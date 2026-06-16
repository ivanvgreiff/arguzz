#!/usr/bin/env python3
"""Phase 7d Inc 5 — Pre-flight validator.

Runs before `inc5_e5_pipeline.sh`. Validates that every input the E5
evidence-generator depends on is present, valid, and correctly versioned.

Exit codes:
  0 = all checks PASS — pipeline may proceed
  1 = one or more checks FAIL — pipeline must NOT proceed

Each check prints `[PASS]` or `[FAIL]` with a one-line reason. Final summary
line: `INC5 PREFLIGHT: PASS` or `INC5 PREFLIGHT: FAIL — N issues`.

Design notes
------------
The whole point of preflight is to catch known failure modes BEFORE the
2-hour-ish E5 generation step starts. Anything we know is required goes
here. If a check is missing and the pipeline fails later, the right fix is
to add a new check here (the preflight is cheap; the failure mode is
expensive).

For Inc 5 we explicitly check (per work order §2):
  - Host binary present + canonical Inc 3 baseline SHA
  - Inc 3 baseline DBs present with expected row counts
  - Inc 4 B11 DBs present with expected row counts
  - Disposition outputs from Inc 3 and Inc 4 present + parseable
  - EXPECTED_ARMS.md parses cleanly + has ≥48 kept arms
  - GLOSSARY.md exists and is non-trivial
  - B1_apply_disposition is importable + categorizes a sample row
  - Disk has ≥ 2 GB free in audit_output/
  - Fast test suite passes (no regressions)
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Canonical Inc 3 baseline binary (the one used for B1/B4/B7 in Inc 3 + Inc 4)
INC3_BASELINE_HOST_SHA = "6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444"
HOST_BIN = REPO_ROOT / "workspace/output/target/release/risc0-host"
AUDIT_OUTPUT_DIR = REPO_ROOT / "a4/audits/audit_output"
EXPECTED_ARMS = REPO_ROOT / "a4/docs/cloud1/EXPECTED_ARMS.md"
GLOSSARY = REPO_ROOT / "a4/docs/cloud1/GLOSSARY.md"

INC3_BASELINE_DBS = [
    REPO_ROOT / f"a4/runs/inc3_baseline/v{i}.db" for i in (1, 2, 3, 4, 5)
]
INC4_B11_DBS = [
    REPO_ROOT / f"a4/runs/inc4_b11/v{i}.db" for i in (1, 2, 3, 4, 5)
]

INC3_BASELINE_MIN_ROWS = 200
INC4_B11_MIN_ROWS = 500

DISPO_JSONS = [
    AUDIT_OUTPUT_DIR / "B1_inc3d_disposition.json",
    AUDIT_OUTPUT_DIR / "B1_inc4_b12_in1_1_disposition.json",
    AUDIT_OUTPUT_DIR / "B1_inc4_b12_in1_100_disposition.json",
    AUDIT_OUTPUT_DIR / "B1_inc4_b11_disposition.json",
]

MIN_FREE_DISK_BYTES = 2 * 1024 ** 3  # 2 GB
EXPECTED_KEPT_ARMS = 48


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_host_binary() -> Tuple[bool, str]:
    if not HOST_BIN.exists():
        return False, f"missing host binary at {HOST_BIN}"
    actual = _sha256(HOST_BIN)
    if actual != INC3_BASELINE_HOST_SHA:
        return False, (
            f"host binary SHA mismatch: got {actual[:16]}…, "
            f"expected {INC3_BASELINE_HOST_SHA[:16]}… (Inc 3 baseline)"
        )
    return True, f"host binary OK ({HOST_BIN.name}, SHA {actual[:16]}…)"


def _check_db(path: Path, min_rows: int, label: str) -> Tuple[bool, str]:
    if not path.exists():
        return False, f"{label}: missing DB at {path}"
    try:
        conn = sqlite3.connect(str(path))
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        required = {"mutations", "bandit_decisions", "mutation_rewards"}
        missing_tables = required - tables
        if missing_tables:
            return False, f"{label}: missing tables {missing_tables}"
        n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
        conn.close()
    except sqlite3.DatabaseError as e:
        return False, f"{label}: DB error — {e}"
    if n < min_rows:
        return False, f"{label}: only {n} rows in `mutations` (need ≥{min_rows})"
    return True, f"{label}: {n} rows OK"


def _check_inc3_baseline_dbs() -> List[Tuple[bool, str]]:
    return [
        _check_db(p, INC3_BASELINE_MIN_ROWS, f"Inc3 baseline V{i+1}")
        for i, p in enumerate(INC3_BASELINE_DBS)
    ]


def _check_inc4_b11_dbs() -> List[Tuple[bool, str]]:
    return [
        _check_db(p, INC4_B11_MIN_ROWS, f"Inc4 B11 V{i+1}")
        for i, p in enumerate(INC4_B11_DBS)
    ]


def _check_disposition_jsons() -> List[Tuple[bool, str]]:
    results = []
    for p in DISPO_JSONS:
        if not p.exists():
            results.append((False, f"missing disposition output: {p.name}"))
            continue
        try:
            d = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            results.append((False, f"{p.name}: invalid JSON — {e}"))
            continue
        for key in ("summary", "per_variant", "_meta"):
            if key not in d:
                results.append((False, f"{p.name}: missing key '{key}'"))
                break
        else:
            verdict = d.get("summary", {}).get("verdict")
            results.append((True, f"{p.name}: verdict={verdict} OK"))
    return results


def _check_expected_arms() -> Tuple[bool, str]:
    if not EXPECTED_ARMS.exists():
        return False, f"missing {EXPECTED_ARMS}"
    try:
        from a4.audits.audit_common import parse_expected_arms_baseline
    except ImportError as e:
        return False, f"cannot import audit_common.parse_expected_arms_baseline — {e}"
    try:
        parsed = parse_expected_arms_baseline(EXPECTED_ARMS)
        n_arms = len(parsed["arms"])
    except Exception as e:
        return False, f"parse error — {e}"
    if n_arms < EXPECTED_KEPT_ARMS:
        return False, (
            f"only parsed {n_arms} kept arms; "
            f"expected ≥ {EXPECTED_KEPT_ARMS}"
        )
    return True, f"EXPECTED_ARMS.md parses cleanly — {n_arms} kept arms"


def _check_glossary() -> Tuple[bool, str]:
    if not GLOSSARY.exists():
        return False, f"missing {GLOSSARY}"
    size = GLOSSARY.stat().st_size
    if size < 1024:
        return False, f"{GLOSSARY.name} too small ({size} bytes); looks empty"
    return True, f"GLOSSARY.md OK ({size} bytes)"


def _check_disposition_module() -> Tuple[bool, str]:
    try:
        mod = importlib.import_module("a4.audits.B1_apply_disposition")
    except ImportError as e:
        return False, f"cannot import B1_apply_disposition — {e}"
    if not hasattr(mod, "categorize"):
        return False, "B1_apply_disposition.categorize() missing"
    sample = {"kind": "INSTR_TYPE_MOD", "step": 0,
              "detail": "cycle_shift_at_step hook old=7/0",
              "hook_payload": {"cycle_major": 7}}
    cat = mod.categorize(sample)
    if cat != "A":
        return False, f"sample categorization returned {cat!r}, expected 'A'"
    return True, "B1_apply_disposition.categorize() works (sample → 'A')"


def _check_disk_space() -> Tuple[bool, str]:
    AUDIT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(AUDIT_OUTPUT_DIR).free
    if free < MIN_FREE_DISK_BYTES:
        return False, (
            f"only {free / 1024 ** 3:.1f} GB free in audit_output "
            f"(need ≥ {MIN_FREE_DISK_BYTES / 1024 ** 3:.1f})"
        )
    return True, f"audit_output disk OK ({free / 1024 ** 3:.1f} GB free)"


def _check_fast_tests() -> Tuple[bool, str]:
    test_dir = REPO_ROOT / "a4/standalone/tests"
    if not test_dir.exists():
        return False, f"no test directory at {test_dir}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    try:
        proc = subprocess.run(
            ["python3", "-m", "pytest", "-q", "--no-header",
             "-x", str(test_dir)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        return False, "pytest timed out after 900s — likely hung test"
    if proc.returncode != 0:
        last = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        return False, "pytest FAIL — tail: " + " | ".join(last)
    last_line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    return True, f"fast tests OK ({last_line})"


CheckFn = Callable[[], Tuple[bool, str]]
BatchCheckFn = Callable[[], List[Tuple[bool, str]]]


SINGLE_CHECKS: List[Tuple[str, CheckFn]] = [
    ("host_binary", _check_host_binary),
    ("expected_arms", _check_expected_arms),
    ("glossary", _check_glossary),
    ("disposition_module", _check_disposition_module),
    ("disk_space", _check_disk_space),
    ("fast_tests", _check_fast_tests),
]
BATCH_CHECKS: List[Tuple[str, BatchCheckFn]] = [
    ("inc3_baseline_dbs", _check_inc3_baseline_dbs),
    ("inc4_b11_dbs", _check_inc4_b11_dbs),
    ("disposition_jsons", _check_disposition_jsons),
]


def _print_result(ok: bool, label: str, msg: str) -> None:
    tag = "[PASS]" if ok else "[FAIL]"
    print(f"{tag} {label}: {msg}", flush=True)


def main() -> int:
    n_fail = 0
    for label, fn in SINGLE_CHECKS:
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, f"unhandled exception — {type(e).__name__}: {e}"
        _print_result(ok, label, msg)
        if not ok:
            n_fail += 1

    for label, fn in BATCH_CHECKS:
        try:
            results = fn()
        except Exception as e:
            _print_result(False, label, f"batch exception — {type(e).__name__}: {e}")
            n_fail += 1
            continue
        for i, (ok, msg) in enumerate(results):
            sublabel = f"{label}[{i}]"
            _print_result(ok, sublabel, msg)
            if not ok:
                n_fail += 1

    print(flush=True)
    if n_fail == 0:
        print("INC5 PREFLIGHT: PASS", flush=True)
        return 0
    print(f"INC5 PREFLIGHT: FAIL — {n_fail} issue(s)", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
