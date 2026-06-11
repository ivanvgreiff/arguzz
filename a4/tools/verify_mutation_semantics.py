#!/usr/bin/env python3
"""
Phase 7c — mutation-semantic verification (G2).

Stratified sample from V5 smoke DB; for each row run host with ONLY
A4_MUTATION_CONFIG (no A4_INSPECT) and assert the mutation hook's own
<a4_<kind>_mod> stdout line matches the DB record.

Spec: a4/docs/cloud1/phases/PHASE_7_INVESTIGATION_REPORT.md §2.6

  python a4/tools/verify_mutation_semantics.py \\
    --db a4/runs/pos_smoke_7b/.../pos_smoke_7b_cTS_semantic_v2_seed999_n200.db \\
    --host workspace/output/target/release/risc0-host \\
    --output a4/docs/cloud1/composer/PHASE_7C_SEMANTIC_RESULTS.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

KINDS = [
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD",
    "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD",
    "MEM_VAL_MOD",
    "INSTR_WORD_MOD_FULL",
    "INSTR_WORD_MOD_SUR",
]

KIND_TO_TAG: Dict[str, str] = {
    "COMP_OUT_MOD": "a4_comp_out_mod",
    "LOAD_VAL_MOD": "a4_load_val_mod",
    "STORE_OUT_MOD": "a4_store_out_mod",
    "PRE_EXEC_REG_MOD": "a4_pre_exec_reg_mod",
    "INSTR_TYPE_MOD": "a4_instr_type_mod",
    "MEM_VAL_MOD": "a4_mem_val_mod",
    "INSTR_WORD_MOD_FULL": "a4_instr_word_mod",
    "INSTR_WORD_MOD_SUR": "a4_instr_word_mod",
}

_MOD_RE = re.compile(r"<(\w+)>({.*?})</\1>")


@dataclass
class SampleRow:
    mutation_id: int
    kind: str
    step: int
    original_value: int
    mutated_value: int
    config: Dict[str, Any]
    passed: bool
    detail: str
    hook_tag: Optional[str] = None
    hook_payload: Optional[Dict[str, Any]] = None


def sample_mutations(db_path: Path, per_kind: int = 3) -> List[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    samples: List[dict] = []
    for kind in KINDS:
        rows = conn.execute(
            """
            SELECT id, kind, step, mutated_value, config_json
            FROM mutations WHERE kind = ?
            ORDER BY RANDOM() LIMIT ?
            """,
            (kind, per_kind),
        ).fetchall()
        for r in rows:
            cfg = json.loads(r["config_json"])
            samples.append({
                "mutation_id": r["id"],
                "kind": r["kind"],
                "step": r["step"],
                "mutated_value": int(r["mutated_value"]),
                "original_value": _original_from_config(cfg, r["kind"]),
                "config": cfg,
            })
    conn.close()
    return samples


def _original_from_config(cfg: Dict[str, Any], kind: str) -> Optional[int]:
    """Pre-mutation value from config _info; None if the field was not recorded."""
    info = cfg.get("_info") or {}
    if kind == "INSTR_TYPE_MOD":
        om = info.get("original_major")
        on = info.get("original_minor")
        if om is not None and on is not None:
            return (int(om) << 16) | int(on)
    if "original_value" in info:
        v = info["original_value"]
        if isinstance(v, str):
            return int(v, 0)
        return int(v)
    if "original_word" in info:
        v = info["original_word"]
        if isinstance(v, str):
            return int(v, 0)
        return int(v)
    return None


def parse_hook_mod(output: str, tag: str) -> Optional[Dict[str, Any]]:
    """Return the last JSON payload for <tag>...</tag> in host output."""
    needle = f"<{tag}>"
    last: Optional[Dict[str, Any]] = None
    for line in output.splitlines():
        if needle not in line:
            continue
        for m in _MOD_RE.finditer(line):
            if m.group(1) != tag:
                continue
            try:
                last = json.loads(m.group(2))
            except json.JSONDecodeError:
                continue
    return last


def run_mutation_hook(
    host: str,
    host_args: List[str],
    config_path: Path,
    *,
    cwd: Optional[Path] = None,
) -> str:
    """Run host with mutation config only (no inspect dump).

    Env mirrors ``run_a4_mutation`` in executor.py so POS and WSL behave the same.
    """
    env = {
        **dict(os.environ),
        "A4_MUTATION_CONFIG": str(config_path),
        "CONSTRAINT_CONTINUE": "1",
        "A4_COVERAGE_TOUCH": "1",
        "A4_FAMILY_RESIDUE": "1",
    }
    env.pop("A4_INSPECT", None)
    env.pop("A4_DUMP_ALL_TXNS", None)
    result = subprocess.run(
        [host] + host_args,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd is not None else None,
    )
    return result.stdout + result.stderr


def _u32(v: Any) -> int:
    return int(v) & 0xFFFFFFFF


def _int_field(v: Any) -> int:
    """Parse int or hex string (0x...) from config / hook fields."""
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


def assert_hook_matches_db(
    kind: str,
    hook: Dict[str, Any],
    step: int,
    original_value: int,
    mutated_value: int,
    config: Dict[str, Any],
) -> Tuple[bool, str]:
    if int(hook.get("step", -1)) != step:
        return False, f"hook step {hook.get('step')} != db step {step}"

    cfg_txn = config.get("txn_idx")
    if cfg_txn is not None and "txn_idx" in hook:
        if int(hook["txn_idx"]) != int(cfg_txn):
            return False, f"hook txn_idx {hook['txn_idx']} != config {cfg_txn}"

    if kind == "INSTR_TYPE_MOD":
        exp_new_m = int(config["major"])
        exp_new_n = int(config["minor"])
        old_m, old_n = int(hook["old_major"]), int(hook["old_minor"])
        new_m, new_n = int(hook["new_major"]), int(hook["new_minor"])
        if new_m != exp_new_m or new_n != exp_new_n:
            return False, (
                f"new_major/minor {new_m}/{new_n} != config {exp_new_m}/{exp_new_n}"
            )
        if old_m == new_m and old_n == new_n:
            return False, f"hook reports no type change at step {step}"
        info = config.get("_info") or {}
        exp_old_m = info.get("original_major")
        exp_old_n = info.get("original_minor")
        if exp_old_m is not None and exp_old_n is not None:
            if old_m != int(exp_old_m) or old_n != int(exp_old_n):
                return False, (
                    f"cycle_shift_at_step: hook old={old_m}/{old_n} "
                    f"!= config exp_old={exp_old_m}/{exp_old_n}"
                )
        return True, f"old={old_m}/{old_n} new={new_m}/{new_n}"

    if kind in ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR", "COMP_OUT_MOD",
                "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_REG_MOD", "MEM_VAL_MOD"):
        exp_new = _u32(config.get("word", mutated_value))
        if "old_word" not in hook or "new_word" not in hook:
            return False, "hook missing old_word/new_word"
        if _u32(hook["new_word"]) != exp_new:
            return False, f"new_word {hook['new_word']:#x} != expected {exp_new:#x}"
        if original_value is not None and _u32(hook["old_word"]) != _u32(original_value):
            return False, (
                f"old_word {hook['old_word']:#x} != expected {original_value:#x}"
            )

        if kind == "LOAD_VAL_MOD":
            reg_idx = (config.get("_info") or {}).get("register_idx")
            if reg_idx is not None and "addr" in hook:
                exp_addr = 1073725472 + int(reg_idx)  # USER_REGS_BASE + idx
                if int(hook["addr"]) != exp_addr:
                    return False, f"addr {hook['addr']} != reg file addr {exp_addr}"

        if kind == "STORE_OUT_MOD":
            info = config.get("_info") or {}
            byte_addr = info.get("byte_addr") or info.get("memory_byte_addr")
            if byte_addr is not None and "addr" in hook:
                exp_word_addr = _int_field(byte_addr) // 4
                if int(hook["addr"]) != exp_word_addr:
                    return False, (
                        f"addr {hook['addr']} != byte_addr//4 {exp_word_addr}"
                    )

        if kind == "MEM_VAL_MOD":
            info = config.get("_info") or {}
            byte_addr = info.get("byte_addr")
            if byte_addr is not None and "byte_addr" in hook:
                if int(hook["byte_addr"]) != _int_field(byte_addr):
                    return False, (
                        f"byte_addr {hook['byte_addr']} != config {byte_addr}"
                    )

        if kind == "PRE_EXEC_REG_MOD":
            reg_idx = (config.get("_info") or {}).get("register_idx")
            if reg_idx is not None and "addr" in hook:
                exp_addr = 1073725472 + int(reg_idx)
                if int(hook["addr"]) != exp_addr:
                    return False, f"addr {hook['addr']} != reg {exp_addr}"

        old_w = _u32(hook["old_word"])
        return True, f"old_word={old_w:#x} new_word={exp_new:#x}"

    return False, f"unsupported kind {kind}"


def verify_sample(
    host: str,
    host_args: List[str],
    sample: dict,
    *,
    cwd: Optional[Path] = None,
) -> SampleRow:
    tag = KIND_TO_TAG[sample["kind"]]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(sample["config"], f)
        cfg_path = Path(f.name)
    hook: Optional[Dict[str, Any]] = None
    ok, detail = False, "not run"
    try:
        output = run_mutation_hook(host, host_args, cfg_path, cwd=cwd)
        hook = parse_hook_mod(output, tag)
        if hook is None:
            ok, detail = False, f"no <{tag}> line in host output"
        else:
            ok, detail = assert_hook_matches_db(
                sample["kind"],
                hook,
                sample["step"],
                sample["original_value"],
                sample["mutated_value"],
                sample["config"],
            )
    finally:
        cfg_path.unlink(missing_ok=True)

    return SampleRow(
        mutation_id=sample["mutation_id"],
        kind=sample["kind"],
        step=sample["step"],
        original_value=sample["original_value"],
        mutated_value=sample["mutated_value"],
        config=sample["config"],
        passed=ok,
        detail=detail,
        hook_tag=tag,
        hook_payload=hook,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 7c semantic verification (G2)")
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--per-kind", type=int, default=3)
    parser.add_argument("host_args", nargs="*", default=["--in1", "5", "--in4", "10"])
    args = parser.parse_args()

    samples = sample_mutations(Path(args.db), args.per_kind)
    results: List[SampleRow] = []
    for s in samples:
        try:
            row = verify_sample(args.host, args.host_args, s)
        except Exception as exc:
            row = SampleRow(
                mutation_id=s["mutation_id"],
                kind=s["kind"],
                step=s["step"],
                original_value=s["original_value"],
                mutated_value=s["mutated_value"],
                config=s["config"],
                passed=False,
                detail=f"exception: {exc}",
            )
        results.append(row)
        status = "PASS" if row.passed else "FAIL"
        print(f"[{status}] id={row.mutation_id} {row.kind} step={row.step}: {row.detail}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([asdict(r) for r in results], indent=2))

    failed = [r for r in results if not r.passed]
    print(f"\n{len(results)} samples, {len(failed)} failures")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
