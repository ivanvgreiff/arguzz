#!/usr/bin/env python3
"""Phase 7d Inc 5 — evidence index + summary JSON builder."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from a4.audits.audit_common import OUTPUT_DIR, EXPECTED_ARMS_PATH, parse_expected_arms_baseline

EVIDENCE_DIR = OUTPUT_DIR / "per_arm_evidence"
SUMMARY_PATH = OUTPUT_DIR / "E5_summary.json"
STATS_PATH = OUTPUT_DIR / "E5_arm_stats.json"
INDEX_PATH = EVIDENCE_DIR / "README.md"

VERDICT_RE = re.compile(r"\*\*Arm verdict: ([^*]+)\*\*")
STATUS_RE = re.compile(r"\*\*Status:\*\s*(.+)")
DIST_RE = re.compile(
    r"\*\*Distribution\*\*:\s*(\d+) PASS,\s*(\d+) exclusion.*?,\s*(\d+) RACE,\s*(\d+) OTHER"
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_evidence(path: Path) -> dict:
    text = path.read_text()
    vm = VERDICT_RE.search(text)
    sm = STATUS_RE.search(text)
    dm = DIST_RE.search(text)
    verdict = vm.group(1).strip() if vm else "UNKNOWN"
    status = sm.group(1).strip() if sm else verdict
    n_pass = n_excl = n_race = n_other = 0
    if dm:
        n_pass, n_excl, n_race, n_other = map(int, dm.groups())
    return {
        "file": path.name,
        "status": status,
        "verdict": verdict,
        "n_pass": n_pass,
        "n_exclusion": n_excl,
        "n_race": n_race,
        "n_other": n_other,
    }


def main() -> int:
    parsed = parse_expected_arms_baseline(EXPECTED_ARMS_PATH)
    expected = parsed["arms"]

    rows = []
    missing = []
    for aid in sorted(expected):
        kind, zone = expected[aid]["kind"], expected[aid]["zone"]
        fname = f"{kind}_{zone}.md"
        path = EVIDENCE_DIR / fname
        if not path.exists():
            missing.append(aid)
            continue
        row = _parse_evidence(path)
        row["arm_id"] = aid
        rows.append(row)

    if missing:
        print(f"E5 index: missing {len(missing)} evidence files", file=sys.stderr)
        for m in missing[:10]:
            print(f"  - {m}", file=sys.stderr)
        return 2

    n_correct = sum(1 for r in rows if "✗" not in r["verdict"])
    n_warning = sum(1 for r in rows if "⚠" in r["verdict"])
    n_incorrect = sum(1 for r in rows if "✗" in r["verdict"])
    n_other_total = sum(r["n_other"] for r in rows)

    verdict = "PASS" if n_incorrect == 0 and n_correct >= 48 and n_other_total == 0 else "FAIL"

    host = REPO_ROOT / "workspace/output/target/release/risc0-host"
    summary = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "n_arms_correct": n_correct,
        "n_arms_warning": n_warning,
        "n_arms_incorrect": n_incorrect,
        "n_other_rows_total": n_other_total,
        "per_arm": {r["arm_id"]: r for r in rows},
        "source_hashes": {
            "risc0-host": _sha256(host) if host.exists() else None,
            "EXPECTED_ARMS.md": _sha256(EXPECTED_ARMS_PATH),
        },
    }
    if STATS_PATH.exists():
        summary["generation_stats"] = json.loads(STATS_PATH.read_text())

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2))

    lines = [
        "# Per-Arm Evidence Index (E5)",
        "",
        "Phase 7d Inc 5 — one markdown evidence file per kept arm in "
        "`EXPECTED_ARMS.md` baseline (`sha2-host @ --in1 5 --in4 10`).",
        "See `a4/docs/cloud1/composer/PHASE_7D_INC5_REPORT.md` and "
        "`CLOUD1_DECISIONS_FOR_PRO_R2.md` for context.",
        "",
        "| Arm | Status | N ✓ | N excl | N RACE | N OTHER | File |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        icon = "✓" if "✓" in r["verdict"] else ("⚠" if "⚠" in r["verdict"] else "✗")
        lines.append(
            f"| `{r['arm_id']}` | {icon} | {r['n_pass']} | {r['n_exclusion']} | "
            f"{r['n_race']} | {r['n_other']} | [{r['file']}]({r['file']}) |"
        )

    lines.extend([
        "",
        f"**Summary:** {n_correct}/48 ✓, {n_warning} ⚠, {n_incorrect} ✗. "
        f"Gate verdict: **{verdict}**.",
        "",
        "Multi-guest-only arms (not exercised by baseline guest) have stub files under "
        "[`_stubs/`](_stubs/).",
        "",
        f"INC5 INDEX: {n_correct}/48 ✓",
        "",
    ])
    INDEX_PATH.write_text("\n".join(lines))

    print(f"E5 index: {INDEX_PATH}")
    print(f"E5 summary: {SUMMARY_PATH} verdict={verdict}")
    print(f"INC5 INDEX: {n_correct}/48 ✓")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
