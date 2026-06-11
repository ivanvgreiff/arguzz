"""A5 — Diff SemanticArmUniverse against EXPECTED_ARMS.md baseline."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    D40_REMOVED_ARMS,
    GLOSSARY_META,
    OUTPUT_DIR,
    DEFAULT_HOST,
    arm_key,
    load_inspection,
    parse_expected_arms_baseline,
)


def _parse_tolerance(tol: str, expected: int) -> Tuple[int, int]:
    tol = tol.strip()
    if tol == "exact":
        return expected, expected
    m = re.match(r"±(\d+)%", tol)
    if m:
        pct = int(m.group(1)) / 100.0
        delta = max(1, int(expected * pct))
        return expected - delta, expected + delta
    m = re.match(r"±(\d+)", tol)
    if m:
        d = int(m.group(1))
        return max(0, expected - d), expected + d
    return expected, expected


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    parsed = parse_expected_arms_baseline()
    expected_meta = parsed["arms"]

    data, universe, _, host_args = load_inspection(args.host, args.in1, args.in4)
    actual: Dict[str, Dict[str, Any]] = {}
    for (kind, zone), steps in universe.arms.items():
        actual[arm_key(kind, zone)] = {
            "kind": kind,
            "zone": zone,
            "actual_steps": len(steps),
        }

    expected_keys = set(expected_meta.keys())
    actual_keys = set(actual.keys())
    d40_str = {arm_key(k, z) for k, z in D40_REMOVED_ARMS}

    added = sorted(actual_keys - expected_keys)
    removed = sorted(expected_keys - actual_keys)
    renamed: List[Dict[str, str]] = []  # reserved for zone string aliasing

    unexplained_removed = [r for r in removed if r not in d40_str]
    explained_d40 = [r for r in removed if r in d40_str]

    step_violations: List[Dict[str, Any]] = []
    for key in sorted(actual_keys & expected_keys):
        exp = expected_meta[key]
        act_steps = actual[key]["actual_steps"]
        lo, hi = _parse_tolerance(exp["tolerance"], exp["expected_steps"])
        if exp["status"] == "🟡":
            # wider ±20% for uncertain arms per EXPECTED_ARMS.md
            lo = max(0, int(exp["expected_steps"] * 0.8))
            hi = int(exp["expected_steps"] * 1.2) + 1
        if not (lo <= act_steps <= hi):
            step_violations.append({
                "arm_id": key,
                "expected_steps": exp["expected_steps"],
                "actual_steps": act_steps,
                "tolerance": exp["tolerance"],
                "allowed_range": [lo, hi],
                "status": exp["status"],
            })

    out = {
        "_meta": GLOSSARY_META,
        "host_args": host_args,
        "expected_count_doc": parsed["expected_count_doc"],
        "expected_count_adjusted_d40": parsed["expected_count_doc"] - len(D40_REMOVED_ARMS),
        "actual_count": len(actual_keys),
        "added": added,
        "removed": removed,
        "removed_explained_d40": explained_d40,
        "removed_unexplained": unexplained_removed,
        "renamed": renamed,
        "step_count_violations": step_violations,
        "per_arm_actual": [
            {"arm_id": k, **actual[k]} for k in sorted(actual_keys)
        ],
    }
    out_path = OUTPUT_DIR / "A5_canonical_diff.json"
    out_path.write_text(json.dumps(out, indent=2))

    print(f"A5 canonical match: expected(doc)={parsed['expected_count_doc']} "
          f"adjusted_d40={out['expected_count_adjusted_d40']} actual={len(actual_keys)}")
    if added:
        print(f"  added ({len(added)}): {added}")
    if removed:
        print(f"  removed ({len(removed)}): {removed}")
        print(f"    d40-explained: {explained_d40}")
        print(f"    unexplained: {unexplained_removed}")
    if step_violations:
        print(f"  step_count_violations: {len(step_violations)}")
        for v in step_violations[:5]:
            print(f"    {v['arm_id']}: {v['actual_steps']} not in {v['allowed_range']}")

    fail = bool(added or unexplained_removed or step_violations)
    print(f"  Wrote {out_path}")
    if fail:
        print("=== A5 RESULT: FAIL ===")
        return 1
    print("=== A5 RESULT: PASS ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
