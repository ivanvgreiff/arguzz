"""A4 — Mutation module target probe per (kind, zone) arm.

Samples 3 steps per arm; verifies get_targets_at_step returns a valid target.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, OUTPUT_DIR, DEFAULT_HOST, arm_key, load_inspection,
)
from a4.standalone.semantic_arm_universe import _MUTATION_MODULES


def _get_target(kind: str, step: int, data):
    mod = _MUTATION_MODULES[kind]
    if kind == "PRE_EXEC_REG_MOD":
        return mod.get_targets_at_step(step, data, strategy="next_read")
    if kind == "MEM_VAL_MOD":
        return mod.get_targets_at_step(step, data)
    return mod.get_targets_at_step(step, data)


def _target_ok(kind: str, target: Any) -> tuple[bool, Optional[Dict[str, Any]]]:
    if target is None:
        return False, None
    if isinstance(target, list):
        if not target:
            return False, None
        target = target[0]
    info: Dict[str, Any] = {"kind": kind}
    if hasattr(target, "txn_idx"):
        info["txn_idx"] = target.txn_idx
        if info["txn_idx"] is None:
            return False, info
    if hasattr(target, "write_txn_idx"):
        info["txn_idx"] = target.write_txn_idx
    if hasattr(target, "original_word"):
        info["original_word"] = target.original_word
    if hasattr(target, "original_value"):
        info["original_value"] = target.original_value
    if hasattr(target, "original_major"):
        info["original_major"] = target.original_major
        info["original_minor"] = target.original_minor
    if kind == "INSTR_TYPE_MOD":
        return True, info
    if kind in ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR"):
        return info.get("txn_idx") is not None, info
    return info.get("txn_idx") is not None, info


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--samples", type=int, default=3)
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    rng = random.Random(args.seed)
    data, universe, _, host_args = load_inspection(args.host, args.in1, args.in4)

    print(f"A4 mutation module targets: arms={universe.num_arms} samples/arm={args.samples}")

    per_arm: List[Dict[str, Any]] = []
    failures = 0

    for (kind, zone), steps in sorted(universe.arms.items()):
        aid = arm_key(kind, zone)
        if not steps:
            per_arm.append({
                "arm_id": aid, "kind": kind, "zone": zone,
                "steps_tested": 0, "targets_found": 0, "success_rate": 0.0,
                "sample_txns": [], "failed_steps": [],
            })
            failures += 1
            continue

        pick_n = min(args.samples, len(steps))
        sampled = rng.sample(steps, pick_n) if len(steps) >= pick_n else steps[:]
        found = 0
        sample_txns: List[Dict[str, Any]] = []
        failed_steps: List[int] = []

        for step in sampled:
            try:
                target = _get_target(kind, step, data)
            except Exception as exc:
                target = None
                sample_txns.append({"step": step, "error": str(exc)})
            ok, txn_info = _target_ok(kind, target)
            if ok:
                found += 1
                if txn_info:
                    txn_info["step"] = step
                    sample_txns.append(txn_info)
            else:
                failed_steps.append(step)
                sample_txns.append({"step": step, "target": None})

        rate = found / len(sampled) if sampled else 0.0
        per_arm.append({
            "arm_id": aid,
            "kind": kind,
            "zone": zone,
            "steps_tested": len(sampled),
            "targets_found": found,
            "success_rate": rate,
            "sample_txns": sample_txns,
            "failed_steps": failed_steps,
        })
        if rate == 0.0:
            failures += 1
            print(f"  FAIL {aid}: 0/{len(sampled)} targets")
        else:
            print(f"  OK   {aid}: {found}/{len(sampled)}")

    summary = {
        "n_arms": len(per_arm),
        "n_arms_success_rate_lt_1_0": sum(1 for a in per_arm if a["success_rate"] < 1.0),
        "n_arms_zero_targets": sum(1 for a in per_arm if a["success_rate"] == 0.0),
    }

    out = {
        "_meta": GLOSSARY_META,
        "host_args": host_args,
        "num_arms": universe.num_arms,
        "summary": summary,
        "per_arm": per_arm,
    }
    out_path = OUTPUT_DIR / "A4_module_targets.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"  Wrote {out_path}")
    print(f"  summary: {summary}")

    if failures:
        print(f"=== A4 RESULT: FAIL ({failures} arms with zero targets) ===")
        return 1
    print("=== A4 RESULT: PASS ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
