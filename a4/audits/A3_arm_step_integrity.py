"""A3 — Per-arm step-list integrity.

Phase 7d gate: for every arm (kind, zone) in SemanticArmUniverse.arms,
every step in the arm's step list must have a real mutation target
(get_targets_at_step returns truthy). No phantom steps within real arms.

Usage:
    python -m a4.audits.A3_arm_step_integrity [--host PATH] [--in1 N] [--in4 N]

Exit codes:
    0  — PASS
    1  — FAIL: at least one arm has phantom steps
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, "/root/arguzz")
from a4.core.inspection_data import InspectionData
from a4.standalone.zone_classifier import zone_to_steps
from a4.standalone.semantic_zones import SEMANTIC_ZONES
from a4.standalone.semantic_arm_universe import (
    ArmKey,
    SemanticArmUniverse, _MUTATION_MODULES, _step_has_real_target,
)

DEFAULT_HOST = "/root/arguzz/workspace/output/target/release/risc0-host"
OUTPUT_DIR = Path(__file__).parent / "audit_output"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"A3 arm step integrity: host={args.host} args=--in1 {args.in1} --in4 {args.in4}")

    kinds = sorted(_MUTATION_MODULES.keys())
    data = InspectionData.from_inspection(args.host, ["--in1", args.in1, "--in4", args.in4])
    print(f"  steps={data.total_steps}")

    universe = SemanticArmUniverse.build(data, kinds)
    print(f"  arms: {universe.num_arms}")

    z2s = zone_to_steps(data)
    valid_by_kind = {k: data.get_valid_steps_for_kind(k) for k in kinds}

    print()
    print(f"{'arm':<48} {'naive':>6} {'kept':>6} {'real':>6} {'phantom%':>9}")
    print("-" * 80)

    violations = 0
    dropped = []
    kept_arms = []

    for kind in kinds:
        vset = set(valid_by_kind[kind])
        for zone in SEMANTIC_ZONES:
            intersect = sorted(vset & set(z2s.get(zone, [])))
            if not intersect:
                continue
            naive = len(intersect)
            arm = ArmKey.v5(kind, zone)
            if arm in universe.arms:
                kept = universe.arms[arm]
                real = sum(1 for s in kept if _step_has_real_target(kind, s, data))
                phantom = len(kept) - real
                pct = 100.0 * phantom / len(kept) if kept else 0
                mark = " ✗" if phantom > 0 else ""
                print(f"{kind+'|'+zone:<48} {naive:>6} {len(kept):>6} {real:>6} {pct:>8.1f}%{mark}")
                kept_arms.append({
                    "kind": kind, "zone": zone, "naive": naive,
                    "kept": len(kept), "real": real, "phantom": phantom,
                })
                if phantom > 0:
                    violations += 1
            else:
                print(f"{kind+'|'+zone:<48} {naive:>6} {'DROP':>6} {'-':>6} {'-':>9}")
                dropped.append({"kind": kind, "zone": zone, "naive": naive})

    print()
    print(f"Arms kept: {len(kept_arms)}")
    print(f"Arms dropped (phantom pruning): {len(dropped)}")
    for d in dropped:
        print(f"  - {d['kind']}|{d['zone']} (would have had {d['naive']} naive steps)")

    out_file = OUTPUT_DIR / f"A3_arms_in1_{args.in1}_in4_{args.in4}.json"
    out_file.write_text(json.dumps({
        "host_args": [f"--in1={args.in1}", f"--in4={args.in4}"],
        "total_steps": data.total_steps,
        "num_arms": universe.num_arms,
        "kept_arms": kept_arms,
        "dropped_arms": dropped,
    }, indent=2))
    print(f"  Detailed arm table written to {out_file}")

    print()
    if violations == 0:
        print("=== A3 RESULT: PASS ===")
        return 0
    else:
        print(f"=== A3 RESULT: FAIL ({violations} arms with phantom steps) ===")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
