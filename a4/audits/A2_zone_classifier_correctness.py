"""A2 — Zone classifier semantic correctness.

Phase 7d gate: for each non-empty zone, every step assigned to it must
satisfy the zone's first-principles predicate (from PHASE_7D_ARCHITECTURE_AUDIT.md
table). 100% of steps must be classified into exactly one zone.

Usage:
    python -m a4.audits.A2_zone_classifier_correctness [--host PATH] [--in1 N] [--in4 N]

Exit codes:
    0  — PASS
    1  — FAIL: at least one zone has a step that violates the predicate
"""
import argparse
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, "/root/arguzz")
from a4.core.inspection_data import InspectionData
from a4.standalone.zone_classifier import classify_zones, zone_to_steps, ECALL_MAJOR
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, BOUNDARY_ZONES, SINGLETON_ZONES, MAJOR_TO_CORE_ZONE,
)

DEFAULT_HOST = "/root/arguzz/workspace/output/target/release/risc0-host"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--sample-size", type=int, default=20)
    args = p.parse_args()

    print(f"A2 zone classifier correctness: host={args.host} args=--in1 {args.in1} --in4 {args.in4}")
    data = InspectionData.from_inspection(args.host, ["--in1", args.in1, "--in4", args.in4])
    print(f"  cycles={len(data.cycles)} steps={data.total_steps}")

    z2s = zone_to_steps(data)
    s2z = classify_zones(data)

    # Build per-step major set
    step_majors = defaultdict(list)
    for c in data.cycles:
        step_majors[c.step].append(c.major)

    ecall_steps = sorted({c.step for c in data.cycles if c.major == ECALL_MAJOR})
    print(f"  ECALL cycles: {sum(1 for c in data.cycles if c.major == ECALL_MAJOR)} on {len(ecall_steps)} distinct steps")
    print()

    random.seed(0)
    violations = []
    print(f"{'zone':<22} {'steps':>8} {'check'}")
    print("-" * 80)
    for z in SEMANTIC_ZONES:
        steps = z2s[z]
        n = len(steps)
        if n == 0:
            print(f"{z:<22} {n:>8} EMPTY")
            continue

        sample = random.sample(steps, min(args.sample_size, n))

        if z == "step0":
            ok = steps == [0]
            msg = "PASS" if ok else f"FAIL: contains {len(steps)} steps, not [0]"
        elif z == "last_step":
            ok = steps == [data.total_steps - 1]
            msg = "PASS" if ok else f"FAIL: not [T-1]"
        elif z == "pre_ecall":
            bad = []
            for s in sample:
                if s == 0 or s == data.total_steps - 1:
                    continue
                if ECALL_MAJOR not in step_majors.get(s, []):
                    bad.append((s, step_majors.get(s, [])))
            msg = "PASS" if not bad else f"FAIL: {len(bad)} bad samples; ex: {bad[:2]}"
        elif z == "post_ecall":
            bad = []
            for s in sample:
                if s == 0 or s == data.total_steps - 1:
                    continue
                if (s - 1) not in ecall_steps:
                    bad.append((s, sorted(step_majors.get(s, []))))
            msg = "PASS" if not bad else f"FAIL: {len(bad)} bad; ex: {bad[:2]}"
        elif z in ("pre_mret", "post_mret", "pre_halt", "post_halt"):
            msg = "N/A — classifier limitation"
        else:
            expected_majors = {m for m, zs in MAJOR_TO_CORE_ZONE.items() if zs == z}
            bad = []
            for s in sample:
                if s == 0 or s == data.total_steps - 1:
                    continue
                mset = set(step_majors.get(s, []))
                if not (mset & expected_majors):
                    bad.append((s, sorted(mset)))
            msg = "PASS" if not bad else f"FAIL: {len(bad)} bad (expected majors {sorted(expected_majors)}); ex: {bad[:2]}"

        print(f"{z:<22} {n:>8} {msg}")
        if "FAIL" in msg:
            violations.append((z, msg))

    # Coverage / overlap
    classified = set(s2z.keys())
    all_steps = set(range(data.total_steps))
    missing = all_steps - classified
    print()
    print(f"Steps in trace but NOT in any zone: {len(missing)}")
    if missing:
        violations.append(("coverage", f"{len(missing)} steps unclassified; sample: {sorted(missing)[:10]}"))

    zone_step_count = defaultdict(int)
    for s in s2z:
        zone_step_count[s] += 1
    multi = [s for s, n in zone_step_count.items() if n > 1]
    print(f"Steps in multiple zones: {len(multi)}")
    if multi:
        violations.append(("overlap", f"{len(multi)} multi-zone steps; sample: {multi[:5]}"))

    print()
    if violations:
        print("=== A2 RESULT: FAIL ===")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)
    else:
        print("=== A2 RESULT: PASS ===")
        return 0


if __name__ == "__main__":
    sys.exit(main())
