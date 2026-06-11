"""E2 — Per-arm failure-class fingerprinting (informational)."""
from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, INC2_SMOKE_SEED, OUTPUT_DIR, DEFAULT_HOST, arm_key, load_inspection,
)
from a4.core.executor import run_a4_mutation
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.reward_v2 import extract_constraint_family

A3_PATH = OUTPUT_DIR / "A3_arms_in1_5_in4_10.json"
A1_NONDET_PATH = OUTPUT_DIR / "A1_nondet_addrs.json"


def _load_nondet_addrs() -> Set[int]:
    if not A1_NONDET_PATH.exists():
        return set()
    data = json.loads(A1_NONDET_PATH.read_text())
    return set(data.get("nondet_addresses", []))


def _mem_val_step_ok(step: int, data, nondet: Set[int]) -> bool:
    from a4.standalone.mutations import mem_val_mod
    targets = mem_val_mod.get_targets_at_step(step, data)
    if not targets:
        return False
    t = targets[0]
    addr = getattr(t, "addr", None)
    return addr not in nondet


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--seed", type=int, default=INC2_SMOKE_SEED)
    p.add_argument("--max-arms", type=int, default=0, help="0 = all 48")
    args = p.parse_args()
    OUTPUT_DIR.mkdir(exist_ok=True)

    a3 = json.loads(A3_PATH.read_text())
    nondet = _load_nondet_addrs()
    rng = random.Random(args.seed)

    per_arm: List[Dict[str, Any]] = []
    zero_bite: List[str] = []
    zone_family: Dict[str, Counter] = defaultdict(Counter)

    with tempfile.TemporaryDirectory(prefix="e2_") as tmp:
        db = str(Path(tmp) / "e2.db")
        with A4Fuzzer(
            host_binary=args.host,
            host_args=["--in1", "5", "--in4", "10"],
            db_path=db,
            kind="all",
            selector_strategy="cTS_semantic_v2",
            seed=args.seed,
            verbose=False,
            telemetry_level="none",
        ) as fuzzer:
            print("E2: running inspection...", flush=True)
            fuzzer.run_inspection()
            data = fuzzer.data
            _, universe, _, _ = load_inspection(args.host, "5", "10")

            arms = a3["kept_arms"]
            if args.max_arms:
                arms = arms[: args.max_arms]
            print(f"E2: {len(arms)} arms to probe", flush=True)

            for i, arm in enumerate(arms):
                kind, zone = arm["kind"], arm["zone"]
                aid = arm_key(kind, zone)
                steps = universe.steps_in_arm(kind, zone)
                if kind == "MEM_VAL_MOD" and nondet:
                    steps = [s for s in steps if _mem_val_step_ok(s, data, nondet)]
                if not steps:
                    per_arm.append({
                        "arm": aid, "n_mutations": 0, "n_with_failures": 0,
                        "mean_failures_per_mut": 0.0,
                        "dominant_failure_family": None,
                        "family_distribution": {},
                        "note": "no steps after D42 filter",
                    })
                    zero_bite.append(aid)
                    continue

                sample = rng.sample(steps, min(5, len(steps)))
                fail_counts = []
                families: Counter = Counter()

                for step in sample:
                    try:
                        config, mutated_value, original_value = fuzzer._create_mutation(kind, step)
                    except Exception:
                        continue
                    if config is None:
                        continue
                    cfg_path = fuzzer.temp_dir / f"e2_{i}_{step}.json"
                    cfg_path.write_text(json.dumps(config))
                    exec_result = run_a4_mutation(args.host, ["--in1", "5", "--in4", "10"], cfg_path)
                    n_fail = len(exec_result.failures or [])
                    fail_counts.append(n_fail)
                    for f in exec_result.failures or []:
                        fam = extract_constraint_family(f.constraint_loc())
                        families[fam] += 1

                n_mut = len(fail_counts)
                n_with = sum(1 for c in fail_counts if c > 0)
                dom = families.most_common(1)[0][0] if families else None
                if n_with == 0:
                    zero_bite.append(aid)
                if dom:
                    zone_family[zone][dom] += 1

                per_arm.append({
                    "arm": aid,
                    "n_mutations": n_mut,
                    "n_with_failures": n_with,
                    "mean_failures_per_mut": (sum(fail_counts) / n_mut) if n_mut else 0.0,
                    "dominant_failure_family": dom,
                    "family_distribution": dict(families),
                })
                if (i + 1) % 3 == 0 or i == 0:
                    print(f"  E2 progress: {i+1}/{len(arms)} arms", flush=True)

    redundant: List[str] = []
    for zone, fam_counts in zone_family.items():
        if not fam_counts:
            continue
        total = sum(fam_counts.values())
        top_fam, top_n = fam_counts.most_common(1)[0]
        if total >= 3 and top_n / total > 0.9:
            arms_in_zone = [r["arm"] for r in per_arm if r["arm"].endswith(f"|{zone}")]
            redundant.extend(arms_in_zone)

    soft_flags = []
    if len(zero_bite) > 5:
        soft_flags.append(f"zero_bite_arms={len(zero_bite)} (>5 → E4)")
    if len(set(redundant)) > 3:
        soft_flags.append(f"candidate_redundant_zones={len(set(redundant))}")

    out = {
        "_meta": GLOSSARY_META,
        "seed": args.seed,
        "n_arms": len(per_arm),
        "per_arm": per_arm,
        "zero_bite_arms": zero_bite,
        "candidate_redundant_arms": sorted(set(redundant)),
        "soft_flags": soft_flags,
        "verdict": "DONE",
    }
    out_path = OUTPUT_DIR / "E2_arm_bite.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"=== E2 RESULT: DONE ({len(per_arm)} arms, {len(zero_bite)} zero-bite) ===")
    print(f"  Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
