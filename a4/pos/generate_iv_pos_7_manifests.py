#!/usr/bin/env python3
"""
Generate the IV.POS.7 (Phase 8) batched-parallel dispatch manifests.

Per PHASE_8_PLAN.md §3 (batched-parallel design, locked 2026-06-13 PM):
  - 5 variants x 10 seeds = 50 total jobs
  - 8 EPYC nodes split across TWO INDEPENDENT runners:
      Tier-S runner: 4 nodes (flare, octorand, opulous, polynize) -> 28 jobs in 7 batches
      Tier-A runner: 4 nodes (algofi, gard, goracle, zone)        -> 22 jobs in 6 batches
  - Each batch = 1 dispatch_pos.py call with up to 4 jobs round-robined to 4 nodes
  - Wall time ~35h (vs ~52h for the by-seed model previously specified) once both
    tiers run concurrently after 2026-06-14 03:00 UTC (christer's reservation
    1750 frees the Tier-A nodes at that point).

JOB ASSIGNMENT (PHASE_8_PLAN.md §3.2)
=====================================
Within-tier variant pinning is preserved (each variant occupies exactly one node
within a tier across all batches). Across tiers, V2-V5 split their 10 seeds as
7 on Tier-S + 3 on Tier-A. V1 (reference, race-immune, no MAB) runs entirely on
Tier-A. Both tiers are EPYC -> race-equivalent (Inc 4 B11 evidence).

Tier-S (4 nodes; jobs ordered so position i lands on nodes[i]):
  Position 0 (flare)    -> V2 (kindUCB_zoned_v1)
  Position 1 (octorand) -> V3 (kindUCB_zoned_v2_noQ)
  Position 2 (opulous)  -> V4 (kindTS_zoned_v2)
  Position 3 (polynize) -> V5 (cTS_semantic_v2)

Tier-A (4 nodes; jobs ordered so position i lands on nodes[i]):
  Position 0 (algofi)   -> V1 in V1-only batches; V4 in mixed batches
  Position 1 (gard)     -> V1 in V1-only batches; V5 in mixed batches
  Position 2 (goracle)  -> V1 in V1-only batches; V2 in mixed batches
  Position 3 (zone)     -> V1 in V1-only batches; V3 in mixed batches

Tier-S batches (7 x 4 = 28 jobs):
  ts_b1..ts_b7: each has [V2, V3, V4, V5] at seeds 1234..1240 respectively

Tier-A batches (6 batches, 22 jobs):
  ta_b1: V1 seeds 1234..1237 (4 V1 jobs)
  ta_b2: V1 seeds 1238..1241 (4 V1 jobs)
  ta_b3: V1 seeds 1242, 1243; V4 seed 1241; V5 seed 1241; V2 seed 1241; V3 seed 1241
         -- actually positionally: [V1@1242 (algofi), V1@1243 (gard), V2@1241 (goracle), V3@1241 (zone)]
  ta_b4: V4@1241 (algofi), V5@1241 (gard), V2@1242 (goracle), V3@1242 (zone)
  ta_b5: V4@1242 (algofi), V5@1242 (gard), V2@1243 (goracle), V3@1243 (zone)
  ta_b6: V4@1243 (algofi), V5@1243 (gard)  -- 2 jobs only

Per-variant node distribution after the campaign:
  V1: 10 seeds on Tier-A (algofi x 3, gard x 3, goracle x 2, zone x 2)
  V2: flare x 7 (s=1234..1240) + goracle x 3 (s=1241..1243)
  V3: octorand x 7 (s=1234..1240) + zone x 3 (s=1241..1243)
  V4: opulous x 7 (s=1234..1240) + algofi x 3 (s=1241..1243)
  V5: polynize x 7 (s=1234..1240) + gard x 3 (s=1241..1243)

USAGE
=====
  python3 a4/pos/generate_iv_pos_7_manifests.py [--out-dir a4/pos/manifests/iv_pos_7]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# Default node labels (documentation only; orchestrator overrides via --nodes order).
TIER_S_NODES = ["flare", "octorand", "opulous", "polynize"]
TIER_A_NODES = ["algofi", "gard", "goracle", "zone"]

# Variant ids -> internal strategy names (passed through to dispatch_pos.py).
V1 = "zoned"
V2 = "kindUCB_zoned_v1"
V3 = "kindUCB_zoned_v2_noQ"
V4 = "kindTS_zoned_v2"
V5 = "cTS_semantic_v2"

# All 5 variants (used by smoke).
ALL_VARIANTS = [V1, V2, V3, V4, V5]

SEEDS = list(range(1234, 1244))  # 10 seeds: 1234..1243
N = 6000
GUEST_ARGS = ["--in1", "5", "--in4", "10"]
IMAGE = "debian-trixie"


def _job(strategy: str, seed: int, n: int, node_label: str) -> dict:
    return {
        "strategy": strategy,
        "seed": seed,
        "n": n,
        "b_count": 16,
        "telemetry_level": "full",
        # node_label is documentation only; dispatch_pos.py ignores it and
        # round-robins to nodes in --nodes order. Orchestrator MUST pass nodes
        # in the order TIER_S_NODES or TIER_A_NODES for the pinning to hold.
        "node_label": node_label,
    }


# ---------- Tier-S batches (28 jobs, 7 batches x 4) ----------

def _ts_batch(seed: int, batch_idx: int) -> dict:
    """One Tier-S batch: [V2@seed, V3@seed, V4@seed, V5@seed] on 4 Tier-S nodes."""
    name = f"pos_iv_pos_7_ts_b{batch_idx}"
    return {
        "_doc": (
            f"IV.POS.7 Tier-S batch {batch_idx}/7. seed={seed}, 4 jobs (V2..V5). "
            f"Wall ~5h on EPYC 9354. Node order (matches orchestrator --nodes): "
            + ", ".join(f"{n}={v}" for n, v in zip(TIER_S_NODES, [V2, V3, V4, V5]))
            + ". Reference: PHASE_8_PLAN.md §3.2 (batched-parallel)."
        ),
        "name": name,
        "image": IMAGE,
        "no_internet": False,
        "guest_args": GUEST_ARGS,
        "jobs": [
            _job(V2, seed, N, TIER_S_NODES[0]),
            _job(V3, seed, N, TIER_S_NODES[1]),
            _job(V4, seed, N, TIER_S_NODES[2]),
            _job(V5, seed, N, TIER_S_NODES[3]),
        ],
    }


def make_tier_s_manifests() -> list[tuple[str, dict]]:
    """7 Tier-S batches, each running V2-V5 at one seed (seeds 1234..1240)."""
    out = []
    for i, seed in enumerate(SEEDS[:7], start=1):  # seeds[0..6] = 1234..1240
        m = _ts_batch(seed, i)
        out.append((m["name"], m))
    return out


# ---------- Tier-A batches (22 jobs, 6 batches; last has only 2) ----------

def _ta_batch(name: str, jobs: list[tuple[str, int]]) -> dict:
    """One Tier-A batch. jobs is a list of (strategy, seed) tuples; positions
    map to TIER_A_NODES via round-robin in dispatch_pos.py (with --nodes in
    the canonical TIER_A_NODES order).
    """
    assert len(jobs) <= 4, f"Tier-A batches must have <= 4 jobs (got {len(jobs)})"
    node_labels = TIER_A_NODES[: len(jobs)]
    return {
        "_doc": (
            f"IV.POS.7 Tier-A batch {name}. {len(jobs)} jobs. Wall ~5.3h on EPYC 7543. "
            f"Node order (matches orchestrator --nodes): "
            + ", ".join(f"{n}={s}@s={sd}" for n, (s, sd) in zip(node_labels, jobs))
            + ". Reference: PHASE_8_PLAN.md §3.2 (batched-parallel)."
        ),
        "name": f"pos_iv_pos_7_{name}",
        "image": IMAGE,
        "no_internet": False,
        "guest_args": GUEST_ARGS,
        "jobs": [_job(strat, seed, N, node) for (strat, seed), node in zip(jobs, node_labels)],
    }


def make_tier_a_manifests() -> list[tuple[str, dict]]:
    """6 Tier-A batches covering V1 x 10 seeds + V2-V5 x seeds 1241-1243."""
    batches: list[tuple[str, list[tuple[str, int]]]] = [
        # ta_b1: V1 x 4 seeds (1234-1237)
        ("ta_b1", [(V1, 1234), (V1, 1235), (V1, 1236), (V1, 1237)]),
        # ta_b2: V1 x 4 seeds (1238-1241)
        ("ta_b2", [(V1, 1238), (V1, 1239), (V1, 1240), (V1, 1241)]),
        # ta_b3: V1 x 2 (1242, 1243) + V2 + V3 at seed 1241
        # Position 0 (algofi)=V1, 1 (gard)=V1, 2 (goracle)=V2, 3 (zone)=V3
        ("ta_b3", [(V1, 1242), (V1, 1243), (V2, 1241), (V3, 1241)]),
        # ta_b4: V4@1241, V5@1241, V2@1242, V3@1242
        # Position 0 (algofi)=V4, 1 (gard)=V5, 2 (goracle)=V2, 3 (zone)=V3
        ("ta_b4", [(V4, 1241), (V5, 1241), (V2, 1242), (V3, 1242)]),
        # ta_b5: V4@1242, V5@1242, V2@1243, V3@1243
        ("ta_b5", [(V4, 1242), (V5, 1242), (V2, 1243), (V3, 1243)]),
        # ta_b6: V4@1243, V5@1243 (2 jobs only; nodes algofi, gard)
        ("ta_b6", [(V4, 1243), (V5, 1243)]),
    ]
    out = []
    for name, jobs in batches:
        m = _ta_batch(name, jobs)
        out.append((m["name"], m))
    return out


# ---------- Smoke manifest ----------

def make_smoke_manifest() -> dict:
    """Tiny N=20 smoke exercising all 5 strategies end-to-end on 5 nodes.

    Used by the orchestrator's --smoke mode to validate the dispatcher, the v2
    telemetry tables, and per-strategy code paths before launching the 13-batch
    full campaign (~35h compute). Fits in any 5-node reservation; the current
    reservation 1751 (flare/meld/octorand/opulous/polynize, 4h remaining as of
    2026-06-13 21:38 UTC) is enough for this smoke.
    """
    smoke_nodes = ["flare", "octorand", "opulous", "polynize", "meld"]
    return {
        "_doc": (
            "IV.POS.7 SMOKE: N=20 per variant, 5 strategies on 5 nodes (~3 min wall). "
            "Validates: (a) all 5 v2 selectors run, (b) all v2 telemetry tables "
            "populate, (c) per-node attribution works, (d) bundle extracts cleanly, "
            "(e) the new batched-runner template can dispatch end-to-end."
        ),
        "name": "pos_iv_pos_7_smoke",
        "image": IMAGE,
        "no_internet": False,
        "guest_args": GUEST_ARGS,
        "jobs": [_job(strat, 9999, 20, node) for strat, node in zip(ALL_VARIANTS, smoke_nodes)],
    }


# ---------- Dispatch plan ----------

def make_dispatch_plan(tier_s: list[tuple[str, dict]], tier_a: list[tuple[str, dict]]) -> dict:
    """Plan summary written to _dispatch_plan.json. Pure metadata."""
    def _summarise(name: str, m: dict) -> dict:
        return {
            "manifest_name": name,
            "manifest_path": f"a4/pos/manifests/iv_pos_7/{name}.json",
            "n_jobs": len(m["jobs"]),
            "jobs": [
                {
                    "strategy": j["strategy"],
                    "seed": j["seed"],
                    "n": j["n"],
                    "node_label": j["node_label"],
                }
                for j in m["jobs"]
            ],
        }

    total_jobs = sum(len(m["jobs"]) for _, m in tier_s) + sum(len(m["jobs"]) for _, m in tier_a)

    # Per-variant node distribution sanity report
    variant_node_count: dict[str, dict[str, int]] = {v: {} for v in ALL_VARIANTS}
    for _, m in tier_s + tier_a:
        for job in m["jobs"]:
            d = variant_node_count.setdefault(job["strategy"], {})
            d[job["node_label"]] = d.get(job["node_label"], 0) + 1

    return {
        "_doc": (
            "IV.POS.7 batched-parallel dispatch plan. 50 total jobs (5 variants x 10 seeds) "
            "split across 13 sequential batches in 2 independent tier runners. "
            "Total compute: ~250 node-hours; wall (8-node parallel) ~35h. "
            "See PHASE_8_PLAN.md §3 for the design rationale."
        ),
        "N": N,
        "seeds": SEEDS,
        "n_variants": len(ALL_VARIANTS),
        "total_jobs": total_jobs,
        "n_tier_s_batches": len(tier_s),
        "n_tier_a_batches": len(tier_a),
        "tier_s_node_order": TIER_S_NODES,
        "tier_a_node_order": TIER_A_NODES,
        "estimated_wall_hr": {
            "tier_s_runner": round(len(tier_s) * 5.0, 1),
            "tier_a_runner": round(len(tier_a) * 5.3, 1),
            "total_with_3.5h_tier_a_delay": round(max(len(tier_s) * 5.0, 3.5 + len(tier_a) * 5.3), 1),
        },
        "tier_s_batches": [_summarise(n, m) for n, m in tier_s],
        "tier_a_batches": [_summarise(n, m) for n, m in tier_a],
        "per_variant_node_counts": variant_node_count,
    }


# ---------- Main ----------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--out-dir",
        default="a4/pos/manifests/iv_pos_7",
        help="Output directory for manifests",
    )
    p.add_argument(
        "--purge-old",
        action="store_true",
        help="Remove old pos_iv_pos_7_d*.json (by-seed model) before generating new ones",
    )
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.purge_old:
        for f in out_dir.glob("pos_iv_pos_7_d*.json"):
            print(f"removing legacy by-seed manifest {f.name}")
            f.unlink()

    tier_s = make_tier_s_manifests()
    tier_a = make_tier_a_manifests()
    smoke = make_smoke_manifest()
    plan = make_dispatch_plan(tier_s, tier_a)

    for name, m in tier_s + tier_a:
        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(m, indent=2))
        print(f"wrote {path} ({len(m['jobs'])} jobs)")

    smoke_path = out_dir / "pos_iv_pos_7_smoke.json"
    smoke_path.write_text(json.dumps(smoke, indent=2))
    print(f"wrote {smoke_path} (smoke, N=20 x 5)")

    plan_path = out_dir / "_dispatch_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2))
    print(f"wrote {plan_path}")

    total_jobs = sum(len(m["jobs"]) for _, m in tier_s + tier_a)
    print(
        f"\nGenerated {len(tier_s)} Tier-S batches + {len(tier_a)} Tier-A batches "
        f"= {total_jobs} jobs (target 50). Smoke + plan written too."
    )
    return 0 if total_jobs == 50 else 1


if __name__ == "__main__":
    raise SystemExit(main())
