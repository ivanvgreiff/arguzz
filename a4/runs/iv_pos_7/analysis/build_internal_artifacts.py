#!/usr/bin/env python3
"""Build internal V0/V6 artifacts — writes internal_*.csv, never overwrites R2 deliverables."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(ROOT))

from analysis.discover import ALL_VARIANTS_ORDER, discover_status
from analysis.metrics import compute_internal_metrics_frame, aggregate_by_variant
from analysis.v0_anchor import build_v0_anchor_outputs
from analysis.v6_comparison import build_v6_outputs


def _print_v6_fairness(v6_out: dict, status: dict) -> None:
    print("\n=== V6 fairness (Batch 3) ===")
    ata = v6_out["apples_to_apples"]
    if not ata.empty:
        r = ata.iloc[0]
        print(
            f"V6 apples-to-apples (normalized): {int(r['v6_a4_reachable_normalized'])}/"
            f"{int(r['v6_full_coverage_normalized'])} locs "
            f"({r['v6_reachable_fraction_normalized']*100:.1f}% A4-reachable) | "
            f"V6-exclusive: {int(r['v6_exclusive_vs_a4_normalized'])} "
            f"({r['v6_exclusive_fraction_normalized']*100:.1f}%)"
        )
        print(
            f"  RAW keying (misleading): {int(r['v6_a4_reachable_raw'])}/"
            f"{int(r['v6_full_coverage_raw'])} overlap — V6 uses different constraint_loc format"
        )
        if "v6_cgc_reachable_fraction" in r:
            print(
                f"CGC apples-to-apples: {int(r['v6_a4_reachable_cgc'])}/"
                f"{int(r['v6_full_cgc'])} ctx_keys "
                f"({r['v6_cgc_reachable_fraction']*100:.1f}% A4-reachable)"
            )

    overlap = v6_out["loc_overlap"]
    norm = overlap[overlap["keying"] == "normalized"]
    for name in (
        "V5_novel_4_hit_by_V6",
        "V5_novel_4_missed_by_V6",
        "V6_exclusive_vs_A4",
        "V6_intersect_A4_reachable",
    ):
        row = norm[norm["set_name"] == name]
        if not row.empty:
            print(f"  {name}: count={int(row.iloc[0]['count'])} "
                  f"sample={row.iloc[0]['sample_locs'][:80]}")

    cmp_df = v6_out["v6_vs_v1_v5"]
    if not cmp_df.empty:
        for ref in ("V1", "V5"):
            sub = cmp_df[
                (cmp_df["reference"] == ref)
                & (cmp_df["metric"] == "local_context_final")
            ]
            if not sub.empty:
                s = sub.iloc[0]
                caveat = " [n<5 preview]" if s["small_n_caveat"] else ""
                print(
                    f"  V6 vs {ref} loc: V6={s['v6_mean']:.1f}, "
                    f"{ref}={s['reference_mean']:.1f}, "
                    f"Δ={s['mean_diff']:+.1f} ({s['mean_diff_pct']:+.1f}%){caveat}"
                )

    inv = v6_out["kind_inventory"]
    if not inv.empty:
        v6_inv = inv[inv["variant"] == "V6"]
        for _, row in v6_inv.iterrows():
            print(
                f"  V6 {row['kind_group']}: pulls={row['total_pulls']}, "
                f"discoveries={row['total_discoveries']}"
            )

    terr = v6_out.get("territory_coverage")
    if terr is not None and not terr.empty:
        print("  A4-territory coverage (normalized, 51-loc union):")
        for _, row in terr.iterrows():
            print(
                f"    {row['variant']}: {int(row['locs_in_a4_territory'])}/"
                f"{int(row['a4_territory_size'])} "
                f"({row['territory_coverage_pct']:.0f}%)"
            )

    if status.get("v6_partial"):
        print(f"  NOTE: V6 partial ({status['v6_seed_count']}/10 seeds) — re-sync before final pass")


def _print_spot_checks(metrics, status: dict) -> None:
    print("\n=== Spot checks ===")
    print(f"Discover status: {json.dumps(status)}")

    if status["v0_seed_count"]:
        v0 = metrics[metrics["variant"] == "V0"]
        print(f"V0 rows: {len(v0)}")
        print(
            f"  V0 mean local_context_final: {v0['local_context_final'].mean():.1f} "
            f"(expect ~35–40, below V1's 42.9)"
        )
        print(f"  V0 mean CGC: {v0['compressed_global_context_final'].mean():.1f}")
        print(
            f"  V0 mean zone entropy: {v0['allocation_entropy_by_zone'].mean():.3f} "
            f"(V1={metrics[metrics['variant']=='V1']['allocation_entropy_by_zone'].mean():.3f}, "
            f"V5={metrics[metrics['variant']=='V5']['allocation_entropy_by_zone'].mean():.3f})"
        )
        for _, row in v0.sort_values("seed").iterrows():
            print(
                f"  seed {row['seed']}: loc={row['local_context_final']}, "
                f"cgc={row['compressed_global_context_final']}, "
                f"zone_H={row['allocation_entropy_by_zone']:.3f}"
            )
    else:
        print("V0: no DBs found — run sync_internal_dbs.sh from coinbase-accessible host")

    if status["v6_seed_count"]:
        v6 = metrics[metrics["variant"] == "V6"]
        print(f"V6 rows: {len(v6)} (partial={status['v6_partial']})")
        print(f"  V6 mean local_context_final: {v6['local_context_final'].mean():.1f}")
        print(f"  V6 mean CGC: {v6['compressed_global_context_final'].mean():.1f}")
        print(f"  V6 mean zone entropy: {v6['allocation_entropy_by_zone'].mean():.3f}")
        for _, row in v6.sort_values("seed").iterrows():
            print(
                f"  seed {row['seed']}: loc={row['local_context_final']}, "
                f"cgc={row['compressed_global_context_final']}, "
                f"zone_H={row['allocation_entropy_by_zone']:.3f}"
            )
    else:
        print("V6: no DBs found — run sync_internal_dbs.sh from coinbase-accessible host")

    v1_mean = metrics[metrics["variant"] == "V1"]["local_context_final"].mean()
    v5_mean = metrics[metrics["variant"] == "V5"]["local_context_final"].mean()
    print(f"\nReference (from synced set): V1 mean loc={v1_mean:.1f}, V5 mean loc={v5_mean:.1f}")


def main() -> int:
    print("=== IV.POS.7 internal artifact build (V0/V6 track) ===")

    status = discover_status()
    metrics = compute_internal_metrics_frame()

    # partial=True on V6 rows until all 10 seeds land.
    metrics["partial"] = False
    if status["v6_partial"] and status["v6_seed_count"] > 0:
        metrics.loc[metrics["variant"] == "V6", "partial"] = True

    out_metrics = ROOT / "internal_metrics_table.csv"
    metrics.to_csv(out_metrics, index=False)
    print(f"internal_metrics_table.csv: {len(metrics)} rows → {out_metrics}")

    agg = aggregate_by_variant(metrics)
    out_agg = ROOT / "internal_metrics_aggregate.csv"
    agg.to_csv(out_agg, index=False)
    print(f"internal_metrics_aggregate.csv: {len(agg)} variants → {out_agg}")

    # Sanity: R2 metrics_table.csv must remain untouched.
    r2_metrics = ROOT / "metrics_table.csv"
    if r2_metrics.exists():
        import pandas as pd
        r2 = pd.read_csv(r2_metrics)
        assert len(r2) == 50, "R2 metrics_table.csv row count changed unexpectedly"
        assert set(r2["variant"]) == {"V1", "V2", "V3", "V4", "V5"}
        print(f"R2 metrics_table.csv: UNTOUCHED ({len(r2)} rows)")

    counts = metrics.groupby("variant").size().reindex(ALL_VARIANTS_ORDER, fill_value=0)
    print("\nPer-variant row counts:")
    for v, n in counts.items():
        flag = ""
        if v == "V6" and status["v6_partial"] and n > 0:
            flag = " [PARTIAL]"
        elif v in ("V0", "V6") and n == 0:
            flag = " [MISSING — sync needed]"
        print(f"  {v}: {n}{flag}")

    _print_spot_checks(metrics, status)

    # Batch 2: V0 anchor analysis
    anchor, paired_v0, sanity = build_v0_anchor_outputs(metrics)
    if not paired_v0.empty:
        pt_cols = paired_v0[["variant", "metric", "n_pairs", "paired_t_pvalue", "mean_diff"]].rename(
            columns={"mean_diff": "paired_mean_diff", "n_pairs": "paired_n_pairs"}
        )
        anchor = anchor.merge(pt_cols, on=["variant", "metric"], how="left")
    else:
        anchor["paired_n_pairs"] = float("nan")
        anchor["paired_t_pvalue"] = float("nan")
        anchor["paired_mean_diff"] = float("nan")

    out_anchor = ROOT / "internal_v0_anchor.csv"
    anchor.to_csv(out_anchor, index=False)
    print(f"\ninternal_v0_anchor.csv: {len(anchor)} rows → {out_anchor}")

    out_sanity = ROOT / "internal_v0_sanity.json"
    out_sanity.write_text(json.dumps(sanity, indent=2))
    print(f"internal_v0_sanity.json → {out_sanity}")
    print(
        f"V0 sanity: loc mean={sanity['v0_local_context_final_mean']:.1f} "
        f"std={sanity['v0_local_context_final_std']:.2f} "
        f"range=[{sanity['v0_local_context_final_min']},{sanity['v0_local_context_final_max']}]"
    )
    print(
        f"V1 CGC delta vs V0: {sanity['v1_cgc_delta_pct_vs_v0']:+.1f}% "
        f"(O1: zoned prior buys little on CGC)"
    )
    print(
        f"Zone entropy: V0={sanity['v0_zone_entropy_mean']:.3f}, "
        f"V1={sanity['v1_zone_entropy_mean']:.3f}, "
        f"V5={sanity['v5_zone_entropy_mean']:.3f}"
    )

    paired_v0.to_csv(ROOT / "internal_v0_paired_tests.csv", index=False)
    print(f"internal_v0_paired_tests.csv: {len(paired_v0)} rows")

    # Batch 3: V6 comparison + fairness decomposition
    v6_out = build_v6_outputs(metrics, root=ROOT)
    v6_out["v6_vs_v1_v5"].to_csv(ROOT / "internal_v6_vs_v1_v5.csv", index=False)
    v6_out["v6_paired_tests"].to_csv(ROOT / "internal_v6_paired_tests.csv", index=False)
    v6_out["loc_overlap"].to_csv(ROOT / "internal_v6_v1_v5_loc_overlap.csv", index=False)
    v6_out["kind_translation"].to_csv(ROOT / "internal_v6_kind_translation.csv", index=False)
    v6_out["kind_inventory"].to_csv(ROOT / "internal_v6_kind_inventory.csv", index=False)
    v6_out["apples_to_apples"].to_csv(ROOT / "internal_v6_apples_to_apples.csv", index=False)
    v6_out["territory_coverage"].to_csv(ROOT / "internal_v6_territory_coverage.csv", index=False)
    print(
        f"\nBatch 3 CSVs: v6_vs_v1_v5={len(v6_out['v6_vs_v1_v5'])}, "
        f"loc_overlap={len(v6_out['loc_overlap'])}, "
        f"kind_translation={len(v6_out['kind_translation'])}"
    )
    _print_v6_fairness(v6_out, status)

    print("\n=== DONE (internal only) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
