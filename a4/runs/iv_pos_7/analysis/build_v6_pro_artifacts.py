#!/usr/bin/env python3
"""Build Pro-facing V6 vs A4 CSV artifacts (V1/V5/V6 focus)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(ROOT))

import pandas as pd

from analysis.metrics import compute_internal_metrics_frame
from analysis.v6_comparison import build_v6_outputs
from analysis.kind_translation import kind_translation_frame, kind_translation_summary

PRO_VARIANTS = ("V1", "V5", "V6")
PRO_ANCHOR_VARIANTS = ("V0", "V1", "V5", "V6")


def build_pro_metrics(metrics: pd.DataFrame) -> pd.DataFrame:
    sub = metrics[metrics["variant"].isin(PRO_ANCHOR_VARIANTS)].copy()
    sub["partial"] = False
    return sub.sort_values(["variant", "seed"]).reset_index(drop=True)


def build_pro_kind_translation(dbs_root: Path) -> pd.DataFrame:
    per_seed = kind_translation_frame(dbs_root, variants=PRO_VARIANTS)
    summary = kind_translation_summary(per_seed)
    return summary


def main() -> int:
    print("=== V6 Pro-facing artifact build ===")
    dbs_root = ROOT / "dbs"

    metrics = compute_internal_metrics_frame(dbs_root)
    v6_out = build_v6_outputs(metrics, dbs_root=dbs_root, root=ROOT)

    pro_metrics = build_pro_metrics(metrics)
    pro_metrics.to_csv(ROOT / "v6_pro_metrics_table.csv", index=False)
    print(f"v6_pro_metrics_table.csv: {len(pro_metrics)} rows")

    v6_out["apples_to_apples"].to_csv(ROOT / "v6_pro_apples_to_apples.csv", index=False)
    print("v6_pro_apples_to_apples.csv: 1 row")

    terr = v6_out["territory_coverage"]
    terr[terr["variant"].isin(PRO_VARIANTS)].to_csv(
        ROOT / "v6_pro_territory_coverage.csv", index=False
    )
    print(f"v6_pro_territory_coverage.csv: {len(terr[terr.variant.isin(PRO_VARIANTS)])} rows")

    kind = build_pro_kind_translation(dbs_root)
    kind.to_csv(ROOT / "v6_pro_kind_translation.csv", index=False)
    print(f"v6_pro_kind_translation.csv: {len(kind)} rows")

    v6_out["v5_novel_overlap"].to_csv(ROOT / "v6_pro_v5_novel_overlap.csv", index=False)
    print(f"v6_pro_v5_novel_overlap.csv: {len(v6_out['v5_novel_overlap'])} rows")

    # Summary for Batch 5 report-back
    v6 = metrics[metrics["variant"] == "V6"]
    v1 = metrics[metrics["variant"] == "V1"]
    v5 = metrics[metrics["variant"] == "V5"]
    ata = v6_out["apples_to_apples"].iloc[0]
    summary = {
        "v6_seeds": len(v6),
        "v6_partial": bool(v6["partial"].any()) if "partial" in v6.columns else False,
        "v6_mean_local_context_final": float(v6["local_context_final"].mean()),
        "v6_mean_cgc": float(v6["compressed_global_context_final"].mean()),
        "v1_mean_local_context_final": float(v1["local_context_final"].mean()),
        "v5_mean_local_context_final": float(v5["local_context_final"].mean()),
        "v6_full_union_normalized": int(ata["v6_full_coverage_normalized"]),
        "v6_a4_reachable_normalized": int(ata["v6_a4_reachable_normalized"]),
        "v6_reachable_fraction_normalized": float(ata["v6_reachable_fraction_normalized"]),
        "v6_cgc_reachable_fraction": float(ata["v6_cgc_reachable_fraction"]),
        "territory_v1": int(terr[terr.variant == "V1"].iloc[0]["locs_in_a4_territory"]),
        "territory_v5": int(terr[terr.variant == "V5"].iloc[0]["locs_in_a4_territory"]),
        "territory_v6": int(terr[terr.variant == "V6"].iloc[0]["locs_in_a4_territory"]),
        "v5_novel_v6_hits": int(v6_out["v5_novel_overlap"]["v6_hit"].sum()),
    }
    (ROOT / "v6_pro_build_summary.json").write_text(json.dumps(summary, indent=2))
    print("\n=== Pro CSV summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\n=== DONE (Pro CSVs) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
