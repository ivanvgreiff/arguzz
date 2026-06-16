#!/usr/bin/env python3
"""Regenerate all Phase 9 CSV/JSON artifacts from analysis modules."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.metrics import compute_metrics_frame, aggregate_by_variant
from analysis.stats import paired_tests
from analysis.success_criteria import evaluate_success_criteria
from analysis.collection_validator import write_collection_report
from analysis.counterfactuals import (
    counterfactual_by_kind_frame,
    counterfactual_kind_summary,
    instr_type_mod_ranking_check,
)
from analysis.per_arm_diagnostic import per_arm_diagnostic_frame, v5_mode_summary
from analysis.discovery_rate import (
    discovery_rate_by_kind_frame,
    discovery_rate_summary,
    discovery_rate_v1_vs_v5_delta,
)
from analysis.per_loc_v2 import per_loc_v2_cells_frame, per_loc_v2_summary


def main() -> int:
    print("=== IV.POS.7 artifact build ===")

    metrics = compute_metrics_frame()
    metrics.to_csv(ROOT / "metrics_table.csv", index=False)
    aggregate_by_variant(metrics).to_csv(ROOT / "metrics_aggregate.csv", index=False)
    print(f"metrics_table.csv: {len(metrics)} rows")

    paired = paired_tests(metrics)
    paired.to_csv(ROOT / "paired_tests.csv", index=False)
    print(f"paired_tests.csv: {len(paired)} rows")

    success = evaluate_success_criteria(metrics, paired)
    success.to_csv(ROOT / "success_criteria.csv", index=False)
    print(f"success_criteria.csv: {len(success)} rows")

    rep = write_collection_report(ROOT / "COLLECTION_REPORT_FINAL.json")
    print(f"COLLECTION_REPORT_FINAL.json: {rep['passed']}/{rep['found_dbs']} PASS")

    cf = counterfactual_by_kind_frame()
    cf.to_csv(ROOT / "counterfactual_by_kind.csv", index=False)
    cf_sum = counterfactual_kind_summary(cf)
    cf_sum.to_csv(ROOT / "counterfactual_kind_summary.csv", index=False)
    ranking = instr_type_mod_ranking_check(cf_sum)
    ranking_doc = {
        "_note": "SUPERSEDED: use discovery_rate_by_kind.csv for Pro §12 per-kind diagnosis. Boolean mean-reward rank is misleading.",
        "ranking": ranking,
    }
    (ROOT / "counterfactual_instr_type_mod_ranking.json").write_text(
        json.dumps(ranking_doc, indent=2)
    )
    print("counterfactual CSVs + INSTR_TYPE_MOD ranking JSON")

    v5 = per_arm_diagnostic_frame()
    v5["mode_totals"].to_csv(ROOT / "v5_mode_totals.csv", index=False)
    v5["pulls_by_mode_arm"].to_csv(ROOT / "v5_pulls_by_mode_arm.csv", index=False)
    v5["final_arm_state"].to_csv(ROOT / "v5_final_arm_state.csv", index=False)
    v5["cumulative_reward_by_arm"].to_csv(ROOT / "v5_cumulative_reward_by_arm.csv", index=False)
    v5_mode_summary(v5["mode_totals"]).to_csv(ROOT / "v5_mode_summary.csv", index=False)
    print("V5 per-arm diagnostic CSVs")

    # Novel contexts report
    v5_novel = metrics[metrics["variant"] == "V5"]["novel_locs_names_vs_v1"]
    all_novel = set()
    for s in v5_novel:
        if s:
            all_novel.update(s.split(";"))
    novel_report = {
        "v1_union_size": 46,
        "v5_union_size": 50,
        "novel_locs_union_vs_v1": sorted(all_novel),
    }
    (ROOT / "v5_novel_contexts.json").write_text(json.dumps(novel_report, indent=2))
    print(f"v5_novel_contexts.json: {len(all_novel)} novel locs")

    dr = discovery_rate_by_kind_frame()
    dr.to_csv(ROOT / "discovery_rate_by_kind_per_seed.csv", index=False)
    dr_sum = discovery_rate_summary(dr)
    dr_sum.to_csv(ROOT / "discovery_rate_by_kind.csv", index=False)
    discovery_rate_v1_vs_v5_delta(dr_sum).to_csv(
        ROOT / "discovery_rate_v1_vs_v5_delta.csv", index=False
    )
    print("discovery_rate_by_kind.csv + delta")

    pl = per_loc_v2_cells_frame()
    pl.to_csv(ROOT / "per_loc_v2_cells_per_seed.csv", index=False)
    per_loc_v2_summary(pl).to_csv(ROOT / "per_loc_v2_cells.csv", index=False)
    print("per_loc_v2_cells.csv")

    print("=== DONE ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
