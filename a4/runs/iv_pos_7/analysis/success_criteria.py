"""Phase 9.3 — Pro §10 success criteria (mechanical evaluation)."""
from __future__ import annotations

from typing import List

import numpy as np
import pandas as pd

from .stats import paired_tests, REFERENCE_VARIANT
from .metrics import N_MUTATIONS

CRITERIA = [
    ("criterion_1_auc_beats_v1", "AUC > zoned_current with p<0.05"),
    ("criterion_2_final_lower_variance", "Final coverage ≥ zoned with σ_variant/σ_V1 < 0.7"),
    ("criterion_3_faster_to_43", "time_to_43 / V1_time_to_43 < 0.7"),
    ("criterion_4_local_and_global", "local ≥ zoned AND compressed-global > zoned + 20%"),
    ("criterion_5_novel_locs", "Discovered constraint loc(s) not in V1 union"),
]


def evaluate_success_criteria(
    metrics_df: pd.DataFrame,
    paired_df: pd.DataFrame | None = None,
    reference: str = REFERENCE_VARIANT,
) -> pd.DataFrame:
    """Return (variant, criterion, passed, evidence_value) rows → D8."""
    if paired_df is None:
        paired_df = paired_tests(metrics_df, reference=reference)

    ref = metrics_df[metrics_df["variant"] == reference]
    ref_mean_final = ref["local_context_final"].mean()
    ref_std_final = ref["local_context_final"].std(ddof=1)
    ref_mean_auc = ref["local_context_AUC"].mean()
    ref_mean_cgc = ref["compressed_global_context_final"].mean()
    ref_t43 = ref["time_to_43"].dropna()
    ref_mean_t43 = float(ref_t43.mean()) if len(ref_t43) else float(N_MUTATIONS)

    rows: List[dict] = []
    variants = [v for v in metrics_df["variant"].unique() if v != reference]

    for variant in sorted(variants):
        sub = metrics_df[metrics_df["variant"] == variant]
        mean_final = sub["local_context_final"].mean()
        std_final = sub["local_context_final"].std(ddof=1)
        mean_auc = sub["local_context_AUC"].mean()
        mean_cgc = sub["compressed_global_context_final"].mean()
        novel_union = int(sub["novel_locs_union_vs_v1"].iloc[0])
        t43 = sub["time_to_43"].dropna()
        mean_t43 = float(t43.mean()) if len(t43) else float(N_MUTATIONS)

        # Criterion 1
        prow = paired_df[
            (paired_df["variant"] == variant) & (paired_df["metric"] == "local_context_AUC")
        ]
        if len(prow):
            pval = float(prow.iloc[0]["paired_t_pvalue"])
            diff = float(prow.iloc[0]["mean_diff"])
            c1 = diff > 0 and pval < 0.05
            ev1 = f"ΔAUC={diff:.0f}, p={pval:.4f}"
        else:
            c1, ev1 = False, "no paired data"

        # Criterion 2: final ≥ V1 mean AND variance ratio < 0.7
        var_ratio = std_final / ref_std_final if ref_std_final > 0 else float("inf")
        c2 = mean_final >= ref_mean_final and var_ratio < 0.7
        ev2 = f"mean_final={mean_final:.2f} vs V1={ref_mean_final:.2f}, σ_ratio={var_ratio:.3f}"

        # Criterion 3
        ratio_t43 = mean_t43 / ref_mean_t43 if ref_mean_t43 > 0 else float("inf")
        c3 = ratio_t43 < 0.7
        ev3 = f"mean_t43={mean_t43:.0f} / V1={ref_mean_t43:.0f} = {ratio_t43:.3f}"

        # Criterion 4
        cgc_thresh = ref_mean_cgc * 1.2
        c4 = mean_final >= ref_mean_final and mean_cgc > cgc_thresh
        ev4 = f"local={mean_final:.2f}≥{ref_mean_final:.2f}, CGC={mean_cgc:.0f}>{cgc_thresh:.0f}"

        # Criterion 5
        c5 = novel_union > 0
        ev5 = f"novel_locs_union_vs_v1={novel_union}"

        for crit_id, crit_desc, passed, ev in [
            (CRITERIA[0][0], CRITERIA[0][1], c1, ev1),
            (CRITERIA[1][0], CRITERIA[1][1], c2, ev2),
            (CRITERIA[2][0], CRITERIA[2][1], c3, ev3),
            (CRITERIA[3][0], CRITERIA[3][1], c4, ev4),
            (CRITERIA[4][0], CRITERIA[4][1], c5, ev5),
        ]:
            rows.append({
                "variant": variant,
                "criterion_id": crit_id,
                "criterion": crit_desc,
                "passed": bool(passed),
                "evidence": ev,
            })

    return pd.DataFrame(rows)
