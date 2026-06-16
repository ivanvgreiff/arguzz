"""Phase 9.2 statistical tests — paired vs reference variant (default V1)."""
from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from scipy import stats

REFERENCE_VARIANT = "V1"
V0_REFERENCE = "V0"
METRICS_FOR_TESTS: Tuple[str, ...] = ("local_context_AUC", "local_context_final")
MIN_PAIRS_FOR_PVALUE = 5


def _paired_series(
    df: pd.DataFrame,
    variant: str,
    metric: str,
    reference: str = REFERENCE_VARIANT,
) -> Optional[tuple]:
    """Align per-seed values for variant vs reference; drop NaN pairs."""
    a = df[df["variant"] == variant].set_index("seed")[metric]
    b = df[df["variant"] == reference].set_index("seed")[metric]
    common = sorted(set(a.index) & set(b.index))
    if len(common) < 2:
        return None
    x = a.loc[common].to_numpy(dtype=float)
    y = b.loc[common].to_numpy(dtype=float)
    mask = ~(np.isnan(x) | np.isnan(y))
    x, y = x[mask], y[mask]
    if len(x) < 2:
        return None
    return x, y


def paired_tests(
    df: pd.DataFrame,
    reference: str = REFERENCE_VARIANT,
    metrics: Optional[Sequence[str]] = None,
) -> pd.DataFrame:
    """Paired t-test, variance ratio, Mann-Whitney U for each variant × metric."""
    metric_list = tuple(metrics) if metrics is not None else METRICS_FOR_TESTS
    rows: List[dict] = []
    variants = sorted(v for v in df["variant"].unique() if v != reference)
    for variant in variants:
        for metric in metric_list:
            pair = _paired_series(df, variant, metric, reference)
            if pair is None:
                continue
            x, y = pair
            t_stat, t_p = stats.ttest_rel(x, y)
            var_ratio = (
                float(np.std(x, ddof=1) / np.std(y, ddof=1))
                if np.std(y, ddof=1) > 0
                else float("nan")
            )
            u_stat, u_p = stats.mannwhitneyu(x, y, alternative="two-sided")
            small_n = len(x) < MIN_PAIRS_FOR_PVALUE
            rows.append({
                "variant": variant,
                "reference": reference,
                "metric": metric,
                "n_pairs": len(x),
                "mean_variant": float(np.mean(x)),
                "mean_reference": float(np.mean(y)),
                "mean_diff": float(np.mean(x) - np.mean(y)),
                "std_variant": float(np.std(x, ddof=1)),
                "std_reference": float(np.std(y, ddof=1)),
                "variance_ratio": var_ratio,
                "paired_t_stat": float(t_stat),
                "paired_t_pvalue": float("nan") if small_n else float(t_p),
                "mannwhitney_u": float(u_stat),
                "mannwhitney_pvalue": float("nan") if small_n else float(u_p),
                "small_n_caveat": small_n,
            })
    return pd.DataFrame(rows)
