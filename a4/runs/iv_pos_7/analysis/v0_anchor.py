"""V0 anchor analysis — quantify structured-prior gain vs uniform random floor."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from .discover import R2_VARIANTS
from .stats import paired_tests

V0_REFERENCE = "V0"

# Metrics for anchor table (plan §2.1 + Opus O1/O6 zone entropy).
ANCHOR_METRICS: Tuple[str, ...] = (
    "local_context_final",
    "local_context_AUC",
    "compressed_global_context_final",
    "time_to_43",
    "local_coverage_v2_final",
    "allocation_entropy_by_zone",
    "allocation_entropy_by_kind",
)

# Subset used for paired t-tests vs V0 (time_to_43 often missing for V0).
PAIRED_TEST_METRICS: Tuple[str, ...] = (
    "local_context_final",
    "local_context_AUC",
    "compressed_global_context_final",
    "local_coverage_v2_final",
    "allocation_entropy_by_zone",
)

COMPARE_VARIANTS: Tuple[str, ...] = R2_VARIANTS  # V1–V5 vs V0


def _v0_baselines(df: pd.DataFrame) -> Dict[str, float]:
    v0 = df[df["variant"] == V0_REFERENCE]
    if v0.empty:
        raise ValueError("V0 rows missing from metrics frame")
    return {m: float(v0[m].mean()) for m in ANCHOR_METRICS}


def _pct_delta(delta_abs: float, baseline: float) -> float:
    if baseline == 0 or np.isnan(baseline):
        return float("nan")
    return 100.0 * delta_abs / baseline


def v0_anchor_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Per-variant Δ vs V0 (absolute + percent) for each anchor metric."""
    baselines = _v0_baselines(df)
    rows: List[dict] = []

    for variant in (V0_REFERENCE,) + COMPARE_VARIANTS:
        sub = df[df["variant"] == variant]
        if sub.empty:
            continue
        for metric in ANCHOR_METRICS:
            v0_mean = baselines[metric]
            # time_to_43: mean over seeds that reached threshold
            if metric == "time_to_43":
                vals = sub[metric].dropna()
                var_mean = float(vals.mean()) if len(vals) else float("nan")
                var_std = float(vals.std(ddof=1)) if len(vals) > 1 else float("nan")
                n_obs = len(vals)
            else:
                var_mean = float(sub[metric].mean())
                var_std = float(sub[metric].std(ddof=1))
                n_obs = len(sub)

            delta_abs = var_mean - v0_mean if variant != V0_REFERENCE else 0.0
            delta_pct = (
                0.0 if variant == V0_REFERENCE else _pct_delta(delta_abs, v0_mean)
            )
            rows.append({
                "variant": variant,
                "reference": V0_REFERENCE,
                "metric": metric,
                "v0_mean": v0_mean,
                "variant_mean": var_mean,
                "variant_std": var_std,
                "n_obs": n_obs,
                "delta_abs": delta_abs,
                "delta_pct": delta_pct,
            })
    return pd.DataFrame(rows)


def v0_paired_tests_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Paired tests V1–V5 vs V0 on shared seeds."""
    return paired_tests(df, reference=V0_REFERENCE, metrics=PAIRED_TEST_METRICS)


def v0_sanity_check(df: pd.DataFrame) -> Dict[str, object]:
    """V0 local_context_final should cluster ~33–37 (Opus §2.4)."""
    v0 = df[df["variant"] == V0_REFERENCE]
    loc = v0["local_context_final"]
    zone_ent = v0["allocation_entropy_by_zone"]
    return {
        "v0_n_seeds": len(v0),
        "v0_local_context_final_mean": float(loc.mean()),
        "v0_local_context_final_std": float(loc.std(ddof=1)),
        "v0_local_context_final_min": int(loc.min()),
        "v0_local_context_final_max": int(loc.max()),
        "v0_local_context_final_in_33_38": bool(loc.min() >= 33 and loc.max() <= 38),
        "v0_zone_entropy_mean": float(zone_ent.mean()),
        "v0_zone_entropy_std": float(zone_ent.std(ddof=1)),
        "v1_zone_entropy_mean": float(
            df[df["variant"] == "V1"]["allocation_entropy_by_zone"].mean()
        ),
        "v5_zone_entropy_mean": float(
            df[df["variant"] == "V5"]["allocation_entropy_by_zone"].mean()
        ),
        "v0_cgc_mean": float(v0["compressed_global_context_final"].mean()),
        "v1_cgc_mean": float(
            df[df["variant"] == "V1"]["compressed_global_context_final"].mean()
        ),
        "v1_cgc_delta_pct_vs_v0": _pct_delta(
            float(df[df["variant"] == "V1"]["compressed_global_context_final"].mean())
            - float(v0["compressed_global_context_final"].mean()),
            float(v0["compressed_global_context_final"].mean()),
        ),
    }


def build_v0_anchor_outputs(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, object]]:
    """Return (anchor_table, paired_tests, sanity_dict)."""
    anchor = v0_anchor_frame(df)
    paired = v0_paired_tests_frame(df)
    sanity = v0_sanity_check(df)
    return anchor, paired, sanity
