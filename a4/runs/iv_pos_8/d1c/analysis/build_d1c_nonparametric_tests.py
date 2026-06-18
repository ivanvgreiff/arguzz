#!/usr/bin/env python3
"""Wilcoxon signed-rank tests for discrete Tier-2 metrics."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd
from scipy import stats

REPO = Path(__file__).resolve().parents[5]
D1C = Path(__file__).resolve().parents[1]
METRICS_CSV = D1C / "d1c_metrics_table.csv"
OUT_CSV = D1C / "d1c_nonparametric_tests.csv"

PAIRED_SEEDS = [1234, 1235, 1236, 1237, 1238]
COMPARISONS = (
    ("V5_decayexp", "V5", "V5_decayexp vs V5"),
    ("V5_decayepoch", "V5", "V5_decayepoch vs V5"),
    ("V5_decayexp", "V5_decayepoch", "V5_decayexp vs V5_decayepoch"),
)
NONPARAM_METRICS = (
    "cat_a_pro_s5_d_loc_p95",
    "cat_a_pro_s5_verifier_accepted_invalid_count",
)


def build_tests(df: pd.DataFrame) -> pd.DataFrame:
    paired_df = df[df["seed"].isin(PAIRED_SEEDS)].copy()
    rows: List[dict] = []
    for metric in NONPARAM_METRICS:
        for variant_a, variant_b, comparison in COMPARISONS:
            sub_a = paired_df[paired_df["variant"] == variant_a].set_index("seed")
            sub_b = paired_df[paired_df["variant"] == variant_b].set_index("seed")
            common = sorted(set(sub_a.index) & set(sub_b.index))
            vals_a = [float(sub_a.loc[s, metric]) for s in common]
            vals_b = [float(sub_b.loc[s, metric]) for s in common]
            n = len(vals_a)
            if n < 2:
                rows.append({
                    "metric": metric,
                    "comparison": comparison,
                    "n_paired": n,
                    "mean_a": float(np.mean(vals_a)) if vals_a else float("nan"),
                    "mean_b": float(np.mean(vals_b)) if vals_b else float("nan"),
                    "wilcoxon_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": "insufficient paired rows",
                })
                continue
            a = np.array(vals_a)
            b = np.array(vals_b)
            if np.all(a == b):
                rows.append({
                    "metric": metric,
                    "comparison": comparison,
                    "n_paired": n,
                    "mean_a": float(a.mean()),
                    "mean_b": float(b.mean()),
                    "wilcoxon_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": "identical values",
                })
                continue
            try:
                stat, p_val = stats.wilcoxon(a, b, alternative="two-sided")
            except ValueError as exc:
                rows.append({
                    "metric": metric,
                    "comparison": comparison,
                    "n_paired": n,
                    "mean_a": float(a.mean()),
                    "mean_b": float(b.mean()),
                    "wilcoxon_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": str(exc),
                })
                continue
            rows.append({
                "metric": metric,
                "comparison": comparison,
                "n_paired": n,
                "mean_a": float(a.mean()),
                "mean_b": float(b.mean()),
                "wilcoxon_stat": float(stat),
                "p_value": float(p_val),
                "note": "",
            })
    return pd.DataFrame(rows)


def main() -> int:
    df = pd.read_csv(METRICS_CSV)
    out = build_tests(df)
    out.to_csv(OUT_CSV, index=False)
    print(f"wrote {OUT_CSV} ({len(out)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
