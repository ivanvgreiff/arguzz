#!/usr/bin/env python3
"""D1.C Batch 2 — Tier-2 per-campaign metrics + paired tests."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
D1C = Path(__file__).resolve().parents[1]
D1B_ANALYSIS = REPO / "a4/runs/iv_pos_8/d1b/analysis"
IV7_DBS = IV7 / "dbs"
D1A_DBS = D1C.parent / "d1a" / "dbs"

METRICS_CSV = D1C / "d1c_metrics_table.csv"
PAIRED_CSV = D1C / "d1c_paired_tests.csv"
UNPAIRED_CSV = D1C / "d1c_unpaired_means.csv"
UNPAIRED_SUMMARY_CSV = D1C / "d1c_unpaired_summary.csv"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(D1B_ANALYSIS))

from build_batch1_audit import cat_a_db_list  # noqa: E402  # D1.B source of truth

from analysis.bug_proximity import (  # noqa: E402
    TIER2_CSV_COLUMNS,
    compute_tier2_metrics_row,
)
from analysis.discover import discover_dbs  # noqa: E402

PAIRED_SEEDS = [1234, 1235, 1236, 1237, 1238]
UNPAIRED_SEEDS = [1239, 1240, 1241, 1242, 1243]
COMPARISONS = (
    ("V5_decayexp", "V5", "V5_decayexp vs V5"),
    ("V5_decayepoch", "V5", "V5_decayepoch vs V5"),
    ("V5_decayexp", "V5_decayepoch", "V5_decayexp vs V5_decayepoch"),
)


def normalize_provenance(corpus: str, variant: str) -> Tuple[str, str]:
    if corpus.startswith("D1.A-decayexp"):
        return "D1A", "V5_decayexp"
    if corpus.startswith("D1.A-decayepoch"):
        return "D1A", "V5_decayepoch"
    return corpus, variant


def build_metrics_table() -> Tuple[pd.DataFrame, List[dict]]:
    rows: List[dict] = []
    internals: List[dict] = []
    for corpus, variant, seed, db_path in cat_a_db_list():
        norm_corpus, norm_variant = normalize_provenance(corpus, variant)
        metrics = compute_tier2_metrics_row(db_path)
        row = {
            "corpus": norm_corpus,
            "variant": norm_variant,
            "seed": seed,
        }
        for col in TIER2_CSV_COLUMNS:
            row[col] = metrics[col]
        rows.append(row)
        internals.append({
            "local_context_final": metrics["_local_context_final"],
            "d_loc_median": metrics["_d_loc_median"],
        })
    return pd.DataFrame(rows), internals


def check_sanity_invariants(
    df: pd.DataFrame, internals: List[dict]
) -> List[str]:
    violations: List[str] = []
    for (_, row), internal in zip(df.iterrows(), internals):
        sfr = row["cat_a_pro_s5_singleton_failure_rate"]
        if not (0.0 <= float(sfr) <= 1.0):
            violations.append(
                f"singleton_rate out of range seed={row['seed']} variant={row['variant']}: {sfr}"
            )

        p95 = float(row["cat_a_pro_s5_d_loc_p95"])
        med = float(internal["d_loc_median"])
        if p95 < med:
            violations.append(
                f"d_loc p95 < median seed={row['seed']} variant={row['variant']}: {p95} < {med}"
            )

        local_final = int(internal["local_context_final"])
        for col in (
            "cat_a_pro_s8_unique_locs_with_d_loc_le_2",
            "cat_a_pro_s8_unique_locs_with_d_glob_le_1",
        ):
            if int(row[col]) > local_final:
                violations.append(
                    f"{col} > local_context_final seed={row['seed']}: "
                    f"{row[col]} > {local_final}"
                )

        is_r2 = row["corpus"] in ("V1", "V5")
        for col in (
            "cat_b_pro_s5_proof_generated_zero_residue_rejected_rate",
            "cat_b_pro_b_wall_clock_per_normalized_discovery",
        ):
            if is_r2 and pd.notna(row[col]):
                violations.append(
                    f"Cat-B should be NaN on R2 seed={row['seed']} variant={row['variant']} {col}={row[col]}"
                )
            if not is_r2 and pd.isna(row[col]):
                violations.append(
                    f"Cat-B should be populated on D1A seed={row['seed']} variant={row['variant']} {col}"
                )

    if df.shape != (30, 11):
        violations.append(f"expected shape (30, 11), got {df.shape}")
    return violations


def build_paired_tests(df: pd.DataFrame) -> pd.DataFrame:
    rows: List[dict] = []
    paired_df = df[df["seed"].isin(PAIRED_SEEDS)].copy()

    for metric in TIER2_CSV_COLUMNS:
        for variant_a, variant_b, comparison in COMPARISONS:
            sub_a = paired_df[paired_df["variant"] == variant_a].set_index("seed")
            sub_b = paired_df[paired_df["variant"] == variant_b].set_index("seed")
            common = sorted(set(sub_a.index) & set(sub_b.index))
            vals_a = []
            vals_b = []
            for seed in common:
                va = sub_a.loc[seed, metric]
                vb = sub_b.loc[seed, metric]
                if pd.isna(va) or pd.isna(vb):
                    continue
                vals_a.append(float(va))
                vals_b.append(float(vb))
            n = len(vals_a)
            if n < 2:
                rows.append({
                    "metric": metric,
                    "comparison": comparison,
                    "n_paired": n,
                    "mean_a": float(np.mean(vals_a)) if vals_a else float("nan"),
                    "mean_b": float(np.mean(vals_b)) if vals_b else float("nan"),
                    "mean_diff": float("nan"),
                    "t_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": "insufficient paired non-null rows",
                })
                continue
            a = np.array(vals_a)
            b = np.array(vals_b)
            diffs = a - b
            if diffs.var(ddof=1) == 0 or np.all(diffs == 0):
                t_stat, p_val = float("nan"), float("nan")
                note = "identical values; t-stat undefined"
            else:
                t_stat, p_val = stats.ttest_rel(a, b)
                note = ""
            rows.append({
                "metric": metric,
                "comparison": comparison,
                "n_paired": n,
                "mean_a": float(a.mean()),
                "mean_b": float(b.mean()),
                "mean_diff": float(a.mean() - b.mean()),
                "t_stat": float(t_stat),
                "p_value": float(p_val),
                "note": note,
            })
    return pd.DataFrame(rows)


def build_unpaired_means(df: pd.DataFrame) -> pd.DataFrame:
    sub = df[(df["variant"] == "V5") & (df["seed"].isin(UNPAIRED_SEEDS))].copy()
    sub = sub.sort_values("seed")
    out_cols = ["seed"] + list(TIER2_CSV_COLUMNS)
    return sub[out_cols].reset_index(drop=True)


def build_unpaired_summary(df: pd.DataFrame) -> pd.DataFrame:
    sub = df[(df["variant"] == "V5") & (df["seed"].isin(UNPAIRED_SEEDS))]
    rows: List[dict] = []
    for metric in TIER2_CSV_COLUMNS:
        vals = sub[metric].dropna().astype(float)
        rows.append({
            "metric": metric,
            "mean": float(vals.mean()) if len(vals) else float("nan"),
            "std": float(vals.std(ddof=1)) if len(vals) > 1 else 0.0,
            "n_seeds": len(vals),
        })
    return pd.DataFrame(rows)


def main() -> int:
    metrics, internals = build_metrics_table()
    violations = check_sanity_invariants(metrics, internals)
    if violations:
        for v in violations:
            print(f"SANITY FAIL: {v}", file=sys.stderr)
        raise SystemExit(1)

    paired = build_paired_tests(metrics)
    unpaired = build_unpaired_means(metrics)
    unpaired_summary = build_unpaired_summary(metrics)

    metrics.to_csv(METRICS_CSV, index=False)
    paired.to_csv(PAIRED_CSV, index=False)
    unpaired.to_csv(UNPAIRED_CSV, index=False)
    unpaired_summary.to_csv(UNPAIRED_SUMMARY_CSV, index=False)

    print(f"wrote {METRICS_CSV} shape={metrics.shape}")
    print(f"wrote {PAIRED_CSV} ({len(paired)} rows)")
    print(f"wrote {UNPAIRED_CSV} ({len(unpaired)} rows)")
    print(f"wrote {UNPAIRED_SUMMARY_CSV} ({len(unpaired_summary)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
