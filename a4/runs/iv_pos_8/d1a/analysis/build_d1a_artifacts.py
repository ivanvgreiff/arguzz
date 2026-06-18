#!/usr/bin/env python3
"""Build IV.POS.8 D1.A analysis CSVs + summary JSON."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
IV7_ANALYSIS = IV7 / "analysis"
R2_DBS = IV7 / "dbs"
D1A_DBS = ROOT / "dbs"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))

from analysis.discover import discover_dbs, parse_db_path  # noqa: E402
from analysis.metrics import (  # noqa: E402
    N_MUTATIONS,
    TIME_THRESHOLDS,
    _coverage_curve,
    _read_first_hits,
    _time_to_threshold,
    compute_metrics_for_db,
)

VARIANTS = ("V5", "V5-decayexp", "V5-decayepoch")
PAIRED_METRICS = (
    "local_context_final",
    "compressed_global_context_final",
    "auc_normalized",
    "time_to_43",
    "time_to_46",
)
COMPARISONS = (
    ("V5-decayexp", "V5", "V5-decayexp vs V5"),
    ("V5-decayepoch", "V5", "V5-decayepoch vs V5"),
    ("V5-decayexp", "V5-decayepoch", "V5-decayexp vs V5-decayepoch"),
)
BUCKETS: List[Tuple[int, int, str]] = [
    (0, 200, "[0,200)"),
    (200, 1000, "[200,1000)"),
    (1000, 2000, "[1000,2000)"),
    (2000, 4000, "[2000,4000)"),
    (4000, 6000, "[4000,6000)"),
]
MODES = ("cold", "singleton", "floor", "adaptive")
# Hardcoded against ~46 final contexts (R2 V5-static mean). V5 seed 1237 hits 48,
# so this denom is mildly low. AUC values can in principle exceed 1.0 if a DB
# discovers contexts very fast; in practice all observed values are < 1.0.
# If we ever see AUC > 1.0, switch to dynamic max(local_context_final) across set.
AUC_DENOM = N_MUTATIONS * 46


def _safe_count(conn: sqlite3.Connection, sql: str) -> Optional[int]:
    try:
        return int(conn.execute(sql).fetchone()[0])
    except sqlite3.OperationalError:
        return None


def _read_floor_schedule(conn: sqlite3.Connection) -> Tuple[str, dict]:
    try:
        row = conn.execute(
            "SELECT extra_json FROM campaign_params LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return "constant", {"value": 0.55}
    if not row or not row[0]:
        return "constant", {"value": 0.55}
    extra = json.loads(row[0])
    ftype = extra.get("floor_schedule_type", "constant")
    fcfg = extra.get("floor_schedule_config", {"value": 0.55})
    return str(ftype), fcfg


def _bandit_mode_stats(conn: sqlite3.Connection) -> Dict[str, float]:
    try:
        rows = conn.execute(
            "SELECT mutation_id, mode FROM bandit_decisions"
        ).fetchall()
    except sqlite3.OperationalError:
        return {
            "floor_mode_share_post_cs": float("nan"),
            "adaptive_mode_share_post_cs": float("nan"),
            "cold_decisions": float("nan"),
        }
    if not rows:
        return {
            "floor_mode_share_post_cs": float("nan"),
            "adaptive_mode_share_post_cs": float("nan"),
            "cold_decisions": float("nan"),
        }
    post = [(mid, mode) for mid, mode in rows if int(mid) > 200]
    n_post = len(post)
    if n_post == 0:
        floor_share = adaptive_share = float("nan")
    else:
        floor_share = sum(1 for _, m in post if m == "floor") / n_post
        adaptive_share = sum(1 for _, m in post if m == "adaptive") / n_post
    cold = sum(1 for _, m in rows if m == "cold")
    return {
        "floor_mode_share_post_cs": floor_share,
        "adaptive_mode_share_post_cs": adaptive_share,
        "cold_decisions": float(cold),
    }


def _d1a_telemetry(conn: sqlite3.Connection) -> Dict[str, Optional[float]]:
    pg = _safe_count(conn, "SELECT COUNT(*) FROM mutations WHERE proof_generated = 1")
    pvf = _safe_count(
        conn, "SELECT COUNT(*) FROM mutations WHERE proof_verify_failed = 1"
    )
    try:
        elapsed = conn.execute(
            "SELECT AVG(elapsed_ms) FROM mutations WHERE elapsed_ms IS NOT NULL"
        ).fetchone()
        mean_elapsed = (
            float(elapsed[0]) if elapsed and elapsed[0] is not None else None
        )
    except sqlite3.OperationalError:
        mean_elapsed = None
    if pg is None:
        return {
            "mean_elapsed_ms": None,
            "proof_generated_count": None,
            "proof_verify_failed_count": None,
        }
    return {
        "mean_elapsed_ms": mean_elapsed,
        "proof_generated_count": pg,
        "proof_verify_failed_count": pvf,
    }


def compute_d1a_row(db_path: Path) -> Dict[str, object]:
    base = compute_metrics_for_db(db_path, v1_union=None)
    variant = str(base["variant"])
    if variant == "V5":
        variant = "V5"
    with sqlite3.connect(db_path) as conn:
        first_hits = _read_first_hits(conn)
        curve = _coverage_curve(first_hits, n=N_MUTATIONS)
        auc_raw = float(base["local_context_AUC"])
        auc_norm = auc_raw / AUC_DENOM if AUC_DENOM else float("nan")
        total_failures = _safe_count(conn, "SELECT COUNT(*) FROM failures")
        unique_global = _safe_count(conn, "SELECT COUNT(*) FROM global_failures")
        ftype, fcfg = _read_floor_schedule(conn)
        mode_stats = _bandit_mode_stats(conn)
        telem = _d1a_telemetry(conn)

    row = {
        "variant": variant,
        "seed": int(base["seed"]),
        "db_path": str(db_path),
        "local_context_final": int(base["local_context_final"]),
        "compressed_global_context_final": int(base["compressed_global_context_final"]),
        "total_mutations": int(base["n_mutations"]),
        "total_failures": total_failures,
        "unique_global_failures": unique_global,
        "time_to_40": base.get("time_to_40"),
        "time_to_43": base.get("time_to_43"),
        "time_to_46": base.get("time_to_46"),
        "auc_normalized": auc_norm,
        "floor_mode_share_post_cs": mode_stats["floor_mode_share_post_cs"],
        "adaptive_mode_share_post_cs": mode_stats["adaptive_mode_share_post_cs"],
        "cold_decisions": mode_stats["cold_decisions"],
        "mean_elapsed_ms": telem["mean_elapsed_ms"],
        "proof_generated_count": telem["proof_generated_count"],
        "proof_verify_failed_count": telem["proof_verify_failed_count"],
        "floor_schedule_type": ftype,
        "floor_schedule_config": json.dumps(fcfg),
    }
    return row


def collect_all_rows() -> pd.DataFrame:
    r2 = discover_dbs(R2_DBS, variants=("V5",))
    d1a = discover_dbs(D1A_DBS, variants=("V5-decayexp", "V5-decayepoch"))
    rows: List[Dict[str, object]] = []
    for seed, path in sorted(r2["V5"].items()):
        rows.append(compute_d1a_row(path))
    for variant in ("V5-decayexp", "V5-decayepoch"):
        for seed, path in sorted(d1a[variant].items()):
            rows.append(compute_d1a_row(path))
    return pd.DataFrame(rows)


def paired_triplet_seeds(metrics: pd.DataFrame) -> List[int]:
    by_var: Dict[str, set] = {}
    for v in VARIANTS:
        by_var[v] = set(metrics.loc[metrics["variant"] == v, "seed"].astype(int))
    return sorted(by_var["V5"] & by_var["V5-decayexp"] & by_var["V5-decayepoch"])


def build_paired_tests(metrics: pd.DataFrame, seeds: List[int]) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    if len(seeds) < 3:
        for metric in PAIRED_METRICS:
            for _, _, comp in COMPARISONS:
                rows.append({
                    "metric": metric,
                    "comparison": comp,
                    "n_paired": len(seeds),
                    "mean_a": float("nan"),
                    "mean_b": float("nan"),
                    "mean_diff": float("nan"),
                    "t_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": "n_paired too small" if len(seeds) < 3 else "",
                })
        return pd.DataFrame(rows)

    sub = metrics[metrics["seed"].isin(seeds)].copy()
    for metric in PAIRED_METRICS:
        for var_a, var_b, comp in COMPARISONS:
            a = sub[sub["variant"] == var_a].set_index("seed")[metric].astype(float)
            b = sub[sub["variant"] == var_b].set_index("seed")[metric].astype(float)
            aligned = pd.concat([a, b], axis=1, keys=("a", "b")).dropna()
            n = len(aligned)
            if n < 3:
                rows.append({
                    "metric": metric,
                    "comparison": comp,
                    "n_paired": n,
                    "mean_a": float("nan"),
                    "mean_b": float("nan"),
                    "mean_diff": float("nan"),
                    "t_stat": float("nan"),
                    "p_value": float("nan"),
                    "note": "n_paired too small",
                })
                continue
            diffs = aligned["a"] - aligned["b"]
            if diffs.var(ddof=1) == 0 or diffs.eq(0).all():
                t_stat, p_val = float("nan"), float("nan")
                note = "identical values; t-stat undefined (zero variance in differences)"
            else:
                t_stat, p_val = stats.ttest_rel(aligned["a"], aligned["b"])
                note = ""
            rows.append({
                "metric": metric,
                "comparison": comp,
                "n_paired": n,
                "mean_a": float(aligned["a"].mean()),
                "mean_b": float(aligned["b"].mean()),
                "mean_diff": float(aligned["a"].mean() - aligned["b"].mean()),
                "t_stat": float(t_stat),
                "p_value": float(p_val),
                "note": note,
            })
    return pd.DataFrame(rows)


def _bucket_label(mutation_id: int) -> Optional[str]:
    for lo, hi, label in BUCKETS:
        if lo <= mutation_id < hi:
            return label
    return None


def build_floor_dynamics(metrics: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    for _, row in metrics.iterrows():
        db_path = Path(str(row["db_path"]))
        variant = str(row["variant"])
        seed = int(row["seed"])
        try:
            with sqlite3.connect(db_path) as conn:
                bd_rows = conn.execute(
                    "SELECT mutation_id, mode FROM bandit_decisions"
                ).fetchall()
        except sqlite3.OperationalError:
            continue
        counts: Dict[Tuple[str, str], int] = {}
        for mid, mode in bd_rows:
            label = _bucket_label(int(mid))
            if label is None or mode not in MODES:
                continue
            key = (label, str(mode))
            counts[key] = counts.get(key, 0) + 1
        for (bucket, mode), count in sorted(counts.items()):
            rows.append({
                "variant": variant,
                "seed": seed,
                "mutation_id_bucket": bucket,
                "mode": mode,
                "count": count,
            })
    return pd.DataFrame(rows)


def _floor_share_in_range(
    dynamics: pd.DataFrame,
    variant: str,
    lo: int,
    hi: int,
) -> float:
    bucket_labels = {label for blo, bhi, label in BUCKETS if blo >= lo and bhi <= hi}
    if not bucket_labels:
        bucket_labels = {
            label for blo, bhi, label in BUCKETS if not (bhi <= lo or blo >= hi)
        }
    sub = dynamics[
        (dynamics["variant"] == variant)
        & (dynamics["mutation_id_bucket"].isin(bucket_labels))
    ]
    if sub.empty:
        return float("nan")
    total = sub["count"].sum()
    floor = sub[sub["mode"] == "floor"]["count"].sum()
    return float(floor / total) if total else float("nan")


def build_summary(
    metrics: pd.DataFrame,
    paired: pd.DataFrame,
    dynamics: pd.DataFrame,
    paired_seeds: List[int],
) -> dict:
    git_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()

    def _mean(var: str, col: str) -> float:
        s = metrics.loc[metrics["variant"] == var, col].astype(float)
        return float(s.mean()) if len(s) else float("nan")

    def _pval(comp: str, metric: str = "local_context_final") -> float:
        row = paired[
            (paired["comparison"] == comp) & (paired["metric"] == metric)
        ]
        if row.empty:
            return float("nan")
        return float(row.iloc[0]["p_value"])

    decayexp = metrics[metrics["variant"] == "V5-decayexp"]
    decayepoch = metrics[metrics["variant"] == "V5-decayepoch"]

    return {
        "n_dbs_v5_static": int((metrics["variant"] == "V5").sum()),
        "n_dbs_v5_decayexp": int((metrics["variant"] == "V5-decayexp").sum()),
        "n_dbs_v5_decayepoch": int((metrics["variant"] == "V5-decayepoch").sum()),
        "n_paired_seeds": len(paired_seeds),
        "paired_seeds": paired_seeds,
        "mean_local_context_final_V5": _mean("V5", "local_context_final"),
        "mean_local_context_final_V5_decayexp": _mean(
            "V5-decayexp", "local_context_final"
        ),
        "mean_local_context_final_V5_decayepoch": _mean(
            "V5-decayepoch", "local_context_final"
        ),
        "mean_auc_normalized_V5": _mean("V5", "auc_normalized"),
        "mean_auc_normalized_V5_decayexp": _mean("V5-decayexp", "auc_normalized"),
        "mean_auc_normalized_V5_decayepoch": _mean("V5-decayepoch", "auc_normalized"),
        "mean_time_to_43_V5": _mean("V5", "time_to_43"),
        "mean_time_to_43_V5_decayexp": _mean("V5-decayexp", "time_to_43"),
        "mean_time_to_43_V5_decayepoch": _mean("V5-decayepoch", "time_to_43"),
        "paired_ttest_local_context_v5_vs_decayexp_p": _pval(
            "V5-decayexp vs V5"
        ),
        "paired_ttest_local_context_v5_vs_decayepoch_p": _pval(
            "V5-decayepoch vs V5"
        ),
        "paired_ttest_local_context_decayexp_vs_decayepoch_p": _pval(
            "V5-decayexp vs V5-decayepoch"
        ),
        "floor_share_decayexp_post200": float(
            decayexp["floor_mode_share_post_cs"].mean()
        )
        if len(decayexp)
        else float("nan"),
        "floor_share_decayepoch_bucket1_200_2000": _floor_share_in_range(
            dynamics, "V5-decayepoch", 200, 2000
        ),
        "floor_share_decayepoch_bucket2_2000_4000": _floor_share_in_range(
            dynamics, "V5-decayepoch", 2000, 4000
        ),
        "floor_share_decayepoch_bucket3_4000_6000": _floor_share_in_range(
            dynamics, "V5-decayepoch", 4000, 6000
        ),
        "git_commit": git_commit,
    }


def main() -> int:
    print("=== D1.A artifact build ===")
    metrics = collect_all_rows()
    metrics = metrics.sort_values(["variant", "seed"]).reset_index(drop=True)
    paired_seeds = paired_triplet_seeds(metrics)
    paired = build_paired_tests(metrics, paired_seeds)
    dynamics = build_floor_dynamics(metrics)
    summary = build_summary(metrics, paired, dynamics, paired_seeds)

    metrics.to_csv(ROOT / "d1a_metrics_table.csv", index=False)
    paired.to_csv(ROOT / "d1a_paired_tests.csv", index=False, na_rep="nan")
    dynamics.to_csv(ROOT / "d1a_floor_dynamics.csv", index=False)
    (ROOT / "d1a_build_summary.json").write_text(json.dumps(summary, indent=2))

    print(f"d1a_metrics_table.csv: {len(metrics)} rows")
    print(f"d1a_paired_tests.csv: {len(paired)} rows")
    print(f"d1a_floor_dynamics.csv: {len(dynamics)} rows")
    print(f"paired seeds: {paired_seeds}")

    print("\n=== Headline numbers ===")
    print(f"  mean local_context_final V5:          {summary['mean_local_context_final_V5']:.2f}")
    print(f"  mean local_context_final V5-decayexp: {summary['mean_local_context_final_V5_decayexp']:.2f}")
    print(f"  mean local_context_final V5-decayepoch: {summary['mean_local_context_final_V5_decayepoch']:.2f}")
    print(f"  paired p (V5 vs decayexp):          {summary['paired_ttest_local_context_v5_vs_decayexp_p']:.4f}")
    print(f"  paired p (V5 vs decayepoch):        {summary['paired_ttest_local_context_v5_vs_decayepoch_p']:.4f}")
    print(f"  floor mode share decayexp post-200: {summary['floor_share_decayexp_post200']:.3f}")

    print("\n=== DONE ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
