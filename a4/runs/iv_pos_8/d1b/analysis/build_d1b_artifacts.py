#!/usr/bin/env python3
"""Build IV.POS.8 D1.B Batch 2 analysis CSVs + summary JSON."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

D1B_ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
IV7_ANALYSIS = IV7 / "analysis"
R2_DBS = IV7 / "dbs"
D1A_DBS = D1B_ROOT.parent / "d1a" / "dbs"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analysis.discover import discover_dbs  # noqa: E402
from analysis.metrics import (  # noqa: E402
    N_MUTATIONS,
    _coverage_curve,
    _time_to_threshold,
)
from d1b_cgc_maps import (  # noqa: E402
    VARIANTS,
    split_memory_lookup_counts,
    variant_first_hit_map,
)
from replay_cgc_corrected import (  # noqa: E402
    replay_lookup_first_hits,
    replay_memory_first_hits,
)

CORPUS_VARIANTS = ("V5", "V5-decayexp", "V5-decayepoch")
BIN_SIZE = 100
TIME_PCTS = (10, 50, 90)
PAIRED_METRICS = (
    "cgc_final",
    "memory_final",
    "auc_normalized",
    "time_to_10",
    "time_to_50",
    "time_to_90",
)
COMPARISONS = (
    ("V5-decayexp", "V5", "V5-decayexp vs V5"),
    ("V5-decayepoch", "V5", "V5-decayepoch vs V5"),
    ("V5-decayexp", "V5-decayepoch", "V5-decayexp vs V5-decayepoch"),
)


def discover_decay_corpus() -> Dict[str, Dict[int, Path]]:
    r2 = discover_dbs(R2_DBS, variants=("V5",))
    d1a = discover_dbs(D1A_DBS, variants=("V5-decayexp", "V5-decayepoch"))
    return {
        "V5": r2["V5"],
        "V5-decayexp": d1a["V5-decayexp"],
        "V5-decayepoch": d1a["V5-decayepoch"],
    }


def paired_triplet_seeds(corpus: Dict[str, Dict[int, Path]]) -> List[int]:
    seeds = set(corpus["V5"])
    for v in ("V5-decayexp", "V5-decayepoch"):
        seeds &= set(corpus[v])
    return sorted(seeds)


def _time_to_pct(curve: np.ndarray, final: int, pct: int) -> Optional[int]:
    if final <= 0 or len(curve) == 0:
        return None
    target = max(1, math.ceil(final * pct / 100.0))
    return _time_to_threshold(curve, target)


def _auc_normalized(curve: np.ndarray, final: int) -> float:
    if final <= 0 or len(curve) == 0:
        return float("nan")
    denom = N_MUTATIONS * final
    return float(np.trapezoid(curve, dx=1.0)) / denom


def compute_variant_metrics(
    db_path: Path,
    corpus_variant: str,
    seed: int,
    cgc_variant: str,
    *,
    memory_hits: Dict[str, int],
    lookup_hits: Dict[str, int],
    conn: sqlite3.Connection,
) -> Dict[str, object]:
    first_hit_map = variant_first_hit_map(
        cgc_variant, memory_hits, lookup_hits, conn
    )

    memory_final, lookup_final = split_memory_lookup_counts(first_hit_map)
    cgc_final = len(first_hit_map)
    first_hits = sorted(first_hit_map.values())
    curve = _coverage_curve(first_hits, n=N_MUTATIONS)

    row: Dict[str, object] = {
        "corpus_variant": corpus_variant,
        "seed": seed,
        "cgc_variant": cgc_variant,
        "db_path": str(db_path),
        "cgc_final": cgc_final,
        "memory_final": memory_final,
        "lookup_final": lookup_final,
        "auc_normalized": _auc_normalized(curve, cgc_final),
    }
    for pct in TIME_PCTS:
        row[f"time_to_{pct}"] = _time_to_pct(curve, cgc_final, pct)
    return row


def collect_all_rows() -> pd.DataFrame:
    corpus = discover_decay_corpus()
    rows: List[Dict[str, object]] = []
    for corpus_variant in CORPUS_VARIANTS:
        for seed, db_path in sorted(corpus[corpus_variant].items()):
            with sqlite3.connect(db_path) as conn:
                memory_hits = replay_memory_first_hits(conn)
                lookup_hits = replay_lookup_first_hits(conn)
                for cgc_variant in VARIANTS:
                    rows.append(
                        compute_variant_metrics(
                            db_path,
                            corpus_variant,
                            seed,
                            cgc_variant,
                            memory_hits=memory_hits,
                            lookup_hits=lookup_hits,
                            conn=conn,
                        )
                    )
    return pd.DataFrame(rows)


def build_paired_tests(metrics: pd.DataFrame, seeds: List[int]) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    if len(seeds) < 3:
        for cgc_variant in VARIANTS:
            for metric in PAIRED_METRICS:
                for _, _, comp in COMPARISONS:
                    rows.append({
                        "cgc_variant": cgc_variant,
                        "metric": metric,
                        "comparison": comp,
                        "n_paired": len(seeds),
                        "mean_a": float("nan"),
                        "mean_b": float("nan"),
                        "mean_diff": float("nan"),
                        "t_stat": float("nan"),
                        "p_value": float("nan"),
                        "note": "n_paired too small",
                    })
        return pd.DataFrame(rows)

    sub = metrics[metrics["seed"].isin(seeds)].copy()
    for cgc_variant in VARIANTS:
        vsub = sub[sub["cgc_variant"] == cgc_variant]
        for metric in PAIRED_METRICS:
            for var_a, var_b, comp in COMPARISONS:
                a = (
                    vsub[vsub["corpus_variant"] == var_a]
                    .set_index("seed")[metric]
                    .astype(float)
                )
                b = (
                    vsub[vsub["corpus_variant"] == var_b]
                    .set_index("seed")[metric]
                    .astype(float)
                )
                aligned = pd.concat([a, b], axis=1, keys=("a", "b")).dropna()
                n = len(aligned)
                if n < 3:
                    rows.append({
                        "cgc_variant": cgc_variant,
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
                    "cgc_variant": cgc_variant,
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


def _bin_new_keys(first_hits: List[int], lo: int, hi: int) -> int:
    return sum(1 for fh in first_hits if lo <= fh < hi)


def build_saturation_profile(
    metrics: pd.DataFrame, paired_seeds: List[int]
) -> pd.DataFrame:
    """Per cgc_variant: first 100-step bin with <1 avg new keys (V5 paired seeds)."""
    rows: List[Dict[str, object]] = []
    bins = [(b, min(b + BIN_SIZE, N_MUTATIONS)) for b in range(0, N_MUTATIONS, BIN_SIZE)]

    for cgc_variant in VARIANTS:
        v5_sub = metrics[
            (metrics["cgc_variant"] == cgc_variant)
            & (metrics["corpus_variant"] == "V5")
            & (metrics["seed"].isin(paired_seeds))
        ]
        per_seed_hits: List[List[int]] = []
        for _, row in v5_sub.iterrows():
            with sqlite3.connect(Path(str(row["db_path"]))) as conn:
                memory_hits = replay_memory_first_hits(conn)
                lookup_hits = replay_lookup_first_hits(conn)
                fhm = variant_first_hit_map(
                    cgc_variant, memory_hits, lookup_hits, conn
                )
            per_seed_hits.append(sorted(fhm.values()))

        sat_bin_lo: Optional[int] = None
        sat_bin_hi: Optional[int] = None
        sat_avg: Optional[float] = None
        for lo, hi in bins:
            counts = [_bin_new_keys(hits, lo, hi) for hits in per_seed_hits]
            if not counts:
                continue
            mean_new = float(np.mean(counts))
            if mean_new < 1.0:
                sat_bin_lo, sat_bin_hi = lo, hi
                sat_avg = mean_new
                break

        saturation_mutation_id = sat_bin_hi
        saturation_cgc_d: Optional[int] = None
        if saturation_mutation_id is not None:
            cum_at_sat: List[int] = []
            for hits in per_seed_hits:
                curve = _coverage_curve(hits, n=N_MUTATIONS)
                idx = saturation_mutation_id - 1
                if 0 <= idx < len(curve):
                    cum_at_sat.append(int(curve[idx]))
            if cum_at_sat:
                saturation_cgc_d = int(round(float(np.mean(cum_at_sat))))

        rows.append({
            "cgc_variant": cgc_variant,
            "n_paired_seeds": len(paired_seeds),
            "saturation_bin_lo": sat_bin_lo,
            "saturation_bin_hi": sat_bin_hi,
            "saturation_mutation_id": saturation_mutation_id,
            "saturation_bin_avg_new_keys": sat_avg,
            "saturation_cgc_d": saturation_cgc_d,
        })
    return pd.DataFrame(rows)


def check_sanity_invariants(metrics: pd.DataFrame) -> List[str]:
    """Return list of invariant violation messages (empty = pass)."""
    violations: List[str] = []
    pivot = metrics.pivot_table(
        index=["corpus_variant", "seed"],
        columns="cgc_variant",
        values=["cgc_final", "memory_final", "lookup_final"],
        aggfunc="first",
    )

    ordering = ("region_only", "log4_explicit", "production_log2_corrected")
    for (corpus_variant, seed), row in pivot.iterrows():
        lookup_vals = {
            v: int(row[("lookup_final", v)])
            for v in VARIANTS
            if ("lookup_final", v) in row.index
        }
        if len(set(lookup_vals.values())) > 1:
            violations.append(
                f"lookup mismatch {corpus_variant} s{seed}: {lookup_vals}"
            )

        for field, label in (("memory_final", "memory"), ("cgc_final", "hybrid")):
            r = int(row[(field, "region_only")])
            l4 = int(row[(field, "log4_explicit")])
            p = int(row[(field, "production_log2_corrected")])
            if not (r <= l4 <= p):
                violations.append(
                    f"{label} ordering fail {corpus_variant} s{seed}: "
                    f"region_only={r} log4={l4} production={p}"
                )

        mem_r = int(row[("memory_final", "region_only")])
        if mem_r <= 5:
            violations.append(
                f"region_only_memory too low {corpus_variant} s{seed}: {mem_r}"
            )

        mem_pc = int(row[("memory_final", "page_class")])
        if mem_pc < 6 or mem_pc > 25:
            violations.append(
                f"page_class_memory out of range {corpus_variant} s{seed}: {mem_pc}"
            )

    return violations


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_summary(
    metrics: pd.DataFrame,
    paired: pd.DataFrame,
    saturation: pd.DataFrame,
    paired_seeds: List[int],
    sanity_violations: List[str],
) -> dict:
    git_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()

    def _mean(cgc_variant: str, corpus_variant: str, col: str) -> float:
        s = metrics.loc[
            (metrics["cgc_variant"] == cgc_variant)
            & (metrics["corpus_variant"] == corpus_variant),
            col,
        ].astype(float)
        return float(s.mean()) if len(s) else float("nan")

    headline: Dict[str, object] = {}
    for cv in VARIANTS:
        headline[f"mean_cgc_final_{cv}_V5"] = _mean(cv, "V5", "cgc_final")
        headline[f"mean_cgc_final_{cv}_decayexp"] = _mean(
            cv, "V5-decayexp", "cgc_final"
        )
        headline[f"mean_cgc_final_{cv}_decayepoch"] = _mean(
            cv, "V5-decayepoch", "cgc_final"
        )

    return {
        "n_dbs": int(len(metrics) / len(VARIANTS)),
        "n_rows_metrics": len(metrics),
        "n_cgc_variants": len(VARIANTS),
        "paired_seeds": paired_seeds,
        "n_paired_seeds": len(paired_seeds),
        "sanity_pass": len(sanity_violations) == 0,
        "sanity_violations": sanity_violations,
        "headline": headline,
        "git_commit": git_commit,
    }


def write_sha256_manifest(paths: List[Path], manifest_path: Path) -> None:
    lines = [f"{_sha256(p)}  {p.name}\n" for p in paths]
    manifest_path.write_text("".join(lines))


def main() -> int:
    print("=== D1.B Batch 2 artifact build ===")
    corpus = discover_decay_corpus()
    n_dbs = sum(len(corpus[v]) for v in CORPUS_VARIANTS)
    if n_dbs != 20:
        raise SystemExit(f"expected 20 DBs, got {n_dbs}")

    paired_seeds = paired_triplet_seeds(corpus)
    print(f"corpus: V5={len(corpus['V5'])}, decayexp={len(corpus['V5-decayexp'])}, "
          f"decayepoch={len(corpus['V5-decayepoch'])}")
    print(f"paired seeds: {paired_seeds}")

    metrics = collect_all_rows()
    metrics = metrics.sort_values(
        ["corpus_variant", "seed", "cgc_variant"]
    ).reset_index(drop=True)
    paired = build_paired_tests(metrics, paired_seeds)
    saturation = build_saturation_profile(metrics, paired_seeds)
    sanity_violations = check_sanity_invariants(metrics)
    summary = build_summary(
        metrics, paired, saturation, paired_seeds, sanity_violations
    )

    metrics_path = D1B_ROOT / "d1b_metrics_table.csv"
    paired_path = D1B_ROOT / "d1b_paired_tests.csv"
    sat_path = D1B_ROOT / "d1b_saturation_profile.csv"
    summary_path = D1B_ROOT / "d1b_build_summary.json"
    manifest_path = D1B_ROOT / "d1b_artifacts.sha256"

    metrics.to_csv(metrics_path, index=False)
    paired.to_csv(paired_path, index=False, na_rep="nan")
    saturation.to_csv(sat_path, index=False)
    summary_path.write_text(json.dumps(summary, indent=2))
    write_sha256_manifest(
        [metrics_path, paired_path, sat_path, summary_path], manifest_path
    )

    print(f"d1b_metrics_table.csv: {len(metrics)} rows")
    print(f"d1b_paired_tests.csv: {len(paired)} rows")
    print(f"d1b_saturation_profile.csv: {len(saturation)} rows")

    print("\n=== Headline (V5 mean cgc_final) ===")
    for cv in VARIANTS:
        v = summary["headline"][f"mean_cgc_final_{cv}_V5"]
        print(f"  {cv}: {v:.1f}")

    print("\n=== Sanity invariants ===")
    if sanity_violations:
        print(f"FAIL ({len(sanity_violations)} violations):")
        for v in sanity_violations[:10]:
            print(f"  - {v}")
        if len(sanity_violations) > 10:
            print(f"  ... and {len(sanity_violations) - 10} more")
        return 1
    print("PASS")
    print("\n=== DONE ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
