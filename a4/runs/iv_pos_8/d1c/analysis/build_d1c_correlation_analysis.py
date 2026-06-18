#!/usr/bin/env python3
"""D1.C Batch 3 — cross-correlation + non-saturation analysis."""

from __future__ import annotations

import csv
import math
import sys
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
D1C = Path(__file__).resolve().parents[1]
D1B_ANALYSIS = REPO / "a4/runs/iv_pos_8/d1b/analysis"

CORR_CSV = D1C / "d1c_correlation_matrix.csv"
THRESH_CSV = D1C / "d1c_recent_marginal_thresholds.csv"
NONSAT_CSV = D1C / "d1c_non_saturation.csv"
AUDIT_CSV = D1C / "d1c_batch1_tier1_audit.csv"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(D1B_ANALYSIS))

from build_batch1_audit import cat_a_db_list  # noqa: E402
from build_d1c_artifacts import normalize_provenance  # noqa: E402

from analysis.bug_proximity import (  # noqa: E402
    CONTINUOUS_TIER1_SIGNALS,
    CORRELATION_THRESHOLD,
    NON_SATURATION_MIN_FIRE_RATE,
    NON_SATURATION_WINDOW,
    TIER1_SIGNALS,
    compute_correlation_matrix,
    compute_disjoint_fire_rate,
    discretize_continuous_signal,
    extract_existing_channels_per_db,
    extract_tier1_signals_per_db,
    fire_rate,
    pearson_r,
)

CHANNELS = ("discovery_binary_reward", "f_new_flag")
THRESHOLD_PCTS = (25, 50, 75)
POST_LOCAL_N = NON_SATURATION_WINDOW[1] - NON_SATURATION_WINDOW[0]


def build_correlation_rows() -> List[dict]:
    rows: List[dict] = []
    for corpus, variant, seed, db_path in cat_a_db_list():
        norm_corpus, norm_variant = normalize_provenance(corpus, variant)
        signals = extract_tier1_signals_per_db(db_path)
        channels = extract_existing_channels_per_db(db_path)
        matrix = compute_correlation_matrix(signals, channels)
        for sig_name in TIER1_SIGNALS:
            for ch_name in CHANNELS:
                if sig_name == "f_new_flag" and ch_name == "f_new_flag":
                    continue
                rows.append({
                    "corpus": norm_corpus,
                    "variant": norm_variant,
                    "seed": seed,
                    "signal_name": sig_name,
                    "channel_name": ch_name,
                    "pearson_r": round(matrix[sig_name][ch_name], 6),
                    "n_pulls": POST_LOCAL_N,
                })
    return rows


def build_threshold_rows() -> List[dict]:
    rows: List[dict] = []
    sig_name = "recent_marginal_discovery_rate"
    for corpus, variant, seed, db_path in cat_a_db_list():
        norm_corpus, norm_variant = normalize_provenance(corpus, variant)
        signals = extract_tier1_signals_per_db(db_path)
        channels = extract_existing_channels_per_db(db_path)
        post_local = signals[sig_name][NON_SATURATION_WINDOW[0] : NON_SATURATION_WINDOW[1]]
        if not post_local:
            continue
        for pct in THRESHOLD_PCTS:
            thresh_val = float(np.percentile(post_local, pct))
            discretized = [
                discretize_continuous_signal(float(v), thresh_val) for v in post_local
            ]
            for ch_name in CHANNELS:
                ch_slice = channels[ch_name][
                    NON_SATURATION_WINDOW[0] : NON_SATURATION_WINDOW[1]
                ]
                r, note = pearson_r(discretized, ch_slice)
                rows.append({
                    "corpus": norm_corpus,
                    "variant": norm_variant,
                    "seed": seed,
                    "threshold_pct": pct,
                    "threshold_value": round(thresh_val, 6),
                    "channel_name": ch_name,
                    "pearson_r": round(r, 6),
                    "note": note,
                })
    return rows


def build_non_saturation_rows() -> List[dict]:
    audit = pd.read_csv(AUDIT_CSV)
    rows: List[dict] = []
    for _, row in audit.iterrows():
        rows.append({
            "corpus": row["corpus"],
            "variant": row["variant"],
            "seed": int(row["seed"]),
            "signal_name": row["signal_name"],
            "fire_rate_full": row["fire_rate_full"],
            "fire_rate_post_local": row["fire_rate_post_local"],
            "passes_5pct_gate": bool(
                float(row["fire_rate_post_local"]) > NON_SATURATION_MIN_FIRE_RATE
            ),
        })
    return rows


def validate_correlation(rows: List[dict]) -> None:
    if len(rows) != 270:
        raise SystemExit(f"expected 270 correlation rows, got {len(rows)}")
    for row in rows:
        r = row["pearson_r"]
        if r is None or math.isnan(r):
            raise SystemExit(f"NaN pearson_r: {row}")
        if not (-1.0 <= float(r) <= 1.0):
            raise SystemExit(f"pearson_r out of range: {row}")


def main() -> int:
    corr_rows = build_correlation_rows()
    validate_correlation(corr_rows)
    thresh_rows = build_threshold_rows()
    nonsat_rows = build_non_saturation_rows()

    if len(thresh_rows) != 180:
        raise SystemExit(f"expected 180 threshold rows, got {len(thresh_rows)}")

    fieldnames = list(corr_rows[0].keys())
    with CORR_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(corr_rows)

    with THRESH_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(thresh_rows[0].keys()))
        w.writeheader()
        w.writerows(thresh_rows)

    with NONSAT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(nonsat_rows[0].keys()))
        w.writeheader()
        w.writerows(nonsat_rows)

    print(f"wrote {CORR_CSV} ({len(corr_rows)} rows)")
    print(f"wrote {THRESH_CSV} ({len(thresh_rows)} rows)")
    print(f"wrote {NONSAT_CSV} ({len(nonsat_rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
