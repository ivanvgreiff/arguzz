#!/usr/bin/env python3
"""D1.C Batch 1 — 30-DB Tier-1 signal audit CSV."""

from __future__ import annotations

import csv
import math
import sqlite3
import sys
from pathlib import Path
from statistics import median
from typing import List

REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
D1C = Path(__file__).resolve().parents[1]
D1B_ANALYSIS = REPO / "a4/runs/iv_pos_8/d1b/analysis"
OUT_CSV = D1C / "d1c_batch1_tier1_audit.csv"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(D1B_ANALYSIS))

from build_batch1_audit import cat_a_db_list  # noqa: E402  # D1.B source of truth

from analysis.bug_proximity import (  # noqa: E402
    CONTINUOUS_TIER1_SIGNALS,
    NON_SATURATION_MIN_FIRE_RATE,
    NON_SATURATION_WINDOW,
    TIER1_SIGNALS,
    extract_tier1_signals_per_db,
    fire_rate,
)

CONTINUOUS_FIRE_THRESHOLD = NON_SATURATION_MIN_FIRE_RATE


def _fire_count(signal: List[int | float], is_continuous: bool) -> int:
    if is_continuous:
        return sum(1 for v in signal if v >= CONTINUOUS_FIRE_THRESHOLD)
    return sum(1 for v in signal if v == 1)


def audit_db(corpus: str, variant: str, seed: int, db_path: Path) -> List[dict]:
    with sqlite3.connect(db_path) as conn:
        n_mut = int(conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0])

    signals = extract_tier1_signals_per_db(db_path)
    for name in TIER1_SIGNALS:
        if len(signals[name]) != n_mut:
            raise SystemExit(
                f"{db_path}: signal {name} length {len(signals[name])} != {n_mut}"
            )

    rows: List[dict] = []
    for name in TIER1_SIGNALS:
        sig = signals[name]
        is_cont = name in CONTINUOUS_TIER1_SIGNALS
        fc = _fire_count(sig, is_cont)
        fr_full = fc / n_mut if n_mut else 0.0
        fr_post = fire_rate(
            sig,
            NON_SATURATION_WINDOW,
            is_continuous=is_cont,
            threshold=CONTINUOUS_FIRE_THRESHOLD,
        )
        med = ""
        if is_cont:
            med = median(sig)
        rows.append(
            {
                "corpus": corpus,
                "variant": variant,
                "seed": seed,
                "signal_name": name,
                "n_mutations": n_mut,
                "fire_count": fc,
                "fire_rate_full": round(fr_full, 6),
                "fire_rate_post_local": round(fr_post, 6),
                "median_value": "" if med == "" else round(med, 6),
            }
        )
    return rows


def run_audit() -> List[dict]:
    all_rows: List[dict] = []
    for corpus, variant, seed, db_path in cat_a_db_list():
        all_rows.extend(audit_db(corpus, variant, seed, db_path))

    if len(all_rows) != 150:
        raise SystemExit(f"expected 150 audit rows, got {len(all_rows)}")

    for row in all_rows:
        for field in ("fire_rate_full", "fire_rate_post_local"):
            v = row[field]
            if v is None or (isinstance(v, float) and math.isnan(v)):
                raise SystemExit(f"NaN in {field}: {row}")
            if not (0.0 <= float(v) <= 1.0):
                raise SystemExit(f"fire_rate out of range: {row}")

    fieldnames = [
        "corpus",
        "variant",
        "seed",
        "signal_name",
        "n_mutations",
        "fire_count",
        "fire_rate_full",
        "fire_rate_post_local",
        "median_value",
    ]
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_rows)
    return all_rows


def main() -> int:
    rows = run_audit()
    print(f"wrote {OUT_CSV} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
