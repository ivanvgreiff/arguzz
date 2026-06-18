#!/usr/bin/env python3
"""Plot all 4 CGC coarsening variants on a single axis with local-sat anchor.

Visualizes the saturation-inversion finding from D1.B Batch 2:
- production_log2_corrected discovers past local saturation (small headroom)
- region_only/page_class/log4_explicit saturate ~1400-1900 muts BEFORE local

Inputs:
- replay_cgc_corrected.py memory/lookup helpers
- d1b_cgc_maps.py variant builders
- d1a_metrics_table.csv for local-sat anchor

Outputs:
- a4/runs/iv_pos_8/d1b/plots/d1b_saturation_overlay_v5.png      (absolute keys)
- a4/runs/iv_pos_8/d1b/plots/d1b_saturation_overlay_v5_norm.png (normalized)
"""

from __future__ import annotations

import sqlite3
import statistics
import sys
from pathlib import Path
from typing import Dict, List

REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
D1B = REPO / "a4/runs/iv_pos_8/d1b"
PLOTS = D1B / "plots"
PLOTS.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(D1B / "analysis"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from d1b_cgc_maps import VARIANTS, variant_first_hit_map  # noqa: E402
from replay_cgc_corrected import (  # noqa: E402
    _lookup_first_hits_from_hook3,
    _replay_memory_corrected,
)
from analysis.discover import discover_dbs  # noqa: E402

# V5 paired seeds (1234-1238) from R2 corpus
PAIRED_SEEDS = [1234, 1235, 1236, 1237, 1238]
LOCAL_SAT_MEAN = 3221  # mean(time_to_46) from d1a_metrics_table V5 paired
LOCAL_SAT_MEDIAN = 3099
TOTAL_MUTS = 6000

VARIANT_COLORS = {
    "production_log2_corrected": "#1f77b4",  # blue
    "region_only": "#d62728",  # red
    "log4_explicit": "#ff7f0e",  # orange
    "page_class": "#2ca02c",  # green
}
VARIANT_LABELS = {
    "production_log2_corrected": "production_log2_corrected (Batch 1.6 fix)",
    "region_only": "region_only",
    "log4_explicit": "log4_explicit",
    "page_class": "page_class (Batch 1.5 + 1.5b)",
}


def cumulative_curve(first_hit_map: Dict[str, int], total_muts: int) -> np.ndarray:
    """Convert {ctx_key: first_hit_mid} into cumulative count over mutation index."""
    curve = np.zeros(total_muts + 1, dtype=np.int32)
    for mid in first_hit_map.values():
        if 0 <= mid <= total_muts:
            curve[mid] += 1
    return np.cumsum(curve)


def compute_v5_curves() -> Dict[str, List[np.ndarray]]:
    """For each variant, return list of 5 cumulative curves (one per paired seed)."""
    out = {v: [] for v in VARIANTS}
    db_map = discover_dbs(IV7 / "dbs", variants=("V5",))
    for seed in PAIRED_SEEDS:
        db_path = db_map["V5"][seed]
        with sqlite3.connect(db_path) as conn:
            mem_hits, _, _ = _replay_memory_corrected(conn)
            lookup_hits, _ = _lookup_first_hits_from_hook3(conn)
            for variant in VARIANTS:
                m = variant_first_hit_map(variant, mem_hits, lookup_hits, conn)
                out[variant].append(cumulative_curve(m, TOTAL_MUTS))
    return out


def plot_overlay(curves: Dict[str, List[np.ndarray]], normalized: bool, out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(TOTAL_MUTS + 1)

    for variant in VARIANTS:
        stack = np.vstack(curves[variant])
        mean = stack.mean(axis=0)
        final = float(mean[-1])
        if normalized:
            mean = mean / final if final > 0 else mean
        std = stack.std(axis=0)
        if normalized:
            std = std / final if final > 0 else std
        ax.plot(
            x,
            mean,
            color=VARIANT_COLORS[variant],
            lw=2.0,
            label=f"{VARIANT_LABELS[variant]} (final={final:.0f})",
        )
        ax.fill_between(
            x,
            mean - std,
            mean + std,
            color=VARIANT_COLORS[variant],
            alpha=0.12,
            linewidth=0,
        )

    # Local-sat anchor lines
    ax.axvline(
        LOCAL_SAT_MEAN,
        color="black",
        linestyle="--",
        lw=1.4,
        label=f"local sat (mean time_to_46 = {LOCAL_SAT_MEAN})",
    )
    ax.axvline(
        LOCAL_SAT_MEDIAN,
        color="gray",
        linestyle=":",
        lw=1.2,
        label=f"local sat (median = {LOCAL_SAT_MEDIAN})",
    )

    # Saturation point markers from d1b_saturation_profile.csv
    sat_points = {
        "production_log2_corrected": (3400, 180),
        "region_only": (1300, 62),
        "log4_explicit": (1800, 84),
        "page_class": (1300, 67),
    }
    for variant, (sat_x, sat_y) in sat_points.items():
        y = sat_y / sat_points[variant][1] if normalized else sat_y
        ax.scatter(
            [sat_x],
            [y],
            color=VARIANT_COLORS[variant],
            edgecolor="black",
            s=80,
            zorder=5,
            marker="o",
        )

    ax.set_xlim(0, TOTAL_MUTS)
    ax.set_xlabel("mutation_id (campaign progression)")
    if normalized:
        ax.set_ylabel("cumulative CGC keys / final count")
        ax.set_ylim(0, 1.05)
        ax.set_title(
            "D1.B saturation inversion (V5 mean, 5 paired seeds, NORMALIZED)\n"
            "Coarsened variants saturate ~1400-1900 mut BEFORE local saturation"
        )
    else:
        ax.set_ylabel("cumulative CGC first-hit keys (hybrid total)")
        ax.set_title(
            "D1.B saturation inversion (V5 mean, 5 paired seeds, ABSOLUTE COUNTS)\n"
            "Coarsened variants saturate ~1400-1900 mut BEFORE local saturation"
        )
    ax.grid(True, alpha=0.3)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.95)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out_path}")


def main() -> int:
    print("Computing V5 paired-seed cumulative curves for 4 variants...")
    curves = compute_v5_curves()
    for variant, cs in curves.items():
        finals = [int(c[-1]) for c in cs]
        print(
            f"  {variant:30s} finals = {finals} mean={statistics.mean(finals):.1f}"
        )
    plot_overlay(curves, normalized=False, out_path=PLOTS / "d1b_saturation_overlay_v5.png")
    plot_overlay(curves, normalized=True, out_path=PLOTS / "d1b_saturation_overlay_v5_norm.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
