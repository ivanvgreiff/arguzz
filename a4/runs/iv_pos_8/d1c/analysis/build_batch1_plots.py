#!/usr/bin/env python3
"""D1.C Batch 1 sanity plots for Tier-1 fire rates."""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
D1C = Path(__file__).resolve().parents[1]
PLOTS = D1C / "plots"
AUDIT_CSV = D1C / "d1c_batch1_tier1_audit.csv"
PAIRED_V5_SEEDS = [1234, 1235, 1236, 1237, 1238]

sys.path.insert(0, str(REPO))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


def load_audit_rows() -> list[dict]:
    with AUDIT_CSV.open(newline="") as f:
        return list(csv.DictReader(f))


def plot_fire_rate_full(rows: list[dict]) -> Path:
    by_signal: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_signal[row["signal_name"]].append(float(row["fire_rate_full"]))

    signals = sorted(by_signal)
    fig, axes = plt.subplots(1, len(signals), figsize=(3.2 * len(signals), 4), sharey=True)
    if len(signals) == 1:
        axes = [axes]
    for ax, sig in zip(axes, signals):
        vals = by_signal[sig]
        ax.hist(vals, bins=10, range=(0, 1), color="#4c72b0", edgecolor="white")
        ax.set_title(sig.replace("_", "\n"), fontsize=8)
        ax.set_xlabel("fire_rate_full")
        if ax is axes[0]:
            ax.set_ylabel("DB count")
    fig.suptitle("D1.C Batch 1 — Tier-1 fire_rate_full across 30 Cat-A DBs", fontsize=11)
    fig.tight_layout()
    out = PLOTS / "d1c_batch1_fire_rate_full.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def plot_fire_rate_post_local(rows: list[dict]) -> Path:
    paired = [
        r
        for r in rows
        if r["variant"] == "V5" and int(r["seed"]) in PAIRED_V5_SEEDS
    ]
    by_signal_seed: dict[str, dict[int, float]] = defaultdict(dict)
    for row in paired:
        by_signal_seed[row["signal_name"]][int(row["seed"])] = float(
            row["fire_rate_post_local"]
        )

    signals = sorted(by_signal_seed)
    x = np.arange(len(PAIRED_V5_SEEDS))
    width = 0.15
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, sig in enumerate(signals):
        vals = [by_signal_seed[sig].get(s, 0.0) for s in PAIRED_V5_SEEDS]
        offset = (i - (len(signals) - 1) / 2) * width
        ax.bar(x + offset, vals, width=width, label=sig)

    ax.set_xticks(x)
    ax.set_xticklabels([str(s) for s in PAIRED_V5_SEEDS])
    ax.set_xlabel("V5 paired seed")
    ax.set_ylabel("fire_rate_post_local [3000, 6000)")
    ax.set_ylim(0, 1)
    ax.legend(fontsize=7, loc="upper right")
    ax.set_title("D1.C Batch 1 — post-local fire rates (paired V5 seeds)")
    fig.tight_layout()
    out = PLOTS / "d1c_batch1_fire_rate_post_local.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def main() -> int:
    PLOTS.mkdir(parents=True, exist_ok=True)
    rows = load_audit_rows()
    p1 = plot_fire_rate_full(rows)
    p2 = plot_fire_rate_post_local(rows)
    print(f"wrote {p1}")
    print(f"wrote {p2}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
