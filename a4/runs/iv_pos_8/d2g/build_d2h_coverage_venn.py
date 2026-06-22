#!/usr/bin/env python3
"""D2.H — constraint-space exploration: coverage curves + proportional Venns.

Builds (and validates on the batch-1 N=10000 DBs):
  - local-loc coverage curve, CGC coverage curve, rarity-weighted local curve
  - area-proportional Venns (local + CGC) over the 3 surface-distinct variants
  - the complete 4-way intersection table (local + CGC)

No matplotlib_venn dependency (custom proportional-circle drawer).
"""
from __future__ import annotations

import math
import sqlite3
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROD = Path("a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1")
OUT = Path("a4/runs/iv_pos_8/d2g/d2h_artifacts")
OUT.mkdir(parents=True, exist_ok=True)

VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
SEEDS = [1234, 1235]
N = 10000
COLORS = {"V5_control": "#1f77b4", "V6_uniform": "#2ca02c",
          "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
# 3 surface-distinct variants for the proportional Venn (V6_uniform ~ V6_cTS surface)
VENN3 = ["V5_control", "V6_cTS", "Hybrid_cTS"]


def _db(variant: str, seed: int) -> Path:
    return PROD / f"pos_iv_pos_8_d2f_{variant}_seed{seed}_n{N}" / "run.db"


def _first_hits(db: Path, table: str, key: str) -> list[tuple[str, int]]:
    """(key, first_hit_mutation_id) rows from coverage / compressed_global_coverage."""
    con = sqlite3.connect(str(db))
    try:
        rows = con.execute(
            f"SELECT {key}, first_hit_mutation_id FROM {table}"
        ).fetchall()
    finally:
        con.close()
    return [(str(k), int(m)) for k, m in rows]


def _curve(first_hit_ids: list[int], n: int = N) -> np.ndarray:
    """Cumulative distinct-count vs mutation index 1..n."""
    arr = np.zeros(n + 1, dtype=float)
    for m in first_hit_ids:
        if 1 <= m <= n:
            arr[m] += 1.0
    return np.cumsum(arr)


def _weighted_curve(rows: list[tuple[str, int]], weight: dict[str, float], n: int = N) -> np.ndarray:
    arr = np.zeros(n + 1, dtype=float)
    for k, m in rows:
        if 1 <= m <= n:
            arr[m] += weight.get(k, 1.0)
    return np.cumsum(arr)


# ---- load everything ----
local_rows: dict[tuple[str, int], list[tuple[str, int]]] = {}
cgc_rows: dict[tuple[str, int], list[tuple[str, int]]] = {}
local_sets: dict[str, set[str]] = {v: set() for v in VARIANTS}
cgc_sets: dict[str, set[str]] = {v: set() for v in VARIANTS}
for v in VARIANTS:
    for s in SEEDS:
        db = _db(v, s)
        if not db.exists():
            print(f"  WARN missing {db}")
            continue
        lr = _first_hits(db, "coverage", "constraint_loc")
        cr = _first_hits(db, "compressed_global_coverage", "ctx_key")
        local_rows[(v, s)] = lr
        cgc_rows[(v, s)] = cr
        local_sets[v] |= {k for k, _ in lr}
        cgc_sets[v] |= {k for k, _ in cr}

# rarity weight = 1 / (# variants whose UNION contains this key)
def _rarity(sets: dict[str, set[str]]) -> dict[str, float]:
    from collections import Counter
    c: Counter = Counter()
    for v in VARIANTS:
        for k in sets[v]:
            c[k] += 1
    return {k: 1.0 / n for k, n in c.items()}

local_w = _rarity(local_sets)


# ---- coverage curves (mean over seeds, min/max band) ----
def _mean_band(curves: list[np.ndarray]):
    M = np.vstack(curves)
    return M.mean(axis=0), M.min(axis=0), M.max(axis=0)

fig, axes = plt.subplots(1, 3, figsize=(18, 5))
x = np.arange(N + 1)
panels = [
    ("Local-constraint coverage", "distinct constraint locs",
     lambda v, s: _curve([m for _, m in local_rows[(v, s)]])),
    ("CGC coverage", "distinct CGC contexts",
     lambda v, s: _curve([m for _, m in cgc_rows[(v, s)]])),
    ("Rarity-weighted local coverage", "Σ 1/(#variants hitting loc)",
     lambda v, s: _weighted_curve(local_rows[(v, s)], local_w)),
]
for ax, (title, ylab, fn) in zip(axes, panels):
    for v in VARIANTS:
        cs = [fn(v, s) for s in SEEDS if (v, s) in local_rows]
        if not cs:
            continue
        mean, lo, hi = _mean_band(cs)
        ax.plot(x, mean, label=v, color=COLORS[v], lw=2)
        ax.fill_between(x, lo, hi, color=COLORS[v], alpha=0.12)
    ax.set_title(title); ax.set_xlabel("applied-pull index"); ax.set_ylabel(ylab)
    ax.legend(fontsize=8); ax.grid(alpha=0.3)
fig.suptitle("D2.H — constraint-space coverage curves (batch-1, N=10000, mean of seeds 1234/1235)")
fig.tight_layout()
fig.savefig(OUT / "d2h_coverage_curves.png", dpi=110)
print(f"[saved] {OUT/'d2h_coverage_curves.png'}")


# ---- proportional Venn (custom; area ∝ set size; regions = exact counts) ----
def _regions3(a: set, b: set, c: set) -> dict[str, int]:
    return {
        "A": len(a - b - c), "B": len(b - a - c), "C": len(c - a - b),
        "AB": len((a & b) - c), "AC": len((a & c) - b), "BC": len((b & c) - a),
        "ABC": len(a & b & c),
    }

def _venn3(sets: dict[str, set[str]], names: list[str], title: str, fname: str):
    a, b, c = (sets[names[0]], sets[names[1]], sets[names[2]])
    reg = _regions3(a, b, c)
    tot = {names[0]: len(a), names[1]: len(b), names[2]: len(c)}
    # circle centers (standard symmetric triangle) + radius ∝ sqrt(area)
    centers = {names[0]: (-0.5, -0.30), names[1]: (0.5, -0.30), names[2]: (0.0, 0.55)}
    rmax = max(tot.values()) or 1
    fig, ax = plt.subplots(figsize=(7.5, 7))
    for nm in names:
        r = 0.95 * math.sqrt(tot[nm] / rmax)
        cx, cy = centers[nm]
        ax.add_patch(plt.Circle((cx, cy), r, color=COLORS[nm], alpha=0.32, lw=2, ec=COLORS[nm]))
        ax.text(cx, cy + r + 0.05, f"{nm}\n(|set|={tot[nm]})", ha="center",
                fontsize=10, color=COLORS[nm], fontweight="bold")
    # exact region counts (geometry illustrative; numbers exact)
    lbl = {
        "A": (-0.85, -0.30), "B": (0.85, -0.30), "C": (0.0, 0.95),
        "AB": (0.0, -0.55), "AC": (-0.45, 0.30), "BC": (0.45, 0.30),
        "ABC": (0.0, 0.0),
    }
    for k, (lx, ly) in lbl.items():
        ax.text(lx, ly, str(reg[k]), ha="center", va="center", fontsize=12, fontweight="bold")
    ax.set_xlim(-1.6, 1.6); ax.set_ylim(-1.3, 1.6); ax.set_aspect("equal"); ax.axis("off")
    ax.set_title(f"{title}\n(circle AREA ∝ set size; region numbers = exact counts)", fontsize=11)
    fig.tight_layout(); fig.savefig(OUT / fname, dpi=110)
    print(f"[saved] {OUT/fname}  regions={reg}")

_venn3(local_sets, VENN3, "Local-constraint territory (proportional)", "d2h_venn_local.png")
_venn3(cgc_sets, VENN3, "CGC territory (proportional)", "d2h_venn_cgc.png")


# ---- complete 4-way intersection table (printed) ----
def _table(sets: dict[str, set[str]], label: str):
    union = set().union(*sets.values())
    print(f"\n=== {label} 4-way decomposition (union={len(union)}) ===")
    print(f"  {'variant':<12} total  exclusive")
    for v in VARIANTS:
        others = set().union(*[sets[o] for o in VARIANTS if o != v])
        print(f"  {v:<12} {len(sets[v]):<6} {len(sets[v]-others)}")
    common = set.intersection(*[sets[v] for v in VARIANTS])
    print(f"  common-to-all-4: {len(common)}")
    # marginal contribution (N4): new territory each adds to the union of others
    for v in VARIANTS:
        others = set().union(*[sets[o] for o in VARIANTS if o != v])
        print(f"  marginal[{v}] = |union with {v}| - |union without| = {len(union) - len(others)}")

_table(local_sets, "LOCAL")
_table(cgc_sets, "CGC")

# ---- validation ----
print("\n=== VALIDATION ===")
assert (OUT / "d2h_coverage_curves.png").stat().st_size > 5000, "curve png too small"
assert (OUT / "d2h_venn_local.png").stat().st_size > 5000, "venn png too small"
for v in VARIANTS:
    assert len(local_sets[v]) > 0 and len(cgc_sets[v]) > 0, f"{v} empty set"
print("  OK: 3 figures produced; all variant sets non-empty; curves+venns+table generated.")
print(f"  final local counts: { {v: len(local_sets[v]) for v in VARIANTS} }")
print(f"  final cgc counts:   { {v: len(cgc_sets[v]) for v in VARIANTS} }")
