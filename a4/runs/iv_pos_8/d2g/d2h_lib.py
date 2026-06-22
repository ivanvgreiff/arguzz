#!/usr/bin/env python3
"""D2.H exploration library — coverage curves, Venn, UpSet, composition,
per-family reach, CGC ratio. Functions return matplotlib Figures (for inline
notebook display); __main__ saves PNGs for standalone validation.

All numbers computed live from the batch-1 N=10000 DBs — no hardcoded values.
"""
from __future__ import annotations

import math
import re
import sqlite3
from collections import Counter
from itertools import combinations
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Full campaign: seeds 1234/1235 in batch-1, seed 1236 in batch-2.
PROD_DIRS = [Path("a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1"),
             Path("a4/runs/iv_pos_8/d2f/prod/d2f_prod_b2")]
OUT = Path("a4/runs/iv_pos_8/d2g/d2h_artifacts")
VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
SEEDS = [1234, 1235, 1236]
N = 10000
COLORS = {"V5_control": "#1f77b4", "V6_uniform": "#2ca02c",
          "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
VENN3 = ["V5_control", "V6_cTS", "Hybrid_cTS"]  # surface-distinct trio for the circle Venn

_FAM = re.compile(r"@([^@]+?)\.zir")


def _fam(loc: str) -> str:
    m = _FAM.search(loc)
    return m.group(1) if m else (loc.split("@")[0] if "@" in loc else loc)


def _db(v: str, s: int) -> Path:
    name = f"pos_iv_pos_8_d2f_{v}_seed{s}_n{N}"
    for base in PROD_DIRS:
        p = base / name / "run.db"
        if p.exists():
            return p
    return PROD_DIRS[0] / name / "run.db"  # nonexistent → skipped by caller's exists() check


def load_data() -> dict:
    local_rows, cgc_rows = {}, {}
    local_sets = {v: set() for v in VARIANTS}
    cgc_sets = {v: set() for v in VARIANTS}
    for v in VARIANTS:
        for s in SEEDS:
            db = _db(v, s)
            if not db.exists():
                continue
            con = sqlite3.connect(str(db))
            lr = [(str(k), int(m)) for k, m in
                  con.execute("SELECT constraint_loc, first_hit_mutation_id FROM coverage")]
            cr = [(str(k), int(m)) for k, m in
                  con.execute("SELECT ctx_key, first_hit_mutation_id FROM compressed_global_coverage")]
            con.close()
            local_rows[(v, s)] = lr
            cgc_rows[(v, s)] = cr
            local_sets[v] |= {k for k, _ in lr}
            cgc_sets[v] |= {k for k, _ in cr}
    # rarity weight = 1 / (#variants whose union contains the loc)
    cnt = Counter()
    for v in VARIANTS:
        for k in local_sets[v]:
            cnt[k] += 1
    local_w = {k: 1.0 / n for k, n in cnt.items()}
    return dict(local_rows=local_rows, cgc_rows=cgc_rows,
                local_sets=local_sets, cgc_sets=cgc_sets, local_w=local_w)


def _cum(ids: list[int], n=N) -> np.ndarray:
    a = np.zeros(n + 1)
    for m in ids:
        if 1 <= m <= n:
            a[m] += 1
    return np.cumsum(a)


def _cum_w(rows, w, n=N) -> np.ndarray:
    a = np.zeros(n + 1)
    for k, m in rows:
        if 1 <= m <= n:
            a[m] += w.get(k, 1.0)
    return np.cumsum(a)


def _band(curves):
    M = np.vstack(curves)
    return M.mean(0), M.min(0), M.max(0)


def show(fig):
    """Render a Figure inline as PNG regardless of backend (Agg-safe), then close it."""
    import io
    from IPython.display import Image, display
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    buf.seek(0)
    display(Image(data=buf.read()))
    plt.close(fig)


# ---------- figures ----------
def fig_curves(d: dict):
    """The headline: cumulative LOCAL + CGC coverage vs applied-pull index.

    Bold line = all seeds POOLED (a constraint counts once it is reached in
    any seed) so the endpoint equals the campaign's total distinct reach —
    the same number shown in the territory bars. Faint lines = the
    individual seeds, to show run-to-run reproducibility.
    """
    x = np.arange(N + 1)
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.2))
    panels = [
        ("Local-constraint coverage", "distinct constraint locs reached", "local_rows"),
        ("CGC (global) coverage", "distinct CGC contexts reached", "cgc_rows"),
    ]
    for ax, (t, yl, rk) in zip(axes, panels):
        for v in VARIANTS:
            per_seed, pooled_min = [], {}
            for s in SEEDS:
                if (v, s) not in d[rk]:
                    continue
                rows = d[rk][(v, s)]
                per_seed.append(_cum([m for _, m in rows]))
                for k, m in rows:
                    if k not in pooled_min or m < pooled_min[k]:
                        pooled_min[k] = m
            if not per_seed:
                continue
            pooled = _cum(list(pooled_min.values()))
            for c in per_seed:
                ax.plot(x, c, color=COLORS[v], lw=0.8, alpha=0.30)
            ax.plot(x, pooled, color=COLORS[v], lw=2.4, label=f"{v} (total {int(pooled[-1])})")
        ax.set_title(t, fontsize=12); ax.set_xlabel("applied-pull index (0–10000)")
        ax.set_ylabel(yl); ax.legend(fontsize=9, loc="lower right", framealpha=0.9)
        ax.grid(alpha=0.3); ax.margins(x=0)
    fig.suptitle("Constraint-space coverage over the full campaign "
                 "(N=10000; bold = all 3 seeds pooled, faint = each seed)", fontsize=13)
    fig.tight_layout()
    return fig


def fig_territory_bars(d: dict):
    """The one decomposition view: per-variant TOTAL vs EXCLUSIVE territory (local + CGC)."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.2))
    for ax, kind in zip(axes, ("local", "cgc")):
        sets = d[f"{kind}_sets"]
        totals = [len(sets[v]) for v in VARIANTS]
        excl = [len(sets[v] - set().union(*[sets[o] for o in VARIANTS if o != v]))
                for v in VARIANTS]
        xs = np.arange(len(VARIANTS))
        ax.bar(xs, totals, color=[COLORS[v] for v in VARIANTS], alpha=0.35,
               label="total reached")
        ax.bar(xs, excl, color=[COLORS[v] for v in VARIANTS], alpha=1.0,
               label="exclusive (only this variant)")
        for i, (t, e) in enumerate(zip(totals, excl)):
            ax.text(i, t, str(t), ha="center", va="bottom", fontsize=9)
            if e:
                ax.text(i, e, str(e), ha="center", va="bottom", fontsize=8, color="white")
        ax.set_xticks(xs); ax.set_xticklabels(VARIANTS, rotation=20, ha="right", fontsize=9)
        ax.set_title(f"{kind.upper()} territory: total (faded) vs exclusive (solid)", fontsize=12)
        ax.set_ylabel(f"distinct {'locs' if kind=='local' else 'CGC contexts'}")
        ax.legend(fontsize=9); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    return fig


def _regions3(a, b, c):
    return {"A": len(a - b - c), "B": len(b - a - c), "C": len(c - a - b),
            "AB": len((a & b) - c), "AC": len((a & c) - b), "BC": len((b & c) - a),
            "ABC": len(a & b & c)}


def fig_venn(d: dict, kind: str):
    sets = d[f"{kind}_sets"]
    a, b, c = sets[VENN3[0]], sets[VENN3[1]], sets[VENN3[2]]
    reg = _regions3(a, b, c)
    tot = {VENN3[0]: len(a), VENN3[1]: len(b), VENN3[2]: len(c)}
    centers = {VENN3[0]: (-0.5, -0.3), VENN3[1]: (0.5, -0.3), VENN3[2]: (0.0, 0.55)}
    rmax = max(tot.values()) or 1
    fig, ax = plt.subplots(figsize=(7, 6.5))
    for nm in VENN3:
        r = 0.95 * math.sqrt(tot[nm] / rmax)
        cx, cy = centers[nm]
        ax.add_patch(plt.Circle((cx, cy), r, color=COLORS[nm], alpha=0.30, lw=2, ec=COLORS[nm]))
        ax.text(cx, cy + r + 0.06, f"{nm}\n|set|={tot[nm]}", ha="center",
                color=COLORS[nm], fontweight="bold", fontsize=9)
    lbl = {"A": (-0.85, -0.3), "B": (0.85, -0.3), "C": (0, 0.95), "AB": (0, -0.55),
           "AC": (-0.45, 0.3), "BC": (0.45, 0.3), "ABC": (0, 0.0)}
    for k, (lx, ly) in lbl.items():
        ax.text(lx, ly, str(reg[k]), ha="center", va="center", fontsize=12, fontweight="bold")
    ax.set_xlim(-1.6, 1.6); ax.set_ylim(-1.3, 1.6); ax.set_aspect("equal"); ax.axis("off")
    ax.set_title(f"{kind.upper()} territory — proportional Venn (3 surface-distinct variants)\n"
                 "circle AREA ∝ |set|; region numbers = EXACT counts (geometry illustrative)",
                 fontsize=10)
    fig.tight_layout()
    return fig


def _intersections(sets: dict):
    """All non-empty exclusive regions: subset S -> |∩S - ∪(others)|."""
    out = {}
    for r in range(1, len(VARIANTS) + 1):
        for combo in combinations(VARIANTS, r):
            inter = set.intersection(*[sets[v] for v in combo])
            others = set().union(*[sets[v] for v in VARIANTS if v not in combo]) if r < len(VARIANTS) else set()
            sz = len(inter - others)
            if sz > 0:
                out[combo] = sz
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def fig_upset(d: dict, kind: str):
    sets = d[f"{kind}_sets"]
    regions = _intersections(sets)
    combos = list(regions)
    sizes = [regions[c] for c in combos]
    totals = {v: len(sets[v]) for v in VARIANTS}
    fig = plt.figure(figsize=(max(9, 0.7 * len(combos) + 4), 6.5))
    gs = fig.add_gridspec(2, 2, width_ratios=[1.4, 5], height_ratios=[3, 1.6],
                          hspace=0.05, wspace=0.05)
    axb = fig.add_subplot(gs[0, 1])   # top: intersection size bars
    axm = fig.add_subplot(gs[1, 1])   # bottom: dot matrix
    axt = fig.add_subplot(gs[1, 0])   # left: per-set totals
    xs = np.arange(len(combos))
    axb.bar(xs, sizes, color="#444"); axb.set_ylabel("intersection size")
    for i, s in enumerate(sizes):
        axb.text(i, s, str(s), ha="center", va="bottom", fontsize=8)
    axb.set_xticks([]); axb.set_xlim(-0.6, len(combos) - 0.4); axb.grid(axis="y", alpha=0.3)
    axb.set_title(f"{kind.upper()} territory — UpSet (every intersection, exact)", fontsize=11)
    yrows = {v: i for i, v in enumerate(VARIANTS)}
    for i, combo in enumerate(combos):
        for v in VARIANTS:
            on = v in combo
            axm.plot(i, yrows[v], "o", ms=11,
                     color=COLORS[v] if on else "#ddd", mec="#888", mew=0.5)
        if len(combo) > 1:
            ys = [yrows[v] for v in combo]
            axm.plot([i, i], [min(ys), max(ys)], "-", color="#666", lw=1.5, zorder=0)
    axm.set_yticks(list(yrows.values())); axm.set_yticklabels(list(yrows), fontsize=8)
    axm.set_xticks([]); axm.set_xlim(-0.6, len(combos) - 0.4)
    axm.set_ylim(-0.6, len(VARIANTS) - 0.4); axm.invert_yaxis()
    for sp in axm.spines.values():
        sp.set_visible(False)
    axt.barh(list(yrows.values()), [totals[v] for v in VARIANTS],
             color=[COLORS[v] for v in VARIANTS])
    axt.set_yticks(list(yrows.values())); axt.set_yticklabels([])
    axt.invert_yaxis(); axt.invert_xaxis(); axt.set_xlabel("set total")
    axt.set_ylim(-0.6, len(VARIANTS) - 0.4); axt.grid(axis="x", alpha=0.3)
    return fig


def fig_composition(d: dict, kind: str):
    """Each variant's territory split: exclusive / shared-with-1 / -2 / common-4."""
    sets = d[f"{kind}_sets"]
    membership = Counter()
    allk = set().union(*sets.values())
    loc_owners = {k: sum(k in sets[v] for v in VARIANTS) for k in allk}
    fig, ax = plt.subplots(figsize=(8, 5))
    bottoms = {v: 0 for v in VARIANTS}
    shades = {1: "#d62728", 2: "#ff7f0e", 3: "#2ca02c", 4: "#1f77b4"}
    labels = {1: "exclusive", 2: "shared by 2", 3: "shared by 3", 4: "common to all 4"}
    for share in [1, 2, 3, 4]:
        vals = [sum(1 for k in sets[v] if loc_owners[k] == share) for v in VARIANTS]
        ax.bar(VARIANTS, vals, bottom=[bottoms[v] for v in VARIANTS],
               color=shades[share], label=labels[share])
        for i, v in enumerate(VARIANTS):
            bottoms[v] += vals[i]
    ax.set_ylabel(f"distinct {kind} contexts"); ax.legend(fontsize=8)
    ax.set_title(f"{kind.upper()} territory composition per variant (exclusive vs shared)")
    fig.tight_layout()
    return fig


def fig_family(d: dict):
    """Local: variant × constraint-family coverage heatmap (count of distinct locs)."""
    sets = d["local_sets"]
    fams = sorted({_fam(l) for v in VARIANTS for l in sets[v]})
    M = np.zeros((len(VARIANTS), len(fams)))
    for i, v in enumerate(VARIANTS):
        c = Counter(_fam(l) for l in sets[v])
        for j, f in enumerate(fams):
            M[i, j] = c.get(f, 0)
    fig, ax = plt.subplots(figsize=(max(11, 0.95 * len(fams) + 3), 4.6))
    im = ax.imshow(M, aspect="auto", cmap="viridis")
    ax.set_xticks(range(len(fams)))
    ax.set_xticklabels(fams, rotation=40, ha="right", rotation_mode="anchor", fontsize=9)
    ax.set_yticks(range(len(VARIANTS))); ax.set_yticklabels(VARIANTS, fontsize=10)
    for i in range(len(VARIANTS)):
        for j in range(len(fams)):
            ax.text(j, i, int(M[i, j]), ha="center", va="center",
                    color="white" if M[i, j] < M.max() * 0.6 else "black", fontsize=9)
    ax.set_title("Where each architecture looks — distinct local locs per circuit family",
                 fontsize=12, pad=10)
    fig.colorbar(im, ax=ax, label="distinct locs", fraction=0.025, pad=0.02)
    fig.subplots_adjust(bottom=0.28, left=0.12, right=0.99, top=0.9)
    return fig


def fig_cgc_ratio(d: dict):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ratios = [len(d["cgc_sets"][v]) / max(1, len(d["local_sets"][v])) for v in VARIANTS]
    ax.bar(VARIANTS, ratios, color=[COLORS[v] for v in VARIANTS])
    for i, r in enumerate(ratios):
        ax.text(i, r, f"{r:.1f}", ha="center", va="bottom")
    ax.set_ylabel("CGC contexts / local loc"); ax.grid(axis="y", alpha=0.3)
    ax.set_title("Global-vs-local reach (CGC ÷ local): higher = more global/witness-internal exploration")
    fig.tight_layout()
    return fig


def summary(d: dict) -> dict:
    out = {}
    for kind in ("local", "cgc"):
        sets = d[f"{kind}_sets"]
        union = set().union(*sets.values())
        out[kind] = dict(
            totals={v: len(sets[v]) for v in VARIANTS},
            union=len(union),
            common4=len(set.intersection(*[sets[v] for v in VARIANTS])),
            exclusive={v: len(sets[v] - set().union(*[sets[o] for o in VARIANTS if o != v]))
                       for v in VARIANTS},
        )
    return out


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    d = load_data()
    fig_curves(d).savefig(OUT / "d2h_curves.png", dpi=110)
    for k in ("local", "cgc"):
        fig_venn(d, k).savefig(OUT / f"d2h_venn_{k}.png", dpi=110)
        fig_upset(d, k).savefig(OUT / f"d2h_upset_{k}.png", dpi=110)
        fig_composition(d, k).savefig(OUT / f"d2h_composition_{k}.png", dpi=110)
    fig_family(d).savefig(OUT / "d2h_family.png", dpi=110)
    fig_cgc_ratio(d).savefig(OUT / "d2h_cgc_ratio.png", dpi=110)
    import json
    print(json.dumps(summary(d), indent=2))
    print("[ok] all figures saved to", OUT)
