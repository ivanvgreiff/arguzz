#!/usr/bin/env python3
"""Standalone publication PNGs for the product-program mixed-arithmetic guest (g0_baseline, seed 1234).
4 figures, each metric alone, NO title / NO caption, Title-Case axes, CGC labeled "Distinct Compressed
Global Contexts". Reads only this campaign's data_extracted CSVs. Run from repo root."""
import csv, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# Font-size history (so it can be re-calibrated):
#   element              v1   v2   v3(current)
#   axis labels          10   22   20
#   tick numbers         10   18   16
#   legend                9   17   15
#   bar total labels     10   17   20 (=y-label)
#   bar exclusive labels  9   15   20 (=y-label)
#   variant x-labels     10   18   20 (=y-label)
plt.rcParams.update({
    "font.size": 15,
    "axes.labelsize": 20,
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "legend.fontsize": 15,
})

BASE = "a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/data_extracted"
OUT = "a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/pngs/figures_product_program_mixed_arithmetic"
os.makedirs(OUT, exist_ok=True)
N = 5000
GUEST = "g0_baseline"; SEED = "1234"
VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
DISPLAY = {"V5_control": "A3 Bandit", "V6_uniform": "Arguzz", "V6_cTS": "Arguzz Bandit", "Hybrid_cTS": "A3+Arguzz Bandit"}
COLORS  = {"V5_control": "#1f77b4", "V6_uniform": "#000000", "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
YLAB = {"CTX": "Distinct Local Contexts", "CGC": "Distinct Compressed Global Contexts"}

# ---- load curve points (canonical host only) + key sets ----
canon = {(j["guest"], j["variant"], j["seed"]): j["host"]
         for j in csv.DictReader(open(f"{BASE}/jobs.csv"), delimiter="|")}
points = {}
for r in csv.DictReader(open(f"{BASE}/curve_points.csv"), delimiter="|"):
    k = (r["guest"], r["variant"], r["seed"])
    if canon.get(k) != r["host"]:
        continue
    points.setdefault((*k, r["metric"]), []).append(int(r["first_hit_mutation_id"]))
KEYSETS = {}
for line in open(f"{BASE}/keys.csv"):
    p = line.rstrip("\n").split("|", 5)
    if len(p) != 6 or p[0] == "source":
        continue
    KEYSETS.setdefault((p[1], p[2], p[3], p[4]), set()).add(p[5])

def cum(ids):
    a = np.zeros(N + 1)
    for m in ids:
        if 1 <= m <= N:
            a[m] += 1
    return np.cumsum(a)

def curve_png(mk, fname):
    fig, ax = plt.subplots(figsize=(10, 6.5))
    for v in VARIANTS:
        ids = points.get((GUEST, v, SEED, mk))
        if ids is None:
            continue
        ax.plot(np.arange(N + 1), cum(ids), color=COLORS[v], lw=2.4, label=DISPLAY[v])
    ax.set_xlabel("Mutation Index"); ax.set_ylabel(YLAB[mk])
    ax.legend(loc="lower right"); ax.grid(alpha=0.3); ax.margins(x=0)
    fig.tight_layout(); fig.savefig(f"{OUT}/{fname}", dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"wrote {OUT}/{fname}")

def bar_png(mk, fname):
    sets = {v: KEYSETS.get((GUEST, v, SEED, mk), set()) for v in VARIANTS}
    totals = [len(sets[v]) for v in VARIANTS]
    excl = [len(sets[v] - set().union(*[sets[o] for o in VARIANTS if o != v])) for v in VARIANTS]
    xs = np.arange(len(VARIANTS))
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.bar(xs, totals, color=[COLORS[v] for v in VARIANTS], alpha=0.35)
    ax.bar(xs, excl, color=[COLORS[v] for v in VARIANTS], alpha=1.0)
    for i, (t, e) in enumerate(zip(totals, excl)):
        ax.text(i, t, str(t), ha="center", va="bottom", fontsize=20)
        if e:
            ax.text(i, e, str(e), ha="center", va="bottom", fontsize=20, color="white")
    ax.set_xticks(xs); ax.set_xticklabels([DISPLAY[v] for v in VARIANTS], rotation=20, ha="right", fontsize=20)
    ax.set_ylabel(YLAB[mk])
    ax.legend(handles=[Patch(facecolor="0.5", alpha=0.35, label="Total Reached"),
                       Patch(facecolor="0.5", alpha=1.0, label="Exclusive (Only This Variant)")],
              loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(f"{OUT}/{fname}", dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"wrote {OUT}/{fname}")

bar_png("CTX", "territory_bar_local_context.png")
bar_png("CGC", "territory_bar_cgc.png")
curve_png("CTX", "coverage_curve_local_context.png")
curve_png("CGC", "coverage_curve_cgc.png")
