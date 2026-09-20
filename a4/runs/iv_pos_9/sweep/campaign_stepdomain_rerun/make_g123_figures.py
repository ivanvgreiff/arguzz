#!/usr/bin/env python3
"""Two 6-panel publication PNGs for guests g1/g2/g3 (seed 1234), reusing make_g0_figures styling.
Layout: rows = g1, g2, g3 ; left column = LOCAL (Distinct Local Contexts) ; right = GLOBAL
(Distinct Compressed Global Contexts).
  - figure 1: the fading territory bars (faded "Total Reached" behind solid "Exclusive")
  - figure 2: the cumulative coverage curves
Reads only this campaign's data_extracted CSVs. Run from repo root. Same fonts as make_g0_figures (v3)."""
import csv, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.lines import Line2D

plt.rcParams.update({
    "font.size": 15,
    "axes.labelsize": 20,
    "axes.titlesize": 22,
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "legend.fontsize": 17,
})

BASE = "a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/data_extracted"
OUT = "a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/pngs"
os.makedirs(OUT, exist_ok=True)
N = 5000
SEED = "1234"
VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
DISPLAY = {"V5_control": "A3 Bandit", "V6_uniform": "Arguzz", "V6_cTS": "Arguzz Bandit", "Hybrid_cTS": "A3+Arguzz Bandit"}
COLORS  = {"V5_control": "#1f77b4", "V6_uniform": "#000000", "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
YLAB = {"CTX": "Distinct Local Contexts", "CGC": "Distinct Compressed Global Contexts"}
GUESTS = [("g1_ecall_control", "System-Call / Control-Heavy Guest"),
          ("g2_mem_stress",    "Memory-Stress Guest"),
          ("g3_accelerator",   "Accelerator / SHA Guest")]
METRICS = ["CTX", "CGC"]   # left = local, right = global

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

def bar_panel(ax, guest, mk):
    sets = {v: KEYSETS.get((guest, v, SEED, mk), set()) for v in VARIANTS}
    totals = [len(sets[v]) for v in VARIANTS]
    excl = [len(sets[v] - set().union(*[sets[o] for o in VARIANTS if o != v])) for v in VARIANTS]
    xs = np.arange(len(VARIANTS))
    ax.bar(xs, totals, color=[COLORS[v] for v in VARIANTS], alpha=0.35)
    ax.bar(xs, excl, color=[COLORS[v] for v in VARIANTS], alpha=1.0)
    for i, (t, e) in enumerate(zip(totals, excl)):
        ax.text(i, t, str(t), ha="center", va="bottom", fontsize=20)
        if e:
            ax.text(i, e, str(e), ha="center", va="bottom", fontsize=20, color="white")
    ax.set_xticks(xs); ax.set_xticklabels([DISPLAY[v] for v in VARIANTS], rotation=20, ha="right", fontsize=20)
    ax.set_ylabel(YLAB[mk]); ax.grid(axis="y", alpha=0.3); ax.margins(y=0.12)

def curve_panel(ax, guest, mk):
    for v in VARIANTS:
        ids = points.get((guest, v, SEED, mk))
        if ids is None:
            continue
        ax.plot(np.arange(N + 1), cum(ids), color=COLORS[v], lw=2.4, label=DISPLAY[v])
    ax.set_xlabel("Mutation Index"); ax.set_ylabel(YLAB[mk])
    ax.grid(alpha=0.3); ax.margins(x=0)

def build(kind, panel_fn, fname, legend_handles):
    fig, axes = plt.subplots(3, 2, figsize=(22, 22))
    for row, (guest, title) in enumerate(GUESTS):
        for col, mk in enumerate(METRICS):
            ax = axes[row][col]
            panel_fn(ax, guest, mk)
            ax.set_title(title)
    fig.legend(handles=legend_handles, loc="upper center",
               ncol=len(legend_handles), frameon=False, bbox_to_anchor=(0.5, 1.0))
    fig.tight_layout(rect=[0, 0, 1, 0.965])
    fig.savefig(f"{OUT}/{fname}", dpi=150, bbox_inches="tight"); plt.close(fig)
    print(f"wrote {OUT}/{fname}")

# Figure 1 — fading territory bars
build("bar", bar_panel, "territory_bars_g123_local_global.png",
      [Patch(facecolor="0.5", alpha=0.35, label="Total Reached"),
       Patch(facecolor="0.5", alpha=1.0, label="Exclusive (Only This Variant)")])

# Figure 2 — coverage curves
build("curve", curve_panel, "coverage_curves_g123_local_global.png",
      [Line2D([0], [0], color=COLORS[v], lw=2.4, label=DISPLAY[v]) for v in VARIANTS])
