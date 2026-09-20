#!/usr/bin/env python3
"""Per-guest coverage figures, three layouts each, 4 variants overlaid.

Metrics (all cumulative distinct-by-first-hit over 0..N, N=5000):
  Constraint Locations   = distinct constraint_loc            (loc-only)
  Local Contexts         = distinct (constraint_loc,major,minor) (the full gamma)
  Compressed Global Ctx  = distinct CGC keys
Loc + Local-Context are both derived from the `failures` table (so Loc <= Context
pointwise and both are uniform across variants); CGC from `compressed_global_coverage`.

For each guest g in {g0,g1,g2,g3} writes:
  coverage_loc_<g>.png      [Constraint Locations | CGC]
  coverage_ctx_<g>.png      [Local Contexts | CGC]
  coverage_3panel_<g>.png   [Constraint Locations | Local Contexts | CGC]

ALL labels use the THESIS variant names. No seed in titles.
Usage: python3 a4/runs/iv_pos_9/sweep/build_per_guest_curves.py [outdir]
"""
import sqlite3, os, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

N = 5000
SWEEP = "a4/runs/iv_pos_9/sweep/data"
D2F = "a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1"

DISPLAY = {"V5_control": "A3 Bandit", "Hybrid_cTS": "A3+Arguzz Bandit",
           "V6_cTS": "Arguzz Bandit", "V6_uniform": "Arguzz"}
ORDER = ["V5_control", "Hybrid_cTS", "V6_cTS", "V6_uniform"]
COLORS = {"V5_control": "#1f77b4", "Hybrid_cTS": "#d62728",
          "V6_cTS": "#ff7f0e", "V6_uniform": "#2ca02c"}

GUESTS = {
    "g0": (lambda v: f"{D2F}/pos_iv_pos_8_d2f_{v}_seed1234_n10000/run.db",
           "Metamorphic Mixed-Arithmetic Guest"),
    "g1": (lambda v: f"{SWEEP}/g1_ecall_control_{v}.db",
           "System-Call / Control-Heavy Guest"),
    "g2": (lambda v: f"{SWEEP}/g2_mem_stress_{v}.db",
           "Memory-Stress Guest"),
    "g3": (lambda v: f"{SWEEP}/g3_accelerator_{v}.db",
           "Accelerator / SHA Guest"),
}
LOC, CTX, CGC = "Constraint Locations", "Local Contexts", "Compressed Global Contexts"


def _cum(first_ids):
    a = np.zeros(N + 1)
    for m in first_ids:
        if m is not None and 1 <= m <= N:
            a[m] += 1
    return np.cumsum(a)


def curves(db):
    """Return {LOC,CTX,CGC: cumulative array} or None if DB missing."""
    if not os.path.exists(db):
        return None
    c = sqlite3.connect(db)
    out = {}
    try:
        out[LOC] = _cum([r[0] for r in c.execute(
            "SELECT MIN(mutation_id) FROM failures GROUP BY constraint_loc")])
        out[CTX] = _cum([r[0] for r in c.execute(
            "SELECT MIN(mutation_id) FROM failures GROUP BY constraint_loc,major,minor")])
        out[CGC] = _cum([r[0] for r in c.execute(
            "SELECT first_hit_mutation_id FROM compressed_global_coverage")])
    except sqlite3.OperationalError:
        c.close(); return None
    c.close()
    return out


def panel(ax, data, metric):
    x = np.arange(N + 1)
    for v in ORDER:
        if data.get(v) is None:
            continue
        y = data[v][metric]
        ax.plot(x, y, color=COLORS[v], lw=2.2, label=f"{DISPLAY[v]} ({int(y[-1])})")
    ax.set_xlabel("mutation index"); ax.set_ylabel(metric)
    ax.legend(fontsize=8.5, loc="lower right", title="(final count)")
    ax.grid(alpha=0.3); ax.margins(x=0)


def figure(title, data, metrics, out):
    fig, axes = plt.subplots(1, len(metrics), figsize=(6.4 * len(metrics), 5))
    if len(metrics) == 1:
        axes = [axes]
    for ax, m in zip(axes, metrics):
        panel(ax, data, m)
    fig.suptitle(f"{title}\ncumulative distinct coverage  ·  N={N}", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(out, dpi=140, bbox_inches="tight"); plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    outdir = sys.argv[1] if len(sys.argv) > 1 else "a4/runs/iv_pos_9/sweep/figures"
    os.makedirs(outdir, exist_ok=True)
    for slug, (dbfn, title) in GUESTS.items():
        data = {v: curves(dbfn(v)) for v in ORDER}
        figure(title, data, [LOC, CGC],        f"{outdir}/coverage_loc_{slug}.png")
        figure(title, data, [CTX, CGC],        f"{outdir}/coverage_ctx_{slug}.png")
        figure(title, data, [LOC, CTX, CGC],   f"{outdir}/coverage_3panel_{slug}.png")
