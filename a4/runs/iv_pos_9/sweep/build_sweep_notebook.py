#!/usr/bin/env python3
"""IV.POS.9 Track-B — multi-guest coverage-curve notebook builder.

Produces, per guest program, ONE figure with all 4 variants overlaid (local + CGC panels),
at N=5000, plus the reused g0 sha2 baseline as its own guest. Emits BOTH a Jupyter notebook
(.ipynb, executed) AND an HTML printout. Self-contained (no edits to shared a4/runs/iv_pos_8/d2g).

Run from the repo root:  python3 a4/runs/iv_pos_9/sweep/build_sweep_notebook.py
"""
import nbformat as nbf
from nbconvert import HTMLExporter
from nbconvert.preprocessors import ExecutePreprocessor
from pathlib import Path
import os

REPO = Path(os.getcwd())
OUTD = REPO / "a4/runs/iv_pos_9/sweep/notebooks"
OUTD.mkdir(parents=True, exist_ok=True)
IPYNB = OUTD / "sweep_coverage_curves.ipynb"
HTML = OUTD / "sweep_coverage_curves.html"

cells = []
def md(s): cells.append(nbf.v4.new_markdown_cell(s.strip("\n")))
def code(s): cells.append(nbf.v4.new_code_cell(s.strip("\n")))

md("""
# IV.POS.9 Track-B — Multi-guest coverage curves (N=5000, seed 1234)

One figure per **guest program**, with all four variants (V5_control, V6_uniform, V6_cTS,
Hybrid_cTS) overlaid — left panel = local constraint-loc coverage, right = CGC (global) coverage,
cumulative vs mutation index. `g0_baseline` is the reused sha2 campaign (D2.F N=10000 truncated to
the first 5000 mutations). Guests with incomplete data are skipped with a note.

*Caveat:* cross-variant comparison is partly confounded (different selectors/extractors); the rigorous
generalization read is **within-variant across guests** — compare a variant's line on g0 vs the same
variant's line on g1/g2/g3.
""")

code("""
import sqlite3, os
import matplotlib.pyplot as plt
import numpy as np
%matplotlib inline

N = 5000
VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
COLORS = {"V5_control": "#1f77b4", "V6_uniform": "#2ca02c", "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
PROD = "a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1"
DATA = "a4/runs/iv_pos_9/sweep/data"

def resolve(guest, v):
    if guest == "g0_baseline":
        return f"{PROD}/pos_iv_pos_8_d2f_{v}_seed1234_n10000/run.db"   # truncated to N by cum()
    return f"{DATA}/{guest}_{v}.db"

def cum(db, table):
    if not os.path.exists(db):
        return None
    c = sqlite3.connect(db)
    ids = [int(m) for (m,) in c.execute(f"SELECT first_hit_mutation_id FROM {table}") if m is not None]
    c.close()
    a = np.zeros(N + 1)
    for m in ids:
        if 1 <= m <= N:
            a[m] += 1
    return np.cumsum(a)

def guest_fig(guest):
    x = np.arange(N + 1)
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.2))
    rows, present = [], 0
    for ax, (table, lbl) in zip(axes, [("coverage", "local constraint-locs"),
                                       ("compressed_global_coverage", "CGC contexts")]):
        for v in VARIANTS:
            cu = cum(resolve(guest, v), table)
            if cu is None:
                continue
            ax.plot(x, cu, color=COLORS[v], lw=2.2, label=f"{v} (final {int(cu[-1])})")
            if table == "coverage":
                present += 1
            rows.append((v, lbl, int(cu[-1])))
        ax.set_title(f"{guest} — {lbl}", fontsize=12)
        ax.set_xlabel("mutation index (0–%d)" % N); ax.set_ylabel(f"distinct {lbl}")
        ax.legend(fontsize=9, loc="lower right", framealpha=0.9); ax.grid(alpha=0.3); ax.margins(x=0)
    fig.suptitle(f"{guest}: coverage trajectories, 4 variants overlaid (N={N}, seed 1234)", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.97])
    return fig, rows, present

print("variants present per guest:")
for g in ["g0_baseline", "g1_ecall_control", "g2_mem_stress", "g3_accelerator"]:
    have = [v for v in VARIANTS if os.path.exists(resolve(g, v))]
    print(f"  {g}: {have}")
""")

# one section per guest (the code skips a guest cleanly if it has no data yet)
for g, title in [("g0_baseline", "g0 — sha2 baseline (reused, truncated to 5000)"),
                 ("g1_ecall_control", "g1 — control/ECALL-heavy guest"),
                 ("g2_mem_stress", "g2 — memory-stress guest"),
                 ("g3_accelerator", "g3 — accelerator/SHA guest")]:
    md(f"## {title}")
    code(f"""
g = {g!r}
have = [v for v in VARIANTS if os.path.exists(resolve(g, v))]
if not have:
    print(f"{{g}}: no completed runs yet — skipped.")
else:
    if len(have) < 4:
        print(f"PARTIAL: only {{have}} complete for {{g}} ({{4-len(have)}} variant(s) still running).")
    fig, rows, _ = guest_fig(g)
    plt.show()
    print("final coverage:")
    for v, lbl, n in rows:
        print(f"  {{v:14}} {{lbl:22}} {{n}}")
""")

nb = nbf.v4.new_notebook(); nb.cells = cells
nb.metadata["kernelspec"] = {"name": "python3", "display_name": "Python 3", "language": "python"}
print("executing notebook…")
ep = ExecutePreprocessor(timeout=300, kernel_name="python3")
ep.preprocess(nb, {"metadata": {"path": str(REPO)}})
nbf.write(nb, str(IPYNB))
html, _ = HTMLExporter(template_name="classic").from_notebook_node(nb)
HTML.write_text(html)
print("wrote", IPYNB)
print("wrote", HTML)
