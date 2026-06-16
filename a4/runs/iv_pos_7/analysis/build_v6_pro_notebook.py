#!/usr/bin/env python3
"""Generate V6_VS_A4_NOTEBOOK.ipynb — Pro-facing companion to R2."""
from __future__ import annotations

import json
import uuid
from pathlib import Path


def _cell(cell_type: str, source: str) -> dict:
    cell = {
        "cell_type": cell_type,
        "metadata": {},
        "id": uuid.uuid4().hex[:8],
        "source": [line + "\n" for line in source.splitlines()],
    }
    if cell_type == "code":
        cell["outputs"] = []
        cell["execution_count"] = None
    return cell


def build_notebook() -> dict:
    cells = []

    cells.append(_cell("markdown", """# V6 vs A4 — Pro Companion Notebook

Companion to `V6_VS_A4_REPORT_FOR_PRO.md`. **Not a replacement for R2** (V1–V5 ablation).

**Protagonist:** V6 (`arguzz`, 10 seeds × N=6000). **Comparators:** V5 (A4 winner), V1 (Pro baseline).

All metrics from `v6_pro_*.csv` and `analysis/` modules — no inline metric logic.
"""))

    cells.append(_cell("markdown", "## Cell 1 — Setup"))
    cells.append(_cell("code", """
import sys, json, sqlite3
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from IPython.display import Image, display

REPO = Path('/root/arguzz')
IV7 = REPO / 'a4/runs/iv_pos_7'
sys.path.insert(0, str(IV7))

from analysis.metrics import N_MUTATIONS, _coverage_curve
from analysis.discover import discover_dbs
from analysis.constraint_loc_normalize import normalize_constraint_loc
from analysis.v6_comparison import _a4_reachable_union

PLOTS = IV7 / 'plots_pro'
PLOTS.mkdir(exist_ok=True)
COLORS = {'V0': '#e41a1c', 'V1': '#2ca02c', 'V5': '#1f77b4', 'V6': '#8c564b'}

def show_plot(fig, path):
    fig.savefig(path, dpi=120, bbox_inches='tight')
    plt.close(fig)
    display(Image(filename=str(path)))

metrics = pd.read_csv(IV7 / 'v6_pro_metrics_table.csv')
ata = pd.read_csv(IV7 / 'v6_pro_apples_to_apples.csv').iloc[0]
terr = pd.read_csv(IV7 / 'v6_pro_territory_coverage.csv')
kind = pd.read_csv(IV7 / 'v6_pro_kind_translation.csv')
novel = pd.read_csv(IV7 / 'v6_pro_v5_novel_overlap.csv')
summary = json.loads((IV7 / 'v6_pro_build_summary.json').read_text())
a4_territory = _a4_reachable_union(IV7 / 'dbs', normalized=True)
print('V6 seeds:', summary['v6_seeds'], 'partial:', summary['v6_partial'])
print(metrics.groupby('variant').size())
"""))

    cells.append(_cell("markdown", "## Cell 2 — Headline: raw vs A4-reachable (Plot 1)"))
    cells.append(_cell("code", """
fig, ax = plt.subplots(figsize=(8, 5))
labels = ['V1\\n(raw)', 'V5\\n(raw)', 'V6\\n(full)', 'V6\\n(A4-reachable)']
vals = [
    metrics[metrics.variant=='V1']['local_context_final'].mean(),
    metrics[metrics.variant=='V5']['local_context_final'].mean(),
    metrics[metrics.variant=='V6']['local_context_final'].mean(),
    summary['v6_a4_reachable_normalized'] / summary['v6_seeds'],  # per-seed avg territory locs
]
# Better: use union territory count / seeds for fair per-run comparison
per_seed_a4 = []
m = discover_dbs(IV7 / 'dbs', variants=('V6',))
for seed, db in sorted(m['V6'].items()):
    with sqlite3.connect(db) as c:
        locs = {normalize_constraint_loc(r[0]) for r in c.execute('SELECT constraint_loc FROM coverage')}
    per_seed_a4.append(len(locs & a4_territory))
vals[3] = np.mean(per_seed_a4)

colors = [COLORS['V1'], COLORS['V5'], COLORS['V6'], '#bcbd22']
ax.bar(labels, vals, color=colors, alpha=0.85)
ax.set_ylabel('Mean local constraint_locs per seed')
ax.set_title('Headline: V6 raw looks 2× V5; A4-reachable subset ~2× below V5')
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '01_headline_raw_vs_reachable.png')
print(f"V6 full mean: {vals[2]:.1f} | V6 A4-reachable mean/seed: {vals[3]:.1f} | V5: {vals[1]:.1f}")
"""))

    cells.append(_cell("markdown", "## Cell 3 — Cumulative coverage (Plot 2)"))
    cells.append(_cell("code", """
m = discover_dbs(IV7 / 'dbs', variants=('V1','V5','V6'))
fig, ax = plt.subplots(figsize=(11, 6))
x = np.arange(1, N_MUTATIONS + 1)

for var in ['V1', 'V5']:
    curves = []
    for seed, db in sorted(m[var].items()):
        with sqlite3.connect(db) as c:
            rows = c.execute('SELECT constraint_loc, first_hit_mutation_id FROM coverage').fetchall()
        hits = [int(r[1]) for r in rows]
        curves.append(_coverage_curve(hits, n=N_MUTATIONS))
    arr = np.array(curves)
    ax.plot(x, arr.mean(0), color=COLORS[var], lw=2, label=f'{var} mean (n=10)')
    ax.fill_between(x, arr.mean(0)-arr.std(0,ddof=1), arr.mean(0)+arr.std(0,ddof=1),
                    color=COLORS[var], alpha=0.12)

v6_full, v6_a4 = [], []
for seed, db in sorted(m['V6'].items()):
    with sqlite3.connect(db) as c:
        rows = c.execute('SELECT constraint_loc, first_hit_mutation_id FROM coverage').fetchall()
    full_hits = [int(r[1]) for r in rows]
    a4_hits = [int(r[1]) for r in rows if normalize_constraint_loc(r[0]) in a4_territory]
    v6_full.append(_coverage_curve(full_hits, n=N_MUTATIONS))
    v6_a4.append(_coverage_curve(a4_hits, n=N_MUTATIONS))
    ax.plot(x, v6_full[-1], color=COLORS['V6'], ls='--', alpha=0.25, lw=0.8)

arr_f = np.array(v6_full)
arr_a = np.array(v6_a4)
ax.plot(x, arr_f.mean(0), color=COLORS['V6'], ls='--', lw=2,
        label=f'V6 full mean (n=10) — incl. V6-exclusive locs')
ax.plot(x, arr_a.mean(0), color=COLORS['V6'], ls='-', lw=2.5,
        label=f'V6 A4-reachable only mean (n=10)')
ax.axhline(46, color='gray', ls=':', alpha=0.5, label='V1 pooled union (46 locs)')
ax.set_xlabel('Mutation number'); ax.set_ylabel('Cumulative constraint_locs')
ax.set_title('Cumulative coverage: V6 full vs A4-reachable restriction')
ax.legend(fontsize=7, loc='lower right'); ax.grid(alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '02_cumulative_v6_territory.png')
"""))

    cells.append(_cell("markdown", "## Cell 4 — Territory coverage on 51-loc A4 union (Plot 3)"))
    cells.append(_cell("code", """
fig, ax = plt.subplots(figsize=(7, 5))
t = terr.set_index('variant').loc[['V1','V5','V6']]
ax.bar(t.index, t['locs_in_a4_territory'], color=[COLORS[v] for v in t.index], alpha=0.85)
ax.axhline(51, color='gray', ls='--', label='A4 union size (51)')
ax.set_ylabel('Locs found within A4-reachable union')
ax.set_title('On A4 territory: V5 dominates V6 (50/51 vs 20/51)')
for v, n in zip(t.index, t['locs_in_a4_territory']):
    ax.text(v, n+0.5, f'{int(n)}/51', ha='center', fontsize=10)
ax.legend(); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '03_territory_coverage.png')
print(terr.to_string(index=False))
"""))

    cells.append(_cell("markdown", "## Cell 5 — Loc overlap set table (Plot 4)"))
    cells.append(_cell("code", """
overlap = pd.read_csv(IV7 / 'internal_v6_v1_v5_loc_overlap.csv')
norm = overlap[overlap.keying=='normalized'].set_index('set_name')['count']
table = pd.DataFrame({
    'set': ['V6 full union', 'A4-reachable union', 'V6 ∩ A4', 'V6-exclusive', 'V5 novel 4 hit by V6'],
    'count': [norm['V6_union'], norm['A4_reachable_union_V0_V5'],
              norm['V6_intersect_A4_reachable'], norm['V6_exclusive_vs_A4'],
              norm['V5_novel_4_hit_by_V6']],
})
print(table.to_string(index=False))
print('\\nRaw keying V6∩A4 = 0 (format artifact — see report §3).')

fig, ax = plt.subplots(figsize=(8, 4))
ax.axis('off')
tbl = ax.table(cellText=table.values, colLabels=table.columns, loc='center', cellLoc='left')
tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.2, 1.4)
ax.set_title('Normalized loc overlap (10/10 V6 seeds)', pad=20)
plt.tight_layout()
show_plot(fig, PLOTS / '04_loc_overlap_table.png')
"""))

    cells.append(_cell("markdown", "## Cell 6 — Kind decomposition (Plot 5)"))
    cells.append(_cell("code", """
inv = kind.groupby(['variant','kind_group'])[['pulls','discoveries']].sum().reset_index()
v6k = inv[inv.variant=='V6']
fig, ax = plt.subplots(figsize=(8, 5))
groups = ['shared', 'v6_only']
colors_g = {'shared': '#4daf4a', 'v6_only': '#ff7f00'}
x = np.arange(2); w = 0.35
pulls = [v6k[v6k.kind_group==g]['pulls'].iloc[0] for g in groups]
discs = [v6k[v6k.kind_group==g]['discoveries'].iloc[0] for g in groups]
ax.bar(x - w/2, pulls, w, label='pulls', color='#377eb8', alpha=0.8)
ax.bar(x + w/2, discs, w, label='discoveries', color='#e41a1c', alpha=0.8)
ax.set_xticks(x); ax.set_xticklabels(['shared (4 kinds)', 'v6_only (7 kinds)'])
ax.set_ylabel('Count (pooled 10 seeds)'); ax.set_title('V6: 79% pulls on V6-only kinds')
ax.legend(); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '05_kind_decomposition.png')
print(v6k.to_string(index=False))
"""))

    cells.append(_cell("markdown", "## Cell 7 — V5 novel 4 vs V6 (Plot 6 / table)"))
    cells.append(_cell("code", """
print(novel.to_string(index=False))
print(f"\\nV6 hits on V5 novel locs: {novel['v6_hit'].sum()}/4")

fig, ax = plt.subplots(figsize=(9, 3))
ax.axis('off')
tbl = ax.table(cellText=novel[['constraint_loc_normalized','v5_novel_hit','v6_hit']].values,
               colLabels=['Normalized loc', 'V5 hit', 'V6 hit'], loc='center')
tbl.auto_set_font_size(False); tbl.set_fontsize(9); tbl.scale(1.1, 1.5)
ax.set_title('V5 signature novel locs: V6 hit count = 0/4 (60k mutations)', pad=20)
plt.tight_layout()
show_plot(fig, PLOTS / '06_v5_novel_vs_v6.png')
"""))

    cells.append(_cell("markdown", "## Cell 8 — CGC apples-to-apples"))
    cells.append(_cell("code", """
print('=== Loc-level (normalized) ===')
print(f"  V6 full: {int(ata.v6_full_coverage_normalized)} | A4-reachable: {int(ata.v6_a4_reachable_normalized)} "
      f"({ata.v6_reachable_fraction_normalized*100:.1f}%)")
print('=== CGC-level (ctx_key) ===')
print(f"  V6 full: {int(ata.v6_full_cgc)} | A4-reachable: {int(ata.v6_a4_reachable_cgc)} "
      f"({ata.v6_cgc_reachable_fraction*100:.1f}%)")

fig, ax = plt.subplots(figsize=(6, 4))
cats = ['Loc\\n(normalized)', 'CGC\\n(ctx_key)']
reachable = [ata.v6_reachable_fraction_normalized*100, ata.v6_cgc_reachable_fraction*100]
exclusive = [ata.v6_exclusive_fraction_normalized*100, ata.v6_cgc_exclusive_fraction*100]
x = np.arange(2)
ax.bar(x, reachable, label='A4-reachable %', color='#4daf4a')
ax.bar(x, exclusive, bottom=reachable, label='V6-exclusive %', color='#ff7f00')
ax.set_xticks(x); ax.set_xticklabels(cats); ax.set_ylim(0, 100)
ax.set_ylabel('% of V6 coverage'); ax.set_title('Fairness: ~16–21% A4-reachable')
ax.legend(loc='upper right'); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '07_cgc_apples_to_apples.png')
"""))

    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "pygments_lexer": "ipython3"},
        },
        "cells": cells,
    }


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "V6_VS_A4_NOTEBOOK.ipynb"
    out.write_text(json.dumps(build_notebook(), indent=1))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
