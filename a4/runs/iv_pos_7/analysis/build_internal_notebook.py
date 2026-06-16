#!/usr/bin/env python3
"""Generate INTERNAL_V0_V6_NOTEBOOK.ipynb scaffold (internal track)."""
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

    cells.append(_cell("markdown", """# Internal V0/V6 Analysis Notebook

Companion to `INTERNAL_V0_V6_ANALYSIS.md`. **Not Pro-facing.** R2 deliverables frozen.

**Variants:** V0 (uniform), V1–V5 (R2 ablation), V6 (arguzz, partial n=4 at time of writing).
All metrics from `internal_*.csv` and `analysis/` modules.
"""))

    cells.append(_cell("markdown", "## Setup"))
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

from analysis.metrics import N_MUTATIONS, _coverage_curve, _read_first_hits
from analysis.discover import discover_dbs, discover_status
from analysis.constraint_loc_normalize import normalize_constraint_loc
from analysis.v6_comparison import _a4_reachable_union

PLOTS = IV7 / 'plots_internal'
PLOTS.mkdir(exist_ok=True)
COLORS = {
    'V0': '#e41a1c', 'V1': '#2ca02c', 'V2': '#d62728', 'V3': '#ff7f0e',
    'V4': '#9467bd', 'V5': '#1f77b4', 'V6': '#8c564b',
}

def show_plot(fig, path):
    fig.savefig(path, dpi=120, bbox_inches='tight')
    plt.close(fig)
    display(Image(filename=str(path)))

metrics = pd.read_csv(IV7 / 'internal_metrics_table.csv')
anchor = pd.read_csv(IV7 / 'internal_v0_anchor.csv')
v6_cmp = pd.read_csv(IV7 / 'internal_v6_vs_v1_v5.csv')
overlap = pd.read_csv(IV7 / 'internal_v6_v1_v5_loc_overlap.csv')
ata = pd.read_csv(IV7 / 'internal_v6_apples_to_apples.csv')
territory = pd.read_csv(IV7 / 'internal_v6_territory_coverage.csv')
kind = pd.read_csv(IV7 / 'internal_v6_kind_translation.csv')
kind_inv = pd.read_csv(IV7 / 'internal_v6_kind_inventory.csv')
sanity = json.loads((IV7 / 'internal_v0_sanity.json').read_text())
status = discover_status(IV7 / 'dbs')
v6_n = int(status['v6_seed_count'])
v6_partial = status['v6_partial']
print('Per-variant counts:', metrics.groupby('variant').size().to_dict())
print(f'V6 partial: {v6_partial} ({v6_n}/10 seeds)')
"""))

    cells.append(_cell("markdown", "## §2 — V0 anchor: Δ vs uniform random floor"))
    cells.append(_cell("code", """
# Key metrics for V1 and V5 vs V0 (from internal_v0_anchor.csv)
key_metrics = ['local_context_final', 'local_context_AUC', 'compressed_global_context_final',
               'allocation_entropy_by_zone']
sub = anchor[anchor['metric'].isin(key_metrics) & anchor['variant'].isin(['V1', 'V5'])]
pivot = sub.pivot(index='variant', columns='metric', values='delta_pct')
print(pivot.round(1).to_string())
print()
print(f"V1 CGC delta vs V0: {sanity['v1_cgc_delta_pct_vs_v0']:+.1f}% (p≈0.053 — does NOT reach α=0.05)")

fig, axes = plt.subplots(1, 3, figsize=(12, 4))
for ax, metric, title in zip(axes,
    ['local_context_final', 'local_context_AUC', 'compressed_global_context_final'],
    ['Local contexts', 'AUC', 'CGC']):
    s = anchor[(anchor.metric == metric) & (anchor.variant.isin(['V0','V1','V2','V3','V4','V5']))]
    ax.bar(s['variant'], s['variant_mean'], color=[COLORS.get(v,'#888') for v in s['variant']], alpha=0.8)
    ax.axhline(s[s.variant=='V0']['variant_mean'].iloc[0], color=COLORS['V0'], ls='--', lw=1.5, label='V0 floor')
    ax.set_title(f'{title} (mean)')
    ax.set_xlabel('Variant')
plt.suptitle('V0 anchor: structured prior gain over uniform random')
plt.tight_layout()
show_plot(fig, PLOTS / '01_v0_anchor_bars.png')
"""))

    cells.append(_cell("markdown", "## §2 — Cumulative coverage: V0–V5 (+ V6 full vs A4-reachable)"))
    cells.append(_cell("code", """
m = discover_dbs(IV7 / 'dbs', variants=('V0','V1','V2','V3','V4','V5','V6'))
a4_territory = _a4_reachable_union(IV7 / 'dbs', normalized=True)
fig, ax = plt.subplots(figsize=(11, 6))
x = np.arange(1, N_MUTATIONS + 1)

for var in ['V0','V1','V2','V3','V4','V5']:
    curves = []
    for seed, db in sorted(m[var].items()):
        with sqlite3.connect(db) as c:
            hits = _read_first_hits(c)
        curves.append(_coverage_curve(hits, n=N_MUTATIONS))
    arr = np.array(curves)
    mean, sd = arr.mean(0), arr.std(0, ddof=1)
    lw = 2.5 if var == 'V0' else 1.5
    ax.plot(x, mean, color=COLORS[var], lw=lw, label=f'{var} (n={len(curves)})')
    if var != 'V0':
        ax.fill_between(x, mean-sd, mean+sd, color=COLORS[var], alpha=0.08)
    else:
        ax.fill_between(x, mean-sd, mean+sd, color=COLORS['V0'], alpha=0.15)

# V6 full: individual seed lines (includes V6-exclusive locs)
v6_a4_curves = []
for seed, db in sorted(m['V6'].items()):
    with sqlite3.connect(db) as c:
        all_rows = c.execute('SELECT constraint_loc, first_hit_mutation_id FROM coverage').fetchall()
    full_hits = [int(r[1]) for r in all_rows]
    a4_hits = [int(r[1]) for r in all_rows if normalize_constraint_loc(r[0]) in a4_territory]
    ax.plot(x, _coverage_curve(full_hits, n=N_MUTATIONS), color=COLORS['V6'], ls='--', alpha=0.45, lw=1.0)
    v6_a4_curves.append(_coverage_curve(a4_hits, n=N_MUTATIONS))

if m['V6']:
    ax.plot([], [], color=COLORS['V6'], ls='--', alpha=0.6,
            label=f'V6 full (n={len(m["V6"])}) — incl. V6-exclusive locs')
    arr_a4 = np.array(v6_a4_curves)
    ax.plot(x, arr_a4.mean(0), color=COLORS['V6'], ls='-', lw=2.5,
            label=f'V6 A4-reachable only (mean, n={len(v6_a4_curves)})')
    ax.fill_between(x, arr_a4.mean(0) - arr_a4.std(0, ddof=1), arr_a4.mean(0) + arr_a4.std(0, ddof=1),
                    color=COLORS['V6'], alpha=0.12)

ax.axhline(46, color='gray', ls=':', alpha=0.6)
ax.set_xlabel('Mutation number'); ax.set_ylabel('Cumulative constraint_locs')
title = 'Cumulative local coverage'
if v6_partial:
    title += f' [V6 PARTIAL: {v6_n}/10 seeds]'
ax.set_title(title)
ax.legend(fontsize=7, loc='lower right'); ax.grid(alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '02_cumulative_coverage_v0_v6.png')
print('V6 full lines include 96 V6-exclusive locs A4 cannot reach. Solid brown = A4-reachable only (~20).')
"""))

    cells.append(_cell("markdown", "## §3 — V6 partial preview vs V1/V5"))
    cells.append(_cell("code", """
print(v6_cmp[v6_cmp.metric == 'local_context_final'].to_string(index=False))
print()
print('A4-territory coverage (normalized 51-loc union):')
print(territory.to_string(index=False))
print()
print('Callout: V6 mean 107.8 locs is on V6 full universe (incl. 96 V6-exclusive).')
print('On A4-reachable territory: V6 reaches 20/51 (39%) vs V5 50/51 (98%).')
if v6_partial:
    print(f'NOTE: n={v6_n} paired seeds — preview only; p-values suppressed.')
"""))

    cells.append(_cell("markdown", "## §4 — Loc overlap: raw vs normalized (format artifact)"))
    cells.append(_cell("code", """
raw = overlap[overlap.keying == 'raw'].set_index('set_name')['count']
norm = overlap[overlap.keying == 'normalized'].set_index('set_name')['count']
compare = pd.DataFrame({'raw': raw, 'normalized': norm})
print(compare.loc[['V6_union','V6_intersect_A4_reachable','V6_exclusive_vs_A4',
                     'V5_novel_4_hit_by_V6','V5_novel_4_missed_by_V6']])

fig, ax = plt.subplots(figsize=(8, 4))
labels = ['V6 full', 'V6∩A4', 'V6-exclusive']
raw_vals = [raw['V6_union'], raw['V6_intersect_A4_reachable'], raw['V6_exclusive_vs_A4']]
norm_vals = [norm['V6_union'], norm['V6_intersect_A4_reachable'], norm['V6_exclusive_vs_A4']]
x = np.arange(3); w = 0.35
ax.bar(x - w/2, raw_vals, w, label='raw keys (misleading)', color='#d62728', alpha=0.6)
ax.bar(x + w/2, norm_vals, w, label='normalized keys', color='#2ca02c', alpha=0.8)
ax.set_xticks(x); ax.set_xticklabels(labels)
ax.set_ylabel('Constraint loc count'); ax.set_title('V6 apples-to-apples: loc overlap')
ax.legend(); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '03_loc_overlap_raw_vs_norm.png')
print('V6 driver stores raw constraint_loc; A4 uses short_loc() — see §4.1 of report.')
"""))

    cells.append(_cell("markdown", "## §4 — Kind-set decomposition (shared / a4-only / v6-only)"))
    cells.append(_cell("code", """
fig, ax = plt.subplots(figsize=(9, 5))
variants = ['V0', 'V1', 'V5', 'V6']
groups = ['shared', 'a4_only', 'v6_only']
bottom = np.zeros(len(variants))
group_colors = {'shared': '#4daf4a', 'a4_only': '#377eb8', 'v6_only': '#ff7f00'}
for g in groups:
    vals = []
    for v in variants:
        row = kind_inv[(kind_inv.variant == v) & (kind_inv.kind_group == g)]
        vals.append(row['total_pulls'].iloc[0] if len(row) else 0)
    ax.bar(variants, vals, bottom=bottom, label=g, color=group_colors[g], alpha=0.85)
    bottom += np.array(vals)
ax.set_ylabel('Mutation pulls (pooled)'); ax.set_title('Kind-set allocation by variant')
ax.legend(title='kind_group'); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '04_kind_pulls_stacked.png')

# Shared-kind discovery rates (4 shared kinds only)
sk = kind[kind.kind_group == 'shared']
sk_sum = sk.groupby('variant')[['pulls','discoveries']].sum()
sk_sum['rate_per_1k'] = 1000 * sk_sum['discoveries'] / sk_sum['pulls']
print('Shared-kind pooled rates (all kinds in shared group):')
print(sk_sum.round(2))
"""))

    cells.append(_cell("markdown", "## §4 — Apples-to-apples: loc + CGC (two views, same story)"))
    cells.append(_cell("code", """
r = ata.iloc[0]
print('=== Loc-level (normalized) ===')
print(f"  V6 full: {int(r.v6_full_coverage_normalized)} | A4-reachable: {int(r.v6_a4_reachable_normalized)} "
      f"({r.v6_reachable_fraction_normalized*100:.1f}%) | exclusive: {int(r.v6_exclusive_vs_a4_normalized)}")
print('=== CGC-level (ctx_key) ===')
print(f"  V6 full: {int(r.v6_full_cgc)} | A4-reachable: {int(r.v6_a4_reachable_cgc)} "
      f"({r.v6_cgc_reachable_fraction*100:.1f}%) | exclusive: {int(r.v6_exclusive_cgc_vs_a4)}")

fig, ax = plt.subplots(figsize=(7, 4))
cats = ['Loc\\n(normalized)', 'CGC\\n(ctx_key)']
reachable = [r.v6_reachable_fraction_normalized * 100, r.v6_cgc_reachable_fraction * 100]
exclusive = [r.v6_exclusive_fraction_normalized * 100, r.v6_cgc_exclusive_fraction * 100]
x = np.arange(2); w = 0.5
ax.bar(x, reachable, w, label='A4-reachable %', color='#4daf4a')
ax.bar(x, exclusive, w, bottom=reachable, label='V6-exclusive %', color='#ff7f00')
ax.set_xticks(x); ax.set_xticklabels(cats)
ax.set_ylabel('% of V6 coverage'); ax.set_ylim(0, 100)
ax.set_title(f'V6 fairness decomposition (n={int(r.v6_seeds)} V6 seeds)')
ax.legend(loc='upper right'); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '05_apples_to_apples_loc_cgc.png')
"""))

    cells.append(_cell("markdown", "## §5 — Implications (data only; §6 conclusion TBD)"))
    cells.append(_cell("code", """
print('Headline data points for internal narrative:')
print(f"  1. V0→V1 CGC: {sanity['v1_cgc_delta_pct_vs_v0']:+.1f}% — zoned prior does NOT significantly improve CGC")
print(f"  2. V0→V1 local: +22.6% — structured prior helps sample efficiency on loc discovery")
print(f"  3. V5 zone entropy {sanity['v5_zone_entropy_mean']:.2f} vs V0 {sanity['v0_zone_entropy_mean']:.2f}")
print(f"  4. A4-territory: V5 {int(territory[territory.variant=='V5'].locs_in_a4_territory.iloc[0])}/51 vs V6 {int(territory[territory.variant=='V6'].locs_in_a4_territory.iloc[0])}/51")
print(f"  5. V5 novel 4 hit by V6: {int(overlap[(overlap.keying=='normalized')&(overlap.set_name=='V5_novel_4_hit_by_V6')].iloc[0]['count'])}/4")
print()
print('§6 conclusion: joint draft after Review #4 — not auto-generated.')
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
    out = Path(__file__).resolve().parents[1] / "INTERNAL_V0_V6_NOTEBOOK.ipynb"
    out.write_text(json.dumps(build_notebook(), indent=1))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
