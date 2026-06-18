#!/usr/bin/env python3
"""Generate IV_POS_8_D1B_NOTEBOOK.ipynb."""

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

    cells.append(_cell("markdown", """# IV.POS.8 D1.B — CGC Coarsening Variants

**Corpus:** 20 decay-comparison DBs (10 R2 V5 + 5 D1.A decayexp + 5 D1.A decayepoch).

**Variants:** `production_log2_corrected`, `region_only`, `log4_explicit`, `page_class`.

All memory keys from **corrected replay** (Batch 1.6); lookup pass-through from `hook3_raw`.

Artifacts from `build_d1b_artifacts.py`. Plots under `plots/`.
"""))

    cells.append(_cell("code", """
import json, sqlite3, sys
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from IPython.display import Image, display, Markdown

REPO = Path('/root/arguzz')
D1B = REPO / 'a4/runs/iv_pos_8/d1b'
IV7 = REPO / 'a4/runs/iv_pos_7'
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))
sys.path.insert(0, str(D1B / 'analysis'))

from analysis.metrics import N_MUTATIONS, _coverage_curve
from d1b_cgc_maps import VARIANTS, variant_first_hit_map
from replay_cgc_corrected import replay_memory_first_hits, replay_lookup_first_hits

PLOTS = D1B / 'plots'
PLOTS.mkdir(exist_ok=True)
COLORS = {'V5': '#1f77b4', 'V5-decayexp': '#2ca02c', 'V5-decayepoch': '#d62728'}

metrics = pd.read_csv(D1B / 'd1b_metrics_table.csv')
paired = pd.read_csv(D1B / 'd1b_paired_tests.csv')
saturation = pd.read_csv(D1B / 'd1b_saturation_profile.csv')
summary = json.loads((D1B / 'd1b_build_summary.json').read_text())
manifest = (D1B / 'd1b_artifacts.sha256').read_text()

def show_plot(fig, path):
    fig.savefig(path, dpi=120, bbox_inches='tight')
    plt.close(fig)
    display(Image(filename=str(path)))

def cgc_curve(db_path, cgc_variant):
    with sqlite3.connect(db_path) as conn:
        mem = replay_memory_first_hits(conn)
        lookup = replay_lookup_first_hits(conn)
        fhm = variant_first_hit_map(cgc_variant, mem, lookup, conn)
    return _coverage_curve(sorted(fhm.values()), n=N_MUTATIONS)
"""))

    cells.append(_cell("markdown", "## Headline numbers (V5 mean cgc_final)"))
    cells.append(_cell("code", """
rows = []
for cv in VARIANTS:
    for corpus in ('V5', 'V5-decayexp', 'V5-decayepoch'):
        m = metrics[(metrics['cgc_variant']==cv) & (metrics['corpus_variant']==corpus)]['cgc_final'].mean()
        rows.append({'cgc_variant': cv, 'corpus_variant': corpus, 'mean_cgc_final': round(m, 1)})
display(pd.DataFrame(rows).pivot(index='cgc_variant', columns='corpus_variant', values='mean_cgc_final'))
"""))

    cells.append(_cell("markdown", "## Saturation overlay vs local catalog saturation (paired V5)"))
    cells.append(_cell("code", """
# Overlay: mean cumulative CGC curves (4 variants, V5 paired seeds) vs local time_to_46 anchor
from analysis.discover import discover_dbs

VARIANT_COLORS = {
    'production_log2_corrected': '#1f77b4',
    'region_only': '#d62728',
    'log4_explicit': '#ff7f0e',
    'page_class': '#2ca02c',
}
VARIANT_LABELS = {
    'production_log2_corrected': 'production_log2_corrected',
    'region_only': 'region_only',
    'log4_explicit': 'log4_explicit',
    'page_class': 'page_class',
}

paired_seeds = summary['paired_seeds']
x = np.arange(1, N_MUTATIONS + 1)
m_v5 = discover_dbs(IV7 / 'dbs', variants=('V5',))

# Local saturation anchor: mean time_to_46 on paired V5 seeds (from D1.A)
import pandas as pd
d1a = pd.read_csv(REPO / 'a4/runs/iv_pos_8/d1a/d1a_metrics_table.csv')
local_sat_mean = float(d1a[(d1a.variant=='V5') & (d1a.seed.isin(paired_seeds))]['time_to_46'].mean())
print(f'Local saturation anchor (mean time_to_46): {local_sat_mean:.0f}')

curves_by_variant = {}
for cv in VARIANTS:
    curves = []
    for seed in paired_seeds:
        db = m_v5['V5'][seed]
        curves.append(cgc_curve(db, cv))
    curves_by_variant[cv] = np.array(curves)

# --- Absolute overlay ---
fig, ax = plt.subplots(figsize=(11, 6))
for cv in VARIANTS:
    arr = curves_by_variant[cv]
    mean_curve = arr.mean(0)
    ax.plot(x, mean_curve, color=VARIANT_COLORS[cv], lw=2.5, label=VARIANT_LABELS[cv])
    row = saturation[saturation.cgc_variant == cv].iloc[0]
    sat_mut = int(row.saturation_mutation_id)
    sat_idx = min(sat_mut, N_MUTATIONS) - 1
    ax.scatter([sat_mut], [mean_curve[sat_idx]], color=VARIANT_COLORS[cv], s=120, zorder=5,
               edgecolors='black', linewidths=1.2, marker='o')

ax.axvline(local_sat_mean, color='black', ls='--', lw=2,
           label=f'local sat (mean time_to_46 = {local_sat_mean:.0f})')
ax.set_xlabel('Mutation index')
ax.set_ylabel('Cumulative CGC keys (hybrid)')
ax.set_title('CGC saturation overlay — V5 paired seeds (n=5)')
ax.legend(fontsize=8, loc='lower right')
ax.grid(alpha=0.3)
ax.set_xlim(0, N_MUTATIONS)
show_plot(fig, PLOTS / 'd1b_saturation_overlay_v5.png')

# --- Normalized overlay ---
fig, ax = plt.subplots(figsize=(11, 6))
for cv in VARIANTS:
    arr = curves_by_variant[cv]
    finals = arr[:, -1].astype(float)
    finals[finals == 0] = np.nan
    norm = arr / finals[:, None] * 100.0
    mean_norm = np.nanmean(norm, axis=0)
    ax.plot(x, mean_norm, color=VARIANT_COLORS[cv], lw=2.5, label=VARIANT_LABELS[cv])
    row = saturation[saturation.cgc_variant == cv].iloc[0]
    sat_mut = int(row.saturation_mutation_id)
    sat_idx = min(sat_mut, N_MUTATIONS) - 1
    ax.scatter([sat_mut], [mean_norm[sat_idx]], color=VARIANT_COLORS[cv], s=120, zorder=5,
               edgecolors='black', linewidths=1.2, marker='o')

ax.axvline(local_sat_mean, color='black', ls='--', lw=2,
           label=f'local sat (mean time_to_46 = {local_sat_mean:.0f})')
ax.axhline(95, color='gray', ls=':', lw=1, alpha=0.7)
ax.set_xlabel('Mutation index')
ax.set_ylabel('% of final CGC keys discovered')
ax.set_title('Normalized CGC saturation overlay — V5 paired seeds (n=5)')
ax.legend(fontsize=8, loc='lower right')
ax.grid(alpha=0.3)
ax.set_xlim(0, N_MUTATIONS)
ax.set_ylim(0, 105)
show_plot(fig, PLOTS / 'd1b_saturation_overlay_v5_norm.png')
"""))

    cells.append(_cell("markdown", "## AUC paired tests (decayexp vs V5)"))
    cells.append(_cell("code", """
auc_pt = paired[(paired.metric=='auc_normalized') & (paired.comparison=='V5-decayexp vs V5')]
display(auc_pt[['cgc_variant','mean_a','mean_b','mean_diff','p_value']].round(4).sort_values('p_value'))
"""))

    cells.append(_cell("markdown", "## Cumulative CGC curves (1 plot per variant, paired seeds)"))
    cells.append(_cell("code", """
paired_seeds = summary['paired_seeds']
x = np.arange(1, N_MUTATIONS + 1)

for cv in VARIANTS:
    fig, ax = plt.subplots(figsize=(10, 5))
    for corpus in ('V5', 'V5-decayexp', 'V5-decayepoch'):
        sub = metrics[(metrics['cgc_variant']==cv) & (metrics['corpus_variant']==corpus) & (metrics['seed'].isin(paired_seeds))]
        curves = [cgc_curve(p, cv) for p in sub['db_path']]
        arr = np.array(curves)
        ax.plot(x, arr.mean(0), color=COLORS[corpus], lw=2, label=f'{corpus} (n={len(curves)})')
        if len(curves) > 1:
            ax.fill_between(x, arr.mean(0)-arr.std(0,ddof=1), arr.mean(0)+arr.std(0,ddof=1),
                            color=COLORS[corpus], alpha=0.12)
    ax.set_title(f'Cumulative CGC — {cv}')
    ax.set_xlabel('Mutation index')
    ax.set_ylabel('Cumulative CGC keys')
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    show_plot(fig, PLOTS / f'cgc_curve_{cv}.png')
"""))

    cells.append(_cell("markdown", "## Paired tests (cgc_final)"))
    cells.append(_cell("code", """
pt = paired[paired['metric']=='cgc_final'][['cgc_variant','comparison','n_paired','mean_a','mean_b','mean_diff','p_value']]
display(pt.round(3))
"""))

    cells.append(_cell("markdown", "## Saturation profile"))
    cells.append(_cell("code", """
display(saturation)
"""))

    cells.append(_cell("markdown", "## Reproducibility"))
    cells.append(_cell("code", """
display(Markdown('```\\n' + manifest + '```'))
display(Markdown(f"git commit: `{summary['git_commit']}`"))
display(Markdown(f"sanity_pass: **{summary['sanity_pass']}**"))
"""))

    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python"},
        },
        "cells": cells,
    }


def main() -> int:
    out = Path(__file__).resolve().parents[1] / "IV_POS_8_D1B_NOTEBOOK.ipynb"
    out.write_text(json.dumps(build_notebook(), indent=1))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
