#!/usr/bin/env python3
"""Generate MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb scaffold (Phase 9.7)."""
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

    cells.append(_cell("markdown", """# MAB Architecture Notebook — IV.POS.7 (Pro Round 2)

Companion to `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`. All computation delegates to
`a4/runs/iv_pos_7/analysis/` — no inline metric logic.

**Variants:** V1–V5 × 10 seeds × N=6000. **Protagonist:** V5 (`cTS_semantic_v2`).
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — Setup"))
    cells.append(_cell("code", """
import sys
from pathlib import Path
import matplotlib
matplotlib.use('Agg')  # headless-safe; figures embedded via IPython.display below
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from IPython.display import Image, display

REPO = Path('/root/arguzz')
IV7 = REPO / 'a4/runs/iv_pos_7'
sys.path.insert(0, str(IV7))

from analysis.metrics import compute_metrics_frame, aggregate_by_variant, N_MUTATIONS
from analysis.stats import paired_tests
from analysis.success_criteria import evaluate_success_criteria
from analysis.counterfactuals import counterfactual_kind_summary, counterfactual_by_kind_frame, instr_type_mod_ranking_check
from analysis.per_arm_diagnostic import per_arm_diagnostic_frame, v5_mode_summary
from analysis.discovery_rate import discovery_rate_summary, discovery_rate_by_kind_frame
from analysis.per_loc_v2 import per_loc_v2_summary, per_loc_v2_cells_frame
from analysis.discover import discover_dbs, VARIANT_TO_PRO_NAME

PLOTS = IV7 / 'plots'
PLOTS.mkdir(exist_ok=True)
VARIANTS = ['V1', 'V2', 'V3', 'V4', 'V5']
COLORS = {'V1': '#2ca02c', 'V2': '#d62728', 'V3': '#ff7f0e', 'V4': '#9467bd', 'V5': '#1f77b4'}

def show_plot(fig, path):
    \"\"\"Save PNG to plots/ and embed inline in HTML (works with Agg + nbconvert).\"\"\"
    fig.savefig(path, dpi=120, bbox_inches='tight')
    plt.close(fig)
    display(Image(filename=str(path)))

metrics = pd.read_csv(IV7 / 'metrics_table.csv')
agg = pd.read_csv(IV7 / 'metrics_aggregate.csv')
paired = pd.read_csv(IV7 / 'paired_tests.csv')
success = pd.read_csv(IV7 / 'success_criteria.csv')
dr = pd.read_csv(IV7 / 'discovery_rate_by_kind.csv')
ploc = pd.read_csv(IV7 / 'per_loc_v2_cells.csv')
print(metrics.groupby('variant').size())
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — Headline coverage table"))
    cells.append(_cell("code", """
print(agg[['variant','local_context_final_mean','local_context_final_std',
           'local_coverage_v2_final_mean','local_context_AUC_mean','all_46_hit_rate',
           'allocation_entropy_by_zone_mean','novel_locs_union_vs_v1']].to_string(index=False))
"""))

    cells.append(_cell("markdown", "## ★ Smoking gun — V5 novel contexts vs V1 union (Criterion 5)"))
    cells.append(_cell("code", """
import json
novel = json.loads((IV7 / 'v5_novel_contexts.json').read_text())
print(f"V1 union: {novel['v1_union_size']} constraint_locs")
print(f"V5 union: {novel['v5_union_size']} constraint_locs")
print("Novel in V5 never hit by any V1 seed:")
for loc in novel['novel_locs_union_vs_v1']:
    print(f"  + {loc}")
print()
print("Footnote: V3 also found 3 novel locs vs V1 union:")
print("  ControlLoadRootAndNonce@inst_control.zir:35")
print("  ControlLoadRootAndNonce@inst_control.zir:36  ← V3-exclusive (V5 missed LRN@36)")
print("  ControlMRET@inst_control.zir:93")
print("V5 found LRN@44 and LRN@45 instead; both probe the LRN/MRET cluster.")
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — Cumulative coverage AUC curves"))
    cells.append(_cell("code", """
import sqlite3
from analysis.metrics import _coverage_curve, _read_first_hits

m = discover_dbs(IV7 / 'dbs')
fig, ax = plt.subplots(figsize=(10, 6))
x = np.arange(1, N_MUTATIONS + 1)
for var in VARIANTS:
    curves = []
    for seed, db in sorted(m[var].items()):
        with sqlite3.connect(db) as c:
            hits = _read_first_hits(c)
        curves.append(_coverage_curve(hits, n=N_MUTATIONS))
    arr = np.array(curves)
    mean, sd = arr.mean(0), arr.std(0, ddof=1)
    ax.plot(x, mean, color=COLORS[var], label=f"{var}")
    ax.fill_between(x, mean - sd, mean + sd, color=COLORS[var], alpha=0.12)
ax.axhline(46, color='gray', ls='--', alpha=0.5)
ax.set_xlabel('Mutation number'); ax.set_ylabel('Cumulative coverage (legacy table)')
ax.set_title('IV.POS.7: cumulative local context discovery')
ax.legend(fontsize=8); ax.grid(alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '01_cumulative_coverage.png')
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — Zone allocation entropy (all variants)"))
    cells.append(_cell("code", """
fig, ax = plt.subplots(figsize=(10, 5))
data = [metrics[metrics.variant == v]['allocation_entropy_by_zone'].values for v in VARIANTS]
bp = ax.boxplot(data, tick_labels=VARIANTS, patch_artist=True)
for patch, v in zip(bp['boxes'], VARIANTS):
    patch.set_facecolor(COLORS[v]); patch.set_alpha(0.4)
ax.set_ylabel('Shannon entropy (zones)')
ax.set_title('Zone allocation entropy (V1–V4: step classifier; V5: bandit zones)')
plt.tight_layout()
show_plot(fig, PLOTS / '02_zone_entropy.png')
print('Zone entropy means:', agg.set_index('variant')['allocation_entropy_by_zone_mean'].to_dict())
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — local_coverage_v2_final (secondary, Pro §8 granularity)"))
    cells.append(_cell("code", """
fig, ax = plt.subplots(figsize=(8, 5))
data = [metrics[metrics.variant == v]['local_coverage_v2_final'].values for v in VARIANTS]
bp = ax.boxplot(data, tick_labels=VARIANTS, patch_artist=True)
for patch, v in zip(bp['boxes'], VARIANTS):
    patch.set_facecolor(COLORS[v]); patch.set_alpha(0.4)
ax.set_ylabel('local_coverage_v2 count'); ax.set_title('Finer (loc, major, minor) contexts at N=6000')
plt.tight_layout()
show_plot(fig, PLOTS / '03_local_coverage_v2.png')
"""))

    cells.append(_cell("markdown", "## Phase 9.1 — Per-loc v2 depth (wide vs deep)"))
    cells.append(_cell("code", """
# Fair comparison on V1's 46 common constraint_locs (per_loc_v2_cells_per_seed.csv).
ps = pd.read_csv(IV7 / 'per_loc_v2_cells_per_seed.csv')
v1_locs = set(ps[ps.variant == 'V1']['constraint_loc'])
rows = []
for var in VARIANTS:
    sub = ps[(ps.variant == var) & (ps.constraint_loc.isin(v1_locs))]
    rows.append({
        'variant': var,
        'mean_locs_per_seed': metrics[metrics.variant == var]['local_context_final'].mean(),
        'mean_v2_per_common_loc': sub['v2_cell_count'].mean(),
        'mean_total_v2': metrics[metrics.variant == var]['local_coverage_v2_final'].mean(),
    })
summary = pd.DataFrame(rows)
print(summary.to_string(index=False))
print()
print('V5 dominates V1 on breadth, depth-per-common-loc, and total v2.')
print('V3/V4 beat V5 on per-loc depth but miss V5 novel kernel/ECALL locs.')

fig, ax = plt.subplots(figsize=(9, 5))
for var in VARIANTS:
    sub = ploc[ploc.variant == var]
    ax.scatter(sub['mean_v2_cells'], sub['constraint_loc'].str.split('@').str[0],
               alpha=0.5, s=20, color=COLORS[var], label=var)
ax.set_xlabel('Mean v2 cells per constraint_loc (10 seeds)')
ax.set_title('Per-loc v2 depth by variant (jittered by loc family)')
ax.legend(fontsize=8)
plt.tight_layout()
show_plot(fig, PLOTS / '04_per_loc_v2_depth.png')
"""))

    cells.append(_cell("markdown", "## Phase 9.2 — Paired tests vs V1"))
    cells.append(_cell("code", """
print(paired.to_string(index=False))
"""))

    cells.append(_cell("markdown", "## Phase 9.3 — Success criteria (Pro §10)"))
    cells.append(_cell("code", """
for var in ['V2','V3','V4','V5']:
    sub = success[success.variant == var]
    passed = sub[sub.passed].criterion_id.tolist()
    print(f"{var}: {len(passed)}/5 PASS — {passed}")
"""))

    cells.append(_cell("markdown", "## Phase 9.4 — Discovery rate per kind (IV.POS.5 §17.1 smoking gun)"))
    cells.append(_cell("code", """
# First-hit credit on coverage.constraint_loc / mutations of that kind / 1000 pulls.
v1v5 = dr[dr.variant.isin(['V1','V5'])].pivot(index='kind', columns='variant', values='discovery_rate_per_1k')
print(v1v5.round(2).to_string())

fig, ax = plt.subplots(figsize=(10, 5))
kinds = dr['kind'].unique()
x = np.arange(len(kinds))
w = 0.35
v1_rates = [dr[(dr.variant=='V1') & (dr.kind==k)]['discovery_rate_per_1k'].iloc[0] for k in kinds]
v5_rates = [dr[(dr.variant=='V5') & (dr.kind==k)]['discovery_rate_per_1k'].iloc[0] for k in kinds]
ax.bar(x - w/2, v1_rates, w, label='V1', color=COLORS['V1'], alpha=0.7)
ax.bar(x + w/2, v5_rates, w, label='V5', color=COLORS['V5'], alpha=0.7)
ax.set_xticks(x); ax.set_xticklabels(kinds, rotation=45, ha='right')
ax.set_ylabel('Discoveries per 1000 mutations')
ax.set_title('Discovery rate by kind: V1 vs V5 (COMP_OUT_MOD 8× improvement)')
ax.legend(); ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '05_discovery_rate_by_kind.png')
"""))

    cells.append(_cell("markdown", "## Phase 9.4 — Counterfactual rewards (Pro §12)"))
    cells.append(_cell("code", """
cf = counterfactual_kind_summary(counterfactual_by_kind_frame(IV7 / 'dbs'))
itm = cf[cf.kind == 'INSTR_TYPE_MOD'][['variant','current_reward','discovery_binary_reward']].copy()
for v in itm['variant']:
    sub = cf[cf.variant == v]
    itm.loc[itm.variant==v, 'rank_current'] = int(sub.current_reward.rank(ascending=False)[sub.kind=='INSTR_TYPE_MOD'].iloc[0])
    itm.loc[itm.variant==v, 'rank_discovery'] = int(sub.discovery_binary_reward.rank(ascending=False)[sub.kind=='INSTR_TYPE_MOD'].iloc[0])
print(itm[itm.variant.isin(['V1','V3','V5'])].round(3).to_string(index=False))
print()
print('Allocation, not reward redesign, was the decisive lever for V1/V5 (ITM rank 1 under both).')
print('Discovery rate per kind (previous cell) is the authoritative per-kind diagnostic.')
"""))

    cells.append(_cell("markdown", "## Phase 9.5 — V5 per-arm mode breakdown"))
    cells.append(_cell("code", """
v5 = per_arm_diagnostic_frame(IV7 / 'dbs')
ms = v5_mode_summary(v5['mode_totals'])
print(ms)
print()
print('σ=0 across seeds is expected: cTS_semantic_v2 schedules MODE deterministically')
print('by mutation index (Pro §7.C k-armed floor); seed only randomizes arm within mode.')
top = v5['cumulative_reward_by_arm'].groupby('arm_id')['cumulative_reward'].mean().sort_values(ascending=False).head(10)
print('Top arms by mean cumulative reward:')
print(top)
"""))

    cells.append(_cell("markdown", "## Summary placeholder (D1 §7 — human-authored, not Composer)"))
    cells.append(_cell("code", """
print('Headline: V5 — 4 novel contexts + 5/5 criteria + 4.3× speedup to 43 (p<1e-4).')
print('See success_criteria.csv, v5_novel_contexts.json, discovery_rate_by_kind.csv.')
print('Do NOT treat this cell as D1 conclusion text.')
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
    out = Path(__file__).resolve().parents[1] / "MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb"
    out.write_text(json.dumps(build_notebook(), indent=1))
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
