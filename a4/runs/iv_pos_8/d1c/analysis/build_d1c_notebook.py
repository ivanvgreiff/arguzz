#!/usr/bin/env python3
"""Generate IV_POS_8_D1C_NOTEBOOK.ipynb and render HTML."""

from __future__ import annotations

import json
import subprocess
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
    cells.append(_cell("markdown", """# IV.POS.8 D1.C — Bug-Proximity Metric Stack

**Corpus:** 30 Cat-A DBs (10 V1 + 10 V5 + 10 D1.A decay).

Artifacts from Batches 1–3 under `a4/runs/iv_pos_8/d1c/`.
"""))

    cells.append(_cell("code", """
import sys
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from IPython.display import Image, display, Markdown

REPO = Path('/root/arguzz')
D1C = REPO / 'a4/runs/iv_pos_8/d1c'
PLOTS = D1C / 'plots'

tier1 = pd.read_csv(D1C / 'd1c_batch1_tier1_audit.csv')
metrics = pd.read_csv(D1C / 'd1c_metrics_table.csv')
corr = pd.read_csv(D1C / 'd1c_correlation_matrix.csv')
paired = pd.read_csv(D1C / 'd1c_paired_tests.csv')

def show_png(name):
    path = PLOTS / name
    if path.exists():
        display(Image(filename=str(path)))
"""))

    cells.append(_cell("markdown", "## §1 Tier-1 fire-rate audit (Batch 1)"))
    cells.append(_cell("code", """
show_png('d1c_batch1_fire_rate_full.png')
show_png('d1c_batch1_fire_rate_post_local.png')
summary = tier1.groupby('signal_name').agg(
    fire_rate_full=('fire_rate_full', 'mean'),
    fire_rate_post_local=('fire_rate_post_local', 'mean'),
)
display(summary.round(4))
"""))

    cells.append(_cell("markdown", "## §2 Tier-2 metrics table (Batch 2)"))
    cells.append(_cell("code", """
display(metrics.groupby('corpus')[
    ['cat_a_pro_s5_singleton_failure_rate', 'cat_a_pro_s5_d_loc_p95',
     'cat_a_pro_s5_co_failure_graph_degree_p95']
].mean().round(4))

singleton = paired[paired.metric == 'cat_a_pro_s5_singleton_failure_rate']
display(singleton[['comparison', 'mean_a', 'mean_b', 'p_value']])
"""))

    cells.append(_cell("markdown", "## §3 Correlation heatmap (Batch 3, V5 paired seeds)"))
    cells.append(_cell("code", """
v5p = corr[(corr.variant == 'V5') & (corr.seed.isin([1234,1235,1236,1237,1238]))]
pivot = v5p.pivot_table(index='signal_name', columns='channel_name', values='pearson_r', aggfunc='mean')
fig, ax = plt.subplots(figsize=(6, 4))
im = ax.imshow(pivot.values, vmin=-0.4, vmax=0.4, cmap='RdBu_r', aspect='auto')
ax.set_xticks(range(len(pivot.columns)))
ax.set_xticklabels(pivot.columns, rotation=30, ha='right')
ax.set_yticks(range(len(pivot.index)))
ax.set_yticklabels(pivot.index)
ax.set_title('Mean Pearson r (V5 paired seeds, post-local window)')
plt.colorbar(im, ax=ax)
out = PLOTS / 'd1c_batch3_corr_heatmap_v5.png'
fig.savefig(out, dpi=120, bbox_inches='tight')
plt.close(fig)
display(Image(filename=str(out)))
display(pivot.round(3))
"""))

    cells.append(_cell("markdown", "## §4 Shortlist summary"))
    cells.append(_cell("code", """
shortlist = (D1C / 'd1c_signal_shortlist.md').read_text()
display(Markdown(shortlist.split('## Bucket A')[0] + '## Bucket A (excerpt)\\n\\nSee `d1c_signal_shortlist.md` for full buckets.'))
"""))

    cells.append(_cell("markdown", "## §5 D1.E hand-off pointer"))
    cells.append(_cell("code", """
display(Markdown((D1C / 'd1e_handoff_L1_signals.md').read_text()[:2000] + '\\n\\n...'))
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
            "language_info": {"name": "python", "pygments_lexer": "ipython3"},
        },
        "cells": cells,
    }


def main() -> int:
    d1c = Path(__file__).resolve().parents[1]
    nb_path = d1c / "IV_POS_8_D1C_NOTEBOOK.ipynb"
    html_path = d1c / "IV_POS_8_D1C_NOTEBOOK.html"
    nb_path.write_text(json.dumps(build_notebook(), indent=1))
    print(f"wrote {nb_path}")
    subprocess.run(
        ["jupyter", "nbconvert", "--to", "html", str(nb_path), "--output", html_path.stem],
        cwd=d1c,
        check=True,
    )
    print(f"wrote {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
