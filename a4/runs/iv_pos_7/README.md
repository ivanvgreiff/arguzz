# IV.POS.7 — Pro Round 2 Packet

**Date:** 2026-06-15  
**Campaign:** IV.POS.7 (5 variants × 10 seeds × N=6000)

## What to read first

| Priority | File | Description |
|---|---|---|
| 1 | `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | **D1** — narrative response (§§1–7 + appendix) |
| 2 | `MAB_ARCHITECTURE_NOTEBOOK_R2.html` | **D3** — rendered analysis with plots |
| 3 | `CLOUD1_DECISIONS_FOR_PRO_R2.md` | Non-Pro-spec choices (zones, CGC schema, etc.) |
| 4 | `ProG_Report_2.md` | Pro's original Round 2 recommendations (context) |

## Supporting data (D4–D8)

| File | Deliverable |
|---|---|
| `COLLECTION_REPORT_FINAL.json` | D4 — 50/50 DB validation |
| `metrics_table.csv` / `metrics_aggregate.csv` | D6 |
| `paired_tests.csv` | D7 |
| `success_criteria.csv` | D8 |
| `discovery_rate_by_kind.csv` | IV.POS.5 §17.1 analogue |
| `per_loc_v2_cells.csv` | Per-loc v2 depth (wide vs deep) |
| `counterfactual_kind_summary.csv` | Pro §12 counterfactual means |
| `v5_novel_contexts.json` | Criterion 5 smoking gun |
| `plots/*.png` | D5 stand-alone figures |

## Reproduce

```bash
cd /root/arguzz
pip install -r a4/runs/iv_pos_7/analysis/requirements.txt
PYTHONPATH=/root/arguzz/a4/runs/iv_pos_7 python3 a4/runs/iv_pos_7/analysis/build_artifacts.py
python3 a4/runs/iv_pos_7/analysis/build_notebook.py
MPLBACKEND=Agg jupyter nbconvert --to notebook --execute a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb --ExecutePreprocessor.timeout=600
python3 a4/runs/iv_pos_7/build_packet.py
```

## Deferred (not in this packet)

- `INTERNAL_V0_V6_ANALYSIS.md` — V0/V6 when DBs land
