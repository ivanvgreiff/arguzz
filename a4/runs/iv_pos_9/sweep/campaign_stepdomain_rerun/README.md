# IV.POS.9 Track-B — step-domain re-run campaign (coverage results)

Self-contained results folder for **one campaign only**: the step-domain re-run (the Arguzz variants
re-run with the `68d90aa` zone fix, plus the external A4/`V5_control` baseline from the 3-kind re-run).
Created so this campaign's data can never be confused with the original Jun-24 run or the 3-kind run.

## Files
| file | what |
|---|---|
| `PROVENANCE.md` | **Read first.** Exactly where every datum comes from; what is deliberately excluded and why. |
| `REPORT.md` | Living findings report (coverage tables + the local/global dissociation). |
| `coverage_curves.html` | Rendered notebook — per-guest curves (LOC · CTX · CGC), 4 variants overlaid. |
| `coverage_curves.ipynb` | The executed notebook. |
| `extract_curves.py` | Read-only extractor (runs on coinbase) → emits the two CSVs below. |
| `build_notebook.py` | Builds + executes + renders the notebook from the CSVs (reads nothing else). |
| `data_extracted/jobs.csv` | One row per job: source, guest, variant, seed, host, **db_path**, n_mut, final counts. |
| `data_extracted/curve_points.csv` | First-hit mutation ids per (guest,variant,seed,host,metric) — the curve data. |
| `data_extracted/EXTRACTION_LOG.txt` | stderr of the last extraction (timestamp + per-node/job counts). |

## Data flow (strict separation)
```
POS node DBs  (this campaign, /tmp/chainjob_*/run.db, READ-ONLY in place)
coinbase DBs  (external V5_control only, results_rerun/+results_miss/, READ-ONLY in place)
        │  extract_curves.py  (ssh node python3 - ; sqlite mode=ro ; never moves/edits a DB)
        ▼
data_extracted/{jobs,curve_points}.csv      ← the ONLY thing the notebook reads
        │  build_notebook.py
        ▼
coverage_curves.ipynb + .html
```
No DB is copied into this folder; no external DB is edited or moved. The CSVs are this campaign's derived
artifacts, each row stamped with its `source` and `db_path`.

## Refresh (as more jobs finish)
```bash
# 1) extract (on coinbase; reads sources in place) and capture locally
scp a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/extract_curves.py coinbase:/tmp/ivg_sweep/
ssh coinbase 'python3 /tmp/ivg_sweep/extract_curves.py' \
   > a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/data_extracted/_capture.txt \
   2> a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/data_extracted/EXTRACTION_LOG.txt
# 2) split _capture.txt on the ###JOBS / ###CURVES sentinels into jobs.csv + curve_points.csv
#    (drop the leading 'kind|' column; see the split snippet in the build commit / chat log)
# 3) rebuild
python3 a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/build_notebook.py
```
CSVs use `|` as the delimiter. The notebook clips first-hits to N=5000 (fair window across variants).
