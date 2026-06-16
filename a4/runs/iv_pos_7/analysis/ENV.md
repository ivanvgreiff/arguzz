# IV.POS.7 analysis environment

**Pinned for:** Phase 9 Pro Round 2 deliverables (`DELIVERABLES_PLAN.md` Steps 1–12).

## Python

- **Version:** Python 3.12 (system `python3` on WSL analysis host).
- **Install:** `pip install -r a4/runs/iv_pos_7/analysis/requirements.txt`
- **Run tests:** `cd /root/arguzz && PYTHONPATH=/root/arguzz python3 -m pytest a4/runs/iv_pos_7/analysis/test_metrics.py a4/runs/iv_pos_7/analysis/test_stats.py -q`

## Parity with IV.POS.5 notebook

The IV.POS.5 diagnostic notebook (`a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb`) used the same core stack: `numpy`, `pandas`, `scipy`, `matplotlib`, `sqlite3` (stdlib). This pin list matches that stack; versions are minimum floors, not exact replicas of the 2026-06-07 IV.POS.5 run environment.

## Scope boundary

All analysis code lives under `a4/runs/iv_pos_7/analysis/`. It imports read-only helpers from `a4/pos/collect_results_pos.py` but does **not** modify `a4/standalone/` or other production paths.
