# CVE post-fix analysis — self-contained, clean-room folder

**Purpose:** everything for the **unconfounded** (post-step-domain-fix) rs1==rs2 CVE comparison —
new data, notebooks, figures, docs — kept **fully separate** from the original bug-race work so
databases never get mixed up.

## Golden rules (do not break)
1. **Never edit, move, checkpoint, or overwrite any EXISTING database/notebook/markdown** used by the
   original race (everything under `../race/`, `../a1/`, `../../../docs/cloud3/...`). We only **read** them,
   read-only, in place.
2. **All NEW data lives here** under `data/` (downloaded copies of the post-fix runs).
3. **All DB access goes through `lib/data_access.py::open_ro()`** — which opens `mode=ro&immutable=1`
   (cannot write, cannot touch `-wal`/`-shm`, cannot lock). Notebooks never build their own sqlite handles.
4. **Provenance is explicit**: every dataset's origin/binary/validity is in `lib/data_access.py` (machine)
   and `DATA_PROVENANCE.md` (human). If you're unsure where a number came from, look there.

## Folder layout
```
cve_postfix_analysis/
├── README.md                 ← you are here
├── DATA_PROVENANCE.md        ← human-readable: every dataset, where it's from, valid-for-what
├── lib/
│   ├── data_access.py        ← SOURCES registry + open_ro() (the only way to open a DB)
│   └── cve_metrics.py        ← the CVE metric + per-variant aggregation (new code; does not touch existing scripts)
├── data/                     ← NEW downloaded post-fix DBs (after running the scripts)
│   ├── v6_cTS_postfix/seed{1234..1239}.db
│   ├── hybrid_B2_postfix/seed{1234..1239}.db
│   ├── hybrid_B3_clean/seed{1234..1239}.db
│   └── MANIFEST.md           ← sha-verified inventory (written by pull_to_local.sh)
├── refs/
│   └── EXISTING_DATA_READONLY.md  ← exact read-only paths to the original race DBs (uniform, V5, pre-fix)
├── scripts/
│   ├── stage_on_coinbase.sh  ← (on coinbase) checkpoint+gather the 18 new DBs to /tmp/postfix_dl
│   └── pull_to_local.sh      ← (in sandbox) pull -> data/, verify sha, write MANIFEST
├── notebooks/                ← analysis/graph notebooks (to create)
└── figures/                  ← generated plots
```

## How to populate + analyze (run when the runs finish)
1. **Download (one time):** run `scripts/stage_on_coinbase.sh` detached on coinbase, then
   `scripts/pull_to_local.sh` in the sandbox. This fills `data/` + writes `data/MANIFEST.md` (sha-verified).
   It checkpoints only OUR new run DBs; it never reads/writes anything under `../race/`.
2. **Sanity:** `python3 lib/data_access.py` — prints every source + which seeds are present.
3. **Notebooks** import `from lib.data_access import SOURCES, BY_KEY, open_ro, cve_candidates` and pull
   NEW data from `data/` and EXISTING data (uniform/V5/pre-fix) read-only from `../race/cve_results`.
   No path is ever hardcoded in a notebook; no existing DB is ever written.

## What's NEW here vs EXISTING (read-only)
- **NEW (in `data/`):** V6_cTS post-fix, Hybrid post-fix on B2, Hybrid clean on B3.
- **EXISTING (read-only, in `../race/cve_results`):** V6_uniform baseline, V5_control, and the pre-fix
  (confounded) V6_cTS/Hybrid kept only for the "before the fix" contrast. See `refs/EXISTING_DATA_READONLY.md`.
