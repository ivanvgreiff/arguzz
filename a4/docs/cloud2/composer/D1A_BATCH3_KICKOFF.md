# D1.A Batch 3 — POS smoke-gate dispatch — Composer Kickoff

**Parent spec:** `a4/docs/cloud2/IV_POS_8_D1_A_SPEC.md`
**Status:** Local Batch 3 attempt abandoned 2026-06-16 (Ivan's WSL ~46 sec/mut → ~7.5 h for N=200 × 3). This kickoff replaces it with a POS-based gate.
**Branch:** `cloud2`
**Date issued:** 2026-06-16

---

## Why this is now a POS gate, not a local smoke

Local smoke is untenable on Ivan's machine (Composer's evidence: 22 mutations in 17 min during the abandoned Batch 3 attempt). Three sources of validation make the local smoke redundant anyway:

1. **Unit tests:** `test_floor_schedule.py` (14 tests) verifies decay math + K=50 clip behavior
2. **Golden-trace test:** `test_bandit_ts.py::TestConstrainedTSFloorScheduleIntegration` verifies that `ConstrainedTSScheduler(floor_schedule=ConstantFloor(0.55))` produces identical decisions to legacy V5 (back-compat is golden-trace-locked, not just argued)
3. **Integration tests:** `test_fuzzer_decay_schedules.py` (5 tests) verifies all 3 selectors instantiate, `campaign_params.extra_json` persists correctly, mid-run `_local_loc_discoveries == COUNT(*) FROM coverage` at checkpoints n=10/25/50, schema columns populate, legacy NULLs tolerated

What these DON'T cover: real `risc0-host` invocation through POS-side `cli fuzz` with the new selector names, and decay behavior visible at scale (the latter only emerges after cold-start exit at mutation ~144, well past any 200-mutation smoke).

**Solution:** the first batch of production jobs is the smoke. It produces real D1.A data **and** acts as a deployment gate, with a hard human checkpoint before the remaining 12 jobs commit.

---

## Goal

Dispatch 8 production jobs (4 paired seeds × 2 new variants) on POS, collect 8 DBs, verify every pass criterion in spec §4.2, then **HALT and report** for Opus/Ivan review. Do not auto-continue to Batch 4.

Total wall: ~5.5 h compute (Tier-A 10% slowdown sets the limit) + ~30 min Composer DB inspection + ~30 min bundle build / dispatch overhead.

---

## Pre-flight checklist — DO BEFORE DISPATCH

| # | Check | Command | Expected |
|---|---|---|---|
| 0.1 | On `cloud2` branch | `git rev-parse --abbrev-ref HEAD` | `cloud2` |
| 0.2 | risc0-host present at canonical path | `ls -la workspace/output/target/release/risc0-host` | file exists, executable |
| 0.3 | risc0-host SHA matches Inc 3 canonical | `sha256sum workspace/output/target/release/risc0-host` | matches `6873e588...` per `PHASE_7D_INC5_WORK.md` §25 (verify against `~/arguzz_backups/risc0-host.FIXED.sha256` if present) |
| 0.4 | Full standalone test suite green | `pytest a4/standalone/tests/ -q` | 494+ passed, 7 skipped (~16 min). DO NOT skip this — it's the structural pre-POS gate |
| 0.5 | Discover unit tests green | `pytest a4/runs/iv_pos_7/analysis/test_discover_internal.py -q` | 15/15 pass |
| 0.6 | Calendar reservation confirmed by Ivan | `pos calendar list-mine` (on coinbase) | all 8 nodes covered for ≥ 20 h ahead |
| 0.7 | Bundle directory exists | `ls -la bundles/` | exists (created by `prepare_bundle.sh`) |

**Halt rule:** If any of 0.1–0.5 fails, debug and re-run before continuing. If 0.6 fails, ping Ivan for the reservation and wait. Do not proceed without all checks green.

---

## Task list

### Task 3.1 — Build the campaign bundle (on WSL, ~10 min)

```bash
cd /root/arguzz
git status                                       # confirm cloud2 dirty state matches Batch 2 report
bash a4/pos/prepare_bundle.sh --allow-dirty       # uncommitted Batch 1/2 work overlays into the bundle
ls -la bundles/a4_campaign_*.tar.gz              # confirm bundle written
```

**Verify the bundle has the new code:**

```bash
BUNDLE=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
BUNDLE_SHA=$(sha256sum "$BUNDLE" | awk '{print $1}')
GIT_SHA=$(git rev-parse --short=12 HEAD)
echo "Bundle: $BUNDLE  SHA=$BUNDLE_SHA  git=$GIT_SHA"

# Confirm new code is inside the bundle:
tar tzf "$BUNDLE" | grep -E '(bandit_ts|fuzzer|coverage_db|cli)\.py$'
tar xzOf "$BUNDLE" "a4_campaign/repo/a4/standalone/bandit_ts.py" | grep -c "class ExponentialDecayFloor"
# expected: at least 1
tar xzOf "$BUNDLE" "a4_campaign/repo/a4/standalone/fuzzer.py" | grep -c "CTS_SEMANTIC_V2_FAMILY"
# expected: at least 1
tar xzOf "$BUNDLE" "a4_campaign/repo/a4/standalone/cli.py" | grep -c "cTS_semantic_v2_decayexp"
# expected: at least 1
```

**Halt rule:** If any of the inside-bundle greps return `0`, the bundle is broken. Re-run `prepare_bundle.sh --allow-dirty` and re-verify; if still broken, escalate.

### Task 3.2 — Hand-write the three manifest files (~10 min)

Create `a4/pos/manifests/iv_pos_8/` (if missing) and write three JSON files. Use `a4/pos/manifests/iv_pos_7/pos_iv_pos_7_smoke.json` as the schema reference.

**`a4/pos/manifests/iv_pos_8/d1a_b1.json` (Batch 3 smoke-gate, 8 jobs):**

```json
{
  "_doc": "IV.POS.8 D1.A Batch 1 (smoke-gate, 8 jobs, seeds 1234-1237 x V5-decayexp + V5-decayepoch). First of 3 sequential batches; acts as deployment smoke before Batch 4. All N=6000 paired with R2 V5-static archive at a4/runs/iv_pos_7/dbs/.",
  "name": "pos_iv_pos_8_d1a_b1",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "jobs": [
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1234, "n": 6000, "telemetry_level": "full", "node_label": "flare"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1234, "n": 6000, "telemetry_level": "full", "node_label": "octorand"},
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1235, "n": 6000, "telemetry_level": "full", "node_label": "opulous"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1235, "n": 6000, "telemetry_level": "full", "node_label": "polynize"},
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1236, "n": 6000, "telemetry_level": "full", "node_label": "algofi"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1236, "n": 6000, "telemetry_level": "full", "node_label": "gard"},
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1237, "n": 6000, "telemetry_level": "full", "node_label": "goracle"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1237, "n": 6000, "telemetry_level": "full", "node_label": "zone"}
  ]
}
```

**`a4/pos/manifests/iv_pos_8/d1a_b2.json` (Batch 4a, 8 jobs, seeds 1238–1241):** same per-position pinning, seeds 1238/1238/1239/1239/1240/1240/1241/1241.

**`a4/pos/manifests/iv_pos_8/d1a_b3.json` (Batch 4b, 4 jobs, seeds 1242–1243 on Tier-S only):**

```json
{
  "_doc": "IV.POS.8 D1.A Batch 3 (tail, 4 jobs, seeds 1242-1243 x 2 variants on 4 Tier-S nodes). Tier-A idle on tail to avoid 10% Tier-A slowdown on the final batch.",
  "name": "pos_iv_pos_8_d1a_b3",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "jobs": [
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1242, "n": 6000, "telemetry_level": "full", "node_label": "flare"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1242, "n": 6000, "telemetry_level": "full", "node_label": "octorand"},
    {"strategy": "cTS_semantic_v2_decayexp",   "seed": 1243, "n": 6000, "telemetry_level": "full", "node_label": "opulous"},
    {"strategy": "cTS_semantic_v2_decayepoch", "seed": 1243, "n": 6000, "telemetry_level": "full", "node_label": "polynize"}
  ]
}
```

Create all three manifest files now. Batches 4a/4b won't be dispatched until after Opus/Ivan green-light Batch 3 — but the manifests are committed up front so any review feedback (e.g. a different node pinning) can be applied before dispatch.

### Task 3.3 — Deploy bundle to coinbase (~2 min)

```bash
BUNDLE=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
rsync -av "$BUNDLE" coinbase:~/
ssh coinbase "ln -sf ~/$(basename $BUNDLE) ~/a4_campaign_iv_pos_8_d1a.tar.gz && ls -la ~/a4_campaign_iv_pos_8_d1a.tar.gz"
```

Also push manifests to coinbase (the dispatcher reads them from the checked-out repo on coinbase, but make sure cloud2 is current there):

```bash
ssh coinbase "cd ~/arguzz && git fetch origin && git checkout cloud2 && git pull origin cloud2 || echo 'NOTE: cloud2 not pushed yet — use rsync of manifests instead'"
```

If cloud2 isn't pushed (likely — the user hasn't asked us to commit yet), rsync the manifests:

```bash
rsync -av a4/pos/manifests/iv_pos_8/ coinbase:~/arguzz/a4/pos/manifests/iv_pos_8/
```

### Task 3.4 — Dispatch Batch 3 from coinbase (~5.5 h wall)

Open a tmux session on coinbase (so the dispatch survives SSH disconnect):

```bash
ssh coinbase
tmux new -s iv_pos_8_d1a_b1
cd ~/arguzz
source /srv/testbed/pos/cli/venv3/bin/activate

python -m a4.pos.dispatch_pos \
    --manifest a4/pos/manifests/iv_pos_8/d1a_b1.json \
    --bundle ~/a4_campaign_iv_pos_8_d1a.tar.gz \
    --nodes flare octorand opulous polynize algofi gard goracle zone \
    --allocation-duration 0 \
    --await \
    2>&1 | tee /tmp/d1a_b1_dispatch.log
```

(`--allocation-duration 0` means "use an existing calendar reservation" — see `POS_PLAYBOOK.md` §12.29 for why this is required when a reservation already exists.)

Detach from tmux (Ctrl-b d). The dispatch will run for ~5.5 h.

### Task 3.5 — Monitor (lightly, every 60–90 min)

```bash
ssh coinbase "tmux attach -t iv_pos_8_d1a_b1"      # peek
# Or check status markers:
ssh coinbase "ls -la /tmp/chainjob_*.OK /tmp/chainjob_*.FAIL* 2>/dev/null"
# Or tail the log:
ssh coinbase "tail -50 /tmp/d1a_b1_dispatch.log"
```

Expect: 8 `.OK` markers when dispatch completes. The dispatcher writes a final `dispatch_manifest.json` recording per-node start/end/result.

### Task 3.6 — Collect Batch 3 DBs (~5 min)

After all 8 jobs report `.OK`:

```bash
# On WSL:
python -m a4.pos.collect_results_pos \
    --campaign iv_pos_8_d1a_b1 \
    --out a4/runs/iv_pos_8/d1a/dbs/ \
    2>&1 | tee /tmp/d1a_b1_collect.log

ls a4/runs/iv_pos_8/d1a/dbs/
# Expected: 8 DB directories or files (one per job)
```

(If `collect_results_pos.py` doesn't accept the `--campaign` flag with this name, inspect its CLI signature; the IV.POS.7 invocation is the template — see `PHASE_8_PLAN.md` §3.9.)

### Task 3.7 — Verify pass criteria (30 min Composer)

For each of the 8 DBs, run the pass criteria from spec §4.2:

```python
import sqlite3, json
from pathlib import Path

DBS_DIR = Path("a4/runs/iv_pos_8/d1a/dbs/")
EXPECTED_CONFIGS = {
    "cTS_semantic_v2_decayexp":   ("exponential", {"K": 50.0, "initial": 0.55, "floor_min": 0.20}),
    "cTS_semantic_v2_decayepoch": ("epoch",       {"boundaries": [[0, 0.55], [2000, 0.35], [4000, 0.20]], "epoch_size": 100}),
}

for db_path in sorted(DBS_DIR.glob("**/*.db")):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    # mutations rowcount
    n_muts = cur.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]

    # campaigns metadata
    selector, ended_at = cur.execute(
        "SELECT selector, ended_at FROM campaigns ORDER BY id DESC LIMIT 1"
    ).fetchone()

    # campaign_params extra_json
    extra_json_str = cur.execute(
        "SELECT extra_json FROM campaign_params ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]
    extra = json.loads(extra_json_str)

    # new schema columns populated
    n_pg_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE proof_generated IS NOT NULL"
    ).fetchone()[0]
    n_pvf_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE proof_verify_failed IS NOT NULL"
    ).fetchone()[0]
    n_elapsed_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE elapsed_ms IS NOT NULL"
    ).fetchone()[0]

    # _local_loc_discoveries == COUNT(*) FROM coverage
    cov_count = cur.execute("SELECT COUNT(*) FROM coverage").fetchone()[0]
    # (the in-memory counter is gone after the run; we verify the floor mode actually fired instead)

    # decay-mode visibility AFTER cold-start
    n_floor_post_cs = cur.execute(
        "SELECT COUNT(*) FROM bandit_decisions WHERE mode='floor' AND mutation_num > 200"
    ).fetchone()[0]

    expected_type, expected_config = EXPECTED_CONFIGS[selector]
    ok = (
        n_muts == 6000
        and ended_at is not None
        and extra.get("floor_schedule_type") == expected_type
        and extra.get("floor_schedule_config") == expected_config
        and n_pg_nonnull == 6000
        and n_pvf_nonnull == 6000
        and n_elapsed_nonnull == 6000
        and n_floor_post_cs > 0
    )

    print(f"{'OK ' if ok else 'FAIL'}  {db_path.name}  n={n_muts}  sel={selector}  fs_type={extra.get('floor_schedule_type')}  floor_post_cs={n_floor_post_cs}  cov={cov_count}")
    if not ok:
        print("  detailed:", {
            "n_muts": n_muts,
            "ended_at": ended_at,
            "extra": extra,
            "new_cols_nonnull": (n_pg_nonnull, n_pvf_nonnull, n_elapsed_nonnull),
            "floor_post_cs": n_floor_post_cs,
        })

    conn.close()
```

Save this script as `a4/runs/iv_pos_8/d1a/validate_d1a_dbs.py` and run it. Capture full output for the Batch 3 report.

**Also verify pairing integrity (R2 V5-static seeds 1234–1237 exist):**

```bash
python3 -c "
from pathlib import Path
from a4.runs.iv_pos_7.analysis import discover
dbs = discover.discover_dbs(Path('a4/runs/iv_pos_7/dbs'))
seeds = sorted({d['seed'] for d in dbs if d['variant'] == 'V5'})
print(f'R2 V5 seeds: {seeds}')
for s in (1234, 1235, 1236, 1237):
    assert s in seeds, f'MISSING: V5 seed {s} not in R2 archive'
print('Pairing integrity OK: all 4 seeds pair to an R2 V5-static DB')
"
```

### Task 3.8 — HALT and report

After Task 3.7 completes:

- **If all 8 DBs pass:** halt. Write the structured Batch 3 report (template below) and ping Opus + Ivan. Do NOT auto-dispatch Batch 4. Wait for greenlight.
- **If any DB fails:** halt immediately. Write a partial report documenting which DBs passed, which failed, and the failure details. Ping Opus + Ivan for triage. Do NOT re-dispatch without instruction.

---

## Required Batch 3 report format

Write this as a single message back to Opus. Follow the Batch 1 / Batch 2 (status-report) structure:

```
## D1.A Batch 3 — Composer Report

### Pre-flight
- Branch: cloud2 (commit <git-sha>)
- risc0-host SHA: <sha>
- pytest a4/standalone/tests/: <pass/fail counts>
- pytest discover: <pass/fail counts>
- Calendar reservation: <node list> for <duration> (covers Batch 3 + 4)
- Bundle: bundles/a4_campaign_<short>.tar.gz  SHA=<bundle-sha>
- Bundle in-content check (new code grep):
  - bandit_ts.py: ExponentialDecayFloor present (<count> matches)
  - fuzzer.py:   CTS_SEMANTIC_V2_FAMILY present (<count> matches)
  - cli.py:      cTS_semantic_v2_decayexp present (<count> matches)

### Dispatch
- Manifest: a4/pos/manifests/iv_pos_8/d1a_b1.json
- Dispatch command: <full command>
- Start: <UTC timestamp>  End: <UTC timestamp>  Wall: <hours>:<minutes>
- Per-node exit: <node:rc table>

### Per-DB pass/fail matrix
| DB | n_muts | selector | floor_schedule_type | floor_post_cs | New-cols filled | Status |
|---|---:|---|---|---:|---|---|
| <db1> | 6000 | cTS_semantic_v2_decayexp | exponential | <count> | 6000/6000/6000 | OK |
| ... (8 rows) ... |

### Decay behavior spot-check (≥ 1 seed paired triple)
- Seed 1234:
  - V5-static (R2): floor mode share over mut #200-6000 = X% (computed from a4/runs/iv_pos_7/dbs/.../seed_1234.db)
  - V5-decayexp:    floor mode share over mut #200-6000 = Y% (expected lower as exp(-d/50) decays)
  - V5-decayepoch:  floor mode share over mut #200-6000 = Z% (expected to drop visibly at mut 2000 and 4000)
- Brief comment: <"decay schedules visibly engaged" / "anomaly: ..." />

### Pairing integrity
- R2 V5-static DBs present for seeds 1234, 1235, 1236, 1237: YES/NO (list any missing)

### Anomalies / surprises
- <none, or describe>

### Status
- Batch 3: PASS / FAIL (with reasons)
- Awaiting Opus + Ivan greenlight to dispatch Batch 4a (a4/pos/manifests/iv_pos_8/d1a_b2.json)
```

---

## Out-of-scope for this batch (so Composer doesn't drift)

- Analysis CSVs / plots (Batch 5)
- D1A_SUBSECTION.md content (Batch 5)
- Modifying `discover.py` further (already done in Batch 2)
- Touching V1–V4 baselines (V3/V4 deprioritized; V1 is V1)
- Local re-smoke attempts (decided 2026-06-16: WSL too slow)

## Notes on the abandoned partial DB

`a4/runs/iv_pos_8/d1a_batch3_smoke/batch3_cTS_semantic_v2_seed9999_n200.db` (Composer's 22-mut partial from the abandoned local smoke) is **gitignored** (covered by the global `*.db` rule). Safe to delete or leave; do not include in any analysis pipeline.

## References

- Spec: `a4/docs/cloud2/IV_POS_8_D1_A_SPEC.md` §2 (Batch 3) and §4.2 (pass criteria), §5.1 (compute), §5.2 (manifests)
- IV.POS.7 dispatch reference: `a4/docs/cloud1/composer/PHASE_8_PLAN.md` §3 (batched-parallel)
- POS dispatch playbook: `a4/docs/precloud/POS_PLAYBOOK.md` (especially §12.28 calendar quota, §12.29 allocation-duration=0)
- Schema reference: `a4/pos/manifests/iv_pos_7/pos_iv_pos_7_smoke.json`
- Bundle build: `a4/pos/prepare_bundle.sh`
- Dispatcher: `a4/pos/dispatch_pos.py`
- Collector: `a4/pos/collect_results_pos.py`
