# Phase III.3 — Per-run reward-component persistence — Implementation Plan

**Status:** PLAN  
**Created:** Jun 3, 2026 (evening session after III.2.5 resolution)  
**Depends on:** Phase III.0 (reward function rewritten — DONE), Phase III.1 (DB schema for global contexts — DONE)  
**Blocks:** Phase IV.2 (boss notebook reads cumulative metrics from SQLite, not from parsed terminal text)

## 1 — Goal

Today the reward diagnostics
($T_{\text{new}}, T_{\text{rare}}, F_{\text{new}}, F_{\text{rare}}, U,
Q_{\text{loc}}, Q_{\text{rep}}, Q_{\text{glob}}, Q, S, r, d_{\text{loc}},
d_{\text{glob}}, d_{\text{ext}}$, plus raw counters
$\Delta_T, \Delta_F, n_{\text{fail}}, r_{\text{rep}}$) live only in:

1. **Terminal stdout/stderr** (parsed by [`analyze_campaign.py:68-79`](a4/standalone/tests/analyze_campaign.py)), and
2. **In-memory `MutationResult.reward_diag` dict** which is discarded at process end.

For the cloud pipeline (Phase IV.2), we must read these per-run scalars from
SQLite. Parsing R × |strategies| × $\sim$20k = $\geq$300k terminal logs at
aggregation time is brittle (any change to the print format breaks
historical analysis) and slow.

This phase adds a `mutation_rewards` sidecar table written in lockstep with
the existing `record_mutation` call, populated from the same `diag` dict
that today reaches `_print_mutation_result`.

## 2 — What this phase is NOT

- **NOT** a refactor of `compute_reward`. The function signature, return
  type, and semantics are unchanged.
- **NOT** a change to the terminal print line. It stays exactly as today so
  existing legacy log files remain parseable by `analyze_campaign.py`.
- **NOT** a change to `update_state` or any bandit/state behaviour.
- **NOT** a backfill of old DBs. Pre-III.3 DBs will have an empty
  `mutation_rewards` table; queries must `LEFT JOIN` to handle this
  cleanly. (Master-plan validation campaigns ran post-III.3 will populate
  everything.)

## 3 — Source-of-truth map (what touches what)

| File | Current state (Jun 3) | Touch in III.3 |
|---|---|---|
| [`a4/standalone/coverage_db.py`](a4/standalone/coverage_db.py) | Has `mutations`, `failures`, `coverage`, `global_failures` tables. `record_mutation` returns `mutation_id`. Pattern for additive schema and bulk-inserts already established by `record_global_failures`. | NEW: `mutation_rewards` table in `_init_schema`. NEW method `record_reward_diag(mutation_id, diag)`. NEW query method `get_reward_diag_for_campaign(campaign_id)`. |
| [`a4/standalone/fuzzer.py`](a4/standalone/fuzzer.py) | `_run_bandit_mutation` (~lines 463-575) and `_run_single_mutation` (~lines 655-829) both call `compute_reward` and stash the result on `result.reward_diag`. Then `_print_mutation_result` reads it. | Add one call to `self.db.record_reward_diag(mutation_id, result.reward_diag)` immediately after `record_global_failures` in both call sites. |
| [`a4/standalone/coverage_state.py`](a4/standalone/coverage_state.py) | `compute_reward` returns `(reward, diag)` with all fields listed above. | **No change.** |
| [`a4/standalone/tests/analyze_campaign.py`](a4/standalone/tests/analyze_campaign.py) | Terminal-parsing only. | OPTIONAL: add a small helper `load_runs_from_db(db_path, campaign_id)` that returns the same `RunRecord` list reconstructed from SQL. Used by future cloud aggregation; not on the critical path for III.3 acceptance. |
| [`a4/standalone/tests/test_coverage_db_global.py`](a4/standalone/tests/test_coverage_db_global.py) (or NEW `test_coverage_db_rewards.py`) | Existing pattern for testing the additive `global_failures` table. | NEW tests in `test_coverage_db_rewards.py`. |

## 4 — Schema design (final)

```sql
CREATE TABLE IF NOT EXISTS mutation_rewards (
    mutation_id INTEGER PRIMARY KEY,
    reward     REAL NOT NULL,
    T_new      REAL NOT NULL,
    T_rare     REAL NOT NULL,
    F_new      REAL NOT NULL,
    F_rare     REAL NOT NULL,
    U          INTEGER NOT NULL,
    Q_loc      REAL NOT NULL,
    Q_rep      REAL NOT NULL,
    Q_glob     REAL NOT NULL,
    Q          REAL NOT NULL,
    S          REAL NOT NULL,
    delta_T    INTEGER NOT NULL,
    delta_F    INTEGER NOT NULL,
    n_fail     INTEGER NOT NULL,
    r_rep      INTEGER NOT NULL,
    d_loc      INTEGER NOT NULL,
    d_glob     INTEGER NOT NULL,
    d_ext      INTEGER NOT NULL,
    mode       TEXT NOT NULL,
    FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_mr_mut ON mutation_rewards(mutation_id);
```

### 4.1 Design choices justified

1. **Sidecar table, not new columns on `mutations`.** Keeps the schema
   layered (`mutations` = "what was tried"; `mutation_rewards` =
   "what came out of the reward function"). Matches the existing
   `failures` and `global_failures` pattern. Allows downstream consumers
   (e.g. dashboard SQL) to query reward-free properties of mutations
   without paying for the JOIN. Critically, it also means an empty
   `mutation_rewards` row set is a legitimate state — pre-III.3 DBs,
   crash-only runs (which never call compute_reward), and any
   `--selector` that doesn't enable coverage tracking can all coexist
   in the same schema.

2. **`mutation_id` is `PRIMARY KEY`, not `id`.** A mutation has exactly
   zero or one reward row. Promoting `mutation_id` to PK eliminates the
   need for a synthetic `id` column and makes "look up reward for this
   mutation" a single index hit.

3. **`mode TEXT NOT NULL`.** The `mode` field in the diag distinguishes
   `"crash"` (early-return in compute_reward) from `"normal"` and
   `"accepted"`. We persist it instead of trying to reconstruct it from
   `n_fail==0 AND r==0` style heuristics.

4. **No new field for `outcome`.** That's already inferable from
   `mutations.verifier_accepted`, `mutations.num_failures > 0`, and
   crash signals on exit code — and the `mutations` table is the
   authoritative place for outcome classification.

5. **No `tau_*`/`a_*` parameters in the row.** Calibrated params apply
   campaign-wide and live in the `campaigns` table (TODO if not already
   there — covered by future III.6 work, not III.3).

6. **All-`NOT NULL`** because `compute_reward` always returns values for
   every field (no `Optional`). The one case that doesn't is the
   crash-early-return: it returns a fully populated dict too (defaults
   to 0/0.0). So `NOT NULL` is honest.

## 5 — Code change inventory

### 5.1 `coverage_db.py`

Add after `record_global_failures`:

```python
def record_reward_diag(
    self,
    mutation_id: int,
    diag: dict,
) -> None:
    """
    Persist the reward-diagnostic dict produced by compute_reward.

    Phase III.3: this is the SQLite-authoritative store for per-run
    reward components. Called from fuzzer._run_bandit_mutation and
    fuzzer._run_single_mutation IFF coverage tracking is enabled and
    compute_reward was invoked.

    Args:
        mutation_id: parent mutation id (foreign key into `mutations`)
        diag: the diag dict returned by compute_reward. Must contain
              all fields listed in the Phase III.3 schema; missing
              fields raise KeyError to fail loudly.
    """
    cursor = self.conn.cursor()
    cursor.execute(
        """
        INSERT OR REPLACE INTO mutation_rewards
        (mutation_id, reward, T_new, T_rare, F_new, F_rare, U,
         Q_loc, Q_rep, Q_glob, Q, S,
         delta_T, delta_F, n_fail, r_rep,
         d_loc, d_glob, d_ext, mode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            mutation_id,
            float(diag["r"]),
            float(diag["T_new"]),
            float(diag["T_rare"]),
            float(diag["F_new"]),
            float(diag["F_rare"]),
            int(diag["U"]),
            float(diag["Q_loc"]),
            float(diag["Q_rep"]),
            float(diag["Q_glob"]),
            float(diag["Q"]),
            float(diag["S"]),
            int(diag["delta_T"]),
            int(diag["delta_F"]),
            int(diag["n_fail"]),
            int(diag["r_rep"]),
            int(diag["d_loc"]),
            int(diag["d_glob"]),
            int(diag["d_ext"]),
            str(diag["mode"]),
        ),
    )
    self.conn.commit()


def get_reward_diag_for_campaign(
    self,
    campaign_id: int,
) -> List[dict]:
    """
    Return all reward rows for mutations in this campaign, in mutation_id
    order (= insertion order = chronological).

    Each row is a dict with the schema columns plus 'mutation_id'.
    Mutations without a reward row (e.g. crash-only campaigns, or
    pre-III.3 DBs being re-read) are absent from the result.
    """
    cursor = self.conn.cursor()
    cursor.execute(
        """
        SELECT mr.*
        FROM mutation_rewards mr
        JOIN mutations m ON mr.mutation_id = m.id
        WHERE m.campaign_id = ?
        ORDER BY mr.mutation_id
        """,
        (campaign_id,),
    )
    return [dict(row) for row in cursor.fetchall()]
```

`INSERT OR REPLACE` is used so a re-run on the same mutation_id (defensive)
overwrites instead of erroring on PK conflict.

In `_init_schema` (after the existing `global_failures` block at line 159):

```python
# Phase III.3: per-run reward-component persistence.
# One row per mutation that had compute_reward called for it. Mutations
# whose campaign had no coverage tracking (`--selector zoned/guided` in
# legacy mode without tracking) will simply have zero rows here.
cursor.execute("""
    CREATE TABLE IF NOT EXISTS mutation_rewards (
        mutation_id INTEGER PRIMARY KEY,
        reward     REAL NOT NULL,
        T_new      REAL NOT NULL,
        T_rare     REAL NOT NULL,
        F_new      REAL NOT NULL,
        F_rare     REAL NOT NULL,
        U          INTEGER NOT NULL,
        Q_loc      REAL NOT NULL,
        Q_rep      REAL NOT NULL,
        Q_glob     REAL NOT NULL,
        Q          REAL NOT NULL,
        S          REAL NOT NULL,
        delta_T    INTEGER NOT NULL,
        delta_F    INTEGER NOT NULL,
        n_fail     INTEGER NOT NULL,
        r_rep      INTEGER NOT NULL,
        d_loc      INTEGER NOT NULL,
        d_glob     INTEGER NOT NULL,
        d_ext      INTEGER NOT NULL,
        mode       TEXT NOT NULL,
        FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
    )
""")
cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_mr_mut
    ON mutation_rewards(mutation_id)
""")
```

### 5.2 `fuzzer.py`

Find the call sites where `result.reward_diag` is set. Add immediately
after, **only inside the `if self.coverage_state is not None` block**:

**Call site 1 — `_run_bandit_mutation`** (after the existing
`compute_reward`/`update_state` block ~line 540-555):

```python
# Phase III.3: persist reward components to SQLite for cloud aggregation.
self.db.record_reward_diag(mutation_id, diag)
```

**Call site 2 — `_run_single_mutation`** (after the existing
`compute_reward`/`update_state` block ~line 811-823):

```python
# Phase III.3: persist reward components to SQLite for cloud aggregation.
self.db.record_reward_diag(mutation_id, diag)
```

Critically, the call must use the `diag` local variable returned by
`compute_reward`, not `result.reward_diag` — both refer to the same dict,
but the local is on the hot path and avoids one attribute access.

### 5.3 `analyze_campaign.py` (OPTIONAL for this phase)

Skipped. The terminal-parsing path stays as-is. A future
`a4/cloud/aggregate.py` (Phase IV.2) will use
`CoverageDB.get_reward_diag_for_campaign` directly via SQL — there is no
reason to pretend the terminal is the source of truth in the SQL-backed
flow.

## 6 — Tests (NEW: `test_coverage_db_rewards.py`)

Five focused unit tests, plus one smoke that exercises the full
fuzzer→DB write path.

1. **`test_schema_created`** — instantiate `CoverageDB`, confirm
   `mutation_rewards` table exists and has the 20 expected columns and
   one index.
2. **`test_record_reward_diag_minimal`** — call `record_mutation`
   followed by `record_reward_diag` with a synthetic diag dict whose
   numeric fields cover the type boundaries (0, 1.0, negative-not-allowed,
   string `mode`). Read back via `get_reward_diag_for_campaign` and
   assert round-trip equality (float comparison via `pytest.approx`).
3. **`test_record_reward_diag_crash_mode`** — pass the crash-early-return
   diag from `compute_reward` (mode="crash", all zeros). Assert it
   persists correctly and `mode == "crash"`.
4. **`test_record_reward_diag_overwrite`** — calling
   `record_reward_diag` twice on the same `mutation_id` (defensive
   `INSERT OR REPLACE`) keeps the second value, not errors.
5. **`test_missing_diag_field_raises`** — passing a diag missing one of
   the required fields (e.g. drop `"Q_glob"`) raises `KeyError`.
6. **`test_full_compute_reward_roundtrip`** — call `compute_reward`
   with a synthetic state + bitmap, take the returned diag, persist
   it via `record_reward_diag`, read back, assert all 19 fields match.
   This anchors the contract between `compute_reward`'s output and the
   schema (so a future addition to the diag dict that ISN'T mirrored to
   the schema will fail this test).

## 7 — Smoke test (manual, after unit tests pass)

```bash
rm -f /tmp/iii3_smoke.db
python3 -m a4.standalone.cli fuzz \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --selector zoned --kind INSTR_TYPE_MOD --num 5 --seed 42 \
  --db /tmp/iii3_smoke.db -- --in1 5 --in4 10 \
  > /tmp/iii3_smoke.log 2>&1
echo "Reward rows persisted:"
sqlite3 /tmp/iii3_smoke.db \
  "SELECT mr.mutation_id, mr.reward, mr.T_new, mr.F_new, mr.d_loc, mr.d_glob, mr.mode \
   FROM mutation_rewards mr ORDER BY mr.mutation_id"
```

Expected: 5 rows, each with `reward >= 0`, `T_new` in [0,1], `d_loc >= 0`,
`d_glob >= 0`, `mode in ("normal", "accepted", "crash")`. Rewards in the
file should equal the rewards printed in the terminal output (within
float tolerance).

## 8 — Acceptance criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | New `mutation_rewards` table exists with 20 columns and 1 index | `sqlite3 :memory: ".schema mutation_rewards"` after running `CoverageDB.__init__` |
| 2 | All 6 unit tests pass | `pytest a4/standalone/tests/test_coverage_db_rewards.py -v` |
| 3 | Existing test suite still passes (no regression) | `pytest a4/standalone/tests/ -x` |
| 4 | Smoke campaign of 5 mutations produces 5 reward rows | shell smoke above |
| 5 | Persisted `reward` values match the corresponding terminal `r=...` printout within `1e-6` | manual eyeball on the smoke output (or programmatic via `analyze_campaign.parse_terminal` and the new `get_reward_diag_for_campaign` helper, but this is optional) |
| 6 | Older campaign DBs (without `mutation_rewards`) can still be opened by `CoverageDB.__init__` without error and existing queries (e.g. `record_failures`, `get_global_contexts_for_campaign`) still work | open `a4_coverage.db` from the repo root after running `_init_schema` once; `pytest a4/standalone/tests/test_coverage_db_global.py -v` still passes |

## 9 — Risk + rollback

**Risk: LOW.** Pure additive schema migration; no existing tables modified;
no existing code paths changed. Worst case is the new table sits empty
(e.g. if `coverage_state is None`) which causes no error.

**Rollback:** drop the `mutation_rewards` table (`DROP TABLE
mutation_rewards;`) and remove the two `record_reward_diag` calls from
`fuzzer.py`. No data loss in any other table.

## 10 — Estimated effort

- Coverage_db.py edits: 30 min
- Fuzzer.py edits: 10 min  
- 6 unit tests: 45 min
- Smoke + acceptance check: 15 min
- Implementation report: 20 min

**Total: ~2 hours.**

## 11 — In simple terms (for anyone new)

The bandit assigns each mutation a numeric reward $r \in [0, 1]$ that it
uses to bias future mutation selection. That reward is the result of a
formula with about a dozen inputs (how many new touch buckets the
mutation hit, how many constraint failures were unique, etc.). Until now
those inputs were only printed in the terminal and discarded when the
process ended. The cloud aggregation pipeline reads SQLite, not terminal
logs, so without this phase we'd be doing fragile regex parsing of
thousands of log files in cloud post-processing. III.3 just stores those
inputs in a SQLite table next to the `mutations` table. No bandit
behaviour changes; nothing about how rewards are computed changes; the
new data simply lives in a new table for later analysis.
