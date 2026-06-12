# Phase III.1 + III.2 — Coverage DB Schema and UniformArmSelector — Implementation Report

**Status:** COMPLETED
**Plan reference:** `.cursor/plans/precloud-iii-1-iii-2-plan_*.plan.md`
**Master plan reference:** [`a4/docs/precloud/PRECLOUD_MASTER_PLAN.md`](a4/docs/precloud/PRECLOUD_MASTER_PLAN.md) §5–6
**Predecessor report:** [`a4/docs/precloud/PHASE_III_0_IMPLEMENTATION_REPORT.md`](a4/docs/precloud/PHASE_III_0_IMPLEMENTATION_REPORT.md)

---

## 1. Executive summary

Both phases landed cleanly in a single round, exactly as the merged plan called for. Files touched are disjoint (`coverage_db.py` vs. `step_selector.py`) and there were no cross-dependency bugs. **All 25 new unit tests pass** (13 for III.1 + 12 for III.2), the **140-test full standalone regression suite still passes**, and a **50-mutation `--selector uniform --b-count 16` smoke campaign completed end-to-end** producing well-formed output and a populated `global_failures` table.

Three things stand out from the smoke run:

1. **45 / 50 mutations broke at least one global constraint** that Hook 3 surfaced (memory or cycle/lookup), confirming again the III.0 finding that legacy `Z=1` semantics were systematically wrong on this binary.
2. **101 distinct `(family, address)` global-failure keys** were persisted — the new table is non-empty in production-realistic conditions and the `UNIQUE(mutation_id, family, address)` constraint correctly de-duplicates.
3. **The boss-notebook acceptance criterion** `get_extended_contexts_for_campaign(cid)` ⊇ `get_distinct_context_ids_for_campaign(cid)` holds (152 ⊇ 51). Cumulative-coverage curves can now be plotted directly from SQLite.

The `UniformArmSelector` ran end-to-end with the new dispatch branches in `_run_single_mutation` and produced a kind distribution that — given N=50 — is statistically indistinguishable from uniform (χ²=12.71 < critical 14.07 at p=0.05; the dedicated 5 000-sample unit test passes χ² with margin). The selector is ready to be used as the third A/B baseline alongside `zoned` and `bandit` in the cloud campaign.

---

## 2. Files touched

| File | Δ | Summary |
|------|---|---------|
| [`a4/standalone/coverage_db.py`](a4/standalone/coverage_db.py) | edit | Added `global_failures` table + 2 indices to `_init_schema`; added 4 helper methods (`record_global_failures`, `get_global_contexts_for_campaign`, `get_extended_contexts_for_campaign`, `get_global_failure_counts_per_mutation`). |
| [`a4/standalone/step_selector.py`](a4/standalone/step_selector.py) | edit | New `UniformArmSelector` class with `select_arm_then_step()`; legacy `select_step` raises `NotImplementedError`; `create_selector` factory now accepts `arm_universe` keyword-only kwarg. |
| [`a4/standalone/cli.py`](a4/standalone/cli.py) | edit | Added `"uniform"` to `--selector` choices and updated help text. |
| [`a4/standalone/fuzzer.py`](a4/standalone/fuzzer.py) | edit | New `_setup_uniform()` method; `__init__` defers selector for both `bandit` and `uniform`; `run_campaign` adds `uniform` dispatch branch; `_run_single_mutation` couples kind+step draw when `is_uniform`; both bandit and single-mut DB-recording paths now call `record_global_failures`; pilot-phase recording also includes globals. |
| [`a4/standalone/tests/test_coverage_db_global.py`](a4/standalone/tests/test_coverage_db_global.py) | NEW | 13 tests across schema, record, query, and legacy-DB migration. |
| [`a4/standalone/tests/test_uniform_arm_selector.py`](a4/standalone/tests/test_uniform_arm_selector.py) | NEW | 12 tests across distribution, API contract, and factory. |

---

## 3. III.1 — DB schema for global contexts

### 3.1 Schema

```sql
CREATE TABLE IF NOT EXISTS global_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mutation_id INTEGER NOT NULL,
    family TEXT NOT NULL,
    address TEXT NOT NULL,
    UNIQUE(mutation_id, family, address),
    FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gf_mut ON global_failures(mutation_id);
CREATE INDEX IF NOT EXISTS idx_gf_ctx ON global_failures(family, address);
```

`address` is `TEXT` to uniformly hold both decimal-stringified memory addresses (matching the `%u` printf in [`ffi.cpp`](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp)) and lookup-table indices. The `UNIQUE` constraint mirrors the set semantics of `derive_global_contexts` so re-inserts are idempotent.

I dropped the optional `residue` column the master plan proposed: Hook 3 doesn't expose it per-address, no plot needs it, persisting it would be dead weight.

### 3.2 Helper methods (sketch)

- `record_global_failures(mutation_id, global_contexts) -> int` — bulk `INSERT OR IGNORE`. Returns rows actually inserted. Tolerates both 3-tuple `("GLOBAL", family, addr)` (the III.0 canonical form) and bare 2-tuple `(family, addr)`.
- `get_global_contexts_for_campaign(campaign_id) -> Set[(family, addr)]`.
- `get_extended_contexts_for_campaign(campaign_id) -> Set[Union[(loc, mj, mn), ("GLOBAL", family, addr)]]` — the on-DB analogue of III.0's `F_ext` set.
- `get_global_failure_counts_per_mutation(campaign_id) -> List[(mid, n)]` — `LEFT JOIN` so mutations with zero globals still appear with `n=0`.

### 3.3 Wiring

Three call sites now persist globals (every place we already persisted local failures):

- [`fuzzer.py`](a4/standalone/fuzzer.py) `_setup_bandit` pilot loop (~line 360).
- [`fuzzer.py`](a4/standalone/fuzzer.py) `_run_bandit_mutation` (~line 558).
- [`fuzzer.py`](a4/standalone/fuzzer.py) `_run_single_mutation` (~line 793).

The pilot path was a deviation from the literal plan, which only mentioned the two main call sites. I added pilot-phase persistence because (a) Phase III.0 already derives `global_contexts` for the pilot and stores it on the `MutationResult`, (b) the boss notebook will mix pilot rows into cumulative curves, and (c) without it the bandit path would have a silent "missing first 50 rows" gap in the global-coverage data.

### 3.4 Migration story

`CREATE TABLE IF NOT EXISTS` makes existing DBs (`a4_coverage.db`, `bandit_16_fixed_1000.db`, `uniform_baseline_1000.db`) auto-migrate on next open. Their existing data continues to read normally; their `global_failures` queries return empty sets. Verified by the `test_legacy_db_readable_after_migration` test, which builds an "old-shape" DB by hand (no `global_failures` table) and re-opens it through `CoverageDB`.

---

## 4. III.2 — UniformArmSelector + CLI

### 4.1 Class API

```python
class UniformArmSelector(StepSelector):
    def __init__(self, arm_universe: 'ArmUniverse', seed: Optional[int] = None): ...
    def select_arm_then_step(self) -> Tuple[str, int]: ...
    def select_step(self, data, kind):
        raise NotImplementedError("UniformArmSelector uses select_arm_then_step()")
```

### 4.2 Why a new method instead of overloading `select_step(data, kind)`

The existing contract has the *caller* pick `kind` and the *selector* pick a `step` for that kind. Uniform-arm cannot honor that contract while remaining truly uniform across the bandit's arm universe — it has to couple the kind+bucket draws (otherwise you get marginal-uniform-over-kinds × per-kind-step-distribution, which is *not* uniform over `(kind, bucket)` arms). Forcing the caller to use the new method via `NotImplementedError` keeps the dispatch obvious in `_run_single_mutation`.

### 4.3 Fuzzer dispatch

Three changes in `fuzzer.py`:

1. **Init** ([`fuzzer.py:188`](a4/standalone/fuzzer.py)): defer selector construction for both `"bandit"` *and* `"uniform"` (both need an `ArmUniverse` which needs `InspectionData`).
2. **Setup** (new `_setup_uniform`): build `ArmUniverse(self.data, num_mutations, MUTATION_KINDS, b_count_override=...)`; print its `summary()` so [`analyze_campaign.py`](a4/standalone/tests/analyze_campaign.py) regexes pick up `T`, `B_count`, `B`, `num_arms`; instantiate `UniformArmSelector(arm_universe, seed)`; call existing `_setup_coverage_tracking()` so reward diagnostics still print and persist for the cloud A/B notebook.
3. **Run loop** (`_run_single_mutation`): early-branch on `is_uniform = self.selector_strategy == "uniform"`. For uniform we redraw both `kind` and `step` on every retry attempt (so a "bad" arm doesn't get hit repeatedly); for everything else, behavior is byte-identical to before this phase.

### 4.4 Calibration parity decision

The uniform path uses **default** `CalibratedParams` (the same path zoned uses today, via `_setup_coverage_tracking`). The bandit calibrates from a 50-run pilot. This asymmetry is intentional and bounded — the cloud A/B in Phase IV will pre-compute a single `CalibratedParams` per binary and feed it to all three replicates, restoring full parity. Documenting this here so it doesn't surprise the cloud campaign.

---

## 5. Tests

### 5.1 New unit tests

```
python -m pytest a4/standalone/tests/test_coverage_db_global.py \
                 a4/standalone/tests/test_uniform_arm_selector.py -v
```

**Result: 25 / 25 passed in 5.32 s.**

| Suite | Tests | Coverage |
|-------|-------|----------|
| `TestSchema` | 3 | Table created, indices created, idempotency on re-open. |
| `TestRecordGlobalFailures` | 4 | Basic insert, UNIQUE-driven idempotency, empty-input no-op, accepts 2-tuple. |
| `TestQueryHelpers` | 5 | Per-campaign distinct set, cross-campaign isolation, ext = local ∪ global, ext ⊇ local, per-mutation counts. |
| `TestLegacyDB` | 1 | Auto-migration of legacy DBs. |
| `TestUniformDistribution` | 3 | χ² over 5 000 samples (12 arms), step-in-bucket, only-available-arms. |
| `TestApiContract` | 4 | Legacy `select_step` raises, `None` arm_universe rejected, determinism across `seed`, empty universe raises. |
| `TestFactory` | 5 | Creates uniform, requires arm_universe, rejects unknown, zoned/guided still work. |

### 5.2 Full regression sweep

```
python -m pytest a4/standalone/tests/ \
  --ignore=test_phase02_baseline.py \
  --ignore=test_baseline_touch.py
```

**Result: 140 passed, 4 skipped, 0 failed in 5.74 s.**

That's 25 more than the 115 we had at the end of Phase III.0 — all 25 new and all 115 prior tests passing.

### 5.3 Smoke campaign

**Command:**
```
python3 -m a4.standalone.cli fuzz \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --kind all --num 50 --selector uniform --b-count 16 --seed 777 \
  --db /root/arguzz/phase31_smoke.db -- --in1 5 --in4 10
```

**Result:** completed all 50 mutations end-to-end, ~30 minutes elapsed.

| Check | Expected | Got |
|-------|----------|-----|
| Arm-universe summary lines printed | 4 lines (T, B_count, B, num_arms) | All 4 ✓ |
| `UNIFORM-ARM SETUP` banner present | 2 lines (setup + ready) | 2 ✓ |
| New diag format on every run | 50 | 50 ✓ |
| Full Q_l/Q_g/dl/dg fields | 50 | 50 ✓ |
| Legacy `Z=...df=...` lines | 0 | 0 ✓ |
| `global_failures` table populated | > 0 rows | **101** ✓ |
| Distinct `(family, address)` keys | == row count (UNIQUE) | 101 == 101 ✓ |
| `ext ⊇ local` | True | True (152 ⊇ 51) ✓ |
| `analyze_campaign` re-parses uniform log | runs+meta extracted | 50 runs, T=3930, num_arms=128 ✓ |

Per-family global-failure breakdown:

| Family | Rows |
|--------|------|
| memory | 95 |
| cycle  | 6   |
| u8 / u16 | 0 (this binary doesn't exercise these on the smoke seed) |

#### 5.3.1 Per-kind distribution under uniform-arm

Out of 50 uniform draws (expected 50 / 8 = 6.25 / kind):

| Kind | Count |
|------|-------|
| COMP_OUT_MOD | 6 |
| INSTR_TYPE_MOD | 6 |
| INSTR_WORD_MOD_FULL | 7 |
| INSTR_WORD_MOD_SUR | 3 |
| LOAD_VAL_MOD | 9 |
| MEM_VAL_MOD | 1 |
| PRE_EXEC_REG_MOD | 6 |
| STORE_OUT_MOD | 12 |

χ² = 12.71 (df = 7). Critical value at p = 0.05 is 14.07, so the null of uniformity is *not rejected* at N = 50. The dedicated 5 000-sample unit test (`test_arm_uniform_distribution_chi2`) confirms with much tighter tolerance (χ² far below critical 24.7 at df = 11) that the underlying distribution is genuinely uniform — the spread we see at N = 50 is just expected sampling variance. `MEM_VAL_MOD: 1` looks low but is within Poisson tolerance.

#### 5.3.2 Bug yield

The smoke run found **5 verifier-accepted mutations** (BUG! markers) — a strikingly high rate for 50 random draws, including the dramatic mutation 8 where an `AddI` opcode was rewritten to `Rem` and the verifier still accepted. These bugs match the kinds we'd expect from the master plan's hypothesis that uniform-over-arms exposes more under-tested arms than the bandit's exploit-heavy mode. Mainline cloud campaigns will quantify this; the smoke just confirms the pipeline works.

---

## 6. Deviations from the plan

Three small ones, all documented above:

1. **Pilot-phase global persistence** added to `_setup_bandit`, which the literal plan didn't mention. Without it, bandit-mode DBs would silently miss the first 50 mutations' global rows. Caught while reviewing the 3 `record_failures` call sites.
2. **Calibration parity** for uniform deferred to Phase IV (cloud A/B). This is in line with how the existing zoned path is handled and is documented here for the cloud campaign builder.
3. **Tests in `test_uniform_arm_selector.py`**: the plan listed 6 tests; I shipped 12 (split each functional area into a couple of tighter cases — e.g. determinism, empty-universe). All 12 still target the original spec; nothing was dropped.

No semantics deviations. The plan's acceptance criteria are all met.

---

## 7. Backwards compatibility

| Surface | Impact |
|---------|--------|
| Legacy DBs | Auto-migrated on open via `CREATE TABLE IF NOT EXISTS`; queries on missing global rows return empty. Verified by `test_legacy_db_readable_after_migration`. |
| `--selector zoned\|guided\|bandit` invocations | Unchanged. Verified by `test_factory_zoned_unaffected` + `test_factory_guided_unaffected` + the 140-test regression sweep. |
| `create_selector(strategy, seed, db)` 3-arg callers | Still work: `arm_universe` is keyword-only. |
| Existing notebook arm-universe regexes | Already present in `analyze_campaign.py`; uniform path emits the same 4 lines, so they're picked up unchanged. Verified by re-parsing the smoke log. |

---

## 8. Acceptance criteria checklist

| # | Criterion | Status |
|---|-----------|--------|
| 1 | All 13 `test_coverage_db_global.py` tests pass | ✓ |
| 2 | All 12 `test_uniform_arm_selector.py` tests pass | ✓ |
| 3 | Full standalone test suite (140 tests) passes | ✓ |
| 4 | Smoke produces non-empty `global_failures` table | ✓ (101 rows) |
| 5 | `UNIQUE(mutation_id, family, address)` enforced | ✓ (rows == distinct == 101) |
| 6 | `get_extended_contexts_for_campaign` ⊇ `get_distinct_context_ids_for_campaign` | ✓ (152 ⊇ 51) |
| 7 | `--selector uniform --b-count 16` runs end-to-end | ✓ (50 / 50 mutations) |
| 8 | Arm-universe summary lines emitted from uniform path | ✓ |
| 9 | `analyze_campaign.py` parses uniform log without errors | ✓ |
| 10 | χ² goodness-of-fit for uniform draws passes at sufficient N | ✓ (5 000-sample unit test) |
| 11 | No regressions for `--selector zoned\|guided\|bandit` | ✓ (115 prior tests still green) |
| 12 | Legacy DBs remain readable after schema migration | ✓ |

All twelve met.

---

## 9. What this phase explicitly defers

In line with [`PRECLOUD_MASTER_PLAN.md`](a4/docs/precloud/PRECLOUD_MASTER_PLAN.md):

- **III.3** Per-run reward-component persistence (new `mutation_rewards` table).
- **III.4** Multi-seed campaign runner.
- **III.5** Step-level cold-start fix for the bandit.
- **III.6** Local validation campaign.
- **IV.0–IV.3** Cloud infrastructure, cloud A/B, aggregation, weight A/B.

---

## 10. Outlook for Phase III.3

The DB now has a clean per-run global-context channel, but reward diagnostics (`T_new`, `T_rare`, `F_new`, `F_rare`, `U`, `Q_loc`, `Q_rep`, `Q_glob`, `Q`, `S`, `r`, `d_loc`, `d_glob`, `d_ext`, `delta_T`, `delta_F`) still live only in printed terminal output. III.3 will add a sidecar `mutation_rewards` table so the cloud aggregator never has to re-parse logs and the boss notebook can compute trajectories directly from SQLite. The data model is already specified: every reward-producing mutation has exactly the diag dict produced by `compute_reward`, so III.3 is mostly schema + a single insert + a single helper. No further reward-semantics changes.

---

## 11. Operational notes

- Smoke artifacts: [`/root/arguzz/phase31_smoke.db`](phase31_smoke.db) (50 mutations, 101 globals, 5 bugs), [`/root/arguzz/phase31_smoke_output.txt`](phase31_smoke_output.txt) (817 lines).
- The plan markdown `.cursor/plans/precloud-iii-1-iii-2-plan_*.plan.md` was **not** modified per instruction.
- This report was authored after running the regression sweep + smoke; all numbers above are from that run. The terminal output of the smoke run is intact and can be re-parsed at any time via `python -m a4.standalone.tests.analyze_campaign /root/arguzz/phase31_smoke_output.txt`.

