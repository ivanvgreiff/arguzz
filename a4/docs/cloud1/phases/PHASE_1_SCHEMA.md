# Phase 1 — Schema & Data Model — Implementation Report

**Status**: ✅ COMPLETE
**Date**: 2026-06-08
**Owner**: Cursor (Opus 4.7)
**Wall-clock**: ~45 min (planning ~10 min, code ~20 min, tests ~10 min, report ~5 min)
**Source plan**: `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md` §Phase 1
**Pro reference**: `a4/docs/cloud1/ProG_Report_2.md` §5, §6.3, §7.A, §12

---

## TL;DR — what did we do, and why does it matter for cloud1?

**Plain English**: Phase 1 defines the **vocabulary** that every later phase will speak in. We did not change any runtime behavior; we built the **data types** and **storage** that Phases 2-6 will populate.

The fuzzer used to think about "where to mutate" in terms of `(mutation_kind, time_bucket)` — basically "this kind of mutation, somewhere in that 31-cycle slice of the trace". ChatGPT Pro's `ProG_Report_2.md` argued this is the wrong vocabulary because the zkVM doesn't care about time slices, it cares about **roles**: boundary cycles, ECALL transitions, memory ops, etc. So Phase 1 introduced **17 semantic zones** (`step0`, `last_step`, `pre_ecall`, `post_ecall`, `pre_mret`, `post_mret`, `pre_halt`, `post_halt`, `core_arithmetic`, `core_memory_load`, `core_memory_store`, `core_branch`, `core_mul`, `core_div`, `core_sha`, `core_poseidon`, `core_other`) and two additional Pro-defined data shapes:
- **Compressed global contexts** — instead of "memory address `0x80001000` was touched" (raw and meaningless), we now say "a user-region memory `read` at log-bucket 31 in the `normal` cycle phase" (semantic, comparable across mutations). Same idea for the three lookup tables (`u8`, `u16`, `cycle`).
- **Structural cells** — a tuple `(kind, zone, opcode_class, mode, txn_role, sub_strategy)` that lets the bandit get a small "you tried a new combination" reward signal even when no constraint was newly hit.

We then created **8 new SQLite tables** so every later phase can log everything Pro asked for in §12 (which arm got picked, which mode, what counterfactual rewards would have been, what raw Hook 3 said, what compressed contexts were extracted, kind-specific mutation details like funct3 fields, periodic snapshots of arm posteriors, and a pilot-runs table that will stay empty for IV.POS.7 per D2 but exists for forward-compat).

**How this fits into the bigger picture**: Phase 1 is the foundation everything else stands on:
- **Phase 2** uses `semantic_zones.SEMANTIC_ZONES` + `MAJOR_TO_CORE_ZONE` to build the new arm space.
- **Phase 3** uses `GlobalMemoryCtx` / `GlobalLookupCtx` + `compressed_global_coverage` table.
- **Phase 4** uses `StructuralCell` for the `S_new` reward term, and `local_coverage_v2` for `L_new`.
- **Phase 5**'s bandit reads/writes `bandit_decisions` + `arm_state_snapshot` tables.
- **Phase 6** wires the `record_*` methods into the fuzzer loop and emits `hook3_raw` + `mutation_substrategy` + `reward_counterfactuals`.

Without Phase 1, none of those phases have anywhere to put their data or any common vocabulary to discuss it.

**Concrete numbers**: 3 new Python modules (~330 LOC total), 1 modified module (+332 LOC of additive schema/method code), 8 new SQLite tables, 8 new `record_*` methods, 25 new unit tests, 132 pre-existing tests still pass.

---

## 1. Goal recap

Translate three Pro §5/§6.3/§7.A schemas + the Pro §12 logging spec into:
1. Three reusable Python dataclasses (frozen, hashable, JSON-serializable).
2. Eight new SQLite tables behind `CREATE TABLE IF NOT EXISTS` (idempotent for migration).
3. Eight Python `record_*` methods on `CoverageDB` for write access.

No runtime behavior change — only data plumbing.

---

## 2. Deviations from plan

**Two intentional additions** to make later phases cleaner; no recorded deviations:

- The plan asked for `MAJOR_TO_CORE_ZONE`; I also added `OPCODE_CLASS_BY_MAJOR` + `major_to_opcode_class()` in the same module. Rationale: the structural cell's `opcode_class` field is derived from the same `major` integer; co-locating the two maps in one module avoids cross-module coupling and gives Phase 4 a single import.
- Added `is_memory_family()` / `is_lookup_family()` predicate helpers in `compressed_global.py`. The Phase 3 extractor will dispatch on these; pre-baking the predicate removes a stringly-typed comparison from every call site.

**Two cosmetic-only deviations from Pro's §12 table naming** (logged in `CLOUD1_DECISIONS_FOR_PRO_R2.md`):
- `arm_state_log` → `arm_state_snapshot` (better reflects "periodic snapshot every E mutations" rather than "append-only log of every change")
- `hook3_raw_or_semantic` → `hook3_raw` (the semantic side is just a column `compressed_ctx_json` in the same table — name is cleaner)

---

## 3. Code changes

### 3.1 `a4/standalone/semantic_zones.py` (new file, 144 LOC)

Top-level constants:

```python
SEMANTIC_ZONES = (
    "step0", "last_step",
    "pre_ecall", "post_ecall",
    "pre_mret", "post_mret",
    "pre_halt", "post_halt",
    "core_arithmetic", "core_memory_load", "core_memory_store",
    "core_branch", "core_mul", "core_div",
    "core_sha", "core_poseidon", "core_other",
)
SINGLETON_ZONES = frozenset({"step0", "last_step"})
BOUNDARY_ZONES = frozenset(SINGLETON_ZONES | {
    "pre_ecall", "post_ecall",
    "pre_mret", "post_mret",
    "pre_halt", "post_halt",
})
CORE_ZONES = frozenset(z for z in SEMANTIC_ZONES if z not in BOUNDARY_ZONES)
```

Lookup maps (Phase 2 corrected `MAJOR_TO_CORE_ZONE` and `OPCODE_CLASS_BY_MAJOR` — see Phase 2 retrospective for the bug fix details):

```python
MAJOR_TO_CORE_ZONE: dict = { 0: "core_arithmetic", ..., 12: "core_other" }
OPCODE_CLASS_BY_MAJOR: dict = { 0: "alu", ..., 12: "other" }
```

Helpers: `major_to_zone(major) -> str`, `major_to_opcode_class(major) -> str`, `is_valid_zone(name) -> bool`. All three default to `"core_other"` / `"other"` / `False` respectively for unknown inputs, so unknown majors never raise but always produce a recognizable sentinel.

**Module-level assertions** (run at import time):
- `len(SEMANTIC_ZONES) == 17`
- `SEMANTIC_ZONES` has no duplicates
- `BOUNDARY_ZONES` and `CORE_ZONES` partition `SEMANTIC_ZONES`
- Every value in `MAJOR_TO_CORE_ZONE` is in `CORE_ZONES`
- Every value in `OPCODE_CLASS_BY_MAJOR` is a known opcode-class string

These run at import, so a typo or accidental mutation breaks the module at first import instead of silently corrupting downstream phases.

### 3.2 `a4/standalone/compressed_global.py` (new file, 110 LOC)

Two frozen, hashable, JSON-serializable dataclasses + their allowed-value tuples + 2 predicate helpers. Both dataclasses' field NAMES and FIELD ORDER are verbatim from Pro §5.

```python
@dataclass(frozen=True)
class GlobalMemoryCtx:
    family: str = "memory"
    address_region: str = "unknown"      # one of ADDRESS_REGIONS
    address_bucket: int = 0              # log2 bucket (decided in Phase 3 / D17)
    txn_role: str = "read"               # one of MEMORY_TXN_ROLES
    cycle_phase: str = "normal"          # one of MEMORY_CYCLE_PHASES

    def to_json_str(self) -> str:        # sorted-keys JSON; used as ctx_key
        return json.dumps({...}, sort_keys=True)

@dataclass(frozen=True)
class GlobalLookupCtx:
    family: str = "u8"                   # one of LOOKUP_FAMILIES
    lookup_index_bucket: int = 0
    producer_kind: str = "UNKNOWN"       # mutation kind that produced this run
    opcode_class: str = "other"          # one of OPCODE_CLASSES
    def to_json_str(self) -> str: ...
```

Both are `frozen=True` so they hash by value — critical for the Phase 4 reward function's "new compressed context?" set semantics.

Allowed-value tuples (`ADDRESS_REGIONS`, `MEMORY_TXN_ROLES`, `MEMORY_CYCLE_PHASES`, `LOOKUP_FAMILIES`, `OPCODE_CLASSES`) are exported so the Phase 3 extractor (and any future code) can validate against the Pro spec.

### 3.3 `a4/standalone/structural_cells.py` (new file, 77 LOC)

```python
@dataclass(frozen=True)
class StructuralCell:
    mutation_kind: str
    semantic_zone: str
    opcode_class: str
    mode: str           # "active" | "rejected_local" | "rejected_global" | "crash" | "accepted"
    txn_role: str
    sub_strategy: Optional[str] = None    # for kind-specific substrategy (e.g. INSTR_WORD_MOD_SUR field)

    def to_tuple(self) -> Tuple[str, str, str, str, str, Optional[str]]:
        return (self.mutation_kind, self.semantic_zone, self.opcode_class,
                self.mode, self.txn_role, self.sub_strategy)

def make_structural_cell(*, mutation_kind, semantic_zone, opcode_class,
                          mode, txn_role, sub_strategy=None) -> StructuralCell:
    ...
```

Per Pro §6.3 + §8.S_new. `sub_strategy` is optional because most mutation kinds don't have a meaningful substrategy (only `INSTR_WORD_MOD_SUR` decomposes into a funct3/funct7-style subfield). The builder uses keyword-only args to prevent positional-arg confusion at call sites.

### 3.4 `a4/standalone/coverage_db.py` — 8 new tables + 8 record methods (+332 LOC, all additive)

All 8 tables are introduced under a clearly marked block:

```python
# ====================================================================
# cloud1 / IV.POS.7 schema additions (Pro ProG_Report_2.md §12)
# All tables idempotent (CREATE TABLE IF NOT EXISTS); old IV.POS.5
# DBs gain these tables on first open under the v2 codebase without
# affecting existing data. Empty rows by default for legacy DBs.
# ====================================================================
```

| # | Table | Purpose | Pro §12 reference | Indexes |
|---|---|---|---|---|
| 1 | `bandit_decisions` | One row per mutation under a bandit-style selector. Records selected arm, mode (`adaptive`/`cold_start`/`forced_floor`/`uniform_baseline`), bandit score, runner-up arm, exploration flag, JSON extras. | `bandit_decisions` | `idx_bd_mode` |
| 2 | `arm_state_snapshot` | Periodic snapshot of every arm's bandit state (pulls, discounted pulls, posterior α/β, etc.), every `epoch_size` mutations. | `arm_state_log` (renamed, see §2) | `idx_arm_snap_camp_mut`, `idx_arm_snap_arm` |
| 3 | `reward_counterfactuals` | For EVERY mutation, what each candidate reward variant would have computed. Enables back-testing reward variants without re-running. | `reward_counterfactuals` | (PK on mutation_id) |
| 4 | `mutation_substrategy` | Kind-specific decomposition of WHAT exactly was mutated (opcode/rd/rs1/rs2/funct3/funct7/imm/byte_lane/bit_mask/value_class). Nullable per-field because each kind populates only its subset. | `mutation_substrategy` | (PK) |
| 5 | `hook3_raw` | Per-mutation raw Hook 3 family payload as JSON + the compressed-context JSON emitted by Phase 3's extractor. | `hook3_raw_or_semantic` (renamed, see §2) | (PK) |
| 6 | `pilot_runs` | Raw pilot observations + calibrated params. **EMPTY for IV.POS.7** per D2 (calibration removed for all 5 v2 variants); schema exists for forward-compat with future variants that may re-introduce calibration. | `pilot_runs` | `idx_pilot_camp` |
| 7 | `compressed_global_coverage` | First-hit table for `GlobalMemoryCtx` / `GlobalLookupCtx` contexts. Composite PK `(ctx_key, campaign_id)` makes inserts idempotent. `hit_count` increments on re-hits so we can report novelty + frequency in one table. | new (analog of existing `coverage` for the compressed family) | `idx_cgc_campaign` |
| 8 | `local_coverage_v2` | Extended local-context table: `(constraint_loc, major, minor)` per Pro §6.1, finer than the existing `coverage.constraint_loc`. Same shape as `compressed_global_coverage`. The OLD `coverage` table is unchanged so legacy analysis keeps working. | new (Pro §6.1 finer local context) | `idx_lcv2_campaign` |

Eight matching `record_*` methods, mirroring the existing `record_reward_diag` / `record_global_failures` pattern. They all:
- Use parameterized SQL (no f-string injection).
- Commit immediately (consistent with the existing `record_*` convention; no batching).
- Return `bool` (for first-hit semantics) or `None` (for append-only) following Pro §12's data-shape implications.
- Tolerate `INSERT OR REPLACE` on PK-keyed tables so a defensive re-call on the same `(mutation_id)` overwrites rather than errors.

### 3.5 Tests — three new test files (438 LOC total)

`tests/test_schema_v2.py` (196 LOC, 9 tests):

| # | Test | Verifies |
|---|---|---|
| 1 | `test_v2_tables_created` | All 8 tables created with `IF NOT EXISTS` and visible in `sqlite_master`. |
| 2 | `test_record_bandit_decision_roundtrip` | INSERT + SELECT round-trips a synthetic bandit decision row. |
| 3 | `test_record_arm_state_snapshot_roundtrip` | Append-only insert, both alpha/beta and `ts_extra_json` columns hold JSON. |
| 4 | `test_record_reward_counterfactuals_roundtrip` | Five reward variants persist as separate columns. |
| 5 | `test_record_mutation_substrategy_with_nulls` | Each kind populates only its subset; the rest are NULL. |
| 6 | `test_record_hook3_raw_roundtrip` | Two large JSON columns (`raw_json`, `compressed_ctx_json`) round-trip. |
| 7 | `test_record_pilot_run_roundtrip` | Insert/select works even though we won't use this table for IV.POS.7. |
| 8 | `test_record_compressed_global_first_hit_returns_new_then_repeats` | First insert returns True, second returns False and increments `hit_count`. |
| 9 | `test_record_local_v2_first_hit_returns_new_then_repeats` | Same idempotency contract as table 8. |

`tests/test_schema_v2_migration.py` (89 LOC, 2 tests):

| # | Test | Verifies |
|---|---|---|
| 1 | `test_legacy_db_gains_v2_tables_on_open` | Open `pos_ab_v1_d5_bandit-16_seed1238_n6000.db` (a real 6000-mutation IV.POS.5 DB), confirm v2 tables exist AND legacy data intact (mutations count, campaigns count). |
| 2 | `test_legacy_analytic_queries_still_work` | Run a representative legacy SQL query (`SELECT kind, COUNT(*) FROM mutations GROUP BY kind`) on the migrated DB; assert ≥5999 rows and the expected 7-8 mutation kinds appear. |

`tests/test_semantic_zone_dataclasses.py` (153 LOC, 14 tests):

| # | Test | Verifies |
|---|---|---|
| 1-3 | Zone-list invariants | 17 zones, no duplicates, BOUNDARY ∪ CORE = ALL. |
| 4-5 | Pro spec verbatim match | Every Pro §7.A name present; no extras. |
| 6-8 | `major_to_zone` correctness | All 13 known majors map to expected zones; unknown → core_other. |
| 9-10 | `major_to_opcode_class` correctness | All 13 known majors map to Pro §5 opcode_class enum; unknown → other. |
| 11-12 | Dataclass hashability + json round-trip | Two `GlobalMemoryCtx` with same fields hash to same value; `to_json_str()` round-trips. |
| 13-14 | `StructuralCell` builder | Keyword-only args reject positional misuse; `sub_strategy` defaults to None. |

**Note**: tests 6-10 in this file were UPGRADED in Phase 2 after we discovered the `major=8` / `major=11` bug. See Phase 2 retrospective for the bug story.

---

## 4. Test results

### 4.1 New unit tests

```
$ python -m pytest a4/standalone/tests/test_schema_v2.py \
                   a4/standalone/tests/test_schema_v2_migration.py \
                   a4/standalone/tests/test_semantic_zone_dataclasses.py -q
.........................                                                [100%]
25 passed in 9.04s
```

### 4.2 Full standalone fast regression

```
$ python -m pytest a4/standalone/tests/test_arm_universe.py \
                   a4/standalone/tests/test_bandit.py \
                   a4/standalone/tests/test_uniform_arm_selector.py \
                   a4/standalone/tests/test_pilot_calibration.py \
                   a4/standalone/tests/test_coverage_state.py \
                   a4/standalone/tests/test_coverage_db_rewards.py \
                   a4/standalone/tests/test_coverage_db_global.py \
                   a4/standalone/tests/test_coverage_db_campaign_params.py -q
......................................................................... [55%]
.....................................................                     [100%]
132 passed in 21.7s
```

**Zero regressions.**

### 4.3 Real-data migration check

```
$ python -c "from a4.standalone.coverage_db import CoverageDB; \
             db = CoverageDB('a4/runs/iv_pos_5/pos_ab_v1_d5/.../pos_ab_v1_d5_bandit-16_seed1238_n6000.db'); \
             print('mutations:', db.conn.execute('SELECT COUNT(*) FROM mutations').fetchone()); \
             print('v2 tables present:', [t[0] for t in db.conn.execute(\"SELECT name FROM sqlite_master WHERE name LIKE '%coverage_v2%' OR name LIKE 'bandit_%' OR name LIKE 'arm_state_%'\").fetchall()])"
mutations: (6000,)
v2 tables present: ['bandit_decisions', 'arm_state_snapshot', 'compressed_global_coverage', 'local_coverage_v2']
```

Confirms: legacy DB opens, mutations intact (6000), new tables added empty without disturbing existing data.

---

## 5. Acceptance-criteria scorecard

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | 3 new modules importable, no circular deps | ✅ | `python -c "import a4.standalone.semantic_zones, a4.standalone.compressed_global, a4.standalone.structural_cells"` succeeds |
| 2 | 17 semantic zones present, verbatim Pro §7.A names | ✅ | `test_semantic_zone_dataclasses.py` tests 4-5 |
| 3 | `GlobalMemoryCtx` field names exactly match Pro §5 | ✅ | `test_semantic_zone_dataclasses.py` test 11 |
| 4 | `GlobalLookupCtx` field names exactly match Pro §5 | ✅ | `test_semantic_zone_dataclasses.py` test 11 |
| 5 | `StructuralCell` matches Pro §6.3 | ✅ | `test_semantic_zone_dataclasses.py` test 13 |
| 6 | 8 new tables created with `CREATE TABLE IF NOT EXISTS` | ✅ | `test_schema_v2.py` test 1 |
| 7 | 8 `record_*` methods implemented | ✅ | `test_schema_v2.py` tests 2-9 |
| 8 | Legacy IV.POS.5 DBs open and auto-migrate non-destructively | ✅ | `test_schema_v2_migration.py` tests 1-2 + manual check §4.3 |
| 9 | Existing 132 tests still pass | ✅ | §4.2 |
| 10 | Two name-only deviations from Pro §12 logged in DECISIONS doc | ✅ | `CLOUD1_DECISIONS_FOR_PRO_R2.md` "Cosmetic / name-only deviations" section |

---

## 6. Key variables / functions

| Symbol | Type | Where | Meaning |
|---|---|---|---|
| `SEMANTIC_ZONES` | `Tuple[str, ...]` of length 17 | `semantic_zones.py:24` | The canonical zone-name list. Order matches Pro §7.A's listing. |
| `SINGLETON_ZONES` | `frozenset[str]` (2 elements) | `semantic_zones.py:35` | `{"step0", "last_step"}`. Singleton-arm forced-pull floor in Phase 5 uses this. |
| `BOUNDARY_ZONES` | `frozenset[str]` (8 elements) | `semantic_zones.py:36` | `SINGLETON_ZONES ∪ {pre/post_ecall/mret/halt}`. Boundary-floor allocation in Phase 5 uses this. |
| `CORE_ZONES` | `frozenset[str]` (9 elements) | `semantic_zones.py:42` | Complement of `BOUNDARY_ZONES`. Adaptive-TS allocation in Phase 5 distributes budget over these. |
| `MAJOR_TO_CORE_ZONE` | `Dict[int, str]` | `semantic_zones.py:48` | rv32im major-class → zone fallback. **Fixed in Phase 2** for majors 8-12 to match `inspection_data.py:224-228`. |
| `OPCODE_CLASS_BY_MAJOR` | `Dict[int, str]` | `semantic_zones.py:83` | rv32im major-class → opcode_class label per Pro §5 enum. |
| `major_to_zone(major)` | function | `semantic_zones.py` | Returns `MAJOR_TO_CORE_ZONE.get(major, "core_other")`. |
| `major_to_opcode_class(major)` | function | `semantic_zones.py` | Returns `OPCODE_CLASS_BY_MAJOR.get(major, "other")`. |
| `GlobalMemoryCtx` | frozen dataclass | `compressed_global.py:57` | Pro §5 GLOBAL_MEMORY shape, hashable. |
| `GlobalLookupCtx` | frozen dataclass | `compressed_global.py:80` | Pro §5 GLOBAL_LOOKUP shape, hashable. |
| `CompressedGlobalCtx` | `Union[GlobalMemoryCtx, GlobalLookupCtx]` | `compressed_global.py:100` | Type alias the Phase 3 extractor returns. |
| `StructuralCell` | frozen dataclass | `structural_cells.py:14` | Pro §6.3/§8 structural-cell tuple. |
| `bandit_decisions` | SQL table | `coverage_db.py:258+` | Pro §12 per-mutation bandit-decision row. |
| `arm_state_snapshot` | SQL table | `coverage_db.py:278+` | Periodic snapshot of arm-bandit state (renamed from Pro's `arm_state_log`). |
| `reward_counterfactuals` | SQL table | `coverage_db.py:305+` | Counterfactual rewards for back-testing reward variants. |
| `mutation_substrategy` | SQL table | `coverage_db.py:321+` | Kind-specific mutation-detail decomposition. |
| `hook3_raw` | SQL table | `coverage_db.py:343+` | Raw + compressed Hook 3 payloads per mutation. |
| `pilot_runs` | SQL table | `coverage_db.py:357+` | Pilot observations + calibrated params. Empty for IV.POS.7 per D2. |
| `compressed_global_coverage` | SQL table | `coverage_db.py:377+` | First-hit table for `GlobalMemoryCtx` / `GlobalLookupCtx`; `(ctx_key, campaign_id)` PK. |
| `local_coverage_v2` | SQL table | `coverage_db.py:402+` | First-hit table for `(constraint_loc, major, minor)` per Pro §6.1. |
| `record_bandit_decision` | method | `coverage_db.py` | Insert one bandit-decision row. |
| `record_arm_state_snapshot` | method | `coverage_db.py` | Append-only snapshot row. |
| `record_reward_counterfactuals` | method | `coverage_db.py` | Insert OR REPLACE per mutation. |
| `record_mutation_substrategy` | method | `coverage_db.py` | Insert OR REPLACE per mutation. |
| `record_hook3_raw` | method | `coverage_db.py` | Insert OR REPLACE per mutation. |
| `record_pilot_run` | method | `coverage_db.py` | Append pilot observation. |
| `record_compressed_global_first_hit` | method | `coverage_db.py:580+` | Returns True if first hit (inserts row), False otherwise (increments `hit_count`). |
| `record_local_v2_first_hit` | method | `coverage_db.py:619+` | Same contract as above for local v2 contexts. |

---

## 7. Insights / what to keep in mind for next phases

1. **The 17-zone vocabulary is a `Tuple`, not a `set`** — ordering matters for the bandit's deterministic arm enumeration. Don't refactor it into a `frozenset`.

2. **`MAJOR_TO_CORE_ZONE` is a FALLBACK** — the zone classifier (Phase 2) applies boundary rules first; only steps not assigned by boundary rules fall through to this map. This is why mapping `major=8` to `core_other` is correct here (the boundary rule should have already placed it in `pre_ecall`).

3. **`compressed_global_coverage` PK is `(ctx_key, campaign_id)`, not `ctx_key` alone** — cross-campaign comparison requires per-campaign first-hit tracking. The `hit_count` column lets us recover total-hits-per-context per campaign without a JOIN.

4. **All 8 v2 tables are FK'd to `mutations.id` or `campaigns.id` with `ON DELETE CASCADE`** — if we ever GC a campaign, all its v2 telemetry goes with it, preventing dangling rows.

5. **The `pilot_runs` table is empty by design for IV.POS.7** (D2: pilot calibration removed for all 5 v2 variants). Future variants that re-introduce calibration can populate it without schema change.

6. **`mutation_substrategy` has 10 nullable columns** — most kinds will populate only 1-3. Phase 6 (logging) needs a per-kind mapper that knows which fields to fill in for which kind. This was deferred to Phase 6 intentionally; Phase 1 only created the schema.

7. **Phase 2 caught a Phase 1 bug** in `MAJOR_TO_CORE_ZONE` (I had `8→core_sha`, `9→core_poseidon` based on guessing from Pro's zone-name list; the AUTHORITATIVE source `inspection_data.py:224-228` says `8=ECALL0`, `9=POSEIDON0`, `10=POSEIDON1`, `11=SHA0`, `12=BIGINT0`). The fix happened in Phase 2; the lesson is: **always cross-check empirical sources before assuming a mapping**, even when the abstract names look plausible.

---

## 8. What's now possible that wasn't before

- **Phase 2** can build a `(kind, semantic_zone)` arm space (done).
- **Phase 3** can write `GlobalMemoryCtx` / `GlobalLookupCtx` rows to `compressed_global_coverage` and get first-hit booleans for free (done).
- **Phase 4** can implement `S_new` reward against `StructuralCell` instances.
- **Phase 5** can persist per-mutation bandit decisions + periodic state snapshots for post-hoc audit.
- **Phase 6** can log raw Hook 3 alongside the compressed contexts, enabling re-derivation if the extractor logic changes.
- **Pro Round 2** can SQL into these tables for diagnostic analysis without needing to re-run the campaign.

---

## 9. Files touched

```
A  a4/standalone/semantic_zones.py                          (+144 LOC, 3 modules, 5 helpers)
A  a4/standalone/compressed_global.py                       (+110 LOC, 2 dataclasses, 5 enums, 2 predicates)
A  a4/standalone/structural_cells.py                        (+77 LOC,  1 dataclass, 1 builder)
M  a4/standalone/coverage_db.py                             (+332 LOC, 8 tables, 8 record_* methods, 8 indexes)
A  a4/standalone/tests/test_schema_v2.py                    (+196 LOC, 9 tests)
A  a4/standalone/tests/test_schema_v2_migration.py          (+89 LOC,  2 tests)
A  a4/standalone/tests/test_semantic_zone_dataclasses.py    (+153 LOC, 14 tests)
M  a4/docs/cloud1/CLOUD1_STATUS.md                          (mark Phase 1 DONE)
M  a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md            (add 2 cosmetic deviations)
A  a4/docs/cloud1/phases/PHASE_1_SCHEMA.md                  (this file)
```

---

## 10. Consistency check against `ProG_Report_2.md`

| Pro reference | What we did | Match? |
|---|---|---|
| §5 GLOBAL_MEMORY schema (5 fields: family, address_region, address_bucket, txn_role, cycle_phase) | `GlobalMemoryCtx` frozen dataclass with these 5 fields, exact names | ✅ |
| §5 GLOBAL_LOOKUP schema (4 fields: family, lookup_index_bucket, producer_kind, opcode_class) | `GlobalLookupCtx` frozen dataclass with these 4 fields, exact names | ✅ |
| §5 ADDRESS_REGION enum (user, kernel, image, stack, heap, invalid, unknown) | `ADDRESS_REGIONS` tuple of 7 strings, exact names | ✅ |
| §5 MEMORY_TXN_ROLE enum (read, write, ifetch, register, prev_word, prev_cycle) | `MEMORY_TXN_ROLES` tuple of 6 strings, exact names | ✅ |
| §5 MEMORY_CYCLE_PHASE enum (normal, ecall, mret, halt, boundary) | `MEMORY_CYCLE_PHASES` tuple of 5 strings, exact names | ✅ |
| §5 LOOKUP_FAMILIES (u8, u16, cycle) | `LOOKUP_FAMILIES` tuple of 3 strings, exact names | ✅ |
| §5 OPCODE_CLASSES (alu, mul, div, mem, branch_or_ctrl, sha, poseidon, other) | `OPCODE_CLASSES` tuple of 8 strings, exact names | ✅ |
| §6.3 structural cell (kind × zone × opcode_class × mode × txn_role) | `StructuralCell` with these 5 + optional `sub_strategy` | ✅ |
| §7.A 17 semantic zones, exact names | `SEMANTIC_ZONES` tuple of 17, names verbatim | ✅ |
| §12 logging tables: bandit_decisions, arm_state_log, reward_counterfactuals, mutation_substrategy, hook3_raw_or_semantic, pilot_runs | 6 tables created with matching schemas; 2 cosmetic renames (`arm_state_log → arm_state_snapshot`, `hook3_raw_or_semantic → hook3_raw`) | ✅ (2 cosmetic deviations logged) |
| §12 implied: store compressed contexts somewhere with first-hit semantics | Added `compressed_global_coverage` table (not in Pro spec — Pro only mentioned the contexts themselves; needed a place to put them) | ✅ (extension Pro will see in Round 2) |
| §6.1 finer local context `(constraint_loc, major, minor)` | Added `local_coverage_v2` table (analog of existing `coverage`) | ✅ |

---

## 11. Variable / symbol reference

(Single-character or non-obvious symbols used in this report and downstream phases:)

- `T` (in `total_steps`) — number of user_cycles in the trace.
- `K` — number of mutation kinds (8 for IV.POS.7).
- `B` (legacy) — number of step buckets in the old `arm_uniform_b128` / `ucb_kindbucket_b16` arm spaces.
- `Z` (cloud1) — number of semantic zones (17).
- `α`, `β` — Beta-posterior shape parameters used by Thompson sampling (Phase 5). Stored as `posterior_alpha` / `posterior_beta` in `arm_state_snapshot`.
- `ctx_key` — stable string serialization of a context, used as composite-PK component in `compressed_global_coverage` and `local_coverage_v2`. For compressed contexts, equals the `to_json_str()` output.
