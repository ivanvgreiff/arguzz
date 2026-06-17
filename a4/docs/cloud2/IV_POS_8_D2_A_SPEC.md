# IV.POS.8 D2.A — Foundation Spec (Hybrid V7 prerequisites)

**Branch:** `cloud2`
**Date opened:** 2026-06-16
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Status:** **LOCKED v0.2** — Ivan accepted all §6 Q1–Q11 recommendations (2026-06-16); §1.1 5-tuple semantics + §4.6 synthetic-arms test added; ready for Composer Batch 1 kickoff
**Parent:** [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) §4 (sub-deliverable D2.A)
**Predecessor:** [`IV_POS_8_D1_A_SPEC.md`](./IV_POS_8_D1_A_SPEC.md) (D1.A floor schedules + schema additions — merged + running)

---

## Changelog

- **v0.2 (2026-06-16, Ivan-locked):**
  - All 11 §6 open questions resolved with Opus recommendations (recorded in new §8 "Decisions Confirmed").
  - New §1.1 "What each 5-tuple field means" — explicit semantics + A4 + Arguzz mapping table per Ivan question.
  - New §4.6 test `test_d2a_arm_shape_arguzz_simulation.py` added — synthetic scheduler-level test that exercises all 5 ArmKey fields with non-trivial values in D2.A Batch 1, closing the "we don't validate the new fields until D2.D" gap Ivan flagged.
  - §6 retitled "Open questions (resolved)" and kept as historical record.
- **v0.1 (2026-06-16):** initial draft (file-by-file changes, decision matrix, 11 open questions for Ivan).

---

## 0. What this document is

The implementation spec for **D2.A — the load-bearing foundation of Hybrid V7**. Everything in D2 (B–G) depends on this landing first. The spec mirrors `IV_POS_8_D1_A_SPEC.md` in shape: concrete file-level changes, test gates, decision table, Composer task breakdown, decisions locked in §8.

**Workflow** (per Ivan v0.2 decision): Ivan reviews this draft → §6 open questions resolved (✓ done v0.2) → spec locked (✓ done v0.2) → Composer Batch 1 kickoff → Composer reports → Ivan + Opus review → iterate as needed → D2.A complete.

## 1. Goal

D2.A delivers three architectural changes to the V5 scheduler / fuzzer / DB layer that are prerequisites for Hybrid V7 variants:

| # | Change | Why D2 needs it |
|---|---|---|
| **1.1** | Extend the bandit arm key from 2-tuple `(kind, zone)` to 5-tuple `(surface, kind, zone, opcode_class, pre_post)`, with V5 back-compat via "n/a" sentinels and unchanged V5 arm_id string format | Pro §8 / §15 — Hybrid scheduler must allocate across both A4-trace-cell and Arguzz exec-fault surfaces, opcode-class-aware |
| **1.2** | Introduce a `MutationOutcome` enum (`APPLIED` / `SKIPPED` / `ERROR`) and a per-variant policy controlling whether `SKIPPED` advances scheduler state; record outcome to DB | Pro §8 explicitly: "the scheduler must count only **applied** Arguzz mutations as pulls"; we need this infrastructure in place before adding V6 kinds in D2.C |
| **1.3** | **Verify** that the V5 fuzzer already writes normalized loc strings at source (it does — `ConstraintFailure.short_loc()` runs inside `record_failures`), tighten the contract, and mark the post-hoc `constraint_loc_normalize.py` as **legacy-only** (used solely for reading R2 V6 archive DBs that bypassed `short_loc()`) | Pro §15: "normalized loc and CGC telemetry" at source. Most of the work is already done at the source layer — D2.A makes it a tested invariant rather than an accident |

### 1.1 What each 5-tuple field means (Ivan question, 2026-06-16)

The new `ArmKey` is `(surface, kind, zone, opcode_class, pre_post)`. Below is what each field means and how A4 vs Arguzz mutations map onto it. The short answer to "can both map cleanly?" is **yes** — the schema was designed for Arguzz's richer parameterization; A4 collapses naturally onto the same shape via "n/a" sentinels in the v1 ship.

| Field | Type | Allowed values (D2.A v1) | What it means | A4 mapping | Arguzz mapping |
|---|---|---|---|---|---|
| `surface` | str | `"A4_trace_cell"` \| `"arguzz_exec_fault"` | Which fuzzing surface this arm dispatches on. Determines **which mutator code path runs**: A4's in-process post-execution trace-cell rewriter, or the Arguzz subprocess fault injector. The dispatcher key. | `"A4_trace_cell"` for all 8 existing A4 kinds and all 3 D2.B kinds | `"arguzz_exec_fault"` for all 4 D2.C V6 kinds |
| `kind` | str | the existing kind-name string (e.g., `"INSTR_WORD_MOD_SUR"`, `"COMP_OUT_MOD"`, `"PRE_EXEC_MEM_MOD"`) | The specific mutation kind. **Name collisions are possible** (Arguzz `"INSTR_WORD_MOD"` ≠ A4 `"INSTR_WORD_MOD_SUR"`, but Arguzz `"PRE_EXEC_REG_MOD"` historically clashes with A4's name) — `surface` disambiguates. | All current 8 A4 kinds + D2.B's 3 new ones (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`) | D2.C's 4 V6 kinds (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`) + expandable to the full 7 from the §2.1 V6 inventory |
| `zone` | str | one of 18 strings from `a4/standalone/semantic_zones.py` (`core_arithmetic`, `core_memory_load`, `core_memory_store`, `core_branch`, `core_jump`, `core_other`, `kernel_decode`, `kernel_ecall`, …) | The semantic zone of the **trace step** being mutated. Cycle's major→zone classification is already done in `zone_classifier.py`. Universal — both surfaces operate on the same trace, so both have a well-defined zone. | zone of the cycle whose witness cell A4 rewrites | zone of the cycle where Arguzz injects the fault (extracted from `<fault>` step in `arguzz_parser.py`) |
| `opcode_class` | str | `"arithmetic"` \| `"memory_load"` \| `"memory_store"` \| `"branch"` \| `"jump"` \| `"ecall_mret"` \| `"system"` \| `"n/a"` | Coarse classification of the opcode at the mutation step. Already derived in `compressed_global_extractor.py` via `semantic_zones.major_to_opcode_class(major)` — **the helper exists today, no new logic to invent**. Crucial for Arguzz because some Arguzz kinds only apply to certain opcode classes (e.g., `BR_NEG_COND` ⇒ `branch` only). | `"n/a"` in v1 — Q7 locked. (D2.B's expansion kinds COULD use real opcode classes for arms like `TXN_PREV_WORD_MOD@core_arithmetic@arithmetic`, but the v1 ship treats them as `"n/a"` to keep arm-space bounded and avoid inflating the V5 baseline.) | Real opcode_class derived from the cycle's major at the fault step. Same `major_to_opcode_class` helper. |
| `pre_post` | str | `"pre_exec"` \| `"post_exec"` \| `"n/a"` | Whether the mutation perturbs **before** instruction execution (e.g., Arguzz pre-fetch register/memory injection) or **after** (e.g., Arguzz post-instruction register/memory injection, or A4's witness-cell rewrite). | `"n/a"` in v1 — Q8 locked. A4 trace-cell mutations are conceptually all "post-execution" (the cycle ran and we rewrite its witness), but threading per-A4-kind pre/post classification through is out-of-scope for D2.A. | `"pre_exec"` for `PRE_EXEC_*` Arguzz kinds (`PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `PRE_EXEC_REG_MOD`); `"post_exec"` for `POST_EXEC_*` kinds (`POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_PC_MOD`). `INSTR_WORD_MOD` and `BR_NEG_COND` are conceptually pre-exec (perturb the instruction before it runs); we'll classify them in D2.C via `arguzz_parser.py` extension. |

**Concrete examples (post-D2.D):**

| Arm string (in `bandit_decisions.selected_arm`) | Meaning |
|---|---|
| `"COMP_OUT_MOD\|core_arithmetic"` | V5 / D2.B A4 arm — kept in legacy 2-pipe format because `surface=A4_trace_cell, opcode=n/a, pre_post=n/a` (Q1+Q7+Q8 lock) |
| `"arguzz_exec_fault\|INSTR_WORD_MOD\|core_arithmetic\|arithmetic\|pre_exec"` | V6 / Hybrid arm — Arguzz instruction-word fault at an arithmetic cycle, pre-execution |
| `"arguzz_exec_fault\|BR_NEG_COND\|core_branch\|branch\|pre_exec"` | V6 / Hybrid arm — Arguzz branch-condition fault, only ever appears in `core_branch` zone with `branch` opcode |
| `"arguzz_exec_fault\|POST_EXEC_REG_MOD\|core_memory_load\|memory_load\|post_exec"` | V6 / Hybrid arm — Arguzz post-register-write injection after a load |

**Bottom line:** both A4 and Arguzz map cleanly onto the 5-tuple. The 3 fields that are constant for A4 in v1 (`surface, opcode_class, pre_post`) are exactly the fields where Arguzz needs richer parameterization. The split is asymmetric by design — that asymmetry is what makes the schema honest about the difference between the two surfaces.

### 1.2 When do the new arm fields actually get populated and tested? (Ivan question, 2026-06-16)

Ivan's concern: under v0.1, D2.A introduces 5-field `ArmKey` but V5 keeps all new fields = `"A4_trace_cell" / "n/a" / "n/a"`. D2.B's pure-A4 kinds also stay on `"A4_trace_cell" / "n/a" / "n/a"` (Q7+Q8). So in the v0.1 plan the new fields don't get **content** until D2.C and don't get **end-to-end testing** until D2.E. That's late.

**Fix in v0.2:** D2.A Batch 1 adds a **scheduler-level synthetic-arms test** (`test_d2a_arm_shape_arguzz_simulation.py`, see §4.6) that constructs a `SemanticArmUniverse` with arms spanning **both** surfaces and **non-trivial** opcode_class + pre_post values — even though no real Arguzz dispatcher exists yet. This validates that:

1. The scheduler correctly handles arms with surface = `"arguzz_exec_fault"` and opcode_class ≠ `"n/a"` and pre_post ≠ `"n/a"` (cold start, singleton picks, floor schedule progression, beta-TS posterior updates).
2. The `arm_id` string formatter produces the **5-pipe full** format for these arms (not the legacy V5 2-pipe shorthand).
3. `applied_accounting_mode=True` works correctly on a mix of A4-surface (always-applied) and Arguzz-surface (mock-skipped) arms.

| Layer | Where in plan | Validation strength |
|---|---|---|
| **Pure scheduler unit test on 5-tuple** | D2.A Batch 1 §4.6 (new) | All 5 fields populated with real values, scheduler exercised end-to-end at the bandit layer |
| **Pure scheduler unit test on V5 back-compat** | D2.A Batch 1 §4.6 (existing golden trace) | V5 RNG sequence byte-identical with new `ArmKey` dataclass |
| **Pure-A4 kinds wired in fuzzer** | D2.B | A4 kinds register on arm-shape and run end-to-end; still `"n/a"` for opcode_class / pre_post (Q7+Q8) |
| **Arguzz subprocess dispatch by surface** | D2.C | Real `arguzz_exec_fault` arms dispatched to `arguzz_runner.run_arguzz_mutation()`; real opcode_class / pre_post populated from `<fault>` parser output |
| **Variant CLI exercising both surfaces in one run** | D2.D + D2.E | Hybrid-cTS arm history must contain both surfaces; per-variant arm-shape coverage assertions |

So the **arm-shape correctness is bulletproof at end of D2.A**; what comes later is real dispatching of arms to mutators, not the arm-shape mechanics themselves.

## 2. Non-goals (deliberately out of D2.A scope)

- **New mutation kinds** — those are D2.B (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`)
- **Any Arguzz subprocess integration** — that is D2.C; D2.A defines the `arguzz_exec_fault` surface enum value but does not wire the surface to a dispatcher
- **Any new CLI selector flag** — that is D2.D; D2.A keeps the existing `cTS_semantic_v2` + decay variants working unchanged
- **Any V5 behavior change** — V5 RNG sequence, V5 arm_id string format, V5 floor schedule, V5 telemetry all **byte-identical pre/post D2.A** under the same seed (golden trace test enforces this)
- **CGC reward variant choice** — D1.B owns that decision; D2.A doesn't touch CGC computation
- **Deletion of `constraint_loc_normalize.py`** — kept as a legacy compat shim for R2 V6 archive analysis; **only** its use in *new* DBs is removed

## 3. Codebase landscape (what we found in §2 investigation)

### 3.1 What V5 currently does

- Arm key: `ArmKey = Tuple[str, str]` defined in `a4/standalone/semantic_arm_universe.py` line 117
- `ConstrainedTSScheduler` in `a4/standalone/bandit_ts.py` lines 114–290 indexes 6 dicts (`pulls`, `successes`, `epoch_pulls`, …) by `ArmKey`
- `BanditDecision.arm_id` is built via `arm_id(kind, zone) = "kind|zone"` (line 44–48)
- The fuzzer's V5 / cTS path is `A4Fuzzer._run_v2_bandit_mutation` in `a4/standalone/fuzzer.py` lines 930–1175. Key call sites:
  - `decision = self.v2_scheduler.select()` (line 939) — returns kind, zone, step
  - Skip-path on `config is None`: `self.v2_scheduler.update(kind, zone, 0)` (line 982) — **counts a skip as a 0-success pull**
  - Success path: `self.v2_scheduler.update(kind, zone, bandit_success)` (line 1115)
  - DB write: `self.db.record_mutation(...)` (line 1123) and `self.db.record_failures(mutation_id, failures)` (line 1128)
- Pure-A4 (non-bandit) loop is `A4Fuzzer._run_single_mutation` in `a4/standalone/fuzzer.py` lines 1349–1575 (no scheduler updates; just records mutations)

### 3.2 What `record_failures` writes (and why normalization is mostly done already)

`a4/standalone/coverage_db.py` lines 754–809:

```python
cursor.execute(""" INSERT INTO failures ... constraint_loc ... """, (
    mutation_id, failure.constraint_type(), failure.constraint_loc(), ...
))
cursor.execute(""" INSERT OR IGNORE INTO coverage (constraint_loc, ...) VALUES (?, ?, ?, 1) """,
    (failure.constraint_loc(), mutation_id, now))
```

Both inserts call `failure.constraint_loc()` which delegates to `ConstraintFailure.short_loc()` in `a4/core/constraint_parser.py` lines 55–84. That method handles **both** A4 `callsite(... path/file.zir:line)` and V6 `Name(zirgen/.../file.zir:line)` source formats and emits the canonical `Name@basename:line`. **Empirical check:** R2 V5 DBs sampled today contain rows like `AddrDecompose@u32.zir:67` — already normalized. The current Q-G driver (`a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py`) is therefore a **read-side compat shim**, not a write-side normalizer.

### 3.3 Why R2 V6 DBs still need the post-hoc normalizer

R2 V6 DBs sampled today contain raw rows like `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)`. The `v6_arguzz` driver that produced those DBs bypassed `short_loc()` and inserted `failure.loc` (the raw form). For D2 forward, V6-cTS and Hybrid-cTS run through `a4.standalone.fuzzer.A4Fuzzer.record_mutation`, which calls `record_failures` → `short_loc()`, so they automatically produce normalized locs. **No write-side code change is needed in D2.A**; the verification gate is what's new.

### 3.4 Existing schema columns relevant to D2.A

`mutations` table after D1.A merge has: `id, campaign_id, kind, step, txn_idx, mutated_value, original_value, config_json, executed_at, num_failures, verifier_accepted, proof_generated, proof_verify_failed, elapsed_ms`. D2.A adds **one** new nullable column: `outcome TEXT`.

`bandit_decisions.selected_arm` is `TEXT NOT NULL`. Currently V5 writes `"KIND|ZONE"`. D2.A's V5 path keeps that exact format (back-compat); new variants will write `"surface|kind|zone|opcode_class|pre_post"` when D2.D ships.

## 4. Detailed change list (file by file)

### 4.1 `a4/standalone/semantic_arm_universe.py`

| Change | Detail |
|---|---|
| Extend `ArmKey` | Promote from `Tuple[str, str]` to a `@dataclass(frozen=True)` with 5 string fields: `surface`, `kind`, `zone`, `opcode_class`, `pre_post`. Provide `as_tuple() -> Tuple[str, str, str, str, str]` for dict-key use |
| `__str__` / `__repr__` | Return `"surface\|kind\|zone\|opcode_class\|pre_post"` (with `"\|"` literal pipe separator) |
| Helper `ArmKey.v5(kind, zone)` | Returns `ArmKey(surface="A4_trace_cell", kind=kind, zone=zone, opcode_class="n/a", pre_post="n/a")` — used by V5 builder |
| `SemanticArmUniverse.build` | Internal arm dict stays `Dict[ArmKey, List[int]]` but is built via `ArmKey.v5(kind, zone)`. Public `available_arms` returns `List[ArmKey]` (unchanged surface from caller's POV — both old `(kind, zone)` and new `ArmKey` are iterables with `.kind`, `.zone` attributes accessible) |
| Back-compat accessor | New methods `kind_of(arm) -> str` and `zone_of(arm) -> str` to unify access whether callers received a tuple or an ArmKey (tests will use these) |
| **Out-of-scope** | No changes to the `_filter_real_target_steps` logic or zone-step resolution |

### 4.2 `a4/standalone/bandit_ts.py`

| Change | Detail |
|---|---|
| Use new `ArmKey` | `self.arms: List[ArmKey]`; dicts `pulls`, `successes`, `epoch_pulls`, `_singleton_set` keyed by `ArmKey` (with `as_tuple()` for hashing) |
| `update(...)` signature | Generalize: `update(arm: ArmKey, success: int)` AND keep a back-compat overload `update(kind: str, zone: str, success: int)` that internally constructs `ArmKey.v5(kind, zone)`. The overload is required to keep V5's `_run_v2_bandit_mutation` call at line 1115 unchanged |
| `BanditDecision.arm_id` | For arms built by `ArmKey.v5(kind, zone)`, `arm_id = f"{kind}\|{zone}"` (V5-format). For arms with non-`n/a` surface/opcode_class/pre_post fields, `arm_id = full ArmKey __str__`. Selection logic in `arm_id_for_decision(arm)` helper |
| Add `MutationOutcome` enum | New top-level: `class MutationOutcome(str, Enum): APPLIED = "applied"; SKIPPED = "skipped"; ERROR = "error"` |
| Add `applied_accounting_mode` constructor flag | Default `False` (V5 unchanged). When `True`, expose a `select()`-with-`re_pick_on_skip` contract: the fuzzer calls `update_with_outcome(arm, outcome)`, which only advances pulls/epoch state when `outcome == APPLIED`. Variant selection of this mode is done **per-selector** by the fuzzer; ` ConstrainedTSScheduler` itself stays opt-in |
| **Tests** | Golden-trace identity test: seed=42, 200 selections, identical decision sequence pre/post the refactor. The fuzzer's `bandit_decisions.selected_arm` strings on this 200-mutation slice must be byte-identical for V5 |

### 4.3 `a4/standalone/fuzzer.py`

| Call site | Current code | Change |
|---|---|---|
| Line 939 | `decision = self.v2_scheduler.select()` | unchanged (decision now holds an `ArmKey`-shaped `arm` attr; V5 path uses `decision.kind / decision.zone` accessors that work identically) |
| Line 982 (skip-on-target-fail) | `self.v2_scheduler.update(kind, zone, 0)` | unchanged for V5. Future D2.C/D2.D variants reading `selector_strategy ∈ {v6_cTS, hybrid_cTS}` get a different branch in D2.C that calls `update_with_outcome(arm, MutationOutcome.SKIPPED)` instead |
| Line 1115 (success update) | `self.v2_scheduler.update(kind, zone, bandit_success)` | unchanged for V5. D2.C/D2.D extend to `update_with_outcome(arm, MutationOutcome.APPLIED, success=bandit_success)` for new variants |
| `record_mutation` call sites (4 total: lines 477, 897, 1123, 1481) | `self.db.record_mutation(... **self._mutation_record_kwargs(result))` | Extend `_mutation_record_kwargs` to include `outcome=MutationOutcome.APPLIED.value` when execution completed; `MutationOutcome.SKIPPED.value` for skipped paths; `MutationOutcome.ERROR.value` for crashed paths |
| **New helper** | — | `_outcome_for(result: MutationResult) -> MutationOutcome` consolidating the classification logic in one place |

### 4.4 `a4/standalone/coverage_db.py`

| Change | Detail |
|---|---|
| Schema migration | Add `outcome TEXT` to `mutations`. Pattern mirrors D1.A's `proof_generated` addition (lines 119–121): `if "outcome" not in mut_cols: ALTER TABLE mutations ADD COLUMN outcome TEXT` |
| `record_mutation` signature | Add `outcome: Optional[str] = None` kwarg between `elapsed_ms` and the close of the call. Default `None` keeps back-compat with any external caller |
| Indices | Add `CREATE INDEX IF NOT EXISTS idx_mutations_outcome ON mutations(outcome)` for fast filtering in analysis |

### 4.5 `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py`

| Change | Detail |
|---|---|
| Top-level docstring | Add a note: "**Legacy / R2-compat only.** D2.A onward, DBs ship with `Name@basename:line` already canonicalized at write-time via `ConstraintFailure.short_loc()`. This module is retained only to read the R2 `v6_arguzz` archive DBs (which bypassed `short_loc()`). Do not import this in new code." |
| Behavior | Unchanged — pure compat shim |

### 4.6 New tests

| Test file | Asserts |
|---|---|
| `a4/standalone/tests/test_d2a_arm_shape.py` | (a) `ArmKey.v5(k, z)` produces the same `arm_id` string format as the legacy `arm_id(k, z)` helper; (b) `ArmKey(...)` with any non-`n/a` field produces a 5-part pipe-separated string; (c) Round-tripping `str(ArmKey(...)) → ArmKey.parse(...)` is the identity |
| `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` | Golden trace: same seed (42), same V5 selector, same 200-mutation slice. Decision sequence + `bandit_decisions.selected_arm` strings + `mutation_rewards` rows + `coverage.constraint_loc` rows are byte-identical pre/post D2.A |
| **`a4/standalone/tests/test_d2a_arm_shape_arguzz_simulation.py` (new in v0.2 — addresses Ivan's "when do all 5 fields get tested?" concern)** | **Scheduler-level synthetic test, no real fuzzer.** Constructs a `SemanticArmUniverse` with hand-built arms: 5 A4-surface arms (`A4_trace_cell, INSTR_WORD_MOD_SUR/COMP_OUT_MOD/..., zone, "n/a", "n/a"`) + 5 Arguzz-surface arms (`arguzz_exec_fault, INSTR_WORD_MOD/PRE_EXEC_MEM_MOD/BR_NEG_COND/..., zone, "arithmetic"/"memory_load"/"branch", "pre_exec"/"post_exec"`). Runs `ConstrainedTSScheduler.select()` for N=200 with `applied_accounting_mode=True`, simulates feedback via `update_with_outcome(arm, outcome)` where mock fuzzer returns `APPLIED` for A4 arms and `SKIPPED` 30% / `APPLIED` 70% for Arguzz arms. Asserts: (a) all 10 arms reach cold-start completion; (b) total `pulls` per Arguzz arm == APPLIED count (not selection count); (c) `arm_id` string is V5-format (2 pipes) for A4 arms and full-5 (4 pipes) for Arguzz arms; (d) floor schedule progression depends only on APPLIED pulls in applied-accounting mode; (e) beta posterior updates correctly for both surfaces under mixed outcome streams |
| `a4/standalone/tests/test_d2a_applied_accounting.py` | Synthetic mock surface: scheduler in `applied_accounting_mode=True`, fuzzer reports `SKIPPED` for 30% of selections, `APPLIED` for the rest. Assert `total_pulls == APPLIED_count`; epoch state advances only on APPLIED; back-compat mode (`applied_accounting_mode=False`) counts SKIPPED as `update(arm, 0)` |
| `a4/standalone/tests/test_d2a_normalize_parity.py` | Run V5 selector N=20 against an in-tree minimal smoke binary if available; OR (offline-only path): synthetic ConstraintFailure with both A4 and V6 raw loc formats fed through `short_loc()` produces identical canonical strings. Assert DB's `coverage.constraint_loc` column contains only `Name@basename:line` form (no parentheses, no full paths) |
| `a4/standalone/tests/test_d2a_outcome_column.py` | Run V5 selector N=10 against the minimal smoke binary (if available) OR a synthetic fuzzer harness. Assert every row has a non-NULL `mutations.outcome` value and the value is one of `{"applied", "skipped", "error"}` |

### 4.7 Files that **must not change** in D2.A

For clarity (will be enforced via golden trace test):

- `a4/standalone/semantic_zones.py` (zones unchanged)
- `a4/standalone/zone_classifier.py` (step → zone unchanged)
- `a4/standalone/reward_v2.py`, `coverage_state.py` (reward unchanged)
- `a4/standalone/mutations/*` (no new kinds in D2.A)
- `a4/standalone/cli.py` (no new flags in D2.A)
- `a4/arguzz_dependent/*` (untouched — addressed in D2.C)

## 5. Decision matrix (what changes for whom)

| Component | V5 selector (`cTS_semantic_v2*`) | New variants (`v6_cTS`, `hybrid_cTS`, etc.) — wired in D2.D |
|---|---|---|
| Arm shape | `ArmKey.v5(kind, zone)` — surface="A4_trace_cell", opcode_class="n/a", pre_post="n/a" | Full 5-tuple with real opcode_class + pre_post when known |
| `arm_id` string | `"kind\|zone"` (V5 legacy format) | `"surface\|kind\|zone\|opcode\|pre_post"` (new format) |
| Applied accounting | OFF (skip → `update(arm, 0)`, current V5 behavior) | ON (skip → `update_with_outcome(arm, SKIPPED)` → no state advance, re-pick) |
| `mutations.outcome` column | Populated (APPLIED / SKIPPED / ERROR) — diagnostic only, doesn't change scheduler | Populated and authoritative for scheduler |
| RNG sequence | **Identical** to pre-D2.A V5 (golden trace gate) | New variants — no back-compat target |

## 6. Open questions (D2.A-specific) — ALL RESOLVED 2026-06-16

> Ivan reviewed the recommendations on 2026-06-16 and accepted all 11 ("i read your 11 questions, and agree with your recommendations"). See §8 for the locked resolution table; this section is kept as the rationale record.

| # | Question | My recommendation | Why I'm asking, not deciding |
|---|---|---|---|
| **Q1** | **`ArmKey` shape — dataclass vs `Tuple[str, ...]`** | `@dataclass(frozen=True)` with 5 string fields. Slightly less Pythonic-tuply, but `arm.kind` is much clearer than `arm[1]` in call sites and survives field additions better | Either works; dataclass is the cleaner long-term path but tuple is the smaller refactor |
| **Q2** | **"n/a" sentinel vs `None` for unused arm-key fields** | String `"n/a"` everywhere. Makes `arm_id` always stringifiable and DB-clean; avoids `None`-handling in 6 dict-key sites | `None` is more idiomatic Python but introduces `Optional` plumbing into every site that builds an `arm_id` string |
| **Q3** | **Applied-accounting mode default in `ConstrainedTSScheduler.__init__`** | `False` (matches V5 today). The fuzzer / CLI layer flips it on for new variants only | The alternative is "default `True`, V5 selector explicitly passes `False`" — same logic, just inverted default. I picked the option that requires fewer V5 call-site changes |
| **Q4** | **`MutationOutcome` granularity** — 3 values (`APPLIED`/`SKIPPED`/`ERROR`) vs 5 (`APPLIED`/`SKIPPED_NO_TARGET`/`SKIPPED_NOT_APPLICABLE`/`EXECUTION_ERROR`/`CRASH`) | 3 values in D2.A; refine in D2.C if Arguzz needs the distinction | 5 values forces the fuzzer to classify more carefully; D2.C will tell us what's actually needed for V6 |
| **Q5** | **Should V5 also adopt applied-accounting?** | **No.** V5's skip rate is ~1–2%; adopting applied-accounting would change V5 RNG sequence and break archive-reuse for D2 paired comparisons. Keep V5 unchanged | Argument FOR: cleanest semantics for everything. Argument AGAINST (my pick): archive-reuse loss + V5 results in Pro's hands are interpreted with current accounting; changing semantics now muddies comparison |
| **Q6** | **Where does `outcome` classification happen?** Option (a): inside `record_mutation` (DB layer infers from `verifier_accepted`/`crashed`/`config is None`). Option (b): explicit `outcome=` arg from the fuzzer | **(b) — explicit from fuzzer.** The fuzzer has more context (knows about retry loop, ValueGeneratorExhausted, etc.); DB-layer inference would be guessing | (a) is fewer call-site edits but loses information |
| **Q7** | **opcode_class for A4 trace-cell arms** | `"n/a"` in v1. Some A4 mutations target instruction-related cycles where `cycle.major` IS an opcode class — but using it would inflate V5 arm space ×8 and breaks V5 back-compat | If Ivan wants opcode_class-aware A4 arms eventually (e.g., for D2.B's pure-A4 expansion kinds), this is a future-spec decision |
| **Q8** | **`pre_post` for A4 trace-cell arms** | Same: `"n/a"` in v1. A4 kinds are technically split (e.g., COMP_OUT_MOD is post-execution, PRE_EXEC_REG_MOD is pre-execution) but threading this through requires a per-kind classification table not currently in the codebase | Defer to D2.B/D2.D if the new pure-A4 kinds make pre_post natural |
| **Q9** | **V5 archive reuse contract** — does D2 paired analysis treat the R2 V5 archive (`a4/runs/iv_pos_7/dbs/`) as the V5 reference, or do we re-run V5 under D2.A code | **Reuse R2 archive.** Golden trace test gates this — if it passes, V5 RNG sequence is identical, so archive results are valid baselines. **Falls back to fresh run only if golden trace fails** | Saves 10 jobs (~3 h on POS). Decision recorded here so D2.F manifests can be written with this assumption |
| **Q10** | **Where does the test for "outcome column is populated" run?** Without a working risc0-host binary it can't actually fuzz | Use a **synthetic fuzzer harness** (mock `run_a4_mutation` to return canned `MutationExecutionResult`s with controlled outcomes). Faster + deterministic. Keep an optional real-binary test for nightly | Real-binary integration test takes ~30 s per mutation; not blocking-cycle friendly |
| **Q11** | **Composer batch granularity for D2.A** — one big batch, or split (Batch 1 = arm-shape; Batch 2 = applied accounting; Batch 3 = outcome + tests)? | **Two batches.** Batch 1: arm-shape refactor + golden trace test (largest, riskiest). Batch 2: `MutationOutcome` enum + `outcome` column + applied-accounting plumbing + remaining tests + normalize verification. This gives us one mid-D2.A review checkpoint, same pattern as D1.A | One big batch is faster but loses the safety net |

## 7. Composer task breakdown (proposed)

Pending §6 lock-in; not started.

### Batch 1 — Arm-shape refactor + golden trace + Arguzz-shape scheduler simulation

**Goal:** make the codebase use the new 5-field `ArmKey` end-to-end, with V5 RNG sequence byte-identical AND scheduler correctness validated on the FULL 5-tuple shape (Arguzz-style arms) at the unit level. This is what closes Ivan's "we don't validate the new arm fields until D2.D" concern: by end of Batch 1, the scheduler has been exercised with `surface="arguzz_exec_fault"` + real opcode_class + real pre_post, just under a mock dispatcher.

| Task | File(s) | Notes |
|---|---|---|
| 1.1 | Promote `ArmKey` to dataclass with `as_tuple()` and `__str__` | `a4/standalone/semantic_arm_universe.py` | Add `.v5(kind, zone)` factory, `.parse(arm_id)` inverse |
| 1.2 | Update `ConstrainedTSScheduler` to use new `ArmKey` for all internal dicts | `a4/standalone/bandit_ts.py` | Keep `update(kind, zone, success)` overload for V5 path |
| 1.3 | Verify all 4 `_run_*_mutation` call sites in fuzzer still produce identical bandit_decisions strings under V5 | `a4/standalone/fuzzer.py` | No code changes needed if 1.2 honors back-compat overload |
| 1.4 | Write golden-trace test (seed=42, N=200, V5 selector, identical DB content pre/post) | `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` | Compares `mutations.config_json`, `bandit_decisions.selected_arm`, `coverage.constraint_loc`, `mutation_rewards.*` |
| 1.5 | Write arm-shape unit tests | `a4/standalone/tests/test_d2a_arm_shape.py` | Pure unit, no fuzzer involved |
| **1.6 (new in v0.2)** | Write Arguzz-shape scheduler simulation test | `a4/standalone/tests/test_d2a_arm_shape_arguzz_simulation.py` | Pure scheduler unit test; constructs 10 mixed-surface arms with non-trivial opcode_class + pre_post; mock outcome stream feeds `update_with_outcome`. Note this test depends on `applied_accounting_mode` + `update_with_outcome` from Batch 2 — so this task moves to **Batch 2** OR the bare bones of `update_with_outcome` are added in Batch 1. **Recommended: Composer adds `MutationOutcome` enum + `update_with_outcome` skeleton in Batch 1 (pure scaffolding, no fuzzer integration) and the synthetic test runs in Batch 1. Full applied-accounting plumbing (fuzzer side + outcome column) still happens in Batch 2.** |
| 1.7 | Run full existing test suite (`pytest a4/standalone/tests/ -q`) | — | All 494 D1.A-era tests still green |

**Pass criteria for Batch 1:** all six pre-D2.A test files in `a4/standalone/tests/` plus the 3 new D2.A-Batch-1 test files green; golden-trace test passes byte-identical on V5; Arguzz-shape scheduler simulation passes with 10 mixed-surface arms; full pytest sweep green.

**Scope adjustment (v0.2):** task 1.6 brings `MutationOutcome` enum + skeleton `update_with_outcome` into Batch 1 as scaffolding-only (no fuzzer call-site changes, no DB column yet). This lets the synthetic test run in Batch 1 and surfaces any scheduler-state correctness issues before Batch 2 wires applied-accounting into the real fuzzer + DB. Batch 2's scope drops the enum task (now done in 1.6) but otherwise stays identical.

### Batch 2 — Applied accounting + outcome column + normalize verification

**Goal:** add `MutationOutcome`, `applied_accounting_mode`, the new `mutations.outcome` column, and the normalize-parity test gate.

| Task | File(s) | Notes |
|---|---|---|
| 2.1 | Add `MutationOutcome` enum to `bandit_ts.py` | `a4/standalone/bandit_ts.py` | Re-exported from `a4.standalone.fuzzer` for convenience |
| 2.2 | Add `applied_accounting_mode` to `ConstrainedTSScheduler.__init__` (default `False`) + `update_with_outcome(arm, outcome, success)` method | `a4/standalone/bandit_ts.py` | Internal: if mode is `True` and outcome is `SKIPPED`, return without updating pulls/epoch state |
| 2.3 | Add `outcome TEXT` column to mutations table + `idx_mutations_outcome` index | `a4/standalone/coverage_db.py` | Mirrors D1.A's column-add pattern at line 119 |
| 2.4 | Extend `record_mutation(..., outcome=None)` signature; update all 4 call sites in `fuzzer.py` | `a4/standalone/coverage_db.py`, `a4/standalone/fuzzer.py` | Via the existing `_mutation_record_kwargs` helper; add `_outcome_for(result)` |
| 2.5 | Add docstring deprecation note to `constraint_loc_normalize.py` | `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py` | Pure docstring change; no behavior change |
| 2.6 | Write applied-accounting unit test | `a4/standalone/tests/test_d2a_applied_accounting.py` | Synthetic harness, no real fuzzer |
| 2.7 | Write outcome-column test | `a4/standalone/tests/test_d2a_outcome_column.py` | Synthetic harness; assert outcome ∈ {applied, skipped, error} |
| 2.8 | Write normalize-parity test | `a4/standalone/tests/test_d2a_normalize_parity.py` | Synthetic ConstraintFailure with both A4 + V6 raw `.loc` strings; assert canonical form matches |
| 2.9 | Run full existing test suite | — | 494 + Batch 1's 2 + Batch 2's 3 = 499 tests green |

**Pass criteria for Batch 2:** all new tests green; full pytest sweep green; manual `sqlite3` check on a 20-mutation smoke DB shows `outcome` column populated and `coverage.constraint_loc` in `Name@basename:line` form.

## 8. Decisions Confirmed

Resolved 2026-06-16 by Ivan ("i read your 11 questions, and agree with your recommendations").

| # | Question | Resolution | Resolved on |
|---|---|---|---|
| Q1 | `ArmKey` shape | **`@dataclass(frozen=True)` with 5 string fields** `(surface, kind, zone, opcode_class, pre_post)`. Tuple-like, hashable, with named field access. | 2026-06-16 |
| Q2 | Sentinel for unused fields | **String `"n/a"`** everywhere a field doesn't apply for v1. No `None`. | 2026-06-16 |
| Q3 | `applied_accounting_mode` default | **`False`** in `ConstrainedTSScheduler.__init__`. V5 selector unchanged; new variants flip it to `True` when they wire up in D2.D. | 2026-06-16 |
| Q4 | `MutationOutcome` granularity | **3 values: `APPLIED` / `SKIPPED` / `ERROR`** in D2.A. Refine in D2.C if Arguzz needs finer distinction. | 2026-06-16 |
| Q5 | V5 adopts applied-accounting? | **No.** V5 stays on current "skip counts as 0-reward pull" semantics. Preserves V5 archive reuse + RNG byte-identity. | 2026-06-16 |
| Q6 | Where `outcome` classification happens | **Explicit `outcome=` kwarg from fuzzer to `record_mutation`.** Fuzzer has the full context (retry loop, ValueGeneratorExhausted, crash flag). DB layer does not infer. | 2026-06-16 |
| Q7 | `opcode_class` for A4 arms | **`"n/a"` in v1.** D2.B's pure-A4 expansion kinds (`TXN_PREV_WORD_MOD`, etc.) also keep `"n/a"`. Future-Pro-spec decision if we want opcode-aware A4 arms. | 2026-06-16 |
| Q8 | `pre_post` for A4 arms | **`"n/a"` in v1.** Same rationale as Q7. | 2026-06-16 |
| Q9 | V5 archive reuse for D2 | **Reuse R2 V5 archive** (10 seeds × N=6000 from D1.A static archive) — gated on the Batch 1 golden-trace test passing byte-identical. Fall back to fresh V5 re-run **only if** golden trace fails. Saves 10 jobs / ~3 h POS wall. | 2026-06-16 |
| Q10 | Where the outcome-column test runs | **Synthetic fuzzer harness** (mock `run_a4_mutation` to return canned `MutationExecutionResult`s with controlled outcomes). Deterministic, fast, doesn't need a working risc0-host binary on the dev box. Optional real-binary integration in nightly later. | 2026-06-16 |
| Q11 | Composer batch granularity | **Two batches.** Batch 1 = arm-shape refactor + golden trace + Arguzz-shape scheduler simulation + `MutationOutcome` enum skeleton. Batch 2 = applied-accounting plumbing + `outcome` column + remaining tests + normalize verification + docstring deprecation. Mid-D2.A review checkpoint between them. | 2026-06-16 |

### Cross-cutting decision (also locked 2026-06-16)

| Topic | Resolution | Rationale |
|---|---|---|
| **Branch flexibility (Ivan note: "we are in a new branch so we can overwrite old code")** | **Keep the back-compat overload** `update(kind, zone, success)` in `ConstrainedTSScheduler` and the V5-legacy `arm_id` string format. The back-compat surface is ~5 lines of code (one helper method + one conditional in `arm_id_for_decision`); the safety net it preserves (V5 RNG byte-identity + R2 V5 archive reuse) is large. Hard-break is offered as a fallback **only if** the Batch 1 golden-trace test reveals an unfixable dict-iteration-order divergence (extremely unlikely — dict iteration is insertion-ordered in CPython 3.7+ and our `SemanticArmUniverse` build order is stable). | Smaller code change, larger archive-reuse and ground-truth-tested-baseline payoff. |

## 9. Risks + mitigations

| Risk | Mitigation |
|---|---|
| Arm-shape refactor breaks V5 RNG sequence subtly (e.g., dict iteration order over `ArmKey` differs from tuple-keyed dict) | Golden trace test (Batch 1 task 1.4) catches this on the first byte mismatch |
| `update(kind, zone, success)` back-compat overload silently dispatches to a different code path than `update_with_outcome` | Unit test asserts both paths advance the same scheduler state under matching inputs |
| `outcome` column is null for legacy DBs being re-opened under D2.A code | Acceptable — `outcome IS NULL` means "pre-D2.A campaign"; analysis filters by this |
| The new `MutationOutcome.ERROR` classification overlaps with current `crashed` field on `MutationResult` | `_outcome_for(result)` defined in §4.3 row 5 is the single source of truth; both `outcome` (text) and `crashed` (bool) live in `mutations`, are consistent by construction |
| Composer touches `arguzz_dependent/` during refactor by accident | Spec §4.7 explicitly lists it as out-of-scope; Composer batch instruction will reiterate |

## 10. What ships at the end of D2.A

- Two PRs (Batch 1 and Batch 2), both squash-mergeable to `cloud2`
- Two Composer reports (one per batch)
- ~500 tests green on `cloud2` (vs 494 today)
- Schema migration applied (DB will accept the new `outcome` column on next open)
- One updated planning doc: `IV_POS_8_D2_PLAN.md` decision-table entry "D2.A → done"
- This spec annotated with "Decisions Confirmed" (§8) and per-batch retrospective notes

---

*End of D2.A spec v0.2. Locked — all §6 decisions resolved in §8. Ready for Composer Batch 1 kickoff doc (next deliverable from Opus).*
