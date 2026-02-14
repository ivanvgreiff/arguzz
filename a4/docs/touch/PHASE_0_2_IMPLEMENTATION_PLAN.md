# Phase 0.2 Detailed Implementation Plan

This document is the **step-by-step, source-code-fact-based** plan for implementing Phase 0.2 (Baseline + Measurements) to complete Phase 0. It is consistent with `PHASE_I_IMPLEMENTATION_PLAN.md` §0.1, §2.4–2.5 and the Phase 0.2 checklist in `PHASE_0_1_IMPLEMENTATION_PLAN.md`.

**Scope**: Run the Phase 0.1 determinism test in the target environment; run a baseline (unmutated) guest and confirm zero constraint failures; run a short fuzzing campaign and measure distinct `context_id()` (constraint_loc, major, minor) per run and total; document whether step_bucket is needed for Phase 3; optionally run a minimal-program sanity check and optionally persist a baseline touch set for Phase 3.

**Preconditions**: Phase 0.1 is complete (canonical IDs, `context_id()`, determinism test, touch-accuracy note). A4-patched RISC Zero host built in release mode; same host and guest as used for Phase 0.1 determinism test (or documented equivalent).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Source-of-Truth Facts for Phase 0.2

### 1.1 Running the host without mutation (baseline)

| Fact | Location |
|------|----------|
| Mutation is triggered only when `A4_MUTATION_CONFIG` is set | `a4/core/executor.py` lines 159–161: `run_a4_mutation` sets `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`; the host binary reads `A4_MUTATION_CONFIG` in Rust (`mod.rs`). |
| Without `A4_MUTATION_CONFIG`, the host runs the guest and proves with no preflight mutation | RISC Zero flow: preflight runs, no mutation block applied, witness is valid; `<constraint_fail>` is only printed when `eqz(ctx, val, loc)` is called with `a.asUInt32()` non-zero (`witgen.h` lines 178–180). So valid witness → no constraint failures → no `<constraint_fail>` lines. |
| To run “baseline”: invoke host with same host_args, **no** `A4_MUTATION_CONFIG`, **no** `CONSTRAINT_CONTINUE` | So: `subprocess.run([host_binary] + host_args, capture_output=True, text=True, env=os.environ)` (or env that does not add A4_MUTATION_CONFIG/CONSTRAINT_CONTINUE). |

### 1.2 Running a short campaign and collecting failures

| Fact | Location |
|------|----------|
| Fuzzer runs N mutations and records each in the DB | `a4/standalone/fuzzer.py`: `run_campaign(num_mutations)` loops `_run_single_mutation`, which calls `run_a4_mutation`, then `db.record_mutation` and `db.record_failures(mutation_id, failures)`. |
| Each mutation’s failures are stored in `failures` with (constraint_loc, major, minor) | `a4/standalone/coverage_db.py` lines 111–127: table `failures` has `mutation_id`, `constraint_type`, `constraint_loc`, `cycle`, `step`, `pc`, `major`, `minor`, `value`, `full_loc`. So distinct `context_id()` = distinct `(constraint_loc, major, minor)`. |
| Mutations are linked to campaign via `mutations.campaign_id` | `coverage_db.py` lines 92–107: `mutations(campaign_id, ...)`; `failures(mutation_id, ...)`. So for a given campaign we can query all failures via `failures f JOIN mutations m ON f.mutation_id = m.id WHERE m.campaign_id = ?`. |
| Campaign is started with `start_campaign(host_binary, host_args, kind, seed)` and ended with `end_campaign(campaign_id)` | `coverage_db.py` lines 209–236, 187–196. |

### 1.3 Computing distinct context_id from the DB

| Fact | Location |
|------|----------|
| `failures` has `constraint_loc`, `major`, `minor` | So `SELECT DISTINCT constraint_loc, major, minor FROM failures f JOIN mutations m ON f.mutation_id = m.id WHERE m.campaign_id = ?` gives the set of context_ids for the campaign. Count = number of distinct context_ids. |
| Per-run distinct count: same query restricted to one `mutation_id` | `SELECT DISTINCT constraint_loc, major, minor FROM failures WHERE mutation_id = ?` for each mutation in the campaign. |

### 1.4 Collision formula (bucket necessity)

From PHASE_I_IMPLEMENTATION_PLAN.md §0.1: with K distinct keys and MAP_SIZE = 65536, expected collisions ≈ K² / (2 × MAP_SIZE). If K < ~20k, a 64k bitmap has acceptable collision rate without step_bucket.

---

## 2. Step-by-Step Implementation Plan

### Step 0.2.1: Re-run Phase 0.1 determinism test in target environment

**Goal**: Confirm that the same host and guest still produce identical failure sets for the same config in the environment where Phase 0.2 will run (same machine, same host binary, same args).

**Facts**: The determinism test is implemented in `a4/standalone/tests/test_determinism.py`; it is skipped unless `A4_TEST_HOST` is set; it runs `run_a4_mutation` twice with the same config and compares sets of `context_id()` and `signature()`.

**Actions**:
1. Set `A4_TEST_HOST` and `A4_TEST_HOST_ARGS` to the host binary and args that will be used for the Phase 0.2 baseline and campaign (e.g. same as README examples).
2. Run: `A4_TEST_HOST=<path> A4_TEST_HOST_ARGS="<args>" python -m pytest a4/standalone/tests/test_determinism.py -v`.
3. Assert both tests pass. If they fail, fix non-determinism or environment before proceeding (e.g. host must be release build; no ASLR or thread-scheduling effects; A4 forces SeqForward when `A4_MUTATION_CONFIG` is set per `hal/mod.rs`).
4. Document in the Phase 0.2 report: host path, host args, and that the determinism test passed.

**Deliverable**: Determinism test passed in the Phase 0.2 environment; one-line note in report.

---

### Step 0.2.2: Baseline run (unmutated guest, zero constraint failures)

**Goal**: Run the host **without** any mutation config and confirm that output contains **no** `<constraint_fail>` lines (valid proof path → no constraint failures).

**Facts**: When `A4_MUTATION_CONFIG` is not set, the Rust code does not apply mutations (`mod.rs` only enters the mutation block when `std::env::var("A4_MUTATION_CONFIG")` is `Ok`). The host runs the guest and builds the witness; if the trace is valid, all constraints pass and `eqz` is never called with a non-zero value, so no `<constraint_fail>` is printed. Parsing with `parse_all_constraint_failures(output)` should return an empty list.

**Actions**:
1. Add a small function or script that runs the host **without** `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`. Use the same `host_binary` and `host_args` as the fuzzer. Example signature: `run_baseline(host_binary: str, host_args: List[str]) -> str` that runs `subprocess.run([host_binary] + host_args, capture_output=True, text=True, env=os.environ)` (or `env` that does not add A4_* or CONSTRAINT_CONTINUE) and returns `result.stdout + result.stderr`.
2. Call `parse_all_constraint_failures(output)` on the returned output.
3. Assert `len(failures) == 0`. If not, document the failure (e.g. unexpected constraint failure in valid run).
4. **Placement**: Implement in a small script under `a4/standalone/tests/` (e.g. `test_phase02_baseline.py`) or as a helper in a Phase 0.2 script module; alternatively add a single test in `test_determinism.py` that is skipped unless `A4_TEST_HOST` is set and that runs baseline and asserts zero failures. Prefer a dedicated script or test so it is runnable and repeatable.

**Deliverable**: Baseline run implemented and executed; output has zero `<constraint_fail>` entries; documented in report.

---

### Step 0.2.3: Short campaign and distinct context_id measurement

**Goal**: Run a short fuzzing campaign (e.g. 50–100 mutations), then compute (1) distinct `context_id()` per mutation run and (2) total distinct `context_id()` over the campaign. Use the results to decide whether step_bucket is needed for Phase 3 (PHASE_I_IMPLEMENTATION_PLAN.md §0.1).

**Facts**:
- Campaign: use existing `A4Fuzzer` in `a4/standalone/fuzzer.py`. `run_campaign(num_mutations)` requires `host_binary`, `host_args`, `db_path`, and optionally `kind`, `seed`, etc. The fuzzer records every mutation and its failures in the DB via `record_mutation` and `record_failures` (lines 356–366).
- The `failures` table stores `constraint_loc`, `major`, `minor` per failure (`coverage_db.py` lines 260–267). So `(constraint_loc, major, minor)` = `context_id()` for that failure.
- No new DB schema is required. We only need a query (or a small method on `CoverageDB`) to compute distinct (constraint_loc, major, minor) for a campaign and per mutation.

**Actions**:
1. **Add a query or method to compute distinct context_id counts** (optional but recommended for reuse):
   - In `a4/standalone/coverage_db.py`, add e.g. `get_distinct_context_ids_for_campaign(self, campaign_id: int) -> Set[Tuple[str, int, int]]` that executes `SELECT DISTINCT constraint_loc, major, minor FROM failures f JOIN mutations m ON f.mutation_id = m.id WHERE m.campaign_id = ?` and returns a set of `(constraint_loc, major, minor)`.
   - Optionally add `get_distinct_context_ids_per_mutation(self, campaign_id: int) -> List[Tuple[int, int]]` returning `[(mutation_id, count)]` by iterating mutations in the campaign and for each running `SELECT COUNT(DISTINCT constraint_loc || '|' || major || '|' || minor) FROM failures WHERE mutation_id = ?` (or `SELECT DISTINCT constraint_loc, major, minor` and len of set). SQLite does not have a tuple distinct count; so either `SELECT DISTINCT constraint_loc, major, minor FROM failures WHERE mutation_id = ?` and count rows, or use a single compound key. Simpler: for each mutation_id, `cursor.execute("SELECT constraint_loc, major, minor FROM failures WHERE mutation_id = ?", (mid,))` and build `len(set((r[0], r[1], r[2]) for r in cursor.fetchall()))`.
   - Alternatively implement this in a standalone Phase 0.2 script that opens the DB and runs the same SQL without modifying `CoverageDB`. Either way, the implementation must use the existing `failures` and `mutations` schema only.
2. **Run a short campaign**:
   - Use CLI: `python -m a4.standalone.cli fuzz --host <path> --num 50 --kind all --seed 42 -- --in1 5 --in4 10` (or equivalent host args). This will create a new campaign and write to the default DB (`a4_coverage.db`) or a DB specified by `--db`.
   - Or from Python: instantiate `A4Fuzzer(host_binary=..., host_args=..., db_path=..., kind="all", seed=42)`, call `fuzzer.run_campaign(50)`.
3. **Compute and record**:
   - Total distinct context_id for the campaign: `K_total = len(get_distinct_context_ids_for_campaign(campaign_id))`.
   - Per-mutation distinct counts: for each mutation in the campaign, number of distinct (constraint_loc, major, minor) for that mutation; report min, max, mean (or histogram).
4. **Document in report**:
   - Campaign parameters (host, args, num_mutations, kind, seed, db path).
   - K_total and per-run stats (min/max/mean distinct context_id per run).
   - Whether K_total (and typical per-run K) is below ~20k: if yes, state that step_bucket is **not** required for Phase 3 bitmap (MAP_SIZE=65536). If K_total or per-run K is high, state that step_bucket may be needed or MAP_SIZE increased, and cite the collision formula K²/(2*MAP_SIZE).

**Deliverable**: Short campaign run; distinct context_id counts (total and per run) computed and documented; bucket-necessity note written (and optionally added to PHASE_I_IMPLEMENTATION_PLAN.md §0.1 or a short Phase 0.2 doc).

---

### Step 0.2.4: Optional — minimal-program sanity check

**Goal**: Run a minimal guest (e.g. one that only executes a single instruction type such as ADD) with one mutation and verify that the failure set only contains constraints that are plausible for that path (e.g. no DIV-only or ECALL-only constraints if the program does not use DIV/ECALL).

**Facts**: PHASE_I_IMPLEMENTATION_PLAN.md §0.2 suggests this as an optional check to confirm that “touched”/failure sets are semantically plausible. Without touch instrumentation we can only check **failure** set. A minimal guest would require a separate guest program (or a way to run a single instruction); the current default guest (e.g. the one invoked with `--in1 5 --in4 10`) may already exercise many instruction types. So this step is optional and may be skipped if no minimal guest is readily available.

**Actions** (if implemented):
1. Identify or build a minimal guest that only uses one instruction family (e.g. ALU only) or document that the check is deferred.
2. Run one mutation (e.g. COMP_OUT_MOD at a step that is known to be that instruction), parse failures, and check that all `constraint_loc` / major/minor are consistent with that path (e.g. no major=4 DIV if the program has no DIV). This can be a manual check or a short script that loads a set of “allowed” constraint names or (major, minor) for the minimal guest and asserts all failures fall in that set.
3. Document result in Phase 0.2 report.

**Deliverable**: Optional; if done, one paragraph in report with result.

---

### Step 0.2.5: Optional — persist baseline “expected touch set” for Phase 3

**Goal**: After Phase 3 touch instrumentation is added, we may want to compare the touch set from an unmutated run to a baseline. Phase 0.2 cannot produce touch sets yet (no instrumentation). We can still persist the fact that “baseline run had zero failures” and, optionally, a placeholder or note that “Phase 3 baseline touch set should be captured once instrumentation exists.”

**Facts**: No touch data exists until Phase 3. The only concrete output from Phase 0.2 baseline is “zero constraint failures.”

**Actions** (if implemented):
1. Add a short note or one-line in docs/touch or in the Phase 0.2 report: “Phase 3 should capture the touch set from an unmutated run (same host/args as baseline) and persist it for comparison.”
2. No code change required for Phase 0.2 beyond the baseline run of Step 0.2.2.

**Deliverable**: Optional; if done, one sentence in report or in a Phase 3 prep doc.

---

## 3. Implementation Order and Dependencies

1. **Step 0.2.1** (determinism test): No new code; run existing test. Do first to confirm environment.
2. **Step 0.2.2** (baseline run): Implement `run_baseline` (or equivalent) and assertion; run and document.
3. **Step 0.2.3** (campaign + measurement): Add DB query/helper for distinct context_id; run short campaign; compute and document counts and bucket-necessity.
4. **Step 0.2.4** (minimal-program): Optional; implement only if minimal guest is available and time permits.
5. **Step 0.2.5** (persist baseline touch note): Optional; one-line note for Phase 3.

---

## 4. Files to Touch (Summary)

| Area | Files |
|------|--------|
| Baseline run | New: `a4/standalone/tests/test_phase02_baseline.py` or similar; or add to existing test file. Uses `subprocess` + `parse_all_constraint_failures`; no `A4_MUTATION_CONFIG`. |
| Distinct context_id | `a4/standalone/coverage_db.py`: optional `get_distinct_context_ids_for_campaign`, and optionally per-mutation helper. Or standalone script that queries the same DB. |
| Campaign run | Use existing `a4/standalone/cli.py` and `fuzzer.py`; no change required except to run with fixed seed and known DB path so the measurement script can open the same DB. |
| Documentation | Phase 0.2 report (new: `PHASE_0_2_IMPLEMENTATION_REPORT.md` or section in a single “Phase 0 report”); optionally one sentence in PHASE_I_IMPLEMENTATION_PLAN.md §0.1 with the measured K and “step_bucket not required” or “consider step_bucket if K > X”. |

---

## 5. Phase 0.2 Completion Checklist

- [ ] Step 0.2.1: Determinism test re-run in target environment; passed; documented.
- [ ] Step 0.2.2: Baseline run (no A4_MUTATION_CONFIG); zero `<constraint_fail>`; documented.
- [ ] Step 0.2.3: Short campaign (e.g. 50–100 mutations) run; distinct context_id total and per-run computed; bucket-necessity documented.
- [ ] Step 0.2.4 (optional): Minimal-program sanity check, if applicable.
- [ ] Step 0.2.5 (optional): Note for Phase 3 baseline touch set.
- [ ] Phase 0.2 implementation report written (host/args, baseline result, campaign params, K_total and per-run stats, bucket decision, any deviations).

---

## 6. Alignment with Phase 0 and Phase I

- **Phase 0.1**: Delivered stable IDs, `context_id()`, determinism test, touch-accuracy note. Phase 0.2 uses the same IDs and the same test; it does not change Phase 0.1 code.
- **PHASE_I_IMPLEMENTATION_PLAN.md §0.1**: Phase 0.2 performs the “measure distinct (constraint_loc, major, minor) per run and total” and “document bucket necessity” that §0.1 defers to Phase 0.2.
- **Phase 0.2 checklist in PHASE_0_1_IMPLEMENTATION_PLAN.md**: All items (determinism re-run, baseline, short campaign + measurement, optional minimal-program, optional persist baseline) are covered above. Phase 0 is complete once this plan is implemented and the report is written.
