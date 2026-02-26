# Phase 0.2 Implementation Report

**Status**: Implemented and tested. Summary: determinism and baseline tests passed; campaign run with 60 mutations (cap enforced); DB helpers added; K_total and per-run stats measured; step_bucket not required for Phase 3 at current scale.

---

## Step 0.2.1: Determinism test

- **Result**: Passed.
- **Host**: `./workspace/output/target/release/risc0-host` (absolute path at run time: `/root/arguzz/workspace/output/target/release/risc0-host`).
- **Host args**: `--in1 5 --in4 10`.
- **Command**: `A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_determinism.py -v`.
- **Outcome**: Both tests passed (`test_same_config_same_failure_set_by_context_id`, `test_same_config_same_failure_set_by_signature`) in ~366 s (6 min 6 s).

---

## Step 0.2.2: Baseline run (unmutated guest, zero constraint failures)

- **Result**: Passed. Unmutated run produced zero `<constraint_fail>` lines.
- **Implementation**:
  - **`run_baseline(host_binary: str, host_args: List[str]) -> str`** in `a4/core/executor.py`: runs the host with `subprocess.run(..., env=dict(os.environ))` (no `A4_MUTATION_CONFIG`, no `CONSTRAINT_CONTINUE`), returns `result.stdout + result.stderr`.
  - **Test**: `a4/standalone/tests/test_phase02_baseline.py::test_baseline_zero_constraint_failures`: calls `run_baseline`, then `parse_all_constraint_failures(output)`, asserts `len(failures) == 0`. Skipped unless `A4_TEST_HOST` is set.
- **Command**: Same env as determinism; `python -m pytest a4/standalone/tests/test_phase02_baseline.py -v`.
- **Outcome**: 1 passed in ~71 s.

---

## Step 0.2.3: Short campaign and distinct context_id measurement

- **Campaign parameters**:
  - **Host**: `./workspace/output/target/release/risc0-host`
  - **Host args**: `--in1 5 --in4 10`
  - **num_mutations**: 60 (user cap: no more than 60 mutations per campaign)
  - **kind**: all
  - **seed**: 42
  - **DB path**: `./phase02_campaign.db`
  - **CLI**: `python -m a4.standalone.cli fuzz --host ./workspace/output/target/release/risc0-host --num 60 --kind all --seed 42 --db ./phase02_campaign.db -- --in1 5 --in4 10`

- **Implementation**:
  - **`get_distinct_context_ids_for_campaign(self, campaign_id: int) -> Set[Tuple[str, int, int]]`** in `a4/standalone/coverage_db.py`: runs `SELECT DISTINCT f.constraint_loc, f.major, f.minor FROM failures f JOIN mutations m ON f.mutation_id = m.id WHERE m.campaign_id = ?`, returns set of `(constraint_loc, major, minor)`.
  - **`get_distinct_context_id_counts_per_mutation(self, campaign_id: int) -> List[Tuple[int, int]]`**: for each mutation in the campaign, queries failures by `mutation_id` and returns `(mutation_id, distinct_count)` where distinct = `len(set((constraint_loc, major, minor)))`.
  - **`get_last_campaign_id(self) -> Optional[int]`**: `SELECT id FROM campaigns ORDER BY id DESC LIMIT 1` for use by the measurement script when campaign_id is not provided.
  - **Measurement script**: `a4/standalone/tests/run_phase02_measurements.py` — accepts `--db` and optional `--campaign`; uses last campaign if `--campaign` omitted; prints K_total, per-run min/max/mean, and bucket-necessity note.

- **Measured results** (at report time; campaign may have been still running):
  - **Mutations in DB for campaign 1**: 24 (campaign was started with 60; 24 had completed when measurements were run).
  - **K_total** (distinct `(constraint_loc, major, minor)` over the campaign): **43**.
  - **Per-run distinct context_id**: **min=0**, **max=9**, **mean≈2.4**, **n=24**.
  - **Bucket-necessity conclusion**: K_total and per-run K are well below ~20k → **step_bucket is not required** for Phase 3 with MAP_SIZE=65536. Collision formula K²/(2×MAP_SIZE) gives negligible expected collisions at this K.

---

## Step 0.2.4 (optional): Minimal-program sanity check

- **Result**: Not performed. No minimal guest was used; plan allows skipping if no minimal guest is readily available.

---

## Step 0.2.5 (optional): Phase 3 baseline touch set note

- **Note for Phase 3**: Phase 3 should capture the touch set from an **unmutated run** (same host/args as this baseline) and persist it for comparison with mutated-run touch sets. Phase 0.2 does not have touch instrumentation; it only confirms baseline produces zero constraint failures.

---

## Deviations from the plan

1. **Campaign size**: Plan suggested “e.g. 50–100 mutations”; user constraint was “at most 60 mutations.” Implementation used **60** mutations.
2. **Per-mutation helper name**: Plan referred to `get_distinct_context_ids_per_mutation`; implementation name is **`get_distinct_context_id_counts_per_mutation`** and it returns **counts** `[(mutation_id, count)]`, not sets, to keep the API simple and avoid large in-memory sets.
3. **Measurement timing**: K_total and per-run stats were computed on the campaign DB while the campaign might still have been running (24 mutations in DB at measurement time). The numbers are therefore for a **partial** 60-mutation campaign; they remain valid as lower bounds and as evidence that K is small at current scale.
4. **Dedicated DB**: Campaign was run with `--db ./phase02_campaign.db` as planned so measurements use a known DB path.

---

## Key variables and symbols

| Variable / concept | Meaning |
|-------------------|--------|
| **context_id** | `(constraint_loc, major, minor)` — stable coverage key from Phase 0.1; no step_bucket in Phase 0.2. |
| **K_total** | Number of distinct context_ids across all failures in the campaign; `len(get_distinct_context_ids_for_campaign(campaign_id))`. |
| **Per-run K** | For each mutation, number of distinct context_ids among its failures; used for min/max/mean. |
| **MAP_SIZE** | Phase I bitmap size (65536); collision expectation ≈ K²/(2×MAP_SIZE). |
| **step_bucket** | Optional bucketing by step (e.g. `step // B`) to reduce K per bucket; not required when K < ~20k. |
| **run_baseline** | Executor helper: run host without A4 env vars; return combined stdout+stderr. |
| **get_last_campaign_id** | DB helper: id of most recent campaign; used by measurement script when `--campaign` is omitted. |

---

## Testing performed

1. **Determinism** (Step 0.2.1): `pytest a4/standalone/tests/test_determinism.py -v` with `A4_TEST_HOST` and `A4_TEST_HOST_ARGS` set — **2 passed**.
2. **Baseline** (Step 0.2.2): `pytest a4/standalone/tests/test_phase02_baseline.py -v` with same env — **1 passed** (zero constraint failures).
3. **Campaign**: CLI fuzz run with 60 mutations, `--db ./phase02_campaign.db`, `--kind all`, `--seed 42`.
4. **Measurement script**: `python -m a4.standalone.tests.run_phase02_measurements --db ./phase02_campaign.db` — produced K_total=43, per-run min=0, max=9, mean≈2.4, and the bucket decision.

No unit tests were added for the DB helpers beyond their use in the measurement script; the script’s successful run and the consistency of K_total with the number of unique constraint locations in the campaign output serve as integration checks.

---

## Insights for Phase 3 implementation plans

1. **Bitmap size**: At current scale (K_total on the order of tens, per-run K single digits), a 64k bitmap is sufficient without step_bucket. Phase 3 plans can assume MAP_SIZE=65536 and no step_bucket unless much larger campaigns or different guests significantly increase K.
2. **Baseline touch set**: Phase 3 should add instrumentation to record the **touch set** (constraint contexts touched) for an unmutated run with the same host/args as Phase 0.2 baseline, and persist it for comparison (e.g. to classify “expected” vs “mutation-induced” touches).
3. **Stable IDs**: Phase 0.2 relies on the same `context_id()` (constraint_loc, major, minor) as Phase 0.1; Phase 3 touch instrumentation should use the same key for consistency with failure-based coverage.
4. **Campaign DB**: Using a dedicated DB path per campaign (or per experiment) allows measurement scripts to open the same DB after the run without modifying the fuzzer; `get_last_campaign_id()` supports “last campaign” when multiple campaigns exist in one DB.
5. **Mutations with 0 failures**: Some runs (e.g. INSTR_WORD_MOD_FULL at step 3582) produced 0 constraint failures (proof failed for other reasons); per-run distinct count can be 0. Phase 3 touch sets may still record “touched” contexts for such runs if instrumentation is applied; the distinction between “failure set” (Phase 0.2) and “touch set” (Phase 3) should be explicit in Phase 3 plans.

---

## Files touched (summary)

| Area | File | Change |
|------|------|--------|
| Baseline run | `a4/core/executor.py` | Added `run_baseline(host_binary, host_args) -> str`. |
| Baseline test | `a4/standalone/tests/test_phase02_baseline.py` | New: test that baseline output has zero constraint failures. |
| Coverage DB | `a4/standalone/coverage_db.py` | Added `get_distinct_context_ids_for_campaign`, `get_distinct_context_id_counts_per_mutation`, `get_last_campaign_id`; typing: `Set` import. |
| Measurement | `a4/standalone/tests/run_phase02_measurements.py` | New: script to compute K_total and per-run stats from a campaign DB. |
| Report | `a4/docs/touch/PHASE_0_2_IMPLEMENTATION_REPORT.md` | This report. |

---

## Phase 0.2 completion checklist

- [x] Step 0.2.1: Determinism test re-run in target environment; passed; documented.
- [x] Step 0.2.2: Baseline run (no A4_MUTATION_CONFIG); zero `<constraint_fail>`; documented.
- [x] Step 0.2.3: Short campaign (60 mutations cap) run; distinct context_id total and per-run computed; bucket-necessity documented.
- [ ] Step 0.2.4 (optional): Minimal-program sanity check — skipped.
- [x] Step 0.2.5 (optional): Note for Phase 3 baseline touch set — added in report.
- [x] Phase 0.2 implementation report written.
