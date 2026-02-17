# Phase 3.3 Implementation Report

This report describes the implementation and testing of Phase 3.3 (Fuzzer integration for touch coverage), deviations from the plan, key variables and functions, testing performed, and insights for the Phase 3.4 implementation plan.

**Reference plan**: [PHASE_3_3_IMPLEMENTATION_PLAN.md](./PHASE_3_3_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase 3.3 was implemented as specified. All seven required steps and one optional step (combined selector reward) are complete. Step 3.3.9 (bitmap persistence) was not implemented; see §2 Deviations. A 5-mutation campaign was run end-to-end and confirmed that touch coverage integrates correctly with the fuzzer loop.

---

## 2. Deviations from the Phase 3.3 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Step 3.3.8 (selector reward) | "Optional. If done, selector receives combined reward." | Implemented: `self.selector.record_mutation(step, new_coverage + result.new_touch)` | Simple and low-risk. Gives touch discovery equal weight to failure discovery. The line that previously passed only `new_coverage` now passes the sum. Phase II will replace this with proper bandit/UCB weighting. |
| Step 3.3.9 (persist bitmap) | "Optional. File-based persistence." | Not implemented. | Not needed for Phase I validation. The global bitmap resets when a new `A4Fuzzer` instance is created (i.e. each campaign starts fresh). Persistence can be added in Phase II when campaign resume is needed. Omitting it keeps Phase 3.3 changes minimal (single file). |
| `total_distinct_touched` computation location | Plan says "In `run_campaign`, after the campaign loop completes and before `_print_campaign_summary`" | Implemented at exactly that location: after `stats.execution_time_ms = ...` and before `self.db.end_campaign(...)`. | As planned. |

No other deviations.

---

## 3. Key Variables and Functions

### 3.1 `MutationResult.new_touch: int = 0`

- **What**: Per-mutation count of bitmap buckets touched for the first time in this campaign.
- **Where set**: `_run_single_mutation`, after `result.new_coverage = new_coverage` (line ~370), inside the `if exec_result.touch_bitmap is not None:` guard.
- **How it works**: `new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)` counts indices where the run bitmap is non-zero and the global bitmap is zero. Then `merge_into_global(...)` updates the global bitmap. Then `result.new_touch = new_touch`.
- **Why parallel to `new_coverage`**: `new_coverage` counts new failure-based constraint coverage (from `record_failures`). `new_touch` counts new touch-based coverage (from the bitmap). They are independent signals. A run can have `new_touch > 0` with `new_coverage == 0` (touched new contexts but none of them failed) or vice versa.

### 3.2 `CampaignStats.new_touch_count: int = 0`

- **What**: Cumulative sum of `new_touch` across all mutations in the campaign.
- **Where accumulated**: `_update_stats`, line: `stats.new_touch_count += result.new_touch`.
- **Behavior**: For a typical campaign where the same guest program is used with the same inputs, most new touch bits are discovered on the first mutation (because the base program exercises the same ~1599 constraint contexts regardless of mutation). Subsequent mutations only add new touch bits if they cause the program to enter different major/minor dispatch branches — e.g., an `INSTR_TYPE_MOD` that changes a JalR to a Sb would exercise store-related constraints that may not appear in the base program's execution path. The test campaign showed `new_touch_count = 1599` (all from run 1).

### 3.3 `CampaignStats.total_distinct_touched: int = 0`

- **What**: Number of non-zero entries in the global bitmap at campaign end.
- **Where set**: `run_campaign`, after the campaign loop: `stats.total_distinct_touched = distinct_touched(bytes(self.global_touch_bitmap))`.
- **Why at campaign end, not per-run**: This is a summary statistic. Computing it once is cheaper and gives the final picture. Per-run values can be derived from `new_touch_count` (cumulative) but are not needed for reporting.

### 3.4 `self.global_touch_bitmap: bytearray`

- **What**: The campaign-level global bitmap. 65536 bytes, initialized to zeros.
- **Where initialized**: `A4Fuzzer.__init__`, line: `self.global_touch_bitmap = make_global_bitmap()`.
- **Lifecycle**: Created once per fuzzer instance. Merged per-mutation via `merge_into_global`. Read (for `count_new_bits`) before each merge. Not persisted (Step 3.3.9 was not implemented). If the user creates a new `A4Fuzzer` for a second campaign, the bitmap resets — each campaign starts with a fresh global bitmap.
- **Why `bytearray`**: Mutable, fixed-size, indexable by byte. `merge_into_global` mutates it in place. `count_new_bits` reads it without copying.

### 3.5 Combined selector reward

- **What**: `self.selector.record_mutation(step, new_coverage + result.new_touch)`.
- **Previous**: `self.selector.record_mutation(step, new_coverage)`.
- **Why sum**: In Phase I, we want the guided selector (if active) to prefer steps where the fuzzer discovered something new — whether that's a new failure-based constraint or a new touch-based constraint. A simple sum is the minimal change that incorporates both signals. Phase II will implement proper reward shaping (Pro_Report_1.md §5: `reward = α * new_touch + β * new_fail_weighted`).

### 3.6 `None` guard for `touch_bitmap`

- **What**: `if exec_result.touch_bitmap is not None:` guards all touch operations.
- **Why**: Phase 3.2 report §5.6 mandates graceful handling when the host doesn't emit a touch bitmap (e.g., crash runs where witgen didn't complete, or older host binaries without Phase 3.2 C++ changes). The guard ensures the fuzzer continues without touch tracking for that run. `result.new_touch` stays at its default `0`.

---

## 4. Testing Performed

### 4.1 Linter check

**Result**: No linter errors on `fuzzer.py` after all changes.

### 4.2 End-to-end campaign (5 mutations)

**Command**: `python -m a4.standalone.cli fuzz --host ./workspace/output/target/release/risc0-host --num 5 --kind all --seed 42 --db ./phase33_test.db -- --in1 5 --in4 10`

**Result**: Campaign completed successfully. All 5 mutations were REJECTED (as expected).

**Touch coverage observations**:

| Run | Kind | Step | Failures | New Coverage | New Touch |
|-----|------|------|----------|-------------|-----------|
| 1 | LOAD_VAL_MOD | 317 | 1 | +1 | +1599 |
| 2 | COMP_OUT_MOD | 1409 | 2 | +2 | 0 |
| 3 | INSTR_TYPE_MOD | 3048 | 5 | +5 | 0 |
| 4 | LOAD_VAL_MOD | 3180 | 2 | +2 | 0 |
| 5 | INSTR_WORD_MOD_FULL | 1742 | 1 | +1 | 0 |

**Campaign summary**:
- Total mutations: 5
- Successful: 5 (all REJECTED)
- New coverage (failure): 11
- **New touch: 1599**
- **Distinct touched: 1599**
- Execution time: ~218s

**Interpretation**:

1. **Run 1 discovers all 1599 touch buckets**: The global bitmap starts empty, so every non-zero bucket in the first run's bitmap is "new." After merging, the global has 1599 non-zero entries.
2. **Runs 2–5 discover zero new touch buckets**: The same guest program with the same inputs produces the same execution path (same cycles, same major/minor dispatch), so the same ~1599 constraint contexts are touched every run. Mutations change the *values* in the trace but do not change the *control flow* of the witness generation loop — the same EQZ call sites are reached because the same steps/cycles execute the same major/minor branches. New touch buckets would only appear if a mutation caused the program to enter a previously-unexercised major/minor branch (e.g., an INSTR_TYPE_MOD that activates a DIV component that the base program never uses, or a mutation that causes execution past the normal program end).
3. **This is expected and correct**: In AFL terms, the first input to the fuzzer discovers the "base coverage." Subsequent inputs only add coverage if they exercise new code paths. The same principle applies here: the first mutation run discovers the base touch coverage, and subsequent mutations need to explore sufficiently different branches to add new touch buckets. This validates the rationale from Pro_Report_1.md §5.1: "Reward a run for producing new `TouchCov` bits" — the first run is highly rewarded, and subsequent runs must find genuinely new contexts to earn reward.
4. **Touch vs failure coverage**: Failure coverage (`new_coverage`) grew from 1 to 11 across 5 runs because different mutations trigger different constraint *failures*. Touch coverage (`new_touch`) saturated after run 1 because the same constraints are *evaluated* regardless of which specific mutation value is used. This demonstrates the fundamental difference: failure coverage is value-dependent (which constraints *break*), while touch coverage is path-dependent (which constraints are *reached*). Both are useful signals but respond to different aspects of mutation selection.

### 4.3 What was not tested

- No campaign with >60 mutations (user's long-standing cap).
- No crash-scenario testing (where `touch_bitmap` is `None`). The `None` guard is trivially correct by inspection.
- No bitmap persistence test (Step 3.3.9 was not implemented).
- No unit test for the fuzzer changes specifically. The integration campaign serves as the end-to-end test.

---

## 5. Insights for the Phase 3.4 Implementation Plan

### 5.1 What Phase 3.4 needs to do

From PHASE_I_IMPLEMENTATION_PLAN.md §4 item 6: "Documentation and constants (MAP_SIZE, B, hash) in one place; add tests that same mutation yields same touch bitmap (determinism for touch)."

### 5.2 Determinism test for touch

Phase 0.1 established the determinism test for *failures* (`test_determinism.py`). Phase 3.4 should extend this to *touch*:

- Run the same mutation config twice with `A4_COVERAGE_TOUCH=1`.
- Parse both `touch_bitmap` values from the two runs.
- Assert they are byte-equal.

This test validates the entire pipeline: C++ marking → hashing → bitmap accumulation → base64 encoding → Python decoding. If the bitmaps differ, something is non-deterministic (thread ordering, ASLR affecting pointer hashes, etc.). The existing `test_determinism.py` already calls `run_a4_mutation` twice; Phase 3.4 can add a third assertion comparing `result1.touch_bitmap == result2.touch_bitmap`.

### 5.3 Constants documentation

Phase 3.4 should create or add to a doc that lists:
- `MAP_SIZE = 65536` (C++: `kA4TouchMapSize`, Python: `A4_TOUCH_MAP_SIZE`)
- Hash: FNV-1a, offset basis `2166136261`, prime `16777619`
- Key: `(loc_string, major, minor)` — no step_bucket in Phase I
- Encoding: base64 (standard alphabet, `=` padding)
- Bitmap semantics: saturating 8-bit counters; `max`-merge for global
- Measured occupancy: ~1599 distinct buckets out of 65536 (~2.4%), ~19.5 expected collisions

### 5.4 Optional FNV-1a in Python

If Phase 3.4 or Phase II needs to map a bitmap index back to an approximate `(constraint_loc, major, minor)`, Python needs the same FNV-1a hash. This is straightforward (~10 lines). Not required for Phase I coverage tracking (bitmap indices are opaque), but useful for debugging ("which constraint does bucket #1234 correspond to?").

### 5.5 The touch saturation pattern

The test campaign shows that for a fixed guest program, touch coverage saturates on the first run. This means:
- **For Phase II scheduling**: The "new touch" reward signal will be most useful when the fuzzer varies inputs or uses instruction-type mutations that change which major/minor branches execute. Pure value mutations (COMP_OUT_MOD, LOAD_VAL_MOD) don't change the control-flow path and won't discover new touch buckets.
- **For rarity weighting**: The `max` values in the global bitmap are useful: a bucket with `max = 1` (touched exactly once per run) represents a rare constraint that is only checked once per cycle; a bucket with `max = 255` (saturated) represents a ubiquitous constraint checked at every cycle. Phase II can use this for `rarity_reward(bucket) = 1 / sqrt(1 + max_count)` per Pro_Report_1.md §5.3.
- **Baseline touch set**: Phase 0.2 report §0.2.5 noted that "Phase 3 should capture the touch set from an unmutated run." With Phase 3.3, this can be done by running `run_baseline` with `A4_COVERAGE_TOUCH=1` set in the environment and parsing the touch bitmap from the output. The baseline touch set is the "expected" set; mutations that produce *different* touch sets are more interesting. Phase 3.4 can document this or add a test.

---

## 6. Files Touched

| File | Change |
|------|--------|
| `a4/standalone/fuzzer.py` | Import `make_global_bitmap`, `count_new_bits`, `merge_into_global`, `distinct_touched`; `MutationResult.new_touch: int = 0`; `CampaignStats.new_touch_count`, `total_distinct_touched`; `self.global_touch_bitmap` in `__init__`; touch compute/merge in `_run_single_mutation`; accumulate in `_update_stats`; display in `_print_mutation_result` and `_print_campaign_summary`; `total_distinct_touched` set after campaign loop; combined reward to selector. |
| `a4/docs/touch/PHASE_3_3_IMPLEMENTATION_REPORT.md` | This report. |

No changes to: `ffi.cpp`, `witgen.h`, `executor.py`, `touch_coverage.py`, `constraint_parser.py`, `coverage_db.py`, `cli.py`, or any mutation module.

---

## 7. Phase 3.3 Completion Checklist

- [x] Step 3.3.1: `MutationResult.new_touch` field added.
- [x] Step 3.3.2: `CampaignStats.new_touch_count` and `total_distinct_touched` fields added.
- [x] Step 3.3.3: `self.global_touch_bitmap` initialized in `A4Fuzzer.__init__`.
- [x] Step 3.3.4: `count_new_bits` and `merge_into_global` called per mutation; `result.new_touch` set.
- [x] Step 3.3.5: `stats.new_touch_count` accumulated in `_update_stats`.
- [x] Step 3.3.6: Per-mutation print shows `[+N touch]` when `new_touch > 0`.
- [x] Step 3.3.7: Campaign summary shows `New touch` and `Distinct touched`.
- [x] Step 3.3.8: Selector receives combined reward (`new_coverage + new_touch`).
- [ ] Step 3.3.9: Bitmap persistence — not implemented (optional; deferred).
- [x] No changes to C++, executor, touch_coverage.py, or DB schema.
- [x] 5-mutation integration campaign passed with correct touch stats.

---

*End of Phase 3.3 Implementation Report.*
