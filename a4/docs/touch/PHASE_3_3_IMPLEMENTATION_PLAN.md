# Phase 3.3 Detailed Implementation Plan

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase 3.3** (Fuzzer/DB integration for touch coverage). It is consistent with [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) §3.5, §3.8, §4, and incorporates all takeaways from the [PHASE_3_2_IMPLEMENTATION_REPORT.md](./PHASE_3_2_IMPLEMENTATION_REPORT.md) §5 (Insights for Phase 3.3).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Phase 3.2 and Earlier Phases

### 1.1 What Phase 3.2 delivered (source-of-truth)

| Artifact | Location | Status |
|----------|----------|--------|
| `MutationExecutionResult.touch_bitmap: Optional[bytes]` | `a4/core/executor.py` line 135 | Implemented |
| `A4_COVERAGE_TOUCH=1` set in `run_a4_mutation` env | `a4/core/executor.py` line 179 | Implemented |
| `parse_touch_bitmap(output) -> Optional[bytes]` | `a4/core/touch_coverage.py` | Implemented |
| `count_new_bits(run_bitmap, global_bitmap) -> int` | `a4/core/touch_coverage.py` | Implemented |
| `merge_into_global(run_bitmap, global_bitmap) -> None` | `a4/core/touch_coverage.py` | Implemented |
| `make_global_bitmap() -> bytearray` | `a4/core/touch_coverage.py` | Implemented |
| `distinct_touched(bitmap) -> int` | `a4/core/touch_coverage.py` | Implemented |
| `total_touches(bitmap) -> int` | `a4/core/touch_coverage.py` | Implemented |
| `A4_TOUCH_MAP_SIZE = 65536` | `a4/core/touch_coverage.py` | Implemented |
| C++ emits `<a4_touch_coverage>BASE64</a4_touch_coverage>` after SeqForward loop | `ffi.cpp` SeqForward block | Implemented |
| Integration verified: 1599 distinct buckets, 192676 total touches per run | Phase 3.2 report §4.4 | Confirmed |

### 1.2 Phase 3.2 report insights that Phase 3.3 must address

From PHASE_3_2_IMPLEMENTATION_REPORT.md §5:

1. **What to consume**: `exec_result.touch_bitmap` from `MutationExecutionResult`.
2. **Where in the fuzzer**: `_run_single_mutation` (around line 300), after `run_a4_mutation` returns. Compute `new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)`, then `merge_into_global(...)`.
3. **`MutationResult`**: Add `new_touch: int = 0` (distinct from `new_coverage` which is failure-based).
4. **`CampaignStats`**: Add `new_touch_count: int = 0` and `total_distinct_touched: int = 0`.
5. **Campaign summary**: Print touch stats alongside existing coverage stats.
6. **Global bitmap lifecycle**: Create in `__init__` or at campaign start. Persist optionally.
7. **Handle `touch_bitmap = None`**: Skip touch tracking for that run; do not crash. Important for backwards compatibility with older host binaries.
8. **Performance**: Bitmap operations are ~5ms — negligible.

### 1.3 What Phase 3.3 does not do (left to Phase 3.4)

- **Phase 3.4**: Centralized constants doc (MAP_SIZE, FNV-1a, base64); determinism test for touch (same mutation → same bitmap); optional FNV-1a in Python for inverse mapping.

Phase 3.3 **must not** modify C++ code, the executor, or the touch coverage parser. It only consumes the infrastructure Phase 3.2 provides to integrate touch coverage into the fuzzer and optionally the DB.

---

## 2. Source-of-Truth Facts for Phase 3.3

### 2.1 Fuzzer dataclasses

| Fact | Location |
|------|----------|
| `MutationResult` has `new_coverage: int = 0` | `a4/standalone/fuzzer.py` line 73 |
| `CampaignStats` has `new_coverage_count: int = 0` | `fuzzer.py` line 90 |
| `CampaignStats` has `unique_constraints: set` (failure-based) | `fuzzer.py` line 93 |

### 2.2 Where mutation results are built

| Fact | Location |
|------|----------|
| `exec_result = run_a4_mutation(...)` | `fuzzer.py` line 300 |
| `exec_result.touch_bitmap` is now available | Phase 3.2 (executor.py line 135) |
| `result = MutationResult(...)` constructed at line 338 | `fuzzer.py` lines 338–353 |
| Failure coverage recorded: `total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)` | `fuzzer.py` line 367 |
| `result.new_coverage = new_coverage` | `fuzzer.py` line 368 |

### 2.3 Where stats are updated

| Fact | Location |
|------|----------|
| `_update_stats(stats, result)` called per mutation | `fuzzer.py` line 231 (within `run_campaign`) |
| `stats.new_coverage_count += result.new_coverage` | `fuzzer.py` line 921 |
| Per-mutation print: `new_cov = f" [+{result.new_coverage} new]"` | `fuzzer.py` line 936 |
| Campaign summary: `print(f"New coverage: {stats.new_coverage_count}")` | `fuzzer.py` line 1087 |

### 2.4 Global state in A4Fuzzer

| Fact | Location |
|------|----------|
| `self.data: Optional[InspectionData] = None` | `fuzzer.py` line 160 |
| `self.campaign_id: Optional[int] = None` | `fuzzer.py` line 161 |
| No global bitmap exists yet | Phase 3.3 adds it |

### 2.5 Guided selector integration

| Fact | Location |
|------|----------|
| `self.selector.record_mutation(step, new_coverage)` | `fuzzer.py` line 372 |
| This passes failure-based `new_coverage` to the selector | Phase 3.3 can optionally also pass `new_touch` |

---

## 3. Step-by-Step Implementation Plan

### Step 3.3.1: Add `new_touch` field to `MutationResult`

**Goal**: The fuzzer's `MutationResult` dataclass carries the per-run new touch count alongside the existing `new_coverage` (failure-based).

**Facts**:

- `MutationResult` at `fuzzer.py` lines 62–79 has `new_coverage: int = 0`.
- Phase 3.3 adds a parallel field for touch coverage.

**Actions**:

1. In `MutationResult` (line 73), add after `new_coverage`:
   - `new_touch: int = 0`

**Deliverable**: `MutationResult` has `new_touch: int = 0`.

---

### Step 3.3.2: Add touch stats to `CampaignStats`

**Goal**: Campaign-level statistics track total new touch count and the final distinct-touched count (bitmap occupancy).

**Facts**:

- `CampaignStats` at `fuzzer.py` lines 82–94 has `new_coverage_count: int = 0`.

**Actions**:

1. In `CampaignStats`, add:
   - `new_touch_count: int = 0` — cumulative new touch bits discovered across the campaign.
   - `total_distinct_touched: int = 0` — number of non-zero entries in the global bitmap at campaign end (set once in `run_campaign`).

**Deliverable**: `CampaignStats` has `new_touch_count` and `total_distinct_touched`.

---

### Step 3.3.3: Initialize global bitmap in `A4Fuzzer`

**Goal**: The fuzzer maintains a global touch bitmap across the campaign for new-bit detection and merge.

**Facts**:

- `A4Fuzzer.__init__` at `fuzzer.py` lines 140–164 initializes `self.data`, `self.campaign_id`, etc.
- `make_global_bitmap()` from `a4.core.touch_coverage` returns a zeroed `bytearray(65536)`.

**Actions**:

1. Add import at the top of `fuzzer.py`:
   - `from a4.core.touch_coverage import make_global_bitmap, count_new_bits, merge_into_global, distinct_touched`
2. In `A4Fuzzer.__init__`, add:
   - `self.global_touch_bitmap: bytearray = make_global_bitmap()`

**Why in `__init__`**: The global bitmap spans the entire lifetime of the `A4Fuzzer` instance. If the user runs multiple campaigns with the same fuzzer object, the bitmap accumulates across campaigns. This is the correct default behavior (touch coverage grows monotonically). To reset between campaigns, call `self.global_touch_bitmap = make_global_bitmap()` at the start of `run_campaign`, but this is **not** the recommended default — cumulative coverage across campaigns is more useful.

**Deliverable**: `self.global_touch_bitmap` initialized in `__init__`.

---

### Step 3.3.4: Compute and record new touch per mutation

**Goal**: After each mutation run, compute `new_touch = count_new_bits(...)` and merge into the global bitmap. Store `new_touch` on `MutationResult`.

**Facts**:

- `exec_result.touch_bitmap` is `Optional[bytes]` (can be `None` if host didn't emit or parsing failed).
- After line 367 (`record_failures`), the fuzzer sets `result.new_coverage`.

**Actions**:

1. In `_run_single_mutation`, after the `MutationResult` is constructed and failure coverage is recorded (after line 368), add:

```python
# Touch coverage (Phase 3.3)
if exec_result.touch_bitmap is not None:
    new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
    merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
    result.new_touch = new_touch
```

2. This is placed after `result.new_coverage = new_coverage` (line 368) and before the guided selector update (line 371).

**Why after `record_failures`**: Touch and failure coverage are independent. Computing touch does not depend on failure recording. Placing it in the same "record results" region keeps the flow clear.

**Why guard with `is not None`**: Phase 3.2 report §5.6 says: "If the host was built without Phase 3.2 (or if parsing fails), `touch_bitmap` will be `None`. Phase 3.3 should handle this gracefully: skip touch coverage tracking for that run, log a warning, but do not crash." The guard achieves this. No warning is printed in the default case since `None` can happen for legitimate reasons (crash runs where the host didn't complete witgen). A verbose warning could be added under `self.verbose` if desired but is not required.

**Deliverable**: `result.new_touch` populated per run; global bitmap merged.

---

### Step 3.3.5: Update `_update_stats` to accumulate touch stats

**Goal**: `CampaignStats.new_touch_count` accumulates across the campaign.

**Facts**:

- `_update_stats(self, stats, result)` at `fuzzer.py` line 896 is called for each successful mutation. Line 921: `stats.new_coverage_count += result.new_coverage`.

**Actions**:

1. In `_update_stats`, after `stats.new_coverage_count += result.new_coverage` (line 921), add:
   - `stats.new_touch_count += result.new_touch`

**Deliverable**: `stats.new_touch_count` accumulates.

---

### Step 3.3.6: Update per-mutation print to show new touch

**Goal**: The verbose per-mutation output shows new touch bits alongside new failure coverage.

**Facts**:

- `_print_mutation_result` at `fuzzer.py` line 923. Line 936: `new_cov = f" [+{result.new_coverage} new]"`.

**Actions**:

1. After line 936 (`new_cov = ...`), add logic to include touch info:
   - If `result.new_touch > 0`, append to the status line, e.g.:
     `new_touch_str = f" [+{result.new_touch} touch]" if result.new_touch > 0 else ""`
   - Include `new_touch_str` in the `print` on line 962–965.

**Deliverable**: Per-mutation output shows `[+N touch]` when new touch bits are discovered.

---

### Step 3.3.7: Update campaign summary to show touch stats

**Goal**: Campaign summary shows total new touch bits and final bitmap occupancy.

**Facts**:

- `_print_campaign_summary` at `fuzzer.py` line 1077. Prints `New coverage: {stats.new_coverage_count}` at line 1087.

**Actions**:

1. In `_print_campaign_summary`, after the `New coverage` line (line 1087), add:
   - `print(f"New touch:           {stats.new_touch_count}")`
   - `print(f"Distinct touched:    {stats.total_distinct_touched}")`
2. In `run_campaign`, after the campaign loop completes and before `_print_campaign_summary` is called, set:
   - `stats.total_distinct_touched = distinct_touched(bytes(self.global_touch_bitmap))`

**Deliverable**: Campaign summary shows touch stats.

---

### Step 3.3.8: Optional — pass `new_touch` to guided selector

**Goal**: The guided selector (if it supports it) receives `new_touch` alongside `new_coverage` for step selection heuristics.

**Facts**:

- `self.selector.record_mutation(step, new_coverage)` at `fuzzer.py` line 372.
- The guided selector's `record_mutation` signature depends on the selector implementation.

**Actions**:

1. This step is **optional for Phase 3.3**. The current guided selector uses `new_coverage` (failure-based). Adding `new_touch` would require changing the selector's API.
2. If implemented: change the call to `self.selector.record_mutation(step, new_coverage + result.new_touch)` (combined reward) or `self.selector.record_mutation(step, new_coverage, new_touch=result.new_touch)`. The former is simpler and gives touch discovery equal weight to failure discovery as a reward signal.
3. **Recommendation for Phase 3.3**: Use the combined approach (`new_coverage + result.new_touch`) as a simple first pass. Phase II (coverage-guided scheduling, bandits) will implement a more sophisticated reward function.

**Deliverable**: Optional. If done, selector receives combined reward.

---

### Step 3.3.9: Optional — persist global bitmap

**Goal**: Save the global bitmap to disk so a campaign can be resumed without losing touch coverage state.

**Facts**:

- The global bitmap is `bytearray(65536)` — 64KB.
- The fuzzer already has `self.db_path` and `self.db` (CoverageDB).

**Actions**:

1. This step is **optional for Phase 3.3**. The simplest approach: save the raw bytes to a file alongside the DB.
   - At campaign end (after `end_campaign`): `Path(self.db_path).with_suffix('.touch_bitmap').write_bytes(bytes(self.global_touch_bitmap))`.
   - At campaign start: if the file exists, load it: `self.global_touch_bitmap = bytearray(Path(...).read_bytes())`.
2. Alternative: store as a BLOB in the campaigns table. This requires a schema change and is deferred to Phase 3.4 or later.
3. **Recommendation for Phase 3.3**: Implement the simple file-based persistence. 64KB is trivial to write/read and does not require DB schema changes.

**Deliverable**: Optional. If done, global bitmap saved to `.touch_bitmap` file.

---

## 4. Files to Touch (Phase 3.3 only)

| File | Change |
|------|--------|
| `a4/standalone/fuzzer.py` | Import touch coverage functions; `MutationResult.new_touch`; `CampaignStats.new_touch_count`, `total_distinct_touched`; `self.global_touch_bitmap` in `__init__`; compute/merge touch in `_run_single_mutation`; accumulate in `_update_stats`; print in `_print_mutation_result` and `_print_campaign_summary`; set `total_distinct_touched` after campaign loop. Optional: pass to selector, persist bitmap. |

No changes to: `ffi.cpp`, `witgen.h`, `executor.py`, `touch_coverage.py`, `constraint_parser.py`, `coverage_db.py`, `cli.py`, or any mutation module.

---

## 5. Alignment with PHASE_I_IMPLEMENTATION_PLAN.md

| Plan reference | Phase 3.3 coverage | Notes |
|----------------|---------------------|-------|
| §3.5 ("Fuzzer/DB record new touch count per run") | Steps 3.3.1–3.3.7: record `new_touch` per run, accumulate in campaign stats. | As planned. |
| §3.5 ("optionally persist global bitmap for restarts") | Step 3.3.9 (optional): file-based persistence. | Plan says "optional"; we implement file-based for simplicity. |
| §3.8 ("Fuzzer/DB record new touch count per run; optionally persist") | Same as above. | As planned. |
| §4 item 5 ("Phase 3.3 – Fuzzer/DB: record new touch count per run; optional persistence") | Fully covered. | As planned. |

### Deviations from higher-level planning

1. **No DB schema change**: PHASE_I §3.5 mentions "optionally persist global bitmap (e.g. in DB or a file)." Phase 3.3 uses a file (`.touch_bitmap`), not a DB BLOB. **Reason**: Adding a BLOB column to the `campaigns` or `mutations` table requires a schema migration that could break existing DBs. A sidecar file is simpler, sufficient for Phase I, and avoids schema risk. A DB-based approach can be added in Phase II if campaign management becomes more complex.

2. **No per-mutation `new_touch` in the DB**: The plan mentions "record new touch count per run." Phase 3.3 records `new_touch` on `MutationResult` (in-memory) and accumulates it in `CampaignStats`, but does **not** add a `new_touch_count` column to the `mutations` table. **Reason**: Adding a column requires a schema change (`ALTER TABLE`). The `new_touch` value is printed in verbose output and accumulated in campaign stats, which is sufficient for Phase I observability. If per-mutation touch data needs to be queried historically, Phase 3.4 or Phase II can add the column.

3. **Combined reward for selector (optional)**: PHASE_I §3.5 says "For Phase I, 'new touch bits' can be the reward signal." Step 3.3.8 optionally passes `new_coverage + new_touch` to the guided selector. This is a simple sum, not a weighted combination. **Reason**: Phase I does not implement sophisticated scheduling (Phase II scope). A combined sum treats one new failure-coverage bit as equal to one new touch-coverage bit, which is a reasonable default. Phase II's bandit/UCB logic (Pro_Report_1.md §6.1) will replace this.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 `MutationResult.new_touch: int = 0`

Number of bitmap buckets that this specific run touched for the first time in the campaign. Parallel to `new_coverage` (failure-based). Phase II will use this as part of the reward signal.

### 6.2 `CampaignStats.new_touch_count: int = 0`

Cumulative sum of `new_touch` across all mutations in the campaign. Analogous to `new_coverage_count`.

### 6.3 `CampaignStats.total_distinct_touched: int = 0`

Number of non-zero entries in the global bitmap at campaign end. This is the "total coverage achieved" metric for touch — how many distinct constraint contexts were ever touched during the campaign. Set once after the campaign loop via `distinct_touched(bytes(self.global_touch_bitmap))`.

### 6.4 `self.global_touch_bitmap: bytearray`

The campaign-level global bitmap. Initialized to zeros in `__init__`. Merged per-run via `merge_into_global`. Used for `count_new_bits` to detect new bits per run. 64KB, constant size.

---

## 7. Phase 3.3 Completion Checklist

- [ ] Step 3.3.1: `MutationResult.new_touch` field added.
- [ ] Step 3.3.2: `CampaignStats.new_touch_count` and `total_distinct_touched` fields added.
- [ ] Step 3.3.3: `self.global_touch_bitmap` initialized in `A4Fuzzer.__init__`.
- [ ] Step 3.3.4: `count_new_bits` and `merge_into_global` called per mutation; `result.new_touch` set.
- [ ] Step 3.3.5: `stats.new_touch_count` accumulated in `_update_stats`.
- [ ] Step 3.3.6: Per-mutation print shows `[+N touch]`.
- [ ] Step 3.3.7: Campaign summary shows `New touch` and `Distinct touched`.
- [ ] Step 3.3.8 (optional): Selector receives combined reward.
- [ ] Step 3.3.9 (optional): Global bitmap persisted to file.
- [ ] No changes to C++, executor, touch_coverage.py, or DB schema.

---

## 8. Dependencies for Phase 3.4 (reminders)

- **Phase 3.4**: Centralize MAP_SIZE (65536), hash function (FNV-1a with offset=2166136261, prime=16777619), encoding (base64), and bitmap semantics (saturating counters, max-merge) in one documentation location. Add a determinism test: run the same mutation config twice with `A4_COVERAGE_TOUCH=1`, parse both bitmaps, assert they are byte-equal. Optionally add FNV-1a hash in Python for inverse mapping (bitmap index → approximate context_id). Optionally document the Phase 3.2 measurement (1599 distinct buckets, ~2.4% occupancy, ~19.5 expected collisions) as evidence that MAP_SIZE=65536 is sufficient without step_bucket.

---

## 9. For Anyone New: What Phase 3.3 Is and Why

### What

Phase 3.3 is the **fuzzer integration** phase. It takes the touch coverage data that Phase 3.2 delivers on every mutation run (a 65536-byte bitmap showing which constraint contexts were evaluated) and wires it into the fuzzing campaign loop so the fuzzer can:

1. **Track new discoveries**: For each run, count how many constraint contexts were touched for the first time in the campaign ("new touch bits"). This is the AFL-style "did this run discover new coverage?" signal.
2. **Accumulate a global map**: Maintain a campaign-level bitmap that grows as new contexts are discovered across runs.
3. **Report progress**: Print per-mutation new-touch counts in verbose output and campaign-level touch statistics in the summary.

### Why this way

- **Minimal changes, maximum observability**: Phase 3.3 only modifies `fuzzer.py`. It adds two fields to dataclasses, a 64KB bytearray to the fuzzer, and a few lines of logic per mutation. No DB schema changes, no C++ changes, no new modules.
- **Separation of concerns**: Phase 3.2 provides the infrastructure (emit + parse + merge utilities). Phase 3.3 uses it in the fuzzer. Phase 3.4 documents and tests it. This keeps each phase focused and independently verifiable.
- **No scheduling changes yet**: Phase 3.3 records the data but does not change how mutations are selected. That is Phase II's job (corpus management, bandit scheduling, rarity weighting). Phase 3.3 provides the raw signal; Phase II will act on it.

### How Phase 3.3 differs from the other phases

| Phase | What it does | Where it lives |
|-------|-------------|----------------|
| **0.1** | Stable IDs, determinism test | Python core (constraint_parser) |
| **0.2** | Baseline, key-space measurement | Python tests + DB helpers |
| **3.1** | C++ bitmap + hash + touch marking | C++ kernel only |
| **3.2** | C++ emission + Python parser + executor wiring | C++ + Python core (cross-language bridge) |
| **3.3** (this) | Fuzzer consumes touch data; campaign-level tracking | **Python fuzzer only** |
| **3.4** | Centralized docs + determinism test for touch | Python tests + docs |

Phase 3.3 is the first phase that modifies the **fuzzer** (`fuzzer.py`). All previous phases worked on core infrastructure (IDs, C++ kernel, executor, parser). Phase 3.3 closes the loop: the fuzzer can now see, for every mutation, not just which constraints **failed** but which constraints were **evaluated at all**.

---

## 10. New and Withheld Sections Compared to Previous Plans

**Sections retained**: All section types from Phase 3.2 plan are present (prerequisites, source-of-truth facts, step-by-step plan, files to touch, alignment/deviations, key variables, checklist, future-phase dependencies, for-anyone-new).

**New sections**: None beyond what Phase 3.2 introduced.

**Sections withheld**: The "Encoding details" section (§4 in Phase 3.2 plan) is not present because Phase 3.3 does not introduce a new serialization format. This is consistent with Phase 3.1's plan which also omitted it.

---

*End of Phase 3.3 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*
