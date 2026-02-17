# Phase 3.4 Detailed Implementation Plan

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase 3.4** (centralized documentation + determinism test for touch). Phase 3.4 is the **final phase of Phase I**. It is consistent with [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) §3.6, §3.8, §4 item 6, and incorporates all takeaways from the [PHASE_3_3_IMPLEMENTATION_REPORT.md](./PHASE_3_3_IMPLEMENTATION_REPORT.md) §5.

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Phase 3.3 and Earlier Phases

### 1.1 What Phases 3.1–3.3 delivered (complete pipeline)

The entire touch coverage pipeline is now operational:

| Layer | What | Where |
|-------|------|-------|
| C++ marking | `a4_touch_mark(ctx, loc)` called at entry of every `eqz` (Val overload only) | `witgen.h` line 182, `ffi.cpp` lines 73–83 |
| C++ bitmap | `g_a4_touch_bitmap[65536]`, FNV-1a hash `(loc, major, minor) % 65536`, saturating increment | `ffi.cpp` lines 56–83 |
| C++ emission | Base64-encoded bitmap printed as `<a4_touch_coverage>...</a4_touch_coverage>` after SeqForward loop | `ffi.cpp` SeqForward block |
| Python parser | `parse_touch_bitmap(output) -> Optional[bytes]` | `a4/core/touch_coverage.py` |
| Python merge | `count_new_bits`, `merge_into_global`, `make_global_bitmap` | `a4/core/touch_coverage.py` |
| Executor | `A4_COVERAGE_TOUCH=1` set; `MutationExecutionResult.touch_bitmap` populated | `a4/core/executor.py` |
| Fuzzer | `self.global_touch_bitmap`; `MutationResult.new_touch`; `CampaignStats.new_touch_count`, `total_distinct_touched`; per-mutation + summary printing | `a4/standalone/fuzzer.py` |

### 1.2 Phase 3.3 report insights that Phase 3.4 must address

From PHASE_3_3_IMPLEMENTATION_REPORT.md §5:

1. **Determinism test for touch**: Extend existing `test_determinism.py` to assert `result1.touch_bitmap == result2.touch_bitmap`.
2. **Constants documentation**: Centralize MAP_SIZE, hash, key, encoding, bitmap semantics, and measured occupancy in one place.
3. **Optional FNV-1a in Python**: For inverse mapping (bitmap index → approximate context_id); useful for debugging.
4. **Touch saturation pattern**: Document that for a fixed guest, touch saturates after the first run.
5. **Baseline touch set**: Document how to capture baseline touch with `A4_COVERAGE_TOUCH=1`.

### 1.3 What Phase 3.4 does not do

Phase 3.4 is the last phase of Phase I. Phase II (coverage-guided scheduling, corpus, bandits, rarity weighting) follows separately and is **not** in Phase 3.4's scope. Specifically:

- No scheduling changes (Phase II).
- No rarity weighting (Phase II).
- No corpus management (Phase II).
- No coherence scoring (Pro_Report_2 Phase 4).
- No DB schema changes.
- No C++ changes.

---

## 2. Source-of-Truth Facts for Phase 3.4

### 2.1 Existing determinism test

| Fact | Location |
|------|----------|
| `test_determinism.py` has two tests: `test_same_config_same_failure_set_by_context_id` and `test_same_config_same_failure_set_by_signature` | `a4/standalone/tests/test_determinism.py` lines 65–124 |
| Both tests call `run_a4_mutation` twice with the same config and compare failure sets | Lines 78–79 (r1, r2), then compare sets |
| `run_a4_mutation` now returns `MutationExecutionResult` with `touch_bitmap: Optional[bytes]` | `a4/core/executor.py` line 135 |
| Tests are skipped unless `A4_TEST_HOST` is set | `pytest.mark.skipif` on each test |
| Config is auto-generated from inspection if `A4_TEST_CONFIG` is not set | `_build_config_from_inspection` helper |

### 2.2 Constants currently defined in two places

| Constant | C++ | Python |
|----------|-----|--------|
| MAP_SIZE | `kA4TouchMapSize = 65536` (`ffi.cpp` line 56) | `A4_TOUCH_MAP_SIZE = 65536` (`touch_coverage.py` line 22) |
| Hash | FNV-1a, offset `2166136261u`, prime `16777619u` (`ffi.cpp` lines 60–71) | Not implemented in Python |
| Key | `(loc_string, major, minor)` — no step_bucket | Documented in `touch_coverage.py` docstring |
| Encoding | Base64 (`ffi.cpp` `a4_base64_encode`) | `base64.b64decode` in `parse_touch_bitmap` |

### 2.3 Existing docs

| Doc | Coverage of touch |
|-----|-------------------|
| `a4/docs/standalone/README.md` | Lists `A4_MUTATION_CONFIG`, `CONSTRAINT_CONTINUE`, `A4_TEST_HOST`; does **not** mention `A4_COVERAGE_TOUCH` | 
| `a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md` | Full design; references §3.6 for constants |
| Individual phase reports | Per-phase details |

### 2.4 Measured bitmap occupancy (Phase 3.2 integration test)

- Distinct buckets: **1599** out of 65536 (~2.4%)
- Total touches: **192676** (~5.9 EQZ calls per cycle)
- Expected collisions: ~1599²/(2×65536) ≈ **19.5** (negligible)
- Conclusion: MAP_SIZE=65536 is sufficient without step_bucket.

---

## 3. Step-by-Step Implementation Plan

### Step 3.4.1: Add touch determinism test to `test_determinism.py`

**Goal**: Confirm that running the same mutation config twice produces byte-identical touch bitmaps.

**Facts**:

- The existing tests already call `run_a4_mutation` twice (`r1`, `r2`) and have access to `r1.touch_bitmap` and `r2.touch_bitmap`.
- The two existing tests use separate functions (each builds its own `r1`/`r2`). Adding a third test with its own `r1`/`r2` pair follows the same pattern. Alternatively, we could refactor to share runs, but that changes the test structure and is not required.

**Actions**:

1. In `test_determinism.py`, add a new test function `test_same_config_same_touch_bitmap()`:
   - Same skip condition (`A4_TEST_HOST` required).
   - Same config logic (auto-generate if not provided).
   - Call `run_a4_mutation` twice.
   - Assert `r1.touch_bitmap is not None` and `r2.touch_bitmap is not None`.
   - Assert `r1.touch_bitmap == r2.touch_bitmap`.
   - On failure, report how many bytes differ: `sum(1 for a, b in zip(r1.touch_bitmap, r2.touch_bitmap) if a != b)`.

**Deliverable**: Third test in `test_determinism.py` that validates touch bitmap determinism.

---

### Step 3.4.2: Add `A4_COVERAGE_TOUCH` to standalone README

**Goal**: Document the `A4_COVERAGE_TOUCH` environment variable in the existing env var reference table.

**Facts**:

- `a4/docs/standalone/README.md` has three env var tables: "Inspection Variables," "Mutation Variables," "Critical Execution Variables," and "Test / development environment variables."
- `A4_COVERAGE_TOUCH` is set automatically by the Python executor (like `CONSTRAINT_CONTINUE`).

**Actions**:

1. In the "Critical Execution Variables" table in README.md, add a row:
   - `A4_COVERAGE_TOUCH=1` | Emit touch coverage bitmap after witness generation | Python executor (Phase 3.2)

**Deliverable**: README documents `A4_COVERAGE_TOUCH`.

---

### Step 3.4.3: Create centralized touch coverage constants reference

**Goal**: One document that lists all constants, the hash function, encoding, bitmap semantics, and measured occupancy — so future implementers (Phase II) have a single reference.

**Facts**:

- Currently, constants are spread across `ffi.cpp`, `touch_coverage.py`, and various phase reports.
- PHASE_I_IMPLEMENTATION_PLAN.md §3.6 says: "MAP_SIZE, B, hash: document in one place."

**Actions**:

1. Create a new section in the PHASE_I_IMPLEMENTATION_PLAN.md (or add a short standalone doc). Given the plan is already long, a **short appendix at the end of this report** (PHASE_3_4_IMPLEMENTATION_REPORT.md) is the right place, since the report is the final Phase I document. Alternatively, add to the existing touch_coverage.py docstring.

   **Recommendation**: Add a "Phase I Touch Coverage Reference" section to the Phase 3.4 implementation report, which serves as the centralized doc. This avoids creating yet another standalone file and ensures the reference lives alongside the final Phase I completion report.

2. Content of the reference:
   - **MAP_SIZE**: 65536 (C++: `kA4TouchMapSize` in `ffi.cpp`; Python: `A4_TOUCH_MAP_SIZE` in `touch_coverage.py`).
   - **Hash function**: FNV-1a 32-bit. Offset basis: `2166136261`. Prime: `16777619`. Input: bytes of `loc` string (null-terminated), then `major` (1 byte), then `minor` (1 byte). Index: `hash % MAP_SIZE`.
   - **Key**: `(loc_string, major, minor)`. No step_bucket in Phase I. `loc_string` is the raw C string passed to `EQZ(val, loc)` — e.g., `"MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)"`.
   - **Encoding**: Base64 (standard 64-char alphabet `A-Za-z0-9+/`, `=` padding). C++ emits after SeqForward loop. Python decodes with `base64.b64decode`.
   - **Tag**: `<a4_touch_coverage>BASE64</a4_touch_coverage>` (single line in stdout). Debug summary: `<a4_touch_debug> total_touches=N distinct_buckets=M </a4_touch_debug>`.
   - **Bitmap semantics**: Each entry is a uint8 saturating counter (0–255). Per-run: cleared to zero before witgen loop; incremented on each `eqz` call that hashes to that index. Per-campaign: global bitmap uses element-wise `max` merge.
   - **Measured occupancy** (Phase 3.2 integration): 1599 distinct buckets, 192676 total touches, ~2.4% occupancy, ~19.5 expected hash collisions. Conclusion: MAP_SIZE=65536 is adequate without step_bucket.
   - **Environment variable**: `A4_COVERAGE_TOUCH=1` (set by Python executor; checked by C++ `a4_touch_mark` and SeqForward emission block).

**Deliverable**: Centralized reference in the Phase 3.4 report.

---

### Step 3.4.4: Optional — FNV-1a hash in Python

**Goal**: Allow Python to compute the same hash as C++ for inverse mapping (bitmap index → context_id).

**Facts**:

- The C++ hash is in `ffi.cpp` lines 60–71: FNV-1a over `loc` bytes, then mix `major`, `minor`.
- Python equivalent is ~10 lines.
- Not required for Phase I coverage tracking (bitmap indices are opaque). Useful for debugging.

**Actions**:

1. In `a4/core/touch_coverage.py`, add:
   - `def fnv1a_touch_hash(loc: str, major: int, minor: int) -> int`: Compute the same FNV-1a hash as C++. Encode `loc` as UTF-8 bytes, iterate, XOR each byte with hash, multiply by prime. Then XOR major, multiply, XOR minor, multiply. Return `hash % A4_TOUCH_MAP_SIZE`.
2. This function is not called by any Phase I code. It exists as a utility for debugging and for Phase II inverse mapping.

**Deliverable**: `fnv1a_touch_hash` in `touch_coverage.py`.

---

### Step 3.4.5: Run all tests (determinism + unit + baseline)

**Goal**: Verify that the new touch determinism test passes and that existing tests still pass.

**Actions**:

1. Run unit tests: `python -m pytest a4/standalone/tests/test_touch_coverage.py -v`.
2. Run determinism tests (requires host): `A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_determinism.py -v`.
3. All tests should pass.

**Deliverable**: All tests green; documented in the Phase 3.4 report.

---

## 4. Files to Touch (Phase 3.4 only)

| File | Change |
|------|--------|
| `a4/standalone/tests/test_determinism.py` | Add `test_same_config_same_touch_bitmap` test. |
| `a4/docs/standalone/README.md` | Add `A4_COVERAGE_TOUCH` to env var table. |
| `a4/core/touch_coverage.py` | Optional: add `fnv1a_touch_hash`. |
| `a4/docs/touch/PHASE_3_4_IMPLEMENTATION_PLAN.md` | This plan. |
| `a4/docs/touch/PHASE_3_4_IMPLEMENTATION_REPORT.md` | Report with centralized constants reference. |

No changes to: `ffi.cpp`, `witgen.h`, `executor.py`, `fuzzer.py`, `coverage_db.py`, `cli.py`, or any mutation module.

---

## 5. Alignment with PHASE_I_IMPLEMENTATION_PLAN.md

| Plan reference | Phase 3.4 coverage | Notes |
|----------------|---------------------|-------|
| §3.6 ("MAP_SIZE, B, hash in one place") | Step 3.4.3: Centralized reference in the Phase 3.4 report. | As planned. |
| §3.8 ("Docs: Update a4/docs/standalone and touch/ to describe A4_COVERAGE_TOUCH, bitmap format, Phase I scope") | Steps 3.4.2 (README) and 3.4.3 (constants reference). | As planned. |
| §4 item 6 ("add tests that same mutation yields same touch bitmap") | Step 3.4.1. | As planned. |

### Deviations from higher-level planning

1. **Constants reference placement**: PHASE_I §3.6 says "document in one place (C++ and Python)." Phase 3.4 places the reference in the Phase 3.4 implementation report rather than creating a standalone doc. **Reason**: The report is the final Phase I document and is the natural place for a consolidated reference. A standalone doc would be one more file to maintain. The `touch_coverage.py` docstring already documents the Python-side constants; the C++ constants are documented in `ffi.cpp` comments. The report serves as the centralized cross-reference.

2. **No separate "Phase I summary" doc**: The Phase I plan mentions updating `PHASE_I_IMPLEMENTATION_PLAN.md` itself. Phase 3.4 does not modify the plan (it's a completed plan, not a living doc). Instead, the Phase 3.4 report serves as the Phase I completion summary. **Reason**: The plan is a historical record of what was designed. The reports are the record of what was implemented. Keeping them separate avoids confusion.

No other deviations.

---

## 6. Key Variables and Functions

### 6.1 `test_same_config_same_touch_bitmap` (test_determinism.py)

- **What**: Runs the same mutation config twice, asserts the two touch bitmaps are byte-equal.
- **Why**: Validates the entire touch pipeline is deterministic: C++ marking, FNV-1a hashing, bitmap accumulation, base64 encoding, Python decoding. If the bitmaps differ, something is non-deterministic (thread ordering, unstable pointer addresses in hashing, etc.).
- **Why as a separate test**: Follows the existing pattern (each test is independent, has its own r1/r2 runs). Could share runs with the failure tests for efficiency, but independent tests are simpler and avoid coupling.

### 6.2 `fnv1a_touch_hash(loc, major, minor)` (touch_coverage.py, optional)

- **What**: Python implementation of the same FNV-1a hash as C++.
- **Why**: Enables mapping a (loc, major, minor) tuple to a bitmap index in Python. Useful for: "which bitmap bucket does `MemoryWrite@mem.zir:99` with major=0, minor=7 map to?" or "given bucket #1234 is hot, which contexts could map there?"
- **Why optional**: Phase I doesn't need inverse mapping. The bitmap is opaque for merge and new-bit counting.

---

## 7. Phase 3.4 Completion Checklist

- [ ] Step 3.4.1: Touch determinism test added to `test_determinism.py`.
- [ ] Step 3.4.2: `A4_COVERAGE_TOUCH` documented in `README.md`.
- [ ] Step 3.4.3: Centralized constants reference in Phase 3.4 report.
- [ ] Step 3.4.4 (optional): `fnv1a_touch_hash` in `touch_coverage.py`.
- [ ] Step 3.4.5: All tests pass (unit + determinism).
- [ ] No changes to C++, executor, fuzzer, or DB.
- [ ] Phase I is complete after this phase.

---

## 8. Phase I Completion (What Phase 3.4 Closes)

Phase 3.4 is the final phase of Phase I. After it is complete:

- **Stable IDs**: `context_id()` = `(constraint_loc(), major, minor)` — established in Phase 0.1.
- **Determinism**: Same config → same failures and same touch bitmap — tested in Phase 0.1 (failures) and Phase 3.4 (touch).
- **Baseline**: Unmutated run produces zero failures — confirmed in Phase 0.2.
- **Key-space sizing**: 1599 distinct touch buckets in a 65536 bitmap, ~2.4% occupancy, ~19.5 expected collisions — measured in Phase 3.2, documented in Phase 3.4.
- **C++ instrumentation**: Every `eqz` call marks a touch in a 64KB bitmap via FNV-1a hash — Phase 3.1.
- **C++ emission**: Bitmap serialized as base64 in `<a4_touch_coverage>` tag — Phase 3.2.
- **Python parsing**: `parse_touch_bitmap` decodes the bitmap; `count_new_bits`/`merge_into_global` provide AFL-style merge — Phase 3.2.
- **Executor wiring**: `A4_COVERAGE_TOUCH=1` set automatically; `MutationExecutionResult.touch_bitmap` populated — Phase 3.2.
- **Fuzzer integration**: `new_touch` per run; `global_touch_bitmap` across campaign; stats in summary — Phase 3.3.
- **Documentation**: Constants, hash, encoding, bitmap semantics in one place — Phase 3.4.
- **Tests**: Failure determinism (Phase 0.1), baseline zero-failures (Phase 0.2), touch parser unit tests (Phase 3.2), touch determinism (Phase 3.4).

Phase II (scheduling, corpus, bandits, rarity) can now build on this infrastructure.

---

## 9. For Anyone New: What Phase 3.4 Is and Why

### What

Phase 3.4 is the **documentation and testing completion** phase. It does two things:

1. **Touch determinism test**: A test that runs the same mutation twice and asserts the touch bitmap is byte-identical both times. This validates that the entire pipeline (C++ instrumentation → hashing → bitmap → base64 → Python decode) is deterministic and reliable.

2. **Centralized documentation**: A single reference that lists all the constants, the hash function, the encoding format, and the bitmap semantics, so anyone working on Phase II knows exactly how the touch coverage system works without reading six different phase reports.

### Why this way

- **Testing last**: Testing and documentation come after implementation because they validate and describe what was built. You can't write a determinism test for touch until the bitmap exists (Phase 3.1), is emitted (Phase 3.2), and is consumed (Phase 3.3).
- **Centralized doc in the final report**: Rather than creating yet another standalone markdown, the constants reference lives in the Phase 3.4 report — which is the natural "Phase I completion" document. Anyone looking for "how does touch coverage work?" can start here and follow links to individual phase reports for details.

### How Phase 3.4 differs from the other phases

| Phase | What it does | Nature |
|-------|-------------|--------|
| **0.1** | Stable IDs, failure determinism test | Foundation |
| **0.2** | Baseline, key-space measurement | Measurement |
| **3.1** | C++ bitmap + hash + touch marking | C++ instrumentation |
| **3.2** | C++ emission + Python parser + executor wiring | Cross-language bridge |
| **3.3** | Fuzzer consumes touch data | Fuzzer integration |
| **3.4** (this) | Touch determinism test + centralized docs | **Validation and documentation** |

Phase 3.4 is the only phase that produces no new runtime functionality. Every previous phase added behavior (a function, a field, a print line). Phase 3.4 adds a test and a document. Its value is ensuring correctness and making the system understandable for future work.

---

## 10. New and Withheld Sections Compared to Previous Plans

**New sections**:

- **§8 (Phase I Completion)**: Added because Phase 3.4 is the final phase of Phase I. This section summarizes what the complete Phase I delivers. Previous plans did not need this because they were mid-sequence.

**Sections retained**: All section types from Phase 3.3 plan are present.

**Sections withheld**: None.

---

*End of Phase 3.4 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*
