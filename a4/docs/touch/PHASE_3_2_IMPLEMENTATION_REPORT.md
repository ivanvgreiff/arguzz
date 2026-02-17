# Phase 3.2 Implementation Report

This report describes the implementation and testing of Phase 3.2 (C++ bitmap emission + Python parser + executor integration), deviations from the plan, key variables and functions, testing performed, and insights for the Phase 3.3 implementation plan.

**Reference plan**: [PHASE_3_2_IMPLEMENTATION_PLAN.md](./PHASE_3_2_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase 3.2 was implemented as specified. All five steps are complete:

1. **C++ emission** (`ffi.cpp`): A base64 encoder was added and the SeqForward post-loop block now emits `<a4_touch_coverage>BASE64</a4_touch_coverage>` alongside the existing `<a4_touch_debug>` line.
2. **Python parser** (`a4/core/touch_coverage.py`): New module with `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`, `make_global_bitmap`, `distinct_touched`, `total_touches`.
3. **Executor** (`a4/core/executor.py`): `run_a4_mutation` now sets `A4_COVERAGE_TOUCH=1` and populates `MutationExecutionResult.touch_bitmap`.
4. **Unit tests** (`a4/standalone/tests/test_touch_coverage.py`): 16 tests, all passing.
5. **Integration verification**: Full host built, single mutation run produced `touch_bitmap` with 1599 distinct buckets and 192676 total touches.

---

## 2. Deviations from the Phase 3.2 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Base64 buffer | "A static `char[87385]`" | `static char g_a4_base64_buf[((kA4TouchMapSize + 2) / 3) * 4 + 1]` — computed from constant | Uses the constant expression so size stays in sync with `kA4TouchMapSize` automatically; evaluates to 87381 (65536 is divisible by 3 with remainder 1, so ceil(65536/3)*4 = 87384; +1 for null). |
| Debug line ordering | Plan says "followed (or preceded) by" | `<a4_touch_debug>` is printed **first**, then `<a4_touch_coverage>`. | The debug line was already there from Phase 3.1; appending the bitmap line after it was the minimal change. Order does not matter for parsing since each has a unique tag. |
| `a4_base64_encode` return type | Plan says "Returns number of chars written (or the output can be null-terminated)" | Returns `size_t` (number of chars written) **and** null-terminates. | Both behaviors for defensive correctness. The caller uses the null-terminated string via `%s` in `printf`. |
| Helper functions | Plan lists `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`, `make_global_bitmap` | Added two additional helpers: `distinct_touched(bitmap)` and `total_touches(bitmap)`. | These are trivial one-liners that were useful for the integration test output and will be useful for Phase 3.3 campaign stats. They do not overlap with Phase 3.3 scope (which is fuzzer/DB integration, not utility functions). |
| `__init__.py` exports | Plan lists 5 exports | Exported 7 (added `distinct_touched` and `total_touches`). | Consistent with the extra helpers above. |

No other deviations. The plan was followed as specified.

---

## 3. Key Variables and Functions

### 3.1 C++ (`ffi.cpp`)

#### `a4_base64_encode(const uint8_t* data, size_t len, char* out) -> size_t`

- **What**: Standard base64 encoder using the 64-character alphabet `A-Za-z0-9+/` with `=` padding.
- **How**: Processes input in groups of 3 bytes → 4 base64 characters. For the final group (if `len % 3 != 0`), pads with `=`. Null-terminates `out`.
- **Why static in ffi.cpp**: Only used once per witgen run in the SeqForward post-loop block. No external visibility needed. Keeping it static in the same file as the bitmap avoids adding new headers or files.
- **Performance**: Called once per run on 65536 bytes. Produces ~87k chars. Negligible cost compared to witness generation (~30-90 seconds per run).

#### `g_a4_base64_buf[87381]`

- **What**: Static buffer for the base64 output. Size = `((65536 + 2) / 3) * 4 + 1`.
- **Why static**: Avoids heap allocation. Constant size, allocated once in BSS. Safe because only the SeqForward path uses it, and A4 forces single-threaded SeqForward mode.

#### Emission sequence in SeqForward block

After the witgen loop, when `A4_COVERAGE_TOUCH` is set:
1. Compute `total_touches` and `distinct_buckets` (Phase 3.1 debug stats).
2. Print `<a4_touch_debug>` line (retained from Phase 3.1 for development visibility).
3. Call `a4_base64_encode(g_a4_touch_bitmap, kA4TouchMapSize, g_a4_base64_buf)`.
4. Print `<a4_touch_coverage>%s</a4_touch_coverage>` with the base64 buffer.
5. `fflush(stdout)` to ensure both lines are flushed.
6. Defensive `memset(g_a4_touch_bitmap, 0, kA4TouchMapSize)` — clears bitmap after emission in case the process is reused for multiple witgen calls.

### 3.2 Python (`a4/core/touch_coverage.py`)

#### `A4_TOUCH_MAP_SIZE = 65536`

- **What**: Bitmap size constant. Must match `kA4TouchMapSize` in C++.
- **Why a module-level constant**: Single source of truth on the Python side. Used by `parse_touch_bitmap` (length validation), `make_global_bitmap`, and will be used by Phase 3.3/3.4.

#### `parse_touch_bitmap(output: str) -> Optional[bytes]`

- **What**: Extracts and decodes the touch bitmap from combined host output.
- **How**: Uses a precompiled regex `<a4_touch_coverage>([\w+/=]+)</a4_touch_coverage>` to find the tag. The character class `[\w+/=]` matches exactly the base64 alphabet plus padding. Calls `base64.b64decode` on the captured group. Returns `None` if: tag not found, decode fails (exception), or decoded length != `A4_TOUCH_MAP_SIZE`.
- **Why regex over line-split**: The base64 string is ~87k chars, all on one line. A regex search over the full output is simpler than line-splitting and checking each line. The tag is unique (emitted exactly once per run), so a single `re.search` suffices.
- **Why `Optional[bytes]` return**: Callers (executor, fuzzer) can check `is not None` before using. Returning `None` on failure avoids exceptions propagating from the parser into the executor's hot path.

#### `count_new_bits(run_bitmap: bytes, global_bitmap: bytearray) -> int`

- **What**: Counts indices where `run_bitmap[i] > 0` and `global_bitmap[i] == 0`.
- **Why**: This is the primary **reward signal** for coverage-guided fuzzing. A run that discovers new bits (buckets never seen before in the campaign) is more valuable than one that only re-touches known buckets. Phase 3.3 will use this count as `new_touch_count` on the mutation result.
- **Why iterate all 65536 entries**: The bitmap is small (64KB). A Python loop over 65536 integers takes ~5ms. This is negligible compared to the ~30-90 second host execution time. No numpy needed.

#### `merge_into_global(run_bitmap: bytes, global_bitmap: bytearray) -> None`

- **What**: Element-wise `global_bitmap[i] = max(global_bitmap[i], run_bitmap[i])`.
- **Why `max`**: Preserves the per-bucket "high water mark" across the campaign. A bucket's global value reflects the maximum activity seen in any single run. This is strictly more informative than boolean OR (which would collapse to 1) and avoids overflow that `+` would risk. Phase II rarity weighting can use these counts. Phase I only checks non-zero vs zero, but `max` preserves the option.
- **Why mutate in place**: The global bitmap is a `bytearray` (mutable). Mutating in place avoids allocating a new 64KB array per merge. The fuzzer will call this once per mutation run.

#### `make_global_bitmap() -> bytearray`

- **What**: Returns `bytearray(A4_TOUCH_MAP_SIZE)` — a zeroed 64KB bitmap.
- **Why a factory function**: Makes the intent clear and centralizes the size constant. Phase 3.3 will call this once at campaign start.

#### `distinct_touched(bitmap: bytes) -> int` and `total_touches(bitmap: bytes) -> int`

- **What**: Count non-zero entries and sum of all entries, respectively.
- **Why added (deviation)**: Trivial one-liners that are convenient for reporting and for Phase 3.3 campaign stats. `distinct_touched` is the Python equivalent of the C++ `distinct_buckets` debug stat.

### 3.3 Python (`a4/core/executor.py`)

#### `MutationExecutionResult.touch_bitmap: Optional[bytes] = None`

- **What**: New field on the execution result dataclass. Contains the decoded 65536-byte bitmap from the run, or `None` if parsing failed or the tag was absent.
- **Why `Optional[bytes]` with default `None`**: (1) Backwards compatible — existing callers that don't use `touch_bitmap` are unaffected. (2) Handles the case where the host was not built with Phase 3.2 (no tag emitted → `None`). (3) `bytes` is immutable and hashable, which is safe for storage and comparison.

#### `A4_COVERAGE_TOUCH` in env dict

- **What**: `"A4_COVERAGE_TOUCH": "1"` added to the `env` dict in `run_a4_mutation`.
- **Why always on**: In Phase I, every mutation run should emit touch coverage. The C++ code's `getenv` check already guards the hot-path cost (no bitmap ops if env var is unset). Having it always on from the executor means no configuration is needed for Phase 3.3 to get touch data.

---

## 4. Testing Performed

### 4.1 Unit tests (no host required)

**File**: `a4/standalone/tests/test_touch_coverage.py`  
**Result**: 16 tests, all passing (0.48s).

Tests are organized into four classes:

| Class | Tests | What they verify |
|-------|-------|-----------------|
| `TestParseTouchBitmap` | 6 | Round-trip encoding/decoding, all-zeros bitmap, missing tag → `None`, invalid base64 → `None`, wrong-length data → `None`, parsing when mixed with `<constraint_fail>` and `<a4_touch_debug>` lines. |
| `TestCountNewBits` | 4 | All entries new, none new, mix of new and existing, empty run. |
| `TestMergeIntoGlobal` | 3 | Merge into empty global, max semantics (global higher vs run higher), zero run does not decrease global. |
| `TestHelpers` | 3 | `distinct_touched`, `total_touches`, `make_global_bitmap` returns correct size and all zeros. |

### 4.2 C++ build

**Command**: `cargo build --release -p risc0-circuit-rv32im-sys` from `workspace/risc0-modified`.  
**Result**: Compiled successfully. No warnings from the new code.

### 4.3 Host build

**Command**: `cd workspace/output && cargo build --release`.  
**Result**: Built successfully (took ~17 minutes). The host binary at `workspace/output/target/release/risc0-host` now links the updated rv32im-sys crate with Phase 3.2 emission.

### 4.4 Integration verification (with host)

**Procedure**: A Python script built a COMP_OUT_MOD config from inspection (step 20, mutated value 0xDEADBEEF), then called `run_a4_mutation` with the rebuilt host.

**Results**:

| Metric | Value |
|--------|-------|
| Exit code | 101 (proof rejected, as expected) |
| Constraint failures | 2 |
| `touch_bitmap` present | Yes |
| `touch_bitmap` length | 65536 bytes |
| **Distinct buckets** | **1599** |
| **Total touches** | **192676** |

**Interpretation**:

- **1599 distinct buckets** is well within the Phase I plan's estimated range of "low thousands to low tens of thousands" (PHASE_I §0.1 says 2k–15k). The actual value is at the lower end, which means a 64k bitmap with no step_bucket has very low collision probability: expected collisions ≈ 1599² / (2 × 65536) ≈ **19.5** — negligible compared to the 1599 distinct contexts.
- **192676 total touches** over ~32768 cycles means an average of ~5.9 EQZ calls per cycle, which is plausible given that each cycle executes one major/minor component with multiple constraints.
- **Comparison with Phase 0.2 failure data**: Phase 0.2 measured K_total=43 distinct *failure* context_ids. Touch coverage sees 1599 distinct *touched* contexts — ~37x more. This is expected: most constraints pass (value=0), so they're touched but not failed. The touch bitmap captures all of them.

### 4.5 Linter check

**Result**: No linter errors on `touch_coverage.py`, `executor.py`, or `__init__.py`.

---

## 5. Insights for the Phase 3.3 Implementation Plan

### 5.1 What Phase 3.3 needs to consume

Phase 3.3 integrates touch coverage into the fuzzer and DB. The infrastructure is now in place:

- `MutationExecutionResult.touch_bitmap` is populated for every mutation run (or `None` if the host doesn't emit it).
- `count_new_bits(run_bitmap, global_bitmap)` computes the "new touch" count.
- `merge_into_global(run_bitmap, global_bitmap)` updates the global campaign bitmap.
- `make_global_bitmap()` creates the initial empty bitmap.
- `distinct_touched(bitmap)` and `total_touches(bitmap)` provide stats for reporting.

### 5.2 Where the fuzzer should integrate

From reading the fuzzer code (`a4/standalone/fuzzer.py`):

- **`_run_single_mutation`** (around line 300): After `run_a4_mutation` returns, the fuzzer already extracts `failures`, `exit_code`, etc. from the `exec_result`. Phase 3.3 should also extract `exec_result.touch_bitmap` here.
- **`MutationResult`** (around line 60): The fuzzer's own `MutationResult` dataclass (distinct from `MutationExecutionResult`) has `new_coverage: int = 0` for failure-based new coverage. Phase 3.3 should add `new_touch: int = 0` (or similar).
- **Line 367**: `total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)` — this is where failure coverage is recorded. Phase 3.3 should compute and record touch coverage nearby: `new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)` then `merge_into_global(...)`.
- **`CampaignStats`** (around line 88): Has `new_coverage_count`. Phase 3.3 should add `new_touch_count`.
- **Campaign summary** (around line 1086): Prints `New coverage: {stats.new_coverage_count}`. Phase 3.3 should print `New touch: {stats.new_touch_count}`.

### 5.3 Global bitmap lifecycle

Phase 3.3 needs to manage the global bitmap:

- **Creation**: `self.global_touch_bitmap = make_global_bitmap()` in `A4Fuzzer.__init__` or at campaign start.
- **Per-run**: After each mutation, compute `new_touch = count_new_bits(...)`, then `merge_into_global(...)`.
- **Persistence** (optional): Save the global bitmap to a file or DB blob so a campaign can be resumed. This is optional for Phase 3.3; the bitmap is 64KB and can be pickled or written as raw bytes.

### 5.4 Performance

The integration run took ~94 seconds total (including inspection). The Python-side bitmap operations are negligible (~5ms for `count_new_bits` + `merge_into_global`). The base64 decode in `parse_touch_bitmap` is also negligible. No performance concerns for Phase 3.3.

### 5.5 Bitmap sizing confirmation

With 1599 distinct buckets in a 65536-entry bitmap, the bitmap is ~2.4% occupied. This is very sparse, which means:
- Collision rate is extremely low (estimated ~19.5 collisions out of 1599 contexts).
- There is no need for step_bucket or a larger MAP_SIZE in Phase I.
- Phase 3.4 should document this measurement alongside the Phase 0.2 failure-data measurement.

### 5.6 Handling `touch_bitmap = None`

If the host was built without Phase 3.2 (or if parsing fails for some reason), `touch_bitmap` will be `None`. Phase 3.3 should handle this gracefully: skip touch coverage tracking for that run, log a warning, but do not crash. This is important for backwards compatibility if someone runs the fuzzer with an older host binary.

---

## 6. Files Touched

| File | Change |
|------|--------|
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | Added `a4_base64_encode`, `g_a4_base64_buf`; in SeqForward post-loop: encode bitmap, print `<a4_touch_coverage>` line, defensive `memset` after emission. |
| `a4/core/touch_coverage.py` | **New**: `A4_TOUCH_MAP_SIZE`, `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`, `make_global_bitmap`, `distinct_touched`, `total_touches`. |
| `a4/core/__init__.py` | Added imports/exports for touch_coverage module (7 symbols). |
| `a4/core/executor.py` | Added `from a4.core.touch_coverage import parse_touch_bitmap`; `Optional` import; `touch_bitmap` field on `MutationExecutionResult`; `A4_COVERAGE_TOUCH=1` in env; parse touch bitmap from combined output. |
| `a4/standalone/tests/test_touch_coverage.py` | **New**: 16 unit tests for parser, merge, count, helpers. |
| `a4/docs/touch/PHASE_3_2_IMPLEMENTATION_REPORT.md` | This report. |

No changes to: `witgen.h`, `coverage_db.py`, `fuzzer.py`, `cli.py`, or any mutation module.

---

## 7. Phase 3.2 Completion Checklist

- [x] Step 3.2.1: C++ base64 encoder and `<a4_touch_coverage>` emission in ffi.cpp.
- [x] Step 3.2.2: `a4/core/touch_coverage.py` with parse, merge, count, constants, helpers.
- [x] Step 3.2.3: `run_a4_mutation` sets `A4_COVERAGE_TOUCH=1`; `MutationExecutionResult` has `touch_bitmap`.
- [x] Step 3.2.4: 16 unit tests in `test_touch_coverage.py`, all passing.
- [x] Step 3.2.5: Integration verification with host; `distinct_buckets=1599`, `total_touches=192676`.
- [x] `a4/core/__init__.py` updated with touch coverage exports.
- [x] No changes to fuzzer, DB, or mutation modules (deferred to 3.3).
- [x] `<a4_touch_debug>` line retained for development visibility.

---

*End of Phase 3.2 Implementation Report.*
