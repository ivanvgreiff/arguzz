# Phase 3.2 Detailed Implementation Plan

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase 3.2** (C++ bitmap emission + Python parser + executor integration). It is consistent with [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) §3.3–3.5 and §4, and incorporates all takeaways from the [PHASE_3_1_IMPLEMENTATION_REPORT.md](./PHASE_3_1_IMPLEMENTATION_REPORT.md) §6 (Insights for Phase 3.2).

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites from Phase 3.1 and Earlier Phases

### 1.1 What Phase 3.1 delivered (source-of-truth)

| Artifact | Location | Status |
|----------|----------|--------|
| `kA4TouchMapSize = 65536` | `ffi.cpp` line 56 (inside `namespace risc0::circuit::rv32im_v2::cpu`) | Implemented |
| `g_a4_touch_bitmap[kA4TouchMapSize]` | `ffi.cpp` line 57 | Implemented |
| `a4_touch_hash(loc, major, minor)` — FNV-1a, offset=2166136261u, prime=16777619u | `ffi.cpp` lines 60–71 | Implemented |
| `a4_touch_mark(ctx, loc)` — env check, hash, saturating increment | `ffi.cpp` lines 73–83 | Implemented |
| Declaration: `void a4_touch_mark(ExecContext&, const char*)` | `witgen.h` line 179 | Implemented |
| Call: `a4_touch_mark(ctx, loc)` at entry of `eqz(ExecContext&, Val, const char*)` | `witgen.h` line 182 | Implemented |
| Clear bitmap: `memset` before SeqForward loop when `A4_COVERAGE_TOUCH` set | `ffi.cpp` lines 346–347 | Implemented |
| Debug print: `<a4_touch_debug>` with `total_touches` and `distinct_buckets` after loop | `ffi.cpp` lines 351–362 | Implemented (temporary; Phase 3.2 replaces or augments) |

### 1.2 Phase 3.1 report insights that Phase 3.2 must address

From PHASE_3_1_IMPLEMENTATION_REPORT.md §6:

1. **Emission format**: Replace/augment `<a4_touch_debug>` with `<a4_touch_coverage>...</a4_touch_coverage>` containing the serialized bitmap.
2. **Hash and MAP_SIZE**: Python must agree on MAP_SIZE=65536 and use the same constants if inverse mapping is ever needed.
3. **When to emit**: After SeqForward loop; clear bitmap after emission.
4. **Executor**: Set `A4_COVERAGE_TOUCH=1` alongside `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`.
5. **Debug line**: Keep or remove `<a4_touch_debug>`. If kept alongside `<a4_touch_coverage>`, Python should only parse the latter.
6. **ExtVal overcount**: Document that bitmap bucket counts are upper bounds.

### 1.3 Phase 0 takeaways relevant to 3.2

| Takeaway | Implication |
|----------|-------------|
| K_total (failure data) = 43; per-run max = 9 (Phase 0.2 report) | Failure key space is tiny. Touch key space will be larger (all EQZ calls, not just failing ones). Phase 3.2 should report `distinct_buckets` from the first real run to verify bitmap sizing. |
| `context_id()` = `(constraint_loc(), major, minor)` (Phase 0.1) | Python normalizes raw `loc` via `short_loc()` → `constraint_loc()`. For bitmap merge, Python works with raw byte indices; normalization only needed when mapping a bucket back to a human-readable context (Phase 3.4 or Phase II). |
| Baseline = zero failures, but non-zero touches expected | Once touch is emitted, baseline runs (`run_baseline`) can also set `A4_COVERAGE_TOUCH=1` to capture the baseline touch set for later comparison. This is noted in Phase 0.2 §0.2.5. |
| `run_a4_mutation` sets only `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE` | `executor.py` lines 175–178. Phase 3.2 adds `A4_COVERAGE_TOUCH` to this env dict. |

### 1.4 What Phase 3.2 does not do (left to 3.3–3.4)

- **Phase 3.3**: Fuzzer/DB integration — record `new_touch_count` per run, optionally persist global bitmap, update `MutationResult` and `CampaignStats`.
- **Phase 3.4**: Centralized constants doc (MAP_SIZE, hash name); determinism test for touch (same mutation → same bitmap).

Phase 3.2 **must not** modify the fuzzer, the DB schema, or `MutationResult`. It only provides the infrastructure (C++ emission + Python parser + executor env) that Phase 3.3 will consume.

---

## 2. Source-of-Truth Facts for Phase 3.2

### 2.1 C++ emission point (already confirmed in Phase 3.1)

| Fact | Location |
|------|----------|
| SeqForward block with touch debug | `ffi.cpp` lines 345–363: `case kStepModeSeqForward: { ... }` with clear before loop, debug print after loop. |
| Bitmap is `g_a4_touch_bitmap[kA4TouchMapSize]` (65536 bytes) | `ffi.cpp` line 57. |
| After the loop, bitmap holds per-run touch data; cleared at start of next run | `ffi.cpp` lines 346–347 (clear) and 351–362 (debug print). |

### 2.2 Python executor (where env vars are set)

| Fact | Location |
|------|----------|
| `run_a4_mutation` builds env with `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE` | `a4/core/executor.py` lines 175–178: `env = {"A4_MUTATION_CONFIG": str(config_path), "CONSTRAINT_CONTINUE": "1"}` |
| Env is merged with `os.environ` via `{**dict(os.environ), **env}` | `executor.py` line 184 |
| Combined output is `result.stdout + result.stderr` | `executor.py` line 187 |
| Failures are parsed from combined output | `executor.py` line 188: `failures = parse_all_constraint_failures(combined)` |

### 2.3 Python constraint parser (pattern for tag parsing)

| Fact | Location |
|------|----------|
| `<constraint_fail>` tags are parsed with regex from line-split output | `a4/core/constraint_parser.py` lines 33–51: `ConstraintFailure.parse(line)` |
| `parse_all_constraint_failures(output)` iterates lines | `constraint_parser.py` lines 150–152 |
| `a4/core/__init__.py` re-exports `ConstraintFailure` and `parse_all_constraint_failures` | `__init__.py` lines 34–37 |

### 2.4 Encoding choice: base64

The bitmap is 65536 bytes. Encoding options:

- **Base64**: ~87382 chars (65536 × 4/3), single line, no delimiters within, standard Python `base64` module.
- **Hex**: 131072 chars, simple but twice the size.
- **Comma-separated decimal**: Variable length, harder to parse.
- **Raw binary in stdout**: Not feasible; stdout is text mode.

**Choice**: Base64. It is well-supported in both C++ (we implement a minimal encoder or use a 4-line lookup table) and Python (`base64.b64decode`), and produces a single unambiguous line.

---

## 3. Step-by-Step Implementation Plan

### Step 3.2.1: C++ — Replace debug print with bitmap emission

**Goal**: After the SeqForward witgen loop, serialize `g_a4_touch_bitmap` to stdout as `<a4_touch_coverage>BASE64_DATA</a4_touch_coverage>` when `A4_COVERAGE_TOUCH` is set.

**Facts**:

- The debug print block is at `ffi.cpp` lines 351–362, inside `if (std::getenv("A4_COVERAGE_TOUCH") != nullptr)`.
- `g_a4_touch_bitmap` is `uint8_t[65536]`.
- No external base64 library is available in this C++ translation unit. We need a small inline base64 encoder (standard lookup table, ~20 lines of code).

**Actions**:

1. In `ffi.cpp`, add a small static helper function `a4_base64_encode(const uint8_t* data, size_t len, char* out)` that encodes `len` bytes of `data` into base64 at `out`. Use the standard base64 alphabet (`A-Za-z0-9+/`) with `=` padding. This is a well-known algorithm; no external dependency.
2. In the SeqForward `if (A4_COVERAGE_TOUCH)` block after the loop:
   - Keep the existing `<a4_touch_debug>` line for development visibility (the Phase 3.1 report §6.5 says "keep both during development"). Python parser will ignore it.
   - Compute the base64 encoding of `g_a4_touch_bitmap[0..kA4TouchMapSize-1]`. Output buffer size = `((kA4TouchMapSize + 2) / 3) * 4 + 1` (87382 chars + null).
   - Print: `printf("<a4_touch_coverage>%s</a4_touch_coverage>\n", base64_buf);` and `fflush(stdout);`.
   - No bitmap clear here; bitmap is already cleared at the *start* of the next run (line 347). However, if the host process is ever reused for multiple witgen calls, Phase 3.2 should also clear after emission. Add `memset(g_a4_touch_bitmap, 0, kA4TouchMapSize);` after the print, guarded by the same env check. This is defensive and does not affect the single-run case.

**Deliverable**: After the SeqForward loop, stdout contains a `<a4_touch_coverage>` line with the full bitmap in base64, followed (or preceded) by the existing `<a4_touch_debug>` line.

---

### Step 3.2.2: Python — New touch coverage parser module

**Goal**: Parse `<a4_touch_coverage>BASE64_DATA</a4_touch_coverage>` from combined output, decode the bitmap, and provide a merge utility that computes "new touch bits" against a global bitmap.

**Facts**:

- The tag and encoding are defined in Step 3.2.1. Python has `base64.b64decode`.
- PHASE_I_IMPLEMENTATION_PLAN.md §3.4 recommends: new `a4/core/touch_coverage_parser.py` (or extend `constraint_parser.py`). A separate module is cleaner because:
  - `constraint_parser.py` is focused on `<constraint_fail>` lines.
  - Touch coverage is a bitmap (bytes), not a list of parsed records.
  - Separate module avoids overloading `constraint_parser.py` and keeps `a4/core/__init__.py` exports clean.
- Phase I does not require mapping bitmap indices back to (constraint_loc, major, minor). That is noted for Phase II (PHASE_I §3.4). So the parser only needs to decode bytes and do merge arithmetic.

**Actions**:

1. Create `a4/core/touch_coverage.py` (naming: `touch_coverage` rather than `touch_coverage_parser` for brevity; the module both parses and merges).
2. Contents:
   - `A4_TOUCH_MAP_SIZE = 65536` — must match C++ `kA4TouchMapSize`.
   - `parse_touch_bitmap(output: str) -> Optional[bytes]`: Search `output` for `<a4_touch_coverage>...</a4_touch_coverage>` (regex, single occurrence). If found, base64-decode the inner content and return bytes of length `A4_TOUCH_MAP_SIZE`. If not found or decode fails, return `None`.
   - `count_new_bits(run_bitmap: bytes, global_bitmap: bytearray) -> int`: Count indices where `run_bitmap[i] > 0` and `global_bitmap[i] == 0`. This is the "new touch" count for the run.
   - `merge_into_global(run_bitmap: bytes, global_bitmap: bytearray) -> None`: For each index, `global_bitmap[i] = max(global_bitmap[i], run_bitmap[i])` (element-wise max, or saturating union). Mutates `global_bitmap` in place.
   - `make_global_bitmap() -> bytearray`: Return `bytearray(A4_TOUCH_MAP_SIZE)` — a zeroed global bitmap.
3. Update `a4/core/__init__.py` to export `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`, `make_global_bitmap`, `A4_TOUCH_MAP_SIZE`.

**Why `bytearray`**: It's mutable, fixed-size, and indexable by byte — exactly the AFL bitmap analog in Python. No numpy dependency needed.

**Deliverable**: `a4/core/touch_coverage.py` with parse, merge, and count utilities. Unit-testable without a host binary (feed a fake `<a4_touch_coverage>` line).

---

### Step 3.2.3: Python — Executor sets `A4_COVERAGE_TOUCH=1`

**Goal**: When `run_a4_mutation` is called, the environment includes `A4_COVERAGE_TOUCH=1` so the host emits the touch bitmap.

**Facts**:

- `run_a4_mutation` in `executor.py` lines 173–196 sets `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`.
- The combined output (line 187) already captures everything from stdout+stderr.
- `MutationExecutionResult` (lines 127–134) has `stdout`, `stderr`, `combined_output`, `exit_code`, `failures`.

**Actions**:

1. In `run_a4_mutation`, add `"A4_COVERAGE_TOUCH": "1"` to the `env` dict (line 175–178).
2. After parsing failures (line 188), also parse touch coverage:
   - `touch_bitmap = parse_touch_bitmap(combined)`
   - Store `touch_bitmap` on `MutationExecutionResult`. Add a new field: `touch_bitmap: Optional[bytes] = None`.
3. Update `MutationExecutionResult` (line 127) to include `touch_bitmap: Optional[bytes] = None` with a default of `None` so existing callers are unaffected.
4. Import `parse_touch_bitmap` from `a4.core.touch_coverage`.

**Why always set A4_COVERAGE_TOUCH**: In Phase I, every mutation run should emit touch coverage. There is no reason to make it optional at the executor level (the env var check in C++ already guards the hot-path cost). If a user later wants runs without touch, they can unset the env var in the environment before calling the executor, but the default should be "on."

**Deliverable**: `run_a4_mutation` sets `A4_COVERAGE_TOUCH=1`; `MutationExecutionResult` carries `touch_bitmap`.

---

### Step 3.2.4: Python — Unit test for the parser

**Goal**: Confirm that `parse_touch_bitmap` correctly decodes a known bitmap and that `count_new_bits` / `merge_into_global` produce correct results, without requiring a host binary.

**Facts**:

- Test can construct a fake output string containing a `<a4_touch_coverage>BASE64</a4_touch_coverage>` tag with known content.
- Existing test pattern: `a4/standalone/tests/test_determinism.py` uses `pytest.mark.skipif` for host-dependent tests; this unit test does not need the host.

**Actions**:

1. Create `a4/standalone/tests/test_touch_coverage.py`.
2. Tests:
   - **test_parse_known_bitmap**: Construct a 65536-byte array with a few non-zero entries at known positions, base64-encode it, wrap in `<a4_touch_coverage>...</a4_touch_coverage>`, call `parse_touch_bitmap`, assert decoded bytes match the original.
   - **test_parse_missing_tag**: Call `parse_touch_bitmap("some output without the tag")`, assert returns `None`.
   - **test_count_new_bits**: Create a run bitmap with non-zero at positions {0, 5, 100} and a global with non-zero at {5}. `count_new_bits` should return 2 (positions 0 and 100 are new).
   - **test_merge_into_global**: After merge, global should have non-zero at {0, 5, 100}; global[5] should be `max(old, run)`.
3. Run with `python -m pytest a4/standalone/tests/test_touch_coverage.py -v`.

**Deliverable**: Unit tests that validate the parser and merge logic independently of the C++ code.

---

### Step 3.2.5: Integration verification (with host)

**Goal**: Build the full host with Phase 3.1+3.2 C++ changes, run one mutation via the Python executor, and confirm that `MutationExecutionResult.touch_bitmap` is non-None and has non-zero entries.

**Facts**:

- Building the host requires `cargo build --release` from the workspace that links `risc0-circuit-rv32im-sys`.
- The executor's combined output will now contain `<a4_touch_coverage>` alongside `<constraint_fail>` and `<a4_touch_debug>` lines.

**Actions**:

1. Build host: `cd workspace/output && cargo build --release` (or the appropriate workspace).
2. Run a single mutation from Python:
   ```python
   from a4.core.executor import run_a4_mutation
   result = run_a4_mutation(host_binary, host_args, config_path)
   assert result.touch_bitmap is not None
   assert sum(result.touch_bitmap) > 0
   ```
3. Report `distinct_buckets` = count of non-zero bytes in `result.touch_bitmap`. Compare with Phase I plan's estimated range (2k–15k) to validate bitmap sizing.
4. Optionally run `run_baseline` with `A4_COVERAGE_TOUCH=1` set in the environment and confirm touch bitmap is non-None and has non-zero entries (baseline touch set).

**Deliverable**: One integration run shows `touch_bitmap` parsed correctly; `distinct_buckets` reported and compared with plan estimates.

---

## 4. Source-of-Truth Facts for Encoding (Base64 in C++)

C++ does not have a standard base64 encoder. The implementation is straightforward:

- **Alphabet**: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- **Algorithm**: Process input in groups of 3 bytes → 4 base64 chars. Pad with `=` if input length is not a multiple of 3.
- **Output size**: For 65536 bytes: `ceil(65536/3) * 4 = 87384` chars, plus null terminator.
- **Buffer**: A static `char[87385]` in `ffi.cpp` is fine (constant size, allocated once).

The encoder is a pure function (no state, no allocation) and is invoked once per witgen run, so performance is not a concern.

---

## 5. Files to Touch (Phase 3.2 only)

| File | Change |
|------|--------|
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | Add `a4_base64_encode` helper; in SeqForward post-loop block, encode and print `<a4_touch_coverage>BASE64</a4_touch_coverage>`; defensive `memset` after emission. |
| `a4/core/touch_coverage.py` | **New**: `A4_TOUCH_MAP_SIZE`, `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`, `make_global_bitmap`. |
| `a4/core/__init__.py` | Add imports/exports for `touch_coverage` module. |
| `a4/core/executor.py` | In `run_a4_mutation`: add `A4_COVERAGE_TOUCH=1` to env; parse `touch_bitmap` from output; add `touch_bitmap` field to `MutationExecutionResult`. |
| `a4/standalone/tests/test_touch_coverage.py` | **New**: Unit tests for parser, merge, count (no host required). |
| `a4/docs/touch/PHASE_3_2_IMPLEMENTATION_PLAN.md` | This plan. |

No changes to: `witgen.h`, `coverage_db.py`, `fuzzer.py`, `cli.py`, or any mutation module. Those are Phase 3.3 or Phase 3.4.

---

## 6. Alignment with PHASE_I_IMPLEMENTATION_PLAN.md

| Plan reference | Phase 3.2 coverage | Notes |
|----------------|---------------------|-------|
| §3.3 item 3 ("When to emit") | Step 3.2.1: emit after SeqForward loop; clear after emission. | Implemented. |
| §3.3 item 4 ("Optional: emit raw touch list for debugging") | Not implemented in 3.2. The `<a4_touch_debug>` line from 3.1 serves this purpose (total_touches, distinct_buckets). A verbose per-touch JSON list is deferred; the bitmap is the primary emission. | Deviation: plan suggests optional raw list; we keep the debug summary line instead. This is lighter weight and sufficient for debugging. |
| §3.4 ("Python: Parse Touch Coverage and Merge") | Step 3.2.2: `a4/core/touch_coverage.py` with parse, merge, count_new_bits. | As planned. |
| §3.4 ("No need to invert bitmap for basic merge") | Step 3.2.2: `count_new_bits` and `merge_into_global` operate on byte arrays without mapping indices to context_ids. | As planned. Inverse mapping deferred to Phase II. |
| §3.5 ("Executor sets A4_COVERAGE_TOUCH=1") | Step 3.2.3. | As planned. |
| §3.5 ("Fuzzer/DB record new touch count") | **Not in 3.2**; deferred to Phase 3.3. | As planned in the implementation order (§4 item 5). |
| §3.6 ("MAP_SIZE, B, hash in one place") | 3.2 defines `A4_TOUCH_MAP_SIZE = 65536` in Python. C++ has `kA4TouchMapSize`. Centralized doc is Phase 3.4. | As planned. |

### Deviations from higher-level planning

1. **No raw touch list emission**: PHASE_I §3.3 item 4 suggests an optional verbose mode emitting per-touch `(loc, step, major, minor)` as JSON. Phase 3.2 does not implement this. **Reason**: The `<a4_touch_debug>` summary line (total_touches, distinct_buckets) provides sufficient verification. A full per-touch JSON for 65536 cycles with many EQZ calls per cycle would be extremely large and slow to parse. If needed for debugging, it can be added later as a separate env var (e.g. `A4_COVERAGE_TOUCH_VERBOSE=1`) without changing the bitmap path.

2. **Base64 encoding**: PHASE_I §3.3 says "base64 or comma-separated bytes." Phase 3.2 uses base64. **Reason**: Comma-separated for 65536 bytes would be ~250k chars; base64 is ~87k chars and is a standard, self-contained format with no ambiguous delimiters.

3. **`touch_bitmap` on `MutationExecutionResult`**: The `MutationExecutionResult` dataclass (defined in `executor.py`) gets a new `Optional[bytes]` field. This is a small structural addition to a core dataclass. **Reason**: The touch bitmap is a direct product of running a mutation; it belongs on the execution result the same way `failures` does. Phase 3.3 will consume it.

No other deviations.

---

## 7. Key Variables and Functions

### 7.1 C++ (ffi.cpp)

- **`a4_base64_encode(const uint8_t* data, size_t len, char* out)`**  
  Static helper. Encodes `len` bytes into base64 at `out`. Uses the standard 64-char alphabet. Returns number of chars written (or the output can be null-terminated).

- **`<a4_touch_coverage>...</a4_touch_coverage>`**  
  The stdout line containing the base64-encoded bitmap. Exactly one such line is emitted per SeqForward witgen run when `A4_COVERAGE_TOUCH` is set.

### 7.2 Python (a4/core/touch_coverage.py)

- **`A4_TOUCH_MAP_SIZE = 65536`**  
  Must match `kA4TouchMapSize` in C++. Single source of truth for bitmap size on the Python side.

- **`parse_touch_bitmap(output: str) -> Optional[bytes]`**  
  Searches for `<a4_touch_coverage>...</a4_touch_coverage>` in `output`. Returns decoded bytes (length `A4_TOUCH_MAP_SIZE`) or `None`.

- **`count_new_bits(run_bitmap: bytes, global_bitmap: bytearray) -> int`**  
  Number of indices where `run_bitmap[i] > 0` and `global_bitmap[i] == 0`. This is the "new touch" count — the primary reward signal for Phase 3.3 / Phase II.

- **`merge_into_global(run_bitmap: bytes, global_bitmap: bytearray) -> None`**  
  Element-wise `global_bitmap[i] = max(global_bitmap[i], run_bitmap[i])`. Mutates in place.

- **`make_global_bitmap() -> bytearray`**  
  Returns a zeroed `bytearray(A4_TOUCH_MAP_SIZE)`.

### 7.3 Python (a4/core/executor.py)

- **`MutationExecutionResult.touch_bitmap: Optional[bytes]`**  
  New field. Contains the decoded bitmap from the run, or `None` if parsing failed or tag was absent.

- **`A4_COVERAGE_TOUCH` in env dict**  
  Added to `run_a4_mutation`'s `env` alongside `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`.

---

## 8. Phase 3.2 Completion Checklist

- [ ] Step 3.2.1: C++ base64 encoder and `<a4_touch_coverage>` emission in ffi.cpp.
- [ ] Step 3.2.2: `a4/core/touch_coverage.py` with parse, merge, count, constants.
- [ ] Step 3.2.3: `run_a4_mutation` sets `A4_COVERAGE_TOUCH=1`; `MutationExecutionResult` has `touch_bitmap`.
- [ ] Step 3.2.4: Unit tests in `test_touch_coverage.py` (no host required).
- [ ] Step 3.2.5: Integration verification with host; report `distinct_buckets` for one run.
- [ ] `a4/core/__init__.py` updated with touch coverage exports.
- [ ] No changes to fuzzer, DB, or mutation modules (deferred to 3.3).
- [ ] `<a4_touch_debug>` line retained for development visibility.

---

## 9. Dependencies for Phases 3.3–3.4 (reminders)

- **Phase 3.3**: Fuzzer consumes `MutationExecutionResult.touch_bitmap` to compute `new_touch_count` (using `count_new_bits`); updates `MutationResult.new_touch`; maintains a global bitmap in the `A4Fuzzer` instance; optionally persists global bitmap to DB or file for campaign restarts; updates `CampaignStats` with `total_new_touch`. This phase can also add a `new_touch_count` column to the `mutations` table if desired.
- **Phase 3.4**: Centralize MAP_SIZE (65536), hash function (FNV-1a), and encoding (base64) in one documentation location. Add a determinism test: run the same mutation config twice with `A4_COVERAGE_TOUCH=1`, parse both bitmaps, assert they are byte-equal. Optionally add the FNV-1a hash in Python for inverse mapping (bitmap index → approximate context_id) if needed for debugging.

---

## 10. For Anyone New: What Phase 3.2 Is and Why

### What

Phase 3.2 is the **bridge** between the C++ touch instrumentation (Phase 3.1) and the Python fuzzing framework (Phase 3.3). It does three things:

1. **C++ emission**: After the zkVM's witness-generation loop finishes, the 65536-byte "touch bitmap" — which records which constraint contexts were evaluated during this run — is serialized as a base64 string and printed to stdout inside a `<a4_touch_coverage>` XML-like tag.

2. **Python parsing**: A new Python module (`touch_coverage.py`) extracts that base64 line from the host's output, decodes it back into 65536 bytes, and provides utilities to merge it into a global campaign bitmap and count how many new constraint contexts this particular run discovered.

3. **Executor wiring**: The Python function that launches the host (`run_a4_mutation`) now sets the `A4_COVERAGE_TOUCH=1` environment variable so the host knows to emit the bitmap, and it stores the decoded bitmap on the execution result so downstream code can use it.

### Why this way

- **Why a bitmap?** The fuzzer can run hundreds or thousands of mutations. Tracking every individual constraint evaluation as a structured record would produce enormous data. An AFL-style bitmap is constant-size (64KB), fast to produce, fast to compare, and proven in coverage-guided fuzzing.

- **Why base64?** The host communicates with Python via stdout (text mode). Base64 is a compact, standard, single-line encoding for binary data.

- **Why a separate Python module?** Touch coverage is conceptually different from constraint *failure* parsing. Failures are individual records with rich metadata (cycle, step, pc, loc, value). Touch coverage is a raw bitmap with no per-entry metadata — it answers "was this hash bucket hit?" not "which specific constraint failed." Keeping them in separate modules maintains clean separation of concerns.

### How Phase 3.2 differs from the other phases

| Phase | What it does | Language |
|-------|-------------|----------|
| **0.1** | Stable constraint IDs, `context_id()`, determinism test | Python only |
| **0.2** | Baseline run, measure key space, bucket-necessity analysis | Python only |
| **3.1** | C++ bitmap + hash + `a4_touch_mark` in `eqz`; no emission to Python | C++ only |
| **3.2** (this) | C++ emission of bitmap; Python parser + merge; executor env wiring | **C++ + Python** (first cross-language phase) |
| **3.3** | Fuzzer/DB consume touch data; `new_touch_count` as reward signal | Python only (fuzzer integration) |
| **3.4** | Centralized docs; determinism test for touch bitmap | Python + docs |

Phase 3.2 is the first phase that spans **both** the C++ kernel code and the Python framework. It is the critical integration point: if the bitmap is not emitted correctly or not parsed correctly, Phase 3.3's reward signal will be wrong. That is why Phase 3.2 includes both unit tests (for the parser) and integration verification (with the host).

---

## 11. New and Withheld Sections Compared to Previous Plans

**New sections added**:

- **§10 (For Anyone New)**: Added per user request to explain Phase 3.2 in plain language for someone unfamiliar with the project. This section does not appear in previous plans because it was not requested.

**Sections retained from previous plans**:

- Prerequisites / takeaways from prior phases (§1) — same as Phase 3.1 plan §1.
- Source-of-truth facts (§2) — same pattern as all previous plans.
- Step-by-step implementation plan (§3) — same pattern.
- Files to touch (§5) — same pattern.
- Alignment / deviations from higher-level plan (§6) — same pattern.
- Key variables and functions (§7) — same pattern.
- Completion checklist (§8) — same pattern.
- Dependencies for future phases (§9) — same as Phase 3.1 plan §7.

**Sections withheld**:

- None. All section types present in the Phase 3.1 plan are present here. The encoding details (§4) are new to this plan because Phase 3.2 is the first phase that requires a serialization format; Phase 3.1 had no analog because it did not emit data.

---

*End of Phase 3.2 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*
