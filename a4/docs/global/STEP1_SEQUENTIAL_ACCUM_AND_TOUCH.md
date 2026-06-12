# Step 1: Sequential Accum Phase + Separate Touch Coverage

## Objective

Modify the RISC Zero accum phase to run sequentially when A4 is active, and add separate touch coverage infrastructure (bitmap + verbose) for accum (global) constraints, distinct from the existing local constraint coverage.

## Context

### Current State

The A4 local constraint hooking works via three mechanisms in `ffi.cpp` and `witgen.h`:

1. **`eqz()` in `witgen.h:181`**: Called by every `EQZ(val, loc)` macro. On failure, prints `<constraint_fail>` JSON. With `CONSTRAINT_CONTINUE=1`, returns instead of throwing.
2. **`a4_touch_mark()` in `ffi.cpp:106`**: Called by every `eqz()`. Updates `g_a4_touch_bitmap` and optionally `g_a4_touch_verbose_set`.
3. **Witgen sequential mode in `ffi.cpp:383-420`**: When `A4_COVERAGE_TOUCH` or `A4_MUTATION_CONFIG` is set, `risc0_circuit_rv32im_cpu_witgen` runs `stepExec` sequentially and emits touch data after the loop.

The accum phase (`risc0_circuit_rv32im_cpu_accum` at `ffi.cpp:438-494`) uses the same `EQZ` macro (via `step_TopAccum` -> `exec_TopAccum` in `steps.cpp`) but always runs in parallel. This causes:

- **Data race on `g_a4_touch_bitmap`**: Non-atomic `uint8_t` increment (line 114-115)
- **Crash risk on `g_a4_touch_verbose_set`**: Non-thread-safe `std::set::insert` (line 119)
- **Interleaved `<constraint_fail>` output**: Printf from multiple threads produces unparseable lines

### What We Need

1. A4-conditional sequential execution of accum phase 1 (stepAccum calls)
2. Separate accum touch bitmap (`g_a4_accum_touch_bitmap`)
3. Separate accum verbose set (`g_a4_accum_touch_verbose_set`)
4. Phase-aware routing in `a4_touch_mark()` so accum EQZ hits go to accum-specific storage
5. Separate emission tags: `<a4_accum_touch_coverage>`, `<a4_accum_touch_verbose>`, `<a4_accum_touch_debug>`
6. The `<constraint_fail>` output should include a `"phase"` field to distinguish local vs accum failures

## Design Decisions

### D1: Phase flag mechanism

**Decision**: Add a `bool is_accum_phase` field to `ExecContext`.

**Rationale**: `ExecContext` is already passed to every `eqz()` call via the `ctx` parameter. Adding a field is zero-overhead (set once per phase) and doesn't require global state. `a4_touch_mark()` and the `<constraint_fail>` printf already receive `ctx` as a parameter.

**Alternative considered**: Global `static bool g_is_accum_phase`. Rejected because it requires careful management across parallel/sequential transitions and is less clean than per-context state.

### D2: Separate bitmap vs shared bitmap

**Decision**: Separate `g_a4_accum_touch_bitmap[65536]`.

**Rationale**: Using the same bitmap would make it impossible to distinguish which type of constraint contributed which bits. Steps 3-5 in the master plan need to independently analyze local vs accum coverage.

### D3: Phases 2 and 3 of accum (prefix-sum, apply-totals)

**Decision**: Leave phases 2 and 3 parallel even when A4 is active.

**Rationale**: These phases do not call `EQZ` or `a4_touch_mark`. They are pure arithmetic on the accum buffer. No hooks are needed. Running them in parallel is safe and faster.

### D4: `<constraint_fail>` enrichment

**Decision**: Add `"phase":"accum"` (or `"phase":"local"`) field to the constraint_fail JSON.

**Rationale**: This is forward-compatible with Steps 2-3 in the master plan (parsing/classification). The loc string alone (`GenerateAccum.cpp:182`) is sufficient to distinguish accum from local, but an explicit `"phase"` field is cleaner for parsing and doesn't rely on string matching.

## Implementation Details

### File: `witgen.h`

#### Change 1: Add `is_accum_phase` to ExecContext

```cpp
// BEFORE (line 104-110):
struct ExecContext {
  ExecContext(PreflightTrace& preflight, LookupTables& tables, size_t cycle)
      : preflight(preflight), tables(tables), cycle(cycle) {}
  PreflightTrace& preflight;
  LookupTables& tables;
  size_t cycle;
};

// AFTER:
struct ExecContext {
  ExecContext(PreflightTrace& preflight, LookupTables& tables, size_t cycle,
             bool is_accum_phase = false)
      : preflight(preflight), tables(tables), cycle(cycle),
        is_accum_phase(is_accum_phase) {}
  PreflightTrace& preflight;
  LookupTables& tables;
  size_t cycle;
  bool is_accum_phase;
};
```

The default `is_accum_phase = false` ensures ALL existing call sites (witgen `stepExec`) continue to work unchanged without modification. Only `stepAccum` in `ffi.cpp` needs to pass `true`.

#### Change 2: Add `"phase"` to constraint_fail output

```cpp
// BEFORE (line 189-191):
printf("<constraint_fail>{\"cycle\":%zu, \"step\":%u, \"pc\":%u, \"major\":%u, \"minor\":%u, \"loc\":\"%s\", \"value\":%u}</constraint_fail>\n",
       ctx.cycle, step, pc, major, minor, loc, a.asUInt32());

// AFTER:
printf("<constraint_fail>{\"cycle\":%zu, \"step\":%u, \"pc\":%u, \"major\":%u, \"minor\":%u, \"loc\":\"%s\", \"value\":%u, \"phase\":\"%s\"}</constraint_fail>\n",
       ctx.cycle, step, pc, major, minor, loc, a.asUInt32(),
       ctx.is_accum_phase ? "accum" : "local");
```

### File: `ffi.cpp`

#### Change 3: Add accum touch globals

After the existing local touch globals (line 59-104), add:

```cpp
// Accum (global constraint) touch coverage -- separate from local.
static uint8_t g_a4_accum_touch_bitmap[kA4TouchMapSize];
static std::set<std::string> g_a4_accum_touch_verbose_set;
static char g_a4_accum_base64_buf[((kA4TouchMapSize + 2) / 3) * 4 + 1];
```

#### Change 4: Phase-aware `a4_touch_mark`

```cpp
// BEFORE (line 106-121):
void a4_touch_mark(ExecContext& ctx, const char* loc) {
  if (std::getenv("A4_COVERAGE_TOUCH") == nullptr)
    return;
  const PreflightCycle& cy = ctx.preflight.cycles[ctx.cycle];
  uint8_t major = cy.major;
  uint8_t minor = cy.minor;
  uint32_t h = a4_touch_hash(loc, major, minor);
  size_t idx = static_cast<size_t>(h) % kA4TouchMapSize;
  if (g_a4_touch_bitmap[idx] < 255)
    g_a4_touch_bitmap[idx]++;
  if (std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
    char key[4096];
    std::snprintf(key, sizeof(key), "%s|%u|%u", loc, (unsigned)major, (unsigned)minor);
    g_a4_touch_verbose_set.insert(std::string(key));
  }
}

// AFTER:
void a4_touch_mark(ExecContext& ctx, const char* loc) {
  if (std::getenv("A4_COVERAGE_TOUCH") == nullptr)
    return;
  const PreflightCycle& cy = ctx.preflight.cycles[ctx.cycle];
  uint8_t major = cy.major;
  uint8_t minor = cy.minor;
  uint32_t h = a4_touch_hash(loc, major, minor);
  size_t idx = static_cast<size_t>(h) % kA4TouchMapSize;

  // Route to the correct bitmap based on phase
  uint8_t* bitmap = ctx.is_accum_phase ? g_a4_accum_touch_bitmap : g_a4_touch_bitmap;
  if (bitmap[idx] < 255)
    bitmap[idx]++;

  if (std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
    char key[4096];
    std::snprintf(key, sizeof(key), "%s|%u|%u", loc, (unsigned)major, (unsigned)minor);
    auto& vset = ctx.is_accum_phase ? g_a4_accum_touch_verbose_set : g_a4_touch_verbose_set;
    vset.insert(std::string(key));
  }
}
```

#### Change 5: Pass `is_accum_phase=true` in `stepAccum`

```cpp
// BEFORE (line 333-349):
void stepAccum(AccumBuffers& buffers,
               PreflightTrace& preflight,
               LookupTables& tables,
               size_t cycle) {
  ExecContext ctx(preflight, tables, cycle);
  ...
}

// AFTER:
void stepAccum(AccumBuffers& buffers,
               PreflightTrace& preflight,
               LookupTables& tables,
               size_t cycle) {
  ExecContext ctx(preflight, tables, cycle, /*is_accum_phase=*/true);
  ...
}
```

#### Change 6: Sequential accum phase 1 when A4 is active

Replace the always-parallel phase 1 in `risc0_circuit_rv32im_cpu_accum` (lines 438-494):

```cpp
const char* risc0_circuit_rv32im_cpu_accum(AccumBuffers* buffers,
                                           PreflightTrace* preflight,
                                           uint32_t lastCycle) {
  try {
    LookupTables tables;

    {
      nvtx3::scoped_range range("phase1");

      // A4: Run accum phase 1 sequentially when A4 env vars are set.
      // Same rationale as witgen sequential mode: avoid data races on
      // touch bitmap and ensure clean constraint_fail output.
      if (std::getenv("A4_MUTATION_CONFIG") != nullptr
          || std::getenv("A4_COVERAGE_TOUCH") != nullptr) {

        // Clear accum touch bitmap before sequential loop
        if (std::getenv("A4_COVERAGE_TOUCH") != nullptr)
          std::memset(g_a4_accum_touch_bitmap, 0, kA4TouchMapSize);
        if (std::getenv("A4_COVERAGE_TOUCH") != nullptr
            && std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr)
          g_a4_accum_touch_verbose_set.clear();

        // Sequential execution
        for (size_t cycle = 0; cycle < lastCycle; cycle++) {
          stepAccum(*buffers, *preflight, tables, cycle);
        }

        // Emit accum touch coverage after sequential loop
        if (std::getenv("A4_COVERAGE_TOUCH") != nullptr) {
          uint64_t total_touches = 0;
          uint32_t distinct_buckets = 0;
          for (size_t i = 0; i < kA4TouchMapSize; i++) {
            total_touches += g_a4_accum_touch_bitmap[i];
            if (g_a4_accum_touch_bitmap[i] != 0)
              distinct_buckets++;
          }
          std::printf("<a4_accum_touch_debug> total_touches=%llu distinct_buckets=%u </a4_accum_touch_debug>\n",
                      (unsigned long long)total_touches, distinct_buckets);
          a4_base64_encode(g_a4_accum_touch_bitmap, kA4TouchMapSize, g_a4_accum_base64_buf);
          std::printf("<a4_accum_touch_coverage>%s</a4_accum_touch_coverage>\n", g_a4_accum_base64_buf);
          std::fflush(stdout);
          std::memset(g_a4_accum_touch_bitmap, 0, kA4TouchMapSize);
        }
        if (std::getenv("A4_COVERAGE_TOUCH") != nullptr
            && std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
          std::printf("<a4_accum_touch_verbose>[");
          bool first = true;
          for (const auto& key : g_a4_accum_touch_verbose_set) {
            if (!first) std::printf(",");
            std::printf("\"%s\"", key.c_str());
            first = false;
          }
          std::printf("]</a4_accum_touch_verbose>\n");
          std::fflush(stdout);
          g_a4_accum_touch_verbose_set.clear();
        }

      } else {
        // Default: parallel execution (original behavior)
        auto begin = poolstl::iota_iter<uint32_t>(0);
        auto end = poolstl::iota_iter<uint32_t>(lastCycle);
        std::for_each(poolstl::par, begin, end, [&](uint32_t cycle) {
          stepAccum(*buffers, *preflight, tables, cycle);
        });
      }
    }

    // Phases 2 and 3 remain unchanged (no EQZ calls, safe in parallel)
    buffers->accum.checked = false;

    {
      // prefix-sum
      nvtx3::scoped_range range("phase2");
      size_t rows = buffers->accum.rows;
      for (size_t j = 0; j < 4; j++) {
        size_t col = buffers->accum.cols - 4 + j;
        Fp* itBegin = buffers->accum.buf + col * rows;
        Fp* itEnd = itBegin + lastCycle;
        std::inclusive_scan(itBegin, itEnd, itBegin);
      }
    }

    {
      // apply totals
      nvtx3::scoped_range range("phase3");
      size_t machineColumns = (buffers->accum.cols - kUserAccumSplit) / 4;
      auto begin = poolstl::iota_iter<uint32_t>(0);
      auto end = poolstl::iota_iter<uint32_t>(lastCycle);
      std::for_each(poolstl::par, begin, end, [&](uint32_t row) {
        size_t back1 = (row + lastCycle - 1) % lastCycle;
        std::array<Fp, 4> prev;
        for (size_t k = 0; k < 4; k++) {
          prev[k] = buffers->accum.get(back1, buffers->accum.cols - 4 + k);
        }
        for (size_t j = 0; j < machineColumns - 1; j++) {
          for (size_t k = 0; k < 4; k++) {
            size_t col = kUserAccumSplit + j * 4 + k;
            buffers->accum.set(row, col, buffers->accum.get(row, col) + prev[k]);
          }
        }
      });
    }
  } catch (const std::exception& err) {
    return strdup(err.what());
  } catch (...) {
    return strdup("Generic exception");
  }
  return nullptr;
}
```

## Edge Cases and Risks

### E1: `ExecContext` default parameter compatibility

The `is_accum_phase = false` default ensures backward compatibility. All existing `ExecContext` constructors in witgen (`stepExec` at line 327) will continue to construct with `is_accum_phase = false`. Only `stepAccum` (line 337) explicitly passes `true`.

**Verify**: Search for ALL `ExecContext(` constructor calls in the codebase to confirm none break.

### E2: `std::getenv` performance in sequential loop

`std::getenv` is called inside `a4_touch_mark` on every `eqz()` call. In sequential accum mode with ~16K cycles and 155 EQZ calls per cycle, that's ~2.5M `getenv` calls. This is the same pattern used for witgen (1757 EQZ * ~16K cycles = ~28M calls) and has been confirmed acceptable there.

**Note**: If performance becomes an issue, we can cache the env var check in a static local, but this matches the existing pattern and should not regress.

### E3: Bitmap emission ordering

The witgen bitmap is emitted at the end of `risc0_circuit_rv32im_cpu_witgen`. The accum bitmap is emitted at the end of accum phase 1 in `risc0_circuit_rv32im_cpu_accum`. Since witgen runs before accum in the proving pipeline (`hal/mod.rs:170-350`), the output order will be:

```
<a4_touch_debug>...</a4_touch_debug>
<a4_touch_coverage>...</a4_touch_coverage>
<a4_touch_verbose>...</a4_touch_verbose>         (if verbose)
... (constraint_fail lines with phase:local) ...
... (constraint_fail lines with phase:accum) ...
<a4_accum_touch_debug>...</a4_accum_touch_debug>
<a4_accum_touch_coverage>...</a4_accum_touch_coverage>
<a4_accum_touch_verbose>...</a4_accum_touch_verbose>  (if verbose)
```

Parsers in Steps 3-4 should handle this ordering.

### E4: `CONSTRAINT_CONTINUE` interaction

When `CONSTRAINT_CONTINUE=1`, both local and accum EQZ failures return instead of throwing. This is already the correct behavior. No changes needed.

With CONSTRAINT_CONTINUE:
- Local failures print `<constraint_fail>` with `"phase":"local"` and continue
- Accum failures print `<constraint_fail>` with `"phase":"accum"` and continue
- Both bitmaps accumulate correctly
- The prover continues to phases 2, 3, and finalize

Without CONSTRAINT_CONTINUE:
- First failure (local or accum) throws, stopping execution
- Only partial bitmap data is available (same as current behavior for local constraints)

### E5: Accum EQZ failures when data buffer is already corrupted

If A4 mutated the PreflightTrace and local constraints failed (with CONSTRAINT_CONTINUE), the data buffer contains wrong values. The accum phase reads from this corrupted data buffer, so accum EQZ failures are expected. These are "cascade" failures, not primary failures. Step 5 in the master plan addresses filtering these. Step 1 just needs to ensure they are captured correctly -- filtering is a later concern.

### E6: The `eqz(ExtVal)` overload

There's a second `eqz` overload for extension field values (`witgen.h:204-208`):

```cpp
inline void eqz(ExecContext& ctx, ExtVal a, const char* loc) {
  for (size_t i = 0; i < EXT_SIZE; i++) {
    eqz(ctx, a.elems[i], loc);
  }
}
```

This calls the base `eqz(Val)` for each element, so it automatically gets the phase-aware routing. No changes needed.

## Testing Plan

### T1: Compilation test

After making changes, rebuild the risc0 project and verify it compiles without errors:

```bash
cd workspace/risc0-modified
cargo build -p risc0-circuit-rv32im
```

### T2: Non-A4 regression test

Run WITHOUT any A4 env vars to verify the accum phase still runs in parallel (default behavior unchanged):

```bash
# Run any existing risc0 test without A4 env vars
cargo test -p risc0-circuit-rv32im -- --test-threads=1
```

### T3: A4 accum touch coverage test

Run WITH A4 env vars and verify accum touch tags appear in output:

```bash
A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1 CONSTRAINT_CONTINUE=1 \
  cargo test -p risc0-circuit-rv32im -- --test-threads=1 2>&1 | \
  grep -E '<a4_accum_touch|<a4_touch'
```

Expected: Both `<a4_touch_coverage>` and `<a4_accum_touch_coverage>` tags should appear.

### T4: Phase field in constraint_fail

Run a mutation that triggers both local and accum failures:

```bash
A4_MUTATION_CONFIG=<some_config> CONSTRAINT_CONTINUE=1 \
  cargo test -p risc0-circuit-rv32im -- --test-threads=1 2>&1 | \
  grep '<constraint_fail>'
```

Verify that output includes both `"phase":"local"` and `"phase":"accum"` lines.

### T5: Unmutated baseline

Run without mutation to verify no constraint failures occur:

```bash
A4_COVERAGE_TOUCH=1 CONSTRAINT_CONTINUE=1 \
  cargo test -p risc0-circuit-rv32im -- --test-threads=1 2>&1 | \
  grep '<constraint_fail>'
```

Expected: No `<constraint_fail>` lines (clean execution).

## Summary of Changes

| File | Change | Lines affected |
|------|--------|---------------|
| `witgen.h` | Add `is_accum_phase` to `ExecContext` | 104-110 |
| `witgen.h` | Add `"phase"` to `<constraint_fail>` printf | 189-191 |
| `ffi.cpp` | Add accum touch globals (bitmap, verbose set, base64 buf) | After line 104 |
| `ffi.cpp` | Phase-aware routing in `a4_touch_mark()` | 106-121 |
| `ffi.cpp` | Pass `is_accum_phase=true` in `stepAccum()` | 333-349 |
| `ffi.cpp` | A4-conditional sequential mode + emit in `risc0_circuit_rv32im_cpu_accum()` | 438-494 |

Total: ~60 lines of new/modified code across 2 files.

## Forward Compatibility with Master Plan Steps 2-6

- **Step 2 (enrich accum EQZ)**: The `"phase":"accum"` field provides the foundation. Step 2 can later add more fields without changing the phase infrastructure.
- **Step 3 (constraint_parser.py)**: Will parse the new `"phase"` field and `<a4_accum_touch_*>` tags. Step 1 just ensures these are emitted correctly.
- **Step 4 (touch_coverage.py)**: Will handle the separate accum bitmap. Step 1 ensures it's a distinct base64 blob.
- **Step 5 (cascade filtering)**: Relies on being able to distinguish accum from local failures. The `"phase"` field enables this.
- **Step 6 (E2E validation)**: Tests defined here (T1-T5) serve as the foundation for the full validation.
