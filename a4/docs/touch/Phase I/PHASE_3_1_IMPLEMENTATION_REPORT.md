# Phase 3.1 Implementation Report

This report describes the implementation and testing of Phase 3.1 (C++ touch accumulator and `a4_touch_mark`, no emission yet), deviations from the plan, key variables and functions, testing performed, and insights for the Phase 3.2 implementation plan.

**Reference plan**: [PHASE_3_1_IMPLEMENTATION_PLAN.md](./PHASE_3_1_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase 3.1 was implemented as specified: the touch bitmap and `a4_touch_mark` were added in `ffi.cpp`, the call from the Val overload of `eqz` was added in `witgen.h`, and a temporary debug line is printed after the SeqForward witgen loop when `A4_COVERAGE_TOUCH` is set. The C++ code compiles; full verification (running the host with `A4_COVERAGE_TOUCH=1` and checking the debug line) requires building the full host binary (e.g. from `workspace/output` or the prover example) and is documented below.

---

## 2. Answers to Points 1 and 2 (pre-implementation)

### 2.1 Why avoid env/stdio in the header?

The plan says to implement `a4_touch_mark` in `ffi.cpp` “to avoid pulling env/stdio into header.” The reasons are:

- **Headers are included in many translation units.** If `witgen.h` called `getenv("A4_COVERAGE_TOUCH")` itself, it would need to include `<cstdlib>` (and possibly `<cstdio>` for any debug output). Every `.cpp` that includes `witgen.h` would then pull in those headers, which can increase compile time and spread the dependency on the coverage feature.
- **Single place for “when to mark.”** The decision “is touch coverage enabled?” is an implementation detail of the coverage system. Keeping it inside `a4_touch_mark` in `ffi.cpp` means the header only declares that the function exists; it does not need to know about the env var or its name. The header stays minimal and stable.
- **Consistency with the plan.** The plan explicitly says the *check* for `A4_COVERAGE_TOUCH` must be inside `a4_touch_mark` in the .cpp so that the header does not need to call `getenv`. Note: `witgen.h` already uses `std::getenv` and `printf` elsewhere (e.g. CONSTRAINT_CONTINUE, failure tracing); the guideline here is to avoid adding *further* env/stdio usage for the *touch* feature in the header when it can live in the .cpp.

### 2.2 Val vs ExtVal: overcount vs losing info; is testing necessary?

- **Call pattern:** The ExtVal overload of `eqz` calls the Val overload once per element (`EXT_SIZE` times) with the same `(ctx, loc)`. So for one *logical* constraint that uses ExtVal, the Val overload runs `EXT_SIZE` times.
- **Mark only in Val (as implemented):**  
  - Constraints that go through the Val overload only: 1 mark per constraint (correct).  
  - Constraints that go through the ExtVal overload: `EXT_SIZE` marks (one per Val call) for the same (ctx, loc). So we **do not lose** any context — every (loc, major, minor) that is touched is still recorded. We **may overcount** for wide constraints: the same bucket can be incremented multiple times per cycle for one logical constraint. The bitmap still reflects “this context was touched”; the count in that bucket is an upper bound (saturating at 255).
- **Conclusion:** There is no wrong assumption that loses info. Optional testing: Phase 3.4 determinism test (same mutation → same bitmap) proves consistency; a test that proves “exactly one mark per logical constraint” would require generator-side knowledge and is optional.

---

## 3. Deviations from the Phase 3.1 Implementation Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| Debug tag | “e.g. `<a4_touch_debug>...</a4_touch_debug>`” | Used exactly `<a4_touch_debug> total_touches=... distinct_buckets=... </a4_touch_debug>` | Unambiguous, easy to grep; Phase 3.2 can replace or keep. |
| Includes in ffi.cpp | Plan did not list every include | Added `#include <cstdlib>`, `#include <cstring>`, `#include <cstdio>` for `getenv`, `memset`, `printf`/`fflush`. | Required for the code that was added. |
| Hash function name | “e.g. FNV-1a” | Implemented as `a4_touch_hash(loc, major, minor)` using FNV-1a (offset basis 2166136261u, prime 16777619u). | Single named helper for clarity and future documentation. |
| Clear bitmap | “Before the for loop … zero … when env set” | Same: `std::memset(g_a4_touch_bitmap, 0, kA4TouchMapSize)` only when `std::getenv("A4_COVERAGE_TOUCH") != nullptr` before the loop. | As planned. |
| step in hash | Phase I uses no step_bucket | Hash uses only `(loc, major, minor)`; step is not mixed in. | As planned. |

No other deviations. The plan’s “Phase 0.1 Implementation Plan” in the user request was interpreted as the **Phase 3.1** Implementation Plan for the purpose of this report.

---

## 4. Key Variables and Functions (and why they are structured this way)

### 4.1 Constants and bitmap (`ffi.cpp`)

- **`kA4TouchMapSize`**  
  - Value: `65536`.  
  - Purpose: Size of the AFL-style touch bitmap (Phase I plan: MAP_SIZE = 65536).  
  - Why: Single named constant so Phase 3.2/3.4 can use the same value and so the bitmap and any serialization stay in sync.

- **`g_a4_touch_bitmap`**  
  - Type: `static uint8_t g_a4_touch_bitmap[kA4TouchMapSize]`.  
  - Purpose: One global bitmap for the current witgen run; each index corresponds to a hash bucket for (loc, major, minor).  
  - Why static in the .cpp: (1) Only the SeqForward path in this translation unit uses it, and A4 forces SeqForward when mutating, so one global is enough. (2) No need to pass it through the call stack from `eqz`. (3) Cleared at the start of the SeqForward run when `A4_COVERAGE_TOUCH` is set so each run sees a clean bitmap.

### 4.2 Hash function (`ffi.cpp`)

- **`a4_touch_hash(const char* loc, uint8_t major, uint8_t minor) -> uint32_t`**  
  - Implementation: FNV-1a over the bytes of `loc` (until `'\0'`), then mix in `major` and `minor` with the same prime (16777619u). Offset basis 2166136261u.  
  - Purpose: Map (loc, major, minor) to a deterministic 32-bit value so that the same context always maps to the same bitmap index.  
  - Why FNV-1a: Simple, deterministic, no external deps; good enough for a coverage bitmap. Same hash in C++ and (if needed later) in Python for Phase 3.4 or inverse mapping.  
  - Why no step: Phase I uses no step_bucket; key is (loc, major, minor) only.

### 4.3 Touch marking (`ffi.cpp`)

- **`a4_touch_mark(ExecContext& ctx, const char* loc)`**  
  - Steps: (1) If `std::getenv("A4_COVERAGE_TOUCH") == nullptr`, return immediately. (2) Read `major` and `minor` from `ctx.preflight.cycles[ctx.cycle]`. (3) Compute `idx = a4_touch_hash(loc, major, minor) % kA4TouchMapSize`. (4) Saturating increment: `if (g_a4_touch_bitmap[idx] < 255) g_a4_touch_bitmap[idx]++;`.  
  - Purpose: Record one “touch” for the current (loc, major, minor) when the env var is set.  
  - Why env check inside the function: So `witgen.h` only needs to call `a4_touch_mark(ctx, loc)` with no env/stdio in the header; the header stays minimal.  
  - Why saturating: Prevents overflow; for coverage we only care that the bucket was hit (and optionally how many times).  
  - Why no I/O inside: Keeps the hot path cheap; debug output happens once after the loop.

### 4.4 Integration in `eqz` (`witgen.h`)

- **Declaration:** `void a4_touch_mark(ExecContext& ctx, const char* loc);`  
  - Placed before the definition of `eqz(ExecContext&, Val, const char*)` so the compiler sees the declaration when compiling call sites. Definition lives in `ffi.cpp`.

- **Call site:** At the very beginning of the **Val** overload of `eqz`, before `if (a.asUInt32())`: `a4_touch_mark(ctx, loc);`.  
  - Purpose: Every EQZ invocation (pass or fail) is counted once from the Val path.  
  - Why only in Val: The ExtVal overload calls the Val overload per element; marking only in Val avoids double-counting (we would get 1 from ExtVal + N from Val if we marked in both). We accept possible overcount for ExtVal-backed constraints (same bucket hit N times) and never lose a touched context.

### 4.5 SeqForward branch (`ffi.cpp`)

- **Before the loop:** If `std::getenv("A4_COVERAGE_TOUCH") != nullptr`, then `std::memset(g_a4_touch_bitmap, 0, kA4TouchMapSize)`.  
  - Purpose: Each witgen run sees a zeroed bitmap so counts are per run.

- **After the loop:** If `A4_COVERAGE_TOUCH` is set, compute `total_touches` (sum of all entries) and `distinct_buckets` (count of non-zero entries), then `std::printf("<a4_touch_debug> total_touches=%llu distinct_buckets=%u </a4_touch_debug>\n", ...)` and `std::fflush(stdout)`.  
  - Purpose: Phase 3.1 verification only; confirms that touches are being recorded. Phase 3.2 will replace or extend this with the real `<a4_touch_coverage>...</a4_touch_coverage>` emission.

---

## 5. Testing Performed

### 5.1 Build

- **Command:** `cargo build --release -p risc0-circuit-rv32im-sys` from `workspace/risc0-modified`.  
- **Result:** The crate compiles successfully with the new code in `ffi.cpp` and `witgen.h`. (Build was run; C++ compilation of the kernel can take several minutes.)

### 5.2 Verification run (manual, when host is available)

To confirm that touches are recorded and the debug line appears:

1. Build the full host that links the modified rv32im-sys (e.g. from `workspace/output` with `cargo build --release`, or the prover example in risc0-modified that produces a host binary).
2. Run with touch and a mutation (or baseline):  
   `A4_COVERAGE_TOUCH=1 A4_MUTATION_CONFIG=/path/to/config.json CONSTRAINT_CONTINUE=1 ./risc0-host --in1 5 --in4 10`  
   (or without mutation config for a baseline run).
3. In stdout, look for a single line:  
   `<a4_touch_debug> total_touches=<N> distinct_buckets=<M> </a4_touch_debug>`.
4. Expect: `total_touches` and `distinct_buckets` non-zero and in a plausible range (e.g. thousands to low tens of thousands per run, per Phase I plan).

Optional: Run the same config twice and confirm the two debug lines are identical (determinism); full determinism testing is Phase 3.4.

### 5.3 What was not tested in this phase

- No Python code was added (Phase 3.2).
- No executor or fuzzer changes (Phase 3.2/3.3).
- No unit test for the hash function (optional for Phase 3.4).
- No test that proves “exactly one mark per logical constraint” (optional; would require generator knowledge).

---

## 6. Insights for the Phase 3.2 Implementation Plan

1. **Emission format**  
   Phase 3.2 should replace (or add alongside) the `<a4_touch_debug>` line with a single line containing the serialized bitmap, e.g. `<a4_touch_coverage><base64 or comma-separated bytes></a4_touch_coverage>`. Use the same `g_a4_touch_bitmap` and `kA4TouchMapSize`; document the encoding so Python can decode and merge.

2. **Hash and MAP_SIZE**  
   Python must use the same hash (FNV-1a with the same constants) and MAP_SIZE (65536) when building context_id → index for any inverse mapping or when comparing with failure context_ids. The C++ key is (raw loc string, major, minor); Python normalizes `loc` with `constraint_loc()` / `short_loc()` for display and DB, but for bitmap merge the raw bytes from C++ and the normalized form must be consistent (Phase 3.2: C++ emits raw loc in the bitmap or in a separate verbose format; Python normalizes when parsing).

3. **When to emit**  
   Emission happens after the SeqForward loop in `risc0_circuit_rv32im_cpu_witgen`, only when `A4_COVERAGE_TOUCH` is set. Phase 3.2 should clear the bitmap after emission (or document that the process is single-run) so the next invocation gets a clean bitmap.

4. **Executor**  
   When running a mutation, the executor should set `A4_COVERAGE_TOUCH=1` in the environment (same way as `A4_MUTATION_CONFIG` and `CONSTRAINT_CONTINUE`) so the host emits touch coverage. No change to how stdout/stderr are captured; the new tag can be parsed from the same combined output.

5. **Debug line**  
   Phase 3.2 can either remove the `<a4_touch_debug>` line and only emit `<a4_touch_coverage>`, or keep both during development. If both are present, the Python parser should only rely on `<a4_touch_coverage>` for the bitmap.

6. **ExtVal overcount**  
   As noted in §2.2, marking only in Val may overcount for ExtVal-backed constraints. For “new touch” count and bitmap merge, this does not lose information (all touched contexts are still marked). If Phase II uses counts for rarity or other heuristics, document that bucket counts are upper bounds.

---

## 7. Files Touched

| File | Change |
|------|--------|
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | Added `#include <cstdlib>`, `<cstring>`, `<cstdio>`; `kA4TouchMapSize`, `g_a4_touch_bitmap`, `a4_touch_hash`, `a4_touch_mark`; in SeqForward branch: clear bitmap when env set, after loop print `<a4_touch_debug>` line. |
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` | Declared `a4_touch_mark`; at start of `eqz(ExecContext&, Val, const char*)` added `a4_touch_mark(ctx, loc);`. |
| `a4/docs/touch/PHASE_3_1_IMPLEMENTATION_PLAN.md` | Added clarifications for “avoid env/stdio in header” and “Val vs ExtVal: overcount vs losing info.” |
| `a4/docs/touch/PHASE_3_1_IMPLEMENTATION_REPORT.md` | This report. |

---

## 8. Phase 3.1 Completion Checklist

- [x] Step 3.1.1: Constants and bitmap in ffi.cpp.
- [x] Step 3.1.2: Hash and `a4_touch_mark` in ffi.cpp; bitmap updated when env set.
- [x] Step 3.1.3: Declaration in witgen.h; call from Val overload of eqz only.
- [x] Step 3.1.4: Clear bitmap at start of SeqForward when env set; debug print after loop.
- [x] Step 3.1.5: Build (rv32im-sys) succeeds; manual verification steps documented.
- [x] No emission format for Python yet (deferred to 3.2).
- [x] No step_bucket in hash key (Phase I: key = loc, major, minor only).

---

*End of Phase 3.1 Implementation Report.*
