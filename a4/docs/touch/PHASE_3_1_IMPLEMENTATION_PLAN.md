# Phase 3.1 Detailed Implementation Plan

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase 3.1** (C++ touch accumulator and `a4_touch_mark`, no emission yet). It is consistent with [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) §3–4 and keeps Phases 3.2, 3.3, and 3.4 in mind so that no later work is blocked or duplicated.

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites: Step-Bucket Necessity and Phase 0 Takeaways

### 1.1 Was the step_bucket necessity analysis necessary for constraint failure info or only for touch?

**Short answer**: The analysis is **for touch (bitmap) design**, not for failure info. Phase 0.2 measured **failure** data as a **proxy** to size the key space. We do **not** need to redo a full campaign-style analysis before implementing Phase 3, but we **should verify** touch key count once emission exists (Phase 3.2).

**Facts**:

- **Failure info**: Constraint failures are stored per-record in the DB (`a4/standalone/coverage_db.py`: `failures` table with `constraint_loc`, `major`, `minor`, etc.). There is no fixed-size bitmap for failures; distinct `context_id()` counts (K_total, per-run) were measured to inform **bitmap** sizing, not failure storage.
- **Touch info** (Phase 3): Touch coverage uses an AFL-style **bitmap** of size `MAP_SIZE` (e.g. 65536). Keys are hashed into the bitmap. Collision formula: expected collisions ≈ `K² / (2 * MAP_SIZE)` (PHASE_I_IMPLEMENTATION_PLAN.md §0.1). So the step_bucket and “K &lt; ~20k” analysis is **necessary for touch bitmap design** (whether to use step_bucket, whether 64k is enough).
- **What Phase 0.2 actually measured**: Phase 0.2 measured distinct `(constraint_loc, major, minor)` from **failure** data only (contexts where a constraint **failed**). So we measured “distinct failure context_ids,” not “distinct touched context_ids.” Touched contexts per run can be **larger** (every EQZ call, not just failing ones).
- **Phase I plan bound**: PHASE_I_IMPLEMENTATION_PLAN.md §0.1 states a **plausible upper bound** for distinct `(loc, major, minor)` in **one run** is “low thousands to low tens of thousands (e.g. 2k–15k).” So even for touch, without step_bucket we stay in a range where a 64k bitmap has acceptable collision rate.
- **Conclusion**: (1) Step_bucket analysis was **for touch**, not for failure storage. (2) Phase 0.2’s measurement on **failure** data was a proxy; it confirmed the key space (failure subset) is tiny (K_total=43, per-run max 9). (3) We do **not** need to redo a full campaign before Phase 3.1. After Phase 3.2 (emission), run **one** unmutated or mutated run with `A4_COVERAGE_TOUCH=1` and report bitmap occupancy or distinct-touched count; if that number is well below 20k, the Phase 0.2 conclusion (no step_bucket, MAP_SIZE=65536) holds for touch.

### 1.2 Phase 0 conclusions and takeaways for Phase 3

Keep these in mind when implementing Phase 3 (all phases):

| Takeaway | Source | Implication for Phase 3 |
|----------|--------|--------------------------|
| **Stable coverage key** | Phase 0.1: `context_id()` = `(constraint_loc(), major, minor)`; Phase I uses no step_bucket. | C++ bitmap key must be derived from the same logical key so Python can merge touch with the same ConstraintContext as failures. Phase 3.2: Python normalizes raw `loc` from C++; C++ hashes (loc, major, minor) without step_bucket. |
| **Determinism** | Phase 0.1/0.2: same config → same failure set; A4 forces SeqForward when `A4_MUTATION_CONFIG` set. | Phase 3.4: same mutation must yield same touch bitmap; single-threaded witgen in SeqForward so no parallel merge. |
| **Baseline = zero failures** | Phase 0.2: `run_baseline()` produces no `<constraint_fail>` lines. | Phase 3: capture baseline **touch** set (unmutated run with same host/args) for comparison with mutated-run touch sets. |
| **Touch accuracy** | Phase 0.1 / PHASE_I §0.2: EQZ is only invoked when the corresponding component/minor branch is taken (`exec_Top`, `exec_Div0` in steps.cpp). | “Touched” = “eqz was called” = constraint active; no overcount of inactive constraints. |
| **MAP_SIZE and collisions** | Phase 0.2 report; PHASE_I §0.1. | Use MAP_SIZE=65536; no step_bucket in Phase I; collision expectation K²/(2×MAP_SIZE). Document in one place (Phase 3.4). |
| **Executor env** | `a4/core/executor.py`: `run_a4_mutation` sets `A4_MUTATION_CONFIG`, `CONSTRAINT_CONTINUE`. | Phase 3.2: executor will set `A4_COVERAGE_TOUCH=1` when running mutations (or under a flag). |
| **Runs with 0 failures** | Phase 0.2 report: some mutations produce 0 constraint failures but proof still fails. | Touch set can be non-empty even when failure set is empty; Phase 3.3 “new touch” is independent of failure count. |
| **Python normalizes `loc`** | `a4/core/constraint_parser.py` `short_loc()`, `constraint_loc()` (e.g. lines 56–76, 120–125). | Phase 3.2: C++ emits raw `loc`; Python normalizes when parsing touch coverage (single source of truth in Python). |
| **ExtVal overload** | `witgen.h`: `eqz(ExecContext&, ExtVal, const char*)` calls `eqz(ctx, a.elems[i], loc)` for each element. | Phase 3.1: mark only in the **Val** overload of `eqz` so each (ctx, loc) is counted once per cycle, not per element (do not mark in ExtVal overload). |

---

## 2. Phase 3.1 scope and relation to 3.2–3.4

From PHASE_I_IMPLEMENTATION_PLAN.md §4 (Implementation Order):

- **Phase 3.1**: C++ touch accumulator + `a4_touch_mark` + call from `eqz`; **no emission yet**. Verify with a debug print that touches are being recorded (e.g. count per run).
- **Phase 3.2**: C++ emission after SeqForward loop; Python parse and merge; executor sets `A4_COVERAGE_TOUCH`.
- **Phase 3.3**: Fuzzer/DB: record new touch count per run; optional persistence.
- **Phase 3.4**: Documentation and constants (MAP_SIZE, B, hash) in one place; tests that same mutation yields same touch bitmap.

**Phase 3.1 deliverables (only C++)**:

1. A global (or static) touch bitmap, active only when `A4_COVERAGE_TOUCH` is set.
2. Function `a4_touch_mark(ExecContext& ctx, const char* loc)` that hashes `(loc, major, minor)` into the bitmap and saturating-increments (no step_bucket in Phase I).
3. Call to `a4_touch_mark` at the very start of `eqz(ExecContext& ctx, Val a, const char* loc)` (before `if (a.asUInt32())`).
4. No marking in the `ExtVal` overload of `eqz`.
5. A **temporary** verification: after the SeqForward witgen loop, if `A4_COVERAGE_TOUCH` is set, print a single debug line (e.g. total touch count or number of non-zero bitmap entries) so we can confirm touches are recorded. This is not the final emission format; Phase 3.2 will replace or extend this with the real `<a4_touch_coverage>...</a4_touch_coverage>` emission.

**What Phase 3.1 does not do** (left to 3.2–3.4):

- No serialization of the bitmap to stdout for Python (3.2).
- No Python parser or executor env (3.2).
- No DB or fuzzer recording of touch (3.3).
- No shared constants doc or determinism test for touch (3.4).

**Design choices in 3.1 that must align with 3.2–3.4**:

- **Key**: Use `(loc, major, minor)` only so that when Python later parses the bitmap (or raw touch list), it can use the same `context_id()` notion. C++ will use raw `loc` pointer; hash input = bytes of loc string + major + minor (or a deterministic mix). Phase 3.2 will define the exact emission format; 3.1 only needs a consistent hash so the same (loc, major, minor) always maps to the same bitmap index.
- **MAP_SIZE**: Use 65536 in 3.1 so 3.2 does not need to change it; document in 3.4.
- **Hash function**: Pick one (e.g. FNV-1a) and use it in C++; Phase 3.2/3.4 will document it and Python may need it for inverse mapping later.

---

## 3. Source-of-truth facts (code anchors)

### 3.1 Where `eqz` is defined and what it has access to

| Fact | Location |
|------|----------|
| Single choke point for constraint check and (to be added) touch | `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` lines 177–197: `inline void eqz(ExecContext& ctx, Val a, const char* loc)` |
| ExecContext has preflight, tables, cycle | `witgen.h` lines 104–109: `PreflightTrace& preflight; LookupTables& tables; size_t cycle;` |
| step, pc, major, minor per cycle | `witgen.h` lines 181–184 (inside failure branch): `ctx.preflight.cycles[ctx.cycle].userCycle`, `.pc`, `.major`, `.minor`; same available at entry of `eqz` |
| PreflightCycle layout | `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/preflight.h` lines 29–41: `userCycle`, `pc`, `major`, `minor` (uint32_t, uint32_t, uint8_t, uint8_t) |
| ExtVal overload calls Val overload per element | `witgen.h` lines 199–204: `eqz(ExecContext&, ExtVal, const char*)` calls `eqz(ctx, a.elems[i], loc)` in a loop — do **not** add touch mark here |

### 3.2 Witgen entry point and SeqForward loop

| Fact | Location |
|------|----------|
| stepExec creates ExecContext and calls step_Top | `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` lines 254–259 |
| risc0_circuit_rv32im_cpu_witgen dispatch | `ffi.cpp` lines 290–331: `switch (mode)`, `case kStepModeSeqForward:` at 311 |
| SeqForward loop | `ffi.cpp` lines 311–315: `for (size_t cycle = 0; cycle < lastCycle; cycle++) { stepExec(...); }` then `break;` |
| A4 forces SeqForward when A4_MUTATION_CONFIG set | Not in C++; Rust `hal/mod.rs`. When we add A4_COVERAGE_TOUCH, we only care about SeqForward path for emission (same loop). |

### 3.3 Include structure

| Fact | Location |
|------|----------|
| ffi.cpp includes witgen.h | `ffi.cpp` line 20: `#include "witgen.h"` |
| ffi.cpp includes preflight.h | `ffi.cpp` line 18: `#include "preflight.h"` |
| Namespace for stepExec and witgen | `ffi.cpp`: `namespace risc0::circuit::rv32im_v2::cpu` (line 50); `risc0_circuit_rv32im_cpu_witgen` is `extern "C"` (line 286) |

### 3.4 Avoiding env/stdio in the header

| Fact | Location |
|------|----------|
| Plan: avoid pulling env/stdio into header | PHASE_I_IMPLEMENTATION_PLAN.md §3.3: “implemented in a new file or in ffi.cpp to avoid pulling env/stdio into header” |
| Implication | `a4_touch_mark` should be **defined** in `ffi.cpp` (where `getenv` and optional debug printf are acceptable). Declaration can be in `witgen.h` so `eqz` can call it, or in a small internal header included only by ffi.cpp and witgen.h. If declaration is in witgen.h, witgen.h must not call `getenv` — so the **check** for `A4_COVERAGE_TOUCH` must be inside `a4_touch_mark` in ffi.cpp. |

**Why avoid env/stdio in the header (clarification)**  
Headers are included in many translation units. If `witgen.h` called `getenv("A4_COVERAGE_TOUCH")` itself, the header would need to include `<cstdlib>` (and possibly `<cstdio>` for any debug output). That would: (1) increase compile times for every file that includes `witgen.h`; (2) spread the dependency on the coverage feature into all those units; (3) make the header responsible for "when to mark" (an implementation detail). By keeping only a **declaration** in the header (`void a4_touch_mark(...);`) and putting the **definition** and the env check in `ffi.cpp`, the header stays minimal: it just says "this function exists." The decision "is touch coverage enabled?" lives in one place (the .cpp), and we avoid adding another env var check (and its include) to the header. Note: `witgen.h` already uses `std::getenv` and `printf` elsewhere (e.g. CONSTRAINT_CONTINUE, failure tracing); the guideline here is to not add *further* env/stdio usage for the *touch* feature in the header when it can live in the .cpp.

**Val vs ExtVal: overcount vs losing info (clarification)**  
The ExtVal overload calls the Val overload once per element (same `ctx`, same `loc`). Marking only in Val: we never lose a touched context; we may overcount for wide constraints (same bucket hit EXT_SIZE times per logical constraint). We do not lose info. Marking in both would double-count; marking only in ExtVal would miss Val-only constraints. Optional testing: Phase 3.4 determinism test (same mutation → same bitmap); a test that proves "exactly one mark per logical constraint" would require generator knowledge and is optional.

---

## 4. Step-by-step implementation plan (Phase 3.1)

### Step 3.1.1: Add constants and touch bitmap in ffi.cpp

**Goal**: Define MAP_SIZE and the touch bitmap in the C++ translation unit that will own `a4_touch_mark`, so that the bitmap is only active when the env var is set and is cleared/reset as needed later (Phase 3.2 will add emission and clear).

**Facts**:

- `ffi.cpp` is in namespace `risc0::circuit::rv32im_v2::cpu` and already includes `witgen.h`, `preflight.h`.
- Phase I uses no step_bucket; key = (loc, major, minor). MAP_SIZE = 65536 (PHASE_I §3.6).

**Actions**:

1. In `ffi.cpp`, inside `namespace risc0::circuit::rv32im_v2::cpu`, add:
   - `constexpr size_t kA4TouchMapSize = 65536;` (or a name that matches the plan’s MAP_SIZE).
   - A static or global bitmap: e.g. `static uint8_t g_a4_touch_bitmap[65536];` (use `kA4TouchMapSize` for size). Initialization to zero is guaranteed for static storage.
   - Optional: a static “initialized” flag or explicit zeroing in a function that will be called before the witgen loop when `A4_COVERAGE_TOUCH` is set; Phase 3.2 will clear after emission. For 3.1, we can zero the bitmap at the start of the SeqForward branch when env is set, so each run sees a clean bitmap.
2. Do **not** add `#include <cstdlib>` for `getenv` in the header; `ffi.cpp` already has includes that typically provide it (or add in ffi.cpp only).

**Deliverable**: Constants and bitmap array in `ffi.cpp`; no change to `witgen.h` yet.

---

### Step 3.1.2: Implement hash and a4_touch_mark in ffi.cpp

**Goal**: Implement a deterministic hash of (loc, major, minor) to an index in [0, MAP_SIZE), and a function `a4_touch_mark(ExecContext& ctx, const char* loc)` that updates the bitmap only when `A4_COVERAGE_TOUCH` is set.

**Facts**:

- `ExecContext` is defined in `witgen.h`; `ffi.cpp` includes it, so we have full type.
- `PreflightCycle` has `major`, `minor` as `uint8_t`, `userCycle` as `uint32_t` (preflight.h).
- We need a hash of (loc string bytes, major, minor). FNV-1a or djb2 are acceptable (PHASE_I §3.6). Use the same hash for the same (loc, major, minor) every time so that Python’s view of “which context_id maps to which bucket” can be reproduced if needed (Phase 3.4 may document or test).

**Actions**:

1. In `ffi.cpp`, inside the same namespace, add a helper that computes a hash from `(const char* loc, uint8_t major, uint8_t minor)`:
   - Option A: FNV-1a over the bytes of `loc` (until `'\0'`), then mix in major and minor (e.g. two more steps of FNV with the two bytes). Result: `uint32_t` or `size_t`, then `idx = hash % kA4TouchMapSize`.
   - Option B: djb2 for `loc`, then `hash = hash * 31 + major; hash = hash * 31 + minor;` and take modulo MAP_SIZE.
   - Ensure the hash is deterministic (no randomness, no address of pointer).
2. Implement `void a4_touch_mark(ExecContext& ctx, const char* loc)`:
   - At the start, if `std::getenv("A4_COVERAGE_TOUCH") == nullptr`, return immediately (no env set → no work).
   - Read `step = ctx.preflight.cycles[ctx.cycle].userCycle`, `major = ctx.preflight.cycles[ctx.cycle].major`, `minor = ctx.preflight.cycles[ctx.cycle].minor`.
   - Compute `idx = hash(loc, major, minor) % kA4TouchMapSize`.
   - Saturating increment: `if (g_a4_touch_bitmap[idx] < 255) g_a4_touch_bitmap[idx]++;` (or use `std::min` with 255).
   - No I/O in this function except optional debug (see Step 3.1.4); keep it cheap for hot path.

**Deliverable**: `a4_touch_mark` and hash helper implemented in `ffi.cpp`; bitmap updated on each call when env is set.

---

### Step 3.1.3: Declare a4_touch_mark and call it from eqz in witgen.h

**Goal**: From the first line of `eqz(ExecContext& ctx, Val a, const char* loc)`, call `a4_touch_mark(ctx, loc)` so every EQZ invocation (pass or fail) is counted once. Do not add the call in the ExtVal overload.

**Facts**:

- `witgen.h` lines 177–178: `inline void eqz(ExecContext& ctx, Val a, const char* loc) {` then `if (a.asUInt32()) {`.
- The plan says: “Insert the touch-mark call immediately after the opening `{`, before `if (a.asUInt32())`” (PHASE_I §3.7).
- Declaration: `a4_touch_mark` must be declared before its use in `eqz`. It lives in the same namespace (`risc0::circuit::rv32im_v2::cpu`). So either: (1) declare in `witgen.h` before `eqz` (forward declaration of `void a4_touch_mark(ExecContext& ctx, const char* loc);`), or (2) declare in a small header included by both. Option (1) is minimal: in `witgen.h`, before line 177, add the declaration inside the same namespace (ExecContext is already defined above).

**Actions**:

1. In `witgen.h`, locate the namespace that contains `ExecContext` and `eqz` (e.g. `risc0::circuit::rv32im_v2::cpu`). Before the definition of `eqz` (line 177), add:
   - `void a4_touch_mark(ExecContext& ctx, const char* loc);`
   - (If the namespace is closed and reopened, add the declaration in the same namespace that contains `eqz`.)
2. In the **Val** overload of `eqz`, at the very beginning of the function body (line 177–178), add:
   - `a4_touch_mark(ctx, loc);`
   - so that the first line of the body is the call, then the existing `if (a.asUInt32()) { ... }`.
3. Do **not** add any call to `a4_touch_mark` in the **ExtVal** overload (lines 199–204); that overload only calls the Val overload per element, so marking in Val is sufficient.

**Deliverable**: One call to `a4_touch_mark(ctx, loc)` at entry of `eqz(ExecContext&, Val, const char*)`; no call in the ExtVal overload.

---

### Step 3.1.4: Clear bitmap at start of SeqForward run and add temporary debug print after loop

**Goal**: (1) Ensure each witgen run sees a zeroed bitmap when touch is enabled (so counts are per run). (2) Verify that touches are being recorded by printing a single debug line after the loop when `A4_COVERAGE_TOUCH` is set.

**Facts**:

- SeqForward branch in `risc0_circuit_rv32im_cpu_witgen`: `case kStepModeSeqForward:` then `for (size_t cycle = 0; cycle < lastCycle; cycle++) { stepExec(...); }` then `break;` (ffi.cpp 311–315).
- We must not clear the bitmap inside the loop (would erase every cycle). Clear once before the loop when `A4_COVERAGE_TOUCH` is set; after the loop, optionally print and then clear for next run (Phase 3.2 will replace the print with real emission).

**Actions**:

1. In `ffi.cpp`, in the `case kStepModeSeqForward:` block:
   - Before the `for` loop: if `std::getenv("A4_COVERAGE_TOUCH") != nullptr`, zero `g_a4_touch_bitmap` (e.g. `memset(g_a4_touch_bitmap, 0, kA4TouchMapSize)`). Include `<cstring>` if needed.
   - After the `for` loop (before `break;`): if `std::getenv("A4_COVERAGE_TOUCH") != nullptr`, compute a simple statistic:
     - Option A: total touches = sum of `g_a4_touch_bitmap[i]` for all i.
     - Option B: number of distinct buckets touched = count of i such that `g_a4_touch_bitmap[i] != 0`.
     - Print one line to stdout, e.g. `printf("<a4_touch_debug> total_touches=%u distinct_buckets=%u </a4_touch_debug>\n", totalTouches, distinctBuckets);` or similar. Use a distinct tag so it can be removed or ignored by Python until 3.2. This is **temporary** for Phase 3.1 verification only.
   - Do not yet serialize the full bitmap; that is Phase 3.2.

2. Document in code or in this plan: this debug line is for Phase 3.1 verification; Phase 3.2 will replace it with `<a4_touch_coverage>...</a4_touch_coverage>` and proper clear-for-next-run if needed.

**Deliverable**: Bitmap cleared at start of SeqForward when env set; one debug line printed after the loop with touch count or distinct-bucket count; manual run with `A4_COVERAGE_TOUCH=1` and a mutation config should show non-zero counts.

---

### Step 3.1.5: Build and verify

**Goal**: Rebuild the RISC Zero host (or the circuit C++ library) and run one mutation with `A4_COVERAGE_TOUCH=1` to confirm the debug line appears and counts are non-zero.

**Facts**:

- Build is project-specific (e.g. Cargo build of workspace that compiles the C++ kernel). No change to build system required for 3.1 beyond the modified sources.
- Executor currently does not set `A4_COVERAGE_TOUCH`; for 3.1 we only need to set it manually when running the host (e.g. `A4_COVERAGE_TOUCH=1 A4_MUTATION_CONFIG=... ./risc0-host ...`).

**Actions**:

1. Build the host (release mode as usual for A4).
2. Run the host with a mutation config and `A4_COVERAGE_TOUCH=1` (and `CONSTRAINT_CONTINUE` if desired). Parse stdout for `<a4_touch_debug>...</a4_touch_debug>` (or the chosen tag).
3. Assert that total_touches and/or distinct_buckets are non-zero and in a plausible range (e.g. thousands to low tens of thousands per the plan’s bound).
4. Optionally run the **same** config twice and confirm the two debug lines show the same numbers (determinism; full determinism test is Phase 3.4).

**Deliverable**: Build succeeds; one manual run shows the debug line with non-zero counts; documented in Phase 3.1 report or checklist.

---

## 5. Files to touch (Phase 3.1 only)

| File | Change |
|------|--------|
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | Add `kA4TouchMapSize`, `g_a4_touch_bitmap`, hash helper, `a4_touch_mark`; in SeqForward branch: clear bitmap when env set, after loop print debug line. |
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h` | Declare `a4_touch_mark` before `eqz`; in `eqz(ExecContext&, Val, const char*)` add call `a4_touch_mark(ctx, loc);` at entry. |

No new files required for 3.1; Phase 3.2 may add a dedicated `coverage.cpp` or keep everything in `ffi.cpp`.

---

## 6. Phase 3.1 completion checklist

- [ ] Step 3.1.1: Constants and bitmap in ffi.cpp.
- [ ] Step 3.1.2: Hash and `a4_touch_mark` in ffi.cpp; bitmap updated when env set.
- [ ] Step 3.1.3: Declaration in witgen.h; call from Val overload of eqz only.
- [ ] Step 3.1.4: Clear bitmap at start of SeqForward when env set; debug print after loop.
- [ ] Step 3.1.5: Build and manual run; debug line shows non-zero counts.
- [ ] No emission format for Python yet (deferred to 3.2).
- [ ] No step_bucket in hash key (Phase I: key = loc, major, minor only).

---

## 7. Dependencies for Phases 3.2–3.4 (reminders)

- **3.2**: Replace (or augment) the Phase 3.1 debug print with serialization of `g_a4_touch_bitmap` into `<a4_touch_coverage>...</a4_touch_coverage>`; Python parser; executor sets `A4_COVERAGE_TOUCH=1`. Hash and MAP_SIZE must match so Python can merge.
- **3.3**: Fuzzer/DB use the parsed touch bitmap to compute “new touch” count per run; optional persistence of global bitmap.
- **3.4**: Centralize MAP_SIZE, hash name, and B (if ever used) in docs; add test that same mutation yields same touch bitmap (determinism for touch).

---

*End of Phase 3.1 Implementation Plan. All assertions are tied to the cited files and line ranges; re-check those locations if the repo changes.*
