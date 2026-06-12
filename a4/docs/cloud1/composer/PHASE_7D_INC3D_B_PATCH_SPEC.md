# Phase 7d Inc 3d — Phase B patch spec

**Branch**: `arguzz/b7-race-instrumentation` in `workspace/risc0-modified/` (user to create).
**Goal**: add three pieces of instrumentation that together pinpoint the source of the `FieldToWord:291` race.
**Built-in regression check**: after each patch, the standalone reproducer (30 runs of mut27) must remain 30/30 byte-identical and produce the same baseline hashes.

---

## Baseline hashes (current `c2e77443…` host, on this machine)

```
<a4_touch_verbose>       sha256 = ac56a7278b17faa7…  (30/30 runs)
<a4_accum_touch_verbose> sha256 = bf4891cb80a0d2b1…  (30/30 runs)
<a4_touch_coverage>      sha256 = b99b53555d06c752…  (30/30 runs)
```

(With `mutation_type=MEM_VAL_MOD step=3259 txn_idx=29184 word=4294967295`; guest args `--in1 5 --in4 10`.)

After each Phase B patch, **B1 changes the verbose tag layout (so the verbose hash will change once, deterministically)** but B2/B4 must NOT change the existing hashes.

---

## Build commands

After applying patches:

```bash
cd /root/arguzz/workspace/output
cargo build --release --bin risc0-host
# new sha:
sha256sum target/release/risc0-host
```

Build time: ~2-3 min for incremental rebuild of host crate, ~15-20 min for full rebuild if rv32im-sys is touched.

---

## B1 — Self-identifying verbose blocks  *(low risk, fixes 49/50 alignment as a side effect)*

### Why
- The current `<a4_touch_verbose>[…]</a4_touch_verbose>` block has no identifying metadata. When the host crashes mid-campaign (e.g., `PRE_EXEC_REG_MOD @ step 2708` SIGSEGV), block N's output goes missing and downstream parsers must guess alignment via `_candidate_block_indices`.
- We want each block to self-identify: `mutation_config_sha256`, `pid`, and a monotonic `seq` counter.

### Files to patch
1. **`risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`** — add helper to compute mutation-config SHA at startup, modify the two emission sites (lines 426-437 and 705-717) to include attributes.

### Patch (apply directly, no need for codegen regeneration)

In `ffi.cpp` near the top of the file (next to other globals around line 105), add:

```cpp
// B1 (Inc 3d): self-identifying tag metadata.
static std::string g_a4_mutation_sha;
static int g_a4_pid = 0;
static uint64_t g_a4_witgen_seq = 0;
static uint64_t g_a4_accum_seq = 0;

static const std::string& a4_mutation_sha() {
  if (g_a4_mutation_sha.empty()) {
    const char* path = std::getenv("A4_MUTATION_CONFIG");
    if (path == nullptr) { g_a4_mutation_sha = "none"; return g_a4_mutation_sha; }
    std::ifstream f(path, std::ios::binary);
    if (!f) { g_a4_mutation_sha = "ereadfail"; return g_a4_mutation_sha; }
    std::ostringstream ss; ss << f.rdbuf();
    std::string body = ss.str();
    // Use std::hash as a cheap 64-bit fingerprint; cryptographic strength is not needed
    // because the fuzzer (caller) supplies the canonical SHA via env var if desired.
    const char* ext = std::getenv("A4_MUTATION_SHA256");
    if (ext != nullptr) {
      g_a4_mutation_sha = ext;
    } else {
      // Fallback: 64-bit FNV-1a of the file contents.
      uint64_t h = 0xcbf29ce484222325ULL;
      for (unsigned char c : body) { h ^= c; h *= 0x100000001b3ULL; }
      char buf[24]; std::snprintf(buf, sizeof(buf), "fnv1a64=%016llx", (unsigned long long)h);
      g_a4_mutation_sha = buf;
    }
    if (g_a4_pid == 0) g_a4_pid = (int)getpid();
  }
  return g_a4_mutation_sha;
}
```

Also add `#include <fstream>`, `#include <sstream>`, `#include <unistd.h>` to the includes section if not already there.

Then **replace** the witgen verbose emission block at lines **426-437** with:

```cpp
if (std::getenv("A4_COVERAGE_TOUCH") != nullptr && std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
  std::printf("<a4_touch_verbose mut=\"%s\" pid=\"%d\" seq=\"%llu\">[",
              a4_mutation_sha().c_str(),
              (g_a4_pid ? g_a4_pid : (g_a4_pid = (int)getpid())),
              (unsigned long long)g_a4_witgen_seq++);
  bool first = true;
  for (const auto& key : g_a4_touch_verbose_set) {
    if (!first) std::printf(",");
    std::printf("\"%s\"", key.c_str());
    first = false;
  }
  std::printf("]</a4_touch_verbose>\n");
  std::fflush(stdout);
  g_a4_touch_verbose_set.clear();
}
```

And the **accum** verbose emission block at lines **705-717**:

```cpp
if (std::getenv("A4_COVERAGE_TOUCH") != nullptr
    && std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
  std::printf("<a4_accum_touch_verbose mut=\"%s\" pid=\"%d\" seq=\"%llu\">[",
              a4_mutation_sha().c_str(),
              (g_a4_pid ? g_a4_pid : (g_a4_pid = (int)getpid())),
              (unsigned long long)g_a4_accum_seq++);
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
```

### Parser change (Python side)

`a4/audits/B7_verbose_touch.py` — extend the block-finder regex to capture the new attrs and **fail hard** when paired A/B blocks don't have matching `mut="…"` values:

```python
VERBOSE_RE = re.compile(
    r'<a4_touch_verbose(?:\s+mut="([^"]*)"\s+pid="(\d+)"\s+seq="(\d+)")?\s*>\[(.*?)\]</a4_touch_verbose>',
    re.DOTALL,
)
```

When `mut="…"` attributes are present on both sides, **require** that A.mut == B.mut for the same paired index — otherwise raise `ParserAlignmentError`. This eliminates the `_candidate_block_indices` heuristic for instrumented runs.

### Regression check
- After B1: verbose-tag SHA WILL change deterministically (new attributes added to opening tag).
- New baseline: capture `ac56a7278b17faa7` → some new hash X. Record X.
- Repeat 30-run reproducer — all 30 must produce hash X.
- Coverage hash should remain `b99b53555d06c752…` (unchanged).
- Accum-verbose hash should remain `bf4891cb80a0d2b1…` only if accum doesn't get the new attrs — actually it does get them, so its hash also changes deterministically.

---

## B2 — Targeted `FieldToWord:291` logging  *(highest diagnostic value)*

### Why
- The race fires inside `exec_FieldToWord(...)` at the `if (lowIsZero)` branch (line 7120 of `steps.cpp`).
- We need to know: when this branch fires (or doesn't fire) — what was `arg0`, `low`, `high`, and which Poseidon major/minor cycle was it in?
- Comparing the `<a4_ftw291>` sequence between A and B will tell us **exactly which Poseidon2 output's bit differs** — that, in turn, lets us trace back upstream to find where the divergence first appears.

### Files to patch
1. **`risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp`** — insert `fprintf` at line 7120 (in `exec_FieldToWord`).

**WARNING**: `steps.cpp` is auto-generated from zirgen. If anyone regenerates it from the zirgen DSL, this patch will be overwritten. For this diagnostic build that's fine. Document the patch as a one-off in the branch.

### Patch

Replace lines 7119-7140 (the `ComponentStruct x9; if-else-else` block) with:

```cpp
ComponentStruct x9;
// B2 (Inc 3d): emit per-touch diagnostic for FieldToWord branch selection.
if (std::getenv("A4_FTW291_TRACE") != nullptr) {
  const PreflightCycle& cy = ctx.preflight.cycles[ctx.cycle];
  fprintf(stderr,
    "<a4_ftw cycle=\"%zu\" userCycle=\"%u\" pc=\"0x%08x\" major=\"%u\" minor=\"%u\" "
    "arg0=\"%u\" low=\"%u\" high=\"%u\" lowIsZero=\"%u\"/>\n",
    ctx.cycle,
    cy.userCycle,
    cy.pc,
    (unsigned)cy.major,
    (unsigned)cy.minor,
    arg0.asUInt32(),
    x2._super._super.asUInt32(),
    x3._super._super.asUInt32(),
    (unsigned)to_size_t(x5._super));
}
if (to_size_t(x5._super)) {
  // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)
  EQZ(x2._super._super, "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)");
  // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:292)
  NondetU16RegStruct x10 = exec_U16Reg(ctx,x6, LAYOUT_LOOKUP(layout1, _2.arm0._0));
  x9 = x7;
} else if (to_size_t((Val(1) - x5._super))) {
  // FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:294)
  NondetU16RegStruct x11 = exec_U16Reg(ctx,x8, LAYOUT_LOOKUP(layout1, _2.arm1._0));
  x9 = x7;
} else {

  // <----------------------- START OF FAULT INJECTION ----------------------->
  if(std::getenv("FAULT_INJECTION_ENABLED") != NULL && !(0 && "Reached unreachable mux arm")) {
    printf("SKIP ASSERT: %s:%d\n", __FILE__, __LINE__);
  } else {
    assert(0 && "Reached unreachable mux arm");
  }
  // <------------------------ END OF FAULT INJECTION ------------------------>

}
```

The `if (std::getenv("A4_FTW291_TRACE") != nullptr)` guard means this fires **only when explicitly enabled** — protects production runs from logging spam. On a single mutation run, expect 2486×2 = ~4972 Poseidon2 cycles × ~16 FieldToWord calls per cycle = ~80K trace lines (~10MB stderr). Manageable.

### Regression check (without `A4_FTW291_TRACE` set)
- Coverage hash, verbose hash, accum hash should all be **unchanged** from B1 baseline. The added code path is gated by env var.

### How to read it after a POS run
For paired logs `A.log` and `B.log` with `A4_FTW291_TRACE=1` set:
```bash
grep '<a4_ftw' A.log | sha256sum
grep '<a4_ftw' B.log | sha256sum
# If they differ:
diff <(grep '<a4_ftw' A.log) <(grep '<a4_ftw' B.log) | head -20
```
The first differing line gives `(cycle, arg0, low, high, lowIsZero)` for both A and B. If `arg0` is the same but `lowIsZero` differs → the prover is making a different choice for the same input (an upstream constraint or NondetBitReg implementation bug). If `arg0` differs → the divergence is **upstream of FieldToWord** in Poseidon2 → time for B4 (boundary hashes).

---

## B3 — Non-allocating racy-context counter  *(optional, cheap, useful for "is verbose set the amplifier?")*

### Why
- The verbose set uses `std::set<std::string>` — allocates a string for every constraint check.
- We want to know: if we turn off verbose entirely but count the racy bit with a single atomic counter, do A and B still diverge?

### Patch

In `ffi.cpp`, near `a4_touch_mark` (around line 118), modify it to:

```cpp
static uint64_t g_a4_ftw291_95_count = 0;  // sequential witgen — no atomic needed for stepExec
static uint64_t g_a4_ftw291_other_count = 0;

void a4_touch_mark(ExecContext& ctx, const char* loc) {
  if (std::getenv("A4_COVERAGE_TOUCH") == nullptr)
    return;
  const PreflightCycle& cy = ctx.preflight.cycles[ctx.cycle];
  // ... existing bitmap-hash code ...

  if (std::getenv("A4_COVERAGE_TOUCH_VERBOSE") != nullptr) {
    char key[4096];
    std::snprintf(key, sizeof(key), "%s|%u|%u", loc, (unsigned)cy.major, (unsigned)cy.minor);
    auto& vset = ctx.is_accum_phase ? g_a4_accum_touch_verbose_set : g_a4_touch_verbose_set;
    vset.insert(std::string(key));
  }

  // B3 (Inc 3d): non-allocating FTW291 counter (always on when A4_COVERAGE_TOUCH=1).
  if (cy.major == 9 && cy.minor == 5 && strstr(loc, "inst_p2.zir:291") != nullptr) {
    g_a4_ftw291_95_count++;
  }
}
```

And emit the count in the existing `<a4_touch_debug>` line (line 417) or as a separate tag:

```cpp
std::printf("<a4_ftw291_95_count value=\"%llu\"/>\n", (unsigned long long)g_a4_ftw291_95_count);
g_a4_ftw291_95_count = 0;
```

### Test
- Run with `A4_COVERAGE_TOUCH=1` but **without** `A4_COVERAGE_TOUCH_VERBOSE=1`.
- Compare counter values across A and B. If counter differs → race confirmed without verbose set.
- If counter is identical even when verbose's symmetric-diff is non-empty → verbose set IS the amplifier.

---

## B4 — Boundary hashes  *(medium effort, definitive localization)*

### Why
- B2 tells us *which Poseidon2 cycle* is racy. B4 tells us *what stage of computation* produced the divergent value.

### Files (depends on what's in this fork — to be confirmed at branch creation)
1. `risc0/circuit/rv32im/src/prove/witgen/mod.rs` — preflight-trace-after-mutation hash.
2. `risc0/circuit/rv32im/src/prove/witgen/poseidon2.rs` (if exists) — Poseidon2 input-state and output-state hashes per round.
3. `risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` — `ExecBuffers` data hash post-`stepExec`.

### Hash function
Use `blake3` (already in `risc0_zkp` deps); emit as hex via `<a4_boundary stage="X" hash="…" idx="N"/>`.

### Defer to follow-up
B4 is the most invasive change; defer until B2 narrows down WHICH Poseidon2 cycle to focus on. Then B4 can be scoped to hash only that cycle's neighborhood.

---

## Recommended execution order

1. **B1** (low risk, immediate alignment fix, no semantic impact).
2. **B3** (5-line change, lets us drop the heavy verbose set during diagnosis).
3. **B2** (the key signal).
4. **Local regression** after each: 30× sequential reproducer, hash check.
5. **POS deployment**: rebuild bundle, re-run Inc 3c SPREAD plan (5 pairs × 50 muts) with `A4_FTW291_TRACE=1`. Compare paired `<a4_ftw>` outputs.
6. **B4** only if B2 shows `arg0` actually differs between A and B at a specific Poseidon2 cycle.

---

## Acceptance criteria for closing B7

We will consider B7 **closed** when one of the following is true:

1. **B2 trace on POS shows identical `arg0` but different `lowIsZero` for the same `(cycle, major, minor)` on A vs B**: then the race is in the prover's NondetBitReg implementation or upstream witness construction. Root cause is local to a small file; fixable.
2. **B2 shows different `arg0`**: then the race is upstream in Poseidon2. B4 boundary hashes localize the stage. Once stage is known, root cause is one of: uninitialized memory, parallel-iteration nondeterminism in `poly_fp`/`ExecBuffers`, or a real Poseidon2 implementation bug.
3. **B3 counter shows the race even with verbose OFF**: confirms it's NOT a verbose-set perturbation artifact.
4. **All three above plus a code-level fix** that makes 5+ paired campaigns on POS produce 0 racy bits.

We will then write a final closure report (`PHASE_7D_INC3D_CLOSURE.md`) and proceed to Phase 8 (large-scale fuzzing).
