# Phase 2: Hook 1 -- Post-Prefix-Sum Total Check

## What We Are Implementing and Why

### Background

We have established (Phase 1 + Phase 1.5) that global constraint violations (permutation/lookup argument failures) exist in our mutation space and are NOT caught by local EQZ hooks. The check polynomial scan (Hook 2) can detect them but requires `circuit_debug` mode, which disables the ZK shift and makes proof verification always fail. This prevents us from checking for soundness bugs (verifier accepting an invalid proof) in the same run.

Hook 1 (Post-Prefix-Sum Total Check) solves this: it checks whether the accumulated total of all permutation/lookup contributions is zero, WITHOUT interfering with the proof pipeline. It runs after the prefix-sum phase and before apply-totals, reading 4 values from the accum buffer and comparing to zero. The proof continues normally afterward.

### What This Hook Does

After the accum phase's prefix-sum converts per-row deltas into running totals, the last row of the last 4 accum columns holds the grand total. For a valid permutation/lookup argument, this total must be zero (all uses cancel all provides). If ANY argument family (memory, U16, U8, cycle, BigInt) has an imbalance, the total is non-zero.

This is a binary signal: "something global broke" or "nothing global broke." It doesn't tell us WHICH family or WHICH row, but it has zero overhead and zero proof interference.

### Design Principles

1. **Env var controlled:** Only active when `A4_GLOBAL_RESIDUE=1` is set. Completely invisible otherwise.
2. **Read-only:** Does NOT modify any buffers. Reads 4 values, prints a tag, continues.
3. **Non-interfering:** The proof pipeline (prefix-sum -> apply-totals -> eval_check -> verification) is completely unaffected.
4. **Distinct tags:** Uses `<a4_global_residue_*>` tags that don't conflict with any other A4 tags.
5. **Easy removal:** Can be deleted later with zero impact on other hooks or the proof pipeline.

---

## Implementation Plan

### What to Change

**One file:** [ffi.cpp](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp)

Insert ~15 lines between the prefix-sum block (ends at line 520) and the apply-totals block (starts at line 522). No other files need modification.

### Exact Code to Add

After the prefix-sum closing brace (line 520) and before the apply-totals opening brace (line 522), insert:

```cpp
    // Hook 1: Post-prefix-sum global residue check
    if (std::getenv("A4_GLOBAL_RESIDUE") != nullptr) {
      bool all_zero = true;
      std::array<uint32_t, 4> residue_vals{};
      for (size_t j = 0; j < 4; j++) {
        size_t col = buffers->accum.cols - 4 + j;
        Fp val = buffers->accum.get(lastCycle - 1, col);
        residue_vals[j] = val.asUInt32();
        if (val != Fp(0))
          all_zero = false;
      }
      if (all_zero) {
        std::printf("<a4_global_residue_zero/>\n");
      } else {
        std::printf("<a4_global_residue_nonzero>{\"e0\":%u, \"e1\":%u, \"e2\":%u, \"e3\":%u}</a4_global_residue_nonzero>\n",
                    residue_vals[0], residue_vals[1], residue_vals[2], residue_vals[3]);
      }
      std::fflush(stdout);
    }
```

### Why This Location

The insertion point is between prefix-sum and apply-totals inside `risc0_circuit_rv32im_cpu_accum`. After prefix-sum:
- The last 4 columns of the accum buffer contain running totals (inclusive scan)
- The last row (`lastCycle - 1`) of these columns holds the GRAND TOTAL of all deltas
- This total has not yet been modified by apply-totals

The 4 values form one FpExt element (extension field = 4 base field elements). If all 4 are zero, the permutation/lookup arguments hold (with Schwartz-Zippel probability). If any is non-zero, some argument is violated.

### Thread Safety

This code runs in the single-threaded section of `risc0_circuit_rv32im_cpu_accum` (between the prefix-sum and apply-totals blocks). No thread safety concerns.

### No Additional Includes Needed

`ffi.cpp` already includes `<cstdlib>` (for `std::getenv`), `<cstdio>` (for `std::printf`), and the `Fp` type is available from `fp.h`. The `std::array` is available from `<array>` (already included).

---

## Testing Plan

### T1: Compilation Test

```bash
cd workspace/risc0-modified && cargo build -p risc0-circuit-rv32im-sys
cd workspace/output && cargo build --release -p risc0-host
```

### T2: Clean Run Without Env Var

```bash
/root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | grep 'a4_global_residue'
```
Expected: No output (env var not set).

### T3: Clean Run With Env Var (No Mutation)

```bash
A4_GLOBAL_RESIDUE=1 /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 | grep 'a4_global_residue'
```
Expected: `<a4_global_residue_zero/>` -- no mutation means no global violation.

### T4: COMP_OUT_MOD (Known Local + Global Failure)

```bash
echo '{"mutation_type": "COMP_OUT_MOD", "step": 785, "txn_idx": 16261, "word": 73117827}' > /tmp/test_mutation.json
A4_MUTATION_CONFIG=/tmp/test_mutation.json CONSTRAINT_CONTINUE=1 A4_GLOBAL_RESIDUE=1 \
  /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 > /tmp/phase2_t4.txt
grep 'a4_global_residue' /tmp/phase2_t4.txt
grep -c '<constraint_fail>' /tmp/phase2_t4.txt
```
Expected: `<a4_global_residue_nonzero>` (global failure) + 2 local constraint failures.

### T5: INSTR_WORD_MOD_SUR Global-Only (Known Global-Only)

Use run 39's config from the F2 campaign:
```bash
echo '{"mutation_type": "INSTR_WORD_MOD", "step": 573, "word": 14487}' > /tmp/test_global_only.json
A4_MUTATION_CONFIG=/tmp/test_global_only.json CONSTRAINT_CONTINUE=1 A4_GLOBAL_RESIDUE=1 \
  /root/arguzz/workspace/output/target/release/risc0-host --in1 5 --in4 10 2>&1 > /tmp/phase2_t5.txt
grep 'a4_global_residue' /tmp/phase2_t5.txt
grep -c '<constraint_fail>' /tmp/phase2_t5.txt
```
Expected: `<a4_global_residue_nonzero>` (global failure) + 0 local constraint failures. This is the critical test: Hook 1 catches the global-only violation that Hook 2 (cycle 0) also caught.

### T6: Consistency Check Against Hook 2

For T4 and T5, also enable circuit_debug and run with `A4_MUTATION_CONFIG` to compare:
- Hook 1 says "nonzero" -> Hook 2 should show cycle 0 non-zero
- Hook 1 says "zero" -> Hook 2 should show cycle 0 absent from non-zero list

This confirms both hooks agree on the same mutations.

### T7: Verification Still Works

Run T4's mutation WITHOUT circuit_debug but WITH `A4_GLOBAL_RESIDUE=1`:
```bash
grep 'Verifier' /tmp/phase2_t4.txt
```
Expected: Verifier output present (verification was attempted). Hook 1 should NOT prevent the proof from being generated and verified. The proof should be rejected (mutation breaks constraints), but the verifier should still RUN (unlike circuit_debug which makes the proof always invalid).

---

## Python-Side Changes

### Parser Addition

Add to [touch_coverage.py](a4/core/touch_coverage.py) or a new `global_residue.py`:

```python
import re
import json
from typing import Optional, Dict

_GLOBAL_RESIDUE_NONZERO_RE = re.compile(
    r'<a4_global_residue_nonzero>({.*?})</a4_global_residue_nonzero>'
)
_GLOBAL_RESIDUE_ZERO_RE = re.compile(r'<a4_global_residue_zero/>')

def parse_global_residue(output: str) -> Optional[Dict]:
    """
    Parse global residue tag from output.
    Returns:
      {"nonzero": True, "e0": ..., "e1": ..., "e2": ..., "e3": ...} if nonzero
      {"nonzero": False} if zero
      None if tag not found (env var not set)
    """
    m = _GLOBAL_RESIDUE_NONZERO_RE.search(output)
    if m:
        data = json.loads(m.group(1))
        return {"nonzero": True, **data}
    if _GLOBAL_RESIDUE_ZERO_RE.search(output):
        return {"nonzero": False}
    return None
```

### Campaign Integration (Later)

For formal campaigns, `run_mutation` in `run_diagnostic_campaign.py` would add `"A4_GLOBAL_RESIDUE": "1"` to the env dict, and the per-run parsing would call `parse_global_residue`. This is deferred until after Phase 3 and the comparison campaign.

---

## How This Hook Works (Easy Explanation)

### The Permutation Argument in Simple Terms

The RISC Zero zkVM uses a "permutation argument" to verify memory consistency. Every memory READ must match a prior memory WRITE at the same address. Instead of checking every read-write pair individually (which would be expensive), the circuit uses a mathematical trick:

For each memory transaction (read or write), it computes a "hash" using random values from the verifier. Writes contribute +1/hash, reads contribute -1/hash. If all reads match all writes, these contributions cancel out to zero across the entire trace.

The accum phase computes these contributions row by row and accumulates them via prefix-sum into a running total. After prefix-sum, the last row's total is the grand sum. If it's zero, memory is consistent. If it's non-zero, some read doesn't match its write.

### What Hook 1 Does

Hook 1 simply reads this grand total after prefix-sum and checks if it's zero. That's it. Four field element values, one comparison. It doesn't modify anything, doesn't interfere with the proof, and costs essentially nothing.

### How It Differs from the Other Hooks

| Hook | What it checks | When it runs | What it costs |
|------|---------------|-------------|--------------|
| **Hook 1 (this one)** | Is the grand total zero? | After prefix-sum, before apply-totals | 4 reads, 1 comparison, 0 proof impact |
| **Hook 2 (check poly scan)** | Are cycle-row constraint evaluations zero? | After eval_check, on the check polynomial | Linear scan, REQUIRES circuit_debug (breaks proof) |
| **Hook 3 (shadow replay)** | Per-family: which family's total is non-zero? | After step_TopAccum, replays accumulator | Re-walks entire trace, 0 proof impact |

Hook 1 is the cheapest and simplest. It gives a binary signal: "something global broke" or "nothing broke." Hook 2 gives per-cycle information but breaks the proof. Hook 3 gives per-family information without breaking the proof but costs more compute.

Together, Hooks 1 and 3 (both non-interfering) would give us: "something global broke" (Hook 1) + "specifically the memory permutation broke" (Hook 3), all without affecting the verifier. Hook 2 is reserved for deep debugging when per-cycle information is needed.
