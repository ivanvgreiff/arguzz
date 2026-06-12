# Global Constraint Hooks Catalog (v2)

*Comprehensive reference for all global constraint detection mechanisms in the A4 RISC Zero fuzzer.*

---

## Prerequisite Concepts

Before understanding the hooks, you need to understand these concepts in the RISC Zero architecture.

### What Are "Global Constraints"?

RISC Zero's circuit has two categories of constraints:

**Local constraints** check properties of one or more execution cycles (rows). Most check the current row, but many also reference the PREVIOUS row (or rows further back). For example: "Does the current cycle number equal the previous cycle number plus 1?" (`cycle@1 + 1` in `top.zir`) or "Does the current PC match the next-PC that the previous instruction computed?" (`next_pc_low@1`). Data taps with `back=1` are used for adjacent-row transitions, and some taps go as far back as 68 rows (for BigInt accumulator powers). These are enforced by `EQZ` checks in the witness generation code (`step_Top` in `steps.cpp`). When a local constraint fails, the `eqz()` function fires and our A4 hooks capture exactly which constraint failed, at which cycle, with what value.

**Global constraints** check properties that span the ENTIRE execution trace -- cross-row consistency that no single row can verify alone. There are three types in RISC Zero:

1. **Memory permutation argument**: Every memory READ must match a prior WRITE at the same address with the same value. This is verified by a LogUp-style argument where each transaction contributes `count / hash(addr, cycle, data)` to a running sum. If all reads match all writes, the sum cancels to zero.

2. **Lookup arguments (U8, U16, Cycle)**: Range checks that verify values fit within expected bounds. For example, when the circuit claims a value is a valid 16-bit number, a U16 lookup entry is created. The lookup table provides matching entries for all valid values (0-65535). The LogUp sum over all entries must cancel to zero.

3. **BigInt polynomial accumulator**: Verifies that large-integer arithmetic (used by cryptographic precompiles like modular multiplication) was performed correctly. Unlike the permutation/lookup arguments, BigInt uses a polynomial state machine (not LogUp) and has its own EQZ check.

### The Prover Pipeline

Understanding where each hook sits requires understanding the prover's phases:

```
Phase 1: WITNESS GENERATION (step_Top)
├── Processes each cycle using the mutated preflight trace
├── Fills data columns (the "witness")
├── Calls extern_memoryDelta for each memory transaction
├── Calls extern_lookupDelta for each U8/U16/Cycle lookup
├── EQZ checks fire for local constraints
└── Our A4 local constraint hooks capture failures here

Phase 2: ACCUMULATOR DELTA COMPUTATION (step_TopAccum)
├── For each cycle, computes the LogUp contribution to the running sum
├── Uses zeroBack: previous-row accum reads return 0
├── EQZ checks verify delta arithmetic (always passes for value mutations)
├── BigInt accumulator: separate state machine in user columns 0-22
│   └── BigIntPolyOpEqz: EQZ that CAN fire (not zeroBack'd)
└── Our A4 accum hooks capture delta-check touches/failures

Phase 3: ACCUMULATOR FINALIZATION
├── Prefix-sum: converts per-row deltas into running totals (last 4 machine columns)
├── Apply-totals: adjusts all machine columns with the running total
└── No EQZ checks here -- purely arithmetic

Phase 4: PROVER CONSTRAINT EVALUATION (eval_check → poly_fp)
├── Evaluates the validity polynomial at every point in the extended domain
├── Uses the FINALIZED accum columns with real back-references
├── Produces the check polynomial
└── In circuit_debug mode: ZK shift disabled, check polynomial is meaningful at cycle rows

Phase 5: VERIFICATION
├── Verifier evaluates poly_ext at a random DEEP query point
├── Compares with the committed check polynomial
├── FRI check for low-degree
└── Accept or reject
```

### The LogUp Mechanism (How Permutation/Lookup Arguments Work)

For each argument (memory, U16, U8, cycle), the circuit creates entries with:
- A **count** (+1 for "uses" / -1 for "provides")
- A **hash** computed from the argument fields using verifier-supplied randomness
- A **delta** = `count / hash`

All deltas are summed across all rows. If the sum is zero, the argument is satisfied. If non-zero, something is inconsistent.

The randomness comes from the `mix` buffer, which is determined by the Fiat-Shamir protocol after the data columns are committed. This means the prover cannot know the randomness while generating the witness -- the LogUp check is probabilistically sound.

### The BigInt Accumulator (How Precompile Verification Works)

BigInt operations (modular arithmetic on large integers) are invoked via ECALL with `a7 = HOST_ECALL_BIGINT (5)`. The execution side runs a bibc (BigInt Bytecode) program that performs the computation and produces a 16-byte witness per cycle.

The BigInt accumulator is a polynomial state machine with three registers:
- `poly`: accumulates the current polynomial
- `term`: stores an intermediate term
- `total`: accumulates the final result

Operations (Shift, SetTerm, AddTotal, Carry1, Carry2) build up a polynomial identity. The **Eqz** operation checks that the total equals zero -- if it does, the computation was correct.

Key difference from LogUp: BigInt uses the USER accum columns (offsets 0-22), which are NOT affected by `zeroBack`. This means BigInt EQZ checks (`BigIntPolyOpEqz`) read real previous-row values and CAN detect failures during `step_TopAccum`. These would show up as `phase:accum` constraint failures in our existing hooks.

### Where Each Type of Constraint Lives

| Constraint Type | Enforcement Mechanism | Where Failures Are Detected |
|---|---|---|
| Local (instruction, ALU, memory format, PC transitions) | EQZ in `step_Top` (can reference previous rows via back=1) | Our local constraint hooks (`phase:local`) |
| Accum delta computation (per-row LogUp arithmetic) | EQZ in `step_TopAccum` (GenerateAccum.cpp:182/125) | Our accum hooks (`phase:accum`), but never fires for value mutations due to zeroBack |
| Memory permutation (read-write consistency across ALL rows) | LogUp grand total = 0 | Hook 1 (binary), Hook 3 (per-family, per-address) |
| U16 lookup (range check, cross-row table matching) | LogUp grand total = 0 | Hook 1 (binary), Hook 3 (per-family, per-index) |
| U8 lookup (range check) | LogUp grand total = 0 | Hook 1 (binary), Hook 3 (per-family, per-index) |
| Cycle ordering (cross-row) | LogUp grand total = 0 | Hook 1 (binary), Hook 3 (per-family, per-index) |
| BigInt polynomial identity (precompile verification) | EQZ in `BigIntPolyOpEqz` (user columns, NOT zeroBack'd) | `phase:accum` in existing EQZ hooks |

---

## Implemented Hooks

### Hook 1: Post-Prefix-Sum Total Check

**Status: IMPLEMENTED AND TESTED (Phase 2)**

**Location:** `ffi.cpp`, inside `risc0_circuit_rv32im_cpu_accum`, between the prefix-sum and apply-totals phases.

**Env var:** `A4_GLOBAL_RESIDUE=1`

**What it does:** After prefix-sum converts per-row deltas into running totals, the last row of the last 4 machine accum columns holds the grand total of ALL LogUp contributions (memory + U16 + U8 + cycle). If this total is zero, all permutation/lookup arguments are satisfied. If non-zero, at least one is broken.

Hook 1 reads these 4 values (which form one FpExt extension field element) and emits:
- `<a4_global_residue_zero/>` if all 4 elements are zero
- `<a4_global_residue_nonzero>{"e0":..., "e1":..., "e2":..., "e3":...}` if any is non-zero

**What it does NOT cover:** BigInt accumulator (separate user columns, not included in the machine grand total).

**Relationship to Hook 3:** Hook 1 and Hook 3 compute the same mathematical quantity (the LogUp grand total) from the SAME underlying data (the DATA buffer filled during witgen). Hook 1 reads the circuit's own accumulated result. Hook 3 independently recomputes it from extern call records. Having both is only useful as a cross-check; Hook 3 alone provides strictly more information.

**How it works in simple terms:** Imagine you run a warehouse. Every item that comes in gets a +1 tally. Every item that goes out gets a -1 tally. At the end of the day, the total should be 0 (everything in = everything out). Hook 1 reads this total and tells you: "balanced" or "imbalanced."

**Properties:**

| Property | Value |
|---|---|
| Granularity | Binary (failed / ok) |
| Per-argument-family? | No -- all families mixed |
| Interferes with proof? | **No** |
| Requires circuit_debug? | No |
| Performance overhead | Negligible (4 reads) |
| Covers BigInt? | No |

**Tested results:**
- Clean run: `<a4_global_residue_zero/>`
- COMP_OUT_MOD: `<a4_global_residue_nonzero>` -- matches Hook 3's memory family residue exactly
- INSTR_WORD_MOD_SUR (global-only): `<a4_global_residue_nonzero>`, 0 local failures

---

### Hook 2: Check Polynomial Scan (circuit_debug)

**Status: IMPLEMENTED AND TESTED (Phase 1)**

**Location:** `prover.rs` (Rust), after `eval_check` computes the check polynomial.

**Env var:** Requires `circuit_debug` Cargo feature flag (compile-time, not runtime).

**What it does:** The prover computes V(x) = C(x) / Z(x), where C(x) is the mixed constraint polynomial and Z(x) = (3x)^cycles - 1 is the vanishing polynomial for the ZK coset. Hook 2 scans this check polynomial at cycle-row positions.

With `circuit_debug` enabled, the ZK shift is disabled (`zk_shift` skipped in `make_coeffs`). The trace polynomials are evaluated on the ORIGINAL domain instead of the coset. At cycle rows on the original domain, Z(x) evaluates to the constant 3^cycles - 1 (non-zero), so V(x) = C(x) / (3^cycles - 1). This means V(x) = 0 at a cycle row if and only if C(x) = 0 at that row (dividing by a non-zero constant preserves zero/non-zero). So scanning V(x) at cycle rows effectively checks C(x) at cycle rows.

Without `circuit_debug`, the trace is on the coset where Z(x) = 0 at cycle rows, making V(x) = C(x)/0 -- a 0/0 indeterminate form. The polynomial division is exact but point-wise evaluation is undefined, so ALL entries appear non-zero. This is why Hook 2 requires `circuit_debug`.

**What it does NOT cover:** Per-family breakdown (all constraints are mixed via `poly_mix`).

**How it works in simple terms:** The prover builds a "scorecard" that should be all zeros if the computation was valid. With circuit_debug, we can read this scorecard directly. Each non-zero entry tells us "something went wrong at cycle X." For global constraint violations, the scorecard shows a non-zero at cycle 0 (the wrap-around point where the accumulator checks its total).

**CRITICAL CAVEAT:** `circuit_debug` disables the ZK shift, which makes the proof ALWAYS INVALID to the verifier. This means you CANNOT check for soundness bugs in the same run. You need a separate run without circuit_debug for verification.

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-cycle |
| Per-argument-family? | No |
| Interferes with proof? | **YES** (proof always invalid) |
| Requires circuit_debug? | **YES** (compile-time feature flag) |
| Performance overhead | Low (linear scan) |
| Covers BigInt? | Yes (all constraints in the check polynomial) |

**Tested results:**
- Clean run with circuit_debug: 0 non-zero cycles
- COMP_OUT_MOD: non-zero at [0, 16777] -- cycle 0 = global, cycle 16777 = local
- INSTR_WORD_MOD_SUR: non-zero at [0] only -- global-only violation
- 86-run campaign: consistent, cycle 0 appears whenever Hook 1 says nonzero

---

### Hook 3: Per-Family Residues via Extern Interception (with Per-Address Detail)

**Status: IMPLEMENTED AND TESTED (Phase 3 + Phase 3.5)**

**Location:** `ffi.cpp` -- intercepts during witgen, computes at start of accum phase.

**Env var:** `A4_FAMILY_RESIDUE=1` (also requires `A4_MUTATION_CONFIG` or `A4_COVERAGE_TOUCH` for sequential mode)

**What it does:** During witness generation, the circuit calls `extern_memoryDelta(addr, cycle, dataLow, dataHigh, count)` for every memory transaction and `extern_lookupDelta(table, index, count)` for every U8/U16/Cycle lookup. Hook 3 records ALL of these calls into two vectors.

After the mix buffer (verifier randomness) becomes available at the start of the accum phase, Hook 3 replays the LogUp computation separately for each family:

For each **memory** record: `delta = Fp(count) * inv(r_addr * addr + r_cycle * cycle + r_dataLow * dataLow + r_dataHigh * dataHigh + offset)`

For each **lookup** record: `delta = Fp(count) * inv(r_val * index + offset)` (with family-specific randomness)

The deltas are summed per family. If a family's total is zero, that argument is consistent. If non-zero, that family is broken.

**Per-address detail (Phase 3.5):** When a family has a non-zero residue, Hook 3 further groups by address (memory) or index (lookups) and computes per-group residues. This identifies WHICH specific memory addresses or lookup values have broken chains.

For register addresses, the address is decoded to a human-readable register name (e.g., `x17` for address `0x3fffc031`).

**What it does NOT cover:** BigInt accumulator (BigInt does not use `extern_memoryDelta` or `extern_lookupDelta`).

**How it works in simple terms:** During the execution, every memory operation and every range check creates a "receipt." Hook 3 collects all these receipts. After the verifier sends its random challenge values, Hook 3 uses them to compute a "checksum" for each type of receipt separately. If the memory checksum is non-zero, some memory read doesn't match its write. If the U16 checksum is non-zero, some value isn't in the valid range.

When a checksum fails, Hook 3 goes further and checks EACH individual memory address or lookup value. It reports the specific broken addresses, like "register x17 has unmatched reads/writes" or "U16 value 45000 has unmatched entries."

**Output tags:**

```
<a4_family_residue>{"family":"memory", "nonzero":true, "e0":..., "e1":..., "e2":..., "e3":...}</a4_family_residue>
<a4_family_residue>{"family":"u16", "nonzero":false}</a4_family_residue>
<a4_family_residue>{"family":"u8", "nonzero":false}</a4_family_residue>
<a4_family_residue>{"family":"cycle", "nonzero":false}</a4_family_residue>
<a4_family_stats>{"family":"memory", "records":69448, "plus":34724, "minus":34724, "distinct_addrs":13952}</a4_family_stats>
<a4_family_detail>{"family":"memory", "broken_addrs":[
  {"addr":527468,"hex":"0x00080c6c","plus":11,"minus":11},
  {"addr":1073725473,"hex":"0x3fffc021","reg":"x1","plus":664,"minus":664},
  {"addr":1073725489,"hex":"0x3fffc031","reg":"x17","plus":92,"minus":92}
],"broken_count":3,"total_addrs":13952}</a4_family_detail>
```

**Properties:**

| Property | Value |
|---|---|
| Granularity | Per-family + per-address/per-index |
| Per-argument-family? | **Yes** (memory, U16, U8, cycle separately) |
| Interferes with proof? | **No** |
| Requires circuit_debug? | No |
| Performance overhead | Moderate (records during witgen, replays LogUp computation) |
| Covers BigInt? | No (BigInt uses different externs) |

**Tested results:**
- Clean run: all families zero, 69448 memory records, 184257 lookup records
- COMP_OUT_MOD: memory nonzero at 1 address (x12, the mutated register), others zero
- INSTR_WORD_MOD_SUR (global-only): memory nonzero at 3 addresses (PC, x1, x17), 0 local failures
- INSTR_TYPE_MOD: sometimes memory+cycle both nonzero (instruction type change affects both)
- Campaign: `G=memory(x17,x1)` format in per-run display

---

## Not-Implemented / Conceptual Hooks

### Hook 4: Re-run step_TopAccum Without zeroBack

**Status: NOT IMPLEMENTED. Superseded by Hook 3.**

The idea: after prefix-sum + apply-totals finalize the accum columns, re-run `step_TopAccum` but with `zeroBack` disabled. The EQZ checks would then read real previous-row accum values and detect transition failures.

**Why not pursued:** Only cycle 0 would ever fail (apply-totals makes all other transitions correct by construction). Hook 3 provides per-family and per-address detail, which is strictly more informative. Hook 4 would also corrupt the accum buffer (step_TopAccum writes to it), requiring a buffer copy.

### Hook 5: Non-Coset poly_fp Evaluation

**Status: NOT IMPLEMENTED. Superseded by Hook 2 + circuit_debug.**

The idea: evaluate `poly_fp` on the original domain (without ZK shift) to get meaningful constraint values at cycle rows without needing circuit_debug.

**Why not pursued:** Significant implementation complexity (NTT operations) for the same information that Hook 2 already provides via circuit_debug. Also, would still only show cycle 0 for global failures.

### Hook 6: Runtime circuit_debug Toggle

**Status: NOT IMPLEMENTED. Would be a practical improvement to Hook 2.**

The idea: replace the compile-time `#[cfg(feature = "circuit_debug")]` checks with runtime `std::env::var("A4_CHECK_POLY")` checks. This eliminates the need for separate builds.

**Why not yet pursued:** Would require modifying the ZK shift logic in `make_coeffs` and the DEEP query point selection, both in the Rust prover. Low priority since Hook 2 already works and is only needed for the consistency validation campaign.

---

## BigInt Coverage Gap

**Current state:** None of the three implemented hooks cover the BigInt polynomial accumulator.

**Why:** BigInt uses a fundamentally different mechanism from the LogUp-based permutation/lookup arguments:
- BigInt uses user accum columns (0-22), not machine accum columns (23+)
- BigInt uses `extern_bigIntExtern` (16 witness bytes), not `extern_memoryDelta`/`extern_lookupDelta`
- BigInt accumulation is a polynomial state machine (poly/term/total), not LogUp (count/hash)
- BigInt EQZ checks (`BigIntPolyOpEqz` at `inst_bigint.zir:315`) ARE captured by existing accum hooks (user columns are not zeroBack'd), so BigInt failures show up as `phase:accum` constraint failures

**Impact:** For A4's current mutation types (which don't target BigInt data), this gap has no practical effect. BigInt mutations would require targeting `trace.bigint_bytes` or the ECALL dispatch. If such mutations were added, BigInt failures would be caught by the existing `phase:accum` EQZ hooks, not by Hooks 1/3.

---

## Comparison Summary (Current State)

| Hook | Status | Granularity | Proof Impact | Per-Family | BigInt | Primary Use |
|---|---|---|---|---|---|---|
| **1: Binary residue** | DONE | Binary | None | No | No | Every run: quick global signal |
| **2: Check poly scan** | DONE | Per-cycle | Breaks proof | No | Yes | Deep debugging: per-cycle detail |
| **3: Per-family + detail** | DONE | Per-family, per-address | None | Yes | No | Every run: which family/address broke |

---

## Recommended Configuration

**Standard campaigns (every run):**
- `A4_FAMILY_RESIDUE=1` -- Hook 3 (per-family + per-address detail, strictly more informative)
- `A4_GLOBAL_RESIDUE=1` -- Hook 1 (optional, adds zero information beyond Hook 3 since both compute from the same underlying data; useful only as a cheap cross-check that the shadow computation matches the circuit's own result)
- Normal build (no circuit_debug)

**Consistency validation campaigns (occasional):**
- All env vars above PLUS `circuit_debug` feature flag
- All 3 hooks active, verify they agree
- Proof always invalid (expected)

**Deep debugging (rare, specific mutations):**
- `circuit_debug` build for per-cycle check polynomial scan
- Used when Hook 3's per-address detail isn't enough and you need to know WHICH constraint expression failed at which cycle
