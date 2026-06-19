# IV.POS.8 — D2.B Mechanism Report

**Subject:** Why some A4 mutation kinds affect proof verification and others don't — a mechanism-level explanation grounded in the RISC-0 zkVM witgen architecture.

**Audience:** Pro check-in (post-D2.B), Ivan, future Arguzz/A4 maintainers.

**Status:** v1.0 — final D2.B knowledge product. Companion to:
- [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md) (W-17 set_cycle overwrite — B.3)
- [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md) (W-18 execution-derived witness keys — B.4/B.5)
- [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) §6c (arm-semantic certainty stack), §6d (Batch 3 attestation predictions), §9b (soundness-bug guard).

**What this document is for:**
- A self-contained explanation, from first principles, of why **3 of the 8 A4 mutation kinds Pro requested are LIVE on sha2-host and 5 are mechanism-proven DEAD ARMS**.
- The source-code-level proof that the dead arms are **structurally inert**, not soundness bugs.
- An identification of **fields in the post-execution preflight trace that are not yet targeted by A4 mutations but are plausibly live**, as the input list for follow-up mutation studies.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Background: trace, witness, constraints, FIE](#2-background-trace-witness-constraints-fie)
3. [The preflight trace structure](#3-the-preflight-trace-structure)
4. [How a mutation reaches (or fails to reach) a constraint](#4-how-a-mutation-reaches-or-fails-to-reach-a-constraint)
5. [Dead-arm mechanism W-17 — `set_cycle` preset overwrite](#5-dead-arm-mechanism-w-17--set_cycle-preset-overwrite)
6. [Dead-arm mechanism W-18 — execution-derived witness keys](#6-dead-arm-mechanism-w-18--execution-derived-witness-keys)
7. [The smoking gun: same extern, four fields, two live + two dead](#7-the-smoking-gun-same-extern-four-fields-two-live--two-dead)
8. [Per-kind analysis (B.1 – B.8)](#8-per-kind-analysis-b1--b8)
9. [How we know they're dead, not soundness bugs — the 4-channel rejection model](#9-how-we-know-theyre-dead-not-soundness-bugs--the-4-channel-rejection-model)
10. [Implications for the Hybrid V7 campaign design](#10-implications-for-the-hybrid-v7-campaign-design)
11. [Remaining preflight-trace fields plausibly live but not yet mutated](#11-remaining-preflight-trace-fields-plausibly-live-but-not-yet-mutated)
12. [Appendix A — complete preflight-field → extern map](#appendix-a--complete-preflight-field--extern-map)
13. [Appendix B — glossary](#appendix-b--glossary)

---

## 1. Executive summary

A4 mutations modify the **post-execution preflight trace** in RAM between guest execution and witness generation. The goal is to perturb the trace in ways that should make the resulting proof invalid, and then observe which constraint family (memory permutation, cycle table, lookup tables, instruction semantics) catches the perturbation.

D2.B implemented the 8 A4 mutation kinds Pro requested in `ProG_Report_3.md`. With full attestation testing (mutation-applied → trace-changed → constraint-fires) wired up, we found:

| Result | Count | Kinds |
|--------|-------|-------|
| **LIVE** (mutation reaches witness; constraint fires) | **3** | B.1 `TXN_PREV_WORD_MOD`, B.2 `TXN_PREV_CYCLE_MOD`, B.8 `CYCLE_DIFF_COUNT_MOD` |
| **DEAD** (mutation is structurally inert at the witness layer) | **5** | B.3 `CYCLE_MODE_MOD`, B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD` |

The dead kinds are dead for **two distinct structural reasons** in the RISC-0 zkVM witgen architecture, codified in our watchlist as:

- **W-17 — `set_cycle` preset overwrite**: the trace field is *seeded* into the witness layout but immediately overwritten by an `exec_Reg` call that stores the *execution-derived* value. (Applies to `cycle.pc`, `cycle.state`, `cycle.machine_mode` on user-instruction cycles → B.3, B.6, B.7.)
- **W-18 — execution-derived witness keys**: the trace field is used as a **sanity-check input** by `extern_getMemoryTxn` but is **never returned** from the extern; the corresponding witness column is bound to the *execution argument*, not the trace field. (Applies to `txn.addr` and `txn.cycle` LSB → B.4, B.5.)

The live kinds work because they mutate fields that the extern **returns to the DSL**, where they then feed memory permutation and cycle constraints (the B.1/B.2 live path), or because they mutate fields read by a separate extern whose return value is directly consumed by a constraint (the B.8 live path via `extern_getDiffCount`).

This is **not a soundness bug** in any of the 5 dead cases. Soundness would require the verifier to accept a witness that *did* incorporate the mutated value — that is, the proof would attest to a corrupted execution. Source-level audit (sections 5–6) shows the witness never incorporates the mutated values for the dead kinds: the proof attests to the original, correct execution.

---

## 2. Background: trace, witness, constraints, FIE

The RISC-0 zkVM proves a guest program executed correctly by constructing a polynomial-IOP proof from a deterministic *witness* (column tables of field elements) that satisfies a system of polynomial constraints over those columns. Verification re-evaluates the polynomial constraints and verifies a commitment.

To produce the witness, the prover runs through two main phases:

1. **Execution** — the RISC-V emulator runs the guest program, mutating its register file, memory, and machine state cycle by cycle.
2. **Preflight** — during execution, the emulator records a **preflight trace**: a struct-of-arrays describing what happened on each cycle (which instruction, which memory transactions, etc.). This is the "post-execution trace" referenced in the user request.
3. **Witgen (witness generation)** — generated C++ code (compiled from the zirgen DSL) reads the preflight trace through *externs* and populates the polynomial-IOP witness columns. The witness columns are the values the constraints are evaluated on.

**A4 mutations operate at the boundary between Preflight and Witgen.** We modify a field in the preflight struct in RAM, then run witgen + prover. We observe whether the resulting proof verifies (mutation was a no-op) or fails verification (mutation was caught by a constraint).

**`FAULT_INJECTION_ENABLED` (FIE)** is an existing RISC-0 mechanism: certain sanity-check `throw` statements in the C++ witgen code (e.g., "expected txn.addr to match the addr the instruction asked for") get skipped when `FAULT_INJECTION_ENABLED=1` is set. This lets us run mutations that violate preflight invariants without crashing the prover, so we can see whether the polynomial constraints catch them instead. A4 sets this flag automatically when a mutation config is provided. **FIE is critical to understand:**

- FIE only suppresses **C++ `throw` statements** at preflight-vs-execution mismatch checks.
- FIE does **not** modify the witness binding logic, does **not** silence Hook 3 emission, does **not** suppress polynomial constraint evaluation, does **not** affect the verifier.
- A mutation that survives FIE without breaking a constraint is **structurally dead**, not "masked by FIE".

---

## 3. The preflight trace structure

The preflight trace is two parallel arrays of cycle records and memory-transaction records, plus a few auxiliary arrays:

```20:31:workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct RawMemoryTransaction {
    #[debug("{addr:#010x}")]
    pub addr: u32,
    pub cycle: u32,
    #[debug("{word:#010x}")]
    pub word: u32,
    pub prev_cycle: u32,
    #[debug("{word:#010x}")]
    pub prev_word: u32,
}
```

```33:59:workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct RawPreflightCycle {
    pub state: u32,
    #[debug("{pc:#010x}")]
    pub pc: u32,
    pub major: u8,
    pub minor: u8,
    pub machine_mode: u8,
    #[debug(skip)]
    pub padding: u8,
    pub user_cycle: u32,
    pub txn_idx: u32,
    pub paging_idx: u32,
    pub bigint_idx: u32,
    pub diff_count: [u32; 2],
}

#[repr(C)]
pub struct RawPreflightTrace {
    pub cycles: *const RawPreflightCycle,
    pub txns: *const RawMemoryTransaction,
    pub bigint_bytes: *const u8,
    pub txns_len: u32,
    pub bigint_bytes_len: u32,
    pub table_split_cycle: u32,
}
```

For each guest cycle `i`, `cycles[i]` describes "what instruction executed at cycle i, and where to find its memory traffic" — `txn_idx` points into the `txns[]` array, `bigint_idx` into the `bigint_bytes[]` array. The `txns[]` array is shared across cycles; each transaction has the address read/written, the value, and a back-pointer (`prev_cycle`, `prev_word`) to the previous access of the same address (for the memory permutation argument).

---

## 4. How a mutation reaches (or fails to reach) a constraint

The pipeline from preflight-field mutation to verifier rejection involves several layers, and a mutation is only "live" if it reaches the last one.

```
┌────────────────────────────────────────────────────────────────────┐
│  preflight trace (RAM)            ← A4 mutation writes here        │
│    cycles[i].field   txns[i].field    bigint_bytes[i]              │
└──────────────────┬─────────────────────────────────────────────────┘
                   │ read by C++ extern (e.g. extern_getMemoryTxn)
                   ▼
┌────────────────────────────────────────────────────────────────────┐
│  extern return values                                              │
│    only fields the extern actually returns enter the next layer    │
│    fields used as args/sanity-checks but NOT returned → DEAD HERE  │
└──────────────────┬─────────────────────────────────────────────────┘
                   │ DSL component receives the return tuple
                   ▼
┌────────────────────────────────────────────────────────────────────┐
│  witness column binding (generated steps.cpp / exec_Reg calls)     │
│    only fields wired into NondetReg / Reg calls enter the witness  │
│    fields seeded by set_cycle but overwritten by exec_Reg → DEAD   │
└──────────────────┬─────────────────────────────────────────────────┘
                   │ polynomial constraints evaluate columns
                   ▼
┌────────────────────────────────────────────────────────────────────┐
│  EQZ / memory-arg / lookup-arg constraint failures                 │
│    Path A: emits <constraint_fail> tag at witgen time              │
│    Path B: polynomial mix imbalance → verify segment panic         │
│    Path C: Hook 3 per-family residue ≠ 0 (when A4_FAMILY_RESIDUE=1) │
│    Path D: A4 dispatcher error tag                                 │
└────────────────────────────────────────────────────────────────────┘
```

There are **two structural ways** for a mutation to be filtered out before it ever reaches the polynomial constraints. Either the extern reads the trace field but does not return it, or the field is overwritten downstream of the trace seed. These are exactly W-17 and W-18.

---

## 5. Dead-arm mechanism W-17 — `set_cycle` preset overwrite

**Affects:** B.3 `CYCLE_MODE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD` (on user-instruction cycles).

### 5.1 The mechanism

For each guest cycle, the generated witgen code performs roughly:

1. **Preset (`set_cycle`):** seed witness row `i`'s **`next_pc_low/high`**, **`next_state_0`**, and **`next_machine_mode`** columns from `cycles[i].pc` / `.state` / `.machine_mode` (trace fields). These are the columns that row `i+1` will read via `back_Reg(..., distance=1)` — but only **after** row `i`'s `step_Top` finishes (see step 3).
2. **Decode and execute:** the DSL runs the instruction's logic, producing `inst_result.new_pc`, `inst_result.new_state`, `inst_result.new_mode`.
3. **Commit-next (`exec_Reg`):** write the *execution-derived* `inst_result.new_*` into row `i`'s `nextPc` / `nextState` / `nextMachineMode` layout positions — **overwriting** the preset from step 1. Row `i+1`'s `step_Top` then reads these execution-derived values via `back_Reg(1, ...)`.

So the witness columns that actually drive constraints are always the `next*` fields populated from execution at the **end** of each row's `step_Top`. The trace-seeded preset at row `i` is never read by row `i`'s own constraints (which read row `i−1` via `back_Reg`) and is overwritten before row `i+1` reads row `i`. A trace mutation to `cycles[i].pc` would create an inconsistency between the preset and execution — but **only if** an extern or constraint read that preset before the overwrite. **None does** on user-instruction cycles; `extern_getPc` does not exist.

### 5.2 Source-level evidence (top.zir + steps.cpp)

```88:97:zirgen/zirgen/circuit/rv32im/v2/dsl/top.zir
  // Compute next PC
  pc_word := inst_result.new_pc.low / 4 + inst_result.new_pc.high * 16384;
  // Log("Cycle, pc, state, mm", cycle, pc_word, inst_result.new_state, inst_result.new_mode);
  next_pc_low := Reg(inst_result.new_pc.low);
  next_pc_high := Reg(inst_result.new_pc.high);
  next_state := Reg(inst_result.new_state);
  next_machine_mode := Reg(inst_result.new_mode);

  inst_result.topState
}
```

Notice `next_pc_low`, `next_pc_high`, `next_state`, `next_machine_mode` are all bound to `inst_result.new_*` — the **execution-derived** results of the instruction's logic. Not to `cycles[i].pc`, `cycles[i].state`, `cycles[i].machine_mode`.

The generated C++ confirms — at `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp:14739–14745`:

```14739:14745:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
NondetRegStruct x47 = exec_Reg(ctx,x20.newPc.low, LAYOUT_LOOKUP(layout0, nextPcLow));
// Top(zirgen/circuit/rv32im/v2/dsl/top.zir:92)
NondetRegStruct x48 = exec_Reg(ctx,x20.newPc.high, LAYOUT_LOOKUP(layout0, nextPcHigh));
// Top(zirgen/circuit/rv32im/v2/dsl/top.zir:93)
NondetRegStruct x49 = exec_Reg(ctx,x20.newState, LAYOUT_LOOKUP(layout0, nextState_0));
// Top(zirgen/circuit/rv32im/v2/dsl/top.zir:94)
NondetRegStruct x50 = exec_Reg(ctx,x20.newMode, LAYOUT_LOOKUP(layout0, nextMachineMode));
```

`x20` is the `inst_result` aggregate. `exec_Reg(ctx, value, layout_position)` writes `value` into the witness column at `layout_position`. So at the end of row `i`'s `step_Top`, the witness columns `nextPcLow/High[i]`, `nextState_0[i]`, `nextMachineMode[i]` are all set from instruction execution (`inst_result.new_*`), overwriting the trace-derived preset that `set_cycle` wrote from `cycles[i].pc/state/machine_mode`. The next row (`i+1`) then reads these execution-derived values via `back_Reg(1, ...)`.

**Grep confirms there is no `extern_getPc` or `extern_getState`** — the only direct cycle-field reads in `ffi.cpp` are `extern_getMajorMinor` (for opcode classification), `extern_getDiffCount` (for cycle-table balancing), and `extern_nextPagingIdx` (for paging — which **does** read `machineMode`, see §5.3).

### 5.3 Why B.3 is dead on user cycles but the W-17 caveat exists for paging

`extern_nextPagingIdx` is the one extern that reads `cycles[i].machine_mode` directly:

```327:332:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
std::array<Val, 2> extern_nextPagingIdx(ExecContext& ctx) {
  uint32_t pagingIdx = ctx.preflight.cycles[ctx.cycle].pagingIdx;
  uint32_t machineMode = ctx.preflight.cycles[ctx.cycle].machineMode;
  // printf("nextPagingIdx: (0x%05x, %u)\n", pagingIdx, machineMode);
  return {pagingIdx, machineMode};
}
```

But this extern is only invoked during **paging cycles** (in `inst_p2.zir`, see DSL line `inst_p2.zir:443: pageInfo := nextPagingIdx();`). On user-instruction cycles — which is what our attestation tests and most campaign cycles target — this extern is never called, so the `machine_mode` mutation never enters the witness. **B.3 is dead on user cycles; on paging cycles it would plausibly be live**, but our current attestation harness only exercises user cycles (this is the W-17 paging caveat documented in the plan watchlist).

---

## 6. Dead-arm mechanism W-18 — execution-derived witness keys

**Affects:** B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD`.

### 6.1 The mechanism

When the witgen reaches a memory instruction, the DSL calls a `MemoryIO` component with the **execution-side** address (from the instruction's `rs1 + imm` calculation) and the **execution-side** cycle counter. Inside `MemoryIO`, an extern (`extern_getMemoryTxn`) is called to look up the preflight transaction at the current `txnIdx`. The extern compares the transaction's `addr` and `cycle` to the execution values as sanity checks, then returns the parts of the transaction that are *new information from preflight*: `prevCycle`, `prevWord` (the back-pointer to the previous access of this address), and `word` (the value at this address).

The witness columns for the memory argument's `addr` and `cycle` are bound to the **execution arguments**, not to the preflight transaction's `addr` or `cycle` field. So mutating `txn.addr` or `txn.cycle` in the preflight trace changes nothing in the witness — the preflight values are only used to satisfy a sanity check (which is bypassed by FIE), not as constraint inputs.

### 6.2 Source-level evidence (mem.zir + ffi.cpp + steps.cpp)

The DSL component:

```65:75:zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir
component MemoryIO(memCycle: Val, addr: Val) {
  ret := GetMemoryTxn(addr);
  public oldTxn := MemoryArg(-1, addr, ret.prevCycle, ret.prevData);
  public newTxn := MemoryArg(1, addr, memCycle, ret.data);
  oldTxn.count = -1;
  newTxn.count = 1;
  newTxn.cycle = memCycle;
  AliasLayout!(oldTxn.addr, newTxn.addr);
  oldTxn.addr = newTxn.addr;
  newTxn.addr = addr;
}
```

Two key lines:
- `newTxn.addr = addr;` — the witness's `newTxn.addr` is constrained to **`addr`**, which is the execution argument passed *into* `MemoryIO`, not the preflight `txn.addr`.
- `newTxn.cycle = memCycle;` — same: bound to the execution `memCycle` argument, not the preflight `txn.cycle`.

Where do `addr` and `memCycle` come from? From the surrounding `MemoryRead` / `MemoryWrite` components:

```87:101:zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir
// A normal memory read, the most constrained case
component MemoryRead(cycle: Reg, addr: Val) {
  io := MemoryIO(2*cycle, addr);
  IsRead(io);
  IsForward(io);
  GetData(io.newTxn, 0, 1)
}

// A normal memory write
component MemoryWrite(cycle: Reg, addr: Val, data: ValU32) {
  public io := MemoryIO(2*cycle + 1, addr);
  IsForward(io);
  io.newTxn.dataLow = data.low;
  io.newTxn.dataHigh = data.high;
}
```

Both `cycle` and `addr` arrive from the **caller** — the instruction-decode logic, which derives them from execution. The phase (read vs write) is encoded by the caller passing `2*cycle` (read) or `2*cycle+1` (write) — *not* by reading the preflight `txn.cycle` LSB. This is the load-bearing detail for B.5 being dead.

The C++ side: `extern_getMemoryTxn` returns exactly five values, none of them `addr`, and none of them `cycle` LSB:

```171:223:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
  // ... debug printf ...

  if (txn.cycle / 2 != ctx.cycle) {
    printf("txn.cycle: %u, ctx.cycle: %zu\n", txn.cycle, ctx.cycle);
    // <----------------------- START OF FAULT INJECTION ----------------------->
    if(std::getenv("FAULT_INJECTION_ENABLED") != NULL) {
      printf("SKIP THROW: %s @ %s:%d\n", "txn cycle mismatch", __FILE__, __LINE__);
    } else {
      throw std::runtime_error("txn cycle mismatch");
    }
    // <------------------------ END OF FAULT INJECTION ------------------------>
  }

  if (txn.addr != addr) {
    printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\n", ctx.cycle, txn.addr, addr);
    fflush(stdout);
    // <----------------------- START OF FAULT INJECTION ----------------------->
    const char* fi_env = std::getenv("FAULT_INJECTION_ENABLED");
    printf("[DEBUG] FAULT_INJECTION_ENABLED = %s\n", fi_env ? fi_env : "NULL");
    fflush(stdout);
    if(fi_env != NULL) {
      printf("SKIP THROW: %s @ %s:%d\n", "memory peek not in preflight", __FILE__, __LINE__);
      fflush(stdout);
    } else {
      throw std::runtime_error("memory peek not in preflight");
    }
    // <------------------------ END OF FAULT INJECTION ------------------------>
  }

  return {
      txn.prevCycle,
      txn.prevWord & 0xffff,
      txn.prevWord >> 16,
      txn.word & 0xffff,
      txn.word >> 16,
  };
}
```

Look at the return statement at lines 217–223: the extern returns `{prevCycle, prevWord_low, prevWord_high, word_low, word_high}`. **Not addr. Not cycle.** Those two fields are read into local variables, used for sanity checks against the execution arguments, and then discarded.

Path for B.4 mutation (mutating `txn.addr`):
1. A4 changes `txn.addr` in preflight RAM.
2. The instruction at the matching cycle calls `MemoryRead(cycle, exec_addr)` or `MemoryWrite(cycle, exec_addr, ...)`. `exec_addr` is computed from `rs1+imm`, unchanged.
3. The DSL builds `MemoryIO(2*cycle [or +1], exec_addr)` and calls `GetMemoryTxn(exec_addr)`.
4. `extern_getMemoryTxn(addrElem=exec_addr)` reads `txn.addr` (mutated) and compares to `exec_addr` (unmutated). They differ. With FIE enabled (A4 default), the `throw` is skipped. The extern continues and returns `{prevCycle, prevWord_lo/hi, word_lo/hi}` — none of which include `txn.addr`.
5. DSL constrains `newTxn.addr = exec_addr`, witness sees `exec_addr` (correct), constraints don't fire.
6. Hook 3 `memory` family balance is preserved (the memory-argument count vectors are unaffected by `txn.addr` because the witness `addr` is `exec_addr`, not mutated `txn.addr`).
7. Verifier accepts the proof — which truthfully attests to the original, unmutated execution.

Path for B.5 mutation (mutating `txn.cycle` LSB by XOR with 1):
1. A4 changes `txn.cycle` LSB. `txn.cycle/2` is unchanged.
2. `extern_getMemoryTxn` sanity check at line 186: `txn.cycle/2 != ctx.cycle`. Because we only flipped the LSB, `txn.cycle/2` is unchanged, so this sanity check **still passes** — no FIE needed.
3. Extern returns the same 5 fields as before. `txn.cycle` is not returned.
4. DSL constrains `newTxn.cycle = memCycle`, where `memCycle` is `2*exec_cycle` (read) or `2*exec_cycle+1` (write) — from execution, not from preflight LSB.
5. Witness sees the correct execution-derived cycle phase. Constraints don't fire. Verifier accepts.

### 6.3 Empirical disambiguation (FIE on/off)

To rule out the possibility that FIE was silencing constraint failures, we re-ran B.4 with `A4_NO_FAULT_INJECTION=1`. Result: witgen panicked at `ffi.cpp:199` with `txn.addr` mismatch — i.e., the throw fired. With FIE enabled (default), the throw is skipped and witgen proceeds; no constraint failure occurs at any later point.

This confirms: FIE controls whether witgen **completes** in the presence of a sanity mismatch, but does **not** modify constraint logic, Hook 3 logic, or witness binding. The dead-arm silence is structural.

---

## 7. The smoking gun: same extern, four fields, two live + two dead

The most compact proof that the dead arms are structural is the following table. Consider four mutations that all target a single memory transaction at the same cycle, all flowing through `extern_getMemoryTxn`:

| Mutation | Field | In extern's return tuple? | Witness column path | Outcome |
|----------|-------|----------------------------|----------------------|---------|
| B.1 `TXN_PREV_WORD_MOD` | `prev_word` | **Yes** (positions 1, 2: `prevWord & 0xffff`, `prevWord >> 16`) | DSL `ret.prevData` → `oldTxn.dataLow/High` → memory permutation argument | **LIVE** — Hook 3 `memory` family residue fires |
| B.2 `TXN_PREV_CYCLE_MOD` | `prev_cycle` | **Yes** (position 0) | DSL `ret.prevCycle` → `oldTxn.cycle` → memory permutation + cycle-table | **LIVE** — Hook 3 `memory` + `cycle` families fire |
| B.4 `TXN_ADDR_MOD` | `addr` | **No** — sanity-check only | Witness `addr` = execution `addrElem` argument | **DEAD** (W-18) |
| B.5 `TXN_CYCLE_PHASE_MOD` | `cycle` LSB | **No** — sanity-check only (and LSB doesn't even trigger the check) | Witness `cycle` = execution `memCycle` argument | **DEAD** (W-18) |

Same extern. Same transaction. Same step. The only differentiator is **which field of the transaction the mutation targets**. The fields the extern returns become live witness columns; the fields it does not return are structurally invisible to the witness. This is the cleanest possible mechanism proof.

---

## 8. Per-kind analysis (B.1 – B.8)

For each kind, we list: what it mutates, why it's live or dead, which extern path is relevant, and the constraint that fires (if live).

### B.1 `TXN_PREV_WORD_MOD` — **LIVE**

- **Mutates:** `txns[i].prev_word` (the previous value at this address before the current access).
- **Flow:** `extern_getMemoryTxn` returns `prevWord_low/high` → DSL `ret.prevData` → `oldTxn.dataLow/dataHigh` → `extern_memoryDelta(addr, prev_cycle, prevData, count=-1)` contributes a negative count vector with the mutated `prevData` into the memory permutation argument; the corresponding positive count vector (from the previous `newTxn`) has the unmutated value. Vectors don't cancel.
- **Constraint that fires:** Hook 3 `memory` family residue ≠ 0 / polynomial mix imbalance at verify.
- **Sub-distinction (`at_read` vs `at_write`):** When the mutated transaction is a memory **read**, the `IsRead` constraint (`oldTxn.dataLow = newTxn.dataLow; oldTxn.dataHigh = newTxn.dataHigh`) is the local trigger — visible as a `<constraint_fail>` tag at witgen time. When it's a **write**, the local `IsRead` does not apply, so the residue surfaces only through the global memory permutation — Hook 3 family residue, no local tag. Both are caught by our 4-channel rejection model.

### B.2 `TXN_PREV_CYCLE_MOD` — **LIVE**

- **Mutates:** `txns[i].prev_cycle` (the cycle index of the previous access of this address).
- **Flow:** Returned at position 0 of the extern tuple → DSL `ret.prevCycle` → `oldTxn.cycle` in `MemoryIO` → both the memory-permutation argument and the cycle-table argument (`IsForward(io) = IsCycle(newTxn.cycle - 1 - oldTxn.cycle)`).
- **Constraint that fires:** Hook 3 `memory` + `cycle` families both fire (mutation breaks both the per-address permutation and the cycle ordering).

### B.3 `CYCLE_MODE_MOD` — **DEAD (W-17)** on user cycles

- **Mutates:** `cycles[i].machine_mode`.
- **Flow on user cycles:** No extern reads `cycles[i].machine_mode` on user-instruction cycles. The witness column `nextMachineMode` is bound to `inst_result.new_mode` from execution. Dead.
- **Flow on paging cycles (caveat):** `extern_nextPagingIdx` reads `cycles[i].machineMode` and returns it. On paging cycles, this kind would plausibly be live — but our attestation harness targets user cycles only. This is the W-17 paging caveat in the watchlist.

### B.4 `TXN_ADDR_MOD` — **DEAD (W-18)**

- **Mutates:** `txns[i].addr`.
- **Flow:** Read by `extern_getMemoryTxn` only as a sanity check against the execution `addrElem`. Not returned. Witness `newTxn.addr` is bound to `addrElem` (execution). Mutated `txn.addr` triggers the FIE-suppressible throw; with FIE skipped, witgen continues with `addrElem`-based witness. Dead.

### B.5 `TXN_CYCLE_PHASE_MOD` — **DEAD (W-18)**

- **Mutates:** `txns[i].cycle` LSB (XOR with 1, flipping read/write phase encoding).
- **Flow:** Read by `extern_getMemoryTxn` only via the `txn.cycle/2 != ctx.cycle` sanity check, which the LSB-only flip **doesn't trigger** (`cycle/2` is unchanged). Not returned. Witness `newTxn.cycle` is bound to the DSL `memCycle` argument = `2*cycle` or `2*cycle+1`, from the execution-side `cycle: Reg` parameter. Dead.

### B.6 `CYCLE_PC_MOD` — **DEAD (W-17)** on user cycles

- **Mutates:** `cycles[i].pc`.
- **Flow:** No `extern_getPc` exists. Grep of `ffi.cpp` confirms `cycles[i].pc` is read only at `witgen.h:189` for debug printing. The witness column `nextPcLow/High` is bound to `inst_result.new_pc.{low,high}` from execution (`exec_Reg` calls at `steps.cpp:14739-14741`). Dead.

### B.7 `CYCLE_STATE_MOD` — **DEAD (W-17)** on user cycles

- **Mutates:** `cycles[i].state` (4-bit cycle state enum).
- **Flow:** No `extern_getState` exists. Grep confirms no `cycles[].state` reads in `ffi.cpp`. Witness `nextState_0` bound to `inst_result.new_state` from execution (`exec_Reg` at `steps.cpp:14743`). Dead.

### B.8 `CYCLE_DIFF_COUNT_MOD` — **LIVE**

- **Mutates:** `cycles[i].diff_count[0]` or `cycles[i].diff_count[1]` (cycle-table balancing counts).
- **Flow:**

```254:258:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
uint32_t extern_getDiffCount(ExecContext& ctx, Val cycle) {
  // printf("getDiffCount\n");
  uint32_t cycleU32 = cycle.asUInt32();
  return ctx.preflight.cycles[cycleU32 / 2].diffCount[cycleU32 % 2];
}
```

The extern returns the field **directly**. The DSL consumer is `CycleArg(-GetDiffCount(2*cycle), 2*cycle)` (`inst.zir:19`) — used to "cancel out cycle-table entries". Mutating `diffCount[0]` or `[1]` breaks the cycle table's balance.

- **Constraint that fires:** Hook 3 `cycle` family residue ≠ 0.

---

## 9. How we know they're dead, not soundness bugs — the 4-channel rejection model

A "soundness bug" would mean the verifier accepts a proof that attests to a **corrupted execution**. To rule this out for the dead arms, we built a 4-channel rejection model and a soundness-bug guard. The model is:

| Channel | Symptom | Source |
|---------|---------|--------|
| **C1** | `<constraint_fail>` tag in witgen output | Local EQZ failure at witgen time (Path A) |
| **C2** | `verify segment` panic from the prover/verifier | Polynomial mix imbalance at verify (Path B — catches global memory-permutation desync without local tags) |
| **C3** | `<a4_family_residue family="..." nonzero/>` tag | Hook 3 per-family residue check (only enabled when `A4_FAMILY_RESIDUE=1`; catches per-family imbalance) |
| **C4** | `<a4_error>` tag | A4 dispatcher error (e.g., malformed config) |

The **soundness-bug guard** raises `SoundnessBugSuspected` when:
- The mutation was applied (`<a4_mutation_applied/>` confirmed).
- The trace was changed (Layer 3 post-mutation dump shows actual diff).
- No rejection channel fired (none of C1/C2/C3/C4).
- The verifier accepted the proof.

This combination would indicate a soundness bug: the proof attests to a corrupted witness without any constraint catching it. **For all 5 dead kinds, the soundness guard fires** — which is why our attestation tests for those kinds use `pytest.xfail` with a documented dead-arm rationale (and assert the guard fires before xfailing). The xfail is not bypassing the guard; it's *documenting* that the guard correctly identifies a structural dead arm that the audit (sections 5–6) has separately proven is not a soundness bug.

The reason the dead arms are not soundness bugs is that the mutated values **never enter the witness**. The proof attests to the original execution, which is correct. There is no corruption — the prover just ignores the mutation because the field was never going to enter the witness in the first place.

---

## 10. Implications for the Hybrid V7 campaign design

### 10.1 Effective vs nominal mutation kind count

For D2's campaign analysis, the "effective" mutation kind count for the A4 family is **3**, not 8:

| Variant | Nominal kinds | Effective kinds | Notes |
|---------|---------------|-----------------|-------|
| `V5_control` | 8 (original V5 set) | 8 | Unchanged baseline |
| `V5_expanded` | 16 (V5 + 8 A4) | 11 (V5 + 3 live A4) | After §9c postscript removes dead kinds from `MUTATION_KINDS` |
| `V6_uniform` / `V6_cTS` / `Hybrid_cTS` | per Pro spec | (TBD; A4 family contribution is 3 live kinds) | |

This is **NFP-11** in `IV_POS_8_NOTES_FOR_PRO.md`.

### 10.2 Postscript cleanup (§9c)

After D2.B Batch 4 lands, we execute the §9c postscript to remove the 5 dead kinds from `A4Fuzzer.MUTATION_KINDS`. This relies on **registry absence**, not filter logic, so the dead kinds simply do not exist in the campaign-effective mutation universe. The Python module + Rust handler + attestation test for each dead kind are kept (for now) as documentation of the mechanism; an optional later step (§9c PS-2) may fully delete them.

### 10.3 Why we believe dead arms should not be in campaign data

If a kind is in `MUTATION_KINDS`, the V5 round-robin scheduler will eventually pick it, attempt a mutation, and "succeed" (mutation applied, trace changed, verifier accepts). The campaign would record this as an "applied, no-rejection" outcome — which a naive analyst would interpret as either (a) a soundness signal or (b) a low-yield mutation. Both interpretations are wrong because the underlying mechanism is structurally inert. Removing dead kinds from the registry avoids contaminating the campaign dataset with structurally-inert "successes".

---

## 11. Remaining preflight-trace fields plausibly live but not yet mutated

This is the headline question for follow-up work: **given the 13 trace fields enumerated in §3 and the 8 kinds in D2.B, which un-mutated fields are plausibly live targets for future A4 mutation studies?**

I evaluated each by tracing whether any extern reads it AND whether the extern returns it (or uses it as a direct constraint argument, not a sanity check). Results:

### Already covered by existing mutation kinds

Before listing new candidates, two paths through the extern surface are **already exercised** by mutation kinds that already exist in `MUTATION_KINDS`:

| Existing kind | Field(s) | Extern path | Status |
|---------------|----------|-------------|--------|
| `INSTR_TYPE_MOD` (V5) | `cycles[i].major`, `cycles[i].minor` | `extern_getMajorMinor` returns both directly to DSL → `MajorOnehot` (13-way arm dispatcher) + `MinorOnehot` (8-way within-arm selector) → instruction execution | **LIVE** (Phase III attestation); covers all major-only, minor-only, and both-field flips with a 75/25 valid/invalid strategy. **No new kind needed for major/minor.** |
| `MEM_VAL_MOD` (V5) | `txns[i].word` | `extern_getMemoryTxn` returns `word_low/high` (return positions 3, 4) → `newTxn.data` → memory permutation | **LIVE**; the `word` field's live status is the V5 baseline counterpart to B.1's `prev_word` live status. |

These cover the most "obvious" extern-return-tuple fields outside the 8 D2.B kinds. The remaining candidate space is the set of fields read by externs but **not yet targeted by any kind** (V5 or D2.B).

### Strong live candidates (new mutation studies)

| Proposed kind | Trace field | Extern | Witness path | Expected rejection channel |
|---------------|-------------|--------|--------------|---------------------------|
| **`BIGINT_BYTES_MOD`** | `bigint_bytes[k]` (top-level array) | `extern_bigIntExtern` (lines 334–341) | Returns 16 bytes directly, consumed by DSL `BigIntWitness(BigIntExtern())` (`inst_bigint.zir:95, 108`) — these become the bigint operation's operand bytes in the witness. | C2 / C3 — bigint constraint network will detect modified operands. **Only fires on cycles that execute bigint instructions** (sha2-host has these in the `BigInt0` arm). |
| **`CYCLE_PAGING_IDX_MOD`** | `cycles[i].paging_idx` | `extern_nextPagingIdx` (lines 327–332) | Returned directly to DSL `pageInfo.idx` (`inst_p2.zir:444`). | C2 / C3 on paging cycles. **Only fires on paging cycles** (page-in/page-out). |
| **`CYCLE_TXN_IDX_MOD`** | `cycles[i].txn_idx` | All txn-touching externs (`extern_getMemoryTxn`, `extern_hostReadPrepare`, `extern_hostWrite`) use it as the array index into `txns[]` | Index, not value — but mutating the index means the *wrong* transaction is read into the witness. Memory permutation will desync because the transaction recorded as occurring at cycle `i` is now bound to data from a different cycle. | C3 (`memory` family residue) almost certain; possibly C2. **Structural-index mutation**: an interesting category we haven't explored — mutates *which* txn the witness sees, not what's *in* the txn. |
| **`CYCLE_BIGINT_IDX_MOD`** | `cycles[i].bigint_idx` | `extern_bigIntExtern` uses it as an offset into `bigint_bytes[]` | Same structural-index category as above; mutating this changes which 16-byte slice the bigint witness sees. | C2 / C3 on bigint cycles. |

### Already covered with a follow-up scope

| Existing kind | Follow-up |
|---------------|-----------|
| **B.3 `CYCLE_MODE_MOD` on paging cycles** | Dead on user cycles (W-17). On paging cycles, `extern_nextPagingIdx` reads `cycles[i].machine_mode` and returns it directly → could be live. A targeted paging-cycle attestation test would resolve the W-17 paging caveat. Not Pro-requested but a clean follow-up to confirm the mechanism universally. |
| **`INSTR_TYPE_MOD` paging-cycle scoping** | Currently targets user-instruction cycles only (`major in {0..6}`). The same extern (`extern_getMajorMinor`) is invoked on all cycle classes; mutating major/minor on paging or ECALL cycles would test arm-dispatch handling on those classes. Out-of-scope for D2.B but a clean V5 extension. |

### Lower-priority / structural candidates

| Proposed kind | Field | Why lower priority |
|---------------|-------|---------------------|
| `TRACE_TXNS_LEN_MOD` | `RawPreflightTrace.txns_len` | Top-level length field. Mutating it almost certainly causes out-of-bounds reads (witgen panic, not constraint failure). Useful for crash-resistance studies but not for constraint-coverage studies. |
| `TRACE_BIGINT_BYTES_LEN_MOD` | `RawPreflightTrace.bigint_bytes_len` | Same as above. |
| `TRACE_TABLE_SPLIT_CYCLE_MOD` | `RawPreflightTrace.table_split_cycle` | Affects lookup-table boundary; deep in lookup machinery. Likely live but requires understanding lookup-arg structure first. |
| `CYCLE_USER_CYCLE_MOD` | `cycles[i].user_cycle` | A "user cycle counter" (distinct from `ctx.cycle`). Not seen as a direct extern read in `ffi.cpp` — needs further investigation before scoping. |

### Recommended scope for next mutation-studies effort

If Pro wants another batch of A4 mutation kinds beyond the original 8 (and beyond what V5 already provides), the high-confidence-live shortlist is:

1. **`BIGINT_BYTES_MOD`** — exercises the bigint instruction family, which neither V5 nor D2.B touches directly.
2. **`CYCLE_PAGING_IDX_MOD`** + **B.3 paging variant** — exercises paging cycles, which both V5 and D2.B leave largely uncovered.
3. **`CYCLE_TXN_IDX_MOD`** — structural-index mutation (a new conceptual category: mutate the *index into* a trace array, not a value *in* the array).
4. **`CYCLE_BIGINT_IDX_MOD`** — companion structural-index mutation for bigint operands.

These 4 would extend A4 coverage from "memory transaction fields" (V5 `MEM_VAL_MOD` + D2.B B.1/B.2/B.8) and "instruction classification" (V5 `INSTR_TYPE_MOD`, `INSTR_WORD_MOD_*`) to **"bigint operands"**, **"paging cycles"**, and **"structural indices"** — three constraint surfaces that no current mutation kind exercises. They are also expected to produce a higher live-rate than the D2.B 8-kind set because we've now done the mechanism analysis up front and selected for fields known to flow into the witness.

Note that all four candidates are tied to **specific cycle classes** (bigint instructions, paging cycles, txn-bearing cycles), so per-kind step-validity filters in `inspection_data.get_valid_steps_for_kind` will be non-trivial — this is part of the implementation effort beyond just writing the Python module + Rust handler.

---

## Appendix A — complete preflight-field → extern map

This is the authoritative cross-reference for **every field** of `RawPreflightCycle`, `RawMemoryTransaction`, and `RawPreflightTrace`, and **every extern** in `ffi.cpp` that reads each. Use this to scope any future mutation kind.

### `RawMemoryTransaction`

| Field | Extern reads | Returns? | Currently mutated by | Status |
|-------|--------------|---------|----------------------|--------|
| `addr` | `extern_getMemoryTxn` | No (sanity check only) | B.4 `TXN_ADDR_MOD` | **DEAD W-18** |
| `cycle` | `extern_getMemoryTxn` | No (sanity check only) | B.5 `TXN_CYCLE_PHASE_MOD` (LSB only) | **DEAD W-18** |
| `word` | `extern_getMemoryTxn`, `extern_hostReadPrepare`, `extern_hostWrite` | Yes (positions 3, 4 of getMemoryTxn) | V5 `MEM_VAL_MOD` | **LIVE** |
| `prev_cycle` | `extern_getMemoryTxn` | Yes (position 0) | B.2 `TXN_PREV_CYCLE_MOD` | **LIVE** |
| `prev_word` | `extern_getMemoryTxn` | Yes (positions 1, 2) | B.1 `TXN_PREV_WORD_MOD` | **LIVE** |

### `RawPreflightCycle`

| Field | Extern reads | Returns? | Currently mutated by | Status |
|-------|--------------|---------|----------------------|--------|
| `state` | (none directly; `set_cycle` preset only) | n/a | B.7 `CYCLE_STATE_MOD` | **DEAD W-17** |
| `pc` | (none directly; `set_cycle` preset; debug only at `witgen.h:189`) | n/a | B.6 `CYCLE_PC_MOD` | **DEAD W-17** |
| `major` | `extern_getMajorMinor` | **Yes** (position 0) | `INSTR_TYPE_MOD` (V5) | **LIVE** |
| `minor` | `extern_getMajorMinor` | **Yes** (position 1) | `INSTR_TYPE_MOD` (V5) | **LIVE** |
| `machine_mode` | `extern_nextPagingIdx` (paging only) | Yes (position 1, paging-only path) | B.3 `CYCLE_MODE_MOD` | **DEAD W-17 on user; possibly live on paging** |
| `padding` | (unused) | n/a | — | (structural) |
| `user_cycle` | (no direct extern read found in ffi.cpp) | n/a | — | Unknown — needs investigation |
| `txn_idx` | `extern_getMemoryTxn`, `extern_hostReadPrepare`, `extern_hostWrite` (as **index** into `txns[]`) | n/a (used as index, not value) | — | 🎯 **plausible LIVE target (structural index)** |
| `paging_idx` | `extern_nextPagingIdx` (paging only) | **Yes** (position 0, paging-only path) | — | 🎯 **plausible LIVE target on paging cycles** |
| `bigint_idx` | `extern_bigIntExtern` (as **offset** into `bigint_bytes[]`) | n/a (used as offset) | — | 🎯 **plausible LIVE target (structural index, bigint only)** |
| `diff_count[0]` | `extern_getDiffCount` (when `cycle % 2 == 0`) | **Yes** (return value) | B.8 `CYCLE_DIFF_COUNT_MOD` | **LIVE** |
| `diff_count[1]` | `extern_getDiffCount` (when `cycle % 2 == 1`) | **Yes** (return value) | B.8 `CYCLE_DIFF_COUNT_MOD` | **LIVE** |

### `RawPreflightTrace` (top-level)

| Field | Extern reads | Returns? | Currently mutated by | Status |
|-------|--------------|---------|----------------------|--------|
| `cycles` (pointer) | All cycle-indexing externs | n/a (pointer base) | — | (would crash on mutate) |
| `txns` (pointer) | All txn-indexing externs | n/a (pointer base) | — | (would crash on mutate) |
| `bigint_bytes` (pointer) | `extern_bigIntExtern` | Yes (returned 16 bytes at a time) | — | 🎯 **plausible LIVE target (bigint operand bytes)** |
| `txns_len` | (bounds; no direct extern read) | n/a | — | (would cause OOB) |
| `bigint_bytes_len` | (bounds; no direct extern read) | n/a | — | (would cause OOB) |
| `table_split_cycle` | (lookup-table machinery) | Unknown without further audit | — | Possibly LIVE, needs lookup-arg audit |

---

## Appendix B — glossary

- **Preflight trace**: The post-execution trace, an array of cycle records and memory transactions produced by the RISC-V emulator. The input to witgen.
- **Witness**: The polynomial-IOP column tables, populated by witgen, on which the constraints are evaluated.
- **Constraint**: A polynomial equation (typically of the form `expression == 0`) over witness columns that must hold for the proof to verify.
- **Extern**: A C++ function (in `ffi.cpp`) called from the generated witgen code (in `steps.cpp`) to obtain values that aren't computable from the witness alone (e.g., values from the preflight trace).
- **Memory argument / cycle argument**: Multi-set permutation arguments (in the RISC-0 lookup framework) used to constrain that all memory accesses to the same address occur in a consistent order, and that all cycle indices are accounted for.
- **Hook 3**: A debug/verification hook that, when `A4_FAMILY_RESIDUE=1` is set, computes per-family running sums of permutation-argument count vectors and tags any non-zero residue. Catches per-family imbalance without needing the verifier.
- **FIE (`FAULT_INJECTION_ENABLED`)**: An existing RISC-0 mechanism that suppresses C++ `throw` statements at preflight-vs-execution sanity checks. Set by A4 dispatcher when a mutation config is loaded (unless `A4_NO_FAULT_INJECTION=1`).
- **`exec_Reg(ctx, value, layout_position)`**: A generated C++ helper that writes `value` to the witness column at `layout_position`. This is the W-17 "overwrite" — when `value` is execution-derived but the layout position was previously seeded from the trace, the trace seed is irrelevant.
- **Soundness bug**: A discrepancy where the verifier accepts a proof attesting to a corrupted (i.e., not-actually-executed) computation.
- **Dead arm**: A mutation kind that is structurally inert at the witness layer — the mutation is applied to the trace, but the trace field never enters the witness. Distinct from a soundness bug.
- **W-17, W-18**: Watchlist labels for the two dead-arm mechanisms (`set_cycle` overwrite and execution-derived witness keys, respectively).

---

*End of document. For implementation details see the linked audit docs and `IV_POS_8_D2_PLAN.md`.*
