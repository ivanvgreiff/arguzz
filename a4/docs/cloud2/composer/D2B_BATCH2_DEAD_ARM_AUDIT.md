# B.3 Dead-Arm Audit — Composer Independent Verification

**Date:** 2026-06-18  
**Subject:** Systematic review of Opus Batch 2 review + `CYCLE_MODE_MOD` witness path  
**Verdict:** Opus's core mechanism is **verified correct**. B.3 is **not a no-op** and **not a soundness bug (W-16)** — it is a **W-3-class dead arm** on sha2-host user-instruction cycles for the Top `machine_mode` chain.

---

## 1. Terminology (precision matters)

| Term | Meaning for B.3 |
|------|-----------------|
| **Trace mutation** | `trace.cycles[i].machine_mode` changed in RAM before witgen — **TRUE** (Layer 3 dump proves) |
| **Witness mutation** | Committed `nextMachineMode` column used by constraints — **FALSE** on user cycles (overwritten) |
| **No-op** | Nothing changed — **WRONG** (trace changed) |
| **Dead arm** | Mutation applies to trace struct but proof constraints unchanged — **CORRECT** for tested cycles |
| **Soundness bug (W-16)** | Verifier accepts corrupted witness — **FALSE** (witness uncorrupted) |

Composer's earlier label "NO_EFFECT" was imprecise. **Dead arm** is the correct classification.

---

## 2. Opus claims — verified line-by-line

### Claim A: Mutation writes trace struct

```746:747:workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
let old_mode = cycle.machine_mode;
cycle.machine_mode = mode;
```

**VERIFIED ✅** — independent of Opus.

### Claim B: `set_cycle` presets witness from trace

```1063:1074:workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
fn set_cycle(&mut self, row: usize, cycle: &RawPreflightCycle) {
    // ...
    self.set(row, NEXT_MACHINE_MODE, cycle.machine_mode as u32);
}
```

Called from `build_injector` at line 977 for every row **before** `generate_witness`.

Flow (`hal_generate_witness` lines 867–874):

1. `hal.scatter(...)` injects preset values into data buffer  
2. `circuit_hal.generate_witness(...)` runs `step_Top` per cycle  

**VERIFIED ✅** — preset happens first.

### Claim C: `step_Top` overwrites `nextMachineMode` with execution output

```14739:14745:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
NondetRegStruct x47 = exec_Reg(ctx,x20.newPc.low, LAYOUT_LOOKUP(layout0, nextPcLow));
NondetRegStruct x48 = exec_Reg(ctx,x20.newPc.high, LAYOUT_LOOKUP(layout0, nextPcHigh));
NondetRegStruct x49 = exec_Reg(ctx,x20.newState, LAYOUT_LOOKUP(layout0, nextState_0));
NondetRegStruct x50 = exec_Reg(ctx,x20.newMode, LAYOUT_LOOKUP(layout0, nextMachineMode));
```

`exec_Reg` → `exec_NondetReg`:

```25:29:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
NondetRegStruct exec_NondetReg(ExecContext& ctx,Val arg0, BoundLayout<NondetRegLayout> layout1)   {
STORE(LAYOUT_LOOKUP(layout1, _super), arg0);
NondetRegStruct x2 = NondetRegStruct{
  ._super = LOAD(LAYOUT_LOOKUP(layout1, _super), 0)};
```

**VERIFIED ✅** — `STORE` overwrites column; EQZ is `arg0 - arg0 == 0` (trivial pass).

### Claim D: Constraint chain reads overwritten columns, not trace field

`top.zir:60-62`:

```
machine_mode := (1 - is_first_cycle) * next_machine_mode@1 + is_first_cycle;
```

In `exec_Top` at row N (lines 14635, 14645):

- `x13 = back_Reg(ctx, 1, nextMachineMode)` → reads column at row **N−1**  
- `machine_mode` input to `InstInput` = `(x4 * x13._super) + x3._super`  
- Row N−1's column was written by `exec_Reg(x20.newMode[N−1], ...)` at end of row N−1  

Row N's preset from trace is **never read** during row N's `exec_Top`; it is only **overwritten** at line 14745.

**VERIFIED ✅**

### Claim E: Verifier acceptance is correct

Witness columns encode **execution-derived** `inst_result.newMode`, not mutated trace. Proof attests original execution. Verifier `status:success` is expected.

**VERIFIED ✅** — not W-16.

---

## 3. Why trace retains `machine_mode` at all

The field is **not vestigial globally**:

| Consumer | Reads trace directly? | Affected by B.3 on user cycles? |
|----------|----------------------|----------------------------------|
| `set_cycle` preset | yes → overwritten | **No** (Top chain) |
| `extern_nextPagingIdx` (`ffi.cpp:328-331`) | yes | **Possibly** on Poseidon paging cycles |
| Executor preflight recording | yes | N/A (not proof) |

Paging path (`steps.cpp:7360-7364`):

```cpp
auto [x6, x7] = INVOKE_EXTERN(ctx,nextPagingIdx);
NondetRegStruct x9 = exec_NondetReg(ctx,x7, LAYOUT_LOOKUP(layout3, curMode));
```

On **Poseidon paging cycles**, mutated `trace.cycles[].machineMode` can enter witness via `curMode` **without** going through Top's overwrite chain.

**Composer pushback on Opus:** "Structural dead arm for **all** cycles" is **too strong**. Correct statement:

> Dead arm for **Top `machine_mode` chain** on **user-instruction cycles** (major 0–6). **May be live** on paging cycles where `nextPagingIdx` reads trace directly — but our Python module restricts targets to `machine_mode ∈ {0,1}` and sha2-host attestation hit step 1 (major=0, minor=7), which does not invoke paging.

---

## 4. Comparison: why B.1/B.2 are live

| Mutation target | Witness path | Overwrite? |
|-----------------|-------------|------------|
| `trace.txns[].prev_word` | `extern_getMemoryTxn` → `MemoryIO` → Hook 3 | **No** |
| `trace.txns[].prev_cycle` | same + `MemoryArg.cycle` in delta | **No** |
| `trace.cycles[].machine_mode` | `set_cycle` → `step_Top` `exec_Reg` | **Yes** |

**VERIFIED ✅** — Opus distinction between **extern-read txn fields** vs **set_cycle cycle fields** is the right taxonomy.

---

## 5. Batch 3 predictions (Opus Part 3) — Composer assessment

| Kind | Field | Opus prediction | Composer confidence |
|------|-------|-----------------|---------------------|
| B.6 `CYCLE_PC_MOD` | `cycle.pc` | Dead (same exec_Reg overwrite) | **High** — same lines 14739-14740 |
| B.7 `CYCLE_STATE_MOD` | `cycle.state` | Dead (same overwrite) | **High** — line 14743 |
| B.8 `CYCLE_DIFF_COUNT_MOD` | `diff_count` | Live (`extern_getDiffCount` reads trace) | **High** — `ffi.cpp:254-257` |
| B.4/B.5 txn fields | addr / cycle phase | Live (extern memory path) | **High** |

No `ffi.cpp` extern reads `cycle.pc` or `cycle.state` directly — only preset columns.

---

## 6. Opus review — what Opus got right vs wrong

### Right (implement fixes)

1. **Not a soundness bug** — verifier correctly accepts uncorrupted witness  
2. **`set_cycle` → `exec_Reg` overwrite mechanism** — fully verified  
3. **Composer bypassed soundness guard** — fixed: guard called, `SoundnessBugSuspected` asserted, then `pytest.xfail(strict=False)`  
4. **B.6/B.7 likely dead** — same overwrite class  
5. **Layer 3 ≠ Layer 3b** — trace dump ≠ witness persistence (plan §6c note warranted)  
6. **Spec §3.3 "0/1 privilege bit"** — incomplete; preflight uses 0–5 (`preflight.rs:164-528`)

### Overstated / needs qualification

1. **"Trace field never enters constraint system"** — false for paging via `nextPagingIdx`  
2. **"Structural dead arm for all cycles"** — true for Top chain on user cycles; not proven for paging/ECALL majors  
3. **"100% dead arm"** without cycle-type qualification — too absolute

### Composer errors (acknowledged)

1. Called it "NO_EFFECT" without tracing overwrite chain  
2. Used `pytest.xfail` **instead of** calling guard (plan §9b violation) — **fixed**  
3. Did not flag `diff_signature.py` helper additions as kickoff deviation in first report

---

## 7. Attestation methodology (post-fix)

B.3 attestation now:

1. Runs Layers 2–4 (evidence + post-mut dump + signature)  
2. **Always** calls `check_soundness_bug_guard`  
3. **Asserts** `SoundnessBugSuspected` fired (`guard_fired == True`)  
4. **`pytest.xfail(strict=False)`** documents W-3 dead arm  

If step (3) ever fails on a future guest/build, the test **fails loudly** (B.3 may have become live).

---

## 8. Testing environment note (Ivan)

Attestation uses **C1 / C1-accum / C3 / C2** only. `<a4_check_poly_scan>` may appear in host stdout (prover debug instrumentation remains in source) but is **not parsed or asserted** in D2.B attestation tests.

---

## 9. Certainty statement

For **sha2-host, step 1, `CYCLE_MODE_MOD` flip on major=0 minor=7 cycle**:

| Statement | Certainty |
|-----------|-------------|
| Trace `machine_mode` mutated | **100%** (Layer 3 dump + Rust handler) |
| Preset written to witness column | **100%** (`set_cycle` + scatter) |
| Column overwritten before constraints use it on next row | **100%** (source chain above) |
| Verifier accept = soundness bug | **0%** (witness reflects execution) |
| Dead arm for bandit on this cycle class | **100%** (all 30 sampled user steps accept) |
| Dead arm on **all** cycle types globally | **Not proven** (paging extern path exists) |

### Batch 3 predictions (locked in plan §6d / spec §5.4 / W-17)

| Kind | Prediction | Reconciliation trigger |
|------|------------|------------------------|
| B.6 `CYCLE_PC_MOD` | **PREDICTED DEAD** (same set_cycle overwrite) | Live rejection → re-read audit |
| B.7 `CYCLE_STATE_MOD` | **PREDICTED DEAD** (same set_cycle overwrite) | Live rejection → re-read audit |
| B.4, B.5, B.8 | **PREDICTED LIVE** (extern-read paths) | Dead arm + guard fire → re-read audit |

---

*End of dead-arm audit. Planning docs: [`IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) §6d + W-17; [`IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) §5.4.*
