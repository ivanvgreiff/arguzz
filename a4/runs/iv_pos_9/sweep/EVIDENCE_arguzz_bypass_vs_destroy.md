# Evidence: Arguzz "bypass vs destroy" of global constraints — worked examples

**Question (from MASTER_REPORT §2, expanded):** is it true that an Arguzz (during-execution) fault
injection *either* (a) **bypasses** the global constraints entirely (0 global failures) *or* (b)
**destroys** them with a flood of failures? And mechanistically, *how* does each happen?

**Short answer: yes — the distribution is strongly bimodal, and the split is by what the fault corrupts.**
- Corrupting a **value output** (a loaded byte, a store output, a comparison result) → the corruption is
  caught (if at all) by *one local per-row constraint* and **does not enter the global arguments → 0 global**.
- Corrupting a **register/memory STATE** value → that value propagates through many downstream cycles and
  memory cells → the **global memory-permutation + cycle-lookup arguments register many inconsistencies → flood**.

This document is **self-contained**: it shows, for one example of each, the exact injection, the trace
before and after (legible instruction logs), and the precise constraints broken — all from the run DB and
from replaying the injection on the actual binary.

---

## 0. The bimodal distribution (the fact being explained)

g1 guest, V6_uniform (Arguzz), N=5000, **4769 applied** mutations, bucketed by **# global-constraint failures**:

| # global failures | mutations | share |
|---|---|---|
| **0 (bypass)** | 1527 | **32%** |
| 1–3 | 282 | 6% |
| 4–9 | 447 | 9% |
| **10+ (destroy)** | 2513 | **53%** |

85% of applied Arguzz mutations land in the two extremes. Per-kind (MASTER_REPORT §C) confirms the *cause*:
value-output kinds (`LOAD_VAL_MOD`, `STORE_OUT_MOD`, `COMP_OUT_MOD`) sit in the bypass bucket
(E[#global]=0–0.05 probability of firing); state kinds (`PRE/POST_EXEC_MEM_MOD`, `PRE/POST_EXEC_REG_MOD`)
sit in the destroy bucket (E[#global]≈12–13).

Both examples below were replayed on the real binary with:
`risc0-host --trace --inject --inject-kind <K> --inject-step <S> --seed <SEED> --ctrl 2863311530 --gseed 305419896 --rounds 55`
and **both run to the full 12,660 steps with no control-flow divergence** — i.e. the fault corrupts witness
*values*, not the instruction path; the **prover** is what catches (or misses) the corruption via constraints.

---

## 1. BYPASS example — corrupting a loaded value slips past the global layer

**Mutation:** id=36 · kind=`LOAD_VAL_MOD` · step=6081 · seed=1234000036 · opcode_class=memory_load · outcome=applied · verifier_accepted=0.

### The injection, in the trace (legible instruction log)
```
step    pc          instr   assembly
6078    0x204970    Beq     beq  a1, zero, 356
6079    0x204994    AndI    andi a1, a2, 2
6080    0x204998    Bne     bne  a1, zero, 16
6081    0x2115944   Lb      lb   a1, 0(a4)          <== INJECTION POINT (load byte into a1)
        <fault>     LOAD_VAL_MOD   info: "out:2 => out:3"   (the loaded byte value 2 is forced to 3)
6082    0x2115948   Lb      lb   a5, 1(a4)
6083    0x2115952   Sb      sb   a1, 0(a3)          (the corrupted a1 is even stored back to memory)
6084    0x2115956   AddI    addi a4, a4, 2
```
The fault changes a single loaded byte from **2 → 3**. Execution continues identically (same 12,660 steps).

### What broke (from the run DB)
```
LOCAL failures (1):
  MemoryWrite@mem.zir:99   step=6060  pc=0x20496c  major=5 minor=0  value=1
GLOBAL failures: 0
```
**Only one local, per-row memory constraint fires** (the read-consistency check at the write that this load
is paired with), and **zero global constraints**. The corrupted value is confined to its own row's check; it
never produces a net imbalance that the global memory-permutation / cycle-lookup *arguments* detect. The
proof is ultimately rejected — but by the **local** layer; the **global** layer was blind to it. **That is the bypass.**

---

## 2. DESTROY example — corrupting a register's state floods the global layer

**Mutation:** id=4902 · kind=`POST_EXEC_REG_MOD` · step=385 · seed=1234004902 · opcode_class=arithmetic · outcome=applied · verifier_accepted=0. (This is the **maximum-global-failure** applied mutation in the run.)

### The injection, in the trace (legible instruction log)
```
step    pc          instr   assembly
382     0x205... 　 AddI    addi a0, a6, 0
383     0x205... 　 JalR    jalr zero, ra, 0
384     0x2109928   SllI    slli s1, s1, 2
385     0x2109932   Lui     lui  a1, 0x00080000     <== INJECTION POINT
        <fault>     POST_EXEC_REG_MOD   info: "t5 = 1"   (register t5's state is forced to 1)
386     0x2109936   Beq     beq  a0, s1, 32
387     0x2109968   AddI    addi a0, a1, 7
388     0x2109972   Sw      sw   a0, 0(s0)
389     0x2109976   Lw      lw   ra, 12(sp)
```
The fault forces register **t5 := 1** — a piece of *machine state*, not a one-shot output. It is consumed by
later cycles (not in this immediate window), and the wrong state flows through subsequent memory/cycle relations.
Execution again runs to the full 12,660 steps (no control divergence) — the damage is in the witness values.

### What broke (from the run DB)
```
LOCAL failures (5):
  IsRead@mem.zir:79             step=380  pc=0x203210  maj=1 min=5  value=2013265920
  VerifyOpcodeF3@inst.zir:96    step=380  pc=0x203210  maj=1 min=5  value=2013265822
  MemoryWrite@mem.zir:99        step=380  pc=0x203210  maj=1 min=5  value=99
  MemoryWrite@mem.zir:100       step=380  pc=0x203210  maj=1 min=5  value=661
  MemoryWrite@mem.zir:99        step=387  pc=0x200874  maj=2 min=4  value=32

GLOBAL failures (17), spanning two argument families and many addresses/cycles:
  family=memory  addresses: 1073725472, 1073725481, 1073725482, 1073725502, 1073725536,
                            527484, 527485, 527486, 527487, 527488
  family=cycle   addresses: 0, 2, 5, 6, 167, 168, 2013265920
```
The corrupted **state** value participates in the global **memory-permutation argument** (10 distinct memory
addresses now inconsistent) and the global **cycle-lookup argument** (7 distinct cycle contexts) → **17 distinct
global-constraint failures**. **That is the destroy** — one injected state-fault propagates into a wide,
distinct global footprint.

---

## 3. Why the two outcomes — mechanism (grounded in §0 per-kind data + the two replays)

| | BYPASS (value output) | DESTROY (machine state) |
|---|---|---|
| example kind | `LOAD_VAL_MOD` (also STORE_OUT, COMP_OUT) | `POST_EXEC_REG_MOD` (also PRE/POST_EXEC_MEM/REG) |
| what's corrupted | a single produced value (loaded byte 2→3) | a register/memory state cell (t5:=1) |
| where it's checked | one **local per-row** constraint | **global** permutation/lookup **arguments** that aggregate across cycles |
| forward reach | none — confined to its own row | propagates into every cycle/cell that consumes the state |
| global failures | **0** | **17** |
| per-kind E[#global] (§C) | 0–0.05 (rarely any) | 12–13 |

The during-execution timing matters only insofar as it lets Arguzz corrupt **state** mid-stream (the
destroy mode), which a post-execution A4 mutation of a finalized cell cannot do as effectively. When Arguzz
instead corrupts a terminal **value** (load/store/compare output), it behaves like the local-only A4 case →
bypass. So Arguzz spans *both* extremes; A4 lives almost entirely in the local/bypass regime (see MASTER_REPORT Q2/Q3).

---

## 4. Reproduce
```bash
B=a4/builds/sweep/28e53771_clean__g1_ecall_control/risc0-host
GUEST="--ctrl 2863311530 --gseed 305419896 --rounds 55"
# baseline trace (no fault):
$B --trace $GUEST
# BYPASS replay:
$B --trace --inject --inject-kind LOAD_VAL_MOD --inject-step 6081 --seed 1234000036 $GUEST | grep -E '<trace>|<fault>'
# DESTROY replay:
$B --trace --inject --inject-kind POST_EXEC_REG_MOD --inject-step 385 --seed 1234004902 $GUEST | grep -E '<trace>|<fault>'
```
Broken-constraint tables are from `failures` / `global_failures` in
`a4/runs/iv_pos_9/sweep/data/g1_ecall_control_V6_uniform.db` for `mutation_id` 36 and 4902.

*Generated 2026-06-24. Summarized in MASTER_REPORT.md §1 (headline) + §2 Q2/Q3.*
