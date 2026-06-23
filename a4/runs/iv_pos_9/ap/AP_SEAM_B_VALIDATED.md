# AP — Seam B VALIDATED: INSTR_TYPE_MOD is the A4 mutation that does NOT break the memory permutation

**Date:** 2026-06-23
**Author:** Opus (this session) — by **direct measurement** (frozen full-sweep host, hook3 armed).
**Companion to:** `AP_B2_010_RESOLVED.md` (why Seam A / register-read is dead).
**Answers:** "Is there any A4 mutation that doesn't break the global memory permutation?" → **Yes: INSTR_TYPE_MOD (ALU→ALU).**

---

## 0. Bottom line

A4's `INSTR_TYPE_MOD` edits the **decode field** (`cycles[].major/minor`), which selects the
instruction-type *constants*. The global memory permutation binds the **fetched instruction word**,
not the type. So an ALU→ALU type change leaves the LogUp **balanced** and is caught **only** by the
local decode-equality constraint `VerifyOpcode*`. This makes a **Seam-B planted bug feasible**
(hole the decode equality → the mutation verifies) where Seam A (register-read) was not.

This was established by **running** the atoms to completion, not inference.

---

## 1. The measurement

Frozen host, `A4_GLOBAL_RESIDUE=1 A4_FAMILY_RESIDUE=1 CONSTRAINT_CONTINUE=1`, run to completion:

| class | tested | outcome | type-changes |
|---|---|---|---|
| `(1,0,0)` | **40 / 40** | exit 101, **`a4_global_residue_ZERO`** | all ALU→ALU: Add, Sub, Xor, Or, And, Slt(U), shifts, Mul*, Div*, Rem*, Lui, Auipc |
| `(1,0,1)` | **8 / 8** | exit 101, **`a4_global_residue_NONZERO`** | all control/memory: Beq, Bne, Blt(U), JalR, Lw, LbU |

Contrast with the dead Seam A (`PRE_EXEC_REG_MOD next_read`, `AP_B2_010_RESOLVED.md`): those either
**SIGSEGV** (pointer reads) or break the LogUp (`NONZERO` in 200/200 measured). INSTR_TYPE_MOD
ALU→ALU is the **only** mutation class observed to reach the verify hook with a **balanced** global
argument.

**Population:** INSTR_TYPE_MOD = **161/250 global-clean** in E5; every other sampled mutation type
(`PRE_EXEC_REG/MEM_MOD`, `MEM_VAL_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `COMP_OUT_MOD`, `TXN_*`)
is **0** global-clean — they edit memory-bound `(addr, cycle, data)` cells.

---

## 2. Why ALU→ALU doesn't break the permutation (mechanism)

- The memory grand product binds the **fetched instruction word** (an instruction-fetch read txn),
  plus register/memory data txns — all on **recorded values**.
- `major/minor` are **not** in the permutation. They select which `Op*` component runs, i.e. which
  *decode constants* (`opcode/func3/func7`) the row must match.
- When A4 edits `major/minor` post-preflight, witgen **recomputes the cycle's intra-row witness**
  (ALU result, rd-write, memory chain) **consistently for the new type**. So the ALU result
  constraint and the global permutation are **satisfied**.
- The **only** thing that cannot be reconciled is the decode equality: `VerifyOpcode*`
  (`inst.zir:90/95/101`) asserts `decoded.{opcode,func3,func7} == {type constants}`. `decoded`
  comes from the unchanged fetched word (still encoding the original instruction); the constants are
  the new type's. The equality fails → local reject. Nothing global re-catches.

```
// inst.zir — the sole guardian for an ALU→ALU type change
component VerifyOpcodeF3F7(decoded, opcode, func3, func7) {
  decoded.opcode = opcode;  decoded.func3 = func3;  decoded.func7 = func7;
}
```

**Why branch/jump/load changes DO break global:** changing to a branch/jump makes witgen recompute
a different **next PC** → the PC/cycle chaining (global) breaks; changing to a load/store makes the
circuit expect a different **memory txn** → the permutation breaks. Only ALU↔ALU keeps both intact.

---

## 3. The hole scope (for the planted bug)

Local constraints that fire on a `(1,0,0)` atom (E5 atom inspection):

| local-constraint set | # of 160 | example |
|---|---|---|
| `VerifyOpcode*` + `MemoryWrite@mem.zir:99` | 147 | AddI→Add |
| `VerifyOpcode*` only | ~13 | AddI→Sub, AddI→Or, Mul→MulHSU, AddI→MulH, SllI→SrlI |

- The **decode equality** `VerifyOpcode/VerifyOpcodeF3/VerifyOpcodeF3F7` is the primary guardian.
- `MemoryWrite@99` (the rd-write local well-formedness) also fires for most; the **~13 "pure-decode"
  type-changes** fire `VerifyOpcode*` only — these are the **cleanest single-family-hole targets**.
- `VerifyOpcode*` is a pure intra-row **equality** → holing it (fold-neutralization, same technique
  as the IsRead work) is **honest-preserving** (on honest proofs the equality already holds).

---

## 4. Seam B planted bug — proposed (feasible, validated premise)

1. **Hole `VerifyOpcode*`** (the decode-equality fold) in the committed circuit, surgically, same
   fold-neutralization machinery as `ap_isread_patch.py`. (For broadest reach also hole
   `MemoryWrite@99`; for a minimal clean bug, target a pure-decode type-change.)
2. **Honest-gate:** patched binary must prove+verify the guest (expected to pass — equality already
   holds honestly).
3. **A4-findability:** an `INSTR_TYPE_MOD` ALU→ALU mutation on the holed binary should **verify**
   (the local decode reject is removed; the global permutation never caught it). This is the test
   Seam A failed and Seam B should pass.
4. **The bug is real:** removing the opcode-decode check lets a prover claim a cycle executed a
   different instruction than the fetched word encodes — **instruction substitution**, a genuine
   soundness underconstraint, reachable by a single post-execution A4 edit.

**Why this is the right target and Seam A was not:**

| | Seam A (IsRead / register read) | Seam B (VerifyOpcode / instr type) |
|---|---|---|
| edited cell in permutation? | **yes** (`newTxn.data`) | **no** (`major/minor` ≠ word) |
| global re-catches? | yes (or SIGSEGV) | **no** (residue ZERO, measured 40/40) |
| local guardian | IsRead (fold) | VerifyOpcode* (fold) |
| honest-preserving hole? | yes | yes |
| verdict | **dead** | **feasible** |

---

## 5. Reproduction

```
cd thesis_side_experiments/full_sweep
# global-clean (ALU->ALU): residue ZERO
CFG=$(pwd)/artifacts/e5/configs/a4__INSTR_TYPE_MOD__default__s4883.json   # AddI->Sub, pure-decode
env CONSTRAINT_CONTINUE=1 A4_GLOBAL_RESIDUE=1 A4_FAMILY_RESIDUE=1 A4_MUTATION_CONFIG=$CFG \
    ./frozen_host/thesis-full-sweep-host.e0frozen | grep a4_global_residue
# -> <a4_global_residue_zero/>     (LogUp balanced; only VerifyOpcode* rejects locally)

# global-breaking (ALU->branch): residue NONZERO
CFG=$(pwd)/artifacts/e5/configs/a4__INSTR_TYPE_MOD__default__s4762.json   # AddI->Beq
env CONSTRAINT_CONTINUE=1 A4_GLOBAL_RESIDUE=1 A4_FAMILY_RESIDUE=1 A4_MUTATION_CONFIG=$CFG \
    ./frozen_host/thesis-full-sweep-host.e0frozen | grep a4_global_residue
# -> <a4_global_residue_nonzero>…
```

---

## 6. Open items before committing to a Seam-B build

- Confirm whether the chosen type-change still fires only `VerifyOpcode*` on the **committed**
  circuit (E5 is the full-sweep guest; map the target to the committed-circuit corpus).
- Decide minimal hole: pure-decode target (`VerifyOpcode*` only) vs. also holing `MemoryWrite@99`.
- The build itself is the same surgical fold-neutralization path already debugged for IsRead — the
  toolchain risk is low; the *scientific* premise (global stays balanced) is now **validated**.
