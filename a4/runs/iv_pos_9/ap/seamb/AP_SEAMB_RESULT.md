# AP / Seam-B — RESULT: planted VerifyOpcode underconstraint built & certified A4-findable

**Date:** 2026-06-23 · **Author:** Opus (this session) · **Verdict: PASS (certain).**
Authoritative data: `ap_seamb_verify.json`. Build spec: `a4/docs/cloud3/IV_POS_9_AP_SEAM_B_BUILD_SPEC.md`.
Premise: `a4/runs/iv_pos_9/ap/AP_SEAM_B_VALIDATED.md`.

---

## 0. Bottom line

We built a buggy RISC-Zero rv32im host binary with a single, precise, honest-preserving planted
underconstraint — the `VerifyOpcode*` decode-equality removed — and demonstrated **with certainty**
that A4's `INSTR_TYPE_MOD` mutation finds it: **12 instruction-type substitutions verify on the holed
binary and are rejected by the clean control (all at `VerifyOpcodeF3F7`)**; honest proofs verify on
both; the global memory permutation stays balanced throughout.

---

## 1. What was built (isolated, committed-circuit, surgical)

- Base: clean worktree `workspace/risc0-seamb` @ **93bda33b** (A4-instrumented, no Seam-A residue).
- Build workspace `workspace/output-seamb` (minimal ALU guest; `cargo build --release -p risc0-host`).
- **control** `a4/builds/ap_seamb/control/risc0-host` (planted_bug=none, sha `4e0f841c…`).
- **holed** `a4/builds/ap_seamb/bench-verifyopcode/risc0-host` (planted_bug=verifyopcode, sha `53ee6663…`).
- Patch `a4/scripts/ap_verifyopcode_patch.py`: fold-neutralization of `VerifyOpcode*` across the 3
  generated artifacts — **witgen 111 EQZ → Val(0)**, **verifier 74 AndEqz → 0**, **prover 74 folds → acc**.
  prover==verifier=74 (consistency). git diff touches only the 6 generated files; balanced (index-preserving).

## 2. Gates (all pass)

| gate | result |
|---|---|
| control honest verify | ✅ Prover+Verifier success |
| **holed honest verify** (prover==verifier consistency — the gate Seam-A failed) | ✅ Verifier success (71.94 ms) |
| premise: ALU→ALU edit keeps permutation balanced | ✅ `a4_global_residue_zero` on control AND holed |
| **mutated-V0** | ✅ 12 substitutions: holed ACCEPT, control REJECT@VerifyOpcodeF3F7 |

## 3. The certainty demonstration

Bracket = 56 `INSTR_TYPE_MOD` configs (`AddI→{Add,Sub,Xor,Or,And,Slt,SltU}` × 8 source cycles),
each run as a real prove+verify (no CONSTRAINT_CONTINUE) on both binaries:

- **Holed: 12 ACCEPT** (`AddI→{Add,Or,Sub,Xor}` at cycles 1091/1829/2418), **44 reject** (at `MemoryWrite@99`).
- **Control: all 12 accepters REJECT at `VerifyOpcodeF3F7`** (and the 44 reject at VerifyOpcode too).
- The ONLY difference between holed-accept and control-reject is the planted hole ⇒ the underconstraint
  is real and is exactly what A4's INSTR_TYPE_MOD exercises.

### Why exactly these 12 (mechanism, and why the result is precisely scoped)
The accepting cycles are `mv`-like (`addi rd, rs, 0`): for those operands `Add/Or/Sub/Xor` all yield
the same result as `AddI`, so the rd-result-write stays consistent and the **sole** discriminating
guardian was the decode check `VerifyOpcode` — now removed ⇒ verify. `And/Slt/SltU` change the result
and are correctly caught by the **un-holed `MemoryWrite@99`** (rd-write integrity). So the 44 rejects
are a feature, not a failure: they prove the hole is **scoped to the decode binding** — we did NOT
weaken result integrity. This is a clean, narrow, defensible underconstraint:
*"the circuit no longer binds a cycle's instruction-type field to the fetched word."*

## 4. Contrast with Seam A (why this one works)
- Seam A (register-read IsRead): edited a memory-resident value → global permutation re-caught it (or
  the read crashed witgen). Dead.
- Seam B (instruction-type / VerifyOpcode): edits a non-memory decode selector → permutation stays
  balanced → removing the local decode check is sufficient for the substitutions whose execution stays
  consistent. **Works, certified.**

## 5. Optional stronger variant (NOT done — decision for Ivan)
The current hole is scoped to decode; result-changing relabelings (And/Slt/SltU) are still caught by
`MemoryWrite@99`. To make **any** ALU→ALU substitution verify (a broader "decode + result-write
unchecked" bug), additionally neutralize the rd-write binding. That is a larger, less surgical hole
and needs a ~16 min rebuild. The current result already certifies an introduced, A4-findable
underconstraint; the broader variant is only for a stronger severity claim.

## 6. Reproduce
```
python3 a4/scripts/ap_verifyopcode_patch.py status        # applied; 0/111, 0/74, 0/74; prover==verifier
python3 a4/runs/iv_pos_9/ap/seamb/gen_and_sanity.py        # honest-gate + configs + premise
python3 a4/runs/iv_pos_9/ap/seamb/mutated_v0.py            # mutated-V0 + bracket -> ap_seamb_verify.json
```
