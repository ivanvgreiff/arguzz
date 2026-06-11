# Minimal-Add Experiment — Running Findings Ledger

Single source of narrative truth. One section per increment: **what / why / results / intuition**.
Companion docs: `EXPERIMENT_PLAN_V2.md` (plan), `CONSTRAINT_CATALOG.md` (the 37 local constraints),
`GUIDANCE_FOR_COMPOSER.md` (initial forensics). Per-milestone machine reports live in `m0/`, `m1/`, …

---

## Method for 100% confidence on constraint meaning (standing)

Dual, self-checking:
- **Static:** each `<constraint_fail>` `loc` is an exact `file:line:col` into
  `zirgen/zirgen/circuit/rv32im/v2/dsl/*.zir`; read the line for the verbatim equation.
- **Dynamic:** the `value` field is the BabyBear residue `(LHS − RHS)` of that equation. Predict it
  from a known mutation delta; observed == predicted ⇒ proven. (`p = 2013265921`.)

---

## M0 — Reproduce & freeze baseline  ✅ (Opus-verified)

**What/why:** establish a deterministic, isolated foundation and auto-derive the add site, so any
later difference is attributable to a mutation, not noise or a mislocated instruction.

**Results (independently re-derived):**
- Guest add auto-derived (parsed, asserted): Arguzz **step 187**, pc **2099232** (`0x00200820`),
  `add s0, a0, a1`, preceded by `li a0,3` / `li a1,4`.
- A4 alignment: **step 185**, pc **2099236** (next-PC), **cycle_idx 15424**, major/minor **0/0**.
- Add cycle has **4 transactions**: instruction fetch (program ROM read, addr 524808·4 = the PC,
  word `0x00B50433` = `add s0,a0,a1`), a0 READ 3, a1 READ 4, s0 WRITE 7.
- Baseline: output **7**, verifier **success**, **0** constraint failures.
- Determinism: local touch set **1580** and accum **298** byte-identical across 2 runs.
- Isolation: production `risc0-host` mtime unchanged; guest comment fixed to a0/a1/s0.

**Intuition:** the "add 3+4" we reason about is a real, single, pinned event whose entire memory
footprint is 4 txns; the pipeline is reproducible to the byte, so we can trust later deltas.

---

## M1 — Enumerate the Add's constraint universe + global control  ✅ (Opus-verified)

**What/why:** get the *denominator* (which constraints the add even exercises) and the *control*
(a clean trace closes all global arguments), so "broken" is measured against a known set.

**Results (independently re-derived):**
- **37** distinct local constraint contexts at `major=0,minor=0` (0 hash collisions in this context).
- Accum-pass universe: **298** contexts (accumulation machinery — **not** global).
- **Global control:** all Hook-3 families `nonzero:false` (`memory`,`u16`,`u8`,`cycle`),
  `<a4_global_residue_zero/>`, 0 constraint failures. A correct trace closes every global argument.

**Intuition / big finding:** there is **no standalone `rs1+rs2=rd` polynomial**. Reading the ZIR
shows the ADD arithmetic is enforced **at the destination write**: `MemoryWrite@mem.zir:99/100`
asserts the recorded `rd` write equals the circuit-recomputed `AddU32(rs1,rs2)`. Memory consistency
splits into a **local** part (`IsRead`: a read returns its claimed previous value) and a **global**
part (the memory permutation argument / Hook-3 `memory`: those claimed values are real).
Full 37-constraint breakdown + intuitive mapping: see `CONSTRAINT_CATALOG.md`.

---

## M2 — A4 (witness) ground-truth on a1: 4→9   ✅ (Opus-verified, 1 provenance correction)

**What/why:** establish exactly what a witness-stage mutation of one recorded read does — which
constraints break, locally and globally — as the A4 half of the bias comparison.

**Results (independently re-derived from raw tags):**
- **Isolation:** only the a1 READ txn (15057) changes (word 4→9, prev_word stays 4); a0 READ stays 3;
  s0 WRITE txn stays **7** (the recorded ALU output is NOT recomputed by the mutation).
- **Local failures (exactly 2, both at cycle 15424):** `IsRead@mem.zir:79` and `MemoryWrite@mem.zir:99`,
  both residue `2013265916 = p−5`. No accum-phase failures.
- **Global:** Hook-3 `memory` family nonzero (e0=1835926732…); `u16/u8/cycle` zero;
  `A4_GLOBAL_RESIDUE` nonzero. (Baseline M1: all zero.) Witness corruption breaks the global memory arg.
- Both failing locs ⊆ the 37-member Add universe.

**Provenance — corrected (this is important):**
- `IsRead@79`: `oldTxn.dataLow = newTxn.dataLow` → `prev(4) = read(9)` → residue 4−9 = −5 = p−5. ✓
- `MemoryWrite@99`: `newTxn.dataLow = data.low`, where `newTxn.dataLow` = **recorded s0 write = 7** and
  `data.low` = **recomputed `AddU32(rs1=3, rs2=9) = 12`** → residue 7−12 = −5 = p−5. ✓
  - composer's report mislabeled this as `4 vs 9`. The correct pair is **7 (recorded write) vs 12
    (recomputed sum)**. Both pairs give −5, so the residue check alone could not disambiguate.

**Intuition (the real M2 lesson):** A4 changes ONE recorded value (the a1 read), but the circuit
*recomputes* everything downstream from it. So that single change is inconsistent with **two** things
in the same cycle: (a) the value previously stored in a1 (→ `IsRead`), and (b) the recorded result of
the add, because the circuit recomputes 3+9=12 while the recorded s0 write is still 7 (→ `MemoryWrite`,
which IS the `rs1+rs2=rd` check). Both residues are p−5 because the +5 read corruption propagates
linearly through the addition (12 = 7+5). Globally, the memory permutation argument no longer closes
(Hook-3 `memory` ≠ 0).

**Methodology reinforcement:** the residue check is *necessary but not sufficient* — linear
propagation can make different `(lhs,rhs)` pairs yield the same residue. Provenance must also name the
specific witness values (from the txn dump + ALU semantics), not just match the number.

**Sharpened M3 prediction (falsifiable):** Arguzz corrupts a1 *before* execution, so the executor
genuinely computes 3+9=12 and **records s0=12**. Then `MemoryWrite` should *pass* (recorded 12 ==
recomputed 12) and only `IsRead` should fail (read 9 vs prev 4). If so, the bias is: witness-stage
breaks {IsRead, MemoryWrite}; executor-stage breaks {IsRead} only. (To be tested in M3.)

---

## M3 — Arguzz (executor) ground-truth on a1   ⬜ (pending)

## M4 — Bias comparison matrix   ⬜ (pending)

## M5 — Thesis prose   ⬜ (pending, needs approval to edit thesis.md)

## M6 — Statistics campaign design   ⬜ (pending)
