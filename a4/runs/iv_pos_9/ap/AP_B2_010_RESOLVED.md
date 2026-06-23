# AP.B2 — RESOLVED: what `(0,1,0)` register-read mutations actually are

**Date:** 2026-06-23
**Author:** Opus (this session) — by **direct measurement**, not inference.
**Supersedes:** the mechanism claim in `AP_B2_GLOBAL_LOGUP_FINDING.md §2.1` (which was wrong),
and resolves the open question in `AP_B2_STATE_AND_ROOTCAUSE.md §5`.

---

## 0. Bottom line

The premise of Seam A — *"`(0,1,0)` register-read mutations break only the local IsRead guardian,
so holing IsRead makes them verify"* — is **false**, and not for the reason the prior finding gave.

A genuine `(0,1,0)` `PRE_EXEC_REG_MOD next_read` mutation does **not** keep the global permutation
balanced. **It crashes the witness generator (SIGSEGV) before the global memory argument is ever
evaluated.** The `(0,1,0)` label is a **measurement artifact**: the classifier defaults `global=0`
when no residue record is emitted, and a crashed process emits no residue record — even though
hook3 (`A4_GLOBAL_RESIDUE`) was armed.

This was established by **running every one of the 21 genuine E5 `(0,1,0)` atoms to completion**,
not by reasoning about the circuit.

---

## 1. The decisive experiment

The 21 layer-`(0,1,0)` `next_read` atoms in
`thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250/` were run to completion against the
frozen full-sweep host with hook3 armed (`A4_GLOBAL_RESIDUE=1 A4_FAMILY_RESIDUE=1
CONSTRAINT_CONTINUE=1`), no early cutoff:

| result | count |
|---|---|
| SIGSEGV (exit 139), **zero** residue records | **21 / 21** |
| reached the residue hook with a `zero` residue | **0 / 21** |
| reached the residue hook with a `nonzero` residue | 0 / 21 |

Every `(0,1,0)` register is a **pointer**: `a0/a2/a3/a7` (used as load/store base addresses),
`sp` (stack pointer), `ra` (return address). Every diverged `word` is a wild 32-bit value in
`0xC0000000–0xFF000000`. The log ends at the IsRead `constraint_fail`(s), then the process
segfaults — the diverged pointer makes witgen dereference a wild address.

Example (s4328): `sw a1, 8(a3)`, register **a3** (the store base), `2229564 → 3544224475`
(`0xD33B0FDB`). Witgen logs `IsRead@mem.zir:79/80`, then **SIGSEGV** computing the store to
`0xD33B0FDB+8`. No accum phase, no residue.

Reproduce:
```
cd thesis_side_experiments/full_sweep
CFG=$(pwd)/artifacts/e5/configs/a4__PRE_EXEC_REG_MOD__next_read__s4328.json
env CONSTRAINT_CONTINUE=1 A4_GLOBAL_RESIDUE=1 A4_FAMILY_RESIDUE=1 A4_MUTATION_CONFIG=$CFG \
    ./frozen_host/thesis-full-sweep-host.e0frozen
# -> exit 139 (SIGSEGV); log ends at two IsRead constraint_fail; 0 residue records.
```

---

## 2. Why `(0,1,0)` is a measurement artifact

The layer classifier (`thesis_side_experiments/bias_campaign/classify.py:88-91`) derives the
global layer from hook3:
```python
global_res     = parse_global_residue(combined_output)
global_nonzero = bool(global_res and global_res.get("nonzero"))
if not global_nonzero and family:
    global_nonzero = any(f.get("nonzero") for f in family)
```
`global_nonzero` is `False` whenever **no residue record exists** — which is exactly what a
crashed (or cut-off) run produces. So `global=0` means **"no global record was emitted"**, NOT
**"the global argument was evaluated and balanced."**

The screening's crash detector (`is_prover_crash`, keyed on a Rust panic `loc`) does **not** catch
a raw SIGSEGV (no panic message), so these 21 crashes were mislabeled `outcome_class:
CONSTRAINT_REJECT, crashed: false`. That mislabeling is the original source of the illusion that
they were "clean rejects with only an IsRead failure."

---

## 3. Why only "a few" `PRE_EXEC_REG_MOD` are `(0,1,0)` — the structural difference

Cross-referencing **all 221** applied `next_read` atoms (layer signature vs. actual emitted
global residue):

| layer signature | actual global residue | count | what happened |
|---|---|---|---|
| (1,1,1) | **NONZERO** | 119 | survived witgen → accum computed → LogUp broken |
| (0,1,1) | **NONZERO** | 81 | survived witgen → accum computed → LogUp broken |
| **(0,1,0)** | **none (SIGSEGV)** | **21** | diverged **pointer** → witgen crash before accum |

So the difference is **not** that the `(0,1,0)` reads keep the permutation balanced. It is:

- **`(0,1,0)`** = the diverged read feeds an **address/pointer** (load/store base, `sp`, `ra`)
  → witgen dereferences a wild address → **SIGSEGV before the global argument runs**.
- **`(0,1,1)` / `(1,1,1)`** = the diverged read is a **data** value that survives witgen
  → the accum phase runs → the global residue is computed and is **NONZERO** (LogUp broken).

**Every** read mutation whose residue was actually measured (200/200) breaks the global LogUp.
None balanced.

---

## 4. Why the global LogUp always breaks for a surviving read edit (the circuit fact)

`mem.zir:65-80`:
```
component MemoryIO(memCycle, addr) {
  oldTxn := MemoryArg(-1, addr, prevCycle, ret.prevData);  // removes (addr, prevCyc, prevData)
  newTxn := MemoryArg(+1, addr, memCycle, ret.data);       // ADDS (addr, cyc, ret.data)
}
// MemoryRead:  io.oldTxn.dataLow = io.newTxn.dataLow   <- this is IsRead (oldData == newData)
```
The value the ALU consumes (`ret.data`) **is the same witness cell** the global grand product binds
(`newTxn.data`). IsRead only ties `oldData == newData`; it does **not** remove `newTxn.data` from
the permutation. A single-cell edit of the read word therefore perturbs the `+1` grand-product
entry, which no `-1` entry cancels → nonzero residue → `verify_integrity` rejects. Holing IsRead
cannot fix this; the global argument is an independent guardian.

This is why `AP_B2_GLOBAL_LOGUP_FINDING.md`'s **conclusion** (IsRead necessary-not-sufficient) is
correct, even though its **mechanism** (§2.1: "accum computed from the un-edited trace") is wrong —
`stepAccum` recomputes accum from the mutated trace (`ffi.cpp:722` before the residue read at
`:742`); the residue is genuinely nonzero because the diverged value has no matching counterpart.

---

## 5. Verdict on Seam A

Seam A (hole `IsRead@ReadReg` so `(0,1,0)` register reads verify) is **dead**, for two independent
reasons:

1. **The `(0,1,0)` class crashes witgen** (wild pointer) — there is no proof to verify, with or
   without IsRead.
2. **Surviving read edits break the global memory LogUp** — `newTxn.data` is in the grand product;
   holing IsRead leaves the global argument rejecting.

No single-cell post-execution edit of a register/memory-resident value can produce a verifying
witness, because RISC-Zero binds every such value in the global memory grand product
(defense-in-depth). This is the same reason A4 cannot reproduce CVE-2025-52484 by a single cell:
the CVE is a *same-cycle double-read* (`rs1==rs2`) structural degeneracy that only a
**propagating, during-execution** witness (Arguzz) can realize.

---

## 6. Forward options (unchanged target: an A4-findable planted bug that verifies)

1. **Seam B (decode/ALU intermediate).** Re-target the planted hole to a value that is
   **locally constrained only** and **never enters the memory permutation** — an intra-cycle
   decode or ALU intermediate. Needs a feasibility pass to find a site whose sole guardian is local
   and whose value is not memory-resident. (Documented fallback; ~64% decode-binding hit-rate.)
2. **Reframe as the complementarity result.** "A4's single post-exec edit cannot create a
   verifiable underconstraint for a memory-bound value, because the global memory argument is a
   redundant guardian; such bugs require a propagating (Arguzz) witness." This is the thesis's
   core complementarity claim, now backed by direct measurement.

**Recommendation:** stop spending on Seam A. Either pursue Seam B with a fresh feasibility pass, or
adopt option 2 as a deliberate negative finding. Decision belongs to the user/OCP.
