# Seam-B Option B — analysis: NOT a stronger demonstration, and NOT a value-changing bug

**Date:** 2026-06-23 · **Author:** Opus (this session) · **Verdict: do NOT build Option B.**
Triggered by Ivan's question: *"we tried value-changing mutations before (Seam A) and they failed on
the global constraint — how can Option B create an A4-findable underconstraint that changes a value
without failing global?"* Answer: **it can't. Ivan's intuition is correct.**

---

## 1. The mechanism (measured, not assumed)

`INSTR_TYPE_MOD` edits only `major/minor`; it does NOT re-execute. So the **rd-write transaction's
data is KEPT from the preflight = the original (AddI) result.** The witgen separately recomputes the
new op's ALU result. `MemoryWrite@mem.zir:99/100` (`io.newTxn.dataLow/High = data.low/high`) binds the
kept txn data to the recomputed result; when they differ (result-changing relabel) it fails — but
**locally only.**

Measured on the holed binary (hook3 = real global residue), result-changing relabels at cycle 1091:

| substitution | global residue | local fails |
|---|---|---|
| AddI→And  | **zero** | MemoryWrite@99, @100 |
| AddI→Slt  | **zero** | MemoryWrite@99, @100 |
| AddI→SltU | **zero** | MemoryWrite@99, @100 |

`global_residue_zero` ⇒ the rd-write txn value is unchanged (it still chains to the downstream reads).

## 2. What Option B (hole MemoryWrite@99/100) would actually do

Removing the txn↔ALU-result binding makes these relabels verify — **but the value written to rd is
still the original AddI result** (the txn data the permutation binds). The new op's result is computed
and then **discarded**. So Option B's extra accepters are *still result-preserving* — the register
state is identical to honest. Option B is therefore **broader** (removes a second real check —
rd-write integrity — circuit-wide) but **not stronger** (no observable value change). Strictly worse
than Option A: muddier claim, same severity.

## 3. Why a TRUE value-changing A4 demonstration is impossible (the Seam-A barrier, confirmed)

To actually write a malicious value V to rd, the rd-write **transaction data** must be V. That datum
is **memory-resident** — bound by the global memory permutation (grand product over (addr,cycle,data)).
A single-cell A4 edit of it has no matching counterpart in the chain (the downstream read still expects
the old value) ⇒ **global residue nonzero ⇒ reject.** This is exactly why Seam A (register-read value
edit) failed, and no local hole changes it: the permutation is independent of any local constraint.
Writing a coherent malicious value requires editing the write **and** every downstream use
consistently — a propagating, during-execution witness (**Arguzz**), not single-cell A4.

## 4. Consequence — this SHARPENS the complementarity thesis (positive finding)

- **A4 single-cell CAN** demonstrate underconstraints in cells **not bound by the global permutation**
  — decode selectors (`VerifyOpcode`, Seam B ✅), and intra-cycle values never entering a memory txn.
- **A4 single-cell CANNOT** demonstrate **value/memory** underconstraints (writing a wrong result) —
  the global permutation re-binds the value regardless of local holes. Those are **Arguzz territory**.

This is the cleanest possible statement of A4-vs-Arguzz complementarity, now backed by direct
measurement on a purpose-built holed binary.

## 5. Recommendation

- **Lock in Option A** (the scoped decode-only `VerifyOpcode` hole) as THE Seam-B result. It is a
  single, precise, A4-findable underconstraint with all other integrity intact.
- **Do NOT build Option B.** It does not yield a value-changing demonstration and only broadens the
  hole. If a *maximal-severity value-substitution* demo is ever wanted, it must be an **Arguzz**
  (during-execution) artifact, not an A4 post-exec one.
- Remaining real decision (reviewer flag #1): **which base commit** Seam B should live on — it is on
  clean `93bda33b`. For the bug *race* (one binary carrying BOTH the Arguzz-findable CVE bug and this
  A4-findable bug), the `VerifyOpcode` hole must be ported onto the buggy CVE commit's circuit. That
  is the next integration question, independent of A/B.
