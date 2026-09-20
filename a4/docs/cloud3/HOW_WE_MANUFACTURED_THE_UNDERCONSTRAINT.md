# How we manufactured the A4-findable underconstraint (intuitive walkthrough)

**Date:** 2026-06-23 · **Scope:** Seam-B (`VerifyOpcode` / `INSTR_TYPE_MOD`).
**Companions:** mechanics in `a4/scripts/ap_verifyopcode_patch.py`; proof in `a4/runs/iv_pos_9/ap/seamb/{AP_SEAMB_RESULT.md,AP_SEAMB_REVIEW.md}`.

This document explains, in plain language, *what we actually did* to create a bug that A4 can find — and why it works.

---

## 1. The goal, in one sentence

We wanted to deliberately weaken the RISC-Zero circuit by **exactly one check**, so that a **single post-execution trace edit** by A4 produces a proof that the verifier still accepts — a proof of something that never really happened. That is an *underconstraint*: the circuit no longer pins down a fact it should.

## 2. What A4 is allowed to do (the rules of the game)

Think of a zk proof as a giant spreadsheet (the "trace") whose every cell is tied down by algebraic rules (the "constraints"). The prover fills the spreadsheet honestly; the verifier checks all the rules hold.

**A4 changes one cell after execution and asks: does the proof still verify?** If yes, the circuit failed to bind that cell — a soundness bug. A4 can't rewrite the program, re-run it, or fix up the rest of the spreadsheet; it gets **one edit**.

So "manufacturing an A4-findable bug" means: find/remove a rule such that flipping a single cell is no longer caught.

## 3. The first idea that failed (and why it taught us the trick)

Our first attempt (**Seam A**) edited a **register's value** as it was read, and removed the local "a read doesn't change memory" check (`IsRead`). It failed — twice, instructively:

1. We first mis-removed the check on the prover side (an off-by-one in which line we edited), so the prover and verifier disagreed and even *honest* proofs broke. Lesson: the patch must be **prover==verifier consistent**.
2. Even after fixing that, the edit was still rejected — by something with **no local error at all**. The reason: registers live in memory, and RISC-Zero has a **global "memory bookkeeping" argument** (a grand-product / LogUp over every memory transaction) that independently guarantees *a value read equals the value last written there*. Editing one read value unbalances that global ledger. Removing the local check did nothing, because a **second, global guardian** was watching the same value.

**The key realization:** *a single edit can only slip through if the cell you touch is guarded by exactly one rule.* Values that live in memory are guarded twice (locally **and** by the global memory ledger), so they're a dead end for a one-cell edit.

## 4. The idea that works: attack the *label*, not a *value*

Every instruction cycle records **what kind of instruction it is** — its "type" (`major/minor`, e.g. `AddI` = add-immediate). The circuit has a check called **`VerifyOpcode`** whose only job is the *decode binding*: "the type you claim matches the opcode bits of the instruction word you fetched."

Crucially, the instruction **type is not a memory value.** It's a decode *selector*. The global memory ledger doesn't care about it at all — it only tracks data words at addresses. So the type field is guarded by **exactly one** rule: `VerifyOpcode`. That makes it the perfect target.

So the plan: **remove `VerifyOpcode` and nothing else.** Then A4 can relabel a cycle's instruction type (one edit), and as long as the computation still adds up, the proof verifies.

## 5. What we actually changed (the surgery)

A subtlety: the same circuit is expressed in **three generated files** that must all agree. We neutralized `VerifyOpcode` in all three, identically:

| file | role | what we did |
|---|---|---|
| `steps.cpp` | **witgen** (fills the spreadsheet) | every `EQZ(expr, "…VerifyOpcode…")` → `EQZ(Val(0), …)` — i.e. "assert 0==0", always true. So A4's relabel doesn't crash trace generation. (111 sites) |
| `poly_ext.rs` | **verifier** constraint poly | every `AndEqz(acc, val)` tagged VerifyOpcode → `AndEqz(acc, 0)` — fold **zero** instead of the decode-mismatch term. (74 folds) |
| `rust_poly_fp_*.cpp` | **prover** constraint poly | every VerifyOpcode fold `dst = acc + term·mix` → `dst = acc` — drop the term. (74 folds) |

Three properties made this clean and trustworthy:

- **Fold-neutralization, not wire-deletion.** We zeroed only the *contribution* of the decode check; we left every shared sub-expression ("diff wire") intact, so no other constraint that happens to reuse those wires was disturbed.
- **Prover == verifier (74 == 74).** The prover and verifier compute the *same* polynomial; if we removed different things they'd disagree and even honest proofs would fail (exactly the Seam-A trap). The patch enforces this and refuses to build on mismatch.
- **Index-preserving.** The `git diff` is a perfect **259/259** one-for-one line swap across 6 files — no rows added or removed, so the circuit stays bit-for-bit comparable to the clean one. The *only* difference between clean and holed is the planted hole.

**Why honest proofs still verify:** for a truthful trace the decode equality already holds, so "fold the difference" and "fold zero" are the same number. Removing a check that was always satisfied changes nothing for honest runs — it only matters once someone lies.

## 6. Why it now works — the A4 edit slips through

A4 takes an honest `AddI rd, rs, 0` cycle and flips its type label to, say, `Sub` (one cell: `minor` 7→1). On the **clean** binary this is caught instantly by `VerifyOpcode` ("you said Sub but the word says AddI"). On the **holed** binary:

- `VerifyOpcode` is gone → the type/word mismatch is no longer checked.
- The instruction is decoded the same way (RISC-Zero reads the same source registers regardless), so **no memory transaction changes** → the global memory ledger stays perfectly balanced (we measured this: `a4_global_residue_zero`). No second guardian fires.
- For these "mv-like" cycles the result is unchanged (`rs+0 = rs-0 = rs^0 = rs|0`), so the result-write check is satisfied too.

⇒ the verifier **accepts** a proof claiming the CPU ran `Sub` when it really ran `AddI`. That is the manufactured underconstraint, and A4 found it with a single edit. Verified by real prove+verify: **12 substitutions accept on the holed binary and are rejected by the clean control at `VerifyOpcodeF3F7`.**

## 7. What we deliberately did NOT break (scope)

We removed *only* the decode binding. Result integrity is untouched: if A4 relabels to something that **changes** the answer (`And/Slt/SltU`, where `rs & 0 = 0 ≠ rs`), the still-present rd-write check (`MemoryWrite`) catches it. Those rejections are a *feature* — they prove the hole is a scalpel, not a sledgehammer: "the type is no longer bound to the word," nothing more.

## 8. The one-paragraph version

RISC-Zero guards each fact with a specific rule, and some facts (memory values) are guarded twice — once locally and once by a global memory ledger — so a single trace edit to them is always caught. The instruction *type*, by contrast, is a pure decode label guarded by exactly **one** rule, `VerifyOpcode`. We surgically deleted just that rule — identically in the witness generator, the prover polynomial, and the verifier polynomial, in a way that leaves honest proofs valid and the circuit otherwise bit-identical — so that A4 can relabel a single instruction and have the lie verify. That is the manufactured, A4-findable underconstraint.
