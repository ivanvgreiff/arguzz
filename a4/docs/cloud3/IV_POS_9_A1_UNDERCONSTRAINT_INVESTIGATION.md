# IV.POS.9 A1 — `rs1==rs2` underconstraint: deep investigation of the injection mechanism

**Date:** 2026-06-25 · **Author:** Opus (OCP) · **Trigger:** Ivan asked whether my live findings corroborate
the cloud3 docs, who was right/wrong, why I was wrong, and the *truth* of how Arguzz triggers the bug —
with instructions to read the Arguzz mutation/injection logic deeply and gather certainty / run tests.

**Bug:** CVE-2025-52484 / risc0 #3181 / zirgen #238 — same-source-register (`rs1==rs2`) double-read.
Vulnerable commit `98387806` (built + run live this session in the MODE-2 Arguzz fuzzer's docker image).

---

## 0. Bottom line (read first)
1. **The *constraint* mechanism in the docs is CORRECT and I corroborate it.** GPT_Bug_Opinion / BUG_MECHANISM_VERIFIED are right; ProG_Report_5 §3.1 is wrong (guest must ENCODE `rs1==rs2`; the exploit is read-**divergence**, not `rs2:=rs1`).
2. **I was WRONG to conclude "Arguzz/MODE-2 cannot trigger it."** It is established that Arguzz *found* this bug (hence the patch). My claim over-generalized from a single injection kind. §3 explains exactly why.
3. **What the docs never pinned — and what my investigation now shows empirically — is the *exact* injection mechanism.** The MODE-2 fuzzer's fault hooks are all **instruction-semantic** (operand/output/pc/mem, pre/post), and **none of them diverges a *single* read of a same-register pair on a compute op.** That is a real, verified finding (§4) — and it is the crux that must be reconciled with "Arguzz found it" (§6).
4. **A4-can't / Arguzz-can prediction stands** (and Ivan's "A4 is blocked by a constraint, try it anyway; Arguzz can" is the right posture) — but the *precise* primitive Arguzz uses is **not yet identified in this frozen source**; resolving it is the remaining work (§8). I have NOT reached 100% certainty on the exact triggering primitive; I have done the thorough investigation and isolated precisely where the uncertainty lives.

---

## 1. Method
- Built + ran the **real MODE-2 Arguzz fuzzer** at `98387806` in its canonical docker image (the original tool that found the bug).
- Read the applied **instrumented executor** `risc0/circuit/rv32im/src/execute/rv32im.rs` (the frozen `rv32im_rs_9838780.py`) — every `is_injection` hook, the compute/load/store paths, `load_register`.
- Read the txn/`prev_cycle` model in `prove/witgen/preflight.rs` (the #3181 fix site).
- Ran live injection tests on a **curated `rs1==rs2` guest** (`remu s0, a0, a0` at step 290 — `objdump`-confirmed same-register, G3).

---

## 2. The documented disagreement — corroborated, with the resolution
| aspect | ProG §3.1 | GPT_Bug_Opinion / BUG_MECHANISM_VERIFIED | my finding |
|---|---|---|---|
| guest shape | `rs1 != rs2`, fault sets `rs2:=rs1` | **ENCODE `rs1==rs2`** (`remu x3,x5,x5`) | **GPT right** — verified `98387806` lacks `load_rs2`, two reads `load_register(rs1)`@326 / `(rs2)`@327 |
| exploit | `rs2:=rs1` (a no-op on equal regs) | the two same-cycle reads **DIVERGE** + result **recomputed** (coherent) | **GPT right** — a lone result-change is caught (see §5); coherence is mandatory |
| who triggers | — | Arguzz (propagating) yes; A4 (single-cell) likely no | **corroborated as the prediction** (but see §6 on the *exact* Arguzz primitive) |

**Verdict (matches BUG_MECHANISM_VERIFIED):** *GPT_Bug_Opinion is CORRECT; ProG_Report_5 §3.1 is WRONG.*
The constraint understanding is settled and I corroborate it from source + live runs.

**What the docs do NOT settle (confirmed by a parallel doc survey):** none of GPT_Bug_Opinion, ProG, or
BUG_MECHANISM_VERIFIED spells out the *low-level fuzzer procedure* — i.e. **by what concrete fault does a
fuzzer produce two divergent same-cycle reads of one register?** BUG_MECHANISM_VERIFIED line 76 explicitly
leaves it open ("depends on the exact witness layout … which the A1 deterministic repro settles empirically").

---

## 3. Where I was WRONG, and why
**My erroneous claim (earlier this session):** "MODE-2/Arguzz cannot produce the coherent divergence; the
spec's `PRE_EXEC_REG_MOD` framing is the wrong primitive and no MODE-2 hook does it."

**Why it was wrong / premature:**
- It contradicts the **established fact** that Arguzz found this bug (→ the patch). When a conclusion
  collides with a known fact, the conclusion is the thing to doubt — I should have treated "Arguzz found it"
  as ground truth and asked *how*, not concluded *whether*.
- I generalized from **one** kind (`PRE_EXEC_REG_MOD`) after reading **one** hook. `PRE_EXEC_REG_MOD` does
  `store_register(rand_reg, rand_val)` *before* execution (rv32im.rs:626-638) — it overwrites a whole
  register, so both reads of `a0` would see the same value (no divergence), and it picked a *random* register
  (`t0`, unrelated to the op). That correctly rules out `PRE_EXEC_REG_MOD` — but **does not** rule out Arguzz.
- I had not yet mapped the **full** hook set, the **witness layout**, or the **memory-argument** structure.

**The honest correction:** the spec's headline "PRE_EXEC_REG_MOD-style during-exec operand mutation" is
*loose*, and `PRE_EXEC_REG_MOD` specifically is not the primitive — but Arguzz can and did trigger it, by a
mechanism this investigation narrows down but does not yet fully pin (§6).

---

## 4. The MODE-2 injection model (read in full) — the key structural finding
All fault hooks are **instruction-semantic**, in `rv32im.rs`:
| hook | line | what it changes |
|---|---|---|
| PRE_EXEC_PC/MEM/REG_MOD | 602/615/628 | before exec: set pc / store a random mem word / **store a whole random register** |
| INSTR_WORD_MOD | 654 | the fetched instruction word |
| BR_NEG_COND | 744 | negate a branch condition |
| **COMP_OUT_MOD** | 862 | the **result** of a compute op (then `store_register(rd,out)` @874) |
| LOAD_VAL_MOD | 931 | the value returned by a **load** (`lw` etc.) |
| STORE_OUT_MOD | 994 | the value written by a **store** (`sw` etc.) |
| POST_EXEC_PC/MEM/REG_MOD | 679/692/705 | after exec |

The compute op reads `rs1 = load_register(decoded.rs1)` (736) then `rs2 = load_register(decoded.rs2)` (737)
**back-to-back, with no fault hook between them**, and `load_register` (impl `executor.rs:578` → pager/
preflight) has no per-call fault hook. **Therefore no MODE-2 hook can make the two same-register reads of a
compute op record different values.** The only compute-op fault is `COMP_OUT_MOD` (the result) — and a result
change alone is caught (§5). The store path is symmetric (`STORE_OUT_MOD` changes the stored value, not a
read). **This is the central structural fact: MODE-2's executor-fault model has no "diverge one read"
primitive for a compute/store op.**

---

## 5. Live tests — the constraint structure (empirical)
On the curated guest (`remu s0,a0,a0` @ step 290, `in0=7` ⇒ honest output `0`, prover+verifier success):
- **`PRE_EXEC_REG_MOD` @290, seed 42:** `<fault> t0 = 1068323197` — diverged **t0** (random, *not* the op's
  `a0`), prover **rejected** (exit 101). Confirms PRE_EXEC_REG_MOD is whole-register + random ⇒ not the primitive.
- **`COMP_OUT_MOD` @290, `CONSTRAINT_CONTINUE=1`:** changing the **result** fails at
  **`<constraint_fail> MemoryWrite(mem.zir:99)`** (the rd-write integrity constraint, part of the memory
  argument). ⇒ the result is *bound*; a lone result change is caught **locally at the write**. This is the
  same `MemoryWrite@99/100` family that is INTACT in the Seam-B planted bug.

**What this proves:** the coherent-witness requirement is real — a lone result change trips `MemoryWrite@99`;
a lone read change (had a hook existed) would trip the *present* read/compute binding; only a **coherent pair**
(diverged read + recomputed result) can satisfy all present constraints while violating the one missing
same-cycle second-read binding. Corroborates BUG_MECHANISM_VERIFIED exactly.

---

## 6. The truth, and the precise remaining uncertainty
**Settled (high confidence):**
- The bug, the guest shape, the coherent-witness requirement, the missing constraint (the same-cycle second
  same-register read is not bound to the register's memory value pre-`98387806`-fix) — all as the docs say.
- A lone single-cell change (read **or** result) is caught by a *present* constraint (empirically: result→
  `MemoryWrite@99`). So **pure single-cell A4 is expected to be blocked** — consistent with Ivan's "A4 is
  blocked by a constraint." (Whether the blocker is best named the local result-binding or the global memory
  permutation, the operational fact is: A4's lone edit leaves an inconsistency a present constraint catches.
  We should still *try* A4 in the race — a negative is the thesis result, and the witness-layout caveat
  (BUG_MECHANISM_VERIFIED:76) means it isn't 100% excluded.)

**The open question (where I stopped short of certainty):** *by what concrete fault does Arguzz produce the
coherent divergence?* This frozen MODE-2 source has **no hook that diverges a single same-register read** on a
compute/store op (§4). Reconciliation candidates, none yet confirmed:
1. **The original Arguzz tool used a richer/different fault model** than this frozen `rv32im_rs_9838780.py`
   (e.g. a read-port or witness-level mutation), and this re-implementation is narrower.
2. **A different instruction/shape** (e.g. `rd==rs1==rs2` maximizing same-cycle same-address I/O, or the store
   path) admits the coherent fault via an existing kind in a way the compute `remu` does not.
3. **The metamorphic generator + repeated tries** land a configuration where an enabled kind happens to
   produce it (Ivan's "try a specific kind over and over") — but I have not identified that kind/path, and the
   structural analysis (§4) suggests no single executor kind suffices on the compute op alone.

I did **not** manufacture a passing trigger, and I will not claim one I cannot show.

---

## 7. Implications for the bug race (A1 → A2 → CVE race)
- **A4 / V5_control:** expected blocked (single-cell edit caught by a present constraint). **Run it anyway**
  in the race — the negative is the thesis "limits of post-exec single-cell mutation" result, and the
  witness-layout caveat keeps it honest (not asserted).
- **Arguzz / V6_*:** expected to find it (it originally did). **But the A1 deliverable must identify the exact
  kind+op+mechanism** so the race is measuring a real, reproducible trigger — not assume it. This is precisely
  A1's job (the deterministic repro / G4-G5), and it is the part still open.
- This does **not** change the Seam-B (A4-side) race already running on POS — that bug + harness are validated.

## 8. Path to 100% certainty (recommended next steps)
1. **Identify Arguzz's real primitive** — the highest-value step. Options, in order:
   a. Read the **original Arguzz paper/tool** fault model for register reads (is it a read-port / witness
      mutation, not an operand mutation?) and/or any shipped finding/test for `98387806` in the fuzzer repo.
   b. **Circuit/witgen layout**: determine in `steps.cpp` / `mem.zir` whether the two same-register reads are
      separate witness cells and exactly which binding is missing pre-fix (settles A4-can/can't definitively).
   c. **Guided empirical search**: run the fuzzer with a guest *seeded with `rs1==rs2` ops*, long enough, and
      capture the actual finding's `(kind, step, params)` — the ground-truth trigger.
2. **Then** build A1.B3's deterministic repro to that confirmed primitive (MODE-1 coordinated edit if it is a
   read+result pair; or drive the during-exec hook if that is what Arguzz uses).
3. Given this is genuinely subtle and collided with an established fact, a **second-LLM review** of the
   primitive (once identified) is warranted before committing POS time to the CVE race.

**Status: thorough investigation complete; constraint mechanism certain; exact Arguzz injection primitive
NOT yet pinned — explicitly flagged, with the resolution path above.**

---
---

# ENTRY 2 (2026-06-25) — Review of ChatGPT's `INSTR_WORD_MOD` assessment + a decisive test

Ivan relayed a ChatGPT review and asked me to evaluate it systematically, document it + my findings as a
second entry (Entry 1 above is preserved), and reach certainty / run tests.

## 2.1 ChatGPT's review (faithful summary)
- **Catalog answer:** the Arguzz catalog kind that found the public RISC Zero bug is **`INSTR_WORD_MOD`** —
  instruction-word modification that changes a 3-register instruction's source field so `rs2` aliases `rs1`
  (`remu rd,rs1,rs2`, rs1≠rs2 → `remu rd,rs1,rs1`), citing the Arguzz paper Appendix B + "found through
  instruction modification, not post-hoc output mutation," and the advisory + zirgen #238 (`loadRS2`/
  `ReadSourceRegs`: when `rs1==rs2`, read once).
- **Underlying bug** still = same-source-register / same-cycle double-read.
- **Two repro styles are different:** (A) Arguzz-style: normal `remu xA,xB` + `INSTR_WORD_MOD`→`remu xA,xA`;
  (B) mechanistic same-register guest `remu xA,xA` where the mutation can't be `rs2:=rs1` (no-op) and needs a
  coordinated witness mutation (read#1=a, read#2=b, a≠b, result recomputed).
- **Don't chase** `PRE_EXEC_REG_MOD`/`COMP_OUT_MOD`/`LOAD_VAL_MOD` for the same-register guest.
- **Verdict:** `INSTR_WORD_MOD` answers "which catalog kind"; the exact low-level witness edit for the
  deterministic same-register guest needs source/log evidence (his checklist: the `INSTR_WORD_MOD` impl, a
  real finding log, the pre/post-fix test, and the read-txn rows / which constraint is absent pre-fix).

## 2.2 Where I AGREE (and ChatGPT improves on Entry 1)
1. **Constraint mechanism** — fully (matches Entry 1 + the advisory + zirgen #238). Settled.
2. **The two-repro-styles distinction is the clarifying insight** — it cleanly separates "the guest creates the
   `rs1==rs2` condition" from "how the divergence is injected," and resolves the apparent GPT-vs-style confusion.
3. **"Don't chase `PRE_EXEC_REG_MOD`/`COMP_OUT_MOD`"** — exactly Entry 1's empirical finding.
4. **The deterministic same-register witness edit needs source/log evidence** — exactly Entry 1's open question;
   his 4-item checklist is good and I adopt it as the §8 resolution plan.

## 2.3 Where I DISAGREE — and the TEST that settles it
**Claim under test:** that `INSTR_WORD_MOD` (aliasing `rs2→rs1`) is the live trigger **on `98387806`**.

**Result — REFUTED on this commit (empirical).** I forced `INSTR_WORD_MOD` at the target op (CONSTRAINT_CONTINUE=1):
```
seed 5 : <constraint_fail> VerifyOpcodeF3F7 (inst.zir:74) at OpREM (inst_div.zir:150)
seed 99: <constraint_fail> VerifyOpcodeF3   (inst.zir:67) at OpANDI  + MemoryWrite(mem.zir:99)
```
**`INSTR_WORD_MOD` is caught by `VerifyOpcode`.** Mechanism (verified in source): the instruction fetch
`word = ctx.load_memory(pc)` (rv32im.rs:643) records the **original committed** word as the fetch txn *before*
`word = new_word` (rv32im.rs:662); the executed (mutated) instruction's decode then disagrees with the fetched
word → the **VerifyOpcode\* decode/operand-field binding fires** (`inst.zir:67/74`). The specific `rs2→rs1`
aliasing is caught the same way — VerifyOpcode binds the cycle's decoded `rs2` field to the fetched word's
`rs2` field, so aliasing the executed `rs2` while the fetched word still encodes `xB` mismatches.

**The reconciliation (important):** `VerifyOpcode*` is *exactly* the constraint our **Seam-B** planted bug
**removes**. So:
| bug | missing constraint | mutation family that finds it | on `98387806` |
|---|---|---|---|
| **Seam-B decode bug** (our planted A4 target, A3 race) | `VerifyOpcode*` removed | **instruction modification** (`INSTR_TYPE_MOD`/`INSTR_WORD_MOD`) | n/a (Seam-B is a separate binary) |
| **`rs1==rs2` read bug** (the CVE, A1) | `load_rs2`/same-cycle second-read binding | **read-value divergence** (coordinated read+result) | `VerifyOpcode` is **INTACT** → instruction mods are CAUGHT |

So ChatGPT's `INSTR_WORD_MOD` is the correct catalog label for the **instruction-modification family** (which,
in our project, is the *decode/VerifyOpcode* surface — the Seam-B bug), **but it does not trigger the
`rs1==rs2` read bug on `98387806`**: VerifyOpcode catches it first. The catalog label conflates two distinct
bugs. The paper's "found through instruction modification" likely refers to the family/another circuit
revision; on *our* pinned vulnerable commit, instruction-word mutation is decisively gated by VerifyOpcode.

## 2.4 The refined truth
- The `rs1==rs2` bug on `98387806` requires a **guest that encodes `rs1==rs2`** (ChatGPT's style B) **plus a
  read-value divergence** (read#1=a, read#2=b, result=op(a,b)) — a **coordinated** change, since any lone
  single-cell change is caught by a present constraint (Entry 1: result→`MemoryWrite@99`; this entry:
  instruction word→`VerifyOpcode`).
- The MODE-2 frozen source exposes **no per-read / per-operand divergence hook** (Entry 1 §4), so I still have
  **not** identified the exact primitive in *this* tool. Whether the original Arguzz used a read-port/operand
  fault (during-exec, produces the coherent pair) or a witness-level coordinated edit is the remaining
  question — to be settled by ChatGPT's checklist (the real finding log + the read-txn rows + pre/post-fix).
- **A4 prediction unchanged:** a single-cell post-exec edit is caught (VerifyOpcode for word, MemoryWrite for
  result, and — per Ivan — the global memory permutation for a read-value cell). Try it in the race; expect a
  negative; the witness-layout caveat keeps it honest.

## 2.5 Verdict on the review
ChatGPT is **right on the framing** (constraint, two repro styles, don't-chase-the-wrong-primitives, need
source/log evidence) and its checklist is the right plan. It is **wrong on the operational claim that
`INSTR_WORD_MOD` triggers the `rs1==rs2` bug on `98387806`** — empirically, VerifyOpcode (intact on this
commit) catches instruction-word mutations; that family finds the *decode* bug (our Seam-B surface), not the
*read* bug. Net: the rs1==rs2 trigger is a **read-value divergence on an `rs1==rs2`-encoding guest**, and the
exact primitive still needs the finding-log / circuit-layout evidence (§8 + ChatGPT's checklist).

## 2.6 RESOLUTION (2026-06-25) — decisive test: ChatGPT is RIGHT, I was wrong
I ran ChatGPT's exact decisive test. Patched `random_word` (env-gated `A1_ALIAS_RS2`) to do a **field-only
`rs2:=rs1` alias** (copy rs1 bits 19:15 → rs2 bits 24:20; opcode/func3/func7/rd/rs1 **preserved**). Guest:
`remu rd, x, y` with distinct source regs. On **`98387806`**:
```
honest (in0=7,in1=5): remu s0, a1, a0  -> output 2, verifies
INJECT rs2:=rs1 @ that op (INSTR_WORD_MOD, A1_ALIAS_RS2=1):
   Prover: success | output: "0" (≠ 2) | Verifier: SUCCESS   <-- ACCEPT-OF-WRONG (G4 PASS)
```
**The proof verifies with the wrong output.** So:
- **ChatGPT's `INSTR_WORD_MOD` (aliasing `rs2→rs1`) IS the trigger** on `98387806`. My Entry-2 "refuted" was wrong:
  it tested **random** word corruption (changes opcode/funct → caught by VerifyOpcodeF3/F3F7), **not** the
  targeted operand-field alias. `VerifyOpcode*` binds only opcode/func3/func7 (inst.zir:90-104), so a pure
  `rs2`-field alias passes it and exploits the missing same-register read binding.
- **`random_word` is random bit-flips** (TODO field-targeting unimplemented), so it produces the clean alias
  only **by luck**. Rate ≈ P(selector-0)·P(right bit) ≈ 1/3·1/30 ≈ **1/90 per mutation WHEN the op's rs1/rs2
  register fields differ by one bit** (the honest trace shows `a1=x11`,`a0=x10` — 1 bit apart). ⇒ **N=5000 ⇒
  ~55 clean aliases**, each exploiting → V6/Arguzz finds it easily **iff the A2 guest's operand regs differ by
  ~1 bit**. (If they differ by k bits, selector-0 can't alias; rate collapses — guest design is load-bearing.)
- **A4/V5 still can't:** the field-aware `INSTR_WORD_MOD_SUR` exists but is an **A4 (post-exec)** kind — no
  recompute → the stale read/result is caught. V6's executor `INSTR_WORD_MOD` is **during-exec → recomputes**
  → coherent. So the finder is **Arguzz**, the prediction holds.

**Open (G5 / right-binary):** confirm the **patched** build **rejects** the identical alias (so this is
CVE-2025-52484 closed by `load_rs2`, not a generic decode-binding gap). Running next.

**Verdict update:** Entry-1/Entry-2 had the constraint right but I over-claimed "Arguzz can't/INSTR_WORD_MOD
caught." Corrected: **Arguzz's `INSTR_WORD_MOD` rs2-alias triggers it (G4 empirically confirmed); A4 cannot;
N=5000 suffices with a 1-bit-apart-register guest.** The CVE race is viable.

