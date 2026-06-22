# Composer Kickoff — A1.B3: Deterministic coherent repro + per-variant propagation

**Parent spec:** [`../IV_POS_9_A1_VULN_BUILD_SPEC.md`](../IV_POS_9_A1_VULN_BUILD_SPEC.md) §5 · **Batch:** A1.B3 · **Status:** BLOCKS ON A1.B2
**Gates this batch satisfies:** **G4, G5** (+ deliverable **D5**) · **Reviewer:** Opus. **This batch closes the A1 gate.**

---

## 0. Objective
Trigger the bug **on demand** in MODE 1 and prove the pre/post-fix bracket: a deterministic, **coherent, propagating** read-divergence fault that the **vulnerable** build accepts as a proof of a wrong output (**G4**) and the **patched** build rejects (**G5**). Then **characterize, per variant, whether its register-mutation arm propagates** (during-execution recompute → coherent) or is a single post-execution cell edit (**D5**) — because that determines which variants can find the bug in the race.

## 1. Context you need — READ THIS, it's the crux
The exploit needs a **coherent** witness, not a single-cell edit. For `remu x3,x5,x5`, `x5=7` (honest: `read_rs1=7, read_rs2=7, result=0`):
- present constraint **C_local:** `rem(read_rs1, read_rs2) == result`;
- **missing** constraint **C_mem(rs2):** the second same-cycle read of x5 must equal x5's memory value.

The exploit witness must be `read_rs2=5, result=2` — **both** — so C_local (`rem(7,5)==2`) holds and only C_mem(rs2) is violated. Committed output = 2 ≠ honest 0.
- **A single post-execution edit of the rs2-read cell does NOT work:** leaving `result=0` makes `rem(7,5)=2≠0` → **C_local fires** (it's present) → proof rejected. A4's non-propagating single-cell mutation cannot produce the coherent pair.
- **A during-execution (propagating) fault works:** inject the rs2 operand = 5 during execution → the executor recomputes `rem(7,5)=2` → records `read_rs2=5, result=2` coherently → only C_mem(rs2) violated → vulnerable accepts. **This is how Arguzz found it.**

Trace mechanics (from the audit): reads are `RawMemoryTransaction{addr,cycle,word,prev_cycle,prev_word}`; registers memory-mapped at `USER_REGS_BASE = 0xFFFF0080/4`; for the op at user-step N the two reads are `txn K`, `txn K+1` (both `addr=base+5`, `cycle=2N`), write is `txn K+2` (`cycle=2N+1`). `A4_MUTATION_CONFIG` (consumed `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs:245-702`) addresses a txn by `txn_idx`. Outcome classification: `a4/standalone/arguzz_invoke.py::_classify_outcome:88-107` (prover `success` + applied → `soundness_signal`).

## 2. Deliverables
1. **Minimal repro guest** encoding `rs1==rs2`: inline-asm `remu x3, x5, x5` with `x5` from input via an input barrier (so `a%a` isn't const-folded). **G3-style proof:** `objdump -d` shows an executed `remu` with identical rs1==rs2 register fields. (This may become Race-guest A in A2.)
2. **Deterministic coherent fault** that produces `read_rs2≠read_rs1` AND a recomputed matching result — via the during-execution `FAULT_INJECTION_ENABLED` operand hook (preferred; same hook MODE 2 uses) **or** a coordinated edit of the rs2-read + result cells. If the MODE-1 framework supports neither deterministically today, **specify the minimal new "coherent same-register divergence" primitive A2 must build** — but still hand-wire a coherent witness here to prove the bug fires.
3. **G4/G5 validation table** (vulnerable accepts wrong output; patched rejects identical fault); cross-checked against A1.B1's canonical trigger.
4. **`a1b3_variant_propagation.md` (D5):** per variant (V5_control, V6_uniform, V6_cTS, Hybrid_cTS) — does its register-mutation arm propagate (recompute) or single-cell-edit? **Check Hybrid specifically** — its 4 imported Arguzz kinds historically excluded `PRE_EXEC_REG_MOD` as a name-duplicate of the A4 kind, so its reg-mutation may be the single-cell A4 flavor. Record facts, do not assume.

## 3. Steps
1. Build the minimal `rs1==rs2` guest; rebuild the vulnerable host to embed it; `objdump` to confirm the op survived (G3 check).
2. Identify the two read txns of the op's cycle via `A4_DUMP`/`A4_INSPECT` (same `addr`, same `cycle`, consecutive `txn_idx`).
3. Apply the **coherent propagating** fault (drive the during-exec operand hook so the result recomputes; if using a coordinated cell edit, set both `txn K+1.word` and the result cell to a coherent pair). Confirm `read_rs2≠read_rs1` and `result == rem(read_rs1, read_rs2)` in the witness.
4. Run on the **vulnerable** build → expect proof **accepts** + committed output wrong (G4). Run the **identical** fault on the **patched** build → expect **reject** (G5). Fill the table.
5. Characterize each variant's reg-mutation propagation (D5).

## 4. Acceptance (G4, G5)
- [ ] Minimal guest's `remu`/`divu` provably encodes `rs1==rs2` (disasm).
- [ ] The fault yields a **coherent** witness (C_local holds; only C_mem(rs2) violated).
- [ ] **G4:** vulnerable build ACCEPTS a proof of a wrong committed output.
- [ ] **G5:** patched build REJECTS the identical fault.
- [ ] Trigger matches A1.B1's canonical record.
- [ ] D5 propagation table written for all four variants.

## 5. Guardrails
- **A single post-execution rs2-read edit with a stale result is NOT a valid repro** — it trips C_local and proves nothing about the bug. The witness must be coherent.
- **Do not** declare "A4 can/can't find it" from this batch — A1.B3 only builds the *deterministic* repro and characterizes the surfaces; the *competitive* answer is the A3 race. (The leading prediction — V5 likely can't on the strong oracle — is in the mechanism doc; this batch gathers the evidence, doesn't settle the race.)
- **Do not** key any acceptance on raw proof-acceptance as a reward (L10) — this is a repro, not a campaign.

## 6. Definition of done
G4 and G5 pass on the same coherent fault; the minimal guest + fault spec + D5 table are written. **A1's gate (G1–G5, G9, G10) is now fully open → A2 may begin.** Hand to A2: the repro guest, the coherent-fault spec (or the new-primitive requirement), and the D5 propagation table.
