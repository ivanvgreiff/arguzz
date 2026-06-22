# Planting an A4-findable soundness bug — FEASIBILITY VERDICT (data-grounded)

**Date:** 2026-06-22 · **Author:** Opus · **Method:** the `full_sweep` E5 statistics run (5000 atoms, `CONSTRAINT_CONTINUE=1` so *all* constraint layers are evaluated per trial) + the rv32im v2 `.zir`/`steps.cpp` source. Every number below is from `thesis_side_experiments/full_sweep/artifacts/e5/`.

## Verdict
**YES — feasible, and Ivan's data-driven instinct is correct. It beats both prior reports.** There exist A4 mutations whose witness, in a measurable fraction of trials, violates **exactly one** local constraint layer while leaving the **global** memory argument **balanced**. Remove/weaken that one constraint on the buggy build and those A4 mutations become **accepted-invalid proofs** = a real soundness bug an A4 single mutation finds. Two clean seams exist; one is findable by **both** A4 and Arguzz.

### Where the prior reports were wrong
Both Composer and Opus argued "the global memory LogUp re-pins every value, so a single A4 edit is always globally rejected." That is true **on average** (e.g. `MEM_VAL_MOD`/`COMP_OUT_MOD`/`STORE_OUT_MOD` break global ~100%), but it is **false for specific, identifiable cases** — and the E5 data finds them. The mistake was reasoning from the average instead of the per-trial histogram. Ivan's "just take the mutation that already keeps a constraint satisfied and remove the other one" is exactly right; the data tells us *which* mutation and *which* constraint.

---

## The two seams (both confirmed in E5, N=250 each)

### Seam A — remove `IsRead` → register-read-consistency bug *(findable by BOTH surfaces)*
- **Mutation:** `PRE_EXEC_REG_MOD` / `next_read` (edits a register **READ**'s `word`, leaves `prev_word`).
- **Layer histogram** (221 applied trials): `(intra,inter,global)` = **(0,1,0): 21** · (0,1,1): 81 · (1,1,1): 119.
- **The (0,1,0) case = the seam:** only the **interstep** layer fires, and that layer is **`IsRead` (`mem.zir:79-80`)** — the check that a read returns the previously-written value. Global (memory residue) stays balanced; no intrastep fires.
- **What those 21 cases are (pinned from the atoms):** **100% `target_region=guest_data`, and the read is a source operand of a STORE/LOAD** — `sw a1, 8(a3)`, `sw ra, 76(sp)`, `lbu t3, 4(a0)`, etc. (i.e. the edited register read feeds a store's value/address or a load, not an ALU result that gets written back — which is why the residue stays balanced and only `IsRead` catches it).
- **The plant:** weaken/remove `IsRead` (`mem.zir:79-80`) — ideally scoped to the register-read path (`ReadReg`/`MemoryRead`), not RAM, to keep it tight. → those 21-class `PRE_EXEC_REG_MOD next_read` mutations now **verify**.
- **Findable by both:**
  - **A4** (post-exec): `PRE_EXEC_REG_MOD next_read` on a guest-data store/load source read → accepted-invalid. Oracle = **internal** (witness read ≠ executed value; journal often unchanged). Hit-rate ≈ **9.5%** of this kind's applied trials.
  - **Arguzz** (during-exec): change a register's value before an instruction reads it → read ≠ prev-write, but Arguzz propagates so the rest of the trace (and global residue) stays coherent → with `IsRead` gone, accepted, **journal wrong** → **strong** oracle.
- **Faithfulness:** register-file read consistency ("a read returns the last value written") is a core, real zkVM soundness invariant. Removing it is a faithful, severe underconstraint — not a contrived harness hole.

### Seam B — remove the decode binding → instruction-type-confusion bug *(A4-strong, high hit-rate)*
- **Mutation:** `INSTR_TYPE_MOD` (edits `cycles[].major/minor` — the **decoded instruction type metadata**, *not* a memory txn).
- **Layer histogram:** `(1,0,0): 160` · (1,0,1): 74 · (1,1,1): 15 · (0,0,0): 1.
- **The (1,0,0) case = the seam (160/250 ≈ 64%!):** only **intrastep** fires, and it's the **decode binding** — `DecodeInst (inst.zir:29)` / `VerifyOpcodeF3(F7)` (`inst.zir:96-104`) — the check that the recorded instruction type matches the fetched word's opcode bits. Global is **structurally** untouched (no memory txn is edited — only metadata), and `IsRead` is untouched.
- **The plant:** weaken/remove the `DecodeInst`/`VerifyOpcode` binding for a marker op. → `INSTR_TYPE_MOD` mutations verify, i.e. the prover can prove a cycle executed as a *different instruction* than the program word encodes.
- **Findability:** **A4** via `INSTR_TYPE_MOD` (very high rate, 64%; internal oracle). **Arguzz** can*not* cleanly use this seam — its `INSTR_WORD_MOD` changes the fetched *word* (a memory value), which breaks **global** (memory residue), so the decode-binding removal doesn't help it. So Seam B is **A4-only/A4-strong**.
- **Faithfulness:** instruction-type confusion (decode not bound to the committed word) is a real, severe soundness class.

> Note on `INSTR_WORD_MOD` (Ivan's earlier candidate, now corrected): it sets `word`+`prev_word` together so the *local* `IsRead` passes, but it **always breaks global** (`INSTR_WORD_MOD_FULL`: global=1.0, 250/250). So `INSTR_WORD_MOD` is **not** a seam. Ivan's correction was right: it only spares the intra/interstep `IsRead`, not the global residue.

---

## Recommendation
- **For the ideal "both-findable" bug → Seam A (remove `IsRead`, register-read path).** It is the one bug the data shows is reachable by A4 (internal oracle) *and* Arguzz (strong oracle), and it's a faithful, catastrophic soundness hole. This directly satisfies "ideally one which can be found by both."
- **Keep the real CVE (`rs1==rs2` double-read) as the Arguzz-native bug** at the same vulnerable commit — it's already there and is the authentic, headline result.
- **Optionally add Seam B (remove decode binding) as a high-rate A4-only bug** if you want a second, very-fast-to-find A4 target (64% hit-rate vs Seam A's 9.5%).
- This gives the race a clean menu: **CVE** (Arguzz-strong, A4-likely-can't), **Seam A** (both), **Seam B** (A4-strong). Per-bug-labeled, separate fingerprinted builds (L13/L14), restore-the-constraint = the patched/post-fix bracket.

## Bracketing & provenance
- "Patched" build for each planted bug = the unmodified circuit (constraint present) → the post-fix REJECT (G5-style). Restoring one EQZ component is the clean bracket.
- Fingerprint (L14/G10): add a `planted_bug` flag (`none|isread|decode`) alongside `load_rs2_present`, so every run proves which hole its binary carries.

## The one confirming spike (cheap, gates any build)
The E5 data + `CONSTRAINT_CONTINUE=1` make this near-certain, but confirm before committing a campaign:
1. On the instrumented vulnerable build, **remove `IsRead` (`mem.zir:79-80`)** (regenerate `steps.cpp` or NOP the two EQZ at the `ReadReg` site).
2. Replay one **known (0,1,0)** `PRE_EXEC_REG_MOD next_read` config (a guest-data `sw`-source read; the 21 are enumerable from `atoms_n250`).
3. **Expect: proof ACCEPTS** (was the only-`IsRead`-firing case). Restore `IsRead` → **REJECTS**. → Seam A confirmed.
4. (Parallel) same for Seam B: remove `DecodeInst`/`VerifyOpcode` binding, replay an `INSTR_TYPE_MOD` (1,0,0) config, expect accept.

## Honest residuals
- **Why exactly those 21 store/load reads keep global balanced** is pinned *empirically* (guest-data store/load source reads) but not yet derived constraint-by-constraint from the `OpSW`/`ReadReg` wiring; the spike confirms the behavior regardless, and the circuit-level "why" can be read off `inst_mem.zir` if needed for the writeup.
- **Scope of `IsRead` removal:** removing it globally weakens *all* memory reads (RAM too) — broader than needed. Prefer scoping to the register-read path (a `ReadReg`-only variant) so the bug is precise and the bracket clean.
- **A4 oracle for Seam A is internal, not strong** (post-exec edits don't move the journal) — consistent with ProG L4; report A4 on the internal oracle, Arguzz on the strong oracle.
