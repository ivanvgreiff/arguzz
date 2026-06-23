# IV.POS.9 — Spec AP/Seam-B: build & certify an A4-findable VerifyOpcode underconstraint

**Version:** v1.0 · **Date:** 2026-06-23 · **Author:** Opus (this session).
**Premise validated by direct measurement:** `AP_SEAM_B_VALIDATED.md` (INSTR_TYPE_MOD ALU→ALU keeps
the global permutation balanced: 40/40 `a4_global_residue_zero`).
**Supersedes Seam A** (`AP_B2_010_RESOLVED.md`: register-read hole is dead).
**Goal:** produce a *holed* RISC-Zero rv32im host binary with a single, precise, planted
underconstraint that **A4's `INSTR_TYPE_MOD` mutation can find** (a mutated proof VERIFIES on the
holed binary and is REJECTED on the clean control), with **certainty**, and **without** repeating the
expensive build mistakes of the Seam-A track.

---

## 0. TL;DR — what we are building and why it will work

- **The bug:** remove the `VerifyOpcode*` decode-equality constraints (the only thing tying the
  *claimed instruction type* `major/minor` to the *fetched instruction word*). Nothing else binds
  the type — the global memory permutation binds the **word**, not the type. So a prover can claim a
  cycle ran instruction T while the fetched word encodes T′, and the holed circuit accepts it.
  **= instruction-type substitution underconstraint.**
- **Why A4 finds it:** `INSTR_TYPE_MOD` edits `major/minor` (an ALU→ALU change). Witgen recomputes
  the cycle consistently for the new type; the permutation stays balanced; only `VerifyOpcode*`
  rejects on the clean circuit. Hole `VerifyOpcode*` → the mutation verifies.
- **Why Seam A failed and this won't:** Seam A edited a *memory-resident* value (`newTxn.data`), so
  the global permutation independently re-caught it (or the read crashed witgen). Seam B edits a
  *non-memory selector*, so removing the **local** decode check leaves **nothing** to catch it —
  measured: 40/40 ALU→ALU mutations already show `a4_global_residue_zero` on the *unholed* circuit.
- **Honest-preserving:** on honest proofs the decode equalities already hold, so removing them does
  not change honest behavior — the holed binary still proves+verifies the guest.

---

## 1. The underconstraint — precise definition

### 1.1 What the constraint is (clean circuit)
`inst.zir`:
```
component DecodeInst(cycle, ii) {
  load_inst := MemoryRead(cycle, pc_addr);   // instruction FETCH (a memory read; word ∈ permutation)
  Decoder(load_inst)                          // decode the fetched word -> opcode/func3/func7/...
}
component InstInput(major, minor, ...) { minor_onehot := OneHot<8>(minor); }  // the type SELECTOR
component VerifyOpcode    (decoded, opcode)               { decoded.opcode = opcode; }
component VerifyOpcodeF3  (decoded, opcode, func3)        { decoded.opcode = opcode; decoded.func3 = func3; }
component VerifyOpcodeF3F7(decoded, opcode, func3, func7) { decoded.opcode = opcode; decoded.func3 = func3; decoded.func7 = func7; }
```
`VerifyOpcode*` is invoked inside every per-instruction `Op*` component (e.g. `OpADD`, `OpSLT`,
`OpSRL`) with the **constants** that instruction's encoding must have. It asserts that the Decoder's
view of the fetched word matches the claimed type.

### 1.2 The planted hole
Remove the `VerifyOpcode/VerifyOpcodeF3/VerifyOpcodeF3F7` equality assertions (in witgen **and** in
the prover/verifier constraint polynomial). Two scope options:

- **(A) Full hole (recommended, cleanest claim):** neutralize **all** `VerifyOpcode*` folds (all Op
  arms). The circuit no longer checks that any instruction's opcode/func3/func7 match the fetched
  word → general instruction substitution. ~110 verifier folds.
- **(B) Targeted hole:** neutralize only the arms of the instructions used in the demonstration (e.g.
  the ALU ops reachable from an `AddI` cycle). Smaller patch, narrower claim.

Pick **(A)** unless the patch proves unwieldy; the bug statement is then simply *"the rv32im circuit
omits opcode-decode verification, so the instruction-type field is unconstrained against the program
image."*

### 1.3 Why it is a genuine soundness bug (not a no-op)
With `VerifyOpcode*` gone, a malicious prover can take an honest execution and **relabel a cycle's
instruction type** (e.g. compute `rd = rs1 - rs2` but have the program image hold `addi`), producing
a proof the verifier accepts for a computation the program never authorized. The fetched word still
exists and is permutation-consistent; only its *interpretation* is now free. This is exactly the
single-cell post-execution edit `INSTR_TYPE_MOD` performs — so A4 discovers it.

### 1.4 What A4 finding it looks like (the certainty signal)
A `INSTR_TYPE_MOD` ALU→ALU mutation (e.g. `AddI→Sub`):
- **clean control binary:** REJECT (witgen `EQZ` and/or `verify_integrity` fire `VerifyOpcode*`).
- **holed binary:** ACCEPT — proof generated and `verify_integrity` passes (the decode check is gone;
  the global permutation never bound the type; `a4_global_residue_zero` already measured).

`bench_accepts && control_rejects` over a corpus ⇒ **certainty** we planted a real, A4-reachable
underconstraint.

---

## 2. The three coordinated edits (witgen + prover + verifier MUST agree)

`VerifyOpcode*` is enforced in **three** generated artifacts. All three must be holed consistently or
honest verify breaks (the Seam-A "prover≠verifier ⇒ verify segment" failure). Target tree:
`risc0/circuit/rv32im{,-sys}/...` (the **committed** circuit; see §3).

| # | file | clean form | holed form | count |
|---|---|---|---|---|
| 1 | `rv32im-sys/kernels/cxx/steps.cpp` (witgen) | `EQZ(diff, "..VerifyOpcode..");` | remove / no-op the EQZ | 235 refs (subset are EQZ calls) |
| 2 | `rv32im-sys/kernels/cxx/rust_poly_fp_{0..3}.cpp` (prover) | `FpExt dst = acc + inner*poly_mix[k];` (loc on **preceding** line) | `FpExt dst = acc;` | ~110 folds |
| 3 | `rv32im/src/zirgen/poly_ext.rs` (verifier) | `PolyExtStep::AndEqz(acc, val), // ..VerifyOpcode..` | `PolyExtStep::AndEqz(acc, 0),` | 110 folds (67 F3F7 + 37 F3 + 6 plain) |

- **CUDA** (`steps.cu`, `steps.cuh`): patch for parity, but the build/test is **CPU-only**, so they
  do not affect the result. Patch them only to keep the tree self-consistent.
- The witgen `EQZ` is a pure assertion (no witness value); removing it is **witness-preserving**.
- The poly edits are **fold-neutralization**, not wire-zeroing: repoint the `AndEqz` value to `0`
  (`fp#0 = Const(0)`) / drop the fold's `inner*poly_mix` term. Do **not** zero the shared `Sub`
  diff-wire (CSE-shared across arms → over-widens). This is the exact lesson from `ap_isread_patch.py`.

### 2.1 Tooling
Clone `a4/scripts/ap_isread_patch.py` → `ap_verifyopcode_patch.py`, changing only the **selector**:
- key regex from `IsRead \(.*ReadReg \(` → `VerifyOpcode(F3(F7)?)? \(` (matches all three tiers in the
  loc comment); for scope (B), additionally require the desired `Op*` callsite.
- `patch_poly_ext`: unchanged mechanism (`AndEqz(acc,val)→AndEqz(acc,0)` on matching lines).
- `patch_rust_poly_fp`: unchanged mechanism; **keep the `lines[i-1]` loc-precedes-statement keying**
  (the off-by-one that cost the Seam-A track its first build — see §6).
- add a `patch_steps_cpp` that removes/neutralizes `EQZ(...)` lines whose loc comment contains
  `VerifyOpcode` (and the matching `steps.cu/cuh`).
- clone `ap_poly_cse_audit.py` → assert prover-neutralized-fold-count == verifier-neutralized-fold-count,
  zero scope violations (no non-`VerifyOpcode` fold touched).

---

## 3. The base circuit — start CLEAN (do NOT reuse risc0-modified)

- `workspace/risc0-modified` is **dirty**: it carries the dead Seam-A IsRead hole (26 `AP_PLANTED`
  markers in `poly_ext.rs`; `rust_poly_fp_*` + `steps.cpp` modified). **Never build Seam B on top of
  it.**
- **Use a clean committed circuit.** Two acceptable bases:
  - revert the generated files in a worktree: `git checkout HEAD -- risc0/circuit/rv32im/src/zirgen
    risc0/circuit/rv32im-sys/kernels` then confirm clean; **or**
  - a fresh worktree at the committed circuit commit (preferred for isolation; mirror the
    `build_sweep_binary.sh` isolation pattern: own `target/`, own output workspace, read-only archive).
- **Circuit-version discipline (Seam-A lesson):** the holed and control binaries **must be the same
  circuit commit**, and the demonstration mutation config must be generated **from that commit's
  preflight** (not reused from a different-circuit corpus — `(step, txn_idx)` mappings drift). Do
  **not** zirgen-regen (the `rsync` path-doubling bug that nested `poly_ext.rs` into ignored
  `src/zirgen/zirgen/...` dirs and silently left the verifier stale — it ate ~2 days). **Surgical
  patch of the committed generated files only.**

---

## 4. Procedure — chronological, gated, single foreground script

> **Orchestration rule (Seam-A lesson):** run §4 as **one foreground script that exits on first
> failure**. No agent background handoffs, no Windows-cwd launches (they produced false "running"
> states and 600s-timeout kills). Each step prints a PASS/FAIL line; the script aborts on the first FAIL.

1. **Prep clean base** (§3). Assert: `poly_ext.rs` clean (`AP_PLANTED`=0), `load_rs2` present
   (non-vulnerable baseline), git status clean for the circuit files.
2. **Build the CONTROL binary** from the clean base → `a4/builds/ap_seamb/control/risc0-host`.
   Stamp `fingerprint.json` (`planted_bug=none`, circuit SHA, instrumentation hash — un-spoofable, as
   in `build_sweep_binary.sh`).
3. **Honest-gate the control:** `run_host(control)` must prove **and** verify the guest
   (`"context":"Verifier","status":"success"`). FAIL ⇒ the clean base or build is broken; stop.
4. **Apply the patch:** `python ap_verifyopcode_patch.py apply` (all 3 artifacts). Then
   `ap_verifyopcode_patch.py status` must report verifier-neutralized == prover-neutralized fold
   counts, and the CSE audit must report **0 scope violations**.
5. **Build the HOLED binary** → `a4/builds/ap_seamb/bench-verifyopcode/risc0-host`. Stamp
   `fingerprint.json` (`planted_bug=verifyopcode`).
6. **Honest-gate the holed binary** (the C2 prover==verifier consistency gate — the one that exposed
   every Seam-A plumbing bug): `run_host(holed)` must prove **and** verify the guest. Because the
   decode equalities hold on honest input, this MUST pass; FAIL ⇒ prover/verifier inconsistency (a
   patch desync — fix before any mutation test). **Do not proceed past a failing honest-gate.**
7. **Generate the demonstration mutation** from the control binary's preflight: pick an `AddI`
   instruction cycle, build an `INSTR_TYPE_MOD` config `AddI→Sub` (a **pure-decode** target — fires
   only `VerifyOpcode*`, no `MemoryWrite@99`; see `AP_SEAM_B_VALIDATED.md §3`). Sanity: run it under
   `A4_GLOBAL_RESIDUE=1` on the **control** and confirm `a4_global_residue_zero` (premise holds for
   this circuit/guest).
8. **Mutated-V0 (the certainty test):** run the same `INSTR_TYPE_MOD` config on both binaries
   **without** `CONSTRAINT_CONTINUE** (a real proof attempt):
   - control → **REJECT** (verify fails: `VerifyOpcode*`).
   - holed → **ACCEPT** (prove+verify success).
   PASS ⇔ `holed_accepts && control_rejects`. This is the decisive demonstration.
9. **Corpus bracket (certainty at scale):** run N (≥15) distinct ALU→ALU `INSTR_TYPE_MOD` configs
   (vary source/target op and cycle). Gate: `holed_accepts = N/N`, `control_rejects = N/N`. Record
   to `ap_seamb_verify.json`.
10. **Provenance & archive:** archive both binaries read-only with fingerprints; record the patch
    diff and the audit output.

---

## 5. Acceptance checklist (Seam-B done ⇔ all pass)

- [ ] Clean committed base (no Seam-A residue; `load_rs2` present).
- [ ] Patch applied to all 3 artifacts; verifier-folds == prover-folds neutralized; **0 CSE scope
      violations**; non-`VerifyOpcode` folds untouched.
- [ ] **Control honest verify = PASS.**
- [ ] **Holed honest verify = PASS** (prover==verifier consistency).
- [ ] Demonstration config shows `a4_global_residue_zero` on control (premise holds here).
- [ ] **Mutated-V0: holed ACCEPTS, control REJECTS.**
- [ ] Bracket: holed accepts N/N, control rejects N/N.
- [ ] Fingerprints stamped; binaries archived read-only.

---

## 6. Lessons baked in (do NOT re-pay these)

From the Seam-A track (`AP_B2_STATE_AND_ROOTCAUSE.md`, `AP_B2_GLOBAL_LOGUP_FINDING.md`, audit log):

1. **Surgical patch of the committed circuit — never zirgen-regen.** The regen `rsync` path-doubling
   nested the Rust verifier poly into ignored `src/zirgen/zirgen/...` dirs, so binaries built from
   df6fb9d C++ + stale committed Rust verifier → every measurement invalid. Cost: ~2 days. Patch the
   committed generated files in place.
2. **Prover and verifier must be patched consistently** or honest verify fails (`verify segment`).
   The honest-gate (steps 3 & 6) is the detector — gate on it before any mutation test.
3. **Loc-precedes-statement off-by-one.** The C++ codegen emits each statement's loc comment on the
   line **above** it; the verifier `poly_ext.rs` carries a trailing same-line loc. Key fold
   identification on `lines[i-1]` for the prover, inline for the verifier. (Keying on `i+1`
   neutralized the wrong folds and desynced prover/verifier — the first Seam-A build's silent failure.)
4. **Neutralize the fold, not the diff-wire.** The `Sub` diff-wire is CSE-shared across instruction
   arms; zeroing it over-widens. Repoint the per-arm `AndEqz`/fold to `0`/`acc`.
5. **Never infer verify-behavior from a screening layer signature.** `(1,0,0)`/`(0,1,0)` global=0 is a
   **default when no residue record exists** (crash/cutoff/hook-unreached). Validate by **running the
   exact mutation to completion with `A4_GLOBAL_RESIDUE=1`** and reading `a4_global_residue_{zero,nonzero}`,
   and by the mutated-V0 on the holed binary. (This is how Seam A's false premise was caught and Seam
   B's true premise confirmed.)
6. **One foreground orchestration script, exit-on-first-failure.** Background agent handoffs +
   600s timeouts produced false "running" states and wasted hours.
7. **Same circuit commit for control + holed + mutation-config source.** Mixing circuit versions
   silently breaks comparability and `(step, txn_idx)` mapping; the mutated-V0 is the drift catch.
8. **VerifyOpcode is a constraint-only check** (witgen `EQZ` + poly folds) — no new component needed
   (unlike IsRead's `MemoryReadNoIsRead`). The witgen edit is removal of `EQZ` asserts, which is
   witness-preserving — simpler and lower-risk than the Seam-A witgen surgery.

---

## 7. Open decisions for Ivan before the build

1. **Scope:** full hole (A, ~110 folds, general bug) vs. targeted arms (B, smaller patch). Recommend A.
2. **Base:** revert-in-place on a worktree vs. fresh isolated worktree (recommend fresh, mirroring
   `build_sweep_binary.sh` isolation).
3. **Guest:** which guest for the honest-gate + demonstration (reuse the AP guest, or a minimal
   single-`addi` guest for a crisp mutated-V0). A minimal guest makes the demonstration unambiguous.
4. **Comparability with the CVE/Track-A race:** Seam B is an *independent planted bug* (no CVE
   back-port), like Seam A was — it gives the race an A4-findable target. Confirm that is still the
   intent.

---

## 8. Inventory of validated facts this spec rests on

| fact | evidence |
|---|---|
| ALU→ALU `INSTR_TYPE_MOD` keeps the permutation balanced | 40/40 `a4_global_residue_zero` (run to completion) — `AP_SEAM_B_VALIDATED.md §1` |
| branch/jump/load type changes break global | 8/8 `nonzero` — same |
| `INSTR_WORD_MOD` (full+sur) always breaks global (memory family) | run to completion; `{1/0/1}` histograms |
| the word is `MemoryRead` data (∈ permutation); major/minor is a selector (∉ permutation) | `inst.zir` `DecodeInst`/`InstInput` |
| sole guardian is `VerifyOpcode*` (a pure intra-row equality) | atom constraint inspection; `inst.zir:90/95/101` |
| 3-artifact enforcement (witgen `EQZ` + 2 poly files); ~110 verifier folds | grep of `steps.cpp` / `poly_ext.rs` / `rust_poly_fp_*` |
| fold-neutralization machinery already exists | `ap_isread_patch.py`, `ap_poly_cse_audit.py`, `ap_v0_smoke.py` |
