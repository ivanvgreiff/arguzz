# AP.B2 — Decisive finding: IsRead@ReadReg hole is necessary but NOT sufficient

> **2026-06-23 UPDATE — SUPERSEDED IN PART. See `AP_B2_010_RESOLVED.md`.**
> The **conclusion** below (IsRead necessary-not-sufficient; Seam A dead) is correct and confirmed.
> The **mechanism** in §2.1 ("accum computed from the un-edited trace") is **WRONG** — `stepAccum`
> recomputes accum from the *mutated* trace. The residue is nonzero because the diverged read value
> (`newTxn.data` in `mem.zir`) has no matching grand-product counterpart. Separately, the smoke here
> used a corpus config (`race_0000`) that is **not a genuine `(0,1,0)`** mutation (it emits a NONZERO
> global residue when run). The genuine E5 `(0,1,0)` atoms **SIGSEGV** (wild pointer) before the
> global argument runs — `(0,1,0)` is a no-residue-record default, not a balanced LogUp. Full
> evidence (21/21 atoms run to completion) in `AP_B2_010_RESOLVED.md`.

**Author:** Reviewing Opus (this session)
**Date:** 2026-06-23 PM
**Status:** Two results. (1) The honest-verify blocker is **fixed** (prover off-by-one). (2) The mutated-V0 smoke **refutes the simple `(0,1,0)` theory** for register-read mutations: the global memory-permutation (LogUp) argument independently re-binds the value and rejects A4's single-cell edit even with IsRead@ReadReg holed.

---

## 1. Result A — honest verify fixed (prover/verifier now agree)

The first build's `bench-isread` failed honest verify (`verify segment`). Root cause: a **prover-side off-by-one** in fold identification. The zirgen C++ codegen emits each statement's loc comment on the line **above** it (loc-precedes-statement); the patch keyed on the line **below** (`lines[i+1]`), so it neutralized **MemoryIO** folds (the ones sitting just before an IsRead comment) instead of the IsRead folds, and missed the real ones. The verifier `poly_ext.rs` (trailing same-line loc) was correct, so prover ≠ verifier ⇒ `verify segment` on honest. This also produced the 40-vs-26 fold asymmetry.

**Fix:** key fold identification on `lines[i-1]` in `ap_isread_patch.py` (`patch_rust_poly_fp`, both counters) and `ap_poly_cse_audit.py` (`fp_active_total`).

**Post-fix verification:**
```
ap_isread_patch.py status →  poly_ext_active=0/26  poly_fp_active=0/26   (asymmetry gone)
ap_poly_cse_audit.py     →  prover 0/26 == verifier 0/26, scope violations 0, PASS
bench-isread honest proof →  VERIFIES   (prover/verifier consistent)
patched honest proof      →  VERIFIES
```
Residual risk #1 (prover/verifier polynomial agreement) is **resolved**.

---

## 2. Result B — the mutated-V0 smoke (the decisive test)

Config `race_0000_s51_txn15613`: `PRE_EXEC_REG_MOD next_read` on register `a0`, data `2233260 → 2233261` (+1). This is a canonical campaign `(0,1,0)` config (clean build rejects **only** at interstep-local).

| build | exit | `n_fail` (local constraint records) | layer | failing loc | verdict |
|---|---|---|---|---|---|
| **patched** (committed clean) | 101 | **1** | interstep-local | `IsRead @ mem.zir:79` | rejects (as designed) |
| **bench-isread** (IsRead@ReadReg holed) | 101 | **0** | none | — (`verify segment`) | **rejects (global)** |

**Reading:**
- On patched, the mutation fires **exactly one** local constraint: `IsRead@ReadReg`. The `(0,1,0)` screening was right that IsRead is the *only local* guardian.
- On bench, that local failure is **gone** (`n_fail` 1 → 0): the surgical hole works precisely as intended.
- **But bench still rejects** with **zero local constraint failures**, panicking `verify segment` (the prover's `verify_integrity`). The only thing left that can reject with no per-row failure is the **global memory-permutation / LogUp grand-product argument**.

### 2.1 Why — register reads are bound globally, not just locally
RISC-Zero rv32im v2 registers are memory-mapped (a0 lives at addr `1073725482`). Every register read/write is a memory transaction; the **global** memory argument (LogUp grand product over all `(addr, cycle, data)` txns) enforces that a read returns the most-recently-written value at that address. `IsRead@MemoryRead` is the **local** companion (a read doesn't mutate memory: `oldData == newData`).

A4 performs **one post-execution trace edit** of the read's data cell. The grand-product accumulator columns were already computed from the *un-edited* trace, so the edit unbalances the global argument. Removing the **local** `IsRead` check cannot fix this — the **global** argument independently binds the same value and is not scoped to a single register. Hence: necessary (to kill the local failure) but **not sufficient** (global re-catches).

### 2.2 Important methodological flag
The `(0,1,0)` screening metric counts **per-row `<constraint_fail>` records** bucketed into intrastep/interstep/global. The global **LogUp imbalance does NOT emit per-row records** — it only surfaces at `verify_integrity` (`verify segment`). So a config can be labelled `(0,1,0)` (global-count = 0) and **still be globally rejected**. The screening never tested the property it implied. This invalidates the premise that "`(0,1,0)` ⇒ only one guardian ⇒ holing it ⇒ verifiable."

---

## 3. Implication for the A4-findable planted bug

A **single** A4 trace edit of a **memory/register-resident** value is fundamentally caught by the global memory argument, regardless of any local-constraint hole. To make such an edit verify you would have to also neutralize the global argument's binding of that value — which is **not register-scoped** (it's one grand product over all memory) and would over-widen massively, destroying comparability with the CVE/Arguzz track.

Therefore the IsRead@ReadReg hole, as a vehicle for an A4-findable bug, **does not work for `PRE_EXEC_REG_MOD` register reads.**

### Options to put to OCP (not yet acted on)
1. **Re-target the bug to a value the global memory argument does NOT bind** — e.g. a purely intra-cycle computed value (ALU/decode intermediate) that is locally constrained but never enters the memory permutation. Requires finding a constraint whose sole guardian is local *and* whose value is not memory-resident. Needs a fresh feasibility pass.
2. **Two-cell A4 edits** — if the threat model can edit the read *and* its paired accumulator/source consistently, the global argument might be satisfiable. This changes A4's "single post-exec edit" definition; likely out of scope.
3. **Reframe the deliverable** — report this as a *negative* soundness result: "removing a local memory check does not create an A4-exploitable underconstraint because the global memory argument is a redundant guardian." This is itself a publishable, defensible finding about RISC-Zero's defence-in-depth.
4. **Pick a genuinely under-constrained site** discovered by A4's own campaign (a real `(0,1,0)` that verifies on the *committed* circuit), rather than synthesising one by holing IsRead.

**Recommendation:** escalate to OCP with this evidence before any further build/patch spend. The honest-verify machinery is now correct and reusable, but the choice of *which* constraint to hole must change — IsRead@ReadReg is the wrong target because of the global memory argument.

---

## 4. Reproduction
```
# state
python3 a4/scripts/ap_isread_patch.py status            # applied, 0/26 + 0/26
python3 a4/scripts/ap_poly_cse_audit.py                 # PASS, 0 scope violations
# honest + mutated smoke
python3 a4/scripts/ap_v0_smoke.py                        # step1/2 PASS, step3 bench rejects
# per-config layer dump (config 0): patched n_fail=1 IsRead; bench n_fail=0 + verify segment
```
Builds: `a4/builds/ap/patched` (committed, `host_sha e4e9c48…`), `a4/builds/ap/bench-isread` (surgical, `host_sha 677c54e9…`, instrumentation_hash provenance field = `pending` in the quick rebuild; cosmetic only).

## 5. Full 15-config bracket — authoritative numbers (CONFIRMED)

```
GP3 corpus_size = 15            PASS
GP4 bench_accept = 0/15         FAIL   (patched_reject = 15/15)
GP5 genuine      = 0/15         FAIL
bench_layers (all 15) = {intrastep_local:0, interstep_local:0, global:0}  → all reject via `verify segment`
classifications: 15/15 = bench_reject
```
**Every** register-read `(0,1,0)` config behaves identically to config 0: the IsRead@ReadReg hole removes the *only local* failure (bench local layers all `{0,0,0}`), but the global memory-permutation argument rejects all 15 at `verify_integrity`. The theory is refuted across the whole corpus, not just one config. Artifacts: `ap_bracket_table.json`, `ap_b2_verify.json`.
