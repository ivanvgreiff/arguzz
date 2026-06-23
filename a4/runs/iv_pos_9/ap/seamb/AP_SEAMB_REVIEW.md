# AP / Seam-B — Independent verification review of OCP's VerifyOpcode underconstraint

**Reviewer:** Reviewing Opus (this session) · **Date:** 2026-06-23 PM
**Subject:** OCP's claim that a planted `VerifyOpcode*` removal is an A4-findable (`INSTR_TYPE_MOD`) underconstraint.
**Verdict: CONFIRMED. No substantive mistakes.** A few non-blocking flags in §4.

---

## 1. What I reviewed (artifacts)
- `a4/scripts/ap_verifyopcode_patch.py` (the patch)
- `a4/runs/iv_pos_9/ap/seamb/{gen_and_sanity,mutated_v0}.py` (the gates)
- `a4/runs/iv_pos_9/ap/seamb/ap_seamb_verify.json` + `AP_SEAMB_RESULT.md` (claims)
- `a4/standalone/mutations/instr_type_mod.py` (the A4 mutation it relies on)
- binaries + fingerprints under `a4/builds/ap_seamb/{control,bench-verifyopcode}`
- the live patched tree `workspace/risc0-seamb`

## 2. Methodology checks — OCP applied BOTH prior lessons
1. **Off-by-one (Seam-A honest-verify failure).** `patch_rust_poly_fp` keys folds on **`lines[i-1]`** (loc-precedes-statement) — the exact fix from the IsRead post-mortem. Spot-checked the diff: neutralized fold `FpExt x296 = arg3 + x291*poly_mix[1] → x296 = arg3` has **preceding** comment `VerifyOpcodeF3F7 (inst.zir:103)`. Correct.
2. **Prover==verifier consistency.** The patch asserts and reports it (74==74) and even prints a `do NOT build` warning on mismatch. `status` confirms `0/111 witgen, 0/74 verifier, 0/74 prover, prover==verifier OK`.
3. **Global-LogUp trap (the Seam-A killer).** `gen_and_sanity.py` measures the **actual global memory-permutation residue** via `A4_GLOBAL_RESIDUE=1 → <a4_global_residue_zero/>`, not the misleading per-row layer metric. This is precisely the property Seam A violated.
4. **"ACCEPT" = real verifier success.** `mutated_v0.accepts()` requires `returncode==0 AND '"context":"Verifier","status":"success"'` with `CONSTRAINT_CONTINUE` explicitly **off**. No "absence of local failure" shortcut (the Seam-A mirage).

## 3. Independent re-execution (I did not trust the JSON)
Real prove+verify, fresh runs:
```
1) HOLED honest (no mutation)              -> VERIFY (rc 0)                         ✅ honest-preserving + prover==verifier
2) HOLED + s1091 AddI->Sub                 -> ACCEPT (rc 0, Verifier success)       ✅ underconstraint is real
3) CONTROL + s1091 AddI->Sub               -> REJECT (rc 101) @ VerifyOpcodeF3F7    ✅ clean circuit catches it (minor=1)
4) HOLED + s1091 AddI->And (result-change) -> REJECT (rc 101) @ MemoryWrite         ✅ hole scoped to decode; rd-write intact
```
The control's `constraint_fail` reports `minor:1`, proving the mutation truly lands (trace now claims `Sub` where honest was `AddI`). Static scope: `git diff --stat` = **6 generated files only, 259/259 insertions/deletions** (1-for-1, index-preserving). Binaries distinct (`4e0f841c` vs `53ee6663`), both base `93bda33b`, `planted_bug` none vs verifyopcode.

**Mechanism, confirmed sound:** registers are read uniformly (rs1+rs2) for major-0 ALU; relabeling only the `minor` selector changes no memory transaction, so the global permutation stays balanced (measured zero). For the 3 mv-like source cycles (effective rs2≡0), `Add/Or/Sub/Xor` reproduce the original `rd`, so the **only** discriminating guardian was `VerifyOpcode` — removed ⇒ verify. `And/Slt/SltU` change `rd` and are caught by the un-holed `MemoryWrite` rd-write. That `44 reject` is a *feature*: it proves the hole is scoped to the decode binding, not result integrity.

## 4. Flags (non-blocking — not errors, but decisions/notes)
1. **Base commit `93bda33b` is NOT the buggy CVE commit.** This is a clean A4-instrumented base (same as track-b). The result is a *standalone* "A4 finds an introduced underconstraint" demonstration. If the AP-track goal is a single binary carrying **both** the Arguzz-findable bug (buggy commit) and this A4-findable bug for the bug race, this hole must be **ported onto the buggy commit**. If the deliverable is the standalone underconstraint demo, `93bda33b` is fine. **This is the more important open item than the A/B variant question — recommend confirming intent.**
2. **The accepters are result-preserving** instruction-type violations (the witness claims a different op but computes the same `rd`). This is a *genuine* type-binding violation (sound to call an underconstraint), but "mild" by design. OCP states this plainly; it is the basis of the A/B decision below.
3. **The hole removes ALL `VerifyOpcode` bindings** (74 folds across every instruction arm — OpSLT, OpSLTU, …), i.e. "instruction type is no longer bound to the fetched word" **circuit-wide**, not a single-instruction hole. This is cleaner to describe, but be explicit about it in any writeup.
4. **witgen 111 ≠ poly 74** is expected and harmless: witgen EQZ are exec-side asserts (neutralized so A4's edit doesn't crash witgen); only the **poly** folds (74 prover == 74 verifier) are soundness constraints. Over-neutralizing witgen asserts cannot weaken soundness.

## 5. Verdict
OCP's Seam-B work is **correct, scoped, honest-preserving, prover==verifier-consistent, and independently reproduced**. It cleanly demonstrates an introduced, A4-findable underconstraint, and the contrast with the dead Seam A is exactly right (non-memory decode selector ⇒ permutation stays balanced ⇒ removing the local decode check suffices). No pushback on correctness. The only real open question is §4.1 (which base commit this must live on).

## 6. The open decision OCP posed (explained in §7 of the chat reply)
Scoped decode-only hole (current) vs. additionally neutralizing the rd-write binding (stronger "decode + result-write unchecked" variant, ~16 min rebuild). OCP recommends keeping the scoped hole as primary; I agree.
