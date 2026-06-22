# Composer Kickoff — AP.B3: Live A4 + Arguzz validation + negative controls

**Parent spec:** [`../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md`](../IV_POS_9_AP_PLANTED_ISREAD_SPEC.md) §5/AP.B3 · **Status:** BLOCKS ON AP.B2 · **Gates:** GP6, GP7, GP8 · **Reviewer:** Opus. **This batch closes the AP gate.**

## 0. Objective
Prove the planted bug is found by the **actual fuzzer arms** (not just hand-configs): (1) MODE-1 `PRE_EXEC_REG_MOD next_read` finds it at the predicted rate on `bench-isread` and never on `patched`; (2) Arguzz's during-execution register mutation also finds it (strong oracle) — the "both surfaces" claim; (3) the hole is **scoped** — other A4 value-mutations still reject.

## 1. Context
- AP.B2 proved (by hand-config replay) that the (0,1,0)-class `PRE_EXEC_REG_MOD next_read` configs accept on `bench-isread` and reject on `patched`. AP.B3 confirms the **live scheduler** reaches them, and that Arguzz does too.
- Predicted A4 accepted-invalid rate ≈ the (0,1,0) fraction ≈ **9.5% of applied** `PRE_EXEC_REG_MOD next_read` trials (E5: 21/221).
- Outcome classification: `a4/standalone/arguzz_invoke.py::_classify_outcome` (proof `success` + applied → `soundness_signal`). Internal-oracle replay from AP.B2.
- Arguzz during-exec reg mod: the original Arguzz `PRE_EXEC_REG_MOD` (MODE-2 / the during-execution hook), or the MODE-1 Arguzz surface (V6) — whichever the harness drives; it propagates (recomputes), so the journal changes.

## 2. Deliverables
1. **V4 live-A4 result (GP6):** MODE-1 `PRE_EXEC_REG_MOD next_read` campaign (N≈2000) on `bench-isread` and on `patched`; accepted-invalid rate + signature check.
2. **V5 Arguzz result (GP7):** Arguzz during-exec reg mod on both builds; strong-oracle verdicts.
3. **V6 negative-control result (GP8):** other A4 value kinds on `bench-isread`.
4. **`ap_validation.md`:** the three result tables + the headline ("A4 finds the planted register-read bug at ~X%, Arguzz finds it on the strong oracle, the control finds nothing, the hole is scoped").

## 3. Steps
1. **V4 (GP6):** run MODE-1 `PRE_EXEC_REG_MOD next_read` for N≈2000 on `bench-isread`. Confirm: accepted-invalid rate ≈ 9.5% of applied (within sampling), and **every** accept carries the (0,1,0) signature (interstep-only / was-IsRead) per the internal replay. Run the identical campaign on `patched` → **0** accepted-invalid. Assert each run's fingerprint (`planted_bug=isread` for bench, `none` for patched) before trusting results (L14/G11).
2. **V5 (GP7):** drive the Arguzz during-execution register mutation on `bench-isread`; confirm ≥1 **strong-oracle** accept (proof verifies + committed journal wrong vs honest). On `patched` → reject. Record the trigger.
3. **V6 (GP8):** run `COMP_OUT_MOD`, `MEM_VAL_MOD`, `STORE_OUT_MOD`, `LOAD_VAL_MOD` (each N≈250) on `bench-isread`; confirm they still **reject** at their normal rates (they break value/global bindings we did not remove). This proves the hole is scoped to `IsRead` and the build isn't trivially broken.

## 4. Acceptance (GP6, GP7, GP8)
- [ ] **GP6** live `PRE_EXEC_REG_MOD next_read`: accepted-invalid ≈ (0,1,0) rate on `bench-isread`, **0** on `patched`, all accepts (0,1,0)-signature; per-run fingerprint asserted.
- [ ] **GP7** Arguzz during-exec reg mod: strong-oracle accept on `bench-isread`, reject on `patched`.
- [ ] **GP8** other A4 value kinds still reject on `bench-isread`.

## 5. Guardrails
- **Assert the fingerprint per run** before counting any result — a `patched`-binary run masquerading as `bench-isread` (or vice versa) would invalidate everything (this is the exact provenance discipline from L14/G11).
- **A4 accept ⇒ verify it's genuine** via the internal replay (reuse AP.B2's checker) before counting it; don't count no-ops.
- **Don't reward acceptance** in any scheduler (L10) — this is validation, not a learning campaign.
- If the live A4 rate is far below ~9.5%, check the scheduler is actually selecting guest-data store/load source reads (arm reachability), not a sampling/scope problem.

## 6. Definition of done
GP6–GP8 pass: the live fuzzer finds the planted bug at the predicted rate (A4) and on the strong oracle (Arguzz), the control finds nothing, and the hole is scoped. **AP is complete** — `bench-isread` is a validated, both-findable A4 target for the A3 race, with full certainty the `PRE_EXEC_REG_MOD next_read` strategy works.
