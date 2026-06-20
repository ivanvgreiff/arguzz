# New Master Plan — IV.POS.8 → IV.POS.9 (governed by `ProG_Report_4.md`)

**Status:** ACTIVE — this is the authoritative forward plan. **Date:** 2026-06-19. **Author:** Opus (planning).
**Governing requirements:** [`pro_checkin_attachments/ProG_Report_4.md`](./pro_checkin_attachments/ProG_Report_4.md) — Pro's architecture call. *Every phase below traces to a section of that report.*
**Companion (backward-looking record of what's DONE + open flags):** [`separate-planning/central-planning-1.md`](./separate-planning/central-planning-1.md).

---

## 0. How this document works (the planning hierarchy)

```
ProG_Report_4.md   →   New_Master.md   →   per-phase SPECS   →   per-spec BATCHES
(requirements)         (this doc:           (IV_POS_8_*_SPEC.md:   (composer/*_KICKOFF + *_REPORT:
                        chronological         detailed phase         implementation detail;
                        plan; what each       design; what each      Composer implements,
                        spec does + its       batch does)            Opus reviews, batch by batch)
                        batches; links)
```

- **New_Master (this doc)** = the chronological plan. It says *what each spec accomplishes and the batches that make it up*, and **links every spec + batch doc** (§6 index). It is deliberately *less* detailed than the specs.
- **Specs** (`IV_POS_8_<phase>_SPEC.md`) = per-phase implementation design; outline what each batch does. Each spec is Ivan+Opus reviewed before Composer starts.
- **Batches** (`composer/<phase>_BATCH<n>_*.md`) = the most detailed level; Composer implements one batch, Opus reviews, then the next. Unchanged from our prior process.

**The reframed thesis (ProG_Report_4 §7 — the north star for everything below):**
> *Constraint-space feedback is **not** a replacement for Arguzz's execution-fault surface. It is a **scheduler + triage layer** that makes execution-fault fuzzing more directed, while A4 adds witness-internal mutation surfaces that execution-time fault injection does not naturally cover.* The candidate winning architecture is **Hybrid-cTS**, validated by the four-variant checkpoint — not "pure post-execution trace fuzzing beats Arguzz."

**Pro's one-line sequencing call (§0/§2):** *Build D2.C → D2.D/E/F → run the four-variant POS checkpoint → analyze by territory → only then decide whether D1.E matters. Do **not** block the checkpoint on a full D1.E reward-rewire.*

---

## 1. Standing decisions LOCKED by ProG_Report_4 (constraints all specs must honor)

These are Pro's answers to the 8 check-in questions + agreements. Specs do **not** re-litigate these.

| # | Decision (locked by ProG_Report_4) | Source |
|---|---|---|
| **Variant set** | `V5_control` (A4-only baseline, **archive-reused**, ConstantFloor 0.55) · `V6_uniform` (all 11 Arguzz kinds, round-robin, **modernized driver — FRESH POS re-run, NOT R2 archive reuse** [Ivan-locked 2026-06-19; needed for schema/outcome parity in D2.G; R2 V6 archive = historical reference only]) · `V6_cTS` (**all 11** Arguzz kinds, cTS) · `Hybrid_cTS` (11 live A4 + **4 selected** Arguzz kinds, cTS) | §1, §2 Phase 1, §4 |
| **D1** Decay | Don't drop, don't make critical path. V5-only = keep `ConstantFloor(0.55)`. Hybrid/V6-cTS = **Bernoulli floor**. If D1.E runs: K≈200–300, epoch `[(0,0.55),(1000,0.35)]`. | Q1 |
| **D2** CGC reward | **Confirm `production_log2_corrected`** as active L0 reward. **Reject `page_class`/coarsened as L0** (keep `page_class` as per-guest *telemetry* only). | Q2, §1 |
| **D3** L1 reward | Naive-OR-with-guards OK for D1.E v1 only. **Do NOT activate L1 on Hybrid's first run** — log it, re-audit on Hybrid telemetry, then decide. Final arch = **per-channel posteriors**, not naive OR. | Q3, §4 |
| **D4** Accept signal | **Acceptance is NEVER a reward.** Add a **cheap fault-propagation filter NOW** (in D2.G); triage accepted candidates into noop / propagated-candidate / hidden-global-reject. Only propagated → Mode-B. | Q4, §4 |
| **D5** Pure-A4 | A4 not "done", but **no new pure-A4 batch before the Hybrid checkpoint**. Next batch is mechanism-selected (BigInt/paging/structural-index) → IV.POS.9. | Q5 |
| **D6** Sequencing | **Hybrid first**, D1.E later/parallel. | Q6 |
| **D7** Multi-guest | Single-guest checkpoint first; **multi-guest before any "beats Arguzz" headline.** Priority: sha2-host → **ECALL/MRET/control-heavy** → memory-stress+branch → BigInt/paging → stock SHA. | Q7 |
| **D8** Mappings | Mostly sound for first checkpoint. Keep 19 zones / 7-class arm opcode / 8-class CGC opcode / 6 txn_roles / `address_region×log2×txn_role×cycle_phase` reward. **Report zone+arm occupancy.** | Q8 |
| **Naming-overlap caveat** | Excluding the 4 A4-name-duplicate Arguzz kinds from Hybrid is **provisional budget control, NOT "names are redundant"** (Arguzz `PRE_EXEC_REG_MOD` ≠ A4 `PRE_EXEC_REG_MOD`). D2.G adds a rule to revisit if those kinds prove high-value in V6-cTS. | §4 |

---

## 2. The chronological plan (Phase 0 → 5)

> Each phase names its spec(s), the batches that make them up (outline), the ProG_Report_4 source, and status. Full batch detail lives in the specs/kickoffs. Links in §6.

### Phase 0 — Lock D2.C (fix spec drift) — *ProG_Report_4 §2 Phase 0*
**Goal:** resolve two pieces of v0.3→v0.4 drift before any implementation.
- **Drift 1:** the arm-certainty-stack (S5) still asserts all D2.C arms are `pre_exec`, contradicting v0.4's nontrivial `pre_post` (5 `pre_exec` + 6 `post_exec`). Fix.
- **Drift 2:** any older NFP/plan tables implying `V6-cTS = 4 kinds` are superseded (V6-cTS = 11). Sweep + fix.
- **Spec:** `IV_POS_8_D2_C_SPEC.md` **v0.5 LOCK** (Phase 0 drift fix; no implementation batches).
- **Status:** ✅ **DONE** (2026-06-19). Unblocks Phase 1 (awaiting Opus Batch 1 kickoff).

### Phase 1 — Build D2.C (Arguzz integration) — *§2 Phase 1*
**Goal:** the 3-layer Arguzz stack + modernized V6-uniform driver, so all four variants can be scheduled.
**Spec:** [`IV_POS_8_D2_C_SPEC.md`](./IV_POS_8_D2_C_SPEC.md) (**v0.5 LOCK**). **Batches (already defined in the spec):**
- **Batch 1** — primitive `arguzz_invoke.py` + real-binary smoke + V5 golden-trace (decision-sequence).
- **Batch 2** — bridge `arguzz_bridge.py` + arm construction (FULL=11 / SELECTED=4) + **arm-count measurement** (triggers Suggestion 2 if >300).
- **Batch 3** — modernized `v6_uniform_driver.py` (writes through `CoverageDB`, normalized loc) + `fuzzer.py` Arguzz dispatch + end-to-end smoke + DB byte-identity gate.
- **Batch 4** — Hybrid integration smoke + cross-cutting registration + closure.
**Status:** ✅ **D2.C COMPLETE** — spec **LOCKED (v0.5)** + **§15 living-issue annex (ISS-1…ISS-9 + POS-run policy)**; **Batches 1–4 implemented & reviewed** ([B1](./composer/D2C_BATCH1_COMPOSER_REPORT.md) · [B2](./composer/D2C_BATCH2_COMPOSER_REPORT.md) · [B3](./composer/D2C_BATCH3_COMPOSER_REPORT.md) · [B4](./composer/D2C_BATCH4_COMPOSER_REPORT.md), all greenlit 2026-06-20); **arm-space: KEEP 437** (ISS-2 closed). **Batch 4 closure** = hybrid forerunner + 66-case registration + **ISS-8 RESOLVED** (F13 config bug — missing `A4_COVERAGE_TOUCH` co-trigger, NOT an analysis-scope limitation; bridge default env now sets both `A4_FAMILY_RESIDUE=1`+`A4_COVERAGE_TOUCH=1`; local N=10 CGC=16/gf=54, POS N=50 flare CGC=88/gf=387) + **ISS-9 RESOLVED** (both fuzzer + driver route through `create_mutation_for_arm`; bridge is the single Arguzz entry point). Tier-1/Tier-2 V5 golden traces byte-identical; full sweep **729 passed / 27 skipped**. Remaining OPEN: ISS-1 (D2.G fault-corroboration residual), F12 (N=10000 cTS fairness → D2.F).

### Phase 2 — Bernoulli floor for the new cTS variants — *§2 Phase 2, Q1* — **DONE (B1, 2026-06-20)**
**Goal:** add `if rand() < floor_fraction: floor else: adaptive` mode to `bandit_ts.py`, used **only by V6-cTS + Hybrid-cTS** (the integer-quota geometry collapses to ~3 regimes — D1.A Finding D — which matters more as arm count grows to ~160–350). **Do NOT change V5_control** (archive baseline stays). A separate `V5_fresh_bernoulli` ablation is optional/later and must not block.
**Spec:** [`IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md`](IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md) **v1.0 LOCKED** (authored 2026-06-20, Opus-CP acting D2-Opus) — single batch B1: `bernoulli_floor` scheduler flag + tier-3 fork in `bandit_ts.py`; `fuzzer.py` enablement gated to `ARGUZZ_CTS_STRATEGIES` (V5 + V5-decay variants unchanged); Layer-1 behavior tests (mode-share linearity for p∈{.20,.35,.55,.80} = the Finding-D fix), Layer-2 V6-cTS golden trace, V5 byte-identity (Tier-1+Tier-2) as the existential gate. *(Could alternatively fold into D2.D; kept separate per Pro's distinct-phase treatment.)*
**Sequencing note:** D2.C (Phase 1, incl. Batch 3) can land *without* Bernoulli — it's orthogonal to the Arguzz bridge. But the **Phase-3 checkpoint campaigns must NOT start until this phase is green** (Pro: "add Bernoulli before large Hybrid campaigns").
**Status:** TODO (after/with Phase 1; before Phase 3 campaigns).

### Phase 3 — Variant dispatch, tests, and the four-variant checkpoint — *§2 Phase 3, Q6 steps 3–5*
**Goal:** wire the 4 variants, validate, and run the checkpoint on the current (sha2-host) guest.
- **Spec D2.D** [`IV_POS_8_D2_D_SPEC.md`](IV_POS_8_D2_D_SPEC.md) **v1.0 DONE** — variant CLI + `variants.py` registry; inactive L1 logging substrate; F9 applied-accounting smoke. Report: [`composer/D2D_B1_B3_COMPOSER_REPORT.md`](./composer/D2D_B1_B3_COMPOSER_REPORT.md).
- **Spec D2.E** `IV_POS_8_D2_E_SPEC.md` (**to write**) — integration tests / golden traces / tiny smoke (the 5-layer "we built what we think" gate); normalized-loc parity; applied-accounting smoke. Batches: per the 5 layers.
- **D2.F** POS dispatch (**master-plan section + Composer kickoff**, to write) — F.1 smoke-gate (8 jobs) → F.2 production tail. **N=6000** for archive comparability; **optionally N=10000 for V6-cTS + Hybrid-cTS** (their arm spaces are 3–7× V5's, so many arms under-sampled at 6000). `V5_control` = archive reuse; `V6_uniform/V6_cTS/Hybrid_cTS` = fresh.
- **Status:** specs TODO. Blocks on Phase 1+2.

### Phase 4 — Territory analysis + propagation filter (D2.G) — *§2 Phase 4, Q4, §6 Suggestions 3/4/5*
**Goal:** analyze the checkpoint by **territory + rejection channel + accepted-candidate propagation**, not raw loc count.
**Spec D2.G** `IV_POS_8_D2_G_SPEC.md` (**to write**) — produces `build_d2_artifacts.py`, CSVs, plots, the Pro-facing D2 report, and the D3 sketch. Must include:
- **Territory decomposition:** common / A4-only / Arguzz-only / Hybrid-only / V5-signature ECALL-MRET / V6-exclusive normalized locs; CGC final+AUC; local AUC; applied-pull count; skip/error rate; **C1/C2/C5 rejection-channel split**; soundness_signal count; arm occupancy + entropy.
- **The cheap fault-propagation filter (Q4 — do NOT defer):** classify each `soundness_signal=True` row → `accepted_noop` / `accepted_propagated_candidate` / `accepted_hidden_global_reject` (rerun w/ `A4_FAMILY_RESIDUE=1`). Only propagated candidates flagged for Mode-B. Use trace/witness propagation, not just journal mismatch.
- **Suggestion 3** — report **separate scores** (survey / proximity / soundness / global), not one Bernoulli.
- **Suggestion 4** — log a **repairability proxy** (low d_loc/d_glob, singleton, recurring loc, C2-only…).
- **Suggestion 5** — **"unique useful failures"** (unique_locs_with_d_loc≤2, singleton-hit, per-loc min d_loc/d_glob).
- **Excluded-kind rule (§4):** if V6-cTS shows the 4 excluded Arguzz kinds have high unique coverage / accepted-propagated / bug-proximity → schedule a Hybrid-full / Hybrid+excluded follow-up.
- The analysis answers the Case A–E gate (§3 below).
**Status:** spec TODO. Blocks on Phase 3 DBs.

### Phase 5 — Decide what's next (gated on Phase 4 results) — *§2 Phase 5, Q6 step 7*
After D2.G, **choose one (or run in parallel)** per the Case A–E gate (§3): Hybrid-L1 run (re-audit L1, then activate) · D1.E V5-only causal test · `V6-cTS-lite` (Suggestion 2) · multi-guest expansion (Q7) · surface meta-bandit (Suggestion 1). **Status:** decision point, not pre-committed.

---

## 3. Decision gate after Phase 4 — ProG_Report_4 §5 (Cases A–E)

The four-variant result selects the next move:

| Case | Result | Next move |
|---|---|---|
| **A** | V6-cTS **beats** V6-uniform | Core feedback hypothesis validated. Keep V6-cTS; run/keep Hybrid-cTS; re-audit + consider active Hybrid-L1. If Hybrid also beats V6-uniform → strongest architecture. |
| **B** | V6-cTS **loses**, Hybrid **wins** | Win is *hybrid surface + A4 witness terrain*, not pure MAB over Arguzz. Investigate V6-cTS arm overfactorization → try `V6-cTS-lite`. Reframe paper accordingly. |
| **C** | V6-cTS **wins**, Hybrid **loses** | A4 arms dilute the Arguzz scheduler / 4-kind subset too narrow. Run Hybrid without A4 floor dominance OR surface budget split (e.g. 60% Arguzz / 40% A4 — Suggestion 1). Don't conclude A4 useless. |
| **D** | **Both lose** to V6-uniform | cTS arm space too fragmented / reward too sparse / floor too thin. Fixes (in order): collapse V6 arms (drop opcode_class or fine zones), N→10000, activate channel-aware L1 after re-audit, surface-level hierarchical scheduling. **Do NOT conclude "feedback failed" until V6-cTS-lite is tested.** |
| **E** | Hybrid preserves V5 terrain but doesn't beat V6 raw | Still publishable: claim shifts from "beats raw loc count" to "dominates on unioned normalized terrain / witness-internal families / bug-proximity." → multi-guest + bug-proximity emphasis. |

---

## 4. Deferred / future (explicitly NOT before the Hybrid checkpoint)

| Item | When | Source / future spec |
|---|---|---|
| **Mechanism-selected pure-A4 batch** (BIGINT_BYTES_MOD, CYCLE_PAGING_IDX_MOD, CYCLE_TXN_IDX_MOD, CYCLE_BIGINT_IDX_MOD, CYCLE_MODE on paging, INSTR_TYPE on paging/ECALL) | IV.POS.9 / post-D2.G; tie to a BigInt/paging guest | Q5; D2.B mechanism report §11 → future `IV_POS_9_A4_BATCH_SPEC.md` |
| **Multi-guest suite** (ECALL/MRET-heavy guest is the priority — V5's signature terrain; needs C++ inspector extension) | After single-guest checkpoint, before any headline | Q7 → future `IV_POS_8_MULTIGUEST_SPEC.md` |
| **Channel-aware reward** (per-channel posteriors / weighted acquisition; retires naive OR) | After L1 re-audit on Hybrid telemetry | Q3, §4, Suggestion 3 |
| **Surface-level meta-bandit** (2-level: choose surface → arm; enforce A4/Arguzz budgets) | Contingency for Case C/D, or a deliberate Hybrid-v2 | Suggestion 1 |
| **Heavy witness-patching / repair / minimization (Mode-B / D3)** | After checkpoint; only on `accepted_propagated_candidate`s | §4 (defer repair, NOT the cheap filter) → `IV_POS_8_D3_DESIGN_PROPOSAL.md` |
| **D1.E V5-only reward-rewire campaign** | Optional/parallel; run only if D2.G shows reward saturation is the limiter | Q1/Q6 → existing draft [`IV_POS_8_D1_E_SPEC.md`](./IV_POS_8_D1_E_SPEC.md) (v0.2.1, demoted) |

---

## 5. Contingencies to keep loaded (from ProG_Report_4 §6)

- **Suggestion 2 — V6-cTS-lite:** if D2.C Batch 2 measures V6-cTS actual arm count **> 300**, reduce *in this order*: (1) drop `pre_post` where kind already encodes it; (2) merge `core_arithmetic/mul/div/shr → core_compute` for Arguzz arms; (3) keep boundary zones; (4) keep `opcode_class` only where it changes applicability. Don't start at the maximal 5-tuple if it crosses the threshold at N=6000.
- **Suggestion 1 — surface meta-bandit:** the structural fix if Hybrid's A4 and Arguzz arms compete destructively in one flat posterior (Case C/D).

---

## 6. Spec & batch index (master tracking table — links to every spec + its batches)

| Phase | Spec | Status | Batches (outline) | Doc |
|---|---|---|---|---|
| — | D2.A foundation | ✅ DONE (`7b66fb9`) | B1 arm-shape; B2 outcome col | [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) · reports `composer/D2A_BATCH{1,2}_*` |
| — | D2.B pure-A4 | ✅ DONE (`e2c2256`→`dfd0ebe`) | B1–B4 + PS-1/PS-2 | [`IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) · [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md) · `composer/D2B_*` |
| **0** | **D2.C** spec lock | ✅ DONE | Phase 0 drift fix → v0.5 LOCK | [`IV_POS_8_D2_C_SPEC.md`](./IV_POS_8_D2_C_SPEC.md) |
| **1** | **D2.C** Arguzz integration | ✅ DONE (v0.5 LOCK · B1–B4 reviewed) | B1 primitive ✅ · B2 bridge ✅ (437 KEEP) · B3 driver+fuzzer ✅ · B4 hybrid+registration+ISS-8/9 closure ✅ (729 pass/27 skip; golden traces green) | [`IV_POS_8_D2_C_SPEC.md`](./IV_POS_8_D2_C_SPEC.md) (§15 ISS-1…9 + POS policy) · [`composer/D2C_BATCH4_COMPOSER_REPORT.md`](./composer/D2C_BATCH4_COMPOSER_REPORT.md) |
| **2** | **D2 Bernoulli floor** | ✅ DONE (B1, 2026-06-20) | B1 scheduler flag + tier-3 fork + Layer-1 behavior tests + Layer-2 V6-cTS golden trace + V5 byte-identity gate (757 pass/27 skip) | [`IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md`](IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md) · [`composer/D2_BERNOULLI_FLOOR_B1_COMPOSER_REPORT.md`](./composer/D2_BERNOULLI_FLOOR_B1_COMPOSER_REPORT.md) |
| **3** | **D2.D** variant dispatch | ✅ DONE (B1–B3, 2026-06-20) | B1 CLI+registry · B2 variant smoke+F9 · B3 inactive L1 logging | [`IV_POS_8_D2_D_SPEC.md`](IV_POS_8_D2_D_SPEC.md) · [`composer/D2D_B1_B3_COMPOSER_REPORT.md`](./composer/D2D_B1_B3_COMPOSER_REPORT.md) |
| **3** | **D2.E** integration tests | ✅ DONE (B1–B3, 2026-06-20) | B1 normalize-loc + schema/applied-accounting · B2 CGC-F13 + e2e (≤10 gated) + POS-path mimic · B3 D2.G-ingestion dry-run + `POS_READINESS_CHECKLIST.md` (819 pass/31 skip; **F15 AMBER**) | [`IV_POS_8_D2_E_SPEC.md`](IV_POS_8_D2_E_SPEC.md) · [`composer/D2E_B1_B3_COMPOSER_REPORT.md`](./composer/D2E_B1_B3_COMPOSER_REPORT.md) · [`POS_READINESS_CHECKLIST.md`](./POS_READINESS_CHECKLIST.md) |
| **3** | **D2.F** POS dispatch | 📝 SPEC LOCKED (v1.0) — ready for B1 | B1 `generate_d2f_manifests.py` (driven by `variants.py`) + F.1 N=100 smoke-gate (8 jobs) · B2 F.2 N=10000 tail (4 variants × R=3, **fresh V5 per F15**) auto-chained via `chain_dispatcher.sh` across 8 reserved nodes | [`IV_POS_8_D2_F_SPEC.md`](IV_POS_8_D2_F_SPEC.md) |
| **4** | **D2.G** territory analysis + propagation filter + Pro report | ⛔ TO WRITE | B1 metrics/CSVs · B2 propagation filter + scores · B3 report+notebook+D3 sketch | `IV_POS_8_D2_G_SPEC.md` (TBD) |
| **5** | D1.E reward-rewire (V5-only) | 💤 DRAFT, demoted/optional | B0–B4 (see spec) | [`IV_POS_8_D1_E_SPEC.md`](./IV_POS_8_D1_E_SPEC.md) |
| future | pure-A4 mechanism batch | 💤 future | TBD | `IV_POS_9_A4_BATCH_SPEC.md` (TBD) |
| future | multi-guest suite | 💤 future | TBD | `IV_POS_8_MULTIGUEST_SPEC.md` (TBD) |
| future | D3 bug-isolation / repair | 💤 future | TBD | `IV_POS_8_D3_DESIGN_PROPOSAL.md` (TBD) |

Legend: ✅ done · 🔧 in finalization · 📝 spec locked (ready for build) · ⛔ spec to write · 💤 deferred/future.

**Governing context docs:** [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) (D2 master plan, predates ProG_Report_4 — reconcile its Q3/Q4 archive-reuse stance with Pro's "modernized V6-uniform re-run"), [`IV_POS_8_NOTES_FOR_PRO.md`](./IV_POS_8_NOTES_FOR_PRO.md) (NFP-1..11), [`separate-planning/central-planning-1.md`](./separate-planning/central-planning-1.md) (done-state + flags).

---

## 7. Open items for Ivan (post–Phase 0)
1. **Confirm this phase ordering** (esp. Bernoulli floor as a discrete Phase 2 vs folded into D2.D).
2. **Spec authoring order:** Opus drafts D2.C Batch 1 kickoff next; then write the Bernoulli + D2.D + D2.E specs (Phase 2–3 can pipeline). Confirm who drafts each (D1 vs D2 pair).
3. **N decision:** N=6000 only, or also N=10000 for V6-cTS/Hybrid? (compute tradeoff).
4. ✅ **RESOLVED (Ivan, 2026-06-19): V6-uniform = fresh POS re-run** with `v6_uniform_driver.py` (R2 archive = historical reference only) — locked in §1.
5. ✅ **RESOLVED (2026-06-19): Phase 0 complete** — D2.C v0.5 LOCK; companion doc sweep done (excluding `separate-planning/`).

*This master is updated as specs are written/locked and batches land. Each spec, when created, links back here; each batch links to its spec.*
