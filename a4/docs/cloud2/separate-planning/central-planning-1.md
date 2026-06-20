# Central Planning Doc 1 — IV.POS.8 (cloud2)

> **OWNERSHIP NOTICE.** This document is maintained **exclusively by Claude (the central-planning assistant, "Opus-CP")**. No other agent (Cursor Opus, Composer, ChatGPT Pro) writes here. Ivan directs; Opus-CP writes. This is the single chronological source of truth for *what has been done, what it found, where it lives, and what it implies* for the architecture and for `ProG_Report_3.md` goals.
>
> **Purpose.** (1) Understand everything in this repo relevant to completing the goals in `ProG_Report_3.md`. (2) Organize it so it can be presented to ChatGPT Pro without missing critical details. (3) Stay current as Pro responds and work continues.
>
> **⟶ 2026-06-19: Pro responded → `ProG_Report_4.md` is now the governing requirements doc, and `../New_Master.md` is the authoritative FORWARD plan (Phase 0–5: lock+build D2.C → Bernoulli floor → 4-variant checkpoint → territory analysis → decide D1.E).** This doc (central-planning-1) is now the **backward-looking** companion: the record of what's DONE + the ⚑ flag ledger. For "what to do next," see `New_Master.md`.
>
> **How to read this doc.** §0–§5 are the *stable framing* (the map). §6 onward is the *chronological deep-dive*, one section per sub-deliverable, filled in incrementally as Ivan + Opus-CP walk through the work. Each deep-dive section records: scope, what was implemented, what was found (results), implications for variants/architecture/Pro-goals, and a pointer index to every relevant doc / notebook / DB / CSV.
>
> **Status of this doc:** FOUNDATION DONE + **all IMPLEMENTED deliverables covered: D1.A / D1.B / D1.C / D2.A / D2.B**. Last updated by Opus-CP. Walkthrough coverage: foundation docs ✓; §6.1 D1.A ✓; §6.2 D1.B ✓; §6.3 D1.C ✓; §6B.1 D2.A ✓; §6B.2 D2.B ✓. **Specs covered: D1.E (v0.2.1) + D2.C (v0.3, re-read fresh).** Integration planning → `separate-planning/integration-d1e-d2c.md`. **Pro check-in package DRAFTED → `a4/docs/cloud2/IV_POS_8_PRO_CHECKIN.md`** (synthesis + self-contained definitions + scope/caveats + **8 decisions for Pro**, incl. accept-signal/no-op (Q4), multi-guest sequencing for the 4-variant comparison (Q7), and semantic-mapping soundness (Q8); §4.1 states Ivan's immediate-next-experiment = the V6-uniform/V6-cTS/Hybrid-cTS/V5 comparison + the constraint-space-advantage hypothesis). Packaging: render Pro-facing docs to PDF-with-figures (integration doc §C.3b). Ivan confirmed: NOT giving Pro the central doc. Check-in doc refined (2026-06-19): V6-cTS kind-set→11 (F10); §1.8 mappings for Q8; §2.1 adaptive-vs-floor reframing. **D1-pair feedback round (2026-06-19):** verified each item against source — applied S1/S2/S3/S4 + nits N1–N5 (post-1.5e baseline scoping, D1.E confound disclosure, decayexp-only d_loc tail, open (a)/(b) singleton framing, etc.); **pushed back on S5** (feedback geometrically wrong — `host_ecall`/`user_dynamic` ARE in the D8 user band; `ecall_dispatch` is at 0xFFFF1000). Surfaced F11; **F11 RESOLVED by Ivan — send ONLY the check-in, drop the briefing** (both pairs concurred); D1-pair conceded the S5 pushback (my framing was correct). **Next: assemble the upload (`IV_POS_8_PRO_CHECKIN.md` + NOTES_FOR_PRO + 3 subsections + D2.B mechanism report + D1.E/D2.C specs + figures/notebook PDFs) → send to Pro → await `ProG_Report_4`.** D2-pair reviewed the check-in (2026-06-19): applied A1/A2/A3/H1/B1/C1/C2/B2/F1 + E1/E3/E4 (verified each vs source), pushed back where right (L172→§2 not §16). D2.C now v0.4 (V6-cTS=11 fixed → F10 resolved). Flags: OPEN F3/F4/F5/F9; PROVISIONALLY-RESOLVED F6/F7 (gate D2.C commit, incl. the v0.4 V6-cTS fix); RESOLVED F1/F2/F8/F10/F11. **⟶ ProG_Report_4 LANDED (2026-06-19); [`../New_Master.md`](../New_Master.md) is now the forward plan (Phase 0–5); this doc = backward-looking companion. D2-pair reviewed New_Master → I verified + fixed stale spots here: V6-cTS=4→11 (line ~165), D2.C status→v0.4/two-tier (~148), and the stale "~95% no-ops" claim (~509 → corrected to ~5% skip / ~91.6% productive per F7). Locked V6-uniform=fresh re-run; bannered D2_PLAN as superseded; pushed back on Composer's "New_Master refs v0.15" (it doesn't).**

---

## ⚑ Open flags & watchlist (LIVE — Opus-CP)

> Running list of inconsistencies, unanswered questions, and things to verify as the walkthrough proceeds. **Each flag is removed (moved to "Resolved" with a one-line outcome) once answered by a later doc/code/Ivan.** If any remain at the end, they are real loose ends to chase before presenting to Pro. Format: `[Fn] <where raised> — <the question/concern>`.

**OPEN:**
- **[F3]** (raised D1.B §6.2; updated D1.C §6.3) — The decayexp **+2.5% AUC** advantage is borderline (n=5, significance flips across CGC variants), flagged as a likely K=50 cold-start artifact. *Genuinely open until D1.E's K≈200–300 forward-run.* **Update from D1.C:** decay vs static now has a MUCH stronger differentiator — `singleton_failure_rate` (decay ~22% lower, p~10⁻⁶) + higher `d_loc_p95`. So decay *does* alter mutation behavior (fewer singletons / more cascades); whether that's good or bad (and whether the AUC hint is real) is the D1.E question. Possible link to Pro's cascade concern (§4/§6).
- **[F4]** (raised D1.B §6.2) — Final-D1-report-assembly action item: the **frozen D1.A subsection still carries the buggy ~186 CGC numbers** (it was deliberately not re-run). D1.B's corrected ~218 supersedes them, but the D1.A doc itself has no correction footnote. *Ensure the Stage-4 final D1 report footnotes/reconciles this so Pro isn't shown two different CGC baselines without explanation.*
- **[F5]** (raised D1.C §6.3, LOW/cosmetic) — `D1C_AUDIT_REPORT.md` header is dated **2026-06-08**, contradicting git (`3a8487c` D1.C = 06-17) and every other D1.C doc. Almost certainly a typo (08↔17). Harmless to results. *Worth a one-char fix if that doc is ever touched.*
- **[F12]** (raised reviewing D2.C Batch 3 kickoff, 2026-06-19; campaign-fairness, Phase 3/D2.F) — **The KEEP-437-arms ruling (D2.C ISS-2) gives V6-cTS a ~22% cold-start tax at N=6000 that V6-uniform does NOT pay.** Code-verified: `cold_start_pulls_per_arm=3` × 437 FULL arms = **1311 cold-start (applied) pulls ≈ 22% of N=6000** (V5: 144 = 2.4%; V6-uniform = balanced round-robin over *kinds*, no arm-cold-start). So an N=6000 `V6-uniform vs V6-cTS` comparison is **asymmetric** — V6-cTS "wastes" ~22% of budget cold-starting arms the uniform baseline never has to. This *upgrades* Pro's N=10000-for-cTS-variants suggestion (§3 Phase 3) from "if compute is cheap" to a **fairness requirement** (at N=10000 the tax drops to ~13%). KEEP-437 itself is fine + Pro-aligned (don't reduce). *Action: New_Master Phase 3 / §7.3 N-decision should reflect this — run N=10000 for V6-cTS + Hybrid-cTS, or explicitly report the cold-start dilution in D2.G. Not a Batch-3 blocker; a Phase-3 campaign-design item.*
- **[F13] ⛔ BLOCKER — D2.C Batch 3 CGC root-caused (2026-06-20, reviewing B3 reports).** D2-opus/composer's diagnosis of empty `compressed_global_coverage` on the Arguzz path ("Hook 3 silent on the local --inject binary / POS binary may differ / Arguzz variants have no CGC channel = analysis-scope limitation") is **WRONG. It is a 1-line env-config bug.** Source proof: Hook-3 family-residue **capture** (`ffi.cpp:228/246`, `extern_memoryDelta`/`extern_lookupDelta`) only populates `g_a4_memory_records`/`g_a4_lookup_records` when `A4_FAMILY_RESIDUE && (A4_MUTATION_CONFIG || A4_COVERAGE_TOUCH)`; **emission** (`ffi.cpp:462`) requires those vectors non-empty; `mod.rs:146-150` shows `A4_COVERAGE_TOUCH` also forces the SeqForward mode emission needs. The new path sets **only** `A4_FAMILY_RESIDUE=1` (`fuzzer.py:1157`, `v6_uniform_driver.py:160`) — omitting the co-trigger `A4_COVERAGE_TOUCH=1` → capture off + parallel mode → zero residues → empty CGC. (`<constraint_fail>` DID emit because `arguzz_invoke` sets `CONSTRAINT_CONTINUE=1` — so the binary IS the modified build, hooks present.) **Disproof of "Arguzz has no CGC channel":** the R2 archive `pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000` (same `--inject` path) has **412 CGC rows + 41,785 global_failures over 6000 muts.** **Fix:** add `"A4_COVERAGE_TOUCH":"1"` to the Arguzz env (best: default inside the ISS-9 bridge entry point) — NOT `A4_MUTATION_CONFIG` (would double-mutate). Verify with a **≤10-mutation LOCAL** run that CGC populates BEFORE any POS spend. **Implications:** V6-cTS/V6-uniform/Hybrid `g_new` reward + D2.G CGC-territory comparison are LIVE once fixed. **Batch-4 kickoff task 4.4 line 80 ("if empty → Arguzz has no CGC channel") must be deleted**; its ISS-9 env (line 68) is still incomplete. → composer should STOP and fix before acting on ISS-8. Flip when env fix lands + local ≤10 run shows non-empty CGC. Side effect: A4_COVERAGE_TOUCH forces sequential mode (slower) — matches R2; budget for it in D2.F. Related: [[F12]]. **✅ RESOLVED (D2.C Batch 4, independently verified 2026-06-20): fix landed as `arguzz_bridge.DEFAULT_ARGUZZ_SUBPROCESS_ENV = {"A4_FAMILY_RESIDUE":"1","A4_COVERAGE_TOUCH":"1"}` centralized in the bridge; CGC now populates (POS eval 88 CGC / 387 gf; local `SMOKE_NUM=10` → 16/54). ISS-8 reclassified as config-bug (not analysis-scope limitation); the false "Arguzz has no CGC channel" branch deleted.**
- **[F14]** (raised authoring D2.D spec, 2026-06-20; cross-spec coordination, HIGH) — **D2.D pre-builds the L1-logging substrate that D1.E's spec assumed it would build.** D1.E (`IV_POS_8_D1_E_SPEC.md` v0.2.1) is **spec-only / never built** (verified: no `bandit_success_l1`, `l1_signals.py`, or d_loc_le_2/singleton/substrategy extractors exist in code as of today). D2.D needs the *logging* half NOW (Pro Q3: "log L1 in fresh runs, inactive") for the V6/Hybrid checkpoint, so D2.D B3 ships: `a4/standalone/l1_signals.py` (the 3 extractors + `composite_substrategy_key`, ported from `bug_proximity.py:57-249`), the `reward_counterfactuals.bandit_success_l1` column + 3 individual flag columns, and the `record_full_telemetry` plumbing — all **observe-only** (bandit reward path untouched; `success=` to `update_with_outcome` stays the base `compute_bandit_success(l,g,s)`). **D1.E (if it runs, Phase 5) must be updated to REUSE this substrate and build only: (a) activation (feed enriched bit to the bandit), (b) the opposite-saturation guard (post-local mean ≤0.75 on [3000,6000)), (c) the K/epoch decay config.** Without this update, D1.E and D2.D would duplicate/conflict on `fuzzer.py:1198-1500`, `reward_v2.compute_bandit_success`, `coverage_db.reward_counterfactuals`, `telemetry_v2.record_full_telemetry`. *Action: tell the D1 pair before they implement D1.E; the signal *definitions* are stable (locked from D1.C), only the *activation* design is still open in D1.E.* Related: [[F13]]. **🟡 UPDATE (D2.D complete, verified 2026-06-20): the logging substrate is BUILT — `l1_signals.py` (port manually verified against `bug_proximity.py`), the 4 `reward_counterfactuals` L1 columns (idempotent migration), observe-only wiring with a genuine inactivity proof (`test_decisions_unchanged_with_l1_on_vs_off`). Residual ISS-DD-1: the cross-check test is circular (compares the port to inline copies, not `bug_proximity` — un-importable due to a relative `.metrics` import); LOW risk (port verified, bug_proximity frozen, L1 observe-only) — D2.E Gate E re-audit will cross-validate logged columns vs offline recompute (closes it). Pending action unchanged: update the D1.E spec to REUSE this substrate (activation-only).**
- **[F15]** (raised authoring D2.E spec, 2026-06-20; pre-POS comparability, HIGH) — **The reused R2 V5 archive may be schema-incompatible with the fresh V6/Hybrid DBs, breaking D2.G's cross-variant comparison.** The R2 V5 archive predates the `mutations.outcome` column, write-time loc normalization, the D2.D L1 columns, and possibly the `A4_COVERAGE_TOUCH` CGC env — i.e. the **same** parity concern that already forced `V6_uniform` to be a FRESH POS re-run instead of archive reuse (New_Master §1, Ivan-locked). But `V5_control` is **still** archive reuse. If the V5 archive lacks comparability-critical columns, D2.G can't put V5 on the same footing as the fresh variants. *Action: D2.E Gate B (Batch 1 first task) dumps the V5 archive schema vs a fresh DB; if incompatible, escalate to Ivan — **fresh V5 re-run vs a documented V5-archive adapter — decided BEFORE D2.F dispatches POS.** Don't paper over it.* Related: [[F12]] (both are D2.F campaign-design items). **✅ RESOLVED → FRESH V5 RE-RUN (Opus-CP decision in D2.F §2, per Ivan's delegation, 2026-06-20). Verified myself: R2 V5 archive has NO `mutations.outcome`, NO L1 columns (has loc+CGC 183/15062). Decision rationale: consistency with the V6_uniform fresh-precedent; N moved to 10000 (archive comparability moot); D2.G needs `outcome` for V5's applied-pull/skip/channel metrics; V5 fresh = identical decisions (golden-trace-protected) + richer telemetry, so Pro's "don't change the deployed baseline behavior" is honored. Archive → historical reference. D2.F treats all 4 variants as fresh N=10000.**
- **[F16]** (raised authoring D2.F spec, 2026-06-20; POS operational, HIGH) — **An N=10000 V5/A4 job runs ~8.2h (measured: archive 6000 muts in 4h55m = ~2.95 s/mut, sequential mode forced by `A4_COVERAGE_TOUCH`), which EXCEEDS a typical 6-hr POS reservation block** → the job would be killed at the boundary, wasting ~8h. V6/Arguzz ~6.8h (~2.46 s/mut). Batch wall-time is V5-gated ~8.5h; R=3 = 2 batches ≈ 17h unattended. *Action: the reservation per node must cover the full batch (contiguous/merged blocks, POS_PLAYBOOK §12.49); confirm with Ivan before D2.F Phase B. Sequential mode is non-negotiable (required for CGC/F13).* Related: [[F12]]. **🟢 DOWNGRADED → MANAGED (Ivan, 2026-06-20): SSH-bypass `chain_dispatcher` launches detached `nohup` jobs that SURVIVE reservation expiry — the calendar window governs node access/holding, not job survival. Ivan reserves a 12h window + re-reserves every 6h to keep the 8 nodes held contiguously. So the ~17h multi-batch campaign runs fine as long as the rolling reservation prevents the nodes being reclaimed/reset. F16 is now an operational note (hold the nodes), not a job-kill risk.**
- **[F17]** (raised authoring D2.F spec, 2026-06-20; POS pre-flight, HIGH) — **The POS bundle must contain the D2.C/D2.D/D2.E/Bernoulli code, but ALL of it is uncommitted in the working tree.** If the bundle is built via `git archive HEAD` it ships STALE code → the entire ~17h campaign is invalid (no v6_cTS/hybrid CLI, no Bernoulli, no CGC env fix, no L1 logging). *Action: D2.F pre-flight gate — commit the D2.x + Bernoulli work (or build the bundle from the working tree), then grep the extracted bundle for `bernoulli_floor` / `v6_cTS` in cli choices / `DEFAULT_ARGUZZ_SUBPROCESS_ENV` / `l1_signals` before dispatch. This is the single most likely way to silently waste the whole campaign.* Related: [[F13]] (the CGC env fix is part of what must be in the bundle). **✅ HANDLED (2026-06-20): Ivan committed (`507397b`); F.1 bundle `a4_campaign_da2e1393078c.tar.gz` verified to contain all four symbols. Composer's F.1 gate tool greps the bundle.**
- **[F18]** (found deep-diving D2.F F.1 DBs, 2026-06-20; D2.G design note, NOT a campaign blocker) — **`V6_uniform`'s telemetry is sparse: `mutation_rewards` / `reward_counterfactuals` / `mutation_substrategy` / `bandit_decisions` are ALL empty** (verified in the F.1 N=100 DB). The `v6_uniform_driver` round-robin path writes only `mutations` + `failures` + `coverage` + `compressed_global_coverage` — it does not compute the fuzzer's reward stack. The other 3 variants (V5/V6_cTS/Hybrid, all fuzzer-path) have all tables populated. **Why it's fine:** V6_uniform has no bandit, so reward_counterfactuals/L1/substrategy/bandit_decisions are inherently N/A; and the CORE checkpoint comparison (Pro §Phase4: territory loc + CGC + outcome + applied-pull + skip + accepted-candidates via `verifier_accepted=1`/`config_json.soundness_signal`) is fully supported for V6_uniform. **D2.G action:** derive V6_uniform's comparable proximity signals (`d_loc` = distinct (loc,major,minor) per mutation; `singleton_failure` = 1-failure-row) from the **`failures` table offline**, NOT from `mutation_rewards` (empty); treat `d_glob` / `substrategy_uniqueness` / per-channel reward as cTS-variant-internal diagnostics (not cross-variant). **Do NOT modify the driver to add reward telemetry before the campaign** (code+behavioral risk for secondary diagnostics; territory comparison doesn't need it). Note: D2.E Gate B was schema-level (tables present) so it didn't flag this population gap; caught here. Related: [[F15]] (V6_uniform/V5 both fresh; this is V6_uniform's intrinsic driver-vs-fuzzer telemetry asymmetry).
- **[F19]** (found deep-diving F.1 smoke accepts, 2026-06-20; analysis-validity + D2.G, MED — NOT a bug) — **The raw "accepted" (verifier_accepted=1) rate is high and V6_cTS (8/100) ≫ V6_uniform (2/100), but this is fully explained — no bug.** (a) **The Q4 fault-propagation triage filter does NOT exist in code** (verified: no `accepted_noop`/`propagated`/`triage` impl in `a4/standalone/` or analysis tree). It's a **D2.G/Phase-4 deliverable, not yet built** — so all accepts are RAW `prover_status="success"` (flagged `soundness_signal=true` in config_json), mostly no-ops / valid-alternate-executions, NOT genuine soundness candidates. The high raw rate is EXPECTED for un-triaged Arguzz fault injection. (b) **The asymmetry is a sampling artifact:** classification is identical (driver `v6_uniform_driver.py:207` + fuzzer `fuzzer.py:1161` both `prover_status=="success"`, same `parse_prover_status`). V6_cTS cold-start = round-robin over 437 **arms** (sorted) → at N=100 reaches only ~5 alphabetically-early kinds, dominated by **INSTR_WORD_MOD = 57/100** (always-applicable → most arms; instruction-word mutations frequently yield valid-alternate executions → high accept); all 8 accepts are INSTR_WORD_MOD. V6_uniform round-robins over 11 **kinds** → INSTR_WORD_MOD only 13/100. Same kind, ~same per-kind accept rate (~8–14%); counts differ only by sampling weight. (c) **N=100 smoke is unrepresentative**: all pulls `mode=cold` (cold-start needs 1311), adaptive/floor never engage; only 5 of 11 kinds sampled. (d) **Meaningful contrast (thesis, not bug):** V5 (A4) = **0** accepts (single-cell mutations are inconsistent-by-construction → caught) vs V6 (Arguzz) = 2–9 (coherent faults → accepted); cross-check: ~87% of V6 faults ARE rejected with failures → injection works. **D2.G actions:** (1) BUILD the Q4 triage filter (the accepts are meaningless raw — rerun candidates w/ `--trace`/`A4_FAMILY_RESIDUE=1` per ISS-1, since Arguzz records 0/0 placeholder values so no-op detection needs reruns); (2) the **arm-weighting (V6_cTS) vs kind-weighting (V6_uniform) confound** means they sample different fault distributions — compare on **territory / per-kind**, not raw accept counts; (3) watch whether adaptive (post-cold-start, N>1311) down-weights the high-arm-count/low-yield INSTR_WORD_MOD — a real cTS-value test; (4) CGC `cycle_phase` collapsed to 1 value on V6_uniform at N=100 — re-check at N=10000 for a D1-style dead dimension. Related: [[F13]] (CGC), ISS-1 (fault-corroboration). **🔬 REPRODUCED + TRIAGED (2026-06-20): re-ran all 8 V6_cTS INSTR_WORD_MOD accepts locally (correct seeds from config_json) with `--trace` + baseline trace-hash comparison. Result: fault IS genuinely injected every time (fault tags, word changed e.g. step174 `0x73→0x173`); ALL 8 reproduce as `prover_status=success` locally (→ NO POS-vs-local binary discrepancy; local `workspace/output/...risc0-host` matches POS). Triage: **5/8 pure NO-OPS** (trace byte-identical to baseline — mutation hit semantically-inert bits, e.g. ECALL's rd field which dispatch ignores) + **3/8 PROPAGATED** (trace differs, full-length, still verifies) + **0/8 genuine soundness candidates.** All commit output `3735928559=0xDEADBEEF` — a SENTINEL, so output-equality is uninformative; the **trace hash is the real no-op signal.** Conclusion: the high raw accept rate = no-ops + valid-alternate executions, ZERO real bugs at N=100 — confirming bugs are hard to find AND that the raw `soundness_signal=true` flag is set on benign accepts. **The D2.G triage filter = exactly this trace-vs-baseline test** (discard trace-identical no-ops; deeper-check the propagated ones for trace-validity). Not built. Not a campaign blocker (data correct), but the raw soundness_signal count must NOT be reported as candidates pre-triage.**
- **[F20]** (found reviewing D2.G B1 artifacts, 2026-06-20; analysis bug + F18-extension, MED — analysis-only, production DBs OK) — **The fuzzer writes a MINIMAL `config_json` (`{kind,step,pre_post,opcode_class,seed,soundness_signal}`) while the v6_uniform DRIVER writes a RICH one (adds `prover_status`,`host_panic`,`rc`,`instruction`,`zone`,`major`,`wall_s`,`iter_seed`).** This is an extension of [[F18]] (driver-vs-fuzzer telemetry asymmetry) into `config_json`. **Concrete bug it caused:** D2.G `rejection_channels.py:30-33` labels a skip `C5` only if `config["host_panic"]` or `config["prover_status"]=="start"` — present in driver config, ABSENT in fuzzer config → **all V6_cTS/Hybrid C5 skips mislabeled `skipped_other`** (V6_cTS showed C5=0, skipped_other=4-6; V6_uniform correctly C5=4). Since `outcome='skipped'` arises ONLY from `start+panic` in `arguzz_invoke._classify_outcome`, `skipped ⟺ C5` for the Arguzz path → **fix: map C5 from `outcome='skipped'` alone, never from driver-only config fields.** **General rule for D2.G:** classify channels/signals from `outcome` + `failures`/`global_failures` COLUMNS, not from `config_json` fields only the driver populates. Fix `rejection_channels.py` before B3 (the C1/C2/C5 split is a Phase-4 deliverable + feeds the Pro report). Spec §5 updated. Other B1/B2 artifacts verified consistent (triage↔accepted counts match; CGC-collapse correctly flagged V6_uniform cycle_phase=1; territory sensible). Triage code (`propagation_triage.py`) verified GENUINE (real trace-digest-vs-baseline, not hardcoded; oracle 5/3/0 PASS is real). Related: [[F18]], [[F19]].
- **[F21]** (Composer's 3-candidate investigation + my verification, 2026-06-20; triage-filter correctness, MED) — **The full-trace-hash triage OVER-classifies; Composer's proposed PC-only fix UNDER-classifies. The correct rule is semantics-aware (control-flow OR data-flow).** Composer investigated the 3 "propagated" smoke accepts (2726/1648/3939) and found the trace-hash differs only at the inject-step `assembly` string. **Composer is RIGHT on 2726/1648** (branches: `beq …,72`→`…,104` — target-only immediate change, condition/registers unchanged, **post-inject PC identical** → not-taken → cosmetic → genuine no-op). **Composer is WRONG on 3939** (store `sw t2,4(t1)`→`sw t2,6(t1)` — offset changed → **different (unaligned) memory address written** = "later memory transaction sequence changed", a Pro Q4 propagation signal). PC-identical ≠ no-op for a store, because the coarse trace (`{step,pc,instruction,assembly}`, no reg/mem values) + sentinel-only output (`0xDEADBEEF`, no usable final-state digest — **verified by rerun**) hides data-flow. **Composer's PC-only fix (exclude `assembly`) is DANGEROUS — it would blind the filter to ALL data-only divergences (store/load offsets, ALU results, register writes with intact control flow) — the most subtle soundness-bug class.** **Corrected oracle: 7 noop / 1 propagated (3939) / 0 hidden** (not Composer's 8/0/0, not the original full-hash 5/3/0). **Fix (spec §3.1, LOCKED):** classify propagated iff (post-inject PC sequence differs) OR (inject-step disasm changed AND the instr is store/load/compute, not a not-taken branch); flag `unaligned_access` on 3939 for D3. **3939 is most likely a benign valid-alternate, but that's D3's call to confirm — the triage must SURFACE it, not assume.** Also agree w/ Composer: relabel campaign log `BUG!`→`ACCEPTED` (it = verifier_accepted, misleading). Related: [[F19]] (sentinel output), ISS-1. **🔄 RESOLVED via Composer counter-pushback + my re-verification (2026-06-20): CONVERGED on EVIDENCE TIERS.** Composer's epistemic critique is FAIR and conceded: I overstated "verified memory-transaction divergence" — we OBSERVE the store's used operand changed (offset 4→6, corroborated by the `<fault>` tag `word:X=>word:Y` + disassembly) and DEDUCE (ISA) a different write, but did NOT observe downstream propagation (post-inject trace + sentinel output identical). So 3939 is a **WEAK** candidate (data-instruction used-operand change, no observed downstream), not a strong/verified one. **Adopted Composer's tiers (spec §3.1): `strong` (post-inject PC/trace differs) / `weak` (inject-step data-instruction operand change, used field) / `cosmetic` (inject-step control-transfer target on not-taken branch, unused field).** Oracle stays **7/1/0** but framed as a **filter-contract** (surfaces 1 weak candidate), NOT "1 verified propagation." **BUT pushed back on two Composer over-corrections: (1) its "8/0/0 is honest" UNDER-classifies** — 3939's mutated field IS used (ISA-certain different write) unlike the not-taken branch's unused target, so dismissing it as no-op is the data-corruption-with-intact-control-flow blind spot; surface it (weak), don't drop it. **(2) Composer's "zero `<fault>` tags / F19 not reproducible" is FACTUALLY WRONG** — the `--trace` rerun emits `<fault>{"step":174,...,"info":"word:115 => word:371"}` (=0x73→0x173, exactly F19); Composer conflated the campaign `--inject`-only log (correctly tagless per ISS-1) with a `--trace` rerun. **Net: both half-right; converged on tiered surfacing. Concede `unaligned_access` is a deduced label not an observed trap. 3939 → D3 low-priority queue.** Forward impact: §3.1 improved (tiers added), oracle framing corrected to filter-contract; no campaign/architecture change.
- **[F22] ⭐ Deep-dive resolution of the 3939 "candidate" (Ivan pushed for 100% certainty, 2026-06-20; triage-correctness + key harness behavior) — 3939 is a TRUE NO-OP, NOT a soundness bug. Ivan's instinct ("the error must be bypassed by our hooks") was EXACTLY right.** Traced through the rv32im circuit + executor:
  1. **The trace-comparison machinery is VALIDATED** (positive/negative controls: identical→same hash, dropped-record→different, divergent-reject→different). No false negatives.
  2. **The faulted 3939 proof genuinely VERIFIES** — there's a real `Verifier` record `status=success` (not just "Prover completed") + 0 `<constraint_fail>`.
  3. **Circuit fact:** `OpSW` (`inst_mem.zir:158-163`) REQUIRES word alignment (`low0=0 AND low1=0`); `AddrDecomposeBits` pins `low1`=bit-1 of the address — so an offset-6 store *should* violate it.
  4. **Resolution (executor code):** `rv32im.rs:994` — the `StoreAddressMisaligned` trap for SW is **gated `&& !self.fault_inj_ctx.is_injection_enabled()`** → **the misalign trap is DISABLED during fault injection** (Ivan's hook-bypass hypothesis, confirmed). AND `ByteAddr.waddr() = addr/4` (`addr.rs:35`) **truncates the low 2 bits**, and the store writes to `addr.waddr()` (`rv32im.rs:1019`). So `sw t2,6(t1)` writes word `(t1+6)/4 = w+1` = **the SAME word** as `sw t2,4(t1)` `(t1+4)/4 = w+1`, with the same data (rs2). **Byte-identical memory → true no-op → identical execution → proof verifies trivially.** No error because (a) trap bypassed by the harness, (b) word-truncation collapses offset 6 → offset 4's word.
  5. **I was WRONG (F21) to call 3939 a `weak propagated_candidate`** — the disassembly byte-offset changed but the WORD address didn't (`6>>2 == 4>>2`). **Composer's original 8/0/0 (all no-ops) was correct.** Corrected oracle: **8 noop / 0 propagated / 0 hidden** (3939 = `word_truncated` no-op). Spec §3.1 fixed: for store/load, classify on the **word address (`offset>>2`)**, not the byte offset — within-word change = no-op; cross-word change = propagated; this needs no register values (same base reg).
  6. **The underlying triage issue Ivan sensed:** the disassembly-based propagation heuristic over-classified within-word store-offset changes. Now fixed (word-address-aware).
  7. **Key documented harness behavior:** the fault-injection build disables misalign traps (SH `rv32im.rs:984`, SW `:994`) → misaligned-address INSTR_WORD_MOD faults don't trap; combined with word-truncation they're largely no-ops. This explains a CLASS of no-op accepts — D2.G/D3 must account for it. NOT a soundness bug (the proof attests to a valid word-truncated execution). Related: [[F19]], [[F21]], ISS-1.
- **[F9]** (raised during D1.E/D2.C re-read, 2026-06-19; first-real-use risk) — **`applied_accounting_mode` has NEVER run in any real campaign.** Code-verified: it appears only in `bandit_ts.py` (scaffolded in D2.A), never in `fuzzer.py` — every run to date (V5, D1.A, D2.B) had it OFF. Its first production use is D2.C/D2.D's V6-cTS/Hybrid-cTS runs (Batch 3 wires it on). Only the D2.A synthetic unit test has exercised it. *Low severity (F7 shows V6 skips only ~5%, so it rarely fires), but it's a load-bearing accounting path going live untested — warrants an explicit smoke gate when D2.C/D2.D run. Not a doc inconsistency; a deployment risk.*

**PROVISIONALLY RESOLVED** *(fixed in D2.C working-tree v0.2 draft, NOT yet committed to HEAD — re-verify after D2.C lock+commit):*
- **[F6→PROVISIONALLY RESOLVED]** (D2 pair, 2026-06-19) D2.C v0.2 working-tree draft corrects the ArmKey citation to `semantic_arm_universe.py:174-182` (changelog line 31, §3.2 line 240, §3.5 line 291, §13 line 1056; notes `bandit_ts.py` imports it on line 25). *Becomes fully RESOLVED when D2.C is locked + committed.*
- **[F7→PROVISIONALLY RESOLVED — MAJOR CORRECTION, see below]** (D2 pair, 2026-06-19) The "94.6% panic" was a **classifier artifact** of `v6_driver_v2.py:479` checking `host_panic ("panicked at" in stdout)` BEFORE `prover_status`. Corrected cross-tab on `pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000.db`: **94.6% APPLIED total** (NOT no-ops) = **91.6% APPLIED+REJECTED** (5497/6000: 65.9% Path-A prover-ran-then-panicked + 23.4% Path-B global-error-no-local-tags — the V6 analog of D2.B `at_write`) + **2.95% APPLIED+ACCEPTED** (177 soundness candidates) + 0.07% other; **only ~5.2% true SKIPPED** (314 true C5 pre-prover crashes) + 0.07% timeout. **→ The V6/Arguzz surface is HIGHLY PRODUCTIVE (~91.6% positive bandit signal), NOT ~95% no-ops.** D2.C v0.2 working draft corrects §5.5/§6.2/§6.3, redefines C5 narrowly (prover_status="start" + host_panic only), and rewrites `_classify_outcome` to a prover_status-primary tree (Q4 Option C) flagging Path-B rows `failure_recording_gap=True`. *This is a substantive finding that reshapes D2.C integration (see §7 integration notes) — not merely a doc typo.*

**RESOLVED:**
- **[F10→RESOLVED by D2.C v0.4 + check-in edit, 2026-06-19]** The V6-cTS kind-set confound is fixed in the **D2.C spec (now v0.4, revised 2026-06-19)**: V6-cTS = all 11 Arguzz `ENABLED_KINDS` (`MUTATION_KINDS_ARGUZZ_FULL`); Hybrid-cTS = 4 selected (`MUTATION_KINDS_ARGUZZ_SELECTED`); arm-space estimates split per-variant (V6-cTS ~200–350, Hybrid ~160–240); §15.2 citation→§8 Track A; `pre_post` axis now both-sided. Check-in §1.2/§1.4/§4 updated to match. The earlier §6 hedge (saying "the spec still shows 4") was removed as now-stale. *(D2.C v0.4 still DRAFT pending scoped Composer review on this change axis, then LOCK — so the underlying "D2.C not yet committed" caveat that gates F6/F7 also gates the final commit of this fix.)*
- **[D2-pair review of check-in, 2026-06-19 → APPLIED/PUSHED-BACK]** Verified all 12 items against source: applied A1/H1 (§15.2/§15.3 don't exist→§8 Track A / Priority 3), A2 (Hybrid-4 vs the 4 *excluded* A4-name-duplicates — distinct sets), A3/C2 (two-tier kind framing), B1 (~23%→**~25.6% of APPLIED+REJECTED**, 1407/5497), C1 (~150–230→V6-cTS ~200–350 / Hybrid ~160–240, both locations), B2 (C5 wording), F1 (94.6% APPLIED ≠ rewarded — coverage-based reward, untested; same softening as the D1.A adaptive fix), + optional E1/E3/E4. **L172 (§13 catalog-ceiling): I verified independently — the verbatim phrase "A4's mutation catalog is now the ceiling" is in §2 (line 32), so I cited §2, NOT the review's suggested §16 (less precise).** Stale-string sweep clean.
- **[F11→RESOLVED by Ivan 2026-06-19]** Two overlapping Pro-facing D1 syntheses existed (my `IV_POS_8_PRO_CHECKIN.md` + the D1-pair's `runs/iv_pos_8/d1/IV_POS_8_PRE_D1E_BRIEFING_FOR_PRO.md` v0.3). **Decision: send ONLY the check-in;** the pre-D1.E briefing is dropped from Pro's package and kept as an internal historical artifact. Both pairs concurred. (The check-in's committed 7-entry page_class — matching `D1B_SUBSECTION.md` — is the canonical layout Pro sees; the briefing's 9-entry version doesn't reach Pro.)
- **[S5 (D1-pair feedback item)→Opus-CP pushback UPHELD]** D1 pair conceded: `host_ecall`/`user_dynamic` page_classes ARE inside the D8 `user` band `[0x10000,0xBFFF0000)`; the D8 `ecall_dispatch` region is at `0xFFFF1000` (a *different* concept that shares the "ecall" substring). The check-in's "carve of the user band" framing was correct; tightened with the band range. *(Logged because Ivan asked me to track verify-and-pushback outcomes.)*
- **[F1→RESOLVED by D1.B]** D1.A's ~186 CGC numbers are buggy-pre-NFP-10; D1.B's post-hoc replay gives the corrected V5 hybrid CGC ≈ **218.2**. Superseded, not footnoted-in-place (D1.A frozen). Local headline unaffected. *(Residual assembly action = [F4].)*
- **[F2→RESOLVED by live-code check]** HEAD has the byte_addr fix (`compressed_global_extractor.py:222` = `("byte_addr","addr","address")`) AND `_TXN_ROLE_BY_KIND` coexisting — clean, no conflict.
- **[F8→RESOLVED at `dfd0ebe` (D2.B-PS-2)]** (D2 pair, 2026-06-19) `_TXN_ROLE_BY_KIND` remapped to Pro-valid roles: `CYCLE_DIFF_COUNT_MOD "diff_count"→"read"`, `TXN_ADDR_MOD "addr"→"read"`, `TXN_CYCLE_PHASE_MOD "cycle_phase"→"read"`; contract test extended to all 11 live kinds (regression guard); CYCLE_DIFF_COUNT_MOD xfail removed; campaign-smoke 3-kind allowlist removed. Tests on affected slice 168→**173 passed, 0 xfailed**; broader suite 616 passed. **Two corrections to my F8 write-up:** (1) precise drift count was **2 dead-registry + 1 LIVE** (`CYCLE_DIFF_COUNT_MOD` was the only one actively contaminating live CGC data), not "all three dead." (2) **NFP-4's stated mitigation is weaker than written:** `producer_kind` exists ONLY in `GlobalLookupCtx` (lookup rows u8/u16/cycle), NOT in `GlobalMemoryCtx` where `txn_role` lives — so for MEMORY rows the per-kind disambiguator is a SQL JOIN `compressed_global_coverage.first_hit_mutation_id → mutations.kind`, and the bad `"diff_count"` value really *did* land in memory `ctx_json` with no co-located disambiguator (drift was contained, not "masked by producer_kind"). NFP-4 decision text unchanged (it was correct; only the code had drifted); footnote added pointing to PS-2.

---

## 0. Conventions & legend

- **A4** = Ivan's framework: **post-execution trace mutation**. Runs the guest once, then mutates the *witness/preflight trace* before witgen, then checks whether the prover/verifier rejects. Surgical, single-cell, witness-layer.
- **Arguzz** = the prior research paper (arXiv 2509.10819): **during-execution mutation** of RISC-V instructions/registers/memory/PC/branches; the VM then naturally propagates consequences. Found 11 bugs across 6 zkVMs incl. a $50k RISC Zero bounty. In our variant naming, Arguzz ≈ **V6-uniform**.
- **POS** = the compute cluster / dispatch infrastructure Ivan runs campaigns on (8 nodes; ~5.5h per N=6000 job).
- **R2** = the previous IV.POS.7 round of results (the "round 2" archive of V0–V6 DBs). Frozen baseline.
- **Pro** = ChatGPT Pro (OpenAI research-grade model). Provides high-level strategic guidance. Latest = `ProG_Report_3.md`.
- **Composer** = the implementation LLM paired with Cursor-Opus per work-stream (D1 pair, D2 pair).
- **N** = number of mutations per campaign (headline runs use N=6000).
- **mut / mutation_id** = index of a mutation within a campaign.
- **loc / constraint_loc** = a circuit constraint location (normalized form `Name@basename:line`).
- **CGC** = Compressed Global Context — a bucketed key for global (cross-row) constraint residues (memory permutation / lookup arguments), used as a reward-discovery signal.
- **cTS** = constrained Thompson Sampling (the V5 scheduler family).
- **The work tree:** `a4/standalone/` = production fuzzer code (self-contained). `a4/runs/iv_pos_X/` = campaign outputs + analysis. `a4/docs/cloud2/` = specs & planning. `a4/docs/cloud2/composer/` = granular per-batch implementation docs. `workspace/risc0-modified/` = the patched RISC Zero (Rust witgen hooks).

---

## 1. The big picture (the research thesis)

**Goal:** design a new fuzzing framework that **beats Arguzz at finding soundness bugs** in the RISC Zero zkVM.

- **Soundness bug endpoint:** `invalid semantic execution + proof ACCEPTED`.
- **Completeness/overconstraint endpoint:** `valid semantic execution + proof REJECTED`.
- A4 mostly produces *invalid witnesses* and checks whether constraints reject. Single-cell invalid witnesses almost always reject → so **local constraint coverage is a SURVEY metric, not a BUG metric** (Pro §5).

**The two mutation surfaces, contrasted (Pro §3–4):**

| | A4 (post-execution trace) | Arguzz (during-execution) |
|---|---|---|
| Surface | witness/preflight trace cells | live register/memory/PC/branch state |
| Timing | after exec, before witgen | during exec |
| Coherence | single-cell, internally inconsistent by construction | rest of trace produced by exec *after* the fault → naturally coherent |
| Interstep-fire rate | ~23% | ~55% (more multi-cycle cascades) |
| Strength | reaches witness/proof-internal structures Arguzz can't | natural coherence → better for *accepted-invalid* discovery |

**Pro's headline verdict (ProG_Report_3, the single most important doc):**
> V5 is a real architectural improvement, but NOT yet evidence that post-execution trace fuzzing broadly beats Arguzz. V5 = "a circuit-aware constrained exploration scheduler with a small adaptive tail." It wins on **A4-native witness-trace territory**; Arguzz wins on **total terrain** because A4's *mutation catalog is the ceiling*. Next move = **hybridization + bug-isolation machinery**, not more V5-only tuning.

Key empirical facts Pro is reacting to (from the prior round):
- V5 reached **46.4** mean final legacy constraint locations vs V1's **42.9**; time-to-43 in **1017** muts vs V1's **4366**; found 4 novel kernel/ECALL locations V1 missed.
- V5 is **floor-dominated**: ~5615 floor pulls, 233 adaptive, 144 cold, 8 singleton per seed. The MAB/posterior is currently *secondary*; the load-bearing pieces are the semantic arm space `(kind, zone)`, the floor schedule, and explicit boundary/kernel/ECALL zones.
- V6/Arguzz raw count **108.0** vs V5's **46.4** — but unfair: V6 runs 11 kinds (7 V6-only), ~79% of pulls on kinds A4 can't use. On the **51-loc A4-reachable union**: V5 covers **50/51**, V1 **46/51**, V6 only **20/51**. V6 surfaces **105 V6-exclusive** locations A4 can't reach. → **ceiling is kind-set-limited, not budget-limited.**

---

## 2. Pro's guidance (`ProG_Report_3.md`) — the goal scaffold

**Two-mode architecture Pro prescribes:**
- **Mode A — survey / cartography:** maximize semantic constraint coverage, discover new locs/CGCs/zones, learn co-failure structure. *V5 is good here.*
- **Mode B — isolation / repair / bug search:** take a discovered region, minimize/repair co-failures until the invalid witness is accepted, or rejected by a tiny interpretable set, or proven unpromising. **This is the most important MISSING layer.**

**The metric stack Pro wants (§5):** exploration metrics (local_context_final, AUC, time_to_threshold, v2 breadth/depth, CGC bucketed, kind×zone entropy, new-region discovery) + **bug-proximity** (verifier_accepted_invalid_count, d_loc/d_glob minima, singleton-failure rate, co-failure degree, repairability, near-acceptance frontier) + **isolation** (per-target min co-failure set, alone-count, repairs) + **fair-Arguzz** (coverage on common/A4-only/Arguzz-only territory, wall-clock per normalized discovery, **applied** mutation count not attempted, accepted-invalid per hour, unique *mechanisms* not just locs).

**Pro's §15 priority order (Pro's own ranking):**
1. **Hybrid V7** — V5 scheduler + selected V6 kinds + applied-mutation accounting + normalized telemetry. Compare V5 / V6-uniform / V6-cTS / Hybrid-cTS. 10 paired seeds, N=6000.
2. **Bug-isolation layer** — co-failure graph + repair templates + minimization loop.
3. **Pure-A4 mutation expansion** — TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, TXN_CYCLE_PHASE_MOD, CYCLE_PC_MOD.
4. **Decaying-floor V5** — static vs decay vs two-stage (don't just sweep floor_fraction).
5. **Multi-guest suite** — stock SHA, ECALL/MRET, control-flow, memory-stress, accelerator.

**Pro's catalog priorities:**
- Arguzz kinds to import (§8 Track A / §15.2): INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND, POST_EXEC_REG_MOD, POST_EXEC_MEM_MOD, POST_EXEC_PC_MOD — integrated as **V5 arms**, not a separate uniform scheduler, with **arm = surface × kind × zone × opcode_class × pre/post**.
- Pure-A4 kinds (§8 Track B): TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, TXN_CYCLE_PHASE_MOD, CYCLE_PC_MOD, CYCLE_STATE_MOD, TXN_ADDR_MOD, CYCLE_DIFF_COUNT_MOD.

**The four variants Pro wants compared (§9):**
- `V6-uniform` = current Arguzz scheduler (balanced round-robin).
- `V6-cTS` = Arguzz kinds only, selected by constrained TS over kind×zone×opcode_class×pre/post.
- `Hybrid-cTS` = A4-V5 kinds + selected Arguzz kinds in one shared arm space. **The likely winning endpoint architecture.**
- `V5` = control.
- Primary comparisons: V6-uniform vs V6-cTS (does feedback improve Arguzz?); V5 vs Hybrid-cTS (does importing terrain help A4 without losing native edge?); V6-uniform vs Hybrid-cTS (can the final architecture beat standard Arguzz?).

**Pro's "big question" answer (§16):** Pure single-cell post-execution fuzzing *probably won't broadly beat Arguzz*. But **structured post-execution witness fuzzing can beat Arguzz in regions Arguzz can't reach** (memory permutation metadata, prev_word, prev_cycle, cycle-state, machine_mode, lookup residues, accelerator/BigInt/Poseidon/SHA state, recursion metadata). Highest-probability path = `V5 scheduler + Arguzz kinds + A4 witness-internal kinds + semantic feedback + co-failure minimization/repair + normalized fair eval`. The next proof point should be: *"Hybrid-cTS finds more normalized constraint mechanisms and more near-acceptance/accepted-invalid candidates per wall-clock hour than standard Arguzz."*

**Other Pro asks:** decaying-floor V5 (§7, with staged schedule survey→adaptive→isolation); coarser CGC (§11, drop log2 dominance); parallel-execution noise (§12, keep default parallelism + 10+ seeds); multi-guest (§13, don't overfit the current 3930-step trace).

---

## 3. The deliverable hierarchy & status board

Ivan's plan deliberately **does NOT follow Pro's §15 order verbatim** — D1 front-loads the smaller asks + metric infrastructure so Hybrid V7 (D2) can be evaluated on the right axes, and gives Pro a fast feedback loop. (See `IV_POS_8_PRELIMINARY_PLAN.md` §1.)

| Deliv | Theme | Maps to Pro | Status |
|---|---|---|---|
| **D1** | Housekeeping + scheduler tuning + D2 design | Priority 4 + smaller asks §6/§7/§11/§12 | In progress (D1.A–C done; D1.E draft) |
| **D2** | **Hybrid V7 headline** | Priority 1 + 3 | In progress (D2.A–B done; D2.C draft) |
| **D3** | Bug-isolation layer | Priority 2 | Sketch only |
| **D4** | Multi-guest cross-validation | Priority 5 | Sketch only |

**Workflow pattern:** each deliverable ships to Pro with (1) results of completed work + (2) the design proposal for the next, so Pro reacts to both and can steer before weeks are sunk.

### 3.1 D1 sub-deliverables (governed by `IV_POS_8_D1_REVISIT_PLAN.md` v0.6)

| Sub | Scope | Status | Key result (one line) |
|---|---|---|---|
| **D1.A** | V5 decaying-floor variant (§7), new `FloorSchedule` abstraction; V5-static vs decayexp vs decayepoch | **FROZEN** (Findings A–F) | Decay does NOT separate from V5-static under sparse binary reward (paired p>0.62); scheduler geometry only supports ~3 mode regimes; reward saturates ~mut 3000–3500 *before* floor decay matters |
| **D1.B** | CGC coarsening variants (§11): region_only / log4_explicit / page_class; analysis-only | DONE (`71dae77`) | **Saturation inversion** — coarsenings saturate 1400–1900 mut EARLIER than local; only `production_log2_corrected` has post-local headroom. Surfaced **NFP-10** byte_addr bug |
| **D1.C** | Bug-proximity metric stack (§5); analysis-only | DONE (`3a8487c`) | 3 Tier-1 L1 OR-channel signals pass orthogonality+non-saturation: `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`. Pro's `f_new>0` is empirically DEAD on V5 |
| **D1.E** | V5 reward-rewired re-run (wire D1.B L0 + D1.C L1, retune K/epoch, re-run 15 jobs) | **DRAFT v0.2.1** (awaiting Ivan greenlight) | Causal test: does enriched reward give decay a discriminating gradient? |
| D1.D | D2 design proposal | **Superseded** by `IV_POS_8_D2_PLAN.md` | Kept as ~1-pg D1→D2 hand-off in final report |

D1 sequence: D1.A frozen → D1.B → D1.C → **[SYNC: wait for D2.B Batch 1.5e]** → D1.E → Stage 4 final D1 report (`a4/runs/iv_pos_8/d1/IV_POS_8_D1_REPORT_FOR_PRO.md`, not yet assembled).

### 3.2 D2 sub-deliverables (governed by `IV_POS_8_D2_PLAN.md` — not yet fully read by Opus-CP)

| Sub | Scope | Status |
|---|---|---|
| **D2.A** | Foundation: 5-tuple `ArmKey`, `MutationOutcome` enum, normalized telemetry, `mutations.outcome` column, applied accounting | **DONE** (`7b66fb9`) |
| **D2.B** | Pure-A4 kind expansion (Pro's 8 kinds) | **DONE / closed** (`78d036c`→Batch4 `2e1d97b`→PS-1 `e2c2256`→**PS-2 `dfd0ebe`**); 3 LIVE + 5 dead arms (NFP-11); NFP-4 doc↔code alignment landed at PS-2 (F8) |
| **D2.C** | V6/Arguzz integration: two-tier Arguzz kinds (V6-cTS=**11**, Hybrid=**4**) into bandit arm space + modernized V6-uniform driver (fresh re-run) | **v0.5 LOCKED** (Phase 0 done: S5→`_PRE_POST_BY_KIND`, baseline→616/17/0); **Batch 1 IN PROGRESS** (Composer, 2026-06-20). *Full D2.C write-up here pending completion.* |
| **D2.D** | Variant CLI / fuzzer dispatch (V5_control / V5_expanded / V6-uniform / V6-cTS / Hybrid-cTS) | Spec'd, not started |
| **D2.E** | Integration tests | Spec'd |
| **D2.F** | POS dispatch for 4-variant campaigns | Spec'd |
| **D2.G** | Cross-variant statistical analysis (consumes D1.C metrics) | Spec'd |

**⛳ IMPLEMENTATION BOUNDARY (confirmed by Ivan 2026-06-19): D2.B is the LAST fully-implemented deliverable.** Everything implemented & committed: D1.A, D1.B, D1.C, D2.A, D2.B. **D1.E and D2.C are SPEC-ONLY DRAFTS — NOT implemented** (no code written, no campaigns run). They are the two "next big things" (the *combination* points pulling many components together), held pending Pro's architectural read. After D2.B we review these two specs and Ivan asks questions about them.

### 3.3 The variants, defined precisely (the moving pieces Ivan must shape)

| Variant | Scheduler | Kind set | Surface(s) | Notes |
|---|---|---|---|---|
| V1 | kind-only cTS (b1/cTS V1) | 8 A4 kinds | A4_trace_cell | prior-round baseline scheduler family |
| V2 | unconstrained UCB | — | A4 | diagnostic; collapsed onto INSTR_WORD_MOD_SUR |
| V3, V4 | discovery-reward / TS | A4 | A4 | diagnostic "survey-depth" variants; not production. Kept as corpus generators |
| **V5** | constrained TS over `(kind, zone)`, floor-dominated | 8 A4 kinds (now 11 post-D2.B) | A4_trace_cell | the architectural win; Mode-A engine |
| **V6-uniform** (=Arguzz) | balanced round-robin | 11 Arguzz kinds | arguzz_exec_fault | the faithful Arguzz baseline |
| **V6-cTS** | constrained TS | **11 Arguzz kinds** (all `ENABLED_KINDS` — same set as V6-uniform; corrected per ProG_Report_4/F10) | arguzz_exec_fault | "does our feedback improve Arguzz?" (scheduler-only ablation) |
| **Hybrid-cTS** (=Hybrid V7) | constrained TS, shared 5-tuple arm space | 11 A4 + 4 Arguzz = 15 effective | both | **the candidate winning endpoint** |

Post-D2.B the A4 trace-cell arm space = **11 LIVE kinds** (8 V5 + 3 D2.B-live). The 5 dead D2.B kinds were removed from `MUTATION_KINDS`. Arguzz adds 4 → **15 effective mutation kinds** for Hybrid V7.

---

## 4. Document & artifact map (where everything lives)

> This index grows as we walk through each sub-deliverable. Paths are repo-relative.

### 4.1 Top-level planning & spec docs (`a4/docs/cloud2/`)
| File | Role |
|---|---|
| `ProG_Report_3.md` | **Pro's latest guidance — the goal scaffold.** Read in full. |
| `IV_POS_8_PRELIMINARY_PLAN.md` | Ivan's initial 4-deliverable plan (D1–D4). Partly superseded (D1.E re-added, D1.D superseded). |
| `IV_POS_8_D1_REVISIT_PLAN.md` (v0.6) | Current D1 structure: D1.B + D1.C + D1.E + final assembly; the D1↔D2 sync point. |
| `IV_POS_8_NOTES_FOR_PRO.md` | **Running architectural-decision log (NFP-1..11).** Pro reads this before deliverable reports. See §5 below. |
| `IV_POS_8_D1_A_SPEC.md` | D1.A spec (FROZEN deliverable). |
| `IV_POS_8_D1_B_SPEC.md` | D1.B spec. |
| `IV_POS_8_D1_C_SPEC.md` | D1.C spec. |
| `IV_POS_8_D1_E_SPEC.md` (v0.2.1) | D1.E spec (draft, awaiting greenlight). |
| `IV_POS_8_D2_PLAN.md` | Master D2 plan (D2.A–G). *Not yet fully read by Opus-CP.* |
| `IV_POS_8_D2_A_SPEC.md` | D2.A spec (LOCKED; merged `7b66fb9`). |
| `IV_POS_8_D2_B_SPEC.md` (v0.5.4) | D2.B spec (LOCKED; closed `e2c2256`). |
| `IV_POS_8_D2_B_MECHANISM_REPORT.md` | Pro-facing W-17/W-18 dead-arm proofs + 4-channel rejection model. |
| `IV_POS_8_D2_C_SPEC.md` (v0.2) | D2.C spec (draft). |
| `composer/` | Granular per-batch implementation kickoffs/reports (see per-section indices). |
| `separate-planning/central-planning-1.md` | **This document.** |

### 4.2 Run outputs (`a4/runs/`)
| Path | Contents |
|---|---|
| `a4/runs/iv_pos_7/` | R2 archive (V0–V6 DBs), drivers (incl. frozen `drivers/v6_driver_v2.py`), analysis (`bug_proximity.py` lives here). |
| `a4/runs/iv_pos_8/d1a/` | D1.A: 10 DBs (5 decayexp + 5 decayepoch, seeds 1234–1238), `D1A_SUBSECTION.md` (frozen findings), notebook+html, `d1a_metrics_table.csv`, `d1a_paired_tests.csv`, `d1a_floor_dynamics.csv`, plots, analysis scripts. |
| `a4/runs/iv_pos_8/d1b/` | D1.B: analysis, plots, replay_artifacts, hand-off docs (`d1e_handoff_CGC_saturation.md`, `d1b_recommendation.md`, `D1B_SUBSECTION.md`, `d1b_page_class_layout.md`). |
| `a4/runs/iv_pos_8/d1c/` | D1.C: analysis, plots, hand-off docs (`d1e_handoff_L1_signals.md`, `d1c_signal_shortlist.md`, `D1C_SUBSECTION.md`, `d1c_tier2_schema.md`, `d1c_batch1_tier1_audit.csv`). |
| `a4/runs/iv_pos_8/d1/` | (reserved) final D1 report assembly. |

### 4.3 Production code (`a4/standalone/` unless noted)
| File | Role (as of foundation read; verify line numbers when touching) |
|---|---|
| `bandit_ts.py` | cTS scheduler, `ArmKey`, `MutationOutcome`, `FloorSchedule` family (`ConstantFloor`/`ExponentialDecayFloor`/`EpochStageFloor`), `_floor_target` quota math. |
| `reward_v2.py` | `compute_bandit_success` (sparse binary composite), `compute_reward`, counterfactuals. |
| `fuzzer.py` | A4Fuzzer: `_create_mutation` dispatch, reward call sites, telemetry write. |
| `coverage_db.py` | `CoverageDB` schema + record APIs (`mutations`, `failures`, `coverage`, `compressed_global_coverage`, `mutation_rewards`, `reward_counterfactuals`). |
| `semantic_arm_universe.py` | `SemanticArmUniverse.build()` — arm construction. |
| `compressed_global_extractor.py` | CGC extraction (`_coerce_broken_addr` byte_addr fix = NFP-10; `_TXN_ROLE_BY_KIND`). |
| `zone_classifier.py`, `semantic_zones.py` | zone classification. |
| `telemetry_v2.py` | telemetry write path, `extract_mutation_substrategy`. |
| `mutations/*.py` | per-A4-kind mutation modules. |
| `a4/arguzz_dependent/arguzz_runner.py` / `arguzz_parser.py` | legacy/partly-adopted Arguzz invocation + fault parsing. |
| `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` | frozen reference V6-uniform driver (608 lines). |
| `workspace/risc0-modified/.../witgen/mod.rs` | Rust mutation hooks + `A4_DUMP_POST_MUT=1` (NFP-5). |

### 4.4 Loose DBs at repo root
Many ad-hoc `.db` files at repo root (`a4_*.db`, `bandit_16_*.db`, `uniform_baseline_1000.db`, `phase*.db`, etc.) — these appear to be older/ad-hoc experiment outputs. *To be triaged when relevant; not yet linked to a sub-deliverable.*

---

## 5. NFP architectural-decision index (`IV_POS_8_NOTES_FOR_PRO.md`)

These are the load-bearing decisions Pro must understand. Summarized; full text in the NFP doc.

| NFP | Decision | Why it matters |
|---|---|---|
| **1** | ArmKey 2-tuple→5-tuple `(surface,kind,zone,opcode_class,pre_post)`; kept `ArmKey.v5()` back-compat | Enables Hybrid arms; preserves V5 archive byte-identity (saves recompute). |
| **2** | D2.B implements all 8 Pro pure-A4 kinds; variants filter via subsets | Without filtering, registry expansion breaks D1.A archive comparability. |
| **3** | `TXN_PREV_WORD_MOD` = single kind, RNG-picks strategy (at_read/at_write) per pull | Smallest arm footprint; bandit sees aggregate reward only (tradeoff). |
| **4** | D2.B CGC maps to Pro-valid `txn_role`s; per-kind analytics pivot on `producer_kind` (lookup rows) or JOIN `mutations.kind` (memory rows). **[code aligned at PS-2 `dfd0ebe`, F8]** | Avoids schema bump; finer roles deferred. *Correction: `producer_kind` is ONLY in `GlobalLookupCtx`, not `GlobalMemoryCtx` — memory per-kind needs a JOIN, not co-located field.* |
| **5** | Layer-3 attestation needs new Rust `A4_DUMP_POST_MUT=1` hook | Without it, "100% certainty" dead-arm claim would be false. |
| **6** | `PRE_EXEC_REG_MOD` retrofix (Batch 1.5e): RNG-picks next_read/prev_write | Half the surface was dead (hardcoded next_read). **Alters V5 baseline → D1.E sync gate.** Landed `78d036c`. |
| **7** | D1.B `page_class` is OUR concrete def (ELF-derived semantic memory-use class), a substantive substitution of Pro's vague "page_class" hint | Pro must confirm/correct in R3. ELF-mandatory derivation; per-guest. |
| **8** | D1.B paired-test corpus = V5-static + decay only (20 rows); V1 excluded from decay tests | V1 is a different scheduler family; would confound. |
| **9** | D1.E rewires reward at **L0 (CGC bucketing) + L1 (OR-channel) only**; K stays anchored to `_local_discoveries` per Pro §7 | L2 scalar bandit deferred. `f_new>0` empirically dead on V5 (2026-06-17 update). |
| **10** | **Hook 3 `addr` vs `byte_addr` bug** — production CGC memory regions mis-labeled (53–59% mismatch) across ALL R2 V1-V5 + D1.A; fixed in extractor; post-hoc replay corrects archives | R2 memory-CGC counts understated ~10–20%, per-region distributions wrong. V5>V1 direction preserved. Pro's `page_class` still valid. |
| **11** | D2.B: of 8 kinds, **3 LIVE** (TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_DIFF_COUNT_MOD) + **5 dead** (W-17 set_cycle overwrite; W-18 execution-derived witness keys) | A4 catalog ceiling narrower than hoped. Dead arms removed from MUTATION_KINDS (`e2c2256`). NOT a soundness bug. |

---

## 6. Chronological deep-dives

> **True chronology (by commit date; the D1 and D2 LLM pairs ran in PARALLEL so the streams interleave):**
> 1. D1.A batches 1+2 — `1db0e88` (06-16)
> 2. **D2.A batches 1+2 — `b844e8e`+`7b66fb9` (06-16)** ← interleaved, between D1.A's work and its freeze
> 3. D1.A frozen — `4fce664` (06-16)
> 4. D1.B — `71dae77` (06-17)
> 5. D1.C — `3a8487c` (06-17)
> 6. D2.B batches — `78d036c`→`e2c2256` (06-18)
> 7. [not yet built] D2.C draft, D1.E draft
>
> **Walkthrough order (Opus-CP, by Ivan's "all D1 then all D2" preference — NOT strict chronology):** D1.A ✓ → D1.B ✓ → **D1.C** → D2.A → D2.B → [drafts]. Note: D2.A predates D1.B/D1.C chronologically; we cover it under the D2 block for narrative coherence (it's the Hybrid-V7 arm-shape foundation, a different stream from the D1 analysis trilogy).

### 6.1 D1.A — V5 decaying-floor variant  *(FROZEN / CLOSED-FOR-NOW)*

**Status:** FROZEN 2026-06-17 (interim — explicitly NOT yet final for Pro). Will be revisited as "D1.A-bis" once D1.E lands. Git commit at freeze: `4fce6649`. Spec: `IV_POS_8_D1_A_SPEC.md` (LOCKED). Maps to **Pro Priority 4** (decaying-floor V5) + Pro §7.

#### Scope & the hypothesis under test
Pro §7 said V5's static 55% floor "is not a bug" but warned against leaving it frozen, and proposed two decay schedules (exponential `floor=max(0.20, 0.55·exp(-d/K))`; epoch-staged `[0.55, 0.35, 0.20]`). D1.A built both and compared **V5-static vs V5-decayexp vs V5-decayepoch** at N=6000 on paired seeds.

**The narrow hypothesis being tested:** *"V5's 96% floor share is too aggressive and is starving productive TS exploitation"* — i.e., would letting the floor decay (handing more decisions to adaptive Thompson sampling) discover more constraint locations?

#### What was implemented
- **`FloorSchedule` abstraction** in `bandit_ts.py` (verified in code at lines 68–118): base class + `ConstantFloor(0.55)` (back-compat default), `ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)`, `EpochStageFloor(stages=[(0,0.55),(2000,0.35),(4000,0.20)])`.
- `ConstrainedTSScheduler` gained `floor_schedule` param + `_local_discoveries` counter + `update_local_coverage(n)` setter. `_floor_target()` now reads the schedule. Back-compat: `floor_schedule=None` → `ConstantFloor(coverage_floor_fraction)` → byte-identical to legacy V5 (golden-trace verified).
- **6-site fuzzer patch** (`CTS_SEMANTIC_V2_FAMILY` frozenset replacing 6 hardcoded `== "cTS_semantic_v2"` checks) — Composer caught that decay variants would otherwise silently fall into the kind-only branch.
- **Discovery counter plumbing (Option B, faithful):** fuzzer accumulates `record_failures()`'s `new_coverage` return into `_local_loc_discoveries`, pushes to scheduler. This equals Pro's `local_coverage_seen` exactly (= `COUNT(*) FROM coverage` = `local_context_final` at end).
- **3 new nullable `mutations` columns** added for D1.C: `proof_generated`, `proof_verify_failed`, `elapsed_ms` (NULL on legacy R2 DBs). Floor config persisted in `campaign_params.extra_json`.
- `discover.py` SELECTOR_TO_VARIANT extended (longest-first to avoid substring collision: `cTS_semantic_v2_decayexp`→`V5-decayexp` etc.).

**Key scope decision:** V5-static baseline = **R2 archive reuse** (no re-run; `ConstantFloor(0.55)` is back-compat-identical, saves ~15 node-hours). Decay variants run fresh on POS.

#### Dataset (and the truncation)
| Variant | Seeds | Source |
|---|---|---|
| V5-static | 1234–1243 (10) | R2 archive `a4/runs/iv_pos_7/dbs/` |
| V5-decayexp | 1234–1238 (5) | `a4/runs/iv_pos_8/d1a/dbs/` |
| V5-decayepoch | 1234–1238 (5) | same |

Spec targeted 10 paired seeds × 2 decay variants (20 new DBs). **POS daemon failure** after the first 8-job dispatch truncated decay coverage to **5 paired triplets** (seeds 1234–1238); all 10 decay DBs recovered via SSH-bypass (POS_PLAYBOOK §12.52). Seeds 1239–1243 × decay were not dispatched (scope lock).

#### Headline results (n=5 paired triplets; from `d1a_build_summary.json` + `d1a_paired_tests.csv`)
| Metric | V5-static | V5-decayexp | V5-decayepoch |
|---|---|---|---|
| mean `local_context_final` | **46.40** | **46.20** | **46.40** |
| mean `compressed_global_context_final` | 186.2 | 186.0 | 188.0 |
| mean `auc_normalized` | 0.950 | 0.964 | 0.952 |
| mean `time_to_43` | 1146.2* | 828.0 | 1146.2 |
| mean `time_to_46` | 3221.2 | 1848.0 | 2932.2 |

*paired-subset n=5 value; n=10 static mean time_to_43 = 1017.1.

**Paired t-tests (`local_context_final`):** V5 vs decayexp **p=0.704**; V5 vs decayepoch **p=1.000** (mean diff exactly 0.0); decayexp vs decayepoch **p=0.621**. → **No statistically significant change on the saturated metric.** (Note the one positive trend: decayexp reaches threshold *faster* — time_to_46 1848 vs 3221, and AUC 0.964 vs 0.950, p=0.159 — but doesn't reach *more*.)

#### The six Findings (the real intellectual content — load-bearing for D1.E & Hybrid V7)
- **Finding A — K=50 saturates immediately.** Our fuzzer accrues ~150 local discoveries / 1000 muts, so `exp(-d/50)` hits `floor_min=0.20` almost at once → decayexp ≈ `ConstantFloor(0.20)` for the whole run. The *correct* K to land the single mode-transition in the saturation tail is **K ≈ 200–300** (K=200→transition at d=27; K=300→d=41). **K=500+ would never transition → ≡ V5-static** (an earlier draft's K=500 recommendation was wrong; corrected in audit).
- **Finding B — `bandit_decisions.extra_json` is NULL** (per-decision floor_fraction not persisted). Minor instrumentation gap.
- **Finding C — Mode sequence is seed-independent within a variant.** The cold/singleton/floor/adaptive *mode* per mutation_id is deterministic; seed only changes *which arm* is picked. Consequence: **decayepoch ≡ V5-static bit-identically through mut ~2049** (first divergence at the epoch boundary); since `local_context_final` saturates ~mut 2800, most coverage is inherited from the shared early phase → p=1.000 is structural cancellation, not zero per-seed effect (per-seed Δ ∈ {0,+1,+1,−2,0}).
- **Finding D — Scheduler mode space is discrete (~3 regimes), NOT a continuous gradient.** `_floor_target = floor_frac × epoch_size(100) / n_arms(48)`; `epoch_pulls` is integer, so only the integer crossings of `target` matter → **only ~3 effective regimes: ~0% / ~48% (1 pass) / ~96% (2 passes) floor.** Verified directly in code (`bandit_ts.py:180–187`). **Two big consequences:** (1) Pro's `[0.55,0.35,0.20]` collapses to a **2-tier** policy — the 0.35→0.20 boundary at mut=4000 is *mechanically invisible* (both → 48%). (2) Any continuous decay collapses to a single step transition. **Pro's intended "gradual decay" is not testable on this scheduler** without either (a) per-mutation Bernoulli sampling (`mode = floor with prob = floor_frac`, ~1-line change) or (b) a much larger arm count (→ Hybrid V7's expanded catalog gives finer quotas).
- **Finding E — Post-boundary discovery is empirically TIED (10 vs 10).** In mut[2000,6000) where decayepoch's lower floor diverges from static, both variants first-discovered **exactly 10 contexts** across 5 seeds. This *directly kills* the narrow hypothesis: the 96% floor is NOT starving exploitation.
- **Finding F — We only tested HALF of Pro §7 Stage 2 — THE most important caveat.** Pro §7 = decay schedule **+** richer TS reward signals (recent marginal discovery, low-cofailure, repairability, underexplored zones). D1.A implemented only the decay. The bandit still learns from the **sparse binary composite** `bandit_success = 1 if (l_new+g_new+s_new) > 0 else 0` (`reward_v2.py:60–62`) — one Bernoulli bit/pull. All three of l_new/g_new/s_new plateau together (local~46, CGC~186, structural saturated), so **adaptive mode loses arm-differentiation signal exactly when the decay hands it more decisions.** *The measured negative may be primarily a reward-signal-saturation result, not a schedule result.* (Note: `f_new` family-novelty is computed in `reward_v2.py` but NOT in the Bernoulli flag.)

#### Implications for the architecture & Pro-goals
1. **D1.A is the direct genesis of D1.E.** Finding F → "rewire the reward (L0 CGC + L1 OR-channels) and re-run" = the entire D1.E sub-deliverable. Findings A & D → D1.E's K retune (≈200–300) and 2-tier epoch boundary (`[(0,0.55),(1000,0.35)]`, dropping the no-op tier).
2. **Decay variants are NOT killed.** The negative is tightly scoped to (V5 catalog × sparse binary reward × integer-quota scheduler). They remain candidates for Hybrid V7 (larger arm count → Finding D relief) and for the enriched reward (Finding F). The frozen Verdict explicitly tells D2 designers: **keep decay in scope, do not drop it.**
3. **A latent scheduler-architecture lever for Pro:** per-mutation Bernoulli floor sampling would make mode-share linear in floor_frac and unlock true gradient decay — a high-leverage ~1-line change Pro should be told about.
3b. **Adaptive-vs-floor reframing (sharpened 2026-06-19, → Pro check-in §2.1):** decayexp handed adaptive ~13× more decision share yet the discovery **ceiling did not move** (only a non-sig trend toward reaching it *faster*). Consistent with Pro's "floor not posterior" read. **BUT (Ivan's 2026-06-19 check — important): "adaptive is ineffective" is TOO STRONG.** Three confounds mean adaptive was never fairly tested in D1.A: (1) Finding F — saturated reward → TS draws ≈uniform by construction (no-signal test); (2) NFP-10 broke the CGC channel (the later-saturating one where adaptive could've helped); (3) small ~48-arm space the floor already fully covers (regime where adaptive matters least). **Defensible claim:** in *that regime*, the floor set the ceiling and adaptive only accelerated. **NOT defensible:** "adaptive can't compensate for floor dilution" — D1.A gives no evidence either way (never had fair conditions). Conservative stance: don't *assume* adaptive rescues a thinned floor (keep mappings bounded/budget adequate) but don't claim it can't — D1.E + Hybrid + the NFP-10 fix are precisely the fair test (each removes one confound).
4. **CGC saturates much later than local** (~186 keys, time_to_46 at mut 3221 vs local saturation ~2800) — this is *why* D1.B/D1.E look to CGC and later-saturating signals to extend the discriminating window. (D1.B then found the saturation-inversion surprise — see §6.2.)
5. The frozen subsection is the template (FROZEN banner, "what this rules out / does NOT rule out", scope disclaimers) that D1.B/C/E subsections follow.

#### Open threads D1.A leaves for Pro / next steps
- Is the **per-mutation Bernoulli floor** worth doing before Hybrid V7? (Finding D.)
- Does the K≈200–300 + 2-tier-epoch + enriched-reward re-run (D1.E) actually separate decay from static? (The causal test D1.E exists to run.)
- `bandit_decisions.extra_json` instrumentation (Finding B) — fix before D2 if per-decision floor telemetry is wanted.

#### Artifact pointer index — D1.A
| Artifact | Path | Role |
|---|---|---|
| Spec | `a4/docs/cloud2/IV_POS_8_D1_A_SPEC.md` | LOCKED implementation spec |
| **Frozen findings (Pro-facing)** | `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` | TL;DR + Findings A–F + Verdict + Limitations. The key results doc. |
| Metrics table | `a4/runs/iv_pos_8/d1a/d1a_metrics_table.csv` | 20 rows (10 V5 + 5 decayexp + 5 decayepoch) |
| Paired tests | `a4/runs/iv_pos_8/d1a/d1a_paired_tests.csv` | 5 metrics × 3 comparisons |
| Floor dynamics | `a4/runs/iv_pos_8/d1a/d1a_floor_dynamics.csv` | per-variant per-time floor-mode share (225 rows) |
| Build summary | `a4/runs/iv_pos_8/d1a/d1a_build_summary.json` | headline numbers + git commit |
| Notebook | `a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb` (+ `.html`) | executed evidence |
| Plots | `a4/runs/iv_pos_8/d1a/plots/01–05_*.png` | floor curves, cumulative coverage, local_context_final, mode share, time-to-threshold |
| DBs (10) | `a4/runs/iv_pos_8/d1a/dbs/` | 5 decayexp + 5 decayepoch (seeds 1234–1238); V5-static DBs live in R2 archive `a4/runs/iv_pos_7/dbs/` |
| Analysis scripts | `a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py`, `build_d1a_notebook.py` | reuse R2 `metrics.py`/`stats.py` |
| Composer docs | `a4/docs/cloud2/composer/D1A_BATCH3_KICKOFF.md` (POS dispatch), `D1A_BATCH5_KICKOFF.md`, `D1A_BATCH5_REPORT.md` (analysis + frozen-state audit §12), `D1A_BATCH5_FOLLOWUP.md`, `D1A_BATCH5_TASK54_REFRESH.md` (n=5 refresh) | granular implementation/analysis |
| Code | `a4/standalone/bandit_ts.py` (FloorSchedule §68–118, `_floor_target` §180–187), `fuzzer.py` (6-site family patch), `coverage_db.py` (3 new cols) | production changes |

> **Caveat carried forward:** all D1.A `compressed_global_context_final` numbers (~186) predate the NFP-10 byte_addr fix and are subject to D1.B's post-hoc correction (corrected V5 hybrid CGC ≈ **218.2**). Local-channel numbers (local_context_final, the headline) are UNAFFECTED by NFP-10.

---

### 6.2 D1.B — CGC coarsening variants  *(DONE / FROZEN)*

**Status:** DONE; committed at `71dae77` ("Check d1.b"). Subsection still flagged INTERIM (pending Ivan+Opus review before final Pro fold-in). Analysis-only (no fuzzer re-runs). Spec: `IV_POS_8_D1_B_SPEC.md` v0.4.3 (LOCKED). Maps to **Pro §11** (coarser CGC) + smaller asks. Base commit when artifacts built: `4fce6649` (D1.A's), then squash-committed.

#### Scope & the question
Pro §11 complained that our production CGC reward is **geometric not semantic**: the `address_region="user"` band spans `[0x00010000, 0xBFFF0000)` (a ~3GB slab), so the only discriminator inside it is `address_bucket = floor(log2(addr))` — "different 64KB bin," not "different kind of memory." Pro suggested evaluating `region_only`, `log4`, and "maybe `page_class`." **D1.B's job:** evaluate coarsening variants on the existing 20-DB decay corpus and recommend the **D2-default CGC reward signal**. *Analysis-only, post-hoc — no re-runs.* Crucially, the D1.B → D1.E hand-off ALSO had to characterize each variant's **CGC saturation profile** (when does `g_new` stop discriminating) — because D1.A Finding F said the reward saturates before the floor decay matters, and the hope was a better CGC bucketing would extend the discriminating window (the "L0" lever).

**The 4 variants compared** (all on *corrected* memory labeling, see byte_addr bug below):
- `production_log2_corrected` — production scheme `(family, region, log2_bucket, txn_role, cycle_phase)` with the byte_addr fix. The baseline.
- `region_only` — `(family, address_region)` only. Coarsest.
- `log4_explicit` — `(family, region, floor(log2/2))`. Strictly coarser than production log2.
- `page_class` — `(family, page_class)` where page_class is an **ELF-derived semantic memory-use class** (our concrete definition of Pro's vague "page_class" → **NFP-7**).

#### The dominant discovery: the byte_addr bug (NFP-10)
Mid-implementation, the Batch 1 data audit found stored memory CGC `address_region` collapsed to just `{user, zero_page}` across all 30 audited DBs — despite `global_failures` showing rich geography. Root cause: `_coerce_broken_addr` in `compressed_global_extractor.py` checked fields in order `("addr", "byte_addr", "address")` and Hook 3 emits BOTH. `addr` = **circuit word address**; `byte_addr` = `addr×4` = **VM byte address** (the one `address_region()`/ELF layout are defined on). So the extractor fed *word* addresses into a *byte*-address region map → **53–59% of memory contexts mis-labeled** (Opus verified: V5 s1234 58.9%, V1 s1234 53.2%, decayexp s1234 55.7%; invariant `byte_addr == addr×4` holds 13670/13670 on V5 s1234). **One-line fix:** reorder to `("byte_addr", "addr", "address")`.
- **Scope of impact:** affects memory-CGC `address_region`/`address_bucket` for **EVERY R2 V1–V5 + D1.A DB**. UNAFFECTED: lookup families (use `_coerce_broken_index`), local channel/`local_context_final`, arms/scheduler, `f_new`, and Hook 3's own residue math (correctly uses `addr`).
- **Correction via post-hoc replay** (not re-dispatch): `hook3_raw` preserves raw payloads → `replay_cgc_corrected.py` reconstructs corrected CGC deterministically. Measured impact: V5 s1234 memory keys **89→117 (+31.5%)**, V1 s1234 69→72 (+4.3%), **mean memory Δ +20.7/DB**. Corrected baseline = the new comparison ground truth for all 4 variants (stored `ctx_json` is buggy-pre-fix, kept only for audit).
- **Methodology subtlety:** memory keys re-extracted through the patched extractor; lookup keys taken from `hook3_raw` runtime snapshot (patch-invariant; 0/30 mismatches = sanity check that lookup is unaffected).

#### page_class layout (NFP-7, ELF-derived, per-guest)
ELF-mandatory derivation (guest ELF sha256 `3e5082ad…`) + `memory.rs` constants + GLOSSARY HOST_ECALL. For sha2-host: `stack [0x10000,0x200800)`, `text [0x200800,0x219db8)`, `rodata [0x219db8,0x22133c)` (folds `.eh_frame` per Q-PC-EHF), `data_bss [0x22133c,0x221488)`, `heap [0x221488,0x42000000)`, `host_ecall [0x42000000,0x42000100)`, `user_dynamic [0x42000100,0xBFFF0000)` (Batch 1.5b: promoted the implicit `user_other` catch-all to a named class — 100% of the residual lived in this upper band; drops `user_other` to ~0%). Non-user/user_bigint regions pass through. **Per-guest** (changes with each guest binary) → D1.B ships a derivation recipe + provenance JSON, not magic numbers. Pro disclosure pending (Q-PC-4).

#### Headline results (corrected labeling; from `d1b_build_summary.json` + CSVs)
**Mean hybrid `cgc_final` (V5, n=10):** production_log2_corrected **218.2** | log4_explicit 120.6 | page_class 110.7 | region_only 105.7. **Memory-channel only (V5 mean):** production **122.0** | log4 24.4 | page_class 14.5 | region_only 9.5. (Sanity ordering `region_only ≤ log4 ≤ production` holds 20/20 on corrected labeling — it did NOT pre-fix, the "memory channel dead" was double-masked by bug + coarsening.)

**Paired decay tests on `cgc_final`:** all p>0.05 (no decay effect on final count). The full corrected hybrid count is ~218, vs D1.A's buggy ~186 — **resolves flag F1**.

#### THE headline finding: Saturation inversion + thin headroom (`d1b_saturation_profile.csv`)
| Variant | CGC saturation mut | Gap vs local sat (mean time_to_46 = 3221) | Keys remaining at mut 3221 |
|---|---|---|---|
| `production_log2_corrected` | **3400** | **+179** | ~39 (~1 key / 70 mut) |
| `log4_explicit` | 1800 | −1421 | ~18 |
| `page_class` | 1300 | −1921 | ~18 |
| `region_only` | 1300 | −1921 | ~18 |

- **Pro's §11 hypothesis is empirically INVERTED.** Coarsening was supposed to make `g_new` discriminate *longer* past local saturation. Instead, fewer keys → faster CGC saturation → **shorter** post-local window. Coarsened variants flatten ~1400–1900 muts *before* local saturates.
- **Thin headroom for ALL L0 candidates.** Even production's best-case post-local window is only +179 mut / ~39 keys (~1 new CGC key per 70 mut). **No L0 scheme provides robust long-window discrimination; production is merely "least-bad."** → **L0 schema-swap alone CANNOT solve D1.A Finding F** (reward saturation). D1.E must look *beyond* L0 bucketing.
- **decayexp AUC hint:** decayexp shows a barely-significant **+2.5% AUC** under coarsened variants (page_class p≈0.0481, region_only p≈0.0484; production p≈0.0588 — *just misses*). Honestly flagged as likely a **K=50 cold-start artifact** (floor hits floor_min by d≈7), not Pro's Stage-2 decay. D1.E forward-run with K≈200–300 is the real test. (Note: this is a *CGC* AUC, distinct from D1.A's *local-context* AUC 0.964 vs 0.950.)

#### Recommendation (`d1b_recommendation.md` / `d1e_handoff_CGC_saturation.md`)
| Decision | Outcome |
|---|---|
| D2 default CGC reward (L0) | **Keep `production_log2_corrected`** + byte_addr fix |
| L0 swap to `page_class`/coarsened | **REJECT** (saturation inversion) |
| L1 semantic enrichment | **OPEN D1.E design question** — naive OR `g_new_production OR g_new_page_class` is **redundant** (page_class first-hits collapse into production first-hits from the same live failure stream). D1.E should consider per-channel posteriors / weighted boost / multi-objective bandit, OR look beyond L0 to D1.C bug-proximity signals. |
| K (floor decay) | NOT driven by CGC — stays on `_local_discoveries` per Pro §7. D1.E characterizes it separately. |

#### Implications for architecture & Pro-goals
1. **D1.B redirected D1.E's whole strategy.** The pre-D1.B hypothesis (revisit plan v0.1–v0.5) was "swap CGC bucketing to extend the window." D1.B *empirically disproved* it (saturation inversion) → D1.E's L0 = keep production, and **L1 enrichment via D1.C's per-mutation signals became the primary lever** (not CGC coarsening, which is redundant). This is why D1.E's L1 ended up using `mutation_substrategy_uniqueness` / `d_loc_le_2_flag` / `singleton_failure_flag`, not a coarsened-CGC channel.
2. **NFP-10 forces R2-conclusion corrections to Pro.** R2 memory-CGC absolute counts were understated ~10–20% and per-region distributions wrong; **V5>V1 direction preserved**, AUC trends preserved. Pro's `page_class` recommendation stays valid (complementary to corrected `address_region`, not redundant). All cloud2 forward runs (D1.E, D2.*) use the patched extractor natively.
3. **For Hybrid V7 / D2:** the D2 reward CGC signal = `production_log2_corrected`. D2.C/D2.B inherit the patched extractor.
4. **Honest negative reinforced:** combined with D1.A, the picture is now "the reward signal saturates and neither floor-decay (D1.A) nor CGC-coarsening (D1.B) fixes it on the V5 catalog" → the case for richer per-mutation reward (D1.C/D1.E) and for Hybrid V7's larger arm space.

#### Artifact pointer index — D1.B
| Artifact | Path | Role |
|---|---|---|
| Spec | `a4/docs/cloud2/IV_POS_8_D1_B_SPEC.md` (v0.4.3) | LOCKED spec; heavy revision history re: byte_addr bug |
| **Subsection (Pro-facing)** | `a4/runs/iv_pos_8/d1b/D1B_SUBSECTION.md` | TL;DR + Findings A–C (corrected baseline, saturation inversion, decayexp AUC) + page_class disclosure |
| **D1.E hand-off (load-bearing)** | `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` | per-variant saturation; "L0 alone cannot solve Finding F"; L1 open |
| Recommendation | `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` | D2 default CGC = production_log2_corrected; reject page_class L0 |
| page_class layout | `a4/runs/iv_pos_8/d1b/d1b_page_class_layout.md` + `d1b_guest_elf_layout.json` | ELF-derived layout + provenance |
| Metrics / paired / saturation | `d1b_metrics_table.csv` (80 rows), `d1b_paired_tests.csv` (72 rows), `d1b_saturation_profile.csv` (4 rows), `d1b_build_summary.json` | results |
| byte_addr audit/replay | `d1b_batch1_data_audit.csv`, `d1b_batch1_replay_corrected.csv`, `replay_artifacts/` | NFP-10 evidence |
| Notebook / plots | `IV_POS_8_D1B_NOTEBOOK.ipynb`(+`.html`); `plots/cgc_curve_*.png` (4), `d1b_saturation_overlay_v5*.png`, `d1b_page_class_histogram.png` | evidence |
| Analysis code | `a4/runs/iv_pos_8/d1b/analysis/` (`build_d1b_artifacts.py`, `d1b_cgc_maps.py`, `replay_cgc_corrected.py`, `build_page_class_layout.py`); coarsening fns in `a4/runs/iv_pos_7/analysis/cgc_variants.py` | analysis-tree modules |
| Production code touched | `a4/standalone/compressed_global_extractor.py` (`_coerce_broken_addr` byte_addr fix = NFP-10; the ONLY production edit in D1.B) | + regression tests in `test_compressed_global_extractor.py` |
| Composer docs | `composer/D1B_BATCH1_REPORT.md` (+§9 byte_addr root cause), `D1B_BATCH1_5_REPORT.md` (page_class + user_dynamic), `D1B_BATCH2_REPORT.md` (analysis), `D1B_BATCH3_REPORT.md` (closure) | granular |

---

### 6.3 D1.C — Bug-proximity metric stack  *(DONE / FROZEN)*

**Status:** DONE; committed at `3a8487c` ("Check d1.c", 06-17). Analysis-only (no `a4/standalone/` changes; new module lives in analysis tree). Spec: `IV_POS_8_D1_C_SPEC.md` v0.3 (LOCKED). Maps to **Pro §5** (bug-proximity metric catalog) + **§8** (analytics). Completes the D1-analysis trilogy.

#### Scope & the question (the third leg of the A→B→C argument)
D1.A: floor-decay alone doesn't help because `bandit_success` saturates ~mut 3000–3500 (Finding F). D1.B: **L0 CGC coarsening can't fix that** (saturation inversion). **D1.C's job:** find **per-mutation (Tier-1) signals** that are (a) **orthogonal** to the existing reward channels, (b) **non-saturating** (still fire >5% post-local), and (c) cheap — these become **D1.E's L1 OR-channel candidates**. Plus ship **per-campaign (Tier-2) metrics** mapped to Pro §5/§8 for D2.G's V5-vs-V6 table + Pro disclosure. **Hard scope disclaimer (repeated everywhere):** D1.C analyzes frozen DBs to find *candidate* signals — it does NOT prove the bandit benefits from learning on them. That's D1.E's forward-run job.

**Three-tier architecture:** Tier-1 (per-pull, → D1.E L1), Tier-2 (per-campaign, → D2.G + Pro), Tier-3 (D3 repair/isolation, out of scope). Corpus: **30 DBs** (10 V1 + 10 V5 + 10 D1.A decay) for Cat-A; **10 D1.A DBs** for Cat-B (the only ones with `proof_generated`/`elapsed_ms` columns).

#### Key implementation subtlety: channel reconstruction (Option A)
The per-pull novelty integers `l_new`/`g_new`/`s_new`/`f_new` are **NOT persisted** to SQLite. Three options: A (use `reward_counterfactuals.discovery_binary_reward` = the bandit's actual Bernoulli bit, + derive `f_new_flag` from `fnew_only_reward>0` which is exact), B (algebraic inversion — underdetermined, rejected), C (full replay — expensive, deferred). **Option A was used** (verified in `bug_proximity.py`); Option C was NOT triggered (its condition — all Tier-1 candidates failing orthogonality — never occurred). Orthogonality is measured against `{discovery_binary_reward, f_new_flag}`.

#### Tier-1 results — 5 candidates → 3 recommended (the D1.E L1 shortlist)
Gates: orthogonality `max|ρ| < 0.4`; non-saturation `fire_rate[3000,6000) > 5%`. (Code-verified definitions: `f_new_flag` = `fnew_only_reward>0`; `singleton_failure_flag` = `COUNT(*) failures == 1`; `d_loc_le_2_flag` = `d_loc <= 2`.)

| Signal | post-local fire | max\|ρ\| | disjoint-fire | Bucket |
|---|---|---|---|---|
| **`mutation_substrategy_uniqueness`** | 33.7% | 0.069 | 98.1% | **A — rank 1** |
| **`d_loc_le_2_flag`** | 60.7% | 0.239 | 99.3% | **A — rank 2** (⚠ opposite-saturation risk) |
| **`singleton_failure_flag`** | 16.5% | 0.082 | 99.6% | **A — rank 3** |
| `recent_marginal_discovery_rate` | 15.8% | 0.114 | (continuous) | A — 4th alternate (scalar/NFP-9) |
| `f_new_flag` | ~0% | 0.123* | — | **B — DEAD post-local** |

- **High disjoint-fire (96–100%)** = these signals fire mostly when `discovery_binary_reward=0` → they genuinely *extend* the success bit into the post-local regime where CGC/floor-decay couldn't. This is the positive result D1.A/D1.B were missing.
- **`f_new_flag` is empirically DEAD post-local** (302/306 fires pre-mut-3000; 0 post-local fires on all 10 V5 DBs) — *confirms NFP-9's f_new finding empirically*. Bucket B; do NOT wire on V5.
- **The "orthogonality surprise":** `recent_marginal_discovery_rate` was *expected* to fail orthogonality (rolling mean of a binary signal) but PASSED (ρ≈0.11) — once `discovery_binary_reward` goes sparse (~3% post-local), the rolling mean decouples. So Bucket C ("scalar-bandit only") ended up **empty**.
- **`d_loc_le_2_flag` at 60.7% fire is a double-edged sword** — fires a lot (passes non-saturation easily) but risks pushing `bandit_success` *always-on* (opposite saturation). → Directly drives D1.E's opposite-saturation guard (mean `bandit_success_l1 ≤ 0.75` in [3000,6000)) and the ≤3-channel cap.
- **`mutation_substrategy_uniqueness` excludes INSTR_TYPE_MOD** (all-NULL substrategy → degenerate; ~25% of corpus). D1.E carries this exclusion forward (Q-E-INSTR_TYPE_MOD).

#### Tier-2 results — 8 metrics (Pro §5/§8); the standout decay finding
8 per-campaign metrics. Most show no decay discrimination. **The headline:** `singleton_failure_rate` is the **ONLY Tier-2 metric that significantly separates decay from V5-static** — decay variants produce **~22% fewer singleton failures**:

| Comparison | decay | V5-static | p |
|---|---|---|---|
| decayexp vs V5 | 12.9% | 16.7% | **2.6×10⁻⁶** |
| decayepoch vs V5 | 13.4% | 16.7% | **9.7×10⁻⁵** |

- Corroborated by `d_loc_p95`: decayexp tail multiplicity is *higher* (7 vs 6, Wilcoxon p=0.0625). **Coherent picture: decay → fewer surgical singletons, more multi-loc cascades.** Architectural interpretation is OPEN: (a) decay pushes toward multi-loc failures, or (b) decay misses singleton mutations entirely. **This is the first metric on which decay and static demonstrably differ** — D1.A's `local_context_final` analysis was totally blind to it.
- **`verifier_accepted_invalid_count = 0` on ALL 30 DBs** — no accepted-invalid found. Expected (single-cell A4 mutations almost always reject), but it's the empirical confirmation that *A4's current catalog produces zero soundness candidates* — exactly Pro's "local coverage is survey, not bug" point. Retained for D2.G schema.
- Cat-B (D1.A only): `proof_generated_zero_residue_rejected_rate` ~12.4%; `wall_clock_per_normalized_discovery` ~65ms.
- Co-failure graph degree p95 (V5 31.4, V1 27.5) — stable across decay; feeds D2.G.

#### Audit (separate Composer audit, `D1C_AUDIT_REPORT.md`)
NFP-10-motivated audit: regenerated all artifacts (0 mismatches), 40/40 tests pass, confirmed `bug_proximity.py` has **zero CGC/byte_addr/address_region dependency** (so the NFP-10 bug class can't apply). Two bounded semantic schisms found + disclosed to D1.E: (a) crash-mode `d_loc=0` with non-empty failures (1.12% of pulls; `d_loc_le_2_flag` fires but `singleton_failure_flag` reads failures directly → they use different failure semantics; <0.2pp impact, shortlist order unchanged); (b) singleton = 1 failure *row*, not 1 distinct *loc* (5/6000 differ on V5 s1234; D1.E to choose semantics).

#### Implications for architecture & Pro-goals
1. **D1.C delivers D1.E's actual lever.** The A→B→C arc concludes: floor-decay (A) and CGC-coarsening (B) can't extend the discriminating window, but **3 orthogonal per-mutation signals (C) DO fire post-local with ~99% disjoint-fire.** D1.E's L1 = OR these in (substrategy_uniqueness + d_loc_le_2 + singleton), capped at ≤3, with an opposite-saturation guard. This is a clean, well-guarded hand-off.
2. **The singleton-decay finding is a genuinely new scientific result for Pro.** Decay variants *do* behave differently from static (fewer singletons / more cascades, p~10⁻⁶) — just not on coverage. This connects to Pro's cascade concern (§4/§6): decay may be pushing toward exactly the cascade-heavy, less-bug-proximate mutations Pro warned about. Worth surfacing to Pro explicitly.
3. **`verifier_accepted_invalid_count=0` everywhere** is the quantitative proof of Pro's thesis that single-cell post-execution fuzzing yields no accepted-invalids on its own → reinforces the need for Hybrid V7 (Arguzz coherence) + the Mode-B isolation/repair layer (D3).
4. **Forward dependency (clean):** D1.E plans to copy `KIND_TO_SUBSTRATEGY_FIELDS` into a new `a4/standalone/l1_signals.py` with a cross-tree fixture test asserting byte-for-byte match. I verified the source-of-truth constant in `bug_proximity.py:57` (8 keys) matches the copy in the D1.E spec — so that test will pass when D1.E is implemented. `bug_proximity.py` is analysis-tree, not importable from `standalone/`, hence the copy.
5. **Scope (§8.5):** all D1.C conclusions are V5-catalog-specific. `mutation_substrategy_uniqueness` fire rates *will* change under Hybrid V7 (V6 kinds add substrategy keys); d_loc/singleton distributions need re-derivation for V7. D1.E forward-run is the only validation.

#### Artifact pointer index — D1.C
| Artifact | Path | Role |
|---|---|---|
| Spec | `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` (v0.3) | LOCKED spec; 3-tier architecture, channel reconstruction §1.4 |
| **Full shortlist reference** | `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` | the readable master doc — all 5 Tier-1 + 8 Tier-2 with results, buckets, definitions |
| **D1.E L1 hand-off (load-bearing)** | `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` | top-3 + decay tables + crash schism + INSTR_TYPE_MOD exclusion + singleton-decay finding |
| Subsection (Pro-facing) | `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` | folds into Stage-4 D1 report |
| Tier-2 schema (D2.G) | `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` | column lock for D2.G `build_d2_artifacts.py` |
| CSVs | `d1c_metrics_table.csv` (30×8 Tier-2), `d1c_correlation_matrix.csv` (270), `d1c_non_saturation.csv` (150), `d1c_batch1_tier1_audit.csv` (150), `d1c_paired_tests.csv` (24), `d1c_nonparametric_tests.csv`, `d1c_recent_marginal_thresholds.csv` (180), `d1c_substrategy_field_audit.csv`, `d1c_unpaired_means.csv` | results |
| Notebook / plots | `IV_POS_8_D1C_NOTEBOOK.ipynb`(+`.html`); `plots/d1c_batch1_fire_rate_{full,post_local}.png` | evidence |
| **Code (read & verified)** | `a4/runs/iv_pos_7/analysis/bug_proximity.py` (713 lines; Tier-1 extractors + Tier-2 aggregators + `KIND_TO_SUBSTRATEGY_FIELDS`); tests `test_bug_proximity.py` (40 pass) | the metric stack |
| Analysis builders | `a4/runs/iv_pos_8/d1c/analysis/build_d1c_*.py` (artifacts, correlation, nonparametric, notebook, substrategy audit) | |
| Composer docs | `composer/D1C_BATCH1_REPORT.md`, `D1C_BATCH2_REPORT.md`, `D1C_BATCH3_REPORT.md`, **`D1C_AUDIT_REPORT.md`** (NFP-10-style audit) | granular |

---

## 6B. The D2 block — Hybrid V7 construction

> The D2 stream is governed by `IV_POS_8_D2_PLAN.md` (master plan, D2.A–G; Opus-CP has read the relevant slices, not the full 747 lines yet). D2 is the **build** stream (vs D1's **analysis** stream). It constructs the infrastructure + variants for Pro's Priority-1 Hybrid V7 comparison (V5 / V6-uniform / V6-cTS / Hybrid-cTS). Sub-deliverable status board is in §3.2. We walk: **D2.A (foundation) → D2.B (pure-A4 kinds) →** [drafts: D2.C Arguzz integration, D1.E].

### 6B.1 D2.A — Hybrid V7 foundation (5-tuple ArmKey + MutationOutcome + normalization)  *(DONE)*

**Status:** DONE. Batch 1 `b844e8e`, Batch 2 `7b66fb9` (both 06-16/06-17). Spec: `IV_POS_8_D2_A_SPEC.md` v0.2 (LOCKED — all 11 §6 questions resolved). Maps to **Pro §8/§15** (Hybrid scheduler prerequisites). **Pure infrastructure — no new behavior, no new mutation kinds.** Everything in D2.B–G depends on it.

#### Scope: three architectural changes
1. **5-tuple `ArmKey`** — promote the bandit arm key from 2-tuple `(kind, zone)` to `(surface, kind, zone, opcode_class, pre_post)`. Needed so the Hybrid scheduler can allocate across both the A4-trace-cell and Arguzz-exec-fault surfaces, opcode-class-aware (Pro §8).
2. **`MutationOutcome` enum + applied-accounting** — `APPLIED`/`SKIPPED`/`ERROR`, plus `applied_accounting_mode` so the scheduler can count *only applied* mutations as pulls (Pro §8: "count only **applied** Arguzz mutations as pulls" — Arguzz frequently no-ops/panics, so attempted≠applied).
3. **Normalization verification** — confirm V5 already writes canonical `Name@basename:line` locs at write-time via `ConstraintFailure.short_loc()`; mark `constraint_loc_normalize.py` legacy/read-only (only needed for R2 V6 archive DBs that bypassed it).

#### What was implemented (code-verified)
- **`ArmKey`** (in `semantic_arm_universe.py:174–210`, NOT `bandit_ts.py` — see flag F6): `@dataclass(frozen=True, order=True)` with 5 string fields. `ArmKey.v5(kind, zone)` → `(A4_TRACE_CELL, kind, zone, "n/a", "n/a")`. `is_v5_shape()`, `__str__` emits **2-pipe** `kind|zone` for V5-shape arms and **5-part** `surface|kind|zone|opcode|pre_post` for full arms; `.parse()` inverse. Constants `A4_TRACE_CELL`/`ARGUZZ_EXEC_FAULT`/`NA`.
- **`MutationOutcome`** (`bandit_ts.py:57`): `(str, Enum)` APPLIED/SKIPPED/ERROR. `update_with_outcome(arm, outcome, success)` (`bandit_ts.py:310`): if `applied_accounting_mode and outcome != APPLIED` → return (no state advance); APPLIED → advance; else (mode off) → advance with 0. Back-compat `update(kind, zone, success)` overload constructs `ArmKey.v5()`.
- **`mutations.outcome TEXT`** column + `idx_mutations_outcome` (forward-compat migration, NULL on legacy DBs). `_outcome_for(result)` in fuzzer: crashed→error, config None→skipped, else→applied; plumbed via `_mutation_record_kwargs` (all 4 `record_mutation` sites unchanged — they spread the helper).
- **`fuzzer.py` = 0 LOC change in Batch 1** (the back-compat overload made the refactor invisible to V5 call sites); +12 LOC in Batch 2 (outcome plumbing only).
- Also present: `arm_state_rows()` / `arm_state_snapshot` infra (Pro §12).

#### Key results & locked decisions
- **Golden-trace byte-identity (the load-bearing gate):** seed=42, N=200, V5 selector → decision sequence (`arm_id, mode, step, kind, zone`) byte-identical pre/post refactor. **This validates Q9: R2 V5 archive is a valid baseline** — V5 doesn't need re-running for D2 comparisons (saves ~10 jobs / ~3h POS per comparison). The whole archive-reuse contract hinges on this test.
- **Synthetic Arguzz-shape scheduler test** (Ivan's specific concern: "when do the 5 fields actually get tested?"): a 10-arm mixed universe (5 A4 + 5 Arguzz with real opcode_class/pre_post) exercised with `applied_accounting_mode=True` + a mock skip stream. Confirms: Arguzz arms emit 5-part arm_id, `pulls == APPLIED count` (skips don't advance state), floor/cold-start/posterior all work on the full 5-tuple. **→ Arm-shape mechanics are bulletproof at end of D2.A**, before any real Arguzz dispatcher exists (that's D2.C).
- **All 11 §6 questions resolved** (highlights): Q1 dataclass (not tuple); Q2 `"n/a"` sentinel (not None); Q3 `applied_accounting_mode` default **False** (V5 unchanged); Q4 **3-value** enum (refine in D2.C if needed); **Q5 V5 does NOT adopt applied-accounting** (keeps "skip = 0-reward pull"; preserves RNG byte-identity + archive reuse); Q6 outcome classified explicitly by fuzzer (not DB inference); **Q7/Q8 `opcode_class`/`pre_post` = "n/a" for ALL A4 arms in v1** (incl. D2.B kinds — keeps arm-space bounded + V5 baseline intact); Q9 archive reuse; Q10 synthetic-harness tests (no binary needed); Q11 two batches.
- **`v6_driver_v2.py` recovered** (608 lines, md5 `284e9714…`, `driver_version=v2.1_utf8safe`, `scheduler=balanced_round_robin`) from coinbase `/tmp/` into `a4/runs/iv_pos_7/drivers/` — it was never in git. Load-bearing reference for D2.C's V6-uniform modernization.
- **Audit hot-patch:** A3/E3/E3b (+B2) tuple-key lookups fixed — `universe.arms` keys are now `ArmKey`, not `(kind, zone)` tuples; without the fix those Phase-7D audits silently returned wrong results (pytest doesn't run them).
- Test count: 494 (D1-era) → **503** (Batch 1) → **510** (Batch 2).

#### Implications for architecture & Pro-goals
1. **D2.A is the enabler for the entire Hybrid V7 path.** It's the schema/scheduler groundwork that lets D2.B register pure-A4 kinds, D2.C add Arguzz arms with real opcode_class/pre_post, and D2.D wire the 4 variants. No experiment runs on D2.A alone.
2. **Asymmetric-by-design arm shape:** the 3 fields constant for A4 (`surface`, `opcode_class`, `pre_post`) are exactly where Arguzz needs richer parameterization. The schema is "honest about the difference between the two surfaces" (spec §1.1).
3. **Two different accounting regimes coexist (Q5):** V5/pure-A4 = "skip counts as 0-reward pull" (applied_accounting OFF); V6-cTS/Hybrid-cTS = applied-accounting ON (skip → no advance). **CORRECTED per F7 (2026-06-19):** the Arguzz surface skips only **~5%** (it is ~91.6% APPLIED+REJECTED — *highly productive*, NOT the "~95% no-ops" the pre-correction D2.C v0.2 §5.5 claimed). So applied-accounting is **low-stakes** (it rarely fires) but still correct to apply; A4 rarely skips (~1–2%). The asymmetry is intentional; F7's correction means it matters far less than originally framed.
4. **Latent lever (Q7/Q8):** A4 arms get NO opcode-class/pre-post learning in v1 (all "n/a"). D2.B kinds *could* use real opcode classes (e.g., `TXN_PREV_WORD_MOD@core_arithmetic@arithmetic`) — deliberately deferred to keep arm-space bounded and the V5 baseline intact. A future refinement if finer A4 learning is wanted.
5. **Multiple outcome-classifiers now exist** — `_outcome_for()` (DB column: applied/skipped/error) vs the older `_classify_outcome()` (reward taxonomy: ACCEPTED/CRASH/REJECTED/NO_EFFECT). Kept separate (orthogonal purposes). D2.C adds a THIRD, Arguzz-specific `_classify_outcome` in `arguzz_invoke.py` — no collision (different module), but worth tracking for clarity when reading D2.C.

#### Artifact pointer index — D2.A
| Artifact | Path | Role |
|---|---|---|
| Spec | `a4/docs/cloud2/IV_POS_8_D2_A_SPEC.md` (v0.2 LOCKED) | 3 changes, §1.1 5-tuple semantics, §8 11 decisions |
| Master D2 plan | `a4/docs/cloud2/IV_POS_8_D2_PLAN.md` | governs D2.A–G (Opus-CP: partial read) |
| **Code (read & verified)** | `semantic_arm_universe.py:169–210` (`ArmKey`, surface constants), `bandit_ts.py:57` (`MutationOutcome`), `:305–322` (`update`/`update_with_outcome`), `:324` (`arm_state_rows`); `coverage_db.py` (`outcome` column); `fuzzer.py` (`_outcome_for`) | the foundation |
| Tests | `tests/test_d2a_arm_shape.py`, `test_d2a_back_compat_golden_trace.py` (+fixture `fixtures/d2a_golden_v5_trace_seed42_n200.json`), `test_d2a_arm_shape_arguzz_simulation.py`, `test_d2a_applied_accounting.py`, `test_d2a_outcome_column.py`, `test_d2a_normalize_parity.py` | gates |
| Recovered driver | `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (608 lines) | D2.C reference (frozen) |
| Composer docs | `composer/D2A_BATCH1_COMPOSER_{KICKOFF,REPORT}.md` (arm-shape, golden trace, driver recovery), `D2A_BATCH2_COMPOSER_{KICKOFF,REPORT}.md` (outcome column, normalize) | granular |

---

### 6B.2 D2.B — Pure-A4 mutation expansion (Pro's 8 kinds → 3 live + 5 dead)  *(DONE / feature-complete — LAST IMPLEMENTED DELIVERABLE)*

**Status:** DONE / feature-complete. Batches 1→4 (`78d036c`→`2e1d97b`) + §9c postscript PS-1 (`e2c2256`, removes 5 dead from `MUTATION_KINDS`). Spec: `IV_POS_8_D2_B_SPEC.md` v0.5.4 (LOCKED; "deeper & more rigorous than a normal spec" per Ivan — witness mutation is sensitive). Maps to **Pro Priority 3 / §8 / §15.3**. This is the **most involved deliverable** (Rust handlers + mechanism proofs + 5-layer attestation). **It is the last fully-implemented deliverable** (D2.C, D1.E are spec-only).

#### Scope
Implement all **8 pure-A4 mutation kinds** Pro requested. These mutate the **post-execution `PreflightTrace`** in Rust witgen (`workspace/risc0-modified/.../witgen/mod.rs:189–601`), single-cell/surgical, *after* execution produces the trace but *before* witness generation reads it. Fundamentally different from Arguzz (during-execution, propagated). The 8 kinds: B.1 `TXN_PREV_WORD_MOD`, B.2 `TXN_PREV_CYCLE_MOD`, B.3 `CYCLE_MODE_MOD`, B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD`, B.8 `CYCLE_DIFF_COUNT_MOD`.

#### THE headline result (NFP-11): 3 LIVE, 5 DEAD on sha2-host user cycles
| Result | Kinds | Mechanism |
|---|---|---|
| **LIVE** (mutation reaches witness; constraint fires) | B.1 `TXN_PREV_WORD_MOD`, B.2 `TXN_PREV_CYCLE_MOD`, B.8 `CYCLE_DIFF_COUNT_MOD` | extern *returns* the field to the DSL → it feeds memory-permutation / cycle constraints |
| **DEAD** (structurally inert at witness layer) | B.3 `CYCLE_MODE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD` (**W-17**) + B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD` (**W-18**) | field never enters the witness |

**Two dead-arm mechanisms (source-proven in the mechanism report):**
- **W-17 — `set_cycle` preset overwrite:** trace field (`pc`/`state`/`machine_mode`) is *seeded* into the witness layout, then **overwritten** by `exec_Reg(inst_result.new_*)` (execution-derived) before any constraint reads it. No `extern_getPc`/`extern_getState` exists. (B.3/B.6/B.7 on user cycles.)
- **W-18 — execution-derived witness keys:** `extern_getMemoryTxn` reads `txn.addr`/`txn.cycle` only as a **sanity check** (FIE-suppressible throw) and **never returns them**; the witness `addr`/`cycle` columns are bound to the *execution arguments* (`rs1+imm`, `2*cycle`), not the trace fields. (B.4/B.5.)
- **The smoking gun (mechanism report §7):** same extern (`getMemoryTxn`), one transaction, four fields — `prev_word`(B.1)+`prev_cycle`(B.2) are **returned** → LIVE; `addr`(B.4)+`cycle`-LSB(B.5) are **sanity-check-only** → DEAD. The sole differentiator is *whether the extern returns the field.* Cleanest possible mechanism proof.

#### Not soundness bugs (the certainty machinery)
For dead kinds the mutated value **never enters the witness** → the proof attests the *original, correct* execution → not a soundness bug. The infrastructure proving this:
- **4-channel rejection model:** **C1** `<constraint_fail>` (local EQZ tag), **C2** `verify segment` prover panic (global polynomial/memory-perm imbalance, no local tag), **C3** `<a4_family_residue>` (Hook 3, opt-in `A4_FAMILY_RESIDUE=1`), **C4** `<a4_error>` (dispatcher). **Origin = Issue 6:** B.1 `at_write` mutations reject via **C2 (panic), emitting ZERO `<constraint_fail>` tags** (while `at_read` on the same step emits `IsRead@mem.zir:79` via C1). The attestation soundness guard initially **false-positived** (only checked C1) → fixed by wiring in C2+C3 to match the production fuzzer's 3-channel check. *This is why the multi-channel model exists — different mutations reject through different channels.* (Validates NFP-3: at_read vs at_write are genuinely different failures.)
- **Soundness-bug guard fires when:** applied + trace-changed (Layer-3 dump) + no channel fired + verifier accepted. **For all 5 dead kinds the guard fires** → they're `pytest.xfail`'d with documented W-17/W-18 rationale (the xfail *documents* the structural dead arm; the source audit separately proves not-a-bug).
- **FIE (`FAULT_INJECTION_ENABLED`):** suppresses only the C++ `throw` at preflight-vs-execution sanity checks; does NOT touch witness binding / Hook 3 / constraints / verifier. A mutation surviving FIE without a constraint break is **structurally dead, not "masked by FIE"** (confirmed via `A4_NO_FAULT_INJECTION=1` → B.4 panics at the throw).

#### The 5-layer attestation framework ("100% certainty" stack)
Per-kind tests assert, in order: **L1** unit (no binary), **L2** Rust handler emits `<a4_<kind>>` tag (old/new value + locator — the binary attests what it did), **L3** post-mutation dump-diff via `A4_DUMP_POST_MUT=1` (**NFP-5** — a new Rust hook; without it L3 would compare two *pre*-mutation dumps and the certainty claim would be false; risk-tiered strictness — strict "one field, one index" for low-risk kinds), **L4** cross-check (L2 tag ≡ L3 diff — load-bearing), **L5** campaign smoke (mocked binary). Dead arms *pass* L2–L4 then trip the soundness guard → xfail.

#### Implementation chronology
- **Batch 1** (`78d036c` region): B.1 (with `at_read`/`at_write` RNG-picked sub-strategies, NFP-3) + B.2 + the Layer-3 Rust hook (`A4_DUMP_POST_MUT`, NFP-5) + **Batch 1.5e: `PRE_EXEC_REG_MOD` retrofix (NFP-6)** — RNG-picks next_read/prev_write (half the surface was dead/hardcoded). **Batch 1.5e is the D1.E sync gate** (it alters V5 behavior, so D1.E's fresh V5 baseline must run post-1.5e). Issue 6 investigation happened here.
- **Batch 2** (`f81523c`): W-17 dead-arm audit (B.3 `CYCLE_MODE_MOD`) → `D2B_BATCH2_DEAD_ARM_AUDIT.md`.
- **Batch 3** (`4e5150a`): W-18 txn dead-arm audit (B.4/B.5 dead), B.6/B.7 dead (W-17), B.8 live → `D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`.
- **Batch 4** (`2e1d97b`): cross-cutting `test_d2b_arm_registration.py` (6 layers × 16 kinds = 94 pass, **3 xfail** — NFP-4 drift, see F8) + campaign smoke + **real-binary POS N=100 on flare**.
- **§9c PS-1** (`e2c2256`): remove the 5 dead kinds from `MUTATION_KINDS` (registry absence, not filter) → live registry = **11 kinds** (8 V5 + 3 D2.B-live; code-verified at `fuzzer.py:253`).
- **§9d PS-2** (`dfd0ebe`, 2026-06-19): **F8 fix** — align `_TXN_ROLE_BY_KIND` with NFP-4 (`CYCLE_DIFF_COUNT_MOD "diff_count"→"read"`; dead-kind sentinels `TXN_ADDR_MOD`/`TXN_CYCLE_PHASE_MOD`→`"read"`); extend the txn_role contract test to all 11 live kinds (the regression guard that would have caught the original drift); remove the `CYCLE_DIFF_COUNT_MOD` xfail + the campaign-smoke 3-kind allowlist. Plan bumped v0.15→v0.16. Closes F8.
- **PS-3** (formerly "PS-2" before F8 took the slot): fully delete dead-arm Python/Rust/test code — TBD post-D2.G. The 5 dead modules still exist on disk (`mutations/cycle_mode_mod.py`, `txn_addr_mod.py`, etc.) as documentation + regression sentinels.

#### ⚠ Campaign-interpretation caveat (important for reading any A4 campaign log)
The fuzzer's **"potential bug" counter** increments on (applied + trace-bytes-changed + verifier-accepts) — which is *exactly* the dead-arm condition. The Batch-4 POS N=100 run printed **"27 potential bugs!"** = exactly the **27 dead-arm attempts** (B.3:6, B.6:7, B.7:6, B.4:6, B.5:2; **0 rejections each**). These are **dead-arm false positives, NOT real soundness bugs.** This is the core reason §9c removes dead kinds from the registry — to stop contaminating campaign data with structurally-inert "successes." (Also: the run reported `exit_code=2` + transient poslib HTTP errors — expected empirical signature, DB complete via EXIT trap.)

#### Implications for architecture & Pro-goals
1. **A4's catalog ceiling is even narrower than Pro feared.** Pro §13 said "the catalog is the ceiling"; D2.B narrowed it — only **3 of 8** requested kinds are live. The A4 trace-cell arm space is **11 effective kinds** (8 V5 + 3 live), not 16. This *sharpens* the case for Hybrid V7 (importing Arguzz terrain) over further pure-A4 expansion — pure-A4 has diminishing returns on this guest.
2. **A concrete forward roadmap exists (mechanism report §11).** Mechanism analysis (extern-returns-field) yields 4 high-confidence-live candidates for a *future* mutation-studies batch: **`BIGINT_BYTES_MOD`** (bigint operands), **`CYCLE_PAGING_IDX_MOD`** + B.3-paging-variant (paging cycles), **`CYCLE_TXN_IDX_MOD`** + **`CYCLE_BIGINT_IDX_MOD`** (a NEW category — *structural-index* mutation: corrupt the index *into* a trace array, not a value in it). These hit bigint/paging/index surfaces no current kind touches, selected by mechanism up front → higher expected live-rate. A clean "Pro Priority-3 extension" pitch.
3. **Ties to D1.C's `verifier_accepted_invalid_count = 0`:** D2.B's dead arms ARE the "applied + accepted" cases; the soundness guard + audit correctly classify them as structural, not soundness signals. Together: A4's current surface produces *zero* real accepted-invalids → reinforces the Hybrid V7 + Mode-B (D3 repair/isolation) need.
4. **Dead-ness is cycle-class-scoped.** Claims are for **sha2-host user cycles**. B.3 (`machine_mode`) is plausibly **LIVE on paging cycles** (`extern_nextPagingIdx` reads+returns it); the harness only exercises user cycles. So "dead" is conditional — relevant for multi-guest (D4) and the §11 paging follow-up.

#### Artifact pointer index — D2.B
| Artifact | Path | Role |
|---|---|---|
| Spec | `a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md` (v0.5.4, 1428 lines) | per-kind design, 5-layer testing framework, risk-tiered Layer 3 |
| **Mechanism report (Pro-facing synthesis)** | `a4/docs/cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md` (601 lines) | W-17/W-18 proofs, smoking gun §7, 4-channel model §9, §11 future candidates, Appendix A field→extern map |
| Dead-arm audits | `composer/D2B_BATCH2_DEAD_ARM_AUDIT.md` (W-17), `D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` (W-18, +`_KICKOFF`) | detailed evidence |
| Issue 6 | `composer/D2B_BATCH1_ISSUE6_INVESTIGATION.md` | at_write rejects via C2 panic not C1 tag → origin of multi-channel guard |
| Taxonomy | `a4/docs/standalone/MUTATION_TAXONOMY.md` | authoritative per-kind reference (spec cross-refs it) |
| **Code (read & verified)** | `fuzzer.py:253` (`MUTATION_KINDS` = 11 live), `compressed_global_extractor.py:161` (`_TXN_ROLE_BY_KIND` — see F8), `mutations/{txn_prev_word,txn_prev_cycle,cycle_diff_count}_mod.py` (live) + 5 dead modules still present; Rust `witgen/mod.rs` (handlers + `A4_DUMP_POST_MUT`) | the kinds |
| Tests | `tests/test_d2b_<kind>_unit.py` (L1, 8), `test_d2b_<kind>_attestation.py` (L2/3/4 gated, 8), `test_d2b_arm_registration.py` (94 pass/3 xfail), `test_d2b_campaign_smoke.py` (L5), `test_d2b_real_binary_campaign.py` (POS) | gates |
| POS artifact | `a4/runs/d2b_smoke/flare/*.db` (N=100, the "27 potential bugs") | dead-arm sentinel evidence |
| Composer docs | `composer/D2B_BATCH{1..4}_*` (kickoffs, reports, followup, `BATCH4_REPORT_FIXUP.md`) | granular chronology |
