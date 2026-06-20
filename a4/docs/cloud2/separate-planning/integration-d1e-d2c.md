# Integration Planning — D1.E & D2.C (the "bring-it-together" phases)

> **OWNERSHIP:** Maintained by Claude (Opus-CP). Companion to `central-planning-1.md` (which is the chronological record of *what was done*). **This doc is about *what to integrate and what to drop*** as the separate components (D1.A–C, D2.A–B) converge into the two integration phases D1.E and D2.C — and how to present all of it to ChatGPT Pro for an architecture call.
>
> **Structure:** §A = a-priori integration map (written BEFORE re-reading the D1.E/D2.C specs — pure synthesis of the 5 implemented phases). §B = how the actual specs shape it (written AFTER reading them). §C = Pro-presentation guidance. **Status: §A done; §B/§C pending spec re-read.**

---

## §A. A-priori integration map (synthesis of the 5 implemented phases)

The mental model: **two integration phases, two surfaces.**
- **D1.E = the reward-engine integration (A4-only, V5 family).** Wires D1.B's L0 + D1.C's L1 into `bandit_success`, retunes K/epoch, re-runs V5/decay. *"Does an enriched reward finally make decay (or just better exploitation) beat static V5?"*
- **D2.C = the surface integration (A4 + Arguzz).** Brings 4 Arguzz exec-fault kinds into the bandit arm space + modernizes the V6-uniform driver. The doorway to Hybrid V7. *"Can we schedule Arguzz mutations through our feedback loop, and does the combined surface beat standard Arguzz?"*

They share the D2.A foundation (5-tuple ArmKey, MutationOutcome, applied-accounting) and will eventually fuse in **Hybrid-cTS** (the endpoint Pro most wants). D1.E's reward enrichment is, in principle, also applicable to Hybrid — but D1.C explicitly scoped its signals to V5 (substrategy fire-rates change with V6 kinds), so that carry-over is an open question.

### A.1 What each completed phase contributes to / constrains the integration

**D1.A (decay floor) → feeds D1.E; informs Hybrid scheduler geometry.**
- *Integrate:* the decay variants themselves (decayexp, decayepoch) — but **retuned**: K≈200–300 (not 50), 2-tier epoch `[(0,0.55),(1000,0.35)]` (drop the no-op 3rd tier).
- *Constraint (Finding D):* the integer-per-arm-quota scheduler only supports ~3 floor regimes → "gradual decay" is mechanically untestable on V5's ~48-arm space. **Latent lever:** per-mutation Bernoulli floor sampling (~1-line change) would make mode-share continuous. **Hybrid's larger arm space partly relieves this** (more arms → finer quotas) — so decay may matter more in Hybrid than in V5. A genuine "try in Hybrid" candidate for Pro.
- *Why D1.E exists (Finding F):* reward saturates ~mut 3000 → decay alone can't help. So D1.E is fundamentally about the *reward*, with decay as a passenger.
- *Drop/keep call for Pro:* does decay stay in the variant matrix at all, or is it deprioritized to "Hybrid-only re-test"?

**D1.B (CGC coarsening) → feeds D1.E L0; sets D2 reward CGC default.**
- *Integrate:* **`production_log2_corrected` as the L0/CGC reward signal** (with the byte_addr fix, NFP-10). This is the D2-wide CGC default too.
- *Drop:* the coarsening idea (`region_only`/`log4`/`page_class` as L0) — **saturation inversion** proved coarser → saturates *earlier* → worse post-local window. page_class is NOT a reward-signal win (though it's still a useful *analysis* lens and Pro should confirm the definition, NFP-7).
- *Constraint:* even the best L0 has thin post-local headroom (~1 key/70 mut) → **L0 alone can't fix Finding F.** This is *why* D1.E leans on L1 (D1.C signals), not CGC.
- *Carry to D2:* all forward runs use the patched extractor; R2 memory-CGC numbers to Pro need the ~10–20% understatement correction (V5>V1 direction preserved).

**D1.C (bug-proximity metrics) → feeds D1.E L1; feeds D2.G analytics.**
- *Integrate (L1 OR-channels):* the **3 Tier-1 signals** — `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag` — capped at ≤3, with an **opposite-saturation guard** (d_loc_le_2 fires 60% post-local → naive OR risks always-on). Plus `recent_marginal_discovery_rate` as a scalar/4th-alternate.
- *Drop:* `f_new_flag` (empirically dead post-local on V5). Confirms NFP-9.
- *Open question Pro should weigh:* D1.B/D1.C both flagged that **naive OR may be the wrong composition** — per-channel posteriors / weighted reward / scalar bandit (L2) are alternatives. D1.E v1 commits to naive OR (≤3) for lowest risk; Pro could push for L2.
- *Scientific finding to surface:* **singleton-failure-rate is the only metric on which decay≠static (p~10⁻⁶, decay ~22% fewer singletons / more cascades).** Possible link to Pro's cascade concern (§4/§6) — decay may push toward exactly the less-bug-proximate cascade-heavy mutations Pro warned about. Pro should opine.
- *Bug-metric reality:* `verifier_accepted_invalid_count = 0` everywhere → A4 alone yields zero accepted-invalids → reinforces Hybrid + Mode-B-isolation need.
- *Feeds D2.G:* the 8 Tier-2 metrics are the V5-vs-V6 comparison stack.
- *Scope caveat:* signals are V5-specific; fire-rates change under V6 kinds → **L1-on-Hybrid needs a re-audit** before being trusted.

**D2.A (foundation) → enables both D1.E plumbing and all of D2.C.**
- *Integrate:* 5-tuple ArmKey, MutationOutcome, applied-accounting, write-time normalization — these are the substrate Hybrid runs on.
- *Constraint (Q5):* V5 keeps "skip = 0-reward pull" (applied-accounting OFF); only V6-cTS/Hybrid turn it ON. **Cross-variant fairness depends on remembering this asymmetry.** *But* the F7 correction (below) changes how much applied-accounting matters.
- *Efficiency keystone (Q9):* V5 baseline = R2 archive (golden-trace-gated). No V5 re-run needed.
- *Latent lever (Q7/Q8):* A4 arms have opcode_class/pre_post = "n/a"; could be enriched for finer A4 learning. Deferred.

**D2.B (pure-A4 kinds) → sets the A4 half of the Hybrid catalog; teaches the mechanism-selection lesson.**
- *Integrate:* **11 live A4 kinds** (8 V5 + 3 D2.B-live: TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_DIFF_COUNT_MOD) as the A4 half of Hybrid-cTS.
- *Drop:* the **5 dead kinds** (already out of `MUTATION_KINDS`). Don't re-add.
- *Lesson for D2.C kind selection:* **mechanism-select kinds up front** (does the extern return the field / does the value reach the witness). D2.B's 3/8 live-rate is the cautionary tale; the §11 roadmap (BIGINT_BYTES_MOD, paging kinds, structural-index kinds) is the high-confidence next batch — a Pro "Priority-3 extension" pitch.
- *Reusable machinery:* the 4-channel rejection model (C1–C4) + soundness guard + 5-layer attestation. D2.C extends this to V6 (adds C5 host-panic).
- *Campaign-reading caveat:* "potential bugs" counter = dead-arm false positives; carry this warning to Pro so V6 campaign logs aren't misread.

### A.2 The F7 correction reshapes D2.C integration thinking (important)
The D2 pair's 2026-06-19 re-analysis inverts a load-bearing premise: **the V6/Arguzz surface is ~91.6% APPLIED+REJECTED + 2.95% APPLIED+ACCEPTED — highly productive, NOT ~95% no-ops.** Implications I should test against the actual D2.C spec:
1. **Applied-accounting may matter far less than the spec built it up to be** (~5% skip, not 95%). The bandit gets a strong V6 reward signal either way. (Still correct to count only applied — just lower-stakes.)
2. **23.4% of V6 mutations reject via the global/Path-B channel with NO local constraint tag** — the exact V6 analog of D2.B's `at_write` finding. So the 4-channel model (esp. C2 verify-segment + C3 Hook 3) and D2.G triage are load-bearing for V6, not just A4.
3. **2.95% APPLIED+ACCEPTED = ~177 soundness candidates per 6000-mut campaign.** These are the highest-EV rows for Mode-B / D3 triage. Whether they're real accepted-invalids or fault-no-ops is the open triage question — and it's the closest thing to a *bug signal* anywhere in the project so far (A4 had 0).

### A.3 The integration decision points Pro must rule on (a-priori list)
1. **Which Arguzz kinds to import** (spec proposes Pro's 4: INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND) — keep 4, or expand toward the 7?
2. **The variant matrix** (Pro §9: V5 / V6-uniform / V6-cTS / Hybrid-cTS). Confirm all 4? V6-cTS separate or folded?
3. **Does decay stay?** V5-only (D1.E) vs Hybrid-only re-test vs drop.
4. **L1 reward composition:** naive OR (≤3) vs per-channel/weighted/scalar-bandit (L2). And does L1 carry to Hybrid (needs re-audit)?
5. **Reward CGC:** confirm `production_log2_corrected`.
6. **Given F7 (V6 productive):** how much weight on applied-accounting vs just running V6-cTS?
7. **Soundness triage (Mode-B/D3):** the 177 V6 accepted-candidates — is triaging these the next real bug-hunt, and what machinery (co-failure graph, repair)?
8. **Pure-A4 next batch:** is the §11 mechanism-selected roadmap worth a future cycle, or is the A4 surface "done" and effort goes to Hybrid + isolation?

---

## §B. How the actual D1.E & D2.C specs shape this  *(after fresh re-read; D1.E v0.2.1, D2.C v0.3)*

Both specs are **uncommitted working-tree drafts, awaiting Ivan greenlight** (D1.E on Q-E-* defaults; D2.C "LOCKED pending Ivan sign-off"). Neither is implemented. The good news: D2.C v0.3's pre-flight audit *self-caught* exactly the errors I would have flagged (F6 ArmKey file, F7 panic-narrative, the false applied-accounting claim, the opcode-class taxonomy contradiction, the "major_to_opcode_class is new" error) — so both specs are now internally consistent with HEAD.

### B.1 D1.E spec — what it LOCKS (the reward-engine integration)
- **L0 = keep `production_log2_corrected`** (from D1.B; coarsening dropped). No code change to CGC.
- **L1 = OR-in D1.C's 3 Tier-1 signals** (`mutation_substrategy_uniqueness` [excluding INSTR_TYPE_MOD], `d_loc_le_2_flag`, `singleton_failure_flag` [row-form]); **naive OR, capped at ≤3 channels**, with an **opposite-saturation guard** (mean `bandit_success_l1` ≤ 0.75 over mut[3000,6000)). `f_new` excluded (dead). `recent_marginal_discovery_rate` deferred as a scalar/L2 candidate.
- **New DB column `bandit_success_l1`** (in `reward_counterfactuals`) = the enriched bit the bandit learns from; `discovery_binary_reward` stays base-only (preserves D1.A/D1.C comparability).
- **K retune ≈ 200–300** (closed-form `K ≈ saturation_d_local × 5.86`, pinned by a Batch-0 SQL pass on legacy `coverage`); **epoch retune to 2-tier `[(0,0.55),(1000,0.35)]`** (drops D1.A's no-op 3rd tier). K stays anchored to `_local_discoveries` per Pro §7.
- **Re-run = Option B, 15 jobs** (5 fresh V5-static + 5 decayexp + 5 decayepoch, all post-1.5e + post-rewire). Confound disclosed: V5-static-fresh vs D1.A-V5-archive mixes the L1 rewire with the PRE_EXEC_REG_MOD retrofix.
- **L2 (scalar-reward bandit) explicitly OUT of scope** — deferred.
- **The causal test:** does enriched reward give the decaying bandit a discriminating gradient that beats V5-static?
- **Scope disclaimer (important for integration):** D1.E is **V5-catalog only.** Results do NOT auto-transfer to Hybrid V7. If Hybrid lands first, a parallel Hybrid + L1 re-audit is recommended before committing V5-paired conclusions.

### B.2 D2.C spec — what it LOCKS (the surface integration)
- **4 Arguzz exec-fault kinds** (Pro's 4: INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND). The other 7 V6 kinds are dropped (overlap A4 or deprioritized).
- **3-layer architecture:** primitive `arguzz_invoke.py` (subprocess + parse, single source of truth) → bridge `arguzz_bridge.py` (adapts to `_create_mutation` for `surface=arguzz_exec_fault`) → driver `v6_uniform_driver.py` (modernized, writes through `CoverageDB`).
- **Outcome mapping = Option C (prover_status-primary):** success→APPLIED+`soundness_signal`; error+failures→APPLIED; error+no-failures→APPLIED+`failure_recording_gap` (Path B / verify-segment, the V6 analog of D2.B at_write); start+host_panic→SKIPPED (true C5, ~5.2%); timeout→ERROR.
- **`applied_accounting_mode=True` wired for v6_cTS + hybrid_cTS** (Batch 3) — **its first real use ever** (scaffolded in D2.A, never set in `fuzzer.py` until now; code-verified).
- **opcode_class = D2.A 7-class set** (arm identity) — distinct from the CGC 8-class telemetry taxonomy.
- **`soundness_signal` infra:** the ~2.95% prove_success rows (≈177 per 6000-mut campaign) are tagged in `config_json` for D2.G triage.
- **Enables V6-uniform, V6-cTS, Hybrid-cTS** — but the CLI/variant wiring and the actual cross-variant campaigns are **D2.D/D2.F/D2.G**, NOT D2.C. D2.C ships the building blocks + local tests only.

### B.3 The shape of the convergence (and the gaps)
- **Hybrid-cTS = D1.E's reward engine ⊕ D2.C's Arguzz surface**, but **neither spec fully specifies that fusion** — it's D2.D's job, and it has an unspecified dependency: *does L1 reward enrichment apply to Hybrid, or only V5?* (D1.C scoped L1 to V5; substrategy fire-rates change with V6 kinds → a re-audit gate.) **This is the single biggest unspecified integration seam.**
- **Sequencing:** D1.E ∥ D2.C are independent after D2.A. The fusion is a 3-step: (1) D2.C lands the surface, (2) D1.E lands the reward engine, (3) D2.D + a Hybrid L1 re-audit fuse them. Pro should be asked whether to *interleave* (D2.C → straight to Hybrid, defer D1.E's V5-only re-run) or run D1.E's V5 causal test first.
- **F7 changes the applied-accounting calculus:** since V6 is ~91.6% productive (only ~5% skip), applied-accounting is **low-stakes** and **untested in any real campaign**. Pro could reasonably say "run V6-cTS without obsessing over applied-accounting" — the bandit gets a strong signal regardless.

### B.4 The explicit KEEP / DROP / PRO-DECIDES ledger (the user's core question)
**DROP (settled by findings):** 5 dead A4 kinds (done, PS-1); CGC coarsening as L0 (D1.B saturation inversion); `f_new` L1 channel (D1.C, dead); the 7 non-Pro Arguzz kinds (overlap/low-priority).
**KEEP / INTEGRATE (settled):** 11 live A4 kinds (8 V5 + 3 D2.B-live); 4 Arguzz kinds; `production_log2_corrected` CGC reward (+ byte_addr fix); the 3 L1 signals *for V5*; applied-accounting *for V6 surfaces*; the soundness_signal triage infra; the 4-channel (+C5) rejection model.
**PRO DECIDES (the real asks):**
1. **Decay's fate** — V5-only re-test (D1.E), Hybrid-only re-test (bigger arm space relieves Finding D), or drop. And: is the per-mutation **Bernoulli-floor** scheduler change worth doing (to make gradual decay testable at all)?
2. **L1 composition** — naive OR (≤3) vs per-channel/weighted/scalar-bandit (L2). And **does L1 carry to Hybrid** (re-audit) or stay V5-only?
3. **Sequencing** — D1.E V5 causal test first, or jump to Hybrid and fold reward enrichment in later?
4. **The 177 V6 accepted-candidates** — is triaging these (real accepted-invalid vs fault-no-op) the next real bug-hunt → stand up Mode-B/D3 (co-failure graph + repair/minimization)? **This is the closest thing to a soundness signal anywhere in the project** (A4 had 0; V6 has ~3%).
5. **Pure-A4 next batch** — pursue the §11 mechanism-selected kinds (BIGINT_BYTES_MOD, paging, structural-index), or declare the A4 surface "done" and pour effort into Hybrid + isolation?
6. **Singleton-decay finding** — decay → ~22% fewer singletons / more cascades (p~10⁻⁶). Is this the cascade-heavy-but-less-bug-proximate behavior Pro warned about (§4/§6)? Does it argue *against* decay?

### B.5 New observations / flags from the spec re-read
- **[obs, not a flag]** D2.C v0.3 is internally consistent post-audit; no new contradictions found. F6/F7 confirmed fixed in the working-tree draft.
- **[risk, → tracked as F9]** `applied_accounting_mode` has **never run in any real campaign** (D2.A synthetic test only). Its first production use is D2.C/D2.D's V6-cTS/Hybrid runs. First-real-use risk on a load-bearing accounting path. (Low severity given F7 means it rarely fires, but worth a smoke gate.)

---

## §C. Pro-presentation guidance — how to package this for the architecture call

**Pro's job in this round:** look at *everything implemented + all results*, and rule on the §B.4 "Pro decides" ledger — what to keep, what to drop, what new thing to try — *before* Ivan commits weeks to D1.E/D2.C integration. So the package must be **decision-oriented**, not just a data dump.

**What Pro already knows vs doesn't:** Pro knows only `ProG_Report_3.md` nomenclature (V5, V6-uniform/cTS, Hybrid-cTS, the metric stack, the §15 priorities, the §5 bug-proximity catalog). Pro does NOT know the D1.A–E / D2.A–G sub-deliverable scheme, the findings, or the repo layout. **Every doc handed to Pro must either be already-Pro-facing or carry a nomenclature preamble.**

### C.1 Recommended package structure (decision-oriented, layered)
**Layer 1 — one NEW synthesis cover doc — ✅ WRITTEN: `a4/docs/cloud2/IV_POS_8_PRO_CHECKIN.md`.** Contents:
1. **Nomenclature primer** — map the local scheme to Pro's terms (D1 = housekeeping/scheduler/reward; D2 = Hybrid V7 build; the variant matrix; "live/dead arm"; "L0/L1/L2"; CGC; the 4-channel model). One table.
2. **Per-phase one-pager** (5 short sections, each: *what we did → headline finding → the decision it surfaces*). This is the spine.
3. **The cross-cutting findings** that don't belong to one phase: (a) `verifier_accepted_invalid_count = 0` for all A4 vs **~177 V6 accepted-candidates**; (b) the F7 V6-is-productive correction; (c) NFP-10 (R2 CGC numbers corrected, direction preserved).
4. **The integration plan** (D1.E + D2.C summarized) + **the §B.4 "Pro decides" ledger as explicit numbered questions.** This is what you want Pro to answer.
5. **Pointers** to the attached deep-dive docs (Layer 2) so Pro can drill in.

**Layer 2 — attach these EXISTING Pro-facing artifacts (already self-contained, minimal/no rewrite):**
| Phase | File(s) to hand Pro | Why |
|---|---|---|
| D1.A | `runs/iv_pos_8/d1a/D1A_SUBSECTION.md` | Frozen findings A–F (decay negative + Finding F reward-saturation + Finding D geometry). Already Pro-facing FROZEN format. |
| D1.B | `runs/iv_pos_8/d1b/D1B_SUBSECTION.md` (+ `d1e_handoff_CGC_saturation.md`) | Saturation inversion + NFP-10 + page_class disclosure (Pro asked to confirm page_class def). |
| D1.C | `runs/iv_pos_8/d1c/D1C_SUBSECTION.md` (+ `d1c_signal_shortlist.md` for depth) | The 3 L1 signals + singleton-decay finding + the §5/§8 metric stack Pro asked for. |
| D2.B | **`docs/cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md`** | THE key one — W-17/W-18 proofs, 3-live/5-dead, 4-channel model, §11 next-batch roadmap. Self-contained, written for Pro. |
| cross | `docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md` (NFP-1..11) | Literally built for Pro; gives the architectural-decision context. |
| plans | `docs/cloud2/IV_POS_8_D1_E_SPEC.md` + `IV_POS_8_D2_C_SPEC.md` | The integration plans Pro reacts to (the "react to results AND plan" workflow). Note D2.C is v0.3 (corrected); D1.E v0.2.1. |

**Layer 3 — figures + raw evidence (REVISED — these are NOT redundant):** The subsection markdowns *reference PNG plots by relative path*; if Pro gets only the `.md`, the figures don't render. So the key PNGs carry visual evidence the text points at and must travel with the subsections. The **highest-value figures to attach as PNGs** (most reliable ingestion format for Pro): `d1b/plots/d1b_saturation_overlay_v5.png` (the saturation-inversion centerpiece), `d1a/plots/04_mode_share_over_time.png` (decay engaged) + `03_local_context_final.png` (the null), `d1c/plots/d1c_batch1_fire_rate_post_local.png` (L1 signals firing post-local). The **executed notebooks** (`IV_POS_8_D1{A,B,C}_NOTEBOOK.html`) hold the *same numbers* as the subsections (so numerically redundant) but add full tables + all plots = a **verification layer** for a thorough model. Caveat: `.html`/`.ipynb` with embedded base64 images may not render reliably in Pro's uploader — prefer uploading the standalone PNGs (they already exist on disk) and offer the notebooks/CSVs on-demand for deep verification.

### C.2 What Pro specifically needs from each phase (the decision it must inform)
- **D1.A →** "floor-decay alone is inert because reward saturates (Finding F); scheduler geometry caps gradient testing (Finding D)." *Pro decides:* keep decay? do the Bernoulli-floor change?
- **D1.B →** "CGC coarsening can't extend the window (saturation inversion); production_log2 is the reward CGC; page_class is an analysis lens not a reward win — please confirm its definition." *Pro decides:* confirm CGC reward; confirm/redirect page_class.
- **D1.C →** "3 orthogonal post-local L1 signals exist (the lever D1.A/B lacked); f_new dead; A4 yields zero accepted-invalids; decay→cascades (singleton finding)." *Pro decides:* L1 composition; L1-on-Hybrid; is the cascade finding a red flag for decay.
- **D2.A →** "foundation done; applied-accounting scaffolded but never run." *Pro:* mostly FYI.
- **D2.B →** "A4 catalog is narrower than feared (3/8 live); mechanism-selection works; here's a high-confidence next batch (§11); reusable rejection machinery." *Pro decides:* pursue §11 pure-A4 batch or declare A4 done.
- **F7 (cross) →** "V6 is highly productive (~91.6%) + ~177 accepted-candidates/campaign." *Pro decides:* triage the 177 (stand up Mode-B/D3)? weight on applied-accounting?

### C.3 On giving Pro `central-planning-1.md` directly
**Recommendation: don't hand it as-is; use it as the SOURCE for the Layer-1 synthesis instead.** Reasons: it assumes repo access, carries internal workflow scaffolding (the ⚑ flags are *our* audit trail, not Pro's concern), and mixes "what's done" with "what to verify." If Ivan still wants to give Pro a single big doc, the minimum changes are: (a) prepend the C.1 nomenclature primer, (b) strip or relabel the ⚑ flags section as "internal QA — resolved," (c) add a one-line "Pro: you don't have repo access; paths are for Ivan's reference." But a purpose-built ~5-page synthesis will land better than a 1000-line internal planning doc. **(NB: if we DO decide to give Pro central-planning-1.md, that triggers the front-matter-definitions work Ivan flagged as out-of-scope-for-now.)**

### C.3b Packaging format (Ivan's Q4: PDF vs HTML; limited file count) — RESOLVED 2026-06-19
**Recommended: render each Pro-facing markdown to a self-contained PDF with figures embedded** (markdown→PDF via pandoc). Rationale: (a) PDFs ingest more reliably in ChatGPT than HTML-with-base64; (b) embedding figures = *one file per doc*, no separate PNGs, solves both the "figures don't render from `.md`" problem and the file-count limit; (c) the raw notebooks become unnecessary (numbers already in the subsections; full tables available on-demand). So the upload set = ~8 PDFs: `PRO_CHECKIN`, the 3 subsections (with figures), the D2.B mechanism report, the 2 specs, `NOTES_FOR_PRO`. **Fallback (no PDF tooling):** markdown-as-text + the 4 key PNGs as image uploads (ChatGPT handles PNG via vision).

**DONE 2026-06-19 (notebook PDFs):** the 3 executed notebooks were rendered HTML→PDF via weasyprint → `a4/docs/cloud2/pro_checkin_attachments/IV_POS_8_D1{A,B,C}_NOTEBOOK.pdf`. D1A (270KB, ~10 figures) and D1B (485KB, ~12 figures) render their plots; **D1C (28KB) is table/text-heavy and its 2 high-res fire-rate plots live as standalone PNGs** (`d1c/plots/d1c_batch1_fire_rate_{full,post_local}.png`) — attach those alongside the D1C notebook if the fire-rate figures are wanted. *(Note: the Pro-facing subsection/cover docs themselves still need rendering to PDF-with-figures, or upload as text + the 4 key PNGs — the notebook PDFs are the verification layer only.)*

### C.4 How to introduce it to Pro (suggested framing)
> "Since ProG_Report_3, I built out the housekeeping/scheduler/reward work (D1) and the Hybrid-V7 foundation + pure-A4 catalog expansion (D2). These were deliberately separate components; D1.E and D2.C are the integration phases that bring them together, and I need your architecture call on what to integrate vs drop before I commit. Attached: a synthesis cover doc with per-phase findings and my explicit open decisions, plus the self-contained subsection/mechanism reports for depth. Headline results to weigh: [V5 decay negative + why; CGC saturation inversion; the 3 L1 signals; 3-live/5-dead A4 with mechanism proofs; A4 yields 0 accepted-invalids but V6 yields ~3%]. My integration plans are the D1.E and D2.C specs — please react to both the results and the plans."

### C.5 Open questions for Ivan about the presentation — RESOLVED 2026-06-19
1. ✅ **Fresh doc** (Ivan's call) → `IV_POS_8_PRO_CHECKIN.md` written.
2. ✅ **Frame the 177 honestly as untriaged/mostly-no-op** (Ivan's view: ~2.2% are no-ops). Done in §3.1 — presented as the only bug-signal but with the no-op confound front-and-center; not over-promised.
3. ✅ Drafted. Plus: the accept-signal/no-op architectural question is now a first-class decision (§5 Q4), framed per Opus-CP's "don't reward accept + add propagation filter + Mode-A/B split" counsel.
4. *(new, open)* Which exact PNG figures + whether to attach the notebooks — see revised Layer-3 above; recommend the 4 key PNGs + notebooks on-demand.
5. *(new, open)* Give Pro `central-planning-1.md` too? Only with a definitions preamble + flags relabeled — but `PRO_CHECKIN.md` already carries the definitions, so likely redundant for Pro.
