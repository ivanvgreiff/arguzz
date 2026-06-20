# IV.POS.8 — Phase 4 Spec: D2.G — Territory analysis, fault-propagation triage, and the Case A–E verdict

**Version:** v1.0 — **LOCKED FOR IMPLEMENTATION** (authored by Opus-CP acting as D2-Opus, 2026-06-20)
**Phase:** New_Master §2 **Phase 4** · Pro: `ProG_Report_4.md` §Phase 4, **Q4** (propagation filter), **§5 Cases A–E**, **§6 Suggestions 3/4/5**, §4 (excluded-kind rule)
**Governing plan:** [`New_Master.md`](New_Master.md) §2 Phase 4, **§3 Case A–E gate**, §4 deferred (Mode-B/D3)
**Consumes:** the D2.F four-variant checkpoint DBs (4 variants × R=3 × N=10000) + the V5 archive (reference) — via the D2.F collection manifest.
**Builds on:** D2.E Gate E ingestion dry-run; reuses the `a4/runs/iv_pos_7/analysis/` suite.
**Produces:** `build_d2_artifacts.py`, CSVs, plots, the **Pro-facing D2 report**, and the **D3 design sketch**. Answers the **Case A–E** gate.
**Can be built NOW** (campaign-independent): validate on the F.1 smoke → first returned N=10000 jobs → full campaign (Ivan's phased plan).

---

## 0. Scope & non-goals

### 0.1 What D2.G IS
The analysis layer that turns the raw four-variant DBs into the **checkpoint verdict** (Case A–E) by measuring **territory, rejection channels, and accepted-candidate propagation — not raw loc count** (Pro §Phase 4). Its load-bearing, novel deliverable is the **fault-propagation triage filter (Q4)**: classify every accepted proof into `accepted_noop` / `accepted_propagated_candidate` / `accepted_hidden_global_reject` so we definitively know whether we have or have not found soundness bugs. Everything else (territory set-algebra, CGC/local AUC, channel split, the S3/S4/S5 scores, arm occupancy) is largely **reuse/adapt** of the existing `iv_pos_7/analysis` suite.

### 0.2 What D2.G is NOT
- **NOT heavy repair/minimization (Mode-B / D3).** D2.G *identifies* `accepted_propagated_candidate`s; the deep "is this a real soundness bug" adjudication (witness repair/minimization) is **D3** (deferred, New_Master §4). D2.G produces the **D3 design sketch**, not D3 itself.
- **NOT re-running the campaign.** It analyzes the D2.F DBs. (It *does* re-run the small accepted-candidate subset with `--trace` for the triage — §3 — which for the full campaign is a POS rerun pass.)
- **NOT activating L1 / changing scheduling.** The L1 columns are logged (D2.D, inactive); D2.G **re-audits** them (Pro Q3) but does not activate.
- **NOT a paper.** Single-guest checkpoint analysis (Pro D7: multi-guest before any "beats Arguzz" headline).

### 0.3 Phased validation (Ivan's plan — LOCKED)
Build + validate incrementally so pipeline bugs surface on cheap data first:
1. **Smoke (N=100, 8 DBs, present):** validate ingestion + every metric shape + the **triage filter against its known oracle** — the 8 V6_cTS INSTR_WORD_MOD accepts triage to **8 no-op / 0 propagated / 0 hidden-reject** (F22 — all are no-ops once `waddr` word-truncation is accounted for; 3939's offset 4→6 is within-word). If the filter reports any `propagated` on this smoke set, it's over-classifying.
2. **First N=10000 jobs (as they land):** validate scoring + the Case-comparison machinery + the POS triage-rerun dispatch on real-scale data.
3. **Full campaign (4×3 N=10000):** the production run → the Pro report + Case verdict + D3 sketch.

---

## 1. Background — what D2.G must honor (verified this session)

### 1.1 The Case A–E gate (New_Master §3 / Pro §5) — the decision D2.G informs
The two comparisons that decide everything: **does V6-cTS beat V6-uniform** (same 11 Arguzz kinds), and **does Hybrid-cTS beat V6-uniform** (total useful territory). The 2×2 → Cases A–E → the Phase-5 next move. **"Beat" is measured on *useful territory* (unique normalized locs + CGC + bug-proximity), NOT raw `constraint_loc_final`** (Pro §Phase 4).

### 1.2 Session findings the analysis MUST bake in
| Finding | Consequence for D2.G |
|---|---|
| **F19 — accepts are no-op-dominated; output is a sentinel** | The triage MUST use **trace/witness propagation, not journal/output** (Pro Q4 says this; I confirmed output is `0xDEADBEEF` sentinel). The 8 smoke accepts (5 no-op/3 propagated/0 real) are the **test oracle**. |
| **F18 — V6_uniform telemetry is sparse** | V6_uniform DBs have **empty** `mutation_rewards`/`reward_counterfactuals`/`mutation_substrategy`/`bandit_decisions`. D2.G must derive V6_uniform's `d_loc` (= distinct `(loc,major,minor)` per mutation) + `singleton` from the **`failures` table**, not `mutation_rewards`; and skip arm-occupancy/L1 for it (no bandit). Compare variants **only on metrics all four support**; mark cTS-only metrics as such. |
| **Arm-weighting confound** | V6_cTS samples per-**arm** (over-weights high-arm-count kinds, e.g. INSTR_WORD_MOD); V6_uniform per-**kind**. The V6-cTS-vs-V6-uniform comparison must **normalize** (report per-kind, and compare on territory/unique-useful, not raw counts) — else the Case verdict is confounded. |
| **ISS-1 — fault-corroboration residual** | The triage's `--trace` rerun **resolves ISS-1** (it's the corroboration pass Pro deferred). |
| **CGC `cycle_phase` collapse (D1-style)** | Re-run the field-diversity collapse check on N=10000 CGC; flag any dead dimension. |
| **F12 — cold-start fairness** | Satisfied at N=10000; D2.G reports the cold-start vs floor vs adaptive pull split (and whether adaptive down-weights INSTR_WORD_MOD — a real cTS-value test). |

### 1.3 Reuse map (from `a4/runs/iv_pos_7/analysis/` — do NOT rebuild)
**Reuse directly / adapt-variant-list:** `discover.py` (`discover_dbs`, `parse_db_path` — update `SELECTOR_TO_VARIANT`), `metrics.py` (`compute_metrics_for_db`, `compute_metrics_frame`, `aggregate_by_variant`, `_coverage_curve`/`trapz` AUC, `_shannon_entropy`, `_zone_entropy_from_bandit`), `v6_comparison.py` (`loc_overlap_frame`, `apples_to_apples_frame`, `a4_territory_coverage_frame`), `constraint_loc_normalize.py` (`read_normalized_constraint_locs`), `discovery_rate.py` (`discovery_rate_by_kind_frame`), `cgc_variants.py` (CGC counts incl. `production_log2`), `bug_proximity.py` (`compute_tier2_metrics_row`, the Tier-1 signal fns — already ported to `l1_signals.py`), `kind_translation.py`, `stats.py` (`paired_tests`), `per_loc_v2.py`, `counterfactuals.py`, `collection_validator.py`.
**Build NEW:** the propagation triage (§3), `rejection_channels.py` (§5.3 — no existing channel classifier), the S3/S4/S5 score assembler (§6), `d2g_plots.py`, `build_d2_artifacts.py` (entry point, modeled on `build_v6_pro_artifacts.py`).
**Skip:** `per_arm_diagnostic.py` (V5-bandit-specific), `v0_anchor.py`.
**Caveat (ISS-DD-1):** `bug_proximity.py` has a relative `.metrics` import → not cleanly importable standalone; port the needed fns (the Tier-1 set already lives in `a4/standalone/l1_signals.py`) rather than cross-import.

---

## 2. Architecture
D2.G analysis lives in a new package **`a4/runs/iv_pos_8/d2g/`** with `build_d2_artifacts.py` as the entry point, importing the reusable `iv_pos_7/analysis` functions where they import cleanly and porting where they don't. Pipeline:
```
collection manifest (D2.F) ─► ingest (discover+validate) ─► per-DB metrics ─► cross-variant aggregation
   ├─► territory set-algebra (§4)
   ├─► CGC/local AUC + channel split + arm occupancy (§5)
   ├─► PROPAGATION TRIAGE (§3)  ──(accepts → rerun w/ --trace)──►  noop / propagated / hidden-reject
   ├─► S3/S4/S5 scores (§6)
   └─► Case A–E determination (§7) ─► Pro report + plots + D3 sketch (§9)
```

---

## 3. The fault-propagation triage filter (Q4 — the centerpiece) — LOCKED

**Goal:** for every accepted proof (`outcome='applied' AND verifier_accepted=1`, equivalently `config_json.soundness_signal=true`), determine definitively whether it is a no-op, a real propagated candidate, or a hidden global reject — so the "soundness_signal count" stops being meaningless raw noise.

### 3.1 Two-tier classification (minimize expensive reruns)
**Tier 1 — cheap DB pass (no rerun), per accept row:**
- `fault_applied` — the row exists with a kind/step/seed (the campaign already injected; corroborated by `--trace` in Tier 2).
- `local_failures = (num_failures > 0)` — should be 0 for an accept (sanity).
- **`global_residue = (global_failures rows for this mutation_id > 0)`.** If an accept has **nonzero `global_failures`** → **`accepted_hidden_global_reject`** (Hook 3's residue flagged it even though the prover accepted — the strongest soundness signal). *This is detectable from the existing DB with NO rerun* (the F13 fix means the campaign already captured Hook-3 residue). **Validate on smoke first** (do the 8 accepts have global_failures? if all 0, all 8 are no-op/propagated, matching the oracle).

**Tier 2 — `--trace` rerun pass (only for accepts NOT already classified hidden-reject):**
Re-run each remaining accept with `--trace --inject --inject-step S --inject-kind K --seed <iter_seed>` (the exact recorded params) + the campaign env, capture the **faulted trace**, and compare to the cached **baseline trace**. **The trace is COARSE — `{step,pc,instruction,assembly}`, no register/memory values, and the only "output" is the `0xDEADBEEF` sentinel (no usable final-state digest — verified).** So **neither full-trace-hash NOR PC-only is a correct propagation detector** (lesson from the B2 follow-up, F21):
- **Full-trace-hash OVER-classifies:** it includes the inject-step `assembly` string, which changes whenever `INSTR_WORD_MOD` touches immediate bits — even for a cosmetic change like a branch *target* on a **not-taken** branch (`beq …,72`→`…,104`, PC sequence unchanged). That is NOT propagation.
- **PC-only UNDER-classifies:** it misses **data-flow** divergences with identical control flow — e.g. a store/load offset change that **crosses a word boundary** (`offset>>2` changes) writes a different memory word, yet PC is identical. **Suppressing all inject-step changes would blind the filter to the most subtle soundness bugs (data corrupted, control flow intact).** (Note F22: a *within-word* offset change like 3939's 4→6 is the opposite — a true no-op, because risc0 word-truncates the address; see rule 3.)
- **LOCKED classification rule with EVIDENCE TIERS (control-flow OR data-flow, semantics-aware — refined per the F21 dispute):**
  1. **post-inject PC sequence OR post-inject trace hash (steps > inject) differs** → `propagated_candidate` / **evidence=`strong`** (observed downstream divergence — Pro Q4 directly measured).
  2. else if **inject-step disassembly is byte-identical** → `accepted_noop`.
  3. else (inject-step disassembly changed, PC + post-inject trace identical):
     - inject-step instr is a **control-transfer (branch/jump)** → `accepted_noop` / **evidence=`cosmetic`** — the mutated field (branch *target*) is **not used** (branch resolved the same; condition/registers unchanged), so it is provably inert.
     - inject-step instr is a **store/load** → **compute the effective WORD address, not the byte offset (F22 — decisive).** risc0 is **word-addressed**: `ByteAddr.waddr() = addr/4` truncates the low 2 bits (`addr.rs:35`), and the misalign trap (`StoreAddressMisaligned`) is **gated off during fault injection** (`rv32im.rs:994`, `&& !is_injection_enabled()`). So a store/load offset change that only touches the **low 2 bits keeps the same word** (`offset>>2` unchanged) → identical memory write → `accepted_noop` / **evidence=`word_truncated`** (e.g. 3939: offset 4→6, both `>>2 == 1` → same word → TRUE no-op). Only an offset change that **changes `offset>>2` (crosses a word)** → `propagated_candidate` / **evidence=`weak`** (different word written; ISA-deducible, surfaced for D3). Computable from the disassembly offsets alone (same base register).
     - inject-step instr is **compute** (ALU immediate/operand changed, PC identical) → `propagated_candidate` / **evidence=`weak`** (register result changes; surfaced for D3).
- **Honest framing (do not overstate):** `weak` = a *surfacing heuristic* (a used operand changed in a way that crosses a word / changes a register, so we cannot rule out an effect the coarse trace can't show) — NOT a verified divergence. `word_truncated` and `cosmetic` are *provable* no-ops (same word written / branch not taken). The principle: a mutated field is inert iff it is **not used** (cosmetic branch target) **or maps to the same word/value** (word-truncated store) — both → no-op.
- **Never use journal/output equality** (sentinel — F19/Pro Q4). **Never reduce to PC-only** (would suppress the `weak` data-instruction tier = the data-corruption-with-intact-control-flow blind spot, F21). Injection itself IS corroborated by the `<fault>` tag on the `--trace` rerun (`word:X => word:Y`) — available for ISS-1 corroboration.

### 3.2 The rerun dispatch (scales smoke→full)
- **Smoke / ≤10 accepts → local** (`arguzz_invoke.run(..., include_trace=True)` + the §3.1 semantics-aware compare). **Oracle test (corrected — F22): the 8 V6_cTS smoke accepts are ALL no-ops → 8 noop / 0 propagated / 0 hidden.** Sub-labels: 174/524/618/3961/3931 = byte-identical (`none`); 2726/1648 = branch target on a not-taken branch (`cosmetic`); **3939 = store offset 4→6, same word after `waddr` truncation (`word_truncated`)**. *(History: original full-hash gave 5/3/0 — over-classified branches; my F21 7/1/0 still over-classified 3939 as a within-word store change; the F22 deep dive — risc0 word-truncates `waddr` + the misalign trap is injection-gated — proves 3939 writes the identical word → true no-op. Composer's original 8/0/0 was right.)* The filter must still surface a CROSS-word store change or any post-inject divergence as `propagated` at N=10000.
- **Full campaign (hundreds of accepts) → POS rerun pass** (>10 real mutations → POS, per the run policy). **Reuse the D2.F `chain_dispatcher`**: collect all accepts across the 4×3 DBs, **dedupe by `(guest, kind, step)`** (a given inject site is deterministic → rerun the unique sites once, not every replicate), generate a `--trace` rerun chain manifest, dispatch on the reserved nodes, pull the traces, classify offline. Dedup is essential — it can cut thousands of reruns to the unique-site count.

### 3.3 Outputs
`d2g_accept_triage.csv`: one row per accept — `variant, seed, mutation_id, kind, step, opcode_class, class ∈ {noop, propagated_candidate, hidden_global_reject}, trace_changed, global_residue, evidence`. Plus a per-variant summary: raw accept count → triaged buckets. **The `soundness_signal` count is ONLY ever reported post-triage** (raw is no-op-dominated). The `propagated_candidate` + `hidden_global_reject` rows are the input to the **D3 sketch** (Mode-B targets) and Pro's `soundness_score` (§6).

---

## 4. Territory decomposition (§Phase 4) — reuse `v6_comparison.py`
Per-variant **normalized-loc sets** (via `short_loc()` / `read_normalized_constraint_locs`) and set-algebra across the 4 variants + V5 archive:
- **common** / **A4-only** (V5 ∪ Hybrid-A4-arms) / **Arguzz-only** (V6-uniform ∪ V6-cTS ∪ Hybrid-Arguzz-arms) / **Hybrid-only** / **V5-signature ECALL-MRET contexts** / **V6-exclusive normalized locs**.
- For Hybrid, attribute each loc to its surface via the arm-id shape (2-pipe = A4, 5-field `arguzz_exec_fault` = Arguzz — verified disjoint/kind-clean this session) — or by kind-set membership for V6_uniform (no arms).
- Report raw-loc and normalized-loc keyings (the normalized one is the headline; raw is the sanity check).
Output: `d2g_territory.csv`, `d2g_loc_overlap.csv`, `d2g_apples_to_apples.csv`.

---

## 5. Metrics (§Phase 4 list)
Reuse `metrics.py`/`discovery_rate.py`; add the channel split.
- **CGC final + CGC-AUC** (production_log2_corrected — the locked L0); **local-context AUC**; discovery-rate-by-kind curves. **+ the D1-style CGC field-collapse check** (distinct values per CGC context field — `family/address_region/txn_role/cycle_phase`; flag any collapsed to 1 at N=10000).
- **applied-pull count, skip/error rate** (from `mutations.outcome`).
- **arm occupancy + entropy** (from `bandit_decisions` for V6_cTS/Hybrid; **cold/floor/adaptive mode split**; whether adaptive down-weights INSTR_WORD_MOD — the cTS-value test. N/A for V6_uniform — no bandit).
- **Rejection-channel split (NEW `rejection_channels.py`):**
  - **C1 = local constraint_fail** → applied + `failures` rows (local `constraint_loc`).
  - **C2 = verify-segment / global-polynomial** → applied + `config_json.failure_recording_gap=true` (Path B: applied, no local failures, prover error). *(Both paths write `failure_recording_gap` to config — F18-safe.)*
  - **C3 = Hook-3 global residue** → `global_failures` rows present. **This is the same signal as the triage's `accepted_hidden_global_reject` (§3 Tier-1)** — for *rejected* rows it's a residue-channel; for *accepted* rows it's the hidden-reject candidate. The §6 `soundness_score`'s "no C3" = `global_failures` count 0. (C4 dispatcher errors are out of scope / negligible here.)
  - **C5 = guest panic during prover startup** → **`outcome='skipped'` ALONE.** ⚠️ **Do NOT gate on `config_json.host_panic`/`prover_status`** — the **fuzzer writes a minimal `config_json`** (`{kind,step,pre_post,opcode_class,seed,soundness_signal}`) and omits those, while the **driver writes a rich one** (F18-extension, **F20**). Since `outcome='skipped'` arises *only* from `start+panic` in `arguzz_invoke._classify_outcome`, `skipped ⟺ C5` for the Arguzz path — map it directly from `outcome`, never from driver-only config fields. **(B1 bug: the shipped classifier required the config marker → mislabeled all V6_cTS/Hybrid C5 skips as `skipped_other`. Fix before B3.)**
  - **General F18/F20 rule:** classify channels from `outcome` + `failures`/`global_failures` columns, NOT from `config_json` fields that only the driver populates. Output `d2g_rejection_channels.csv`.

---

## 6. Scoring (Pro Suggestions 3/4/5) — reuse `bug_proximity.py` Tier-2 + assemble
Report **separate scores** (do NOT collapse to one Bernoulli — S3):
- **survey_score** — `l_new, g_new, s_new` (from `reward_counterfactuals` for fuzzer variants; derive for V6_uniform from coverage/CGC deltas).
- **proximity_score** — `singleton_failure`, `d_loc_le_2`, `d_glob_le_1`, low co-failure degree (Tier-1 fns; V6_uniform's `d_loc`/`singleton` from `failures` per F18).
- **soundness_score** — **`accepted + propagated + no C1/C2/C3/C5`** ⟵ **consumes the §3 triage `propagated_candidate`/`hidden_global_reject` output** (this is why the triage is upstream).
- **global_score** — C2/`failure_recording_gap` novelty, Hook-3 residue novelty.
- **S4 repairability_proxy** (low d_loc/d_glob, singleton, recurring loc w/ different co-failure sets, accepted/proof_generated, C2-only) — logged per candidate, targets D3.
- **S5 unique-useful-failures** (`unique_locs_with_d_loc≤2`, `unique_locs_with_singleton_hit`, per-loc min d_loc/d_glob, per-loc singleton-ever) — reuse `compute_tier2_metrics_row`'s `cat_a_pro_s8_*`. Directly answers "coverage is less useful if only in giant cascades."
Output: `d2g_scores.csv` (per variant×seed), `d2g_unique_useful.csv`.

---

## 7. The Case A–E determination (§7) — LOCKED method
1. Compute, per variant (mean ± std over R seeds), the **useful-territory** metrics: unique normalized locs, CGC final/AUC, unique-useful-failures (S5), triaged soundness candidates (§3). Use `paired_tests` for significance.
2. **V6-cTS vs V6-uniform** and **Hybrid vs V6-uniform** on useful territory — **normalized for the arm-weighting confound** (report per-kind territory and the pooled territory; flag if a "win" is driven solely by INSTR_WORD_MOD over-sampling).
3. Map the 2×2 outcome → **Case A/B/C/D/E** (New_Master §3) and state the **Phase-5 next move** the Case prescribes. Do not over-claim: single-guest, directional (Pro D7).
Output: `d2g_case_verdict.md` (the verdict + evidence + the prescribed next move).

## 8. Excluded-kind rule (§4)
If V6-cTS shows the **4 excluded Arguzz kinds** (those not in Hybrid's SELECTED set) have high unique coverage / accepted-propagated / bug-proximity → recommend a **Hybrid-full / Hybrid+excluded** follow-up. Output a row in the verdict. (Remember the naming-overlap caveat: Arguzz `PRE_EXEC_REG_MOD` ≠ A4's.)

---

## 9. Artifacts (deliverables)
- **CSVs:** `d2g_metrics_table.csv`, `d2g_metrics_aggregate.csv`, `d2g_territory.csv`, `d2g_loc_overlap.csv`, `d2g_apples_to_apples.csv`, `d2g_discovery_rate_by_kind.csv`, `d2g_rejection_channels.csv`, `d2g_accept_triage.csv`, `d2g_scores.csv`, `d2g_unique_useful.csv`, `d2g_paired_tests.csv`, `d2g_COLLECTION_REPORT.json`.
- **Plots (`d2g_plots.py`):** CGC + local AUC curves per variant; territory Venn/diagram; per-kind discovery heatmap; channel-split bars; accept-triage breakdown; arm cold/floor/adaptive mode timeline (cTS variants).
- **The Pro-facing D2 report** (`IV_POS_8_D2_REPORT.md`): the Case verdict + the territory/triage/score story + the honest caveats (single-guest, arm-weighting confound, raw-vs-triaged accepts, N=10000 cold-start split).
- **The D3 design sketch** (`IV_POS_8_D3_DESIGN_PROPOSAL.md` stub): Mode-B repair/minimization targeting the `propagated_candidate`/`hidden_global_reject` rows; the repairability_proxy ranking.

---

## 10. Batch structure (mapped to the phased validation)
- **B1 — Ingestion + metrics + territory + channels (validate on smoke).** `d2g/` package; `discover`/`metrics`/`territory` adapted to the 4 variants; NEW `rejection_channels.py`; CGC/AUC + field-collapse check; arm occupancy. Run on the 8 smoke DBs: assert shapes, V6_uniform sparse-telemetry handled (F18), no crashes. **Gate:** all CSVs produced for smoke; V6_uniform rows populated where derivable, NaN/marked where not.
- **B2 — The propagation triage filter (validate on the 8-accept oracle).** Tier-1 DB pass + Tier-2 local `--trace` rerun + classification; the POS rerun-dispatch design (chain_dispatcher reuse + dedup). **Gate:** the 8 V6_cTS smoke accepts triage to exactly **8 noop / 0 propagated / 0 hidden-reject** (F22; 3939 = `word_truncated` no-op, not propagated); `accepted_hidden_global_reject` Tier-1 logic validated on smoke.
- **B3 — Scores + Case machinery (validate on first N=10000 jobs).** S3/S4/S5 assembler; the V6-cTS-vs-V6-uniform / Hybrid-vs-V6-uniform comparison with confound-normalization; `paired_tests`. **Gate:** runs on the first returned N=10000 DBs; produces a provisional Case read; POS triage-rerun dispatch tested on one variant's accepts.
- **B4 — Full run + report + D3 sketch (on the complete 4×3 campaign).** Full pipeline + POS triage-rerun pass on all accepts; the Pro report + plots + Case verdict + D3 sketch + excluded-kind recommendation. **Gate:** the verdict is evidence-backed and states the Phase-5 next move.

---

## 11. Acceptance checklist
- [ ] `d2g/` package + `build_d2_artifacts.py` entry point; reuses `iv_pos_7/analysis` where clean, ports where blocked (ISS-DD-1).
- [ ] All §9 CSVs produced; V6_uniform handled per F18 (failures-derived proximity; cTS-only metrics marked N/A).
- [ ] **Triage filter reproduces the smoke oracle** (8 noop / 0 propagated / 0 hidden on the 8 V6_cTS accepts; F22) using word-address-aware compare for store/load (`offset>>2`), control-flow for branches — **not** full-hash (over-classifies branches), **not** byte-offset (over-classifies within-word stores), **not** PC-only (under-classifies cross-word stores).
- [ ] `accepted_hidden_global_reject` detected cheaply from `global_failures` (Tier-1); validated on smoke.
- [ ] Territory set-algebra (common/A4-only/Arguzz-only/Hybrid-only/V5-ECALL-MRET/V6-exclusive) on normalized locs; surface attribution correct for Hybrid.
- [ ] C1/C2/C5 channel split for **all 4** variants; CGC field-collapse check at N=10000.
- [ ] S3 separate scores (survey/proximity/soundness/global); S4 repairability; S5 unique-useful — soundness_score consumes the triage.
- [ ] Case A–E verdict with confound-normalized comparison + significance + the prescribed Phase-5 move; excluded-kind recommendation.
- [ ] Pro report + plots + D3 sketch; **soundness count reported post-triage only**; honest caveats.
- [ ] ISS-1 resolved (the triage rerun is the corroboration pass). New_Master Phase 4 → DONE.

---

## 12. Risks / flags
| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **DG-1 — triage rerun cost** | Hundreds–thousands of `--trace` reruns for the full campaign's accepts = many POS-hours. | **High** | Tier-1 cheap pass first (hidden-reject from DB, no rerun); **dedup accepts by `(guest,kind,step)`** before rerunning (deterministic inject sites); POS dispatch via chain_dispatcher; this is the ISS-1 corroboration pass anyway. |
| **DG-2 — arm-weighting confound corrupts the Case verdict** | V6-cTS "wins/loses" could be an INSTR_WORD_MOD over-sampling artifact, not a real cTS effect. | **High** | §7 normalizes: per-kind territory + flag any win driven by one over-sampled kind; report the cold/floor/adaptive split. |
| **DG-3 — V6_uniform telemetry gap (F18)** | Naively comparing reward/L1 metrics across variants breaks (V6_uniform empty). | Med | F18: derive d_loc/singleton from `failures`; mark cTS-only metrics N/A for V6_uniform; compare only on shared metrics. |
| **DG-4 — over-filtering accepts as no-ops on output** | Calling a candidate a no-op because output unchanged (it's a sentinel) would hide a real bug. | Med | Pro Q4 + F19: classify on **trace**, never journal/output; the oracle test enforces this. |
| **DG-5 — propagated_candidate ≠ confirmed bug** | A `propagated_candidate` (trace changed, verifies) is usually a valid-alternate, not a soundness bug. | Med | D2.G *identifies* candidates; the real adjudication is **D3** (Mode-B). Report candidates as "to-adjudicate," not "bugs." Sub-rank by `hidden_global_reject` (stronger) vs pure-propagated. |
| **DG-6 — CGC dead dimension** | `cycle_phase` (or another field) may collapse to 1 value (D1-style), inflating/hollowing CGC. | Low–Med | §5 field-collapse check at N=10000; flag for the CGC-reward review. |

---

## 13. Tracked issues (LIVING ANNEX)
*(None at lock. Composer adds `ISS-*` as batches surface them.)*

## 14. Sequencing & dependencies
- **Depends on:** D2.F DBs (smoke now; N=10000 as they land) + collection manifest; D2.E gates.
- **Resolves:** ISS-1 (fault-corroboration via the triage rerun); the F19 triage gap; re-audits L1 (Pro Q3) on V6/Hybrid telemetry.
- **Feeds:** Phase 5 (the Case verdict picks the next move) + the **D3 design sketch** (Mode-B on propagated candidates).
- **Carry-forward:** F18 (V6_uniform telemetry), arm-weighting confound, CGC field-collapse.

## 15. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-20 | Opus-CP (acting D2-Opus) | v1.0 LOCKED | Initial spec. Centerpiece = the Q4 fault-propagation triage (two-tier: cheap DB hidden-reject pass + `--trace` rerun no-op/propagated classification on **trace, not output**), prototyped this session with the 8-accept oracle (5 noop/3 propagated/0 hidden). Territory/CGC/AUC/scoring = reuse `iv_pos_7/analysis`; NEW = triage + `rejection_channels` + scores + plots. Bakes in F18 (V6_uniform telemetry), arm-weighting confound, ISS-1 (resolved by triage rerun), sentinel-output (F19), CGC collapse check. 4 batches mapped to Ivan's smoke→first-N10000→full validation. Answers Case A–E. Grounded in ProG_Report_4 §Phase4/Q4/§5/§6, the reuse map, and this session's reproduction. |
