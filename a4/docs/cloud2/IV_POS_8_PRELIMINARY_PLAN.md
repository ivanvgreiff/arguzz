# IV.POS.8 — Preliminary Plan (cloud2)

**Branch:** `cloud2`
**Date:** 2026-06-16
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Source:** `a4/docs/cloud2/ProG_Report_3.md`
**Status:** **DRAFT** — needs Ivan review before locking; details intentionally not yet specified

---

## 0. What Pro told us

Pro's overall verdict:

> V5 is a real architectural improvement, but it is not yet evidence that post-execution trace fuzzing broadly beats Arguzz at bug finding. … The next move should be **hybridization plus bug-isolation machinery**, not more V5-only tuning.

### Pro's §15 priority order (their words)

1. **Hybrid V7** — V5 scheduler + selected V6 kinds + applied-mutation accounting + normalized telemetry; compare V5, V6-uniform, V6-cTS, Hybrid-cTS
2. **Bug-isolation layer** — co-failure graph + repair templates + minimization loop (TXN word/prev_word, prev_cycle, PC/instruction-fetch, major/minor/instr_word, machine_mode/user-kernel, ECALL/MRET)
3. **Pure-A4 mutation expansion** — TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, TXN_CYCLE_PHASE_MOD, CYCLE_PC_MOD
4. **Decaying-floor V5** — V5-static vs V5-decay vs V5-two-stage
5. **Multi-guest suite** — stock SHA, ECALL/MRET, control-flow, memory-stress, accelerator

### Pro's smaller asks (scattered across §5, §6, §7, §11, §12)

- §6: verify V3/V4 are "survey-depth variants" (use `d_loc`, singleton-failure, co-failure graph, repair success)
- §7: V5 decaying-floor variant (don't just sweep `coverage_floor_fraction` 0.50/0.55/0.60/0.65)
- §11: coarser CGC variants (drop log2 buckets, report three variants: region-only, log4, page_class)
- §12: parallel-execution noise — keep default parallelism + 10+ seeds; file upstream only if reproducible independently
- §5: new metric stack (exploration / bug-proximity / isolation / fair-Arguzz)
- §13: multi-guest — important but not first

---

## 1. Critical reasoning about how to organize ourselves

### Why incremental delivery (Ivan's call) is right here

Pro's framing implies a **multi-month architecture build** (Hybrid V7 + bug-isolation + catalog expansion). If we go heads-down on the full thing and present a megabatch in 3 months, three bad outcomes are possible:

1. We spend 3 months on a path Pro would have steered away from at month 1
2. Pro reads a 50-page report and pushes back on framing we cannot easily change
3. We accumulate analysis debt — N+1 kinds, M+1 variants, P+1 metrics — and the audit surface gets unmanageable

The R2/V6-companion cycle showed that **review checkpoints every 1–2 hours** caught real errors (my §7.2.2 pull-direction flip, my `PRE_EXEC_REG_MOD` mis-classification, etc.). The same logic at a coarser cadence (every 2–6 weeks) on a multi-month build is the safe pattern.

### Why we should NOT just follow Pro's §15 priority order directly

Pro's order says "Hybrid V7" first. But Hybrid V7 is the **largest single integration in the entire roadmap**: it requires mutation-surface abstraction, V5 scheduler refactor, V6 kind integration, applied-mutation accounting, AND a 4-variant comparison. That is 4–6 weeks of work before Pro sees any new results.

Pro also gave us four smaller asks (§6, §7, §11, §12) that are largely "owed" responses from the previous round — small in scope, fast to deliver, and they **build the metric infrastructure Hybrid V7 needs to be evaluated**. Doing them first means:

- Pro sees we're responding to all their concerns, not cherry-picking the headline
- We build the bug-proximity / isolation / fair-Arguzz metric stack BEFORE Hybrid V7 runs (so the Hybrid results are immediately measurable on the right axes)
- We have a fast first feedback loop with Pro (~2-3 weeks)
- Pro can course-correct before we commit to the 4-6 week Hybrid build

So my recommendation is a **4-deliverable structure**, not Pro's priority order verbatim.

---

## 2. Proposed 4-deliverable structure

**Workflow pattern (each deliverable previews the next):**
Each deliverable ships to Pro with two things: (1) the results of the just-completed work, and (2) the implementation plan for the next deliverable. Pro reacts to BOTH — validating results AND steering the next architecture before we commit weeks of work. This means Pro never waits long for a feedback opportunity, and we never sink 4–6 weeks into a path Pro would have redirected.

| # | Deliverable | What goes to Pro | ETA | Pro's source priority |
|---|---|---|---:|---|
| **D1** | **Housekeeping + scheduler tuning** + **D2 plan** | V5-decay results + CGC variant analysis + new metric stack instrumentation, **plus the D2 (Hybrid V7) design proposal for Pro to react to** | 2–3 weeks | §7, §11, parts of §5 + §8 (= Pro Priority 4 + smaller asks + D2 design) |
| **D2** | **Hybrid V7 headline** + **D3 plan** | V5 vs V6-uniform vs V6-cTS vs Hybrid-cTS on normalized metrics; pure-A4 catalog expansion built in; plus D3 design | 5–7 weeks after D1 sign-off | §8 Track A+B, §9, §15 Priority 1 + 3 |
| **D3** | **Bug-isolation layer** + **D4 plan** | Co-failure graph + repair templates + minimization loop; bug-proximity demonstration on Hybrid V7; plus D4 design | 6–8 weeks after D2 sign-off | §10, §15 Priority 2 |
| **D4** | **Multi-guest cross-validation** + **IV.POS.9 design** | At minimum stock SHA + ECALL/MRET-heavy guest; cross-validation of V5/Hybrid-cTS/D3 architecture; plus IV.POS.9 design | 2–3 weeks after D3 sign-off | §13, §15 Priority 5 |

**Total horizon: 4–5 months** of wall-clock work + Pro review cycles in between. Pro check-in after each deliverable.

### Why D1 first (the case for housekeeping before Hybrid)

| Argument | Weight |
|---|---|
| Pro explicitly asked for all four (§6/§7/§11/§12); declining or deferring would be poor responsiveness | strong |
| The §5 metric stack additions (d_loc, singleton-failure, co-failure graph, fair-Arguzz metrics) are PREREQUISITES for evaluating Hybrid V7 properly | strong |
| D1 is mostly analysis on existing DBs + one new compute run (V5-decay × 10 seeds × 2 NEW variants = 20 jobs, ~4.5h on POS) — small wall-clock | strong |
| D1 produces a quick win that shows Pro we're listening, while D2 is brewing | strong |
| Pro might steer differently after D1 (e.g., "actually decay didn't help, skip ahead to Hybrid") — saves wasted Hybrid effort | medium |
| Skipping D1 means Hybrid V7 ships without bug-proximity metrics, forcing a D2 re-run later | strong |

### Why D2 (Hybrid V7) before D3 (bug-isolation)

Hybrid V7 is **catalog-driven**; D3 is **mechanism-driven**. We need to see whether the catalog expansion (D2) alone closes the gap with Arguzz before deciding what bug-isolation scope to commit to in D3. If Hybrid V7 already wins on territory + novel-loc metrics, D3 scope can be lighter. If it doesn't, D3 becomes critical and may need to be larger.

### Why D4 (multi-guest) last

Multi-guest validates the architecture across diverse workloads, but only meaningful once we have an architecture to validate. Pro explicitly says §13 is "important but not the next single most important experiment."

---

## 3. D1 detailed scope (the first batch we should tackle)

D1 is "**housekeeping + scheduler tuning + D2 design proposal**." Four work streams, mostly independent. Two of Pro's smaller asks (V3/V4 verification §6 and parallel noise §12) were considered and **deprioritized** — see §3.X below for rationale.

### D1.A — V5 decaying-floor variant (§7) — **LOCKED, see `IV_POS_8_D1_A_SPEC.md`**

| Item | Detail |
|---|---|
| Implementation | New `FloorSchedule` abstraction in `bandit_ts.py`: `ConstantFloor` (back-compat default), `ExponentialDecayFloor(K=50)`, `EpochStageFloor([(0, 0.55), (2000, 0.35), (4000, 0.20)])`. Plumbed via `update_local_coverage()` from fuzzer's cumulative `record_failures` return value (Option B faithful) |
| Variants to compare | V5-static (reuse R2 archive at `a4/runs/iv_pos_7/dbs/`), V5-decayexp (new), V5-decayepoch (new) |
| Compute | **20 jobs** (10 seeds × 2 NEW variants only — V5-static back-compat by construction, verified via unit tests) — ~4.5h on 8 POS nodes |
| Metrics | All existing R2 metrics + D1.C bug-proximity metrics (overlapping work — schema verification confirmed most D1.C metrics derivable from EXISTING schema) |
| Schema additions | 3 new nullable columns on `mutations`: `proof_generated`, `proof_verify_failed`, `elapsed_ms`. Forward-compatible, NULL on legacy DBs. Unlocks D1.C metrics that are currently computed but lost |
| K rationale | K=50: smooth decay through V5's typical 0–46 discovery trajectory, clip to floor_min=0.20 at d=51 (just past saturation). See `IV_POS_8_D1_A_SPEC.md` §3.1 for verified math |
| Output | `D1A_SUBSECTION.md` (subsection inside D1 final report); CSVs + plots in `a4/runs/iv_pos_8/d1a/` |

### D1.B — CGC coarsening + three-variant analysis (§11)

| Item | Detail |
|---|---|
| Implementation | Add CGC computation variants in `metrics.py`: (1) region-only (drop bucket entirely), (2) log4 buckets, (3) `page_class` semantic bucketing |
| Compute | None — re-analyze existing 70-DB V0–V6 corpus |
| Analysis | For each CGC variant, recompute `compressed_global_context_final`, `cgc_AUC`, family/zone breakdown |
| **Disclosure to Pro (Composer review note)** | Pro's §11 specifically asked for `region-only, log4, log2`. We propose substituting `page_class` for `log2` because page_class encodes semantic bucketing (region + access pattern) that's a better reward-candidate than log2 (which is just a finer-grained version of log4). **D1.B Pro-facing subsection must explicitly disclose this substitution and the rationale**, not silently swap |
| Production change? | Open question for Pro: should reward switch to coarser CGC in D2's Hybrid V7? Pro hints yes but doesn't mandate. Include the decision in D2 design proposal (§3.D) |
| Output | `CGC_VARIANT_ANALYSIS.md` (subsection inside D1 final report) |

### D1.C — New metric stack instrumentation (§5)

**Schema verification (2026-06-16, see `IV_POS_8_D1_A_SPEC.md` §1.3) found that the existing DB schema covers more than we initially thought.** D1.C splits into three categories by data source:

#### D1.C — Category A: Derivable from EXISTING schema (works on R2 V1, V5 + new D1.A DBs)

| Metric | SQL definition | Source |
|---|---|---|
| `verifier_accepted_invalid_count` | `SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0` | Already in `mutations.verifier_accepted` (auto-populated by `_check_verifier_acceptance`) |
| `mean / median / p95 d_loc` | `SELECT ... FROM mutation_rewards.d_loc JOIN mutations` | Already in `mutation_rewards` table (populated for all bandit selectors with active `coverage_state`) |
| `mean / median / p95 d_glob` | Same with `d_glob` | Same |
| `singleton_failure_rate` | `WITH per_mut AS (SELECT m.id, COUNT(f.id) AS n_fail FROM mutations m LEFT JOIN failures f ...) SELECT SUM(CASE WHEN n_fail=1 ...) FROM per_mut` | `mutations` + `failures` join (existing) |
| `co_failure_graph_degree` (mean / max) | Build graph in pandas from `failures` table; nodes = constraint_locs, edges = co-failure in same mutation_id | `failures` table |
| `min_d_loc_per_target` | Per-loc aggregate `MIN(d_loc)` from `mutation_rewards` cross with `failures` | Existing schema |
| `applied_mutation_count` | `COUNT(*) FROM mutations WHERE campaign_id=?` | Skipped mutations don't get DB rows — count IS applied count |
| Fair-Arguzz territory metrics | Common / A4-only / Arguzz-only territory coverage | Already shipped in V6 companion (`v6_pro_territory_coverage.csv`) |

#### D1.C — Category B: Requires the 3 new schema columns (D1.A adds these; new D1.A DBs only)

| Metric | Source |
|---|---|
| `proof_generated_with_zero_residue_rejected` | New `proof_generated` + `proof_verify_failed` columns + `mutation_rewards.d_loc/d_glob` |
| `wall_clock_per_normalized_discovery` | New `elapsed_ms` column ÷ normalized loc count |

These are NULL on legacy R2 DBs (graceful degradation in analysis CSVs).

#### D1.C — Category C: D3 dependencies (stubs only)

| Metric | Why stub |
|---|---|
| `repairability_score` | Needs repair logic — D3 |
| `near_acceptance_frontier_size` | Needs repair + distance metric — D3 |
| `accepted_invalid_proofs_per_hour` | Needs B + repair loop — D3 |
| `successful local repairs per target` | D3 |
| `unique bug mechanisms` | Needs taxonomy work — D3 |

#### D1.C work scope

| Item | Detail |
|---|---|
| Application scope | Category A applied to R2 V1, V5 (60 DBs) + new D1.A DBs (20 DBs). V3/V4 deliberately excluded per Ivan decision (deprecated). Category B applied to new D1.A DBs only |
| D3 dependency markers | Category C functions defined with TODOs marking "populated in D3" |
| Output | Updates to `analysis/metrics.py`; new `analysis/bug_proximity.py`; CSVs in `a4/runs/iv_pos_8/d1c/`; D1.C subsection in D1 final report on what V5 baseline looks like under the new metrics |

### D1.D — D2 (Hybrid V7) design proposal

This is the design document Pro reviews alongside D1 results. It does NOT commit to D2 implementation — it's the proposal Pro reacts to.

| Item | Detail |
|---|---|
| Architecture overview | Mutation-surface abstraction: `arm = (mutation_surface, mutation_kind, semantic_zone, opcode_class, pre/post)` where `mutation_surface ∈ {A4_trace_cell, arguzz_exec_fault}`. Scheduler-level changes needed for hybrid arm space. Applied-mutation accounting (pulls = applied, not attempted) |
| Kind menu — from V6 | Top-N V6-only kinds per Pro's §8 priority order. Decide N (3? 5? all 7?) — preliminary recommendation: top 4 (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`) to keep arm space manageable |
| Kind menu — pure-A4 | Top-N from Pro's §8 Track B (which lists 5 total: `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`). **D1.D proposal to Pro: top 3** (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`) — keeps Hybrid V7 arm space manageable. The D2 sketch in §4 lists all 5 for reference but D1.D's curated subset of 3 is what we'd actually implement; Pro can expand to 5 if requested |
| Variant comparison plan | V5 (control) vs V6-uniform (current arguzz) vs V6-cTS (arguzz kinds + V5 scheduler) vs Hybrid-cTS (V5 + selected V6 + selected A4 expansion, full hybrid) |
| Normalization | Q-G driver fix: write normalized `constraint_loc` at source in V6 driver; new A4 kinds use existing `short_loc()` |
| CGC choice | Use D1.B result to pick CGC variant for D2 reward (region-only / log4 / page_class) |
| Compute estimate | 10 paired seeds × 4 variants × N=6000 = 40 jobs (~12 hours on 8 POS nodes) |
| Specific open questions for Pro | (1) Top-N kind menu sizing — does Pro want all 12 (7 V6 + 5 A4), or do we start narrower? (2) Should reward use coarser CGC (from D1.B)? (3) Should V6-cTS be a separate variant or fold into Hybrid-cTS? (4) Is N=6000 still right, or should we extend for Hybrid? (5) Should pure-A4 expansion be Phase-1 of D2 (additive to V5) before Hybrid, or fold directly into Hybrid? |
| Risks documented | V5 scheduler refactor complexity, applied-mutation accounting subtlety, V6 driver integration, Hybrid arm-space size explosion |
| Output | `IV_POS_8_D2_DESIGN_PROPOSAL.md` (sibling document; bundled with D1 final report shipped to Pro) |

### D1.X — Deprioritized (acknowledged, not built)

Two of Pro's smaller asks were considered and **deliberately not implemented** for D1. Brief explanations included in D1 final report so Pro sees we considered them.

| Pro section | Ask | D1 disposition | Justification |
|---|---|---|---|
| **§6** | V3/V4 cascade verification (d_loc, singleton-failure, co-failure graph applied retroactively to V3/V4 DBs) | **Skipped — acknowledged in report** | V3/V4 are deprecated as production candidates. V5 is the architectural baseline going forward. Confirming or disconfirming "V3/V4 are cascade-heavy" doesn't change IV.POS.8 trajectory. The d_loc / singleton-failure / co-failure metric **infrastructure** is still built in D1.C, but applied to V5 (the live baseline) and forward to Hybrid V7 in D2, where the bug-proximity story is load-bearing |
| **§12** | Parallel-execution noise — explicit decision + minimal reproduction attempt | **Documentation only (1 paragraph in `POS_PLAYBOOK.md`)** | Pro already gave the answer (keep default parallelism + 10+ paired seeds; file upstream if independently reproducible). We already use both. The minimal reproduction is low-value: upstream filing doesn't change our methodology and takes months to land. One paragraph in the playbook codifying "default parallelism, 10+ seeds, single-thread only for forensic confirmation" is sufficient |

These deprioritization decisions are themselves part of the D1 report — Pro sees explicit text saying "we considered this and chose not to do it, here's why" rather than silent omission.

### D1 final assembly

| Item | Detail |
|---|---|
| Top-level D1 report | `IV_POS_8_D1_REPORT_FOR_PRO.md` — Pro-facing companion that wraps D1.A + D1.B + D1.C into one narrative with TL;DR + per-section results + deprioritization notes for §6/§12. Then includes/references the D2 design proposal |
| D2 design proposal | `IV_POS_8_D2_DESIGN_PROPOSAL.md` — separate document, bundled with D1 ship |
| Companion notebook | `IV_POS_8_D1_NOTEBOOK.ipynb` — analogue to V6 companion |
| Frozen artifacts | R2 packet stays frozen; V6 companion stays frozen; D1 is additive |
| Pro disclosure | Ship both files together: "Here are D1 results, and here's our D2 plan — please react to both." |

---

## 4. D2–D4 sketch (placeholder detail — to be planned after D1)

### D2 — Hybrid V7 (sketch)

**Implementation:**
- Mutation-surface abstraction: `arm = (mutation_surface, mutation_kind, semantic_zone, opcode_class, pre/post)` where `mutation_surface ∈ {A4_trace_cell, arguzz_exec_fault}`
- V6 kind integration into V5 scheduler — Pro's §8 priority order: `INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND, POST_EXEC_REG_MOD, POST_EXEC_MEM_MOD, POST_EXEC_PC_MOD`
- Pure-A4 expansion (§8 Track B priorities): `TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, TXN_CYCLE_PHASE_MOD, CYCLE_PC_MOD`
- Applied-mutation accounting (pulls = applied, not attempted)
- Normalized loc + CGC telemetry at source (kills Q-G overhead)

**Experiments:**
- V5 (control) vs V6-uniform (current arguzz) vs V6-cTS (arguzz kinds + V5 scheduler) vs Hybrid-cTS (V5 + arguzz + new A4 kinds, full hybrid)
- 10 paired seeds × N=6000

**Output:**
- `IV_POS_8_D2_REPORT_FOR_PRO.md` — the headline IV.POS.8 deliverable

### D3 — Bug-isolation layer (sketch)

**Implementation:**
- Co-failure graph: for every mutation, record `(mutated_field, semantic_zone, opcode_class, local_failure_set, global_failure_set, proof_generated, verifier_accepted)` → build `field → constraints`, `constraint → co-failing constraints`, `field → repair candidates`
- Repair templates for the 6 clusters Pro lists: kernel/ECALL, memory consistency, instruction decode, PC/control-flow, lookup/global residue, accelerator
- Minimization loop: freeze semantic invalidity, repair unrelated failures, minimize `d_loc` / `d_glob`, prefer `proof_generated=true`, re-run prover/verifier
- Full bug-proximity metric implementation (was stubs in **D1.C Category C** — typo corrected; see `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.C)

**Experiments:**
- Hybrid-cTS + bug-isolation vs Hybrid-cTS alone
- Top N "promising regions" from D2 corpus, isolation+repair run
- Look for: accepted-invalid candidates, near-acceptance frontier population, repair success rate per cluster

**Output:**
- `IV_POS_8_D3_REPORT_FOR_PRO.md` — bug-proximity / accepted-invalid demonstration

### D4 — Multi-guest cross-validation (sketch)

**Implementation:**
- Add stock RISC Zero SHA guest (Pro §13 g1) — minimal new guest infrastructure
- Optionally add ECALL/MRET-heavy guest (Pro §13 g2) — requires C++ inspector extension for MRET/halt detection
- Optionally control-flow guest (g3), memory-stress (g4), accelerator (g5)

**Experiments:**
- Re-run V5 + Hybrid-cTS + Hybrid-cTS+isolation on g1; compare per-guest dynamics
- (If time) extend to g2

**Output:**
- `IV_POS_8_D4_REPORT_FOR_PRO.md` — cross-guest robustness verdict

---

## 5. Open questions for Ivan (before we lock D1)

These are decisions only Ivan can make. Defer until after Ivan reads this draft.

### Resolved with Ivan (2026-06-16)

| # | Question | Resolution |
|---|---|---|
| R1 | 4-deliverable structure or collapsed? | **Keep separate.** Each deliverable previews next via design proposal |
| R2 | D1 scope — keep all five? | **Drop D1.E (parallel noise) and drop D1.C V3/V4 verification.** Bug-proximity metric infrastructure (d_loc, cofailure) still built, but applied forward to V5+Hybrid, not retroactively to V3/V4 |
| R6 | Share D1 plan with Pro before building? | **Ship results + D2 design proposal together** (Pro reacts to both at once, no plan-document round-trip) |
| R10 | Pro disclosure — D1 report alone or with D2 design? | **Both together** — see R6 |

### Still open

| # | Question | My recommendation |
|---|---|---|
| 3 | D1 wall-clock target — 2 weeks (aggressive) or 3 weeks (comfortable)? | 3 weeks — leaves room for Composer review cycles |
| 4 | Compute: V5-decay × 30 jobs on POS — same chain dispatcher / 8-node infra as IV.POS.7? | Yes, no infrastructure change needed |
| 5 | D1 report tone — formal Pro-facing (like R2) or terse update? | Formal Pro-facing (consistent with R2 + V6 companion) |
| 7 | Composer batch cadence — same as previous round? | Yes, same pattern. D1 likely ≈ 4–6 Composer batches |
| 8 | Branch hygiene — merge `cloud2` → `main` after each deliverable, or after all four? | After each deliverable. Keeps `main` shippable |
| 9 | "Hybrid V7" the right name, or just "V7"? | Defer to D2 design proposal discussion |
| 11 | D1.D top-N kind menu — preliminary 4 V6-only + 3 A4 in design proposal, OR all 12, OR explicit "Pro picks N"? | Preliminary 4+3 in design proposal, explicit ask for Pro feedback. Larger N inflates arm space significantly |
| 12 | Should D1.A V5-decay use Pro's exponential form, the epoch-based form, OR both as separate variants? | **RESOLVED 2026-06-16: Both** (see `IV_POS_8_D1_A_SPEC.md` §1.2.4) |
| 13 | K parameter for exponential decay — sweep (~3 values) or pick one? | **RESOLVED 2026-06-16: K=50** (see `IV_POS_8_D1_A_SPEC.md` §3.1 — verified math table) |
| 14 | Re-run V5-static or reuse R2 archive? | **RESOLVED 2026-06-16: Reuse R2** — back-compat by construction (`ConstantFloor(0.55)` is a pure passthrough); saves ~15 node-hours; verified by golden-trace unit test in `test_bandit_ts.py` |
| 15 | Discovery counter plumbing — Option A (sum of successes) or Option B (faithful)? | **RESOLVED 2026-06-16: Option B** — uses `record_failures` return value (already computed); exact match to Pro's `local_coverage_seen` |
| 16 | Local pre-POS smoke or POS-only? | **RESOLVED 2026-06-16: POS-only smoke-gate.** Ivan's WSL runs at ~46 sec/mut (Composer's partial run: 22 muts in 17 min). N=200 local × 3 variants would be ~7.5 h wall and not feasible. Pre-POS validation comes from integration tests + golden-trace test (already complete). The first batch of 8 production jobs (Batch 3) acts as the deployment smoke before the remaining 12 jobs commit. See `IV_POS_8_D1_A_SPEC.md` §D10/D11/D12 |
| 17 | Batch 3 gate sizing — 2-job minimal or 8-job wide? | **RESOLVED 2026-06-16: 8-job wide gate** (4 paired seeds × 2 variants on all 8 nodes). 8 nodes available + longer reservations; same per-batch wall (~5.5 h) regardless of gate size; saves ~3 h total and gives 4× more validation data at the checkpoint |

---

## 6. What we should tackle FIRST (concrete next steps)

In order:

1. **Ivan + Opus joint review of this plan v2** — confirm updated structure (D1.E dropped, V3/V4 verification dropped, D2 design proposal added). Edit as needed [DONE]
2. **Lock remaining open questions** — answer §5 questions 3, 4, 5, 7, 8, 9, 11; resolved 12, 13, 14, 15 are now in `IV_POS_8_D1_A_SPEC.md` §8
3. **Detailed D1 specs** — write `IV_POS_8_D1_A_SPEC.md` (DONE), then `IV_POS_8_D1_B_SPEC.md`, `IV_POS_8_D1_C_SPEC.md`, `IV_POS_8_D2_DESIGN_PROPOSAL.md` as separate documents (one per work stream)
4. **Composer reviews D1.A spec** [DONE — review absorbed in spec v1.1: 6-site fuzzer fix, discover.py longest-first fix, golden-trace framing]
5. **Composer Batch 1 kickoff — D1.A (scheduler)**, possibly in parallel with **D1.B Batch 1 (CGC reanalysis on existing DBs)** since they share no state. Ivan to decide single-thread vs parallel
6. **Composer Batch 2 (D1.A)** — CLI/fuzzer/schema integration with all critical fixes (Composer review additions)
7. **Composer Batch 3 (D1.A)** — POS smoke-gate dispatch (8 jobs = seeds 1234–1237 × 2 variants on 8 nodes, ~5.5 h wall) + hard checkpoint before Batch 4. Local smoke abandoned (Q16 resolved 2026-06-16)
8. **Compute D1.A** — POS Batch 4a (8 jobs) + Batch 4b (4 Tier-S jobs) = remaining 12 jobs. V5-static baseline reused from R2 archive (no re-run). Total D1.A POS wall ~16 h across 3 sequential dispatches; ~19 h end-to-end including Composer setup/checkpoint/collection
9. **In parallel with POS wait** — D1.C metric stack instrumentation (`analysis/bug_proximity.py`); D1.D D2 design proposal drafting
10. **D1 assembly** — wrap D1.A + D1.B + D1.C + deprioritization notes into `IV_POS_8_D1_REPORT_FOR_PRO.md` + `IV_POS_8_D1_NOTEBOOK.ipynb`
11. **D2 design proposal finalization** — incorporate any D1 surprises into D2 design (e.g., if D1.B CGC variant changes preferred reward formula, update D2 reward design)
12. **Ship to Pro** — D1 results + D2 design proposal bundle. Wait for feedback before kicking off D2 implementation

---

## 7. What this plan does NOT do (yet)

- **Does not** specify D2/D3/D4 implementation details. Those wait until after D1 ships and Pro reacts.
- **Does not** commit to specific kind-name parameters, K values, epoch sizes, or thresholds. Those are D1 spec details (next step).
- **Does not** commit to compute allocation (POS schedule). That's a separate operational document.
- **Does not** include IV.POS.7 closeout — that's done (V6 vs A4 Pro companion v1.0, last round).
- **Does not** address §16's "big question" directly. Pro's own answer is "Pure single-cell post-execution trace fuzzing probably will not broadly beat Arguzz." Our job is to test the hybrid path empirically; we'll let the data speak in D2.

---

## 8. Why this plan is right (TL;DR for Ivan)

- **Responsive to Pro** — D1 addresses the load-bearing smaller asks (§7, §11, parts of §5), D2 is Pro's Priority 1, D3 is Pro's Priority 2, D4 is Pro's Priority 5. Two smaller asks (§6 V3/V4 verification, §12 parallel noise) deliberately deprioritized with explicit Pro-facing acknowledgment
- **Front-loads metric infrastructure** — bug-proximity / isolation / fair-Arguzz metrics built in D1.C so Hybrid V7 can be evaluated properly when D2 lands
- **Every deliverable previews the next** — D1 ships with D2 design proposal, D2 ships with D3 design proposal, etc. Pro reacts to results AND plan in each cycle, not just results
- **Short feedback loops with Pro** (~2–3 weeks per cycle, not 3 months)
- **Reversible at every cycle** — if Pro steers differently after D1, we adapt D2 design before committing 4–6 weeks of implementation. Same for D2 → D3 transition
- **Builds on what we have** — D1 is 2 pure-analysis pieces (existing DBs) + 1 small compute run; reuses all R2 + V6 companion infrastructure
- **Keeps R2 + V6 companion frozen** — additive only
- **Lean** — V3/V4 retrospective and minimal-reproduction parallel-noise work are explicitly skipped because their strategic value is near zero; the savings go into D2 design quality

---

*End of preliminary plan v2.1 (Composer-review absorbed). `IV_POS_8_D1_A_SPEC.md` is locked; awaiting Ivan greenlight for Composer Batch 1 kickoff. D1.B / D1.C / D1.D specs to be drafted as separate documents.*
