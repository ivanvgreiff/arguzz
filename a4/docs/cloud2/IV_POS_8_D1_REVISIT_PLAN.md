# IV.POS.8 — D1 Revisit Plan (D1.B + D1.C + D1.E + Final D1 Report Assembly)

**Branch:** `cloud2`
**Status:** **DRAFT v0.5** — D1.B Batch 1 ACCEPTED 2026-06-17 15:30 EDT. Batch 1.6 (NEW: `_coerce_broken_addr` field-priority fix) inserted in D1.B spec between Batch 1.5 and Batch 2 to address production extractor bug surfaced by Batch 1 audit data (see NFP-10 for full disclosure). All forward runs (D1.E, D2.*) use patched extractor; R2 + D1.A use post-hoc replay from `hook3_raw` for corrected metrics. D1.B spec is at v0.4 (`IV_POS_8_D1_B_SPEC.md`). v0.5 of this revisit plan threads the byte_addr fix coordination into §3.3 (D1.E) and §4 (sequence).
**Author:** Opus
**Parent docs:** [`IV_POS_8_PRELIMINARY_PLAN.md`](./IV_POS_8_PRELIMINARY_PLAN.md), [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md), [`IV_POS_8_NOTES_FOR_PRO.md`](./IV_POS_8_NOTES_FOR_PRO.md)
**Frozen interim artefact this plan iterates from:** [`a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md`](../../runs/iv_pos_8/d1a/D1A_SUBSECTION.md)
**Trigger:** Post-D1.A-freeze decision (2026-06-17) — current D1.A is insufficient as the final Pro deliverable because we ran only **half of Pro §7 Stage 2** (floor decay on the existing sparse-binary-composite bandit reward; richer reward signals not wired).

---

## 0. TL;DR

Three sub-deliverables, **drafted as serial spec → implement → review cycles** (one Composer spec at a time), with **one mandatory cross-chat sync point** with the D2-focused chat:

```
[NOW]   D1.A FROZEN ✓ (subsection + Findings A–F applied; binary-composite fact correction applied 2026-06-17)
          │
          ├─ Stage 1: D1.B (CGC coarsening variants, analysis-only on existing DBs)
          │
          ├─ Stage 2: D1.C (bug-proximity metric stack, analysis-only — Categories A + B)
          │
          ▼
[SYNC]  D1 chat HALTS — waits for D2 chat to land:
          • D2.B Batch 1   (arm-shape + retro arm-state snapshots, depends on D2.A)
          • D2.B Batch 1.5e (NFP-6: `PRE_EXEC_REG_MOD` two-strategy retrofix — alters V5 behavior)
          │
          ▼
[RESUME] Stage 3: D1.E (NEW sub-deliverable) — wire D1.B coarsened CGC + D1.C-shortlisted
          signals into `bandit_success`, retune `K`/epoch boundaries per Finding D,
          re-run V5-static + V5-decayexp + V5-decayepoch on POS (5 paired triplets = 15 jobs).
          │
          ▼
        Stage 4: Final D1 report assembly →
          `a4/runs/iv_pos_8/d1/IV_POS_8_D1_REPORT_FOR_PRO.md`
          (folds frozen D1.A + D1.B + D1.C + D1.E; cross-links to D2 design)
```

**Naming:** This plan introduces **D1.E** as the name for the reward-rewired re-run (the prelim plan dropped the old "D1.E parallel noise" sub-deliverable, freeing the letter). The composer-suggested name "D1.A-revisit" is an acceptable synonym, but **D1.E** keeps the lettered scheme intact and makes the new-scope nature explicit. Decision deferred to Ivan (Open Decision #1 in §6).

---

## 1. Why this plan exists

The frozen D1.A subsection encodes the diagnosis (Findings A–F) — the audit-verified facts are:

1. **Pro §7 Stage 2 is a two-part proposal** (`ProG_Report_3.md:175-196`): (a) floor decay schedule, (b) richer TS reward signals (recent marginal discovery, low-cofailure, repairability, underexplored semantic zones). D1.A tested (a) only.
2. **Today's TS reward is a sparse binary composite**: `bandit_success = 1 if (l_new + g_new + s_new) > 0 else 0` (`reward_v2.py:60-62`). Compressed-global novelty IS already part of the bandit reward, but the bucketing is the production log4 — D1.B's job is to test alternative coarsenings.
3. **Scheduler geometry only supports ~3 mode regimes** (Finding D): integer-per-arm-quota in `bandit_ts.py:180-187` collapses Pro's intended 3-tier `[0.55, 0.35, 0.20]` epoch schedule into a 2-tier `{~96%, ~48%}` floor policy. A retune (`K`, epoch boundaries) is needed for any future decay re-run — and Pro's full "gradient" requires architectural changes beyond `K`.
4. **Per-mutation_id mode is deterministic within a variant** (Finding C); seed only affects arm picked within a mode. Pairing on seed gives identity-by-construction inside the floor regions.
5. **In the post-boundary window where decayepoch's policy diverges from V5-static**, both variants discovered the same 10 contexts across 5 seeds (Finding E) — but this is **scoped to `local_context_final` which saturates at ~46**. The richer Pro signals + later-saturating metrics (compressed_global at ~186–189) have not been tested.

**Strategic implication:** A re-run on the same bandit reward would produce the same answer. To either (i) salvage decay variants or (ii) defensibly kill them in the final Pro deliverable, we must rewire the bandit reward path with the signals D1.B and D1.C deliver.

---

## 2. Scope & cross-references

### 2.1 In scope (this plan)

| Sub-deliverable | What it produces | Owns code in |
|---|---|---|
| **D1.B** | 3 coarsened-CGC variant functions; recommendation for D2 default; analysis tables on the **decay-comparison corpus** (10 R2 V5 + 5 decayexp + 5 decayepoch = **20 rows**) — V1 not paired for CGC comparison because V1 baseline differs by more than just CGC bucketing | `a4/runs/iv_pos_8/d1b/`, `analysis/cgc_variants.py` (new module, see §3.1.1), notebook |
| **D1.C** | `analysis/bug_proximity.py`; Category A metrics on **all R2 V1 + R2 V5 + D1.A new = ~30 rows** (10 + 10 + 10; **NOT 20** — earlier draft was wrong; **prelim plan §3 line 165 ALSO has wrong row counts** — "(60 DBs)" for V1+V5 should be 20, "(20 DBs)" for D1.A new should be 10 — to be corrected in D1.C spec §0); Category B metrics on **10 D1.A new DBs only** (NULL on R2); two-tier signal shortlist: (i) per-mutation signals viable for bandit-reward rewire (D1.E L1), (ii) per-campaign signals for D1.C reporting + D2.G consumption only | `a4/runs/iv_pos_8/d1c/`, `analysis/bug_proximity.py`, notebook |
| **D1.E** (NEW) | (a) wire D1.B-recommended CGC + D1.C-shortlisted signals into `bandit_success`; (b) retune `K` / epoch boundaries per Finding D; (c) POS re-run 5 paired triplets (V5-static + decayexp + decayepoch) under the rewired path; (d) refreshed paired-analysis CSVs + notebook | `a4/standalone/fuzzer.py`, `a4/standalone/reward_v2.py`, `a4/standalone/bandit_ts.py`, `a4/runs/iv_pos_8/d1e/`, POS manifests |
| **Final D1 report** | `a4/runs/iv_pos_8/d1/IV_POS_8_D1_REPORT_FOR_PRO.md` wrapping frozen D1.A + D1.B + D1.C + D1.E with TL;DR + Pro-facing narrative | `a4/runs/iv_pos_8/d1/` |

### 2.2 Out of scope — cross-links only, NOT re-spec'd here

| Owned by | Sub-deliverable | Status as of this draft | Relevance to this plan |
|---|---|---|---|
| D2 chat | D2.A | **DONE** at `7b66fb9` | Added `mutations.outcome`, applied accounting, V5 byte-identity confirmed. D1.B/D1.C analysis must respect the new schema. |
| D2 chat | D2.B Batch 1 | NOT YET STARTED (Composer kickoff next) | Schedules retro arm-state snapshots — does not affect D1.B/D1.C. |
| D2 chat | **D2.B Batch 1.5e (NFP-6)** | NOT YET STARTED | **Sync point.** Retrofixes `PRE_EXEC_REG_MOD` to RNG-pick `next_read`/`prev_write`. Alters V5 failure surfaces → must land before D1.E POS re-run so fresh V5 baseline matches new codebase. |
| D2 chat | D2.B Batch 2/3 | Spec'd, not started | Independent of D1 revisit. |
| D2 chat | D2.C | DRAFT v0.1 (substantial content; not locked) | Independent; cross-link only. |
| D2 chat | D2.D / D2.E / D2.F / D2.G | Spec'd in `IV_POS_8_D2_PLAN.md`; D2.G consumes D1.C Category A metrics | Cross-link only. |
| D1.D (prelim plan original) | "D2 design proposal" | **Superseded** by `IV_POS_8_D2_PLAN.md` | The final D1 report (Stage 4) will cross-link `IV_POS_8_D2_PLAN.md`, not re-author a D2 design proposal. |

**Composer point #9 explicit:** This plan does **not** duplicate `IV_POS_8_D2_PLAN.md`. D2 detail lives in the D2 plan; we only mark sync points here.

---

## 3. Sub-deliverable detail (level: enough to drive next spec drafts)

> Detailed implementation specs (`IV_POS_8_D1_B_SPEC.md`, `IV_POS_8_D1_C_SPEC.md`, `IV_POS_8_D1_E_SPEC.md`) are deliverables of the **next** Opus turn, one at a time, per the user's spec → implement → review cycle.

### 3.1 D1.B — CGC coarsening variants (analysis-only)

**Not greenfield (Composer point #2):** `analysis/metrics.py:138` already computes the production CGC (`compressed_global_context_final`) by reading `SELECT COUNT(*) FROM compressed_global_coverage`. `d1a_paired_tests.csv` already runs paired tests on it (all p-values 0.62–0.96 — null on the current corpus).

**What D1.B adds:**

1. Three **alternate coarsening functions** added to a NEW `analysis/cgc_variants.py` module (NOT additive edits to `metrics.py` — see §3.1.1 below):
   - `region_only` — region tag only (coarsest)
   - `log4_explicit` — current production, made explicit (control / sanity check)
   - `page_class` — **semantic memory-use class** within bulk `user`/`user_bigint` bands (e.g. `code` / `heap` / `stack` / `host_ecall` / `user_other`), orthogonal to `txn_role`/`cycle_phase`/`opcode_class`. Substitutes for Pro's `log2`; the substitution is **already disclosed in `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.B**. Definition refined 2026-06-17 per Composer + Ivan investigation; see `IV_POS_8_D1_B_SPEC.md` §0 Q-PC-1 for full rationale and the alternatives that were rejected (e.g., "region + access pattern" duplicates `txn_role`, so it is NOT what `page_class` means)
2. Re-analysis on the **20-row decay-comparison corpus** (10 R2 V5 + 5 D1.A decayexp + 5 D1.A decayepoch). **No new compute on the fuzzer side**, but see §3.1.1 below — D1.B MUST commit to a CGC data-source path.
3. Paired-test tables, cumulative curves, AUC under each variant.
4. **Recommendation table:** which variant should D2 use as the CGC reward signal? (D2 Q8 — currently defaults to log4 until D1.B recommends.)

#### 3.1.1 D1.B data-source decision (Composer point #3 — must resolve in D1.B spec)

The stored `compressed_global_coverage` table schema (`a4/standalone/coverage_db.py:395-406`) is:

```
ctx_key TEXT NOT NULL,                  -- production-bucketed key (log4 today)
campaign_id INTEGER NOT NULL,
first_hit_mutation_id INTEGER NOT NULL,
family TEXT NOT NULL,
ctx_json TEXT NOT NULL,                 -- full context dict, e.g. {"address_region":"user","address_bucket":31}
first_hit_at TEXT NOT NULL,
hit_count INTEGER DEFAULT 1
```

Three feasibility tiers for each candidate coarsening:

| Coarsening | Re-bucket from stored `ctx_json`? | If not, fallback |
|---|---|---|
| `region_only` | **Yes** — `ctx_json` has `address_region`; drop everything else, GROUP BY (family, region) | n/a |
| `log4_explicit` | **Yes** — `ctx_json` stores `address_bucket` (log2 per `compressed_global_extractor.py:125-136`); log4 is computed as `log2 // 2`. log4 is **strictly coarser** than production log2, not equivalent | n/a |
| `page_class` | **TBD** — `ctx_json` stores `address_region` + `address_bucket` only. If `page_class` needs raw access pattern beyond region+bucket, NOT re-derivable from stored data | Requires either (a) a small production extractor change to widen `ctx_json` (coordination with D2.B's `compressed_global_extractor.py` edits — see §2.2) or (b) recomputing from `failures` + `family_details` mutation telemetry per-mutation |

**D1.B spec MUST commit to one of three paths for `page_class`:**

1. **Post-hoc re-bucket only** — if `ctx_json` is sufficient (likely yes for region-only, log4_explicit; possibly no for page_class). Cheapest path.
2. **Widen `ctx_json` in production extractor** (small additive edit; coordinates with D2.B's `_TXN_ROLE_BY_KIND` changes in the same file). Requires a re-run to populate, OR backfill from raw telemetry where possible.
3. **Analysis-time recompute from raw telemetry** — read per-mutation `failures` / `family_details` and re-bucket. No production-code change. More analysis code; works on all existing DBs.

Composer's framing is correct: this is **the** load-bearing implementation question for D1.B and must be answered before Composer touches code. Recommendation (to be confirmed in D1.B spec): **Path 1 for `region_only` + `log4_explicit`; Path 3 for `page_class`** (avoids touching `compressed_global_extractor.py` while D2.B edits it).

**Expected outcome (calibrated, per Composer point #7):** D1.B may show **null differences** on the frozen corpus too (since the bandit didn't learn from variant CGC, only from the production log4). That's still informative — it tells us either (a) coarsening doesn't help even with hindsight, or (b) some coarsening shows decay-vs-static separation, which becomes the candidate for D1.E rewire. The plan must NOT promise D1.B will be conclusive on its own.

**Exit criteria:**

- 3 coarsening fns implemented, tests green.
- `d1b_metrics_table.csv`, `d1b_paired_tests.csv`, `d1b_recommendation.md` written.
- Notebook + HTML rendered.
- D1.B subsection drafted (will fold into final D1 report at Stage 4).

#### 3.1.2 D1.B → D1.E hand-off file index (added 2026-06-17 per Composer audit)

Subsection files in §3.4 Stage 4 are Pro-facing summaries. The **load-bearing inputs for the D1.E spec** are the hand-off artifacts below. D1.E spec drafting MUST start by reading these:

| Artifact | Purpose | Audience |
|---|---|---|
| `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` | L0 baseline + saturation inversion findings; rationale for `production_log2_corrected` as D1.E L0 baseline | D1.E spec author |
| `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` | Variant-selection rationale + §4 L1 open-question framing (per-channel reward / weighted / scalar bandit alternatives to naive OR) | D1.E spec author + D2.G |
| `a4/runs/iv_pos_8/d1b/D1B_SUBSECTION.md` | Pro-facing summary; folds into Stage 4 final D1 report | Pro (via Stage 4) |
| `a4/runs/iv_pos_8/d1b/d1b_page_class_layout.md` | `user_dynamic` enhancement rationale (Batch 1.5b); informs L0 schema discussions for D1.E + D2.G | D1.E + D2.G (informational) |

### 3.2 D1.C — Bug-proximity metric stack (analysis-only, Categories A + B)

**Categories per `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.C** (with row-count correction — prelim §3 line 165 has wrong numbers; D1.C spec §0 must restate):

| Category | Source | Applies to | Status |
|---|---|---|---|
| **A** | Derivable from existing schema (R2 V1, R2 V5, D1.A new) | **~30 analysis rows** (10 V1 + 10 V5 + 10 D1.A); prelim plan said "(60 DBs) + (20 DBs)" — both numbers wrong (V1+V5 is 10+10=20, D1.A new is 10). To be restated in D1.C spec §0 | In scope for D1.C |
| **B** | Requires the 3 D1.A schema columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`) | **10 D1.A new DBs only** — NULL on R2 V1/V5 (Composer point #3 correction) | In scope for D1.C |
| **C** | D3 dependencies (e.g., repair templates) | n/a | Stubs only, per prelim plan |

**What D1.C produces:**

1. `analysis/bug_proximity.py` with at minimum these Category-A metrics:
   - `verifier_accepted_invalid_count` (per Pro §5)
   - `co_failure_graph_degree` distributions (mean/median/p95)
   - `singleton_failure_rate`
   - `d_loc` distribution stats (mean/median/p95)
2. Category-B metrics on the 10 D1.A new DBs:
   - `proof_generated_with_zero_residue_rejected` rate
   - `wall_clock_per_normalized_discovery` (from `elapsed_ms`)
3. **Two-tier signal shortlist (split per Composer's second-round pushback):**
   - **Tier-1 (bandit-rewire candidates for D1.E L1)** — must be **per-mutation** (sliding-window OK if window updates per pull), non-saturating in [0, 6000), low correlation with `l_new`/`g_new`/`s_new`. Examples: sliding-window `d_loc` rate, singleton-failure flag, recent-marginal-discovery rate.
   - **Tier-2 (D1.C reporting + D2.G consumption)** — per-campaign metrics fine. Examples: `co_failure_graph_degree` distributions, `verifier_accepted_invalid_count` totals, `wall_clock_per_normalized_discovery`. These do NOT need to be per-mutation to be useful in the Pro-facing analysis or as D2.G inputs.
   - Also note (Composer point #4): `f_new` family-novelty is **already computed** in `reward_v2.py:compute_reward_v2_components` but is NOT in `compute_bandit_success`. D1.E L1 could trivially OR-in `f_new > 0` as a 4th channel at zero extra instrumentation cost — call this out as a Tier-1 candidate that's "free" relative to the D1.C signals.
4. **Catalog impact note:** which Category-A Tier-2 metrics could D2.G consume directly (cross-link to `IV_POS_8_D2_PLAN.md` D2.G).

**Important framing (Composer points #7 + #10):** D1.C analysis on frozen DBs answers "what do variants look like under bug-proximity metrics?" but does NOT answer "does the bandit help if it learns from those signals?" — that question is reserved for D1.E.

**Exit criteria:**

- `analysis/bug_proximity.py` shipped + unit tests.
- `d1c_metrics_table.csv`, `d1c_paired_tests.csv` (where statistical comparison applies), `d1c_signal_shortlist.md` written.
- Notebook + HTML rendered.
- D1.C subsection drafted (folds into final D1 report at Stage 4).

#### 3.2.1 D1.C → D1.E hand-off file index (added 2026-06-17 per Composer audit)

Parallel to §3.1.2. The D1.E spec MUST read these in addition to the D1.B set above:

| Artifact | Purpose | Audience |
|---|---|---|
| `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` | Top 2-3 Tier-1 signal shortlist + selection rationale (orthogonality + non-saturation) + sample L1 OR sketch + alternatives reference | D1.E spec author |
| `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` | Full per-signal shortlist with recommended/deferred labels and rationale | D1.E spec author + D2.G |
| `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` | Pro-facing summary; folds into Stage 4 final D1 report | Pro (via Stage 4) |
| `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` | Tier-2 column schema for D2.G `build_d2_artifacts.py` consumption (column names + dtypes + Pro-§ mapping) | D2.G author |

### 3.3 D1.E — V5 Reward-Rewired Re-run (NEW sub-deliverable)

> **This sub-deliverable was NOT in the original prelim plan (Composer point #1).** It is justified by Finding F: D1.A only tested half of Pro §7 Stage 2. D1.E is the second half.

**Three components, gated by D1.B + D1.C + D2.B Batch 1.5e:**

**(A) Reward rewire** — in `a4/standalone/reward_v2.py` + `a4/standalone/fuzzer.py`:

| Layer | Change | Notes |
|---|---|---|
| L0 | **D1.B outcome (commit `71dae77`): keep `production_log2_corrected` as L0 baseline.** D1.B Batch 3 showed that all three alternate coarsenings (`region_only`, `log4_explicit`, `page_class`) saturate 1400-1900 mut EARLIER than local saturation (3221 mean `time_to_46`) — the opposite of what the original v0.1/v0.2 of this row hypothesized; coarsening makes the post-local discriminating window WORSE, not better. `production_log2_corrected` (post-`_coerce_broken_addr` byte_addr fix per Batch 1.6 + NFP-10) is the only L0 candidate with material post-local headroom (~39 keys remaining at mut 3221, ~1.4 new keys/100 mutations — thin but non-zero). **Coordinates with D2.B Batch 1.5e (`_TXN_ROLE_BY_KIND`)** in the same file (`compressed_global_extractor.py`). D1.E v1 spec MUST cite `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` (§3.1.2 hand-off index) as the load-bearing input for this row. | D1.B's saturation-inversion finding means L0 schema-swap alone cannot extend the post-local discriminating window — L1 enrichment (D1.C-shortlisted signals) is the primary lever. D1.E v1 spec assumes patched extractor is already in main. |
| L1 | Extend `compute_bandit_success` to OR-in: (a) `f_new > 0` (free — already computed but excluded from Bernoulli today; Composer point #4), and (b) one or more Tier-1 D1.C-shortlisted per-mutation signals (e.g., `recent_marginal_discovery_rate > θ`, `singleton_flag`) | Keeps the binary Bernoulli shape; lowest implementation risk. Note: adding signals MONOTONICALLY increases the fraction of successes — D1.E spec must define a stopping rule (e.g., max 3 OR'd channels) to avoid saturating the bandit reward in the opposite direction |
| L2 | Optionally replace Beta-Bernoulli TS with a scalar-reward bandit using `compute_reward_v2` directly | **Out of scope for D1.E v1** — flag as deferred to D2 or follow-on. Pro §7 Stage 2 does not literally require this; binary suffices if the OR-of-signals is informative. |

D1.E v1 spec **must commit** to L0 + L1 only; L2 is explicitly flagged as deferred to avoid scope creep (Open Decision #4).

**(B) Parameter retune** — per Finding D + Pro-intent clarification (Ivan 2026-06-17):

**Pro's design split (re-confirmed):**
- **K decays on local survey progress** (`_local_discoveries` per `bandit_ts.py:98-100`; Pro §7 formula uses `local_coverage_seen`). K stays anchored here.
- **CGC coarsening (D1.B) + bug-proximity signals (D1.C) feed Bernoulli learning (L0+L1), NOT K.** The whole point is to extend the `bandit_success` discriminating window past local saturation, so that when the floor decays as designed, adaptive TS still has signal to optimize on. (D1.A's diagnosis: floor decayed correctly, but `bandit_success` had also saturated — adaptive mode had nothing to learn from.)
- The earlier-draft `L_floor` option (driving floor from CGC instead of local survey) is **anti-Pro** and removed from D1.E scope.

**K target derivation for D1.E:**

- `K` for decayexp: target the 96% → 48% transition to land in the saturation tail of `_local_discoveries`. **D1.E spec adds a short SQL pass** (`SELECT COUNT(*) FROM coverage` cumulative curve on existing DBs — `coverage` is the legacy constraint_loc-deduplicated table, distinct from `local_coverage_v2`) to pin the saturation point. Anchored to D1.A's existing profile: `local_context_final` (`local_coverage_v2` count) ≈ 46 is an upper bound; legacy `coverage` count is smaller (constraint_loc-only dedup). K ≈ 100–200 is a rough placeholder pending D1.E's coverage-table characterization. **K is a D1.E-spec-time decision, not a revisit-plan-time decision; D1.B does NOT feed it.**
- decayepoch boundaries: same anchor (`_local_discoveries` saturation, not CGC). Shift the first boundary earlier (e.g., mut = 1000) so the policy differs from V5-static during the productive window. Final values: D1.E spec.
- Architectural caveat (call out, do NOT attempt in D1.E): Pro's full "gradient" is mechanically impossible on the current per-arm-integer-quota scheduler. A real gradient needs either per-mutation Bernoulli sampling or arm-count expansion (Hybrid V7 territory).

**D1.B's role re-stated:** D1.B does NOT feed K. D1.B feeds (i) D2's default CGC reward choice and (ii) D1.E's L0 (replace production log2 CGC bucketing with D1.B-recommended coarsening), so that `g_new` continues to discriminate past `_local_discoveries` saturation. See `IV_POS_8_D1_B_SPEC.md` §0.1.1.

**(C) POS re-run** — 5 paired triplets, 15 jobs total (Composer point #5 correction):

| Sub-batch | Variant | Seeds | Job count |
|---|---|---|---|
| E.1 | V5-static (fresh, post-NFP-6 + post-rewire) | 1234, 1235, 1236, 1237, 1238 | 5 |
| E.2 | V5-decayexp (retuned K) | 1234, 1235, 1236, 1237, 1238 | 5 |
| E.3 | V5-decayepoch (retuned boundaries) | 1234, 1235, 1236, 1237, 1238 | 5 |
| **Total** | | | **15** |

**Why fresh V5 (not R2 archive reuse) — Option B per the audit (Composer point #5 nuance):**

1. NFP-6 retrofix (D2.B Batch 1.5e) RNG-picks `next_read`/`prev_write` for `PRE_EXEC_REG_MOD`, materially altering V5 failure surfaces — not just cosmetic.
2. The reward path itself is rewired, so the bandit's pull pattern will differ even on the same kind catalog. Reusing R2 V5 archive would conflate "did the rewire help?" with "did the retrofix change V5's baseline?"
3. D2 plan §5 Q3 ALSO permits archive reuse for D2 evaluations when the codebase is back-compat. **D1.E is explicitly NOT a back-compat scenario** (Composer point #5) — fresh V5 is justified.
4. Run-time cost: 15 jobs × ~5.5 h = ~5.5 h wall on 8 nodes (~2 sequential dispatches: 8 jobs + 7 jobs); within one 6-h reservation block.

(**Option C** — running BOTH pre-rewire-pre-retrofix decay variants AND post-rewire-post-retrofix triplets — would be 25 jobs and is overkill unless we explicitly want a retrofix ablation subsection. **Deferred to Open Decision #3.**)

**Exit criteria:**

- L0 + L1 reward rewire merged with tests; deterministic / golden-trace coverage.
- Parameter retune values agreed in D1.E spec.
- 15 DBs collected + locally validated.
- Refreshed `d1e_metrics_table.csv`, `d1e_paired_tests.csv`, `d1e_floor_dynamics.csv`, `d1e_recommendation.md`.
- Notebook + HTML rendered.
- D1.E subsection drafted (folds into final D1 report at Stage 4).

### 3.4 Final D1 report assembly (Stage 4)

- `a4/runs/iv_pos_8/d1/IV_POS_8_D1_REPORT_FOR_PRO.md` — Pro-facing narrative with:
  - TL;DR (entire D1).
  - §A frozen D1.A subsection (verbatim cross-reference + 1-paragraph framing).
  - §B D1.B subsection.
  - §C D1.C subsection.
  - §E D1.E subsection.
  - §Z deprioritization notes (§6 V3/V4 cascade — already documented; §12 etc).
  - Cross-link to `IV_POS_8_D2_PLAN.md` for D2 design.
- `IV_POS_8_D1_NOTEBOOK.ipynb` — bundled executable evidence.

---

## 4. Execution sequence (with explicit D1 ↔ D2 boundary)

### 4.1 Stage table

| Stage | Sub-deliverable | Owner | Triggers | Halt? |
|---|---|---|---|---|
| 0 | D1.A frozen | D1 chat (DONE) | n/a | — |
| 1 | D1.B spec → implement → review | D1 chat | Ivan greenlight on this plan | — |
| 2 | D1.C spec → implement → review | D1 chat | Stage 1 reviewed | — |
| **SYNC** | D2.B Batch 1 + Batch 1.5e (NFP-6 retrofix) | **D2 chat** | Stage 2 reviewed; D2 chat already kicking off Batch 1 in parallel | **D1 chat HALTS** until D2 chat reports Batch 1.5e merged + tests green |
| 3 | D1.E spec → implement → POS re-run → review | D1 chat | D2 chat sync acknowledged | — |
| 4 | Final D1 report assembly | D1 chat | Stage 3 reviewed | — |

### 4.2 Spec-by-spec cycle (per user's request)

Each stage uses the **Opus spec → Composer implements → Opus + Ivan review → next stage** cycle:

1. **Spec drafting (Opus):** Opus drafts `IV_POS_8_D1_X_SPEC.md` with v0.1 status.
2. **Ivan review of spec:** Ivan greenlights or sends back questions.
3. **Composer implements** against locked spec; produces report + artifacts; pushes to `cloud2`.
4. **Opus + Ivan review** Composer's output (artifacts + numbers + report).
5. **Cycle closes:** mark stage complete in this plan's revision history; next stage spec drafting begins.

**Strict serial.** The user's message specified "spec by opus → composer implements → we review → next spec by opus and so on" — so D1.B fully closes before D1.C starts, D1.C fully closes before SYNC, etc. (Open Decision #2 below: relax to parallel D1.B ‖ D1.C if Ivan wants.)

### 4.3 D1 ↔ D2 hand-off matrix

| Event | D1 chat action | D2 chat action |
|---|---|---|
| This plan greenlighted | Begin D1.B spec drafting | Continue D2.B Batch 1 kickoff (already in progress per D2 plan §10) |
| Stage 1 + Stage 2 complete | **HALT.** Post status to shared cloud2 docs ("D1 ready for sync"). | Continue D2.B Batch 1 → Batch 1.5e |
| D2.B Batch 1.5e merged + tests green on cloud2 | **RESUME.** Begin D1.E spec drafting. | Continue D2.B Batch 2/3 in parallel with D1.E |
| Stage 3 (D1.E) complete | Begin Stage 4 assembly | (no dependency) |
| Stage 4 complete | Pro deliverable ready | Cross-link from `IV_POS_8_D2_DESIGN_PROPOSAL.md` (when D2 produces it) |

**Hand-off signal mechanism (Open Decision #5):**

- Option A (simplest): D2 chat appends a row to `IV_POS_8_NOTES_FOR_PRO.md` revision history when Batch 1.5e merges; D1 chat watches for the commit.
- Option B: D1 chat polls `git log --grep "Batch 1.5e"` on cloud2.
- Option C: Out-of-band Ivan ping ("D2 chat says Batch 1.5e is in").

---

## 5. Compute / time estimates

| Stage | Wall (best case) | Notes |
|---|---|---|
| 1 (D1.B) | 1–2 days (no POS compute) | Pure analysis. Spec drafting ~half-day, Composer impl + Opus review ~1 day. |
| 2 (D1.C) | 2–4 days (no POS compute) | New `bug_proximity.py` module is the bulk; Category B SQL queries are short. |
| SYNC | Open — gated by D2 chat | D2.B Batch 1.5e is ~10 LOC + 1 unit test (per `IV_POS_8_D2_B_SPEC.md:1205-1206`). Optimistic: 1–2 days inside the D2 chat. |
| 3 (D1.E) | 3–5 days | Spec ~1 day, reward-rewire impl ~1 day, POS re-run ~5.5 h wall + collection + validation ~half-day, refresh notebook ~half-day, review ~1 day. |
| 4 (Assembly) | 1 day | Narrative wrapper + cross-links. |
| **Total D1-chat work** | **7–12 days** (excluding SYNC wait) | |

POS compute: **15 jobs × 6000 mutations × ~5.5 h** = within 1 reservation block of 8 nodes.

---

## 6. Open decisions (need Ivan greenlight before Stage 1 starts)

| # | Decision | Options | My recommendation |
|---|---|---|---|
| 1 | Naming of the rewired-reward re-run | (a) **D1.E** (this plan); (b) "D1.A-revisit" (Composer); (c) other | (a) D1.E — keeps lettered scheme intact, makes new-scope nature explicit |
| 2 | D1.B vs D1.C ordering | (a) Strict serial (D1.B first); (b) parallel (different files, different Composer turns interleaved) | (a) Strict serial per your "spec → implement → review → next spec" instruction. **Technically both are safe** (`IV_POS_8_PRELIMINARY_PLAN.md` line 300 explicitly says D1.B ‖ D1.C parallel-safe). Serial is process preference (cleaner review checkpoints), not technical dependency. Revisit if you want to relax |
| 3 | D1.E re-run scope | (a) **Option B: 15 jobs post-retrofix only**; (b) Option C: 25 jobs (10 pre-retrofix + 15 post) | (a) Option B — 15 jobs is sufficient for paired analysis; retrofix ablation is not required for Pro §7 evidence |
| 4 | D1.E reward path layer ceiling | (a) **L0 + L1 (binary stays, signal channels enriched)**; (b) L0 + L1 + L2 (replace Beta-Bernoulli with scalar reward bandit) | (a) L0 + L1 — keeps Bernoulli shape, lowest risk, sufficient to test Pro §7; L2 is its own architecture change |
| 5 | D1 ↔ D2 sync signal | (a) NOTES_FOR_PRO row; (b) git log poll; (c) Ivan ping | (c) Ivan ping — most reliable; (a) as backup audit trail |
| 6 | Stage 4 D1.D treatment | (a) Drop D1.D entirely (D2 plan supersedes); (b) Keep D1.D as a 1-page "D1 → D2 hand-off summary" in the final report | (b) Keep as ~1-page section so the Pro report reads coherently end-to-end |

---

## 7. Watchlist (deferred decisions tracked per-stage)

| ID | Watch | First check | Resolution path |
|---|---|---|---|
| W-R1 | D1.B coarsening winner has high correlation with current log4 → "no change" | D1.B `d1b_recommendation.md` | If null, D1.E reward rewire leans harder on D1.C signal; document in D1.E spec |
| W-R2 | D1.C signal shortlist is empty (no non-saturating, non-correlated signal found) | D1.C `d1c_signal_shortlist.md` | Re-evaluate D1.E scope — may collapse to "decay variants neutral even with richer hindsight metrics; reward enrichment requires D3 (repair) instrumentation" |
| W-R3 | NFP-6 retrofix shifts V5 baseline materially (e.g., `local_context_final` mean changes by > 5 contexts) | D1.E E.1 (fresh V5) vs R2 V5 archive comparison | If yes, document as separate finding for Pro; flag for D2 archive-reuse decision |
| W-R4 | Retuned K still misses target transition window (Finding D collapsibility) | D1.E E.2 (decayexp) `d1e_floor_dynamics.csv` | Iterate K or document as architectural-blocker (move decay-gradient evaluation to Hybrid V7) |
| W-R5 | D1.E even with rewire shows null decay-vs-static | Stage 3 review | This IS a valid outcome; report to Pro with "decay needs Hybrid V7 + scheduler-geometry change to matter" as the honest verdict (Composer point #4 framing) |
| W-R6 | D2 chat takes > 1 week on Batch 1.5e | SYNC stage | **LAST RESORT — requires explicit Ivan sign-off.** Pivoting to "re-run only decay variants, reuse R2 V5 archive" contradicts D1.E Option B's own rationale (reward rewire + NFP-6 make R2 V5 stale; per-paired-comparison cleanliness lost). If invoked: (a) document the conflict explicitly in D1.E spec revision history; (b) flag the resulting subsection with a banner equivalent to D1.A's FROZEN banner indicating "compromised baseline due to D2 sync delay"; (c) prefer waiting longer over invoking this fallback unless project deadline pressure justifies the compromise |

---

## 8. Cross-references

| Document | Why |
|---|---|
| [`a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md`](../../runs/iv_pos_8/d1a/D1A_SUBSECTION.md) | Frozen D1.A subsection; Findings A–F encoded |
| [`a4/docs/cloud2/ProG_Report_3.md`](./ProG_Report_3.md) §7 (lines 175–196), §15 | Pro's Stage-2 reward signal list (Finding F source); decay V5 ranked Priority-4 in §15 |
| [`a4/docs/cloud2/IV_POS_8_PRELIMINARY_PLAN.md`](./IV_POS_8_PRELIMINARY_PLAN.md) §3 (D1.B, D1.C scope) | Sub-deliverable scope inherited from prelim plan |
| [`a4/docs/cloud2/IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) §5 Q8 (CGC default), §4 D2.G (Category A consumer), §9a W-7 (NFP-6 mitigation) | D2 dependencies and downstream consumers |
| [`a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) §1205-1206 (Batch 1.5e) | SYNC point definition |
| [`a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md`](./IV_POS_8_NOTES_FOR_PRO.md) NFP-6 | NFP-6 architectural note |
| `a4/standalone/reward_v2.py:60-62` | `compute_bandit_success` definition (binary composite — Composer point #4) |
| `a4/standalone/bandit_ts.py:180-187` | `_floor_target` calculation (Finding D source) |

---

## 9. Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Opus | Initial draft v0.1. Incorporates Composer's 10-point feedback on D2-survey analysis. Scope: D1.B + D1.C + D1.E + final assembly; explicit D1 ↔ D2 sync point at D2.B Batch 1.5e (NFP-6); 6 open decisions, 6 watchlist items. |
| 2026-06-17 | Opus | v0.2 — Incorporates Composer's second-round pushback (7 points, 6 substantive + 1 framing). Fixes: (1) D1.C Category A row count corrected to ~30 (was 20; flagged prelim §3 row counts also wrong); (2) D1.B implementation path made explicit (new §3.1.1 — `compressed_global_coverage.ctx_json` data-source decision with 3 feasibility tiers per coarsening); (3) D1.C signal shortlist split into two tiers (per-mutation Tier-1 for bandit rewire; per-campaign Tier-2 for analysis + D2.G); (4) D1.E L1 explicitly includes `f_new > 0` as a free OR-channel (`f_new` is already computed but excluded from today's `compute_bandit_success`); (5) W-R6 marked LAST RESORT with explicit Ivan sign-off requirement + banner protocol; (6) Open Decision #2 notes parallel D1.B ‖ D1.C is technically safe per prelim line 300 (serial is process preference, not technical dependency); also explicit D1.E coordination note with D2.B's edits to `compressed_global_extractor.py` in L0 row. Awaiting Ivan greenlight to begin Stage-1 (D1.B) spec drafting. |
| 2026-06-17 | Opus | v0.3 — Post-spec-drafting cross-fixes (per Composer's pushback on `IV_POS_8_D1_B_SPEC.md` v0.1): (i) §3.1 page_class row updated from "region + access pattern" to **semantic memory-use class** (orthogonal to txn_role/cycle_phase/opcode_class), cross-linked to D1.B spec §0 Q-PC-1; (ii) §3.1.1 `log4_explicit` feasibility row corrected — log4 is **strictly coarser** than production log2 (which is `floor(log2(addr))` per `compressed_global_extractor.py:125-136`), NOT equivalent. K-timing language in §3.3(B) tightened in earlier v0.2 turn; further hardening (clarifying that `_local_discoveries` not CGC drives `ExponentialDecayFloor.K`) is encoded in D1.B spec v0.2 §0.1.1 and referenced from here. |
| 2026-06-17 | Opus | v0.4 — Ivan's Pro-intent restatement (CGC + bug-proximity feed L0+L1, NOT K; K stays on local survey progress per Pro §7 verbatim formula) cleanly threaded through §3.3(B): **K target derivation moved entirely into D1.E spec** with explicit anchor on `_local_discoveries` saturation (legacy `coverage` row count, distinct from `local_coverage_v2`); D1.B's role re-stated as feeding (i) D2 default CGC reward choice and (ii) D1.E L0 — explicitly NOT K. The earlier-draft `L_floor` option (driving floor from CGC) **removed as anti-Pro** — would prevent floor from decaying on local saturation, defeating Pro's staged-exploration design. Cross-references D1.B spec v0.3 §0.1.1 and §0.4 for the Pro-intent re-derivation and the page_class folklore-vs-facts audit. |
| 2026-06-17 | Opus | v0.5 — D1.B Batch 1 ACCEPTED; **Batch 1.6 NEW** inserted in D1.B spec §3.2.5 to land `_coerce_broken_addr` field-priority fix (production CGC memory regions had been mis-labeled across all R2 V1-V5 + D1.A runs; Hook 3 emits both `addr` (word) and `byte_addr` (byte = addr×4); extractor was preferring `addr` and feeding word-addresses into D8 `address_region()` which is defined on byte-addresses, causing 53-59% mis-classification across audited DBs). Opus verified bug independently with SQL: V5 s1234: 58.9% region mismatch, V1 s1234: 53.2%, decayexp s1234: 55.7%; stored CGC memory regions collapsed to `{user, zero_page}` only despite Hook 3 seeing 9 distinct regions. Lookup family unaffected; local channel unaffected; arm scheduler unaffected. NFP-10 added to `IV_POS_8_NOTES_FOR_PRO.md` documenting bug + impact + post-hoc replay strategy. D1.E (§3.3) updated: L0 baseline is now `production_log2_corrected` (post-fix), not pre-fix; forward D1.E runs use patched extractor natively. Re-dispatch of R2 V1-V5 explicitly NOT scheduled — `hook3_raw` preserves raw payloads for post-hoc replay (verified). Pro disclosure timing: NFP-10 lands with D1.B subsection at Batch 3 (after Batch 2's corrected-baseline analysis), not earlier. |
| 2026-06-17 | Opus | v0.6 — Three cross-doc fixes prompted by D1.C spec v0.2/v0.3 drafting + Composer audits: **(1)** new **§3.1.2** "D1.B → D1.E hand-off file index" (4 artifacts: `d1e_handoff_CGC_saturation.md`, `d1b_recommendation.md`, `D1B_SUBSECTION.md`, `d1b_page_class_layout.md`) — D1.E spec author was at risk of reading only Stage-4 subsections and missing L0/L1 wiring detail per Composer Part 1 discoverability audit. **(2)** new **§3.2.1** "D1.C → D1.E hand-off file index" (4 artifacts: `d1e_handoff_L1_signals.md`, `d1c_signal_shortlist.md`, `D1C_SUBSECTION.md`, `d1c_tier2_schema.md`) — parallel to §3.1.2 for D1.C deliverables. **(3)** §3.3 L0 row materially updated — v0.1-v0.5 wording ("Replace production bucketing with D1.B-recommended coarsening" / "If D1.B picks region_only or page_class, the same g_new channel becomes more selective / less saturating") was a HYPOTHESIS that D1.B Batch 3 EMPIRICALLY DISPROVED: coarsenings saturate 1400-1900 mut EARLIER than local saturation (3221), making the post-local discriminating window WORSE not better. v0.6 row states D1.B's actual outcome (keep `production_log2_corrected` as L0; saturation-inversion finding means L0 schema-swap alone cannot extend the post-local window; L1 enrichment via D1.C signals is the primary lever) and cites the §3.1.2 hand-off file as the load-bearing D1.E input. No changes to D1.C scope, K decision, or W-R watchlist. |

*End of `IV_POS_8_D1_REVISIT_PLAN.md` v0.6.*
