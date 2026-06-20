# D1.E — V5 Reward-Rewired Re-run: Implementation Spec

**Parent plan:** `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.E + `IV_POS_8_D1_REVISIT_PLAN.md` v0.6 §3.3 (full D1.E target description) + §3.1.2 + §3.2.1 (hand-off file indices)
**Pro references:** `ProG_Report_3.md` §7 (Stage 2 enriched reward signals), §11 (CGC bucketing), §15 (priorities)
**Status:** **DRAFT v0.2.1 — awaiting Ivan greenlight on Q-E-* open questions before Batch 0 kickoff.** D1.A (FROZEN), D1.B (commit `71dae77`), D1.C (commit `3a8487c`), D2.A (commits `b844e8e` + `7b66fb9`), and **D2.B full feature-complete (commits `78d036c` → `e2c2256`)** are all DONE. **D2.B Batch 1.5e (`PRE_EXEC_REG_MOD` retrofix) sync gate is satisfied at `78d036c`.**
**Author:** Opus
**Branch:** `cloud2`
**Revision note (v0.2):** Composer (D1 chat) systematic audit of v0.1 caught real bugs against the actual `cloud2` HEAD schema + code. **All 11 confirmed issues fixed in v0.2:** (1) `bandit_success_l1` moved from `mutation_rewards` (which has no `bandit_success` column) to `reward_counterfactuals` alongside `discovery_binary_reward`. (2) Persistence model explicit: `discovery_binary_reward` stays base-only for D1.C comparability; new `bandit_success_l1` stores the L1-enriched bit the bandit actually learns from; Q-E-TIER1-VALIDATION correlates vs the enriched bit. (3) Batch 0 SQL corrected to use `coverage.first_hit_mutation_id` (real schema) instead of nonexistent `coverage.mutation_id`. (4) Batch 1 golden-trace reframed to post-1.5e regression + `compute_bandit_success` unit-equivalence (R2 archive byte-identity is gone after `78d036c`). (5) Opposite-saturation pre-flight moved from `[800, 1000)` to post-local `[3000, 6000)` — matches D1.C gate window where `d_loc_le_2_flag` actually fires 60.7%. (6) Class name `EpochStaircaseFloor` → `EpochStageFloor` throughout (matches `bandit_ts.py:103`). (7) `mutation_substrategy_uniqueness` wiring spec'd via existing `telemetry_v2.extract_mutation_substrategy` + new `composite_substrategy_key` helper in standalone (no cross-tree imports). (8) `singleton_failure_flag` clarified as in-memory `len(exec_result.failures)`. (9) `d_loc_le_2_flag` reads `diag["d_loc"]` from `compute_reward` return at `fuzzer.py:1078-1084` (in-memory, before `mutation_rewards` write). (10) Briefing §6.1 L1 row fix re-confirmed (separately applied to briefing v0.3). (11) §2.4 / §6 D2.A byte-identity claims softened in briefing v0.3. **Composer pushback Issue 12 (K algebra "oversimplified"):** Opus pushed back — the closed-form `K = saturation_d / 0.171` correctly identifies the K at which the integer-quota step transition lands at d (verified: K=200 → d=27, K=300 → d=41, both match D1.A Finding A's published table). Composer's underlying concern is partially valid; addressed by adding a Batch 0 sub-task to emit a `floor_target_curve_K{K}.csv` sanity table from `_floor_target()` — but the closed-form is the primary tool, not a replacement.

**Load-bearing inputs (mandatory reads for spec drafting and Composer execution):**
- `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` (D1.B's L0 choice + L1 open question framing)
- `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` (D1.B's saturation inversion finding)
- `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` (D1.C's full signal reference)
- `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` (D1.C's L1 recommendations + empirical disclosures)
- `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` (D1.C Pro-facing subsection with the V5-scope disclaimers)
- `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` (frozen D1.A findings, especially Finding A K-derivation table, Finding D scheduler-geometry, Finding F reward-saturation)
- `a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md` NFP-9 (D1.E reward rewire framing, including 2026-06-17 UPDATE on `f_new` empirical deadness)
- `a4/docs/cloud2/composer/D1C_AUDIT_REPORT.md` (D1.C NFP-10-style audit — confirms zero CGC-class field-priority risk in `bug_proximity.py`; semantic schism disclosures the spec inherits)

---

## 0. Goal recap + open questions Ivan must resolve

### 0.1 Goal

D1.A (FROZEN) measured V5 + decay variants under the **existing sparse binary composite reward** (`bandit_success = 1 if (l_new + g_new + s_new) > 0 else 0` at `reward_v2.py:60-62`). Result: decay variants do NOT separate from V5-static on `local_context_final` (paired p > 0.62), AND scheduler geometry only supports 3 effective mode regimes (Finding D), AND `bandit_success` saturates by mut ~3000-3500 alongside local discovery, leaving adaptive TS with no discriminating signal exactly when the floor decays (Finding F).

D1.B measured four CGC coarsening alternates and found **saturation inversion** — coarsened variants (`region_only`, `log4_explicit`, `page_class`) saturate **1400-1900 mut BEFORE** local saturation. `production_log2_corrected` (with NFP-10 `byte_addr` fix) is the **only** L0 candidate with material post-local headroom (~39 keys / ~1.4 keys per 100 mut). **L0 schema-swap alone cannot extend the post-local discriminating window.**

D1.C measured 5 candidate per-mutation signals + 8 per-campaign metrics on the V5 corpus and identified **three Tier-1 L1 OR-channel candidates** that pass both orthogonality (`max |ρ| < 0.4`) and non-saturation (`fire_rate(post_local) > 5%`) gates: `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`. Pro's "free L1 channel" candidate `f_new > 0` was empirically dead post-local on V5 and is excluded.

**D1.E's job:** Wire D1.B's L0 baseline + D1.C's L1 enrichment into the production reward path, retune K/epoch boundaries against the legacy `coverage` table saturation point (per Pro §7 verbatim formula), and re-dispatch 15 paired-triplet POS jobs to test whether the enriched reward signal makes decay variants beat V5-static.

**The causal test D1.E exists to perform:** Does enriching `compute_bandit_success` with L1 OR-channel D1.C signals + retuning K to land its mode-transition in the saturation tail give the adaptive bandit a discriminating gradient that decay variants can exploit?

### 0.1.1 Three-layer reward rewire (per NFP-9 — L2 is OUT of scope)

| Layer | Scope in D1.E v1 | Source/justification |
|---|---|---|
| **L0** (CGC bucketing schema) | **NO CODE CHANGE.** Keep `production_log2_corrected` as-is. NFP-10 `byte_addr` fix is already in `compressed_global_extractor.py` from D1.B Batch 1.6 (commit `71dae77`). | D1.B `d1b_recommendation.md` §4; revisit plan §3.3 L0 row v0.6 |
| **L1** (`compute_bandit_success` OR-channel extension) | **NEW WIRING.** Modify `reward_v2.py:compute_bandit_success` to accept and OR-in D1.C Tier-1 signals computed per-pull in `fuzzer.py`. Top-3 candidates by default; subset selectable via campaign param. | D1.C `d1e_handoff_L1_signals.md` §1 + §2 |
| **L2** (Scalar-reward bandit replacing Beta-Bernoulli TS) | **OUT OF SCOPE.** Deferred to D2 or follow-on per NFP-9. | NFP-9 + revisit plan §3.3 |

### 0.1.2 K/epoch retune scope (per Pro §7 verbatim + D1.A Finding A/D)

| Parameter | D1.A value (FROZEN) | D1.E v1 target | Why change |
|---|---|---|---|
| `ExponentialDecayFloor.K` | 50 | **K ≈ 200-300** (Q-E-K-TARGET locks final value after Batch 0 SQL pass) | D1.A Finding A: K=50 saturates `floor_frac` to `floor_min` at d=7, behaviorally identical to `ConstantFloor(0.20)` — never tested actual decay |
| `EpochStageFloor` boundaries (class name is `EpochStageFloor` per `bandit_ts.py:103`, NOT `EpochStaircaseFloor`) | `[(0, 0.55), (2000, 0.35), (4000, 0.20)]` | **`[(0, 0.55), (1000, 0.35)]`** (drop the no-op third tier per Finding D; shift first boundary earlier so policy differs from V5-static during productive window) | D1.A Finding D: 0.35→0.20 mechanically invisible to scheduler; Finding C: decayepoch ≡ V5-static through mut ~2049 by construction |

**Both retunes are driven by `_local_discoveries` (legacy `coverage` table cumulative count) per Pro §7 verbatim formula and `bandit_ts.py:98-100`.** D1.B's CGC saturation point does NOT feed K (anti-Pro per NFP-9).

### 0.1.3 Why this is necessary after D1.A + D1.B + D1.C

D1.A established: floor decay alone does not move `local_context_final` under sparse binary reward. The reward signal saturated before the floor decay could matter.

D1.B established: L0 schema-swap cannot extend the post-local discriminating window — coarsened variants make it WORSE.

D1.C established: There ARE per-mutation signals (3 Tier-1) that fire post-local on >5% of pulls AND are orthogonal (|ρ| < 0.4) to the existing bandit success bit on the V5 corpus.

**D1.E is the integration point.** If the enriched reward gives decay a discriminating gradient (`local_context_final`, `cgc_final`, or the new Tier-2 bug-proximity metrics improve significantly on decay), Pro's §7 Stage 2 vision is validated. If it does NOT, decay variants are deprioritized for V5-paired runs (kept available for Hybrid V7 per Pro §15 Priority 1).

### 0.2 Open questions Ivan must resolve before Batch 0

| ID | Question | Why it matters | Recommendation (default if Ivan doesn't pick) |
|---|---|---|---|
| **Q-E-L1-COMPOSITION** | Wire D1.C signals via naive OR into `compute_bandit_success`, or use one of the richer compositions D1.B §4 listed (per-channel reward tracking, weighted reward boost, multi-objective bandit)? | D1.B explicitly flagged naive OR as "open question — naive may add little signal." D1.C's signals are orthogonal so naive OR should add information, BUT `d_loc_le_2_flag` at 60.7% post-local fire risks the OPPOSITE-saturation failure mode (`bandit_success` always-on). | **Naive OR for D1.E v1**, capped at **≤ 3 OR'd channels** beyond `discovery_binary_reward` per revisit plan §3.3 stopping rule. Document non-naive alternatives in `D1E_SUBSECTION.md` as deferred to D2/L2. Justification: signals are empirically orthogonal (max |ρ| ≤ 0.239), and naive OR is the lowest-risk implementation. Opposite-saturation guard: pre-flight unit test that asserts no V5-static seed's `bandit_success_l1` mean exceeds **0.75** across mut [3000, 6000) — fail-fast if d_loc_le_2 saturates. Threshold 0.75 (not 0.70) because three OR'd channels can legitimately push post-local mean above 0.70 even when reward signal remains informative (per Composer v0.2.1 Pushback 2). Same threshold used in Batch 1 task 6 + R-E-1 for consistency. |
| **Q-E-L1-SIGNALS** | All three D1.C top-3 in L1, or subset? | All-three maximizes signal but increases opposite-saturation risk and reward variance. Subset is conservative but may under-fire. | **All three top-3** (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`). Make selectable via campaign_params for future ablation. Excludes `f_new_flag` (empirically dead on V5 per NFP-9 update) and `recent_marginal_discovery_rate` (continuous; keep as scalar-bandit Layer-2 candidate). |
| **Q-E-INSTR_TYPE_MOD** | `mutation_substrategy_uniqueness` for `INSTR_TYPE_MOD` is degenerate (all-NULL substrategy columns → at most 1 fire per campaign). Exclude INSTR_TYPE_MOD from this channel, special-case it, or leave as-is? | D1.C `d1e_handoff_L1_signals.md` §3 explicitly flagged this. On the V5 corpus, post-local INSTR_TYPE_MOD uniqueness fires are 0, so leaving as-is doesn't pollute V5 numbers — but D1.E's whole point is forward-run dynamics may differ. | **Exclude INSTR_TYPE_MOD from `mutation_substrategy_uniqueness` channel** for D1.E v1. Document in `D1E_SUBSECTION.md`. Rationale: D1.C audit confirmed INSTR_TYPE_MOD has 0 post-local uniqueness fires on V5; excluding is a no-op on the empirical baseline but prevents a single first-INSTR_TYPE_MOD fire from contaminating early-campaign reward signal in the forward run. |
| **Q-E-D_LOC-SOURCE** | `d_loc_le_2_flag` uses the production-semantic `d_loc` (with crash-mode `d_loc=0` schism — ~1.1% of pulls treated as `d_loc ≤ 2` even with non-empty failures) or recompute from `failures` table per pull? | D1.C audit bounded the impact at <0.2 pp on post-local fire rate. Using production semantic is consistent with what `mutation_rewards.d_loc` already stores. | **Use the production-semantic `d_loc` read from in-memory `diag["d_loc"]`** returned by `compute_reward` at `fuzzer.py:1078-1084` (Composer audit Issue 9 — this is the same value that subsequently writes to `mutation_rewards.d_loc`; reading from DB is impossible at the L1 call site because `mutation_rewards` hasn't been written yet). The crash schism is a known production semantic from `coverage_state.py:190-198` — D1.E does NOT diverge from production's existing d_loc definition. Document the schism in `D1E_SUBSECTION.md` Limitations and in code comments next to the L1 wiring. |
| **Q-E-SINGLETON-DEFINITION** | `singleton_failure_flag` uses (a) `COUNT(*) FROM failures == 1` (row form, what D1.C shipped), or (b) `COUNT(DISTINCT constraint_loc) == 1` (loc form, what D1.C spec prose said)? | On V5 s1234 these agree on 996 pulls; 5 pulls have 2 rows at same loc with different `(major, minor)`. Internally consistent across D1.C but spec prose was ambiguous. | **Row form (a)** for D1.E v1 — matches D1.C shipped extractor + Tier-2 metric for internal consistency. Document the choice in code comments + `D1E_SUBSECTION.md`. Loc form is a 0.5% perturbation; not worth a re-audit. |
| **Q-E-K-TARGET** | What value of K for decayexp? D1.A Finding A computed table: K=200 transitions at d=27, K=300 at d=41. Final value depends on legacy `coverage` saturation point. | K must land its 96%→48% transition in the saturation tail of `_local_discoveries`, NOT during the discovery rush. | **Batch 0 SQL pass on legacy `coverage` table** (cumulative `COUNT(*)` curve on D1.A's 10 decay DBs + R2's 10 V5 DBs) pins the saturation point. Spec target: K such that 96%→48% transition occurs at d = 0.80 × (saturation d) — i.e., 80% of the way through legacy coverage discovery. Locked in spec v0.2 amendment after Batch 0. **Tentative placeholder: K = 200** if Batch 0 SQL pass yields legacy coverage saturation at d ≈ 30-40. |
| **Q-E-EPOCH-BOUNDARIES** | Where does the `EpochStageFloor` boundary shift to? D1.A used `(0, 0.55), (2000, 0.35), (4000, 0.20)` — boundary at mut=2000 lands AFTER `local_context_final` saturation (~mut 2800). Pro's intended policy fires too late. | Same as Q-E-K-TARGET — the staircase must fire during the productive window. | **`[(0, 0.55), (1000, 0.35)]`** — two-tier policy. Drop the no-op third tier per D1.A Finding D. First boundary at mut=1000 fires inside the discovery window. Lock after Batch 0 SQL confirms this matches `_local_discoveries` saturation curve geometry. |
| **Q-E-RETROFIX-ABLATION** | Option B (15 jobs: fresh V5 + 5 decayexp + 5 decayepoch, all post-rewire + post-D2.B-Batch-1.5e retrofix) or Option C (25 jobs: 15 above + 10 pre-retrofix decay to isolate retrofix from rewire)? | Option B confounds the L1 rewire with the `PRE_EXEC_REG_MOD` retrofix side-effect (D2.B Batch 1.5e changes V5 mutation behavior). Option C isolates them but costs +67% compute. | **Option B (15 jobs)** for D1.E v1. The retrofix is a single-kind change with bounded surface area (`PRE_EXEC_REG_MOD` only). D1.E subsection will explicitly call out the confound and recommend a follow-on retrofix ablation only IF D1.E v1 results are ambiguous. Saves ~3.5 hours wall + one POS reservation. |
| **Q-E-PRE_EXEC_REG_MOD-SYNC** | D2.B Batch 1.5e (`PRE_EXEC_REG_MOD` retrofix, ~10 LOC) was a hard sync dependency before D1.E dispatches. How to coordinate? | If D1.E dispatches BEFORE D2.B Batch 1.5e merges, V5 + decay runs would use hardcoded `next_read` strategy — same as D1.A archive — but D1.E's whole point is to test the **post-retrofix** V5 baseline under the rewired reward. | **RESOLVED — sync gate satisfied.** D2.B Batch 1.5e landed at `78d036c`; full D2.B done at `e2c2256`. Batch 0 re-verifies this is in HEAD ancestry as defense-in-depth, but no coordination needed. |
| **Q-E-TIER1-VALIDATION** | After Batch 4 collection, validate the L1 signals' empirical claims (orthogonality, non-saturation, disjoint-fire) hold on the fresh D1.E DBs — not just the frozen D1.C corpus? | D1.C's gates were measured on R2 V1/V5 + D1.A archive. Fresh D1.E DBs run under enriched reward; signal dynamics may shift. | **Yes — Batch 4 includes a re-audit pass** (re-run `bug_proximity.extract_tier1_signals_per_db` on the 15 fresh D1.E DBs; emit `d1e_tier1_validation.csv`; flag any signal whose post-local fire rate drops below 1% or correlation exceeds 0.6). Cheap (existing analysis-only code from D1.C). |

### 0.3 Recommended Ivan-greenlight on Q-E questions

| Q | Recommended answer |
|---|---|
| Q-E-L1-COMPOSITION | Naive OR, capped at ≤ 3 channels + opposite-saturation pre-flight test |
| Q-E-L1-SIGNALS | All three top-3 D1.C signals (substrategy_uniqueness + d_loc_le_2 + singleton); make selectable via campaign_params; exclude f_new_flag + recent_marginal_discovery_rate |
| Q-E-INSTR_TYPE_MOD | Exclude INSTR_TYPE_MOD from `mutation_substrategy_uniqueness` channel |
| Q-E-D_LOC-SOURCE | Use production-semantic `d_loc` from in-memory `diag["d_loc"]` (`fuzzer.py:1078-1084`); document crash schism |
| Q-E-SINGLETON-DEFINITION | Row form (`len(failures) == 1` in-memory; equivalent to `COUNT(*) FROM failures == 1` post-write); match D1.C |
| Q-E-K-TARGET | Tentative K ≈ saturation_d × 5.86 (closed-form); lock after Batch 0 SQL pass on legacy `coverage` + `_floor_target` simulation sanity check |
| Q-E-EPOCH-BOUNDARIES | `[(0, 0.55), (1000, 0.35)]` two-tier; lock after Batch 0 |
| Q-E-RETROFIX-ABLATION | Option B (15 jobs, all post-1.5e); confound disclosure in subsection |
| Q-E-PRE_EXEC_REG_MOD-SYNC | RESOLVED — D2.B Batch 1.5e landed at `78d036c`; Batch 0 re-verifies as defense-in-depth |
| Q-E-TIER1-VALIDATION | Yes — re-audit on fresh D1.E DBs in Batch 4; correlate vs `bandit_success_l1` (the enriched bit), not `discovery_binary_reward` |

**If Ivan greenlights this set,** Batches 1+2 (code work) proceed in parallel with the Batch 0 SQL pass. Batch 3 dispatch waits on Q-E-K-TARGET/Q-E-EPOCH-BOUNDARIES Batch 0 outputs (D2.B sync is already satisfied; Batch 0 just re-verifies as defense-in-depth).

---

## 1. Existing data + new module locations

### 1.1 Files modified (production code)

**Schema correction note (Composer audit Issue 1):** `mutation_rewards` does NOT have a `bandit_success` column. Verified `coverage_db.py:229-251` — columns are `(reward, T_new, T_rare, F_new, F_rare, U, Q_loc, Q_rep, Q_glob, Q, S, delta_T, delta_F, n_fail, r_rep, d_loc, d_glob, d_ext, mode)`. The Bernoulli reward bit lives in `reward_counterfactuals.discovery_binary_reward` (line 345). D1.E v2 adds `bandit_success_l1` to `reward_counterfactuals`, not `mutation_rewards`.

| File | Change | Tests must cover |
|---|---|---|
| `a4/standalone/reward_v2.py:60-62` | Extend `compute_bandit_success` signature: `def compute_bandit_success(l_new, g_new, s_new, *, l1_signals: Optional[Mapping[str, int]] = None) -> int`. Backward-compat default: `l1_signals=None` → returns original `1 if (l+g+s) > 0 else 0`. When provided: `1 if (base + sum(int(v) for v in l1_signals.values())) > 0 else 0`. | (a) Backward-compat unit test: `compute_bandit_success(l, g, s)` (no kwarg) returns same value as `compute_bandit_success(l, g, s, l1_signals=None)`. (b) OR-semantics unit test: with `l1_signals={"foo": 1}`, returns 1 even if `l + g + s == 0`. |
| `a4/standalone/reward_v2.py:205-223` (`compute_counterfactuals`) | **DO NOT propagate L1 here.** `compute_counterfactuals` keeps calling `compute_bandit_success(l_new, g_new, s_new)` (no `l1_signals` kwarg). This keeps `reward_counterfactuals.discovery_binary_reward` storing the base OR only — preserves D1.C / D1.A comparability and lets analysis tools read the "what would have happened pre-L1" channel. The L1-enriched bit is stored separately in `bandit_success_l1` (see `coverage_db.py` row below). | Existing `compute_counterfactuals` tests at `test_reward_v2.py:272-310` still pass byte-identically — no new tests needed; just don't regress. |
| `a4/standalone/fuzzer.py` (around line 1078-1115) | Add Tier-1 signal computation between `compute_reward` return (line 1078-1084, which produces `diag` containing `d_loc`) and the `compute_bandit_success` call (line 1113-1115). Compute signals from in-memory state: see §1.2 for per-signal extractor definitions. Then call `compute_bandit_success(l, g, s, l1_signals=signal_dict)` with the dict. Also pass the resulting `bandit_success_l1` into the telemetry write path (see `telemetry_v2.py` row below for the explicit plumbing). | Per-pull replay unit test: signal values produced inline match `bug_proximity.py`'s extractor output on a 1000-pull V5 s1234 replay (cross-check against `a4/runs/iv_pos_8/d1c/d1c_batch1_tier1_audit.csv`). |
| `a4/standalone/telemetry_v2.py:170-207` (`record_full_telemetry` or equivalent entry point — verify exact function name at Batch 1 start) | **Extend signature to accept `bandit_success_l1: Optional[int] = None`** and pass it through to `db.record_reward_counterfactuals(...)` as a new kwarg. Without this, `bandit_success_l1` would be NULL on every row even when the bandit learned from the enriched bit — breaking Batch 4 Q-E-TIER1-VALIDATION (Composer v0.2.1 Pushback 3). Caller (`fuzzer.py`) computes `bandit_success_l1` and passes it through. Default `None` preserves back-compat for any other caller. | Telemetry-plumbing unit test: pass `bandit_success_l1=1` through `record_full_telemetry` → row in `reward_counterfactuals` has `bandit_success_l1 = 1` AND `discovery_binary_reward = compute_bandit_success(l,g,s)` (base only). Pass `bandit_success_l1=None` → row has NULL in new column, base unchanged. |
| `a4/standalone/cli.py` + `_persist_campaign_params` path (see existing floor-schedule serialization at `fuzzer.py:680-688` for the pattern) | Add new `L1_SIGNALS` (list[str]) and `L1_SIGNAL_KIND_EXCLUSIONS` (dict[str, list[str]]) campaign params. Default `[]` (back-compat = pre-D1.E behavior; `compute_bandit_success` is called with `l1_signals=None`). D1.E V5 + decay sub-batches use `["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"]` + `{"mutation_substrategy_uniqueness": ["INSTR_TYPE_MOD"]}`. Validate signal names against an allow-list `{"mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag", "f_new_flag", "recent_marginal_discovery_rate"}` (allows future expansion without code). Persist into `campaign_params.extra_json` using the same JSON serialization the existing floor-schedule does. | CLI test: parse + propagate to fuzzer; round-trip through `extra_json` write+read; reject unknown signal names. |
| `a4/standalone/bandit_ts.py:88` (`ExponentialDecayFloor.K`) | NO code change. K is a constructor argument; D1.E sets it at campaign creation time. | Existing tests cover K parameterization |
| `a4/standalone/bandit_ts.py:103-115` (**`EpochStageFloor`** constructor — NOT `EpochStaircaseFloor`; that name does not exist in code) | NO code change. Stages are constructor argument; D1.E sets `[(0, 0.55), (1000, 0.35)]`. | Existing tests at `test_floor_schedule.py:71` cover stages parameterization |
| `a4/standalone/coverage_db.py` (`reward_counterfactuals` schema at line 340-348 + `record_reward_counterfactuals` write path at line 530-544) | Add new `bandit_success_l1 INTEGER` column to `reward_counterfactuals`. KEEP existing `discovery_binary_reward INTEGER` unchanged (= base OR, populated by unchanged `compute_counterfactuals`). The new column stores the L1-enriched bit the bandit actually learned from. Migration: `ALTER TABLE reward_counterfactuals ADD COLUMN bandit_success_l1 INTEGER`; default NULL on existing archives. Update `record_reward_counterfactuals` signature to accept and persist `bandit_success_l1`. | Migration test: open D1.A archive DB (which lacks the new column) → reads cleanly with `bandit_success_l1` as NULL; existing reads of `discovery_binary_reward` unchanged. |
| `a4/standalone/telemetry_v2.py:209` (already calls `extract_mutation_substrategy`) | NO change here. `fuzzer.py` will reuse the same `extract_mutation_substrategy(kind, config, original_value, mutated_value)` for the `mutation_substrategy_uniqueness` signal extraction. | n/a |

**No production file outside the above 7 is touched by D1.E.** Specifically, `compressed_global_extractor.py` is NOT touched — the NFP-10 byte_addr fix already landed in D1.B Batch 1.6 (commit `71dae77`).

### 1.2 L1 signal extractors (Composer audit Issues 7, 8, 9)

**Composer pushback addressed:** `bug_proximity.py` lives in the analysis tree (`a4/runs/iv_pos_7/analysis/`) and is NOT importable from `a4/standalone/`. D1.E must reproduce the extractor logic inside `standalone/`, ideally in a new tiny module `a4/standalone/l1_signals.py` for cleanliness.

**New module `a4/standalone/l1_signals.py`:**

```python
"""D1.E L1 OR-channel signal extractors. Mirrors bug_proximity.py logic
but lives in standalone so the fuzzer hot path can use it."""

from typing import Any, Mapping, Optional, Set, Tuple

# Copy from a4/runs/iv_pos_7/analysis/bug_proximity.py (empirically derived
# from D1.C 30-DB substrategy audit; INSTR_TYPE_MOD is intentionally ()).
# Composer Batch 1 must verify this copy matches bug_proximity.py byte-for-byte.
KIND_TO_SUBSTRATEGY_FIELDS: dict[str, tuple[str, ...]] = {
    "INSTR_WORD_MOD_SUR": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "INSTR_WORD_MOD_FULL": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "MEM_VAL_MOD": ("byte_lane", "bit_mask", "value_class"),
    "COMP_OUT_MOD": ("value_class",),
    "LOAD_VAL_MOD": ("value_class",),
    "PRE_EXEC_REG_MOD": ("value_class",),
    "STORE_OUT_MOD": ("value_class",),
    "INSTR_TYPE_MOD": (),  # empirically all-NULL on V5 corpus per D1.C audit
}

def composite_substrategy_key(
    kind: str, substrategy_dict: Mapping[str, Any]
) -> tuple:
    fields = KIND_TO_SUBSTRATEGY_FIELDS.get(kind, ())
    return tuple(substrategy_dict.get(f) for f in fields)
```

**Per-signal extraction at `fuzzer.py` (right after `compute_reward` return; right before `compute_bandit_success` call):**

| Signal | Source (in-memory at call site) | Computation | Notes |
|---|---|---|---|
| `mutation_substrategy_uniqueness` | `telemetry_v2.extract_mutation_substrategy(kind, config, original_value, mutated_value)` + per-campaign `self._seen_composite_keys: Set[Tuple[str, tuple]]` | If `kind in L1_SIGNAL_KIND_EXCLUSIONS["mutation_substrategy_uniqueness"]` (default: `["INSTR_TYPE_MOD"]`): signal = 0 (do NOT add to seen set). Else: `key = (kind, composite_substrategy_key(kind, substrategy_dict))`; signal = `0 if key in self._seen_composite_keys else 1`; then `self._seen_composite_keys.add(key)`. | INSTR_TYPE_MOD exclusion is Q-E-INSTR_TYPE_MOD default. The `extract_mutation_substrategy` helper is already imported by `telemetry_v2.py:209` for the `mutation_substrategy` DB write — reuse, do NOT duplicate. |
| `d_loc_le_2_flag` | `diag["d_loc"]` from `compute_reward` return at `fuzzer.py:1078-1084` | `1 if diag["d_loc"] <= 2 else 0` | **Read from in-memory `diag`, NOT from `mutation_rewards` DB** (which hasn't been written at the call site). This is the same value that subsequently writes to `mutation_rewards.d_loc` — i.e., the production semantic including the crash-mode `d_loc=0` schism documented in D1.C audit (`coverage_state.py:190-198` hardcodes `d_loc=0` on crash even when `failures` has rows; affects ~1.1% of pulls; bounded < 0.2 pp impact on D1.C fire rate). |
| `singleton_failure_flag` | `failures` local in fuzzer (the in-memory list passed to `compute_reward` at `fuzzer.py:1078`; same list later written to `failures` table) | `1 if len(failures) == 1 else 0` | Q-E-SINGLETON-DEFINITION = row form. In-memory `len()` is equivalent to `COUNT(*) FROM failures WHERE mutation_id=?` for non-retried pulls (D1.C's Tier-1 extractor reads the DB rows post-write; semantics identical). |

**Pass to `compute_bandit_success`:**

```python
l1_signals = None
if self.L1_SIGNALS:
    l1_signals = {}
    if "mutation_substrategy_uniqueness" in self.L1_SIGNALS:
        l1_signals["mutation_substrategy_uniqueness"] = _msu_value
    if "d_loc_le_2_flag" in self.L1_SIGNALS:
        l1_signals["d_loc_le_2_flag"] = 1 if diag["d_loc"] <= 2 else 0
    if "singleton_failure_flag" in self.L1_SIGNALS:
        l1_signals["singleton_failure_flag"] = 1 if len(failures) == 1 else 0
bandit_success_l1 = compute_bandit_success(
    components["l_new"], components["g_new"], components["s_new"],
    l1_signals=l1_signals,
)
# Pass to scheduler.update(..., bandit_success_l1) AND to telemetry write
```

### 1.3 Persistence model (Composer audit Issue 2)

| Column | Lives in | Stores | Populated by | Read by |
|---|---|---|---|---|
| `discovery_binary_reward` | `reward_counterfactuals` (existing) | Base OR only: `1 if (l_new+g_new+s_new) > 0 else 0` | `compute_counterfactuals` at `reward_v2.py:221` (unchanged) | D1.C extractors, D1.A archive comparison, analysis tools |
| `bandit_success_l1` (NEW) | `reward_counterfactuals` (additive column) | L1-enriched: base OR ∪ Tier-1 signal flags | New write path in `fuzzer.py` (computed inline) | Q-E-TIER1-VALIDATION re-audit, D1.E analysis CSVs, scheduler-input ground truth |

### 1.2 New campaign param shape

Add to `campaign_params.extra_json` JSON blob:

```json
{
  "L1_SIGNALS": ["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"],
  "L1_SIGNAL_KIND_EXCLUSIONS": {
    "mutation_substrategy_uniqueness": ["INSTR_TYPE_MOD"]
  },
  "FLOOR_SCHEDULE": "ExponentialDecayFloor",
  "FLOOR_PARAMS": {"initial": 0.55, "floor_min": 0.20, "K": 200}
}
```

For decayepoch variant:
```json
{
  "L1_SIGNALS": ["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"],
  "L1_SIGNAL_KIND_EXCLUSIONS": {
    "mutation_substrategy_uniqueness": ["INSTR_TYPE_MOD"]
  },
  "FLOOR_SCHEDULE": "EpochStageFloor",
  "FLOOR_PARAMS": {"stages": [[0, 0.55], [1000, 0.35]]}
}
```

For V5-static (post-rewire baseline):
```json
{
  "L1_SIGNALS": ["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"],
  "L1_SIGNAL_KIND_EXCLUSIONS": {
    "mutation_substrategy_uniqueness": ["INSTR_TYPE_MOD"]
  },
  "FLOOR_SCHEDULE": "ConstantFloor",
  "FLOOR_PARAMS": {"value": 0.55}
}
```

### 1.3 New analysis artifacts (post-Batch 3)

Under `a4/runs/iv_pos_8/d1e/`:

| Artifact | Source | Purpose |
|---|---|---|
| `dbs/` | POS dispatch (Batch 3) | 15 raw DBs |
| `analysis/build_d1e_artifacts.py` | NEW | Reads 15 D1.E DBs + 5 D1.A V5-static archive seeds; computes D1.A metric table + new L1-signal metrics |
| `d1e_metrics_table.csv` | analysis script | One row per DB. Columns: `{variant, seed, n_pulls, local_context_final, cgc_final, time_to_46, bandit_success_l1_mean, discovery_binary_reward_mean (ablation: base OR without L1, read from existing column), d_loc_p95, singleton_failure_rate, mutation_substrategy_uniqueness_rate, d_loc_le_2_rate, ...}`. **Row composition (30 rows total):** 15 fresh D1.E rows (5 V5-static + 5 decayexp + 5 decayepoch) + 5 D1.A V5-static archive rows (context, pre-rewire) + 10 R2 rows (5 V5 + 5 V1) (context, pre-D2.A + pre-rewire). These supplementary 15 rows have `bandit_success_l1_mean = NULL` (no L1 column). The primary statistical claims come from the 15 fresh D1.E rows; archive rows are visual context only. |
| `d1e_paired_tests.csv` | analysis script | Paired t-tests: D1.E V5-static vs D1.E decayexp; D1.E V5-static vs D1.E decayepoch; D1.E V5-static vs D1.A V5-static archive (ablation: pure rewire effect) |
| `d1e_floor_dynamics.csv` | analysis script | Floor mode share per 100-mut bin per variant |
| `d1e_tier1_validation.csv` | analysis script | Q-E-TIER1-VALIDATION: post-rewire signal fire rates + correlations on fresh DBs |
| `d1e_recommendation.md` | manual | TL;DR + decision matrix: keep/drop decay variants for V5-paired; K/epoch final values; deferral notes |
| `D1E_SUBSECTION.md` | manual | Pro-facing subsection for Stage 4 D1 report fold-in |
| `IV_POS_8_D1E_NOTEBOOK.ipynb` + `.html` | analysis script | Executable evidence bundle |

---

## 2. Implementation batches

### 2.0 Batch 0 — Pre-work (analysis + sync, no production code change)

**Scope:** SQL pass on legacy `coverage` table + `_floor_target()` simulation sanity check + D2.B sync re-check.

**Schema correction note (Composer audit Issue 3):** Verified `coverage_db.py:150-156` — `coverage` table has `(constraint_loc PK, first_hit_mutation_id, first_hit_at, hit_count)`. There is no `mutation_id` column. The fuzzer's `_local_loc_discoveries` running counter (fed into `ExponentialDecayFloor.K` via `bandit_ts.py:98-99`) increments per-row inserted into `coverage` (see `fuzzer.py:691-699`). So legacy-coverage saturation is correctly anchored to `first_hit_mutation_id` ordering, not `mutation_id`.

**Tasks:**

1. **Legacy `coverage` table saturation SQL pass.** On the 10 R2 V5 DBs + 10 D1.A decay DBs.
   **Unit clarity (Composer audit v0.2.1 Pushback 1):** `ExponentialDecayFloor.K` operates on `local_discoveries` (a count of distinct constraint_locs, range ~tens), NOT `mutation_id` (range ~thousands). Per `bandit_ts.py:81-100`:
   ```python
   def current(self, *, total_mutations: int, local_discoveries: int) -> float:
       raw = self.initial * math.exp(-local_discoveries / self.K)
   ```
   D1.A Finding A's `d=27 for K=200` is a *discovery count*, not a `mutation_id`. Batch 0 must therefore emit **two separate quantities per DB** (do not conflate):

   | Quantity | SQL | Used for |
   |---|---|---|
   | `saturation_d_local` (discovery count) | `SELECT 0.95 * COUNT(*) FROM coverage` (rounded to nearest integer) | **K formula** in task 2 — this is the value of `local_discoveries` at 95% saturation, feeds into `K = saturation_d_local × 5.86` |
   | `saturation_mut` (mutation index) | `WITH ordered AS (SELECT first_hit_mutation_id AS mid FROM coverage ORDER BY first_hit_mutation_id) SELECT mid, ROW_NUMBER() OVER (ORDER BY mid) AS cum FROM ordered;` then take smallest `mid` where `cum >= saturation_d_local` | **Epoch-boundary sanity check** in task 4 — this is the mutation index by which 95% of local discoveries have occurred, used to validate that `[(0, 0.55), (1000, 0.35)]` boundary fires before saturation |

   Aggregate (mean / median / range) of both quantities across V5 paired seeds (1234-1238 in each variant) → `legacy_coverage_saturation_d1e.csv` with columns `db_label, saturation_d_local, saturation_mut, total_local_coverage_rows`.
2. **Pin Q-E-K-TARGET final value (closed-form, primary tool).** Solve: K such that the mode-share step transition (96% → 48% floor share) lands at `d_local = 0.80 × saturation_d_local` — where `d_local` is `local_discoveries` (a count), NOT a mutation_id. Per `bandit_ts.py:234-237` the per-arm quota target = `floor_frac × 100 / 48`; mode share is 48% when `target ∈ (0, 1]`, 96% when `target ∈ (1, 2]`. The 96%→48% step happens at `target = 1`, i.e., `floor_frac × 100 / 48 = 1`, i.e., `floor_frac = 0.48`. From `0.55 × exp(-d_local/K) = 0.48`: **`K = d_local / ln(0.55/0.48) ≈ d_local / 0.1366 ≈ d_local × 7.32`**. So `K_target = 0.80 × saturation_d_local × 7.32 ≈ saturation_d_local × 5.86`. (Verification against D1.A Finding A's published table: K=200 → d_local=27, K=300 → d_local=41 — both match exactly. Expected V5 numbers: if `saturation_d_local ≈ 30-40`, `K_target ≈ 176-234`, matching v0.1's tentative K=200.)
3. **Sanity-check Q-E-K-TARGET via `_floor_target()` simulation (Composer audit Issue 12 partial agreement).** Emit `floor_target_curve_K{K}.csv` over `mut ∈ [0, 6000)` at the chosen K by replaying the `_floor_target` integer-quota math from `bandit_ts.py:230-237`. For each 100-mut bin, record: `mut_bin, local_discoveries_at_bin_end, floor_frac, per_arm_target, expected_mode_share`. Verify the step transition from 96%→48% lands at the empirically-measured saturation tail (i.e., near the mut where `local_discoveries == 0.80 × saturation_d_local`, which is `saturation_mut × (0.80 / 0.95)` approximately if discovery is roughly linear in `mut` over the discovery window). If the closed-form K differs from the simulation by >5 `local_discoveries`-equivalent units, investigate `_EPSILON` handling. **The closed-form is the primary tool; the simulation is a sanity check, not a replacement.**
4. **Pin Q-E-EPOCH-BOUNDARIES final value.** `EpochStageFloor` operates on `total_mutations` (mutation-count space, NOT `local_discoveries`) per `bandit_ts.py:103` docstring "Piecewise-constant floor over total_mutations". So epoch boundaries use `saturation_mut` from task 1, not `saturation_d_local`. First boundary should fire when 30-50% of legacy coverage has been discovered — translated to mutation-count space, that means `boundary_mut ≈ saturation_mut × (0.40 / 0.95) ≈ saturation_mut × 0.42`. Tentative default `(0, 0.55), (1000, 0.35)` matches if `saturation_mut ≈ 2400` on V5 paired seeds (i.e., boundary at mut=1000 is at ~42% × saturation_mut). Adjust if SQL pass shows otherwise.
5. **D2.B Batch 1.5e sync re-check.** `git log --oneline cloud2 | head -20` — confirm `78d036c Batch 1.5e D2.B` is present + ancestor of HEAD. **Already satisfied** at spec v0.2 drafting time (verified by Composer audit); this task is a defense-in-depth re-check before Batch 1 starts.

**Deliverables:**
- `legacy_coverage_saturation_mut_d1e.csv` (per-DB + aggregate saturation point)
- `floor_target_curve_K{K_chosen}.csv` (K-simulation sanity table)
- D1.E spec v0.3 amendment locking Q-E-K-TARGET + Q-E-EPOCH-BOUNDARIES with empirical values
- Sync status note in `a4/docs/cloud2/composer/D1E_BATCH0_REPORT.md`

**Exit criteria:**
- K + epoch boundaries locked in spec v0.3 amendment
- Closed-form K matches simulation step-transition mut within ±5
- D2.B sync re-confirmed (must be ancestor of HEAD)
- Q-E-TIER1-VALIDATION re-audit code path identified (existing `bug_proximity.extract_tier1_signals_per_db` reused; analysis-only call)

### 2.1 Batch 1 — L1 reward rewire (production code change)

**Scope:** `reward_v2.py` + `fuzzer.py` + `coverage_db.py` + `cli.py` + new `l1_signals.py`. See §1.1 + §1.2 for the per-file change spec.

**Tasks:**

1. **Extend `compute_bandit_success` signature** (`reward_v2.py:60-62`):
   ```python
   def compute_bandit_success(
       l_new: int,
       g_new: int,
       s_new: int,
       *,
       l1_signals: Optional[Mapping[str, int]] = None,
   ) -> int:
       """Pro §8 Bernoulli success indicator for Thompson sampling.
       
       L1 OR-channel extension (D1.E): when `l1_signals` is provided, OR-in
       the per-signal flag values. See `IV_POS_8_D1_E_SPEC.md` §0.1.1 for
       layer architecture; D1.C `d1e_handoff_L1_signals.md` for signal definitions.
       
       Backward-compat: `l1_signals=None` (or empty/None values) reproduces
       original V5/D1.A behavior.
       """
       base = 1 if (l_new + g_new + s_new) > 0 else 0
       if not l1_signals:
           return base
       return 1 if (base + sum(int(v) for v in l1_signals.values() if v)) > 0 else 0
   ```
   **Do NOT modify `compute_counterfactuals`** — it keeps storing the base OR in `discovery_binary_reward` (see §1.1 row 2 + §1.3 persistence model).

2. **Create new module `a4/standalone/l1_signals.py`** with `KIND_TO_SUBSTRATEGY_FIELDS` constant + `composite_substrategy_key()` helper (see §1.2). Add a unit test that asserts `KIND_TO_SUBSTRATEGY_FIELDS` exactly matches the constant in `a4/runs/iv_pos_7/analysis/bug_proximity.py` (cross-tree fixture test — read both files at test time, compare). This protects against silent drift between analysis tree and standalone.

3. **Add Tier-1 signal extractors to `fuzzer.py`** (between line 1084 `result.reward_diag = diag` and line 1113 `bandit_success = compute_bandit_success(...)`). Per the wiring sketch in §1.2:
   - Maintain per-campaign `self._l1_seen_composite_keys: Set[Tuple[str, tuple]]` initialized in `__init__`.
   - Compute the 3 signals inline (see §1.2 table) into a `l1_signals` dict ONLY if a signal name is in `self.L1_SIGNALS`; otherwise the dict entry is omitted.
   - Call `compute_bandit_success(l, g, s, l1_signals=l1_signals or None)`.
   - Capture both base and enriched bit (base from `compute_bandit_success(l,g,s)` with `l1_signals=None`, enriched from the call above). Pass enriched to scheduler; pass enriched to telemetry as `bandit_success_l1`.

4. **Persist `bandit_success_l1` to `reward_counterfactuals`** (NOT `mutation_rewards` — Composer audit Issue 1):
   - `coverage_db.py:340-348` schema: add `bandit_success_l1 INTEGER` to `CREATE TABLE`.
   - `coverage_db.py:530-544` `record_reward_counterfactuals`: extend signature with `bandit_success_l1: Optional[int] = None`; extend INSERT SQL accordingly.
   - `telemetry_v2.py:197-203` (the caller): plumb `bandit_success_l1` through `record_full_telemetry`.
   - Migration: existing DBs read with `bandit_success_l1` as NULL; D1.A and R2 archives remain readable.

5. **CLI plumbing.** Per §1.1 row 4 — extend `cli.py` + the `_persist_campaign_params` path that already serializes the floor schedule into `campaign_params.extra_json` at `fuzzer.py:680-688`. Reuse the same serialization pattern for `L1_SIGNALS` + `L1_SIGNAL_KIND_EXCLUSIONS`.

6. **Opposite-saturation pre-flight test** (Composer audit Issue 5 — use the right window):
   - Build a V5-static replay fixture that runs through 6000 pulls under `L1_SIGNALS=["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"]`.
   - **Fixture must run on post-1.5e codebase** (commit `78d036c` or later) — NOT R2 archive replay, which uses the hardcoded `PRE_EXEC_REG_MOD next_read` strategy. Post-1.5e fixture matches D1.E's actual dispatch conditions (Composer v0.2.1 Minor 2).
   - Assert `mean(bandit_success_l1 for mut in [3000, 6000)) <= 0.75` — the **post-local window** where D1.C measured `d_loc_le_2_flag` fires 60.7%. This catches the actual opposite-saturation risk; an early-campaign window would not. Threshold matches Q-E-L1-COMPOSITION + R-E-1 (Composer v0.2.1 Pushback 2 — unified at 0.75).
   - On failure, the test message must point at D1.C `d_loc_le_2_flag` opposite-saturation caveat and link this spec's Q-E-L1-COMPOSITION + risk R-E-1.

**Tests required:**

- (a) **Backward-compat unit test:** `compute_bandit_success(l, g, s)` (no kwarg) returns same value as `compute_bandit_success(l, g, s, l1_signals=None)` across all input combinations in existing `test_reward_v2.py:108-119` table. Plus byte-identical pass through `compute_counterfactuals` → `discovery_binary_reward` stored value (Composer Issue 2 invariant).
- (b) **L1 OR-semantics unit test:** `compute_bandit_success(0, 0, 0, l1_signals={"foo": 1})` returns 1; `compute_bandit_success(0, 0, 0, l1_signals={"foo": 0})` returns 0; `compute_bandit_success(1, 0, 0, l1_signals={"foo": 0})` returns 1.
- (c) **Per-signal extractor replay test:** on a 1000-pull V5 s1234 fixture, the 3 inline signal values produced in `fuzzer.py` match `bug_proximity.extract_tier1_signals_per_db` output column-for-column.
- (d) **`KIND_TO_SUBSTRATEGY_FIELDS` cross-tree fixture test:** Standalone `l1_signals.KIND_TO_SUBSTRATEGY_FIELDS` == analysis-tree `bug_proximity.KIND_TO_SUBSTRATEGY_FIELDS` byte-for-byte.
- (e) **INSTR_TYPE_MOD exclusion test:** 100-pull fixture where the only mutations are INSTR_TYPE_MOD — `mutation_substrategy_uniqueness` always 0; nothing added to `_l1_seen_composite_keys` for that kind.
- (f) **Post-1.5e regression golden-trace test** (Composer audit Issue 4 fix): Post-`78d036c` codebase + `L1_SIGNALS=[]` + a fixed seed reproduces itself byte-identically across reruns. **Do NOT claim byte-identity to the R2 V5 archive** — that's broken post-1.5e because `PRE_EXEC_REG_MOD` is now RNG-picked per pull (`fuzzer.py:1685-1686`). The test catches L1 wiring inadvertently affecting non-L1 path; it does NOT claim equivalence with the pre-1.5e codebase.
- (g) **Opposite-saturation pre-flight** on the `[3000, 6000)` window per task 6.
- (h) **Schema migration test:** open D1.A archive DB → `SELECT bandit_success_l1 FROM reward_counterfactuals` returns NULL for existing rows; `SELECT discovery_binary_reward FROM reward_counterfactuals` returns unchanged values.

**Deliverables:**
- 5 production file modifications + 1 new module (`a4/standalone/l1_signals.py`)
- Test suite passing (existing + ~8 new tests; aim for ≥ 525 standalone passed)
- `a4/docs/cloud2/composer/D1E_BATCH1_REPORT.md`

**Exit criteria:**
- All tests pass including the cross-tree `KIND_TO_SUBSTRATEGY_FIELDS` fixture and the post-1.5e regression golden trace
- `git diff cloud2 -- a4/standalone/` shows only the 5 modified files + 1 new module
- Composer reports any post-1.5e regression-trace divergence (should be zero; if non-zero, investigate Batch 1.5e interaction with the L1 wiring path)
- Opposite-saturation pre-flight passes (or — if it fails — Composer + Opus convene to either drop `d_loc_le_2_flag`, raise the threshold to `<= 1`, or move to weighted composition)

### 2.2 Batch 2 — K/epoch retune + dispatch infrastructure

**Scope:** Wire Batch 0's locked K + epoch boundaries into the D1.E POS dispatch config. No production code change.

**Tasks:**

1. Add D1.E dispatch config to `a4/runs/iv_pos_8/d1e/dispatch/` (mirror `d1a/dispatch/` structure):
   - `dispatch_d1e_v5_static.yaml` — 5 seeds, V5_semantic_v2 catalog, `ConstantFloor(0.55)`, L1_SIGNALS=top-3.
   - `dispatch_d1e_decayexp.yaml` — 5 seeds, V5_semantic_v2 catalog, `ExponentialDecayFloor(K=<Batch 0 value>)`, L1_SIGNALS=top-3.
   - `dispatch_d1e_decayepoch.yaml` — 5 seeds, V5_semantic_v2 catalog, `EpochStageFloor(stages=[(0, 0.55), (1000, 0.35)])`, L1_SIGNALS=top-3.
2. POS reservation sketch: 8 nodes × ~5.5h per job → ~2 sequential dispatches (8 + 7). One 6h reservation block.
3. POS sanity smoke: dispatch 1 V5-static seed (e.g., s1234), let run to completion (~5.5h), inspect raw DB for schema completeness + `bandit_success_l1` non-NULL on all 6000 pulls.

**Deliverables:**
- 3 dispatch YAML configs
- 1 POS sanity smoke run (1 DB)
- `a4/docs/cloud2/composer/D1E_BATCH2_REPORT.md`

**Exit criteria:**
- Sanity-smoke DB has 6000 rows, `bandit_success_l1` populated on all pulls, schema migration successful
- POS daemon healthy (per POS_PLAYBOOK §12.52); SSH-bypass plan ready in case POS upload fails
- Full 15-job dispatch plan reviewed by Ivan

### 2.3 Batch 3 — POS dispatch + collection

**Scope:** Run all 15 jobs; collect DBs.

**Hard prerequisite:** D2.B Batch 1.5e merged to `cloud2` HEAD (verified in Batch 0 sync check + re-verified at Batch 3 start).

**Tasks:**

1. Dispatch 15 jobs in 2 sequential batches (8 + 7).
2. After each batch, verify SSH-bypass collection completes successfully.
3. Sanity-check each DB: 6000 pulls, `bandit_success_l1` populated, no crash signatures.

**Deliverables:**
- 15 DBs in `a4/runs/iv_pos_8/d1e/dbs/`
- `a4/docs/cloud2/composer/D1E_BATCH3_REPORT.md` with per-DB sanity-check table

**Exit criteria:**
- 15 DBs collected
- All schema-complete
- POS reservation closed cleanly

### 2.4 Batch 4 — Analysis + subsection drafting

**Scope:** All analysis CSVs + notebook + subsection draft.

**Tasks:**

1. Build `d1e_metrics_table.csv` (30 rows: 15 fresh D1.E DBs + 5 D1.A V5-static archive + 10 R2 V5/V1 — the 15 supplementary rows are context only and have `bandit_success_l1_mean = NULL`; statistical comparisons use the 15 fresh D1.E rows).
2. Build `d1e_paired_tests.csv` with three paired-test comparisons:
   - D1.E V5-static vs D1.E decayexp (effect of decay under enriched reward)
   - D1.E V5-static vs D1.E decayepoch (same, epoch variant)
   - D1.E V5-static vs D1.A V5-static archive (effect of pure L1 rewire isolated from decay — note: confounded with PRE_EXEC_REG_MOD retrofix per Q-E-RETROFIX-ABLATION)
3. Build `d1e_floor_dynamics.csv` per D1.A's pattern (floor mode share per 100-mut bin per variant).
4. Q-E-TIER1-VALIDATION: re-run `bug_proximity.extract_tier1_signals_per_db` on the 15 fresh D1.E DBs → `d1e_tier1_validation.csv`. **Important (Composer v0.2.1 Minor 1):** D1.C's extractor defaults to correlating against `discovery_binary_reward`. For D1.E it must correlate against **`bandit_success_l1`** (the L1-enriched bit the bandit actually learned from), NOT `discovery_binary_reward` (which stays base-only per §1.3 persistence model). Either (a) modify `extract_tier1_signals_per_db` to accept a target-column parameter and pass `"bandit_success_l1"`, or (b) write a small D1.E-specific wrapper that re-reads the rows and computes correlation manually. Flag any signal whose post-local fire rate drops below 1% or correlation vs `bandit_success_l1` exceeds 0.6.
5. Build notebook `IV_POS_8_D1E_NOTEBOOK.ipynb` (executed) + HTML.
6. Draft `d1e_recommendation.md` (Pro-facing TL;DR + decision matrix).
7. Draft `D1E_SUBSECTION.md` (Pro-facing subsection for Stage 4 D1 report fold-in). Must include:
   - Scope disclaimer (V5 catalog only; Hybrid V7 / V7 / Arguzz-with-thompson untested — mirror D1.C pattern)
   - Confound disclosure: D1.E V5-static vs D1.A V5-static comparison confounds L1 rewire with `PRE_EXEC_REG_MOD` retrofix
   - L1 signal validation results (Q-E-TIER1-VALIDATION)
   - Singleton-decay finding follow-up: did L1 wiring of `singleton_failure_flag` improve decay's gradient (interpretation b in D1.C §4.3 Finding C) or not (interpretation a)?
   - K/epoch retune effect: did decay variants finally separate from V5-static on `local_context_final`?

**Deliverables:**
- 4 CSVs + 1 notebook + 1 recommendation + 1 subsection
- `a4/docs/cloud2/composer/D1E_BATCH4_REPORT.md`

**Exit criteria:**
- All artifacts generated + sanity-invariant-checked (mirror D1.B/D1.C exit criteria)
- Subsection draft reviewed by Opus + Ivan
- Ready for Stage 4 D1 report assembly

---

## 3. Risks + mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **R-E-1: Opposite saturation** — `bandit_success_l1` goes always-on because `d_loc_le_2_flag` at 60.7% post-local fire rate dominates the OR | Medium | High (reward signal becomes uninformative — same failure mode as D1.A in opposite direction) | Q-E-L1-COMPOSITION pre-flight test catches mean > 0.75 in **mut [3000, 6000)** (matches D1.C gate window — Composer audit Issue 5 fix); if triggered, Ivan + Opus decide to (a) drop `d_loc_le_2_flag`, (b) switch to non-naive composition (weighted OR), or (c) raise the d_loc threshold (e.g., `d_loc <= 1`) |
| ~~R-E-2: PRE_EXEC_REG_MOD retrofix delays D1.E~~ | **RESOLVED** at spec v0.2 drafting | n/a | D2.B Batch 1.5e landed at `78d036c`; full D2.B done at `e2c2256`. Sync gate satisfied. Risk closed. |
| **R-E-3: K target wrong** — Batch 0 SQL pass under-estimates legacy coverage saturation, K transition lands too early | Low | Medium (decayexp behaves like ConstantFloor again, repeat D1.A Finding A) | K is derived from 80% × saturation_d, not 50% — buffer against under-estimation. Sanity check tied to **Batch 0 task 3 `_floor_target` simulation** (Composer audit Issue 12 partial): the simulated step transition must land at mut ≥ 80% × saturation_d. If closed-form K and simulation diverge by >5 mut, investigate `_EPSILON` handling at `bandit_ts.py:234-237` before proceeding to Batch 1. |
| **R-E-4: Q-E-TIER1-VALIDATION reveals signal drift** — post-rewire DBs show signals correlating differently than frozen D1.C corpus | Medium | Medium (D1.C's empirical orthogonality claim invalidated for D1.E run; subsection must disclose) | Batch 4 re-audit is the explicit catch. If max |ρ| > 0.6 on fresh DBs for any L1 signal (correlated against `bandit_success_l1`, NOT `discovery_binary_reward` — Composer audit Issue 2 fix), disclose in subsection + flag for D2 / Hybrid V7 re-evaluation |
| **R-E-5: Decay variants still don't separate from V5-static on `local_context_final`** even under enriched reward | Medium | High but expected | This IS a valid D1.E outcome — would mean decay is genuinely orthogonal to the discovery-rate bottleneck (i.e., the floor schedule is not the lever). Subsection frames as "decay+L1 still insufficient on V5; defer to Hybrid V7 + decay re-test." |
| **R-E-6: POS daemon failure** during Batch 3 (D1.A precedent) | Medium | High (loses N hours of compute) | SSH-bypass collection plan ready (POS_PLAYBOOK §12.52); allocate 2 reservation blocks instead of 1; first reservation = 8 jobs, second = 7 jobs + retry buffer |
| **R-E-7: Schema migration regression** — adding `bandit_success_l1` column to **`reward_counterfactuals`** (NOT `mutation_rewards`; Composer audit Issue 1 fix) breaks an existing R2 archive read path elsewhere | Low | Medium | Migration test (Batch 1 test (h)) explicitly opens D1.A archive DB + reads `discovery_binary_reward` (unchanged) and `bandit_success_l1` (NULL on archive rows). Composer must `rg -n reward_counterfactuals a4/standalone/` to find all consumers + verify NULL handling. |
| **R-E-8: Confound between L1 rewire and PRE_EXEC_REG_MOD retrofix** in V5-static vs V5-static archive comparison | Certain (it's the cost of Option B per Q-E-RETROFIX-ABLATION) | Low to medium | Explicit subsection disclosure; Open Decision: do we run Option C ablation (~10 jobs, +1 reservation) in a D1.E follow-up if v1 results are ambiguous? |

---

## 4. Composer kickoff checklist

Before kicking off Batch 0, Composer must:

1. **Read all 7 load-bearing input files** listed at the top of this spec (now includes `D1C_AUDIT_REPORT.md` per v0.2).
2. **Confirm Ivan greenlight on Q-E-* defaults** (or Ivan's overrides if any).
3. **Run `git log --oneline cloud2 | head -20`** and confirm all of:
   - `3a8487c "Check d1.c"` is present (D1.C committed)
   - `71dae77 Check d1.b` is present (D1.B committed, contains NFP-10 byte_addr fix)
   - `7b66fb9 D2.A Batch 2: mutations.outcome column...` is present (D2.A back-compat preserved)
   - **`78d036c Batch 1.5e D2.B`** is present (PRE_EXEC_REG_MOD retrofix — D1.E sync gate)
   - `e2c2256 d2.b-ps-1: remove 5 dead arms from MUTATION_KINDS` is present (D2.B feature-complete; final cleanup)
4. **Run `pytest a4/standalone/tests/` baseline** and record passed count for regression detection.
5. **Open Q-E-K-TARGET / Q-E-EPOCH-BOUNDARIES as TODOs** — these lock in spec v0.3 amendment after Batch 0 SQL pass + simulation sanity table.
6. **Confirm POS reservation availability** (8-node block, ~6h) with Ivan before Batch 2 sanity smoke.

After Batch 0 SQL pass + simulation:
7. Compose spec v0.3 amendment with final K + epoch values (verify closed-form K matches `_floor_target` simulation step-transition mut within ±5); Ivan + Opus review before Batch 1 kickoff.

---

## 5. Hand-off + disclaimer

D1.E delivers:

- **`a4/runs/iv_pos_8/d1e/dbs/`** — 15 fresh DBs
- **`d1e_metrics_table.csv`** — 30+ row metric table
- **`d1e_paired_tests.csv`** — 3 paired comparisons (decayexp vs static; decayepoch vs static; pure-rewire ablation)
- **`d1e_floor_dynamics.csv`** — floor mode share per variant
- **`d1e_tier1_validation.csv`** — Q-E-TIER1-VALIDATION signal re-audit
- **`d1e_recommendation.md`** — Pro-facing TL;DR
- **`D1E_SUBSECTION.md`** — Pro-facing subsection for Stage 4 D1 report fold-in
- **`IV_POS_8_D1E_NOTEBOOK.ipynb` + `.html`** — executable evidence

**Critical disclaimer (mirror D1.A FROZEN + D1.B + D1.C scope language):**

- D1.E is scoped to the **V5_semantic_v2 catalog + cTS scheduler family**. Results do NOT transfer automatically to Hybrid V7 (Pro §15 Priority 1), V7 (Priority 3), or Arguzz-with-thompson (§14 ablation).
- D1.E tests **L0 + L1 only** per NFP-9. Scalar-reward bandit (L2) and per-channel reward tracking (D1.B §4 open alternative) remain deferred.
- D1.E v1 uses **Option B** (15-job fresh V5 + decay, post-rewire + post-retrofix). The V5-static vs V5-static archive comparison confounds L1 rewire with `PRE_EXEC_REG_MOD` retrofix; explicit follow-up Option C ablation is conditional on v1 results.

**D1.E does NOT validate L1 enrichment on Hybrid V7.** If Pro's Priority-1 schedule lands Hybrid V7 before D1.E v1 conclusions are acted on, a parallel Hybrid V7 + D1.C Tier-1 re-audit + D1.E L1 re-validation is recommended before committing to V5-paired architectural decisions based on D1.E findings.

---

## 6. Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Opus | Initial v0.1 draft after D1.C commit `3a8487c`; pending Ivan greenlight on Q-E-* defaults |
| 2026-06-18 | Opus | **v0.2 — post-Composer-audit refresh.** 11 confirmed issues fixed (see header revision note). Schema corrected: `bandit_success_l1` lives in `reward_counterfactuals`, not `mutation_rewards`. Persistence model explicit (Issue 2): `discovery_binary_reward` stays base-only, `bandit_success_l1` is the new enriched column. Batch 0 SQL corrected to use `coverage.first_hit_mutation_id`. Golden trace reframed to post-1.5e regression. Opposite-saturation pre-flight moved to `[3000, 6000)`. `EpochStageFloor` (not `EpochStaircaseFloor`) throughout. `mutation_substrategy_uniqueness` wiring spec'd via existing `telemetry_v2.extract_mutation_substrategy` + new `l1_signals.py` module. `d_loc_le_2_flag` reads in-memory `diag["d_loc"]`. Q-E-RETROFIX / Q-E-PRE_EXEC_REG_MOD-SYNC reflect D2.B DONE (commits `78d036c` → `e2c2256`). Opus pushed back on Composer Issue 12 (K closed-form is mathematically exact); added simulation sanity table as partial agreement. Briefing v0.3 (separate doc) carries the §6.1 L1 row fix + D2.A byte-identity softening. |
| 2026-06-18 | Opus | **v0.2.1 — Composer 2nd-pass audit fixes.** Three confirmed pushbacks: **(P1) Batch 0 unit conflation** — `ExponentialDecayFloor.K` uses `local_discoveries` (count), NOT `mutation_id` (index). My v0.2 wording "this `mid` is the per-DB legacy-coverage saturation point" wrongly conflated the two. Fix: Batch 0 task 1 now emits BOTH `saturation_d_local` (discovery count = `0.95 × COUNT(*)`) for K formula AND `saturation_mut` (mutation index) for epoch boundary; tasks 2-4 use the right unit. **(P2) Threshold 0.70 vs 0.75 inconsistency** — unified at 0.75 in Q-E-L1-COMPOSITION + Batch 1 task 6 + R-E-1. Three OR'd channels can legitimately push post-local mean above 0.70 even when reward signal remains informative. **(P3) `bandit_success_l1` telemetry plumbing underspecified** — explicit `telemetry_v2.py:170-207` row added requiring signature extension `record_full_telemetry(..., bandit_success_l1: Optional[int] = None)` with pass-through to `record_reward_counterfactuals`. Without this, the new column stays NULL and Batch 4 Q-E-TIER1-VALIDATION breaks. Plus two minor clarifications: Q-E-TIER1-VALIDATION must correlate vs `bandit_success_l1` not `discovery_binary_reward` (extractor needs target-column param); pre-flight fixture must be post-1.5e codebase (not R2 archive). Composer's third minor note about `INSTR_WORD_MOD` (bare) in `KIND_TO_SUBSTRATEGY_FIELDS` is a misread — my spec only lists SUR + FULL, matching `bug_proximity.py:60-61` exactly; bare `INSTR_WORD_MOD` is recognized by `telemetry_v2.word_kinds` but is NOT in the V5 catalog, so the cross-tree fixture test is correct as written. Spec is now implementation-safe at v0.2.1; awaiting Ivan Q-E-* greenlight. |
