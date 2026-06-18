# D1.E — V5 Reward-Rewired Re-run: Implementation Spec

**Parent plan:** `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.E + `IV_POS_8_D1_REVISIT_PLAN.md` v0.6 §3.3 (full D1.E target description) + §3.1.2 + §3.2.1 (hand-off file indices)
**Pro references:** `ProG_Report_3.md` §7 (Stage 2 enriched reward signals), §11 (CGC bucketing), §15 (priorities)
**Status:** **DRAFT v0.1 — awaiting Ivan greenlight on Q-E-* open questions before Batch 0 kickoff.** D1.A (FROZEN), D1.B (commit `71dae77`), D1.C (commit `3a8487c`), and D2.A (commits `b844e8e` + `7b66fb9`) are all DONE. D2.B Batch 1.5e (`PRE_EXEC_REG_MOD` retrofix) is a hard sync dependency before Batch 3 dispatches.
**Author:** Opus
**Branch:** `cloud2`

**Load-bearing inputs (mandatory reads for spec drafting and Composer execution):**
- `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` (D1.B's L0 choice + L1 open question framing)
- `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` (D1.B's saturation inversion finding)
- `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` (D1.C's full signal reference)
- `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` (D1.C's L1 recommendations + empirical disclosures)
- `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` (frozen D1.A findings, especially Finding D scheduler-geometry + Finding F reward-saturation)
- `a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md` NFP-9 (D1.E reward rewire framing, including 2026-06-17 UPDATE on `f_new` empirical deadness)

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
| `EpochStaircaseFloor` boundaries | `[(0, 0.55), (2000, 0.35), (4000, 0.20)]` | **`[(0, 0.55), (1000, 0.35)]`** (drop the no-op third tier per Finding D; shift first boundary earlier so policy differs from V5-static during productive window) | D1.A Finding D: 0.35→0.20 mechanically invisible to scheduler; Finding C: decayepoch ≡ V5-static through mut ~2049 by construction |

**Both retunes are driven by `_local_discoveries` (legacy `coverage` table cumulative count) per Pro §7 verbatim formula and `bandit_ts.py:98-100`.** D1.B's CGC saturation point does NOT feed K (anti-Pro per NFP-9).

### 0.1.3 Why this is necessary after D1.A + D1.B + D1.C

D1.A established: floor decay alone does not move `local_context_final` under sparse binary reward. The reward signal saturated before the floor decay could matter.

D1.B established: L0 schema-swap cannot extend the post-local discriminating window — coarsened variants make it WORSE.

D1.C established: There ARE per-mutation signals (3 Tier-1) that fire post-local on >5% of pulls AND are orthogonal (|ρ| < 0.4) to the existing bandit success bit on the V5 corpus.

**D1.E is the integration point.** If the enriched reward gives decay a discriminating gradient (`local_context_final`, `cgc_final`, or the new Tier-2 bug-proximity metrics improve significantly on decay), Pro's §7 Stage 2 vision is validated. If it does NOT, decay variants are deprioritized for V5-paired runs (kept available for Hybrid V7 per Pro §15 Priority 1).

### 0.2 Open questions Ivan must resolve before Batch 0

| ID | Question | Why it matters | Recommendation (default if Ivan doesn't pick) |
|---|---|---|---|
| **Q-E-L1-COMPOSITION** | Wire D1.C signals via naive OR into `compute_bandit_success`, or use one of the richer compositions D1.B §4 listed (per-channel reward tracking, weighted reward boost, multi-objective bandit)? | D1.B explicitly flagged naive OR as "open question — naive may add little signal." D1.C's signals are orthogonal so naive OR should add information, BUT `d_loc_le_2_flag` at 60.7% post-local fire risks the OPPOSITE-saturation failure mode (`bandit_success` always-on). | **Naive OR for D1.E v1**, capped at **≤ 3 OR'd channels** beyond `discovery_binary_reward` per revisit plan §3.3 stopping rule. Document non-naive alternatives in `D1E_SUBSECTION.md` as deferred to D2/L2. Justification: signals are empirically orthogonal (max |ρ| ≤ 0.239), and naive OR is the lowest-risk implementation. Opposite-saturation guard: pre-flight unit test that asserts no V5-static seed's `bandit_success` mean exceeds 0.70 across mut [3000, 6000) — fail-fast if d_loc_le_2 saturates. |
| **Q-E-L1-SIGNALS** | All three D1.C top-3 in L1, or subset? | All-three maximizes signal but increases opposite-saturation risk and reward variance. Subset is conservative but may under-fire. | **All three top-3** (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`). Make selectable via campaign_params for future ablation. Excludes `f_new_flag` (empirically dead on V5 per NFP-9 update) and `recent_marginal_discovery_rate` (continuous; keep as scalar-bandit Layer-2 candidate). |
| **Q-E-INSTR_TYPE_MOD** | `mutation_substrategy_uniqueness` for `INSTR_TYPE_MOD` is degenerate (all-NULL substrategy columns → at most 1 fire per campaign). Exclude INSTR_TYPE_MOD from this channel, special-case it, or leave as-is? | D1.C `d1e_handoff_L1_signals.md` §3 explicitly flagged this. On the V5 corpus, post-local INSTR_TYPE_MOD uniqueness fires are 0, so leaving as-is doesn't pollute V5 numbers — but D1.E's whole point is forward-run dynamics may differ. | **Exclude INSTR_TYPE_MOD from `mutation_substrategy_uniqueness` channel** for D1.E v1. Document in `D1E_SUBSECTION.md`. Rationale: D1.C audit confirmed INSTR_TYPE_MOD has 0 post-local uniqueness fires on V5; excluding is a no-op on the empirical baseline but prevents a single first-INSTR_TYPE_MOD fire from contaminating early-campaign reward signal in the forward run. |
| **Q-E-D_LOC-SOURCE** | `d_loc_le_2_flag` uses `mutation_rewards.d_loc` (with crash-mode `d_loc=0` schism — ~1.1% of pulls treated as `d_loc ≤ 2` even with non-empty failures) or recompute from `failures` table per pull? | D1.C audit bounded the impact at <0.2 pp on post-local fire rate. Using stored is consistent with how the L1 channel would be computed in the fuzzer hot path. | **Use stored `mutation_rewards.d_loc`** (computed inline in `coverage_state.py:201-206`). The crash schism is a known production semantic — D1.E should NOT diverge from production's existing d_loc definition. Document the schism in `D1E_SUBSECTION.md` Limitations and in code comments next to the L1 wiring. |
| **Q-E-SINGLETON-DEFINITION** | `singleton_failure_flag` uses (a) `COUNT(*) FROM failures == 1` (row form, what D1.C shipped), or (b) `COUNT(DISTINCT constraint_loc) == 1` (loc form, what D1.C spec prose said)? | On V5 s1234 these agree on 996 pulls; 5 pulls have 2 rows at same loc with different `(major, minor)`. Internally consistent across D1.C but spec prose was ambiguous. | **Row form (a)** for D1.E v1 — matches D1.C shipped extractor + Tier-2 metric for internal consistency. Document the choice in code comments + `D1E_SUBSECTION.md`. Loc form is a 0.5% perturbation; not worth a re-audit. |
| **Q-E-K-TARGET** | What value of K for decayexp? D1.A Finding A computed table: K=200 transitions at d=27, K=300 at d=41. Final value depends on legacy `coverage` saturation point. | K must land its 96%→48% transition in the saturation tail of `_local_discoveries`, NOT during the discovery rush. | **Batch 0 SQL pass on legacy `coverage` table** (cumulative `COUNT(*)` curve on D1.A's 10 decay DBs + R2's 10 V5 DBs) pins the saturation point. Spec target: K such that 96%→48% transition occurs at d = 0.80 × (saturation d) — i.e., 80% of the way through legacy coverage discovery. Locked in spec v0.2 amendment after Batch 0. **Tentative placeholder: K = 200** if Batch 0 SQL pass yields legacy coverage saturation at d ≈ 30-40. |
| **Q-E-EPOCH-BOUNDARIES** | Where does the `EpochStaircaseFloor` boundary shift to? D1.A used `(0, 0.55), (2000, 0.35), (4000, 0.20)` — boundary at mut=2000 lands AFTER `local_context_final` saturation (~mut 2800). Pro's intended policy fires too late. | Same as Q-E-K-TARGET — the staircase must fire during the productive window. | **`[(0, 0.55), (1000, 0.35)]`** — two-tier policy. Drop the no-op third tier per D1.A Finding D. First boundary at mut=1000 fires inside the discovery window. Lock after Batch 0 SQL confirms this matches `_local_discoveries` saturation curve geometry. |
| **Q-E-RETROFIX-ABLATION** | Option B (15 jobs: fresh V5 + 5 decayexp + 5 decayepoch, all post-rewire + post-D2.B-Batch-1.5e retrofix) or Option C (25 jobs: 15 above + 10 pre-retrofix decay to isolate retrofix from rewire)? | Option B confounds the L1 rewire with the `PRE_EXEC_REG_MOD` retrofix side-effect (D2.B Batch 1.5e changes V5 mutation behavior). Option C isolates them but costs +67% compute. | **Option B (15 jobs)** for D1.E v1. The retrofix is a single-kind change with bounded surface area (`PRE_EXEC_REG_MOD` only). D1.E subsection will explicitly call out the confound and recommend a follow-on retrofix ablation only IF D1.E v1 results are ambiguous. Saves ~3.5 hours wall + one POS reservation. |
| **Q-E-PRE_EXEC_REG_MOD-SYNC** | D2.B Batch 1.5e (`PRE_EXEC_REG_MOD` retrofix, ~10 LOC) is a hard sync dependency before D1.E dispatches. How to coordinate? | If D1.E dispatches BEFORE D2.B Batch 1.5e merges, V5 + decay runs use hardcoded `next_read` strategy — same as D1.A archive — but D1.E's whole point is to test the **post-retrofix** V5 baseline under the rewired reward. | **Batch 0 includes a sync check** — verify D2.B Batch 1.5e has merged to `cloud2` HEAD before Batch 3 dispatch. If D2.B is delayed, Batch 1+2 (code work) proceed in parallel; Batch 3 (POS dispatch) blocks on D2.B sync. Ivan coordinates merge order with D2 chat. |
| **Q-E-TIER1-VALIDATION** | After Batch 4 collection, validate the L1 signals' empirical claims (orthogonality, non-saturation, disjoint-fire) hold on the fresh D1.E DBs — not just the frozen D1.C corpus? | D1.C's gates were measured on R2 V1/V5 + D1.A archive. Fresh D1.E DBs run under enriched reward; signal dynamics may shift. | **Yes — Batch 4 includes a re-audit pass** (re-run `bug_proximity.extract_tier1_signals_per_db` on the 15 fresh D1.E DBs; emit `d1e_tier1_validation.csv`; flag any signal whose post-local fire rate drops below 1% or correlation exceeds 0.6). Cheap (existing analysis-only code from D1.C). |

### 0.3 Recommended Ivan-greenlight on Q-E questions

| Q | Recommended answer |
|---|---|
| Q-E-L1-COMPOSITION | Naive OR, capped at ≤ 3 channels + opposite-saturation pre-flight test |
| Q-E-L1-SIGNALS | All three top-3 D1.C signals (substrategy_uniqueness + d_loc_le_2 + singleton); make selectable via campaign_params; exclude f_new_flag + recent_marginal_discovery_rate |
| Q-E-INSTR_TYPE_MOD | Exclude INSTR_TYPE_MOD from `mutation_substrategy_uniqueness` channel |
| Q-E-D_LOC-SOURCE | Use stored `mutation_rewards.d_loc` (production semantic); document crash schism |
| Q-E-SINGLETON-DEFINITION | Row form (`COUNT(*) FROM failures == 1`); match D1.C |
| Q-E-K-TARGET | Tentative K=200; lock after Batch 0 SQL pass on legacy `coverage` |
| Q-E-EPOCH-BOUNDARIES | `[(0, 0.55), (1000, 0.35)]` two-tier; lock after Batch 0 |
| Q-E-RETROFIX-ABLATION | Option B (15 jobs); confound disclosure in subsection |
| Q-E-PRE_EXEC_REG_MOD-SYNC | Batch 0 sync check; Batch 1+2 parallel; Batch 3 blocks on D2.B merge |
| Q-E-TIER1-VALIDATION | Yes — re-audit on fresh D1.E DBs in Batch 4 |

**If Ivan greenlights this set,** Batches 1+2 (code work) proceed in parallel with the Batch 0 SQL pass. Batch 3 dispatch waits on D2.B Batch 1.5e + Q-E-K-TARGET/Q-E-EPOCH-BOUNDARIES Batch 0 outputs.

---

## 1. Existing data + new module locations

### 1.1 Files modified (production code)

| File | Change | Tests must cover |
|---|---|---|
| `a4/standalone/reward_v2.py:60-62` | Extend `compute_bandit_success` signature to accept optional Tier-1 signal flags. Backward-compat default: signals=None → original behavior. | Golden-trace test: signals=None reproduces V5 R2 archive byte-for-byte on at least one seed |
| `a4/standalone/fuzzer.py` | Add Tier-1 signal computation BEFORE the `compute_bandit_success` call site. Compute `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag` per pull from already-available per-pull state. Pass via the new `compute_bandit_success` kwargs. | Per-pull unit test: signal values match the D1.C extractor output on a replay of V5 s1234 |
| `a4/standalone/cli.py` (or `campaign_params.py` equivalent) | Add new `L1_SIGNALS` campaign param: list of signal names to OR-in. Default `[]` (back-compat = V5 R2 behavior). D1.E V5 + decay sub-batches use `["mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag"]`. | CLI test: parse + propagate to fuzzer; persists into `campaign_params.extra_json` |
| `a4/standalone/bandit_ts.py:98` (`ExponentialDecayFloor.K`) | NO code change. K is a constructor argument; D1.E sets it at campaign creation time. | Existing tests cover K parameterization |
| `a4/standalone/bandit_ts.py:103-115` (`EpochStaircaseFloor` constructor) | NO code change. Stages are constructor argument; D1.E sets `[(0, 0.55), (1000, 0.35)]`. | Existing tests cover stages parameterization |
| `a4/standalone/coverage_db.py` (`mutation_rewards` write path) | Add new `bandit_success_l1` column (integer; `compute_bandit_success` output with signals OR'd in). KEEP existing `bandit_success` column (= original `discovery_binary_reward`) for backward-compat + paired-archive comparison. | Migration test: schema upgrade leaves R2 + D1.A archives readable as `bandit_success_l1 = NULL` |

**No production file outside the above 5 is touched by D1.E.** Specifically, `compressed_global_extractor.py` is NOT touched — the NFP-10 byte_addr fix already landed in D1.B Batch 1.6 (commit `71dae77`).

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
  "FLOOR_SCHEDULE": "EpochStaircaseFloor",
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
| `d1e_metrics_table.csv` | analysis script | One row per DB × {variant, seed, local_context_final, cgc_final, time_to_46, bandit_success_l1_mean, bandit_success_orig_mean (for ablation), d_loc_p95, singleton_failure_rate, ...} |
| `d1e_paired_tests.csv` | analysis script | Paired t-tests: D1.E V5-static vs D1.E decayexp; D1.E V5-static vs D1.E decayepoch; D1.E V5-static vs D1.A V5-static archive (ablation: pure rewire effect) |
| `d1e_floor_dynamics.csv` | analysis script | Floor mode share per 100-mut bin per variant |
| `d1e_tier1_validation.csv` | analysis script | Q-E-TIER1-VALIDATION: post-rewire signal fire rates + correlations on fresh DBs |
| `d1e_recommendation.md` | manual | TL;DR + decision matrix: keep/drop decay variants for V5-paired; K/epoch final values; deferral notes |
| `D1E_SUBSECTION.md` | manual | Pro-facing subsection for Stage 4 D1 report fold-in |
| `IV_POS_8_D1E_NOTEBOOK.ipynb` + `.html` | analysis script | Executable evidence bundle |

---

## 2. Implementation batches

### 2.0 Batch 0 — Pre-work (analysis + sync, no production code change)

**Scope:** SQL pass on legacy `coverage` table + D2.B sync check.

**Tasks:**

1. **Legacy `coverage` table saturation SQL pass.** On the 10 R2 V5 DBs + 10 D1.A decay DBs:
   ```sql
   SELECT mutation_id, COUNT(*) OVER (ORDER BY mutation_id) AS cum_coverage_rows
   FROM coverage
   ORDER BY mutation_id;
   ```
   Compute per-DB saturation point: smallest `mutation_id` such that 95% of final `cum_coverage_rows` is reached. Aggregate mean across V5 paired seeds → `legacy_coverage_saturation_mut_d1e.csv`.
2. **Pin Q-E-K-TARGET final value** using the saturation point. Target: K such that `0.55 * exp(-d/K) = 0.48` at `d = 0.80 × (saturation_d)`. Algebra: `K = 0.80 × saturation_d / ln(0.55/0.48) ≈ saturation_d / 0.171`.
3. **Pin Q-E-EPOCH-BOUNDARIES final value** by inspecting the cum-coverage curve — first boundary should fire when 30-50% of legacy coverage has been discovered.
4. **D2.B Batch 1.5e sync check.** `git log --oneline cloud2 | head -20` — confirm `PRE_EXEC_REG_MOD` retrofix commit is present. If absent, Batch 3 blocks; Batch 1+2 proceed in parallel.

**Deliverables:**
- `legacy_coverage_saturation_mut_d1e.csv` (per-DB + aggregate saturation point)
- D1.E spec v0.2 amendment locking Q-E-K-TARGET + Q-E-EPOCH-BOUNDARIES
- Sync status note in `a4/docs/cloud2/composer/D1E_BATCH0_REPORT.md`

**Exit criteria:**
- K + epoch boundaries locked in spec
- D2.B sync status known
- Q-E-TIER1-VALIDATION re-audit code path identified (existing `bug_proximity.extract_tier1_signals_per_db` reused)

### 2.1 Batch 1 — L1 reward rewire (production code change)

**Scope:** `reward_v2.py` + `fuzzer.py` + `coverage_db.py` + `cli.py`.

**Tasks:**

1. **Extend `compute_bandit_success` signature** (`reward_v2.py:60-62`):
   ```python
   def compute_bandit_success(
       l_new: int,
       g_new: int,
       s_new: int,
       l1_signals: Optional[Dict[str, int]] = None,
   ) -> int:
       """Pro §8 Bernoulli success indicator for Thompson sampling.
       
       L1 OR-channel extension (D1.E): when `l1_signals` is provided, OR-in
       the per-signal flag values. See `IV_POS_8_D1_E_SPEC.md` §0.1.1 for
       layer architecture; D1.C `d1e_handoff_L1_signals.md` for signal definitions.
       
       Backward-compat: `l1_signals=None` reproduces original V5/D1.A behavior.
       """
       base = 1 if (l_new + g_new + s_new) > 0 else 0
       if not l1_signals:
           return base
       return 1 if (base + sum(int(v) for v in l1_signals.values())) > 0 else 0
   ```

2. **Add Tier-1 signal extractors to `fuzzer.py`** (compute per-pull, BEFORE the `compute_bandit_success` call site):
   - `mutation_substrategy_uniqueness`: Maintain a per-campaign `seen_composite_keys` set. On each pull, compute `(kind, composite_key)` using D1.C's `KIND_TO_SUBSTRATEGY_FIELDS` empirical mapping (copied from `bug_proximity.py`). If `kind in L1_SIGNAL_KIND_EXCLUSIONS["mutation_substrategy_uniqueness"]` (default: `["INSTR_TYPE_MOD"]`), signal = 0. Else: signal = 1 if `(kind, composite_key) not in seen_composite_keys` else 0; then add to set.
   - `d_loc_le_2_flag`: After `coverage_state` produces the per-pull `d_loc`, signal = 1 if `d_loc <= 2` else 0. Uses production-stored d_loc (Q-E-D_LOC-SOURCE).
   - `singleton_failure_flag`: signal = 1 if `len(exec_result.failures) == 1` else 0. Row-form (Q-E-SINGLETON-DEFINITION).

3. **Persist `bandit_success_l1` to `mutation_rewards`** (`coverage_db.py` schema migration):
   - Add column `bandit_success_l1 INTEGER`. Existing `bandit_success` column unchanged.
   - Write path: store the new L1-enriched value in `bandit_success_l1`; store the original (pre-OR) value in `bandit_success` for ablation.
   - Migration: ALTER TABLE; default NULL on existing archives.

4. **CLI plumbing** (`cli.py` or `campaign_params.py`):
   - Parse `L1_SIGNALS` and `L1_SIGNAL_KIND_EXCLUSIONS` from CLI / config.
   - Default: `[]` (back-compat).
   - Validate each signal name against an allowed list `{"mutation_substrategy_uniqueness", "d_loc_le_2_flag", "singleton_failure_flag", "f_new_flag", "recent_marginal_discovery_rate"}` (allow future expansion without code change).
   - Persist into `campaign_params.extra_json`.

5. **Opposite-saturation pre-flight test** (per Q-E-L1-COMPOSITION):
   - Unit test that runs a 1000-pull V5-static fixture with all 3 L1 signals active.
   - Assert `mean(bandit_success_l1 for mut in [800, 1000)) <= 0.75` (heuristic ceiling — fail-fast if d_loc_le_2 fully saturates).

**Tests required:**

- Golden trace test: V5 s1234 1000-pull replay with `L1_SIGNALS=[]` produces byte-identical `bandit_success` and trajectory to R2 archive.
- Per-signal unit tests: each of the 3 signals returns the same value on a 1000-pull replay as `bug_proximity.extract_tier1_signals_per_db` would on the resulting DB.
- INSTR_TYPE_MOD exclusion test: a 100-pull fixture where the only mutations are INSTR_TYPE_MOD — `mutation_substrategy_uniqueness` always 0.
- Backward-compat test: existing `compute_bandit_success(l, g, s)` call (no kwarg) returns identical value.
- Opposite-saturation pre-flight (above).
- Schema migration test: open D1.A archive DB → reads cleanly with `bandit_success_l1` as NULL.

**Deliverables:**
- 5 file modifications
- Test suite passing (existing + ~6 new tests; aim for ≥ 520 standalone passed)
- `a4/docs/cloud2/composer/D1E_BATCH1_REPORT.md`

**Exit criteria:**
- All tests pass
- `git diff cloud2 -- a4/standalone/` shows only the 5 expected file modifications
- Composer reports any unexpected golden-trace divergence

### 2.2 Batch 2 — K/epoch retune + dispatch infrastructure

**Scope:** Wire Batch 0's locked K + epoch boundaries into the D1.E POS dispatch config. No production code change.

**Tasks:**

1. Add D1.E dispatch config to `a4/runs/iv_pos_8/d1e/dispatch/` (mirror `d1a/dispatch/` structure):
   - `dispatch_d1e_v5_static.yaml` — 5 seeds, V5_semantic_v2 catalog, `ConstantFloor(0.55)`, L1_SIGNALS=top-3.
   - `dispatch_d1e_decayexp.yaml` — 5 seeds, V5_semantic_v2 catalog, `ExponentialDecayFloor(K=<Batch 0 value>)`, L1_SIGNALS=top-3.
   - `dispatch_d1e_decayepoch.yaml` — 5 seeds, V5_semantic_v2 catalog, `EpochStaircaseFloor(stages=[(0, 0.55), (1000, 0.35)])`, L1_SIGNALS=top-3.
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

1. Build `d1e_metrics_table.csv` (30 rows: 15 D1.E + 5 D1.A V5-static archive + 10 R2 V5/V1 for context).
2. Build `d1e_paired_tests.csv` with three paired-test comparisons:
   - D1.E V5-static vs D1.E decayexp (effect of decay under enriched reward)
   - D1.E V5-static vs D1.E decayepoch (same, epoch variant)
   - D1.E V5-static vs D1.A V5-static archive (effect of pure L1 rewire isolated from decay — note: confounded with PRE_EXEC_REG_MOD retrofix per Q-E-RETROFIX-ABLATION)
3. Build `d1e_floor_dynamics.csv` per D1.A's pattern (floor mode share per 100-mut bin per variant).
4. Q-E-TIER1-VALIDATION: re-run `bug_proximity.extract_tier1_signals_per_db` on the 15 fresh D1.E DBs → `d1e_tier1_validation.csv`. Flag any signal whose post-local fire rate drops below 1% or correlation exceeds 0.6 vs `bandit_success_l1`.
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
| **R-E-1: Opposite saturation** — `bandit_success_l1` goes always-on because `d_loc_le_2_flag` at 60.7% post-local fire rate dominates the OR | Medium | High (reward signal becomes uninformative — same failure mode as D1.A in opposite direction) | Q-E-L1-COMPOSITION pre-flight test catches mean > 0.75 in mut [800, 1000); if triggered, Ivan + Opus decide to (a) drop `d_loc_le_2_flag`, (b) switch to non-naive composition (weighted OR), or (c) raise the d_loc threshold (e.g., `d_loc <= 1`) |
| **R-E-2: PRE_EXEC_REG_MOD retrofix delays D1.E** | Medium | Medium (Batch 3 dispatch blocked) | Batch 0 sync check + Batch 1+2 in parallel; if D2.B is materially delayed (>1 week), Ivan + D2 chat coordinate to either fast-track Batch 1.5e or temporarily revert it locally for D1.E + re-apply post-D1.E |
| **R-E-3: K target wrong** — Batch 0 SQL pass under-estimates legacy coverage saturation, K transition lands too early | Low | Medium (decayexp behaves like ConstantFloor again, repeat D1.A Finding A) | K is derived from 80% × saturation_d, not 50% — buffer against under-estimation. Sanity check in Batch 2 sanity smoke: V5-static seed's `_floor_target` should cross the 0.48 boundary at mut closer to mut 4000-5000, not earlier |
| **R-E-4: Q-E-TIER1-VALIDATION reveals signal drift** — post-rewire DBs show signals correlating differently than frozen D1.C corpus | Medium | Medium (D1.C's empirical orthogonality claim invalidated for D1.E run; subsection must disclose) | Batch 4 re-audit is the explicit catch. If max |ρ| > 0.6 on fresh DBs for any L1 signal, disclose in subsection + flag for D2 / Hybrid V7 re-evaluation |
| **R-E-5: Decay variants still don't separate from V5-static on `local_context_final`** even under enriched reward | Medium | High but expected | This IS a valid D1.E outcome — would mean decay is genuinely orthogonal to the discovery-rate bottleneck (i.e., the floor schedule is not the lever). Subsection frames as "decay+L1 still insufficient on V5; defer to Hybrid V7 + decay re-test." |
| **R-E-6: POS daemon failure** during Batch 3 (D1.A precedent) | Medium | High (loses N hours of compute) | SSH-bypass collection plan ready (POS_PLAYBOOK §12.52); allocate 2 reservation blocks instead of 1; first reservation = 8 jobs, second = 7 jobs + retry buffer |
| **R-E-7: Schema migration regression** — adding `bandit_success_l1` column breaks an existing R2 archive read path elsewhere | Low | Medium | Migration test (Batch 1) explicitly tests R2 + D1.A archive read. Composer must `grep -r mutation_rewards a4/standalone/` to find all consumers + verify NULL handling |
| **R-E-8: Confound between L1 rewire and PRE_EXEC_REG_MOD retrofix** in V5-static vs V5-static archive comparison | Certain (it's the cost of Option B per Q-E-RETROFIX-ABLATION) | Low to medium | Explicit subsection disclosure; Open Decision: do we run Option C ablation (~10 jobs, +1 reservation) in a D1.E follow-up if v1 results are ambiguous? |

---

## 4. Composer kickoff checklist

Before kicking off Batch 0, Composer must:

1. **Read all 6 load-bearing input files** listed at the top of this spec.
2. **Confirm Ivan greenlight on Q-E-* defaults** (or Ivan's overrides if any).
3. **Run `git log --oneline cloud2 | head -20`** and confirm:
   - `3a8487c "Check d1.c"` is present (D1.C committed)
   - `71dae77 Check d1.b` is present (D1.B committed, contains NFP-10 byte_addr fix)
   - `7b66fb9 D2.A Batch 2: mutations.outcome column...` is present (D2.A back-compat preserved)
4. **Run `pytest a4/standalone/tests/` baseline** and record passed count for regression detection.
5. **Open Q-E-K-TARGET / Q-E-EPOCH-BOUNDARIES as TODOs** — these lock in spec v0.2 after Batch 0 SQL pass.
6. **Confirm POS reservation availability** (8-node block, ~6h) with Ivan before Batch 2 sanity smoke.

After Batch 0 SQL pass:
7. Compose spec v0.2 amendment with final K + epoch values; Ivan + Opus review before Batch 1 kickoff.

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
