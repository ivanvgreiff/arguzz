# D1.C — Bug-Proximity Metric Stack

> **⚠ INTERIM RESULTS — pending Ivan + Opus review before Pro-facing D1 deliverable fold-in.**
>
> This subsection reports the D1.C bug-proximity work performed on the existing R2 V5 (b1/cTS V5_semantic_v2) corpus and the D1.A V5-decay variants — i.e., the **single-catalog V5 cTS scheduler family**. We measured Pro Report 3 §5/§7/§8 bug-proximity metrics + 5 candidate per-mutation reward-channel signals on **frozen DBs**. We did NOT run any of these metrics under:
>
> 1. **Hybrid-cTS** (Pro §15 Priority 1) — V5 catalog **plus** selected V6-only kinds (INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, etc.). The expanded arm set would change `mutation_substrategy_uniqueness` fire rates, `d_loc`/`d_glob` distributions, and likely the singleton-failure rate — all measured here only on V5's 8 kinds.
> 2. **V7** (post-D1.E mutation catalog expansion: TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, CYCLE_PC_MOD, etc., per Pro §15 Priority 3) — different reachability surface; new mutation kinds would each need a substrategy field audit; the `INSTR_TYPE_MOD` all-NULL degeneracy we found here would not necessarily generalize.
> 3. **Arguzz-with-thompson** (Pro §14 ablation) — different scheduler entirely. The post-local saturation regime (`discovery_binary_reward` fire rate ~3% post-local on V5) is what makes some of our signals decorrelate or saturate the way they do; an Arguzz-driven cTS would have a different post-local regime and different gate outcomes.
>
> **Pro-facing implication:** D1.C's shortlist of L1 OR-channel candidates and the per-campaign singleton-failure discriminator are V5-corpus conclusions. They are the best we can extract from the data Pro asked us to analyze, but they are not pre-validated for Pro's Priority-1 (Hybrid V7) architecture. If Pro plans to build Hybrid-cTS, a Tier-1 re-audit on the first Hybrid-cTS campaign is recommended before wiring L1.

---

## 0. TL;DR

D1.C tested **all 8 of Pro Report 3 §5/§8 bug-proximity metrics** (per-campaign Tier-2) and **5 candidate per-mutation reward signals** (Tier-1) on 30 V5-family DBs (10 R2 V1 + 10 R2 V5 + 10 D1.A decay).

**Three headline results for Pro:**

1. **Only one Pro §5 metric significantly discriminates V5-decay from V5-static:** `pro_s5_singleton_failure_rate`. Decay variants find ~22% fewer singleton failures than V5-static (p = 2.6 × 10⁻⁶ for decayexp, 9.7 × 10⁻⁵ for decayepoch). **Open architectural question for Pro:** does this mean decay schedules push the bandit toward richer multi-loc failures (good?) or systematically miss surgical singleton-failure mutations (bad?). D1.C cannot answer; D1.E forward-run can.

2. **Pro's "free L1 OR-channel" candidate `f_new > 0` is empirically dead on V5.** Fire rate is ~0.17% full-campaign and ~0% post-local. Wiring it into bandit_success would add essentially zero new signal on this corpus. NFP-9's "free" framing is correct on engineering cost but practically vacuous on this catalog. **May still be useful on Hybrid V7** where new V6-only kinds could re-activate the family novelty channel.

3. **Three new per-mutation signals pass D1.E's L1 OR-channel gates** (orthogonality |ρ| < 0.4 + non-saturation > 5% post-local fire rate): `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`. These will be evaluated in D1.E forward runs. A 4th alternate, `recent_marginal_discovery_rate` (Pro §7 Stage 2's "recent marginal discovery" signal), also passes — surprisingly, because spec expected it to fail orthogonality.

**Critical scope disclaimer (repeat):** All results scoped to **V5 catalog + cTS scheduler**. Hybrid V7 / V7-only / Arguzz-with-thompson NOT tested.

**D1.C does NOT claim L1 enrichment will help the bandit** — D1.E forward-run is the causal test.

---

## 1. What Pro asked for in Report 3, and how each metric performed

Pro Report 3 §5 and §8 catalogued bug-proximity metrics. §7 Stage 2 listed candidate per-pull reward signals for the adaptive bandit. D1.C measured **all of §5/§8** and the directly-implementable subset of **§7 Stage 2**.

### 1.1 Pro §5 bug-proximity metrics (per-campaign, all 30 DBs)

| Pro §5 metric | D1.C name | What we found |
|---|---|---|
| Verifier-accepted invalid count | `cat_a_pro_s5_verifier_accepted_invalid_count` | **0 on all 30 DBs.** SQL is correct (matches D1.A spec :539). Corpus has no `verifier_accepted=1 AND num_failures>0` pulls. Useful as a V6 regression detector when Hybrid-cTS runs; currently informative-by-absence. |
| Co-failure graph degree distribution | `cat_a_pro_s5_co_failure_graph_degree_p95` | V1 27.5, V5 31.4, decayexp 31.0, decayepoch 30.8 (campaign means). **No significant decay-vs-V5 discrimination** (p ≈ 0.23-0.62). Co-failure structure is stable across the V5 family on this corpus. |
| Singleton-failure rate | `cat_a_pro_s5_singleton_failure_rate` | **Discriminates decay-vs-V5 strongly** (p = 2.6e-06 / 9.7e-05). V5-static 16.7%, decayexp 12.9%, decayepoch 13.4%. **The headline Tier-2 finding.** |
| `d_loc` distribution stats | `cat_a_pro_s5_d_loc_p95` | V1 = 5, V5 = 6, decayexp = 7, decayepoch = 6 (p95, integer). decayexp consistently +1 above static (Wilcoxon p = 0.0625 at n=5; smallest possible p for 5 paired). Pattern is real but weak; D1.E may want non-parametric tests on a larger paired corpus. |
| Proof-generated zero-residue rejected rate | `cat_b_pro_s5_proof_generated_zero_residue_rejected_rate` | **Cat-B (D1.A DBs only — column NULL on R2 V1/V5).** Mean **12.4%** across 10 D1.A DBs (range 11.6–13.8%). No R2 baseline to compare. Decayexp vs decayepoch paired p ≈ 0.10 (n.s. at n=5). |

### 1.2 Pro §8 analytics (per-campaign)

| Pro §8 metric | D1.C name | What we found |
|---|---|---|
| Unique locs with `d_loc ≤ 2` | `cat_a_pro_s8_unique_locs_with_d_loc_le_2` | V1 25.3, V5 28.2, decayexp 29.8, decayepoch 29.6 (campaign means). Decay variants explore slightly more "near-minimal" loc footprint, but **not significant** (p ≈ 0.06 decayexp vs V5). |
| Unique locs with `d_glob ≤ 1` | `cat_a_pro_s8_unique_locs_with_d_glob_le_1` | V1 30.0, V5 33.4, decayexp 33.6, decayepoch 33.2. No significant decay discrimination. Included for §8 catalog completeness. |
| `f_new` channel | `f_new_flag` (Tier-1) | **Empirically dead post-local on V5** (~0% fire). Pro's "free L1 OR-channel" intuition is true on engineering cost but doesn't add discrimination on this catalog. See §1.4 for full discussion. |

### 1.3 Pro §7 Stage 2 reward signals (per-pull)

Pro §7 Stage 2 listed four candidate signals for enriching the adaptive bandit's reward. D1.C tested the directly-computable subset on frozen DBs.

| Pro §7 Stage 2 signal | D1.C tested as | Status |
|---|---|---|
| **Recent marginal discovery** | `recent_marginal_discovery_rate` (Tier-1, continuous, 100-pull rolling mean of `discovery_binary_reward`) | **Passes orthogonality + non-saturation gates** post-local. Surprise — spec predicted ρ ≈ 0.4-0.7 by construction; actual max |ρ| = 0.114 because post-local sparse-discovery decorrelates the rolling mean from the instant bit. Available as 4th L1 alternate or NFP-9 scalar-bandit input. |
| **Low-cofailure discoveries** | NOT a per-pull Tier-1 signal — co-failure graph is per-campaign only | **Not implemented as Tier-1.** Per-pull "low-cofailure" flag would require running-graph update per pull (expensive). Available at Tier-2 as `cat_a_pro_s5_co_failure_graph_degree_p95`. **Open D1.E design question** if Pro wants this as an L1 channel. |
| **Repairability** | NOT in D1.C scope | **Deferred to D3** (Pro §15 Priority 2 bug-isolation layer). Requires repair templates / minimization machinery not yet built. |
| **Underexplored semantic zones** | Partially via `mutation_substrategy_uniqueness` | First-occurrence of `(kind, substrategy_composite_key)` proxies "exploring a new sub-arm within a kind." Not identical to Pro's "semantic zones" framing (which is zone-coverage-based), but captures the spirit. **Passes gates; rank 1 in shortlist.** Pro may want a more direct zone-coverage signal in a future iteration. |

**Net coverage of Pro §7 Stage 2:** 2 of 4 directly implemented (recent marginal discovery + a sub-arm proxy for underexplored zones). 1 deferred to D3 (repairability). 1 (low-cofailure) only at campaign level. **D1.E spec author should decide** whether per-pull low-cofailure is worth the implementation cost given that Tier-2 co-failure already shows no decay discrimination on V5.

---

## 2. New D1.C signals beyond Pro's catalog

Two Tier-1 signals were added beyond Pro's direct list, with the rationale that they are cheap (no replay) and capture per-pull "near-bug" intuition Pro §8 hinted at:

| New signal | Rationale | Result |
|---|---|---|
| `singleton_failure_flag` | Per-pull form of Pro §5's singleton-failure rate | **Passes gates; rank 3 in shortlist.** Per-campaign form (Tier-2) is the headline decay discriminator. |
| `d_loc_le_2_flag` | Per-pull threshold form of Pro §8's `d_loc` distribution | **Passes gates; rank 2 in shortlist.** Highest post-local fire (60.7%) — opposite-saturation risk if naive-OR'd. |

The Tier-2 metric `cat_b_pro_b_wall_clock_per_normalized_discovery` (mean elapsed_ms / local_context_final) was also added beyond Pro's catalog as an efficiency metric — only computable on D1.A DBs (R2 DBs lack `elapsed_ms`). Mean ~65-66 ms / discovery unit; not significant between decay variants.

---

## 3. Dataset

| Sub-corpus | Variant label | Seeds | N | Source |
|---|---|---|---:|---|
| R2 V1 | V1 | 1234–1243 | 10 | R2 `iv_pos_7/dbs/` (b1/cTS V1) |
| R2 V5 | V5 | 1234–1243 | 10 | R2 `iv_pos_7/dbs/` (b1/cTS V5_semantic_v2) |
| D1.A decay | V5_decayexp | 1234–1238 | 5 | `iv_pos_8/d1a/dbs/` (V5_semantic_v2 + ExponentialDecayFloor K=50) |
| D1.A decay | V5_decayepoch | 1234–1238 | 5 | `iv_pos_8/d1a/dbs/` (V5_semantic_v2 + EpochStaircaseFloor) |

**Paired triplets:** seeds 1234–1238 (n=5) carry V5, V5_decayexp, V5_decayepoch — used for decay paired t-tests.

**6000 mutations per DB.** All schema-complete (zero missing rows in `mutation_rewards`, `reward_counterfactuals`, `mutation_substrategy`).

**Cat-A vs Cat-B:** Tier-2 metrics requiring D1.A's new `mutations` columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`) are Cat-B and only populate on the 10 D1.A DBs. R2 V1/V5 rows have NaN.

---

## 4. Method

### 4.1 Architecture (two tiers, two consumers)

- **Tier-1** (5 signals): per-mutation, evaluated as L1 OR-channel candidates for the D1.E reward rewire.
- **Tier-2** (8 metrics): per-campaign, scalar per DB, for D2.G's V5-vs-V6 comparison table + Pro §5/§8 disclosure.

### 4.2 Selection gates (Tier-1)

| Gate | Criterion | Rationale |
|---|---|---|
| Non-saturation | `fire_rate(post_local_window) > 5%` per signal | Signal must keep firing after `bandit_success` saturates (mut ~3200 local saturation; signals dying alongside `discovery_binary_reward` add no post-local information) |
| Orthogonality | `max |Pearson ρ| < 0.4` vs `{discovery_binary_reward, f_new_flag}` across all 30 DBs | Signal must not duplicate what bandit already learns; correlation gate is heuristic but stricter than spec's V5-paired-only framing |

The two existing channels we compare against were read directly from `reward_counterfactuals` via spec §1.4 "Option A" (no per-pull replay of `l_new/g_new/s_new`). Production tests support Option A's bit-identity with replay; full Option C replay was not run.

### 4.3 Post-local analysis window

`[3000, 6000)` — anchored to D1.B's mean `time_to_46` ≈ 3221 on V5 paired seeds. This is the regime where `discovery_binary_reward` has gone sparse (~3% fire rate on V5 s1234) and adaptive Thompson sampling has lost its gradient.

### 4.4 Channel reconstruction note (important caveat for Pro)

Per-pull `l_new`, `g_new`, `s_new`, `f_new` integers are **not stored** in the SQLite DBs. D1.C uses Option A — derives the bandit's success bit from `reward_counterfactuals.discovery_binary_reward` (already an OR over the three channels) and derives `f_new_flag` from `reward_counterfactuals.fnew_only_reward` (= 0.30 × sat(f_new, 1.0), so `> 0` is an exact proxy for `f_new ≥ 1`).

**Why this matters for Pro:** We did not reconstruct the per-channel granularity. If Pro wants to see whether L1 signals correlate with `l_new` specifically vs `g_new` specifically, that requires Option C full replay — not yet run, accepted risk for D1.C scope. Would be needed if Pro's design intuition pushes us toward per-channel reward weighting in D1.E.

---

## 5. Tier-1 signals — full catalog with definitions and results

Five per-mutation signals, one value per pull (6000 per DB).

### 5.1 `f_new_flag` (Pro §8 f_new channel)

**Construction:** `1 if reward_counterfactuals.fnew_only_reward > 0 else 0`. Exact proxy for `f_new ≥ 1` because `fnew_only_reward = 0.30 × sat(f_new, 1.0)`.

**Pro's hypothesis (NFP-9):** Family novelty (`f_new`) is computed but NOT included in the bandit's current Bernoulli success bit. OR-ing it in would be a "free" L1 channel addition.

**30-DB results:**

| Stat | Value |
|---|---:|
| Full-campaign fire rate (mean) | 0.17% |
| Post-local fire rate (mean) | **~0%** (max 0.03% on a single DB; 0/30 DBs pass 5% gate) |
| Max \|ρ\| vs `discovery_binary_reward` | 0.123 (V1 s1243 single-event artifact) |
| Max \|ρ\| on V5 sub-corpus | 0.0 |

**Bucket B (DEFERRED — non-saturation failure).** On V5 catalog, family novelty events are too rare post-local to extend the bandit signal. **Likely re-activates on Hybrid V7** if V6-only kinds discover new families.

### 5.2 `recent_marginal_discovery_rate` (Pro §7 Stage 2 "recent marginal discovery")

**Construction:** 100-pull rolling mean of `discovery_binary_reward`. Continuous in [0, 1]. Discretized at threshold 0.05 for binary gate evaluation.

**Pro's hypothesis (§7 Stage 2):** Even when the instantaneous discovery bit is 0, a high trailing discovery rate may indicate an active discovery phase. Useful as continuous magnitude input for adaptive TS.

**30-DB results:**

| Stat | Value |
|---|---:|
| Post-local fire rate (discretized @ 0.05, mean) | 15.8% |
| Max \|ρ\| discretized vs `discovery_binary_reward` | 0.114 (D1.A decayexp s1238) |
| Max \|ρ\| continuous Pearson (sensitivity) | 0.134 (D1.A decayexp s1236) |
| Passes both gates | 30/30 DBs |

**Bucket A — 4th alternate.** **Surprise finding:** spec docstring predicted ρ ≈ 0.4-0.7 "by construction" (rolling mean of a binary signal should track the bit closely). Reality post-local is decorrelated because once `discovery_binary_reward` becomes sparse (~3% on V5), the rolling mean also stays low and moves slowly — the two stop tracking each other.

**Implication for Pro:** A 4th L1 candidate is available that spec did not predict. D1.E may prefer the three binary OR candidates first; this is the scalar-bandit fallback per NFP-9.

### 5.3 `singleton_failure_flag` (per-pull form of Pro §5 singleton-failure rate)

**Construction:** `1 if COUNT(*) FROM failures WHERE mutation_id = ? = 1 else 0`. Per pull.

**Note on spec wording:** Spec prose sometimes says "exactly one constraint_loc broke." Implementation uses **one failure row** (not one distinct loc). On V5 s1234 these align on 996 pulls; 5 edge cases have 2 rows at the same loc with different `(major, minor)` codes. Tier-1 and Tier-2 forms are internally consistent.

**Hypothesis:** Singleton failures represent surgical, isolated bug witnesses — plausibly closer to "one bug step away" than multi-loc cascades.

**30-DB results:**

| Stat | Value |
|---|---:|
| Post-local fire rate (mean) | 16.5% |
| Max \|ρ\| vs `discovery_binary_reward` | 0.082 (V1 s1241) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | 99.6% |
| Per-variant post-local fire (V1 / V5 / decayexp / decayepoch) | 20.3% / 16.8% / 12.5% / 12.2% |

**Bucket A — rank 3.** Strong link to the Batch 2 finding: the per-campaign form (`pro_s5_singleton_failure_rate`) is the **only Tier-2 metric** with significant decay discrimination. The per-pull form is what D1.E would wire as an L1 OR-channel.

### 5.4 `mutation_substrategy_uniqueness` (proxy for Pro §7 "underexplored semantic zones")

**Construction:** Composite key `(kind, tuple of non-NULL kind-specific substrategy columns)` from `mutation_substrategy` table. Fires `1` on first occurrence of each composite key in campaign order; `0` otherwise.

**Empirically-derived KIND_TO_SUBSTRATEGY_FIELDS** (from 30-DB audit, since `mutation_substrategy` columns are kind-specific with all-NULL gaps):

| Kind | Composite fields |
|---|---|
| `INSTR_WORD_MOD_SUR`, `INSTR_WORD_MOD_FULL` | opcode, rd, rs1, rs2, funct3, funct7, imm |
| `MEM_VAL_MOD` | byte_lane, bit_mask, value_class |
| `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `PRE_EXEC_REG_MOD`, `STORE_OUT_MOD` | value_class |
| `INSTR_TYPE_MOD` | **empty** (all substrategy columns NULL on all 30 DBs) |

**INSTR_TYPE_MOD caveat for Pro:** ~25% of corpus pulls are `INSTR_TYPE_MOD` with degenerate composite key `(INSTR_TYPE_MOD, ())`. Only the FIRST INSTR_TYPE_MOD pull per DB ever fires `uniqueness=1` for this kind (30 fires corpus-wide). All post-local uniqueness fires come from non-INSTR_TYPE_MOD kinds. Sample 30-DB results below are unaffected by this on V5, but **Pro should know**: if a future catalog (Hybrid V7) populates INSTR_TYPE_MOD substrategy fields, this signal's fire rate would increase. D1.E should consider whether to special-case INSTR_TYPE_MOD or treat each kind as a separate arm channel.

**30-DB results:**

| Stat | Value |
|---|---:|
| Post-local fire rate (mean) | 33.7% |
| Max \|ρ\| vs `discovery_binary_reward` | 0.069 (V5 s1243) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | 98.1% |
| Per-variant post-local fire (V1 / V5 / decayexp / decayepoch) | 33.5% / 39.5% / 30.0% / 29.5% |

**Bucket A — rank 1.** Best orthogonality of all candidates; solid post-local fire; very high disjoint-fire.

### 5.5 `d_loc_le_2_flag` (per-pull form of Pro §8 d_loc analytics)

**Construction:** `1 if mutation_rewards.d_loc <= 2 else 0` (production-stored `d_loc`).

**d_loc definition note for Pro:** Production `coverage_state.py` computes `d_loc` as `|{distinct (constraint_loc, major, minor) tuples}|` — **not** `COUNT(*) FROM failures`. On crash pulls (touch bitmap missing), production hardcodes `d_loc = 0` even when `failures` has rows. This affects 1.12% of pulls corpus-wide (verified on V5 s1234: 67/6000 pulls, all `mode='crash'`). Sensitivity check: recomputing the flag from raw failure-context counts shifts the post-local fire rate by **< 0.2 percentage points** and does not change the shortlist ordering.

**Hypothesis:** Low `d_loc` means few distinct local failure contexts broke — "near-minimal" fault multiplicity per Pro §8. Pulls with `d_loc ≤ 2` may be bug-proximate even when no new coverage key was discovered.

**30-DB results:**

| Stat | Value |
|---|---:|
| Post-local fire rate (mean) | **60.7%** (highest of all candidates) |
| Max \|ρ\| vs `discovery_binary_reward` | 0.239 (V1 s1241) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | 99.3% |
| Per-variant post-local fire (V1 / V5 / decayexp / decayepoch) | 76.3% / 60.8% / 46.5% / 47.5% |

**Bucket A — rank 2** with **opposite-saturation caveat:** at 60%+ post-local fire, naive OR into `bandit_success` risks pushing the bit always-on — the OPPOSITE failure mode from the saturation problem D1.C is trying to solve. D1.E must cap L1 OR channels at ≤ 3 per revisit plan §3.3 and evaluate non-naive compositions (per-channel reward, weighted, scalar bandit).

---

## 6. Tier-2 metrics — full catalog with definitions and results

Eight per-campaign scalars per DB. Schema locked in `d1c_tier2_schema.md` for D2.G consumption.

### 6.1 `cat_a_pro_s5_verifier_accepted_invalid_count`

**SQL** (aligned to D1.A spec :539): `SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0`

**Result:** 0 on all 30 DBs. Verifier never accepts mutations with failures on this corpus. Retained for D2.G schema completeness and as a V6/Hybrid-cTS regression detector.

### 6.2 `cat_a_pro_s5_co_failure_graph_degree_p95`

**Construction:** Undirected graph: nodes = distinct `constraint_loc`; edge `(a, b)` iff both appear in `failures` for the same `mutation_id`. Return p95 of node degree.

**Results:** V1 27.5, V5 31.4, decayexp 31.0, decayepoch 30.8 (campaign means). **No significant decay discrimination** (paired t p ≈ 0.23-0.62).

**V5 s1234 graph sanity:** 46 nodes, 273 edges, density 0.264 — within expected scale.

### 6.3 `cat_a_pro_s5_singleton_failure_rate` — **the headline Tier-2 finding**

**Construction:** Fraction of mutations where exactly 1 failure row exists. Matches the Tier-1 `singleton_failure_flag` full-campaign mean exactly on all 30 DBs.

**Decay discrimination (5 paired seeds):**

| Comparison | Mean A | Mean B | t-stat | p (paired) |
|---|---:|---:|---:|---:|
| decayexp vs V5-static | 12.93% | 16.69% | -38.93 | **2.6 × 10⁻⁶** |
| decayepoch vs V5-static | 13.44% | 16.69% | -15.65 | **9.7 × 10⁻⁵** |
| decayexp vs decayepoch | 12.93% | 13.44% | -2.62 | 0.059 (n.s. at α=0.05) |

**Interpretation (open question for Pro):** Decay variants find ~22% fewer singleton failures than V5-static. Two plausible architectural readings, both consistent with the data:

- **(a)** Decay schedules push the bandit toward exploring mutations that break **multiple constraint_locs simultaneously** (higher per-pull d_loc). The Tier-2 `d_loc_p95` data weakly supports this (decayexp p95=7 vs V5 p95=6, Wilcoxon p=0.0625). If this is the right reading, decay is finding **more complex failure modes** that V5-static misses.
- **(b)** Decay schedules MISS the singleton-failure mutations entirely (waste exploration on multi-loc mutations that V5-static would have found anyway via floor-mode coverage). If this is the right reading, decay is **less efficient** at surfacing surgical bug witnesses.

**D1.C cannot distinguish (a) from (b)** — both predict the same decay-vs-static singleton rate gap. **D1.E forward-run with the singleton signal wired into L1 is the only way to tell** — if decay's gradient improves with the singleton signal, (b) is likely; if it doesn't, (a) is more consistent.

### 6.4 `cat_a_pro_s5_d_loc_p95`

**Construction:** `int(p95(mutation_rewards.d_loc))`. Discrete integer-valued.

**Results:** V1 = 5, V5 = 6, decayexp = 7, decayepoch = 6. Decayexp consistently +1 above V5 (5/5 paired seeds). Wilcoxon signed-rank p = 0.0625 (smallest possible at n=5; t-test undefined due to zero within-group variance).

### 6.5 `cat_a_pro_s8_unique_locs_with_d_loc_le_2`

**SQL:** `SELECT COUNT(DISTINCT f.constraint_loc) FROM failures f JOIN mutation_rewards mr ON mr.mutation_id=f.mutation_id WHERE mr.d_loc <= 2`

**Results:** V1 25.3, V5 28.2, decayexp 29.8, decayepoch 29.6. p ≈ 0.06 decayexp vs V5 (marginal). Sanity invariant `≤ local_context_final` passes on all 30 DBs.

### 6.6 `cat_a_pro_s8_unique_locs_with_d_glob_le_1`

**SQL:** Same as 6.5 but `mr.d_glob <= 1`.

**Results:** V1 30.0, V5 33.4, decayexp 33.6, decayepoch 33.2. No significant discrimination. Included for §8 catalog completeness.

### 6.7 `cat_b_pro_s5_proof_generated_zero_residue_rejected_rate`

**SQL** (D1.A DBs only — `proof_generated` NULL on R2):

```sql
SELECT SUM(CASE WHEN m.proof_generated=1 AND mr.d_glob=0 AND m.proof_verify_failed=1 THEN 1 ELSE 0 END) * 1.0
       / COUNT(*) FROM mutations m JOIN mutation_rewards mr ON mr.mutation_id=m.id
```

Uses `d_glob=0` as the "family residues all zero" heuristic per spec §2.2.

**Results (10 D1.A DBs only):** Mean **12.4%** (range 11.6-13.8%). No R2 baseline. Decayexp vs decayepoch p ≈ 0.10 (n.s.).

### 6.8 `cat_b_pro_b_wall_clock_per_normalized_discovery`

**Construction:** `mean(mutations.elapsed_ms) / local_context_final`. D1.A DBs only.

**Results:** Mean **~65-66 ms / discovery unit**. decayexp vs decayepoch p ≈ 0.60. Returns NULL on R2.

---

## 7. Findings

### Finding A — Orthogonality surprise (`recent_marginal_discovery_rate`)

Spec §1.2 predicted `recent_marginal_discovery_rate` would correlate ρ ≈ 0.4-0.7 with `discovery_binary_reward` "by construction" (rolling mean tracks the bit). **Reality: max |ρ| = 0.114 post-local** (discretized at 0.05; max continuous Pearson 0.134). The spec's intuition was wrong for the sparse-discovery post-local regime where `discovery_binary_reward` fires on only ~3% of pulls — the rolling mean also stays low and the two decouple.

**Implication:** Pro's §7 Stage 2 "recent marginal discovery" signal IS available as an L1 OR-channel candidate, not just as a continuous magnitude for a future scalar bandit. D1.E gains a 4th candidate.

### Finding B — Singleton-failure rate is the only Tier-2 decay discriminator

Of 8 Tier-2 metrics, only `pro_s5_singleton_failure_rate` shows significant V5-decay vs V5-static separation (p = 2.6e-06 / 9.7e-05). All others (verifier_accepted=0 everywhere, co-failure degree, d_loc_p95, unique_locs metrics, Cat-B Cat-B) either don't separate or have only marginal trends.

**Architectural significance:** Pro's Report 3 §15 Priority 4 ("Decaying-floor V5") explicitly noted decay variants needed re-evaluation with enriched reward signals. D1.C now provides the per-pull form (`singleton_failure_flag`) for D1.E to test that re-evaluation. **The headline message for Pro:** decay variants ARE doing something measurably different at the singleton-failure level — D1.E will tell us whether that difference is good (multi-loc richness) or bad (singleton miss).

### Finding C — Pro's "free f_new L1 channel" is empirically dead on V5

`f_new_flag` fires on ~0.17% of pulls full-campaign and ~0% post-local on the V5 corpus. OR-ing it into bandit_success would add essentially zero new discrimination bits. **NFP-9's "free" framing remains correct on engineering cost** but is practically vacuous on V5. **Likely re-activates on Hybrid V7** if V6-only kinds bring new constraint families that fire `f_new`.

### Finding D — Conditional Option C replay not triggered

Spec §1.4 reserved a conditional Batch 1.5 to replay per-pull `l_new/g_new/s_new/f_new` from raw tables IF all 4 non-trivial Tier-1 signals failed orthogonality. Only `f_new_flag` fails (and on non-saturation, not orthogonality); the other 4 pass. **Option A channel set is sufficient** for D1.C scope.

### Finding E — D1.C has zero CGC-class field-priority dependency

Composer audit verified `git grep` over `bug_proximity.py` shows zero references to `compressed_global_coverage`, `byte_addr`, or `address_region`. The NFP-10 class of bug (wrong field fed to a downstream function, plausible aggregates) cannot apply to this metric stack. The closest semantic schism is crash-mode `d_loc = 0` with non-empty `failures` (~1.1% of pulls; bounded < 0.2 pp impact; documented in §5.5).

---

## 8. What Pro should know before judging D1.C's value

### 8.1 Scope of every conclusion in this subsection

**D1.C ran exclusively on V5_semantic_v2 catalog under the cTS scheduler.** Every number, every gate pass/fail, every shortlist ranking is derived from:

- 10 R2 V1 DBs (b1/cTS V1 — different catalog, used as context only; primary D1.E target is V5)
- 10 R2 V5 DBs (b1/cTS V5_semantic_v2 — the primary D1.E target)
- 10 D1.A decay DBs (V5_semantic_v2 + ExponentialDecayFloor / EpochStaircaseFloor)

**We did NOT test:**

- **Hybrid-cTS (Pro §15 Priority 1).** V5 catalog + selected V6-only kinds. The V6-only kinds (INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, etc.) would change mutation distribution. Expected changes:
  - `mutation_substrategy_uniqueness` fire rate: probably **higher** (more diverse substrategy keys); may saturate faster
  - `d_loc_le_2_flag` fire rate: unknown — depends on V6-only kinds' d_loc distributions
  - `f_new_flag` near-deadness: may **NOT hold** if V6 kinds discover new constraint families
  - `singleton_failure_flag` decay discrimination: V5 finding; may differ on Hybrid catalog
- **V7 (post-D1.E expansion — Pro §15 Priority 3).** New kinds (TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD, CYCLE_PC_MOD, etc.) would each need a substrategy-field audit; `INSTR_TYPE_MOD` degeneracy we found here may not generalize.
- **Arguzz-with-thompson (Pro §14 ablation).** Different scheduler entirely. The post-local sparse-discovery regime that drove our orthogonality surprise (`recent_marginal_discovery_rate` passing because `discovery_binary_reward` decouples post-local) may not hold under Arguzz dynamics. Gates would need re-validation.

### 8.2 What we CAN claim with high confidence

1. On the V5 cTS catalog: three new per-mutation signals (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`) pass D1.E's L1 OR-channel pre-screening gates.
2. On the V5 cTS catalog: Pro §7 Stage 2 "recent marginal discovery" is available as a 4th L1 candidate (orthogonality surprise).
3. On the V5 cTS catalog: Pro's "free f_new L1 channel" adds essentially zero new signal post-local.
4. On the V5 cTS catalog: V5-decay variants find ~22% fewer singleton failures than V5-static (p = 2.6e-06 / 9.7e-05). The architectural interpretation (richer multi-loc vs missed surgical) is **open**.
5. Pro §5 `verifier_accepted_invalid_count` is 0 on the entire V5 corpus — useful as a V6/Hybrid-cTS regression detector, currently informative-by-absence.

### 8.3 What we CANNOT claim

1. **That L1 enrichment will help the bandit.** D1.E forward-run is the causal test.
2. **That these signals generalize to Hybrid V7 / V7 / Arguzz-with-thompson.** Catalog and scheduler changes could shift fire rates, correlations, and decay-vs-static gaps materially. A Tier-1 re-audit on the first Hybrid-cTS campaign is recommended before wiring L1.
3. **That `f_new_flag` is universally dead.** It is dead on V5 because V5 family-novelty events are concentrated early. On Hybrid V7 it may re-activate.
4. **That the singleton-failure decay discrimination explains decay variants' overall behavior.** It's the largest measurable Tier-2 gap, but D1.A already showed decay variants do not significantly change `local_context_final` on this corpus. The two findings are not in tension (decay can reshape failure profile without changing local coverage) but are separate.

### 8.4 If Pro wants to redirect D1.C's effort, here are the natural options

- **(i)** Accept the V5 shortlist for D1.E forward-run, then re-audit on the first Hybrid-cTS campaign. (Default plan.)
- **(ii)** Defer L1 wiring entirely until Hybrid V7 lands, then run D1.C-equivalent fresh. Pro's Priority-1 timing dictates this — D1.E vs Hybrid V7 sequencing is currently D1.E-first per the revisit plan.
- **(iii)** Add per-pull "low-cofailure" signal as a 6th Tier-1 candidate. Requires running-graph update per pull (expensive). Pro §7 Stage 2 lists this; we did not implement it because Tier-2 co-failure already shows no decay discrimination.
- **(iv)** Trigger Option C replay (Batch 1.5) to surface per-channel `l_new/g_new/s_new` granularity. Only justified if D1.E needs per-channel reward weighting.

---

## 9. Verdict for D1.E

| Recommendation | What D1.E should do |
|---|---|
| **Top-3 L1 OR-channel candidates** | Wire `mutation_substrategy_uniqueness`, `d_loc_le_2_flag` (with opposite-saturation guard), `singleton_failure_flag` |
| **4th alternate** | `recent_marginal_discovery_rate` (continuous; scalar bandit per NFP-9, or 4th OR with discretization) |
| **Do not wire on V5** | `f_new_flag` (Bucket B — empirically dead post-local; keep for non-V5 catalogs) |
| **L1 composition** | Cap at ≤ 3 OR'd channels per revisit plan §3.3 to avoid opposite-saturation; evaluate alternative compositions (per-channel reward, weighted, scalar bandit) per D1.B §4 open question |
| **Singleton-decay finding** | Validate in forward run — if singleton signal in L1 improves decay's gradient, supports interpretation (b) "decay misses singletons"; if not, interpretation (a) "decay finds richer multi-loc" is more consistent |
| **Hybrid V7 re-audit** | Required before assuming D1.C shortlist transfers; budget ~2-3 days of analysis-only Composer time post-Hybrid-cTS first campaign |

---

## 10. Limitations

1. **V5-catalog scope.** All conclusions are V5-specific. Hybrid V7 / V7 / Arguzz-with-thompson not tested.
2. **Option A channel reconstruction.** Per-pull `l_new/g_new/s_new` granularity not recovered; we use the bandit's binary success bit only. Production tests support Option A bit-identity but Option C full replay not run.
3. **Crash-mode d_loc=0 schism.** Production sets `d_loc=0` on crash with non-empty failures (~1.1% of pulls). `d_loc_le_2_flag` reads stored d_loc; sensitivity check bounds the impact at < 0.2 pp on post-local fire rate; shortlist ordering unchanged.
4. **Singleton definition: 1 row vs 1 loc.** Code uses `COUNT(*) FROM failures = 1` (row form). Spec prose says "1 constraint_loc broke" (loc form). Tier-1 and Tier-2 are internally consistent; D1.E spec drafting should pin the architectural choice.
5. **INSTR_TYPE_MOD substrategy degeneracy.** All-NULL columns on this catalog → composite key collapses to `(INSTR_TYPE_MOD, ())`. Only first INSTR_TYPE_MOD pull per DB fires `mutation_substrategy_uniqueness=1`. D1.E should consider special-casing or excluding INSTR_TYPE_MOD.
6. **N=5 paired triplets for decay tests.** Decay variants are paired with V5-static on 5 seeds only (1234-1238). Larger n needed for confident sub-effect significance.
7. **D1.C ≠ D1.E causality.** Passing pre-screening gates is necessary, not sufficient, for bandit improvement.
8. **No forward-run validation.** Analysis-only on frozen DBs. The whole point of D1.E is the forward-run causal test.

---

## 11. Provenance

| Item | Value |
|---|---|
| Module | `a4/runs/iv_pos_7/analysis/bug_proximity.py` (707 LOC) |
| Tests | `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` — **40 passed** |
| Tier-1 audit | `a4/runs/iv_pos_8/d1c/d1c_batch1_tier1_audit.csv` (150 rows) |
| Tier-2 table | `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv` (30 rows × 11 cols) |
| Tier-2 schema (D2.G) | `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` |
| Correlation matrix | `a4/runs/iv_pos_8/d1c/d1c_correlation_matrix.csv` (270 rows) |
| Multi-threshold | `a4/runs/iv_pos_8/d1c/d1c_recent_marginal_thresholds.csv` (180 rows) |
| Non-saturation | `a4/runs/iv_pos_8/d1c/d1c_non_saturation.csv` (150 rows) |
| Paired t-tests | `a4/runs/iv_pos_8/d1c/d1c_paired_tests.csv` (24 rows) |
| Wilcoxon non-parametric | `a4/runs/iv_pos_8/d1c/d1c_nonparametric_tests.csv` (6 rows) |
| Shortlist (full reference) | `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` |
| D1.E hand-off | `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` |
| Notebook | `a4/runs/iv_pos_8/d1c/IV_POS_8_D1C_NOTEBOOK.ipynb` + `.html` |
| Composer audit report | `a4/docs/cloud2/composer/D1C_AUDIT_REPORT.md` |

---

## Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 (Batch 3) | Composer | Initial subsection draft — sparse summary form |
| 2026-06-17 (audit-driven rewrite) | Opus | Substantial rewrite per Ivan request — added §1 "What Pro asked for, and how each metric performed" mapping table; added §5 + §6 full Tier-1/Tier-2 catalog with definitions + per-variant results; added §8 "What Pro should know" scope-disclaimer section explicitly covering Hybrid-cTS / V7 / Arguzz-with-thompson; reframed §9 verdict for D1.E; expanded limitations to 8 items |
