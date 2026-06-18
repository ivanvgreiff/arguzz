# D1.C Bug-Proximity Metric Stack — Signal Shortlist & Full Metric Reference

**Status:** D1.C Batches 1+2+3 complete (analysis-only; no `a4/standalone/` changes)  
**Audience:** Opus review, D1.E spec author, Pro disclosure (via `D1C_SUBSECTION.md`)  
**Implementation:** `a4/runs/iv_pos_7/analysis/bug_proximity.py`  
**Spec:** `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` v0.3  

This document is the **readable reference** for everything D1.C planned, built, and measured. It explains what each metric is, how it is constructed, why we hypothesized it would help extend the bandit's discriminating window past local saturation, what the 30-DB Cat-A corpus actually shows, and which non-obvious definitions matter for interpretation.

---

## 1. What problem D1.C is solving

D1.A showed that the production bandit success bit — `discovery_binary_reward = 1` iff any of `{l_new, g_new, s_new} > 0` — **saturates by mutation ~3000–3500**. After local context discovery (~46 distinct `local_coverage_v2` keys), the bit fires rarely in the post-local regime. Adaptive Thompson sampling then has almost no gradient.

D1.B showed that **L0 schema coarsening alone cannot fix this**. Even the best corrected CGC variant (`production_log2_corrected`, with the NFP-10 `byte_addr` fix) yields only ~1.4 new global keys per 100 mutations post-local. Coarser variants saturate *earlier*, making the problem worse.

**D1.C's job** is therefore different from D1.B: find **per-mutation (Tier-1)** signals that (a) stay active after local saturation, (b) are empirically **orthogonal** to the existing reward channels the bandit already learns from, and (c) are cheap enough to wire into production in D1.E as **L1 OR-channel** candidates. In parallel, ship **per-campaign (Tier-2)** bug-proximity metrics aligned with Pro Report 3 §5/§8 for D2.G's V5-vs-V6 comparison table.

**Critical scope disclaimer:** D1.C analyzes **frozen DBs** and reports statistical properties (fire rate, correlation, decay discrimination). It does **not** prove that OR-ing these signals into `bandit_success` will improve the bandit — that causal question is **D1.E's forward-run job**.

---

## 2. Architecture: two tiers, two consumers

| Tier | Granularity | Count | Purpose | Primary consumer |
|---|---|---:|---|---|
| **Tier-1** | Per-mutation (per pull) | **5 signals** | L1 OR-channel candidates for D1.E reward rewire | D1.E spec |
| **Tier-2** | Per-campaign (one scalar per DB) | **8 metrics** | Bug-proximity disclosure + V5/V6 comparison | D2.G `build_d2_artifacts.py`, Pro §5/§8 |

**Cat-A vs Cat-B labeling:** Every metric is tagged by what schema it needs.

- **Cat-A:** Computable on all R2 V1, R2 V5, and D1.A decay DBs (existing tables only).
- **Cat-B:** Requires D1.A's new `mutations` columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`). These are **NULL on R2 V1/V5** and populated only on D1.A's 10 decay DBs.

CSV columns use `cat_a_*` / `cat_b_*` prefixes so consumers instantly know corpus requirements.

---

## 3. Corpus and analysis windows

### 3.1 The 30-DB Cat-A corpus

Same 30 databases as D1.B Batch 1 audit via `cat_a_db_list()`:

| Sub-corpus | Count | Variants | Seeds | Role |
|---|---:|---|---|---|
| R2 V1 | 10 | `V1` | 1234–1243 | Different scheduler family (b1/cTS V1); context only |
| R2 V5 | 10 | `V5` | 1234–1243 | **Primary D1.E target** (V5-static paired seeds) |
| D1.A decay | 10 | `V5_decayexp`, `V5_decayepoch` | 1234–1238 (paired) | Decay-vs-static discrimination |

Each DB has **6000 mutations** (pulls). All 30 DBs have complete `mutation_rewards`, `reward_counterfactuals`, and `mutation_substrategy` rows (no missing joins).

### 3.2 Post-local analysis window

Tier-1 **non-saturation** and **orthogonality** gates use the post-local window:

```
NON_SATURATION_WINDOW = [3000, 6000)   # mutations 3000..5999 inclusive → 3000 pulls
NON_SATURATION_MIN_FIRE_RATE = 0.05    # strict > 5%, not ≥
CORRELATION_THRESHOLD = 0.4              # |Pearson ρ| must stay below this
```

**Intuition:** D1.B's mean `time_to_46` ≈ 3221 on V5 paired seeds. The window `[3000, 6000)` is where we need signals to keep firing *after* local saturation, when `discovery_binary_reward` has mostly gone quiet (~3% post-local fire rate on V5 s1234).

### 3.3 Existing channels (Option A — no replay)

Per-pull `l_new`, `g_new`, `s_new`, `f_new` integers are **not stored** in SQLite. D1.C uses **Option A** from the spec:

| Channel | Source | Construction |
|---|---|---|
| `discovery_binary_reward` | `reward_counterfactuals.discovery_binary_reward` | `1 if (l_new + g_new + s_new) > 0 else 0` — the bandit's actual Bernoulli success bit |
| `f_new_flag` | `reward_counterfactuals.fnew_only_reward` | `1 if fnew_only_reward > 0 else 0` — exact proxy for `f_new ≥ 1` because `fnew_only_reward = 0.30 × sat(f_new, 1.0)` |

**Option C replay** (recomputing `l_new/g_new/s_new/f_new` from `failures` + coverage tables) was **not triggered** — see §8.

Correlation analysis uses **30 DBs × 9 non-trivial cells** = **270 rows** in `d1c_correlation_matrix.csv`. The 9 non-trivial cells per DB = 5 Tier-1 signals × 2 channels (`discovery_binary_reward`, `f_new_flag`) − 1 trivial `f_new_flag × f_new_flag` self-cell. Spec §1.3.3 originally framed orthogonality on the 5 paired V5 seeds only; implementation reports max |ρ| across all 30 Cat-A DBs as a conservative (stricter) gate. Audit confirms shortlist ordering is **unchanged** under V5-paired-5-only scope (see Composer's audit report §5.2).

---

## 4. Key definitions (self-contained)

### 4.1 `d_loc` — local failure context count

**Production definition** (`coverage_state.py`): For each pull, collect failure contexts as `(constraint_loc, major, minor)` tuples. Then:

```
d_loc = |{unique failure contexts}|
n_fail = total failure rows
r_rep  = max(0, n_fail - d_loc)   # repeat mass within contexts
```

**Important:** `d_loc` is **not** the same as `COUNT(*)` from the `failures` table. Multiple failure rows can share the same context (same loc + major + minor), in which case `n_fail > d_loc`.

**Crash pulls:** When `mode='crash'` (missing touch bitmap), production sets `d_loc = 0` even if the `failures` table has rows. This affects ~1.1% of pulls corpus-wide (2,009 / 180,000). Tier-1 `d_loc_le_2_flag` reads stored `mutation_rewards.d_loc` and therefore treats crash pulls as `d_loc ≤ 2`. Sensitivity analysis shows this moves post-local fire rates by **< 0.2 percentage points** — not enough to change shortlist conclusions.

### 4.2 Singleton failure

**Tier-1 `singleton_failure_flag`:** `1` iff exactly **one failure row** exists for this `mutation_id`:

```sql
SELECT COUNT(*) FROM failures WHERE mutation_id = ?  →  must equal 1
```

**Tier-2 `pro_s5_singleton_failure_rate`:** Fraction of all mutations where the above holds:

```sql
COUNT(mutations with exactly 1 failure row) / COUNT(all mutations)
```

**Note:** Spec prose sometimes says "exactly one constraint_loc broke." The implemented definition is **one failure row** (which, on V5 s1234, aligns perfectly with `d_loc = 1` on 996 pulls; five edge cases have two rows at the same loc with different major/minor).

**Hypothesis:** Singleton failures are "surgical" — one constraint broke in isolation, often closer to a minimal bug witness than multi-loc cascades. Pro Report 3 §5 lists singleton-failure rate as a bug-proximity metric.

### 4.3 Orthogonality (Pearson ρ)

For each Tier-1 signal `S` and existing channel `c`, compute Pearson correlation on the post-local window. Binary signals use `{0,1}`; the continuous signal `recent_marginal_discovery_rate` is **discretized at threshold 0.05** before correlation (same threshold as its fire-rate gate).

**Gate:** `max |ρ| < 0.4` across all 30 DBs and both channels `{discovery_binary_reward, f_new_flag}`.

**Why 0.4?** Heuristic tolerance — signals too correlated with what the bandit already sees provide little new information when OR'd in.

### 4.4 Disjoint-fire fraction

Correlation alone can miss useful signals. We also report:

```
disjoint_fire_rate(S, c) = |{pulls: S fires AND c = 0}| / |{pulls: S fires}|
```

**Intuition:** A good L1 OR-channel should fire **mostly when `discovery_binary_reward` is already 0**, extending the success bit without redundant co-firing. Bucket A candidates show **96–100%** disjoint-fire vs `discovery_binary_reward` (30-DB means in §7).

### 4.5 Rank score (shortlist ordering)

Per spec §2.3 task 3:

```
rank_score = (1 / max|ρ|) × mean_fire_rate_post_local
```

Higher is better. Uses **30-DB mean** post-local fire rate and **30-DB max |ρ|** (conservative). This is a **tie-breaker heuristic** within signals that already pass both gates — not an independent selection criterion.

---

## 5. Tier-1 signals — full catalog

Five per-mutation signals were implemented in Batch 1. All produce one value per mutation, aligned to `mutations.id` order (length 6000 per DB).

---

### 5.1 `f_new_flag` — global family novelty bit

| Property | Value |
|---|---|
| **Category** | Cat-A |
| **Type** | Binary `{0,1}` |
| **Source table** | `reward_counterfactuals.fnew_only_reward` |

**Construction:**

```python
f_new_flag = 1 if fnew_only_reward > 0.0 else 0
# Exact proxy: fnew_only_reward = 0.30 * sat(f_new, 1.0); positive iff f_new >= 1
```

**Hypothesis:** `f_new` captures global family novelty (new constraint-family discoveries). OR-ing it into L1 would give the bandit signal when a **new family** is found, even if the aggregate `discovery_binary_reward` is saturated or fires on a different channel (local/global/structural). NFP-9 framed this as a "free" L1 channel because `fnew_only_reward` is already stored.

**Results (30-DB):**

| Metric | Value |
|---|---:|
| Mean post-local fire rate | **~0%** (0/30 DBs pass 5% gate) |
| Full-campaign fire rate | **~0.17%** (~321 positive pulls / 180,000) |
| Max \|ρ\| vs `discovery_binary_reward` | **0.123** (V1 s1243 only — small-sample artifact) |
| Max \|ρ\| on V5 sub-corpus | **0.0** |

**Interpretation:** Empirically **dead post-local** on the V5 corpus. The bandit already "sees" global family novelty indirectly through `discovery_binary_reward` when co-occurring; when it doesn't co-occur, it almost never fires alone. **Bucket B** — deferred for non-saturation failure, not orthogonality failure.

---

### 5.2 `recent_marginal_discovery_rate` — discovery momentum

| Property | Value |
|---|---|
| **Category** | Cat-A |
| **Type** | Continuous `[0.0, 1.0]` |
| **Source table** | `reward_counterfactuals.discovery_binary_reward` (rolling) |

**Construction:**

```python
# W = 100 pulls (ROLLING_DISCOVERY_WINDOW)
recent_marginal_discovery_rate[t] = mean(discovery_binary_reward[t-W+1 : t+1])
```

At mutation 0, the window is shorter (uses all pulls so far). Fire-rate gate treats "fires" as `rate >= 0.05`.

**Hypothesis:** Even when the instantaneous discovery bit is 0, a **high trailing discovery rate** might indicate the campaign is still in a "hot" discovery phase — useful as (a) a timing detector for the saturation boundary, or (b) a continuous magnitude input for a future scalar bandit (NFP-9 deferred L2).

**Spec expectation vs reality:** The spec docstring predicted ρ ≈ 0.4–0.7 vs `discovery_binary_reward` "by construction" on stationary stretches. **Post-local reality is different:**

| Measure | Max \|ρ\| | Where |
|---|---:|---|
| Discretized @ 0.05 (correlation gate) | **0.114** | D1.A decayexp s1238 |
| Continuous Pearson (sensitivity) | **0.134** | D1.A decayexp s1236 |

Once `discovery_binary_reward` becomes sparse post-local (~3% on V5), the rolling mean also stays low and moves slowly — the two decouple.

**Results (30-DB):**

| Metric | Value |
|---|---:|
| Mean post-local fire rate | **15.8%** |
| Passes non-saturation gate | **30/30 DBs** |
| Passes orthogonality gate | **Yes** (surprise finding) |

**By variant (post-local fire rate):** V1 9.9%, V5 14.8%, D1.A decayexp 15.3%, D1.A decayepoch 14.5%.

**Bucket placement:** Passes both gates → listed as **4th alternate in Bucket A** (continuous; D1.E may prefer binary OR channels first). **Bucket C is empty** on this corpus — `recent_marginal` was *expected* to fail orthogonality and land in Bucket C as an NFP-9 scalar candidate, but post-local decorrelation changed that. Multi-threshold analysis (`d1c_recent_marginal_thresholds.csv`, 180 rows) confirms ρ < 0.4 at 25th/50th/75th percentile discretization thresholds.

---

### 5.3 `singleton_failure_flag` — surgical failure indicator

| Property | Value |
|---|---|
| **Category** | Cat-A |
| **Type** | Binary `{0,1}` |
| **Source table** | `failures` (grouped by `mutation_id`) |

**Construction:**

```python
singleton_failure_flag = 1 if COUNT(failures for this mid) == 1 else 0
```

**Hypothesis:** Pulls that break exactly one failure row represent **minimal, isolated fault witnesses** — plausibly closer to "one bug step away" than pulls that break many constraints at once. Pro §5 explicitly catalogs singleton-failure rate. As an L1 OR-channel, it would fire in post-local pulls where the bandit sees no discovery but a surgical failure still occurred.

**Results (30-DB):**

| Metric | Value |
|---|---:|
| Mean post-local fire rate | **16.5%** |
| Max \|ρ\| vs `discovery_binary_reward` | **0.082** (V1 s1241) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | **99.6%** (range 98.7–100%) |
| Rank score | **2.02** (3rd) |

**By variant (post-local):** V1 **20.3%**, V5 **16.8%**, D1.A decayexp **12.5%**, D1.A decayepoch **12.2%**.

**Batch 2 link (load-bearing):** The per-campaign form `pro_s5_singleton_failure_rate` is the **only Tier-2 metric** with statistically significant decay-vs-V5-static discrimination:

| Comparison | Mean singleton rate | p-value |
|---|---:|---:|
| V5_decayexp vs V5 | 12.9% vs 16.7% | **2.6×10⁻⁶** |
| V5_decayepoch vs V5 | 13.4% vs 16.7% | **9.7×10⁻⁵** |
| V5_decayexp vs V5_decayepoch | 12.9% vs 13.4% | 0.059 (n.s.) |

Decay variants produce ~22% fewer singleton-failure mutations. Architectural interpretation is **open** (decay pushes multi-loc failures vs decay misses singletons entirely). D1.E should validate singleton channel behavior on decay forward runs.

**Bucket A — rank 3.**

---

### 5.4 `mutation_substrategy_uniqueness` — first-time arm sub-variant

| Property | Value |
|---|---|
| **Category** | Cat-A |
| **Type** | Binary `{0,1}` |
| **Source tables** | `mutations.kind` + `mutation_substrategy` |

**Construction:**

```python
composite_key = (kind, tuple of kind-specific non-null substrategy columns)
mutation_substrategy_uniqueness = 1 iff composite_key not in seen_set else 0
```

`KIND_TO_SUBSTRATEGY_FIELDS` was **empirically derived** from `d1c_substrategy_field_audit.csv` on all 30 DBs:

| Kind | Substrategy fields used |
|---|---|
| `INSTR_WORD_MOD_SUR`, `INSTR_WORD_MOD_FULL` | opcode, rd, rs1, rs2, funct3, funct7, imm |
| `MEM_VAL_MOD` | byte_lane, bit_mask, value_class |
| `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `PRE_EXEC_REG_MOD`, `STORE_OUT_MOD` | value_class |
| `INSTR_TYPE_MOD` | **empty tuple** (all substrategy columns NULL on all 30 DBs) |

**Hypothesis:** The bandit selects mutation **kind** (arm) but not fine-grained sub-variant. First occurrence of a `(kind, substrategy)` composite represents exploration of a **new sub-arm** within the same kind — potentially orthogonal to whether that pull also discovered a new coverage key. High disjoint-fire would mean new sub-variants are tried mostly on non-discovery pulls, extending learning signal post-local.

**INSTR_TYPE_MOD caveat:** ~45,511 pulls (25% of corpus) are `INSTR_TYPE_MOD` with all-NULL substrategy → degenerate composite key `(INSTR_TYPE_MOD, ())`. Only the **first** INSTR_TYPE_MOD pull per DB gets `uniqueness=1` (~30 fires corpus-wide). Post-local window on V5 s1234: **0** INSTR_TYPE_MOD uniqueness fires — all post-local signal comes from INSTR_WORD_MOD_*, MEM_VAL_MOD, etc. D1.E should consider excluding INSTR_TYPE_MOD from this channel or treating it as a separate arm class.

**Results (30-DB):**

| Metric | Value |
|---|---:|
| Mean post-local fire rate | **33.7%** |
| Max \|ρ\| vs `discovery_binary_reward` | **0.069** (V5 s1243) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | **98.1%** (range 96.9–99.0%) |
| Rank score | **4.91** (highest) |

**By variant (post-local):** V1 33.5%, V5 **39.5%**, D1.A decayexp 30.0%, D1.A decayepoch 29.5%.

**Bucket A — rank 1.**

---

### 5.5 `d_loc_le_2_flag` — near-minimal local failure context

| Property | Value |
|---|---|
| **Category** | Cat-A |
| **Type** | Binary `{0,1}` |
| **Source table** | `mutation_rewards.d_loc` |

**Construction:**

```python
d_loc_le_2_flag = 1 if mutation_rewards.d_loc <= 2 else 0
```

Substituted for revisit plan's "sliding-window d_loc rate" — simpler per-pull threshold flag; sliding-window variant deferred to D1.C v2 if needed.

**Hypothesis:** Low `d_loc` means few distinct local failure contexts broke on this pull — "near-minimal" fault multiplicity per Pro §8. Pulls with `d_loc ≤ 2` may be bug-proximate even when no new coverage key was discovered. Pro Report 3 §8 pairs `d_loc` distribution stats with `unique_locs_with_d_loc_le_2` at campaign level.

**Results (30-DB):**

| Metric | Value |
|---|---:|
| Mean post-local fire rate | **60.7%** (highest of all candidates) |
| Max \|ρ\| vs `discovery_binary_reward` | **0.239** (V1 s1241) |
| 30-DB mean disjoint-fire vs `discovery_binary_reward` | **99.3%** (range 98.8–99.6%) |
| Rank score | **2.54** (2nd) |

**By variant (post-local):** V1 **76.3%**, V5 **60.8%**, D1.A decayexp 46.5%, D1.A decayepoch 47.5%.

**Opposite-saturation caveat:** At 60%+ post-local fire, naive OR into `bandit_success` risks pushing the bit **always-on** — the opposite failure mode from saturation. D1.E must cap OR channels at **≤ 3** beyond `discovery_binary_reward` per revisit plan §3.3 and evaluate composition (not naive OR alone).

**Bucket A — rank 2.**

---

## 6. Tier-2 metrics — full catalog

Eight per-campaign metrics were implemented in Batch 2. One row per DB in `d1c_metrics_table.csv` (30 rows × 8 metric columns + provenance). Schema locked in `d1c_tier2_schema.md` for D2.G consumption.

---

### 6.1 `cat_a_pro_s5_verifier_accepted_invalid_count`

| Property | Value |
|---|---|
| **Pro reference** | §5 |
| **Category** | Cat-A |

**Construction** (locked to D1.A spec SQL):

```sql
SELECT COUNT(*) FROM mutations
WHERE verifier_accepted = 1 AND num_failures > 0
```

**Hypothesis:** Mutations where the verifier said "yes" but failures existed indicate **accepted-invalid** executions — a direct bug-proximity / soundness-gap signal.

**Results:** **0 on all 30 DBs.** R2 and D1.A corpora have `verifier_accepted = 0` everywhere. Metric is correctly implemented but **uninformative on this corpus**. Retained for D2.G schema completeness.

---

### 6.2 `cat_a_pro_s5_co_failure_graph_degree_p95`

| Property | Value |
|---|---|
| **Pro reference** | §5 |
| **Category** | Cat-A |

**Construction:**

1. Build undirected graph: nodes = distinct `constraint_loc` values; edge `(a,b)` if both co-appear in `failures` for the same `mutation_id`.
2. Compute degree per node; return 95th percentile.

**Hypothesis:** Dense co-failure coupling suggests constraints fail together — campaign-level "failure geography" structure. May differ across V5 vs V6 mutation engines.

**Results (campaign means):**

| Variant | Mean p95 degree |
|---|---:|
| V1 | 27.5 |
| V5 | 31.4 |
| V5_decayexp | 31.0 |
| V5_decayepoch | 30.8 |

No significant decay-vs-V5 discrimination (paired t-tests p ≈ 0.23–0.62). Co-failure structure is stable across decay variants on this corpus.

---

### 6.3 `cat_a_pro_s5_singleton_failure_rate`

| Property | Value |
|---|---|
| **Pro reference** | §5 |
| **Category** | Cat-A |

**Construction:** See §4.2. Campaign-level fraction; Tier-1 `singleton_failure_flag` per-pull rate matches this on full `[0, 6000)` window (verified identical on all 30 DBs).

**Results:** See §5.3 decay table. **The headline Batch 2 finding.**

---

### 6.4 `cat_a_pro_s5_d_loc_p95`

| Property | Value |
|---|---|
| **Pro reference** | §5 / §8 |
| **Category** | Cat-A |

**Construction:** 95th percentile of `mutation_rewards.d_loc` across all 6000 pulls. Stored as **integer** (`int(round(p95))`).

**Results (campaign means):**

| Variant | Mean p95 |
|---|---:|
| V1 | **5** |
| V5 | **6** |
| V5_decayexp | **7** |
| V5_decayepoch | **6** |

Decayexp consistently shows higher tail multiplicity (p95 = 7 on all 5 paired seeds vs 6 for V5-static) — consistent with fewer singletons / more multi-context failures under decay. Wilcoxon signed-rank p = 0.0625 for decayexp vs V5 (marginal, n=5 pairs).

---

### 6.5 `cat_a_pro_s8_unique_locs_with_d_loc_le_2`

| Property | Value |
|---|---|
| **Pro reference** | §8 |
| **Category** | Cat-A |

**Construction:**

```sql
SELECT COUNT(DISTINCT f.constraint_loc)
FROM failures f
JOIN mutation_rewards mr ON mr.mutation_id = f.mutation_id
WHERE mr.d_loc <= 2
```

Distinct constraint locations that ever appeared during a low-multiplicity pull.

**Hypothesis:** Campaign-level footprint of "near-minimal" failures — how many different program loci were touched by surgical-ish breaks.

**Results (means):** V1 25.3, V5 28.2, decayexp 29.8, decayepoch 29.6. Sanity invariant `≤ local_context_final` passes on all 30 DBs.

---

### 6.6 `cat_a_pro_s8_unique_locs_with_d_glob_le_1`

| Property | Value |
|---|---|
| **Pro reference** | §8 (paired with d_loc metric) |
| **Category** | Cat-A |

**Construction:** Same as §6.5 but `mr.d_glob <= 1` (minimal global Hook-3 context count).

**Results (means):** V1 30.0, V5 33.4, decayexp 33.6, decayepoch 33.2. No significant decay discrimination. Included for Pro §8 catalog completeness.

---

### 6.7 `cat_b_pro_s5_proof_generated_zero_residue_rejected_rate`

| Property | Value |
|---|---|
| **Pro reference** | §5 |
| **Category** | Cat-B (D1.A DBs only) |

**Construction:**

```sql
-- Fraction of mutations where proof was generated, d_glob=0 (zero global residue heuristic), proof_verify_failed=1
```

Returns `None` on R2 DBs (no `proof_generated` column population).

**Hypothesis:** Captures "proof looked valid but residues were zero and verification failed" — near-acceptance / soundness-gap signal from D1.A's new proof telemetry.

**Results (D1.A only):** Mean **12.4%** (range 11.6–13.8% across 10 DBs). No R2 comparison available. Decayexp vs decayepoch paired p ≈ 0.10 (n.s.).

---

### 6.8 `cat_b_pro_b_wall_clock_per_normalized_discovery`

| Property | Value |
|---|---|
| **Pro reference** | Revisit plan §3.2 |
| **Category** | Cat-B (D1.A DBs only) |

**Construction:**

```
mean(mutations.elapsed_ms) / local_context_final
```

`local_context_final` from `metrics.py` (distinct `local_coverage_v2` keys at campaign end).

**Hypothesis:** Normalized wall-clock cost per local discovery — efficiency metric for comparing decay vs static under enriched telemetry.

**Results (D1.A only):** Mean **~65–66 ms per normalized discovery unit** (decayexp and decayepoch similar; paired p ≈ 0.60). Returns `None` on R2.

---

## 7. Selection methodology and bucket assignments

### 7.1 Gates applied (Tier-1)

| Gate | Criterion | Rationale |
|---|---|---|
| **Non-saturation** | `fire_rate_post_local > 5%` on each signal (evaluated per-DB; all 30 reported) | Signal must keep firing after local saturation |
| **Orthogonality** | `max |ρ| < 0.4` vs both Option A channels | Signal must not duplicate what bandit already learns |

### 7.2 Summary table (30-DB aggregates)

| Signal | Mean post-local fire | Max \|ρ\| (30-DB) | Rank score | Disjoint-fire mean | Bucket |
|---|---:|---:|---:|---:|---|
| `mutation_substrategy_uniqueness` | 33.7% | 0.069 | **4.91** | 98.1% | **A (rank 1)** |
| `d_loc_le_2_flag` | 60.7% | 0.239 | **2.54** | 99.3% | **A (rank 2)** |
| `singleton_failure_flag` | 16.5% | 0.082 | **2.02** | 99.6% | **A (rank 3)** |
| `recent_marginal_discovery_rate` | 15.8% | 0.114 | 1.38 | n/a (continuous) | **A (4th alternate)** |
| `f_new_flag` | ~0% | 0.123* | n/a | n/a | **B** |

\*Max \|ρ\| = 0.123 driven by 4 V1 DBs where `f_new` fired once (ρ ≈ 0.12); all V5 \|ρ\| = 0.

### 7.3 Bucket definitions

**Bucket A — RECOMMENDED for D1.E L1 OR-channel (top 3 + 1 alternate)**

Passes **both** gates. Ordered by rank score. Expected L1 effect: high disjoint-fire → OR extends `bandit_success` bit mostly on pulls where `discovery_binary_reward = 0`.

| Priority | Signal | Why it made the cut |
|---:|---|---|
| 1 | `mutation_substrategy_uniqueness` | Best orthogonality (lowest ρ); solid 34% post-local fire; 98% disjoint |
| 2 | `d_loc_le_2_flag` | Strong bug-proximity intuition (Pro §8); 61% fire; watch opposite-saturation |
| 3 | `singleton_failure_flag` | Links to Batch 2 decay finding; 17% fire; highest disjoint-fire |
| 4th | `recent_marginal_discovery_rate` | Passes gates; continuous — scalar bandit or secondary channel |

**Bucket B — DEFERRED (non-saturation failure)**

`f_new_flag` only. Orthogonality would pass on V5 but signal is empirically dead post-local. Do not wire into L1 for V5-paired D1.E without new evidence.

**Bucket C — DEFERRED for orthogonality failure, scalar-bandit only (NFP-9)**

**Empty on this corpus.** Populated only when a signal fails the orthogonality gate but retains useful continuous magnitude. `recent_marginal_discovery_rate` was the expected occupant but passed orthogonality post-local (the **orthogonality surprise** — §8.1). It remains in Bucket A as a binary-eligible alternate; Bucket C is vacant.

---

## 8. Headline findings

### 8.1 Orthogonality surprise (`recent_marginal_discovery_rate`)

**Expected:** Rolling mean of `discovery_binary_reward` correlates ρ ≈ 0.4–0.7 with the instantaneous bit on stationary stretches.

**Observed post-local:** Max ρ = **0.114** (discretized), **0.134** (continuous). Once discovery becomes sparse (~3% post-local on V5), the 100-pull rolling mean also stays low and decouples from the instant bit.

**Implication:** A 4th L1 candidate is available that the spec did not predict would pass the binary orthogonality gate. D1.E can still prefer binary OR channels first; `recent_marginal` is the scalar-bandit fallback.

### 8.2 Singleton decay discrimination (Batch 2)

Only `pro_s5_singleton_failure_rate` significantly separates decay from V5-static (p = 2.6×10⁻⁶ / 9.7×10⁻⁵). Strengthens the case for `singleton_failure_flag` as Bucket A rank 3 — the per-pull form is what D1.E would wire.

### 8.3 Option C replay not triggered (Batch 1.5)

Conditional replay activates only if **all four** non-trivial Tier-1 signals fail orthogonality (|ρ| > 0.4 AND disjoint-fire < 0.3). Only `f_new_flag` fails, and on **non-saturation** not orthogonality. Option A channel set is sufficient.

### 8.4 What D1.C does not touch (NFP-10 lesson)

D1.C has **no dependency** on CGC keys, `byte_addr`, or `address_region` — verified by `git grep` over `bug_proximity.py`. The NFP-10 class of bug (wrong field fed to downstream function, aggregates look plausible) cannot apply to this metric stack. The closest semantic schism is crash-mode `d_loc = 0` with non-empty `failures` (~1.1% of pulls; 100% mode=crash on V5 s1234) — bounded impact (<0.2 pp on `d_loc_le_2_flag` post-local fire rate), documented in §4.1 and traced to `coverage_state.py:190-198`.

### 8.5 Scope of D1.C conclusions

All findings in §8.1-8.4 are derived from the **V5 single-catalog scheduler family** (cTS V5_semantic_v2 + V5 decay variants) on the existing R2 + D1.A corpus. D1.C did NOT test:

- **Hybrid-cTS** (Pro Report 3 §15 Priority 1) — would change `mutation_substrategy_uniqueness` fire rates because the V6-only kinds add new substrategy keys
- **V7** (post-D1.E mutation catalog with TXN_PREV_*, CYCLE_*) — different reachability surface; d_loc / singleton distributions would need re-derivation
- **Arguzz-with-thompson** (Pro Report 3 §14 ablation) — different scheduler dynamics; saturation patterns may not transfer

The shortlist conclusions and the singleton-decay discrimination finding are V5-specific. They are the **most defensible signal candidates given the corpus we have**, but D1.E's forward-run validation is the only way to confirm they remain useful when the catalog or scheduler changes. See `D1C_SUBSECTION.md` "What Pro should know" section for the full scope discussion.

---

## 9. Known limitations and audit disclosures

1. **Option A trust boundary:** `discovery_binary_reward` is read from DB, not Option C replay-verified per pull. Production `reward_v2.py` tests support correctness; residual risk is historical DB corruption only.

2. **`INSTR_TYPE_MOD` degeneracy:** Empty substrategy → at most one uniqueness fire per DB, always early-campaign. Post-local signal unaffected on V5 but D1.E wiring should exclude or special-case this kind.

3. **`singleton` definition:** Code uses one failure **row**, not one distinct `constraint_loc`. Tier-1 and Tier-2 are internally consistent; spec prose in §2.2 slightly overstates "one loc."

4. **`compute_correlation_matrix` discretization:** Continuous `recent_marginal_discovery_rate` is thresholded at 0.05 before Pearson ρ (implementation detail; docstring should note this).

5. **30-DB vs 5-seed framing:** Spec §2.3 originally described 5 paired V5 seeds; implementation uses all 30 DBs for max-|ρ|. Shortlist ordering is **unchanged** under V5-paired-5-only scope (verified in independent audit).

6. **Tier-2 dead metrics on corpus:** `verifier_accepted_invalid_count = 0` everywhere; not a implementation bug.

7. **D1.C ≠ D1.E causality:** Passing gates is necessary, not sufficient, for bandit improvement.

---

## 10. D1.E hand-off summary

**Wire first (max 3 OR channels beyond `discovery_binary_reward`):**

1. `mutation_substrategy_uniqueness`
2. `d_loc_le_2_flag` (with opposite-saturation guard)
3. `singleton_failure_flag`

**Alternate:** `recent_marginal_discovery_rate` (continuous / scalar bandit per NFP-9)

**Do not wire:** `f_new_flag` on V5 corpus (Bucket B)

**Stopping rule:** ≤ 3 OR'd L1 channels per revisit plan §3.3.

Full integration sketch and decay tables: `d1e_handoff_L1_signals.md`.

---

## 11. Artifact provenance

| Artifact | Rows | Contents |
|---|---:|---|
| `d1c_batch1_tier1_audit.csv` | 150 | 30 DBs × 5 Tier-1 signals: fire rates, counts |
| `d1c_correlation_matrix.csv` | 270 | 30 DBs × 9 cells: Pearson ρ per signal × channel |
| `d1c_non_saturation.csv` | 150 | Pass/fail 5% gate per signal per DB |
| `d1c_recent_marginal_thresholds.csv` | 180 | Multi-percentile discretization sensitivity |
| `d1c_metrics_table.csv` | 30 | 8 Tier-2 metrics per DB |
| `d1c_paired_tests.csv` | 24 | Paired t-tests (decay subset, 8 metrics × 3 comparisons) |
| `d1c_nonparametric_tests.csv` | 6 | Wilcoxon for discrete Tier-2 (d_loc_p95, verifier) |
| `d1c_substrategy_field_audit.csv` | — | Empirical `KIND_TO_SUBSTRATEGY_FIELDS` derivation |
| `d1c_tier2_schema.md` | — | D2.G column lock |

**Code:** `a4/runs/iv_pos_7/analysis/bug_proximity.py` (extractors + Tier-2 functions)  
**Tests:** `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` — **40 passed**  
**Builders:** `a4/runs/iv_pos_8/d1c/analysis/build_d1c_*.py`

---

*Generated from D1.C Batches 1+2+3. For Opus review package and D1.E spec drafting.*
