# D1.C — Bug-Proximity Metric Stack: Implementation Spec

**Parent plan:** `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.C + `IV_POS_8_D1_REVISIT_PLAN.md` v0.6 §3.2 + §3.2.1 + §3.3 (D1.E L1 dependency) + §3.1.2 (D1.B handoff for D1.E L0 baseline)
**Pro reference:** `ProG_Report_3.md` §5 (bug-proximity metric catalog) + §8 (analytics) + §15 (priorities)
**Status:** **DRAFT v0.3 — awaiting Ivan greenlight on Q-C-* open questions before Batch 1 kickoff.** D1.B is COMPLETE and committed at `71dae77 Check d1.b` (single squash bundling Batches 1+1.5+1.5b+1.6+2+3); D2 team is unblocked on `compressed_global_extractor.py` field-priority fix per Ivan's coordination plan. D1.C spec uses the corrected baseline (Batch 1.6 byte_addr fix) for all post-hoc analysis.
**Author:** Opus
**Branch:** `cloud2`
**Revision note (v0.3):** Reconciles internal drift from v0.2 surgical edits per Composer second-round audit — Tier-2 count harmonized to **8** in all locations (Q-C-TIER2, §0.3, §1.2 `TIER2_METRICS` constant, §2.2 Batch 2 task list + exit criteria, §2.3 Batch 3 TL;DR); §1.2 `TIER1_SIGNALS` comment updated to reference `discovery_binary_reward` (was stale `l_new+g_new+s_new`); §0.1.1 Tier table updated to reference §1.4 channel set; §1.3.3 orthogonality reformulated against §1.4 Option A channels with explicit "expected high ρ" framing for `recent_marginal_discovery_rate` (Composer pushback B — it is a momentum/smoothing signal, not a strong-orthogonality candidate); §1.2 `recent_marginal_discovery_rate` docstring reframed accordingly + flagged as potential scalar-bandit candidate; §1.4 correlation matrix diagram corrected to put the self-cell at the correct intersection (f_new_flag × f_new_flag); risk row for `verifier_accepted_invalid_count` `hook3_raw` cost removed as stale (D1.A SQL is `mutations` table only). All v0.2 substantive content preserved.
**D2 sync coupling:**
- **D2.G** (Track-β): D1.C ships **Tier-2 Category-A metrics** (per-campaign) that D2.G's `build_d2_artifacts.py` consumes for the V5 vs V6 comparison table (`IV_POS_8_D2_PLAN.md:333`). D1.C must lock its Tier-2 schema before D2.G starts. Coordinate column names + dtypes; analysis path is read-only post-hoc on shared corpus.
- **D1.E** (Stage 3 of revisit plan): D1.C ships **Tier-1 shortlist** (per-mutation, low-correlation-to-existing-channels signals) for L1 OR-channel candidates. D1.C does NOT instrument L1 in production — D1.E does.

---

## 0. Goal recap + open questions Ivan must resolve

### 0.1 Goal

D1.A (FROZEN) showed `bandit_success = (l_new + g_new + s_new) > 0` saturates by mut ~3000-3500 — adaptive TS has no discriminating signal once Pro's floor decays as designed. D1.B showed that **L0 schema-coarsening alone cannot fix this** — coarsened CGC variants (`region_only`, `log4_explicit`, `page_class`) saturate 1400-1900 mut **before** local saturation, making the post-local discriminating window worse, not better. Even `production_log2_corrected` (the least-bad L0) has only ~39 keys discoverable post-local — ~1 new key per 70 mutations, weak signal.

**D1.C's job: find per-mutation signals that are (a) orthogonal to the existing `l_new`/`g_new`/`s_new`/`f_new` channels, (b) stay non-saturated through the campaign, and (c) are computable from existing schema (Cat-A) or D1.A's new schema columns (Cat-B).** These signals become **D1.E L1 OR-channel candidates** that, when OR'd into `bandit_success`, extend the discriminating window past local saturation in a way that L0 schema-swap cannot.

D1.C also produces **per-campaign Tier-2 metrics** for (i) D2.G's V5-vs-V6 comparison table and (ii) Pro-facing bug-proximity disclosure aligned with Pro Report 3 §5/§8 metric catalog.

### 0.1.1 Three-tier signal architecture (must hold internally consistent)

| Tier | Granularity | Purpose | Consumer | Selection criteria |
|---|---|---|---|---|
| **Tier-1** | **Per-mutation** (or per-N-mut sliding window updated per pull) | L1 OR-channel candidate for D1.E reward rewire | D1.E spec | (a) low correlation with the existing-channel set defined in §1.4 (`discovery_binary_reward` + `f_new_flag` for Option A; expandable to per-channel `l_new`/`g_new`/`s_new`/`f_new` if conditional Batch 1.5 replay is triggered) — target Pearson \|r\| < 0.4 across paired V5 seeds; (b) non-saturating fire-rate over [0, 6000) (target: fires on >5% of pulls between mut 3000 and mut 6000 where existing channels do not); (c) cheaply computable in production fuzzer hot path (<10µs per pull or computable from already-stored state) |
| **Tier-2** | **Per-campaign** (aggregate over a full DB) | D2.G comparison table + Pro-facing bug-proximity disclosure | D2.G `build_d2_artifacts.py` + `D1C_SUBSECTION.md` (Stage 4 final D1 report) | (a) maps to a Pro Report 3 §5 or §8 metric; (b) discriminates V5 vs V1 OR V5 vs V6 (TBD when D2 runs); (c) Cat-A (existing schema) or Cat-B (D1.A new schema only) clearly labeled |
| **Tier-3** | n/a (out of D1.C scope) | D3 dependencies (repair templates, isolation layer) | D3 design — `IV_POS_8_D3_DESIGN_PROPOSAL.md` (Track-β) | NOT in D1.C; stubs only per prelim plan |

**Critical separation per Composer point #7 + #10 (revisit plan §3.2):** D1.C analyzes frozen DBs to identify CANDIDATE signals — it does NOT answer "does the bandit help if it learns from these signals?" That question is D1.E's. D1.C must explicitly disclaim this in the subsection to prevent Pro from over-reading the analysis.

### 0.1.2 Why this is necessary after D1.B (L0 finding)

D1.B's saturation overlay (V5 paired seeds, mean local `time_to_46` = 3221):

| L0 candidate | CGC sat | Remaining keys at mut 3221 | Rate post-local (keys/100 mut) |
|---|---:|---:|---:|
| production_log2_corrected | mut 3400 | 39 | ~1.4 |
| log4_explicit | mut 1800 | 18 | ~0.6 |
| page_class | mut 1300 | 18 | ~0.6 |
| region_only | mut 1300 | 18 | ~0.6 |

Even the BEST L0 (production_log2_corrected with byte_addr fix) produces only ~1.4 new CGC keys per 100 mutations after local saturation. Bandit_success bit goes mostly to 0 once both channels saturate. **L1 enrichment with orthogonal signals is the only remaining lever for extending the discriminating window short of a Layer-2 architectural change (scalar-reward bandit, deferred per NFP-9).**

### 0.2 Open questions Ivan must resolve before Batch 1

| ID | Question | Why it matters | Recommendation (default if Ivan doesn't pick) |
|---|---|---|---|
| **Q-C-CORPUS-A** | Cat-A analysis corpus = the same 30 DBs as D1.B Batch 1 audit (10 V1 + 10 V5 + 10 D1.A decay)? Or different mix? | Same corpus = directly comparable to D1.B findings; uses Batch 1.6 corrected memory labeling. Different mix = analysis bias risk. | **Same 30 DBs as D1.B Batch 1 audit** (10 V1 + 10 V5 + 10 D1.A decay). Reuses Composer's existing `cat_a_db_list()` helper. |
| **Q-C-CORPUS-B** | Cat-B (proof_generated/elapsed_ms) is restricted to D1.A's 10 new DBs only — confirm? Or also pull D2.A's new V5 fresh DBs if they exist by Stage 2 start? | Cat-B columns are NULL on R2 V1/V5; only D1.A populated them. D2.A's V5 fresh runs (if landed) would extend Cat-B corpus but cross-coordinate with D2 Track-β. | **D1.A's 10 DBs only** for v1 D1.C. If D2.A V5 fresh DBs land before D1.C Batch 2, optionally extend via Q-C-CORPUS-B-v2 amendment; do NOT block D1.C on D2 work. |
| **Q-C-TIER1-CANDIDATES** | Initial Tier-1 candidate list? Revisit plan §3.2 named: sliding-window `d_loc` rate, singleton-failure flag, recent-marginal-discovery rate, `f_new > 0` (free per Composer point #4). Add anything? | Defines Batch 1 implementation scope. More candidates = better shortlist but slower batches. | **Five candidates for Batch 1:** (1) `f_new_flag` (`fnew_only_reward > 0` from `reward_counterfactuals`; exact proxy for `f_new ≥ 1` per §1.4), (2) `recent_marginal_discovery_rate` (rolling sum of `discovery_binary_reward` over last W=100 pulls per §1.4 — uses DB column, no replay needed), (3) `singleton_failure_flag` (`COUNT(*) FROM failures WHERE mutation_id=?` returns exactly 1), (4) `mutation_substrategy_uniqueness` (first occurrence of `(kind, composite_substrategy_key)` where the composite key hashes the non-null kind-specific columns per §1.4), (5) `d_loc_le_2_flag` (`mutation_rewards.d_loc <= 2`; a **per-pull threshold flag**, deliberately substituted for revisit plan §3.2's "sliding-window `d_loc` rate" example — simpler, cheaper, still per-pull; sliding-window rate variant deferred to D1.C v2 if the flag underperforms in Batch 3). Each candidate documented with formula + computational cost estimate in `bug_proximity.py` docstrings. |
| **Q-C-TIER2-LIST** | Tier-2 per-campaign metric list? Revisit plan §3.2 named four: `verifier_accepted_invalid_count`, `co_failure_graph_degree`, `singleton_failure_rate`, `d_loc` distribution stats. Add anything? | Defines Batch 2 scope. D2.G consumes these. | **Eight metrics for Batch 2** (8 distinct callable functions, 8 CSV columns): the four named + (5) `pro_s8_unique_locs_with_d_loc_le_2` + (6) `pro_s8_unique_locs_with_d_glob_le_1` (Pro Report 3 §8 lists BOTH as paired metrics — `:163` — including both for §8 catalog completeness) + (7) `pro_s5_proof_generated_zero_residue_rejected_rate` (Cat-B; Pro Report 3 §5 explicit) + (8) `pro_b_wall_clock_per_normalized_discovery` (Cat-B; revisit plan `:160` explicit Cat-B metric — derives from D1.A new column `mutations.elapsed_ms`; was missing from v0.1). |
| **Q-C-SHORTLIST-DEPTH** | How many Tier-1 signals does D1.E receive in the L1 shortlist? | Too few = D1.E has limited L1 design space; too many = D1.E becomes a Tier-1-evaluation deliverable, not a re-run deliverable. | **Top 2-3 signals** (ordered by orthogonality + non-saturation), with the remaining candidates listed as "deferred" with rationale. D1.E picks 1-2 to actually wire into L1. |
| **Q-C-D2G-COORD** | Wait for D2.G to specify Tier-2 column schema, or define our own and let D2.G adapt? | Avoid Track-α / Track-β churn; commit to a schema early. | **Define our own schema in Batch 2** with explicit Pro Report 3 §5/§8 mapping in the column names (e.g., `pro_s5_verifier_accepted_invalid_count`). D2.G adapts. Cross-link in `IV_POS_8_D2_PLAN.md` D2.G section once D1.C Batch 2 lands. |
| **Q-C-COFAILURE-WINDOW** | `co_failure_graph_degree` window: per-mutation node-degree on a running graph, or per-campaign aggregate? | Pro §5 describes co-failure graph as a campaign artifact (degree, density). Per-mutation degree would be Tier-1; per-campaign degree distribution is Tier-2. | **Tier-2 only** in v1 D1.C (per-campaign mean/median/p95 of constraint_loc node degree in the co-failure graph). Per-mutation variant (would require running-graph update per pull, expensive) is deferred to D1.C v2 or D2.G. |

### 0.3 Recommended Ivan-greenlight on Q-C questions

| Q | Recommended answer |
|---|---|
| Q-C-CORPUS-A | Same 30 DBs as D1.B Batch 1 audit (uses `cat_a_db_list()`) |
| Q-C-CORPUS-B | D1.A's 10 DBs only; optionally extend via Q-C-CORPUS-B-v2 if D2.A V5 fresh available |
| Q-C-TIER1-CANDIDATES | 5 candidates: `f_new_flag` (via `fnew_only_reward>0`), `recent_marginal_discovery_rate` (via `discovery_binary_reward` rolling sum), `singleton_failure_flag`, `mutation_substrategy_uniqueness` (composite kind-key), `d_loc_le_2_flag` (substituted for sliding-window d_loc rate, noted explicitly) |
| Q-C-TIER2-LIST | 8 metrics: Pro's 4 named + `unique_locs_with_d_loc_le_2` + `unique_locs_with_d_glob_le_1` (Pro §8 paired) + `proof_generated_zero_residue_rejected_rate` (Cat-B) + `wall_clock_per_normalized_discovery` (Cat-B; missing from v0.1) |
| Q-C-SHORTLIST-DEPTH | Top 2-3 with deferred list |
| Q-C-D2G-COORD | Define schema in Batch 2 with Pro-§-tagged column names; D2.G adapts |
| Q-C-COFAILURE-WINDOW | Tier-2 only (per-campaign aggregate) in v1 |

If Ivan greenlights the recommended set above, Batch 1 proceeds without delay. If Ivan wants different answers, the batches likely affected are Batch 1 (Q-C-TIER1-CANDIDATES) and Batch 2 (Q-C-TIER2-LIST, Q-C-D2G-COORD).

---

## 1. Existing data + new module locations

### 1.1 Data sources (per-DB)

All tables are in the per-DB SQLite file. Verified columns against `a4/standalone/coverage_db.py` schema definitions.

| Table | Key columns | Used for | Available in |
|---|---|---|---|
| `mutations` | `id`, `kind`, `zone`, `step`, `mutation_major`, `mutation_minor`, `seed` | Per-pull arm context | All DBs |
| `failures` | `mutation_id`, `constraint_loc`, `mutation_major`, `mutation_minor` | Per-pull constraint_loc set (drives `d_loc`, singleton, co-failure graph) | All DBs |
| `coverage` | `constraint_loc`, `first_hit_mutation_id` | Legacy local discoveries (drives K) | All DBs |
| `local_coverage_v2` | `constraint_loc`, `mutation_major`, `mutation_minor`, `first_hit_mutation_id` | Enriched local contexts (drives `l_new`) | All DBs |
| `compressed_global_coverage` | `family`, `ctx_key`, `ctx_json`, `first_hit_mutation_id` | CGC first-hits | All DBs; **buggy-pre-fix unless Batch 1.6 replay applied** (see NFP-10) |
| `mutation_rewards` | `mutation_id`, `d_loc`, `d_glob`, `reward` (+ legacy `T_new`, `F_new`, `delta_T`, `delta_F`, `n_fail`, `r_rep`, etc. per `coverage_db.py:229-251`) | Per-pull d_loc / d_glob + LEGACY reward terms. **CAUTION: `T_new`, `F_new`, `delta_T`, `delta_F` are LEGACY reward-function floats/counters; they are NOT v2 novelty integers `l_new`/`f_new`** (different function — `compute_reward_v2_components` per `reward_v2.py:133`). See §1.4 for the channel-reconstruction strategy. | All DBs |
| `reward_counterfactuals` | `mutation_id`, `current_reward`, `no_qloc_reward`, `fnew_only_reward`, `discovery_binary_reward`, `compressed_global_reward` (verified `coverage_db.py:340-348`) | Per-pull reward variants. `discovery_binary_reward = compute_bandit_success(l_new, g_new, s_new)` = OR of l+g+s (the bandit success bit, NOT individual channels). `fnew_only_reward = 0.30 * sat(f_new, 1.0)` — sign-test gives `f_new ≥ 1` exactly (see §1.4). | All DBs |
| `bandit_decisions` | `mutation_id`, `selected_arm`, `mode`, `score`, `extra_json` | Per-pull bandit decisions | V5+ only (V1 has empty table) |
| `global_failures` | `mutation_id`, `family`, `address` | Raw Hook 3 broken addresses (dict-string per `coverage_db.py:165-173`) | All DBs |
| `hook3_raw` | `mutation_id`, `raw_json`, `compressed_ctx_json` | Raw Hook 3 payload per pull | All DBs |
| `mutation_substrategy` | `mutation_id`, `opcode`, `rd`, `rs1`, `rs2`, `funct3`, `funct7`, `imm`, `byte_lane`, `bit_mask`, `value_class` (verified `coverage_db.py:356-369`) | Per-pull substrategy variant. All fields nullable; each `kind` populates only its own. **No `substrategy_name` column** — derive a composite key from non-null kind-specific columns (see §1.4). | All DBs (confirmed via R2 V5 s1234 audit: 6000 rows present) |
| **NEW columns on `mutations` table** (D1.A schema, added via `ALTER TABLE` per `coverage_db.py:119-121`) | `mutations.proof_generated`, `mutations.proof_verify_failed`, `mutations.elapsed_ms` | Cat-B Tier-2 metrics | D1.A's 10 new DBs only; NULL on R2 V1/V5 |

### 1.2 New module — `a4/runs/iv_pos_7/analysis/bug_proximity.py`

Lives in the iv_pos_7 analysis tree (matches D1.B convention — `cgc_variants.py` is there). **Does NOT modify production code.** Imports production helpers for consistency.

**Module-level constants:**

```python
TIER1_SIGNALS = (
    "f_new_flag",                       # fnew_only_reward > 0; exact proxy for f_new >= 1 (§1.4)
    "recent_marginal_discovery_rate",   # rolling mean of reward_counterfactuals.discovery_binary_reward
                                        # over W=100 pulls; "discovery momentum" / smoothed
                                        # bandit-success rate (NOT integer rolling sum of l+g+s,
                                        # which would require Option C replay per §1.4). EXPECTED
                                        # to correlate highly with discovery_binary_reward by
                                        # construction — see §1.2 docstring + risks §3.
    "singleton_failure_flag",           # |failures for this mid| == 1
    "mutation_substrategy_uniqueness",  # first time this (kind, composite_key) fires;
                                        # composite_key per §1.4 (no substrategy_name column exists)
    "d_loc_le_2_flag",                  # d_loc <= 2 (Pro Report 3 §8); per-pull threshold flag
                                        # substituted for revisit plan §3.2's "sliding-window
                                        # d_loc rate" example — see Q-C-TIER1-CANDIDATES rationale
)

TIER2_METRICS = (
    "pro_s5_verifier_accepted_invalid_count",            # Pro §5 / Cat-A
    "pro_s5_co_failure_graph_degree_p95",                # Pro §5 / Cat-A
    "pro_s5_singleton_failure_rate",                     # Pro §5 / Cat-A
    "pro_s5_d_loc_p95",                                  # Pro §5 / §8 / Cat-A
    "pro_s8_unique_locs_with_d_loc_le_2",                # Pro §8 / Cat-A
    "pro_s8_unique_locs_with_d_glob_le_1",               # Pro §8 paired / Cat-A (v0.3 add)
    "pro_s5_proof_generated_zero_residue_rejected_rate", # Pro §5 / Cat-B
    "pro_b_wall_clock_per_normalized_discovery",         # Revisit plan :160 / Cat-B (v0.3 add)
)

CORRELATION_THRESHOLD = 0.4  # Pearson |r| above this = NOT orthogonal to existing channel
NON_SATURATION_WINDOW = (3000, 6000)  # mut range where Tier-1 must still fire on >5% of pulls
NON_SATURATION_MIN_FIRE_RATE = 0.05
ROLLING_DISCOVERY_WINDOW = 100  # pulls
```

**Module-level functions (Batch 1 scope) — corrected APIs per §1.4:**

```python
# Per-mutation signal extractors (Tier-1)

def f_new_flag(fnew_only_reward: float) -> int:
    """Cat-A. Exact proxy for f_new >= 1. See §1.4.

    fnew_only_reward = 0.30 * sat(f_new, 1.0); fnew_only_reward > 0 iff f_new >= 1.
    Cost: O(1) per pull. Source: reward_counterfactuals.fnew_only_reward.
    """

def recent_marginal_discovery_rate(
    rolling_discovery_bits: list[int],
    window: int = ROLLING_DISCOVERY_WINDOW,
) -> float:
    """Cat-A. Rolling fraction of pulls in [mid-W, mid) that discovered something.

    Defined on reward_counterfactuals.discovery_binary_reward (=
    compute_bandit_success(l_new, g_new, s_new), the OR of l+g+s) per §1.4
    Option A. NOT the integer sum of l_new+g_new+s_new (which would require
    Option C replay).

    SEMANTICS (Composer audit pushback B): this is a 'discovery momentum'
    or 'smoothed bandit-success rate' signal, NOT a strong-orthogonality
    candidate. A rolling mean of a binary signal correlates highly with
    its instantaneous bit BY CONSTRUCTION (Pearson r tends to be O(0.4-0.7)
    on stationary stretches). We include it because (i) it may still
    discriminate the post-saturation regime if discovery_binary_reward goes
    from 'fires every pull' to 'fires occasionally' as the campaign saturates
    (timing detector for the saturation boundary itself), and (ii) it could
    be useful as a continuous-valued signal in a future scalar bandit
    (NFP-9) even if it fails the binary ortho gate in §1.3.3. The shortlist
    rationale template in Batch 3 explicitly handles 'rejected for ortho
    failure but kept as scalar-bandit candidate' as a distinct deferred
    category.

    Returns float in [0, 1]. Cost: O(1) amortized per pull with a deque.
    """

def singleton_failure_flag(failures_count_for_mid: int) -> int:
    """Cat-A. 1 iff exactly one constraint_loc broke this pull.

    Source: SELECT COUNT(*) FROM failures WHERE mutation_id=?;
    Cost: O(1) with pre-grouped index. Pro Report 3 §5.
    """

def mutation_substrategy_uniqueness(
    kind: str,
    substrategy_row: tuple,   # (opcode, rd, rs1, rs2, funct3, funct7, imm,
                              #  byte_lane, bit_mask, value_class) per
                              #  coverage_db.py:356-369; non-null subset per kind
    seen_composite_keys: set[tuple[str, tuple]],
) -> int:
    """Cat-A. 1 iff this is the first occurrence of (kind, composite_key).

    composite_key = tuple of non-null kind-specific column values. Caller
    constructs this from the row tuple by filtering NULLs (kind-specific:
    INSTR_WORD_MOD_SUR uses opcode+funct3+funct7+rd+rs1+rs2+imm; MEM_VAL_MOD
    uses byte_lane+bit_mask+value_class; etc.). Helper:
      composite_key_for_kind(kind, row) -> tuple
    Cost: O(1) per pull (set membership).
    """

def d_loc_le_2_flag(d_loc: int) -> int:
    """Cat-A. 1 iff mutation_rewards.d_loc <= 2 (Pro Report 3 §8).

    Substituted for revisit plan §3.2's 'sliding-window d_loc rate' (per-pull
    threshold flag is simpler/cheaper; sliding-window variant deferred to
    D1.C v2 if Batch 3 cross-correlation shows the flag underperforms).
    """

# Per-campaign signal aggregators (Tier-2, Batch 2 scope)

def pro_s5_verifier_accepted_invalid_count(conn: sqlite3.Connection) -> int:
    """Cat-A. ALIGNED with IV_POS_8_D1_A_SPEC.md:539 locked SQL:
      SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0
    Pro §5 framing: 'mutations where verifier said yes but failures existed.'
    Note: Pro Report 3 §5's exact wording is
      `proof_generated && d_loc=0 && d_glob=0 && rejected`
    which is a DIFFERENT (Cat-B-flavored) metric describing 'accepted-looking
    proofs that should have been rejected.' D1.A spec already locked the
    Cat-A variant above; we ship that one. If Pro wants the §5-literal Cat-B
    variant, add as `cat_b_pro_s5_literal_accepted_invalid_count` in a later
    revision (requires `proof_generated` column; D1.A 10 DBs only).
    """

def pro_s5_co_failure_graph_degree_distribution(conn: sqlite3.Connection) -> dict: ...
def pro_s5_singleton_failure_rate(conn: sqlite3.Connection) -> float: ...
def pro_s5_d_loc_distribution(conn: sqlite3.Connection) -> dict: ...
def pro_s8_unique_locs_with_d_loc_le_2(conn: sqlite3.Connection) -> int: ...
def pro_s8_unique_locs_with_d_glob_le_1(conn: sqlite3.Connection) -> int: ...
def pro_s5_proof_generated_zero_residue_rejected_rate(
    conn: sqlite3.Connection,
) -> Optional[float]:
    """Cat-B. Returns None if `proof_generated` column is NULL (R2 DBs)."""

def pro_b_wall_clock_per_normalized_discovery(
    conn: sqlite3.Connection,
) -> Optional[float]:
    """Cat-B. revisit plan :160 explicit. mean elapsed_ms per normalized
    discovery (local_context_final per campaign). Returns None if
    `elapsed_ms` column is NULL.
    """

# Cross-correlation analysis (Batch 3 scope)
def compute_signal_correlation_matrix(
    signals_per_mutation: dict[str, list[int | float]],
    existing_channels: dict[str, list[int]],
) -> dict[str, dict[str, float]]:
    """Pearson r matrix. Note: f_new_flag self-correlation against `f_new`
    channel is trivially 1.0; exclude that pair from the published matrix
    (document in comments).
    """

def compute_fire_rate_over_window(
    signal_per_mutation: list[int | float],
    window: tuple[int, int],
) -> float: ...
```

### 1.3 Signal-construction conventions

#### 1.3.1 Tier-1 signal "fires" semantics

A Tier-1 signal is a **binary or thresholded-continuous per-pull value**. For the L1 OR-channel use case:

```python
# What D1.E L1 might look like (NOT in scope for D1.C; informational only):
bandit_success_L1 = 1 if (
    l_new + g_new + s_new
    + (1 if any_selected_tier1_signal_fires else 0)
) > 0 else 0
```

For analysis purposes, D1.C measures `signal_fire_rate` per pull range:

```
fire_rate(signal, [a, b]) = |{mid in [a, b) where signal(mid) == 1}| / (b - a)
```

#### 1.3.2 Continuous signals → fire thresholds

Some Tier-1 candidates are continuous (`recent_marginal_discovery_rate` is a float). For fire-rate purposes:

```python
def discretize_continuous_signal(value: float, threshold: float) -> int:
    return 1 if value >= threshold else 0
```

The threshold itself is a hyperparameter; D1.C reports multiple thresholds (e.g., 25th/50th/75th percentile of the signal distribution) and lets D1.E pick.

#### 1.3.3 Orthogonality criterion (Tier-1 selection)

For each Tier-1 signal `S`, compute Pearson correlation against each existing channel `c` from the **§1.4 Option A channel set** `c ∈ {discovery_binary_reward, f_new_flag}`:

```python
r_S_c = pearsonr(per_pull_S, per_pull_c)
```

**Orthogonality criterion:** `max_c |r_S_c| < CORRELATION_THRESHOLD (=0.4)` across paired V5 seeds.

Rationale: `discovery_binary_reward` IS the bandit's actual learning signal (`compute_bandit_success(l_new, g_new, s_new)`); if a candidate Tier-1 signal fires mostly when this bit is already on, OR-ing it into the L1 reward adds little new information. `f_new_flag` is included as a separate channel because it is computed but NOT in today's `bandit_success`; adding it is the cheapest L1 extension and Tier-1 candidates should be orthogonal to it too.

If conditional Batch 1.5 (Option C replay) is triggered per §1.4, the channel set expands to `{l_new, g_new, s_new, f_new, discovery_binary_reward}` and the orthogonality matrix is re-computed; `discovery_binary_reward` becomes a derived channel (= OR of l+g+s) reported for cross-comparison rather than primary gate.

**Caveat:** Per-pull correlation can miss "fires mostly in disjoint regions" patterns. Supplement with **disjoint-fire fraction**:

```python
disjoint_fire_rate(S, c) = |{mid: S(mid)=1 AND c(mid)=0}| / |{mid: S(mid)=1}|
```

A signal can have `r > 0.4` but still high disjoint_fire (fires alongside `c` often AND fires alone often). Report both metrics in the shortlist.

**Expected pattern for `recent_marginal_discovery_rate`** (Composer audit pushback B): a rolling mean of `discovery_binary_reward` correlates with the instantaneous bit by construction. This candidate is expected to **fail** the binary ortho gate. The shortlist rationale in Batch 3 task 3 explicitly distinguishes "rejected for ortho failure (NOT a good L1 OR-channel)" from "rejected for ortho failure but kept as scalar-bandit candidate per NFP-9 deferred L2 wiring."

#### 1.3.4 Non-saturation criterion (Tier-1 selection)

For each Tier-1 signal `S`, compute `fire_rate(S, [3000, 6000))` across paired V5 seeds.

**Non-saturation criterion:** `mean fire_rate(S, [3000, 6000)) > 0.05` (fires on >5% of post-local pulls).

Rationale: signals that fire heavily early-campaign but die by mut 3000 do NOT solve D1.A's adaptive-TS-no-signal problem. We specifically need signals that keep firing past local saturation.

### 1.3.5 Cat-A vs Cat-B labeling (Pro disclosure clarity)

Every Tier-1 and Tier-2 metric must be tagged in its docstring + the metrics CSV:

```python
# Cat-A: derivable from existing schema (R2 V1, R2 V5, D1.A)
# Cat-B: requires D1.A's new columns (NULL on R2)
```

CSV column convention: `cat_a_` or `cat_b_` prefix on the metric name. This lets D2.G and Pro instantly see which corpus a metric is grounded in.

### 1.4 Channel-reconstruction strategy (Composer audit fix)

**Problem:** §1.3.3 orthogonality requires per-pull values of the existing reward channels `l_new`, `g_new`, `s_new`, `f_new`. These integers are **NOT persisted to SQLite**:

- `mutation_rewards` (schema `coverage_db.py:229-251`) has LEGACY reward terms (`T_new`, `F_new`, `delta_T`, `delta_F`, `n_fail`, `r_rep`, `d_loc`, `d_glob`, `d_ext`) — these are the OLD reward function's outputs, NOT the v2 novelty counts.
- `reward_counterfactuals` (schema `coverage_db.py:340-348`) has only floats/binary: `current_reward`, `no_qloc_reward`, `fnew_only_reward`, `discovery_binary_reward`, `compressed_global_reward`. Per `reward_v2.py:60-62`, `discovery_binary_reward = compute_bandit_success(l_new, g_new, s_new) = 1 if (l_new+g_new+s_new)>0 else 0` — the OR, not individual channels.

**Three reconstruction options:**

| Option | What | Cost | Information loss |
|---|---|---|---|
| **A — direct read** | Use `discovery_binary_reward` as a single "did anything fire" channel (already in DB) | O(1) per pull, no replay | Cannot distinguish l_new vs g_new vs s_new; loses integer counts |
| **B — algebraic inversion** | Solve for integers from `current_reward + fnew_only_reward + compressed_global_reward` | O(1) per pull | **Underdetermined** — multiple integer tuples give same float reward; not uniquely recoverable |
| **C — full replay** | Walk mutations in order; for each, read `failures` + `hook3_raw` + cumulative seen-sets; recompute `compute_reward_v2_components` exactly | O(N) per DB with O(failures + hook3_raw_payload) per pull | None |

**D1.C decision (locked v0.2, reaffirmed v0.3):** Use **Option A for Batch 1 + Batch 3 correlation analysis**; reserve Option C as a Batch 1.5 follow-up only if Option A's orthogonality results are inconclusive (specifically: if Batch 3 finds all 4 non-trivial Tier-1 signals — excluding `f_new_flag` which is its own channel — have `|r| > 0.4` against `discovery_binary_reward` AND disjoint_fire_rate < 0.3, then trigger Batch 1.5).

**Rationale:**
1. The L1 OR-channel use case in D1.E only cares about the **bandit_success bit**, not individual channel integers. So `discovery_binary_reward` is the appropriate single "existing-channel" baseline to OR new signals against.
2. `f_new_flag` is **separately recoverable as a per-pull binary** from `fnew_only_reward > 0` — this is exact (proof: `fnew_only_reward = 0.30 * sat(f_new, 1.0) = 0.30 * (1 - exp(-f_new))`; equals 0 iff `f_new = 0`). No replay needed for `f_new_flag`.
3. Option C (full replay) is feasible but expensive and adds Batch 1 scope. We defer it because:
   - For Tier-1 selection (orthogonality vs the bandit's actual learning signal), Option A IS the bandit's learning signal.
   - If Batch 3 finds all Tier-1 candidates have `corr > 0.4` against `discovery_binary_reward`, Option C may still rescue some signals that fire on multi-discovery pulls (where `discovery_binary_reward=1` but specifically `l_new=0, g_new=0, s_new=1`). Add Batch 1.5 replay only at that point.

**Batch 1 correlation matrix (revised structure):**

Rows = 5 Tier-1 candidate signals. Columns = 2 existing channels per §1.4 Option A.

```
                    | discovery_binary_reward | f_new_flag |   <-- columns: existing channels
--------------------+-------------------------+------------+
f_new_flag          |          rho            | 1.000 (sel)|   <-- self-cell at (f_new_flag, f_new_flag) is trivially 1.0; EXCLUDE from published matrix
recent_marginal_d_r |          rho            |    rho     |   <-- target: |rho| < CORRELATION_THRESHOLD (0.4);
                    |        (expected        |            |       except recent_marginal_discovery_rate is EXPECTED
                    |         high, see       |            |       to fail vs discovery_binary_reward (see §1.3.3)
                    |         §1.3.3)         |            |
singleton_failure   |          rho            |    rho     |
substrategy_uniq    |          rho            |    rho     |
d_loc_le_2          |          rho            |    rho     |
```

This is a 5×2 matrix = 10 cells, one trivial (the `f_new_flag` × `f_new_flag` self-cell). Batch 3 publishes 9 non-trivial cells per seed × 5 paired V5 seeds = **45 rows** in `d1c_correlation_matrix.csv` (matches §2.3 task 1 row count).

If conditional Batch 1.5 (Option C replay per §1.4) is added, the matrix expands to 5×5 with columns `{l_new, g_new, s_new, f_new, discovery_binary_reward}`; `discovery_binary_reward` is listed as a derived channel (= OR of l+g+s) for cross-comparison. After excluding the f_new_flag self-cell, that's 24 non-trivial cells per seed × 5 seeds = 120 rows in the expanded matrix CSV.

**`mutation_substrategy_uniqueness` composite-key construction:**

The table (`coverage_db.py:356-369`) has 10 nullable columns. Different kinds populate different subsets. The composite key is a tuple of (kind-name, non-null column values in fixed order).

Helper signature:

```python
def composite_substrategy_key(kind: str, row: dict) -> tuple:
    """Return a hashable composite key from non-null kind-specific fields.

    Per coverage_db.py:351-354 comment: 'For INSTR_WORD_MOD_SUR this captures
    funct3/funct7/etc.; for MEM_VAL_MOD: byte_lane; etc. All fields nullable
    since each kind populates only its own.'

    Empirical kind-to-columns mapping must be derived from a Batch 1 audit:
    for each kind in [INSTR_WORD_MOD_SUR, INSTR_TYPE_MOD, MEM_VAL_MOD, ...],
    discover which subset of {opcode, rd, rs1, rs2, funct3, funct7, imm,
    byte_lane, bit_mask, value_class} is non-null on real DBs. Persist the
    mapping as KIND_TO_SUBSTRATEGY_FIELDS at module level.
    """
```

Batch 1 includes a sub-task to audit kind→non-null-fields mapping on the 30-DB corpus and persist `KIND_TO_SUBSTRATEGY_FIELDS` as a module constant.

---

## 2. Batched implementation plan

### 2.1 Batch 1 — Foundation + Tier-1 per-mutation signal extractors

**Goal:** Ship `bug_proximity.py` Tier-1 functions + unit tests + Batch 1 data audit on the 30-DB corpus + sanity histograms. NO Tier-2 yet; NO cross-correlation yet. Composer review checkpoint before Batch 2.

**Tasks:**

1. **Create `a4/runs/iv_pos_7/analysis/bug_proximity.py`** with module-level constants from §1.2 and the 5 Tier-1 signal extractors per the **corrected APIs in §1.2 / §1.4**. Each function has:
   - Cat-A / Cat-B docstring tag
   - Pro Report 3 §X reference where applicable
   - Type hints + return type
   - Computational cost note (cheap / moderate / expensive)
   - Source-table reference (which DB column(s) the signal reads from)
2. **Add the channel-reconstruction helper per §1.4 Option A:**
   ```python
   def extract_existing_channels_per_db(db_path: Path) -> dict[str, list[int]]:
       """Return per-mutation existing-channel signals (length N_mutations).

       Output keys:
         discovery_binary_reward  -> int 0/1   (from reward_counterfactuals)
         f_new_flag               -> int 0/1   (derived: fnew_only_reward > 0)

       Replay (Option C per §1.4) is deferred to Batch 1.5 if needed.
       """
   ```
3. **Audit `mutation_substrategy` kind→non-null-fields mapping** on the 30-DB corpus and persist as a module constant:
   ```python
   KIND_TO_SUBSTRATEGY_FIELDS: dict[str, tuple[str, ...]] = {
       "INSTR_WORD_MOD_SUR": ("opcode", "funct3", "funct7", "rd", "rs1", "rs2", "imm"),
       # ... discovered empirically by Batch 1 audit script
   }
   ```
   Write `a4/runs/iv_pos_8/d1c/d1c_substrategy_field_audit.csv` as the evidence artifact (kind × column × non-null-count across 30 DBs).
4. **Add the Tier-1 batch-extraction helper:**
   ```python
   def extract_tier1_signals_per_db(db_path: Path) -> dict[str, list[int | float]]:
       """Return per-mutation Tier-1 signals for the DB (length N_mutations per signal)."""
   ```
   Reads `mutations`, `failures`, `mutation_rewards`, `reward_counterfactuals`, `mutation_substrategy` tables. Returns dict of signal_name → list of per-pull values.
5. **Write unit tests** in `a4/runs/iv_pos_7/analysis/test_bug_proximity.py`:
   - Each Tier-1 extractor on synthetic inputs (test_*_edge_cases, test_*_typical, test_*_boundary)
   - `recent_marginal_discovery_rate` correctly rolls W=100 window over `discovery_binary_reward` (test at mut 0, mut 50, mut 100, mut 6000)
   - `mutation_substrategy_uniqueness` correctly fires only on FIRST occurrence per (kind, composite_key); test with synthetic INSTR_WORD_MOD_SUR + MEM_VAL_MOD rows (different non-null subsets) to confirm composite-key construction handles kind-specific NULL patterns
   - `d_loc_le_2_flag` boundary at d_loc=2 (fires) vs d_loc=3 (doesn't)
   - `f_new_flag` correctly derives from `fnew_only_reward > 0` per §1.4 (test: fnew_only_reward=0 → 0; fnew_only_reward=0.0001 → 1; fnew_only_reward=0.1896 → 1)
   - Integration: extract signals from 1 real DB; assert lengths == COUNT(*) from mutations; assert no exceptions
6. **Batch 1 audit script** `a4/runs/iv_pos_8/d1c/analysis/build_batch1_audit.py`:
   - Discover 30 Cat-A DBs via existing `cat_a_db_list()` helper
   - For each DB, extract Tier-1 signals + existing channels
   - Output `a4/runs/iv_pos_8/d1c/d1c_batch1_tier1_audit.csv` with columns: corpus, variant, seed, signal_name, fire_count, fire_rate_full, fire_rate_post_local (3000-6000), median_value (for continuous signals)
   - Sanity assert: every DB has N rows per signal where N = `SELECT COUNT(*) FROM mutations`; no NaN in fire_rate fields
7. **Batch 1 sanity plots** `a4/runs/iv_pos_8/d1c/plots/`:
   - Per-signal histogram of `fire_rate_full` across 30 DBs
   - Per-signal `fire_rate_post_local` for paired V5 seeds (5 bars per signal)

**Exit criteria:**

- `bug_proximity.py` with 5 Tier-1 functions + `f_new_flag` exact-proxy derivation + `recent_marginal_discovery_rate` defined on `discovery_binary_reward` per §1.4 + `extract_existing_channels_per_db` helper + `KIND_TO_SUBSTRATEGY_FIELDS` constant
- `test_bug_proximity.py` with ≥15 tests passing
- `d1c_substrategy_field_audit.csv` (kind × column × non-null counts)
- `d1c_batch1_tier1_audit.csv` with 30 DBs × 5 signals = 150 rows
- Plots written
- Batch 1 Composer report at `a4/docs/cloud2/composer/D1C_BATCH1_REPORT.md`
- Composer + Opus review pass

### 2.2 Batch 2 — Tier-2 per-campaign metrics + D2.G schema lock

**Goal:** Ship Cat-A Tier-2 metrics on all 30 DBs + Cat-B metrics on 10 D1.A DBs + lock the schema for D2.G consumption.

**Tasks:**

1. **Add Tier-2 functions to `bug_proximity.py`** (8 metrics per §1.2 `TIER2_METRICS` constant; 8 distinct callable functions, 8 CSV columns):
   - `pro_s5_verifier_accepted_invalid_count(conn)` — **ALIGNED with `IV_POS_8_D1_A_SPEC.md:539` locked SQL**: `SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0`. Pro Report 3 §5 framing. The §5-literal Cat-B variant (`proof_generated && d_loc=0 && d_glob=0 && rejected`) is a different metric describing 'accepted-looking proofs that should have been rejected'; if Pro wants both, add as `cat_b_pro_s5_literal_accepted_invalid_count` in a later revision (requires `mutations.proof_generated` + `proof_verify_failed` columns; D1.A 10 DBs only).
   - `pro_s5_co_failure_graph_degree_distribution(conn)` — build undirected graph where nodes = distinct `constraint_loc`, edges = pairs that co-failed in any single mutation. Return `{mean: ..., median: ..., p95: ..., p99: ..., density: ...}`.
   - `pro_s5_singleton_failure_rate(conn)` — fraction of mutations where exactly 1 constraint_loc broke.
   - `pro_s5_d_loc_distribution(conn)` — `{mean, median, p95, p99}` of `mutation_rewards.d_loc`.
   - `pro_s8_unique_locs_with_d_loc_le_2(conn)` — distinct `constraint_loc` that ever appeared in a mutation with `mutation_rewards.d_loc ≤ 2`.
   - `pro_s8_unique_locs_with_d_glob_le_1(conn)` — distinct `constraint_loc` that ever appeared in a mutation with `mutation_rewards.d_glob ≤ 1`. **Pro Report 3 §8 lists this paired with the d_loc ≤ 2 metric (verified `ProG_Report_3.md:163`); included for §8 catalog completeness.**
   - `pro_s5_proof_generated_zero_residue_rejected_rate(conn)` — Cat-B; fraction of mutations where `mutations.proof_generated = 1` AND family_residues all zero (heuristic: `mutation_rewards.d_glob = 0`) AND `mutations.proof_verify_failed = 1`. Returns None if `proof_generated` column is NULL (R2 DBs).
   - **`pro_b_wall_clock_per_normalized_discovery(conn)`** — **NEW in v0.2 per Composer audit + revisit plan `:160`**. Cat-B. Returns `mean(mutations.elapsed_ms) / local_context_final` (mean wall-clock per normalized local discovery for this campaign). Returns None if `elapsed_ms` column is NULL.
2. **Batch 2 metrics script** `a4/runs/iv_pos_8/d1c/analysis/build_d1c_artifacts.py`:
   - For each of 30 DBs, compute all 8 Tier-2 metrics
   - Output `d1c_metrics_table.csv` with explicit column tagging: `cat_a_*` / `cat_b_*`, Pro-§-mapping in header comment row
   - Output `d1c_paired_tests.csv` — paired t-tests on the **15-row decay-paired subset only** (5 V5-static-paired + 5 decayexp + 5 decayepoch, all sharing seeds 1234-1238 per D1.A pairing). Per-campaign Tier-2 metrics are only meaningfully paired where seed-pairing exists; the unpaired V5-static rows (1239-1243) provide only marginal mean/variance comparison, not a paired test — listed separately as `d1c_unpaired_means.csv`. (v0.1's "20-row 5+5+5+5 unpaired" framing was confusing per Composer audit.)
3. **Schema lock for D2.G:** Write `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md`:
   - Column name + dtype + Pro-§ reference
   - Cat-A vs Cat-B labeling
   - Cross-link to `IV_POS_8_D2_PLAN.md` D2.G section ("D2.G's `build_d2_artifacts.py` consumes columns prefixed `cat_a_pro_s*`")
4. **Tier-2 unit tests** in `test_bug_proximity.py`:
   - Each Tier-2 metric on a synthetic mini-DB
   - Co-failure graph correctly handles disconnected components, self-loops (none expected), empty graph
   - Cat-B metrics return None when columns NULL
   - `pro_s5_verifier_accepted_invalid_count` matches the exact SQL from `IV_POS_8_D1_A_SPEC.md:539` (cite the file:line in the test docstring for traceability)
5. **Sanity invariants:**
   - For every DB: `pro_s5_singleton_failure_rate ∈ [0, 1]`
   - For every DB: `pro_s5_d_loc_p95 ≥ pro_s5_d_loc_median`
   - For every DB: `pro_s8_unique_locs_with_d_loc_le_2 ≤ local_context_final` (subset of total locs)
   - For every DB: `pro_s8_unique_locs_with_d_glob_le_1 ≤ local_context_final`
   - For Cat-B metrics: returns None on R2 DBs, returns float on D1.A DBs

**Exit criteria:**

- 8 Tier-2 functions implemented + ≥14 new tests (≥1 unit test per function + sanity invariants)
- `d1c_metrics_table.csv` (30 rows × 8 metric columns + provenance)
- `d1c_paired_tests.csv` (15-row paired-decay subset)
- `d1c_unpaired_means.csv` (V5-static unpaired rows 1239-1243)
- `d1c_tier2_schema.md` (D2.G coordination artifact)
- All sanity invariants pass
- Batch 2 Composer report
- Composer + Opus review pass before Batch 3

### 2.3 Batch 3 — Cross-correlation + Tier-1 shortlist + D1.E hand-off

**Goal:** Run orthogonality + non-saturation analysis on Tier-1 signals; produce Tier-1 shortlist; write D1.E L1 hand-off note.

**Tasks:**

1. **Cross-correlation analysis** `build_d1c_correlation_analysis.py`:
   - For each of 5 paired V5 seeds (1234-1238):
     - Extract per-pull existing channels via §1.4 Option A: `discovery_binary_reward` + `f_new_flag` (derived from `fnew_only_reward > 0`)
     - Extract per-pull Tier-1 signals (from Batch 1 helper)
     - Compute Pearson correlation matrix: 5 Tier-1 signals × 2 existing channels (`discovery_binary_reward`, `f_new_flag`), excluding the trivial `f_new_flag` self-cell
     - Compute disjoint-fire fraction matrix (same shape)
   - Output `d1c_correlation_matrix.csv`: 5 signals × 2 channels = 10 cells/seed (minus 1 trivial = 9 rows/seed) × 5 seeds = 45 rows; columns: seed, signal_name, channel_name, pearson_r, disjoint_fire_rate
   - If Batch 3 finds all Tier-1 candidates have `|r| > 0.4` against `discovery_binary_reward`, trigger **Batch 1.5 Option C replay** per §1.4 to expand the channel set to `{l_new, g_new, s_new, f_new}` separately and re-test orthogonality. Document this as a conditional follow-up, not unconditional.
2. **Non-saturation analysis:**
   - For each Tier-1 signal, compute `fire_rate([3000, 6000))` across 5 paired V5 seeds
   - Output `d1c_non_saturation.csv`: signal_name × seed × fire_rate_full × fire_rate_post_local × passes_5pct_gate (boolean)
3. **Shortlist composition** `d1c_signal_shortlist.md` — three explicit buckets per §1.3.3:
   - Apply selection criteria from §1.3 (orthogonality + non-saturation)
   - Rank Tier-1 signals by (1 / max_correlation) × fire_rate_post_local — higher is better
   - **Bucket A — RECOMMENDED for D1.E L1 (top 2-3):** passes both orthogonality (`max_c |r| < 0.4` against §1.4 channels) AND non-saturation (fire-rate in [3000, 6000) > 5%) gates
   - **Bucket B — DEFERRED, NOT a good L1 OR-channel:** fails orthogonality (high `r` against `discovery_binary_reward` or `f_new_flag`) without offering scalar-bandit value. Example expected: signals that fire mostly redundantly with `discovery_binary_reward` AND don't provide useful continuous magnitude (e.g., a saturated binary flag)
   - **Bucket C — DEFERRED FOR ORTHO FAILURE BUT KEPT AS NFP-9 SCALAR-BANDIT CANDIDATE:** fails orthogonality gate but provides continuous-valued signal that could be useful in a future scalar-reward bandit (NFP-9 deferred L2 wiring). Example expected: `recent_marginal_discovery_rate` per §1.3.3 expected pattern — high `r` against `discovery_binary_reward` by construction, but the continuous magnitude (0.0-1.0 vs binary 0/1) preserves richer information that a scalar bandit could use even though a binary OR cannot
   - For each Bucket-A signal: include "expected L1 effect" — what disjoint-fire fraction means for `bandit_success` bit-rate post-local
   - For each Bucket-C signal: include "scalar-bandit motivation" — what continuous-magnitude information would be lost if D1.E only does binary OR
4. **D1.E L1 hand-off note** `d1e_handoff_L1_signals.md`:
   - Top 2-3 signals + selection rationale
   - Per-seed disjoint-fire rates (= "how much additional bandit_success bit-firing would this give post-local")
   - Plain statement: "**D1.C does NOT validate that the bandit benefits from learning on these signals** — that is D1.E's forward-run job. D1.C's job is to find candidates with empirically promising properties (orthogonal + non-saturating)."
   - **Cross-reference D1.B's L1 open-question framing** at `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` §4 — D1.B already established that naive OR over already-related channels (e.g., `g_new_production OR g_new_page_class` where `page_class ⊂ production`) is logically redundant. D1.C's Tier-1 signals are designed to be **orthogonal** to existing channels via §1.3.3 criterion, so naive OR is the correct first sketch — but the hand-off must call out that D1.E should evaluate alternative compositions (per-channel reward, weighted reward, scalar bandit) as well.
   - Sample L1 sketch (informational only; D1.E spec decides actual wiring):
     ```python
     # Naive-OR sketch — appropriate ONLY because §1.3.3 filtered signals
     # to be empirically orthogonal to discovery_binary_reward (|rho| < 0.4).
     # Alternative compositions (per-channel reward, weighted, scalar bandit)
     # are open questions for D1.E per d1b_recommendation.md §4.
     bandit_success_L1 = 1 if (
         discovery_binary_reward
         + (1 if recommended_signal_1 else 0)
         + (1 if recommended_signal_2 else 0)
     ) > 0 else 0
     ```
   - **Stopping rule** (per revisit plan §3.3 L1 note): D1.E must define a max of 3 OR'd channels to avoid saturating `bandit_success` in the OPPOSITE direction (always firing → no discrimination).
5. **Pro-facing subsection draft** `D1C_SUBSECTION.md`:
   - Following the same FROZEN-template structure as `D1A_SUBSECTION.md` + `D1B_SUBSECTION.md`
   - TL;DR: D1.C surveyed 5 Tier-1 candidate signals and 8 Tier-2 metrics on the 30-DB corpus (Cat-B metrics scoped to the 10 D1.A DBs that have `proof_generated` / `proof_verify_failed` / `elapsed_ms`). Top N Tier-1 signals shortlisted for D1.E L1 evaluation; Tier-2 metrics show [findings]. D1.E forward-run will validate.
   - Method, results, Pro disclosures, recommendation, limitations, provenance + revision history

6. **D1.C notebook** (NEW in v0.2 per Composer audit — revisit plan `:173` explicit):
   - `a4/runs/iv_pos_8/d1c/IV_POS_8_D1C_NOTEBOOK.ipynb` (+ rendered `.html`)
   - Following the sibling pattern of `IV_POS_8_D1A_NOTEBOOK.ipynb` + `IV_POS_8_D1B_NOTEBOOK.ipynb`
   - Sections: (1) corpus + provenance, (2) Tier-1 signal distributions + post-local fire-rates, (3) correlation matrix heatmap, (4) Tier-2 per-campaign metrics tables, (5) Tier-1 shortlist + D1.E hand-off summary
   - Builder script: `a4/runs/iv_pos_8/d1c/analysis/build_d1c_notebook.py` (matches D1.B's `build_d1b_notebook.py` template)

**Exit criteria:**

- `d1c_correlation_matrix.csv` (45 rows per §2.3 task 1)
- `d1c_non_saturation.csv`
- `d1c_signal_shortlist.md` (Top 2-3 recommended + deferred list with rationale)
- `d1e_handoff_L1_signals.md` (≤3 OR'd channels rule + D1.B §4 open-question cross-link)
- `D1C_SUBSECTION.md` (Pro-facing draft)
- `IV_POS_8_D1C_NOTEBOOK.ipynb` + `.html` (revisit plan `:173` requirement)
- Batch 3 Composer report
- Composer + Opus review pass

### 2.4 Squash commit (D1.C is COMPLETE)

Single squash commit per Ivan's "one commit per D-letter deliverable" preference:

```
D1.C Batches 1+2+3: bug_proximity.py + Tier-1 audit + Tier-2 metrics +
  cross-correlation shortlist + D1.E L1 hand-off + Pro subsection
```

After D1.C commits, **Stage 3 (D1.E)** spec drafting begins.

---

## 3. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Tier-1 candidates ALL show high correlation with existing channels → empty shortlist | Medium | Document honestly; widen candidate pool in Batch 1-rev with additional signals (bug_proximity_index, address_distance_to_text); flag to D1.E that L1 enrichment may not work without Layer-2 architectural change (scalar bandit) |
| Cat-B metrics return None for all R2 DBs (expected) → Tier-2 paired tests can only run on D1.A subset | High (expected) | Cat-B paired tests explicitly scoped to D1.A's 10 DBs; document NULL handling; cross-check with D2.A V5 fresh DBs if available |
| `co_failure_graph_degree` distribution is degenerate (all nodes have similar degree) | Low | Document distribution shape; if degenerate, drop this metric from Tier-2 with rationale; replace with `co_failure_graph_density` only |
| `mutation_substrategy` table missing on R2 V1/V5 DBs | LOW (downgraded in v0.2 — Composer audit confirmed table present on R2 V5 s1234 with 6000 rows) | If audit reveals missing rows on R2 V1 specifically, scope `mutation_substrategy_uniqueness` to V5+D1.A DBs and document in Batch 1 report. |
| `KIND_TO_SUBSTRATEGY_FIELDS` mapping is wrong for some kind → composite-key collisions or false uniqueness | Medium | Batch 1 audit script (`d1c_substrategy_field_audit.csv`) catches this empirically: any kind with all-NULL rows or unexpected populated columns triggers a Composer flag for manual mapping review. |
| §1.4 Option A (`discovery_binary_reward`) is insufficient — all Tier-1 candidates show correlation > 0.4 against the OR | Medium | Conditional Batch 1.5 (Option C replay) per §1.4 expands channel set to per-channel l_new/g_new/s_new/f_new integers. This is a CONDITIONAL follow-up, not unconditional Batch 1 scope. |
| Composer touches `reward_v2.py` or `fuzzer.py` (production code) | Low | Batch 1 acceptance checklist includes "no production-code edits" review. D1.C is analysis-only per revisit plan §3.2 |
| D2.G changes column schema after D1.C Batch 2 locks → re-coordinate | Medium | Use Pro-§-tagged column names (e.g., `cat_a_pro_s5_singleton_failure_rate`) so D2.G can adapt without renaming. Lock schema in `d1c_tier2_schema.md` and cross-link from `IV_POS_8_D2_PLAN.md`. |
| `recent_marginal_discovery_rate` window W=100 is arbitrary | Low | Run W ∈ {50, 100, 200} in Batch 3 analysis; document the W-vs-correlation curve in `d1c_signal_shortlist.md`. (Note: per §1.3.3, this signal is EXPECTED to fail the binary ortho gate vs `discovery_binary_reward` by construction; choosing W is mostly about characterizing the smoothing scale, not about achieving orthogonality.) |
| `recent_marginal_discovery_rate` correlates highly with `discovery_binary_reward` by construction → shortlist may drop this candidate from Top-N | Expected (per Composer audit B) | Tagged in §1.2 docstring + §1.3.3 expected-pattern note + shortlist rationale template "rejected for ortho failure but kept as scalar-bandit candidate per NFP-9 deferred L2 wiring." Not a failure mode — captured intentionally. |
| `verifier_accepted_invalid_count` Cat-A query (`SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0`) is fast — risk N/A (v0.3: previous v0.2 row claiming `hook3_raw` scan was stale, removed) | n/a | n/a |

---

## 4. Test plan

| Test type | Where | What it covers |
|---|---|---|
| Unit | `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | All Tier-1 + Tier-2 functions; edge cases; Pro-§ reference docstrings present |
| Integration | `build_d1c_artifacts.py` self-check assertions | Sanity invariants (singleton_rate ∈ [0,1], d_loc_p95 ≥ d_loc_median, etc.) |
| Smoke | 1 R2 V5 + 1 D1.A DB, Batch 1 | Tier-1 extraction end-to-end before full-corpus run |
| Schema-lock | `d1c_tier2_schema.md` | D2.G column name compatibility |
| Correlation matrix | `build_d1c_correlation_analysis.py` | Pearson computation on paired V5 seeds; matches scipy reference |

---

## 5. Pro disclosure considerations

D1.C's Pro-facing subsection (Stage 4 fold-in to `IV_POS_8_D1_REPORT_FOR_PRO.md`) must explicitly:

1. **Disclaim analytical scope** per §0.1.1 — D1.C does NOT prove L1 enrichment helps the bandit; D1.E does.
2. **Pro Report 3 §-mapping** — every Tier-2 metric tagged with its §5 or §8 reference; tells Pro "we measured what you asked us to measure."
3. **Cat-A vs Cat-B labeling** — Pro sees which findings have 30-DB support vs 10-DB support.
4. **Tier-1 shortlist with caveats** — top 2-3 signals shipped with selection rationale; remaining deferred with explicit "not selected because [correlation X.X with l_new / fire rate Y.Y% post-local]".
5. **NOT a separate Pro disclosure** — D1.C subsection bundles with D1.A + D1.B + D1.E in Stage 4 final D1 report. No standalone NFP entry needed unless Batch 3 surfaces a new architectural concern.

---

## 6. Composer kickoff checklist (Batch 1)

Before Composer starts Batch 1:

- [ ] Ivan greenlights Q-C-CORPUS-A / B, Q-C-TIER1-CANDIDATES, Q-C-D2G-COORD
- [ ] Ivan confirms v0.2+v0.3 Composer-audit fixes (channel reconstruction §1.4 with Option A commitment, `verifier_accepted_invalid_count` SQL alignment to D1.A spec, `mutation_substrategy` composite-key API + `KIND_TO_SUBSTRATEGY_FIELDS` Batch 1 audit task, **8 Tier-2 metrics** including the v0.2 adds `pro_s8_unique_locs_with_d_glob_le_1` and `pro_b_wall_clock_per_normalized_discovery`, notebook in Batch 3 exit criteria, `recent_marginal_discovery_rate` reframed as momentum/scalar-bandit candidate per v0.3 Composer pushback B)
- [ ] Confirm D1.B squash commit `71dae77 Check d1.b` reachable from `cloud2` HEAD (file paths under `a4/runs/iv_pos_8/d1b/` reachable)
- [ ] Confirm Batch 1.6 byte_addr fix is in main branch (`compressed_global_extractor.py` field order `("byte_addr", "addr", "address")`)
- [ ] D2 team acknowledged Batch 1.6 fix coordination
- [ ] No active work on `a4/standalone/reward_v2.py` or `a4/standalone/fuzzer.py` from D2 team during D1.C window (analysis-only D1.C shouldn't touch these, but D2.B's NFP-4 `_TXN_ROLE_BY_KIND` work is in the same file — coordinate)

---

## 7. Open questions (carried over from revisit plan; deferred to D1.E)

These are NOT in D1.C scope but referenced for cross-coordination:

- D1.E L0 baseline confirmed: `production_log2_corrected` (per D1.B Batch 3 recommendation)
- D1.E L1 design: D1.C ships shortlist; D1.E picks wiring (per-channel reward vs scalar bandit vs simple OR)
- K target derivation: D1.E spec characterizes via legacy `coverage` cumulative curves (per Pro §7); D1.B confirmed K stays driven by `_local_discoveries`, NOT CGC

---

## 8. Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Opus | Initial draft v0.1. 3 batches (Batch 1 Tier-1 foundation, Batch 2 Tier-2 + D2.G schema lock, Batch 3 cross-correlation + shortlist + D1.E hand-off). 7 Ivan-decision questions (Q-C-CORPUS-A/B, Q-C-TIER1-CANDIDATES, Q-C-TIER2-LIST, Q-C-SHORTLIST-DEPTH, Q-C-D2G-COORD, Q-C-COFAILURE-WINDOW). Aligned with revisit plan v0.5 §3.2 + §3.3 (D1.E L1 dependency). Uses D1.B Batch 1.6 corrected baseline. |
| 2026-06-17 | Opus (Composer audit fixes) | v0.2 incorporates Composer's audit feedback. Material changes: **(1)** added §1.4 Channel-reconstruction strategy resolving the per-pull `l_new`/`g_new`/`s_new`/`f_new`-not-in-DB gap with three options (A direct read of `discovery_binary_reward`, B algebraic inversion ruled out as underdetermined, C full replay reserved for conditional Batch 1.5); committed to Option A for v0.2 Batch 1 + Batch 3; **(2)** corrected `f_new_flag` derivation to use `fnew_only_reward > 0` as exact binary proxy (proof: `fnew_only_reward = 0.30 * sat(f_new, 1.0)`); **(3)** redefined `recent_marginal_discovery_rate` on `discovery_binary_reward` rolling sum (no replay needed); **(4)** corrected `mutation_substrategy_uniqueness` to use composite key from actual kind-specific columns (`opcode, rd, rs1, rs2, funct3, funct7, imm, byte_lane, bit_mask, value_class` per `coverage_db.py:356-369`) — `substrategy_name` column does not exist; added `KIND_TO_SUBSTRATEGY_FIELDS` audit task to Batch 1; **(5)** aligned `pro_s5_verifier_accepted_invalid_count` SQL with locked D1.A spec definition (`IV_POS_8_D1_A_SPEC.md:539`: `mutations WHERE verifier_accepted=1 AND num_failures>0`); flagged Pro §5-literal Cat-B variant as v0.3 add; **(6)** added 7th Tier-2 metric `pro_b_wall_clock_per_normalized_discovery` per revisit plan `:160` (Cat-B; was missing from v0.1); **(7)** added Pro §8 paired `pro_s8_unique_locs_with_d_glob_le_1` companion to `d_loc_le_2` per `ProG_Report_3.md:163`; **(8)** explicitly noted `d_loc_le_2_flag` substitution for revisit plan §3.2's "sliding-window d_loc rate" example; **(9)** added Batch 3 notebook + builder script per revisit plan `:173` "Notebook + HTML rendered" exit criterion; **(10)** corrected status line to cite D1.B commit SHA `71dae77`; **(11)** fixed Cat-B column wording (on `mutations` table, not in CSV); **(12)** restructured paired-test framing to 15-row paired-decay subset + separate `d1c_unpaired_means.csv` (v0.1's "20-row 5+5+5+5" was confusing); **(13)** Tier-1 correlation matrix shrunk to 5x2 channels (existing channel set reduced to `discovery_binary_reward` + `f_new_flag` per §1.4 Option A); excluded trivial `f_new_flag` self-cell; **(14)** Batch 3 L1 hand-off cross-references D1.B `d1b_recommendation.md` §4 open-question framing for L1 composition (per-channel reward / weighted / scalar bandit alternatives); **(15)** downgraded `mutation_substrategy` missing-on-R2 risk from Medium to Low per Composer verification (6000 rows present on R2 V5 s1234); added new risks for KIND_TO_SUBSTRATEGY_FIELDS misclassification and §1.4 Option A insufficiency; **(16)** added Q-C-* v0.2 confirmation row to Composer kickoff checklist. No semantic changes to Q-C-CORPUS-A/B, Q-C-SHORTLIST-DEPTH, Q-C-COFAILURE-WINDOW recommendations. |
| 2026-06-17 | Opus (Composer second-round audit fixes) | v0.3 reconciles internal drift from v0.2 surgical edits. **(1)** Tier-2 count harmonized to **8** (was inconsistent: §0.2 said "Seven", §0.3 said "7", §1.2 `TIER2_METRICS` listed 6, §2.2 said "7 metrics"/"all 7"/"30 rows × 7", §2.2 exit criteria "7 Tier-2 functions", §2.3 task 5 TL;DR said "6 Tier-2 metrics" — all updated to 8); **(2)** §1.2 `TIER1_SIGNALS` constant comments updated — `recent_marginal_discovery_rate` now references `discovery_binary_reward` rolling mean per §1.4 (was stale `l_new+g_new+s_new` rolling sum from v0.1 narrative); other Tier-1 entries gained §1.4 cross-refs; **(3)** §1.2 `TIER2_METRICS` constant updated to include `pro_s8_unique_locs_with_d_glob_le_1` and `pro_b_wall_clock_per_normalized_discovery` (both added to v0.2 function list + Batch 2 tasks but missed in the module-level constant); **(4)** §0.1.1 Tier table criterion column updated — "low correlation with `l_new`/`g_new`/`s_new`/`f_new`" replaced with reference to §1.4 channel set (Option A: `discovery_binary_reward` + `f_new_flag`; expandable on Batch 1.5 trigger); **(5)** §1.3.3 orthogonality criterion text fully updated to §1.4 Option A channels with rationale; added explicit "expected pattern for `recent_marginal_discovery_rate`" subsection per Composer pushback B — a rolling mean of a binary signal correlates with the instantaneous bit by construction; this candidate is EXPECTED to fail the binary ortho gate; shortlist rationale template distinguishes "rejected for ortho failure (NOT a good L1 OR-channel)" from "rejected for ortho failure but kept as scalar-bandit candidate per NFP-9 deferred L2 wiring" — captured intentionally, not a failure mode; **(6)** §1.2 `recent_marginal_discovery_rate` docstring rewritten with the momentum/smoothing framing, expected-rho range (O(0.4-0.7)), and dual-role rationale (saturation-boundary detector OR scalar-bandit candidate); **(7)** §1.4 correlation matrix diagram corrected — v0.2 placed "(n/a self)" at (f_new_flag row × discovery_binary_reward col) which is NOT a self-cell; v0.3 puts the trivial 1.000 self-cell at the correct intersection (f_new_flag × f_new_flag) and adds an inline "expected high (see §1.3.3)" annotation for `recent_marginal_discovery_rate` × `discovery_binary_reward`; corrected row count math (5×2 = 10 cells - 1 trivial = 9 non-trivial cells × 5 seeds = 45 rows, matches §2.3 task 1); **(8)** §3 risk table — old `recent_marginal_discovery_rate W=100 arbitrary` row reframed (W selection is about characterizing smoothing scale, not orthogonality); new explicit risk row added documenting expected high ρ as intentional, not a bug; old `verifier_accepted_invalid_count hook3_raw expensive` row removed (stale — D1.A SQL only queries `mutations` table, which is fast). No changes to Q-C-* recommendations, batch structure, or §1.4 Option A commitment. |

*End of `IV_POS_8_D1_C_SPEC.md` v0.3.*
