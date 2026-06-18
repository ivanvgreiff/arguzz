# D1.E L1 Signal Hand-off

**Source:** D1.C complete (Batches 1+2+3)
**Audience:** D1.E spec author
**Purpose:** Enumerate L1 OR-channel candidates for the D1.E reward rewire

---

## §1 Recommended L1 OR-channel additions (from `d1c_signal_shortlist.md` Bucket A)

**Top 3 (ordered by rank score `(1/max|ρ|) × fire_rate_post_local`):**

| Priority | Signal | Post-local fire rate | Max \|ρ\| | Disjoint-fire vs `discovery_binary_reward` (30-DB mean) |
|---:|---|---:|---:|---:|
| 1 | `mutation_substrategy_uniqueness` | 33.7% | 0.069 | 98.1% |
| 2 | `d_loc_le_2_flag` | 60.7% | 0.239 | 99.3% |
| 3 | `singleton_failure_flag` | 16.5% | 0.082 | 99.6% |

**4th alternate:** `recent_marginal_discovery_rate` (15.8% fire, ρ=0.114) — continuous; lower rank score but passes both gates.

**Stopping rule:** Max **3** OR'd channels beyond `discovery_binary_reward` per revisit plan §3.3 — avoid saturating `bandit_success` always-on.

---

## §2 Per-pull integration approach

For each recommended binary signal `S`:

| Approach | Sketch | When to use |
|---|---|---|
| **(a) OR-into-bandit-success** | `bandit_success_L1 = 1 if (discovery_binary_reward + S_flag + ...) > 0` | Default for Bucket A binary signals (empirically orthogonal + high disjoint-fire) |
| **(b) AND-filter** | Rarely useful unless filtering discoveries | Not recommended for v1 |
| **(c) Scalar bandit channel** | Feed continuous magnitude to NFP-9 deferred L2 | For `recent_marginal_discovery_rate` if D1.E explores scalar reward |

```python
# Naive-OR sketch — appropriate ONLY because §1.3.3 filtered signals
# to be empirically orthogonal to discovery_binary_reward (|rho| < 0.4).
# Alternative compositions (per-channel reward, weighted, scalar bandit)
# are open questions for D1.E per d1b_recommendation.md §4.
bandit_success_L1 = 1 if (
    discovery_binary_reward
    + (1 if mutation_substrategy_uniqueness else 0)
    + (1 if singleton_failure_flag else 0)
) > 0 else 0
```

D1.E should evaluate alternative compositions per D1.B §4 open-question framing.

---

## §3 Empirical disclosures for D1.E

### f_new_flag is empirically dead post-local (especially on V5)

`f_new` counts **new constraint-family** discoveries (`f_new ≥ 1` via `fnew_only_reward > 0`). Families are discovered early; after mut ~3000 almost no new families appear.

**30-DB counts (pulls where `f_new_flag = 1`):**

| Window | Fires | Share of all f_new fires |
|---|---:|---:|
| Pre-local `[0, 3000)` | **302** | **98.7%** |
| Post-local `[3000, 6000)` | **4** | **1.3%** |
| Full campaign | 306 | 100% |

- **V5 (10 DBs):** 0 post-local fires. Example V5 s1234: all 10 fires at mids `{1, 5, 12, 13, 38, 41, 61, 85, 149, 167}` — every one **before mut 3000**. Each has `fnew_only_reward ≈ 0.19` and `discovery_binary_reward = 1` (co-fires with main discovery bit).
- **V1 (4 of 10 DBs):** exactly **1** post-local fire each (0.033% rate = 1/3000), at mids **4951, 3861, 3651, 4002** on s1235/s1236/s1239/s1243. Still far below the 5% non-saturation gate.
- **D1.A decay (10 DBs):** 0 post-local fires.

Corpus-wide index histogram: 283/306 fires in `[0, 500)`; only 4 in `[3000, 5000)`; **zero** in `[5000, 6000)`.

**Implication:** Not "always zero everywhere" — ~0.17% full-campaign with almost all mass pre-local. Post-local mean **~0%** (4 fires / 90,000 post-local pulls). Do not wire into L1 for V5-paired D1.E; kept for catalog completeness only.

### Crash-mode `d_loc` schism (D1.C audit finding)

On ~**1.12%** of pulls (`d_loc=0` in `mutation_rewards` but non-empty `failures` table), production sets `d_loc = 0` because `mode='crash'` (`coverage_state.py:190-198`) even when failures were recorded. **100%** of these pulls are crash mode (verified on V5 s1234: 67/67).

| Signal | Reads | On crash pull with failures |
|---|---|---|
| `d_loc_le_2_flag` | `mutation_rewards.d_loc` | **Fires** (`0 ≤ 2`) |
| `singleton_failure_flag` | `COUNT(*)` from `failures` | Does **not** fire if `count > 1` |

Sensitivity: recomputing `d_loc_le_2_flag` from failure-table contexts shifts post-local fire rates by **< 0.2 pp** on all 30 DBs — shortlist ordering unchanged. D1.E must disclose this so Pro understands the channels use different failure semantics.

### `mutation_substrategy_uniqueness` — exclude `INSTR_TYPE_MOD`

`INSTR_TYPE_MOD` has **all-NULL** substrategy columns on all 30 DBs → degenerate composite key `(INSTR_TYPE_MOD, ())`. Only the **first** INSTR_TYPE_MOD pull per DB gets `uniqueness=1` (~30 fires corpus-wide); **0** post-local INSTR_TYPE_MOD uniqueness fires on V5 s1234. D1.E should **exclude INSTR_TYPE_MOD** from this channel or treat it as a separate arm class.

### Tier-2 singleton definition (defer to D1.E spec)

`pro_s5_singleton_failure_rate` and Tier-1 `singleton_failure_flag` both use **one failure row** (`COUNT(*) = 1`), not one distinct `constraint_loc`. On V5 s1234 they agree (996); five pulls have two failure rows at the same loc (different major/minor). D1.E spec should choose explicitly between row-based vs distinct-loc singleton semantics.

### Saturation inversion (D1.B)

Coarsened CGC variants saturate **before** local saturation; `production_log2_corrected` remains L0 baseline. See `d1e_handoff_CGC_saturation.md`.

### Singleton-failure-rate decay-vs-static discrimination (D1.C Batch 2) — **load-bearing**

Decay variants find **~22% fewer singleton failures** than V5-static on the paired decay corpus:

| Comparison | Mean decay | Mean V5-static | p-value |
|---|---:|---:|---:|
| V5_decayexp vs V5 | 12.9% | 16.7% | 2.6e-06 |
| V5_decayepoch vs V5 | 13.4% | 16.7% | 9.7e-05 |
| V5_decayexp vs V5_decayepoch | 12.9% | 13.4% | 0.059 (marginal) |

**Per-variant singleton post-local fire rates (Tier-1 audit):** V5-static 16.8%, decayexp 12.5%, decayepoch 12.2%, V1 20.3%.

**Architectural interpretation is open:**
- (a) Decay pushes toward multi-loc failures (higher d_loc per pull), OR
- (b) Decay misses singleton-failure mutations entirely.

**Implication for D1.E:** `singleton_failure_flag` (Tier-1 per-pull form) is recommended in Bucket A with high disjoint-fire (99.6% on V5 s1234). If D1.E wires decay variants, singleton channel behavior should be validated in forward run.

### Orthogonality surprise

`recent_marginal_discovery_rate` passed the orthogonality gate in post-local window (ρ≈0.11, not the ≥0.4 expected from full-campaign analysis). Post-local discovery momentum is decorrelated from instantaneous `discovery_binary_reward` once saturation sets in.

---

## §4 Scope disclaimer

**D1.C does NOT validate that the bandit benefits from learning on these signals** — that is D1.E's forward-run job. D1.C's job is to find candidates with empirically promising properties (orthogonal + non-saturating on frozen DBs).

---

## §5 Cross-references

- D1.B L1 OR-channel framing: `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` §4
- D1.B saturation inversion: `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md`
- D1.C shortlist: `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md`
- D1.C Tier-2 schema (D2.G): `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md`
- D1.C metrics table: `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv`
- D1.C audit report: `a4/docs/cloud2/composer/D1C_AUDIT_REPORT.md`
