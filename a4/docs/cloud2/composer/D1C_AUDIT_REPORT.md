# D1.C Post-Batch Systematic Audit Report

**Date:** 2026-06-08  
**Auditor:** Composer (requested by Ivan; Opus independently spot-checked)  
**Scope:** D1.C Batches 1+2+3 — logic, artifacts, conclusions  
**Motivation:** NFP-10 lesson (CGC `addr` vs `byte_addr`) — verify underlying field semantics and distributions, not just pipeline correctness.

---

## Executive verdict

**GREENLIGHT for polish + squash.** No CGC-class field-priority bug exists in D1.C code paths. Two real semantic schisms were found, causation traced to production source, impact bounded. Shortlist top-3 and Batch 2 singleton decay finding survive all sensitivity checks.

| Claim | Status |
|---|---|
| Top 3 L1 shortlist correct | ✅ |
| Orthogonality surprise (recent_marginal max ρ ≈ 0.11) | ✅ |
| Singleton decay p = 2.6×10⁻⁶ | ✅ (recomputed exact) |
| 270 correlation rows regenerate exactly | ✅ |
| 40/40 tests pass | ✅ |
| Option C replay needed | ❌ Not triggered |

---

## 1. Methodology

1. Re-ran all extractors on all 30 Cat-A DBs via `cat_a_db_list()`.
2. Regenerated `d1c_correlation_matrix.csv` and `d1c_metrics_table.csv` key-by-key — compared to committed artifacts.
3. SQL forensics on `failures`, `mutation_rewards`, `reward_counterfactuals` cross-tables.
4. Sensitivity analysis: alternative `d_loc` source for `d_loc_le_2_flag`; continuous vs discretized Pearson for `recent_marginal_discovery_rate`.
5. Scope-variant checks: 30-DB vs V5-only vs V5-paired-5 for max |ρ| and rank order.
6. Confirmed `bug_proximity.py` has zero `compressed_global` / `byte_addr` / `address_region` references.

---

## 2. Artifact regeneration (machine-precision)

| Artifact | Rows | Regeneration match |
|---|---:|---|
| `d1c_correlation_matrix.csv` | 270 | **0 mismatches** |
| `d1c_metrics_table.csv` | 30 | **0 cell mismatches** |
| `d1c_paired_tests.csv` singleton decayexp vs V5 | — | p = **2.600575e-06** (exact) |
| `pytest test_bug_proximity.py` | 40 | **all pass** |

Sanity invariants from `build_d1c_artifacts.py`: singleton rate ∈ [0,1]; d_loc_p95 ≥ median; unique_locs ≤ local_context_final; Cat-B NaN on R2 — **all pass**.

---

## 3. Finding A — Crash-mode `d_loc` schism

### Observation

~**1.12%** of pulls (2,009 / 180,000 on 30-DB corpus) have `mutation_rewards.d_loc = 0` but non-empty `failures` table.

### Root cause

`coverage_state.py:190-198` hardcodes `d_loc = 0` on crash/missing-bitmap pulls. Failures may still be persisted to `failures`.

### Opus spot-check (V5 s1234)

| Check | Result |
|---|---|
| Pulls with d_loc=0 + failures | **67** |
| All have `mode='crash'` | **67/67** (100%) |
| Non-crash cases | **0** |

Example: mid=40 — `d_loc=0, n_fail=2, mode='crash'`, two failure rows present.

### Impact on Tier-1 signals

| Signal | Source | Crash pull behavior |
|---|---|---|
| `d_loc_le_2_flag` | `mutation_rewards.d_loc` | **Fires** (0 ≤ 2) |
| `singleton_failure_flag` | `COUNT(*)` failures | Does not fire if count ≠ 1 |

### Sensitivity

Recomputed `d_loc_le_2_flag` from failure-table `(loc, major, minor)` contexts instead of stored `d_loc`:

- Max post-local fire-rate delta across 30 DBs: **−0.002** (0.2 pp)
- Shortlist rank order: **unchanged**

### Disclosure

Documented in `d1e_handoff_L1_signals.md` §3 for D1.E. Not a D1.C implementation bug — production semantic difference.

---

## 4. Finding B — Tier-2 singleton spec prose vs code

### Observation

Spec §2.2 prose: "fraction of mutations where exactly **1 constraint_loc** broke."

Code (Tier-1 and Tier-2): `COUNT(*) FROM failures GROUP BY mutation_id HAVING COUNT(*) = 1` — **one failure row**.

### Opus spot-check (V5 s1234)

| Definition | Count |
|---|---:|
| Tier-1 `singleton_failure_flag` fires | 996 |
| Tier-2 `pro_s5_singleton_failure_rate` numerator | 996 |
| Overlap | **100%** |
| Pulls with 1 distinct loc but 2 failure rows (same loc, different major/minor) | **5** |

Examples: `MemoryWrite@mem.zir:99` with minor pairs `(2,6)` and `(2,4)`.

### Verdict

Tier-1 and Tier-2 are **internally consistent** (both row-based). Spec prose overstates "one loc." **Defer architectural choice** (row vs distinct-loc) to D1.E spec drafting — noted in `d1e_handoff_L1_signals.md` §3.

---

## 5. Finding C — `INSTR_TYPE_MOD` substrategy degeneracy

- 45,511 INSTR_TYPE_MOD pulls (~25% of corpus); all substrategy columns NULL.
- `KIND_TO_SUBSTRATEGY_FIELDS['INSTR_TYPE_MOD'] = ()` → at most **1** uniqueness fire per DB (first INSTR_TYPE_MOD only).
- V5 s1234 post-local: **0** INSTR_TYPE_MOD uniqueness fires; all post-local signal from other kinds.

**Recommendation:** D1.E should exclude INSTR_TYPE_MOD from `mutation_substrategy_uniqueness` or treat separately. Documented in hand-off §3.

---

## 6. Finding D — `f_new_flag` post-local near-zero (not literally zero)

### Observation

"~0% post-local" means **below the 5% gate**, not identically zero on every DB.

| Window | f_new fires (30-DB) | Share |
|---|---:|---:|
| Pre-local `[0, 3000)` | **302** | 98.7% |
| Post-local `[3000, 6000)` | **4** | 1.3% |
| Full campaign | 306 | 100% |

- **V5 (all 10 DBs):** 0 post-local fires. V5 s1234: 10 fires, all at mids ≤ 167 (pre-local).
- **V1 (4/10 DBs):** 1 post-local fire each at mids 4951, 3861, 3651, 4002 (0.033% = 1/3000).
- **D1.A decay:** 0 post-local fires.

Corpus index histogram: 283/306 fires in `[0, 500)`; 0 in `[5000, 6000)`.

### Verdict

Early-campaign family discovery saturation — not a pipeline bug. Bucket B assignment correct.

---

## 7. Orthogonality surprise — confirmed

| Measure | Max \|ρ\| | Location |
|---|---:|---|
| Discretized @ 0.05 (gate) | 0.114 | D1.A decayexp s1238 |
| Continuous (sensitivity) | 0.134 | D1.A decayexp s1236 |

Both < 0.4. Sparse post-local `discovery_binary_reward` (~3% on V5 s1234) decouples rolling mean from instant bit.

---

## 8. Disjoint-fire 30-DB cross-averages

| Signal | 30-DB mean | Range |
|---|---:|---|
| `mutation_substrategy_uniqueness` | 98.11% | [96.94%, 98.98%] |
| `d_loc_le_2_flag` | 99.27% | [98.80%, 99.62%] |
| `singleton_failure_flag` | 99.62% | [98.70%, 100%] |

V5 s1234 anecdote (98.2/99.2/99.6%) was representative, not anomalous.

---

## 9. Opus review exchange

### Opus confirmed

- Audit methodology sound; spot-checked integers exact.
- f_new ρ artifact (V1-only small sample).
- Disjoint-fire and docstring omissions valid.
- Rank score **is** in spec §2.3 task 3 line 534 — Opus's "Composer invented it" pushback was **wrong** (process lesson: grep spec before claiming undocumented).

### Polish applied (post-audit)

1. ✅ `compute_correlation_matrix` docstring — discretization @ 0.05 documented.
2. ✅ `d1c_signal_shortlist.md` — expanded readable reference; Bucket C wording fixed.
3. ✅ `d1e_handoff_L1_signals.md` §3 — crash-mode schism, INSTR_TYPE_MOD, singleton definition deferral, f_new pre/post table, 30-DB disjoint-fire.
4. ✅ This audit report saved for squash commit.

### Deferred to D1.E spec

- Singleton row vs distinct-loc architectural choice.
- Naive OR composition vs alternatives.

---

## 10. What D1.C does NOT depend on (NFP-10 non-applicability)

`bug_proximity.py` reads: `mutations`, `failures`, `mutation_rewards`, `reward_counterfactuals`, `mutation_substrategy`, `coverage` (for `local_context_final` only). **No CGC / Hook-3 address fields.** The byte_addr mis-labeling bug cannot affect these metrics.

---

## 11. Residual accepted risks

1. **Option A channel trust** — `discovery_binary_reward` not Option-C replay-verified per pull (production tests support correctness).
2. **D1.C ≠ D1.E causality** — gate passage does not prove bandit improvement.
3. **V6 / Arguzz** — R2 V6 archive lacks `mutation_rewards` / `reward_counterfactuals`; D1.C shortlist is V1–V5 + D1.A scoped.

---

## 12. Recommended squash commit addendum

> Includes Composer CGC-style post-batch audit (`D1C_AUDIT_REPORT.md`). Two real semantic schisms found and bounded: (a) `d_loc=0` on crash mode with non-empty failures (1.12% of pulls; <0.2 pp shortlist delta), (b) Tier-2 singleton uses 1 failure row not 1 distinct loc (5 pull differences per 6000 on V5 s1234). Both disclosed to D1.E. No CGC-class field-priority bug in D1.C code paths.

---

*Opus spot-check 2026-06-08: GREENLIGHT polish + squash.*
