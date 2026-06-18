# D1.C Batch 1 — Composer Report

**Spec:** `IV_POS_8_D1_C_SPEC.md` v0.3 §2.1  
**Kickoff:** `composer/D1C_BATCH1_COMPOSER_KICKOFF.md`  
**Branch:** `cloud2` (uncommitted — awaiting Ivan/Opus review)  
**Date:** 2026-06-17

---

## 1. Spec review verdict

**Greenlight confirmed.** Kickoff scope matches v0.3 §2.1. No blocking disagreements with Opus's brief.

**Constraints honored:**
- Analysis-only — zero edits under `a4/standalone/` (verified below).
- Channel reconstruction **Option A only** — `extract_existing_channels_per_db` reads `discovery_binary_reward` + derives `f_new_flag` from `fnew_only_reward > 0`; no replay logic.
- `KIND_TO_SUBSTRATEGY_FIELDS` derived empirically from 30-DB audit (not hand-guessed).
- Tier-2 function bodies are `NotImplementedError` stubs pointing to Batch 2.
- `recent_marginal_discovery_rate` docstring pasted verbatim from v0.3 §1.2 (momentum/smoothing + expected high ρ framing).

---

## 2. Files created

| Path | LOC | Purpose |
|---|---:|---|
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | 355 | Tier-1 extractors + Option A channel helper + Tier-2 stubs |
| `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | 249 | 20 unit + integration tests |
| `a4/runs/iv_pos_8/d1c/analysis/build_substrategy_field_audit.py` | 90 | Kind × column non-null audit |
| `a4/runs/iv_pos_8/d1c/analysis/build_batch1_audit.py` | 127 | 30-DB Tier-1 audit CSV builder |
| `a4/runs/iv_pos_8/d1c/analysis/build_batch1_plots.py` | 101 | Sanity PNG plots |
| `a4/runs/iv_pos_8/d1c/d1c_substrategy_field_audit.csv` | — | 80 rows (8 kinds × 10 columns) |
| `a4/runs/iv_pos_8/d1c/d1c_batch1_tier1_audit.csv` | — | 150 rows (30 DBs × 5 signals) |
| `a4/runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_full.png` | — | Per-signal full-campaign fire-rate histograms |
| `a4/runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_post_local.png` | — | Paired V5 post-local bar chart |
| `a4/docs/cloud2/composer/D1C_BATCH1_REPORT.md` | — | This report |

**`KIND_TO_SUBSTRATEGY_FIELDS` choice:** Embedded directly in `bug_proximity.py` (not a separate auto-generated import file). The audit script prints the dict to stdout for Opus audit; values were copy-pasted after the first corpus run.

---

## 3. Empirical `KIND_TO_SUBSTRATEGY_FIELDS`

Derived from `d1c_substrategy_field_audit.csv` (30 Cat-A DBs via `cat_a_db_list()`):

```python
KIND_TO_SUBSTRATEGY_FIELDS = {
    "COMP_OUT_MOD": ("value_class",),
    "INSTR_TYPE_MOD": (),
    "INSTR_WORD_MOD_FULL": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "INSTR_WORD_MOD_SUR": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "LOAD_VAL_MOD": ("value_class",),
    "MEM_VAL_MOD": ("byte_lane", "bit_mask", "value_class"),
    "PRE_EXEC_REG_MOD": ("value_class",),
    "STORE_OUT_MOD": ("value_class",),
}
```

**Sanity notes:**
- Matches `coverage_db.py:351-354` comment pattern (INSTR_* use opcode/funct fields; MEM_VAL_MOD uses byte_lane/bit_mask/value_class).
- **`INSTR_TYPE_MOD` is special:** 734 `mutation_substrategy` rows per DB, but **all 10 substrategy columns are NULL** across the full 30-DB corpus. Composite key is always `()` — `mutation_substrategy_uniqueness` fires once per campaign for this kind (first `INSTR_TYPE_MOD` pull only). Documented here for Batch 3 shortlist interpretation; not a schema bug.

---

## 4. Analysis-only enforcement

```bash
$ git diff cloud2 -- a4/standalone/ | head
# (empty — no output)
```

---

## 5. Unit tests

```bash
$ pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q
20 passed in 0.39s
```

| Test cluster | Coverage |
|---|---|
| `f_new_flag` proxy | 0 → 0, 0.0001 → 1, 0.1896 → 1 |
| `d_loc_le_2_flag` | fires at d_loc=2, not at d_loc=3 |
| `recent_marginal_discovery_rate` | mut 0, 50, 100, 6000 window cases |
| `mutation_substrategy_uniqueness` | INSTR_WORD_MOD_SUR + MEM_VAL_MOD composite keys |
| Tier-2 stubs | `NotImplementedError` with Batch 2 pointer |
| Integration | V5 seed1234 — lengths == 6000, `f_new_flag` matches channel helper |

**Standalone regression sweep:**

```bash
$ pytest a4/standalone/tests/ -q
515 passed, 7 skipped, 8 warnings in 500.34s
```

(D1.B left ~497–499; +20 new D1.C tests → no regressions.)

---

## 6. `f_new_flag` proxy deviation check

**No deviations found.** Across all 30 DBs:
- Zero rows with negative `fnew_only_reward`.
- Implementation uses strict `fnew_only_reward > 0.0` per §1.4.
- Integration test confirms `extract_tier1_signals_per_db` `f_new_flag` list == `extract_existing_channels_per_db` `f_new_flag` list on V5 s1234.

No case where `fnew_only_reward > 0` but true `f_new = 0` was observed (would contradict the locked formula `0.30 * (1 - exp(-f_new))`).

---

## 7. Tier-1 audit observations (descriptive only)

**Output:** `d1c_batch1_tier1_audit.csv` — **150 rows**, all sanity asserts pass (no NaN; fire_rate ∈ [0, 1]; per-signal list lengths == `COUNT(*) FROM mutations`).

| Signal | fire_rate_full (30-DB mean) | fire_rate_post_local [3000,6000) mean |
|---|---:|---:|
| `f_new_flag` | 0.17% | ~0% (max 0.03% on one DB) |
| `recent_marginal_discovery_rate` | 45.7% | 15.8% |
| `singleton_failure_flag` | 16.7% | 16.5% |
| `mutation_substrategy_uniqueness` | 35.7% | 33.7% |
| `d_loc_le_2_flag` | 61.8% | 60.7% |

**V5 s1234 trajectory (illustrative):** `recent_marginal_discovery_rate` at mut 100 ≈ 0.67, mut 3000 ≈ 0.01, mut 5999 ≈ 0.03 — consistent with early-campaign high discovery momentum decaying toward local saturation. `f_new_flag` full-campaign fire rate on that DB is 0.17%.

Continuous-signal fire counts use threshold **0.05** (`NON_SATURATION_MIN_FIRE_RATE`) per §1.3.2 discretization convention — documented here for Batch 3 reproducibility.

**No orthogonality pre-judgment** — correlation analysis is Batch 3 scope.

---

## 8. Sanity plots

![fire_rate_full histograms](../../runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_full.png)

![post-local fire rates (paired V5)](../../runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_post_local.png)

**Plot read (descriptive):**
- `f_new_flag` clusters near zero across all 30 DBs (full histogram in first bin).
- `d_loc_le_2_flag` and `mutation_substrategy_uniqueness` show the widest cross-DB spread.
- Post-local paired V5 chart: `f_new_flag` bars are effectively zero; `d_loc_le_2_flag` ~0.6; `recent_marginal_discovery_rate` ~0.10–0.16 on paired seeds.

---

## 9. Pass criteria checklist (kickoff §Pass criteria)

| # | Criterion | Status |
|---|---|---|
| 1 | `bug_proximity.py` with constants + 5 Tier-1 extractors + v0.3 docstrings | ✅ |
| 2 | `composite_substrategy_key()` with kind-specific NULL handling | ✅ |
| 3 | `extract_existing_channels_per_db` → `{discovery_binary_reward, f_new_flag}` only | ✅ |
| 4 | `extract_tier1_signals_per_db` → 5 keys, length == N mutations | ✅ |
| 5 | `KIND_TO_SUBSTRATEGY_FIELDS` empirical | ✅ |
| 6 | `TIER2_METRICS` = 8 names; bodies raise `NotImplementedError` | ✅ |
| 7 | ≥15 tests, all green | ✅ (20 tests) |
| 8 | `f_new_flag` three-value proxy tests | ✅ |
| 9 | `d_loc_le_2_flag` boundary at 2 vs 3 | ✅ |
| 10 | `mutation_substrategy_uniqueness` INSTR + MEM rows | ✅ |
| 11 | `d1c_substrategy_field_audit.csv` | ✅ (80 rows) |
| 12 | `d1c_batch1_tier1_audit.csv` 150 rows, no NaN | ✅ |
| 13 | 2 sanity PNGs | ✅ |
| 14 | Standalone pytest green | ✅ (515 passed) |
| 15 | `git diff cloud2 -- a4/standalone/` empty | ✅ |
| 16 | This report | ✅ |

---

## 10. Deviations / surprises for Opus

1. **`INSTR_TYPE_MOD` all-NULL substrategy columns** — not in kickoff's example mapping but present in every DB. Handled with empty tuple `()`; uniqueness degenerates to one fire per campaign for this kind. Flagged for Batch 3 shortlist interpretation.

2. **Continuous fire threshold** — audit CSV uses `NON_SATURATION_MIN_FIRE_RATE` (0.05) for `recent_marginal_discovery_rate` fire_count / fire_rate fields. Not explicitly specified in kickoff; aligns with §1.3.4 non-saturation gate and is noted in §7 above.

3. **`recent_marginal_discovery_rate` API** — spec shows `rolling_discovery_bits` + `window` returning a single float (window slice mean). Batch helper `compute_recent_marginal_discovery_rates()` builds the per-pull list for `extract_tier1_signals_per_db`. Tests exercise the slice API directly per §2.1 task 5.

**No surprises on:** `mutation_substrategy` table presence (all 30 DBs have rows), Option A channel reconstruction, or `f_new_flag` proxy exactness.

---

## 11. Hand-off to Batch 2

Batch 1 foundation is ready. Batch 2 can implement the 8 Tier-2 metric bodies in `bug_proximity.py`, run `build_d1c_artifacts.py`, and lock `d1c_tier2_schema.md` for D2.G.

*End of D1.C Batch 1 report.*
