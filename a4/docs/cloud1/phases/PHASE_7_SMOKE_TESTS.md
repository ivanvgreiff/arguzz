# Phase 7 — Smoke Tests (Hybrid: local + POS)

**Status**: ⚪ PENDING (depends on Phases 0-6 complete)
**Owner**: Composer (review: Opus)
**Estimated effort**: 2 hours Opus + ~1 h WSL + ~30-60 min POS
**Risk**: low (catches issues before paying full Phase 8 POS compute)

**Plan structure (D39, decided 2026-06-08 with user)**: three sub-phases, **all three required for exit**:
- **7a — Local fast smoke (WSL)**: catches crashes / NaN / schema / fuzzer-init bugs cheaply
- **7b — POS smoke (`coinbase`)**: budget-relevant measurements that depend on host hardware
- **7c — Mutation-semantic verification**: resolves G2 — proves we mutate what we think we mutate

User has signed off on this structure; G2 is now a Phase 7 exit criterion, not an open question for Pro.

---

## 7a. Local fast smoke (WSL)

**Goal**: catch obvious bugs (crashes, NaN counterfactuals, missing rows, fuzzer-init errors, schema mismatches) in a tight iterate-and-rerun loop BEFORE paying for POS time.

**N=20 per variant.** At Composer's measured ~30 s/mutation on WSL, this is ~50 min total wall-clock for all 5 variants.

### 7a.1 Per-variant runs

For each of the 5 IV.POS.7 variants, run locally on Ivan's WSL:

```bash
python -m a4.standalone.cli fuzz \
    --selector=<VARIANT> \
    --num=20 \
    --seed=999 \
    --telemetry-level=full \
    --db=a4/smoke_7a/smoke_<VARIANT>.db \
    -- --in1 5 --in4 10
```

Variants (in execution order):
- [ ] `zoned` (Variant 1, reference)
- [ ] `kindUCB_zoned_v1` (Variant 2)
- [ ] `kindUCB_zoned_v2_noQ` (Variant 3)
- [ ] `kindTS_zoned_v2` (Variant 4)
- [ ] `cTS_semantic_v2` (Variant 5)

### 7a.2 Per-variant validation (N=20)

For each smoke DB, check (script the assertions in `tools/check_smoke_db.py`):
- [ ] No exception raised during run (`exit code 0`)
- [ ] DB exists, openable, schema version matches expectation
- [ ] All v2 tables exist (`reward_counterfactuals`, `mutation_substrategy`, `hook3_raw`, `local_coverage_v2`, `compressed_global_coverage`, `bandit_decisions`, `arm_state_snapshot`)
- [ ] **All counterfactual rows finite** (no NaN/inf in any of the 5 columns) — `SELECT COUNT(*) WHERE NOT (col = col) ...` returns 0
- [ ] Variants 2-5: `bandit_decisions` has ≥1 row per **completed** mutation (probably <20 due to skips)
- [ ] Variants 3-5: `reward_counterfactuals` has ≥1 row per completed mutation
- [ ] Variant 5: at least one `local_coverage_v2` row populated (mid-budget input should hit some constraints)
- [ ] V5 wall-time / V1 wall-time ≤ 2.0× (loose at N=20; tighter check at 7b)

### 7a.3 Exit gates (must pass before proceeding to 7b)

Hard gates — any failure here aborts 7b and triggers debug:
1. **No crashes** across all 5 variants
2. **No NaN/inf** in any counterfactual column for any variant
3. **All v2 tables wired** — verified by row counts > 0 where expected
4. **Schema unchanged** vs Phase 1 baseline

Soft gates (warn but don't block):
- Wall-time anomalies > 3× expected
- More than 50% skipped mutations (suggests host invocation issue)

---

## 7b. POS smoke (`coinbase`)

**Goal**: budget-relevant measurements that DEPEND on POS hardware (extrapolation from WSL is unreliable for size/time budgets). Only executed if 7a passes all hard gates.

**N=200 per variant.** Provisional POS estimate: 5-15 s/mutation → ~15–40 min per variant → ~75 min – ~3.5 h total. Refine on first variant before launching the rest.

### 7b.1 Per-variant runs

Same CLI as 7a but `--num=200` and `--db=a4/smoke_7b/smoke_<VARIANT>.db` on POS host. Use `tmux` so disconnect is safe.

### 7b.2 Per-variant validation (N=200)

For each smoke DB:
- [ ] All 7a checks (re-run on POS DBs)
- [ ] Variants 2-5: `bandit_decisions` ≈ 200 rows (allowing for ~10% skip rate)
- [ ] Variants 2-5: `arm_state_snapshot` ≈ 2 rows (200 / 100 snapshot frequency)
- [ ] Variants 3-5: `reward_counterfactuals` ≈ 200 rows
- [ ] Variant 5: `local_coverage_v2` AND `compressed_global_coverage` both populated
- [ ] **DB size ≤ 5 MB per variant at N=200** (extrapolates to ≤ 150 MB at N=6000, Pro's budget)
- [ ] **V5 wall-time / V1 wall-time ≤ 1.3×** (Pro's target performance ceiling)

### 7b.3 Cross-variant zoned consistency

- [ ] Run `zoned` at `--seed=999` on POS using **legacy code path** (pre-cloud1, if a tag is available) AND new code path (`--telemetry-level=standard`)
- [ ] Final coverage (`local_coverage`, `failures`, `mutations` row counts) MUST match exactly between the two
- [ ] Goal: prove we did not change legacy behavior unintentionally

### 7b.4 Schema compatibility test

- [ ] Open one IV.POS.5 DB (read-only) using v2 codebase
- [ ] Verify legacy `analyze_campaign.py` and `analyze_replicates.py` still produce output without error

---

## 7c. Mutation-semantic verification (G2 — RESOLVED INTERNALLY)

**Goal**: prove we MUTATE WHAT WE THINK WE MUTATE. Per Pro's `ProG_Report_2.md` concerns and the user's question during Phase 6 review, plumbing existence is not enough — we need ground-truth confirmation that e.g. an `INSTR_TYPE_MOD@step=42` actually changed the opcode at that cycle in the guest trace, and that the resulting failure pattern matches the mutated semantics.

**Method**: random spot-check, 3 mutations per variant on Variant-5 DB (which exercises all 8 kinds via `cTS_semantic_v2`).

### 7c.1 Sample selection

From `smoke_7b/smoke_cTS_semantic_v2.db`:
- [ ] SELECT 3 random `mutation_id` rows per `mutation_kind`, stratified to cover all 8 kinds → max 24 samples
- [ ] For each sample, record: `(mutation_id, kind, step, original_value, mutated_value, config)`

### 7c.2 Re-execute and compare traces

For each sample:
- [ ] Re-run the guest with the SAME mutation config (deterministic from `seed + mutation_id`)
- [ ] Capture before/after `InspectionData` slices at the mutation step
- [ ] Assert kind-specific properties:

| Kind | Property to verify |
|---|---|
| `INSTR_WORD_MOD_SUR` | Cycle at `step` has `insn_decode.word == mutated_value`; before had `original_value` |
| `INSTR_WORD_MOD_FULL` | Same as above; additionally cycle's `kind` matches decode of mutated word |
| `INSTR_TYPE_MOD` | Cycle at `step` has `insn_decode.kind == mutated_value`; failure (if any) is one of the expected `MemLoadInput` / `InstDecode` family |
| `LOAD_VAL_MOD` | Memory write at `step` has new value = mutated_value |
| `STORE_OUT_MOD` | Store cycle output equals mutated_value |
| `COMP_OUT_MOD` | Compute cycle output equals mutated_value |
| `MEM_VAL_MOD` | Memory cell at config-specified `addr` has new value = mutated_value |
| `PRE_EXEC_REG_MOD` | Initial register file has `reg[config.reg_idx] = mutated_value` |

### 7c.3 Result documentation

- [ ] Write `a4/docs/cloud1/phases/PHASE_7_SEMANTIC_VERIFICATION.md` with:
  - Sample table (24 rows): mutation_id, kind, step, expected vs observed
  - PASS/FAIL per row
  - If FAIL: detailed trace diff + diagnosis (is it a mutation bug? a Hook bug? a fuzzer bug?)

### 7c.4 Exit gate

- [ ] **All 24 samples PASS**. Any failure must be either fixed or explained (with explicit Pro-facing note) before Phase 8.

---

## 7.5 Summary report

- [ ] Write `phases/PHASE_7_SMOKE_REPORT.md` consolidating 7a + 7b + 7c with:
  - 7a per-variant: wall-time, row counts, any anomalies
  - 7b per-variant: wall-time, DB size, row counts, V5/V1 ratio, zoned-consistency outcome
  - 7c: 24-row semantic verification table
  - Net pass/fail per variant
  - User signs off proceeding to Phase 8

---

## Exit criteria (consolidated)

| # | Gate | From |
|---|---|---|
| 1 | All 5 variants smoke-clean at N=20 on WSL | 7a.3 |
| 2 | All 5 variants smoke-clean at N=200 on POS | 7b.2 |
| 3 | Zoned-consistency: legacy code path vs new code path match exactly | 7b.3 |
| 4 | Schema compat: IV.POS.5 DBs openable + analyzable with v2 codebase | 7b.4 |
| 5 | DB size ≤ 5 MB at N=200 (extrapolates to ≤ 150 MB at N=6000) | 7b.2 |
| 6 | V5 wall-time / V1 wall-time ≤ 1.3× on POS | 7b.2 |
| 7 | All 24 mutation-semantic samples PASS | 7c.4 |
| 8 | Summary report written + user sign-off | 7.5 |

---

## Notes / decisions made during phase

- **D39** (this phase plan): three-sub-phase structure (local → POS → semantic). Filed in `CLOUD1_DECISIONS_FOR_PRO_R2.md`. User-approved 2026-06-08.
- **G2 RESOLVED INTERNALLY**: was an open question for Pro R2 about whether to add semantic verification; now a required Phase 7 exit criterion (7c). G2 will be referenced in the Pro R2 report as "implemented internally per §X.Y; see PHASE_7_SEMANTIC_VERIFICATION.md".
- (To be filled by Composer / Opus as work progresses.)
