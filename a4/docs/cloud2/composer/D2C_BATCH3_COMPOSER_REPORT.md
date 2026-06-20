# D2.C Batch 3 — Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) v0.5 LOCKED + §15 annex  
**Kickoff:** [`D2C_BATCH3_COMPOSER_KICKOFF.md`](D2C_BATCH3_COMPOSER_KICKOFF.md)  
**Date:** 2026-06-20  
**HEAD:** `7182237c8245e7a5d7c1309d3f38671c25f4934e` (Batches 1–3 uncommitted on top)  
**Status:** Implementation complete — **not committed** (awaiting Ivan/Opus greenlight)

**Opus / Central Planner inputs incorporated:** ISS-6/ISS-7 resolutions, §A positive (`outcome=` kwarg), F12 (N=10000 fairness for cTS variants), V5-path diff-empty discipline (`CTS_SEMANTIC_V2_FAMILY` kept V5-only; Arguzz strategies use `ALL_SEMANTIC_CTS_STRATEGIES` union).

---

## 1. Pre-kickoff checklist output

```text
$ git rev-parse HEAD
7182237c8245e7a5d7c1309d3f38671c25f4934e

$ python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py | tail -3
654 passed, 21 skipped   # post-Batch-2 floor (recorded)

$ python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py -q
2 passed   # Tier-1 BEFORE fuzzer edits

$ grep -n 'def record_mutation' a4/standalone/coverage_db.py
726:    def record_mutation(

$ grep -n 'outcome' a4/standalone/coverage_db.py | head -5
740:        outcome: Optional[str] = None,
# → §A RESOLVED POSITIVE (Central Planner): outcome= kwarg exists; no STOP branch.

$ grep -n 'v6_cTS\|hybrid_cTS' a4/standalone/fuzzer.py
# BEFORE Batch 3: no hits (added in this batch)

$ grep -n 'applied_accounting_mode' a4/standalone/fuzzer.py
# BEFORE Batch 3: no hits (wired for v6_cTS/hybrid_cTS only)

$ python -c "from a4.standalone.semantic_arm_universe import ArmKey, ARGUZZ_EXEC_FAULT; ..."
ArmKey round-trip OK
```

---

## 2. What was implemented (per-task + LOC)

| Task | File | Status | LOC (approx) |
|------|------|--------|--------------|
| **3.1** | `a4/standalone/v6_uniform_driver.py` **(NEW)** | ✅ | 242 |
| **3.2** | `a4/standalone/fuzzer.py` | ✅ | +318 / −12 (net ~306) |
| **3.2a** | `applied_accounting_mode=True` + `update_with_outcome` on Arguzz path | ✅ | in fuzzer delta |
| **3.2b** | `test_d2c_golden_trace_v5_db_byte_identity.py` + fixture | ✅ | 158 + fixture |
| **3.3** | `test_d2c_v6_uniform_driver_smoke.py` | ✅ | 112 |
| **3.4** | Schema-parity documentation | ✅ | §7 below |
| **3.5** | Soundness-signal + `failure_recording_gap` counts | ✅ | §6 below |
| **3.6** | Pytest sweep | ✅ | §9 below |
| **3.7** | This report + §15 updates | ✅ | — |

**Frozen files untouched:** `arguzz_invoke.py`, `arguzz_bridge.py`, `bandit_ts.py`, `semantic_arm_universe.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`.

### 3.1 — `v6_uniform_driver.py`

- Verbatim bootstrap from `v6_driver_v2.py`: `ArguzzScheduler`, `host --trace` → `InspectionData` → `classify_zones`.
- Replaced inline SQL + `run_inject` with `arguzz_invoke.run()` + `CoverageDB`.
- `driver_version="v3_d2c"`, `iter_seed = seed * 1_000_000 + i`, `include_trace=False`.
- `record_mutation(..., outcome=result.outcome.value)` on every row.
- `A4_FAMILY_RESIDUE=1` passed via `env=` to enable Hook-3 pipeline (CGC wiring; see §10 deviation).

### 3.2 — `fuzzer.py` Arguzz dispatch

- **`V2_BANDIT_STRATEGIES`:** added `v6_cTS`, `hybrid_cTS`.
- **`ARGUZZ_CTS_STRATEGIES`:** `frozenset({"v6_cTS", "hybrid_cTS"})`.
- **`CTS_SEMANTIC_V2_FAMILY`:** **unchanged V5-only** (3 decay variants) — preserves `test_cts_family_contains_all_v5_selectors` and Central Planner's "V5 branch diff-empty" requirement.
- **`ALL_SEMANTIC_CTS_STRATEGIES`:** `CTS_SEMANTIC_V2_FAMILY | ARGUZZ_CTS_STRATEGIES` — used for shared cTS setup/dispatch/update paths.
- **`_arguzz_strategy_config()`:** `v6_cTS` → FULL kinds; `hybrid_cTS` → SELECTED + live A4 kinds; V5 → `(None, a4_kinds, False)`.
- **`_capture_baseline_trace()` (ISS-7):** `host --trace` → step→instruction map; only when `arguzz_kinds is not None`.
- **`_run_v2_bandit_mutation` (ISS-6):** `ArmKey.parse(decision.arm_id).surface == ARGUZZ_EXEC_FAULT` → `_run_arguzz_cts_mutation`; A4 arms fall through unchanged V5 path.
- **`_run_arguzz_cts_mutation`:** direct `arguzz_run(..., include_trace=False, env={"A4_FAMILY_RESIDUE": "1"})`; `update_with_outcome(arm, inv_result.outcome, success=bandit_success)`.
- **`_record_arguzz_mutation`:** `record_mutation(..., outcome=inv_result.outcome.value)` + failures/CGC/global_failures.
- **`_floor_schedule_for_strategy`:** Arguzz strategies use `ConstantFloor(0.55)` (same as V5 static).

---

## 3. `outcome` column — write path (§A)

**Mechanism:** `CoverageDB.record_mutation(..., outcome: Optional[str] = None)` at `coverage_db.py:740` (keyword-only after `*`).

**Write sites (Batch 3):**

| Path | Call site |
|------|-----------|
| V6-uniform driver | `v6_uniform_driver.py:200` — `outcome=result.outcome.value` |
| Fuzzer Arguzz dispatch | `fuzzer.py:1112` — `outcome=inv_result.outcome.value` |

**N=50 smoke proof:** 50/50 rows non-NULL (`null_outcome=0`); distribution `applied=47`, `skipped=3`.

---

## 4. A4-side byte-identity (Tier-1 + Tier-2)

### Tier-1 — decision sequence

```text
$ python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py -v
test_v5_decision_trace_matches_d2c_fixture PASSED
test_d2c_fixture_matches_d2a_baseline PASSED
```

**Before/after fuzzer refactor:** byte-identical (2/2 green throughout Batch 3).

### Tier-2 — DB byte-identity

```text
$ python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py -v
test_v5_db_byte_identity_matches_fixture PASSED
```

Fixture: `fixtures/d2c_golden_v5_db_byte_identity_seed42_n20.json` (N=20, seed=42, `cTS_semantic_v2`).

**Note:** `_stable_db_snapshot()` normalizes sqlite tuples → lists before JSON compare (fixture regenerated once during Batch 3 bring-up).

---

## 5. Layer-5 smoke output (`A4_REAL_BINARY=1`, N=50)

**Command:**

```bash
A4_REAL_BINARY=1 python -m pytest a4/standalone/tests/test_d2c_v6_uniform_driver_smoke.py -v
# subprocess timeout raised to 1800s (50 mutations × ~15s avg ≈ 13 min observed)
```

**Manual N=50 run (seed=1243, reference for report counts):**

```text
=== V6-uniform DONE  total_wall=771.5s ===
outcomes: {'skipped': 3, 'applied': 47}
```

| Assertion | Result |
|-----------|--------|
| 50 `mutations` rows | ✅ |
| ≥6/11 ENABLED_KINDS | ✅ **9/11** distinct kinds |
| All 4 SELECTED kinds present | ✅ INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND |
| `outcome` column populated | ✅ 50/50 non-NULL |
| `constraint_loc` normalized (`Name@basename:line`) | ✅ e.g. `AddrDecomposeBits@u32.zir:87` |
| `extra_json.driver_version="v3_d2c"` | ✅ |
| `compressed_global_coverage` non-empty | ⚠️ **skipped** — Hook 3 silent on `--inject` path (§10) |

**Kinds observed (N=50):** PRE_EXEC_MEM_MOD, POST_EXEC_REG_MOD, INSTR_WORD_MOD, PRE_EXEC_REG_MOD, POST_EXEC_PC_MOD, POST_EXEC_MEM_MOD, BR_NEG_COND, LOAD_VAL_MOD, PRE_EXEC_PC_MOD.

**Missing at N=50 (applicability):** COMP_OUT_MOD, STORE_OUT_MOD, POST_EXEC_REG_MOD present; missing from 11-set: COMP_OUT_MOD, STORE_OUT_MOD, INSTR_TYPE_MOD (trace-dependent).

---

## 6. Soundness-signal + `failure_recording_gap` (task 3.5)

From N=50 smoke DB (`/tmp/v6_smoke_n50.db`, seed 1243):

| Tag | Count | Notes |
|-----|-------|-------|
| `soundness_signal=True` in `config_json` | **0** | No prove_success+applied rows at N=50 |
| `failure_recording_gap=True` in `config_json` | **13** | Path B — prover error, no local `<constraint_fail>` |
| `failures` table rows | 293 | Path A local witgen EQZ |
| `global_failures` rows | 0 | Hook 3 tags absent on inject path |

---

## 7. Schema-parity vs R2 V6 (task 3.4)

R2 archive DB not present in workspace; parity documented from `v6_driver_v2.py` inline schema vs `CoverageDB` schema on N=50 smoke DB.

| Aspect | R2 V6 (`v6_driver_v2.py` inline SQL) | D2.C (`CoverageDB` / `v6_uniform_driver`) |
|--------|--------------------------------------|-------------------------------------------|
| **`mutations.outcome`** | ❌ absent | ✅ TEXT column + `idx_mutations_outcome` |
| **`mutations.proof_*` / `elapsed_ms`** | partial / ad hoc | ✅ standardized nullable columns |
| **`constraint_loc` in failures/coverage** | raw `loc(...)` strings | ✅ `Name@basename:line` via `ConstraintFailure.short_loc()` at write-time |
| **`campaign_params`** | ❌ absent | ✅ present (A4 parity; driver writes selector + `driver_version`) |
| **`compressed_global_coverage`** | ✅ same table shape | ✅ same; rows depend on Hook 3 emission |
| **`extra_json.driver_version`** | `"v2.1_utf8safe"` | `"v3_d2c"` (LOCKED per spec §9 Q5) |
| **Core tables** | campaigns, mutations, failures, coverage, global_failures, compressed_global_coverage | ✅ superset via CoverageDB |

**Expected D2.G handling:** one-time R2 `constraint_loc` normalization via existing `constraint_loc_normalize.py`; cross-variant analysis keys on `driver_version`.

---

## 8. Spec §15 status changes

| ID | Before | After |
|----|--------|-------|
| **ISS-6** | OPEN | **RESOLVED** (Batch 3) — `ArmKey.parse(decision.arm_id)` dispatch |
| **ISS-7** | OPEN | **RESOLVED** (Batch 3) — `_capture_baseline_trace()` in `_setup_v2_bandit` |
| **ISS-5** (Batch 3 half) | deferred | **RESOLVED** — `outcome=` writes on driver + fuzzer Arguzz paths |
| **ISS-1** | RESOLVED (bridge) | unchanged — D2.G fault-corroboration residual still OPEN |
| **ISS-2** | RESOLVED KEEP 437 | unchanged |
| **F12** | — | logged in resolution log — N=10000 for cTS variants at Phase 3/D2.F |

Full §15 table updated in `IV_POS_8_D2_C_SPEC.md`.

---

## 9. Test counts vs 654/21 floor

```text
$ python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py
655 passed, 27 skipped
```

**Delta vs Batch 2 floor:** +1 passed (Tier-2 DB byte-identity test); +6 skipped (Layer-5 smoke module + related gating).

**Batch 3 new tests:**

| File | Role |
|------|------|
| `test_d2c_golden_trace_v5_db_byte_identity.py` | Tier-2 regression gate |
| `test_d2c_v6_uniform_driver_smoke.py` | Layer-5 gating (6 cases; CGC may skip) |

**Golden traces after full Batch 3:** Tier-1 2/2 + Tier-2 1/1 green.

---

## 10. Deviations + open questions for Batch 4

### D1 — `CTS_SEMANTIC_V2_FAMILY` split (Central Planner refinement)

Kickoff draft added `v6_cTS`/`hybrid_cTS` into `CTS_SEMANTIC_V2_FAMILY`, breaking `test_cts_family_contains_all_v5_selectors`. **Fix:** restored V5-only set; introduced `ALL_SEMANTIC_CTS_STRATEGIES` for shared cTS logic. V5 code paths gated on the original 3-member set where semantics differ (campaign_params floor serialization for V5-only is unchanged).

### D2 — `get_valid_steps` / `get_targets_at_step` required `baseline_trace` (Batch 2, Opus-approved)

Unchanged in Batch 3; threads cleanly into fuzzer `_capture_baseline_trace()`.

### D3 — Hook 3 / CGC empty on `--inject` path

Driver and fuzzer pass `A4_FAMILY_RESIDUE=1`, CGC extractor is wired, but current `sha2-host` emits `<constraint_fail>` tags without `<a4_family_residue>` under `--inject`. Layer-5 CGC assertion **skips with documented reason** rather than failing. R2 spec §6.4 notes C3 was "not in default R2 V6" — consistent. **Batch 4 / D2.G:** confirm whether POS env or binary build enables Hook 3 on inject; re-enable strict CGC assert if tags appear.

### D4 — Layer-5 subprocess timeout

Initial 600s timeout insufficient for N=50 (~771s observed). Raised fixture timeout to **1800s**.

### D5 — Fuzzer Arguzz invoke bypasses `create_mutation_for_arm`

To pass `A4_FAMILY_RESIDUE=1` without editing frozen `arguzz_bridge.py`, `_run_arguzz_cts_mutation` calls `arguzz_run()` directly and builds config inline (mirrors bridge). **Batch 4 option:** add optional `env=` to bridge API in a bridge-touching batch.

### Open for Batch 4

- `test_d2c_hybrid_smoke.py` (Layer 6 forerunner) — stub + `hybrid_cTS` both surfaces.
- CLI registration (`--selector=v6_cTS`, etc.) — D2.D.
- Augment `test_d2c_arguzz_bridge.py` with dispatch/outcome assertions (ISS-5 residual test scope).
- **F12:** D2.F campaign design — prefer **N=10000** for V6-cTS/Hybrid-cTS (437 × 3 cold-start ≈ 22% of N=6000 budget vs ~0% for V6-uniform round-robin).

---

## 11. Acceptance checklist (Batch 3)

- [x] `v6_uniform_driver.py` end-to-end; bootstrap verbatim; CoverageDB; `driver_version="v3_d2c"`.
- [x] `fuzzer.py` recognizes `v6_cTS`/`hybrid_cTS`; ISS-6/ISS-7; `arguzz_timeout=90.0`.
- [x] `mutations.outcome` populated on Arguzz rows.
- [x] `applied_accounting_mode=True` for Arguzz strategies only; `update_with_outcome` on Arguzz path.
- [x] Tier-1 + Tier-2 golden traces green.
- [x] Layer-5 smoke green (CGC skipped — documented).
- [x] Soundness/gap counts reported.
- [x] Schema-parity documented.
- [x] Pytest sweep ≥654/21 + new tests.
- [x] Frozen files untouched.
- [x] §15 updated (ISS-6/ISS-7/ISS-5).
- [x] This report submitted.

---

*End of D2.C Batch 3 Composer report. Ready for Opus review → Batch 4 kickoff.*
