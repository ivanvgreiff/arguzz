# D2.C Batch 4 — Composer Report (closure)

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) v0.5 + §15 annex  
**Kickoff:** [`D2C_BATCH4_COMPOSER_KICKOFF.md`](D2C_BATCH4_COMPOSER_KICKOFF.md) (updated per Central Planner F13)  
**Date:** 2026-06-20  
**HEAD:** `7182237c8245e7a5d7c1309d3f38671c25f4934e` (D2.C Batches 1–4 uncommitted)  
**Status:** Implementation complete — **not committed**

---

## 0. Central Planner feedback — disposition

| Feedback | Action | Pushback? |
|----------|--------|-----------|
| **Do NOT run task 4.4 as originally written** (wrong premise + false "no CGC channel" branch) | Accepted. Fixed F13 **before** POS staging; rewrote kickoff task 4.4. | **None** — diagnosis was correct; Batch 3 report was wrong. |
| Add `A4_COVERAGE_TOUCH=1` co-trigger in bridge default env | Implemented `DEFAULT_ARGUZZ_SUBPROCESS_ENV` | None |
| Verify locally ≤10 mutations: CGC + global_failures non-empty | **CGC=16, global_failures=54** at N=10 | None — empirically confirms F13 |
| ISS-9: single bridge entry point | Fuzzer + driver both use `create_mutation_for_arm` | None |
| Reframe 4.4 as scale validation, delete line-80 limitation branch | Kickoff updated; POS manifest authored | None |
| F12 N=10000 unchanged | Carried in §15 resolution log | N/A |

---

## 1. Pre-flight

```text
Floor (post-Batch-3): 655 passed, 27 skipped
Golden traces before Batch 4: Tier-1 2/2 + Tier-2 1/1 green
```

---

## 2. F13 fix — ISS-8 root cause (done FIRST, before task 4.4)

### 2.1 Problem

Batch 3 set only `A4_FAMILY_RESIDUE=1`. Hook-3 capture in `ffi.cpp` requires **`A4_FAMILY_RESIDUE && (A4_MUTATION_CONFIG || A4_COVERAGE_TOUCH)`**. Without `A4_COVERAGE_TOUCH`, capture is off → empty `family_residues` → empty CGC. This is a **config bug**, not "Arguzz has no CGC channel."

### 2.2 Code change — `arguzz_bridge.py`

Added:

```python
DEFAULT_ARGUZZ_SUBPROCESS_ENV = {
    "A4_FAMILY_RESIDUE": "1",
    "A4_COVERAGE_TOUCH": "1",
}
```

Updated `create_mutation_for_arm(..., env: Optional[dict] = None)`:

- Starts from `DEFAULT_ARGUZZ_SUBPROCESS_ENV`
- Merges optional caller `env` on top
- Forwards to `arguzz_invoke.run(..., env=subprocess_env)`
- **Does not** use `A4_MUTATION_CONFIG` (would double-mutate)

### 2.3 Local verification (decisive, ≤10 mutations)

```bash
python -m a4.standalone.v6_uniform_driver \
  --host workspace/output/target/release/risc0-host \
  --db /tmp/v6_cgc_fix.db --seed 1243 --num 10 \
  --progress-every 10 --label cgc_fix_verify -- --in1 5 --in4 10
```

| Metric | Before F13 (Batch 3) | After F13 (Batch 4) |
|--------|----------------------|---------------------|
| `compressed_global_coverage` | **0** | **16** |
| `global_failures` | **0** | **54** |
| `mutations` | 10 | 10 |
| outcomes | applied=8, skipped=2 | applied=8, skipped=2 |

**ISS-8 reclassified:** RESOLVED (local) — config bug fixed + verified.

---

## 3. Task 4.3 — ISS-9 bridge reconciliation

### 3.1 `fuzzer.py`

- Removed direct `arguzz_invoke.run` import/call from `_run_arguzz_cts_mutation`
- Restored `create_mutation_for_arm(arm, step, …)` as sole Arguzz invoke path
- Default env (both co-triggers) inherited from bridge — no caller `env=` needed

### 3.2 `v6_uniform_driver.py`

- Removed direct `arguzz_run` call
- Builds `ArmKey(ARGUZZ_EXEC_FAULT, kind, zone, opcode_class, pre_post)` from scheduler pick + `MAPPING_INSTR_TO_OPCODE_CLASS`
- Calls `create_mutation_for_arm`; merges driver fields (`instruction`, `iter_seed`, `wall_s`, `rc`, `prover_status`, `zone`, `major`) onto bridge `config`

### 3.3 `test_d2c_arguzz_bridge.py`

- Added `test_default_subprocess_env_includes_hook3_co_trigger`
- Updated mock assert to expect `env=dict(DEFAULT_ARGUZZ_SUBPROCESS_ENV)`

### 3.4 Golden traces

```text
test_d2c_golden_trace_v5_decision_seq.py — 2/2 PASSED
test_d2c_golden_trace_v5_db_byte_identity.py — 1/1 PASSED
```

V5 path untouched; byte-identical.

---

## 4. Task 4.1 — Layer-6 Hybrid forerunner

**File:** `test_d2c_hybrid_smoke.py` (NEW, ~178 LOC)

- Stubbed `create_mutation_for_arm`, `run_a4_mutation`, baseline touch/trace
- `A4Fuzzer.run_campaign(N=50, selector_strategy="hybrid_cTS")`
- Asserts:
  - ≥1 Arguzz arm via mock
  - DB contains both Arguzz SELECTED kinds and A4 `INSTR_TYPE_MOD`
  - `update_with_outcome` called for Arguzz surface
  - Scheduler `pulls` includes both `arguzz_exec_fault` and `A4_trace_cell`

```text
test_d2c_hybrid_smoke.py — 1 passed in 3.47s
```

---

## 5. Task 4.2 — cross-cutting registration (66 cases)

**File:** `test_d2c_arm_registration.py` (NEW, ~108 LOC)

Parametrize `MUTATION_KINDS_ARGUZZ_FULL` (11) × 6 layers:

| Layer | Assertion |
|-------|-----------|
| 1 | `kind in ENABLED_KINDS` + FULL constant |
| 2 | `_PRE_POST_BY_KIND` entry |
| 3 | `get_valid_steps` ≥1 on fixture trace |
| 4 | `opcode_class_for_step` in mapping values |
| 5 | `SemanticArmUniverse` has Arguzz arm |
| 6 | `ArmKey.parse(str(arm))` round-trip + `ARGUZZ_EXEC_FAULT` |

```text
test_d2c_arm_registration.py — 66 passed
```

---

## 6. Task 4.4 — ISS-8 POS scale validation (reframed)

### 6.1 Layer-5 local test refactor

**File:** `test_d2c_v6_uniform_driver_smoke.py`

| Change | Detail |
|--------|--------|
| N=50 → **N=10** | POS-run policy compliance |
| Removed | kind-coverage ≥6/11 (POS job) |
| Removed | conditional CGC skip |
| Added | **strict** `compressed_global_coverage >= 1` |
| Added | **strict** `global_failures >= 1` |
| Timeout | 600s (sufficient for N=10) |

### 6.2 POS manifest (staged)

**File:** `a4/pos/manifests/iv_pos_8/d2c_v6_uniform_smoke.json`

- N=50, seed=1243, `v6_uniform_driver`
- Purpose: **scale-validate** corrected path (not re-diagnose CGC)

### 6.3 POS dispatch (executed)

**Yes — task 4.4 was Batch 4.** It was staged at report write time; executed on **flare** (pre-reserved, `ALLOC_DURATION=0`) after user confirmation.

**Dispatch:**

```bash
bash a4/pos/prepare_bundle.sh --allow-dirty --skip-host-sha
scp -P 10022 bundles/a4_campaign_7182237c8245.tar.gz ivgreiff@coinbase.net.in.tum.de:~/
scp -P 10022 a4/pos/manifests/iv_pos_8/d2c_v6_uniform_smoke.json \
    ivgreiff@coinbase.net.in.tum.de:~/arguzz/a4/pos/manifests/iv_pos_8/
# Also required: dispatcher launches run_campaign_pos.sh from coinbase checkout, not bundle
scp -P 10022 a4/pos/run_campaign_pos.sh ivgreiff@coinbase.net.in.tum.de:~/arguzz/a4/pos/

ssh coinbase
source /srv/testbed/pos/cli/venv3/bin/activate && cd ~/arguzz
BUNDLE=~/a4_campaign_7182237c8245.tar.gz ALLOC_DURATION=0 \
  bash a4/pos/dispatch_audit.sh a4/pos/manifests/iv_pos_8/d2c_v6_uniform_smoke.json flare
```

**First attempt failed** (rc=255 await HTTP flake + wrong runner): coinbase's `run_campaign_pos.sh` lacked the `v6_uniform` branch, so the job fell through to `cli fuzz --selector v6_uniform` (invalid). Fixed by SCP'ing updated `run_campaign_pos.sh`; **second dispatch rc=0**.

**Local eval:**

```bash
A4_REAL_BINARY=1 A4_SMOKE_DB=a4/runs/d2c_v6_uniform_smoke/flare/d2c_v6_uniform_smoke_v1_v6_uniform_seed1243_n50.db \
  pytest a4/standalone/tests/test_d2c_v6_uniform_pos_smoke.py -v
# 6 passed
```

**POS results (flare, seed 1243, N=50):**

| Metric | Value |
|--------|-------|
| mutations recorded | 50 |
| kinds covered | **9/11** (≥6 floor met; all 4 SELECTED present) |
| outcomes | applied=47, skipped=3 |
| `compressed_global_coverage` | **88** |
| `global_failures` | **387** |
| campaign wall | ~114 s (08:10:29–08:12:23 UTC) |
| dispatch wall (incl. reset) | ~5.5 min |
| host sha | `24f23a0de02b...` |
| git in bundle | `7182237c8245` (+ dirty overlay) |

Per-kind counts: INSTR_WORD_MOD 11, PRE_EXEC_REG_MOD 7, POST_EXEC_REG_MOD 7, POST_EXEC_MEM_MOD 7, PRE_EXEC_PC_MOD 6, PRE_EXEC_MEM_MOD 5, POST_EXEC_PC_MOD 4, BR_NEG_COND 2, LOAD_VAL_MOD 1.

**ISS-8:** fully **RESOLVED** (local + POS scale).

---

## 7. Task 4.5 — plan status

**File:** `IV_POS_8_D2_PLAN.md`

- D2.C row → **DONE** (Batches 1–4, 2026-06-20)

---

## 8. Task 4.6 — full sweep

```text
723 passed, 27 skipped, 8 warnings in 105.88s
```

**Delta vs Batch 3 floor (655/27):** +68 passed

| New tests | Count |
|-----------|-------|
| `test_d2c_hybrid_smoke.py` | 1 |
| `test_d2c_arm_registration.py` | 66 |
| `test_d2c_arguzz_bridge.py` (co-trigger) | +1 |

Golden traces: green.

---

## 9. Spec §15 updates

| ID | Status |
|----|--------|
| ISS-8 | **RESOLVED** — F13 config bug; local N=10 + POS N=50 scale validated |
| ISS-9 | **RESOLVED** — bridge single entry point |
| F13 | Logged in resolution log |
| F12 | Unchanged (D2.F) |

Kickoff task 4.4 rewritten (deleted false "no CGC channel" branch).

---

## 10. Files touched (complete inventory)

### Production code

| File | Change |
|------|--------|
| `a4/standalone/mutations/arguzz_bridge.py` | `DEFAULT_ARGUZZ_SUBPROCESS_ENV`, `env=` param |
| `a4/standalone/fuzzer.py` | ISS-9: route through bridge |
| `a4/standalone/v6_uniform_driver.py` | ISS-9: route through bridge + ArmKey construction |

### Tests

| File | Change |
|------|--------|
| `test_d2c_v6_uniform_driver_smoke.py` | N=10, strict CGC/GF asserts |
| `test_d2c_v6_uniform_pos_smoke.py` | NEW — POS DB evaluator (N=50) |
| `test_d2c_hybrid_smoke.py` | NEW |
| `test_d2c_arm_registration.py` | NEW |
| `test_d2c_arguzz_bridge.py` | co-trigger env test |

### Docs / manifests

| File | Change |
|------|--------|
| `D2C_BATCH4_COMPOSER_KICKOFF.md` | Task 4.3/4.4 rewritten (F13) |
| `IV_POS_8_D2_C_SPEC.md` | §15 ISS-8/ISS-9 RESOLVED |
| `IV_POS_8_D2_PLAN.md` | D2.C → DONE |
| `a4/pos/manifests/iv_pos_8/d2c_v6_uniform_smoke.json` | NEW |
| `a4/pos/run_campaign_pos.sh` | `v6_uniform` → `v6_uniform_driver` branch |
| `D2C_BATCH4_COMPOSER_REPORT.md` | this file |

### Frozen (unchanged)

`arguzz_invoke.py`, `bandit_ts.py`, `semantic_arm_universe.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`, `workspace/risc0-modified/`

---

## 11. D2.C closure statement

All four batches implemented:

| Batch | Deliverable | Status |
|-------|-------------|--------|
| 1 | `arguzz_invoke.py` primitive + Tier-1 golden trace | ✅ |
| 2 | `arguzz_bridge.py` + arm universe extension | ✅ |
| 3 | `v6_uniform_driver.py` + fuzzer Arguzz dispatch | ✅ |
| 4 | Hybrid forerunner + 66-case registration + ISS-8/9 closure | ✅ |

**Remaining residuals (out of D2.C scope):**

- ISS-1 D2.G fault-corroboration (`--trace` rerun on soundness candidates)
- F12: N=10000 for cTS variants at D2.F
- D2.D: CLI wiring (`--selector=v6_cTS`, `hybrid_cTS`, `--variant=v6_uniform`)

---

## 12. Acceptance checklist

- [x] Layer-6 Hybrid forerunner green (stubbed)
- [x] Registration 66/66 green
- [x] ISS-9 RESOLVED; golden traces green
- [x] ISS-8 RESOLVED (F13 local + POS N=50 scale)
- [x] Sweep 723/27; no regression
- [x] D2.C plan → DONE
- [x] §15 updated
- [x] This report submitted

---

*End of D2.C Batch 4 / D2.C closure report.*
