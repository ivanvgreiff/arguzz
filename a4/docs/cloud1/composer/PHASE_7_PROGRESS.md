# Phase 7 — Composer progress (Opus-reviewed fixes)

**Date**: 2026-06-09 (updated)  
**Refs**: `PHASE_7_FIX_TASKS.md`, `PHASE_7_INVESTIGATION_REPORT.md` §1.4, Opus G3/platform.rs turn

---

## For Opus — executive summary

| Item | Status |
|------|--------|
| Tasks 1+2 (Bug A/B) | ✅ Implemented + **95 tests pass** (incl. step-list pruning) |
| D8 / G3 address map | ✅ Updated to `platform.rs`; G3 struck in `CLOUD1_DECISIONS_FOR_PRO_R2.md` |
| Hook 3 dict coercion | ✅ In `compressed_global_extractor.py` |
| Task 3 (V5 N=200 validation) | ✅ **CLOSED** — flare `bbfbf7b`, see §Task 3 results |
| Task 4 (7c verifier 24/24) | ✅ **CLOSED** — 24/24 PASS → `PHASE_7C_SEMANTIC_RESULTS_v2.json` |
| Task 5 (compressed_global) | ✅ **CLOSED** — 37 rows on fixed DB (was 0); dict coercion + D8 |

---

## Task 3: WSL vs flare — timing answer

**Yes, N=200 takes a long time on WSL. Flare is much faster.**

| Environment | Per-mutation (measured) | N=200 wall (fuzz only) | Total with setup |
|-------------|-------------------------|-------------------------|------------------|
| **flare** (7b POS) | **~2.9 s/mut** | **~7–10 min** | **~12–15 min** (incl. ~5 min POS dispatch overhead) |
| **WSL** (7a extrap.) | **~32 s/mut** (54 min / 100 mut) | **~100–110 min (~1.7 h)** | N/A |

**Speedup: ~10–11×** on flare (bare-metal EPYC vs WSL proof runs).

**Recommendation**: Run Task 3 on **flare** via POS dispatch (same path as 7b). Acceptance criteria unchanged:
1. `mutations` = **200**
2. `bandit_decisions` with **`mode != 'cold'` ≥ 1** (proves cTS escaped cold-start)
3. Final `arm_state_snapshot` = **48 arms**, all `pulls > 0`

**Prerequisite**: Rebuild bundle on WSL (includes Bug A/B + D8 + step pruning), `scp` to coinbase — POS does not have our uncommitted fixes.

**Manifest**: `a4/pos/manifests/smoke_7b/pos_smoke_7b_v5_fixed_validation.json`

**Dispatch** (on coinbase, after bundle + code sync):
```bash
python a4/pos/dispatch_pos.py \
  --manifest a4/pos/manifests/smoke_7b/pos_smoke_7b_v5_fixed_validation.json \
  --node flare
```

Local WSL Task 3 was **stopped** (missing `a4/smoke_7a_v5_fixed/` dir, tee failed; ~1.7 h projected).

---

## Tasks 1+2 — implementation detail (approved)

### Bug B (`fuzzer.py`)
- `v2_scheduler.update(..., 0)` on `config is None` skip path (cTS + kindUCB + kindTS)
- Same on kind-only `step is None` early return

### Bug A (`semantic_arm_universe.py`)
- `_filter_real_target_steps()`: scans **all** steps in arm, keeps only those with real `get_targets_at_step` hits
- Drops 5/6 §1.4.2 phantom arms; **48 arms** remain on `--in1 5 --in4 10` trace
- `MEM_VAL_MOD|core_div` step list pruned to **`[3921]`** only (was 23 coarse steps)

### Tests
- `test_v5_bandit_skip_update.py` — skip path increments pulls
- `test_v5_phantom_arm_pruning.py` — renamed `test_production_arm_count_is_48`, added `test_mem_val_core_div_step_list_pruned`
- `test_semantic_arm_universe.py` — fixtures updated for reg txns
- **95 passed** (`test_compressed_global_extractor` + bandit + universe)

---

## D8 / G3 — platform.rs map (resolved)

**File**: `compressed_global_extractor.py` `_ADDRESS_REGION_MAP`

```
zero_page [0, 0x10000)
user [0x10000, 0xBFFF0000)
user_bigint [0xBFFF0000, 0xC0000000)
kernel [0xC0000000, 0xFF000000)
machine_regs [0xFFFF0000, 0xFFFF0080)
user_regs [0xFFFF0080, 0xFFFF0100)
machine_special [0xFFFF0100, 0xFFFF1000)
ecall_dispatch [0xFFFF1000, 0xFFFF2000)
trap_dispatch_and_beyond [0xFFFF2000, 0x100000000)
```

`ADDRESS_REGIONS` in `compressed_global.py` updated. G3 marked **RESOLVED** in `CLOUD1_DECISIONS_FOR_PRO_R2.md`.

---

## Task 4 — verifier (hook stdout, ready to run)

**File**: `a4/tools/verify_mutation_semantics.py` — parses `<a4_<kind>_mod>` only (no `A4_INSPECT`).

- Hex `byte_addr` via `_int_field()`
- `INSTR_TYPE_MOD`: asserts `new_*` matches config; `old != new` only (multi-cycle ambiguity documented)

**Gate**: 24/24 → `a4/docs/cloud1/composer/PHASE_7C_SEMANTIC_RESULTS_v2.json`  
**Run after** Task 3 green (on fixed-V5 DB or existing 7b DB — sample is random).

---

## Task 5 — Hook 3 / compressed_global

See `PHASE_7_HOOK3_DIAGNOSTIC.md`:
- Log grep inconclusive (stdout not in `.log`)
- `run_a4_mutation` emits family tags; `hook3_raw` populated
- **Extractor bug**: `broken_addrs` dicts → fixed with `_coerce_broken_addr`
- D8 fix may change `compressed_global_coverage` region labels on re-run

---

## 7c history (not interpretable)

- Old verifier (pre-mutation trace): **stopped**
- Partial hook-stdout run: 17/24 (7 verifier bugs, fixed)
- Do **not** use `PHASE_7C_SEMANTIC_RESULTS.json` as fuzzer signal

---

## Task 3 results (flare, 2026-06-09)

**Job**: `pos_smoke_7b_v5_fixed_cTS_semantic_v2_seed999_n200` (rc=0, ~12.5 min)  
**DB on flare**: `/root/results_pos_smoke_7b_v5_fixed_cTS_semantic_v2_seed999_n200/pos_smoke_7b_v5_fixed_cTS_semantic_v2_seed999_n200.db` (811 KB)

| Acceptance gate | Result |
|-----------------|--------|
| `mutations` = 200 | **200** ✅ |
| `bandit_decisions.mode != 'cold'` > 0 | **56** (44 floor + 12 singleton) ✅ |
| Final `arm_state_snapshot` = 48 arms, all warm | **48 arms, 0 zero-pulls** ✅ |

**Campaign summary** (from POS log): 200 mutations, **0 skips** (was 56/144), 48 arms at setup, ~572s execution. Bandit escaped cold-start — adaptive path active via floor/singleton modes after cold-start phase.

**Mode breakdown**: cold=144, floor=44, singleton=12.

## Task 4 results

Hook-stdout verifier: **24/24 PASS** (~13 min WSL). Artifact: `PHASE_7C_SEMANTIC_RESULTS_v2.json`. G2 resolved.

## Task 5 results (on fixed Task 3 DB)

| Table | Rows |
|-------|------|
| `hook3_raw` | 200 |
| `compressed_global_coverage` | **37** (was 0 on pre-fix 7b) |

Confirms: Hook 3 plumbing OK; zero rows were **extractor** bugs (dict `broken_addrs` + wrong D8 map), now fixed.

## Remaining (Phase 8 prep)

- `bandit_skip_log` table (deferred)
- Optional: scp fixed DB from flare to WSL for archival / 7c re-run on fixed DB
- INSTR_TYPE_MOD multi-cycle step ambiguity — documented in verifier, not blocking G2

---

## Message to Opus

Tasks 1+2 + D8 + step pruning + Hook3 extractor fixes are **code-complete** and tested. Task 3 should run on **flare** (~15 min total vs ~1.7 h WSL). Please confirm bundle-rebuild + dispatch workflow, or green-light if you'll run dispatch from coinbase. Task 4 queued immediately after Task 3 acceptance numbers land.
