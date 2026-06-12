# Phase 7d — Increment 1.5 Report

## Summary

- **D50 implemented:** `core_div` / `core_shr` split by DIV0 minor (0–3 → `core_shr`, 4–7 → `core_div`).
- **D53 implemented:** `post_ecall` = first user-PC Decode step in `[e+1, e+5]` per ECALL.
- **D54 implemented:** HYBRID `kernel_other` zone with classifier precedence (after singletons / pre_ecall / post_ecall).
- **E3b investigation:** Theme 6 dossier at `audit_output/E3b_mem_val_non_memory_majors.json`.
- **EXPECTED_ARMS.md:** baseline section regenerated from A3 output; PRE-HYBRID disclaimer removed.

## Acceptance gate results

| Gate | Status | Numbers |
|---|---|---|
| A3 arm count | **FAIL** | **48** kept (work-order threshold ≥50; see surprises below) |
| A4 success_rate | **PASS** | 48/48 arms, all `success_rate=1.0`, `n_arms_zero_targets=0` |
| A5 canonical match | **PASS** | doc=48, actual=48, 0 added/removed, 0 step-count violations |
| E6 verification | **PASS** | `post_ecall` = **32** steps (gate 30–32); offsets e+1 (14) and e+4 (18); **18** ECALLs with offset >1 |
| E7 verification | **PASS** | `kernel_other` = **356** steps (E7 predicted ~357, within ±5%) |
| E3b dossier | **DONE** | `audit_output/E3b_mem_val_non_memory_majors.json` |
| Fast tests | **PASS** | **460** passed, 7 skipped (`pytest a4/standalone/tests/` from repo root) |

**Note on fast tests:** run from `/root/arguzz` so `run_replicates` subprocesses resolve `a4.*` modules. Running pytest with `cwd=a4/` fails 3 e2e replicates tests immediately (`ModuleNotFoundError: a4`).

## Implementation details (D50 / D53 / D54)

### D50 — `core_shr`

- `semantic_zones.py`: 19 zones; `major_minor_to_core_zone()` splits major=4 by minor.
- Baseline guest: **zero** user-PC DIV/REM cycles → `core_div` zone empty; 22 steps in `core_shr`.

### D53 — `post_ecall` window

- `zone_classifier.py`: for each ECALL step `e`, smallest `k∈[1,5]` where step `e+k` has primary Decode at user PC.
- Replaces old `e+1`-only rule; kernel-handler intermediates fall through to `kernel_other` (D54).

### D54 — `kernel_other`

- Precedence: step0 → last_step → pre_ecall → post_ecall → kernel_other (kernel PC primary Decode) → core_* .
- `KERNEL_PC_RANGE = (0xC0000000, 0xC1000000)`, `USER_PC_RANGE = (0x00200000, 0x00400000)`.
- Step 0 stays `step0`; ECALL cycles stay `pre_ecall`; other kernel-PC steps → `kernel_other`.

## New arm counts (48 kept)

| arm | steps |
|---|---:|
| COMP_OUT_MOD\|core_arithmetic | 1685 |
| COMP_OUT_MOD\|core_mul | 66 |
| COMP_OUT_MOD\|core_shr | 22 |
| COMP_OUT_MOD\|post_ecall | 16 |
| INSTR_TYPE_MOD\|core_arithmetic | 2226 |
| INSTR_TYPE_MOD\|core_memory_load | 584 |
| INSTR_TYPE_MOD\|core_memory_store | 586 |
| INSTR_TYPE_MOD\|core_mul | 66 |
| INSTR_TYPE_MOD\|core_shr | 22 |
| INSTR_TYPE_MOD\|kernel_other | 356 |
| INSTR_TYPE_MOD\|post_ecall | 32 |
| INSTR_TYPE_MOD\|pre_ecall | 18 |
| INSTR_TYPE_MOD\|step0 | 1 |
| INSTR_WORD_MOD_FULL\|core_arithmetic | 2226 |
| INSTR_WORD_MOD_FULL\|core_memory_load | 584 |
| INSTR_WORD_MOD_FULL\|core_memory_store | 586 |
| INSTR_WORD_MOD_FULL\|core_mul | 66 |
| INSTR_WORD_MOD_FULL\|core_shr | 22 |
| INSTR_WORD_MOD_FULL\|kernel_other | 356 |
| INSTR_WORD_MOD_FULL\|post_ecall | 32 |
| INSTR_WORD_MOD_SUR\|core_arithmetic | 2226 |
| INSTR_WORD_MOD_SUR\|core_memory_load | 584 |
| INSTR_WORD_MOD_SUR\|core_memory_store | 586 |
| INSTR_WORD_MOD_SUR\|core_mul | 66 |
| INSTR_WORD_MOD_SUR\|core_shr | 22 |
| INSTR_WORD_MOD_SUR\|kernel_other | 356 |
| INSTR_WORD_MOD_SUR\|post_ecall | 32 |
| LOAD_VAL_MOD\|core_memory_load | 584 |
| LOAD_VAL_MOD\|post_ecall | 4 |
| MEM_VAL_MOD\|core_arithmetic | 636 |
| MEM_VAL_MOD\|core_branch | 24 |
| MEM_VAL_MOD\|core_memory_load | 584 |
| MEM_VAL_MOD\|core_memory_store | 586 |
| MEM_VAL_MOD\|kernel_other | 356 |
| MEM_VAL_MOD\|last_step | 1 |
| MEM_VAL_MOD\|post_ecall | 16 |
| MEM_VAL_MOD\|pre_ecall | 32 |
| MEM_VAL_MOD\|step0 | 1 |
| PRE_EXEC_REG_MOD\|core_arithmetic | 2226 |
| PRE_EXEC_REG_MOD\|core_memory_load | 584 |
| PRE_EXEC_REG_MOD\|core_memory_store | 586 |
| PRE_EXEC_REG_MOD\|core_mul | 66 |
| PRE_EXEC_REG_MOD\|core_shr | 22 |
| PRE_EXEC_REG_MOD\|kernel_other | 83 |
| PRE_EXEC_REG_MOD\|post_ecall | 32 |
| PRE_EXEC_REG_MOD\|step0 | 1 |
| STORE_OUT_MOD\|core_memory_store | 586 |
| STORE_OUT_MOD\|kernel_other | 10 |

**Dropped (13):** 9 phantom + 4 D40 — see `EXPECTED_ARMS.md` Expected-DROPPED table.

**Delta vs Inc 1 (44 kept):** +4 arms net — new `kernel_other` / `core_shr` labels; offset by phantom drops (`MEM_VAL_MOD|core_mul`, `MEM_VAL_MOD|core_shr`, `COMP/LOAD|kernel_other`).

## E3b — MEM_VAL on non-memory majors (Theme 6)

- Script: `a4/audits/E3b_mem_val_non_memory_majors.py`
- `MEM_VAL_MOD|core_arithmetic`: 636 steps, 902 mem txns — mostly register-file (`0xffff…`) and user-data witnesses co-located with ALU steps.
- `MEM_VAL_MOD|core_mul`: **0 steps** post-HYBRID (MUL steps at user PC; arm dropped from universe as phantom for MEM_VAL).
- Verdict: targets are real consistency witnesses, not scratch phantoms; keep arms; D42 nondet still pending E2.

## Files changed (Inc 1.5 scope)

| File | Change |
|---|---|
| `a4/standalone/semantic_zones.py` | 19 zones, PC ranges, D50 minor split |
| `a4/standalone/zone_classifier.py` | D53/D54 precedence classifier |
| `a4/audits/E3b_mem_val_non_memory_majors.py` | new Theme 6 audit |
| `a4/audits/audit_common.py` | flexible Kept-arms parser |
| `a4/audits/E3_uncertain_arm_review.py` | classifier reasoning for D50/D53/D54 |
| `a4/docs/cloud1/EXPECTED_ARMS.md` | regenerated baseline (48 arms); disclaimer removed |
| `a4/standalone/tests/test_zone_classifier.py` | D50/D53/D54 tests |
| `a4/standalone/tests/test_semantic_zone_dataclasses.py` | 19-zone + D50 tests |
| `a4/standalone/tests/test_v5_phantom_arm_pruning.py` | kernel_other phantom case |
| `a4/standalone/tests/test_semantic_arm_universe.py` | user PC on post_ecall fixture step |
| `audit_output/A3_arms_in1_5_in4_10.json` | regenerated |
| `audit_output/A4_module_targets.json` | regenerated |
| `audit_output/A5_canonical_diff.json` | regenerated |
| `audit_output/E3b_mem_val_non_memory_majors.json` | new |

**Not touched (per hard rules):** `inspection_data.py`, Rust hooks.

## Open items / surprises

1. **A3 gate miss (48 < 50):** Work-order estimate assumed ~50–52 from “48 naive − 4 D40 + core_shr + kernel_other”. On this guest, D50 **renames** `core_div`→`core_shr` (no new arm for `core_div`), and three intersections phantom-drop (`MEM_VAL|core_mul`, `MEM_VAL|core_shr`, `COMP/LOAD|kernel_other`). Net +4 vs Inc 1’s 44-arm baseline, not +6–8. Implementation matches D50/D53/D54 spec; threshold may need Opus adjudication (arm count ≤55 invariant still holds).

2. **`core_div` zone empty** on `c0c1_differential_guest` — all major=4 activity is SRL/SRA (minor 0–3). Documented in EXPECTED_ARMS empty-zones table.

3. **`LOAD_VAL_MOD|post_ecall`** grew 2→4 steps after D53 window (still 🟡 / Q5).

4. **`MEM_VAL_MOD|core_arithmetic`** step count 848→636 after HYBRID reclassification (kernel-PC steps moved to `kernel_other`).

## Ready-to-proceed

Inc 1.5 implementation is complete. **6/7 acceptance gates green; A3 arm-count gate FAIL (48 vs ≥50).** Awaiting Opus review before Increment 2 (B3, B5, B6, B9, B10, E2).
