# C1 Pilot Report

**Status:** FAIL
**Generated:** 2026-06-12T05:29:39.490313+00:00

## Throughput

- Avg duration: 109935.6 ms/run
- Active runs: 550 (skipped: 50)
- Est. C2 @ 500/kind/fuzzer: 183.23 h

## Outcome class distribution (fuzzer × kind)

### a4/COMP_OUT_MOD
- CONSTRAINT_REJECT: 40

### a4/INSTR_WORD_MOD_FULL
- CONSTRAINT_REJECT: 50

### a4/LOAD_VAL_MOD
- CONSTRAINT_REJECT: 20

### a4/MEM_VAL_MOD
- CONSTRAINT_REJECT: 50

### a4/PRE_EXEC_REG_MOD
- CONSTRAINT_REJECT: 40

### a4/STORE_OUT_MOD
- CONSTRAINT_REJECT: 50

### arguzz/COMP_OUT_MOD
- CONSTRAINT_REJECT: 32
- OTHER_CRASH: 3
- VERIFY_REJECT: 15

### arguzz/INSTR_WORD_MOD
- CONSTRAINT_REJECT: 13
- GLOBAL_REJECT: 6
- VERIFY_REJECT: 31

### arguzz/LOAD_VAL_MOD
- CONSTRAINT_REJECT: 19
- VERIFY_REJECT: 31

### arguzz/PRE_EXEC_MEM_MOD
- CONSTRAINT_REJECT: 47
- PREFLIGHT_CRASH: 3

### arguzz/PRE_EXEC_REG_MOD
- CONSTRAINT_REJECT: 44
- PREFLIGHT_CRASH: 3
- VERIFY_REJECT: 3

### arguzz/STORE_OUT_MOD
- CONSTRAINT_REJECT: 45
- OTHER_CRASH: 1
- VERIFY_REJECT: 4

## Fail category (primary)

### a4/COMP_OUT_MOD
- L2: 40

### a4/INSTR_WORD_MOD_FULL
- L1: 22
- L2: 28

### a4/LOAD_VAL_MOD
- L2: 20

### a4/MEM_VAL_MOD
- L1: 8
- L2: 42

### a4/PRE_EXEC_REG_MOD
- L1: 2
- L2: 38

### a4/STORE_OUT_MOD
- L2: 50

### arguzz/COMP_OUT_MOD
- L1: 5
- L2: 27
- NONE: 18

### arguzz/INSTR_WORD_MOD
- G: 6
- L1: 4
- L2: 9
- NONE: 31

### arguzz/LOAD_VAL_MOD
- L2: 19
- NONE: 31

### arguzz/PRE_EXEC_MEM_MOD
- L1: 3
- L2: 44
- NONE: 3

### arguzz/PRE_EXEC_REG_MOD
- L1: 3
- L2: 41
- NONE: 6

### arguzz/STORE_OUT_MOD
- L2: 45
- NONE: 5

## Reachability

- **a4/COMP_OUT_MOD**: 40/40 (100.0%)
- **a4/INSTR_WORD_MOD_FULL**: 50/50 (100.0%)
- **a4/LOAD_VAL_MOD**: 20/20 (100.0%)
- **a4/MEM_VAL_MOD**: 50/50 (100.0%)
- **a4/PRE_EXEC_REG_MOD**: 40/40 (100.0%)
- **a4/STORE_OUT_MOD**: 50/50 (100.0%)
- **arguzz/COMP_OUT_MOD**: 50/50 (100.0%)
- **arguzz/INSTR_WORD_MOD**: 50/50 (100.0%)
- **arguzz/LOAD_VAL_MOD**: 50/50 (100.0%)
- **arguzz/PRE_EXEC_MEM_MOD**: 50/50 (100.0%)
- **arguzz/PRE_EXEC_REG_MOD**: 50/50 (100.0%)
- **arguzz/STORE_OUT_MOD**: 50/50 (100.0%)

## Soundness escapes

Total: 0

## Acceptance gate

- c0_still_pass: True
- outcome_classes_ge_5: True
- outcome_classes_observed: 5
- both_fuzzers_all_kinds: False
- sanity_checks: {'a4_register_reach_approx_100pct': True, 'arguzz_nonzero_crash_rate': True, 'a4_register_l2g_fail_mass': True}
- determinism: True
- host_unchanged: True

**Gate passed:** False

## Outcome class examples (for hand verification)

- **CONSTRAINT_REJECT**: arguzz/PRE_EXEC_REG_MOD seed=0 step=0 log=/root/arguzz/thesis_side_experiments/bias_campaign/artifacts/c1/logs/arguzz_PRE_EXEC_REG_MOD_0.txt
- **VERIFY_REJECT**: arguzz/PRE_EXEC_REG_MOD seed=5 step=5 log=/root/arguzz/thesis_side_experiments/bias_campaign/artifacts/c1/logs/arguzz_PRE_EXEC_REG_MOD_5.txt
- **PREFLIGHT_CRASH**: arguzz/PRE_EXEC_REG_MOD seed=10 step=10 log=/root/arguzz/thesis_side_experiments/bias_campaign/artifacts/c1/logs/arguzz_PRE_EXEC_REG_MOD_10.txt
- **OTHER_CRASH**: arguzz/COMP_OUT_MOD seed=32 step=46 log=/root/arguzz/thesis_side_experiments/bias_campaign/artifacts/c1/logs/arguzz_COMP_OUT_MOD_32.txt
- **GLOBAL_REJECT**: arguzz/INSTR_WORD_MOD seed=2 step=2 log=/root/arguzz/thesis_side_experiments/bias_campaign/artifacts/c1/logs/arguzz_INSTR_WORD_MOD_2.txt
