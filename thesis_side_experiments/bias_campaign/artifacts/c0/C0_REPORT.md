# C0 Report — Parity Harness + Category Classifier

**Status:** PASS

Runtime: 138.82s

## Acceptance gate
- **unit_tests_pass**: True
- **A4_a1_M2_match**: True
- **arguzz_a1_preflight_crash**: True
- **arguzz_s9_constraint_reject_7**: True
- **targeting_37_contexts**: True
- **determinism_all_cases**: True
- **production_host_mtime_unchanged**: True
- **all_pass**: True

## Cases
### baseline
- outcome: **VALID_NO_SIGNAL**
- FAIL categories: {'L1': 0, 'L2': 0, 'ACCUM': 0}
- G families: {'memory': False, 'u16': False, 'u8': False, 'cycle': False, 'any': False}
- determinism 2×: **True**

### A4-a1
- outcome: **CONSTRAINT_REJECT**
- FAIL categories: {'L1': 0, 'L2': 2, 'ACCUM': 0}
- G families: {'memory': True, 'u16': False, 'u8': False, 'cycle': False, 'any': True}
- TARGET (add local): {'local_context_count': 37, 'target_L1': 26, 'target_L2': 11, 'accum_universe_total': 298, 'matches_m1_universe_count': True}
- failures:
  - [L2] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` value=2013265916
  - [L2] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at…` value=2013265916
- determinism 2×: **True**

### Arguzz-a1
- outcome: **PREFLIGHT_CRASH**
- FAIL categories: {'L1': 0, 'L2': 0, 'ACCUM': 0}
- G families: {'memory': False, 'u16': False, 'u8': False, 'cycle': False, 'any': False}
- determinism 2×: **True**

### Arguzz-s9
- outcome: **CONSTRAINT_REJECT**
- FAIL categories: {'L1': 3, 'L2': 4, 'ACCUM': 0}
- G families: {'memory': True, 'u16': False, 'u8': False, 'cycle': True, 'any': True}
- failures:
  - [L2] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` value=2013265740
  - [L2] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` value=2013264847
  - [L2] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at…` value=2013238918
  - [L2] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at…` value=2013229530
  - [L1] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir…` value=72
  - [L1] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir…` value=6
  - [L1] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir…` value=71
- determinism 2×: **True**

## Isolation
- production `risc0-host` mtime unchanged: **True**
