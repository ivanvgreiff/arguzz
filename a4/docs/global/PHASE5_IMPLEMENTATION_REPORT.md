# Phase 5 Implementation Report: Main Fuzzer Integration

## Summary

Phase 5 integrated Hook 3 (per-family residues + per-address broken chain detail) into the MAIN A4 standalone fuzzer (`a4.standalone.cli fuzz`). Every mutation now shows human-readable global constraint information alongside existing local constraint details.

---

## Changes Made

### 1. executor.py
- Added `A4_FAMILY_RESIDUE=1` to `run_a4_mutation` env vars
- Added `family_residues` and `family_details` fields to `MutationExecutionResult`
- Parse Hook 3 tags (`parse_family_residues`, `parse_family_detail`) from combined output

### 2. fuzzer.py
- Added `broken_families`, `broken_addresses`, `is_global_only`, `family_stats` fields to `MutationResult`
- Added `global_violations`, `global_only`, `local_only` fields to `CampaignStats`
- Updated `_classify_outcome` to recognize global violations as "REJECTED"
- Updated `_run_single_mutation` and `_run_bandit_mutation` to populate global fields from exec_result
- Updated `_print_mutation_result` with rich global display:
  - Status line shows `G=memory[GO]` for global-only, `G=memory` for local+global
  - Local and accum constraints shown separately
  - Global violations section with per-address broken chain detail and register names
- Updated `_update_stats` to count global_violations, global_only, local_only
- Updated `_print_campaign_summary` with Global Constraint Summary section
- Fixed duplicate outcome classification (removed inline code that overwrote `_classify_outcome` result)
- Fixed status icon: `✓` now shows for global-only violations (previously showed `○`)

---

## Deviations from Plan

**Bug fix: Duplicate outcome classification.** The `_print_mutation_result` method had an inline outcome classification (lines 1322-1329) that overrode the `_classify_outcome` call. This inline code didn't check `broken_families`, causing global-only mutations to show `outcome: NO_EFFECT`. Removed the duplicate code.

**Bug fix: Non-bandit path missing global fields.** The `_run_single_mutation` method (non-bandit path) wasn't populating `broken_families` and `broken_addresses` from exec_result. Added the same global field extraction logic used in the bandit path.

---

## Test Results

### T1: 5 mutations (all kinds, seed 42)

All 5 mutations showed local constraints only. Global constraint info correctly shows "no permutation/lookup violations (local-only)":

```
[1] ✓ LOAD_VAL_MOD @ step 317: 1 failures, outcome: REJECTED, G not shown
       Local constraints hit (1 unique):
         - MemoryWrite@mem.zir:100
       Global: no permutation/lookup violations (local-only)

[2] ✓ COMP_OUT_MOD @ step 1409: 2 failures, outcome: REJECTED
       Local constraints hit (2 unique):
         - MemoryWrite@mem.zir:100
         - MemoryWrite@mem.zir:99
       Global: no permutation/lookup violations (local-only)
```

### T2: INSTR_WORD_MOD_SUR (10 mutations, seed 42)

3 out of 10 mutations were global-only (mutations [2], [4], [10]):

**Global-only mutation [2] (rd = 9 -> 14):**
```
[2] ✓ INSTR_WORD_MOD_SUR @ step 1016: 0 failures, outcome: REJECTED, G=memory[GO]
       Surgical: rd = 9 -> 14
       Original: LW x9, 4(x2)
       Mutated:  LW x14, 4(x2)
       Global violations: memory permutation [GLOBAL-ONLY]
         - 0x00080c7c: 11 +entries, 11 -entries -- chain mismatch
         - x9 (0x3fffc029): 177 +entries, 177 -entries -- chain mismatch
         - x14 (0x3fffc02e): 532 +entries, 532 -entries -- chain mismatch
```

Human interpretation: "Changed LW destination from x9 to x14. No local constraints detected the change. But the memory permutation caught it: register x9 has an imbalanced read-write chain (expected a write that went to x14 instead), and register x14 has an imbalanced chain (received an unexpected write). The PC address also has a mismatch (the instruction fetch word was changed)."

**Local+global mutation [3] (opcode change):**
```
[3] ✓ INSTR_WORD_MOD_SUR @ step 3034: 1 failures, outcome: REJECTED, G=memory
       Surgical: opcode = 111 -> 22
       Original: JAL x0, 336
       Mutated:  UNKNOWN 0x15000016
       Local constraints hit (1 unique):
         - VerifyOpcode@inst.zir:91
       Global violations: memory permutation
         - 0x30000052: 28 +entries, 28 -entries -- chain mismatch
         - ... (additional broken addresses)
```

Human interpretation: "Changed JAL to an unknown opcode. Local constraint VerifyOpcode caught the opcode mismatch. Additionally, the memory permutation broke at address 0x30000052."

### Campaign Summary Output

```
Global Constraint Summary:
  Mutations with global violations: X
  Global-only (no local failures):  Y
  Local-only (no global violations):Z
```

---

## How the Terminal Output Now Looks Per Mutation

### For a local-only mutation (most common):
```
[N] ✓ COMP_OUT_MOD @ step 785: 2 failures, 15234ms, outcome: REJECTED, exit: 101 [proof:GENERATED]
       Value: 0x00000003 -> 0x045C6103
       Destination: rd = x12 (a2)
       Local constraints hit (2 unique):
         - MemoryWrite@mem.zir:99
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
       Global: no permutation/lookup violations (local-only)
```

### For a global-only mutation (the premium bucket):
```
[N] ✓ INSTR_WORD_MOD_SUR @ step 1016: 0 failures, 32627ms, outcome: REJECTED, exit: 101 [proof:GENERATED] G=memory[GO]
       Value: 0x00412483 -> 0x00412703
       Surgical: rd = 9 -> 14
       Original: LW x9, 4(x2)
       Mutated:  LW x14, 4(x2)
       Global violations: memory permutation [GLOBAL-ONLY]
         - 0x00080c7c: 11 +entries, 11 -entries -- chain mismatch
         - x9 (0x3fffc029): 177 +entries, 177 -entries -- chain mismatch
         - x14 (0x3fffc02e): 532 +entries, 532 -entries -- chain mismatch
```

### For a local+global mutation:
```
[N] ✓ INSTR_TYPE_MOD @ step 3048: 5 failures, 18631ms, outcome: REJECTED, exit: 101 [proof:GENERATED] G=memory
       Original: JalR [major=2, minor=4]
       Mutated:  Sb [major=6, minor=0]
       Local constraints hit (4 unique):
         - IsRead@mem.zir:79
         - MemoryWrite@mem.zir:99 (x2)
         - MemoryWrite@mem.zir:100
         - VerifyOpcodeF3@inst.zir:96
       Global violations: memory permutation
         - 0x00080c7d: 11 +entries, 11 -entries -- chain mismatch
         - x1 (0x3fffc021): 664 +entries, 664 -entries -- chain mismatch
```

---

## What Each Piece of Information Means

| Output Element | Meaning |
|---|---|
| `✓` | Mutation was detected (constraints broken or global violation) |
| `0 failures` | No local/accum EQZ constraints failed |
| `outcome: REJECTED` | Proof was rejected (even without local failures, global violation is sufficient) |
| `G=memory[GO]` | Memory permutation broken, GLOBAL-ONLY (no local failures) |
| `G=memory` | Memory permutation broken (local failures also present) |
| `x9 (0x3fffc029): 177 +entries, 177 -entries` | Register x9's read-write chain has 177 entries on each side but they don't cancel (the hash-weighted sum is non-zero) |
| `[GLOBAL-ONLY]` | This mutation broke only global constraints, not any local constraints |
| `chain mismatch` | The LogUp sum for this address is non-zero -- reads and writes don't balance |
