# INSTR_WORD_MOD Crash vs. Constraint Failure Behavior

> **For the complete, detailed analysis with source code citations, see:**
> **[INSTR_WORD_MOD_CRASH_ANALYSIS.md](./INSTR_WORD_MOD_CRASH_ANALYSIS.md)**

## Quick Summary

### Root Cause of Crashes

Crashes occur when `INSTR_WORD_MOD` mutations change the `rs1`, `rs2`, or `immediate` fields of an instruction word. The circuit handler decodes these fields from the mutated word and computes different memory/register addresses than what the original execution recorded in the preflight trace. This causes an address mismatch exception in `ffi.cpp:112-119`.

### Key Source Code Locations

| Component | File | Lines | Description |
|-----------|------|-------|-------------|
| Mutation | mod.rs | 300-301 | Sets `txn.word` and `txn.prev_word` |
| Decoding | steps.cpp | 697-698 | Extracts rs1/rs2/imm from instruction word |
| Address Calc | steps.cpp | 987-990 | Computes register address: `base + rs2` |
| Mismatch Check | ffi.cpp | 112-119 | Throws exception if `txn.addr != addr` |

### What Causes What

| Mutation Type | Fields Changed | Result |
|--------------|----------------|--------|
| Opcode only [6:0] | opcode | **Constraint Failure** |
| func3 only [14:12] | func3 | **Constraint Failure** |
| rs1 [19:15] | base address | **CRASH** |
| rs2 [24:20] | source register | **CRASH** |
| immediate [31:25,11:7] | memory offset | **CRASH** |

### Recommendation

For useful fuzzing results (constraint failures, not crashes), `INSTR_WORD_MOD` should:
1. Only mutate opcode [6:0] and/or func3 [14:12] bits
2. Preserve all other instruction fields (rs1, rs2, rd, immediate)

See the detailed analysis for the complete source code trace and verification tests.
