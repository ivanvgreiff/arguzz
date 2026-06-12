# Hook 3 Display Redesign

## Overview

This document describes the redesign of Hook 3's terminal output in the A4 fuzzer campaign. The previous display showed cryptic "+/- entry" counts and raw word addresses. The new display extracts actual mismatched data values, converts addresses to human-readable form, and summarizes cascading failures.

## Problem with the Previous Display

```
Global violations: memory permutation
  - x1 (0x3fffc021): 664 +entries, 664 -entries -- chain mismatch
  - 0x00080c7d: 11 +entries, 11 -entries -- chain mismatch
```

Issues:
1. **Equal +/- counts mislead**: `664 +entries, 664 -entries` looks balanced, but the chain IS broken (data values differ, not counts).
2. **Raw word addresses**: `0x00080c7d` is a word address; byte address is `0x002031F4`.
3. **"chain mismatch" is cryptic**: no explanation of what data actually mismatched.
4. **No data values shown**: the most important information (wrote X, expected Y) was absent.
5. **No cascade handling**: INSTR_TYPE_MOD can break 100+ addresses; listing all is noise.

## Root Cause: Why +/- Counts Are Equal But There's a Mismatch

The memory permutation uses LogUp: each write emits `+1 * inv(hash(addr, cycle, data))`, each subsequent read emits `-1 * inv(hash(addr, prev_cycle, prev_data))`. When a mutation changes data at a write, the `+1` entry carries mutated data while the `-1` entry still references the original data. Counts are equal (same number of reads/writes), but the hash inputs differ.

## New Display Format

### Single Address Violations (COMP_OUT_MOD, LOAD_VAL_MOD, etc.)

```
       Global: memory permutation violated
         x3/gp: wrote 0x000003e7, expected 0x00010700 (cycle 33187)
```

### Global-Only Violations (INSTR_WORD_MOD_SUR rd)

```
       Global: memory permutation violated [GLOBAL-ONLY]
         0x002031F0 (code): wrote 0x00410693, expected 0x00410483 (cycle 35310)
         x9/s1: expected write missing, needed 0x00203af8 (cycle 35310)
         x14/a4: unexpected write 0x00203af8 (cycle 35310)
```

### Cascading Violations (INSTR_TYPE_MOD, 10+ addresses)

```
       Global: memory permutation violated (100 addrs: 1 register, 99 code)
         x1/ra: unexpected write 0x00203774 (cycle 39552)
         + 99 code addresses diverged (instruction fetch cascade)
       Global: cycle lookup violated (3 indices broken)
         index 0: 2254 provides, 1 uses (imbalanced)
         index 2013265920: orphan provide (1 entries, no matching use)
```

## Implementation Details

### C++ Changes (ffi.cpp)

For each broken memory address (up to 10 emitted, non-code first):

1. Group all `A4MemoryRecord` entries by `(addr, cycle)` into `CyclePair` structs.
2. Scan cycles in ascending order to find the first divergence point:
   - Both `+1` and `-1` exist but data differs: emit `wrote` and `expected` hex values.
   - Only `+1` exists (orphan write): emit `wrote` with `expected: null`.
   - Only `-1` exists (orphan read): emit `expected` with `wrote: null`.
3. Emit enriched JSON fields per broken address: `byte_addr`, `type` (register/code/data), `wrote`, `expected`, `mismatch_cycle`.
4. Emit aggregate counts: `broken_count`, `n_reg`, `n_code`, `n_data`.
5. Non-code addresses (registers, data) are emitted before code addresses so that cascade summaries always have the interesting entries available.

### Address Classification

| Type     | Word Address Range            | Byte Address Range              |
|----------|-------------------------------|---------------------------------|
| Register | `0x3fffc020` -- `0x3fffc03f` | `0xFFFF0080` -- `0xFFFF00FC`   |
| Code     | `0x00080200` -- `0x000FFFFF` | `0x00200800` -- `0x003FFFFC`   |
| Data     | Everything else               | Everything else                 |

Register index is derived as `word_addr - 0x3fffc020`, mapped to RISC-V ABI names (x0/zero through x31/t6).

### Python Changes (fuzzer.py)

The `_format_mem_mismatch` static method formats a single broken address entry:
- Registers: `x3/gp: wrote 0x000003e7, expected 0x00010700 (cycle 33187)`
- Code addresses: `0x002031F0 (code): wrote 0x00410693, expected 0x00410483`
- Orphan write: `x14/a4: unexpected write 0x00203af8 (cycle 35310)`
- Orphan read: `x9/s1: expected write missing, needed 0x00203af8 (cycle 35310)`
- Fallback (old binary): `x3 (0x3fffc023): 72 +entries, 72 -entries`

The `_print_mutation_result` method now:
- Processes `family_details` directly (not the flat `broken_addresses` list) for structured access to aggregate counts.
- For cascades (10+ broken addresses): shows type breakdown in header, non-code entries first, then summarizes code addresses.
- For lookup violations: distinguishes orphan provides from orphan uses.

## Per-Mutation Type Patterns (Verified Empirically)

| Mutation Type       | Typical Broken Count | Types         | Pattern                                    |
|---------------------|----------------------|---------------|--------------------------------------------|
| COMP_OUT_MOD        | 1                    | 1 register    | wrote mutated value, expected original      |
| LOAD_VAL_MOD        | 1                    | 1 register    | wrote mutated value, expected original      |
| PRE_EXEC_REG_MOD    | 1                    | 1 register    | wrote mutated value, expected original      |
| STORE_OUT_MOD       | 1                    | 1 data        | wrote mutated value, expected original      |
| MEM_VAL_MOD         | 1                    | 1 data        | wrote mutated value, expected original      |
| INSTR_WORD_MOD_SUR  | 1-3                  | code+register | global-only possible; orphan writes/reads   |
| INSTR_TYPE_MOD      | 10-100+              | 1 reg + N code| cascade from txnIdx offset; summarized      |

## Overhead

Hook 3 overhead (including mismatch extraction) is negligible:
- Recording: ~253K struct pushes during sequential witgen
- Computation: one LogUp residue pass + up to 10 mismatch extractions (each scanning ~69K records)
- Timing: within measurement noise (~30s proving pipeline)
- Memory: ~3.4 MB total (~2% of circuit buffers)
- Mismatch extraction adds < 1ms (350K map operations)
