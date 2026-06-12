# Phase 3.5 Implementation Report: Granular Hook 3 Output + Campaign Integration

## Summary

Phase 3.5 enhanced Hook 3 to provide Level 3 (maximum) granularity: per-address broken chain analysis for memory permutations and per-index analysis for lookup arguments. All global constraint data is now integrated into the standard diagnostic campaign display, showing broken families and specific broken addresses (with register names) on every mutation run.

---

## What Was Implemented

### C++ Changes (ffi.cpp)

**1. Per-family statistics (`<a4_family_stats>` tags):**

After computing per-family residues, we now count +1 vs -1 entries and distinct addresses/indices for each family. This shows the volume and balance of each family's argument contributions.

Example output:
```
<a4_family_stats>{"family":"memory", "records":69448, "plus":34724, "minus":34724, "distinct_addrs":13952}</a4_family_stats>
<a4_family_stats>{"family":"u8", "records":2899, "plus":2643, "minus":256, "distinct_indices":256}</a4_family_stats>
<a4_family_stats>{"family":"u16", "records":95050, "plus":29514, "minus":65536, "distinct_indices":65536}</a4_family_stats>
<a4_family_stats>{"family":"cycle", "records":86308, "plus":20772, "minus":65536, "distinct_indices":65536}</a4_family_stats>
```

**2. Per-address broken chain detail (`<a4_family_detail>` tags):**

When a family's residue is non-zero, we group all records by address (for memory) or index (for lookups), compute per-group LogUp residues, and report which specific addresses/indices are broken. Register addresses are decoded to `x0`-`x31` names.

Example output (COMP_OUT_MOD changing register x12):
```
<a4_family_detail>{"family":"memory", "broken_addrs":[
  {"addr":1073725484,"hex":"0x3fffc02c","reg":"x12","plus":816,"minus":816}
],"broken_count":1,"total_addrs":13952}</a4_family_detail>
```

Example output (INSTR_WORD_MOD_SUR changing rd from x1 to x17):
```
<a4_family_detail>{"family":"memory", "broken_addrs":[
  {"addr":527468,"hex":"0x00080c6c","plus":11,"minus":11},
  {"addr":1073725473,"hex":"0x3fffc021","reg":"x1","plus":664,"minus":664},
  {"addr":1073725489,"hex":"0x3fffc031","reg":"x17","plus":92,"minus":92}
],"broken_count":3,"total_addrs":13952}</a4_family_detail>
```

**3. Include addition:** Added `<map>` to the includes list for `std::map` used in per-address grouping.

### Python Changes

**touch_coverage.py:** Added `parse_family_stats()` and `parse_family_detail()` functions with corresponding regexes.

**run_diagnostic_campaign.py:**
- Added `A4_GLOBAL_RESIDUE=1` and `A4_FAMILY_RESIDUE=1` to `run_mutation` env vars
- Added global hook parsing per run (global_residue, family_residues, family_details)
- Updated per-run display to show `G=family(addrs)` format
- Added GLOBAL CONSTRAINT SUMMARY report section

---

## Deviations from Plan

**No significant deviations.** The implementation follows the Phase 3.5 plan closely. Minor addition: the `<a4_family_stats>` tags include a `distinct_addrs`/`distinct_indices` field (not explicitly in the plan but useful for context).

---

## Test Results

### T2: Clean Run (no mutation)

All families `nonzero:false`. Stats show:
- memory: 69448 records (34724 +1, 34724 -1) -- perfectly balanced
- u16: 95050 records, 65536 distinct indices
- u8: 2899 records, 256 distinct indices
- cycle: 86308 records, 65536 distinct indices
- NO `<a4_family_detail>` tags (all clean)

### T3: COMP_OUT_MOD (step 785, addr 0x3fffc02c = register x12)

```
Family detail: memory broken_addrs=[{"addr":1073725484,"hex":"0x3fffc02c","reg":"x12","plus":816,"minus":816}]
broken_count=1, total_addrs=13952
```

**Result:** Exactly 1 broken address, which is the mutated register (x12). The mutation tag confirms the target address is 0x3fffc02c. Plus and minus counts are equal (816 each) -- the chain has balanced entries but the data doesn't match at the break point.

### T4: INSTR_WORD_MOD_SUR (step 573, AUIPC rd x1→x17)

```
Family detail: memory broken_addrs=[
  {"addr":527468,"hex":"0x00080c6c","plus":11,"minus":11},           -- PC address
  {"addr":1073725473,"hex":"0x3fffc021","reg":"x1","plus":664,"minus":664},  -- original rd
  {"addr":1073725489,"hex":"0x3fffc031","reg":"x17","plus":92,"minus":92}    -- mutated rd
]
broken_count=3, total_addrs=13952
```

**Result:** 3 broken addresses, exactly as predicted:
1. **PC address (0x00080c6c):** Instruction fetch chain break -- mutated word doesn't match the page-in's original word
2. **Register x1 (0x3fffc021):** Original destination register -- missing its expected write (write went to x17 instead)
3. **Register x17 (0x3fffc031):** New destination register -- got an unexpected write with x1's transaction data

**0 local failures.** This is a pure global-only violation detected and diagnosed by Hook 3.

### T5: 20-Mutation Campaign

Successfully integrated all global data into the standard campaign display. Key observations:

- **19/20 runs show global violations** (`G=memory` or `G=memory,cycle`)
- **1 run (run 7) is global-only**: 0 local failures, `G=memory(0x3fffc0b2)`, `[Z]` flag
- **1 run (run 5) has no global violation**: `G=--` (INSTR_TYPE_MOD that preserved accumulator contributions)
- **1 run (run 10) shows TWO broken families**: `G=memory,cycle` -- INSTR_TYPE_MOD that changed instruction category enough to break both memory and cycle ordering
- Register names appear in the display: `G=memory(x1)`, `G=memory(x17)`, `G=memory(x18)`, etc.
- Memory addresses for non-register locations appear as hex: `G=memory(0x000800d6)`

---

## New Variables and Functions

### C++ (ffi.cpp)

| Name | Purpose |
|------|---------|
| `addr_res` (local) | `std::map<uint32_t, FpExt>` -- per-address LogUp residues |
| `addr_cnt` (local) | `std::map<uint32_t, pair<uint32_t,uint32_t>>` -- per-address +1/-1 counts |
| `idx_res` (local) | `std::map<uint32_t, FpExt>` -- per-lookup-index residues |
| `idx_cnt` (local) | `std::map<uint32_t, pair<uint32_t,uint32_t>>` -- per-index +1/-1 counts |
| `USER_REG_BASE` | Constant `0x3fffc020` -- base address for user registers |
| `emit_lookup_detail` (lambda) | Emits `<a4_family_detail>` for a lookup family |

### Python (touch_coverage.py)

| Name | Purpose |
|------|---------|
| `parse_family_stats()` | Parses `<a4_family_stats>` tags -- per-family record counts and balance |
| `parse_family_detail()` | Parses `<a4_family_detail>` tags -- broken addresses/indices with details |
| `_FAMILY_STATS_RE` | Regex for stats tags |
| `_FAMILY_DETAIL_RE` | Regex for detail tags |

### Campaign (run_diagnostic_campaign.py)

| Name | Purpose |
|------|---------|
| `global_residue` (per-run) | Parsed Hook 1 result |
| `family_residues` (per-run) | Parsed Hook 3 per-family results |
| `family_details` (per-run) | Parsed per-address/per-index detail |
| `broken_families` (per-run) | List of family names with non-zero residues |
| `g_str` (per-run) | Display string like `G=memory(x17,x1)` |

---

## How This Fits the Grand Scheme

### Before Phase 3.5

The campaign displayed:
```
[1/20] COMP_OUT_MOD @ step 785: 2Lf 0Af 2d r=0.207 [REJECTED]
```
You knew: 2 local constraints failed at this step. Nothing about global constraints.

### After Phase 3.5

The campaign displays:
```
[1/20] COMP_OUT_MOD @ step 785: 2Lf 0Af 2d r=0.207 G=memory(x12) [REJECTED]
```
You now know: 2 local constraints failed AND the memory permutation is broken specifically at register x12. For global-only mutations:
```
[7/20] MEM_VAL_MOD @ step 3929: 0Lf 0Af 0d r=0.256 G=memory(0x3fffc0b2) [Z] [REJECTED]
```
No local failures, but memory permutation broken at address 0x3fffc0b2. The `[Z]` flag indicates this is a zero-local-fail event.

### What This Enables for the Bandit

The per-address detail provides information the bandit can use:
1. **Which registers are commonly broken** -- the bandit could learn that mutations targeting instructions that write to x1 (return address register) are more likely to produce global-only violations
2. **Which memory regions are vulnerable** -- PC-area addresses vs register addresses vs heap addresses
3. **Multi-family violations are rare and interesting** -- run 10 showing `G=memory,cycle` indicates the mutation broke TWO independent global properties, which is a richer signal
4. **The number of broken addresses** -- a mutation breaking 3 addresses (like the INSTR_WORD_MOD_SUR case) is more disruptive than one breaking 1 address

### The Three Layers of Information Now Available Per Run

```
Layer 1 (Local):   2Lf -- 2 local constraint failures (MemoryWrite@mem.zir:99, MemoryWrite@mem.zir:100)
Layer 2 (Global):  G=memory -- memory permutation broken
Layer 3 (Detail):  G=memory(x12) -- specifically register x12's read-write chain is broken
```

Each layer adds specificity without interfering with the proof pipeline.
