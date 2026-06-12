# Phase 3.5: Granular Hook 3 Output and Campaign Display Integration

## What We Are Planning and Why

### The Goal

We want Hook 3's per-family residue data to be as informative as possible, both for human understanding during campaigns and for the multi-armed bandit's reward computation. Currently, Hook 3 reports a binary signal per family ("memory: nonzero" / "memory: zero"). We want to extract and display richer information from the recorded data.

### What Local Constraints Currently Provide (The Target Standard)

For each mutation run, the Rust-side witgen emits a detailed mutation tag AND per-constraint failure tags. Here's what a typical COMP_OUT_MOD run shows:

**Mutation detail (from Rust witgen):**
```
<a4_comp_out_mod>{"step":785, "cycle_idx":17406, "txn_idx":16261, "pc":2099648,
  "addr":1073725484, "old_word":3, "new_word":73117827, "prev_word":16,
  "major":0, "minor":7}</a4_comp_out_mod>
```
This tells you: "At step 785 (cycle 17406, PC 0x200740), we changed memory address 0x3fffc02c from value 3 to 73117827. The instruction is MISC0/minor7."

**Per-constraint failures (from C++ EQZ hooks):**
```
<constraint_fail>{"cycle":16777, "step":198, "pc":2144420, "major":0, "minor":7,
  "loc":"MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)", "value":45184,
  "phase":"local"}</constraint_fail>
```
This tells you: "At cycle 16777 (step 198, PC 0x20B4A4), the MemoryWrite constraint at mem.zir:99 failed with value 45184. This is a local constraint in the MISC0/minor7 instruction."

**Campaign per-run display:**
```
[1/200] COMP_OUT_MOD @ step 785: 2Lf 0Af 2d r=0.219 [bm:+0 ex:+1614] [abm:+300 aex:+304] [REJECTED]
```
This tells you: 2 local failures, 0 accum failures, 2 distinct context_ids, reward 0.219, touch coverage deltas, outcome REJECTED.

**Campaign report sections provide:**
- Per-kind failure statistics
- Distinct constraint families and context_ids found across the campaign
- Failure novelty curve (how quickly new contexts are discovered)
- Reward component breakdown by mutation kind

### What Hook 3 Currently Provides

```
<a4_family_residue>{"family":"memory", "nonzero":true, "e0":865737024, ...}</a4_family_residue>
<a4_family_residue>{"family":"u16", "nonzero":false}</a4_family_residue>
```

**Campaign per-run display:** Nothing yet -- Hook 3 is not integrated into the campaign.

### The Gap

Hook 3 tells us WHICH family broke but provides no detail about:
- How many memory records were involved
- Which specific addresses have imbalanced read-write chains
- How many lookup entries are imbalanced
- Which specific lookup values are problematic
- The count split (+1 vs -1 entries) per family

---

## Part 1: What Granular Information Can Hook 3 Realistically Provide?

### What We Have Access To

Hook 3 records `A4MemoryRecord` (addr, cycle, dataLow, dataHigh, count) and `A4LookupRecord` (table, index, count) for EVERY argument usage. We can compute:

**For the memory family:**
- **Total memory records**: how many memory transactions occurred
- **Per-address subtotals**: group records by `addr`, sum per-address. Non-zero addresses indicate where the read-write chain broke.
- **Distinct addresses touched**: how many unique memory addresses appear in the records
- **Distinct addresses with non-zero residue**: which specific addresses are broken
- **Count balance**: how many +1 vs -1 entries total (should be equal on a valid trace)

**For lookup families (U16, U8, Cycle):**
- **Total lookup records per family**: volume of lookups
- **Per-index subtotals**: group by `index`, sum per-index. Non-zero indices indicate which specific values have lookup imbalances.
- **Distinct indices**: how many unique values are checked
- **Count balance**: +1 vs -1 entries

### What We CANNOT Provide (honest assessment)

- **Per-cycle attribution**: Hook 3 records don't store which execution cycle created each record (the `cycle` field in MemoryRecord is the MEMORY cycle, not the execution cycle). We could add the execution cycle to the record struct, but this would increase memory usage.
- **Constraint-name-level detail**: Hook 3 doesn't know which zirgen constraint (e.g., "MemoryWrite@mem.zir:99") generated each record. It only knows the family.
- **Causality**: Even with per-address residues, we can identify WHERE the chain broke but not WHY (the mutation's address vs. the address that fails in the chain may be different).

### Practical granularity levels

**Level 1 (current):** Per-family binary: `memory: nonzero/zero`
**Level 2 (moderate):** Per-family counts + stats: `memory: nonzero, 69448 records, 5234 distinct addrs, 2 addrs with broken chains`
**Level 3 (detailed):** Per-address/per-index residues: `memory: addr 0x3fffc031 broken (register x17), addr 0x3fffc021 broken (register x1)`

Level 2 is achievable with modest changes. Level 3 is achievable but with more computation and output. Both are achievable without Rust changes -- only C++ and Python.

---

## Part 2: Implementation Plan

### Change 1: Enhance C++ Hook 3 to emit granular data

**File:** [ffi.cpp](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp)

In the Hook 3 computation block (currently lines 461-527), after computing per-family totals, add:

**1a. Per-family statistics:**
```
<a4_family_stats>{"family":"memory", "total_records":69448, "plus_count":34724, "minus_count":34724,
  "distinct_addrs":5234}</a4_family_stats>
<a4_family_stats>{"family":"u16", "total_records":150000, "plus_count":75000, "minus_count":75000,
  "distinct_indices":8192}</a4_family_stats>
```

**1b. Per-address/per-index broken detail (when nonzero):**

Only emit when the family residue is nonzero. Group memory records by `addr`, compute per-address residue, emit the broken addresses:
```
<a4_family_detail>{"family":"memory", "broken_addrs":[
  {"addr":1073725489, "addr_hex":"0x3fffc031", "type":"register", "reg_num":17, "plus":1, "minus":0},
  {"addr":1073725473, "addr_hex":"0x3fffc021", "type":"register", "reg_num":1, "plus":0, "minus":1}
]}</a4_family_detail>
```

For lookups, group by index and emit broken indices:
```
<a4_family_detail>{"family":"u16", "broken_indices":[
  {"index":45000, "plus":3, "minus":2}
]}</a4_family_detail>
```

**1c. Implementation in C++:**

After computing per-family totals, add a detailed analysis block:

```cpp
if (!is_zero(res_memory)) {
    // Per-address residue analysis
    std::map<uint32_t, FpExt> addr_residues;
    std::map<uint32_t, std::pair<uint32_t,uint32_t>> addr_counts; // plus, minus
    for (const auto& rec : g_a4_memory_records) {
        FpExt hash = r_mem_addr * Fp(rec.addr) + r_mem_cycle * Fp(rec.cycle)
                   + r_mem_dataLow * Fp(rec.dataLow) + r_mem_dataHigh * Fp(rec.dataHigh)
                   + r_offset;
        FpExt delta = FpExt(Fp(rec.count)) * inv(hash);
        addr_residues[rec.addr] = addr_residues[rec.addr] + delta;
        auto& ac = addr_counts[rec.addr];
        if (rec.count == 1) ac.first++; else ac.second++;
    }
    // Emit broken addresses (non-zero residue)
    std::printf("<a4_family_detail>{\"family\":\"memory\", \"broken_addrs\":[");
    bool first = true;
    int broken_count = 0;
    constexpr uint32_t USER_REG_BASE = 0x3fffc020;
    for (const auto& [addr, res] : addr_residues) {
        if (!is_zero(res)) {
            if (!first) std::printf(",");
            broken_count++;
            if (broken_count <= 20) { // limit output
                bool is_reg = (addr >= USER_REG_BASE && addr < USER_REG_BASE + 64);
                uint32_t reg_num = is_reg ? (addr - USER_REG_BASE) : 0;
                std::printf("{\"addr\":%u, \"addr_hex\":\"0x%08x\", \"is_reg\":%s",
                    addr, addr, is_reg ? "true" : "false");
                if (is_reg) std::printf(", \"reg\":\"x%u\"", reg_num);
                std::printf(", \"plus\":%u, \"minus\":%u}",
                    addr_counts[addr].first, addr_counts[addr].second);
            }
            first = false;
        }
    }
    std::printf("], \"broken_addr_count\":%d, \"total_addrs\":%zu}</a4_family_detail>\n",
        broken_count, addr_residues.size());
}
```

Similar for lookup families: group by index, find broken indices.

**Includes needed:** `<map>` for `std::map`.

### Change 2: Add Python parser for granular data

**File:** [touch_coverage.py](a4/core/touch_coverage.py)

Add parsers for the new tags:

```python
_FAMILY_STATS_RE = re.compile(r'<a4_family_stats>({.*?})</a4_family_stats>')
_FAMILY_DETAIL_RE = re.compile(r'<a4_family_detail>({.*?})</a4_family_detail>')

def parse_family_stats(output: str) -> Optional[List[dict]]:
    """Parse <a4_family_stats> tags."""

def parse_family_detail(output: str) -> Optional[List[dict]]:
    """Parse <a4_family_detail> tags. Only present when a family has nonzero residue."""
```

### Change 3: Integrate into campaign display

**File:** [run_diagnostic_campaign.py](a4/standalone/tests/run_diagnostic_campaign.py)

**3a. Add env vars to run_mutation:**
```python
"A4_GLOBAL_RESIDUE": "1",
"A4_FAMILY_RESIDUE": "1",
```

**3b. Parse per-run global data:**
```python
global_residue = parse_global_residue(output)
family_residues = parse_family_residues(output)
family_details = parse_family_detail(output)
```

**3c. Update per-run display line:**

Current:
```
[1/200] COMP_OUT_MOD @ step 785: 2Lf 0Af 2d r=0.219 [bm:+0 ex:+1614] [abm:+300 aex:+304] [REJECTED]
```

Proposed (with global data):
```
[1/200] COMP_OUT_MOD @ step 785: 2Lf 0Af 2d r=0.219 [bm:+0 ex:+1614] G=memory [REJECTED]
```

Where `G=memory` means "global residue nonzero, memory family broken". Other examples:
- `G=--` = global residue zero (no global violation)
- `G=memory,u16` = multiple families broken
- `G=memory(x17,x1)` = memory broken at registers x17 and x1 (if detail available)

**3d. Add campaign report sections:**

**Global Constraint Summary:**
```
--- GLOBAL CONSTRAINT SUMMARY ---
Runs with global violations: 85/100
  memory: 83 runs
  u16: 5 runs
  u8: 0 runs
  cycle: 2 runs
Global-only (no local failures): 4 runs
```

**Per-Family Detail (for broken families):**
```
--- BROKEN MEMORY ADDRESSES (across campaign) ---
Distinct broken addresses: 42
  0x3fffc021 (x1):  seen in 15 runs
  0x3fffc031 (x17): seen in 3 runs
  0x3fffc022 (x2):  seen in 12 runs
  ...
```

**3e. Add RunResult fields:**
```python
global_residue: Optional[dict] = None
family_residues: Optional[List[dict]] = None
family_details: Optional[List[dict]] = None
broken_families: List[str] = None  # e.g., ["memory"]
```

### Change 4: Enhance accum constraint display

The accum-phase constraint failures (`phase:"accum"`) already flow through the same `ConstraintFailure` dataclass and are displayed as `Af` in the per-run line. But the campaign report doesn't analyze them separately. Add:

**Accum Failure Detail section in campaign report:**
```
--- ACCUM CONSTRAINT FAILURES ---
Runs with accum failures: 0/100
(Accum EQZ constraints check delta computation; they rarely fire for value mutations)
Distinct accum context_ids across campaign: 0
```

This is already partially done from our earlier work (the ACCUM FAILURE COVERAGE section). We just need to ensure the per-run display shows accum failures with the same granularity as local:

If accum failures ever fire, they would show in the `<constraint_fail>` output with `"phase":"accum"` and would include `loc` strings like `"GenerateAccum.cpp:182"`. The `short_loc()` method already handles these.

---

## Part 3: What Each Source Provides as Human-Readable Output

### Local Constraints (existing)

| Information | Source | Example |
|-------------|--------|---------|
| **Mutation applied** | Rust `<a4_*_mod>` tag | "Changed word at addr 0x3fffc02c from 3 to 73117827" |
| **Which constraint failed** | C++ `<constraint_fail>` `loc` field | "MemoryWrite@mem.zir:99" |
| **Where it failed** | `cycle`, `step`, `pc` fields | "At cycle 16777, step 198, PC 0x20B4A4" |
| **What instruction was executing** | `major`, `minor` fields | "MISC0 minor 7" |
| **How badly it failed** | `value` field | "Value mismatch of 45184" |
| **Phase** | `phase` field | "local" |

### Accum Constraints (existing but rarely fires)

| Information | Source | Example |
|-------------|--------|---------|
| **Which delta check failed** | C++ `<constraint_fail>` `loc` field | "GenerateAccum.cpp:182" |
| **Where** | `cycle`, `step`, `pc`, `major`, `minor` | Same as local |
| **Phase** | `phase` field | "accum" |

The accum constraints use the same `<constraint_fail>` format as local. They just rarely fire because zeroBack makes them always pass for value mutations. When they do fire (rare edge cases), the display is identical.

### Hook 1 -- Global Residue (existing)

| Information | Source | Example |
|-------------|--------|---------|
| **Binary: something global broke** | `<a4_global_residue_*>` | "nonzero" or "zero" |
| **Raw FpExt values** | `e0`-`e3` fields | "(for consistency checking)" |

### Hook 3 -- Per-Family Residues (current)

| Information | Source | Example |
|-------------|--------|---------|
| **Which family broke** | `<a4_family_residue>` `family` + `nonzero` | "memory: broken, u16/u8/cycle: ok" |
| **Raw FpExt values** | `e0`-`e3` | "(for consistency checking)" |
| **Record counts** | `<a4_family_residue_stats>` | "69448 memory, 184257 lookups" |

### Hook 3 -- Per-Family Residues (PLANNED granular)

| Information | Source | Example |
|-------------|--------|---------|
| **Which family broke** | (same as current) | "memory: broken" |
| **Per-family record counts** | NEW `<a4_family_stats>` | "memory: 69448 records, 34724 +1, 34724 -1, 5234 addrs" |
| **Broken memory addresses** | NEW `<a4_family_detail>` | "addr 0x3fffc031 (register x17): 1 write, 0 reads -- chain broken" |
| **Broken lookup indices** | NEW `<a4_family_detail>` | "u16 index 45000: 3 uses, 2 provides -- imbalanced" |
| **Register identification** | Address decoding in C++ | "x17" for addr 0x3fffc031 |

---

## Part 4: Can We Achieve Local-Constraint-Level Granularity?

### Honest Assessment

**For the memory family: YES, substantially.** We can identify which specific memory addresses (including register names) have broken read-write chains. For the global-only mutation case (INSTR_WORD_MOD_SUR changing rd from x1 to x17), the output would be:

```
Global: memory family broken
  Broken addresses:
    x17 (0x3fffc031): 1 write, 0 reads  <- this register got a write it shouldn't have
    x1  (0x3fffc021): 0 writes, 1 read  <- this register expected a write it didn't get
```

This is comparable to the local constraint output "MemoryWrite@mem.zir:99 failed at cycle 16777."

**For lookup families: PARTIALLY.** We can identify which specific values have lookup imbalances, but the meaning is less intuitive: "U16 index 45000 has 3 uses but only 2 provides" doesn't map as clearly to a human-understandable constraint violation. It's more of a statistical anomaly than a descriptive failure.

**For cycle family: YES, similar to memory.** We can identify which specific cycle numbers have ordering imbalances.

### Comparison

| Aspect | Local Constraints | Hook 3 (planned) |
|--------|-------------------|-------------------|
| **Which constraint** | Exact constraint name + source location | Argument family (memory/U16/U8/cycle) |
| **Where** | Exact execution cycle, step, PC | Which memory address or lookup index |
| **What value** | The non-zero constraint value | Per-address/per-index +/- counts |
| **Why** | Implicit from constraint name | Implicit from address/index analysis |
| **Per-cycle** | Yes | Not directly (could add execution cycle to records) |

**Conclusion:** We CAN achieve useful granularity, but it's a DIFFERENT kind of granularity. Local constraints tell you "which rule was broken at which instruction." Hook 3 tells you "which data entity (address/value) has inconsistent history." Both are valuable for different reasons.

---

## Part 5: Testing Plan

### T1: Compilation
Rebuild rv32im-sys and host after C++ changes.

### T2: Clean run
Verify no `<a4_family_detail>` or `<a4_family_stats>` tags when global is clean.

### T3: COMP_OUT_MOD
Verify per-address detail shows the mutated address as broken.

### T4: INSTR_WORD_MOD_SUR (global-only)
Verify per-address detail shows x17 (new destination) and x1 (expected destination) as broken addresses.

### T5: Campaign integration
Run 20-mutation campaign and verify display output.

---

## Part 6: Env Var Design

Hook 3's granular output is controlled by the SAME env var as before: `A4_FAMILY_RESIDUE=1`. The additional detail (stats + broken addresses/indices) is emitted alongside the existing family residue tags. No new env var needed.

---

## Part 7: Thorough Investigation of Per-Address Analysis Accuracy

### The Chain Structure

For each memory address, the permutation argument maintains a chain of transactions. Each `MemoryIO` creates:
- **oldTxn** (count=-1): references the PREVIOUS value at this address `(addr, prev_cycle, prev_data)`
- **newTxn** (count=+1): records the CURRENT value `(addr, this_cycle, data)`

The +1 from transaction N is cancelled by the -1 from transaction N+1's oldTxn (same addr, same cycle, same data). If ANY link in this chain has mismatched data, the residue for that address is non-zero.

### Per-Mutation-Type Analysis

**COMP_OUT_MOD (changes txn.word AND txn.prev_word to same mutated value):**

At the mutated transaction:
- oldTxn: (-1, addr, prev_cycle, MUTATED_prev_word) -- but the preceding transaction's newTxn had data=ORIGINAL
- newTxn: (+1, addr, cycle, MUTATED_word) -- but the following transaction's oldTxn has prev_data=ORIGINAL

Two chain breaks at the SAME address:
- The preceding link: (+1, prev_cycle, ORIGINAL) vs (-1, prev_cycle, MUTATED) -- don't cancel
- The following link: (+1, cycle, MUTATED) vs (-1, cycle, ORIGINAL) -- don't cancel

**Result: 1 broken address. Confidence: 95%.** The address is the mutated register/memory location. The per-address residue correctly identifies it.

**INSTR_WORD_MOD_SUR (changes fetch txn word, altering rd from x1 to x17):**

This is more complex. The mutation changes the instruction fetch's word/prev_word. The witgen then decodes the mutated instruction and gets rd=17. When it tries to WriteRd to x17, the trace has a txn for x1, causing an address mismatch. The FAULT_INJECTION_ENABLED flag skips the throw, and the witgen proceeds with the x1 txn's data applied at the x17 address.

What extern_memoryDelta records:
1. **PC address fetch**: oldTxn(-1, PC, prev_cycle, MUTATED_word) + newTxn(+1, PC, cycle, MUTATED_word). The IsRead constraint makes prev_word=word (both MUTATED). But the preceding PageIn had data=ORIGINAL. So PC address has a broken chain.
2. **Register write to x17**: The MemoryIO is created for address x17, but GetMemoryTxn returns the x1 txn's data (address mismatch skipped). So extern_memoryDelta records addr=x17 with x1's data values. This creates entries at x17 that have no corresponding PageIn for x17 -- broken chain.
3. **Original x1 register**: The x1 txn was consumed by the x17 write. If there's a later read from x1, its oldTxn references the cycle where x1 was "written" (but the write actually went to x17). The chain at x1 may or may not break depending on whether subsequent accesses exist.

**Result: Likely 2-3 broken addresses (PC, x17, possibly x1). Confidence: 75%.** The complexity comes from the FAULT_INJECTION address mismatch causing x1's txn data to appear at x17's address. The per-address residue correctly identifies which addresses are broken, but the interpretation requires understanding the mismatch.

**INSTR_TYPE_MOD (changes major/minor):**

Changes which instruction arm executes. The instruction word is unchanged. Different arms may create different numbers of memory transactions and lookup arguments. If the new arm has MORE memory args than the original, it consumes more txns from the trace, potentially causing address mismatches for later args. If FEWER, leftover txns aren't consumed.

**Result: Variable number of broken addresses. Confidence: 70%.** The chain breaks depend on how the arm change affects transaction consumption order.

**MEM_VAL_MOD (changes a memory transaction value):**

Similar to COMP_OUT_MOD but targets non-register memory (e.g., stack, heap). Sets both word and prev_word.

**Result: 1 broken address. Confidence: 95%.** Same mechanism as COMP_OUT_MOD.

### Confidence Scores for Per-Address Analysis

| Information | Confidence | Why |
|-------------|------------|-----|
| **Which addresses have non-zero residue** | 99% | Mathematically exact: the LogUp sum is deterministic given the recorded data and verifier randomness. If the sum is non-zero, the address has a broken chain. |
| **How many addresses are broken** | 95% | Reliable count from the residue computation. Edge case: Schwartz-Zippel could cause a false zero (two non-zero deltas cancel by coincidence), but probability is negligible (~1/field_size). |
| **Identifying register addresses (x0-x31)** | 99% | Address decoding is exact: `UserRegBase + reg_num` with known `UserRegBase = 0x3fffc020`. |
| **Identifying which is "original" vs "mutated" address** | 60% | We know WHICH addresses are broken but not always WHY. For COMP_OUT_MOD (1 broken address = mutated register), it's clear. For INSTR_WORD_MOD_SUR (2-3 broken addresses), we can't directly tell which address was "intended" vs "unintended" without cross-referencing the mutation config. |
| **Per-address +1/-1 count balance** | 99% | Simple counting from recorded data. |
| **Execution cycle for each record** | 99% | Recoverable: `exec_cycle = rec.cycle / 2` (reads have even memory cycles, writes have odd). |
| **Per-lookup-index broken values** | 99% | Same LogUp residue computation, grouped by index instead of address. |
| **Per-lookup-index count balance** | 99% | Simple counting. |

### The Two-Mismatch Question

The user asked: "there will not only be one mismatch but two right?"

**Yes, typically.** A mutation creates a chain break at one point, but each break involves TWO unmatched entries:
- The +1 entry before the break point (with the expected data)
- The -1 entry after the break point (with the mutated data)

In per-address residue terms, both unmatched entries are at the SAME address, so the address shows as "broken" with a non-zero residue. The residue value encodes the combined effect of both unmatched entries.

For INSTR_WORD_MOD_SUR, the breaks can span MULTIPLE addresses (PC, x17, x1), each with their own unmatched entries. The per-address analysis correctly identifies all broken addresses.

### Can We Tell Which Mismatch is the "Cause" vs "Effect"?

**Not directly from the per-address residue alone.** But we CAN cross-reference:
- The mutation config tells us what was changed (e.g., "step 573, word changed from 12439 to 14487")
- The mutation detail tag (e.g., `<a4_instr_word_mod>`) tells us the target address
- By comparing the broken addresses with the target address, we can infer causality

This cross-referencing would be done on the Python side, not in C++.

---

## Implementation Summary

| File | Changes |
|------|---------|
| [ffi.cpp](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp) | Add per-address/per-index grouping after family residue computation. Emit `<a4_family_stats>` and `<a4_family_detail>` tags. Add `<map>` include. ~80 lines of new C++. |
| [touch_coverage.py](a4/core/touch_coverage.py) | Add `parse_family_stats()` and `parse_family_detail()` parsers. ~30 lines. |
| [run_diagnostic_campaign.py](a4/standalone/tests/run_diagnostic_campaign.py) | Add `A4_GLOBAL_RESIDUE` and `A4_FAMILY_RESIDUE` to env vars. Parse global/family data per-run. Update per-run display with `G=memory(x17,x1)` format. Add campaign report sections. Add RunResult fields. ~60 lines. |
