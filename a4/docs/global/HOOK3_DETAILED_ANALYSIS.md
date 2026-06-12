# Hook 3 Detailed Analysis: Per-Family Residues

This document provides a comprehensive analysis of Hook 3, explaining what data it extracts, how it processes it, what it returns, and how it could be used by the multi-armed bandit for smarter mutation selection.

---

## Part 1: What Data Does Hook 3 Record?

Hook 3 intercepts two extern functions during witness generation (`step_Top`). These externs fire for EVERY argument usage across all instruction types.

### A4MemoryRecord (from `extern_memoryDelta`)

Each memory transaction in the trace produces one call to `extern_memoryDelta` with 5 fields:

| Field | Type | What It Is | Source |
|-------|------|------------|--------|
| `addr` | uint32_t | **Word address** of the memory location being accessed. For register accesses, this is `UserRegBase + register_number` (where UserRegBase = 0x3fffc020). For memory accesses, this is the actual memory word address. | Comes from `MemoryArg.addr` in `mem.zir:26`. Passed to `MemoryDelta` at `mem.zir:30`. |
| `cycle` | uint32_t | **Memory cycle number** -- a monotonically increasing counter that orders memory transactions. For reads: `2 * execution_cycle`. For writes: `2 * execution_cycle + 1`. This ensures writes within a cycle are ordered after reads. | Comes from `MemoryIO` in `mem.zir:67-68`: `MemoryArg(-1, addr, ret.prevCycle, ret.prevData)` for old, `MemoryArg(1, addr, memCycle, ret.data)` for new. |
| `dataLow` | uint32_t | **Low 16 bits** of the value at this memory address. | From `MemoryArg.dataLow` = `data.low` in `mem.zir:28`. |
| `dataHigh` | uint32_t | **High 16 bits** of the value at this memory address. | From `MemoryArg.dataHigh` = `data.high` in `mem.zir:29`. |
| `count` | uint32_t | **Permutation side indicator**. In Baby Bear field: `1` means "+1 side" (the new/current transaction), `2013265920` means "-1 side" (the old/previous transaction). Every `MemoryIO` creates TWO MemoryArgs: an oldTxn (count=-1) and a newTxn (count=+1). For the permutation to balance, every +1 entry must match a -1 entry. | From `MemoryArg.count` in `mem.zir:25`. Set to `-1` for oldTxn and `+1` for newTxn at `mem.zir:67-68`. |

**Volume:** On our test trace (32768 cycles), Hook 3 records 69,448 memory records. This is roughly 2 records per memory transaction (old + new sides), and there are ~35K memory transactions in the trace.

### A4LookupRecord (from `extern_lookupDelta`)

Each lookup argument usage produces one call to `extern_lookupDelta` with 3 fields:

| Field | Type | What It Is | Source |
|-------|------|------------|--------|
| `table` | uint32_t | **Lookup table ID**. `8` = U8 range check table (values 0-255). `16` = U16 range check table (values 0-65535). `0` = Cycle ordering table. | From `LookupDelta(table, index, count)` in `lookups.zir:4`. Table IDs: U8 at `lookups.zir:11`, U16 at `lookups.zir:35`, Cycle at `mem.zir:56`. |
| `index` | uint32_t | **The value being looked up**. For U8: a value in [0, 255] that the circuit claims is a valid byte. For U16: a value in [0, 65535] claimed as a valid 16-bit number. For Cycle: an execution cycle number. | From `LookupDelta`'s second argument. For U8: `val` at `lookups.zir:11`. For U16: `val` at `lookups.zir:35`. For Cycle: `cycle` at `mem.zir:56`. |
| `count` | uint32_t | **Usage vs. table side**. `1` = this value is being USED (claimed to be in the table). For the system's table-side entries (which provide the valid values), count is typically `-1`. The lookup argument balances when every usage (+1) is cancelled by a table entry (-1). | From `LookupDelta`'s third argument. |

**Volume:** On our test trace, Hook 3 records 184,257 lookup records. The majority are U16 (each instruction uses several U16 range checks for value normalization).

---

## Part 2: How Hook 3 Processes the Data

### Step 1: Recording (during witgen, step_Top)

During witness generation, the circuit processes each cycle and calls `extern_memoryDelta` for each memory operation and `extern_lookupDelta` for each range check / cycle lookup. Hook 3 pushes these calls into two vectors.

This happens ONLY when all three conditions are met:
- `A4_FAMILY_RESIDUE=1` is set
- Sequential witgen mode is active (`A4_MUTATION_CONFIG` or `A4_COVERAGE_TOUCH` set)
- The extern is called (i.e., the instruction arm uses that argument type)

### Step 2: Read verifier randomness (at start of accum phase)

When the accum phase begins, the mix buffer is available. Hook 3 reads 8 extension field values (each 4 Fp elements) from fixed offsets in the mix buffer:

| Randomness | Mix Offset | Used By |
|-----------|-----------|---------|
| `r_u8_val` | 0 | U8 lookup hash |
| `r_u16_val` | 4 | U16 lookup hash |
| `r_mem_addr` | 8 | Memory hash (addr component) |
| `r_mem_cycle` | 12 | Memory hash (cycle component) |
| `r_mem_dataLow` | 16 | Memory hash (dataLow component) |
| `r_mem_dataHigh` | 20 | Memory hash (dataHigh component) |
| `r_cyc_cycle` | 24 | Cycle lookup hash |
| `r_offset` | 28 | Shared offset added to all hashes |

These are the same random values that the circuit's accumulator uses. By using the same randomness, our shadow computation produces the same residues.

### Step 3: Compute per-family residues

For each recorded argument, Hook 3 computes the LogUp hash and delta:

**Memory:** `hash = r_mem_addr * addr + r_mem_cycle * cycle + r_mem_dataLow * dataLow + r_mem_dataHigh * dataHigh + r_offset`
Then: `delta = Fp(count) * inv(hash)`

**U16:** `hash = r_u16_val * Fp(index) + r_offset`
Then: `delta = Fp(count) * inv(hash)`

**U8:** `hash = r_u8_val * Fp(index) + r_offset`
Then: `delta = Fp(count) * inv(hash)`

**Cycle:** `hash = r_cyc_cycle * Fp(index) + r_offset`
Then: `delta = Fp(count) * inv(hash)`

Each delta is summed into the family's running total (in FpExt = 4 Fp elements).

### Step 4: Emit results

For each family, if the total is zero, emit `{"family":"...", "nonzero":false}`. If non-zero, emit the 4 FpExt elements as `e0`-`e3`.

---

## Part 3: What Hook 3 Returns and Shows

### Output Tags

```
<a4_family_residue>{"family":"memory", "nonzero":true, "e0":2010187561, "e1":307902251, "e2":700757994, "e3":753788442}</a4_family_residue>
<a4_family_residue>{"family":"u16", "nonzero":false}</a4_family_residue>
<a4_family_residue>{"family":"u8", "nonzero":false}</a4_family_residue>
<a4_family_residue>{"family":"cycle", "nonzero":false}</a4_family_residue>
<a4_family_residue_stats>{"memory_records":69448, "lookup_records":184257}</a4_family_residue_stats>
```

### How to Interpret

- **`memory: nonzero=true`** -- The memory permutation argument failed. Some memory read doesn't match its corresponding write, or a write happened to an unexpected address. This is the most common global failure for A4 mutations.

- **`u16: nonzero=true`** -- A U16 range check failed. Some value claimed to be in [0, 65535] doesn't properly cancel in the lookup argument. This could happen if a mutation changes a value decomposition (e.g., splitting a 32-bit word into two 16-bit halves incorrectly).

- **`u8: nonzero=true`** -- A U8 range check failed. Some value claimed to be in [0, 255] doesn't cancel. Less common since fewer instructions use U8 arguments.

- **`cycle: nonzero=true`** -- Cycle ordering constraints failed. The execution cycle ordering is inconsistent.

- **`e0`-`e3` values** -- The raw FpExt residue. These are meaningless as individual numbers (they're field elements in Baby Bear), but their non-zero-ness indicates violation, and two hooks producing the same values indicates they computed the same residue (consistency check).

---

## Part 4: Could This Data Help the Multi-Armed Bandit?

### How the Current Bandit Works

The bandit scheduler uses a Discounted-UCB algorithm with two levels:
- **Level 1:** Selects a (mutation_kind, step_bucket) arm
- **Level 2:** Selects a specific step within the bucket

The reward function (`compute_reward` in `coverage_state.py`) has 5 components:
1. **T_new** -- Touch coverage novelty (new bitmap buckets touched)
2. **T_rare** -- Touch coverage rarity (touching rarely-seen constraint contexts)
3. **F_new** -- Failure novelty (new constraint failure contexts)
4. **F_rare** -- Failure rarity (triggering rarely-seen failure contexts)
5. **Z** -- Zero-local-fail indicator (proof rejected but no local constraint failed)

These are combined into a weighted sum `S`, multiplied by a quality factor `Q` (penalizing cascade failures), to produce a reward in [0, 1].

### What Hook 3 Adds That the Bandit Doesn't Have Yet

**1. The Z component is currently coarse -- Hook 3 can make it richer.**

The current Z indicator is binary: "proof rejected AND no local failures." Hook 3 adds the REASON: which family broke. This enables:
- **Family-specific Z:** Instead of just "something global broke," the bandit could value "memory broke" differently from "U16 broke." A mutation that breaks a U16 lookup might be more interesting than one that breaks memory (since U16 failures are rarer and might indicate a different class of underconstraint).
- **Multi-family Z:** A mutation that breaks MULTIPLE families simultaneously would be highly unusual and potentially more interesting.

**2. Hook 3 enables global coverage tracking -- a new dimension for the bandit.**

Currently, the bandit tracks LOCAL constraint coverage (T_new, T_rare for touch bitmap; F_new, F_rare for failure contexts). Hook 3 enables a parallel tracking for global constraints:
- **G_new**: Did this mutation produce a new combination of family violations? (e.g., first time we've seen u16 break without memory breaking)
- **G_rare**: How rare is this global family violation pattern across the campaign?

This would add global constraint coverage as a reward signal alongside local constraint coverage.

**3. The recorded fields (addr, cycle, data, index) could enable finer mutation targeting.**

Currently not possible without additional analysis, but the raw records contain rich information:

- **Memory records with addr:** We can identify WHICH memory addresses are involved in the permutation failure. If we compute per-address residues (grouping memory records by addr), we could identify the specific address whose read-write chain broke. This would tell the bandit "mutations targeting address 0x3fffc031 (register x17) are interesting."

- **Lookup records with index:** We can identify WHICH specific values have lookup imbalances. If a U16 lookup fails for index 45000, that tells us a value normalization at that specific number is problematic.

- **Memory records with cycle:** We can identify WHICH execution cycles contributed to the memory imbalance. Combined with the mutation's target step, this could reveal which instruction is the "receiver" of the broken consistency chain.

### Concrete Bandit Integration Ideas

**Idea 1: Add G_family as a reward component**

```python
# New component: global family novelty
family_key = tuple(sorted(f["family"] for f in family_residues if f["nonzero"]))
G_family = 1.0 if family_key not in state.seen_family_patterns else 0.0
```

This rewards mutations that produce NEW patterns of family violations.

**Idea 2: Enhance Z with family specificity**

```python
# Enhanced Z: weight by family rarity
if Z == 1 and family_residues:
    broken_families = [f["family"] for f in family_residues if f["nonzero"]]
    family_rarity = 1.0 / (1.0 + state.family_freq.get(broken_families[0], 0))
    Z_enhanced = Z * family_rarity
```

This makes Z higher when the broken family is rare (e.g., first U8 violation > 10th memory violation).

**Idea 3: Use per-address memory analysis for step selection**

If we extend Hook 3 to emit per-address residues (which addresses have imbalanced read-write chains), the bandit could:
- Identify "hot" addresses (frequently broken by mutations)
- Steer mutations toward steps that access "cold" addresses (rarely broken)
- This requires additional computation but could significantly improve coverage

### What Hook 3 Does NOT Currently Provide (But Could)

1. **Per-address memory residues:** Currently all memory records are summed into one family total. We COULD compute per-address subtotals to identify which specific memory addresses have broken chains.

2. **Per-record contribution magnitude:** Currently we only check if the family total is zero/nonzero. We COULD track which individual records contribute the most to the non-zero total, identifying the specific "bad" transaction.

3. **Per-cycle family violations:** Currently we sum across all cycles. We COULD track per-cycle family deltas to identify which specific cycle caused the imbalance.

These extensions would increase computational cost but could provide much richer signals for the bandit.

---

## Part 5: Summary of What Each Field Means

### A4MemoryRecord Fields (from extern_memoryDelta)

| Field | Plain English | Example |
|-------|---------------|---------|
| **addr** | The memory address being accessed (word-aligned). Register x17 = 0x3fffc031. Memory location 0x1000 = 0x400. | A mutation that changes AUIPC rd from x1 to x17 produces a memory record at addr=0x3fffc031 instead of addr=0x3fffc021. |
| **cycle** | When this access happened in the "memory timeline." Even numbers = reads, odd = writes within the same execution cycle. | A read at execution cycle 100 has memory cycle 200. A write at execution cycle 100 has memory cycle 201. |
| **dataLow** | The bottom 16 bits of the 32-bit value at this address. | If register x1 holds 0xDEADBEEF, dataLow = 0xBEEF = 48879. |
| **dataHigh** | The top 16 bits. | For 0xDEADBEEF, dataHigh = 0xDEAD = 57005. |
| **count** | Which "side" of the permutation this entry is on. 1 = current/new side. 2013265920 = old/previous side (which is -1 in Baby Bear field). | Every MemoryIO creates exactly two records: one with count=2013265920 (old) and one with count=1 (new). |

### A4LookupRecord Fields (from extern_lookupDelta)

| Field | Plain English | Example |
|-------|---------------|---------|
| **table** | Which lookup table. 8 = "is this a valid byte?" (0-255). 16 = "is this a valid 16-bit number?" (0-65535). 0 = "is this a valid cycle number?" | When the circuit splits a 32-bit word into two 16-bit halves, each half generates a U16 lookup (table=16). |
| **index** | The specific value being checked. For U8: the byte value. For U16: the 16-bit value. For Cycle: the cycle number. | If the circuit claims 45000 is a valid U16 value, index=45000 and table=16. |
| **count** | Usage (+1) or table provision (-1 = 2013265920 in Baby Bear). +1 means "I'm using this value and it should be in the table." -1 means "I'm providing this value as a valid table entry." | Each instruction's value decomposition produces +1 lookup entries. The system/table cycles produce -1 entries for all valid values 0-255 (U8) and 0-65535 (U16). |

---

## Part 6: How This Fits the Fuzzing Goal

A4's purpose is finding **underconstraints** in the RISC Zero zkVM -- cases where a mutation produces an invalid execution but the verifier accepts the proof. Hook 3 contributes to this goal in three ways:

1. **Detecting mutations that break global but not local constraints.** These are especially interesting because they represent cases where the circuit's local checks are blind to the inconsistency. If the verifier ALSO misses it (accepts the proof), that's an underconstraint.

2. **Identifying which constraint FAMILY is broken.** This helps the bandit focus on under-tested families. If U8 lookups are never broken by any mutation, maybe the bandit should design mutations that specifically target U8 values.

3. **Providing a richer reward signal.** Instead of just "something global broke" (Hook 1), Hook 3 tells the bandit "specifically the memory permutation broke." This enables the bandit to learn which mutation types are most effective at breaking specific families, and to diversify its exploration across all families.
