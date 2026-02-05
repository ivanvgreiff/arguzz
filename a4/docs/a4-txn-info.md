
# Comprehensive Report: `PreflightTrace.txns[]` Structure Analysis

## 1. Overview of the Transaction Array

The `trace.txns[]` array stores **all memory and register accesses** during program execution. Each transaction is a `RawMemoryTransaction` struct defined in:

**File**: `/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs:22-31`

```rust
pub struct RawMemoryTransaction {
    pub addr: u32,       // Word address (bytes / 4)
    pub cycle: u32,      // Indicates read vs write phase
    pub word: u32,       // Value read or written
    pub prev_cycle: u32, // Last cycle this address was accessed
    pub prev_word: u32,  // For READs: same as word; for WRITEs: previous value
}
```

---

## 2. Detailed Field Explanations

### 2.1. `addr` Field

**What it is**: The **word address** (32-bit aligned address divided by 4).

**Source code proof** (`preflight.rs:592-593`):
```rust
let txn = RawMemoryTransaction {
    addr: addr.0,  // addr is WordAddr, stored directly
    ...
};
```

**Address ranges** (from `platform.rs:27-48`):

| Address Range (words) | Description |
|----------------------|-------------|
| 0 - 262,143 | Zero page (0x0000_0000 - 0x0000_FFFF bytes) |
| 262,144 - 805,306,367 | User memory (0x0001_0000 - 0xBFFF_FFFF bytes) |
| 1,073,725,440+ | Special regions (registers, etc.) |
| **1,073,725,472** | `USER_REGS_ADDR / 4` = start of user registers |

**For step 198 transactions**:

| txn_idx | addr | Calculation | Meaning |
|---------|------|-------------|---------|
| 16258 | 536104 | 536104 × 4 = 2144416 | PC of instruction being executed |
| 16259 | 1073725472 | USER_REGS_ADDR/4 + 0 | Register x0 (zero) |
| 16260 | 1073725475 | USER_REGS_ADDR/4 + 3 | Register x3 (gp) |
| 16261 | 1073725484 | USER_REGS_ADDR/4 + 12 | Register x12 (a2) |

---

### 2.2. `cycle` Field

**What it is**: Encodes **which ZK circuit cycle** the access occurs in AND **whether it's a read or write**.

**Source code proof** (`preflight.rs:572, 607`):
```rust
// For READs (in load_u32):
let cycle = (2 * self.trace.cycles.len()) as u32;

// For WRITEs (in store_u32):
let cycle = (2 * self.trace.cycles.len() + 1) as u32;
```

**Interpretation**:
- **Even cycle** = READ operation
- **Odd cycle** = WRITE operation
- `cycle / 2` = the actual `cycle_idx` in `trace.cycles[]`

**For step 198** (cycle_idx = 16777):

| txn_idx | cycle | calculation | type |
|---------|-------|-------------|------|
| 16258 | 33554 | 2 × 16777 = 33554 (even) | READ |
| 16259 | 33554 | 2 × 16777 = 33554 (even) | READ |
| 16260 | 33554 | 2 × 16777 = 33554 (even) | READ |
| 16261 | 33555 | 2 × 16777 + 1 = 33555 (odd) | WRITE |

---

### 2.3. `word` Field

**What it is**: The **value** that was read or written.

**Source code proof** (`preflight.rs:595, 621`):
```rust
// For READs:
let txn = RawMemoryTransaction {
    word,  // The value loaded from memory/register
    ...
};

// For WRITEs:
let txn = RawMemoryTransaction {
    word,  // The value being stored
    ...
};
```

**For step 198 transactions**:

| txn_idx | word | Meaning |
|---------|------|---------|
| 16258 | 3147283 | Instruction word = 0x00300613 = `addi a2, x0, 3` |
| 16259 | 0 | Value in x0 (always 0) |
| 16260 | 67584 | Value in x3 (gp register) |
| 16261 | **3** | **Output value written to a2** ← COMP_OUT_MOD target |

**Instruction word decoding** (word = 3147283 = 0x00300613):

| Field | Bits | Value | Meaning |
|-------|------|-------|---------|
| opcode | [6:0] | 0x13 | I-type arithmetic |
| rd | [11:7] | 12 | a2 (x12) |
| func3 | [14:12] | 0 | ADDI |
| rs1 | [19:15] | 0 | x0 (zero) |
| imm_i | [31:20] | 3 | immediate = 3 |

---

### 2.4. `prev_cycle` Field

**What it is**: The **cycle number** when this address was **last accessed**.

**Source code proof** (`preflight.rs:591, 617`):
```rust
let prev_cycle = self.prev_cycle.insert_default(&addr, cycle, u32::MAX);
```

This is used by the ZK circuit to verify **memory consistency** - ensuring that the "previous" value matches what was written at `prev_cycle`.

---

### 2.5. `prev_word` Field

**What it is**: 
- For **READs**: Same as `word` (verifies consistency)
- For **WRITEs**: The **previous value** at that address before the write

**Source code proof** (`preflight.rs:597, 623`):
```rust
// For READs:
prev_word: word,  // Same value

// For WRITEs:
prev_word,  // Previous value loaded before storing
```

**For step 198 transaction 16261** (the WRITE):
- `word = 3` (new value)
- `prev_word = 16` (a2 previously held 16)

---

## 3. Why Transaction 16260 Exists (Reading x3/gp)

You may wonder: **Why does `addi a2, x0, 3` read register x3?**

**Answer**: The `DecodedInstruction::new()` function extracts `rs2` from bits `[24:20]` **regardless of instruction format**.

**Source** (`rv32im.rs:463`):
```rust
rs2: (insn & 0x01f00000) >> 20,  // Always extracts these bits
```

For instruction 0x00300613, bits `[24:20]` = 3. So `decoded.rs2 = 3`.

Then in `load_rs2()` (`rv32im.rs:724-735`):
```rust
fn load_rs2(...) -> Result<u32> {
    if decoded.rs1 == decoded.rs2 {
        Ok(rs1)
    } else {
        ctx.load_register(decoded.rs2 as usize)  // Loads x3
    }
}
```

Since rs1=0 ≠ rs2=3, it loads register x3. **This value (67584) is never used by ADDI**, but the register read is still recorded in the transaction log.

---

## 4. Transaction Flow for `step_compute` (AddI)

**Complete execution flow** for `li a2, 3` at step 198:

| Order | Action | Function | Transaction |
|-------|--------|----------|-------------|
| 1 | Instruction fetch | `step()` line 643: `ctx.load_memory(pc.waddr())` | txn 16258 |
| 2 | Load rs1 | `step_compute()` line 749: `ctx.load_register(decoded.rs1)` | txn 16259 |
| 3 | Load rs2 | `step_compute()` line 750: `self.load_rs2(ctx, &decoded, rs1)` | txn 16260 |
| 4 | Compute | `step_compute()` line 796: `out = rs1.wrapping_add(imm_i)` | (no txn) |
| 5 | **COMP_OUT_MOD injection** | lines 875-882: `out = new_out` | (no txn) |
| 6 | Store result | `step_compute()` line 887: `ctx.store_register(rd, out)` | **txn 16261** |

---

## 5. COMP_OUT_MOD Mutation Target

For A4 to replicate Arguzz's COMP_OUT_MOD mutation:

**Arguzz mutation**:
```
<fault>{"step":200, "pc":2144416, "kind":"COMP_OUT_MOD", "info":"out:3 => out:73117827"}</fault>
```

**A4 target**:
- **Transaction**: `txn_idx = 16261`
- **Field to mutate**: `word` (from 3 to 73117827)
- Also mutate: `prev_word` → keep as 16 (unchanged, it's the previous value)

The constraint failures occur because:
- Circuit expects: `word_written = prev_word_read` for memory consistency
- After mutation: The written value (73117827) doesn't match what subsequent reads expect

---

## 6. Summary Table

| txn_idx | addr | addr meaning | cycle | R/W | word | word meaning | prev_word |
|---------|------|--------------|-------|-----|------|--------------|-----------|
| 16258 | 536104 | PC 2144416 | 33554 | R | 3147283 | Instruction `li a2, 3` | 3147283 |
| 16259 | 1073725472 | x0 (zero) | 33554 | R | 0 | x0 always 0 | 0 |
| 16260 | 1073725475 | x3 (gp) | 33554 | R | 67584 | gp value (unused) | 67584 |
| 16261 | 1073725484 | **x12 (a2)** | 33555 | **W** | **3** | **OUTPUT** | 16 |

**Key insight**: For COMP_OUT_MOD, mutate `trace.txns[16261].word` from 3 → 73117827.