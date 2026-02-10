# A4 Standalone Mutation Implementation Plan

This document provides a detailed multi-phase plan for implementing all new mutation functions defined in `MUTATION_TAXONOMY.md`.

## Overview

### Implementation Scope

| Category | Mutations | Rust Needed | Python Needed |
|----------|-----------|-------------|---------------|
| Phase 1 (Python-only) | 1 | ❌ Already exists | ✅ |
| Phase 2-3 (TXN Metadata) | 4 | ✅ | ✅ |
| Phase 4-5 (Cycle Metadata) | 6 | ✅ | ✅ |
| Phase 6 (Gap Coverage) | 1 | ✅ | ✅ |
| Phase 7 (Advanced) | 4 | ✅ | ✅ |
| **Total** | **16** | | |

### Files Modified Per Mutation

For each new mutation, the following files need changes:

1. **`a4/standalone/mutations/<mutation_name>.py`** (NEW) - Python mutation module
2. **`a4/standalone/mutations/__init__.py`** - Export new mutation
3. **`a4/standalone/fuzzer.py`** - Add to `MUTATION_KINDS` and `_create_mutation()`
4. **`workspace/.../witgen/mod.rs`** - Rust-side mutation support (if needed)

### Testing Protocol

For each mutation, run a mini-campaign:

```bash
# Mini-campaign test command template
python -m a4.standalone.cli \
    --binary /path/to/risc0-host \
    --args "prove" "/path/to/guest.elf" \
    --db /tmp/a4_test_<MUTATION>.db \
    --kind <MUTATION_KIND> \
    --mutations 20 \
    --verbose
```

**Success Criteria:**
- ✅ No Python exceptions
- ✅ Mutations execute without crash
- ✅ At least some constraint failures detected (for most mutations)
- ✅ Results recorded in database

---

## Phase 0: Setup and Foundation

**Goal:** Prepare testing infrastructure and verify baseline.

### 0.1 Create Mini-Campaign Test Script

Create `a4/standalone/test_mini_campaign.py`:

```python
#!/usr/bin/env python3
"""
Mini-campaign test script for validating new mutations.

Usage:
    python -m a4.standalone.test_mini_campaign --kind INSTR_WORD_MOD --mutations 10
"""
```

**Tasks:**
- [ ] Create test script that runs N mutations of a specific kind
- [ ] Add summary output showing success/failure rates
- [ ] Add option to use a default test guest program

### 0.2 Verify Existing Mutations

Run baseline tests on all existing mutations:

```bash
for kind in COMP_OUT_MOD LOAD_VAL_MOD STORE_OUT_MOD PRE_EXEC_REG_MOD INSTR_TYPE_MOD MEM_VAL_MOD; do
    echo "Testing $kind..."
    python -m a4.standalone.cli --kind $kind --mutations 10 --verbose
done
```

**Tasks:**
- [ ] Verify all 6 existing mutations work
- [ ] Document any issues found
- [ ] Fix any broken mutations before proceeding

---

## Phase 1: Low-Hanging Fruit (Python-Only)

**Goal:** Implement INSTR_WORD_MOD which already has Rust support.

### 1.1 INSTR_WORD_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🔴 Highest |
| **Risk** | Low |
| **Rust Support** | ✅ Already exists |
| **Fills Gap** | Instruction fetch in MEM_VAL_MOD |

**Implementation Steps:**

#### Step 1.1.1: Create Python Module

Create `a4/standalone/mutations/instr_word_mod.py`:

```python
"""
INSTR_WORD_MOD Mutation (Standalone)

Mutates instruction fetch transaction word values.
This targets the first memory READ at each step that fetches the instruction.

Target: txns[].word for instruction fetch
Condition: First transaction at step where addr = (pc-4)/4
Expected Constraint: Instruction decoding constraints

Fills the gap explicitly left by MEM_VAL_MOD (which excludes instruction fetch).
"""

@dataclass
class InstrWordModTarget:
    step: int
    cycle_idx: int
    pc: int
    txn_idx: int           # Index of instruction fetch transaction
    addr: int              # Word address of instruction
    original_word: int     # Original instruction word
    major: int
    minor: int

def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[InstrWordModTarget]:
    """Find instruction fetch transaction at this step."""
    # 1. Get cycle info
    # 2. Get first transaction at cycle.txn_idx
    # 3. Verify it's a READ at addr = (pc-4)/4
    # 4. Return target

def create_config(target: InstrWordModTarget, mutated_value: int, output_path: Path) -> Path:
    """Create mutation config for INSTR_WORD_MOD."""
    config = {
        "mutation_type": "INSTR_WORD_MOD",
        "step": target.step,
        "word": mutated_value,
    }
    # Write and return path
```

#### Step 1.1.2: Update `__init__.py`

Add exports:
```python
from a4.standalone.mutations.instr_word_mod import (
    InstrWordModTarget,
    get_targets_at_step as get_instr_word_targets,
    create_config as create_instr_word_config,
)
```

#### Step 1.1.3: Update `fuzzer.py`

Add to `MUTATION_KINDS`:
```python
MUTATION_KINDS = [
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD", 
    "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD",
    "MEM_VAL_MOD",
    "INSTR_WORD_MOD",  # NEW
]
```

Add handler in `_create_mutation()`:
```python
elif kind == "INSTR_WORD_MOD":
    target = get_instr_word_targets(step, self.data)
    if not target:
        return None, 0, 0
    mutated_value = self.value_gen.generate_different(
        target.original_word,
        {'major': target.major, 'minor': target.minor}
    )
    config = {
        "mutation_type": "INSTR_WORD_MOD",
        "step": target.step,
        "word": mutated_value,
    }
    return config, mutated_value, target.original_word
```

#### Step 1.1.4: Test Mini-Campaign

```bash
python -m a4.standalone.cli \
    --kind INSTR_WORD_MOD \
    --mutations 20 \
    --verbose
```

**Expected Results:**
- Constraint failures related to instruction decoding
- No witness generation failures (instruction fetch is clean)

---

## Phase 2: Transaction Metadata (Low Risk)

**Goal:** Implement low-risk transaction metadata mutations.

### 2.1 TXN_PREV_WORD_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🔴 High |
| **Risk** | Low |
| **Rust Support** | ❌ Needs implementation |
| **Target** | `txns[].prev_word` |

**Implementation Steps:**

#### Step 2.1.1: Add Rust Support

In `mod.rs`, add handler after MEM_VAL_MOD:

```rust
(Some("TXN_PREV_WORD_MOD"), Some(target_step)) => {
    if let (Some(txn_idx), Some(new_prev_word)) = (extract_num("txn_idx"), extract_num("word")) {
        if let Some(txn) = trace.txns.get_mut(txn_idx as usize) {
            let original = txn.prev_word;
            txn.prev_word = new_prev_word as u32;
            println!("<a4_mutation>{{\"type\":\"TXN_PREV_WORD_MOD\", \"step\":{}, \"txn_idx\":{}, \"original\":{}, \"mutated\":{}}}</a4_mutation>",
                     target_step, txn_idx, original, new_prev_word);
        } else {
            println!("<a4_error>{{\"error\":\"txn_idx out of bounds\", \"txn_idx\":{}}}</a4_error>", txn_idx);
        }
    } else {
        println!("<a4_error>{{\"error\":\"TXN_PREV_WORD_MOD requires txn_idx and word\"}}</a4_error>");
    }
}
```

#### Step 2.1.2: Create Python Module

Create `a4/standalone/mutations/txn_prev_word_mod.py`:

```python
"""
TXN_PREV_WORD_MOD Mutation (Standalone)

Mutates txns[].prev_word field to break word consistency.

For READ transactions: constraint IsRead checks word == prev_word
For WRITE transactions: prev_word represents the previous value

Breaking this creates inconsistency in memory value tracking.
"""

@dataclass
class TxnPrevWordModTarget:
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    is_write: bool
    original_word: int       # Current word value
    original_prev_word: int  # Value we're mutating
    major: int
    minor: int
```

#### Step 2.1.3: Update exports and fuzzer

(Same pattern as Phase 1)

#### Step 2.1.4: Test Mini-Campaign

```bash
python -m a4.standalone.cli --kind TXN_PREV_WORD_MOD --mutations 20 --verbose
```

**Expected Results:**
- IsRead constraint failures for READ transactions
- MemoryWrite constraint failures for WRITE transactions

---

### 2.2 TXN_PREV_CYCLE_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🔴 High |
| **Risk** | Low |
| **Rust Support** | ❌ Needs implementation |
| **Target** | `txns[].prev_cycle` |

**Implementation Steps:**

Similar structure to 2.1, but targeting `prev_cycle` field.

```rust
// Rust handler
(Some("TXN_PREV_CYCLE_MOD"), Some(target_step)) => {
    if let (Some(txn_idx), Some(new_prev_cycle)) = (extract_num("txn_idx"), extract_num("prev_cycle")) {
        if let Some(txn) = trace.txns.get_mut(txn_idx as usize) {
            let original = txn.prev_cycle;
            txn.prev_cycle = new_prev_cycle as u32;
            // ... logging
        }
    }
}
```

**Expected Results:**
- Memory ordering/consistency constraint failures

---

## Phase 3: Transaction Metadata (Medium/High Risk)

**Goal:** Implement riskier transaction metadata mutations.

### 3.1 TXN_ADDR_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟡 Medium |
| **Risk** | High (may crash witness gen) |
| **Target** | `txns[].addr` |

**Special Considerations:**
- Changing address can cause witness generation to fail
- Need to track witness gen failures separately
- Consider strategies: small offset changes vs random addresses

**Implementation:**
- Add Rust handler for `TXN_ADDR_MOD`
- Python module with mutation strategies:
  - `adjacent`: Change to addr+1 or addr-1
  - `swap`: Swap with another transaction's address
  - `random`: Completely random address

---

### 3.2 TXN_CYCLE_PHASE_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟡 Medium |
| **Risk** | Medium |
| **Target** | `txns[].cycle` |

**Special Considerations:**
- Flips even↔odd to change READ/WRITE classification
- Simplest mutation: `cycle ^= 1` (toggle LSB)

---

## Phase 4: Cycle Metadata (Low/Medium Risk)

**Goal:** Implement cycle metadata mutations starting with lowest risk.

### 4.1 CYCLE_MODE_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟡 Medium |
| **Risk** | Low |
| **Target** | `cycles[].machine_mode` |

**Implementation:**
- Simple flip: `machine_mode ^= 1`
- Tests privilege checking constraints

---

### 4.2 CYCLE_PC_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟡 Medium |
| **Risk** | Medium |
| **Target** | `cycles[].pc` |

**Special Considerations:**
- PC is NEXT PC after instruction
- Mutation strategies:
  - `offset`: PC + small offset (±4, ±8, ±12)
  - `misalign`: PC + 1, 2, 3 (misalignment)
  - `random`: Random valid PC

---

### 4.3 CYCLE_STATE_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟡 Medium |
| **Risk** | Medium |
| **Target** | `cycles[].state` |

**Implementation:**
- Mutate to different valid state values
- See Appendix A in MUTATION_TAXONOMY.md for state values

---

## Phase 5: Cycle Metadata (High Risk)

**Goal:** Implement high-risk cycle metadata mutations.

### 5.1 CYCLE_INDEX_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | High (likely crashes) |
| **Target** | `cycles[].txn_idx`, `paging_idx`, `bigint_idx` |

**Special Considerations:**
- Breaking indices likely causes array bounds errors
- May be useful for finding panic-related bugs
- Consider "safe" mutations: swap with adjacent cycle's index

---

### 5.2 CYCLE_DIFF_COUNT_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | Medium |
| **Target** | `cycles[].diff_count` |

---

## Phase 6: Gap Coverage

**Goal:** Cover remaining gaps in txns[].word coverage.

### 6.1 REG_TXN_NON_INSN_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | Low |
| **Target** | Register transactions at non-instruction cycles (major 7+) |

**Pre-Implementation Investigation:**

Before implementing, verify that register transactions actually occur at non-instruction cycles:

```python
# Investigation script
def check_reg_txns_at_non_insn():
    """Check if any register transactions exist at major 7+ cycles."""
    for cycle in data.cycles:
        if cycle.major >= 7:
            reg_txns = data.get_reg_txns_at_step(cycle.step)
            if reg_txns:
                print(f"Found reg txns at major {cycle.major}: {reg_txns}")
```

If no register transactions exist at major 7+, this mutation can be skipped.

---

## Phase 7: Advanced Mutations

**Goal:** Implement complex mutations requiring deep understanding.

### 7.1 BIGINT_DATA_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | High |
| **Target** | `bigint_bytes[]` |

**Pre-Implementation:**
- Study BigInt operation flow
- Identify which steps have BigInt data
- Understand bigint_idx relationship

---

### 7.2 CRYPTO_STATE_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | High |
| **Target** | `backs[]` (Poseidon2State, Sha2State) |

**Pre-Implementation:**
- Study Poseidon2/SHA2 state structures
- Identify which cycles have crypto operations
- Understand state field semantics

---

### 7.3 ECALL_BACK_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | Medium |
| **Target** | `backs[]` (Ecall variant) |

**Implementation:**
- Target `Back::Ecall(u32, u32, u32)` parameters
- Identify cycles with Ecall backs

---

### 7.4 STRUCTURAL_MOD

| Property | Value |
|----------|-------|
| **Priority** | 🟢 Low |
| **Risk** | High |
| **Target** | `table_split_cycle`, `rand_z` |

**Pre-Implementation:**
- Understand table generation process
- Understand rand_z usage in checksums

---

## Implementation Checklist

### Phase 0: Setup
- [ ] 0.1 Create test script
- [ ] 0.2 Verify existing mutations

### Phase 1: Low-Hanging Fruit
- [ ] 1.1 INSTR_WORD_MOD

### Phase 2: TXN Metadata (Low Risk)
- [ ] 2.1 TXN_PREV_WORD_MOD
- [ ] 2.2 TXN_PREV_CYCLE_MOD

### Phase 3: TXN Metadata (Medium/High Risk)
- [ ] 3.1 TXN_ADDR_MOD
- [ ] 3.2 TXN_CYCLE_PHASE_MOD

### Phase 4: Cycle Metadata (Low/Medium Risk)
- [ ] 4.1 CYCLE_MODE_MOD
- [ ] 4.2 CYCLE_PC_MOD
- [ ] 4.3 CYCLE_STATE_MOD

### Phase 5: Cycle Metadata (High Risk)
- [ ] 5.1 CYCLE_INDEX_MOD
- [ ] 5.2 CYCLE_DIFF_COUNT_MOD

### Phase 6: Gap Coverage
- [ ] 6.1 REG_TXN_NON_INSN_MOD (verify existence first)

### Phase 7: Advanced
- [ ] 7.1 BIGINT_DATA_MOD
- [ ] 7.2 CRYPTO_STATE_MOD
- [ ] 7.3 ECALL_BACK_MOD
- [ ] 7.4 STRUCTURAL_MOD

---

## Appendix: Implementation Template

### Python Module Template

```python
"""
<MUTATION_NAME> Mutation (Standalone)

<Description>

Target: <target field>
Condition: <conditions>
Expected Constraint: <expected failures>
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class <MutationName>Target:
    """Target for <MUTATION_NAME> mutation."""
    step: int
    cycle_idx: int
    # ... other fields


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[<MutationName>Target]:
    """
    Get mutation target at a specific step.
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        Target if valid target exists at step, None otherwise
    """
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    
    # Find target...
    
    return <MutationName>Target(...)


def create_config(target: <MutationName>Target, mutated_value: int, output_path: Path) -> Path:
    """
    Create mutation config file.
    
    Args:
        target: The mutation target
        mutated_value: The new value
        output_path: Where to save config
        
    Returns:
        Path to created config file
    """
    config = {
        "mutation_type": "<MUTATION_NAME>",
        "step": target.step,
        # ... other fields
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """Get all steps that have valid targets for this mutation."""
    valid = []
    for cycle in data.cycles:
        if get_targets_at_step(cycle.step, data):
            valid.append(cycle.step)
    return valid
```

### Rust Handler Template

```rust
(Some("<MUTATION_NAME>"), Some(target_step)) => {
    if let (Some(txn_idx), Some(new_value)) = (extract_num("txn_idx"), extract_num("value")) {
        // Find target
        if let Some(target) = trace.<target_array>.get_mut(txn_idx as usize) {
            let original = target.<field>;
            target.<field> = new_value as u32;
            println!("<a4_mutation>{{\"type\":\"<MUTATION_NAME>\", \"step\":{}, \"txn_idx\":{}, \"original\":{}, \"mutated\":{}}}</a4_mutation>",
                     target_step, txn_idx, original, new_value);
        } else {
            println!("<a4_error>{{\"error\":\"index out of bounds\", \"idx\":{}}}</a4_error>", txn_idx);
        }
    } else {
        println!("<a4_error>{{\"error\":\"<MUTATION_NAME> requires txn_idx and value\"}}</a4_error>");
    }
}
```

---

## Timeline Estimate

| Phase | Mutations | Est. Time | Cumulative |
|-------|-----------|-----------|------------|
| Phase 0 | Setup | 1 day | 1 day |
| Phase 1 | 1 | 0.5 day | 1.5 days |
| Phase 2 | 2 | 1 day | 2.5 days |
| Phase 3 | 2 | 1.5 days | 4 days |
| Phase 4 | 3 | 2 days | 6 days |
| Phase 5 | 2 | 1.5 days | 7.5 days |
| Phase 6 | 1 | 0.5 day | 8 days |
| Phase 7 | 4 | 4 days | 12 days |

**Total Estimated Time: ~12 working days**

Note: Phase 7 (Advanced) may take longer due to complexity and required investigation.
