# Phase 2: Transaction Metadata Mutations Implementation Plan

## Overview

**Phase 2.1**: TXN_PREV_WORD_MOD  
**Phase 2.2**: TXN_PREV_CYCLE_MOD

Both mutations target previously untouched fields in `RawMemoryTransaction`, filling documented gaps GAP-F-3 and GAP-F-4.

---

## Pre-Implementation Verification Summary

### No Overlap Confirmation

| Existing Mutation | Modifies `prev_word`? | Modifies `prev_cycle`? |
|-------------------|----------------------|------------------------|
| COMP_OUT_MOD | ❌ Only `word` | ❌ |
| LOAD_VAL_MOD | ❌ Only `word` | ❌ |
| STORE_OUT_MOD | ❌ Only `word` | ❌ |
| PRE_EXEC_REG_MOD | ❌ Only `word` | ❌ |
| MEM_VAL_MOD | ❌ Only `word` | ❌ |
| INSTR_WORD_MOD | Sets both to SAME value | ❌ |
| INSTR_TYPE_MOD | N/A (cycles) | N/A (cycles) |

**INSTR_WORD_MOD Special Case**: Sets `word = prev_word = mutated_value` (both equal) to preserve IsRead. This is different from TXN_PREV_WORD_MOD which creates `word != prev_word`.

### Constraint Analysis

**TXN_PREV_WORD_MOD Target Constraint** (mem.zir:79-80):
```
IsRead constraint:
  old_txn.data_low == new_txn.data_low   (prev_word_low == word_low)
  old_txn.data_high == new_txn.data_high (prev_word_high == word_high)
```
Changing `prev_word` while keeping `word` intact breaks this equality.

**TXN_PREV_CYCLE_MOD Target Constraint** (mem.zir:83-84):
```
IsForward constraint:
  IsCycle(new_txn.cycle - old_txn.cycle)  (current_cycle - prev_cycle)
```
This validates temporal ordering. Changing `prev_cycle` breaks the expected cycle difference.

---

## Phase 2.1: TXN_PREV_WORD_MOD

### Step 2.1.1: Add Rust Support

**File**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

Add after MEM_VAL_MOD handler (around line 560):

```rust
(Some("TXN_PREV_WORD_MOD"), Some(target_step)) => {
    // TXN_PREV_WORD_MOD: Mutate txns[].prev_word to break memory consistency
    // This targets the IsRead constraint which checks word == prev_word for READs
    
    let txn_idx = extract_num("txn_idx");
    let new_prev_word = extract_num("word");  // "word" key contains the mutated prev_word value
    
    match (txn_idx, new_prev_word) {
        (Some(idx), Some(new_val)) => {
            let idx = idx as usize;
            if idx < trace.txns.len() {
                let txn = &mut trace.txns[idx];
                let original_prev_word = txn.prev_word;
                let current_word = txn.word;
                let is_read = txn.cycle % 2 == 0;
                
                // Apply mutation
                txn.prev_word = new_val;
                
                // Find cycle info for logging
                let mut cycle_info: Option<(usize, u32, u8, u8)> = None;
                for (ci, cycle) in trace.cycles.iter().enumerate() {
                    if cycle.user_cycle == target_step {
                        cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                        break;
                    }
                }
                
                let txn_type = if is_read { "READ" } else { "WRITE" };
                
                if let Some((ci, pc, major, minor)) = cycle_info {
                    println!("<a4_txn_prev_word_mod>{{\"step\":{}, \"cycle_idx\":{}, \"txn_idx\":{}, \"pc\":{}, \"addr\":{}, \"txn_type\":\"{}\", \"word\":{}, \"original_prev_word\":{}, \"new_prev_word\":{}, \"major\":{}, \"minor\":{}}}</a4_txn_prev_word_mod>",
                             target_step, ci, idx, pc, txn.addr, txn_type, current_word, original_prev_word, new_val, major, minor);
                } else {
                    println!("<a4_txn_prev_word_mod>{{\"step\":{}, \"txn_idx\":{}, \"addr\":{}, \"txn_type\":\"{}\", \"word\":{}, \"original_prev_word\":{}, \"new_prev_word\":{}}}</a4_txn_prev_word_mod>",
                             target_step, idx, txn.addr, txn_type, current_word, original_prev_word, new_val);
                }
            } else {
                println!("<a4_error>{{\"error\":\"txn_idx out of range\", \"txn_idx\":{}, \"max\":{}}}</a4_error>",
                         idx, trace.txns.len());
            }
        }
        _ => {
            println!("<a4_error>{{\"error\":\"TXN_PREV_WORD_MOD requires txn_idx and word\"}}</a4_error>");
        }
    }
}
```

### Step 2.1.2: Create Python Module

**File**: `a4/standalone/mutations/txn_prev_word_mod.py`

```python
"""
TXN_PREV_WORD_MOD Mutation (Standalone)

Mutates txns[].prev_word field to break memory value consistency.

================================================================================
BACKGROUND: Memory Consistency in RISC Zero
================================================================================

For READ transactions, the circuit enforces:
  IsRead constraint (mem.zir:79-80): word == prev_word

This ensures that when reading from memory, the value matches what was 
previously stored at that address. By changing prev_word while keeping word
intact, we create word != prev_word, triggering IsRead constraint failures.

For WRITE transactions:
  prev_word represents the value that was at this address before the write.
  Changing it affects memory tracking consistency.

================================================================================
DIFFERENCE FROM INSTR_WORD_MOD
================================================================================

INSTR_WORD_MOD sets both word AND prev_word to the SAME mutated value,
preserving word == prev_word but changing the actual instruction bits.

TXN_PREV_WORD_MOD changes ONLY prev_word, creating word != prev_word
to directly target the IsRead constraint.

================================================================================
EXPECTED CONSTRAINT FAILURES
================================================================================

- For READ transactions: IsRead constraint (word != prev_word)
- For WRITE transactions: Memory tracking constraints

================================================================================
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class TxnPrevWordModTarget:
    """
    Target for a TXN_PREV_WORD_MOD mutation.
    """
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    txn_idx: int            # Index into trace.txns[]
    addr: int               # Word address
    is_read: bool           # True if READ transaction
    original_word: int      # Current word value (not mutated)
    original_prev_word: int # Value we're mutating
    major: int              # Instruction major category
    minor: int              # Instruction minor variant


def get_targets_at_step(step: int, data: 'InspectionData') -> List[TxnPrevWordModTarget]:
    """
    Get all TXN_PREV_WORD_MOD mutation targets at a specific step.
    
    Any transaction can be targeted - both READs and WRITEs.
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        List of TxnPrevWordModTarget for all transactions at this step
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return []
    
    targets = []
    
    # Get all transactions for this cycle
    txn_start = cycle.txn_idx
    txn_end = data.get_next_txn_idx(step)
    
    for txn_idx in range(txn_start, txn_end):
        txn = data.get_txn(txn_idx)
        if not txn:
            continue
        
        targets.append(TxnPrevWordModTarget(
            step=step,
            cycle_idx=cycle.cycle_idx,
            txn_idx=txn_idx,
            addr=txn.addr,
            is_read=txn.is_read(),
            original_word=txn.word,
            original_prev_word=txn.prev_word,
            major=cycle.major,
            minor=cycle.minor,
        ))
    
    return targets


def create_config(target: TxnPrevWordModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for TXN_PREV_WORD_MOD.
    
    Args:
        target: The mutation target
        mutated_value: The new prev_word value (should be different from original)
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "TXN_PREV_WORD_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "word": mutated_value,  # "word" key contains the new prev_word value
        "_info": {
            "description": "TXN_PREV_WORD_MOD: Mutate prev_word to break IsRead",
            "addr": f"0x{target.addr * 4:08x}",
            "is_read": target.is_read,
            "original_word": f"0x{target.original_word:08x}",
            "original_prev_word": f"0x{target.original_prev_word:08x}",
            "mutated_prev_word": f"0x{mutated_value:08x}",
            "expected_constraint": "IsRead" if target.is_read else "MemoryWrite",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """
    Get all steps that have valid TXN_PREV_WORD_MOD targets.
    
    All steps with transactions are valid.
    
    Args:
        data: InspectionData with pre-collected trace information
        
    Returns:
        List of step numbers that have TXN_PREV_WORD_MOD targets
    """
    valid_steps = []
    
    for cycle in data.cycles:
        # Any step with transactions is valid
        if get_targets_at_step(cycle.step, data):
            valid_steps.append(cycle.step)
    
    return valid_steps
```

### Step 2.1.3: Update Exports

**File**: `a4/standalone/mutations/__init__.py`

Add imports:
```python
from a4.standalone.mutations.txn_prev_word_mod import (
    TxnPrevWordModTarget,
    get_targets_at_step as get_txn_prev_word_targets,
    create_config as create_txn_prev_word_config,
    get_valid_steps as get_txn_prev_word_valid_steps,
)
```

Add to `__all__`:
```python
    # TXN_PREV_WORD_MOD
    'TxnPrevWordModTarget',
    'get_txn_prev_word_targets',
    'create_txn_prev_word_config',
    'get_txn_prev_word_valid_steps',
```

### Step 2.1.4: Update Fuzzer

**File**: `a4/standalone/fuzzer.py`

Add to `MUTATION_KINDS`:
```python
"TXN_PREV_WORD_MOD",
```

Add handler in `_create_mutation()`:
```python
elif kind == "TXN_PREV_WORD_MOD":
    # TXN_PREV_WORD_MOD: Mutate prev_word to break IsRead constraint
    targets = get_txn_prev_word_targets(step, self.data)
    if not targets:
        return None, 0, 0
    # Select one target randomly
    target = self.rng.choice(targets)
    mutated_value = self.value_gen.generate_different(
        target.original_prev_word,
        {
            'major': target.major,
            'minor': target.minor,
            'txn_type': 'prev_word_read' if target.is_read else 'prev_word_write',
        }
    )
    config = {
        "mutation_type": "TXN_PREV_WORD_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "word": mutated_value,
    }
    return config, mutated_value, target.original_prev_word
```

### Step 2.1.5: Test Mini-Campaign

```bash
cd /root/arguzz

# Build first (if not done)
cd workspace/output && cargo build --release && cd ../..

# Test INSTR_WORD_MOD (verify Phase 1 works)
python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --args "prove" \
    --kind TXN_PREV_WORD_MOD \
    --mutations 20 \
    --verbose
```

**Expected Results:**
- IsRead constraint failures for READ transactions
- MemoryWrite constraint failures for WRITE transactions
- No witness generation panics

---

## Phase 2.2: TXN_PREV_CYCLE_MOD

### Step 2.2.1: Add Rust Support

**File**: `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`

Add after TXN_PREV_WORD_MOD handler:

```rust
(Some("TXN_PREV_CYCLE_MOD"), Some(target_step)) => {
    // TXN_PREV_CYCLE_MOD: Mutate txns[].prev_cycle to break cycle ordering
    // This targets the IsForward constraint which validates temporal ordering
    
    let txn_idx = extract_num("txn_idx");
    let new_prev_cycle = extract_num("prev_cycle");
    
    match (txn_idx, new_prev_cycle) {
        (Some(idx), Some(new_val)) => {
            let idx = idx as usize;
            if idx < trace.txns.len() {
                let txn = &mut trace.txns[idx];
                let original_prev_cycle = txn.prev_cycle;
                let current_cycle = txn.cycle;
                let is_read = txn.cycle % 2 == 0;
                
                // Apply mutation
                txn.prev_cycle = new_val;
                
                // Find cycle info for logging
                let mut cycle_info: Option<(usize, u32, u8, u8)> = None;
                for (ci, cycle) in trace.cycles.iter().enumerate() {
                    if cycle.user_cycle == target_step {
                        cycle_info = Some((ci, cycle.pc, cycle.major, cycle.minor));
                        break;
                    }
                }
                
                let txn_type = if is_read { "READ" } else { "WRITE" };
                
                if let Some((ci, pc, major, minor)) = cycle_info {
                    println!("<a4_txn_prev_cycle_mod>{{\"step\":{}, \"cycle_idx\":{}, \"txn_idx\":{}, \"pc\":{}, \"addr\":{}, \"txn_type\":\"{}\", \"current_cycle\":{}, \"original_prev_cycle\":{}, \"new_prev_cycle\":{}, \"major\":{}, \"minor\":{}}}</a4_txn_prev_cycle_mod>",
                             target_step, ci, idx, pc, txn.addr, txn_type, current_cycle, original_prev_cycle, new_val, major, minor);
                } else {
                    println!("<a4_txn_prev_cycle_mod>{{\"step\":{}, \"txn_idx\":{}, \"addr\":{}, \"txn_type\":\"{}\", \"current_cycle\":{}, \"original_prev_cycle\":{}, \"new_prev_cycle\":{}}}</a4_txn_prev_cycle_mod>",
                             target_step, idx, txn.addr, txn_type, current_cycle, original_prev_cycle, new_val);
                }
            } else {
                println!("<a4_error>{{\"error\":\"txn_idx out of range\", \"txn_idx\":{}, \"max\":{}}}</a4_error>",
                         idx, trace.txns.len());
            }
        }
        _ => {
            println!("<a4_error>{{\"error\":\"TXN_PREV_CYCLE_MOD requires txn_idx and prev_cycle\"}}</a4_error>");
        }
    }
}
```

### Step 2.2.2: Create Python Module

**File**: `a4/standalone/mutations/txn_prev_cycle_mod.py`

```python
"""
TXN_PREV_CYCLE_MOD Mutation (Standalone)

Mutates txns[].prev_cycle field to break memory temporal consistency.

================================================================================
BACKGROUND: Memory Temporal Ordering in RISC Zero
================================================================================

Each memory transaction records:
- `cycle`: The current cycle number for this transaction
- `prev_cycle`: The cycle number when this address was last accessed

The circuit enforces temporal ordering via:
  IsForward constraint (mem.zir:83-84): IsCycle(current_cycle - prev_cycle)

This validates that memory accesses are properly ordered in time.
By changing prev_cycle, we break this temporal ordering constraint.

================================================================================
MUTATION STRATEGIES
================================================================================

Interesting values for prev_cycle mutation:
1. `current_cycle` - Makes difference 0 (IsCycle may fail on 0)
2. `current_cycle + N` - Makes difference negative (invalid)
3. `0` - Maximum difference (may overflow or fail bounds)
4. Random value - Unpredictable difference

================================================================================
EXPECTED CONSTRAINT FAILURES
================================================================================

- IsForward/IsCycle constraints (cycle ordering validation)
- Potentially memory consistency cascading failures

================================================================================
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class TxnPrevCycleModTarget:
    """
    Target for a TXN_PREV_CYCLE_MOD mutation.
    """
    step: int                   # A4 step (user_cycle)
    cycle_idx: int              # Index into trace.cycles[]
    txn_idx: int                # Index into trace.txns[]
    addr: int                   # Word address
    is_read: bool               # True if READ transaction
    current_cycle: int          # Current transaction cycle value
    original_prev_cycle: int    # Value we're mutating
    major: int                  # Instruction major category
    minor: int                  # Instruction minor variant


def get_targets_at_step(step: int, data: 'InspectionData') -> List[TxnPrevCycleModTarget]:
    """
    Get all TXN_PREV_CYCLE_MOD mutation targets at a specific step.
    
    Any transaction can be targeted.
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        List of TxnPrevCycleModTarget for all transactions at this step
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return []
    
    targets = []
    
    # Get all transactions for this cycle
    txn_start = cycle.txn_idx
    txn_end = data.get_next_txn_idx(step)
    
    for txn_idx in range(txn_start, txn_end):
        txn = data.get_txn(txn_idx)
        if not txn:
            continue
        
        targets.append(TxnPrevCycleModTarget(
            step=step,
            cycle_idx=cycle.cycle_idx,
            txn_idx=txn_idx,
            addr=txn.addr,
            is_read=txn.is_read(),
            current_cycle=txn.cycle,
            original_prev_cycle=txn.prev_cycle,
            major=cycle.major,
            minor=cycle.minor,
        ))
    
    return targets


def generate_mutated_prev_cycle(target: TxnPrevCycleModTarget, rng) -> int:
    """
    Generate an interesting mutated prev_cycle value.
    
    Strategies:
    1. Same as current (makes difference 0)
    2. Greater than current (makes difference negative - invalid)
    3. Zero (maximum difference)
    4. Random
    """
    import random
    
    strategies = [
        lambda: target.current_cycle,                    # Same as current
        lambda: target.current_cycle + 1,               # Just after current
        lambda: target.current_cycle + rng.randint(1, 100),  # Future
        lambda: 0,                                       # Zero
        lambda: rng.randint(0, 0xFFFFFFFF),             # Random
    ]
    
    # Pick a strategy
    strategy = rng.choice(strategies)
    mutated = strategy()
    
    # Ensure it's different from original
    if mutated == target.original_prev_cycle:
        mutated = (target.original_prev_cycle + 1) % 0x100000000
    
    return mutated


def create_config(target: TxnPrevCycleModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for TXN_PREV_CYCLE_MOD.
    
    Args:
        target: The mutation target
        mutated_value: The new prev_cycle value
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    # Calculate what the cycle difference would be
    original_diff = target.current_cycle - target.original_prev_cycle
    new_diff = target.current_cycle - mutated_value
    
    config = {
        "mutation_type": "TXN_PREV_CYCLE_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "prev_cycle": mutated_value,
        "_info": {
            "description": "TXN_PREV_CYCLE_MOD: Mutate prev_cycle to break IsForward",
            "addr": f"0x{target.addr * 4:08x}",
            "is_read": target.is_read,
            "current_cycle": target.current_cycle,
            "original_prev_cycle": target.original_prev_cycle,
            "mutated_prev_cycle": mutated_value,
            "original_diff": original_diff,
            "new_diff": new_diff,
            "expected_constraint": "IsForward/IsCycle",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """
    Get all steps that have valid TXN_PREV_CYCLE_MOD targets.
    
    All steps with transactions are valid.
    
    Args:
        data: InspectionData with pre-collected trace information
        
    Returns:
        List of step numbers that have TXN_PREV_CYCLE_MOD targets
    """
    valid_steps = []
    
    for cycle in data.cycles:
        if get_targets_at_step(cycle.step, data):
            valid_steps.append(cycle.step)
    
    return valid_steps
```

### Step 2.2.3: Update Exports

**File**: `a4/standalone/mutations/__init__.py`

Add imports:
```python
from a4.standalone.mutations.txn_prev_cycle_mod import (
    TxnPrevCycleModTarget,
    get_targets_at_step as get_txn_prev_cycle_targets,
    create_config as create_txn_prev_cycle_config,
    get_valid_steps as get_txn_prev_cycle_valid_steps,
    generate_mutated_prev_cycle,
)
```

Add to `__all__`:
```python
    # TXN_PREV_CYCLE_MOD
    'TxnPrevCycleModTarget',
    'get_txn_prev_cycle_targets',
    'create_txn_prev_cycle_config',
    'get_txn_prev_cycle_valid_steps',
    'generate_mutated_prev_cycle',
```

### Step 2.2.4: Update Fuzzer

**File**: `a4/standalone/fuzzer.py`

Add to `MUTATION_KINDS`:
```python
"TXN_PREV_CYCLE_MOD",
```

Add handler in `_create_mutation()`:
```python
elif kind == "TXN_PREV_CYCLE_MOD":
    # TXN_PREV_CYCLE_MOD: Mutate prev_cycle to break IsForward constraint
    targets = get_txn_prev_cycle_targets(step, self.data)
    if not targets:
        return None, 0, 0
    # Select one target randomly
    target = self.rng.choice(targets)
    mutated_value = generate_mutated_prev_cycle(target, self.rng)
    config = {
        "mutation_type": "TXN_PREV_CYCLE_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "prev_cycle": mutated_value,
    }
    return config, mutated_value, target.original_prev_cycle
```

### Step 2.2.5: Test Mini-Campaign

```bash
cd /root/arguzz

python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --args "prove" \
    --kind TXN_PREV_CYCLE_MOD \
    --mutations 20 \
    --verbose
```

**Expected Results:**
- IsForward/IsCycle constraint failures
- Possibly witness generation issues for extreme values

---

## Implementation Checklist

### Phase 2.1: TXN_PREV_WORD_MOD
- [ ] Add Rust handler in `mod.rs`
- [ ] Create `txn_prev_word_mod.py`
- [ ] Update `__init__.py` exports
- [ ] Update `fuzzer.py` MUTATION_KINDS and handler
- [ ] Rebuild: `cd workspace/output && cargo build --release`
- [ ] Run mini-campaign test
- [ ] Verify IsRead constraint failures appear

### Phase 2.2: TXN_PREV_CYCLE_MOD
- [ ] Add Rust handler in `mod.rs`
- [ ] Create `txn_prev_cycle_mod.py`
- [ ] Update `__init__.py` exports
- [ ] Update `fuzzer.py` MUTATION_KINDS and handler
- [ ] Rebuild: `cd workspace/output && cargo build --release`
- [ ] Run mini-campaign test
- [ ] Verify IsForward/IsCycle constraint failures appear

---

## Appendix: Constraint Reference

### IsRead (mem.zir:79-80)
```
// For READ transactions: old value must equal new value
old_txn.data_low == new_txn.data_low
old_txn.data_high == new_txn.data_high
```

### IsForward (mem.zir:83-84)
```
// Validates cycle ordering
IsCycle(new_txn.cycle - old_txn.cycle)
```

### IsCycle (mem.zir:61-62)
```
// Validates a cycle value
count == 1
cycle == arg0
```
