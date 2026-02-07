"""
PRE_EXEC_REG_MOD Mutation (Standalone)

Mutates register transactions to create inconsistencies in the trace.
This targets the memory consistency checks by modifying either:
- A READ transaction's word field (making it differ from prev_word)
- A WRITE transaction's word field (causing subsequent READs to fail)

Two strategies are supported:

Strategy "next_read":
  Find a READ of a register and modify its 'word' field while keeping
  'prev_word' unchanged. This creates word != prev_word, triggering:
  - IsRead constraint failure (direct)
  - MemoryWrite cascade failure

Strategy "prev_write":
  Find a WRITE to a register and modify its 'word' field. Subsequent
  READs will have prev_word != the modified WRITE's word, triggering:
  - MemoryWrite constraint failure only

Note: Only targets instruction cycles (major 0-6). Special operations
like Poseidon, SHA, BigInt don't check IsRead constraints.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo, A4RegTxn


# Register name mapping
REGISTER_NAMES = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
]

# USER_REGS word address base
USER_REGS_BASE = 1073725472  # 0xFFFF0080 / 4

# Maximum major value for instruction cycles
MAX_INSTRUCTION_MAJOR = 6


@dataclass
class PreExecRegModTarget:
    """Target for a PRE_EXEC_REG_MOD mutation"""
    step: int               # A4 step where the transaction occurs
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # PC value at this step
    major: int              # Instruction major category
    minor: int              # Instruction minor category
    txn_idx: int            # Index of target transaction
    addr: int               # Word address of register
    register_idx: int       # Register index (0-31)
    register_name: str      # Register name (e.g., "s3")
    original_word: int      # Original word value
    prev_word: int          # Previous word value (for consistency check)
    is_write: bool          # True if WRITE, False if READ
    strategy: str           # "next_read" or "prev_write"


def get_targets_at_step(
    step: int, 
    data: 'InspectionData',
    strategy: str = "next_read"
) -> List[PreExecRegModTarget]:
    """
    Get all PRE_EXEC_REG_MOD mutation targets at a specific step.
    
    Unlike other mutations, PRE_EXEC_REG_MOD can have multiple targets
    per step (one per register transaction).
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing cycles and register transactions
        strategy: "next_read" or "prev_write"
        
    Returns:
        List of PreExecRegModTarget for valid register transactions at this step
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return []
    
    # Only target instruction cycles
    if cycle.major > MAX_INSTRUCTION_MAJOR:
        return []
    
    # Get register transactions at this step
    reg_txns = data.get_reg_txns_at_step(step)
    if not reg_txns:
        return []
    
    targets = []
    for txn in reg_txns:
        # Filter by strategy
        if strategy == "next_read" and not txn.is_read():
            continue
        if strategy == "prev_write" and not txn.is_write():
            continue
        
        reg_idx = txn.register_index()
        reg_name = REGISTER_NAMES[reg_idx] if reg_idx < len(REGISTER_NAMES) else f"x{reg_idx}"
        
        targets.append(PreExecRegModTarget(
            step=step,
            cycle_idx=cycle.cycle_idx,
            pc=cycle.pc,
            major=cycle.major,
            minor=cycle.minor,
            txn_idx=txn.txn_idx,
            addr=txn.addr,
            register_idx=reg_idx,
            register_name=reg_name,
            original_word=txn.word,
            prev_word=txn.prev_word,
            is_write=txn.is_write(),
            strategy=strategy,
        ))
    
    return targets


def get_all_targets(
    data: 'InspectionData',
    strategy: str = "next_read",
    register_filter: Optional[List[int]] = None
) -> List[PreExecRegModTarget]:
    """
    Get all PRE_EXEC_REG_MOD targets across the entire trace.
    
    This is more efficient than calling get_targets_at_step() for every step
    because it iterates through reg_txns directly.
    
    Args:
        data: InspectionData containing cycles and register transactions
        strategy: "next_read" or "prev_write"
        register_filter: Optional list of register indices to target (None = all)
        
    Returns:
        List of all valid targets
    """
    targets = []
    step_to_cycle = {c.step: c for c in data.cycles}
    
    for txn in data.reg_txns:
        # Filter by strategy
        if strategy == "next_read" and not txn.is_read():
            continue
        if strategy == "prev_write" and not txn.is_write():
            continue
        
        # Get cycle info
        cycle = step_to_cycle.get(txn.step)
        if not cycle or cycle.major > MAX_INSTRUCTION_MAJOR:
            continue
        
        # Filter by register if specified
        reg_idx = txn.register_index()
        if register_filter is not None and reg_idx not in register_filter:
            continue
        
        reg_name = REGISTER_NAMES[reg_idx] if reg_idx < len(REGISTER_NAMES) else f"x{reg_idx}"
        
        targets.append(PreExecRegModTarget(
            step=txn.step,
            cycle_idx=cycle.cycle_idx,
            pc=cycle.pc,
            major=cycle.major,
            minor=cycle.minor,
            txn_idx=txn.txn_idx,
            addr=txn.addr,
            register_idx=reg_idx,
            register_name=reg_name,
            original_word=txn.word,
            prev_word=txn.prev_word,
            is_write=txn.is_write(),
            strategy=strategy,
        ))
    
    return targets


def create_config(target: PreExecRegModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for PRE_EXEC_REG_MOD.
    
    Args:
        target: The mutation target
        mutated_value: The value to write (mutated from original)
        output_path: Where to save the config
        
    Returns:
        Path to the created config file
    """
    if target.strategy == "next_read":
        note = "Modifies READ word to create word != prev_word (triggers IsRead + MemoryWrite)"
    else:
        note = "Modifies WRITE word; subsequent READ's prev_word won't match (triggers MemoryWrite)"
    
    config = {
        "mutation_type": "PRE_EXEC_REG_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "word": mutated_value,
        "strategy": target.strategy,
        "_info": {
            "register": target.register_name,
            "register_idx": target.register_idx,
            "original_word": target.original_word,
            "prev_word": target.prev_word,
            "is_write_target": target.is_write,
            "pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
            "note": note,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
