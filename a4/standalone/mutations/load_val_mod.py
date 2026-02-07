"""
LOAD_VAL_MOD Mutation (Standalone)

Mutates the loaded value of load instructions by modifying the WRITE 
transaction to the destination register.

When the RISC Zero executor runs a load instruction (LW, LH, LB, etc.):
1. Base address register is read
2. Memory is accessed at computed address
3. Loaded value is written to destination register

A4's LOAD_VAL_MOD mutates the WRITE transaction's word field, making the
recorded loaded value differ from what memory should have contained.
This triggers memory consistency check failures.

Valid for instruction cycles with major 5:
- major 5 (MEM0): Lb, Lh, Lw, LbU, LhU
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo, A4Txn, A4RegTxn


# Register name mapping for pretty printing
REGISTER_NAMES = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    's0/fp', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
]

# Valid major category for load instructions
VALID_MAJOR = 5


@dataclass
class LoadValModTarget:
    """Target for a LOAD_VAL_MOD mutation"""
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # PC value (next PC after instruction)
    major: int              # Instruction major category (always 5)
    minor: int              # Instruction minor category
    write_txn_idx: int      # Index of WRITE transaction in trace.txns[]
    write_addr: int         # Word address of destination register
    register_idx: int       # Destination register index (0-31)
    register_name: str      # Destination register name (e.g., "a2")
    original_value: int     # Original loaded value


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[LoadValModTarget]:
    """
    Get the LOAD_VAL_MOD mutation target at a specific step.
    
    For load instructions, finds the WRITE transaction to the destination
    register and returns it as a mutation target.
    
    Uses pre-collected reg_txns for performance (avoids subprocess calls).
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing cycles and register transactions
        
    Returns:
        LoadValModTarget if this step has a valid load instruction, None otherwise
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    
    # Check if this is a load instruction
    if cycle.major != VALID_MAJOR:
        return None
    
    # Get register transactions at this step (fast - uses pre-collected data)
    reg_txns = data.get_reg_txns_at_step(step)
    if not reg_txns:
        return None
    
    # Find the WRITE transaction to a register
    write_txns = [t for t in reg_txns if t.is_write()]
    if not write_txns:
        return None
    
    # Use the last register write (destination register)
    write_txn = write_txns[-1]
    
    # Get register info
    reg_idx = write_txn.register_index()
    reg_name = REGISTER_NAMES[reg_idx] if reg_idx < len(REGISTER_NAMES) else f"x{reg_idx}"
    
    return LoadValModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        major=cycle.major,
        minor=cycle.minor,
        write_txn_idx=write_txn.txn_idx,
        write_addr=write_txn.addr,
        register_idx=reg_idx,
        register_name=reg_name,
        original_value=write_txn.word,
    )


def _find_register_write(txns: List[A4Txn]) -> Optional[A4Txn]:
    """Find the WRITE transaction to a register within the transactions"""
    write_txns = [t for t in txns if t.is_write() and t.is_register()]
    if not write_txns:
        return None
    # Return the last register write (destination register)
    return write_txns[-1]


def create_config(target: LoadValModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for LOAD_VAL_MOD.
    
    Args:
        target: The mutation target
        mutated_value: The value to write (mutated from original)
        output_path: Where to save the config
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "LOAD_VAL_MOD",
        "step": target.step,
        "txn_idx": target.write_txn_idx,
        "word": mutated_value,
        "_info": {
            "register": target.register_name,
            "original_value": target.original_value,
            "pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
