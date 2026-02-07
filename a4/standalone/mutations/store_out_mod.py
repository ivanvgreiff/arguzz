"""
STORE_OUT_MOD Mutation (Standalone)

Mutates the stored value of store instructions by modifying the WRITE 
transaction to memory.

When the RISC Zero executor runs a store instruction (SW, SH, SB):
1. Base address register is read
2. Source value register is read
3. Value is written to memory at computed address

A4's STORE_OUT_MOD mutates the WRITE transaction's word field, making the
recorded stored value differ from what the register should have contained.
This triggers memory consistency check failures.

Key Difference from LOAD_VAL_MOD/COMP_OUT_MOD:
- LOAD_VAL_MOD/COMP_OUT_MOD write to REGISTERS
- STORE_OUT_MOD writes to MEMORY (not in register address range)

Valid for instruction cycles with major 6:
- major 6 (MEM1): Sb, Sh, Sw
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo, A4Txn


# Valid major category for store instructions
VALID_MAJOR = 6


@dataclass
class StoreOutModTarget:
    """Target for a STORE_OUT_MOD mutation"""
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # PC value (next PC after instruction)
    major: int              # Instruction major category (always 6)
    minor: int              # Instruction minor category
    write_txn_idx: int      # Index of WRITE transaction in trace.txns[]
    write_addr: int         # Word address of memory location
    memory_byte_addr: int   # Byte address of memory location (write_addr * 4)
    original_value: int     # Original stored value


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[StoreOutModTarget]:
    """
    Get the STORE_OUT_MOD mutation target at a specific step.
    
    For store instructions, finds the WRITE transaction to memory
    and returns it as a mutation target.
    
    NOTE: This mutation type requires fetching detailed transactions
    (memory writes are not in reg_txns), which is slower (~20s per step).
    For fast fuzzing, prefer other mutation kinds.
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing cycles and transactions
        
    Returns:
        StoreOutModTarget if this step has a valid store instruction, None otherwise
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    
    # Check if this is a store instruction
    if cycle.major != VALID_MAJOR:
        return None
    
    # STORE_OUT_MOD needs detailed transactions (memory writes not in reg_txns)
    # This is slower but necessary for memory mutation
    txns = data.get_txns_for_step(step)
    if not txns:
        return None
    
    # Find the WRITE transaction to memory (not register)
    write_txn = _find_memory_write(txns)
    if not write_txn:
        return None
    
    return StoreOutModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        major=cycle.major,
        minor=cycle.minor,
        write_txn_idx=write_txn.txn_idx,
        write_addr=write_txn.addr,
        memory_byte_addr=write_txn.addr * 4,
        original_value=write_txn.word,
    )


def _find_memory_write(txns: List[A4Txn]) -> Optional[A4Txn]:
    """Find the WRITE transaction to memory (not register) within the transactions"""
    # Memory writes are WRITE transactions NOT to registers
    write_txns = [t for t in txns if t.is_write() and not t.is_register()]
    if not write_txns:
        return None
    # Return the last memory write
    return write_txns[-1]


def create_config(target: StoreOutModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for STORE_OUT_MOD.
    
    Args:
        target: The mutation target
        mutated_value: The value to write (mutated from original)
        output_path: Where to save the config
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "STORE_OUT_MOD",
        "step": target.step,
        "txn_idx": target.write_txn_idx,
        "word": mutated_value,
        "_info": {
            "memory_addr": f"0x{target.memory_byte_addr:08x}",
            "original_value": target.original_value,
            "pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
