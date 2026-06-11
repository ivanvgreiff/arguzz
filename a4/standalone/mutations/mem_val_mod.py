"""
MEM_VAL_MOD Mutation (Standalone)

Mutates memory transaction values in the preflight trace. This targets memory
READ and WRITE transactions that are NOT already covered by other mutations.

================================================================================
BACKGROUND: How Memory Works in RISC-V Store/Load Instructions
================================================================================

**Load Instructions (LW, LH, LB, LHU, LBU) - major 5:**
  - Perform ONE memory operation: READ data from memory
  - The read value is then written to a REGISTER
  - The register write is covered by LOAD_VAL_MOD
  - The memory read is what MEM_VAL_MOD targets as "load_mem_read"

**Store Instructions (SW, SH, SB) - major 6:**
  - Perform TWO memory operations: READ then WRITE (Read-Modify-Write pattern)
  
  Why Read-Modify-Write?
  - Memory is organized in 32-bit words
  - For sub-word stores (SH = half-word, SB = byte), we can't just write part
    of a word; we must:
      1. READ the existing word from memory
      2. MODIFY the appropriate bytes
      3. WRITE the modified word back
  - Even SW (store word) follows this pattern in the trace for consistency
  
  Example: SB x5, 2(x10) (store byte at offset 2)
    1. READ word at address [x10] -> gets 0xAABBCCDD
    2. MODIFY byte 2 with value from x5 -> becomes 0xAAXXCCDD
    3. WRITE 0xAAXXCCDD back to address [x10]
  
  MEM_VAL_MOD targets:
    - "store_rmw_read": The READ in step 1 (Read-Modify-Write read)
    - "store_mem_write": The WRITE in step 3 (covered by STORE_OUT_MOD, excluded here)

================================================================================
TRANSACTION TYPES
================================================================================

| Type             | Instruction    | Description                              |
|------------------|----------------|------------------------------------------|
| load_mem_read    | LW/LH/LB/etc.  | Load reads data FROM memory              |
| store_rmw_read   | SW/SH/SB       | Store reads current value (RMW pattern)  |
| store_mem_write  | SW/SH/SB       | Store writes new value (EXCLUDED - see below) |
| other_mem_read   | ECALL/system   | Other memory reads (crypto, I/O, etc.)   |
| other_mem_write  | ECALL/system   | Other memory writes (crypto, I/O, etc.)  |

================================================================================
EXCLUSIONS (What MEM_VAL_MOD Does NOT Target)
================================================================================

1. **Instruction Fetch Transactions** - Covered by INSTR_WORD_MOD
   The first READ at each step fetches the instruction from memory.
   
2. **Register Transactions** - Covered by COMP_OUT_MOD, LOAD_VAL_MOD, PRE_EXEC_REG_MOD
   Register addresses are in the range 0x3FFFC020 - 0x3FFFC03F (word addresses).
   
3. **Store Memory Writes (store_mem_write)** - Covered by STORE_OUT_MOD
   The WRITE transaction during store instructions is already handled.

================================================================================
CONSTRAINT FAILURE EXPECTATIONS
================================================================================

| Transaction Type | When Mutated                        | Expected Failures        |
|------------------|-------------------------------------|--------------------------|
| load_mem_read    | Load sees wrong value from memory   | MemoryRead constraint    |
| store_rmw_read   | Store's RMW read sees wrong value   | MemoryRead constraint    |
|                  | (may cascade if circuit expects     | (different from STORE_   |
|                  | read-write consistency)             | OUT_MOD's MemoryWrite)   |
| other_mem_read   | System/crypto reads wrong value     | MemoryRead + potential   |
|                  |                                     | crypto constraint fails  |
| other_mem_write  | System/crypto writes wrong value    | MemoryWrite + potential  |
|                  |                                     | crypto constraint fails  |

================================================================================
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo, A4AllTxn


# Instruction major codes
MAJOR_LOAD = 5   # Load instructions (LW, LH, LB, LHU, LBU)
MAJOR_STORE = 6  # Store instructions (SW, SH, SB)


@dataclass
class MemValModTarget:
    """
    Target for a MEM_VAL_MOD mutation.
    
    Represents a memory transaction that can be mutated by changing its word value.
    """
    step: int               # A4 step (user_cycle) where transaction occurs
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # PC value (next PC after instruction)
    major: int              # Instruction major category
    minor: int              # Instruction minor category
    txn_idx: int            # Index of transaction in trace.txns[]
    addr: int               # Memory word address
    byte_addr: int          # Byte address (addr * 4, for display)
    original_value: int     # Original word value
    is_write: bool          # True if WRITE transaction, False if READ
    txn_type: str           # Transaction type classification (see module docstring)


def get_targets_at_step(step: int, data: 'InspectionData') -> List[MemValModTarget]:
    """
    Get all MEM_VAL_MOD mutation targets at a specific step.
    
    Finds memory transactions that can be mutated, excluding:
    - Instruction fetch transactions (covered by INSTR_WORD_MOD)
    - Register transactions (covered by other mutations)
    - Store memory writes (covered by STORE_OUT_MOD)
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        List of MemValModTarget for valid mutation targets at this step.
        May be empty if step has no valid targets.
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return []
    
    # Get memory transactions at this step (O(1) lookup from pre-indexed data)
    mem_txns = data.get_mem_txns_at_step(step)
    if not mem_txns:
        return []
    
    targets = []
    
    for txn in mem_txns:
        # EXCLUSION 1: Skip instruction fetch
        # Instruction fetch is handled by INSTR_WORD_MOD
        if _is_instruction_fetch(txn, cycle):
            continue
        
        # EXCLUSION 2: Skip store memory writes
        # These are already covered by STORE_OUT_MOD
        if txn.is_write() and cycle.major == MAJOR_STORE:
            continue
        
        # Classify the transaction type
        txn_type = _classify_txn_type(txn, cycle)
        
        targets.append(MemValModTarget(
            step=step,
            cycle_idx=cycle.cycle_idx,
            pc=cycle.pc,
            major=cycle.major,
            minor=cycle.minor,
            txn_idx=txn.txn_idx,
            addr=txn.addr,
            byte_addr=txn.addr * 4,
            original_value=txn.word,
            is_write=txn.is_write(),
            txn_type=txn_type,
        ))
    
    return targets


def _is_instruction_fetch(txn: A4AllTxn, cycle: A4CycleInfo) -> bool:
    """
    Check if a transaction is an instruction fetch.
    
    Instruction fetch characteristics:
    - First transaction of the cycle (txn_idx == cycle.txn_idx)
    - A READ transaction (even cycle number in transaction)
    - Address matches where the instruction was fetched from
    
    Note on PC semantics:
    - PC in cycle is the NEXT PC (after instruction execution)
    - For sequential instructions, the instruction was fetched from PC - 4
    - We convert to word address by dividing by 4
    
    EXCLUSION REASON: Instruction fetches are handled by INSTR_WORD_MOD,
    which mutates the instruction word directly via cycles[].
    
    Args:
        txn: The transaction to check
        cycle: The cycle info for context
        
    Returns:
        True if this is an instruction fetch transaction
    """
    # Must be the first transaction of this cycle
    if txn.txn_idx != cycle.txn_idx:
        return False
    
    # Must be a READ transaction
    if not txn.is_read():
        return False
    
    # Address must match where instruction was fetched
    # PC is the NEXT PC, so instruction was at PC - 4
    expected_fetch_addr = (cycle.pc - 4) // 4
    return txn.addr == expected_fetch_addr


def _classify_txn_type(txn: A4AllTxn, cycle: A4CycleInfo) -> str:
    """
    Classify the type of memory transaction.
    
    Classification is based on:
    1. The instruction type (major code)
    2. Whether this is a READ or WRITE transaction
    
    Transaction Types:
    
    - "load_mem_read": A load instruction (LW/LH/LB/etc.) reading data from memory.
      The loaded value will be written to a register (handled by LOAD_VAL_MOD).
      MEM_VAL_MOD targets the memory READ side of this operation.
      
    - "store_rmw_read": A store instruction (SW/SH/SB) reading the current value
      from memory as part of the Read-Modify-Write pattern. This happens BEFORE
      the store writes its new value. Mutating this causes different constraint
      failures than mutating the write (which STORE_OUT_MOD handles).
      
    - "store_mem_write": A store instruction writing to memory. This is EXCLUDED
      from MEM_VAL_MOD because it's already handled by STORE_OUT_MOD.
      
    - "other_mem_read"/"other_mem_write": Memory operations during system calls
      (ECALL), crypto operations (SHA2, Poseidon2), or other non-standard
      instruction types. These are valuable targets because they exercise
      different constraint paths than regular load/store operations.
    
    Args:
        txn: The transaction to classify
        cycle: The cycle info containing instruction major/minor
        
    Returns:
        String classification of the transaction type
    """
    if cycle.major == MAJOR_LOAD:
        # Load instruction: only has memory READ (no write)
        # The register write is a separate transaction handled elsewhere
        return "load_mem_read"
    
    elif cycle.major == MAJOR_STORE:
        # Store instruction: has both READ (RMW) and WRITE
        if txn.is_read():
            return "store_rmw_read"
        else:
            # This should be excluded by caller, but classify anyway
            return "store_mem_write"
    
    else:
        # Other instruction types (system calls, crypto, etc.)
        if txn.is_read():
            return "other_mem_read"
        else:
            return "other_mem_write"


def create_config(target: MemValModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for MEM_VAL_MOD.
    
    The config tells the Rust witgen code which transaction to mutate
    and what value to use.
    
    Args:
        target: The mutation target
        mutated_value: The new value to write (different from original)
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "MEM_VAL_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "word": mutated_value,
        "_info": {
            "description": "MEM_VAL_MOD: Mutate memory transaction value",
            "txn_type": target.txn_type,
            "is_write": target.is_write,
            "memory_addr": f"0x{target.byte_addr:08x}",
            "original_value": target.original_value,
            "original_value_hex": f"0x{target.original_value:08x}",
            "mutated_value": f"0x{mutated_value:08x}",
            "pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """
    Get all steps that have valid MEM_VAL_MOD targets.
    
    This pre-filters steps to avoid calling get_targets_at_step() on steps
    that definitely won't have any targets.
    
    Args:
        data: InspectionData with pre-collected trace information
        
    Returns:
        List of step numbers that may have MEM_VAL_MOD targets
    """
    valid_steps = []
    
    for cycle in data.cycles:
        # Any cycle with memory transactions could have targets
        # The actual filtering (exclusions) is done in get_targets_at_step()
        mem_txns = data.get_mem_txns_at_step(cycle.step)
        if mem_txns:
            valid_steps.append(cycle.step)
    
    return valid_steps
