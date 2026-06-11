"""
INSTR_WORD_MOD Mutation (Standalone)

Mutates the instruction word fetched from memory at the start of each instruction
or ECALL cycle. This changes what instruction the circuit "sees" without affecting
memory consistency.

Target: txns[].word AND txns[].prev_word (both set to same mutated value)
Condition: First transaction at instruction/ECALL step

================================================================================
SUPPORTED CYCLE TYPES
================================================================================

This mutation targets cycles with:
  - major 0-6: Regular RISC-V instructions (MISC0-2, MUL0, DIV0, MEM0-1)
  - major 8: ECALL cycles (system calls)

NOT supported:
  - major 7: CONTROL cycles (no instruction fetch, system state management)
  - major 9-10: POSEIDON cycles (cryptographic ops, no transactions)
  - major 11: SHA cycles (hashing ops)

================================================================================
EXCLUSIONS
================================================================================

Step 0 is excluded because:
  1. It has 16,574 cycles (massive overhead to iterate through)
  2. The instruction is AUIPC x3, 0x40011000 at kernel address 0xC0000000
  3. This is RISC Zero bootloader initialization, not user program code
  4. It's the same instruction every execution (not input-dependent)

================================================================================
WHY BOTH word AND prev_word ARE SET
================================================================================

The Rust handler sets both fields to the same mutated value:
    txn.word = new_word;
    txn.prev_word = new_word;

This is intentional because instruction fetch is a READ transaction, and for READs
the circuit enforces `word == prev_word` (IsRead constraint).

By setting both to the same mutated value:
1. The IsRead constraint still passes (memory consistency preserved)
2. But the circuit now "sees" a different instruction word
3. This causes INSTRUCTION DECODING constraints to fail

If we only changed `word` but not `prev_word`, the IsRead constraint would fail
instead of instruction decoding. This mutation is specifically designed to test
instruction decoding logic, not memory consistency.

Memory consistency (IsRead) is already tested by MEM_VAL_MOD on other memory
transactions.

================================================================================
BRANCH/JUMP HANDLING
================================================================================

For branches (BEQ, BNE, BLT, BGE, etc.) and jumps (JAL, JALR):
  - cycle.pc stores the NEXT PC (branch target or sequential)
  - We DO NOT use (cycle.pc - 4) / 4 to calculate instruction address
  - Instead, we use cycle.txn_idx directly to find the instruction fetch
  - This correctly handles all instruction types regardless of control flow

================================================================================
EXPECTED CONSTRAINT FAILURES
================================================================================

Mutating the instruction word should trigger:
  - Instruction decoding constraints (opcode validation: VerifyOpcodeF3F7)
  - Potentially instruction-specific computation constraints

NOTE: Changing the opcode to a different instruction type may cause prover crashes
instead of constraint failures due to instruction format mismatch.

================================================================================
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo


def _is_instruction_or_ecall(major: int) -> bool:
    """
    Check if a cycle major indicates an instruction or ECALL.
    
    Args:
        major: The cycle's major value
        
    Returns:
        True if major indicates instruction (0-6) or ECALL (8)
    """
    return major <= 6 or major == 8


@dataclass
class InstrWordModTarget:
    """
    Target for an INSTR_WORD_MOD mutation.
    
    Represents the instruction fetch transaction that can be mutated.
    """
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # NEXT PC (after instruction execution)
    txn_idx: int            # Index of instruction fetch transaction
    fetch_addr: int         # Word address where instruction was fetched
    original_word: int      # Original instruction word
    major: int              # Instruction major category
    minor: int              # Instruction minor variant


def _find_instruction_cycle(step: int, data: 'InspectionData') -> Optional[A4CycleInfo]:
    """
    Find the instruction or ECALL cycle for a given step.
    
    Multi-cycle steps may have multiple cycles (e.g., ECALL handling has
    multiple ECALL cycles, then an instruction cycle for the return).
    We need to find the cycle that has an instruction fetch.
    
    Args:
        step: The step number to search for
        data: InspectionData containing cycles
        
    Returns:
        The instruction/ECALL cycle, or None if not found
    """
    # For multi-cycle steps, iterate through all cycles to find instruction/ECALL
    for cycle in data.cycles:
        if cycle.step == step and _is_instruction_or_ecall(cycle.major):
            return cycle
    return None


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[InstrWordModTarget]:
    """
    Get the INSTR_WORD_MOD mutation target at a specific step.
    
    Instruction fetch is the first transaction at each instruction/ECALL cycle.
    We use cycle.txn_idx directly to find it, avoiding the (pc-4)/4 calculation
    that fails for branches and jumps.
    
    Args:
        step: The step number to find target for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        InstrWordModTarget if valid instruction fetch found, None otherwise
    """
    # Exclude step 0 (bootloader initialization, massive overhead)
    if step == 0:
        return None
    
    # Find the instruction or ECALL cycle for this step
    cycle = _find_instruction_cycle(step, data)
    if not cycle:
        return None
    
    # Get the first transaction at this cycle (instruction fetch)
    txn_idx = cycle.txn_idx
    if txn_idx >= len(data.all_txns):
        return None
    
    txn = data.all_txns[txn_idx]
    
    # Verify it's a READ transaction (instruction fetch should be a read)
    if not txn.is_read():
        return None
    
    return InstrWordModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        txn_idx=txn.txn_idx,
        fetch_addr=txn.addr,
        original_word=txn.word,
        major=cycle.major,
        minor=cycle.minor,
    )


def create_config(target: InstrWordModTarget, mutated_value: int, output_path: Path) -> Path:
    """
    Create an A4 mutation config file for INSTR_WORD_MOD.
    
    The config tells the Rust witgen code which instruction to mutate.
    Note: The Rust handler identifies the transaction by step, not txn_idx,
    and sets BOTH word and prev_word to the mutated value.
    
    Args:
        target: The mutation target
        mutated_value: The new instruction word (different from original)
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    config = {
        "mutation_type": "INSTR_WORD_MOD",
        "step": target.step,
        "word": mutated_value,
        "_info": {
            "description": "INSTR_WORD_MOD: Mutate instruction fetch word",
            "note": "Rust handler sets both word and prev_word to preserve IsRead",
            "fetch_word_addr": target.fetch_addr,
            "fetch_byte_addr": f"0x{target.fetch_addr * 4:08x}",
            "original_value": target.original_word,
            "original_word": f"0x{target.original_word:08x}",
            "mutated_word": f"0x{mutated_value:08x}",
            "next_pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """
    Get all steps that have valid INSTR_WORD_MOD targets.
    
    Includes instruction cycles (major 0-6) and ECALL cycles (major 8).
    Excludes step 0 (bootloader initialization).
    
    Args:
        data: InspectionData with pre-collected trace information
        
    Returns:
        List of step numbers that have INSTR_WORD_MOD targets
    """
    valid_steps = set()  # Use set to avoid duplicates from multi-cycle steps
    
    for cycle in data.cycles:
        # Skip step 0 (bootloader)
        if cycle.step == 0:
            continue
        
        # Include instruction cycles (major 0-6) and ECALL (major 8)
        if _is_instruction_or_ecall(cycle.major):
            # Verify target exists
            if get_targets_at_step(cycle.step, data):
                valid_steps.add(cycle.step)
    
    return sorted(valid_steps)
