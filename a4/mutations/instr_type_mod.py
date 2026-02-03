"""
INSTR_TYPE_MOD Mutation

This mutation targets the cycles[].major/minor fields in the PreflightTrace,
corresponding to Arguzz's INSTR_WORD_MOD mutation which changes the instruction
word during execution.

When Arguzz mutates an instruction word:
1. The instruction fetch is recorded with the ORIGINAL word
2. The execution uses the MUTATED word
3. The cycles[].major/minor records the MUTATED instruction type

A4's INSTR_TYPE_MOD directly mutates cycles[].major/minor to match the effect
of Arguzz's mutation, allowing us to see the CORE constraint that catches this
inconsistency (VerifyOpcodeF3) without cascading execution effects.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from a4.common.insn_decode import decode_insn_word
from a4.common.trace_parser import ArguzzFault, A4CycleInfo

# Re-export shared utilities for backwards compatibility
from a4.mutations.base import (
    run_a4_inspection,
    run_arguzz_mutation,
    run_a4_mutation,
    compare_failures,
    ComparisonResult,
)


@dataclass
class MutationTarget:
    """The target location in A4 for an INSTR_TYPE_MOD mutation"""
    cycle_idx: int      # Index into trace.cycles[]
    step: int           # user_cycle value
    pc: int             # PC value (next PC)
    original_major: int
    original_minor: int
    mutated_major: int
    mutated_minor: int
    original_kind_name: str
    mutated_kind_name: str


def find_mutation_target(arguzz_fault: ArguzzFault, a4_cycles: List[A4CycleInfo]) -> Optional[MutationTarget]:
    """
    Find the A4 mutation target that corresponds to an Arguzz INSTR_WORD_MOD fault.
    
    Algorithm:
    1. Decode the original instruction word to get expected major/minor
    2. Calculate expected A4 PC (Arguzz PC + 4, since A4 records next PC)
    3. Search for cycles matching PC + major/minor
    4. For loops, pick the latest iteration <= Arguzz step
    
    Args:
        arguzz_fault: The parsed Arguzz fault information
        a4_cycles: List of A4 cycle info from A4_INSPECT output
        
    Returns:
        MutationTarget if found, None otherwise
    """
    # Step 1: Decode original and mutated instructions
    original_decoded = decode_insn_word(arguzz_fault.original_value)
    mutated_decoded = decode_insn_word(arguzz_fault.mutated_value)
    
    if not original_decoded:
        print(f"ERROR: Could not decode original instruction word: {arguzz_fault.original_value}")
        return None
    
    if not mutated_decoded:
        print(f"ERROR: Could not decode mutated instruction word: {arguzz_fault.mutated_value}")
        return None
    
    expected_major = original_decoded.major
    expected_minor = original_decoded.minor
    
    # Step 2: Calculate expected A4 PC
    # A4 records the NEXT PC (after instruction), Arguzz records CURRENT PC (before)
    expected_a4_pc = arguzz_fault.pc + 4
    
    # Step 3: Find matching cycles
    exact_matches = []
    for cycle in a4_cycles:
        if (cycle.pc == expected_a4_pc and 
            cycle.major == expected_major and 
            cycle.minor == expected_minor):
            exact_matches.append(cycle)
    
    if not exact_matches:
        # Try to find close matches for debugging
        pc_matches = [c for c in a4_cycles if c.pc == expected_a4_pc]
        print(f"No exact match found for PC={expected_a4_pc}, major={expected_major}, minor={expected_minor}")
        if pc_matches:
            print(f"  Found {len(pc_matches)} cycles with matching PC but different major/minor:")
            for c in pc_matches[:5]:
                print(f"    cycle_idx={c.cycle_idx}, step={c.step}, major={c.major}, minor={c.minor}")
        return None
    
    # Step 4: Handle loops - pick the latest iteration <= Arguzz step
    if len(exact_matches) > 1:
        # For loops, pick the highest user_cycle that is still <= Arguzz step
        valid_matches = [c for c in exact_matches if c.step <= arguzz_fault.step]
        if not valid_matches:
            print(f"ERROR: No valid matches found for loop disambiguation (step <= {arguzz_fault.step})")
            return None
        result = max(valid_matches, key=lambda c: c.step)
    else:
        result = exact_matches[0]
    
    return MutationTarget(
        cycle_idx=result.cycle_idx,
        step=result.step,
        pc=result.pc,
        original_major=expected_major,
        original_minor=expected_minor,
        mutated_major=mutated_decoded.major,
        mutated_minor=mutated_decoded.minor,
        original_kind_name=original_decoded.name,
        mutated_kind_name=mutated_decoded.name,
    )


def create_config(target: MutationTarget, output_path: Path) -> Path:
    """Create an A4 mutation config file for INSTR_TYPE_MOD"""
    config = {
        "mutation_type": "INSTR_TYPE_MOD",
        "step": target.step,
        "major": target.mutated_major,
        "minor": target.mutated_minor,
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
