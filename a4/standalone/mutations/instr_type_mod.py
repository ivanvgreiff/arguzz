"""
INSTR_TYPE_MOD Mutation (Standalone)

Mutates the instruction type (major/minor) in the PreflightTrace,
causing a mismatch between what the circuit expects and what was recorded.

When the RISC Zero executor runs an instruction:
1. Instruction is fetched and recorded with its actual major/minor
2. Execution proceeds based on the decoded instruction type

A4's INSTR_TYPE_MOD directly modifies cycles[].major and/or cycles[].minor,
creating a mismatch that triggers VerifyOpcodeF3 constraint failures.

Valid for instruction cycles with major 0-6:
- major 0 (MISC0) through major 6 (MEM1)
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo
from a4.core.insn_decode import INSN_KIND_NAMES


# Valid major categories for instruction cycles
VALID_MAJORS = {0, 1, 2, 3, 4, 5, 6}


@dataclass
class InstrTypeModTarget:
    """Target for an INSTR_TYPE_MOD mutation"""
    step: int               # A4 step (user_cycle)
    cycle_idx: int          # Index into trace.cycles[]
    pc: int                 # PC value (next PC after instruction)
    original_major: int     # Original major category
    original_minor: int     # Original minor category
    kind_name: str          # Human-readable instruction name (e.g., "Add")


def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[InstrTypeModTarget]:
    """
    Get the INSTR_TYPE_MOD mutation target at a specific step.
    
    For instruction cycles, returns a target allowing mutation of
    the major and/or minor fields.
    
    Args:
        step: The step number to find targets for
        data: InspectionData containing cycles
        
    Returns:
        InstrTypeModTarget if this step has a valid instruction, None otherwise
    """
    # Get cycle info for this step
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    
    # Check if this is an instruction cycle
    if cycle.major not in VALID_MAJORS:
        return None
    
    # Get instruction name from major/minor
    kind_name = INSN_KIND_NAMES.get((cycle.major, cycle.minor), f"Unknown({cycle.major},{cycle.minor})")
    
    return InstrTypeModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        original_major=cycle.major,
        original_minor=cycle.minor,
        kind_name=kind_name,
    )


def create_config(
    target: InstrTypeModTarget, 
    mutated_major: int, 
    mutated_minor: int, 
    output_path: Path
) -> Path:
    """
    Create an A4 mutation config file for INSTR_TYPE_MOD.
    
    Args:
        target: The mutation target
        mutated_major: The new major value
        mutated_minor: The new minor value
        output_path: Where to save the config
        
    Returns:
        Path to the created config file
    """
    mutated_kind = INSN_KIND_NAMES.get((mutated_major, mutated_minor), 
                                        f"Unknown({mutated_major},{mutated_minor})")
    
    config = {
        "mutation_type": "INSTR_TYPE_MOD",
        "step": target.step,
        "major": mutated_major,
        "minor": mutated_minor,
        "_info": {
            "original_major": target.original_major,
            "original_minor": target.original_minor,
            "original_kind": target.kind_name,
            "mutated_kind": mutated_kind,
            "pc": f"0x{target.pc:08x}",
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def generate_random_mutation(target: InstrTypeModTarget, rng) -> tuple:
    """
    Generate random mutated major/minor values.
    
    Args:
        target: The mutation target
        rng: Random number generator
        
    Returns:
        Tuple of (mutated_major, mutated_minor)
    """
    # Strategy: Either change major, minor, or both
    strategy = rng.choice(['major', 'minor', 'both'])
    
    if strategy == 'major':
        new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
        new_minor = target.original_minor
    elif strategy == 'minor':
        new_major = target.original_major
        # Minors range 0-15 typically
        new_minor = rng.randint(0, 15)
        while new_minor == target.original_minor:
            new_minor = rng.randint(0, 15)
    else:  # both
        new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
        new_minor = rng.randint(0, 15)
    
    return new_major, new_minor
