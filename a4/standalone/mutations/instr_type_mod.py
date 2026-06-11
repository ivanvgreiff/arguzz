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

Mutation Strategy (75%/25% split):
- 75%: Generate valid (major, minor) combinations
- 25%: Generate potentially invalid combinations (for testing circuit handling)
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo
from a4.core.insn_decode import INSN_KIND_NAMES


# Valid major categories for instruction cycles
VALID_MAJORS = {0, 1, 2, 3, 4, 5, 6}

# Valid minors for each major (from INSN_KIND_NAMES)
# major = kind // 8, minor = kind % 8
VALID_MINORS_BY_MAJOR = {
    0: [0, 1, 2, 3, 4, 5, 6, 7],  # Add, Sub, Xor, Or, And, Slt, SltU, AddI
    1: [0, 1, 2, 3, 4, 5, 6, 7],  # XorI, OrI, AndI, SltI, SltIU, Beq, Bne, Blt
    2: [0, 1, 2, 3, 4, 5, 6],     # Bge, BltU, BgeU, Jal, JalR, Lui, Auipc
    3: [0, 1, 2, 3, 4, 5],        # Sll, SllI, Mul, MulH, MulHSU, MulHU
    4: [0, 1, 2, 3, 4, 5, 6, 7],  # Srl, Sra, SrlI, SraI, Div, DivU, Rem, RemU
    5: [0, 1, 2, 3, 4],           # Lb, Lh, Lw, LbU, LhU
    6: [0, 1, 2],                 # Sb, Sh, Sw
    7: [0, 1],                    # Eany, Mret
}


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

    Cycle-resolution rule (Phase 7d Inc 3 / B1 Option B fix):
        Boundary steps (step=0 init prelude, step=lastCycle-1 teardown epilogue,
        ECALL-handler boundaries like step=446) contain MANY cycles sharing the
        same `user_cycle`, only some of which are user-instruction cycles
        (`major` in `VALID_MAJORS` = {0..6}). The runtime hook iterates
        `trace.cycles` and lands on the FIRST cycle matching
        `cycle.user_cycle == step && cycle.major <= 6` (post-fix). We must
        return the SAME cycle here so the verifier's `(original_major,
        original_minor)` matches what the hook reports.

        Previously this called `data.get_cycle(step)` which uses
        `_step_to_cycle = {c.step: c for c in cycles}` (dict-comp LAST wins) —
        on boundary steps that returns the last user-instruction cycle, which
        the hook never sees because it stops at the first match.

    Args:
        step: The step number to find targets for
        data: InspectionData containing cycles

    Returns:
        InstrTypeModTarget if this step has a valid instruction, None otherwise
    """
    # Find the FIRST cycle at `step` whose major is a user-instruction class.
    # This MUST match the runtime hook's selection rule in
    # workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
    # (INSTR_TYPE_MOD branch).
    cycle = None
    for c in data.cycles:
        if c.step == step and c.major in VALID_MAJORS:
            cycle = c
            break
    if cycle is None:
        return None

    kind = cycle.major * 8 + cycle.minor
    kind_name = INSN_KIND_NAMES.get(kind, f"Unknown({cycle.major},{cycle.minor})")

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
    output_path: Path,
    is_valid: bool = True
) -> Path:
    """
    Create an A4 mutation config file for INSTR_TYPE_MOD.
    
    Args:
        target: The mutation target
        mutated_major: The new major value
        mutated_minor: The new minor value
        output_path: Where to save the config
        is_valid: Whether (mutated_major, mutated_minor) is a valid instruction
        
    Returns:
        Path to the created config file
    """
    # Convert (major, minor) to kind (kind = major*8 + minor)
    mutated_kind_num = mutated_major * 8 + mutated_minor
    mutated_kind = INSN_KIND_NAMES.get(mutated_kind_num, 
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
            "is_valid_combination": is_valid,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def is_valid_combination(major: int, minor: int) -> bool:
    """Check if (major, minor) corresponds to a valid instruction."""
    if major not in VALID_MINORS_BY_MAJOR:
        return False
    return minor in VALID_MINORS_BY_MAJOR[major]


def generate_random_mutation(target: InstrTypeModTarget, rng) -> tuple:
    """
    Generate random mutated major/minor values.
    
    Uses a 75%/25% split:
    - 75%: Generate valid (major, minor) combinations
    - 25%: Generate potentially invalid combinations
    
    Args:
        target: The mutation target
        rng: Random number generator
        
    Returns:
        Tuple of (mutated_major, mutated_minor, is_valid)
    """
    # 75% chance of generating a valid combination
    generate_valid = rng.random() < 0.75
    
    # Strategy: Either change major, minor, or both
    strategy = rng.choice(['major', 'minor', 'both'])
    
    if generate_valid:
        # Generate a VALID (major, minor) combination
        if strategy == 'major':
            new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
            # Pick a valid minor for the new major
            valid_minors = VALID_MINORS_BY_MAJOR.get(new_major, [0])
            new_minor = rng.choice(valid_minors)
        elif strategy == 'minor':
            new_major = target.original_major
            # Pick a different valid minor for the same major
            valid_minors = VALID_MINORS_BY_MAJOR.get(new_major, [0])
            choices = [m for m in valid_minors if m != target.original_minor]
            new_minor = rng.choice(choices) if choices else rng.choice(valid_minors)
        else:  # both
            new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
            valid_minors = VALID_MINORS_BY_MAJOR.get(new_major, [0])
            new_minor = rng.choice(valid_minors)
    else:
        # Generate a potentially INVALID (major, minor) combination
        if strategy == 'major':
            new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
            new_minor = target.original_minor  # Keep original minor (may be invalid for new major)
        elif strategy == 'minor':
            new_major = target.original_major
            # Pick a random minor (0-15), may be invalid for this major
            new_minor = rng.randint(0, 15)
            while new_minor == target.original_minor:
                new_minor = rng.randint(0, 15)
        else:  # both
            new_major = rng.choice([m for m in VALID_MAJORS if m != target.original_major])
            new_minor = rng.randint(0, 15)  # Random minor, may be invalid
    
    # Check if the result is actually valid
    is_valid = is_valid_combination(new_major, new_minor)
    
    return new_major, new_minor, is_valid
