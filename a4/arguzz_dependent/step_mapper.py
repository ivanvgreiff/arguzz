"""
Arguzz to A4 Step Mapping

Functions for mapping Arguzz steps to A4 preflight trace steps.
This is necessary because:
- Arguzz counts steps differently than preflight trace
- Arguzz records PC before execution, preflight records PC after (PC+4)
- Loops can cause the same PC to appear multiple times

Key functions:
- compute_arguzz_preflight_offset(): Find the step counting offset
- find_a4_step_for_arguzz_step(): Map an Arguzz step to A4 step
"""

from typing import List

from a4.core.trace_parser import A4CycleInfo
from a4.arguzz_dependent.arguzz_parser import ArguzzTrace


def compute_arguzz_preflight_offset(
    arguzz_traces: List[ArguzzTrace],
    a4_cycles: List[A4CycleInfo]
) -> int:
    """
    Compute the offset between Arguzz step counting and preflight step counting.
    
    The offset = arguzz_step - preflight_step at corresponding instructions.
    
    This offset exists because:
    - Arguzz counts only instruction executions
    - Preflight counts instruction cycles PLUS some special cycles
    
    The offset grows over time as more special cycles are executed.
    
    Strategy:
    - Find PCs that appear in both traces
    - For each PC, find the first occurrence in each trace
    - Compute offset = arguzz_step - preflight_step
    - Use the median offset (to handle any edge cases)
    
    Args:
        arguzz_traces: List of ArguzzTrace entries
        a4_cycles: All A4 cycles from inspection
        
    Returns:
        The offset (arguzz_step - preflight_step)
    """
    # Build PC -> first step mappings
    arguzz_pc_to_first_step = {}
    for t in arguzz_traces:
        if t.pc not in arguzz_pc_to_first_step:
            arguzz_pc_to_first_step[t.pc] = t.step
    
    preflight_pc_to_first_step = {}
    for c in a4_cycles:
        if c.major <= 6 and c.pc not in preflight_pc_to_first_step:  # Only instruction cycles
            preflight_pc_to_first_step[c.pc] = c.step
    
    # Find common PCs and compute offsets
    offsets = []
    common_pcs = set(arguzz_pc_to_first_step.keys()) & set(preflight_pc_to_first_step.keys())
    
    for pc in common_pcs:
        arguzz_step = arguzz_pc_to_first_step[pc]
        preflight_step = preflight_pc_to_first_step[pc]
        offset = arguzz_step - preflight_step
        offsets.append(offset)
    
    if not offsets:
        # Fallback: assume small offset
        return 0
    
    # Use median offset (most robust to outliers)
    offsets.sort()
    return offsets[len(offsets) // 2]


def find_a4_step_for_arguzz_step(
    arguzz_step: int,
    arguzz_pc: int,
    a4_cycles: List[A4CycleInfo],
    offset: int = None
) -> int:
    """
    Find the A4 user_cycle (step) that corresponds to an Arguzz step.
    
    Key insight about step counting differences:
    - Arguzz counts only instruction executions
    - Preflight counts instruction cycles PLUS special cycles (Control, Poseidon, SHA)
    - The offset (arguzz_step - preflight_step) grows over time
    
    Strategy:
    1. If offset is provided, calculate target_step = arguzz_step - offset
    2. Find the preflight cycle at arguzz_pc closest to target_step
    
    This gives 100% accuracy for tight loops where offset > loop_period.
    
    Args:
        arguzz_step: Arguzz injection step
        arguzz_pc: PC from Arguzz fault
        a4_cycles: All A4 cycles from inspection
        offset: Pre-computed offset (arguzz_step - preflight_step). If None,
                falls back to heuristic (closest step <= arguzz_step).
        
    Returns:
        The A4 step (user_cycle) that corresponds to this Arguzz step
        
    Raises:
        ValueError: If no suitable A4 step can be found
    """
    # Find all instruction cycles at arguzz_pc + 4
    # Why +4? Because preflight cycle.pc is the NEXT PC (after set_pc is called during execution)
    # So if arguzz injects at PC=X, the preflight cycle has pc=X+4
    # Only consider instruction cycles (major 0-6)
    expected_pc = arguzz_pc + 4
    matches = [c for c in a4_cycles if c.pc == expected_pc and c.major <= 6]
    
    if not matches:
        raise ValueError(
            f"No A4 instruction cycle found at PC=0x{expected_pc:X} (arguzz_pc+4) for Arguzz step {arguzz_step}. "
            f"This PC may not have been reached in the preflight trace."
        )
    
    if len(matches) == 1:
        return matches[0].step
    
    # Multiple matches (loop iterations)
    if offset is not None:
        # Use exact offset calculation
        target_step = arguzz_step - offset
        # Find the cycle closest to target_step
        return min(matches, key=lambda c: abs(c.step - target_step)).step
    else:
        # Fallback: heuristic (closest step <= arguzz_step)
        # This works when offset < loop_period, but fails for tight loops
        valid = [c for c in matches if c.step <= arguzz_step]
        if valid:
            return max(valid, key=lambda c: c.step).step
        return min(matches, key=lambda c: abs(c.step - arguzz_step)).step
