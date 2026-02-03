"""
A4 Mutation Strategies

Available mutations:
- INSTR_TYPE_MOD: Mutate cycles[].major/minor (for Arguzz INSTR_WORD_MOD)
- COMP_OUT_MOD: Mutate txns[].word for WRITE transactions (for Arguzz COMP_OUT_MOD)
"""

from a4.mutations.base import (
    run_a4_inspection,
    run_a4_inspection_with_step,
    run_arguzz_mutation,
    run_a4_mutation,
    compare_failures,
    ComparisonResult,
    find_a4_step_for_arguzz_step,
)

__all__ = [
    'run_a4_inspection',
    'run_a4_inspection_with_step', 
    'run_arguzz_mutation',
    'run_a4_mutation',
    'compare_failures',
    'ComparisonResult',
    'find_a4_step_for_arguzz_step',
]
