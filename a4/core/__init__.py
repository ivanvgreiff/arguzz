"""
A4 Core - Shared utilities for A4 fuzzing

This module contains the minimal shared components used by both:
- standalone/ - Standalone A4 fuzzing
- arguzz_dependent/ - Arguzz comparison mode

Contents:
- executor.py: run_a4_inspection, run_a4_mutation
- trace_parser.py: A4 trace parsing (A4CycleInfo, A4Txn, etc.)
- constraint_parser.py: ConstraintFailure parsing
- insn_decode.py: RISC-V instruction decoding
- inspection_data.py: InspectionData container
"""

from a4.core.executor import (
    run_a4_inspection,
    run_a4_inspection_with_step,
    run_a4_mutation,
)

from a4.core.trace_parser import (
    A4CycleInfo,
    A4StepTxns,
    A4Txn,
    A4RegTxn,
    A4InstrTypeMod,
    parse_all_a4_cycles,
    parse_all_step_txns,
    parse_all_txns,
    parse_all_reg_txns,
)

from a4.core.constraint_parser import (
    ConstraintFailure,
    parse_all_constraint_failures,
)

from a4.core.inspection_data import InspectionData

__all__ = [
    # Executor
    'run_a4_inspection',
    'run_a4_inspection_with_step',
    'run_a4_mutation',
    # Trace parsing
    'A4CycleInfo',
    'A4StepTxns',
    'A4Txn',
    'A4RegTxn',
    'A4InstrTypeMod',
    'parse_all_a4_cycles',
    'parse_all_step_txns',
    'parse_all_txns',
    'parse_all_reg_txns',
    # Constraint parsing
    'ConstraintFailure',
    'parse_all_constraint_failures',
    # Inspection data container
    'InspectionData',
]
