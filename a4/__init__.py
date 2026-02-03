"""
A4: Post-Preflight Trace Mutation for RISC Zero

A mutation testing strategy that modifies the PreflightTrace (execution witness data)
BEFORE witness generation, enabling precise constraint failure analysis without
cascading execution effects.

Modules:
    common.insn_decode - RISC-V instruction decoding
    common.trace_parser - Arguzz/A4 output parsing
    mutations.instr_type_mod - INSTR_TYPE_MOD mutation (for Arguzz INSTR_WORD_MOD)
    injection.inject - Patch injection system

Usage:
    python3 -m a4.cli compare --step 200 --kind INSTR_WORD_MOD --seed 12345
"""

__version__ = "0.1.0"
