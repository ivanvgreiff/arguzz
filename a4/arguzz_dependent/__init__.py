"""
A4 Arguzz-Dependent Strategy

This module contains the Arguzz-dependent A4 implementation,
which runs A4 mutations based on Arguzz fault information for
verification and comparison purposes.

Entry point:
    python3 -m a4.arguzz_dependent.cli

Contents:
- cli.py: Command-line interface for Arguzz comparison
- arguzz_runner.py: Running Arguzz mutations
- arguzz_parser.py: Parsing Arguzz output (ArguzzFault, ArguzzTrace)
- step_mapper.py: Mapping Arguzz steps to A4 steps
- comparison.py: Comparing constraint failures
- mutations/: Mutation implementations with Arguzz wrappers
"""
