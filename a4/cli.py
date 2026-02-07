#!/usr/bin/env python3
"""
A4: Post-Preflight Trace Mutation for RISC Zero

This is the main entry point for A4. It provides guidance on which CLI to use.

CLIs available:
    python3 -m a4.standalone.cli        # Standalone A4 fuzzing (independent)
    python3 -m a4.arguzz_dependent.cli  # Compare Arguzz vs A4 mutations
    python3 -m a4.injection.cli         # Apply/check/revert A4 patches

For backwards compatibility, this CLI forwards to arguzz_dependent for
compare/find-target commands and injection for inject command.

Examples:
    # Standalone fuzzing (future)
    python3 -m a4.standalone.cli fuzz --kind COMP_OUT_MOD --steps 100
    
    # Compare Arguzz vs A4 mutations
    python3 -m a4.arguzz_dependent.cli compare --step 200 --kind COMP_OUT_MOD --seed 12345
    
    # Apply A4 patches
    python3 -m a4.injection.cli apply --risc0-path ./workspace/risc0-modified
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description='A4: Post-Preflight Trace Mutation for RISC Zero',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
A4 provides two fuzzing strategies:

1. STANDALONE FUZZING (recommended for new campaigns)
   python3 -m a4.standalone.cli fuzz --help
   
   - Independent of Arguzz
   - Selects steps and values randomly/heuristically
   - Tracks coverage in SQLite database
   - Best for exploring constraint failures

2. ARGUZZ COMPARISON (for verification)
   python3 -m a4.arguzz_dependent.cli compare --help
   
   - Runs both Arguzz and A4 on same step
   - Compares constraint failures
   - Used to verify A4 produces correct failures

3. PATCH INJECTION
   python3 -m a4.injection.cli apply --help
   
   - Applies A4 patches to RISC Zero source
   - Required before running any A4 mutations

For backwards compatibility, this CLI forwards commands to the appropriate module.
        """
    )
    subparsers = parser.add_subparsers(dest='command')
    
    # Backwards-compatible commands that forward to arguzz_dependent
    find_parser = subparsers.add_parser('find-target', 
        help='Find A4 mutation target (forwards to arguzz_dependent.cli)')
    find_parser.add_argument('--fault', type=str, required=True)
    find_parser.add_argument('--host-binary', type=str, 
                            default='./workspace/output/target/release/risc0-host')
    find_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10')
    find_parser.add_argument('--output-config', type=str)
    
    compare_parser = subparsers.add_parser('compare',
        help='Compare Arguzz and A4 mutations (forwards to arguzz_dependent.cli)')
    compare_parser.add_argument('--step', type=int, required=True)
    compare_parser.add_argument('--kind', type=str, default='INSTR_WORD_MOD',
                               choices=['INSTR_WORD_MOD', 'COMP_OUT_MOD', 'LOAD_VAL_MOD', 
                                       'STORE_OUT_MOD', 'PRE_EXEC_REG_MOD'])
    compare_parser.add_argument('--seed', type=int, default=12345)
    compare_parser.add_argument('--host-binary', type=str, 
                               default='./workspace/output/target/release/risc0-host')
    compare_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10')
    compare_parser.add_argument('--output-json', type=str)
    compare_parser.add_argument('--strategy', type=str, default='next_read',
                               choices=['next_read', 'prev_write'])
    
    inject_parser = subparsers.add_parser('inject',
        help='Apply A4 patches (forwards to injection.cli)')
    inject_parser.add_argument('--risc0-path', type=str, required=True)
    inject_parser.add_argument('--check', action='store_true')
    inject_parser.add_argument('--revert', action='store_true')
    
    args, remaining = parser.parse_known_args()
    
    if args.command is None:
        parser.print_help()
        print("\n" + "="*60)
        print("TIP: Use one of the specialized CLIs for full functionality:")
        print("  python3 -m a4.standalone.cli --help")
        print("  python3 -m a4.arguzz_dependent.cli --help")
        print("  python3 -m a4.injection.cli --help")
        print("="*60)
        return 0
    
    # Forward to appropriate CLI
    if args.command == 'find-target':
        from a4.arguzz_dependent.cli import cmd_find_target
        return cmd_find_target(args)
    
    elif args.command == 'compare':
        from a4.arguzz_dependent.cli import cmd_compare
        return cmd_compare(args)
    
    elif args.command == 'inject':
        from a4.injection.inject import inject_a4, check_a4, revert_a4
        from pathlib import Path
    
    risc0_path = Path(args.risc0_path).resolve()
    if args.check:
        success = check_a4(risc0_path)
    elif args.revert:
        success = revert_a4(risc0_path)
    else:
        success = inject_a4(risc0_path)
    return 0 if success else 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
