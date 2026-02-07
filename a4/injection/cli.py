#!/usr/bin/env python3
"""
A4 Injection CLI

Applies or reverts A4 patches to RISC Zero source code.

Usage:
    python3 -m a4.injection.cli apply --risc0-path /path/to/risc0
    python3 -m a4.injection.cli check --risc0-path /path/to/risc0
    python3 -m a4.injection.cli revert --risc0-path /path/to/risc0
"""

import argparse
import sys
from pathlib import Path


def cmd_inject(args):
    """Apply A4 patches to RISC Zero"""
    from a4.injection.inject import inject_a4
    
    risc0_path = Path(args.risc0_path).resolve()
    success = inject_a4(risc0_path)
    return 0 if success else 1


def cmd_check(args):
    """Check if A4 patches are applied"""
    from a4.injection.inject import check_a4
    
    risc0_path = Path(args.risc0_path).resolve()
    success = check_a4(risc0_path)
    return 0 if success else 1


def cmd_revert(args):
    """Revert A4 patches"""
    from a4.injection.inject import revert_a4
    
    risc0_path = Path(args.risc0_path).resolve()
    success = revert_a4(risc0_path)
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(
        description='A4 Patch Injection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool applies or reverts the A4 patches needed to enable
preflight trace mutation in RISC Zero.

Patches are applied to:
- risc0/circuit/rv32im/src/execute/mod.rs
        """
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # apply command
    apply_parser = subparsers.add_parser('apply', help='Apply A4 patches')
    apply_parser.add_argument('--risc0-path', type=str, required=True,
                             help='Path to RISC Zero repository')
    apply_parser.set_defaults(func=cmd_inject)
    
    # check command
    check_parser = subparsers.add_parser('check', help='Check if patches are applied')
    check_parser.add_argument('--risc0-path', type=str, required=True,
                             help='Path to RISC Zero repository')
    check_parser.set_defaults(func=cmd_check)
    
    # revert command
    revert_parser = subparsers.add_parser('revert', help='Revert A4 patches')
    revert_parser.add_argument('--risc0-path', type=str, required=True,
                              help='Path to RISC Zero repository')
    revert_parser.set_defaults(func=cmd_revert)
    
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
