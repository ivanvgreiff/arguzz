"""
Standalone A4 Fuzzing CLI

Commands for autonomous A4 fuzzing campaigns:
- fuzz: Run a fuzzing campaign
- inspect: Run inspection and show trace summary
- coverage: Show coverage statistics from database
- analyze: Analyze specific mutations or constraints

Example usage:
    # Run 100 mutations with default settings
    python -m a4.standalone.cli fuzz --host ./risc0-host --num 100 -- program arg1 arg2
    
    # Run with specific mutation kind and seed
    python -m a4.standalone.cli fuzz --host ./risc0-host --kind LOAD_VAL_MOD --seed 42 --num 50 -- program
    
    # Show coverage stats
    python -m a4.standalone.cli coverage --db ./coverage.db
    
    # Inspect trace without fuzzing
    python -m a4.standalone.cli inspect --host ./risc0-host -- program arg1
"""

import argparse
import sys
from pathlib import Path

from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.coverage_db import CoverageDB
from a4.core.inspection_data import InspectionData


def cmd_fuzz(args):
    """Run a fuzzing campaign"""
    print("A4 Standalone Fuzzer")
    print("=" * 60)
    
    # Validate host binary
    host_binary = Path(args.host)
    if not host_binary.exists():
        print(f"Error: Host binary not found: {host_binary}")
        sys.exit(1)
    
    # Parse host args (everything after --)
    host_args = args.host_args if args.host_args else []
    
    # Create fuzzer
    with A4Fuzzer(
        host_binary=str(host_binary.absolute()),
        host_args=host_args,
        db_path=args.db,
        kind=args.kind,
        selector_strategy=args.selector,
        value_strategy=args.values,
        seed=args.seed,
        verbose=True,
    ) as fuzzer:
        # Run campaign
        stats = fuzzer.run_campaign(args.num)
        
        # Exit with non-zero if bugs found
        if stats.verifier_accepts > 0:
            print(f"\n⚠️  Found {stats.verifier_accepts} potential bugs!")
            sys.exit(2)


def cmd_inspect(args):
    """Run inspection and show trace summary"""
    print("A4 Trace Inspection")
    print("=" * 60)
    
    # Validate host binary
    host_binary = Path(args.host)
    if not host_binary.exists():
        print(f"Error: Host binary not found: {host_binary}")
        sys.exit(1)
    
    host_args = args.host_args if args.host_args else []
    
    print(f"Host: {host_binary}")
    print(f"Args: {' '.join(host_args)}")
    print()
    
    # Run inspection
    data = InspectionData.from_inspection(str(host_binary.absolute()), host_args)
    
    # Print summary
    print(data.summary())
    
    # Print valid steps by kind if requested
    if args.show_steps:
        print("\nValid steps by mutation kind:")
        for kind in ["COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", 
                     "PRE_EXEC_REG_MOD", "INSTR_TYPE_MOD"]:
            steps = data.get_valid_steps_for_kind(kind)
            print(f"  {kind}: {len(steps)} steps")
            if args.verbose and steps:
                print(f"    First 10: {steps[:10]}")


def cmd_coverage(args):
    """Show coverage statistics from database"""
    print("A4 Coverage Statistics")
    print("=" * 60)
    
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)
    
    with CoverageDB(str(db_path)) as db:
        stats = db.get_coverage_stats()
        
        print(f"\nTotal mutations:        {stats['total_mutations']}")
        print(f"Total failures:         {stats['total_failures']}")
        print(f"Unique constraints:     {stats['total_constraints']}")
        print(f"Verifier acceptance:    {stats['verifier_acceptance_rate']*100:.1f}%")
        
        print("\nMutations by kind:")
        for kind, count in sorted(stats['mutations_by_kind'].items()):
            print(f"  {kind}: {count}")
        
        print("\nTop 10 most-hit constraints:")
        for loc, count in stats['top_constraints']:
            print(f"  {count:5d}x  {loc}")
        
        # Show uncovered patterns
        uncovered = db.get_uncovered_constraint_patterns()
        if uncovered:
            print(f"\nPotentially uncovered constraint types:")
            for pattern in uncovered:
                print(f"  - {pattern}")


def cmd_analyze(args):
    """Analyze specific mutations or constraints"""
    print("A4 Analysis")
    print("=" * 60)
    
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)
    
    with CoverageDB(str(db_path)) as db:
        if args.constraint:
            # Find mutations hitting this constraint
            mutations = db.get_mutations_hitting_constraint(args.constraint)
            print(f"\nMutations hitting '{args.constraint}':")
            print(f"  Total: {len(mutations)}")
            
            if mutations:
                print("\n  First 5 mutations:")
                for m in mutations[:5]:
                    print(f"    [{m.id}] {m.kind} @ step {m.step}, value={m.mutated_value}")
        
        elif args.campaign:
            # Show campaign info
            info = db.get_campaign_info(args.campaign)
            if info:
                print(f"\nCampaign {info.id}:")
                print(f"  Host: {info.host_binary}")
                print(f"  Kind: {info.kind}")
                print(f"  Seed: {info.seed}")
                print(f"  Started: {info.started_at}")
                print(f"  Ended: {info.ended_at}")
                print(f"  Total mutations: {info.total_mutations}")
                print(f"  Unique constraints: {info.unique_constraints}")
            else:
                print(f"Campaign {args.campaign} not found")


def main():
    parser = argparse.ArgumentParser(
        description="A4 Standalone Fuzzer - Autonomous trace mutation fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run 100 mutations
  python -m a4.standalone.cli fuzz --host ./risc0-host --num 100 -- program arg1
  
  # Inspect trace
  python -m a4.standalone.cli inspect --host ./risc0-host -- program
  
  # View coverage
  python -m a4.standalone.cli coverage --db ./fuzz.db
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Fuzz command
    fuzz_parser = subparsers.add_parser("fuzz", help="Run a fuzzing campaign")
    fuzz_parser.add_argument("--host", required=True, help="Path to risc0-host binary")
    fuzz_parser.add_argument("--num", type=int, default=100, help="Number of mutations (default: 100)")
    fuzz_parser.add_argument("--kind", default="all", 
                            choices=["all", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD",
                                    "PRE_EXEC_REG_MOD", "INSTR_TYPE_MOD"],
                            help="Mutation kind (default: all)")
    fuzz_parser.add_argument("--selector", default="random",
                            choices=["random", "heuristic", "guided", "sequential"],
                            help="Step selection strategy (default: random)")
    fuzz_parser.add_argument("--values", default="mixed",
                            choices=["random", "bitflip", "boundary", "arithmetic", "smart", "mixed"],
                            help="Value generation strategy (default: mixed)")
    fuzz_parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    fuzz_parser.add_argument("--db", default="./a4_coverage.db", help="Coverage database path")
    fuzz_parser.add_argument("host_args", nargs="*", help="Arguments for risc0-host (after --)")
    
    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect trace without fuzzing")
    inspect_parser.add_argument("--host", required=True, help="Path to risc0-host binary")
    inspect_parser.add_argument("--show-steps", action="store_true", help="Show valid steps by kind")
    inspect_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    inspect_parser.add_argument("host_args", nargs="*", help="Arguments for risc0-host")
    
    # Coverage command
    coverage_parser = subparsers.add_parser("coverage", help="Show coverage statistics")
    coverage_parser.add_argument("--db", default="./a4_coverage.db", help="Coverage database path")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze mutations/constraints")
    analyze_parser.add_argument("--db", default="./a4_coverage.db", help="Coverage database path")
    analyze_parser.add_argument("--constraint", help="Show mutations hitting this constraint")
    analyze_parser.add_argument("--campaign", type=int, help="Show campaign info")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    if args.command == "fuzz":
        cmd_fuzz(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "coverage":
        cmd_coverage(args)
    elif args.command == "analyze":
        cmd_analyze(args)


if __name__ == "__main__":
    main()
