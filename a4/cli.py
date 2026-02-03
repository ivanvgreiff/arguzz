#!/usr/bin/env python3
"""
A4: Post-Preflight Trace Mutation for RISC Zero

Main CLI entry point for A4 mutation testing.

Usage:
    # Compare INSTR_WORD_MOD (Arguzz) vs INSTR_TYPE_MOD (A4)
    python3 -m a4.cli compare --step 200 --kind INSTR_WORD_MOD --seed 12345 --host-binary ./risc0-host

    # Compare COMP_OUT_MOD (Arguzz) vs COMP_OUT_MOD (A4)  
    python3 -m a4.cli compare --step 200 --kind COMP_OUT_MOD --seed 12345 --host-binary ./risc0-host
    
    # Find mutation target for an Arguzz fault
    python3 -m a4.cli find-target --fault '<fault>...</fault>' --host-binary ./risc0-host
    
    # Check/apply A4 patches
    python3 -m a4.cli inject --risc0-path /path/to/risc0
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import List


def cmd_find_target(args):
    """Find A4 mutation target for an Arguzz fault"""
    from a4.common.trace_parser import ArguzzFault, parse_all_a4_cycles
    from a4.mutations.base import run_a4_inspection
    
    # Parse the fault
    fault = ArguzzFault.parse(args.fault)
    if not fault:
        print(f"ERROR: Could not parse fault: {args.fault}")
        return 1
    
    print(f"Arguzz fault: step={fault.step}, pc={fault.pc}, kind={fault.kind}")
    print(f"  Info type: {fault.info_type}")
    print(f"  Original: {fault.original_value}")
    print(f"  Mutated:  {fault.mutated_value}")
    
    # Run A4 inspection
    print("\nRunning A4 inspection...")
    host_args = args.host_args.split() if args.host_args else []
    output = run_a4_inspection(args.host_binary, host_args)
    
    cycles = parse_all_a4_cycles(output)
    print(f"Parsed {len(cycles)} cycles")
    
    # Route based on fault kind
    if fault.kind == "INSTR_WORD_MOD":
        from a4.mutations.instr_type_mod import find_mutation_target, create_config
        target = find_mutation_target(fault, cycles)
        if not target:
            print("ERROR: Could not find mutation target")
            return 1
        
        print(f"\n=== A4 MUTATION TARGET (INSTR_TYPE_MOD) ===")
        print(f"cycle_idx: {target.cycle_idx}")
        print(f"step (user_cycle): {target.step}")
        print(f"pc: {target.pc}")
        print(f"Original: major={target.original_major}, minor={target.original_minor} ({target.original_kind_name})")
        print(f"Mutated:  major={target.mutated_major}, minor={target.mutated_minor} ({target.mutated_kind_name})")
        
        if args.output_config:
            config_path = Path(args.output_config)
            create_config(target, config_path)
            print(f"\nConfig written to: {config_path}")
            
    elif fault.kind == "COMP_OUT_MOD":
        from a4.mutations.comp_out_mod import find_mutation_target, create_config, run_full_inspection
        
        # Need step-specific inspection for COMP_OUT_MOD
        print("Running step-specific inspection...")
        cycles, step_txns, txns, a4_step = run_full_inspection(
            args.host_binary, host_args.split() if args.host_args else [], fault
        )
        
        target = find_mutation_target(fault, cycles, step_txns, txns)
        if not target:
            print("ERROR: Could not find mutation target")
            return 1
        
        print(f"\n=== A4 MUTATION TARGET (COMP_OUT_MOD) ===")
        print(f"cycle_idx: {target.cycle_idx}")
        print(f"step (user_cycle): {target.step}")
        print(f"pc: {target.pc}")
        print(f"major: {target.major}, minor: {target.minor}")
        print(f"write_txn_idx: {target.write_txn_idx}")
        print(f"register: {target.register_name} (x{target.register_idx})")
        print(f"original_value: {target.original_value}")
        print(f"mutated_value: {target.mutated_value}")
        
        if args.output_config:
            config_path = Path(args.output_config)
            create_config(target, config_path)
            print(f"\nConfig written to: {config_path}")
    else:
        print(f"ERROR: Unsupported fault kind: {fault.kind}")
        return 1
    
    return 0


def cmd_compare_instr_word_mod(args, host_args: List[str]):
    """Compare Arguzz INSTR_WORD_MOD vs A4 INSTR_TYPE_MOD"""
    from a4.common.trace_parser import parse_all_a4_cycles
    from a4.mutations.base import run_arguzz_mutation, run_a4_mutation, run_a4_inspection, compare_failures
    from a4.mutations.instr_type_mod import find_mutation_target
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz INSTR_WORD_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_output, faults, arguzz_failures = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "INSTR_WORD_MOD", args.seed
    )
    
    if not faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = faults[0]
    print(f"Fault: word:{fault.original_value} => word:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_failures)}")
    
    # Step 2: Run A4 inspection
    print(f"\n=== Step 2: A4 Inspection ===")
    inspect_output = run_a4_inspection(args.host_binary, host_args)
    cycles = parse_all_a4_cycles(inspect_output)
    print(f"Parsed {len(cycles)} cycles")
    
    # Step 3: Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1
    
    print(f"Target: cycle_idx={target.cycle_idx}, step={target.step}")
    print(f"  {target.original_kind_name} (major={target.original_major}, minor={target.original_minor})")
    print(f"  => {target.mutated_kind_name} (major={target.mutated_major}, minor={target.mutated_minor})")
    
    # Step 4: Run A4 mutation
    print(f"\n=== Step 4: A4 INSTR_TYPE_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "mutation_type": "INSTR_TYPE_MOD",
            "step": target.step,
            "major": target.mutated_major,
            "minor": target.mutated_minor,
        }
        json.dump(config, f)
        config_path = Path(f.name)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Step 5: Compare
    print(f"\n=== Step 5: Comparison ===")
    step_offset = fault.step - target.step
    comparison = compare_failures(arguzz_failures, a4_failures, step_offset)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare_comp_out_mod(args, host_args: List[str]):
    """Compare Arguzz COMP_OUT_MOD vs A4 COMP_OUT_MOD"""
    from a4.common.trace_parser import parse_all_a4_cycles
    from a4.mutations.base import run_arguzz_mutation, run_a4_mutation, compare_failures
    from a4.mutations.comp_out_mod import find_mutation_target, run_full_inspection
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz COMP_OUT_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_output, faults, arguzz_failures = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "COMP_OUT_MOD", args.seed
    )
    
    if not faults:
        print("ERROR: No fault recorded by Arguzz")
        print("  (Note: COMP_OUT_MOD only works on compute instructions like ADD, ADDI, etc.)")
        return 1, None, None, None
    
    fault = faults[0]
    print(f"Fault: out:{fault.original_value} => out:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_failures)}")
    
    # Step 2: Run A4 inspection with step-specific transactions
    print(f"\n=== Step 2: A4 Inspection ===")
    cycles, step_txns, txns, a4_step = run_full_inspection(
        args.host_binary, host_args, fault
    )
    print(f"Parsed {len(cycles)} cycles")
    print(f"A4 step: {a4_step} (offset from Arguzz: {fault.step - a4_step})")
    
    # Step 3: Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles, step_txns, txns)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1, None, None, None
    
    print(f"Target: cycle_idx={target.cycle_idx}, step={target.step}")
    print(f"  write_txn_idx={target.write_txn_idx}")
    print(f"  register: {target.register_name} (x{target.register_idx})")
    print(f"  {target.original_value} => {target.mutated_value}")
    
    # Step 4: Run A4 mutation
    print(f"\n=== Step 4: A4 COMP_OUT_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "mutation_type": "COMP_OUT_MOD",
            "step": target.step,
            "txn_idx": target.write_txn_idx,
            "word": target.mutated_value,
        }
        json.dump(config, f)
        config_path = Path(f.name)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Step 5: Compare
    print(f"\n=== Step 5: Comparison ===")
    step_offset = fault.step - target.step
    comparison = compare_failures(arguzz_failures, a4_failures, step_offset)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare_load_val_mod(args, host_args: List[str]):
    """Compare Arguzz LOAD_VAL_MOD vs A4 LOAD_VAL_MOD"""
    from a4.common.trace_parser import parse_all_a4_cycles
    from a4.mutations.base import run_arguzz_mutation, run_a4_mutation, compare_failures
    from a4.mutations.load_val_mod import find_mutation_target, run_full_inspection
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz LOAD_VAL_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_output, faults, arguzz_failures = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "LOAD_VAL_MOD", args.seed
    )
    
    if not faults:
        print("ERROR: No fault recorded by Arguzz")
        print("  (Note: LOAD_VAL_MOD only works on load instructions like Lw, Lh, Lb, etc.)")
        return 1, None, None, None
    
    fault = faults[0]
    print(f"Fault: out:{fault.original_value} => out:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_failures)}")
    
    # Step 2: Run A4 inspection with step-specific transactions
    print(f"\n=== Step 2: A4 Inspection ===")
    cycles, step_txns, txns, a4_step = run_full_inspection(
        args.host_binary, host_args, fault
    )
    print(f"Parsed {len(cycles)} cycles")
    print(f"A4 step: {a4_step} (offset from Arguzz: {fault.step - a4_step})")
    
    # Step 3: Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles, step_txns, txns)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1, None, None, None
    
    print(f"Target: cycle_idx={target.cycle_idx}, step={target.step}")
    print(f"  write_txn_idx={target.write_txn_idx}")
    print(f"  register: {target.register_name} (x{target.register_idx})")
    print(f"  {target.original_value} => {target.mutated_value}")
    
    # Step 4: Run A4 mutation
    print(f"\n=== Step 4: A4 LOAD_VAL_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "mutation_type": "LOAD_VAL_MOD",
            "step": target.step,
            "txn_idx": target.write_txn_idx,
            "word": target.mutated_value,
        }
        json.dump(config, f)
        config_path = Path(f.name)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Step 5: Compare
    print(f"\n=== Step 5: Comparison ===")
    step_offset = fault.step - target.step
    comparison = compare_failures(arguzz_failures, a4_failures, step_offset)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare_store_out_mod(args, host_args: List[str]):
    """Compare Arguzz STORE_OUT_MOD vs A4 STORE_OUT_MOD"""
    from a4.common.trace_parser import parse_all_a4_cycles
    from a4.mutations.base import run_arguzz_mutation, run_a4_mutation, compare_failures
    from a4.mutations.store_out_mod import find_mutation_target, run_full_inspection
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz STORE_OUT_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_output, faults, arguzz_failures = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "STORE_OUT_MOD", args.seed
    )
    
    if not faults:
        print("ERROR: No fault recorded by Arguzz")
        print("  (Note: STORE_OUT_MOD only works on store instructions like Sw, Sh, Sb)")
        return 1, None, None, None
    
    fault = faults[0]
    print(f"Fault: data:{fault.original_value} => data:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_failures)}")
    
    # Step 2: Run A4 inspection with step-specific transactions
    print(f"\n=== Step 2: A4 Inspection ===")
    cycles, step_txns, txns, a4_step = run_full_inspection(
        args.host_binary, host_args, fault
    )
    print(f"Parsed {len(cycles)} cycles")
    print(f"A4 step: {a4_step} (offset from Arguzz: {fault.step - a4_step})")
    
    # Step 3: Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles, step_txns, txns)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1, None, None, None
    
    print(f"Target: cycle_idx={target.cycle_idx}, step={target.step}")
    print(f"  write_txn_idx={target.write_txn_idx}")
    print(f"  memory: 0x{target.memory_byte_addr:08x}")
    print(f"  {target.original_value} => {target.mutated_value}")
    
    # Step 4: Run A4 mutation
    print(f"\n=== Step 4: A4 STORE_OUT_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config = {
            "mutation_type": "STORE_OUT_MOD",
            "step": target.step,
            "txn_idx": target.write_txn_idx,
            "word": target.mutated_value,
        }
        json.dump(config, f)
        config_path = Path(f.name)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Step 5: Compare
    print(f"\n=== Step 5: Comparison ===")
    step_offset = fault.step - target.step
    comparison = compare_failures(arguzz_failures, a4_failures, step_offset)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare(args):
    """Run full comparison between Arguzz and A4 mutations"""
    host_args = args.host_args.split() if args.host_args else []
    
    # Route based on mutation kind
    if args.kind == "INSTR_WORD_MOD":
        result = cmd_compare_instr_word_mod(args, host_args)
    elif args.kind == "COMP_OUT_MOD":
        result = cmd_compare_comp_out_mod(args, host_args)
    elif args.kind == "LOAD_VAL_MOD":
        result = cmd_compare_load_val_mod(args, host_args)
    elif args.kind == "STORE_OUT_MOD":
        result = cmd_compare_store_out_mod(args, host_args)
    else:
        print(f"ERROR: Unsupported mutation kind: {args.kind}")
        print("  Supported kinds: INSTR_WORD_MOD, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD")
        return 1
    
    # Handle results
    if isinstance(result, tuple):
        exit_code, comparison, fault, target = result
        
        # Save results if requested
        if args.output_json and comparison:
            output = {
                'arguzz': {
                    'step': args.step,
                    'kind': args.kind,
                    'seed': args.seed,
                    'fault': {
                        'pc': fault.pc,
                        'info_type': fault.info_type,
                        'original_value': fault.original_value,
                        'mutated_value': fault.mutated_value,
                    },
                    'failures': len(comparison.arguzz_failures),
                },
                'a4': {
                    'step': target.step if target else None,
                    'failures': len(comparison.a4_failures),
                },
                'comparison': {
                    'common': comparison.common_signatures,
                    'arguzz_only': comparison.arguzz_only_signatures,
                    'a4_only': comparison.a4_only_signatures,
                }
            }
            
            output_path = Path(args.output_json)
            output_path.write_text(json.dumps(output, indent=2))
            print(f"\nResults written to: {output_path}")
        
        return exit_code
    
    return result


def cmd_inject(args):
    """Check/apply A4 patches to RISC Zero"""
    from a4.injection.inject import inject_a4, check_a4, revert_a4
    
    risc0_path = Path(args.risc0_path).resolve()
    
    if args.check:
        success = check_a4(risc0_path)
    elif args.revert:
        success = revert_a4(risc0_path)
    else:
        success = inject_a4(risc0_path)
    
    return 0 if success else 1


def main():
    # Add parent directory to path so we can import a4 modules
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    parser = argparse.ArgumentParser(
        description='A4: Post-Preflight Trace Mutation for RISC Zero',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # find-target command
    find_parser = subparsers.add_parser('find-target', help='Find A4 mutation target')
    find_parser.add_argument('--fault', type=str, required=True,
                            help='Arguzz <fault> line')
    find_parser.add_argument('--host-binary', type=str, default='./target/release/risc0-host',
                            help='Path to risc0-host binary')
    find_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10',
                            help='Arguments for risc0-host')
    find_parser.add_argument('--output-config', type=str,
                            help='Output config file path')
    find_parser.set_defaults(func=cmd_find_target)
    
    # compare command
    compare_parser = subparsers.add_parser('compare', help='Compare Arguzz and A4 mutations')
    compare_parser.add_argument('--step', type=int, required=True,
                               help='Arguzz injection step')
    compare_parser.add_argument('--kind', type=str, default='INSTR_WORD_MOD',
                               choices=['INSTR_WORD_MOD', 'COMP_OUT_MOD', 'LOAD_VAL_MOD', 'STORE_OUT_MOD'],
                               help='Arguzz mutation kind')
    compare_parser.add_argument('--seed', type=int, default=12345,
                               help='Random seed')
    compare_parser.add_argument('--host-binary', type=str, default='./target/release/risc0-host',
                               help='Path to risc0-host binary')
    compare_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10',
                               help='Arguments for risc0-host')
    compare_parser.add_argument('--output-json', type=str,
                               help='Output JSON results path')
    compare_parser.set_defaults(func=cmd_compare)
    
    # inject command
    inject_parser = subparsers.add_parser('inject', help='Apply A4 patches to RISC Zero')
    inject_parser.add_argument('--risc0-path', type=str, required=True,
                              help='Path to RISC Zero repository')
    inject_parser.add_argument('--check', action='store_true',
                              help='Check if patches are applied')
    inject_parser.add_argument('--revert', action='store_true',
                              help='Revert patches')
    inject_parser.set_defaults(func=cmd_inject)
    
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
