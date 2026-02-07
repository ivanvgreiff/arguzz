#!/usr/bin/env python3
"""
A4 Arguzz-Dependent CLI

Command-line interface for comparing Arguzz and A4 mutations.
This is used to verify that A4 mutations produce the same core
constraint failures as corresponding Arguzz mutations.

Usage:
    python3 -m a4.arguzz_dependent.cli compare --help
    python3 -m a4.arguzz_dependent.cli find-target --help

Examples:
    # Compare COMP_OUT_MOD mutations
    python3 -m a4.arguzz_dependent.cli compare \\
        --step 200 --kind COMP_OUT_MOD --seed 12345 \\
        --host-binary ./workspace/output/target/release/risc0-host
    
    # Find mutation target for an Arguzz fault
    python3 -m a4.arguzz_dependent.cli find-target \\
        --fault '<fault>{"step":200,"pc":0x1234,"kind":"COMP_OUT_MOD"}</fault>' \\
        --host-binary ./workspace/output/target/release/risc0-host
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import List

# Core imports
from a4.core.executor import run_a4_inspection, run_a4_mutation
from a4.core.trace_parser import parse_all_a4_cycles

# Arguzz-dependent imports
from a4.arguzz_dependent.arguzz_parser import ArguzzFault
from a4.arguzz_dependent.arguzz_runner import run_arguzz_mutation
from a4.arguzz_dependent.step_mapper import compute_arguzz_preflight_offset
from a4.arguzz_dependent.comparison import (
    compare_failures, compare_failures_by_constraint_only, ComparisonResult
)


def cmd_find_target(args):
    """Find A4 mutation target for an Arguzz fault"""
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
        from a4.arguzz_dependent.mutations.instr_type_mod import find_mutation_target, create_config
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
        from a4.arguzz_dependent.mutations.comp_out_mod import find_mutation_target, create_config, run_full_inspection
        
        # Need step-specific inspection for COMP_OUT_MOD
        print("Running step-specific inspection...")
        cycles, step_txns, txns, a4_step, step_error = run_full_inspection(
            args.host_binary, args.host_args.split() if args.host_args else [], fault
        )
        
        if step_error:
            print(f"ERROR: Step finding failed: {step_error}")
            return 1
        
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
    from a4.arguzz_dependent.mutations.instr_type_mod import find_mutation_target
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz INSTR_WORD_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_result = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "INSTR_WORD_MOD", args.seed
    )
    
    if not arguzz_result.faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = arguzz_result.faults[0]
    print(f"Fault: word:{fault.original_value} => word:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_result.failures)}")
    
    # Check for guest crash
    if arguzz_result.guest_crashed:
        print(f"\n*** GUEST CRASHED ***")
        print(f"Reason: {arguzz_result.crash_reason}")
        print("\nSkipping A4 comparison - Arguzz mutation caused program crash before prover completed.")
        comparison = ComparisonResult.skipped_result(
            f"Arguzz guest crashed: {arguzz_result.crash_reason}"
        )
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Step 2: Run A4 inspection
    print(f"\n=== Step 2: A4 Inspection ===")
    inspect_output = run_a4_inspection(args.host_binary, host_args)
    cycles = parse_all_a4_cycles(inspect_output)
    print(f"Parsed {len(cycles)} cycles")
    
    # Compute offset for accurate step mapping in tight loops
    print(f"  Computing Arguzz-preflight offset...")
    offset = compute_arguzz_preflight_offset(arguzz_result.traces, cycles)
    print(f"  Offset (arguzz - preflight): {offset}")
    
    # Step 3: Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles, offset)
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
    comparison = compare_failures(arguzz_result.failures, a4_failures, step_offset)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare_comp_out_mod(args, host_args: List[str]):
    """Compare Arguzz COMP_OUT_MOD vs A4 COMP_OUT_MOD"""
    from a4.arguzz_dependent.mutations.comp_out_mod import find_mutation_target, run_full_inspection, create_config
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz COMP_OUT_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_result = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "COMP_OUT_MOD", args.seed
    )
    
    if not arguzz_result.faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = arguzz_result.faults[0]
    print(f"Fault: out:{fault.original_value} => out:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_result.failures)}")
    
    # Check for guest crash
    if arguzz_result.guest_crashed:
        print(f"\n*** GUEST CRASHED ***")
        print(f"Reason: {arguzz_result.crash_reason}")
        print("\nSkipping A4 comparison - Arguzz mutation caused program crash before prover completed.")
        comparison = ComparisonResult.skipped_result(
            f"Arguzz guest crashed: {arguzz_result.crash_reason}"
        )
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Compute offset for accurate step mapping
    print(f"\n=== Step 2: Compute Step Offset ===")
    inspect_output = run_a4_inspection(args.host_binary, host_args)
    all_cycles = parse_all_a4_cycles(inspect_output)
    offset = compute_arguzz_preflight_offset(arguzz_result.traces, all_cycles)
    print(f"  Offset (arguzz - preflight): {offset}")
    
    # Step 3: Run A4 inspection with step-specific info
    print(f"\n=== Step 3: A4 Full Inspection ===")
    cycles, step_txns, txns, a4_step, step_error = run_full_inspection(
        args.host_binary, host_args, fault, offset
    )
    
    if step_error:
        print(f"ERROR: Step finding failed: {step_error}")
        comparison = ComparisonResult.skipped_result(f"A4 step finding failed: {step_error}")
        comparison.print_summary()
        return 0, comparison, fault, None
    
    print(f"  A4 step: {a4_step}")
    
    # Step 4: Find mutation target
    print(f"\n=== Step 4: Find Mutation Target ===")
    target = find_mutation_target(fault, cycles, step_txns, txns, a4_step)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1
    
    print(f"Target: txn_idx={target.write_txn_idx}, register={target.register_name}")
    print(f"  Value: {target.original_value} => {target.mutated_value}")
    
    # Step 5: Run A4 mutation
    print(f"\n=== Step 5: A4 COMP_OUT_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = Path(f.name)
    create_config(target, config_path)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Step 6: Compare
    print(f"\n=== Step 6: Comparison ===")
    comparison = compare_failures(arguzz_result.failures, a4_failures)
    comparison.print_summary()
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    return 0, comparison, fault, target


def cmd_compare_load_val_mod(args, host_args: List[str]):
    """Compare Arguzz LOAD_VAL_MOD vs A4 LOAD_VAL_MOD"""
    from a4.arguzz_dependent.mutations.load_val_mod import find_mutation_target, run_full_inspection, create_config
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz LOAD_VAL_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_result = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "LOAD_VAL_MOD", args.seed
    )
    
    if not arguzz_result.faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = arguzz_result.faults[0]
    print(f"Fault: out:{fault.original_value} => out:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_result.failures)}")
    
    if arguzz_result.guest_crashed:
        comparison = ComparisonResult.skipped_result(f"Arguzz guest crashed: {arguzz_result.crash_reason}")
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Compute offset
    inspect_output = run_a4_inspection(args.host_binary, host_args)
    all_cycles = parse_all_a4_cycles(inspect_output)
    offset = compute_arguzz_preflight_offset(arguzz_result.traces, all_cycles)
    
    # Run A4 full inspection
    cycles, step_txns, txns, a4_step = run_full_inspection(args.host_binary, host_args, fault, offset)
    
    # Find mutation target
    target = find_mutation_target(fault, cycles, step_txns, txns, a4_step)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1
    
    # Run A4 mutation
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = Path(f.name)
    create_config(target, config_path)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    
    # Compare
    comparison = compare_failures(arguzz_result.failures, a4_failures)
    comparison.print_summary()
    
    config_path.unlink(missing_ok=True)
    return 0, comparison, fault, target


def cmd_compare_store_out_mod(args, host_args: List[str]):
    """Compare Arguzz STORE_OUT_MOD vs A4 STORE_OUT_MOD"""
    from a4.arguzz_dependent.mutations.store_out_mod import find_mutation_target, run_full_inspection, create_config
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz STORE_OUT_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_result = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "STORE_OUT_MOD", args.seed
    )
    
    if not arguzz_result.faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = arguzz_result.faults[0]
    print(f"Fault: data:{fault.original_value} => data:{fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_result.failures)}")
    
    if arguzz_result.guest_crashed:
        comparison = ComparisonResult.skipped_result(f"Arguzz guest crashed: {arguzz_result.crash_reason}")
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Compute offset
    inspect_output = run_a4_inspection(args.host_binary, host_args)
    all_cycles = parse_all_a4_cycles(inspect_output)
    offset = compute_arguzz_preflight_offset(arguzz_result.traces, all_cycles)
    
    # Run A4 full inspection
    cycles, step_txns, txns, a4_step = run_full_inspection(args.host_binary, host_args, fault, offset)
    
    # Find mutation target
    target = find_mutation_target(fault, cycles, step_txns, txns, a4_step)
    if not target:
        print("ERROR: Could not find mutation target")
        return 1
    
    # Run A4 mutation
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = Path(f.name)
    create_config(target, config_path)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    
    # Compare
    comparison = compare_failures(arguzz_result.failures, a4_failures)
    comparison.print_summary()
    
    config_path.unlink(missing_ok=True)
    return 0, comparison, fault, target


def cmd_compare_pre_exec_reg_mod(args, host_args: List[str]):
    """Compare Arguzz PRE_EXEC_REG_MOD vs A4 PRE_EXEC_REG_MOD"""
    from a4.arguzz_dependent.mutations.pre_exec_reg_mod import (
        find_mutation_target, run_full_inspection, create_config
    )
    
    # Step 1: Run Arguzz mutation
    print(f"=== Step 1: Arguzz PRE_EXEC_REG_MOD at step {args.step} (seed {args.seed}) ===")
    arguzz_result = run_arguzz_mutation(
        args.host_binary, host_args, args.step, "PRE_EXEC_REG_MOD", args.seed
    )
    
    if not arguzz_result.faults:
        print("ERROR: No fault recorded by Arguzz")
        return 1
    
    fault = arguzz_result.faults[0]
    print(f"Fault: {fault.target_register} = {fault.mutated_value}")
    print(f"Arguzz constraint failures: {len(arguzz_result.failures)}")
    
    if arguzz_result.guest_crashed:
        comparison = ComparisonResult.skipped_result(f"Arguzz guest crashed: {arguzz_result.crash_reason}")
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Run A4 full inspection
    print(f"\n=== Step 2: A4 Full Inspection ===")
    cycles, reg_txns, injection_a4_step = run_full_inspection(args.host_binary, host_args, fault)
    
    # Find mutation target
    print(f"\n=== Step 3: Find Mutation Target ({args.strategy} strategy) ===")
    target, skip_reason = find_mutation_target(fault, cycles, reg_txns, args.strategy)
    
    if not target:
        print(f"WARNING: Could not find mutation target: {skip_reason}")
        comparison = ComparisonResult.skipped_result(f"A4 target not found: {skip_reason}")
        comparison.print_summary()
        return 0, comparison, fault, None
    
    # Run A4 mutation
    print(f"\n=== Step 4: A4 PRE_EXEC_REG_MOD ===")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        config_path = Path(f.name)
    create_config(target, config_path)
    
    a4_output, a4_failures = run_a4_mutation(args.host_binary, host_args, config_path)
    print(f"A4 constraint failures: {len(a4_failures)}")
    
    # Compare using constraint-only matching
    print(f"\n=== Step 5: Comparison ===")
    comparison = compare_failures_by_constraint_only(arguzz_result.failures, a4_failures)
    comparison.print_summary()
    
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
    elif args.kind == "PRE_EXEC_REG_MOD":
        result = cmd_compare_pre_exec_reg_mod(args, host_args)
    else:
        print(f"ERROR: Unsupported mutation kind: {args.kind}")
        print("  Supported kinds: INSTR_WORD_MOD, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD")
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
                        'pc': fault.pc if fault else None,
                        'info_type': fault.info_type if fault else None,
                        'original_value': fault.original_value if fault else None,
                        'mutated_value': fault.mutated_value if fault else None,
                    },
                    'failures': len(comparison.arguzz_failures),
                },
                'a4': {
                    'step': (target.step if hasattr(target, 'step') else target.target_step) if target else None,
                    'failures': len(comparison.a4_failures),
                },
                'comparison': {
                    'skipped': comparison.skipped,
                    'skip_reason': comparison.skip_reason if comparison.skipped else None,
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


def main():
    parser = argparse.ArgumentParser(
        description='A4 Arguzz-Dependent Comparison',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This CLI is for comparing Arguzz and A4 mutations to verify that A4
produces the same core constraint failures as Arguzz.

For standalone A4 fuzzing, use: python3 -m a4.standalone.cli
        """
    )
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # find-target command
    find_parser = subparsers.add_parser('find-target', help='Find A4 mutation target')
    find_parser.add_argument('--fault', type=str, required=True,
                            help='Arguzz <fault> line')
    find_parser.add_argument('--host-binary', type=str, 
                            default='./workspace/output/target/release/risc0-host',
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
                               choices=['INSTR_WORD_MOD', 'COMP_OUT_MOD', 'LOAD_VAL_MOD', 
                                       'STORE_OUT_MOD', 'PRE_EXEC_REG_MOD'],
                               help='Arguzz mutation kind')
    compare_parser.add_argument('--seed', type=int, default=12345,
                               help='Random seed')
    compare_parser.add_argument('--host-binary', type=str, 
                               default='./workspace/output/target/release/risc0-host',
                               help='Path to risc0-host binary')
    compare_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10',
                               help='Arguments for risc0-host')
    compare_parser.add_argument('--output-json', type=str,
                               help='Output JSON results path')
    compare_parser.add_argument('--strategy', type=str, default='next_read',
                               choices=['next_read', 'prev_write'],
                               help='Strategy for PRE_EXEC_REG_MOD')
    compare_parser.set_defaults(func=cmd_compare)
    
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
