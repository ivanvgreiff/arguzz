#!/usr/bin/env python3
"""
Test Runner for A4 Verification

Runs verification tests based on selected steps.

Usage:
    # Run all tests for one mutation type
    python3 -m a4.verification.scripts.run_tests --mutation-type INSTR_WORD_MOD
    
    # Run all tests
    python3 -m a4.verification.scripts.run_tests --all
    
    # Run specific steps
    python3 -m a4.verification.scripts.run_tests --mutation-type COMP_OUT_MOD --steps 200 205 210
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


def load_selected_steps(path: Path) -> dict:
    """Load selected steps from JSON"""
    with open(path) as f:
        return json.load(f)


def run_single_test(
    mutation_type: str,
    step: int,
    instruction: str,
    host_binary: str,
    host_args: str,
    results_dir: Path,
    logs_dir: Path,
    seed: int = 12345,
    strategy: Optional[str] = None,  # For PRE_EXEC_REG_MOD: "next_read" or "prev_write"
) -> dict:
    """Run a single verification test"""
    
    # Build file names (include strategy suffix for PRE_EXEC_REG_MOD)
    if strategy:
        result_file = results_dir / f"{mutation_type.lower()}_{strategy}_step{step}.json"
        log_file = logs_dir / f"{mutation_type.lower()}_{strategy}_step{step}.log"
    else:
        result_file = results_dir / f"{mutation_type.lower()}_step{step}.json"
        log_file = logs_dir / f"{mutation_type.lower()}_step{step}.log"
    
    cmd = [
        "python3", "-m", "a4.cli", "compare",
        "--step", str(step),
        "--kind", mutation_type,
        "--seed", str(seed),
        "--host-binary", host_binary,
        "--host-args", host_args,
        "--output-json", str(result_file),
    ]
    
    # Add strategy for PRE_EXEC_REG_MOD
    if strategy:
        cmd.extend(["--strategy", strategy])
    
    # Build display name
    display_name = f"{mutation_type}"
    if strategy:
        display_name = f"{mutation_type} ({strategy})"
    
    print(f"\n{'='*60}")
    print(f"Testing {display_name} at step {step} ({instruction})")
    print(f"{'='*60}")
    print(f"Command: {' '.join(cmd)}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360,  # 6 minute timeout
        )
        
        elapsed = time.time() - start_time
        
        # Save log
        with open(log_file, 'w') as f:
            f.write(f"Command: {' '.join(cmd)}\n")
            f.write(f"Exit code: {result.returncode}\n")
            f.write(f"Elapsed: {elapsed:.2f}s\n")
            f.write("\n=== STDOUT ===\n")
            f.write(result.stdout)
            f.write("\n=== STDERR ===\n")
            f.write(result.stderr)
        
        # Print key output
        for line in result.stdout.split('\n'):
            if 'constraint failure' in line.lower() or 'common' in line.lower():
                print(line)
        
        # Parse result if exists
        success = False
        skipped = False
        skip_reason = ""
        common_count = 0
        if result_file.exists():
            with open(result_file) as f:
                data = json.load(f)
                comparison = data.get('comparison', {})
                skipped = comparison.get('skipped', False)
                skip_reason = comparison.get('skip_reason', "")
                common_count = len(comparison.get('common', []))
                # Only count as success if NOT skipped AND has common failures
                if not skipped:
                    success = common_count > 0
        
        if skipped:
            # Differentiate between guest crash and target not found
            if "guest crashed" in skip_reason.lower():
                status = "⊘ N/A (guest crashed)"
            elif "no mutation target" in skip_reason.lower():
                status = "⊘ N/A (target not found)"
            else:
                status = "⊘ N/A (skipped)"
            print(f"\nResult: {status} (time={elapsed:.2f}s)")
        else:
            status = "✓ PASS" if success else "✗ FAIL"
            print(f"\nResult: {status} (common={common_count}, time={elapsed:.2f}s)")
        
        return {
            "mutation_type": mutation_type,
            "strategy": strategy,
            "step": step,
            "instruction": instruction,
            "success": success,
            "skipped": skipped,
            "skip_reason": skip_reason,
            "common_count": common_count,
            "elapsed": elapsed,
            "exit_code": result.returncode,
        }
        
    except subprocess.TimeoutExpired:
        print(f"\n✗ TIMEOUT after 360s")
        return {
            "mutation_type": mutation_type,
            "strategy": strategy,
            "step": step,
            "instruction": instruction,
            "success": False,
            "skipped": False,
            "skip_reason": "",
            "common_count": 0,
            "elapsed": 360,
            "exit_code": -1,
            "error": "timeout",
        }
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        return {
            "mutation_type": mutation_type,
            "strategy": strategy,
            "step": step,
            "instruction": instruction,
            "success": False,
            "skipped": False,
            "skip_reason": "",
            "common_count": 0,
            "elapsed": 0,
            "exit_code": -1,
            "error": str(e),
        }


def run_tests(
    selected_steps: dict,
    mutation_types: List[str],
    specific_steps: Optional[List[int]],
    host_binary: str,
    host_args: str,
    results_dir: Path,
    logs_dir: Path,
    seed: int,
    strategies: Optional[List[str]] = None,  # For PRE_EXEC_REG_MOD
) -> List[dict]:
    """Run verification tests"""
    
    results_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    all_results = []
    
    for mut_type in mutation_types:
        if mut_type not in selected_steps.get('selected_steps', {}):
            print(f"\nWARNING: No selected steps for {mut_type}")
            continue
        
        steps = selected_steps['selected_steps'][mut_type]
        
        # Determine which strategies to use for this mutation type
        if mut_type == "PRE_EXEC_REG_MOD":
            test_strategies = strategies if strategies else ["next_read", "prev_write"]
        else:
            test_strategies = [None]  # No strategy for other mutation types
        
        for step_info in steps:
            step = step_info['step']
            instruction = step_info['instruction']
            
            # Filter by specific steps if provided
            if specific_steps and step not in specific_steps:
                continue
            
            # Run test for each strategy
            for strategy in test_strategies:
                result = run_single_test(
                    mutation_type=mut_type,
                    step=step,
                    instruction=instruction,
                    host_binary=host_binary,
                    host_args=host_args,
                    results_dir=results_dir,
                    logs_dir=logs_dir,
                    seed=seed,
                    strategy=strategy,
                )
                all_results.append(result)
    
    return all_results


def print_summary(results: List[dict]):
    """Print summary of all test results"""
    print("\n" + "=" * 70)
    print("TEST RESULTS SUMMARY")
    print("=" * 70)
    
    # Group by mutation type (and strategy for PRE_EXEC_REG_MOD)
    by_type = {}
    for r in results:
        mt = r['mutation_type']
        strategy = r.get('strategy')
        if strategy:
            key = f"{mt} ({strategy})"
        else:
            key = mt
        if key not in by_type:
            by_type[key] = []
        by_type[key].append(r)
    
    total_pass = 0
    total_fail = 0
    total_skipped = 0
    
    for type_key, type_results in by_type.items():
        passed = sum(1 for r in type_results if r['success'] and not r.get('skipped', False))
        skipped = sum(1 for r in type_results if r.get('skipped', False))
        failed = sum(1 for r in type_results if not r['success'] and not r.get('skipped', False))
        total_pass += passed
        total_fail += failed
        total_skipped += skipped
        
        # Count only non-skipped tests for the "passed" count
        non_skipped = len(type_results) - skipped
        print(f"\n{type_key}: {passed}/{non_skipped} passed" + (f" ({skipped} skipped)" if skipped else ""))
        for r in type_results:
            skip_reason = r.get('skip_reason', '')
            if r.get('skipped', False):
                status = "⊘"
                # Differentiate skip reasons
                if "guest crashed" in skip_reason.lower():
                    detail = "N/A (guest crashed)"
                elif "no mutation target" in skip_reason.lower():
                    detail = "N/A (target not found)"
                else:
                    detail = "N/A (skipped)"
            elif r['success']:
                status = "✓"
                detail = f"common={r['common_count']}"
            else:
                status = "✗"
                detail = f"common={r['common_count']}"
            print(f"  {status} Step {r['step']:5d} ({r['instruction']:10s}): {detail}")
    
    print("\n" + "=" * 70)
    non_skipped_total = total_pass + total_fail
    print(f"TOTAL: {total_pass}/{non_skipped_total} passed" + (f" ({total_skipped} skipped/N/A)" if total_skipped else ""))
    if total_fail == 0 and non_skipped_total > 0:
        print("ALL APPLICABLE TESTS PASSED!")
    elif total_fail > 0:
        print(f"{total_fail} TESTS FAILED")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Run A4 verification tests',
    )
    parser.add_argument('--selected-steps', type=str,
                       default='./a4/verification/selected_steps.json',
                       help='Path to selected steps JSON')
    parser.add_argument('--mutation-type', type=str,
                       choices=['INSTR_WORD_MOD', 'COMP_OUT_MOD', 'LOAD_VAL_MOD', 'STORE_OUT_MOD', 'PRE_EXEC_REG_MOD'],
                       help='Run tests for specific mutation type')
    parser.add_argument('--all', action='store_true',
                       help='Run tests for all mutation types')
    parser.add_argument('--steps', type=int, nargs='+',
                       help='Run specific steps only')
    parser.add_argument('--strategy', type=str, nargs='+',
                       choices=['next_read', 'prev_write'],
                       help='Strategy for PRE_EXEC_REG_MOD (default: both). Can specify one or both.')
    parser.add_argument('--host-binary', type=str,
                       default='./workspace/output/target/release/risc0-host',
                       help='Host binary path')
    parser.add_argument('--host-args', type=str,
                       default='--in1 5 --in4 10',
                       help='Host arguments')
    parser.add_argument('--seed', type=int, default=12345,
                       help='Random seed')
    parser.add_argument('--results-dir', type=str,
                       default='./a4/verification/results',
                       help='Results directory')
    parser.add_argument('--logs-dir', type=str,
                       default='./a4/verification/logs',
                       help='Logs directory')
    parser.add_argument('--output-summary', type=str,
                       help='Save summary JSON to this path')
    
    args = parser.parse_args()
    
    # Determine which mutation types to test
    if args.all:
        mutation_types = ['INSTR_WORD_MOD', 'COMP_OUT_MOD', 'LOAD_VAL_MOD', 'STORE_OUT_MOD', 'PRE_EXEC_REG_MOD']
    elif args.mutation_type:
        mutation_types = [args.mutation_type]
    else:
        print("ERROR: Specify --mutation-type or --all")
        return 1
    
    # Load selected steps
    selected_path = Path(args.selected_steps)
    if not selected_path.exists():
        print(f"ERROR: Selected steps file not found: {selected_path}")
        print("\nRun step selection first:")
        print("  python3 -m a4.verification.scripts.select_steps")
        return 1
    
    selected_steps = load_selected_steps(selected_path)
    
    # Run tests
    results = run_tests(
        selected_steps=selected_steps,
        mutation_types=mutation_types,
        specific_steps=args.steps,
        host_binary=args.host_binary,
        host_args=args.host_args,
        results_dir=Path(args.results_dir),
        logs_dir=Path(args.logs_dir),
        seed=args.seed,
        strategies=args.strategy,  # For PRE_EXEC_REG_MOD
    )
    
    # Print summary
    print_summary(results)
    
    # Save summary if requested
    if args.output_summary:
        summary_path = Path(args.output_summary)
        summary_path.write_text(json.dumps(results, indent=2))
        print(f"\nSummary saved to: {summary_path}")
    
    # Return exit code based on results
    # Skipped tests (N/A due to guest crash) don't count as failures
    non_skipped_results = [r for r in results if not r.get('skipped', False)]
    if not non_skipped_results:
        print("\nNote: All tests were skipped (guest crashes)")
        return 0
    
    all_passed = all(r['success'] for r in non_skipped_results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
