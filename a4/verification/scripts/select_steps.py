#!/usr/bin/env python3
"""
Step Selection for A4 Verification

Parses trace log and selects valid steps for each mutation type.
Supports two modes:
- COMPREHENSIVE: Select steps for EVERY unique instruction type (default)
- QUICK: Select a small diverse subset for fast testing

Usage:
    # Comprehensive mode (test all instruction types)
    python3 -m a4.verification.scripts.select_steps --trace-file ./a4/tmp/trace.log
    
    # Quick mode (small diverse set)
    python3 -m a4.verification.scripts.select_steps --trace-file ./a4/tmp/trace.log --quick
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class TraceEntry:
    """Parsed trace entry"""
    step: int
    pc: int
    instruction: str
    assembly: str


# Instruction categorization for each mutation type
MUTATION_VALID_INSTRUCTIONS = {
    # INSTR_WORD_MOD: Can mutate any instruction to a different type
    # Best tested on compute instructions where the type change is meaningful
    "INSTR_WORD_MOD": {
        # R-type compute
        "Add", "Sub", "Sll", "Slt", "SltU", "Xor", "Or", "And",
        "Mul", "MulH", "MulHSU", "MulHU", "Div", "DivU", "Rem", "RemU",
        "Srl", "Sra",
        # I-type compute
        "AddI", "XorI", "OrI", "AndI", "SltI", "SltIU",
        "SllI", "SrlI", "SraI",
        # U-type
        "Lui", "Auipc",
    },
    
    # COMP_OUT_MOD: Compute instructions that write to a register
    "COMP_OUT_MOD": {
        # R-type compute
        "Add", "Sub", "Sll", "Slt", "SltU", "Xor", "Or", "And",
        "Mul", "MulH", "MulHSU", "MulHU", "Div", "DivU", "Rem", "RemU",
        "Srl", "Sra",
        # I-type compute
        "AddI", "XorI", "OrI", "AndI", "SltI", "SltIU",
        "SllI", "SrlI", "SraI",
        # U-type
        "Lui", "Auipc",
        # Jumps (write return address to register)
        "Jal", "JalR",
    },
    
    # LOAD_VAL_MOD: Load instructions
    "LOAD_VAL_MOD": {
        "Lw", "Lh", "Lb", "LhU", "LbU",
    },
    
    # STORE_OUT_MOD: Store instructions
    "STORE_OUT_MOD": {
        "Sw", "Sh", "Sb",
    },
    
    # PRE_EXEC_REG_MOD: Injects random value into random register BEFORE instruction
    # The instruction type doesn't determine validity (injection is pre-execution)
    # We select compute-heavy instructions where registers are actively used
    # Note: Has two sub-strategies (next_read, prev_write) tested separately
    "PRE_EXEC_REG_MOD": {
        # R-type compute (use multiple registers)
        "Add", "Sub", "Sll", "Slt", "SltU", "Xor", "Or", "And",
        "Mul", "MulH", "MulHSU", "MulHU", "Div", "DivU", "Rem", "RemU",
        "Srl", "Sra",
        # I-type compute
        "AddI", "XorI", "OrI", "AndI", "SltI", "SltIU",
        "SllI", "SrlI", "SraI",
        # U-type
        "Lui", "Auipc",
        # Load/Store (read/write registers)
        "Lw", "Lh", "Lb", "LhU", "LbU",
        "Sw", "Sh", "Sb",
    },
}


def parse_trace_line(line: str) -> Optional[TraceEntry]:
    """Parse a <trace> line"""
    match = re.search(r'<trace>({.*?})</trace>', line)
    if not match:
        return None
    
    try:
        data = json.loads(match.group(1))
        return TraceEntry(
            step=data['step'],
            pc=data['pc'],
            instruction=data['instruction'],
            assembly=data.get('assembly', ''),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def load_trace(trace_file: Path) -> List[TraceEntry]:
    """Load and parse trace file"""
    entries = []
    with open(trace_file) as f:
        for line in f:
            entry = parse_trace_line(line)
            if entry:
                entries.append(entry)
    return entries


def categorize_steps(entries: List[TraceEntry]) -> Dict[str, Dict[str, List[int]]]:
    """
    Categorize steps by mutation type and instruction type.
    
    Returns:
        {
            "INSTR_WORD_MOD": {"AddI": [1, 5, 8, ...], "Add": [52, 68, ...], ...},
            "COMP_OUT_MOD": {...},
            ...
        }
    """
    result = {mut_type: defaultdict(list) for mut_type in MUTATION_VALID_INSTRUCTIONS}
    
    for entry in entries:
        for mut_type, valid_insns in MUTATION_VALID_INSTRUCTIONS.items():
            if entry.instruction in valid_insns:
                result[mut_type][entry.instruction].append(entry.step)
    
    # Convert defaultdicts to regular dicts
    return {k: dict(v) for k, v in result.items()}


def select_comprehensive_steps(
    categorized: Dict[str, Dict[str, List[int]]],
    min_step: int = 100,
    steps_per_instruction: int = 3,
) -> Dict[str, List[Dict]]:
    """
    COMPREHENSIVE MODE: Select steps for EVERY unique instruction type.
    
    For each mutation type, selects multiple steps for each instruction type
    found in the trace to ensure complete coverage.
    
    Args:
        categorized: Categorized steps by mutation type and instruction
        min_step: Minimum step number (skip early init)
        steps_per_instruction: Number of steps to select per instruction type
        
    Returns:
        {
            "INSTR_WORD_MOD": [
                {"step": 200, "instruction": "AddI"},
                {"step": 500, "instruction": "AddI"},
                {"step": 52, "instruction": "Add"},
                ...
            ],
            ...
        }
    """
    result = {}
    
    for mut_type, insn_steps in categorized.items():
        selected = []
        
        # For EVERY instruction type found in the trace
        for insn, steps in sorted(insn_steps.items()):
            # Filter to steps >= min_step
            valid_steps = sorted(set(s for s in steps if s >= min_step))
            
            if not valid_steps:
                continue
            
            n = len(valid_steps)
            to_select = min(steps_per_instruction, n)
            
            if to_select == 1:
                # Just pick middle
                indices = [n // 2]
            elif to_select == 2:
                # Pick early and late
                indices = [n // 4, 3 * n // 4]
            else:
                # Spread evenly: pick at 1/4, 1/2, 3/4 positions
                indices = []
                for i in range(to_select):
                    # Spread from 1/(to_select+1) to to_select/(to_select+1)
                    idx = (i + 1) * n // (to_select + 1)
                    indices.append(min(idx, n - 1))
            
            # Ensure unique indices
            indices = sorted(set(indices))
            
            for idx in indices:
                selected.append({
                    "step": valid_steps[idx],
                    "instruction": insn,
                    "total_available": len(steps),
                })
        
        # Sort by instruction name, then step
        selected.sort(key=lambda x: (x["instruction"], x["step"]))
        result[mut_type] = selected
    
    return result


def select_quick_steps(
    categorized: Dict[str, Dict[str, List[int]]],
    min_step: int = 100,
    total_steps: int = 5,
) -> Dict[str, List[Dict]]:
    """
    QUICK MODE: Select a small diverse set for fast testing.
    
    Selects one step from each instruction type until total_steps is reached.
    """
    result = {}
    
    for mut_type, insn_steps in categorized.items():
        selected = []
        
        # Sort instructions by frequency (least common first for diversity)
        sorted_insns = sorted(insn_steps.items(), key=lambda x: len(x[1]))
        
        for insn, steps in sorted_insns:
            if len(selected) >= total_steps:
                break
                
            valid_steps = [s for s in steps if s >= min_step]
            if valid_steps:
                # Pick from middle of range
                idx = len(valid_steps) // 3
                selected.append({
                    "step": valid_steps[idx],
                    "instruction": insn,
                    "total_available": len(steps),
                })
        
        selected.sort(key=lambda x: x["step"])
        result[mut_type] = selected
    
    return result


def print_summary(categorized: Dict, selected: Dict, mode: str):
    """Print summary of categorization and selection"""
    print("\n" + "=" * 80)
    print(f"STEP SELECTION SUMMARY ({mode} MODE)")
    print("=" * 80)
    
    for mut_type in MUTATION_VALID_INSTRUCTIONS:
        insn_steps = categorized[mut_type]
        total_valid = sum(len(v) for v in insn_steps.values())
        unique_insns = len(insn_steps)
        selected_count = len(selected.get(mut_type, []))
        
        print(f"\n### {mut_type} ###")
        print(f"Total valid steps in trace: {total_valid}")
        print(f"Unique instruction types: {unique_insns}")
        print(f"Selected test steps: {selected_count}")
        
        print("\nInstruction breakdown:")
        for insn, steps in sorted(insn_steps.items(), key=lambda x: -len(x[1])):
            count = len(steps)
            selected_for_insn = [s for s in selected.get(mut_type, []) if s["instruction"] == insn]
            selected_steps_str = ", ".join(str(s["step"]) for s in selected_for_insn) if selected_for_insn else "-"
            print(f"  {insn:10s}: {count:5d} available → selected: [{selected_steps_str}]")
    
    # Summary table
    print("\n" + "=" * 80)
    print("SELECTION SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Mutation Type':<20} {'Unique Insns':<15} {'Total Steps':<15} {'Selected':<10}")
    print("-" * 60)
    for mut_type in MUTATION_VALID_INSTRUCTIONS:
        insn_steps = categorized[mut_type]
        unique = len(insn_steps)
        total = sum(len(v) for v in insn_steps.values())
        sel = len(selected.get(mut_type, []))
        print(f"{mut_type:<20} {unique:<15} {total:<15} {sel:<10}")


def generate_test_commands(selected: Dict, host_binary: str, host_args: str) -> Dict[str, List[str]]:
    """Generate shell commands for running tests"""
    commands = {}
    
    for mut_type, steps in selected.items():
        cmds = []
        for s in steps:
            step = s["step"]
            insn = s["instruction"]
            cmd = (
                f"python3 -m a4.cli compare --step {step} --kind {mut_type} --seed 12345 "
                f"--host-binary {host_binary} --host-args '{host_args}' "
                f"--output-json ./a4/verification/results/{mut_type.lower()}_step{step}_{insn.lower()}.json "
                f"2>&1 | tee ./a4/verification/logs/{mut_type.lower()}_step{step}_{insn.lower()}.log"
            )
            cmds.append(cmd)
        commands[mut_type] = cmds
    
    return commands


def save_results(output_path: Path, categorized: Dict, selected: Dict, commands: Dict, mode: str):
    """Save all results to JSON"""
    results = {
        "mode": mode,
        "categorized_summary": {
            k: {insn: len(steps) for insn, steps in v.items()}
            for k, v in categorized.items()
        },
        "selected_steps": selected,
        "test_commands": commands,
        "stats": {
            mut_type: {
                "unique_instructions": len(categorized[mut_type]),
                "total_valid_steps": sum(len(v) for v in categorized[mut_type].values()),
                "selected_count": len(selected.get(mut_type, [])),
            }
            for mut_type in MUTATION_VALID_INSTRUCTIONS
        }
    }
    
    output_path.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Select valid steps for A4 verification testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comprehensive mode (test ALL instruction types)
  python3 -m a4.verification.scripts.select_steps --trace-file ./a4/tmp/trace.log
  
  # Quick mode (small diverse set)
  python3 -m a4.verification.scripts.select_steps --trace-file ./a4/tmp/trace.log --quick
  
  # More steps per instruction type
  python3 -m a4.verification.scripts.select_steps --steps-per-instruction 5
"""
    )
    parser.add_argument('--trace-file', type=str, 
                       default='./a4/tmp/trace.log',
                       help='Path to trace log file')
    parser.add_argument('--output', type=str, 
                       default='./a4/verification/selected_steps.json',
                       help='Output JSON file path')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode: select small diverse set instead of all instructions')
    parser.add_argument('--steps-per-instruction', type=int, default=3,
                       help='Number of steps per instruction type (comprehensive mode)')
    parser.add_argument('--quick-total', type=int, default=5,
                       help='Total steps per mutation type (quick mode)')
    parser.add_argument('--min-step', type=int, default=100,
                       help='Minimum step number (skip early init)')
    parser.add_argument('--host-binary', type=str,
                       default='./workspace/output/target/release/risc0-host',
                       help='Host binary for command generation')
    parser.add_argument('--host-args', type=str,
                       default='--in1 5 --in4 10',
                       help='Host arguments for command generation')
    parser.add_argument('--print-commands', action='store_true',
                       help='Print generated test commands')
    
    args = parser.parse_args()
    
    trace_path = Path(args.trace_file)
    if not trace_path.exists():
        print(f"ERROR: Trace file not found: {trace_path}")
        print("\nGenerate trace with:")
        print(f"  cd /root/arguzz/workspace/output")
        print(f"  ./target/release/risc0-host --trace {args.host_args} 2>&1 | grep '<trace>' > ../../a4/tmp/trace.log")
        return 1
    
    # Load trace
    print(f"Loading trace from: {trace_path}")
    entries = load_trace(trace_path)
    print(f"Parsed {len(entries)} trace entries")
    
    # Categorize
    categorized = categorize_steps(entries)
    
    # Select test steps based on mode
    mode = "QUICK" if args.quick else "COMPREHENSIVE"
    
    if args.quick:
        selected = select_quick_steps(
            categorized,
            min_step=args.min_step,
            total_steps=args.quick_total,
        )
    else:
        selected = select_comprehensive_steps(
            categorized,
            min_step=args.min_step,
            steps_per_instruction=args.steps_per_instruction,
        )
    
    # Generate commands
    commands = generate_test_commands(selected, args.host_binary, args.host_args)
    
    # Print summary
    print_summary(categorized, selected, mode)
    
    # Print commands if requested
    if args.print_commands:
        print("\n" + "=" * 80)
        print("GENERATED TEST COMMANDS")
        print("=" * 80)
        for mut_type, cmds in commands.items():
            print(f"\n# {mut_type} ({len(cmds)} tests)")
            for cmd in cmds:
                print(cmd)
                print()
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    save_results(output_path, categorized, selected, commands, mode)
    
    # Print next steps
    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    total_tests = sum(len(v) for v in selected.values())
    print(f"\nTotal tests to run: {total_tests}")
    print("\nRun tests with:")
    print("  # All mutation types")
    print("  python3 -m a4.verification.scripts.run_tests --all")
    print("\n  # One mutation type at a time")
    print("  python3 -m a4.verification.scripts.run_tests --mutation-type INSTR_WORD_MOD")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
