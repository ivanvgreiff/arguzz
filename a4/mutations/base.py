"""
Base utilities for A4 mutations

Contains shared functions used by all mutation types:
- Running Arguzz mutations
- Running A4 inspection
- Running A4 mutations
- Comparing constraint failures
"""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from a4.common.trace_parser import (
    ArguzzFault, A4CycleInfo, ConstraintFailure, A4StepTxns, A4Txn,
    parse_all_faults, parse_all_a4_cycles, parse_all_constraint_failures,
    parse_all_step_txns, parse_all_txns
)


def run_a4_inspection(host_binary: str, host_args: List[str]) -> str:
    """Run A4 in inspection mode to get all cycle info"""
    env = {"A4_INSPECT": "1"}
    cmd = [host_binary] + host_args
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**dict(os.environ), **env}
    )
    
    return result.stdout + result.stderr


def run_a4_inspection_with_step(
    host_binary: str, 
    host_args: List[str], 
    step: int
) -> Tuple[str, List[A4CycleInfo], List[A4StepTxns], List[A4Txn]]:
    """
    Run A4 inspection with step-specific transaction dump.
    
    Returns:
        (raw_output, cycles, step_txns, txns)
    """
    env = {
        "A4_INSPECT": "1",
        "A4_DUMP_STEP": str(step),
    }
    cmd = [host_binary] + host_args
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**dict(os.environ), **env}
    )
    
    output = result.stdout + result.stderr
    cycles = parse_all_a4_cycles(output)
    step_txns = parse_all_step_txns(output)
    txns = parse_all_txns(output)
    
    return output, cycles, step_txns, txns


def run_arguzz_mutation(
    host_binary: str,
    host_args: List[str],
    step: int,
    kind: str,
    seed: int
) -> Tuple[str, List[ArguzzFault], List[ConstraintFailure]]:
    """Run Arguzz mutation and capture output"""
    cmd = [
        host_binary, "--trace", "--inject",
        "--seed", str(seed),
        "--inject-step", str(step),
        "--inject-kind", kind,
    ] + host_args
    
    env = {
        "CONSTRAINT_CONTINUE": "1",
    }
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**dict(os.environ), **env}
    )
    
    output = result.stdout + result.stderr
    faults = parse_all_faults(output)
    failures = parse_all_constraint_failures(output)
    
    return output, faults, failures


def run_a4_mutation(
    host_binary: str,
    host_args: List[str],
    config_path: Path
) -> Tuple[str, List[ConstraintFailure]]:
    """Run A4 mutation and capture output"""
    cmd = [host_binary] + host_args
    
    env = {
        "A4_MUTATION_CONFIG": str(config_path),
        "CONSTRAINT_CONTINUE": "1",
    }
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={**dict(os.environ), **env}
    )
    
    output = result.stdout + result.stderr
    failures = parse_all_constraint_failures(output)
    
    return output, failures


@dataclass
class ComparisonResult:
    """Result of comparing Arguzz and A4 constraint failures"""
    arguzz_failures: List[ConstraintFailure]
    a4_failures: List[ConstraintFailure]
    common_signatures: List[str]
    arguzz_only_signatures: List[str]
    a4_only_signatures: List[str]
    
    def print_summary(self):
        """Print a summary of the comparison"""
        print("\n" + "=" * 60)
        print("CONSTRAINT FAILURE COMPARISON")
        print("=" * 60)
        
        print(f"\nArguzz: {len(self.arguzz_failures)} failures")
        print(f"A4:     {len(self.a4_failures)} failures")
        
        print(f"\n--- Common ({len(self.common_signatures)}) ---")
        for sig in self.common_signatures:
            self._print_signature(sig)
        
        print(f"\n--- Arguzz only ({len(self.arguzz_only_signatures)}) ---")
        for sig in self.arguzz_only_signatures:
            self._print_signature(sig)
        
        print(f"\n--- A4 only ({len(self.a4_only_signatures)}) ---")
        for sig in self.a4_only_signatures:
            self._print_signature(sig)
        
        print("=" * 60)
    
    def _print_signature(self, sig: str):
        """Pretty-print a signature"""
        parts = sig.split(':')
        if len(parts) >= 5:
            step, pc, major, minor, constraint = parts[0], parts[1], parts[2], parts[3], ':'.join(parts[4:])
            print(f"  step={step}, pc={pc}, major={major}, minor={minor}: {constraint}")
        else:
            print(f"  {sig}")


def compare_failures(
    arguzz_failures: List[ConstraintFailure],
    a4_failures: List[ConstraintFailure],
    step_offset: int = 0
) -> ComparisonResult:
    """
    Compare constraint failures between Arguzz and A4.
    
    Note: Constraint failures are reported at the ACTUAL step (user_cycle),
    not the Arguzz injection step. So we don't apply the step_offset to
    failure comparison - both should report at the same step.
    
    Args:
        arguzz_failures: Failures from Arguzz run
        a4_failures: Failures from A4 run
        step_offset: Informational only (not used for comparison)
    """
    # Normalize signatures (NO step adjustment - both report at actual step)
    def normalize_sig(f: ConstraintFailure) -> str:
        return f"{f.step}:{f.pc}:{f.major}:{f.minor}:{f.short_loc()}"
    
    arguzz_sigs = {normalize_sig(f): f for f in arguzz_failures}
    a4_sigs = {normalize_sig(f): f for f in a4_failures}
    
    common = set(arguzz_sigs.keys()) & set(a4_sigs.keys())
    arguzz_only = set(arguzz_sigs.keys()) - common
    a4_only = set(a4_sigs.keys()) - common
    
    return ComparisonResult(
        arguzz_failures=arguzz_failures,
        a4_failures=a4_failures,
        common_signatures=sorted(common),
        arguzz_only_signatures=sorted(arguzz_only),
        a4_only_signatures=sorted(a4_only),
    )


def find_a4_step_for_arguzz_step(
    arguzz_step: int,
    arguzz_pc: int,
    a4_cycles: List[A4CycleInfo]
) -> int:
    """
    Find the A4 user_cycle (step) that corresponds to an Arguzz step.
    
    Uses PC-based matching since A4 records next PC = Arguzz PC + 4.
    
    Args:
        arguzz_step: Arguzz injection step
        arguzz_pc: PC from Arguzz fault
        a4_cycles: All A4 cycles from inspection
        
    Returns:
        The A4 step (user_cycle) that corresponds to this Arguzz step
    """
    expected_a4_pc = arguzz_pc + 4
    
    # Find all cycles with matching PC
    matches = [c for c in a4_cycles if c.pc == expected_a4_pc]
    
    if not matches:
        raise ValueError(f"No A4 cycle found with PC={expected_a4_pc}")
    
    # For loops, pick the latest iteration <= Arguzz step
    if len(matches) > 1:
        valid = [c for c in matches if c.step <= arguzz_step]
        if not valid:
            raise ValueError(f"No valid match for loop disambiguation (step <= {arguzz_step})")
        return max(valid, key=lambda c: c.step).step
    
    return matches[0].step
