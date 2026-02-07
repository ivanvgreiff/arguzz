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


@dataclass
class ArguzzResult:
    """Result from running an Arguzz mutation"""
    output: str
    faults: List[ArguzzFault]
    failures: List[ConstraintFailure]
    guest_crashed: bool
    crash_reason: str = ""


def run_arguzz_mutation(
    host_binary: str,
    host_args: List[str],
    step: int,
    kind: str,
    seed: int
) -> ArguzzResult:
    """Run Arguzz mutation and capture output
    
    Returns:
        ArguzzResult containing output, faults, failures, and crash status.
        If guest_crashed is True, the prover never completed so no constraint
        failures could be detected.
    """
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
    
    # Detect guest crash
    # A "guest crash" is when the prover fails BEFORE it could check constraints.
    # This is indicated by: 0 constraint failures AND prover error/panic.
    # 
    # If there ARE constraint failures, the prover completed enough to detect them,
    # even if it then panicked/errored - that's expected behavior, not a crash.
    guest_crashed = False
    crash_reason = ""
    
    # Only consider it a "guest crash" if there are NO constraint failures
    # and the prover errored
    if len(failures) == 0:
        # Check for prover error status or panic
        has_prover_error = '"status":"error"' in output and '"context":"Prover"' in output
        has_panic = "panicked at" in output or "Guest panicked:" in output
        
        if has_prover_error or has_panic:
            guest_crashed = True
            
            # Extract crash reason
            if "Guest panicked:" in output:
                for line in output.split('\n'):
                    if "Guest panicked:" in line:
                        crash_reason = line.strip()
                        break
            elif "panicked at" in output:
                for line in output.split('\n'):
                    if "panicked at" in line:
                        crash_reason = line.strip()
                        break
            else:
                crash_reason = "Prover error (unknown reason)"
    
    return ArguzzResult(
        output=output,
        faults=faults,
        failures=failures,
        guest_crashed=guest_crashed,
        crash_reason=crash_reason,
    )


def run_a4_mutation(
    host_binary: str,
    host_args: List[str],
    config_path: Path,
    skip_addr_check: bool = False
) -> Tuple[str, List[ConstraintFailure]]:
    """Run A4 mutation and capture output
    
    Args:
        skip_addr_check: If True, set FAULT_INJECTION_ENABLED to skip the
            address mismatch check in extern_getMemoryTxn. Generally not
            needed for A4's supported mutation types.
    """
    cmd = [host_binary] + host_args
    
    env = {
        "A4_MUTATION_CONFIG": str(config_path),
        "CONSTRAINT_CONTINUE": "1",
    }
    
    if skip_addr_check:
        env["FAULT_INJECTION_ENABLED"] = "1"
    
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
    skipped: bool = False
    skip_reason: str = ""
    
    def print_summary(self):
        """Print a summary of the comparison"""
        print("\n" + "=" * 60)
        print("CONSTRAINT FAILURE COMPARISON")
        print("=" * 60)
        
        if self.skipped:
            print(f"\n*** COMPARISON SKIPPED ***")
            print(f"Reason: {self.skip_reason}")
            print("=" * 60)
            return
        
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
        # Handle MATCH: prefix from compare_failures_by_constraint_only
        if sig.startswith("MATCH:"):
            constraint = sig[6:]  # Remove "MATCH:" prefix
            print(f"  ✓ {constraint}")
            return
        
        parts = sig.split(':')
        if len(parts) >= 5:
            step, pc, major, minor, constraint = parts[0], parts[1], parts[2], parts[3], ':'.join(parts[4:])
            print(f"  step={step}, pc={pc}, major={major}, minor={minor}: {constraint}")
        else:
            print(f"  {sig}")
    
    @classmethod
    def skipped_result(cls, reason: str) -> 'ComparisonResult':
        """Create a skipped comparison result"""
        return cls(
            arguzz_failures=[],
            a4_failures=[],
            common_signatures=[],
            arguzz_only_signatures=[],
            a4_only_signatures=[],
            skipped=True,
            skip_reason=reason,
        )


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


def compare_failures_by_constraint_only(
    arguzz_failures: List[ConstraintFailure],
    a4_failures: List[ConstraintFailure],
) -> ComparisonResult:
    """
    Compare constraint failures using ONLY the constraint location (short_loc).
    
    This is used for PRE_EXEC_REG_MOD and similar mutations where:
    - Arguzz injects a NEW transaction at step X
    - A4 modifies an EXISTING transaction at step Y (Y != X)
    - Both cause the SAME TYPE of memory consistency failure
    - But at DIFFERENT steps/PCs
    
    For these mutations, we only care if both triggered the same constraint
    types (e.g., IsRead@mem.zir:79), not whether they occurred at the same
    step/PC.
    
    Args:
        arguzz_failures: Failures from Arguzz run
        a4_failures: Failures from A4 run
    
    Returns:
        ComparisonResult with common = same constraint locations
    """
    # Use only short_loc for comparison (constraint name + file:line)
    # This ignores step, pc, major, minor
    def constraint_only_sig(f: ConstraintFailure) -> str:
        return f.short_loc()
    
    # For display, we still want the full signature
    def full_sig(f: ConstraintFailure) -> str:
        return f"{f.step}:{f.pc}:{f.major}:{f.minor}:{f.short_loc()}"
    
    # Build maps: constraint_loc -> list of full signatures
    arguzz_by_constraint = {}
    for f in arguzz_failures:
        loc = constraint_only_sig(f)
        if loc not in arguzz_by_constraint:
            arguzz_by_constraint[loc] = []
        arguzz_by_constraint[loc].append(full_sig(f))
    
    a4_by_constraint = {}
    for f in a4_failures:
        loc = constraint_only_sig(f)
        if loc not in a4_by_constraint:
            a4_by_constraint[loc] = []
        a4_by_constraint[loc].append(full_sig(f))
    
    # Find common constraint locations
    common_locs = set(arguzz_by_constraint.keys()) & set(a4_by_constraint.keys())
    arguzz_only_locs = set(arguzz_by_constraint.keys()) - common_locs
    a4_only_locs = set(a4_by_constraint.keys()) - common_locs
    
    # For common: show both Arguzz and A4 versions (they differ in step/pc)
    common_signatures = []
    for loc in sorted(common_locs):
        # Show constraint loc with both versions
        arguzz_examples = arguzz_by_constraint[loc]
        a4_examples = a4_by_constraint[loc]
        # Use a combined format: "CONSTRAINT (Arguzz: step=X, A4: step=Y)"
        common_signatures.append(f"MATCH:{loc}")
    
    # For Arguzz-only: show full signatures
    arguzz_only_signatures = []
    for loc in sorted(arguzz_only_locs):
        for sig in arguzz_by_constraint[loc]:
            arguzz_only_signatures.append(sig)
    
    # For A4-only: show full signatures
    a4_only_signatures = []
    for loc in sorted(a4_only_locs):
        for sig in a4_by_constraint[loc]:
            a4_only_signatures.append(sig)
    
    return ComparisonResult(
        arguzz_failures=arguzz_failures,
        a4_failures=a4_failures,
        common_signatures=common_signatures,
        arguzz_only_signatures=arguzz_only_signatures,
        a4_only_signatures=a4_only_signatures,
    )


def find_a4_step_for_arguzz_step(
    arguzz_step: int,
    arguzz_pc: int,
    a4_cycles: List[A4CycleInfo]
) -> int:
    """
    Find the A4 user_cycle (step) that corresponds to an Arguzz step.
    
    Key insight about step counting differences:
    - Arguzz counts every instruction execution (including machine mode)
    - Preflight trace counts instruction cycles PLUS Control/Poseidon/SHA cycles
    - The offset (arguzz_step - preflight_step) grows over time as more special
      cycles are executed
    
    Strategy:
    1. Find all preflight cycles at the EXACT Arguzz PC (the instruction location)
    2. Find the closest preflight step to the Arguzz step
    
    This works because:
    - The PC uniquely identifies which instruction we're looking for
    - The offset between Arguzz and preflight is typically < 100, so the closest
      match at the same PC is the correct one
    - For loops, there may be multiple cycles at the same PC; we pick the one
      closest to (but not exceeding) the Arguzz step
    
    Args:
        arguzz_step: Arguzz injection step
        arguzz_pc: PC from Arguzz fault
        a4_cycles: All A4 cycles from inspection
        
    Returns:
        The A4 step (user_cycle) that corresponds to this Arguzz step
        
    Raises:
        ValueError: If no suitable A4 step can be found
    """
    # Find all instruction cycles at the exact Arguzz PC
    # Only consider instruction cycles (major 0-6)
    matches = [c for c in a4_cycles if c.pc == arguzz_pc and c.major <= 6]
    
    if not matches:
        raise ValueError(
            f"No A4 instruction cycle found at PC=0x{arguzz_pc:X} for Arguzz step {arguzz_step}. "
            f"This PC may not have been reached in the preflight trace."
        )
    
    if len(matches) == 1:
        return matches[0].step
    
    # Multiple matches (loop iterations) - find the closest to arguzz_step
    # Prefer matches where preflight_step <= arguzz_step (since preflight counts more cycles)
    valid = [c for c in matches if c.step <= arguzz_step]
    if valid:
        # Return the largest preflight step that's still <= arguzz_step
        return max(valid, key=lambda c: c.step).step
    
    # All matches are > arguzz_step (unusual), return the closest
    return min(matches, key=lambda c: abs(c.step - arguzz_step)).step
