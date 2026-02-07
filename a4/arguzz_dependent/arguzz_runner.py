"""
Arguzz Mutation Runner

Functions for running Arguzz mutations and capturing results.
"""

import os
import subprocess
from dataclasses import dataclass
from typing import List

from a4.core.constraint_parser import ConstraintFailure, parse_all_constraint_failures
from a4.arguzz_dependent.arguzz_parser import (
    ArguzzFault, ArguzzTrace,
    parse_all_faults, parse_all_traces
)


@dataclass
class ArguzzResult:
    """Result from running an Arguzz mutation"""
    output: str
    faults: List[ArguzzFault]
    failures: List[ConstraintFailure]
    traces: List[ArguzzTrace]  # Execution trace for offset computation
    guest_crashed: bool
    crash_reason: str = ""


def run_arguzz_mutation(
    host_binary: str,
    host_args: List[str],
    step: int,
    kind: str,
    seed: int
) -> ArguzzResult:
    """
    Run Arguzz mutation and capture output.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        step: Injection step
        kind: Mutation kind (e.g., "COMP_OUT_MOD")
        seed: Random seed
        
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
    traces = parse_all_traces(output)  # Parse trace for offset computation
    
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
        traces=traces,
        guest_crashed=guest_crashed,
        crash_reason=crash_reason,
    )
