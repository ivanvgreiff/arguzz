"""
A4 Execution Utilities

Functions for running A4 inspection and mutation via the risc0-host binary.
These are the core execution primitives shared by all A4 strategies.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Tuple

from a4.core.trace_parser import (
    A4CycleInfo, A4StepTxns, A4Txn,
    parse_all_a4_cycles, parse_all_step_txns, parse_all_txns
)
from a4.core.constraint_parser import (
    ConstraintFailure,
    parse_all_constraint_failures
)


def run_a4_inspection(host_binary: str, host_args: List[str]) -> str:
    """
    Run A4 in inspection mode to get all cycle info.
    
    Sets A4_INSPECT=1 to enable preflight trace inspection output.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        
    Returns:
        Combined stdout+stderr output containing <a4_cycle_info> lines
    """
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
    
    Sets A4_INSPECT=1 and A4_DUMP_STEP=<step> to get transactions
    for a specific step.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        step: The user_cycle (step) to dump transactions for
        
    Returns:
        Tuple of (raw_output, cycles, step_txns, txns)
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


def run_a4_inspection_with_reg_txns(
    host_binary: str,
    host_args: List[str]
) -> Tuple[str, List[A4CycleInfo]]:
    """
    Run A4 inspection with register transaction dump.
    
    Sets A4_INSPECT=1 and A4_DUMP_REG_TXNS=1 to get all register
    transactions in a single pass.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        
    Returns:
        Tuple of (raw_output, cycles)
        Caller should use parse_all_reg_txns() on output for reg txns.
    """
    env = {
        "A4_INSPECT": "1",
        "A4_DUMP_REG_TXNS": "1",
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
    
    return output, cycles


def run_a4_mutation(
    host_binary: str,
    host_args: List[str],
    config_path: Path,
) -> Tuple[str, List[ConstraintFailure]]:
    """
    Run A4 mutation and capture constraint failures.
    
    Sets A4_MUTATION_CONFIG to the config file path and
    CONSTRAINT_CONTINUE=1 to collect all failures.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        config_path: Path to JSON mutation config file
        
    Returns:
        Tuple of (raw_output, constraint_failures)
    """
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
