"""
COMP_OUT_MOD Mutation

This mutation targets the txns[].word field for WRITE transactions in the
PreflightTrace, corresponding to Arguzz's COMP_OUT_MOD mutation which changes
the output value of compute instructions before writing to the destination register.

When Arguzz mutates a compute output:
1. The computation produces the ORIGINAL output value
2. Arguzz changes it to a MUTATED value before ctx.store_register()
3. The MUTATED value is written to the destination register

A4's COMP_OUT_MOD directly mutates the WRITE transaction's word field to match
the effect of Arguzz's mutation, testing the circuit's memory consistency checks.

Transaction Identification:
- For compute instructions, there are typically 4 transactions:
  1. Instruction fetch (READ) - addr = PC/4
  2. Load rs1 (READ) - addr = register address
  3. Load rs2 (READ) - addr = register address (may not be used)
  4. Store rd (WRITE) - addr = destination register address
- We identify the WRITE transaction by: cycle % 2 == 1 (odd = WRITE)
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from a4.common.trace_parser import (
    ArguzzFault, A4CycleInfo, A4StepTxns, A4Txn,
    parse_all_a4_cycles, parse_all_step_txns, parse_all_txns
)

from a4.mutations.base import (
    run_a4_inspection_with_step,
    run_arguzz_mutation,
    run_a4_mutation,
    compare_failures,
    ComparisonResult,
    find_a4_step_for_arguzz_step,
)


# Register name mapping for pretty printing
REGISTER_NAMES = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    's0/fp', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
]


@dataclass
class CompOutModTarget:
    """The target location in A4 for a COMP_OUT_MOD mutation"""
    cycle_idx: int          # Index into trace.cycles[]
    step: int               # user_cycle value (A4 step)
    pc: int                 # PC value (next PC)
    major: int              # Instruction major category
    minor: int              # Instruction minor category
    write_txn_idx: int      # Index of the WRITE transaction in trace.txns[]
    write_addr: int         # Address of the WRITE (register word address)
    register_idx: int       # Destination register index (0-31)
    register_name: str      # Destination register name (e.g., "a2")
    original_value: int     # Original output value (from Arguzz fault)
    mutated_value: int      # Mutated output value (from Arguzz fault)


def find_write_transaction(txns: List[A4Txn], step_txns: A4StepTxns) -> Optional[A4Txn]:
    """
    Find the WRITE transaction within a step's transaction range.
    
    For compute instructions, there should be exactly one WRITE transaction
    which writes to the destination register.
    
    Args:
        txns: List of parsed transactions
        step_txns: Transaction range info for the target step
        
    Returns:
        The WRITE transaction, or None if not found
    """
    # Filter transactions to those in the step's range
    step_txn_indices = set(range(step_txns.txn_start, step_txns.txn_end))
    step_txn_list = [t for t in txns if t.txn_idx in step_txn_indices]
    
    # Find WRITE transactions (odd cycle number)
    write_txns = [t for t in step_txn_list if t.is_write()]
    
    if not write_txns:
        print(f"ERROR: No WRITE transaction found in step {step_txns.step}")
        print(f"  Transactions in range [{step_txns.txn_start}, {step_txns.txn_end}):")
        for t in step_txn_list:
            print(f"    txn_idx={t.txn_idx}, addr={t.addr}, cycle={t.cycle}, "
                  f"word={t.word}, {'WRITE' if t.is_write() else 'READ'}")
        return None
    
    if len(write_txns) > 1:
        # For compute instructions, there should typically be only one WRITE
        # If multiple, prefer the one writing to a register
        reg_writes = [t for t in write_txns if t.is_register()]
        if reg_writes:
            # Return the last register write (destination register)
            return reg_writes[-1]
        print(f"WARNING: Multiple WRITE transactions found, using last one")
    
    return write_txns[-1]


def find_mutation_target(
    arguzz_fault: ArguzzFault,
    a4_cycles: List[A4CycleInfo],
    step_txns_list: List[A4StepTxns],
    txns: List[A4Txn]
) -> Optional[CompOutModTarget]:
    """
    Find the A4 mutation target for a COMP_OUT_MOD Arguzz fault.
    
    Algorithm:
    1. Find the A4 step corresponding to the Arguzz step (using PC matching)
    2. Get the transaction range for that step
    3. Find the WRITE transaction within that range
    4. Return the target with all necessary info
    
    Args:
        arguzz_fault: The parsed Arguzz COMP_OUT_MOD fault
        a4_cycles: All A4 cycles from inspection
        step_txns_list: Transaction range info (from A4_DUMP_STEP)
        txns: Individual transactions (from A4_DUMP_STEP)
        
    Returns:
        CompOutModTarget if found, None otherwise
    """
    # Step 1: Find A4 step using PC matching
    try:
        a4_step = find_a4_step_for_arguzz_step(
            arguzz_fault.step, arguzz_fault.pc, a4_cycles
        )
    except ValueError as e:
        print(f"ERROR: {e}")
        return None
    
    # Find the cycle info for this step
    matching_cycle = None
    for cycle in a4_cycles:
        if cycle.step == a4_step:
            matching_cycle = cycle
            break
    
    if not matching_cycle:
        print(f"ERROR: Could not find cycle info for step {a4_step}")
        return None
    
    # Step 2: Get transaction range for this step
    step_txns = None
    for st in step_txns_list:
        if st.step == a4_step:
            step_txns = st
            break
    
    if not step_txns:
        print(f"ERROR: No transaction range found for step {a4_step}")
        print(f"  Available step_txns: {[st.step for st in step_txns_list]}")
        return None
    
    # Step 3: Find the WRITE transaction
    write_txn = find_write_transaction(txns, step_txns)
    if not write_txn:
        return None
    
    # Get register info
    reg_idx = write_txn.register_index()
    if reg_idx is None:
        print(f"WARNING: WRITE transaction not to a register (addr={write_txn.addr})")
        reg_idx = -1
        reg_name = f"mem[{write_txn.addr}]"
    else:
        reg_name = REGISTER_NAMES[reg_idx] if reg_idx < len(REGISTER_NAMES) else f"x{reg_idx}"
    
    return CompOutModTarget(
        cycle_idx=matching_cycle.cycle_idx,
        step=a4_step,
        pc=matching_cycle.pc,
        major=matching_cycle.major,
        minor=matching_cycle.minor,
        write_txn_idx=write_txn.txn_idx,
        write_addr=write_txn.addr,
        register_idx=reg_idx,
        register_name=reg_name,
        original_value=arguzz_fault.original_value,
        mutated_value=arguzz_fault.mutated_value,
    )


def create_config(target: CompOutModTarget, output_path: Path) -> Path:
    """Create an A4 mutation config file for COMP_OUT_MOD"""
    config = {
        "mutation_type": "COMP_OUT_MOD",
        "step": target.step,
        "txn_idx": target.write_txn_idx,
        "word": target.mutated_value,
        # Additional info for debugging (not used by mutation)
        "_info": {
            "register": target.register_name,
            "original_value": target.original_value,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def run_full_inspection(
    host_binary: str,
    host_args: List[str],
    arguzz_fault: ArguzzFault
) -> Tuple[List[A4CycleInfo], List[A4StepTxns], List[A4Txn], int]:
    """
    Run A4 inspection to get cycles and step-specific transactions.
    
    This performs two inspections:
    1. Full inspection to get all cycles and find the A4 step
    2. Step-specific inspection to get transaction details
    
    Returns:
        (cycles, step_txns, txns, a4_step)
    """
    # First, run full inspection to get all cycles
    output1, cycles, _, _ = run_a4_inspection_with_step(host_binary, host_args, 0)
    
    # Find the A4 step
    a4_step = find_a4_step_for_arguzz_step(arguzz_fault.step, arguzz_fault.pc, cycles)
    
    # Now run inspection with the specific step to get transactions
    output2, _, step_txns, txns = run_a4_inspection_with_step(host_binary, host_args, a4_step)
    
    return cycles, step_txns, txns, a4_step
