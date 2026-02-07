"""
STORE_OUT_MOD Mutation

This mutation targets the txns[].word field for WRITE transactions to MEMORY
in the PreflightTrace, corresponding to Arguzz's STORE_OUT_MOD mutation which
changes the data value before writing to memory.

When Arguzz mutates a store value:
1. The source register value is loaded (ctx.load_register for rs2)
2. For partial stores (Sb, Sh), the current memory value is read and modified
3. Arguzz changes the data value to a MUTATED value before ctx.store_memory()
4. The MUTATED value is written to memory

A4's STORE_OUT_MOD directly mutates the WRITE transaction's word field to match
the effect of Arguzz's mutation, testing the circuit's memory consistency checks.

Key Difference from LOAD_VAL_MOD/COMP_OUT_MOD:
- LOAD_VAL_MOD/COMP_OUT_MOD write to REGISTERS
- STORE_OUT_MOD writes to MEMORY (not in register address range)

Store instructions affected:
- Sw (store word)
- Sh (store halfword)
- Sb (store byte)

Transaction Structure for Store Instructions:
1. Instruction fetch (READ) - addr = PC/4
2. Load rs1 (READ) - base address register
3. Load rs2 (READ) - value register to store
4. Load current memory (READ) - for partial stores
5. Store to memory (WRITE) - memory address ← STORE_OUT_MOD target
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


@dataclass
class StoreOutModTarget:
    """The target location in A4 for a STORE_OUT_MOD mutation"""
    cycle_idx: int          # Index into trace.cycles[]
    step: int               # user_cycle value (A4 step)
    pc: int                 # PC value (next PC)
    major: int              # Instruction major category
    minor: int              # Instruction minor category
    write_txn_idx: int      # Index of the WRITE transaction in trace.txns[]
    write_addr: int         # Memory word address
    memory_byte_addr: int   # Memory byte address (write_addr * 4)
    original_value: int     # Original data value (from Arguzz fault)
    mutated_value: int      # Mutated data value (from Arguzz fault)


def find_write_transaction(txns: List[A4Txn], step_txns: A4StepTxns) -> Optional[A4Txn]:
    """
    Find the WRITE transaction to MEMORY within a step's transaction range.
    
    For store instructions, there should be exactly one WRITE transaction
    which writes the data to memory (not to a register).
    
    Args:
        txns: List of parsed transactions
        step_txns: Transaction range info for the target step
        
    Returns:
        The WRITE transaction to memory, or None if not found
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
    
    # For store instructions, we want the WRITE to MEMORY (not register)
    memory_writes = [t for t in write_txns if not t.is_register()]
    
    if not memory_writes:
        print(f"ERROR: No WRITE to memory found in step {step_txns.step}")
        print(f"  Found {len(write_txns)} WRITE transactions, but all to registers")
        for t in write_txns:
            reg_idx = t.register_index()
            print(f"    txn_idx={t.txn_idx}, addr={t.addr}, reg_idx={reg_idx}")
        return None
    
    if len(memory_writes) > 1:
        print(f"WARNING: Multiple memory WRITE transactions found, using last one")
    
    return memory_writes[-1]


def find_mutation_target(
    arguzz_fault: ArguzzFault,
    a4_cycles: List[A4CycleInfo],
    step_txns_list: List[A4StepTxns],
    txns: List[A4Txn],
    a4_step: int = None
) -> Optional[StoreOutModTarget]:
    """
    Find the A4 mutation target for a STORE_OUT_MOD Arguzz fault.
    
    Algorithm:
    1. Use provided a4_step or find it using PC matching
    2. Get the transaction range for that step
    3. Find the WRITE transaction to MEMORY within that range
    4. Return the target with all necessary info
    
    Args:
        arguzz_fault: The parsed Arguzz STORE_OUT_MOD fault
        a4_cycles: All A4 cycles from inspection
        step_txns_list: Transaction range info (from A4_DUMP_STEP)
        txns: Individual transactions (from A4_DUMP_STEP)
        a4_step: Pre-computed A4 step (from run_full_inspection with offset).
                 If None, will be computed using heuristic (may be wrong in tight loops).
        
    Returns:
        StoreOutModTarget if found, None otherwise
    """
    # Step 1: Use provided a4_step or find it
    if a4_step is None:
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
    
    # Step 3: Find the WRITE transaction to memory
    write_txn = find_write_transaction(txns, step_txns)
    if not write_txn:
        return None
    
    return StoreOutModTarget(
        cycle_idx=matching_cycle.cycle_idx,
        step=a4_step,
        pc=matching_cycle.pc,
        major=matching_cycle.major,
        minor=matching_cycle.minor,
        write_txn_idx=write_txn.txn_idx,
        write_addr=write_txn.addr,
        memory_byte_addr=write_txn.addr * 4,
        original_value=arguzz_fault.original_value,
        mutated_value=arguzz_fault.mutated_value,
    )


def create_config(target: StoreOutModTarget, output_path: Path) -> Path:
    """Create an A4 mutation config file for STORE_OUT_MOD"""
    config = {
        "mutation_type": "STORE_OUT_MOD",
        "step": target.step,
        "txn_idx": target.write_txn_idx,
        "word": target.mutated_value,
        # Additional info for debugging (not used by mutation)
        "_info": {
            "memory_addr": f"0x{target.memory_byte_addr:08x}",
            "original_value": target.original_value,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def run_full_inspection(
    host_binary: str,
    host_args: List[str],
    arguzz_fault: ArguzzFault,
    offset: int = None
) -> Tuple[List[A4CycleInfo], List[A4StepTxns], List[A4Txn], int]:
    """
    Run A4 inspection to get cycles and step-specific transactions.
    
    This performs two inspections:
    1. Full inspection to get all cycles and find the A4 step
    2. Step-specific inspection to get transaction details
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        arguzz_fault: The Arguzz fault info
        offset: Pre-computed offset (arguzz_step - preflight_step) for accurate
                step mapping in tight loops. If None, uses heuristic.
    
    Returns:
        (cycles, step_txns, txns, a4_step)
    """
    # First, run full inspection to get all cycles
    output1, cycles, _, _ = run_a4_inspection_with_step(host_binary, host_args, 0)
    
    # Find the A4 step
    a4_step = find_a4_step_for_arguzz_step(arguzz_fault.step, arguzz_fault.pc, cycles, offset)
    
    # Now run inspection with the specific step to get transactions
    output2, _, step_txns, txns = run_a4_inspection_with_step(host_binary, host_args, a4_step)
    
    return cycles, step_txns, txns, a4_step
