"""
PRE_EXEC_REG_MOD Mutation (Arguzz-Dependent)

This mutation targets register transactions in the PreflightTrace,
corresponding to Arguzz's PRE_EXEC_REG_MOD which writes a random value
to a random register BEFORE instruction execution.

A4 supports TWO strategies:

Strategy "next_read" (Option 1 - Default):
1. Parse Arguzz fault to get target register (e.g., "s3") and value (e.g., 1)
2. Find the A4 step corresponding to the Arguzz injection step
3. Search FORWARD to find the NEXT READ transaction of that specific register
   DURING AN INSTRUCTION CYCLE (major 0-6 only)
4. Modify that READ's 'word' field to the corrupted value
5. Keep 'prev_word' unchanged to create word ≠ prev_word inconsistency
Effect: Triggers BOTH IsRead (direct) AND MemoryWrite (cascade) failures

IMPORTANT: The next_read strategy ONLY targets transactions during instruction
execution cycles (major 0-6). Transactions during special operations like
Poseidon (major 9-10), SHA (major 11), BigInt (major 12), or Control (major 7-8)
are SKIPPED because these cycles don't check IsRead constraints.

Strategy "prev_write" (Option 2):
1. Parse Arguzz fault to get target register (e.g., "s3") and value (e.g., 1)
2. Find the A4 step corresponding to the Arguzz injection step
3. Search BACKWARD to find the PREVIOUS WRITE to that specific register
4. Modify that WRITE's 'word' field to the corrupted value
5. The next READ's prev_word won't match the modified WRITE's word
Effect: Triggers ONLY MemoryWrite failures (no IsRead at a WRITE)

NOTE: prev_write strategy always finds instruction-cycle targets because
register WRITEs only happen during instruction execution (ADD, LW, etc.).

OPTIMIZATION: Uses A4_DUMP_REG_TXNS to dump all register transactions
in a single pass, then searches in Python. This reduces the number of
host invocations from ~200 to just 2.

Major Value Reference (from platform.rs):
  major 0 (MISC0):  Compute (Add, Sub, Xor, Or, And, Slt, SltU, AddI)
  major 1 (MISC1):  Immediate (XorI, OrI, AndI, SltI, SltIU, Beq, Bne, Blt)
  major 2 (MISC2):  Branch/Jump (Bge, BltU, BgeU, Jal, JalR, Lui, Auipc)
  major 3 (MUL0):   Multiply/Shift (Sll, SllI, Mul, MulH, MulHSU, MulHU)
  major 4 (DIV0):   Divide/Shift (Srl, Sra, SrlI, SraI, Div, DivU, Rem, RemU)
  major 5 (MEM0):   Load (Lb, Lh, Lw, LbU, LhU)
  major 6 (MEM1):   Store (Sb, Sh, Sw)
  ---- Below are NON-INSTRUCTION cycles (IsRead NOT checked) ----
  major 7 (CONTROL0):  Control/padding
  major 8 (ECALL0):    Ecall operations
  major 9 (POSEIDON0): Poseidon hash
  major 10 (POSEIDON1): Poseidon hash
  major 11 (SHA0):     SHA operations
  major 12 (BIGINT0):  BigInt operations
"""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from a4.core.trace_parser import (
    A4CycleInfo, A4RegTxn,
    parse_all_a4_cycles, parse_all_reg_txns
)
from a4.arguzz_dependent.arguzz_parser import ArguzzFault
from a4.arguzz_dependent.step_mapper import find_a4_step_for_arguzz_step


# Register name to index mapping
REGISTER_NAMES = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'
]

# Also handle fp alias for s0
REGISTER_ALIASES = {
    'fp': 8,  # fp is alias for s0
    's0/fp': 8,
}

# USER_REGS word address base
USER_REGS_BASE = 1073725472  # 0xFFFF0080 / 4

# Maximum major value for instruction cycles (from platform.rs)
# major 0-6: Instruction execution (MISC0, MISC1, MISC2, MUL0, DIV0, MEM0, MEM1)
# major 7+: Non-instruction cycles (CONTROL0, ECALL0, POSEIDON0, POSEIDON1, SHA0, BIGINT0)
MAX_INSTRUCTION_MAJOR = 6


def register_name_to_index(name: str) -> Optional[int]:
    """Convert register name to index (0-31)"""
    name_lower = name.lower()
    
    # Check aliases first
    if name_lower in REGISTER_ALIASES:
        return REGISTER_ALIASES[name_lower]
    
    # Check standard names
    try:
        return REGISTER_NAMES.index(name_lower)
    except ValueError:
        pass
    
    # Try x<N> format
    if name_lower.startswith('x') and name_lower[1:].isdigit():
        idx = int(name_lower[1:])
        if 0 <= idx < 32:
            return idx
    
    return None


def register_index_to_name(idx: int) -> str:
    """Convert register index to name"""
    if 0 <= idx < 32:
        return REGISTER_NAMES[idx]
    return f"x{idx}"


def register_word_addr(reg_idx: int) -> int:
    """Get the word address for a register"""
    return USER_REGS_BASE + reg_idx


@dataclass
class PreExecRegModTarget:
    """The target location in A4 for a PRE_EXEC_REG_MOD mutation"""
    # Injection point info (where Arguzz injected)
    injection_step: int             # A4 step where injection occurred
    injection_cycle_idx: int        # cycle_idx at injection
    injection_pc: int               # PC at injection
    
    # Target transaction info (where we mutate)
    target_step: int                # A4 step where we found the target txn
    target_cycle_idx: int           # cycle_idx of target
    target_pc: int                  # PC of target instruction
    target_major: int               # major category
    target_minor: int               # minor category
    
    # Transaction details
    target_txn_idx: int             # Index of the target transaction
    target_addr: int                # Word address of the register
    
    # Register info
    register_idx: int               # Register index (0-31)
    register_name: str              # Register name (e.g., "s3")
    
    # Values
    original_word: int              # Original word value in transaction
    mutated_word: int               # Mutated word value (from Arguzz)
    prev_word: int                  # prev_word (unchanged, creates inconsistency)
    
    # Strategy info
    strategy: str                   # "next_read" or "prev_write"
    is_write_target: bool           # True for prev_write, False for next_read
    
    # Backwards compatibility aliases
    @property
    def read_txn_idx(self) -> int:
        return self.target_txn_idx
    
    @property
    def read_addr(self) -> int:
        return self.target_addr


def find_next_read_of_register_fast(
    reg_txns: List[A4RegTxn],
    injection_a4_step: int,
    target_reg_idx: int,
    step_to_cycle: dict = None,
) -> Tuple[Optional[A4RegTxn], str]:
    """
    Find the next READ transaction of a specific register after the injection step,
    ONLY during instruction cycles (major 0-6).
    
    FAST VERSION: Uses pre-collected register transactions with step info,
    avoiding the need to map txn_idx to cycles.
    
    IMPORTANT: Only targets transactions during instruction execution cycles
    (major 0-6). Transactions during special operations like Poseidon (major 9-10),
    SHA (major 11), BigInt (major 12), or Control (major 7-8) are SKIPPED because
    these cycles don't check IsRead constraints.
    
    Args:
        reg_txns: All register transactions from A4_DUMP_REG_TXNS
        injection_a4_step: The A4 step where injection occurred
        target_reg_idx: Register index to search for (0-31)
        step_to_cycle: Mapping from step -> A4CycleInfo for filtering by major
    
    Returns:
        Tuple of (A4RegTxn, skip_reason) where:
        - (txn, "") if found valid target
        - (None, reason) if no valid target, with reason explaining why
    """
    target_addr = register_word_addr(target_reg_idx)
    
    # Sort by txn_idx to ensure we find the FIRST read after injection
    sorted_txns = sorted(reg_txns, key=lambda t: t.txn_idx)
    
    found_non_instruction_read = False
    non_instruction_step = None
    non_instruction_major = None
    
    for txn in sorted_txns:
        # Skip if BEFORE injection step
        # Note: Use < not <= because Arguzz injects BEFORE the instruction executes,
        # so a READ at the injection step IS the first affected read
        if txn.step < injection_a4_step:
            continue
        
        # Check if this is a READ of our target register
        if not txn.is_read() or txn.addr != target_addr:
            continue
        
        # Found a READ - check if it's during an instruction cycle
        if step_to_cycle is not None:
            cycle_info = step_to_cycle.get(txn.step)
            if cycle_info is not None:
                if cycle_info.major > MAX_INSTRUCTION_MAJOR:
                    # This READ is during a non-instruction cycle (Poseidon, SHA, etc.)
                    # Record it but keep searching for an instruction-cycle READ
                    if not found_non_instruction_read:
                        found_non_instruction_read = True
                        non_instruction_step = txn.step
                        non_instruction_major = cycle_info.major
                    continue
        
        # Valid instruction-cycle READ found
        return txn, ""
    
    # No valid instruction-cycle READ found - determine why
    if found_non_instruction_read:
        major_names = {
            7: "CONTROL0", 8: "ECALL0", 9: "POSEIDON0", 
            10: "POSEIDON1", 11: "SHA0", 12: "BIGINT0"
        }
        major_name = major_names.get(non_instruction_major, f"major={non_instruction_major}")
        return None, f"register READ found at step {non_instruction_step} but it's during {major_name} (non-instruction cycle); IsRead constraints not checked during special operations"
    else:
        return None, "register not read during any instruction execution after injection point"


def find_prev_write_to_register_fast(
    reg_txns: List[A4RegTxn],
    injection_a4_step: int,
    target_reg_idx: int
) -> Optional[A4RegTxn]:
    """
    Find the previous WRITE transaction to a specific register BEFORE the injection step.
    
    This is Option 2 (prev_write strategy): modify the source value so subsequent
    reads see inconsistency when their prev_word doesn't match the modified WRITE's word.
    
    FAST VERSION: Uses pre-collected register transactions with step info.
    
    Args:
        reg_txns: All register transactions from A4_DUMP_REG_TXNS
        injection_a4_step: The A4 step where injection occurred
        target_reg_idx: Register index to search for (0-31)
    
    Returns:
        A4RegTxn if found, None otherwise
    """
    target_addr = register_word_addr(target_reg_idx)
    
    # Sort by txn_idx DESCENDING to find the LAST write before injection
    sorted_txns = sorted(reg_txns, key=lambda t: t.txn_idx, reverse=True)
    
    for txn in sorted_txns:
        # Skip if not BEFORE injection step
        if txn.step >= injection_a4_step:
            continue
        
        # Check if this is a WRITE to our target register
        if txn.is_write() and txn.addr == target_addr:
            return txn
    
    return None


def find_mutation_target(
    arguzz_fault: ArguzzFault,
    a4_cycles: List[A4CycleInfo],
    reg_txns: List[A4RegTxn],
    strategy: str = "next_read",
) -> Tuple[Optional[PreExecRegModTarget], str]:
    """
    Find the A4 mutation target for a PRE_EXEC_REG_MOD Arguzz fault.
    
    Strategies:
    - "next_read" (Option 1): Find next READ of corrupted register, modify word
      Effect: Triggers BOTH IsRead (direct) AND MemoryWrite (cascade) failures
      NOTE: Only targets instruction cycles (major 0-6); skips Poseidon/SHA/etc.
    - "prev_write" (Option 2): Find prev WRITE to corrupted register, modify word
      Effect: Triggers ONLY MemoryWrite failures (no IsRead at a WRITE)
    
    Args:
        arguzz_fault: The parsed Arguzz PRE_EXEC_REG_MOD fault
        a4_cycles: All A4 cycles from inspection
        reg_txns: All register transactions from A4_DUMP_REG_TXNS
        strategy: "next_read" or "prev_write"
        
    Returns:
        Tuple of (PreExecRegModTarget, skip_reason) where:
        - (target, "") if found valid target
        - (None, reason) if no valid target, with reason explaining why
    """
    # Validate strategy
    if strategy not in ("next_read", "prev_write"):
        return None, f"unknown strategy: {strategy}"
    
    # Step 1: Get target register
    if not arguzz_fault.target_register:
        return None, "no target register in fault"
    
    target_reg_idx = register_name_to_index(arguzz_fault.target_register)
    if target_reg_idx is None:
        return None, f"unknown register name: {arguzz_fault.target_register}"
    
    print(f"  Target register: {arguzz_fault.target_register} (x{target_reg_idx})")
    print(f"  Corrupted value: {arguzz_fault.mutated_value}")
    print(f"  Strategy: {strategy}")
    
    # Step 2: Find A4 step for injection point
    try:
        injection_a4_step = find_a4_step_for_arguzz_step(
            arguzz_fault.step, arguzz_fault.pc, a4_cycles
        )
    except ValueError as e:
        return None, str(e)
    
    # Find cycle info at injection point
    injection_cycle = next((c for c in a4_cycles if c.step == injection_a4_step), None)
    if not injection_cycle:
        return None, f"could not find cycle info for injection step {injection_a4_step}"
    
    print(f"  Injection A4 step: {injection_a4_step} (cycle_idx: {injection_cycle.cycle_idx})")
    
    # Build step -> cycle mapping for major filtering (used by next_read strategy)
    step_to_cycle = {c.step: c for c in a4_cycles}
    
    # Step 3: Find target transaction based on strategy
    if strategy == "next_read":
        target_txn, skip_reason = find_next_read_of_register_fast(
            reg_txns, injection_a4_step, target_reg_idx, step_to_cycle
        )
        is_write_target = False
        txn_type_desc = "READ"
        search_dir = "after"
    else:  # prev_write
        target_txn = find_prev_write_to_register_fast(reg_txns, injection_a4_step, target_reg_idx)
        skip_reason = "" if target_txn else "register not written before injection point"
        is_write_target = True
        txn_type_desc = "WRITE"
        search_dir = "before"
    
    if not target_txn:
        print(f"  No valid {txn_type_desc} found: {skip_reason}")
        return None, skip_reason
    
    # Find the cycle info for the target step
    target_cycle = step_to_cycle.get(target_txn.step)
    if not target_cycle:
        # Fallback - create minimal cycle info from what we have
        print(f"  Warning: Could not find cycle info for step {target_txn.step}, using partial info")
        target_cycle_idx = 0
        target_pc = 0
        target_major = 0
        target_minor = 0
    else:
        target_cycle_idx = target_cycle.cycle_idx
        target_pc = target_cycle.pc
        target_major = target_cycle.major
        target_minor = target_cycle.minor
    
    print(f"  Found {txn_type_desc} at step {target_txn.step} (cycle_idx: {target_cycle_idx}, major: {target_major})")
    print(f"  Transaction: txn_idx={target_txn.txn_idx}, word={target_txn.word}, prev_word={target_txn.prev_word}")
    
    target = PreExecRegModTarget(
        # Injection point
        injection_step=injection_a4_step,
        injection_cycle_idx=injection_cycle.cycle_idx,
        injection_pc=injection_cycle.pc,
        
        # Target
        target_step=target_txn.step,
        target_cycle_idx=target_cycle_idx,
        target_pc=target_pc,
        target_major=target_major,
        target_minor=target_minor,
        
        # Transaction
        target_txn_idx=target_txn.txn_idx,
        target_addr=target_txn.addr,
        
        # Register
        register_idx=target_reg_idx,
        register_name=arguzz_fault.target_register,
        
        # Values
        original_word=target_txn.word,
        mutated_word=arguzz_fault.mutated_value,
        prev_word=target_txn.prev_word,
        
        # Strategy
        strategy=strategy,
        is_write_target=is_write_target,
    )
    
    return target, ""  # Empty skip_reason means success


def create_config(target: PreExecRegModTarget, output_path: Path) -> Path:
    """Create an A4 mutation config file for PRE_EXEC_REG_MOD"""
    
    # Strategy-specific notes
    if target.strategy == "next_read":
        note = "Modifies next READ of corrupted register to create word != prev_word (triggers IsRead + MemoryWrite)"
    else:  # prev_write
        note = "Modifies prev WRITE to corrupted register; next READ's prev_word won't match (triggers MemoryWrite only)"
    
    config = {
        "mutation_type": "PRE_EXEC_REG_MOD",
        "step": target.target_step,  # Step where we mutate (not injection step!)
        "txn_idx": target.target_txn_idx,
        "word": target.mutated_word,
        "strategy": target.strategy,  # "next_read" or "prev_write"
        # Additional info for debugging
        "_info": {
            "injection_step": target.injection_step,
            "target_step": target.target_step,
            "register": target.register_name,
            "register_idx": target.register_idx,
            "original_word": target.original_word,
            "prev_word": target.prev_word,
            "is_write_target": target.is_write_target,
            "note": note,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path


def run_full_inspection(
    host_binary: str,
    host_args: List[str],
    arguzz_fault: ArguzzFault,
    offset: int = None
) -> Tuple[List[A4CycleInfo], List[A4RegTxn], int]:
    """
    Run A4 inspection to get all cycles and register transactions.
    
    OPTIMIZED VERSION (Option 2): Uses A4_DUMP_REG_TXNS to dump all register
    transactions in a SINGLE pass. This reduces invocations from ~200 to 2.
    
    Args:
        host_binary: Path to risc0-host binary
        host_args: Arguments for risc0-host
        arguzz_fault: The Arguzz fault info
        offset: Pre-computed offset (arguzz_step - preflight_step) for accurate
                step mapping in tight loops. If None, uses heuristic.
    
    Returns:
        (cycles, reg_txns, injection_a4_step)
    """
    # Single invocation with A4_INSPECT=1 and A4_DUMP_REG_TXNS=1
    print(f"  Running single-pass inspection with A4_DUMP_REG_TXNS...")
    
    env = os.environ.copy()
    env["A4_INSPECT"] = "1"
    env["A4_DUMP_REG_TXNS"] = "1"
    
    cmd = [host_binary] + host_args
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    output = result.stdout + result.stderr
    
    # Parse cycles and register transactions
    cycles = parse_all_a4_cycles(output)
    reg_txns = parse_all_reg_txns(output)
    
    print(f"  Parsed {len(cycles)} cycles, {len(reg_txns)} register transactions")
    
    # Find the injection A4 step
    injection_a4_step = find_a4_step_for_arguzz_step(arguzz_fault.step, arguzz_fault.pc, cycles, offset)
    
    return cycles, reg_txns, injection_a4_step
