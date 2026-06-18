"""
Inspection Data Container

Holds all pre-fetched inspection data from a single guest program run.
This allows running inspection once and reusing the data for many mutations.

Uses A4_DUMP_ALL_TXNS to collect ALL transactions (memory + registers) in one
pass, enabling fast lookup for all mutation types.
"""

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from a4.core.trace_parser import (
    A4CycleInfo, A4AllTxn, A4RegTxn,
    parse_all_a4_cycles, parse_all_all_txns
)


@dataclass
class InspectionData:
    """
    Container for all inspection data from a guest program execution.
    
    This is collected once at the start of a fuzzing campaign and reused
    for all mutations, avoiding repeated expensive inspection runs.
    
    Uses A4_DUMP_ALL_TXNS for efficient access to both register and memory
    transactions, indexed by step.
    """
    
    # Core data
    cycles: List[A4CycleInfo] = field(default_factory=list)
    all_txns: List[A4AllTxn] = field(default_factory=list)  # Unified transactions
    
    # Legacy: keep reg_txns for backward compatibility
    reg_txns: List[A4RegTxn] = field(default_factory=list)
    
    # Computed indices for fast lookup
    _step_to_cycle: Dict[int, A4CycleInfo] = field(default_factory=dict, repr=False)
    _step_to_all_txns: Dict[int, List[A4AllTxn]] = field(default_factory=dict, repr=False)
    _step_to_reg_txns: Dict[int, List[A4AllTxn]] = field(default_factory=dict, repr=False)
    _step_to_mem_txns: Dict[int, List[A4AllTxn]] = field(default_factory=dict, repr=False)
    
    # Metadata
    host_binary: str = ""
    host_args: List[str] = field(default_factory=list)
    total_steps: int = 0
    
    def __post_init__(self):
        """Build indices after initialization"""
        self._build_indices()
    
    def _build_indices(self):
        """Build lookup indices for fast access"""
        # Step -> Cycle mapping
        self._step_to_cycle = {c.step: c for c in self.cycles}
        
        # Step -> AllTxns mapping (unified)
        self._step_to_all_txns = {}
        self._step_to_reg_txns = {}
        self._step_to_mem_txns = {}
        
        for txn in self.all_txns:
            # All transactions
            if txn.step not in self._step_to_all_txns:
                self._step_to_all_txns[txn.step] = []
            self._step_to_all_txns[txn.step].append(txn)
            
            # Register transactions
            if txn.is_register():
                if txn.step not in self._step_to_reg_txns:
                    self._step_to_reg_txns[txn.step] = []
                self._step_to_reg_txns[txn.step].append(txn)
            
            # Memory transactions
            if txn.is_memory():
                if txn.step not in self._step_to_mem_txns:
                    self._step_to_mem_txns[txn.step] = []
                self._step_to_mem_txns[txn.step].append(txn)
        
        # Total steps
        if self.cycles:
            self.total_steps = max(c.step for c in self.cycles) + 1
    
    @classmethod
    def from_inspection(cls, host_binary: str, host_args: List[str]) -> 'InspectionData':
        """
        Run inspection and create populated InspectionData.
        
        This runs the guest program once with A4_INSPECT=1 and A4_DUMP_ALL_TXNS=1
        to collect all cycles and transactions (both memory and registers).
        
        Args:
            host_binary: Path to risc0-host binary
            host_args: Arguments for risc0-host
            
        Returns:
            Populated InspectionData instance
        """
        env = os.environ.copy()
        env["A4_INSPECT"] = "1"
        env["A4_DUMP_ALL_TXNS"] = "1"
        
        cmd = [host_binary] + host_args
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        output = result.stdout + result.stderr
        
        cycles = parse_all_a4_cycles(output)
        all_txns = parse_all_all_txns(output)
        
        return cls(
            cycles=cycles,
            all_txns=all_txns,
            host_binary=host_binary,
            host_args=host_args,
        )
    
    def get_cycle(self, step: int) -> Optional[A4CycleInfo]:
        """Get cycle info for a specific step"""
        return self._step_to_cycle.get(step)
    
    def get_all_txns_at_step(self, step: int) -> List[A4AllTxn]:
        """Get all transactions (memory + registers) at a specific step"""
        return self._step_to_all_txns.get(step, [])
    
    def get_reg_txns_at_step(self, step: int) -> List[A4AllTxn]:
        """
        Get all register transactions at a specific step.
        
        Returns A4AllTxn objects (unified format) filtered to registers only.
        O(1) lookup from pre-indexed data.
        """
        return self._step_to_reg_txns.get(step, [])
    
    def get_mem_txns_at_step(self, step: int) -> List[A4AllTxn]:
        """
        Get all memory transactions at a specific step.
        
        Returns A4AllTxn objects (unified format) filtered to memory only.
        O(1) lookup from pre-indexed data.
        """
        return self._step_to_mem_txns.get(step, [])
    
    def get_valid_steps_for_kind(self, kind: str) -> List[int]:
        """
        Get list of unique steps where a specific mutation kind can be applied.
        
        Args:
            kind: Mutation kind (COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, 
                  PRE_EXEC_REG_MOD, INSTR_TYPE_MOD, MEM_VAL_MOD, INSTR_WORD_MOD)
        
        Returns:
            Sorted list of unique valid step numbers
            
        Note on Deduplication:
        ----------------------
        Each "step" can have multiple "cycles" (micro-operations). For example:
        - Step 0 may have ~18,000 cycles (POSEIDON, ECALL operations)
        - A normal instruction step has 1 cycle
        
        Previous implementation appended cycle.step for each matching cycle,
        causing steps with many cycles to be massively over-represented.
        
        This implementation uses a set to ensure each step appears at most once,
        providing unbiased selection when combined with ZonedStepSelector.
        """
        valid_steps = set()  # Use set for automatic deduplication
        
        for cycle in self.cycles:
            # Filter by instruction type based on mutation kind
            if kind == "COMP_OUT_MOD":
                # Compute instructions: major 0-4 (MISC0, MISC1, MISC2, MUL0, DIV0)
                if cycle.major in (0, 1, 2, 3, 4):
                    valid_steps.add(cycle.step)
            
            elif kind == "LOAD_VAL_MOD":
                # Load instructions: major 5 (MEM0)
                if cycle.major == 5:
                    valid_steps.add(cycle.step)
            
            elif kind == "STORE_OUT_MOD":
                # Store instructions: major 6 (MEM1)
                if cycle.major == 6:
                    valid_steps.add(cycle.step)
            
            elif kind == "PRE_EXEC_REG_MOD":
                # Any instruction cycle: major 0-6
                if cycle.major <= 6:
                    valid_steps.add(cycle.step)
            
            elif kind == "INSTR_TYPE_MOD":
                # Any instruction cycle: major 0-6
                if cycle.major <= 6:
                    valid_steps.add(cycle.step)
            
            elif kind == "MEM_VAL_MOD":
                # MEM_VAL_MOD targets memory transactions, not registers
                # Valid for any step with memory transactions
                # Most common: load (major 5) and store (major 6), but also
                # ECALLs (major 7+) can have memory transactions
                if cycle.step in self._step_to_mem_txns:
                    valid_steps.add(cycle.step)
            
            elif kind in ("INSTR_WORD_MOD", "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR"):
                # Instruction word mutation: any instruction or ECALL cycle
                # Targets the instruction fetch transaction
                # Both FULL (entire word) and SUR (surgical field) use same targets
                if cycle.major <= 6 or cycle.major == 8:
                    valid_steps.add(cycle.step)

            elif kind == "TXN_PREV_WORD_MOD":
                # Any non-bootstrap step with at least one txn
                if cycle.step != 0 and cycle.step in self._step_to_all_txns:
                    valid_steps.add(cycle.step)
        
        # Return sorted list for deterministic ordering
        return sorted(valid_steps)
    
    def summary(self) -> str:
        """Get a summary string of the inspection data"""
        # Count by major category
        major_counts = {}
        for cycle in self.cycles:
            major_counts[cycle.major] = major_counts.get(cycle.major, 0) + 1
        
        major_names = {
            0: "MISC0", 1: "MISC1", 2: "MISC2", 3: "MUL0", 4: "DIV0",
            5: "MEM0 (load)", 6: "MEM1 (store)", 7: "CONTROL0", 8: "ECALL0",
            9: "POSEIDON0", 10: "POSEIDON1", 11: "SHA0", 12: "BIGINT0"
        }
        
        # Count register vs memory transactions
        reg_count = sum(1 for t in self.all_txns if t.is_register())
        mem_count = sum(1 for t in self.all_txns if t.is_memory())
        
        lines = [
            f"Inspection Data Summary:",
            f"  Total cycles: {len(self.cycles)}",
            f"  Total steps: {self.total_steps}",
            f"  Total transactions: {len(self.all_txns)}",
            f"    - Register transactions: {reg_count}",
            f"    - Memory transactions: {mem_count}",
            f"  Cycles by major category:",
        ]
        
        for major in sorted(major_counts.keys()):
            name = major_names.get(major, f"major={major}")
            lines.append(f"    {name}: {major_counts[major]}")
        
        return "\n".join(lines)
