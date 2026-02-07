"""
Inspection Data Container

Holds all pre-fetched inspection data from a single guest program run.
This allows running inspection once and reusing the data for many mutations.
"""

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from a4.core.trace_parser import (
    A4CycleInfo, A4StepTxns, A4Txn, A4RegTxn,
    parse_all_a4_cycles, parse_all_step_txns, parse_all_txns, parse_all_reg_txns
)


@dataclass
class InspectionData:
    """
    Container for all inspection data from a guest program execution.
    
    This is collected once at the start of a fuzzing campaign and reused
    for all mutations, avoiding repeated expensive inspection runs.
    """
    
    # Core data
    cycles: List[A4CycleInfo] = field(default_factory=list)
    reg_txns: List[A4RegTxn] = field(default_factory=list)
    
    # Computed indices for fast lookup
    _step_to_cycle: Dict[int, A4CycleInfo] = field(default_factory=dict, repr=False)
    _step_to_reg_txns: Dict[int, List[A4RegTxn]] = field(default_factory=dict, repr=False)
    
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
        
        # Step -> RegTxns mapping
        self._step_to_reg_txns = {}
        for txn in self.reg_txns:
            if txn.step not in self._step_to_reg_txns:
                self._step_to_reg_txns[txn.step] = []
            self._step_to_reg_txns[txn.step].append(txn)
        
        # Total steps
        if self.cycles:
            self.total_steps = max(c.step for c in self.cycles) + 1
    
    @classmethod
    def from_inspection(cls, host_binary: str, host_args: List[str]) -> 'InspectionData':
        """
        Run inspection and create populated InspectionData.
        
        This runs the guest program once with A4_INSPECT=1 and A4_DUMP_REG_TXNS=1
        to collect all cycles and register transactions.
        
        Args:
            host_binary: Path to risc0-host binary
            host_args: Arguments for risc0-host
            
        Returns:
            Populated InspectionData instance
        """
        env = os.environ.copy()
        env["A4_INSPECT"] = "1"
        env["A4_DUMP_REG_TXNS"] = "1"
        
        cmd = [host_binary] + host_args
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        output = result.stdout + result.stderr
        
        cycles = parse_all_a4_cycles(output)
        reg_txns = parse_all_reg_txns(output)
        
        return cls(
            cycles=cycles,
            reg_txns=reg_txns,
            host_binary=host_binary,
            host_args=host_args,
        )
    
    def get_cycle(self, step: int) -> Optional[A4CycleInfo]:
        """Get cycle info for a specific step"""
        return self._step_to_cycle.get(step)
    
    def get_reg_txns_at_step(self, step: int) -> List[A4RegTxn]:
        """Get all register transactions at a specific step"""
        return self._step_to_reg_txns.get(step, [])
    
    def get_txns_for_step(self, step: int) -> List[A4Txn]:
        """
        Get detailed transactions for a specific step.
        
        NOTE: This requires a separate inspection run with A4_DUMP_STEP.
        For performance in fuzzing, prefer using reg_txns which are
        pre-collected.
        """
        env = os.environ.copy()
        env["A4_INSPECT"] = "1"
        env["A4_DUMP_STEP"] = str(step)
        
        cmd = [self.host_binary] + self.host_args
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        output = result.stdout + result.stderr
        
        step_txns_list = parse_all_step_txns(output)
        txns = parse_all_txns(output)
        
        # Find the step_txns entry for this step
        step_txns = next((st for st in step_txns_list if st.step == step), None)
        if not step_txns:
            return []
        
        # Filter to transactions in this step's range
        return [t for t in txns if step_txns.txn_start <= t.txn_idx < step_txns.txn_end]
    
    def get_valid_steps_for_kind(self, kind: str) -> List[int]:
        """
        Get list of steps where a specific mutation kind can be applied.
        
        Args:
            kind: Mutation kind (COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, 
                  PRE_EXEC_REG_MOD, INSTR_TYPE_MOD)
        
        Returns:
            List of valid step numbers
        """
        valid_steps = []
        
        for cycle in self.cycles:
            # Filter by instruction type based on mutation kind
            if kind == "COMP_OUT_MOD":
                # Compute instructions: major 0-4 (MISC0, MISC1, MISC2, MUL0, DIV0)
                if cycle.major in (0, 1, 2, 3, 4):
                    valid_steps.append(cycle.step)
            
            elif kind == "LOAD_VAL_MOD":
                # Load instructions: major 5 (MEM0)
                if cycle.major == 5:
                    valid_steps.append(cycle.step)
            
            elif kind == "STORE_OUT_MOD":
                # Store instructions: major 6 (MEM1)
                if cycle.major == 6:
                    valid_steps.append(cycle.step)
            
            elif kind == "PRE_EXEC_REG_MOD":
                # Any instruction cycle: major 0-6
                if cycle.major <= 6:
                    valid_steps.append(cycle.step)
            
            elif kind == "INSTR_TYPE_MOD":
                # Any instruction cycle: major 0-6
                if cycle.major <= 6:
                    valid_steps.append(cycle.step)
        
        return valid_steps
    
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
        
        lines = [
            f"Inspection Data Summary:",
            f"  Total cycles: {len(self.cycles)}",
            f"  Total steps: {self.total_steps}",
            f"  Register transactions: {len(self.reg_txns)}",
            f"  Cycles by major category:",
        ]
        
        for major in sorted(major_counts.keys()):
            name = major_names.get(major, f"major={major}")
            lines.append(f"    {name}: {major_counts[major]}")
        
        return "\n".join(lines)
