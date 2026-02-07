"""
A4 Trace Parsing

Parses A4-specific trace output formats:
- <a4_cycle_info> - A4 preflight cycle data
- <a4_step_txns> - Transaction range for a step
- <a4_txn> - Individual transaction
- <a4_reg_txn> - Register transaction with step info
- <a4_instr_type_mod> - Instruction type modification info

Note: Arguzz-specific parsing (ArguzzFault, ArguzzTrace) is in
arguzz_dependent/arguzz_parser.py
"""

import json
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class A4CycleInfo:
    """Parsed A4 <a4_cycle_info> output"""
    cycle_idx: int
    step: int       # user_cycle
    pc: int         # Next PC (after instruction)
    txn_idx: int
    major: int
    minor: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4CycleInfo']:
        """Parse an <a4_cycle_info> line from A4 output"""
        match = re.search(r'<a4_cycle_info>({.*?})</a4_cycle_info>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                cycle_idx=data['cycle_idx'],
                step=data['step'],
                pc=data['pc'],
                txn_idx=data['txn_idx'],
                major=data['major'],
                minor=data['minor'],
            )
        except (json.JSONDecodeError, KeyError):
            return None


@dataclass
class A4StepTxns:
    """Parsed A4 <a4_step_txns> output - transaction range for a step"""
    step: int
    cycle_idx: int
    txn_start: int
    txn_end: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4StepTxns']:
        """Parse an <a4_step_txns> line"""
        match = re.search(r'<a4_step_txns>({.*?})</a4_step_txns>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                step=data['step'],
                cycle_idx=data['cycle_idx'],
                txn_start=data['txn_start'],
                txn_end=data['txn_end'],
            )
        except (json.JSONDecodeError, KeyError):
            return None


@dataclass
class A4Txn:
    """Parsed A4 <a4_txn> output - individual transaction"""
    txn_idx: int
    addr: int
    cycle: int
    word: int
    prev_cycle: int
    prev_word: int
    
    # Constants for register address detection
    USER_REGS_BASE: int = 1073725472  # 0xFFFF0080 / 4
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4Txn']:
        """Parse an <a4_txn> line"""
        match = re.search(r'<a4_txn>({.*?})</a4_txn>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                txn_idx=data['txn_idx'],
                addr=data['addr'],
                cycle=data['cycle'],
                word=data['word'],
                prev_cycle=data['prev_cycle'],
                prev_word=data['prev_word'],
            )
        except (json.JSONDecodeError, KeyError):
            return None
    
    def is_write(self) -> bool:
        """Check if this is a WRITE transaction (odd cycle)"""
        return self.cycle % 2 == 1
    
    def is_read(self) -> bool:
        """Check if this is a READ transaction (even cycle)"""
        return self.cycle % 2 == 0
    
    def is_register(self) -> bool:
        """Check if this address is a user register"""
        return self.USER_REGS_BASE <= self.addr < self.USER_REGS_BASE + 32
    
    def register_index(self) -> Optional[int]:
        """Get the register index if this is a register access"""
        if self.is_register():
            return self.addr - self.USER_REGS_BASE
        return None


@dataclass
class A4RegTxn:
    """Parsed A4 <a4_reg_txn> output - register transaction with step info"""
    txn_idx: int
    step: int       # user_cycle / A4 step
    addr: int
    cycle: int
    word: int
    prev_cycle: int
    prev_word: int
    
    # Constants for register address detection
    USER_REGS_BASE: int = 1073725472  # 0xFFFF0080 / 4
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4RegTxn']:
        """Parse an <a4_reg_txn> line"""
        match = re.search(r'<a4_reg_txn>({.*?})</a4_reg_txn>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                txn_idx=data['txn_idx'],
                step=data['step'],
                addr=data['addr'],
                cycle=data['cycle'],
                word=data['word'],
                prev_cycle=data['prev_cycle'],
                prev_word=data['prev_word'],
            )
        except (json.JSONDecodeError, KeyError):
            return None
    
    def is_write(self) -> bool:
        """Check if this is a WRITE transaction (odd cycle)"""
        return self.cycle % 2 == 1
    
    def is_read(self) -> bool:
        """Check if this is a READ transaction (even cycle)"""
        return self.cycle % 2 == 0
    
    def register_index(self) -> int:
        """Get the register index (0-31)"""
        return self.addr - self.USER_REGS_BASE


@dataclass
class A4InstrTypeMod:
    """Parsed A4 <a4_instr_type_mod> output"""
    step: int
    cycle_idx: int
    pc: int
    old_major: int
    old_minor: int
    new_major: int
    new_minor: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4InstrTypeMod']:
        """Parse an <a4_instr_type_mod> line"""
        match = re.search(r'<a4_instr_type_mod>({.*?})</a4_instr_type_mod>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                step=data['step'],
                cycle_idx=data['cycle_idx'],
                pc=data['pc'],
                old_major=data['old_major'],
                old_minor=data['old_minor'],
                new_major=data['new_major'],
                new_minor=data['new_minor'],
            )
        except (json.JSONDecodeError, KeyError):
            return None


# Parsing functions

def parse_all_a4_cycles(output: str) -> List[A4CycleInfo]:
    """Parse all <a4_cycle_info> entries from output"""
    return [c for line in output.splitlines() if (c := A4CycleInfo.parse(line))]


def parse_all_step_txns(output: str) -> List[A4StepTxns]:
    """Parse all <a4_step_txns> entries from output"""
    return [t for line in output.splitlines() if (t := A4StepTxns.parse(line))]


def parse_all_txns(output: str) -> List[A4Txn]:
    """Parse all <a4_txn> entries from output"""
    return [t for line in output.splitlines() if (t := A4Txn.parse(line))]


def parse_all_reg_txns(output: str) -> List[A4RegTxn]:
    """Parse all <a4_reg_txn> entries from output"""
    return [t for line in output.splitlines() if (t := A4RegTxn.parse(line))]
