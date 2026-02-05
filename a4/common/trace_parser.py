"""
Trace Output Parsing

Parses Arguzz and A4 trace output formats including:
- <fault> - Arguzz fault injection info
- <trace> - Arguzz execution trace
- <a4_cycle_info> - A4 preflight cycle data
- <constraint_fail> - Constraint failure reports
"""

import json
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ArguzzFault:
    """Parsed Arguzz <fault> output - supports multiple fault types"""
    step: int
    pc: int
    kind: str
    info_type: str          # "word" for INSTR_WORD_MOD, "out" for COMP_OUT_MOD, "reg_assign" for PRE_EXEC_REG_MOD
    original_value: int     # Original value (word or output)
    mutated_value: int      # Mutated value
    target_register: Optional[str] = None  # For PRE_EXEC_REG_MOD: register name (e.g., "s3")
    
    # Backwards compatibility aliases
    @property
    def original_word(self) -> int:
        return self.original_value
    
    @property
    def mutated_word(self) -> int:
        return self.mutated_value
    
    @classmethod
    def parse(cls, line: str) -> Optional['ArguzzFault']:
        """Parse a <fault> line from Arguzz output
        
        Supports multiple fault formats:
        - INSTR_WORD_MOD: "word:3147283 => word:8897555"
        - COMP_OUT_MOD:   "out:3 => out:73117827"
        """
        match = re.search(r'<fault>({.*?})</fault>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            info = data.get('info', '')
            
            # Try word:X => word:Y (INSTR_WORD_MOD)
            word_match = re.search(r'word:(\d+)\s*=>\s*word:(\d+)', info)
            if word_match:
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='word',
                    original_value=int(word_match.group(1)),
                    mutated_value=int(word_match.group(2)),
                )
            
            # Try out:X => out:Y (COMP_OUT_MOD, LOAD_VAL_MOD)
            out_match = re.search(r'out:(\d+)\s*=>\s*out:(\d+)', info)
            if out_match:
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='out',
                    original_value=int(out_match.group(1)),
                    mutated_value=int(out_match.group(2)),
                )
            
            # Try data:X => data:Y (STORE_OUT_MOD)
            data_match = re.search(r'data:(\d+)\s*=>\s*data:(\d+)', info)
            if data_match:
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='data',
                    original_value=int(data_match.group(1)),
                    mutated_value=int(data_match.group(2)),
                )
            
            # Try pc:X => pc:Y (PRE_EXEC_PC_MOD)
            pc_match = re.search(r'pc:(\d+)\s*=>\s*pc:(\d+)', info)
            if pc_match:
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='pc',
                    original_value=int(pc_match.group(1)),
                    mutated_value=int(pc_match.group(2)),
                )
            
            # Try <reg_name> = <value> (PRE_EXEC_REG_MOD, POST_EXEC_REG_MOD)
            # Format: "s3 = 1" or "a7 = 3792952734"
            reg_assign_match = re.search(r'^(\w+)\s*=\s*(\d+)$', info.strip())
            if reg_assign_match and data['kind'] in ('PRE_EXEC_REG_MOD', 'POST_EXEC_REG_MOD'):
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='reg_assign',
                    original_value=0,  # Not available in Arguzz output
                    mutated_value=int(reg_assign_match.group(2)),
                    target_register=reg_assign_match.group(1),
                )
            
            # Try MEM[<addr>] = <value> (PRE_EXEC_MEM_MOD, POST_EXEC_MEM_MOD)
            # Format: "MEM[$0x13946509] = 3792952734"
            mem_assign_match = re.search(r'MEM\[\$?(0x[0-9a-fA-F]+|\d+)\]\s*=\s*(\d+)', info)
            if mem_assign_match and data['kind'] in ('PRE_EXEC_MEM_MOD', 'POST_EXEC_MEM_MOD'):
                addr_str = mem_assign_match.group(1)
                addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                return cls(
                    step=data['step'],
                    pc=data['pc'],
                    kind=data['kind'],
                    info_type='mem_assign',
                    original_value=addr,  # Store address as original_value
                    mutated_value=int(mem_assign_match.group(2)),
                )
            
            # Unknown format - store raw info
            return cls(
                step=data['step'],
                pc=data['pc'],
                kind=data['kind'],
                info_type='unknown',
                original_value=0,
                mutated_value=0,
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            return None


@dataclass  
class ArguzzTrace:
    """Parsed Arguzz <trace> output"""
    step: int
    pc: int
    instruction: str
    assembly: str
    
    @classmethod
    def parse(cls, line: str) -> Optional['ArguzzTrace']:
        """Parse a <trace> line from Arguzz output"""
        match = re.search(r'<trace>({.*?})</trace>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                step=data['step'],
                pc=data['pc'],
                instruction=data['instruction'],
                assembly=data.get('assembly', ''),
            )
        except (json.JSONDecodeError, KeyError):
            return None


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
class ConstraintFailure:
    """Parsed <constraint_fail> output"""
    cycle: int
    step: int
    pc: int
    major: int
    minor: int
    loc: str
    value: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['ConstraintFailure']:
        """Parse a <constraint_fail> line"""
        match = re.search(r'<constraint_fail>({.*?})</constraint_fail>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
            return cls(
                cycle=data['cycle'],
                step=data['step'],
                pc=data['pc'],
                major=data['major'],
                minor=data['minor'],
                loc=data['loc'],
                value=data['value'],
            )
        except (json.JSONDecodeError, KeyError):
            return None
    
    def short_loc(self) -> str:
        """Get a shortened version of the location for display, including file:line for uniqueness"""
        # Try to extract constraint name + file:line
        # Pattern 1: "loc(callsite( ConstraintName ( path/file.zir :line:col)" 
        match = re.search(r'callsite\(\s*(\w+)\s*\(\s*\S+/(\w+\.\w+)\s*:(\d+)', self.loc)
        if match:
            return f"{match.group(1)}@{match.group(2)}:{match.group(3)}"
        
        # Pattern 2: "ConstraintName(zirgen/.../file.zir:line)"
        match = re.search(r'^(\w+)\(zirgen/[^:]+/(\w+\.\w+):(\d+)', self.loc)
        if match:
            return f"{match.group(1)}@{match.group(2)}:{match.group(3)}"
        
        # Pattern 3: Just constraint name from callsite (fallback)
        match = re.search(r'callsite\(\s*(\w+)\s*\(', self.loc)
        if match:
            return match.group(1)
        
        # Pattern 4: Just constraint name at start
        match = re.search(r'^(\w+)\(', self.loc)
        if match:
            return match.group(1)
        
        return self.loc[:40]
    
    def signature(self) -> str:
        """Get a signature for comparing failures (ignoring cycle numbers)"""
        return f"{self.step}:{self.pc}:{self.major}:{self.minor}:{self.short_loc()}"


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
        # USER_REGS_ADDR / 4 = 1073725472
        USER_REGS_BASE = 1073725472
        return USER_REGS_BASE <= self.addr < USER_REGS_BASE + 32
    
    def register_index(self) -> Optional[int]:
        """Get the register index if this is a register access"""
        USER_REGS_BASE = 1073725472
        if self.is_register():
            return self.addr - USER_REGS_BASE
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
        USER_REGS_BASE = 1073725472
        return self.addr - USER_REGS_BASE


def parse_all_faults(output: str) -> List[ArguzzFault]:
    """Parse all <fault> entries from output"""
    return [f for line in output.splitlines() if (f := ArguzzFault.parse(line))]


def parse_all_traces(output: str) -> List[ArguzzTrace]:
    """Parse all <trace> entries from output"""
    return [t for line in output.splitlines() if (t := ArguzzTrace.parse(line))]


def parse_all_a4_cycles(output: str) -> List[A4CycleInfo]:
    """Parse all <a4_cycle_info> entries from output"""
    return [c for line in output.splitlines() if (c := A4CycleInfo.parse(line))]


def parse_all_constraint_failures(output: str) -> List[ConstraintFailure]:
    """Parse all <constraint_fail> entries from output"""
    return [f for line in output.splitlines() if (f := ConstraintFailure.parse(line))]


def parse_all_step_txns(output: str) -> List[A4StepTxns]:
    """Parse all <a4_step_txns> entries from output"""
    return [t for line in output.splitlines() if (t := A4StepTxns.parse(line))]


def parse_all_txns(output: str) -> List[A4Txn]:
    """Parse all <a4_txn> entries from output"""
    return [t for line in output.splitlines() if (t := A4Txn.parse(line))]


def parse_all_reg_txns(output: str) -> List[A4RegTxn]:
    """Parse all <a4_reg_txn> entries from output"""
    return [t for line in output.splitlines() if (t := A4RegTxn.parse(line))]
