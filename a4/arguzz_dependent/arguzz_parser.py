"""
Arguzz Output Parsing

Parses Arguzz-specific trace output formats:
- <fault> - Arguzz fault injection info
- <trace> - Arguzz execution trace

Note: A4-specific parsing is in core/trace_parser.py
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
    info_type: str          # "word" for INSTR_WORD_MOD, "out" for COMP_OUT_MOD, etc.
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
        - STORE_OUT_MOD:  "data:123 => data:456"
        - PRE_EXEC_REG_MOD: "s3 = 1"
        - PRE_EXEC_MEM_MOD: "MEM[0x12345] = 789"
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


def parse_all_faults(output: str) -> List[ArguzzFault]:
    """Parse all <fault> entries from output"""
    return [f for line in output.splitlines() if (f := ArguzzFault.parse(line))]


def parse_all_traces(output: str) -> List[ArguzzTrace]:
    """Parse all <trace> entries from output"""
    return [t for line in output.splitlines() if (t := ArguzzTrace.parse(line))]
