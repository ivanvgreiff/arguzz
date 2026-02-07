"""
Constraint Failure Parsing

Parses <constraint_fail> output from A4 mutation runs.
This is used by both standalone and arguzz-dependent strategies
to analyze which constraints were violated.
"""

import json
import re
from dataclasses import dataclass
from typing import List, Optional


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
        """
        Get a shortened version of the location for display.
        
        Includes file:line for uniqueness. Examples:
        - "MemoryWrite@mem.zir:99"
        - "IsRead@mem.zir:79"
        - "VerifyOpcodeF3@inst.zir:123"
        """
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
        """
        Get a full signature for comparing failures.
        
        Includes step, pc, major, minor, and constraint location.
        Used for exact matching between different runs.
        """
        return f"{self.step}:{self.pc}:{self.major}:{self.minor}:{self.short_loc()}"
    
    def constraint_loc(self) -> str:
        """
        Get just the constraint location (without step/pc).
        
        Used for coverage tracking - two failures at different steps
        but same constraint are considered the "same" for coverage.
        """
        return self.short_loc()


def parse_all_constraint_failures(output: str) -> List[ConstraintFailure]:
    """Parse all <constraint_fail> entries from output"""
    return [f for line in output.splitlines() if (f := ConstraintFailure.parse(line))]
