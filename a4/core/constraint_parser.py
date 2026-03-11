"""
Constraint Failure Parsing

Parses <constraint_fail> output from A4 mutation runs.
This is used by both standalone and arguzz-dependent strategies
to analyze which constraints were violated.

Canonical coverage IDs (see a4/docs/touch/PHASE_I_IMPLEMENTATION_PLAN.md §2.1, §0.1):
- ConstraintFamily = constraint_loc() (name@file:line).
- ConstraintContext = (constraint_loc(), major, minor). No step_bucket in Phase I.
Constraint 'touched' = EQZ was invoked for that (cycle, loc); in RV32IM codegen this
implies the constraint was active (control-flow gated). See PHASE_I_IMPLEMENTATION_PLAN.md §0.2.
"""

import json
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


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
    phase: str = "local"
    
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
                phase=data.get('phase', 'local'),
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
    
    def constraint_type(self) -> str:
        """
        Get just the constraint TYPE name (without file:line).
        
        Used for coverage tracking - two failures at different file lines
        but same constraint type are considered the "same" for coverage.
        
        Examples:
        - "MemoryWrite" (not "MemoryWrite@mem.zir:99")
        - "VerifyOpcodeF3F7" (not "VerifyOpcodeF3F7@inst.zir:102")
        
        This is the recommended metric for "new" coverage since the same
        logical constraint may appear at multiple source locations.
        """
        # Pattern 1: "loc(callsite( ConstraintName ("
        match = re.search(r'callsite\(\s*(\w+)\s*\(', self.loc)
        if match:
            return match.group(1)
        
        # Pattern 2: "ConstraintName(zirgen/..."
        match = re.search(r'^(\w+)\(', self.loc)
        if match:
            return match.group(1)
        
        # Fallback: use short_loc if we can't extract just the name
        return self.short_loc()
    
    def constraint_loc(self) -> str:
        """
        Get the constraint location WITH file:line (e.g., "MemoryWrite@mem.zir:99").

        This provides more granular tracking - same constraint type at different
        source locations are counted separately. Useful for detailed analysis
        but inflates "new" coverage counts.

        For the recommended "new" coverage metric, use constraint_type() instead.
        """
        return self.short_loc()

    def context_id(self) -> Tuple[str, int, int]:
        """
        Stable coverage key: (constraint_loc, major, minor).

        Used for determinism tests and Phase 0.2 measurement (distinct contexts).
        Hashable for use in sets/dicts. See PHASE_I_IMPLEMENTATION_PLAN.md §2.2, §0.1.
        """
        return (self.constraint_loc(), self.major, self.minor)

    def context_id_with_step_bucket(self, B: int) -> Tuple[str, int, int, int]:
        """
        Coverage key with step bucketing: (constraint_loc, major, minor, step // B).

        For future location-aware coverage; Phase I uses context_id() only.
        """
        return (self.constraint_loc(), self.major, self.minor, self.step // B)


def parse_all_constraint_failures(output: str) -> List[ConstraintFailure]:
    """Parse all <constraint_fail> entries from output"""
    return [f for line in output.splitlines() if (f := ConstraintFailure.parse(line))]
