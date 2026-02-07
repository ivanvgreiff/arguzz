"""
Constraint Failure Comparison

Functions for comparing constraint failures between Arguzz and A4 runs.
"""

from dataclasses import dataclass
from typing import List

from a4.core.constraint_parser import ConstraintFailure


@dataclass
class ComparisonResult:
    """Result of comparing Arguzz and A4 constraint failures"""
    arguzz_failures: List[ConstraintFailure]
    a4_failures: List[ConstraintFailure]
    common_signatures: List[str]
    arguzz_only_signatures: List[str]
    a4_only_signatures: List[str]
    skipped: bool = False
    skip_reason: str = ""
    
    def print_summary(self):
        """Print a summary of the comparison"""
        print("\n" + "=" * 60)
        print("CONSTRAINT FAILURE COMPARISON")
        print("=" * 60)
        
        if self.skipped:
            print(f"\n*** COMPARISON SKIPPED ***")
            print(f"Reason: {self.skip_reason}")
            print("=" * 60)
            return
        
        print(f"\nArguzz: {len(self.arguzz_failures)} failures")
        print(f"A4:     {len(self.a4_failures)} failures")
        
        print(f"\n--- Common ({len(self.common_signatures)}) ---")
        for sig in self.common_signatures:
            self._print_signature(sig)
        
        print(f"\n--- Arguzz only ({len(self.arguzz_only_signatures)}) ---")
        for sig in self.arguzz_only_signatures:
            self._print_signature(sig)
        
        print(f"\n--- A4 only ({len(self.a4_only_signatures)}) ---")
        for sig in self.a4_only_signatures:
            self._print_signature(sig)
        
        print("=" * 60)
    
    def _print_signature(self, sig: str):
        """Pretty-print a signature"""
        # Handle MATCH: prefix from compare_failures_by_constraint_only
        if sig.startswith("MATCH:"):
            constraint = sig[6:]  # Remove "MATCH:" prefix
            print(f"  ✓ {constraint}")
            return
        
        parts = sig.split(':')
        if len(parts) >= 5:
            step, pc, major, minor, constraint = parts[0], parts[1], parts[2], parts[3], ':'.join(parts[4:])
            print(f"  step={step}, pc={pc}, major={major}, minor={minor}: {constraint}")
        else:
            print(f"  {sig}")
    
    @classmethod
    def skipped_result(cls, reason: str) -> 'ComparisonResult':
        """Create a skipped comparison result"""
        return cls(
            arguzz_failures=[],
            a4_failures=[],
            common_signatures=[],
            arguzz_only_signatures=[],
            a4_only_signatures=[],
            skipped=True,
            skip_reason=reason,
        )


def compare_failures(
    arguzz_failures: List[ConstraintFailure],
    a4_failures: List[ConstraintFailure],
    step_offset: int = 0
) -> ComparisonResult:
    """
    Compare constraint failures between Arguzz and A4.
    
    Note: Constraint failures are reported at the ACTUAL step (user_cycle),
    not the Arguzz injection step. So we don't apply the step_offset to
    failure comparison - both should report at the same step.
    
    Args:
        arguzz_failures: Failures from Arguzz run
        a4_failures: Failures from A4 run
        step_offset: Informational only (not used for comparison)
    """
    # Normalize signatures (NO step adjustment - both report at actual step)
    def normalize_sig(f: ConstraintFailure) -> str:
        return f"{f.step}:{f.pc}:{f.major}:{f.minor}:{f.short_loc()}"
    
    arguzz_sigs = {normalize_sig(f): f for f in arguzz_failures}
    a4_sigs = {normalize_sig(f): f for f in a4_failures}
    
    common = set(arguzz_sigs.keys()) & set(a4_sigs.keys())
    arguzz_only = set(arguzz_sigs.keys()) - common
    a4_only = set(a4_sigs.keys()) - common
    
    return ComparisonResult(
        arguzz_failures=arguzz_failures,
        a4_failures=a4_failures,
        common_signatures=sorted(common),
        arguzz_only_signatures=sorted(arguzz_only),
        a4_only_signatures=sorted(a4_only),
    )


def compare_failures_by_constraint_only(
    arguzz_failures: List[ConstraintFailure],
    a4_failures: List[ConstraintFailure],
) -> ComparisonResult:
    """
    Compare constraint failures using ONLY the constraint location (short_loc).
    
    This is used for PRE_EXEC_REG_MOD and similar mutations where:
    - Arguzz injects a NEW transaction at step X
    - A4 modifies an EXISTING transaction at step Y (Y != X)
    - Both cause the SAME TYPE of memory consistency failure
    - But at DIFFERENT steps/PCs
    
    For these mutations, we only care if both triggered the same constraint
    types (e.g., IsRead@mem.zir:79), not whether they occurred at the same
    step/PC.
    
    Args:
        arguzz_failures: Failures from Arguzz run
        a4_failures: Failures from A4 run
    
    Returns:
        ComparisonResult with common = same constraint locations
    """
    # Use only short_loc for comparison (constraint name + file:line)
    # This ignores step, pc, major, minor
    def constraint_only_sig(f: ConstraintFailure) -> str:
        return f.short_loc()
    
    # For display, we still want the full signature
    def full_sig(f: ConstraintFailure) -> str:
        return f"{f.step}:{f.pc}:{f.major}:{f.minor}:{f.short_loc()}"
    
    # Build maps: constraint_loc -> list of full signatures
    arguzz_by_constraint = {}
    for f in arguzz_failures:
        loc = constraint_only_sig(f)
        if loc not in arguzz_by_constraint:
            arguzz_by_constraint[loc] = []
        arguzz_by_constraint[loc].append(full_sig(f))
    
    a4_by_constraint = {}
    for f in a4_failures:
        loc = constraint_only_sig(f)
        if loc not in a4_by_constraint:
            a4_by_constraint[loc] = []
        a4_by_constraint[loc].append(full_sig(f))
    
    # Find common constraint locations
    common_locs = set(arguzz_by_constraint.keys()) & set(a4_by_constraint.keys())
    arguzz_only_locs = set(arguzz_by_constraint.keys()) - common_locs
    a4_only_locs = set(a4_by_constraint.keys()) - common_locs
    
    # For common: show both Arguzz and A4 versions (they differ in step/pc)
    common_signatures = []
    for loc in sorted(common_locs):
        # Use a combined format
        common_signatures.append(f"MATCH:{loc}")
    
    # For Arguzz-only: show full signatures
    arguzz_only_signatures = []
    for loc in sorted(arguzz_only_locs):
        for sig in arguzz_by_constraint[loc]:
            arguzz_only_signatures.append(sig)
    
    # For A4-only: show full signatures
    a4_only_signatures = []
    for loc in sorted(a4_only_locs):
        for sig in a4_by_constraint[loc]:
            a4_only_signatures.append(sig)
    
    return ComparisonResult(
        arguzz_failures=arguzz_failures,
        a4_failures=a4_failures,
        common_signatures=common_signatures,
        arguzz_only_signatures=arguzz_only_signatures,
        a4_only_signatures=a4_only_signatures,
    )
