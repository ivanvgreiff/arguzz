"""
Arm Universe Construction (Phase II.1)

Builds the action space for the Discounted-UCB bandit scheduler.
Each "arm" is a (mutation_kind, step_bucket) pair. The arm universe
is computed once per campaign from InspectionData and budget N.

Terminology:
  K       = number of mutation kinds (8)
  T       = step horizon (1 + max valid step across all kinds)
  B_count = number of step buckets (derived from budget)
  B       = steps per bucket (ceil(T / B_count))
  arm     = (kind, bucket_index) pair with at least one valid step
  S_k     = set of valid steps for mutation kind k
  S_{k,b} = steps in S_k that fall in bucket b

See a4/docs/touch/Phase II/PHASE_II_1_IMPLEMENTATION_PLAN.md
and a4/docs/touch/Phase II/PHASE_II_MASTER_IMPLEMENTATION_PLAN.md section 2.2.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


# =========================================================================
# Helpers
# =========================================================================

def pow2_clamp(x: int, lo: int, hi: int) -> int:
    """
    Round x down to the nearest power of 2, then clamp to [lo, hi].

    If x < lo, returns lo. If x > hi, returns hi.
    Otherwise returns the largest power of 2 that is <= x.

    Examples:
        pow2_clamp(41, 16, 128) = 32
        pow2_clamp(5, 16, 128)  = 16  (clamped up to lo)
        pow2_clamp(200, 16, 128) = 128 (clamped down to hi)
        pow2_clamp(64, 16, 128) = 64  (exact power of 2)
    """
    if x <= 0:
        return lo
    # Largest power of 2 <= x
    p = 1 << (x.bit_length() - 1)
    return max(lo, min(p, hi))


# =========================================================================
# Arm Universe
# =========================================================================

# Default constants from Pro_Report_5 section 11
_N_TARGET = 3       # desired average samples per arm
_B_MIN = 16         # minimum step buckets
_B_MAX = 128        # maximum step buckets


class ArmUniverse:
    """
    The action space for the coverage-guided bandit scheduler.

    Each arm is a (mutation_kind, bucket_index) pair. The universe is
    computed from InspectionData (which provides valid steps per kind)
    and the campaign budget N (which determines how many buckets to use).
    """

    def __init__(
        self,
        data: 'InspectionData',
        budget: int,
        mutation_kinds: List[str],
    ):
        """
        Construct the arm universe.

        Args:
            data: InspectionData from a guest program inspection run.
            budget: Campaign budget N (total number of mutations planned).
            mutation_kinds: List of mutation kind names (e.g. A4Fuzzer.MUTATION_KINDS).
        """
        self.budget = budget
        self.mutation_kinds = list(mutation_kinds)
        self.K = len(mutation_kinds)

        # Step 1: Compute S_k for each kind
        self.steps_per_kind: Dict[str, List[int]] = {}
        all_valid_steps: set = set()
        for kind in mutation_kinds:
            steps = data.get_valid_steps_for_kind(kind)
            self.steps_per_kind[kind] = steps
            all_valid_steps.update(steps)

        # Step 2: Compute T (step horizon)
        if all_valid_steps:
            self.T = 1 + max(all_valid_steps)
        else:
            self.T = 0

        # Step 3: Compute B_count (number of step buckets) from budget
        if self.K > 0 and budget > 0:
            raw = budget // (self.K * _N_TARGET)
            self.B_count = pow2_clamp(raw, _B_MIN, _B_MAX)
        else:
            self.B_count = _B_MIN

        # Step 4: Compute B (steps per bucket)
        if self.B_count > 0 and self.T > 0:
            self.B = math.ceil(self.T / self.B_count)
        else:
            self.B = 1

        # Step 5: Enumerate arms — (kind, bucket) -> list of valid steps
        self.arms: Dict[Tuple[str, int], List[int]] = {}
        for kind in mutation_kinds:
            for step in self.steps_per_kind[kind]:
                bucket = step // self.B
                key = (kind, bucket)
                if key not in self.arms:
                    self.arms[key] = []
                self.arms[key].append(step)

        # Sort step lists within each arm for deterministic selection
        for key in self.arms:
            self.arms[key].sort()

        # Step 6: Available arms (those with at least one valid step)
        self.available_arms: List[Tuple[str, int]] = sorted(self.arms.keys())
        self.num_arms = len(self.available_arms)

        # Step 7: Forced exploration minimum
        self.n_min = 1 if budget >= self.num_arms else 0

    def bucket_for_step(self, step: int) -> int:
        """Return the bucket index for a given step."""
        return step // self.B

    def steps_in_arm(self, kind: str, bucket: int) -> List[int]:
        """Return the list of valid steps for a given arm, or empty list."""
        return self.arms.get((kind, bucket), [])

    def summary(self) -> str:
        """Human-readable summary of the arm universe."""
        lines = [
            "Arm Universe Summary:",
            f"  Budget (N):        {self.budget}",
            f"  Mutation kinds (K): {self.K}",
            f"  Step horizon (T):  {self.T}",
            f"  Bucket count:      {self.B_count}",
            f"  Steps per bucket:  {self.B}",
            f"  Total arms:        {self.num_arms} (of {self.K} x {self.B_count} = {self.K * self.B_count} possible)",
            f"  Forced exploration (n_min): {self.n_min}",
            f"  Avg steps per arm: {sum(len(v) for v in self.arms.values()) / max(self.num_arms, 1):.1f}",
            f"  Avg samples/arm at budget: {self.budget / max(self.num_arms, 1):.1f}",
            "",
            "  Arms per kind:",
        ]
        for kind in self.mutation_kinds:
            kind_arms = [(k, b) for (k, b) in self.available_arms if k == kind]
            total_steps = sum(len(self.arms[(k, b)]) for k, b in kind_arms)
            lines.append(f"    {kind}: {len(kind_arms)} arms, {total_steps} steps")

        return "\n".join(lines)
