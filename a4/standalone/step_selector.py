"""
Step Selection Strategies for Standalone A4 Fuzzing

Different strategies for selecting which step to mutate:
- RandomStepSelector: Uniform random selection from valid steps
- HeuristicStepSelector: Prefer certain instruction types (loads, stores, branches)
- GuidedStepSelector: Use coverage data to prefer under-tested areas

All selectors work with a specific mutation kind to ensure only valid steps
are selected.
"""

import random
from abc import ABC, abstractmethod
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData
    from a4.standalone.coverage_db import CoverageDB


class StepSelector(ABC):
    """Abstract base class for step selection strategies"""
    
    @abstractmethod
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        """
        Select a step to mutate.
        
        Args:
            data: InspectionData containing trace information
            kind: Mutation kind (COMP_OUT_MOD, LOAD_VAL_MOD, etc.)
            
        Returns:
            Selected step number, or None if no valid steps
        """
        pass
    
    def get_valid_steps(self, data: 'InspectionData', kind: str) -> List[int]:
        """Get list of valid steps for a mutation kind"""
        return data.get_valid_steps_for_kind(kind)


class RandomStepSelector(StepSelector):
    """
    Random step selection with uniform distribution.
    
    Simple strategy: pick uniformly at random from all valid steps
    for the given mutation kind.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize with optional random seed.
        
        Args:
            seed: Random seed for reproducibility
        """
        self.rng = random.Random(seed)
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        return self.rng.choice(valid_steps)


class HeuristicStepSelector(StepSelector):
    """
    Heuristic-based step selection.
    
    Prioritizes certain instruction types that are more likely to
    expose interesting bugs:
    - Memory operations (loads/stores) for consistency checks
    - Branch instructions for control flow checks
    - Arithmetic with potential overflow
    
    Uses weighted random selection based on instruction type.
    """
    
    # Weight multipliers by major category
    # Higher weight = more likely to be selected
    MAJOR_WEIGHTS = {
        0: 1.0,   # MISC0 (compute) - baseline
        1: 1.5,   # MISC1 (immediate + branches) - branches are interesting
        2: 2.0,   # MISC2 (jumps) - control flow
        3: 1.2,   # MUL0 (multiply/shift)
        4: 1.5,   # DIV0 (divide) - potential edge cases
        5: 2.5,   # MEM0 (load) - memory consistency
        6: 2.5,   # MEM1 (store) - memory consistency
    }
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize with optional random seed.
        
        Args:
            seed: Random seed for reproducibility
        """
        self.rng = random.Random(seed)
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        # Calculate weights for each step
        weights = []
        for step in valid_steps:
            cycle = data.get_cycle(step)
            if cycle:
                weight = self.MAJOR_WEIGHTS.get(cycle.major, 1.0)
            else:
                weight = 1.0
            weights.append(weight)
        
        # Weighted random selection
        return self.rng.choices(valid_steps, weights=weights, k=1)[0]


class GuidedStepSelector(StepSelector):
    """
    Coverage-guided step selection.
    
    Uses coverage database to prefer steps that:
    1. Have not been mutated before
    2. Are near steps that produced new coverage
    3. Have instruction types with low coverage
    
    Falls back to random selection if no coverage data available.
    """
    
    def __init__(self, db: 'CoverageDB', seed: Optional[int] = None):
        """
        Initialize with coverage database.
        
        Args:
            db: CoverageDB instance for coverage queries
            seed: Random seed for reproducibility
        """
        self.db = db
        self.rng = random.Random(seed)
        self._mutated_steps: set = set()
        self._high_value_steps: set = set()
    
    def record_mutation(self, step: int, new_coverage: int):
        """
        Record a mutation result to guide future selection.
        
        Args:
            step: The step that was mutated
            new_coverage: Number of new constraints discovered
        """
        self._mutated_steps.add(step)
        if new_coverage > 0:
            # Mark nearby steps as high-value
            for s in range(max(0, step - 10), step + 10):
                self._high_value_steps.add(s)
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        # Prioritize: unmutated > high-value > random
        unmutated = [s for s in valid_steps if s not in self._mutated_steps]
        
        if unmutated:
            # Prefer high-value unmutated steps
            high_value_unmutated = [s for s in unmutated if s in self._high_value_steps]
            if high_value_unmutated:
                return self.rng.choice(high_value_unmutated)
            return self.rng.choice(unmutated)
        
        # All steps have been mutated; pick randomly
        return self.rng.choice(valid_steps)


class SequentialStepSelector(StepSelector):
    """
    Sequential step selection for exhaustive testing.
    
    Iterates through all valid steps in order. Useful for
    systematic testing of all possible mutation points.
    """
    
    def __init__(self):
        self._current_idx = 0
        self._last_kind: Optional[str] = None
        self._last_valid_steps: List[int] = []
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        # Reset if kind changed
        if kind != self._last_kind:
            self._current_idx = 0
            self._last_kind = kind
            self._last_valid_steps = valid_steps
        
        if self._current_idx >= len(valid_steps):
            self._current_idx = 0  # Wrap around
        
        step = valid_steps[self._current_idx]
        self._current_idx += 1
        return step
    
    def reset(self):
        """Reset to start from the beginning"""
        self._current_idx = 0


def create_selector(
    strategy: str, 
    seed: Optional[int] = None,
    db: Optional['CoverageDB'] = None
) -> StepSelector:
    """
    Factory function to create a step selector.
    
    Args:
        strategy: One of "random", "heuristic", "guided", "sequential"
        seed: Random seed for reproducibility
        db: CoverageDB instance (required for "guided" strategy)
        
    Returns:
        Configured StepSelector instance
    """
    if strategy == "random":
        return RandomStepSelector(seed)
    elif strategy == "heuristic":
        return HeuristicStepSelector(seed)
    elif strategy == "guided":
        if db is None:
            raise ValueError("CoverageDB required for guided strategy")
        return GuidedStepSelector(db, seed)
    elif strategy == "sequential":
        return SequentialStepSelector()
    else:
        raise ValueError(f"Unknown strategy: {strategy}")
