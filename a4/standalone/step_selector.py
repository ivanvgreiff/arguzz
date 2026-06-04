"""
Zoned Step Selection for Standalone A4 Fuzzing

This module implements a zoned step selection strategy that ensures a controlled
distribution of mutations across different phases of program execution:

- INIT zone (5%): Step 0 only - initialization, ECALL setup, POSEIDON operations
- CORE zone (90%): Steps 1 to max_step-1 - main program execution
- FINAL zone (5%): Last step only - cleanup, finalization

This distribution ensures:
1. Adequate coverage of edge cases at program boundaries (init/final)
2. Primary focus on the bulk of program execution (core)
3. Future extensibility for coverage-guided selection

Architecture Notes:
-------------------
The previous selectors (RandomStepSelector, SequentialStepSelector, HeuristicStepSelector)
have been removed because:
- RandomStepSelector: Suffered from severe bias due to duplicate steps in valid_steps list
- SequentialStepSelector: Too slow for practical fuzzing; deterministic order not useful
- HeuristicStepSelector: The heuristic weights were speculative; zoned approach is better

The GuidedStepSelector is kept as a stub for future coverage-guided integration.
"""

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData
    from a4.standalone.coverage_db import CoverageDB
    from a4.standalone.arm_universe import ArmUniverse


# =============================================================================
# Zone Configuration
# =============================================================================

@dataclass
class ZoneConfig:
    """
    Configuration for the zoned step selection strategy.
    
    The three zones partition all valid steps:
    - init: Only step 0 (program initialization)
    - core: Steps 1 through max_step-1 (main execution)
    - final: Only the last step (program completion)
    
    Weights define the probability of selecting from each zone.
    These are fixed at 5%/90%/5% and do not need normalization
    since they sum to 100%.
    """
    init_weight: float = 0.05    # 5% chance for step 0
    core_weight: float = 0.90    # 90% chance for middle steps
    final_weight: float = 0.05   # 5% chance for last step
    
    def get_zone_weights(self) -> Dict[str, float]:
        """Return zone weights as a dictionary"""
        return {
            "init": self.init_weight,
            "core": self.core_weight,
            "final": self.final_weight,
        }


# Default zone configuration - used by all zoned selectors
DEFAULT_ZONE_CONFIG = ZoneConfig()


# =============================================================================
# Base Class
# =============================================================================

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
        """
        Get list of valid steps for a mutation kind.
        
        Note: The underlying data.get_valid_steps_for_kind() returns unique steps
        (no duplicates), so uniform random selection from this list is unbiased.
        """
        return data.get_valid_steps_for_kind(kind)


# =============================================================================
# Zoned Step Selector
# =============================================================================

class ZonedStepSelector(StepSelector):
    """
    Zoned step selection with fixed distribution.
    
    Ensures mutations are distributed across program execution phases:
    - 5% init (step 0): Catches initialization bugs, ECALL/POSEIDON issues
    - 90% core (middle steps): Main program execution coverage
    - 5% final (last step): Catches finalization/cleanup bugs
    
    Selection Algorithm:
    1. Get all valid steps for the mutation kind (already deduplicated)
    2. Partition valid steps into zones (init, core, final)
    3. Pick a zone based on configured weights (5%/90%/5%)
    4. Pick uniformly at random from steps within the chosen zone
    5. If chosen zone is empty, pick from any valid step (fallback)
    
    Why This Works:
    - The valid_steps list contains unique step numbers (no duplicates)
    - Zone selection is weighted, ensuring controlled distribution
    - Within-zone selection is uniform, ensuring fairness within each phase
    - Fallback handles edge cases (e.g., mutation kind only valid for certain steps)
    """
    
    def __init__(self, seed: Optional[int] = None, config: ZoneConfig = None):
        """
        Initialize the zoned selector.
        
        Args:
            seed: Random seed for reproducibility
            config: Zone configuration (defaults to 5%/90%/5%)
        """
        self.rng = random.Random(seed)
        self.config = config or DEFAULT_ZONE_CONFIG
    
    def _partition_into_zones(
        self, valid_steps: List[int]
    ) -> Dict[str, List[int]]:
        """
        Partition valid steps into zones based on step number.
        
        Args:
            valid_steps: List of unique valid step numbers
            
        Returns:
            Dictionary mapping zone name to list of steps in that zone
            
        Zone definitions:
        - init: step == 0
        - final: step == max(valid_steps)
        - core: all other steps
        """
        if not valid_steps:
            return {"init": [], "core": [], "final": []}
        
        max_step = max(valid_steps)
        
        zones = {"init": [], "core": [], "final": []}
        
        for step in valid_steps:
            if step == 0:
                zones["init"].append(step)
            elif step == max_step:
                zones["final"].append(step)
            else:
                zones["core"].append(step)
        
        return zones
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        """
        Select a step using zoned distribution.
        
        Returns:
            Selected step, or None if no valid steps exist
        """
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        # Partition into zones
        zones = self._partition_into_zones(valid_steps)
        
        # Build weighted selection for non-empty zones
        available_zones = []
        zone_weights = []
        
        weights = self.config.get_zone_weights()
        for zone_name in ["init", "core", "final"]:
            if zones[zone_name]:  # Only include non-empty zones
                available_zones.append(zone_name)
                zone_weights.append(weights[zone_name])
        
        if not available_zones:
            # Shouldn't happen if valid_steps is non-empty, but be safe
            return self.rng.choice(valid_steps)
        
        # Select zone (weighted) then step (uniform within zone)
        chosen_zone = self.rng.choices(available_zones, weights=zone_weights, k=1)[0]
        return self.rng.choice(zones[chosen_zone])
    
    def get_zone_stats(self, data: 'InspectionData', kind: str) -> Dict[str, int]:
        """
        Get statistics about zone populations for debugging.
        
        Returns:
            Dictionary with step counts per zone
        """
        valid_steps = self.get_valid_steps(data, kind)
        zones = self._partition_into_zones(valid_steps)
        return {
            "init": len(zones["init"]),
            "core": len(zones["core"]),
            "final": len(zones["final"]),
            "total": len(valid_steps),
        }


# =============================================================================
# Coverage-Guided Selector (Stub for Future Development)
# =============================================================================

class CoverageGuidedSelector(StepSelector):
    """
    Coverage-guided step selection (STUB FOR FUTURE DEVELOPMENT).
    
    This selector extends ZonedStepSelector with coverage-based guidance.
    Currently, it behaves identically to ZonedStepSelector, but provides
    hooks for future coverage integration.
    
    Future Implementation Plan:
    ---------------------------
    The record_result() method will be called after each mutation to record:
    - Which step was mutated
    - What mutation kind was used
    - The outcome (constraint failures, witness failures, etc.)
    - Which constraints were triggered
    
    This data will be used to:
    1. Track which steps have been tested (avoid over-testing same steps)
    2. Identify "high-value" steps near those that found new coverage
    3. Adjust zone weights dynamically based on coverage progress
    4. Prioritize under-tested areas of execution
    
    Mutation Result Tracking:
    -------------------------
    The `record_result()` method accepts a result dictionary that should contain:
    - "step": int - The step that was mutated
    - "kind": str - The mutation kind (e.g., "MEM_VAL_MOD")
    - "outcome": str - One of "CONSTRAINT_FAIL", "WITNESS_FAIL", "NO_EFFECT", "VERIFIER_ACCEPTED"
    - "new_coverage": int - Number of new unique constraints triggered
    - "constraints": List[str] - List of constraint locations triggered
    
    This stub stores data but does not yet use it for selection decisions.
    """
    
    def __init__(
        self, 
        db: Optional['CoverageDB'] = None,
        seed: Optional[int] = None, 
        config: ZoneConfig = None
    ):
        """
        Initialize the coverage-guided selector.
        
        Args:
            db: CoverageDB instance for persistent storage (optional for now)
            seed: Random seed for reproducibility
            config: Zone configuration (defaults to 5%/90%/5%)
        """
        self.rng = random.Random(seed)
        self.config = config or DEFAULT_ZONE_CONFIG
        self.db = db
        
        # =====================================================================
        # STUB DATA STRUCTURES - For future coverage guidance
        # These track mutation history but are not yet used for selection
        # =====================================================================
        
        # Set of steps that have been mutated at least once
        # Future use: avoid over-testing same steps
        self._mutated_steps: Dict[str, set] = {}  # kind -> set of steps
        
        # Steps that produced new coverage, mapped to their "value"
        # Future use: prioritize nearby steps
        self._high_value_steps: Dict[int, int] = {}  # step -> new_coverage count
        
        # Total mutations per zone for adaptive weighting
        # Future use: balance exploration across zones
        self._zone_mutation_counts: Dict[str, int] = {
            "init": 0,
            "core": 0, 
            "final": 0,
        }
    
    def _partition_into_zones(
        self, valid_steps: List[int]
    ) -> Dict[str, List[int]]:
        """Partition valid steps into zones (same as ZonedStepSelector)"""
        if not valid_steps:
            return {"init": [], "core": [], "final": []}
        
        max_step = max(valid_steps)
        zones = {"init": [], "core": [], "final": []}
        
        for step in valid_steps:
            if step == 0:
                zones["init"].append(step)
            elif step == max_step:
                zones["final"].append(step)
            else:
                zones["core"].append(step)
        
        return zones
    
    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        """
        Select a step using zoned distribution.
        
        Currently identical to ZonedStepSelector.
        Future: Will incorporate coverage data for smarter selection.
        """
        valid_steps = self.get_valid_steps(data, kind)
        if not valid_steps:
            return None
        
        zones = self._partition_into_zones(valid_steps)
        
        # Build weighted selection for non-empty zones
        available_zones = []
        zone_weights = []
        
        weights = self.config.get_zone_weights()
        for zone_name in ["init", "core", "final"]:
            if zones[zone_name]:
                available_zones.append(zone_name)
                zone_weights.append(weights[zone_name])
        
        if not available_zones:
            return self.rng.choice(valid_steps)
        
        # Select zone then step
        chosen_zone = self.rng.choices(available_zones, weights=zone_weights, k=1)[0]
        selected_step = self.rng.choice(zones[chosen_zone])
        
        # Track which zone we selected from (for future adaptive weighting)
        self._zone_mutation_counts[chosen_zone] += 1
        
        return selected_step
    
    def record_result(self, result: Dict) -> None:
        """
        Record a mutation result for future coverage guidance.
        
        STUB: Currently stores data but does not use it for selection.
        
        Args:
            result: Dictionary containing mutation result information:
                - "step": int - The step that was mutated
                - "kind": str - The mutation kind
                - "outcome": str - CONSTRAINT_FAIL, WITNESS_FAIL, NO_EFFECT, VERIFIER_ACCEPTED
                - "new_coverage": int - Number of new unique constraints
                - "constraints": List[str] - Constraint locations triggered
        
        Future Use:
        -----------
        This data will be used to:
        1. Track coverage progress per step/kind combination
        2. Identify high-value steps for prioritization
        3. Detect diminishing returns (repeated mutations with no new coverage)
        4. Guide exploration toward under-tested execution regions
        """
        step = result.get("step")
        kind = result.get("kind", "unknown")
        new_coverage = result.get("new_coverage", 0)
        
        if step is None:
            return
        
        # Record that this step has been mutated for this kind
        if kind not in self._mutated_steps:
            self._mutated_steps[kind] = set()
        self._mutated_steps[kind].add(step)
        
        # Track high-value steps (those that found new coverage)
        if new_coverage > 0:
            current = self._high_value_steps.get(step, 0)
            self._high_value_steps[step] = current + new_coverage
    
    def get_coverage_stats(self) -> Dict:
        """
        Get coverage statistics for debugging and analysis.
        
        Returns:
            Dictionary with coverage tracking information
        """
        return {
            "mutated_steps_by_kind": {
                k: len(v) for k, v in self._mutated_steps.items()
            },
            "high_value_steps": len(self._high_value_steps),
            "zone_mutation_counts": dict(self._zone_mutation_counts),
        }


# =============================================================================
# Uniform-Arm Selector (Phase III.2)
# =============================================================================

class UniformArmSelector(StepSelector):
    """
    Pick (kind, bucket) uniformly at random over the bandit's arm universe,
    then pick a step uniformly at random inside that bucket. Independent of
    any reward signal — used as the fair learning-free baseline against the
    bandit (same arm universe and bucket discretisation, no UCB).

    Interface note:
      The legacy StepSelector contract is `select_step(data, kind)`, which
      assumes the caller has already chosen `kind`. UniformArmSelector
      cannot satisfy that contract while remaining truly uniform across the
      arm universe (it must couple kind+bucket draws). It exposes a new
      `select_arm_then_step()` method that returns (kind, step). The
      legacy `select_step` raises NotImplementedError so the fuzzer's
      dispatch branch is forced to use the new API.

    Determinism: a single Random instance seeds both draws, so passing
    the same `seed` reproduces an identical sequence of (kind, step) pairs.
    """

    def __init__(self, arm_universe: 'ArmUniverse', seed: Optional[int] = None):
        if arm_universe is None:
            raise ValueError("UniformArmSelector requires a non-None arm_universe")
        self.au = arm_universe
        self.rng = random.Random(seed)

    def select_arm_then_step(self) -> Tuple[str, int]:
        """Return (kind, step) drawn uniformly at random from the arm universe."""
        if not self.au.available_arms:
            raise RuntimeError("UniformArmSelector: arm universe has zero arms")
        kind, bucket = self.rng.choice(self.au.available_arms)
        steps = self.au.arms[(kind, bucket)]
        return kind, self.rng.choice(steps)

    def select_step(self, data: 'InspectionData', kind: str) -> Optional[int]:
        raise NotImplementedError(
            "UniformArmSelector uses select_arm_then_step(); "
            "the (data, kind) contract does not match its arm-coupled sampling."
        )


# =============================================================================
# Factory Function
# =============================================================================

def create_selector(
    strategy: str = "zoned",
    seed: Optional[int] = None,
    db: Optional['CoverageDB'] = None,
    config: Optional[ZoneConfig] = None,
    *,
    arm_universe: Optional['ArmUniverse'] = None,
) -> StepSelector:
    """
    Factory function to create a step selector.

    Args:
        strategy: Selection strategy:
            - "zoned":   Fixed 5%/90%/5% distribution (default, recommended).
            - "guided":  Coverage-guided with zoned base (stub for future).
            - "uniform": Phase III.2; uniform draw over (kind, bucket) arms,
                         requires `arm_universe`.
        seed: Random seed for reproducibility.
        db: CoverageDB instance (for "guided" strategy).
        config: ZoneConfig for custom zone weights (optional).
        arm_universe: ArmUniverse instance (required for "uniform"). Must be
                      passed by keyword to avoid breaking legacy 3-arg callers.

    Returns:
        Configured StepSelector instance.

    Examples:
        selector = create_selector("zoned", seed=12345)
        selector = create_selector("guided", seed=12345, db=coverage_db)
        selector = create_selector("uniform", seed=12345, arm_universe=au)
    """
    if strategy == "zoned":
        return ZonedStepSelector(seed=seed, config=config)
    elif strategy == "guided":
        return CoverageGuidedSelector(db=db, seed=seed, config=config)
    elif strategy == "uniform":
        if arm_universe is None:
            raise ValueError(
                "strategy='uniform' requires arm_universe to be passed "
                "(keyword-only). Build one from ArmUniverse(...)."
            )
        return UniformArmSelector(arm_universe=arm_universe, seed=seed)
    else:
        raise ValueError(
            f"Unknown strategy: {strategy}. "
            f"Valid options: 'zoned', 'guided', 'uniform' (and 'bandit' is "
            f"handled separately in fuzzer.py)."
        )
