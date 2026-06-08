"""
Semantic arm universe — replaces the geometric `ArmUniverse` (kind × time
bucket) with a SEMANTIC arm space (kind × semantic_zone) per
ProG_Report_2.md §7.A.

Each "arm" is a `(mutation_kind, semantic_zone)` pair whose step set is
the intersection of:
    - steps where `mutation_kind` is applicable
      (from `InspectionData.get_valid_steps_for_kind(kind)`)
    - steps assigned to `semantic_zone`
      (from `zone_classifier.zone_to_steps(data)[zone]`)

Arms with empty intersections are SKIPPED (cloud1 D7: define all 17 zones,
runtime-skip empty). This makes the same code work across guest programs:
sha2-host doesn't use Poseidon so all `(*, core_poseidon)` arms are dropped
without changing user code.

This module does NOT touch the existing `ArmUniverse` in `arm_universe.py`,
which remains the basis for the legacy `arm_uniform_b128` / `ucb_kindbucket_b16`
strategies. The two coexist; the IV.POS.7 dispatcher picks one based on the
selected strategy.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, BOUNDARY_ZONES,
)
from a4.standalone.zone_classifier import zone_to_steps

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


# An arm key is the pair `(mutation_kind, semantic_zone)`. We use string
# tuples directly instead of a dataclass for keyspace simplicity (these
# are hashable, comparable, and pickleable out of the box).
ArmKey = Tuple[str, str]


@dataclass
class SemanticArmUniverse:
    """The (kind, semantic_zone) action space.

    Build with `SemanticArmUniverse.build(data, mutation_kinds)`.
    """

    mutation_kinds: List[str]
    arms: Dict[ArmKey, List[int]]            # arm → sorted valid steps
    zone_step_map: Dict[str, List[int]]      # zone → sorted steps (full trace)
    valid_steps_by_kind: Dict[str, List[int]]
    total_steps: int

    @classmethod
    def build(
        cls,
        data: "InspectionData",
        mutation_kinds: List[str],
    ) -> "SemanticArmUniverse":
        """Build the semantic arm universe from inspection data."""
        z2s = zone_to_steps(data)

        valid_by_kind: Dict[str, List[int]] = {}
        for k in mutation_kinds:
            valid_by_kind[k] = data.get_valid_steps_for_kind(k)

        arms: Dict[ArmKey, List[int]] = {}
        for kind in mutation_kinds:
            valid_set = set(valid_by_kind[kind])
            for zone in SEMANTIC_ZONES:
                zone_steps_in_kind = sorted(valid_set & set(z2s.get(zone, [])))
                if zone_steps_in_kind:
                    arms[(kind, zone)] = zone_steps_in_kind

        return cls(
            mutation_kinds=list(mutation_kinds),
            arms=arms,
            zone_step_map={z: list(z2s.get(z, [])) for z in SEMANTIC_ZONES},
            valid_steps_by_kind=valid_by_kind,
            total_steps=data.total_steps,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def available_arms(self) -> List[ArmKey]:
        """Sorted list of (kind, zone) pairs with at least one valid step."""
        return sorted(self.arms.keys())

    @property
    def num_arms(self) -> int:
        return len(self.arms)

    def steps_in_arm(self, kind: str, zone: str) -> List[int]:
        """Return the (sorted) valid steps for `(kind, zone)`, or []."""
        return self.arms.get((kind, zone), [])

    def zones_for_kind(self, kind: str) -> List[str]:
        """Return all zones that contain at least one valid step for `kind`."""
        return sorted({z for (k, z) in self.arms if k == kind})

    def kinds_for_zone(self, zone: str) -> List[str]:
        """Return all kinds with at least one valid step in `zone`."""
        return sorted({k for (k, z) in self.arms if z == zone})

    def singleton_arms(self) -> List[ArmKey]:
        """Arms whose step set has exactly one step AND whose zone is a
        SINGLETON_ZONE. These get the forced-pull floor from
        ConstrainedTSScheduler (Pro §7.A)."""
        return sorted(
            (k, z) for (k, z), steps in self.arms.items()
            if z in SINGLETON_ZONES and len(steps) == 1
        )

    def boundary_arms(self) -> List[ArmKey]:
        """All arms whose zone is in BOUNDARY_ZONES (used for boundary
        floor in ConstrainedTSScheduler — Pro §7.C 'minimum pulls for
        boundary zones')."""
        return sorted(
            (k, z) for (k, z) in self.arms.keys() if z in BOUNDARY_ZONES
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Human-readable summary of the arm structure."""
        lines = [
            f"SemanticArmUniverse:",
            f"  Total steps:        {self.total_steps}",
            f"  Mutation kinds (K): {len(self.mutation_kinds)}",
            f"  Total available arms: {self.num_arms}",
            f"  Boundary arms:      {len(self.boundary_arms())}",
            f"  Singleton arms:     {len(self.singleton_arms())}",
            "",
            "  Arms per kind (zone counts):",
        ]
        for k in self.mutation_kinds:
            zones = self.zones_for_kind(k)
            total_steps_for_kind = sum(len(self.arms[(k, z)]) for z in zones)
            lines.append(
                f"    {k:25} {len(zones):>3} zones, "
                f"{total_steps_for_kind:>5} steps total"
            )
        lines.append("")
        lines.append("  Arms per zone (kind counts):")
        from a4.standalone.semantic_zones import SEMANTIC_ZONES as ALL_Z
        for z in ALL_Z:
            kinds = self.kinds_for_zone(z)
            total_steps_for_zone = sum(len(self.arms[(k, z)]) for k in kinds)
            marker = ""
            if z in SINGLETON_ZONES:
                marker = " (singleton)"
            elif z in BOUNDARY_ZONES:
                marker = " (boundary)"
            lines.append(
                f"    {z:20} {len(kinds):>3} kinds, "
                f"{total_steps_for_zone:>5} steps{marker}"
            )
        return "\n".join(lines)


__all__ = ["SemanticArmUniverse", "ArmKey"]
