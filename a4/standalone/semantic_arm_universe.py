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
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING, Union

from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, BOUNDARY_ZONES,
)
from a4.standalone.zone_classifier import zone_to_steps
from a4.standalone.mutations import comp_out_mod, load_val_mod, store_out_mod
from a4.standalone.mutations import pre_exec_reg_mod, instr_type_mod, mem_val_mod
from a4.standalone.mutations import instr_word_mod, instr_word_mod_sur
from a4.standalone.mutations import txn_prev_word_mod
from a4.standalone.mutations import txn_prev_cycle_mod, cycle_mode_mod
from a4.standalone.mutations import txn_addr_mod, txn_cycle_phase_mod
from a4.standalone.mutations import cycle_pc_mod, cycle_state_mod, cycle_diff_count_mod

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

_MUTATION_MODULES = {
    "COMP_OUT_MOD": comp_out_mod,
    "LOAD_VAL_MOD": load_val_mod,
    "STORE_OUT_MOD": store_out_mod,
    "PRE_EXEC_REG_MOD": pre_exec_reg_mod,
    "INSTR_TYPE_MOD": instr_type_mod,
    "MEM_VAL_MOD": mem_val_mod,
    "INSTR_WORD_MOD_FULL": instr_word_mod,
    "INSTR_WORD_MOD_SUR": instr_word_mod_sur,
    "TXN_PREV_WORD_MOD": txn_prev_word_mod,
    "TXN_PREV_CYCLE_MOD": txn_prev_cycle_mod,
    "CYCLE_MODE_MOD": cycle_mode_mod,
    "TXN_ADDR_MOD": txn_addr_mod,
    "TXN_CYCLE_PHASE_MOD": txn_cycle_phase_mod,
    "CYCLE_PC_MOD": cycle_pc_mod,
    "CYCLE_STATE_MOD": cycle_state_mod,
    "CYCLE_DIFF_COUNT_MOD": cycle_diff_count_mod,
}

def _cycle_matches_kind_filter(kind: str, cycle, data: "InspectionData") -> bool:
    """True if this cycle would contribute the step to get_valid_steps_for_kind."""
    if kind == "COMP_OUT_MOD":
        return cycle.major in (0, 1, 2, 3, 4)
    if kind == "LOAD_VAL_MOD":
        return cycle.major == 5
    if kind == "STORE_OUT_MOD":
        return cycle.major == 6
    if kind in ("PRE_EXEC_REG_MOD", "INSTR_TYPE_MOD"):
        return cycle.major <= 6
    if kind == "MEM_VAL_MOD":
        return cycle.step in data._step_to_mem_txns
    if kind in ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR"):
        return cycle.major <= 6 or cycle.major == 8
    if kind == "TXN_PREV_WORD_MOD":
        return cycle.step != 0 and cycle.step in data._step_to_all_txns
    if kind == "TXN_PREV_CYCLE_MOD":
        return cycle.step != 0 and cycle.step in data._step_to_all_txns
    if kind == "CYCLE_MODE_MOD":
        return cycle.step != 0
    if kind == "TXN_ADDR_MOD":
        return cycle.step != 0 and cycle.step in data._step_to_mem_txns
    if kind == "TXN_CYCLE_PHASE_MOD":
        return cycle.step != 0 and cycle.step in data._step_to_all_txns
    if kind == "CYCLE_PC_MOD":
        return cycle.step != 0 and cycle.major <= 6
    if kind in ("CYCLE_STATE_MOD", "CYCLE_DIFF_COUNT_MOD"):
        return cycle.step != 0
    return True


def _matching_cycles_at_step(kind: str, step: int, data: "InspectionData") -> int:
    """Count cycles at step that match the kind's major/txn filter (D40)."""
    return sum(
        1 for c in data.cycles
        if c.step == step and _cycle_matches_kind_filter(kind, c, data)
    )


_MAJOR_FILTER_KINDS = frozenset({
    "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD", "INSTR_TYPE_MOD",
    "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR",
    "CYCLE_PC_MOD",
})


def _step_has_real_target(kind: str, step: int, data: "InspectionData") -> bool:
    # D40 option (b): drop multi-cycle steps for major-filter kinds only.
    # MEM_VAL_MOD has no major filter (D40 brief: "match the kind's major filter").
    if kind in _MAJOR_FILTER_KINDS and _matching_cycles_at_step(kind, step, data) > 1:
        return False
    mod = _MUTATION_MODULES.get(kind)
    if mod is None:
        return True
    try:
        if kind == "PRE_EXEC_REG_MOD":
            t_read = mod.get_targets_at_step(step, data, strategy="next_read")
            t_write = mod.get_targets_at_step(step, data, strategy="prev_write")
            t = t_read or t_write
        elif kind == "TXN_PREV_WORD_MOD":
            t_read = mod.get_targets_at_step(step, data, strategy="at_read")
            t_write = mod.get_targets_at_step(step, data, strategy="at_write")
            t = t_read or t_write
        elif kind == "TXN_PREV_CYCLE_MOD":
            t = mod.get_targets_at_step(step, data)
        elif kind == "CYCLE_MODE_MOD":
            t = mod.get_targets_at_step(step, data)
            t = [t] if t is not None else []
        elif kind == "TXN_ADDR_MOD":
            t = mod.get_targets_at_step(step, data)
        elif kind == "TXN_CYCLE_PHASE_MOD":
            t = mod.get_targets_at_step(step, data)
        elif kind == "CYCLE_PC_MOD":
            t = mod.get_targets_at_step(step, data)
            t = [t] if t is not None else []
        elif kind == "CYCLE_STATE_MOD":
            t = mod.get_targets_at_step(step, data)
            t = [t] if t is not None else []
        elif kind == "CYCLE_DIFF_COUNT_MOD":
            t = mod.get_all_targets(data)
            t = [x for x in t if x.step == step]
        else:
            t = mod.get_targets_at_step(step, data)
    except Exception:
        return False
    if isinstance(t, list):
        return bool(t)
    return t is not None


def _filter_real_target_steps(
    kind: str,
    zone_steps: List[int],
    data: "InspectionData",
) -> List[int]:
    """Keep only steps where the mutation module's getter succeeds."""
    if not zone_steps:
        return []
    return sorted(
        s for s in zone_steps if _step_has_real_target(kind, s, data)
    )


# ---------------------------------------------------------------------------
# Arm key — D2.A 5-tuple (surface, kind, zone, opcode_class, pre_post)
# ---------------------------------------------------------------------------

A4_TRACE_CELL = "A4_trace_cell"
ARGUZZ_EXEC_FAULT = "arguzz_exec_fault"
NA = "n/a"


@dataclass(frozen=True, order=True)
class ArmKey:
    """Bandit arm identity for Hybrid V7 (D2.A). Hashable dict key."""

    surface: str
    kind: str
    zone: str
    opcode_class: str
    pre_post: str

    @classmethod
    def v5(cls, kind: str, zone: str) -> "ArmKey":
        """V5 / pure-A4 arm with collapsed opcode_class and pre_post."""
        return cls(A4_TRACE_CELL, kind, zone, NA, NA)

    def as_tuple(self) -> Tuple[str, str, str, str, str]:
        return (self.surface, self.kind, self.zone, self.opcode_class, self.pre_post)

    def is_v5_shape(self) -> bool:
        return (
            self.surface == A4_TRACE_CELL
            and self.opcode_class == NA
            and self.pre_post == NA
        )

    def __str__(self) -> str:
        if self.is_v5_shape():
            return f"{self.kind}|{self.zone}"
        return (
            f"{self.surface}|{self.kind}|{self.zone}|"
            f"{self.opcode_class}|{self.pre_post}"
        )

    @classmethod
    def parse(cls, arm_id_str: str) -> "ArmKey":
        parts = arm_id_str.split("|")
        if len(parts) == 2:
            return cls.v5(parts[0], parts[1])
        if len(parts) == 5:
            return cls(*parts)
        raise ValueError(f"invalid arm_id string: {arm_id_str!r}")

    def __iter__(self):
        """Back-compat: `kind, zone = arm` in legacy call sites."""
        yield self.kind
        yield self.zone


def kind_of(arm: Union[ArmKey, Tuple[str, str]]) -> str:
    if isinstance(arm, ArmKey):
        return arm.kind
    return arm[0]


def zone_of(arm: Union[ArmKey, Tuple[str, str]]) -> str:
    if isinstance(arm, ArmKey):
        return arm.zone
    return arm[1]


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
                if not zone_steps_in_kind:
                    continue
                real_steps = _filter_real_target_steps(
                    kind, zone_steps_in_kind, data,
                )
                if not real_steps:
                    continue
                arms[ArmKey.v5(kind, zone)] = real_steps

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
        return self.arms.get(ArmKey.v5(kind, zone), [])

    def steps_for_arm(self, arm: ArmKey) -> List[int]:
        """Return valid steps for an `ArmKey`."""
        return self.arms.get(arm, [])

    def zones_for_kind(self, kind: str) -> List[str]:
        """Return all zones that contain at least one valid step for `kind`."""
        return sorted({z for (k, z) in ((a.kind, a.zone) for a in self.arms) if k == kind})

    def kinds_for_zone(self, zone: str) -> List[str]:
        """Return all kinds with at least one valid step in `zone`."""
        return sorted({k for (k, z) in ((a.kind, a.zone) for a in self.arms) if z == zone})

    def singleton_arms(self) -> List[ArmKey]:
        """Arms whose step set has exactly one step AND whose zone is a
        SINGLETON_ZONE. These get the forced-pull floor from
        ConstrainedTSScheduler (Pro §7.A)."""
        return sorted(
            arm for arm, steps in self.arms.items()
            if arm.zone in SINGLETON_ZONES and len(steps) == 1
        )

    def boundary_arms(self) -> List[ArmKey]:
        """All arms whose zone is in BOUNDARY_ZONES (used for boundary
        floor in ConstrainedTSScheduler — Pro §7.C 'minimum pulls for
        boundary zones')."""
        return sorted(
            arm for arm in self.arms if arm.zone in BOUNDARY_ZONES
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
            total_steps_for_kind = sum(len(steps) for arm, steps in self.arms.items() if arm.kind == k)
            lines.append(
                f"    {k:25} {len(zones):>3} zones, "
                f"{total_steps_for_kind:>5} steps total"
            )
        lines.append("")
        lines.append("  Arms per zone (kind counts):")
        from a4.standalone.semantic_zones import SEMANTIC_ZONES as ALL_Z
        for z in ALL_Z:
            kinds = self.kinds_for_zone(z)
            total_steps_for_zone = sum(len(steps) for arm, steps in self.arms.items() if arm.zone == z)
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


__all__ = [
    "A4_TRACE_CELL",
    "ARGUZZ_EXEC_FAULT",
    "ArmKey",
    "NA",
    "SemanticArmUniverse",
    "kind_of",
    "zone_of",
]
