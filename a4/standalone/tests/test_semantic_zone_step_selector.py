"""
Phase 2 (cloud1) — tests for `SemanticZoneStepSelector`.
"""

from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.semantic_arm_universe import SemanticArmUniverse
from a4.standalone.step_selector import SemanticZoneStepSelector


def _make_cycle(step: int, major: int) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0, txn_idx=0,
        major=major, minor=0,
    )


def _build_data(cycles: List[A4CycleInfo]) -> InspectionData:
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


@pytest.fixture
def au():
    cycles = [
        _make_cycle(0, major=0),   # step0
        _make_cycle(1, major=0),
        _make_cycle(2, major=5),   # LOAD
        _make_cycle(3, major=5),   # LOAD
        _make_cycle(4, major=0),
        _make_cycle(5, major=0),   # last_step
    ]
    return SemanticArmUniverse.build(
        _build_data(cycles),
        ["COMP_OUT_MOD", "LOAD_VAL_MOD", "INSTR_TYPE_MOD"],
    )


def test_requires_arm_universe():
    with pytest.raises(ValueError):
        SemanticZoneStepSelector(arm_universe=None)


def test_singleton_zone_is_deterministic(au):
    sel = SemanticZoneStepSelector(au, seed=42)
    step = sel.pick_step_in_zone("INSTR_TYPE_MOD", "step0")
    assert step == 0  # only step in step0 zone


def test_broad_zone_samples_uniformly_from_arm_steps(au):
    sel = SemanticZoneStepSelector(au, seed=42)
    valid = {2, 3}
    for _ in range(30):
        s = sel.pick_step_in_zone("LOAD_VAL_MOD", "core_memory_load")
        assert s in valid


def test_seed_makes_selection_deterministic(au):
    s1 = SemanticZoneStepSelector(au, seed=42)
    s2 = SemanticZoneStepSelector(au, seed=42)
    picks1 = [s1.pick_step_in_zone("LOAD_VAL_MOD", "core_memory_load") for _ in range(20)]
    picks2 = [s2.pick_step_in_zone("LOAD_VAL_MOD", "core_memory_load") for _ in range(20)]
    assert picks1 == picks2


def test_empty_arm_returns_none(au):
    sel = SemanticZoneStepSelector(au, seed=42)
    # (LOAD_VAL_MOD, step0) should not exist (step 0 is major=0, not 5)
    assert sel.pick_step_in_zone("LOAD_VAL_MOD", "step0") is None


def test_select_step_legacy_interface_raises(au):
    sel = SemanticZoneStepSelector(au, seed=42)
    with pytest.raises(NotImplementedError):
        # Synthetic data isn't needed for the raise; pass any data.
        sel.select_step(data=None, kind="INSTR_TYPE_MOD")
