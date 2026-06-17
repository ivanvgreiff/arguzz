"""
Phase 2 (cloud1) — tests for `semantic_arm_universe.py`.

Verifies:
    - `SemanticArmUniverse.build()` produces the correct (kind, zone) →
      step-list mapping for a synthetic InspectionData
    - empty intersections are SKIPPED (D7: define all 17, runtime-skip empty)
    - `singleton_arms()` and `boundary_arms()` accessors return correct subsets
    - `zones_for_kind()` and `kinds_for_zone()` are correct
    - the summary string runs and contains the expected info
"""

from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo, A4AllTxn
from a4.core.inspection_data import InspectionData

_USER_REGS = 1073725472


def _reg_txn(
    step: int,
    reg_idx: int = 10,
    word: int = 1,
    *,
    is_write: bool = True,
) -> A4AllTxn:
    return A4AllTxn(
        txn_idx=step * 100 + reg_idx,
        step=step,
        txn_type="reg",
        addr=_USER_REGS + reg_idx,
        cycle=1 if is_write else 0,
        word=word,
        prev_cycle=0,
        prev_word=word if not is_write else 0,
    )
from a4.standalone.semantic_arm_universe import ArmKey, SemanticArmUniverse
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, BOUNDARY_ZONES, USER_PC_RANGE,
)

_USER_PC = USER_PC_RANGE[0] + 0x1000


def _make_cycle(
    step: int,
    major: int,
    minor: int = 0,
    *,
    pc: int = 0,
) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=pc, txn_idx=0,
        major=major, minor=minor,
    )


def _build_data(
    cycles: List[A4CycleInfo],
    write_steps: List[int] | None = None,
    read_steps: List[int] | None = None,
) -> InspectionData:
    """Synthetic trace with register txns so target getters see real targets."""
    txns: List[A4AllTxn] = []
    for s in write_steps or []:
        txns.append(_reg_txn(s, is_write=True))
    for s in read_steps or []:
        txns.append(_reg_txn(s, reg_idx=5, is_write=False))
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def small_data():
    """4 ALU steps + 2 LOAD + 1 STORE + 1 ECALL + last step."""
    cycles = [
        _make_cycle(0, major=0),    # step0
        _make_cycle(1, major=0),    # ALU
        _make_cycle(2, major=5),    # LOAD
        _make_cycle(3, major=5),    # LOAD
        _make_cycle(4, major=6),    # STORE
        _make_cycle(5, major=8),    # ECALL → pre_ecall
        _make_cycle(6, major=0, pc=_USER_PC),  # D53 post_ecall (user PC at e+1)
        _make_cycle(7, major=0),    # last_step
    ]
    return _build_data(
        cycles,
        write_steps=[0, 1, 2, 3, 4, 6, 7],
        read_steps=[0],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_build_returns_arm_universe(small_data):
    au = SemanticArmUniverse.build(
        small_data,
        ["COMP_OUT_MOD", "LOAD_VAL_MOD", "INSTR_TYPE_MOD"],
    )
    assert isinstance(au, SemanticArmUniverse)
    assert au.total_steps == 8
    assert au.mutation_kinds == ["COMP_OUT_MOD", "LOAD_VAL_MOD", "INSTR_TYPE_MOD"]
    assert au.num_arms > 0


def test_empty_intersections_are_skipped(small_data):
    """No arm should exist for (LOAD_VAL_MOD, core_arithmetic) because
    LOAD_VAL_MOD only applies to major=5, and no major=5 cycle is in
    core_arithmetic."""
    au = SemanticArmUniverse.build(small_data, ["LOAD_VAL_MOD"])
    assert ArmKey.v5("LOAD_VAL_MOD", "core_arithmetic") not in au.arms
    assert ArmKey.v5("LOAD_VAL_MOD", "core_memory_load") in au.arms
    assert au.steps_in_arm("LOAD_VAL_MOD", "core_memory_load") == [2, 3]


def test_singleton_arms_for_instr_type_mod(small_data):
    """INSTR_TYPE_MOD applies to majors 0-6 (per inspection_data.py:194-197).
    Step 0 is one such step → (INSTR_TYPE_MOD, step0) is a singleton arm."""
    au = SemanticArmUniverse.build(small_data, ["INSTR_TYPE_MOD"])
    singletons = au.singleton_arms()
    assert ArmKey.v5("INSTR_TYPE_MOD", "step0") in singletons
    # last_step at step 7 also a singleton (major=0 → INSTR_TYPE_MOD applies)
    assert ArmKey.v5("INSTR_TYPE_MOD", "last_step") in singletons


def test_boundary_arms_for_instr_type_mod_excludes_pre_ecall(small_data):
    """For INSTR_TYPE_MOD (major 0-6 only), pre_ecall is STRUCTURALLY EMPTY.

    The ECALL cycle has major=8, which falls outside INSTR_TYPE_MOD's
    applicability (majors 0-6 per inspection_data.py:194-197). So the
    (INSTR_TYPE_MOD, pre_ecall) arm doesn't exist and is correctly
    omitted from boundary_arms().

    This is a structural property of the new arm space worth noting for
    Pro Round 2: certain (kind, zone) pairs are ALWAYS empty for any guest
    because of opcode-class incompatibility. The constrained TS bandit must
    handle this gracefully (it does, via runtime-skip of empty arms — D7).
    """
    au = SemanticArmUniverse.build(small_data, ["INSTR_TYPE_MOD"])
    barms = au.boundary_arms()
    boundary_zones_in_arms = {a.zone for a in barms}
    assert "step0" in boundary_zones_in_arms
    assert "last_step" in boundary_zones_in_arms
    # pre_ecall is structurally empty for INSTR_TYPE_MOD (ECALL has major 8;
    # INSTR_TYPE_MOD only applies to majors 0-6):
    assert "pre_ecall" not in boundary_zones_in_arms
    # post_ecall is the cycle AFTER an ECALL — for INSTR_TYPE_MOD that
    # cycle's major can be 0-6 (in small_data it's major=0), so present:
    assert "post_ecall" in boundary_zones_in_arms
    # NO core zones should appear in boundary arms
    assert not (boundary_zones_in_arms & {"core_arithmetic", "core_memory_load"})


def test_boundary_arms_for_instr_word_mod_includes_pre_ecall(small_data):
    """INSTR_WORD_MOD applies to majors 0-6 AND major 8 (per
    inspection_data.py:211). So (INSTR_WORD_MOD, pre_ecall) is non-empty
    when an ECALL cycle exists. This shows the structural sampler reaches
    ECALL cycles correctly for this kind."""
    au = SemanticArmUniverse.build(small_data, ["INSTR_WORD_MOD"])
    barms = au.boundary_arms()
    boundary_zones_in_arms = {a.zone for a in barms}
    assert "pre_ecall" in boundary_zones_in_arms
    # The ECALL cycle is at step 5 in small_data:
    assert au.steps_in_arm("INSTR_WORD_MOD", "pre_ecall") == [5]


def test_zones_for_kind(small_data):
    au = SemanticArmUniverse.build(small_data, ["COMP_OUT_MOD"])
    # COMP_OUT_MOD applies to majors 0-4 (compute insts).
    # In small_data: cycles 0,1,6,7 are major=0; ECALL=8 excluded; LOAD/STORE excluded
    zones = au.zones_for_kind("COMP_OUT_MOD")
    assert "step0" in zones
    assert "last_step" in zones
    assert "post_ecall" in zones  # step 6 = major=0 → post_ecall by rule 3
    assert "core_arithmetic" in zones  # step 1
    # Should NOT include load/store/ecall zones
    assert "core_memory_load" not in zones
    assert "pre_ecall" not in zones


def test_kinds_for_zone_step0(small_data):
    au = SemanticArmUniverse.build(small_data, [
        "COMP_OUT_MOD", "INSTR_TYPE_MOD", "PRE_EXEC_REG_MOD",
        "LOAD_VAL_MOD", "STORE_OUT_MOD",
    ])
    # Step 0 = major=0 (MISC0/ALU). Applicable mutation kinds:
    #   COMP_OUT_MOD       (major 0-4): YES
    #   INSTR_TYPE_MOD     (major 0-6): YES
    #   PRE_EXEC_REG_MOD   (major 0-6): YES
    #   LOAD_VAL_MOD       (major 5):   NO
    #   STORE_OUT_MOD      (major 6):   NO
    kinds = au.kinds_for_zone("step0")
    assert set(kinds) == {"COMP_OUT_MOD", "INSTR_TYPE_MOD", "PRE_EXEC_REG_MOD"}


def test_kinds_for_zone_unused_zone_is_empty(small_data):
    au = SemanticArmUniverse.build(small_data, ["LOAD_VAL_MOD"])
    # No Poseidon cycles in small_data → no kinds in core_poseidon
    assert au.kinds_for_zone("core_poseidon") == []


def test_available_arms_sorted(small_data):
    au = SemanticArmUniverse.build(small_data, ["COMP_OUT_MOD", "LOAD_VAL_MOD"])
    arms = au.available_arms
    assert arms == sorted(arms)


def test_summary_runs_without_crash(small_data):
    au = SemanticArmUniverse.build(
        small_data,
        ["COMP_OUT_MOD", "LOAD_VAL_MOD", "INSTR_TYPE_MOD"],
    )
    s = au.summary()
    assert "SemanticArmUniverse" in s
    assert "Total available arms" in s
    assert "Boundary arms" in s
    assert "Singleton arms" in s
