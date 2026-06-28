"""IV.POS.9 V0 — tests for `SemanticUniformArmSelector`.

V0 = A4 surface, semantic-arm UNIFORM (no bandit). It draws an `ArmKey.v5(kind,zone)`
uniformly over the SAME `SemanticArmUniverse` V5 uses, then a step uniformly inside the
arm — the "arm semantics, no learning" rung of the scheduler ablation. See
a4/docs/cloud3/bug_race_a4_arguzz_scheduler/.
"""
from collections import Counter
from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo, A4AllTxn
from a4.core.inspection_data import InspectionData

_USER_REGS = 1073725472
from a4.standalone.semantic_arm_universe import SemanticArmUniverse
from a4.standalone.step_selector import SemanticUniformArmSelector


def _make_cycle(step: int, major: int) -> A4CycleInfo:
    return A4CycleInfo(cycle_idx=step, step=step, pc=0, txn_idx=0, major=major, minor=0)


def _reg_write(step: int, reg_idx: int = 10, word: int = 1) -> A4AllTxn:
    return A4AllTxn(
        txn_idx=step * 100 + reg_idx, step=step, txn_type="reg",
        addr=_USER_REGS + reg_idx, cycle=1, word=word, prev_cycle=0, prev_word=0,
    )


def _build_data(cycles: List[A4CycleInfo]) -> InspectionData:
    txns = [_reg_write(2), _reg_write(3)]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


@pytest.fixture
def au():
    cycles = [
        _make_cycle(0, major=0), _make_cycle(1, major=0),
        _make_cycle(2, major=5), _make_cycle(3, major=5),
        _make_cycle(4, major=0), _make_cycle(5, major=0),
    ]
    return SemanticArmUniverse.build(
        _build_data(cycles), ["COMP_OUT_MOD", "LOAD_VAL_MOD", "INSTR_TYPE_MOD"],
    )


def test_requires_arm_universe():
    with pytest.raises(ValueError):
        SemanticUniformArmSelector(arm_universe=None)


def test_returns_valid_kind_and_step(au):
    sel = SemanticUniformArmSelector(au, seed=42)
    valid = {(arm.kind, s) for arm in au.available_arms for s in au.steps_for_arm(arm)}
    assert valid, "fixture produced no arms"
    for _ in range(300):
        assert sel.select_arm_then_step() in valid


def test_uniform_over_arms(au):
    """The KEY property: arms (not kinds, not steps) are drawn uniformly."""
    arms = au.available_arms
    assert len(arms) >= 2
    ks_to_arm = {(arm.kind, s): arm for arm in arms for s in au.steps_for_arm(arm)}
    sel = SemanticUniformArmSelector(au, seed=7)
    n = len(arms)
    N = 3000 * n
    counts = Counter()
    for _ in range(N):
        counts[ks_to_arm[sel.select_arm_then_step()]] += 1
    exp = N / n
    for arm in arms:
        assert counts[arm] > 0, f"arm {arm} never selected"
        assert abs(counts[arm] - exp) < 0.2 * exp, f"{arm}: {counts[arm]} vs exp {exp:.0f}"


def test_instr_type_mod_reachable(au):
    """V0 must be able to apply INSTR_TYPE_MOD — the only bug-reaching kind."""
    sel = SemanticUniformArmSelector(au, seed=3)
    kinds = {sel.select_arm_then_step()[0] for _ in range(500)}
    assert "INSTR_TYPE_MOD" in kinds


def test_determinism(au):
    s1 = SemanticUniformArmSelector(au, seed=99)
    s2 = SemanticUniformArmSelector(au, seed=99)
    assert [s1.select_arm_then_step() for _ in range(50)] == \
           [s2.select_arm_then_step() for _ in range(50)]


def test_select_step_legacy_raises(au):
    sel = SemanticUniformArmSelector(au, seed=1)
    with pytest.raises(NotImplementedError):
        sel.select_step(data=None, kind="INSTR_TYPE_MOD")
