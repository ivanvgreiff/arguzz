"""
Phase 2 (cloud1) — tests for `zone_classifier.py`.
"""

from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.zone_classifier import (
    classify_zones, zone_to_steps, summarize_zones, ECALL_MAJOR,
)
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, USER_PC_RANGE, KERNEL_PC_RANGE,
)

_USER_PC = USER_PC_RANGE[0]
_KERNEL_PC = KERNEL_PC_RANGE[0]


def _make_cycle(step: int, major: int, minor: int = 0, pc: int = _USER_PC) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=pc, txn_idx=0,
        major=major, minor=minor,
    )


def _build_data(cycles: List[A4CycleInfo]) -> InspectionData:
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


def test_empty_inspection_returns_empty_zones():
    data = _build_data([])
    assert classify_zones(data) == {}
    z2s = zone_to_steps(data)
    assert set(z2s.keys()) == set(SEMANTIC_ZONES)
    for v in z2s.values():
        assert v == []


def test_single_step_is_step0_not_last_step():
    data = _build_data([_make_cycle(0, major=0, pc=_KERNEL_PC)])
    z = classify_zones(data)
    assert z[0] == "step0"
    z2s = zone_to_steps(data)
    assert z2s["step0"] == [0]
    assert z2s["last_step"] == []


def test_two_steps_step0_and_last_step():
    data = _build_data([
        _make_cycle(0, major=0),
        _make_cycle(1, major=0),
    ])
    z = classify_zones(data)
    assert z[0] == "step0"
    assert z[1] == "last_step"


def test_fallback_by_major_user_pc():
    data = _build_data([
        _make_cycle(0, major=0),
        _make_cycle(1, major=0),
        _make_cycle(2, major=3),
        _make_cycle(3, major=4, minor=0),
        _make_cycle(4, major=4, minor=4),
        _make_cycle(5, major=5),
        _make_cycle(6, major=6),
        _make_cycle(7, major=7),
        _make_cycle(8, major=11),
        _make_cycle(9, major=9),
        _make_cycle(10, major=10),
        _make_cycle(11, major=12),
        _make_cycle(12, major=2),
    ])
    z = classify_zones(data)
    assert z[0] == "step0"
    assert z[1] == "core_arithmetic"
    assert z[2] == "core_mul"
    assert z[3] == "core_shr"
    assert z[4] == "core_div"
    assert z[5] == "core_memory_load"
    assert z[6] == "core_memory_store"
    assert z[7] == "core_branch"
    assert z[8] == "core_sha"
    assert z[9] == "core_poseidon"
    assert z[10] == "core_poseidon"
    assert z[11] == "core_other"
    assert z[12] == "last_step"


def test_kernel_pc_becomes_kernel_other():
    data = _build_data([
        _make_cycle(0, major=0, pc=_KERNEL_PC),
        _make_cycle(1, major=2, pc=_KERNEL_PC),
        _make_cycle(2, major=0),
    ])
    z = classify_zones(data)
    assert z[0] == "step0"
    assert z[1] == "kernel_other"
    assert z[2] == "last_step"


def test_ecall_cycle_becomes_pre_ecall():
    data = _build_data([
        _make_cycle(0, major=0),
        _make_cycle(1, major=0),
        _make_cycle(2, major=ECALL_MAJOR, pc=_KERNEL_PC),
        _make_cycle(3, major=0, pc=_USER_PC),
        _make_cycle(4, major=0),
        _make_cycle(5, major=0),
    ])
    z = classify_zones(data)
    assert z[2] == "pre_ecall"
    assert z[3] == "post_ecall"


def test_post_ecall_skips_kernel_handler_to_user_return():
    """D53: e+1 kernel, e+2 user → post_ecall at e+2."""
    data = _build_data([
        _make_cycle(0, major=0),
        _make_cycle(1, major=ECALL_MAJOR, pc=_KERNEL_PC),
        _make_cycle(2, major=0, pc=_KERNEL_PC),
        _make_cycle(3, major=0, pc=_USER_PC),
        _make_cycle(4, major=0),
    ])
    z = classify_zones(data)
    assert z[1] == "pre_ecall"
    assert z[2] == "kernel_other"
    assert z[3] == "post_ecall"


def test_ecall_at_boundary_does_not_overwrite_singleton():
    data = _build_data([
        _make_cycle(0, major=ECALL_MAJOR, pc=_KERNEL_PC),
        _make_cycle(1, major=0, pc=_USER_PC),
        _make_cycle(2, major=0),
        _make_cycle(3, major=ECALL_MAJOR, pc=_KERNEL_PC),
    ])
    z = classify_zones(data)
    assert z[0] == "step0"
    assert z[1] == "post_ecall"
    assert z[2] == "core_arithmetic"
    assert z[3] == "last_step"


def test_multiple_ecalls():
    cycles = []
    for s in range(20):
        if s in (5, 12, 17):
            cycles.append(_make_cycle(s, major=ECALL_MAJOR, pc=_KERNEL_PC))
        elif s in (6, 13, 18):
            cycles.append(_make_cycle(s, major=0, pc=_USER_PC))
        else:
            cycles.append(_make_cycle(s, major=0))
    data = _build_data(cycles)
    z2s = zone_to_steps(data)
    assert z2s["pre_ecall"] == [5, 12, 17]
    assert z2s["post_ecall"] == [6, 13, 18]


def test_all_zones_in_output_dict():
    data = _build_data([_make_cycle(0, major=0), _make_cycle(1, major=0)])
    z2s = zone_to_steps(data)
    assert set(z2s.keys()) == set(SEMANTIC_ZONES)
    assert z2s["core_poseidon"] == []
    assert z2s["pre_mret"] == []
    assert z2s["kernel_other"] == []


def test_summarize_zones_runs_without_crash():
    data = _build_data([_make_cycle(0, major=0), _make_cycle(1, major=0)])
    s = summarize_zones(data)
    assert "Zone populations" in s
    assert "kernel_other" not in s or "boundary" in s
