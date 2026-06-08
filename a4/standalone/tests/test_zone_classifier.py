"""
Phase 2 (cloud1) — tests for `zone_classifier.py`.

Uses synthetic `InspectionData` fixtures (no host binary needed) to validate
the classification rules in priority order:
    1. step0 wins absolutely
    2. last_step wins over fallback (but not step0 if T==1)
    3. ECALL cycle (major=8) goes to pre_ecall; e+1 to post_ecall
    4. fallback by major
    5. all 17 zones present in the output dict (empty allowed)

A separate test runs the classifier on a REAL IV.POS.5 inspection (reading
back from existing fuzzing data) to verify the zone populations look
sensible end-to-end.
"""

from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.zone_classifier import (
    classify_zones, zone_to_steps, summarize_zones, ECALL_MAJOR,
)
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, BOUNDARY_ZONES,
)


# =============================================================================
# Synthetic InspectionData helpers
# =============================================================================


def _make_cycle(step: int, major: int, minor: int = 0) -> A4CycleInfo:
    """Build a minimal A4CycleInfo. Fields per trace_parser.py:22-29."""
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0, txn_idx=0,
        major=major, minor=minor,
    )


def _build_data(cycles: List[A4CycleInfo]) -> InspectionData:
    """Build a synthetic InspectionData from a cycle list."""
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


# =============================================================================
# Tests — synthetic
# =============================================================================


def test_empty_inspection_returns_empty_zones():
    data = _build_data([])
    assert classify_zones(data) == {}
    z2s = zone_to_steps(data)
    # All 17 zones present, all empty
    assert set(z2s.keys()) == set(SEMANTIC_ZONES)
    for v in z2s.values():
        assert v == []


def test_single_step_is_step0_not_last_step():
    """Pro §7.A invariant: step0 always wins; with T=1 the same step is
    step0, not last_step. (Rule 1 has absolute precedence over Rule 2.)"""
    data = _build_data([_make_cycle(0, major=0)])
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


def test_fallback_by_major():
    """Steps not in any rule should fall through to major_to_zone()."""
    data = _build_data([
        _make_cycle(0, major=0),   # → step0 (rule 1 overrides)
        _make_cycle(1, major=0),   # ALU
        _make_cycle(2, major=3),   # MUL
        _make_cycle(3, major=4),   # DIV
        _make_cycle(4, major=5),   # LOAD
        _make_cycle(5, major=6),   # STORE
        _make_cycle(6, major=7),   # BRANCH
        _make_cycle(7, major=11),  # SHA
        _make_cycle(8, major=9),   # POSEIDON0
        _make_cycle(9, major=10),  # POSEIDON1
        _make_cycle(10, major=12), # BIGINT → other
        _make_cycle(11, major=2),  # ALU → last_step (rule 2 overrides)
    ])
    z = classify_zones(data)
    assert z[0]  == "step0"
    assert z[1]  == "core_arithmetic"
    assert z[2]  == "core_mul"
    assert z[3]  == "core_div"
    assert z[4]  == "core_memory_load"
    assert z[5]  == "core_memory_store"
    assert z[6]  == "core_branch"
    assert z[7]  == "core_sha"
    assert z[8]  == "core_poseidon"
    assert z[9]  == "core_poseidon"
    assert z[10] == "core_other"
    assert z[11] == "last_step"


def test_ecall_cycle_becomes_pre_ecall():
    """A non-boundary cycle with major==ECALL_MAJOR is classified as pre_ecall."""
    data = _build_data([
        _make_cycle(0, major=0),   # step0
        _make_cycle(1, major=0),
        _make_cycle(2, major=ECALL_MAJOR),   # ← pre_ecall
        _make_cycle(3, major=0),             # ← post_ecall (e+1)
        _make_cycle(4, major=0),
        _make_cycle(5, major=0),   # last_step
    ])
    z = classify_zones(data)
    assert z[2] == "pre_ecall"
    assert z[3] == "post_ecall"
    assert z[1] == "core_arithmetic"
    assert z[4] == "core_arithmetic"


def test_ecall_at_boundary_does_not_overwrite_singleton():
    """If the ECALL cycle is at step 0 or T-1, the singleton zone wins."""
    data = _build_data([
        _make_cycle(0, major=ECALL_MAJOR),  # step0 wins
        _make_cycle(1, major=0),            # could become post_ecall (rule 3 sets it)
        _make_cycle(2, major=0),
        _make_cycle(3, major=ECALL_MAJOR),  # last_step wins
    ])
    z = classify_zones(data)
    assert z[0] == "step0"                  # NOT pre_ecall
    assert z[1] == "post_ecall"             # set by rule 3 from step 0's ECALL
    assert z[2] == "core_arithmetic"
    assert z[3] == "last_step"              # NOT pre_ecall (last_step wins)


def test_multiple_ecalls():
    """Several ECALLs produce several pre_ecall/post_ecall classifications."""
    cycles = []
    for s in range(20):
        if s in (5, 12, 17):
            cycles.append(_make_cycle(s, major=ECALL_MAJOR))
        else:
            cycles.append(_make_cycle(s, major=0))
    data = _build_data(cycles)
    z2s = zone_to_steps(data)
    # 3 ECALL cycles → 3 pre_ecall entries (5, 12, 17) and 3 post_ecall (6, 13, 18)
    assert z2s["pre_ecall"] == [5, 12, 17]
    assert z2s["post_ecall"] == [6, 13, 18]


def test_all_17_zones_in_output_dict():
    """zone_to_steps() returns all 17 zones (some may be empty for a guest)."""
    data = _build_data([_make_cycle(0, major=0), _make_cycle(1, major=0)])
    z2s = zone_to_steps(data)
    assert set(z2s.keys()) == set(SEMANTIC_ZONES)
    # For sha2-host-like (no Poseidon), core_poseidon should be empty:
    assert z2s["core_poseidon"] == []
    # pre_mret/post_mret/pre_halt/post_halt are NOT detected in Phase 2; empty
    assert z2s["pre_mret"] == []
    assert z2s["post_mret"] == []
    assert z2s["pre_halt"] == []
    assert z2s["post_halt"] == []


def test_summarize_zones_runs_without_crash():
    """summarize_zones produces a non-empty string."""
    data = _build_data([_make_cycle(0, major=0), _make_cycle(1, major=0)])
    s = summarize_zones(data)
    assert "Zone populations" in s
    assert "boundary zones" in s
    assert "core zones" in s


def test_step0_always_in_zones_even_with_only_one_cycle_at_other_step():
    """Edge case: cycle list is [_make_cycle(0, ...)] — step0 should be set."""
    data = _build_data([_make_cycle(0, major=8)])  # ECALL at step 0
    z = classify_zones(data)
    assert z[0] == "step0"  # singleton wins over ECALL rule
