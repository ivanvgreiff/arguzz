#!/usr/bin/env python3
"""
Unit tests for cloud1 Phase 4 reward_v2 (ProG_Report_2.md §6.1, §8).

Synthetic inputs only — no host binary or IV.POS.5 DB required.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.standalone.reward_v2 import (
    sat,
    compute_reward_v2,
    compute_bandit_success,
    extract_constraint_family,
    make_local_v2_ctx_key,
    compute_reward_v2_components,
    compute_counterfactuals,
)
from a4.standalone.structural_cells import StructuralCell


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _fail(
    name: str = "MemLoadInput",
    zir_file: str = "inst_mem.zir",
    line: int = 8,
    major: int = 5,
    minor: int = 4,
) -> ConstraintFailure:
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc=f"{name}(zirgen/circuit/rv32im/v2/dsl/{zir_file}:{line})",
        value=1,
    )


@dataclass
class StubExecResult:
    failures: List[Any] = field(default_factory=list)
    exit_code: int = 0
    touch_bitmap: Optional[bytes] = b"\x01"
    family_residues: Optional[List[dict]] = None
    family_details: Optional[List[dict]] = None
    config: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# sat
# ---------------------------------------------------------------------------

class TestSat:
    def test_sat_zero_is_zero(self):
        assert sat(0.0, 1.0) == pytest.approx(0.0)

    def test_sat_large_x_approaches_one(self):
        assert sat(1e6, 1.0) == pytest.approx(1.0, abs=1e-6)

    def test_sat_at_tau_is_one_minus_exp_neg_one(self):
        assert sat(1.0, 1.0) == pytest.approx(1.0 - math.exp(-1.0))

    def test_sat_monotonic_in_x(self):
        assert sat(1.0, 2.0) < sat(2.0, 2.0) < sat(5.0, 2.0)

    def test_sat_zero_tau_returns_zero(self):
        assert sat(10.0, 0.0) == 0.0


# ---------------------------------------------------------------------------
# compute_reward_v2
# ---------------------------------------------------------------------------

class TestComputeRewardV2:
    def test_all_zeros_no_crash(self):
        assert compute_reward_v2(0, 0, 0, 0, False, 0) == pytest.approx(0.0)

    def test_only_l_new_one(self):
        r = compute_reward_v2(1, 0, 0, 0, False, 0)
        assert r == pytest.approx(1.00 * sat(1.0, 1.0))

    def test_only_crash(self):
        assert compute_reward_v2(0, 0, 0, 0, True, 0) == pytest.approx(-0.50)

    def test_full_positive_bounded_by_coeff_sum(self):
        r = compute_reward_v2(10, 10, 10, 10, False, 0)
        max_pos = 1.00 + 0.30 + 0.25 + 0.15
        assert r <= max_pos + 1e-9

    def test_repeat_penalizes(self):
        base = compute_reward_v2(1, 0, 0, 0, False, 0)
        with_repeat = compute_reward_v2(1, 0, 0, 0, False, 5)
        assert with_repeat < base


# ---------------------------------------------------------------------------
# compute_bandit_success
# ---------------------------------------------------------------------------

class TestComputeBanditSuccess:
    def test_all_zero_returns_zero(self):
        assert compute_bandit_success(0, 0, 0) == 0

    def test_l_new_positive_returns_one(self):
        assert compute_bandit_success(1, 0, 0) == 1

    def test_g_new_positive_returns_one(self):
        assert compute_bandit_success(0, 2, 0) == 1

    def test_s_new_positive_returns_one(self):
        assert compute_bandit_success(0, 0, 1) == 1


# ---------------------------------------------------------------------------
# extract_constraint_family
# ---------------------------------------------------------------------------

class TestExtractConstraintFamily:
    def test_inst_mem_zir(self):
        assert extract_constraint_family("MemLoadInput@inst_mem.zir:8") == "inst_mem"

    def test_mem_zir(self):
        assert extract_constraint_family("MemoryWrite@mem.zir:99") == "mem"

    def test_inst_zir(self):
        assert extract_constraint_family("VerifyOpcodeF3@inst.zir:123") == "inst"

    def test_no_at_fallback_name(self):
        assert extract_constraint_family("MemoryWrite") == "MemoryWrite"

    def test_empty_string_unknown(self):
        assert extract_constraint_family("") == "unknown"


# ---------------------------------------------------------------------------
# compute_reward_v2_components
# ---------------------------------------------------------------------------

class TestComputeRewardV2Components:
    def test_l_new_set_semantics_duplicate_failures(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        f1 = _fail()
        f2 = _fail()  # same context, second instance
        exec_r = StubExecResult(failures=[f1, f2])
        comp = compute_reward_v2_components(
            exec_r, seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["l_new"] == 1
        assert comp["f_new"] == 1

    def test_already_seen_local_increments_repeat_not_l_new(self):
        f = _fail()
        ctx = (f.constraint_loc(), f.major, f.minor)
        seen_local = {ctx}
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[f]),
            seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["l_new"] == 0
        assert comp["repeat"] == 1

    def test_f_new_second_family_same_file_different_context(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        f1 = _fail(name="MemLoadInput", zir_file="inst_mem.zir", minor=4)
        f2 = _fail(name="MemStoreOutput", zir_file="inst_mem.zir", minor=6)
        compute_reward_v2_components(
            StubExecResult(failures=[f1]),
            seen_local, seen_global, seen_struct,
            "INSTR_WORD_MOD_SUR", "core_memory_load", 5,
        )
        comp2 = compute_reward_v2_components(
            StubExecResult(failures=[f2]),
            seen_local, seen_global, seen_struct,
            "INSTR_WORD_MOD_SUR", "core_memory_load", 5,
        )
        assert comp2["l_new"] == 1
        assert comp2["f_new"] == 0  # same inst_mem family

    def test_g_new_from_hook3_first_hit(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        exec_r = StubExecResult(
            failures=[],
            family_residues=[{"family": "memory", "nonzero": True}],
            family_details=[{"family": "memory", "broken_addrs": [0x80001000]}],
        )
        comp = compute_reward_v2_components(
            exec_r, seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["g_new"] == 1
        comp2 = compute_reward_v2_components(
            exec_r, seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp2["g_new"] == 0

    def test_s_new_structural_cell_first_hit(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[]),
            seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["s_new"] == 1
        comp2 = compute_reward_v2_components(
            StubExecResult(failures=[]),
            seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp2["s_new"] == 0

    def test_crash_exit_code(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[], exit_code=139),
            seen_local, seen_global, seen_struct,
            "PRE_EXEC_REG_MOD", "step0", 0,
        )
        assert comp["crash"] is True

    def test_missing_touch_bitmap_is_crash(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[], touch_bitmap=None),
            seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["crash"] is True

    def test_empty_exec_result_all_zero_except_s_new(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(),
            seen_local, seen_global, seen_struct,
            "MEM_VAL_MOD", "core_memory_load", 5,
        )
        assert comp["l_new"] == 0
        assert comp["f_new"] == 0
        assert comp["g_new"] == 0
        assert comp["s_new"] == 1
        assert comp["repeat"] == 0
        assert comp["crash"] is False


# ---------------------------------------------------------------------------
# compute_counterfactuals
# ---------------------------------------------------------------------------

class TestComputeCounterfactuals:
    def _components(self, **kw) -> dict:
        base = dict(l_new=2, f_new=1, g_new=1, s_new=1, crash=False, repeat=0)
        base.update(kw)
        return base

    def test_current_reward_matches_compute_reward_v2(self):
        comp = self._components()
        cf = compute_counterfactuals(comp, {"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0})
        expected = compute_reward_v2(2, 1, 1, 1, False, 0)
        assert cf["current_reward"] == pytest.approx(expected)

    def test_fnew_only_reward(self):
        cf = compute_counterfactuals(self._components(f_new=3), {})
        assert cf["fnew_only_reward"] == pytest.approx(0.30 * sat(3.0, 1.0))

    def test_compressed_global_reward(self):
        cf = compute_counterfactuals(self._components(g_new=2), {})
        assert cf["compressed_global_reward"] == pytest.approx(0.25 * sat(2.0, 3.0))

    def test_discovery_binary_matches_bandit_success(self):
        comp = self._components(l_new=0, g_new=0, s_new=1)
        cf = compute_counterfactuals(comp, {})
        assert cf["discovery_binary_reward"] == compute_bandit_success(0, 0, 1)

    def test_no_qloc_crash_mode(self):
        cf = compute_counterfactuals(self._components(), {"mode": "crash"})
        assert cf["no_qloc_reward"] == 0.0

    def test_no_qloc_accepted_mode(self):
        cf = compute_counterfactuals(self._components(), {"mode": "accepted"})
        assert cf["no_qloc_reward"] == 1.0

    def test_no_qloc_normal_forces_q_loc_one(self):
        diag = {"mode": "normal", "S": 0.4, "Q_loc": 0.1, "Q_rep": 0.9, "Q_glob": 0.8, "Q": 0.072, "r": 0.072}
        cf = compute_counterfactuals(self._components(), diag)
        assert cf["no_qloc_reward"] == pytest.approx(min(1.0, 0.9 * 0.8 * 0.4))


# ---------------------------------------------------------------------------
# misc / edge
# ---------------------------------------------------------------------------

class TestMisc:
    def test_make_local_v2_ctx_key(self):
        assert make_local_v2_ctx_key("A@mem.zir:1", 5, 4) == "A@mem.zir:1|5|4"

    def test_bandit_success_repeat_does_not_count(self):
        # repeat is not an input to compute_bandit_success
        assert compute_bandit_success(0, 0, 0) == 0

    def test_dict_shaped_failure_in_components(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[{
                "constraint_loc": "X@mem.zir:1",
                "major": 1,
                "minor": 0,
            }]),
            seen_local, seen_global, seen_struct,
            "INSTR_TYPE_MOD", "step0", 1,
        )
        assert comp["l_new"] == 1
        assert comp["f_new"] == 1

    def test_crash_with_no_failures_still_penalized_in_reward(self):
        r = compute_reward_v2(0, 0, 0, 0, True, 0)
        assert r == pytest.approx(-0.50)
