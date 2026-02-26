#!/usr/bin/env python3
"""
Phase II.2R unit tests for revised CoverageState, compute_reward, and update_state.

Tests the 5-component reward (T_new, T_rare, F_new, F_rare, Z),
revised Q (Q_dist * Q_rep), weighted average, baseline seeding,
valid-run gating, and update order.

Run: python -m pytest a4/standalone/tests/test_coverage_state.py -v
"""

import math
import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.pilot_calibration import CalibratedParams
from a4.standalone.coverage_state import (
    CoverageState,
    compute_reward,
    update_state,
)


def _params(**overrides) -> CalibratedParams:
    defaults = dict(
        tau_new=64.0, tau_d=3.0, K_T_rare=32, gamma=0.9965,
        tau_F_new=2.0, K_F_rare=2, r_0=10, tau_r=25.0, c_explore=0.25,
        a_Tn=1.0, a_Tr=0.25, a_Fn=1.0, a_Fr=1.0, a_Z=1.0,
    )
    defaults.update(overrides)
    return CalibratedParams(**defaults)


def _bm(nonzero: dict = None) -> bytes:
    buf = bytearray(A4_TOUCH_MAP_SIZE)
    if nonzero:
        for idx, val in nonzero.items():
            buf[idx] = val
    return bytes(buf)


def _fail(loc: str = "Test", major: int = 0, minor: int = 0) -> ConstraintFailure:
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc=f"{loc}(zirgen/circuit/rv32im/v2/dsl/test.zir:1)", value=1,
    )


class TestCoverageStateInit:
    def test_init(self):
        state = CoverageState(_params())
        assert len(state.global_bitmap) == A4_TOUCH_MAP_SIZE
        assert len(state.freq) == A4_TOUCH_MAP_SIZE
        assert state.fail_freq == {}
        assert state.total_runs == 0

    def test_seed_from_baseline(self):
        state = CoverageState(_params())
        bm = _bm({10: 5, 20: 3, 100: 1})
        state.seed_from_baseline(bm)
        assert state.global_bitmap[10] == 5
        assert state.global_bitmap[20] == 3
        assert state.global_bitmap[100] == 1
        assert state.global_bitmap[0] == 0
        assert state.freq[10] == 1
        assert state.freq[20] == 1
        assert state.freq[100] == 1
        assert state.freq[0] == 0


class TestComputeReward:
    def test_crash_returns_zero(self):
        state = CoverageState(_params())
        r, d = compute_reward(_bm({0: 1}), [], -11, "CRASH", False, state)
        assert r == 0.0
        assert d["mode"] == "crash"

    def test_no_bitmap_returns_zero(self):
        state = CoverageState(_params())
        r, d = compute_reward(None, [], 101, "REJECTED", True, state)
        assert r == 0.0

    def test_touch_novelty(self):
        state = CoverageState(_params(tau_new=64.0))
        bm = _bm({i: 1 for i in range(100)})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d["delta_T"] == 100
        expected = 1.0 - math.exp(-100 / 64.0)
        assert abs(d["T_new"] - expected) < 0.001

    def test_touch_rarity(self):
        state = CoverageState(_params(K_T_rare=2))
        state.freq[0] = 100  # common
        state.freq[1] = 1    # rare
        state.freq[2] = 0    # rarest
        for i in range(3):
            state.global_bitmap[i] = 1
        bm = _bm({0: 1, 1: 1, 2: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        # Top 2 rarest: bucket 2 (freq=0, w=1.0) and bucket 1 (freq=1, w=1/sqrt(2))
        expected = (1.0 + 1.0 / math.sqrt(2.0)) / 2
        assert abs(d["T_rare"] - expected) < 0.01

    def test_failure_novelty(self):
        state = CoverageState(_params(tau_F_new=2.0))
        bm = _bm({0: 1})
        fails = [_fail("A", 0, 0), _fail("B", 1, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        assert d["delta_F"] == 2
        expected = 1.0 - math.exp(-2.0 / 2.0)
        assert abs(d["F_new"] - expected) < 0.01

    def test_failure_novelty_no_new(self):
        state = CoverageState(_params())
        state.fail_freq[("A@test.zir:1", 0, 0)] = 5
        bm = _bm({0: 1})
        fails = [_fail("A", 0, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        assert d["delta_F"] == 0
        assert d["F_new"] == 0.0

    def test_failure_rarity(self):
        state = CoverageState(_params(K_F_rare=2))
        state.fail_freq[("A@test.zir:1", 0, 0)] = 50  # common
        state.fail_freq[("B@test.zir:1", 1, 0)] = 1   # rare
        bm = _bm({0: 1})
        fails = [_fail("A", 0, 0), _fail("B", 1, 0), _fail("C", 2, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        # C is newest (freq=0, w=1.0), B is rare (freq=1, w=1/sqrt(2))
        # Top 2: C and B
        expected = (1.0 + 1.0 / math.sqrt(2.0)) / 2
        assert abs(d["F_rare"] - expected) < 0.01

    def test_failure_rarity_no_failures(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d["F_rare"] == 0.0

    def test_Z_fires_correctly(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d["Z"] == 1  # REJECTED + proof_generated + d_fail==0

    def test_Z_not_on_crash(self):
        state = CoverageState(_params())
        r, d = compute_reward(_bm({0: 1}), [], -11, "CRASH", False, state)
        assert d["Z"] == 0

    def test_Z_not_without_proof(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", False, state)
        assert d["Z"] == 0  # proof_generated is False

    def test_Z_not_with_failures(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        fails = [_fail("A", 0, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        assert d["Z"] == 0  # d_fail > 0

    def test_Q_dist_penalty(self):
        state = CoverageState(_params(tau_d=3.0))
        bm = _bm({0: 1})
        fails = [_fail(f"F{i}", i, 0) for i in range(6)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        expected_Q_dist = math.exp(-6.0 / 3.0)
        assert abs(d["Q_dist"] - expected_Q_dist) < 0.001

    def test_Q_rep_no_cascade(self):
        state = CoverageState(_params(r_0=10))
        bm = _bm({0: 1})
        # 5 failures, 3 distinct → r_rep=2, below r_0=10
        fails = [_fail("A", 0, 0), _fail("A", 0, 0), _fail("B", 1, 0), _fail("B", 1, 0), _fail("C", 2, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        assert d["Q_rep"] == 1.0  # r_rep=2 <= r_0=10

    def test_Q_rep_cascade(self):
        state = CoverageState(_params(r_0=10, tau_r=25.0))
        bm = _bm({0: 1})
        # 50 instances, 2 distinct → r_rep=48, above r_0=10
        fails = [_fail("A", 0, 0)] * 48 + [_fail("B", 1, 0)] * 2
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        expected = math.exp(-(48 - 10) / 25.0)
        assert abs(d["Q_rep"] - expected) < 0.001

    def test_weighted_average(self):
        state = CoverageState(_params(a_Tn=1.0, a_Tr=0.0, a_Fn=0.0, a_Fr=0.0, a_Z=0.0))
        bm = _bm({i: 1 for i in range(50)})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        # Only T_new has weight, and Z fires but a_Z=0
        # S should equal T_new (since only a_Tn has weight)
        assert abs(d["S"] - d["T_new"]) < 0.001

    def test_accepted_override(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 0, "ACCEPTED", True, state)
        assert r == 1.0
        assert d["mode"] == "accepted"

    def test_reward_bounded(self):
        state = CoverageState(_params())
        bm = _bm({i: 1 for i in range(500)})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert 0.0 <= r <= 1.0


class TestUpdateState:
    def test_valid_run_updates(self):
        state = CoverageState(_params())
        bm = _bm({10: 5, 20: 3})
        fails = [_fail("A", 0, 0)]
        update_state(bm, fails, 101, state)
        assert state.global_bitmap[10] == 5
        assert state.freq[10] == 1
        assert state.fail_freq[("A@test.zir:1", 0, 0)] == 1
        assert state.total_runs == 1

    def test_crash_no_coverage_update(self):
        state = CoverageState(_params())
        bm = _bm({10: 5})
        fails = [_fail("A", 0, 0)]
        update_state(bm, fails, -11, state)  # CRASH exit code
        assert state.global_bitmap[10] == 0  # NOT updated
        assert state.freq[10] == 0           # NOT updated
        assert ("A@test.zir:1", 0, 0) not in state.fail_freq  # NOT updated
        assert state.total_runs == 1         # Still counted

    def test_no_bitmap_no_coverage_update(self):
        state = CoverageState(_params())
        fails = [_fail("A", 0, 0)]
        update_state(None, fails, 101, state)
        assert state.total_runs == 1
        assert ("A@test.zir:1", 0, 0) not in state.fail_freq

    def test_fail_freq_per_run_per_context(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        # Same context repeated 5 times in one run
        fails = [_fail("A", 0, 0)] * 5
        update_state(bm, fails, 101, state)
        assert state.fail_freq[("A@test.zir:1", 0, 0)] == 1  # Not 5

    def test_freq_increments_per_run(self):
        state = CoverageState(_params())
        bm = _bm({10: 1})
        update_state(bm, [], 101, state)
        assert state.freq[10] == 1
        update_state(bm, [], 101, state)
        assert state.freq[10] == 2

    def test_update_order_matters(self):
        state = CoverageState(_params(tau_new=64.0))
        bm = _bm({0: 1, 1: 1, 2: 1})

        r1, d1 = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d1["delta_T"] == 3
        update_state(bm, [], 101, state)

        r2, d2 = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d2["delta_T"] == 0
        assert r2 < r1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
