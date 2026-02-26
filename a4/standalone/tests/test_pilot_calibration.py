#!/usr/bin/env python3
"""
Phase II.2R unit tests for revised pilot calibration.

Tests CalibratedParams, PilotRunStats (with d_fail), calibrate_from_pilot
(tau_d, tighter tau_T clamp, no W), and collect_pilot_stat.

Run: python -m pytest a4/standalone/tests/test_pilot_calibration.py -v
"""

import math
import pytest

from a4.standalone.pilot_calibration import (
    PilotRunStats,
    CalibratedParams,
    calibrate_from_pilot,
    compute_N_pilot,
    collect_pilot_stat,
    _percentile,
)
from a4.core.executor import MutationExecutionResult
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE, make_global_bitmap


def _stat(delta_new=0, abs_U=1599, n_fail=3, d_fail=2, is_crash=False, has_bitmap=True):
    return PilotRunStats(
        delta_new=delta_new, abs_U=abs_U, n_fail=n_fail, d_fail=d_fail,
        is_crash=is_crash, has_bitmap=has_bitmap,
    )


class TestComputeNPilot:
    def test_typical(self):
        assert compute_N_pilot(1000) == 50
    def test_clamp_low(self):
        assert compute_N_pilot(500) == 30
    def test_clamp_high(self):
        assert compute_N_pilot(5000) == 100


class TestPercentile:
    def test_single(self):
        assert _percentile([5.0], 75) == 5.0
    def test_two(self):
        assert abs(_percentile([10.0, 20.0], 75) - 17.5) < 0.01


class TestCalibrateFromPilot:
    def test_typical(self):
        stats = [_stat(delta_new=0, d_fail=2, n_fail=3)] * 50
        stats[0] = _stat(delta_new=40, d_fail=2, n_fail=3)
        p = calibrate_from_pilot(stats, budget=1000)
        # tau_new: only one nonzero delta (40), p75 of [40]=40, clamp [8,128]=40
        assert p.tau_new == 40.0
        # tau_d: p75 of [2,2,...2]=2, max(1,2)=2
        assert p.tau_d == 2.0
        # K_T_rare: 0.02*1599=31.98 -> 31, clamp [16,64]=31
        assert p.K_T_rare == 31
        # gamma derived from budget
        H = max(50, min(300, 1000 // 5))
        assert abs(p.gamma - 2.0 ** (-1.0 / H)) < 1e-6

    def test_no_novelty(self):
        stats = [_stat(delta_new=0)] * 30
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_new == 64.0  # default

    def test_all_crashes(self):
        stats = [_stat(is_crash=True, has_bitmap=False)] * 30
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_d == 3.0  # default

    def test_tau_T_tighter_clamp(self):
        stats = [_stat(delta_new=1000)] * 30
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_new == 128.0  # clamped to max 128 (was 256 before)

    def test_tau_T_lower_clamp(self):
        stats = [_stat(delta_new=3)] * 30
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_new == 8.0  # clamped to min 8 (was 16 before)

    def test_tau_d_from_d_fail(self):
        stats = [_stat(d_fail=4)] * 50
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_d == 4.0  # p75 of [4,...,4] = 4

    def test_tau_d_minimum(self):
        stats = [_stat(d_fail=0)] * 50
        p = calibrate_from_pilot(stats, budget=1000)
        assert p.tau_d == 1.0  # max(1, p75(0s)) = max(1,0) = 1

    def test_no_W_in_params(self):
        """CalibratedParams should not have W (rolling window removed)."""
        p = calibrate_from_pilot([_stat()] * 30, budget=1000)
        assert not hasattr(p, 'W')

    def test_hard_params_defaults(self):
        p = calibrate_from_pilot([_stat()] * 30, budget=1000)
        assert p.tau_F_new == 2.0
        assert p.K_F_rare == 2
        assert p.r_0 == 10
        assert p.tau_r == 25.0
        assert p.c_explore == 0.25
        assert p.a_Tn == 1.0
        assert p.a_Tr == 0.25
        assert p.a_Fn == 1.0
        assert p.a_Fr == 1.0
        assert p.a_Z == 1.0

    def test_gamma_scaling(self):
        stats = [_stat()] * 30
        p500 = calibrate_from_pilot(stats, budget=500)
        p5000 = calibrate_from_pilot(stats, budget=5000)
        assert p500.gamma < p5000.gamma

    def test_K_T_rare_scales(self):
        small = [_stat(abs_U=500)] * 30
        large = [_stat(abs_U=3000)] * 30
        p_s = calibrate_from_pilot(small, budget=1000)
        p_l = calibrate_from_pilot(large, budget=1000)
        assert p_s.K_T_rare == 16  # 0.02*500=10, clamp to 16
        assert p_l.K_T_rare == 60  # 0.02*3000=60


class TestCollectPilotStat:
    def _make_bm(self, nonzero):
        buf = bytearray(A4_TOUCH_MAP_SIZE)
        for idx, val in nonzero.items():
            buf[idx] = val
        return bytes(buf)

    def test_basic(self):
        bm = self._make_bm({0: 1, 100: 5})
        result = MutationExecutionResult(
            stdout="", stderr="", combined_output="",
            exit_code=101, failures=[], touch_bitmap=bm,
        )
        stat = collect_pilot_stat(result, make_global_bitmap())
        assert stat.delta_new == 2
        assert stat.abs_U == 2
        assert stat.n_fail == 0
        assert stat.d_fail == 0
        assert stat.is_crash is False
        assert stat.has_bitmap is True

    def test_d_fail_counted(self):
        from a4.core.constraint_parser import ConstraintFailure
        f1 = ConstraintFailure(0, 0, 0, 0, 0, "A(zirgen/test.zir:1)", 1)
        f2 = ConstraintFailure(0, 0, 0, 1, 0, "B(zirgen/test.zir:2)", 1)
        f3 = ConstraintFailure(0, 0, 0, 0, 0, "A(zirgen/test.zir:1)", 2)  # same context as f1
        bm = self._make_bm({0: 1})
        result = MutationExecutionResult(
            stdout="", stderr="", combined_output="",
            exit_code=101, failures=[f1, f2, f3], touch_bitmap=bm,
        )
        stat = collect_pilot_stat(result, make_global_bitmap())
        assert stat.n_fail == 3
        assert stat.d_fail == 2  # A and B, not 3

    def test_no_bitmap(self):
        result = MutationExecutionResult(
            stdout="", stderr="", combined_output="",
            exit_code=-11, failures=[], touch_bitmap=None,
        )
        stat = collect_pilot_stat(result, make_global_bitmap())
        assert stat.has_bitmap is False
        assert stat.is_crash is True
        assert stat.delta_new == 0

    def test_does_not_modify_global(self):
        bm = self._make_bm({50: 7})
        glob = make_global_bitmap()
        result = MutationExecutionResult(
            stdout="", stderr="", combined_output="",
            exit_code=101, failures=[], touch_bitmap=bm,
        )
        collect_pilot_stat(result, glob)
        assert glob[50] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
