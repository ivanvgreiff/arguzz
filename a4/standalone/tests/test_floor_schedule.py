#!/usr/bin/env python3
"""Unit tests for IV.POS.8 D1.A FloorSchedule implementations."""

from __future__ import annotations

import math

import pytest

from a4.standalone.bandit_ts import (
    ConstantFloor,
    EpochStageFloor,
    ExponentialDecayFloor,
)


def _exp_floor(d: int, *, initial: float = 0.55, floor_min: float = 0.20, K: float = 50) -> float:
    return max(floor_min, initial * math.exp(-d / K))


class TestConstantFloor:
    def test_returns_same_value_at_every_state(self):
        sched = ConstantFloor(0.55)
        for tm in (0, 100, 5000):
            for ld in (0, 15, 46, 100):
                assert sched.current(total_mutations=tm, local_discoveries=ld) == 0.55

    def test_value_in_unit_interval(self):
        for v in (0.0, 0.55, 1.0):
            sched = ConstantFloor(v)
            assert 0.0 <= sched.current(total_mutations=0, local_discoveries=0) <= 1.0


class TestExponentialDecayFloor:
    def test_returns_initial_at_zero_discoveries(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)
        assert sched.current(total_mutations=0, local_discoveries=0) == pytest.approx(0.55)

    def test_monotonic_decreasing_in_local_discoveries(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)
        prev = sched.current(total_mutations=0, local_discoveries=0)
        for d in range(1, 60):
            cur = sched.current(total_mutations=9999, local_discoveries=d)
            assert cur <= prev + 1e-15
            prev = cur

    def test_k50_clip_off_regime_before_saturation(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)
        assert sched.current(total_mutations=0, local_discoveries=50) == pytest.approx(
            _exp_floor(50), rel=1e-9
        )
        assert sched.current(total_mutations=0, local_discoveries=50) > 0.20

    def test_k50_clip_on_at_d51(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)
        assert sched.current(total_mutations=0, local_discoveries=51) == pytest.approx(0.20)
        assert sched.current(total_mutations=0, local_discoveries=100) == pytest.approx(0.20)

    def test_k15_aggressive_clip_regime(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=15)
        assert sched.current(total_mutations=0, local_discoveries=15) > 0.20
        assert sched.current(total_mutations=0, local_discoveries=16) == pytest.approx(0.20)

    def test_values_in_unit_interval(self):
        sched = ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)
        for d in range(0, 80):
            v = sched.current(total_mutations=0, local_discoveries=d)
            assert 0.0 <= v <= 1.0


class TestEpochStageFloor:
    STAGES = [(0, 0.55), (2000, 0.35), (4000, 0.20)]

    def test_stage_values_at_representative_counts(self):
        sched = EpochStageFloor(self.STAGES)
        assert sched.current(total_mutations=0, local_discoveries=0) == pytest.approx(0.55)
        assert sched.current(total_mutations=1999, local_discoveries=0) == pytest.approx(0.55)
        assert sched.current(total_mutations=2000, local_discoveries=0) == pytest.approx(0.35)
        assert sched.current(total_mutations=3999, local_discoveries=0) == pytest.approx(0.35)
        assert sched.current(total_mutations=4000, local_discoveries=0) == pytest.approx(0.20)
        assert sched.current(total_mutations=6000, local_discoveries=0) == pytest.approx(0.20)

    def test_transitions_at_boundaries(self):
        sched = EpochStageFloor(self.STAGES)
        assert sched.current(total_mutations=1999, local_discoveries=99) == pytest.approx(0.55)
        assert sched.current(total_mutations=2000, local_discoveries=99) == pytest.approx(0.35)
        assert sched.current(total_mutations=3999, local_discoveries=99) == pytest.approx(0.35)
        assert sched.current(total_mutations=4000, local_discoveries=99) == pytest.approx(0.20)

    def test_local_discoveries_ignored(self):
        sched = EpochStageFloor(self.STAGES)
        assert sched.current(total_mutations=2500, local_discoveries=0) == pytest.approx(
            sched.current(total_mutations=2500, local_discoveries=46)
        )

    def test_values_in_unit_interval(self):
        sched = EpochStageFloor(self.STAGES)
        for tm in (0, 1000, 2000, 3000, 4000, 6000):
            v = sched.current(total_mutations=tm, local_discoveries=0)
            assert 0.0 <= v <= 1.0

    def test_empty_stages_rejected(self):
        with pytest.raises(ValueError):
            EpochStageFloor([])
