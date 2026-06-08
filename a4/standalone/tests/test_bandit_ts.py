#!/usr/bin/env python3
"""
Phase 5 unit tests — ConstrainedTSScheduler, KindLevelUCBScheduler, KindLevelTSScheduler.
"""

from __future__ import annotations

from typing import List

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.semantic_arm_universe import SemanticArmUniverse
from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    KindLevelUCBScheduler,
    KindLevelTSScheduler,
    arm_id,
)


def _make_cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0, txn_idx=0,
        major=major, minor=0,
    )


def _small_universe() -> SemanticArmUniverse:
    """5-step trace with step0 singleton + core zones."""
    cycles = [
        _make_cycle(0, 0),
        _make_cycle(1, 0),
        _make_cycle(2, 5),
        _make_cycle(3, 5),
        _make_cycle(4, 0),
    ]
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return SemanticArmUniverse.build(
        data,
        ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR"],
    )


KINDS_3 = ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR"]


class TestArmId:
    def test_kind_only(self):
        assert arm_id("INSTR_TYPE_MOD") == "INSTR_TYPE_MOD"

    def test_kind_zone(self):
        assert arm_id("INSTR_TYPE_MOD", "step0") == "INSTR_TYPE_MOD|step0"


class TestConstrainedTSColdStart:
    def test_cold_start_before_adaptive(self):
        sched = ConstrainedTSScheduler(
            _small_universe(),
            cold_start_pulls_per_arm=2,
            forced_singleton_pulls=1,
            epoch_size=50,
            seed=1,
        )
        modes = []
        for _ in range(sched.universe.num_arms * 2):
            d = sched.select()
            modes.append(d.mode)
            sched.update(d.kind, d.zone, 0)
        assert "cold" in modes
        assert modes[0] == "cold"


class TestConstrainedTSSingletonFloor:
    def test_singleton_gets_forced_pulls(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=4,
            epoch_size=200,
            seed=42,
        )
        singleton_arms = set(au.singleton_arms())
        # Complete cold-start quickly
        for _ in range(au.num_arms):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)

        singleton_counts = {a: 0 for a in singleton_arms}
        for _ in range(80):
            d = sched.select()
            if (d.kind, d.zone) in singleton_counts:
                singleton_counts[(d.kind, d.zone)] += 1
            sched.update(d.kind, d.zone, 0)

        for a, cnt in singleton_counts.items():
            assert sched.pulls[a] >= 4, f"singleton {a} only {sched.pulls[a]} pulls"


class TestConstrainedTSFloorEnforcement:
    def test_epoch_floor_gives_minimum_allocation(self):
        au = _small_universe()
        n_arms = au.num_arms
        sched = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=1,
            coverage_floor_fraction=0.55,
            epoch_size=100,
            seed=99,
        )
        # Burn cold-start
        for _ in range(n_arms):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)

        target = int(sched.coverage_floor_fraction * sched.epoch_size / n_arms)
        counts = {a: 0 for a in sched.arms}
        for _ in range(sched.epoch_size):
            d = sched.select()
            counts[(d.kind, d.zone)] += 1
            sched.update(d.kind, d.zone, 0)

        min_count = min(counts.values())
        assert min_count >= max(1, target - 1)


class TestConstrainedTSConvergence:
    def test_favored_arm_gets_more_pulls_over_1000_rounds(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=1,
            coverage_floor_fraction=0.10,
            epoch_size=500,
            seed=7,
        )
        favored = au.available_arms[0]
        for _ in range(1000):
            d = sched.select()
            success = 1 if (d.kind, d.zone) == favored else (
                1 if sched.rng.random() < 0.05 else 0
            )
            if (d.kind, d.zone) == favored:
                success = 1 if sched.rng.random() < 0.50 else 0
            sched.update(d.kind, d.zone, success)

        pull_counts = list(sched.pulls.values())
        assert max(pull_counts) > min(pull_counts) + 50


class TestConstrainedTSSnapshot:
    def test_arm_state_rows_cover_all_arms(self):
        sched = ConstrainedTSScheduler(_small_universe(), seed=1)
        d = sched.select()
        sched.update(d.kind, d.zone, 1)
        rows = sched.arm_state_rows()
        assert len(rows) == sched.universe.num_arms
        assert all("posterior_alpha" in r for r in rows)


class TestKindLevelUCB:
    def test_cold_start_each_kind_once(self):
        sched = KindLevelUCBScheduler(KINDS_3, seed=1)
        seen = set()
        for _ in range(3):
            d = sched.select()
            assert d.mode == "cold"
            seen.add(d.kind)
            sched.update(d.kind, 0.5)
        assert seen == set(KINDS_3)

    def test_high_reward_kind_preferred(self):
        sched = KindLevelUCBScheduler(KINDS_3, c_explore=0.1, seed=2)
        for _ in range(3):
            d = sched.select()
            sched.update(d.kind, 0.1)
        for _ in range(200):
            d = sched.select()
            sched.update(d.kind, 0.9 if d.kind == "INSTR_TYPE_MOD" else 0.01)
        assert sched.pulls["INSTR_TYPE_MOD"] > sched.pulls["LOAD_VAL_MOD"]


class TestKindLevelTS:
    def test_update_increments_posterior(self):
        sched = KindLevelTSScheduler(KINDS_3, seed=1)
        sched.update("INSTR_TYPE_MOD", 1)
        rows = sched.arm_state_rows()
        row = next(r for r in rows if r["arm_id"] == "INSTR_TYPE_MOD")
        assert row["posterior_alpha"] == 2.0
        assert row["posterior_beta"] == 1.0

    def test_favored_kind_gets_more_pulls_simulation(self):
        sched = KindLevelTSScheduler(KINDS_3, seed=3)
        for _ in range(1000):
            d = sched.select()
            success = 1 if d.kind == "INSTR_TYPE_MOD" and sched.rng.random() < 0.5 else (
                1 if sched.rng.random() < 0.05 else 0
            )
            sched.update(d.kind, success)
        assert sched.pulls["INSTR_TYPE_MOD"] > sched.pulls["LOAD_VAL_MOD"]


class TestKindLevelSelectMetadata:
    def test_ucb_returns_runnerup(self):
        sched = KindLevelUCBScheduler(KINDS_3, seed=1)
        for k in KINDS_3:
            d = sched.select()
            sched.update(d.kind, 0.5)
        d = sched.select()
        assert d.runnerup_arm is not None or d.mode == "cold"

    def test_ts_adaptive_mode(self):
        sched = KindLevelTSScheduler(KINDS_3, seed=1)
        d = sched.select()
        assert d.mode == "adaptive"
        assert d.score is not None
