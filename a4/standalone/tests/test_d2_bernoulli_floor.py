#!/usr/bin/env python3
"""Phase 2 — Bernoulli floor behavior tests (IV.POS.8 D2 Bernoulli spec §6 Layer-1)."""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Tuple

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    ConstantFloor,
    EpochStageFloor,
    MutationOutcome,
)
from a4.standalone.semantic_arm_universe import ArmKey, SemanticArmUniverse
from a4.standalone.tests.test_bandit_ts import _decision_trace, _small_universe


def _cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0, txn_idx=0, major=major, minor=0,
    )


def _medium_universe() -> SemanticArmUniverse:
    """~10–15 arms — cold-start completes well before N=4000."""
    cycles = [_cycle(i, i % 7) for i in range(20)]
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return SemanticArmUniverse.build(
        data,
        ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR", "COMP_OUT_MOD"],
    )


def _run_applied(
    sched: ConstrainedTSScheduler,
    n: int,
    *,
    outcome_mix: List[MutationOutcome] | None = None,
) -> List[str]:
    """Run n pulls; return mode sequence."""
    modes: List[str] = []
    for i in range(n):
        d = sched.select()
        modes.append(d.mode)
        outcome = (
            outcome_mix[i]
            if outcome_mix is not None
            else MutationOutcome.APPLIED
        )
        sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), outcome, 0)
    return modes


def _floor_share(modes: List[str]) -> float:
    post = [m for m in modes if m in ("floor", "adaptive")]
    if not post:
        return 0.0
    return sum(1 for m in post if m == "floor") / len(post)


class TestBernoulliModeShareLinearity:
    @pytest.mark.parametrize("p", [0.20, 0.35, 0.55, 0.80])
    def test_realized_floor_share_matches_constant_p(self, p: float):
        sched = ConstrainedTSScheduler(
            _medium_universe(),
            cold_start_pulls_per_arm=3,
            forced_singleton_pulls=5,
            epoch_size=100,
            seed=1243,
            floor_schedule=ConstantFloor(p),
            bernoulli_floor=True,
        )
        modes = _run_applied(sched, 4000)
        share = _floor_share(modes)
        assert abs(share - p) <= 0.03, f"p={p}: realized={share:.3f}"

    def test_bernoulli_distinguishes_nominal_p_legacy_does_not_track(self):
        """Bernoulli: p=0.20 vs p=0.35 realized shares differ and track nominal."""
        shares = {}
        for p in (0.20, 0.35):
            sched = ConstrainedTSScheduler(
                _medium_universe(),
                cold_start_pulls_per_arm=3,
                forced_singleton_pulls=5,
                epoch_size=100,
                seed=1243,
                floor_schedule=ConstantFloor(p),
                bernoulli_floor=True,
            )
            shares[p] = _floor_share(_run_applied(sched, 4000))
        assert abs(shares[0.20] - 0.20) <= 0.03
        assert abs(shares[0.35] - 0.35) <= 0.03
        assert abs(shares[0.20] - shares[0.35]) >= 0.08


class TestBernoulliDecayContinuity:
    def test_epoch_stage_floor_windows(self):
        sched = ConstrainedTSScheduler(
            _medium_universe(),
            cold_start_pulls_per_arm=3,
            forced_singleton_pulls=5,
            epoch_size=100,
            seed=99,
            floor_schedule=EpochStageFloor([(0, 0.55), (2000, 0.35), (4000, 0.20)]),
            bernoulli_floor=True,
        )
        window_modes: Dict[str, List[str]] = {
            "w1": [],
            "w2": [],
            "w3": [],
        }
        for _ in range(6000):
            d = sched.select()
            tm = sched._total_mutations
            if d.mode in ("floor", "adaptive"):
                if tm < 2000:
                    window_modes["w1"].append(d.mode)
                elif tm < 4000:
                    window_modes["w2"].append(d.mode)
                else:
                    window_modes["w3"].append(d.mode)
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        assert abs(_floor_share(window_modes["w1"]) - 0.55) <= 0.04
        assert abs(_floor_share(window_modes["w2"]) - 0.35) <= 0.04
        assert abs(_floor_share(window_modes["w3"]) - 0.20) <= 0.04


class TestBernoulliColdSingletonPreserved:
    def test_hard_guarantees_before_floor_adaptive(self):
        au = _medium_universe()
        sched = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=3,
            forced_singleton_pulls=5,
            epoch_size=100,
            seed=7,
            floor_schedule=ConstantFloor(0.55),
            bernoulli_floor=True,
        )
        n_arms = au.num_arms
        cold_seen = 0
        while cold_seen < n_arms * sched.cold_start_pulls_per_arm:
            d = sched.select()
            assert d.mode == "cold", f"expected cold during bootstrap, got {d.mode}"
            cold_seen += 1
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        singleton_arms = set(au.singleton_arms())
        singleton_counts = {a: 0 for a in singleton_arms}
        for _ in range(200):
            d = sched.select()
            if d.mode == "singleton":
                singleton_counts[ArmKey.v5(d.kind, d.zone)] += 1
            elif d.mode in ("floor", "adaptive"):
                break
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        for arm in au.arms:
            assert sched.pulls[arm] >= sched.cold_start_pulls_per_arm
        for a in singleton_arms:
            assert sched.pulls[a] >= sched.forced_singleton_pulls


class TestBernoulliFloorPickBalancing:
    def test_all_floor_spreads_epoch_pulls_evenly(self):
        au = _medium_universe()
        sched = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=1,
            epoch_size=100,
            seed=11,
            floor_schedule=ConstantFloor(1.0),
            bernoulli_floor=True,
        )
        for _ in range(au.num_arms * 2):
            d = sched.select()
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        floor_pulls = 0
        for _ in range(au.num_arms):
            d = sched.select()
            assert d.mode == "floor"
            floor_pulls += 1
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        counts = list(sched.epoch_pulls.values())
        assert max(counts) - min(counts) <= 1


class TestBernoulliAppliedAccountingClock:
    def test_skipped_pulls_do_not_advance_floor_clock(self):
        sched = ConstrainedTSScheduler(
            _medium_universe(),
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=1,
            epoch_size=100,
            seed=55,
            floor_schedule=ConstantFloor(0.55),
            bernoulli_floor=True,
            applied_accounting_mode=True,
        )
        for _ in range(sched.universe.num_arms * 2):
            d = sched.select()
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), MutationOutcome.APPLIED, 0)

        applied_modes: List[str] = []
        for i in range(3000):
            d = sched.select()
            outcome = (
                MutationOutcome.SKIPPED if i % 3 == 0 else MutationOutcome.APPLIED
            )
            if outcome == MutationOutcome.APPLIED and d.mode in ("floor", "adaptive"):
                applied_modes.append(d.mode)
            sched.update_with_outcome(ArmKey.v5(d.kind, d.zone), outcome, 0)

        assert abs(_floor_share(applied_modes) - 0.55) <= 0.04


class TestBernoulliDeterminism:
    def test_same_seed_same_trace(self):
        au = _medium_universe()
        seed = 4242
        n = 300
        successes = [0] * n

        a = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=2,
            forced_singleton_pulls=2,
            epoch_size=100,
            seed=seed,
            floor_schedule=ConstantFloor(0.55),
            bernoulli_floor=True,
        )
        b = ConstrainedTSScheduler(
            au,
            cold_start_pulls_per_arm=2,
            forced_singleton_pulls=2,
            epoch_size=100,
            seed=seed,
            floor_schedule=ConstantFloor(0.55),
            bernoulli_floor=True,
        )
        assert _decision_trace(a, n, successes) == _decision_trace(b, n, successes)


class TestFuzzerBernoulliWiring:
    def test_v6_cts_enables_bernoulli_hybrid_does_too(self):
        from unittest.mock import patch

        from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
        from a4.standalone.baseline_touch import BaselineTouch
        from a4.standalone.fuzzer import A4Fuzzer

        data = InspectionData(
            cycles=[_cycle(i, i % 5) for i in range(8)],
            all_txns=[],
            reg_txns=[],
        )
        touch = BaselineTouch(
            bitmap=bytearray(A4_TOUCH_MAP_SIZE),
            distinct_buckets=0,
            total_touches=0,
            touched_indices=[],
        )

        for strategy, expected in (("v6_cTS", True), ("hybrid_cTS", True), ("cTS_semantic_v2", False)):
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=":memory:",
                selector_strategy=strategy,
                seed=1,
                telemetry_level="none",
            )
            fz.data = data
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=touch,
            ):
                with patch.object(
                    fz,
                    "_capture_baseline_trace",
                    return_value={i: "add" for i in range(8)},
                ):
                    fz._setup_v2_bandit(10)
            assert isinstance(fz.v2_scheduler, ConstrainedTSScheduler)
            assert fz.v2_scheduler.bernoulli_floor is expected, strategy
