#!/usr/bin/env python3
"""
Phase 7d B3 — property-based bandit math tests (3 scheduler classes).

Uses hand-rolled random trials (no hypothesis dep). 200 trials per property.
"""

from __future__ import annotations

import math
import random
from typing import List, Tuple

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    KindLevelUCBScheduler,
    KindLevelTSScheduler,
)
from a4.standalone.semantic_arm_universe import SemanticArmUniverse

_TRIALS = 200
_TOL = 1e-9

KINDS = ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR", "COMP_OUT_MOD"]


def _cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0x00201000, txn_idx=0,
        major=major, minor=0,
    )


def _universe() -> SemanticArmUniverse:
    cycles = [_cycle(i, i % 6) for i in range(12)]
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return SemanticArmUniverse.build(data, KINDS)


# ---------------------------------------------------------------------------
# ConstrainedTSScheduler
# ---------------------------------------------------------------------------


class TestConstrainedTSProperties:
    def test_update_success_increments_alpha_only(self):
        au = _universe()
        for seed in range(_TRIALS):
            sched = ConstrainedTSScheduler(au, seed=seed)
            arm = sched.arms[seed % len(sched.arms)]
            a0, b0 = sched._alpha(arm), sched._beta(arm)
            sched.update(arm[0], arm[1], 1)
            assert sched._alpha(arm) == pytest.approx(a0 + 1)
            assert sched._beta(arm) == pytest.approx(b0)

    def test_update_failure_increments_beta_only(self):
        au = _universe()
        for seed in range(_TRIALS):
            sched = ConstrainedTSScheduler(au, seed=seed)
            arm = sched.arms[seed % len(sched.arms)]
            a0, b0 = sched._alpha(arm), sched._beta(arm)
            sched.update(arm[0], arm[1], 0)
            assert sched._alpha(arm) == pytest.approx(a0)
            assert sched._beta(arm) == pytest.approx(b0 + 1)

    def test_update_always_increments_pulls(self):
        au = _universe()
        for seed in range(_TRIALS):
            sched = ConstrainedTSScheduler(au, seed=seed)
            arm = sched.arms[seed % len(sched.arms)]
            success = seed % 2
            p0 = sched.pulls[arm]
            sched.update(arm[0], arm[1], success)
            assert sched.pulls[arm] == p0 + 1

    def test_cold_start_mode_and_candidate(self):
        au = _universe()
        sched = ConstrainedTSScheduler(au, seed=42)
        threshold = sched.cold_start_pulls_per_arm
        for _ in range(_TRIALS):
            cold = [a for a in sched.arms if sched.pulls[a] < threshold]
            if not cold:
                break
            d = sched.select()
            assert d.mode == "cold"
            chosen = (d.kind, d.zone)
            assert chosen in cold
            min_pull = min(sched.pulls[a] for a in cold)
            assert sched.pulls[chosen] == min_pull
            sched.update(d.kind, d.zone, 0)


# ---------------------------------------------------------------------------
# KindLevelUCBScheduler — formula matches implementation (c * sqrt(ln(t)/n))
# ---------------------------------------------------------------------------


class TestKindLevelUCBProperties:
    def test_ucb_formula_matches_implementation(self):
        for seed in range(_TRIALS):
            sched = KindLevelUCBScheduler(KINDS, c_explore=0.25, seed=seed)
            # Warm all kinds so t > 0 and n > 0
            for k in KINDS:
                d = sched.select()
                sched.update(d.kind, float(seed % 10) * 0.1)
            for k in KINDS:
                n = sched.pulls[k]
                mean = sched.reward_sum[k] / n
                expected = mean + sched.c * math.sqrt(math.log(sched.t + 1) / n)
                assert sched._ucb(k) == pytest.approx(expected, abs=_TOL)

    def test_untried_beats_tried(self):
        for seed in range(_TRIALS):
            sched = KindLevelUCBScheduler(KINDS, seed=seed)
            d = sched.select()
            sched.update(d.kind, 0.5)
            tried = d.kind
            for k in KINDS:
                if k != tried:
                    assert sched._ucb(k) == float("inf")
                    assert sched._ucb(k) > sched._ucb(tried)

    def test_score_monotonic_in_mean(self):
        for seed in range(_TRIALS):
            sched = KindLevelUCBScheduler(KINDS, seed=seed)
            for k in KINDS:
                d = sched.select()
                sched.update(d.kind, 0.1)
            k = KINDS[0]
            n = sched.pulls[k]
            t = sched.t
            low = sched._ucb(k)
            sched.reward_sum[k] += 1.0
            high = sched._ucb(k)
            assert high > low + _TOL
            # n and t fixed after this single reward bump
            assert sched.pulls[k] == n
            assert sched.t == t + 0  # no extra select

    def test_score_monotonic_in_total_pulls(self):
        """Holding n_i and mean fixed, UCB exploration term grows with N_total."""
        for seed in range(_TRIALS):
            sched = KindLevelUCBScheduler(KINDS, seed=seed)
            for k in KINDS:
                d = sched.select()
                sched.update(d.kind, 0.5)
            k = KINDS[1]
            n = sched.pulls[k]
            mean = sched.reward_sum[k] / n
            t_lo = sched.t
            t_hi = t_lo + 10
            low = mean + sched.c * math.sqrt(math.log(t_lo + 1) / n)
            high = mean + sched.c * math.sqrt(math.log(t_hi + 1) / n)
            assert high >= low - _TOL


# ---------------------------------------------------------------------------
# KindLevelTSScheduler
# ---------------------------------------------------------------------------


class TestKindLevelTSProperties:
    def test_update_success_increments_alpha_only(self):
        for seed in range(_TRIALS):
            sched = KindLevelTSScheduler(KINDS, seed=seed)
            k = KINDS[seed % len(KINDS)]
            a0, b0 = sched._alpha(k), sched._beta(k)
            sched.update(k, 1)
            assert sched._alpha(k) == pytest.approx(a0 + 1)
            assert sched._beta(k) == pytest.approx(b0)

    def test_update_failure_increments_beta_only(self):
        for seed in range(_TRIALS):
            sched = KindLevelTSScheduler(KINDS, seed=seed)
            k = KINDS[seed % len(KINDS)]
            a0, b0 = sched._alpha(k), sched._beta(k)
            sched.update(k, 0)
            assert sched._alpha(k) == pytest.approx(a0)
            assert sched._beta(k) == pytest.approx(b0 + 1)

    def test_update_always_increments_pulls(self):
        for seed in range(_TRIALS):
            sched = KindLevelTSScheduler(KINDS, seed=seed)
            k = KINDS[seed % len(KINDS)]
            p0 = sched.pulls[k]
            sched.update(k, seed % 2)
            assert sched.pulls[k] == p0 + 1

    def test_select_samples_in_unit_interval(self):
        rng = random.Random(99)
        for _ in range(_TRIALS):
            sched = KindLevelTSScheduler(KINDS, seed=rng.randint(0, 10**9))
            d = sched.select()
            assert d.score is not None
            assert 0.0 <= d.score <= 1.0 + _TOL
