#!/usr/bin/env python3
"""
Adversarial / skeptical-review tests for cloud1 Phase 5 bandit_ts.

Written by Opus during Phase 5 review of Composer's implementation.
Target areas (from Composer's review pointer):
  1. floor priority order (cold > singleton > epoch > adaptive)
  2. all-cold behavior for N < (num_arms * cold_start_pulls_per_arm)
  3. UCB vs TS reward signal handling
  4. epoch reset arithmetic
  5. UCB runnerup ≠ chosen invariant
  6. determinism under seed
"""

from __future__ import annotations

from collections import Counter
from typing import List, Set, Tuple

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.semantic_arm_universe import SemanticArmUniverse, ArmKey
from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    KindLevelUCBScheduler,
    KindLevelTSScheduler,
    arm_id,
)


def _cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(cycle_idx=step, step=step, pc=0, txn_idx=0,
                      major=major, minor=0)


def _small_universe() -> SemanticArmUniverse:
    """3-kind × small trace yielding ~5-7 (kind, zone) arms."""
    cycles = [
        _cycle(0, 0), _cycle(1, 0), _cycle(2, 5),
        _cycle(3, 5), _cycle(4, 0),
    ]
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return SemanticArmUniverse.build(
        data,
        ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR"],
    )


def _larger_universe() -> SemanticArmUniverse:
    """More cycles + 4 kinds → ~10-15 arms; useful for floor / cold tests."""
    cycles = []
    for i in range(20):
        major = i % 7   # spread across all 7 instruction majors
        cycles.append(_cycle(i, major))
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return SemanticArmUniverse.build(
        data,
        ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR", "COMP_OUT_MOD"],
    )


KINDS_3 = ["INSTR_TYPE_MOD", "LOAD_VAL_MOD", "INSTR_WORD_MOD_SUR"]


# ---------------------------------------------------------------------------
# 1. FLOOR PRIORITY ORDER
# ---------------------------------------------------------------------------

class TestFloorPriorityOrder:
    """Cold > Singleton > Epoch-floor > Adaptive."""

    def test_cold_beats_singleton(self):
        # Singleton arm exists AND cold-start not satisfied -> cold mode fires.
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=3, forced_singleton_pulls=5,
            epoch_size=1000, seed=1,
        )
        # All arms pulls=0; singletons exist; should pick cold, not singleton.
        d = sched.select()
        assert d.mode == "cold", f"expected cold, got {d.mode}"

    def test_singleton_beats_epoch_floor(self):
        # After cold-start, singletons should drain BEFORE epoch-floor opens.
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=5,
            epoch_size=1000, coverage_floor_fraction=0.55, seed=1,
        )
        # Drain cold-start (1 pull/arm)
        for _ in range(sched.universe.num_arms):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        # Now singleton arms have pulls=1 < 5 → next picks MUST be singleton (until drained).
        singletons = set(au.singleton_arms())
        if singletons:
            d = sched.select()
            assert d.mode == "singleton", (
                f"expected singleton (singletons={singletons}), got mode={d.mode}, "
                f"arm={d.arm_id}"
            )

    def test_epoch_floor_beats_adaptive(self):
        au = _small_universe()
        n_arms = au.num_arms
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=1,
            epoch_size=100, coverage_floor_fraction=0.55, seed=1,
        )
        # Drain cold + singleton
        for _ in range(n_arms * 2):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        # epoch_pulls has been incrementing; epoch_size=100 so still mid-epoch.
        # Floor target = 0.55 * 100 / n_arms; should still be UNDER target for some arms.
        target = sched._floor_target()
        under_arms = [a for a in sched.arms if sched.epoch_pulls[a] < target - 1e-12]
        if under_arms:
            d = sched.select()
            assert d.mode in ("floor", "singleton"), (
                f"expected floor (singletons should be drained), got {d.mode}; "
                f"under_arms={len(under_arms)}, target={target:.2f}"
            )


# ---------------------------------------------------------------------------
# 2. ALL-COLD BEHAVIOR FOR N < (num_arms * cold_start_pulls_per_arm)
# ---------------------------------------------------------------------------

class TestAllColdBehavior:
    """Validates Composer's smoke observation: 89/89 mode=cold with ~50 arms × 3 cold."""

    def test_all_cold_until_quota_satisfied(self):
        au = _larger_universe()
        n_arms = au.num_arms
        cold_quota = 3
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=cold_quota, forced_singleton_pulls=1,
            epoch_size=1000, seed=42,
        )
        modes_before_all_warm = []
        for i in range(n_arms * cold_quota):
            d = sched.select()
            modes_before_all_warm.append(d.mode)
            sched.update(d.kind, d.zone, 0)
        # Every single one must be cold.
        assert all(m == "cold" for m in modes_before_all_warm), (
            f"Some non-cold picks in first {n_arms * cold_quota}: "
            f"{Counter(modes_before_all_warm)}"
        )

    def test_first_non_cold_after_quota_exact(self):
        au = _larger_universe()
        n_arms = au.num_arms
        cold_quota = 3
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=cold_quota, forced_singleton_pulls=0,
            epoch_size=10000, coverage_floor_fraction=0.0, seed=42,
        )
        # Drain exactly cold quota
        for _ in range(n_arms * cold_quota):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        # Now next pick MUST be adaptive (no singleton, no floor, no cold).
        d = sched.select()
        assert d.mode == "adaptive", (
            f"expected adaptive after cold quota drained, got {d.mode}"
        )

    def test_cold_round_robin_not_random(self):
        """D29: cold-start uses round-robin (deterministic), not rng.choice."""
        au = _larger_universe()
        n_arms = au.num_arms
        sched1 = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=0,
            epoch_size=10000, seed=1,
        )
        sched2 = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=0,
            epoch_size=10000, seed=999,  # DIFFERENT seed
        )
        picks1, picks2 = [], []
        for _ in range(n_arms):
            d1 = sched1.select(); sched1.update(d1.kind, d1.zone, 0); picks1.append(d1.arm_id)
            d2 = sched2.select(); sched2.update(d2.kind, d2.zone, 0); picks2.append(d2.arm_id)
        # Round-robin should be seed-independent during cold-start
        assert picks1 == picks2, (
            f"Cold-start picks differ across seeds (not round-robin!): "
            f"seed=1: {picks1[:5]}... vs seed=999: {picks2[:5]}..."
        )


# ---------------------------------------------------------------------------
# 3. EPOCH RESET ARITHMETIC
# ---------------------------------------------------------------------------

class TestEpochReset:
    """epoch_pulls must reset to 0 every `epoch_size` updates."""

    def test_epoch_resets_after_exactly_epoch_size(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=1,
            epoch_size=10, coverage_floor_fraction=0.0, seed=1,
        )
        # Drain enough to get past cold/singleton phases.
        for _ in range(au.num_arms * 2):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        # After (au.num_arms * 2) updates, _epoch_mutations counter likely reset 1+ times.
        # Now do exactly epoch_size MORE updates to align cleanly.
        n_before = sched._epoch_mutations
        target = sched.epoch_size
        do = target - n_before  # bring counter to 0 by triggering exactly one reset
        for _ in range(do):
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        # epoch_mutations should be 0 (just reset), epoch_pulls all 0
        assert sched._epoch_mutations == 0
        assert all(sched.epoch_pulls[a] == 0 for a in sched.arms)

    def test_total_pulls_not_reset_on_epoch_boundary(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=1,
            epoch_size=5, seed=1,
        )
        for _ in range(50):  # 10 epochs
            d = sched.select()
            sched.update(d.kind, d.zone, 0)
        total = sum(sched.pulls.values())
        assert total == 50, f"total pulls should accumulate across epochs, got {total}"

    def test_successes_not_reset_on_epoch_boundary(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=1, forced_singleton_pulls=1,
            epoch_size=5, seed=1,
        )
        # Force one arm to always succeed
        first = au.available_arms[0]
        for _ in range(50):
            d = sched.select()
            success = 1 if ArmKey.v5(d.kind, d.zone) == first else 0
            sched.update(d.kind, d.zone, success)
        # Posterior should reflect all successes (alpha=1+s_total)
        s_first = sched.successes[first]
        p_first = sched.pulls[first]
        assert s_first > 0
        assert sched._alpha(first) == 1.0 + s_first
        assert sched._beta(first) == 1.0 + (p_first - s_first)


# ---------------------------------------------------------------------------
# 4. UCB RUNNERUP INVARIANT (potential subtle bug)
# ---------------------------------------------------------------------------

class TestUCBRunnerupInvariant:
    """When KindLevelUCB has ties, runnerup might equal chosen (logging artifact)."""

    def test_runnerup_can_equal_chosen_when_tied_FYI(self):
        """DOCUMENTS a quirk: with tied UCB scores, runnerup may equal chosen.

        This is a logging-quality issue, not a correctness bug. Composer's
        impl uses sorted_k[1] regardless of tied chosen. If Phase 9 analysis
        is sensitive to runnerup distinctness, post-process the bandit_decisions
        table.
        """
        # Construct a controlled scenario: 3 kinds, force 2 to tie at the top.
        sched = KindLevelUCBScheduler(KINDS_3, c_explore=0.0, seed=1)  # c=0 -> pure greedy
        # Drain cold-start (one pull each)
        for _ in range(3):
            d = sched.select()
            sched.update(d.kind, 0.5)   # equal rewards → tied means
        # Now all scores equal (mean=0.5, c=0). Pick a few more; ties resolve via rng.choice.
        ties_observed = 0
        runnerup_eq_chosen = 0
        for _ in range(20):
            d = sched.select()
            if d.runnerup_arm is not None and d.runnerup_arm == d.arm_id:
                runnerup_eq_chosen += 1
            ties_observed += 1
            sched.update(d.kind, 0.5)
        # This is OK; just documenting. If the count is > 0 it's the known quirk.
        # We don't assert nonzero (depends on rng); but assert no crash.
        assert ties_observed == 20

    def test_runnerup_differs_when_clear_winner(self):
        sched = KindLevelUCBScheduler(KINDS_3, c_explore=0.0, seed=1)
        for _ in range(3):
            d = sched.select()
            sched.update(d.kind, 0.5)
        # Give one kind a big reward boost.
        for _ in range(20):
            d = sched.select()
            sched.update(d.kind, 0.95 if d.kind == "INSTR_TYPE_MOD" else 0.01)
        # Final pick should have INSTR_TYPE_MOD as chosen, runnerup != chosen.
        d = sched.select()
        assert d.kind == "INSTR_TYPE_MOD"
        if d.runnerup_arm is not None:
            assert d.runnerup_arm != d.arm_id


# ---------------------------------------------------------------------------
# 5. UCB & TS DETERMINISM UNDER SEED
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_constrained_ts_deterministic(self):
        au = _small_universe()

        def run(seed: int) -> List[str]:
            s = ConstrainedTSScheduler(au, seed=seed)
            out = []
            for _ in range(20):
                d = s.select()
                out.append(d.arm_id)
                s.update(d.kind, d.zone, 0)
            return out

        a = run(123)
        b = run(123)
        assert a == b

    def test_kind_ts_deterministic(self):
        def run(seed: int) -> List[str]:
            s = KindLevelTSScheduler(KINDS_3, seed=seed)
            out = []
            for _ in range(30):
                d = s.select()
                out.append(d.arm_id)
                s.update(d.kind, 0)
            return out

        a = run(42)
        b = run(42)
        assert a == b
        # Different seeds should diverge (with high prob)
        c = run(43)
        assert a != c

    def test_kind_ucb_deterministic(self):
        def run(seed: int) -> List[str]:
            s = KindLevelUCBScheduler(KINDS_3, seed=seed)
            out = []
            for _ in range(20):
                d = s.select()
                out.append(d.arm_id)
                s.update(d.kind, 0.3 if d.kind == "LOAD_VAL_MOD" else 0.5)
            return out

        a = run(7)
        b = run(7)
        assert a == b


# ---------------------------------------------------------------------------
# 6. BERNOULLI POSTERIOR ARITHMETIC
# ---------------------------------------------------------------------------

class TestPosteriorArithmetic:
    def test_alpha_increments_only_on_success(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(
            au, cold_start_pulls_per_arm=0, forced_singleton_pulls=0,
            epoch_size=10000, coverage_floor_fraction=0.0, seed=1,
        )
        arm = au.available_arms[0]
        for _ in range(7):
            sched.update(arm.kind, arm.zone, 1)  # 7 successes
        for _ in range(3):
            sched.update(arm.kind, arm.zone, 0)  # 3 failures
        assert sched.pulls[arm] == 10
        assert sched.successes[arm] == 7
        assert sched._alpha(arm) == 1.0 + 7
        assert sched._beta(arm) == 1.0 + 3

    def test_update_with_unknown_arm_is_noop(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(au, seed=1)
        before_pulls = dict(sched.pulls)
        sched.update("UNKNOWN_KIND", "unknown_zone", 1)
        assert sched.pulls == before_pulls   # no change

    def test_success_clamped_to_int(self):
        """`success` should be int-coerced regardless of input type."""
        au = _small_universe()
        sched = ConstrainedTSScheduler(au, seed=1)
        arm = au.available_arms[0]
        sched.update(arm.kind, arm.zone, True)   # bool → int
        assert sched.successes[arm] == 1


# ---------------------------------------------------------------------------
# 7. EMPTY-EDGE CASES
# ---------------------------------------------------------------------------

class TestEmptyEdgeCases:
    def test_empty_universe_raises(self):
        # Build a universe with no kinds → produces 0 arms.
        data = InspectionData(cycles=[_cycle(0, 0)], all_txns=[], reg_txns=[])
        empty = SemanticArmUniverse.build(data, [])
        sched = ConstrainedTSScheduler(empty, seed=1)
        with pytest.raises(RuntimeError):
            sched.select()

    def test_select_returns_valid_step_in_arm(self):
        au = _small_universe()
        sched = ConstrainedTSScheduler(au, seed=1)
        for _ in range(30):
            d = sched.select()
            valid_steps = au.steps_in_arm(d.kind, d.zone)
            assert d.step in valid_steps, (
                f"Selected step {d.step} not in arm's valid steps {valid_steps}"
            )
            sched.update(d.kind, d.zone, 0)
