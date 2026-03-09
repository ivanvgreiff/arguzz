#!/usr/bin/env python3
"""
Phase II.3 unit tests for DiscountedUCBScheduler.

Tests cover: forced exploration, lazy decay, UCB exploitation, UCB exploration,
step-level selection, discount forgetting, crash rewards, N_tot computation,
step-level scoping, determinism, and synthetic integration.

Run: python -m pytest a4/standalone/tests/test_bandit.py -v
"""

from collections import Counter

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.arm_universe import ArmUniverse
from a4.standalone.pilot_calibration import CalibratedParams
from a4.standalone.bandit import DiscountedUCBScheduler, _EPSILON


# =========================================================================
# Helpers
# =========================================================================

def _make_cycle(step: int, major: int, minor: int = 0) -> A4CycleInfo:
    return A4CycleInfo(cycle_idx=step, step=step, pc=0, txn_idx=0, major=major, minor=minor)


def _make_inspection(cycles: list) -> InspectionData:
    return InspectionData(cycles=cycles)


def _small_universe(n_steps=30, budget=1000) -> ArmUniverse:
    """
    Build a small universe with 3 mutation kinds and n_steps steps.

    Kinds: COMP_OUT_MOD (major 0), MEM_VAL_MOD (major 5/6), INSTR_TYPE_MOD (all).
    Steps 0..n_steps-1, all with major=0 so COMP_OUT_MOD and INSTR_TYPE_MOD can
    target them. Add some MEM cycles so MEM_VAL_MOD has targets too.
    """
    cycles = []
    for s in range(n_steps):
        cycles.append(_make_cycle(s, major=0))
    for s in range(0, n_steps, 3):
        cycles.append(_make_cycle(s, major=5))
    data = _make_inspection(cycles)
    kinds = ["COMP_OUT_MOD", "MEM_VAL_MOD", "INSTR_TYPE_MOD"]
    return ArmUniverse(data, budget, kinds)


def _default_params(gamma=0.99) -> CalibratedParams:
    return CalibratedParams(tau_new=40.0, tau_d=3.0, K_T_rare=31, gamma=gamma)


# =========================================================================
# Test 1: Forced exploration
# =========================================================================

class TestForcedExploration:
    def test_all_arms_explored_early(self):
        """With n_min=1, all arms are explored within ~3× n_arms iterations.

        Because γ < 1, previously-explored arms decay below n_min and become
        re-eligible for forced exploration. So we allow up to 3× n_arms
        iterations, which is more than enough with high probability.
        """
        universe = _small_universe(n_steps=10, budget=1000)
        params = _default_params()
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        assert universe.n_min == 1, "n_min should be 1 for budget >= num_arms"
        n_arms = universe.num_arms

        selected_arms = set()
        for _ in range(n_arms * 3):
            kind, step = scheduler.select()
            scheduler.update(kind, step, 0.5)
            bucket = universe.bucket_for_step(step)
            selected_arms.add((kind, bucket))
            if len(selected_arms) == n_arms:
                break

        assert len(selected_arms) == n_arms, (
            f"All {n_arms} arms should be explored within 3x iterations, got {len(selected_arms)}"
        )

    def test_forced_exploration_without_update(self):
        """Without update(), all arms stay at N=0, so forced exploration repeats."""
        universe = _small_universe(n_steps=6, budget=1000)
        params = _default_params()
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        arms_seen = set()
        for _ in range(universe.num_arms * 3):
            kind, step = scheduler.select()
            bucket = universe.bucket_for_step(step)
            arms_seen.add((kind, bucket))

        assert arms_seen == set(universe.available_arms)


# =========================================================================
# Test 2: Lazy decay
# =========================================================================

class TestLazyDecay:
    def test_decay_reduces_count(self):
        """After advancing time without touching an arm, its count decays."""
        universe = _small_universe(n_steps=6, budget=1000)
        params = _default_params(gamma=0.9)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        arm = universe.available_arms[0]
        kind, bucket = arm
        steps = universe.steps_in_arm(kind, bucket)

        scheduler.t = 1
        scheduler.arm_N[arm] = 1.0
        scheduler.arm_S[arm] = 0.5
        scheduler.arm_t[arm] = 1

        scheduler.t = 21
        scheduler._decay_arm(arm)

        expected = 1.0 * (0.9 ** 20)
        assert abs(scheduler.arm_N[arm] - expected) < 0.001, (
            f"N should be γ^20 = {expected:.6f}, got {scheduler.arm_N[arm]:.6f}"
        )
        assert scheduler.arm_N[arm] < 0.15, "N should have decayed well below 0.5"

    def test_decay_preserves_mean(self):
        """Lazy decay of N and S should preserve mean reward μ = S/N."""
        universe = _small_universe(n_steps=6, budget=1000)
        params = _default_params(gamma=0.95)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        kind, step = scheduler.select()
        scheduler.update(kind, step, 0.7)
        arm = (kind, universe.bucket_for_step(step))

        mu_before = scheduler.arm_S[arm] / max(scheduler.arm_N[arm], _EPSILON)

        scheduler.t += 50
        scheduler._decay_arm(arm)

        mu_after = scheduler.arm_S[arm] / max(scheduler.arm_N[arm], _EPSILON)

        assert abs(mu_before - mu_after) < 0.001, (
            f"Mean should be preserved: {mu_before:.4f} vs {mu_after:.4f}"
        )


# =========================================================================
# Test 3: UCB exploits best arm
# =========================================================================

class TestUCBExploitation:
    def test_best_arm_selected_most(self):
        """After training, the arm with highest mean reward should be selected most."""
        universe = _small_universe(n_steps=10, budget=1000)
        params = _default_params(gamma=0.99)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)
        arms = universe.available_arms

        # Phase 1: Force-explore all arms with different rewards
        for arm in arms:
            kind, bucket = arm
            steps = universe.steps_in_arm(kind, bucket)
            scheduler.t += 1
            for a in arms:
                scheduler._decay_arm(a)
            scheduler.arm_N[arm] += 1.0
            scheduler.arm_S[arm] += (0.9 if kind == "COMP_OUT_MOD" else 0.1)
            scheduler.arm_t[arm] = scheduler.t
            step = steps[0]
            scheduler.step_N[(kind, step)] += 1.0
            scheduler.step_S[(kind, step)] += (0.9 if kind == "COMP_OUT_MOD" else 0.1)
            scheduler.step_t[(kind, step)] = scheduler.t

        # Phase 2: Let bandit select freely
        selections = Counter()
        for _ in range(100):
            kind, step = scheduler.select()
            selections[kind] += 1
            reward = 0.9 if kind == "COMP_OUT_MOD" else 0.1
            scheduler.update(kind, step, reward)

        assert selections["COMP_OUT_MOD"] > selections["MEM_VAL_MOD"], (
            f"COMP_OUT_MOD should be selected more: {dict(selections)}"
        )
        assert selections["COMP_OUT_MOD"] > selections["INSTR_TYPE_MOD"], (
            f"COMP_OUT_MOD should be selected more: {dict(selections)}"
        )


# =========================================================================
# Test 4: UCB explores unseen
# =========================================================================

class TestUCBExploration:
    def test_unseen_arm_explored(self):
        """An arm with m=0 (never pulled) should be selected via cold-start."""
        universe = _small_universe(n_steps=10, budget=1000)
        params = _default_params(gamma=0.999)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)
        arms = universe.available_arms

        scheduler.t = len(arms)

        # Mark all arms EXCEPT the last one as pulled (m > 0)
        for arm in arms[:-1]:
            kind, bucket = arm
            steps = universe.steps_in_arm(kind, bucket)
            scheduler.arm_N[arm] = 2.0
            scheduler.arm_S[arm] = 1.0
            scheduler.arm_t[arm] = scheduler.t
            scheduler.arm_m[arm] = 1
            step = steps[0]
            scheduler.step_N[(kind, step)] = 2.0
            scheduler.step_S[(kind, step)] = 1.0
            scheduler.step_t[(kind, step)] = scheduler.t
            scheduler.step_m[(kind, step)] = 1

        unseen_arm = arms[-1]
        assert scheduler.arm_m[unseen_arm] == 0, "Last arm should have m=0"
        kind, step = scheduler.select()
        bucket = universe.bucket_for_step(step)
        selected_arm = (kind, bucket)
        assert selected_arm == unseen_arm, (
            f"Should select unseen arm {unseen_arm}, got {selected_arm}"
        )


# =========================================================================
# Test 5: Step-level selection
# =========================================================================

class TestStepSelection:
    def test_step_cold_start(self):
        """Steps within a bucket should be cold-start explored (m=0 first)."""
        universe = _small_universe(n_steps=300, budget=200)
        params = _default_params(gamma=0.99)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        multi_step_arms = [
            a for a in universe.available_arms
            if len(universe.steps_in_arm(*a)) >= 3
        ]
        if not multi_step_arms:
            pytest.skip("Need an arm with at least 3 steps")
        arm = multi_step_arms[0]
        kind, bucket = arm
        steps = universe.steps_in_arm(kind, bucket)

        steps_seen = set()
        for _ in range(len(steps) * 3):
            scheduler.t += 1
            for a in universe.available_arms:
                scheduler._decay_arm(a)
            scheduler.arm_N[arm] = 10.0
            scheduler.arm_t[arm] = scheduler.t
            scheduler.arm_m[arm] = 10

            for s in steps:
                scheduler._decay_step((kind, s))

            cold_start = [s for s in steps if scheduler.step_m[(kind, s)] == 0]
            if cold_start:
                chosen = scheduler.rng.choice(cold_start)
                scheduler.step_N[(kind, chosen)] += 1.0
                scheduler.step_S[(kind, chosen)] += 0.5
                scheduler.step_t[(kind, chosen)] = scheduler.t
                scheduler.step_m[(kind, chosen)] += 1
                steps_seen.add(chosen)

        assert steps_seen == set(steps), (
            f"All steps should be cold-started: expected {set(steps)}, got {steps_seen}"
        )


# =========================================================================
# Test 6: Discount forgets old rewards
# =========================================================================

class TestDiscountForgetting:
    def test_recent_high_reward_preferred(self):
        """With strong discounting, recently-high arm should have higher discounted N."""
        universe = _small_universe(n_steps=10, budget=1000)
        params = _default_params(gamma=0.9)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)
        arms = universe.available_arms

        arm_a = arms[0]
        arm_b = arms[1] if len(arms) > 1 else arms[0]

        # Give arm A high reward early (rounds 1-5)
        for _ in range(5):
            scheduler.t += 1
            scheduler._decay_arm(arm_a)
            scheduler.arm_N[arm_a] += 1.0
            scheduler.arm_S[arm_a] += 0.9
            scheduler.arm_t[arm_a] = scheduler.t

        # Let 50 rounds pass with no arm_a updates (arm_a decays away)
        # Give arm B updates during this time
        for _ in range(50):
            scheduler.t += 1
            scheduler._decay_arm(arm_b)
            scheduler.arm_N[arm_b] += 1.0
            scheduler.arm_S[arm_b] += 0.5
            scheduler.arm_t[arm_b] = scheduler.t

        scheduler._decay_arm(arm_a)
        scheduler._decay_arm(arm_b)

        # arm_a should have decayed to near-zero N
        assert scheduler.arm_N[arm_b] > scheduler.arm_N[arm_a] * 10, (
            f"arm_b (recently active) should have much higher N: "
            f"N_a={scheduler.arm_N[arm_a]:.6f} N_b={scheduler.arm_N[arm_b]:.3f}"
        )


# =========================================================================
# Test 7: Crash reward updates
# =========================================================================

class TestCrashReward:
    def test_crash_lowers_mean(self):
        """Updating with reward=0 (crash) should lower the arm's mean."""
        universe = _small_universe(n_steps=6, budget=1000)
        params = _default_params(gamma=0.99)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)
        arm = universe.available_arms[0]

        scheduler.t = 1
        scheduler.arm_N[arm] = 1.0
        scheduler.arm_S[arm] = 0.8
        scheduler.arm_t[arm] = 1

        mu_before = scheduler.arm_S[arm] / scheduler.arm_N[arm]

        scheduler.t = 2
        scheduler._decay_arm(arm)
        scheduler.arm_N[arm] += 1.0
        scheduler.arm_S[arm] += 0.0
        scheduler.arm_t[arm] = 2

        mu_after = scheduler.arm_S[arm] / scheduler.arm_N[arm]

        assert mu_after < mu_before, (
            f"Mean should decrease after crash: {mu_before:.3f} → {mu_after:.3f}"
        )


# =========================================================================
# Test 8: N_tot uses decayed counts
# =========================================================================

class TestNTotDecayed:
    def test_n_tot_reflects_decay(self):
        """N_tot should use decayed counts, not raw cumulative."""
        universe = _small_universe(n_steps=6, budget=1000)
        params = _default_params(gamma=0.9)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)
        arms = universe.available_arms

        # Update all arms at t=1
        scheduler.t = 1
        for arm in arms:
            scheduler.arm_N[arm] = 1.0
            scheduler.arm_S[arm] = 0.5
            scheduler.arm_t[arm] = 1

        raw_total = sum(scheduler.arm_N[a] for a in arms)

        # Advance time and decay
        scheduler.t = 50
        for arm in arms:
            scheduler._decay_arm(arm)

        decayed_total = sum(scheduler.arm_N[a] for a in arms)

        assert decayed_total < raw_total * 0.1, (
            f"Decayed N_tot ({decayed_total:.3f}) should be much less than raw ({raw_total:.3f})"
        )


# =========================================================================
# Test 9: Step N_tot scoped to bucket
# =========================================================================

class TestStepNTotScope:
    def test_step_n_tot_is_bucket_scoped(self):
        """Step-level N_tot should only sum steps within the chosen bucket."""
        universe = _small_universe(n_steps=30, budget=1000)
        params = _default_params(gamma=0.99)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        kind = "COMP_OUT_MOD"
        all_comp_arms = [(k, b) for k, b in universe.available_arms if k == kind]
        if len(all_comp_arms) < 2:
            pytest.skip("Need at least 2 COMP_OUT_MOD buckets")

        arm1 = all_comp_arms[0]
        arm2 = all_comp_arms[1]
        steps1 = universe.steps_in_arm(*arm1)
        steps2 = universe.steps_in_arm(*arm2)

        # Update steps in bucket 1
        scheduler.t = 1
        for s in steps1:
            scheduler.step_N[(kind, s)] = 5.0
            scheduler.step_t[(kind, s)] = 1

        # Steps in bucket 2 should still have N=0
        n_tot_bucket2 = sum(scheduler.step_N[(kind, s)] for s in steps2)
        assert n_tot_bucket2 == 0.0, (
            f"Bucket 2 step N_tot should be 0, not {n_tot_bucket2}"
        )


# =========================================================================
# Test 10: Deterministic with seed
# =========================================================================

class TestDeterminism:
    def test_same_seed_same_selections(self):
        """Two schedulers with same seed should make identical selections."""
        universe = _small_universe(n_steps=10, budget=1000)
        params = _default_params(gamma=0.99)

        sched1 = DiscountedUCBScheduler(universe, params, seed=777)
        sched2 = DiscountedUCBScheduler(universe, params, seed=777)

        for _ in range(50):
            k1, s1 = sched1.select()
            k2, s2 = sched2.select()
            assert (k1, s1) == (k2, s2), f"Selections differ: ({k1},{s1}) vs ({k2},{s2})"
            reward = 0.3
            sched1.update(k1, s1, reward)
            sched2.update(k2, s2, reward)


# =========================================================================
# Test 11: Synthetic integration test
# =========================================================================

class TestSyntheticIntegration:
    def test_full_loop(self):
        """Run 100 iterations of select → synthetic reward → update."""
        universe = _small_universe(n_steps=30, budget=1000)
        params = _default_params(gamma=0.995)
        scheduler = DiscountedUCBScheduler(universe, params, seed=42)

        kind_rewards = {
            "COMP_OUT_MOD": 0.08,
            "MEM_VAL_MOD": 0.10,
            "INSTR_TYPE_MOD": 0.15,
        }

        selections = Counter()
        for _ in range(100):
            kind, step = scheduler.select()
            reward = kind_rewards.get(kind, 0.05)
            reward += scheduler.rng.gauss(0, 0.02)
            reward = max(0.0, min(1.0, reward))
            scheduler.update(kind, step, reward)
            selections[kind] += 1

        assert sum(selections.values()) == 100
        assert len(selections) >= 2, "At least 2 kinds should be selected"

        summary = scheduler.summary()
        assert "DiscountedUCBScheduler" in summary
        assert "t=100" in summary

    def test_bandit_learns_preference(self):
        """After sufficient training, bandit should prefer the highest-reward kind."""
        universe = _small_universe(n_steps=30, budget=5000)
        params = _default_params(gamma=0.995)
        scheduler = DiscountedUCBScheduler(universe, params, seed=123)

        kind_rewards = {
            "COMP_OUT_MOD": 0.05,
            "MEM_VAL_MOD": 0.05,
            "INSTR_TYPE_MOD": 0.25,
        }

        late_selections = Counter()
        for i in range(500):
            kind, step = scheduler.select()
            reward = kind_rewards.get(kind, 0.05)
            scheduler.update(kind, step, reward)
            if i >= 400:
                late_selections[kind] += 1

        assert late_selections["INSTR_TYPE_MOD"] >= late_selections.get("COMP_OUT_MOD", 0), (
            f"INSTR_TYPE_MOD should be preferred in late phase: {dict(late_selections)}"
        )
