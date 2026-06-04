#!/usr/bin/env python3
"""
Phase III.2 unit tests for UniformArmSelector and the create_selector
'uniform' factory case.

Run: python -m pytest a4/standalone/tests/test_uniform_arm_selector.py -v
"""

from types import SimpleNamespace
from collections import Counter

import pytest

from a4.standalone.step_selector import (
    UniformArmSelector,
    create_selector,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

def _mock_arm_universe(kinds=("A", "B", "C"), buckets=(0, 1, 2, 3), B=10):
    """Build a duck-typed ArmUniverse with the two attributes the selector needs.

    Each (kind, bucket) arm has 3 valid steps inside [bucket*B, (bucket+1)*B).
    """
    arms = {}
    available = []
    for k in kinds:
        for b in buckets:
            steps = [b * B + 1, b * B + 4, b * B + 7]
            arms[(k, b)] = steps
            available.append((k, b))
    return SimpleNamespace(
        available_arms=sorted(available),
        arms=arms,
        B=B,
    )


# -----------------------------------------------------------------------------
# Distribution properties
# -----------------------------------------------------------------------------

class TestUniformDistribution:
    def test_arm_uniform_distribution_chi2(self):
        """5000 selections across 12 arms; chi^2 goodness-of-fit at p > 0.01.

        Critical value for 11 dof at 0.01 is ~24.7. Under the null (true
        uniform), our chi^2 statistic should fall well below this with
        probability >> 0.99.
        """
        au = _mock_arm_universe()  # 3 kinds * 4 buckets = 12 arms
        sel = UniformArmSelector(au, seed=42)
        N = 5000
        n_arms = len(au.available_arms)
        expected = N / n_arms
        counts = Counter()
        for _ in range(N):
            kind, step = sel.select_arm_then_step()
            bucket = step // au.B
            counts[(kind, bucket)] += 1

        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        # Add zeros for any unsampled arm (shouldn't happen with N=5000)
        missing = n_arms - len(counts)
        chi2 += missing * expected
        # Critical value at p=0.01 with df = 11 is approximately 24.725.
        assert chi2 < 24.725, f"chi2={chi2:.2f} suggests non-uniformity"

    def test_step_within_bucket(self):
        """Every selected step must fall inside its arm's bucket range."""
        au = _mock_arm_universe()
        sel = UniformArmSelector(au, seed=123)
        for _ in range(1000):
            kind, step = sel.select_arm_then_step()
            bucket = step // au.B
            assert (kind, bucket) in au.available_arms
            # Step must come from this arm's step list
            assert step in au.arms[(kind, bucket)]

    def test_only_uses_available_arms(self):
        au = _mock_arm_universe()
        sel = UniformArmSelector(au, seed=7)
        seen_arms = set()
        for _ in range(2000):
            kind, step = sel.select_arm_then_step()
            seen_arms.add((kind, step // au.B))
        assert seen_arms.issubset(set(au.available_arms))


# -----------------------------------------------------------------------------
# API contract
# -----------------------------------------------------------------------------

class TestApiContract:
    def test_legacy_select_step_raises(self):
        au = _mock_arm_universe()
        sel = UniformArmSelector(au, seed=1)
        with pytest.raises(NotImplementedError):
            sel.select_step(data=None, kind="A")

    def test_constructor_rejects_none_arm_universe(self):
        with pytest.raises(ValueError):
            UniformArmSelector(arm_universe=None, seed=1)

    def test_determinism_same_seed(self):
        au = _mock_arm_universe()
        s1 = UniformArmSelector(au, seed=99)
        s2 = UniformArmSelector(au, seed=99)
        seq1 = [s1.select_arm_then_step() for _ in range(50)]
        seq2 = [s2.select_arm_then_step() for _ in range(50)]
        assert seq1 == seq2

    def test_empty_arm_universe_raises(self):
        empty_au = SimpleNamespace(available_arms=[], arms={}, B=10)
        sel = UniformArmSelector(empty_au, seed=1)
        with pytest.raises(RuntimeError):
            sel.select_arm_then_step()


# -----------------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------------

class TestFactory:
    def test_factory_creates_uniform_selector(self):
        au = _mock_arm_universe()
        sel = create_selector("uniform", seed=1, arm_universe=au)
        assert isinstance(sel, UniformArmSelector)

    def test_factory_requires_arm_universe(self):
        with pytest.raises(ValueError, match="arm_universe"):
            create_selector("uniform", seed=1)

    def test_factory_rejects_unknown_strategy(self):
        with pytest.raises(ValueError, match="Unknown strategy"):
            create_selector("nonexistent", seed=1)

    def test_factory_zoned_unaffected(self):
        # Regression: existing 3-arg calls must still work.
        sel = create_selector("zoned", seed=1)
        assert sel is not None

    def test_factory_guided_unaffected(self):
        sel = create_selector("guided", seed=1)
        assert sel is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
