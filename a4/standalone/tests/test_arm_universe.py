#!/usr/bin/env python3
"""
Phase II.1 unit tests for arm universe construction.

Tests pow2_clamp and ArmUniverse with synthetic data (no host required),
plus an integration test with real inspection data (host required).

Run: python -m pytest a4/standalone/tests/test_arm_universe.py -v
"""

import os

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.arm_universe import pow2_clamp, ArmUniverse


# =========================================================================
# Helpers for building synthetic InspectionData
# =========================================================================

def _make_cycle(step: int, major: int, minor: int = 0) -> A4CycleInfo:
    """Create a minimal A4CycleInfo for testing."""
    return A4CycleInfo(cycle_idx=step, step=step, pc=0, txn_idx=0, major=major, minor=minor)


def _make_inspection(cycles: list) -> InspectionData:
    """Create an InspectionData from a list of A4CycleInfo objects."""
    return InspectionData(cycles=cycles)


# =========================================================================
# pow2_clamp tests
# =========================================================================

class TestPow2Clamp:
    def test_exact_power(self):
        assert pow2_clamp(64, 16, 128) == 64
        assert pow2_clamp(32, 16, 128) == 32
        assert pow2_clamp(16, 16, 128) == 16
        assert pow2_clamp(128, 16, 128) == 128

    def test_round_down(self):
        assert pow2_clamp(41, 16, 128) == 32
        assert pow2_clamp(63, 16, 128) == 32
        assert pow2_clamp(100, 16, 128) == 64
        assert pow2_clamp(33, 16, 128) == 32

    def test_clamp_to_lo(self):
        assert pow2_clamp(5, 16, 128) == 16
        assert pow2_clamp(1, 16, 128) == 16
        assert pow2_clamp(15, 16, 128) == 16

    def test_clamp_to_hi(self):
        assert pow2_clamp(200, 16, 128) == 128
        assert pow2_clamp(256, 16, 128) == 128
        assert pow2_clamp(1000, 16, 128) == 128

    def test_zero_and_negative(self):
        assert pow2_clamp(0, 16, 128) == 16
        assert pow2_clamp(-5, 16, 128) == 16

    def test_small_range(self):
        assert pow2_clamp(1, 1, 4) == 1
        assert pow2_clamp(3, 1, 4) == 2
        assert pow2_clamp(4, 1, 4) == 4
        assert pow2_clamp(7, 1, 4) == 4


# =========================================================================
# ArmUniverse tests (synthetic data)
# =========================================================================

KINDS = [
    "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD", "MEM_VAL_MOD", "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR",
]


class TestArmUniverseSynthetic:
    def _make_simple_data(self) -> InspectionData:
        """Create a simple trace with 100 steps, various majors."""
        cycles = []
        for s in range(100):
            if s < 30:
                major = 0  # MISC0 (valid for COMP_OUT_MOD, PRE_EXEC_REG_MOD, etc.)
            elif s < 50:
                major = 5  # MEM0 / load (valid for LOAD_VAL_MOD)
            elif s < 70:
                major = 6  # MEM1 / store (valid for STORE_OUT_MOD)
            else:
                major = 7  # CONTROL0 (not valid for most kinds)
            cycles.append(_make_cycle(s, major))
        return _make_inspection(cycles)

    def test_basic_construction(self):
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=1000, mutation_kinds=KINDS)

        # Steps 70-99 have major=7 (CONTROL) → not valid for any kind
        # max valid step = 69 → T = 70
        assert au.T == 70
        assert au.K == 8
        assert au.B_count == 32  # pow2_clamp(1000//(8*3)=41, 16, 128) = 32
        assert au.B == 3  # ceil(70/32) = 3
        assert au.num_arms > 0
        assert au.num_arms <= 8 * 32

    def test_T_from_valid_steps(self):
        """T should be 1 + max valid step, not 1 + max of all cycles."""
        # Create cycles where the last step (99) has major=7 (CONTROL)
        # which is not valid for most kinds except INSTR_WORD_MOD (major<=6 or ==8)
        # So major=7 is excluded from all kinds
        cycles = [_make_cycle(s, major=0) for s in range(50)]
        # Add step 99 with major=7 (control — not valid for any kind)
        cycles.append(_make_cycle(99, major=7))
        data = _make_inspection(cycles)

        au = ArmUniverse(data, budget=1000, mutation_kinds=KINDS)
        # T should be 50 (1 + max of steps 0..49) not 100 (1 + 99)
        # because step 99 with major=7 is not valid for any of the 8 kinds
        assert au.T == 50

    def test_bucket_assignment(self):
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=1000, mutation_kinds=KINDS)

        # B = 3 for this case (ceil(70/32) = 3)
        assert au.B == 3
        assert au.bucket_for_step(0) == 0  # 0 // 3 = 0
        assert au.bucket_for_step(2) == 0  # 2 // 3 = 0
        assert au.bucket_for_step(3) == 1  # 3 // 3 = 1
        assert au.bucket_for_step(5) == 1  # 5 // 3 = 1
        assert au.bucket_for_step(6) == 2  # 6 // 3 = 2
        assert au.bucket_for_step(69) == 23  # 69 // 3 = 23

    def test_empty_kind_no_arms(self):
        """A kind with no valid steps produces no arms."""
        # Only major=5 cycles → only LOAD_VAL_MOD has steps
        cycles = [_make_cycle(s, major=5) for s in range(10)]
        data = _make_inspection(cycles)

        au = ArmUniverse(data, budget=500, mutation_kinds=KINDS)
        # COMP_OUT_MOD requires major 0-4, none present → no arms for it
        comp_arms = [(k, b) for k, b in au.available_arms if k == "COMP_OUT_MOD"]
        assert len(comp_arms) == 0
        # LOAD_VAL_MOD should have arms
        load_arms = [(k, b) for k, b in au.available_arms if k == "LOAD_VAL_MOD"]
        assert len(load_arms) > 0

    def test_n_min_with_large_budget(self):
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=10000, mutation_kinds=KINDS)
        assert au.n_min == 1  # budget >> num_arms

    def test_n_min_with_tiny_budget(self):
        """With a tiny budget, n_min should be 0 if budget < num_arms."""
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=5, mutation_kinds=KINDS)
        # With budget=5, B_count = pow2_clamp(5//(8*3)=0, 16, 128) = 16
        # num_arms could be up to 8*16=128, certainly > 5
        assert au.n_min == 0

    def test_steps_in_arm(self):
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=1000, mutation_kinds=KINDS)

        # Pick an arm that should exist (COMP_OUT_MOD at bucket 0)
        steps = au.steps_in_arm("COMP_OUT_MOD", 0)
        assert len(steps) > 0
        # All returned steps should map to bucket 0
        for s in steps:
            assert au.bucket_for_step(s) == 0

        # Non-existent arm returns empty
        steps = au.steps_in_arm("COMP_OUT_MOD", 999)
        assert steps == []

    def test_budget_scaling(self):
        """Larger budget should produce more buckets (up to B_MAX)."""
        data = self._make_simple_data()
        au_small = ArmUniverse(data, budget=200, mutation_kinds=KINDS)
        au_large = ArmUniverse(data, budget=5000, mutation_kinds=KINDS)
        # Small budget: 200//(8*3)=8 → pow2_clamp(8, 16, 128) = 16
        assert au_small.B_count == 16
        # Large budget: 5000//(8*3)=208 → pow2_clamp(208, 16, 128) = 128
        assert au_large.B_count == 128

    def test_summary_runs(self):
        data = self._make_simple_data()
        au = ArmUniverse(data, budget=1000, mutation_kinds=KINDS)
        s = au.summary()
        assert "Arm Universe Summary" in s
        assert "Budget (N):" in s
        assert "1000" in s


# =========================================================================
# Integration test with real inspection data
# =========================================================================

@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (and optionally A4_TEST_HOST_ARGS) to run",
)
def test_arm_universe_real_inspection():
    """Construct arm universe from real inspection data and verify plausibility."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    data = InspectionData.from_inspection(host_binary, host_args)

    for budget in [500, 1000, 5000]:
        au = ArmUniverse(data, budget=budget, mutation_kinds=KINDS)
        print(f"\n--- Budget N={budget} ---")
        print(au.summary())

        assert au.T > 0
        assert 16 <= au.B_count <= 128
        assert au.num_arms > 0
        assert au.num_arms <= au.K * au.B_count
        assert au.B > 0

        # Every arm should have at least one step
        for kind, bucket in au.available_arms:
            steps = au.steps_in_arm(kind, bucket)
            assert len(steps) > 0, f"Arm ({kind}, {bucket}) has no steps"

        # Every step in an arm should map to the correct bucket
        for (kind, bucket), steps in au.arms.items():
            for s in steps:
                assert au.bucket_for_step(s) == bucket, (
                    f"Step {s} maps to bucket {au.bucket_for_step(s)}, expected {bucket}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
