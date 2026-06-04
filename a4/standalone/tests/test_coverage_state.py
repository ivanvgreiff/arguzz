#!/usr/bin/env python3
"""
Phase II.2R / Phase III.0 unit tests for CoverageState, compute_reward, update_state,
and derive_global_contexts.

Tests the 5-component reward (T_new, T_rare, F_new, F_rare, U),
three-factor Q (Q_loc * Q_rep * Q_glob), weighted average, baseline seeding,
valid-run gating, update order, and global-context unification.

Phase III.0 deltas:
  - U replaces Z (stricter: also requires d_glob == 0)
  - d_loc/d_glob/d_ext replace d_fail
  - Q_loc/Q_glob replace/extend Q_dist
  - F_new and F_rare run over the extended context set

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
    derive_global_contexts,
)


def _params(**overrides) -> CalibratedParams:
    defaults = dict(
        tau_new=64.0, tau_d=3.0, K_T_rare=32, gamma=0.9965,
        tau_F_new=2.0, K_F_rare=2, r_0=10, tau_r=25.0, c_explore=0.25,
        a_Tn=1.0, a_Tr=0.25, a_Fn=1.0, a_Fr=1.0, a_U=1.0,
        # tau_g defaults to 2*tau_d via __post_init__
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

    def test_U_fires_correctly(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        assert d["U"] == 1  # REJECTED + proof + d_loc==0 + d_glob==0

    def test_U_not_on_crash(self):
        state = CoverageState(_params())
        r, d = compute_reward(_bm({0: 1}), [], -11, "CRASH", False, state)
        assert d["U"] == 0

    def test_U_not_without_proof(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        r, d = compute_reward(bm, [], 101, "REJECTED", False, state)
        assert d["U"] == 0  # proof_generated is False

    def test_U_not_with_failures(self):
        state = CoverageState(_params())
        bm = _bm({0: 1})
        fails = [_fail("A", 0, 0)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        assert d["U"] == 0  # d_loc > 0

    def test_Q_loc_penalty(self):
        state = CoverageState(_params(tau_d=3.0))
        bm = _bm({0: 1})
        fails = [_fail(f"F{i}", i, 0) for i in range(6)]
        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state)
        expected_Q_loc = math.exp(-6.0 / 3.0)
        assert abs(d["Q_loc"] - expected_Q_loc) < 0.001

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
        state = CoverageState(_params(a_Tn=1.0, a_Tr=0.0, a_Fn=0.0, a_Fr=0.0, a_U=0.0))
        bm = _bm({i: 1 for i in range(50)})
        r, d = compute_reward(bm, [], 101, "REJECTED", True, state)
        # Only T_new has weight, and U fires but a_U=0
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


# =============================================================================
# Phase III.0 — Global-Aware Reward
# =============================================================================

def _residues(*nonzero_families) -> list:
    """Build family_residues fixture. Pass family names that are nonzero.
    Adds exactly one nonzero=False entry per missing family for realism."""
    return [
        {"family": fam, "nonzero": True, "e0": 1, "e1": 0, "e2": 0, "e3": 0}
        for fam in nonzero_families
    ]


def _details_memory(*addrs) -> dict:
    return {
        "family": "memory", "broken_addrs": list(addrs),
        "broken_count": len(addrs), "total_addrs": len(addrs),
        "n_reg": 0, "n_code": 0, "n_data": len(addrs),
    }


def _details_lookup(family: str, *idxs) -> dict:
    return {
        "family": family, "broken_indices": list(idxs),
        "broken_count": len(idxs), "total_indices": len(idxs),
    }


class TestDeriveGlobalContexts:
    def test_empty_input(self):
        assert derive_global_contexts(None, None) == set()
        assert derive_global_contexts([], []) == set()
        assert derive_global_contexts(_residues(), [_details_memory(1, 2)]) == set()

    def test_only_memory(self):
        ctx = derive_global_contexts(
            _residues("memory"), [_details_memory(10, 20, 30)]
        )
        assert ctx == {
            ("GLOBAL", "memory", "10"),
            ("GLOBAL", "memory", "20"),
            ("GLOBAL", "memory", "30"),
        }

    def test_only_lookup(self):
        ctx = derive_global_contexts(
            _residues("u8"), [_details_lookup("u8", 5, 7)]
        )
        assert ctx == {("GLOBAL", "u8", "5"), ("GLOBAL", "u8", "7")}

    def test_mixed_memory_and_lookup(self):
        ctx = derive_global_contexts(
            _residues("memory", "u8", "u16"),
            [
                _details_memory(100),
                _details_lookup("u8", 5),
                _details_lookup("u16", 9, 12),
            ],
        )
        assert ctx == {
            ("GLOBAL", "memory", "100"),
            ("GLOBAL", "u8", "5"),
            ("GLOBAL", "u16", "9"),
            ("GLOBAL", "u16", "12"),
        }

    def test_residue_without_detail(self):
        # Residue says nonzero but no detail dict provided -> empty result
        # (defensive: don't fabricate keys when we lack address info)
        assert derive_global_contexts(_residues("memory"), None) == set()
        assert derive_global_contexts(_residues("memory"), []) == set()

    def test_detail_for_zero_residue_family_skipped(self):
        # Family detail present but residue says nonzero=False -> family ignored
        residues = [
            {"family": "memory", "nonzero": False},
            {"family": "u8", "nonzero": True, "e0": 1, "e1": 0, "e2": 0, "e3": 0},
        ]
        details = [_details_memory(99), _details_lookup("u8", 7)]
        ctx = derive_global_contexts(residues, details)
        assert ctx == {("GLOBAL", "u8", "7")}


class TestGlobalAwareReward:
    """Phase III.0: F_new and F_rare run over F_ext = F_loc U F_glob;
    Q gains Q_glob; U replaces Z with stricter semantics."""

    def test_no_global_contexts_matches_local_only_baseline(self):
        """With global_contexts=set(), reward equals the pre-III.0 reward
        on a non-trivial fixture."""
        state = CoverageState(_params(tau_new=64.0, tau_d=3.0))
        bm = _bm({i: 1 for i in range(50)})
        fails = [_fail("A", 0, 0), _fail("A", 0, 0), _fail("B", 1, 0)]  # n=3, d_loc=2, r_rep=1

        r, d = compute_reward(bm, fails, 101, "REJECTED", True, state, global_contexts=set())

        # Verify baseline shape
        assert d["d_loc"] == 2
        assert d["d_glob"] == 0
        assert d["d_ext"] == 2
        assert d["U"] == 0
        assert d["Q_glob"] == 1.0  # exp(-0/tau_g) = 1
        assert d["Q_loc"] == pytest.approx(math.exp(-2.0 / 3.0), abs=1e-9)
        # Reward equals what the legacy formula would have produced
        assert 0.0 < r < 1.0

    def test_global_only_increases_F_new_and_lowers_Q_glob(self):
        state = CoverageState(_params(tau_F_new=2.0, tau_d=3.0))
        # Baseline-seed touch so delta_T = 0 (we want to isolate F_* contribution)
        state.seed_from_baseline(_bm({0: 1, 1: 1, 2: 1}))
        bm = _bm({0: 1, 1: 1, 2: 1})
        g_ctx = {
            ("GLOBAL", "memory", "10"),
            ("GLOBAL", "u8", "5"),
            ("GLOBAL", "u16", "7"),
        }

        r, d = compute_reward(bm, [], 0, "REJECTED", True, state, global_contexts=g_ctx)

        assert d["d_loc"] == 0
        assert d["d_glob"] == 3
        assert d["d_ext"] == 3
        assert d["F_new"] > 0  # all three globals novel
        assert d["U"] == 0  # because d_glob > 0
        assert d["Q_glob"] < 1.0  # mild penalty bites
        assert d["Q_loc"] == 1.0  # exp(0) = 1, no local failures

    def test_U_indicator_distinguishes_global_from_unknown(self):
        """U=1 requires d_loc=0 AND d_glob=0 (and proof + REJECTED)."""
        state = CoverageState(_params())
        bm = _bm({0: 1})

        # Case (a): clean rejection with no failures of any kind -> U=1
        _, d = compute_reward(bm, [], 0, "REJECTED", True, state, global_contexts=set())
        assert d["U"] == 1

        # Case (b): rejected with global-only failures -> U=0
        g = {("GLOBAL", "memory", "1")}
        _, d = compute_reward(bm, [], 0, "REJECTED", True, state, global_contexts=g)
        assert d["U"] == 0

        # Case (c): rejected with local failures only -> U=0
        _, d = compute_reward(bm, [_fail()], 101, "REJECTED", True, state, global_contexts=set())
        assert d["U"] == 0

        # Case (d): rejected with both -> U=0
        _, d = compute_reward(bm, [_fail()], 101, "REJECTED", True, state, global_contexts=g)
        assert d["U"] == 0

    def test_Q_glob_mild_relative_to_Q_loc(self):
        """With tau_g = 2*tau_d (default), Q_glob(d_glob=2k) == Q_loc(d_loc=k)."""
        p = _params(tau_d=3.0)
        assert p.tau_g == pytest.approx(6.0)  # __post_init__ default

        # Local case: 3 distinct local failures, tau_d=3 -> Q_loc = exp(-1)
        state_a = CoverageState(p)
        bm = _bm({0: 1})
        fails = [_fail("A", 1, 1), _fail("B", 2, 2), _fail("C", 3, 3)]
        _, d_loc = compute_reward(bm, fails, 101, "REJECTED", True, state_a)

        # Global case: 6 distinct global contexts, tau_g=6 -> Q_glob = exp(-1)
        state_b = CoverageState(p)
        g = {("GLOBAL", "memory", str(i)) for i in range(6)}
        _, d_glob = compute_reward(bm, [], 0, "REJECTED", True, state_b, global_contexts=g)

        assert d_loc["Q_loc"] == pytest.approx(d_glob["Q_glob"], abs=1e-9)
        assert d_loc["Q_loc"] == pytest.approx(math.exp(-1.0), abs=1e-6)

    def test_update_state_increments_once_per_ext_ctx(self):
        """Local repeats are deduped (existing semantics); globals are already a set.
        Two consecutive runs with the same ext_contexts each bump every key by 1."""
        state = CoverageState(_params())
        bm = _bm({0: 1})
        # Three local instances of the SAME context plus two global contexts.
        f = [_fail("A", 1, 1)] * 3
        g = {("GLOBAL", "memory", "10"), ("GLOBAL", "u8", "5")}

        update_state(bm, f, 101, state, global_contexts=g)
        update_state(bm, f, 101, state, global_contexts=g)

        # constraint_loc() shortens the fixture path to "A@test.zir:1"
        loc_key = ("A@test.zir:1", 1, 1)
        assert state.fail_freq[loc_key] == 2  # once per run, regardless of repeats
        assert state.fail_freq[("GLOBAL", "memory", "10")] == 2
        assert state.fail_freq[("GLOBAL", "u8", "5")] == 2

    def test_compute_reward_reads_extended_freq_for_F_rare(self):
        """F_rare must consider state.fail_freq entries for global keys too."""
        p = _params(K_F_rare=1)
        state = CoverageState(p)
        # Pre-seed: a global context already seen 99 times (very common).
        common_g = ("GLOBAL", "memory", "100")
        state.fail_freq[common_g] = 99
        bm = _bm({0: 1})

        # Run breaks two globals: the common one and a fresh one.
        g = {common_g, ("GLOBAL", "memory", "200")}
        _, d = compute_reward(bm, [], 0, "REJECTED", True, state, global_contexts=g)

        # K_F_rare=1: top-1 should be the rare one with weight 1/sqrt(1+0)=1.0
        assert d["F_rare"] == pytest.approx(1.0, abs=1e-9)


class TestCalibratedParamsAlias:
    """Phase III.0 rename: a_Z is preserved as a property alias for a_U."""

    def test_a_Z_reads_a_U(self):
        p = _params(a_U=0.7)
        assert p.a_Z == 0.7

    def test_a_Z_setter_writes_a_U(self):
        p = _params()
        p.a_Z = 2.5
        assert p.a_U == 2.5

    def test_tau_g_default_is_2x_tau_d(self):
        p = _params(tau_d=3.0)
        assert p.tau_g == pytest.approx(6.0)

    def test_tau_g_explicit_override(self):
        p = _params(tau_d=3.0, tau_g=12.0)
        assert p.tau_g == 12.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
