"""
Coverage State and Reward Function (Phase II.2, revised in Phase II.2R)

Holds all global coverage state for a campaign and provides the reward function
that evaluates each mutation run. The reward drives the bandit scheduler.

Revised per Pro_Report_6/7:
  - 5 co-primary reward components: T_new, T_rare, F_new, F_rare, Z
  - Revised Q: Q_dist (distinct failures) * Q_rep (cascade penalty)
  - No saturation switch / rolling window
  - Baseline seeding for touch frequencies
  - Valid-run gating: crash/missing-bitmap runs don't update coverage state

Update order contract:
  1. compute_reward (reads state BEFORE this run's contribution)
  2. update_state (writes this run's contribution for next run)

See a4/docs/touch/Phase II/PHASE_II_MASTER_IMPLEMENTATION_PLAN.md §2.
"""

import math
from typing import Dict, List, Optional, Tuple

from a4.core.constraint_parser import ConstraintFailure
from a4.core.touch_coverage import (
    A4_TOUCH_MAP_SIZE,
    count_new_bits,
    merge_into_global,
    make_global_bitmap,
)
from a4.standalone.pilot_calibration import CalibratedParams


_CRASH_SIGNALS_NEGATIVE = (-11, -6, -8, -9, -10)
_CRASH_SIGNALS_SHELL = (139, 134, 136, 137, 138)


def _is_crash(exit_code: int) -> bool:
    return exit_code in _CRASH_SIGNALS_NEGATIVE or exit_code in _CRASH_SIGNALS_SHELL


class CoverageState:
    """
    All mutable campaign-level coverage state.

    Created once at campaign start. Call seed_from_baseline() before pilot runs.
    Read by compute_reward, written by update_state.
    """

    def __init__(self, params: CalibratedParams):
        self.params = params
        self.global_bitmap: bytearray = make_global_bitmap()
        self.freq: List[int] = [0] * A4_TOUCH_MAP_SIZE
        self.fail_freq: Dict[Tuple[str, int, int], int] = {}
        self.total_runs: int = 0
        self.maj_seen: Dict[int, int] = {}
        self.maj_min_seen: Dict[Tuple[int, int], int] = {}

    def seed_from_baseline(self, baseline_bitmap: bytes) -> None:
        """
        Initialize touch state from a baseline (unmutated) run.

        Sets seen_touch and freq_touch for all baseline-touched buckets so that
        pilot calibration sees incremental novelty, not the empty->baseline jump.
        Call BEFORE any pilot or campaign runs.
        """
        for i in range(A4_TOUCH_MAP_SIZE):
            if baseline_bitmap[i] > 0:
                self.global_bitmap[i] = baseline_bitmap[i]
                self.freq[i] = 1


def compute_reward(
    touch_bitmap: Optional[bytes],
    failures: List[ConstraintFailure],
    exit_code: int,
    outcome: str,
    proof_generated: bool,
    state: CoverageState,
) -> Tuple[float, dict]:
    """
    Compute the reward for a single mutation run. Does NOT modify state.

    Args:
        touch_bitmap: 65536-byte touch bitmap (or None if crash/missing).
        failures: List of ConstraintFailure from this run.
        exit_code: Host process exit code.
        outcome: "REJECTED", "CRASH", "ACCEPTED", "NO_EFFECT".
        proof_generated: Whether the host generated a proof before failing.
        state: Current CoverageState (read only).

    Returns:
        (reward, diagnostics) where reward is in [0, 1].
    """
    p = state.params

    # --- Crash / missing bitmap: reward = 0, don't compute anything ---
    if _is_crash(exit_code) or touch_bitmap is None:
        return 0.0, {
            "T_new": 0.0, "T_rare": 0.0, "F_new": 0.0, "F_rare": 0.0, "Z": 0,
            "delta_T": 0, "delta_F": 0, "d_fail": 0, "n_fail": len(failures),
            "r_rep": 0, "Q_dist": 0.0, "Q_rep": 1.0, "Q": 0.0, "S": 0.0,
            "r": 0.0, "mode": "crash",
        }

    # --- Per-run failure analysis ---
    fail_contexts = set()
    for f in failures:
        fail_contexts.add((f.constraint_loc(), f.major, f.minor))
    n_fail = len(failures)
    d_fail = len(fail_contexts)
    r_rep = max(0, n_fail - d_fail)

    # --- Touch novelty ---
    delta_T = count_new_bits(touch_bitmap, state.global_bitmap)
    T_new = 1.0 - math.exp(-delta_T / p.tau_new) if p.tau_new > 0 else 0.0

    # --- Touch rarity ---
    touched_indices = [i for i in range(A4_TOUCH_MAP_SIZE) if touch_bitmap[i] > 0]
    if touched_indices:
        t_weights = [(1.0 / math.sqrt(1.0 + state.freq[i]), i) for i in touched_indices]
        t_weights.sort(reverse=True)
        K_T = min(p.K_T_rare, len(t_weights))
        T_rare = sum(w for w, _ in t_weights[:K_T]) / K_T
    else:
        T_rare = 0.0

    # --- Failure novelty ---
    delta_F = sum(1 for c in fail_contexts if c not in state.fail_freq)
    F_new = 1.0 - math.exp(-delta_F / p.tau_F_new) if p.tau_F_new > 0 else 0.0

    # --- Failure rarity ---
    if fail_contexts:
        f_weights = [(1.0 / math.sqrt(1.0 + state.fail_freq.get(c, 0)), c) for c in fail_contexts]
        f_weights.sort(reverse=True)
        K_F = min(p.K_F_rare, len(f_weights))
        F_rare = sum(w for w, _ in f_weights[:K_F]) / K_F
    else:
        F_rare = 0.0

    # --- Zero-local-fail indicator (gated per Pro_Report_7) ---
    Z = 1 if (outcome == "REJECTED" and proof_generated and d_fail == 0) else 0

    # --- Q: execution quality (revised: distinct + cascade split) ---
    Q_dist = math.exp(-d_fail / p.tau_d) if p.tau_d > 0 else 0.0
    if r_rep <= p.r_0:
        Q_rep = 1.0
    else:
        Q_rep = math.exp(-(r_rep - p.r_0) / p.tau_r) if p.tau_r > 0 else 0.0
    Q = Q_dist * Q_rep

    # --- Weighted average S ---
    w_sum = p.a_Tn + p.a_Tr + p.a_Fn + p.a_Fr + p.a_Z
    if w_sum > 0:
        S = (p.a_Tn * T_new + p.a_Tr * T_rare + p.a_Fn * F_new + p.a_Fr * F_rare + p.a_Z * Z) / w_sum
    else:
        S = 0.0

    # --- Final reward ---
    r = min(1.0, Q * S)

    # --- ACCEPTED override ---
    if outcome == "ACCEPTED":
        r = 1.0

    diag = {
        "T_new": T_new, "T_rare": T_rare, "F_new": F_new, "F_rare": F_rare, "Z": Z,
        "delta_T": delta_T, "delta_F": delta_F, "d_fail": d_fail, "n_fail": n_fail,
        "r_rep": r_rep, "Q_dist": Q_dist, "Q_rep": Q_rep, "Q": Q, "S": S,
        "r": r, "mode": "accepted" if outcome == "ACCEPTED" else "normal",
    }
    return r, diag


def update_state(
    touch_bitmap: Optional[bytes],
    failures: List[ConstraintFailure],
    exit_code: int,
    state: CoverageState,
) -> None:
    """
    Update CoverageState with this run's data. Call AFTER compute_reward.

    Only updates coverage frequencies (freq, fail_freq, seen) for VALID runs.
    Crash or missing-bitmap runs increment total_runs but do not affect
    frequency data (Pro_Report_7: prevents crashes from corrupting rarity).
    """
    state.total_runs += 1

    # Invalid run: don't update coverage data
    if touch_bitmap is None or _is_crash(exit_code):
        return

    # Merge bitmap (updates seen/global)
    merge_into_global(touch_bitmap, state.global_bitmap)

    # Increment touch frequency for all touched buckets
    for i in range(A4_TOUCH_MAP_SIZE):
        if touch_bitmap[i] > 0:
            state.freq[i] += 1

    # Increment failure frequency per-run-per-context (NOT per-instance)
    fail_contexts_seen = set()
    for f in failures:
        key = (f.constraint_loc(), f.major, f.minor)
        if key not in fail_contexts_seen:
            fail_contexts_seen.add(key)
            state.fail_freq[key] = state.fail_freq.get(key, 0) + 1

    # Diagnostic counters
    for f in failures:
        state.maj_seen[f.major] = state.maj_seen.get(f.major, 0) + 1
        key_mm = (f.major, f.minor)
        state.maj_min_seen[key_mm] = state.maj_min_seen.get(key_mm, 0) + 1
