"""
Coverage State and Reward Function (Phase II.2, revised in Phase II.2R, then Phase III.0)

Holds all global coverage state for a campaign and provides the reward function
that evaluates each mutation run. The reward drives the bandit scheduler.

Revised per Pro_Report_6/7:
  - 5 co-primary reward components: T_new, T_rare, F_new, F_rare, Z
  - Revised Q: Q_dist (distinct failures) * Q_rep (cascade penalty)
  - No saturation switch / rolling window
  - Baseline seeding for touch frequencies
  - Valid-run gating: crash/missing-bitmap runs don't update coverage state

Phase III.0 (precloud, ProG_Report_1):
  - F_new and F_rare now operate over the EXTENDED context set
        F_ext = F_loc U F_glob
    where F_glob is built from Hook 3 family residues / details (see
    derive_global_contexts below).
  - Z renamed to U with strictly stricter semantics: U = 1 only if no local
    AND no global failures, AND outcome is REJECTED with proof generated.
  - New Q_glob factor: Q = Q_loc * Q_rep * Q_glob.
    Q_loc replaces Q_dist (rename only).
  - state.fail_freq is now keyed off extended contexts (per-run-per-context
    increment). Local keys: (constraint_loc_str, major, minor).
    Global keys:           ("GLOBAL", family_name, decimal_str(addr_or_idx)).
    Collision is structurally impossible (local first element is always a
    file-path-with-line string).

Update order contract:
  1. compute_reward (reads state BEFORE this run's contribution)
  2. update_state (writes this run's contribution for next run)

See a4/docs/precloud/PHASE_III_0_IMPLEMENTATION_PLAN.md and
    a4/docs/touch/Phase II/PHASE_II_MASTER_IMPLEMENTATION_PLAN.md §2.
"""

import math
from typing import Dict, List, Optional, Set, Tuple

from a4.core.constraint_parser import ConstraintFailure
from a4.core.touch_coverage import (
    A4_TOUCH_MAP_SIZE,
    count_new_bits,
    merge_into_global,
    make_global_bitmap,
)
from a4.standalone.pilot_calibration import CalibratedParams


GlobalContext = Tuple[str, str, str]
"""Canonical global failure-context key: ("GLOBAL", family_name, decimal_str)."""


# Hook 3 caps (verified against ffi.cpp:582-630):
#   memory:  10 broken_addrs
#   u8/u16/cycle: 20 broken_indices each
# Total upper bound per run: 10 + 3*20 = 70. We assert at 4*30 = 120 as
# a generous upper bound that catches any future cap drift without false alarms.
_GLOBAL_CONTEXT_SAFETY_CAP = 120


def derive_global_contexts(
    family_residues: Optional[List[dict]],
    family_details: Optional[List[dict]],
) -> Set[GlobalContext]:
    """Build the canonical set F_glob = {("GLOBAL", family, addr-or-idx-str), ...}
    from Hook 3 output dicts.

    Inputs (from a4.core.touch_coverage parsers):
      family_residues: list of dicts, each {"family": str, "nonzero": bool, ...}.
        Only families with nonzero=True contribute.
      family_details:  list of dicts, each either
          {"family": "memory", "broken_addrs": [int, ...], ...}
        or
          {"family": "u8"|"u16"|"cycle", "broken_indices": [int, ...], ...}

    Returns: a set of 3-tuples ("GLOBAL", family_name, str(addr_or_idx)).
             Decimal stringification is consistent with the C++ "%u" printf
             format used by ffi.cpp, so the same address never appears under
             two different keys.
    """
    if not family_residues:
        return set()

    nonzero_families = {fr["family"] for fr in family_residues if fr.get("nonzero")}
    if not nonzero_families or not family_details:
        return set()

    ctx: Set[GlobalContext] = set()
    for fd in family_details:
        family = fd.get("family")
        if not family or family not in nonzero_families:
            continue
        if family == "memory":
            for a in fd.get("broken_addrs", []) or []:
                ctx.add(("GLOBAL", "memory", str(a)))
        else:
            for i in fd.get("broken_indices", []) or []:
                ctx.add(("GLOBAL", family, str(i)))

    if len(ctx) > _GLOBAL_CONTEXT_SAFETY_CAP:
        # Defensive truncation; should not happen given Hook 3 caps.
        # We keep an arbitrary deterministic subset to avoid runtime explosion.
        ctx = set(sorted(ctx)[:_GLOBAL_CONTEXT_SAFETY_CAP])
    return ctx


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
        # Phase III.0: keys are heterogeneous 3-tuples.
        # - Local: (constraint_loc_str, major: int, minor: int)
        # - Global: ("GLOBAL", family_name: str, decimal_str: str)
        # Collision is structurally impossible because constraint_loc_str
        # always contains a file path and parens (e.g. "MemoryWrite(...zir:99)").
        self.fail_freq: Dict[Tuple, int] = {}
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
    global_contexts: Optional[Set[GlobalContext]] = None,
) -> Tuple[float, dict]:
    """
    Compute the reward for a single mutation run. Does NOT modify state.

    Phase III.0:
      - global_contexts (optional) is the F_glob set built from Hook 3 by
        derive_global_contexts(). When omitted (legacy callers), the function
        behaves exactly like the pre-III.0 reward (provided a_Z == a_U), which
        the alias preserves.
      - F_new and F_rare now operate over F_ext = F_loc U F_glob.
      - Q gains a third factor Q_glob; the diag dict renames Z->U,
        d_fail->d_loc, Q_dist->Q_loc, and adds d_glob, d_ext, Q_glob.

    Args:
        touch_bitmap: 65536-byte touch bitmap (or None if crash/missing).
        failures: List of ConstraintFailure from this run.
        exit_code: Host process exit code.
        outcome: "REJECTED", "CRASH", "ACCEPTED", "NO_EFFECT".
        proof_generated: Whether the host generated a proof before failing.
        state: Current CoverageState (read only).
        global_contexts: Set of canonical F_glob keys for this run.

    Returns:
        (reward, diagnostics) where reward is in [0, 1].
    """
    p = state.params
    g_ctx: Set[GlobalContext] = global_contexts or set()
    d_glob = len(g_ctx)

    # --- Crash / missing bitmap: reward = 0, don't compute anything ---
    if _is_crash(exit_code) or touch_bitmap is None:
        return 0.0, {
            "T_new": 0.0, "T_rare": 0.0, "F_new": 0.0, "F_rare": 0.0,
            "U": 0,
            "delta_T": 0, "delta_F": 0,
            "d_loc": 0, "d_glob": d_glob, "d_ext": d_glob,
            "n_fail": len(failures), "r_rep": 0,
            "Q_loc": 0.0, "Q_rep": 1.0, "Q_glob": 1.0, "Q": 0.0,
            "S": 0.0, "r": 0.0, "mode": "crash",
        }

    # --- Per-run failure analysis (local) ---
    fail_contexts = set()
    for f in failures:
        fail_contexts.add((f.constraint_loc(), f.major, f.minor))
    n_fail = len(failures)
    d_loc = len(fail_contexts)
    # Cascade repeat-mass uses local instances ONLY: global "instances" are
    # already deduped to addresses by Hook 3; feeding them into r_rep would
    # double-clip the cascade penalty.
    r_rep = max(0, n_fail - d_loc)

    # --- Extended context set for novelty / rarity ---
    ext_contexts = fail_contexts | g_ctx
    d_ext = len(ext_contexts)

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

    # --- Failure novelty (over EXTENDED contexts) ---
    delta_F = sum(1 for c in ext_contexts if c not in state.fail_freq)
    F_new = 1.0 - math.exp(-delta_F / p.tau_F_new) if p.tau_F_new > 0 else 0.0

    # --- Failure rarity (over EXTENDED contexts) ---
    if ext_contexts:
        f_weights = [(1.0 / math.sqrt(1.0 + state.fail_freq.get(c, 0)), c) for c in ext_contexts]
        f_weights.sort(reverse=True)
        K_F = min(p.K_F_rare, len(f_weights))
        F_rare = sum(w for w, _ in f_weights[:K_F]) / K_F
    else:
        F_rare = 0.0

    # --- Unknown-rejection indicator (Phase III.0: stricter than legacy Z) ---
    # U = 1 only if rejected AND proof generated AND no local AND no global failures.
    U = 1 if (
        outcome == "REJECTED"
        and proof_generated
        and d_loc == 0
        and d_glob == 0
    ) else 0

    # --- Q: three-factor quality multiplier ---
    Q_loc = math.exp(-d_loc / p.tau_d) if p.tau_d > 0 else 0.0
    if r_rep <= p.r_0:
        Q_rep = 1.0
    else:
        Q_rep = math.exp(-(r_rep - p.r_0) / p.tau_r) if p.tau_r > 0 else 0.0
    Q_glob = math.exp(-d_glob / p.tau_g) if p.tau_g > 0 else 1.0
    Q = Q_loc * Q_rep * Q_glob

    # --- Weighted average S ---
    w_sum = p.a_Tn + p.a_Tr + p.a_Fn + p.a_Fr + p.a_U
    if w_sum > 0:
        S = (
            p.a_Tn * T_new
            + p.a_Tr * T_rare
            + p.a_Fn * F_new
            + p.a_Fr * F_rare
            + p.a_U * U
        ) / w_sum
    else:
        S = 0.0

    # --- Final reward ---
    r = min(1.0, Q * S)

    # --- ACCEPTED override ---
    if outcome == "ACCEPTED":
        r = 1.0

    diag = {
        "T_new": T_new, "T_rare": T_rare, "F_new": F_new, "F_rare": F_rare,
        "U": U,
        "delta_T": delta_T, "delta_F": delta_F,
        "d_loc": d_loc, "d_glob": d_glob, "d_ext": d_ext,
        "n_fail": n_fail, "r_rep": r_rep,
        "Q_loc": Q_loc, "Q_rep": Q_rep, "Q_glob": Q_glob, "Q": Q,
        "S": S, "r": r,
        "mode": "accepted" if outcome == "ACCEPTED" else "normal",
    }
    return r, diag


def update_state(
    touch_bitmap: Optional[bytes],
    failures: List[ConstraintFailure],
    exit_code: int,
    state: CoverageState,
    global_contexts: Optional[Set[GlobalContext]] = None,
) -> None:
    """
    Update CoverageState with this run's data. Call AFTER compute_reward.

    Phase III.0: also increments fail_freq for each global context (once per run
    per context, matching the local semantics). Local and global keys live in
    the same dict; collision is structurally impossible (see CoverageState
    docstring).

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

    # Increment failure frequency per-run-per-context (NOT per-instance) - locals
    fail_contexts_seen = set()
    for f in failures:
        key = (f.constraint_loc(), f.major, f.minor)
        if key not in fail_contexts_seen:
            fail_contexts_seen.add(key)
            state.fail_freq[key] = state.fail_freq.get(key, 0) + 1

    # Phase III.0: globals are already a set => once-per-run-per-context for free
    if global_contexts:
        for key in global_contexts:
            state.fail_freq[key] = state.fail_freq.get(key, 0) + 1

    # Diagnostic counters
    for f in failures:
        state.maj_seen[f.major] = state.maj_seen.get(f.major, 0) + 1
        key_mm = (f.major, f.minor)
        state.maj_min_seen[key_mm] = state.maj_min_seen.get(key_mm, 0) + 1
