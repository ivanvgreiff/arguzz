"""
Pilot Calibration (Phase II.1.5, revised in Phase II.2R)

Collects statistics from pilot mutation runs and computes calibrated parameters
for the coverage-guided bandit scheduler. The pilot runs at the start of each
campaign to adapt parameters to the specific guest program and inputs.

Revised per Pro_Report_6/7:
  - tau_d replaces tau_fail_count (calibrated from distinct failure contexts)
  - K_T_rare replaces K_rare (touch rarity K)
  - K_F_rare = 2 (HARD, not calibrated)
  - Rolling window W removed (no saturation switch)
  - Weights (a_Tn, a_Tr, a_Fn, a_Fr, a_Z) added with defaults
  - Cascade parameters (r_0, tau_r) added as HARD

See a4/docs/touch/Phase II/PHASE_II_2R_IMPLEMENTATION_PLAN.md
and a4/docs/touch/Phase II/PHASE_II_MASTER_IMPLEMENTATION_PLAN.md.
"""

import math
import os
import statistics
from dataclasses import dataclass
from typing import List, Optional

from a4.core.executor import MutationExecutionResult
from a4.core.touch_coverage import (
    count_new_bits,
    distinct_touched,
    A4_TOUCH_MAP_SIZE,
)


_CRASH_SIGNALS_NEGATIVE = (-11, -6, -8, -9, -10)
_CRASH_SIGNALS_SHELL = (139, 134, 136, 137, 138)


def _is_crash(exit_code: int) -> bool:
    return exit_code in _CRASH_SIGNALS_NEGATIVE or exit_code in _CRASH_SIGNALS_SHELL


@dataclass
class PilotRunStats:
    """Statistics from a single pilot mutation run."""
    delta_new: int
    abs_U: int
    n_fail: int
    d_fail: int
    is_crash: bool
    has_bitmap: bool


@dataclass
class CalibratedParams:
    """
    All parameters needed by the reward function and bandit, frozen after calibration.

    CALIBRATE ONCE (from pilot):
      tau_new       - touch novelty scaling
      tau_d         - local distinct-failure penalty scaling
      K_T_rare      - touch rarity top-K

    DERIVED (from budget):
      gamma         - discount factor for bandit

    HARD (not calibrated):
      tau_F_new     - failure novelty scaling (over extended contexts post-III.0)
      K_F_rare      - failure rarity top-K (over extended contexts post-III.0)
      r_0           - cascade repeat threshold
      tau_r         - cascade penalty slope
      c_explore     - UCB exploration coefficient
      a_Tn..a_U     - reward component weights
      tau_g         - global distinct-failure penalty scaling (default 2*tau_d,
                      env override A4_TAU_G); added in Phase III.0.

    Phase III.0 rename: a_Z -> a_U (semantic shift; old `Z` indicator now ill-defined
    after Hook 3 enabled global instrumentation). The legacy name `a_Z` is preserved
    as a property alias for back-compat with external scripts.
    """
    # Calibrated
    tau_new: float
    tau_d: float
    K_T_rare: int
    # Derived
    gamma: float
    # Hard
    tau_F_new: float = 2.0
    K_F_rare: int = 2
    r_0: int = 10
    tau_r: float = 25.0
    c_explore: float = 0.25
    # Weights
    a_Tn: float = 1.0
    a_Tr: float = 0.25
    a_Fn: float = 1.0
    a_Fr: float = 1.0
    a_U: float = 1.0      # Phase III.0: renamed from a_Z (alias kept below)
    # Global distinct-failure scale (Phase III.0). Defaults to 2*tau_d via __post_init__.
    tau_g: float = 0.0

    def __post_init__(self):
        if self.tau_g <= 0:
            override = os.environ.get("A4_TAU_G")
            self.tau_g = float(override) if override else 2.0 * self.tau_d

    @property
    def a_Z(self) -> float:
        """Back-compat alias for a_U (Phase III.0 rename)."""
        return self.a_U

    @a_Z.setter
    def a_Z(self, value: float) -> None:
        self.a_U = value


def compute_N_pilot(budget: int) -> int:
    """Number of pilot runs: 5% of budget, clamped to [30, 100]."""
    return max(30, min(100, budget // 20))


def collect_pilot_stat(
    exec_result: MutationExecutionResult,
    global_bitmap: bytearray,
) -> PilotRunStats:
    """
    Extract PilotRunStats from one mutation run's results.

    Does NOT merge into global_bitmap. The caller must merge explicitly
    after collecting the stat.
    """
    has_bitmap = exec_result.touch_bitmap is not None
    if has_bitmap:
        delta_new = count_new_bits(exec_result.touch_bitmap, global_bitmap)
        abs_U = distinct_touched(exec_result.touch_bitmap)
    else:
        delta_new = 0
        abs_U = 0

    fail_contexts = set()
    for f in exec_result.failures:
        fail_contexts.add((f.constraint_loc(), f.major, f.minor))

    return PilotRunStats(
        delta_new=delta_new,
        abs_U=abs_U,
        n_fail=len(exec_result.failures),
        d_fail=len(fail_contexts),
        is_crash=_is_crash(exec_result.exit_code),
        has_bitmap=has_bitmap,
    )


def _percentile(data: List[float], p: float) -> float:
    """Compute the p-th percentile (0-100) using linear interpolation."""
    if not data:
        raise ValueError("Cannot compute percentile of empty list")
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[f] * (c - k) + sorted_data[c] * (k - f)


def calibrate_from_pilot(
    pilot_stats: List[PilotRunStats],
    budget: int,
) -> CalibratedParams:
    """
    Compute all parameters from pilot statistics and campaign budget.

    Changes from v1 (Pro_Report_6/7):
      - tau_T clamp tightened to [8, 128]
      - tau_d calibrated from p75(d_fail) (replaces tau_fail_count)
      - W removed (no rolling window / saturation switch)
      - K_F_rare = 2 (HARD, not calibrated)
    """
    # tau_new: 75th percentile of nonzero delta_new, clamped [8, 128]
    nonzero_deltas = [s.delta_new for s in pilot_stats if s.delta_new > 0]
    if nonzero_deltas:
        tau_new = _percentile(nonzero_deltas, 75)
        tau_new = max(8.0, min(128.0, tau_new))
    else:
        tau_new = 64.0

    # tau_d: max(1, 75th percentile of d_fail among valid runs)
    d_fail_values = [s.d_fail for s in pilot_stats if not s.is_crash and s.has_bitmap]
    if d_fail_values:
        tau_d = max(1.0, _percentile(d_fail_values, 75))
    else:
        tau_d = 3.0

    # K_T_rare: 2% of median |U_t|, clamped [16, 64]
    abs_U_values = [s.abs_U for s in pilot_stats if s.has_bitmap]
    if abs_U_values:
        median_abs_U = statistics.median(abs_U_values)
        K_T_rare = int(math.floor(0.02 * median_abs_U))
        K_T_rare = max(16, min(64, K_T_rare))
    else:
        K_T_rare = 32

    # gamma: discount factor from budget via half-life
    H = max(50, min(300, budget // 5))
    gamma = 2.0 ** (-1.0 / H)

    return CalibratedParams(
        tau_new=tau_new,
        tau_d=tau_d,
        K_T_rare=K_T_rare,
        gamma=gamma,
    )
