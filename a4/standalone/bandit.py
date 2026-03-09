"""
Discounted-UCB Bandit Scheduler (Phase II.3)

Two-level scheduler for coverage-guided fuzzing:
  Level 1: Discounted-UCB over arms = (mutation_kind, step_bucket)
  Level 2: Nested Discounted-UCB over steps within the chosen bucket

The discount factor γ makes the bandit forget old rewards, adapting to
the non-stationary reward landscape where coverage novelty decays over time.

Specification sources:
  Pro_Report_4 §7-8 (bandit model + nested step selection)
  Pro_Report_5 §11 (parameter derivation)
  Pro_Report_7 §H-I (explicit parameter decisions)

Update protocol (called by the campaign loop):
  1. (kind, step) = scheduler.select()
  2. execute mutation
  3. reward = compute_reward(...)
  4. scheduler.update(kind, step, reward)
  5. update_state(...)
"""

import math
import random
from typing import Dict, List, Optional, Tuple

from a4.standalone.arm_universe import ArmUniverse
from a4.standalone.pilot_calibration import CalibratedParams

_EPSILON = 1e-6


class DiscountedUCBScheduler:
    """
    Two-level Discounted-UCB bandit for mutation scheduling.

    Level 1 (arm selection):
      Arms are (mutation_kind, step_bucket) pairs from ArmUniverse.
      Each arm tracks discounted count N, reward sum S, last-update time t,
      and raw pull count m (for cold-start, never decayed).
      Selection: cold-start (m==0) then UCB index maximization.

    Level 2 (step selection within chosen arm):
      Same Discounted-UCB structure over individual steps in the bucket.
      N_tot for the exploration bonus is scoped to the bucket, not global.

    Fixed per Pro_Report_9: forced exploration now uses raw pull counts (m)
    instead of decayed N, preventing the perpetual-exploration trap where
    UCB was dead code.
    """

    def __init__(
        self,
        universe: ArmUniverse,
        params: CalibratedParams,
        seed: Optional[int] = None,
    ):
        self.universe = universe
        self.gamma = params.gamma
        self.c = params.c_explore
        self.rng = random.Random(seed)

        self.t: int = 0

        self.arm_N: Dict[Tuple[str, int], float] = {}
        self.arm_S: Dict[Tuple[str, int], float] = {}
        self.arm_t: Dict[Tuple[str, int], int] = {}
        self.arm_m: Dict[Tuple[str, int], int] = {}
        for arm in universe.available_arms:
            self.arm_N[arm] = 0.0
            self.arm_S[arm] = 0.0
            self.arm_t[arm] = 0
            self.arm_m[arm] = 0

        self.step_N: Dict[Tuple[str, int], float] = {}
        self.step_S: Dict[Tuple[str, int], float] = {}
        self.step_t: Dict[Tuple[str, int], int] = {}
        self.step_m: Dict[Tuple[str, int], int] = {}
        for arm in universe.available_arms:
            kind, bucket = arm
            for s in universe.steps_in_arm(kind, bucket):
                key = (kind, s)
                self.step_N[key] = 0.0
                self.step_S[key] = 0.0
                self.step_t[key] = 0
                self.step_m[key] = 0

        self.stats_coldstart_arm: int = 0
        self.stats_ucb_arm: int = 0
        self.stats_coldstart_step: int = 0
        self.stats_ucb_step: int = 0

    # ------------------------------------------------------------------
    # Lazy decay helpers
    # ------------------------------------------------------------------

    def _decay_arm(self, arm: Tuple[str, int]) -> None:
        dt = self.t - self.arm_t[arm]
        if dt > 0:
            decay = self.gamma ** dt
            self.arm_N[arm] *= decay
            self.arm_S[arm] *= decay
            self.arm_t[arm] = self.t

    def _decay_step(self, key: Tuple[str, int]) -> None:
        dt = self.t - self.step_t[key]
        if dt > 0:
            decay = self.gamma ** dt
            self.step_N[key] *= decay
            self.step_S[key] *= decay
            self.step_t[key] = self.t

    # ------------------------------------------------------------------
    # UCB helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ucb_index(mean: float, c: float, n_tot: float, n_a: float) -> float:
        return mean + c * math.sqrt(math.log(1.0 + n_tot) / max(n_a, _EPSILON))

    def _pick_max_random_tie(self, items: list, key_fn) -> object:
        """Pick the item with the highest key_fn value, breaking ties randomly."""
        if not items:
            raise ValueError("Cannot pick from empty list")
        best_val = max(key_fn(x) for x in items)
        tied = [x for x in items if abs(key_fn(x) - best_val) < 1e-12]
        return self.rng.choice(tied)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def select(self) -> Tuple[str, int]:
        """
        Select (mutation_kind, step) using two-level Discounted-UCB.

        Returns:
            (kind, step) tuple ready for mutation execution.
        """
        self.t += 1
        arms = self.universe.available_arms

        # --- Arm-level decay ---
        for arm in arms:
            self._decay_arm(arm)

        # --- Arm-level cold-start (raw pull count, never decayed) ---
        cold_start = [a for a in arms if self.arm_m[a] == 0]
        if cold_start:
            chosen_arm = self.rng.choice(cold_start)
            self.stats_coldstart_arm += 1
        else:
            # --- Arm-level UCB selection ---
            n_tot = sum(self.arm_N[a] for a in arms)

            def arm_ucb(a):
                mu = self.arm_S[a] / max(self.arm_N[a], _EPSILON)
                return self._ucb_index(mu, self.c, n_tot, self.arm_N[a])

            chosen_arm = self._pick_max_random_tie(arms, arm_ucb)
            self.stats_ucb_arm += 1

        kind, bucket = chosen_arm

        # --- Step-level selection ---
        steps = self.universe.steps_in_arm(kind, bucket)

        for s in steps:
            self._decay_step((kind, s))

        cold_start_steps = [s for s in steps if self.step_m[(kind, s)] == 0]
        if cold_start_steps:
            chosen_step = self.rng.choice(cold_start_steps)
            self.stats_coldstart_step += 1
        else:
            n_tot_step = sum(self.step_N[(kind, s)] for s in steps)

            def step_ucb(s):
                key = (kind, s)
                mu = self.step_S[key] / max(self.step_N[key], _EPSILON)
                return self._ucb_index(mu, self.c, n_tot_step, self.step_N[key])

            chosen_step = self._pick_max_random_tie(steps, step_ucb)
            self.stats_ucb_step += 1

        return kind, chosen_step

    def update(self, kind: str, step: int, reward: float) -> None:
        """
        Update bandit statistics with the observed reward.

        Must be called AFTER select() and compute_reward(), at the same
        iteration t (do not increment t here).

        Args:
            kind: The mutation kind that was executed.
            step: The step that was mutated.
            reward: The reward from compute_reward (in [0, 1]).
        """
        bucket = self.universe.bucket_for_step(step)
        arm = (kind, bucket)

        if arm in self.arm_N:
            self.arm_N[arm] += 1.0
            self.arm_S[arm] += reward
            self.arm_t[arm] = self.t
            self.arm_m[arm] += 1

        step_key = (kind, step)
        if step_key in self.step_N:
            self.step_N[step_key] += 1.0
            self.step_S[step_key] += reward
            self.step_t[step_key] = self.t
            self.step_m[step_key] += 1

    def get_arm_stats(self, arm: Tuple[str, int]) -> Tuple[float, float, float]:
        """Return (N, mean_reward, ucb_index) for an arm at current t."""
        self._decay_arm(arm)
        n = self.arm_N[arm]
        mu = self.arm_S[arm] / max(n, _EPSILON)
        n_tot = sum(self.arm_N[a] for a in self.universe.available_arms)
        ucb = self._ucb_index(mu, self.c, n_tot, n)
        return n, mu, ucb

    def summary(self) -> str:
        """Human-readable summary of bandit state."""
        lines = [
            f"DiscountedUCBScheduler (t={self.t}, \u03b3={self.gamma:.4f}, c={self.c})",
            f"  Arms: {self.universe.num_arms}",
        ]

        total_arm_sel = self.stats_coldstart_arm + self.stats_ucb_arm
        if total_arm_sel > 0:
            lines.append(f"  Arm selections: {self.stats_coldstart_arm} coldstart "
                         f"({self.stats_coldstart_arm/total_arm_sel*100:.0f}%) + "
                         f"{self.stats_ucb_arm} UCB ({self.stats_ucb_arm/total_arm_sel*100:.0f}%)")
        total_step_sel = self.stats_coldstart_step + self.stats_ucb_step
        if total_step_sel > 0:
            lines.append(f"  Step selections: {self.stats_coldstart_step} coldstart + "
                         f"{self.stats_ucb_step} UCB")

        for arm in self.universe.available_arms:
            self._decay_arm(arm)

        active = [(a, self.arm_N[a]) for a in self.universe.available_arms if self.arm_N[a] > 0.5]
        lines.append(f"  Active arms (N > 0.5): {len(active)}")

        arm_stats = []
        for arm in self.universe.available_arms:
            n = self.arm_N[arm]
            mu = self.arm_S[arm] / max(n, _EPSILON) if n > _EPSILON else 0.0
            arm_stats.append((arm, n, mu))

        arm_stats.sort(key=lambda x: -x[2])

        lines.append("\n  Top 10 arms by mean reward:")
        for arm, n, mu in arm_stats[:10]:
            lines.append(f"    {arm[0]:25s} bucket={arm[1]:3d}  N={n:6.2f}  μ={mu:.4f}")

        lines.append("\n  Bottom 10 arms by mean reward:")
        for arm, n, mu in arm_stats[-10:]:
            lines.append(f"    {arm[0]:25s} bucket={arm[1]:3d}  N={n:6.2f}  μ={mu:.4f}")

        return "\n".join(lines)
