"""
Constrained Thompson Sampling and kind-level bandit schedulers — cloud1 Phase 5.

Implements ProG_Report_2.md §7.C (constrained bandit with coverage floor) and
§7.D (Thompson sampling with Bernoulli success). Lives alongside legacy
`DiscountedUCBScheduler` in `bandit.py`; does not replace it.

Schedulers:
  - ConstrainedTSScheduler — (kind, semantic_zone) arms, floor + Beta TS
  - KindLevelUCBScheduler — kind-only UCB (IV.POS.7 Variants 2–3)
  - KindLevelTSScheduler — kind-only Beta TS (IV.POS.7 Variant 4)

Decisions D4, D9, D10, D28–D32 documented in `CLOUD1_DECISIONS_FOR_PRO_R2.md`
and `composer/PROPOSED_DECISIONS.md`.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

from a4.standalone.semantic_arm_universe import SemanticArmUniverse, ArmKey

_EPSILON = 1e-12


@dataclass(frozen=True)
class BanditDecision:
    """Selection metadata for `bandit_decisions` logging (Pro §12)."""

    kind: str
    zone: Optional[str]
    step: int
    arm_id: str
    mode: str                    # cold | singleton | floor | adaptive | ucb
    score: Optional[float] = None
    runnerup_arm: Optional[str] = None
    runnerup_score: Optional[float] = None
    exploration: bool = False


def arm_id(kind: str, zone: Optional[str] = None) -> str:
    """Stable string key for DB / logging (V5 legacy 2-pipe format)."""
    if zone is None:
        return kind
    return f"{kind}|{zone}"


def arm_id_for_decision(arm: ArmKey) -> str:
    """Format selected_arm for bandit_decisions (V5 vs full Hybrid shape)."""
    return str(arm)


class MutationOutcome(str, Enum):
    APPLIED = "applied"
    SKIPPED = "skipped"
    ERROR = "error"


# =============================================================================
# V5 coverage-floor schedules (IV.POS.8 D1.A)
# =============================================================================


class FloorSchedule:
    """Returns coverage_floor_fraction at a given scheduler state."""

    def current(self, *, total_mutations: int, local_discoveries: int) -> float:
        raise NotImplementedError


class ConstantFloor(FloorSchedule):
    """Fixed floor fraction (V5-static back-compat default)."""

    def __init__(self, value: float = 0.55) -> None:
        self.value = value

    def current(self, *, total_mutations: int, local_discoveries: int) -> float:
        return self.value


class ExponentialDecayFloor(FloorSchedule):
    """max(floor_min, initial × exp(-local_discoveries / K))."""

    def __init__(
        self,
        initial: float = 0.55,
        floor_min: float = 0.20,
        K: float = 50,
    ) -> None:
        self.initial = initial
        self.floor_min = floor_min
        self.K = K

    def current(self, *, total_mutations: int, local_discoveries: int) -> float:
        raw = self.initial * math.exp(-local_discoveries / self.K)
        return max(self.floor_min, raw)


class EpochStageFloor(FloorSchedule):
    """Piecewise-constant floor over total_mutations (mutation-count space)."""

    def __init__(self, stages: List[Tuple[int, float]]) -> None:
        if not stages:
            raise ValueError("EpochStageFloor requires at least one stage")
        self.stages = sorted(stages, key=lambda s: s[0])

    def current(self, *, total_mutations: int, local_discoveries: int) -> float:
        frac = self.stages[0][1]
        for lower, value in self.stages:
            if total_mutations >= lower:
                frac = value
            else:
                break
        return frac


# =============================================================================
# Constrained TS over (kind, semantic_zone)
# =============================================================================


class ConstrainedTSScheduler:
    """Constrained Thompson Sampling over SemanticArmUniverse arms.

    Defaults per D4, D9, D10:
      prior Beta(1,1), 55% epoch floor, 3 cold-start pulls/arm,
      5 forced singleton pulls, epoch_size=100.
    """

    def __init__(
        self,
        universe: SemanticArmUniverse,
        *,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        coverage_floor_fraction: float = 0.55,
        cold_start_pulls_per_arm: int = 3,
        forced_singleton_pulls: int = 5,
        epoch_size: int = 100,
        seed: Optional[int] = None,
        floor_schedule: Optional[FloorSchedule] = None,
        applied_accounting_mode: bool = False,
    ):
        self.universe = universe
        self.prior_alpha = prior_alpha
        self.prior_beta = prior_beta
        self.coverage_floor_fraction = coverage_floor_fraction
        self.cold_start_pulls_per_arm = cold_start_pulls_per_arm
        self.forced_singleton_pulls = forced_singleton_pulls
        self.epoch_size = epoch_size
        self.rng = random.Random(seed)
        self.applied_accounting_mode = applied_accounting_mode
        self.floor_schedule = (
            floor_schedule
            if floor_schedule is not None
            else ConstantFloor(coverage_floor_fraction)
        )

        self.arms: List[ArmKey] = universe.available_arms
        self._singleton_set = set(universe.singleton_arms())

        self.pulls: Dict[ArmKey, int] = {a: 0 for a in self.arms}
        self.successes: Dict[ArmKey, int] = {a: 0 for a in self.arms}
        self.epoch_pulls: Dict[ArmKey, int] = {a: 0 for a in self.arms}
        self._epoch_mutations: int = 0
        self._total_mutations: int = 0
        self._local_discoveries: int = 0
        self._cold_rr: int = 0

    def _alpha(self, a: ArmKey) -> float:
        return self.prior_alpha + self.successes[a]

    def _beta(self, a: ArmKey) -> float:
        return self.prior_beta + (self.pulls[a] - self.successes[a])

    def _floor_target(self) -> float:
        if not self.arms:
            return 0.0
        frac = self.floor_schedule.current(
            total_mutations=self._total_mutations,
            local_discoveries=self._local_discoveries,
        )
        return frac * self.epoch_size / len(self.arms)

    def update_local_coverage(self, n: int) -> None:
        """Set cumulative legacy constraint_loc discoveries (Pro local_coverage_seen)."""
        self._local_discoveries = n

    def _pick_round_robin(self, candidates: List[ArmKey]) -> ArmKey:
        if not candidates:
            raise ValueError("empty candidate list")
        idx = self._cold_rr % len(candidates)
        self._cold_rr += 1
        return candidates[idx]

    def _sample_thetas(self) -> Dict[ArmKey, float]:
        return {a: self.rng.betavariate(self._alpha(a), self._beta(a)) for a in self.arms}

    def select(self) -> BanditDecision:
        """Pick (kind, zone, step) with floor constraints then Beta TS."""
        if not self.arms:
            raise RuntimeError("ConstrainedTSScheduler: empty arm universe")

        chosen: ArmKey
        mode: str
        score: Optional[float] = None
        runnerup_arm: Optional[str] = None
        runnerup_score: Optional[float] = None
        exploration = False

        # 1. Cold-start floor (D28, D29 round-robin)
        cold = [a for a in self.arms if self.pulls[a] < self.cold_start_pulls_per_arm]
        if cold:
            chosen = self._pick_round_robin(sorted(cold))
            mode = "cold"
            exploration = True
        else:
            # 2. Singleton floor (D10)
            singleton_need = [
                a for a in self.arms
                if a in self._singleton_set
                and self.pulls[a] < self.forced_singleton_pulls
            ]
            if singleton_need:
                chosen = self._pick_round_robin(sorted(singleton_need))
                mode = "singleton"
                exploration = True
            else:
                # 3. Per-epoch coverage floor (D9, D30)
                target = self._floor_target()
                under = [
                    a for a in self.arms
                    if self.epoch_pulls[a] < target - _EPSILON
                ]
                if under:
                    chosen = min(under, key=lambda a: self.epoch_pulls[a])
                    mode = "floor"
                    exploration = True
                else:
                    # 4. Adaptive TS (D4, D-I)
                    thetas = self._sample_thetas()
                    sorted_arms = sorted(self.arms, key=lambda a: thetas[a], reverse=True)
                    chosen = sorted_arms[0]
                    score = thetas[chosen]
                    mode = "adaptive"
                    if len(sorted_arms) > 1:
                        runnerup_arm = arm_id_for_decision(sorted_arms[1])
                        runnerup_score = thetas[sorted_arms[1]]

        kind, zone = chosen.kind, chosen.zone
        steps = self.universe.steps_for_arm(chosen)
        if not steps:
            steps = self.universe.steps_in_arm(kind, zone)
        if not steps:
            raise RuntimeError(f"selected empty arm {chosen}")
        step = steps[0] if len(steps) == 1 else self.rng.choice(steps)

        return BanditDecision(
            kind=kind,
            zone=zone,
            step=step,
            arm_id=arm_id_for_decision(chosen),
            mode=mode,
            score=score,
            runnerup_arm=runnerup_arm,
            runnerup_score=runnerup_score,
            exploration=exploration,
        )

    def _advance_state(self, key: ArmKey, success: int) -> None:
        if key not in self.pulls:
            return
        self.pulls[key] += 1
        self.successes[key] += int(success)
        self.epoch_pulls[key] += 1
        self._epoch_mutations += 1
        self._total_mutations += 1
        if self._epoch_mutations >= self.epoch_size:
            for a in self.arms:
                self.epoch_pulls[a] = 0
            self._epoch_mutations = 0

    def update(self, kind_or_arm: Union[str, ArmKey], zone_or_success: Union[str, int], success: Optional[int] = None) -> None:
        """Bernoulli update (success ∈ {0, 1}) per D-I.

        Back-compat overload: ``update(kind, zone, success)``.
        Primary form: ``update(arm, success)`` when *success* is passed positionally
        as the second arg to a single ArmKey — use ``update_with_outcome`` for
        applied-accounting mode instead.
        """
        if isinstance(kind_or_arm, ArmKey):
            arm = kind_or_arm
            if success is None:
                if isinstance(zone_or_success, int):
                    success = zone_or_success
                else:
                    raise TypeError("update(arm, success) requires int success")
            self._advance_state(arm, success)
            return
        kind = kind_or_arm
        zone = zone_or_success
        if success is None:
            raise TypeError("update(kind, zone, success) requires success int")
        self._advance_state(ArmKey.v5(kind, zone), success)

    def update_with_outcome(
        self,
        arm: ArmKey,
        outcome: MutationOutcome,
        success: Optional[int] = None,
    ) -> None:
        """Update scheduler state respecting applied-mutation accounting."""
        if self.applied_accounting_mode and outcome != MutationOutcome.APPLIED:
            return
        if outcome == MutationOutcome.APPLIED:
            self._advance_state(arm, int(success or 0))
        elif not self.applied_accounting_mode:
            self._advance_state(arm, 0)

    def arm_state_rows(self) -> List[dict]:
        """Snapshot rows for `arm_state_snapshot` (Pro §12)."""
        rows = []
        for a in self.arms:
            p = self.pulls[a]
            s = self.successes[a]
            rows.append({
                "arm_id": arm_id_for_decision(a),
                "pulls": p,
                "posterior_alpha": self._alpha(a),
                "posterior_beta": self._beta(a),
                "mean_reward": (s / p) if p > 0 else None,
            })
        return rows

    @property
    def total_mutations(self) -> int:
        return self._total_mutations


# =============================================================================
# Kind-level UCB (Variants 2–3)
# =============================================================================


class KindLevelUCBScheduler:
    """UCB over mutation kinds only; step selection is external (ZonedStepSelector)."""

    def __init__(
        self,
        kinds: List[str],
        c_explore: float = 0.25,
        seed: Optional[int] = None,
    ):
        self.kinds = list(kinds)
        self.c = c_explore
        self.rng = random.Random(seed)
        self.t: int = 0
        self.pulls: Dict[str, int] = {k: 0 for k in self.kinds}
        self.reward_sum: Dict[str, float] = {k: 0.0 for k in self.kinds}

    def _ucb(self, kind: str) -> float:
        n = self.pulls[kind]
        if n == 0:
            return float("inf")
        mean = self.reward_sum[kind] / n
        return mean + self.c * math.sqrt(math.log(self.t + 1) / n)

    def select(self) -> BanditDecision:
        self.t += 1
        cold = [k for k in self.kinds if self.pulls[k] == 0]
        if cold:
            chosen = self.rng.choice(cold)
            return BanditDecision(
                kind=chosen, zone=None, step=-1,
                arm_id=arm_id(chosen), mode="cold", exploration=True,
            )
        scores = {k: self._ucb(k) for k in self.kinds}
        best = max(scores.values())
        tied = [k for k in self.kinds if abs(scores[k] - best) < 1e-12]
        chosen = self.rng.choice(tied)
        sorted_k = sorted(self.kinds, key=lambda k: scores[k], reverse=True)
        runnerup = sorted_k[1] if len(sorted_k) > 1 else None
        return BanditDecision(
            kind=chosen, zone=None, step=-1,
            arm_id=arm_id(chosen), mode="ucb",
            score=scores[chosen],
            runnerup_arm=arm_id(runnerup) if runnerup else None,
            runnerup_score=scores[runnerup] if runnerup else None,
            exploration=False,
        )

    def update(self, kind: str, reward: float) -> None:
        if kind not in self.pulls:
            return
        self.pulls[kind] += 1
        self.reward_sum[kind] += reward

    def arm_state_rows(self) -> List[dict]:
        rows = []
        for k in self.kinds:
            p = self.pulls[k]
            rows.append({
                "arm_id": arm_id(k),
                "pulls": p,
                "mean_reward": (self.reward_sum[k] / p) if p > 0 else None,
            })
        return rows

    @property
    def total_mutations(self) -> int:
        return self.t


# =============================================================================
# Kind-level TS (Variant 4)
# =============================================================================


class KindLevelTSScheduler:
    """Beta Thompson sampling over mutation kinds only."""

    def __init__(
        self,
        kinds: List[str],
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        seed: Optional[int] = None,
    ):
        self.kinds = list(kinds)
        self.prior_alpha = prior_alpha
        self.prior_beta = prior_beta
        self.rng = random.Random(seed)
        self.pulls: Dict[str, int] = {k: 0 for k in self.kinds}
        self.successes: Dict[str, int] = {k: 0 for k in self.kinds}
        self._total: int = 0

    def _alpha(self, k: str) -> float:
        return self.prior_alpha + self.successes[k]

    def _beta(self, k: str) -> float:
        return self.prior_beta + (self.pulls[k] - self.successes[k])

    def select(self) -> BanditDecision:
        thetas = {k: self.rng.betavariate(self._alpha(k), self._beta(k)) for k in self.kinds}
        sorted_k = sorted(self.kinds, key=lambda k: thetas[k], reverse=True)
        chosen = sorted_k[0]
        runnerup = sorted_k[1] if len(sorted_k) > 1 else None
        return BanditDecision(
            kind=chosen, zone=None, step=-1,
            arm_id=arm_id(chosen), mode="adaptive",
            score=thetas[chosen],
            runnerup_arm=arm_id(runnerup) if runnerup else None,
            runnerup_score=thetas[runnerup] if runnerup else None,
            exploration=False,
        )

    def update(self, kind: str, success: int) -> None:
        if kind not in self.pulls:
            return
        self.pulls[kind] += 1
        self.successes[kind] += int(success)
        self._total += 1

    def arm_state_rows(self) -> List[dict]:
        rows = []
        for k in self.kinds:
            p = self.pulls[k]
            s = self.successes[k]
            rows.append({
                "arm_id": arm_id(k),
                "pulls": p,
                "posterior_alpha": self._alpha(k),
                "posterior_beta": self._beta(k),
                "mean_reward": (s / p) if p > 0 else None,
            })
        return rows

    @property
    def total_mutations(self) -> int:
        return self._total


__all__ = [
    "BanditDecision",
    "MutationOutcome",
    "arm_id",
    "arm_id_for_decision",
    "ConstantFloor",
    "ConstrainedTSScheduler",
    "EpochStageFloor",
    "ExponentialDecayFloor",
    "FloorSchedule",
    "KindLevelUCBScheduler",
    "KindLevelTSScheduler",
]
