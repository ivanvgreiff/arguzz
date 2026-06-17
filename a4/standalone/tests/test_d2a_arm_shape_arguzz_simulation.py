#!/usr/bin/env python3
"""D2.A Batch 1 — synthetic scheduler test with mixed A4 + Arguzz arms."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import pytest

from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    MutationOutcome,
    arm_id_for_decision,
)
from a4.standalone.semantic_arm_universe import (
    ARGUZZ_EXEC_FAULT,
    A4_TRACE_CELL,
    ArmKey,
    SemanticArmUniverse,
)


def _mixed_universe() -> SemanticArmUniverse:
    """Hand-built 10-arm universe: 5 V5-shape + 5 Arguzz-shape."""
    a4_arms = [
        ArmKey.v5("INSTR_TYPE_MOD", "core_arithmetic"),
        ArmKey.v5("COMP_OUT_MOD", "core_mul"),
        ArmKey.v5("LOAD_VAL_MOD", "core_memory_load"),
        ArmKey.v5("INSTR_WORD_MOD_SUR", "step0"),
        ArmKey.v5("STORE_OUT_MOD", "post_ecall"),
    ]
    arguzz_arms = [
        ArmKey(ARGUZZ_EXEC_FAULT, "INSTR_WORD_MOD", "core_arithmetic", "arithmetic", "pre_exec"),
        ArmKey(ARGUZZ_EXEC_FAULT, "PRE_EXEC_MEM_MOD", "core_memory_load", "memory_load", "pre_exec"),
        ArmKey(ARGUZZ_EXEC_FAULT, "BR_NEG_COND", "core_branch", "branch", "pre_exec"),
        ArmKey(ARGUZZ_EXEC_FAULT, "POST_EXEC_REG_MOD", "core_memory_store", "memory_store", "post_exec"),
        ArmKey(ARGUZZ_EXEC_FAULT, "PRE_EXEC_PC_MOD", "kernel_other", "system", "pre_exec"),
    ]
    arms: Dict[ArmKey, List[int]] = {a: [0] for a in a4_arms + arguzz_arms}
    return SemanticArmUniverse(
        mutation_kinds=["INSTR_TYPE_MOD"],
        arms=arms,
        zone_step_map={},
        valid_steps_by_kind={"INSTR_TYPE_MOD": [0]},
        total_steps=1,
    )


@dataclass
class _OutcomeStream:
    """Deterministic mock: A4 always APPLIED; Arguzz 30% SKIPPED."""

    rng_state: int = 0
    _skip_mod: Dict[ArmKey, int] = field(default_factory=dict)

    def outcome_for(self, arm: ArmKey) -> MutationOutcome:
        if arm.surface == A4_TRACE_CELL:
            return MutationOutcome.APPLIED
        n = self._skip_mod.get(arm, 0)
        self._skip_mod[arm] = n + 1
        return MutationOutcome.SKIPPED if n % 10 < 3 else MutationOutcome.APPLIED


class TestArguzzShapeSchedulerSimulation:
    def test_mixed_surface_applied_accounting_and_arm_id_formats(self):
        uni = _mixed_universe()
        sched = ConstrainedTSScheduler(
            uni,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=1,
            epoch_size=50,
            seed=7,
            applied_accounting_mode=True,
        )
        stream = _OutcomeStream()
        n_rounds = 200
        selection_counts: Dict[ArmKey, int] = {a: 0 for a in sched.arms}

        for _ in range(n_rounds):
            d = sched.select()
            arm = next(a for a in sched.arms if a.kind == d.kind and a.zone == d.zone)
            selection_counts[arm] += 1
            outcome = stream.outcome_for(arm)
            success = 1 if outcome == MutationOutcome.APPLIED else 0
            sched.update_with_outcome(arm, outcome, success=success)

        for arm in sched.arms:
            assert sched.pulls[arm] >= sched.cold_start_pulls_per_arm

        for arm in sched.arms:
            if arm.surface == A4_TRACE_CELL:
                assert arm_id_for_decision(arm).count("|") == 1
                assert sched.pulls[arm] == selection_counts[arm]
            else:
                assert arm_id_for_decision(arm).count("|") == 4
                assert sched.pulls[arm] <= selection_counts[arm]
                assert sched.pulls[arm] > 0

        assert sum(sched.pulls[a] for a in sched.arms if a.surface == ARGUZZ_EXEC_FAULT) > 0
        assert sum(selection_counts[a] for a in sched.arms if a.surface == ARGUZZ_EXEC_FAULT) > sum(
            sched.pulls[a] for a in sched.arms if a.surface == ARGUZZ_EXEC_FAULT
        )
