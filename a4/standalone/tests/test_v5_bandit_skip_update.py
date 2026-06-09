"""Phase 7 Bug B — bandit update() on mutation skip path."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from a4.core.trace_parser import A4CycleInfo
from a4.core.inspection_data import InspectionData
from a4.standalone.fuzzer import A4Fuzzer, CampaignStats
from a4.standalone.semantic_arm_universe import SemanticArmUniverse
from a4.standalone.bandit_ts import (
    BanditDecision,
    ConstrainedTSScheduler,
    KindLevelTSScheduler,
    arm_id,
)
from a4.standalone.step_selector import ZonedStepSelector, SemanticZoneStepSelector


def _cycles(n: int = 5):
    return [
        A4CycleInfo(cycle_idx=i, step=i, pc=0, txn_idx=0, major=0, minor=0)
        for i in range(n)
    ]


def _cts_fuzzer(data: InspectionData) -> A4Fuzzer:
    fz = A4Fuzzer(
        host_binary="/bin/true",
        host_args=[],
        db_path=":memory:",
        selector_strategy="cTS_semantic_v2",
        seed=42,
    )
    fz.data = data
    kinds = fz._active_mutation_kinds()
    fz.semantic_arm_universe = SemanticArmUniverse.build(data, kinds)
    fz.v2_scheduler = ConstrainedTSScheduler(fz.semantic_arm_universe, seed=42)
    fz.semantic_zone_selector = SemanticZoneStepSelector(
        fz.semantic_arm_universe, seed=43,
    )
    return fz


class TestSkipPathUpdatesBandit:
    def test_cts_skip_increments_pulls(self):
        data = InspectionData(cycles=_cycles(), all_txns=[], reg_txns=[])
        fz = _cts_fuzzer(data)
        stats = CampaignStats()
        arm = fz.v2_scheduler.arms[0]
        kind, zone = arm
        step = fz.semantic_arm_universe.steps_in_arm(kind, zone)[0]
        decision = BanditDecision(
            kind=kind,
            zone=zone,
            step=step,
            arm_id=arm_id(kind, zone),
            mode="cold",
        )

        with patch.object(fz.v2_scheduler, "select", return_value=decision):
            with patch.object(fz, "_create_mutation", return_value=(None, 0, 0)):
                with patch.object(
                    fz.semantic_zone_selector, "pick_step_in_zone", return_value=None,
                ):
                    for i in range(4):
                        fz._run_v2_bandit_mutation(i, 4, stats)

        assert stats.skipped_mutations == 4
        assert fz.v2_scheduler.pulls[arm] == 4
        cold = [a for a in fz.v2_scheduler.arms if fz.v2_scheduler.pulls[a] < 3]
        assert arm not in cold

    def test_kind_ts_skip_increments_pulls(self):
        data = InspectionData(cycles=_cycles(), all_txns=[], reg_txns=[])
        fz = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="kindTS_zoned_v2",
            seed=1,
        )
        fz.data = data
        kinds = ["INSTR_TYPE_MOD"]
        fz.v2_scheduler = KindLevelTSScheduler(kinds, seed=1)
        fz.selector = ZonedStepSelector(seed=2)

        stats = CampaignStats()
        with patch.object(fz, "_create_mutation", return_value=(None, 0, 0)):
            with patch.object(fz.selector, "select_step", return_value=0):
                for i in range(3):
                    fz._run_v2_bandit_mutation(i, 3, stats)

        assert stats.skipped_mutations == 3
        assert fz.v2_scheduler.pulls["INSTR_TYPE_MOD"] == 3
