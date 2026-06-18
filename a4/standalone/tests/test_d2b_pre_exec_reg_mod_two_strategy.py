#!/usr/bin/env python3
"""D2.B Batch 1 — PRE_EXEC_REG_MOD two-strategy retrofix (task 1.5f)."""

from __future__ import annotations

import random

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.semantic_arm_universe import _step_has_real_target
from a4.standalone.tests import test_d2a_back_compat_golden_trace as golden_trace_mod

_USER_REGS = 1073725472


def _cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0x1000, txn_idx=0, major=major, minor=0
    )


def _reg_txn(step: int, *, is_write: bool) -> A4AllTxn:
    return A4AllTxn(
        txn_idx=step * 10,
        step=step,
        txn_type="reg",
        addr=_USER_REGS + 5,
        cycle=1 if is_write else 0,
        word=100,
        prev_cycle=0,
        prev_word=100 if not is_write else 0,
    )


def _data() -> InspectionData:
    cycles = [_cycle(1), _cycle(2)]
    txns = [_reg_txn(1, is_write=False), _reg_txn(2, is_write=True)]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


class TestPreExecRegModTwoStrategy:
    def test_fuzzer_rng_picks_both_strategies(self):
        data = _data()
        seen = set()
        for seed in range(200):
            fuzzer = A4Fuzzer(
                host_binary="/bin/true",
                host_args=[],
                db_path=":memory:",
                selector_strategy="zoned",
                seed=seed,
            )
            fuzzer.data = data
            config = None
            for step in (1, 2):
                config, _, _ = fuzzer._create_mutation("PRE_EXEC_REG_MOD", step)
                if config is not None:
                    break
            if config is not None:
                seen.add(config["strategy"])
        assert seen == {"next_read", "prev_write"}

    def test_step_has_real_target_ors_both_strategies(self):
        data = _data()
        assert _step_has_real_target("PRE_EXEC_REG_MOD", 1, data)
        assert _step_has_real_target("PRE_EXEC_REG_MOD", 2, data)

    def test_golden_trace_still_green(self):
        golden_trace_mod.TestD2ABackCompatGoldenTrace().test_v5_decision_trace_matches_pre_d2a_baseline()
