#!/usr/bin/env python3
"""D2.B Batch 2 — TXN_PREV_CYCLE_MOD unit tests (Layer 1)."""

from __future__ import annotations

import random

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.mutations.txn_prev_cycle_mod import (
    TxnPrevCycleModTarget,
    create_config,
    generate_new_value,
    get_targets_at_step,
)
from a4.standalone.compressed_global_extractor import txn_role_for_kind


def _cycle(step: int) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0x1000 + step, txn_idx=0, major=0, minor=0
    )


def _txn(step: int, txn_idx: int, *, cycle: int, prev_cycle: int) -> A4AllTxn:
    return A4AllTxn(
        txn_idx=txn_idx,
        step=step,
        txn_type="mem",
        addr=0x30000001,
        cycle=cycle,
        word=42,
        prev_cycle=prev_cycle,
        prev_word=42,
    )


def _data() -> InspectionData:
    cycles = [_cycle(1), _cycle(2)]
    txns = [
        _txn(1, 10, cycle=100, prev_cycle=50),
        _txn(2, 20, cycle=200, prev_cycle=150),
    ]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


class TestTxnPrevCycleModTargets:
    def test_returns_all_txns_at_step(self):
        targets = get_targets_at_step(1, _data())
        assert len(targets) == 1
        assert targets[0].txn_idx == 10
        assert targets[0].original_prev_cycle == 50
        assert targets[0].original_cycle == 100

    def test_step_zero_excluded(self):
        assert get_targets_at_step(0, _data()) == []


class TestTxnPrevCycleModValueGen:
    def test_excludes_zero_and_own_cycle(self):
        target = TxnPrevCycleModTarget(
            step=1, cycle_idx=1, txn_idx=10, addr=1,
            original_prev_cycle=50, original_cycle=100,
            original_word=42, original_prev_word=42,
        )
        rng = random.Random(0)
        for _ in range(50):
            val = generate_new_value(target, rng)
            assert val != 0
            assert val != 100
            assert val != 50

    def test_bounded_draws_in_range(self):
        target = TxnPrevCycleModTarget(
            step=1, cycle_idx=1, txn_idx=10, addr=1,
            original_prev_cycle=50, original_cycle=500,
            original_word=42, original_prev_word=42,
        )
        rng = random.Random(1)
        bounded = []
        for _ in range(100):
            rng2 = random.Random(rng.randint(0, 10_000))
            if rng2.random() < 0.70:
                val = generate_new_value(target, rng2)
                if 1 <= val < 500:
                    bounded.append(val)
        assert len(bounded) >= 20


class TestTxnPrevCycleModConfig:
    def test_create_config(self, tmp_path):
        target = TxnPrevCycleModTarget(
            step=2, cycle_idx=2, txn_idx=20, addr=99,
            original_prev_cycle=150, original_cycle=200,
            original_word=42, original_prev_word=42,
        )
        path = create_config(target, 99, tmp_path / "cfg.json")
        import json
        cfg = json.loads(path.read_text())
        assert cfg["mutation_type"] == "TXN_PREV_CYCLE_MOD"
        assert cfg["prev_cycle"] == 99


class TestRegistryPlumbing:
    def test_valid_steps_for_kind(self):
        steps = _data().get_valid_steps_for_kind("TXN_PREV_CYCLE_MOD")
        assert 1 in steps and 2 in steps

    def test_cgc_role_mapping(self):
        assert txn_role_for_kind("TXN_PREV_CYCLE_MOD") == "prev_cycle"

    def test_fuzzer_dispatch(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
            seed=7,
        )
        fuzzer.data = _data()
        config, _, _ = fuzzer._create_mutation("TXN_PREV_CYCLE_MOD", 1)
        assert config is not None
        assert config["mutation_type"] == "TXN_PREV_CYCLE_MOD"

    def test_mutation_kinds_registry(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
        )
        assert "TXN_PREV_CYCLE_MOD" in fuzzer.MUTATION_KINDS
