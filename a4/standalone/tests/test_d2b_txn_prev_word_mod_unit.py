#!/usr/bin/env python3
"""D2.B Batch 1 — TXN_PREV_WORD_MOD unit tests (Layer 1)."""

from __future__ import annotations

import random
from typing import List

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.mutations.txn_prev_word_mod import (
    TxnPrevWordModTarget,
    create_config,
    generate_new_value,
    get_targets_at_step,
)
from a4.standalone.compressed_global_extractor import txn_role_for_kind


_USER_REGS = 1073725472


def _cycle(step: int, major: int = 0) -> A4CycleInfo:
    return A4CycleInfo(
        cycle_idx=step, step=step, pc=0x1000 + step, txn_idx=0, major=major, minor=0
    )


def _txn(
    step: int,
    txn_idx: int,
    *,
    is_write: bool,
    prev_word: int = 10,
    word: int = 10,
) -> A4AllTxn:
    return A4AllTxn(
        txn_idx=txn_idx,
        step=step,
        txn_type="reg",
        addr=_USER_REGS + 5,
        cycle=1 if is_write else 0,
        word=word,
        prev_cycle=0,
        prev_word=prev_word,
    )


def _data(steps: List[int]) -> InspectionData:
    cycles = [_cycle(s) for s in steps]
    txns = [
        _txn(1, 10, is_write=False, prev_word=42, word=42),
        _txn(2, 20, is_write=True, prev_word=7, word=99),
    ]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


class TestTxnPrevWordModTargets:
    def test_at_read_filters_writes(self):
        data = _data([1, 2])
        targets = get_targets_at_step(1, data, strategy="at_read")
        assert len(targets) == 1
        assert targets[0].is_read is True
        assert targets[0].strategy == "at_read"

    def test_at_write_filters_reads(self):
        data = _data([1, 2])
        targets = get_targets_at_step(2, data, strategy="at_write")
        assert len(targets) == 1
        assert targets[0].is_read is False
        assert targets[0].strategy == "at_write"

    def test_step_zero_excluded(self):
        data = _data([0, 1])
        assert get_targets_at_step(0, data, strategy="at_read") == []


class TestTxnPrevWordModValueGen:
    def test_generate_new_value_differs(self):
        target = TxnPrevWordModTarget(
            step=1,
            cycle_idx=1,
            txn_idx=10,
            addr=1,
            is_read=True,
            original_prev_word=0x12345678,
            original_word=0x12345678,
            original_prev_cycle=0,
            strategy="at_read",
        )
        rng = random.Random(0)
        for _ in range(20):
            assert generate_new_value(target, rng) != target.original_prev_word


class TestTxnPrevWordModConfig:
    def test_create_config_includes_strategy(self, tmp_path):
        target = TxnPrevWordModTarget(
            step=2,
            cycle_idx=2,
            txn_idx=20,
            addr=99,
            is_read=False,
            original_prev_word=7,
            original_word=99,
            original_prev_cycle=1,
            strategy="at_write",
        )
        path = create_config(target, 0xBEEF, tmp_path / "cfg.json")
        import json

        cfg = json.loads(path.read_text())
        assert cfg["mutation_type"] == "TXN_PREV_WORD_MOD"
        assert cfg["prev_word"] == 0xBEEF
        assert cfg["strategy"] == "at_write"


class TestRegistryPlumbing:
    def test_valid_steps_for_kind(self):
        data = _data([1, 2])
        steps = data.get_valid_steps_for_kind("TXN_PREV_WORD_MOD")
        assert 1 in steps and 2 in steps
        assert 0 not in steps

    def test_cgc_role_mapping(self):
        assert txn_role_for_kind("TXN_PREV_WORD_MOD") == "prev_word"

    def test_fuzzer_dispatch_rng_picks_strategy(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
            seed=123,
        )
        fuzzer.data = _data([1, 2])
        seen = set()
        for seed in range(200):
            fuzzer.rng = random.Random(seed)
            config = None
            for step in (1, 2):
                config, _, _ = fuzzer._create_mutation("TXN_PREV_WORD_MOD", step)
                if config is not None:
                    break
            if config is not None:
                seen.add(config["strategy"])
        assert seen == {"at_read", "at_write"}

    def test_mutation_kinds_registry(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
        )
        assert "TXN_PREV_WORD_MOD" in fuzzer.MUTATION_KINDS
