#!/usr/bin/env python3
"""D2.B Batch 3 — unit tests (Layer 1) for B.4–B.8."""

from __future__ import annotations

import json
import random

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.compressed_global_extractor import txn_role_for_kind
from a4.standalone.mutations.txn_addr_mod import create_config as create_addr_config, get_targets_at_step as addr_targets
from a4.standalone.mutations.txn_cycle_phase_mod import create_config as create_phase_config, flipped_cycle, get_targets_at_step as phase_targets
from a4.standalone.mutations.cycle_pc_mod import create_config as create_pc_config, get_targets_at_step as pc_targets
from a4.standalone.mutations.cycle_state_mod import create_config as create_state_config, get_targets_at_step as state_targets
from a4.standalone.mutations.cycle_diff_count_mod import create_config as create_diff_config, get_all_targets as diff_targets


def _data() -> InspectionData:
    cycles = [
        A4CycleInfo(cycle_idx=1, step=1, pc=0x1004, txn_idx=0, major=0, minor=0, state=48, diff_count_0=1, diff_count_1=2),
        A4CycleInfo(cycle_idx=2, step=2, pc=0x1008, txn_idx=1, major=5, minor=0, state=48, diff_count_0=0, diff_count_1=0),
        A4CycleInfo(cycle_idx=3, step=3, pc=0x100c, txn_idx=2, major=7, minor=0, state=48, diff_count_0=0, diff_count_1=0),
    ]
    txns = [
        A4AllTxn(txn_idx=0, step=1, txn_type="mem", addr=100, cycle=10, word=1, prev_cycle=0, prev_word=0),
        A4AllTxn(txn_idx=1, step=2, txn_type="mem", addr=200, cycle=11, word=2, prev_cycle=0, prev_word=0),
    ]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


class TestBatch3Registry:
    @pytest.mark.parametrize(
        "kind,expected_role",
        [
            ("TXN_ADDR_MOD", "addr"),
            ("TXN_CYCLE_PHASE_MOD", "cycle_phase"),
            ("CYCLE_DIFF_COUNT_MOD", "diff_count"),
        ],
    )
    def test_cgc_roles(self, kind, expected_role):
        assert txn_role_for_kind(kind) == expected_role

    def test_mutation_kinds_registered(self):
        """Post-D2.B-PS-1: CYCLE_DIFF_COUNT_MOD is the only Batch-3 kind still
        in MUTATION_KINDS. The 4 dead kinds (TXN_ADDR_MOD, TXN_CYCLE_PHASE_MOD,
        CYCLE_PC_MOD, CYCLE_STATE_MOD) are excluded per W-17/W-18 audits; their
        per-kind modules + Rust handlers + attestation tests remain on disk as
        regression sentinels but are not wired into bandit dispatch.
        """
        fuzzer = A4Fuzzer(host_binary="/bin/true", host_args=[], db_path=":memory:", selector_strategy="zoned")
        assert "CYCLE_DIFF_COUNT_MOD" in fuzzer.MUTATION_KINDS
        for dead_kind in (
            "TXN_ADDR_MOD", "TXN_CYCLE_PHASE_MOD", "CYCLE_PC_MOD", "CYCLE_STATE_MOD",
        ):
            assert dead_kind not in fuzzer.MUTATION_KINDS, (
                f"{dead_kind} re-introduced; see D2.B-PS-1 in IV_POS_8_D2_PLAN.md"
            )


class TestTxnAddrMod:
    def test_targets_exclude_registers(self):
        data = _data()
        assert len(addr_targets(1, data)) == 1

    def test_config(self, tmp_path):
        t = addr_targets(1, _data())[0]
        cfg = json.loads(create_addr_config(t, 999, tmp_path / "c.json").read_text())
        assert cfg["mutation_type"] == "TXN_ADDR_MOD"
        assert cfg["addr"] == 999


class TestTxnCyclePhaseMod:
    def test_xor_phase(self):
        t = phase_targets(1, _data())[0]
        assert flipped_cycle(t) == t.original_cycle ^ 1

    def test_config_no_value_field(self, tmp_path):
        t = phase_targets(1, _data())[0]
        cfg = json.loads(create_phase_config(t, tmp_path / "c.json").read_text())
        assert "cycle" not in cfg or cfg.get("txn_idx") is not None
        assert "addr" not in cfg.get("mutation_type", "")


class TestCyclePcMod:
    def test_major_filter(self):
        assert pc_targets(1, _data()) is not None
        assert pc_targets(3, _data()) is None  # major 7 excluded


class TestCycleStateMod:
    def test_target(self):
        t = state_targets(1, _data())
        assert t is not None
        assert t.original_state == 48

    def test_config(self, tmp_path):
        t = state_targets(1, _data())
        cfg = json.loads(create_state_config(t, 8, tmp_path / "c.json").read_text())
        assert cfg["state"] == 8


class TestCycleDiffCountMod:
    def test_two_indices(self):
        targets = diff_targets(_data())
        assert len(targets) == 6  # 3 cycles x 2 indices

    def test_config(self, tmp_path):
        t = diff_targets(_data())[0]
        cfg = json.loads(create_diff_config(t, 99, tmp_path / "c.json").read_text())
        assert cfg["index"] in (0, 1)
        assert cfg["diff_count"] == 99
