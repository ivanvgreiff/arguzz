#!/usr/bin/env python3
"""D2.B Batch 2 — CYCLE_MODE_MOD unit tests (Layer 1)."""

from __future__ import annotations

import json

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.mutations.cycle_mode_mod import (
    CycleModeModTarget,
    create_config,
    flipped_mode,
    get_targets_at_step,
)
from a4.standalone.compressed_global_extractor import txn_role_for_kind


def _data() -> InspectionData:
    cycles = [
        A4CycleInfo(0, 0, 0x1000, 0, 0, 0, machine_mode=0),
        A4CycleInfo(1, 1, 0x1004, 0, 0, 0, machine_mode=0),
        A4CycleInfo(2, 2, 0x1008, 0, 5, 0, machine_mode=1),
        A4CycleInfo(3, 3, 0x100C, 0, 7, 0, machine_mode=3),
    ]
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


class TestCycleModeModTargets:
    def test_step_zero_excluded(self):
        assert get_targets_at_step(0, _data()) is None

    def test_flippable_mode(self):
        t = get_targets_at_step(1, _data())
        assert t is not None
        assert t.original_mode == 0

    def test_non_binary_mode_skipped(self):
        assert get_targets_at_step(3, _data()) is None


class TestCycleModeModConfig:
    def test_deterministic_flip(self, tmp_path):
        target = CycleModeModTarget(
            step=2, cycle_idx=2, pc=0x1008, original_mode=1, major=5, minor=0
        )
        assert flipped_mode(target) == 0
        path = create_config(target, tmp_path / "cfg.json")
        cfg = json.loads(path.read_text())
        assert cfg["mode"] == 0
        assert cfg["mutation_type"] == "CYCLE_MODE_MOD"


class TestRegistryPlumbing:
    def test_valid_steps_for_kind(self):
        steps = _data().get_valid_steps_for_kind("CYCLE_MODE_MOD")
        assert 1 in steps and 2 in steps and 3 in steps
        assert 0 not in steps

    def test_cgc_role_mapping(self):
        assert txn_role_for_kind("CYCLE_MODE_MOD") == "read"

    def test_fuzzer_dispatch(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
        )
        fuzzer.data = _data()
        config, new_mode, old_mode = fuzzer._create_mutation("CYCLE_MODE_MOD", 1)
        assert config is not None
        assert old_mode == 0 and new_mode == 1

    def test_mutation_kinds_registry(self):
        fuzzer = A4Fuzzer(
            host_binary="/bin/true",
            host_args=[],
            db_path=":memory:",
            selector_strategy="zoned",
        )
        assert "CYCLE_MODE_MOD" in fuzzer.MUTATION_KINDS
