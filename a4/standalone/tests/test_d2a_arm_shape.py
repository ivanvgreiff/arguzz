#!/usr/bin/env python3
"""D2.A Batch 1 — ArmKey dataclass shape tests."""

from __future__ import annotations

import pytest

from a4.standalone.bandit_ts import arm_id, arm_id_for_decision
from a4.standalone.semantic_arm_universe import (
    A4_TRACE_CELL,
    ARGUZZ_EXEC_FAULT,
    ArmKey,
    NA,
)


class TestArmKeyV5:
    def test_v5_matches_legacy_arm_id_helper(self):
        ak = ArmKey.v5("INSTR_TYPE_MOD", "core_arithmetic")
        assert arm_id_for_decision(ak) == arm_id("INSTR_TYPE_MOD", "core_arithmetic")
        assert str(ak) == "INSTR_TYPE_MOD|core_arithmetic"

    def test_v5_sentinel_fields(self):
        ak = ArmKey.v5("COMP_OUT_MOD", "step0")
        assert ak.surface == A4_TRACE_CELL
        assert ak.opcode_class == NA
        assert ak.pre_post == NA
        assert ak.is_v5_shape()

    def test_tuple_unpack_back_compat(self):
        ak = ArmKey.v5("LOAD_VAL_MOD", "core_memory_load")
        kind, zone = ak
        assert kind == "LOAD_VAL_MOD"
        assert zone == "core_memory_load"


class TestArmKeyArguzzShape:
    def test_full_five_pipe_format(self):
        ak = ArmKey(
            ARGUZZ_EXEC_FAULT,
            "INSTR_WORD_MOD",
            "core_arithmetic",
            "arithmetic",
            "pre_exec",
        )
        assert str(ak) == (
            "arguzz_exec_fault|INSTR_WORD_MOD|core_arithmetic|arithmetic|pre_exec"
        )
        assert not ak.is_v5_shape()
        assert arm_id_for_decision(ak) == str(ak)

    def test_parse_round_trip_v5(self):
        s = "INSTR_TYPE_MOD|core_mul"
        assert str(ArmKey.parse(s)) == s

    def test_parse_round_trip_full(self):
        s = "arguzz_exec_fault|BR_NEG_COND|core_branch|branch|pre_exec"
        assert str(ArmKey.parse(s)) == s

    def test_parse_rejects_bad_format(self):
        with pytest.raises(ValueError):
            ArmKey.parse("only|three|parts")
