#!/usr/bin/env python3
"""Phase 6 unit tests — telemetry_v2 helpers and record_full_telemetry."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.standalone.fuzzer import V2_BANDIT_STRATEGIES
from a4.standalone.telemetry_v2 import (
    TELEMETRY_LEVELS,
    build_hook3_payload,
    classify_value_class,
    default_telemetry_level,
    extract_mutation_substrategy,
    record_full_telemetry,
)
from a4.standalone.structural_cells import StructuralCell


@dataclass
class StubExecResult:
    failures: List[Any] = field(default_factory=list)
    exit_code: int = 0
    touch_bitmap: Optional[bytes] = b"\x01"
    family_residues: Optional[List[dict]] = None
    family_details: Optional[List[dict]] = None
    config: Dict[str, Any] = field(default_factory=dict)


def _fail(major: int = 5, minor: int = 4) -> ConstraintFailure:
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc="MemLoadInput(zirgen/circuit/rv32im/v2/dsl/inst_mem.zir:8)",
        value=1,
    )


class TestClassifyValueClass:
    def test_zero(self):
        assert classify_value_class(100, 0) == "zero"

    def test_bit_pattern_single_bit(self):
        assert classify_value_class(0, 1) == "bit_pattern"
        assert classify_value_class(0b1111, 0b1011) == "bit_pattern"

    def test_small_literal(self):
        assert classify_value_class(1000, 42) == "small"

    def test_large(self):
        assert classify_value_class(0, 0xDEADBEEF) == "large"


class TestDefaultTelemetryLevel:
    def test_v2_selectors_default_full(self):
        for sel in V2_BANDIT_STRATEGIES:
            assert default_telemetry_level(sel, V2_BANDIT_STRATEGIES) == "full"

    def test_legacy_default_standard(self):
        assert default_telemetry_level("zoned", V2_BANDIT_STRATEGIES) == "standard"
        assert default_telemetry_level("bandit", V2_BANDIT_STRATEGIES) == "standard"

    def test_levels_frozen(self):
        assert TELEMETRY_LEVELS == frozenset({"none", "standard", "full"})


class TestExtractMutationSubstrategy:
    def test_load_val_mod_value_class(self):
        sub = extract_mutation_substrategy("LOAD_VAL_MOD", {}, 100, 0)
        assert sub["value_class"] == "zero"
        assert sub["opcode"] is None

    def test_mem_val_mod_xor_mask(self):
        sub = extract_mutation_substrategy("MEM_VAL_MOD", {}, 0xFF00, 0xFF01)
        assert sub["bit_mask"] == 1
        assert sub["byte_lane"] == 0
        assert sub["value_class"] is not None

    def test_instr_word_sur_decodes_fields(self):
        # addi x1, x0, 4  => imm=4, opcode=0x13
        word = 0x00400093
        sub = extract_mutation_substrategy(
            "INSTR_WORD_MOD_SUR", {"word": word}, 0, word,
        )
        assert sub["opcode"] == 0x13
        assert sub["rd"] == 1
        assert sub["rs1"] == 0
        assert sub["imm"] == 4


class TestBuildHook3Payload:
    def test_empty_returns_nones(self):
        raw, compressed = build_hook3_payload(None, None, "LOAD_VAL_MOD", "core", 0)
        assert raw is None
        assert compressed is None

    def test_d36_shape(self):
        residues = [{"family": "memory", "nonzero": True}]
        raw, compressed = build_hook3_payload(
            residues, None, "MEM_VAL_MOD", "core_memory", 5,
        )
        assert raw == {"family_residues": residues}
        assert compressed is None or isinstance(compressed, list)


class TestRecordFullTelemetry:
    @pytest.fixture
    def telemetry_ctx(self, tmp_path):
        from a4.standalone.coverage_db import CoverageDB

        db_path = str(tmp_path / "tel.db")
        with CoverageDB(db_path) as db:
            cid = db.start_campaign("/bin/host", [], "all", 1)
            mid = db.record_mutation(cid, "LOAD_VAL_MOD", 3, 0, {"step": 3}, None, False)
            yield db, cid, mid

    def test_writes_all_v2_tables(self, telemetry_ctx):
        db, cid, mid = telemetry_ctx
        exec_result = StubExecResult(
            failures=[_fail()],
            family_residues=[{"family": "memory", "nonzero": True}],
        )
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_global: Set[str] = set()
        seen_struct: Set[StructuralCell] = set()

        record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD",
            step=3,
            exec_result=exec_result,
            config={"step": 3, "mutation_type": "LOAD_VAL_MOD"},
            original_value=100,
            mutated_value=0,
            legacy_reward_diag={"reward": 0.5, "T_new": 0.0, "Q_new": 0.0},
            step_to_zone={3: "core_other"},
            seen_local_v2=seen_local,
            seen_compressed_global=seen_global,
            seen_structural=seen_struct,
        )

        cf = db.conn.execute(
            "SELECT * FROM reward_counterfactuals WHERE mutation_id=?", (mid,)
        ).fetchone()
        assert cf is not None
        for col in (
            "current_reward", "no_qloc_reward", "fnew_only_reward",
            "compressed_global_reward",
        ):
            val = cf[col]
            assert math.isfinite(val), col

        sub = db.conn.execute(
            "SELECT * FROM mutation_substrategy WHERE mutation_id=?", (mid,)
        ).fetchone()
        assert sub["value_class"] == "zero"

        hook3 = db.conn.execute(
            "SELECT * FROM hook3_raw WHERE mutation_id=?", (mid,)
        ).fetchone()
        assert hook3 is not None
        raw = json.loads(hook3["raw_json"])
        assert "family_residues" in raw

        local = db.conn.execute(
            "SELECT COUNT(*) AS n FROM local_coverage_v2 WHERE campaign_id=?", (cid,)
        ).fetchone()["n"]
        assert local >= 1
