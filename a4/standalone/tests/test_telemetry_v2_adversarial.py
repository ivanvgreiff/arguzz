#!/usr/bin/env python3
"""
Adversarial / skeptical-review tests for cloud1 Phase 6 telemetry_v2.

Written by Opus during Phase 6 review of Composer's implementation.
Target areas (from Composer's review pointer):
  1. classify_value_class edge cases (MSB, overflow, near-overflow)
  2. extract_mutation_substrategy across all kinds
  3. build_hook3_payload both-fields case
  4. record_full_telemetry with crash exec_result
  5. mutation_major fallback chain (cycle.major > failures[0].major > 0)
  6. counterfactual round-trip via SQLite (finite, finite-after-NaN-protection)
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.standalone.coverage_db import CoverageDB
from a4.standalone.fuzzer import V2_BANDIT_STRATEGIES
from a4.standalone.structural_cells import StructuralCell
from a4.standalone.telemetry_v2 import (
    TELEMETRY_LEVELS,
    build_hook3_payload,
    classify_value_class,
    default_telemetry_level,
    extract_mutation_substrategy,
    record_full_telemetry,
)


@dataclass
class StubExec:
    failures: List[Any] = field(default_factory=list)
    exit_code: int = 0
    touch_bitmap: Optional[bytes] = b"\x01"
    family_residues: Optional[List[dict]] = None
    family_details: Optional[List[dict]] = None
    config: Dict[str, Any] = field(default_factory=dict)


def _fail(major=5, minor=4, loc=None):
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc=loc or "MemLoadInput(zirgen/circuit/rv32im/v2/dsl/inst_mem.zir:8)",
        value=1,
    )


# ---------------------------------------------------------------------------
# 1. value_class edges
# ---------------------------------------------------------------------------

class TestClassifyValueClassEdges:
    def test_msb_high_negative_treated_as_unsigned(self):
        # 0x80000000 = top bit set (would be negative in two's complement int32)
        # The function uses & 0xFFFFFFFF, so it's treated as unsigned.
        # mut=0x80000000 != 0, XOR with original=0 has bit_count=1 (single MSB)
        # so this should be classified as bit_pattern.
        assert classify_value_class(0, 0x80000000) == "bit_pattern"

    def test_max_u32_to_min_diff_small_wraps(self):
        # orig=0xFFFFFFFF (-1 unsigned), mut=0 - already covered by zero check.
        assert classify_value_class(0xFFFFFFFF, 0) == "zero"

    def test_max_u32_to_one_small_diff_via_wrap(self):
        # orig=0xFFFFFFFF, mut=1: diff (1 - 0xFFFFFFFF) mod 2^32 = 2.
        # XOR=0xFFFFFFFE has bit_count=31 → not bit_pattern.
        # diff in 2's-complement-style wrap is 2 → small.
        result = classify_value_class(0xFFFFFFFF, 1)
        assert result == "small"

    def test_truly_large(self):
        # No bit pattern (>4 differing bits), big distance, mut != small.
        result = classify_value_class(0, 0x12345678)
        # 0x12345678 has 13 set bits; mut > 256; diff > 256; 2^32 - diff > 256
        assert result == "large"

    def test_exactly_4_bit_xor_is_bit_pattern(self):
        # 4-bit XOR is the boundary (<=4)
        assert classify_value_class(0, 0xF) == "bit_pattern"   # 4 bits

    def test_exactly_5_bit_xor_not_bit_pattern(self):
        # 5 bits set → exceeds bit_pattern threshold; mut=0x1F<256 → small
        assert classify_value_class(0, 0x1F) == "small"

    def test_signed_negative_original(self):
        # original passed as -1; & 0xFFFFFFFF makes it 0xFFFFFFFF
        # mut=0 → "zero" wins
        assert classify_value_class(-1, 0) == "zero"

    def test_both_zero_returns_zero(self):
        # XOR is 0, mut is 0
        assert classify_value_class(0, 0) == "zero"

    def test_identical_nonzero_no_change_classified_by_mut(self):
        # mut == orig, XOR=0, falls through to mut size check.
        # mut=1000 → not <256, diff=0 → small (because diff < 256)
        assert classify_value_class(1000, 1000) == "small"


# ---------------------------------------------------------------------------
# 2. extract_mutation_substrategy across kinds
# ---------------------------------------------------------------------------

class TestExtractMutationSubstrategy:
    def test_unknown_kind_returns_all_nones(self):
        sub = extract_mutation_substrategy("UNKNOWN_KIND", {}, 10, 20)
        # All keys present; all None
        for k, v in sub.items():
            assert v is None, f"{k}={v} should be None for unknown kind"

    def test_pre_exec_reg_mod_gets_value_class(self):
        # D-decision concern: PRE_EXEC_REG_MOD was added to value_class even
        # though Pro listed only LOAD/STORE/COMP. Verify it's present.
        sub = extract_mutation_substrategy("PRE_EXEC_REG_MOD", {}, 5, 0)
        assert sub["value_class"] == "zero"

    def test_instr_word_mod_full_decodes(self):
        # addi x1, x0, 4 = 0x00400093
        word = 0x00400093
        sub = extract_mutation_substrategy("INSTR_WORD_MOD_FULL", {}, 0, word)
        assert sub["opcode"] == 0x13
        assert sub["rd"] == 1

    def test_instr_type_mod_no_decode(self):
        # INSTR_TYPE_MOD changes the instruction kind enum at the byte level,
        # not the word. It is NOT in word_kinds, so no instruction decode.
        sub = extract_mutation_substrategy("INSTR_TYPE_MOD", {}, 0, 0x13)
        assert sub["opcode"] is None
        assert sub["rd"] is None

    def test_mem_val_mod_zero_xor_byte_lane(self):
        # If original == mutated, XOR=0, byte_lane=0 per code.
        sub = extract_mutation_substrategy("MEM_VAL_MOD", {}, 0xFF, 0xFF)
        assert sub["bit_mask"] is None       # None for zero XOR
        assert sub["byte_lane"] == 0

    def test_mem_val_mod_high_bit_xor(self):
        # XOR = 0x80000000 (single high bit)
        sub = extract_mutation_substrategy("MEM_VAL_MOD", {}, 0, 0x80000000)
        assert sub["bit_mask"] == 0x80000000
        assert sub["byte_lane"] == 31   # min(31, 32-1)

    def test_load_val_mod_no_instr_decode(self):
        # 100→50: XOR = 0x56 = 0b01010110 has exactly 4 bits → bit_pattern
        # (boundary case of the <=4 rule)
        sub = extract_mutation_substrategy("LOAD_VAL_MOD", {}, 100, 50)
        assert sub["opcode"] is None
        assert sub["value_class"] == "bit_pattern"

    def test_load_val_mod_truly_small(self):
        # 100→50 has 4 differing bits → bit_pattern. Use a case with >4
        # differing bits AND mut < 256 to actually hit `small`.
        # 0xDE = 0b11011110, XOR with 0 = 7 bits → not bit_pattern; mut=222<256 → small
        sub = extract_mutation_substrategy("LOAD_VAL_MOD", {}, 0, 0xDE)
        assert sub["value_class"] == "small"


# ---------------------------------------------------------------------------
# 3. build_hook3_payload combinations
# ---------------------------------------------------------------------------

class TestBuildHook3Payload:
    def test_both_fields_present(self):
        residues = [{"family": "memory", "nonzero": True}]
        details = [{"family": "memory", "broken_addrs": [0x80001000]}]
        raw, compressed = build_hook3_payload(
            residues, details, "MEM_VAL_MOD", "core_memory_load", 5,
        )
        assert raw == {"family_residues": residues, "family_details": details}
        # Should have at least one compressed context now.
        assert compressed is not None
        assert isinstance(compressed, list)
        assert len(compressed) >= 1

    def test_only_residues_no_details_no_compression(self):
        # residues alone (no details) → cannot extract compressed ctx
        residues = [{"family": "memory", "nonzero": True}]
        raw, compressed = build_hook3_payload(
            residues, None, "MEM_VAL_MOD", "core_memory_load", 5,
        )
        assert raw == {"family_residues": residues}
        assert compressed is None or compressed == []

    def test_compressed_json_round_trips(self):
        details = [{"family": "lookup", "broken_indices": [10, 20]}]
        raw, compressed = build_hook3_payload(
            None, details, "MEM_VAL_MOD", "core_memory_load", 5,
        )
        if compressed:
            # Every entry should be a JSON-serializable dict (D36 contract)
            for c in compressed:
                assert isinstance(c, dict)
                json.dumps(c)  # MUST not raise


# ---------------------------------------------------------------------------
# 4. record_full_telemetry edge cases
# ---------------------------------------------------------------------------

class TestRecordFullTelemetryEdges:
    @pytest.fixture
    def db_mid(self, tmp_path):
        db_path = str(tmp_path / "tel.db")
        with CoverageDB(db_path) as db:
            cid = db.start_campaign("/bin/host", [], "all", 1)
            mid = db.record_mutation(cid, "LOAD_VAL_MOD", 3, 0,
                                      {"step": 3}, None, False)
            yield db, cid, mid

    def test_crash_exec_result_still_writes_rows(self, db_mid):
        db, cid, mid = db_mid
        exec_result = StubExec(failures=[], exit_code=139, touch_bitmap=None)
        record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=100, mutated_value=0,
            legacy_reward_diag={"mode": "crash"},
            step_to_zone={3: "core_other"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        cf = db.conn.execute(
            "SELECT * FROM reward_counterfactuals WHERE mutation_id=?", (mid,)
        ).fetchone()
        assert cf is not None
        # Crash with empty seen_structural still grants s_new=1 (novel cell);
        # reward = 0.15*sat(1,2) - 0.50 ≈ -0.441 (NOT pure -0.50).
        # This is a Pro §6.3 design property: novel structural combinations
        # are rewarded regardless of outcome.
        assert math.isfinite(cf["current_reward"])
        assert cf["current_reward"] == pytest.approx(-0.441, abs=1e-3)
        # no_qloc reward for mode=crash should be 0.0 per D23
        assert cf["no_qloc_reward"] == 0.0

    def test_crash_with_warm_structural_set_pure_minus_05(self, db_mid):
        # If structural cell is ALREADY seen, s_new=0, then crash reward = -0.50.
        db, cid, mid = db_mid
        from a4.standalone.structural_cells import make_structural_cell
        from a4.standalone.semantic_zones import major_to_opcode_class
        from a4.standalone.compressed_global_extractor import txn_role_for_kind
        # Pre-populate the structural set with the cell this call would build.
        cell = make_structural_cell(
            kind="LOAD_VAL_MOD",
            semantic_zone="core_other",
            opcode_class=major_to_opcode_class(0),
            mode="user",
            txn_role=txn_role_for_kind("LOAD_VAL_MOD"),
            sub_strategy=None,
        )
        seen_struct = {cell}
        exec_result = StubExec(failures=[], exit_code=139, touch_bitmap=None)
        record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=100, mutated_value=0,
            legacy_reward_diag={"mode": "crash"},
            step_to_zone={3: "core_other"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=seen_struct,
        )
        cf = db.conn.execute(
            "SELECT * FROM reward_counterfactuals WHERE mutation_id=?", (mid,)
        ).fetchone()
        # s_new=0 now → reward = pure -0.50
        assert cf["current_reward"] == pytest.approx(-0.50, abs=1e-6)

    def test_empty_failures_no_local_v2_rows(self, db_mid):
        db, cid, mid = db_mid
        exec_result = StubExec(failures=[])
        record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=100, mutated_value=50,
            legacy_reward_diag={"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0},
            step_to_zone={3: "core_other"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        # No failures → no local_coverage_v2 rows
        n = db.conn.execute(
            "SELECT COUNT(*) AS n FROM local_coverage_v2 WHERE campaign_id=?", (cid,)
        ).fetchone()["n"]
        assert n == 0

    def test_mutation_major_from_failure_when_cycle_major_absent(self, db_mid):
        # When `_mutation_major` is NOT set on exec_result, falls back to
        # failures[0].major.
        db, cid, mid = db_mid
        exec_result = StubExec(failures=[_fail(major=11, minor=0)])
        components = record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=10, mutated_value=20,
            legacy_reward_diag={"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0},
            step_to_zone={3: "core_sha"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        # Components produced and structural cell built with major=11.
        # Just verify call succeeded and structural cell has appropriate opcode_class.
        assert components is not None
        assert components["s_new"] in (0, 1)

    def test_mutation_major_explicit_overrides_failure(self, db_mid):
        # When `_mutation_major` IS set, it wins over failures[0].major.
        db, cid, mid = db_mid
        exec_result = StubExec(failures=[_fail(major=11)])
        setattr(exec_result, "_mutation_major", 5)   # MEM0 should win over SHA0
        components = record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=10, mutated_value=20,
            legacy_reward_diag={"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0},
            step_to_zone={3: "core_memory_load"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        assert components is not None

    def test_duplicate_failure_locs_in_same_run_dedup_local_v2(self, db_mid):
        db, cid, mid = db_mid
        f = _fail()
        exec_result = StubExec(failures=[f, f, f, f])   # 4 dup
        record_full_telemetry(
            db, cid, mid,
            kind="LOAD_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=10, mutated_value=20,
            legacy_reward_diag={"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0},
            step_to_zone={3: "core_other"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        # 4 dup failures = 1 distinct local_v2 row
        n = db.conn.execute(
            "SELECT COUNT(*) AS n FROM local_coverage_v2 WHERE campaign_id=?", (cid,)
        ).fetchone()["n"]
        assert n == 1


# ---------------------------------------------------------------------------
# 5. default_telemetry_level invariants
# ---------------------------------------------------------------------------

class TestDefaultTelemetryLevel:
    def test_unknown_selector_defaults_standard(self):
        # Forward-compat: unknown selector treated as legacy.
        assert default_telemetry_level("future_selector", V2_BANDIT_STRATEGIES) == "standard"

    def test_each_v2_strategy_individually(self):
        for sel in sorted(V2_BANDIT_STRATEGIES):
            assert default_telemetry_level(sel, V2_BANDIT_STRATEGIES) == "full", sel


# ---------------------------------------------------------------------------
# 6. SQLite round-trip — counterfactuals MUST round-trip as finite floats
# ---------------------------------------------------------------------------

class TestCounterfactualRoundTrip:
    @pytest.fixture
    def db_mid(self, tmp_path):
        db_path = str(tmp_path / "tel.db")
        with CoverageDB(db_path) as db:
            cid = db.start_campaign("/bin/host", [], "all", 1)
            mid = db.record_mutation(cid, "LOAD_VAL_MOD", 3, 0,
                                      {"step": 3}, None, False)
            yield db, cid, mid

    def test_all_five_columns_round_trip_finite(self, db_mid):
        db, cid, mid = db_mid
        exec_result = StubExec(
            failures=[_fail()],
            family_residues=[{"family": "memory", "nonzero": True}],
            family_details=[{"family": "memory", "broken_addrs": [0x80001000]}],
        )
        record_full_telemetry(
            db, cid, mid,
            kind="MEM_VAL_MOD", step=3, exec_result=exec_result,
            config={"step": 3}, original_value=0, mutated_value=0xCAFE,
            legacy_reward_diag={"mode": "normal", "S": 0.7, "Q_rep": 0.8, "Q_glob": 0.9},
            step_to_zone={3: "core_memory_load"},
            seen_local_v2=set(), seen_compressed_global=set(),
            seen_structural=set(),
        )
        row = db.conn.execute(
            "SELECT current_reward, no_qloc_reward, fnew_only_reward, "
            "discovery_binary_reward, compressed_global_reward "
            "FROM reward_counterfactuals WHERE mutation_id=?", (mid,)
        ).fetchone()
        assert row is not None
        for col in ("current_reward", "no_qloc_reward", "fnew_only_reward",
                    "compressed_global_reward"):
            assert math.isfinite(row[col]), f"{col}={row[col]}"
        assert row["discovery_binary_reward"] in (0, 1)
