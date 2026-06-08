#!/usr/bin/env python3
"""
Adversarial / skeptical-review tests for cloud1 Phase 4 reward_v2.

Written by Opus during the Phase 4 review of Composer's implementation.
Target areas (per Composer's review pointer):
  1. malformed constraint_loc family parse
  2. repeat on zero-failure runs
  3. counterfactual consistency

These tests do NOT replace Composer's `test_reward_v2.py`. They add
coverage that Composer's tests do not exercise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.standalone.reward_v2 import (
    sat,
    compute_reward_v2,
    compute_bandit_success,
    extract_constraint_family,
    compute_reward_v2_components,
    compute_counterfactuals,
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


def _fail(name="MemLoadInput", zir="inst_mem.zir", line=8, major=5, minor=4):
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc=f"{name}(zirgen/circuit/rv32im/v2/dsl/{zir}:{line})",
        value=1,
    )


# ---------------------------------------------------------------------------
# 1. MALFORMED constraint_loc family parse
# ---------------------------------------------------------------------------

class TestMalformedFamilyParse:
    """Composer's `@…\\.zir` regex must degrade gracefully on weird inputs."""

    def test_at_zir_with_empty_filename_falls_back_to_prefix(self):
        # "X@.zir:1" → regex requires ≥1 char (`[^@]+?` = 1+), so it does
        # NOT match. Fallback path strips the suffix and returns prefix "X".
        # This is the safer behavior — empty family would have been bad.
        assert extract_constraint_family("X@.zir:1") == "X"

    def test_nested_path_in_filename(self):
        # Pro examples are flat "inst_mem.zir"; verify nested paths
        # (which DO appear in `constraint_parser` short_loc patterns 1-2)
        # also parse cleanly.
        result = extract_constraint_family(
            "MemLoad(zirgen/circuit/rv32im/v2/dsl/inst_mem.zir:8)")
        # No @ in this form → fallback to full stripped string
        # (this is the long-form loc; Pro families assume short_loc was called)
        assert result == "MemLoad(zirgen/circuit/rv32im/v2/dsl/inst_mem.zir:8)"

    def test_double_at_picks_segment_containing_dot_zir(self):
        # Regex `@([^@]+?)\.zir` skips segments without `.zir`. Here, only
        # "inst" is followed by ".zir", so it wins. Documents that the parser
        # picks the *file-bearing* @-segment, not the first one.
        # Real short_loc patterns only ever emit one @, so this branch is
        # belt-and-suspenders.
        assert extract_constraint_family("Outer@Inner@inst.zir:1") == "inst"

    def test_double_zir_takes_first(self):
        # Two .zir in the path — non-greedy picks first
        result = extract_constraint_family("X@a.zir.zir:1")
        assert result == "a"

    def test_inst_ecall_multi_underscore(self):
        # Composer's open question 1 — verify their parser handles
        # multi-underscore names correctly.
        assert extract_constraint_family(
            "ECallHostReadSetup@inst_ecall.zir:70") == "inst_ecall"
        assert extract_constraint_family(
            "BigInt2Step@inst_bigint2.zir:5") == "inst_bigint2"

    def test_path_with_hex_address_in_filename(self):
        # Strange but possible from constraint debug strings
        assert extract_constraint_family("X@0x80001000.zir:1") == "0x80001000"

    def test_only_at_no_dot_zir(self):
        # Falls back to prefix-before-@
        assert extract_constraint_family("Foo@somewhere/else:1") == "Foo"

    def test_only_dot_zir_no_at(self):
        # Falls back to full stripped string (no @ present)
        assert extract_constraint_family("file.zir:1") == "file.zir:1"

    def test_whitespace_only(self):
        # Strips to empty → returns the stripped form
        assert extract_constraint_family("   ").strip() == ""

    def test_unicode_in_filename(self):
        # Defensive: ensure no encoding crash
        assert extract_constraint_family("Foo@bär.zir:1") == "bär"


# ---------------------------------------------------------------------------
# 2. REPEAT on zero-failure runs
# ---------------------------------------------------------------------------

class TestRepeatOnZeroFailureRuns:
    """A mutation that produces NO constraint failures must have repeat=0,
    regardless of how much history is in seen_local_v2."""

    def test_empty_failures_repeat_is_zero_with_empty_history(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        comp = compute_reward_v2_components(
            StubExecResult(failures=[]),
            seen_local, set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["repeat"] == 0
        assert comp["l_new"] == 0
        assert comp["f_new"] == 0

    def test_empty_failures_repeat_is_zero_with_large_history(self):
        # Even with 1000 prior contexts, no failures => no repeats.
        seen_local: Set[Tuple[str, int, int]] = {
            (f"A@x.zir:{i}", 5, 4) for i in range(1000)
        }
        comp = compute_reward_v2_components(
            StubExecResult(failures=[]),
            seen_local, set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["repeat"] == 0

    def test_partial_overlap_only_counts_overlap(self):
        # 3 failures: 2 already seen, 1 new. Use short_loc keys (real path).
        f1 = _fail(name="A", zir="inst_mem.zir", line=1, major=5, minor=4)
        f2 = _fail(name="B", zir="mem.zir", line=2, major=5, minor=0)
        f3 = _fail(name="C", zir="inst.zir", line=3, major=2, minor=0)
        seen_local: Set[Tuple[str, int, int]] = {
            (f1.constraint_loc(), f1.major, f1.minor),
            (f2.constraint_loc(), f2.major, f2.minor),
        }
        comp = compute_reward_v2_components(
            StubExecResult(failures=[f1, f2, f3]),
            seen_local, set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["repeat"] == 2
        assert comp["l_new"] == 1

    def test_duplicate_failures_same_context_repeat_counts_once(self):
        # Pro §8 says "number of already-seen local CONTEXTS hit again" —
        # SET semantics, not per-failure instance count.
        # IMPORTANT: keys use f.constraint_loc() = short_loc() form, NOT
        # the raw long-form `loc`. Seed seen_local accordingly.
        f = _fail()
        short_key = (f.constraint_loc(), f.major, f.minor)
        seen_local: Set[Tuple[str, int, int]] = {short_key}
        comp = compute_reward_v2_components(
            StubExecResult(failures=[f, f, f, f, f]),  # 5 instances, 1 context
            seen_local, set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        # Set semantics: 5 dup instances of the same context = repeat=1
        assert comp["repeat"] == 1
        assert comp["l_new"] == 0

    def test_crash_with_zero_failures_still_zero_repeat(self):
        # Crash mode shouldn't generate spurious repeats.
        comp = compute_reward_v2_components(
            StubExecResult(failures=[], exit_code=139),
            set(), set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert comp["crash"] is True
        assert comp["repeat"] == 0


# ---------------------------------------------------------------------------
# 3. COUNTERFACTUAL consistency
# ---------------------------------------------------------------------------

class TestCounterfactualConsistency:
    """current_reward in counterfactuals MUST equal compute_reward_v2(*components)
    exactly, for any component combination."""

    @pytest.mark.parametrize("l_new,f_new,g_new,s_new,crash,repeat", [
        (0, 0, 0, 0, False, 0),
        (1, 0, 0, 0, False, 0),
        (0, 1, 0, 0, False, 0),
        (0, 0, 1, 0, False, 0),
        (0, 0, 0, 1, False, 0),
        (10, 5, 3, 2, False, 0),
        (0, 0, 0, 0, True, 0),    # crash only
        (5, 5, 5, 5, True, 3),    # crash + everything
        (1, 0, 0, 0, False, 10),  # high repeat
        (100, 100, 100, 100, False, 100),  # saturated everywhere
    ])
    def test_current_reward_equals_compute_reward_v2(
        self, l_new, f_new, g_new, s_new, crash, repeat,
    ):
        comp = {
            "l_new": l_new, "f_new": f_new, "g_new": g_new, "s_new": s_new,
            "crash": crash, "repeat": repeat,
        }
        cf = compute_counterfactuals(
            comp,
            {"mode": "normal", "S": 0.5, "Q_rep": 1.0, "Q_glob": 1.0},
        )
        expected = compute_reward_v2(l_new, f_new, g_new, s_new, crash, repeat)
        assert cf["current_reward"] == pytest.approx(expected, abs=1e-12)

    def test_no_qloc_reward_never_exceeds_one(self):
        # Legacy r = min(1.0, Q * S) is clamped; counterfactual must respect.
        diag = {
            "mode": "normal", "S": 10.0, "Q_loc": 0.01,
            "Q_rep": 1.0, "Q_glob": 1.0,
        }
        cf = compute_counterfactuals(
            {"l_new": 0, "f_new": 0, "g_new": 0, "s_new": 0,
             "crash": False, "repeat": 0},
            diag,
        )
        assert cf["no_qloc_reward"] == pytest.approx(1.0)

    def test_no_qloc_with_low_q_components(self):
        # min(1.0, 0.3 * 0.4 * 0.5) = 0.06
        diag = {"mode": "normal", "S": 0.5, "Q_rep": 0.3, "Q_glob": 0.4}
        cf = compute_counterfactuals(
            {"l_new": 1, "f_new": 0, "g_new": 0, "s_new": 0,
             "crash": False, "repeat": 0},
            diag,
        )
        assert cf["no_qloc_reward"] == pytest.approx(0.06)

    def test_compressed_global_reward_independent_of_other_terms(self):
        # Should depend ONLY on g_new.
        for g in (0, 1, 3, 10, 100):
            cf = compute_counterfactuals(
                {"l_new": 99, "f_new": 99, "g_new": g, "s_new": 99,
                 "crash": True, "repeat": 99},
                {},
            )
            assert cf["compressed_global_reward"] == pytest.approx(
                0.25 * sat(float(g), 3.0))

    def test_fnew_only_reward_independent_of_other_terms(self):
        for f in (0, 1, 5, 100):
            cf = compute_counterfactuals(
                {"l_new": 0, "f_new": f, "g_new": 99, "s_new": 99,
                 "crash": True, "repeat": 99},
                {},
            )
            assert cf["fnew_only_reward"] == pytest.approx(
                0.30 * sat(float(f), 1.0))

    def test_discovery_binary_zero_when_only_f_new_or_repeat(self):
        # f_new alone should NOT flip discovery_binary (only l/g/s do).
        cf = compute_counterfactuals(
            {"l_new": 0, "f_new": 5, "g_new": 0, "s_new": 0,
             "crash": False, "repeat": 10},
            {},
        )
        assert cf["discovery_binary_reward"] == 0

    def test_counterfactual_with_missing_diag_fields(self):
        # Defensive: missing Q_rep / Q_glob / S in diag (Phase 6 not yet wired).
        cf = compute_counterfactuals(
            {"l_new": 1, "f_new": 0, "g_new": 0, "s_new": 0,
             "crash": False, "repeat": 0},
            {"mode": "normal"},  # no S, Q_rep, Q_glob
        )
        # no_qloc with all defaults: min(1, 1.0 * 1.0 * 0.0) = 0.0
        assert cf["no_qloc_reward"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# 4. STATEFUL invariants (side-effects on seen_* sets)
# ---------------------------------------------------------------------------

class TestStatefulInvariants:
    """Verify side-effects on seen_* sets are correct."""

    def test_seen_local_updated_after_call(self):
        seen_local: Set[Tuple[str, int, int]] = set()
        f = _fail()
        compute_reward_v2_components(
            StubExecResult(failures=[f]),
            seen_local, set(), set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        expected_key = (f.constraint_loc(), f.major, f.minor)
        assert expected_key in seen_local

    def test_second_call_no_double_count(self):
        # First call: l_new=1. Second call (same failure): l_new=0, repeat=1.
        seen_local: Set[Tuple[str, int, int]] = set()
        seen_struct: Set[StructuralCell] = set()
        f = _fail()
        c1 = compute_reward_v2_components(
            StubExecResult(failures=[f]),
            seen_local, set(), seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert c1["l_new"] == 1 and c1["repeat"] == 0
        c2 = compute_reward_v2_components(
            StubExecResult(failures=[f]),
            seen_local, set(), seen_struct,
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert c2["l_new"] == 0 and c2["repeat"] == 1
        # Structural cell already seen from c1
        assert c2["s_new"] == 0

    def test_seen_compressed_global_grows_monotonically(self):
        seen_global: Set[str] = set()
        exec_r = StubExecResult(
            failures=[],
            family_residues=[{"family": "memory", "nonzero": True}],
            family_details=[{"family": "memory", "broken_addrs": [0x80001000]}],
        )
        n_before = len(seen_global)
        compute_reward_v2_components(
            exec_r, set(), seen_global, set(),
            "INSTR_TYPE_MOD", "step0", 5,
        )
        assert len(seen_global) > n_before
