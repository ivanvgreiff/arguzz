#!/usr/bin/env python3
"""Offline tests for §3.1 semantics-aware triage (no binary)."""
from __future__ import annotations

from a4.arguzz_dependent.arguzz_parser import ArguzzTrace
from a4.runs.iv_pos_8.d2g.propagation_triage import (
    EVIDENCE_COSMETIC,
    EVIDENCE_NONE,
    EVIDENCE_WEAK,
    EVIDENCE_WORD_TRUNCATED,
    TRIAGE_NOOP,
    TRIAGE_PROPAGATED,
    classify_semantics,
)

# These exercise the INSTR_WORD_MOD (disasm-bearing) path; the value-mutating-kind
# and spurious-identity paths live in test_propagation_triage_unit.py (F24).
IWM = "INSTR_WORD_MOD"


def _trace(step: int, pc: int, instr: str, asm: str) -> ArguzzTrace:
    return ArguzzTrace(step=step, pc=pc, instruction=instr, assembly=asm)


def test_identical_trace_is_noop():
    base = [_trace(10, 100, "Lw", "lw a0, 0(sp)"), _trace(11, 104, "AddI", "addi a0, a0, 1")]
    r = classify_semantics(base, list(base), 10, faults=[], kind=IWM)
    assert r.klass == TRIAGE_NOOP
    assert r.evidence == EVIDENCE_NONE


def test_branch_target_change_cosmetic_noop():
    base = [
        _trace(10, 100, "Beq", "beq a0, zero, 72"),
        _trace(11, 104, "Lw", "lw a0, 0(sp)"),
    ]
    fault = [
        _trace(10, 100, "Beq", "beq a0, zero, 104"),
        _trace(11, 104, "Lw", "lw a0, 0(sp)"),
    ]
    r = classify_semantics(base, fault, 10, faults=[], kind=IWM)
    assert r.klass == TRIAGE_NOOP
    assert r.evidence == EVIDENCE_COSMETIC


def test_full_word_store_within_word_is_word_truncated():
    # F22/F23: a FULL-WORD sw with a within-word offset change (4->6, both >>2 == 1)
    # writes the identical word -> provable no-op (was wrongly `weak` under F21).
    base = [
        _trace(10, 100, "Sw", "sw t2, 4(t1)"),
        _trace(11, 104, "Lw", "lw t2, 8(t0)"),
    ]
    fault = [
        _trace(10, 100, "Sw", "sw t2, 6(t1)"),
        _trace(11, 104, "Lw", "lw t2, 8(t0)"),
    ]
    r = classify_semantics(base, fault, 10, faults=[], kind=IWM)
    assert r.klass == TRIAGE_NOOP
    assert r.evidence == EVIDENCE_WORD_TRUNCATED
    assert r.unaligned_access is True  # offset 6 still flagged for D3


def test_post_inject_pc_change_strong():
    base = [_trace(10, 100, "Beq", "beq a0, zero, 8"), _trace(11, 104, "Lw", "lw a0, 0(sp)")]
    fault = [_trace(10, 100, "Beq", "beq a0, zero, 8"), _trace(11, 200, "Lw", "lw a0, 0(sp)")]
    r = classify_semantics(base, fault, 10, faults=[], kind=IWM)
    assert r.klass == TRIAGE_PROPAGATED
    assert r.evidence == "strong"
