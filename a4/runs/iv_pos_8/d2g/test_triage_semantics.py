#!/usr/bin/env python3
"""Offline tests for §3.1 semantics-aware triage (no binary)."""
from __future__ import annotations

from a4.arguzz_dependent.arguzz_parser import ArguzzTrace
from a4.runs.iv_pos_8.d2g.propagation_triage import (
    EVIDENCE_COSMETIC,
    EVIDENCE_NONE,
    EVIDENCE_WEAK,
    TRIAGE_NOOP,
    TRIAGE_PROPAGATED,
    classify_semantics,
)


def _trace(step: int, pc: int, instr: str, asm: str) -> ArguzzTrace:
    return ArguzzTrace(step=step, pc=pc, instruction=instr, assembly=asm)


def test_identical_trace_is_noop():
    base = [_trace(10, 100, "Lw", "lw a0, 0(sp)"), _trace(11, 104, "AddI", "addi a0, a0, 1")]
    r = classify_semantics(base, list(base), 10, faults=[])
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
    r = classify_semantics(base, fault, 10, faults=[])
    assert r.klass == TRIAGE_NOOP
    assert r.evidence == EVIDENCE_COSMETIC


def test_store_offset_change_weak_propagated():
    base = [
        _trace(10, 100, "Sw", "sw t2, 4(t1)"),
        _trace(11, 104, "Lw", "lw t2, 8(t0)"),
    ]
    fault = [
        _trace(10, 100, "Sw", "sw t2, 6(t1)"),
        _trace(11, 104, "Lw", "lw t2, 8(t0)"),
    ]
    r = classify_semantics(base, fault, 10, faults=[])
    assert r.klass == TRIAGE_PROPAGATED
    assert r.evidence == EVIDENCE_WEAK
    assert r.unaligned_access is True


def test_post_inject_pc_change_strong():
    base = [_trace(10, 100, "Beq", "beq a0, zero, 8"), _trace(11, 104, "Lw", "lw a0, 0(sp)")]
    fault = [_trace(10, 100, "Beq", "beq a0, zero, 8"), _trace(11, 200, "Lw", "lw a0, 0(sp)")]
    r = classify_semantics(base, fault, 10, faults=[])
    assert r.klass == TRIAGE_PROPAGATED
    assert r.evidence == "strong"
