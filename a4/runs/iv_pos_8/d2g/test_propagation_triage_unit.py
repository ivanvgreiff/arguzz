#!/usr/bin/env python3
"""Unit tests for the fault-value-aware + kind-aware triage rule (F21/F22/F23/F24).

These run WITHOUT the real binary — they drive `classify_semantics` directly with
synthetic traces + faults. The smoke oracle is all INSTR_WORD_MOD, so these are the
only coverage of the value-mutating-kind path (F24) and the sub-word width guard (F23).
"""
from __future__ import annotations

from a4.arguzz_dependent.arguzz_parser import ArguzzFault, ArguzzTrace
from a4.runs.iv_pos_8.d2g.propagation_triage import (
    EVIDENCE_CF_INERT,
    EVIDENCE_COSMETIC,
    EVIDENCE_IDENTITY,
    EVIDENCE_NONE,
    EVIDENCE_STRONG,
    EVIDENCE_WEAK,
    EVIDENCE_WORD_TRUNCATED,
    TRIAGE_NOOP,
    TRIAGE_PROPAGATED,
    classify_semantics,
)

STEP = 10


def _tr(step, pc, instr, asm):
    return ArguzzTrace(step=step, pc=pc, instruction=instr, assembly=asm)


def _tail():
    # identical post-inject records (steps > STEP) => no control-flow divergence
    return [_tr(11, 0x44, "Addi", "addi a0, a0, 1"), _tr(12, 0x48, "Sw", "sw a0, 0(sp)")]


def _fault(kind, info_type, x, y, reg=None):
    return ArguzzFault(
        step=STEP, pc=0x40, kind=kind, info_type=info_type,
        original_value=x, mutated_value=y, target_register=reg,
    )


def _classify(base_inj, fault_inj, faults, kind, *, diverge=False):
    baseline = [base_inj] + _tail()
    tail = _tail()
    if diverge:
        tail = [_tr(11, 0x99, "Jal", "jal x0, 0x99")]  # different post-inject PC seq
    fault = [fault_inj] + tail
    return classify_semantics(baseline, fault, STEP, faults=faults, kind=kind)


# --- F24: value-mutating kinds (no disasm change) ---------------------------------

def test_comp_out_identity_is_noop():
    base = _tr(STEP, 0x40, "Add", "add t0, t1, t2")
    r = _classify(base, base, [_fault("COMP_OUT_MOD", "out", 5, 5)], "COMP_OUT_MOD")
    assert r.klass == TRIAGE_NOOP and r.evidence == EVIDENCE_IDENTITY


def test_comp_out_value_change_is_weak():
    base = _tr(STEP, 0x40, "Add", "add t0, t1, t2")
    r = _classify(base, base, [_fault("COMP_OUT_MOD", "out", 5, 9)], "COMP_OUT_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_store_out_value_change_is_weak():
    base = _tr(STEP, 0x40, "Sw", "sw t0, 0(sp)")
    r = _classify(base, base, [_fault("STORE_OUT_MOD", "data", 1, 2)], "STORE_OUT_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_load_val_change_reaching_control_flow_is_strong():
    base = _tr(STEP, 0x40, "Lw", "lw t0, 0(sp)")
    r = _classify(base, base, [_fault("LOAD_VAL_MOD", "out", 1, 2)], "LOAD_VAL_MOD",
                  diverge=True)
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_STRONG


# --- F24 pushback: spurious-identity guard for non-genuine-pair kinds --------------

def test_br_neg_cond_spurious_identity_not_noop():
    # BR_NEG_COND parses to info_type='unknown' 0=>0; must NOT be called identity.
    base = _tr(STEP, 0x40, "Beq", "beq t0, t1, 0x60")
    r = _classify(base, base, [_fault("BR_NEG_COND", "unknown", 0, 0)], "BR_NEG_COND")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_br_neg_cond_with_divergence_is_strong():
    base = _tr(STEP, 0x40, "Beq", "beq t0, t1, 0x60")
    r = _classify(base, base, [_fault("BR_NEG_COND", "unknown", 0, 0)], "BR_NEG_COND",
                  diverge=True)
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_STRONG


def test_reg_mod_zero_value_not_noop():
    # REG_MOD parser hardcodes original_value=0; writing 0 yields a spurious 0=>0.
    base = _tr(STEP, 0x40, "Add", "add t0, t1, t2")
    r = _classify(base, base,
                  [_fault("POST_EXEC_REG_MOD", "reg_assign", 0, 0, reg="t0")],
                  "POST_EXEC_REG_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_mem_mod_is_weak():
    base = _tr(STEP, 0x40, "Add", "add t0, t1, t2")
    r = _classify(base, base,
                  [_fault("PRE_EXEC_MEM_MOD", "mem_assign", 0x13946509, 789)],
                  "PRE_EXEC_MEM_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


# --- F23: INSTR_WORD_MOD width-aware store/load ------------------------------------

def test_full_word_within_word_is_word_truncated():
    base = _tr(STEP, 0x40, "Sw", "sw t2, 4(t1)")
    flt = _tr(STEP, 0x40, "Sw", "sw t2, 6(t1)")  # 4>>2 == 6>>2 == 1, same word
    r = _classify(base, flt, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_NOOP and r.evidence == EVIDENCE_WORD_TRUNCATED


def test_sub_word_within_word_is_weak():
    base = _tr(STEP, 0x40, "Sb", "sb t2, 4(t1)")
    flt = _tr(STEP, 0x40, "Sb", "sb t2, 6(t1)")  # same word, but lane 0 -> lane 2
    r = _classify(base, flt, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_full_word_cross_word_is_weak():
    base = _tr(STEP, 0x40, "Sw", "sw t2, 4(t1)")
    flt = _tr(STEP, 0x40, "Sw", "sw t2, 8(t1)")  # 4>>2=1 != 8>>2=2, crosses word
    r = _classify(base, flt, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_full_word_unaligned_base_is_weak():
    # F25: off>>2 equal (0==0) but b_off % 4 == 2 -> base is unaligned, so the two offsets
    # can land in different words once rs1's low bits carry. Must NOT be word_truncated.
    base = _tr(STEP, 0x40, "Sw", "sw t2, 2(t1)")  # 2>>2 == 0
    flt = _tr(STEP, 0x40, "Sw", "sw t2, 0(t1)")   # 0>>2 == 0, but b_off%4==2 (unaligned base)
    r = _classify(base, flt, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_instr_word_byte_identical_disasm_is_noop():
    base = _tr(STEP, 0x40, "Add", "add t0, t1, t2")
    r = _classify(base, base, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_NOOP and r.evidence == EVIDENCE_NONE


def test_not_taken_branch_target_is_cosmetic():
    base = _tr(STEP, 0x40, "Beq", "beq t0, t1, 0x60")
    flt = _tr(STEP, 0x40, "Beq", "beq t0, t1, 0x80")  # target changed, branch not taken
    r = _classify(base, flt, [_fault("INSTR_WORD_MOD", "word", 100, 356)], "INSTR_WORD_MOD")
    assert r.klass == TRIAGE_NOOP and r.evidence == EVIDENCE_COSMETIC


# --- F27: POST_EXEC_PC_MOD control-flow-inert (no PC-provenance constraint, INV1 §2c) ----

def test_post_exec_pc_mod_no_divergence_is_cf_inert():
    # +4-on-sequential: PC overwritten with the value the executor already committed -> the
    # post-inject pc stream is identical -> provably inert (INV1 §2c, INV2 30/30).
    base = _tr(STEP, 0x40, "Addi", "addi a0, a0, 1")
    r = _classify(base, base, [_fault("POST_EXEC_PC_MOD", "pc", 0x40, 0x44)], "POST_EXEC_PC_MOD")
    assert r.klass == TRIAGE_NOOP and r.evidence == EVIDENCE_CF_INERT


def test_post_exec_pc_mod_divergence_is_strong():
    # A non-+4 jump that changes the post-inject pc sequence -> caught by STRONG (rule 1), never noop.
    base = _tr(STEP, 0x40, "Addi", "addi a0, a0, 1")
    r = _classify(base, base, [_fault("POST_EXEC_PC_MOD", "pc", 0x40, 0x400)],
                  "POST_EXEC_PC_MOD", diverge=True)
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_STRONG


def test_post_exec_pc_mod_last_step_is_weak():
    # GUARD: empty post-inject window (mutation on the last step) -> cannot confirm convergence
    # from the step trace (the only effect would be the final committed pc) -> fail safe to weak.
    base = [_tr(STEP, 0x40, "Addi", "addi a0, a0, 1")]   # no records with step > STEP
    fault = [_tr(STEP, 0x40, "Addi", "addi a0, a0, 1")]
    r = classify_semantics(base, fault, STEP,
                           faults=[_fault("POST_EXEC_PC_MOD", "pc", 0x40, 0x44)],
                           kind="POST_EXEC_PC_MOD")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK


def test_br_neg_cond_no_divergence_stays_weak_not_cf_inert():
    # F27 is scoped to POST_EXEC_PC_MOD ONLY (circuit-audited). BR_NEG_COND is NOT in the set —
    # its no-divergence inertness is reasoned, not audited, so it must stay at the weak fail-safe.
    base = _tr(STEP, 0x40, "Beq", "beq t0, t1, 0x60")
    r = _classify(base, base, [_fault("BR_NEG_COND", "unknown", 0, 0)], "BR_NEG_COND")
    assert r.klass == TRIAGE_PROPAGATED and r.evidence == EVIDENCE_WEAK
