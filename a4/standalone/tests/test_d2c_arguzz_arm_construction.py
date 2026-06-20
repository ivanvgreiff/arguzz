#!/usr/bin/env python3
"""D2.C Batch 2 — Layer 4 Arguzz arm-construction (synthetic InspectionData)."""

from __future__ import annotations

from typing import Dict, List

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.mutations.arguzz_bridge import (
    MAPPING_INSTR_TO_OPCODE_CLASS,
    MUTATION_KINDS_ARGUZZ_FULL,
    MUTATION_KINDS_ARGUZZ_SELECTED,
    _PRE_POST_BY_KIND,
)
from a4.standalone.semantic_arm_universe import (
    ARGUZZ_EXEC_FAULT,
    A4_TRACE_CELL,
    SemanticArmUniverse,
)


def _synthetic_data_and_trace() -> tuple[InspectionData, Dict[int, str]]:
    """Trace with branch, ALU, load, store, jump, and ecall steps."""
    baseline_trace = {
        0: "add",
        1: "beq",
        2: "lw",
        3: "sw",
        4: "jal",
        5: "eany",
    }
    majors = [0, 7, 5, 6, 7, 8]
    cycles: List[A4CycleInfo] = []
    for step, instr in baseline_trace.items():
        cycles.append(
            A4CycleInfo(
                cycle_idx=step,
                step=step,
                pc=0x00200000 + step * 4,
                txn_idx=step,
                major=majors[step],
                minor=0,
                state=48,
                diff_count_0=1,
                diff_count_1=2,
            )
        )
    txns = [
        A4AllTxn(
            txn_idx=10, step=2, txn_type="mem", addr=0x20000,
            cycle=0, word=1, prev_cycle=0, prev_word=0,
        ),
        A4AllTxn(
            txn_idx=11, step=3, txn_type="mem", addr=0x20004,
            cycle=0, word=2, prev_cycle=0, prev_word=0,
        ),
    ]
    data = InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)
    return data, baseline_trace


KIND_LISTS = [
    pytest.param(MUTATION_KINDS_ARGUZZ_FULL, id="FULL"),
    pytest.param(MUTATION_KINDS_ARGUZZ_SELECTED, id="SELECTED"),
]


@pytest.fixture(scope="module")
def synth() -> tuple[InspectionData, Dict[int, str]]:
    return _synthetic_data_and_trace()


class TestArguzzArmConstruction:
    @pytest.mark.parametrize("kind_list", KIND_LISTS)
    def test_each_kind_emits_at_least_one_arm(self, synth, kind_list):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data, [], arguzz_kinds=list(kind_list), baseline_trace=baseline_trace,
        )
        for kind in kind_list:
            arms_for_kind = [a for a in uni.arms if a.kind == kind]
            assert arms_for_kind, f"no arms for {kind}"

    @pytest.mark.parametrize("kind_list", KIND_LISTS)
    def test_pre_post_matches_by_kind(self, synth, kind_list):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data, [], arguzz_kinds=list(kind_list), baseline_trace=baseline_trace,
        )
        for arm in uni.arms:
            if arm.surface != ARGUZZ_EXEC_FAULT:
                continue
            assert arm.pre_post == _PRE_POST_BY_KIND[arm.kind]

    @pytest.mark.parametrize("kind_list", KIND_LISTS)
    def test_opcode_classes_match_mapping(self, synth, kind_list):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data, [], arguzz_kinds=list(kind_list), baseline_trace=baseline_trace,
        )
        for arm, steps in uni.arms.items():
            if arm.surface != ARGUZZ_EXEC_FAULT:
                continue
            for step in steps:
                instr = baseline_trace[step].lower()
                expected = MAPPING_INSTR_TO_OPCODE_CLASS[instr]
                assert arm.opcode_class == expected

    def test_class_restricted_kinds_only_on_applicable_steps(self, synth):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data,
            [],
            arguzz_kinds=list(MUTATION_KINDS_ARGUZZ_FULL),
            baseline_trace=baseline_trace,
        )
        br_steps = set()
        for arm, steps in uni.arms.items():
            if arm.kind == "BR_NEG_COND":
                br_steps.update(steps)
        assert br_steps == {1}

        load_steps = set()
        for arm, steps in uni.arms.items():
            if arm.kind == "LOAD_VAL_MOD":
                load_steps.update(steps)
        assert load_steps == {2}

    def test_default_build_emits_no_arguzz_arms(self, synth):
        data, _ = synth
        uni = SemanticArmUniverse.build(data, ["COMP_OUT_MOD"])
        assert all(a.surface == A4_TRACE_CELL for a in uni.arms)

    def test_missing_baseline_trace_raises(self, synth):
        data, _ = synth
        with pytest.raises(ValueError, match="baseline_trace required"):
            SemanticArmUniverse.build(
                data, [], arguzz_kinds=list(MUTATION_KINDS_ARGUZZ_SELECTED),
            )

    def test_ecall_mret_distinct_from_system(self, synth):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data, [], arguzz_kinds=["INSTR_WORD_MOD"], baseline_trace=baseline_trace,
        )
        ecall_arms = [
            a for a in uni.arms
            if a.opcode_class == "ecall_mret"
        ]
        assert ecall_arms, "expected ecall_mret arm at step 5"

    @pytest.mark.parametrize("kind_list", KIND_LISTS)
    def test_arm_count_in_predicted_band(self, synth, kind_list):
        data, baseline_trace = synth
        uni = SemanticArmUniverse.build(
            data, [], arguzz_kinds=list(kind_list), baseline_trace=baseline_trace,
        )
        arguzz_count = sum(
            1 for a in uni.arms if a.surface == ARGUZZ_EXEC_FAULT
        )
        if len(kind_list) == len(MUTATION_KINDS_ARGUZZ_SELECTED):
            assert 1 <= arguzz_count <= 160
        else:
            assert 1 <= arguzz_count <= 350
