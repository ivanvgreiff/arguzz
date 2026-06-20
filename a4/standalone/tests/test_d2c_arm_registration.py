#!/usr/bin/env python3
"""D2.C Batch 4 — cross-cutting Arguzz arm registration (11 kinds × 6 layers)."""

from __future__ import annotations

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.mutations.arguzz_bridge import (
    ENABLED_KINDS,
    MAPPING_INSTR_TO_OPCODE_CLASS,
    MUTATION_KINDS_ARGUZZ_FULL,
    _PRE_POST_BY_KIND,
    get_valid_steps,
    opcode_class_for_step,
)
from a4.standalone.semantic_arm_universe import (
    ARGUZZ_EXEC_FAULT,
    ArmKey,
    SemanticArmUniverse,
)

KINDS = list(MUTATION_KINDS_ARGUZZ_FULL)


def _fixture_data_and_trace() -> tuple[InspectionData, dict[int, str]]:
    baseline_trace = {
        0: "add",
        1: "beq",
        2: "lw",
        3: "sw",
        4: "jal",
        5: "mul",
        6: "eany",
        7: "invalid",
    }
    cycles = [
        A4CycleInfo(
            cycle_idx=s, step=s, pc=0x200000 + s * 4, txn_idx=s,
            major=0 if s < 4 else 7, minor=0, state=48,
            diff_count_0=1, diff_count_1=2,
        )
        for s in baseline_trace
    ]
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[]), baseline_trace


@pytest.fixture(scope="module")
def registration_ctx():
    data, baseline_trace = _fixture_data_and_trace()
    universe = SemanticArmUniverse.build(
        data,
        ["INSTR_TYPE_MOD"],
        arguzz_kinds=list(MUTATION_KINDS_ARGUZZ_FULL),
        baseline_trace=baseline_trace,
    )
    return data, baseline_trace, universe


@pytest.mark.parametrize("kind", KINDS)
def test_kind_in_enabled_registry(kind: str):
    assert kind in ENABLED_KINDS
    assert kind in MUTATION_KINDS_ARGUZZ_FULL


@pytest.mark.parametrize("kind", KINDS)
def test_pre_post_registry_entry(kind: str):
    assert kind in _PRE_POST_BY_KIND
    assert _PRE_POST_BY_KIND[kind] in ("pre_exec", "post_exec")


@pytest.mark.parametrize("kind", KINDS)
def test_get_valid_steps_non_empty(kind: str, registration_ctx):
    data, baseline_trace, _ = registration_ctx
    steps = get_valid_steps(data, kind, baseline_trace=baseline_trace)
    assert len(steps) >= 1, f"{kind} has no valid steps on fixture trace"


@pytest.mark.parametrize("kind", KINDS)
def test_opcode_class_derivation(kind: str, registration_ctx):
    data, baseline_trace, _ = registration_ctx
    steps = get_valid_steps(data, kind, baseline_trace=baseline_trace)
    oc = opcode_class_for_step(steps[0], data, baseline_trace)
    assert oc in set(MAPPING_INSTR_TO_OPCODE_CLASS.values())


@pytest.mark.parametrize("kind", KINDS)
def test_semantic_arm_universe_entry(kind: str, registration_ctx):
    _, _, universe = registration_ctx
    matching = [a for a in universe.arms if a.kind == kind and a.surface == ARGUZZ_EXEC_FAULT]
    assert len(matching) >= 1, f"no Arguzz arm for {kind}"


@pytest.mark.parametrize("kind", KINDS)
def test_dispatch_arm_key_roundtrip(kind: str, registration_ctx):
    _, _, universe = registration_ctx
    arm = next(a for a in universe.arms if a.kind == kind and a.surface == ARGUZZ_EXEC_FAULT)
    parsed = ArmKey.parse(str(arm))
    assert parsed == arm
    assert parsed.surface == ARGUZZ_EXEC_FAULT
