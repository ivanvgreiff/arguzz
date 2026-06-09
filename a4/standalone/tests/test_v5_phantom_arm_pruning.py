"""Phase 7 Bug A — drop phantom (kind, zone) arms from semantic universe."""

from __future__ import annotations

from pathlib import Path

import pytest

from a4.core.inspection_data import InspectionData
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.semantic_arm_universe import (
    SemanticArmUniverse,
    _PHANTOM_ARMS_PRODUCTION_TRACE,
)

HOST = Path("workspace/output/target/release/risc0-host")
HOST_ARGS = ["--in1", "5", "--in4", "10"]
# 53 coarse arms − 5 full phantoms + MEM_VAL|core_div kept (1 real step at 3921)
PRODUCTION_ARM_COUNT = 48


@pytest.fixture(scope="module")
def production_data() -> InspectionData:
    if not HOST.is_file():
        pytest.skip("risc0-host not built — skip production-trace test")
    return InspectionData.from_inspection(str(HOST), HOST_ARGS)


@pytest.fixture(scope="module")
def production_universe(production_data) -> SemanticArmUniverse:
    kinds = A4Fuzzer.MUTATION_KINDS
    return SemanticArmUniverse.build(production_data, kinds)


def test_phantom_arms_absent(production_universe):
    for arm in _PHANTOM_ARMS_PRODUCTION_TRACE:
        assert arm not in production_universe.arms, f"phantom arm still present: {arm}"


def test_production_arm_count_is_48(production_universe):
    assert production_universe.num_arms == PRODUCTION_ARM_COUNT


def test_mem_val_core_div_step_list_pruned(production_universe):
    """MEM_VAL_MOD|core_div: only step 3921 has a real target (not all 23)."""
    steps = production_universe.steps_in_arm("MEM_VAL_MOD", "core_div")
    assert steps == [3921]
