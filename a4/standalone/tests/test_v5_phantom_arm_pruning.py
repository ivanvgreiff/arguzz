"""Phase 7 Bug A — drop phantom (kind, zone) arms from semantic universe."""

from __future__ import annotations

from pathlib import Path

import pytest

from a4.core.inspection_data import InspectionData
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.semantic_arm_universe import SemanticArmUniverse

HOST = Path("workspace/output/target/release/risc0-host")
HOST_ARGS = ["--in1", "5", "--in4", "10"]
# 48 arms after Phase 7 Bug A phantom pruning; D40 (Inc 0) may drop ≤4 more.
PRODUCTION_ARM_COUNT_MIN = 44
PRODUCTION_ARM_COUNT_MAX = 48


@pytest.fixture(scope="module")
def production_data() -> InspectionData:
    if not HOST.is_file():
        pytest.skip("risc0-host not built — skip production-trace test")
    return InspectionData.from_inspection(str(HOST), HOST_ARGS)


@pytest.fixture(scope="module")
def production_universe(production_data) -> SemanticArmUniverse:
    kinds = A4Fuzzer.MUTATION_KINDS
    return SemanticArmUniverse.build(production_data, kinds)


def test_production_arm_count_in_d40_range(production_universe):
    n = production_universe.num_arms
    assert PRODUCTION_ARM_COUNT_MIN <= n <= PRODUCTION_ARM_COUNT_MAX, (
        f"expected {PRODUCTION_ARM_COUNT_MIN}–{PRODUCTION_ARM_COUNT_MAX} arms, got {n}"
    )


def test_mem_val_kernel_other_has_targets(production_universe):
    """D54: step 3921 (halt cleanup) is kernel_other, not core_div."""
    steps = production_universe.steps_in_arm("MEM_VAL_MOD", "kernel_other")
    assert 3921 in steps
    assert production_universe.steps_in_arm("MEM_VAL_MOD", "core_div") == []
