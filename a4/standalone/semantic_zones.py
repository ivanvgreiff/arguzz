"""
Semantic zones for the (mutation_kind, semantic_zone) arm space.

Defines 19 semantic zones (Pro §7.A base 17 + D50 `core_shr` + D54
`kernel_other`). Classification logic lives in `zone_classifier.py`.
"""

from typing import FrozenSet, Tuple

# D54 / GLOSSARY § User vs kernel PC ranges
KERNEL_PC_RANGE: Tuple[int, int] = (0xC0000000, 0xC1000000)
USER_PC_RANGE: Tuple[int, int] = (0x00200000, 0x00400000)

# D50: major=4 minor split (DIV0 circuit table)
CORE_SHR_MINORS: FrozenSet[int] = frozenset({0, 1, 2, 3})   # SRL/SRA/SRLI/SRAI
CORE_DIV_MINORS: FrozenSet[int] = frozenset({4, 5, 6, 7})   # DIV/DIVU/REM/REMU

SEMANTIC_ZONES: Tuple[str, ...] = (
    "step0",
    "last_step",
    "pre_ecall",
    "post_ecall",
    "pre_mret",
    "post_mret",
    "pre_halt",
    "post_halt",
    "core_arithmetic",
    "core_memory_load",
    "core_memory_store",
    "core_branch",
    "core_mul",
    "core_div",
    "core_shr",
    "core_sha",
    "core_poseidon",
    "core_other",
    "kernel_other",
)

SINGLETON_ZONES: FrozenSet[str] = frozenset({"step0", "last_step"})

BOUNDARY_ZONES: FrozenSet[str] = frozenset({
    "step0",
    "last_step",
    "pre_ecall",
    "post_ecall",
    "pre_mret",
    "post_mret",
    "pre_halt",
    "post_halt",
})

CORE_ZONES: FrozenSet[str] = frozenset(SEMANTIC_ZONES) - BOUNDARY_ZONES

MAJOR_TO_CORE_ZONE: dict = {
    0: "core_arithmetic",
    1: "core_arithmetic",
    2: "core_arithmetic",
    3: "core_mul",
    4: "core_div",
    5: "core_memory_load",
    6: "core_memory_store",
    7: "core_branch",
    8: "core_other",
    9: "core_poseidon",
    10: "core_poseidon",
    11: "core_sha",
    12: "core_other",
}


def major_minor_to_core_zone(major: int, minor: int) -> str:
    """D50-aware core zone for a Decode cycle (major, minor)."""
    if major == 4:
        if minor in CORE_SHR_MINORS:
            return "core_shr"
        return "core_div"
    return MAJOR_TO_CORE_ZONE.get(major, "core_other")


def major_to_zone(major: int) -> str:
    """Major-only fallback (no minor). For major=4 defaults to core_div."""
    return MAJOR_TO_CORE_ZONE.get(major, "core_other")


OPCODE_CLASS_BY_MAJOR: dict = {
    0: "alu", 1: "alu", 2: "alu",
    3: "mul",
    4: "div",
    5: "mem",
    6: "mem",
    7: "branch_or_ctrl",
    8: "branch_or_ctrl",
    9: "poseidon",
    10: "poseidon",
    11: "sha",
    12: "other",
}


def major_to_opcode_class(major: int) -> str:
    return OPCODE_CLASS_BY_MAJOR.get(major, "other")


def is_valid_zone(zone: str) -> bool:
    return zone in SEMANTIC_ZONES


def pc_in_kernel(pc: int) -> bool:
    lo, hi = KERNEL_PC_RANGE
    return lo <= pc < hi


def pc_in_user(pc: int) -> bool:
    lo, hi = USER_PC_RANGE
    return lo <= pc < hi


assert len(SEMANTIC_ZONES) == 19, f"expected 19 zones, got {len(SEMANTIC_ZONES)}"
assert SINGLETON_ZONES.issubset(set(SEMANTIC_ZONES))
assert BOUNDARY_ZONES.issubset(set(SEMANTIC_ZONES))
assert BOUNDARY_ZONES | CORE_ZONES == set(SEMANTIC_ZONES)
assert BOUNDARY_ZONES & CORE_ZONES == set()
