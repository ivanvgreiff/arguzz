"""
Semantic zones for the (mutation_kind, semantic_zone) arm space.

This module defines the 17 semantic zones recommended by ChatGPT Pro in
`a4/docs/cloud1/ProG_Report_2.md` §7.A. The zones replace the geometric
"contiguous step bucket" abstraction used in the old `ArmUniverse` with
zones that correspond to semantically meaningful regions of the RISC Zero
execution trace (boundary cycles, ECALL/MRET transitions, opcode classes).

This module only defines the *enum*. The classification logic (which step
belongs to which zone) lives in `a4/standalone/zone_classifier.py`, the
`(kind, zone)` arm structure lives in `a4/standalone/semantic_arm_universe.py`,
and the step sampler lives in `a4/standalone/step_selector.py::SemanticZoneStepSelector`.

Decisions documented in `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` (D7):
all 17 zones are defined here; zones with zero valid steps for a given guest
are silently skipped at runtime by the arm universe builder.
"""

from typing import FrozenSet, Tuple

# =============================================================================
# The 17 semantic zones (verbatim from ProG_Report_2.md §7.A)
# =============================================================================

# Ordering is fixed and stable: it determines deterministic iteration order
# inside the arm universe and selector, and is referenced by DB string keys.
SEMANTIC_ZONES: Tuple[str, ...] = (
    # Boundary singletons (always size 1 if present)
    "step0",
    "last_step",
    # Boundary adjacency (size ≈ count of ECALL/MRET/halt cycles)
    "pre_ecall",
    "post_ecall",
    "pre_mret",
    "post_mret",
    "pre_halt",
    "post_halt",
    # Core opcode-class zones (size = remainder of the trace)
    "core_arithmetic",
    "core_memory_load",
    "core_memory_store",
    "core_branch",
    "core_mul",
    "core_div",
    "core_sha",
    "core_poseidon",
    "core_other",
)

# Singleton zones — guaranteed to be 1 step or empty.
# Pro §7.A: "INSTR_TYPE_MOD@step0 should be an explicit singleton arm with a
# guaranteed minimum pull count. Do not bury it inside bucket 0." We honor
# this by giving singleton arms a higher forced-pull floor in
# `ConstrainedTSScheduler` (cloud1 D10 explanation).
SINGLETON_ZONES: FrozenSet[str] = frozenset({"step0", "last_step"})

# Boundary zones — singletons + cycle-adjacency zones. These are the zones
# Pro identified as under-sampled by uniform-over-trace strategies. The
# coverage-floor in ConstrainedTSScheduler reserves explicit pulls here.
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

# Core zones — the non-boundary execution body. Most of the trace lives here.
CORE_ZONES: FrozenSet[str] = frozenset(SEMANTIC_ZONES) - BOUNDARY_ZONES

# =============================================================================
# Major opcode class → zone mapping
# =============================================================================
#
# `major` is the rv32im circuit's opcode-class column. The authoritative
# mapping comes from `a4/core/inspection_data.py::summary()` line 224-228:
#
#   0/1/2  → MISC0/1/2  (ALU: ADD/SUB/AND/OR/XOR/SLT/SLL/SRL/SRA, AUIPC, etc.)
#   3      → MUL0       (MUL family)
#   4      → DIV0       (DIV family)
#   5      → MEM0       (load: LW/LH/LB/LHU/LBU)
#   6      → MEM1       (store: SW/SH/SB)
#   7      → CONTROL0   (branches BEQ/BNE/BLT/BGE, JAL, JALR, MRET, etc.)
#   8      → ECALL0     (ECALL syscalls — boundary cycles!)
#   9      → POSEIDON0
#   10     → POSEIDON1
#   11     → SHA0       (SHA accelerator)
#   12     → BIGINT0    (no Pro zone for this; falls into core_other)
#
# This map is used by the zone classifier as a FALLBACK after boundary
# rules apply. ECALL cycles (major=8) should already be classified into
# pre_ecall by the boundary rule, so this map maps 8 → core_other for
# defensive fallback only.
MAJOR_TO_CORE_ZONE: dict = {
    0: "core_arithmetic",
    1: "core_arithmetic",
    2: "core_arithmetic",
    3: "core_mul",
    4: "core_div",
    5: "core_memory_load",
    6: "core_memory_store",
    7: "core_branch",
    8: "core_other",      # ECALL — should be caught by pre_ecall rule first
    9: "core_poseidon",
    10: "core_poseidon",
    11: "core_sha",
    12: "core_other",     # BIGINT — Pro did not list a core_bigint zone
}

# Reverse-derived opcode class label (used in StructuralCell).
# This is the "compressed" opcode-class enum referenced in Pro §5/§6.3.
# Valid values: alu | mul | div | mem | branch_or_ctrl | sha | poseidon | other
OPCODE_CLASS_BY_MAJOR: dict = {
    0: "alu", 1: "alu", 2: "alu",
    3: "mul",
    4: "div",
    5: "mem",
    6: "mem",
    7: "branch_or_ctrl",
    8: "branch_or_ctrl",   # ECALL is a control transition
    9: "poseidon",
    10: "poseidon",
    11: "sha",
    12: "other",           # BIGINT
}


def major_to_zone(major: int) -> str:
    """Return the core zone string for a given major value.

    Boundary zones are NOT returned by this function — boundary assignment
    happens in the zone classifier based on ECALL/MRET/halt adjacency and
    overrides whatever major-based zone the step would otherwise get.
    """
    return MAJOR_TO_CORE_ZONE.get(major, "core_other")


def major_to_opcode_class(major: int) -> str:
    """Return the compressed opcode-class label for a given major value."""
    return OPCODE_CLASS_BY_MAJOR.get(major, "other")


def is_valid_zone(zone: str) -> bool:
    """True if `zone` is one of the 17 defined semantic zones."""
    return zone in SEMANTIC_ZONES


# =============================================================================
# Sanity check (run at import time in __main__)
# =============================================================================

# Invariants:
# - 17 zones total
# - all SINGLETON_ZONES are in SEMANTIC_ZONES
# - BOUNDARY_ZONES and CORE_ZONES partition SEMANTIC_ZONES
assert len(SEMANTIC_ZONES) == 17, f"expected 17 zones, got {len(SEMANTIC_ZONES)}"
assert SINGLETON_ZONES.issubset(set(SEMANTIC_ZONES))
assert BOUNDARY_ZONES.issubset(set(SEMANTIC_ZONES))
assert BOUNDARY_ZONES | CORE_ZONES == set(SEMANTIC_ZONES)
assert BOUNDARY_ZONES & CORE_ZONES == set()
