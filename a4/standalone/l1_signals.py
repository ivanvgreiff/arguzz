"""D1.C / D2.D L1 bug-proximity signal extractors (observe-only logging substrate).

Definitions ported from ``a4/runs/iv_pos_7/analysis/bug_proximity.py`` — no
cross-tree import in production code. D1.E reuses this module for activation.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

# Empirically derived from 30-DB Cat-A corpus (bug_proximity.py).
KIND_TO_SUBSTRATEGY_FIELDS: dict[str, tuple[str, ...]] = {
    "COMP_OUT_MOD": ("value_class",),
    "INSTR_TYPE_MOD": (),
    "INSTR_WORD_MOD_FULL": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "INSTR_WORD_MOD_SUR": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "INSTR_WORD_MOD": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "LOAD_VAL_MOD": ("value_class",),
    "MEM_VAL_MOD": ("byte_lane", "bit_mask", "value_class"),
    "PRE_EXEC_REG_MOD": ("value_class",),
    "STORE_OUT_MOD": ("value_class",),
}

SUBSTRATEGY_EXCLUDED_KINDS: FrozenSet[str] = frozenset({"INSTR_TYPE_MOD"})


def composite_substrategy_key(
    kind: str,
    sub_dict: Dict[str, Any],
) -> tuple[Any, ...]:
    """Hashable composite key from kind-specific substrategy fields."""
    fields = KIND_TO_SUBSTRATEGY_FIELDS.get(kind)
    if fields is None:
        fields = tuple(k for k, v in sub_dict.items() if v is not None)
    return tuple(sub_dict.get(f) for f in fields)


def d_loc_le_2(d_loc: int) -> int:
    """1 iff mutation_rewards.d_loc <= 2."""
    return 1 if d_loc <= 2 else 0


def singleton_failure(failures: list) -> int:
    """1 iff exactly one constraint failure this pull."""
    return 1 if len(failures) == 1 else 0


def substrategy_uniqueness(
    kind: str,
    sub_dict: Dict[str, Any],
    seen: Set[Tuple[str, tuple[Any, ...]]],
    *,
    excluded_kinds: FrozenSet[str] = SUBSTRATEGY_EXCLUDED_KINDS,
) -> int:
    """1 iff first occurrence of (kind, composite_substrategy_key) this campaign."""
    if kind in excluded_kinds:
        return 0
    comp = composite_substrategy_key(kind, sub_dict)
    key = (kind, comp)
    if key in seen:
        return 0
    seen.add(key)
    return 1


def compute_l1_flags(
    *,
    d_loc: int,
    failures: list,
    kind: str,
    substrategy: Dict[str, Any],
    seen: Set[Tuple[str, tuple[Any, ...]]],
) -> dict[str, int]:
    """Return the three individual L1 flag columns."""
    return {
        "l1_d_loc_le_2": d_loc_le_2(d_loc),
        "l1_singleton_failure": singleton_failure(failures),
        "l1_substrategy_uniqueness": substrategy_uniqueness(
            kind, substrategy, seen,
        ),
    }


def bandit_success_l1_counterfactual(
    bandit_success: int,
    l1_flags: dict[str, int],
) -> int:
    """Counterfactual enriched bit: base OR any L1 signal fired."""
    if bandit_success:
        return 1
    return 1 if any(l1_flags.values()) else 0


__all__ = [
    "KIND_TO_SUBSTRATEGY_FIELDS",
    "SUBSTRATEGY_EXCLUDED_KINDS",
    "bandit_success_l1_counterfactual",
    "composite_substrategy_key",
    "compute_l1_flags",
    "d_loc_le_2",
    "singleton_failure",
    "substrategy_uniqueness",
]
