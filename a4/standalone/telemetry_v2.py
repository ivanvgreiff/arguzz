"""
IV.POS.7 extended telemetry — cloud1 Phase 6 (ProG_Report_2.md §12).

Pure helpers + `record_full_telemetry()` to populate v2 SQLite tables:
  reward_counterfactuals, mutation_substrategy, hook3_raw,
  local_coverage_v2, compressed_global_coverage.

Called from the fuzzer when `telemetry_level == "full"`.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from a4.standalone.compressed_global_extractor import (
    extract_compressed_global_contexts,
    to_storage_rows,
)
from a4.standalone.reward_v2 import (
    RewardComponents,
    compute_counterfactuals,
    compute_reward_v2_components,
)
from a4.standalone.structural_cells import StructuralCell

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData
    from a4.standalone.coverage_db import CoverageDB

TELEMETRY_LEVELS = frozenset({"none", "standard", "full"})


def default_telemetry_level(selector_strategy: str, v2_strategies: frozenset) -> str:
    """D35: full for IV.POS.7 bandit variants, standard for legacy."""
    if selector_strategy in v2_strategies:
        return "full"
    return "standard"


def classify_value_class(original_value: int, mutated_value: int) -> str:
    """D34: zero | small | large | bit_pattern."""
    orig = original_value & 0xFFFFFFFF
    mut = mutated_value & 0xFFFFFFFF
    if mut == 0:
        return "zero"
    xor = orig ^ mut
    if xor != 0 and xor.bit_count() <= 4:
        return "bit_pattern"
    if mut < 256:
        return "small"
    diff = (mut - orig) & 0xFFFFFFFF
    if diff < 256 or (0xFFFFFFFF - diff) < 256:
        return "small"
    return "large"


def _instr_fields_from_word(word: int) -> Dict[str, Optional[int]]:
    """Decode RISC-V instruction fields for mutation_substrategy."""
    from a4.standalone.mutations.instr_word_mod_sur import RiscVInstruction

    instr = RiscVInstruction.from_word(word & 0xFFFFFFFF)
    imm_val: Optional[int] = None
    if instr.imm is not None:
        imm_val = instr.imm & 0xFFFFFFFF
    return {
        "opcode": instr.opcode,
        "rd": instr.rd,
        "rs1": instr.rs1,
        "rs2": instr.rs2,
        "funct3": instr.funct3,
        "funct7": instr.funct7,
        "imm": imm_val,
    }


def extract_mutation_substrategy(
    kind: str,
    config: Dict[str, Any],
    original_value: int,
    mutated_value: int,
) -> Dict[str, Optional[Any]]:
    """Per-kind fields for `mutation_substrategy` (Pro §12)."""
    out: Dict[str, Optional[Any]] = {
        "opcode": None,
        "rd": None,
        "rs1": None,
        "rs2": None,
        "funct3": None,
        "funct7": None,
        "imm": None,
        "byte_lane": None,
        "bit_mask": None,
        "value_class": None,
    }

    word_kinds = ("INSTR_WORD_MOD_SUR", "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD")
    if kind in word_kinds:
        fields = _instr_fields_from_word(mutated_value)
        out.update(fields)

    if kind in ("LOAD_VAL_MOD", "STORE_OUT_MOD", "COMP_OUT_MOD", "MEM_VAL_MOD",
                "PRE_EXEC_REG_MOD"):
        out["value_class"] = classify_value_class(original_value, mutated_value)

    if kind == "MEM_VAL_MOD":
        xor = (original_value ^ mutated_value) & 0xFFFFFFFF
        out["bit_mask"] = xor if xor else None
        if xor:
            out["byte_lane"] = min(31, max(0, xor.bit_length() - 1))
        else:
            out["byte_lane"] = 0

    return out


def build_hook3_payload(
    family_residues: Optional[List[dict]],
    family_details: Optional[List[dict]],
    kind: str,
    mutation_zone: str,
    mutation_major: int,
) -> Tuple[Optional[dict], Optional[List[dict]]]:
    """Build raw + compressed Hook 3 rows for `hook3_raw` (D36)."""
    raw_obj: Optional[dict] = None
    if family_residues or family_details:
        raw_obj = {}
        if family_residues:
            raw_obj["family_residues"] = family_residues
        if family_details:
            raw_obj["family_details"] = family_details

    compressed_ctxs = extract_compressed_global_contexts(
        family_residues,
        family_details,
        kind,
        mutation_zone,
        mutation_major,
    )
    compressed_list: Optional[List[dict]] = None
    if compressed_ctxs:
        import json
        compressed_list = [
            json.loads(ctx_json)
            for _key, _fam, ctx_json in to_storage_rows(compressed_ctxs)
        ]
    return raw_obj, compressed_list


def _sanitize_reward(val: float) -> float:
    """Reject inf/nan for counterfactual storage."""
    if not math.isfinite(val):
        return 0.0
    return val


def record_full_telemetry(
    db: "CoverageDB",
    campaign_id: int,
    mutation_id: int,
    *,
    kind: str,
    step: int,
    exec_result: Any,
    config: Dict[str, Any],
    original_value: int,
    mutated_value: int,
    legacy_reward_diag: Dict[str, Any],
    step_to_zone: Dict[int, str],
    seen_local_v2: Set[Tuple[str, int, int]],
    seen_compressed_global: Set[str],
    seen_structural: Set[StructuralCell],
    components: Optional[RewardComponents] = None,
    l1_logging: bool = False,
    bandit_success_l1: Optional[int] = None,
    l1_substrategy_uniqueness: Optional[int] = None,
    l1_d_loc_le_2: Optional[int] = None,
    l1_singleton_failure: Optional[int] = None,
) -> RewardComponents:
    """Write all Phase 6 v2 tables for one mutation. Returns reward components."""
    mutation_zone = step_to_zone.get(step, "core_other")
    mutation_major = 0
    if hasattr(exec_result, "failures") and exec_result.failures:
        mutation_major = exec_result.failures[0].major
    # Prefer cycle major when available via config step — caller may set on exec_result
    cycle_major = getattr(exec_result, "_mutation_major", None)
    if cycle_major is not None:
        mutation_major = int(cycle_major)

    if components is None:
        setattr(exec_result, "config", config)
        components = compute_reward_v2_components(
            exec_result,
            seen_local_v2,
            seen_compressed_global,
            seen_structural,
            kind,
            mutation_zone,
            mutation_major,
        )

    counterfactuals = compute_counterfactuals(components, legacy_reward_diag)
    l1_kwargs = {}
    if l1_logging:
        l1_kwargs = {
            "bandit_success_l1": bandit_success_l1,
            "l1_substrategy_uniqueness": l1_substrategy_uniqueness,
            "l1_d_loc_le_2": l1_d_loc_le_2,
            "l1_singleton_failure": l1_singleton_failure,
        }
    db.record_reward_counterfactuals(
        mutation_id,
        current_reward=_sanitize_reward(float(counterfactuals["current_reward"])),
        no_qloc_reward=_sanitize_reward(float(counterfactuals["no_qloc_reward"])),
        fnew_only_reward=_sanitize_reward(float(counterfactuals["fnew_only_reward"])),
        discovery_binary_reward=int(counterfactuals["discovery_binary_reward"]),
        compressed_global_reward=_sanitize_reward(
            float(counterfactuals["compressed_global_reward"])
        ),
        **l1_kwargs,
    )

    sub = extract_mutation_substrategy(kind, config, original_value, mutated_value)
    db.record_mutation_substrategy(mutation_id, **sub)

    raw_obj, compressed_list = build_hook3_payload(
        getattr(exec_result, "family_residues", None),
        getattr(exec_result, "family_details", None),
        kind,
        mutation_zone,
        mutation_major,
    )
    db.record_hook3_raw(mutation_id, raw_entries=raw_obj, compressed_ctx_list=compressed_list)

    failures = getattr(exec_result, "failures", None) or []
    seen_loc: Set[Tuple[str, int, int]] = set()
    for f in failures:
        if hasattr(f, "constraint_loc"):
            loc = f.constraint_loc()
            major, minor = f.major, f.minor
        elif isinstance(f, dict):
            loc = f.get("constraint_loc", "")
            major = int(f.get("major", 0))
            minor = int(f.get("minor", 0))
        else:
            continue
        key = (loc, major, minor)
        if key in seen_loc:
            continue
        seen_loc.add(key)
        db.record_local_v2_first_hit(campaign_id, mutation_id, loc, major, minor)

    compressed_ctxs = extract_compressed_global_contexts(
        getattr(exec_result, "family_residues", None),
        getattr(exec_result, "family_details", None),
        kind,
        mutation_zone,
        mutation_major,
    )
    for ctx_key, family, ctx_json in to_storage_rows(compressed_ctxs):
        db.record_compressed_global_first_hit(
            campaign_id, mutation_id, ctx_key, family, ctx_json,
        )

    return components


__all__ = [
    "TELEMETRY_LEVELS",
    "default_telemetry_level",
    "classify_value_class",
    "extract_mutation_substrategy",
    "build_hook3_payload",
    "record_full_telemetry",
]
