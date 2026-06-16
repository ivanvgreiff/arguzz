"""A4 config builders for E5 full_sweep guest (incl. INSTR_TYPE_MOD)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.standalone.mutations.instr_type_mod import (  # noqa: E402
    VALID_MINORS_BY_MAJOR,
    create_config as create_instr_type_config,
    get_targets_at_step as get_instr_type_targets,
    is_valid_combination,
)
from thesis_side_experiments.bias_campaign.a4_config import (  # noqa: E402
    build_a4_config,
    pick_mutated_value,
)

# Re-export PRE_EXEC via existing module
from a4.standalone.mutations.pre_exec_reg_mod import (  # noqa: E402
    get_targets_at_step as get_pre_exec_reg_targets,
    create_config as create_pre_exec_reg_config,
)


def pick_alternate_type(original_major: int, original_minor: int, seed: int) -> Tuple[int, int]:
    """Deterministic different valid (major, minor) for INSTR_TYPE_MOD."""
    candidates: List[Tuple[int, int]] = []
    for major, minors in VALID_MINORS_BY_MAJOR.items():
        if major > 6:
            continue
        for minor in minors:
            if major != original_major or minor != original_minor:
                candidates.append((major, minor))
    if not candidates:
        raise ValueError("no alternate instruction types")
    idx = seed % len(candidates)
    return candidates[idx]


def build_instr_type_mod(
    step: int,
    data: InspectionData,
    output_path: Path,
    seed: int = 0,
) -> Optional[Tuple[Path, str]]:
    target = get_instr_type_targets(step, data)
    if not target:
        return None
    new_major, new_minor = pick_alternate_type(
        target.original_major, target.original_minor, seed
    )
    create_instr_type_config(
        target,
        new_major,
        new_minor,
        output_path,
        is_valid=is_valid_combination(new_major, new_minor),
    )
    desc = (
        f"INSTR_TYPE_MOD {target.kind_name} "
        f"({target.original_major},{target.original_minor})"
        f"->({new_major},{new_minor}) @step={step}"
    )
    return output_path, desc


def build_pre_exec_reg_mod(
    step: int,
    data: InspectionData,
    output_path: Path,
    seed: int,
    strategy: str = "next_read",
) -> Optional[Tuple[Path, str]]:
    targets = get_pre_exec_reg_targets(step, data, strategy=strategy)
    if not targets:
        return None
    target = targets[seed % len(targets)]
    mutated = pick_mutated_value(target.original_word, seed, target.prev_word)
    create_pre_exec_reg_config(target, mutated, output_path)
    desc = f"{strategy} {target.register_name} @step={step}"
    return output_path, desc


def build_a4_sample_config(
    mutation_type: str,
    variant: Optional[str],
    step: int,
    data: InspectionData,
    output_path: Path,
    seed: int,
) -> Optional[Tuple[Path, str]]:
    if mutation_type == "INSTR_TYPE_MOD":
        return build_instr_type_mod(step, data, output_path, seed)
    if mutation_type == "PRE_EXEC_REG_MOD":
        strategy = variant or "next_read"
        return build_pre_exec_reg_mod(step, data, output_path, seed, strategy=strategy)
    if mutation_type == "INSTR_WORD_MOD_SUR":
        from thesis_side_experiments.bias_campaign.a4_config import build_a4_sur_config  # noqa: E402
        from a4.standalone.mutations.instr_word_mod_sur import SurgicalField  # noqa: E402

        field_map = {
            "funct3_xor": (SurgicalField.FUNCT3, [4, 2, 6, 1, 3, 5, 7]),
            "funct3_slt": (SurgicalField.FUNCT3, [2, 4, 6, 1, 3, 5, 7]),
            "funct7_sub": (SurgicalField.FUNCT7, [0x20, 0x00, 0x01, 0x10]),
            "rd": (SurgicalField.RD, [(10 + i) % 32 for i in range(32)]),
            "rs1": (SurgicalField.RS1, [(10 + i) % 32 for i in range(32)]),
            "rs2": (SurgicalField.RS2, [(10 + i) % 32 for i in range(32)]),
        }
        if variant not in field_map:
            return None
        field, candidates = field_map[variant]
        start = seed % len(candidates)
        for offset in range(len(candidates)):
            val = candidates[(start + offset) % len(candidates)]
            try:
                built = build_a4_sur_config(field, val, step, data, output_path, step_offset=0)
            except ValueError:
                continue
            if built:
                return (built[0], built[1])
        return None

    kind_map = {
        "COMP_OUT_MOD": "COMP_OUT_MOD",
        "LOAD_VAL_MOD": "LOAD_VAL_MOD",
        "STORE_OUT_MOD": "STORE_OUT_MOD",
        "INSTR_WORD_MOD_FULL": "INSTR_WORD_MOD_FULL",
        "MEM_VAL_MOD": "MEM_VAL_MOD",
    }
    a4_kind = kind_map.get(mutation_type)
    if not a4_kind:
        return None
    forced = None
    if mutation_type != "INSTR_WORD_MOD_FULL":
        forced = pick_mutated_value(7 if "COMP" in mutation_type else 3, seed)
    else:
        from a4.standalone.mutations.instr_word_mod import get_targets_at_step as gw  # noqa: E402

        t = gw(step, data)
        if t:
            forced = pick_mutated_value(t.original_word, seed)
    return build_a4_config(
        a4_kind, step, seed, data, output_path, step_offset=0, forced_value=forced
    )
