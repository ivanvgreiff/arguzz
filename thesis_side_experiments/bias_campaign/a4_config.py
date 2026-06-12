"""Build A4 mutation configs for aligned kinds (read-only use of a4/ creators)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.standalone.mutations.comp_out_mod import (
    get_targets_at_step as get_comp_out_targets,
    create_config as create_comp_out_config,
)
from a4.standalone.mutations.load_val_mod import (
    get_targets_at_step as get_load_val_targets,
    create_config as create_load_val_config,
)
from a4.standalone.mutations.store_out_mod import (
    get_targets_at_step as get_store_out_targets,
    create_config as create_store_out_config,
)
from a4.standalone.mutations.pre_exec_reg_mod import (
    get_targets_at_step as get_pre_exec_reg_targets,
    create_config as create_pre_exec_reg_config,
)
from a4.standalone.mutations.mem_val_mod import (
    get_targets_at_step as get_mem_val_targets,
    create_config as create_mem_val_config,
)
from a4.standalone.mutations.instr_word_mod import (
    get_targets_at_step as get_instr_word_targets,
    create_config as create_instr_word_config,
)

A4_KINDS = (
    "PRE_EXEC_REG_MOD",
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD",
    "STORE_OUT_MOD",
    "MEM_VAL_MOD",
    "INSTR_WORD_MOD_FULL",
)


def arguzz_to_a4_step(arguzz_step: int, offset: int = -2) -> int:
    return arguzz_step + offset


def pick_mutated_value(original: int, seed: int, prev: Optional[int] = None) -> int:
    """Deterministic mutated word != original (and != prev when given for READ consistency)."""
    candidate = (original + (seed + 1) * 0x9E3779B1) & 0xFFFFFFFF
    if candidate == original:
        candidate = (original + seed + 7) & 0xFFFFFFFF
    if prev is not None and candidate == prev:
        candidate = (prev + seed + 11) & 0xFFFFFFFF
    if candidate == original:
        candidate = original ^ ((seed + 3) | 1)
    return candidate


def _pick_from_list(items: List[Any], seed: int) -> Any:
    return items[seed % len(items)]


def build_a4_config(
    kind: str,
    arguzz_step: int,
    seed: int,
    data: "InspectionData",
    output_path: Path,
    step_offset: int = -2,
) -> Optional[tuple[Path, str]]:
    """Return (config_path, target_desc) or None if no valid target."""
    a4_step = arguzz_to_a4_step(arguzz_step, step_offset)

    if kind == "PRE_EXEC_REG_MOD":
        targets = get_pre_exec_reg_targets(a4_step, data, strategy="next_read")
        if not targets:
            return None
        target = _pick_from_list(targets, seed)
        mutated = pick_mutated_value(target.original_word, seed, target.prev_word)
        create_pre_exec_reg_config(target, mutated, output_path)
        desc = f"{target.register_name} READ word {target.original_word}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "COMP_OUT_MOD":
        target = get_comp_out_targets(a4_step, data)
        if not target:
            return None
        mutated = pick_mutated_value(target.original_value, seed)
        create_comp_out_config(target, mutated, output_path)
        desc = f"{target.register_name} WRITE {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "LOAD_VAL_MOD":
        target = get_load_val_targets(a4_step, data)
        if not target:
            return None
        mutated = pick_mutated_value(target.original_value, seed)
        create_load_val_config(target, mutated, output_path)
        desc = f"{target.register_name} load {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "STORE_OUT_MOD":
        target = get_store_out_targets(a4_step, data)
        if not target:
            return None
        mutated = pick_mutated_value(target.original_value, seed)
        create_store_out_config(target, mutated, output_path)
        desc = f"store mem {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "MEM_VAL_MOD":
        targets = get_mem_val_targets(a4_step, data)
        if not targets:
            return None
        target = _pick_from_list(targets, seed)
        mutated = pick_mutated_value(target.original_value, seed)
        create_mem_val_config(target, mutated, output_path)
        desc = f"mem {target.txn_type} {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "INSTR_WORD_MOD_FULL":
        target = get_instr_word_targets(a4_step, data)
        if not target:
            return None
        mutated = pick_mutated_value(target.original_word, seed)
        create_instr_word_config(target, mutated, output_path)
        desc = f"ifetch {target.original_word:#010x}->{mutated:#010x} @a4_step={a4_step}"
        return output_path, desc

    raise ValueError(f"unknown A4 kind: {kind}")
