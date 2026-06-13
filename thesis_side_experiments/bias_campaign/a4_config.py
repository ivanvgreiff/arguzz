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
from a4.standalone.mutations.instr_word_mod_sur import (
    SurgicalField,
    get_targets_at_step as get_instr_sur_targets,
    create_config as create_instr_sur_config,
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
    forced_value: Optional[int] = None,
) -> Optional[tuple[Path, str]]:
    """Return (config_path, target_desc) or None if no valid target."""
    a4_step = arguzz_to_a4_step(arguzz_step, step_offset)

    def resolve_mutated(original: int, prev: Optional[int] = None) -> int:
        if forced_value is not None:
            return forced_value & 0xFFFFFFFF
        return pick_mutated_value(original, seed, prev)

    if kind == "PRE_EXEC_REG_MOD":
        targets = get_pre_exec_reg_targets(a4_step, data, strategy="next_read")
        if not targets:
            return None
        target = _pick_from_list(targets, seed)
        mutated = resolve_mutated(target.original_word, target.prev_word)
        create_pre_exec_reg_config(target, mutated, output_path)
        desc = f"{target.register_name} READ word {target.original_word}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "COMP_OUT_MOD":
        target = get_comp_out_targets(a4_step, data)
        if not target:
            return None
        mutated = resolve_mutated(target.original_value)
        create_comp_out_config(target, mutated, output_path)
        desc = f"{target.register_name} WRITE {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "LOAD_VAL_MOD":
        target = get_load_val_targets(a4_step, data)
        if not target:
            return None
        mutated = resolve_mutated(target.original_value)
        create_load_val_config(target, mutated, output_path)
        desc = f"{target.register_name} load {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "STORE_OUT_MOD":
        target = get_store_out_targets(a4_step, data)
        if not target:
            return None
        mutated = resolve_mutated(target.original_value)
        create_store_out_config(target, mutated, output_path)
        desc = f"store mem {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "MEM_VAL_MOD":
        targets = get_mem_val_targets(a4_step, data)
        if not targets:
            return None
        target = _pick_from_list(targets, seed)
        mutated = resolve_mutated(target.original_value)
        create_mem_val_config(target, mutated, output_path)
        desc = f"mem {target.txn_type} {target.original_value}->{mutated} @a4_step={a4_step}"
        return output_path, desc

    if kind == "INSTR_WORD_MOD_FULL":
        target = get_instr_word_targets(a4_step, data)
        if not target:
            return None
        mutated = resolve_mutated(target.original_word)
        create_instr_word_config(target, mutated, output_path)
        desc = f"ifetch {target.original_word:#010x}->{mutated:#010x} @a4_step={a4_step}"
        return output_path, desc

    raise ValueError(f"unknown A4 kind: {kind}")


def build_a4_sur_config(
    surgical_field: SurgicalField,
    new_field_value: int,
    arguzz_step: int,
    data: "InspectionData",
    output_path: Path,
    step_offset: int = -2,
) -> Optional[tuple[Path, str, int]]:
    """Single-field INSTR_WORD_MOD_SUR at arguzz_step. Returns (path, desc, mutated_word)."""
    a4_step = arguzz_to_a4_step(arguzz_step, step_offset)
    target = get_instr_sur_targets(a4_step, data)
    if not target:
        return None
    insn = target.instruction
    mutated_word = insn.encode_with_mutation(surgical_field, new_field_value)
    if mutated_word == target.original_word:
        raise ValueError(
            f"SUR {surgical_field.value}={new_field_value} unchanged word @ step {a4_step}"
        )
    create_instr_sur_config(
        target, surgical_field, mutated_word, new_field_value, output_path
    )
    desc = (
        f"SUR {surgical_field.value} {insn.get_field_value(surgical_field)}"
        f"->{new_field_value} word {target.original_word:#010x}->{mutated_word:#010x}"
        f" @a4_step={a4_step}"
    )
    return output_path, desc, mutated_word


def build_a4_mem_val_config(
    arguzz_step: int,
    data: "InspectionData",
    output_path: Path,
    seed: int,
    step_offset: int = -2,
    txn_type: Optional[str] = None,
    forced_value: Optional[int] = None,
) -> Optional[tuple[Path, str]]:
    """MEM_VAL_MOD at arguzz_step; optional txn_type filter (load_mem_read, store_rmw_read)."""
    a4_step = arguzz_to_a4_step(arguzz_step, step_offset)
    targets = get_mem_val_targets(a4_step, data)
    if txn_type:
        targets = [t for t in targets if t.txn_type == txn_type]
    if not targets:
        return None
    target = _pick_from_list(targets, seed)
    if forced_value is not None:
        mutated = forced_value & 0xFFFFFFFF
    else:
        mutated = pick_mutated_value(target.original_value, seed)
    create_mem_val_config(target, mutated, output_path)
    desc = (
        f"mem {target.txn_type} addr=0x{target.byte_addr:08x} "
        f"{target.original_value}->{mutated} @a4_step={a4_step}"
    )
    return output_path, desc
