"""Bridge layer between A4Fuzzer's bandit scheduler and the Arguzz subprocess primitive.

For arms with ``surface=arguzz_exec_fault``, this module is the analog of the
``a4.standalone.mutations.*_mod`` modules for A4 arms.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from a4.core.inspection_data import InspectionData
from a4.standalone.arguzz_invoke import ArguzzInvocationResult, run
from a4.standalone.bandit_ts import MutationOutcome
from a4.standalone.semantic_arm_universe import ArmKey

# Verbatim from v6_driver_v2.py:145-173
INSTR_KINDS = {
    "add", "sub", "xor", "or", "and", "slt", "sltu",
    "addi", "xori", "ori", "andi", "slti", "sltiu",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "jal", "jalr", "lui", "auipc",
    "sll", "slli", "mul", "mulh", "mulhsu", "mulhu",
    "srl", "sra", "srli", "srai",
    "div", "divu", "rem", "remu",
    "lb", "lh", "lw", "lbu", "lhu",
    "sb", "sh", "sw",
    "eany", "mret", "invalid",
}
BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}
LOADS = {"lb", "lh", "lw", "lbu", "lhu"}
STORES = {"sb", "sh", "sw"}
COMPUTATIONS = {
    "add", "sub", "xor", "or", "and", "slt", "sltu",
    "addi", "xori", "ori", "andi", "slti", "sltiu",
    "lui", "auipc",
    "sll", "slli", "mul", "mulh", "mulhsu", "mulhu",
    "srl", "sra", "srli", "srai",
    "div", "divu", "rem", "remu",
}
ENABLED_KINDS = [
    "PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD",
    "BR_NEG_COND", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD",
    "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD",
    "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD",
]

MUTATION_KINDS_ARGUZZ_FULL = (
    "PRE_EXEC_PC_MOD",
    "POST_EXEC_PC_MOD",
    "INSTR_WORD_MOD",
    "BR_NEG_COND",
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD",
    "STORE_OUT_MOD",
    "PRE_EXEC_MEM_MOD",
    "POST_EXEC_MEM_MOD",
    "PRE_EXEC_REG_MOD",
    "POST_EXEC_REG_MOD",
)

MUTATION_KINDS_ARGUZZ_SELECTED = (
    "INSTR_WORD_MOD",
    "PRE_EXEC_MEM_MOD",
    "PRE_EXEC_PC_MOD",
    "BR_NEG_COND",
)

_PRE_POST_BY_KIND: Dict[str, str] = {
    "INSTR_WORD_MOD": "pre_exec",
    "PRE_EXEC_PC_MOD": "pre_exec",
    "PRE_EXEC_MEM_MOD": "pre_exec",
    "PRE_EXEC_REG_MOD": "pre_exec",
    "BR_NEG_COND": "pre_exec",
    "POST_EXEC_PC_MOD": "post_exec",
    "POST_EXEC_MEM_MOD": "post_exec",
    "POST_EXEC_REG_MOD": "post_exec",
    "COMP_OUT_MOD": "post_exec",
    "LOAD_VAL_MOD": "post_exec",
    "STORE_OUT_MOD": "post_exec",
}

# Hook-3 capture requires A4_FAMILY_RESIDUE plus a co-trigger (A4_COVERAGE_TOUCH or
# A4_MUTATION_CONFIG). Use COVERAGE_TOUCH only — MUTATION_CONFIG would double-mutate.
DEFAULT_ARGUZZ_SUBPROCESS_ENV: Dict[str, str] = {
    "A4_FAMILY_RESIDUE": "1",
    "A4_COVERAGE_TOUCH": "1",
}


def _normalize_instr(name: str) -> str:
    return name.lower().replace("_", "").replace(".", "")


def valid_injection_kinds_for_instr(instr: str) -> list[str]:
    """Verbatim from v6_driver_v2.py:176-191."""
    instr = instr.lower()
    result = {
        "PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD",
        "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD",
        "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD",
    }
    if instr in BRANCHES:
        result.add("BR_NEG_COND")
    if instr in COMPUTATIONS:
        result.add("COMP_OUT_MOD")
    if instr in LOADS:
        result.add("LOAD_VAL_MOD")
    if instr in STORES:
        result.add("STORE_OUT_MOD")
    return sorted(result & set(ENABLED_KINDS))


def _build_opcode_class_mapping() -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for instr in COMPUTATIONS:
        mapping[instr] = "arithmetic"
    for instr in BRANCHES:
        mapping[instr] = "branch"
    for instr in LOADS:
        mapping[instr] = "memory_load"
    for instr in STORES:
        mapping[instr] = "memory_store"
    mapping["jal"] = "jump"
    mapping["jalr"] = "jump"
    mapping["eany"] = "ecall_mret"
    mapping["mret"] = "ecall_mret"
    mapping["invalid"] = "system"
    return mapping


MAPPING_INSTR_TO_OPCODE_CLASS: Dict[str, str] = _build_opcode_class_mapping()


@dataclass
class ArguzzBridgeTarget:
    step: int
    kind: str
    instruction: str
    opcode_class: str
    pre_post: str


def opcode_class_for_step(
    step: int,
    data: InspectionData,
    baseline_trace: dict[int, str],
) -> str:
    """Return D2.A LOCKED opcode_class for the instruction at ``step``."""
    _ = data
    instr = baseline_trace.get(step)
    if instr is None:
        return "system"
    return MAPPING_INSTR_TO_OPCODE_CLASS.get(_normalize_instr(instr), "system")


def get_valid_steps(
    data: InspectionData,
    kind: str,
    *,
    baseline_trace: Optional[dict[int, str]] = None,
) -> list[int]:
    """Steps whose instruction class allows ``kind`` (per v6_driver validity)."""
    _ = data
    if baseline_trace is None:
        raise ValueError("baseline_trace required for Arguzz step enumeration")
    steps: list[int] = []
    for step in sorted(baseline_trace):
        instr = _normalize_instr(baseline_trace[step])
        if kind in valid_injection_kinds_for_instr(instr):
            steps.append(step)
    return steps


def get_targets_at_step(
    step: int,
    data: InspectionData,
    kind: str,
    *,
    baseline_trace: Optional[dict[int, str]] = None,
) -> list[ArguzzBridgeTarget]:
    if baseline_trace is None:
        return []
    instr_raw = baseline_trace.get(step)
    if instr_raw is None:
        return []
    instr = _normalize_instr(instr_raw)
    if kind not in valid_injection_kinds_for_instr(instr):
        return []
    return [
        ArguzzBridgeTarget(
            step=step,
            kind=kind,
            instruction=instr_raw,
            opcode_class=MAPPING_INSTR_TO_OPCODE_CLASS.get(instr, "system"),
            pre_post=_PRE_POST_BY_KIND[kind],
        )
    ]


def create_mutation_for_arm(
    arm: ArmKey,
    step: int,
    host: str,
    host_args: list[str],
    seed: int,
    data: InspectionData,
    *,
    timeout: float = 90.0,
    env: Optional[dict] = None,
) -> tuple[MutationOutcome, ArguzzInvocationResult, dict]:
    """Invoke the Arguzz primitive for a scheduler-picked arm + step."""
    _ = data
    subprocess_env = dict(DEFAULT_ARGUZZ_SUBPROCESS_ENV)
    if env:
        subprocess_env.update(env)
    # ISS-1: inject-only (include_trace=False) — outcome is prover_status-primary.
    result = run(
        host,
        host_args,
        step,
        arm.kind,
        seed,
        timeout=timeout,
        include_trace=False,
        env=subprocess_env,
    )
    config = {
        "kind": arm.kind,
        "step": step,
        "pre_post": arm.pre_post,
        "opcode_class": arm.opcode_class,
        "seed": seed,
        "soundness_signal": result.soundness_signal,
    }
    if result.extra_tags.get("failure_recording_gap"):
        config["failure_recording_gap"] = True
    return result.outcome, result, config


__all__ = [
    "ArguzzBridgeTarget",
    "BRANCHES",
    "COMPUTATIONS",
    "ENABLED_KINDS",
    "DEFAULT_ARGUZZ_SUBPROCESS_ENV",
    "INSTR_KINDS",
    "LOADS",
    "MAPPING_INSTR_TO_OPCODE_CLASS",
    "MUTATION_KINDS_ARGUZZ_FULL",
    "MUTATION_KINDS_ARGUZZ_SELECTED",
    "STORES",
    "_PRE_POST_BY_KIND",
    "create_mutation_for_arm",
    "get_targets_at_step",
    "get_valid_steps",
    "opcode_class_for_step",
    "valid_injection_kinds_for_instr",
]
