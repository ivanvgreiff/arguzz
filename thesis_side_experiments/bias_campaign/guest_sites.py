"""Guest site map for c0/c1 differential guest."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ROOT = Path(__file__).resolve().parent
DEFAULT_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")
DEFAULT_GUEST_ARGS = ["--in1", "5", "--in4", "10"]

TRACE_RE = re.compile(r"<trace>(\{.*?\})</trace>")
CYCLE_RE = re.compile(r"<a4_cycle_info>(\{.*?\})</a4_cycle_info>")

COMPUTE_OPS = {
    "Add", "Sub", "Mul", "MulH", "MulHSU", "MulHU", "Div", "DivU", "Rem", "RemU",
    "And", "Or", "Xor", "Slt", "SltU", "Sll", "Srl", "Sra", "Lui", "Auipc",
    "AddI", "AndI", "OrI", "XorI", "SltI", "SltIU", "SllI", "SrlI", "SraI",
}
LOAD_OPS = {"Lw", "Lh", "Lb", "Lhu", "Lbu", "LbU", "LhU", "LbU"}
STORE_OPS = {"Sw", "Sh", "Sb"}
BRANCH_OPS = {"Beq", "Bne", "Blt", "Bge", "BltU", "BgeU", "Jal", "JalR"}


def instruction_class(name: str) -> str:
    if name in COMPUTE_OPS:
        return "compute"
    if name in LOAD_OPS:
        return "load"
    if name in STORE_OPS:
        return "store"
    if name in BRANCH_OPS:
        return "branch"
    return "other"


def infer_step_offset(trace_steps: List[dict], cycles: List[dict]) -> int:
    """Empirical Arguzz→A4 step offset (a4_step = arguzz_step + offset)."""
    for t in trace_steps:
        if t.get("instruction") not in COMPUTE_OPS:
            continue
        arguzz_step = t["step"]
        arguzz_pc = t["pc"]
        for off in range(-5, 6):
            a4_step = arguzz_step + off
            for c in cycles:
                if c.get("step") != a4_step:
                    continue
                if c.get("pc") == arguzz_pc + 4 and c.get("major", 99) <= 4:
                    return off
    return -2


def build_guest_sites(
    host: Path = DEFAULT_HOST,
    guest_args: Optional[List[str]] = None,
    timeout: int = 180,
) -> dict:
    guest_args = guest_args or DEFAULT_GUEST_ARGS
    env = {**dict(os.environ), "A4_INSPECT": "1"}
    proc = subprocess.run(
        [str(host), "--trace"] + guest_args,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    output = proc.stdout + proc.stderr
    trace_steps = [json.loads(m.group(1)) for m in TRACE_RE.finditer(output)]
    cycles = [json.loads(m.group(1)) for m in CYCLE_RE.finditer(output)]

    steps = []
    for t in trace_steps:
        ic = instruction_class(t.get("instruction", ""))
        steps.append(
            {
                "step": t["step"],
                "pc": t["pc"],
                "instruction": t.get("instruction"),
                "asm": t.get("assembly"),
                "class": ic,
            }
        )

    offset = infer_step_offset(trace_steps, cycles)
    all_steps = [s["step"] for s in steps]
    eligible: Dict[str, List[int]] = {
        "PRE_EXEC_REG_MOD": all_steps,
        "PRE_EXEC_MEM_MOD": all_steps,
        "INSTR_WORD_MOD": all_steps,
        "COMP_OUT_MOD": [s["step"] for s in steps if s["class"] == "compute"],
        "LOAD_VAL_MOD": [s["step"] for s in steps if s["class"] == "load"],
        "STORE_OUT_MOD": [s["step"] for s in steps if s["class"] == "store"],
    }

    return {
        "host": str(host),
        "guest_args": guest_args,
        "trace_step_count": len(steps),
        "arguzz_to_a4_step_offset": offset,
        "steps": steps,
        "eligible_steps_by_kind": eligible,
    }


def load_guest_sites(path: Optional[Path] = None) -> dict:
    path = path or ROOT / "artifacts" / "c1" / "guest_sites.json"
    return json.loads(path.read_text())


def ensure_guest_sites(
    host: Path = DEFAULT_HOST,
    guest_args: Optional[List[str]] = None,
    cache_path: Optional[Path] = None,
) -> dict:
    cache_path = cache_path or ROOT / "artifacts" / "c1" / "guest_sites.json"
    if cache_path.exists():
        return load_guest_sites(cache_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    sites = build_guest_sites(host, guest_args)
    cache_path.write_text(json.dumps(sites, indent=2))
    return sites


def sample_eligible_step(kind: str, seed: int, sites: dict) -> Optional[int]:
    steps = sites["eligible_steps_by_kind"].get(kind, [])
    if not steps:
        return None
    return steps[seed % len(steps)]
