"""
CYCLE_PC_MOD Mutation (Standalone)

Mutates cycles[].pc on instruction cycles (major 0-6).
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class CyclePcModTarget:
    step: int
    cycle_idx: int
    original_pc: int
    major: int
    minor: int
    machine_mode: int


def get_targets_at_step(step: int, data: "InspectionData") -> Optional[CyclePcModTarget]:
    if step == 0:
        return None
    cycle = data.get_cycle(step)
    if not cycle or cycle.major > 6:
        return None
    return CyclePcModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        original_pc=cycle.pc,
        major=cycle.major,
        minor=cycle.minor,
        machine_mode=cycle.machine_mode,
    )


def get_all_targets(data: "InspectionData") -> List[CyclePcModTarget]:
    targets: List[CyclePcModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0 or cycle.major > 6:
            continue
        targets.append(
            CyclePcModTarget(
                step=cycle.step,
                cycle_idx=cycle.cycle_idx,
                original_pc=cycle.pc,
                major=cycle.major,
                minor=cycle.minor,
                machine_mode=cycle.machine_mode,
            )
        )
    return targets


def generate_new_value(target: CyclePcModTarget, rng: random.Random) -> int:
    original = target.original_pc
    roll = rng.random()

    for _ in range(32):
        if roll < 0.40:
            candidate = (original + rng.choice([-12, -8, -4, 4, 8, 12])) & 0xFFFFFFFF
        elif roll < 0.70:
            candidate = (original + rng.choice([-1024, -512, 256, 512, 1024])) & 0xFFFFFFFF
        else:
            candidate = rng.getrandbits(32) & 0xFFFFFFFC

        candidate &= 0xFFFFFFFC
        if candidate != original:
            return candidate

    return (original + 4) & 0xFFFFFFFC


def create_config(
    target: CyclePcModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    config = {
        "mutation_type": "CYCLE_PC_MOD",
        "step": target.step,
        "pc": mutated_value,
        "_info": {
            "original_pc": target.original_pc,
            "major": target.major,
            "minor": target.minor,
            "machine_mode": target.machine_mode,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
