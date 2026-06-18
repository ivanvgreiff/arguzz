"""
CYCLE_STATE_MOD Mutation (Standalone)

Mutates cycles[].state to a different valid CycleState enum value.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from a4.standalone.mutations._cycle_state_enum import CYCLE_STATE

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

_VALID_STATES = sorted(set(CYCLE_STATE.values()))


@dataclass
class CycleStateModTarget:
    step: int
    cycle_idx: int
    pc: int
    original_state: int
    major: int
    minor: int


def get_targets_at_step(step: int, data: "InspectionData") -> Optional[CycleStateModTarget]:
    if step == 0:
        return None
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    return CycleStateModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        original_state=cycle.state,
        major=cycle.major,
        minor=cycle.minor,
    )


def get_all_targets(data: "InspectionData") -> List[CycleStateModTarget]:
    targets: List[CycleStateModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        targets.append(
            CycleStateModTarget(
                step=cycle.step,
                cycle_idx=cycle.cycle_idx,
                pc=cycle.pc,
                original_state=cycle.state,
                major=cycle.major,
                minor=cycle.minor,
            )
        )
    return targets


def generate_new_value(target: CycleStateModTarget, rng: random.Random) -> int:
    alternatives = [s for s in _VALID_STATES if s != target.original_state]
    if alternatives:
        return rng.choice(alternatives)
    return (target.original_state + 1) & 0xFFFFFFFF


def create_config(
    target: CycleStateModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    config = {
        "mutation_type": "CYCLE_STATE_MOD",
        "step": target.step,
        "state": mutated_value,
        "_info": {
            "pc": f"0x{target.pc:08x}",
            "original_state": target.original_state,
            "major": target.major,
            "minor": target.minor,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
