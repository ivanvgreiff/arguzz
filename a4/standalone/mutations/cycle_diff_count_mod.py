"""
CYCLE_DIFF_COUNT_MOD Mutation (Standalone)

Mutates one element of cycles[].diff_count[index].
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
class CycleDiffCountModTarget:
    step: int
    cycle_idx: int
    index: int
    original_value: int
    pc: int
    major: int
    minor: int
    other_value: int


def _cycle_diff_values(cycle) -> tuple[int, int]:
    return cycle.diff_count_0, cycle.diff_count_1


def get_targets_at_step(step: int, data: "InspectionData") -> Optional[CycleDiffCountModTarget]:
    if step == 0:
        return None
    cycle = data.get_cycle(step)
    if not cycle:
        return None
    d0, d1 = _cycle_diff_values(cycle)
    index = 0
    return CycleDiffCountModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        index=index,
        original_value=d0,
        pc=cycle.pc,
        major=cycle.major,
        minor=cycle.minor,
        other_value=d1,
    )


def get_all_targets(data: "InspectionData") -> List[CycleDiffCountModTarget]:
    targets: List[CycleDiffCountModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        d0, d1 = _cycle_diff_values(cycle)
        for index, original in enumerate((d0, d1)):
            targets.append(
                CycleDiffCountModTarget(
                    step=cycle.step,
                    cycle_idx=cycle.cycle_idx,
                    index=index,
                    original_value=original,
                    pc=cycle.pc,
                    major=cycle.major,
                    minor=cycle.minor,
                    other_value=d1 if index == 0 else d0,
                )
            )
    return targets


def generate_new_value(target: CycleDiffCountModTarget, rng: random.Random) -> int:
    roll = rng.random()
    original = target.original_value

    for _ in range(32):
        if roll < 0.60:
            candidate = max(0, original + rng.choice([-3, -2, -1, 1, 2, 3]))
        else:
            candidate = rng.randint(0, 65535)

        if candidate != original:
            return candidate

    return original + 1


def pick_index(target: CycleDiffCountModTarget, rng: random.Random) -> int:
    return rng.choice([0, 1])


def create_config(
    target: CycleDiffCountModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    config = {
        "mutation_type": "CYCLE_DIFF_COUNT_MOD",
        "step": target.step,
        "index": target.index,
        "diff_count": mutated_value,
        "_info": {
            "pc": f"0x{target.pc:08x}",
            "original_value": target.original_value,
            "other_value": target.other_value,
            "major": target.major,
            "minor": target.minor,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
