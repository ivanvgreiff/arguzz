"""
CYCLE_MODE_MOD Mutation (Standalone)

Mutates cycles[].machine_mode (privilege bit). Deterministic 0↔1 flip.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class CycleModeModTarget:
    """Target for a CYCLE_MODE_MOD mutation."""
    step: int
    cycle_idx: int
    pc: int
    original_mode: int
    major: int
    minor: int


def get_targets_at_step(step: int, data: "InspectionData") -> Optional[CycleModeModTarget]:
    """Return the cycle at this step if step != 0 and mode is binary (0 or 1)."""
    if step == 0:
        return None

    cycle = data.get_cycle(step)
    if not cycle:
        return None

    if cycle.machine_mode not in (0, 1):
        return None

    return CycleModeModTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        original_mode=cycle.machine_mode,
        major=cycle.major,
        minor=cycle.minor,
    )


def get_all_targets(data: "InspectionData") -> List[CycleModeModTarget]:
    """All flippable cycle-mode targets on the trace."""
    targets: List[CycleModeModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        if cycle.machine_mode not in (0, 1):
            continue
        targets.append(
            CycleModeModTarget(
                step=cycle.step,
                cycle_idx=cycle.cycle_idx,
                pc=cycle.pc,
                original_mode=cycle.machine_mode,
                major=cycle.major,
                minor=cycle.minor,
            )
        )
    return targets


def flipped_mode(target: CycleModeModTarget) -> int:
    """Deterministic privilege flip for binary modes."""
    return 1 - target.original_mode


def create_config(target: CycleModeModTarget, output_path: Path) -> Path:
    """Create an A4 mutation config file for CYCLE_MODE_MOD."""
    new_mode = flipped_mode(target)
    config = {
        "mutation_type": "CYCLE_MODE_MOD",
        "step": target.step,
        "mode": new_mode,
        "_info": {
            "pc": f"0x{target.pc:08x}",
            "original_mode": target.original_mode,
            "major": target.major,
            "minor": target.minor,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
