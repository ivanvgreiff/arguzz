"""
TXN_PREV_CYCLE_MOD Mutation (Standalone)

Mutates txn.prev_cycle on memory/register transactions, breaking the
memory permutation temporal-ordering invariant.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class TxnPrevCycleModTarget:
    """Target for a TXN_PREV_CYCLE_MOD mutation."""
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    original_prev_cycle: int
    original_cycle: int
    original_word: int
    original_prev_word: int


def get_targets_at_step(step: int, data: "InspectionData") -> List[TxnPrevCycleModTarget]:
    """Return all txns at this step (no READ/WRITE filter)."""
    if step == 0:
        return []

    cycle = data.get_cycle(step)
    if not cycle:
        return []

    targets: List[TxnPrevCycleModTarget] = []
    for txn in data.get_all_txns_at_step(step):
        targets.append(
            TxnPrevCycleModTarget(
                step=step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                original_prev_cycle=txn.prev_cycle,
                original_cycle=txn.cycle,
                original_word=txn.word,
                original_prev_word=txn.prev_word,
            )
        )
    return targets


def get_all_targets(data: "InspectionData") -> List[TxnPrevCycleModTarget]:
    """Iterate all txns globally for arm-space construction."""
    step_to_cycle = {c.step: c for c in data.cycles}
    targets: List[TxnPrevCycleModTarget] = []
    for txn in data.all_txns:
        if txn.step == 0:
            continue
        cycle = step_to_cycle.get(txn.step)
        if not cycle:
            continue
        targets.append(
            TxnPrevCycleModTarget(
                step=txn.step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                original_prev_cycle=txn.prev_cycle,
                original_cycle=txn.cycle,
                original_word=txn.word,
                original_prev_word=txn.prev_word,
            )
        )
    return targets


def _is_valid_candidate(value: int, target: TxnPrevCycleModTarget) -> bool:
    return value != 0 and value != target.original_cycle and value != target.original_prev_cycle


def generate_new_value(target: TxnPrevCycleModTarget, rng: random.Random) -> int:
    """35% off-by-N, 35% bounded, 30% unbounded u32; exclude 0 and own cycle."""
    original = target.original_prev_cycle
    own_cycle = target.original_cycle
    roll = rng.random()

    for _ in range(32):
        if roll < 0.35:
            delta = rng.choice([-1, 1, -5, 5, -100, 100])
            candidate = (original + delta) & 0xFFFFFFFF
        elif roll < 0.70:
            upper = max(own_cycle, 1)
            if upper <= 1:
                candidate = rng.randint(1, 0xFFFF)
            else:
                candidate = rng.randint(1, upper - 1)
        else:
            candidate = rng.getrandbits(32)

        if _is_valid_candidate(candidate, target):
            return candidate

    return (original + 1) & 0xFFFFFFFF if original != 1 else 2


def create_config(
    target: TxnPrevCycleModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    """Create an A4 mutation config file for TXN_PREV_CYCLE_MOD."""
    config = {
        "mutation_type": "TXN_PREV_CYCLE_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "prev_cycle": mutated_value,
        "_info": {
            "addr": f"0x{target.addr:08x}",
            "original_prev_cycle": target.original_prev_cycle,
            "original_cycle": target.original_cycle,
            "original_word": target.original_word,
            "original_prev_word": target.original_prev_word,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
