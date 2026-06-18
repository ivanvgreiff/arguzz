"""
TXN_CYCLE_PHASE_MOD Mutation (Standalone)

Flips txn.cycle LSB (read/write phase) via deterministic XOR with 1.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, TYPE_CHECKING

from a4.standalone.mutations.mem_val_mod import _is_instruction_fetch

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class TxnCyclePhaseModTarget:
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    original_cycle: int
    original_word: int
    original_prev_word: int
    original_prev_cycle: int


def _eligible_txns(step: int, data: "InspectionData") -> List[TxnCyclePhaseModTarget]:
    cycle = data.get_cycle(step)
    if not cycle or step == 0:
        return []

    targets: List[TxnCyclePhaseModTarget] = []
    for txn in data.get_all_txns_at_step(step):
        if _is_instruction_fetch(txn, cycle):
            continue
        targets.append(
            TxnCyclePhaseModTarget(
                step=step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                original_cycle=txn.cycle,
                original_word=txn.word,
                original_prev_word=txn.prev_word,
                original_prev_cycle=txn.prev_cycle,
            )
        )
    return targets


def get_targets_at_step(step: int, data: "InspectionData") -> List[TxnCyclePhaseModTarget]:
    return _eligible_txns(step, data)


def get_all_targets(data: "InspectionData") -> List[TxnCyclePhaseModTarget]:
    targets: List[TxnCyclePhaseModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        targets.extend(_eligible_txns(cycle.step, data))
    return targets


def flipped_cycle(target: TxnCyclePhaseModTarget) -> int:
    return target.original_cycle ^ 1


def create_config(target: TxnCyclePhaseModTarget, output_path: Path) -> Path:
    new_cycle = flipped_cycle(target)
    config = {
        "mutation_type": "TXN_CYCLE_PHASE_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "_info": {
            "addr": f"0x{target.addr:08x}",
            "original_cycle": target.original_cycle,
            "new_cycle": new_cycle,
            "original_word": target.original_word,
            "original_prev_word": target.original_prev_word,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
