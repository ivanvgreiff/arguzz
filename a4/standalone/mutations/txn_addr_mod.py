"""
TXN_ADDR_MOD Mutation (Standalone)

Mutates txn.addr on non-fetch, non-register memory transactions.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, TYPE_CHECKING

from a4.standalone.mutations.mem_val_mod import _is_instruction_fetch

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


@dataclass
class TxnAddrModTarget:
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    original_addr: int
    original_cycle: int
    original_word: int
    original_prev_word: int
    original_prev_cycle: int


def _eligible_txns(step: int, data: "InspectionData") -> List[TxnAddrModTarget]:
    cycle = data.get_cycle(step)
    if not cycle or step == 0:
        return []

    targets: List[TxnAddrModTarget] = []
    for txn in data.get_all_txns_at_step(step):
        if txn.is_register():
            continue
        if _is_instruction_fetch(txn, cycle):
            continue
        targets.append(
            TxnAddrModTarget(
                step=step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                original_addr=txn.addr,
                original_cycle=txn.cycle,
                original_word=txn.word,
                original_prev_word=txn.prev_word,
                original_prev_cycle=txn.prev_cycle,
            )
        )
    return targets


def get_targets_at_step(step: int, data: "InspectionData") -> List[TxnAddrModTarget]:
    return _eligible_txns(step, data)


def get_all_targets(data: "InspectionData") -> List[TxnAddrModTarget]:
    targets: List[TxnAddrModTarget] = []
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        targets.extend(_eligible_txns(cycle.step, data))
    return targets


def generate_new_value(target: TxnAddrModTarget, rng: random.Random, data: "InspectionData") -> int:
    original = target.original_addr
    roll = rng.random()

    for _ in range(32):
        if roll < 0.40:
            candidate = (original + rng.choice([-8, -4, -2, -1, 1, 2, 4, 8])) & 0xFFFFFFFF
        elif roll < 0.70:
            same_step_addrs = [
                t.addr for t in data.get_all_txns_at_step(target.step)
                if t.txn_idx != target.txn_idx and not t.is_register()
            ]
            candidate = rng.choice(same_step_addrs) if same_step_addrs else rng.getrandbits(32)
        else:
            candidate = rng.getrandbits(32)

        if candidate != original:
            return candidate

    return (original + 1) & 0xFFFFFFFF


def create_config(
    target: TxnAddrModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    config = {
        "mutation_type": "TXN_ADDR_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "addr": mutated_value,
        "_info": {
            "original_addr": target.original_addr,
            "original_cycle": target.original_cycle,
            "original_word": target.original_word,
            "original_prev_word": target.original_prev_word,
            "original_prev_cycle": target.original_prev_cycle,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
