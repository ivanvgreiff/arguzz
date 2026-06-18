"""
TXN_PREV_WORD_MOD Mutation (Standalone)

Mutates txn.prev_word on memory or register transactions. Two strategies:
- at_read: target READ txns → break IsRead (prev_word != word)
- at_write: target WRITE txns → break memory permutation chain
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4AllTxn


@dataclass
class TxnPrevWordModTarget:
    """Target for a TXN_PREV_WORD_MOD mutation."""
    step: int
    cycle_idx: int
    txn_idx: int
    addr: int
    is_read: bool
    original_prev_word: int
    original_word: int
    original_prev_cycle: int
    strategy: str  # "at_read" or "at_write"


def get_targets_at_step(
    step: int,
    data: "InspectionData",
    strategy: str = "at_read",
) -> List[TxnPrevWordModTarget]:
    """Return all valid targets at this step for the given strategy."""
    if step == 0 or strategy not in ("at_read", "at_write"):
        return []

    cycle = data.get_cycle(step)
    if not cycle:
        return []

    txns = data.get_all_txns_at_step(step)
    targets: List[TxnPrevWordModTarget] = []
    for txn in txns:
        if strategy == "at_read" and not txn.is_read():
            continue
        if strategy == "at_write" and not txn.is_write():
            continue
        targets.append(
            TxnPrevWordModTarget(
                step=step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                is_read=txn.is_read(),
                original_prev_word=txn.prev_word,
                original_word=txn.word,
                original_prev_cycle=txn.prev_cycle,
                strategy=strategy,
            )
        )
    return targets


def get_all_targets(
    data: "InspectionData",
    strategy: str = "at_read",
    zone_filter=None,
) -> List[TxnPrevWordModTarget]:
    """Iterate all txns globally for arm-space construction."""
    del zone_filter  # reserved for D2.D zone filtering
    step_to_cycle = {c.step: c for c in data.cycles}
    targets: List[TxnPrevWordModTarget] = []
    for txn in data.all_txns:
        if txn.step == 0:
            continue
        if strategy == "at_read" and not txn.is_read():
            continue
        if strategy == "at_write" and not txn.is_write():
            continue
        cycle = step_to_cycle.get(txn.step)
        if not cycle:
            continue
        targets.append(
            TxnPrevWordModTarget(
                step=txn.step,
                cycle_idx=cycle.cycle_idx,
                txn_idx=txn.txn_idx,
                addr=txn.addr,
                is_read=txn.is_read(),
                original_prev_word=txn.prev_word,
                original_word=txn.word,
                original_prev_cycle=txn.prev_cycle,
                strategy=strategy,
            )
        )
    return targets


def generate_new_value(target: TxnPrevWordModTarget, rng: random.Random) -> int:
    """Mixed strategy: 33% bit-flip, 33% nearby, 34% random u32."""
    original = target.original_prev_word
    roll = rng.random()
    if roll < 0.33:
        candidate = original ^ (1 << rng.randint(0, 31))
    elif roll < 0.66:
        delta = rng.choice([-1, 1, -256, 256])
        candidate = (original + delta) & 0xFFFFFFFF
    else:
        candidate = rng.getrandbits(32)
    if candidate == original:
        candidate = (original + 1) & 0xFFFFFFFF
    return candidate


def create_config(
    target: TxnPrevWordModTarget,
    mutated_value: int,
    output_path: Path,
) -> Path:
    """Create an A4 mutation config file for TXN_PREV_WORD_MOD."""
    config = {
        "mutation_type": "TXN_PREV_WORD_MOD",
        "step": target.step,
        "txn_idx": target.txn_idx,
        "prev_word": mutated_value,
        "strategy": target.strategy,
        "_info": {
            "addr": f"0x{target.addr:08x}",
            "is_read": target.is_read,
            "original_prev_word": target.original_prev_word,
            "original_word": target.original_word,
            "original_prev_cycle": target.original_prev_cycle,
        },
    }
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
