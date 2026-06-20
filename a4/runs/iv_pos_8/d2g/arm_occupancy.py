"""Bandit arm occupancy / kind allocation over campaign phases (D2.G §5, F19 action 3)."""
from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from .discover import flat_db_list, parse_d2f_run_dir


def _kind_from_arm(selected_arm: str) -> str:
    """Extract mutation kind from bandit selected_arm (V5 2-pipe or Hybrid 5-pipe)."""
    parts = selected_arm.split("|")
    if len(parts) >= 2 and parts[0] in ("arguzz_exec_fault", "A4_trace_cell"):
        return parts[1]
    return parts[0]


def arm_occupancy_for_db(db_path: Path, *, split_at: int = 5000) -> List[Dict[str, object]]:
    """Per-DB kind allocation in early vs late campaign + INSTR_WORD_MOD share."""
    variant, seed, n = parse_d2f_run_dir(db_path.parent)
    rows: List[Dict[str, object]] = []
    with sqlite3.connect(db_path) as conn:
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='bandit_decisions'"
        ).fetchone():
            return rows
        q = """
            SELECT bd.mode, bd.selected_arm, m.id
            FROM bandit_decisions bd
            JOIN mutations m ON m.id = bd.mutation_id
            ORDER BY m.id
        """
        records = list(conn.execute(q))
        if not records:
            return rows

        early_kinds: Counter[str] = Counter()
        late_kinds: Counter[str] = Counter()
        mode_kinds: Counter[str] = Counter()
        for mode, arm, mid in records:
            kind = _kind_from_arm(arm)
            mode_kinds[f"{mode}|{kind}"] += 1
            if int(mid) <= split_at:
                early_kinds[kind] += 1
            else:
                late_kinds[kind] += 1

        total = len(records)
        early_total = sum(early_kinds.values())
        late_total = sum(late_kinds.values())
        for phase, counter, denom in (
            ("early", early_kinds, early_total),
            ("late", late_kinds, late_total),
            ("all", Counter(_kind_from_arm(a) for _m, a, _i in records), total),
        ):
            if denom == 0:
                continue
            iwm = counter.get("INSTR_WORD_MOD", 0) / denom
            rows.append({
                "variant": variant,
                "seed": seed,
                "expected_n": n,
                "phase": phase,
                "split_at_mutation_id": split_at if phase != "all" else "",
                "pulls": denom,
                "instr_word_mod_share": iwm,
                "instr_word_mod_pulls": counter.get("INSTR_WORD_MOD", 0),
                "top_kind": counter.most_common(1)[0][0] if counter else "",
                "top_kind_share": counter.most_common(1)[0][1] / denom if counter else 0.0,
                "kind_entropy": _entropy(counter),
            })

        for key, cnt in sorted(mode_kinds.items()):
            mode, kind = key.split("|", 1)
            rows.append({
                "variant": variant,
                "seed": seed,
                "expected_n": n,
                "phase": f"mode_{mode}",
                "split_at_mutation_id": "",
                "pulls": cnt,
                "instr_word_mod_share": 1.0 if kind == "INSTR_WORD_MOD" else 0.0,
                "instr_word_mod_pulls": cnt if kind == "INSTR_WORD_MOD" else 0,
                "top_kind": kind,
                "top_kind_share": cnt / total,
                "kind_entropy": float("nan"),
            })
    return rows


def _entropy(counter: Counter) -> float:
    import math
    n = sum(counter.values())
    if n == 0:
        return 0.0
    ent = 0.0
    for c in counter.values():
        p = c / n
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def arm_occupancy_frame(collection_root: Path, *, split_at: int = 5000) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    for db in flat_db_list(collection_root):
        rows.extend(arm_occupancy_for_db(db, split_at=split_at))
    return pd.DataFrame(rows)


def instr_word_mod_adaptive_correction(df: pd.DataFrame) -> pd.DataFrame:
    """Summarize early→late INSTR_WORD_MOD share delta per variant×seed."""
    if df.empty:
        return df
    sub = df[df["phase"].isin(("early", "late"))].copy()
    if sub.empty:
        return pd.DataFrame()
    pivot = sub.pivot_table(
        index=["variant", "seed"],
        columns="phase",
        values="instr_word_mod_share",
        aggfunc="first",
    ).reset_index()
    if "early" in pivot.columns and "late" in pivot.columns:
        pivot["iwm_share_delta_late_minus_early"] = pivot["late"] - pivot["early"]
        pivot["adaptive_reduced_iwm"] = pivot["iwm_share_delta_late_minus_early"] < 0
    return pivot
