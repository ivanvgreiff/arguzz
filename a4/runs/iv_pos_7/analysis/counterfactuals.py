"""Phase 9.4 — reward counterfactual analysis (Pro §12)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from .discover import discover_dbs

KINDS = [
    "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD", "MEM_VAL_MOD", "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR",
]


def _kind_rewards_for_db(db_path: Path) -> List[dict]:
    with sqlite3.connect(db_path) as conn:
        try:
            rows = conn.execute("""
                SELECT m.kind,
                       AVG(rc.current_reward) AS current_reward,
                       AVG(rc.no_qloc_reward) AS no_qloc_reward,
                       AVG(rc.discovery_binary_reward) AS discovery_binary_reward,
                       AVG(rc.compressed_global_reward) AS compressed_global_reward,
                       COUNT(*) AS n
                FROM mutations m
                JOIN reward_counterfactuals rc ON rc.mutation_id = m.id
                GROUP BY m.kind
            """).fetchall()
        except sqlite3.OperationalError:
            return []
    return [
        {
            "kind": r[0],
            "current_reward": float(r[1] or 0),
            "no_qloc_reward": float(r[2] or 0),
            "discovery_binary_reward": float(r[3] or 0),
            "compressed_global_reward": float(r[4] or 0),
            "n": int(r[5]),
        }
        for r in rows
    ]


def counterfactual_by_kind_frame(dbs_root: Optional[Path] = None) -> pd.DataFrame:
    """Per (variant, seed, kind) mean counterfactual rewards."""
    m = discover_dbs(dbs_root) if dbs_root else discover_dbs()
    rows: List[dict] = []
    for variant in ("V1", "V2", "V3", "V4", "V5"):
        for seed, db in sorted(m[variant].items()):
            for kr in _kind_rewards_for_db(db):
                rows.append({"variant": variant, "seed": seed, "db_path": str(db), **kr})
    return pd.DataFrame(rows)


def counterfactual_kind_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate per (variant, kind) across seeds."""
    if df.empty:
        return df
    return (
        df.groupby(["variant", "kind"])[
            ["current_reward", "no_qloc_reward", "discovery_binary_reward", "compressed_global_reward", "n"]
        ]
        .mean()
        .reset_index()
    )


def instr_type_mod_ranking_check(summary: pd.DataFrame) -> Dict[str, object]:
    """Pro §12: discovery_binary should rank INSTR_TYPE_MOD higher than current_reward."""
    out: Dict[str, object] = {}
    for variant in summary["variant"].unique():
        sub = summary[summary["variant"] == variant].set_index("kind")
        if "INSTR_TYPE_MOD" not in sub.index:
            out[variant] = {"error": "INSTR_TYPE_MOD missing"}
            continue
        it = sub.loc["INSTR_TYPE_MOD"]
        # Rank by mean reward among kinds (1 = highest)
        cur_rank = int(sub["current_reward"].rank(ascending=False).loc["INSTR_TYPE_MOD"])
        disc_rank = int(sub["discovery_binary_reward"].rank(ascending=False).loc["INSTR_TYPE_MOD"])
        noq_rank = int(sub["no_qloc_reward"].rank(ascending=False).loc["INSTR_TYPE_MOD"])
        out[variant] = {
            "current_reward_rank": cur_rank,
            "discovery_binary_rank": disc_rank,
            "no_qloc_reward_rank": noq_rank,
            "discovery_ranks_higher_than_current": disc_rank < cur_rank,
            "current_reward": float(it["current_reward"]),
            "discovery_binary_reward": float(it["discovery_binary_reward"]),
        }
    return out
