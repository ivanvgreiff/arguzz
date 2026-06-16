"""Phase 9.5 — V5 per-arm diagnostic (cTS_semantic_v2)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from .discover import discover_dbs

V5_VARIANT = "V5"


def _pulls_by_mode(db_path: Path) -> pd.DataFrame:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("""
            SELECT mode, selected_arm, COUNT(*) AS pulls
            FROM bandit_decisions
            GROUP BY mode, selected_arm
        """).fetchall()
    return pd.DataFrame(rows, columns=["mode", "selected_arm", "pulls"])


def _mode_totals(db_path: Path) -> Dict[str, int]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("""
            SELECT mode, COUNT(*) FROM bandit_decisions GROUP BY mode
        """).fetchall()
    return {r[0]: int(r[1]) for r in rows}


def _final_arm_state(db_path: Path) -> pd.DataFrame:
    """Latest arm_state_snapshot row per arm_id (max mutation_idx)."""
    with sqlite3.connect(db_path) as conn:
        try:
            max_idx = conn.execute(
                "SELECT MAX(mutation_idx) FROM arm_state_snapshot"
            ).fetchone()[0]
            if max_idx is None:
                return pd.DataFrame()
            rows = conn.execute("""
                SELECT arm_id, pulls, discounted_pulls, mean_reward,
                       posterior_alpha, posterior_beta, ts_extra_json
                FROM arm_state_snapshot
                WHERE mutation_idx = ?
            """, (max_idx,)).fetchall()
        except sqlite3.OperationalError:
            return pd.DataFrame()
    return pd.DataFrame(
        rows,
        columns=[
            "arm_id", "pulls", "discounted_pulls", "mean_reward",
            "posterior_alpha", "posterior_beta", "ts_extra_json",
        ],
    )


def _cumulative_reward_by_arm(db_path: Path) -> pd.DataFrame:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("""
            SELECT bd.selected_arm AS arm_id, SUM(mr.reward) AS cumulative_reward,
                   COUNT(*) AS n_mutations, AVG(mr.reward) AS mean_reward
            FROM bandit_decisions bd
            JOIN mutation_rewards mr ON mr.mutation_id = bd.mutation_id
            GROUP BY bd.selected_arm
        """).fetchall()
    return pd.DataFrame(
        rows,
        columns=["arm_id", "cumulative_reward", "n_mutations", "mean_reward"],
    )


def per_arm_diagnostic_frame(dbs_root: Optional[Path] = None) -> Dict[str, pd.DataFrame]:
    """V5 per-seed diagnostics: mode pulls, final posterior, cumulative reward."""
    m = discover_dbs(dbs_root) if dbs_root else discover_dbs()
    mode_rows: List[dict] = []
    pull_rows: List[dict] = []
    state_rows: List[dict] = []
    cum_rows: List[dict] = []

    for seed, db in sorted(m[V5_VARIANT].items()):
        totals = _mode_totals(db)
        for mode, n in totals.items():
            mode_rows.append({"seed": seed, "mode": mode, "pulls": n, "db_path": str(db)})

        pulls = _pulls_by_mode(db)
        for _, r in pulls.iterrows():
            pull_rows.append({"seed": seed, **r.to_dict(), "db_path": str(db)})

        state = _final_arm_state(db)
        for _, r in state.iterrows():
            state_rows.append({"seed": seed, **r.to_dict(), "db_path": str(db)})

        cum = _cumulative_reward_by_arm(db)
        for _, r in cum.iterrows():
            cum_rows.append({"seed": seed, **r.to_dict(), "db_path": str(db)})

    return {
        "mode_totals": pd.DataFrame(mode_rows),
        "pulls_by_mode_arm": pd.DataFrame(pull_rows),
        "final_arm_state": pd.DataFrame(state_rows),
        "cumulative_reward_by_arm": pd.DataFrame(cum_rows),
    }


def v5_mode_summary(mode_totals: pd.DataFrame) -> pd.DataFrame:
    """Mean pulls per mode across 10 V5 seeds."""
    if mode_totals.empty:
        return mode_totals
    return (
        mode_totals.groupby("mode")["pulls"]
        .agg(["mean", "std", "sum"])
        .reset_index()
        .rename(columns={"mean": "mean_pulls_per_seed", "std": "std_pulls", "sum": "total_pulls"})
    )
