"""D2.G per-DB metrics — adapts iv_pos_7/analysis with F18 V6_uniform handling."""
from __future__ import annotations

import math
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

import numpy as np
import pandas as pd

from a4.runs.iv_pos_7.analysis.constraint_loc_normalize import read_normalized_constraint_locs
from a4.runs.iv_pos_7.analysis.discovery_rate import discovery_rate_by_kind_frame
from a4.runs.iv_pos_7.analysis.metrics import (
    _coverage_curve,
    _read_first_hits,
    _shannon_entropy,
    _zone_entropy_from_bandit,
    _zone_entropy_from_mutations,
)

from .discover import D2F_VARIANTS, flat_db_list, parse_d2f_run_dir

CTS_VARIANTS = frozenset({"V6_cTS", "Hybrid_cTS"})
UNIFORM_VARIANT = "V6_uniform"


def _outcome_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    if "outcome" not in {r[1] for r in conn.execute("PRAGMA table_info(mutations)")}:
        return {}
    rows = conn.execute(
        "SELECT outcome, COUNT(*) FROM mutations GROUP BY outcome"
    ).fetchall()
    return {str(o or "NULL"): int(c) for o, c in rows}


def _v6_uniform_failures_proximity(conn: sqlite3.Connection) -> Dict[str, float]:
    """F18 — derive d_loc/singleton signals from failures when rewards empty."""
    try:
        rows = conn.execute(
            """
            SELECT m.id,
                   COUNT(DISTINCT f.constraint_loc) AS locs,
                   COUNT(f.id) AS fail_n
            FROM mutations m
            LEFT JOIN failures f ON f.mutation_id = m.id
            GROUP BY m.id
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return {"failures_derived_d_loc_le_2_rate": float("nan"), "failures_derived_singleton_rate": float("nan")}
    if not rows:
        return {"failures_derived_d_loc_le_2_rate": 0.0, "failures_derived_singleton_rate": 0.0}
    d_le2 = sum(1 for _mid, locs, _fn in rows if locs <= 2)
    singleton = sum(1 for _mid, _locs, fn in rows if fn == 1)
    n = len(rows)
    return {
        "failures_derived_d_loc_le_2_rate": d_le2 / n,
        "failures_derived_singleton_rate": singleton / n,
    }


def compute_d2g_metrics_for_db(db_path: Path) -> Dict[str, object]:
    variant, seed, n = parse_d2f_run_dir(db_path.parent)
    with sqlite3.connect(db_path) as conn:
        first_hits = _read_first_hits(conn)
        curve = _coverage_curve(first_hits, n=n)
        local_final = int(curve[-1]) if len(curve) else 0
        auc = float(np.trapezoid(curve, dx=1.0)) if len(curve) else 0.0

        try:
            lc_v2_final = int(conn.execute(
                "SELECT COUNT(*) FROM local_coverage_v2"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            lc_v2_final = float("nan")

        try:
            cgc = int(conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            cgc = 0

        n_mut = int(conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0])
        kind_counts = Counter(r[0] for r in conn.execute("SELECT kind FROM mutations"))
        alloc_entropy_kind = _shannon_entropy(kind_counts)

        bandit_zone_ent = _zone_entropy_from_bandit(conn)
        alloc_entropy_zone = (
            bandit_zone_ent if bandit_zone_ent is not None
            else _zone_entropy_from_mutations(conn)
        )

        norm_locs = read_normalized_constraint_locs(conn)
        outcomes = _outcome_counts(conn)
        applied = outcomes.get("applied", 0)
        skipped = outcomes.get("skipped", 0)
        errors = outcomes.get("error", 0)

        has_rewards = bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mutation_rewards'"
        ).fetchone())
        rewards_nonempty = False
        if has_rewards:
            try:
                rewards_nonempty = int(conn.execute(
                    "SELECT COUNT(*) FROM mutation_rewards"
                ).fetchone()[0]) > 0
            except sqlite3.OperationalError:
                rewards_nonempty = False

        f18 = _v6_uniform_failures_proximity(conn) if variant == UNIFORM_VARIANT else {}

        has_bandit = bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='bandit_decisions'"
        ).fetchone())
        bandit_pulls = 0
        if has_bandit:
            try:
                bandit_pulls = int(conn.execute(
                    "SELECT COUNT(*) FROM bandit_decisions"
                ).fetchone()[0])
            except sqlite3.OperationalError:
                bandit_pulls = 0

    row: Dict[str, object] = {
        "variant": variant,
        "seed": seed,
        "expected_n": n,
        "db_path": str(db_path),
        "n_mutations": n_mut,
        "local_context_final": local_final,
        "local_coverage_v2_final": lc_v2_final,
        "local_context_AUC": auc,
        "compressed_global_context_final": cgc,
        "allocation_entropy_by_kind": alloc_entropy_kind,
        "allocation_entropy_by_zone": alloc_entropy_zone,
        "unique_normalized_locs": len(norm_locs),
        "applied_count": applied,
        "skipped_count": skipped,
        "error_count": errors,
        "applied_rate": applied / n_mut if n_mut else 0.0,
        "telemetry_sparse": variant == UNIFORM_VARIANT and not rewards_nonempty,
        "bandit_decisions_count": bandit_pulls if variant in CTS_VARIANTS or variant == "Hybrid_cTS" else float("nan"),
        "arm_occupancy_available": variant in CTS_VARIANTS or variant == "Hybrid_cTS",
    }
    row.update(f18)
    return row


def compute_d2g_metrics_frame(collection_root: Path) -> pd.DataFrame:
    rows = [compute_d2g_metrics_for_db(db) for db in flat_db_list(collection_root)]
    return pd.DataFrame(rows)


def aggregate_d2g_metrics(df: pd.DataFrame) -> pd.DataFrame:
    numeric = [
        "local_context_final", "local_coverage_v2_final", "local_context_AUC",
        "compressed_global_context_final", "allocation_entropy_by_kind",
        "allocation_entropy_by_zone", "unique_normalized_locs",
        "applied_rate", "failures_derived_d_loc_le_2_rate",
        "failures_derived_singleton_rate",
    ]
    present = [c for c in numeric if c in df.columns]
    agg = df.groupby("variant")[present].agg(["mean", "std", "count"])
    agg.columns = ["_".join(c).strip("_") for c in agg.columns]
    return agg.reset_index()


def discovery_rate_frame(collection_root: Path) -> pd.DataFrame:
    """Per-kind discovery rates — uses iv_pos_7 helper on symlinked paths."""
    # discovery_rate_by_kind_frame expects iv_pos_7 layout; build inline instead.
    rows: List[dict] = []
    for db in flat_db_list(collection_root):
        variant, seed, n = parse_d2f_run_dir(db.parent)
        with sqlite3.connect(db) as conn:
            kind_counts = Counter(r[0] for r in conn.execute("SELECT kind FROM mutations"))
            fail_by_kind = Counter(
                r[0] for r in conn.execute(
                    """
                    SELECT m.kind FROM failures f
                    JOIN mutations m ON m.id = f.mutation_id
                    """
                )
            )
        for kind in sorted(kind_counts):
            pulls = kind_counts[kind]
            fails = fail_by_kind.get(kind, 0)
            rows.append({
                "variant": variant,
                "seed": seed,
                "kind": kind,
                "pulls": pulls,
                "failures": fails,
                "failure_rate": fails / pulls if pulls else 0.0,
                "pulls_per_1k": 1000.0 * pulls / n if n else 0.0,
            })
    return pd.DataFrame(rows)
