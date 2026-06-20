"""Shared helpers for D2.E pre-POS integration gates."""

from __future__ import annotations

import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Set

from a4.standalone.coverage_db import CoverageDB

CANONICAL_LOC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*@[A-Za-z0-9_.]+:\d+$")

COMPARABILITY_TABLES: FrozenSet[str] = frozenset({
    "campaigns",
    "campaign_params",
    "mutations",
    "failures",
    "coverage",
    "mutation_rewards",
    "reward_counterfactuals",
    "mutation_substrategy",
    "compressed_global_coverage",
    "global_failures",
    "bandit_decisions",
    "local_coverage_v2",
})

FRESH_VARIANT_REQUIRED_COLUMNS: Dict[str, FrozenSet[str]] = {
    "mutations": frozenset({
        "outcome", "proof_generated", "proof_verify_failed", "elapsed_ms",
    }),
    "reward_counterfactuals": frozenset({
        "bandit_success_l1",
        "l1_substrategy_uniqueness",
        "l1_d_loc_le_2",
        "l1_singleton_failure",
    }),
}

V5_ARCHIVE_PATH = (
    Path(__file__).resolve().parents[2]
    / "runs" / "iv_pos_7" / "dbs"
    / "2026-06-14_03-00-16_498814" / "polynize"
    / "pos_iv_pos_7_ts_b1_cTS_semantic_v2_seed1234_n6000.db"
)

D2C_V6_UNIFORM_SMOKE_DB = (
    Path(__file__).resolve().parents[2]
    / "runs" / "d2c_v6_uniform_smoke" / "flare"
    / "d2c_v6_uniform_smoke_v1_v6_uniform_seed1243_n50.db"
)


def table_columns(db_path: Path, table: str) -> Set[str]:
    with sqlite3.connect(db_path) as conn:
        return {
            row[1]
            for row in conn.execute(f"PRAGMA table_info({table})")
        }


def list_tables(db_path: Path) -> Set[str]:
    with sqlite3.connect(db_path) as conn:
        return {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }


def fresh_reference_db_path() -> Path:
    """Minimal fresh DB with current schema migrations applied."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = CoverageDB(tmp.name)
    cid = db.start_campaign("/bin/true", ["--in1", "5"], "INSTR_TYPE_MOD", seed=1)
    mid = db.record_mutation(
        cid, "INSTR_TYPE_MOD", 0, 42, {"kind": "INSTR_TYPE_MOD", "step": 0},
        verifier_accepted=False, outcome="applied",
    )
    db.record_reward_counterfactuals(
        mid, 0.1, 0.1, 0.0, 1, 0.0,
        bandit_success_l1=1,
        l1_d_loc_le_2=0,
        l1_singleton_failure=0,
        l1_substrategy_uniqueness=0,
    )
    db.conn.close()
    return Path(tmp.name)


def schema_gaps_vs_fresh(archive_path: Path, fresh_path: Path) -> dict[str, set[str]]:
    gaps: dict[str, set[str]] = {}
    for table, required in FRESH_VARIANT_REQUIRED_COLUMNS.items():
        archive_cols = table_columns(archive_path, table)
        fresh_cols = table_columns(fresh_path, table)
        missing = set(required) - archive_cols
        if missing:
            gaps[table] = missing
        extra_fresh = fresh_cols - archive_cols
        if extra_fresh & set(required):
            gaps.setdefault(table, set()).update(extra_fresh & set(required))
    return gaps


def assert_all_failure_locs_canonical(db_path: Path, *, limit: int = 500) -> None:
    with sqlite3.connect(db_path) as conn:
        locs = [
            row[0]
            for row in conn.execute(
                f"SELECT constraint_loc FROM failures LIMIT {limit}"
            ).fetchall()
        ]
    for loc in locs:
        assert CANONICAL_LOC_RE.match(loc), f"non-canonical failure loc: {loc!r}"


def v5_archive_path() -> Optional[Path]:
    return V5_ARCHIVE_PATH if V5_ARCHIVE_PATH.is_file() else None
