"""
Phase 1 (cloud1) — migration test: ensure opening an existing IV.POS.5 DB
with the v2 codebase adds the 8 new tables WITHOUT touching existing data.

This is the safety net against regressions where extending `_init_schema`
might accidentally truncate or alter existing tables.

If no IV.POS.5 DB is available in `a4/runs/iv_pos_5/`, the test is
skipped with an informative message.
"""

import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from a4.standalone.coverage_db import CoverageDB


REPO_ROOT = Path(__file__).resolve().parents[3]
IV_POS_5_DIR = REPO_ROOT / "a4" / "runs" / "iv_pos_5"


def _find_iv_pos_5_db() -> Path:
    candidates = sorted(IV_POS_5_DIR.rglob("pos_ab_v1*_seed*_n*.db"))
    if not candidates:
        pytest.skip("no IV.POS.5 DB found; migration test requires real data")
    return candidates[0]


def test_open_iv_pos_5_db_adds_v2_tables(tmp_path):
    """Open an IV.POS.5 DB via v2 codebase; check old data is intact and
    new tables exist."""
    src = _find_iv_pos_5_db()
    work = tmp_path / src.name
    shutil.copy2(src, work)

    # Pre-migration snapshot of legacy tables
    pre = sqlite3.connect(work)
    pre.row_factory = sqlite3.Row
    pre_counts = {
        "campaigns": pre.execute("SELECT COUNT(*) AS c FROM campaigns").fetchone()["c"],
        "mutations": pre.execute("SELECT COUNT(*) AS c FROM mutations").fetchone()["c"],
        "failures":  pre.execute("SELECT COUNT(*) AS c FROM failures").fetchone()["c"],
        "coverage":  pre.execute("SELECT COUNT(*) AS c FROM coverage").fetchone()["c"],
    }
    pre.close()

    # Open through v2 CoverageDB → triggers _init_schema (idempotent CREATE IF NOT EXISTS)
    db = CoverageDB(str(work))

    # Verify pre-existing counts unchanged
    post_counts = {
        "campaigns": db.conn.execute("SELECT COUNT(*) AS c FROM campaigns").fetchone()["c"],
        "mutations": db.conn.execute("SELECT COUNT(*) AS c FROM mutations").fetchone()["c"],
        "failures":  db.conn.execute("SELECT COUNT(*) AS c FROM failures").fetchone()["c"],
        "coverage":  db.conn.execute("SELECT COUNT(*) AS c FROM coverage").fetchone()["c"],
    }
    assert pre_counts == post_counts, f"row counts changed by migration: {pre_counts} → {post_counts}"

    # Verify new v2 tables exist (and are empty for this legacy DB)
    new_tables = {
        "bandit_decisions", "arm_state_snapshot", "reward_counterfactuals",
        "mutation_substrategy", "hook3_raw", "pilot_runs",
        "compressed_global_coverage", "local_coverage_v2",
    }
    rows = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    actual = {r["name"] for r in rows}
    missing = new_tables - actual
    assert not missing, f"v2 tables not added by migration: {missing}"

    for t in new_tables:
        c = db.conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"]
        assert c == 0, f"v2 table {t} should be empty after migration, got {c} rows"

    db.conn.close()


def test_old_analysis_query_still_works(tmp_path):
    """Verify a representative legacy analysis SQL still returns sensible
    data on a migrated DB."""
    src = _find_iv_pos_5_db()
    work = tmp_path / src.name
    shutil.copy2(src, work)
    db = CoverageDB(str(work))

    row = db.conn.execute("""
        SELECT m.kind, COUNT(*) AS n
        FROM mutations m
        GROUP BY m.kind
        ORDER BY n DESC
    """).fetchall()
    assert len(row) > 0
    total = sum(r["n"] for r in row)
    assert total >= 5999, f"expected ~6000 mutations, got {total}"
    db.conn.close()
