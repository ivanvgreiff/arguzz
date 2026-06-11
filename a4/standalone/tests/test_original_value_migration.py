"""Phase 7d (P2) — mutations.original_value column migration."""

import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from a4.standalone.coverage_db import CoverageDB

REPO_ROOT = Path(__file__).resolve().parents[3]
IV_POS_5_DIR = REPO_ROOT / "a4" / "runs" / "iv_pos_5"


def _find_legacy_db() -> Path:
    candidates = sorted(IV_POS_5_DIR.rglob("pos_ab_v1*_seed*_n*.db"))
    if not candidates:
        pytest.skip("no IV.POS.5 DB found; migration test requires real data")
    return candidates[0]


def test_legacy_db_gains_original_value_column(tmp_path):
    src = _find_legacy_db()
    work = tmp_path / src.name
    shutil.copy2(src, work)

    pre = sqlite3.connect(work)
    cols = {row[1] for row in pre.execute("PRAGMA table_info(mutations)")}
    pre.close()
    assert "original_value" not in cols, "fixture DB should predate P2 column"

    db = CoverageDB(str(work))
    post_cols = {row[1] for row in db.conn.execute("PRAGMA table_info(mutations)")}
    assert "original_value" in post_cols

    n = db.conn.execute("SELECT COUNT(*) AS c FROM mutations").fetchone()["c"]
    zeros = db.conn.execute(
        "SELECT COUNT(*) AS c FROM mutations WHERE original_value = 0"
    ).fetchone()["c"]
    assert zeros == n, "legacy rows should default original_value to 0"
    db.conn.close()
