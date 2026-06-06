#!/usr/bin/env python3
"""
Phase IV.0-prep unit tests for the `campaign_params` table and helpers.

Persists the calibrated reward params + bandit knobs used by one
campaign, so downstream aggregation/notebooks don't need to parse
terminal logs to recover tau_g, gamma, B_count, etc.

Run: python -m pytest a4/standalone/tests/test_coverage_db_campaign_params.py -v
"""

import json
import os
import tempfile

import pytest

from a4.standalone.coverage_db import CoverageDB


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    inst = CoverageDB(path)
    try:
        yield inst
    finally:
        inst.close()
        os.unlink(path)


def _start(db: CoverageDB) -> int:
    return db.start_campaign("/tmp/host", ["--in1", "5"], "all", seed=42)


# -----------------------------------------------------------------------------
# 1 — Schema
# -----------------------------------------------------------------------------

def test_campaign_params_table_exists(db):
    cur = db.conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='campaign_params'"
    )
    assert cur.fetchone() is not None

    cur.execute("PRAGMA table_info(campaign_params)")
    cols = {row[1] for row in cur.fetchall()}
    assert {
        "campaign_id", "tau_new", "tau_d", "tau_g", "gamma",
        "K_T_rare", "b_count", "selector", "extra_json", "recorded_at",
    }.issubset(cols)


# -----------------------------------------------------------------------------
# 2 — Record / readback
# -----------------------------------------------------------------------------

def test_record_and_readback_full_row(db):
    cid = _start(db)
    db.record_campaign_params(
        cid,
        tau_new=40.0, tau_d=3.0, tau_g=6.0, gamma=0.9965,
        K_T_rare=31, b_count=16, selector="bandit",
        extra={"num_arms": 248},
    )
    got = db.get_campaign_params(cid)
    assert got is not None
    assert got["campaign_id"] == cid
    assert got["tau_new"] == pytest.approx(40.0)
    assert got["tau_d"] == pytest.approx(3.0)
    assert got["tau_g"] == pytest.approx(6.0)
    assert got["gamma"] == pytest.approx(0.9965)
    assert got["K_T_rare"] == 31
    assert got["b_count"] == 16
    assert got["selector"] == "bandit"
    assert got["extra"] == {"num_arms": 248}
    assert isinstance(got["recorded_at"], str)


def test_get_returns_none_when_missing(db):
    cid = _start(db)
    assert db.get_campaign_params(cid) is None


def test_record_overwrites_on_same_campaign_id(db):
    """Re-calling with the same campaign_id should overwrite (INSERT OR REPLACE)."""
    cid = _start(db)
    db.record_campaign_params(cid, tau_g=1.0, gamma=0.5, selector="bandit")
    db.record_campaign_params(cid, tau_g=2.0, gamma=0.9, selector="bandit")
    got = db.get_campaign_params(cid)
    assert got["tau_g"] == pytest.approx(2.0)
    assert got["gamma"] == pytest.approx(0.9)

    # Only one row total
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM campaign_params WHERE campaign_id = ?", (cid,))
    assert cur.fetchone()[0] == 1


def test_record_with_minimal_args(db):
    """Most fields are nullable; minimal call should work and read back as Nones."""
    cid = _start(db)
    db.record_campaign_params(cid, selector="uniform")
    got = db.get_campaign_params(cid)
    assert got is not None
    assert got["selector"] == "uniform"
    assert got["tau_g"] is None
    assert got["b_count"] is None
    assert got.get("extra") is None  # no extra_json -> no extra


def test_extra_json_roundtrip_with_complex_value(db):
    cid = _start(db)
    extra = {"num_arms": 248, "step_buckets": [0, 245, 490, 735], "label": "iii6"}
    db.record_campaign_params(cid, selector="bandit", extra=extra)
    got = db.get_campaign_params(cid)
    assert got["extra"] == extra
    assert json.loads(got["extra_json"]) == extra


# -----------------------------------------------------------------------------
# 3 — Multi-campaign independence
# -----------------------------------------------------------------------------

def test_two_campaigns_dont_alias(db):
    c1 = _start(db)
    c2 = _start(db)
    assert c1 != c2
    db.record_campaign_params(c1, tau_g=1.0, selector="uniform")
    db.record_campaign_params(c2, tau_g=2.0, selector="bandit")
    assert db.get_campaign_params(c1)["tau_g"] == pytest.approx(1.0)
    assert db.get_campaign_params(c1)["selector"] == "uniform"
    assert db.get_campaign_params(c2)["tau_g"] == pytest.approx(2.0)
    assert db.get_campaign_params(c2)["selector"] == "bandit"


# -----------------------------------------------------------------------------
# 4 — Backward compatibility: an existing pre-IV.0 DB shouldn't be broken
# -----------------------------------------------------------------------------

def test_init_schema_is_idempotent_on_reopen(db):
    """Re-opening the DB shouldn't error or duplicate rows."""
    path = db.conn.execute("PRAGMA database_list").fetchone()["file"]
    cid = _start(db)
    db.record_campaign_params(cid, tau_g=1.0)

    # Close + reopen
    db.close()
    db2 = CoverageDB(path)
    try:
        got = db2.get_campaign_params(cid)
        assert got is not None
        assert got["tau_g"] == pytest.approx(1.0)
    finally:
        db2.close()


def test_pre_existing_db_without_table_gets_migrated(db):
    """If we drop the table to simulate a pre-IV.0 DB, reopening should re-create it."""
    path = db.conn.execute("PRAGMA database_list").fetchone()["file"]
    cid = _start(db)
    db.conn.execute("DROP TABLE campaign_params")
    db.conn.commit()
    db.close()

    # Reopen -> _init_schema runs again and CREATE IF NOT EXISTS recreates the table
    db2 = CoverageDB(path)
    try:
        cur = db2.conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='campaign_params'"
        )
        assert cur.fetchone() is not None
        # Now we can record/read
        db2.record_campaign_params(cid, tau_g=7.5)
        assert db2.get_campaign_params(cid)["tau_g"] == pytest.approx(7.5)
    finally:
        db2.close()
