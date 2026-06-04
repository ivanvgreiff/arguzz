#!/usr/bin/env python3
"""
Phase III.1 unit tests for global_failures table and helpers in CoverageDB.

Run: python -m pytest a4/standalone/tests/test_coverage_db_global.py -v
"""

import os
import sqlite3
import tempfile

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.standalone.coverage_db import CoverageDB


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh on-disk SQLite (file, not :memory:, so re-open tests work)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    inst = CoverageDB(path)
    try:
        yield inst
    finally:
        inst.close()
        os.unlink(path)


def _start_campaign(db: CoverageDB) -> int:
    return db.start_campaign("/tmp/host", ["--in1", "5"], "all", seed=777)


def _record_mutation(db: CoverageDB, campaign_id: int, kind="COMP_OUT_MOD", step=10) -> int:
    return db.record_mutation(
        campaign_id=campaign_id,
        kind=kind,
        step=step,
        mutated_value=0,
        config={"step": step},
        txn_idx=None,
        verifier_accepted=False,
    )


def _local_failure(loc="MemoryWrite", file_line="mem.zir:99", major=2, minor=3):
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=major, minor=minor,
        loc=f"{loc}(zirgen/circuit/rv32im/v2/dsl/{file_line})",
        value=1,
    )


# -----------------------------------------------------------------------------
# Schema
# -----------------------------------------------------------------------------

class TestSchema:
    def test_global_failures_table_created(self, db):
        cur = db.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='global_failures'")
        assert cur.fetchone() is not None

    def test_global_failures_indices_created(self, db):
        cur = db.conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_gf%'")
        names = {r["name"] for r in cur.fetchall()}
        assert "idx_gf_mut" in names
        assert "idx_gf_ctx" in names

    def test_global_failures_table_idempotent(self, db):
        # Re-opening must not error or duplicate the table.
        cur = db.conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS global_failures ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "mutation_id INTEGER NOT NULL,"
                    "family TEXT NOT NULL,"
                    "address TEXT NOT NULL,"
                    "UNIQUE(mutation_id, family, address))")
        # Should still pass schema check
        db.conn.commit()
        # Reopen: simulate closing and reopening
        path = db.db_path
        db.close()
        re_db = CoverageDB(path)
        cur2 = re_db.conn.cursor()
        cur2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='global_failures'")
        assert cur2.fetchone() is not None
        re_db.close()


# -----------------------------------------------------------------------------
# record_global_failures
# -----------------------------------------------------------------------------

class TestRecordGlobalFailures:
    def test_basic_insert(self, db):
        cid = _start_campaign(db)
        mid = _record_mutation(db, cid)
        ctxs = {
            ("GLOBAL", "memory", "100"),
            ("GLOBAL", "u8", "5"),
            ("GLOBAL", "u16", "9"),
        }
        n = db.record_global_failures(mid, ctxs)
        assert n == 3
        cur = db.conn.cursor()
        cur.execute("SELECT family, address FROM global_failures WHERE mutation_id = ?", (mid,))
        rows = {(r["family"], r["address"]) for r in cur.fetchall()}
        assert rows == {("memory", "100"), ("u8", "5"), ("u16", "9")}

    def test_unique_idempotency(self, db):
        cid = _start_campaign(db)
        mid = _record_mutation(db, cid)
        ctxs = {("GLOBAL", "memory", "1"), ("GLOBAL", "memory", "2")}
        n1 = db.record_global_failures(mid, ctxs)
        n2 = db.record_global_failures(mid, ctxs)  # re-insert same keys
        assert n1 == 2
        assert n2 == 0  # all dropped by INSERT OR IGNORE
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM global_failures WHERE mutation_id = ?", (mid,))
        assert cur.fetchone()["c"] == 2

    def test_empty_input_is_noop(self, db):
        cid = _start_campaign(db)
        mid = _record_mutation(db, cid)
        assert db.record_global_failures(mid, set()) == 0
        assert db.record_global_failures(mid, None) == 0
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM global_failures")
        assert cur.fetchone()["c"] == 0

    def test_accepts_two_tuple_format(self, db):
        # Defensive path: accept (family, addr) without the "GLOBAL" prefix too.
        cid = _start_campaign(db)
        mid = _record_mutation(db, cid)
        n = db.record_global_failures(mid, [("memory", 42), ("u8", 7)])
        assert n == 2
        cur = db.conn.cursor()
        cur.execute("SELECT family, address FROM global_failures WHERE mutation_id = ?", (mid,))
        rows = {(r["family"], r["address"]) for r in cur.fetchall()}
        assert rows == {("memory", "42"), ("u8", "7")}


# -----------------------------------------------------------------------------
# Query helpers
# -----------------------------------------------------------------------------

class TestQueryHelpers:
    def test_get_global_contexts_for_campaign(self, db):
        cid = _start_campaign(db)
        m1 = _record_mutation(db, cid, step=10)
        m2 = _record_mutation(db, cid, step=20)
        db.record_global_failures(m1, {("GLOBAL", "memory", "1"), ("GLOBAL", "u8", "2")})
        db.record_global_failures(m2, {("GLOBAL", "memory", "1"), ("GLOBAL", "u16", "9")})
        ctxs = db.get_global_contexts_for_campaign(cid)
        # Distinct across mutations: memory:1 (shared), u8:2, u16:9
        assert ctxs == {("memory", "1"), ("u8", "2"), ("u16", "9")}

    def test_get_global_contexts_isolation_across_campaigns(self, db):
        # Different campaign rows must not bleed.
        c1 = _start_campaign(db)
        c2 = _start_campaign(db)
        m1 = _record_mutation(db, c1)
        m2 = _record_mutation(db, c2)
        db.record_global_failures(m1, {("GLOBAL", "memory", "1")})
        db.record_global_failures(m2, {("GLOBAL", "u8", "5")})
        assert db.get_global_contexts_for_campaign(c1) == {("memory", "1")}
        assert db.get_global_contexts_for_campaign(c2) == {("u8", "5")}

    def test_get_extended_contexts_unions_local_and_global(self, db):
        cid = _start_campaign(db)
        m1 = _record_mutation(db, cid, step=10)
        # local failure
        db.record_failures(m1, [_local_failure("MemoryWrite", "mem.zir:99", 2, 3)])
        # global failure
        db.record_global_failures(m1, {("GLOBAL", "memory", "100")})

        ext = db.get_extended_contexts_for_campaign(cid)
        # Should be union; local 3-tuple AND ("GLOBAL", family, addr) tuple.
        # Local key shape mirrors get_distinct_context_ids_for_campaign().
        local_part = db.get_distinct_context_ids_for_campaign(cid)
        assert local_part.issubset(ext)
        assert ("GLOBAL", "memory", "100") in ext
        # No raw 2-tuple sneaks in.
        assert ("memory", "100") not in ext

    def test_get_extended_is_superset_of_local(self, db):
        # Acceptance criterion from the master plan.
        cid = _start_campaign(db)
        mid = _record_mutation(db, cid)
        db.record_failures(mid, [
            _local_failure("MemoryWrite", "mem.zir:99", 2, 3),
            _local_failure("IsRead", "mem.zir:79", 2, 4),
        ])
        db.record_global_failures(mid, {("GLOBAL", "memory", "1234")})
        local = db.get_distinct_context_ids_for_campaign(cid)
        ext = db.get_extended_contexts_for_campaign(cid)
        assert local.issubset(ext)
        assert len(ext) == len(local) + 1

    def test_global_failure_counts_per_mutation(self, db):
        cid = _start_campaign(db)
        m1 = _record_mutation(db, cid, step=10)
        m2 = _record_mutation(db, cid, step=20)  # zero globals
        m3 = _record_mutation(db, cid, step=30)
        db.record_global_failures(m1, {("GLOBAL", "memory", "1"), ("GLOBAL", "u8", "5")})
        db.record_global_failures(m3, {("GLOBAL", "memory", "9")})
        counts = dict(db.get_global_failure_counts_per_mutation(cid))
        assert counts[m1] == 2
        assert counts[m2] == 0  # LEFT JOIN keeps zero rows
        assert counts[m3] == 1


# -----------------------------------------------------------------------------
# Legacy-DB compatibility
# -----------------------------------------------------------------------------

class TestLegacyDB:
    def test_legacy_db_readable_after_migration(self, tmp_path):
        # Simulate a legacy DB: build one without global_failures, then re-open.
        path = str(tmp_path / "legacy.db")
        # Manually create old schema (failures only)
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_binary TEXT, host_args TEXT, kind TEXT,
            seed INTEGER, started_at TEXT, ended_at TEXT)""")
        conn.execute("""CREATE TABLE mutations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER, kind TEXT, step INTEGER,
            txn_idx INTEGER, mutated_value INTEGER, config_json TEXT,
            executed_at TEXT, num_failures INTEGER, verifier_accepted INTEGER)""")
        conn.execute("INSERT INTO campaigns (host_binary, host_args, kind, started_at) VALUES ('h','[]','all','t')")
        cid = conn.execute("SELECT id FROM campaigns").fetchone()[0]
        conn.execute("INSERT INTO mutations (campaign_id, kind, step, mutated_value, config_json, executed_at) VALUES (?, 'X', 1, 0, '{}', 't')", (cid,))
        conn.commit()
        conn.close()

        # Re-open via CoverageDB: should auto-migrate by adding global_failures.
        db = CoverageDB(path)
        try:
            cur = db.conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='global_failures'")
            assert cur.fetchone() is not None, "migration must add global_failures table"

            # Queries on legacy data must work and return empty / zero.
            assert db.get_global_contexts_for_campaign(cid) == set()
            counts = db.get_global_failure_counts_per_mutation(cid)
            assert all(c == 0 for _, c in counts)
        finally:
            db.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
