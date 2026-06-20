#!/usr/bin/env python3
"""D2.C Batch 4 — evaluate POS N=50 v6_uniform driver DB (ISS-8 scale validation)."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from a4.standalone.mutations.arguzz_bridge import (
    MUTATION_KINDS_ARGUZZ_FULL,
    MUTATION_KINDS_ARGUZZ_SELECTED,
)

SELECTED = set(MUTATION_KINDS_ARGUZZ_SELECTED)
POS_DB_DEFAULT = "a4/runs/d2c_v6_uniform_smoke/flare/d2c_v6_uniform_smoke_v1_v6_uniform_seed1243_n50.db"


def _db_path() -> str:
    return os.environ.get("A4_SMOKE_DB", POS_DB_DEFAULT)


@pytest.fixture(scope="module")
def pos_db() -> str:
    path = _db_path()
    if not os.path.isfile(path):
        pytest.skip(f"POS DB not found: {path}")
    return path


class TestV6UniformPosSmoke:
    def test_mutation_count(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
        assert n == 50

    def test_outcome_column_populated(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            rows = conn.execute("SELECT outcome FROM mutations").fetchall()
        assert len(rows) == 50
        assert all(r[0] is not None for r in rows)

    def test_kind_coverage(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            kinds = {
                row[0]
                for row in conn.execute("SELECT DISTINCT kind FROM mutations")
            }
        assert len(kinds & set(MUTATION_KINDS_ARGUZZ_FULL)) >= 6
        assert SELECTED <= kinds

    def test_cgc_and_global_failures(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            cgc = conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0]
            gf = conn.execute("SELECT COUNT(*) FROM global_failures").fetchone()[0]
        assert cgc >= 1, "CGC empty on POS — F13 co-trigger may be missing"
        assert gf >= 1, "global_failures empty on POS"

    def test_driver_version(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            extra = conn.execute(
                "SELECT extra_json FROM campaign_params LIMIT 1"
            ).fetchone()[0]
        data = json.loads(extra)
        assert data.get("driver_version") == "v3_d2c"

    def test_outcome_distribution(self, pos_db: str):
        with sqlite3.connect(pos_db) as conn:
            dist = dict(
                conn.execute(
                    "SELECT outcome, COUNT(*) FROM mutations GROUP BY outcome"
                ).fetchall()
            )
        assert dist.get("applied", 0) >= 1
