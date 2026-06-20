#!/usr/bin/env python3
"""D2.C Batch 4 — Layer 5 V6-uniform driver local wiring gate (N≤10, POS policy)."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HOST_DEFAULT = "workspace/output/target/release/risc0-host"
HOST_ARGS_DEFAULT = "--in1 5 --in4 10"
SMOKE_NUM = 10


def _host() -> str:
    return os.environ.get("A4_TEST_HOST", HOST_DEFAULT).strip()


def _host_args() -> list[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", HOST_ARGS_DEFAULT).strip()
    return raw.split() if raw else []


@pytest.fixture(scope="module")
def smoke_db() -> str:
    if os.environ.get("A4_REAL_BINARY") != "1":
        pytest.skip("Set A4_REAL_BINARY=1 to run Layer-5 driver smoke")
    if not os.path.isfile(_host()):
        pytest.skip(f"missing host binary: {_host()}")

    tmp = tempfile.mkdtemp(prefix="d2c_v6_smoke_")
    db_path = str(Path(tmp) / "v6_smoke.db")
    cmd = [
        sys.executable, "-m", "a4.standalone.v6_uniform_driver",
        "--host", _host(),
        "--db", db_path,
        "--seed", "1243",
        "--num", str(SMOKE_NUM),
        "--progress-every", str(SMOKE_NUM),
        "--label", "v6_uniform_smoke",
        "--",
        *_host_args(),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        pytest.fail(
            f"v6_uniform_driver failed rc={proc.returncode}\n"
            f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}"
        )
    return db_path


class TestV6UniformDriverSmoke:
    def test_mutation_count(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
        assert n == SMOKE_NUM

    def test_outcome_column_populated(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            rows = conn.execute("SELECT outcome FROM mutations").fetchall()
        assert len(rows) == SMOKE_NUM
        assert all(r[0] is not None for r in rows)

    def test_constraint_loc_normalized(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            locs = [
                r[0] for r in conn.execute(
                    "SELECT constraint_loc FROM failures LIMIT 20"
                ).fetchall()
            ]
        if not locs:
            pytest.skip("no failures in smoke run — cannot check constraint_loc")
        for loc in locs:
            assert "@" in loc, f"expected Name@basename:line format, got {loc!r}"

    def test_compressed_global_coverage_nonempty(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0]
        assert n >= 1, (
            "CGC empty — check DEFAULT_ARGUZZ_SUBPROCESS_ENV includes "
            "A4_COVERAGE_TOUCH=1 (F13 co-trigger)"
        )

    def test_global_failures_nonempty(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            n = conn.execute("SELECT COUNT(*) FROM global_failures").fetchone()[0]
        assert n >= 1, "global_failures empty — Hook-3 path not active"

    def test_driver_version_in_extra_json(self, smoke_db: str):
        with sqlite3.connect(smoke_db) as conn:
            extra = conn.execute(
                "SELECT extra_json FROM campaign_params LIMIT 1"
            ).fetchone()[0]
        data = json.loads(extra)
        assert data.get("driver_version") == "v3_d2c"
