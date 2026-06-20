#!/usr/bin/env python3
"""D2.E Gate F + L2 — per-variant e2e smoke and determinism (≤10 real-binary gated)."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from a4.standalone.bandit_ts import ConstrainedTSScheduler, ConstantFloor
from a4.standalone.tests.test_bandit_ts import _decision_trace, _small_universe
from a4.standalone.tests.d2e_helpers import assert_all_failure_locs_canonical

HOST_DEFAULT = "workspace/output/target/release/risc0-host"
HOST_ARGS = ["--in1", "5", "--in4", "10"]
SMOKE_N = 5
REPO_ROOT = Path(__file__).resolve().parents[3]


def _host() -> str:
    return os.environ.get("A4_HOST", HOST_DEFAULT)


@pytest.mark.skipif(os.environ.get("A4_REAL_BINARY") != "1", reason="real-binary gate")
class TestFreshVariantE2ESmoke:
    def test_v6_uniform_driver_smoke(self):
        if not os.path.isfile(_host()):
            pytest.skip(f"missing host: {_host()}")
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "v6u.db")
            cmd = [
                sys.executable, "-m", "a4.standalone.v6_uniform_driver",
                "--host", _host(), "--db", db,
                "--seed", "1243", "--num", str(SMOKE_N),
                "--progress-every", str(SMOKE_N),
                "--label", "d2e_smoke",
                "--", *HOST_ARGS,
            ]
            proc = subprocess.run(
                cmd, cwd=str(REPO_ROOT), capture_output=True,
                text=True, timeout=600,
            )
            assert proc.returncode == 0, proc.stderr[-800:]
            with sqlite3.connect(db) as conn:
                n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
                assert n == SMOKE_N
                null_out = conn.execute(
                    "SELECT COUNT(*) FROM mutations WHERE outcome IS NULL"
                ).fetchone()[0]
                cgc = conn.execute(
                    "SELECT COUNT(*) FROM compressed_global_coverage"
                ).fetchone()[0]
            assert null_out == 0
            assert cgc >= 1
            assert_all_failure_locs_canonical(Path(db))

    def test_v6_cts_cli_smoke(self):
        if not os.path.isfile(_host()):
            pytest.skip(f"missing host: {_host()}")
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "v6cts.db")
            cmd = [
                sys.executable, "-m", "a4.standalone.cli", "fuzz",
                "--host", _host(), "--db", db,
                "--num", str(SMOKE_N), "--seed", "4242",
                "--selector", "v6_cTS",
                "--telemetry-level", "full",
                "--", *HOST_ARGS,
            ]
            proc = subprocess.run(
                cmd, cwd=str(REPO_ROOT), capture_output=True,
                text=True, timeout=600,
            )
            assert proc.returncode == 0, proc.stderr[-800:]
            with sqlite3.connect(db) as conn:
                n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
                cgc = conn.execute(
                    "SELECT COUNT(*) FROM compressed_global_coverage"
                ).fetchone()[0]
                l1 = conn.execute(
                    """
                    SELECT COUNT(*) FROM reward_counterfactuals
                    WHERE bandit_success_l1 IS NOT NULL
                    """
                ).fetchone()[0]
            assert n == SMOKE_N
            assert cgc >= 1
            assert l1 >= 1

    def test_hybrid_cts_cli_smoke(self):
        if not os.path.isfile(_host()):
            pytest.skip(f"missing host: {_host()}")
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "hybrid.db")
            cmd = [
                sys.executable, "-m", "a4.standalone.cli", "fuzz",
                "--host", _host(), "--db", db,
                "--num", str(SMOKE_N), "--seed", "7777",
                "--selector", "hybrid_cTS",
                "--telemetry-level", "full",
                "--kind", "INSTR_TYPE_MOD",
                "--", *HOST_ARGS,
            ]
            proc = subprocess.run(
                cmd, cwd=str(REPO_ROOT), capture_output=True,
                text=True, timeout=600,
            )
            assert proc.returncode == 0, proc.stderr[-800:]
            with sqlite3.connect(db) as conn:
                kinds = {
                    row[0]
                    for row in conn.execute("SELECT DISTINCT kind FROM mutations")
                }
                cgc = conn.execute(
                    "SELECT COUNT(*) FROM compressed_global_coverage"
                ).fetchone()[0]
            assert len(kinds) >= 1
            assert cgc >= 1


class TestDeterminismGoldenRegression:
    def test_bernoulli_v6_cts_trace_stable(self):
        from a4.standalone.tests.test_d2_bernoulli_floor_golden_trace import (
            TestD2BernoulliFloorGoldenTrace,
        )
        TestD2BernoulliFloorGoldenTrace().test_v6_cts_bernoulli_decision_trace_matches_fixture()

    def test_v5_decision_trace_stable(self):
        seed = 42
        n = 50
        successes = [0] * n
        a = ConstrainedTSScheduler(_small_universe(), seed=seed)
        b = ConstrainedTSScheduler(_small_universe(), seed=seed)
        assert _decision_trace(a, n, successes) == _decision_trace(b, n, successes)
