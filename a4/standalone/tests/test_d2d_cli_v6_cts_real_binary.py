#!/usr/bin/env python3
"""D2.D Layer-5 — real-binary CLI smoke for v6_cTS (≤10 mutations, gated)."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HOST_DEFAULT = "workspace/output/target/release/risc0-host"


@pytest.mark.skipif(
    os.environ.get("A4_REAL_BINARY") != "1",
    reason="real-binary gate",
)
class TestD2DCliV6CTSRealBinary:
    def test_cli_v6_cts_end_to_end(self):
        host = os.environ.get("A4_HOST", HOST_DEFAULT)
        if not os.path.isfile(host):
            pytest.skip(f"host not found: {host}")

        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "v6_cli.db")
            cmd = [
                sys.executable, "-m", "a4.standalone.cli", "fuzz",
                "--host", host,
                "--db", db,
                "--num", "5",
                "--seed", "4242",
                "--selector", "v6_cTS",
                "--telemetry-level", "full",
                "--",
                "--in1", "5", "--in4", "10",
            ]
            proc = subprocess.run(
                cmd, cwd=str(Path(__file__).resolve().parents[3]),
                capture_output=True, text=True, timeout=600,
            )
            assert proc.returncode == 0, proc.stderr[-500:]

            with sqlite3.connect(db) as conn:
                n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
                assert n == 5
                cgc = conn.execute(
                    "SELECT COUNT(*) FROM compressed_global_coverage"
                ).fetchone()[0]
                assert cgc >= 1
                l1 = conn.execute(
                    """
                    SELECT COUNT(*) FROM reward_counterfactuals
                    WHERE bandit_success_l1 IS NOT NULL
                    """
                ).fetchone()[0]
                assert l1 >= 1
