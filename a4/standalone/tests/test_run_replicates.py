#!/usr/bin/env python3
"""
Phase III.4 unit tests for the multi-seed replicate runner.

Run: python -m pytest a4/standalone/tests/test_run_replicates.py -v
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

from a4.standalone.run_replicates import (
    _parse_strategy,
    _VALID_BARE_STRATEGIES,
    build_argparser,
    main,
)


# Real host binary required for end-to-end smokes. Same path the
# precloud master plan uses everywhere.
_HOST = "/root/arguzz/workspace/output/target/release/risc0-host"


# -----------------------------------------------------------------------------
# 1 — Strategy-label parsing (pure unit)
# -----------------------------------------------------------------------------

class TestParseStrategy:
    def test_bare_uniform(self):
        assert _parse_strategy("uniform") == ("uniform", None)

    def test_bare_zoned(self):
        assert _parse_strategy("zoned") == ("zoned", None)

    def test_bare_bandit(self):
        assert _parse_strategy("bandit") == ("bandit", None)

    def test_bandit_with_b_count(self):
        assert _parse_strategy("bandit-16") == ("bandit", 16)
        assert _parse_strategy("bandit-128") == ("bandit", 128)

    def test_bandit_zero_b_count_rejected(self):
        with pytest.raises(ValueError):
            _parse_strategy("bandit-0")

    def test_bandit_negative_b_count_rejected(self):
        with pytest.raises(ValueError):
            _parse_strategy("bandit--5")

    def test_bandit_non_integer_b_count_rejected(self):
        with pytest.raises(ValueError):
            _parse_strategy("bandit-abc")

    def test_unknown_strategy_rejected(self):
        with pytest.raises(ValueError):
            _parse_strategy("magic")

    def test_all_bare_strategies_round_trip(self):
        for label in _VALID_BARE_STRATEGIES:
            sel, b = _parse_strategy(label)
            assert sel == label
            assert b is None


# -----------------------------------------------------------------------------
# 2 — CLI argument validation (no subprocess yet)
# -----------------------------------------------------------------------------

class TestCliValidation:
    def test_parallel_above_cpu_ceiling_rejected(self, capsys):
        """--parallel above NCPU/2 should fail with exit code 2."""
        rc = main([
            "--host", _HOST, "--num", "1",
            "--strategies", "uniform",
            "--parallel", "9999",
        ])
        assert rc == 2
        captured = capsys.readouterr()
        assert "parallel" in captured.err.lower()

    def test_unknown_strategy_rejected(self, capsys):
        rc = main([
            "--host", _HOST, "--num", "1",
            "--strategies", "magic-strategy",
        ])
        assert rc == 2
        captured = capsys.readouterr()
        assert "magic-strategy" in captured.err.lower() or "unknown" in captured.err.lower()

    def test_replicates_zero_rejected(self, capsys):
        rc = main([
            "--host", _HOST, "--num", "1",
            "--strategies", "uniform",
            "--replicates", "0",
        ])
        assert rc == 2
        captured = capsys.readouterr()
        assert "replicates" in captured.err.lower()

    def test_nonexistent_host_rejected(self, capsys):
        rc = main([
            "--host", "/nonexistent/host/binary/that/does/not/exist",
            "--num", "1", "--strategies", "uniform",
        ])
        assert rc == 2
        captured = capsys.readouterr()
        assert "host" in captured.err.lower() or "not found" in captured.err.lower()


# -----------------------------------------------------------------------------
# 3 — End-to-end smokes (require risc0-host)
# -----------------------------------------------------------------------------

_HOST_AVAILABLE = pytest.mark.skipif(
    not Path(_HOST).is_file(),
    reason=f"risc0-host not built at {_HOST}",
)


@pytest.fixture
def tmp_out_dir():
    d = tempfile.mkdtemp(prefix="iii4_test_")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@_HOST_AVAILABLE
class TestEndToEnd:
    """
    Each test runs a tiny --num campaign, so total per-test wall clock
    is dominated by risc0-host startup + a few mutations. With --num 2,
    each campaign is ~1-2 minutes on this hardware.
    """

    def test_one_replicate_one_strategy_smoke(self, tmp_out_dir):
        rc = main([
            "--host", _HOST,
            "--strategies", "uniform",
            "--replicates", "1", "--seed-base", "555",
            "--num", "2",
            "--out-dir", tmp_out_dir,
            "--", "--in1", "5", "--in4", "10",
        ])
        assert rc == 0

        manifest_path = Path(tmp_out_dir) / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())

        assert manifest["replicates"] == 1
        assert manifest["strategies"] == ["uniform"]
        assert len(manifest["campaigns"]) == 1

        c = manifest["campaigns"][0]
        assert c["strategy"] == "uniform"
        assert c["seed"] == 555
        assert c["exit_code"] == 0
        assert c["num_mutations_recorded"] == 2

        db_abs = Path(tmp_out_dir) / c["db"]
        assert db_abs.exists()
        with sqlite3.connect(str(db_abs)) as conn:
            n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
            assert n == 2

        # Paths in manifest are relative-to-out-dir.
        assert not Path(c["db"]).is_absolute()
        assert not Path(c["log"]).is_absolute()

    def test_two_replicates_one_strategy_distinct(self, tmp_out_dir):
        """Two seeds → two DBs whose mutation-id orderings differ."""
        rc = main([
            "--host", _HOST,
            "--strategies", "uniform",
            "--replicates", "2", "--seed-base", "777",
            "--num", "3",
            "--out-dir", tmp_out_dir,
            "--", "--in1", "5", "--in4", "10",
        ])
        assert rc == 0

        out = Path(tmp_out_dir)
        db_a = out / "uniform" / "seed_777.db"
        db_b = out / "uniform" / "seed_778.db"
        assert db_a.exists() and db_b.exists()

        def _ids(db_path):
            with sqlite3.connect(str(db_path)) as c:
                return [
                    (r[0], r[1], r[2]) for r in c.execute(
                        "SELECT kind, step, config_json FROM mutations "
                        "ORDER BY id"
                    )
                ]

        ids_a = _ids(db_a)
        ids_b = _ids(db_b)
        assert len(ids_a) == 3 and len(ids_b) == 3
        # The seeds drive different selections, so the (kind, step) or
        # config sequences must differ. Note: we don't assert ALL rows
        # differ (sampling collisions are possible on N=3), only that
        # the sequences as a whole aren't identical.
        assert ids_a != ids_b, (
            f"Replicates with different seeds produced identical "
            f"mutation sequences: {ids_a}"
        )

    def test_strategies_cross_product_layout(self, tmp_out_dir):
        rc = main([
            "--host", _HOST,
            "--strategies", "uniform", "zoned",
            "--replicates", "1", "--seed-base", "9000",
            "--num", "2",
            "--out-dir", tmp_out_dir,
            "--", "--in1", "5", "--in4", "10",
        ])
        assert rc == 0

        out = Path(tmp_out_dir)
        assert (out / "uniform" / "seed_9000.db").exists()
        assert (out / "uniform" / "seed_9000.log").exists()
        assert (out / "zoned" / "seed_9000.db").exists()
        assert (out / "zoned" / "seed_9000.log").exists()

        manifest = json.loads((out / "manifest.json").read_text())
        assert sorted([c["strategy"] for c in manifest["campaigns"]]) == \
            ["uniform", "zoned"]
