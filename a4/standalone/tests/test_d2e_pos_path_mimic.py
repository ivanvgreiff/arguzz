#!/usr/bin/env python3
"""D2.E Gate L5 — POS-path mimic and V5 archive ingestion."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from a4.standalone.variants import CANONICAL_VARIANTS, variant_launch_command
from a4.standalone.tests.d2e_helpers import v5_archive_path

MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "pos" / "manifests" / "iv_pos_8" / "d2d_checkpoint_smoke.json"
)
RUNNER = (
    Path(__file__).resolve().parents[2]
    / "pos" / "run_campaign_pos.sh"
)


class TestPOSManifestStubs:
    def test_checkpoint_smoke_manifest_valid(self):
        assert MANIFEST.is_file()
        data = json.loads(MANIFEST.read_text())
        assert data["name"] == "d2d_checkpoint_smoke_v1"
        strategies = {job["strategy"] for job in data["jobs"]}
        assert "v6_uniform" in strategies
        assert "v6_cTS" in strategies
        assert "hybrid_cTS" in strategies
        assert "cTS_semantic_v2" in strategies
        for job in data["jobs"]:
            assert job["n"] <= 10

    def test_variant_launch_commands_match_registry(self):
        for name in CANONICAL_VARIANTS:
            if name == "V5_control":
                continue
            cmd = variant_launch_command(
                name,
                host="/path/host",
                db="/path/db.db",
                seed=42,
                num=10,
                host_args=["--in1", "5"],
            )
            assert "--host" in cmd
            assert "/path/host" in cmd

    def test_run_campaign_pos_has_v6_uniform_branch(self):
        text = RUNNER.read_text()
        assert 'A4_STRATEGY" = "v6_uniform"' in text or 'v6_uniform' in text
        assert "v6_uniform_driver" in text


class TestV5ArchiveIngestion:
    def test_v5_archive_opens_and_has_mutations(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 R2 archive not present")
        with sqlite3.connect(archive) as conn:
            n = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
            selector = conn.execute(
                "SELECT selector FROM campaign_params LIMIT 1"
            ).fetchone()[0]
        assert n == 6000
        assert "cTS_semantic_v2" in selector

    def test_v5_archive_failures_locs_normalized(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 R2 archive not present")
        with sqlite3.connect(archive) as conn:
            sample = conn.execute(
                "SELECT constraint_loc FROM failures LIMIT 20"
            ).fetchall()
        for (loc,) in sample:
            assert "@" in loc
            assert "callsite" not in loc
