#!/usr/bin/env python3
"""D2.G smoke gates — B1 shape + B2 triage oracle (gated on real binary)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
SMOKE_ROOT = REPO / "a4" / "runs" / "iv_pos_8" / "d2f" / "smoke" / "d2f_smoke_b1"

from a4.runs.iv_pos_8.d2g.discover import discover_d2f_dbs, flat_db_list
from a4.runs.iv_pos_8.d2g.d2g_metrics import compute_d2g_metrics_frame
from a4.runs.iv_pos_8.d2g.propagation_triage import (
    default_host,
    default_host_args,
    extract_accepts,
    triage_accepts,
    validate_smoke_oracle,
)
from a4.runs.iv_pos_8.d2g.rejection_channels import rejection_channels_frame


@pytest.fixture(scope="module")
def smoke_root() -> Path:
    if not SMOKE_ROOT.is_dir():
        pytest.skip(f"smoke DBs not present at {SMOKE_ROOT}")
    return SMOKE_ROOT


class TestD2GSmokeB1:
    def test_eight_dbs_discovered(self, smoke_root: Path):
        mapping = discover_d2f_dbs(smoke_root)
        assert sum(len(v) for v in mapping.values()) == 8

    def test_metrics_frame_all_variants(self, smoke_root: Path):
        df = compute_d2g_metrics_frame(smoke_root)
        assert len(df) == 8
        assert set(df["variant"]) == {
            "V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS",
        }

    def test_v6_uniform_sparse_telemetry(self, smoke_root: Path):
        df = compute_d2g_metrics_frame(smoke_root)
        v6u = df[df["variant"] == "V6_uniform"]
        assert v6u["telemetry_sparse"].all()
        assert v6u["failures_derived_d_loc_le_2_rate"].notna().all()

    def test_rejection_channels_populated(self, smoke_root: Path):
        ch = rejection_channels_frame(smoke_root)
        assert not ch.empty
        assert "channel" in ch.columns


@pytest.mark.skipif(os.environ.get("A4_REAL_BINARY") != "1", reason="A4_REAL_BINARY=1 required")
class TestD2GSmokeB2Oracle:
    def test_triage_oracle_v6_cTS_seed1234(self, smoke_root: Path):
        host = default_host()
        if not os.path.isfile(host):
            pytest.skip(f"missing host: {host}")
        db = smoke_root / "pos_iv_pos_8_d2f_V6_cTS_seed1234_n100" / "run.db"
        if not db.is_file():
            pytest.skip("V6_cTS seed1234 smoke DB missing")
        accepts = extract_accepts(db)
        assert len(accepts) == 8
        df = triage_accepts(
            accepts,
            host=host,
            host_args=default_host_args(),
            run_tier2=True,
        )
        ok, msg = validate_smoke_oracle(df)
        assert ok, msg
