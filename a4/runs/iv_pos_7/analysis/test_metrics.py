"""Unit tests for metrics.py (one real IV.POS.7 DB)."""
from __future__ import annotations

import math
from pathlib import Path

import pytest

from .discover import discover_dbs
from .metrics import compute_metrics_for_db, compute_metrics_frame, N_MUTATIONS


@pytest.fixture(scope="module")
def sample_v1_db() -> Path:
    m = discover_dbs()
    return m["V1"][1238]


def test_compute_metrics_for_db_shape(sample_v1_db: Path):
    row = compute_metrics_for_db(sample_v1_db)
    assert row["variant"] == "V1"
    assert row["seed"] == 1238
    assert row["n_mutations"] >= 5999
    assert 0 <= row["local_context_final"] <= 50
    assert row["local_context_AUC"] > 0
    assert row["crash_rate"] >= 0


def test_coverage_curve_monotone(sample_v1_db: Path):
    import sqlite3
    from .metrics import _coverage_curve, _read_first_hits
    with sqlite3.connect(sample_v1_db) as c:
        hits = _read_first_hits(c)
    curve = _coverage_curve(hits, n=N_MUTATIONS)
    assert len(curve) == N_MUTATIONS
    assert curve[-1] == len(hits)
    assert all(curve[i] <= curve[i + 1] for i in range(len(curve) - 1))


def test_v1_zone_entropy_not_nan(sample_v1_db: Path):
    row = compute_metrics_for_db(sample_v1_db, v1_union=set())
    assert not math.isnan(row["allocation_entropy_by_zone"])
    assert row["allocation_entropy_by_zone"] > 0


def test_novel_locs_v5():
    df = compute_metrics_frame()
    v5 = df[df["variant"] == "V5"]
    assert v5["novel_locs_union_vs_v1"].iloc[0] == 4
    assert v5["local_coverage_v2_final"].mean() > df[df["variant"] == "V1"]["local_coverage_v2_final"].mean()


def test_full_frame_has_50_rows():
    df = compute_metrics_frame()
    assert len(df) == 50
    assert set(df["variant"]) == {"V1", "V2", "V3", "V4", "V5"}
    assert df.groupby("variant").size().tolist() == [10, 10, 10, 10, 10]
    assert "local_coverage_v2_final" in df.columns
    assert "novel_locs_vs_v1" in df.columns
