"""Tests for v0_anchor.py."""
from __future__ import annotations

import pandas as pd
import pytest

from .v0_anchor import (
    V0_REFERENCE,
    build_v0_anchor_outputs,
    v0_anchor_frame,
    v0_sanity_check,
)


def _make_metrics_df() -> pd.DataFrame:
    rows = []
    for seed in range(1234, 1244):
        rows.append({
            "variant": "V0", "seed": seed,
            "local_context_final": 35.0,
            "local_context_AUC": 190000.0,
            "compressed_global_context_final": 140.0,
            "local_coverage_v2_final": 530.0,
            "allocation_entropy_by_zone": 1.94,
            "allocation_entropy_by_kind": 2.97,
            "time_to_43": None,
        })
        rows.append({
            "variant": "V1", "seed": seed,
            "local_context_final": 43.0,
            "local_context_AUC": 228000.0,
            "compressed_global_context_final": 144.0,
            "local_coverage_v2_final": 565.0,
            "allocation_entropy_by_zone": 2.20,
            "allocation_entropy_by_kind": 3.0,
            "time_to_43": 4000.0,
        })
        rows.append({
            "variant": "V5", "seed": seed,
            "local_context_final": 46.0,
            "local_context_AUC": 265000.0,
            "compressed_global_context_final": 188.0,
            "local_coverage_v2_final": 684.0,
            "allocation_entropy_by_zone": 3.27,
            "allocation_entropy_by_kind": 2.81,
            "time_to_43": 1000.0,
        })
    return pd.DataFrame(rows)


def test_v0_anchor_delta_v1_local():
    df = _make_metrics_df()
    anchor = v0_anchor_frame(df)
    v1_loc = anchor[(anchor["variant"] == "V1") & (anchor["metric"] == "local_context_final")].iloc[0]
    assert v1_loc["delta_abs"] == pytest.approx(8.0)
    assert v1_loc["delta_pct"] == pytest.approx(100 * 8 / 35)


def test_v0_anchor_cgc_small_delta():
    df = _make_metrics_df()
    anchor = v0_anchor_frame(df)
    v1_cgc = anchor[(anchor["variant"] == "V1") & (anchor["metric"] == "compressed_global_context_final")].iloc[0]
    assert v1_cgc["delta_abs"] == pytest.approx(4.0)
    assert v1_cgc["delta_pct"] == pytest.approx(100 * 4 / 140, rel=0.01)


def test_v0_anchor_zone_entropy_included():
    df = _make_metrics_df()
    anchor = v0_anchor_frame(df)
    assert "allocation_entropy_by_zone" in anchor["metric"].values
    v5_zone = anchor[(anchor["variant"] == "V5") & (anchor["metric"] == "allocation_entropy_by_zone")].iloc[0]
    assert v5_zone["delta_abs"] == pytest.approx(3.27 - 1.94, rel=0.01)


def test_v0_sanity_check_cluster():
    df = _make_metrics_df()
    s = v0_sanity_check(df)
    assert s["v0_n_seeds"] == 10
    assert s["v0_local_context_final_mean"] == 35.0
    assert s["v0_local_context_final_std"] == 0.0


def test_v0_paired_tests_produced():
    df = _make_metrics_df()
    anchor, paired, sanity = build_v0_anchor_outputs(df)
    assert len(anchor) == 7 * 3  # V0,V1,V5 × 7 metrics
    v5_auc = paired[(paired["variant"] == "V5") & (paired["metric"] == "local_context_AUC")]
    assert len(v5_auc) == 1
    assert v5_auc.iloc[0]["reference"] == V0_REFERENCE
    assert v5_auc.iloc[0]["paired_t_pvalue"] < 0.05
