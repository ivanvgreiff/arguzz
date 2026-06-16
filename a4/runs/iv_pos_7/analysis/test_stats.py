"""Unit tests for stats.py."""
from __future__ import annotations

import pandas as pd
import pytest

from .stats import paired_tests, REFERENCE_VARIANT


def _synthetic_df() -> pd.DataFrame:
    rows = []
    for seed in range(1234, 1244):
        rows.append({"variant": "V1", "seed": seed, "local_context_AUC": 100.0 + seed % 3,
                     "local_context_final": 43.0})
        rows.append({"variant": "V5", "seed": seed, "local_context_AUC": 110.0 + seed % 3,
                     "local_context_final": 46.0})
    return pd.DataFrame(rows)


def test_paired_tests_v5_vs_v1():
    # Synthetic fixture uses near-constant V1 rows; scipy may warn about precision loss — expected.
    df = _synthetic_df()
    pt = paired_tests(df)
    v5 = pt[(pt["variant"] == "V5") & (pt["metric"] == "local_context_AUC")].iloc[0]
    assert v5["mean_diff"] > 0
    assert v5["n_pairs"] == 10
    assert v5["paired_t_pvalue"] < 0.05


def test_paired_tests_v5_vs_v0():
    df = _synthetic_df()
    # Add V0 rows
    v0_rows = []
    for seed in range(1234, 1244):
        v0_rows.append({
            "variant": "V0", "seed": seed,
            "local_context_AUC": 90.0,
            "local_context_final": 35.0,
        })
    df = pd.concat([df, pd.DataFrame(v0_rows)], ignore_index=True)
    pt = paired_tests(df, reference="V0", metrics=("local_context_final",))
    v5 = pt[(pt["variant"] == "V5") & (pt["metric"] == "local_context_final")].iloc[0]
    assert v5["reference"] == "V0"
    assert v5["mean_diff"] == pytest.approx(11.0)
    assert v5["n_pairs"] == 10


def test_no_self_comparison():
    df = _synthetic_df()
    pt = paired_tests(df)
    assert REFERENCE_VARIANT not in pt["variant"].values
