"""Tests for v6_comparison.py and kind_translation.py."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import pytest

from .kind_translation import KIND_GROUPS, SHARED_KINDS, kind_translation_frame
from .metrics import compute_internal_metrics_frame
from .stats import MIN_PAIRS_FOR_PVALUE, paired_tests
from .v6_comparison import (
    apples_to_apples_frame,
    build_v6_outputs,
    loc_overlap_frame,
    v6_paired_tests_frame,
)


def test_v6_lc_v2_is_nan_not_zero():
    df = compute_internal_metrics_frame()
    v6 = df[df["variant"] == "V6"]
    if v6.empty:
        pytest.skip("no V6 DBs")
    assert v6["local_coverage_v2_final"].isna().all()
    assert v6["crash_rate"].isna().all()
    assert v6["no_effect_rate"].isna().all()


def test_v6_no_lc_v2_paired_test_vs_v0():
    df = compute_internal_metrics_frame()
    pt = paired_tests(df, reference="V0", metrics=("local_coverage_v2_final",))
    v6_rows = pt[pt["variant"] == "V6"]
    assert len(v6_rows) == 0


def test_v6_paired_tests_n10():
    """With 10/10 V6 seeds, p-values are computed (no small-n suppression)."""
    df = compute_internal_metrics_frame()
    pt = v6_paired_tests_frame(df)
    if pt.empty:
        pytest.skip("no V6 paired tests")
    assert (pt["n_pairs"] >= MIN_PAIRS_FOR_PVALUE).all()
    assert not pt["small_n_caveat"].any()
    assert pt["paired_t_pvalue"].notna().all()


def test_loc_overlap_has_critical_sets():
    overlap = loc_overlap_frame()
    norm = overlap[overlap["keying"] == "normalized"]
    names = set(norm["set_name"])
    assert "V5_novel_4_hit_by_V6" in names
    assert "V6_exclusive_vs_A4" in names
    assert "V6_intersect_A4_reachable" in names


def test_apples_to_apples_fractions():
    ata = apples_to_apples_frame()
    if ata.empty or ata.iloc[0]["v6_full_coverage_normalized"] == 0:
        pytest.skip("no V6")
    row = ata.iloc[0]
    assert row["v6_reachable_fraction_normalized"] + row["v6_exclusive_fraction_normalized"] == pytest.approx(1.0, rel=1e-6)
    # Raw overlap is 0 due to naming format — not a real zero coverage result.
    assert row["v6_a4_reachable_raw"] == 0


def test_normalize_constraint_loc():
    from .constraint_loc_normalize import normalize_constraint_loc
    assert normalize_constraint_loc("Foo@bar.zir:12") == "Foo:bar.zir:12"
    assert normalize_constraint_loc("Foo(path/to/bar.zir:12)") == "Foo:bar.zir:12"


def test_build_v6_outputs_keys():
    df = compute_internal_metrics_frame()
    out = build_v6_outputs(df)
    assert "v6_vs_v1_v5" in out
    assert "loc_overlap" in out
    assert "kind_translation" in out
    assert not out["kind_translation"].empty or df[df["variant"] == "V6"].empty


def test_territory_coverage_frame():
    from .v6_comparison import a4_territory_coverage_frame
    terr = a4_territory_coverage_frame()
    v5 = terr[terr["variant"] == "V5"].iloc[0]
    v6 = terr[terr["variant"] == "V6"].iloc[0]
    assert int(v5["locs_in_a4_territory"]) == 50
    assert int(v6["locs_in_a4_territory"]) == 20
    assert int(v5["a4_territory_size"]) == 51
