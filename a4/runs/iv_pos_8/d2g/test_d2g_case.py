"""Unit tests for Case A–E gate (F30 territory-only gate)."""
from __future__ import annotations

import pandas as pd

from a4.runs.iv_pos_8.d2g.d2g_case import determine_case


def _scores_frame() -> pd.DataFrame:
    """Minimal n=3 scores mirroring full-campaign prod means."""
    rows = [
        # V6_uniform
        {"variant": "V6_uniform", "seed": 1234, "survey_unique_normalized_locs": 34,
         "survey_cgc_final": 495, "unique_locs_d_loc_le_2": 30},
        {"variant": "V6_uniform", "seed": 1235, "survey_unique_normalized_locs": 36,
         "survey_cgc_final": 482, "unique_locs_d_loc_le_2": 31},
        {"variant": "V6_uniform", "seed": 1236, "survey_unique_normalized_locs": 35,
         "survey_cgc_final": 484, "unique_locs_d_loc_le_2": 30},
        # V6_cTS — ties territory (+1 mean), wins CGC (confound)
        {"variant": "V6_cTS", "seed": 1234, "survey_unique_normalized_locs": 36,
         "survey_cgc_final": 619, "unique_locs_d_loc_le_2": 36},
        {"variant": "V6_cTS", "seed": 1235, "survey_unique_normalized_locs": 36,
         "survey_cgc_final": 615, "unique_locs_d_loc_le_2": 36},
        {"variant": "V6_cTS", "seed": 1236, "survey_unique_normalized_locs": 36,
         "survey_cgc_final": 619, "unique_locs_d_loc_le_2": 36},
        # Hybrid — clear territory win
        {"variant": "Hybrid_cTS", "seed": 1234, "survey_unique_normalized_locs": 48,
         "survey_cgc_final": 500, "unique_locs_d_loc_le_2": 39},
        {"variant": "Hybrid_cTS", "seed": 1235, "survey_unique_normalized_locs": 49,
         "survey_cgc_final": 517, "unique_locs_d_loc_le_2": 39},
        {"variant": "Hybrid_cTS", "seed": 1236, "survey_unique_normalized_locs": 48,
         "survey_cgc_final": 502, "unique_locs_d_loc_le_2": 42},
    ]
    return pd.DataFrame(rows)


def test_determine_case_f30_is_case_b_not_a():
    scores = _scores_frame()
    territory = pd.DataFrame([{"bucket": "union_all_four", "count": 52}])
    metrics = pd.DataFrame()
    apples = pd.DataFrame([{
        "v6_uniform_normalized_locs": 37,
        "v6_cTS_normalized_locs": 36,
        "hybrid_normalized_locs": 49,
        "v6_cTS_minus_uniform": 0,
        "hybrid_minus_uniform": 13,
        "uniform_minus_v6_cTS": 1,
    }])
    case, _rationale, evidence = determine_case(
        scores, territory, metrics, apples_df=apples,
    )
    assert case == "B"
    assert evidence["cts_beats_uniform_territory"] is False
    assert evidence["hyb_beats_uniform_territory"] is True
    assert evidence["cgc_not_case_gate"] is True


def test_old_cgc_gate_would_have_been_case_a():
    """Document why F30 changed the gate: raw CGC would falsely yield Case A."""
    scores = _scores_frame()
    cts_cgc = scores[scores["variant"] == "V6_cTS"]["survey_cgc_final"].mean()
    uni_cgc = scores[scores["variant"] == "V6_uniform"]["survey_cgc_final"].mean()
    assert cts_cgc > uni_cgc + 100  # +130 confound artifact
