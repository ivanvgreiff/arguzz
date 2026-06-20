"""S3/S4/S5 score assembly (D2.G §6)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from a4.runs.iv_pos_7.analysis.bug_proximity import compute_tier2_metrics_row

from .discover import flat_db_list, parse_d2f_run_dir
from .propagation_triage import TRIAGE_HIDDEN, TRIAGE_PROPAGATED


def _survey_from_metrics(row: pd.Series) -> Dict[str, float]:
    return {
        "survey_local_context_final": float(row.get("local_context_final", float("nan"))),
        "survey_local_context_auc": float(row.get("local_context_AUC", float("nan"))),
        "survey_cgc_final": float(row.get("compressed_global_context_final", float("nan"))),
        "survey_unique_normalized_locs": float(row.get("unique_normalized_locs", float("nan"))),
    }


def _proximity_from_tier2(t2: dict) -> Dict[str, float]:
    return {
        "proximity_singleton_failure_rate": float(t2.get("cat_a_pro_s5_singleton_failure_rate") or 0),
        "proximity_d_loc_p95": float(t2.get("cat_a_pro_s5_d_loc_p95") or 0),
        "proximity_co_failure_degree_p95": float(t2.get("cat_a_pro_s5_co_failure_graph_degree_p95") or 0),
    }


def _unique_useful_from_tier2(t2: dict) -> Dict[str, float]:
    return {
        "unique_locs_d_loc_le_2": float(t2.get("cat_a_pro_s8_unique_locs_with_d_loc_le_2") or 0),
        "unique_locs_d_glob_le_1": float(t2.get("cat_a_pro_s8_unique_locs_with_d_glob_le_1") or 0),
    }


def _soundness_from_triage(
    triage_df: Optional[pd.DataFrame],
    variant: str,
    seed: int,
) -> Dict[str, float]:
    if triage_df is None or triage_df.empty:
        return {
            "raw_accepts": float("nan"),
            "triaged_propagated": float("nan"),
            "triaged_hidden": float("nan"),
            "triaged_weak": float("nan"),
            "triaged_strong": float("nan"),
            "soundness_score_candidates": float("nan"),
        }
    sub = triage_df[(triage_df["variant"] == variant) & (triage_df["seed"] == seed)]
    raw = len(sub)
    prop = sub[sub["class"] == TRIAGE_PROPAGATED]
    hidden = sub[sub["class"] == TRIAGE_HIDDEN]
    weak = prop[prop["evidence"] == "weak"] if "evidence" in prop.columns else prop.iloc[0:0]
    strong = prop[prop["evidence"] == "strong"] if "evidence" in prop.columns else prop.iloc[0:0]
    # soundness_score proxy: propagated + hidden (post-triage candidates)
    score = len(prop) + len(hidden)
    return {
        "raw_accepts": raw,
        "triaged_propagated": len(prop),
        "triaged_hidden": len(hidden),
        "triaged_weak": len(weak),
        "triaged_strong": len(strong),
        "soundness_score_candidates": score,
    }


def compute_scores_frame(
    collection_root: Path,
    metrics_df: pd.DataFrame,
    channels_df: pd.DataFrame,
    triage_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    rows: List[dict] = []
    for db in flat_db_list(collection_root):
        variant, seed, n = parse_d2f_run_dir(db.parent)
        mrow = metrics_df[
            (metrics_df["variant"] == variant) & (metrics_df["seed"] == seed)
        ]
        if mrow.empty:
            continue
        m = mrow.iloc[0]
        t2 = compute_tier2_metrics_row(db)
        ch = channels_df[
            (channels_df["variant"] == variant) & (channels_df["seed"] == seed)
        ] if not channels_df.empty else pd.DataFrame()
        c1 = int((ch["channel"] == "C1").sum()) if not ch.empty else 0
        c2 = int((ch["channel"] == "C2").sum()) if not ch.empty else 0
        c5 = int((ch["channel"] == "C5").sum()) if not ch.empty else 0
        accepted = int((ch["channel"] == "accepted").sum()) if not ch.empty else 0

        row = {
            "variant": variant,
            "seed": seed,
            "expected_n": n,
            "global_c2_count": c2,
            "global_c5_count": c5,
            "global_failure_recording_gap_rate": c2 / max(c1 + c2 + accepted, 1),
            ** _survey_from_metrics(m),
            ** _proximity_from_tier2(t2),
            ** _unique_useful_from_tier2(t2),
            ** _soundness_from_triage(triage_df, variant, seed),
            "repairability_singleton_rate": float(t2.get("cat_a_pro_s5_singleton_failure_rate") or 0),
            "repairability_d_loc_p95": float(t2.get("cat_a_pro_s5_d_loc_p95") or 0),
            "repairability_zero_residue_reject_rate": float(
                t2.get("cat_b_pro_s5_proof_generated_zero_residue_rejected_rate") or 0
            ),
        }
        rows.append(row)
    return pd.DataFrame(rows)


def unique_useful_frame(scores_df: pd.DataFrame) -> pd.DataFrame:
    if scores_df.empty:
        return scores_df
    cols = [
        "variant", "seed", "unique_locs_d_loc_le_2", "unique_locs_d_glob_le_1",
        "proximity_singleton_failure_rate", "repairability_d_loc_p95",
    ]
    present = [c for c in cols if c in scores_df.columns]
    return scores_df[present].copy()
