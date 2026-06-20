"""Case A–E determination machinery (D2.G §7, New_Master §3)."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import pandas as pd

from a4.runs.iv_pos_7.analysis.stats import paired_tests

CASES = {
    "A": "V6-cTS beats V6-uniform — core feedback hypothesis validated",
    "B": "V6-cTS loses, Hybrid wins — hybrid surface + A4 witness terrain",
    "C": "V6-cTS wins, Hybrid loses — A4 arms dilute Arguzz scheduler",
    "D": "Both lose to V6-uniform — cTS arm space too fragmented",
    "E": "Hybrid preserves V5 terrain but doesn't beat V6 raw — union territory claim",
}


def _mean_metric(df: pd.DataFrame, variant: str, metric: str) -> float:
    sub = df[df["variant"] == variant][metric]
    return float(sub.mean()) if not sub.empty else float("nan")


def _beats(a: float, b: float, *, margin: float = 0.0) -> Optional[bool]:
    if pd.isna(a) or pd.isna(b):
        return None
    return a > b + margin


def determine_case(
    scores_df: pd.DataFrame,
    territory_df: pd.DataFrame,
    metrics_df: pd.DataFrame,
    *,
    reference: str = "V6_uniform",
) -> Tuple[str, str, Dict[str, object]]:
    """Return (case_id, rationale, evidence_dict). Provisional with n=2 seeds."""
    # Useful-territory headline metrics
    metrics = (
        "survey_unique_normalized_locs",
        "survey_cgc_final",
        "unique_locs_d_loc_le_2",
        "soundness_score_candidates",
    )
    present = [m for m in metrics if m in scores_df.columns]
    paired = paired_tests(scores_df, reference=reference, metrics=present) if present else pd.DataFrame()

    v6c = "V6_cTS"
    v6u = reference
    hyb = "Hybrid_cTS"
    v5 = "V5_control"

    # Headline comparisons (mean over seeds)
    cts_locs = _mean_metric(scores_df, v6c, "survey_unique_normalized_locs")
    uni_locs = _mean_metric(scores_df, v6u, "survey_unique_normalized_locs")
    hyb_locs = _mean_metric(scores_df, hyb, "survey_unique_normalized_locs")
    cts_cgc = _mean_metric(scores_df, v6c, "survey_cgc_final")
    uni_cgc = _mean_metric(scores_df, v6u, "survey_cgc_final")
    hyb_cgc = _mean_metric(scores_df, hyb, "survey_cgc_final")
    cts_uuf = _mean_metric(scores_df, v6c, "unique_locs_d_loc_le_2")
    uni_uuf = _mean_metric(scores_df, v6u, "unique_locs_d_loc_le_2")
    hyb_uuf = _mean_metric(scores_df, hyb, "unique_locs_d_loc_le_2")

    cts_beats_uni = _beats(cts_locs, uni_locs) and _beats(cts_cgc, uni_cgc)
    cts_loses_uni = _beats(uni_locs, cts_locs) and _beats(uni_cgc, cts_cgc)
    hyb_beats_uni = _beats(hyb_locs, uni_locs) and _beats(hyb_cgc, uni_cgc)
    hyb_loses_uni = _beats(uni_locs, hyb_locs) and _beats(uni_cgc, hyb_cgc)

    if cts_beats_uni and hyb_beats_uni:
        case = "A"
    elif cts_loses_uni and hyb_beats_uni:
        case = "B"
    elif cts_beats_uni and hyb_loses_uni:
        case = "C"
    elif cts_loses_uni and hyb_loses_uni:
        case = "D"
    else:
        case = "E"

    # Territory union check
    union_row = territory_df[territory_df["bucket"] == "union_all_four"]
    union_count = int(union_row["count"].iloc[0]) if not union_row.empty else 0
    v5_mean_locs = _mean_metric(scores_df, v5, "survey_unique_normalized_locs")

    evidence = {
        "provisional": True,
        "n_seeds": int(scores_df["seed"].nunique()),
        "v6_cTS_vs_uniform_locs": {"cts": cts_locs, "uniform": uni_locs},
        "v6_cTS_vs_uniform_cgc": {"cts": cts_cgc, "uniform": uni_cgc},
        "hybrid_vs_uniform_locs": {"hybrid": hyb_locs, "uniform": uni_locs},
        "hybrid_vs_uniform_cgc": {"hybrid": hyb_cgc, "uniform": uni_cgc},
        "unique_useful_d_loc_le_2": {"cts": cts_uuf, "uniform": uni_uuf, "hybrid": hyb_uuf},
        "territory_union_all_four": union_count,
        "v5_mean_unique_locs": v5_mean_locs,
        "cts_beats_uniform": cts_beats_uni,
        "hyb_beats_uniform": hyb_beats_uni,
    }

    rationale = (
        f"Provisional Case {case} (n={evidence['n_seeds']} seeds): {CASES[case]}. "
        f"V6_cTS locs={cts_locs:.1f} CGC={cts_cgc:.0f} vs V6_uniform locs={uni_locs:.1f} CGC={uni_cgc:.0f}; "
        f"Hybrid locs={hyb_locs:.1f} CGC={hyb_cgc:.0f}. "
        "Final verdict requires batch-2 (seed 1236) and post-triage soundness counts."
    )
    return case, rationale, evidence


def render_case_verdict_md(
    case: str,
    rationale: str,
    evidence: Dict[str, object],
    paired_df: pd.DataFrame,
    *,
    iwm_correction: Optional[pd.DataFrame] = None,
) -> str:
    lines = [
        "# D2.G Provisional Case Verdict (Batch 1, seeds 1234/1235)",
        "",
        f"**Case {case}** — {CASES.get(case, 'unknown')}",
        "",
        rationale,
        "",
        "## Evidence summary",
        "",
        f"- Provisional: **{evidence.get('provisional')}** (batch 2 pending)",
        f"- Territory union (all four variants): **{evidence.get('territory_union_all_four')}** normalized locs",
        f"- V6_cTS beats V6_uniform (locs+CGC): **{evidence.get('cts_beats_uniform')}**",
        f"- Hybrid beats V6_uniform (locs+CGC): **{evidence.get('hyb_beats_uniform')}**",
        "",
        "### Mean metrics (2 seeds)",
        "",
        "| Comparison | locs | CGC | unique_useful (d_loc≤2) |",
        "|---|---:|---:|---:|",
    ]
    v = evidence.get("v6_cTS_vs_uniform_locs", {})
    c = evidence.get("v6_cTS_vs_uniform_cgc", {})
    u = evidence.get("unique_useful_d_loc_le_2", {})
    lines.append(
        f"| V6_cTS | {v.get('cts', 'n/a')} | {c.get('cts', 'n/a')} | {u.get('cts', 'n/a')} |"
    )
    lines.append(
        f"| V6_uniform | {v.get('uniform', 'n/a')} | {c.get('uniform', 'n/a')} | {u.get('uniform', 'n/a')} |"
    )
    h = evidence.get("hybrid_vs_uniform_locs", {})
    hc = evidence.get("hybrid_vs_uniform_cgc", {})
    lines.append(
        f"| Hybrid_cTS | {h.get('hybrid', 'n/a')} | {hc.get('hybrid', 'n/a')} | {u.get('hybrid', 'n/a')} |"
    )
    lines.append("")
    if iwm_correction is not None and not iwm_correction.empty:
        lines.extend([
            "## INSTR_WORD_MOD adaptive correction (F19 action 3)",
            "",
            iwm_correction.to_markdown(index=False),
            "",
        ])
    if not paired_df.empty:
        lines.extend([
            "## Paired tests (vs V6_uniform)",
            "",
            paired_df.to_markdown(index=False),
            "",
        ])
    lines.extend([
        "## Caveats",
        "",
        "- Single guest (`--in1 5 --in4 10`); directional only.",
        "- Raw accept counts are NOT soundness bugs — post-triage counts required.",
        "- Arm-weighting confound: check per-kind territory before claiming cTS wins.",
        "- Batch 2 (seed 1236) required for final Case read.",
        "",
    ])
    return "\n".join(lines)
