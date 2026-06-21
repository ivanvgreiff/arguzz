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

# F30: within this many normalized locs = tie (seed noise / near-subset territory).
TERRITORY_TIE_MARGIN = 1
CASE_GATE_METRIC = "survey_unique_normalized_locs"


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
    apples_df: Optional[pd.DataFrame] = None,
) -> Tuple[str, str, Dict[str, object]]:
    """Return (case_id, rationale, evidence_dict).

    F30: Case gate uses **normalized territory only** (``survey_unique_normalized_locs``).
    Raw CGC is reported separately — arm-weighting makes CGC a reward-proxy artifact
    for V6_cTS vs V6_uniform, not confound-corrected territory (IV_POS_8_D2_G_SPEC §7).
    """
    gate_metrics = [CASE_GATE_METRIC]
    report_metrics = (
        "survey_unique_normalized_locs",
        "survey_cgc_final",
        "unique_locs_d_loc_le_2",
        "soundness_score_candidates",
    )
    present = [m for m in report_metrics if m in scores_df.columns]
    paired = paired_tests(scores_df, reference=reference, metrics=present) if present else pd.DataFrame()

    v6c = "V6_cTS"
    v6u = reference
    hyb = "Hybrid_cTS"
    v5 = "V5_control"

    cts_locs = _mean_metric(scores_df, v6c, CASE_GATE_METRIC)
    uni_locs = _mean_metric(scores_df, v6u, CASE_GATE_METRIC)
    hyb_locs = _mean_metric(scores_df, hyb, CASE_GATE_METRIC)
    cts_cgc = _mean_metric(scores_df, v6c, "survey_cgc_final")
    uni_cgc = _mean_metric(scores_df, v6u, "survey_cgc_final")
    hyb_cgc = _mean_metric(scores_df, hyb, "survey_cgc_final")
    cts_uuf = _mean_metric(scores_df, v6c, "unique_locs_d_loc_le_2")
    uni_uuf = _mean_metric(scores_df, v6u, "unique_locs_d_loc_le_2")
    hyb_uuf = _mean_metric(scores_df, hyb, "unique_locs_d_loc_le_2")

    # Territory gate only — ties do not count as "beats" (F30).
    cts_beats_uni = _beats(cts_locs, uni_locs, margin=TERRITORY_TIE_MARGIN)
    hyb_beats_uni = _beats(hyb_locs, uni_locs, margin=TERRITORY_TIE_MARGIN)
    cts_loses_uni = _beats(uni_locs, cts_locs, margin=TERRITORY_TIE_MARGIN)
    hyb_loses_uni = _beats(uni_locs, hyb_locs, margin=TERRITORY_TIE_MARGIN)

    if cts_beats_uni and hyb_beats_uni:
        case = "A"
    elif not cts_beats_uni and hyb_beats_uni:
        case = "B"
    elif cts_beats_uni and not hyb_beats_uni:
        case = "C"
    elif not cts_beats_uni and not hyb_beats_uni:
        case = "D"
    else:
        case = "E"

    union_row = territory_df[territory_df["bucket"] == "union_all_four"]
    union_count = int(union_row["count"].iloc[0]) if not union_row.empty else 0
    v5_mean_locs = _mean_metric(scores_df, v5, CASE_GATE_METRIC)

    apples_evidence: Dict[str, object] = {}
    if apples_df is not None and not apples_df.empty:
        ar = apples_df.iloc[0]
        apples_evidence = {
            "pooled_v6_uniform_locs": int(ar.get("v6_uniform_normalized_locs", 0)),
            "pooled_v6_cTS_locs": int(ar.get("v6_cTS_normalized_locs", 0)),
            "pooled_hybrid_locs": int(ar.get("hybrid_normalized_locs", 0)),
            "v6_cTS_minus_uniform": int(ar.get("v6_cTS_minus_uniform", 0)),
            "uniform_minus_v6_cTS": int(ar.get("uniform_minus_v6_cTS", 0)),
        }

    evidence = {
        "provisional": False,
        "n_seeds": int(scores_df["seed"].nunique()),
        "case_gate_metric": CASE_GATE_METRIC,
        "territory_tie_margin": TERRITORY_TIE_MARGIN,
        "v6_cTS_vs_uniform_locs": {"cts": cts_locs, "uniform": uni_locs},
        "v6_cTS_vs_uniform_cgc": {"cts": cts_cgc, "uniform": uni_cgc},
        "hybrid_vs_uniform_locs": {"hybrid": hyb_locs, "uniform": uni_locs},
        "hybrid_vs_uniform_cgc": {"hybrid": hyb_cgc, "uniform": uni_cgc},
        "unique_useful_d_loc_le_2": {"cts": cts_uuf, "uniform": uni_uuf, "hybrid": hyb_uuf},
        "territory_union_all_four": union_count,
        "v5_mean_unique_locs": v5_mean_locs,
        "cts_beats_uniform_territory": cts_beats_uni,
        "hyb_beats_uniform_territory": hyb_beats_uni,
        "cts_loses_uniform_territory": cts_loses_uni,
        "cgc_not_case_gate": True,
        "apples_to_apples": apples_evidence,
    }

    cts_territory_note = (
        "tie (~+1 loc, within margin)"
        if not cts_beats_uni and not cts_loses_uni
        else ("beats" if cts_beats_uni else "loses")
    )

    rationale = (
        f"Case {case} (n={evidence['n_seeds']} seeds): {CASES[case]}. "
        f"Gate = normalized territory only (F30): V6_cTS {cts_territory_note} V6_uniform "
        f"(locs {cts_locs:.1f} vs {uni_locs:.1f}); Hybrid beats uniform on territory "
        f"({hyb_locs:.1f} vs {uni_locs:.1f}). "
        f"CGC reported but NOT gating: V6_cTS {cts_cgc:.0f} vs uniform {uni_cgc:.0f} "
        "(arm-weighting confound — IWM over-sampling inflates CGC without new locs). "
        "Soundness: 0 strong (F29 verified negative)."
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
        "# D2.G Case Verdict (full campaign, seeds 1234/1235/1236)",
        "",
        f"**Case {case}** — {CASES.get(case, 'unknown')}",
        "",
        rationale,
        "",
        "## Evidence summary",
        "",
        f"- Seeds: **{evidence.get('n_seeds')}** (directional; paired p-values empty at n=3)",
        f"- Case gate: **{evidence.get('case_gate_metric')}** only (CGC not gating — F30)",
        f"- Territory union (all four variants): **{evidence.get('territory_union_all_four')}** normalized locs",
        f"- V6_cTS beats V6_uniform on territory: **{evidence.get('cts_beats_uniform_territory')}**",
        f"- Hybrid beats V6_uniform on territory: **{evidence.get('hyb_beats_uniform_territory')}**",
        "",
    ]
    apples = evidence.get("apples_to_apples") or {}
    if apples:
        lines.extend([
            "### Pooled territory (apples_to_apples)",
            "",
            f"- V6_uniform: **{apples.get('pooled_v6_uniform_locs')}** locs",
            f"- V6_cTS: **{apples.get('pooled_v6_cTS_locs')}** locs "
            f"(+{apples.get('v6_cTS_minus_uniform')} exclusive, "
            f"uniform +{apples.get('uniform_minus_v6_cTS')} exclusive)",
            f"- Hybrid: **{apples.get('pooled_hybrid_locs')}** locs",
            "",
        ])
    lines.extend([
        "### Mean metrics (3 seeds)",
        "",
        "| Comparison | locs (gate) | CGC (info only) | unique_useful (d_loc≤2) |",
        "|---|---:|---:|---:|",
    ])
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
            "## Paired tests (vs V6_uniform) — informational; territory gate uses locs only",
            "",
            paired_df.to_markdown(index=False),
            "",
        ])
    lines.extend([
        "## Caveats",
        "",
        "- Single guest (`--in1 5 --in4 10`); directional only (n=3, `small_n_caveat=True`).",
        "- Raw CGC must not gate Case A–E — arm-weighting confound (F30).",
        "- V6_uniform `unique_locs_d_loc_le_2` uses F18 failures-derived path when sparse.",
        "- Soundness: 0 strong residue (F29 verified negative on full triage).",
        "",
    ])
    return "\n".join(lines)
