#!/usr/bin/env python3
"""D2.G artifact builder — B1 ingestion/metrics/territory/channels, B2 triage."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[4]
IV_POS_8 = Path(__file__).resolve().parents[1]
DEFAULT_SMOKE = IV_POS_8 / "d2f" / "smoke" / "d2f_smoke_b1"

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from a4.runs.iv_pos_8.d2g.cgc_audit import cgc_field_collapse_frame
from a4.runs.iv_pos_8.d2g.d2g_metrics import (
    aggregate_d2g_metrics,
    compute_d2g_metrics_frame,
    discovery_rate_frame,
)
from a4.runs.iv_pos_8.d2g.discover import flat_db_list
from a4.runs.iv_pos_8.d2g.propagation_triage import (
    default_host,
    default_host_args,
    extract_accepts,
    triage_accepts,
    triage_summary,
    validate_smoke_oracle,
)
from a4.runs.iv_pos_8.d2g.rejection_channels import (
    rejection_channels_frame,
    rejection_channels_summary,
)
from a4.runs.iv_pos_8.d2g.arm_occupancy import (
    arm_occupancy_frame,
    instr_word_mod_adaptive_correction,
)
from a4.runs.iv_pos_8.d2g.d2g_case import determine_case, render_case_verdict_md
from a4.runs.iv_pos_8.d2g.d2g_scores import compute_scores_frame, unique_useful_frame
from a4.runs.iv_pos_8.d2g.territory import (
    apples_to_apples_row,
    loc_overlap_pairs,
    territory_decomposition,
)
from a4.runs.iv_pos_8.d2g.triage_at_scale import triage_at_scale_pipeline

from a4.runs.iv_pos_7.analysis.stats import paired_tests


def _write(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    print(f"  wrote {path.name} ({len(df)} rows)")


def run_b1(collection_root: Path, out_dir: Path) -> dict:
    print(f"=== D2.G B1 — {collection_root} ===")
    dbs = flat_db_list(collection_root)
    print(f"  discovered {len(dbs)} DBs")

    metrics = compute_d2g_metrics_frame(collection_root)
    _write(metrics, out_dir / "d2g_metrics_table.csv")
    _write(aggregate_d2g_metrics(metrics), out_dir / "d2g_metrics_aggregate.csv")
    _write(territory_decomposition(collection_root), out_dir / "d2g_territory.csv")
    _write(loc_overlap_pairs(collection_root), out_dir / "d2g_loc_overlap.csv")
    _write(apples_to_apples_row(collection_root), out_dir / "d2g_apples_to_apples.csv")
    _write(discovery_rate_frame(collection_root), out_dir / "d2g_discovery_rate_by_kind.csv")

    channels = rejection_channels_frame(collection_root)
    _write(channels, out_dir / "d2g_rejection_channels.csv")
    _write(rejection_channels_summary(channels), out_dir / "d2g_rejection_channels_summary.csv")
    _write(cgc_field_collapse_frame(collection_root), out_dir / "d2g_cgc_field_collapse.csv")

    v6_sparse = None
    if not metrics.empty and "V6_uniform" in metrics["variant"].values:
        v6_sparse = bool(
            metrics.loc[metrics["variant"] == "V6_uniform", "telemetry_sparse"].all()
        )

    summary = {
        "phase": "B1",
        "collection_root": str(collection_root),
        "n_dbs": len(dbs),
        "variants": sorted(metrics["variant"].unique().tolist()) if not metrics.empty else [],
        "v6_uniform_telemetry_sparse": v6_sparse,
    }
    report_path = out_dir / "d2g_COLLECTION_REPORT.json"
    report_path.write_text(json.dumps(summary, indent=2))
    print(f"  wrote {report_path.name}")
    return summary


def run_b2(
    collection_root: Path,
    out_dir: Path,
    *,
    run_tier2: bool,
    host: str,
    host_args: list[str],
) -> dict:
    print(f"=== D2.G B2 — triage on {collection_root} ===")
    all_accepts = []
    for db in flat_db_list(collection_root):
        all_accepts.extend(extract_accepts(db))
    print(f"  extracted {len(all_accepts)} accept rows")

    triage_df = triage_accepts(
        all_accepts,
        host=host,
        host_args=host_args,
        run_tier2=run_tier2,
    )
    _write(triage_df, out_dir / "d2g_accept_triage.csv")
    _write(triage_summary(triage_df), out_dir / "d2g_accept_triage_summary.csv")

    oracle_ok, oracle_msg = validate_smoke_oracle(triage_df)
    print(f"  smoke oracle: {oracle_msg}")

    summary = {
        "phase": "B2",
        "n_accepts": len(all_accepts),
        "run_tier2": run_tier2,
        "oracle_pass": oracle_ok,
        "oracle_message": oracle_msg,
        "class_counts": triage_df["class"].value_counts().to_dict() if not triage_df.empty else {},
    }
    (out_dir / "d2g_triage_report.json").write_text(json.dumps(summary, indent=2))
    return summary


def run_b3(
    collection_root: Path,
    out_dir: Path,
    *,
    host: str,
    host_args: list[str],
    tier2_variant: str,
    tier2_limit: int | None,
    run_local_tier2: bool,
    triage_csv: Path | None = None,
) -> dict:
    print(f"=== D2.G B3 — scores + Case on {collection_root} ===")
    metrics = compute_d2g_metrics_frame(collection_root)
    channels = rejection_channels_frame(collection_root)
    territory = territory_decomposition(collection_root)

    # DG-1 triage-at-scale (tier-1 all + tier-2 sample + POS manifest)
    triage_out = out_dir / "triage_at_scale"
    scale_summary = triage_at_scale_pipeline(
        collection_root,
        triage_out,
        host=host,
        host_args=host_args,
        tier2_variant=tier2_variant,
        tier2_limit=tier2_limit,
        run_local_tier2=run_local_tier2,
    )
    print(f"  triage-at-scale: {scale_summary.get('raw_accepts')} raw accepts, "
          f"{scale_summary.get('deduped_rerun_jobs')} deduped rerun jobs")

    triage_sample_path = triage_out / "d2g_accept_triage_tier2_sample.csv"
    if triage_csv is not None and triage_csv.is_file():
        from a4.runs.iv_pos_8.d2g.triage_at_scale import dedupe_collected_triage

        triage_df = pd.read_csv(triage_csv)
        triage_df, n_dropped = dedupe_collected_triage(triage_df)
        if n_dropped:
            print(f"  triage CSV: dropped {n_dropped} duplicate row(s) from {triage_csv}")
        print(f"  triage CSV: {len(triage_df)} classified rows from {triage_csv}")
    elif triage_sample_path.is_file():
        triage_df = pd.read_csv(triage_sample_path)
    else:
        triage_df = None

    scores = compute_scores_frame(collection_root, metrics, channels, triage_df=triage_df)
    _write(scores, out_dir / "d2g_scores.csv")
    _write(unique_useful_frame(scores), out_dir / "d2g_unique_useful.csv")

    arm_occ = arm_occupancy_frame(collection_root)
    _write(arm_occ, out_dir / "d2g_arm_occupancy.csv")
    iwm = instr_word_mod_adaptive_correction(arm_occ)
    if not iwm.empty:
        _write(iwm, out_dir / "d2g_instr_word_mod_correction.csv")

    case_id, rationale, evidence = determine_case(scores, territory, metrics)
    paired = paired_tests(
        scores,
        reference="V6_uniform",
        metrics=[
            c for c in (
                "survey_unique_normalized_locs",
                "survey_cgc_final",
                "unique_locs_d_loc_le_2",
            ) if c in scores.columns
        ],
    )
    _write(paired, out_dir / "d2g_paired_tests.csv")
    verdict_md = render_case_verdict_md(case_id, rationale, evidence, paired, iwm_correction=iwm)
    (out_dir / "d2g_case_verdict.md").write_text(verdict_md)
    print(f"  provisional Case: {case_id}")

    summary = {
        "phase": "B3",
        "provisional_case": case_id,
        "case_rationale": rationale,
        "triage_at_scale": scale_summary,
        "evidence": evidence,
    }
    (out_dir / "d2g_b3_report.json").write_text(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build D2.G analysis artifacts")
    parser.add_argument(
        "collection_root",
        nargs="?",
        type=Path,
        default=DEFAULT_SMOKE,
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory (default: d2f/smoke/artifacts/d2g)",
    )
    parser.add_argument(
        "--phase",
        choices=("b1", "b2", "b3", "all"),
        default="all",
    )
    parser.add_argument(
        "--tier2-variant",
        default="Hybrid_cTS",
        help="B3: variant for triage-at-scale tier-2 sample",
    )
    parser.add_argument(
        "--tier2-limit",
        type=int,
        default=None,
        help="B3: cap local tier-2 reruns (default: all deduped for --tier2-variant)",
    )
    parser.add_argument(
        "--skip-local-tier2",
        action="store_true",
        help="B3: tier-1 + manifest only, no local trace reruns",
    )
    parser.add_argument(
        "--triage-csv",
        type=Path,
        default=None,
        help="B3: full post-POS triage CSV for soundness columns (overrides tier-2 sample)",
    )
    parser.add_argument(
        "--tier2",
        action="store_true",
        help="run Tier-2 trace reruns (requires real binary)",
    )
    parser.add_argument("--host", default=default_host())
    parser.add_argument(
        "--host-args",
        nargs=argparse.REMAINDER,
        default=default_host_args(),
    )
    args = parser.parse_args()
    collection_root = args.collection_root.resolve()
    out_dir = args.out or (collection_root.parent.parent / "artifacts" / "d2g")
    out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    if args.phase in ("b1", "all"):
        run_b1(collection_root, out_dir)
    if args.phase in ("b2", "all"):
        b2 = run_b2(
            collection_root,
            out_dir,
            run_tier2=args.tier2,
            host=args.host,
            host_args=list(args.host_args),
        )
        if args.tier2 and not b2.get("oracle_pass", True):
            exit_code = 1
    if args.phase in ("b3", "all"):
        run_b3(
            collection_root,
            out_dir,
            host=args.host,
            host_args=list(args.host_args),
            tier2_variant=args.tier2_variant,
            tier2_limit=args.tier2_limit,
            run_local_tier2=not args.skip_local_tier2,
            triage_csv=args.triage_csv.resolve() if args.triage_csv else None,
        )
    print("=== DONE ===")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
