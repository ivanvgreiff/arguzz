"""Triage-at-scale: tier-1 DB pass, deduped tier-2 rerun manifest, local dispatch (D2.G §3, DG-1)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, List, Optional

import pandas as pd

from .discover import flat_db_list, parse_d2f_run_dir
from .propagation_triage import (
    AcceptRow,
    TRIAGE_HIDDEN,
    default_host,
    default_host_args,
    dedupe_accepts_for_rerun,
    extract_accepts,
    tier1_classify,
    tier2_classify,
    triage_accepts,
    triage_summary,
    baseline_traces,
)

GUEST_KEY = "--in1 5 --in4 10"


def accept_rows_to_frame(accepts: List[AcceptRow]) -> pd.DataFrame:
    rows = [
        {
            "variant": a.variant,
            "seed": a.seed,
            "mutation_id": a.mutation_id,
            "kind": a.kind,
            "step": a.step,
            "iter_seed": a.iter_seed,
            "local_failures": a.local_failures,
            "global_failures": a.global_failures,
        }
        for a in accepts
    ]
    return pd.DataFrame(rows)


def tier1_pass(collection_root: Path) -> pd.DataFrame:
    """Cheap DB-only pass: flag hidden global rejects; mark others pending tier-2."""
    rows: List[dict] = []
    for db in flat_db_list(collection_root):
        for acc in extract_accepts(db):
            t1 = tier1_classify(acc)
            rows.append({
                "variant": acc.variant,
                "seed": acc.seed,
                "mutation_id": acc.mutation_id,
                "kind": acc.kind,
                "step": acc.step,
                "iter_seed": acc.iter_seed,
                "guest": GUEST_KEY,
                "tier1_class": t1 or "pending_tier2",
                "global_failures": acc.global_failures,
            })
    return pd.DataFrame(rows)


def build_rerun_manifest(
    accepts_df: pd.DataFrame,
    out_path: Path,
    *,
    variant_filter: Optional[str] = None,
    dedupe: bool = True,
) -> pd.DataFrame:
    """Write deduped tier-2 rerun manifest (one row per guest×kind×step)."""
    df = accepts_df.copy()
    if variant_filter:
        df = df[df["variant"] == variant_filter]
    if dedupe:
        df = dedupe_accepts_for_rerun(df)
    df = df.assign(guest=GUEST_KEY)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    return df


def write_chain_manifest(
    manifest_df: pd.DataFrame,
    out_path: Path,
    *,
    host: str,
    batch_name: str = "d2g_triage_rerun",
) -> Path:
    """Emit chain_dispatcher-compatible manifest for POS tier-2 reruns."""
    host_args = default_host_args()
    args_str = " ".join(host_args)
    lines = [
        f"# D2.G tier-2 triage reruns — {len(manifest_df)} deduped jobs",
        "# format: batch|node|run_id|remote_cmd",
        "",
    ]
    for i, row in manifest_df.iterrows():
        run_id = (
            f"triage_{row['variant']}_s{row['seed']}_{row['kind']}_step{row['step']}"
        )
        cmd = (
            f"export A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 CONSTRAINT_CONTINUE=1; "
            f"cd /root/a4_campaign/repo && PYTHONPATH=/root/a4_campaign/repo "
            f"python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale run_one "
            f"--host {host} --step {row['step']} --kind {row['kind']} "
            f"--seed {row['iter_seed']} --host-args {args_str}"
        )
        node = ["flare", "polynize", "octorand", "opulous", "algofi", "zone", "gard", "goracle"][i % 8]
        lines.append(f"{batch_name}|{node}|{run_id}|{cmd}")
    out_path.write_text("\n".join(lines) + "\n")
    return out_path


def run_tier2_local(
    manifest_df: pd.DataFrame,
    *,
    host: str,
    host_args: Optional[List[str]] = None,
    env: Optional[dict] = None,
    limit: Optional[int] = None,
) -> pd.DataFrame:
    """Run tier-2 classification for manifest rows locally."""
    host_args = host_args or default_host_args()
    cache = {}
    baseline = baseline_traces(host, host_args, env=env, cache=cache)
    rows: List[dict] = []
    subset = manifest_df.head(limit) if limit else manifest_df
    for _, row in subset.iterrows():
        acc = AcceptRow(
            variant=str(row["variant"]),
            seed=int(row["seed"]),
            mutation_id=int(row.get("mutation_id", 0)),
            kind=str(row["kind"]),
            step=int(row["step"]),
            iter_seed=int(row["iter_seed"]),
            local_failures=int(row.get("local_failures", 0)),
            global_failures=int(row.get("global_failures", 0)),
        )
        t2 = tier2_classify(
            acc, host=host, host_args=host_args, baseline=baseline, env=env,
        )
        rows.append({
            "variant": acc.variant,
            "seed": acc.seed,
            "mutation_id": acc.mutation_id,
            "kind": acc.kind,
            "step": acc.step,
            "iter_seed": acc.iter_seed,
            "class": t2.klass,
            "evidence": t2.evidence,
            "trace_changed": t2.trace_changed,
            "post_inject_pc_changed": t2.post_inject_pc_changed,
            "post_inject_trace_changed": t2.post_inject_trace_changed,
            "inject_disasm_changed": t2.inject_disasm_changed,
            "unaligned_access": t2.unaligned_access,
            "fault_word_change": t2.fault_word_change,
            "global_residue": acc.global_failures > 0,
        })
    return pd.DataFrame(rows)


def triage_at_scale_pipeline(
    collection_root: Path,
    out_dir: Path,
    *,
    host: str,
    host_args: Optional[List[str]] = None,
    tier2_variant: Optional[str] = "Hybrid_cTS",
    tier2_limit: Optional[int] = None,
    run_local_tier2: bool = True,
) -> dict:
    """Full DG-1 pipeline: tier1 all accepts, manifest, optional tier2 sample."""
    out_dir.mkdir(parents=True, exist_ok=True)
    all_accepts = []
    for db in flat_db_list(collection_root):
        all_accepts.extend(extract_accepts(db))
    accepts_df = accept_rows_to_frame(all_accepts)
    accepts_df.to_csv(out_dir / "d2g_raw_accepts.csv", index=False)

    tier1_df = tier1_pass(collection_root)
    tier1_df.to_csv(out_dir / "d2g_tier1_pass.csv", index=False)

    manifest = build_rerun_manifest(
        accepts_df,
        out_dir / "d2g_triage_rerun_manifest.csv",
        variant_filter=tier2_variant,
        dedupe=True,
    )
    chain_path = write_chain_manifest(
        manifest, out_dir / "d2g_triage_rerun.chain", host=host,
    )

    triage_df = pd.DataFrame()
    if run_local_tier2 and not manifest.empty:
        triage_df = run_tier2_local(
            manifest,
            host=host,
            host_args=host_args,
            limit=tier2_limit,
        )
        triage_df.to_csv(out_dir / "d2g_accept_triage_tier2_sample.csv", index=False)

    # Extrapolate tier1 hidden + tier2 sample stats
    hidden_n = int((tier1_df["tier1_class"] == TRIAGE_HIDDEN).sum())
    summary = {
        "guest": GUEST_KEY,
        "raw_accepts": len(accepts_df),
        "tier1_hidden_global_reject": hidden_n,
        "tier1_pending_tier2": int((tier1_df["tier1_class"] == "pending_tier2").sum()),
        "deduped_rerun_jobs": len(manifest),
        "tier2_variant_filter": tier2_variant,
        "tier2_local_ran": run_local_tier2,
        "tier2_local_rows": len(triage_df),
        "chain_manifest": str(chain_path),
    }
    if not triage_df.empty:
        summary["tier2_class_counts"] = triage_df["class"].value_counts().to_dict()
        summary["tier2_evidence_counts"] = triage_df["evidence"].value_counts().to_dict()
    (out_dir / "d2g_triage_at_scale_report.json").write_text(
        json.dumps(summary, indent=2)
    )
    return summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="D2.G triage-at-scale")
    sub = parser.add_subparsers(dest="cmd")

    p_pipe = sub.add_parser("pipeline")
    p_pipe.add_argument("collection_root", type=Path)
    p_pipe.add_argument("--out", type=Path, required=True)
    p_pipe.add_argument("--host", default=default_host())
    p_pipe.add_argument("--tier2-variant", default="Hybrid_cTS")
    p_pipe.add_argument("--tier2-limit", type=int, default=None)
    p_pipe.add_argument("--no-local-tier2", action="store_true")

    args = parser.parse_args()
    if args.cmd == "pipeline":
        summary = triage_at_scale_pipeline(
            args.collection_root.resolve(),
            args.out.resolve(),
            host=args.host,
            tier2_variant=args.tier2_variant,
            tier2_limit=args.tier2_limit,
            run_local_tier2=not args.no_local_tier2,
        )
        print(json.dumps(summary, indent=2))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
