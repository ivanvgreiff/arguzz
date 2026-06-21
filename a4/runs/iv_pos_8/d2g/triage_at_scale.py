"""Triage-at-scale: tier-1 DB pass, deduped tier-2 rerun manifest, POS/local dispatch (D2.G §3, B4)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from .discover import flat_db_list, parse_d2f_run_dir
from .propagation_triage import (
    AcceptRow,
    TRIAGE_HIDDEN,
    baseline_traces,
    default_host,
    default_host_args,
    dedupe_accepts_for_rerun,
    extract_accepts,
    tier1_classify,
    tier2_classify,
)

GUEST_KEY = "--in1 5 --in4 10"


def default_pos_host() -> str:
    return os.environ.get("A4_POS_HOST", "/root/a4_campaign/bin/risc0-host").strip()


TRIAGE_ROW_COLUMNS = [
    "variant", "seed", "mutation_id", "kind", "step", "iter_seed",
    "class", "evidence", "trace_changed", "post_inject_pc_changed",
    "post_inject_trace_changed", "inject_disasm_changed", "unaligned_access",
    "fault_word_change", "global_residue", "run_id",
]


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


def _resolve_variant_filter(tier2_variant: Optional[str]) -> Optional[str]:
    if not tier2_variant or tier2_variant.lower() in ("all", "none", "*"):
        return None
    return tier2_variant


def build_rerun_manifest(
    accepts_df: pd.DataFrame,
    out_path: Path,
    *,
    variant_filter: Optional[str] = None,
    dedupe: bool = True,
) -> pd.DataFrame:
    """Write deduped tier-2 rerun manifest (one row per kind×step globally)."""
    df = accepts_df.copy()
    if variant_filter:
        df = df[df["variant"] == variant_filter]
    if dedupe:
        df = dedupe_accepts_for_rerun(df)
    df = df.assign(guest=GUEST_KEY)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    return df


def tier2_row_from_accept(
    acc: AcceptRow,
    *,
    host: str,
    host_args: List[str],
    baseline,
    env: Optional[dict],
    run_id: str = "",
) -> dict:
    """Classify one accept via live tier2_classify → classify_semantics."""
    t2 = tier2_classify(
        acc, host=host, host_args=host_args, baseline=baseline, env=env,
    )
    return {
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
        "run_id": run_id,
    }


def run_one(
    *,
    variant: str,
    seed: int,
    step: int,
    kind: str,
    iter_seed: int,
    host: str,
    host_args: Optional[List[str]] = None,
    mutation_id: int = 0,
    local_failures: int = 0,
    global_failures: int = 0,
    env: Optional[dict] = None,
    run_id: str = "",
    results_dir: Optional[Path] = None,
) -> dict:
    """Triage a single accept; write JSON result and return the row dict."""
    host_args = host_args or default_host_args()
    acc = AcceptRow(
        variant=variant,
        seed=seed,
        mutation_id=mutation_id,
        kind=kind,
        step=step,
        iter_seed=iter_seed,
        local_failures=local_failures,
        global_failures=global_failures,
    )
    baseline = baseline_traces(host, host_args, env=env)
    row = tier2_row_from_accept(
        acc, host=host, host_args=host_args, baseline=baseline, env=env, run_id=run_id,
    )
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        out_name = run_id or f"triage_{variant}_s{seed}_{kind}_step{step}"
        out_path = results_dir / f"{out_name}.json"
        out_path.write_text(json.dumps(row, sort_keys=True))
    return row


def write_chain_manifest(
    manifest_df: pd.DataFrame,
    out_path: Path,
    *,
    host: Optional[str] = None,
    batch_name: str = "d2g_triage_rerun",
    results_dir: str = "/tmp/d2g_triage_results",
) -> Path:
    """Emit chain_dispatcher-compatible manifest for POS tier-2 reruns."""
    pos_host = host or default_pos_host()
    host_args = default_host_args()
    args_str = " ".join(host_args)
    lines = [
        f"# D2.G tier-2 triage reruns — {len(manifest_df)} deduped jobs",
        "# format: batch|node|run_id|remote_cmd",
        "",
    ]
    nodes = ["flare", "polynize", "octorand", "opulous", "algofi", "zone", "gard", "goracle"]
    for i, row in manifest_df.iterrows():
        run_id = (
            f"triage_{row['variant']}_s{row['seed']}_{row['kind']}_step{row['step']}"
        )
        cmd = (
            f"export A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 CONSTRAINT_CONTINUE=1; "
            f"mkdir -p {results_dir} && cd /root/a4_campaign/repo && "
            f"PYTHONPATH=/root/a4_campaign/repo "
            f"python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale run_one "
            f"--host {pos_host} --variant {row['variant']} --seed {int(row['seed'])} "
            f"--step {int(row['step'])} --kind {row['kind']} "
            f"--iter-seed {int(row['iter_seed'])} "
            f"--mutation-id {int(row.get('mutation_id', 0))} "
            f"--host-args {args_str} "
            f"--run-id {run_id} --results-dir {results_dir}"
        )
        node = nodes[i % len(nodes)]
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
    results_dir: Optional[Path] = None,
) -> pd.DataFrame:
    """Run tier-2 classification for manifest rows locally."""
    host_args = host_args or default_host_args()
    cache: Dict[str, list] = {}
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
        run_id = f"triage_{acc.variant}_s{acc.seed}_{acc.kind}_step{acc.step}"
        row_dict = tier2_row_from_accept(
            acc, host=host, host_args=host_args, baseline=baseline, env=env, run_id=run_id,
        )
        if results_dir is not None:
            results_dir.mkdir(parents=True, exist_ok=True)
            (results_dir / f"{run_id}.json").write_text(json.dumps(row_dict, sort_keys=True))
        rows.append(row_dict)
    return pd.DataFrame(rows)


def collect_results(
    results_dir: Path,
    out_csv: Path,
    *,
    report_json: Optional[Path] = None,
) -> pd.DataFrame:
    """Merge per-job run_one JSON outputs into one CSV + aggregated report."""
    rows: List[dict] = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            rows.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    df = pd.DataFrame(rows)
    if not df.empty:
        for col in TRIAGE_ROW_COLUMNS:
            if col not in df.columns:
                df[col] = ""
        df = df[TRIAGE_ROW_COLUMNS]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False)

    summary = {
        "n_results": len(df),
        "results_dir": str(results_dir),
        "out_csv": str(out_csv),
    }
    if not df.empty:
        summary["class_counts"] = df["class"].value_counts().to_dict()
        summary["evidence_counts"] = df["evidence"].value_counts().to_dict()
        summary["by_variant_kind"] = (
            df.groupby(["variant", "kind", "class", "evidence"])
            .size()
            .reset_index(name="count")
            .to_dict(orient="records")
        )
    if report_json is not None:
        report_json.write_text(json.dumps(summary, indent=2))
    return df


def triage_at_scale_pipeline(
    collection_root: Path,
    out_dir: Path,
    *,
    host: str,
    host_args: Optional[List[str]] = None,
    tier2_variant: Optional[str] = "Hybrid_cTS",
    tier2_limit: Optional[int] = None,
    run_local_tier2: bool = True,
    results_dir: Optional[Path] = None,
) -> dict:
    """Full pipeline: tier1 all accepts, manifest, optional tier2 sample."""
    out_dir.mkdir(parents=True, exist_ok=True)
    variant_filter = _resolve_variant_filter(tier2_variant)
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
        variant_filter=variant_filter,
        dedupe=True,
    )
    chain_path = write_chain_manifest(
        manifest, out_dir / "d2g_triage_rerun.chain",
    )

    triage_df = pd.DataFrame()
    local_results = results_dir or (out_dir / "run_one_results")
    if run_local_tier2 and not manifest.empty:
        triage_df = run_tier2_local(
            manifest,
            host=host,
            host_args=host_args,
            limit=tier2_limit,
            results_dir=local_results if tier2_limit else None,
        )
        triage_df.to_csv(out_dir / "d2g_accept_triage_tier2_sample.csv", index=False)

    hidden_n = int((tier1_df["tier1_class"] == TRIAGE_HIDDEN).sum())
    kind_counts = accepts_df["kind"].value_counts().to_dict() if not accepts_df.empty else {}
    summary = {
        "guest": GUEST_KEY,
        "raw_accepts": len(accepts_df),
        "raw_accepts_by_kind": kind_counts,
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


def _parse_host_args(raw: Optional[List[str]]) -> List[str]:
    if not raw:
        return default_host_args()
    return list(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="D2.G triage-at-scale")
    sub = parser.add_subparsers(dest="cmd")

    p_pipe = sub.add_parser("pipeline")
    p_pipe.add_argument("collection_root", type=Path)
    p_pipe.add_argument("--out", type=Path, required=True)
    p_pipe.add_argument("--host", default=default_host())
    p_pipe.add_argument("--tier2-variant", default="Hybrid_cTS",
                        help="Variant name or 'all' for every variant with accepts")
    p_pipe.add_argument("--tier2-limit", type=int, default=None)
    p_pipe.add_argument("--no-local-tier2", action="store_true")

    p_one = sub.add_parser("run_one", help="Classify a single accept (POS/local)")
    p_one.add_argument("--host", default=default_host())
    p_one.add_argument("--variant", required=True)
    p_one.add_argument("--seed", type=int, required=True)
    p_one.add_argument("--step", type=int, required=True)
    p_one.add_argument("--kind", required=True)
    p_one.add_argument("--iter-seed", type=int, required=True)
    p_one.add_argument("--mutation-id", type=int, default=0)
    p_one.add_argument("--host-args", nargs=argparse.REMAINDER, default=None)
    p_one.add_argument("--run-id", default="")
    p_one.add_argument("--results-dir", type=Path, default=None)

    p_collect = sub.add_parser("collect", help="Merge run_one JSON outputs")
    p_collect.add_argument("results_dir", type=Path)
    p_collect.add_argument("--out", type=Path, required=True)
    p_collect.add_argument("--report", type=Path, default=None)

    p_smoke = sub.add_parser("smoke", help="Run ≤10 local run_one jobs + collect")
    p_smoke.add_argument("manifest_csv", type=Path)
    p_smoke.add_argument("--results-dir", type=Path, required=True)
    p_smoke.add_argument("--out", type=Path, required=True)
    p_smoke.add_argument("--host", default=default_host())
    p_smoke.add_argument("--limit", type=int, default=10)
    p_smoke.add_argument("--host-args", nargs=argparse.REMAINDER, default=None)

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

    if args.cmd == "run_one":
        row = run_one(
            variant=args.variant,
            seed=args.seed,
            step=args.step,
            kind=args.kind,
            iter_seed=args.iter_seed,
            host=args.host,
            host_args=_parse_host_args(args.host_args),
            mutation_id=args.mutation_id,
            run_id=args.run_id,
            results_dir=args.results_dir,
        )
        print(json.dumps(row, sort_keys=True))
        return 0

    if args.cmd == "collect":
        df = collect_results(
            args.results_dir.resolve(),
            args.out.resolve(),
            report_json=args.report.resolve() if args.report else None,
        )
        print(json.dumps({"n_rows": len(df), "out": str(args.out)}, indent=2))
        return 0

    if args.cmd == "smoke":
        manifest = pd.read_csv(args.manifest_csv)
        subset = manifest.head(args.limit)
        args.results_dir.mkdir(parents=True, exist_ok=True)
        host_args = _parse_host_args(args.host_args)
        for _, row in subset.iterrows():
            run_id = f"triage_{row['variant']}_s{row['seed']}_{row['kind']}_step{row['step']}"
            run_one(
                variant=str(row["variant"]),
                seed=int(row["seed"]),
                step=int(row["step"]),
                kind=str(row["kind"]),
                iter_seed=int(row["iter_seed"]),
                host=args.host,
                host_args=host_args,
                mutation_id=int(row.get("mutation_id", 0)),
                run_id=run_id,
                results_dir=args.results_dir,
            )
        collect_results(
            args.results_dir,
            args.out,
            report_json=args.results_dir / "smoke_collect_report.json",
        )
        print(json.dumps({"smoke_jobs": len(subset), "out": str(args.out)}, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
