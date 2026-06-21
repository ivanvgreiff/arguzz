"""Triage-at-scale: tier-1 DB pass, deduped tier-2 rerun manifest, POS/local dispatch (D2.G §3, B4)."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

TRIAGE_POS_NODES = [
    # Tier B (fastest available besides D2.F EPYC pool) then Tier C.
    "pact", "stoi", "idex", "meld", "tinyman",
]
# Legacy D2.F campaign nodes — do not use for triage while fuzz jobs run.
POS_NODES = [
    "flare", "polynize", "octorand", "opulous", "algofi", "zone", "gard", "goracle",
]
DEFAULT_POS_RESULTS_DIR = "/tmp/d2g_triage_results"
DEFAULT_POS_HOST_PATH = "/root/a4_campaign/bin/risc0-host"
DEFAULT_POS_REPO = "/root/a4_campaign/repo"


def triage_run_id(
    variant: str,
    seed: int,
    kind: str,
    step: int,
    iter_seed: int,
) -> str:
    """Unique run_one / chain run_id (iter_seed disambiguates same-step PEPC jobs)."""
    return f"triage_{variant}_s{seed}_{kind}_step{step}_is{iter_seed}"


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
    """Write kind-aware deduped tier-2 rerun manifest (ISS-4)."""
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
        out_name = run_id or triage_run_id(variant, seed, kind, step, iter_seed)
        out_path = results_dir / f"{out_name}.json"
        out_path.write_text(json.dumps(row, sort_keys=True))
    return row


def order_manifest_for_dispatch(manifest_df: pd.DataFrame) -> pd.DataFrame:
    """PEPC first (soundness lead), then IWM; stable within kind."""
    kind_rank = {"POST_EXEC_PC_MOD": 0, "INSTR_WORD_MOD": 1}
    df = manifest_df.copy()
    df["_kind_rank"] = df["kind"].map(kind_rank).fillna(9)
    df = df.sort_values(
        ["_kind_rank", "variant", "seed", "step", "iter_seed"],
        kind="mergesort",
    ).drop(columns=["_kind_rank"])
    return df.reset_index(drop=True)


def write_chain_manifest(
    manifest_df: pd.DataFrame,
    out_path: Path,
    *,
    host: Optional[str] = None,
    batch_prefix: str = "d2g_triage_rerun",
    results_dir: str = DEFAULT_POS_RESULTS_DIR,
    nodes: Optional[List[str]] = None,
) -> Path:
    """Emit chain_dispatcher-compatible manifest for POS tier-2 reruns.

    Jobs are grouped into waves of len(nodes): one job per node per batch so
    chain_dispatcher never stacks multiple concurrent writers on the same node.
    """
    pos_host = host or default_pos_host()
    host_args = default_host_args()
    args_str = " ".join(host_args)
    nodes = list(nodes or TRIAGE_POS_NODES)
    ordered = order_manifest_for_dispatch(manifest_df)
    records = ordered.to_dict("records")
    n_waves = (len(records) + len(nodes) - 1) // len(nodes) if records else 0
    lines = [
        f"# D2.G tier-2 triage reruns — {len(records)} jobs, {n_waves} batches, {len(nodes)} nodes",
        f"# nodes: {' '.join(nodes)}",
        "# format: batch|node|run_id|remote_cmd",
        "# One job per node per batch (chain_dispatcher 1-per-node concurrency rule).",
        "",
    ]
    for wave_idx in range(0, len(records), len(nodes)):
        batch_name = f"{batch_prefix}_w{(wave_idx // len(nodes)) + 1:04d}"
        chunk = records[wave_idx: wave_idx + len(nodes)]
        for node_idx, row in enumerate(chunk):
            node = nodes[node_idx]
            run_id = triage_run_id(
                str(row["variant"]),
                int(row["seed"]),
                str(row["kind"]),
                int(row["step"]),
                int(row["iter_seed"]),
            )
            cmd = (
                f"export A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 CONSTRAINT_CONTINUE=1 "
                f"D2G_BASELINE_CACHE={results_dir}/baseline_cache; "
                f"mkdir -p {results_dir} $D2G_BASELINE_CACHE && cd {DEFAULT_POS_REPO} && "
                f"PYTHONPATH={DEFAULT_POS_REPO} "
                f"python3 -m a4.runs.iv_pos_8.d2g.run_one_pos "
                f"--host {pos_host} --variant {row['variant']} --seed {int(row['seed'])} "
                f"--step {int(row['step'])} --kind {row['kind']} "
                f"--iter-seed {int(row['iter_seed'])} "
                f"--mutation-id {int(row.get('mutation_id', 0))} "
                f"--run-id {run_id} --results-dir {results_dir} "
                f"--host-args {args_str}"
            )
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
        run_id = triage_run_id(
            acc.variant, acc.seed, acc.kind, acc.step, acc.iter_seed,
        )
        row_dict = tier2_row_from_accept(
            acc, host=host, host_args=host_args, baseline=baseline, env=env, run_id=run_id,
        )
        if results_dir is not None:
            results_dir.mkdir(parents=True, exist_ok=True)
            (results_dir / f"{run_id}.json").write_text(json.dumps(row_dict, sort_keys=True))
        rows.append(row_dict)
    return pd.DataFrame(rows)


def expected_run_ids_from_manifest(manifest_csv: Path) -> set:
    """Reconstruct the full set of run_ids the manifest should produce (ISS-5)."""
    m = pd.read_csv(manifest_csv)
    return {
        triage_run_id(
            str(r["variant"]), int(r["seed"]), str(r["kind"]),
            int(r["step"]), int(r["iter_seed"]),
        )
        for _, r in m.iterrows()
    }


def collect_results(
    results_dir: Path,
    out_csv: Path,
    *,
    report_json: Optional[Path] = None,
    manifest_csv: Optional[Path] = None,
) -> pd.DataFrame:
    """Merge per-job run_one JSON outputs into one CSV + aggregated report.

    If ``manifest_csv`` is given, asserts completeness (every expected run_id has a
    result) so the soundness re-read never runs on a silent subset (ISS-5).
    """
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
    if manifest_csv is not None:
        expected = expected_run_ids_from_manifest(manifest_csv)
        got = set(df["run_id"]) if (not df.empty and "run_id" in df) else set()
        missing = sorted(expected - got)
        summary["n_expected"] = len(expected)
        summary["n_missing"] = len(missing)
        summary["complete"] = not missing
        summary["missing_run_ids"] = missing[:50]
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


def _manifest_row_to_accept(row: dict) -> AcceptRow:
    return AcceptRow(
        variant=str(row["variant"]),
        seed=int(row["seed"]),
        mutation_id=int(row.get("mutation_id", 0)),
        kind=str(row["kind"]),
        step=int(row["step"]),
        iter_seed=int(row["iter_seed"]),
        local_failures=int(row.get("local_failures", 0)),
        global_failures=int(row.get("global_failures", 0)),
    )


def _run_manifest_row(
    row: dict,
    *,
    host: str,
    host_args: List[str],
    baseline,
    results_dir: Path,
    resume: bool,
) -> dict:
    acc = _manifest_row_to_accept(row)
    run_id = triage_run_id(
        acc.variant, acc.seed, acc.kind, acc.step, acc.iter_seed,
    )
    out_path = results_dir / f"{run_id}.json"
    if resume and out_path.is_file():
        return {"run_id": run_id, "status": "skipped"}
    row_dict = tier2_row_from_accept(
        acc,
        host=host,
        host_args=host_args,
        baseline=baseline,
        env=None,
        run_id=run_id,
    )
    results_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(row_dict, sort_keys=True))
    return {"run_id": run_id, "status": "ok", "class": row_dict.get("class")}


def run_manifest(
    manifest_df: pd.DataFrame,
    *,
    host: str,
    host_args: Optional[List[str]] = None,
    results_dir: Path,
    workers: int = 1,
    resume: bool = True,
    limit: Optional[int] = None,
) -> dict:
    """Run tier-2 for every manifest row (resumable local/POS substitute)."""
    host_args = host_args or default_host_args()
    cache: Dict[str, list] = {}
    baseline = baseline_traces(host, host_args, env=None, cache=cache)
    subset = manifest_df.head(limit) if limit else manifest_df
    records = subset.to_dict("records")
    results_dir.mkdir(parents=True, exist_ok=True)
    stats = {"total": len(records), "ok": 0, "skipped": 0, "error": 0}

    if workers <= 1:
        for row in records:
            try:
                result = _run_manifest_row(
                    row,
                    host=host,
                    host_args=host_args,
                    baseline=baseline,
                    results_dir=results_dir,
                    resume=resume,
                )
                stats[result["status"]] += 1
            except Exception as exc:  # noqa: BLE001 — aggregate runner must continue
                stats["error"] += 1
                print(f"ERROR {row.get('variant')} step={row.get('step')}: {exc}", file=sys.stderr)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _run_manifest_row,
                    row,
                    host=host,
                    host_args=host_args,
                    baseline=baseline,
                    results_dir=results_dir,
                    resume=resume,
                ): row
                for row in records
            }
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    stats[result["status"]] += 1
                except Exception as exc:  # noqa: BLE001
                    stats["error"] += 1
                    row = futures[fut]
                    print(
                        f"ERROR {row.get('variant')} step={row.get('step')}: {exc}",
                        file=sys.stderr,
                    )
    stats["json_count"] = len(list(results_dir.glob("*.json")))
    return stats


def _ssh_cmd(node: str, remote_cmd: str, *, timeout: int = 30) -> Tuple[int, str]:
    proc = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=no", node, remote_cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    if proc.stderr:
        out = f"{out}\n{proc.stderr.strip()}".strip()
    return proc.returncode, out


def preflight_pos(
    nodes: Optional[List[str]] = None,
    *,
    pos_host: str = DEFAULT_POS_HOST_PATH,
    repo_path: str = DEFAULT_POS_REPO,
) -> dict:
    """Verify POS nodes have host binary + current triage module."""
    nodes = nodes or TRIAGE_POS_NODES
    rows: List[dict] = []
    for node in nodes:
        rc, out = _ssh_cmd(
            node,
            f"test -x {pos_host} && test -f {repo_path}/a4/runs/iv_pos_8/d2g/run_one_pos.py "
            f"&& cd {repo_path} && PYTHONPATH={repo_path} python3 -c "
            f"\"import a4.runs.iv_pos_8.d2g.run_one_pos\" "
            f"&& echo OK",
            timeout=20,
        )
        rows.append({
            "node": node,
            "ok": rc == 0 and "OK" in out,
            "detail": out or f"exit={rc}",
        })
    return {
        "nodes_checked": len(rows),
        "nodes_ok": sum(1 for r in rows if r["ok"]),
        "all_ok": all(r["ok"] for r in rows),
        "checks": rows,
    }


def gather_pos_results(
    local_dir: Path,
    *,
    nodes: Optional[List[str]] = None,
    remote_dir: str = DEFAULT_POS_RESULTS_DIR,
) -> dict:
    """SCP triage JSON from each POS node into local_dir/<node>/."""
    nodes = nodes or TRIAGE_POS_NODES
    local_dir.mkdir(parents=True, exist_ok=True)
    merged = local_dir / "merged"
    merged.mkdir(parents=True, exist_ok=True)
    per_node: List[dict] = []
    total = 0
    for node in nodes:
        node_dir = local_dir / node
        node_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [
                "scp", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=no",
                f"{node}:{remote_dir}/*.json", f"{node_dir}/",
            ],
            capture_output=True,
            text=True,
        )
        n_json = len(list(node_dir.glob("*.json")))
        total += n_json
        per_node.append({
            "node": node,
            "json_count": n_json,
            "scp_rc": proc.returncode,
            "scp_err": (proc.stderr or "").strip()[:200],
        })
        for path in node_dir.glob("*.json"):
            link = merged / path.name
            if not link.exists():
                link.write_bytes(path.read_bytes())
    return {
        "nodes": per_node,
        "total_json": total,
        "merged_unique": len(list(merged.glob("*.json"))),
        "merged_dir": str(merged),
    }


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
        nodes=os.environ.get("A4_TRIAGE_NODES", "").split() or None,
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
    p_collect.add_argument("--manifest", type=Path, default=None,
                           help="Manifest CSV to assert result completeness (ISS-5)")

    p_smoke = sub.add_parser("smoke", help="Run ≤10 local run_one jobs + collect")
    p_smoke.add_argument("manifest_csv", type=Path)
    p_smoke.add_argument("--results-dir", type=Path, required=True)
    p_smoke.add_argument("--out", type=Path, required=True)
    p_smoke.add_argument("--host", default=default_host())
    p_smoke.add_argument("--limit", type=int, default=10)
    p_smoke.add_argument("--host-args", nargs=argparse.REMAINDER, default=None)

    p_run = sub.add_parser("run_manifest", help="Run full manifest locally (resumable)")
    p_run.add_argument("manifest_csv", type=Path)
    p_run.add_argument("--results-dir", type=Path, required=True)
    p_run.add_argument("--host", default=default_host())
    p_run.add_argument("--workers", type=int, default=1)
    p_run.add_argument("--no-resume", action="store_true")
    p_run.add_argument("--limit", type=int, default=None)
    p_run.add_argument("--host-args", nargs=argparse.REMAINDER, default=None)

    p_gather = sub.add_parser("gather", help="SCP triage JSON from POS nodes")
    p_gather.add_argument("--out", type=Path, required=True)
    p_gather.add_argument("--remote-dir", default=DEFAULT_POS_RESULTS_DIR)
    p_gather.add_argument("--nodes", nargs="*", default=None)

    p_preflight = sub.add_parser("preflight", help="Verify POS nodes ready for triage")
    p_preflight.add_argument("--nodes", nargs="*", default=None)

    p_chain = sub.add_parser("write-chain", help="Write chain manifest from CSV")
    p_chain.add_argument("manifest_csv", type=Path)
    p_chain.add_argument("--out", type=Path, required=True)
    p_chain.add_argument("--nodes", nargs="+", default=None)

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
        manifest_csv = args.manifest.resolve() if args.manifest else None
        df = collect_results(
            args.results_dir.resolve(),
            args.out.resolve(),
            report_json=args.report.resolve() if args.report else None,
            manifest_csv=manifest_csv,
        )
        out = {"n_rows": len(df), "out": str(args.out)}
        if manifest_csv is not None:
            expected = expected_run_ids_from_manifest(manifest_csv)
            got = set(df["run_id"]) if (not df.empty and "run_id" in df) else set()
            missing = sorted(expected - got)
            out["n_expected"] = len(expected)
            out["n_missing"] = len(missing)
            if missing:
                out["complete"] = False
                out["missing_sample"] = missing[:20]
                print(json.dumps(out, indent=2))
                print(
                    f"INCOMPLETE: {len(missing)}/{len(expected)} results missing — "
                    f"re-dispatch the missing run_ids before the soundness re-read.",
                    file=sys.stderr,
                )
                return 3
            out["complete"] = True
        print(json.dumps(out, indent=2))
        return 0

    if args.cmd == "smoke":
        manifest = pd.read_csv(args.manifest_csv)
        subset = manifest.head(args.limit)
        args.results_dir.mkdir(parents=True, exist_ok=True)
        host_args = _parse_host_args(args.host_args)
        for _, row in subset.iterrows():
            run_id = triage_run_id(
                str(row["variant"]),
                int(row["seed"]),
                str(row["kind"]),
                int(row["step"]),
                int(row["iter_seed"]),
            )
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

    if args.cmd == "run_manifest":
        manifest = pd.read_csv(args.manifest_csv)
        stats = run_manifest(
            manifest,
            host=args.host,
            host_args=_parse_host_args(args.host_args),
            results_dir=args.results_dir.resolve(),
            workers=max(1, args.workers),
            resume=not args.no_resume,
            limit=args.limit,
        )
        print(json.dumps(stats, indent=2))
        return 0 if stats.get("error", 0) == 0 else 1

    if args.cmd == "gather":
        report = gather_pos_results(
            args.out.resolve(),
            nodes=args.nodes or None,
            remote_dir=args.remote_dir,
        )
        print(json.dumps(report, indent=2))
        return 0

    if args.cmd == "preflight":
        report = preflight_pos(nodes=args.nodes or None)
        print(json.dumps(report, indent=2))
        return 0 if report["all_ok"] else 1

    if args.cmd == "write-chain":
        manifest = pd.read_csv(args.manifest_csv)
        path = write_chain_manifest(
            manifest,
            args.out.resolve(),
            nodes=args.nodes,
        )
        n_batches = len({l.split("|")[0] for l in path.read_text().splitlines()
                         if l and not l.startswith("#") and "|" in l})
        print(json.dumps({
            "chain": str(path),
            "jobs": len(manifest),
            "batches": n_batches,
            "nodes": args.nodes or TRIAGE_POS_NODES,
        }, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
