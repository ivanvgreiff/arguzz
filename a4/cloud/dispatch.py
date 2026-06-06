#!/usr/bin/env python3
"""
DEFERRED OPTIONAL BACKEND — NOT THE DEFAULT PATH (Jun 4, 2026)
==============================================================
The primary backend is now the university POS testbed; see
``a4/pos/dispatch_pos.py`` for the POS-native dispatcher.

This module is kept because its core (manifest schema, Cartesian
``(strategy, seed)`` enumeration, per-pair launch, manifest
writeback) is reused there; only the underlying launcher
(``gcloud run jobs execute`` vs ``pos commands launch``) differs.

Do not use this dispatcher for current campaigns.
==============================================================

Phase IV.0 — Cloud Run Jobs dispatcher.

Enumerates the (strategy, seed) cartesian product for a campaign batch
and submits one Cloud Run Jobs execution per pair, with the env vars
that run_campaign.sh expects.

Single-seed-per-job by design. Cross-seed and cross-strategy parallelism
come from Cloud Run's max_concurrent_tasks (not from this script).

Usage:
    python -m a4.cloud.dispatch \\
        --campaign-name cloud_ab_v1 \\
        --image-uri us-central1-docker.pkg.dev/PROJECT/REPO/arguzz-cloud:v1 \\
        --bucket arguzz-results \\
        --strategies uniform zoned bandit \\
        --seeds 42 43 44 45 46 \\
        --num 5000 \\
        --region us-central1 \\
        --job-name arguzz-fuzz \\
        --dry-run

Without --dry-run: actually calls `gcloud run jobs execute` for each pair
and writes dispatch_manifest.json with the returned execution names.

This script does NOT create the job template (the gcloud command for
that is a one-time setup step; see the IV.0 README in this dir).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gcloud_execute_job(
    *,
    job_name: str,
    region: str,
    env_vars: dict,
    image_uri: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    dry_run: bool = False,
) -> dict:
    """
    Submit one Cloud Run Jobs execution. Returns a dict with stdout, stderr,
    exit code, and the parsed execution name (if available).
    """
    update_str = ",".join(f"{k}={v}" for k, v in env_vars.items())
    cmd = [
        "gcloud", "run", "jobs", "execute", job_name,
        "--region", region,
        "--update-env-vars", update_str,
        "--format=json",
        "--async",
    ]
    if image_uri:
        cmd += ["--image", image_uri]
    if extra_args:
        cmd += extra_args

    if dry_run:
        return {
            "command": cmd,
            "env": env_vars,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "execution_name": None,
            "dry_run": True,
        }

    proc = subprocess.run(cmd, capture_output=True, text=True)
    execution_name = None
    if proc.returncode == 0:
        try:
            parsed = json.loads(proc.stdout)
            execution_name = parsed.get("metadata", {}).get("name")
        except (json.JSONDecodeError, AttributeError):
            execution_name = None
    return {
        "command": cmd,
        "env": env_vars,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "exit_code": proc.returncode,
        "execution_name": execution_name,
        "dry_run": False,
    }


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dispatch",
        description=__doc__,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--campaign-name", required=True,
                   help="Human-readable campaign batch name (e.g. 'cloud_ab_v1').")
    p.add_argument("--bucket", required=True,
                   help="GCS bucket for results (no gs:// prefix).")
    p.add_argument("--strategies", nargs="+", required=True,
                   help="Strategy labels: uniform | zoned | bandit. Repeat for more.")
    p.add_argument("--seeds", nargs="+", type=int, required=True,
                   help="Seeds (one per replicate). Will be paired Cartesianly with strategies.")
    p.add_argument("--num", type=int, required=True,
                   help="Mutations per campaign.")
    p.add_argument("--b-count", type=int, default=16,
                   help="Bandit b-count (default 16). Ignored for non-bandit.")
    p.add_argument("--job-name", required=True,
                   help="The pre-created Cloud Run Jobs name to invoke.")
    p.add_argument("--region", required=True,
                   help="GCP region for the job (e.g. us-central1).")
    p.add_argument("--image-uri", default=None,
                   help="Override the image URI (Artifact Registry path). "
                        "Default: use whatever the job is already configured with.")
    p.add_argument("--host-args", default="--in1 5 --in4 10",
                   help="Args after '--' in cli.py fuzz (default '--in1 5 --in4 10').")
    p.add_argument("--manifest-out", default="dispatch_manifest.json",
                   help="Where to write the per-execution manifest (default cwd).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print commands without invoking gcloud.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    valid_strats = {"uniform", "zoned", "guided", "bandit"}
    for s in args.strategies:
        if s not in valid_strats:
            print(f"error: unknown strategy '{s}'; valid: {sorted(valid_strats)}",
                  file=sys.stderr)
            return 2

    executions = []
    submitted_at = time.time()
    for strategy in args.strategies:
        for seed in args.seeds:
            run_id = f"{strategy}_seed{seed}_{int(submitted_at)}"
            env_vars = {
                "A4_STRATEGY":      strategy,
                "A4_SEED":          str(seed),
                "A4_NUM":           str(args.num),
                "A4_BUCKET":        args.bucket,
                "A4_CAMPAIGN_NAME": args.campaign_name,
                "A4_B_COUNT":       str(args.b_count),
                "A4_HOST_ARGS":     args.host_args,
                "A4_RUN_ID":        run_id,
            }
            print(f"[dispatch] submitting {strategy} seed={seed} run_id={run_id}")
            result = _gcloud_execute_job(
                job_name=args.job_name,
                region=args.region,
                env_vars=env_vars,
                image_uri=args.image_uri,
                dry_run=args.dry_run,
            )
            executions.append({
                "strategy": strategy,
                "seed": seed,
                "run_id": run_id,
                "env": env_vars,
                "execution_name": result.get("execution_name"),
                "exit_code": result["exit_code"],
                "stderr": result["stderr"][:2000] if result.get("stderr") else "",
            })
            if result["exit_code"] != 0:
                print(f"[dispatch] WARN submission failed for {run_id}: "
                      f"exit={result['exit_code']}", file=sys.stderr)
                print(result["stderr"], file=sys.stderr)

    manifest = {
        "campaign_name": args.campaign_name,
        "submitted_at_utc": _iso(submitted_at),
        "image_uri": args.image_uri,
        "bucket": args.bucket,
        "job_name": args.job_name,
        "region": args.region,
        "num": args.num,
        "b_count": args.b_count,
        "host_args": args.host_args,
        "strategies": args.strategies,
        "seeds": args.seeds,
        "dry_run": args.dry_run,
        "executions": executions,
    }
    Path(args.manifest_out).write_text(json.dumps(manifest, indent=2))
    print(f"[dispatch] manifest written: {args.manifest_out}")

    failures = [e for e in executions if e["exit_code"] != 0]
    if failures:
        print(f"[dispatch] {len(failures)}/{len(executions)} submissions failed",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
