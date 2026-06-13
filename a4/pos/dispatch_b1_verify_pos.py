#!/usr/bin/env python3
"""Dispatch B1 strict verifier shards to POS (one variant per node)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, List

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required on coinbase", file=sys.stderr)
    sys.exit(2)

# Reuse dispatch_pos helpers (pos module set by _require_poslib at runtime)
import a4.pos.dispatch_pos as dp


@dataclass
class VerifyJob:
    variant: str
    db: str
    node: str = ""
    command_id: str | None = None
    error: str | None = None


def _check_node_result_file(node: str, variant: str, campaign_name: str) -> bool:
    """SSH to a POS node and verify the B1 verifier result JSON exists & is valid.

    Used as a resilience fallback when `pos.commands.await_id` raises a transient
    HTTP error (coordinator hiccup) but the underlying verifier job may still have
    completed on the node. We `ssh root@<node>` and look for
    `/root/b1_verify_results/<campaign>_<variant>/B1_<variant>.json` containing
    `per_variant.<variant>.total > 0`. Returns True iff result file is present
    and well-formed.

    Requires SSH access from the dispatcher host (coinbase) to the POS nodes —
    in practice this is set up via the standard testbed SSH config since the
    dispatcher already uses `pos.nodes.copy` which uses the same channel.
    """
    import subprocess
    remote_path = f"/root/b1_verify_results/{campaign_name}_{variant}/B1_{variant}.json"
    try:
        proc = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
             "-o", "LogLevel=ERROR", f"root@{node}",
             f"cat {remote_path} 2>/dev/null | python3 -c "
             f"\"import sys,json; d=json.load(sys.stdin); "
             f"pv=d['per_variant']['{variant}']; "
             f"print('OK' if pv.get('total',0)>0 else 'EMPTY')\""],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode == 0 and "OK" in proc.stdout
    except Exception as e:
        print(f"  ~ {node} node-side check failed: {e}", file=sys.stderr)
        return False


def _vars_yaml(job: VerifyJob, manifest_name: str, guest_args: list[str], expected_n: str = "") -> dict[str, str]:
    out = {
        "A4_VARIANT": job.variant,
        "A4_CAMPAIGN_NAME": manifest_name,
        "A4_HOST_ARGS": " ".join(guest_args),
        "A4_RUN_ID": f"{manifest_name}_{job.variant}",
    }
    if expected_n:
        out["A4_EXPECTED_N"] = expected_n
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Dispatch B1 verifier shards to POS")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--nodes", nargs="+", required=True)
    parser.add_argument("--image", default="debian-trixie")
    parser.add_argument("--allocation-duration", type=int, default=180)
    parser.add_argument("--allocation-id", default=None,
                        help="Reuse existing allocation (skip allocate)")
    parser.add_argument("--await", dest="await_completion", action="store_true")
    parser.add_argument("--await-timeout", type=int, default=7200)
    parser.add_argument("--out", default="dispatch_b1_verify_manifest.json")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())
    name = manifest.get("name", manifest_path.stem)
    image = manifest.get("image", args.image)
    guest_args = manifest.get("guest_args", ["--in1", "5", "--in4", "10"])
    expected_n = str(manifest.get("expected_n", ""))
    results_dir = Path(manifest["results_dir"])
    jobs_raw = manifest["jobs"]

    bundle_path = Path(args.bundle).resolve()
    if not bundle_path.is_file():
        print(f"ERROR: bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    nodes = list(args.nodes)
    if len(nodes) < len(jobs_raw):
        print(f"ERROR: need {len(jobs_raw)} nodes, got {len(nodes)}", file=sys.stderr)
        return 2

    assignments: List[VerifyJob] = []
    for i, j in enumerate(jobs_raw):
        assignments.append(VerifyJob(variant=j["variant"], db=j["db"], node=nodes[i]))

    for job in assignments:
        db_path = results_dir / job.db
        if not db_path.is_file():
            print(f"ERROR: DB missing: {db_path}", file=sys.stderr)
            return 2

    dp._require_poslib()
    pos = dp.pos

    if args.allocation_id:
        alloc = args.allocation_id
        print(f"[b1_verify] reusing allocation {alloc}")
    else:
        dp._delete_stale_calendar_entries(nodes)
        print(f"[b1_verify] allocating {len(nodes)} nodes for {args.allocation_duration}m")
        alloc_resp = pos.allocations.allocate(
            nodes,
            duration=args.allocation_duration,
            result_folder=f"a4/{name}",
        )
        try:
            alloc = alloc_resp[0]
        except (TypeError, IndexError):
            alloc = alloc_resp
        print(f"[b1_verify] allocation = {alloc}")

    try:
        # set variables BEFORE reset
        per_job_yml: dict[str, str] = {}
        for job in assignments:
            vars_dict = _vars_yaml(job, name, guest_args, expected_n)
            with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
                yaml.safe_dump(vars_dict, f)
                yml_path = f.name
            per_job_yml[job.node] = yml_path
            dp._set_variables_cli(job.node, yml_path)
            print(f"  + {job.node:20s} vars for {job.variant}")

        for n in nodes:
            pos.nodes.image(n, image)
        for n in nodes:
            pos.nodes.reset(n, blocking=True)

        bundle_basename = bundle_path.name
        print(f"[b1_verify] copying bundle {bundle_basename}")
        for n in nodes:
            pos.nodes.copy(n, str(bundle_path), "/root/", recursive=False)

        extract_script_path = dp._make_extract_bundle_script(bundle_basename)
        try:
            for n in nodes:
                with open(extract_script_path, "r") as fh:
                    cid_resp = pos.commands.launch(
                        n, infile=fh, blocking=False, queued=True, name="extract_bundle",
                    )
                cid = dp._extract_cmd_id(cid_resp, n)
                if cid:
                    rc, err = dp._await_id_silently(cid, timeout_s=300)
                    if rc != 0:
                        print(f"WARN extract {n} rc={rc} {err}", file=sys.stderr)
        finally:
            Path(extract_script_path).unlink(missing_ok=True)

        # Patch updated B1 script onto each node (bundle may be stale)
        script_dir = Path(__file__).resolve().parent
        patch_files = [
            (script_dir.parent / "audits" / "B1_hook_fidelity.py",
             "/root/a4_campaign/repo/a4/audits/B1_hook_fidelity.py"),
            (script_dir.parent / "tools" / "verify_mutation_semantics.py",
             "/root/a4_campaign/repo/a4/tools/verify_mutation_semantics.py"),
        ]
        for local_path, remote_path in patch_files:
            if local_path.is_file():
                print(f"[b1_verify] patching {local_path.name} on nodes")
                for n in nodes:
                    pos.nodes.copy(n, str(local_path), remote_path, recursive=False)

        # Copy each variant DB to /root/b1_verify/ on its node
        print("[b1_verify] copying variant DBs")
        for job in assignments:
            db_path = results_dir / job.db
            pos.nodes.copy(job.node, str(db_path), "/root/", recursive=False)
            print(f"  + {job.node:20s} <- {job.db}")

        runner = script_dir / "run_verify_b1_pos.sh"
        if not runner.is_file():
            raise SystemExit(f"runner missing: {runner}")

        print(f"[b1_verify] launching {len(assignments)} verifier shards")
        for job in assignments:
            try:
                with open(str(runner), "r") as fh:
                    cmd_resp = pos.commands.launch(
                        job.node,
                        infile=fh,
                        blocking=False,
                        queued=True,
                        name=f"b1_verify_{job.variant}",
                    )
                job.command_id = dp._extract_cmd_id(cmd_resp, job.node)
                print(f"  + {job.node:20s} {job.variant} -> cmd {job.command_id}")
            except Exception as e:
                job.error = str(e)
                print(f"  ! {job.node} FAILED: {e}", file=sys.stderr)

        for _n, yml in per_job_yml.items():
            Path(yml).unlink(missing_ok=True)

        if args.await_completion:
            print(f"[b1_verify] awaiting (timeout {args.await_timeout}s per job)")
            for job in assignments:
                if not job.command_id:
                    continue
                rc, err = dp._await_id_silently(job.command_id, timeout_s=args.await_timeout)
                print(f"  = {job.node:20s} {job.variant} rc={rc} {err}")
                if rc != 0 and not job.error:
                    # RESILIENCE (added 2026-06-13): if the await failed due to
                    # a coordinator-side HTTP hiccup (rc=255 from _await_id_silently
                    # after retries), the COMMAND ON THE NODE may still have completed
                    # successfully. Verify by checking the node-side result file
                    # before declaring the job failed.
                    if rc == 255:
                        node_ok = _check_node_result_file(job.node, job.variant, name)
                        if node_ok:
                            print(f"  ~ {job.node:20s} {job.variant} await failed BUT "
                                  f"node-side result file present and valid -> treating as SUCCESS",
                                  flush=True)
                            continue
                    job.error = err or f"rc={rc}"

    except BaseException:
        print(f"\n[b1_verify] ERROR — free allocation manually: pos allocations free {alloc}\n",
              file=sys.stderr)
        raise

    out_doc = {
        "manifest": name,
        "bundle": str(bundle_path),
        "allocation": alloc,
        "results_dir": str(results_dir),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "assignments": [asdict(j) for j in assignments],
    }
    Path(args.out).write_text(json.dumps(out_doc, indent=2))
    print(f"[b1_verify] wrote {args.out}")

    failed = [j for j in assignments if j.error]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
