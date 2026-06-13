#!/usr/bin/env python3
"""Dispatch thesis E2 smoke to POS — follows a4/pos/dispatch_pos.py + POS_PLAYBOOK.md.

On coinbase (management node):
  source /srv/testbed/pos/cli/venv3/bin/activate
  cd ~/arguzz && git pull   # or scp this file into thesis_side_experiments/pos/
  python thesis_side_experiments/pos/dispatch_thesis_pos.py \\
    --bundle ~/thesis_minimal_add_thesis_d5eddb8309cf.tar.gz \\
    --nodes polynize \\
    --allocation-duration 0 \\
    --image debian-trixie \\
    --await
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _find_repo() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here.parents[2], Path.cwd(), Path.home() / "arguzz"):
        if (candidate / "a4" / "pos" / "dispatch_pos.py").is_file():
            return candidate
    raise SystemExit(
        "Cannot find arguzz repo (need a4/pos/dispatch_pos.py).\n"
        "Run from ~/arguzz:\n"
        "  cd ~/arguzz\n"
        "  python thesis_side_experiments/pos/dispatch_thesis_pos.py ..."
    )


REPO = _find_repo()
sys.path.insert(0, str(REPO))

from a4.pos.dispatch_pos import (  # noqa: E402
    _await_id_silently,
    _extract_cmd_id,
    _make_extract_bundle_script,
    _require_poslib,
)
import a4.pos.dispatch_pos as dp  # noqa: E402


def dispatch_thesis(args: argparse.Namespace) -> dict:
    bundle_path = Path(args.bundle).expanduser().resolve()
    if not bundle_path.is_file():
        raise SystemExit(f"bundle not found: {bundle_path}")

    nodes = list(args.nodes)
    if len(nodes) != 1:
        raise SystemExit("thesis smoke expects exactly one node (1 runner, manifest in bundle)")

    node = nodes[0]
    image = args.image or "debian-trixie"
    _require_poslib()
    pos = dp.pos

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    we_own = False
    alloc = args.allocation_id

    if alloc:
        print(f"[thesis] reusing allocation {alloc}")
    else:
        will_create = args.allocation_duration > 0
        print(f"[thesis] freeing nodes (idempotent, trim={will_create}): {' '.join(nodes)}")
        for n in nodes:
            try:
                pos.allocations.free(n, trim=will_create)
            except Exception:
                pass
        if will_create:
            dp._delete_stale_calendar_entries(nodes)

        dur = None if args.allocation_duration <= 0 else args.allocation_duration
        print(f"[thesis] allocating: {' '.join(nodes)} (duration={dur!r})")
        try:
            alloc_resp = pos.allocations.allocate(
                nodes,
                duration=dur,
                result_folder="a4/thesis_e2_smoke",
            )
        except Exception as exc:
            msg = str(exc)
            if "Maximum number of future entries" in msg:
                print(
                    f"\n[thesis] ALLOCATE FAILED: {exc}\n"
                    "[thesis] POS per-user quota is 2 calendar entries (§12.28).\n"
                    "[thesis] pos allocations list | grep $(whoami)\n",
                    file=sys.stderr,
                )
            elif "no calendar event" in msg.lower():
                print(
                    f"\n[thesis] ALLOCATE FAILED: {exc}\n"
                    "[thesis] --allocation-duration 0 requires a pre-reserved calendar entry\n"
                    "[thesis] for this node (§12.37). Reserve via web UI first.\n",
                    file=sys.stderr,
                )
            elif "Cannot update event in the past" in msg:
                print(
                    f"\n[thesis] ALLOCATE FAILED: {exc}\n"
                    "[thesis] Stale calendar entry — pos calendar list -j (§12.32).\n",
                    file=sys.stderr,
                )
            elif "already allocated" in msg.lower():
                print(
                    f"\n[thesis] ALLOCATE FAILED: {exc}\n"
                    "[thesis] Node still held. Wait until reservation start_date (§12.38).\n"
                    "[thesis] If past start_date and still held, STOP (§12.39).\n",
                    file=sys.stderr,
                )
            else:
                print(f"[thesis] ALLOCATE FAILED: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        try:
            alloc = alloc_resp[0]
        except (TypeError, IndexError):
            alloc = alloc_resp
        we_own = True
        print(f"[thesis] allocation = {alloc}")

    try:
        print(f"[thesis] image {node} -> {image}")
        pos.nodes.image(node, image)
        print(f"[thesis] reset {node} (blocking)")
        pos.nodes.reset(node, blocking=True)

        bundle_basename = bundle_path.name
        print(f"[thesis] copy bundle -> {node}: {bundle_basename}")
        pos.nodes.copy(node, str(bundle_path), "/root/", recursive=False)

        extract_path = _make_extract_bundle_script(bundle_basename)
        try:
            with open(extract_path, "r") as fh:
                cid_resp = pos.commands.launch(
                    node, infile=fh, blocking=False, queued=True, name="extract_bundle"
                )
            cid = _extract_cmd_id(cid_resp, node)
            if cid:
                rc, err = _await_id_silently(cid, timeout_s=300)
                if rc != 0:
                    raise SystemExit(f"extract failed rc={rc} {err}")
        finally:
            Path(extract_path).unlink(missing_ok=True)

        runner = (
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "export WORK=/root/a4_campaign\n"
            f"export THESIS_MANIFEST=$WORK/thesis/{args.manifest}\n"
            "export THESIS_RESULTS=$WORK/thesis/results\n"
            "exec bash $WORK/thesis/thesis_run_pos.sh\n"
        )
        runner_path = Path("/tmp/thesis_runner_launch.sh")
        runner_path.write_text(runner)
        runner_path.chmod(0o755)

        print(f"[thesis] launch thesis_run_pos.sh on {node}")
        with open(runner_path, "r") as fh:
            cmd_resp = pos.commands.launch(
                node,
                infile=fh,
                blocking=False,
                queued=True,
                name="thesis_e2_smoke",
            )
        cmd_id = _extract_cmd_id(cmd_resp, node)
        print(f"[thesis] command_id = {cmd_id}")

        if args.await_completion and cmd_id:
            exit_rc, err = _await_id_silently(cmd_id, timeout_s=args.await_timeout)
            print(f"[thesis] await rc={exit_rc} ({err})")
            if exit_rc != 0:
                raise SystemExit(exit_rc)

        manifest = {
            "node": node,
            "allocation": str(alloc),
            "bundle": str(bundle_path),
            "image": image,
            "command_id": cmd_id,
            "started_at": started,
            "ended_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        out = Path(args.out)
        out.write_text(json.dumps(manifest, indent=2))
        print(f"[thesis] wrote {out}")
        return manifest
    finally:
        if we_own and args.free_on_exit:
            print(f"[thesis] freeing {alloc}")
            try:
                pos.allocations.free(alloc)
            except Exception as exc:
                print(f"[thesis] WARN free failed: {exc}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Thesis E2 POS smoke dispatcher")
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--nodes", nargs="+", default=["polynize"])
    ap.add_argument("--image", default="debian-trixie")
    ap.add_argument("--allocation-duration", type=int, default=0)
    ap.add_argument("--allocation-id", default=None)
    ap.add_argument(
        "--await",
        dest="await_completion",
        action="store_true",
        help="block until thesis_run_pos.sh finishes",
    )
    ap.add_argument("--await-timeout", type=int, default=3600)
    ap.add_argument("--free-on-exit", action="store_true", default=True)
    ap.add_argument("--no-free-on-exit", action="store_false", dest="free_on_exit")
    ap.add_argument("--out", default="thesis_dispatch_manifest.json")
    ap.add_argument(
        "--manifest",
        default="manifest_e2.json",
        help="manifest filename under thesis/ in bundle",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dry_run:
        print(f"[thesis] dry-run ok: bundle={args.bundle} nodes={args.nodes}")
        return
    dispatch_thesis(args)


if __name__ == "__main__":
    main()
