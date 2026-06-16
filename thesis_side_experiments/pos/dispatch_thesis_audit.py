#!/usr/bin/env python3
"""Dispatch E5 acceptance audit to POS (meld/idex/tinyman, full list per node)."""

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
    raise SystemExit("Cannot find arguzz repo")


REPO = _find_repo()
sys.path.insert(0, str(REPO))

from a4.pos.dispatch_pos import (  # noqa: E402
    _await_id_silently,
    _extract_cmd_id,
    _make_extract_bundle_script,
    _require_poslib,
)
import a4.pos.dispatch_pos as dp  # noqa: E402

EXPECTED_HOST_SHA = "84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45"
AUDIT_NODES = frozenset({"meld", "idex", "tinyman"})


def _setup_node(node: str, bundle_path: Path, image: str) -> str:
    pos = dp.pos
    bundle_basename = bundle_path.name
    pos.nodes.image(node, image)
    pos.nodes.reset(node, blocking=True)
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
                raise SystemExit(f"extract failed on {node} rc={rc} {err}")
    finally:
        Path(extract_path).unlink(missing_ok=True)

    runner = (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "export WORK=/root/a4_campaign\n"
        "export THESIS_MANIFEST=$WORK/thesis/audit_run_list.json\n"
        "export THESIS_RESULTS=$WORK/thesis/e5_audit_results\n"
        f"export THESIS_HOST_SHA={EXPECTED_HOST_SHA}\n"
        "exec bash $WORK/thesis/thesis_audit_run.sh\n"
    )
    runner_path = Path(f"/tmp/thesis_audit_runner_{node}.sh")
    runner_path.write_text(runner)
    runner_path.chmod(0o755)

    with open(runner_path, "r") as fh:
        cmd_resp = pos.commands.launch(
            node,
            infile=fh,
            blocking=False,
            queued=True,
            name="thesis_audit",
        )
    cmd_id = _extract_cmd_id(cmd_resp, node)
    runner_path.unlink(missing_ok=True)
    return cmd_id or ""


def dispatch_audit(args: argparse.Namespace) -> dict:
    bundle_path = Path(args.bundle).expanduser().resolve()
    if not bundle_path.is_file():
        raise SystemExit(f"bundle not found: {bundle_path}")

    nodes = list(args.nodes)
    for n in nodes:
        if n not in AUDIT_NODES:
            raise SystemExit(f"audit allows only meld/idex/tinyman, got {n}")

    _require_poslib()
    pos = dp.pos
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    we_own = False
    alloc = args.allocation_id

    if alloc:
        print(f"[audit] reusing allocation {alloc}")
    else:
        will_create = args.allocation_duration > 0
        print(f"[audit] freeing nodes (trim={will_create}): {' '.join(nodes)}")
        for n in nodes:
            try:
                pos.allocations.free(n, trim=will_create)
            except Exception:
                pass
        if will_create:
            dp._delete_stale_calendar_entries(nodes)

        dur = None if args.allocation_duration <= 0 else args.allocation_duration
        print(f"[audit] allocating: {' '.join(nodes)} (duration={dur!r})")
        alloc_resp = pos.allocations.allocate(
            nodes,
            duration=dur,
            result_folder="a4/thesis_e5_audit",
        )
        try:
            alloc = alloc_resp[0]
        except (TypeError, IndexError):
            alloc = alloc_resp
        we_own = True
        print(f"[audit] allocation = {alloc}")

    image = args.image or "debian-trixie"
    cmd_ids = {}
    try:
        for node in nodes:
            print(f"[audit] setup {node}")
            cmd_ids[node] = _setup_node(node, bundle_path, image)
            print(f"[audit] {node} command_id = {cmd_ids[node]}")

        if args.await_completion:
            for node, cid in cmd_ids.items():
                if not cid:
                    continue
                print(f"[audit] awaiting {node} …")
                exit_rc, err = _await_id_silently(cid, timeout_s=args.await_timeout)
                print(f"[audit] {node} await rc={exit_rc} ({err})")
                if exit_rc != 0:
                    raise SystemExit(exit_rc)

        manifest = {
            "nodes": nodes,
            "allocation": str(alloc),
            "bundle": str(bundle_path),
            "image": image,
            "command_ids": cmd_ids,
            "host_sha256": EXPECTED_HOST_SHA,
            "started_at": started,
            "ended_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        out = Path(args.out)
        out.write_text(json.dumps(manifest, indent=2))
        print(f"[audit] wrote {out}")
        return manifest
    finally:
        if we_own and args.free_on_exit:
            try:
                pos.allocations.free(alloc)
            except Exception as exc:
                print(f"[audit] WARN free failed: {exc}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Thesis E5 audit POS dispatcher")
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--nodes", nargs="+", default=["meld", "idex", "tinyman"])
    ap.add_argument("--image", default="debian-trixie")
    ap.add_argument("--allocation-duration", type=int, default=0)
    ap.add_argument("--allocation-id", default=None)
    ap.add_argument("--await", dest="await_completion", action="store_true")
    ap.add_argument("--await-timeout", type=int, default=3600)
    ap.add_argument("--free-on-exit", action="store_true", default=False)
    ap.add_argument("--no-free-on-exit", action="store_false", dest="free_on_exit")
    ap.add_argument("--out", default="thesis_audit_dispatch.json")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.dry_run:
        print(f"[audit] dry-run ok: bundle={args.bundle} nodes={args.nodes}")
        return
    dispatch_audit(args)


if __name__ == "__main__":
    main()
