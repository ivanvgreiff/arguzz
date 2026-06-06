#!/usr/bin/env python3
"""
a4/pos/dispatch_pos.py — POS management-node dispatcher.

Replaces the GCP `a4/cloud/dispatch.py`. Same logical contract:
enumerate the cartesian product of (strategy, seed) and submit one
campaign per pair, writing a dispatch manifest with command IDs and
node mapping.

REVISED Jun 5, 2026 to match the REAL POS API discovered from `pos-examples/`:
  * NO `--env KEY=VAL` (POS doesn't support it).
  * Per-job parameters are pushed via `pos.allocations.set_variables(<node>, <yml>)`;
    read on the node via `pos_get_variable <key>`.
  * The bundle tarball is shipped to each node via `pos.nodes.copy(<role>, <local-tarball>,
    '/root/', recursive=False)` then extracted on the node by a tiny pre-launch wrapper.
    This avoids needing the `/srv/testbed/files` central staging path entirely.
  * Uses the `poslib` Python API (not subprocessing the `pos` CLI) for cleaner error
    propagation and structured returns.

Workflow:

    1. Read a campaign manifest:
        {
          "name": "pos_ab_v1",
          "image": "debian-bullseye",
          "bundle": "/path/to/a4_campaign_<git>.tar.gz",
          "guest_args": ["--in1", "5", "--in4", "10"],
          "no_internet": false,            # if true, sets A4_NO_INTERNET=1 on each node
          "jobs": [
            {"strategy": "uniform", "seed": 42, "n": 1000, "b_count": 16},
            ...
          ]
        }

    2. Allocate the requested nodes (or attach to a pre-existing allocation if
       --allocation-id is given).

    3. Boot the chosen image on each allocated node, then reset.

    4. Copy the bundle tarball to each node (`pos.nodes.copy(node, bundle, '/root/')`)
       and run a setup snippet that extracts it to `/root/a4_campaign/`.

    5. For each job, write a per-node YAML with A4_STRATEGY, A4_SEED, etc.,
       push via `pos.allocations.set_variables(node, yaml_path)`, then
       `pos.commands.launch(node, infile='run_campaign_pos.sh', queued=True, name=...)`
       returning a command id.

    6. Write `dispatch_manifest.json` (node → cmd id → job spec mapping).

    7. If --await, block on each cmd id; else return immediately.

Usage:

    python -m a4.pos.dispatch_pos \\
        --manifest a4/pos/manifests/pos_ab_v1.json \\
        --nodes bitcoin bitcoincash bitcoingold \\
        --bundle /tmp/a4_campaign_abc1234.tar.gz \\
        --image debian-bullseye \\
        --out dispatch_manifest.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML — pre-installed on the management node
except ImportError:
    print("ERROR: PyYAML required. apt-get install python3-yaml on the management node.",
          file=sys.stderr)
    sys.exit(2)

# poslib is the testbed's Python API. We DEFER the import so `--dry-run` works
# off-testbed (validates manifest + assignment without needing POS).
pos = None  # set by _require_poslib() before any live operation


def _require_poslib() -> None:
    global pos
    if pos is not None:
        return
    try:
        import poslib as _pos  # noqa: WPS433
    except ImportError:
        print("ERROR: 'poslib' not importable on this host. "
              "This script MUST run on the POS management node "
              "(coinbase.net.in.tum.de) for non-dry-run operation.",
              file=sys.stderr)
        print("       Run `python3 -c 'import poslib'` to verify.",
              file=sys.stderr)
        sys.exit(3)
    pos = _pos


# --------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------- #
@dataclass
class JobSpec:
    strategy: str
    seed: int
    n: int
    b_count: int = 16

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "JobSpec":
        return cls(
            strategy=d["strategy"],
            seed=int(d["seed"]),
            n=int(d["n"]),
            b_count=int(d.get("b_count", 16)),
        )


@dataclass
class JobAssignment:
    job: JobSpec
    node: str
    command_id: str | None = None
    error: str | None = None
    run_id: str = ""


@dataclass
class DispatchResult:
    manifest_name: str
    bundle_path: str
    image: str
    no_internet: bool
    allocation: str | int | None
    assignments: list[JobAssignment] = field(default_factory=list)
    started_at: str = ""
    ended_at: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "bundle_path": self.bundle_path,
            "image": self.image,
            "no_internet": self.no_internet,
            "allocation": self.allocation,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "assignments": [
                {
                    **{k: v for k, v in asdict(a).items() if k != "job"},
                    "job": asdict(a.job),
                }
                for a in self.assignments
            ],
        }


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #
def _job_run_id(job: JobSpec, manifest_name: str) -> str:
    return f"{manifest_name}_{job.strategy}_seed{job.seed}_n{job.n}"


def _vars_yaml_for_job(job: JobSpec, manifest_name: str,
                       guest_args: list[str], no_internet: bool) -> dict[str, Any]:
    """The dict that will be YAML-dumped + pushed via pos.allocations.set_variables."""
    return {
        "A4_STRATEGY":      job.strategy,
        "A4_SEED":          str(job.seed),
        "A4_NUM":           str(job.n),
        "A4_CAMPAIGN_NAME": manifest_name,
        "A4_B_COUNT":       str(job.b_count),
        "A4_HOST_ARGS":     " ".join(guest_args),
        "A4_RUN_ID":        _job_run_id(job, manifest_name),
        "A4_NO_INTERNET":   "1" if no_internet else "0",
    }


def _extract_bundle_inline(bundle_basename: str) -> str:
    """Returns an inline bash one-liner to extract the bundle tarball.
    This is `pos.commands.launch`-ed before the per-job runner."""
    return (
        f"set -e && cd /root && "
        f"rm -rf a4_campaign && "
        f"tar -xzf {bundle_basename} && "
        f"ls -la a4_campaign/"
    )


def _await_id_silently(cid: str, timeout_s: int) -> tuple[int, str]:
    """Wait for one POS command id; return (exit_code, error_message).

    NOTE per official docs: `poslib.api.commands.await_id(command_id)` takes
    EXACTLY one argument (no timeout kwarg). Timeout enforcement is up to us.
    We do a coarse external deadline via signal.alarm to avoid hanging forever.
    """
    try:
        import signal

        def _alarm_handler(signum, frame):  # noqa: ARG001
            raise TimeoutError(f"await_id exceeded {timeout_s}s")

        # SIGALRM only works on the main thread on POSIX. For this dispatcher
        # context (single-threaded mgmt node) that is fine.
        old = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(timeout_s))
        try:
            rc = pos.commands.await_id(cid)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
        if rc is None:
            return 0, ""  # treat None return as success-ish; await contract is "blocks until done"
        return int(rc), ""
    except TimeoutError as e:
        return 254, str(e)
    except Exception as e:
        return 255, f"poslib exception: {e}"


# --------------------------------------------------------------------- #
# Main dispatch logic
# --------------------------------------------------------------------- #
def dispatch(args: argparse.Namespace) -> DispatchResult:
    manifest_path = Path(args.manifest).resolve()
    bundle_path = Path(args.bundle).resolve()
    if not manifest_path.is_file():
        raise SystemExit(f"manifest not found: {manifest_path}")
    if not bundle_path.is_file():
        raise SystemExit(f"bundle not found: {bundle_path}")

    spec = json.loads(manifest_path.read_text())
    name = spec["name"]
    image = args.image or spec.get("image", "debian-bullseye")
    guest_args = spec.get("guest_args", ["--in1", "5", "--in4", "10"])
    no_internet = bool(spec.get("no_internet", False))
    jobs = [JobSpec.from_dict(j) for j in spec["jobs"]]

    nodes = list(args.nodes)
    if len(nodes) < len(jobs):
        print(f"WARNING: {len(jobs)} jobs but only {len(nodes)} nodes; "
              f"jobs will queue (one per node, multiple batches).", file=sys.stderr)
    assignments = [JobAssignment(job=j, node=nodes[i % len(nodes)], run_id=_job_run_id(j, name))
                   for i, j in enumerate(jobs)]

    result = DispatchResult(
        manifest_name=name,
        bundle_path=str(bundle_path),
        image=image,
        no_internet=no_internet,
        allocation=None,
        assignments=assignments,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    if args.dry_run:
        print(f"[dispatch] DRY RUN. Would dispatch {len(jobs)} jobs onto {len(nodes)} nodes.")
        for a in assignments:
            vars_dict = _vars_yaml_for_job(a.job, name, guest_args, no_internet)
            print(f"  {a.node:20s} <- {a.run_id}")
            for k, v in vars_dict.items():
                print(f"      {k} = {v}")
        return result

    _require_poslib()

    # ----- 1. allocate ------------------------------------------------------
    if args.allocation_id:
        alloc = args.allocation_id
        print(f"[dispatch] reusing existing allocation: {alloc}")
    else:
        print(f"[dispatch] freeing nodes (idempotent): {' '.join(nodes)}")
        for n in nodes:
            try:
                pos.allocations.free(n, trim=False)
            except Exception:
                pass  # already free
        print(f"[dispatch] allocating: {' '.join(nodes)}")
        alloc_resp = pos.allocations.allocate(
            nodes,
            duration=None if args.allocation_duration <= 0 else args.allocation_duration,
            result_folder=f"a4/{name}",
        )
        # poslib usually returns (alloc_id, _, result_dir); fall back if shape differs
        try:
            alloc = alloc_resp[0]
        except (TypeError, IndexError):
            alloc = alloc_resp
        print(f"[dispatch] allocation = {alloc}")
    result.allocation = alloc

    # ----- 2. image + reset ------------------------------------------------
    print(f"[dispatch] setting image {image} on each node")
    for n in nodes:
        pos.nodes.image(n, image)
    print(f"[dispatch] resetting nodes (blocking — wait for boot)")
    pos.nodes.reset(nodes, blocking=True)

    # ----- 3. ship bundle to each node -------------------------------------
    bundle_basename = bundle_path.name
    print(f"[dispatch] copying bundle to {len(nodes)} nodes: {bundle_basename}")
    for n in nodes:
        pos.nodes.copy(n, str(bundle_path), "/root/", recursive=False)

    print(f"[dispatch] extracting bundle on each node (synchronous)")
    extract_cmd = _extract_bundle_inline(bundle_basename)
    extract_ids: list[str] = []
    for n in nodes:
        cid = pos.commands.launch(n, command=extract_cmd, blocking=False,
                                  queued=False, name="extract_bundle")
        # poslib returns either a cmd id directly or a dict with ['nodes'][node]
        cid_v = cid["nodes"][n] if isinstance(cid, dict) and "nodes" in cid else cid
        extract_ids.append(cid_v)
    for cid in extract_ids:
        rc, err = _await_id_silently(cid, timeout_s=300)
        if rc != 0:
            print(f"[dispatch] WARN: extract cmd {cid} rc={rc} ({err})", file=sys.stderr)

    # ----- 4. push per-job variables + launch -------------------------------
    runner_local = Path(__file__).parent / "run_campaign_pos.sh"
    if not runner_local.is_file():
        raise SystemExit(f"runner not found: {runner_local}")

    print(f"[dispatch] pushing per-job variables and launching {len(assignments)} jobs")
    for a in assignments:
        vars_dict = _vars_yaml_for_job(a.job, name, guest_args, no_internet)
        # Write to a temp file, push as per-node (non-global, non-loop)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            yaml.safe_dump(vars_dict, f)
            yml_path = f.name
        try:
            # Per official docs: set_variables(allocation, datafile, extension,
            # as_global, as_loop, print_variables). All but the first two have
            # safe defaults documented at the CLI level; pass them explicitly
            # as kwargs to match the API while not relying on positional order.
            pos.allocations.set_variables(
                a.node,
                yml_path,
                extension=None,
                as_global=False,
                as_loop=False,
                print_variables=False,
            )
            cmd_resp = pos.commands.launch(
                a.node,
                infile=str(runner_local),
                blocking=False,
                queued=True,
                name=a.run_id,
            )
            # Extract command id
            if isinstance(cmd_resp, dict) and "nodes" in cmd_resp:
                a.command_id = cmd_resp["nodes"][a.node]
            else:
                a.command_id = cmd_resp
            print(f"  + {a.node:20s} -> cmd {a.command_id} ({a.run_id})")
        except Exception as e:
            a.error = str(e)
            print(f"  ! {a.node:20s} FAILED: {e}", file=sys.stderr)
        finally:
            Path(yml_path).unlink(missing_ok=True)

    # ----- 5. optionally wait -----------------------------------------------
    if args.await_completion:
        print(f"[dispatch] awaiting {len(assignments)} commands (per-job timeout {args.await_timeout}s)")
        for a in assignments:
            if not a.command_id:
                continue
            rc, err = _await_id_silently(a.command_id, timeout_s=args.await_timeout)
            print(f"  = {a.node:20s} {a.command_id} rc={rc} {err}")
            if rc != 0 and not a.error:
                a.error = err or f"rc={rc}"

    result.ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return result


# --------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------- #
def _main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else "")
    p.add_argument("--manifest", required=True, help="path to campaign manifest JSON")
    p.add_argument("--bundle", required=True, help="path to bundle tarball (local on mgmt node)")
    p.add_argument("--nodes", nargs="+", required=True, help="POS nodes to dispatch onto")
    p.add_argument("--image", default=None, help="image (overrides manifest; default debian-bullseye)")
    p.add_argument("--out", default="dispatch_manifest.json", help="output JSON path")
    p.add_argument("--allocation-id", default=None,
                   help="reuse this allocation id (skip allocate/free)")
    p.add_argument("--allocation-duration", type=int, default=-1,
                   help="allocation duration in minutes (-1 = poslib default)")
    p.add_argument("--await", dest="await_completion", action="store_true",
                   help="block on each command id and report exit codes")
    p.add_argument("--await-timeout", type=int, default=60 * 60 * 24,
                   help="per-job await timeout in seconds (default 24h)")
    p.add_argument("--dry-run", action="store_true",
                   help="parse, plan, print; do NOT touch POS or nodes")
    args = p.parse_args()

    res = dispatch(args)

    out_path = Path(args.out).resolve()
    out_path.write_text(json.dumps(res.to_json(), indent=2))
    print(f"\n[dispatch] wrote {out_path} with {len(res.assignments)} assignments.")

    # exit non-zero if any assignment had an error
    if any(a.error for a in res.assignments):
        print(f"[dispatch] {sum(1 for a in res.assignments if a.error)} jobs had errors.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
