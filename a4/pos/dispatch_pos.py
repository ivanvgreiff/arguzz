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
import os
import subprocess
import sys
import time
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, List

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
    telemetry_level: str | None = None
    run_suffix: str | None = None
    debug_bandit_trace: bool = False
    coverage_touch_verbose: bool = False
    ftw291_trace: bool = False
    mem_fingerprint: bool = False
    preflight_fingerprint: bool = False
    preflight_fingerprint_wide: bool = False
    rayon_threads: int | None = None
    risc0_threads: int | None = None
    omp_threads: int | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "JobSpec":
        return cls(
            strategy=d["strategy"],
            seed=int(d["seed"]),
            n=int(d["n"]),
            b_count=int(d.get("b_count", 16)),
            telemetry_level=d.get("telemetry_level"),
            run_suffix=d.get("run_suffix"),
            debug_bandit_trace=bool(d.get("debug_bandit_trace", False)),
            coverage_touch_verbose=bool(d.get("coverage_touch_verbose", False)),
            ftw291_trace=bool(d.get("ftw291_trace", False)),
            mem_fingerprint=bool(d.get("mem_fingerprint", False)),
            preflight_fingerprint=bool(d.get("preflight_fingerprint", False)),
            preflight_fingerprint_wide=bool(d.get("preflight_fingerprint_wide", False)),
            rayon_threads=d.get("rayon_threads"),
            risc0_threads=d.get("risc0_threads"),
            omp_threads=d.get("omp_threads"),
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
    base = f"{manifest_name}_{job.strategy}_seed{job.seed}_n{job.n}"
    if job.run_suffix:
        return f"{base}_{job.run_suffix}"
    return base


def _vars_yaml_for_job(job: JobSpec, manifest_name: str,
                       guest_args: list[str], no_internet: bool) -> dict[str, Any]:
    """The dict that will be YAML-dumped + pushed via pos.allocations.set_variables."""
    out = {
        "A4_STRATEGY":      job.strategy,
        "A4_SEED":          str(job.seed),
        "A4_NUM":           str(job.n),
        "A4_CAMPAIGN_NAME": manifest_name,
        "A4_B_COUNT":       str(job.b_count),
        "A4_HOST_ARGS":     " ".join(guest_args),
        "A4_RUN_ID":        _job_run_id(job, manifest_name),
        "A4_NO_INTERNET":   "1" if no_internet else "0",
    }
    if job.telemetry_level:
        out["A4_TELEMETRY_LEVEL"] = job.telemetry_level
    if job.run_suffix:
        out["A4_RUN_SUFFIX"] = job.run_suffix
    if job.debug_bandit_trace:
        out["A4_DEBUG_BANDIT_TRACE"] = "1"
    if job.coverage_touch_verbose:
        out["A4_COVERAGE_TOUCH_VERBOSE"] = "1"
    if job.ftw291_trace:
        out["A4_FTW291_TRACE"] = "1"
    if job.mem_fingerprint:
        out["A4_MEM_FINGERPRINT"] = "1"
    if job.preflight_fingerprint:
        out["A4_PREFLIGHT_FINGERPRINT"] = "1"
    if job.preflight_fingerprint_wide:
        out["A4_PREFLIGHT_FINGERPRINT_WIDE"] = "1"
    if job.rayon_threads is not None:
        out["A4_RAYON_THREADS"] = str(job.rayon_threads)
    if job.risc0_threads is not None:
        out["A4_RISC0_THREADS"] = str(job.risc0_threads)
    if job.omp_threads is not None:
        out["A4_OMP_THREADS"] = str(job.omp_threads)
    return out


def _make_extract_bundle_script(bundle_basename: str) -> str:
    """Writes a temp bash script that extracts the bundle tarball on the test node
    and returns its path. We ship this via `--infile` rather than inline `command=`
    because the latter trips the server's "commandlist" type check:
        `"command" list is required for type "commandlist"`
    even when `queued=True`. The `--infile` path is known to work (it's how the
    main runner is launched). Verified Jun 6 06:35 after two failed attempts with
    inline `command=`.
    """
    content = (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "cd /root\n"
        f"rm -rf a4_campaign\n"
        f"tar -xzf {bundle_basename}\n"
        f"ls -la a4_campaign/\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     prefix="a4_extract_") as f:
        f.write(content)
        path = f.name
    # NOTE: poslib uploads the file to /tmp/<cmd-id> on the test node and execs
    # it directly; chmod here is for sanity but not strictly required.
    os.chmod(path, 0o755)
    return path


def _extract_cmd_id(resp: Any, node: str) -> str:
    """Normalise the return of `pos.commands.launch(...)` into a single cmd id string.

    poslib's `commands.launch` returns a TUPLE `(is_role, data)` (verified Jun 6
    by inspecting pos-examples `synthesize_programs:207`: `_, ids = pos.commands.launch(...)`).
    `data` is typically `{'nodes': {<n>: <cmd_id>, ...}}`. We also tolerate the
    dict form (legacy/other variants) and a bare string (unlikely but cheap).

    IMPORTANT: skip booleans — `is_role` is `True/False` and would otherwise be
    stringified as `"True"` / `"False"` and treated as a cmd id, leading to the
    failure mode `await "False"` -> `Resource False not found` (Jun 6 07:02).
    """
    if isinstance(resp, bool) or resp is None:
        return ""
    if isinstance(resp, tuple):
        # Prefer the element that actually carries the id info (dict / nested tuple).
        for part in resp:
            if isinstance(part, bool) or part is None:
                continue
            try:
                cid = _extract_cmd_id(part, node)
                if cid:
                    return cid
            except Exception:
                continue
        return ""  # nothing usable; caller will log a warning
    if isinstance(resp, dict):
        if "nodes" in resp and isinstance(resp["nodes"], dict):
            if node in resp["nodes"]:
                return str(resp["nodes"][node])
            vals = list(resp["nodes"].values())
            if len(vals) == 1:
                return str(vals[0])
        # raw id sometimes sits under 'id' / 'cmd_id'
        for k in ("id", "cmd_id", "command_id"):
            if k in resp:
                return str(resp[k])
        return ""
    return str(resp)


def _normalise_exit_code(rc: Any) -> int:
    """Coerce whatever `await_id` returns into an int exit code.

    poslib's `await_id` return shape varies (observed Jun 6 07:14):
      - None  -> treat as success (await contract is "blocks until done")
      - int / numeric str -> use directly
      - dict like {'nodes': {<n>: <rc>}}, {'exit_status': <rc>}, {'rc': <rc>}
      - tuple/list -> first usable element
    Returns 0 if we cannot extract a numeric exit code (don't fail the dispatch
    just because we can't introspect a status; the cmd id is still recorded).
    """
    if rc is None:
        return 0
    if isinstance(rc, bool):
        return 0 if rc else 1
    if isinstance(rc, int):
        return rc
    if isinstance(rc, str):
        try:
            return int(rc.strip())
        except ValueError:
            return 0
    if isinstance(rc, dict):
        for k in ("exit_status", "exit_code", "rc", "returncode"):
            if k in rc:
                return _normalise_exit_code(rc[k])
        if "nodes" in rc and isinstance(rc["nodes"], dict):
            vals = list(rc["nodes"].values())
            if vals:
                return _normalise_exit_code(vals[0])
        return 0
    if isinstance(rc, (list, tuple)):
        for part in rc:
            if part is None:
                continue
            try:
                return _normalise_exit_code(part)
            except Exception:  # noqa: BLE001
                continue
        return 0
    return 0


def _delete_stale_calendar_entries(nodes: List[str]) -> None:
    """Remove any calendar entries for our nodes owned by the current user.

    Why: per anti-pattern §12.32, `free(node, trim=True)` only clips end_date
    on the calendar entry — it does NOT delete it. If start_date is already
    in the past (e.g. an allocation we created an hour ago), the next
    `allocate(...)` call tries to UPDATE that stale entry and fails with
    `Cannot update event in the past`. The clean fix is to explicitly
    delete those entries via `pos calendar delete --id <id> <node>`.

    We shell out to the CLI because the poslib Python API for
    `calendar.delete(nodes, _id=...)` exists but mirroring it via CLI is
    one less surface to debug.
    """
    target = set(nodes)
    user = os.environ.get("USER", "")
    try:
        cal_json = subprocess.run(
            ["pos", "calendar", "list", "-j"],
            capture_output=True, text=True, check=False,
        ).stdout
        entries = json.loads(cal_json) if cal_json.strip() else []
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[dispatch] WARN: could not list calendar ({e}); skipping cleanup",
              file=sys.stderr)
        return

    # entries shape: [{"id": <int>, "nodes": [<n>...], "owner": <str>,
    #                  "start_date": "...", "end_date": "..."}, ...]
    deleted = 0
    for e in entries if isinstance(entries, list) else []:
        ent_nodes = e.get("nodes") or []
        ent_owner = e.get("owner", "")
        ent_id = e.get("id")
        # Only touch entries OWNED BY US for our target nodes (safety)
        if (user and ent_owner != user) or ent_id is None:
            continue
        match = [n for n in ent_nodes if n in target]
        if not match:
            continue
        for n in match:
            try:
                subprocess.run(
                    ["pos", "calendar", "delete", "--id", str(ent_id), n],
                    capture_output=True, text=True, check=False,
                )
                deleted += 1
                print(f"  [calendar] deleted entry id={ent_id} for {n}")
            except Exception as exc:
                print(f"  [calendar] WARN could not delete id={ent_id} on {n}: {exc}",
                      file=sys.stderr)
    if deleted == 0:
        print(f"  [calendar] no stale entries found for {sorted(target)}")


def _set_variables_cli(node: str, yml_path: str) -> None:
    """Push variables for a node by SHELLING OUT to `pos allocations set_variables`.

    Why subprocess instead of `pos.allocations.set_variables(...)`:
      - Verified Jun 6 07:14: the Python API call returned without raising,
        but the variables did not show up on the test node
        (`pos_get_variable A4_STRATEGY` returned `variable A4_STRATEGY unknown`).
      - pos-examples ONLY uses the CLI form for this operation:
        `pos allocations set_variables $NODE1 ./node1.yml`
        (see pos-examples/tutorials/simple/experiment.sh:24).
      - The CLI is the proven canonical path.
    """
    cmd = ["pos", "allocations", "set_variables", node, yml_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`pos allocations set_variables {node} {yml_path}` failed "
            f"(rc={proc.returncode}). stderr:\n{proc.stderr.strip()}"
        )
    # Stdout/err often contain useful confirmation lines; log them at info level.
    if proc.stdout.strip():
        print(f"  [set_variables] {proc.stdout.strip()}")


def _await_id_silently(cid: str, timeout_s: int, max_retries: int = 3) -> tuple[int, str]:
    """Wait for one POS command id; return (exit_code, error_message).

    NOTE per official docs: `poslib.api.commands.await_id(command_id)` takes
    EXACTLY one argument (no timeout kwarg). Timeout enforcement is up to us.
    We do a coarse external deadline via signal.alarm to avoid hanging forever.
    Return shapes from poslib vary (see _normalise_exit_code).

    Resilience (added 2026-06-13 after Inc 4 B1 verify incident):
    poslib's `await_id` performs an HTTP GET against the POS coordinator
    (`http://172.16.128.1:5000/commands/await/<cid>`). Under coordinator load
    or transient network blips this GET can fail with a `requests.ConnectionError`
    or `requests.Timeout`, even though the underlying command is still
    running on the node and will finish normally. We RETRY transient HTTP
    failures up to `max_retries` times with exponential backoff before
    giving up. Hard non-network errors (ValueError, etc.) bubble out
    immediately.
    """
    import signal
    last_err = ""
    for attempt in range(max_retries):
        try:
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
            return _normalise_exit_code(rc), ""
        except TimeoutError as e:
            return 254, str(e)
        except Exception as e:
            last_err = f"poslib exception: {e}"
            msg = str(e).lower()
            transient = (
                "unable to get url" in msg
                or "connection" in msg
                or "timeout" in msg
                or "remote disconnect" in msg
                or "broken pipe" in msg
            )
            if not transient or attempt == max_retries - 1:
                return 255, last_err
            backoff_s = 5 * (2 ** attempt)  # 5s, 10s, 20s
            print(f"[await {cid[:30]}] transient HTTP error (attempt {attempt+1}/{max_retries}); "
                  f"retrying in {backoff_s}s: {e}", file=sys.stderr)
            time.sleep(backoff_s)
    return 255, last_err


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
    # NB: debian-trixie has GLIBC 2.39+; bookworm has 2.36 which is TOO OLD for
    # risc0-host built against Ubuntu 24.04's GLIBC 2.39. Anti-pattern §12.30.
    image = args.image or spec.get("image", "debian-trixie")
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
    # NOTE: when we allocate ourselves (not via --allocation-id reuse), we keep
    # track of whether we should free on error. Reused allocations belong to
    # the caller and we never free them implicitly.
    we_own_allocation = False
    if args.allocation_id:
        alloc = args.allocation_id
        print(f"[dispatch] reusing existing allocation: {alloc}")
    else:
        # Anti-pattern §12.31 (trim=True helps) + §12.32 (trim alone is NOT
        # enough when start_date is already in the past — trim clips end_date
        # but leaves the stale event in place, and the next allocate trying
        # to update it fails with `Cannot update event in the past`).
        # Verified Jun 6 08:54.
        # Fix: free with trim AND explicitly delete any matching calendar
        # entries for our nodes before allocating.
        will_create_event = args.allocation_duration > 0
        print(f"[dispatch] freeing nodes (idempotent, trim={will_create_event}): "
              f"{' '.join(nodes)}")
        for n in nodes:
            try:
                pos.allocations.free(n, trim=will_create_event)
            except Exception:
                pass  # already free

        if will_create_event:
            _delete_stale_calendar_entries(nodes)
        print(f"[dispatch] allocating: {' '.join(nodes)}")
        try:
            alloc_resp = pos.allocations.allocate(
                nodes,
                # NOTE per pos-examples synthesize_programs:51-58 + anti-pattern §12.29:
                #  - duration=None  ⇒ "use a PRE-EXISTING calendar event"
                #    (fails with `You have no calendar event for nodes: <n>` if none)
                #  - duration=N     ⇒ "create a new calendar event for N minutes"
                # Default arg is 120 so allocate always works without prior
                # calendar setup; pass --allocation-duration 0 to use a pre-existing
                # event (only useful if your TA pre-allocated time for you).
                duration=None if args.allocation_duration <= 0 else args.allocation_duration,
                result_folder=f"a4/{name}",
            )
        except Exception as e:
            msg = str(e)
            # Decode poslib's misleading messages into actionable hints
            # (anti-pattern §12.28: pos allocate failure modes).
            if "Maximum number of future entries" in msg:
                print(
                    f"\n[dispatch] !!! ALLOCATE FAILED: {e}\n"
                    f"[dispatch] !!! POS per-user quota is 2 concurrent calendar events.\n"
                    f"[dispatch] !!! See your active allocations:\n"
                    f"[dispatch] !!!   pos allocations list | grep $(whoami)\n"
                    f"[dispatch] !!! Either free one of them:\n"
                    f"[dispatch] !!!   pos allocations free <alloc-id>\n"
                    f"[dispatch] !!! Or wait for one to finish (this dispatcher\n"
                    f"[dispatch] !!! will auto-clean its calendar entry on free).\n"
                    f"[dispatch] !!! See anti-pattern §12.28.\n",
                    file=sys.stderr,
                )
            elif "no calendar event" in msg.lower():
                print(
                    f"\n[dispatch] !!! ALLOCATE FAILED: {e}\n"
                    f"[dispatch] !!! Likely cause: --allocation-duration set to 0\n"
                    f"[dispatch] !!! (uses pre-existing event) but no event exists\n"
                    f"[dispatch] !!! for this node. Try omitting --allocation-duration\n"
                    f"[dispatch] !!! (defaults to 120 min) or pass a positive value.\n"
                    f"[dispatch] !!! See anti-pattern §12.29.\n",
                    file=sys.stderr,
                )
            elif "Cannot update event in the past" in msg:
                print(
                    f"\n[dispatch] !!! ALLOCATE FAILED: {e}\n"
                    f"[dispatch] !!! Stale calendar entry with past start_date is blocking\n"
                    f"[dispatch] !!! the new allocate. The dispatcher should have cleaned\n"
                    f"[dispatch] !!! this up via _delete_stale_calendar_entries() but didn't.\n"
                    f"[dispatch] !!! Inspect: pos calendar list -j | python -m json.tool\n"
                    f"[dispatch] !!! Manually delete: pos calendar delete --id <id> <node>\n"
                    f"[dispatch] !!! See anti-patterns §12.31 and §12.32.\n",
                    file=sys.stderr,
                )
            raise
        # poslib usually returns (alloc_id, _, result_dir); fall back if shape differs
        try:
            alloc = alloc_resp[0]
        except (TypeError, IndexError):
            alloc = alloc_resp
        we_own_allocation = True
        print(f"[dispatch] allocation = {alloc}")
    result.allocation = alloc

    # From here on, any uncaught exception leaves the allocation orphaned.
    # We print a CLEAR hint so the user knows the exact `pos allocations free`
    # command to run for cleanup (we don't auto-free because the user may want
    # to inspect partial state).
    def _print_orphan_hint(exc: BaseException) -> None:
        if we_own_allocation:
            print(
                f"\n[dispatch] !!! UNCAUGHT ERROR after allocation: {exc}\n"
                f"[dispatch] !!! Allocation {alloc} is still held by you and will\n"
                f"[dispatch] !!! tick down its full duration unless you free it manually:\n"
                f"[dispatch] !!!   pos allocations free {alloc}\n",
                file=sys.stderr,
            )

    try:
        _dispatch_after_alloc(args, result, nodes, image, bundle_path,
                              assignments, name, guest_args, no_internet)
    except BaseException as e:
        _print_orphan_hint(e)
        raise

    result.ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return result


def _dispatch_after_alloc(args, result, nodes, image, bundle_path,
                          assignments, name, guest_args, no_internet) -> None:
    """Steps 2–5 of dispatch, factored out so the caller can wrap in a
    try/except that prints a free-the-allocation hint on uncaught errors."""

    # ----- 2. push per-job variables BEFORE reset --------------------------
    # CRITICAL ordering rule (verified Jun 6 07:30 from ALL 5 pos-examples):
    # `set_variables` MUST be called BEFORE `nodes reset`. On-node
    # `pos_get_variable` reads BOOTSTRAP-CACHED values, so vars set after
    # reset are INVISIBLE to the booted node. Anti-pattern §12.27.
    # NB: this assumes one job per node per allocation (true for smoke and
    # the v1 manifests). For multi-job-per-node we'd need to reset between
    # jobs, which is a bigger redesign.
    print(f"[dispatch] pushing per-job variables BEFORE reset ({len(assignments)} jobs)")
    per_job_yml: dict[str, str] = {}  # node -> tmp yml path (for cleanup)
    for a in assignments:
        vars_dict = _vars_yaml_for_job(a.job, name, guest_args, no_internet)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            yaml.safe_dump(vars_dict, f)
            yml_path = f.name
        per_job_yml[a.node] = yml_path
        # Use the CLI path because pos-examples uses it universally; the
        # Python API works too but the CLI is the canonical reference.
        _set_variables_cli(a.node, yml_path)
        print(f"  + {a.node:20s} variables set ({len(vars_dict)} keys)")

    # ----- 3. image + reset ------------------------------------------------
    # NOTE per official poslib docs (verified Jun 6) `pos.nodes.image` and
    # `pos.nodes.reset` take a SINGLE NODE STRING (or a role), NOT a list.
    # Passing a list trips poslib's URL builder ('/'.join with a list inside).
    # For multi-node dispatch (IV.POS.3+) we should switch to non-blocking
    # reset + await for parallelism; sequential is fine for 1-node smoke.
    print(f"[dispatch] setting image {image} on each node")
    for n in nodes:
        pos.nodes.image(n, image)
    print(f"[dispatch] resetting nodes (blocking — wait for boot, sequential)")
    for n in nodes:
        pos.nodes.reset(n, blocking=True)

    # ----- 4. ship bundle to each node -------------------------------------
    bundle_basename = bundle_path.name
    print(f"[dispatch] copying bundle to {len(nodes)} nodes: {bundle_basename}")
    for n in nodes:
        pos.nodes.copy(n, str(bundle_path), "/root/", recursive=False)

    print(f"[dispatch] extracting bundle on each node (synchronous)")
    # Write the extract script ONCE to a temp file, ship via `infile=` to every
    # node. NOTE per poslib source (`api/commands.py:67`) `infile` must be a
    # FILE OBJECT (`.read()` is called on it), NOT a path string. Only the
    # `pos commands launch --infile <path>` CLI form takes a path; the Python
    # API takes the open file. pos-examples `synthesize_programs:69` confirms:
    # `return open(full_path, 'r')`. Verified Jun 6 06:54.
    extract_script_path = _make_extract_bundle_script(bundle_basename)
    extract_ids: list[tuple[str, str]] = []
    try:
        for n in nodes:
            with open(extract_script_path, "r") as fh:
                cid_resp = pos.commands.launch(
                    n,
                    infile=fh,
                    blocking=False,
                    queued=True,
                    name="extract_bundle",
                )
            cid = _extract_cmd_id(cid_resp, n)
            if not cid:
                print(f"[dispatch] WARN: extract launch on {n} returned no cmd id "
                      f"(resp={cid_resp!r}); proceeding without await",
                      file=sys.stderr)
                continue
            extract_ids.append((n, cid))
        for n, cid in extract_ids:
            rc, err = _await_id_silently(cid, timeout_s=300)
            if rc != 0:
                print(f"[dispatch] WARN: extract on {n} cmd={cid} rc={rc} ({err})",
                      file=sys.stderr)
    finally:
        Path(extract_script_path).unlink(missing_ok=True)

    # ----- 5. launch runners ------------------------------------------------
    runner_local = Path(__file__).parent / "run_campaign_pos.sh"
    if not runner_local.is_file():
        raise SystemExit(f"runner not found: {runner_local}")

    print(f"[dispatch] launching {len(assignments)} jobs")
    for a in assignments:
        try:
            # `infile=` must be a FILE OBJECT (anti-pattern §12.23).
            with open(str(runner_local), "r") as fh:
                cmd_resp = pos.commands.launch(
                    a.node,
                    infile=fh,
                    blocking=False,
                    queued=True,
                    name=a.run_id,
                )
            a.command_id = _extract_cmd_id(cmd_resp, a.node)
            print(f"  + {a.node:20s} -> cmd {a.command_id} ({a.run_id})")
        except Exception as e:
            a.error = str(e)
            print(f"  ! {a.node:20s} FAILED: {e}", file=sys.stderr)

    # Clean up the temp YAML files now that variables have been persisted
    # by the master and launches are queued.
    for _node, _yml in per_job_yml.items():
        Path(_yml).unlink(missing_ok=True)

    # ----- 6. optionally wait -----------------------------------------------
    if args.await_completion:
        print(f"[dispatch] awaiting {len(assignments)} commands (per-job timeout {args.await_timeout}s)")
        for a in assignments:
            if not a.command_id:
                continue
            rc, err = _await_id_silently(a.command_id, timeout_s=args.await_timeout)
            print(f"  = {a.node:20s} {a.command_id} rc={rc} {err}")
            if rc != 0 and not a.error:
                a.error = err or f"rc={rc}"


# --------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------- #
def _main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else "")
    p.add_argument("--manifest", required=True, help="path to campaign manifest JSON")
    p.add_argument("--bundle", required=True, help="path to bundle tarball (local on mgmt node)")
    p.add_argument("--nodes", nargs="+", required=True, help="POS nodes to dispatch onto")
    p.add_argument("--image", default=None,
                   help="image (overrides manifest; default debian-trixie because "
                        "risc0-host needs GLIBC 2.39+; see anti-pattern §12.30)")
    p.add_argument("--out", default="dispatch_manifest.json", help="output JSON path")
    p.add_argument("--allocation-id", default=None,
                   help="reuse this allocation id (skip allocate/free)")
    p.add_argument("--allocation-duration", type=int, default=120,
                   help="allocation duration in minutes; ALSO creates the calendar "
                        "event when one doesn't pre-exist. Set to 0 (NOT recommended) "
                        "to use a pre-existing calendar event. Default 120 matches "
                        "pos-examples synthesize_programs:53.")
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
