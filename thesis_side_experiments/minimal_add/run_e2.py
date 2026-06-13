#!/usr/bin/env python3
"""E2-FULL orchestrator: bake → run (local or polynize) → analyze → report."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
HOST = ROOT / "frozen_host" / "thesis-minimal-host.e0frozen"
CFG = ROOT / "artifacts" / "e2" / "configs"
MANIFEST = CFG / "manifest_e2.json"
LOG_DIR = ROOT / "artifacts" / "e2" / "pos_full" / "logs"
ANALYSIS = ROOT / "artifacts" / "e2" / "pos_full" / "analysis"
DISPATCH_JSON = ROOT / "artifacts" / "e2" / "pos_full" / "thesis_dispatch_manifest.json"

COINBASE = "ivgreiff@coinbase.net.in.tum.de"
SSH = ["ssh", "-p", "10022", COINBASE]
SCP = ["scp", "-P", "10022"]

sys.path.insert(0, str(REPO))

from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV  # noqa: E402
from thesis_side_experiments.minimal_add.host_guard import assert_frozen_host  # noqa: E402


def bake() -> None:
    subprocess.run([sys.executable, str(ROOT / "bake_e2_full.py")], check=True)


def run_local(entry: dict, log_path: Path) -> None:
    env = {**os.environ, **DEFAULT_ENV}
    cfg = CFG / Path(entry["config_file"]).name
    cmd = [str(HOST)]
    env["A4_MUTATION_CONFIG"] = str(cfg.resolve())
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(proc.stdout + proc.stderr)


def run_local_all(manifest_path: Path, log_dir: Path) -> None:
    assert_frozen_host(HOST)
    data = json.loads(manifest_path.read_text())
    runs = data["runs"]
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"Local run: {len(runs)} entries × 2 …", flush=True)
    for i, entry in enumerate(runs, 1):
        rid = entry["run_id"]
        run_local(entry, log_dir / f"{rid}.log")
        run_local(entry, log_dir / f"{rid}.rerun.log")
        print(f"  [{i}/{len(runs)}] {rid}", flush=True)


def analyze(manifest_path: Path, log_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "analyze_logs.py"),
            "--manifest",
            str(manifest_path),
            "--log-dir",
            str(log_dir),
            "--out-dir",
            str(out_dir),
            "--rerun-suffix",
            ".rerun",
        ],
        check=True,
    )


def prepare_bundle() -> Path:
    existing = sorted((REPO / "bundles").glob("thesis_minimal_add_*.tar.gz"))
    if existing:
        bundle = existing[-1]
        print(f"Reusing bundle: {bundle.name}", flush=True)
        return bundle
    subprocess.run(
        ["bash", str(REPO / "thesis_side_experiments" / "pos" / "prepare_thesis_bundle.sh")],
        check=True,
        cwd=str(REPO),
    )
    bundles = sorted((REPO / "bundles").glob("thesis_minimal_add_*.tar.gz"))
    if not bundles:
        raise SystemExit("bundle not found after prepare_thesis_bundle.sh")
    return bundles[-1]


def dispatch_polynize(bundle: Path, await_timeout: int = 7200) -> dict:
    remote_bundle = f"~/{bundle.name}"
    print(f"Copying bundle to coinbase: {bundle.name}", flush=True)
    subprocess.run(SCP + [str(bundle), f"{COINBASE}:{remote_bundle}"], check=True)

    remote_repo = "~/arguzz"
    for rel in (
        "thesis_side_experiments/pos/dispatch_thesis_pos.py",
        "thesis_side_experiments/pos/thesis_run_pos.sh",
        "thesis_side_experiments/minimal_add/analyze_logs.py",
        "thesis_side_experiments/minimal_add/e2_report.py",
        "thesis_side_experiments/bias_campaign/a4_config.py",
    ):
        local = REPO / rel
        subprocess.run(SCP + [str(local), f"{COINBASE}:{remote_repo}/{rel}"], check=True)

    remote_out = "~/thesis_e2_dispatch.json"
    remote_rc = "~/thesis_e2_dispatch.rc"
    inner = (
        "source /srv/testbed/pos/cli/venv3/bin/activate && "
        f"cd {remote_repo} && "
        "rm -f ~/thesis_e2_dispatch.rc && "
        f"python thesis_side_experiments/pos/dispatch_thesis_pos.py "
        f"--bundle {remote_bundle} "
        "--nodes polynize "
        "--allocation-duration 0 "
        "--image debian-trixie "
        "--manifest manifest_e2.json "
        f"--await --await-timeout {await_timeout} "
        f"--out {remote_out} "
        "2>&1 | tee ~/thesis_e2_dispatch.log; "
        f"echo $? > {remote_rc}"
    )
    tmux_cmd = (
        "tmux kill-session -t thesis_e2 2>/dev/null; "
        f"tmux new-session -d -s thesis_e2 {json.dumps(inner)}"
    )
    print(
        "Launching polynize dispatch in tmux session 'thesis_e2' "
        "(thin thesis_run_pos.sh path, ~10–15 min expected)…",
        flush=True,
    )
    subprocess.run(SSH + [tmux_cmd], check=True)

    deadline = time.time() + await_timeout + 300
    last_line = ""
    while time.time() < deadline:
        poll = subprocess.run(
            SSH
            + [
                "bash -lc "
                + json.dumps(
                    "tmux has-session -t thesis_e2 2>/dev/null && echo RUNNING || echo DONE; "
                    "tail -1 ~/thesis_e2_dispatch.log 2>/dev/null; "
                    "test -f ~/thesis_e2_dispatch.rc && cat ~/thesis_e2_dispatch.rc"
                )
            ],
            capture_output=True,
            text=True,
        )
        lines = [ln for ln in poll.stdout.splitlines() if ln.strip()]
        status = lines[0] if lines else "?"
        log_tail = lines[1] if len(lines) > 1 else ""
        rc_str = lines[2] if len(lines) > 2 else ""
        if log_tail and log_tail != last_line:
            print(f"[polynize] {log_tail}", flush=True)
            last_line = log_tail
        if rc_str:
            rc = int(rc_str.strip())
            # zsh pipeline $? reflects tee, not python — trust dispatch json + log
            if rc != 0:
                log_check = subprocess.run(
                    SSH + ["grep -q 'await rc=0' ~/thesis_e2_dispatch.log && echo OK"],
                    capture_output=True,
                    text=True,
                )
                if "OK" in log_check.stdout:
                    rc = 0
            if rc != 0:
                tail = subprocess.run(
                    SSH + ["tail -30 ~/thesis_e2_dispatch.log"],
                    capture_output=True,
                    text=True,
                )
                print(tail.stdout, file=sys.stderr)
                raise SystemExit(f"polynize dispatch failed rc={rc}")
            break
        if status == "DONE" and not rc_str:
            time.sleep(5)
            continue
        time.sleep(30)
    else:
        raise SystemExit("polynize dispatch timed out waiting for tmux session")

    fetch = subprocess.run(
        SSH + [f"cat {remote_out}"],
        capture_output=True,
        text=True,
        check=True,
    )
    dm = json.loads(fetch.stdout)
    DISPATCH_JSON.parent.mkdir(parents=True, exist_ok=True)
    DISPATCH_JSON.write_text(json.dumps(dm, indent=2))
    return dm


def pull_results(dispatch: dict) -> Path:
    """Pull thesis results from polynize via coinbase pos collect or scp."""
    alloc = dispatch.get("allocation", "")
    node = dispatch.get("node", "polynize")
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    pull_cmd = (
        "source /srv/testbed/pos/cli/venv3/bin/activate && "
        "python3 - <<'PY'\n"
        "import poslib as pos, json, sys\n"
        f"alloc = {json.dumps(alloc)!r}\n"
        f"node = {json.dumps(node)!r}\n"
        "paths = pos.results.list(alloc)\n"
        "print(json.dumps(paths))\n"
        "PY"
    )
    try:
        out = subprocess.run(SSH + [pull_cmd], capture_output=True, text=True, check=True)
        paths = json.loads(out.stdout.strip() or "[]")
        print(f"POS result paths: {len(paths)}", flush=True)
    except Exception as exc:
        print(f"WARN list results: {exc}", flush=True)
        paths = []

    remote_results = "~/a4_campaign/thesis/results"
    scp_cmd = SCP + ["-r", f"{COINBASE}:{remote_results}/*", str(LOG_DIR) + "/"]
    try:
        subprocess.run(scp_cmd, check=True, timeout=300)
    except subprocess.CalledProcessError:
        alt = (
            f"/srv/testbed/results/ivgreiff/a4/thesis_e2_smoke/"
        )
        print(f"Trying POS results folder under {alt}…", flush=True)
        find_cmd = (
            f"find {alt} -name 'determinism_summary.txt' 2>/dev/null | tail -1"
        )
        found = subprocess.run(SSH + [find_cmd], capture_output=True, text=True)
        if found.stdout.strip():
            res_dir = str(Path(found.stdout.strip()).parent)
            subprocess.run(
                SCP + ["-r", f"{COINBASE}:{res_dir}/*", str(LOG_DIR) + "/"],
                check=True,
            )
        else:
            raise SystemExit(
                "Could not pull polynize logs — check ~/thesis_e2_dispatch.log on coinbase"
            )
    return LOG_DIR


def main() -> None:
    ap = argparse.ArgumentParser(description="E2-FULL run orchestrator")
    ap.add_argument("--bake-only", action="store_true")
    ap.add_argument("--local", action="store_true", help="run on WSL frozen host (not polynize)")
    ap.add_argument("--dispatch", action="store_true", help="dispatch to polynize via coinbase")
    ap.add_argument("--skip-bake", action="store_true")
    ap.add_argument("--skip-dispatch", action="store_true")
    ap.add_argument("--analysis-only", action="store_true")
    ap.add_argument("--log-dir", type=Path, default=None)
    ap.add_argument("--await-timeout", type=int, default=7200)
    args = ap.parse_args()

    if args.analysis_only:
        log_dir = args.log_dir or LOG_DIR
        analyze(MANIFEST, log_dir, ANALYSIS)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "e2_report.py"),
                "--analysis-dir",
                str(ANALYSIS),
                "--log-dir",
                str(log_dir),
                "--dispatch-json",
                str(DISPATCH_JSON),
            ],
            check=True,
        )
        return

    if not args.skip_bake:
        bake()

    if args.bake_only:
        return

    dispatch = None
    if args.local:
        log_dir = args.log_dir or (ROOT / "artifacts" / "e2" / "local_full" / "logs")
        run_local_all(MANIFEST, log_dir)
    elif args.dispatch and not args.skip_dispatch:
        bundle = prepare_bundle()
        dispatch = dispatch_polynize(bundle, args.await_timeout)
        log_dir = pull_results(dispatch)
    else:
        log_dir = args.log_dir or LOG_DIR
        if not log_dir.exists() or not list(log_dir.glob("*.log")):
            raise SystemExit("No logs — use --local, --dispatch, or --log-dir")

    analyze(MANIFEST, log_dir, ANALYSIS)
    report_args = [
        sys.executable,
        str(ROOT / "e2_report.py"),
        "--analysis-dir",
        str(ANALYSIS),
        "--log-dir",
        str(log_dir),
    ]
    if dispatch or DISPATCH_JSON.exists():
        report_args.extend(["--dispatch-json", str(DISPATCH_JSON)])
    subprocess.run(report_args, check=True)


if __name__ == "__main__":
    main()
