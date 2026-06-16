#!/usr/bin/env python3
"""Dispatch E5 distribution study to POS (multi-node shard) or run locally."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
HOST = ROOT / "frozen_host" / "thesis-full-sweep-host.e0frozen"
SAMPLE_SET = ROOT / "artifacts" / "e5" / "sample_set.json"
RAW = ROOT / "artifacts" / "e5" / "raw"
ATOMS = ROOT / "artifacts" / "e5" / "atoms"
DISPATCH_JSON = ROOT / "artifacts" / "e5" / "thesis_dispatch_manifest.json"

COINBASE = "ivgreiff@coinbase.net.in.tum.de"
SSH = ["ssh", "-p", "10022", COINBASE]
SCP = ["scp", "-P", "10022"]

sys.path.insert(0, str(REPO))

from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV  # noqa: E402
from thesis_side_experiments.full_sweep.e5_atom import parse_atom, write_gzip_log  # noqa: E402
from thesis_side_experiments.full_sweep.host_guard import assert_frozen_full_sweep  # noqa: E402

# User's thesis calendar nodes (entries 1752/1753) — do NOT use for E5.
RESERVED_NODES = frozenset(
    {"algofi", "flare", "gard", "goracle", "octorand", "opulous", "polynize", "zone"}
)


def ensure_sample_set(n: int) -> None:
    if not SAMPLE_SET.exists():
        subprocess.run(
            [sys.executable, str(ROOT / "sample_e5.py"), "--n", str(n), "--bake-a4"],
            check=True,
        )


def prepare_bundle() -> Path:
    subprocess.run(
        ["bash", str(REPO / "thesis_side_experiments" / "pos" / "prepare_e5_bundle.sh")],
        check=True,
        cwd=str(REPO),
    )
    bundles = sorted((REPO / "bundles").glob("thesis_e5_full_sweep_*.tar.gz"))
    if not bundles:
        raise SystemExit("E5 bundle not found after prepare_e5_bundle.sh")
    return bundles[-1]


def run_local_sample(sample: dict, host_sha: str) -> bool:
    """Run one sample. Returns False (skipped) if an A4 sample has no valid config
    (A4 had no valid target at this position -> build_a4_sample_config returned None)."""
    env = {**os.environ, **DEFAULT_ENV}
    if sample["fuzzer"] == "arguzz":
        cmd = [
            str(HOST),
            "--trace",
            "--inject",
            "--inject-step",
            str(sample["inject_step"]),
            "--inject-kind",
            sample["mutation_type"],
            "--seed",
            str(sample["seed"]),
        ]
    else:
        cfg_rel = sample.get("a4_config_path")
        cfg = (ROOT / cfg_rel) if cfg_rel else None
        if cfg is None or not cfg.is_file():
            return False  # no valid A4 target -> skip, do NOT pass the configs dir
        cmd = [str(HOST)]
        env["A4_MUTATION_CONFIG"] = str(cfg.resolve())
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    text = proc.stdout + proc.stderr
    raw_path = RAW / f"{sample['sample_id']}.log.gz"
    write_gzip_log(raw_path, text)
    sample_meta = {
        **sample,
        "raw_log_path": str(raw_path.relative_to(ROOT)),
        "cmd": cmd,
        "env": {k: env[k] for k in DEFAULT_ENV if k in env},
    }
    atom = parse_atom(sample_meta, text, host_sha)
    atom_path = ATOMS / f"{sample['sample_id']}.json"
    atom_path.parent.mkdir(parents=True, exist_ok=True)
    atom_path.write_text(json.dumps(atom, indent=2))
    return True


def run_local(limit: int) -> None:
    host_sha = assert_frozen_full_sweep(HOST)
    data = json.loads(SAMPLE_SET.read_text())
    samples = data["samples"][:limit]
    RAW.mkdir(parents=True, exist_ok=True)
    ATOMS.mkdir(parents=True, exist_ok=True)
    skipped = 0
    for i, s in enumerate(samples, 1):
        ran = run_local_sample(s, host_sha)
        if not ran:
            skipped += 1
            print(f"  [{i}/{len(samples)}] SKIP (no valid A4 target) {s['sample_id']}", flush=True)
            continue
        print(f"  [{i}/{len(samples)}] {s['sample_id']}", flush=True)
    if skipped:
        print(f"skipped {skipped} A4 samples with no valid target/config", flush=True)


def dispatch_pos(
    nodes: List[str],
    bundle: Path,
    await_timeout: int = 7200,
) -> dict:
    for n in nodes:
        if n in RESERVED_NODES:
            raise SystemExit(
                f"node {n} is reserved for thesis batch-1 — pick free Tier A/C nodes "
                f"(see POS_PLAYBOOK §3 + bias_campaign/POS_NOTES.md)"
            )

    remote_bundle = f"~/{bundle.name}"
    print(f"Copying bundle to coinbase: {bundle.name}", flush=True)
    subprocess.run(SCP + [str(bundle), f"{COINBASE}:{remote_bundle}"], check=True)

    remote_repo = "~/arguzz"
    for rel in (
        "thesis_side_experiments/pos/dispatch_thesis_e5.py",
        "thesis_side_experiments/pos/thesis_run_e5.sh",
        "thesis_side_experiments/full_sweep/e5_atom.py",
    ):
        local = REPO / rel
        if local.exists():
            subprocess.run(SCP + [str(local), f"{COINBASE}:{remote_repo}/{rel}"], check=True)

    nodes_s = " ".join(nodes)
    remote_out = "~/thesis_e5_dispatch.json"
    inner = (
        "source /srv/testbed/pos/cli/venv3/bin/activate && "
        f"cd {remote_repo} && "
        f"python thesis_side_experiments/pos/dispatch_thesis_e5.py "
        f"--bundle {remote_bundle} "
        f"--nodes {nodes_s} "
        "--allocation-duration 0 "
        "--image debian-trixie "
        f"--await --await-timeout {await_timeout} "
        f"--out {remote_out}"
    )
    tmux = (
        f"tmux new-session -d -s thesis_e5 "
        f"\"bash -lc '{inner}; echo rc=\\$? > ~/thesis_e5_dispatch.rc'\""
    )
    print(f"Launching tmux on coinbase: thesis_e5 ({len(nodes)} nodes)", flush=True)
    subprocess.run(SSH + [tmux], check=True)
    return {"tmux": "thesis_e5", "nodes": nodes, "bundle": str(bundle)}


def pull_results() -> None:
    remote = f"{COINBASE}:/root/a4_campaign/thesis/e5_results/"
    RAW.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        SCP + ["-r", remote, str(RAW.parent / "pos_raw")],
        check=False,
    )


def ingest(host_sha: str) -> None:
    """Parse pulled POS logs into atoms."""
    pos_raw = RAW.parent / "pos_raw"
    log_dir = pos_raw if pos_raw.exists() else RAW
    data = json.loads(SAMPLE_SET.read_text())
    by_id = {s["sample_id"]: s for s in data["samples"]}
    ATOMS.mkdir(parents=True, exist_ok=True)
    n = 0
    for gz in sorted(log_dir.glob("*.log.gz")):
        sid = gz.name.replace(".log.gz", "")
        if sid.endswith(".rerun") or sid not in by_id:
            continue
        with gzip.open(gz, "rt") as f:
            text = f.read()
        sample = {**by_id[sid], "raw_log_path": str(gz.relative_to(ROOT))}
        atom = parse_atom(sample, text, host_sha)
        (ATOMS / f"{sid}.json").write_text(json.dumps(atom, indent=2))
        n += 1
    print(f"ingested {n} atoms from {log_dir}")


def main() -> None:
    ap = argparse.ArgumentParser(description="E5 distribution study runner")
    ap.add_argument("--n", type=int, default=20, help="samples per type-variant (sample_e5)")
    sub = ap.add_subparsers(dest="cmd")

    loc = sub.add_parser("local", help="run first K samples locally (smoke)")
    loc.add_argument("--limit", type=int, default=5)

    pos = sub.add_parser("pos", help="dispatch to POS (multi-node shard)")
    pos.add_argument(
        "--nodes",
        nargs="+",
        required=True,
        help="free Tier A/C nodes (NOT polynize/flare/meld/octorand/opulous)",
    )
    pos.add_argument("--await-timeout", type=int, default=7200)

    sub.add_parser("ingest", help="parse pulled POS logs → atoms")
    sub.add_parser("pull", help="scp results from coinbase")

    args = ap.parse_args()
    ensure_sample_set(args.n)

    if args.cmd == "local":
        run_local(args.limit)
    elif args.cmd == "pos":
        bundle = prepare_bundle()
        dispatch_pos(args.nodes, bundle, args.await_timeout)
        print(json.dumps({"status": "dispatched", "bundle": str(bundle)}, indent=2))
    elif args.cmd == "pull":
        pull_results()
    elif args.cmd == "ingest":
        host_sha = assert_frozen_full_sweep(HOST)
        ingest(host_sha)
    else:
        ap.print_help()
        raise SystemExit(2)


if __name__ == "__main__":
    main()
