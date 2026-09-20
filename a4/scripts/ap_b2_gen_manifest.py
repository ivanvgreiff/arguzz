#!/usr/bin/env python3
"""Generate AP.B2 chain manifests from inspection (screen + bracket phases)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.standalone.mutations.pre_exec_reg_mod import get_all_targets  # noqa: E402

DEFAULT_NODES = ["flare", "zone", "goracle", "algofi", "opulous", "polynize", "octorand", "gard"]
OUT_DIR = ROOT / "a4/runs/iv_pos_9/ap"
REMOTE_BASE = "/tmp/chainjob"
CAMPAIGN_ROOT = "/root/a4_ap_campaign"


def _remote_dir(run_id: str) -> str:
    return f"{REMOTE_BASE}_{run_id}"


def _remote_cmd(run_id: str, py_args: str) -> str:
    remote_dir = _remote_dir(run_id)
    return (
        f"mkdir -p {remote_dir} && cd {CAMPAIGN_ROOT}/repo && "
        f"PYTHONPATH={CAMPAIGN_ROOT}/repo "
        f"python3 a4/scripts/ap_b2_run_one.py {py_args} "
        f"--run-id {run_id} --results-dir {remote_dir} "
        f"&& touch {remote_dir}/.OK"
    )


def _screen_args(t, patched_host: str, cfg_dir: str) -> str:
    return (
        f"--mode screen "
        f"--patched-host {patched_host} "
        f"--cfg-dir {cfg_dir} "
        f"--step {t.step} --cycle-idx {t.cycle_idx} --pc {t.pc} "
        f"--major {t.major} --minor {t.minor} --txn-idx {t.txn_idx} "
        f"--addr {t.addr} --register-idx {t.register_idx} "
        f"--register-name {t.register_name} "
        f"--original-word {t.original_word} --prev-word {t.prev_word} "
        f"--is-write {1 if t.is_write else 0} --strategy {t.strategy}"
    )


def _bracket_args(entry: dict, bench_host: str, patched_host: str) -> str:
    return (
        f"--mode bracket "
        f"--bench-host {bench_host} --patched-host {patched_host} "
        f"--config-id {entry['config_id']} "
        f"--step {entry['step']} --txn-idx {entry['txn_idx']} "
        f"--word {entry['word']} --strategy {entry['strategy']} "
        f"--major {entry['major']} --minor {entry['minor']} "
        f"--register-name {entry['register_name']} "
        f"--register-idx {entry['register_idx']} "
        f"--original-word {entry['original_word']} --prev-word {entry['prev_word']} "
        f"--addr {entry.get('addr', 0)} --cycle-idx {entry.get('cycle_idx', 0)} "
        f"--is-write {1 if entry.get('is_write') else 0} "
        f"--pc {entry['pc']} --source {entry['source']}"
    )


def write_round_robin_manifest(
    path: Path,
    batch_prefix: str,
    nodes: List[str],
    jobs: List[tuple],
) -> None:
    """jobs: list of (run_id, remote_cmd)"""
    lines: List[str] = []
    batch_idx = 0
    for i in range(0, len(jobs), len(nodes)):
        batch_idx += 1
        chunk = jobs[i : i + len(nodes)]
        for j, (run_id, cmd) in enumerate(chunk):
            node = nodes[j % len(nodes)]
            lines.append(f"{batch_prefix}{batch_idx:04d}|{node}|{run_id}|{cmd}")
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_screen = sub.add_parser("screen", help="Generate screen-phase manifest from inspection")
    p_screen.add_argument("--max-screen", type=int, default=None)
    p_screen.add_argument("--patched-host", default=str(ROOT / "a4/builds/ap/patched/risc0-host"))
    p_screen.add_argument("--guest-args", nargs="*", default=["--in1", "5", "--in4", "10"])
    p_screen.add_argument("--nodes", nargs="*", default=DEFAULT_NODES)
    p_screen.add_argument("--out", type=Path, default=OUT_DIR / "ap_b2_screen.chain")
    p_screen.add_argument("--targets-json", type=Path, default=None)

    p_bracket = sub.add_parser("bracket", help="Generate bracket manifest from corpus JSON")
    p_bracket.add_argument("--corpus", type=Path, default=OUT_DIR / "ap_corpus_010.json")
    p_bracket.add_argument(
        "--bench-host",
        default=f"{CAMPAIGN_ROOT}/bin/risc0-host-bench-isread",
    )
    p_bracket.add_argument(
        "--patched-host",
        default=f"{CAMPAIGN_ROOT}/bin/risc0-host-patched",
    )
    p_bracket.add_argument("--nodes", nargs="*", default=DEFAULT_NODES)
    p_bracket.add_argument("--out", type=Path, default=OUT_DIR / "ap_b2_bracket.chain")

    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    if args.cmd == "screen":
        if args.targets_json and args.targets_json.is_file():
            raw = json.loads(args.targets_json.read_text())
            targets = raw["targets"]
            from a4.standalone.mutations.pre_exec_reg_mod import PreExecRegModTarget

            target_objs = [PreExecRegModTarget(**t) for t in targets]
            if args.max_screen is not None:
                target_objs = target_objs[: args.max_screen]
        else:
            print(f"[gen] inspection via {args.patched_host}...", flush=True)
            data = InspectionData.from_inspection(args.patched_host, args.guest_args)
            target_objs = [
                t
                for t in get_all_targets(data, strategy="next_read")
                if t.major in (5, 6)
            ]
            if args.max_screen is not None:
                target_objs = target_objs[: args.max_screen]
            targets_path = OUT_DIR / "ap_b2_targets_loadstore.json"
            targets_path.write_text(
                json.dumps(
                    {
                        "count": len(target_objs),
                        "guest_args": args.guest_args,
                        "targets": [
                            {
                                "step": t.step,
                                "cycle_idx": t.cycle_idx,
                                "pc": t.pc,
                                "major": t.major,
                                "minor": t.minor,
                                "txn_idx": t.txn_idx,
                                "addr": t.addr,
                                "register_idx": t.register_idx,
                                "register_name": t.register_name,
                                "original_word": t.original_word,
                                "prev_word": t.prev_word,
                                "is_write": t.is_write,
                                "strategy": t.strategy,
                            }
                            for t in target_objs
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            print(f"[gen] wrote {len(target_objs)} targets -> {targets_path}", flush=True)

        patched = f"{CAMPAIGN_ROOT}/bin/risc0-host-patched"
        cfg_dir = f"{CAMPAIGN_ROOT}/configs/screen"
        jobs = []
        for i, t in enumerate(target_objs):
            run_id = f"ap_b2_screen_{i:05d}"
            py_args = _screen_args(t, patched, cfg_dir)
            jobs.append((run_id, _remote_cmd(run_id, py_args)))

        write_round_robin_manifest(args.out, "ap_b2_screen_b", args.nodes, jobs)
        print(f"[gen] screen manifest: {len(jobs)} jobs -> {args.out}")
        return 0

    raw = json.loads(args.corpus.read_text())
    corpus = raw["corpus"]
    jobs = []
    for entry in corpus:
        run_id = f"ap_b2_bracket_{entry['config_id']}"
        py_args = _bracket_args(entry, args.bench_host, args.patched_host)
        jobs.append((run_id, _remote_cmd(run_id, py_args)))

    write_round_robin_manifest(args.out, "ap_b2_bracket_b", args.nodes, jobs)
    print(f"[gen] bracket manifest: {len(jobs)} jobs -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
