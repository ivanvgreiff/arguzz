#!/usr/bin/env python3
"""AP.B2 POS entrypoint — single screen or bracket job (writes JSON + .OK marker dir)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from a4.scripts.ap_b2_replay import (  # noqa: E402
    CorpusEntry,
    bracket_corpus,
    is_010,
    pick_mutated,
    run_config,
)
from a4.standalone.mutations.pre_exec_reg_mod import (  # noqa: E402
    PreExecRegModTarget,
    create_config,
)

DEFAULT_PATCHED = ROOT / "a4/builds/ap/patched/risc0-host"
DEFAULT_BENCH = ROOT / "a4/builds/ap/bench-isread/risc0-host"
DEFAULT_GUEST_ARGS = ["--in1", "5", "--in4", "10"]


def _target_from_args(args: argparse.Namespace) -> PreExecRegModTarget:
    return PreExecRegModTarget(
        step=args.step,
        cycle_idx=args.cycle_idx,
        pc=args.pc,
        major=args.major,
        minor=args.minor,
        txn_idx=args.txn_idx,
        addr=args.addr,
        register_idx=args.register_idx,
        register_name=args.register_name,
        original_word=args.original_word,
        prev_word=args.prev_word,
        is_write=bool(args.is_write),
        strategy=args.strategy,
    )


def run_screen(args: argparse.Namespace) -> dict:
    target = _target_from_args(args)
    cfg_dir = Path(args.cfg_dir)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    mutated = pick_mutated(target)
    cfg_path = create_config(
        target,
        mutated,
        cfg_dir / f"screen_s{target.step}_txn{target.txn_idx}.json",
    )
    outcome = run_config(args.patched_host, args.guest_args, cfg_path)
    hit = is_010(outcome["layers"])
    return {
        "mode": "screen",
        "run_id": args.run_id,
        "hit": hit,
        "target": {
            "step": target.step,
            "cycle_idx": target.cycle_idx,
            "pc": target.pc,
            "major": target.major,
            "minor": target.minor,
            "txn_idx": target.txn_idx,
            "addr": target.addr,
            "register_idx": target.register_idx,
            "register_name": target.register_name,
            "original_word": target.original_word,
            "prev_word": target.prev_word,
            "is_write": target.is_write,
            "strategy": target.strategy,
        },
        "mutated_word": mutated,
        "config_path": str(cfg_path),
        "layers_patched": outcome["layers"],
        "accepted": outcome["accepted"],
    }


def run_bracket(args: argparse.Namespace) -> dict:
    cfg_dir = Path(args.cfg_dir)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / f"{args.config_id}.json"
    entry = CorpusEntry(
        config_id=args.config_id,
        step=args.step,
        txn_idx=args.txn_idx,
        word=args.word,
        strategy=args.strategy,
        major=args.major,
        minor=args.minor,
        register_name=args.register_name,
        register_idx=args.register_idx,
        original_word=args.original_word,
        prev_word=args.prev_word,
        pc=args.pc if isinstance(args.pc, str) else f"0x{args.pc:08x}",
        source=args.source,
        layers_patched={},
        config_path=str(cfg_path),
        addr=args.addr,
        cycle_idx=args.cycle_idx,
        is_write=bool(args.is_write),
    )
    rows = bracket_corpus(
        [entry],
        args.bench_host,
        args.patched_host,
        args.guest_args,
    )
    row = rows[0]
    row["mode"] = "bracket"
    row["run_id"] = args.run_id
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("screen", "bracket"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--patched-host", default=str(DEFAULT_PATCHED))
    parser.add_argument("--bench-host", default=str(DEFAULT_BENCH))
    parser.add_argument("--guest-args", nargs="*", default=DEFAULT_GUEST_ARGS)
    parser.add_argument("--cfg-dir", default=None)

    # screen target fields
    parser.add_argument("--step", type=int, default=0)
    parser.add_argument("--cycle-idx", type=int, default=0)
    parser.add_argument("--pc", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--major", type=int, default=0)
    parser.add_argument("--minor", type=int, default=0)
    parser.add_argument("--txn-idx", type=int, default=0)
    parser.add_argument("--addr", type=int, default=0)
    parser.add_argument("--register-idx", type=int, default=0)
    parser.add_argument("--register-name", default="")
    parser.add_argument("--original-word", type=int, default=0)
    parser.add_argument("--prev-word", type=int, default=0)
    parser.add_argument("--is-write", type=int, default=0)
    parser.add_argument("--strategy", default="next_read")

    # bracket corpus fields
    parser.add_argument("--config-id", default="")
    parser.add_argument("--word", type=int, default=0)
    parser.add_argument("--source", default="race_guest_screen")
    parser.add_argument("--layers-json", default="{}")
    parser.add_argument("--config-path", default="")

    args = parser.parse_args()
    if args.cfg_dir is None:
        sub = "screen" if args.mode == "screen" else "bracket"
        args.cfg_dir = str(ROOT / f"a4/runs/iv_pos_9/ap/configs/{sub}")
    args.results_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "screen":
        row = run_screen(args)
    else:
        row = run_bracket(args)

    out_path = args.results_dir / f"{args.run_id}.json"
    out_path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    print(json.dumps(row, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
