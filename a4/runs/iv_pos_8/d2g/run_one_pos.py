#!/usr/bin/env python3
"""Minimal POS entrypoint for single-accept triage (no pandas dependency)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .propagation_triage import (
    AcceptRow,
    baseline_traces,
    default_host,
    default_host_args,
    tier2_classify,
)


def triage_run_id(variant: str, seed: int, kind: str, step: int, iter_seed: int) -> str:
    return f"triage_{variant}_s{seed}_{kind}_step{step}_is{iter_seed}"


def main() -> int:
    parser = argparse.ArgumentParser(description="D2.G run_one (POS, no pandas)")
    parser.add_argument("--host", default=default_host())
    parser.add_argument("--variant", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--step", type=int, required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--iter-seed", type=int, required=True)
    parser.add_argument("--mutation-id", type=int, default=0)
    parser.add_argument("--host-args", nargs=argparse.REMAINDER, default=None)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--results-dir", type=Path, default=None)
    args = parser.parse_args()
    host_args = list(args.host_args) if args.host_args else default_host_args()

    acc = AcceptRow(
        variant=args.variant,
        seed=args.seed,
        mutation_id=args.mutation_id,
        kind=args.kind,
        step=args.step,
        iter_seed=args.iter_seed,
        local_failures=0,
        global_failures=0,
    )
    run_id = args.run_id or triage_run_id(
        acc.variant, acc.seed, acc.kind, acc.step, acc.iter_seed,
    )
    baseline = baseline_traces(args.host, host_args)
    t2 = tier2_classify(acc, host=args.host, host_args=host_args, baseline=baseline)
    row = {
        "variant": acc.variant,
        "seed": acc.seed,
        "mutation_id": acc.mutation_id,
        "kind": acc.kind,
        "step": acc.step,
        "iter_seed": acc.iter_seed,
        "class": t2.klass,
        "evidence": t2.evidence,
        "trace_changed": t2.trace_changed,
        "post_inject_pc_changed": t2.post_inject_pc_changed,
        "post_inject_trace_changed": t2.post_inject_trace_changed,
        "inject_disasm_changed": t2.inject_disasm_changed,
        "unaligned_access": t2.unaligned_access,
        "fault_word_change": t2.fault_word_change,
        "global_residue": False,
        "run_id": run_id,
    }
    if args.results_dir is not None:
        args.results_dir.mkdir(parents=True, exist_ok=True)
        (args.results_dir / f"{run_id}.json").write_text(json.dumps(row, sort_keys=True))
    print(json.dumps(row, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
