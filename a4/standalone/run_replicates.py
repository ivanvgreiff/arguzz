#!/usr/bin/env python3
"""
Phase III.4 — Multi-seed replicate runner.

A thin wrapper around `python -m a4.standalone.cli fuzz` that runs the
same campaign R times with different seeds, optionally across multiple
strategies, and emits a manifest.json so downstream aggregation (Phase
IV.2 boss notebook, cloud aggregator) can discover the per-replicate
DBs without re-parsing CLI invocations.

Usage:
    python -m a4.standalone.run_replicates \\
        --host /path/to/risc0-host \\
        --strategies uniform zoned bandit-16 \\
        --replicates 3 --seed-base 1000 \\
        --num 200 \\
        --out-dir ./local_validation/ \\
        -- --in1 5 --in4 10

Produces:
    local_validation/
    ├── manifest.json
    ├── uniform/
    │   ├── seed_1000.db   seed_1000.log
    │   ├── seed_1001.db   seed_1001.log
    │   └── seed_1002.db   seed_1002.log
    ├── zoned/
    │   └── ...
    └── bandit-16/
        └── ...

Notes:
- Each campaign is one subprocess of `python -m a4.standalone.cli fuzz`.
  The host binary is single-CPU-bound, so --parallel N > NCPU//2 is
  rejected.
- Strategy labels: "uniform", "zoned", "guided", "bandit", and
  "bandit-<N>" where <N> is the --b-count override.
- This script is local-only. In cloud, each job runs one campaign with
  one seed; cross-seed parallelism comes from the dispatcher.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


_VALID_BARE_STRATEGIES = {"uniform", "zoned", "guided", "bandit"}


def _iso(epoch_seconds: float) -> str:
    """RFC3339 UTC timestamp."""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_strategy(label: str) -> Tuple[str, Optional[int]]:
    """
    Parse a strategy label.

    >>> _parse_strategy("uniform")
    ('uniform', None)
    >>> _parse_strategy("bandit-16")
    ('bandit', 16)
    >>> _parse_strategy("bandit")
    ('bandit', None)
    """
    if label in _VALID_BARE_STRATEGIES:
        return label, None
    if label.startswith("bandit-"):
        try:
            b_count = int(label.split("-", 1)[1])
        except ValueError as e:
            raise ValueError(f"Invalid bandit b-count in label {label!r}") from e
        if b_count <= 0:
            raise ValueError(f"Bandit b-count must be > 0, got {b_count}")
        return "bandit", b_count
    raise ValueError(
        f"Unknown strategy {label!r}; expected one of "
        f"{sorted(_VALID_BARE_STRATEGIES)} or 'bandit-<N>'"
    )


def _run_one_campaign(spec: dict) -> dict:
    """
    Execute one inner CLI invocation and return a manifest entry.

    Pickling-safe (uses only stdlib + str args) so it runs cleanly
    under ProcessPoolExecutor.
    """
    cmd = [
        sys.executable, "-m", "a4.standalone.cli", "fuzz",
        "--host", spec["host"],
        "--num", str(spec["num"]),
        "--kind", spec["kind"],
        "--values", spec["values"],
        "--selector", spec["selector"],
        "--seed", str(spec["seed"]),
        "--db", spec["db_abs"],
    ]
    if spec["b_count"] is not None:
        cmd += ["--b-count", str(spec["b_count"])]
    if spec["host_args"]:
        cmd += ["--"] + list(spec["host_args"])

    started_at = time.time()
    with open(spec["log_abs"], "w") as f:
        rc = subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT)
    finished_at = time.time()

    n_mut = -1
    db_path = Path(spec["db_abs"])
    if db_path.exists():
        try:
            with sqlite3.connect(spec["db_abs"]) as c:
                n_mut = c.execute(
                    "SELECT COUNT(*) FROM mutations"
                ).fetchone()[0]
        except sqlite3.Error:
            n_mut = -1  # corrupt DB or schema mismatch

    return {
        "strategy": spec["strategy_label"],
        "seed": spec["seed"],
        "db": spec["db_rel"],
        "log": spec["log_rel"],
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "elapsed_seconds": round(finished_at - started_at, 2),
        "exit_code": rc,
        "num_mutations_recorded": n_mut,
    }


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run_replicates",
        description=(
            "Run R replicates of the same fuzz campaign across "
            "one or more strategies, with per-seed DBs and a "
            "manifest.json for aggregation."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--host", required=True,
                   help="Path to risc0-host binary.")
    p.add_argument("--num", type=int, default=200,
                   help="Mutations per campaign (default: 200).")
    p.add_argument("--kind", default="all",
                   help="Mutation kind (default: all).")
    p.add_argument("--values", default="mixed",
                   help="Value strategy (default: mixed).")
    p.add_argument("--replicates", type=int, default=3,
                   help="Number of seeds per strategy (default: 3).")
    p.add_argument("--seed-base", type=int, default=1000,
                   help="First seed; subsequent are S0+1..S0+R-1 (default: 1000).")
    p.add_argument("--strategies", nargs="+", default=["uniform"],
                   help=("Strategy labels (default: ['uniform']). "
                         "Use 'bandit-<N>' to override b-count, "
                         "e.g. 'bandit-16'."))
    p.add_argument("--out-dir", default="./replicates_out/",
                   help="Output directory (default: ./replicates_out/).")
    p.add_argument("--parallel", type=int, default=1,
                   help=("Run up to N campaigns concurrently. Default 1 "
                         "(sequential). Capped at os.cpu_count()//2."))
    p.add_argument("host_args", nargs="*",
                   help="Arguments forwarded to risc0-host (after --).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    # Validate strategies up-front (fast fail).
    strategy_specs: List[Tuple[str, str, Optional[int]]] = []
    for label in args.strategies:
        try:
            sel, b_count = _parse_strategy(label)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        strategy_specs.append((label, sel, b_count))

    # Cap --parallel.
    ncpu = os.cpu_count() or 1
    ceiling = max(1, ncpu // 2)
    if args.parallel > ceiling:
        print(f"error: --parallel {args.parallel} exceeds ceiling "
              f"{ceiling} (= os.cpu_count() // 2)", file=sys.stderr)
        return 2
    if args.parallel < 1:
        print(f"error: --parallel must be >= 1, got {args.parallel}",
              file=sys.stderr)
        return 2
    if args.replicates < 1:
        print(f"error: --replicates must be >= 1, got {args.replicates}",
              file=sys.stderr)
        return 2

    if not Path(args.host).is_file():
        print(f"error: host binary not found: {args.host}", file=sys.stderr)
        return 2

    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Build the cartesian product of (strategy, seed_offset).
    specs: List[dict] = []
    for strat_label, selector, b_count in strategy_specs:
        strat_dir = out / strat_label
        strat_dir.mkdir(exist_ok=True)
        for i in range(args.replicates):
            seed = args.seed_base + i
            specs.append({
                "strategy_label": strat_label,
                "selector": selector,
                "b_count": b_count,
                "seed": seed,
                "host": args.host,
                "num": args.num,
                "kind": args.kind,
                "values": args.values,
                "host_args": args.host_args,
                "db_abs": str(strat_dir / f"seed_{seed}.db"),
                "log_abs": str(strat_dir / f"seed_{seed}.log"),
                "db_rel": f"{strat_label}/seed_{seed}.db",
                "log_rel": f"{strat_label}/seed_{seed}.log",
            })

    # Execute.
    completed: List[dict] = []
    if args.parallel <= 1:
        for spec in specs:
            print(f"[run_replicates] starting "
                  f"{spec['strategy_label']} seed={spec['seed']}")
            completed.append(_run_one_campaign(spec))
    else:
        print(f"[run_replicates] running {len(specs)} campaigns with "
              f"{args.parallel}-way parallelism")
        with ProcessPoolExecutor(max_workers=args.parallel) as ex:
            futures = {ex.submit(_run_one_campaign, s): s for s in specs}
            for fut in as_completed(futures):
                completed.append(fut.result())
        completed.sort(key=lambda d: (d["strategy"], d["seed"]))

    # Write manifest.
    manifest = {
        "created_at": _iso(time.time()),
        "host_binary": args.host,
        "host_args": list(args.host_args),
        "num_per_campaign": args.num,
        "values": args.values,
        "kind": args.kind,
        "seed_base": args.seed_base,
        "replicates": args.replicates,
        "strategies": list(args.strategies),
        "campaigns": completed,
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[run_replicates] manifest: {manifest_path}")

    failed = [c for c in completed if c["exit_code"] != 0]
    if failed:
        print(f"[run_replicates] {len(failed)}/{len(completed)} "
              f"campaigns failed:", file=sys.stderr)
        for c in failed:
            print(f"  {c['strategy']}/seed_{c['seed']}: "
                  f"exit={c['exit_code']} "
                  f"recorded={c['num_mutations_recorded']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
