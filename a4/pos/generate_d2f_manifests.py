#!/usr/bin/env python3
"""Generate IV.POS.8 D2.F chain_dispatcher manifests from variants.py.

Emits text manifests (batch|node|run_id|remote_cmd) for:
  - F.1 smoke: 4 variants × 2 seeds, N=100, 1 batch × 8 jobs
  - F.2 production: 4 variants × R seeds, N=10000, 2 batches (8 + 4 jobs)

Launch commands are derived from ``a4.standalone.variants.variant_launch_command``
(single source of truth — no hand-written per-variant commands).

USAGE
=====
  python3 a4/pos/generate_d2f_manifests.py --phase smoke --out a4/pos/manifests/iv_pos_8/d2f_smoke.chain
  python3 a4/pos/generate_d2f_manifests.py --phase production --seeds 1234 1235 1236 \\
      --out a4/pos/manifests/iv_pos_8/d2f_production.chain
"""
from __future__ import annotations

import argparse
import shlex
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from a4.standalone.variants import CANONICAL_VARIANTS, variant_launch_command

# Ivan-reserved D2.F node pool (1 job/node concurrently).
DEFAULT_NODES: Tuple[str, ...] = (
    "flare", "polynize", "octorand", "opulous",
    "algofi", "zone", "gard", "goracle",
)

VARIANT_ORDER: Tuple[str, ...] = tuple(CANONICAL_VARIANTS.keys())

GUEST_ARGS = ["--in1", "5", "--in4", "10"]
WORK = "/root/a4_campaign"
HOST_BIN = f"{WORK}/bin/risc0-host"
REPO_DIR = f"{WORK}/repo"
REMOTE_BASE = "/tmp/chainjob"

SMOKE_N = 100
PRODUCTION_N = 10000
SMOKE_SEEDS: Tuple[int, ...] = (1234, 1235)
DEFAULT_PRODUCTION_SEEDS: Tuple[int, ...] = (1234, 1235, 1236)


def run_id(variant: str, seed: int, n: int) -> str:
    return f"pos_iv_pos_8_d2f_{variant}_seed{seed}_n{n}"


def _db_path(rid: str) -> str:
    return f"{REMOTE_BASE}_{rid}/run.db"


def _env_exports(variant: str) -> str:
    spec = CANONICAL_VARIANTS[variant]
    parts = [
        "A4_COVERAGE_TOUCH=1",
        "A4_FAMILY_RESIDUE=1",
        "CONSTRAINT_CONTINUE=1",
    ]
    if spec.launcher == "cli":
        parts.append("A4_GLOBAL_RESIDUE=1")
    return "export " + " ".join(parts)


def _argv(variant: str, seed: int, n: int, rid: str) -> List[str]:
    argv = variant_launch_command(
        variant,
        host=HOST_BIN,
        db=_db_path(rid),
        seed=seed,
        num=n,
        host_args=GUEST_ARGS,
    )
    spec = CANONICAL_VARIANTS[variant]
    if spec.launcher == "cli":
        # Insert --telemetry-level full before guest `--` separator.
        if "--" in argv:
            idx = argv.index("--")
            argv = argv[:idx] + ["--telemetry-level", "full"] + argv[idx:]
        else:
            argv.extend(["--telemetry-level", "full"])
    if spec.launcher == "driver":
        # v6_uniform_driver: add progress + label for POS traceability.
        if "--progress-every" not in argv:
            insert_at = len(argv)
            if "--" in argv:
                insert_at = argv.index("--")
            argv[insert_at:insert_at] = [
                "--progress-every", str(max(10, min(n, 100))),
                "--label", "d2f",
            ]
    return argv


def remote_cmd(variant: str, seed: int, n: int, rid: str) -> str:
    env = _env_exports(variant)
    argv = _argv(variant, seed, n, rid)
    cmd = " ".join(shlex.quote(a) for a in argv)
    return f"{env}; cd {REPO_DIR} && {cmd}"


def _job_assignments(
    seeds: Sequence[int],
    n: int,
) -> List[Tuple[str, int, str]]:
    """Return (variant, seed, node) assignments — one job per node per batch."""
    jobs: List[Tuple[str, int, str]] = []
    pairs: List[Tuple[str, int]] = []
    for seed in seeds:
        for variant in VARIANT_ORDER:
            pairs.append((variant, seed))
    if len(pairs) > len(DEFAULT_NODES):
        raise ValueError(
            f"too many jobs ({len(pairs)}) for {len(DEFAULT_NODES)} nodes "
            "in a single batch — split seeds across batches in caller"
        )
    for i, (variant, seed) in enumerate(pairs):
        jobs.append((variant, seed, DEFAULT_NODES[i]))
    return jobs


def _batch_jobs(
    seeds: Sequence[int],
    n: int,
    batch_prefix: str,
) -> List[Tuple[str, str, str, str]]:
    """Build (batch_name, node, run_id, remote_cmd) rows for one chain batch."""
    rows: List[Tuple[str, str, str, str]] = []
    for variant, seed, node in _job_assignments(seeds, n):
        rid = run_id(variant, seed, n)
        rows.append((f"{batch_prefix}", node, rid, remote_cmd(variant, seed, n, rid)))
    return rows


def make_smoke_rows() -> List[Tuple[str, str, str, str]]:
    return _batch_jobs(SMOKE_SEEDS, SMOKE_N, "d2f_smoke_b1")


def make_production_rows(seeds: Sequence[int]) -> List[Tuple[str, str, str, str]]:
    if len(seeds) < 2:
        raise ValueError("production needs at least 2 seeds for 2-batch layout")
    batch1_seeds = seeds[:2]
    batch2_seeds = seeds[2:]
    rows = _batch_jobs(batch1_seeds, PRODUCTION_N, "d2f_prod_b1")
    if batch2_seeds:
        rows.extend(_batch_jobs(batch2_seeds, PRODUCTION_N, "d2f_prod_b2"))
    return rows


def format_chain(rows: Iterable[Tuple[str, str, str, str]], *, doc: str) -> str:
    lines = [
        f"# {doc}",
        "# format: batch|node|run_id|remote_cmd",
        "",
    ]
    for batch, node, rid, cmd in rows:
        lines.append(f"{batch}|{node}|{rid}|{cmd}")
    lines.append("")
    return "\n".join(lines)


def write_manifest(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase", choices=("smoke", "production"), required=True,
    )
    parser.add_argument(
        "--seeds", type=int, nargs="+",
        default=list(DEFAULT_PRODUCTION_SEEDS),
        help="production seeds (default: 1234 1235 1236)",
    )
    parser.add_argument(
        "--out", type=Path, required=True,
    )
    args = parser.parse_args()

    if args.phase == "smoke":
        rows = make_smoke_rows()
        doc = (
            f"D2.F F.1 smoke — {len(rows)} jobs, N={SMOKE_N}, "
            f"seeds={list(SMOKE_SEEDS)}"
        )
    else:
        rows = make_production_rows(tuple(args.seeds))
        doc = (
            f"D2.F F.2 production — {len(rows)} jobs, N={PRODUCTION_N}, "
            f"seeds={list(args.seeds)}"
        )

    write_manifest(args.out, format_chain(rows, doc=doc))
    print(f"wrote {args.out} ({len(rows)} jobs)")


if __name__ == "__main__":
    main()
