#!/usr/bin/env python3
"""Generate the Seam-B A4-findable-bug RACE chain manifest (IV_POS_9_A3_SEAMB_RACE_SPEC).

Clone of generate_d2f_manifests.py with three race-specific changes:
  1. **guard prefix** on every job: `fingerprint_guard --profile verifyopcode
     --head-sha .. --guest-id ..` MUST exit 0 before the campaign runs (G-FP, L14) —
     the on-POS contamination guardrail. A wrong/clean/sweep binary aborts the job.
  2. race guest args (the Seam-B minimal ALU guest) + race run-id namespace.
  3. host stays /root/a4_campaign/bin/risc0-host — the BUNDLE ships the holed binary
     there (G-BUNDLE asserts its sha); the guard prefix proves it on the node.

No stop-on-first-bug (the campaign runs the full N; the oracle/markers run post-hoc).
"""
from __future__ import annotations

import argparse
import shlex
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from a4.standalone.variants import CANONICAL_VARIANTS, variant_launch_command

VARIANT_ORDER: Tuple[str, ...] = tuple(CANONICAL_VARIANTS.keys())

# Seam-B guest (minimal ALU). 8-node EPYC pool (matches D2.F DEFAULT_NODES).
GUEST_ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]
WORK = "/root/a4_campaign"
HOST_BIN = f"{WORK}/bin/risc0-host"   # bundle ships the HOLED binary here
REPO_DIR = f"{WORK}/repo"
REMOTE_BASE = "/tmp/chainjob"
# Node names are NOT hardcoded — the operator passes the REAL reserved nodes via --nodes
# (e.g. the fast pool: flare/octorand/opulous/polynize [Tier-S EPYC 9354] +
# algofi/gard/goracle/zone [Tier-A EPYC 7543]). The user assigns which of these go to
# Track A vs the concurrent Track-B (sweep) OCP.

# Provenance to assert on every node (the holed binary's fingerprint).
EXPECT_HEAD_SHA = "93bda33b4f95f29acc9ddce1e225cdf949c83874"
EXPECT_GUEST_ID = "1145334646,2159102285,1953889312,304928682,3764427408,3452386835,1931880701,971553701"
GUARD_PROFILE = "verifyopcode"


def run_id(variant: str, seed: int, n: int) -> str:
    return f"pos_iv_pos_9_a3seamb_{variant}_seed{seed}_n{n}"


def _db_path(rid: str) -> str:
    return f"{REMOTE_BASE}_{rid}/run.db"


def _guard_prefix() -> str:
    """The blocking contamination guard (G-FP). Nonzero guard exit => abort job (rc 87)."""
    return (
        f"python3 -m a4.pos.fingerprint_guard {shlex.quote(HOST_BIN)} "
        f"--profile {GUARD_PROFILE} --head-sha {EXPECT_HEAD_SHA} "
        f"--guest-id {shlex.quote(EXPECT_GUEST_ID)} "
        f"|| {{ echo '[race] FINGERPRINT GUARD FAILED — aborting job'; exit 87; }}"
    )


def _env_exports(variant: str) -> str:
    spec = CANONICAL_VARIANTS[variant]
    parts = ["A4_COVERAGE_TOUCH=1", "A4_FAMILY_RESIDUE=1", "CONSTRAINT_CONTINUE=1"]
    if spec.launcher == "cli":
        parts.append("A4_GLOBAL_RESIDUE=1")
    return "export " + " ".join(parts)


def _argv(variant: str, seed: int, n: int, rid: str) -> List[str]:
    argv = variant_launch_command(
        variant, host=HOST_BIN, db=_db_path(rid), seed=seed, num=n, host_args=GUEST_ARGS,
    )
    spec = CANONICAL_VARIANTS[variant]
    if spec.launcher == "cli":
        if "--" in argv:
            idx = argv.index("--")
            argv = argv[:idx] + ["--telemetry-level", "full"] + argv[idx:]
        else:
            argv.extend(["--telemetry-level", "full"])
    if spec.launcher == "driver":
        insert_at = argv.index("--") if "--" in argv else len(argv)
        argv[insert_at:insert_at] = ["--progress-every", str(max(10, min(n, 100))), "--label", "a3seamb"]
    return argv


def remote_cmd(variant: str, seed: int, n: int, rid: str) -> str:
    guard = _guard_prefix()
    env = _env_exports(variant)
    cmd = " ".join(shlex.quote(a) for a in _argv(variant, seed, n, rid))
    return f"{guard}; {env}; cd {REPO_DIR} && {cmd}"


def batch_rows(seeds: Sequence[int], n: int, batch_prefix: str,
               nodes: Sequence[str]) -> List[Tuple[str, str, str, str]]:
    """(batch, node, run_id, remote_cmd) rows; one job per node per batch (round-robin
    over the REAL reserved nodes the operator passes — never hardcoded placeholders)."""
    if not nodes:
        raise ValueError("nodes required — pass the actual reserved node names")
    pairs = [(v, s) for s in seeds for v in VARIANT_ORDER]
    rows: List[Tuple[str, str, str, str]] = []
    for i, (variant, seed) in enumerate(pairs):
        node = nodes[i % len(nodes)]
        batch = f"{batch_prefix}_b{i // len(nodes) + 1}"
        rid = run_id(variant, seed, n)
        rows.append((batch, node, rid, remote_cmd(variant, seed, n, rid)))
    return rows


def format_chain(rows: Iterable[Tuple[str, str, str, str]], *, doc: str) -> str:
    lines = [f"# {doc}", "# format: batch|node|run_id|remote_cmd"]
    lines += ["|".join(r) for r in rows]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=["smoke", "thesis"], required=True)
    p.add_argument("--nodes", nargs="+", required=True, help="REAL reserved node names (e.g. flare zone goracle ...)")
    p.add_argument("--seeds", type=int, nargs="+", default=None)
    p.add_argument("--n", type=int, default=None, help="mutations per job (S2 N is data-driven; pass explicitly)")
    p.add_argument("--out", default=None)
    a = p.parse_args()
    if a.stage == "smoke":
        seeds = a.seeds or [1234, 1235, 1236]
        n = a.n or 2000
        prefix = "a3seamb_smoke"
    else:
        seeds = a.seeds or list(range(1234, 1244))  # 10 paired seeds
        n = a.n or 5000  # CAP; real S2 N is set data-driven from S1 (spec §5)
        prefix = "a3seamb_thesis"
    rows = batch_rows(seeds, n, prefix, a.nodes)
    chain = format_chain(rows, doc=f"IV.POS.9 A3 Seam-B race ({a.stage}): {len(rows)} jobs, N={n}, nodes={','.join(a.nodes)}, guard=verifyopcode")
    if a.out:
        Path(a.out).write_text(chain)
        print(f"wrote {len(rows)} jobs -> {a.out}")
    else:
        print(chain)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
