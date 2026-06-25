#!/usr/bin/env python3
"""IV.POS.9 Track-B — multi-guest sweep manifest generator (guest-aware).

Track-B-OWNED copy of `a4/pos/generate_d2f_manifests.py`, parameterized by GUEST
(per the §1.4 isolation rule — the shared D2.F generator is NOT edited in place;
the stable variant machinery is imported READ-ONLY). Differences vs the D2.F generator:
  - a GUEST_SPECS table (per-guest archived host binary + guest CLI args);
  - run_ids carry the guest slug: `pos_iv_pos_9_b_<guest>_<variant>_seed<seed>_n<n>`;
  - the loop is guests × variants × seeds, laid out 8-jobs/batch over the node pool;
  - every job is PREFIXED with a fingerprint-guard assertion (G11): the deployed binary
    must report the `sweep` profile (load_rs2_present=1, planted_bug=none) — and its
    guest_image_id if known — or the job aborts before launching (a holed/vuln binary
    can never silently run a sweep).

USAGE
  python3 a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py \
      --stage screening --seeds 1234 1235 1236 \
      --out a4/runs/iv_pos_9/sweep/manifests/screening.chain
"""
from __future__ import annotations

import argparse
import shlex
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

# READ-ONLY reuse of the stable shared variant machinery (never edited here).
from a4.standalone.variants import CANONICAL_VARIANTS, variant_launch_command

# Track-B-only node pool for IV.POS.9 screening (1 job/node/batch).
# zone is RESERVED FOR TRACK A (2026-06-24) and must NOT be used here.
# Track-B pool: pact, stoi (Xeon 6421N) + idex, meld, tinyman (Xeon 6312U, Tier C).
# Overridable via --nodes (use only owned-by-ivgreiff + ssh-reachable nodes; the chain
# is resume-safe so a smaller live pool just means more sequential batches, never lost work).
DEFAULT_NODES: Tuple[str, ...] = (
    "pact", "stoi", "idex", "meld", "tinyman",
)
VARIANT_ORDER: Tuple[str, ...] = tuple(CANONICAL_VARIANTS.keys())

WORK = "/root/a4_campaign"
REPO_DIR = f"{WORK}/repo"
REMOTE_BASE = "/tmp/chainjob"
BUILDS_DIR = f"{WORK}/builds/sweep"   # where per-guest read-only binaries are deployed on POS

# Per-guest deploy config. `host_bin` is the deployed sweep binary (read-only archive);
# `guest_args` are the guest CLI inputs; `guest_image_id` is filled AFTER B1.4 builds each
# guest (None = guard checks the sweep profile only — still catches vuln/isread).
GUEST_SPECS: Dict[str, Dict[str, object]] = {
    "g0_baseline": {
        "host_bin": f"{BUILDS_DIR}/28e53771_clean__g0_baseline/risc0-host",
        "guest_args": ["--in1", "5", "--in4", "10"],
        # known from the B1.1 build:
        "guest_image_id": "1452377150,355336093,1150425782,11922678,2102388000,4182981023,1891758213,1686536209",
    },
    "g1_ecall_control": {
        "host_bin": f"{BUILDS_DIR}/28e53771_clean__g1_ecall_control/risc0-host",
        "guest_args": ["--ctrl", "2863311530", "--gseed", "305419896", "--rounds", "55"],
        "guest_image_id": "1065889426,3372648979,917961822,142713301,1412562154,4260020781,3324273047,4286975246",
    },
    "g2_mem_stress": {
        "host_bin": f"{BUILDS_DIR}/28e53771_clean__g2_mem_stress/risc0-host",
        "guest_args": ["--gseed", "305419896", "--mask", "2779096485", "--rounds", "130"],
        "guest_image_id": "3043401936,1185355993,4029295040,252990520,457335726,3670169622,1695560176,3569472882",
    },
    "g3_accelerator": {
        "host_bin": f"{BUILDS_DIR}/28e53771_clean__g3_accelerator/risc0-host",
        "guest_args": ["--gseed", "305419896", "--modulus", "4294967291", "--rounds", "4"],
        "guest_image_id": "2463764742,2929831918,4011611460,3491061469,2362472272,351733895,504567371,3980335897",
    },
}

STAGE_N = {"screening": 5000, "thesis": 10000}
DEFAULT_SEEDS: Tuple[int, ...] = (1234, 1235, 1236)


def run_id(guest: str, variant: str, seed: int, n: int) -> str:
    return f"pos_iv_pos_9_b_{guest}_{variant}_seed{seed}_n{n}"


def _db_path(rid: str) -> str:
    return f"{REMOTE_BASE}_{rid}/run.db"


def _env_exports(variant: str) -> str:
    spec = CANONICAL_VARIANTS[variant]
    parts = ["A4_COVERAGE_TOUCH=1", "A4_FAMILY_RESIDUE=1", "CONSTRAINT_CONTINUE=1"]
    if spec.launcher == "cli":
        parts.append("A4_GLOBAL_RESIDUE=1")
    return "export " + " ".join(parts)


def _guard_prefix(guest: str) -> str:
    """Fingerprint-guard assertion (G11): abort the job unless the binary is a clean sweep build."""
    g = GUEST_SPECS[guest]
    parts = ["python3", "-m", "a4.pos.fingerprint_guard", str(g["host_bin"]), "--profile", "sweep"]
    if g.get("guest_image_id"):
        parts += ["--guest-id", str(g["guest_image_id"])]
    return " ".join(shlex.quote(p) for p in parts)


def _argv(guest: str, variant: str, seed: int, n: int, rid: str) -> List[str]:
    g = GUEST_SPECS[guest]
    argv = variant_launch_command(
        variant, host=str(g["host_bin"]), db=_db_path(rid),
        seed=seed, num=n, host_args=list(g["guest_args"]),
    )
    spec = CANONICAL_VARIANTS[variant]
    if spec.launcher == "cli":
        if "--" in argv:
            idx = argv.index("--"); argv = argv[:idx] + ["--telemetry-level", "full"] + argv[idx:]
        else:
            argv += ["--telemetry-level", "full"]
    if spec.launcher == "driver":
        if "--progress-every" not in argv:
            insert_at = argv.index("--") if "--" in argv else len(argv)
            argv[insert_at:insert_at] = ["--progress-every", str(max(10, min(n, 100))), "--label", "iv_pos_9_b"]
    return argv


def remote_cmd(guest: str, variant: str, seed: int, n: int, rid: str) -> str:
    guard = _guard_prefix(guest)            # G11: assert binary BEFORE launching (abort on mismatch)
    g = GUEST_SPECS[guest]
    dbdir = f"{REMOTE_BASE}_{rid}"
    # AUDIT (B1.1c): record the deployed binary's fingerprint next to the run DB, every run.
    emit = (f"python3 -m a4.pos.fingerprint_guard {shlex.quote(str(g['host_bin']))} "
            f"--emit-json > {shlex.quote(dbdir + '/build_fingerprint.json')}")
    env = _env_exports(variant)
    cmd = " ".join(shlex.quote(a) for a in _argv(guest, variant, seed, n, rid))
    return f"cd {REPO_DIR} && mkdir -p {shlex.quote(dbdir)} && {guard} && {emit} && {env}; {cmd}"


def make_rows(guests: Sequence[str], seeds: Sequence[int], n: int,
              nodes: Sequence[str] = DEFAULT_NODES,
              variants: Sequence[str] = VARIANT_ORDER) -> List[Tuple[str, str, str, str]]:
    """One-job-per-node-per-batch layout over the live node pool, across guests × variants × seeds.

    `nodes` is the live, owned-by-ivgreiff + ssh-reachable subset at dispatch time. run_ids
    are node-independent (guest_variant_seed_n), so regenerating with a larger pool and resuming
    just re-packs the not-yet-.OK jobs onto the wider set — completed jobs are skipped.
    """
    rows: List[Tuple[str, str, str, str]] = []
    flat: List[Tuple[str, str, int]] = []
    for seed in seeds:
        for guest in guests:
            for variant in variants:
                flat.append((guest, variant, seed))
    per_batch = len(nodes)
    for bi in range(0, len(flat), per_batch):
        batch = flat[bi:bi + per_batch]
        bname = f"sweep_b{bi // per_batch + 1}"
        for j, (guest, variant, seed) in enumerate(batch):
            rid = run_id(guest, variant, seed, n)
            rows.append((bname, nodes[j], rid, remote_cmd(guest, variant, seed, n, rid)))
    return rows


def format_chain(rows: Iterable[Tuple[str, str, str, str]], *, doc: str) -> str:
    lines = [f"# {doc}", "# format: batch|node|run_id|remote_cmd", ""]
    for batch, node, rid, cmd in rows:
        lines.append(f"{batch}|{node}|{rid}|{cmd}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=sorted(STAGE_N), required=True)
    p.add_argument("--guests", nargs="+", default=list(GUEST_SPECS.keys()),
                   help="guest slugs (default: all 4)")
    p.add_argument("--seeds", type=int, nargs="+", default=list(DEFAULT_SEEDS))
    p.add_argument("--nodes", nargs="+", default=list(DEFAULT_NODES),
                   help="live node pool (owned-by-ivgreiff + ssh-reachable). Default: the 6 reserved.")
    p.add_argument("--variants", nargs="+", default=list(VARIANT_ORDER),
                   help="subset of variants (e.g. re-run only V5_control Hybrid_cTS). Default: all 4.")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    for v in args.variants:
        if v not in VARIANT_ORDER:
            p.error(f"unknown variant {v!r}; known: {list(VARIANT_ORDER)}")

    for g in args.guests:
        if g not in GUEST_SPECS:
            p.error(f"unknown guest {g!r}; known: {sorted(GUEST_SPECS)}")
    if not args.nodes:
        p.error("--nodes must list at least one live node")
    n = STAGE_N[args.stage]
    rows = make_rows(args.guests, tuple(args.seeds), n, tuple(args.nodes), tuple(args.variants))
    doc = (f"IV.POS.9 Track-B {args.stage} sweep — {len(rows)} jobs, N={n}, "
           f"guests={list(args.guests)}, variants={list(args.variants)}, seeds={list(args.seeds)}, "
           f"nodes={list(args.nodes)}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(format_chain(rows, doc=doc))
    print(f"wrote {args.out} ({len(rows)} jobs across {len(set(r[0] for r in rows))} batches)")


if __name__ == "__main__":
    main()
