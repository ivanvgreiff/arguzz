#!/usr/bin/env python3
"""Enumerate E5 sample set: N per type-variant, spread across applicable sites."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
CONTEXT = ROOT / "artifacts" / "e5" / "context"
SITES_PATH = CONTEXT / "sites.json"
OUT = ROOT / "artifacts" / "e5" / "sample_set.json"
CONFIG_DIR = ROOT / "artifacts" / "e5" / "configs"

REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO))

from a4.core.inspection_data import InspectionData  # noqa: E402
from thesis_side_experiments.full_sweep.a4_config_ext import build_a4_sample_config  # noqa: E402

HOST = ROOT / "frozen_host" / "thesis-full-sweep-host.e0frozen"

ARGUZZ_TYPES = [
    ("COMP_OUT_MOD", "compute", None),
    ("LOAD_VAL_MOD", "load", None),
    ("STORE_OUT_MOD", "store", None),
    ("INSTR_WORD_MOD", "compute", None),
    ("BR_NEG_COND", "branch", None),
    ("PRE_EXEC_PC_MOD", "any", None),
    ("POST_EXEC_PC_MOD", "any", None),
    ("PRE_EXEC_MEM_MOD", "any", None),
    ("POST_EXEC_MEM_MOD", "any", None),
    ("PRE_EXEC_REG_MOD", "any", None),
    ("POST_EXEC_REG_MOD", "any", None),
]

A4_TYPES = [
    ("COMP_OUT_MOD", "compute", None),
    ("LOAD_VAL_MOD", "load", None),
    ("STORE_OUT_MOD", "store", None),
    ("INSTR_WORD_MOD_FULL", "compute", None),
    ("INSTR_WORD_MOD_SUR", "compute", "funct3_xor"),
    ("MEM_VAL_MOD", "load", None),
    ("PRE_EXEC_REG_MOD", "any", "next_read"),
    ("PRE_EXEC_REG_MOD", "any", "prev_write"),
    ("INSTR_TYPE_MOD", "compute", None),
]

SUR_ROTATE = ["funct3_xor", "funct3_slt", "funct7_sub", "rd", "rs1", "rs2"]


def spread_sites(sites: List[dict], n: int) -> List[tuple[dict, int]]:
    if not sites:
        return []
    out: List[tuple[dict, int]] = []
    per = max(1, (n + len(sites) - 1) // len(sites))
    seed = 0
    for site in sites:
        for _ in range(per):
            if len(out) >= n:
                break
            out.append((site, seed))
            seed += 1
        if len(out) >= n:
            break
    while len(out) < n:
        out.append((sites[len(out) % len(sites)], seed))
        seed += 1
    return out[:n]


def make_sample_id(fuzzer: str, mtype: str, variant: Optional[str], idx: int) -> str:
    v = variant or "default"
    return f"{fuzzer}__{mtype}__{v}__s{idx:04d}"


def bake_a4_configs(samples: List[dict], data: InspectionData) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    for s in samples:
        if s["fuzzer"] != "a4":
            continue
        cfg_path = CONFIG_DIR / f"{s['sample_id']}.json"
        built = build_a4_sample_config(
            s["mutation_type"],
            s.get("variant"),
            s["site"]["step"],
            data,
            cfg_path,
            s["seed"],
        )
        if built is None:
            s["bake_error"] = "build_a4_sample_config returned None"
        else:
            s["a4_config_path"] = str(cfg_path.relative_to(ROOT))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20, help="samples per type-variant")
    ap.add_argument("--bake-a4", action="store_true", help="pre-bake A4 configs")
    args = ap.parse_args()

    if not SITES_PATH.exists():
        raise SystemExit(f"missing {SITES_PATH} — run run_e5_e0.py first")

    sites = json.loads(SITES_PATH.read_text())
    samples: List[dict] = []
    idx = 0

    for mtype, pool, variant in ARGUZZ_TYPES:
        pool_sites = sites.get(pool, [])
        if mtype == "INSTR_WORD_MOD":
            pool_sites = sites.get("compute", []) + sites.get("load", [])[:2]
        for site, seed in spread_sites(pool_sites, args.n):
            sid = make_sample_id("arguzz", mtype, variant, idx)
            samples.append(
                {
                    "sample_id": sid,
                    "fuzzer": "arguzz",
                    "mutation_type": mtype,
                    "variant": variant,
                    "seed": seed,
                    "site": site,
                    "inject_step": site["step"],
                    "target_kind": "reg"
                    if "REG" in mtype
                    else "pc"
                    if "PC" in mtype
                    else "mem"
                    if "MEM" in mtype
                    else "value",
                }
            )
            idx += 1

    sur_i = 0
    for mtype, pool, variant in A4_TYPES:
        pool_sites = sites.get(pool, [])
        if mtype == "MEM_VAL_MOD":
            pool_sites = sites.get("load", [])[:3]
        if mtype == "INSTR_WORD_MOD_SUR":
            variant = SUR_ROTATE[sur_i % len(SUR_ROTATE)]
            sur_i += 1
        for site, seed in spread_sites(pool_sites, args.n):
            sid = make_sample_id("a4", mtype, variant, idx)
            samples.append(
                {
                    "sample_id": sid,
                    "fuzzer": "a4",
                    "mutation_type": mtype,
                    "variant": variant,
                    "seed": seed,
                    "site": site,
                    "inject_step": site["step"],
                }
            )
            idx += 1

    if args.bake_a4:
        data = InspectionData.from_inspection(str(HOST), [])
        bake_a4_configs(samples, data)

    out = {
        "n_per_type": args.n,
        "type_variant_count": len(ARGUZZ_TYPES) + len(A4_TYPES),
        "sample_count": len(samples),
        "expected_runs_with_det": int(len(samples) * 1.1),
        "samples": samples,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2))
    print(f"wrote {OUT}: {len(samples)} samples ({len(ARGUZZ_TYPES)+len(A4_TYPES)} type-variants × N={args.n})")


if __name__ == "__main__":
    main()
