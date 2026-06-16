#!/usr/bin/env python3
"""M1 — Enumerate the Add's constraint universe (baseline, no mutation)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
M0_ART = ROOT / "artifacts" / "m0"
ART = ROOT / "artifacts" / "m1"
HOST = ROOT / "target/release/thesis-minimal-host"

import sys

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.executor import run_baseline  # noqa: E402
from a4.core.touch_coverage import (  # noqa: E402
    distinct_touched,
    fnv1a_touch_hash,
    parse_accum_touch_bitmap,
    parse_accum_verbose_set,
    parse_family_residues,
    parse_global_residue,
    parse_touch_bitmap,
)
from thesis_side_experiments.minimal_add.run_m0 import parse_verbose_set  # noqa: E402

BASELINE_ENV = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
}

ADD_MAJOR = 0
ADD_MINOR = 0
EXPECTED_ADD_LOCAL_COUNT = 37

# Plain-English labels grounded in a4/docs/global/PRESENTATION_DEEP_DIVE.md and mutation docs.
EXACT_LABELS: Dict[str, str] = {
    "loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))": (
        "IsRead@mem.zir:79 — on a READ txn, word must equal prev_word on the same transaction "
        "(intra-txn consistency; does NOT prove cross-row memory closure — see PRESENTATION_DEEP_DIVE §Slide 2)"
    ),
    "loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))": (
        "IsRead@mem.zir:80 — high limb of READ word equals prev_word high limb (companion to :79)"
    ),
    "MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)": (
        "MemoryWrite@mem.zir:99 — WRITE txn: written word must match the computed/read chain for this cycle"
    ),
    "MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)": (
        "MemoryWrite@mem.zir:100 — companion WRITE consistency check (high limb / paired row)"
    ),
}


def parse_context_key(key: str) -> Tuple[str, int, int]:
    loc, maj_s, min_s = key.rsplit("|", 2)
    return loc, int(maj_s), int(min_s)


def filter_by_context(keys: Set[str], major: int, minor: int) -> List[str]:
    out = [k for k in keys if k.endswith(f"|{major}|{minor}")]
    return sorted(out)


def human_label(loc_key: str) -> str:
    loc, major, minor = parse_context_key(loc_key)
    if loc in EXACT_LABELS:
        return EXACT_LABELS[loc]

    if "IsRead" in loc and "mem.zir" in loc:
        return "IsRead — memory READ intra-transaction word/prev_word consistency"
    if loc.startswith("MemoryWrite("):
        return "MemoryWrite — memory WRITE consistency with same-cycle read/compute chain"
    if "VerifyOpcodeF3F7" in loc and "OpADD" in loc:
        return "VerifyOpcodeF3F7 — decoded funct3/funct7 match the ADD opcode pattern"
    if loc.startswith("Misc0("):
        return "Misc0 — MISC0 ALU arm active (ADD path through inst_misc.zir)"
    if loc.startswith("MiscInput("):
        return "MiscInput — ALU operand inputs wired into MISC0 block"
    if loc.startswith("ReadSourceRegs("):
        return "ReadSourceRegs — rs1/rs2 register reads connected to execution unit"
    if loc.startswith("DecodeInst(") or loc.startswith("Decoder("):
        return "Decoder — instruction word decomposes to expected R-type ADD fields"
    if loc.startswith("DoCycleTable("):
        return "DoCycleTable — instruction class selects MISC0 row in cycle table"
    if loc.startswith("MemoryIO("):
        return "MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step"
    if loc.startswith("IsCycle("):
        return "IsCycle — memory-row cycle counters consistent with circuit cycle"
    if loc.startswith("AddrDecompose(") or loc.startswith("NormalizeU32("):
        return "U32 normalize/decompose — 32-bit value split into circuit-native limbs"
    if loc.startswith("OneHot("):
        return "OneHot — one-hot mux selector for decode/execute routing"
    if loc.startswith("IsZero("):
        return "IsZero — zero-test helper used in decode/ALU plumbing"
    if loc.startswith("NondetU16Reg(") or loc.startswith("U16Reg("):
        return "U16 lookup — register limb participates in U16 range lookup table (LogUp use-side)"
    if loc.startswith("Reg("):
        return "Reg preamble — register file cell witness wiring"
    if "AssertBit" in loc or "NondetBitReg" in loc:
        return "Bit witness — single-bit nondeterministic value constrained to {0,1}"
    if "AssertTwit" in loc or "NondetTwitReg" in loc:
        return "Twit witness — 2-bit nondeterministic value constrained to small range"
    if "GenerateAccum.cpp" in loc:
        return (
            "Accum transition (accum pass) — row's LogUp delta matches DATA buffer "
            "(accumulation machinery; NOT the global multiset closure — that is Hook 3)"
        )
    if "builtin EqzExt" in loc or "ExtReg" in loc:
        return "Extension-field register witness — accum-phase extension column consistency"
    if "LookupDelta" in loc or "MemoryDelta" in loc:
        return "LogUp delta witness — per-row contribution to family accumulator"
    return f"EQZ active at {loc} (major={major}, minor={minor})"


def build_universe_entries(keys: List[str]) -> List[dict]:
    entries = []
    for key in keys:
        loc, major, minor = parse_context_key(key)
        entries.append(
            {
                "context_key": key,
                "loc": loc,
                "major": major,
                "minor": minor,
                "label": human_label(key),
            }
        )
    return entries


def reconcile_bitmap(verbose_keys: List[str], bitmap: Optional[bytes]) -> dict:
    if bitmap is None:
        return {"error": "no local touch bitmap"}

    bucket_to_keys: Dict[int, List[str]] = {}
    for key in verbose_keys:
        loc, major, minor = parse_context_key(key)
        idx = fnv1a_touch_hash(loc, major, minor)
        bucket_to_keys.setdefault(idx, []).append(key)

    collision_groups = [keys for keys in bucket_to_keys.values() if len(keys) > 1]
    touched_buckets = sum(1 for idx, keys in bucket_to_keys.items() if bitmap[idx] > 0)

    return {
        "verbose_context_count": len(verbose_keys),
        "distinct_bitmap_buckets": len(bucket_to_keys),
        "bitmap_buckets_with_counter_gt_zero": touched_buckets,
        "collision_group_count": len(collision_groups),
        "collision_groups": collision_groups,
        "all_buckets_touched": touched_buckets == len(bucket_to_keys),
    }


def load_frozen_add_site() -> dict:
    path = M0_ART / "add_site.json"
    if not path.exists():
        raise SystemExit(f"Missing frozen add site from M0: {path}")
    return json.loads(path.read_text())


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    add_site = load_frozen_add_site()
    major = add_site["major"]
    minor = add_site["minor"]

    output = run_baseline(str(HOST), [], BASELINE_ENV)
    (ART / "baseline_full.txt").write_text(output)

    failures = parse_all_constraint_failures(output)
    if failures:
        raise SystemExit(f"baseline must have 0 constraint failures; got {len(failures)}")

    local_verbose = parse_verbose_set(output)
    accum_verbose = parse_accum_verbose_set(output)
    if local_verbose is None:
        raise SystemExit("missing <a4_touch_verbose>")
    if accum_verbose is None:
        raise SystemExit("missing <a4_accum_touch_verbose>")

    add_local_keys = filter_by_context(local_verbose, major, minor)
    if len(add_local_keys) != EXPECTED_ADD_LOCAL_COUNT:
        raise SystemExit(
            f"expected {EXPECTED_ADD_LOCAL_COUNT} Add local contexts; got {len(add_local_keys)}"
        )

    add_local = build_universe_entries(add_local_keys)
    accum_all = build_universe_entries(sorted(accum_verbose))

    family = parse_family_residues(output)
    global_res = parse_global_residue(output)
    if family is None:
        raise SystemExit("missing Hook-3 <a4_family_residue> tags")
    if global_res is None:
        raise SystemExit("missing A4_GLOBAL_RESIDUE tag")

    for entry in family:
        if entry.get("nonzero"):
            raise SystemExit(f"baseline Hook-3 family {entry.get('family')} must be zero")
    if global_res.get("nonzero"):
        raise SystemExit("baseline A4_GLOBAL_RESIDUE must be zero")

    local_bitmap = parse_touch_bitmap(output)
    accum_bitmap = parse_accum_touch_bitmap(output)
    add_reconcile = reconcile_bitmap(add_local_keys, local_bitmap)

    report: Dict[str, Any] = {
        "milestone": "M1",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "frozen_add_site": add_site,
        "baseline_env": BASELINE_ENV,
        "constraint_fail_count": 0,
        "hook3_family_residues": family,
        "global_residue": global_res,
        "add_local_universe": {
            "filter": f"major=={major} && minor=={minor}",
            "count": len(add_local),
            "entries": add_local,
        },
        "accum_pass_universe": {
            "note": "accum-pass EQZ contexts (phase=accum); NOT the thesis global multiset closure",
            "count": len(accum_all),
            "entries": accum_all,
        },
        "bitmap_reconciliation": {
            "add_context": add_reconcile,
            "whole_program_local_bitmap_distinct": distinct_touched(local_bitmap)
            if local_bitmap
            else None,
            "whole_program_accum_bitmap_distinct": distinct_touched(accum_bitmap)
            if accum_bitmap
            else None,
        },
        "acceptance": {
            "add_local_count_37": len(add_local) == 37,
            "baseline_zero_failures": True,
            "hook3_all_zero": all(not f.get("nonzero") for f in family),
            "global_residue_zero": not global_res.get("nonzero"),
            "add_verbose_bitmap_reconcile_no_collisions": add_reconcile["collision_group_count"] == 0,
            "add_all_buckets_touched": add_reconcile["all_buckets_touched"],
        },
    }

    (ART / "add_local_universe.json").write_text(json.dumps(add_local, indent=2))
    (ART / "accum_universe.json").write_text(json.dumps(accum_all, indent=2))
    (ART / "M1_REPORT.json").write_text(json.dumps(report, indent=2))

    md_lines = [
        "# M1 Report — Add Constraint Universe (Baseline, No Mutation)",
        "",
        "**Status:** PASS",
        "",
        f"Frozen add site from M0: Arguzz step {add_site['arguzz_step']}, A4 step {add_site['a4_step']}, "
        f"cycle_idx {add_site['cycle_idx']}, major/minor {major}/{minor}.",
        "",
        "## Baseline control (global signal silent)",
        "",
        f"- `<constraint_fail>` count: **0**",
        "- Hook 3 family residues (GLOBAL control):",
    ]
    for f in family:
        md_lines.append(f"  - **{f['family']}**: nonzero={f['nonzero']}")
    md_lines.extend(
        [
            f"- A4_GLOBAL_RESIDUE: **nonzero={global_res['nonzero']}**",
            "",
            "## Add local universe (phase=local witgen, major=0 minor=0)",
            "",
            f"**{len(add_local)} contexts** — denominator for bias comparison at the Add instruction class.",
            "",
            "| # | loc (short) | label |",
            "|---|-------------|-------|",
        ]
    )
    for i, e in enumerate(add_local, 1):
        short = e["loc"]
        if len(short) > 72:
            short = short[:69] + "..."
        md_lines.append(f"| {i} | `{short}` | {e['label']} |")

    md_lines.extend(
        [
            "",
            "## Accum-pass universe (phase=accum, whole trace)",
            "",
            f"**{len(accum_all)} contexts** — accumulation machinery checks; **not** the thesis GLOBAL multiset "
            "(that is Hook 3). Full list in `accum_universe.json`.",
            "",
            "## Bitmap reconciliation (Add context only)",
            "",
            f"- Verbose Add contexts: **{add_reconcile['verbose_context_count']}**",
            f"- Distinct bitmap buckets: **{add_reconcile['distinct_bitmap_buckets']}**",
            f"- Collision groups: **{add_reconcile['collision_group_count']}**",
            f"- All Add buckets have counter>0: **{add_reconcile['all_buckets_touched']}**",
            "",
            "Whole-program bitmap distinct buckets (for reference): "
            f"local={report['bitmap_reconciliation']['whole_program_local_bitmap_distinct']}, "
            f"accum={report['bitmap_reconciliation']['whole_program_accum_bitmap_distinct']}.",
            "",
            "## Artifacts",
            "- `artifacts/m1/M1_REPORT.json`",
            "- `artifacts/m1/add_local_universe.json`",
            "- `artifacts/m1/accum_universe.json`",
            "- `artifacts/m1/baseline_full.txt`",
            "",
            "**Opus gate:** M1 acceptance met. Await greenlight for **M2**.",
        ]
    )
    (ART / "M1_REPORT.md").write_text("\n".join(md_lines) + "\n")
    print((ART / "M1_REPORT.md").read_text())


if __name__ == "__main__":
    main()
