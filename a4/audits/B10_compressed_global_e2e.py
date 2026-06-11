"""B10 — Compressed-global pipeline end-to-end."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, INC2_SMOKE_SEED, OUTPUT_DIR, DEFAULT_HOST, run_fuzz_smoke,
)
from a4.standalone.compressed_global_extractor import (
    address_region,
    extract_compressed_global_contexts,
)

ROUND_TRIP_CASES = [
    (0xFFFF0080, "user_regs"),
    (0x42000020, "user"),          # D8: host_io band; work-order alias host_ecall
    (0xC0000004, "kernel"),
    (0x00203F7C, "user"),          # D8: user code band; work-order alias user_code
]

KNOWN_PLATFORM_ADDRS = [
    (0x00000000, 0x0C000000),
    (0x42000000, 0x42000100),
    (0xC0000000, 0xFFFFFFFF),
]


def _in_known_platform(addr: int) -> bool:
    for lo, hi in KNOWN_PLATFORM_ADDRS:
        if lo <= addr < hi:
            return True
    return False


def _round_trip_tests() -> Dict[str, Any]:
    results = []
    all_ok = True
    for addr, expected_region in ROUND_TRIP_CASES:
        actual = address_region(addr)
        ok = actual == expected_region
        results.append({
            "addr": f"0x{addr:08x}",
            "expected_region": expected_region,
            "actual_region": actual,
            "pass": ok,
        })
        all_ok = all_ok and ok

    # Synthetic Hook3 → extractor
    hook_residues = [{"family": "memory", "nonzero": True}]
    hook_details = [{"family": "memory", "broken_addrs": [0xFFFF0080, 0x00203F7C]}]
    ctxs = extract_compressed_global_contexts(
        hook_residues, hook_details,
        "MEM_VAL_MOD", "core_arithmetic", 0,
    )
    synth_ok = len(ctxs) >= 1
    regions = {c.address_region for c in ctxs if hasattr(c, "address_region")}
    synth_ok = synth_ok and "user_regs" in regions
    return {
        "address_region_cases": results,
        "synthetic_extractor": {"pass": synth_ok, "regions": sorted(regions)},
        "pass": all_ok and synth_ok,
    }


def _db_check(db_path: str) -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ctx_key, family, ctx_json FROM compressed_global_coverage"
    ).fetchall()
    conn.close()

    with_region = 0
    regions: set = set()
    unknown_in_known = []
    for r in rows:
        try:
            ctx = json.loads(r["ctx_json"])
        except json.JSONDecodeError:
            continue
        reg = ctx.get("address_region")
        if reg and reg not in ("unknown", "invalid"):
            with_region += 1
            regions.add(reg)
        for addr_field in ("broken_addrs",):
            pass
        # Check no 'unknown' for memory contexts in known platform ranges
        if reg == "unknown" and r["family"] == "memory":
            unknown_in_known.append(r["ctx_key"])

    return {
        "n_rows": len(rows),
        "n_with_address_region": with_region,
        "distinct_regions": sorted(regions),
        "unknown_violations": unknown_in_known,
        "pass": with_region >= 1 and len(regions) >= 2 and not unknown_in_known,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--db", default=None, help="Reuse B6 V5 smoke DB")
    args = p.parse_args()
    OUTPUT_DIR.mkdir(exist_ok=True)

    rt = _round_trip_tests()

    with tempfile.TemporaryDirectory(prefix="b10_") as tmp:
        db_path = args.db or str(Path(tmp) / "b10_v5.db")
        if args.db is None:
            rc = run_fuzz_smoke(
                selector="cTS_semantic_v2", db_path=db_path, num=20, host=args.host,
            )
            if rc not in (0, 2):
                print(f"B10 smoke failed exit={rc}")
                return 1
        db_check = _db_check(db_path)

    all_pass = rt["pass"] and db_check["pass"]
    out = {
        "_meta": GLOSSARY_META,
        "seed": INC2_SMOKE_SEED,
        "check1_db": db_check,
        "check2_round_trip": rt,
        "verdict": "PASS" if all_pass else "FAIL",
    }
    out_path = OUTPUT_DIR / "B10_compressed_global_e2e.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"=== B10 RESULT: {out['verdict']} ===")
    print(f"  Wrote {out_path}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
