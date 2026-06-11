#!/usr/bin/env python3
"""Merge per-variant B1 POS shard JSONs into B1_hook_fidelity.json."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import B1_N_PER_VARIANT, GLOSSARY_META, INC2_SMOKE_SEED, INC2_VARIANTS, OUTPUT_DIR


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard-dir", required=True, help="Dir with B1_V*.json shards")
    parser.add_argument("--output", default=str(OUTPUT_DIR / "B1_hook_fidelity.json"))
    parser.add_argument("--prevalidate", help="Optional existing prevalidate block JSON path")
    args = parser.parse_args()

    shard_dir = Path(args.shard_dir)
    per_variant = {}
    for vk in sorted(INC2_VARIANTS):
        shard = shard_dir / f"B1_{vk}.json"
        if not shard.is_file():
            print(f"ERROR: missing shard {shard}", file=sys.stderr)
            return 2
        data = json.loads(shard.read_text())
        pv = data.get("per_variant", {}).get(vk)
        if not pv:
            print(f"ERROR: shard {shard} missing per_variant.{vk}", file=sys.stderr)
            return 2
        per_variant[vk] = pv

    total_pass = sum(int(v.get("pass", 0)) for v in per_variant.values())
    total_mut = sum(int(v.get("total", 0)) for v in per_variant.values())
    all_pass = all(v.get("verdict") == "PASS" for v in per_variant.values())

    prevalidate = None
    if args.prevalidate:
        prev = json.loads(Path(args.prevalidate).read_text())
        prevalidate = prev.get("prevalidate")

    report = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B1_hook_fidelity",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": INC2_SMOKE_SEED,
            "n_per_variant": B1_N_PER_VARIANT,
            "verifier": "a4/tools/verify_mutation_semantics.py (strict P1)",
            "pos_shards": True,
        },
        "per_variant": per_variant,
        "prevalidate": prevalidate,
        "totals": {"pass": total_pass, "mutations": total_mut},
        "verdict": "PASS" if all_pass else "FAIL",
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B1 merged verdict: {report['verdict']} ({total_pass}/{total_mut})")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
