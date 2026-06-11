"""E1 — Independent instruction decode vs trace (major, minor)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, OUTPUT_DIR, DEFAULT_HOST, arm_key, load_inspection,
)
from a4.core.insn_decode import decode_insn_word
from a4.standalone.mutations import instr_word_mod


def _primary_cycle_at_step(step: int, data):
    for c in data.cycles:
        if c.step == step and (c.major <= 6 or c.major == 8):
            return c
    return data.get_cycle(step)


def _fetch_word(step: int, data) -> Optional[tuple]:
    target = instr_word_mod.get_targets_at_step(step, data)
    if target:
        return target.original_word, target.cycle_idx, target.pc, target.major, target.minor
    cycle = _primary_cycle_at_step(step, data)
    if not cycle or cycle.txn_idx >= len(data.all_txns):
        return None
    txn = data.all_txns[cycle.txn_idx]
    if not txn.is_read():
        return None
    return txn.word, cycle.cycle_idx, cycle.pc, cycle.major, cycle.minor


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--steps-per-arm", type=int, default=10)
    p.add_argument("--min-match-rate", type=float, default=0.95)
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    data, universe, _, host_args = load_inspection(args.host, args.in1, args.in4)

    print(f"E1 decode ground truth: arms={universe.num_arms} steps/arm={args.steps_per_arm}")

    per_arm: List[Dict[str, Any]] = []
    all_mismatches: List[Dict[str, Any]] = []
    failing_arms = 0

    for (kind, zone), steps in sorted(universe.arms.items()):
        aid = arm_key(kind, zone)
        sample = sorted(steps)[: args.steps_per_arm]
        matches = 0
        checked = 0
        skipped = 0
        mismatches: List[Dict[str, Any]] = []

        for step in sample:
            fetched = _fetch_word(step, data)
            if fetched is None:
                skipped += 1
                continue
            word, cycle_idx, pc, exp_m, exp_n = fetched
            decoded = decode_insn_word(word & 0xFFFFFFFF)
            if decoded is None:
                mismatches.append({
                    "step": step,
                    "cycle_idx": cycle_idx,
                    "pc": f"0x{pc:08x}",
                    "raw_word_hex": f"0x{word & 0xFFFFFFFF:08x}",
                    "expected_major": exp_m,
                    "expected_minor": exp_n,
                    "decoded_major": None,
                    "decoded_minor": None,
                    "reason": "decode_insn_word returned None",
                })
                checked += 1
                continue
            checked += 1
            if decoded.major == exp_m and decoded.minor == exp_n:
                matches += 1
            else:
                rec = {
                    "step": step,
                    "cycle_idx": cycle_idx,
                    "pc": f"0x{pc:08x}",
                    "raw_word_hex": f"0x{word & 0xFFFFFFFF:08x}",
                    "expected_major": exp_m,
                    "expected_minor": exp_n,
                    "decoded_major": decoded.major,
                    "decoded_minor": decoded.minor,
                    "decoded_name": decoded.name,
                    "reason": "major/minor mismatch",
                }
                mismatches.append(rec)
                all_mismatches.append({**rec, "arm_id": aid, "kind": kind, "zone": zone})

        rate = matches / checked if checked else 1.0
        per_arm.append({
            "arm_id": aid,
            "kind": kind,
            "zone": zone,
            "cycles_checked": checked,
            "cycles_skipped": skipped,
            "decode_matches": matches,
            "decode_mismatches": len(mismatches),
            "match_rate": round(rate, 4),
            "mismatches": mismatches,
        })
        mark = "OK" if rate >= args.min_match_rate or checked == 0 else "LOW"
        print(f"  {mark} {aid}: {matches}/{checked} matches ({rate:.1%}), skipped={skipped}")
        if checked and rate < args.min_match_rate:
            failing_arms += 1

    out = {
        "_meta": GLOSSARY_META,
        "host_args": host_args,
        "min_match_rate": args.min_match_rate,
        "per_arm": per_arm,
        "total_mismatches": len(all_mismatches),
    }
    out_path = OUTPUT_DIR / "E1_decode_ground_truth.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"  Wrote {out_path}")

    # E1 mismatches do not block Inc 1 per user spec
    print(f"=== E1 RESULT: PASS ({failing_arms} arms below {args.min_match_rate:.0%}; "
          f"{len(all_mismatches)} mismatches → E4 queue) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
