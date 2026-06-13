#!/usr/bin/env python3
"""Apply Inc 3 + Inc 4 B1 disposition to a B1 result JSON dir.

Inc 3 documented 4 exclusion categories for raw B1 failures (see
PHASE_7D_INC3D_B1_DISPOSITION.md):
  A  — INSTR_TYPE_MOD step=0 multi-cycle (Auipc boot, hook cycle 0 = CONTROL major=7)
  B  — MEM_VAL_MOD step=3929 ECALL last_step, **byte_addr** mismatch
  C  — INSTR_TYPE_MOD hook major=8 (ECALL-adjacent, hook fired on ECALL cycle)
  D  — MEM_VAL_MOD step=0 boot/ECALL boundary, **byte_addr** mismatch

Inc 4 B11 (2500-mut sample) surfaced one additional sub-pattern within the same
D42+D46 architectural envelope:
  B2 — MEM_VAL_MOD step=3929 ECALL last_step, **old_word / old_byte** mismatch
       Same root cause as B: ECALL's prepare/dispatch/cleanup sub-stages cause
       the hook to read the mem-txn state at a different sub-stage than the
       config recorded. Whereas B catches "which byte_addr is at txn_idx=N",
       B2 catches "what value was at that byte_addr at sub-stage S".
       SAFETY: B2 only triggers if the mutation EFFECT (`new_word`) agrees
       between hook and config — i.e. the mutation actually applied; only the
       metadata around it drifted. If new_word also mismatches, the failure
       stays unclassified (OTHER) and is flagged for review.

Inc 4 closeout (2026-06-13) ruling: B2 is a sub-category of B (same D42+D46
disposition), tracked as B2 in the output so the disposition trail makes the
extension visible rather than silently broadening B.

The strict verifier (`verify_mutation_semantics.py P1`) does NOT apply these
exclusions — by design, to keep the raw signal honest. This tool applies them
post-hoc and reports the net pass/fail.

Usage:
  python3 -m a4.audits.B1_apply_disposition --in-dir <dir-of-B1_V*.json> \
      --output <out.json> [--label <campaign_label>]

Where <dir> contains files like B1_V1.json, B1_V2.json, ..., each with schema
  {"per_variant": {"V<n>": {"total": int, "pass": int, "fail": int,
                            "failures": [{mutation_id, kind, step, detail, hook_payload}]}}}
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _mutation_actually_applied(row: dict) -> bool:
    """Safety check for B2/D2: did the MEM_VAL_MOD mutation's effect (new_word)
    agree between hook and config? If yes, only the metadata around the mutation
    drifted (ECALL sub-stage capture timing). If no, the mutation got clobbered
    and the failure is real — do NOT classify as B2/D2.

    Defensive: if the row doesn't carry enough info to verify, returns False
    (forcing the failure to OTHER for explicit review).
    """
    hp = row.get("hook_payload") or {}
    cfg = row.get("config") or {}
    hook_new = hp.get("new_word")
    cfg_new = cfg.get("new_word") or cfg.get("mutated_value") or (cfg.get("_info") or {}).get("new_word")
    if hook_new is None or cfg_new is None:
        # Fallback: parse detail string for explicit indication that only old_word
        # diverged ("old_word mismatch" appears without "new_word mismatch").
        detail = row.get("detail", "")
        if ("old_word" in detail or "old_byte" in detail) and "new_word" not in detail:
            return True
        return False
    # Normalize to ints if strings
    try:
        return int(hook_new, 0) == int(cfg_new, 0) if isinstance(hook_new, str) else hook_new == cfg_new
    except (ValueError, TypeError):
        return hook_new == cfg_new


def categorize(row: dict) -> str:
    """Return one of: 'A','B','B2','C','D','D2','RACE','OTHER' for a failure row.

    A/B/C/D: original Inc 3 disposition (PHASE_7D_INC3D_B1_DISPOSITION.md §3-4).
    B2/D2:   Inc 4 extension — same D42+D46 envelope, different mem-txn cell.
    RACE:    Poseidon2 inst_p2.zir:291 fingerprint (would map to B7; NEW if appears).
    OTHER:   Unclassified — flagged for review, counted as net failure.
    """
    kind = row.get("kind", "")
    step = row.get("step", -1)
    detail = row.get("detail", "")
    hp = row.get("hook_payload") or {}
    hook_major = None
    if "hook old=8/" in detail or hp.get("cycle_major") == 8:
        hook_major = 8
    if "hook old=7/" in detail:
        hook_major = 7

    # Category A — Auipc boot INSTR_TYPE_MOD at step 0 with hook major=7 (CONTROL0)
    if kind == "INSTR_TYPE_MOD" and step == 0 and "cycle_shift" in detail and hook_major == 7:
        return "A"
    # Category B — MEM_VAL_MOD at step 3929 (ECALL last_step) byte_addr mismatch
    if kind == "MEM_VAL_MOD" and step == 3929 and "byte_addr" in detail:
        return "B"
    # Category B2 — MEM_VAL_MOD at step 3929, old_word/old_byte mismatch
    # (Inc 4 B11 finding: same ECALL sub-stage taxonomy, different cell.)
    # SAFETY: only if the mutation actually applied (new_word agrees).
    if (kind == "MEM_VAL_MOD" and step == 3929
            and ("old_word" in detail or "old_byte" in detail)
            and "new_word" not in detail
            and _mutation_actually_applied(row)):
        return "B2"
    # Category C — INSTR_TYPE_MOD ECALL-adjacent with hook major=8
    if kind == "INSTR_TYPE_MOD" and "cycle_shift" in detail and hook_major == 8:
        return "C"
    # Category D — MEM_VAL_MOD at step 0 byte_addr mismatch
    if kind == "MEM_VAL_MOD" and step == 0 and "byte_addr" in detail:
        return "D"
    # Category D2 — MEM_VAL_MOD at step 0, old_word/old_byte mismatch (extension)
    if (kind == "MEM_VAL_MOD" and step == 0
            and ("old_word" in detail or "old_byte" in detail)
            and "new_word" not in detail
            and _mutation_actually_applied(row)):
        return "D2"
    # Race — Poseidon2 fingerprint
    if "inst_p2.zir:291" in detail or "FieldToWord" in detail:
        return "RACE"
    return "OTHER"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--in-dir", required=True, help="Directory containing B1_V*.json files")
    p.add_argument("--output", required=True, help="Output JSON path for disposition summary")
    p.add_argument("--label", default="", help="Campaign label for the report _meta")
    args = p.parse_args()

    in_dir = Path(args.in_dir)
    files = sorted(in_dir.glob("B1_V*.json"))
    if not files:
        print(f"ERROR: no B1_V*.json in {in_dir}", file=sys.stderr)
        return 2

    per_variant = {}
    grand_total = grand_pass = grand_fail = grand_net_fail = 0
    grand_category_counts: Counter[str] = Counter()
    other_details: list[dict] = []

    for f in files:
        d = json.loads(f.read_text())
        for v, pv in d.get("per_variant", {}).items():
            total = pv.get("total", 0)
            pas = pv.get("pass", 0)
            fail = pv.get("fail", 0)
            failures = pv.get("failures", []) or []
            cats = Counter(categorize(r) for r in failures)
            net_fail = cats.get("OTHER", 0) + cats.get("RACE", 0)
            net_pass = total - net_fail
            per_variant[v] = {
                "total": total,
                "raw_pass": pas,
                "raw_fail": fail,
                "category_counts": dict(cats),
                "net_pass": net_pass,
                "net_fail": net_fail,
                "verdict_after_disposition": "PASS" if net_fail == 0 else "REVIEW",
            }
            grand_total += total
            grand_pass += pas
            grand_fail += fail
            grand_net_fail += net_fail
            grand_category_counts.update(cats)
            for r in failures:
                if categorize(r) in ("OTHER", "RACE"):
                    other_details.append({"variant": v, **r})

    grand_net_pass = grand_total - grand_net_fail
    out = {
        "_meta": {
            "audit": "B1_apply_disposition",
            "label": args.label,
            "source_dir": str(in_dir),
            "files_consumed": [f.name for f in files],
            "categories": {
                "A": "INSTR_TYPE_MOD step=0 multi-cycle (Auipc boot, hook major=7) — EXCLUDED per PHASE_7D_INC3D_B1_DISPOSITION.md §4.1 (D40)",
                "B": "MEM_VAL_MOD step=3929 ECALL last_step, byte_addr mismatch — EXCLUDED per disposition §4.2 (D42+D46)",
                "B2": "MEM_VAL_MOD step=3929 ECALL last_step, old_word/old_byte mismatch with new_word OK — EXCLUDED per D42+D46 (Inc 4 extension of B; same architectural envelope, mutation actually applied)",
                "C": "INSTR_TYPE_MOD ECALL-adjacent hook major=8 — EXCLUDED per disposition §4.2 (D46)",
                "D": "MEM_VAL_MOD step=0 boot/ECALL boundary, byte_addr mismatch — EXCLUDED per disposition §4.2 (D42+D46)",
                "D2": "MEM_VAL_MOD step=0 boot/ECALL boundary, old_word/old_byte mismatch with new_word OK — EXCLUDED per D42+D46 (Inc 4 extension of D)",
                "RACE": "Poseidon2 inst_p2.zir:291 race fingerprint — would map to B7, NEW if appears",
                "OTHER": "Unclassified — needs review (counted as net failure)",
            },
        },
        "summary": {
            "raw_total": grand_total,
            "raw_pass": grand_pass,
            "raw_fail": grand_fail,
            "raw_pass_rate": (grand_pass / grand_total) if grand_total else None,
            "net_pass": grand_net_pass,
            "net_fail": grand_net_fail,
            "net_pass_rate": (grand_net_pass / grand_total) if grand_total else None,
            "category_counts": dict(grand_category_counts),
            "verdict": "PASS" if grand_net_fail == 0 else "REVIEW",
        },
        "per_variant": per_variant,
        "needs_review": other_details,
    }

    Path(args.output).write_text(json.dumps(out, indent=2))
    print(f"[B1 disposition] {args.label or in_dir.name}: raw {grand_pass}/{grand_total} "
          f"({100*grand_pass/grand_total:.1f}%) -> net {grand_net_pass}/{grand_total} "
          f"({100*grand_net_pass/grand_total:.1f}%) [{out['summary']['verdict']}]")
    if other_details:
        print(f"  ! {len(other_details)} unclassified failure(s) need review:")
        for r in other_details:
            print(f"    {r['variant']} mut{r.get('mutation_id')} {r.get('kind')} step={r.get('step')} - {r.get('detail')}")
    print(f"  -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
