"""E3 — Dossier for each 🟡 arm in EXPECTED_ARMS.md (joint review prep)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    D40_REMOVED_ARMS,
    GLOSSARY_META,
    EXPECTED_ARMS_PATH,
    OUTPUT_DIR,
    DEFAULT_HOST,
    arm_key,
    load_inspection,
    parse_arm_cell,
    _normalize_arm_cell,
)
from a4.core.insn_decode import decode_insn_word
from a4.standalone.mutations import instr_word_mod
from a4.standalone.semantic_zones import SINGLETON_ZONES, BOUNDARY_ZONES
from a4.standalone.zone_classifier import ECALL_MAJOR, classify_zones, _primary_decode_cycle
from a4.standalone.semantic_zones import major_minor_to_core_zone, pc_in_kernel, pc_in_user
from a4.standalone.semantic_arm_universe import ArmKey


_UNCERTAIN_ROW_RE = re.compile(
    r"^\|\s*(.+?)\s*\|\s*(\d+)\s*\|\s*([^|]+)\|\s*🟡\s*\|\s*(.*)\|",
)


def _open_questions(notes: str) -> List[str]:
    qs = set()
    for token in re.findall(r"Q(\d)", notes):
        qs.add(f"Q{token}")
    if "E1" in notes:
        qs.add("Q3" if "split" in notes.lower() else "Q1")
    if "E2" in notes:
        qs.add("Q6")
    if "E3" in notes:
        for q in ("Q1", "Q2", "Q5"):
            if q in notes or "split" in notes or "narrow" in notes or "only 2" in notes:
                pass
        if "only 2" in notes or "narrow" in notes:
            qs.add("Q5")
        if "split" in notes or "boundary" in notes:
            qs.add("Q2")
        if "ECALL step" in notes:
            qs.add("Q1")
    if "branch" in notes.lower():
        qs.add("Q4")
    if "D42" in notes or "host-controlled" in notes:
        qs.add("Q4")
    return sorted(qs) or ["Q1"]


def _classifier_reasoning(step: int, data, zones: Dict[int, str]) -> str:
    zone = zones.get(step, "unclassified")
    if step == 0:
        return "Rule 1: step==0 → step0 (singleton; overrides kernel PC)"
    if step == data.total_steps - 1:
        return "Rule 2: step==T-1 → last_step (singleton)"
    if any(c.major == ECALL_MAJOR and c.step == step for c in data.cycles):
        return f"Rule 3: step {step} contains ECALL (major=8) → pre_ecall (D13)"
    prim = _primary_decode_cycle(step, data)
    if zone == "post_ecall":
        return f"Rule D53: first user-PC Decode step in [e+1,e+5] after an ECALL → post_ecall"
    if zone == "kernel_other" and prim and pc_in_kernel(prim.pc):
        return f"Rule D54: primary Decode at kernel PC 0x{prim.pc:08x} → kernel_other"
    if prim:
        mz = major_minor_to_core_zone(prim.major, prim.minor)
        return f"Rule 5/D50: primary Decode major={prim.major} minor={prim.minor} → {mz}"
    return f"zone={zone}"


def _draft_verdict(kind: str, zone: str, notes: str, in_universe: bool) -> str:
    if not in_universe:
        if (kind, zone) in D40_REMOVED_ARMS:
            return "DROP_D40 — arm removed by D40 multi-cycle filter (Inc 0); no longer in universe; adjudicate whether to restore via cycle_idx (option a) or accept drop"
        return "DROP — arm not in current 44-arm universe; review whether EXPECTED_ARMS row should move to Expected-DROPPED"
    if "E2" in notes and ("effect" in notes or "mutable" in notes or "I/O" in notes):
        return "KEEP_PENDING_E2 — categorization plausible; mutation-effect confirmation deferred to E2/B1"
    if "split" in notes.lower() or "narrow" in notes.lower():
        return "KEEP_PENDING_REVIEW — zone policy question; needs joint review (see open questions)"
    if "only 2" in notes or "Why" in notes:
        return "KEEP_PENDING_REVIEW — rare arm; enumerate why steps qualify/don't qualify"
    if "branch" in notes.lower() and "mem" in notes.lower():
        return "KEEP_PENDING_E1 — likely JAL/JALR fetch txn at major=7 steps; confirm via E1 mismatches"
    return "KEEP_PENDING_REVIEW — default: retain arm pending joint adjudication"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--samples", type=int, default=5)
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    text = EXPECTED_ARMS_PATH.read_text()
    uncertain: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = _UNCERTAIN_ROW_RE.match(line.strip())
        if not m:
            continue
        kind, zone = parse_arm_cell(_normalize_arm_cell(m.group(1)))
        uncertain.append({
            "kind": kind,
            "zone": zone,
            "doc_step_count": int(m.group(2)),
            "notes": m.group(4).strip(),
        })

    data, universe, _, host_args = load_inspection(args.host, args.in1, args.in4)
    zones = classify_zones(data)

    print(f"E3 uncertain arm review: {len(uncertain)} 🟡 arms in EXPECTED_ARMS.md")

    dossiers: List[Dict[str, Any]] = []
    for arm in uncertain:
        kind, zone = arm["kind"], arm["zone"]
        aid = arm_key(kind, zone)
        in_univ = ArmKey.v5(kind, zone) in universe.arms
        steps = sorted(universe.arms.get(ArmKey.v5(kind, zone), []))
        sample_steps = steps[: args.samples]
        if len(sample_steps) < args.samples and steps:
            # if fewer than 5, take all
            pass
        elif not steps and arm["doc_step_count"] > 0:
            # D40-dropped: sample from zone ∩ valid steps for documentation
            from a4.standalone.zone_classifier import zone_to_steps
            z2s = zone_to_steps(data)
            sample_steps = sorted(z2s.get(zone, []))[: args.samples]

        samples: List[Dict[str, Any]] = []
        for step in sample_steps[: args.samples]:
            cycle = data.get_cycle(step)
            c_maj = cycle.major if cycle else None
            c_min = cycle.minor if cycle else None
            c_pc = f"0x{cycle.pc:08x}" if cycle else None
            decoded = None
            tgt = instr_word_mod.get_targets_at_step(step, data)
            if tgt:
                d = decode_insn_word(tgt.original_word & 0xFFFFFFFF)
                decoded = d.name if d else f"0x{tgt.original_word:08x}"
            elif cycle and cycle.txn_idx < len(data.all_txns):
                w = data.all_txns[cycle.txn_idx].word
                d = decode_insn_word(w & 0xFFFFFFFF)
                decoded = d.name if d else f"0x{w:08x}"

            samples.append({
                "step": step,
                "cycle_major": c_maj,
                "cycle_minor": c_min,
                "cycle_pc": c_pc,
                "classifier_reasoning": _classifier_reasoning(step, data, zones),
                "decoded_instr": decoded,
                "in_arm_step_list": step in steps,
            })

        dossiers.append({
            "arm_id": aid,
            "kind": kind,
            "zone": zone,
            "current_marker": "🟡",
            "in_current_universe": in_univ,
            "universe_step_count": len(steps),
            "doc_step_count": arm["doc_step_count"],
            "notes_from_expected_arms": arm["notes"],
            "sample_steps": samples,
            "draft_verdict": _draft_verdict(kind, zone, arm["notes"], in_univ),
            "open_questions_referenced": _open_questions(arm["notes"]),
        })
        print(f"  {aid}: in_universe={in_univ} steps={len(steps)} draft={dossiers[-1]['draft_verdict'][:40]}...")

    out = {
        "_meta": GLOSSARY_META,
        "host_args": host_args,
        "n_uncertain_arms": len(dossiers),
        "per_arm": dossiers,
    }
    out_path = OUTPUT_DIR / "E3_uncertain_review.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"  Wrote {out_path}")
    print(f"=== E3 RESULT: PASS ({len(dossiers)} 🟡 dossiers ready for joint review) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
