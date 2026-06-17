"""B2 — Multi-cycle replay (D40 option-b drop verification)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    D40_REMOVED_ARMS,
    GLOSSARY_META,
    OUTPUT_DIR,
    arm_key,
    load_inspection,
)
from a4.standalone.semantic_arm_universe import (
    ArmKey,
    SemanticArmUniverse,
    _MAJOR_FILTER_KINDS,
    _matching_cycles_at_step,
)

B1_OUTPUT = OUTPUT_DIR / "B1_hook_fidelity.json"


def _step0_arms(universe: SemanticArmUniverse) -> List[str]:
    arms = []
    for kind, zone in universe.available_arms:
        if zone != "step0":
            continue
        arms.append(arm_key(kind, zone))
    return sorted(arms)


def _step0_cycles(data, universe: SemanticArmUniverse) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for kind, zone in universe.available_arms:
        if zone != "step0":
            continue
        steps = universe.steps_in_arm(kind, zone)
        if not steps:
            continue
        step = steps[0] if len(steps) == 1 else min(steps)
        n = _matching_cycles_at_step(kind, step, data)
        out[arm_key(kind, zone)] = n
    return out


def _instr_type_mod_step0_in_universe(universe: SemanticArmUniverse) -> bool:
    return ArmKey.v5("INSTR_TYPE_MOD", "step0") in universe.arms


def _b1_multicycle_violations(b1_path: Path) -> int:
    if not b1_path.exists():
        return -1
    b1 = json.loads(b1_path.read_text())
    total = 0
    for pv in b1.get("per_variant", {}).values():
        total += int(pv.get("multicycle_flags", 0))
        for f in pv.get("failures", []):
            if "cycle_shift" in f.get("detail", ""):
                total += 1
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="B2 multi-cycle replay audit")
    parser.add_argument("--b1-output", default=str(B1_OUTPUT))
    parser.add_argument("--output", default=str(OUTPUT_DIR / "B2_multicycle_replay.json"))
    parser.add_argument("--in1", default="5")
    parser.add_argument("--in4", default="10")
    args = parser.parse_args()

    host = str(Path(__file__).resolve().parents[2] / "workspace/output/target/release/risc0-host")
    data, universe, kinds, _ = load_inspection(host, args.in1, args.in4)

    step0_arms = _step0_arms(universe)
    cycles_per = _step0_cycles(data, universe)
    major_filter_cycles = {
        k: v for k, v in cycles_per.items()
        if k.split("|", 1)[0] in _MAJOR_FILTER_KINDS
    }
    all_single = all(n <= 1 for n in major_filter_cycles.values())

    dropped_absent = all(
        ArmKey.v5(kind, zone) not in universe.arms
        for kind, zone in D40_REMOVED_ARMS
    )

    # D40 option (b): INSTR_TYPE_MOD|step0 kept only if single-cycle at step 0.
    instr_step0_kept = _instr_type_mod_step0_in_universe(universe)
    step0_instr_cycles = 0
    if instr_step0_kept:
        step0_instr_cycles = _matching_cycles_at_step(
            "INSTR_TYPE_MOD", 0, data,
        )

    b1_violations = _b1_multicycle_violations(Path(args.b1_output))

    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B2_multicycle_replay",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "d40_reference": "Inc 1.5 — option (b) drop multi-cycle steps",
        },
        "d40_choice": "option_b_drop_multi_cycle_steps",
        "universe_query": {
            "step0_arms": step0_arms,
            "step0_cycles_per_arm": cycles_per,
            "step0_cycles_major_filter_only": major_filter_cycles,
            "all_single_cycle": all_single,
            "instr_type_mod_step0_in_universe": instr_step0_kept,
            "instr_type_mod_step0_matching_cycles": step0_instr_cycles,
        },
        "d40_dropped_arms_absent": dropped_absent,
        "d40_dropped_arms_checked": [arm_key(k, z) for k, z in sorted(D40_REMOVED_ARMS)],
        "b1_multicycle_violations": b1_violations,
        "b1_output": args.b1_output,
    }

    ok = (
        dropped_absent
        and all_single
        and (not instr_step0_kept or step0_instr_cycles <= 1)
        and (b1_violations <= 0)
    )
    if b1_violations < 0:
        report["b1_pending"] = True
    report["verdict"] = "PASS" if ok else "FAIL"

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B2 verdict: {report['verdict']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
