#!/usr/bin/env python3
"""Run thesis §3.3.3 experiment phases for minimal-add guest (isolated)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
HOST = ROOT / "target/release/thesis-minimal-host"
ARGUZZ_ADD_STEP = 187
ARGUZZ_ADD_PC = 2099232
SEED = 42

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.executor import (  # noqa: E402
    run_a4_inspection_with_step,
    run_a4_mutation,
    run_baseline,
)
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.touch_coverage import parse_family_residues, parse_touch_bitmap  # noqa: E402
from a4.standalone.mutations.pre_exec_reg_mod import (  # noqa: E402
    REGISTER_NAMES,
    create_config,
    get_targets_at_step,
)


def main() -> None:
    ART.mkdir(exist_ok=True)
    host = str(HOST)

    # Phase 1: A4 inspect + instruction card at Arguzz add step
    data = InspectionData.from_inspection(host, [])
    (ART / "inspection_summary.txt").write_text(data.summary())

    a4_step = None
    for c in data.cycles:
        if c.major == 0 and c.minor == 0 and c.pc == ARGUZZ_ADD_PC + 4:
            a4_step = c.step
            break
    if a4_step is None:
        for c in data.cycles:
            if c.major == 0 and c.minor == 0 and abs(c.pc - (ARGUZZ_ADD_PC + 4)) <= 8:
                a4_step = c.step
                break
    if a4_step is None:
        raise SystemExit("Could not align A4 Add step by PC")

    out, cycles, step_txns, txns = run_a4_inspection_with_step(host, [], a4_step)
    (ART / f"step_{a4_step}_dump.txt").write_text(out)

    card = {
        "guest_add": {
            "arguzz_step": ARGUZZ_ADD_STEP,
            "arguzz_pc": ARGUZZ_ADD_PC,
            "assembly": "add s0, a0, a1  (after li a0,3; li a1,4)",
            "a4_step": a4_step,
            "a4_pc": ARGUZZ_ADD_PC + 4,
            "major": 0,
            "minor": 0,
            "expected_sum": 7,
        },
        "transactions": [
            {
                "txn_idx": t.txn_idx,
                "a4_step": a4_step,
                "addr": t.addr,
                "word": t.word,
                "prev_word": t.prev_word,
                "is_read": t.is_read(),
                "is_write": t.is_write(),
                "register": (
                    REGISTER_NAMES[t.register_index()]
                    if t.register_index() is not None
                    else None
                ),
            }
            for t in txns
        ],
    }
    (ART / "instruction_card.json").write_text(json.dumps(card, indent=2))

    # Phase 2: touch coverage baseline (unmutated)
    touch_out = run_baseline(host, [], {"A4_COVERAGE_TOUCH": "1", "CONSTRAINT_CONTINUE": "1"})
    (ART / "touch_baseline.txt").write_text(touch_out)
    touch_lines = [ln for ln in touch_out.splitlines() if "<a4_touch_coverage>" in ln and f'"step": {a4_step}' in ln]
    (ART / "touch_at_add.txt").write_text("\n".join(touch_lines))

    # Phase 3: Arguzz PRE_EXEC_REG_MOD at guest add step
    arguzz_cmd = [
        host,
        "--trace",
        "--inject",
        "--inject-step",
        str(ARGUZZ_ADD_STEP),
        "--inject-kind",
        "PRE_EXEC_REG_MOD",
        "--seed",
        str(SEED),
    ]
    proc = subprocess.run(arguzz_cmd, capture_output=True, text=True)
    arguzz_out = proc.stdout + proc.stderr
    (ART / "arguzz_mut.txt").write_text(arguzz_out)
    arguzz_failures = parse_all_constraint_failures(arguzz_out)
    arguzz_hook3 = parse_family_residues(arguzz_out)

    # Phase 4: A4 PRE_EXEC_REG_MOD — mutate a1 read (value 4) at add step
    targets = get_targets_at_step(a4_step, data, strategy="next_read")
    a1_reads = [t for t in targets if t.register_name == "a1" and not t.is_write]
    if not a1_reads:
        a1_reads = [t for t in targets if t.register_name == "a1"]
    if not a1_reads:
        raise SystemExit(f"No a1 read target at A4 step {a4_step}; targets={targets}")

    target = a1_reads[0]
    mutated = target.original_word + 5 if target.original_word == 4 else 9
    cfg_path = ART / "a4_mutation.json"
    create_config(target, mutated, cfg_path)

    a4_result = run_a4_mutation(host, [], cfg_path)

    (ART / "a4_mut.txt").write_text(a4_result.combined_output)

    # Phase 6: comparison matrix
    def fail_names(failures):
        return sorted({f.loc for f in failures})

    matrix = {
        "site": {
            "arguzz_step": ARGUZZ_ADD_STEP,
            "a4_step": a4_step,
            "operand_register": "a1 (rs2, value 4)",
            "a4_mutated_word": mutated,
        },
        "arguzz": {
            "exit_code": proc.returncode,
            "local_failures": fail_names(arguzz_failures),
            "hook3_families": arguzz_hook3,
        },
        "a4": {
            "exit_code": a4_result.exit_code,
            "local_failures": fail_names(a4_result.failures),
            "hook3_families": a4_result.family_residues,
            "mutation_config": json.loads(cfg_path.read_text()),
        },
    }
    (ART / "comparison_matrix.json").write_text(json.dumps(matrix, indent=2))

    print(json.dumps(matrix, indent=2))


if __name__ == "__main__":
    main()
