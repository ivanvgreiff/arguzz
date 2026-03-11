#!/usr/bin/env python3
"""
Phase 4: Hook Consistency Campaign -- verify all 3 global hooks agree.

Runs N mutations with Hook 1 (global residue), Hook 2 (check poly scan),
and Hook 3 (per-family residues) all active simultaneously. Reports any
disagreements between hooks.

REQUIRES: Host built with circuit_debug feature (for Hook 2).
          All runs will have exit code 101 (proof invalid due to disabled ZK shift).

Usage:
    python -m a4.standalone.tests.run_hook_consistency_campaign \
        --host ./workspace/output/target/release/risc0-host \
        --num 100 --seed 42 \
        -- --in1 5 --in4 10
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from a4.core.inspection_data import InspectionData
from a4.core.constraint_parser import parse_all_constraint_failures
from a4.core.touch_coverage import (
    parse_global_residue, parse_family_residues,
)
from a4.standalone.step_selector import ZonedStepSelector
from a4.standalone.value_generator import create_generator

from a4.standalone.mutations import (
    get_comp_out_targets, get_load_val_targets, get_store_out_targets,
    get_pre_exec_reg_targets, get_instr_type_targets,
    get_mem_val_targets, get_instr_word_targets,
)
from a4.standalone.mutations.instr_type_mod import generate_random_mutation as generate_instr_mutation
from a4.standalone.mutations.instr_word_mod_sur import (
    get_targets_at_step as get_instr_word_sur_targets,
    select_surgical_field, generate_field_value,
)

MUTATION_KINDS = [
    "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_REG_MOD",
    "INSTR_TYPE_MOD", "MEM_VAL_MOD", "INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR",
]

CHECK_POLY_RE = re.compile(r'<a4_check_poly_scan>({.*?})</a4_check_poly_scan>')


def create_mutation(kind, step, data, rng, value_gen):
    config = None
    if kind == "COMP_OUT_MOD":
        target = get_comp_out_targets(step, data)
        if target is None: return None
        config = {"mutation_type": "COMP_OUT_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": value_gen.generate_different(target.original_value)}
    elif kind == "LOAD_VAL_MOD":
        target = get_load_val_targets(step, data)
        if target is None: return None
        config = {"mutation_type": "LOAD_VAL_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": value_gen.generate_different(target.original_value)}
    elif kind == "STORE_OUT_MOD":
        target = get_store_out_targets(step, data)
        if target is None: return None
        config = {"mutation_type": "STORE_OUT_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": value_gen.generate_different(target.original_value)}
    elif kind == "PRE_EXEC_REG_MOD":
        targets = get_pre_exec_reg_targets(step, data, strategy="next_read")
        if not targets: return None
        target = rng.choice(targets)
        config = {"mutation_type": "PRE_EXEC_REG_MOD", "step": target.step,
                  "txn_idx": target.txn_idx, "word": value_gen.generate_different(target.original_word)}
    elif kind == "INSTR_TYPE_MOD":
        target = get_instr_type_targets(step, data)
        if not target: return None
        new_major, new_minor, _ = generate_instr_mutation(target, rng)
        config = {"mutation_type": "INSTR_TYPE_MOD", "step": target.step,
                  "major": new_major, "minor": new_minor}
    elif kind == "MEM_VAL_MOD":
        targets = get_mem_val_targets(step, data)
        if not targets: return None
        target = rng.choice(targets)
        config = {"mutation_type": "MEM_VAL_MOD", "step": target.step,
                  "txn_idx": target.txn_idx, "word": value_gen.generate_different(target.original_value)}
    elif kind == "INSTR_WORD_MOD_FULL":
        target = get_instr_word_targets(step, data)
        if not target: return None
        config = {"mutation_type": "INSTR_WORD_MOD", "step": target.step,
                  "word": value_gen.generate_different(target.original_word)}
    elif kind == "INSTR_WORD_MOD_SUR":
        target = get_instr_word_sur_targets(step, data)
        if target is None: return None
        instr = target.instruction
        sur_field = select_surgical_field(instr, rng)
        if sur_field is None: return None
        orig_field_val = instr.get_field_value(sur_field)
        new_field_val = generate_field_value(sur_field, orig_field_val, instr, rng)
        config = {"mutation_type": "INSTR_WORD_MOD", "step": target.step,
                  "word": instr.encode_with_mutation(sur_field, new_field_val)}
    if config is None:
        return None
    return config


def run_mutation(host, host_args, config):
    fd, config_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    Path(config_path).write_text(json.dumps(config, indent=2))

    env = {
        **dict(os.environ),
        "A4_MUTATION_CONFIG": config_path,
        "CONSTRAINT_CONTINUE": "1",
        "A4_COVERAGE_TOUCH": "1",
        "A4_GLOBAL_RESIDUE": "1",
        "A4_FAMILY_RESIDUE": "1",
    }
    result = subprocess.run([host] + host_args, capture_output=True, text=True, env=env)
    os.unlink(config_path)
    return result.stdout + result.stderr, result.returncode


def check_consistency(hook1, hook2_cp, hook3_families, local_count):
    """Check if all 3 hooks agree. Returns list of mismatch descriptions."""
    mismatches = []

    h1_global = hook1 is not None and hook1.get("nonzero", False)
    h3_any_nonzero = False
    h3_families_broken = []
    if hook3_families:
        for f in hook3_families:
            if f.get("nonzero", False):
                h3_any_nonzero = True
                h3_families_broken.append(f["family"])

    if h1_global and not h3_any_nonzero:
        mismatches.append("Hook1=nonzero but Hook3=all_zero")
    if not h1_global and h3_any_nonzero:
        mismatches.append(f"Hook1=zero but Hook3 has nonzero families: {h3_families_broken}")

    if hook2_cp:
        h2_has_cycle0 = 0 in hook2_cp.get("first_nonzero_cycles", [])
        h2_nz = hook2_cp.get("nonzero_cycles", 0)
        if h2_nz == 32768:
            mismatches.append("Hook2 shows ALL cycles nonzero (circuit_debug not active?)")
        elif h1_global and not h2_has_cycle0:
            mismatches.append("Hook1=nonzero but Hook2 has no cycle 0")
        elif not h1_global and h2_has_cycle0 and local_count == 0:
            mismatches.append("Hook1=zero but Hook2 has cycle 0 (and no local failures)")

    return mismatches


def main():
    parser = argparse.ArgumentParser(description="Hook Consistency Campaign")
    parser.add_argument("--host", required=True)
    parser.add_argument("--num", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("host_args", nargs="*")
    args = parser.parse_args()

    host, host_args, num, seed = args.host, args.host_args, args.num, args.seed
    rng = random.Random(seed)

    print(f"=== Hook Consistency Campaign: {num} mutations, seed={seed} ===")
    print(f"All 3 hooks active: Hook1 (global residue), Hook2 (check poly), Hook3 (per-family)")
    print(f"NOTE: Requires circuit_debug build for Hook 2 to produce meaningful data")
    print()

    print("Running inspection...")
    data = InspectionData.from_inspection(host, host_args)
    print(f"  {data.summary()}")

    selector = ZonedStepSelector(seed=seed)
    value_gen = create_generator("mixed", seed)

    results = []
    mismatches_total = 0
    kind_counter = Counter()
    t_start = time.time()

    for i in range(num):
        kind = rng.choice(MUTATION_KINDS)
        kind_counter[kind] += 1

        config = None
        step = None
        for attempt in range(10):
            step = selector.select_step(data, kind)
            if step is None: break
            config = create_mutation(kind, step, data, rng, value_gen)
            if config is not None: break

        if config is None:
            continue

        t0 = time.time()
        output, exit_code = run_mutation(host, host_args, config)
        elapsed_ms = (time.time() - t0) * 1000

        failures = parse_all_constraint_failures(output)
        local_count = len([f for f in failures if f.phase == "local"])
        accum_count = len([f for f in failures if f.phase == "accum"])

        hook1 = parse_global_residue(output)
        hook3 = parse_family_residues(output)

        hook2_cp = None
        m = CHECK_POLY_RE.search(output)
        if m:
            hook2_cp = json.loads(m.group(1))

        mismatches = check_consistency(hook1, hook2_cp, hook3, local_count)

        h1_str = "NZ" if (hook1 and hook1.get("nonzero")) else "Z" if hook1 else "?"
        h2_nz = hook2_cp["nonzero_cycles"] if hook2_cp else "?"
        h2_c0 = "c0" if (hook2_cp and 0 in hook2_cp.get("first_nonzero_cycles", [])) else "--"
        h3_broken = ",".join(f["family"] for f in hook3 if f.get("nonzero")) if hook3 else "none"
        mismatch_str = f" MISMATCH: {'; '.join(mismatches)}" if mismatches else ""
        if mismatches:
            mismatches_total += 1

        result = {
            "run": i + 1, "kind": kind, "step": step, "exit_code": exit_code,
            "elapsed_ms": round(elapsed_ms), "local_count": local_count,
            "accum_count": accum_count,
            "hook1": hook1, "hook2_cp": hook2_cp, "hook3": hook3,
            "mismatches": mismatches, "config": config,
        }
        results.append(result)

        print(f"  [{i+1:3d}/{num}] {kind:25s} step={step:5d} | L={local_count:2d} A={accum_count} | "
              f"H1={h1_str} H2={h2_nz}({h2_c0}) H3=[{h3_broken:15s}]{mismatch_str}")

    total_time = time.time() - t_start

    # ===== REPORT =====
    print()
    print("=" * 80)
    print("HOOK CONSISTENCY CAMPAIGN REPORT")
    print("=" * 80)

    print(f"\nRuns: {len(results)}, seed={seed}, {total_time:.0f}s")
    print(f"MISMATCHES: {mismatches_total}/{len(results)}")

    if mismatches_total > 0:
        print(f"\n--- MISMATCH DETAILS ---")
        for r in results:
            if r["mismatches"]:
                print(f"  Run {r['run']} ({r['kind']}): {'; '.join(r['mismatches'])}")

    # Hook agreement stats
    h1_nz = sum(1 for r in results if r["hook1"] and r["hook1"].get("nonzero"))
    h1_z = sum(1 for r in results if r["hook1"] and not r["hook1"].get("nonzero"))
    h3_any_nz = sum(1 for r in results if r["hook3"] and any(f.get("nonzero") for f in r["hook3"]))
    h2_c0 = sum(1 for r in results if r["hook2_cp"] and 0 in r["hook2_cp"].get("first_nonzero_cycles", []))

    print(f"\n--- HOOK SIGNALS ---")
    print(f"Hook 1 (global residue): nonzero={h1_nz}, zero={h1_z}")
    print(f"Hook 2 (check poly c0): cycle_0_present={h2_c0}")
    print(f"Hook 3 (any family NZ): {h3_any_nz}")

    # Per-family breakdown
    family_counts = Counter()
    for r in results:
        if r["hook3"]:
            for f in r["hook3"]:
                if f.get("nonzero"):
                    family_counts[f["family"]] += 1
    print(f"\n--- PER-FAMILY VIOLATIONS ---")
    for fam in ["memory", "u16", "u8", "cycle"]:
        print(f"  {fam:10s}: {family_counts.get(fam, 0)}")

    # Global-only bucket
    global_only = [r for r in results if r["local_count"] == 0 and r["hook1"] and r["hook1"].get("nonzero")]
    print(f"\n--- GLOBAL-ONLY BUCKET ---")
    print(f"Runs with 0 local failures + nonzero global: {len(global_only)}")
    for r in global_only[:10]:
        h3_fams = ",".join(f["family"] for f in r["hook3"] if f.get("nonzero")) if r["hook3"] else "?"
        print(f"  Run {r['run']} ({r['kind']:25s}): families=[{h3_fams}]")

    # Per-kind stats
    print(f"\n--- PER-KIND BREAKDOWN ---")
    for kind in MUTATION_KINDS:
        kr = [r for r in results if r["kind"] == kind]
        if not kr: continue
        nz = sum(1 for r in kr if r["hook1"] and r["hook1"].get("nonzero"))
        go = sum(1 for r in kr if r["local_count"] == 0 and r["hook1"] and r["hook1"].get("nonzero"))
        print(f"  {kind:25s}: n={len(kr):3d} global_nz={nz:3d} global_only={go:2d}")

    # Save results
    output_path = "/tmp/hook_consistency_results.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nFull results saved to {output_path}")
    print(f"\nDone.")


if __name__ == "__main__":
    main()
