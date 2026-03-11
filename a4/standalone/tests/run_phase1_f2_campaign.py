#!/usr/bin/env python3
"""
Phase 1 / Investigation F2: 100-mutation campaign with circuit_debug enabled.

Goal: Find mutations where local_failures == 0 but check_poly nonzero_cycles > 0
      (the "global-only" premium bucket).

Reuses the existing A4 mutation infrastructure for proven mutation generation.
Adds parsing for <a4_check_poly_scan> and <a4_accum_touch_debug> tags.

NOTE: Requires the host binary to be built with circuit_debug feature enabled.
      The ZK shift is disabled in this mode, so verification always fails (exit 101).
      This is expected -- we're measuring constraint satisfaction, not proof validity.

Usage:
    python -m a4.standalone.tests.run_phase1_f2_campaign \
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
ACCUM_DEBUG_RE = re.compile(r'<a4_accum_touch_debug>\s*total_touches=(\d+)\s+distinct_buckets=(\d+)\s*</a4_accum_touch_debug>')
POLY_FP_SUMMARY_RE = re.compile(r'<a4_poly_fp_summary>({.*?})</a4_poly_fp_summary>')


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
    }
    result = subprocess.run([host] + host_args, capture_output=True, text=True, env=env)
    os.unlink(config_path)
    return result.stdout + result.stderr, result.returncode


def parse_output(output):
    """Parse all A4 diagnostic tags from run output."""
    failures = parse_all_constraint_failures(output)
    local_failures = [f for f in failures if '"phase":"local"' in output.split(f.loc)[0].split('\n')[-1] or True]
    local_count = len(re.findall(r'"phase":"local"', output))
    accum_count = len(re.findall(r'"phase":"accum"', output))

    local_cycles = set()
    for f in failures:
        local_cycles.add(f.cycle)

    check_poly = None
    m = CHECK_POLY_RE.search(output)
    if m:
        check_poly = json.loads(m.group(1))

    accum_debug = None
    m = ACCUM_DEBUG_RE.search(output)
    if m:
        accum_debug = {"total_touches": int(m.group(1)), "distinct_buckets": int(m.group(2))}

    return {
        "local_failure_count": local_count,
        "accum_failure_count": accum_count,
        "total_failure_count": len(failures),
        "distinct_local_cycles": len(local_cycles),
        "local_cycles": sorted(local_cycles),
        "check_poly": check_poly,
        "accum_debug": accum_debug,
    }


def main():
    parser = argparse.ArgumentParser(description="Phase 1 F2 Campaign")
    parser.add_argument("--host", required=True)
    parser.add_argument("--num", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("host_args", nargs="*")
    args = parser.parse_args()

    host, host_args, num, seed = args.host, args.host_args, args.num, args.seed
    rng = random.Random(seed)

    print(f"=== Phase 1 F2 Campaign: {num} mutations, seed={seed} ===")
    print(f"Host: {host}")
    print(f"Host args: {host_args}")
    print()

    print("Running inspection...")
    data = InspectionData.from_inspection(host, host_args)
    print(f"  {data.summary()}")

    selector = ZonedStepSelector(seed=seed)
    value_gen = create_generator("mixed", seed)

    results = []
    kind_counter = Counter()
    skipped = 0
    t_start = time.time()

    for i in range(num):
        kind = rng.choice(MUTATION_KINDS)
        kind_counter[kind] += 1

        config = None
        step = None
        for attempt in range(10):
            step = selector.select_step(data, kind)
            if step is None:
                break
            config = create_mutation(kind, step, data, rng, value_gen)
            if config is not None:
                break

        if config is None:
            skipped += 1
            continue

        t0 = time.time()
        output, exit_code = run_mutation(host, host_args, config)
        elapsed_ms = (time.time() - t0) * 1000

        parsed = parse_output(output)

        result = {
            "run": i + 1,
            "kind": kind,
            "step": step,
            "exit_code": exit_code,
            "elapsed_ms": round(elapsed_ms),
            **parsed,
            "config": config,
        }
        results.append(result)

        cp = parsed["check_poly"]
        nz = cp["nonzero_cycles"] if cp else "?"
        nz_list = cp["first_nonzero_cycles"][:5] if cp else []
        print(f"  [{i+1:3d}/{num}] {kind:25s} step={step:5d} | local={parsed['local_failure_count']:3d} accum={parsed['accum_failure_count']:1d} | check_nz={nz} cycles={nz_list} | {elapsed_ms:.0f}ms")

    total_time = time.time() - t_start

    # ===== REPORT =====
    print()
    print("=" * 80)
    print("PHASE 1 F2 CAMPAIGN REPORT")
    print("=" * 80)

    valid = [r for r in results if r["check_poly"] is not None]
    print(f"\nRuns: {len(results)} completed, {skipped} skipped, {len(valid)} with check_poly data")
    print(f"Time: {total_time:.0f}s ({total_time/len(results):.1f}s/run)")

    # H2 Analysis
    print(f"\n--- H2 ANALYSIS ---")
    h2_extra_cycles = []
    h2_match = []
    for r in valid:
        nz_cycles = set(r["check_poly"]["first_nonzero_cycles"])
        local_cycles = set(r["local_cycles"])
        extra = nz_cycles - local_cycles
        if extra:
            h2_extra_cycles.append(r)
        else:
            h2_match.append(r)

    print(f"  Runs with check_poly non-zero cycles BEYOND local failures: {len(h2_extra_cycles)}")
    print(f"  Runs where check_poly non-zero cycles match local failures only: {len(h2_match)}")

    if h2_extra_cycles:
        print(f"\n  Runs with extra non-zero cycles:")
        for r in h2_extra_cycles[:20]:
            cp = r["check_poly"]
            extra = set(cp["first_nonzero_cycles"]) - set(r["local_cycles"])
            print(f"    Run {r['run']:3d} ({r['kind']:25s}): check_nz={cp['nonzero_cycles']} local_cycles={r['local_cycles'][:5]} extra={sorted(extra)[:5]}")

    # PREMIUM BUCKET: global-only
    print(f"\n--- PREMIUM BUCKET: GLOBAL-ONLY ---")
    global_only = [r for r in valid if r["local_failure_count"] == 0 and r["check_poly"]["nonzero_cycles"] > 0]
    print(f"  Runs with 0 local failures AND nonzero check_poly: {len(global_only)}")
    for r in global_only[:10]:
        cp = r["check_poly"]
        print(f"    Run {r['run']:3d} ({r['kind']:25s}): check_nz={cp['nonzero_cycles']} cycles={cp['first_nonzero_cycles'][:10]}")

    # Runs with 0 local AND 0 check_poly (no effect mutations)
    no_effect = [r for r in valid if r["local_failure_count"] == 0 and r["check_poly"]["nonzero_cycles"] == 0]
    print(f"  Runs with 0 local failures AND 0 check_poly nonzero (no effect): {len(no_effect)}")

    # Per-kind stats
    print(f"\n--- PER-KIND BREAKDOWN ---")
    for kind in MUTATION_KINDS:
        kr = [r for r in valid if r["kind"] == kind]
        if not kr:
            continue
        nz_counts = [r["check_poly"]["nonzero_cycles"] for r in kr]
        local_counts = [r["local_failure_count"] for r in kr]
        global_only_k = [r for r in kr if r["local_failure_count"] == 0 and r["check_poly"]["nonzero_cycles"] > 0]
        extra_k = [r for r in kr if set(r["check_poly"]["first_nonzero_cycles"]) - set(r["local_cycles"])]
        print(f"  {kind:25s}: n={len(kr):3d} | check_nz: min={min(nz_counts)} max={max(nz_counts)} mean={sum(nz_counts)/len(nz_counts):.1f} | "
              f"local: mean={sum(local_counts)/len(local_counts):.1f} | extra_cycles={len(extra_k)} global_only={len(global_only_k)}")

    # Cycle 0 analysis
    print(f"\n--- CYCLE 0 ANALYSIS ---")
    cycle0_count = sum(1 for r in valid if 0 in (r["check_poly"]["first_nonzero_cycles"] or []))
    print(f"  Runs with cycle 0 in nonzero list: {cycle0_count}/{len(valid)}")
    cycle0_no_local = sum(1 for r in valid if 0 in (r["check_poly"]["first_nonzero_cycles"] or []) and 0 not in r["local_cycles"])
    print(f"  Of those, runs where cycle 0 has NO local failure: {cycle0_no_local}")

    # Save results
    output_path = "/tmp/phase1_f2_results.json"
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nFull results saved to {output_path}")

    print(f"\nDone.")


if __name__ == "__main__":
    main()
