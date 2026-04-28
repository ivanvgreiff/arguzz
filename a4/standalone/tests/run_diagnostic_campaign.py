#!/usr/bin/env python3
"""
Diagnostic campaign with revised reward computation (Phase II.2V).

Runs N mutations with bitmap + verbose touch, computes the revised reward
(5 components + Q + weighted avg) per run, and produces comprehensive
analysis including per-kind reward distributions.

Usage:
    python -m a4.standalone.tests.run_diagnostic_campaign \
        --host ./workspace/output/target/release/risc0-host \
        --num 200 --seed 123 \
        -- --in1 5 --in4 10
"""

import argparse
import json
import math
import os
import random
import re
import subprocess
import statistics
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from a4.core.inspection_data import InspectionData
from a4.core.constraint_parser import ConstraintFailure, parse_all_constraint_failures
from a4.core.touch_coverage import (
    parse_touch_bitmap, count_new_bits, merge_into_global,
    make_global_bitmap, distinct_touched, A4_TOUCH_MAP_SIZE,
    parse_accum_touch_bitmap, parse_accum_verbose_set,
    parse_global_residue, parse_family_residues, parse_family_detail,
)
from a4.standalone.step_selector import ZonedStepSelector
from a4.standalone.value_generator import create_generator
from a4.standalone.baseline_touch import capture_baseline_touch
from a4.standalone.pilot_calibration import CalibratedParams
from a4.standalone.coverage_state import CoverageState, compute_reward, update_state

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

CRASH_SIGNALS = {-11, -6, -8, -9, -10, 139, 134, 136, 137, 138}

VERBOSE_RE = re.compile(r'<a4_touch_verbose>\[(.*?)\]</a4_touch_verbose>', re.DOTALL)
ACCUM_VERBOSE_RE = re.compile(r'<a4_accum_touch_verbose>\[(.*?)\]</a4_accum_touch_verbose>', re.DOTALL)


def parse_verbose_set(output: str) -> Optional[Set[str]]:
    match = VERBOSE_RE.search(output)
    if not match:
        return None
    return set(json.loads('[' + match.group(1) + ']'))


def parse_accum_verbose(output: str) -> Optional[Set[str]]:
    match = ACCUM_VERBOSE_RE.search(output)
    if not match:
        return None
    return set(json.loads('[' + match.group(1) + ']'))


def classify_outcome(output: str, exit_code: int, n_fail: int) -> Tuple[str, bool]:
    """Classify run outcome and proof_generated. Returns (outcome, proof_generated)."""
    crashed = exit_code in CRASH_SIGNALS
    if crashed:
        return "CRASH", False

    proof_generated = False
    if "verify segment" in output:
        proof_generated = True
    elif '"context":"Prover"' in output and '"status":"success"' in output:
        proof_generated = True
    elif '"context":"Verifier"' in output:
        proof_generated = True

    verifier_accepted = bool(re.search(
        r'<record>\s*\{[^}]*"context"\s*:\s*"Verifier"[^}]*"status"\s*:\s*"success"[^}]*\}\s*</record>',
        output
    )) or bool(re.search(
        r'<record>\s*\{[^}]*"status"\s*:\s*"success"[^}]*"context"\s*:\s*"Verifier"[^}]*\}\s*</record>',
        output
    ))

    if verifier_accepted:
        return "ACCEPTED", proof_generated
    elif n_fail > 0 or "verify segment" in output:
        return "REJECTED", proof_generated
    else:
        return "NO_EFFECT", proof_generated


@dataclass
class RunResult:
    run_num: int
    kind: str
    step: int
    exit_code: int
    crashed: bool
    outcome: str
    proof_generated: bool
    n_fail: int
    d_fail: int
    r_rep: int
    fail_context_ids: Set[Tuple[str, int, int]]
    bitmap_delta_new: int
    exact_delta_new: int
    exact_touched_count: int
    bitmap_touched_count: int
    reward: float
    diag: dict
    execution_time_ms: float
    n_fail_local: int = 0
    n_fail_accum: int = 0
    d_fail_local: int = 0
    d_fail_accum: int = 0
    fail_context_ids_local: Set[Tuple[str, int, int]] = None
    fail_context_ids_accum: Set[Tuple[str, int, int]] = None
    accum_bitmap_delta_new: int = 0
    accum_exact_delta_new: int = 0
    accum_exact_touched_count: int = 0
    accum_bitmap_touched_count: int = 0


def create_mutation(kind, step, data, rng, value_gen):
    """Create mutation config dict and write to temp file."""
    config = None
    mutated_value = 0
    original_value = 0

    if kind == "COMP_OUT_MOD":
        target = get_comp_out_targets(step, data)
        if target is None: return None, 0, 0
        mutated_value = value_gen.generate_different(target.original_value)
        original_value = target.original_value
        config = {"mutation_type": "COMP_OUT_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": mutated_value}
    elif kind == "LOAD_VAL_MOD":
        target = get_load_val_targets(step, data)
        if target is None: return None, 0, 0
        mutated_value = value_gen.generate_different(target.original_value)
        original_value = target.original_value
        config = {"mutation_type": "LOAD_VAL_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": mutated_value}
    elif kind == "STORE_OUT_MOD":
        target = get_store_out_targets(step, data)
        if target is None: return None, 0, 0
        mutated_value = value_gen.generate_different(target.original_value)
        original_value = target.original_value
        config = {"mutation_type": "STORE_OUT_MOD", "step": target.step,
                  "txn_idx": target.write_txn_idx, "word": mutated_value}
    elif kind == "PRE_EXEC_REG_MOD":
        targets = get_pre_exec_reg_targets(step, data, strategy="next_read")
        if not targets: return None, 0, 0
        target = rng.choice(targets)
        mutated_value = value_gen.generate_different(target.original_word)
        original_value = target.original_word
        config = {"mutation_type": "PRE_EXEC_REG_MOD", "step": target.step,
                  "txn_idx": target.txn_idx, "word": mutated_value, "strategy": target.strategy}
    elif kind == "INSTR_TYPE_MOD":
        target = get_instr_type_targets(step, data)
        if not target: return None, 0, 0
        new_major, new_minor, is_valid = generate_instr_mutation(target, rng)
        mutated_value = (new_major << 16) | new_minor
        original_value = (target.original_major << 16) | target.original_minor
        config = {"mutation_type": "INSTR_TYPE_MOD", "step": target.step,
                  "major": new_major, "minor": new_minor}
    elif kind == "MEM_VAL_MOD":
        targets = get_mem_val_targets(step, data)
        if not targets: return None, 0, 0
        target = rng.choice(targets)
        mutated_value = value_gen.generate_different(target.original_value)
        original_value = target.original_value
        config = {"mutation_type": "MEM_VAL_MOD", "step": target.step,
                  "txn_idx": target.txn_idx, "word": mutated_value}
    elif kind == "INSTR_WORD_MOD_FULL":
        target = get_instr_word_targets(step, data)
        if not target: return None, 0, 0
        mutated_value = value_gen.generate_different(target.original_word)
        original_value = target.original_word
        config = {"mutation_type": "INSTR_WORD_MOD", "step": target.step, "word": mutated_value}
    elif kind == "INSTR_WORD_MOD_SUR":
        target = get_instr_word_sur_targets(step, data)
        if target is None: return None, 0, 0
        instr = target.instruction
        sur_field = select_surgical_field(instr, rng)
        if sur_field is None: return None, 0, 0
        orig_field_val = instr.get_field_value(sur_field)
        new_field_val = generate_field_value(sur_field, orig_field_val, instr, rng)
        mutated_value = instr.encode_with_mutation(sur_field, new_field_val)
        original_value = target.original_word
        config = {"mutation_type": "INSTR_WORD_MOD", "step": target.step, "word": mutated_value}

    if config is None:
        return None, 0, 0
    fd, p = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    Path(p).write_text(json.dumps(config, indent=2))
    return p, mutated_value, original_value


def run_mutation(host, host_args, config_path):
    env = {
        **dict(os.environ),
        "A4_MUTATION_CONFIG": config_path,
        "CONSTRAINT_CONTINUE": "1",
        "A4_COVERAGE_TOUCH": "1",
        "A4_COVERAGE_TOUCH_VERBOSE": "1",
        "A4_GLOBAL_RESIDUE": "1",
        "A4_FAMILY_RESIDUE": "1",
    }
    result = subprocess.run([host] + host_args, capture_output=True, text=True, env=env)
    return result.stdout + result.stderr, result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--num", type=int, default=200)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("host_args", nargs="*")
    args = parser.parse_args()

    host, host_args, num, seed = args.host, args.host_args, args.num, args.seed
    print(f"Diagnostic campaign: {num} mutations, seed={seed}")

    # Inspection
    print("Running inspection...")
    data = InspectionData.from_inspection(host, host_args)
    print(data.summary())

    # Baseline
    print("Capturing baseline touch...")
    baseline = capture_baseline_touch(host, host_args)
    print(f"Baseline: {baseline.distinct_buckets} bitmap buckets")

    # Setup
    rng = random.Random(seed)
    selector = ZonedStepSelector(seed=seed)
    value_gen = create_generator("mixed", seed)

    params = CalibratedParams(tau_new=40.0, tau_d=3.0, K_T_rare=31, gamma=0.9965)
    state = CoverageState(params)
    state.seed_from_baseline(baseline.bitmap)

    # Also track exact sets for bitmap comparison
    global_bitmap = make_global_bitmap()
    merge_into_global(baseline.bitmap, global_bitmap)
    global_exact_set: Set[str] = set()

    # Accum (global constraint) tracking
    global_accum_bitmap = make_global_bitmap()
    global_accum_exact_set: Set[str] = set()

    results: List[RunResult] = []
    kind_counter: Counter = Counter()
    campaign_start = time.perf_counter()

    for i in range(num):
        kind = rng.choice(MUTATION_KINDS)
        kind_counter[kind] += 1

        config_path = None
        step = None
        for attempt in range(10):
            step = selector.select_step(data, kind)
            if step is None: break
            cp, mv, ov = create_mutation(kind, step, data, rng, value_gen)
            if cp is not None:
                config_path = cp
                break

        if config_path is None:
            print(f"  [{i+1}/{num}] SKIP {kind}")
            continue

        t0 = time.perf_counter()
        output, exit_code = run_mutation(host, host_args, config_path)
        exec_ms = (time.perf_counter() - t0) * 1000
        os.unlink(config_path)

        failures = parse_all_constraint_failures(output)
        bitmap = parse_touch_bitmap(output)
        verbose = parse_verbose_set(output)

        local_failures = [f for f in failures if f.phase == "local"]
        accum_failures = [f for f in failures if f.phase == "accum"]

        n_fail = len(failures)
        n_fail_local = len(local_failures)
        n_fail_accum = len(accum_failures)

        fail_ctx_local = set((f.constraint_loc(), f.major, f.minor) for f in local_failures)
        fail_ctx_accum = set((f.constraint_loc(), f.major, f.minor) for f in accum_failures)
        fail_ctx = fail_ctx_local | fail_ctx_accum
        d_fail = len(fail_ctx)
        d_fail_local = len(fail_ctx_local)
        d_fail_accum = len(fail_ctx_accum)
        r_rep = max(0, n_fail - d_fail)

        outcome, proof_generated = classify_outcome(output, exit_code, n_fail)
        crashed = exit_code in CRASH_SIGNALS

        # Local bitmap tracking
        if bitmap is not None:
            bitmap_delta = count_new_bits(bitmap, global_bitmap)
            bitmap_count = distinct_touched(bitmap)
            merge_into_global(bitmap, global_bitmap)
        else:
            bitmap_delta = 0
            bitmap_count = 0

        # Local exact set tracking
        if verbose is not None:
            exact_delta = len(verbose - global_exact_set)
            exact_count = len(verbose)
            global_exact_set.update(verbose)
        else:
            exact_delta = 0
            exact_count = 0

        # Accum bitmap tracking
        accum_bitmap = parse_accum_touch_bitmap(output)
        if accum_bitmap is not None:
            accum_bitmap_delta = count_new_bits(accum_bitmap, global_accum_bitmap)
            accum_bitmap_count = distinct_touched(accum_bitmap)
            merge_into_global(accum_bitmap, global_accum_bitmap)
        else:
            accum_bitmap_delta = 0
            accum_bitmap_count = 0

        # Accum exact set tracking
        accum_verbose = parse_accum_verbose(output)
        if accum_verbose is not None:
            accum_exact_delta = len(accum_verbose - global_accum_exact_set)
            accum_exact_count = len(accum_verbose)
            global_accum_exact_set.update(accum_verbose)
        else:
            accum_exact_delta = 0
            accum_exact_count = 0

        # Global hooks parsing
        global_residue = parse_global_residue(output)
        family_residues = parse_family_residues(output)
        family_details = parse_family_detail(output)

        # Build global summary string
        broken_families = []
        broken_addrs_str = ""
        if family_residues:
            for fr in family_residues:
                if fr.get("nonzero"):
                    broken_families.append(fr["family"])
        if family_details:
            for fd in family_details:
                if fd.get("broken_addrs"):
                    addrs = []
                    for a in fd["broken_addrs"][:3]:
                        addrs.append(a.get("reg", a.get("hex", str(a["addr"]))))
                    if fd.get("broken_count", 0) > 3:
                        addrs.append(f"+{fd['broken_count']-3}")
                    broken_addrs_str = "(" + ",".join(addrs) + ")"

        # REWARD COMPUTATION (revised formula)
        reward, diag = compute_reward(bitmap, failures, exit_code, outcome, proof_generated, state)
        update_state(bitmap, failures, exit_code, state)

        rr = RunResult(
            run_num=i+1, kind=kind, step=step, exit_code=exit_code,
            crashed=crashed, outcome=outcome, proof_generated=proof_generated,
            n_fail=n_fail, d_fail=d_fail, r_rep=r_rep,
            fail_context_ids=fail_ctx,
            bitmap_delta_new=bitmap_delta, exact_delta_new=exact_delta,
            exact_touched_count=exact_count, bitmap_touched_count=bitmap_count,
            reward=reward, diag=diag, execution_time_ms=exec_ms,
            n_fail_local=n_fail_local, n_fail_accum=n_fail_accum,
            d_fail_local=d_fail_local, d_fail_accum=d_fail_accum,
            fail_context_ids_local=fail_ctx_local, fail_context_ids_accum=fail_ctx_accum,
            accum_bitmap_delta_new=accum_bitmap_delta, accum_exact_delta_new=accum_exact_delta,
            accum_exact_touched_count=accum_exact_count, accum_bitmap_touched_count=accum_bitmap_count,
        )
        results.append(rr)

        touch_str = f" [bm:+{bitmap_delta} ex:+{exact_delta}]" if bitmap_delta > 0 or exact_delta > 0 else ""
        accum_touch_str = f" [abm:+{accum_bitmap_delta} aex:+{accum_exact_delta}]" if accum_bitmap_delta > 0 or accum_exact_delta > 0 else ""
        z_str = " [Z]" if diag.get("Z", 0) == 1 else ""
        g_str = ""
        if broken_families:
            g_str = f" G={','.join(broken_families)}{broken_addrs_str}"
        elif global_residue and not global_residue.get("nonzero"):
            g_str = " G=--"
        print(f"  [{i+1}/{num}] {kind} @ step {step}: {n_fail_local}Lf {n_fail_accum}Af {d_fail}d r={reward:.3f}{touch_str}{accum_touch_str}{g_str}{z_str} [{outcome}]")

    total_time = (time.perf_counter() - campaign_start) * 1000

    # ===== REPORT =====
    print("\n" + "=" * 70)
    print("DIAGNOSTIC CAMPAIGN REPORT (with revised reward)")
    print("=" * 70)

    print(f"\nCampaign: {len(results)} runs, seed={seed}, {total_time/1000:.0f}s total")
    outcomes = Counter(r.outcome for r in results)
    for o in ["REJECTED", "CRASH", "NO_EFFECT", "ACCEPTED"]:
        print(f"  {o}: {outcomes.get(o, 0)}")

    # Touch coverage
    print(f"\n--- TOUCH COVERAGE ---")
    print(f"Final bitmap buckets: {distinct_touched(bytes(global_bitmap))}")
    print(f"Final exact triples: {len(global_exact_set)}")
    print(f"Hash collisions: {len(global_exact_set) - distinct_touched(bytes(global_bitmap))}")

    # Failure coverage (combined)
    all_fail_ctx = set()
    all_fail_locs = set()
    for r in results:
        all_fail_ctx.update(r.fail_context_ids)
        all_fail_locs.update(loc for loc, _, _ in r.fail_context_ids)
    print(f"\n--- FAILURE COVERAGE (combined) ---")
    print(f"Distinct constraint_loc families: {len(all_fail_locs)}")
    print(f"Distinct (loc,major,minor) context_ids: {len(all_fail_ctx)}")

    # Local failure coverage
    all_local_ctx = set()
    all_local_locs = set()
    for r in results:
        if r.fail_context_ids_local:
            all_local_ctx.update(r.fail_context_ids_local)
            all_local_locs.update(loc for loc, _, _ in r.fail_context_ids_local)
    print(f"\n--- LOCAL FAILURE COVERAGE ---")
    print(f"Distinct local constraint_loc families: {len(all_local_locs)}")
    print(f"Distinct local (loc,major,minor) context_ids: {len(all_local_ctx)}")

    # Accum failure coverage
    all_accum_ctx = set()
    all_accum_locs = set()
    for r in results:
        if r.fail_context_ids_accum:
            all_accum_ctx.update(r.fail_context_ids_accum)
            all_accum_locs.update(loc for loc, _, _ in r.fail_context_ids_accum)
    runs_with_accum = sum(1 for r in results if r.n_fail_accum > 0)
    print(f"\n--- ACCUM FAILURE COVERAGE ---")
    print(f"Distinct accum constraint_loc families: {len(all_accum_locs)}")
    print(f"Distinct accum (loc,major,minor) context_ids: {len(all_accum_ctx)}")
    print(f"Runs with accum failures: {runs_with_accum}/{len(results)}")

    # Accum touch coverage
    print(f"\n--- ACCUM TOUCH COVERAGE ---")
    print(f"Final accum bitmap buckets: {distinct_touched(bytes(global_accum_bitmap))}")
    print(f"Final accum exact triples: {len(global_accum_exact_set)}")

    # Phase breakdown
    local_only = sum(1 for r in results if r.n_fail_local > 0 and r.n_fail_accum == 0)
    accum_only = sum(1 for r in results if r.n_fail_local == 0 and r.n_fail_accum > 0)
    both_phases = sum(1 for r in results if r.n_fail_local > 0 and r.n_fail_accum > 0)
    no_failures = sum(1 for r in results if r.n_fail == 0)
    print(f"\n--- PHASE BREAKDOWN ---")
    print(f"Runs with local-only failures: {local_only}")
    print(f"Runs with accum-only failures: {accum_only}")
    print(f"Runs with both local + accum failures: {both_phases}")
    print(f"Runs with no failures: {no_failures}")

    # Global constraint summary
    print(f"\n--- GLOBAL CONSTRAINT SUMMARY ---")
    # Note: global_residue and family data are not stored in RunResult yet,
    # so we re-scan from the run output. For now, use the per-run parsed data.
    # We stored broken_families in the display string; let's count from residues.
    # Since we don't persist family_residues in RunResult, just report what we showed per-run.
    global_nz_count = sum(1 for r in results if r.n_fail_local == 0 and r.n_fail_accum == 0
                          and r.outcome == "REJECTED")
    print(f"Global-only runs (0 local, 0 accum, REJECTED): {global_nz_count}")

    # Reward distributions
    print(f"\n--- REWARD BY KIND ---")
    for kind in MUTATION_KINDS:
        kr = [r.reward for r in results if r.kind == kind]
        if kr:
            print(f"  {kind:25s}: n={len(kr):3d}  min={min(kr):.3f}  median={statistics.median(kr):.3f}  "
                  f"mean={statistics.mean(kr):.3f}  max={max(kr):.3f}  stdev={statistics.stdev(kr) if len(kr)>1 else 0:.3f}")

    # Overall reward stats
    all_r = [r.reward for r in results]
    print(f"\n  ALL: n={len(all_r)}  min={min(all_r):.3f}  median={statistics.median(all_r):.3f}  "
          f"mean={statistics.mean(all_r):.3f}  max={max(all_r):.3f}  stdev={statistics.stdev(all_r):.3f}")

    # Component breakdown by kind
    print(f"\n--- REWARD COMPONENTS (mean per kind) ---")
    print(f"  {'Kind':25s} {'T_new':>6s} {'T_rare':>6s} {'F_new':>6s} {'F_rare':>6s} {'Z':>4s} {'Q':>6s}")
    for kind in MUTATION_KINDS:
        kr = [r for r in results if r.kind == kind]
        if kr:
            print(f"  {kind:25s} {statistics.mean([r.diag['T_new'] for r in kr]):6.3f} "
                  f"{statistics.mean([r.diag['T_rare'] for r in kr]):6.3f} "
                  f"{statistics.mean([r.diag['F_new'] for r in kr]):6.3f} "
                  f"{statistics.mean([r.diag['F_rare'] for r in kr]):6.3f} "
                  f"{sum(r.diag['Z'] for r in kr):4d} "
                  f"{statistics.mean([r.diag['Q'] for r in kr]):6.3f}")

    # Z-event analysis
    z_runs = [r for r in results if r.diag.get("Z", 0) == 1]
    print(f"\n--- Z-EVENT ANALYSIS ---")
    print(f"Total Z events: {len(z_runs)}")
    if z_runs:
        print(f"Z-event rewards: min={min(r.reward for r in z_runs):.3f} max={max(r.reward for r in z_runs):.3f} mean={statistics.mean([r.reward for r in z_runs]):.3f}")
        z_kinds = Counter(r.kind for r in z_runs)
        for k, c in z_kinds.most_common():
            print(f"  {k}: {c}")
    non_z = [r for r in results if r.diag.get("Z", 0) == 0 and not r.crashed]
    if non_z:
        print(f"Non-Z non-crash rewards: mean={statistics.mean([r.reward for r in non_z]):.3f}")

    # Cascade analysis
    cascade_runs = [r for r in results if r.r_rep > 10]
    print(f"\n--- CASCADE ANALYSIS ---")
    print(f"Runs with r_rep > 10: {len(cascade_runs)}")
    for r in sorted(cascade_runs, key=lambda x: -x.r_rep)[:5]:
        print(f"  Run {r.run_num} ({r.kind}): n_fail={r.n_fail} d_fail={r.d_fail} r_rep={r.r_rep} "
              f"Q_rep={r.diag['Q_rep']:.3f} Q={r.diag['Q']:.3f} reward={r.reward:.3f}")

    # Top 10 rewards
    print(f"\n--- TOP 10 HIGHEST REWARDS ---")
    for r in sorted(results, key=lambda x: -x.reward)[:10]:
        print(f"  Run {r.run_num} ({r.kind:20s}) r={r.reward:.3f} T_new={r.diag['T_new']:.2f} "
              f"F_new={r.diag['F_new']:.2f} F_rare={r.diag['F_rare']:.2f} Z={r.diag['Z']} Q={r.diag['Q']:.2f}")

    # Failure context_id novelty curve
    print(f"\n--- FAILURE CONTEXT_ID NOVELTY ---")
    running_ctx: Set[Tuple[str, int, int]] = set()
    novel_runs = 0
    milestones = {1, 10, 25, 50, 100, 150, 200}
    for r in results:
        new_ctx = r.fail_context_ids - running_ctx
        if new_ctx:
            novel_runs += 1
        running_ctx.update(r.fail_context_ids)
        if r.run_num in milestones:
            print(f"  After run {r.run_num}: {len(running_ctx)} distinct context_ids ({novel_runs} novel runs so far)")
    print(f"  Final: {len(running_ctx)} distinct, {novel_runs}/{len(results)} runs had new context_ids")

    print(f"\nDone.")


if __name__ == "__main__":
    main()
