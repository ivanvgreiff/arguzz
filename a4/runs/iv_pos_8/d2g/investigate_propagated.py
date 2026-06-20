#!/usr/bin/env python3
"""Deep investigation of propagated vs noop accept triage (ad-hoc)."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

from a4.arguzz_dependent.arguzz_parser import parse_all_faults, parse_all_traces
from a4.standalone.arguzz_invoke import _decode_safe, parse_prover_status, run as arguzz_run
from a4.standalone.mutations.arguzz_bridge import DEFAULT_ARGUZZ_SUBPROCESS_ENV

HOST = os.environ.get("A4_TEST_HOST", "workspace/output/target/release/risc0-host")
HOST_ARGS = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").split()
DB = REPO / "a4/runs/iv_pos_8/d2f/smoke/d2f_smoke_b1/pos_iv_pos_8_d2f_V6_cTS_seed1234_n100/run.db"

PROP = {2726, 1648, 3939}
NOOP = {174, 524, 618, 3961, 3931}


def run_baseline_trace() -> Tuple[str, List]:
    env = {**os.environ, "CONSTRAINT_CONTINUE": "1", **DEFAULT_ARGUZZ_SUBPROCESS_ENV}
    cmd = [HOST, "--trace", *HOST_ARGS]
    proc = subprocess.run(cmd, capture_output=True, timeout=120, env=env)
    stdout = _decode_safe(proc.stdout) + _decode_safe(proc.stderr)
    traces = parse_all_traces(stdout)
    return stdout, traces


def run_inject_trace(step: int, kind: str, seed: int) -> Tuple[str, object]:
    r = arguzz_run(
        HOST, HOST_ARGS, step=step, kind=kind, seed=seed,
        include_trace=True, env=dict(DEFAULT_ARGUZZ_SUBPROCESS_ENV), timeout=120,
    )
    return r.raw_stdout, r


def trace_key(t) -> Tuple:
    return (t.step, t.pc, t.instruction, t.assembly)


def first_divergence(base: List, fault: List) -> Optional[dict]:
    bm = {t.step: t for t in base}
    fm = {t.step: t for t in fault}
    all_steps = sorted(set(bm) | set(fm))
    for s in all_steps:
        b, f = bm.get(s), fm.get(s)
        if b is None:
            return {"step": s, "reason": "step_only_in_fault", "fault": asdict(f) if f else None}
        if f is None:
            return {"step": s, "reason": "step_only_in_baseline", "base": asdict(b)}
        if trace_key(b) != trace_key(f):
            return {
                "step": s,
                "reason": "field_mismatch",
                "baseline": asdict(b),
                "fault": asdict(f),
            }
    if len(base) != len(fault):
        return {"step": None, "reason": "same_steps_different_count", "base_n": len(base), "fault_n": len(fault)}
    return None


def count_constraint_fails(stdout: str) -> int:
    return stdout.count("<constraint_fail>")


def main() -> None:
    accepts = []
    with sqlite3.connect(DB) as conn:
        for row in conn.execute("""
            SELECT m.id, m.step, m.kind, m.config_json
            FROM mutations m
            WHERE json_extract(m.config_json,'$.soundness_signal')=1
            ORDER BY m.step
        """):
            cfg = json.loads(row[3])
            accepts.append({
                "id": row[0], "step": row[1], "kind": row[2],
                "iter_seed": cfg["seed"], "opcode_class": cfg.get("opcode_class"),
                "pre_post": cfg.get("pre_post"),
            })

    print("=" * 70)
    print("PHASE 1: Baseline --trace (no inject)")
    print("=" * 70)
    base_stdout, base_traces = run_baseline_trace()
    base_digest = hashlib.sha256(json.dumps([trace_key(t) for t in base_traces]).encode()).hexdigest()[:16]
    print(f"  trace_records={len(base_traces)} digest_prefix={base_digest}")
    print(f"  prover={parse_prover_status(base_stdout)} constraint_fails={count_constraint_fails(base_stdout)}")

    print("\n" + "=" * 70)
    print("PHASE 2: Per-accept inject --trace rerun vs baseline")
    print("=" * 70)

    results = []
    for acc in accepts:
        step = acc["step"]
        label = "PROPAGATED" if step in PROP else ("NOOP" if step in NOOP else "?")
        raw, inv = run_inject_trace(step, acc["kind"], acc["iter_seed"])
        faults = parse_all_faults(raw)
        traces = inv.traces
        div = first_divergence(base_traces, traces)
        digest = hashlib.sha256(json.dumps([trace_key(t) for t in traces]).encode()).hexdigest()[:16]
        same_full = digest == base_digest
        results.append({**acc, "label": label, "div": div, "same_full": same_full,
                        "n_faults": len(faults), "n_traces": len(traces),
                        "traces": traces,
                        "outcome": inv.outcome.name, "prover": inv.prover_status,
                        "soundness_signal": inv.soundness_signal,
                        "local_failures": len(inv.failures),
                        "constraint_fails_stdout": count_constraint_fails(raw),
                        "faults": faults})

        print(f"\n--- step={step} ({label}) opcode={acc['opcode_class']} iter_seed={acc['iter_seed']} ---")
        print(f"  outcome={inv.outcome.name} prover={inv.prover_status} soundness={inv.soundness_signal}")
        print(f"  faults_parsed={len(faults)} traces={len(traces)} digest_prefix={digest} full_hash_match={same_full}")
        print(f"  constraint_fail_tags={count_constraint_fails(raw)} parsed_failures={len(inv.failures)}")
        if faults:
            f0 = faults[0]
            print(f"  fault@step={f0.step} pc={hex(f0.pc)} orig={f0.original_value} mut={f0.mutated_value}")
        if div:
            print(f"  FIRST_DIVERGENCE: {json.dumps(div, indent=4)}")
        else:
            print("  FIRST_DIVERGENCE: none (identical trace keys)")

    print("\n" + "=" * 70)
    print("PHASE 3: Hypothesis — inject-at-step vs baseline (expected diff at inject step)")
    print("=" * 70)
    for r in results:
        step = r["step"]
        bm = {t.step: t for t in base_traces}
        if step in bm and r["faults"]:
            bt = bm[step]
            print(f"  step={step} ({r['label']}): baseline_insn={bt.instruction} asm={bt.assembly[:60]}")

    print("\n" + "=" * 70)
    print("PHASE 4: Post-fault-only divergence (steps > inject_step)")
    print("=" * 70)
    for r in results:
        step = r["step"]
        bm = {t.step: t for t in base_traces}
        fm = {t.step: t for t in r["traces"]}
        post_diffs = []
        for s in sorted(set(bm) & set(fm)):
            if s <= step:
                continue
            if trace_key(bm[s]) != trace_key(fm[s]):
                post_diffs.append(s)
        print(f"  step={step} ({r['label']}): post_inject_diff_count={len(post_diffs)} "
              f"first_post_diff={post_diffs[0] if post_diffs else None}")

    print("\n" + "=" * 70)
    print("PHASE 5: Campaign stdout cross-check (original POS run logs)")
    print("=" * 70)
    stdout_log = DB.parent / "stdout.log"
    if stdout_log.is_file():
        text = stdout_log.read_text(errors="replace")
        for acc in accepts:
            step = acc["step"]
            # campaign logs mutation blocks — search for step references
            hits = [ln for ln in text.splitlines() if f"step={step}" in ln.lower() or f"step {step}" in ln.lower()]
            print(f"  step={step}: campaign_log_hits={len(hits)}")
            for h in hits[:2]:
                print(f"    {h[:120]}")


if __name__ == "__main__":
    main()
