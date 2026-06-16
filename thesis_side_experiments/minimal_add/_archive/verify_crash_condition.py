#!/usr/bin/env python3
"""EXHAUSTIVE verification of the M3 preflight-panic condition.

Question: is the panic pathological to PRE_EXEC_REG_MOD, or specific to injecting
a register the instruction at the inject step accesses that same cycle?

Hypothesis: crash (preflight.rs:227) <=> injected register is consumed by the
instruction at the inject step. At step 187 (`add s0,a0,a1`) that set is
{a0,a1,s0}; every other register injects fine (witgen completes).

Part A: full prove for EVERY distinct register target found at step 187.
Part B: fix one operand-hitting seed (register is seed-determined, step-independent)
        and inject across a sweep of steps; the crash should track only the steps
        where that register is consumed.

Existing host binary only; no rebuild; no changes outside this dir.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "verify_crash"
HOST = ROOT / "target/release/thesis-minimal-host"
ADD_STEP = 187
OPERANDS = {"a0", "a1", "s0"}
SWEEP_MAX = 500
STEP_SWEEP = [184, 185, 186, 187, 188, 189]
MAX_WORKERS = 4

FULL_ENV_EXTRA = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_FAMILY_RESIDUE": "1",
}

FAULT_RE = re.compile(r"<fault>(\{.*?\})</fault>")
INFO_REG_RE = re.compile(r"^\s*([a-z][0-9a-z]*)\s*=")
PANIC_RE = re.compile(r"panicked at ([^\n]+?:\d+)")


def cmd(seed: int, step: int) -> List[str]:
    return [
        str(HOST), "--trace", "--inject",
        "--inject-step", str(step),
        "--inject-kind", "PRE_EXEC_REG_MOD",
        "--seed", str(seed),
    ]


def quick_register(seed: int, step: int = ADD_STEP) -> Optional[str]:
    proc = subprocess.Popen(cmd(seed, step), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    reg: Optional[str] = None
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            m = FAULT_RE.search(line)
            if not m:
                continue
            obj = json.loads(m.group(1))
            if obj.get("step") != step:
                continue
            mm = INFO_REG_RE.match(obj.get("info", ""))
            if mm:
                reg = mm.group(1)
            proc.kill()
            break
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return reg


def run_full(seed: int, step: int) -> Dict[str, object]:
    env = {**dict(os.environ), **FULL_ENV_EXTRA}
    try:
        proc = subprocess.run(cmd(seed, step), capture_output=True, text=True,
                              env=env, timeout=300)
        out = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return {"seed": seed, "step": step, "timeout": True}
    pm = PANIC_RE.search(out)
    panic_loc = pm.group(1) if pm else None
    preflight_crash = panic_loc is not None and "preflight.rs:227" in panic_loc
    fault = None
    fm = FAULT_RE.search(out)
    if fm:
        info = json.loads(fm.group(1)).get("info", "")
        rmatch = INFO_REG_RE.match(info)
        fault = rmatch.group(1) if rmatch else info
    return {
        "seed": seed,
        "step": step,
        "fault_register": fault,
        "returncode": rc,
        "panic_loc": panic_loc,
        "preflight_crash": preflight_crash,
        "witgen_completed": not preflight_crash,
        "constraint_fail_count": len(re.findall(r"<constraint_fail>", out)),
    }


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)

    # ---- discover register -> first seed at step 187 ----
    print(f"[sweep] seeds 0..{SWEEP_MAX-1} at step {ADD_STEP} ...", flush=True)
    reg_to_seed: Dict[str, int] = {}
    for seed in range(SWEEP_MAX):
        r = quick_register(seed)
        if r and r not in reg_to_seed:
            reg_to_seed[r] = seed
    print(f"[sweep] {len(reg_to_seed)} distinct registers: "
          f"{sorted(reg_to_seed)}", flush=True)

    # ---- Part A: full prove for EVERY distinct register ----
    print(f"[A] full prove for all {len(reg_to_seed)} registers "
          f"(parallel x{MAX_WORKERS}) ...", flush=True)
    jobs = [(r, s) for r, s in reg_to_seed.items()]
    part_a: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(run_full, s, ADD_STEP): r for r, s in jobs}
        for fut in futs:
            res = fut.result()
            res["register"] = futs[fut]
            res["is_operand"] = futs[fut] in OPERANDS
            part_a.append(res)
            print(f"  [{res['register']:<4}] seed={res['seed']:<4} "
                  f"preflight_crash={res.get('preflight_crash')} "
                  f"cfails={res.get('constraint_fail_count')} "
                  f"loc={res.get('panic_loc')}", flush=True)
    part_a.sort(key=lambda x: (not x["is_operand"], x["register"]))

    # ---- Part B: fix an operand-hitting seed, sweep the inject step ----
    a1_seed = reg_to_seed.get("a1")
    part_b: List[Dict[str, object]] = []
    if a1_seed is not None:
        print(f"[B] seed={a1_seed} (hits a1), sweep steps {STEP_SWEEP} ...", flush=True)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(run_full, a1_seed, st): st for st in STEP_SWEEP}
            for fut in futs:
                res = fut.result()
                part_b.append(res)
                print(f"  step={res['step']:<4} fault_reg={res.get('fault_register')} "
                      f"preflight_crash={res.get('preflight_crash')} "
                      f"cfails={res.get('constraint_fail_count')} "
                      f"loc={res.get('panic_loc')}", flush=True)
        part_b.sort(key=lambda x: x["step"])

    # ---- evaluate ----
    operand_rows = [r for r in part_a if r["is_operand"]]
    nonop_rows = [r for r in part_a if not r["is_operand"]]
    a_holds = (
        len(operand_rows) == 3
        and all(r["preflight_crash"] for r in operand_rows)
        and all(not r["preflight_crash"] for r in nonop_rows)
        and len(nonop_rows) > 0
    )

    report = {
        "inject_step": ADD_STEP,
        "operands": sorted(OPERANDS),
        "registers_to_seed": reg_to_seed,
        "part_a_all_registers": part_a,
        "part_b_step_sweep": part_b,
        "part_a_hypothesis": "preflight crash <=> register in {a0,a1,s0}",
        "part_a_holds": a_holds,
    }
    (ART / "verify_report.json").write_text(json.dumps(report, indent=2))

    print("\n=== PART A: all registers @ step 187 ===")
    print(f"{'reg':<5}{'operand':<9}{'seed':<6}{'preflight_crash':<17}{'cfails':<8}{'panic_loc'}")
    for r in part_a:
        print(f"{r['register']:<5}{str(r['is_operand']):<9}{r['seed']:<6}"
              f"{str(r.get('preflight_crash')):<17}{r.get('constraint_fail_count'):<8}"
              f"{r.get('panic_loc')}")
    print(f"\nPART A holds (crash <=> operand): {a_holds}")

    if part_b:
        print("\n=== PART B: a1-seed across steps ===")
        print(f"{'step':<6}{'fault_reg':<11}{'preflight_crash':<17}{'cfails':<8}{'panic_loc'}")
        for r in part_b:
            print(f"{r['step']:<6}{str(r.get('fault_register')):<11}"
                  f"{str(r.get('preflight_crash')):<17}{r.get('constraint_fail_count'):<8}"
                  f"{r.get('panic_loc')}")

    print(f"\nreport: {ART / 'verify_report.json'}")


if __name__ == "__main__":
    main()
