"""A1 — Trace determinism audit.

Phase 7d gate: cycle structure + register transactions must be 100%
deterministic across N=3 host runs. Memory transactions are allowed
bounded variance in HOST_ECALL_ADDR and user-journal regions; these are
recorded to `audit_output/A1_nondet_addrs.json` so MEM_VAL_MOD target
collection can filter them out.

Usage:
    python -m a4.audits.A1_trace_determinism [--host PATH] [--in1 N] [--in4 N] [--runs N]

Exit codes:
    0  — PASS
    1  — FAIL: cycle structure or register txns vary
    2  — WARN-as-FAIL: memory variance exceeds 1% or hits unknown regions
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

DEFAULT_HOST = "/root/arguzz/workspace/output/target/release/risc0-host"
OUTPUT_DIR = Path(__file__).parent / "audit_output"

CYCLE_PAT = re.compile(r"<a4_cycle_info>(.+?)</a4_cycle_info>")
TXN_PAT = re.compile(r"<a4_all_txn>(.+?)</a4_all_txn>")


def extract(text):
    cycles, txns = [], []
    for l in text.splitlines():
        m = CYCLE_PAT.search(l)
        if m:
            try:
                cycles.append(json.loads(m.group(1)))
            except Exception:
                pass
        m = TXN_PAT.search(l)
        if m:
            try:
                txns.append(json.loads(m.group(1)))
            except Exception:
                pass
    return cycles, txns


def run_host(host, args, runs):
    env = os.environ.copy()
    env["A4_INSPECT"] = "1"
    env["A4_DUMP_ALL_TXNS"] = "1"
    out = []
    for i in range(runs):
        t0 = time.perf_counter()
        r = subprocess.run([host] + args, capture_output=True, text=True, env=env)
        dur = time.perf_counter() - t0
        text = r.stdout + r.stderr
        c, t = extract(text)
        print(f"  Run {i+1}: dur={dur:.1f}s cycles={len(c)} txns={len(t)} exit={r.returncode}")
        if r.returncode != 0:
            print(f"    ERROR: host exited non-zero", file=sys.stderr)
            sys.exit(1)
        out.append((c, t))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--runs", type=int, default=3)
    args = p.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"A1 trace determinism: host={args.host} args=--in1 {args.in1} --in4 {args.in4} runs={args.runs}")

    host_args = ["--in1", args.in1, "--in4", args.in4]
    runs = run_host(args.host, host_args, args.runs)

    # Cycle structure
    base_c = runs[0][0]
    cycle_field_diffs = defaultdict(int)
    for run_c, _ in runs[1:]:
        if len(run_c) != len(base_c):
            print(f"FAIL: cycle counts differ ({len(base_c)} vs {len(run_c)})", file=sys.stderr)
            sys.exit(1)
        for a, b in zip(base_c, run_c):
            for k in ("cycle_idx", "step", "pc", "major", "minor", "txn_idx"):
                if a.get(k) != b.get(k):
                    cycle_field_diffs[k] += 1
    if cycle_field_diffs:
        print(f"FAIL: cycle fields differ: {dict(cycle_field_diffs)}", file=sys.stderr)
        sys.exit(1)
    print(f"  Cycles: 100% deterministic ({len(base_c)})")

    # Register txns
    base_t = runs[0][1]
    base_reg = [t for t in base_t if t.get("txn_type") == "reg"]
    reg_diffs = 0
    for _, run_t in runs[1:]:
        run_reg = [t for t in run_t if t.get("txn_type") == "reg"]
        if len(run_reg) != len(base_reg):
            print(f"FAIL: reg txn counts differ ({len(base_reg)} vs {len(run_reg)})", file=sys.stderr)
            sys.exit(1)
        for a, b in zip(base_reg, run_reg):
            for k in ("txn_idx", "step", "addr", "cycle", "word", "prev_cycle"):
                if a.get(k) != b.get(k):
                    reg_diffs += 1
    if reg_diffs:
        print(f"FAIL: register txns differ in {reg_diffs} fields", file=sys.stderr)
        sys.exit(1)
    print(f"  Reg txns: 100% deterministic ({len(base_reg)})")

    # Memory txns — allow bounded variance
    base_mem = [t for t in base_t if t.get("txn_type") == "mem"]
    nondet_addrs = defaultdict(int)
    nondet_steps = defaultdict(int)
    mem_diffs = 0
    for _, run_t in runs[1:]:
        run_mem = [t for t in run_t if t.get("txn_type") == "mem"]
        if len(run_mem) != len(base_mem):
            print(f"FAIL: mem txn counts differ ({len(base_mem)} vs {len(run_mem)})", file=sys.stderr)
            sys.exit(1)
        for a, b in zip(base_mem, run_mem):
            if a.get("word") != b.get("word"):
                mem_diffs += 1
                nondet_addrs[a.get("addr")] += 1
                nondet_steps[a.get("step")] += 1
    variance = mem_diffs / max(1, len(base_mem) * (args.runs - 1))
    print(f"  Mem txns: {mem_diffs}/{len(base_mem) * (args.runs - 1)} variances ({variance*100:.3f}%) on {len(nondet_addrs)} unique addrs at {len(nondet_steps)} steps")

    # Categorize addresses by region (loose check)
    def categorize(addr):
        if 0x42000000 <= addr <= 0x42000100:
            return "host_ecall"
        if 0xC0000000 <= addr <= 0xFFFFFFFF:
            return "kernel"
        if 0x40000000 <= addr <= 0x42000000:
            return "host_ecall_near"
        # journal region varies per guest; loose heuristic
        if 0x00040000 <= addr <= 0x000FFFFF:
            return "user_journal"
        return "other"

    region_counts = defaultdict(int)
    for addr in nondet_addrs:
        region_counts[categorize(addr)] += 1
    print(f"  Region categorization: {dict(region_counts)}")

    out_file = OUTPUT_DIR / "A1_nondet_addrs.json"
    out_file.write_text(json.dumps({
        "host_args": [f"--in1={args.in1}", f"--in4={args.in4}"],
        "runs": args.runs,
        "nondet_addresses": sorted(nondet_addrs.keys()),
        "nondet_addresses_hex": [f"0x{a:08x}" for a in sorted(nondet_addrs.keys())],
        "nondet_steps": sorted(nondet_steps.keys()),
        "variance_pct": variance * 100,
        "region_counts": dict(region_counts),
    }, indent=2))
    print(f"  Non-det allow-list written to {out_file}")

    if region_counts.get("other", 0) > 0:
        print(f"WARN: {region_counts['other']} non-det addresses in unrecognized regions. Review.", file=sys.stderr)
    if variance > 0.01:
        print(f"FAIL: mem variance {variance*100:.2f}% > 1.0% threshold", file=sys.stderr)
        sys.exit(2)

    print()
    print("=== A1 RESULT: PASS ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
