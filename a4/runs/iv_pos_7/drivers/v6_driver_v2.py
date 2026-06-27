#!/usr/bin/env python3
"""
V6 (arguzz) driver — v2: uses A4's FULL compressed_global_coverage extractor
so V6 produces IDENTICAL ctx_key schema as V0-V5.

Pipeline differences vs v1:
  - Bootstrap: now does TWO host calls
       (a) host --trace  (for arguzz scheduler's instruction-to-steps map)
       (b) InspectionData.from_inspection  (A4_INSPECT/A4_DUMP_ALL_TXNS for cycles+txns)
  - Compresses globals via a4.standalone.compressed_global_extractor.extract_compressed_global_contexts
    with mutation_zone (from classify_zones) + mutation_major (from inspection cycles).
  - Patches _TXN_ROLE_BY_KIND to map arguzz-only kinds to A4's existing txn_role
    vocabulary, keeping the ctx_key SPACE consistent across all variants.

Usage:
  python3 v6_driver_v2.py \\
      --host /root/a4_campaign/bin/risc0-host \\
      --db /root/results/v6_seed1234.db \\
      --seed 1234 --num 6000 \\
      --label v6_arguzz \\
      -- --in1 5 --in4 10
"""

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from random import Random

# ----------------------------- A4 reuse via PYTHONPATH ----------------------- #
A4_REPO = os.environ.get("A4_REPO", "/root/a4_campaign/repo")
if A4_REPO not in sys.path:
    sys.path.insert(0, A4_REPO)

# Imports below are MANDATORY for v2 (we hard-require A4 helpers for metric parity).
from a4.core.touch_coverage import (
    parse_family_residues,
    parse_family_detail,
    parse_global_residue,
)
from a4.core.inspection_data import InspectionData
from a4.standalone.zone_classifier import classify_zones
from a4.standalone import compressed_global_extractor as _cge
from a4.standalone.compressed_global_extractor import (
    extract_compressed_global_contexts,
    to_storage_rows,
)

# ---------------------------------------------------------------------------- #
# Patch _TXN_ROLE_BY_KIND so arguzz-only kinds use A4's existing role
# vocabulary {ifetch, read, write, register, prev_word, prev_cycle}. This keeps
# the ctx_key SPACE identical across V0-V6 — every variant's memory contexts
# live in the same coordinate system (region × bucket × role × phase).
#
# Rationale per kind (matches A4's _TXN_ROLE_BY_KIND semantics):
#   PRE/POST_EXEC_PC_MOD : modifies the PC (which is fetched as part of the
#                          instruction-fetch txn). → "ifetch"
#   BR_NEG_COND          : flips a branch decision (decoded from the fetched
#                          instruction word). → "ifetch"
#   POST_EXEC_REG_MOD    : like PRE_EXEC_REG_MOD but after instruction execution.
#                          Both touch the register file. → "register"
#   PRE_EXEC_MEM_MOD     : mutates a random memory address before execution.
#                          Conservatively → "read" (no read/write semantic).
#   POST_EXEC_MEM_MOD    : mutates a random memory address after execution.
#                          → "write" (matches STORE_OUT_MOD).
# ---------------------------------------------------------------------------- #

_ARGUZZ_KIND_ROLE_EXTENSIONS = {
    "PRE_EXEC_PC_MOD":     "ifetch",
    "POST_EXEC_PC_MOD":    "ifetch",
    "BR_NEG_COND":         "ifetch",
    "POST_EXEC_REG_MOD":   "register",
    "PRE_EXEC_MEM_MOD":    "read",
    "POST_EXEC_MEM_MOD":   "write",
}
for k, v in _ARGUZZ_KIND_ROLE_EXTENSIONS.items():
    # Do not overwrite an existing entry — preserves A4's authoritative mapping.
    _cge._TXN_ROLE_BY_KIND.setdefault(k, v)


# ============================================================================ #
#                           Output parsers (regex)                              #
# ============================================================================ #

_TRACE_RE = re.compile(r"<trace>(\{.*?\})</trace>")
_CFAIL_RE = re.compile(r"<constraint_fail>(\{.*?\})</constraint_fail>")
_PROVER_REC_RE = re.compile(
    r'<record>\{"context":"Prover",\s*"status":"(\w+)"(?:,\s*"time":"([^"]+)")?\}</record>'
)


def parse_trace_steps(stdout: str):
    out = []
    for m in _TRACE_RE.findall(stdout):
        try:
            d = json.loads(m)
            out.append((int(d["step"]), int(d["pc"]), d["instruction"], d.get("assembly", "")))
        except Exception:
            continue
    return out


def parse_constraint_failures(stdout: str):
    out = []
    for m in _CFAIL_RE.findall(stdout):
        try:
            out.append(json.loads(m))
        except Exception:
            continue
    return out


def parse_prover_status(stdout: str):
    matches = _PROVER_REC_RE.findall(stdout)
    if not matches:
        return ("none", None)
    return matches[-1]


# ============================================================================ #
#                            Arguzz scheduler                                   #
# ============================================================================ #
#
# Faithful re-implementation of
#   libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/injection.py::InjectionContext
# with PREFERRED_INSTRUCTIONS = [] (the risc0 default per
# projects/risc0-fuzzer/risc0_fuzzer/settings.py:70).
#
# Algorithm (per call):
#   1. Filter candidate InstrKinds in trace to those with any available
#      injection kind.
#   2. Pick the InstrKind with the minimum cumulative selection count
#      (balanced round-robin); ties broken by rng.choice.
#   3. Pick a step uniformly at random from all trace steps with that instr.
#   4. Pick an injection kind uniformly at random from the kinds valid for
#      that instruction class (computed by InjectionKind.retrieve_injection_types
#      ∩ ENABLED_INJECTION_KINDS).

INSTR_KINDS = {
    "add", "sub", "xor", "or", "and", "slt", "sltu",
    "addi", "xori", "ori", "andi", "slti", "sltiu",
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    "jal", "jalr", "lui", "auipc",
    "sll", "slli", "mul", "mulh", "mulhsu", "mulhu",
    "srl", "sra", "srli", "srai",
    "div", "divu", "rem", "remu",
    "lb", "lh", "lw", "lbu", "lhu",
    "sb", "sh", "sw",
    "eany", "mret", "invalid",
}
BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}
LOADS = {"lb", "lh", "lw", "lbu", "lhu"}
STORES = {"sb", "sh", "sw"}
COMPUTATIONS = {
    "add", "sub", "xor", "or", "and", "slt", "sltu",
    "addi", "xori", "ori", "andi", "slti", "sltiu",
    "lui", "auipc",
    "sll", "slli", "mul", "mulh", "mulhsu", "mulhu",
    "srl", "sra", "srli", "srai",
    "div", "divu", "rem", "remu",
}
ENABLED_KINDS = [
    "PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD",
    "BR_NEG_COND", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD",
    "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD",
    "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD",
]


def valid_injection_kinds_for_instr(instr: str):
    instr = instr.lower()
    result = {
        "PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD",
        "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD",
        "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD",
    }
    if instr in BRANCHES:
        result.add("BR_NEG_COND")
    if instr in COMPUTATIONS:
        result.add("COMP_OUT_MOD")
    if instr in LOADS:
        result.add("LOAD_VAL_MOD")
    if instr in STORES:
        result.add("STORE_OUT_MOD")
    return sorted(result & set(ENABLED_KINDS))


def normalize_instr(s: str) -> str:
    return s.lower().replace("_", "").replace(".", "")


class ArguzzScheduler:
    def __init__(self, instr_to_steps, rng):
        self._instr_to_steps = instr_to_steps
        self._rng = rng
        self._counter = {}
        self._candidate_instrs = sorted(
            k for k in instr_to_steps
            if k in INSTR_KINDS and len(valid_injection_kinds_for_instr(k)) > 0
        )
        if not self._candidate_instrs:
            raise RuntimeError(f"no candidate instructions found in trace: {sorted(instr_to_steps)}")

    def pick(self):
        min_count = min(self._counter.get(c, 0) for c in self._candidate_instrs)
        prefs = [c for c in self._candidate_instrs if self._counter.get(c, 0) == min_count]
        instr = prefs[0] if len(prefs) == 1 else self._rng.choice(prefs)
        step = self._rng.choice(self._instr_to_steps[instr])
        kind = self._rng.choice(valid_injection_kinds_for_instr(instr))
        self._counter[instr] = self._counter.get(instr, 0) + 1
        return instr, step, kind


# ============================================================================ #
#                           V6 DB schema (A4-compatible)                        #
# ============================================================================ #

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_binary TEXT NOT NULL,
    host_args TEXT NOT NULL,
    kind TEXT NOT NULL,
    seed INTEGER,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE IF NOT EXISTS campaign_params (
    campaign_id INTEGER PRIMARY KEY,
    tau_new     REAL,
    tau_d       REAL,
    tau_g       REAL,
    gamma       REAL,
    K_T_rare    INTEGER,
    b_count     INTEGER,
    selector    TEXT,
    extra_json  TEXT,
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS mutations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    step INTEGER NOT NULL,
    txn_idx INTEGER,
    mutated_value INTEGER NOT NULL DEFAULT 0,
    original_value INTEGER NOT NULL DEFAULT 0,
    config_json TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    num_failures INTEGER DEFAULT 0,
    verifier_accepted INTEGER DEFAULT 0,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mutation_id INTEGER NOT NULL,
    constraint_type TEXT NOT NULL,
    constraint_loc TEXT NOT NULL,
    cycle INTEGER NOT NULL,
    step INTEGER NOT NULL,
    pc INTEGER NOT NULL,
    major INTEGER NOT NULL,
    minor INTEGER NOT NULL,
    value INTEGER NOT NULL,
    full_loc TEXT NOT NULL,
    FOREIGN KEY (mutation_id) REFERENCES mutations(id)
);

CREATE TABLE IF NOT EXISTS global_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mutation_id INTEGER NOT NULL,
    family TEXT NOT NULL,
    address TEXT NOT NULL,
    UNIQUE(mutation_id, family, address),
    FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS coverage (
    constraint_loc TEXT PRIMARY KEY,
    first_hit_mutation_id INTEGER NOT NULL,
    first_hit_at TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id)
);

CREATE TABLE IF NOT EXISTS compressed_global_coverage (
    ctx_key                 TEXT NOT NULL,
    campaign_id             INTEGER NOT NULL,
    first_hit_mutation_id   INTEGER NOT NULL,
    family                  TEXT NOT NULL,
    ctx_json                TEXT NOT NULL,
    first_hit_at            TEXT NOT NULL,
    hit_count               INTEGER DEFAULT 1,
    PRIMARY KEY (ctx_key, campaign_id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
);
"""


# ============================================================================ #
#                              Host invocation                                  #
# ============================================================================ #

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def capture_baseline_trace(host, host_args, timeout=120):
    cmd = [host, "--trace"] + list(host_args)
    t0 = time.time()
    # Bytes mode + safe decode — see _decode_safe rationale.
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    t1 = time.time()
    return p.returncode, _decode_safe(p.stdout) + _decode_safe(p.stderr), t1 - t0


def _decode_safe(b) -> str:
    """Decode subprocess bytes safely. risc0-host CAN emit non-UTF-8 bytes
    (raw register/memory dumps in panic stack traces). Using text=True in
    subprocess.run blows up with UnicodeDecodeError on those bytes; we decode
    with errors='replace' so the A4 tag parsers still extract what they need."""
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return ""


def run_inject(host, step, kind, seed, host_args, timeout=90):
    cmd = [
        host, "--inject",
        "--inject-step", str(step),
        "--inject-kind", kind,
        "--seed", str(seed),
    ] + list(host_args)
    t0 = time.time()
    try:
        # IMPORTANT: capture as BYTES (no text=True). host may emit non-UTF-8.
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        rc = p.returncode
        out = _decode_safe(p.stdout) + _decode_safe(p.stderr)
    except subprocess.TimeoutExpired:
        rc = 124
        out = ""
    except Exception as e:
        # Last-resort guard so the main loop survives ANY subprocess error.
        rc = 125
        out = "<v6_driver_subprocess_error>" + type(e).__name__ + ": " + str(e) + "</v6_driver_subprocess_error>"
    t1 = time.time()
    return rc, out, t1 - t0


# ============================================================================ #
#                                 Main driver                                   #
# ============================================================================ #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--num", type=int, required=True)
    ap.add_argument("--progress-every", type=int, default=100)
    ap.add_argument("--label", default="v6_arguzz")
    ap.add_argument("host_args", nargs="*", help="passed after `--` to host")
    args = ap.parse_args()

    print(f"=== V6 driver v2 start  seed={args.seed} num={args.num}  {now_iso()} ===")
    print(f"host: {args.host}")
    print(f"host_args: {args.host_args}")
    print(f"db: {args.db}")
    print(f"A4_REPO: {A4_REPO}")
    print(f"_TXN_ROLE_BY_KIND patched with {len(_ARGUZZ_KIND_ROLE_EXTENSIONS)} arguzz kinds")

    # ---------------- Bootstrap (a): baseline trace ----------------
    print("\n--- bootstrap (a): baseline trace via `host --trace` ---")
    t0 = time.time()
    rc, out, wall = capture_baseline_trace(args.host, args.host_args)
    print(f"  rc={rc} wall={wall:.2f}s out_bytes={len(out)}")
    if rc != 0:
        print(f"  ERROR: baseline trace returned {rc}")
        sys.exit(2)
    trace = parse_trace_steps(out)
    if not trace:
        print("  ERROR: no <trace> tags parsed")
        sys.exit(2)
    instr_to_steps = {}
    for step, pc, instr, _asm in trace:
        norm = normalize_instr(instr)
        instr_to_steps.setdefault(norm, []).append(step)
    print(f"  trace: {len(trace)} steps across {len(instr_to_steps)} instr kinds")
    unknown = [k for k in instr_to_steps if k not in INSTR_KINDS]
    if unknown:
        print(f"  ! unknown instr kinds (not in arguzz enum): {unknown}")

    # ---------------- Bootstrap (b): InspectionData ----------------
    print("\n--- bootstrap (b): InspectionData via A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 ---")
    t_b = time.time()
    insp = InspectionData.from_inspection(args.host, list(args.host_args))
    t_be = time.time()
    print(f"  wall={t_be-t_b:.2f}s  total_steps={insp.total_steps}  cycles={len(insp.cycles)}")
    if not insp.cycles:
        print("  ERROR: InspectionData has no cycles — extractor cannot get major/zone")
        sys.exit(2)

    # ---------------- Zone classification ----------------
    print("\n--- step_to_zone via classify_zones(InspectionData) ---")
    t_z = time.time()
    step_to_zone = classify_zones(insp)
    t_ze = time.time()
    print(f"  wall={t_ze-t_z:.2f}s  classified={len(step_to_zone)} steps")

    # Step-domain fix (a4/docs/cloud3/arguzz_step_domain_fix; added 2026-06-27).
    # LEGACY driver (superseded by a4/standalone/v6_uniform_driver.py). Same issue as
    # there: the scheduler picks EXECUTOR `current_step`s but `step_to_zone`/`get_cycle`
    # are keyed by witgen `user_cycle`, so the RECORDED zone/major were mislabeled by the
    # host-ecall drift. Round-robin selection never reads zone, so results were valid;
    # this corrects only the persisted labels. Recording-only ⇒ fall back on map failure.
    exec_step_to_zone = None
    _step_map = None
    try:
        from a4.arguzz_dependent.arguzz_parser import parse_all_traces
        from a4.standalone.step_domain_map import build_step_domain_map
        _step_map = build_step_domain_map(
            parse_all_traces(out),
            insp.total_steps,
            compute_user_cycles={c.step for c in insp.cycles if c.major <= 6},
        )
        exec_step_to_zone = _step_map.exec_step_zone_map(step_to_zone)
        print(f"  step-domain map: {_step_map.n_host_ecalls} host ecalls skipped (labels corrected)")
    except Exception as e:
        print(f"  WARNING: step-domain map unavailable ({e}); recorded zone/major mislabeled")
    # Quick zone histogram
    from collections import Counter
    zhist = Counter(step_to_zone.values())
    for z, n in zhist.most_common(8):
        print(f"    {z:20s} {n}")

    # ---------------- Scheduler ----------------
    rng = Random(args.seed)
    sched = ArguzzScheduler(instr_to_steps, rng)
    print(f"\n  scheduler ready: {len(sched._candidate_instrs)} candidate instr kinds")

    # ---------------- DB setup ----------------
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(args.db):
        os.remove(args.db)
    conn = sqlite3.connect(args.db)
    conn.executescript(DB_SCHEMA)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO campaigns (host_binary, host_args, kind, seed, started_at) VALUES (?, ?, ?, ?, ?)",
        (args.host, " ".join(args.host_args), args.label, args.seed, now_iso()),
    )
    campaign_id = cur.lastrowid
    cur.execute(
        "INSERT INTO campaign_params (campaign_id, selector, extra_json, recorded_at) VALUES (?, ?, ?, ?)",
        (campaign_id, "arguzz", json.dumps({
            "num": args.num,
            "scheduler": "balanced_round_robin",
            "driver_version": "v2.1_utf8safe",
            "compressed_extractor": "a4.compressed_global_extractor",
        }), now_iso()),
    )
    conn.commit()

    # ---------------- Main loop ----------------
    print(f"\n--- begin {args.num} arguzz mutations ---")
    t_start = time.time()
    constraint_locs_seen = set()
    compressed_ctx_seen = set()
    outcomes = {"prove_success": 0, "prove_error": 0, "panic": 0, "timeout": 0, "other": 0}

    for i in range(1, args.num + 1):
        instr, step, kind = sched.pick()
        iter_seed = args.seed * 1_000_000 + i

        rc, stdout, wall = run_inject(args.host, step, kind, iter_seed, args.host_args)

        cfs = parse_constraint_failures(stdout)
        fr = parse_family_residues(stdout) or []
        fd = parse_family_detail(stdout) or []
        gr = parse_global_residue(stdout)
        prov_status, prov_time = parse_prover_status(stdout)

        host_panic = "panicked at " in stdout
        if rc == 124:
            outcome = "timeout"
        elif host_panic:
            outcome = "panic"
        elif prov_status == "success":
            outcome = "prove_success"
        elif prov_status == "error":
            outcome = "prove_error"
        else:
            outcome = "other"
        outcomes[outcome] += 1

        # Zone + major for this mutation (step-domain fix: executor step -> user_cycle)
        zone = (exec_step_to_zone or step_to_zone).get(step, "core_other")
        _u = _step_map.user_cycle_of(step) if _step_map is not None else step
        cycle = insp.get_cycle(_u) if _u is not None else None
        major = cycle.major if cycle is not None else 0

        config = {
            "kind": kind, "step": step, "instruction": instr, "iter_seed": iter_seed,
            "wall_s": round(wall, 3), "rc": rc, "prover_status": prov_status,
            "prover_time": prov_time, "outcome": outcome, "zone": zone, "major": major,
        }
        cur.execute(
            "INSERT INTO mutations (campaign_id, kind, step, txn_idx, mutated_value, original_value, "
            "config_json, executed_at, num_failures, verifier_accepted) "
            "VALUES (?, ?, ?, NULL, 0, 0, ?, ?, ?, 0)",
            (campaign_id, kind, step, json.dumps(config), now_iso(), len(cfs)),
        )
        mut_id = cur.lastrowid

        # failures + coverage
        for cf in cfs:
            try:
                cycle_n = int(cf.get("cycle", 0))
                cstep = int(cf.get("step", 0))
                pc = int(cf.get("pc", 0))
                cmajor = int(cf.get("major", 0))
                cminor = int(cf.get("minor", 0))
                value = int(cf.get("value", 0))
                loc = cf.get("loc", "?")
            except Exception:
                continue
            cur.execute(
                "INSERT INTO failures (mutation_id, constraint_type, constraint_loc, cycle, step, pc, major, minor, value, full_loc) "
                "VALUES (?, 'L', ?, ?, ?, ?, ?, ?, ?, ?)",
                (mut_id, loc, cycle_n, cstep, pc, cmajor, cminor, value, loc),
            )
            if loc not in constraint_locs_seen:
                constraint_locs_seen.add(loc)
                cur.execute(
                    "INSERT OR IGNORE INTO coverage (constraint_loc, first_hit_mutation_id, first_hit_at, hit_count) "
                    "VALUES (?, ?, ?, 1)",
                    (loc, mut_id, now_iso()),
                )
            else:
                cur.execute("UPDATE coverage SET hit_count = hit_count + 1 WHERE constraint_loc = ?", (loc,))

        # global_failures: one row per (family, broken addr/idx) — same as A4
        if fd:
            seen = set()
            for fdi in fd:
                fam = fdi.get("family", "?")
                items = fdi.get("broken_addrs", []) or fdi.get("broken_indices", []) or []
                for raw in items:
                    try:
                        addr = int(raw) if not isinstance(raw, dict) else int(
                            raw.get("addr") or raw.get("byte_addr") or raw.get("address")
                            or raw.get("index") or raw.get("idx") or raw.get("lookup_index") or 0
                        )
                    except Exception:
                        continue
                    key = (fam, str(addr))
                    if key in seen:
                        continue
                    seen.add(key)
                    cur.execute(
                        "INSERT OR IGNORE INTO global_failures (mutation_id, family, address) VALUES (?, ?, ?)",
                        (mut_id, fam, str(addr)),
                    )

        # compressed_global_coverage via A4's EXACT extractor (uses zone + major)
        ctxs = extract_compressed_global_contexts(
            family_residues=fr,
            family_details=fd,
            mutation_kind=kind,
            mutation_zone=zone,
            mutation_major=major,
        )
        for ctx_key, fam, ctx_json in to_storage_rows(ctxs):
            sig = (ctx_key, campaign_id)
            if sig not in compressed_ctx_seen:
                compressed_ctx_seen.add(sig)
                cur.execute(
                    "INSERT OR IGNORE INTO compressed_global_coverage "
                    "(ctx_key, campaign_id, first_hit_mutation_id, family, ctx_json, first_hit_at, hit_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (ctx_key, campaign_id, mut_id, fam, ctx_json, now_iso()),
                )
            else:
                cur.execute(
                    "UPDATE compressed_global_coverage SET hit_count = hit_count + 1 "
                    "WHERE ctx_key = ? AND campaign_id = ?",
                    (ctx_key, campaign_id),
                )

        if i % args.progress_every == 0 or i == args.num:
            conn.commit()
            elapsed = time.time() - t_start
            rate = i / elapsed
            eta = (args.num - i) / rate if rate > 0 else 0
            cf_total = cur.execute("SELECT COUNT(*) FROM failures").fetchone()[0]
            gf_total = cur.execute("SELECT COUNT(*) FROM global_failures").fetchone()[0]
            cgc_total = cur.execute("SELECT COUNT(*) FROM compressed_global_coverage").fetchone()[0]
            cov_total = cur.execute("SELECT COUNT(*) FROM coverage").fetchone()[0]
            print(f"  [{i:>5}/{args.num}] elapsed={elapsed:.1f}s rate={rate:.2f}it/s "
                  f"eta={eta/60:.1f}min  cf={cf_total} gf={gf_total} cgc={cgc_total} cov={cov_total} "
                  f"out={outcomes}", flush=True)

    cur.execute("UPDATE campaigns SET ended_at = ? WHERE id = ?", (now_iso(), campaign_id))
    conn.commit()
    conn.close()
    elapsed = time.time() - t_start
    print(f"\n=== V6 DONE  total_wall={elapsed:.1f}s ({elapsed/3600:.2f}h)  {now_iso()} ===")
    print(f"db: {args.db}")
    print(f"outcomes: {outcomes}")


if __name__ == "__main__":
    main()
