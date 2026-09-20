#!/usr/bin/env python3
"""Build-provenance fingerprint guard (IV.POS.9 B1.1, gates G10/G11).

Reads a risc0-host binary's self-reported build fingerprint and asserts it matches
the INTENDED build for an experiment, BEFORE any run launches. The guard is the
runtime safety net of the binary-isolation scheme: physical worktree/output
separation PREVENTS cross-track contamination, this guard DETECTS a wrong binary in
a run-slot, and the emitted JSON is recorded per run for AUDIT.

Why it checks `planted_bug`, not just `load_rs2_present`: the AP IsRead-holed binary
is built on the PATCHED tree, so it reports `load_rs2_present=1` exactly like a clean
sweep binary — they are distinguished ONLY by `planted_bug` (`isread` vs `none`). A
`load_rs2`-only guard would silently admit a holed circuit into a coverage sweep.

The binary emits its fingerprint at main.rs:78 (before arg-parse) when
`A4_INSPECT_FINGERPRINT=1`, so we extract it cheaply with no guest args (the binary
prints the tag, then clap errors on the missing --in1/--in4 — we ignore the exit code
and scrape stdout).

CLI:
  python -m a4.pos.fingerprint_guard <host_bin> --profile sweep [--guest-id "a,b,..."]
  python -m a4.pos.fingerprint_guard <host_bin> --emit-json     # just print parsed fp
Exit 0 = fingerprint matches intended; nonzero = MISMATCH (caller must abort the run).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional

_FP_RE = re.compile(r"<a4_fingerprint>(\{.*?\})</a4_fingerprint>", re.DOTALL)

# Intended-build profiles (the experiment → expected fingerprint invariants).
PROFILES: Dict[str, Dict[str, object]] = {
    # Track B / multi-guest coverage sweep: patched circuit, NO planted bug.
    "sweep":   {"load_rs2_present": 1, "planted_bug": "none"},
    # Track A bug race: vulnerable circuit (no load_rs2), no planted bug.
    "race":    {"load_rs2_present": 0, "planted_bug": "none"},
    # AP planted-bug bench: patched circuit, IsRead hole present.
    "isread":  {"load_rs2_present": 1, "planted_bug": "isread"},
    # AP/Seam-B planted-bug bench: patched circuit, VerifyOpcode decode hole present.
    # Distinguished from `sweep` (also load_rs2_present=1) ONLY by planted_bug — so a
    # load_rs2-only guard would silently admit the holed circuit into a coverage sweep,
    # or admit a clean binary into the race. (IV_POS_9_A3_SEAMB_RACE_SPEC §1.)
    "verifyopcode": {"load_rs2_present": 1, "planted_bug": "verifyopcode"},
}

# The A4 mutation-handler match-arm strings the CURRENT fuzzer emits (a4/standalone/fuzzer.py
# MUTATION_KINDS → 10 distinct binary `mutation_type` strings). These literals are compiled into
# the binary, so we can confirm a binary actually handles them by scanning its bytes. The three
# marked (*) were added in risc0 commit 6556e8d7; a "7-handler" binary lacks them and would
# SILENTLY NO-OP those mutation kinds (the F35 "3-kind contamination"), scoring false ACCEPTs.
A4_HANDLERS_CURRENT = (
    "INSTR_TYPE_MOD", "INSTR_WORD_MOD", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD", "MEM_VAL_MOD",
    "TXN_PREV_WORD_MOD", "TXN_PREV_CYCLE_MOD", "CYCLE_DIFF_COUNT_MOD",  # (*) the 3-kind set
)
A4_HANDLERS_3KIND = ("TXN_PREV_WORD_MOD", "TXN_PREV_CYCLE_MOD", "CYCLE_DIFF_COUNT_MOD")


def check_handlers(host_bin: str, required: tuple[str, ...]) -> tuple[bool, List[str]]:
    """Scan the binary for each required handler-name literal; return (ok, missing).

    The A4_MUTATION_CONFIG dispatcher in witgen/mod.rs matches these names as string literals,
    so a present handler => the name appears in the compiled binary. A missing name means that
    mutation kind hits the `invalid config` fallback and silently no-ops.
    """
    with open(host_bin, "rb") as f:
        data = f.read()
    missing = [name for name in required if name.encode() not in data]
    return (not missing), missing


def read_fingerprint(host_bin: str, timeout: float = 60.0) -> Dict[str, object]:
    """Run the binary with A4_INSPECT_FINGERPRINT=1 (no guest args) and parse the tag."""
    env = dict(os.environ)
    env["A4_INSPECT_FINGERPRINT"] = "1"
    proc = subprocess.run(
        [host_bin],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    # Fingerprint prints before clap's arg-parse error, so nonzero exit is expected.
    m = _FP_RE.search(proc.stdout)
    if not m:
        raise RuntimeError(
            f"no <a4_fingerprint> emitted by {host_bin} "
            f"(stdout head: {proc.stdout[:200]!r})"
        )
    return json.loads(m.group(1))


def assert_fingerprint(
    host_bin: str,
    *,
    expect_load_rs2: int,
    expect_planted_bug: str,
    expect_guest_id: Optional[List[int]] = None,
    expect_head_sha: Optional[str] = None,
    expect_instrumentation_hash: Optional[str] = None,
) -> tuple[bool, str, Dict[str, object]]:
    """Return (ok, message, parsed_fingerprint). Only asserts the fields requested."""
    fp = read_fingerprint(host_bin)
    fails: List[str] = []
    if int(fp.get("load_rs2_present", -1)) != expect_load_rs2:
        fails.append(f"load_rs2_present={fp.get('load_rs2_present')} != {expect_load_rs2}")
    if str(fp.get("planted_bug", "?")) != expect_planted_bug:
        fails.append(f"planted_bug={fp.get('planted_bug')!r} != {expect_planted_bug!r}")
    if expect_guest_id is not None and list(fp.get("guest_image_id", [])) != list(expect_guest_id):
        fails.append(f"guest_image_id={fp.get('guest_image_id')} != {expect_guest_id}")
    # head_sha / instrumentation_hash are only asserted when both intended AND populated
    # (some builds leave them "unknown"); never weaken the load_rs2/planted_bug invariants.
    if expect_head_sha and fp.get("risc0_head_sha") not in ("unknown", expect_head_sha):
        fails.append(f"risc0_head_sha={fp.get('risc0_head_sha')} != {expect_head_sha}")
    if expect_instrumentation_hash and fp.get("instrumentation_hash") not in ("unknown", expect_instrumentation_hash):
        fails.append(f"instrumentation_hash mismatch")
    if fails:
        return False, "FINGERPRINT MISMATCH: " + "; ".join(fails), fp
    return True, "fingerprint OK", fp


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("host_bin")
    p.add_argument("--profile", choices=sorted(PROFILES), help="intended-build profile")
    p.add_argument("--guest-id", help="comma-separated expected guest_image_id (optional)")
    p.add_argument("--head-sha", help="expected risc0_head_sha (optional)")
    p.add_argument("--require-handlers", metavar="SPEC",
                   help="also assert the binary contains the A4 mutation handlers: "
                        "'current10' (all the current fuzzer emits), '3kind' (the 3 that older "
                        "binaries silently no-op), or a comma-separated list of handler names")
    p.add_argument("--emit-json", action="store_true", help="print parsed fingerprint and exit 0")
    args = p.parse_args()

    if args.emit_json:
        print(json.dumps(read_fingerprint(args.host_bin)))
        return 0

    if not args.profile:
        p.error("--profile is required unless --emit-json")
    prof = PROFILES[args.profile]
    guest_id = [int(x) for x in args.guest_id.split(",")] if args.guest_id else None
    ok, msg, fp = assert_fingerprint(
        args.host_bin,
        expect_load_rs2=int(prof["load_rs2_present"]),
        expect_planted_bug=str(prof["planted_bug"]),
        expect_guest_id=guest_id,
        expect_head_sha=args.head_sha,
    )
    # Optional handler-set check (closes the 7-vs-10-handler "3-kind contamination" gap that the
    # planted_bug/load_rs2 fields cannot see).
    if args.require_handlers:
        spec = args.require_handlers
        if spec == "current10":
            required = A4_HANDLERS_CURRENT
        elif spec == "3kind":
            required = A4_HANDLERS_3KIND
        else:
            required = tuple(s.strip() for s in spec.split(",") if s.strip())
        h_ok, missing = check_handlers(args.host_bin, required)
        if not h_ok:
            ok = False
            msg += f"; MISSING HANDLERS: {', '.join(missing)} (binary would silently no-op these kinds)"

    tag = "PASS" if ok else "ABORT"
    print(f"[fingerprint_guard] {tag} ({args.profile}): {msg}")
    print(f"[fingerprint_guard] binary fp: planted_bug={fp.get('planted_bug')} "
          f"load_rs2_present={fp.get('load_rs2_present')} "
          f"head_sha={str(fp.get('risc0_head_sha'))[:12]} "
          f"guest_image_id={fp.get('guest_image_id')}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
