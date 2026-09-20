#!/usr/bin/env python3
"""Focused mutated-V0 smoke for the surgical fold-neutralization build.

Exits non-zero on first failure. Tests, in order:
  1. bench-isread honest proof verifies   (prover==verifier consistency; the C2 risk)
  2. patched (committed) honest proof verifies (sanity)
  3. one (0,1,0) PRE_EXEC_REG_MOD mutation: bench ACCEPTS and patched REJECTS

GP1 source gate is intentionally NOT run here (ap_b1_verify's GP1 is regen-oriented;
use ap_poly_cse_audit.py for the surgical GP1). This is the decisive arbiter.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from a4.scripts.ap_b1_verify import (  # noqa: E402
    BENCH_HOST,
    PATCHED_HOST,
    run_host,
    _v0_mutated_smoke,
)


def main() -> int:
    print("[v0] === step 1: bench-isread honest verify (prover/verifier consistency) ===", flush=True)
    bench_ok, bench_out = run_host(BENCH_HOST)
    print(f"[v0] bench_honest_verifies={bench_ok}", flush=True)
    if not bench_ok:
        print("[v0] FAIL: bench honest proof did not verify -> prover/verifier MISMATCH (C2).", flush=True)
        print(bench_out[-2000:], flush=True)
        return 1

    print("[v0] === step 2: patched (committed) honest verify ===", flush=True)
    patched_ok, patched_out = run_host(PATCHED_HOST)
    print(f"[v0] patched_honest_verifies={patched_ok}", flush=True)
    if not patched_ok:
        print("[v0] FAIL: patched honest proof did not verify (committed circuit broken?).", flush=True)
        print(patched_out[-2000:], flush=True)
        return 1

    print("[v0] === step 3: mutated (0,1,0) — bench must ACCEPT, patched must REJECT ===", flush=True)
    m = _v0_mutated_smoke()
    print("[v0] mutated result:", json.dumps(m, indent=2), flush=True)
    if not m.get("pass"):
        print("[v0] FAIL: (0,1,0) mutation did not show bench-accept + patched-reject.", flush=True)
        return 1

    print("[v0] PASS: surgical fold-neutralization hole is real and scoped (mutated-V0).", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
