#!/usr/bin/env python3
"""GP1 gate for the AP bench-isread FOLD-neutralization patch.

The planted bug disables IsRead for the ReadReg path by neutralizing the per-arm
AndEqz *folds* (verifier) and the matching `FpExt ... * poly_mix[k]` folds (prover),
leaving every Sub/diff wire and every non-ReadReg fold intact. This auditor proves
the patch is simultaneously COMPLETE, SCOPED, and CONSISTENT:

  (a) COMPLETE  : 0 active IsRead@ReadReg folds remain (verifier AND every prover file).
  (b) SCOPED    : git diff touched ONLY sanctioned fold lines -> no Sub/diff wire,
                  no non-ReadReg fold was modified (catches over-widening).
  (c) CONSISTENT: both verifier (poly_ext.rs) and all prover files (rust_poly_fp_*)
                  were neutralized (catches a prover/verifier mismatch -> verify segment).

Run on the PATCHED tree (compares against git HEAD). Exit 0 = PASS.

Usage:
    python a4/scripts/ap_poly_cse_audit.py            # full GP1 gate (count + git diff)
    python a4/scripts/ap_poly_cse_audit.py --counts   # counts only (no git)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RISC0 = ROOT / "workspace" / "risc0-modified"
KERNELS = RISC0 / "risc0" / "circuit" / "rv32im-sys" / "kernels"
POLY_FP = [KERNELS / "cxx" / f"rust_poly_fp_{i}.cpp" for i in range(4)]
POLY_EXT = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "poly_ext.rs"

ISREAD_RR = re.compile(r"IsRead \(.*ReadReg \(")
POLY_EXT_ANDEQZ = re.compile(r"^(\s*)PolyExtStep::AndEqz\((\d+),\s*(\d+)\),")
CPP_FOLD = re.compile(r"^\s*FpExt x\d+ = x\d+ \+ \S+ \* poly_mix\[\d+\];\s*$")
CPP_FOLD_NEUTRALIZED = re.compile(r"^\s*FpExt x\d+ = x\d+;(\s*//.*)?$")
AP_FOLD = "AP_PLANTED neutralized IsRead@ReadReg fold"

# Lines that must NEVER appear in the diff (would mean a wire/diff was touched).
FORBIDDEN_IN_DIFF = (re.compile(r"PolyExtStep::Sub\("), re.compile(r"^\s*auto x\d+ ="))


def is_rr(line: str) -> bool:
    return bool(ISREAD_RR.search(line))


# --- counts (works without git) -------------------------------------------------
def ext_active_total(path: Path) -> tuple[int, int]:
    active = total = 0
    for line in path.read_text().splitlines():
        if not is_rr(line):
            continue
        m = POLY_EXT_ANDEQZ.match(line)
        if m:
            total += 1
            if m.group(3) != "0":
                active += 1
    return active, total


def fp_active_total(path: Path) -> tuple[int, int]:
    lines = path.read_text().splitlines()
    active = total = 0
    for i, line in enumerate(lines):
        # zirgen C++ codegen emits each fold's loc on the PRECEDING line.
        prev = lines[i - 1] if i - 1 >= 0 else ""
        if not (is_rr(prev) and prev.lstrip().startswith("//")):
            continue
        if CPP_FOLD.match(line):
            active += 1
            total += 1
        elif CPP_FOLD_NEUTRALIZED.match(line) and AP_FOLD in line:
            total += 1
    return active, total


# --- git diff scope check -------------------------------------------------------
def git_diff(path: Path) -> list[str]:
    rel = path.relative_to(RISC0).as_posix()
    out = subprocess.run(
        ["git", "-C", str(RISC0), "diff", "--unified=0", "--", rel],
        capture_output=True, text=True, check=True,
    ).stdout
    return out.splitlines()


def scope_violations(path: Path, is_ext: bool) -> list[str]:
    """Return a list of unsanctioned changed lines (empty = clean)."""
    viol = []
    for raw in git_diff(path):
        if raw.startswith(("+++", "---", "@@")) or not raw.startswith(("+", "-")):
            continue
        body = raw[1:]
        # forbidden objects must never be in the diff
        for pat in FORBIDDEN_IN_DIFF:
            if pat.search(body):
                viol.append(f"touched diff/Sub wire: {raw.strip()[:90]}")
        if is_ext:
            # every changed AndEqz must be the neutralization (added -> ,0; removed -> old)
            if "PolyExtStep::AndEqz(" in body and "ReadReg (" not in body and "IsRead (" not in body:
                # AndEqz changed but not on an IsRead@ReadReg line -> scope leak
                if raw.startswith("+") and ", 0)" not in body:
                    viol.append(f"non-ReadReg AndEqz changed: {raw.strip()[:90]}")
        else:
            if raw.startswith("+") and CPP_FOLD_NEUTRALIZED.match(body) and AP_FOLD not in body:
                viol.append(f"fold neutralized without AP marker/tag: {raw.strip()[:90]}")
    return viol


def main() -> int:
    counts_only = "--counts" in sys.argv
    print("== AP fold-neutralization GP1 gate ==")

    ext_active, ext_total = ext_active_total(POLY_EXT)
    print(f"verifier poly_ext.rs : IsRead@ReadReg AndEqz active={ext_active}/{ext_total}")
    fp_tot_active = fp_tot_total = 0
    for p in POLY_FP:
        a, t = fp_active_total(p)
        fp_tot_active += a
        fp_tot_total += t
        print(f"prover {p.name:18s}: ReadReg folds active={a}/{t}")
    print(f"prover TOTAL          : ReadReg folds active={fp_tot_active}/{fp_tot_total}")

    ok_complete = ext_active == 0 and fp_tot_active == 0
    ok_present = ext_total > 0 and fp_tot_total > 0
    ok_consistent = ext_total > 0 and all(fp_active_total(p)[1] > 0 for p in POLY_FP)

    if counts_only:
        ok = ok_complete and ok_present and ok_consistent
        print("RESULT:", "PASS (counts)" if ok else "FAIL (counts)")
        return 0 if ok else 1

    violations = scope_violations(POLY_EXT, is_ext=True)
    for p in POLY_FP:
        violations += scope_violations(p, is_ext=False)
    print(f"scope violations (git diff): {len(violations)}")
    for v in violations[:20]:
        print("  !!", v)

    ok = ok_complete and ok_present and ok_consistent and not violations
    print("RESULT:", "PASS" if ok else "FAIL")
    if not ok_complete:
        print("  - INCOMPLETE: active ReadReg folds remain (under-scoped hole).")
    if not ok_consistent:
        print("  - INCONSISTENT: a prover file or the verifier has 0 ReadReg folds (mismatch risk).")
    if violations:
        print("  - SCOPE LEAK: diff touched a wire/diff or non-ReadReg fold (over-widening).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
