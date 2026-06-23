#!/usr/bin/env python3
"""Apply / revert the Seam-B planted bug: neutralize VerifyOpcode* on the COMMITTED circuit.

THE BUG (instruction-type substitution underconstraint):
Remove every `VerifyOpcode/VerifyOpcodeF3/VerifyOpcodeF3F7` decode-equality (the only
constraint binding the claimed instruction type `major/minor` to the fetched word). The
global memory permutation binds the WORD, not the type, so with these gone an INSTR_TYPE_MOD
(ALU->ALU) mutation verifies. Validated premise: a4/runs/iv_pos_9/ap/AP_SEAM_B_VALIDATED.md.

Mechanism (3 coordinated artifacts; all keyed on "VerifyOpcode"; FOLD-neutralization, not
wire-zeroing — leaves the shared diff `Sub`/`auto x=a-b` wires intact):

- steps.cpp (witgen):  EQZ(expr, "...VerifyOpcode...")  ->  EQZ(Val(0), "...")     [~111]
- poly_ext.rs (verif): PolyExtStep::AndEqz(acc,val), //..VerifyOpcode..  ->  AndEqz(acc,0)  [74]
- rust_poly_fp_{0..3}.cpp (prover): fold "FpExt dst = acc + inner*poly_mix[k];" whose
                       PRECEDING line is a VerifyOpcode loc comment  ->  "FpExt dst = acc;"  [74]

prover(74) == verifier(74) keeps verify_integrity consistent (honest-gate). Honest proofs are
unaffected: the equalities already hold, so removing them is vacuous.

Base tree: workspace/risc0-seamb (detached @ committed circuit; NOT risc0-modified).
revert = git checkout -- <files>.

Usage:  python a4/scripts/ap_verifyopcode_patch.py {apply|revert|status}
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RISC0 = ROOT / "workspace" / "risc0-seamb"
KERNELS = RISC0 / "risc0" / "circuit" / "rv32im-sys" / "kernels"
STEPS_CPP = KERNELS / "cxx" / "steps.cpp"
POLY_FP = [KERNELS / "cxx" / f"rust_poly_fp_{i}.cpp" for i in range(4)]
POLY_EXT = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "poly_ext.rs"
ALL_FILES = [STEPS_CPP, POLY_EXT, *POLY_FP]

AP_TAG = "// AP_PLANTED VerifyOpcode neutralized"

# --- selectors ---
def is_vo(line: str) -> bool:
    return "VerifyOpcode" in line

# Witgen: EQZ(<expr>, "<loc with VerifyOpcode>");  -> EQZ(Val(0), "<loc>");
STEPS_EQZ_RE = re.compile(r'^(\s*)EQZ\((.+?), ("loc\(callsite\( VerifyOpcode.+)\);\s*$')
# Verifier: PolyExtStep::AndEqz(acc, val), // <inline loc>
POLY_EXT_ANDEQZ_RE = re.compile(r"^(\s*)PolyExtStep::AndEqz\((\d+),\s*(\d+)\),(.*)$")
# Prover: FpExt dst = acc + inner * poly_mix[k];   (loc on PRECEDING line)
CPP_FOLD_RE = re.compile(r"^(\s*)FpExt (x\d+) = (x\d+|arg\d+) \+ (\S+) \* poly_mix\[(\d+)\];\s*$")


# ---------------------------------------------------------------------------
# Patch functions
# ---------------------------------------------------------------------------
def patch_steps(text: str) -> tuple[str, int]:
    """Neutralize each VerifyOpcode EQZ assertion: assert Val(0) (always true).
    Index-irrelevant (witgen exec code, not the constraint poly), so safe to edit in place.
    """
    out: list[str] = []
    changed = 0
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\n")
        if not is_vo(raw) or AP_TAG in raw:
            out.append(line)
            continue
        m = STEPS_EQZ_RE.match(raw)
        if m:
            indent, _expr, loc = m.groups()
            out.append(f"{indent}EQZ(Val(0), {loc}); {AP_TAG}\n")
            changed += 1
            continue
        out.append(line)
    return "".join(out), changed


def patch_poly_ext(text: str) -> tuple[str, int]:
    """Each VerifyOpcode AndEqz(acc, val) -> AndEqz(acc, 0). Index-preserving."""
    out: list[str] = []
    changed = 0
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\n")
        if not is_vo(raw) or AP_TAG in raw:
            out.append(line)
            continue
        m = POLY_EXT_ANDEQZ_RE.match(raw)
        if m and m.group(3) != "0":
            indent, acc, _val, rest = m.groups()
            out.append(f"{indent}PolyExtStep::AndEqz({acc}, 0), {AP_TAG}{rest}\n")
            changed += 1
            continue
        out.append(line)
    return "".join(out), changed


def patch_rust_poly_fp(text: str) -> tuple[str, int]:
    """Neutralize VerifyOpcode folds: a fold whose IMMEDIATELY-PRECEDING line is a
    VerifyOpcode loc comment -> drop the inner*poly_mix term (FpExt dst = acc).
    Leaves diff wires (`auto x = a - b`) untouched (CPP_FOLD_RE only matches FpExt folds).
    Keys on lines[i-1] (loc-precedes-statement; the IsRead off-by-one lesson).
    """
    lines = text.splitlines(keepends=True)
    out = list(lines)
    changed = 0
    for i, line in enumerate(lines):
        prev = lines[i - 1] if i - 1 >= 0 else ""
        if not (is_vo(prev) and prev.lstrip().startswith("//")):
            continue
        if AP_TAG in line:
            continue
        m = CPP_FOLD_RE.match(line.rstrip("\n"))
        if m:
            indent, dst, acc, _inner, _k = m.groups()
            out[i] = f"{indent}FpExt {dst} = {acc}; {AP_TAG}\n"
            changed += 1
    return "".join(out), changed


# ---------------------------------------------------------------------------
# Counting / status
# ---------------------------------------------------------------------------
def count_steps_active(p: Path) -> int:
    return sum(1 for l in p.read_text().splitlines()
               if is_vo(l) and STEPS_EQZ_RE.match(l.rstrip("\n")) and AP_TAG not in l)

def count_steps_total(p: Path) -> int:
    return sum(1 for l in p.read_text().splitlines()
               if is_vo(l) and (STEPS_EQZ_RE.match(l.rstrip("\n"))
                                or (AP_TAG in l and "EQZ(Val(0)" in l)))

def count_ext_active(p: Path) -> int:
    n = 0
    for l in p.read_text().splitlines():
        if not is_vo(l):
            continue
        m = POLY_EXT_ANDEQZ_RE.match(l.rstrip("\n"))
        if m and m.group(3) != "0":
            n += 1
    return n

def count_ext_total(p: Path) -> int:
    return sum(1 for l in p.read_text().splitlines()
               if is_vo(l) and POLY_EXT_ANDEQZ_RE.match(l.rstrip("\n")))

def count_fp_active(p: Path) -> int:
    L = p.read_text().splitlines()
    n = 0
    for i, line in enumerate(L):
        prev = L[i - 1] if i - 1 >= 0 else ""
        if is_vo(prev) and prev.lstrip().startswith("//") and CPP_FOLD_RE.match(line) and AP_TAG not in line:
            n += 1
    return n

def count_fp_total(p: Path) -> int:
    L = p.read_text().splitlines()
    n = 0
    for i, line in enumerate(L):
        prev = L[i - 1] if i - 1 >= 0 else ""
        if is_vo(prev) and prev.lstrip().startswith("//"):
            s = line.lstrip()
            if CPP_FOLD_RE.match(line) or (AP_TAG in line and s.startswith("FpExt")):
                n += 1
    return n


def stats() -> dict:
    return {
        "steps_active": count_steps_active(STEPS_CPP),
        "steps_total": count_steps_total(STEPS_CPP),
        "ext_active": count_ext_active(POLY_EXT),
        "ext_total": count_ext_total(POLY_EXT),
        "fp_active": sum(count_fp_active(p) for p in POLY_FP),
        "fp_total": sum(count_fp_total(p) for p in POLY_FP),
    }


# ---------------------------------------------------------------------------
def apply() -> None:
    t, n_st = patch_steps(STEPS_CPP.read_text()); STEPS_CPP.write_text(t)
    t, n_ext = patch_poly_ext(POLY_EXT.read_text()); POLY_EXT.write_text(t)
    n_fp = 0
    for p in POLY_FP:
        t, n = patch_rust_poly_fp(p.read_text()); p.write_text(t); n_fp += n
    print(f"Seam-B VerifyOpcode patch APPLIED  (witgen EQZ={n_st}, verifier folds={n_ext}, prover folds={n_fp})")
    if n_ext != n_fp:
        print(f"  *** WARNING: verifier({n_ext}) != prover({n_fp}) — prover/verifier INCONSISTENT, do NOT build ***")


def revert() -> None:
    rels = [p.relative_to(RISC0).as_posix() for p in ALL_FILES]
    subprocess.run(["git", "-C", str(RISC0), "checkout", "--", *rels], check=True)
    print("Seam-B VerifyOpcode patch REVERTED (git checkout)")


def status() -> int:
    s = stats()
    applied = (s["steps_active"] == 0 and s["ext_active"] == 0 and s["fp_active"] == 0
               and s["steps_total"] > 0 and s["ext_total"] > 0 and s["fp_total"] > 0)
    consistent = s["ext_total"] == s["fp_total"]
    print("applied" if applied else "clean/partial")
    print(f"  witgen EQZ  active={s['steps_active']}/{s['steps_total']}")
    print(f"  verifier    active={s['ext_active']}/{s['ext_total']}")
    print(f"  prover      active={s['fp_active']}/{s['fp_total']}")
    print(f"  prover==verifier total: {s['ext_total']}=={s['fp_total']} -> {'OK' if consistent else 'MISMATCH'}")
    return 0 if (applied and consistent) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=["apply", "revert", "status"])
    a = ap.parse_args()
    for p in ALL_FILES:
        if not p.exists():
            print(f"Missing {p}", file=sys.stderr)
            return 1
    if a.action == "apply":
        apply()
    elif a.action == "revert":
        revert()
    else:
        return status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
