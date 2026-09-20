#!/usr/bin/env python3
"""Apply or revert the AP bench-isread patch (ReadReg path) on the COMMITTED circuit.

Mechanism: FOLD-neutralization (not wire-zeroing).
The IsRead@ReadReg constraint is enforced by per-arm AndEqz folds, NOT by the
CSE-shared Sub/diff wire. The diff wires are reused by Poseidon/Div/Control IsRead
folds, so zeroing a wire over-widens the bug to all memory reads. Instead we
neutralize only the ReadReg *folds*, leaving every diff wire and every non-ReadReg
fold intact -> register-read IsRead disabled, all other IsRead enforced, exact
committed circuit preserved (index-identical, full comparability with the CVE track).

- steps.cpp/cu/cuh: exec_ReadReg -> MemoryReadNoIsRead (witgen, already ReadReg-scoped)
- poly_ext.rs (verifier): each IsRead@ReadReg AndEqz(acc, val) -> AndEqz(acc, 0)
                          (fp#0 = Const(0) -> fold is trivially true)
- rust_poly_fp_{0..3}.cpp (prover): each IsRead@ReadReg fold
                          "FpExt dst = acc + inner * poly_mix[k];" -> "FpExt dst = acc;"
                          (drops the contribution; leaves the shared `inner` diff alone)

Diffs (auto a-b) and witness reads (auto arg0[i]) are NEVER modified.

Usage:
    python a4/scripts/ap_isread_patch.py apply
    python a4/scripts/ap_isread_patch.py revert
    python a4/scripts/ap_isread_patch.py status
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RISC0 = ROOT / "workspace" / "risc0-modified"
KERNELS = RISC0 / "risc0" / "circuit" / "rv32im-sys" / "kernels"
STEPS_CPP = KERNELS / "cxx" / "steps.cpp"
STEPS_CU = KERNELS / "cuda" / "steps.cu"
STEPS_CUH = KERNELS / "cuda" / "steps.cuh"
POLY_FP = [KERNELS / "cxx" / f"rust_poly_fp_{i}.cpp" for i in range(4)]
POLY_EXT = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "poly_ext.rs"

MARKER_BEGIN = "// >>> AP_PLANTED MemoryReadNoIsRead BEGIN >>>"
MARKER_END = "// <<< AP_PLANTED MemoryReadNoIsRead END <<<"
AP_FOLD = "// AP_PLANTED neutralized IsRead@ReadReg fold"

ISREAD_READREG = re.compile(r"IsRead \(.*ReadReg \(")
# Verifier: AndEqz(acc, val) with inline loc comment. Repoint val -> 0 (fp#0 = Const(0)).
POLY_EXT_ANDEQZ_RE = re.compile(r"^(\s*)PolyExtStep::AndEqz\((\d+),\s*(\d+)\),(.*)$")
# Prover: fold "FpExt dst = acc + inner * poly_mix[k];" (loc on the PRECEDING line).
CPP_FOLD_RE = re.compile(r"^(\s*)FpExt (x\d+) = (x\d+) \+ (\S+) \* poly_mix\[(\d+)\];\s*$")


def is_isread_readreg_line(line: str) -> bool:
    return bool(ISREAD_READREG.search(line))


# ---------------------------------------------------------------------------
# Constraint-polynomial patch (fold-neutralization)
# ---------------------------------------------------------------------------
def patch_poly_ext(text: str) -> tuple[str, int]:
    """Repoint each IsRead@ReadReg AndEqz(acc, val) -> AndEqz(acc, 0).

    Leaves Sub/diff steps and every non-ReadReg fold untouched. Index-preserving
    (no step added/removed), so prover/verifier wire indices stay aligned.
    """
    out: list[str] = []
    changed = 0
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\n")
        if not is_isread_readreg_line(raw) or AP_FOLD in raw:
            out.append(line)
            continue
        m = POLY_EXT_ANDEQZ_RE.match(raw)
        if m and m.group(3) != "0":
            indent, acc, _val, rest = m.groups()
            out.append(f"{indent}PolyExtStep::AndEqz({acc}, 0), {AP_FOLD}{rest}\n")
            changed += 1
            continue
        out.append(line)
    return "".join(out), changed


def patch_rust_poly_fp(text: str) -> tuple[str, int]:
    """Neutralize IsRead@ReadReg *folds* only.

    A fold is ReadReg-tagged when the IMMEDIATELY PRECEDING line is an
    IsRead(...ReadReg...) loc comment. The zirgen C++ codegen emits the loc comment
    *before* the statement it annotates (verified on disk: e.g. `FpExt x423 = x421 +
    x422*poly_mix[6]` folds the MemoryIO residual x422 and carries a MemoryIO loc on
    the line above it; the IsRead loc on the line *below* belongs to the next stmt).
    Keying on the next line (i+1) mis-tagged MemoryIO folds as IsRead and desynced
    the prover poly from the verifier (honest `verify segment` failure).

    Diffs (auto a-b) and witness reads (auto arg0[i]) are left untouched so shared
    wires keep enforcing the Poseidon/Div/Control arms.
    """
    lines = text.splitlines(keepends=True)
    out = list(lines)
    changed = 0
    for i, line in enumerate(lines):
        prev = lines[i - 1] if i - 1 >= 0 else ""
        if not (is_isread_readreg_line(prev) and prev.lstrip().startswith("//")):
            continue
        if AP_FOLD in line:
            continue
        m = CPP_FOLD_RE.match(line.rstrip("\n"))
        if m:
            indent, dst, acc, _inner, _k = m.groups()
            out[i] = f"{indent}FpExt {dst} = {acc}; {AP_FOLD}\n"
            changed += 1
    return "".join(out), changed


# ---------------------------------------------------------------------------
# Counting / status
# ---------------------------------------------------------------------------
def count_poly_ext_active(path: Path) -> int:
    """ReadReg AndEqz folds whose value arg is not 0 (i.e. not yet neutralized)."""
    if not path.is_file():
        return 0
    n = 0
    for line in path.read_text().splitlines():
        if not is_isread_readreg_line(line):
            continue
        m = POLY_EXT_ANDEQZ_RE.match(line.rstrip("\n"))
        if m and m.group(3) != "0":
            n += 1
    return n


def count_poly_ext_total(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(
        1
        for line in path.read_text().splitlines()
        if is_isread_readreg_line(line) and POLY_EXT_ANDEQZ_RE.match(line.rstrip("\n"))
    )


def count_poly_fp_active(path: Path) -> int:
    """ReadReg-tagged folds still carrying a poly_mix term (not yet neutralized)."""
    if not path.is_file():
        return 0
    lines = path.read_text().splitlines()
    n = 0
    for i, line in enumerate(lines):
        prev = lines[i - 1] if i - 1 >= 0 else ""
        if is_isread_readreg_line(prev) and prev.lstrip().startswith("//"):
            if CPP_FOLD_RE.match(line) and AP_FOLD not in line:
                n += 1
    return n


def count_poly_fp_total(path: Path) -> int:
    """ReadReg-tagged folds, active or already neutralized."""
    if not path.is_file():
        return 0
    lines = path.read_text().splitlines()
    n = 0
    for i, line in enumerate(lines):
        prev = lines[i - 1] if i - 1 >= 0 else ""
        if is_isread_readreg_line(prev) and prev.lstrip().startswith("//"):
            stripped = line.lstrip()
            if CPP_FOLD_RE.match(line) or (AP_FOLD in line and stripped.startswith("FpExt")):
                n += 1
    return n


def count_isread_non_readreg(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(
        1
        for line in path.read_text().splitlines()
        if "IsRead (" in line and "ReadReg (" not in line
    )


# ---------------------------------------------------------------------------
# Witgen patch (unchanged: ReadReg-scoped MemoryReadNoIsRead)
# ---------------------------------------------------------------------------
CPP_NO_ISREAD_FN = f"""
{MARKER_BEGIN}
GetDataStruct exec_MemoryReadNoIsRead(ExecContext& ctx,NondetRegStruct arg0, Val arg1_0, BoundLayout<MemoryReadLayout> layout2)   {{
// MemoryReadNoIsRead — IsRead removed for ReadReg path only (AP bench-isread)
MemoryIOStruct x3 = exec_MemoryIO(ctx,(arg0._super * Val(2)), arg1_0, LAYOUT_LOOKUP(layout2, io));
IsForwardStruct x6 = exec_IsForward(ctx,x3, LAYOUT_LOOKUP(layout2, _0));
ValU32Struct x7 = ValU32Struct{{
  .low = x3.newTxn.dataLow._super,   .high = x3.newTxn.dataHigh._super}};
return GetDataStruct{{
  ._super = x7,   .diffLow = Val(0),   .diffHigh = Val(1)}};
}}
{MARKER_END}
"""

CU_NO_ISREAD_FN = f"""
{MARKER_BEGIN}
__device__ GetDataStruct exec_MemoryReadNoIsRead(ExecContext& ctx,
                                                 NondetRegStruct arg0,
                                                 Val arg1_0,
                                                 BoundLayout<MemoryReadLayout> layout2) {{
  MemoryIOStruct x3 =
      exec_MemoryIO(ctx, (arg0._super * Val(2)), arg1_0, LAYOUT_LOOKUP(layout2, io));
  IsForwardStruct x6 = exec_IsForward(ctx, x3, LAYOUT_LOOKUP(layout2, _0));
  ValU32Struct x7 =
      ValU32Struct{{.low = x3.newTxn.dataLow._super, .high = x3.newTxn.dataHigh._super}};
  return GetDataStruct{{._super = x7, .diffLow = Val(0), .diffHigh = Val(1)}};
}}
{MARKER_END}
"""

CUH_DECL = f"""
{MARKER_BEGIN}
extern __device__ GetDataStruct exec_MemoryReadNoIsRead(ExecContext& ctx,
                                                        NondetRegStruct arg0,
                                                        Val arg1_0,
                                                        BoundLayout<MemoryReadLayout> layout2);
{MARKER_END}
"""

READREG_CPP_OLD = (
    "GetDataStruct x7 = exec_MemoryRead(ctx,arg0, x6._super, LAYOUT_LOOKUP(layout3, _super));"
)
READREG_CPP_NEW = (
    "GetDataStruct x7 = exec_MemoryReadNoIsRead(ctx,arg0, x6._super, LAYOUT_LOOKUP(layout3, _super));"
)

READREG_CU_OLD = (
    "  GetDataStruct x7 = exec_MemoryRead(ctx, arg0, x6._super, LAYOUT_LOOKUP(layout3, _super));"
)
READREG_CU_NEW = (
    "  GetDataStruct x7 = exec_MemoryReadNoIsRead(ctx, arg0, x6._super, LAYOUT_LOOKUP(layout3, _super));"
)


def _insert_after_memory_read(text: str, block: str) -> str:
    if MARKER_BEGIN in text:
        return text
    needle = "return GetDataStruct{\n  ._super = x7,   .diffLow = Val(0),   .diffHigh = Val(1)};\n}"
    idx = text.find(needle)
    if idx == -1:
        raise RuntimeError("Could not locate exec_MemoryRead end in steps.cpp")
    end = idx + len(needle)
    return text[:end] + block + text[end:]


def _insert_after_memory_read_cu(text: str, block: str) -> str:
    if MARKER_BEGIN in text:
        return text
    needle = "  return GetDataStruct{._super = x7, .diffLow = Val(0), .diffHigh = Val(1)};\n}"
    idx = text.find(needle)
    if idx == -1:
        raise RuntimeError("Could not locate exec_MemoryRead end in steps.cu")
    end = idx + len(needle)
    return text[:end] + block + text[end:]


def apply_witgen() -> None:
    cpp = STEPS_CPP.read_text()
    if MARKER_BEGIN not in cpp:
        cpp = _insert_after_memory_read(cpp, CPP_NO_ISREAD_FN)
    if READREG_CPP_OLD in cpp:
        cpp = cpp.replace(READREG_CPP_OLD, READREG_CPP_NEW, 1)
    elif READREG_CPP_NEW not in cpp:
        raise RuntimeError("exec_ReadReg call site not found in steps.cpp")
    STEPS_CPP.write_text(cpp)

    cu = STEPS_CU.read_text()
    if MARKER_BEGIN not in cu:
        cu = _insert_after_memory_read_cu(cu, CU_NO_ISREAD_FN)
    if READREG_CU_OLD in cu:
        cu = cu.replace(READREG_CU_OLD, READREG_CU_NEW, 1)
    elif READREG_CU_NEW not in cu:
        raise RuntimeError("exec_ReadReg call site not found in steps.cu")
    STEPS_CU.write_text(cu)

    cuh = STEPS_CUH.read_text()
    if MARKER_BEGIN not in cuh:
        insert_after = (
            "extern __device__ GetDataStruct exec_MemoryRead(ExecContext& ctx,\n"
            "                                                NondetRegStruct arg0,\n"
            "                                                Val arg1_0,\n"
            "                                                BoundLayout<MemoryReadLayout> layout2);"
        )
        if insert_after not in cuh:
            raise RuntimeError("Could not locate exec_MemoryRead decl in steps.cuh")
        cuh = cuh.replace(insert_after, insert_after + "\n" + CUH_DECL)
    STEPS_CUH.write_text(cuh)


def apply_poly() -> tuple[int, int]:
    fp_changed = 0
    for path in POLY_FP:
        text, n = patch_rust_poly_fp(path.read_text())
        path.write_text(text)
        fp_changed += n
    text, ext_changed = patch_poly_ext(POLY_EXT.read_text())
    POLY_EXT.write_text(text)
    return fp_changed, ext_changed


def revert_witgen() -> None:
    for path in (STEPS_CPP, STEPS_CU):
        text = path.read_text()
        text = re.sub(
            re.escape(MARKER_BEGIN) + r"[\s\S]*?" + re.escape(MARKER_END) + r"\n?",
            "",
            text,
        )
        text = text.replace(READREG_CPP_NEW, READREG_CPP_OLD)
        text = text.replace(READREG_CU_NEW, READREG_CU_OLD)
        path.write_text(text)

    cuh = STEPS_CUH.read_text()
    cuh = re.sub(
        re.escape(MARKER_BEGIN) + r"[\s\S]*?" + re.escape(MARKER_END) + r"\n?",
        "",
        cuh,
    )
    STEPS_CUH.write_text(cuh)


def revert_poly_git() -> None:
    rel_paths = [
        *(p.relative_to(RISC0).as_posix() for p in POLY_FP),
        POLY_EXT.relative_to(RISC0).as_posix(),
    ]
    subprocess.run(
        ["git", "-C", str(RISC0), "checkout", "--", *rel_paths],
        check=True,
    )


def apply() -> None:
    apply_witgen()
    fp_n, ext_n = apply_poly()
    print(f"AP isread patch APPLIED (verifier folds={ext_n}, prover folds={fp_n})")


def revert() -> None:
    # git checkout ALL touched files (witgen + poly) for a pristine committed state.
    rels = [p.relative_to(RISC0).as_posix() for p in (STEPS_CPP, STEPS_CU, STEPS_CUH, POLY_EXT, *POLY_FP)]
    subprocess.run(["git", "-C", str(RISC0), "checkout", "--", *rels], check=True)
    print("AP isread patch REVERTED (witgen + poly via git checkout)")


def poly_stats() -> dict:
    return {
        "poly_fp_isread_readreg_total": sum(count_poly_fp_total(p) for p in POLY_FP),
        "poly_fp_isread_readreg_active": sum(count_poly_fp_active(p) for p in POLY_FP),
        "poly_ext_isread_readreg_total": count_poly_ext_total(POLY_EXT),
        "poly_ext_isread_readreg_active": count_poly_ext_active(POLY_EXT),
        "poly_fp_isread_non_readreg": sum(count_isread_non_readreg(p) for p in POLY_FP),
        "poly_ext_isread_non_readreg": count_isread_non_readreg(POLY_EXT),
    }


def status() -> int:
    cpp = STEPS_CPP.read_text()
    witgen_applied = (
        MARKER_BEGIN in cpp
        and READREG_CPP_NEW in cpp
        and "exec_MemoryReadNoIsRead" in cpp
    )
    stats = poly_stats()
    poly_applied = (
        stats["poly_fp_isread_readreg_active"] == 0
        and stats["poly_ext_isread_readreg_active"] == 0
        and stats["poly_fp_isread_readreg_total"] > 0
        and stats["poly_ext_isread_readreg_total"] > 0
    )
    applied = witgen_applied and poly_applied
    print("applied" if applied else "partial" if witgen_applied else "clean")
    print(
        f"  witgen={witgen_applied}"
        f" poly_ext_active={stats['poly_ext_isread_readreg_active']}/{stats['poly_ext_isread_readreg_total']}"
        f" poly_fp_active={stats['poly_fp_isread_readreg_active']}/{stats['poly_fp_isread_readreg_total']}"
        f" non_rr(ext={stats['poly_ext_isread_non_readreg']},fp={stats['poly_fp_isread_non_readreg']})"
    )
    return 0 if applied or (not witgen_applied and READREG_CPP_OLD in cpp) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "revert", "status"])
    args = parser.parse_args()
    for p in (STEPS_CPP, STEPS_CU, STEPS_CUH, POLY_EXT, *POLY_FP):
        if not p.exists():
            print(f"Missing {p}", file=sys.stderr)
            return 1
    if args.action == "apply":
        apply()
    elif args.action == "revert":
        revert()
    else:
        return status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
