#!/usr/bin/env python3
"""AP.B1 verification: GP1 source gate, GP2 fingerprint, V0 smoke proof."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RISC0 = ROOT / "workspace" / "risc0-modified"
KERNELS = RISC0 / "risc0" / "circuit" / "rv32im-sys" / "kernels" / "cxx"
STEPS_CPP = KERNELS / "steps.cpp"
POLY_FP = [KERNELS / f"rust_poly_fp_{i}.cpp" for i in range(4)]
POLY_EXT = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "poly_ext.rs"
BUILD_AP = ROOT / "a4" / "builds" / "ap"
PATCHED_FP = BUILD_AP / "patched" / "fingerprint.json"
BENCH_FP = BUILD_AP / "bench-isread" / "fingerprint.json"
PATCHED_HOST = BUILD_AP / "patched" / "risc0-host"
BENCH_HOST = BUILD_AP / "bench-isread" / "risc0-host"
CORPUS_010 = ROOT / "a4" / "runs" / "iv_pos_9" / "ap" / "ap_corpus_010.json"
GUEST_ARGS = ["--in1", "5", "--in4", "10"]

ISREAD_READREG = re.compile(r"IsRead \(.*ReadReg \(")
STEPS_CU = RISC0 / "risc0" / "circuit" / "rv32im-sys" / "kernels" / "cuda" / "steps.cu"
INFO_RS = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "info.rs"
TAPS_RS = RISC0 / "risc0" / "circuit" / "rv32im" / "src" / "zirgen" / "taps.rs"


def run_host(host: Path) -> tuple[bool, str]:
    env = os.environ.copy()
    env["A4_INSPECT_FINGERPRINT"] = "1"
    try:
        proc = subprocess.run(
            [str(host), *GUEST_ARGS],
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd=str(ROOT),
        )
        out = proc.stdout + proc.stderr
        ok = proc.returncode == 0 and '"context":"Verifier"' in out and '"status":"success"' in out
        return ok, out
    except subprocess.TimeoutExpired:
        return False, "timeout"


def read_fingerprint(build_dir: Path) -> dict:
    return json.loads((build_dir / "fingerprint.json").read_text())


POLY_EXT_ANDEQZ = re.compile(r"PolyExtStep::AndEqz\(")


def _count_isread_readreg_loc_tags(path: Path) -> int:
    return sum(
        1 for line in path.read_text().splitlines() if ISREAD_READREG.search(line)
    )


def _count_isread_readreg_andeqz(path: Path) -> int:
    return sum(
        1
        for line in path.read_text().splitlines()
        if ISREAD_READREG.search(line) and POLY_EXT_ANDEQZ.search(line)
    )


def _count_isread_non_readreg(path: Path) -> int:
    return sum(
        1
        for line in path.read_text().splitlines()
        if "IsRead (" in line and "ReadReg (" not in line
    )


def _witgen_readreg_uses_no_isread(cpp: str) -> bool:
    """Function-name level — survives regen variable renames."""
    return (
        "exec_MemoryReadNoIsRead" in cpp
        and bool(
            re.search(
                r"GetDataStruct exec_ReadReg\([\s\S]*?exec_MemoryReadNoIsRead\(",
                cpp,
            )
        )
    )


def _witgen_memory_read_has_isread(cpp: str) -> bool:
    return bool(
        re.search(
            r"GetDataStruct exec_MemoryRead\([\s\S]*?"
            r"IsRead \( zirgen/circuit/rv32im/v2/dsl/mem\.zir",
            cpp,
        )
    )


def gp1_source_gate() -> dict:
    cpp = STEPS_CPP.read_text()
    readreg_uses_no_isread = _witgen_readreg_uses_no_isread(cpp)
    memory_read_has_isread = _witgen_memory_read_has_isread(cpp)
    decode_uses_memory_read = "exec_DecodeInst" in cpp and memory_read_has_isread
    isread_eqz_count = len(re.findall(r"IsRead \( zirgen/circuit/rv32im/v2/dsl/mem\.zir", cpp))
    zir_mem = (ROOT / "zirgen" / "zirgen" / "circuit" / "rv32im" / "v2" / "dsl" / "mem.zir").read_text()
    zir_inst = (ROOT / "zirgen" / "zirgen" / "circuit" / "rv32im" / "v2" / "dsl" / "inst.zir").read_text()
    zir_ok = (
        "MemoryReadNoIsRead" in zir_mem
        and "MemoryReadNoIsRead(cycle, addr)" in zir_inst
    )
    steps_readreg_tags = _count_isread_readreg_loc_tags(STEPS_CPP)
    steps_cu_readreg_tags = _count_isread_readreg_loc_tags(STEPS_CU) if STEPS_CU.is_file() else 0
    poly_fp_readreg_tags = sum(_count_isread_readreg_loc_tags(p) for p in POLY_FP)
    poly_ext_readreg_tags = _count_isread_readreg_loc_tags(POLY_EXT)
    poly_ext_readreg_andeqz = _count_isread_readreg_andeqz(POLY_EXT)
    total_readreg_tags = (
        steps_readreg_tags + steps_cu_readreg_tags + poly_fp_readreg_tags + poly_ext_readreg_tags
    )
    poly_fp_non_readreg = sum(_count_isread_non_readreg(p) for p in POLY_FP)
    poly_ext_non_readreg = _count_isread_non_readreg(POLY_EXT)
    steps_non_readreg = _count_isread_non_readreg(STEPS_CPP)
    # Post-regen: IsRead@ReadReg loc-tags absent everywhere (not zeroed in-place).
    poly_ok = total_readreg_tags == 0
    ram_fetch_ok = (
        poly_fp_non_readreg > 0
        and poly_ext_non_readreg > 0
        and steps_non_readreg >= 2
    )
    info_has_protocol = (
        INFO_RS.is_file()
        and 'ProtocolInfo(*b"RV32IM:v2rev2___")' in INFO_RS.read_text()
    )
    return {
        "readreg_uses_memory_read_no_isread": readreg_uses_no_isread,
        "exec_memory_read_still_has_isread": memory_read_has_isread,
        "decode_inst_path_intact": decode_uses_memory_read,
        "isread_loc_strings_in_steps_cpp": isread_eqz_count,
        "zirgen_source_has_memory_read_no_isread": zir_ok,
        "steps_cpp_isread_readreg_loc_tags": steps_readreg_tags,
        "steps_cu_isread_readreg_loc_tags": steps_cu_readreg_tags,
        "poly_fp_isread_readreg_loc_tags": poly_fp_readreg_tags,
        "poly_ext_isread_readreg_loc_tags": poly_ext_readreg_tags,
        "poly_ext_isread_readreg_andeqz": poly_ext_readreg_andeqz,
        "total_isread_readreg_loc_tags": total_readreg_tags,
        "poly_fp_isread_non_readreg": poly_fp_non_readreg,
        "poly_ext_isread_non_readreg": poly_ext_non_readreg,
        "steps_cpp_isread_non_readreg": steps_non_readreg,
        "info_rs_protocol_v2rev2": info_has_protocol,
        "pass": (
            readreg_uses_no_isread
            and memory_read_has_isread
            and zir_ok
            and isread_eqz_count >= 2
            and poly_ok
            and ram_fetch_ok
            and info_has_protocol
        ),
    }


def gp2_fingerprint() -> dict:
    patched_fp = read_fingerprint(BUILD_AP / "patched")
    bench_fp = read_fingerprint(BUILD_AP / "bench-isread")
    ok = (
        patched_fp.get("planted_bug") == "none"
        and bench_fp.get("planted_bug") == "isread"
        and bench_fp.get("isread_scope") == "reg_only"
        and patched_fp.get("load_rs2_present") == 1
        and bench_fp.get("load_rs2_present") == 1
    )
    _, patched_out = run_host(PATCHED_HOST)
    _, bench_out = run_host(BENCH_HOST)
    patched_emit = "<a4_fingerprint>" in patched_out and '"planted_bug":"none"' in patched_out.replace(" ", "")
    bench_emit = "<a4_fingerprint>" in bench_out and '"planted_bug":"isread"' in bench_out.replace(" ", "")
    return {
        "patched_fingerprint": patched_fp,
        "bench_fingerprint": bench_fp,
        "patched_host_emits_fingerprint": patched_emit,
        "bench_host_emits_fingerprint": bench_emit,
        "pass": ok and patched_emit and bench_emit,
    }


def v0_smoke() -> dict:
    patched_ok, _ = run_host(PATCHED_HOST)
    bench_ok, _ = run_host(BENCH_HOST)
    mutated = _v0_mutated_smoke()
    return {
        "patched_honest_verifies": patched_ok,
        "bench_isread_honest_verifies": bench_ok,
        "mutated_config_id": mutated.get("config_id"),
        "mutated_bench_accepts": mutated.get("bench_accepts"),
        "mutated_patched_rejects": mutated.get("patched_rejects"),
        "mutated_patched_layers": mutated.get("patched_layers"),
        "pass": patched_ok and bench_ok and mutated.get("pass", False),
    }


def _read_circuit_source() -> dict:
    """Fingerprint metadata — mutated-V0 must run against current patched host circuit."""
    out: dict = {}
    for label, path in [("patched", PATCHED_FP), ("bench", BENCH_FP)]:
        if path.is_file():
            fp = json.loads(path.read_text())
            out[f"{label}_circuit_source"] = fp.get("circuit_source", "unknown")
            out[f"{label}_zirgen_head_sha"] = fp.get("zirgen_head_sha", "")
    return out


def _v0_mutated_smoke() -> dict:
    if not CORPUS_010.is_file():
        return {"pass": False, "error": "missing corpus"}
    if not PATCHED_HOST.is_file() or not BENCH_HOST.is_file():
        return {"pass": False, "error": "missing hosts"}

    circuit_meta = _read_circuit_source()
    # Corpus (step, txn_idx) derived on committed circuit; under Option B patched host
    # should be zirgen_control (df6fb9d unmodified). Drift is caught here: if indices
    # no longer hit IsRead@ReadReg, patched_rejects or bench_accepts will fail.
    corpus_note = (
        "Corpus step/txn_idx from committed-circuit POS screen; "
        "valid under Option B iff patched host is df6fb9d control (see circuit_source)."
    )

    sys.path.insert(0, str(ROOT))
    from a4.scripts.ap_b2_replay import CorpusEntry, bracket_corpus  # noqa: WPS433

    entry_raw = json.loads(CORPUS_010.read_text())["corpus"][0]
    entry = CorpusEntry(**{k: entry_raw[k] for k in CorpusEntry.__dataclass_fields__})
    rows = bracket_corpus(
        [entry],
        str(BENCH_HOST),
        str(PATCHED_HOST),
        GUEST_ARGS,
    )
    row = rows[0]
    bench_accepts = row["bench_accepted"]
    patched_rejects = not row["patched_accepted"]
    return {
        "config_id": entry.config_id,
        "corpus_step": entry.step,
        "corpus_txn_idx": entry.txn_idx,
        "corpus_resolution_note": corpus_note,
        **circuit_meta,
        "bench_accepts": bench_accepts,
        "patched_rejects": patched_rejects,
        "patched_layers": row.get("patched_layers"),
        "pass": bench_accepts and patched_rejects,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--honest-only",
        action="store_true",
        help="Run only patched honest verify (df6fb9d control-regen gate)",
    )
    args = ap.parse_args()

    if args.honest_only:
        patched_ok, _ = run_host(PATCHED_HOST)
        results = {"patched_honest_verifies": patched_ok, "pass": patched_ok}
        print(json.dumps(results, indent=2))
        return 0 if patched_ok else 1

    results = {
        "GP1": gp1_source_gate(),
        "GP2": gp2_fingerprint(),
        "V0_smoke": v0_smoke(),
    }
    out_path = ROOT / "a4" / "runs" / "iv_pos_9" / "ap" / "ap_b1_verify.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    all_pass = all(v.get("pass") for v in results.values())
    print(f"\nAP.B1 verify: {'PASS' if all_pass else 'FAIL'} -> {out_path}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
