#!/usr/bin/env python3
"""Semantic diff of zirgen PolyExt opcodes (ignores loc-comment text).

Option A comparability: compare committed risc0-modified poly_ext.rs against
a control-regen snapshot. Reports opcode sequence + info.rs mix metadata.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

POLY_STEP = re.compile(
    r"^\s*PolyExtStep::(\w+)\(([^)]*)\)",
)


def extract_poly_ops(path: Path) -> list[str]:
    if not path.is_file():
        return []
    ops: list[str] = []
    for line in path.read_text().splitlines():
        m = POLY_STEP.match(line)
        if m:
            ops.append(f"{m.group(1)}({m.group(2).strip()})")
    return ops


def extract_info_constants(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    text = path.read_text()
    out: dict[str, str] = {}
    for key in ("MIX_SIZE", "NUM_POLY_MIX_POWERS", "ProtocolInfo"):
        m = re.search(rf"{key}[^=]*=\s*([^;]+);", text)
        if m:
            out[key] = m.group(1).strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--committed", type=Path, required=True)
    ap.add_argument("--control", type=Path, required=True)
    args = ap.parse_args()

    committed_poly = args.committed / "risc0/circuit/rv32im/src/zirgen/poly_ext.rs"
    control_poly = args.control / "risc0/circuit/rv32im/src/zirgen/poly_ext.rs"
    committed_info = args.committed / "risc0/circuit/rv32im/src/zirgen/info.rs"
    control_info = args.control / "risc0/circuit/rv32im/src/zirgen/info.rs"

    c_ops = extract_poly_ops(committed_poly)
    r_ops = extract_poly_ops(control_poly)
    c_info = extract_info_constants(committed_info)
    r_info = extract_info_constants(control_info)

    print(f"committed poly_ext steps: {len(c_ops)}")
    print(f"control-regen poly_ext steps: {len(r_ops)}")
    print(f"committed info: {c_info}")
    print(f"control info: {r_info}")

    if c_ops == r_ops and c_info == r_info:
        print("\nSEMANTIC MATCH: Option A comparability confirmed")
        return 0

    # First divergence
    for i, (a, b) in enumerate(zip(c_ops, r_ops)):
        if a != b:
            print(f"\nFIRST DIVERGENCE at step {i}:")
            print(f"  committed: {a}")
            print(f"  control:   {b}")
            break
    else:
        if len(c_ops) != len(r_ops):
            print(f"\nLENGTH MISMATCH: {len(c_ops)} vs {len(r_ops)}")

    print("\nSEMANTIC MISMATCH: use Option B (AP isolated on df6fb9d pair)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
