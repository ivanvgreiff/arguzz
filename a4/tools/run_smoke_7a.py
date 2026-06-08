#!/usr/bin/env python3
"""
Run Phase 7a local smoke: 5 variants × N=20 with full telemetry.

Logs wall times and runs check_smoke_db.py after each variant.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST = REPO_ROOT / "workspace/output/target/release/risc0-host"
OUT_DIR = REPO_ROOT / "a4/smoke_7a"
CHECK = REPO_ROOT / "a4/tools/check_smoke_db.py"

VARIANTS = [
    "zoned",
    "kindUCB_zoned_v1",
    "kindUCB_zoned_v2_noQ",
    "kindTS_zoned_v2",
    "cTS_semantic_v2",
]

NUM = 20
SEED = 999


def main() -> int:
    if not HOST.is_file():
        print(f"ERROR: host binary not found: {HOST}", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    wall_times: dict[str, float] = {}
    failures: list[str] = []

    for variant in VARIANTS:
        db_path = OUT_DIR / f"smoke_{variant}.db"
        print(f"\n=== 7a run: {variant} -> {db_path} ===", flush=True)
        t0 = time.time()
        cmd = [
            sys.executable, "-m", "a4.standalone.cli", "fuzz",
            f"--host={HOST}",
            f"--selector={variant}",
            f"--num={NUM}",
            f"--seed={SEED}",
            "--telemetry-level=full",
            f"--db={db_path}",
            "--",
            "--in1", "5", "--in4", "10",
        ]
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT))
        elapsed = time.time() - t0
        wall_times[variant] = elapsed
        print(f"  exit={proc.returncode} wall_sec={elapsed:.1f}", flush=True)

        if proc.returncode != 0:
            failures.append(f"{variant}: fuzz exit {proc.returncode}")
            continue

        check_cmd = [
            sys.executable, str(CHECK),
            f"--db={db_path}",
            f"--variant={variant}",
            "--phase=7a",
            f"--requested={NUM}",
            f"--wall-time-sec={elapsed:.3f}",
        ]
        if variant == "cTS_semantic_v2" and "zoned" in wall_times:
            check_cmd.append(f"--ref-wall-time-sec={wall_times['zoned']:.3f}")
        chk = subprocess.run(check_cmd, cwd=str(REPO_ROOT))
        if chk.returncode != 0:
            failures.append(f"{variant}: check_smoke_db failed")

    print("\n=== 7a summary ===")
    for v, t in wall_times.items():
        print(f"  {v}: {t:.1f}s")
    if "zoned" in wall_times and "cTS_semantic_v2" in wall_times:
        ratio = wall_times["cTS_semantic_v2"] / wall_times["zoned"]
        print(f"  V5/V1 wall-time ratio: {ratio:.2f}")

    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("ALL 7a HARD GATES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
