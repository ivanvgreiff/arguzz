#!/usr/bin/env python3
"""
Run Phase 7b POS smoke: 5 variants × N=200 with full telemetry.

Execute on coinbase POS host inside tmux. Same structure as run_smoke_7a.py.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST = REPO_ROOT / "workspace/output/target/release/risc0-host"
OUT_DIR = REPO_ROOT / "a4/smoke_7b"
CHECK = REPO_ROOT / "a4/tools/check_smoke_db.py"

VARIANTS = [
    "zoned",
    "kindUCB_zoned_v1",
    "kindUCB_zoned_v2_noQ",
    "kindTS_zoned_v2",
    "cTS_semantic_v2",
]

NUM = 200
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
        print(f"\n=== 7b run: {variant} -> {db_path} ===", flush=True)
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
            "--phase=7b",
            f"--requested={NUM}",
            f"--wall-time-sec={elapsed:.3f}",
        ]
        if variant == "cTS_semantic_v2" and "zoned" in wall_times:
            check_cmd.append(f"--ref-wall-time-sec={wall_times['zoned']:.3f}")
        chk = subprocess.run(check_cmd, cwd=str(REPO_ROOT))
        if chk.returncode != 0:
            failures.append(f"{variant}: check_smoke_db failed")

    print("\n=== 7b summary ===")
    for v, t in wall_times.items():
        print(f"  {v}: {t:.1f}s")
    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        return 1
    print("ALL 7b HARD GATES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
