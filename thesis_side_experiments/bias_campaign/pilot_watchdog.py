#!/usr/bin/env python3
"""Keep C1 pilot running until all 600 jobs are in pilot.db, then analyze."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CAMPAIGN = ROOT / "thesis_side_experiments" / "bias_campaign"
ART = CAMPAIGN / "artifacts" / "c1"
DB_PATH = ART / "pilot.db"
PILOT = CAMPAIGN / "pilot.py"
ANALYZE = CAMPAIGN / "analyze_pilot.py"
LOG = ART / "pilot_watchdog.log"
TARGET_JOBS = 600
POLL_SEC = 20
STALL_SEC = 900  # restart if no DB growth for 15 min while pilot "running"


def log(msg: str) -> None:
    line = f"{datetime.now(tz=timezone.utc).isoformat()} {msg}"
    print(line, flush=True)
    ART.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(line + "\n")


def run_count() -> int:
    if not DB_PATH.exists():
        return 0
    conn = sqlite3.connect(str(DB_PATH))
    n = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    conn.close()
    return n


def incomplete_groups() -> list[tuple]:
    if not DB_PATH.exists():
        return [("all", 0)]
    conn = sqlite3.connect(str(DB_PATH))
    rows = conn.execute(
        "SELECT fuzzer, kind, COUNT(*) FROM runs GROUP BY fuzzer, kind HAVING COUNT(*) < 50"
    ).fetchall()
    conn.close()
    return rows


def pilot_pids() -> list[int]:
    out = subprocess.run(
        ["pgrep", "-f", "python3 thesis_side_experiments/bias_campaign/pilot.py"],
        capture_output=True,
        text=True,
    )
    my_pid = str(os.getpid())
    return [int(p) for p in out.stdout.split() if p and p != my_pid]


def start_pilot() -> None:
    log("starting pilot.py")
    subprocess.Popen(
        [sys.executable, str(PILOT)],
        cwd=str(ROOT),
        stdout=open(ART / "pilot_run.log", "a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def is_complete() -> bool:
    if run_count() < TARGET_JOBS:
        return False
    return len(incomplete_groups()) == 0


def main() -> int:
    log(f"watchdog started target={TARGET_JOBS}")
    last_count = run_count()
    last_progress = time.time()

    while not is_complete():
        n = run_count()
        pids = pilot_pids()
        groups = incomplete_groups()
        log(f"runs={n}/{TARGET_JOBS} pilot_pids={pids or 'none'} incomplete_groups={len(groups)}")

        if n > last_count:
            last_count = n
            last_progress = time.time()

        if not pids:
            log("pilot not running — launching")
            start_pilot()
            time.sleep(30)
            continue

        if time.time() - last_progress > STALL_SEC:
            log(f"STALL: no progress in {STALL_SEC}s — killing pilot {pids}")
            for pid in pids:
                try:
                    subprocess.run(["kill", str(pid)], check=False)
                except Exception:
                    pass
            time.sleep(5)
            start_pilot()
            last_progress = time.time()
            time.sleep(30)
            continue

        time.sleep(POLL_SEC)

    log("all jobs complete — running analyze_pilot.py")
    proc = subprocess.run([sys.executable, str(ANALYZE)], cwd=str(ROOT))
    log(f"analyze exit={proc.returncode}")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
