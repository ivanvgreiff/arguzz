#!/usr/bin/env python3
"""
Analyze cTS_semantic_v2 skip / arm coverage from a Phase 7b V5 smoke DB.

Skips (no valid mutation target) are NOT stored per-attempt in SQLite today —
only successful mutations get `mutations` + `bandit_decisions` rows.
This script summarizes what Opus CAN see offline.

Usage:
  cd ~/arguzz
  python a4/tools/analyze_cts_skips.py \\
    --db a4/runs/pos_smoke_7b/.../pos_smoke_7b_cTS_semantic_v2_seed999_n200.db \\
    --log a4/runs/pos_smoke_7b/.../pos_smoke_7b_cTS_semantic_v2_seed999_n200.log
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--log", default=None, help="Optional campaign .log from POS")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    n_mut = conn.execute("SELECT COUNT(*) AS c FROM mutations").fetchone()["c"]
    meta_requested = None
    if args.log and Path(args.log).is_file():
        text = Path(args.log).read_text()
        m = re.search(r"Skipped \(no valid target\):\s*(\d+)", text)
        if m:
            meta_requested = int(m.group(1)) + n_mut
        print(f"From log: recorded={n_mut} skipped={m.group(1) if m else '?'}")
    print(f"mutations in DB: {n_mut}")
    print()

    print("=== Successful mutations by kind ===")
    for row in conn.execute(
        "SELECT kind, COUNT(*) AS n FROM mutations GROUP BY kind ORDER BY n DESC"
    ):
        print(f"  {row['kind']}: {row['n']}")
    print()

    print("=== Successful bandit arms (kind|zone) ===")
    arms = conn.execute(
        "SELECT selected_arm, COUNT(*) AS n FROM bandit_decisions "
        "GROUP BY selected_arm ORDER BY n DESC"
    ).fetchall()
    for row in arms:
        print(f"  {row['selected_arm']}: {row['n']}")
    print(f"  ({len(arms)} arms with >=1 success)")
    print()

    last_idx = conn.execute(
        "SELECT MAX(mutation_idx) AS m FROM arm_state_snapshot"
    ).fetchone()["m"]
    if last_idx is not None:
        print(f"=== Arm state at mutation_idx={last_idx} (pulls=0 => never updated) ===")
        zero = conn.execute(
            "SELECT arm_id FROM arm_state_snapshot "
            "WHERE mutation_idx=? AND pulls=0 ORDER BY arm_id",
            (last_idx,),
        ).fetchall()
        for row in zero:
            print(f"  {row['arm_id']}")
        print(f"  ({len(zero)} arms with 0 pulls)")
        print()

    print("=== kind|zone|step for successes (from mutations) ===")
    for row in conn.execute(
        "SELECT m.kind, m.step, bd.selected_arm, COUNT(*) AS n "
        "FROM mutations m "
        "JOIN bandit_decisions bd ON bd.mutation_id = m.id "
        "GROUP BY m.kind, m.step, bd.selected_arm "
        "ORDER BY n DESC LIMIT 25"
    ):
        print(f"  {row['selected_arm']} step={row['step']}: {row['n']}")

    print()
    print("LIMITATION: 56 skipped attempts are NOT in the DB (no per-skip arm/step).")
    print("To capture skips: re-run with verbose=True or add bandit_skip_log table.")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
