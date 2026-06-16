#!/usr/bin/env python3
"""Validate IV.POS.8 D1.A POS DBs against spec §4.2 pass criteria."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

DBS_DIR = Path(__file__).resolve().parent / "dbs"

EXPECTED_CONFIGS = {
    "cTS_semantic_v2_decayexp": (
        "exponential",
        {"K": 50.0, "initial": 0.55, "floor_min": 0.20},
    ),
    "cTS_semantic_v2_decayepoch": (
        "epoch",
        {
            "boundaries": [[0, 0.55], [2000, 0.35], [4000, 0.20]],
            "epoch_size": 100,
        },
    ),
}


def validate_db(db_path: Path) -> tuple[bool, dict]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    n_muts = cur.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
    ended_at = cur.execute(
        "SELECT ended_at FROM campaigns ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]
    selector = cur.execute(
        "SELECT selector FROM campaign_params ORDER BY campaign_id DESC LIMIT 1"
    ).fetchone()[0]
    extra_json_str = cur.execute(
        "SELECT extra_json FROM campaign_params ORDER BY campaign_id DESC LIMIT 1"
    ).fetchone()[0]
    extra = json.loads(extra_json_str)

    n_pg_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE proof_generated IS NOT NULL"
    ).fetchone()[0]
    n_pvf_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE proof_verify_failed IS NOT NULL"
    ).fetchone()[0]
    n_elapsed_nonnull = cur.execute(
        "SELECT COUNT(*) FROM mutations WHERE elapsed_ms IS NOT NULL"
    ).fetchone()[0]

    cov_count = cur.execute("SELECT COUNT(*) FROM coverage").fetchone()[0]
    n_floor_post_cs = cur.execute(
        """
        SELECT COUNT(*) FROM bandit_decisions
        WHERE mode='floor' AND mutation_id > 200
        """
    ).fetchone()[0]

    expected_type, expected_config = EXPECTED_CONFIGS[selector]
    ok = (
        n_muts == 6000
        and ended_at is not None
        and extra.get("floor_schedule_type") == expected_type
        and extra.get("floor_schedule_config") == expected_config
        and n_pg_nonnull == 6000
        and n_pvf_nonnull == 6000
        and n_elapsed_nonnull == 6000
        and n_floor_post_cs > 0
    )

    details = {
        "n_muts": n_muts,
        "ended_at": ended_at,
        "selector": selector,
        "extra": extra,
        "new_cols_nonnull": (n_pg_nonnull, n_pvf_nonnull, n_elapsed_nonnull),
        "floor_post_cs": n_floor_post_cs,
        "cov_count": cov_count,
    }
    conn.close()
    return ok, details


def main() -> int:
    db_paths = sorted(DBS_DIR.glob("**/*.db"))
    if not db_paths:
        print(f"No DBs found under {DBS_DIR}")
        return 1

    all_ok = True
    for db_path in db_paths:
        ok, details = validate_db(db_path)
        all_ok &= ok
        status = "OK " if ok else "FAIL"
        print(
            f"{status}  {db_path.name}  n={details['n_muts']}  "
            f"sel={details['selector']}  "
            f"fs_type={details['extra'].get('floor_schedule_type')}  "
            f"floor_post_cs={details['floor_post_cs']}  "
            f"cov={details['cov_count']}"
        )
        if not ok:
            print("  detailed:", details)

    return 0 if all_ok else 2


if __name__ == "__main__":
    sys.exit(main())
