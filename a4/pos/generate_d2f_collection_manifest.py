#!/usr/bin/env python3
"""Build D2.G collection manifest from F.2 production DBs."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


def _parse_run_id(name: str) -> tuple[str, int, int]:
    m = re.match(r"pos_iv_pos_8_d2f_(.+)_seed(\d+)_n(\d+)", name)
    if not m:
        raise ValueError(name)
    return m.group(1), int(m.group(2)), int(m.group(3))


def _summarize_db(db_path: Path) -> Dict[str, Any]:
    variant, seed, n = _parse_run_id(db_path.parent.name)
    with sqlite3.connect(db_path) as conn:
        n_mut = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
        cgc = conn.execute(
            "SELECT COUNT(*) FROM compressed_global_coverage"
        ).fetchone()[0]
        gf = conn.execute(
            "SELECT COUNT(*) FROM global_failures"
        ).fetchone()[0]
        outcomes = dict(
            conn.execute(
                "SELECT outcome, COUNT(*) FROM mutations GROUP BY outcome"
            ).fetchall()
        )
        null_out = conn.execute(
            "SELECT COUNT(*) FROM mutations WHERE outcome IS NULL"
        ).fetchone()[0]
        l1 = conn.execute(
            "SELECT COUNT(*) FROM reward_counterfactuals "
            "WHERE bandit_success_l1 IS NOT NULL"
        ).fetchone()[0]
        meta_path = db_path.parent / "meta.json"
        wall_sec = None
        exit_code = None
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text())
            wall_sec = meta.get("wall_sec")
            exit_code = meta.get("exit_code")

    applied = outcomes.get("applied", 0)
    applied_rate = (applied / n_mut) if n_mut else 0.0

    return {
        "variant": variant,
        "seed": seed,
        "n_requested": n,
        "db_path": str(db_path),
        "n_mutations": n_mut,
        "cgc_count": cgc,
        "global_failures_count": gf,
        "outcome_distribution": outcomes,
        "outcome_null_count": null_out,
        "l1_logged_rows": l1,
        "applied_rate": round(applied_rate, 4),
        "wall_sec": wall_sec,
        "exit_code": exit_code,
    }


def build_manifest(results_base: Path) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for db in sorted(results_base.rglob("run.db")):
        if "pos_iv_pos_8_d2f_" not in str(db):
            continue
        rows.append(_summarize_db(db))
    rows.sort(key=lambda r: (r["variant"], r["seed"]))
    return {
        "campaign": "iv_pos_8_d2f",
        "n_requested": rows[0]["n_requested"] if rows else None,
        "job_count": len(rows),
        "jobs": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_base", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.results_base)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {args.out} ({manifest['job_count']} jobs)")


if __name__ == "__main__":
    main()
