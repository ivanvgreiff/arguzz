#!/usr/bin/env python3
"""
Phase 7 smoke DB validator — checks 7a/7b exit gates per PHASE_7_SMOKE_TESTS.md.

Usage:
  python a4/tools/check_smoke_db.py --db a4/smoke_7a/smoke_zoned.db --variant zoned --phase 7a
  python a4/tools/check_smoke_db.py --db a4/smoke_7b/smoke_cTS_semantic_v2.db --variant cTS_semantic_v2 --phase 7b
"""

from __future__ import annotations

import argparse
import math
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Repo root = parent of a4/
REPO_ROOT = Path(__file__).resolve().parents[2]

V2_TABLES = frozenset({
    "bandit_decisions",
    "arm_state_snapshot",
    "reward_counterfactuals",
    "mutation_substrategy",
    "hook3_raw",
    "pilot_runs",
    "compressed_global_coverage",
    "local_coverage_v2",
})

V2_BANDIT_VARIANTS = frozenset({
    "kindUCB_zoned_v1",
    "kindUCB_zoned_v2_noQ",
    "kindTS_zoned_v2",
    "cTS_semantic_v2",
})

V2_REWARD_CF_VARIANTS = frozenset({
    "kindUCB_zoned_v2_noQ",
    "kindTS_zoned_v2",
    "cTS_semantic_v2",
})

COUNTERFACTUAL_FLOAT_COLS = (
    "current_reward",
    "no_qloc_reward",
    "fnew_only_reward",
    "compressed_global_reward",
)


@dataclass
class CheckResult:
    hard_failures: List[str] = field(default_factory=list)
    soft_warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.hard_failures


def _count(conn: sqlite3.Connection, sql: str) -> int:
    return int(conn.execute(sql).fetchone()[0])


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def check_smoke_db(
    db_path: Path,
    variant: str,
    phase: str,
    *,
    requested_mutations: Optional[int] = None,
    wall_time_sec: Optional[float] = None,
    ref_wall_time_sec: Optional[float] = None,
) -> CheckResult:
    """Run Phase 7a or 7b checks; return structured result."""
    res = CheckResult()

    if not db_path.is_file():
        res.hard_failures.append(f"DB not found: {db_path}")
        return res

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        res.hard_failures.append(f"cannot open DB: {exc}")
        return res

    # Legacy tables (schema baseline)
    for legacy in ("campaigns", "mutations", "failures", "coverage"):
        if not _table_exists(conn, legacy):
            res.hard_failures.append(f"missing legacy table: {legacy}")

    missing_v2 = sorted(V2_TABLES - {
        r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    })
    if missing_v2:
        res.hard_failures.append(f"missing v2 tables: {missing_v2}")

    n_mut = _count(conn, "SELECT COUNT(*) FROM mutations")
    res.info.append(f"mutations={n_mut}")

    if n_mut == 0:
        res.hard_failures.append("no mutations recorded")

    # NaN / inf in counterfactuals
    if _table_exists(conn, "reward_counterfactuals"):
        rows = conn.execute("SELECT * FROM reward_counterfactuals").fetchall()
        bad = 0
        for row in rows:
            for col in COUNTERFACTUAL_FLOAT_COLS:
                val = row[col]
                if val is None:
                    continue
                if not math.isfinite(float(val)):
                    bad += 1
                    break
        if bad:
            res.hard_failures.append(f"non-finite counterfactuals in {bad} rows")

    counts = {}
    for table in (
        "reward_counterfactuals",
        "mutation_substrategy",
        "hook3_raw",
        "bandit_decisions",
        "arm_state_snapshot",
        "local_coverage_v2",
        "compressed_global_coverage",
    ):
        if _table_exists(conn, table):
            counts[table] = _count(conn, f"SELECT COUNT(*) FROM {table}")
            res.info.append(f"{table}={counts[table]}")

    # Full telemetry wiring (7a: all variants use --telemetry-level=full)
    for table in ("reward_counterfactuals", "mutation_substrategy", "hook3_raw"):
        c = counts.get(table, 0)
        if c < n_mut:
            res.hard_failures.append(
                f"{table}: expected >= {n_mut} rows (one per mutation), got {c}"
            )

    if variant in V2_BANDIT_VARIANTS:
        bd = counts.get("bandit_decisions", 0)
        if bd < n_mut:
            res.hard_failures.append(
                f"bandit_decisions: expected >= {n_mut}, got {bd}"
            )

    if variant in V2_REWARD_CF_VARIANTS:
        rc = counts.get("reward_counterfactuals", 0)
        if rc < n_mut:
            res.hard_failures.append(
                f"reward_counterfactuals (v3+): expected >= {n_mut}, got {rc}"
            )

    if variant == "cTS_semantic_v2":
        lc = counts.get("local_coverage_v2", 0)
        if lc < 1:
            res.hard_failures.append(
                f"local_coverage_v2: expected >= 1 for V5, got {lc}"
            )
        if phase == "7b":
            cg = counts.get("compressed_global_coverage", 0)
            if cg < 1:
                res.hard_failures.append(
                    f"compressed_global_coverage: expected >= 1 for V5@7b, got {cg}"
                )

    if phase == "7b":
        if variant in V2_BANDIT_VARIANTS:
            bd = counts.get("bandit_decisions", 0)
            if requested_mutations and bd < int(requested_mutations * 0.85):
                res.hard_failures.append(
                    f"bandit_decisions@7b: expected ~{requested_mutations}, got {bd}"
                )
            snaps = counts.get("arm_state_snapshot", 0)
            if requested_mutations and snaps < 1:
                res.hard_failures.append("arm_state_snapshot@7b: expected >= 1 row")

        db_mb = db_path.stat().st_size / (1024 * 1024)
        res.info.append(f"db_size_mb={db_mb:.3f}")
        if db_mb > 5.0:
            res.hard_failures.append(
                f"DB size {db_mb:.2f} MB exceeds 5 MB budget at N=200"
            )

    if requested_mutations and n_mut < requested_mutations:
        skip_rate = 1.0 - (n_mut / requested_mutations)
        res.info.append(f"skip_rate={skip_rate:.1%}")
        if skip_rate > 0.50:
            res.soft_warnings.append(
                f"skip rate {skip_rate:.0%} > 50% ({n_mut}/{requested_mutations})"
            )

    if wall_time_sec is not None:
        res.info.append(f"wall_time_sec={wall_time_sec:.1f}")
        if requested_mutations and n_mut > 0:
            per_mut = wall_time_sec / n_mut
            res.info.append(f"sec_per_mutation={per_mut:.1f}")

    if (
        wall_time_sec is not None
        and ref_wall_time_sec is not None
        and ref_wall_time_sec > 0
    ):
        ratio = wall_time_sec / ref_wall_time_sec
        res.info.append(f"wall_time_ratio={ratio:.2f}")
        limit = 2.0 if phase == "7a" else 1.3
        if ratio > limit:
            label = "hard" if phase == "7b" else "soft"
            msg = f"V5/V1 wall-time ratio {ratio:.2f} > {limit} ({phase})"
            if label == "hard":
                res.hard_failures.append(msg)
            else:
                res.soft_warnings.append(msg)

    conn.close()
    return res


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 7 smoke DB validator")
    parser.add_argument("--db", required=True, help="Path to smoke SQLite DB")
    parser.add_argument(
        "--variant",
        required=True,
        choices=[
            "zoned",
            "kindUCB_zoned_v1",
            "kindUCB_zoned_v2_noQ",
            "kindTS_zoned_v2",
            "cTS_semantic_v2",
        ],
    )
    parser.add_argument("--phase", choices=["7a", "7b"], default="7a")
    parser.add_argument(
        "--requested",
        type=int,
        default=None,
        help="Requested mutation count (20 for 7a, 200 for 7b)",
    )
    parser.add_argument("--wall-time-sec", type=float, default=None)
    parser.add_argument(
        "--ref-wall-time-sec",
        type=float,
        default=None,
        help="Reference variant wall time (V1) for ratio check",
    )
    args = parser.parse_args()

    requested = args.requested
    if requested is None:
        requested = 20 if args.phase == "7a" else 200

    result = check_smoke_db(
        Path(args.db),
        args.variant,
        args.phase,
        requested_mutations=requested,
        wall_time_sec=args.wall_time_sec,
        ref_wall_time_sec=args.ref_wall_time_sec,
    )

    print(f"check_smoke_db: {args.db} variant={args.variant} phase={args.phase}")
    for line in result.info:
        print(f"  {line}")
    for w in result.soft_warnings:
        print(f"  WARN: {w}")
    for f in result.hard_failures:
        print(f"  FAIL: {f}")

    if result.ok:
        print("  PASS")
        return 0
    print("  HARD GATE FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
