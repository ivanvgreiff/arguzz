#!/usr/bin/env python3
"""D2.F F.1 smoke gate — validate collected POS DBs before F.2 tail."""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Tuple

CANONICAL_LOC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*@[A-Za-z0-9_.]+:\d+$")

ARGUZZ_VARIANTS = {"V6_uniform", "V6_cTS", "Hybrid_cTS"}


def _find_db(result_dir: Path) -> Path:
    dbs = list(result_dir.glob("*.db")) + list(result_dir.glob("**/run.db"))
    if not dbs:
        raise FileNotFoundError(f"no .db in {result_dir}")
    return max(dbs, key=lambda p: p.stat().st_size)


def _parse_run_id(run_id: str) -> Tuple[str, int, int]:
    m = re.match(r"pos_iv_pos_8_d2f_(.+)_seed(\d+)_n(\d+)", run_id)
    if not m:
        raise ValueError(f"unexpected run_id: {run_id}")
    return m.group(1), int(m.group(2)), int(m.group(3))


def validate_db(db_path: Path, *, expected_n: int) -> Dict[str, object]:
    variant, seed, n = _parse_run_id(db_path.parent.name)
    issues: List[str] = []
    with sqlite3.connect(db_path) as conn:
        cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(mutations)")
        }
        if "outcome" not in cols:
            issues.append("mutations.outcome column missing")
        else:
            null_out = conn.execute(
                "SELECT COUNT(*) FROM mutations WHERE outcome IS NULL"
            ).fetchone()[0]
            if null_out:
                issues.append(f"mutations.outcome NULL count={null_out}")

        rc_cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(reward_counterfactuals)")
        }
        if "bandit_success_l1" not in rc_cols:
            issues.append("reward_counterfactuals.bandit_success_l1 missing")
        else:
            l1 = conn.execute(
                "SELECT COUNT(*) FROM reward_counterfactuals "
                "WHERE bandit_success_l1 IS NOT NULL"
            ).fetchone()[0]
            if l1 == 0 and variant in {"V6_cTS", "Hybrid_cTS", "V5_control"}:
                issues.append("no L1-logged counterfactual rows")

        n_mut = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
        if n_mut != expected_n:
            issues.append(f"mutation count {n_mut} != expected {expected_n}")

        cgc = conn.execute(
            "SELECT COUNT(*) FROM compressed_global_coverage"
        ).fetchone()[0]
        gf = conn.execute(
            "SELECT COUNT(*) FROM global_failures"
        ).fetchone()[0]
        if variant in ARGUZZ_VARIANTS:
            if cgc < 1:
                issues.append("F13: compressed_global_coverage empty")
            if gf < 1:
                issues.append("F13: global_failures empty")

        locs = [
            row[0]
            for row in conn.execute(
                "SELECT constraint_loc FROM failures LIMIT 200"
            ).fetchall()
        ]
        for loc in locs:
            if not CANONICAL_LOC_RE.match(loc):
                issues.append(f"non-canonical failure loc: {loc!r}")
                break

        if variant == "Hybrid_cTS":
            arms = [
                row[0]
                for row in conn.execute(
                    "SELECT selected_arm FROM bandit_decisions"
                ).fetchall()
            ]
            has_a4 = any(
                a and not a.startswith("arguzz_exec_fault|") for a in arms
            )
            has_arguzz = any(
                a and a.startswith("arguzz_exec_fault|") for a in arms
            )
            if not has_a4:
                issues.append("Hybrid: no A4-surface bandit pulls")
            if not has_arguzz:
                issues.append("Hybrid: no Arguzz-surface bandit pulls")
            cgc_a4 = conn.execute(
                """
                SELECT COUNT(*) FROM compressed_global_coverage cgc
                JOIN bandit_decisions bd
                  ON bd.mutation_id = cgc.first_hit_mutation_id
                WHERE bd.selected_arm NOT LIKE 'arguzz_exec_fault|%'
                """
            ).fetchone()[0]
            cgc_arguzz = conn.execute(
                """
                SELECT COUNT(*) FROM compressed_global_coverage cgc
                JOIN bandit_decisions bd
                  ON bd.mutation_id = cgc.first_hit_mutation_id
                WHERE bd.selected_arm LIKE 'arguzz_exec_fault|%'
                """
            ).fetchone()[0]
            if cgc_a4 < 1:
                issues.append("Hybrid: no CGC from A4 surface")
            if cgc_arguzz < 1:
                issues.append("Hybrid: no CGC from Arguzz surface")

        outcome_dist = dict(
            conn.execute(
                "SELECT outcome, COUNT(*) FROM mutations GROUP BY outcome"
            ).fetchall()
        ) if "outcome" in cols else {}

    return {
        "variant": variant,
        "seed": seed,
        "n": n,
        "path": str(db_path),
        "n_mutations": n_mut,
        "cgc": cgc,
        "global_failures": gf,
        "outcome_dist": outcome_dist,
        "issues": issues,
        "ok": not issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_base",
        type=Path,
        help="chain_dispatcher RESULTS_BASE (contains batch/run_id dirs)",
    )
    parser.add_argument(
        "--expected-n", type=int, default=100,
    )
    args = parser.parse_args()

    rows: List[Dict[str, object]] = []
    for run_dir in sorted(args.results_base.rglob("*")):
        if not run_dir.is_dir():
            continue
        if not run_dir.name.startswith("pos_iv_pos_8_d2f_"):
            continue
        try:
            db = _find_db(run_dir)
        except FileNotFoundError:
            continue
        rows.append(validate_db(db, expected_n=args.expected_n))

    if not rows:
        print(f"ERROR: no run dirs under {args.results_base}", file=sys.stderr)
        return 2

    ok_all = True
    for row in rows:
        status = "PASS" if row["ok"] else "FAIL"
        print(
            f"{status} {row['variant']} seed={row['seed']} "
            f"n_mut={row['n_mutations']} cgc={row['cgc']} gf={row['global_failures']} "
            f"outcomes={row['outcome_dist']}"
        )
        if row["issues"]:
            ok_all = False
            for issue in row["issues"]:
                print(f"  - {issue}")

    print(f"\nSUMMARY: {sum(1 for r in rows if r['ok'])}/{len(rows)} passed")
    return 0 if ok_all and len(rows) >= 8 else 1


if __name__ == "__main__":
    sys.exit(main())
