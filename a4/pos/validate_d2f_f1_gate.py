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

# F28: a completed run may record a few fewer mutations than expected when a final iteration
# crashes before its DB insert. Tolerate a tiny undershoot; a truncated run is short by hundreds.
MUTATION_COUNT_TOL = 5


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
        # F28: tolerate a tiny undershoot — a completed run can record a few less than
        # expected_n when a final iteration crashes before its DB insert (V5 seeds 1234/1236
        # recorded 9999/9998: runs complete, last mutations 'applied', full step range, CGC/GF
        # populated). A genuinely truncated run is short by hundreds, which still fails.
        if n_mut > expected_n or n_mut < expected_n - MUTATION_COUNT_TOL:
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

        # F28 (recalibrated 2026-06-21): the old V6_cTS band [0.75,0.92] "expect ~0.87 cold-start
        # tax" was MIS-MODELED — cold-start pulls EXECUTE (applied), they do NOT skip (verified:
        # V6_cTS N=10000 had 1409 'cold' bandit decisions of which only 96 skipped). Real skips
        # (~5–6%) come from "no valid mutation site at the chosen (arm,step)", a guest/kind property
        # shared with V6_uniform (also ~5%) — so V6_cTS applies ~0.94, ≈ uniform's ~0.95, and the
        # cold-start asymmetry F12 feared did NOT materialize (the comparison is fair). Replace the
        # brittle applied-rate proxy with (a) a broad sanity band + (b) a DIRECT cTS-adaptivity check.
        if variant in {"V6_cTS", "Hybrid_cTS"} and expected_n >= 1000 and "outcome" in cols:
            applied = int(outcome_dist.get("applied", 0))
            rate = applied / n_mut if n_mut else 0.0
            if rate < 0.60 or rate > 0.99:
                issues.append(
                    f"{variant} applied rate {rate:.3f} outside sanity band [0.60, 0.99] "
                    f"(near-0 => bandit starving all pulls; near-1 => no skip path at all)"
                )
            # Direct adaptivity check: a working cTS bandit explores many arms and runs all phases.
            # A degenerate bandit (stuck on one arm / no floor / no learning) is the real failure mode
            # the applied-rate proxy was groping at.
            n_arms = conn.execute(
                "SELECT COUNT(DISTINCT selected_arm) FROM bandit_decisions"
            ).fetchone()[0]
            modes = {
                row[0]
                for row in conn.execute("SELECT DISTINCT mode FROM bandit_decisions")
            }
            if n_arms < 100:
                issues.append(f"{variant} explored only {n_arms} arms (<100) — bandit may be degenerate")
            if not ({"adaptive", "floor"} <= modes):
                issues.append(f"{variant} bandit modes {sorted(modes)} missing adaptive/floor phase")

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
    parser.add_argument(
        "--min-runs",
        type=int,
        default=None,
        help="minimum run dirs required (default: 8 if N=100 else 12)",
    )
    args = parser.parse_args()
    min_runs = args.min_runs if args.min_runs is not None else (
        8 if args.expected_n <= 100 else 12
    )

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
    return 0 if ok_all and len(rows) >= min_runs else 1


if __name__ == "__main__":
    sys.exit(main())
