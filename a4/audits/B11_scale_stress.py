"""B11 — Scale stress: N=500 DB analysis (prefix + B1/B4/B9 re-runs)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META,
    INC2_HOST_ARGS,
    INC2_SMOKE_SEED,
    INC2_VARIANTS,
    OUTPUT_DIR,
    resolve_variant_dbs,
    resolve_variant_traces,
)
from a4.audits.b7_filter import diff_mutation_prefix, filter_meta
from a4.audits.B1_hook_fidelity import verify_db
from a4.audits.B4_bandit_db_traceability import audit_variant, B4_N
from a4.audits.B9_db_schema_integrity import _audit_db, _canonical_schema, EXPECTED_TABLES

DEFAULT_B11_DIR = OUTPUT_DIR / "inc4_b11"
DEFAULT_BASELINE_DIR = OUTPUT_DIR / "inc3_b1"
B11_N = 500
PREFIX_N = 200
WALL_SOFT_SEC = 90 * 60
WALL_HARD_SEC = 2 * WALL_SOFT_SEC


def _wall_seconds(db_path: Path) -> Optional[float]:
    """Best-effort wall from mutations.executed_at span."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT MIN(executed_at), MAX(executed_at) FROM mutations"
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not rows or not rows[0] or not rows[1]:
        return None
    try:
        from datetime import datetime as dt
        t0 = dt.fromisoformat(str(rows[0]).replace("Z", "+00:00"))
        t1 = dt.fromisoformat(str(rows[1]).replace("Z", "+00:00"))
        return (t1 - t0).total_seconds()
    except (ValueError, TypeError):
        return None


def _run_b1_variant(db_path: Path, vk: str, host: str, host_args: List[str]) -> Dict[str, Any]:
    pv = verify_db(db_path, host, host_args, vk)
    ok = pv["fail"] == 0 and pv["total"] == B11_N
    return {
        "pass": pv["pass"],
        "fail": pv["fail"],
        "total": pv["total"],
        "documented_exclusions": pv.get("multicycle_flags", 0),
        "effective_pass_rate": pv["pass"] / max(1, pv["total"]),
        "verdict": "PASS" if ok else "FAIL",
    }


def _run_b4_variant(db_path: Path, trace_path: Path, vk: str, expected_n: int) -> Dict[str, Any]:
    pv = audit_variant(vk, db_path, trace_path, expected_n=expected_n)
    return {
        "agreed": pv["n_agreed"],
        "disagreed": pv["n_mutations"] - pv["n_agreed"],
        "n_mutations": pv["n_mutations"],
        "verdict": pv["verdict"],
    }


def _run_b9_variant(db_path: Path, canonical: Dict) -> Dict[str, Any]:
    result = _audit_db(str(db_path), canonical, expected_n=B11_N)
    return {
        "tables_present": len(EXPECTED_TABLES) if result["tables"] == "ALL_PRESENT" else 0,
        "schema_ok": result["schemas"] == "MATCH",
        "fk_ok": result["fks"] == "VALID",
        "row_count": result["n_mutations"],
        "pass": result["pass"],
        "verdict": "PASS" if result["pass"] else "FAIL",
    }


def _v5_posteriors(db_path: Path) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            """
            SELECT arm_id, posterior_alpha, posterior_beta FROM arm_state_snapshot
            WHERE mutation_idx = (SELECT MAX(mutation_idx) FROM arm_state_snapshot)
            ORDER BY arm_id
            """
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [
        {"arm_id": r[0], "alpha": r[1], "beta": r[2], "sum": (r[1] or 0) + (r[2] or 0)}
        for r in rows
    ]


def main() -> int:
    p = argparse.ArgumentParser(description="B11 scale stress audit")
    p.add_argument("--db-dir", default=str(DEFAULT_B11_DIR))
    p.add_argument("--baseline-dir", default=str(DEFAULT_BASELINE_DIR),
                   help="B1 N=200 baseline DBs for prefix check")
    p.add_argument("--nondet-path", default=str(OUTPUT_DIR / "A1_nondet_addrs.json"))
    p.add_argument("--host", default=None)
    p.add_argument("--output", default=str(OUTPUT_DIR / "B11_scale_stress.json"))
    p.add_argument("host_args", nargs="*", default=INC2_HOST_ARGS)
    args = p.parse_args()

    from a4.audits.audit_common import DEFAULT_HOST
    host = args.host or DEFAULT_HOST
    db_dir = Path(args.db_dir)
    baseline_dir = Path(args.baseline_dir)
    nondet_path = Path(args.nondet_path)

    db_map = resolve_variant_dbs(db_dir, campaign_hint="b11", n_hint=B11_N)
    baseline_map = resolve_variant_dbs(baseline_dir, n_hint=PREFIX_N)
    trace_map = resolve_variant_traces(db_dir, db_map)

    missing = set(INC2_VARIANTS) - set(db_map)
    if missing:
        print(f"ERROR: missing B11 DBs for {missing} in {db_dir}", file=sys.stderr)
        return 2

    canonical = _canonical_schema()
    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B11_scale_stress",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "n_per_variant": B11_N,
            "prefix_baseline_n": PREFIX_N,
            "seed": INC2_SMOKE_SEED,
        },
        "filter_applied": filter_meta(nondet_path),
        "expected_exclusion_scaling": (
            "B1 documented exclusions scale ~linearly with N; at N=500 expect "
            "~2.5× Inc3 N=200 baseline counts — not a regression signal"
        ),
        "per_variant": {},
        "verdict": "PENDING",
    }

    all_pass = True
    for vk in sorted(INC2_VARIANTS):
        db_path = db_map[vk]
        trace_path = trace_map.get(vk)
        prefix_diffs = -1
        prefix_pass = False
        if vk in baseline_map:
            prefix_diffs = diff_mutation_prefix(
                baseline_map[vk], db_path, PREFIX_N, nondet_path=nondet_path,
            )
            prefix_pass = prefix_diffs == 0
        else:
            print(f"WARN: no baseline DB for {vk}; skipping prefix check", file=sys.stderr)

        b1 = _run_b1_variant(db_path, vk, host, args.host_args)
        b4 = {"verdict": "SKIP", "error": "no trace"}
        if trace_path:
            b4 = _run_b4_variant(db_path, trace_path, vk, B11_N)
        else:
            print(f"WARN: no bandit trace for {vk}; B4 sub-check skipped", file=sys.stderr)
            all_pass = False

        b9 = _run_b9_variant(db_path, canonical)
        wall = _wall_seconds(db_path)
        wall_flag = None
        if wall is not None:
            if wall > WALL_HARD_SEC:
                wall_flag = "hard_fail"
            elif wall > WALL_SOFT_SEC:
                wall_flag = "soft_warn"

        pv = {
            "n_mutations": B11_N,
            "db": str(db_path),
            "prefix_check": {
                "baseline_n": PREFIX_N,
                "baseline_db": str(baseline_map.get(vk, "")),
                "diffs": prefix_diffs,
                "pass": prefix_pass,
            },
            "b1_rerun": b1,
            "b4_rerun": b4,
            "b9_rerun": b9,
            "wall_seconds": wall,
            "wall_flag": wall_flag,
            "pass": (
                prefix_pass
                and b1["verdict"] == "PASS"
                and b4.get("verdict") == "PASS"
                and b9["verdict"] == "PASS"
                and wall_flag != "hard_fail"
            ),
        }
        if vk == "V5":
            pv["v5_posteriors_at_end"] = _v5_posteriors(db_path)
        report["per_variant"][vk] = pv
        if not pv["pass"]:
            all_pass = False

    report["verdict"] = "PASS" if all_pass else "FAIL"
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B11 verdict: {report['verdict']}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
