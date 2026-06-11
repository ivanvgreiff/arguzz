"""B9 — DB schema integrity across 5 variants."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, INC2_SMOKE_SEED, INC2_VARIANTS, OUTPUT_DIR, DEFAULT_HOST, run_fuzz_smoke,
)
from a4.standalone.coverage_db import CoverageDB

EXPECTED_TABLES = [
    "campaigns", "mutations", "bandit_decisions", "arm_state_snapshot",
    "mutation_rewards", "mutation_substrategy", "hook3_raw", "local_coverage_v2",
    "reward_counterfactuals", "compressed_global_coverage", "global_failures",
    "failures", "coverage", "campaign_params", "pilot_runs",
]


def _canonical_schema() -> Dict[str, List[Dict[str, str]]]:
    """Fresh DB schema from coverage_db._init_schema."""
    import tempfile as tf
    tmp = tf.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = CoverageDB(tmp.name)
    conn = db.conn
    schema: Dict[str, List[Dict[str, str]]] = {}
    for table in EXPECTED_TABLES:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        schema[table] = [
            {"name": c[1], "type": c[2].upper(), "notnull": c[3], "pk": c[5]}
            for c in cols
        ]
    conn.close()
    Path(tmp.name).unlink(missing_ok=True)
    return schema


def _normalize_type(t: str) -> str:
    return t.upper().replace("INT", "INTEGER")


def _check_schema(conn: sqlite3.Connection, canonical: Dict[str, List]) -> List[str]:
    errors = []
    for table, expected_cols in canonical.items():
        actual = conn.execute(f"PRAGMA table_info({table})").fetchall()
        exp_names = [c["name"] for c in expected_cols]
        act_names = [r[1] for r in actual]
        if exp_names != act_names:
            errors.append(f"{table}: columns mismatch exp={exp_names} act={act_names}")
            continue
        for exp, act in zip(expected_cols, actual):
            if _normalize_type(exp["type"]) != _normalize_type(act[2]):
                errors.append(f"{table}.{exp['name']}: type {act[2]} != {exp['type']}")
    return errors


def _check_fks(conn: sqlite3.Connection) -> List[str]:
    errors = []
    for row in conn.execute(
        "SELECT mutation_id FROM mutation_rewards"
    ).fetchall():
        ok = conn.execute(
            "SELECT 1 FROM mutations WHERE id=?", (row[0],)
        ).fetchone()
        if not ok:
            errors.append(f"mutation_rewards.mutation_id={row[0]} orphan")
    for row in conn.execute("SELECT mutation_id FROM bandit_decisions").fetchall():
        ok = conn.execute(
            "SELECT 1 FROM mutations WHERE id=?", (row[0],)
        ).fetchone()
        if not ok:
            errors.append(f"bandit_decisions.mutation_id={row[0]} orphan")
    return errors


def _audit_db(db_path: str, canonical: Dict[str, List], expected_n: int = 10) -> Dict[str, Any]:
    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    missing = [t for t in EXPECTED_TABLES if t not in tables]
    extra = [t for t in tables if t not in EXPECTED_TABLES and not t.startswith("sqlite_")]
    schema_errs = _check_schema(conn, canonical) if not missing else ["missing tables"]
    fk_errs = _check_fks(conn) if not missing else []
    n_mut = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
    conn.close()
    return {
        "tables": "ALL_PRESENT" if not missing else f"MISSING:{missing}",
        "extra_tables": extra,
        "schemas": "MATCH" if not schema_errs else schema_errs,
        "fks": "VALID" if not fk_errs else fk_errs,
        "n_mutations": n_mut,
        "pass": not missing and not extra and not schema_errs and not fk_errs and n_mut == expected_n,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    args = p.parse_args()
    OUTPUT_DIR.mkdir(exist_ok=True)
    canonical = _canonical_schema()

    per_variant: Dict[str, Any] = {}
    all_pass = True
    with tempfile.TemporaryDirectory(prefix="b9_") as tmp:
        for vid, spec in INC2_VARIANTS.items():
            db = str(Path(tmp) / f"{vid}.db")
            rc = run_fuzz_smoke(selector=spec["selector"], db_path=db, num=10, host=args.host)
            if rc not in (0, 2):
                per_variant[vid] = {"pass": False, "error": f"exit={rc}"}
                all_pass = False
                continue
            per_variant[vid] = _audit_db(db, canonical)
            all_pass = all_pass and per_variant[vid]["pass"]

    out = {
        "_meta": GLOSSARY_META,
        "seed": INC2_SMOKE_SEED,
        "per_variant": per_variant,
        "verdict": "PASS" if all_pass else "FAIL",
    }
    out_path = OUTPUT_DIR / "B9_db_schema.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"=== B9 RESULT: {out['verdict']} ===")
    print(f"  Wrote {out_path}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
