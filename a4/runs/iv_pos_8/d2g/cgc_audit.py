"""CGC field-diversity / collapse check (D1-style, D2.G §5)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List

import pandas as pd

from .discover import flat_db_list, parse_d2f_run_dir

CGC_CONTEXT_FIELDS = ("family", "address_region", "txn_role", "cycle_phase")


def _distinct_field_values(conn: sqlite3.Connection, field: str) -> int:
    try:
        rows = conn.execute(
            "SELECT ctx_json FROM compressed_global_coverage"
        ).fetchall()
    except sqlite3.OperationalError:
        return 0
    values = set()
    for (raw,) in rows:
        try:
            obj = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            continue
        if field in obj:
            values.add(str(obj[field]))
    return len(values)


def cgc_field_collapse_for_db(db_path: Path) -> Dict[str, object]:
    variant, seed, n = parse_d2f_run_dir(db_path.parent)
    with sqlite3.connect(db_path) as conn:
        try:
            cgc_count = int(conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0])
        except sqlite3.OperationalError:
            cgc_count = 0
        field_distinct = {
            f: _distinct_field_values(conn, f) for f in CGC_CONTEXT_FIELDS
        }
    collapsed = [f for f, d in field_distinct.items() if cgc_count > 0 and d <= 1]
    return {
        "variant": variant,
        "seed": seed,
        "expected_n": n,
        "cgc_rows": cgc_count,
        **{f"distinct_{f}": field_distinct[f] for f in CGC_CONTEXT_FIELDS},
        "collapsed_fields": ";".join(collapsed) if collapsed else "",
        "has_collapse": bool(collapsed),
    }


def cgc_field_collapse_frame(collection_root: Path) -> pd.DataFrame:
    rows = [cgc_field_collapse_for_db(db) for db in flat_db_list(collection_root)]
    return pd.DataFrame(rows)
