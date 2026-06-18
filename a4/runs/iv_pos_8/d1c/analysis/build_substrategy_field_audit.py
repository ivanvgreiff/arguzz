#!/usr/bin/env python3
"""D1.C Batch 1 — audit mutation_substrategy non-null columns per kind."""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
D1C = Path(__file__).resolve().parents[1]
D1B_ANALYSIS = REPO / "a4/runs/iv_pos_8/d1b/analysis"
OUT_CSV = D1C / "d1c_substrategy_field_audit.csv"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(D1B_ANALYSIS))

from build_batch1_audit import cat_a_db_list  # noqa: E402  # D1.B source of truth

from analysis.bug_proximity import SUBSTRATEGY_COLUMNS  # noqa: E402

IV7 = REPO / "a4/runs/iv_pos_7"
sys.path.insert(0, str(IV7))


def derive_kind_mapping(
    counts: dict[str, dict[str, int]],
) -> dict[str, tuple[str, ...]]:
    """Columns with any non-null observations across the 30-DB corpus."""
    mapping: dict[str, tuple[str, ...]] = {}
    for kind in sorted(counts):
        active = tuple(c for c in SUBSTRATEGY_COLUMNS if counts[kind].get(c, 0) > 0)
        mapping[kind] = active
    return mapping


def run_audit() -> tuple[list[dict], dict[str, tuple[str, ...]]]:
    agg: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    kinds_seen: set[str] = set()
    for _corpus, _variant, _seed, db_path in cat_a_db_list():
        import sqlite3

        with sqlite3.connect(db_path) as conn:
            sql = f"""
                SELECT m.kind, {", ".join(
                    f"SUM(CASE WHEN ms.{c} IS NOT NULL THEN 1 ELSE 0 END)"
                    for c in SUBSTRATEGY_COLUMNS
                )}
                FROM mutation_substrategy ms
                JOIN mutations m ON m.id = ms.mutation_id
                GROUP BY m.kind
            """
            for row in conn.execute(sql):
                kind = row[0]
                kinds_seen.add(kind)
                for col, n in zip(SUBSTRATEGY_COLUMNS, row[1:]):
                    if n:
                        agg[kind][col] += int(n)

    rows: list[dict] = []
    for kind in sorted(kinds_seen):
        for col in SUBSTRATEGY_COLUMNS:
            rows.append(
                {
                    "kind": kind,
                    "column": col,
                    "non_null_count_across_30_dbs": agg[kind].get(col, 0),
                }
            )

    mapping = derive_kind_mapping({k: agg[k] for k in kinds_seen})
    fieldnames = ["kind", "column", "non_null_count_across_30_dbs"]
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return rows, mapping


def main() -> int:
    rows, mapping = run_audit()
    print(f"wrote {OUT_CSV} ({len(rows)} rows)")
    print("KIND_TO_SUBSTRATEGY_FIELDS = {")
    for kind, fields in mapping.items():
        print(f'    "{kind}": {fields!r},')
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
