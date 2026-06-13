"""B7 race filter — shared diff normalization for Inc 4 B8/B11.

Inherits Inc 3 B7 rules: drop executed_at, exclude D42 nondet addresses,
normalize mutation_rewards.delta_T to binary (0 vs >0) to absorb ~0.7%
Poseidon2 race noise under default parallelism.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from a4.audits.audit_common import OUTPUT_DIR

DROP_COLS: Dict[str, List[str]] = {
    "mutations": ["executed_at"],
    "bandit_decisions": [],
    "mutation_rewards": [],
    "mutation_substrategy": [],
    "arm_state_snapshot": ["snapshot_at"],
    "compressed_global_coverage": [],
}

FLOAT_TOLERANCE = 1e-9
FLOAT_COLS = {"posterior_q", "prior_q", "q_value"}


def load_nondet_addrs(path: Path) -> Set[int]:
    data = json.loads(path.read_text())
    return {int(a) for a in data["nondet_addresses"]}


def filter_meta(nondet_path: Path) -> Dict[str, Any]:
    nondet = load_nondet_addrs(nondet_path)
    return {
        "executed_at_excluded": True,
        "snapshot_at_excluded": True,
        "d42_addresses_excluded_count": len(nondet),
        "d42_addresses_source": str(nondet_path),
        "delta_t_normalized_to_binary": True,
        "float_tolerance": FLOAT_TOLERANCE,
        "reason_for_delta_t_normalization": (
            "Inc 3 B7 closure: ~0.7% Poseidon2 race-noise floor on delta_T; "
            "aggregate sign is what isolation actually requires"
        ),
    }


def _table_rows(conn: sqlite3.Connection, table: str) -> List[dict]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(f"SELECT * FROM {table} ORDER BY 1")
    return [dict(r) for r in cur.fetchall()]


def _mutation_addr(row: dict) -> Optional[int]:
    if row.get("kind") != "MEM_VAL_MOD":
        return None
    try:
        cfg = json.loads(row["config_json"])
    except (json.JSONDecodeError, TypeError):
        return None
    byte_addr = (cfg.get("_info") or {}).get("byte_addr")
    if byte_addr is None:
        return None
    return int(byte_addr, 0) if isinstance(byte_addr, str) else int(byte_addr)


def _filter_mutations(rows: List[dict], nondet: Set[int]) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        addr = _mutation_addr(row)
        if addr is not None and addr in nondet:
            continue
        filtered = {k: v for k, v in row.items() if k not in DROP_COLS["mutations"]}
        out.append(filtered)
    return out


def _normalize_rewards(rows: List[dict]) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        filtered = dict(row)
        if "delta_T" in filtered:
            filtered["delta_T_binary"] = 1 if int(filtered["delta_T"]) > 0 else 0
            del filtered["delta_T"]
        out.append(filtered)
    return out


def _filter_generic(rows: List[dict], table: str) -> List[dict]:
    skip = set(DROP_COLS.get(table, []))
    return [{k: v for k, v in row.items() if k not in skip} for row in rows]


def _values_equal(a: Any, b: Any, col: str) -> bool:
    if col in FLOAT_COLS:
        try:
            fa, fb = float(a), float(b)
            return abs(fa - fb) < FLOAT_TOLERANCE
        except (TypeError, ValueError):
            pass
    return a == b


def _diff_row_lists(left: List[dict], right: List[dict], table: str) -> int:
    if len(left) != len(right):
        return abs(len(left) - len(right)) + 1
    diffs = 0
    for la, rb in zip(left, right):
        keys = set(la) | set(rb)
        for k in keys:
            if not _values_equal(la.get(k), rb.get(k), k):
                diffs += 1
                break
    return diffs


def prepare_table(
    db_path: Path,
    table: str,
    *,
    nondet: Set[int],
) -> List[dict]:
    conn = sqlite3.connect(str(db_path))
    try:
        rows = _table_rows(conn, table)
    finally:
        conn.close()
    if table == "mutations":
        return _filter_mutations(rows, nondet)
    if table == "mutation_rewards":
        return _normalize_rewards(rows)
    return _filter_generic(rows, table)


def diff_tables(
    left_db: Path,
    right_db: Path,
    table: str,
    *,
    nondet_path: Path = OUTPUT_DIR / "A1_nondet_addrs.json",
) -> int:
    """Return 0 if filtered table contents match; else positive diff count."""
    nondet = load_nondet_addrs(nondet_path)
    left = prepare_table(left_db, table, nondet=nondet)
    right = prepare_table(right_db, table, nondet=nondet)
    return _diff_row_lists(left, right, table)


def diff_databases(
    left_db: Path,
    right_db: Path,
    *,
    tables: Optional[List[str]] = None,
    nondet_path: Path = OUTPUT_DIR / "A1_nondet_addrs.json",
) -> Dict[str, int]:
    """Diff all requested tables; return per-table diff counts."""
    if tables is None:
        tables = [
            "mutations",
            "bandit_decisions",
            "mutation_rewards",
            "mutation_substrategy",
            "arm_state_snapshot",
            "compressed_global_coverage",
        ]
    return {t: diff_tables(left_db, right_db, t, nondet_path=nondet_path) for t in tables}


def _mutation_prefix_key(row: dict) -> Tuple:
    """Prefix-equality: bandit draw path (kind/step/mutated), not DB schema extras."""
    cfg = json.loads(row["config_json"])
    txn = row.get("txn_idx")
    if txn is None:
        txn = cfg.get("txn_idx")
    return (row["kind"], int(row["step"]), txn, int(row["mutated_value"]))


def diff_mutation_prefix(
    baseline_db: Path,
    extended_db: Path,
    prefix_n: int,
    *,
    nondet_path: Path = OUTPUT_DIR / "A1_nondet_addrs.json",
) -> int:
    """Compare first prefix_n mutations using semantic keys (B7-style)."""
    nondet = load_nondet_addrs(nondet_path)
    conn_a = sqlite3.connect(str(baseline_db))
    conn_b = sqlite3.connect(str(extended_db))
    conn_a.row_factory = sqlite3.Row
    conn_b.row_factory = sqlite3.Row
    rows_a = [dict(r) for r in conn_a.execute(
        "SELECT * FROM mutations ORDER BY id LIMIT ?", (prefix_n,)
    ).fetchall()]
    rows_b = [dict(r) for r in conn_b.execute(
        "SELECT * FROM mutations ORDER BY id LIMIT ?", (prefix_n,)
    ).fetchall()]
    conn_a.close()
    conn_b.close()
    if len(rows_a) != len(rows_b):
        return abs(len(rows_a) - len(rows_b)) + 1
    diffs = 0
    for ra, rb in zip(rows_a, rows_b):
        if _mutation_prefix_key(ra) != _mutation_prefix_key(rb):
            diffs += 1
    return diffs
