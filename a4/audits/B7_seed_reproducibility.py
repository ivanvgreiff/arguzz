"""B7 — Same-seed reproducibility (paired runs per variant)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    DEFAULT_HOST,
    GLOSSARY_META,
    INC2_HOST_ARGS,
    INC2_SMOKE_SEED,
    INC2_VARIANTS,
    OUTPUT_DIR,
    run_fuzz_smoke,
)

B7_N = 50
NONDET_PATH = OUTPUT_DIR / "A1_nondet_addrs.json"


def _load_nondet_addrs() -> Set[int]:
    data = json.loads(NONDET_PATH.read_text())
    return {int(a) for a in data["nondet_addresses"]}


def _table_rows(conn: sqlite3.Connection, table: str) -> List[dict]:
    conn.row_factory = sqlite3.Row
    cur = conn.execute(f"SELECT * FROM {table} ORDER BY 1")
    return [dict(r) for r in cur.fetchall()]


def _mutation_key(row: dict, nondet: Set[int]) -> Tuple:
    cfg = json.loads(row["config_json"])
    kind = row["kind"]
    step = row["step"]
    txn = row.get("txn_idx")
    mutated = row["mutated_value"]
    orig = row["original_value"]
    if kind == "MEM_VAL_MOD":
        byte_addr = (cfg.get("_info") or {}).get("byte_addr")
        if byte_addr is not None and int(byte_addr) in nondet:
            orig = "<nondet>"
    return (kind, step, txn, mutated, orig, row.get("verifier_accepted"), row.get("num_failures"))


def _diff_mutations(a_rows: List[dict], b_rows: List[dict], nondet: Set[int]) -> int:
    if len(a_rows) != len(b_rows):
        return max(len(a_rows), len(b_rows))
    diffs = 0
    for ra, rb in zip(a_rows, b_rows):
        ka = _mutation_key(ra, nondet)
        kb = _mutation_key(rb, nondet)
        if ka != kb:
            diffs += 1
    return diffs


def _diff_tables(
    db_a: Path,
    db_b: Path,
    table: str,
    *,
    sort_cols: Optional[List[str]] = None,
) -> int:
    conn_a = sqlite3.connect(str(db_a))
    conn_b = sqlite3.connect(str(db_b))
    rows_a = _table_rows(conn_a, table)
    rows_b = _table_rows(conn_b, table)
    conn_a.close()
    conn_b.close()

    if sort_cols:
        def _sort_key(r: dict) -> tuple:
            return tuple(r.get(c) for c in sort_cols)
        rows_a.sort(key=_sort_key)
        rows_b.sort(key=_sort_key)

    if len(rows_a) != len(rows_b):
        return abs(len(rows_a) - len(rows_b)) + 1

    diffs = 0
    skip_cols = {"executed_at"} if table == "mutations" else set()
    for ra, rb in zip(rows_a, rows_b):
        keys = set(ra) | set(rb)
        for k in keys:
            if k in skip_cols:
                continue
            if ra.get(k) != rb.get(k):
                diffs += 1
                break
    return diffs


def _diff_compressed_global(db_a: Path, db_b: Path) -> Tuple[int, str]:
    conn_a = sqlite3.connect(str(db_a))
    conn_b = sqlite3.connect(str(db_b))
    na = conn_a.execute("SELECT COUNT(*) FROM compressed_global_coverage").fetchone()[0]
    nb = conn_b.execute("SELECT COUNT(*) FROM compressed_global_coverage").fetchone()[0]
    conn_a.close()
    conn_b.close()
    if na == 0 and nb == 0:
        return 0, "empty_both"
    if na != nb:
        return abs(na - nb), "row_count"
    return _diff_tables(db_a, db_b, "compressed_global_coverage", sort_cols=["ctx_key"]), "sorted"


def run_paired(smoke_dir: Path, host: str, host_args: List[str]) -> None:
    for vk, spec in INC2_VARIANTS.items():
        for run in ("A", "B"):
            db = smoke_dir / f"b7_{vk}_run{run}_seed{INC2_SMOKE_SEED}_n{B7_N}.db"
            if db.exists():
                db.unlink()
            print(f"[B7] {vk} run_{run} n={B7_N}", flush=True)
            rc = run_fuzz_smoke(
                selector=spec["selector"],
                db_path=str(db),
                num=B7_N,
                host=host,
                host_args=host_args,
                seed=INC2_SMOKE_SEED,
                telemetry_level="full",
            )
            if rc != 0:
                raise RuntimeError(f"B7 fuzz {vk} run{run} exit {rc}")


def _resolve_b7_pair(smoke_dir: Path, vk: str, selector: str) -> Tuple[Path, Path]:
    patterns_a = [
        f"pos_audit_b7_{selector}_seed{INC2_SMOKE_SEED}_n{B7_N}_runA.db",
        f"b7_{vk}_runA_seed{INC2_SMOKE_SEED}_n{B7_N}.db",
    ]
    patterns_b = [
        f"pos_audit_b7_{selector}_seed{INC2_SMOKE_SEED}_n{B7_N}_runB.db",
        f"b7_{vk}_runB_seed{INC2_SMOKE_SEED}_n{B7_N}.db",
    ]
    db_a = db_b = None
    for pat in patterns_a:
        hits = sorted(smoke_dir.glob(pat))
        if hits:
            db_a = hits[0]
            break
    for pat in patterns_b:
        hits = sorted(smoke_dir.glob(pat))
        if hits:
            db_b = hits[0]
            break
    if db_a is None or db_b is None:
        raise FileNotFoundError(f"B7 pair missing for {vk} in {smoke_dir}")
    return db_a, db_b


def audit_variant(vk: str, smoke_dir: Path, nondet: Set[int], selector: str) -> Dict[str, Any]:
    db_a, db_b = _resolve_b7_pair(smoke_dir, vk, selector)

    conn_a = sqlite3.connect(str(db_a))
    conn_b = sqlite3.connect(str(db_b))
    mut_a = _table_rows(conn_a, "mutations")
    mut_b = _table_rows(conn_b, "mutations")
    conn_a.close()
    conn_b.close()

    mut_diff = _diff_mutations(mut_a, mut_b, nondet)
    bd_diff = _diff_tables(db_a, db_b, "bandit_decisions")
    mr_diff = _diff_tables(db_a, db_b, "mutation_rewards")
    lcv_diff = _diff_tables(
        db_a, db_b, "local_coverage_v2",
        sort_cols=["ctx_key", "constraint_loc", "major", "minor"],
    )
    cg_diff, cg_note = _diff_compressed_global(db_a, db_b)

    ok = mut_diff == 0 and bd_diff == 0 and mr_diff == 0
    return {
        "mutations_diff": mut_diff,
        "bandit_decisions_diff": bd_diff,
        "mutation_rewards_diff": mr_diff,
        "local_coverage_v2_diff": lcv_diff,
        "compressed_global_coverage_diff": cg_diff,
        "compressed_global_note": cg_note,
        "pass": ok,
        "db_a": str(db_a),
        "db_b": str(db_b),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="B7 seed reproducibility")
    parser.add_argument("--smoke-dir", default=str(OUTPUT_DIR / "inc3_smokes"))
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--run", action="store_true", help="Run paired local campaigns")
    parser.add_argument("--output", default=str(OUTPUT_DIR / "B7_seed_reproducibility.json"))
    parser.add_argument("host_args", nargs="*", default=INC2_HOST_ARGS)
    args = parser.parse_args()

    smoke_dir = Path(args.smoke_dir)
    smoke_dir.mkdir(parents=True, exist_ok=True)
    nondet = _load_nondet_addrs()

    if args.run:
        run_paired(smoke_dir, args.host, args.host_args)

    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B7_seed_reproducibility",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": INC2_SMOKE_SEED,
            "n_per_variant": B7_N,
        },
        "filter_metadata": {
            "excluded_columns": ["mutations.executed_at"],
            "excluded_addresses_count": len(nondet),
            "excluded_addresses_source": str(NONDET_PATH.relative_to(
                Path(__file__).resolve().parents[2]
            )),
        },
        "per_variant": {},
        "verdict": "PENDING",
    }

    all_pass = True
    for vk in sorted(INC2_VARIANTS):
        try:
            pv = audit_variant(vk, smoke_dir, nondet, INC2_VARIANTS[vk]["selector"])
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        report["per_variant"][vk] = pv
        if not pv["pass"]:
            all_pass = False

    report["verdict"] = "PASS" if all_pass else "FAIL"
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B7 verdict: {report['verdict']}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
