#!/usr/bin/env python3
"""D1.B Batch 1 — 30-DB Cat-A data audit + smoke validation."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Optional, Tuple

D1B_ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
IV7_DBS = IV7 / "dbs"
D1A_DBS = D1B_ROOT.parent / "d1a" / "dbs"
OUT_DIR = D1B_ROOT

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))

from analysis.cgc_variants import (  # noqa: E402
    _default_campaign_id,
    count_cgc_log4_explicit,
    count_cgc_page_class,
    count_cgc_production_log2,
    count_cgc_region_only,
    parse_memory_byte_addr,
)
from analysis.discover import discover_dbs, parse_db_path  # noqa: E402

AUDIT_CSV = OUT_DIR / "d1b_batch1_data_audit.csv"
SMOKE_TXT = OUT_DIR / "d1b_batch1_smoke.txt"

D1A_SELECTORS = (
    ("cTS_semantic_v2_decayexp", "D1.A-decayexp"),
    ("cTS_semantic_v2_decayepoch", "D1.A-decayepoch"),
)


def discover_d1a_dbs(dbs_root: Path = D1A_DBS) -> Dict[str, Dict[int, Path]]:
    """Flat D1.A DB filenames → corpus label → seed → path."""
    found: Dict[str, Dict[int, Path]] = {label: {} for _, label in D1A_SELECTORS}
    for db in sorted(dbs_root.glob("*.db")):
        name = db.name
        label = None
        for sel, lab in D1A_SELECTORS:
            if sel in name:
                label = lab
                break
        if label is None:
            continue
        m = re.search(r"seed(\d+)", name)
        if not m:
            continue
        seed = int(m.group(1))
        prev = found[label].get(seed)
        if prev is None or db.stat().st_mtime >= prev.stat().st_mtime:
            found[label][seed] = db
    return found


def cat_a_db_list() -> List[Tuple[str, str, int, Path]]:
    """30-row Cat-A corpus: 10 V1 + 10 V5 + 10 D1.A decay."""
    m = discover_dbs(IV7_DBS, variants=("V1", "V5"))
    rows: List[Tuple[str, str, int, Path]] = []
    for variant in ("V1", "V5"):
        for seed in sorted(m[variant]):
            rows.append((variant, variant, seed, m[variant][seed]))
    d1a = discover_d1a_dbs()
    for label in ("D1.A-decayexp", "D1.A-decayepoch"):
        for seed in sorted(d1a[label]):
            rows.append((label, label, seed, d1a[label][seed]))
    return rows


def _address_region_distribution(conn: sqlite3.Connection, campaign_id: int) -> str:
    counts: Counter[str] = Counter()
    for (ctx_json_str,) in conn.execute(
        """
        SELECT ctx_json FROM compressed_global_coverage
        WHERE campaign_id = ? AND family = 'memory'
        """,
        (campaign_id,),
    ):
        try:
            ctx = json.loads(ctx_json_str)
        except json.JSONDecodeError:
            counts["__malformed_json__"] += 1
            continue
        counts[ctx.get("address_region", "__missing__")] += 1
    return json.dumps(dict(sorted(counts.items())), sort_keys=True)


def _memory_ctx_json_keysets(conn: sqlite3.Connection, campaign_id: int) -> Tuple[str, int]:
    keysets: set[frozenset] = set()
    bad_json = 0
    for (ctx_json_str,) in conn.execute(
        """
        SELECT ctx_json FROM compressed_global_coverage
        WHERE campaign_id = ? AND family = 'memory'
        """,
        (campaign_id,),
    ):
        try:
            ctx = json.loads(ctx_json_str)
        except json.JSONDecodeError:
            bad_json += 1
            continue
        keysets.add(frozenset(ctx.keys()))
    observed = sorted({",".join(sorted(ks)) for ks in keysets})
    return ";".join(observed), bad_json


def audit_db(corpus: str, variant: str, seed: int, db_path: Path) -> dict:
    with sqlite3.connect(db_path) as conn:
        cid = _default_campaign_id(conn)
        cgc_rows = int(
            conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage WHERE campaign_id = ?",
                (cid,),
            ).fetchone()[0]
        )
        gf_rows = int(conn.execute("SELECT COUNT(*) FROM global_failures").fetchone()[0])

        byte_addrs: List[int] = []
        parse_none = 0
        for (address,) in conn.execute(
            "SELECT address FROM global_failures WHERE family = 'memory'"
        ):
            ba = parse_memory_byte_addr(address)
            if ba is None:
                parse_none += 1
            else:
                byte_addrs.append(ba)

        addr_region_dist = _address_region_distribution(conn, cid)
        keyset_observed, ctx_json_bad = _memory_ctx_json_keysets(conn, cid)

        all_ctx_ok = True
        for (ctx_json_str,) in conn.execute(
            "SELECT ctx_json FROM compressed_global_coverage WHERE campaign_id = ?",
            (cid,),
        ):
            try:
                json.loads(ctx_json_str)
            except json.JSONDecodeError:
                all_ctx_ok = False
                break

    return {
        "corpus": corpus,
        "variant": variant,
        "seed": seed,
        "db_path": str(db_path),
        "campaign_id": cid,
        "cgc_row_count": cgc_rows,
        "global_failures_row_count": gf_rows,
        "address_region_distribution": addr_region_dist,
        "memory_byte_addr_min": min(byte_addrs) if byte_addrs else "",
        "memory_byte_addr_max": max(byte_addrs) if byte_addrs else "",
        "memory_byte_addr_mean": round(mean(byte_addrs), 2) if byte_addrs else "",
        "memory_parse_none_count": parse_none,
        "memory_ctx_json_keysets": keyset_observed,
        "ctx_json_malformed_count": ctx_json_bad,
        "ctx_json_all_well_formed": all_ctx_ok,
    }


def run_audit() -> List[dict]:
    rows = [audit_db(c, v, s, p) for c, v, s, p in cat_a_db_list()]
    if len(rows) != 30:
        raise SystemExit(f"expected 30 DBs, found {len(rows)}")
    fieldnames = list(rows[0].keys())
    with AUDIT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return rows


def run_smoke() -> str:
    m = discover_dbs(IV7_DBS, variants=("V5",))
    v5_db = m["V5"][1234]
    d1a = discover_d1a_dbs()
    decayexp_db = d1a["D1.A-decayexp"][1234]

    lines: List[str] = []
    for label, db in (("R2-V5", v5_db), ("D1.A-decayexp", decayexp_db)):
        with sqlite3.connect(db) as conn:
            cid = _default_campaign_id(conn)
            prod = count_cgc_production_log2(conn, cid)
            region = count_cgc_region_only(conn, cid)
            log4 = count_cgc_log4_explicit(conn, cid)
            try:
                count_cgc_page_class(conn, cid)
                page_msg = "page_class=UNEXPECTED_OK"
            except NotImplementedError as exc:
                page_msg = f"page_class=NotImplementedError({exc})"
            ok = region <= log4 <= prod
            lines.append(
                f"{label} {db.name}: production={prod} region_only={region} "
                f"log4_explicit={log4} inequality_ok={ok} {page_msg}"
            )
    text = "\n".join(lines) + "\n"
    SMOKE_TXT.write_text(text)
    print(text, end="")
    return text


def main() -> int:
    rows = run_audit()
    print(f"wrote {AUDIT_CSV} ({len(rows)} rows)")
    run_smoke()
    print(f"wrote {SMOKE_TXT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
