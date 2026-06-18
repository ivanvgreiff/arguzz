#!/usr/bin/env python3
"""Replay corrected CGC first-hit keys from hook3_raw (Batch 1.6).

Compares stored compressed_global_coverage (pre-fix labeling snapshot in DB)
against replay through the patched extractor. Read-only on input DBs.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

D1B_ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[5]
IV7 = REPO / "a4/runs/iv_pos_7"
IV7_DBS = IV7 / "dbs"
D1A_DBS = D1B_ROOT.parent / "d1a" / "dbs"
OUT_DIR = D1B_ROOT / "replay_artifacts"
CSV_PATH = D1B_ROOT / "d1b_batch1_replay_corrected.csv"

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(IV7))

from analysis.discover import discover_dbs  # noqa: E402
from a4.standalone.compressed_global_extractor import (  # noqa: E402
    extract_compressed_global_contexts,
)

# Reuse D1.A discovery from build_batch1_audit
from build_batch1_audit import discover_d1a_dbs  # noqa: E402


def _step_zone_map(conn: sqlite3.Connection) -> Dict[int, str]:
    zones: Dict[int, str] = {}
    for mid, arm in conn.execute(
        "SELECT mutation_id, selected_arm FROM bandit_decisions"
    ):
        if arm and "|" in arm:
            zones[mid] = arm.split("|")[1]
    return zones


def _stored_cgc_snapshot(conn: sqlite3.Connection) -> Tuple[Dict, Counter, Counter]:
    """Return first-hit map, memory region counts, lookup count from stored table."""
    first_hits: Dict[str, int] = {}
    mem_regions: Counter = Counter()
    lookup_keys = 0
    memory_keys = 0
    for ctx_key, family, ctx_json, mid in conn.execute(
        """
        SELECT ctx_key, family, ctx_json, first_hit_mutation_id
        FROM compressed_global_coverage
        """
    ):
        first_hits[ctx_key] = int(mid)
        if family == "memory":
            memory_keys += 1
            mem_regions[json.loads(ctx_json).get("address_region", "?")] += 1
        elif family in ("cycle", "u8", "u16"):
            lookup_keys += 1
    return first_hits, mem_regions, Counter({"memory": memory_keys, "lookup": lookup_keys})


def _lookup_first_hits_from_hook3(conn: sqlite3.Connection) -> Tuple[Dict[str, int], int]:
    """Lookup keys from hook3 compressed_ctx_json (runtime snapshot; patch-invariant)."""
    seen: Dict[str, int] = {}
    for mid, cctx in conn.execute(
        """
        SELECT mutation_id, compressed_ctx_json
        FROM hook3_raw
        WHERE compressed_ctx_json IS NOT NULL
        ORDER BY mutation_id
        """
    ):
        for entry in json.loads(cctx):
            fam = entry.get("family")
            if fam not in ("cycle", "u8", "u16"):
                continue
            key = json.dumps(entry, sort_keys=True)
            if key not in seen:
                seen[key] = int(mid)
    return seen, len(seen)


def _replay_memory_corrected(conn: sqlite3.Connection) -> Tuple[Dict[str, int], Counter, int]:
    """Replay memory keys from hook3_raw through patched extractor (major unused)."""
    step_zones = _step_zone_map(conn)
    seen: Dict[str, int] = {}
    mem_regions: Counter = Counter()
    memory_keys = 0

    rows = conn.execute(
        """
        SELECT h.mutation_id, h.raw_json, m.kind, m.step
        FROM hook3_raw h
        JOIN mutations m ON m.id = h.mutation_id
        WHERE h.raw_json IS NOT NULL
        ORDER BY h.mutation_id
        """
    ).fetchall()

    for mid, raw_json, kind, step in rows:
        rawj = json.loads(raw_json)
        zone = step_zones.get(mid, "core_other")
        # mutation_major affects lookup opcode_class only; memory path ignores it.
        ctxs = extract_compressed_global_contexts(
            rawj.get("family_residues"),
            rawj.get("family_details"),
            kind,
            zone,
            0,
        )
        for ctx in ctxs:
            if ctx.family != "memory":
                continue
            key = ctx.to_json_str()
            if key not in seen:
                seen[key] = int(mid)
                memory_keys += 1
                mem_regions[ctx.address_region] += 1

    return seen, mem_regions, memory_keys


def replay_memory_first_hits(conn: sqlite3.Connection) -> Dict[str, int]:
    """Corrected memory ctx_key → first_hit_mutation_id (Batch 2 source map)."""
    hits, _, _ = _replay_memory_corrected(conn)
    return hits


def replay_lookup_first_hits(conn: sqlite3.Connection) -> Dict[str, int]:
    """Lookup ctx_key → first_hit_mutation_id from hook3 snapshot."""
    hits, _ = _lookup_first_hits_from_hook3(conn)
    return hits


def replay_corrected_production_first_hits(conn: sqlite3.Connection) -> Dict[str, int]:
    """Merged corrected memory + lookup first-hit map."""
    mem = replay_memory_first_hits(conn)
    lookup = replay_lookup_first_hits(conn)
    return {**lookup, **mem}


def _replay_corrected(conn: sqlite3.Connection) -> Tuple[Dict, Counter, Counter]:
    """Build corrected first-hit map: patched memory replay + hook3 lookup snapshot."""
    mem_hits, mem_regions, memory_keys = _replay_memory_corrected(conn)
    lookup_hits, lookup_keys = _lookup_first_hits_from_hook3(conn)
    merged = {**lookup_hits, **mem_hits}
    return merged, mem_regions, Counter({"memory": memory_keys, "lookup": lookup_keys})


def replay_db(db_path: Path, corpus: str, variant: str, seed: int) -> dict:
    with sqlite3.connect(db_path) as conn:
        stored, stored_mem_regs, stored_fam = _stored_cgc_snapshot(conn)
        replayed, replay_mem_regs, replay_fam = _replay_corrected(conn)

    buggy_mem = stored_fam.get("memory", 0)
    corr_mem = replay_fam.get("memory", 0)
    buggy_lookup = stored_fam.get("lookup", 0)
    corr_lookup = replay_fam.get("lookup", 0)
    buggy_total = len(stored)
    corr_total = len(replayed)

    return {
        "corpus": corpus,
        "variant": variant,
        "seed": seed,
        "db_path": str(db_path),
        "prod_buggy_memory_keys": buggy_mem,
        "prod_corrected_memory_keys": corr_mem,
        "delta_memory_keys": corr_mem - buggy_mem,
        "delta_memory_pct": round(
            100.0 * (corr_mem - buggy_mem) / buggy_mem if buggy_mem else 0.0, 2
        ),
        "prod_buggy_lookup_keys": buggy_lookup,
        "prod_corrected_lookup_keys": corr_lookup,
        "prod_buggy_total": buggy_total,
        "prod_corrected_total": corr_total,
        "delta_total": corr_total - buggy_total,
        "prod_buggy_memory_regions_json": json.dumps(
            dict(sorted(stored_mem_regs.items())), sort_keys=True
        ),
        "prod_corrected_memory_regions_json": json.dumps(
            dict(sorted(replay_mem_regs.items())), sort_keys=True
        ),
    }


def cat_a_db_list() -> List[Tuple[str, str, int, Path]]:
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


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = [replay_db(p, c, v, s) for c, v, s, p in cat_a_db_list()]
    if len(rows) != 30:
        raise SystemExit(f"expected 30 DBs, got {len(rows)}")

    fieldnames = list(rows[0].keys())
    CSV_PATH.write_text("")  # truncate
    with CSV_PATH.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    sha = hashlib.sha256(CSV_PATH.read_bytes()).hexdigest()
    manifest = OUT_DIR / "d1b_batch1_replay_corrected.sha256"
    manifest.write_text(f"{sha}  {CSV_PATH.name}\n")

    lookup_mismatch = [
        r for r in rows
        if r["prod_buggy_lookup_keys"] != r["prod_corrected_lookup_keys"]
    ]
    print(f"wrote {CSV_PATH} ({len(rows)} rows)")
    print(f"sha256: {sha}")
    print(f"lookup key mismatches (expect 0): {len(lookup_mismatch)}")
    if lookup_mismatch:
        for r in lookup_mismatch[:3]:
            print(
                f"  {r['corpus']} s{r['seed']}: "
                f"{r['prod_buggy_lookup_keys']} -> {r['prod_corrected_lookup_keys']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
