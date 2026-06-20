"""Territory set-algebra for D2.F four-variant checkpoint (D2.G §4)."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, Set, Tuple

import pandas as pd

from a4.runs.iv_pos_7.analysis.constraint_loc_normalize import (
    normalize_constraint_loc,
    read_normalized_constraint_locs,
)

from .discover import D2F_VARIANTS, discover_d2f_dbs, flat_db_list, parse_d2f_run_dir

A4_VARIANTS = ("V5_control",)
ARGUZZ_VARIANTS = ("V6_uniform", "V6_cTS")
HYBRID_VARIANT = "Hybrid_cTS"

V5_ECALL_MRET_SIGNATURE = frozenset({
    "ControlMRET@inst_control.zir:93",
    "ControlLoadRootAndNonce@inst_control.zir:35",
    "ControlLoadRootAndNonce@inst_control.zir:44",
    "ControlLoadRootAndNonce@inst_control.zir:45",
})


def _variant_loc_union(
    collection_root: Path,
    variant: str,
    *,
    normalized: bool = True,
) -> Set[str]:
    mapping = discover_d2f_dbs(collection_root, variants=(variant,))
    union: Set[str] = set()
    for db in mapping.get(variant, {}).values():
        with sqlite3.connect(db) as conn:
            if normalized:
                union |= read_normalized_constraint_locs(conn)
            else:
                union |= {
                    r[0] for r in conn.execute(
                        "SELECT DISTINCT constraint_loc FROM failures"
                    ).fetchall()
                    if conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='failures'"
                    ).fetchone()
                }
    return union


def territory_decomposition(collection_root: Path) -> pd.DataFrame:
    sets_norm: Dict[str, Set[str]] = {
        v: _variant_loc_union(collection_root, v, normalized=True)
        for v in D2F_VARIANTS
    }
    v5 = sets_norm["V5_control"]
    v6u = sets_norm["V6_uniform"]
    v6c = sets_norm["V6_cTS"]
    hyb = sets_norm["Hybrid_cTS"]
    arguzz = v6u | v6c
    a4 = v5  # fresh V5 is the A4-family reference in D2.F
    all_four = v5 | v6u | v6c | hyb

    common = v5 & v6u & v6c & hyb
    a4_only = a4 - arguzz - hyb
    arguzz_only = arguzz - a4 - hyb
    hybrid_only = hyb - v5 - v6u - v6c
    v6_exclusive = (v6u | v6c) - v5 - hyb
    v5_ecall_mret = {normalize_constraint_loc(x) for x in V5_ECALL_MRET_SIGNATURE} & v5

    buckets = {
        "common_all_four": common,
        "a4_only": a4_only,
        "arguzz_only": arguzz_only,
        "hybrid_only": hybrid_only,
        "v6_exclusive": v6_exclusive,
        "v5_ecall_mret_signature": v5_ecall_mret,
    }
    rows = []
    for name, s in buckets.items():
        rows.append({
            "bucket": name,
            "count": len(s),
            "sample_locs": ";".join(sorted(s)[:5]),
        })
    rows.append({"bucket": "union_all_four", "count": len(all_four), "sample_locs": ""})
    return pd.DataFrame(rows)


def loc_overlap_pairs(collection_root: Path) -> pd.DataFrame:
    sets = {v: _variant_loc_union(collection_root, v) for v in D2F_VARIANTS}
    rows = []
    variants = list(D2F_VARIANTS)
    for i, a in enumerate(variants):
        for b in variants[i + 1:]:
            inter = sets[a] & sets[b]
            rows.append({
                "variant_a": a,
                "variant_b": b,
                "intersection": len(inter),
                "union": len(sets[a] | sets[b]),
                "jaccard": len(inter) / len(sets[a] | sets[b]) if (sets[a] | sets[b]) else 0.0,
            })
    return pd.DataFrame(rows)


def apples_to_apples_row(collection_root: Path) -> pd.DataFrame:
    """Shared-kind territory comparison scaffold (DG-2 confound normalization hook)."""
    sets = {v: _variant_loc_union(collection_root, v) for v in D2F_VARIANTS}
    v6u, v6c, hyb = sets["V6_uniform"], sets["V6_cTS"], sets["Hybrid_cTS"]
    return pd.DataFrame([{
        "v6_uniform_normalized_locs": len(v6u),
        "v6_cTS_normalized_locs": len(v6c),
        "hybrid_normalized_locs": len(hyb),
        "v6_cTS_minus_uniform": len(v6c - v6u),
        "hybrid_minus_uniform": len(hyb - v6u),
        "uniform_minus_v6_cTS": len(v6u - v6c),
    }])
