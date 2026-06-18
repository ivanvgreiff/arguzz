"""D1.B Batch 2 — corrected CGC first-hit maps per coarsening variant."""

from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Tuple

from analysis.cgc_variants import (
    LOOKUP_FAMILIES,
    cgc_key_log4_explicit,
    cgc_key_page_class,
    cgc_key_region_only,
    parse_memory_byte_addr,
)

VARIANTS = (
    "production_log2_corrected",
    "region_only",
    "log4_explicit",
    "page_class",
)


def _min_merge(dst: Dict[str, int], key: str, mid: int) -> None:
    if key not in dst or mid < dst[key]:
        dst[key] = mid


def _memory_ctx_json(ctx_key: str) -> dict:
    return json.loads(ctx_key)


def memory_region_only_map(memory_hits: Dict[str, int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for ctx_key, mid in memory_hits.items():
        d = _memory_ctx_json(ctx_key)
        coarse = cgc_key_region_only("memory", d)
        _min_merge(out, coarse, mid)
    return out


def memory_log4_explicit_map(memory_hits: Dict[str, int]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for ctx_key, mid in memory_hits.items():
        d = _memory_ctx_json(ctx_key)
        coarse = cgc_key_log4_explicit("memory", d)
        _min_merge(out, coarse, mid)
    return out


def memory_page_class_map(conn: sqlite3.Connection) -> Dict[str, int]:
    """Path 3: MIN(mutation_id) per page_class from global_failures byte_addr."""
    out: Dict[str, int] = {}
    for mid, addr in conn.execute(
        """
        SELECT mutation_id, address FROM global_failures
        WHERE family = 'memory' AND address IS NOT NULL
        """
    ):
        ba = parse_memory_byte_addr(addr)
        if ba is None:
            continue
        coarse = cgc_key_page_class("memory", ba)
        _min_merge(out, coarse, int(mid))
    return out


def hybrid_first_hit_map(
    memory_map: Dict[str, int], lookup_hits: Dict[str, int]
) -> Dict[str, int]:
    """§1.5 hybrid: memory re-bucket + lookup pass-through."""
    return {**lookup_hits, **memory_map}


def variant_first_hit_map(
    variant: str,
    memory_hits: Dict[str, int],
    lookup_hits: Dict[str, int],
    conn: sqlite3.Connection,
) -> Dict[str, int]:
    if variant == "production_log2_corrected":
        return hybrid_first_hit_map(memory_hits, lookup_hits)
    if variant == "region_only":
        return hybrid_first_hit_map(memory_region_only_map(memory_hits), lookup_hits)
    if variant == "log4_explicit":
        return hybrid_first_hit_map(memory_log4_explicit_map(memory_hits), lookup_hits)
    if variant == "page_class":
        return hybrid_first_hit_map(memory_page_class_map(conn), lookup_hits)
    raise ValueError(f"unknown variant {variant}")


def count_memory_keys(first_hit_map: Dict[str, int]) -> int:
    n = 0
    for k in first_hit_map:
        if k.startswith('{"family":'):
            try:
                if json.loads(k).get("family") in LOOKUP_FAMILIES:
                    continue
            except json.JSONDecodeError:
                pass
        if k.startswith("memory|") or (
            k.startswith('{"family": "memory"') or k.startswith('{"family":"memory"')
        ):
            n += 1
    return n


def count_lookup_keys(first_hit_map: Dict[str, int]) -> int:
    n = 0
    for k in first_hit_map:
        if k.startswith("memory|"):
            continue
        if k.startswith('{"family":'):
            try:
                fam = json.loads(k).get("family")
                if fam in LOOKUP_FAMILIES:
                    n += 1
            except json.JSONDecodeError:
                pass
    return n


def split_memory_lookup_counts(first_hit_map: Dict[str, int]) -> Tuple[int, int]:
    """Return (memory_key_count, lookup_key_count) for hybrid maps."""
    lookup = count_lookup_keys(first_hit_map)
    memory = len(first_hit_map) - lookup
    return memory, lookup
