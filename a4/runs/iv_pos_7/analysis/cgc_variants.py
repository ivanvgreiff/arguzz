"""D1.B — alternate CGC coarsening functions for post-hoc analysis.

These are analysis-time re-buckets / re-derivations. The production CGC
pipeline is unchanged — D1.B reads stored data and reapplies a different
key derivation, then counts uniques per (family, key).

Per IV_POS_8_D1_B_SPEC.md v0.3.1 §1.2–§1.5, three variants are evaluated:
  • region_only      — Path 1 (re-bucket from ctx_json)
  • log4_explicit    — Path 1 (re-bucket from ctx_json)
  • page_class       — Path 3 (recompute from global_failures.address dict
                       string → ast.literal_eval → byte_addr); Batch 1.5 impl
"""
from __future__ import annotations

import ast
import json
import sqlite3
import sys
from pathlib import Path
from typing import FrozenSet, List, Optional, Set, Tuple

_REPO = Path(__file__).resolve().parents[4]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from a4.standalone.compressed_global_extractor import address_region  # noqa: E402

MEMORY_FAMILY = "memory"
LOOKUP_FAMILIES: FrozenSet[str] = frozenset({"u8", "u16", "cycle"})

_LAYOUT_JSON = (
    Path(__file__).resolve().parents[2]
    / "iv_pos_8"
    / "d1b"
    / "d1b_guest_elf_layout.json"
)

# Fallback until Batch 1.5 derivation runs (half-open-up-to-next-section convention).
_DEFAULT_PAGE_CLASS_USER_LAYOUT: List[Tuple[int, int, str]] = [
    (0x00010000, 0x00200800, "stack"),
    (0x00200800, 0x00219DB8, "text"),
    (0x00219DB8, 0x0022133C, "rodata"),
    (0x0022133C, 0x00221488, "data_bss"),
    (0x00221488, 0x42000000, "heap"),
    (0x42000000, 0x42000100, "host_ecall"),
    (0x42000100, 0xBFFF0000, "user_dynamic"),
]
_PAGE_CLASS_USER_DEFAULT = "user_other"


def _load_page_class_layout() -> List[Tuple[int, int, str]]:
    if not _LAYOUT_JSON.is_file():
        return list(_DEFAULT_PAGE_CLASS_USER_LAYOUT)
    data = json.loads(_LAYOUT_JSON.read_text())
    rows = data.get("page_class_user_layout", [])
    return [(int(r["lo"]), int(r["hi"]), str(r["label"])) for r in rows]


_PAGE_CLASS_USER_LAYOUT: List[Tuple[int, int, str]] = _load_page_class_layout()


def parse_memory_byte_addr(address: str) -> Optional[int]:
    """Extract memory-family byte_addr from global_failures.address dict-string.

    Returns None for non-memory rows (cycle family) or malformed strings.
    """
    try:
        d = ast.literal_eval(address)
    except (ValueError, SyntaxError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    ba = d.get("byte_addr")
    return int(ba) if isinstance(ba, int) else None


def cgc_key_region_only(family: str, ctx_json: dict) -> str:
    """Coarsest variant: (family, address_region). Drops address_bucket."""
    return f"{family}|{ctx_json.get('address_region', 'unknown')}"


def cgc_key_log4_explicit(family: str, ctx_json: dict) -> str:
    """Explicit log4 bucketing. Strictly coarser than production log2."""
    bucket_log2 = ctx_json.get("address_bucket", 0)
    bucket_log4 = bucket_log2 // 2
    region = ctx_json.get("address_region", "unknown")
    return f"{family}|{region}|log4_{bucket_log4}"


def page_class(addr: int) -> str:
    """Semantic memory-use class (Batch 1.5 ELF-derived layout)."""
    region = address_region(addr)
    if region not in ("user", "user_bigint"):
        return region
    if region == "user_bigint":
        return region
    for lo, hi, label in _PAGE_CLASS_USER_LAYOUT:
        if lo <= addr < hi:
            return label
    return _PAGE_CLASS_USER_DEFAULT


def cgc_key_page_class(family: str, addr: int) -> str:
    """Page-class variant: (family, page_class). Drops address_bucket."""
    return f"{family}|{page_class(addr)}"


def _parse_ctx_json(ctx_json: str) -> dict:
    if not ctx_json:
        return {}
    return json.loads(ctx_json)


def _default_campaign_id(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT campaign_id FROM compressed_global_coverage LIMIT 1"
    ).fetchone()
    if row is None:
        raise ValueError("compressed_global_coverage is empty")
    return int(row[0])


def count_cgc_production_log2(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Production baseline: one row per first-hit ctx_key (hybrid total)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM compressed_global_coverage WHERE campaign_id = ?",
        (campaign_id,),
    ).fetchone()
    return int(row[0])


def _memory_keys_region_only(rows: list[tuple]) -> Set[str]:
    keys: Set[str] = set()
    for family, ctx_json_str, _ctx_key in rows:
        if family != MEMORY_FAMILY:
            continue
        keys.add(cgc_key_region_only(family, _parse_ctx_json(ctx_json_str)))
    return keys


def _memory_keys_log4_explicit(rows: list[tuple]) -> Set[str]:
    keys: Set[str] = set()
    for family, ctx_json_str, _ctx_key in rows:
        if family != MEMORY_FAMILY:
            continue
        keys.add(cgc_key_log4_explicit(family, _parse_ctx_json(ctx_json_str)))
    return keys


def _lookup_keys(rows: list[tuple]) -> Set[str]:
    return {
        ctx_key
        for family, _ctx_json, ctx_key in rows
        if family in LOOKUP_FAMILIES
    }


def _load_cgc_rows(conn: sqlite3.Connection, campaign_id: int) -> list[tuple]:
    return conn.execute(
        """
        SELECT family, ctx_json, ctx_key
        FROM compressed_global_coverage
        WHERE campaign_id = ?
        """,
        (campaign_id,),
    ).fetchall()


def count_cgc_region_only(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Hybrid total: memory re-bucket + lookup pass-through (§1.5)."""
    rows = _load_cgc_rows(conn, campaign_id)
    return len(_memory_keys_region_only(rows)) + len(_lookup_keys(rows))


def count_cgc_log4_explicit(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Hybrid total: memory log4 re-bucket + lookup pass-through (§1.5)."""
    rows = _load_cgc_rows(conn, campaign_id)
    return len(_memory_keys_log4_explicit(rows)) + len(_lookup_keys(rows))


def count_cgc_page_class(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Path 3 counter — implemented in Batch 2 after page_class() in Batch 1.5."""
    raise NotImplementedError("implemented in Batch 2 (after page_class in Batch 1.5)")


def count_cgc_memory_region_only(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Memory-family subset only (§1.5.1 invariant tests)."""
    return len(_memory_keys_region_only(_load_cgc_rows(conn, campaign_id)))


def count_cgc_memory_log4_explicit(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Memory-family subset only (§1.5.1 invariant tests)."""
    return len(_memory_keys_log4_explicit(_load_cgc_rows(conn, campaign_id)))


def count_cgc_memory_production_log2(conn: sqlite3.Connection, campaign_id: int) -> int:
    """Memory-family production row count."""
    row = conn.execute(
        """
        SELECT COUNT(*) FROM compressed_global_coverage
        WHERE campaign_id = ? AND family = ?
        """,
        (campaign_id, MEMORY_FAMILY),
    ).fetchone()
    return int(row[0])


# §1.4 aliases for metrics integration (Batch 2+).
compressed_global_context_final_region_only = count_cgc_region_only
compressed_global_context_final_log4_explicit = count_cgc_log4_explicit
compressed_global_context_final_page_class = count_cgc_page_class
