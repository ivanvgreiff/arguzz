"""Unit tests for cgc_variants.py (D1.B Batch 1 + 1.5)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from .cgc_variants import (
    LOOKUP_FAMILIES,
    MEMORY_FAMILY,
    _PAGE_CLASS_USER_LAYOUT,
    _default_campaign_id,
    cgc_key_log4_explicit,
    cgc_key_page_class,
    cgc_key_region_only,
    count_cgc_log4_explicit,
    count_cgc_memory_log4_explicit,
    count_cgc_memory_production_log2,
    count_cgc_memory_region_only,
    count_cgc_page_class,
    count_cgc_production_log2,
    count_cgc_region_only,
    page_class,
    parse_memory_byte_addr,
)
from .discover import discover_dbs

_LAYOUT_JSON = Path(__file__).resolve().parents[2] / "iv_pos_8" / "d1b" / "d1b_guest_elf_layout.json"


@pytest.fixture(scope="module")
def sample_v5_db() -> Path:
    return discover_dbs()["V5"][1234]


def test_cgc_key_region_only_edge_cases():
    assert cgc_key_region_only("memory", {}) == "memory|unknown"
    assert cgc_key_region_only("memory", {"address_region": "invalid"}) == "memory|invalid"
    assert cgc_key_region_only("memory", {"address_region": "user", "address_bucket": 29}) == "memory|user"


def test_cgc_key_log4_explicit_halves_buckets():
    k0 = cgc_key_log4_explicit("memory", {"address_region": "user", "address_bucket": 0})
    k1 = cgc_key_log4_explicit("memory", {"address_region": "user", "address_bucket": 1})
    assert k0 == k1 == "memory|user|log4_0"
    k2 = cgc_key_log4_explicit("memory", {"address_region": "user", "address_bucket": 2})
    k3 = cgc_key_log4_explicit("memory", {"address_region": "user", "address_bucket": 3})
    assert k2 == k3 == "memory|user|log4_1"
    assert k0 != k2


def test_region_only_collapses_log2_buckets_within_region():
    keys = {
        cgc_key_region_only("memory", {"address_region": "user", "address_bucket": b})
        for b in range(32)
    }
    assert keys == {"memory|user"}


def test_page_class_elf_derived_ranges():
    """Each layout band maps to its label (midpoint probe)."""
    assert _LAYOUT_JSON.is_file(), "run build_page_class_layout.py first"
    for lo, hi, label in _PAGE_CLASS_USER_LAYOUT:
        mid = lo + max(1, (hi - lo) // 2)
        assert page_class(mid) == label, f"{label} @ {mid:#x}"


def test_page_class_user_dynamic_above_host_ecall():
    assert page_class(0x50000000) == "user_dynamic"
    assert page_class(0x42000100) == "user_dynamic"


def test_page_class_user_bigint_unchanged_by_user_dynamic():
    assert page_class(0xBFFF0000) == "user_bigint"
    assert page_class(0xBFFFC000) == "user_bigint"


def test_page_class_pass_through_non_user():
    assert page_class(0xFFFF0088) == "user_regs"
    assert page_class(0x00000000) == "zero_page"
    assert page_class(0xBFFF0000) == "user_bigint"


def test_page_class_stack_text_gap_folded():
    # [STACK_TOP, TEXT_START) gap → stack per half-open convention.
    assert page_class(0x00200500) == "stack"


def test_cgc_key_page_class_format():
    assert cgc_key_page_class("memory", 0x00210000) == "memory|text"


def test_parse_memory_byte_addr_forms():
    mem = "{'addr': 1, 'byte_addr': 0x200800, 'type': 'data'}"
    assert parse_memory_byte_addr(mem) == 0x200800
    cycle = "{'index': 0, 'plus': 1, 'minus': 1}"
    assert parse_memory_byte_addr(cycle) is None
    assert parse_memory_byte_addr("not a dict") is None


def test_page_class_empirical_gate_documented():
    data = json.loads(_LAYOUT_JSON.read_text())
    emp = data["empirical_validation"]
    assert emp.get("user_other_post_15b_gate_pass", emp["user_other_gate_pass"])
    assert emp["user_other_fraction_pct"] < 0.5
    assert emp["label_counts"].get("user_dynamic", 0) > 0


def test_count_cgc_page_class_stub_raises(sample_v5_db: Path):
    with sqlite3.connect(sample_v5_db) as conn:
        cid = _default_campaign_id(conn)
        with pytest.raises(NotImplementedError, match="Batch 2"):
            count_cgc_page_class(conn, cid)


def test_memory_subset_inequality(sample_v5_db: Path):
    with sqlite3.connect(sample_v5_db) as conn:
        cid = _default_campaign_id(conn)
        prod = count_cgc_memory_production_log2(conn, cid)
        log4 = count_cgc_memory_log4_explicit(conn, cid)
        region = count_cgc_memory_region_only(conn, cid)
        assert region <= log4 <= prod


def test_hybrid_total_inequality(sample_v5_db: Path):
    with sqlite3.connect(sample_v5_db) as conn:
        cid = _default_campaign_id(conn)
        prod = count_cgc_production_log2(conn, cid)
        log4 = count_cgc_log4_explicit(conn, cid)
        region = count_cgc_region_only(conn, cid)
        assert region <= log4 <= prod
        assert prod > 0


def test_lookup_families_constant_across_variants(sample_v5_db: Path):
    with sqlite3.connect(sample_v5_db) as conn:
        cid = _default_campaign_id(conn)
        lookup_count = conn.execute(
            f"""
            SELECT COUNT(DISTINCT ctx_key) FROM compressed_global_coverage
            WHERE campaign_id = ? AND family IN ({",".join("?" * len(LOOKUP_FAMILIES))})
            """,
            (cid, *sorted(LOOKUP_FAMILIES)),
        ).fetchone()[0]
        memory_prod = count_cgc_memory_production_log2(conn, cid)
        memory_region = count_cgc_memory_region_only(conn, cid)
        assert count_cgc_region_only(conn, cid) == memory_region + lookup_count
        assert count_cgc_production_log2(conn, cid) == memory_prod + lookup_count


def test_invariants_hold_across_v1_v5_seeds():
    m = discover_dbs(variants=("V1", "V5"))
    for variant in ("V1", "V5"):
        for seed, db in sorted(m[variant].items()):
            with sqlite3.connect(db) as conn:
                cid = _default_campaign_id(conn)
                prod = count_cgc_production_log2(conn, cid)
                log4 = count_cgc_log4_explicit(conn, cid)
                region = count_cgc_region_only(conn, cid)
                assert region <= log4 <= prod, f"{variant} seed{seed}"
