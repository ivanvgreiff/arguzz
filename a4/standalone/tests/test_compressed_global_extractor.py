"""
Phase 3 (cloud1) — tests for `compressed_global_extractor.py`.

Validates:
    - D8 address-region map covers every region with concrete addresses
    - log2-bucket functions are correct for representative values
    - D16 txn_role/cycle_phase derivations cover all 8 mutation kinds
      and all 17 semantic zones
    - extractor returns empty set for empty/None Hook 3 input
    - extractor compresses many raw addresses into few semantic contexts
    - memory and lookup families produce the correct dataclass types
    - safety cap (64) bounds output size
    - to_storage_rows produces valid (ctx_key, family, ctx_json) triples
    - JSON serialization is round-trippable and stable
"""

import json
from typing import List, Optional

import pytest

from a4.standalone.compressed_global import (
    ADDRESS_REGIONS, MEMORY_TXN_ROLES, MEMORY_CYCLE_PHASES,
    LOOKUP_FAMILIES, OPCODE_CLASSES,
    GlobalMemoryCtx, GlobalLookupCtx,
)
from a4.standalone.compressed_global_extractor import (
    address_region, address_bucket, lookup_index_bucket,
    txn_role_for_kind, cycle_phase_for_zone,
    extract_compressed_global_contexts, to_storage_rows,
    _GLOBAL_COMPRESSED_SAFETY_CAP,
)
from a4.standalone.semantic_zones import SEMANTIC_ZONES, SINGLETON_ZONES


# ============================================================================
# D8 address region map tests
# ============================================================================


@pytest.mark.parametrize("addr, expected", [
    (0x00000000, "zero_page"),
    (0x0000FFFF, "zero_page"),
    (0x00010000, "user"),
    (0x00020000, "user"),
    (0xBFFEFFFF, "user"),
    (0xBFFFFFFF, "user_bigint"),
    (0xC0000000, "kernel"),
    (0xFEFFFFFF, "kernel"),
    (0xFF000000, "invalid"),           # gap before machine_regs
    (0xFFFF0000, "machine_regs"),
    (0xFFFF007F, "machine_regs"),
    (0xFFFF0080, "user_regs"),
    (0xFFFF00FF, "user_regs"),
    (0xFFFF0100, "machine_special"),
    (0xFFFF0FFF, "machine_special"),
    (0xFFFF1000, "ecall_dispatch"),
    (0xFFFF1FFF, "ecall_dispatch"),
    (0xFFFF2000, "trap_dispatch_and_beyond"),
    (0xFFFFFFFF, "trap_dispatch_and_beyond"),
])
def test_address_region_d8_map(addr, expected):
    assert address_region(addr) == expected


def test_address_region_invalid_for_negatives_and_oversize():
    assert address_region(-1) == "invalid"
    assert address_region(1 << 32) == "invalid"
    assert address_region(1 << 40) == "invalid"


def test_every_region_in_d8_map_is_reachable():
    """All platform.rs D8 regions reachable (G3 resolved)."""
    seen = {
        address_region(0x00000000),
        address_region(0x00020000),
        address_region(0xBFFFFFFF),
        address_region(0xC0000000),
        address_region(0xFFFF0000),
        address_region(0xFFFF0084),
        address_region(0xFFFF0100),
        address_region(0xFFFF1000),
        address_region(0xFFFF2000),
        address_region(0xFF000000),  # invalid gap
    }
    assert seen == {
        "zero_page", "user", "user_bigint", "kernel",
        "machine_regs", "user_regs", "machine_special",
        "ecall_dispatch", "trap_dispatch_and_beyond", "invalid",
    }


# ============================================================================
# Log2-bucket tests
# ============================================================================


@pytest.mark.parametrize("addr, expected_bucket", [
    (0, 0),
    (1, 0),
    (2, 1),
    (3, 1),
    (4, 2),
    (0x80000000, 31),
    (0xFFFFFFFF, 31),
])
def test_address_bucket_log2(addr, expected_bucket):
    assert address_bucket(addr) == expected_bucket


def test_address_bucket_negative_returns_zero():
    assert address_bucket(-5) == 0


def test_lookup_index_bucket_basic():
    assert lookup_index_bucket(0) == 0
    assert lookup_index_bucket(1) == 0
    assert lookup_index_bucket(255) == 7
    assert lookup_index_bucket(256) == 8
    assert lookup_index_bucket(65535) == 15


# ============================================================================
# D16 — mutation context → (txn_role, cycle_phase) derivations
# ============================================================================


@pytest.mark.parametrize("kind, expected_role", [
    # V5 control set (8 kinds)
    ("INSTR_WORD_MOD",      "ifetch"),
    ("INSTR_WORD_MOD_FULL", "ifetch"),
    ("INSTR_WORD_MOD_SUR",  "ifetch"),
    ("INSTR_TYPE_MOD",      "ifetch"),
    ("LOAD_VAL_MOD",        "read"),
    ("STORE_OUT_MOD",       "write"),
    ("MEM_VAL_MOD",         "read"),
    ("PRE_EXEC_REG_MOD",    "register"),
    ("COMP_OUT_MOD",        "register"),
    # D2.B live kinds (3) — per NFP-4
    ("TXN_PREV_WORD_MOD",   "prev_word"),
    ("TXN_PREV_CYCLE_MOD",  "prev_cycle"),
    ("CYCLE_DIFF_COUNT_MOD", "read"),   # PS-2: was "diff_count" pre-remap
    # D2.B dead kinds (post-PS-1) — sentinel entries so any residual caller
    # gets a Pro-valid label; not in MUTATION_KINDS.
    ("TXN_ADDR_MOD",        "read"),    # PS-2: was "addr" pre-remap
    ("TXN_CYCLE_PHASE_MOD", "read"),    # PS-2: was "cycle_phase" pre-remap
    ("CYCLE_MODE_MOD",      "read"),
    # Default fallback
    ("UNKNOWN_KIND",        "read"),
])
def test_txn_role_for_kind_all_known_kinds(kind, expected_role):
    assert txn_role_for_kind(kind) == expected_role


def test_all_txn_roles_used_are_valid_per_pro_spec():
    """Every txn_role we produce must be in MEMORY_TXN_ROLES (Pro §5 / NFP-4).

    Post-D2.B-PS-2: enumeration extended from the original 8 V5 kinds to all
    11 live MUTATION_KINDS so this contract test catches any future drift on
    D2.B-live kinds (the gap that allowed NFP-4 drift to ship undetected
    until F8). Dead D2.B kinds (TXN_ADDR_MOD, TXN_CYCLE_PHASE_MOD,
    CYCLE_MODE_MOD) are also included as sentinels: their dict entries are
    dead code per PS-1 but must still return Pro-valid labels.
    """
    from a4.standalone.fuzzer import A4Fuzzer
    live_kinds = list(A4Fuzzer.MUTATION_KINDS)  # 11 live kinds post-PS-1
    dead_kinds = [  # D2.B dead-arm sentinels (per W-17/W-18 audits)
        "TXN_ADDR_MOD", "TXN_CYCLE_PHASE_MOD",
        "CYCLE_MODE_MOD", "CYCLE_PC_MOD", "CYCLE_STATE_MOD",
    ]
    for k in live_kinds + dead_kinds + ["UNKNOWN_KIND"]:
        assert txn_role_for_kind(k) in MEMORY_TXN_ROLES, (
            f"{k} -> {txn_role_for_kind(k)!r} violates Pro-valid roles "
            "(MEMORY_TXN_ROLES); see NFP-4 + D2.B-PS-2."
        )


@pytest.mark.parametrize("zone, expected_phase", [
    ("step0",              "boundary"),
    ("last_step",          "boundary"),
    ("pre_ecall",          "ecall"),
    ("post_ecall",         "ecall"),
    ("pre_mret",           "mret"),
    ("post_mret",          "mret"),
    ("pre_halt",           "halt"),
    ("post_halt",          "halt"),
    ("core_arithmetic",    "normal"),
    ("core_memory_load",   "normal"),
    ("core_memory_store",  "normal"),
    ("core_branch",        "normal"),
    ("core_mul",           "normal"),
    ("core_div",           "normal"),
    ("core_sha",           "normal"),
    ("core_poseidon",      "normal"),
    ("core_other",         "normal"),
    ("unknown_zone",       "normal"),  # default
])
def test_cycle_phase_for_every_zone(zone, expected_phase):
    assert cycle_phase_for_zone(zone) == expected_phase


def test_all_cycle_phases_used_are_valid_per_pro_spec():
    """Every cycle_phase we produce must be in MEMORY_CYCLE_PHASES (Pro §5)."""
    for z in SEMANTIC_ZONES + ("unknown_zone",):
        assert cycle_phase_for_zone(z) in MEMORY_CYCLE_PHASES


def test_all_17_semantic_zones_have_a_cycle_phase():
    """No zone should map to None or an undefined phase."""
    for z in SEMANTIC_ZONES:
        phase = cycle_phase_for_zone(z)
        assert phase in MEMORY_CYCLE_PHASES


# ============================================================================
# Extractor — basic cases
# ============================================================================


def test_extractor_empty_input_returns_empty_set():
    assert extract_compressed_global_contexts(
        None, None, "INSTR_TYPE_MOD", "step0", 0,
    ) == set()
    assert extract_compressed_global_contexts(
        [], [], "INSTR_TYPE_MOD", "step0", 0,
    ) == set()


def test_extractor_no_nonzero_families_returns_empty():
    """If all families have nonzero=False, output is empty."""
    fr = [{"family": "memory", "nonzero": False}]
    fd = [{"family": "memory", "broken_addrs": [0x80001000]}]
    assert extract_compressed_global_contexts(
        fr, fd, "INSTR_TYPE_MOD", "step0", 0,
    ) == set()


def test_extractor_memory_single_address():
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": [0x80001000]}]
    out = extract_compressed_global_contexts(
        fr, fd, "INSTR_TYPE_MOD", "step0", 0,
    )
    assert len(out) == 1
    ctx = next(iter(out))
    assert isinstance(ctx, GlobalMemoryCtx)
    assert ctx.family == "memory"
    assert ctx.address_region == "user"
    assert ctx.address_bucket == address_bucket(0x80001000)
    assert ctx.txn_role == "ifetch"        # INSTR_TYPE_MOD → ifetch
    assert ctx.cycle_phase == "boundary"   # step0 → boundary


def test_extractor_compresses_many_addresses_in_same_region_and_bucket():
    """Addresses within the same (region, log2-bucket) should compress to
    a single GlobalMemoryCtx."""
    fr = [{"family": "memory", "nonzero": True}]
    # All 4 addresses are in user region, log2 ∈ [31, 31]:
    addrs = [0x80000000, 0x80000004, 0x80000008, 0x9FFFFFFF]
    fd = [{"family": "memory", "broken_addrs": addrs}]
    out = extract_compressed_global_contexts(
        fr, fd, "LOAD_VAL_MOD", "core_memory_load", 5,
    )
    assert len(out) == 1                   # compressed!
    ctx = next(iter(out))
    assert ctx.address_region == "user"
    assert ctx.address_bucket == 31


def test_extractor_multiple_regions_produce_multiple_contexts():
    """Addresses in different regions remain distinct."""
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": [
        0x00000100,    # zero_page
        0x00020000,    # user
        0xC0000000,    # kernel
        0xFFFF0084,    # user_regs
    ]}]
    out = extract_compressed_global_contexts(
        fr, fd, "LOAD_VAL_MOD", "core_memory_load", 5,
    )
    assert len(out) == 4
    regions = {c.address_region for c in out}
    assert regions == {"zero_page", "user", "kernel", "user_regs"}


def test_extractor_lookup_family_produces_lookup_ctx():
    fr = [{"family": "u8", "nonzero": True}]
    fd = [{"family": "u8", "broken_indices": [42]}]
    out = extract_compressed_global_contexts(
        fr, fd, "COMP_OUT_MOD", "core_arithmetic", 0,
    )
    assert len(out) == 1
    ctx = next(iter(out))
    assert isinstance(ctx, GlobalLookupCtx)
    assert ctx.family == "u8"
    assert ctx.lookup_index_bucket == lookup_index_bucket(42)
    assert ctx.producer_kind == "COMP_OUT_MOD"
    assert ctx.opcode_class == "alu"       # major 0 → alu


def test_extractor_mixed_memory_and_lookup():
    fr = [
        {"family": "memory", "nonzero": True},
        {"family": "u16",    "nonzero": True},
    ]
    fd = [
        {"family": "memory", "broken_addrs": [0x80001000, 0x80002000]},  # 2 addrs, same region/bucket
        {"family": "u16",    "broken_indices": [256, 257]},              # both bucket 8
    ]
    out = extract_compressed_global_contexts(
        fr, fd, "MEM_VAL_MOD", "pre_ecall", 8,
    )
    mem_ctxs = [c for c in out if isinstance(c, GlobalMemoryCtx)]
    lkp_ctxs = [c for c in out if isinstance(c, GlobalLookupCtx)]
    assert len(mem_ctxs) == 1              # compressed
    assert len(lkp_ctxs) == 1              # compressed
    assert mem_ctxs[0].cycle_phase == "ecall"   # pre_ecall → ecall
    assert mem_ctxs[0].txn_role == "read"       # MEM_VAL_MOD → read


def test_extractor_filters_unknown_families():
    """Hook 3 might report an unknown family; we should silently skip it."""
    fr = [
        {"family": "memory",  "nonzero": True},
        {"family": "fictional","nonzero": True},
    ]
    fd = [
        {"family": "memory",   "broken_addrs": [0x80001000]},
        {"family": "fictional","broken_addrs": [0x123456]},
    ]
    out = extract_compressed_global_contexts(
        fr, fd, "LOAD_VAL_MOD", "core_memory_load", 5,
    )
    assert len(out) == 1
    assert all(isinstance(c, GlobalMemoryCtx) for c in out)


def test_extractor_skips_family_with_no_addrs():
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": []}]
    assert extract_compressed_global_contexts(
        fr, fd, "INSTR_TYPE_MOD", "step0", 0,
    ) == set()


def test_extractor_handles_malformed_addresses_gracefully():
    """Non-integer broken_addrs entries should be silently skipped."""
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": [
        0x80001000,
        "not-an-int",
        None,
        {"weird": "object"},
    ]}]
    out = extract_compressed_global_contexts(
        fr, fd, "INSTR_TYPE_MOD", "step0", 0,
    )
    assert len(out) == 1                   # only the valid one


def test_extractor_accepts_rich_broken_addr_dicts_from_host():
    """Production Hook 3 emits dict broken_addrs (POS 7b shape)."""
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": [
        {"addr": 1073725482, "byte_addr": 0x20036C, "type": "register"},
    ]}]
    out = extract_compressed_global_contexts(
        fr, fd, "STORE_OUT_MOD", "step0", 6,
    )
    assert len(out) == 1


# ============================================================================
# Safety cap
# ============================================================================


def test_safety_cap_truncates_huge_input():
    """If somehow >64 distinct contexts emerge, output is capped."""
    fr = [{"family": "u16", "nonzero": True}]
    # Generate 200 unique indices in different log2 buckets:
    indices = [1 << b for b in range(15)] * 20   # ~200 entries, but only 15 buckets
    fd = [{"family": "u16", "broken_indices": indices}]
    out = extract_compressed_global_contexts(
        fr, fd, "COMP_OUT_MOD", "core_arithmetic", 0,
    )
    # Compression should already keep it well under 64 (one ctx per bucket).
    assert len(out) <= _GLOBAL_COMPRESSED_SAFETY_CAP
    assert len(out) == 15                  # exactly one per unique bucket


def test_extractor_always_within_safety_cap():
    """Force-test: even degenerate input must respect the cap."""
    fr = [{"family": "memory", "nonzero": True}]
    # 200 addresses, all distinct regions AND buckets is impossible (only
    # 7 regions + 32 buckets), so compression will naturally limit; we
    # just verify the assertion.
    addrs = [(b << 20) for b in range(200)]
    fd = [{"family": "memory", "broken_addrs": addrs}]
    out = extract_compressed_global_contexts(
        fr, fd, "LOAD_VAL_MOD", "core_memory_load", 5,
    )
    assert len(out) <= _GLOBAL_COMPRESSED_SAFETY_CAP


# ============================================================================
# JSON serialization & storage rows
# ============================================================================


def test_memory_ctx_json_is_stable_across_instances():
    a = GlobalMemoryCtx(
        family="memory", address_region="user", address_bucket=31,
        txn_role="ifetch", cycle_phase="boundary",
    )
    b = GlobalMemoryCtx(
        family="memory", address_region="user", address_bucket=31,
        txn_role="ifetch", cycle_phase="boundary",
    )
    assert a.to_json_str() == b.to_json_str()
    # Round-trippable:
    d = json.loads(a.to_json_str())
    assert d["family"] == "memory"
    assert d["address_region"] == "user"
    assert d["address_bucket"] == 31


def test_lookup_ctx_json_is_stable():
    c = GlobalLookupCtx(
        family="u8", lookup_index_bucket=7,
        producer_kind="COMP_OUT_MOD", opcode_class="alu",
    )
    d = json.loads(c.to_json_str())
    assert d["family"] == "u8"
    assert d["lookup_index_bucket"] == 7
    assert d["producer_kind"] == "COMP_OUT_MOD"
    assert d["opcode_class"] == "alu"


def test_to_storage_rows_is_deterministic():
    """Same input set → same output list (sorted by ctx_key)."""
    ctxs = {
        GlobalMemoryCtx(
            family="memory", address_region="user", address_bucket=31,
            txn_role="read", cycle_phase="normal",
        ),
        GlobalLookupCtx(
            family="u8", lookup_index_bucket=3,
            producer_kind="COMP_OUT_MOD", opcode_class="alu",
        ),
    }
    rows1 = to_storage_rows(ctxs)
    rows2 = to_storage_rows(ctxs)
    assert rows1 == rows2
    assert len(rows1) == 2
    for ctx_key, family, ctx_json in rows1:
        assert isinstance(ctx_key, str)
        assert family in ("memory",) + LOOKUP_FAMILIES
        # ctx_key should equal ctx_json (both are the canonical json):
        assert ctx_key == ctx_json
        json.loads(ctx_json)                # round-trippable


def test_extracted_contexts_round_trip_through_storage_rows():
    fr = [
        {"family": "memory", "nonzero": True},
        {"family": "u8", "nonzero": True},
    ]
    fd = [
        {"family": "memory", "broken_addrs": [0x80001000]},
        {"family": "u8", "broken_indices": [42]},
    ]
    contexts = extract_compressed_global_contexts(
        fr, fd, "MEM_VAL_MOD", "post_ecall", 5,
    )
    rows = to_storage_rows(contexts)
    assert len(rows) == 2
    families_seen = {r[1] for r in rows}
    assert families_seen == {"memory", "u8"}


# ============================================================================
# Pro §5 conformance
# ============================================================================


def test_all_emitted_memory_ctxs_have_valid_fields():
    """Every (address_region, txn_role, cycle_phase) emitted must be in
    Pro's allowed enums."""
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{"family": "memory", "broken_addrs": [
        0x00000100, 0x00500000, 0x10000000, 0x70000000, 0x80000000, 0xC0000000,
    ]}]
    for kind in ["INSTR_TYPE_MOD", "MEM_VAL_MOD", "STORE_OUT_MOD",
                 "PRE_EXEC_REG_MOD", "INSTR_WORD_MOD", "COMP_OUT_MOD"]:
        for zone in SEMANTIC_ZONES:
            for major in range(13):
                ctxs = extract_compressed_global_contexts(fr, fd, kind, zone, major)
                for ctx in ctxs:
                    if isinstance(ctx, GlobalMemoryCtx):
                        assert ctx.address_region in ADDRESS_REGIONS
                        assert ctx.txn_role in MEMORY_TXN_ROLES
                        assert ctx.cycle_phase in MEMORY_CYCLE_PHASES


def test_all_emitted_lookup_ctxs_have_valid_fields():
    fr = [{"family": "u16", "nonzero": True}]
    fd = [{"family": "u16", "broken_indices": [0, 1, 100, 30000]}]
    for kind in ["INSTR_TYPE_MOD", "COMP_OUT_MOD"]:
        for major in range(13):
            ctxs = extract_compressed_global_contexts(
                fr, fd, kind, "core_arithmetic", major,
            )
            for ctx in ctxs:
                if isinstance(ctx, GlobalLookupCtx):
                    assert ctx.family in LOOKUP_FAMILIES
                    assert ctx.opcode_class in OPCODE_CLASSES
                    assert isinstance(ctx.lookup_index_bucket, int)
                    assert ctx.producer_kind == kind


# ============================================================================
# Batch 1.6 — _coerce_broken_addr field priority (byte_addr before addr)
# ============================================================================

from a4.standalone.compressed_global_extractor import _coerce_broken_addr
import inspect


def test_coerce_broken_addr_prefers_byte_addr_over_addr():
    """Test A: register dict → user_regs via byte_addr, not user via addr."""
    raw = {"addr": 0x3FFFC022, "byte_addr": 0xFFFF0088, "type": "register"}
    coerced = _coerce_broken_addr(raw)
    assert coerced == 0xFFFF0088
    assert address_region(coerced) == "user_regs"
    assert address_region(raw["addr"]) == "user"


def test_coerce_broken_addr_falls_back_to_addr_without_byte_addr():
    """Test B: legacy dict without byte_addr uses addr."""
    raw = {"addr": 0x00020000, "type": "data"}
    assert _coerce_broken_addr(raw) == 0x00020000
    assert address_region(_coerce_broken_addr(raw)) == "user"


def test_coerce_broken_addr_int_legacy_unchanged():
    """Test C: bare int passthrough."""
    assert _coerce_broken_addr(0x00020000) == 0x00020000


def test_field_priority_tuple_documentation():
    """Test E: prevent regression on coercion field order."""
    src = inspect.getsource(_coerce_broken_addr)
    assert '("byte_addr", "addr", "address")' in src


def test_extract_memory_includes_non_user_regions_post_patch():
    """Test D: replay-style integration — exotic address_region labels appear."""
    fr = [{"family": "memory", "nonzero": True}]
    fd = [{
        "family": "memory",
        "broken_addrs": [
            {"addr": 0x3FFFC022, "byte_addr": 0xFFFF0088, "type": "register"},
            {"addr": 0x3BD09A7F, "byte_addr": 0xEF4269FC, "type": "data"},
        ],
    }]
    ctxs = extract_compressed_global_contexts(
        fr, fd, "PRE_EXEC_REG_MOD", "core_arithmetic", 0,
    )
    mem_regions = {
        c.address_region for c in ctxs if isinstance(c, GlobalMemoryCtx)
    }
    assert mem_regions & {"user_regs", "kernel"}
