"""
Phase 1 (cloud1) — tests for the three new dataclass modules:
- a4.standalone.semantic_zones
- a4.standalone.compressed_global
- a4.standalone.structural_cells

These modules are pure dataclasses + constants — no I/O — so the tests
are fast and focused on invariants documented in ProG_Report_2.md.
"""

from a4.standalone import semantic_zones as sz
from a4.standalone import compressed_global as cg
from a4.standalone import structural_cells as sc


# =============================================================================
# semantic_zones
# =============================================================================


def test_17_zones_present():
    """Pro §7.A lists exactly 17 semantic zones; we should match."""
    assert len(sz.SEMANTIC_ZONES) == 17


def test_zones_match_pro_spec():
    """All 17 zone names match ProG_Report_2.md §7.A verbatim."""
    expected = {
        "step0", "last_step",
        "pre_ecall", "post_ecall",
        "pre_mret", "post_mret",
        "pre_halt", "post_halt",
        "core_arithmetic", "core_memory_load", "core_memory_store",
        "core_branch", "core_mul", "core_div",
        "core_sha", "core_poseidon", "core_other",
    }
    assert set(sz.SEMANTIC_ZONES) == expected


def test_singleton_and_boundary_zones():
    """SINGLETON_ZONES ⊂ BOUNDARY_ZONES ⊂ SEMANTIC_ZONES; CORE ∪ BOUNDARY = all."""
    assert sz.SINGLETON_ZONES.issubset(sz.BOUNDARY_ZONES)
    assert sz.BOUNDARY_ZONES.issubset(set(sz.SEMANTIC_ZONES))
    assert sz.BOUNDARY_ZONES | sz.CORE_ZONES == set(sz.SEMANTIC_ZONES)
    assert sz.BOUNDARY_ZONES & sz.CORE_ZONES == set()
    assert sz.SINGLETON_ZONES == {"step0", "last_step"}


def test_major_to_zone_known_majors():
    """Major values per `a4/core/inspection_data.py::summary()` line 224-228.

    Note: major=8 is ECALL0 (boundary), not SHA. SHA is major 11. Boundary
    classification (pre_ecall) is applied by the zone classifier BEFORE this
    fallback map runs, so this map maps major=8 → core_other defensively.
    """
    assert sz.major_to_zone(0) == "core_arithmetic"
    assert sz.major_to_zone(1) == "core_arithmetic"
    assert sz.major_to_zone(2) == "core_arithmetic"
    assert sz.major_to_zone(3) == "core_mul"
    assert sz.major_to_zone(4) == "core_div"
    assert sz.major_to_zone(5) == "core_memory_load"
    assert sz.major_to_zone(6) == "core_memory_store"
    assert sz.major_to_zone(7) == "core_branch"
    # ECALL0 falls through to core_other in the major-fallback map;
    # the zone classifier should have already placed it in pre_ecall.
    assert sz.major_to_zone(8) == "core_other"
    assert sz.major_to_zone(9) == "core_poseidon"
    assert sz.major_to_zone(10) == "core_poseidon"
    assert sz.major_to_zone(11) == "core_sha"
    assert sz.major_to_zone(12) == "core_other"  # BIGINT — no zone in Pro's list


def test_major_to_zone_unknown_falls_back_to_core_other():
    assert sz.major_to_zone(99) == "core_other"
    assert sz.major_to_zone(-1) == "core_other"


def test_major_to_opcode_class_known_majors():
    """opcode_class strings match ProG_Report_2.md §5 enum exactly."""
    assert sz.major_to_opcode_class(0) == "alu"
    assert sz.major_to_opcode_class(1) == "alu"
    assert sz.major_to_opcode_class(2) == "alu"
    assert sz.major_to_opcode_class(3) == "mul"
    assert sz.major_to_opcode_class(4) == "div"
    assert sz.major_to_opcode_class(5) == "mem"
    assert sz.major_to_opcode_class(6) == "mem"
    assert sz.major_to_opcode_class(7) == "branch_or_ctrl"
    assert sz.major_to_opcode_class(8) == "branch_or_ctrl"   # ECALL is a ctrl transition
    assert sz.major_to_opcode_class(9) == "poseidon"
    assert sz.major_to_opcode_class(10) == "poseidon"
    assert sz.major_to_opcode_class(11) == "sha"
    assert sz.major_to_opcode_class(12) == "other"
    assert sz.major_to_opcode_class(99) == "other"


def test_is_valid_zone():
    for z in sz.SEMANTIC_ZONES:
        assert sz.is_valid_zone(z)
    assert not sz.is_valid_zone("BOGUS_ZONE")


# =============================================================================
# compressed_global
# =============================================================================


def test_global_memory_ctx_hashable_and_jsonable():
    a = cg.GlobalMemoryCtx(address_region="user", address_bucket=31)
    b = cg.GlobalMemoryCtx(address_region="user", address_bucket=31)
    c = cg.GlobalMemoryCtx(address_region="kernel", address_bucket=31)
    assert hash(a) == hash(b)
    assert a == b
    assert a != c
    js = a.to_json_str()
    assert "user" in js
    assert "31" in js


def test_global_lookup_ctx_hashable_and_jsonable():
    a = cg.GlobalLookupCtx(family="u8", lookup_index_bucket=4, producer_kind="MEM_VAL_MOD")
    b = cg.GlobalLookupCtx(family="u8", lookup_index_bucket=4, producer_kind="MEM_VAL_MOD")
    assert a == b
    assert hash(a) == hash(b)
    js = a.to_json_str()
    assert "u8" in js
    assert "MEM_VAL_MOD" in js


def test_compressed_ctx_set_dedup():
    """Sets of compressed contexts should dedup by structural equality."""
    s = set()
    s.add(cg.GlobalMemoryCtx(address_region="user", address_bucket=31))
    s.add(cg.GlobalMemoryCtx(address_region="user", address_bucket=31))  # dup
    s.add(cg.GlobalMemoryCtx(address_region="kernel", address_bucket=31))
    s.add(cg.GlobalLookupCtx(family="u8", lookup_index_bucket=4))
    assert len(s) == 3


def test_family_predicates():
    assert cg.is_memory_family("memory")
    assert not cg.is_memory_family("u8")
    assert cg.is_lookup_family("u8")
    assert cg.is_lookup_family("u16")
    assert cg.is_lookup_family("cycle")
    assert not cg.is_lookup_family("memory")


# =============================================================================
# structural_cells
# =============================================================================


def test_structural_cell_hashable_and_equal():
    a = sc.StructuralCell(kind="INSTR_TYPE_MOD", semantic_zone="step0", opcode_class="mem")
    b = sc.StructuralCell(kind="INSTR_TYPE_MOD", semantic_zone="step0", opcode_class="mem")
    c = sc.StructuralCell(kind="INSTR_TYPE_MOD", semantic_zone="step0", opcode_class="mul")
    assert a == b
    assert hash(a) == hash(b)
    assert a != c


def test_structural_cell_dedup_in_set():
    s = {
        sc.StructuralCell(kind="A", semantic_zone="step0", opcode_class="mem"),
        sc.StructuralCell(kind="A", semantic_zone="step0", opcode_class="mem"),
        sc.StructuralCell(kind="A", semantic_zone="step0", opcode_class="mul",
                          sub_strategy="alt"),
    }
    assert len(s) == 2  # the third differs by opcode_class + sub_strategy


def test_structural_cell_to_tuple_stable_shape():
    cell = sc.StructuralCell(
        kind="K", semantic_zone="step0", opcode_class="mem",
        mode="user", txn_role="read", sub_strategy="x",
    )
    t = cell.to_tuple()
    assert t == ("K", "step0", "mem", "user", "read", "x")


def test_make_structural_cell_builder():
    cell = sc.make_structural_cell(
        kind="INSTR_TYPE_MOD",
        semantic_zone="step0",
        opcode_class="mem",
        mode="user",
        txn_role="ifetch",
        sub_strategy=None,
    )
    assert cell.kind == "INSTR_TYPE_MOD"
    assert cell.semantic_zone == "step0"
    assert cell.sub_strategy is None
