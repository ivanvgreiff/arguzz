"""
Compressed global context extractor — cloud1 Phase 3.

Converts raw Hook 3 output (`family_residues` + `family_details` from
`a4.core.touch_coverage`) into the SEMANTIC compressed global contexts
defined in `ProG_Report_2.md §5` and instantiated as the
`GlobalMemoryCtx` / `GlobalLookupCtx` dataclasses in
`a4/standalone/compressed_global.py`.

Why this exists
---------------
The old global-context derivation (`coverage_state.derive_global_contexts`)
produced raw `("GLOBAL", family, str(address))` tuples — one per broken
address. Pro §5 says this is too noisy: the bandit ends up optimizing
"different memory byte touched" rather than "different constraint mechanism
explored". Compression maps multiple raw addresses to the same semantic
context whenever they share `(region, log2-bucket, txn_role, cycle_phase)`.

Pro's schema (verbatim from §5):

    GLOBAL_MEMORY:
      family = memory
      address_region = user | kernel | image | stack | heap | invalid | unknown
      address_bucket = page or log2-range bucket
      txn_role = read | write | ifetch | register | prev_word | prev_cycle
      cycle_phase = normal | ecall | mret | halt | boundary

    GLOBAL_LOOKUP:
      family = u8 | u16 | cycle
      lookup_index_bucket
      producer_kind
      opcode_class

Source of fields
----------------
| Field                | Source                                                   |
|----------------------|----------------------------------------------------------|
| family               | Hook 3 family_residues                                   |
| address_region       | derived from broken_addr via D8 map                      |
| address_bucket       | floor(log2(max(broken_addr, 1)))                         |
| txn_role             | mutation kind → role mapping (D16, see _TXN_ROLE_BY_KIND) |
| cycle_phase          | mutation step's semantic zone → cycle_phase (D16)        |
| lookup_index_bucket  | floor(log2(max(broken_index, 1)))                        |
| producer_kind        | the mutation kind                                        |
| opcode_class         | semantic_zones.major_to_opcode_class(mutation_major)     |

D16 (logged in `CLOUD1_DECISIONS_FOR_PRO_R2.md`): we derive `txn_role` and
`cycle_phase` from the MUTATION's context, not from per-failure metadata
(which Hook 3 does not expose). This is an approximation; see the decision
doc for full reasoning and risk.

Caps and safety
---------------
- `_GLOBAL_COMPRESSED_SAFETY_CAP = 64`: hard cap on compressed contexts
  emitted per run. Because compression collapses many addresses to few
  tuples, the natural cardinality is ~10-20; 64 is a 3-4× safety margin.
  Hit it → defensive truncation by sorted ctx_key (deterministic).
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Set, Tuple, Union

from a4.standalone.compressed_global import (
    ADDRESS_REGIONS,
    MEMORY_TXN_ROLES,
    MEMORY_CYCLE_PHASES,
    LOOKUP_FAMILIES,
    OPCODE_CLASSES,
    GlobalMemoryCtx,
    GlobalLookupCtx,
    CompressedGlobalCtx,
    is_memory_family,
    is_lookup_family,
)
from a4.standalone.semantic_zones import (
    SINGLETON_ZONES, BOUNDARY_ZONES, SEMANTIC_ZONES, major_to_opcode_class,
)


# =============================================================================
# Safety cap
# =============================================================================

_GLOBAL_COMPRESSED_SAFETY_CAP = 64


# =============================================================================
# D8: address region mapping
# =============================================================================
#
# Verbatim from `CLOUD1_DECISIONS_FOR_PRO_R2.md` D8. Half-open intervals.

# platform.rs (rv32im execute) — G3 resolved Phase 7 via Opus platform.rs audit.
_ADDRESS_REGION_MAP: List[Tuple[int, int, str]] = [
    (0x00000000, 0x00010000, "zero_page"),
    (0x00010000, 0xBFFF0000, "user"),
    (0xBFFF0000, 0xC0000000, "user_bigint"),
    (0xC0000000, 0xFF000000, "kernel"),
    (0xFFFF0000, 0xFFFF0080, "machine_regs"),
    (0xFFFF0080, 0xFFFF0100, "user_regs"),
    (0xFFFF0100, 0xFFFF1000, "machine_special"),
    (0xFFFF1000, 0xFFFF2000, "ecall_dispatch"),
    (0xFFFF2000, 0x100000000, "trap_dispatch_and_beyond"),
]


def address_region(addr: int) -> str:
    """Return the address-region label for `addr` per D8.

    Falls back to `"invalid"` for addresses not in any defined region
    (e.g. the gap [0x00400000, 0x10000000) which is neither image nor heap).
    `addr` is treated as a 32-bit unsigned integer; values >= 2**32 are
    rejected as `"invalid"`.
    """
    if addr < 0 or addr >= (1 << 32):
        return "invalid"
    for lo, hi, label in _ADDRESS_REGION_MAP:
        if lo <= addr < hi:
            return label
    return "invalid"


def address_bucket(addr: int) -> int:
    """Return the log2-based bucket index for a memory address.

    bucket = floor(log2(max(addr, 1)))

    For 32-bit addresses this yields buckets 0..31. addr=0 → bucket 0.
    Two addresses that differ only in low-order bits within the same
    log2 window fall into the same bucket. This drives the compression.
    """
    if addr <= 0:
        return 0
    return int(math.floor(math.log2(addr)))


def lookup_index_bucket(index: int) -> int:
    """Return the log2-based bucket index for a lookup-table index.

    Same scheme as `address_bucket`. Indices into u8 lookup are tiny
    (0..255 → bucket 0..7); u16 indices reach bucket 15; cycle indices
    can reach ~bucket 12-13 for our trace lengths.
    """
    if index <= 0:
        return 0
    return int(math.floor(math.log2(index)))


# =============================================================================
# D16: mutation-context derivation of txn_role and cycle_phase
# =============================================================================
#
# Hook 3 raw output gives us {family, broken_addrs|broken_indices} only —
# NOT which transaction caused the residue. To populate Pro's txn_role and
# cycle_phase fields, we use the MUTATION'S context as a proxy. This is a
# deliberate approximation logged as D16; rationale and risk in
# CLOUD1_DECISIONS_FOR_PRO_R2.md.

_TXN_ROLE_BY_KIND: Dict[str, str] = {
    # Instruction-fetch-targeting kinds:
    "INSTR_WORD_MOD":      "ifetch",
    "INSTR_WORD_MOD_FULL": "ifetch",
    "INSTR_WORD_MOD_SUR":  "ifetch",
    "INSTR_TYPE_MOD":      "ifetch",   # changes how the fetched word is decoded
    # Memory-data kinds:
    "LOAD_VAL_MOD":        "read",     # mutates the loaded value
    "STORE_OUT_MOD":       "write",    # mutates the stored value
    "MEM_VAL_MOD":         "read",     # mutates a memory-read txn value
    # Register kinds:
    "PRE_EXEC_REG_MOD":    "register",
    "COMP_OUT_MOD":        "register",
    "TXN_PREV_WORD_MOD":   "prev_word",
    "TXN_PREV_CYCLE_MOD":  "prev_cycle",
    "CYCLE_MODE_MOD":        "read",
    "TXN_ADDR_MOD":          "addr",
    "TXN_CYCLE_PHASE_MOD":   "cycle_phase",
    "CYCLE_DIFF_COUNT_MOD":  "diff_count",
}


def txn_role_for_kind(mutation_kind: str) -> str:
    """Map a mutation kind to the txn_role we attribute to its compressed
    context. See D16. Unknown kinds default to "read"."""
    return _TXN_ROLE_BY_KIND.get(mutation_kind, "read")


def cycle_phase_for_zone(zone: str) -> str:
    """Map a semantic zone to a cycle_phase per Pro §5's allowed values.

    Mapping:
        step0, last_step                       → boundary
        pre_ecall, post_ecall                  → ecall
        pre_mret, post_mret                    → mret
        pre_halt, post_halt                    → halt
        any core_* zone (or unknown)           → normal
    """
    if zone in SINGLETON_ZONES:                      # step0, last_step
        return "boundary"
    if zone in {"pre_ecall", "post_ecall"}:
        return "ecall"
    if zone in {"pre_mret", "post_mret"}:
        return "mret"
    if zone in {"pre_halt", "post_halt"}:
        return "halt"
    return "normal"


# =============================================================================
# Extractor
# =============================================================================


def _coerce_broken_addr(raw_addr: object) -> Optional[int]:
    """Normalize Hook 3 broken_addrs entry (int or rich dict from host)."""
    if isinstance(raw_addr, bool):
        return None
    if isinstance(raw_addr, int):
        return raw_addr
    if isinstance(raw_addr, dict):
        for key in ("byte_addr", "addr", "address"):
            if key in raw_addr and raw_addr[key] is not None:
                try:
                    return int(raw_addr[key])
                except (TypeError, ValueError):
                    return None
    try:
        return int(raw_addr)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _coerce_broken_index(raw_idx: object) -> Optional[int]:
    if isinstance(raw_idx, bool):
        return None
    if isinstance(raw_idx, int):
        return raw_idx
    if isinstance(raw_idx, dict):
        for key in ("index", "idx", "lookup_index"):
            if key in raw_idx and raw_idx[key] is not None:
                try:
                    return int(raw_idx[key])
                except (TypeError, ValueError):
                    return None
    try:
        return int(raw_idx)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def extract_compressed_global_contexts(
    family_residues: Optional[List[dict]],
    family_details: Optional[List[dict]],
    mutation_kind: str,
    mutation_zone: str,
    mutation_major: int,
) -> Set[CompressedGlobalCtx]:
    """Build the set of compressed global contexts for one mutation run.

    Args:
        family_residues: Hook 3 `family_residues` list (or None / []).
        family_details:  Hook 3 `family_details` list (or None / []).
        mutation_kind:   The mutation kind that produced this run (e.g.
                         "INSTR_TYPE_MOD"). Used for txn_role + producer_kind.
        mutation_zone:   The semantic zone of the mutation's target step.
                         Used for cycle_phase.
        mutation_major:  The `major` of the mutation's target cycle (from
                         InspectionData.cycles[step].major). Used for
                         opcode_class.

    Returns:
        Set of `GlobalMemoryCtx` and/or `GlobalLookupCtx` (deduplicated).
        Returns the empty set if no families have nonzero residue.

    Notes:
        - Compression collapses raw addresses sharing the same
          (region, log2-bucket) (for memory) or the same log2-bucket
          (for lookups) into a single context entry.
        - The same `mutation_kind/zone/major` is reused across all
          addresses in this run (D16), so a single mutation can produce
          at most |regions| × |buckets| memory contexts and 1 lookup
          context per (family, index-bucket).
    """
    if not family_residues:
        return set()

    nonzero_families = {fr["family"] for fr in family_residues if fr.get("nonzero")}
    if not nonzero_families or not family_details:
        return set()

    # Mutation-context-derived fields (D16). Computed once per call.
    txn_role = txn_role_for_kind(mutation_kind)
    cycle_phase = cycle_phase_for_zone(mutation_zone)
    opcode_class = major_to_opcode_class(mutation_major)

    out: Set[CompressedGlobalCtx] = set()

    for fd in family_details:
        family = fd.get("family")
        if not family or family not in nonzero_families:
            continue

        if is_memory_family(family):
            for raw_addr in fd.get("broken_addrs", []) or []:
                addr_int = _coerce_broken_addr(raw_addr)
                if addr_int is None:
                    continue
                out.add(GlobalMemoryCtx(
                    family="memory",
                    address_region=address_region(addr_int),
                    address_bucket=address_bucket(addr_int),
                    txn_role=txn_role,
                    cycle_phase=cycle_phase,
                ))
        elif is_lookup_family(family):
            for raw_idx in fd.get("broken_indices", []) or []:
                idx_int = _coerce_broken_index(raw_idx)
                if idx_int is None:
                    continue
                out.add(GlobalLookupCtx(
                    family=family,
                    lookup_index_bucket=lookup_index_bucket(idx_int),
                    producer_kind=mutation_kind,
                    opcode_class=opcode_class,
                ))
        # Unknown family → silently ignored. Pro §5 lists only memory + u8/u16/cycle.

    if len(out) > _GLOBAL_COMPRESSED_SAFETY_CAP:
        # Defensive truncation by sorted ctx_key (deterministic). Should
        # not happen in practice because compression collapses adjacent
        # addresses to one tuple.
        truncated = sorted(out, key=lambda c: c.to_json_str())[:_GLOBAL_COMPRESSED_SAFETY_CAP]
        out = set(truncated)

    return out


# =============================================================================
# Storage adapter — turns extracted contexts into rows ready for the
# `compressed_global_coverage` table.
# =============================================================================


def to_storage_rows(
    contexts: Set[CompressedGlobalCtx],
) -> List[Tuple[str, str, str]]:
    """Convert a set of compressed contexts to `(ctx_key, family, ctx_json)`
    tuples ready for `CoverageDB.record_compressed_global_first_hit()`.

    `ctx_key` is the same string as `ctx_json` (sorted-keys JSON), which
    is stable across runs and short enough to be a primary key.
    """
    rows: List[Tuple[str, str, str]] = []
    for ctx in contexts:
        ctx_json = ctx.to_json_str()
        rows.append((ctx_json, ctx.family, ctx_json))
    rows.sort()                                # deterministic insertion order
    return rows


__all__ = [
    "address_region",
    "address_bucket",
    "lookup_index_bucket",
    "txn_role_for_kind",
    "cycle_phase_for_zone",
    "extract_compressed_global_contexts",
    "to_storage_rows",
    "_GLOBAL_COMPRESSED_SAFETY_CAP",
]
