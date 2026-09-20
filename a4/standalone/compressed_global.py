"""
Compressed global context schemas (ProG_Report_2.md §5, cloud1 D8).

Pro recommends replacing raw global address coverage with **semantic** global
contexts to prevent the bandit from optimizing "different memory byte touched"
over "different constraint mechanism explored".

Two compressed context families are defined, verbatim from §5:

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

The dataclasses are frozen so they are hashable; sets of them are used by
`coverage_state` to compute `g_new` (the new-compressed-global reward term)
and persisted in the new `compressed_global_coverage` SQLite table.

The extractor that maps a raw Hook 3 global failure → a CompressedCtx lives
in `a4/standalone/compressed_global_extractor.py` (Phase 3 of cloud1).
"""

from dataclasses import dataclass
from typing import Union


# Allowed value sets (used by the extractor for validation to see what we actually emit).

ADDRESS_REGIONS = (
    "zero_page",
    "user",
    "user_bigint",
    "kernel",
    "machine_regs",
    "user_regs",
    "machine_special",
    "ecall_dispatch",
    "trap_dispatch_and_beyond",
    "invalid",
    "unknown",
)

MEMORY_TXN_ROLES = (
    "read", "write", "ifetch", "register", "prev_word", "prev_cycle",
)

MEMORY_CYCLE_PHASES = (
    "normal", "ecall", "mret", "halt", "boundary",
)

LOOKUP_FAMILIES = ("u8", "u16", "cycle")

OPCODE_CLASSES = (
    "alu", "mul", "div", "mem", "branch_or_ctrl", "sha", "poseidon", "other",
)


@dataclass(frozen=True)
class GlobalMemoryCtx:
    """Compressed global context for memory-family residues."""

    family: str = "memory"          # always "memory" for this dataclass
    address_region: str = "unknown"
    address_bucket: int = 0          # floor(log2(addr)) typically, see extractor
    txn_role: str = "read"
    cycle_phase: str = "normal"

    def to_json_str(self) -> str:
        """Serialize for the compressed_global_coverage.ctx_json column."""
        import json
        return json.dumps({
            "family": self.family,
            "address_region": self.address_region,
            "address_bucket": self.address_bucket,
            "txn_role": self.txn_role,
            "cycle_phase": self.cycle_phase,
        }, sort_keys=True)


@dataclass(frozen=True)
class GlobalLookupCtx:
    """Compressed global context for lookup-family residues (u8, u16, cycle)."""

    family: str = "u8"               # one of LOOKUP_FAMILIES
    lookup_index_bucket: int = 0     # floor(log2(idx)) or similar bucket
    producer_kind: str = "UNKNOWN"   # the mutation_kind that produced this
    opcode_class: str = "other"      # cycle's opcode class

    def to_json_str(self) -> str:
        """Serialize for the compressed_global_coverage.ctx_json column."""
        import json
        return json.dumps({
            "family": self.family,
            "lookup_index_bucket": self.lookup_index_bucket,
            "producer_kind": self.producer_kind,
            "opcode_class": self.opcode_class,
        }, sort_keys=True)


# Type alias for "either kind of compressed context".
CompressedGlobalCtx = Union[GlobalMemoryCtx, GlobalLookupCtx]


def is_memory_family(family: str) -> bool:
    """True if `family` should produce a GlobalMemoryCtx."""
    return family == "memory"


def is_lookup_family(family: str) -> bool:
    """True if `family` should produce a GlobalLookupCtx."""
    return family in LOOKUP_FAMILIES


__all__ = [
    "ADDRESS_REGIONS",
    "MEMORY_TXN_ROLES",
    "MEMORY_CYCLE_PHASES",
    "LOOKUP_FAMILIES",
    "OPCODE_CLASSES",
    "GlobalMemoryCtx",
    "GlobalLookupCtx",
    "CompressedGlobalCtx",
    "is_memory_family",
    "is_lookup_family",
]
