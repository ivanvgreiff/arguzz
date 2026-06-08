"""
Structural cell schema (ProG_Report_2.md §6.3, §8.S_new).

Pro's "structural cell" reward term `S_new` counts new tuples of the form:

    (mutation_kind, semantic_zone, opcode_class, mode, txn_role, sub_strategy?)

The intuition (Pro §6.3): "This would have rewarded INSTR_TYPE_MOD@step=0
before any local context appeared repeatedly." Structural cells let the
bandit get a small positive reward for trying a NEW combination of
(kind, zone, opcode_class, ...) even when no constraint has been newly hit
yet. This breaks the cold-start problem where the bandit has nothing to
learn from in the first few thousand mutations.

`mode` distinguishes user-mode vs machine-mode execution (relevant for the
RISC Zero zkVM's user/kernel split, per Pro §7.A which references the
RISC-V user/machine mode distinction).

`txn_role` is the role of the mutated transaction within the cycle:
    read | write | ifetch | register | prev_word | prev_cycle (Pro §5)

`sub_strategy` is mutation-kind-specific: for `INSTR_WORD_MOD_SUR` we
record `funct3` here (since that's the field varied within a SUR mutation);
for `MEM_VAL_MOD` we record `byte_lane`; etc. It can be None for kinds
without a sub-strategy axis.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class StructuralCell:
    """One row of the (kind × zone × opcode × mode × txn_role × sub_strategy)
    structural-cell space."""

    kind: str                       # mutation_kind name (e.g. "INSTR_TYPE_MOD")
    semantic_zone: str              # one of SEMANTIC_ZONES (e.g. "step0")
    opcode_class: str               # one of OPCODE_CLASSES (e.g. "mem")
    mode: str = "user"              # "user" | "machine"
    txn_role: str = "ifetch"        # one of MEMORY_TXN_ROLES
    sub_strategy: Optional[str] = None  # kind-specific axis label

    def to_tuple(self) -> tuple:
        """Return the cell as a hashable tuple for set membership tests."""
        return (
            self.kind,
            self.semantic_zone,
            self.opcode_class,
            self.mode,
            self.txn_role,
            self.sub_strategy,
        )


def make_structural_cell(
    kind: str,
    semantic_zone: str,
    opcode_class: str,
    mode: str = "user",
    txn_role: str = "ifetch",
    sub_strategy: Optional[str] = None,
) -> StructuralCell:
    """Convenience constructor with named-arg validation.

    This is the canonical entry point for the fuzzer loop to build a
    StructuralCell for the just-completed mutation. The fuzzer is
    responsible for resolving `opcode_class`, `mode`, `txn_role`, and
    `sub_strategy` from the mutation `config` and `exec_result`.
    """
    return StructuralCell(
        kind=kind,
        semantic_zone=semantic_zone,
        opcode_class=opcode_class,
        mode=mode,
        txn_role=txn_role,
        sub_strategy=sub_strategy,
    )


__all__ = ["StructuralCell", "make_structural_cell"]
