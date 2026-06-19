#!/usr/bin/env python3
"""D2.B Batch 4 — Layer 1 cross-cutting arm registration meta-test."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import List

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.standalone.compressed_global import MEMORY_TXN_ROLES
from a4.standalone.compressed_global_extractor import _TXN_ROLE_BY_KIND, txn_role_for_kind
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.semantic_arm_universe import (
    _MUTATION_MODULES,
    _cycle_matches_kind_filter,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MOD_RS = (
    _REPO_ROOT
    / "workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs"
)

DEAD_KINDS = frozenset({
    "CYCLE_MODE_MOD",
    "TXN_ADDR_MOD",
    "TXN_CYCLE_PHASE_MOD",
    "CYCLE_PC_MOD",
    "CYCLE_STATE_MOD",
})

TXN_TARGETING_KINDS = frozenset({
    "TXN_PREV_WORD_MOD",
    "TXN_PREV_CYCLE_MOD",
    "TXN_ADDR_MOD",
    "TXN_CYCLE_PHASE_MOD",
})

# Rust match arms use the base kind name for word-mod variants.
_RUST_KIND_LITERAL = {
    "INSTR_WORD_MOD_FULL": "INSTR_WORD_MOD",
    "INSTR_WORD_MOD_SUR": "INSTR_WORD_MOD",
}


def _registration_fixture_data() -> InspectionData:
    """Synthetic trace covering all D2.B + V5 step filters."""
    cycles: List[A4CycleInfo] = []
    for step in range(4):
        majors = [0, 5, 6, 8]
        cycles.append(
            A4CycleInfo(
                cycle_idx=step,
                step=step,
                pc=0x1000 + step * 4,
                txn_idx=step,
                major=majors[step % len(majors)],
                minor=0,
                state=48,
                diff_count_0=1,
                diff_count_1=2,
            )
        )
    txns = [
        A4AllTxn(
            txn_idx=10,
            step=1,
            txn_type="reg",
            addr=0xFFFF0084,
            cycle=1,
            word=42,
            prev_cycle=0,
            prev_word=41,
        ),
        A4AllTxn(
            txn_idx=20,
            step=2,
            txn_type="mem",
            addr=0x00020000,
            cycle=0,
            word=7,
            prev_cycle=0,
            prev_word=6,
        ),
        A4AllTxn(
            txn_idx=30,
            step=3,
            txn_type="mem",
            addr=0x00020004,
            cycle=1,
            word=9,
            prev_cycle=1,
            prev_word=8,
        ),
    ]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


@pytest.fixture(scope="module")
def registration_data() -> InspectionData:
    return _registration_fixture_data()


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_python_module_exists(kind: str):
    assert kind in _MUTATION_MODULES, f"{kind} missing from semantic_arm_universe._MUTATION_MODULES"
    mod = _MUTATION_MODULES[kind]
    assert inspect.ismodule(mod), f"{kind} registry entry is not a module"
    has_targets = any(
        hasattr(mod, name)
        for name in ("get_targets_at_step", "get_all_targets", "get_comp_out_targets")
    )
    assert has_targets or hasattr(mod, "create_config"), (
        f"{kind} module lacks target getter or create_config"
    )


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_mutation_modules_registry(kind: str):
    assert kind in _MUTATION_MODULES
    assert kind in A4Fuzzer.MUTATION_KINDS


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_get_valid_steps_for_kind(kind: str, registration_data: InspectionData):
    steps = registration_data.get_valid_steps_for_kind(kind)
    assert isinstance(steps, list)
    if kind == "INSTR_WORD_MOD":
        pytest.skip("INSTR_WORD_MOD alias not in MUTATION_KINDS registry")
    if kind in ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR"):
        assert len(steps) >= 1, f"{kind} returned no valid steps on fixture trace"


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_rust_handler_match_arm_exists(kind: str):
    assert _MOD_RS.is_file(), f"witgen mod.rs not found at {_MOD_RS}"
    text = _MOD_RS.read_text(encoding="utf-8")
    literal = _RUST_KIND_LITERAL.get(kind, kind)
    assert f'"{literal}"' in text, (
        f"No Rust match arm literal for {kind} (lookup {literal}) in mod.rs"
    )


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_semantic_arm_universe_kind_filter(kind: str, registration_data: InspectionData):
    cycle = registration_data.cycles[1]
    result = _cycle_matches_kind_filter(kind, cycle, registration_data)
    assert isinstance(result, bool)


@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_cgc_txn_role_mapping(kind: str):
    role = txn_role_for_kind(kind)
    # Post-D2.B-PS-2: NFP-4 drift fixed. CYCLE_DIFF_COUNT_MOD (the only live
    # D2.B kind that previously returned a non-Pro-valid label "diff_count")
    # is now remapped to "read" per NFP-4's Pro-valid roles decision.
    if kind in TXN_TARGETING_KINDS:
        assert kind in _TXN_ROLE_BY_KIND
        assert role in MEMORY_TXN_ROLES, f"{kind} txn_role {role!r} not Pro-valid"
    else:
        assert role in MEMORY_TXN_ROLES, f"{kind} txn_role {role!r} not Pro-valid"


def test_dead_kinds_excluded_from_registry():
    """Post-§9c postscript: all 5 W-17/W-18 dead kinds are excluded from
    A4Fuzzer.MUTATION_KINDS. Re-introducing any of them would be a regression
    against the audited dead-arm mechanism — see
    a4/docs/cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md §5–§8 and the audits at
    a4/docs/cloud2/composer/D2B_BATCH2_DEAD_ARM_AUDIT.md (W-17) and
    a4/docs/cloud2/composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md (W-18).
    """
    assert DEAD_KINDS.isdisjoint(A4Fuzzer.MUTATION_KINDS), (
        f"Dead kinds re-introduced into MUTATION_KINDS: "
        f"{sorted(DEAD_KINDS & set(A4Fuzzer.MUTATION_KINDS))}. "
        "These are W-17/W-18 dead arms; their per-kind attestation tests "
        "remain on disk as regression sentinels but they must not be wired "
        "into bandit/campaign dispatch."
    )
