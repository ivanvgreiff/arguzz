"""Shared run record building + env constants."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from thesis_side_experiments.bias_campaign.categorize import (
    categorize_failure,
    categorize_failures,
    categorize_touched,
    global_failed,
)
from thesis_side_experiments.bias_campaign.classify import RunOutcome
from thesis_side_experiments.bias_campaign.touch_parse import (
    parse_accum_verbose_set,
    parse_local_verbose_set,
)

DEFAULT_ENV = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
}

ALIGNED_KINDS: List[Tuple[str, str]] = [
    ("PRE_EXEC_REG_MOD", "PRE_EXEC_REG_MOD"),
    ("COMP_OUT_MOD", "COMP_OUT_MOD"),
    ("LOAD_VAL_MOD", "LOAD_VAL_MOD"),
    ("STORE_OUT_MOD", "STORE_OUT_MOD"),
    ("MEM_VAL_MOD", "PRE_EXEC_MEM_MOD"),
    ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD"),
]

PILOT_N = 50
PILOT_SEEDS = list(range(PILOT_N))


@dataclass
class RunRecord:
    fuzzer: str
    guest: str
    kind: str
    seed: int
    inject_step: Optional[int]
    target_desc: str
    outcome: RunOutcome
    fail_categories: Dict[str, int]
    target_categories: Dict[str, int]
    global_families: Dict[str, Any]
    runtime_ms: int
    raw_log_path: str
    skipped: bool = False
    skip_reason: str = ""


def target_categories_from_output(output: str) -> Dict[str, int]:
    local = parse_local_verbose_set(output)
    accum = parse_accum_verbose_set(output)
    if local is None:
        local = set()
    if accum is None:
        accum = set()
    return categorize_touched(local, accum)


def failure_rows(outcome: RunOutcome) -> List[dict]:
    seen: Set[Tuple[str, int, int, str]] = set()
    rows = []
    for f in outcome.failures:
        key = (f.loc, f.major, f.minor, f.phase)
        if key in seen:
            continue
        seen.add(key)
        cat = categorize_failure(f.loc, f.phase)
        rows.append(
            {
                "constraint_type": cat,
                "constraint_loc": f.loc,
                "cycle": f.cycle,
                "step": f.step,
                "pc": f.pc,
                "major": f.major,
                "minor": f.minor,
                "value": f.value,
                "full_loc": f.loc,
                "phase": f.phase,
                "category": cat,
            }
        )
    return rows


def global_failure_rows(outcome: RunOutcome) -> List[dict]:
    rows = []
    if outcome.family_residues:
        for fam in outcome.family_residues:
            if fam.get("nonzero"):
                rows.append({"family": fam["family"], "address": None})
    return rows


def build_run_record(
    fuzzer: str,
    guest: str,
    kind: str,
    seed: int,
    inject_step: Optional[int],
    target_desc: str,
    outcome: RunOutcome,
    runtime_ms: int,
    raw_log_path: str,
) -> RunRecord:
    return RunRecord(
        fuzzer=fuzzer,
        guest=guest,
        kind=kind,
        seed=seed,
        inject_step=inject_step,
        target_desc=target_desc,
        outcome=outcome,
        fail_categories=categorize_failures(outcome.failures),
        target_categories=target_categories_from_output(outcome.combined_output),
        global_families=global_failed(outcome.family_residues, outcome.global_residue),
        runtime_ms=runtime_ms,
        raw_log_path=raw_log_path,
    )
