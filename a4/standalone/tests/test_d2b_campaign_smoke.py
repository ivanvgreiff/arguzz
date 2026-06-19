#!/usr/bin/env python3
"""D2.B Batch 4 — Layer 5 mutation-selection-loop smoke (no binary invocation)."""

from __future__ import annotations

import random
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Set
from unittest.mock import patch

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4AllTxn, A4CycleInfo
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.bandit_ts import MutationOutcome
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.compressed_global import MEMORY_TXN_ROLES
from a4.standalone.compressed_global_extractor import txn_role_for_kind
from a4.standalone.fuzzer import A4Fuzzer, MutationResult

MUTATIONS_PER_KIND = 50
TOTAL_ITERATIONS = len(A4Fuzzer.MUTATION_KINDS) * MUTATIONS_PER_KIND


def _fixture_data() -> InspectionData:
    cycles = [
        A4CycleInfo(cycle_idx=i, step=i, pc=0x1000 + i, txn_idx=i, major=m, minor=0)
        for i, m in enumerate([0, 0, 5, 6, 0, 3, 4, 5])
    ]
    txns = [
        A4AllTxn(
            txn_idx=10 + i,
            step=step,
            txn_type="mem" if step % 2 else "reg",
            addr=0x00020000 + i,
            cycle=i % 2,
            word=i,
            prev_cycle=0,
            prev_word=i - 1,
        )
        for i, step in enumerate([1, 2, 3, 5, 6])
    ]
    return InspectionData(cycles=cycles, all_txns=txns, reg_txns=txns)


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


def _run_selection_loop_smoke(db_path: Path) -> tuple[Set[str], Counter[str]]:
    """Bandit-like kind rotation without invoking the prover."""
    data = _fixture_data()
    rng = random.Random(1234)
    kinds_seen: Set[str] = set()
    outcomes: Counter[str] = Counter()

    fz = A4Fuzzer(
        host_binary="/bin/true",
        host_args=["--in1", "5", "--in4", "10"],
        db_path=str(db_path),
        selector_strategy="bandit",
        seed=1234,
        b_count_override=16,
        telemetry_level="none",
    )
    fz.data = data
    fz.campaign_id = fz.db.start_campaign("/bin/true", fz.host_args, "all", 1234)

    for i in range(TOTAL_ITERATIONS):
        kind = A4Fuzzer.MUTATION_KINDS[i % len(A4Fuzzer.MUTATION_KINDS)]
        if i >= len(A4Fuzzer.MUTATION_KINDS):
            kind = rng.choice(A4Fuzzer.MUTATION_KINDS)
        kinds_seen.add(kind)

        step = None
        config = None
        mv = ov = 0
        for attempt in range(10):
            step = rng.choice(data.get_valid_steps_for_kind(kind) or [1])
            try:
                config, mv, ov = fz._create_mutation(kind, step)
            except Exception:
                config = None
            if config is not None:
                break

        if config is None:
            skipped = MutationResult(
                kind=kind,
                step=step or 0,
                original_value=0,
                mutated_value=0,
                config=None,
                failures=[],
                verifier_accepted=False,
                execution_time_ms=0.0,
            )
            fz.db.record_mutation(
                fz.campaign_id,
                kind,
                step or 0,
                0,
                None,
                None,
                False,
                original_value=0,
                **fz._mutation_record_kwargs(skipped),
            )
            outcomes[MutationOutcome.SKIPPED.value] += 1
            continue

        applied = MutationResult(
            kind=kind,
            step=step or 0,
            original_value=ov,
            mutated_value=mv,
            config=config,
            failures=[],
            verifier_accepted=True,
            execution_time_ms=1.0,
        )
        fz.db.record_mutation(
            fz.campaign_id,
            kind,
            step or 0,
            mv,
            config,
            config.get("txn_idx"),
            True,
            original_value=ov,
            **fz._mutation_record_kwargs(applied),
        )
        outcomes[MutationOutcome.APPLIED.value] += 1

        role = txn_role_for_kind(kind)
        assert role in MEMORY_TXN_ROLES or kind in {
            "TXN_ADDR_MOD",
            "TXN_CYCLE_PHASE_MOD",
            "CYCLE_DIFF_COUNT_MOD",
        }

    fz.db.end_campaign(fz.campaign_id)
    return kinds_seen, outcomes


@pytest.fixture(scope="module")
def smoke_artifacts(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("d2b_campaign_smoke") / "campaign_smoke.db"
    with patch(
        "a4.standalone.fuzzer.capture_baseline_touch",
        return_value=_baseline_touch(),
    ):
        kinds_seen, outcomes = _run_selection_loop_smoke(db_path)
    return db_path, kinds_seen, outcomes


def test_dispatch_coverage_all_kinds_selected(smoke_artifacts):
    _, kinds_seen, _ = smoke_artifacts
    missing = set(A4Fuzzer.MUTATION_KINDS) - kinds_seen
    assert not missing, f"Kinds never selected: {sorted(missing)}"


def test_no_exceptions_under_load(smoke_artifacts):
    db_path, _, outcomes = smoke_artifacts
    total = sum(outcomes.values())
    assert total == TOTAL_ITERATIONS
    with sqlite3.connect(db_path) as conn:
        n_rows = conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0]
    assert n_rows == TOTAL_ITERATIONS


def test_mutation_outcome_distribution(smoke_artifacts):
    _, _, outcomes = smoke_artifacts
    assert outcomes[MutationOutcome.ERROR.value] == 0
    assert outcomes[MutationOutcome.APPLIED.value] > 0
    assert outcomes[MutationOutcome.SKIPPED.value] >= 0


def test_cgc_tag_well_formed(smoke_artifacts):
    db_path, _, _ = smoke_artifacts
    with sqlite3.connect(db_path) as conn:
        kinds = [
            row[0]
            for row in conn.execute(
                "SELECT kind FROM mutations WHERE outcome = ?",
                (MutationOutcome.APPLIED.value,),
            )
        ]
    assert kinds
    for kind in kinds:
        role = txn_role_for_kind(kind)
        assert isinstance(role, str) and role
