#!/usr/bin/env python3
"""D2.A Batch 2 — mutations.outcome column populated via synthetic fuzzer harness."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.core.executor import MutationExecutionResult
from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.bandit_ts import MutationOutcome
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer, MutationResult


def _cycles(n: int = 5):
    majors = [0, 0, 5, 5, 0]
    return [
        A4CycleInfo(
            cycle_idx=i,
            step=i,
            pc=0,
            txn_idx=0,
            major=majors[i % len(majors)],
            minor=0,
        )
        for i in range(n)
    ]


def _inspection_data() -> InspectionData:
    return InspectionData(cycles=_cycles(), all_txns=[], reg_txns=[])


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


def _outcomes_from_db(db_path: str) -> list[str]:
    with sqlite3.connect(db_path) as conn:
        return [row[0] for row in conn.execute(
            "SELECT outcome FROM mutations ORDER BY id"
        ).fetchall()]


class TestOutcomeForHelper:
    def test_classifies_applied_skipped_error(self):
        fz = A4Fuzzer(
            host_binary="/bin/true",
            host_args=["--in1", "5"],
            db_path=":memory:",
            selector_strategy="uniform",
            seed=1,
        )
        applied = MutationResult(
            kind="INSTR_TYPE_MOD",
            step=0,
            original_value=0,
            mutated_value=1,
            config={"step": 0},
            failures=[],
            verifier_accepted=True,
            execution_time_ms=1.0,
        )
        skipped = MutationResult(
            kind="INSTR_TYPE_MOD",
            step=0,
            original_value=0,
            mutated_value=0,
            config=None,
            failures=[],
            verifier_accepted=False,
            execution_time_ms=0.0,
        )
        error = MutationResult(
            kind="INSTR_TYPE_MOD",
            step=0,
            original_value=0,
            mutated_value=1,
            config={"step": 0},
            failures=[],
            verifier_accepted=False,
            execution_time_ms=1.0,
            crashed=True,
        )
        assert fz._outcome_for(applied) == MutationOutcome.APPLIED.value
        assert fz._outcome_for(skipped) == MutationOutcome.SKIPPED.value
        assert fz._outcome_for(error) == MutationOutcome.ERROR.value


class TestOutcomeColumnIntegration:
    def test_synthetic_campaign_populates_outcome_column(self):
        """Mock exec: applied, error (crash), applied — plus direct skipped row."""
        data = _inspection_data()
        exec_plan = iter([
            MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[],
                touch_bitmap=None,
            ),
            MutationExecutionResult(
                stdout="",
                stderr="segfault",
                combined_output="",
                exit_code=139,
                failures=[],
                touch_bitmap=None,
            ),
            MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[
                    ConstraintFailure(
                        cycle=1,
                        step=1,
                        pc=0,
                        major=0,
                        minor=0,
                        loc="callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:1)",
                        value=1,
                    )
                ],
                touch_bitmap=None,
            ),
        ])

        def _fake_exec(*_args, **_kwargs) -> MutationExecutionResult:
            return next(exec_plan)

        def _fake_create_mutation(kind: str, step: int):
            return ({"kind": kind, "step": step, "txn_idx": 0}, 42, 41)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "outcome.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5", "--in4", "10"],
                db_path=db_path,
                selector_strategy="cTS_semantic_v2",
                seed=99,
                telemetry_level="none",
                kind="INSTR_TYPE_MOD",
            )
            fz.data = data

            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=_baseline_touch(),
            ):
                with patch(
                    "a4.standalone.fuzzer.run_a4_mutation",
                    side_effect=_fake_exec,
                ):
                    with patch.object(
                        fz,
                        "_create_mutation",
                        side_effect=_fake_create_mutation,
                    ):
                        stats = fz.run_campaign(3)

            assert stats.total_mutations == 3

            # Direct skipped row (early-return skip paths do not record today).
            skipped = MutationResult(
                kind="LOAD_VAL_MOD",
                step=2,
                original_value=0,
                mutated_value=0,
                config=None,
                failures=[],
                verifier_accepted=False,
                execution_time_ms=0.0,
            )
            fz.db.record_mutation(
                fz.campaign_id,
                skipped.kind,
                skipped.step,
                0,
                None,
                None,
                False,
                original_value=0,
                **fz._mutation_record_kwargs(skipped),
            )

            outcomes = _outcomes_from_db(db_path)
            assert len(outcomes) == 4
            assert all(o is not None for o in outcomes)
            assert set(outcomes) == {
                MutationOutcome.APPLIED.value,
                MutationOutcome.ERROR.value,
                MutationOutcome.SKIPPED.value,
            }
            assert outcomes.count(MutationOutcome.APPLIED.value) == 2
            assert outcomes.count(MutationOutcome.ERROR.value) == 1
            assert outcomes.count(MutationOutcome.SKIPPED.value) == 1
