#!/usr/bin/env python3
"""D2.C Batch 4 — Layer 6 Hybrid-cTS forerunner (stubbed primitive)."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.arguzz_invoke import ArguzzInvocationResult
from a4.standalone.bandit_ts import ConstrainedTSScheduler, MutationOutcome
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer
from a4.core.executor import MutationExecutionResult
from a4.standalone.mutations.arguzz_bridge import MUTATION_KINDS_ARGUZZ_SELECTED
from a4.standalone.semantic_arm_universe import ARGUZZ_EXEC_FAULT, ArmKey


def _inspection_data() -> InspectionData:
    cycles = [
        A4CycleInfo(
            cycle_idx=s, step=s, pc=0x200000 + s * 4, txn_idx=s,
            major=0 if s == 0 else 7, minor=0, state=48,
            diff_count_0=1, diff_count_1=2,
        )
        for s in range(8)
    ]
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


def _baseline_trace() -> dict[int, str]:
    return {s: ("add" if s % 2 == 0 else "beq") for s in range(8)}


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


class TestHybridCTSSmoke:
    def test_both_surfaces_pulled_and_update_with_outcome(self):
        arguzz_calls: list[ArmKey] = []
        update_calls: list[tuple] = []

        def _fake_a4_exec(*_args, **_kwargs):
            return MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[],
                touch_bitmap=None,
            )

        def _fake_create(kind: str, step: int):
            return ({"kind": kind, "step": step, "txn_idx": 0}, 42, 41)

        def _fake_arguzz(arm, step, host, host_args, seed, data, **kwargs):
            arguzz_calls.append(arm)
            inv = ArguzzInvocationResult(
                rc=101,
                outcome=MutationOutcome.APPLIED,
                prover_status="error",
                wall_s=0.01,
                faults=[],
                failures=[
                    ConstraintFailure(
                        cycle=1, step=step, pc=0, major=0, minor=0,
                        loc="callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:1)",
                        value=1,
                    )
                ],
                family_residues=[{"family": "memory", "nonzero": True}],
                family_details=[{
                    "family": "memory",
                    "broken_addrs": [0x20000],
                }],
                global_residue={},
                host_panic=False,
                crash_reason="",
                traces=[],
                soundness_signal=False,
                extra_tags={},
                raw_stdout="",
            )
            config = {
                "kind": arm.kind,
                "step": step,
                "pre_post": arm.pre_post,
                "opcode_class": arm.opcode_class,
                "seed": seed,
                "soundness_signal": False,
            }
            return MutationOutcome.APPLIED, inv, config

        real_update = ConstrainedTSScheduler.update_with_outcome

        def _track_update(self, arm, outcome, *, success):
            update_calls.append((arm.surface, outcome, success))
            return real_update(self, arm, outcome, success=success)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "hybrid.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5", "--in4", "10"],
                db_path=db_path,
                selector_strategy="hybrid_cTS",
                seed=4242,
                telemetry_level="none",
                kind="INSTR_TYPE_MOD",
            )
            fz.data = _inspection_data()

            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=_baseline_touch(),
            ), patch.object(
                A4Fuzzer,
                "_capture_baseline_trace",
                return_value=_baseline_trace(),
            ), patch(
                "a4.standalone.fuzzer.run_a4_mutation",
                side_effect=_fake_a4_exec,
            ), patch(
                "a4.standalone.fuzzer.create_mutation_for_arm",
                side_effect=_fake_arguzz,
            ), patch.object(
                ConstrainedTSScheduler,
                "update_with_outcome",
                _track_update,
            ):
                with patch.object(fz, "_create_mutation", side_effect=_fake_create):
                    stats = fz.run_campaign(50)

            assert stats.successful_mutations >= 1
            assert len(arguzz_calls) >= 1, "expected ≥1 Arguzz arm pull"
            assert all(a.surface == ARGUZZ_EXEC_FAULT for a in arguzz_calls)

            with sqlite3.connect(db_path) as conn:
                outcomes = {
                    row[0]
                    for row in conn.execute(
                        "SELECT DISTINCT outcome FROM mutations WHERE outcome IS NOT NULL"
                    )
                }
                db_kinds = {
                    row[0]
                    for row in conn.execute("SELECT DISTINCT kind FROM mutations")
                }
            assert "applied" in outcomes

            assert db_kinds & set(MUTATION_KINDS_ARGUZZ_SELECTED), (
                "expected ≥1 Arguzz kind in DB"
            )
            assert "INSTR_TYPE_MOD" in db_kinds, "expected ≥1 A4 kind in DB"

            surfaces_updated = {c[0] for c in update_calls}
            assert ARGUZZ_EXEC_FAULT in surfaces_updated
            assert len(update_calls) >= 1

            surfaces_pulled = {
                arm.surface for arm, n in fz.v2_scheduler.pulls.items() if n > 0
            }
            assert ARGUZZ_EXEC_FAULT in surfaces_pulled
            assert "A4_trace_cell" in surfaces_pulled
