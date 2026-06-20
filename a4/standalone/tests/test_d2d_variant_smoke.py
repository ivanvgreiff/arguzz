#!/usr/bin/env python3
"""D2.D Batch 2 — per-variant arm coverage + applied-accounting F9 smoke."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from a4.core.constraint_parser import ConstraintFailure
from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.core.executor import MutationExecutionResult
from a4.standalone.arguzz_invoke import ArguzzInvocationResult
from a4.standalone.bandit_ts import ConstrainedTSScheduler, MutationOutcome
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.mutations.arguzz_bridge import (
    MUTATION_KINDS_ARGUZZ_FULL,
    MUTATION_KINDS_ARGUZZ_SELECTED,
)
from a4.standalone.semantic_arm_universe import ARGUZZ_EXEC_FAULT, ArmKey


def _inspection_data() -> InspectionData:
    cycles = [
        A4CycleInfo(
            cycle_idx=s, step=s, pc=0x200000 + s * 4, txn_idx=s,
            major=0 if s == 0 else 7, minor=0,
        )
        for s in range(8)
    ]
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


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
        family_details=[{"family": "memory", "broken_addrs": [0x20000]}],
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
    }
    return MutationOutcome.APPLIED, inv, config


class TestV6CTSVariantSmoke:
    def test_v6_cts_pulls_only_arguzz_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "v6.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="v6_cTS",
                seed=99,
                telemetry_level="none",
            )
            fz.data = _inspection_data()
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=_baseline_touch(),
            ), patch.object(
                A4Fuzzer, "_capture_baseline_trace",
                return_value={i: "add" for i in range(8)},
            ), patch(
                "a4.standalone.fuzzer.create_mutation_for_arm",
                side_effect=_fake_arguzz,
            ):
                fz.run_campaign(30)

            with sqlite3.connect(db_path) as conn:
                kinds = {
                    row[0]
                    for row in conn.execute("SELECT DISTINCT kind FROM mutations")
                }
            assert kinds <= set(MUTATION_KINDS_ARGUZZ_FULL)
            assert len(kinds) >= 1


class TestHybridCTSVariantSmoke:
    def test_hybrid_pulls_both_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "hybrid.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
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
                A4Fuzzer, "_capture_baseline_trace",
                return_value={i: "add" for i in range(8)},
            ), patch(
                "a4.standalone.fuzzer.run_a4_mutation",
                side_effect=_fake_a4_exec,
            ), patch(
                "a4.standalone.fuzzer.create_mutation_for_arm",
                side_effect=_fake_arguzz,
            ), patch.object(fz, "_create_mutation", side_effect=_fake_create):
                fz.run_campaign(50)

            with sqlite3.connect(db_path) as conn:
                kinds = {
                    row[0]
                    for row in conn.execute("SELECT DISTINCT kind FROM mutations")
                }
            assert kinds & set(MUTATION_KINDS_ARGUZZ_SELECTED)
            assert "INSTR_TYPE_MOD" in kinds


class TestAppliedAccountingF9:
    def test_v6_cts_advances_pulls_only_on_applied(self):
        call_idx = {"n": 0}
        applied_pulls: list[int] = []

        def _alternating_arguzz(arm, step, host, host_args, seed, data, **kwargs):
            call_idx["n"] += 1
            outcome = (
                MutationOutcome.APPLIED
                if call_idx["n"] % 2 == 1
                else MutationOutcome.SKIPPED
            )
            inv = ArguzzInvocationResult(
                rc=101 if outcome == MutationOutcome.APPLIED else 0,
                outcome=outcome,
                prover_status="error" if outcome == MutationOutcome.APPLIED else "none",
                wall_s=0.01,
                faults=[],
                failures=[] if outcome == MutationOutcome.SKIPPED else [
                    ConstraintFailure(
                        cycle=1, step=step, pc=0, major=0, minor=0,
                        loc="TestLoc(zirgen/circuit/rv32im/v2/dsl/test.zir:1)",
                        value=1,
                    )
                ],
                family_residues=[],
                family_details=[],
                global_residue={},
                host_panic=False,
                crash_reason="",
                traces=[],
                soundness_signal=False,
                extra_tags={},
                raw_stdout="",
            )
            config = {"kind": arm.kind, "step": step, "seed": seed}
            return outcome, inv, config

        real_update = ConstrainedTSScheduler.update_with_outcome

        def _track(self, arm, outcome, *, success):
            if outcome == MutationOutcome.APPLIED:
                applied_pulls.append(self.pulls.get(arm, 0))
            return real_update(self, arm, outcome, success=success)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "f9.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="v6_cTS",
                seed=7,
                telemetry_level="none",
            )
            fz.data = _inspection_data()
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=_baseline_touch(),
            ), patch.object(
                A4Fuzzer, "_capture_baseline_trace",
                return_value={i: "add" for i in range(8)},
            ), patch(
                "a4.standalone.fuzzer.create_mutation_for_arm",
                side_effect=_alternating_arguzz,
            ), patch.object(
                ConstrainedTSScheduler, "update_with_outcome", _track,
            ):
                fz.run_campaign(20)

            sched = fz.v2_scheduler
            assert sched.applied_accounting_mode is True
            total_pulls = sum(sched.pulls.values())
            assert total_pulls <= 20
            assert len(applied_pulls) >= 1
