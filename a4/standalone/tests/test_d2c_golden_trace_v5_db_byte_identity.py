#!/usr/bin/env python3
"""D2.C Batch 3 — Tier-2 V5 golden-trace DB byte-identity gate."""

from __future__ import annotations

import json
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
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer

_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "d2c_golden_v5_db_byte_identity_seed42_n20.json"
)


def _cycles(n: int = 8):
    majors = [0, 0, 5, 6, 0, 7, 0, 5]
    return [
        A4CycleInfo(
            cycle_idx=i,
            step=i,
            pc=0x200000 + i * 4,
            txn_idx=i,
            major=majors[i % len(majors)],
            minor=0,
            state=48,
            diff_count_0=1,
            diff_count_1=2,
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


def _stable_db_snapshot(db_path: str) -> list:
    """Serialize DB rows minus timestamps/ids for byte-identity comparison."""
    with sqlite3.connect(db_path) as conn:
        mutations = conn.execute(
            """
            SELECT kind, step, mutated_value, original_value, config_json,
                   verifier_accepted, proof_generated, proof_verify_failed,
                   elapsed_ms, outcome
            FROM mutations ORDER BY id
            """
        ).fetchall()
        failures = conn.execute(
            """
            SELECT constraint_loc, cycle, step, pc, major, minor, value
            FROM failures ORDER BY id
            """
        ).fetchall()
        coverage = conn.execute(
            "SELECT constraint_loc, hit_count FROM coverage ORDER BY constraint_loc"
        ).fetchall()
    return {
        "mutations": [list(r) for r in mutations],
        "failures": [list(r) for r in failures],
        "coverage": [list(r) for r in coverage],
    }


def _run_mocked_campaign(db_path: str) -> list:
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
            stderr="",
            combined_output="",
            exit_code=0,
            failures=[
                ConstraintFailure(
                    cycle=1, step=1, pc=0, major=0, minor=0,
                    loc="callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:1)",
                    value=1,
                )
            ],
            touch_bitmap=None,
        ),
    ] * 20)

    def _fake_exec(*_args, **_kwargs):
        try:
            return next(exec_plan)
        except StopIteration:
            return MutationExecutionResult(
                stdout="", stderr="", combined_output="", exit_code=0,
                failures=[], touch_bitmap=None,
            )

    def _fake_create(kind: str, step: int):
        return ({"kind": kind, "step": step, "txn_idx": 0}, 42, 41)

    fz = A4Fuzzer(
        host_binary="/bin/true",
        host_args=["--in1", "5", "--in4", "10"],
        db_path=db_path,
        selector_strategy="cTS_semantic_v2",
        seed=42,
        telemetry_level="none",
        kind="all",
    )
    fz.data = _inspection_data()

    with patch(
        "a4.standalone.fuzzer.capture_baseline_touch",
        return_value=_baseline_touch(),
    ), patch(
        "a4.standalone.fuzzer.time.perf_counter",
        side_effect=[float(i) for i in range(500)],
    ):
        with patch("a4.standalone.fuzzer.run_a4_mutation", side_effect=_fake_exec):
            with patch.object(fz, "_create_mutation", side_effect=_fake_create):
                fz.run_campaign(20)
    return _stable_db_snapshot(db_path)


class TestD2CGoldenTraceV5DbByteIdentity:
    def test_v5_db_byte_identity_matches_fixture(self):
        assert _FIXTURE.is_file(), f"missing fixture: {_FIXTURE}"
        expected = json.loads(_FIXTURE.read_text())

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "golden.db")
            actual = _run_mocked_campaign(db_path)

        assert actual == expected
