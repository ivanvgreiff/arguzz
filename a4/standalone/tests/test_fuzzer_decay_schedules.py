#!/usr/bin/env python3
"""Integration tests for IV.POS.8 D1.A decay floor schedules in the fuzzer."""

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
from a4.standalone.fuzzer import A4Fuzzer, CTS_SEMANTIC_V2_FAMILY


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


def _coverage_count(db_path: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM coverage").fetchone()[0])


def _campaign_params(db_path: str) -> dict:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT selector, extra_json FROM campaign_params LIMIT 1"
        ).fetchone()
    assert row is not None
    extra = json.loads(row[1]) if row[1] else {}
    return {"selector": row[0], "extra": extra}


def _mutation_telemetry_sample(db_path: str) -> dict:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT proof_generated, proof_verify_failed, elapsed_ms
            FROM mutations ORDER BY id LIMIT 1
            """
        ).fetchone()
    return {
        "proof_generated": row[0],
        "proof_verify_failed": row[1],
        "elapsed_ms": row[2],
    }


@pytest.mark.parametrize(
    "selector,expected_type,expected_config",
    [
        (
            "cTS_semantic_v2",
            "constant",
            {"value": 0.55},
        ),
        (
            "cTS_semantic_v2_decayexp",
            "exponential",
            {"initial": 0.55, "floor_min": 0.20, "K": 50},
        ),
        (
            "cTS_semantic_v2_decayepoch",
            "epoch",
            {"stages": [[0, 0.55], [2000, 0.35], [4000, 0.20]]},
        ),
    ],
)
def test_decay_schedule_campaign_integration(selector, expected_type, expected_config):
    data = _inspection_data()
    mutation_counter = {"n": 0}
    sync_checkpoints: list[int] = []

    def _fake_exec(*_args, **_kwargs) -> MutationExecutionResult:
        mutation_counter["n"] += 1
        n = mutation_counter["n"]
        loc = f"TestLoc(zirgen/circuit/rv32im/v2/dsl/test.zir:{n})"
        failure = ConstraintFailure(
            cycle=n,
            step=n % 5,
            pc=0,
            major=0,
            minor=0,
            loc=loc,
            value=1,
        )
        return MutationExecutionResult(
            stdout='{"context":"Prover","status":"success"}\n',
            stderr="",
            combined_output='{"context":"Prover","status":"success"}\n',
            exit_code=0,
            failures=[failure],
            touch_bitmap=None,
        )

    def _fake_create_mutation(kind: str, step: int):
        return (
            {"kind": kind, "step": step, "txn_idx": 0, "targets": []},
            42,
            41,
        )

    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / f"{selector}.db")
        fz = A4Fuzzer(
            host_binary="/bin/true",
            host_args=["--in1", "5", "--in4", "10"],
            db_path=db_path,
            selector_strategy=selector,
            seed=4242,
            telemetry_level="none",
            kind="INSTR_TYPE_MOD",
        )
        fz.data = data
        orig_sync = fz._sync_local_coverage_after_failures

        def _sync_with_checkpoints(new_coverage: int) -> None:
            orig_sync(new_coverage)
            n = fz._local_loc_discoveries
            if n in (10, 25, 50):
                sync_checkpoints.append(n)
                assert n == _coverage_count(db_path)

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
                    with patch.object(
                        fz,
                        "_sync_local_coverage_after_failures",
                        side_effect=_sync_with_checkpoints,
                    ):
                        stats = fz.run_campaign(50)

        assert stats.successful_mutations == 50
        assert sync_checkpoints == [10, 25, 50]
        assert fz._local_loc_discoveries == 50
        assert fz._local_loc_discoveries == _coverage_count(db_path)

        params = _campaign_params(db_path)
        assert params["selector"] == selector
        assert params["extra"]["floor_schedule_type"] == expected_type
        assert params["extra"]["floor_schedule_config"] == expected_config

        sample = _mutation_telemetry_sample(db_path)
        assert sample["proof_generated"] == 1
        assert sample["elapsed_ms"] is not None
        assert sample["elapsed_ms"] >= 0


def test_legacy_db_nullable_telemetry_columns():
    """New columns tolerate NULL (legacy rows)."""
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        db_path = tmp.name
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE mutations (
                id INTEGER PRIMARY KEY,
                proof_generated INTEGER,
                proof_verify_failed INTEGER,
                elapsed_ms INTEGER
            )
            """
        )
        conn.execute("INSERT INTO mutations (id) VALUES (1)")
        conn.commit()
        row = conn.execute(
            "SELECT proof_generated, proof_verify_failed, elapsed_ms FROM mutations"
        ).fetchone()
    assert row == (None, None, None)


def test_cts_family_contains_all_v5_selectors():
    assert CTS_SEMANTIC_V2_FAMILY == frozenset({
        "cTS_semantic_v2",
        "cTS_semantic_v2_decayexp",
        "cTS_semantic_v2_decayepoch",
    })
