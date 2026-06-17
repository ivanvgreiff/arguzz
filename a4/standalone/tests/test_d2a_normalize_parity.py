#!/usr/bin/env python3
"""D2.A Batch 2 — short_loc() parity for A4 + V6 raw constraint loc formats."""

from __future__ import annotations

import re
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

_CANONICAL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*@[A-Za-z0-9_.]+:\d+$")

_A4_RAW = (
    "callsite( AddrDecompose ( zirgen/circuit/rv32im/v2/dsl/u32.zir :67:3)"
)
_V6_RAW = "AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)"
_EXPECTED = "AddrDecompose@u32.zir:67"


def _failure(loc: str) -> ConstraintFailure:
    return ConstraintFailure(
        cycle=0,
        step=0,
        pc=0,
        major=0,
        minor=0,
        loc=loc,
        value=1,
    )


def _cycles(n: int = 5):
    return [
        A4CycleInfo(
            cycle_idx=i,
            step=i,
            pc=0,
            txn_idx=0,
            major=0,
            minor=0,
        )
        for i in range(n)
    ]


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


class TestShortLocParity:
    def test_a4_raw_produces_canonical_form(self):
        assert _failure(_A4_RAW).short_loc() == _EXPECTED

    def test_v6_raw_produces_canonical_form(self):
        assert _failure(_V6_RAW).short_loc() == _EXPECTED

    def test_a4_and_v6_equivalent_for_same_constraint(self):
        assert _failure(_A4_RAW).short_loc() == _failure(_V6_RAW).short_loc()

    def test_canonical_matches_expected_regex(self):
        for raw in (_A4_RAW, _V6_RAW):
            loc = _failure(raw).short_loc()
            assert _CANONICAL_RE.match(loc), loc


class TestCoverageConstraintLocFromSyntheticFuzzer:
    def test_v5_campaign_writes_normalized_coverage_locs(self):
        data = InspectionData(cycles=_cycles(), all_txns=[], reg_txns=[])
        counter = {"n": 0}

        def _fake_exec(*_args, **_kwargs) -> MutationExecutionResult:
            counter["n"] += 1
            n = counter["n"]
            loc = (
                "callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir "
                f":{70 + n}:1)"
            )
            return MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[_failure(loc)],
                touch_bitmap=None,
            )

        def _fake_create_mutation(kind: str, step: int):
            return ({"kind": kind, "step": step, "txn_idx": 0}, 42, 41)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "norm.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5", "--in4", "10"],
                db_path=db_path,
                selector_strategy="cTS_semantic_v2",
                seed=7,
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
                        fz.run_campaign(20)

            with sqlite3.connect(db_path) as conn:
                locs = [
                    row[0]
                    for row in conn.execute(
                        "SELECT constraint_loc FROM coverage ORDER BY constraint_loc"
                    ).fetchall()
                ]

            assert len(locs) >= 1
            for loc in locs:
                assert "(" not in loc, loc
                assert "zirgen/" not in loc, loc
                assert _CANONICAL_RE.match(loc), loc
