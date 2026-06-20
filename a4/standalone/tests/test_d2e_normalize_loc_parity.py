#!/usr/bin/env python3
"""D2.E Gate A — normalized constraint_loc parity across live paths."""

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
from a4.standalone.tests.d2e_helpers import (
    CANONICAL_LOC_RE,
    assert_all_failure_locs_canonical,
)

_A4_RAW = (
    "callsite( AddrDecompose ( zirgen/circuit/rv32im/v2/dsl/u32.zir :67:3)"
)
_V6_RAW = "AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)"
_NESTED_A4 = (
    "callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:1)"
)
_V6_MEM = "IsRead(zirgen/circuit/rv32im/v2/dsl/mem.zir:79)"
_EXPECTED_ADDR = "AddrDecompose@u32.zir:67"
_EXPECTED_MEM = "IsRead@mem.zir:79"


def _failure(loc: str) -> ConstraintFailure:
    return ConstraintFailure(
        cycle=0, step=0, pc=0, major=0, minor=0, loc=loc, value=1,
    )


def _cycles(n: int = 5):
    return [
        A4CycleInfo(
            cycle_idx=i, step=i, pc=0, txn_idx=0, major=0, minor=0,
        )
        for i in range(n)
    ]


class TestNormalizeLocUnitParity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            (_A4_RAW, _EXPECTED_ADDR),
            (_V6_RAW, _EXPECTED_ADDR),
            (_NESTED_A4, _EXPECTED_MEM),
            (_V6_MEM, _EXPECTED_MEM),
        ],
    )
    def test_raw_formats_canonicalize_identically(self, raw: str, expected: str):
        assert _failure(raw).short_loc() == expected
        assert CANONICAL_LOC_RE.match(expected)

    def test_a4_and_v6_equivalent_pairs(self):
        pairs = [
            (_A4_RAW, _V6_RAW),
            (_NESTED_A4, _V6_MEM),
        ]
        for a4, v6 in pairs:
            assert _failure(a4).short_loc() == _failure(v6).short_loc()


class TestNormalizeLocE2E:
    def test_v6_cts_mocked_failures_are_canonical(self):
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

        def _fake_create(kind: str, step: int):
            return ({"kind": kind, "step": step, "txn_idx": 0}, 42, 41)

        touch = BaselineTouch(
            bitmap=bytearray(A4_TOUCH_MAP_SIZE),
            distinct_buckets=0,
            total_touches=0,
            touched_indices=[],
        )

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "norm_cts.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="v6_cTS",
                seed=11,
                telemetry_level="none",
            )
            fz.data = data
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=touch,
            ), patch.object(
                A4Fuzzer,
                "_capture_baseline_trace",
                return_value={i: "add" for i in range(5)},
            ), patch(
                "a4.standalone.fuzzer.run_a4_mutation",
                side_effect=_fake_exec,
            ), patch.object(
                fz, "_create_mutation", side_effect=_fake_create,
            ):
                fz.run_campaign(15)

            assert_all_failure_locs_canonical(Path(db_path))

            with sqlite3.connect(db_path) as conn:
                cov_locs = [
                    row[0]
                    for row in conn.execute(
                        "SELECT constraint_loc FROM coverage"
                    ).fetchall()
                ]
            for loc in cov_locs:
                assert "(" not in loc
                assert CANONICAL_LOC_RE.match(loc), loc
