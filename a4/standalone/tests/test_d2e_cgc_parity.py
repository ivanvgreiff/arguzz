#!/usr/bin/env python3
"""D2.E Gate C — CGC parity (F13 standing regression)."""

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
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.bandit_ts import MutationOutcome
from a4.standalone.tests.d2e_helpers import D2C_V6_UNIFORM_SMOKE_DB


class TestCGCFromPosV6UniformSmoke:
    def test_v6_uniform_pos_db_has_cgc_and_global_failures(self):
        if not D2C_V6_UNIFORM_SMOKE_DB.is_file():
            pytest.skip("V6-uniform POS smoke DB not present")
        with sqlite3.connect(D2C_V6_UNIFORM_SMOKE_DB) as conn:
            cgc = conn.execute(
                "SELECT COUNT(*) FROM compressed_global_coverage"
            ).fetchone()[0]
            gf = conn.execute(
                "SELECT COUNT(*) FROM global_failures"
            ).fetchone()[0]
        assert cgc >= 1, "F13 regression: CGC empty on V6-uniform POS DB"
        assert gf >= 1, "F13 regression: global_failures empty"


class TestCGCFromMockedHybrid:
    def test_hybrid_arguzz_path_populates_cgc(self):
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
            config = {"kind": arm.kind, "step": step, "seed": seed}
            return MutationOutcome.APPLIED, inv, config

        def _fake_a4(*_a, **_k):
            return MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[],
                touch_bitmap=None,
            )

        cycles = [
            A4CycleInfo(
                cycle_idx=s, step=s, pc=0, txn_idx=s,
                major=0 if s == 0 else 7, minor=0,
            )
            for s in range(8)
        ]
        touch = BaselineTouch(
            bitmap=bytearray(A4_TOUCH_MAP_SIZE),
            distinct_buckets=0,
            total_touches=0,
            touched_indices=[],
        )

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "hybrid_cgc.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="hybrid_cTS",
                seed=88,
                telemetry_level="full",
                kind="INSTR_TYPE_MOD",
            )
            fz.data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=touch,
            ), patch.object(
                A4Fuzzer,
                "_capture_baseline_trace",
                return_value={i: "add" for i in range(8)},
            ), patch(
                "a4.standalone.fuzzer.create_mutation_for_arm",
                side_effect=_fake_arguzz,
            ), patch(
                "a4.standalone.fuzzer.run_a4_mutation",
                side_effect=_fake_a4,
            ), patch.object(
                fz,
                "_create_mutation",
                side_effect=lambda k, s: (
                    {"kind": k, "step": s, "txn_idx": 0}, 42, 41
                ),
            ):
                fz.run_campaign(30)

            with sqlite3.connect(db_path) as conn:
                cgc = conn.execute(
                    "SELECT COUNT(*) FROM compressed_global_coverage"
                ).fetchone()[0]
                gf = conn.execute(
                    "SELECT COUNT(*) FROM global_failures"
                ).fetchone()[0]
            assert cgc >= 1
            assert gf >= 1
