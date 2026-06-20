#!/usr/bin/env python3
"""D2.E Gate B + D — schema parity and applied-accounting consistency."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.variants import CANONICAL_VARIANTS
from a4.standalone.tests.d2e_helpers import (
    COMPARABILITY_TABLES,
    D2C_V6_UNIFORM_SMOKE_DB,
    FRESH_VARIANT_REQUIRED_COLUMNS,
    fresh_reference_db_path,
    list_tables,
    schema_gaps_vs_fresh,
    table_columns,
    v5_archive_path,
)


class TestF15V5ArchiveSchema:
    """F15 — V5 R2 archive vs fresh-variant schema (escalation if incompatible)."""

    def test_v5_archive_missing_comparability_columns_documented(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 R2 archive DB not present in workspace")

        fresh = fresh_reference_db_path()
        try:
            gaps = schema_gaps_vs_fresh(archive, fresh)
            assert "mutations" in gaps
            assert "outcome" in gaps["mutations"]
            assert "reward_counterfactuals" in gaps
            assert "bandit_success_l1" in gaps["reward_counterfactuals"]
        finally:
            fresh.unlink(missing_ok=True)

    def test_v5_archive_has_core_comparability_tables(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 R2 archive DB not present")
        tables = list_tables(archive)
        missing = COMPARABILITY_TABLES - tables
        assert not missing, f"V5 archive missing tables: {missing}"

    def test_fresh_v6_uniform_smoke_has_outcome_column(self):
        if not D2C_V6_UNIFORM_SMOKE_DB.is_file():
            pytest.skip("POS V6-uniform smoke DB not present locally")
        cols = table_columns(D2C_V6_UNIFORM_SMOKE_DB, "mutations")
        assert "outcome" in cols


class TestFreshVariantSchemaParity:
    def test_reference_fresh_db_has_all_required_columns(self):
        fresh = fresh_reference_db_path()
        try:
            for table, cols in FRESH_VARIANT_REQUIRED_COLUMNS.items():
                present = table_columns(fresh, table)
                assert cols <= present, f"{table} missing {cols - present}"
        finally:
            fresh.unlink(missing_ok=True)


class TestAppliedAccountingProvenance:
    def _setup(self, selector: str) -> A4Fuzzer:
        cycles = [
            A4CycleInfo(
                cycle_idx=i, step=i, pc=0, txn_idx=i, major=i % 5, minor=0,
            )
            for i in range(8)
        ]
        fz = A4Fuzzer(
            host_binary="/bin/true",
            host_args=["--in1", "5"],
            db_path=":memory:",
            selector_strategy=selector,
            seed=3,
            telemetry_level="none",
        )
        fz.data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
        touch = BaselineTouch(
            bitmap=bytearray(A4_TOUCH_MAP_SIZE),
            distinct_buckets=0,
            total_touches=0,
            touched_indices=[],
        )
        with patch(
            "a4.standalone.fuzzer.capture_baseline_touch",
            return_value=touch,
        ):
            if selector in ("v6_cTS", "hybrid_cTS"):
                with patch.object(
                    fz,
                    "_capture_baseline_trace",
                    return_value={i: "add" for i in range(8)},
                ):
                    fz._setup_v2_bandit(10)
            else:
                fz._setup_v2_bandit(10)
        return fz

    def test_v6_cts_applied_accounting_on(self):
        spec = CANONICAL_VARIANTS["V6_cTS"]
        fz = self._setup("v6_cTS")
        assert fz.v2_scheduler.applied_accounting_mode is spec.applied_accounting

    def test_hybrid_applied_accounting_on(self):
        spec = CANONICAL_VARIANTS["Hybrid_cTS"]
        fz = self._setup("hybrid_cTS")
        assert fz.v2_scheduler.applied_accounting_mode is spec.applied_accounting

    def test_v5_fresh_equiv_applied_accounting_off(self):
        spec = CANONICAL_VARIANTS["V5_control"]
        fz = self._setup("cTS_semantic_v2")
        assert fz.v2_scheduler.applied_accounting_mode is spec.applied_accounting

    def test_mocked_campaign_outcomes_non_null(self):
        from a4.core.executor import MutationExecutionResult
        from a4.core.constraint_parser import ConstraintFailure

        def _fake_exec(*_a, **_k):
            return MutationExecutionResult(
                stdout='{"context":"Prover","status":"success"}\n',
                stderr="",
                combined_output='{"context":"Prover","status":"success"}\n',
                exit_code=0,
                failures=[
                    ConstraintFailure(
                        cycle=1, step=1, pc=0, major=0, minor=0,
                        loc="callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:1)",
                        value=1,
                    )
                ],
                touch_bitmap=None,
            )

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "outcome.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="cTS_semantic_v2",
                seed=9,
                telemetry_level="none",
                kind="INSTR_TYPE_MOD",
            )
            fz.data = InspectionData(
                cycles=[
                    A4CycleInfo(
                        cycle_idx=i, step=i, pc=0, txn_idx=i,
                        major=0, minor=0,
                    )
                    for i in range(5)
                ],
                all_txns=[],
                reg_txns=[],
            )
            touch = BaselineTouch(
                bitmap=bytearray(A4_TOUCH_MAP_SIZE),
                distinct_buckets=0,
                total_touches=0,
                touched_indices=[],
            )
            with patch(
                "a4.standalone.fuzzer.capture_baseline_touch",
                return_value=touch,
            ), patch(
                "a4.standalone.fuzzer.run_a4_mutation",
                side_effect=_fake_exec,
            ), patch.object(
                fz,
                "_create_mutation",
                side_effect=lambda k, s: (
                    {"kind": k, "step": s, "txn_idx": 0}, 42, 41
                ),
            ):
                fz.run_campaign(10)

            with sqlite3.connect(db_path) as conn:
                nulls = conn.execute(
                    "SELECT COUNT(*) FROM mutations WHERE outcome IS NULL"
                ).fetchone()[0]
                dist = dict(
                    conn.execute(
                        "SELECT outcome, COUNT(*) FROM mutations GROUP BY outcome"
                    ).fetchall()
                )
            assert nulls == 0
            assert dist.get("applied", 0) >= 1
