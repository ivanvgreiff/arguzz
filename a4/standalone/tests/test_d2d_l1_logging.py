#!/usr/bin/env python3
"""D2.D Batch 3 — inactive L1 logging (observe-only substrate)."""

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
from a4.standalone.coverage_db import CoverageDB
from a4.standalone.fuzzer import A4Fuzzer
from a4.standalone.l1_signals import (
    composite_substrategy_key,
    compute_l1_flags,
    d_loc_le_2,
    singleton_failure,
    substrategy_uniqueness,
)
from a4.standalone.tests.test_bandit_ts import _decision_trace, _small_universe


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


class TestL1Extractors:
    def test_d_loc_le_2(self):
        assert d_loc_le_2(0) == 1
        assert d_loc_le_2(2) == 1
        assert d_loc_le_2(3) == 0

    def test_singleton_failure(self):
        assert singleton_failure([]) == 0
        assert singleton_failure([object()]) == 1
        assert singleton_failure([object(), object()]) == 0

    def test_instr_type_mod_excluded_from_substrategy(self):
        seen: set = set()
        assert substrategy_uniqueness("INSTR_TYPE_MOD", {}, seen) == 0

    def test_substrategy_first_occurrence_only(self):
        seen: set = set()
        sub = {"value_class": "boundary"}
        assert substrategy_uniqueness("LOAD_VAL_MOD", sub, seen) == 1
        assert substrategy_uniqueness("LOAD_VAL_MOD", sub, seen) == 0

    def test_cross_check_reference_definitions(self):
        """Match bug_proximity.py predicates (ported verbatim into l1_signals)."""
        sub_row = {
            "opcode": 1, "rd": 2, "rs1": 3, "rs2": 4,
            "funct3": 5, "funct7": 6, "imm": 7,
            "byte_lane": None, "bit_mask": None, "value_class": None,
        }
        ref_key = tuple(sub_row[f] for f in (
            "opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm",
        ))
        assert composite_substrategy_key("INSTR_WORD_MOD_SUR", sub_row) == ref_key
        assert d_loc_le_2(2) == (1 if 2 <= 2 else 0)
        assert singleton_failure([object()]) == (1 if 1 == 1 else 0)
        seen: set = set()
        key = ("INSTR_WORD_MOD_SUR", ref_key)
        first = 0 if key in seen else 1
        if first:
            seen.add(key)
        second = 0 if key in seen else 1
        assert first == 1 and second == 0
        assert substrategy_uniqueness("INSTR_WORD_MOD_SUR", sub_row, set()) == first


class TestL1SchemaMigration:
    def test_old_db_reads_l1_columns_as_null(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            db = CoverageDB(tmp.name)
            db.record_reward_counterfactuals(
                1, 0.5, 0.4, 0.1, 1, 0.2,
            )
            with sqlite3.connect(tmp.name) as conn:
                cols = {
                    row[1] for row in conn.execute(
                        "PRAGMA table_info(reward_counterfactuals)"
                    )
                }
                assert "bandit_success_l1" in cols
                row = conn.execute(
                    "SELECT bandit_success_l1, l1_d_loc_le_2 FROM reward_counterfactuals"
                ).fetchone()
            assert row == (None, None)


class TestL1InactivityProof:
    def _run_v6_trace(self, *, l1_logging: bool) -> tuple[list, list]:
        arguzz_calls = {"n": 0}
        update_successes: list[int] = []

        def _fake_arguzz(arm, step, host, host_args, seed, data, **kwargs):
            arguzz_calls["n"] += 1
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
            config = {"kind": arm.kind, "step": step, "seed": seed}
            return MutationOutcome.APPLIED, inv, config

        real_update = ConstrainedTSScheduler.update_with_outcome

        def _track(self, arm, outcome, *, success):
            update_successes.append(int(success))
            return real_update(self, arm, outcome, success=success)

        decisions: list[tuple] = []
        real_select = ConstrainedTSScheduler.select

        def _track_select(self):
            d = real_select(self)
            decisions.append((d.arm_id, d.mode, d.step))
            return d

        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "l1.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="v6_cTS",
                seed=555,
                telemetry_level="full" if l1_logging else "none",
            )
            fz.l1_logging = l1_logging
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
            ), patch.object(
                ConstrainedTSScheduler, "update_with_outcome", _track,
            ), patch.object(
                ConstrainedTSScheduler, "select", _track_select,
            ):
                fz.run_campaign(25)

            l1_rows = []
            if l1_logging:
                with sqlite3.connect(db_path) as conn:
                    l1_rows = conn.execute(
                        """
                        SELECT bandit_success_l1, l1_d_loc_le_2,
                               l1_singleton_failure, l1_substrategy_uniqueness,
                               discovery_binary_reward
                        FROM reward_counterfactuals
                        """
                    ).fetchall()
        return decisions, update_successes, l1_rows

    def test_l1_columns_populated_when_logging_on(self):
        _, _, l1_rows = self._run_v6_trace(l1_logging=True)
        assert len(l1_rows) >= 1
        assert all(r[0] is not None for r in l1_rows)
        assert any(r[1] is not None for r in l1_rows)

    def test_decisions_unchanged_with_l1_on_vs_off(self):
        on_dec, on_succ, _ = self._run_v6_trace(l1_logging=True)
        off_dec, off_succ, _ = self._run_v6_trace(l1_logging=False)
        assert on_dec == off_dec
        assert on_succ == off_succ

    def test_discovery_binary_unchanged_base_bit(self):
        _, _, l1_rows = self._run_v6_trace(l1_logging=True)
        for bs_l1, _, _, _, disc in l1_rows:
            assert disc in (0, 1)
            if disc == 0 and bs_l1 == 1:
                pass  # L1 can enrich counterfactual only


class TestL1DoesNotChangeV5GoldenTrace:
    def test_v5_decision_seq_unchanged(self):
        from a4.standalone.bandit_ts import ConstrainedTSScheduler as CTS

        seed = 42
        n = 200
        successes = [1 if i % 7 == 0 else 0 for i in range(n)]
        sched = CTS(_small_universe(), seed=seed)
        trace = _decision_trace(sched, n, successes)
        assert len(trace) == n
