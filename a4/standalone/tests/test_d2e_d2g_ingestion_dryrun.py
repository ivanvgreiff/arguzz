#!/usr/bin/env python3
"""D2.E Gate E — D2.G analysis ingestion dry-run."""

from __future__ import annotations

import sqlite3

import pytest

from a4.runs.iv_pos_7.analysis.counterfactuals import counterfactual_by_kind_frame
from a4.runs.iv_pos_7.analysis.metrics import compute_metrics_for_db
from a4.runs.iv_pos_7.analysis.per_loc_v2 import per_loc_v2_cells_frame
from a4.standalone.l1_signals import (
    bandit_success_l1_counterfactual,
    compute_l1_flags,
    d_loc_le_2,
    singleton_failure,
)
from a4.standalone.tests.d2e_helpers import (
    D2C_V6_UNIFORM_SMOKE_DB,
    v5_archive_path,
)


class TestD2GIngestionDryRun:
    def test_metrics_ingests_v5_archive(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 archive not present")
        row = compute_metrics_for_db(archive, n=6000)
        assert row["variant"] == "V5"
        assert row["local_context_final"] > 0
        assert row["compressed_global_context_final"] > 0
        assert row["n_mutations"] == 6000

    def test_metrics_ingests_v6_uniform_smoke_db(self):
        if not D2C_V6_UNIFORM_SMOKE_DB.is_file():
            pytest.skip("V6-uniform POS smoke DB not present")
        row = compute_metrics_for_db(D2C_V6_UNIFORM_SMOKE_DB, n=50)
        assert row["n_mutations"] == 50
        assert row["compressed_global_context_final"] >= 1

    def test_counterfactuals_reads_v5_archive(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 archive not present")
        root = archive.parent.parent.parent  # iv_pos_7/dbs
        df = counterfactual_by_kind_frame(root)
        v5_rows = df[df["variant"] == "V5"]
        assert len(v5_rows) >= 1
        assert "discovery_binary_reward" in v5_rows.columns

    def test_per_loc_v2_reads_v5_archive(self):
        archive = v5_archive_path()
        if archive is None:
            pytest.skip("V5 archive not present")
        root = archive.parent.parent.parent
        df = per_loc_v2_cells_frame(root, variants=("V5",))
        assert not df.empty
        assert "constraint_loc" in df.columns

    def test_l1_offline_recompute_matches_logged_definition(self):
        """ISS-DD-1 closure: offline predicates match l1_signals definitions."""
        assert d_loc_le_2(2) == 1
        assert d_loc_le_2(3) == 0
        assert singleton_failure([1]) == 1
        assert singleton_failure([1, 2]) == 0

    def test_l1_logged_columns_match_offline_recompute(self):
        """Gate E — re-audit logged L1 columns from a mocked v6_cTS DB."""
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from a4.core.constraint_parser import ConstraintFailure
        from a4.core.inspection_data import InspectionData
        from a4.core.trace_parser import A4CycleInfo
        from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
        from a4.standalone.arguzz_invoke import ArguzzInvocationResult
        from a4.standalone.bandit_ts import MutationOutcome
        from a4.standalone.baseline_touch import BaselineTouch
        from a4.standalone.fuzzer import A4Fuzzer

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
            config = {"kind": arm.kind, "step": step, "seed": seed}
            return MutationOutcome.APPLIED, inv, config

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
            db_path = str(Path(tmp) / "l1_reaudit.db")
            fz = A4Fuzzer(
                host_binary="/bin/true",
                host_args=["--in1", "5"],
                db_path=db_path,
                selector_strategy="v6_cTS",
                seed=555,
                telemetry_level="full",
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
            ):
                fz.run_campaign(20)

            with sqlite3.connect(db_path) as conn:
                rows = conn.execute(
                    """
                    SELECT rc.discovery_binary_reward,
                           rc.bandit_success_l1,
                           rc.l1_d_loc_le_2,
                           rc.l1_singleton_failure,
                           rc.l1_substrategy_uniqueness,
                           mr.d_loc,
                           m.kind,
                           (SELECT COUNT(*) FROM failures f
                            WHERE f.mutation_id = m.id) AS fail_count,
                           ms.opcode, ms.rd, ms.rs1, ms.rs2,
                           ms.funct3, ms.funct7, ms.imm,
                           ms.byte_lane, ms.bit_mask, ms.value_class
                    FROM reward_counterfactuals rc
                    JOIN mutations m ON m.id = rc.mutation_id
                    LEFT JOIN mutation_rewards mr ON mr.mutation_id = m.id
                    LEFT JOIN mutation_substrategy ms ON ms.mutation_id = m.id
                    ORDER BY m.id
                    """
                ).fetchall()

            assert rows, "expected L1-logged counterfactual rows"
            seen: set = set()
            for row in rows:
                (
                    disc, bs_l1, l1_d, l1_s, l1_u,
                    d_loc, kind, fail_count,
                    opcode, rd, rs1, rs2, funct3, funct7, imm,
                    byte_lane, bit_mask, value_class,
                ) = row
                sub = {
                    "opcode": opcode, "rd": rd, "rs1": rs1, "rs2": rs2,
                    "funct3": funct3, "funct7": funct7, "imm": imm,
                    "byte_lane": byte_lane, "bit_mask": bit_mask,
                    "value_class": value_class,
                }
                d_loc_val = int(d_loc) if d_loc is not None else 999
                flags = compute_l1_flags(
                    d_loc=d_loc_val,
                    failures=[None] * int(fail_count),
                    kind=kind,
                    substrategy=sub,
                    seen=seen,
                )
                exp_bs_l1 = bandit_success_l1_counterfactual(int(disc), flags)
                assert l1_d == flags["l1_d_loc_le_2"]
                assert l1_s == flags["l1_singleton_failure"]
                assert l1_u == flags["l1_substrategy_uniqueness"]
                assert bs_l1 == exp_bs_l1
