#!/usr/bin/env python3
"""D2.C Batch 2 — Layer 3 bridge wiring (stubbed primitive + real bandit)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.arguzz_invoke import ArguzzInvocationResult
from a4.standalone.bandit_ts import ConstrainedTSScheduler, MutationOutcome
from a4.standalone.mutations import arguzz_bridge
from a4.standalone.mutations.arguzz_bridge import (
    DEFAULT_ARGUZZ_SUBPROCESS_ENV,
    INSTR_KINDS,
    MAPPING_INSTR_TO_OPCODE_CLASS,
    create_mutation_for_arm,
)
from a4.standalone.semantic_arm_universe import ARGUZZ_EXEC_FAULT, ArmKey, SemanticArmUniverse


def _data() -> InspectionData:
    cycles = [
        A4CycleInfo(
            cycle_idx=0, step=0, pc=0x200000, txn_idx=0,
            major=0, minor=0, state=48, diff_count_0=1, diff_count_1=2,
        ),
    ]
    return InspectionData(cycles=cycles, all_txns=[], reg_txns=[])


def _arm() -> ArmKey:
    return ArmKey(
        ARGUZZ_EXEC_FAULT,
        "INSTR_WORD_MOD",
        "core_arithmetic",
        "arithmetic",
        "pre_exec",
    )


class TestMappingCoverage:
    def test_instr_kinds_map_to_intended_opcode_classes(self):
        """ISS-4: known RV32IM mnemonics must not silently fall through to system."""
        system_only = {"invalid"}
        for instr in INSTR_KINDS:
            oc = MAPPING_INSTR_TO_OPCODE_CLASS.get(instr, "system")
            if instr in system_only:
                assert oc == "system", instr
            else:
                assert oc != "system", f"{instr} unexpectedly mapped to system"


class TestCreateMutationForArm:
    def test_applied_via_error_with_failures(self, monkeypatch):
        mock_run = MagicMock(
            return_value=ArguzzInvocationResult(
                rc=101,
                outcome=MutationOutcome.APPLIED,
                prover_status="error",
                wall_s=0.1,
                faults=[],
                failures=[object()],
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
        )
        monkeypatch.setattr("a4.standalone.mutations.arguzz_bridge.run", mock_run)

        outcome, result, config = create_mutation_for_arm(
            _arm(), 0, "host", ["--in1", "5"], 42, _data(),
        )
        assert outcome == MutationOutcome.APPLIED
        assert result.prover_status == "error"
        assert config["kind"] == "INSTR_WORD_MOD"
        assert config["step"] == 0
        assert config["pre_post"] == "pre_exec"
        assert config["opcode_class"] == "arithmetic"
        assert config["seed"] == 42
        mock_run.assert_called_once_with(
            "host", ["--in1", "5"], 0, "INSTR_WORD_MOD", 42,
            timeout=90.0, include_trace=False,
            env=dict(DEFAULT_ARGUZZ_SUBPROCESS_ENV),
        )

    def test_default_subprocess_env_includes_hook3_co_trigger(self, monkeypatch):
        mock_run = MagicMock(
            return_value=ArguzzInvocationResult(
                rc=101,
                outcome=MutationOutcome.APPLIED,
                prover_status="error",
                wall_s=0.1,
                faults=[],
                failures=[],
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
        )
        monkeypatch.setattr("a4.standalone.mutations.arguzz_bridge.run", mock_run)
        create_mutation_for_arm(_arm(), 0, "host", [], 1, _data())
        env = mock_run.call_args.kwargs["env"]
        assert env["A4_FAMILY_RESIDUE"] == "1"
        assert env["A4_COVERAGE_TOUCH"] == "1"

    def test_soundness_signal_on_success(self, monkeypatch):
        mock_run = MagicMock(
            return_value=ArguzzInvocationResult(
                rc=0,
                outcome=MutationOutcome.APPLIED,
                prover_status="success",
                wall_s=0.1,
                faults=[],
                failures=[],
                family_residues=[],
                family_details=[],
                global_residue={},
                host_panic=False,
                crash_reason="",
                traces=[],
                soundness_signal=True,
                extra_tags={"soundness_signal": True},
                raw_stdout="",
            )
        )
        monkeypatch.setattr("a4.standalone.mutations.arguzz_bridge.run", mock_run)

        outcome, _, config = create_mutation_for_arm(
            _arm(), 0, "host", [], 7, _data(),
        )
        assert outcome == MutationOutcome.APPLIED
        assert config["soundness_signal"] is True

    def test_skipped_on_start_panic(self, monkeypatch):
        mock_run = MagicMock(
            return_value=ArguzzInvocationResult(
                rc=0,
                outcome=MutationOutcome.SKIPPED,
                prover_status="start",
                wall_s=0.1,
                faults=[],
                failures=[],
                family_residues=[],
                family_details=[],
                global_residue={},
                host_panic=True,
                crash_reason="Guest panicked: oops",
                traces=[],
                soundness_signal=False,
                extra_tags={},
                raw_stdout="",
            )
        )
        monkeypatch.setattr("a4.standalone.mutations.arguzz_bridge.run", mock_run)

        outcome, _, _ = create_mutation_for_arm(
            _arm(), 0, "host", [], 7, _data(),
        )
        assert outcome == MutationOutcome.SKIPPED


class TestBridgeWithRealBandit:
    def test_update_with_outcome_accepts_bridge_outcome(self, monkeypatch):
        mock_run = MagicMock(
            return_value=ArguzzInvocationResult(
                rc=101,
                outcome=MutationOutcome.APPLIED,
                prover_status="error",
                wall_s=0.1,
                faults=[],
                failures=[object()],
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
        )
        monkeypatch.setattr("a4.standalone.mutations.arguzz_bridge.run", mock_run)

        data, baseline_trace = _synthetic_data_and_trace()
        uni = SemanticArmUniverse.build(
            data,
            [],
            arguzz_kinds=["INSTR_WORD_MOD"],
            baseline_trace=baseline_trace,
        )
        arm = next(a for a in uni.arms if a.kind == "INSTR_WORD_MOD")
        sched = ConstrainedTSScheduler(
            uni,
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=0,
            epoch_size=50,
            seed=1,
            applied_accounting_mode=True,
        )

        outcome, _, _ = create_mutation_for_arm(
            arm, uni.steps_for_arm(arm)[0], "host", [], 99, data,
        )
        sched.update_with_outcome(arm, outcome, success=1)
        assert sched.pulls[arm] == 1
        assert sched.successes[arm] == 1


def _synthetic_data_and_trace():
    from a4.core.trace_parser import A4CycleInfo

    baseline_trace = {0: "add", 1: "beq"}
    cycles = [
        A4CycleInfo(
            cycle_idx=s, step=s, pc=0x200000 + s * 4, txn_idx=s,
            major=0 if s == 0 else 7, minor=0, state=48,
            diff_count_0=1, diff_count_1=2,
        )
        for s in baseline_trace
    ]
    data = InspectionData(cycles=cycles, all_txns=[], reg_txns=[])
    return data, baseline_trace
