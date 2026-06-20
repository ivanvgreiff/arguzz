#!/usr/bin/env python3
"""D2.C Batch 1 — arguzz_invoke subprocess mock tests (Layer 1)."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from a4.standalone.arguzz_invoke import _decode_safe, run
from a4.standalone.bandit_ts import MutationOutcome

_FAULT = (
    '<fault>{"step":10,"pc":100,"kind":"INSTR_WORD_MOD",'
    '"info":"word:0x1 => word:0x2"}</fault>'
)
_TRACE = '<trace>{"step":10,"pc":100,"instruction":"add","assembly":"add"}</trace>'
_CFAIL = (
    '<constraint_fail>{"cycle":10,"step":10,"pc":100,"major":1,"minor":0,'
    '"loc":"VerifyOpcodeF3(zirgen/rv32im/inst.zir:1)","value":1,"phase":"local"}'
    "</constraint_fail>"
)
_PROVER_SUCCESS = '<record>{"context":"Prover","status":"success","time":"1.0s"}</record>'
_PROVER_ERROR = '<record>{"context":"Prover","status":"error","time":"1.0s"}</record>'
_PROVER_START = '<record>{"context":"Prover","status":"start","time":"0.1s"}</record>'
_FAMILY_RES = '<a4_family_residue>{"family":"memory","nonzero":true}</a4_family_residue>'
_FAMILY_DETAIL = (
    '<a4_family_detail>{"family":"memory","broken_addrs":[42]}</a4_family_detail>'
)


def _mock_run(stdout: str, *, rc: int = 0):
    def _fake_run(cmd, capture_output, timeout, env):
        return SimpleNamespace(
            returncode=rc,
            stdout=stdout.encode("utf-8"),
            stderr=b"",
        )

    return _fake_run


class TestArguzzInvokeMock:
    def test_decode_safe_non_utf8(self):
        raw = b"ok \xff\xfe tail"
        decoded = _decode_safe(raw)
        assert "ok" in decoded
        assert "\ufffd" in decoded

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_timeout_bucket(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["host"], timeout=90)
        result = run("host", [], step=5, kind="INSTR_WORD_MOD", seed=1)
        assert result.rc == 124
        assert result.outcome == MutationOutcome.ERROR

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_prove_success_bucket(self, mock_run):
        stdout = "\n".join([_FAULT, _TRACE, _PROVER_SUCCESS])
        mock_run.side_effect = _mock_run(stdout)
        result = run("host", [], step=10, kind="INSTR_WORD_MOD", seed=2)
        assert result.outcome == MutationOutcome.APPLIED
        assert result.soundness_signal is True
        assert len(result.faults) == 1
        assert len(result.traces) == 1

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_prove_error_with_failures_bucket(self, mock_run):
        stdout = "\n".join([_FAULT, _CFAIL, _PROVER_ERROR, "panicked at verify"])
        mock_run.side_effect = _mock_run(stdout)
        result = run("host", [], step=10, kind="INSTR_WORD_MOD", seed=3)
        assert result.outcome == MutationOutcome.APPLIED
        assert result.extra_tags == {}
        assert len(result.failures) == 1

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_prove_error_without_failures_path_b(self, mock_run):
        stdout = "\n".join([_FAULT, _PROVER_ERROR, "verify segment panicked at x"])
        mock_run.side_effect = _mock_run(stdout)
        result = run("host", [], step=10, kind="INSTR_WORD_MOD", seed=4)
        assert result.outcome == MutationOutcome.APPLIED
        assert result.extra_tags == {"failure_recording_gap": True}

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_start_panic_c5_skipped(self, mock_run):
        stdout = "\n".join([_FAULT, _PROVER_START, "Guest panicked: boom"])
        mock_run.side_effect = _mock_run(stdout)
        result = run("host", [], step=10, kind="INSTR_WORD_MOD", seed=5)
        assert result.outcome == MutationOutcome.SKIPPED
        assert result.host_panic is True

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_family_residue_parsing(self, mock_run):
        stdout = "\n".join([_FAULT, _FAMILY_RES, _FAMILY_DETAIL, _PROVER_ERROR, _CFAIL])
        mock_run.side_effect = _mock_run(stdout)
        result = run("host", [], step=10, kind="INSTR_WORD_MOD", seed=6)
        assert result.family_residues
        assert result.family_details

    @patch("a4.standalone.arguzz_invoke.subprocess.run")
    def test_subprocess_env_sets_constraint_continue(self, mock_run):
        mock_run.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        run(
            "host",
            ["--in1", "5"],
            step=1,
            kind="INSTR_WORD_MOD",
            seed=7,
            env={"A4_FAMILY_RESIDUE": "1"},
        )
        _, kwargs = mock_run.call_args
        assert kwargs["env"]["CONSTRAINT_CONTINUE"] == "1"
        assert kwargs["env"]["A4_FAMILY_RESIDUE"] == "1"
