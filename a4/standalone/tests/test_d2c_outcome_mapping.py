#!/usr/bin/env python3
"""D2.C Batch 1 — Option C outcome mapping unit tests."""

from __future__ import annotations

from a4.standalone.arguzz_invoke import _classify_outcome, _detect_host_panic
from a4.standalone.bandit_ts import MutationOutcome


class TestClassifyOutcome:
    def test_timeout_rc_124(self):
        outcome, tags = _classify_outcome(124, False, "none", False)
        assert outcome == MutationOutcome.ERROR
        assert tags == {}

    def test_prove_success_not_panic(self):
        outcome, tags = _classify_outcome(0, False, "success", False)
        assert outcome == MutationOutcome.APPLIED
        assert tags == {"soundness_signal": True}

    def test_path_a_error_with_failures(self):
        outcome, tags = _classify_outcome(0, True, "error", True)
        assert outcome == MutationOutcome.APPLIED
        assert tags == {}

    def test_path_b_error_without_failures(self):
        outcome, tags = _classify_outcome(0, True, "error", False)
        assert outcome == MutationOutcome.APPLIED
        assert tags == {"failure_recording_gap": True}

    def test_start_with_failures_mid_witgen(self):
        outcome, tags = _classify_outcome(0, True, "start", True)
        assert outcome == MutationOutcome.APPLIED
        assert tags == {}

    def test_c5_start_with_host_panic(self):
        outcome, tags = _classify_outcome(0, True, "start", False)
        assert outcome == MutationOutcome.SKIPPED
        assert tags == {}

    def test_edge_other(self):
        outcome, tags = _classify_outcome(0, False, "start", False)
        assert outcome == MutationOutcome.ERROR
        assert tags == {}

    def test_start_both_failures_and_panic_failures_win(self):
        """§6.1 order: start+has_failures before start+host_panic."""
        outcome, tags = _classify_outcome(0, True, "start", True)
        assert outcome == MutationOutcome.APPLIED
        assert tags == {}


class TestDetectHostPanic:
    def test_panicked_at(self):
        stdout = "thread 'main' panicked at 'oops', src/main.rs:1:1"
        ok, reason = _detect_host_panic(stdout)
        assert ok is True
        assert "panicked at" in reason

    def test_guest_panicked(self):
        stdout = "Guest panicked: invalid opcode"
        ok, reason = _detect_host_panic(stdout)
        assert ok is True
        assert "Guest panicked:" in reason

    def test_no_panic(self):
        ok, reason = _detect_host_panic("prover finished cleanly")
        assert ok is False
        assert reason == ""
