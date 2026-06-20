#!/usr/bin/env python3
"""D2.C Batch 1 — real-binary Arguzz invoke smoke (Layer 2, gating)."""

from __future__ import annotations

import os
import subprocess

import pytest

from a4.arguzz_dependent.arguzz_parser import parse_all_traces
from a4.standalone.arguzz_invoke import run
from a4.standalone.bandit_ts import MutationOutcome

SELECTED_KINDS = (
    "INSTR_WORD_MOD",
    "PRE_EXEC_MEM_MOD",
    "PRE_EXEC_PC_MOD",
    "BR_NEG_COND",
)

BRANCHES = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}


def _normalize_instr(name: str) -> str:
    return name.lower().replace("_", "").replace(".", "")


def _host_binary() -> str:
    default = "workspace/output/target/release/risc0-host"
    return os.environ.get("A4_TEST_HOST", default).strip()


def _host_args() -> list[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    return raw.split() if raw else []


def _pick_steps(host: str, host_args: list[str]) -> dict[str, int]:
    cmd = [host, "--trace", *host_args]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    stdout = (proc.stdout or b"").decode("utf-8", errors="replace") + (
        proc.stderr or b""
    ).decode("utf-8", errors="replace")
    if proc.returncode != 0:
        pytest.fail(f"baseline --trace failed rc={proc.returncode}")

    traces = parse_all_traces(stdout)
    if not traces:
        pytest.fail("no <trace> tags parsed from baseline --trace")

    steps: dict[str, int] = {"default": traces[len(traces) // 2].step}
    branch_step: int | None = None
    for tr in traces:
        instr = _normalize_instr(tr.instruction)
        if branch_step is None and instr in BRANCHES:
            branch_step = tr.step

    if branch_step is None:
        pytest.fail("no branch instruction found in baseline trace")
    steps["BR_NEG_COND"] = branch_step
    return steps


@pytest.fixture(scope="module")
def injection_steps() -> dict[str, int]:
    if os.environ.get("A4_REAL_BINARY") != "1":
        pytest.skip("Set A4_REAL_BINARY=1 to run real-binary smoke")
    if not os.path.isfile(_host_binary()):
        pytest.skip(f"missing host binary: {_host_binary()}")
    return _pick_steps(_host_binary(), _host_args())


@pytest.mark.parametrize("kind", SELECTED_KINDS)
def test_real_binary_selected_kind_emits_fault(kind: str, injection_steps: dict[str, int]):
    step = injection_steps.get(kind, injection_steps["default"])
    result = run(
        _host_binary(),
        _host_args(),
        step=step,
        kind=kind,
        seed=1243,
        timeout=90.0,
        include_trace=True,
    )
    assert len(result.faults) >= 1, (
        f"{kind} at step={step}: zero faults parsed; prover_status={result.prover_status}"
    )
    assert result.outcome in {MutationOutcome.APPLIED, MutationOutcome.ERROR}
    assert result.wall_s < 90.0
