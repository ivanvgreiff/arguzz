#!/usr/bin/env python3
"""D2.C primitive — single source of truth for risc0-host --inject invocations."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from a4.arguzz_dependent.arguzz_parser import (
    ArguzzFault,
    ArguzzTrace,
    parse_all_faults,
    parse_all_traces,
)
from a4.core.constraint_parser import ConstraintFailure, parse_all_constraint_failures
from a4.core.touch_coverage import (
    parse_family_detail,
    parse_family_residues,
    parse_global_residue,
)
from a4.standalone.bandit_ts import MutationOutcome

logger = logging.getLogger("a4.arguzz_invoke")

_RAW_STDOUT_TAIL_BYTES = 4096
_CRASH_REASON_MAX = 256

_PROVER_REC_RE = re.compile(
    r'<record>\{"context":"Prover",\s*"status":"(\w+)"(?:,\s*"time":"([^"]+)")?\}</record>'
)


@dataclass
class ArguzzInvocationResult:
    rc: int
    outcome: MutationOutcome
    prover_status: str
    wall_s: float
    faults: List[ArguzzFault]
    failures: List[ConstraintFailure]
    family_residues: list
    family_details: list
    global_residue: dict
    host_panic: bool
    crash_reason: str
    traces: List[ArguzzTrace]
    soundness_signal: bool = False
    extra_tags: Dict[str, bool] = field(default_factory=dict)
    raw_stdout: str = ""


def _decode_safe(b: bytes | None) -> str:
    """Decode subprocess bytes safely (from v6_driver_v2.py:328-340)."""
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_prover_status(stdout: str) -> Tuple[str, Optional[str]]:
    """Return (status, time) from the last Prover record, or ('none', None)."""
    matches = _PROVER_REC_RE.findall(stdout)
    if not matches:
        return ("none", None)
    status, prov_time = matches[-1]
    return (status, prov_time)


def _detect_host_panic(stdout: str) -> Tuple[bool, str]:
    for needle in ("panicked at ", "Guest panicked:"):
        if needle not in stdout:
            continue
        for line in stdout.splitlines():
            if needle in line:
                return True, line.strip()[:_CRASH_REASON_MAX]
    return False, ""


def _classify_outcome(
    rc: int,
    host_panic: bool,
    prover_status: str,
    has_failures: bool,
) -> Tuple[MutationOutcome, dict]:
    """Option C prover_status-primary tree (IV_POS_8_D2_C_SPEC.md §6.1)."""
    if rc == 124:
        return MutationOutcome.ERROR, {}
    if prover_status == "success" and not host_panic:
        return MutationOutcome.APPLIED, {"soundness_signal": True}
    if prover_status == "error" and has_failures:
        return MutationOutcome.APPLIED, {}
    if prover_status == "error" and not has_failures:
        return MutationOutcome.APPLIED, {"failure_recording_gap": True}
    if prover_status == "start" and has_failures:
        return MutationOutcome.APPLIED, {}
    if prover_status == "start" and host_panic:
        return MutationOutcome.SKIPPED, {}
    return MutationOutcome.ERROR, {}


def _cap_raw_stdout(stdout: str) -> str:
    if len(stdout) <= _RAW_STDOUT_TAIL_BYTES:
        return stdout
    return stdout[-_RAW_STDOUT_TAIL_BYTES:]


def run(
    host: str,
    host_args: list[str],
    step: int,
    kind: str,
    seed: int,
    *,
    timeout: float = 90.0,
    env: Optional[dict] = None,
    include_trace: bool = False,
) -> ArguzzInvocationResult:
    """Invoke risc0-host --inject and parse/classify the combined output."""
    cmd = [host]
    if include_trace:
        cmd.append("--trace")
    cmd.extend(
        [
            "--inject",
            "--inject-step",
            str(step),
            "--inject-kind",
            kind,
            "--seed",
            str(seed),
            *host_args,
        ]
    )
    subprocess_env = {**os.environ, "CONSTRAINT_CONTINUE": "1"}
    if env:
        subprocess_env.update(env)

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            env=subprocess_env,
        )
        rc = proc.returncode
        stdout = _decode_safe(proc.stdout) + _decode_safe(proc.stderr)
    except subprocess.TimeoutExpired:
        rc = 124
        stdout = ""
    except Exception as exc:
        rc = 125
        stdout = (
            "<v6_driver_subprocess_error>"
            + type(exc).__name__
            + ": "
            + str(exc)
            + "</v6_driver_subprocess_error>"
        )
    wall_s = time.time() - t0

    faults = parse_all_faults(stdout)
    traces = parse_all_traces(stdout)
    failures = parse_all_constraint_failures(stdout)
    family_residues = parse_family_residues(stdout) or []
    family_details = parse_family_detail(stdout) or []
    global_residue = parse_global_residue(stdout) or {}
    prover_status, _ = parse_prover_status(stdout)
    host_panic, crash_reason = _detect_host_panic(stdout)
    outcome, extra_tags = _classify_outcome(
        rc,
        host_panic,
        prover_status,
        has_failures=len(failures) > 0,
    )

    return ArguzzInvocationResult(
        rc=rc,
        outcome=outcome,
        prover_status=prover_status,
        wall_s=wall_s,
        faults=faults,
        failures=failures,
        family_residues=family_residues,
        family_details=family_details,
        global_residue=global_residue,
        host_panic=host_panic,
        crash_reason=crash_reason,
        traces=traces,
        soundness_signal=bool(extra_tags.get("soundness_signal")),
        extra_tags=extra_tags,
        raw_stdout=_cap_raw_stdout(stdout),
    )


__all__ = [
    "ArguzzFault",
    "ArguzzInvocationResult",
    "ArguzzTrace",
    "ConstraintFailure",
    "parse_family_detail",
    "parse_family_residues",
    "parse_global_residue",
    "parse_prover_status",
    "run",
    "_classify_outcome",
    "_decode_safe",
    "_detect_host_panic",
]
