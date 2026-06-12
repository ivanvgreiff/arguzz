"""Single Arguzz injection runner."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from thesis_side_experiments.bias_campaign.classify import classify_run
from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV, RunRecord, build_run_record


def run_arguzz(
    host: str,
    guest_args: List[str],
    kind: str,
    step: int,
    seed: int,
    extra_env: Optional[Dict[str, str]] = None,
    timeout: int = 300,
    log_path: Optional[Path] = None,
    fuzzer: str = "arguzz",
    guest: str = "c0c1",
) -> RunRecord:
    cmd = [
        host,
        "--trace",
        "--inject",
        "--inject-step",
        str(step),
        "--inject-kind",
        kind,
        "--seed",
        str(seed),
    ] + guest_args

    env = {**dict(os.environ), **DEFAULT_ENV}
    if extra_env:
        env.update(extra_env)

    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    runtime_ms = int((time.perf_counter() - t0) * 1000)
    output = proc.stdout + proc.stderr

    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(output)

    outcome = classify_run(output, target_step=step)
    target_desc = ""
    if outcome.fault:
        reg = outcome.fault.get("register", "")
        target_desc = f"{reg}={outcome.fault.get('value')} @step={step}" if reg else str(outcome.fault)

    return build_run_record(
        fuzzer=fuzzer,
        guest=guest,
        kind=kind,
        seed=seed,
        inject_step=step,
        target_desc=target_desc,
        outcome=outcome,
        runtime_ms=runtime_ms,
        raw_log_path=str(log_path) if log_path else "",
    )
