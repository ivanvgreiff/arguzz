"""Single A4 mutation runner."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

from thesis_side_experiments.bias_campaign.classify import classify_run
from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV, RunRecord, build_run_record

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData


def run_a4(
    host: str,
    guest_args: List[str],
    config_path: Path,
    target_desc: str = "",
    inject_step: Optional[int] = None,
    kind: str = "",
    seed: int = 0,
    extra_env: Optional[Dict[str, str]] = None,
    timeout: int = 300,
    log_path: Optional[Path] = None,
    fuzzer: str = "a4",
    guest: str = "c0c1",
) -> RunRecord:
    cmd = [host] + guest_args
    env = {
        **dict(os.environ),
        **DEFAULT_ENV,
        "A4_MUTATION_CONFIG": str(config_path),
    }
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

    outcome = classify_run(output, target_step=None, injected_override=True)
    return build_run_record(
        fuzzer=fuzzer,
        guest=guest,
        kind=kind,
        seed=seed,
        inject_step=inject_step,
        target_desc=target_desc,
        outcome=outcome,
        runtime_ms=runtime_ms,
        raw_log_path=str(log_path) if log_path else "",
    )


def run_a4_kind(
    host: str,
    guest_args: List[str],
    kind: str,
    arguzz_step: int,
    seed: int,
    data: "InspectionData",
    config_dir: Path,
    step_offset: int,
    log_path: Path,
    max_retries: int = 10,
) -> RunRecord:
    from thesis_side_experiments.bias_campaign.a4_config import build_a4_config

    for attempt in range(max_retries):
        step = arguzz_step + attempt  # try nearby steps if target missing
        cfg_path = config_dir / f"a4_{kind}_{seed}_{step}.json"
        built = build_a4_config(kind, step, seed + attempt, data, cfg_path, step_offset)
        if built is None:
            continue
        path, desc = built
        return run_a4(
            host,
            guest_args,
            path,
            target_desc=desc,
            inject_step=step,
            kind=kind,
            seed=seed,
            log_path=log_path,
        )
    rec = build_run_record(
        fuzzer="a4",
        guest="c0c1",
        kind=kind,
        seed=seed,
        inject_step=arguzz_step,
        target_desc="",
        outcome=classify_run("", target_step=None, injected_override=False),
        runtime_ms=0,
        raw_log_path=str(log_path),
    )
    rec.skipped = True
    rec.skip_reason = "no valid A4 target after retries"
    return rec
