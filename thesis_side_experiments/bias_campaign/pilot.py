#!/usr/bin/env python3
"""C1 pilot driver — both fuzzers × 6 aligned kinds × N seeds."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "c1"
LOG_DIR = ART / "logs"
CFG_DIR = ART / "configs"
DB_PATH = ART / "pilot.db"
HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")
PRODUCTION_HOST = HOST
GUEST_ARGS = ["--in1", "5", "--in4", "10"]
GUEST_NAME = "c0c1"
MAX_WORKERS = 6

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.inspection_data import InspectionData  # noqa: E402

from thesis_side_experiments.bias_campaign.a4_config import build_a4_config  # noqa: E402
from thesis_side_experiments.bias_campaign.campaign_db import CampaignDB  # noqa: E402
from thesis_side_experiments.bias_campaign.guest_sites import ensure_guest_sites, sample_eligible_step  # noqa: E402
from thesis_side_experiments.bias_campaign.run_a4 import run_a4  # noqa: E402
from thesis_side_experiments.bias_campaign.run_arguzz import run_arguzz  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import (  # noqa: E402
    ALIGNED_KINDS,
    PILOT_SEEDS,
    RunRecord,
    build_run_record,
)
from thesis_side_experiments.bias_campaign.classify import classify_run  # noqa: E402

A4_ELIGIBLE_KEY = {
    "PRE_EXEC_REG_MOD": "PRE_EXEC_REG_MOD",
    "COMP_OUT_MOD": "COMP_OUT_MOD",
    "LOAD_VAL_MOD": "LOAD_VAL_MOD",
    "STORE_OUT_MOD": "STORE_OUT_MOD",
    "MEM_VAL_MOD": "PRE_EXEC_MEM_MOD",
    "INSTR_WORD_MOD_FULL": "INSTR_WORD_MOD",
}


def existing_run_keys(db_path: Path) -> set[tuple[str, str, int]]:
    if not db_path.exists():
        return set()
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT fuzzer, kind, seed FROM runs").fetchall()
    conn.close()
    return {(f, k, s) for f, k, s in rows}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_rev() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT.parent.parent, text=True
        ).strip()
    except Exception:
        return "unknown"


def probe_production_error_behavior() -> dict:
    """Empirical: how production host behaves on known rejections."""
    from thesis_side_experiments.bias_campaign.guest_sites import sample_eligible_step

    sites = ensure_guest_sites(HOST, GUEST_ARGS, ART / "guest_sites.json")
    notes = {}

    # Arguzz s9 @ step from verify_crash on minimal was seed 0 step 187 - use first compute step here
    step = sample_eligible_step("PRE_EXEC_REG_MOD", 0, sites) or 200
    rec = run_arguzz(
        str(HOST),
        GUEST_ARGS,
        "PRE_EXEC_REG_MOD",
        step,
        0,
        log_path=ART / "probe_arguzz.txt",
    )
    notes["arguzz_sample"] = {
        "step": step,
        "outcome": rec.outcome.outcome_class,
        "panic_loc": rec.outcome.panic_loc,
        "host_panic": rec.outcome.host_panic,
        "prover_crash": rec.outcome.prover_crash,
        "fail_count": len(rec.outcome.failures),
    }

    data = InspectionData.from_inspection(str(HOST), GUEST_ARGS)
    offset = sites["arguzz_to_a4_step_offset"]
    cfg = CFG_DIR / "probe_a4.json"
    built = build_a4_config("PRE_EXEC_REG_MOD", step, 1, data, cfg, offset)
    if built:
        path, desc = built
        a4rec = run_a4(
            str(HOST),
            GUEST_ARGS,
            path,
            target_desc=desc,
            inject_step=step,
            kind="PRE_EXEC_REG_MOD",
            seed=1,
            log_path=ART / "probe_a4.txt",
        )
        notes["a4_sample"] = {
            "outcome": a4rec.outcome.outcome_class,
            "panic_loc": a4rec.outcome.panic_loc,
            "host_panic": a4rec.outcome.host_panic,
            "fail_count": len(a4rec.outcome.failures),
        }
    return notes


def run_one(job: dict) -> RunRecord:
    fuzzer = job["fuzzer"]
    a4_kind = job["a4_kind"]
    arguzz_kind = job["arguzz_kind"]
    seed = job["seed"]
    kind = a4_kind if fuzzer == "a4" else arguzz_kind
    log_path = LOG_DIR / f"{fuzzer}_{kind}_{seed}.txt"

    if fuzzer == "arguzz":
        step = job["step"]
        if step is None:
            rec = build_run_record(
                fuzzer, GUEST_NAME, kind, seed, None, "",
                classify_run("", target_step=step), 0, str(log_path),
            )
            rec.skipped = True
            rec.skip_reason = "no eligible step"
            return rec
        return run_arguzz(str(HOST), GUEST_ARGS, arguzz_kind, step, seed, log_path=log_path)

    # A4 — retry up to 10 eligible steps (not just consecutive offsets)
    step = job["step"]
    data = job["data"]
    offset = job["offset"]
    eligible = job["eligible_steps"]
    if not eligible:
        eligible = [step] if step is not None else []
    for attempt in range(min(10, len(eligible) or 1)):
        try_step = eligible[(seed + attempt) % len(eligible)] if eligible else step
        cfg = CFG_DIR / f"a4_{a4_kind}_{seed}_{try_step}.json"
        built = build_a4_config(a4_kind, try_step, seed + attempt, data, cfg, offset)
        if built is None:
            continue
        path, desc = built
        return run_a4(
            str(HOST),
            GUEST_ARGS,
            path,
            target_desc=desc,
            inject_step=try_step,
            kind=a4_kind,
            seed=seed,
            log_path=log_path,
        )
    rec = build_run_record(
        fuzzer, GUEST_NAME, a4_kind, seed, step, "",
        classify_run("", injected_override=False), 0, str(log_path),
    )
    rec.skipped = True
    rec.skip_reason = "no valid A4 target"
    return rec


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    CFG_DIR.mkdir(parents=True, exist_ok=True)

    if not HOST.exists():
        raise SystemExit(f"missing production host: {HOST}")

    host_sha_before = file_sha256(HOST)
    mtime_before = HOST.stat().st_mtime
    t0 = time.time()

    sites = ensure_guest_sites(HOST, GUEST_ARGS, ART / "guest_sites.json")
    offset = sites["arguzz_to_a4_step_offset"]
    probe_path = ART / "production_error_probe.json"
    if probe_path.exists():
        probe = json.loads(probe_path.read_text())
    else:
        probe = probe_production_error_behavior()
        probe_path.write_text(json.dumps(probe, indent=2))

    print("Loading InspectionData (one-time)…", flush=True)
    data = InspectionData.from_inspection(str(HOST), GUEST_ARGS)

    jobs = []
    for a4_kind, arguzz_kind in ALIGNED_KINDS:
        eligible_arguzz = sites["eligible_steps_by_kind"].get(arguzz_kind, [])
        eligible_a4 = sites["eligible_steps_by_kind"].get(A4_ELIGIBLE_KEY[a4_kind], [])
        for seed in PILOT_SEEDS:
            step = sample_eligible_step(arguzz_kind, seed, sites)
            jobs.append(
                {
                    "fuzzer": "arguzz",
                    "a4_kind": a4_kind,
                    "arguzz_kind": arguzz_kind,
                    "seed": seed,
                    "step": step,
                }
            )
            jobs.append(
                {
                    "fuzzer": "a4",
                    "a4_kind": a4_kind,
                    "arguzz_kind": arguzz_kind,
                    "seed": seed,
                    "step": step,
                    "data": data,
                    "offset": offset,
                    "eligible_steps": eligible_a4,
                }
            )

    done_keys = existing_run_keys(DB_PATH)
    pending = []
    for j in jobs:
        kind = j["a4_kind"] if j["fuzzer"] == "a4" else j["arguzz_kind"]
        if (j["fuzzer"], kind, j["seed"]) in done_keys:
            continue
        pending.append(j)

    db = CampaignDB(DB_PATH)
    if not pending:
        print(f"All {len(jobs)} jobs already in {DB_PATH}", flush=True)
    else:
        print(
            f"Running {len(pending)} pending jobs ({len(done_keys)} already done) "
            f"with {MAX_WORKERS} workers…",
            flush=True,
        )
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(run_one, j): j for j in pending}
            done = len(done_keys)
            total = len(jobs)
            for fut in as_completed(futs):
                rec = fut.result()
                db.insert_run(rec)
                done += 1
                if done % 20 == 0 or done == total:
                    print(f"  {done}/{total}", flush=True)

    db.close()
    meta = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "host": str(HOST),
        "host_sha256": host_sha_before,
        "guest_args": GUEST_ARGS,
        "seeds": PILOT_SEEDS,
        "aligned_kinds": ALIGNED_KINDS,
        "arguzz_to_a4_step_offset": offset,
        "git_rev": git_rev(),
        "runtime_seconds": round(time.time() - t0, 2),
        "job_count": len(jobs),
        "production_error_probe": probe,
    }
    (ART / "pilot_meta.json").write_text(json.dumps(meta, indent=2))

    host_sha_after = file_sha256(HOST)
    if host_sha_after != host_sha_before or HOST.stat().st_mtime != mtime_before:
        raise SystemExit("production host changed during pilot")
    print(f"Done in {meta['runtime_seconds']}s — {DB_PATH}", flush=True)


if __name__ == "__main__":
    main()
