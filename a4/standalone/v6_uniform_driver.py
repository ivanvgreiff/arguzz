#!/usr/bin/env python3
"""V6-uniform driver — D2.C modernized successor to v6_driver_v2.py.

Uses ``arguzz_invoke.run()`` + ``CoverageDB`` (no inline SQL).
``ArguzzScheduler`` + bootstrap copied verbatim from ``v6_driver_v2.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from random import Random

from a4.core.inspection_data import InspectionData
from a4.runs.iv_pos_7.drivers.v6_driver_v2 import (
    ArguzzScheduler,
    capture_baseline_trace,
    normalize_instr,
    parse_trace_steps,
)
from a4.standalone.compressed_global_extractor import (
    extract_compressed_global_contexts,
    to_storage_rows,
)
from a4.standalone.mutations.arguzz_bridge import (
    MAPPING_INSTR_TO_OPCODE_CLASS,
    _PRE_POST_BY_KIND,
    create_mutation_for_arm,
)
from a4.standalone.coverage_db import CoverageDB
from a4.standalone.semantic_arm_universe import ARGUZZ_EXEC_FAULT, ArmKey
from a4.standalone.zone_classifier import classify_zones

logger = logging.getLogger("a4.v6_uniform_driver")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _global_contexts_from_family_details(family_details: list) -> list[tuple[str, str, str]]:
    """Build (GLOBAL, family, address) tuples from Hook-3 family_details."""
    if not family_details:
        return []
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for fdi in family_details:
        fam = fdi.get("family", "?")
        items = fdi.get("broken_addrs", []) or fdi.get("broken_indices", []) or []
        for raw in items:
            try:
                if isinstance(raw, dict):
                    addr = int(
                        raw.get("addr")
                        or raw.get("byte_addr")
                        or raw.get("address")
                        or raw.get("index")
                        or raw.get("idx")
                        or raw.get("lookup_index")
                        or 0
                    )
                else:
                    addr = int(raw)
            except (TypeError, ValueError):
                continue
            key = (fam, str(addr))
            if key in seen:
                continue
            seen.add(key)
            out.append(("GLOBAL", fam, str(addr)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--num", type=int, required=True)
    ap.add_argument("--progress-every", type=int, default=100)
    ap.add_argument("--label", default="v6_arguzz")
    ap.add_argument("host_args", nargs="*", help="passed after `--` to host")
    args = ap.parse_args()

    print(f"=== V6-uniform driver start  seed={args.seed} num={args.num}  {now_iso()} ===")
    print(f"host: {args.host}")
    print(f"host_args: {args.host_args}")
    print(f"db: {args.db}")

    # Bootstrap (a): baseline trace — verbatim from v6_driver_v2.py
    print("\n--- bootstrap (a): baseline trace via `host --trace` ---")
    rc, out, wall = capture_baseline_trace(args.host, args.host_args)
    print(f"  rc={rc} wall={wall:.2f}s out_bytes={len(out)}")
    if rc != 0:
        print(f"  ERROR: baseline trace returned {rc}")
        sys.exit(2)
    trace = parse_trace_steps(out)
    if not trace:
        print("  ERROR: no <trace> tags parsed")
        sys.exit(2)
    instr_to_steps: dict[str, list[int]] = {}
    for step, _pc, instr, _asm in trace:
        norm = normalize_instr(instr)
        instr_to_steps.setdefault(norm, []).append(step)
    print(f"  trace: {len(trace)} steps across {len(instr_to_steps)} instr kinds")

    # Bootstrap (b): InspectionData
    print("\n--- bootstrap (b): InspectionData via A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 ---")
    t_b = time.time()
    insp = InspectionData.from_inspection(args.host, list(args.host_args))
    print(f"  wall={time.time() - t_b:.2f}s  total_steps={insp.total_steps}  cycles={len(insp.cycles)}")
    if not insp.cycles:
        print("  ERROR: InspectionData has no cycles")
        sys.exit(2)

    # Zone classification
    print("\n--- step_to_zone via classify_zones(InspectionData) ---")
    step_to_zone = classify_zones(insp)
    print(f"  classified={len(step_to_zone)} steps")

    rng = Random(args.seed)
    sched = ArguzzScheduler(instr_to_steps, rng)
    print(f"\n  scheduler ready: {len(sched._candidate_instrs)} candidate instr kinds")

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(args.db):
        os.remove(args.db)

    db = CoverageDB(args.db)
    campaign_id = db.start_campaign(args.host, list(args.host_args), args.label, args.seed)
    db.record_campaign_params(
        campaign_id,
        selector="arguzz_balanced_rr",
        extra={
            "num": args.num,
            "scheduler": "balanced_round_robin",
            "driver_version": "v3_d2c",
            "compressed_extractor": "a4.compressed_global_extractor",
            "primitive": "a4.standalone.arguzz_invoke",
        },
    )

    print(f"\n--- begin {args.num} arguzz mutations ---")
    t_start = time.time()
    outcomes: dict[str, int] = {}

    for i in range(1, args.num + 1):
        instr, step, kind = sched.pick()
        iter_seed = args.seed * 1_000_000 + i

        zone = step_to_zone.get(step, "core_other")
        norm_instr = normalize_instr(instr)
        opcode_class = MAPPING_INSTR_TO_OPCODE_CLASS.get(norm_instr, "system")
        arm = ArmKey(
            ARGUZZ_EXEC_FAULT,
            kind,
            zone,
            opcode_class,
            _PRE_POST_BY_KIND[kind],
        )
        _outcome, result, bridge_config = create_mutation_for_arm(
            arm,
            step,
            args.host,
            list(args.host_args),
            iter_seed,
            insp,
            timeout=90.0,
        )

        cycle = insp.get_cycle(step)
        major = cycle.major if cycle is not None else 0

        config = {
            **bridge_config,
            "instruction": instr,
            "iter_seed": iter_seed,
            "wall_s": round(result.wall_s, 3),
            "rc": result.rc,
            "prover_status": result.prover_status,
            "outcome": result.outcome.value,
            "zone": zone,
            "major": major,
        }
        if result.soundness_signal:
            config["soundness_signal"] = True
            logger.warning(
                "prove_success while applied at step=%d kind=%s zone=%s — possible soundness signal",
                step, kind, zone,
            )
        if result.extra_tags.get("failure_recording_gap"):
            config["failure_recording_gap"] = True

        mutation_id = db.record_mutation(
            campaign_id,
            kind,
            step,
            0,
            config,
            txn_idx=None,
            verifier_accepted=(result.prover_status == "success"),
            original_value=0,
            proof_generated=(result.prover_status != "none"),
            proof_verify_failed=(
                result.prover_status == "error" and len(result.failures) > 0
            ),
            elapsed_ms=int(result.wall_s * 1000),
            outcome=result.outcome.value,
        )

        _, new_cov = db.record_failures(mutation_id, result.failures)
        global_ctxs = _global_contexts_from_family_details(result.family_details)
        if global_ctxs:
            db.record_global_failures(mutation_id, global_ctxs)

        ctxs = extract_compressed_global_contexts(
            family_residues=result.family_residues,
            family_details=result.family_details,
            mutation_kind=kind,
            mutation_zone=zone,
            mutation_major=major,
        )
        for ctx_key, fam, ctx_json in to_storage_rows(ctxs):
            db.record_compressed_global_first_hit(
                campaign_id, mutation_id, ctx_key, fam, ctx_json,
            )

        outcomes[result.outcome.value] = outcomes.get(result.outcome.value, 0) + 1

        if i % args.progress_every == 0 or i == args.num:
            elapsed = time.time() - t_start
            rate = i / elapsed if elapsed > 0 else 0.0
            eta = (args.num - i) / rate if rate > 0 else 0.0
            print(
                f"  [{i:>5}/{args.num}] elapsed={elapsed:.1f}s rate={rate:.2f}it/s "
                f"eta={eta/60:.1f}min  new_cov={new_cov} out={outcomes}",
                flush=True,
            )

    db.end_campaign(campaign_id)
    db.close()
    elapsed = time.time() - t_start
    print(f"\n=== V6-uniform DONE  total_wall={elapsed:.1f}s  {now_iso()} ===")
    print(f"db: {args.db}")
    print(f"outcomes: {outcomes}")


if __name__ == "__main__":
    main()
