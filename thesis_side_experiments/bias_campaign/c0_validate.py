#!/usr/bin/env python3
"""C0 validation matrix — prove primitives against minimal_add ground truth."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
MINIMAL = ROOT.parent / "minimal_add"
ART = ROOT / "artifacts" / "c0"
HOST = MINIMAL / "target/release/thesis-minimal-host"
PRODUCTION_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")
M2_CONFIG = MINIMAL / "artifacts/m2/a4_mutation.json"
ADD_SITE = MINIMAL / "artifacts/m0/add_site.json"
ADD_UNIVERSE = MINIMAL / "artifacts/m1/add_local_universe.json"

sys.path.insert(0, str(ROOT.parent.parent))

from thesis_side_experiments.bias_campaign.categorize import (  # noqa: E402
    categorize_failures,
    categorize_touched,
    global_failed,
    mem_zir_loc_matches,
)
from thesis_side_experiments.bias_campaign.classify import RunOutcome, classify_run  # noqa: E402
from thesis_side_experiments.bias_campaign.run_a4 import DEFAULT_ENV, run_a4  # noqa: E402
from thesis_side_experiments.bias_campaign.run_arguzz import run_arguzz  # noqa: E402
from thesis_side_experiments.bias_campaign.touch_parse import (  # noqa: E402
    filter_by_context,
    parse_accum_verbose_set,
    parse_local_verbose_set,
)

BABYBEAR_P = 2013265921
P_MINUS_5 = BABYBEAR_P - 5
ARGUZZ_ADD_STEP = 187
EXPECTED_LOCAL_CONTEXTS = 37


def production_host_mtime() -> float:
    return PRODUCTION_HOST.stat().st_mtime if PRODUCTION_HOST.exists() else -1.0


def failure_fingerprint(outcome: RunOutcome) -> List[Tuple]:
    seen: Set[Tuple] = set()
    rows = []
    for f in outcome.failures:
        key = (f.loc, f.major, f.minor, f.phase, f.value)
        if key in seen:
            continue
        seen.add(key)
        rows.append(key)
    return sorted(rows)


def dedupe_failures(outcome: RunOutcome) -> List[dict]:
    seen: Set[Tuple] = set()
    out = []
    for f in outcome.failures:
        key = (f.loc, f.major, f.minor, f.phase)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "loc": f.loc,
                "major": f.major,
                "minor": f.minor,
                "phase": f.phase,
                "value": f.value,
                "category": categorize_failure_loc_phase(f.loc, f.phase),
            }
        )
    return sorted(out, key=lambda x: x["loc"])


def categorize_failure_loc_phase(loc: str, phase: str) -> str:
    from thesis_side_experiments.bias_campaign.categorize import categorize_failure

    return categorize_failure(loc, phase)


def summarize_outcome(name: str, outcome: RunOutcome, extra: Optional[dict] = None) -> dict:
    fail_cats = categorize_failures(outcome.failures)
    g = global_failed(outcome.family_residues, outcome.global_residue)
    row = {
        "case": name,
        "outcome_class": outcome.outcome_class,
        "injected": outcome.injected,
        "fault": outcome.fault,
        "fail_category_counts": fail_cats,
        "global_families": {k: g[k] for k in ("memory", "u16", "u8", "cycle", "any")},
        "failure_count_raw": len(outcome.failures),
        "failures_deduped": dedupe_failures(outcome),
        "verifier_success": outcome.verifier_success,
        "preflight_crash": outcome.preflight_crash,
        "panic_loc": outcome.panic_loc,
        "fingerprint": failure_fingerprint(outcome),
    }
    if extra:
        row.update(extra)
    return row


def run_baseline() -> RunOutcome:
    env = {**dict(os.environ), **DEFAULT_ENV}
    proc = subprocess.run(
        [str(HOST)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    return classify_run(proc.stdout + proc.stderr, target_step=None)


def run_case_twice(run_fn) -> Tuple[RunOutcome, RunOutcome, bool]:
    a = run_fn()
    b = run_fn()
    fa = failure_fingerprint(a)
    fb = failure_fingerprint(b)
    det = (
        a.outcome_class == b.outcome_class
        and fa == fb
        and a.global_nonzero == b.global_nonzero
    )
    return a, b, det


def check_a4_a1(outcome: RunOutcome) -> List[str]:
    errors = []
    if outcome.outcome_class != "CONSTRAINT_REJECT":
        errors.append(f"expected CONSTRAINT_REJECT, got {outcome.outcome_class}")
    cats = categorize_failures(outcome.failures)
    if cats["L1"] != 0:
        errors.append(f"expected L1=0, got {cats['L1']}")
    if cats["ACCUM"] != 0:
        errors.append(f"expected ACCUM=0, got {cats['ACCUM']}")
    if cats["L2"] != 2:
        errors.append(f"expected L2=2, got {cats['L2']}")

    l2 = [f for f in dedupe_failures(outcome) if f["category"] == "L2"]
    isread = next((f for f in l2 if mem_zir_loc_matches(f["loc"], "IsRead@mem.zir:79")), None)
    memwrite = next((f for f in l2 if mem_zir_loc_matches(f["loc"], "MemoryWrite@mem.zir:99")), None)
    if not isread:
        errors.append("missing IsRead@79 failure")
    elif isread["value"] != P_MINUS_5:
        errors.append(f"IsRead value {isread['value']} != {P_MINUS_5}")
    if not memwrite:
        errors.append("missing MemoryWrite@99 failure")
    elif memwrite["value"] != P_MINUS_5:
        errors.append(f"MemoryWrite value {memwrite['value']} != {P_MINUS_5}")

    g = global_failed(outcome.family_residues, outcome.global_residue)
    if not g["memory"]:
        errors.append("expected G memory family nonzero")
    return errors


def check_targeting(outcome: RunOutcome) -> Tuple[dict, List[str]]:
    errors = []
    add_site = json.loads(ADD_SITE.read_text())
    major, minor = add_site["major"], add_site["minor"]
    local = parse_local_verbose_set(outcome.combined_output)
    accum = parse_accum_verbose_set(outcome.combined_output)
    if local is None:
        errors.append("missing <a4_touch_verbose>")
        return {}, errors
    if accum is None:
        errors.append("missing <a4_accum_touch_verbose>")
        return {}, errors

    add_keys = filter_by_context(local, major, minor)
    target_cats = categorize_touched(add_keys, [])
    expected = json.loads(ADD_UNIVERSE.read_text())
    if len(add_keys) != EXPECTED_LOCAL_CONTEXTS:
        errors.append(f"expected {EXPECTED_LOCAL_CONTEXTS} local contexts, got {len(add_keys)}")
    if len(expected) != EXPECTED_LOCAL_CONTEXTS:
        errors.append(f"universe file has {len(expected)} entries")

    info = {
        "local_context_count": len(add_keys),
        "target_L1": target_cats["L1"],
        "target_L2": target_cats["L2"],
        "accum_universe_total": len(accum),
        "matches_m1_universe_count": len(add_keys) == EXPECTED_LOCAL_CONTEXTS,
    }
    return info, errors


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    mtime_before = production_host_mtime()

    if not HOST.exists():
        raise SystemExit(f"missing minimal host: {HOST}")
    if not M2_CONFIG.exists():
        raise SystemExit(f"missing M2 config: {M2_CONFIG}")

    # Unit tests
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "thesis_side_experiments.bias_campaign.test_categorize"
    )
    test_result = unittest.TextTestRunner(verbosity=0).run(suite)
    unit_ok = test_result.wasSuccessful()

    cases: Dict[str, Any] = {}
    determinism: Dict[str, bool] = {}
    gate_errors: List[str] = []

    # baseline
    base_a, base_b, base_det = run_case_twice(run_baseline)
    determinism["baseline"] = base_det
    cases["baseline"] = summarize_outcome("baseline", base_a)
    if base_a.outcome_class != "VALID_NO_SIGNAL":
        gate_errors.append(f"baseline outcome {base_a.outcome_class} != VALID_NO_SIGNAL")
    if not base_a.verifier_success:
        gate_errors.append("baseline verifier not success")
    if base_a.failures:
        gate_errors.append(f"baseline has {len(base_a.failures)} failures")

    # A4-a1
    def run_a4_a1():
        return run_a4(str(HOST), [], M2_CONFIG).outcome

    a4_a, a4_b, a4_det = run_case_twice(run_a4_a1)
    determinism["A4-a1"] = a4_det
    targeting, targ_errs = check_targeting(a4_a)
    a4_errs = check_a4_a1(a4_a)
    cases["A4-a1"] = summarize_outcome("A4-a1", a4_a, {"targeting": targeting})
    gate_errors.extend(a4_errs)
    gate_errors.extend(targ_errs)

    # Arguzz-a1
    def run_arguzz_a1():
        return run_arguzz(str(HOST), [], "PRE_EXEC_REG_MOD", ARGUZZ_ADD_STEP, 32).outcome

    az_a1_a, az_a1_b, az_a1_det = run_case_twice(run_arguzz_a1)
    determinism["Arguzz-a1"] = az_a1_det
    cases["Arguzz-a1"] = summarize_outcome("Arguzz-a1", az_a1_a)
    if az_a1_a.outcome_class != "PREFLIGHT_CRASH":
        gate_errors.append(f"Arguzz-a1 outcome {az_a1_a.outcome_class} != PREFLIGHT_CRASH")
    if not az_a1_a.preflight_crash:
        gate_errors.append("Arguzz-a1 preflight_crash not set")
    elif "preflight.rs:227" not in (az_a1_a.panic_loc or ""):
        gate_errors.append(f"Arguzz-a1 panic_loc {az_a1_a.panic_loc!r} missing :227")
    if az_a1_a.failures:
        gate_errors.append(f"Arguzz-a1 has {len(az_a1_a.failures)} failures")

    # Arguzz-s9
    def run_arguzz_s9():
        return run_arguzz(str(HOST), [], "PRE_EXEC_REG_MOD", ARGUZZ_ADD_STEP, 0).outcome

    az_s9_a, az_s9_b, az_s9_det = run_case_twice(run_arguzz_s9)
    determinism["Arguzz-s9"] = az_s9_det
    cases["Arguzz-s9"] = summarize_outcome("Arguzz-s9", az_s9_a)
    if az_s9_a.outcome_class != "CONSTRAINT_REJECT":
        gate_errors.append(f"Arguzz-s9 outcome {az_s9_a.outcome_class} != CONSTRAINT_REJECT")
    if len(cases["Arguzz-s9"]["failures_deduped"]) != 7:
        gate_errors.append(
            f"Arguzz-s9 deduped failure count {len(cases['Arguzz-s9']['failures_deduped'])} != 7"
        )

    if not all(determinism.values()):
        gate_errors.append(f"determinism failed: {determinism}")

    mtime_after = production_host_mtime()
    isolation_ok = mtime_before == mtime_after

    acceptance = {
        "unit_tests_pass": unit_ok,
        "A4_a1_M2_match": not a4_errs,
        "arguzz_a1_preflight_crash": az_a1_a.outcome_class == "PREFLIGHT_CRASH",
        "arguzz_s9_constraint_reject_7": (
            az_s9_a.outcome_class == "CONSTRAINT_REJECT"
            and len(cases["Arguzz-s9"]["failures_deduped"]) == 7
        ),
        "targeting_37_contexts": targeting.get("local_context_count") == EXPECTED_LOCAL_CONTEXTS,
        "determinism_all_cases": all(determinism.values()),
        "production_host_mtime_unchanged": isolation_ok,
        "all_pass": False,
    }
    acceptance["all_pass"] = (
        unit_ok
        and not gate_errors
        and isolation_ok
    )

    report = {
        "milestone": "C0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "host": str(HOST),
        "runtime_seconds": round(time.time() - t0, 2),
        "acceptance": acceptance,
        "determinism": determinism,
        "cases": cases,
        "gate_errors": gate_errors,
        "isolation": {
            "production_host": str(PRODUCTION_HOST),
            "mtime_before": mtime_before,
            "mtime_after": mtime_after,
            "unchanged": isolation_ok,
        },
    }

    (ART / "C0_REPORT.json").write_text(json.dumps(report, indent=2))

    md = [
        "# C0 Report — Parity Harness + Category Classifier",
        "",
        f"**Status:** {'PASS' if acceptance['all_pass'] else 'FAIL'}",
        "",
        f"Runtime: {report['runtime_seconds']}s",
        "",
        "## Acceptance gate",
    ]
    for k, v in acceptance.items():
        md.append(f"- **{k}**: {v}")
    if gate_errors:
        md.append("")
        md.append("### Gate errors")
        for e in gate_errors:
            md.append(f"- {e}")
    md.append("")
    md.append("## Cases")
    for name, case in cases.items():
        md.append(f"### {name}")
        md.append(f"- outcome: **{case['outcome_class']}**")
        md.append(f"- FAIL categories: {case['fail_category_counts']}")
        md.append(f"- G families: {case['global_families']}")
        if case.get("targeting"):
            md.append(f"- TARGET (add local): {case['targeting']}")
        if case["failures_deduped"]:
            md.append("- failures:")
            for f in case["failures_deduped"]:
                md.append(f"  - [{f['category']}] `{f['loc'][:70]}…` value={f['value']}" if len(f["loc"]) > 70 else f"  - [{f['category']}] `{f['loc']}` value={f['value']}")
        md.append(f"- determinism 2×: **{determinism.get(name, 'n/a')}**")
        md.append("")
    md.append("## Isolation")
    md.append(f"- production `risc0-host` mtime unchanged: **{isolation_ok}**")
    (ART / "C0_REPORT.md").write_text("\n".join(md) + "\n")

    print((ART / "C0_REPORT.md").read_text())
    if not acceptance["all_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
