#!/usr/bin/env python3
"""D2.B Batch 3 — CYCLE_STATE_MOD attestation (PREDICTED DEAD / W-17)."""

from __future__ import annotations

import hashlib
import os
import random
import subprocess
import tempfile
from pathlib import Path

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.touch_coverage import parse_family_residues
from a4.core.trace_parser import parse_all_a4_cycles, parse_cycle_state_mod, parse_post_mut_cycle_dump
from a4.standalone.mutations.cycle_state_mod import (
    CycleStateModTarget,
    create_config,
    generate_new_value,
    get_targets_at_step,
)
from a4.standalone.tests._test_helpers.diff_signature import (
    SoundnessBugSuspected,
    assert_cycle_diff_matches_signature,
    check_soundness_bug_guard,
    collect_cycle_field_diffs,
)


def _host_binary() -> str:
    return os.environ.get("A4_TEST_HOST", "workspace/output/target/release/risc0-host").strip()


def _host_args() -> list[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    return raw.split() if raw else []


def _run_host(env_extra: dict[str, str], config_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [_host_binary()] + _host_args()
    env = {**os.environ, **env_extra}
    if config_path is not None:
        config_bytes = config_path.read_bytes()
        env["A4_MUTATION_CONFIG"] = str(config_path)
        env["A4_MUTATION_SHA256"] = hashlib.sha256(config_bytes).hexdigest()
        env.setdefault("CONSTRAINT_CONTINUE", "1")
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def _verifier_accepted(output: str) -> bool:
    return '"context":"Verifier"' in output and '"status":"success"' in output


def _find_target(data: InspectionData) -> CycleStateModTarget:
    for step in data.get_valid_steps_for_kind("CYCLE_STATE_MOD"):
        target = get_targets_at_step(step, data)
        if target is not None:
            return target
    raise AssertionError("no CYCLE_STATE_MOD target")


def _run_layers_2_3_4(target: CycleStateModTarget) -> None:
    new_state = generate_new_value(target, random.Random(42))
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = create_config(target, new_state, Path(tmp) / "mut.json")
        pre_out = _combined_output(_run_host({"A4_INSPECT": "1"}))
        pre_cycles = [
            {"cycle_idx": c.cycle_idx, "state": c.state, "pc": c.pc, "major": c.major, "minor": c.minor}
            for c in parse_all_a4_cycles(pre_out)
        ]
        mut_out = _combined_output(
            _run_host(
                {"A4_INSPECT": "1", "A4_DUMP_POST_MUT": "1", "A4_FAMILY_RESIDUE": "1"},
                cfg_path,
            )
        )

    tag = parse_cycle_state_mod(mut_out)[-1]
    assert tag.new_state == new_state
    center = next(d for d in parse_post_mut_cycle_dump(mut_out) if d.cycle_idx == target.cycle_idx)
    assert center.state == new_state

    post_by_idx = {d.cycle_idx: d for d in parse_post_mut_cycle_dump(mut_out)}
    pre_by_idx = {c["cycle_idx"]: c for c in pre_cycles}
    window = [{**pre_by_idx[i], "cycle_idx": i} for i in sorted(post_by_idx) if i in pre_by_idx]
    post_window = [
        {"cycle_idx": i, "state": post_by_idx[i].state, "pc": post_by_idx[i].pc,
         "major": post_by_idx[i].major, "minor": post_by_idx[i].minor}
        for i in sorted(post_by_idx) if i in pre_by_idx
    ]
    diffs = collect_cycle_field_diffs(window, post_window, fields=("state", "pc", "major", "minor"))
    assert_cycle_diff_matches_signature(
        diffs,
        {"primary": {"cycle_idx": target.cycle_idx, "field": "state", "old": target.original_state, "new": new_state}, "cascade": []},
    )

    broken_families = [fr["family"] for fr in (parse_family_residues(mut_out) or []) if fr.get("nonzero")]
    if "constraint_fail" in mut_out.lower() or "verify segment" in mut_out or broken_families:
        pytest.fail(
            "AUDIT FAILURE — RECONCILE REQUIRED: CYCLE_STATE_MOD showed live rejection; "
            "W-17 prediction falsified. See D2B_BATCH2_DEAD_ARM_AUDIT.md"
        )

    guard_fired = False
    try:
        check_soundness_bug_guard(
            mutation_applied=True, trace_changed=bool(diffs),
            constraint_failed="constraint_fail" in mut_out.lower(),
            error_emitted="<a4_error>" in mut_out,
            proof_verify_failed="verify segment" in mut_out,
            broken_families_nonzero=bool(broken_families),
            verifier_accepted=_verifier_accepted(mut_out),
        )
    except SoundnessBugSuspected:
        guard_fired = True

    assert guard_fired
    pytest.xfail(
        "CYCLE_STATE_MOD: set_cycle/exec_Reg overwrite dead arm (steps.cpp:14743). "
        "See D2B_BATCH2_DEAD_ARM_AUDIT.md + plan §6d."
    )


@pytest.mark.skipif(os.environ.get("A4_REAL_BINARY") != "1", reason="Set A4_REAL_BINARY=1")
class TestCycleStateModAttestation:
    def test_layers_2_3_4(self):
        host = _host_binary()
        if not Path(host).is_file():
            pytest.skip("risc0-host not built")
        data = InspectionData.from_inspection(host, _host_args())
        _run_layers_2_3_4(_find_target(data))
