#!/usr/bin/env python3
"""D2.B Batch 2 — CYCLE_MODE_MOD attestation (Layers 2+3+4)."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.touch_coverage import parse_family_residues
from a4.core.trace_parser import (
    parse_all_a4_cycles,
    parse_cycle_mode_mod,
    parse_post_mut_cycle_dump,
)
from a4.standalone.mutations.cycle_mode_mod import (
    CycleModeModTarget,
    create_config,
    flipped_mode,
    get_targets_at_step,
)
from a4.standalone.tests._test_helpers.diff_signature import (
    SoundnessBugSuspected,
    assert_cycle_diff_matches_signature,
    check_soundness_bug_guard,
    collect_cycle_field_diffs,
)


def _host_binary() -> str:
    default = "workspace/output/target/release/risc0-host"
    return os.environ.get("A4_TEST_HOST", default).strip()


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


def _find_target(data: InspectionData) -> CycleModeModTarget:
    valid = data.get_valid_steps_for_kind("CYCLE_MODE_MOD")
    assert valid, "no valid CYCLE_MODE_MOD steps"
    for step in valid:
        target = get_targets_at_step(step, data)
        if target is not None:
            return target
    raise AssertionError("no flippable CYCLE_MODE_MOD target on production trace")


def _run_layers_2_3_4(target: CycleModeModTarget) -> None:
    new_mode = flipped_mode(target)

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = create_config(target, Path(tmp) / "mut.json")

        pre_result = _run_host({"A4_INSPECT": "1"})
        pre_out = _combined_output(pre_result)
        pre_cycles = [
            {
                "cycle_idx": c.cycle_idx,
                "machine_mode": c.machine_mode,
                "pc": c.pc,
                "major": c.major,
                "minor": c.minor,
            }
            for c in parse_all_a4_cycles(pre_out)
        ]

        mut_result = _run_host(
            {
                "A4_INSPECT": "1",
                "A4_DUMP_POST_MUT": "1",
                "A4_FAMILY_RESIDUE": "1",
            },
            cfg_path,
        )
        mut_out = _combined_output(mut_result)

    evidence = parse_cycle_mode_mod(mut_out)
    assert evidence, "Layer 2: missing <a4_cycle_mode_mod> tag"
    tag = evidence[-1]
    assert tag.cycle_idx == target.cycle_idx
    assert tag.old_mode == target.original_mode
    assert tag.new_mode == new_mode

    dumps = parse_post_mut_cycle_dump(mut_out)
    assert dumps, "Layer 3: missing <a4_post_mut_cycle_dump> tags"
    center = next(d for d in dumps if d.cycle_idx == target.cycle_idx)
    assert center.machine_mode == new_mode

    post_by_idx = {d.cycle_idx: d for d in dumps}
    pre_by_idx = {c["cycle_idx"]: c for c in pre_cycles}
    window = [
        {
            "cycle_idx": idx,
            "machine_mode": pre_by_idx[idx]["machine_mode"],
            "pc": pre_by_idx[idx]["pc"],
            "major": pre_by_idx[idx]["major"],
            "minor": pre_by_idx[idx]["minor"],
        }
        for idx in sorted(post_by_idx)
        if idx in pre_by_idx
    ]
    post_window = [
        {
            "cycle_idx": idx,
            "machine_mode": post_by_idx[idx].machine_mode,
            "pc": post_by_idx[idx].pc,
            "major": post_by_idx[idx].major,
            "minor": post_by_idx[idx].minor,
        }
        for idx in sorted(post_by_idx)
        if idx in pre_by_idx
    ]
    diffs = collect_cycle_field_diffs(window, post_window)
    assert_cycle_diff_matches_signature(
        diffs,
        {
            "primary": {
                "cycle_idx": target.cycle_idx,
                "field": "machine_mode",
                "old": target.original_mode,
                "new": new_mode,
            },
            "cascade": [],
        },
    )

    assert tag.new_mode == center.machine_mode, "Layer 4 cross-check failed"

    family_residues = parse_family_residues(mut_out)
    broken_families = []
    if family_residues is not None:
        broken_families = [fr["family"] for fr in family_residues if fr.get("nonzero")]

    guard_fired = False
    try:
        check_soundness_bug_guard(
            mutation_applied=True,
            trace_changed=bool(diffs),
            constraint_failed="constraint_fail" in mut_out.lower(),
            error_emitted="<a4_error>" in mut_out,
            proof_verify_failed="verify segment" in mut_out,
            broken_families_nonzero=bool(broken_families),
            verifier_accepted=_verifier_accepted(mut_out),
        )
    except SoundnessBugSuspected:
        guard_fired = True

    # W-3-class dead arm on sha2-host user-instruction cycles: trace.cycles[].machine_mode
    # is preset via set_cycle (witgen/mod.rs:1073) but step_Top overwrites nextMachineMode
    # with inst_result.newMode (steps.cpp:14745 → exec_Reg → exec_NondetReg STORE).
    # Layer 3 post-mut dump is real; proof reflects unmutated execution — not W-16.
    assert guard_fired, (
        "Expected SoundnessBugSuspected (W-3 dead arm): trace changed but all rejection "
        "channels silent and verifier accepted. If this stops firing, re-investigate "
        "per W-16 — B.3 may have become a live signal."
    )
    pytest.xfail(
        "CYCLE_MODE_MOD: set_cycle/exec_Reg overwrite dead arm on sha2-host user cycles. "
        "See D2B_BATCH2_COMPOSER_REPORT.md §Appendix B.3 dead-arm proof."
    )


@pytest.mark.skipif(
    os.environ.get("A4_REAL_BINARY") != "1",
    reason="Set A4_REAL_BINARY=1 to run real-binary attestation",
)
class TestCycleModeModAttestation:
    def test_layers_2_3_4(self):
        host = _host_binary()
        if not Path(host).is_file():
            pytest.skip(f"risc0-host not found at {host}")

        data = InspectionData.from_inspection(host, _host_args())
        target = _find_target(data)
        _run_layers_2_3_4(target)
