#!/usr/bin/env python3
"""D2.B Batch 2 — TXN_PREV_CYCLE_MOD attestation (Layers 2+3+4)."""

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
from a4.core.trace_parser import parse_all_all_txns, parse_post_mut_dump, parse_txn_prev_cycle_mod
from a4.standalone.mutations.txn_prev_cycle_mod import (
    TxnPrevCycleModTarget,
    create_config,
    generate_new_value,
    get_targets_at_step,
)
from a4.standalone.tests._test_helpers.diff_signature import (
    assert_trace_diff_matches_signature,
    check_soundness_bug_guard,
    collect_txn_field_diffs,
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


def _find_target(data: InspectionData) -> TxnPrevCycleModTarget:
    valid = data.get_valid_steps_for_kind("TXN_PREV_CYCLE_MOD")
    assert valid, "no valid TXN_PREV_CYCLE_MOD steps"
    for step in valid:
        candidates = get_targets_at_step(step, data)
        if candidates:
            return candidates[0]
    raise AssertionError("no TXN_PREV_CYCLE_MOD target on production trace")


def _run_layers_2_3_4(target: TxnPrevCycleModTarget, seed: int = 42) -> None:
    rng = random.Random(seed)
    new_prev_cycle = generate_new_value(target, rng)

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = create_config(target, new_prev_cycle, Path(tmp) / "mut.json")

        pre_result = _run_host({"A4_INSPECT": "1", "A4_DUMP_ALL_TXNS": "1"})
        pre_out = _combined_output(pre_result)
        pre_txns = [
            {
                "txn_idx": t.txn_idx,
                "word": t.word,
                "prev_word": t.prev_word,
                "prev_cycle": t.prev_cycle,
                "cycle": t.cycle,
                "addr": t.addr,
            }
            for t in parse_all_all_txns(pre_out)
        ]

        mut_result = _run_host(
            {
                "A4_INSPECT": "1",
                "A4_DUMP_ALL_TXNS": "1",
                "A4_DUMP_POST_MUT": "1",
                "A4_FAMILY_RESIDUE": "1",
            },
            cfg_path,
        )
        mut_out = _combined_output(mut_result)

    evidence = parse_txn_prev_cycle_mod(mut_out)
    assert evidence, "Layer 2: missing <a4_txn_prev_cycle_mod> tag"
    tag = evidence[-1]
    assert tag.txn_idx == target.txn_idx
    assert tag.old_prev_cycle == target.original_prev_cycle
    assert tag.new_prev_cycle == new_prev_cycle

    dumps = parse_post_mut_dump(mut_out)
    assert dumps, "Layer 3: missing <a4_post_mut_dump> tags"
    center = next(d for d in dumps if d.txn_idx == target.txn_idx)
    assert center.prev_cycle == new_prev_cycle

    post_by_idx = {d.txn_idx: d for d in dumps}
    pre_by_idx = {t["txn_idx"]: t for t in pre_txns}
    window = [
        {
            "txn_idx": idx,
            "word": pre_by_idx[idx]["word"],
            "prev_word": pre_by_idx[idx]["prev_word"],
            "prev_cycle": pre_by_idx[idx]["prev_cycle"],
            "cycle": pre_by_idx[idx]["cycle"],
            "addr": pre_by_idx[idx]["addr"],
        }
        for idx in sorted(post_by_idx)
        if idx in pre_by_idx
    ]
    post_window = [
        {
            "txn_idx": idx,
            "word": post_by_idx[idx].word,
            "prev_word": post_by_idx[idx].prev_word,
            "prev_cycle": post_by_idx[idx].prev_cycle,
            "cycle": post_by_idx[idx].cycle,
            "addr": post_by_idx[idx].addr,
        }
        for idx in sorted(post_by_idx)
        if idx in pre_by_idx
    ]
    diffs = collect_txn_field_diffs(window, post_window)
    assert_trace_diff_matches_signature(
        diffs,
        {
            "primary": {
                "txn_idx": target.txn_idx,
                "field": "prev_cycle",
                "old": target.original_prev_cycle,
                "new": new_prev_cycle,
            },
            "cascade": [],
        },
    )

    assert tag.new_prev_cycle == center.prev_cycle, "Layer 4 cross-check failed"

    family_residues = parse_family_residues(mut_out)
    assert family_residues is not None, (
        "Hook 3: missing <a4_family_residue> tags (is A4_FAMILY_RESIDUE=1 set?)"
    )
    broken_families = [fr["family"] for fr in family_residues if fr.get("nonzero")]
    assert broken_families, f"Hook 3: expected nonzero family; got {family_residues}"
    assert "memory" in broken_families, (
        f"Hook 3: expected memory family for prev_cycle mutation; broken={broken_families}"
    )

    check_soundness_bug_guard(
        mutation_applied=True,
        trace_changed=bool(diffs),
        constraint_failed="constraint_fail" in mut_out.lower(),
        error_emitted="<a4_error>" in mut_out,
        proof_verify_failed="verify segment" in mut_out,
        broken_families_nonzero=bool(broken_families),
        verifier_accepted=_verifier_accepted(mut_out),
    )


@pytest.mark.skipif(
    os.environ.get("A4_REAL_BINARY") != "1",
    reason="Set A4_REAL_BINARY=1 to run real-binary attestation",
)
class TestTxnPrevCycleModAttestation:
    def test_layers_2_3_4(self):
        host = _host_binary()
        if not Path(host).is_file():
            pytest.skip(f"risc0-host not found at {host}")

        data = InspectionData.from_inspection(host, _host_args())
        target = _find_target(data)
        _run_layers_2_3_4(target)
