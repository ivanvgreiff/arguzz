#!/usr/bin/env python3
"""D2.B Batch 3 — TXN_ADDR_MOD attestation (empirical: dead arm on sha2-host)."""

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
from a4.core.trace_parser import parse_all_all_txns, parse_post_mut_dump, parse_txn_addr_mod
from a4.standalone.mutations.txn_addr_mod import (
    TxnAddrModTarget,
    create_config,
    generate_new_value,
    get_targets_at_step,
)
from a4.standalone.tests._test_helpers.diff_signature import (
    SoundnessBugSuspected,
    assert_trace_diff_matches_signature,
    check_soundness_bug_guard,
    collect_txn_field_diffs,
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


def _find_target(data: InspectionData) -> TxnAddrModTarget:
    for step in data.get_valid_steps_for_kind("TXN_ADDR_MOD"):
        candidates = get_targets_at_step(step, data)
        if candidates:
            return candidates[0]
    raise AssertionError("no TXN_ADDR_MOD target")


def _run_layers_2_3_4(target: TxnAddrModTarget, data: InspectionData, seed: int = 42) -> None:
    new_addr = generate_new_value(target, random.Random(seed), data)
    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = create_config(target, new_addr, Path(tmp) / "mut.json")
        pre_out = _combined_output(_run_host({"A4_INSPECT": "1", "A4_DUMP_ALL_TXNS": "1"}))
        pre_txns = [
            {"txn_idx": t.txn_idx, "word": t.word, "prev_word": t.prev_word,
             "prev_cycle": t.prev_cycle, "cycle": t.cycle, "addr": t.addr}
            for t in parse_all_all_txns(pre_out)
        ]
        mut_out = _combined_output(
            _run_host(
                {"A4_INSPECT": "1", "A4_DUMP_ALL_TXNS": "1", "A4_DUMP_POST_MUT": "1", "A4_FAMILY_RESIDUE": "1"},
                cfg_path,
            )
        )

    tag = parse_txn_addr_mod(mut_out)[-1]
    assert tag.new_addr == new_addr
    center = next(d for d in parse_post_mut_dump(mut_out) if d.txn_idx == target.txn_idx)
    assert center.addr == new_addr

    post_by_idx = {d.txn_idx: d for d in parse_post_mut_dump(mut_out)}
    pre_by_idx = {t["txn_idx"]: t for t in pre_txns}
    fields = ("word", "prev_word", "prev_cycle", "cycle", "addr")
    window = [{**{f: pre_by_idx[i][f] for f in fields}, "txn_idx": i} for i in sorted(post_by_idx) if i in pre_by_idx]
    post_window = [{**{f: getattr(post_by_idx[i], f) for f in fields}, "txn_idx": i} for i in sorted(post_by_idx) if i in pre_by_idx]
    diffs = collect_txn_field_diffs(window, post_window)
    assert_trace_diff_matches_signature(
        diffs,
        {"primary": {"txn_idx": target.txn_idx, "field": "addr", "old": target.original_addr, "new": new_addr},
         "cascade": []},
    )

    broken_families = [fr["family"] for fr in (parse_family_residues(mut_out) or []) if fr.get("nonzero")]
    rejected = bool(broken_families) or "verify segment" in mut_out or "constraint_fail" in mut_out.lower()
    if rejected:
        pytest.fail(
            "AUDIT FAILURE — RECONCILE REQUIRED: TXN_ADDR_MOD showed live rejection. "
            "Batch 3 empirical dead-arm finding contradicted on this target. "
            "Investigate which witness path reached the constraint; reconcile against "
            "D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md."
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
        "TXN_ADDR_MOD: unexpected dead arm on sha2-host (trace addr mutates; no C1/C2/C3; "
        "verifier accepts). Contradicts spec §5.4 LIVE prediction — see Batch 3 report."
    )


@pytest.mark.skipif(os.environ.get("A4_REAL_BINARY") != "1", reason="Set A4_REAL_BINARY=1")
class TestTxnAddrModAttestation:
    def test_layers_2_3_4(self):
        host = _host_binary()
        if not Path(host).is_file():
            pytest.skip("risc0-host not built")
        data = InspectionData.from_inspection(host, _host_args())
        _run_layers_2_3_4(_find_target(data), data)
