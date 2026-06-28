#!/usr/bin/env python3
"""A3.1 unit tests for the Seam-B race harness (IV_POS_9_A3_SEAMB_RACE_SPEC §6).

Pure-logic / mocked — NO binaries, fast, deterministic. The binary-dependent
ground-truth (test 13 / Stage-0) lives in run_stage0.py (gated on the archived
binaries). Run: python -m pytest a4/runs/iv_pos_9/race/tests/test_race.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path("/root/arguzz")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from a4.runs.iv_pos_9.race import oracle, markers          # noqa: E402
from a4.pos import fingerprint_guard                         # noqa: E402
from a4.pos import generate_race_manifests as grm            # noqa: E402
from a4.standalone.variants import CANONICAL_VARIANTS        # noqa: E402


# --- helpers ---------------------------------------------------------------
def _mk_db(tmp_path, rows):
    """rows = [(id, kind, verifier_accepted, outcome, config_dict), ...]"""
    db = tmp_path / "run.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE mutations (id INTEGER PRIMARY KEY, kind TEXT, step INTEGER, "
                "config_json TEXT, verifier_accepted INTEGER, outcome TEXT)")
    for (mid, kind, va, outcome, cfg) in rows:
        con.execute("INSERT INTO mutations (id,kind,step,config_json,verifier_accepted,outcome) "
                    "VALUES (?,?,?,?,?,?)", (mid, kind, 0, json.dumps(cfg), va, outcome))
    con.commit(); con.close()
    return str(db)


def _itm(orig=(0, 7), mut=(0, 1)):  # AddI -> Sub
    return {"mutation_type": "INSTR_TYPE_MOD", "step": 1, "major": mut[0], "minor": mut[1],
            "_info": {"original_major": orig[0], "original_minor": orig[1]}}


# --- 1: fingerprint profile (logic, read_fingerprint monkeypatched) --------
def test_fingerprint_profile(monkeypatch):
    assert fingerprint_guard.PROFILES["verifyopcode"] == {"load_rs2_present": 1, "planted_bug": "verifyopcode"}
    holed = {"load_rs2_present": 1, "planted_bug": "verifyopcode", "risc0_head_sha": "93bda33b", "guest_image_id": [1, 2]}
    ctrl = {"load_rs2_present": 1, "planted_bug": "none", "risc0_head_sha": "93bda33b", "guest_image_id": [1, 2]}
    monkeypatch.setattr(fingerprint_guard, "read_fingerprint", lambda *a, **k: holed)
    ok, _, _ = fingerprint_guard.assert_fingerprint("x", expect_load_rs2=1, expect_planted_bug="verifyopcode",
                                                     expect_head_sha="93bda33b", expect_guest_id=[1, 2])
    assert ok
    monkeypatch.setattr(fingerprint_guard, "read_fingerprint", lambda *a, **k: ctrl)
    ok, _, _ = fingerprint_guard.assert_fingerprint("x", expect_load_rs2=1, expect_planted_bug="verifyopcode")
    assert not ok  # control fails the verifyopcode profile
    # guest_image_id mismatch also fails
    monkeypatch.setattr(fingerprint_guard, "read_fingerprint", lambda *a, **k: holed)
    ok, _, _ = fingerprint_guard.assert_fingerprint("x", expect_load_rs2=1, expect_planted_bug="verifyopcode",
                                                     expect_guest_id=[9, 9])
    assert not ok


# --- 2: confirmed find -----------------------------------------------------
def test_oracle_confirmed_find(tmp_path):
    db = _mk_db(tmp_path, [(19, "INSTR_TYPE_MOD", 1, "applied", _itm())])
    res = oracle.classify_run(db, control_check_fn=lambda cfg: True)  # control rejects @ VerifyOpcode
    assert res == [{"id": 19, "kind": "INSTR_TYPE_MOD", "verdict": oracle.FIND}]


# --- 3: no-op (benign) excluded — control-checked, does NOT reject @ VerifyOpcode --
def test_oracle_noop_excluded(tmp_path):
    db = _mk_db(tmp_path, [(5, "CYCLE_DIFF_COUNT_MOD", 1, "applied", {"mutation_type": "CYCLE_DIFF_COUNT_MOD"})])
    res = oracle.classify_run(db, control_check_fn=lambda cfg: False)  # control accepts (not @ VerifyOpcode)
    assert res[0]["verdict"] == oracle.NON_PLANTED  # not the planted decode bug


# --- 3b: FALSIFIER — a non-ITM accept that DOES reject @ VerifyOpcode on control is a FIND
def test_oracle_falsifier_non_itm_find(tmp_path):
    # e.g. a hypothetical Arguzz fault that produced an accepted decode-divergent trace
    db = _mk_db(tmp_path, [(8, "CYCLE_PC_MOD", 1, "applied", {"mutation_type": "CYCLE_PC_MOD"})])
    res = oracle.classify_run(db, control_check_fn=lambda cfg: True)  # control rejects @ VerifyOpcode
    assert res[0]["verdict"] == oracle.FIND  # the experiment CAN detect an off-surface find


# --- 4: result-changer never an accept (verifier_accepted=0) --------------
def test_oracle_result_changer_not_accept(tmp_path):
    db = _mk_db(tmp_path, [(7, "INSTR_TYPE_MOD", 0, "applied", _itm(mut=(0, 4)))])  # AddI->And rejected on holed
    assert oracle.extract_accepts(db) == []  # verifier_accepted=0 -> not extracted -> never a find


# --- 5: oracle guards the control binary ----------------------------------
def test_oracle_guards_control(monkeypatch):
    monkeypatch.setattr(oracle, "assert_fingerprint", lambda *a, **k: (False, "bad", {}))
    with pytest.raises(RuntimeError):
        oracle.guard_control("ctrl", "93bda33b", [1, 2])
    monkeypatch.setattr(oracle, "assert_fingerprint", lambda *a, **k: (True, "ok", {}))
    oracle.guard_control("ctrl", "93bda33b", [1, 2])  # no raise


# --- 6: markers extraction (censoring, densities) -------------------------
def test_markers_extraction(tmp_path):
    rows = [(i, "INSTR_TYPE_MOD", 0, "applied", _itm()) for i in range(1, 51)]
    db = _mk_db(tmp_path, rows)
    m = markers.per_run_markers(db, find_ids=[10, 30], n_planned=50)
    assert m["found"] and m["first_find_idx"] == 10 and m["n_finds"] == 2 and not m["censored"]
    assert m["n_applied"] == 50 and m["n_instr_type_mod_applied"] == 50
    assert abs(m["find_density"] - 2 / 50) < 1e-9
    assert abs(m["conditional_find_density"] - 2 / 50) < 1e-9
    m0 = markers.per_run_markers(db, find_ids=[], n_planned=50)
    assert m0["censored"] and m0["first_find_idx"] == 51 and not m0["found"]


# --- 7: discovery CDF ------------------------------------------------------
def test_markers_cdf():
    cdf = markers.discovery_cdf([10, 20, 5001], n_planned=5000, grid=[10, 100, 5000])
    assert cdf[0] == (10, 1 / 3) and cdf[1] == (100, 2 / 3) and cdf[2][1] == 2 / 3  # censored never counts


# --- 8: conditional density / Arguzz n_itm=0 -> None ----------------------
def test_conditional_density(tmp_path):
    rows = [(i, "CYCLE_DIFF_COUNT_MOD", 0, "applied", {}) for i in range(1, 11)]  # no ITM (Arguzz-like)
    db = _mk_db(tmp_path, rows)
    m = markers.per_run_markers(db, find_ids=[], n_planned=10)
    assert m["n_instr_type_mod_applied"] == 0
    assert m["conditional_find_density"] is None  # defined, not div0


# --- 9: manifest generator -------------------------------------------------
def test_manifest_generator():
    rows = grm.batch_rows(seeds=[1234, 1235], n=2000, batch_prefix="t",
                          nodes=["flare", "zone", "goracle", "algofi"])
    assert len(rows) == 2 * len(grm.VARIANT_ORDER)  # variants x seeds
    assert all(n in ("flare", "zone", "goracle", "algofi") for _, n, _, _ in rows)
    for batch, node, rid, cmd in rows:
        assert "fingerprint_guard" in cmd and "--profile verifyopcode" in cmd
        assert grm.EXPECT_HEAD_SHA in cmd and grm.HOST_BIN in cmd
        assert rid.startswith("pos_iv_pos_9_a3seamb_")
        # control BINARY (not the V5_control variant name) is never a race target:
        assert "ap_seamb/control" not in cmd and "/control/risc0-host" not in cmd
        assert "exit 87" in cmd  # guard aborts on mismatch
        # REGRESSION (smoke death 2026-06-24): the guard MUST run from the repo, NOT
        # the chain launcher's run-dir CWD. Otherwise `python -m a4.pos.fingerprint_guard`
        # dies with ModuleNotFoundError: No module named 'a4', and its inline
        # `|| { ...; exit 87; }` silently kills the launcher before it writes a marker.
        assert cmd.startswith(f"cd {grm.REPO_DIR} &&")
        assert cmd.index(f"cd {grm.REPO_DIR}") < cmd.index("fingerprint_guard")


# --- 10: variant launch commands ------------------------------------------
def test_variant_launch_cmds():
    from a4.standalone.variants import variant_launch_command
    for v in CANONICAL_VARIANTS:
        argv = variant_launch_command(v, host="/h", db="/d", seed=1, num=10, host_args=["--ctrl", "7"])
        assert "/h" in argv and "--seed" in argv and "10" in argv


# --- 10b: --variants manifest filter (IV.POS.9 ablation: restrict to V0/V5/V8/Hybrid) ---
def test_variants_filter():
    # restrict to a 2-variant subset -> exactly those, in VARIANT_ORDER order
    rows = grm.batch_rows(seeds=[1234], n=5000, batch_prefix="t", nodes=["a", "b"],
                          variants=["V0_uniform", "V8_arguzz_sched"])
    assert len(rows) == 2
    rids = " ".join(r[2] for r in rows)
    assert "V0_uniform" in rids and "V8_arguzz_sched" in rids
    assert "V5_control" not in rids and "V6_uniform" not in rids
    # default (None) = all CANONICAL_VARIANTS
    assert len(grm.batch_rows(seeds=[1234], n=5000, batch_prefix="t", nodes=["a"])) \
        == len(grm.VARIANT_ORDER)
    # unknown variant errors cleanly
    with pytest.raises(ValueError):
        grm.batch_rows(seeds=[1234], n=5000, batch_prefix="t", nodes=["a"], variants=["V99_bogus"])


# --- 11: propagation_triage reuse smoke -----------------------------------
def test_triage_reuse_importable():
    from a4.runs.iv_pos_8.d2g import propagation_triage as pt
    assert hasattr(pt, "classify_semantics") and hasattr(pt, "extract_accepts")


# --- 12: F10 regression — A4 accept via COLUMN, not config soundness_signal --
def test_accept_signal_column(tmp_path):
    # A4 accept: verifier_accepted column=1, NO soundness_signal in config_json
    db = _mk_db(tmp_path, [(19, "INSTR_TYPE_MOD", 1, "applied", _itm())])
    acc = oracle.extract_accepts(db)
    assert len(acc) == 1 and acc[0]["id"] == 19  # caught via the column
    assert "soundness_signal" not in acc[0]["config"]  # confirms it's NOT relying on the Arguzz tag
