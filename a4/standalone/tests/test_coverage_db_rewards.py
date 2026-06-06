#!/usr/bin/env python3
"""
Phase III.3 unit tests for the `mutation_rewards` table and helpers in
CoverageDB. Persists every field of the diag dict returned by
coverage_state.compute_reward.

Run: python -m pytest a4/standalone/tests/test_coverage_db_rewards.py -v
"""

import os
import tempfile

import pytest

from a4.standalone.coverage_db import CoverageDB
from a4.standalone.coverage_state import CoverageState, compute_reward
from a4.standalone.pilot_calibration import CalibratedParams
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh on-disk SQLite (file, not :memory:, so re-open semantics hold)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    inst = CoverageDB(path)
    try:
        yield inst
    finally:
        inst.close()
        os.unlink(path)


def _start_campaign(db: CoverageDB) -> int:
    return db.start_campaign("/tmp/host", ["--in1", "5"], "all", seed=42)


def _record_mutation(db: CoverageDB, cid: int, kind="COMP_OUT_MOD", step=10) -> int:
    return db.record_mutation(
        campaign_id=cid, kind=kind, step=step,
        mutated_value=0, config={"step": step}, txn_idx=None,
        verifier_accepted=False,
    )


def _full_diag(
    r=0.42, T_new=0.1, T_rare=0.2, F_new=0.3, F_rare=0.4,
    U=0, Q_loc=0.9, Q_rep=1.0, Q_glob=0.85,
    delta_T=5, delta_F=2, n_fail=3, r_rep=0,
    d_loc=2, d_glob=1, d_ext=3, mode="normal",
):
    """Build a synthetic diag dict with every required key."""
    Q = Q_loc * Q_rep * Q_glob
    S = (T_new + T_rare + F_new + F_rare + U) / 5.0
    return {
        "r": r, "T_new": T_new, "T_rare": T_rare, "F_new": F_new, "F_rare": F_rare,
        "U": U, "Q_loc": Q_loc, "Q_rep": Q_rep, "Q_glob": Q_glob, "Q": Q, "S": S,
        "delta_T": delta_T, "delta_F": delta_F, "n_fail": n_fail, "r_rep": r_rep,
        "d_loc": d_loc, "d_glob": d_glob, "d_ext": d_ext, "mode": mode,
    }


def _calibrated_params() -> CalibratedParams:
    """Realistic CalibratedParams for compute_reward roundtrip."""
    return CalibratedParams(
        tau_new=40.0, tau_d=3.0, K_T_rare=64,
        gamma=0.999,
        tau_F_new=5.0, K_F_rare=32, r_0=0, tau_r=10.0,
        a_Tn=1.0, a_Tr=1.0, a_Fn=1.0, a_Fr=1.0, a_U=1.0,
        tau_g=5.0,
    )


# -----------------------------------------------------------------------------
# 1 — Schema
# -----------------------------------------------------------------------------

def test_schema_created(db):
    """mutation_rewards table + index exist after _init_schema."""
    cur = db.conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='mutation_rewards'"
    )
    assert cur.fetchone() is not None

    cur.execute("PRAGMA table_info(mutation_rewards)")
    cols = {row["name"]: row["type"] for row in cur.fetchall()}
    expected = {
        "mutation_id": "INTEGER",
        "reward": "REAL", "T_new": "REAL", "T_rare": "REAL",
        "F_new": "REAL", "F_rare": "REAL", "U": "INTEGER",
        "Q_loc": "REAL", "Q_rep": "REAL", "Q_glob": "REAL",
        "Q": "REAL", "S": "REAL",
        "delta_T": "INTEGER", "delta_F": "INTEGER",
        "n_fail": "INTEGER", "r_rep": "INTEGER",
        "d_loc": "INTEGER", "d_glob": "INTEGER", "d_ext": "INTEGER",
        "mode": "TEXT",
    }
    assert cols == expected, f"got {cols}"

    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_mr_mut'"
    )
    assert cur.fetchone() is not None


# -----------------------------------------------------------------------------
# 2 — Basic record + readback
# -----------------------------------------------------------------------------

def test_record_reward_diag_minimal(db):
    cid = _start_campaign(db)
    mid = _record_mutation(db, cid)
    diag = _full_diag()
    db.record_reward_diag(mid, diag)

    rows = db.get_reward_diag_for_campaign(cid)
    assert len(rows) == 1
    row = rows[0]
    assert row["mutation_id"] == mid
    assert row["reward"] == pytest.approx(0.42)
    assert row["T_new"] == pytest.approx(0.1)
    assert row["Q"] == pytest.approx(0.9 * 1.0 * 0.85)
    assert row["U"] == 0
    assert row["d_ext"] == 3
    assert row["mode"] == "normal"


# -----------------------------------------------------------------------------
# 3 — Crash-mode diag
# -----------------------------------------------------------------------------

def test_record_reward_diag_crash_mode(db):
    """Persisting the crash-early-return diag from compute_reward."""
    cid = _start_campaign(db)
    mid = _record_mutation(db, cid, kind="MEM_VAL_MOD")

    state = CoverageState(_calibrated_params())
    # SIGSEGV exit code (-11) triggers crash path; touch_bitmap=None also
    # triggers it. Either way the early-return path runs.
    r, diag = compute_reward(
        touch_bitmap=None, failures=[], exit_code=-11,
        outcome="CRASH", proof_generated=False, state=state,
        global_contexts=None,
    )
    assert r == 0.0
    db.record_reward_diag(mid, diag)

    rows = db.get_reward_diag_for_campaign(cid)
    assert len(rows) == 1
    assert rows[0]["mode"] == "crash"
    assert rows[0]["reward"] == 0.0
    assert rows[0]["Q"] == 0.0
    assert rows[0]["T_new"] == 0.0


# -----------------------------------------------------------------------------
# 4 — INSERT OR REPLACE semantics
# -----------------------------------------------------------------------------

def test_record_reward_diag_overwrite(db):
    """Re-recording for the same mutation_id replaces, not errors."""
    cid = _start_campaign(db)
    mid = _record_mutation(db, cid)

    db.record_reward_diag(mid, _full_diag(r=0.1, T_new=0.5))
    db.record_reward_diag(mid, _full_diag(r=0.9, T_new=0.8))

    rows = db.get_reward_diag_for_campaign(cid)
    assert len(rows) == 1, "PK conflict should have replaced, not duplicated"
    assert rows[0]["reward"] == pytest.approx(0.9)
    assert rows[0]["T_new"] == pytest.approx(0.8)


# -----------------------------------------------------------------------------
# 5 — Schema contract enforcement
# -----------------------------------------------------------------------------

def test_missing_diag_field_raises(db):
    """A diag without all required keys must fail loudly with KeyError."""
    cid = _start_campaign(db)
    mid = _record_mutation(db, cid)
    diag = _full_diag()
    del diag["Q_glob"]  # remove a required field
    with pytest.raises(KeyError):
        db.record_reward_diag(mid, diag)


# -----------------------------------------------------------------------------
# 6 — Full compute_reward → record → readback roundtrip
# -----------------------------------------------------------------------------

def test_full_compute_reward_roundtrip(db):
    """
    Anchor the schema-vs-diag-dict contract: whatever compute_reward
    returns must be persistable without information loss. If someone
    adds a new field to the diag dict and forgets to mirror it in the
    schema, this test catches the mismatch (the new field is silently
    dropped).
    """
    cid = _start_campaign(db)
    mid = _record_mutation(db, cid)

    state = CoverageState(_calibrated_params())
    # Build a synthetic touch bitmap so the touch-novelty branch runs.
    tb = bytearray(A4_TOUCH_MAP_SIZE)
    for i in range(0, 100):
        tb[i] = 1
    r, diag = compute_reward(
        touch_bitmap=bytes(tb), failures=[], exit_code=0,
        outcome="NO_EFFECT", proof_generated=True, state=state,
        global_contexts=None,
    )
    db.record_reward_diag(mid, diag)

    rows = db.get_reward_diag_for_campaign(cid)
    assert len(rows) == 1
    row = rows[0]

    # Every diag key (except mutation_id which is the FK) should be
    # round-tripped equal. This catches schema/diag drift.
    diag_keys = set(diag.keys())
    row_keys = set(row.keys()) - {"mutation_id"}
    # Persisted column 'reward' corresponds to diag key 'r' (single-letter
    # name is preserved in the dict but verbose in SQL — that's deliberate).
    persisted = (row_keys - {"reward"}) | {"r"}
    assert diag_keys == persisted, (
        f"schema/diag drift: only-in-diag={diag_keys - persisted}, "
        f"only-in-row={persisted - diag_keys}"
    )

    # And the values themselves must match.
    assert row["reward"] == pytest.approx(diag["r"])
    for k in diag_keys - {"r"}:
        if isinstance(diag[k], float):
            assert row[k] == pytest.approx(diag[k]), f"mismatch on {k}"
        else:
            assert row[k] == diag[k], f"mismatch on {k}"
