"""
Phase 1 (cloud1) — schema v2 round-trip tests.

Verifies that:
1. The 8 new tables (bandit_decisions, arm_state_snapshot,
   reward_counterfactuals, mutation_substrategy, hook3_raw, pilot_runs,
   compressed_global_coverage, local_coverage_v2) are all created on a
   fresh DB.
2. Each table accepts inserts via its `record_*` method.
3. Inserted values round-trip through SQLite cleanly.
4. JSON-encoded extras decode back to the original dict.

Companion test for migration on existing IV.POS.5 DBs is in
`test_schema_v2_migration.py`.
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

from a4.standalone.coverage_db import CoverageDB


# =============================================================================
# Fixture
# =============================================================================


@pytest.fixture
def db_and_mutation():
    """Provide a fresh DB + one campaign + one mutation row, yielding
    `(db, campaign_id, mutation_id)`."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = CoverageDB(tmp.name)
    cid = db.start_campaign(
        host_binary="/fake/risc0-host",
        host_args=["--in1", "5"],
        kind="INSTR_TYPE_MOD",
        seed=42,
    )
    mid = db.record_mutation(
        campaign_id=cid,
        kind="INSTR_TYPE_MOD",
        step=0,
        mutated_value=12345,
        config={"mutation_type": "INSTR_TYPE_MOD", "step": 0},
        verifier_accepted=False,
    )
    yield db, cid, mid
    db.conn.close()
    Path(tmp.name).unlink(missing_ok=True)


# =============================================================================
# Test: all 8 new tables exist
# =============================================================================


def test_v2_tables_created(db_and_mutation):
    db, _cid, _mid = db_and_mutation
    expected = {
        "bandit_decisions",
        "arm_state_snapshot",
        "reward_counterfactuals",
        "mutation_substrategy",
        "hook3_raw",
        "pilot_runs",
        "compressed_global_coverage",
        "local_coverage_v2",
    }
    rows = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    actual = {r["name"] for r in rows}
    missing = expected - actual
    assert not missing, f"missing v2 tables: {missing}"


# =============================================================================
# Per-table round-trip tests
# =============================================================================


def test_bandit_decisions_roundtrip(db_and_mutation):
    db, _cid, mid = db_and_mutation
    db.record_bandit_decision(
        mutation_id=mid,
        selected_arm="INSTR_TYPE_MOD|step0",
        mode="cold",
        score=0.73,
        runnerup_arm="MEM_VAL_MOD|core_other",
        runnerup_score=0.61,
        exploration=True,
        extra={"epoch_idx": 0},
    )
    row = db.conn.execute(
        "SELECT * FROM bandit_decisions WHERE mutation_id=?", (mid,)
    ).fetchone()
    assert row is not None
    assert row["selected_arm"] == "INSTR_TYPE_MOD|step0"
    assert row["mode"] == "cold"
    assert abs(row["score"] - 0.73) < 1e-9
    assert row["runnerup_arm"] == "MEM_VAL_MOD|core_other"
    assert abs(row["runnerup_score"] - 0.61) < 1e-9
    assert row["exploration"] == 1
    assert json.loads(row["extra_json"]) == {"epoch_idx": 0}


def test_arm_state_snapshot_roundtrip(db_and_mutation):
    db, cid, _mid = db_and_mutation
    snaps = [
        {"arm_id": "A|step0", "pulls": 3, "mean_reward": 0.5,
         "posterior_alpha": 2.0, "posterior_beta": 2.0},
        {"arm_id": "B|core_arithmetic", "pulls": 7, "mean_reward": 0.2,
         "posterior_alpha": 2.4, "posterior_beta": 6.6,
         "ts_extra": {"note": "warm"}},
    ]
    db.record_arm_state_snapshot(campaign_id=cid, mutation_idx=100, arm_states=snaps)
    rows = db.conn.execute(
        "SELECT * FROM arm_state_snapshot WHERE campaign_id=? ORDER BY arm_id",
        (cid,),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["arm_id"] == "A|step0"
    assert rows[0]["pulls"] == 3
    assert rows[1]["arm_id"] == "B|core_arithmetic"
    assert rows[1]["pulls"] == 7
    assert rows[1]["ts_extra_json"] is not None
    assert json.loads(rows[1]["ts_extra_json"]) == {"note": "warm"}


def test_reward_counterfactuals_roundtrip(db_and_mutation):
    db, _cid, mid = db_and_mutation
    db.record_reward_counterfactuals(
        mutation_id=mid,
        current_reward=1.50,
        no_qloc_reward=0.95,
        fnew_only_reward=0.30,
        discovery_binary_reward=1,
        compressed_global_reward=0.10,
    )
    row = db.conn.execute(
        "SELECT * FROM reward_counterfactuals WHERE mutation_id=?", (mid,)
    ).fetchone()
    assert abs(row["current_reward"] - 1.50) < 1e-9
    assert abs(row["no_qloc_reward"] - 0.95) < 1e-9
    assert abs(row["fnew_only_reward"] - 0.30) < 1e-9
    assert row["discovery_binary_reward"] == 1
    assert abs(row["compressed_global_reward"] - 0.10) < 1e-9


def test_mutation_substrategy_partial_null(db_and_mutation):
    db, _cid, mid = db_and_mutation
    db.record_mutation_substrategy(
        mutation_id=mid,
        opcode=0b0110011, funct3=0b000, funct7=0b0000000, rd=1, rs1=2, rs2=3,
        # other fields default to None
    )
    row = db.conn.execute(
        "SELECT * FROM mutation_substrategy WHERE mutation_id=?", (mid,)
    ).fetchone()
    assert row["opcode"] == 0b0110011
    assert row["funct3"] == 0
    assert row["funct7"] == 0
    assert row["byte_lane"] is None
    assert row["bit_mask"] is None
    assert row["value_class"] is None


def test_hook3_raw_roundtrip(db_and_mutation):
    db, _cid, mid = db_and_mutation
    raw = [{"family": "memory", "address": "2147483648"}]
    compressed = [{"family": "memory", "address_region": "user", "address_bucket": 31,
                   "txn_role": "read", "cycle_phase": "normal"}]
    db.record_hook3_raw(mid, raw_entries=raw, compressed_ctx_list=compressed)
    row = db.conn.execute(
        "SELECT * FROM hook3_raw WHERE mutation_id=?", (mid,)
    ).fetchone()
    assert json.loads(row["raw_json"]) == raw
    assert json.loads(row["compressed_ctx_json"]) == compressed


def test_pilot_runs_roundtrip(db_and_mutation):
    db, cid, _mid = db_and_mutation
    db.record_pilot_run(
        campaign_id=cid,
        pilot_idx=0,
        raw_pilot_observation={"n_fail": 3, "T_new": 0.0},
        calibrated_params={"tau_new": 35.0},
    )
    row = db.conn.execute(
        "SELECT * FROM pilot_runs WHERE campaign_id=?", (cid,)
    ).fetchone()
    assert row["pilot_idx"] == 0
    assert json.loads(row["raw_pilot_observation_json"])["n_fail"] == 3
    assert json.loads(row["calibrated_params_json"])["tau_new"] == 35.0


def test_compressed_global_coverage_first_hit(db_and_mutation):
    db, cid, mid = db_and_mutation
    is_new1 = db.record_compressed_global_first_hit(
        cid, mid, ctx_key="memory|user|31|read|normal",
        family="memory",
        ctx_json='{"address_region":"user","address_bucket":31}',
    )
    is_new2 = db.record_compressed_global_first_hit(
        cid, mid, ctx_key="memory|user|31|read|normal",
        family="memory",
        ctx_json='{"address_region":"user","address_bucket":31}',
    )
    assert is_new1 is True
    assert is_new2 is False
    row = db.conn.execute(
        "SELECT hit_count FROM compressed_global_coverage WHERE ctx_key=? AND campaign_id=?",
        ("memory|user|31|read|normal", cid),
    ).fetchone()
    assert row["hit_count"] == 2


def test_local_coverage_v2_first_hit(db_and_mutation):
    db, cid, mid = db_and_mutation
    new1 = db.record_local_v2_first_hit(cid, mid, "MemLoadInput@inst_mem.zir:8", 5, 4)
    new2 = db.record_local_v2_first_hit(cid, mid, "MemLoadInput@inst_mem.zir:8", 5, 4)
    new3 = db.record_local_v2_first_hit(cid, mid, "MemLoadInput@inst_mem.zir:8", 5, 6)
    assert new1 is True
    assert new2 is False  # same (loc, major, minor) → not new
    assert new3 is True   # different minor → new
    rows = db.conn.execute(
        "SELECT * FROM local_coverage_v2 WHERE campaign_id=? ORDER BY minor",
        (cid,),
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["minor"] == 4
    assert rows[1]["minor"] == 6
    assert rows[0]["hit_count"] == 2  # incremented from second insert
    assert rows[1]["hit_count"] == 1
