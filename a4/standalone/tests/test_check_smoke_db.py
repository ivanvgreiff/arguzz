"""Unit tests for a4/tools/check_smoke_db.py (synthetic DBs only)."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "a4" / "tools"))

from check_smoke_db import check_smoke_db  # noqa: E402

from a4.standalone.coverage_db import CoverageDB


@pytest.fixture
def minimal_full_db(tmp_path):
    """One mutation with full v2 rows (V5-style)."""
    db_path = tmp_path / "mini.db"
    with CoverageDB(str(db_path)) as db:
        cid = db.start_campaign("/bin/host", ["--in1", "5"], "all", 999)
        mid = db.record_mutation(cid, "LOAD_VAL_MOD", 3, 0, {"step": 3}, None, False)
        db.record_reward_counterfactuals(
            mid, current_reward=0.5, no_qloc_reward=0.4,
            fnew_only_reward=0.1, discovery_binary_reward=0,
            compressed_global_reward=0.0,
        )
        db.record_mutation_substrategy(mid, value_class="zero")
        db.record_hook3_raw(mid, raw_entries={"family_residues": []})
        db.record_bandit_decision(
            mid, selected_arm="LOAD_VAL_MOD|core_other", mode="cold",
            score=0.0, runnerup_arm=None, runnerup_score=None, exploration=True,
        )
        db.record_local_v2_first_hit(
            cid, mid, "MemLoadInput(zirgen/circuit/rv32im/v2/dsl/inst_mem.zir:8)", 5, 4,
        )
        db.end_campaign(cid)
    return db_path


def test_7a_v5_passes(minimal_full_db):
    res = check_smoke_db(
        minimal_full_db, "cTS_semantic_v2", "7a", requested_mutations=1,
    )
    assert res.ok, res.hard_failures


def test_missing_counterfactuals_fails(minimal_full_db):
    import sqlite3
    conn = sqlite3.connect(str(minimal_full_db))
    conn.execute("DELETE FROM reward_counterfactuals")
    conn.commit()
    conn.close()
    res = check_smoke_db(minimal_full_db, "cTS_semantic_v2", "7a", requested_mutations=1)
    assert not res.ok
    assert any("reward_counterfactuals" in f for f in res.hard_failures)


def test_inf_counterfactual_fails(minimal_full_db):
    import sqlite3
    conn = sqlite3.connect(str(minimal_full_db))
    conn.execute(
        "UPDATE reward_counterfactuals SET current_reward = ? WHERE mutation_id = 1",
        (float("inf"),),
    )
    conn.commit()
    conn.close()
    res = check_smoke_db(minimal_full_db, "cTS_semantic_v2", "7a", requested_mutations=1)
    assert not res.ok
    assert any("non-finite" in f for f in res.hard_failures)
