#!/usr/bin/env python3
"""D2.B Batch 4 — Layer 5 real-binary bandit-16 campaign smoke + POS DB evaluation."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set

import pytest

from a4.standalone.fuzzer import A4Fuzzer

DEAD_KINDS: Set[str] = {
    "CYCLE_MODE_MOD",
    "TXN_ADDR_MOD",
    "TXN_CYCLE_PHASE_MOD",
    "CYCLE_PC_MOD",
    "CYCLE_STATE_MOD",
}

LIVE_KINDS: Set[str] = set(A4Fuzzer.MUTATION_KINDS) - DEAD_KINDS


def _host_binary() -> str:
    default = "workspace/output/target/release/risc0-host"
    return os.environ.get("A4_TEST_HOST", default).strip()


def _host_args() -> List[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    return raw.split() if raw else []


def _smoke_n() -> int:
    return int(os.environ.get("A4_SMOKE_N", "100"))


def _has_rejection(conn: sqlite3.Connection, mutation_id: int) -> bool:
    row = conn.execute(
        "SELECT proof_verify_failed, verifier_accepted FROM mutations WHERE id = ?",
        (mutation_id,),
    ).fetchone()
    if row is None:
        return False
    proof_verify_failed, verifier_accepted = row
    if proof_verify_failed:
        return True
    n_fail = conn.execute(
        "SELECT COUNT(*) FROM failures WHERE mutation_id = ?",
        (mutation_id,),
    ).fetchone()[0]
    if n_fail > 0:
        return True
    n_global = conn.execute(
        "SELECT COUNT(*) FROM global_failures WHERE mutation_id = ?",
        (mutation_id,),
    ).fetchone()[0]
    if n_global > 0:
        return True
    n_cgc = conn.execute(
        "SELECT COUNT(*) FROM compressed_global_coverage WHERE first_hit_mutation_id = ?",
        (mutation_id,),
    ).fetchone()[0]
    if n_cgc > 0:
        return True
    if verifier_accepted is not None and int(verifier_accepted) == 0:
        return True
    return False


def evaluate_campaign_db(db_path: str, n_expected: int, *, strict: bool) -> None:
    """Assert POS/local campaign DB meets Batch 4 smoke criteria."""
    path = Path(db_path)
    assert path.is_file(), f"Coverage DB not found: {db_path}"

    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, kind, outcome
            FROM mutations
            ORDER BY id
            """
        ).fetchall()

        assert rows, "mutations table is empty"

        attempted = sum(
            1 for _, _, outcome in rows if outcome in ("applied", "error")
        )
        min_attempted = int(0.8 * n_expected)
        assert attempted >= min_attempted, (
            f"Too few attempted mutations: {attempted} < 0.8 * {n_expected} = {min_attempted}"
        )

        kinds_selected = {kind for _, kind, _ in rows}
        if strict:
            missing = set(A4Fuzzer.MUTATION_KINDS) - kinds_selected
            assert not missing, f"Bandit never selected kinds: {sorted(missing)}"

        rejections_by_kind: Dict[str, bool] = defaultdict(bool)
        for mid, kind, _ in rows:
            if _has_rejection(conn, mid):
                rejections_by_kind[kind] = True

        if strict:
            for kind in sorted(LIVE_KINDS):
                assert rejections_by_kind.get(kind), (
                    f"Live kind {kind} produced zero rejection signals across "
                    f"{sum(1 for _, k, _ in rows if k == kind)} attempts — regression"
                )

            for kind in sorted(DEAD_KINDS):
                dead_rows = [(mid, k) for mid, k, _ in rows if k == kind]
                if not dead_rows:
                    continue
                for mid, k in dead_rows:
                    assert not _has_rejection(conn, mid), (
                        f"Dead kind {k} mutation id={mid} fired a rejection signal — "
                        "W-17/W-18 audit may be wrong"
                    )

        assert len(rows) >= min_attempted, (
            f"DB row count {len(rows)} below attempted threshold {min_attempted}"
        )


def _run_local_campaign(db_path: Path, n: int) -> None:
    os.environ.setdefault("A4_FAMILY_RESIDUE", "1")
    os.environ.setdefault("CONSTRAINT_CONTINUE", "1")
    fz = A4Fuzzer(
        host_binary=_host_binary(),
        host_args=_host_args(),
        db_path=str(db_path),
        selector_strategy="bandit",
        seed=1234,
        b_count_override=16,
        telemetry_level="standard",
        verbose=False,
    )
    fz.run_campaign(n)


@pytest.mark.skipif(
    os.environ.get("A4_REAL_BINARY") != "1",
    reason="Set A4_REAL_BINARY=1 to run real-binary campaign smoke",
)
class TestD2BRealBinaryCampaign:
    def test_campaign_smoke(self):
        n = _smoke_n()
        db_env = os.environ.get("A4_SMOKE_DB", "").strip()
        strict = n >= 32

        if db_env:
            evaluate_campaign_db(db_env, n, strict=strict)
            return

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / f"d2b_smoke_bandit_seed1234_n{n}.db"
            _run_local_campaign(db_path, n)
            evaluate_campaign_db(str(db_path), n, strict=strict)
