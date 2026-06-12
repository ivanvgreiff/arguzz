"""SQLite storage for bias campaign runs."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable, List, Optional

from thesis_side_experiments.bias_campaign.run_common import RunRecord


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    fuzzer TEXT NOT NULL,
    guest TEXT NOT NULL,
    kind TEXT NOT NULL,
    seed INTEGER NOT NULL,
    inject_step INTEGER,
    target_desc TEXT,
    outcome_class TEXT NOT NULL,
    constraint_fail_count INTEGER NOT NULL,
    fail_L1 INTEGER NOT NULL,
    fail_L2 INTEGER NOT NULL,
    fail_ACCUM INTEGER NOT NULL,
    global_any INTEGER NOT NULL,
    global_families_json TEXT,
    target_L1 INTEGER NOT NULL,
    target_L2 INTEGER NOT NULL,
    target_ACCUM INTEGER NOT NULL,
    verifier_success INTEGER NOT NULL,
    injected INTEGER NOT NULL,
    soundness_escape INTEGER NOT NULL,
    panic_loc TEXT,
    runtime_ms INTEGER NOT NULL,
    raw_log_path TEXT,
    skipped INTEGER NOT NULL DEFAULT 0,
    skip_reason TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    constraint_type TEXT,
    constraint_loc TEXT,
    cycle INTEGER,
    step INTEGER,
    pc INTEGER,
    major INTEGER,
    minor INTEGER,
    value INTEGER,
    full_loc TEXT,
    phase TEXT,
    category TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS global_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    family TEXT,
    address INTEGER,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
"""


class CampaignDB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def insert_run(self, record: RunRecord) -> int:
        from thesis_side_experiments.bias_campaign.run_common import (
            failure_rows,
            global_failure_rows,
        )

        o = record.outcome
        gf = record.global_families
        cur = self.conn.execute(
            """
            INSERT INTO runs (
                fuzzer, guest, kind, seed, inject_step, target_desc,
                outcome_class, constraint_fail_count,
                fail_L1, fail_L2, fail_ACCUM, global_any, global_families_json,
                target_L1, target_L2, target_ACCUM,
                verifier_success, injected, soundness_escape, panic_loc,
                runtime_ms, raw_log_path, skipped, skip_reason
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                record.fuzzer,
                record.guest,
                record.kind,
                record.seed,
                record.inject_step,
                record.target_desc,
                o.outcome_class,
                len(o.failures),
                record.fail_categories.get("L1", 0),
                record.fail_categories.get("L2", 0),
                record.fail_categories.get("ACCUM", 0),
                int(gf.get("any", False)),
                json.dumps(gf),
                record.target_categories.get("L1", 0),
                record.target_categories.get("L2", 0),
                record.target_categories.get("ACCUM", 0),
                int(o.verifier_success),
                int(o.injected),
                int(o.soundness_escape),
                o.panic_loc,
                record.runtime_ms,
                record.raw_log_path,
                int(record.skipped),
                record.skip_reason,
            ),
        )
        run_id = cur.lastrowid
        for row in failure_rows(o):
            self.conn.execute(
                """
                INSERT INTO failures (
                    run_id, constraint_type, constraint_loc, cycle, step, pc,
                    major, minor, value, full_loc, phase, category
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    row["constraint_type"],
                    row["constraint_loc"],
                    row["cycle"],
                    row["step"],
                    row["pc"],
                    row["major"],
                    row["minor"],
                    row["value"],
                    row["full_loc"],
                    row["phase"],
                    row["category"],
                ),
            )
        for row in global_failure_rows(o):
            self.conn.execute(
                "INSERT INTO global_failures (run_id, family, address) VALUES (?,?,?)",
                (run_id, row["family"], row["address"]),
            )
        self.conn.commit()
        return run_id

    def fetch_all_runs(self) -> List[dict]:
        cur = self.conn.execute("SELECT * FROM runs WHERE skipped=0")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_runs(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM runs WHERE skipped=0").fetchone()[0]
