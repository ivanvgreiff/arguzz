"""
Coverage Database for Standalone A4 Fuzzing

SQLite-based tracking of:
- Fuzzing campaigns (metadata, configuration)
- Individual mutations (step, kind, value, config)
- Constraint failures (location, context)
- Coverage statistics (deduplicated by constraint location)
- Phase III.1: Global failures from Hook 3 (memory/u8/u16/cycle residues
  with per-address detail), keyed (mutation_id, family, address).

This enables coverage-guided fuzzing by tracking which constraints
have been hit and prioritizing mutations that explore new areas.
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from a4.core.constraint_parser import ConstraintFailure


@dataclass
class CampaignInfo:
    """Metadata about a fuzzing campaign"""
    id: int
    host_binary: str
    host_args: str  # JSON array
    kind: str
    seed: Optional[int]
    started_at: str
    ended_at: Optional[str]
    total_mutations: int
    unique_constraints: int


@dataclass
class MutationRecord:
    """Record of a single mutation attempt"""
    id: int
    campaign_id: int
    kind: str
    step: int
    txn_idx: Optional[int]
    mutated_value: int
    config_json: str
    executed_at: str
    num_failures: int
    verifier_accepted: bool


class CoverageDB:
    """
    SQLite database for tracking fuzzing coverage.
    
    Schema:
    - campaigns: Fuzzing campaign metadata
    - mutations: Individual mutation attempts
    - failures: Constraint failures from mutations
    - coverage: Deduplicated constraint coverage
    """
    
    def __init__(self, db_path: str):
        """
        Initialize or open the coverage database.
        
        Args:
            db_path: Path to SQLite database file (created if doesn't exist)
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
    
    def _init_schema(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Campaigns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_binary TEXT NOT NULL,
                host_args TEXT NOT NULL,
                kind TEXT NOT NULL,
                seed INTEGER,
                started_at TEXT NOT NULL,
                ended_at TEXT
            )
        """)
        
        # Mutations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mutations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                step INTEGER NOT NULL,
                txn_idx INTEGER,
                mutated_value INTEGER NOT NULL,
                original_value INTEGER NOT NULL DEFAULT 0,
                config_json TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                num_failures INTEGER DEFAULT 0,
                verifier_accepted INTEGER DEFAULT 0,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            )
        """)
        # Phase 7d (P2): add original_value to legacy DBs (pre-mutation txn.word).
        mut_cols = {row[1] for row in cursor.execute("PRAGMA table_info(mutations)")}
        if "original_value" not in mut_cols:
            cursor.execute(
                "ALTER TABLE mutations ADD COLUMN original_value INTEGER NOT NULL DEFAULT 0"
            )
            mut_cols.add("original_value")
        for col in ("proof_generated", "proof_verify_failed", "elapsed_ms"):
            if col not in mut_cols:
                cursor.execute(f"ALTER TABLE mutations ADD COLUMN {col} INTEGER")
        if "outcome" not in mut_cols:
            cursor.execute("ALTER TABLE mutations ADD COLUMN outcome TEXT")
            mut_cols.add("outcome")
        
        # Failures table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mutation_id INTEGER NOT NULL,
                constraint_type TEXT NOT NULL,
                constraint_loc TEXT NOT NULL,
                cycle INTEGER NOT NULL,
                step INTEGER NOT NULL,
                pc INTEGER NOT NULL,
                major INTEGER NOT NULL,
                minor INTEGER NOT NULL,
                value INTEGER NOT NULL,
                full_loc TEXT NOT NULL,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id)
            )
        """)
        
        # Coverage table (deduplicated by constraint_loc which includes file:line)
        # The line number IS semantically meaningful:
        # - IsRead@mem.zir:79 checks data_low (low 16 bits)
        # - IsRead@mem.zir:80 checks data_high (high 16 bits)
        # So different line numbers = different constraint checks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coverage (
                constraint_loc TEXT PRIMARY KEY,
                first_hit_mutation_id INTEGER NOT NULL,
                first_hit_at TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1,
                FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id)
            )
        """)
        
        # Phase III.1: Global failures table (Hook 3 family-level residues).
        # The (family, address) pair canonicalises a global failure key the
        # same way coverage_state.GlobalContext does: ("GLOBAL", family, addr).
        #
        # `address` is TEXT containing the Python repr (`str(addr)`) of the
        # address object returned by `coverage_state.derive_global_contexts()`
        # — NOT a numeric/decimal string. Observed stored formats per family
        # in our corpus (verified by direct SQL inspection on iv_pos_7 +
        # iv_pos_8 DBs, 2026-06-17 — only `memory` and `cycle` families have
        # been observed in this table to date; lookup families u8/u16 reach
        # `compressed_global_coverage` but not `global_failures` in any
        # campaign we have inspected):
        #   memory : "{'addr': N, 'byte_addr': N, 'type': 'data'|'word',
        #              'wrote': '0xHHHHHHHH', 'expected': ...|None,
        #              'mismatch_cycle': N}"
        #   cycle  : "{'index': N, 'plus': N, 'minus': N}"
        # Downstream analysis MUST parse with `ast.literal_eval()` and extract
        # the relevant field (e.g. `d['byte_addr']` for memory-family page-class
        # derivation — see a4/runs/iv_pos_7/analysis/cgc_variants.py
        # ::parse_memory_byte_addr). The earlier comment claimed `%u` decimal
        # matching ffi.cpp; that was Phase-III planning intent, never the
        # actual stored format.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS global_failures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mutation_id INTEGER NOT NULL,
                family TEXT NOT NULL,
                address TEXT NOT NULL,
                UNIQUE(mutation_id, family, address),
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)

        # Indices for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mutations_campaign 
            ON mutations(campaign_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mutations_outcome
            ON mutations(outcome)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_failures_mutation 
            ON failures(mutation_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_failures_constraint 
            ON failures(constraint_loc)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_failures_constraint_type 
            ON failures(constraint_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_gf_mut
            ON global_failures(mutation_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_gf_ctx
            ON global_failures(family, address)
        """)

        # Phase III.3: Per-run reward-component persistence.
        # One row per mutation that had compute_reward called for it
        # (i.e. coverage_state is not None). Mutations from campaigns
        # without coverage tracking simply have zero rows here, which
        # callers must handle via LEFT JOIN. ON DELETE CASCADE keeps
        # this in lockstep with the parent mutations row.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mutation_rewards (
                mutation_id INTEGER PRIMARY KEY,
                reward     REAL NOT NULL,
                T_new      REAL NOT NULL,
                T_rare     REAL NOT NULL,
                F_new      REAL NOT NULL,
                F_rare     REAL NOT NULL,
                U          INTEGER NOT NULL,
                Q_loc      REAL NOT NULL,
                Q_rep      REAL NOT NULL,
                Q_glob     REAL NOT NULL,
                Q          REAL NOT NULL,
                S          REAL NOT NULL,
                delta_T    INTEGER NOT NULL,
                delta_F    INTEGER NOT NULL,
                n_fail     INTEGER NOT NULL,
                r_rep      INTEGER NOT NULL,
                d_loc      INTEGER NOT NULL,
                d_glob     INTEGER NOT NULL,
                d_ext      INTEGER NOT NULL,
                mode       TEXT NOT NULL,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_mr_mut
            ON mutation_rewards(mutation_id)
        """)

        # Phase IV.0-prep: Per-campaign calibrated reward parameters.
        # tau_g and gamma in particular are needed by aggregation/notebooks
        # so they don't have to be reconstructed from terminal-log parsing.
        # One row per campaign (PRIMARY KEY enforces). All numeric fields
        # nullable because some selectors (uniform) don't run the bandit
        # pilot but still call coverage_state init with the same defaults.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_params (
                campaign_id INTEGER PRIMARY KEY,
                tau_new     REAL,
                tau_d       REAL,
                tau_g       REAL,
                gamma       REAL,
                K_T_rare    INTEGER,
                b_count     INTEGER,
                selector    TEXT,
                extra_json  TEXT,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            )
        """)

        # ====================================================================
        # cloud1 / IV.POS.7 schema additions (Pro ProG_Report_2.md §12)
        # All tables idempotent (CREATE TABLE IF NOT EXISTS); old IV.POS.5
        # DBs gain these tables on first open under the v2 codebase without
        # affecting existing data. Empty rows by default for legacy DBs.
        # ====================================================================

        # 1. bandit_decisions — one row per mutation under a bandit-style
        #    selector (cTS_semantic_v2, kindTS_zoned_v2, kindUCB_zoned_*).
        #    Captures Pro §12 "bandit_decisions" diagnostics:
        #    mutation_id, selected arm, coldstart vs adaptive, score,
        #    runner-up arm and score, exploration/exploitation flag.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bandit_decisions (
                mutation_id     INTEGER PRIMARY KEY,
                selected_arm    TEXT NOT NULL,
                mode            TEXT NOT NULL,
                score           REAL,
                runnerup_arm    TEXT,
                runnerup_score  REAL,
                exploration     INTEGER NOT NULL,
                extra_json      TEXT,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_bd_mode
            ON bandit_decisions(mode)
        """)

        # 2. arm_state_snapshot — periodic (every epoch_size mutations)
        #    snapshot of every arm's state. For Pro §12 "arm_state_log".
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS arm_state_snapshot (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id       INTEGER NOT NULL,
                mutation_idx      INTEGER NOT NULL,
                arm_id            TEXT NOT NULL,
                pulls             INTEGER NOT NULL,
                discounted_pulls  REAL,
                mean_reward       REAL,
                posterior_alpha   REAL,
                posterior_beta    REAL,
                ts_extra_json     TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_arm_snap_camp_mut
            ON arm_state_snapshot(campaign_id, mutation_idx)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_arm_snap_arm
            ON arm_state_snapshot(arm_id)
        """)

        # 3. reward_counterfactuals — for EVERY mutation, what each of the
        #    candidate rewards would have computed. Lets us back-test reward
        #    variants without re-running. Pro §12 "reward_counterfactuals".
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reward_counterfactuals (
                mutation_id                INTEGER PRIMARY KEY,
                current_reward             REAL NOT NULL,
                no_qloc_reward             REAL NOT NULL,
                fnew_only_reward           REAL NOT NULL,
                discovery_binary_reward    INTEGER NOT NULL,
                compressed_global_reward   REAL NOT NULL,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)
        rc_cols = {
            row[1] for row in cursor.execute("PRAGMA table_info(reward_counterfactuals)")
        }
        for col in (
            "bandit_success_l1",
            "l1_substrategy_uniqueness",
            "l1_d_loc_le_2",
            "l1_singleton_failure",
        ):
            if col not in rc_cols:
                cursor.execute(
                    f"ALTER TABLE reward_counterfactuals ADD COLUMN {col} INTEGER"
                )

        # 4. mutation_substrategy — kind-specific decomposition of what
        #    exactly was mutated. For INSTR_WORD_MOD_SUR this captures
        #    funct3/funct7/etc.; for MEM_VAL_MOD: byte_lane; etc.
        #    All fields nullable since each kind populates only its own.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mutation_substrategy (
                mutation_id  INTEGER PRIMARY KEY,
                opcode       INTEGER,
                rd           INTEGER,
                rs1          INTEGER,
                rs2          INTEGER,
                funct3       INTEGER,
                funct7       INTEGER,
                imm          INTEGER,
                byte_lane    INTEGER,
                bit_mask     INTEGER,
                value_class  TEXT,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)

        # 5. hook3_raw — per-mutation raw Hook 3 family payload + compressed
        #    context. `raw_json` is a JSON list of {family,address,...}; the
        #    `compressed_ctx_json` is a JSON list of the
        #    GlobalMemoryCtx/GlobalLookupCtx contexts emitted by the
        #    Phase 3 extractor. For Pro §12 "hook3_raw_or_semantic".
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hook3_raw (
                mutation_id          INTEGER PRIMARY KEY,
                raw_json             TEXT,
                compressed_ctx_json  TEXT,
                FOREIGN KEY (mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)

        # 6. pilot_runs — raw pilot observations and resulting calibrated
        #    params, in case we ever re-introduce calibration. For IV.POS.7
        #    (per cloud1 D2) this table will stay empty because pilot
        #    calibration is REMOVED for all 5 v2 variants. The schema is
        #    created for forward-compat. Pro §12 "pilot_runs".
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pilot_runs (
                id                          INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id                 INTEGER NOT NULL,
                pilot_idx                   INTEGER NOT NULL,
                raw_pilot_observation_json  TEXT,
                calibrated_params_json      TEXT,
                recorded_at                 TEXT NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pilot_camp
            ON pilot_runs(campaign_id)
        """)

        # 7. compressed_global_coverage — first-hit table for compressed
        #    global contexts. Analog of existing `coverage` table but for
        #    GlobalMemoryCtx / GlobalLookupCtx. `ctx_key` is a stable
        #    string serialization (see GlobalMemoryCtx.to_json_str()).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS compressed_global_coverage (
                ctx_key                 TEXT NOT NULL,
                campaign_id             INTEGER NOT NULL,
                first_hit_mutation_id   INTEGER NOT NULL,
                family                  TEXT NOT NULL,
                ctx_json                TEXT NOT NULL,
                first_hit_at            TEXT NOT NULL,
                hit_count               INTEGER DEFAULT 1,
                PRIMARY KEY (ctx_key, campaign_id),
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
                FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cgc_campaign
            ON compressed_global_coverage(campaign_id)
        """)

        # 8. local_coverage_v2 — extends the existing `coverage` table to
        #    include `major` and `minor` columns. Pro §6.1 defines the new
        #    local context as `(constraint_loc, major, minor)`, which is
        #    finer-grained than the existing `coverage.constraint_loc`.
        #    The legacy `coverage` table is unchanged; this is an additive
        #    secondary index for the v2 reward function's L_new term.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS local_coverage_v2 (
                ctx_key                 TEXT NOT NULL,
                campaign_id             INTEGER NOT NULL,
                first_hit_mutation_id   INTEGER NOT NULL,
                constraint_loc          TEXT NOT NULL,
                major                   INTEGER NOT NULL,
                minor                   INTEGER NOT NULL,
                first_hit_at            TEXT NOT NULL,
                hit_count               INTEGER DEFAULT 1,
                PRIMARY KEY (ctx_key, campaign_id),
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
                FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_lcv2_campaign
            ON local_coverage_v2(campaign_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_lcv2_loc
            ON local_coverage_v2(constraint_loc)
        """)

        self.conn.commit()

    # ========================================================================
    # cloud1 / IV.POS.7 record_* methods
    # ========================================================================

    def record_bandit_decision(
        self,
        mutation_id: int,
        selected_arm: str,
        mode: str,
        score: Optional[float] = None,
        runnerup_arm: Optional[str] = None,
        runnerup_score: Optional[float] = None,
        exploration: bool = False,
        extra: Optional[dict] = None,
    ) -> None:
        """Insert one row into `bandit_decisions` (Pro §12)."""
        extra_json = json.dumps(extra, sort_keys=True) if extra is not None else None
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO bandit_decisions
                (mutation_id, selected_arm, mode, score,
                 runnerup_arm, runnerup_score, exploration, extra_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (mutation_id, selected_arm, mode, score,
              runnerup_arm, runnerup_score, 1 if exploration else 0, extra_json))
        self.conn.commit()

    def record_arm_state_snapshot(
        self,
        campaign_id: int,
        mutation_idx: int,
        arm_states: List[dict],
    ) -> None:
        """Batch-insert a list of arm-state rows (Pro §12 'arm_state_log').

        `arm_states` is a list of dicts with keys:
          arm_id, pulls, discounted_pulls, mean_reward,
          posterior_alpha, posterior_beta, ts_extra (optional dict).
        Missing optional fields are stored as NULL.
        """
        cursor = self.conn.cursor()
        rows = []
        for s in arm_states:
            rows.append((
                campaign_id,
                mutation_idx,
                s["arm_id"],
                int(s["pulls"]),
                s.get("discounted_pulls"),
                s.get("mean_reward"),
                s.get("posterior_alpha"),
                s.get("posterior_beta"),
                json.dumps(s["ts_extra"], sort_keys=True) if s.get("ts_extra") else None,
            ))
        cursor.executemany("""
            INSERT INTO arm_state_snapshot
                (campaign_id, mutation_idx, arm_id, pulls, discounted_pulls,
                 mean_reward, posterior_alpha, posterior_beta, ts_extra_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        self.conn.commit()

    def record_reward_counterfactuals(
        self,
        mutation_id: int,
        current_reward: float,
        no_qloc_reward: float,
        fnew_only_reward: float,
        discovery_binary_reward: int,
        compressed_global_reward: float,
        *,
        bandit_success_l1: Optional[int] = None,
        l1_substrategy_uniqueness: Optional[int] = None,
        l1_d_loc_le_2: Optional[int] = None,
        l1_singleton_failure: Optional[int] = None,
    ) -> None:
        """Insert one row into `reward_counterfactuals` (Pro §12)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO reward_counterfactuals
                (mutation_id, current_reward, no_qloc_reward,
                 fnew_only_reward, discovery_binary_reward,
                 compressed_global_reward,
                 bandit_success_l1, l1_substrategy_uniqueness,
                 l1_d_loc_le_2, l1_singleton_failure)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (mutation_id, current_reward, no_qloc_reward,
              fnew_only_reward, int(discovery_binary_reward),
              compressed_global_reward,
              bandit_success_l1, l1_substrategy_uniqueness,
              l1_d_loc_le_2, l1_singleton_failure))
        self.conn.commit()

    def record_mutation_substrategy(
        self,
        mutation_id: int,
        opcode: Optional[int] = None,
        rd: Optional[int] = None,
        rs1: Optional[int] = None,
        rs2: Optional[int] = None,
        funct3: Optional[int] = None,
        funct7: Optional[int] = None,
        imm: Optional[int] = None,
        byte_lane: Optional[int] = None,
        bit_mask: Optional[int] = None,
        value_class: Optional[str] = None,
    ) -> None:
        """Insert one row into `mutation_substrategy` (Pro §12)."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO mutation_substrategy
                (mutation_id, opcode, rd, rs1, rs2, funct3, funct7,
                 imm, byte_lane, bit_mask, value_class)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (mutation_id, opcode, rd, rs1, rs2, funct3, funct7,
              imm, byte_lane, bit_mask, value_class))
        self.conn.commit()

    def record_hook3_raw(
        self,
        mutation_id: int,
        raw_entries: Optional[list] = None,
        compressed_ctx_list: Optional[list] = None,
    ) -> None:
        """Insert one row into `hook3_raw` (Pro §12)."""
        raw_json = json.dumps(raw_entries, sort_keys=True) if raw_entries is not None else None
        compressed_json = (
            json.dumps(compressed_ctx_list, sort_keys=True)
            if compressed_ctx_list is not None else None
        )
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO hook3_raw
                (mutation_id, raw_json, compressed_ctx_json)
            VALUES (?, ?, ?)
        """, (mutation_id, raw_json, compressed_json))
        self.conn.commit()

    def record_pilot_run(
        self,
        campaign_id: int,
        pilot_idx: int,
        raw_pilot_observation: Optional[dict] = None,
        calibrated_params: Optional[dict] = None,
    ) -> None:
        """Insert one row into `pilot_runs` (Pro §12).

        For IV.POS.7 (cloud1 D2: pilot REMOVED) this method will not be
        called by any v2 variant. Present for forward-compat / legacy.
        """
        raw_json = json.dumps(raw_pilot_observation, sort_keys=True) if raw_pilot_observation else None
        cal_json = json.dumps(calibrated_params, sort_keys=True) if calibrated_params else None
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO pilot_runs
                (campaign_id, pilot_idx, raw_pilot_observation_json,
                 calibrated_params_json, recorded_at)
            VALUES (?, ?, ?, ?, ?)
        """, (campaign_id, pilot_idx, raw_json, cal_json,
              datetime.now().isoformat()))
        self.conn.commit()

    def record_compressed_global_first_hit(
        self,
        campaign_id: int,
        mutation_id: int,
        ctx_key: str,
        family: str,
        ctx_json: str,
    ) -> bool:
        """Record a compressed-global context first-hit.

        Returns True if the context was new (i.e. this is a first hit),
        False if it had been seen before (in which case `hit_count` is
        incremented).
        """
        cursor = self.conn.cursor()
        # Check existing
        existing = cursor.execute(
            "SELECT 1 FROM compressed_global_coverage WHERE ctx_key=? AND campaign_id=?",
            (ctx_key, campaign_id),
        ).fetchone()
        if existing is None:
            cursor.execute("""
                INSERT INTO compressed_global_coverage
                    (ctx_key, campaign_id, first_hit_mutation_id,
                     family, ctx_json, first_hit_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (ctx_key, campaign_id, mutation_id, family, ctx_json,
                  datetime.now().isoformat()))
            self.conn.commit()
            return True
        else:
            cursor.execute("""
                UPDATE compressed_global_coverage
                SET hit_count = hit_count + 1
                WHERE ctx_key=? AND campaign_id=?
            """, (ctx_key, campaign_id))
            self.conn.commit()
            return False

    def record_local_v2_first_hit(
        self,
        campaign_id: int,
        mutation_id: int,
        constraint_loc: str,
        major: int,
        minor: int,
    ) -> bool:
        """Record a local-v2 context (constraint_loc, major, minor) first-hit.

        Returns True if new (first hit), False if previously seen.
        """
        ctx_key = f"{constraint_loc}|{major}|{minor}"
        cursor = self.conn.cursor()
        existing = cursor.execute(
            "SELECT 1 FROM local_coverage_v2 WHERE ctx_key=? AND campaign_id=?",
            (ctx_key, campaign_id),
        ).fetchone()
        if existing is None:
            cursor.execute("""
                INSERT INTO local_coverage_v2
                    (ctx_key, campaign_id, first_hit_mutation_id,
                     constraint_loc, major, minor, first_hit_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (ctx_key, campaign_id, mutation_id, constraint_loc,
                  int(major), int(minor), datetime.now().isoformat()))
            self.conn.commit()
            return True
        else:
            cursor.execute("""
                UPDATE local_coverage_v2 SET hit_count = hit_count + 1
                WHERE ctx_key=? AND campaign_id=?
            """, (ctx_key, campaign_id))
            self.conn.commit()
            return False
    
    def start_campaign(
        self, 
        host_binary: str, 
        host_args: List[str], 
        kind: str,
        seed: Optional[int] = None
    ) -> int:
        """
        Start a new fuzzing campaign.
        
        Args:
            host_binary: Path to risc0-host binary
            host_args: Arguments for risc0-host
            kind: Mutation kind (COMP_OUT_MOD, etc.) or "all"
            seed: Optional random seed for reproducibility
            
        Returns:
            Campaign ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO campaigns (host_binary, host_args, kind, seed, started_at)
            VALUES (?, ?, ?, ?, ?)
        """, (host_binary, json.dumps(host_args), kind, seed, datetime.now().isoformat()))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def end_campaign(self, campaign_id: int):
        """Mark a campaign as ended"""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE campaigns SET ended_at = ? WHERE id = ?
        """, (datetime.now().isoformat(), campaign_id))
        self.conn.commit()
    
    def record_mutation(
        self,
        campaign_id: int,
        kind: str,
        step: int,
        mutated_value: int,
        config: dict,
        txn_idx: Optional[int] = None,
        verifier_accepted: bool = False,
        original_value: int = 0,
        *,
        proof_generated: Optional[bool] = None,
        proof_verify_failed: Optional[bool] = None,
        elapsed_ms: Optional[int] = None,
        outcome: Optional[str] = None,
    ) -> int:
        """
        Record a mutation attempt.
        
        Args:
            campaign_id: Campaign this mutation belongs to
            kind: Mutation kind
            step: Target step
            mutated_value: The mutated value used
            config: Full config dict (will be JSON serialized)
            txn_idx: Transaction index (if applicable)
            verifier_accepted: Whether the verifier accepted the proof
            original_value: Pre-mutation txn.word (or encoded major/minor for INSTR_TYPE_MOD)
            proof_generated: Whether a proof was generated (IV.POS.8 D1.A)
            proof_verify_failed: Whether proof verification failed (IV.POS.8 D1.A)
            elapsed_ms: Wall-clock execution time in milliseconds (IV.POS.8 D1.A)
            outcome: Mutation outcome (IV.POS.8 D2.A): applied / skipped / error
            
        Returns:
            Mutation ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO mutations 
            (campaign_id, kind, step, txn_idx, mutated_value, original_value,
             config_json, executed_at, verifier_accepted,
             proof_generated, proof_verify_failed, elapsed_ms, outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign_id, kind, step, txn_idx, mutated_value, int(original_value),
            json.dumps(config), datetime.now().isoformat(), int(verifier_accepted),
            (int(proof_generated) if proof_generated is not None else None),
            (int(proof_verify_failed) if proof_verify_failed is not None else None),
            elapsed_ms,
            outcome,
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def record_failures(
        self, 
        mutation_id: int, 
        failures: List[ConstraintFailure]
    ) -> Tuple[int, int]:
        """
        Record constraint failures from a mutation.
        
        Args:
            mutation_id: The mutation that caused these failures
            failures: List of ConstraintFailure objects
            
        Returns:
            Tuple of (total_recorded, new_coverage_count)
        """
        cursor = self.conn.cursor()
        new_coverage = 0
        now = datetime.now().isoformat()
        
        for failure in failures:
            # Record the failure with both constraint_type and constraint_loc
            # constraint_loc includes file:line which IS semantically meaningful
            # (e.g., line 79 checks data_low, line 80 checks data_high)
            cursor.execute("""
                INSERT INTO failures 
                (mutation_id, constraint_type, constraint_loc, cycle, step, pc, major, minor, value, full_loc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mutation_id, failure.constraint_type(), failure.constraint_loc(), failure.cycle,
                failure.step, failure.pc, failure.major, failure.minor,
                failure.value, failure.loc
            ))
            
            # Update coverage using constraint_loc (includes file:line)
            # Different line numbers = different constraint checks
            # Two-step approach: INSERT OR IGNORE to detect new, then UPDATE for existing.
            # SQLite's ON CONFLICT DO UPDATE returns rowcount=1 for both insert and update,
            # so we cannot use it to distinguish new vs existing (Phase II bug fix).
            cursor.execute("""
                INSERT OR IGNORE INTO coverage (constraint_loc, first_hit_mutation_id, first_hit_at, hit_count)
                VALUES (?, ?, ?, 1)
            """, (failure.constraint_loc(), mutation_id, now))
            if cursor.rowcount == 1:
                new_coverage += 1
            else:
                cursor.execute("""
                    UPDATE coverage SET hit_count = hit_count + 1 WHERE constraint_loc = ?
                """, (failure.constraint_loc(),))
        
        # Update mutation's num_failures
        cursor.execute("""
            UPDATE mutations SET num_failures = ? WHERE id = ?
        """, (len(failures), mutation_id))
        
        self.conn.commit()
        return len(failures), new_coverage
    
    def get_coverage_stats(self) -> Dict:
        """
        Get overall coverage statistics.
        
        Returns:
            Dict with coverage statistics
        """
        cursor = self.conn.cursor()
        
        # Total unique constraints hit
        cursor.execute("SELECT COUNT(*) FROM coverage")
        total_constraints = cursor.fetchone()[0]
        
        # Total mutations
        cursor.execute("SELECT COUNT(*) FROM mutations")
        total_mutations = cursor.fetchone()[0]
        
        # Total failures
        cursor.execute("SELECT COUNT(*) FROM failures")
        total_failures = cursor.fetchone()[0]
        
        # Mutations by kind
        cursor.execute("""
            SELECT kind, COUNT(*) as count FROM mutations GROUP BY kind
        """)
        mutations_by_kind = {row['kind']: row['count'] for row in cursor.fetchall()}
        
        # Top 10 most-hit constraints (by location)
        cursor.execute("""
            SELECT constraint_loc, hit_count FROM coverage 
            ORDER BY hit_count DESC LIMIT 10
        """)
        top_constraints = [(row['constraint_loc'], row['hit_count']) for row in cursor.fetchall()]
        
        # Verifier acceptance rate
        cursor.execute("""
            SELECT 
                SUM(verifier_accepted) as accepted,
                COUNT(*) as total
            FROM mutations
        """)
        row = cursor.fetchone()
        acceptance_rate = row['accepted'] / row['total'] if row['total'] > 0 else 0
        
        return {
            "total_constraints": total_constraints,
            "total_mutations": total_mutations,
            "total_failures": total_failures,
            "mutations_by_kind": mutations_by_kind,
            "top_constraints": top_constraints,
            "verifier_acceptance_rate": acceptance_rate,
        }
    
    def get_uncovered_constraint_patterns(self) -> List[str]:
        """
        Get constraint types NOT yet covered.
        
        This is useful for guiding fuzzing toward unexplored areas.
        Returns constraint types that could be targeted.
        
        Note: This is a heuristic - we don't know all possible constraints,
        but we can identify types we haven't hit yet based on what we have.
        """
        cursor = self.conn.cursor()
        
        # Get all unique constraint types we've seen (extract from constraint_loc)
        cursor.execute("""
            SELECT DISTINCT 
                substr(constraint_loc, 1, instr(constraint_loc, '@') - 1) as constraint_type
            FROM coverage
            WHERE constraint_loc LIKE '%@%'
        """)
        seen_types = {row['constraint_type'] for row in cursor.fetchall() if row['constraint_type']}
        
        # Known constraint types from RISC Zero
        known_types = {
            'MemoryWrite', 'IsRead', 'VerifyOpcodeF3', 'VerifyOpcodeF7',
            'VerifyFunc3', 'VerifyFunc7', 'CheckPCAlign', 'CheckAddrAlign',
        }
        
        return list(known_types - seen_types)
    
    def get_campaign_info(self, campaign_id: int) -> Optional[CampaignInfo]:
        """Get info about a specific campaign"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT c.*, 
                   (SELECT COUNT(*) FROM mutations WHERE campaign_id = c.id) as total_mutations,
                   (SELECT COUNT(DISTINCT constraint_loc) FROM failures f 
                    JOIN mutations m ON f.mutation_id = m.id 
                    WHERE m.campaign_id = c.id) as unique_constraints
            FROM campaigns c WHERE c.id = ?
        """, (campaign_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        return CampaignInfo(
            id=row['id'],
            host_binary=row['host_binary'],
            host_args=row['host_args'],
            kind=row['kind'],
            seed=row['seed'],
            started_at=row['started_at'],
            ended_at=row['ended_at'],
            total_mutations=row['total_mutations'],
            unique_constraints=row['unique_constraints'],
        )

    def get_last_campaign_id(self) -> Optional[int]:
        """Return the most recent campaign id, or None if no campaigns exist."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM campaigns ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return int(row["id"]) if row else None

    def get_distinct_context_ids_for_campaign(self, campaign_id: int) -> Set[Tuple[str, int, int]]:
        """
        Return the set of distinct (constraint_loc, major, minor) for all failures in a campaign.

        Used for Phase 0.2: K_total = len(get_distinct_context_ids_for_campaign(cid)).
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT DISTINCT f.constraint_loc, f.major, f.minor
            FROM failures f
            JOIN mutations m ON f.mutation_id = m.id
            WHERE m.campaign_id = ?
        """, (campaign_id,))
        return {(row["constraint_loc"], row["major"], row["minor"]) for row in cursor.fetchall()}

    def get_distinct_context_id_counts_per_mutation(self, campaign_id: int) -> List[Tuple[int, int]]:
        """
        Return [(mutation_id, distinct_context_id_count)] for each mutation in the campaign.

        Used for Phase 0.2 per-run stats (min/max/mean distinct context_id per run).
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM mutations WHERE campaign_id = ? ORDER BY id",
            (campaign_id,),
        )
        mutation_ids = [row["id"] for row in cursor.fetchall()]
        result = []
        for mid in mutation_ids:
            cursor.execute(
                "SELECT constraint_loc, major, minor FROM failures WHERE mutation_id = ?",
                (mid,),
            )
            rows = cursor.fetchall()
            distinct = len({(r["constraint_loc"], r["major"], r["minor"]) for r in rows})
            result.append((mid, distinct))
        return result

    def get_mutations_hitting_constraint(self, constraint_loc: str) -> List[MutationRecord]:
        """Get all mutations that hit a specific constraint location"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT m.* FROM mutations m
            JOIN failures f ON f.mutation_id = m.id
            WHERE f.constraint_loc = ?
            ORDER BY m.executed_at
        """, (constraint_loc,))
        
        return [MutationRecord(
            id=row['id'],
            campaign_id=row['campaign_id'],
            kind=row['kind'],
            step=row['step'],
            txn_idx=row['txn_idx'],
            mutated_value=row['mutated_value'],
            config_json=row['config_json'],
            executed_at=row['executed_at'],
            num_failures=row['num_failures'],
            verifier_accepted=bool(row['verifier_accepted']),
        ) for row in cursor.fetchall()]
    
    # =========================================================================
    # Phase III.1: Global failures (Hook 3 family residues + per-address detail)
    # =========================================================================

    def record_global_failures(
        self,
        mutation_id: int,
        global_contexts,
    ) -> int:
        """
        Bulk-insert global-failure rows for a single mutation.

        Args:
            mutation_id: parent mutation id (foreign key)
            global_contexts: iterable of canonical 3-tuples
                ("GLOBAL", family: str, address: str), as produced by
                a4.standalone.coverage_state.derive_global_contexts().
                Empty / None is a valid no-op.

        The UNIQUE(mutation_id, family, address) constraint plus
        INSERT OR IGNORE makes this idempotent: re-inserting the same
        key for the same mutation is a silent no-op.

        Returns:
            Number of rows actually inserted (excludes IGNOREd duplicates).
        """
        if not global_contexts:
            return 0

        rows = []
        for ctx in global_contexts:
            # Defensive: tolerate either ("GLOBAL", family, addr) or (family, addr).
            if len(ctx) == 3 and ctx[0] == "GLOBAL":
                _, family, addr = ctx
            elif len(ctx) == 2:
                family, addr = ctx
            else:
                continue
            rows.append((mutation_id, family, str(addr)))

        if not rows:
            return 0

        cursor = self.conn.cursor()
        cursor.executemany(
            """
            INSERT OR IGNORE INTO global_failures (mutation_id, family, address)
            VALUES (?, ?, ?)
            """,
            rows,
        )
        inserted = cursor.rowcount
        self.conn.commit()
        return inserted

    def get_global_contexts_for_campaign(
        self, campaign_id: int
    ) -> Set[Tuple[str, str]]:
        """
        Return the set of distinct (family, address) pairs over all global
        failures recorded against any mutation in this campaign.

        Note: returns 2-tuples, not the canonical 3-tuple. To rebuild the
        canonical key, prepend "GLOBAL" or use get_extended_contexts_for_campaign.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT DISTINCT g.family, g.address
            FROM global_failures g
            JOIN mutations m ON g.mutation_id = m.id
            WHERE m.campaign_id = ?
            """,
            (campaign_id,),
        )
        return {(row["family"], row["address"]) for row in cursor.fetchall()}

    def get_extended_contexts_for_campaign(
        self, campaign_id: int
    ) -> Set[Tuple]:
        """
        Return the EXTENDED context set for a campaign:
            { (constraint_loc, major: int, minor: int)            for each local }
          ∪ { ("GLOBAL", family: str, address: str)               for each global }

        This matches the F_ext set semantics used by Phase III.0
        (coverage_state.compute_reward / update_state).
        """
        local = self.get_distinct_context_ids_for_campaign(campaign_id)
        global_pairs = self.get_global_contexts_for_campaign(campaign_id)
        ext: Set[Tuple] = set(local)
        for family, addr in global_pairs:
            ext.add(("GLOBAL", family, addr))
        return ext

    def get_global_failure_counts_per_mutation(
        self, campaign_id: int
    ) -> List[Tuple[int, int]]:
        """
        Return [(mutation_id, distinct_global_contexts_count), ...] for every
        mutation in the campaign, in mutation_id order. Mutations with zero
        global failures still appear with count 0 (LEFT JOIN).

        Used by the boss notebook for per-run plots and the precloud
        validation campaign.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT m.id AS mid,
                   COUNT(DISTINCT g.family || ':' || g.address) AS n
            FROM mutations m
            LEFT JOIN global_failures g ON g.mutation_id = m.id
            WHERE m.campaign_id = ?
            GROUP BY m.id
            ORDER BY m.id
            """,
            (campaign_id,),
        )
        return [(int(row["mid"]), int(row["n"])) for row in cursor.fetchall()]

    # =========================================================================
    # Phase III.3: Per-run reward-component persistence
    # =========================================================================

    def record_reward_diag(
        self,
        mutation_id: int,
        diag: dict,
    ) -> None:
        """
        Persist the reward-diagnostic dict produced by compute_reward.

        Phase III.3: SQLite-authoritative store for per-run reward
        components. Called from fuzzer._run_bandit_mutation and
        fuzzer._run_single_mutation IFF coverage tracking is enabled
        (i.e. self.coverage_state is not None) and compute_reward was
        invoked.

        Args:
            mutation_id: parent mutation id (foreign key into `mutations`)
            diag: the diag dict returned by compute_reward. Must contain
                  all 19 fields listed in the Phase III.3 schema; missing
                  fields raise KeyError to fail loudly rather than silently
                  insert defaults.

        Uses INSERT OR REPLACE so a defensive re-call with the same
        mutation_id (e.g. from a retry) overwrites instead of erroring.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO mutation_rewards
            (mutation_id, reward, T_new, T_rare, F_new, F_rare, U,
             Q_loc, Q_rep, Q_glob, Q, S,
             delta_T, delta_F, n_fail, r_rep,
             d_loc, d_glob, d_ext, mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mutation_id,
                float(diag["r"]),
                float(diag["T_new"]),
                float(diag["T_rare"]),
                float(diag["F_new"]),
                float(diag["F_rare"]),
                int(diag["U"]),
                float(diag["Q_loc"]),
                float(diag["Q_rep"]),
                float(diag["Q_glob"]),
                float(diag["Q"]),
                float(diag["S"]),
                int(diag["delta_T"]),
                int(diag["delta_F"]),
                int(diag["n_fail"]),
                int(diag["r_rep"]),
                int(diag["d_loc"]),
                int(diag["d_glob"]),
                int(diag["d_ext"]),
                str(diag["mode"]),
            ),
        )
        self.conn.commit()

    def get_reward_diag_for_campaign(
        self,
        campaign_id: int,
    ) -> List[dict]:
        """
        Return all reward-diagnostic rows for a campaign, in mutation_id
        order (= insertion order = chronological order).

        Each entry is a dict containing every column of the
        `mutation_rewards` row. Mutations without a reward row (e.g.
        crash-only campaigns, pre-III.3 DBs being re-read, or a
        --selector run without coverage tracking) are absent from the
        result rather than appearing as nulls.

        Used by Phase IV.2 cloud aggregation as the SQL-authoritative
        replacement for parsing terminal log files.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT mr.*
            FROM mutation_rewards mr
            JOIN mutations m ON mr.mutation_id = m.id
            WHERE m.campaign_id = ?
            ORDER BY mr.mutation_id
            """,
            (campaign_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def record_campaign_params(
        self,
        campaign_id: int,
        *,
        tau_new: Optional[float] = None,
        tau_d: Optional[float] = None,
        tau_g: Optional[float] = None,
        gamma: Optional[float] = None,
        K_T_rare: Optional[int] = None,
        b_count: Optional[int] = None,
        selector: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """
        Persist the calibrated CalibratedParams + bandit knobs used for one
        campaign. Idempotent on (campaign_id): re-calling overwrites.

        Why: tau_g and gamma are needed by Phase IV.2 aggregation and the
        Phase IV.2.5 boss notebook so they don't have to be reconstructed
        from terminal-log parsing (which is fragile across config changes).

        Pre-IV.0 campaigns (where this method was never called) simply
        have no row, and callers should fall back to defaults or the
        terminal-log parser as needed.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO campaign_params (
                campaign_id, tau_new, tau_d, tau_g, gamma,
                K_T_rare, b_count, selector, extra_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                campaign_id,
                tau_new, tau_d, tau_g, gamma,
                K_T_rare, b_count, selector,
                json.dumps(extra) if extra else None,
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

    def get_campaign_params(self, campaign_id: int) -> Optional[dict]:
        """Return the campaign_params row, or None if not persisted."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM campaign_params WHERE campaign_id = ?",
            (campaign_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        d = dict(row)
        if d.get("extra_json"):
            try:
                d["extra"] = json.loads(d["extra_json"])
            except (json.JSONDecodeError, TypeError):
                d["extra"] = None
        return d

    def close(self):
        """Close the database connection"""
        self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
