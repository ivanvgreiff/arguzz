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
                config_json TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                num_failures INTEGER DEFAULT 0,
                verifier_accepted INTEGER DEFAULT 0,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            )
        """)
        
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
        # `address` is TEXT to uniformly hold memory addresses (decimal,
        # matching the C++ "%u" printf in ffi.cpp) and lookup indices.
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

        self.conn.commit()
    
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
        verifier_accepted: bool = False
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
            
        Returns:
            Mutation ID
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO mutations 
            (campaign_id, kind, step, txn_idx, mutated_value, config_json, executed_at, verifier_accepted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            campaign_id, kind, step, txn_idx, mutated_value,
            json.dumps(config), datetime.now().isoformat(), int(verifier_accepted)
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
