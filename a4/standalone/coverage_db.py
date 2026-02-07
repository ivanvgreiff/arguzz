"""
Coverage Database for Standalone A4 Fuzzing

SQLite-based tracking of:
- Fuzzing campaigns (metadata, configuration)
- Individual mutations (step, kind, value, config)
- Constraint failures (location, context)
- Coverage statistics (deduplicated by constraint location)

This enables coverage-guided fuzzing by tracking which constraints
have been hit and prioritizing mutations that explore new areas.
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        
        # Coverage table (deduplicated by constraint_loc)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coverage (
                constraint_loc TEXT PRIMARY KEY,
                first_hit_mutation_id INTEGER NOT NULL,
                first_hit_at TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1,
                FOREIGN KEY (first_hit_mutation_id) REFERENCES mutations(id)
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
            # Record the failure
            cursor.execute("""
                INSERT INTO failures 
                (mutation_id, constraint_loc, cycle, step, pc, major, minor, value, full_loc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                mutation_id, failure.constraint_loc(), failure.cycle,
                failure.step, failure.pc, failure.major, failure.minor,
                failure.value, failure.loc
            ))
            
            # Update coverage (insert or increment)
            cursor.execute("""
                INSERT INTO coverage (constraint_loc, first_hit_mutation_id, first_hit_at, hit_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(constraint_loc) DO UPDATE SET hit_count = hit_count + 1
            """, (failure.constraint_loc(), mutation_id, now))
            
            # Check if this was a new coverage entry
            if cursor.rowcount == 1:  # INSERT happened, not UPDATE
                new_coverage += 1
        
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
        
        # Top 10 most-hit constraints
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
        Get patterns of constraints NOT yet covered.
        
        This is useful for guiding fuzzing toward unexplored areas.
        Returns constraint location patterns that could be targeted.
        
        Note: This is a heuristic - we don't know all possible constraints,
        but we can identify patterns we haven't hit yet based on what we have.
        """
        cursor = self.conn.cursor()
        
        # Get all unique constraint prefixes we've seen
        cursor.execute("""
            SELECT DISTINCT 
                substr(constraint_loc, 1, instr(constraint_loc, '@') - 1) as constraint_type
            FROM coverage
        """)
        seen_types = {row['constraint_type'] for row in cursor.fetchall()}
        
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
    
    def get_mutations_hitting_constraint(self, constraint_loc: str) -> List[MutationRecord]:
        """Get all mutations that hit a specific constraint"""
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
    
    def close(self):
        """Close the database connection"""
        self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
