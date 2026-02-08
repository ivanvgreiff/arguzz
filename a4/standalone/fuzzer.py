"""
Standalone A4 Fuzzer

Main fuzzing orchestrator that:
1. Runs initial inspection to collect trace data
2. Iteratively selects steps, generates mutations, executes them
3. Tracks coverage and results in SQLite database
4. Reports findings

A campaign runs multiple mutations on the SAME guest program, each
mutation modifying a single variable at a single step, then passing
the result to the verifier to check if it accepts or rejects the proof.
"""

import json
import os
import random
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from a4.core.inspection_data import InspectionData
from a4.core.executor import run_a4_mutation
from a4.core.constraint_parser import ConstraintFailure

from a4.standalone.coverage_db import CoverageDB
from a4.standalone.step_selector import StepSelector, create_selector
from a4.standalone.value_generator import (
    ValueGenerator, 
    ValueGeneratorExhaustedError,
    create_generator
)

# Import mutation modules
from a4.standalone.mutations import (
    get_comp_out_targets, create_comp_out_config, CompOutModTarget,
    get_load_val_targets, create_load_val_config, LoadValModTarget,
    get_store_out_targets, create_store_out_config, StoreOutModTarget,
    get_pre_exec_reg_targets, create_pre_exec_reg_config, PreExecRegModTarget,
    get_instr_type_targets, create_instr_type_config, InstrTypeModTarget,
    get_mem_val_targets, create_mem_val_config, MemValModTarget,
)
from a4.standalone.mutations.instr_type_mod import generate_random_mutation as generate_instr_mutation


@dataclass
class MutationResult:
    """Result of a single mutation attempt"""
    kind: str
    step: int
    original_value: int
    mutated_value: int
    config: dict
    failures: List[ConstraintFailure]
    verifier_accepted: bool
    execution_time_ms: float
    new_coverage: int = 0
    witness_gen_failed: bool = False  # True if prover panicked during witness generation


@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign"""
    total_mutations: int = 0
    successful_mutations: int = 0  # Caused failures
    verifier_accepts: int = 0      # BUGS: verifier accepted bad proof
    witness_gen_failures: int = 0  # Prover panicked during witness generation
    new_coverage_count: int = 0
    total_failures: int = 0
    mutations_by_kind: Dict[str, int] = field(default_factory=dict)
    unique_constraints: set = field(default_factory=set)
    execution_time_ms: float = 0


class A4Fuzzer:
    """
    Standalone A4 Fuzzer
    
    Runs autonomous fuzzing campaigns against a guest program.
    Each mutation:
    1. Selects a step using the configured strategy
    2. Gets mutation targets at that step
    3. Generates a mutated value
    4. Creates config and executes mutation
    5. Records results and checks verifier acceptance
    """
    
    # Supported mutation kinds
    MUTATION_KINDS = [
        "COMP_OUT_MOD",
        "LOAD_VAL_MOD", 
        "STORE_OUT_MOD",
        "PRE_EXEC_REG_MOD",
        "INSTR_TYPE_MOD",
        "MEM_VAL_MOD",
    ]
    
    def __init__(
        self,
        host_binary: str,
        host_args: List[str],
        db_path: str,
        kind: str = "all",
        selector_strategy: str = "random",
        value_strategy: str = "mixed",
        seed: Optional[int] = None,
        verbose: bool = False,
    ):
        """
        Initialize the fuzzer.
        
        Args:
            host_binary: Path to risc0-host binary
            host_args: Arguments for risc0-host
            db_path: Path to SQLite database for coverage tracking
            kind: Mutation kind or "all" for all kinds
            selector_strategy: Step selection strategy
            value_strategy: Value generation strategy
            seed: Random seed for reproducibility
            verbose: Print detailed output
        """
        self.host_binary = host_binary
        self.host_args = host_args
        self.db_path = db_path
        self.kind = kind
        self.verbose = verbose
        self.seed = seed if seed is not None else random.randint(0, 2**32)
        
        # Initialize components
        self.db = CoverageDB(db_path)
        self.selector = create_selector(selector_strategy, self.seed, self.db)
        self.value_gen = create_generator(value_strategy, self.seed)
        self.rng = random.Random(self.seed)
        
        # Will be populated by run_inspection()
        self.data: Optional[InspectionData] = None
        self.campaign_id: Optional[int] = None
        
        # Temp directory for config files
        self.temp_dir = Path(tempfile.mkdtemp(prefix="a4_fuzz_"))
    
    def run_inspection(self) -> InspectionData:
        """
        Run initial inspection to collect trace data.
        
        This is called once at the start of a campaign to collect
        all cycles and transactions.
        """
        if self.verbose:
            print(f"Running inspection on {self.host_binary}...")
            print(f"  Args: {' '.join(self.host_args)}")
        
        self.data = InspectionData.from_inspection(self.host_binary, self.host_args)
        
        if self.verbose:
            print(self.data.summary())
        
        return self.data
    
    def run_campaign(self, num_mutations: int) -> CampaignStats:
        """
        Run a fuzzing campaign with the specified number of mutations.
        
        Each mutation:
        1. Selects a step and mutation kind
        2. Gets targets at that step
        3. Generates mutated value
        4. Executes mutation and checks verifier
        5. Records results
        
        Args:
            num_mutations: Number of mutations to attempt
            
        Returns:
            CampaignStats with results
        """
        # Run inspection if not already done
        if self.data is None:
            self.run_inspection()
        
        # Start campaign in database
        self.campaign_id = self.db.start_campaign(
            self.host_binary,
            self.host_args,
            self.kind,
            self.seed
        )
        
        if self.verbose:
            print(f"\nStarting campaign {self.campaign_id}")
            print(f"  Mutations: {num_mutations}")
            print(f"  Kind: {self.kind}")
            print(f"  Seed: {self.seed}")
            print()
        
        stats = CampaignStats()
        # Use perf_counter for monotonic timing (immune to WSL2 clock sync issues)
        campaign_start = time.perf_counter()
        
        for i in range(num_mutations):
            result = self._run_single_mutation(i + 1, num_mutations)
            
            if result:
                self._update_stats(stats, result)
                
                if self.verbose:
                    self._print_mutation_result(i + 1, result)
        
        stats.execution_time_ms = (time.perf_counter() - campaign_start) * 1000
        
        # End campaign
        self.db.end_campaign(self.campaign_id)
        
        if self.verbose:
            self._print_campaign_summary(stats)
        
        return stats
    
    def _run_single_mutation(
        self, 
        mutation_num: int, 
        total: int
    ) -> Optional[MutationResult]:
        """Run a single mutation attempt"""
        # Select mutation kind
        if self.kind == "all":
            kind = self.rng.choice(self.MUTATION_KINDS)
        else:
            kind = self.kind
        
        # Select step
        step = self.selector.select_step(self.data, kind)
        if step is None:
            if self.verbose:
                print(f"  [{mutation_num}/{total}] No valid steps for {kind}")
            return None
        
        # Get target and generate mutation
        try:
            config, mutated_value, original_value = self._create_mutation(kind, step)
        except ValueGeneratorExhaustedError as e:
            # This is a serious error - the generator is broken
            print(f"  [{mutation_num}/{total}] ERROR: {e}")
            raise
        except Exception as e:
            if self.verbose:
                print(f"  [{mutation_num}/{total}] Failed to create mutation: {e}")
            return None
        
        if config is None:
            return None
        
        # Execute mutation
        # Use time.perf_counter() instead of time.time() because:
        # - perf_counter() is monotonic (never goes backward)
        # - time.time() can jump backward during WSL2 clock sync with Windows host
        start_time = time.perf_counter()
        config_path = self.temp_dir / f"mutation_{mutation_num}.json"
        config_path.write_text(json.dumps(config, indent=2))
        
        output, failures = run_a4_mutation(
            self.host_binary,
            self.host_args,
            config_path
        )
        
        end_time = time.perf_counter()
        execution_time = (end_time - start_time) * 1000
        
        # Check for witness generation failure (prover panic before constraint check)
        witness_gen_failed = self._check_witness_gen_failure(output)
        
        # Check if verifier accepted (look for specific output)
        verifier_accepted = self._check_verifier_acceptance(output)
        
        result = MutationResult(
            kind=kind,
            step=step,
            original_value=original_value,
            mutated_value=mutated_value,
            config=config,
            failures=failures,
            verifier_accepted=verifier_accepted,
            execution_time_ms=execution_time,
            witness_gen_failed=witness_gen_failed,
        )
        
        # Record in database
        txn_idx = config.get("txn_idx")
        mutation_id = self.db.record_mutation(
            self.campaign_id,
            kind,
            step,
            mutated_value,
            config,
            txn_idx,
            verifier_accepted
        )
        
        total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)
        result.new_coverage = new_coverage
        
        # Update guided selector if applicable
        if hasattr(self.selector, 'record_mutation'):
            self.selector.record_mutation(step, new_coverage)
        
        return result
    
    def _create_mutation(self, kind: str, step: int) -> Tuple[Optional[dict], int, int]:
        """
        Create mutation config for a given kind and step.
        
        Returns:
            Tuple of (config, mutated_value, original_value)
            Returns (None, 0, 0) if no valid target at this step
        """
        if kind == "COMP_OUT_MOD":
            target = get_comp_out_targets(step, self.data)
            if not target:
                return None, 0, 0
            mutated_value = self.value_gen.generate_different(
                target.original_value,
                {'major': target.major, 'minor': target.minor}
            )
            config = {
                "mutation_type": "COMP_OUT_MOD",
                "step": target.step,
                "txn_idx": target.write_txn_idx,
                "word": mutated_value,
            }
            return config, mutated_value, target.original_value
        
        elif kind == "LOAD_VAL_MOD":
            target = get_load_val_targets(step, self.data)
            if not target:
                return None, 0, 0
            mutated_value = self.value_gen.generate_different(
                target.original_value,
                {'major': target.major, 'minor': target.minor}
            )
            config = {
                "mutation_type": "LOAD_VAL_MOD",
                "step": target.step,
                "txn_idx": target.write_txn_idx,
                "word": mutated_value,
            }
            return config, mutated_value, target.original_value
        
        elif kind == "STORE_OUT_MOD":
            target = get_store_out_targets(step, self.data)
            if not target:
                return None, 0, 0
            mutated_value = self.value_gen.generate_different(
                target.original_value,
                {'major': target.major, 'minor': target.minor}
            )
            config = {
                "mutation_type": "STORE_OUT_MOD",
                "step": target.step,
                "txn_idx": target.write_txn_idx,
                "word": mutated_value,
            }
            return config, mutated_value, target.original_value
        
        elif kind == "PRE_EXEC_REG_MOD":
            targets = get_pre_exec_reg_targets(step, self.data, strategy="next_read")
            if not targets:
                return None, 0, 0
            target = self.rng.choice(targets)
            mutated_value = self.value_gen.generate_different(
                target.original_word,
                {'major': target.major, 'minor': target.minor, 'register': target.register_idx}
            )
            config = {
                "mutation_type": "PRE_EXEC_REG_MOD",
                "step": target.step,
                "txn_idx": target.txn_idx,
                "word": mutated_value,
                "strategy": target.strategy,
            }
            return config, mutated_value, target.original_word
        
        elif kind == "INSTR_TYPE_MOD":
            target = get_instr_type_targets(step, self.data)
            if not target:
                return None, 0, 0
            new_major, new_minor = generate_instr_mutation(target, self.rng)
            mutated_value = (new_major << 16) | new_minor  # Encode for tracking
            original_value = (target.original_major << 16) | target.original_minor
            config = {
                "mutation_type": "INSTR_TYPE_MOD",
                "step": target.step,
                "major": new_major,
                "minor": new_minor,
            }
            return config, mutated_value, original_value
        
        elif kind == "MEM_VAL_MOD":
            # MEM_VAL_MOD returns a list of targets (multiple per step possible)
            targets = get_mem_val_targets(step, self.data)
            if not targets:
                return None, 0, 0
            # Select one target randomly
            target = self.rng.choice(targets)
            mutated_value = self.value_gen.generate_different(
                target.original_value,
                {
                    'major': target.major, 
                    'minor': target.minor,
                    'txn_type': target.txn_type,  # load_mem_read, store_rmw_read, etc.
                }
            )
            config = {
                "mutation_type": "MEM_VAL_MOD",
                "step": target.step,
                "txn_idx": target.txn_idx,
                "word": mutated_value,
            }
            return config, mutated_value, target.original_value
        
        return None, 0, 0
    
    def _check_witness_gen_failure(self, output: str) -> bool:
        """
        Check if witness generation failed (prover panic).
        
        This happens when the mutation creates an inconsistency that the
        witness generator detects before constraint checking even begins.
        
        Symptoms:
        - "witness generation failure" in output
        - Prover status: error
        - Zero constraint failures
        - Verifier never runs
        """
        witness_failure_patterns = [
            "witness generation failure",
            "panicked at",
            "set(row:",  # Witness matrix conflict error
        ]
        
        for pattern in witness_failure_patterns:
            if pattern in output:
                return True
        
        return False
    
    def _check_verifier_acceptance(self, output: str) -> bool:
        """
        Check if the verifier accepted the proof.
        
        Looks for specific patterns in output indicating acceptance.
        A BUG is when verifier accepts a mutated (invalid) proof.
        
        The risc0-host outputs verification results as JSON:
        - <record>{"context":"Verifier", "status":"success"}</record> = accepted
        - <record>{"context":"Verifier", "status":"error"}</record> = rejected
        """
        import re
        
        # Check for JSON-format verifier output (primary check)
        # Pattern: <record>{"context":"Verifier", "status":"success"}</record>
        verifier_success = re.search(
            r'<record>\s*\{[^}]*"context"\s*:\s*"Verifier"[^}]*"status"\s*:\s*"success"[^}]*\}\s*</record>',
            output
        )
        if verifier_success:
            return True
        
        # Also check reverse order: status before context
        verifier_success_alt = re.search(
            r'<record>\s*\{[^}]*"status"\s*:\s*"success"[^}]*"context"\s*:\s*"Verifier"[^}]*\}\s*</record>',
            output
        )
        if verifier_success_alt:
            return True
        
        # Legacy patterns (fallback for other output formats)
        acceptance_patterns = [
            "Verification successful",
            "Proof verified",
            "seal verified",
        ]
        
        # These patterns indicate verifier rejected (expected behavior)
        rejection_patterns = [
            "constraint fail",
            "Verification failed",
            "Invalid proof",
            "CONSTRAINT_FAIL",
            '"status":"error"',  # JSON error format
        ]
        
        output_lower = output.lower()
        
        # Check for rejection first (most common expected case)
        for pattern in rejection_patterns:
            if pattern.lower() in output_lower:
                return False
        
        # Check for acceptance (this would be a bug!)
        for pattern in acceptance_patterns:
            if pattern.lower() in output_lower:
                return True
        
        # Default to not accepted (constraint failures should have been detected)
        return False
    
    def _update_stats(self, stats: CampaignStats, result: MutationResult):
        """Update campaign statistics with mutation result"""
        stats.total_mutations += 1
        stats.mutations_by_kind[result.kind] = stats.mutations_by_kind.get(result.kind, 0) + 1
        
        # Track constraint failures (for coverage metrics)
        if result.failures:
            stats.total_failures += len(result.failures)
            for f in result.failures:
                stats.unique_constraints.add(f.constraint_loc())
        
        # Classify outcome (mutually exclusive, with priority order):
        # 1. VERIFIER_ACCEPTED (bug) - highest priority, always track
        # 2. WITNESS_FAIL - witness matrix conflict (may have constraint failures too)
        # 3. CONSTRAINT_FAIL - constraint failures without witness matrix conflict
        # 4. NO_EFFECT - no failures detected
        if result.verifier_accepted:
            stats.verifier_accepts += 1
        
        if result.witness_gen_failed:
            # Witness generation failed (may also have constraint failures, but we classify as WITNESS_FAIL)
            stats.witness_gen_failures += 1
        elif result.failures:
            # Constraint failures without witness matrix conflict
            stats.successful_mutations += 1
        # else: no effect (counted implicitly as total - witness - constraint)
        
        stats.new_coverage_count += result.new_coverage
    
    def _print_mutation_result(self, num: int, result: MutationResult):
        """Print detailed result of a single mutation"""
        # Status indicator
        if result.witness_gen_failed:
            status = "⚡"  # Witness generation failure
        elif result.failures:
            status = "✓"  # Constraint failures
        else:
            status = "○"  # No effect detected
        
        bug_marker = " 🐛 BUG!" if result.verifier_accepted else ""
        new_cov = f" [+{result.new_coverage} new]" if result.new_coverage > 0 else ""
        
        # Outcome classification
        # Note: witness_gen_failed means the witness matrix had a conflict. This can occur
        # AFTER constraint failures are detected, since both happen during witness generation.
        # Constraint failures and witness failures are NOT mutually exclusive.
        if result.witness_gen_failed:
            outcome = "WITNESS_FAIL"  # Matrix conflict (may have constraint failures too)
        elif result.verifier_accepted:
            outcome = "ACCEPTED"  # BUG: verifier should have rejected
        else:
            outcome = "REJECTED"  # Expected behavior
        
        # Basic info line
        print(f"  [{num}] {status} {result.kind} @ step {result.step}: "
              f"{len(result.failures)} failures, {result.execution_time_ms:.0f}ms, "
              f"outcome: {outcome}"
              f"{new_cov}{bug_marker}")
        
        # Value change info
        print(f"       Value: 0x{result.original_value:08X} -> 0x{result.mutated_value:08X}")
        
        # Constraint failure details (grouped by constraint location)
        if result.failures:
            # Group failures by constraint location
            failures_by_loc = {}
            for f in result.failures:
                loc = f.constraint_loc()
                if loc not in failures_by_loc:
                    failures_by_loc[loc] = []
                failures_by_loc[loc].append(f)
            
            print(f"       Constraints hit ({len(failures_by_loc)} unique):")
            for loc, failures in sorted(failures_by_loc.items()):
                # Show first failure details for each unique constraint
                first = failures[0]
                count_str = f" (x{len(failures)})" if len(failures) > 1 else ""
                print(f"         - {loc}{count_str}")
                print(f"           cycle={first.cycle}, step={first.step}, "
                      f"pc=0x{first.pc:08X}, major={first.major}, minor={first.minor}")
        else:
            print(f"       No constraint failures (mutation may have been ineffective)")
    
    def _print_campaign_summary(self, stats: CampaignStats):
        """Print campaign summary"""
        print("\n" + "="*60)
        print("Campaign Summary")
        print("="*60)
        print(f"Total mutations:     {stats.total_mutations}")
        print(f"Successful (caused failures): {stats.successful_mutations}")
        print(f"Total failures:      {stats.total_failures}")
        print(f"Unique constraints:  {len(stats.unique_constraints)}")
        print(f"New coverage:        {stats.new_coverage_count}")
        print(f"Execution time:      {stats.execution_time_ms:.0f}ms")
        
        # Outcome summary (mutually exclusive categories)
        # - successful_mutations: constraint failures WITHOUT witness matrix conflict
        # - witness_gen_failures: witness matrix conflict (may ALSO have constraint failures)
        # - no_effect: no failures of any kind
        constraint_only = stats.successful_mutations  # Constraint fail without witness conflict
        witness_fail = stats.witness_gen_failures     # Witness matrix conflict
        no_effect = stats.total_mutations - constraint_only - witness_fail
        
        print(f"\nOutcome breakdown:")
        print(f"  Constraint failures:    {constraint_only}")
        print(f"  Witness gen failures:   {witness_fail} (may include constraint failures)")
        print(f"  No effect detected:     {no_effect}")
        print(f"  Verifier accepted:      {stats.verifier_accepts} {'🐛 BUGS!' if stats.verifier_accepts > 0 else ''}")
        
        if stats.verifier_accepts > 0:
            print(f"\n🐛 BUGS FOUND: {stats.verifier_accepts} mutations accepted by verifier!")
        
        print(f"\nMutations by kind:")
        for kind, count in sorted(stats.mutations_by_kind.items()):
            print(f"  {kind}: {count}")
    
    def cleanup(self):
        """Clean up temporary files and close database"""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
        self.db.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
