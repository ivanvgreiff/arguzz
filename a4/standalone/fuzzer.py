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
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from a4.core.inspection_data import InspectionData
from a4.core.executor import run_a4_mutation, MutationExecutionResult
from a4.core.constraint_parser import ConstraintFailure
from a4.core.touch_coverage import (
    make_global_bitmap, count_new_bits, merge_into_global, distinct_touched,
)

from a4.standalone.coverage_db import CoverageDB
from a4.standalone.step_selector import StepSelector, ZonedStepSelector, create_selector
from a4.standalone.value_generator import (
    ValueGenerator, 
    ValueGeneratorExhaustedError,
    create_generator
)

from a4.standalone.bandit import DiscountedUCBScheduler
from a4.standalone.bandit_ts import (
    ConstrainedTSScheduler,
    KindLevelUCBScheduler,
    KindLevelTSScheduler,
    BanditDecision,
)
from a4.standalone.arm_universe import ArmUniverse
from a4.standalone.semantic_arm_universe import SemanticArmUniverse
from a4.standalone.step_selector import SemanticZoneStepSelector
from a4.standalone.zone_classifier import classify_zones
from a4.standalone.reward_v2 import (
    compute_reward_v2,
    compute_reward_v2_components,
    compute_bandit_success,
)
from a4.standalone.telemetry_v2 import (
    TELEMETRY_LEVELS,
    default_telemetry_level,
    record_full_telemetry,
)
from a4.standalone.structural_cells import StructuralCell
from a4.standalone.pilot_calibration import (
    CalibratedParams, calibrate_from_pilot, collect_pilot_stat, compute_N_pilot,
)
from a4.standalone.coverage_state import (
    CoverageState, compute_reward, update_state,
    derive_global_contexts, GlobalContext,
)
from a4.standalone.baseline_touch import capture_baseline_touch

# Import mutation modules
from a4.standalone.mutations import (
    get_comp_out_targets, create_comp_out_config, CompOutModTarget,
    get_load_val_targets, create_load_val_config, LoadValModTarget,
    get_store_out_targets, create_store_out_config, StoreOutModTarget,
    get_pre_exec_reg_targets, create_pre_exec_reg_config, PreExecRegModTarget,
    get_instr_type_targets, create_instr_type_config, InstrTypeModTarget,
    get_mem_val_targets, create_mem_val_config, MemValModTarget,
    get_instr_word_targets, create_instr_word_config, InstrWordModTarget,
)
from a4.standalone.mutations.instr_type_mod import generate_random_mutation as generate_instr_mutation

# Surgical instruction mutations
from a4.standalone.mutations.instr_word_mod_sur import (
    RiscVInstruction,
    InstrFormat,
    SurgicalField,
    get_targets_at_step as get_instr_word_sur_targets,
    select_surgical_field,
    generate_field_value,
    create_config as create_instr_word_sur_config,
    InstrWordModSurTarget,
)


# IV.POS.7 bandit variants (cloud1 Phase 5 — Pro §8.1 / §7.C–D)
V2_BANDIT_STRATEGIES = frozenset({
    "kindUCB_zoned_v1",
    "kindUCB_zoned_v2_noQ",
    "kindTS_zoned_v2",
    "cTS_semantic_v2",
})


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
    new_touch: int = 0
    exit_code: int = 0
    crashed: bool = False
    proof_generated: bool = False
    proof_verify_failed: bool = False
    raw_errors: List[str] = field(default_factory=list)
    raw_output: Optional[str] = None
    reward: float = 0.0
    reward_diag: Optional[dict] = None
    broken_families: List[str] = field(default_factory=list)
    broken_addresses: List[dict] = field(default_factory=list)
    is_global_only: bool = False
    family_stats: Optional[List[dict]] = None
    family_details: Optional[List[dict]] = None
    # Phase III.0: canonical F_glob set passed to compute_reward / update_state.
    global_contexts: Set[GlobalContext] = field(default_factory=set)


@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign"""
    total_mutations: int = 0
    successful_mutations: int = 0
    verifier_accepts: int = 0
    crashes: int = 0
    skipped_mutations: int = 0
    new_coverage_count: int = 0
    new_touch_count: int = 0
    total_distinct_touched: int = 0
    total_failures: int = 0
    mutations_by_kind: Dict[str, int] = field(default_factory=dict)
    unique_constraints: set = field(default_factory=set)
    execution_time_ms: float = 0
    global_violations: int = 0
    global_only: int = 0
    local_only: int = 0


# =============================================================================
# Strategy display names (Pro ProG_Report_2.md §14.2)
#
# These map internal selector identifiers (used everywhere in DBs and CLI) to
# the display names ChatGPT Pro recommended in §14.2 of ProG_Report_2.md.
# Internal names are kept unchanged so all existing IV.POS.1-5 DBs remain
# readable by analyze_campaign.py and the boss notebook. Display names should
# be used in human-facing reports, plots, and notebook output going forward.
# =============================================================================
STRATEGY_DISPLAY_NAMES = {
    "uniform":   "arm_uniform_b128",
    "zoned":     "kind_uniform_zoned_step",
    "bandit":    "ucb_kindbucket_b16",
    "bandit-16": "ucb_kindbucket_b16",  # alias used in IV.POS.5 plots
    # cloud1 (IV.POS.7) additions — populated in Phase 5:
    "kindUCB_zoned_v1":     "kindUCB_zoned_v1",      # Variant 2
    "kindUCB_zoned_v2_noQ": "kindUCB_zoned_v2_noQ",  # Variant 3
    "kindTS_zoned_v2":      "kindTS_zoned_v2",       # Variant 4
    "cTS_semantic_v2":      "cTS_semantic_v2",       # Variant 5 (main candidate)
}


def display_strategy_name(internal_name: str) -> str:
    """Return the Pro §14.2 display name for an internal selector identifier.

    Falls back to the internal name unchanged if not in the map (forward-compat
    for future variants added without updating this dict).
    """
    return STRATEGY_DISPLAY_NAMES.get(internal_name, internal_name)


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
        "INSTR_WORD_MOD_FULL",  # Full 32-bit instruction word mutation
        "INSTR_WORD_MOD_SUR",   # Surgical field-level mutation
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
        b_count_override: Optional[int] = None,
        telemetry_level: Optional[str] = None,
        debug_coverage_delta_path: Optional[str] = None,
        debug_bandit_trace_path: Optional[str] = None,
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
            b_count_override: Override bucket count for bandit arm universe
            telemetry_level: `none` | `standard` | `full` (D35: default full for v2 selectors)
            debug_coverage_delta_path: B6 audit-only JSONL side channel (default OFF)
            debug_bandit_trace_path: B4 audit-only JSONL side channel (default OFF)
        """
        self.host_binary = host_binary
        self.debug_coverage_delta_path = debug_coverage_delta_path
        self.debug_bandit_trace_path = debug_bandit_trace_path
        self.host_args = host_args
        self.db_path = db_path
        self.kind = kind
        self.verbose = verbose
        self.seed = seed if seed is not None else random.randint(0, 2**32)
        
        self.selector_strategy = selector_strategy
        if telemetry_level is not None and telemetry_level not in TELEMETRY_LEVELS:
            raise ValueError(
                f"telemetry_level must be one of {sorted(TELEMETRY_LEVELS)}, got {telemetry_level!r}"
            )
        self.telemetry_level = (
            telemetry_level
            if telemetry_level is not None
            else default_telemetry_level(selector_strategy, V2_BANDIT_STRATEGIES)
        )
        
        # Initialize components
        self.db = CoverageDB(db_path)
        if selector_strategy in ("bandit", "uniform") or selector_strategy in V2_BANDIT_STRATEGIES:
            # Deferred: needs InspectionData (and arm universe for uniform / v2 bandit).
            self.selector: Optional[StepSelector] = None
        else:
            self.selector = create_selector(selector_strategy, self.seed, self.db)
        self.value_gen = create_generator(value_strategy, self.seed)
        self.rng = random.Random(self.seed)
        
        # Will be populated by run_inspection()
        self.data: Optional[InspectionData] = None
        self.campaign_id: Optional[int] = None
        
        # Phase 3.3: Global touch bitmap (campaign-level accumulator)
        self.global_touch_bitmap: bytearray = make_global_bitmap()
        
        # Phase II.4: Bandit-mode state (populated by _setup_bandit)
        self.scheduler: Optional[DiscountedUCBScheduler] = None
        self.coverage_state: Optional[CoverageState] = None
        self.arm_universe: Optional[ArmUniverse] = None
        self._pilot_count: int = 0
        self.b_count_override: Optional[int] = b_count_override

        # cloud1 Phase 5: IV.POS.7 v2 bandit schedulers
        self.v2_scheduler = None
        self.semantic_arm_universe: Optional[SemanticArmUniverse] = None
        self.semantic_zone_selector: Optional[SemanticZoneStepSelector] = None
        self._step_to_zone: Dict[int, str] = {}
        self._seen_local_v2: Set[Tuple[str, int, int]] = set()
        self._seen_compressed_global: Set[str] = set()
        self._seen_structural: Set[StructuralCell] = set()
        self._v2_mutation_count: int = 0
        
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
    
    def _classify_outcome(self, result: 'MutationResult') -> str:
        """Derive outcome string from MutationResult fields."""
        if result.verifier_accepted:
            return "ACCEPTED"
        elif result.crashed:
            return "CRASH"
        elif result.failures or result.proof_verify_failed or result.broken_families:
            return "REJECTED"
        return "NO_EFFECT"

    def _derive_global_info(
        self,
        exec_result: MutationExecutionResult,
        failures: List[ConstraintFailure],
    ) -> Tuple[List[str], List, bool, Set[GlobalContext]]:
        """
        Phase III.0: extract global Hook 3 info into the four pieces every
        mutation path needs.

        Returns (broken_families, broken_addresses, is_global_only, global_contexts):
          - broken_families: list of family names with nonzero residue
          - broken_addresses: flat list of broken_addrs / broken_indices
          - is_global_only: True iff at least one global broke and zero local failures
          - global_contexts: canonical F_glob set keyed off (GLOBAL, family, addr_str)
        """
        broken_families: List[str] = []
        broken_addresses: List = []
        if exec_result.family_residues:
            for fr in exec_result.family_residues:
                if fr.get("nonzero"):
                    broken_families.append(fr["family"])
        if exec_result.family_details:
            for fd in exec_result.family_details:
                if fd.get("broken_addrs"):
                    broken_addresses.extend(fd["broken_addrs"])
                if fd.get("broken_indices"):
                    broken_addresses.extend(fd["broken_indices"])
        local_failures = [f for f in failures if f.phase == "local"]
        is_global_only = len(broken_families) > 0 and len(local_failures) == 0
        global_contexts = derive_global_contexts(
            exec_result.family_residues, exec_result.family_details
        )
        return broken_families, broken_addresses, is_global_only, global_contexts
    
    def _setup_bandit(self, num_mutations: int, stats: 'CampaignStats') -> None:
        """
        Full bandit initialization: baseline → arms → pilot → calibration → bandit.

        Pilot mutations are executed here and count toward the campaign budget.
        After this method returns, self.scheduler is ready for select()/update().
        """
        if self.verbose:
            print("\n--- BANDIT SETUP ---")

        # 1. Baseline capture
        if self.verbose:
            print("Capturing baseline touch...")
        baseline = capture_baseline_touch(self.host_binary, self.host_args)
        if self.verbose:
            print(f"  Baseline: {baseline.distinct_buckets} bitmap buckets")

        # 2. Arm universe
        self.arm_universe = ArmUniverse(
            self.data, num_mutations, self.MUTATION_KINDS,
            b_count_override=self.b_count_override,
        )
        if self.verbose:
            print(self.arm_universe.summary())

        # 3. Pilot calibration
        N_pilot = compute_N_pilot(num_mutations)
        # Defensive guardrail (IV.POS.3 finding): if N_pilot >= num_mutations
        # then the main bandit loop iterates ZERO times, scheduler is never
        # updated, mutation_rewards table stays empty, and the run is useless
        # for any bandit-vs-uniform comparison. Warn loudly so the operator
        # immediately knows to increase N or switch strategy.
        if N_pilot >= num_mutations:
            print(
                f"\n*** WARNING: bandit budget N={num_mutations} <= N_pilot={N_pilot}.\n"
                f"*** The pilot phase will consume the entire budget; the main\n"
                f"*** bandit loop will run ZERO post-pilot mutations. The DB will\n"
                f"*** have ~{N_pilot} mutations rows but ZERO mutation_rewards rows\n"
                f"*** and the DiscountedUCBScheduler will report t=0.\n"
                f"*** Set N >= {N_pilot + 30} (recommend N >= 100) for meaningful\n"
                f"*** bandit data. See playbook §12.35.",
                file=sys.stderr,
            )
        if self.verbose:
            print(f"\nRunning {N_pilot} pilot mutations (uniform random)...")

        pilot_selector = ZonedStepSelector(seed=self.seed + 1000)
        pilot_bitmap = make_global_bitmap()
        merge_into_global(baseline.bitmap, pilot_bitmap)
        pilot_stats_list = []

        for p in range(N_pilot):
            kind = self.rng.choice(self.MUTATION_KINDS)
            config_path = None
            step = None

            for attempt in range(10):
                step = pilot_selector.select_step(self.data, kind)
                if step is None:
                    break
                config, mv, ov = self._create_mutation(kind, step)
                if config is not None:
                    config_path = self.temp_dir / f"pilot_{p}.json"
                    config_path.write_text(json.dumps(config, indent=2))
                    break

            if config_path is None:
                continue

            exec_result = run_a4_mutation(self.host_binary, self.host_args, config_path)

            pstat = collect_pilot_stat(exec_result, pilot_bitmap)
            if exec_result.touch_bitmap is not None:
                merge_into_global(exec_result.touch_bitmap, pilot_bitmap)
            pilot_stats_list.append(pstat)

            # Record pilot mutation in DB + stats (it counts toward the campaign)
            output = exec_result.combined_output
            failures = exec_result.failures
            exit_code = exec_result.exit_code

            crash_signals_negative = (-11, -6, -8, -9, -10)
            crash_signals_shell = (139, 134, 136, 137, 138)
            crashed = exit_code in crash_signals_negative or exit_code in crash_signals_shell
            proof_generated = self._check_proof_generated(output, exit_code)
            proof_verify_failed = self._check_proof_verification_failure(output)
            verifier_accepted = self._check_verifier_acceptance(output)

            pilot_result = MutationResult(
                kind=kind, step=step or 0,
                original_value=ov, mutated_value=mv, config=config,
                failures=failures, verifier_accepted=verifier_accepted,
                execution_time_ms=0, exit_code=exit_code, crashed=crashed,
                proof_generated=proof_generated, proof_verify_failed=proof_verify_failed,
            )
            self._update_stats(stats, pilot_result)

            txn_idx = config.get("txn_idx") if config else None
            mutation_id = self.db.record_mutation(
                self.campaign_id, kind, step or 0, mv, config, txn_idx,
                verifier_accepted, original_value=ov,
            )
            self.db.record_failures(mutation_id, failures)
            # Phase III.1: pilot-phase mutations also produce Hook 3 globals; persist them
            # so analyze_campaign can include the pilot rows in cumulative-coverage curves.
            _, _, _, pilot_global_ctx = self._derive_global_info(exec_result, failures)
            if pilot_global_ctx:
                self.db.record_global_failures(mutation_id, pilot_global_ctx)

            if exec_result.touch_bitmap is not None:
                new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
                merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
                pilot_result.new_touch = new_touch

            if self.verbose:
                n_fail = len(failures)
                print(f"  [pilot {p+1}/{N_pilot}] {kind} @ step {step}: {n_fail}f")

        self._pilot_count = len(pilot_stats_list)

        if self.verbose:
            print(f"  Pilot: {self._pilot_count} runs completed")

        # 4. Calibrate
        params = calibrate_from_pilot(pilot_stats_list, num_mutations)
        if self.verbose:
            print(f"  Calibrated: τ_T={params.tau_new:.1f}, τ_d={params.tau_d:.1f}, "
                  f"K_T_rare={params.K_T_rare}, γ={params.gamma:.4f}")

        # 5. Coverage state (seeded from baseline + pilot coverage)
        self.coverage_state = CoverageState(params)
        self.coverage_state.seed_from_baseline(baseline.bitmap)
        # Merge pilot's incremental touch into coverage state
        for i in range(len(pilot_bitmap)):
            if pilot_bitmap[i] > 0 and self.coverage_state.global_bitmap[i] == 0:
                self.coverage_state.global_bitmap[i] = pilot_bitmap[i]
                self.coverage_state.freq[i] = 1
            elif pilot_bitmap[i] > self.coverage_state.global_bitmap[i]:
                self.coverage_state.global_bitmap[i] = pilot_bitmap[i]

        # 6. Construct bandit
        self.scheduler = DiscountedUCBScheduler(self.arm_universe, params, seed=self.seed)

        if self.verbose:
            print(f"\n--- BANDIT READY ({self.arm_universe.num_arms} arms, "
                  f"budget remaining: {num_mutations - self._pilot_count}) ---\n")

        self._init_full_telemetry_state()

    def _setup_coverage_tracking(self) -> None:
        """Initialize CoverageState for non-bandit mode (reward diagnostics only)."""
        if self.verbose:
            print("\n--- COVERAGE TRACKING SETUP ---")
            print("Capturing baseline touch...")

        baseline = capture_baseline_touch(self.host_binary, self.host_args)

        if self.verbose:
            print(f"  Baseline: {baseline.distinct_buckets} bitmap buckets")

        params = CalibratedParams(
            tau_new=35.0,
            tau_d=3.0,
            K_T_rare=31,
            gamma=0.9965,
        )

        self.coverage_state = CoverageState(params)
        self.coverage_state.seed_from_baseline(baseline.bitmap)

        if self.verbose:
            print(f"  Calibrated: \u03c4_T={params.tau_new:.1f}, \u03c4_d={params.tau_d:.1f}, "
                  f"K_T_rare={params.K_T_rare}, \u03b3={params.gamma:.4f}")
            print("--- COVERAGE TRACKING READY ---\n")

        self._init_full_telemetry_state()

    def _init_full_telemetry_state(self) -> None:
        """Initialize seen_* sets for Phase 6 full telemetry on any selector path."""
        if self.telemetry_level != "full" or self.data is None:
            return
        if not self._step_to_zone:
            self._step_to_zone = classify_zones(self.data)
        self._seen_local_v2 = set()
        self._seen_compressed_global = set()
        self._seen_structural = set()

    def _record_full_telemetry(
        self,
        mutation_id: int,
        *,
        kind: str,
        step: int,
        exec_result: MutationExecutionResult,
        config: dict,
        original_value: int,
        mutated_value: int,
        legacy_reward_diag: Optional[dict],
        components: Optional[dict] = None,
    ) -> None:
        """Phase 6: populate v2 telemetry tables when telemetry_level is full."""
        if self.telemetry_level != "full":
            return
        if self.data is not None and not self._step_to_zone:
            self._step_to_zone = classify_zones(self.data)
        cycle = self.data.get_cycle(step) if self.data is not None else None
        mutation_major = cycle.major if cycle is not None else 0
        setattr(exec_result, "_mutation_major", mutation_major)
        record_full_telemetry(
            self.db,
            self.campaign_id,
            mutation_id,
            kind=kind,
            step=step,
            exec_result=exec_result,
            config=config,
            original_value=original_value,
            mutated_value=mutated_value,
            legacy_reward_diag=legacy_reward_diag or {},
            step_to_zone=self._step_to_zone,
            seen_local_v2=self._seen_local_v2,
            seen_compressed_global=self._seen_compressed_global,
            seen_structural=self._seen_structural,
            components=components,
        )

    def _active_mutation_kinds(self) -> List[str]:
        """Kinds for this campaign (all 8 or a single kind)."""
        if self.kind == "all":
            return list(self.MUTATION_KINDS)
        return [self.kind]

    def _setup_v2_bandit(self, num_mutations: int) -> None:
        """Initialize IV.POS.7 v2 bandit schedulers — no pilot (D2)."""
        if self.verbose:
            print(f"\n--- V2 BANDIT SETUP ({self.selector_strategy}) ---")

        baseline = capture_baseline_touch(self.host_binary, self.host_args)
        if self.verbose:
            print(f"  Baseline: {baseline.distinct_buckets} bitmap buckets")

        params = CalibratedParams(
            tau_new=35.0,
            tau_d=3.0,
            K_T_rare=31,
            gamma=0.9965,
        )
        self.coverage_state = CoverageState(params)
        self.coverage_state.seed_from_baseline(baseline.bitmap)

        self._step_to_zone = classify_zones(self.data)
        self._seen_local_v2 = set()
        self._seen_compressed_global = set()
        self._seen_structural = set()
        self._v2_mutation_count = 0

        kinds = self._active_mutation_kinds()

        if self.selector_strategy == "cTS_semantic_v2":
            self.semantic_arm_universe = SemanticArmUniverse.build(self.data, kinds)
            self.v2_scheduler = ConstrainedTSScheduler(
                self.semantic_arm_universe, seed=self.seed,
            )
            self.semantic_zone_selector = SemanticZoneStepSelector(
                self.semantic_arm_universe, seed=self.seed + 1,
            )
            if self.verbose:
                print(self.semantic_arm_universe.summary())
        elif self.selector_strategy in ("kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ"):
            self.v2_scheduler = KindLevelUCBScheduler(
                kinds, c_explore=params.c_explore, seed=self.seed,
            )
            self.selector = ZonedStepSelector(seed=self.seed + 1)
        elif self.selector_strategy == "kindTS_zoned_v2":
            self.v2_scheduler = KindLevelTSScheduler(kinds, seed=self.seed)
            self.selector = ZonedStepSelector(seed=self.seed + 1)
        else:
            raise ValueError(f"unknown v2 strategy: {self.selector_strategy}")

        if self.verbose:
            n_arms = (
                self.semantic_arm_universe.num_arms
                if self.semantic_arm_universe is not None
                else len(kinds)
            )
            print(f"--- V2 BANDIT READY ({n_arms} arms, budget {num_mutations}) ---\n")

        self._init_full_telemetry_state()

    def _persist_campaign_params(self) -> None:
        """
        Phase IV.0-prep: write the calibrated reward params + bandit knobs
        to `campaign_params` so downstream (cloud aggregator, boss notebook,
        analyze_campaign.py) can read them by SQL rather than parsing the
        verbose terminal log. Silently no-ops if coverage_state was never
        initialised (which today means: nothing — all selectors enable it
        as of III.2). Idempotent on (campaign_id).
        """
        if self.campaign_id is None or self.coverage_state is None:
            return
        params = self.coverage_state.params
        self.db.record_campaign_params(
            self.campaign_id,
            tau_new=float(params.tau_new),
            tau_d=float(params.tau_d),
            tau_g=float(params.tau_g),
            gamma=float(params.gamma),
            K_T_rare=int(params.K_T_rare),
            b_count=(
                int(self.arm_universe.B_count) if self.arm_universe is not None else None
            ),
            selector=self.selector_strategy,
            extra={"num_arms": int(self.arm_universe.num_arms)} if self.arm_universe is not None else None,
        )

    def _setup_uniform(self, num_mutations: int, stats: 'CampaignStats') -> None:
        """
        Phase III.2: setup for the 'uniform' selector — fair learning-free
        baseline that draws (kind, bucket) uniformly over the same arm
        universe the bandit uses.

        Steps:
          1. Build ArmUniverse from inspection data + budget (mirroring _setup_bandit).
             Print summary so analyze_campaign.py picks up T / B_count / B / num_arms.
          2. Construct UniformArmSelector(arm_universe, seed).
          3. Enable coverage tracking (default CalibratedParams) so reward
             diagnostics still print and persist alongside each mutation.
        """
        if self.verbose:
            print("\n--- UNIFORM-ARM SETUP ---")

        self.arm_universe = ArmUniverse(
            self.data, num_mutations, self.MUTATION_KINDS,
            b_count_override=self.b_count_override,
        )
        if self.verbose:
            print(self.arm_universe.summary())

        self.selector = create_selector(
            "uniform", seed=self.seed, arm_universe=self.arm_universe,
        )

        self._setup_coverage_tracking()

        if self.verbose:
            print(f"--- UNIFORM-ARM READY ({self.arm_universe.num_arms} arms) ---\n")

    def _run_bandit_mutation(
        self,
        mutation_num: int,
        total: int,
        stats: 'CampaignStats',
    ) -> Optional['MutationResult']:
        """Run a single mutation using the bandit scheduler."""
        kind, step = self.scheduler.select()

        # Retry within same arm's bucket if _create_mutation fails
        bucket = self.arm_universe.bucket_for_step(step)
        bucket_steps = self.arm_universe.steps_in_arm(kind, bucket)
        config = None
        mutated_value = 0
        original_value = 0

        for attempt in range(min(10, len(bucket_steps))):
            try:
                config, mutated_value, original_value = self._create_mutation(kind, step)
            except ValueGeneratorExhaustedError:
                raise
            except Exception:
                config = None

            if config is not None:
                break
            # Pick a different step from the same bucket
            step = self.rng.choice(bucket_steps)

        if config is None:
            if self.verbose:
                print(f"  [{mutation_num}/{total}] SKIP {kind} bucket {bucket}")
            stats.skipped_mutations += 1
            return None

        # Execute
        start_time = time.perf_counter()
        config_path = self.temp_dir / f"mutation_{mutation_num}.json"
        config_path.write_text(json.dumps(config, indent=2))
        exec_result = run_a4_mutation(self.host_binary, self.host_args, config_path)
        execution_time = (time.perf_counter() - start_time) * 1000

        output = exec_result.combined_output
        failures = exec_result.failures
        exit_code = exec_result.exit_code

        crash_signals_negative = (-11, -6, -8, -9, -10)
        crash_signals_shell = (139, 134, 136, 137, 138)
        crashed = exit_code in crash_signals_negative or exit_code in crash_signals_shell
        proof_generated = self._check_proof_generated(output, exit_code)
        proof_verify_failed = self._check_proof_verification_failure(output)
        verifier_accepted = self._check_verifier_acceptance(output)
        raw_errors = self._extract_raw_error(exec_result.stdout, exec_result.stderr)
        raw_output_truncated = output[-2000:] if len(output) > 2000 else output

        # Global constraint info from Hook 3 (Phase III.0: also derives F_glob set)
        broken_families, broken_addresses, is_global_only, global_contexts = (
            self._derive_global_info(exec_result, failures)
        )

        result = MutationResult(
            kind=kind, step=step,
            original_value=original_value, mutated_value=mutated_value,
            config=config, failures=failures, verifier_accepted=verifier_accepted,
            execution_time_ms=execution_time, exit_code=exit_code, crashed=crashed,
            proof_generated=proof_generated, proof_verify_failed=proof_verify_failed,
            raw_errors=raw_errors, raw_output=raw_output_truncated,
            broken_families=broken_families, broken_addresses=broken_addresses,
            is_global_only=is_global_only,
            family_details=exec_result.family_details,
            global_contexts=global_contexts,
        )

        # Outcome classification for reward
        outcome = self._classify_outcome(result)

        # Reward computation (reads state BEFORE this run)
        reward, diag = compute_reward(
            exec_result.touch_bitmap, failures, exit_code,
            outcome, proof_generated, self.coverage_state,
            global_contexts=global_contexts,
        )
        result.reward = reward
        result.reward_diag = diag

        # Bandit update
        self.scheduler.update(kind, step, reward)

        # Coverage state update (writes this run's data)
        update_state(
            exec_result.touch_bitmap, failures, exit_code, self.coverage_state,
            global_contexts=global_contexts,
        )

        # DB recording
        txn_idx = config.get("txn_idx")
        mutation_id = self.db.record_mutation(
            self.campaign_id, kind, step, mutated_value, config, txn_idx,
            verifier_accepted, original_value=original_value,
        )
        total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)
        # Phase III.1: persist global Hook 3 contexts for offline analysis.
        if global_contexts:
            self.db.record_global_failures(mutation_id, global_contexts)
        if self.telemetry_level != "none":
            self.db.record_reward_diag(mutation_id, diag)
        result.new_coverage = new_coverage

        self._record_full_telemetry(
            mutation_id,
            kind=kind,
            step=step,
            exec_result=exec_result,
            config=config,
            original_value=original_value,
            mutated_value=mutated_value,
            legacy_reward_diag=diag,
        )

        # Touch tracking (separate from CoverageState, for campaign stats)
        if exec_result.touch_bitmap is not None:
            new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
            merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
            result.new_touch = new_touch

        return result

    def _run_v2_bandit_mutation(
        self,
        mutation_num: int,
        total: int,
        stats: 'CampaignStats',
    ) -> Optional['MutationResult']:
        """Run one mutation under IV.POS.7 v2 bandit schedulers (Phase 5)."""
        decision: BanditDecision
        if self.selector_strategy == "cTS_semantic_v2":
            decision = self.v2_scheduler.select()
            kind, zone, step = decision.kind, decision.zone, decision.step
        else:
            decision = self.v2_scheduler.select()
            kind = decision.kind
            zone = None
            step = self.selector.select_step(self.data, kind)
            if step is None:
                stats.skipped_mutations += 1
                if self.selector_strategy in ("kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ"):
                    self.v2_scheduler.update(kind, 0.0)
                elif self.selector_strategy == "kindTS_zoned_v2":
                    self.v2_scheduler.update(kind, 0)
                return None

        bandit_kind = kind
        bandit_zone = zone if self.selector_strategy == "cTS_semantic_v2" else None
        bandit_step_at_select = step

        config = None
        mutated_value = 0
        original_value = 0
        for attempt in range(10):
            try:
                config, mutated_value, original_value = self._create_mutation(kind, step)
            except ValueGeneratorExhaustedError:
                raise
            except Exception:
                config = None
            if config is not None:
                break
            if self.selector_strategy == "cTS_semantic_v2" and zone is not None:
                alt = self.semantic_zone_selector.pick_step_in_zone(kind, zone)
                if alt is not None:
                    step = alt
            elif self.selector is not None:
                step = self.selector.select_step(self.data, kind)
                if step is None:
                    break

        if config is None:
            stats.skipped_mutations += 1
            if self.selector_strategy == "cTS_semantic_v2" and zone is not None:
                self.v2_scheduler.update(kind, zone, 0)
            elif self.selector_strategy in ("kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ"):
                self.v2_scheduler.update(kind, 0.0)
            elif self.selector_strategy == "kindTS_zoned_v2":
                self.v2_scheduler.update(kind, 0)
            return None

        # B4 trace: step may change during target retries; log final resolved step.
        bandit_step_at_select = step

        start_time = time.perf_counter()
        config_path = self.temp_dir / f"mutation_{mutation_num}.json"
        config_path.write_text(json.dumps(config, indent=2))
        exec_result = run_a4_mutation(self.host_binary, self.host_args, config_path)
        execution_time = (time.perf_counter() - start_time) * 1000

        output = exec_result.combined_output
        failures = exec_result.failures
        exit_code = exec_result.exit_code

        crash_signals_negative = (-11, -6, -8, -9, -10)
        crash_signals_shell = (139, 134, 136, 137, 138)
        crashed = exit_code in crash_signals_negative or exit_code in crash_signals_shell
        proof_generated = self._check_proof_generated(output, exit_code)
        proof_verify_failed = self._check_proof_verification_failure(output)
        verifier_accepted = self._check_verifier_acceptance(output)
        raw_errors = self._extract_raw_error(exec_result.stdout, exec_result.stderr)
        raw_output_truncated = output[-2000:] if len(output) > 2000 else output

        broken_families, broken_addresses, is_global_only, global_contexts = (
            self._derive_global_info(exec_result, failures)
        )

        result = MutationResult(
            kind=kind, step=step,
            original_value=original_value, mutated_value=mutated_value,
            config=config, failures=failures, verifier_accepted=verifier_accepted,
            execution_time_ms=execution_time, exit_code=exit_code, crashed=crashed,
            proof_generated=proof_generated, proof_verify_failed=proof_verify_failed,
            raw_errors=raw_errors, raw_output=raw_output_truncated,
            broken_families=broken_families, broken_addresses=broken_addresses,
            is_global_only=is_global_only,
            family_details=exec_result.family_details,
            global_contexts=global_contexts,
        )

        outcome = self._classify_outcome(result)
        reward, diag = compute_reward(
            exec_result.touch_bitmap, failures, exit_code,
            outcome, proof_generated, self.coverage_state,
            global_contexts=global_contexts,
        )
        result.reward = reward
        result.reward_diag = diag

        setattr(exec_result, "config", config)
        mutation_zone = self._step_to_zone.get(step, "core_other")
        cycle = self.data.get_cycle(step)
        mutation_major = cycle.major if cycle is not None else 0

        if self.debug_coverage_delta_path:
            seen_local_before = set(self._seen_local_v2)
            seen_global_before = set(self._seen_compressed_global)
            seen_struct_before = set(self._seen_structural)
            touch_before = bytes(self.global_touch_bitmap)
        else:
            seen_local_before = seen_global_before = seen_struct_before = None
            touch_before = None

        components = compute_reward_v2_components(
            exec_result,
            self._seen_local_v2,
            self._seen_compressed_global,
            self._seen_structural,
            kind,
            mutation_zone,
            mutation_major,
        )
        reward_v2 = compute_reward_v2(
            components["l_new"], components["f_new"], components["g_new"],
            components["s_new"], components["crash"], components["repeat"],
        )
        bandit_success = compute_bandit_success(
            components["l_new"], components["g_new"], components["s_new"],
        )

        if self.debug_coverage_delta_path:
            touch_delta = (
                count_new_bits(exec_result.touch_bitmap, bytearray(touch_before))
                if exec_result.touch_bitmap is not None and touch_before is not None
                else 0
            )
            failures_snap = []
            for f in failures:
                failures_snap.append({
                    "constraint_loc": f.constraint_loc(),
                    "major": f.major,
                    "minor": f.minor,
                })
            self._append_coverage_delta_debug({
                "mutation_num": mutation_num,
                "kind": kind,
                "step": step,
                "zone": mutation_zone,
                "major": mutation_major,
                "config": config,
                "reported": {
                    "l_new": int(components["l_new"]),
                    "f_new": int(components["f_new"]),
                    "g_new": int(components["g_new"]),
                    "s_new": int(components["s_new"]),
                    "crash": bool(components["crash"]),
                    "repeat": int(components["repeat"]),
                },
                "touch_delta": int(touch_delta),
                "seen_local_before": [list(x) for x in seen_local_before],
                "seen_global_before": list(seen_global_before),
                "seen_struct_before": [
                    (x.kind, x.semantic_zone, x.opcode_class, x.mode, x.txn_role, x.sub_strategy)
                    for x in seen_struct_before
                ],
                "failures": failures_snap,
                "family_residues": getattr(exec_result, "family_residues", None),
                "family_details": getattr(exec_result, "family_details", None),
            })

        if self.selector_strategy == "kindUCB_zoned_v1":
            self.v2_scheduler.update(kind, reward)
        elif self.selector_strategy == "kindUCB_zoned_v2_noQ":
            self.v2_scheduler.update(kind, reward_v2)
        elif self.selector_strategy == "kindTS_zoned_v2":
            self.v2_scheduler.update(kind, bandit_success)
        elif self.selector_strategy == "cTS_semantic_v2":
            self.v2_scheduler.update(kind, zone, bandit_success)

        update_state(
            exec_result.touch_bitmap, failures, exit_code, self.coverage_state,
            global_contexts=global_contexts,
        )

        txn_idx = config.get("txn_idx")
        mutation_id = self.db.record_mutation(
            self.campaign_id, kind, step, mutated_value, config, txn_idx,
            verifier_accepted, original_value=original_value,
        )
        total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)
        if global_contexts:
            self.db.record_global_failures(mutation_id, global_contexts)
        if self.telemetry_level != "none":
            self.db.record_reward_diag(mutation_id, diag)
        result.new_coverage = new_coverage

        if self.telemetry_level == "full":
            self._record_full_telemetry(
                mutation_id,
                kind=kind,
                step=step,
                exec_result=exec_result,
                config=config,
                original_value=original_value,
                mutated_value=mutated_value,
                legacy_reward_diag=diag,
                components=components,
            )
            self.db.record_bandit_decision(
                mutation_id,
                selected_arm=decision.arm_id,
                mode=decision.mode,
                score=decision.score,
                runnerup_arm=decision.runnerup_arm,
                runnerup_score=decision.runnerup_score,
                exploration=decision.exploration,
            )
            if mutation_num % 100 == 0:
                self.db.record_arm_state_snapshot(
                    self.campaign_id,
                    mutation_num,
                    self.v2_scheduler.arm_state_rows(),
                )

        if exec_result.touch_bitmap is not None:
            new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
            merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
            result.new_touch = new_touch

        if self.debug_coverage_delta_path:
            self._patch_coverage_delta_mutation_id(mutation_num, mutation_id)

        if self.debug_bandit_trace_path:
            hook = self._parse_hook_step(kind, output)
            hook_step = int(hook["step"]) if hook and "step" in hook else None
            self._append_bandit_trace_debug({
                "mutation_num": mutation_num,
                "bandit_kind": bandit_kind,
                "bandit_zone": bandit_zone,
                "bandit_step": bandit_step_at_select,
                "executed_kind": kind,
                "executed_step": step,
                "hook_kind": kind if hook is not None else None,
                "hook_step": hook_step,
            })
            self._patch_bandit_trace_mutation_id(mutation_num, mutation_id)

        return result

    def _append_coverage_delta_debug(self, row: dict) -> None:
        """B6 audit-only: append one JSON line to the debug side channel."""
        path = Path(self.debug_coverage_delta_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(row) + "\n")

    def _patch_coverage_delta_mutation_id(self, mutation_num: int, mutation_id: int) -> None:
        """Attach DB mutation_id to the last debug row for this mutation_num."""
        path = Path(self.debug_coverage_delta_path)
        if not path.exists():
            return
        lines = path.read_text().splitlines()
        for i in range(len(lines) - 1, -1, -1):
            row = json.loads(lines[i])
            if row.get("mutation_num") == mutation_num and "mutation_id" not in row:
                row["mutation_id"] = mutation_id
                lines[i] = json.dumps(row)
                path.write_text("\n".join(lines) + ("\n" if lines else ""))
                return

    _BANDIT_TRACE_KIND_TAG = {
        "COMP_OUT_MOD": "a4_comp_out_mod",
        "LOAD_VAL_MOD": "a4_load_val_mod",
        "STORE_OUT_MOD": "a4_store_out_mod",
        "PRE_EXEC_REG_MOD": "a4_pre_exec_reg_mod",
        "INSTR_TYPE_MOD": "a4_instr_type_mod",
        "MEM_VAL_MOD": "a4_mem_val_mod",
        "INSTR_WORD_MOD_FULL": "a4_instr_word_mod",
        "INSTR_WORD_MOD_SUR": "a4_instr_word_mod",
    }
    _BANDIT_TRACE_MOD_RE = re.compile(r"<(\w+)>({.*?})</\1>")

    def _parse_hook_step(self, kind: str, output: str) -> Optional[Dict]:
        """B4 audit-only: parse mutation hook JSON from host output."""
        tag = self._BANDIT_TRACE_KIND_TAG.get(kind)
        if tag is None:
            return None
        needle = f"<{tag}>"
        last = None
        for line in output.splitlines():
            if needle not in line:
                continue
            for m in self._BANDIT_TRACE_MOD_RE.finditer(line):
                if m.group(1) != tag:
                    continue
                try:
                    last = json.loads(m.group(2))
                except json.JSONDecodeError:
                    continue
        return last

    def _append_bandit_trace_debug(self, row: dict) -> None:
        """B4 audit-only: append one JSON line to the debug side channel."""
        path = Path(self.debug_bandit_trace_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(row) + "\n")

    def _patch_bandit_trace_mutation_id(self, mutation_num: int, mutation_id: int) -> None:
        """Attach DB mutation_id to the last bandit-trace row for mutation_num."""
        path = Path(self.debug_bandit_trace_path)
        if not path.exists():
            return
        lines = path.read_text().splitlines()
        for i in range(len(lines) - 1, -1, -1):
            row = json.loads(lines[i])
            if row.get("mutation_num") == mutation_num and "mutation_id" not in row:
                row["mutation_id"] = mutation_id
                lines[i] = json.dumps(row)
                path.write_text("\n".join(lines) + ("\n" if lines else ""))
                return

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
        campaign_start = time.perf_counter()
        
        # Bandit mode: run setup (baseline + pilot + calibration)
        if self.selector_strategy == "bandit":
            self._setup_bandit(num_mutations, stats)
            main_budget = num_mutations - self._pilot_count
            start_idx = self._pilot_count
        elif self.selector_strategy == "uniform":
            # Phase III.2: arm-universe + uniform sampler + coverage tracking.
            # No pilot phase (uniform doesn't need calibrated params for sampling).
            self._setup_uniform(num_mutations, stats)
            main_budget = num_mutations
            start_idx = 0
        elif self.selector_strategy in V2_BANDIT_STRATEGIES:
            self._setup_v2_bandit(num_mutations)
            main_budget = num_mutations
            start_idx = 0
        else:
            main_budget = num_mutations
            start_idx = 0
            self._setup_coverage_tracking()

        self._persist_campaign_params()
        
        for i in range(main_budget):
            mutation_num = start_idx + i + 1
            
            if self.v2_scheduler is not None:
                result = self._run_v2_bandit_mutation(mutation_num, num_mutations, stats)
            elif self.scheduler is not None:
                result = self._run_bandit_mutation(mutation_num, num_mutations, stats)
            else:
                result = self._run_single_mutation(mutation_num, num_mutations, stats)
            
            if result:
                self._update_stats(stats, result)
                
                if self.verbose:
                    self._print_mutation_result(mutation_num, result)
        
        stats.execution_time_ms = (time.perf_counter() - campaign_start) * 1000
        stats.total_distinct_touched = distinct_touched(bytes(self.global_touch_bitmap))
        
        self.db.end_campaign(self.campaign_id)
        
        if self.verbose:
            self._print_campaign_summary(stats)
        
        return stats
    
    def _run_single_mutation(
        self, 
        mutation_num: int, 
        total: int,
        stats: CampaignStats
    ) -> Optional[MutationResult]:
        """Run a single mutation attempt with retry logic"""
        # Phase III.2: 'uniform' couples kind and step (uniform draw over
        # the bandit's arm universe) and must re-draw both on retry.
        is_uniform = self.selector_strategy == "uniform"

        # For non-uniform strategies, pick kind once outside the retry loop.
        if not is_uniform:
            if self.kind == "all":
                kind = self.rng.choice(self.MUTATION_KINDS)
            else:
                kind = self.kind

        # Retry loop: step selection is coarse-grained (by major), but
        # mutation creation does finer validation. Retry up to 10 times
        # to find a valid target.
        MAX_RETRIES = 10
        for attempt in range(MAX_RETRIES):
            # Select step (and kind, for uniform)
            if is_uniform:
                kind, step = self.selector.select_arm_then_step()
            else:
                step = self.selector.select_step(self.data, kind)
            if step is None:
                if self.verbose:
                    print(f"  [{mutation_num}/{total}] ⊘ SKIP: No valid steps for {kind}")
                stats.skipped_mutations += 1
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
                    print(f"  [{mutation_num}/{total}] ⊘ SKIP: Failed to create mutation: {e}")
                stats.skipped_mutations += 1
                return None
            
            if config is not None:
                break  # Success - found valid target
            
            # Step was valid by major but had no mutation target, retry
            if attempt == MAX_RETRIES - 1:
                if self.verbose:
                    print(f"  [{mutation_num}/{total}] ⊘ SKIP: No valid target after {MAX_RETRIES} retries for {kind}")
                stats.skipped_mutations += 1
                return None
        
        # Execute mutation
        # Use time.perf_counter() instead of time.time() because:
        # - perf_counter() is monotonic (never goes backward)
        # - time.time() can jump backward during WSL2 clock sync with Windows host
        start_time = time.perf_counter()
        config_path = self.temp_dir / f"mutation_{mutation_num}.json"
        config_path.write_text(json.dumps(config, indent=2))
        
        exec_result = run_a4_mutation(
            self.host_binary,
            self.host_args,
            config_path
        )
        
        end_time = time.perf_counter()
        execution_time = (end_time - start_time) * 1000
        
        output = exec_result.combined_output
        failures = exec_result.failures
        exit_code = exec_result.exit_code
        
        # Check for process crash (segfault, etc.)
        # Python subprocess returns negative signal number: -11 for SIGSEGV, -6 for SIGABRT
        # Shell returns 128+signal: 139 for SIGSEGV, 134 for SIGABRT
        # We check both conventions to be safe
        crash_signals_negative = (-11, -6, -8, -9, -10)  # SIGSEGV, SIGABRT, SIGFPE, SIGKILL, SIGBUS
        crash_signals_shell = (139, 134, 136, 137, 138)  # 128 + signal
        crashed = exit_code in crash_signals_negative or exit_code in crash_signals_shell
        
        # Check if proof was generated
        # "verify segment" error means proof WAS created but failed self-verification
        # Prover status "success" = proof generated
        proof_generated = self._check_proof_generated(output, exit_code)
        
        # Check for proof verification failure (verify segment panic)
        proof_verify_failed = self._check_proof_verification_failure(output)
        
        # Check if verifier accepted (look for specific output)
        verifier_accepted = self._check_verifier_acceptance(output)
        
        # Extract exact error lines from risc0 for accurate tracing (unmodified)
        raw_errors = self._extract_raw_error(exec_result.stdout, exec_result.stderr)
        
        # Truncate raw output to last 2000 chars for debugging
        raw_output_truncated = output[-2000:] if len(output) > 2000 else output
        
        # Global constraint info from Hook 3 (Phase III.0: also derives F_glob set)
        broken_families, broken_addresses, is_global_only, global_contexts = (
            self._derive_global_info(exec_result, failures)
        )

        result = MutationResult(
            kind=kind,
            step=step,
            original_value=original_value,
            mutated_value=mutated_value,
            config=config,
            failures=failures,
            verifier_accepted=verifier_accepted,
            execution_time_ms=execution_time,
            exit_code=exit_code,
            crashed=crashed,
            proof_generated=proof_generated,
            proof_verify_failed=proof_verify_failed,
            raw_errors=raw_errors,
            raw_output=raw_output_truncated,
            broken_families=broken_families,
            broken_addresses=broken_addresses,
            is_global_only=is_global_only,
            family_details=exec_result.family_details,
            global_contexts=global_contexts,
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
            verifier_accepted,
            original_value=original_value,
        )
        
        total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)
        # Phase III.1: persist global Hook 3 contexts for offline analysis.
        if global_contexts:
            self.db.record_global_failures(mutation_id, global_contexts)
        result.new_coverage = new_coverage
        
        # Phase 3.3: Touch coverage — count new bits and merge into global bitmap
        if exec_result.touch_bitmap is not None:
            new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
            merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
            result.new_touch = new_touch
        
        # Phase II.5a: Reward computation for coverage tracking (non-bandit mode)
        # Phase III.0: now passes global_contexts to both compute_reward and update_state.
        if self.coverage_state is not None:
            outcome = self._classify_outcome(result)
            reward, diag = compute_reward(
                exec_result.touch_bitmap, failures, exit_code,
                outcome, proof_generated, self.coverage_state,
                global_contexts=global_contexts,
            )
            result.reward = reward
            result.reward_diag = diag
            update_state(
                exec_result.touch_bitmap, failures, exit_code, self.coverage_state,
                global_contexts=global_contexts,
            )
            if self.telemetry_level != "none":
                self.db.record_reward_diag(mutation_id, diag)
            self._record_full_telemetry(
                mutation_id,
                kind=kind,
                step=step,
                exec_result=exec_result,
                config=config,
                original_value=original_value,
                mutated_value=mutated_value,
                legacy_reward_diag=diag,
            )

        # Update guided selector if applicable
        if hasattr(self.selector, 'record_mutation'):
            self.selector.record_mutation(step, new_coverage + result.new_touch)

        if self.debug_bandit_trace_path:
            hook = self._parse_hook_step(kind, output)
            hook_step = int(hook["step"]) if hook and "step" in hook else None
            self._append_bandit_trace_debug({
                "mutation_num": mutation_num,
                "bandit_kind": kind,
                "bandit_zone": None,
                "bandit_step": step,
                "executed_kind": kind,
                "executed_step": step,
                "hook_kind": kind if hook is not None else None,
                "hook_step": hook_step,
            })
            self._patch_bandit_trace_mutation_id(mutation_num, mutation_id)
        
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
                "_info": {
                    "register_idx": target.register_idx,
                    "register_name": target.register_name,
                    "original_value": target.original_value,
                    "pc": f"0x{target.pc:08x}",
                },
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
                "_info": {
                    "register_idx": target.register_idx,
                    "register_name": target.register_name,
                    "original_value": target.original_value,
                    "pc": f"0x{target.pc:08x}",
                },
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
                "_info": {
                    "memory_byte_addr": f"0x{target.memory_byte_addr:08x}",
                    "original_value": target.original_value,
                    "pc": f"0x{target.pc:08x}",
                },
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
                "_info": {
                    "register_idx": target.register_idx,
                    "register_name": target.register_name,
                    "is_write": target.is_write,
                    "original_value": target.original_word,
                    "pc": f"0x{target.pc:08x}",
                },
            }
            return config, mutated_value, target.original_word
        
        elif kind == "INSTR_TYPE_MOD":
            target = get_instr_type_targets(step, self.data)
            if not target:
                return None, 0, 0
            new_major, new_minor, is_valid = generate_instr_mutation(target, self.rng)
            mutated_value = (new_major << 16) | new_minor  # Encode for tracking
            original_value = (target.original_major << 16) | target.original_minor
            # Get instruction name for mutated combination (kind = major*8 + minor)
            from a4.core.insn_decode import INSN_KIND_NAMES
            mutated_kind_num = new_major * 8 + new_minor
            mutated_kind = INSN_KIND_NAMES.get(mutated_kind_num, 
                                                f"Unknown({new_major},{new_minor})")
            config = {
                "mutation_type": "INSTR_TYPE_MOD",
                "step": target.step,
                "major": new_major,
                "minor": new_minor,
                "_info": {
                    "original_major": target.original_major,
                    "original_minor": target.original_minor,
                    "original_kind": target.kind_name,
                    "mutated_kind": mutated_kind,
                    "pc": f"0x{target.pc:08x}",
                    "is_valid_combination": is_valid,
                },
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
                "_info": {
                    "txn_type": target.txn_type,
                    "byte_addr": f"0x{target.byte_addr:08x}",
                    "is_write": target.is_write,
                    "original_value": target.original_value,
                },
            }
            return config, mutated_value, target.original_value
        
        elif kind == "INSTR_WORD_MOD_FULL":
            # INSTR_WORD_MOD_FULL: Mutate entire instruction word (32 bits)
            # Uses arguzz's mutation strategy: validated random mutations
            target = get_instr_word_targets(step, self.data)
            if not target:
                return None, 0, 0
            
            # Generate mutation using arguzz's strategy (validated loop)
            mutated_value = self._generate_valid_instr_word_mutation(target.original_word)
            if mutated_value is None:
                return None, 0, 0
            
            # Decode both instructions for detailed output
            orig_instr = RiscVInstruction.from_word(target.original_word)
            mut_instr = RiscVInstruction.from_word(mutated_value)
            
            # Note: Rust handler sets both word AND prev_word to preserve IsRead
            config = {
                "mutation_type": "INSTR_WORD_MOD",  # Rust handler name unchanged
                "step": target.step,
                "word": mutated_value,
                "original_disassembly": orig_instr.disassemble(),
                "mutated_disassembly": mut_instr.disassemble(),
                "original_format": orig_instr.format.value,
                "mutated_format": mut_instr.format.value,
                "_info": {
                    "original_value": target.original_word,
                },
            }
            return config, mutated_value, target.original_word
        
        elif kind == "INSTR_WORD_MOD_SUR":
            # INSTR_WORD_MOD_SUR: Surgical field-level mutation
            target = get_instr_word_sur_targets(step, self.data)
            if not target:
                return None, 0, 0
            
            # Decode instruction to understand format
            instr = target.instruction
            
            # Select which field to mutate
            surgical_field = select_surgical_field(instr, self.rng)
            if surgical_field is None:
                return None, 0, 0
            
            # Get original field value
            original_field_value = instr.get_field_value(surgical_field)
            
            # Generate a new value for that field
            new_field_value = generate_field_value(
                surgical_field, original_field_value, instr, self.rng
            )
            
            # Apply the surgical mutation
            mutated_value = instr.encode_with_mutation(surgical_field, new_field_value)
            
            # Ensure the mutation actually changed something
            if mutated_value == target.original_word:
                return None, 0, 0
            
            # Decode mutated instruction for disassembly
            mutated_instr = RiscVInstruction.from_word(mutated_value)
            
            # Note: Rust handler is the same as INSTR_WORD_MOD
            config = {
                "mutation_type": "INSTR_WORD_MOD",  # Rust handler name unchanged
                "step": target.step,
                "word": mutated_value,
                # Surgical mutation details (top-level for easy access in output)
                "surgical_field": surgical_field.value,
                "original_field_value": original_field_value,
                "mutated_field_value": new_field_value,
                "original_disassembly": instr.disassemble(),
                "mutated_disassembly": mutated_instr.disassemble(),
                "instruction_format": instr.format.value,
                "format_name": instr.format_name,
                "_info": {
                    "original_value": target.original_word,
                },
            }
            return config, mutated_value, target.original_word
        
        return None, 0, 0
    
    def _is_valid_rv32im_instruction(self, word: int) -> bool:
        """
        Check if a 32-bit word is a valid RV32IM instruction.
        
        Ported from arguzz's insn_kind_from_decoded (rv32im.rs:55-116).
        Checks the full (opcode, funct3, funct7) combination, not just opcode.
        """
        # Bits 0-1 must be 0b11 for a 32-bit instruction
        if (word & 0x03) != 0x03:
            return False
        
        opcode = word & 0x7F
        funct3 = (word >> 12) & 0x7
        funct7 = (word >> 25) & 0x7F
        
        # R-type (opcode=0b0110011) - need specific funct3/funct7 combinations
        if opcode == 0b0110011:
            valid_r_type = {
                # Base RV32I
                (0b000, 0b0000000),  # ADD
                (0b000, 0b0100000),  # SUB
                (0b001, 0b0000000),  # SLL
                (0b010, 0b0000000),  # SLT
                (0b011, 0b0000000),  # SLTU
                (0b100, 0b0000000),  # XOR
                (0b101, 0b0000000),  # SRL
                (0b101, 0b0100000),  # SRA
                (0b110, 0b0000000),  # OR
                (0b111, 0b0000000),  # AND
                # RV32M extension
                (0b000, 0b0000001),  # MUL
                (0b001, 0b0000001),  # MULH
                (0b010, 0b0000001),  # MULHSU
                (0b011, 0b0000001),  # MULHU
                (0b100, 0b0000001),  # DIV
                (0b101, 0b0000001),  # DIVU
                (0b110, 0b0000001),  # REM
                (0b111, 0b0000001),  # REMU
            }
            return (funct3, funct7) in valid_r_type
        
        # I-type ALU (opcode=0b0010011) - some need specific funct7
        if opcode == 0b0010011:
            if funct3 == 0b001:  # SLLI
                return funct7 == 0b0000000
            if funct3 == 0b101:  # SRLI/SRAI
                return funct7 in (0b0000000, 0b0100000)
            # ADDI, SLTI, SLTIU, XORI, ORI, ANDI - funct7 is part of immediate
            return funct3 in (0b000, 0b010, 0b011, 0b100, 0b110, 0b111)
        
        # I-type LOAD (opcode=0b0000011) - valid funct3 values
        if opcode == 0b0000011:
            return funct3 in (0b000, 0b001, 0b010, 0b100, 0b101)  # LB, LH, LW, LBU, LHU
        
        # S-type STORE (opcode=0b0100011) - valid funct3 values
        if opcode == 0b0100011:
            return funct3 in (0b000, 0b001, 0b010)  # SB, SH, SW
        
        # B-type BRANCH (opcode=0b1100011) - valid funct3 values
        if opcode == 0b1100011:
            return funct3 in (0b000, 0b001, 0b100, 0b101, 0b110, 0b111)  # BEQ, BNE, BLT, BGE, BLTU, BGEU
        
        # U-type: LUI (0b0110111), AUIPC (0b0010111) - any funct3 valid
        if opcode in (0b0110111, 0b0010111):
            return True
        
        # J-type: JAL (0b1101111) - any funct3 valid
        if opcode == 0b1101111:
            return True
        
        # I-type: JALR (0b1100111) - any funct3 valid (though typically 0)
        if opcode == 0b1100111:
            return True
        
        # SYSTEM (opcode=0b1110011) - specific funct3/funct7 for ECALL, EBREAK, MRET
        if opcode == 0b1110011:
            if funct3 == 0b000:
                # ECALL: funct7=0, rs2=0; EBREAK: funct7=0, rs2=1; MRET: funct7=0b0011000
                rs2 = (word >> 20) & 0x1F
                imm_11_0 = (word >> 20) & 0xFFF
                return imm_11_0 in (0b000000000000, 0b000000000001, 0b001100000010)
            return False
        
        # MISC-MEM: FENCE (opcode=0b0001111)
        if opcode == 0b0001111:
            return funct3 == 0b000
        
        return False
    
    def _generate_valid_instr_word_mutation(self, original_word: int, max_attempts: int = 100) -> Optional[int]:
        """
        Generate a mutated instruction word that is valid RV32IM.
        
        Uses arguzz's mutation strategy (rv32im.rs:190-222):
        - Strategy 0: Flip exactly 1 bit (bits 2-31)
        - Strategy 1: Flip N random bits (bits 2-31)
        - Strategy 2: Random word with bits 0-1 = 0b11
        
        Loops until we get a word that is:
        1. Different from original
        2. Valid RV32IM instruction
        """
        for _ in range(max_attempts):
            strategy = self.rng.randint(0, 2)
            
            if strategy == 0:
                # Strategy 0: Flip exactly 1 bit (bits 2-31)
                bit_to_flip = self.rng.randint(2, 31)
                new_word = original_word ^ (1 << bit_to_flip)
            
            elif strategy == 1:
                # Strategy 1: Flip N random bits (bits 2-31)
                n = self.rng.randint(1, 29)
                bits_to_flip = self.rng.sample(range(2, 32), min(n, 30))
                new_word = original_word
                for bit in bits_to_flip:
                    new_word ^= (1 << bit)
            
            else:
                # Strategy 2: Random word with bits 0-1 = 0b11
                new_word = self.rng.randint(0, 0xFFFFFFFF) | 0x03
            
            # Check if valid and different
            if new_word != original_word and self._is_valid_rv32im_instruction(new_word):
                return new_word
        
        # Fallback: couldn't find valid mutation in max_attempts
        return None
    
    def _check_proof_generated(self, output: str, exit_code: int) -> bool:
        """
        Check if a proof was actually generated (even if invalid).
        
        From risc0 source (prover_impl.rs:271-280):
        1. SegmentReceipt is created in memory (proof generated)
        2. Then verify_integrity_with_context is called
        3. If verification fails, "verify segment" error occurs
        
        So "verify segment" error = proof WAS generated but failed self-verification
        Prover "status":"success" also means proof was generated (from main.rs:131-138)
        """
        # If process crashed (segfault), no proof was generated
        # Python subprocess: negative signal, Shell: 128+signal
        crash_signals_negative = (-11, -6, -8, -9, -10)
        crash_signals_shell = (139, 134, 136, 137, 138)
        if exit_code in crash_signals_negative or exit_code in crash_signals_shell:
            return False
        
        # "verify segment" means proof WAS created but failed verification
        if "verify segment" in output:
            return True
        
        # Prover success means proof was generated
        # NOTE: The actual JSON uses "status":"success", not "status":"ok"
        if '"context":"Prover"' in output and '"status":"success"' in output:
            return True
        
        # If we see verifier output, proof must have been generated
        if '"context":"Verifier"' in output:
            return True
        
        return False
    
    def _check_proof_verification_failure(self, output: str) -> bool:
        """
        Check if proof self-verification failed ("verify segment" panic).
        
        This is DIFFERENT from verifier rejection:
        - "verify segment" = prover's internal self-check failed (proof generated but invalid)
        - This always indicates the mutation was effective (constraints broken)
        """
        return "verify segment" in output
    
    def _extract_raw_error(self, stdout: str, stderr: str) -> List[str]:
        """
        Extract error messages from risc0 prover output with verified source locations.
        
        Each error is annotated with its exact source file and line number.
        Only includes annotations we can verify from source code.
        """
        import re
        
        errors = []
        
        # Extract panic info from stderr
        # Format: "thread 'main' panicked at host/src/main.rs:150:13:\nverify segment"
        # - The panic location (host/src/main.rs:150) is where panic!() is called
        # - The message "verify segment" is added at prover_impl.rs:280 via .context()
        panic_loc_match = re.search(r"panicked at ([^:]+:\d+:\d+):", stderr)
        panic_msg_lines = []
        in_panic = False
        for line in stderr.split('\n'):
            line = line.strip()
            if 'panicked at' in line:
                in_panic = True
                continue
            if in_panic and line and not line.startswith('note:'):
                panic_msg_lines.append(line)
            elif line.startswith('note:'):
                in_panic = False
        
        if panic_loc_match and panic_msg_lines:
            panic_loc = panic_loc_match.group(1)
            panic_msg = ' '.join(panic_msg_lines)
            # "verify segment" is added at prover_impl.rs:280
            if 'verify segment' in panic_msg:
                errors.append(f"[prover_impl.rs:280] verify segment (internal proof verification failed)")
            else:
                errors.append(f"[{panic_loc}] {panic_msg}")
        
        # Extract address mismatch from stdout
        # Source: ffi.cpp:113 - printf("[%lu]: txn.addr: 0x%08x, addr: 0x%08x\n", ...)
        addr_match = re.search(r"\[(\d+)\]: txn\.addr: (0x[0-9a-fA-F]+), addr: (0x[0-9a-fA-F]+)", stdout)
        if addr_match:
            cycle = addr_match.group(1)
            expected = addr_match.group(2)
            actual = addr_match.group(3)
            errors.append(f"[ffi.cpp:113] address mismatch at cycle {cycle}: preflight={expected}, actual={actual}")
        
        # Extract SKIP THROW from stdout
        # Source: ffi.cpp:121 - printf("SKIP THROW: %s @ %s:%d\n", ...)
        skip_match = re.search(r"SKIP THROW: ([^@]+)@ ([^\n]+)", stdout)
        if skip_match:
            reason = skip_match.group(1).strip()
            location = skip_match.group(2).strip()
            errors.append(f"[{location}] SKIP THROW: {reason}")
        
        return errors
    
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
        
        # Classify outcome (mutually exclusive, priority order):
        # 1. ACCEPTED (bug) - verifier accepted invalid proof
        # 2. CRASH - process crashed (segfault, etc.)
        # 3. REJECTED - constraint failures OR proof verification failed
        # 4. NO_EFFECT - no failures detected
        if result.verifier_accepted:
            stats.verifier_accepts += 1
        
        if result.crashed:
            # Process crashed - something severe happened
            stats.crashes += 1
        elif result.failures or result.proof_verify_failed:
            # Constraint failures detected OR proof verification failed - mutation was effective!
            stats.successful_mutations += 1
        # else: no effect (counted implicitly)
        
        stats.new_coverage_count += result.new_coverage
        stats.new_touch_count += result.new_touch
        
        if result.broken_families:
            stats.global_violations += 1
            if result.is_global_only:
                stats.global_only += 1
        local_fails = [f for f in result.failures if f.phase == "local"]
        if local_fails and not result.broken_families:
            stats.local_only += 1
    
    _REG_ABI = [
        "zero","ra","sp","gp","tp","t0","t1","t2",
        "s0","s1","a0","a1","a2","a3","a4","a5",
        "a6","a7","s2","s3","s4","s5","s6","s7",
        "s8","s9","s10","s11","t3","t4","t5","t6",
    ]

    @staticmethod
    def _format_mem_mismatch(info: dict) -> str:
        """Format a single broken memory address for display."""
        reg = info.get("reg")
        if reg:
            idx = int(reg[1:]) if reg.startswith("x") and reg[1:].isdigit() else -1
            abi = A4Fuzzer._REG_ABI
            name = f"{reg}/{abi[idx]}" if 0 <= idx < 32 else reg
        else:
            byte_addr = info.get("byte_addr")
            if byte_addr is not None:
                addr_type = info.get("type", "data")
                name = f"0x{int(byte_addr):08X} ({addr_type})"
            else:
                name = info.get("hex", f"0x{info.get('addr', 0):08x}")

        wrote = info.get("wrote")
        expected = info.get("expected")
        cycle = info.get("mismatch_cycle")
        cycle_str = f" (cycle {cycle})" if cycle is not None else ""

        if wrote is not None and expected is not None:
            return f"{name}: wrote {wrote}, expected {expected}{cycle_str}"
        elif wrote is not None and expected is None:
            return f"{name}: unexpected write {wrote}{cycle_str}"
        elif wrote is None and expected is not None:
            return f"{name}: expected write missing, needed {expected}{cycle_str}"
        else:
            plus = info.get("plus", 0)
            minus = info.get("minus", 0)
            return f"{name}: {plus} +entries, {minus} -entries"

    def _print_mutation_result(self, num: int, result: MutationResult):
        """Print detailed result of a single mutation"""
        # Status indicator
        if result.verifier_accepted:
            status = "🐛"  # BUG - verifier accepted invalid proof
        elif result.crashed:
            status = "💥"  # Process crashed
        elif result.failures or result.proof_verify_failed or result.broken_families:
            status = "✓"  # Mutation detected - proof rejected
        else:
            status = "○"  # No effect detected
        
        outcome = self._classify_outcome(result)
        bug_marker = " BUG!" if result.verifier_accepted else ""
        new_cov = f" [+{result.new_coverage} new]" if result.new_coverage > 0 else ""
        new_touch_str = f" [+{result.new_touch} touch]" if result.new_touch > 0 else ""
        
        # Proof status for clarity
        proof_status = ""
        if result.proof_generated:
            proof_status = " [proof:GENERATED]"
        elif result.crashed:
            proof_status = " [proof:NOT_GENERATED]"
        
        # Global marker
        global_marker = ""
        if result.broken_families:
            fams = "|".join(result.broken_families)
            if result.is_global_only:
                global_marker = f" G={fams}[GO]"
            else:
                global_marker = f" G={fams}"
        
        local_count = len([f for f in result.failures if f.phase == "local"])
        accum_count = len([f for f in result.failures if f.phase == "accum"])
        fail_str = f"{local_count}L {accum_count}A" if accum_count > 0 else f"{local_count} failures"
        
        # Basic info line
        print(f"  [{num}] {status} {result.kind} @ step {result.step}: "
              f"{fail_str}, {result.execution_time_ms:.0f}ms, "
              f"outcome: {outcome}, exit: {result.exit_code}"
              f"{proof_status}{new_cov}{new_touch_str}{global_marker}{bug_marker}")
        
        if result.reward_diag is not None:
            d = result.reward_diag
            # Phase III.0: U replaces Z; Q_l/Q_g surface the loc/glob factors;
            # dl/dg replace df with both halves of d_ext.
            print(f"       r={result.reward:.3f}  T_new={d.get('T_new',0):.2f} "
                  f"F_new={d.get('F_new',0):.2f} F_rare={d.get('F_rare',0):.2f} "
                  f"U={d.get('U',0)} Q={d.get('Q',0):.2f} "
                  f"Q_l={d.get('Q_loc',0):.2f} Q_g={d.get('Q_glob',1):.2f} "
                  f"dl={d.get('d_loc',0)} dg={d.get('d_glob',0)}")
        
        # Value change info
        print(f"       Value: 0x{result.original_value:08X} -> 0x{result.mutated_value:08X}")
        
        # Show instruction details for INSTR_WORD_MOD mutations
        if result.kind == "INSTR_WORD_MOD_SUR" and result.config:
            surgical_field = result.config.get("surgical_field", "unknown")
            orig_field_val = result.config.get("original_field_value", "?")
            mut_field_val = result.config.get("mutated_field_value", "?")
            orig_disasm = result.config.get("original_disassembly", "")
            mut_disasm = result.config.get("mutated_disassembly", "")
            print(f"       Surgical: {surgical_field} = {orig_field_val} -> {mut_field_val}")
            if orig_disasm:
                print(f"       Original: {orig_disasm}")
            if mut_disasm:
                print(f"       Mutated:  {mut_disasm}")
        elif result.kind == "INSTR_WORD_MOD_FULL" and result.config:
            orig_disasm = result.config.get("original_disassembly", "")
            mut_disasm = result.config.get("mutated_disassembly", "")
            orig_fmt = result.config.get("original_format", "")
            mut_fmt = result.config.get("mutated_format", "")
            if orig_disasm:
                print(f"       Original: {orig_disasm}")
            if mut_disasm:
                print(f"       Mutated:  {mut_disasm}")
            if orig_fmt != mut_fmt:
                print(f"       Format changed: {orig_fmt} -> {mut_fmt}")
        elif result.kind == "INSTR_TYPE_MOD" and result.config:
            # Show decoded major/minor values with instruction names
            info = result.config.get("_info", {})
            orig_major = info.get("original_major", "?")
            orig_minor = info.get("original_minor", "?")
            orig_kind = info.get("original_kind", "?")
            mut_kind = info.get("mutated_kind", "?")
            mut_major = result.config.get("major", "?")
            mut_minor = result.config.get("minor", "?")
            is_valid = info.get("is_valid_combination", True)
            valid_marker = "" if is_valid else " ⚠INVALID"
            # Format: "InstructionName [major=X, minor=Y]"
            print(f"       Original: {orig_kind} [major={orig_major}, minor={orig_minor}]")
            print(f"       Mutated:  {mut_kind} [major={mut_major}, minor={mut_minor}]{valid_marker}")
        elif result.kind == "COMP_OUT_MOD" and result.config:
            # Show destination register (rd) being mutated
            info = result.config.get("_info", {})
            reg_name = info.get("register_name", "?")
            reg_idx = info.get("register_idx", "?")
            print(f"       Destination: rd = x{reg_idx} ({reg_name})")
        elif result.kind == "LOAD_VAL_MOD" and result.config:
            # Show destination register being mutated (load result)
            info = result.config.get("_info", {})
            reg_name = info.get("register_name", "?")
            reg_idx = info.get("register_idx", "?")
            print(f"       Load destination: rd = x{reg_idx} ({reg_name})")
        elif result.kind == "STORE_OUT_MOD" and result.config:
            # Show memory address being written to
            info = result.config.get("_info", {})
            mem_addr = info.get("memory_byte_addr", "?")
            print(f"       Store address: {mem_addr}")
        elif result.kind == "PRE_EXEC_REG_MOD" and result.config:
            # Show register being mutated
            info = result.config.get("_info", {})
            reg_name = info.get("register_name", "?")
            reg_idx = info.get("register_idx", "?")
            is_write = info.get("is_write", False)
            strategy = result.config.get("strategy", "?")
            op = "WRITE" if is_write else "READ"
            print(f"       Register: x{reg_idx} ({reg_name}), {op}, strategy={strategy}")
        elif result.kind == "MEM_VAL_MOD" and result.config:
            # Show memory transaction type and address
            # Note: "Value" line above shows original -> mutated value
            # This line shows WHERE in memory and WHAT TYPE of transaction
            info = result.config.get("_info", {})
            txn_type = info.get("txn_type", "?")
            byte_addr = info.get("byte_addr", "?")
            is_write = info.get("is_write", False)
            op = "WRITE" if is_write else "READ"
            print(f"       Transaction: {txn_type} ({op}) at address {byte_addr}")
        
        # Show raw errors from risc0 for accurate outcome tracing (exact text, no reformatting)
        if result.raw_errors:
            print(f"       zkVM errors ({len(result.raw_errors)} lines):")
            for err in result.raw_errors:
                print(f"         • {err}")
        
        # Constraint failure details (separated by phase)
        if result.failures:
            local_failures = [f for f in result.failures if f.phase == "local"]
            accum_failures = [f for f in result.failures if f.phase == "accum"]
            
            if local_failures:
                local_by_loc = {}
                for f in local_failures:
                    loc = f.constraint_loc()
                    if loc not in local_by_loc:
                        local_by_loc[loc] = []
                    local_by_loc[loc].append(f)
                print(f"       Local constraints hit ({len(local_by_loc)} unique):")
                for loc, fails in sorted(local_by_loc.items()):
                    first = fails[0]
                    count_str = f" (x{len(fails)})" if len(fails) > 1 else ""
                    print(f"         - {loc}{count_str}")
                    print(f"           cycle={first.cycle}, step={first.step}, "
                          f"pc=0x{first.pc:08X}, major={first.major}, minor={first.minor}")
            
            if accum_failures:
                accum_by_loc = {}
                for f in accum_failures:
                    loc = f.constraint_loc()
                    if loc not in accum_by_loc:
                        accum_by_loc[loc] = []
                    accum_by_loc[loc].append(f)
                print(f"       Accum constraints hit ({len(accum_by_loc)} unique):")
                for loc, fails in sorted(accum_by_loc.items()):
                    first = fails[0]
                    count_str = f" (x{len(fails)})" if len(fails) > 1 else ""
                    label = "BigInt" if "BigInt" in loc or "inst_bigint" in loc else "AccumDelta"
                    print(f"         - [{label}] {loc}{count_str}")
                    print(f"           cycle={first.cycle}, step={first.step}, "
                          f"pc=0x{first.pc:08X}, major={first.major}, minor={first.minor}")
        elif not result.broken_families:
            if result.proof_verify_failed:
                print(f"       Proof verification failed (no constraint failures detected)")
            elif outcome == "NO_EFFECT":
                print(f"       No constraint failures detected")
            else:
                print(f"       No constraint failures (mutation may have been ineffective)")
        
        # Global constraint info from Hook 3
        if result.broken_families:
            go_str = " [GLOBAL-ONLY]" if result.is_global_only else ""

            # Memory permutation violations
            if "memory" in result.broken_families:
                mem_detail = None
                if result.family_details:
                    for fd in result.family_details:
                        if fd.get("family") == "memory":
                            mem_detail = fd
                            break
                broken_count = mem_detail.get("broken_count", 0) if mem_detail else 0
                n_reg = mem_detail.get("n_reg", 0) if mem_detail else 0
                n_code = mem_detail.get("n_code", 0) if mem_detail else 0
                n_data = mem_detail.get("n_data", 0) if mem_detail else 0
                mem_addrs = mem_detail.get("broken_addrs", []) if mem_detail else []

                if broken_count >= 10:
                    parts = []
                    if n_reg: parts.append(f"{n_reg} register")
                    if n_code: parts.append(f"{n_code} code")
                    if n_data: parts.append(f"{n_data} data")
                    type_str = ", ".join(parts)
                    print(f"       Global: memory permutation violated ({broken_count} addrs: {type_str}){go_str}")
                    interesting = [a for a in mem_addrs if a.get("type") != "code"]
                    for a in interesting[:3]:
                        print(f"         {self._format_mem_mismatch(a)}")
                    code_shown = sum(1 for a in mem_addrs if a.get("type") == "code")
                    remaining = broken_count - len(interesting[:3])
                    if n_code:
                        print(f"         + {n_code} code addresses diverged (instruction fetch cascade)")
                        remaining -= n_code
                    if remaining > 0:
                        print(f"         + {remaining} more addresses")
                else:
                    print(f"       Global: memory permutation violated{go_str}")
                    for a in mem_addrs:
                        print(f"         {self._format_mem_mismatch(a)}")

            # Lookup violations
            if result.family_details:
                for fd in result.family_details:
                    fam = fd.get("family", "")
                    if fam == "memory":
                        continue
                    broken_indices = fd.get("broken_indices", [])
                    if not broken_indices:
                        continue
                    broken_count = fd.get("broken_count", len(broken_indices))
                    print(f"       Global: {fam} lookup violated ({broken_count} indices broken)")
                    for idx_info in broken_indices[:5]:
                        idx = idx_info.get("index", "?")
                        plus = idx_info.get("plus", 0)
                        minus = idx_info.get("minus", 0)
                        if plus > 0 and minus == 0:
                            print(f"         index {idx}: orphan provide ({plus} entries, no matching use)")
                        elif minus > 0 and plus == 0:
                            print(f"         index {idx}: orphan use ({minus} entries, no matching provide)")
                        else:
                            print(f"         index {idx}: {plus} provides, {minus} uses (imbalanced)")
                    if broken_count > 5:
                        print(f"         + {broken_count - 5} more indices")
        elif result.failures and not result.broken_families:
            print(f"       Global: no permutation/lookup violations (local-only)")
    
    def _print_campaign_summary(self, stats: CampaignStats):
        """Print campaign summary"""
        print("\n" + "="*60)
        print("Campaign Summary")
        print("="*60)
        print(f"Total mutations:     {stats.total_mutations}")
        print(f"Successful (caused failures): {stats.successful_mutations}")
        print(f"Skipped (no valid target):    {stats.skipped_mutations}")
        print(f"Total failures:      {stats.total_failures}")
        print(f"Unique constraints:  {len(stats.unique_constraints)}")
        print(f"New coverage:        {stats.new_coverage_count}")
        print(f"New touch:           {stats.new_touch_count}")
        print(f"Distinct touched:    {stats.total_distinct_touched}")
        print(f"\nGlobal Constraint Summary:")
        print(f"  Mutations with global violations: {stats.global_violations}")
        print(f"  Global-only (no local failures):  {stats.global_only}")
        print(f"  Local-only (no global violations):{stats.local_only}")
        print(f"Execution time:      {stats.execution_time_ms:.0f}ms")
        
        # Outcome summary (mutually exclusive categories)
        # - successful_mutations: REJECTED (constraint failures detected, proof invalid)
        # - crashes: CRASH (process crashed, segfault, etc.)
        # - verifier_accepts: ACCEPTED (BUG!)
        # - no_effect: NO_EFFECT (no failures)
        # - skipped: No valid target found after retries
        rejected = stats.successful_mutations  # Mutation detected, proof rejected
        crashes = stats.crashes  # Process crashed
        no_effect = stats.total_mutations - rejected - crashes
        
        print(f"\nOutcome breakdown:")
        print(f"  REJECTED (mutation detected): {rejected}")
        print(f"  CRASH (segfault, etc.):       {crashes}")
        print(f"  NO_EFFECT:                    {no_effect}")
        print(f"  ACCEPTED (BUG!):              {stats.verifier_accepts} {'🐛' if stats.verifier_accepts > 0 else ''}")
        print(f"  SKIPPED:                      {stats.skipped_mutations}")
        
        if stats.verifier_accepts > 0:
            print(f"\n🐛 BUGS FOUND: {stats.verifier_accepts} mutations accepted by verifier!")
        
        print(f"\nMutations by kind:")
        for kind, count in sorted(stats.mutations_by_kind.items()):
            print(f"  {kind}: {count}")
        
        if self.scheduler is not None:
            print(f"\n{self.scheduler.summary()}")
    
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
