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
from a4.core.executor import run_a4_mutation, MutationExecutionResult
from a4.core.constraint_parser import ConstraintFailure
from a4.core.touch_coverage import (
    make_global_bitmap, count_new_bits, merge_into_global, distinct_touched,
)

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
    exit_code: int = 0  # Process exit code (139=SIGSEGV, 101=panic, 0=success)
    crashed: bool = False  # True if process crashed (segfault, etc.)
    proof_generated: bool = False  # True if proof was generated (may still be invalid)
    proof_verify_failed: bool = False  # True if proof verification failed (verify segment)
    raw_errors: List[str] = field(default_factory=list)  # Exact error lines from risc0 prover (unmodified)
    raw_output: Optional[str] = None  # Raw stdout for debugging (truncated)


@dataclass
class CampaignStats:
    """Statistics for a fuzzing campaign"""
    total_mutations: int = 0
    successful_mutations: int = 0  # Caused failures (REJECTED)
    verifier_accepts: int = 0      # BUGS: verifier accepted bad proof
    crashes: int = 0               # CRASH: process crashed (segfault, etc.)
    skipped_mutations: int = 0     # Mutations skipped (no valid target after retries)
    new_coverage_count: int = 0
    new_touch_count: int = 0
    total_distinct_touched: int = 0
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
        
        # Phase 3.3: Global touch bitmap (campaign-level accumulator)
        self.global_touch_bitmap: bytearray = make_global_bitmap()
        
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
            result = self._run_single_mutation(i + 1, num_mutations, stats)
            
            if result:
                self._update_stats(stats, result)
                
                if self.verbose:
                    self._print_mutation_result(i + 1, result)
        
        stats.execution_time_ms = (time.perf_counter() - campaign_start) * 1000
        
        # Phase 3.3: Record final bitmap occupancy
        stats.total_distinct_touched = distinct_touched(bytes(self.global_touch_bitmap))
        
        # End campaign
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
        # Select mutation kind
        if self.kind == "all":
            kind = self.rng.choice(self.MUTATION_KINDS)
        else:
            kind = self.kind
        
        # Retry loop: step selection is coarse-grained (by major), but
        # mutation creation does finer validation. Retry up to 10 times
        # to find a valid target.
        MAX_RETRIES = 10
        for attempt in range(MAX_RETRIES):
            # Select step
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
        
        # Phase 3.3: Touch coverage — count new bits and merge into global bitmap
        if exec_result.touch_bitmap is not None:
            new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
            merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
            result.new_touch = new_touch
        
        # Update guided selector if applicable
        if hasattr(self.selector, 'record_mutation'):
            self.selector.record_mutation(step, new_coverage + result.new_touch)
        
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
    
    def _print_mutation_result(self, num: int, result: MutationResult):
        """Print detailed result of a single mutation"""
        # Status indicator
        if result.verifier_accepted:
            status = "🐛"  # BUG - verifier accepted invalid proof
        elif result.crashed:
            status = "💥"  # Process crashed
        elif result.failures or result.proof_verify_failed:
            status = "✓"  # Mutation detected - proof rejected
        else:
            status = "○"  # No effect detected
        
        bug_marker = " BUG!" if result.verifier_accepted else ""
        new_cov = f" [+{result.new_coverage} new]" if result.new_coverage > 0 else ""
        new_touch_str = f" [+{result.new_touch} touch]" if result.new_touch > 0 else ""
        
        # Outcome classification (priority order):
        # 
        # ACCEPTED = Verifier accepted (BUG!) - soundness violation
        # CRASH = Process crashed (segfault, etc.) - severe mutation effect
        # REJECTED = Proof invalid - constraint failures OR verify segment failed
        # NO_EFFECT = No failures detected
        #
        if result.verifier_accepted:
            outcome = "ACCEPTED"  # BUG: soundness violation!
        elif result.crashed:
            outcome = "CRASH"  # Process crashed (segfault, etc.)
        elif result.failures or result.proof_verify_failed:
            outcome = "REJECTED"  # Mutation detected, proof invalid
        else:
            outcome = "NO_EFFECT"  # No failures detected
        
        # Proof status for clarity
        proof_status = ""
        if result.proof_generated:
            proof_status = " [proof:GENERATED]"
        elif result.crashed:
            proof_status = " [proof:NOT_GENERATED]"
        
        # Basic info line
        print(f"  [{num}] {status} {result.kind} @ step {result.step}: "
              f"{len(result.failures)} failures, {result.execution_time_ms:.0f}ms, "
              f"outcome: {outcome}, exit: {result.exit_code}"
              f"{proof_status}{new_cov}{new_touch_str}{bug_marker}")
        
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
        elif result.proof_verify_failed:
            # Proof verification failed but no constraint tags emitted
            print(f"       Proof verification failed (no local constraint failures)")
        elif outcome == "NO_EFFECT":
            # No constraint failures detected - this is unusual and worth investigating
            print(f"       ⚠ No constraint failures detected - possible edge case or parsing issue")
        else:
            print(f"       No constraint failures (mutation may have been ineffective)")
    
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
