#!/usr/bin/env python3
"""
A4 Mutation Target Finder

This script finds the exact position in the post-preflight trace that corresponds
to an Arguzz INSTR_WORD_MOD mutation at a given step.

The mapping is based on:
1. PC matching: A4 records next_pc (after execution), Arguzz records current_pc (before execution)
   So: a4_pc == arguzz_pc + 4 (for sequential instructions)
2. Instruction type verification: major/minor from original word must match

This approach is more robust than counting ecalls because:
- PC is deterministic for the same program/inputs
- We verify instruction type as a sanity check
- We don't need to track which ecalls returned false

Usage:
    python find_mutation_target.py --arguzz-fault '<fault>{"step":200, "pc":2144416, "kind":"INSTR_WORD_MOD", "info":"word:3147283 => word:8897555"}</fault>'

Or pipe from command:
    ./risc0-host --trace --inject ... 2>&1 | grep "<fault>" | python find_mutation_target.py --from-stdin
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional, Tuple, List


# RISC-V Instruction Decoding (based on rv32im.rs lines 56-116)
# This maps (opcode, func3, func7) -> InsnKind

INSN_KIND_MAP = {
    # R-format arithmetic ops
    (0b0110011, 0b000, 0b0000000): 0,   # Add
    (0b0110011, 0b000, 0b0100000): 1,   # Sub
    (0b0110011, 0b100, 0b0000000): 2,   # Xor
    (0b0110011, 0b110, 0b0000000): 3,   # Or
    (0b0110011, 0b111, 0b0000000): 4,   # And
    (0b0110011, 0b010, 0b0000000): 5,   # Slt
    (0b0110011, 0b011, 0b0000000): 6,   # SltU
    # I-format arithmetic ops
    (0b0010011, 0b000, None): 7,        # AddI
    (0b0010011, 0b100, None): 8,        # XorI
    (0b0010011, 0b110, None): 9,        # OrI
    (0b0010011, 0b111, None): 10,       # AndI
    (0b0010011, 0b010, None): 11,       # SltI
    (0b0010011, 0b011, None): 12,       # SltIU
    # B-format branch
    (0b1100011, 0b000, None): 13,       # Beq
    (0b1100011, 0b001, None): 14,       # Bne
    (0b1100011, 0b100, None): 15,       # Blt
    (0b1100011, 0b101, None): 16,       # Bge
    (0b1100011, 0b110, None): 17,       # BltU
    (0b1100011, 0b111, None): 18,       # BgeU
    # J-format jal
    (0b1101111, None, None): 19,        # Jal
    # I-format jalr
    (0b1100111, None, None): 20,        # JalR
    # U-format
    (0b0110111, None, None): 21,        # Lui
    (0b0010111, None, None): 22,        # Auipc
    # Shift instructions
    (0b0110011, 0b001, 0b0000000): 24,  # Sll
    (0b0010011, 0b001, 0b0000000): 25,  # SllI
    # M extension
    (0b0110011, 0b000, 0b0000001): 26,  # Mul
    (0b0110011, 0b001, 0b0000001): 27,  # MulH
    (0b0110011, 0b010, 0b0000001): 28,  # MulHSU
    (0b0110011, 0b011, 0b0000001): 29,  # MulHU
    (0b0110011, 0b101, 0b0000000): 32,  # Srl
    (0b0110011, 0b101, 0b0100000): 33,  # Sra
    (0b0010011, 0b101, 0b0000000): 34,  # SrlI
    (0b0010011, 0b101, 0b0100000): 35,  # SraI
    (0b0110011, 0b100, 0b0000001): 36,  # Div
    (0b0110011, 0b101, 0b0000001): 37,  # DivU
    (0b0110011, 0b110, 0b0000001): 38,  # Rem
    (0b0110011, 0b111, 0b0000001): 39,  # RemU
    # Load instructions
    (0b0000011, 0b000, None): 40,       # Lb
    (0b0000011, 0b001, None): 41,       # Lh
    (0b0000011, 0b010, None): 42,       # Lw
    (0b0000011, 0b100, None): 43,       # LbU
    (0b0000011, 0b101, None): 44,       # LhU
    # Store instructions
    (0b0100011, 0b000, None): 48,       # Sb
    (0b0100011, 0b001, None): 49,       # Sh
    (0b0100011, 0b010, None): 50,       # Sw
    # System instructions
    (0b1110011, 0b000, 0b0000000): 56,  # Eany
    (0b1110011, 0b000, 0b0011000): 57,  # Mret
}

INSN_KIND_NAMES = {
    0: "Add", 1: "Sub", 2: "Xor", 3: "Or", 4: "And", 5: "Slt", 6: "SltU",
    7: "AddI", 8: "XorI", 9: "OrI", 10: "AndI", 11: "SltI", 12: "SltIU",
    13: "Beq", 14: "Bne", 15: "Blt", 16: "Bge", 17: "BltU", 18: "BgeU",
    19: "Jal", 20: "JalR", 21: "Lui", 22: "Auipc",
    24: "Sll", 25: "SllI", 26: "Mul", 27: "MulH", 28: "MulHSU", 29: "MulHU",
    32: "Srl", 33: "Sra", 34: "SrlI", 35: "SraI",
    36: "Div", 37: "DivU", 38: "Rem", 39: "RemU",
    40: "Lb", 41: "Lh", 42: "Lw", 43: "LbU", 44: "LhU",
    48: "Sb", 49: "Sh", 50: "Sw",
    56: "Eany", 57: "Mret",
    255: "Invalid",
}


@dataclass
class DecodedInstruction:
    """Decoded RISC-V instruction fields"""
    opcode: int
    rd: int
    func3: int
    rs1: int
    rs2: int
    func7: int
    imm_i: int
    imm_s: int
    imm_b: int
    imm_u: int
    imm_j: int
    
    @classmethod
    def from_word(cls, word: int) -> 'DecodedInstruction':
        """Decode a 32-bit RISC-V instruction word"""
        return cls(
            opcode=(word >> 0) & 0x7f,
            rd=(word >> 7) & 0x1f,
            func3=(word >> 12) & 0x07,
            rs1=(word >> 15) & 0x1f,
            rs2=(word >> 20) & 0x1f,
            func7=(word >> 25) & 0x7f,
            imm_i=(word >> 20) & 0xfff,
            imm_s=((word >> 7) & 0x1f) | (((word >> 25) & 0x7f) << 5),
            imm_b=((word >> 8) & 0xf) << 1 | ((word >> 25) & 0x3f) << 5 | 
                  ((word >> 7) & 0x1) << 11 | ((word >> 31) & 0x1) << 12,
            imm_u=(word >> 12) & 0xfffff,
            imm_j=((word >> 21) & 0x3ff) << 1 | ((word >> 20) & 0x1) << 11 |
                  ((word >> 12) & 0xff) << 12 | ((word >> 31) & 0x1) << 20,
        )


def get_insn_kind(word: int) -> int:
    """
    Get InsnKind from instruction word (based on rv32im.rs insn_kind_from_decoded)
    """
    decoded = DecodedInstruction.from_word(word)
    
    # Try exact match with func7
    key = (decoded.opcode, decoded.func3, decoded.func7)
    if key in INSN_KIND_MAP:
        return INSN_KIND_MAP[key]
    
    # Try match without func7 (for I-format, U-format, etc.)
    key = (decoded.opcode, decoded.func3, None)
    if key in INSN_KIND_MAP:
        return INSN_KIND_MAP[key]
    
    # Try match without func3 (for J-format jal, etc.)
    key = (decoded.opcode, None, None)
    if key in INSN_KIND_MAP:
        return INSN_KIND_MAP[key]
    
    return 255  # Invalid


def kind_to_major_minor(kind: int) -> Tuple[int, int]:
    """Convert InsnKind to major/minor (based on add_cycle_insn in preflight.rs)"""
    major = kind // 8
    minor = kind % 8
    return (major, minor)


@dataclass
class ArguzzFault:
    """Parsed Arguzz fault information"""
    step: int
    pc: int
    kind: str
    original_word: int
    mutated_word: int
    
    @classmethod
    def parse(cls, fault_line: str) -> Optional['ArguzzFault']:
        """Parse a <fault> line from Arguzz output"""
        # Extract JSON from <fault>...</fault>
        match = re.search(r'<fault>(\{.*?\})</fault>', fault_line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
        
        # Parse the info field for INSTR_WORD_MOD: "word:ORIGINAL => word:MUTATED"
        info = data.get('info', '')
        word_match = re.search(r'word:(\d+)\s*=>\s*word:(\d+)', info)
        if not word_match:
            return None
        
        return cls(
            step=data.get('step', 0),
            pc=data.get('pc', 0),
            kind=data.get('kind', ''),
            original_word=int(word_match.group(1)),
            mutated_word=int(word_match.group(2)),
        )


@dataclass
class A4CycleInfo:
    """Parsed A4 cycle information"""
    cycle_idx: int
    step: int  # user_cycle
    pc: int    # next_pc (after instruction)
    txn_idx: int
    major: int
    minor: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['A4CycleInfo']:
        """Parse an <a4_cycle_info> line"""
        match = re.search(r'<a4_cycle_info>(\{.*?\})</a4_cycle_info>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
        
        return cls(
            cycle_idx=data.get('cycle_idx', 0),
            step=data.get('step', 0),
            pc=data.get('pc', 0),
            txn_idx=data.get('txn_idx', 0),
            major=data.get('major', 0),
            minor=data.get('minor', 0),
        )


def find_mutation_target(
    arguzz_fault: ArguzzFault,
    a4_cycles: List[A4CycleInfo],
) -> Optional[A4CycleInfo]:
    """
    Find the A4 cycle that corresponds to the Arguzz mutation target.
    
    Matching strategy (handles loops correctly):
    1. PC match: A4 records next_pc, Arguzz records current_pc
       So for sequential instructions: a4_pc == arguzz_pc + 4
    2. Instruction type verification: major/minor must match original instruction
    3. Step disambiguation: If multiple matches (loops), pick the one with user_cycle
       closest to (but not greater than) arguzz_step
    
    Why this works without counting ECALLs:
    - We SEARCH for matching cycles by properties (PC, instruction type)
    - We use Arguzz step as an UPPER BOUND to disambiguate loop iterations
    - The offset (arguzz_step - user_cycle) is always non-negative because
      machine-mode ecalls cause user_cycle to not increment while arguzz step does
    - Among multiple matches, the correct one has the SMALLEST positive offset
    
    Returns the matching A4CycleInfo or None if not found.
    """
    # Calculate expected major/minor from original instruction
    original_kind = get_insn_kind(arguzz_fault.original_word)
    expected_major, expected_minor = kind_to_major_minor(original_kind)
    
    # Expected A4 PC (next PC after the instruction)
    # For sequential instructions, this is arguzz_pc + 4
    expected_a4_pc = arguzz_fault.pc + 4
    
    print(f"\n=== Finding A4 mutation target ===")
    print(f"Arguzz fault: step={arguzz_fault.step}, pc={arguzz_fault.pc}")
    print(f"Original word: {arguzz_fault.original_word} (0x{arguzz_fault.original_word:08x})")
    print(f"Original instruction: {INSN_KIND_NAMES.get(original_kind, 'Unknown')} (kind={original_kind})")
    print(f"Expected major/minor: {expected_major}/{expected_minor}")
    print(f"Expected A4 PC (next_pc): {expected_a4_pc}")
    
    # Search for matching cycles
    exact_matches = []  # (PC, major, minor) all match
    pc_only_matches = []  # Only PC matches
    
    # Search for cycles matching (PC, major, minor)
    for cycle in a4_cycles:
        if cycle.pc == expected_a4_pc:
            if cycle.major == expected_major and cycle.minor == expected_minor:
                exact_matches.append(cycle)
            else:
                pc_only_matches.append(cycle)
    
    print(f"\nFound {len(exact_matches)} exact matches, {len(pc_only_matches)} PC-only matches")
    
    if not exact_matches and not pc_only_matches:
        print(f"\nERROR: No matching cycle found!")
        print(f"Searched for: pc={expected_a4_pc}, major={expected_major}, minor={expected_minor}")
        return None
    
    # Handle exact matches (prefer these)
    if exact_matches:
        if len(exact_matches) == 1:
            # Single match - straightforward case
            result = exact_matches[0]
            print(f"\n=== FOUND UNIQUE EXACT MATCH ===")
        else:
            # Multiple matches (loop case) - disambiguate using step
            # The correct match has user_cycle <= arguzz_step with SMALLEST difference
            # This is because:
            # 1. user_cycle can never exceed arguzz_step (ecalls only cause positive offset)
            # 2. The correct iteration is the one closest to the arguzz_step
            print(f"\n=== MULTIPLE MATCHES (loop detected) ===")
            print(f"Using Arguzz step ({arguzz_fault.step}) to disambiguate...")
            
            # Filter: user_cycle must be <= arguzz_step
            valid_matches = [c for c in exact_matches if c.step <= arguzz_fault.step]
            
            if not valid_matches:
                print(f"ERROR: No match has user_cycle <= arguzz_step!")
                print(f"Candidates: {[(c.step, c.cycle_idx) for c in exact_matches]}")
                return None
            
            # Pick the one with the smallest offset (closest user_cycle to arguzz_step)
            result = max(valid_matches, key=lambda c: c.step)
            
            print(f"Selected from {len(exact_matches)} candidates:")
            for c in exact_matches:
                offset = arguzz_fault.step - c.step
                marker = " <-- SELECTED" if c == result else ""
                print(f"  cycle_idx={c.cycle_idx}, user_cycle={c.step}, offset={offset}{marker}")
        
        print(f"\n=== RESULT ===")
        print(f"A4 cycle_idx: {result.cycle_idx}")
        print(f"A4 user_cycle (step): {result.step}")
        print(f"A4 pc: {result.pc}")
        print(f"A4 txn_idx: {result.txn_idx}")
        print(f"A4 major/minor: {result.major}/{result.minor}")
        offset = arguzz_fault.step - result.step
        print(f"\nOffset: Arguzz step {arguzz_fault.step} -> A4 step {result.step} (diff={offset})")
        print(f"(This offset = number of machine-mode ecalls before this instruction)")
        return result
    
    # If no exact match, report PC-only matches (indicates potential issue)
    if pc_only_matches:
        # Same disambiguation logic
        valid_matches = [c for c in pc_only_matches if c.step <= arguzz_fault.step]
        if valid_matches:
            result = max(valid_matches, key=lambda c: c.step)
        else:
            result = pc_only_matches[0]
        
        print(f"\nWARNING: Found PC match but major/minor mismatch!")
        print(f"Expected major/minor: {expected_major}/{expected_minor}")
        print(f"Found major/minor: {result.major}/{result.minor}")
        print(f"This might indicate instruction prefetching or a non-sequential instruction.")
        return result
    
    return None


def run_a4_inspection(host_binary: str, args: List[str]) -> List[A4CycleInfo]:
    """Run the host binary with A4_INSPECT=1 and parse output"""
    import os
    env = os.environ.copy()
    env['A4_INSPECT'] = '1'
    
    cmd = [host_binary] + args
    print(f"Running: A4_INSPECT=1 {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    
    cycles = []
    for line in result.stdout.split('\n') + result.stderr.split('\n'):
        cycle = A4CycleInfo.parse(line)
        if cycle:
            cycles.append(cycle)
    
    print(f"Parsed {len(cycles)} A4 cycles")
    return cycles


# ============================================================================
# CONSTRAINT FAILURE PARSING
# ============================================================================

@dataclass
class ConstraintFailure:
    """Parsed constraint failure from either Arguzz or A4"""
    cycle: int
    step: int
    pc: int
    major: int
    minor: int
    loc: str
    value: int
    
    @classmethod
    def parse(cls, line: str) -> Optional['ConstraintFailure']:
        """Parse a <constraint_fail> line"""
        match = re.search(r'<constraint_fail>(\{.*?\})</constraint_fail>', line)
        if not match:
            return None
        
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
        
        return cls(
            cycle=data.get('cycle', 0),
            step=data.get('step', 0),
            pc=data.get('pc', 0),
            major=data.get('major', 0),
            minor=data.get('minor', 0),
            loc=data.get('loc', ''),
            value=data.get('value', 0),
        )
    
    def to_dict(self) -> dict:
        return {
            'cycle': self.cycle,
            'step': self.step,
            'pc': self.pc,
            'major': self.major,
            'minor': self.minor,
            'loc': self.loc,
            'value': self.value,
        }


# ============================================================================
# A4 CONFIG GENERATION
# ============================================================================

def generate_a4_config(
    mutation_type: str,
    a4_step: int,  # This is user_cycle, not Arguzz step!
    major: Optional[int] = None,
    minor: Optional[int] = None,
    word: Optional[int] = None,
) -> dict:
    """
    Generate A4 mutation config for mod.rs
    
    Args:
        mutation_type: "INSTR_TYPE_MOD" or "INSTR_WORD_MOD"
        a4_step: The A4 user_cycle (NOT Arguzz step!)
        major/minor: For INSTR_TYPE_MOD
        word: For INSTR_WORD_MOD
    """
    config = {
        "mutation_type": mutation_type,
        "step": a4_step,  # mod.rs uses "step" to mean user_cycle
    }
    
    if mutation_type == "INSTR_TYPE_MOD":
        if major is not None:
            config["major"] = major
        if minor is not None:
            config["minor"] = minor
    elif mutation_type == "INSTR_WORD_MOD":
        if word is not None:
            config["word"] = word
    
    return config


def write_a4_config(config: dict, path: str) -> None:
    """Write A4 config to file"""
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)


# ============================================================================
# MUTATION RUNNER
# ============================================================================

@dataclass
class MutationResult:
    """Result of running a mutation"""
    fault: Optional[ArguzzFault]
    constraint_failures: List[ConstraintFailure]
    raw_output: str
    
    def to_dict(self) -> dict:
        return {
            'fault': {
                'step': self.fault.step,
                'pc': self.fault.pc,
                'original_word': self.fault.original_word,
                'mutated_word': self.fault.mutated_word,
            } if self.fault else None,
            'constraint_failures': [cf.to_dict() for cf in self.constraint_failures],
            'num_failures': len(self.constraint_failures),
        }


def run_arguzz_mutation(
    host_binary: str,
    host_args: List[str],
    step: int,
    kind: str,
    seed: int,
) -> MutationResult:
    """
    Run Arguzz mutation and capture results
    
    Args:
        host_binary: Path to risc0-host
        host_args: Base arguments (e.g., ['--in1', '5', '--in4', '10'])
        step: Arguzz injection step
        kind: Injection kind (e.g., 'INSTR_WORD_MOD')
        seed: Random seed
    """
    import os
    env = os.environ.copy()
    env['CONSTRAINT_CONTINUE'] = '1'
    env['CONSTRAINT_TRACE_ENABLED'] = '1'
    
    cmd = [host_binary, '--trace', '--inject',
           '--seed', str(seed),
           '--inject-step', str(step),
           '--inject-kind', kind] + host_args
    
    print(f"Running Arguzz: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    raw_output = result.stdout + result.stderr
    
    # Parse fault
    fault = None
    for line in raw_output.split('\n'):
        if '<fault>' in line and kind in line:
            fault = ArguzzFault.parse(line)
            if fault:
                break
    
    # Parse constraint failures
    failures = []
    for line in raw_output.split('\n'):
        cf = ConstraintFailure.parse(line)
        if cf:
            failures.append(cf)
    
    print(f"Arguzz: Found fault={fault is not None}, {len(failures)} constraint failures")
    
    return MutationResult(fault=fault, constraint_failures=failures, raw_output=raw_output)


def run_a4_mutation(
    host_binary: str,
    host_args: List[str],
    config_path: str,
) -> MutationResult:
    """
    Run A4 mutation and capture results
    
    Args:
        host_binary: Path to risc0-host
        host_args: Base arguments (e.g., ['--in1', '5', '--in4', '10'])
        config_path: Path to A4 mutation config file
    """
    import os
    env = os.environ.copy()
    env['A4_MUTATION_CONFIG'] = config_path
    env['CONSTRAINT_CONTINUE'] = '1'
    env['CONSTRAINT_TRACE_ENABLED'] = '1'
    
    cmd = [host_binary] + host_args
    
    print(f"Running A4: A4_MUTATION_CONFIG={config_path} {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    raw_output = result.stdout + result.stderr
    
    # Parse constraint failures
    failures = []
    for line in raw_output.split('\n'):
        cf = ConstraintFailure.parse(line)
        if cf:
            failures.append(cf)
    
    print(f"A4: {len(failures)} constraint failures")
    
    return MutationResult(fault=None, constraint_failures=failures, raw_output=raw_output)


# ============================================================================
# COMPARISON AND ANALYSIS
# ============================================================================

@dataclass
class ComparisonResult:
    """Result of comparing Arguzz vs A4 mutations"""
    arguzz_result: MutationResult
    a4_result: MutationResult
    
    # Constraint failure analysis
    arguzz_only_failures: List[ConstraintFailure]  # Failures in Arguzz but not A4
    a4_only_failures: List[ConstraintFailure]      # Failures in A4 but not Arguzz
    common_failures: List[Tuple[ConstraintFailure, ConstraintFailure]]  # Matched failures
    
    def to_dict(self) -> dict:
        return {
            'arguzz': self.arguzz_result.to_dict(),
            'a4': self.a4_result.to_dict(),
            'analysis': {
                'arguzz_total_failures': len(self.arguzz_result.constraint_failures),
                'a4_total_failures': len(self.a4_result.constraint_failures),
                'arguzz_only_count': len(self.arguzz_only_failures),
                'a4_only_count': len(self.a4_only_failures),
                'common_count': len(self.common_failures),
                'arguzz_only': [cf.to_dict() for cf in self.arguzz_only_failures],
                'a4_only': [cf.to_dict() for cf in self.a4_only_failures],
            }
        }
    
    def print_summary(self):
        print("\n" + "="*70)
        print("MUTATION COMPARISON SUMMARY")
        print("="*70)
        
        print(f"\n--- Arguzz Mutation ---")
        if self.arguzz_result.fault:
            f = self.arguzz_result.fault
            print(f"  Step: {f.step}, PC: {f.pc}")
            print(f"  Word: {f.original_word} (0x{f.original_word:08x}) -> {f.mutated_word} (0x{f.mutated_word:08x})")
            orig_kind = get_insn_kind(f.original_word)
            mut_kind = get_insn_kind(f.mutated_word)
            print(f"  Instruction: {INSN_KIND_NAMES.get(orig_kind, '?')} -> {INSN_KIND_NAMES.get(mut_kind, '?')}")
        print(f"  Constraint failures: {len(self.arguzz_result.constraint_failures)}")
        
        print(f"\n--- A4 Mutation ---")
        print(f"  Constraint failures: {len(self.a4_result.constraint_failures)}")
        
        print(f"\n--- Comparison ---")
        print(f"  Arguzz-only failures: {len(self.arguzz_only_failures)}")
        print(f"  A4-only failures:     {len(self.a4_only_failures)}")
        print(f"  Common failures:      {len(self.common_failures)}")
        
        if self.arguzz_only_failures:
            print(f"\n  Arguzz-only failure locations:")
            for cf in self.arguzz_only_failures[:5]:  # Show first 5
                print(f"    step={cf.step}, pc={cf.pc}, loc={cf.loc[:50]}...")
        
        if self.a4_only_failures:
            print(f"\n  A4-only failure locations:")
            for cf in self.a4_only_failures[:5]:  # Show first 5
                print(f"    step={cf.step}, pc={cf.pc}, loc={cf.loc[:50]}...")
        
        if self.common_failures:
            print(f"\n  Common failure locations:")
            for arguzz_cf, a4_cf in self.common_failures[:5]:  # Show first 5
                print(f"    Arguzz: step={arguzz_cf.step}, A4: step={a4_cf.step}, loc={arguzz_cf.loc[:40]}...")


def compare_mutations(
    arguzz_result: MutationResult,
    a4_result: MutationResult,
    step_offset: int = 0,  # Arguzz step - A4 step offset
) -> ComparisonResult:
    """
    Compare constraint failures between Arguzz and A4 mutations
    
    Matching strategy:
    - Two failures "match" if they have the same location (loc field)
    - We account for step offset when comparing step numbers
    """
    arguzz_by_loc = {cf.loc: cf for cf in arguzz_result.constraint_failures}
    a4_by_loc = {cf.loc: cf for cf in a4_result.constraint_failures}
    
    arguzz_locs = set(arguzz_by_loc.keys())
    a4_locs = set(a4_by_loc.keys())
    
    common_locs = arguzz_locs & a4_locs
    arguzz_only_locs = arguzz_locs - a4_locs
    a4_only_locs = a4_locs - arguzz_locs
    
    return ComparisonResult(
        arguzz_result=arguzz_result,
        a4_result=a4_result,
        arguzz_only_failures=[arguzz_by_loc[loc] for loc in arguzz_only_locs],
        a4_only_failures=[a4_by_loc[loc] for loc in a4_only_locs],
        common_failures=[(arguzz_by_loc[loc], a4_by_loc[loc]) for loc in common_locs],
    )


# ============================================================================
# MAIN ENTRY POINTS
# ============================================================================

def cmd_find_target(args):
    """Find A4 mutation target for a given Arguzz fault"""
    # Parse Arguzz fault
    fault_line = None
    if args.from_stdin:
        for line in sys.stdin:
            if '<fault>' in line and 'INSTR_WORD_MOD' in line:
                fault_line = line
                break
    elif args.arguzz_fault:
        fault_line = args.arguzz_fault
    
    if not fault_line:
        print("ERROR: No Arguzz fault line provided or found")
        return None
    
    arguzz_fault = ArguzzFault.parse(fault_line)
    if not arguzz_fault:
        print(f"ERROR: Failed to parse fault line: {fault_line}")
        return None
    
    print(f"Parsed Arguzz fault: {arguzz_fault}")
    
    # Get A4 cycles
    a4_cycles = []
    if args.a4_cycles_file:
        with open(args.a4_cycles_file) as f:
            for line in f:
                cycle = A4CycleInfo.parse(line)
                if cycle:
                    a4_cycles.append(cycle)
        print(f"Loaded {len(a4_cycles)} A4 cycles from {args.a4_cycles_file}")
    else:
        # Run A4 inspection
        host_args = args.host_args.split()
        a4_cycles = run_a4_inspection(args.host_binary, host_args)
    
    if not a4_cycles:
        print("ERROR: No A4 cycles found")
        return None
    
    # Find the matching cycle
    result = find_mutation_target(arguzz_fault, a4_cycles)
    
    if result:
        # Calculate mutated major/minor
        mutated_kind = get_insn_kind(arguzz_fault.mutated_word)
        mutated_major, mutated_minor = kind_to_major_minor(mutated_kind)
        
        output = {
            'success': True,
            'arguzz_step': arguzz_fault.step,
            'arguzz_pc': arguzz_fault.pc,
            'original_word': arguzz_fault.original_word,
            'mutated_word': arguzz_fault.mutated_word,
            'original_insn': INSN_KIND_NAMES.get(get_insn_kind(arguzz_fault.original_word), 'Unknown'),
            'mutated_insn': INSN_KIND_NAMES.get(mutated_kind, 'Unknown'),
            'a4_cycle_idx': result.cycle_idx,
            'a4_user_cycle': result.step,
            'a4_pc': result.pc,
            'a4_txn_idx': result.txn_idx,
            'a4_original_major': result.major,
            'a4_original_minor': result.minor,
            'a4_mutated_major': mutated_major,
            'a4_mutated_minor': mutated_minor,
            'step_offset': arguzz_fault.step - result.step,
        }
        
        if args.output_json:
            with open(args.output_json, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"\nResult written to {args.output_json}")
        
        # Print mutation config for A4
        print(f"\n=== A4 Mutation Config ===")
        print(f"To mutate cycles[{result.cycle_idx}] (user_cycle={result.step}):")
        print(f"  Original: major={result.major}, minor={result.minor} ({INSN_KIND_NAMES.get(result.major*8+result.minor, '?')})")
        print(f"  Mutated:  major={mutated_major}, minor={mutated_minor} ({INSN_KIND_NAMES.get(mutated_kind, '?')})")
        
        return output
    else:
        print("\nFailed to find matching A4 cycle")
        return None


def cmd_compare(args):
    """Run both Arguzz and A4 mutations and compare results"""
    import tempfile
    import os
    
    host_args = args.host_args.split()
    
    # Step 1: Run Arguzz mutation
    print("\n" + "="*70)
    print("STEP 1: Running Arguzz mutation")
    print("="*70)
    
    arguzz_result = run_arguzz_mutation(
        args.host_binary,
        host_args,
        args.step,
        args.kind,
        args.seed,
    )
    
    if not arguzz_result.fault:
        print("ERROR: Arguzz mutation did not produce a fault")
        return None
    
    # Step 2: Find A4 target
    print("\n" + "="*70)
    print("STEP 2: Finding A4 mutation target")
    print("="*70)
    
    # Build a fake args object for find_target
    class FakeArgs:
        pass
    find_args = FakeArgs()
    find_args.arguzz_fault = f'<fault>{json.dumps({"step": arguzz_result.fault.step, "pc": arguzz_result.fault.pc, "kind": args.kind, "info": f"word:{arguzz_result.fault.original_word} => word:{arguzz_result.fault.mutated_word}"})}</fault>'
    find_args.from_stdin = False
    find_args.a4_cycles_file = None
    find_args.host_binary = args.host_binary
    find_args.host_args = args.host_args
    find_args.output_json = None
    
    target = cmd_find_target(find_args)
    
    if not target:
        print("ERROR: Could not find A4 mutation target")
        return None
    
    # Step 3: Generate and run A4 mutation
    print("\n" + "="*70)
    print("STEP 3: Running A4 mutation")
    print("="*70)
    
    # Generate config
    config = generate_a4_config(
        "INSTR_TYPE_MOD",
        target['a4_user_cycle'],
        target['a4_mutated_major'],
        target['a4_mutated_minor'],
    )
    
    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name
    
    print(f"Generated A4 config: {config}")
    
    try:
        a4_result = run_a4_mutation(args.host_binary, host_args, config_path)
    finally:
        os.unlink(config_path)  # Clean up temp file
    
    # Step 4: Compare results
    print("\n" + "="*70)
    print("STEP 4: Comparing results")
    print("="*70)
    
    comparison = compare_mutations(arguzz_result, a4_result, target['step_offset'])
    comparison.print_summary()
    
    # Save results if requested
    if args.output_json:
        with open(args.output_json, 'w') as f:
            json.dump(comparison.to_dict(), f, indent=2)
        print(f"\nFull results written to {args.output_json}")
    
    return comparison


def main():
    parser = argparse.ArgumentParser(
        description='A4 Mutation Tool - Find targets and compare with Arguzz mutations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find A4 target for a specific Arguzz fault:
  python %(prog)s find-target --arguzz-fault '<fault>{"step":200, ...}</fault>'
  
  # Run full comparison (Arguzz + A4):
  python %(prog)s compare --step 200 --kind INSTR_WORD_MOD --seed 12345
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Common arguments for all subcommands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('--host-binary', type=str, default='./target/release/risc0-host',
                               help='Path to risc0-host binary')
    common_parser.add_argument('--host-args', type=str, default='--in1 5 --in4 10',
                               help='Arguments for risc0-host (space-separated)')
    common_parser.add_argument('--output-json', type=str, help='Output results as JSON to this file')
    
    # find-target subcommand
    find_parser = subparsers.add_parser('find-target', parents=[common_parser], 
                                        help='Find A4 mutation target')
    find_parser.add_argument('--arguzz-fault', type=str, help='Arguzz fault line')
    find_parser.add_argument('--from-stdin', action='store_true', help='Read from stdin')
    find_parser.add_argument('--a4-cycles-file', type=str, help='File with A4 cycle info')
    
    # compare subcommand
    compare_parser = subparsers.add_parser('compare', parents=[common_parser],
                                           help='Run and compare Arguzz vs A4')
    compare_parser.add_argument('--step', type=int, required=True, help='Arguzz injection step')
    compare_parser.add_argument('--kind', type=str, default='INSTR_WORD_MOD', help='Injection kind')
    compare_parser.add_argument('--seed', type=int, required=True, help='Random seed')
    
    args = parser.parse_args()
    
    if args.command == 'find-target':
        result = cmd_find_target(args)
        sys.exit(0 if result else 1)
    elif args.command == 'compare':
        result = cmd_compare(args)
        sys.exit(0 if result else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
