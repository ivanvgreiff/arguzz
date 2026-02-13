"""
INSTR_WORD_MOD_SUR: Surgical Instruction Word Mutation

This module provides surgical mutations of RISC-V instruction fields,
allowing targeted mutation of specific instruction components:
- opcode (7 bits)
- rd (5 bits) - destination register
- funct3 (3 bits) - function code
- rs1 (5 bits) - source register 1
- rs2 (5 bits) - source register 2 (R/S/B-type only)
- funct7 (7 bits) - extended function code (R-type only)
- imm - immediate value (format-dependent encoding)

================================================================================
RISC-V INSTRUCTION FORMATS
================================================================================

R-type (register-register operations): ADD, SUB, XOR, OR, AND, SLL, SRL, SRA, SLT, SLTU
  31    25 24  20 19  15 14  12 11   7 6    0
  [funct7 ][ rs2 ][ rs1 ][func3][ rd  ][opcode]

I-type (immediate operations): ADDI, XORI, ORI, ANDI, SLTI, SLTIU, LW, LH, LB, JALR
  31          20 19  15 14  12 11   7 6    0
  [  imm[11:0] ][ rs1 ][func3][ rd  ][opcode]

S-type (store operations): SW, SH, SB
  31    25 24  20 19  15 14  12 11   7 6    0
  [imm7   ][ rs2 ][ rs1 ][func3][imm5 ][opcode]
  imm = {imm7, imm5} = {[31:25], [11:7]}

B-type (branch operations): BEQ, BNE, BLT, BGE, BLTU, BGEU
  31    25 24  20 19  15 14  12 11   7 6    0
  [imm7   ][ rs2 ][ rs1 ][func3][imm5 ][opcode]
  imm = {imm[12], imm[10:5], imm[4:1], imm[11]}
       = {[31], [30:25], [11:8], [7]}

U-type (upper immediate): LUI, AUIPC
  31                  12 11   7 6    0
  [     imm[31:12]      ][ rd  ][opcode]

J-type (jump): JAL
  31                  12 11   7 6    0
  [     imm[20|10:1|11|19:12]  ][ rd  ][opcode]
  imm = {imm[20], imm[10:1], imm[11], imm[19:12]}
       = {[31], [30:21], [20], [19:12]}

================================================================================
"""

import json
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from a4.core.inspection_data import InspectionData

from a4.core.trace_parser import A4CycleInfo


class InstrFormat(Enum):
    """RISC-V instruction format types"""
    R = "R"      # Register-register
    I = "I"      # Immediate
    S = "S"      # Store
    B = "B"      # Branch
    U = "U"      # Upper immediate
    J = "J"      # Jump
    UNKNOWN = "UNKNOWN"


class SurgicalField(Enum):
    """Fields that can be surgically mutated"""
    OPCODE = "opcode"
    RD = "rd"
    FUNCT3 = "funct3"
    RS1 = "rs1"
    RS2 = "rs2"
    FUNCT7 = "funct7"
    IMM = "imm"


# RISC-V opcode definitions
OPCODES = {
    # R-type
    0b0110011: ("R", "OP"),           # ADD, SUB, XOR, OR, AND, SLL, SRL, SRA, SLT, SLTU, MUL, etc.
    
    # I-type
    0b0010011: ("I", "OP-IMM"),       # ADDI, XORI, ORI, ANDI, SLLI, SRLI, SRAI, SLTI, SLTIU
    0b0000011: ("I", "LOAD"),         # LW, LH, LB, LHU, LBU
    0b1100111: ("I", "JALR"),         # JALR
    0b1110011: ("I", "SYSTEM"),       # ECALL, EBREAK, CSR*
    
    # S-type
    0b0100011: ("S", "STORE"),        # SW, SH, SB
    
    # B-type
    0b1100011: ("B", "BRANCH"),       # BEQ, BNE, BLT, BGE, BLTU, BGEU
    
    # U-type
    0b0110111: ("U", "LUI"),          # LUI
    0b0010111: ("U", "AUIPC"),        # AUIPC
    
    # J-type
    0b1101111: ("J", "JAL"),          # JAL
}


@dataclass
class RiscVInstruction:
    """
    Decoded RISC-V instruction with surgical mutation support.
    
    Properly handles all instruction formats and their different field layouts.
    """
    word: int
    
    # Common fields (present in all formats)
    opcode: int = 0
    rd: int = 0
    funct3: int = 0
    rs1: int = 0
    
    # R/S/B-type fields
    rs2: int = 0
    funct7: int = 0
    
    # Decoded format
    format: InstrFormat = InstrFormat.UNKNOWN
    format_name: str = "UNKNOWN"
    
    # Cached immediate (computed on demand)
    _imm: Optional[int] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Decode the instruction word into fields"""
        self._decode()
    
    def _decode(self):
        """Decode instruction word into constituent fields"""
        w = self.word
        
        # Extract common fields
        self.opcode = w & 0x7F
        self.rd = (w >> 7) & 0x1F
        self.funct3 = (w >> 12) & 0x7
        self.rs1 = (w >> 15) & 0x1F
        self.rs2 = (w >> 20) & 0x1F
        self.funct7 = (w >> 25) & 0x7F
        
        # Determine format from opcode
        if self.opcode in OPCODES:
            fmt_str, self.format_name = OPCODES[self.opcode]
            self.format = InstrFormat(fmt_str)
        else:
            self.format = InstrFormat.UNKNOWN
            self.format_name = "UNKNOWN"
    
    @property
    def imm(self) -> int:
        """Get immediate value, decoded based on instruction format"""
        if self._imm is not None:
            return self._imm
        
        self._imm = self._decode_immediate()
        return self._imm
    
    @staticmethod
    def _to_signed32(val: int) -> int:
        """Convert 32-bit unsigned representation to Python signed int."""
        if val >= 0x80000000:
            return val - 0x100000000
        return val
    
    def _decode_immediate(self) -> int:
        """
        Decode immediate value based on instruction format.
        
        Returns sign-extended immediate as a proper Python signed integer.
        """
        w = self.word
        
        if self.format == InstrFormat.I:
            # I-type: imm[11:0] = inst[31:20], sign-extended from 12 bits
            imm = (w >> 20) & 0xFFF
            if imm & 0x800:
                imm |= 0xFFFFF000
            return self._to_signed32(imm)
        
        elif self.format == InstrFormat.S:
            # S-type: imm = {inst[31:25], inst[11:7]}, sign-extended from 12 bits
            imm_11_5 = (w >> 25) & 0x7F
            imm_4_0 = (w >> 7) & 0x1F
            imm = (imm_11_5 << 5) | imm_4_0
            if imm & 0x800:
                imm |= 0xFFFFF000
            return self._to_signed32(imm)
        
        elif self.format == InstrFormat.B:
            # B-type: imm = {inst[31], inst[7], inst[30:25], inst[11:8], 0}
            # Note: LSB is always 0 (encoded in 2-byte granularity)
            imm_12 = (w >> 31) & 0x1
            imm_11 = (w >> 7) & 0x1
            imm_10_5 = (w >> 25) & 0x3F
            imm_4_1 = (w >> 8) & 0xF
            imm = (imm_12 << 12) | (imm_11 << 11) | (imm_10_5 << 5) | (imm_4_1 << 1)
            # Sign extend from 13 bits
            if imm & 0x1000:
                imm |= 0xFFFFE000
            return self._to_signed32(imm)
        
        elif self.format == InstrFormat.U:
            # U-type: imm = {inst[31:12], 12'b0}
            # Returns the upper 20 bits in position (NOT sign-extended, as this
            # represents the literal upper bits loaded, not a signed offset)
            return w & 0xFFFFF000
        
        elif self.format == InstrFormat.J:
            # J-type: imm = {inst[31], inst[19:12], inst[20], inst[30:21], 0}
            imm_20 = (w >> 31) & 0x1
            imm_19_12 = (w >> 12) & 0xFF
            imm_11 = (w >> 20) & 0x1
            imm_10_1 = (w >> 21) & 0x3FF
            imm = (imm_20 << 20) | (imm_19_12 << 12) | (imm_11 << 11) | (imm_10_1 << 1)
            # Sign extend from 21 bits
            if imm & 0x100000:
                imm |= 0xFFE00000
            return self._to_signed32(imm)
        
        # R-type and UNKNOWN have no immediate
        return 0
    
    def get_mutable_fields(self) -> List[SurgicalField]:
        """
        Get list of fields that can be surgically mutated for this instruction format.
        
        Returns fields in order of "most interesting" mutations first.
        """
        # All formats have these
        base = [SurgicalField.OPCODE, SurgicalField.RD, SurgicalField.FUNCT3, SurgicalField.RS1]
        
        if self.format == InstrFormat.R:
            return base + [SurgicalField.RS2, SurgicalField.FUNCT7]
        
        elif self.format == InstrFormat.I:
            return base + [SurgicalField.IMM]
        
        elif self.format == InstrFormat.S:
            # S-type has rs2, but rd is repurposed for immediate
            return [SurgicalField.OPCODE, SurgicalField.FUNCT3, SurgicalField.RS1, 
                    SurgicalField.RS2, SurgicalField.IMM]
        
        elif self.format == InstrFormat.B:
            # B-type has rs2, but rd is repurposed for immediate
            return [SurgicalField.OPCODE, SurgicalField.FUNCT3, SurgicalField.RS1,
                    SurgicalField.RS2, SurgicalField.IMM]
        
        elif self.format == InstrFormat.U:
            return [SurgicalField.OPCODE, SurgicalField.RD, SurgicalField.IMM]
        
        elif self.format == InstrFormat.J:
            return [SurgicalField.OPCODE, SurgicalField.RD, SurgicalField.IMM]
        
        return base
    
    def get_field_value(self, field: SurgicalField) -> int:
        """Get current value of a field"""
        if field == SurgicalField.OPCODE:
            return self.opcode
        elif field == SurgicalField.RD:
            return self.rd
        elif field == SurgicalField.FUNCT3:
            return self.funct3
        elif field == SurgicalField.RS1:
            return self.rs1
        elif field == SurgicalField.RS2:
            return self.rs2
        elif field == SurgicalField.FUNCT7:
            return self.funct7
        elif field == SurgicalField.IMM:
            return self.imm
        return 0
    
    def encode_with_mutation(self, field: SurgicalField, new_value: int) -> int:
        """
        Re-encode instruction with one field mutated to a new value.
        
        Args:
            field: Which field to mutate
            new_value: New value for the field
            
        Returns:
            New instruction word with the mutation applied
        """
        w = self.word
        
        if field == SurgicalField.OPCODE:
            return (w & ~0x7F) | (new_value & 0x7F)
        
        elif field == SurgicalField.RD:
            # RD is at bits [11:7] - BUT only for R/I/U/J types
            # For S/B types, these bits are part of immediate
            if self.format in (InstrFormat.R, InstrFormat.I, InstrFormat.U, InstrFormat.J):
                return (w & ~0xF80) | ((new_value & 0x1F) << 7)
            else:
                # For S/B types, this would corrupt the immediate
                # We should not allow rd mutation for S/B types
                return w
        
        elif field == SurgicalField.FUNCT3:
            return (w & ~0x7000) | ((new_value & 0x7) << 12)
        
        elif field == SurgicalField.RS1:
            return (w & ~0xF8000) | ((new_value & 0x1F) << 15)
        
        elif field == SurgicalField.RS2:
            # RS2 is at bits [24:20] - only valid for R/S/B types
            if self.format in (InstrFormat.R, InstrFormat.S, InstrFormat.B):
                return (w & ~0x1F00000) | ((new_value & 0x1F) << 20)
            else:
                # For I/U/J types, these bits are part of immediate or funct7
                return w
        
        elif field == SurgicalField.FUNCT7:
            # FUNCT7 is at bits [31:25] - only valid for R-type
            if self.format == InstrFormat.R:
                return (w & ~0xFE000000) | ((new_value & 0x7F) << 25)
            else:
                # For other types, these bits are part of immediate
                return w
        
        elif field == SurgicalField.IMM:
            return self._encode_immediate(new_value)
        
        return w
    
    def _encode_immediate(self, imm: int) -> int:
        """
        Encode a new immediate value into the instruction word.
        
        Args:
            imm: New immediate value (will be masked/truncated as needed)
            
        Returns:
            New instruction word with immediate encoded
        """
        w = self.word
        
        if self.format == InstrFormat.I:
            # I-type: imm[11:0] goes to inst[31:20]
            imm_12 = imm & 0xFFF
            return (w & 0x000FFFFF) | (imm_12 << 20)
        
        elif self.format == InstrFormat.S:
            # S-type: imm[11:5] to inst[31:25], imm[4:0] to inst[11:7]
            imm_11_5 = (imm >> 5) & 0x7F
            imm_4_0 = imm & 0x1F
            w = w & ~0xFE000F80  # Clear imm bits
            w = w | (imm_11_5 << 25) | (imm_4_0 << 7)
            return w
        
        elif self.format == InstrFormat.B:
            # B-type encoding is complex:
            # inst[31] = imm[12]
            # inst[30:25] = imm[10:5]
            # inst[11:8] = imm[4:1]
            # inst[7] = imm[11]
            imm_12 = (imm >> 12) & 0x1
            imm_11 = (imm >> 11) & 0x1
            imm_10_5 = (imm >> 5) & 0x3F
            imm_4_1 = (imm >> 1) & 0xF
            
            w = w & ~0xFE000F80  # Clear imm bits (same positions as S-type rd and funct7)
            w = w | (imm_12 << 31) | (imm_10_5 << 25) | (imm_4_1 << 8) | (imm_11 << 7)
            return w
        
        elif self.format == InstrFormat.U:
            # U-type: imm[31:12] goes to inst[31:12]
            return (w & 0x00000FFF) | (imm & 0xFFFFF000)
        
        elif self.format == InstrFormat.J:
            # J-type encoding is complex:
            # inst[31] = imm[20]
            # inst[30:21] = imm[10:1]
            # inst[20] = imm[11]
            # inst[19:12] = imm[19:12]
            imm_20 = (imm >> 20) & 0x1
            imm_19_12 = (imm >> 12) & 0xFF
            imm_11 = (imm >> 11) & 0x1
            imm_10_1 = (imm >> 1) & 0x3FF
            
            w = w & 0x00000FFF  # Keep only opcode and rd
            w = w | (imm_20 << 31) | (imm_10_1 << 21) | (imm_11 << 20) | (imm_19_12 << 12)
            return w
        
        # R-type and UNKNOWN don't have immediates
        return w
    
    def _get_instruction_name(self) -> str:
        """Get the exact RISC-V instruction mnemonic based on opcode, funct3, and funct7"""
        # LOAD instructions (I-type, opcode=0b0000011)
        if self.opcode == 0b0000011:
            load_names = {0: "LB", 1: "LH", 2: "LW", 4: "LBU", 5: "LHU"}
            return load_names.get(self.funct3, f"LOAD.{self.funct3}")
        
        # STORE instructions (S-type, opcode=0b0100011)
        if self.opcode == 0b0100011:
            store_names = {0: "SB", 1: "SH", 2: "SW"}
            return store_names.get(self.funct3, f"STORE.{self.funct3}")
        
        # OP-IMM instructions (I-type, opcode=0b0010011)
        if self.opcode == 0b0010011:
            if self.funct3 == 5:  # SRLI/SRAI
                return "SRAI" if (self.funct7 & 0x20) else "SRLI"
            op_imm_names = {0: "ADDI", 1: "SLLI", 2: "SLTI", 3: "SLTIU", 
                           4: "XORI", 6: "ORI", 7: "ANDI"}
            return op_imm_names.get(self.funct3, f"OP-IMM.{self.funct3}")
        
        # OP instructions (R-type, opcode=0b0110011)
        if self.opcode == 0b0110011:
            if self.funct3 == 0:  # ADD/SUB
                return "SUB" if self.funct7 == 0x20 else "ADD"
            if self.funct3 == 5:  # SRL/SRA
                return "SRA" if self.funct7 == 0x20 else "SRL"
            op_names = {1: "SLL", 2: "SLT", 3: "SLTU", 4: "XOR", 6: "OR", 7: "AND"}
            return op_names.get(self.funct3, f"OP.{self.funct3}")
        
        # BRANCH instructions (B-type, opcode=0b1100011)
        if self.opcode == 0b1100011:
            branch_names = {0: "BEQ", 1: "BNE", 4: "BLT", 5: "BGE", 6: "BLTU", 7: "BGEU"}
            return branch_names.get(self.funct3, f"BRANCH.{self.funct3}")
        
        # JALR (I-type, opcode=0b1100111)
        if self.opcode == 0b1100111:
            return "JALR"
        
        # JAL (J-type, opcode=0b1101111)
        if self.opcode == 0b1101111:
            return "JAL"
        
        # LUI (U-type, opcode=0b0110111)
        if self.opcode == 0b0110111:
            return "LUI"
        
        # AUIPC (U-type, opcode=0b0010111)
        if self.opcode == 0b0010111:
            return "AUIPC"
        
        # SYSTEM instructions (I-type, opcode=0b1110011)
        if self.opcode == 0b1110011:
            if self.funct3 == 0:
                if self.imm == 0:
                    return "ECALL"
                elif self.imm == 1:
                    return "EBREAK"
            return f"SYSTEM.{self.funct3}"
        
        # MISC-MEM (FENCE, opcode=0b0001111)
        if self.opcode == 0b0001111:
            return "FENCE"
        
        return f"OP{self.opcode:#04x}.F{self.funct3}"
    
    def disassemble(self) -> str:
        """Get a human-readable disassembly of the instruction with proper RISC-V mnemonics"""
        name = self._get_instruction_name()
        
        if self.format == InstrFormat.R:
            return f"{name} x{self.rd}, x{self.rs1}, x{self.rs2}"
        elif self.format == InstrFormat.I:
            if self.opcode == 0b0000011:  # LOAD
                return f"{name} x{self.rd}, {self.imm}(x{self.rs1})"
            elif self.opcode == 0b1100111:  # JALR
                return f"{name} x{self.rd}, x{self.rs1}, {self.imm}"
            else:
                return f"{name} x{self.rd}, x{self.rs1}, {self.imm}"
        elif self.format == InstrFormat.S:
            return f"{name} x{self.rs2}, {self.imm}(x{self.rs1})"
        elif self.format == InstrFormat.B:
            return f"{name} x{self.rs1}, x{self.rs2}, {self.imm}"
        elif self.format == InstrFormat.U:
            return f"{name} x{self.rd}, {self.imm:#x}"
        elif self.format == InstrFormat.J:
            return f"{name} x{self.rd}, {self.imm}"
        return f"UNKNOWN 0x{self.word:08x}"
    
    @classmethod
    def from_word(cls, word: int) -> 'RiscVInstruction':
        """Create instruction from a 32-bit word"""
        return cls(word=word)


# =============================================================================
# Surgical Mutation Target
# =============================================================================

@dataclass
class InstrWordModSurTarget:
    """
    Target for an INSTR_WORD_MOD_SUR (surgical) mutation.
    
    Extends the basic target with decoded instruction information.
    """
    step: int
    cycle_idx: int
    pc: int
    txn_idx: int
    fetch_addr: int
    original_word: int
    major: int
    minor: int
    
    # Decoded instruction
    instruction: RiscVInstruction = field(default=None)
    
    def __post_init__(self):
        if self.instruction is None:
            self.instruction = RiscVInstruction.from_word(self.original_word)


# =============================================================================
# Helper Functions
# =============================================================================

def _is_instruction_or_ecall(major: int) -> bool:
    """Check if a cycle major indicates an instruction or ECALL."""
    return major <= 6 or major == 8


def _find_instruction_cycle(step: int, data: 'InspectionData') -> Optional[A4CycleInfo]:
    """Find the instruction or ECALL cycle for a given step."""
    for cycle in data.cycles:
        if cycle.step == step and _is_instruction_or_ecall(cycle.major):
            return cycle
    return None


# =============================================================================
# Main API
# =============================================================================

def get_targets_at_step(step: int, data: 'InspectionData') -> Optional[InstrWordModSurTarget]:
    """
    Get the INSTR_WORD_MOD_SUR mutation target at a specific step.
    
    Args:
        step: The step number to find target for
        data: InspectionData containing pre-collected cycles and transactions
        
    Returns:
        InstrWordModSurTarget if valid instruction fetch found, None otherwise
    """
    # Exclude step 0 (bootloader)
    if step == 0:
        return None
    
    cycle = _find_instruction_cycle(step, data)
    if not cycle:
        return None
    
    txn_idx = cycle.txn_idx
    if txn_idx >= len(data.all_txns):
        return None
    
    txn = data.all_txns[txn_idx]
    
    if not txn.is_read():
        return None
    
    return InstrWordModSurTarget(
        step=step,
        cycle_idx=cycle.cycle_idx,
        pc=cycle.pc,
        txn_idx=txn.txn_idx,
        fetch_addr=txn.addr,
        original_word=txn.word,
        major=cycle.major,
        minor=cycle.minor,
    )


def get_valid_steps(data: 'InspectionData') -> List[int]:
    """Get all steps that have valid INSTR_WORD_MOD_SUR targets."""
    valid_steps = set()
    
    for cycle in data.cycles:
        if cycle.step == 0:
            continue
        
        if _is_instruction_or_ecall(cycle.major):
            if get_targets_at_step(cycle.step, data):
                valid_steps.add(cycle.step)
    
    return sorted(valid_steps)


def select_surgical_field(
    instruction: RiscVInstruction,
    rng: random.Random,
    exclude_fields: Optional[Set[SurgicalField]] = None
) -> Optional[SurgicalField]:
    """
    Select a field to surgically mutate.
    
    Args:
        instruction: Decoded instruction
        rng: Random number generator
        exclude_fields: Optional set of fields to exclude from selection
        
    Returns:
        Selected field, or None if no valid fields
    """
    valid_fields = instruction.get_mutable_fields()
    
    if exclude_fields:
        valid_fields = [f for f in valid_fields if f not in exclude_fields]
    
    if not valid_fields:
        return None
    
    return rng.choice(valid_fields)


def generate_field_value(
    field: SurgicalField,
    original_value: int,
    instruction: RiscVInstruction,
    rng: random.Random,
) -> int:
    """
    Generate a new value for a surgical field mutation.
    
    Args:
        field: Which field to generate value for
        original_value: Current value of the field
        instruction: The decoded instruction
        rng: Random number generator
        
    Returns:
        New value different from original
    """
    max_attempts = 20
    
    for _ in range(max_attempts):
        if field == SurgicalField.OPCODE:
            # Pick from known valid opcodes or random
            if rng.random() < 0.7:
                new_val = rng.choice(list(OPCODES.keys()))
            else:
                new_val = rng.randint(0, 127)
        
        elif field in (SurgicalField.RD, SurgicalField.RS1, SurgicalField.RS2):
            # Register: 0-31
            new_val = rng.randint(0, 31)
        
        elif field == SurgicalField.FUNCT3:
            # 3-bit field
            new_val = rng.randint(0, 7)
        
        elif field == SurgicalField.FUNCT7:
            # Pick common funct7 values or random
            common_funct7 = [0b0000000, 0b0100000, 0b0000001]  # Normal, SUB/SRA, MUL/DIV
            if rng.random() < 0.6:
                new_val = rng.choice(common_funct7)
            else:
                new_val = rng.randint(0, 127)
        
        elif field == SurgicalField.IMM:
            # Immediate: depends on format
            if instruction.format == InstrFormat.I:
                # 12-bit signed: -2048 to 2047
                new_val = rng.randint(-2048, 2047) & 0xFFF
            elif instruction.format == InstrFormat.S:
                # 12-bit signed
                new_val = rng.randint(-2048, 2047) & 0xFFF
            elif instruction.format == InstrFormat.B:
                # 13-bit signed, must be even
                new_val = (rng.randint(-4096, 4094) & ~1) & 0x1FFF
            elif instruction.format == InstrFormat.U:
                # 20-bit upper, already shifted
                new_val = (rng.randint(0, 0xFFFFF) << 12)
            elif instruction.format == InstrFormat.J:
                # 21-bit signed, must be even
                new_val = (rng.randint(-1048576, 1048574) & ~1) & 0x1FFFFF
            else:
                new_val = 0
        else:
            new_val = 0
        
        if new_val != original_value:
            return new_val
    
    # Fallback: just flip a bit
    return original_value ^ 1


def create_config(
    target: InstrWordModSurTarget,
    surgical_field: SurgicalField,
    mutated_value: int,
    new_field_value: int,
    output_path: Path,
) -> Path:
    """
    Create an A4 mutation config file for INSTR_WORD_MOD_SUR.
    
    Args:
        target: The mutation target
        surgical_field: Which field was mutated
        mutated_value: The complete mutated instruction word
        new_field_value: The new value of the mutated field
        output_path: Where to save the config JSON
        
    Returns:
        Path to the created config file
    """
    original_field_value = target.instruction.get_field_value(surgical_field)
    
    config = {
        "mutation_type": "INSTR_WORD_MOD",  # Rust handler is the same
        "step": target.step,
        "word": mutated_value,
        "_surgical": {
            "field": surgical_field.value,
            "original_field_value": original_field_value,
            "mutated_field_value": new_field_value,
            "instruction_format": target.instruction.format.value,
            "format_name": target.instruction.format_name,
        },
        "_info": {
            "description": f"INSTR_WORD_MOD_SUR: Mutate {surgical_field.value} field",
            "fetch_word_addr": target.fetch_addr,
            "fetch_byte_addr": f"0x{target.fetch_addr * 4:08x}",
            "original_word": f"0x{target.original_word:08x}",
            "mutated_word": f"0x{mutated_value:08x}",
            "disasm_original": target.instruction.disassemble(),
            "next_pc": f"0x{target.pc:08x}",
            "major": target.major,
            "minor": target.minor,
        }
    }
    
    output_path.write_text(json.dumps(config, indent=2))
    return output_path
