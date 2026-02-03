"""
RISC-V Instruction Decoding

Provides InsnKind enumeration and instruction word decoding,
mirroring the logic in risc0/circuit/rv32im/src/execute/rv32im.rs
"""

from dataclasses import dataclass
from typing import Optional, Tuple


# InsnKind enum values (from rv32im.rs)
# These match the Rust enum exactly: major = kind // 8, minor = kind % 8
INSN_KIND_NAMES = {
    0: "Add", 1: "Sub", 2: "Xor", 3: "Or", 4: "And", 5: "Slt", 6: "SltU", 7: "AddI",
    8: "XorI", 9: "OrI", 10: "AndI", 11: "SltI", 12: "SltIU", 13: "Beq", 14: "Bne", 15: "Blt",
    16: "Bge", 17: "BltU", 18: "BgeU", 19: "Jal", 20: "JalR", 21: "Lui", 22: "Auipc", 23: "Mul",
    24: "MulH", 25: "MulHSU", 26: "MulHU", 27: "Sll", 28: "Srl", 29: "Sra", 30: "SllI", 31: "SrlI",
    32: "SraI", 33: "Div", 34: "DivU", 35: "Rem", 36: "RemU", 37: "Lb", 38: "Lh", 39: "Lbu",
    40: "Lhu", 41: "Lw_", 42: "Lw", 43: "Sb", 44: "Sh", 45: "Sw_", 46: "Sw", 47: "?47",
    48: "?48", 49: "?49", 50: "Sw2", 51: "Fence", 52: "Eany", 53: "Mret", 54: "?54", 55: "?55",
    56: "?56", 57: "Invalid",
}


@dataclass
class DecodedInsn:
    """Decoded instruction information"""
    kind: int           # InsnKind enum value
    major: int          # kind // 8
    minor: int          # kind % 8
    name: str           # Human-readable name
    opcode: int         # 7-bit opcode
    func3: int          # 3-bit function code
    func7: Optional[int] = None  # 7-bit function code (R-type only)


def decode_insn_word(word: int) -> Optional[DecodedInsn]:
    """
    Decode a RISC-V instruction word to get its InsnKind.
    
    This mirrors the decoding logic in rv32im.rs exec_rv32im().
    Returns None if instruction is invalid/unknown.
    """
    opcode = word & 0x7f
    func3 = (word >> 12) & 0x7
    func7 = (word >> 25) & 0x7f
    
    kind = None
    
    # Decode based on opcode (matching rv32im.rs logic)
    if opcode == 0x33:  # R-type arithmetic
        if func7 == 0x00:
            kind = [0, 27, 2, 6, 3, 28, 5, 4][func3]  # Add, Sll, Xor, SltU, Or, Srl, Slt, And
        elif func7 == 0x20:
            kind = {0: 1, 5: 29}.get(func3)  # Sub, Sra
        elif func7 == 0x01:
            kind = [23, 24, 25, 26, 33, 34, 35, 36][func3]  # Mul*, Div*, Rem*
    
    elif opcode == 0x13:  # I-type arithmetic
        if func3 == 0x0:
            kind = 7   # AddI
        elif func3 == 0x1 and func7 == 0x00:
            kind = 30  # SllI
        elif func3 == 0x2:
            kind = 11  # SltI
        elif func3 == 0x3:
            kind = 12  # SltIU
        elif func3 == 0x4:
            kind = 8   # XorI
        elif func3 == 0x5:
            if func7 == 0x00:
                kind = 31  # SrlI
            elif func7 == 0x20:
                kind = 32  # SraI
        elif func3 == 0x6:
            kind = 9   # OrI
        elif func3 == 0x7:
            kind = 10  # AndI
    
    elif opcode == 0x03:  # Load
        kind = {0: 37, 1: 38, 2: 42, 4: 39, 5: 40}.get(func3)  # Lb, Lh, Lw, Lbu, Lhu
    
    elif opcode == 0x23:  # Store
        kind = {0: 43, 1: 44, 2: 50}.get(func3)  # Sb, Sh, Sw (Sw2 = 50)
    
    elif opcode == 0x63:  # Branch
        kind = {0: 13, 1: 14, 4: 15, 5: 16, 6: 17, 7: 18}.get(func3)  # Beq, Bne, Blt, Bge, BltU, BgeU
    
    elif opcode == 0x6f:  # JAL
        kind = 19
    
    elif opcode == 0x67:  # JALR
        kind = 20
    
    elif opcode == 0x37:  # LUI
        kind = 21
    
    elif opcode == 0x17:  # AUIPC
        kind = 22
    
    elif opcode == 0x0f:  # FENCE
        kind = 51
    
    elif opcode == 0x73:  # SYSTEM (ECALL/MRET)
        if word == 0x00000073:
            kind = 52  # Eany (ecall)
        elif word == 0x30200073:
            kind = 53  # Mret
    
    if kind is None:
        return None
    
    return DecodedInsn(
        kind=kind,
        major=kind // 8,
        minor=kind % 8,
        name=INSN_KIND_NAMES.get(kind, f"?{kind}"),
        opcode=opcode,
        func3=func3,
        func7=func7 if opcode == 0x33 else None,
    )


def kind_to_major_minor(kind: int) -> Tuple[int, int]:
    """Convert InsnKind to (major, minor) tuple"""
    return (kind // 8, kind % 8)


def major_minor_to_kind(major: int, minor: int) -> int:
    """Convert (major, minor) to InsnKind"""
    return major * 8 + minor


def get_kind_name(kind: int) -> str:
    """Get the name of an InsnKind"""
    return INSN_KIND_NAMES.get(kind, f"?{kind}")


def get_major_minor_name(major: int, minor: int) -> str:
    """Get the name for a (major, minor) pair"""
    return get_kind_name(major_minor_to_kind(major, minor))
