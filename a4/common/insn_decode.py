"""
RISC-V Instruction Decoding

Provides InsnKind enumeration and instruction word decoding,
mirroring the logic in risc0/circuit/rv32im/src/execute/rv32im.rs
"""

from dataclasses import dataclass
from typing import Optional, Tuple


# InsnKind enum values (from rv32im.rs:398-455)
# These match the Rust enum exactly: major = kind // 8, minor = kind % 8
INSN_KIND_NAMES = {
    # major=0
    0: "Add", 1: "Sub", 2: "Xor", 3: "Or", 4: "And", 5: "Slt", 6: "SltU", 7: "AddI",
    # major=1  
    8: "XorI", 9: "OrI", 10: "AndI", 11: "SltI", 12: "SltIU", 13: "Beq", 14: "Bne", 15: "Blt",
    # major=2
    16: "Bge", 17: "BltU", 18: "BgeU", 19: "Jal", 20: "JalR", 21: "Lui", 22: "Auipc",
    # major=3
    24: "Sll", 25: "SllI", 26: "Mul", 27: "MulH", 28: "MulHSU", 29: "MulHU",
    # major=4
    32: "Srl", 33: "Sra", 34: "SrlI", 35: "SraI", 36: "Div", 37: "DivU", 38: "Rem", 39: "RemU",
    # major=5
    40: "Lb", 41: "Lh", 42: "Lw", 43: "LbU", 44: "LhU",
    # major=6
    48: "Sb", 49: "Sh", 50: "Sw",
    # major=7
    56: "Eany", 57: "Mret",
    # invalid
    255: "Invalid",
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
    # 
    # R-type func3 mapping (from rv32im.rs lines 58-67):
    #   func3=0 → Add (kind=0)
    #   func3=1 → Sll (kind=24)
    #   func3=2 → Slt (kind=5)
    #   func3=3 → SltU (kind=6)
    #   func3=4 → Xor (kind=2)
    #   func3=5 → Srl (kind=32) [func7=0x00] or Sra (kind=33) [func7=0x20]
    #   func3=6 → Or (kind=3)
    #   func3=7 → And (kind=4)
    #
    if opcode == 0x33:  # R-type arithmetic
        if func7 == 0x00:
            # func3: 0=Add, 1=Sll, 2=Slt, 3=SltU, 4=Xor, 5=Srl, 6=Or, 7=And
            # kinds: Add=0, Sll=24, Slt=5, SltU=6, Xor=2, Srl=32, Or=3, And=4
            kind = [0, 24, 5, 6, 2, 32, 3, 4][func3]
        elif func7 == 0x20:
            kind = {0: 1, 5: 33}.get(func3)  # Sub=1, Sra=33
        elif func7 == 0x01:
            # M-extension: func3: 0=Mul, 1=MulH, 2=MulHSU, 3=MulHU, 4=Div, 5=DivU, 6=Rem, 7=RemU
            # kinds: Mul=26, MulH=27, MulHSU=28, MulHU=29, Div=36, DivU=37, Rem=38, RemU=39
            kind = [26, 27, 28, 29, 36, 37, 38, 39][func3]
    
    elif opcode == 0x13:  # I-type arithmetic
        # Verified against rv32im.rs:77-85
        if func3 == 0x0:
            kind = 7   # AddI
        elif func3 == 0x1 and func7 == 0x00:
            kind = 25  # SllI (kind=25, major=3, minor=1)
        elif func3 == 0x2:
            kind = 11  # SltI
        elif func3 == 0x3:
            kind = 12  # SltIU
        elif func3 == 0x4:
            kind = 8   # XorI
        elif func3 == 0x5:
            if func7 == 0x00:
                kind = 34  # SrlI (kind=34, major=4, minor=2)
            elif func7 == 0x20:
                kind = 35  # SraI (kind=35, major=4, minor=3)
        elif func3 == 0x6:
            kind = 9   # OrI
        elif func3 == 0x7:
            kind = 10  # AndI
    
    elif opcode == 0x03:  # Load
        # Verified against rv32im.rs:87-91: Lb=40, Lh=41, Lw=42, LbU=43, LhU=44
        kind = {0: 40, 1: 41, 2: 42, 4: 43, 5: 44}.get(func3)
    
    elif opcode == 0x23:  # Store
        # Verified against rv32im.rs:93-95: Sb=48, Sh=49, Sw=50
        kind = {0: 48, 1: 49, 2: 50}.get(func3)
    
    elif opcode == 0x63:  # Branch
        # Verified against rv32im.rs:101-106: Beq=13, Bne=14, Blt=15, Bge=16, BltU=17, BgeU=18
        kind = {0: 13, 1: 14, 4: 15, 5: 16, 6: 17, 7: 18}.get(func3)
    
    elif opcode == 0x6f:  # JAL
        kind = 19  # Jal
    
    elif opcode == 0x67:  # JALR
        kind = 20  # JalR
    
    elif opcode == 0x37:  # LUI
        kind = 21  # Lui
    
    elif opcode == 0x17:  # AUIPC
        kind = 22  # Auipc
    
    # Note: No FENCE in InsnKind enum - it's handled specially
    
    elif opcode == 0x73:  # SYSTEM (ECALL/MRET)
        # Verified against rv32im.rs:112-113: Mret=57, Eany=56
        if word == 0x00000073:
            kind = 56  # Eany (ecall)
        elif word == 0x30200073:
            kind = 57  # Mret
    
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
