#!/usr/bin/env python3
"""
Comprehensive Test Suite for INSTR_WORD_MOD_SUR

Tests RISC-V instruction decoding, encoding, and surgical mutation.
Uses known instruction encodings from the RISC-V specification to verify correctness.

Run with: python3 -m a4.standalone.tests.test_instr_word_mod_sur
"""

import sys
import random
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from a4.standalone.mutations.instr_word_mod_sur import (
    RiscVInstruction,
    InstrFormat,
    SurgicalField,
    OPCODES,
)


# =============================================================================
# Test Data: Known RISC-V Instructions
# =============================================================================

# Format: (instruction_word, expected_format, description, expected_fields)
# Fields: {'opcode': val, 'rd': val, 'funct3': val, 'rs1': val, 'rs2': val, 'funct7': val, 'imm': val}

TEST_INSTRUCTIONS = [
    # R-type instructions
    (0x00B50533, InstrFormat.R, "ADD x10, x10, x11",
     {'opcode': 0b0110011, 'rd': 10, 'funct3': 0, 'rs1': 10, 'rs2': 11, 'funct7': 0}),
    
    (0x40B50533, InstrFormat.R, "SUB x10, x10, x11",
     {'opcode': 0b0110011, 'rd': 10, 'funct3': 0, 'rs1': 10, 'rs2': 11, 'funct7': 0b0100000}),
    
    (0x00C5F5B3, InstrFormat.R, "AND x11, x11, x12",
     {'opcode': 0b0110011, 'rd': 11, 'funct3': 7, 'rs1': 11, 'rs2': 12, 'funct7': 0}),
    
    (0x00B54533, InstrFormat.R, "XOR x10, x10, x11",
     {'opcode': 0b0110011, 'rd': 10, 'funct3': 4, 'rs1': 10, 'rs2': 11, 'funct7': 0}),
    
    (0x02B505B3, InstrFormat.R, "MUL x11, x10, x11",
     {'opcode': 0b0110011, 'rd': 11, 'funct3': 0, 'rs1': 10, 'rs2': 11, 'funct7': 1}),
    
    # I-type ALU instructions
    (0x00100593, InstrFormat.I, "ADDI x11, x0, 1",
     {'opcode': 0b0010011, 'rd': 11, 'funct3': 0, 'rs1': 0, 'imm': 1}),
    
    (0xFFF50513, InstrFormat.I, "ADDI x10, x10, -1",
     {'opcode': 0b0010011, 'rd': 10, 'funct3': 0, 'rs1': 10, 'imm': -1}),
    
    (0x01050513, InstrFormat.I, "ADDI x10, x10, 16",
     {'opcode': 0b0010011, 'rd': 10, 'funct3': 0, 'rs1': 10, 'imm': 16}),
    
    (0x00157593, InstrFormat.I, "ANDI x11, x10, 1",
     {'opcode': 0b0010011, 'rd': 11, 'funct3': 7, 'rs1': 10, 'imm': 1}),
    
    (0x00451513, InstrFormat.I, "SLLI x10, x10, 4",
     {'opcode': 0b0010011, 'rd': 10, 'funct3': 1, 'rs1': 10, 'imm': 4}),
    
    # I-type LOAD instructions
    (0x00052503, InstrFormat.I, "LW x10, 0(x10)",
     {'opcode': 0b0000011, 'rd': 10, 'funct3': 2, 'rs1': 10, 'imm': 0}),
    
    (0x00452583, InstrFormat.I, "LW x11, 4(x10)",
     {'opcode': 0b0000011, 'rd': 11, 'funct3': 2, 'rs1': 10, 'imm': 4}),
    
    (0xFFC52503, InstrFormat.I, "LW x10, -4(x10)",
     {'opcode': 0b0000011, 'rd': 10, 'funct3': 2, 'rs1': 10, 'imm': -4}),
    
    # S-type STORE instructions
    (0x00B52023, InstrFormat.S, "SW x11, 0(x10)",
     {'opcode': 0b0100011, 'funct3': 2, 'rs1': 10, 'rs2': 11, 'imm': 0}),
    
    (0x00B52223, InstrFormat.S, "SW x11, 4(x10)",
     {'opcode': 0b0100011, 'funct3': 2, 'rs1': 10, 'rs2': 11, 'imm': 4}),
    
    (0xFEB52E23, InstrFormat.S, "SW x11, -4(x10)",
     {'opcode': 0b0100011, 'funct3': 2, 'rs1': 10, 'rs2': 11, 'imm': -4}),
    
    # B-type BRANCH instructions
    (0x00B50463, InstrFormat.B, "BEQ x10, x11, 8",
     {'opcode': 0b1100011, 'funct3': 0, 'rs1': 10, 'rs2': 11, 'imm': 8}),
    
    (0x00B51463, InstrFormat.B, "BNE x10, x11, 8",
     {'opcode': 0b1100011, 'funct3': 1, 'rs1': 10, 'rs2': 11, 'imm': 8}),
    
    (0xFEB50CE3, InstrFormat.B, "BEQ x10, x11, -8",
     {'opcode': 0b1100011, 'funct3': 0, 'rs1': 10, 'rs2': 11, 'imm': -8}),
    
    (0x00B54463, InstrFormat.B, "BLT x10, x11, 8",
     {'opcode': 0b1100011, 'funct3': 4, 'rs1': 10, 'rs2': 11, 'imm': 8}),
    
    # U-type instructions
    (0x12345537, InstrFormat.U, "LUI x10, 0x12345",
     {'opcode': 0b0110111, 'rd': 10, 'imm': 0x12345000}),
    
    (0x00001517, InstrFormat.U, "AUIPC x10, 1",
     {'opcode': 0b0010111, 'rd': 10, 'imm': 0x1000}),
    
    (0xFFFFF537, InstrFormat.U, "LUI x10, 0xFFFFF",
     {'opcode': 0b0110111, 'rd': 10, 'imm': 0xFFFFF000}),
    
    # J-type instructions
    (0x008000EF, InstrFormat.J, "JAL x1, 8",
     {'opcode': 0b1101111, 'rd': 1, 'imm': 8}),
    
    (0xFF9FF0EF, InstrFormat.J, "JAL x1, -8",
     {'opcode': 0b1101111, 'rd': 1, 'imm': -8}),
    
    # I-type JALR
    (0x000500E7, InstrFormat.I, "JALR x1, x10, 0",
     {'opcode': 0b1100111, 'rd': 1, 'funct3': 0, 'rs1': 10, 'imm': 0}),
]


# =============================================================================
# Test Functions
# =============================================================================

def test_format_detection():
    """Test that instruction formats are correctly detected"""
    print("=" * 70)
    print("TEST: Format Detection")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for word, expected_format, desc, _ in TEST_INSTRUCTIONS:
        instr = RiscVInstruction.from_word(word)
        
        if instr.format == expected_format:
            print(f"  ✓ {desc}")
            print(f"    word=0x{word:08X} → format={instr.format.value}")
            passed += 1
        else:
            print(f"  ✗ {desc}")
            print(f"    word=0x{word:08X}")
            print(f"    expected={expected_format.value}, got={instr.format.value}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_field_decoding():
    """Test that instruction fields are correctly decoded"""
    print("\n" + "=" * 70)
    print("TEST: Field Decoding")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for word, expected_format, desc, expected_fields in TEST_INSTRUCTIONS:
        instr = RiscVInstruction.from_word(word)
        
        errors = []
        for field_name, expected_val in expected_fields.items():
            if field_name == 'imm':
                actual_val = instr.imm
                # instr.imm now returns proper Python signed integers
                if instr.format == InstrFormat.U:
                    # U-type: compare as hex (upper 20 bits)
                    if actual_val != expected_val:
                        errors.append(f"{field_name}: expected 0x{expected_val:X}, got 0x{actual_val:X}")
                else:
                    # Direct comparison - both are signed Python ints
                    if actual_val != expected_val:
                        errors.append(f"{field_name}: expected {expected_val}, got {actual_val}")
            else:
                actual_val = getattr(instr, field_name)
                if actual_val != expected_val:
                    errors.append(f"{field_name}: expected {expected_val}, got {actual_val}")
        
        if not errors:
            print(f"  ✓ {desc}")
            passed += 1
        else:
            print(f"  ✗ {desc}")
            print(f"    word=0x{word:08X}")
            for err in errors:
                print(f"    ERROR: {err}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_roundtrip_encoding():
    """Test that decoding then re-encoding produces the same word"""
    print("\n" + "=" * 70)
    print("TEST: Roundtrip Encoding (decode → mutate with same value → encode)")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    for word, expected_format, desc, _ in TEST_INSTRUCTIONS:
        instr = RiscVInstruction.from_word(word)
        
        # Test each mutable field
        fields = instr.get_mutable_fields()
        field_errors = []
        
        for field in fields:
            original_val = instr.get_field_value(field)
            # Re-encode with the same value - should produce identical word
            reencoded = instr.encode_with_mutation(field, original_val)
            
            if reencoded != word:
                field_errors.append(f"{field.value}: 0x{word:08X} → 0x{reencoded:08X}")
        
        if not field_errors:
            print(f"  ✓ {desc}")
            print(f"    Tested fields: {[f.value for f in fields]}")
            passed += 1
        else:
            print(f"  ✗ {desc}")
            for err in field_errors:
                print(f"    ERROR: {err}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_surgical_mutation():
    """Test that surgical mutations actually change the instruction"""
    print("\n" + "=" * 70)
    print("TEST: Surgical Mutations")
    print("=" * 70)
    
    rng = random.Random(12345)
    passed = 0
    failed = 0
    
    for word, expected_format, desc, expected_fields in TEST_INSTRUCTIONS:
        instr = RiscVInstruction.from_word(word)
        fields = instr.get_mutable_fields()
        
        field_results = []
        
        for field in fields:
            original_val = instr.get_field_value(field)
            
            # Generate a different value
            if field == SurgicalField.OPCODE:
                new_val = (original_val + 1) & 0x7F
            elif field in (SurgicalField.RD, SurgicalField.RS1, SurgicalField.RS2):
                new_val = (original_val + 1) & 0x1F
            elif field == SurgicalField.FUNCT3:
                new_val = (original_val + 1) & 0x7
            elif field == SurgicalField.FUNCT7:
                new_val = (original_val + 1) & 0x7F
            elif field == SurgicalField.IMM:
                # Different delta based on format
                if instr.format in (InstrFormat.I, InstrFormat.S):
                    new_val = (original_val + 4) & 0xFFF
                elif instr.format == InstrFormat.B:
                    new_val = (original_val + 4) & 0x1FFE  # Keep even
                elif instr.format == InstrFormat.U:
                    new_val = (original_val + 0x1000) & 0xFFFFF000
                elif instr.format == InstrFormat.J:
                    new_val = (original_val + 4) & 0x1FFFFE  # Keep even
                else:
                    new_val = original_val
            else:
                new_val = original_val
            
            mutated_word = instr.encode_with_mutation(field, new_val)
            
            # Verify mutation happened
            if new_val != original_val:
                if mutated_word == word:
                    field_results.append((field, False, "mutation had no effect"))
                else:
                    # Decode the mutated instruction and verify field changed
                    mutated_instr = RiscVInstruction.from_word(mutated_word)
                    mutated_field_val = mutated_instr.get_field_value(field)
                    
                    # For IMM, we need to compare carefully due to sign extension
                    if field == SurgicalField.IMM:
                        if instr.format == InstrFormat.U:
                            expected_in_word = new_val
                        else:
                            expected_in_word = new_val
                        # Check the raw encoding changed
                        if mutated_word != word:
                            field_results.append((field, True, f"{original_val} → {new_val}"))
                        else:
                            field_results.append((field, False, "word unchanged"))
                    elif mutated_field_val == new_val:
                        field_results.append((field, True, f"{original_val} → {new_val}"))
                    else:
                        field_results.append((field, False, f"expected {new_val}, got {mutated_field_val}"))
            else:
                field_results.append((field, True, "same value (no mutation needed)"))
        
        all_passed = all(r[1] for r in field_results)
        
        if all_passed:
            print(f"  ✓ {desc}")
            passed += 1
        else:
            print(f"  ✗ {desc}")
            for field, success, msg in field_results:
                status = "✓" if success else "✗"
                print(f"    {status} {field.value}: {msg}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_immediate_encoding_detailed():
    """Detailed test of immediate encoding for each format"""
    print("\n" + "=" * 70)
    print("TEST: Detailed Immediate Encoding")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    # Test I-type immediate encoding
    print("\n  I-type immediate tests:")
    i_type_tests = [
        (0x00100593, 1),      # ADDI x11, x0, 1
        (0xFFF50513, -1),     # ADDI x10, x10, -1
        (0x7FF50513, 2047),   # ADDI x10, x10, 2047 (max positive)
        (0x80050513, -2048),  # ADDI x10, x10, -2048 (max negative)
    ]
    
    for word, expected_imm in i_type_tests:
        instr = RiscVInstruction.from_word(word)
        actual_imm = instr.imm
        # Sign extend for comparison
        if actual_imm & 0x800:
            actual_signed = actual_imm | 0xFFFFF000
            if actual_signed >= 0x80000000:
                actual_signed -= 0x100000000
        else:
            actual_signed = actual_imm
        
        if actual_signed == expected_imm:
            print(f"    ✓ imm={expected_imm}: word=0x{word:08X}")
            passed += 1
        else:
            print(f"    ✗ imm={expected_imm}: expected {expected_imm}, got {actual_signed}")
            failed += 1
    
    # Test S-type immediate encoding
    print("\n  S-type immediate tests:")
    s_type_tests = [
        (0x00B52023, 0),   # SW x11, 0(x10)
        (0x00B52223, 4),   # SW x11, 4(x10)
        (0xFEB52E23, -4),  # SW x11, -4(x10)
    ]
    
    for word, expected_imm in s_type_tests:
        instr = RiscVInstruction.from_word(word)
        actual_imm = instr.imm
        if actual_imm & 0x800:
            actual_signed = actual_imm | 0xFFFFF000
            if actual_signed >= 0x80000000:
                actual_signed -= 0x100000000
        else:
            actual_signed = actual_imm
        
        if actual_signed == expected_imm:
            print(f"    ✓ imm={expected_imm}: word=0x{word:08X}")
            passed += 1
        else:
            print(f"    ✗ imm={expected_imm}: expected {expected_imm}, got {actual_signed}")
            failed += 1
    
    # Test B-type immediate encoding
    print("\n  B-type immediate tests:")
    b_type_tests = [
        (0x00B50463, 8),    # BEQ x10, x11, 8
        (0xFEB50CE3, -8),   # BEQ x10, x11, -8
        (0x00B50063, 0),    # BEQ x10, x11, 0
    ]
    
    for word, expected_imm in b_type_tests:
        instr = RiscVInstruction.from_word(word)
        actual_imm = instr.imm
        if actual_imm & 0x1000:
            actual_signed = actual_imm | 0xFFFFE000
            if actual_signed >= 0x80000000:
                actual_signed -= 0x100000000
        else:
            actual_signed = actual_imm
        
        if actual_signed == expected_imm:
            print(f"    ✓ imm={expected_imm}: word=0x{word:08X}")
            passed += 1
        else:
            print(f"    ✗ imm={expected_imm}: expected {expected_imm}, got {actual_signed}")
            failed += 1
    
    # Test J-type immediate encoding
    print("\n  J-type immediate tests:")
    j_type_tests = [
        (0x008000EF, 8),    # JAL x1, 8
        (0xFF9FF0EF, -8),   # JAL x1, -8
    ]
    
    for word, expected_imm in j_type_tests:
        instr = RiscVInstruction.from_word(word)
        actual_imm = instr.imm
        if actual_imm & 0x100000:
            actual_signed = actual_imm | 0xFFE00000
            if actual_signed >= 0x80000000:
                actual_signed -= 0x100000000
        else:
            actual_signed = actual_imm
        
        if actual_signed == expected_imm:
            print(f"    ✓ imm={expected_imm}: word=0x{word:08X}")
            passed += 1
        else:
            print(f"    ✗ imm={expected_imm}: expected {expected_imm}, got {actual_signed}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_immediate_roundtrip():
    """Test that immediate values survive encode-decode roundtrip"""
    print("\n" + "=" * 70)
    print("TEST: Immediate Roundtrip (change imm, decode, verify)")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    def sign_extend_to_width(val, width):
        """Sign extend a value to the specified bit width, returning Python signed int"""
        mask = (1 << width) - 1
        val = val & mask
        sign_bit = 1 << (width - 1)
        if val & sign_bit:
            return val - (1 << width)
        return val
    
    # Test for each format that has immediates
    test_cases = [
        # (base_word, format, test_immediates, bit_width)
        (0x00100593, InstrFormat.I, [0, 1, -1, 100, -100, 2047, -2048], 12),
        (0x00B52023, InstrFormat.S, [0, 4, -4, 100, -100, 2047, -2048], 12),
        (0x00B50463, InstrFormat.B, [0, 8, -8, 100, -100, 4094, -4096], 13),
        (0x12345537, InstrFormat.U, [0x1000, 0x12345000, 0xFFFFF000], 32),
        (0x008000EF, InstrFormat.J, [0, 8, -8, 1000, -1000], 21),
    ]
    
    for base_word, fmt, test_imms, bit_width in test_cases:
        print(f"\n  {fmt.value}-type immediate roundtrip:")
        instr = RiscVInstruction.from_word(base_word)
        
        for test_imm in test_imms:
            # Encode the new immediate
            mutated_word = instr.encode_with_mutation(SurgicalField.IMM, test_imm)
            
            # Decode it back
            decoded = RiscVInstruction.from_word(mutated_word)
            recovered_imm = decoded.imm
            
            # Calculate expected value based on format constraints
            if fmt == InstrFormat.U:
                # U-type: upper 20 bits, no sign extension, just mask
                expected = test_imm & 0xFFFFF000
            elif fmt == InstrFormat.B or fmt == InstrFormat.J:
                # B/J: must be even (LSB always 0), then sign extend
                expected = sign_extend_to_width(test_imm & ~1, bit_width)
            else:
                # I/S: sign extend to bit width
                expected = sign_extend_to_width(test_imm, bit_width)
            
            if recovered_imm == expected:
                print(f"    ✓ imm={test_imm} → encode → decode → {recovered_imm}")
                passed += 1
            else:
                print(f"    ✗ imm={test_imm} → encode → decode → {recovered_imm} (expected {expected})")
                print(f"      word=0x{mutated_word:08X}")
                failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_register_mutation():
    """Test that register field mutations work correctly"""
    print("\n" + "=" * 70)
    print("TEST: Register Field Mutations")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    # Base instruction: ADD x10, x10, x11
    base_word = 0x00B50533
    instr = RiscVInstruction.from_word(base_word)
    
    print(f"  Base instruction: {instr.disassemble()}")
    print(f"  word=0x{base_word:08X}\n")
    
    # Test rd mutation
    for new_rd in [0, 1, 15, 31]:
        mutated = instr.encode_with_mutation(SurgicalField.RD, new_rd)
        decoded = RiscVInstruction.from_word(mutated)
        
        if decoded.rd == new_rd:
            print(f"  ✓ rd → {new_rd}: word=0x{mutated:08X}, decoded rd={decoded.rd}")
            passed += 1
        else:
            print(f"  ✗ rd → {new_rd}: expected rd={new_rd}, got rd={decoded.rd}")
            failed += 1
    
    # Test rs1 mutation
    for new_rs1 in [0, 1, 15, 31]:
        mutated = instr.encode_with_mutation(SurgicalField.RS1, new_rs1)
        decoded = RiscVInstruction.from_word(mutated)
        
        if decoded.rs1 == new_rs1:
            print(f"  ✓ rs1 → {new_rs1}: word=0x{mutated:08X}, decoded rs1={decoded.rs1}")
            passed += 1
        else:
            print(f"  ✗ rs1 → {new_rs1}: expected rs1={new_rs1}, got rs1={decoded.rs1}")
            failed += 1
    
    # Test rs2 mutation
    for new_rs2 in [0, 1, 15, 31]:
        mutated = instr.encode_with_mutation(SurgicalField.RS2, new_rs2)
        decoded = RiscVInstruction.from_word(mutated)
        
        if decoded.rs2 == new_rs2:
            print(f"  ✓ rs2 → {new_rs2}: word=0x{mutated:08X}, decoded rs2={decoded.rs2}")
            passed += 1
        else:
            print(f"  ✗ rs2 → {new_rs2}: expected rs2={new_rs2}, got rs2={decoded.rs2}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def test_opcode_mutation():
    """Test that opcode mutations work correctly"""
    print("\n" + "=" * 70)
    print("TEST: Opcode Mutations")
    print("=" * 70)
    
    passed = 0
    failed = 0
    
    # Base instruction: ADDI x10, x10, 1
    base_word = 0x00150513
    instr = RiscVInstruction.from_word(base_word)
    
    print(f"  Base instruction: {instr.disassemble()}")
    print(f"  word=0x{base_word:08X}, opcode=0b{instr.opcode:07b}\n")
    
    # Test opcode mutations to other known opcodes
    test_opcodes = [
        (0b0110011, "R-type OP"),
        (0b0000011, "I-type LOAD"),
        (0b0100011, "S-type STORE"),
        (0b1100011, "B-type BRANCH"),
        (0b0110111, "U-type LUI"),
        (0b1101111, "J-type JAL"),
    ]
    
    for new_opcode, name in test_opcodes:
        mutated = instr.encode_with_mutation(SurgicalField.OPCODE, new_opcode)
        decoded = RiscVInstruction.from_word(mutated)
        
        if decoded.opcode == new_opcode:
            print(f"  ✓ opcode → 0b{new_opcode:07b} ({name}): word=0x{mutated:08X}")
            passed += 1
        else:
            print(f"  ✗ opcode → 0b{new_opcode:07b} ({name}): expected {new_opcode}, got {decoded.opcode}")
            failed += 1
    
    print(f"\n  Results: {passed} passed, {failed} failed")
    return failed == 0


def run_all_tests():
    """Run all tests and report summary"""
    print("\n" + "=" * 70)
    print("INSTR_WORD_MOD_SUR TEST SUITE")
    print("=" * 70)
    print(f"\nTesting RISC-V instruction decoding and surgical mutation encoding.\n")
    
    results = []
    
    results.append(("Format Detection", test_format_detection()))
    results.append(("Field Decoding", test_field_decoding()))
    results.append(("Roundtrip Encoding", test_roundtrip_encoding()))
    results.append(("Surgical Mutation", test_surgical_mutation()))
    results.append(("Immediate Encoding (Detailed)", test_immediate_encoding_detailed()))
    results.append(("Immediate Roundtrip", test_immediate_roundtrip()))
    results.append(("Register Mutation", test_register_mutation()))
    results.append(("Opcode Mutation", test_opcode_mutation()))
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print("=" * 70)
    if all_passed:
        print("ALL TESTS PASSED ✓")
        return 0
    else:
        print("SOME TESTS FAILED ✗")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
