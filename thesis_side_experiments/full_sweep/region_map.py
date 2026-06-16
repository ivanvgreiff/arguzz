"""Memory/PC region classifier for E5 target_region (from platform.rs constants)."""

from __future__ import annotations

from typing import Any, Dict, Optional

USER_START = 0x0001_0000
USER_END = 0xC000_0000
KERNEL_START = 0xC000_0000
KERNEL_END = 0xFF00_0000
USER_REGS_BYTE = 0xFFFF_0080
MACHINE_REGS_BYTE = 0xFFFF_0000


def build_region_map_rules() -> dict:
    return {
        "source": "workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs",
        "USER_START_ADDR": hex(USER_START),
        "USER_END_ADDR": hex(USER_END),
        "KERNEL_START_ADDR": hex(KERNEL_START),
        "KERNEL_PC_threshold": hex(KERNEL_START),
        "USER_REGS_ADDR": hex(USER_REGS_BYTE),
    }


def classify_byte_addr(addr: int) -> str:
    if addr < USER_START:
        return "bootloader"
    if USER_START <= addr < USER_END:
        return "guest_data"
    if KERNEL_START <= addr < KERNEL_END:
        return "machine_kernel"
    if addr >= MACHINE_REGS_BYTE:
        return "machine_kernel"
    return "other"


def classify_pc(pc: int, guest_text_lo: Optional[int], guest_text_hi: Optional[int]) -> str:
    if pc >= KERNEL_START:
        return "machine_kernel"
    if guest_text_lo is not None and guest_text_hi is not None:
        if guest_text_lo <= pc < guest_text_hi:
            return "guest_code"
    if USER_START <= pc < USER_END:
        return "guest_data"
    return "other"


def classify_target(
    target_kind: Optional[str],
    addr_or_reg: Optional[Any],
    pc: Optional[int],
    guest_text: tuple[Optional[int], Optional[int]] = (None, None),
) -> tuple[str, bool]:
    """Return (target_region, hits_guest_data)."""
    lo, hi = guest_text
    if target_kind == "pc" and pc is not None:
        region = classify_pc(pc, lo, hi)
        return region, region == "guest_data"
    if target_kind in ("mem", "word", "txn") and isinstance(addr_or_reg, int):
        region = classify_byte_addr(addr_or_reg)
        return region, region == "guest_data"
    if target_kind == "reg" and isinstance(addr_or_reg, str):
        return "guest_data", True
    if pc is not None:
        region = classify_pc(pc, lo, hi)
        return region, region == "guest_data"
    return "other", False
