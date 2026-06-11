#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

/// Minimal thesis guest: one R-type add with fixed operands 3 + 4 = 7.
///
/// Equivalent assembly intent (as compiled):
///   li a0, 3
///   li a1, 4
///   add s0, a0, a1
risc0_zkvm::guest::entry!(main);

fn main() {
    let rs1: u32 = 3;
    let rs2: u32 = 4;
    let rd: u32;

    unsafe {
        core::arch::asm!(
            "add {rd}, {rs1}, {rs2}",
            rd = out(reg) rd,
            rs1 = in(reg) rs1,
            rs2 = in(reg) rs2,
        );
    }

    env::commit(&rd);
}
