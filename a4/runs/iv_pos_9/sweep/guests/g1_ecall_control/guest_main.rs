#![allow(unused_parens)]
// =============================================================================
// IV.POS.9 Track-B  Guest 1 — control-flow-heavy guest (ProG_Report_5 §2.2 "Guest 1")
// =============================================================================
//
// PURPOSE (Pro §2.2): exercise the decode/CONTROL families (`inst_control`) where
// D2.H found A4 strongest — branches, jumps, function calls (JalR), conditional
// control. Tests whether A4's local/control advantage generalizes.
//
// SIZE (v3, 2026-06-24): re-sized to ~the sha2 baseline (7924 executed steps, risc0
// 2^13 proving segment) so proving cost matches the baseline (~3.3 s/mut on Tier A)
// instead of the v2 25k-step / 2^15 segment (~5-6x slower). The risc0 runtime bootstrap
// is ~6200 steps, so only ~1700 "user" steps fit under 8192 — to keep a CLEAR control
// signal in that budget the loop is CONTROL-DENSE: each iteration is a ladder of
// conditional branches + #[inline(never)] calls (Beq/Bne/Jal/JalR), with minimal
// arithmetic. Loop length = `rounds` (host input) so trace size is tunable WITHOUT
// recompiling; the sweep fixes `--rounds` to land ~7900 steps.
//
// I/O ABI: host writes ctrl, gseed, rounds (guest reads the 3 control words).
// =============================================================================

use risc0_zkvm::guest::env;

// #[inline(never)] forces real call/return (Jal/JalR) AND each callee has an internal
// branch — so every call contributes both jump-density and branch-density to inst_control.
#[inline(never)]
fn step_a(x: u32) -> u32 { if (x & 1) != 0 { x.rotate_left(7) } else { x.wrapping_add(0x9E37_79B9) } }
#[inline(never)]
fn step_b(x: u32) -> u32 { if (x & 2) != 0 { x ^ 0x5851_F42D } else { x.rotate_right(5) } }
#[inline(never)]
fn step_c(x: u32, y: u32) -> u32 {
    if x > y { x.wrapping_sub(y) } else if (x & 4) != 0 { x ^ y } else { x.wrapping_add(y | 1) }
}

fn main() {
    let ctrl: u32 = env::read();
    let gseed: u32 = env::read();
    let rounds: u32 = env::read();

    let iters = rounds;                 // host fixes this to size the trace (~7900 steps)
    let mut acc: u32 = gseed | 1;
    let mut taken: u32 = 0;
    let mut i: u32 = 0;
    while i < iters {
        // Dense branch ladder + calls — almost all CONTROL, little arithmetic.
        acc = if (acc & 1) != 0 { step_a(acc) } else { step_b(acc) };
        if (acc & 2) != 0 { acc = step_b(acc); taken = taken.wrapping_add(1); }
        acc = if (acc & 4) != 0 { step_a(acc) }
              else if (acc & 8) != 0 { step_c(acc, ctrl) }
              else { step_b(acc) };
        match acc & 7 {
            0 => acc = step_a(acc),
            1 => acc = step_b(acc),
            2 => acc = step_c(acc, i),
            3 => { if acc > gseed { acc = step_a(acc); taken = taken.wrapping_add(1); } else { acc = step_b(acc); } }
            4 => acc = step_c(acc, ctrl),
            5 => acc = step_a(acc),
            6 => { if (acc & 0x100) != 0 { acc = step_b(acc); } else { acc = step_c(acc, gseed); } }
            _ => acc = step_a(acc),
        }
        acc = if acc > ctrl { step_c(acc, taken) } else { step_a(acc) };
        i = i.wrapping_add(1);
    }

    env::commit(&acc);
    env::commit(&taken);
    env::commit(&0xDEAD_BEEF_u32);
}
