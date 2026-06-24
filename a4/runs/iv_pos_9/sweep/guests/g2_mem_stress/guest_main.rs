#![allow(unused_parens)]
// =============================================================================
// IV.POS.9 Track-B  Guest 2 — memory-stress + branch/control guest
// (ProG_Report_5 §2.2 "Guest 2 — memory-stress + branch/control guest")
// =============================================================================
//
// PURPOSE (Pro §2.2): exercise the memory-permutation / lookup constraint families
// and the global CGC surface — load/store, `prev_word`, `prev_cycle`, dependent
// write→read chains, data-dependent addressing, branches on loaded values. This is
// where Arguzz's GLOBAL (CGC) advantage is expected to come from, AND where A4's live
// kinds (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`) touch memory-permutation metadata.
//
// DESIGN: an in-guest array with (1) dependent writes, then (2) a loop of DATA-DEPENDENT
// reads (index computed from previously-loaded values → varied access pattern → stresses
// the permutation argument), branches on loaded values, and dependent writes-after-reads.
// Pure u32 + memory + control (no SHA/Poseidon/BigInt — that's Guest 3).
//
// SIZE (v2, 2026-06-24): re-sized to ~the sha2 baseline (7924 steps, risc0 2^13 segment)
// for equal proving cost. Array N reduced 64→32 (the array phases set the size floor);
// phase-2 length = `rounds` (host input) so trace size is tunable WITHOUT recompiling.
// The data-dependent-addressing PATTERN (the actual point — it stresses the permutation
// argument differently than sha2's sequential memory) is preserved at the smaller N.
//
// I/O ABI: host writes seed, mask, rounds (in order — see host_main.rs).
// =============================================================================

use risc0_zkvm::guest::env;

const N: usize = 32;          // array length (memory footprint) — was 64; sets the size floor

fn main() {
    let seed: u32 = env::read();
    let mask: u32 = env::read();
    let rounds: u32 = env::read();

    // ---- Phase 1: dependent WRITES — each store depends on the previous (write→write chain) ----
    let mut arr = [0u32; N];
    let mut x = seed | 1;
    let mut i = 0usize;
    while i < N {
        x = x.wrapping_mul(2654435761).wrapping_add(i as u32);
        arr[i] = x ^ mask;                                  // STORE
        i += 1;
    }

    // ---- Phase 2: data-dependent READS + address arithmetic + branches + write-after-read ----
    // bound = rounds (host-fixed to size the trace ~7900 steps); the access PATTERN is the point.
    let bound = rounds;
    let mut acc: u32 = seed;
    let mut idx: usize = (seed as usize) % N;
    let mut k: u32 = 0;
    while k < bound {
        let v = arr[idx];                                   // LOAD at a data-dependent address
        if (v & 1) == 0 {
            acc = acc.wrapping_add(v);
            arr[(idx + 1) % N] = acc.rotate_left(idx as u32 & 31);   // STORE (write-after-read)
        } else if (v & 2) == 0 {
            acc = acc ^ v;
            let j = (v as usize) % N;                        // second data-dependent index
            arr[j] = arr[j].wrapping_sub(acc);               // read-modify-write at a different addr
        } else {
            acc = acc.wrapping_mul(v | 1);                   // pure address-arithmetic path
        }
        idx = ((v as usize).wrapping_add(idx).wrapping_mul(2654435761 as usize)) % N;
        k = k.wrapping_add(1);
    }

    // ---- commit a checksum that depends on the full memory state ----
    let mut chk: u32 = acc;
    let mut m = 0usize;
    while m < N {
        chk = chk.wrapping_add(arr[m]).rotate_left(1);       // final read sweep over the array
        m += 1;
    }
    env::commit(&chk);
    env::commit(&(idx as u32));
    env::commit(&0xDEAD_BEEF_u32);
}
