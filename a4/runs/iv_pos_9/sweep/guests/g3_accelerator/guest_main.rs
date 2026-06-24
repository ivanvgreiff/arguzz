#![allow(unused_parens)]
// =============================================================================
// IV.POS.9 Track-B  Guest 3 — accelerator / under-explored-family guest
// (ProG_Report_5 §2.2 "Guest 3 — accelerator / Poseidon / BigInt guest")
// =============================================================================
//
// PURPOSE (Pro §2.2): activate circuit families EMPTY or thin on the baseline guest —
// the `core_sha` accelerator family (entirely empty on the CircIL baseline). Tests
// under-explored regions and whether currently-dead A4 paging/cycle kinds activate here.
//
// HEADLINE FAMILY = core_sha (the SHA accelerator). VERIFIED: each SHA finalize() drives
// the SHA circuit, surfacing as extra `Eany` (sys_sha) ecalls — present here, ZERO on the
// baseline → a qualitatively new family even at low round count.
//
// DIV CAVEAT (found 2026-06-24): the div/rem section below does NOT surface as Div/Rem
// instructions in the executor trace (the toolchain lowers u32 `/`,`%` to a __udivsi3-style
// helper / the rv32im DIV is not emitted as expected) — so `inst_div` activation is NOT
// confirmed for this guest. g3's genuine differentiator is core_sha; the div loop is kept
// only as a cheap, deterministic non-SHA tail (it does not inflate `inst_div`).
//
// SIZE (v2, 2026-06-24): re-sized toward the sha2 baseline (7924 steps, 2^13 segment).
// SHA is the cost driver (~1350 steps/round), so the SHA chain length = `rounds` (host
// input): rounds=1 → ~2^13 (cost parity, minimal-but-present core_sha); rounds=2 → ~2^14
// (clearer SHA signal, ~2x cost). The sweep fixes `--rounds` to the chosen point.
//
// I/O ABI: host writes seed, modulus, rounds (in order — see host_main.rs).
// =============================================================================

use risc0_zkvm::guest::env;
// risc0's BUILT-IN accelerated SHA-256 — no extra crate, no `[patch]` (ships with risc0-zkvm).
use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};

const SHA_CAP: u32 = 8;     // safety cap on the input-driven SHA chain length
const DIV_ROUNDS: u32 = 16; // cheap deterministic non-SHA tail (does NOT activate inst_div — see caveat)

fn main() {
    let seed: u32 = env::read();
    let modulus: u32 = env::read();
    let rounds: u32 = env::read();

    // ---- Section 1: SHA-256 accelerator (core_sha family) — the headline new family ----
    // Chain hashes: digest_{n+1} = SHA256(digest_n). Each finalize() drives the SHA circuit.
    let mut block = seed.to_le_bytes().to_vec();
    let sha_n = if rounds > SHA_CAP { SHA_CAP } else { rounds };   // host fixes size via rounds
    let mut digest = [0u8; 32];
    let mut r = 0u32;
    while r < sha_n {
        let mut hasher = Sha256::new();
        hasher.update(&block);
        let out = hasher.finalize();
        digest.copy_from_slice(&out[..]);
        block = out[..].to_vec();             // chain: hash the previous digest
        r = r.wrapping_add(1);
    }
    let sha_word = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    env::commit(&sha_word);

    // ---- Section 2: small modular-arithmetic tail (see DIV CAVEAT above) ----
    let m = if modulus < 2 { 0xFFFF_FFFB } else { modulus };
    let mut acc: u32 = sha_word | 1;
    let mut d = 0u32;
    while d < DIV_ROUNDS {
        acc = acc.wrapping_mul(2654435761).wrapping_add(d);
        let q = acc / m;
        let rem = acc % m;
        if (rem & 1) == 0 { acc = acc ^ (q.wrapping_add(rem)); } else { acc = acc.wrapping_sub(q ^ rem); }
        d = d.wrapping_add(1);
    }

    env::commit(&acc);
    env::commit(&0xDEAD_BEEF_u32);
}
