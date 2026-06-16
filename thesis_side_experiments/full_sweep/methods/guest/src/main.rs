#![no_main]
#![no_std]

// E5 broad guest — deterministic, no host args.
// Intended coverage (one line per concern; actual op mix is compiler-dependent):
//   ALU: add/sub/xor/or/and/shl/mul
//   Mem: lb/lh/lw + sb/sh/sh/sw + read-back lw
//   Ctrl: counted loop + branch taken on even / not-taken on odd iterations

use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    static mut WORDS: [u32; 8] = [3, 4, 0, 0, 0, 0, 0, 0];
    static mut BYTES: [u8; 16] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];

    unsafe {
        let words = core::ptr::addr_of_mut!(WORDS) as *mut u32;
        let bytes = core::ptr::addr_of_mut!(BYTES) as *mut u8;

        // --- word load (lw) ---
        let x = read_volatile(words.add(0));
        let y = read_volatile(words.add(1));

        // --- byte/half/word narrow loads (lb/lh/lw from byte buffer) ---
        let b0 = read_volatile(bytes.add(0)) as u32;
        let b1 = read_volatile(bytes.add(1)) as u32;
        let half = b0 | (b1 << 8);
        let b2 = read_volatile(bytes.add(2)) as u32;
        let b3 = read_volatile(bytes.add(3)) as u32;
        let b4 = read_volatile(bytes.add(4)) as u32;
        let b5 = read_volatile(bytes.add(5)) as u32;
        let b6 = read_volatile(bytes.add(6)) as u32;
        let b7 = read_volatile(bytes.add(7)) as u32;
        let word_from_bytes = b4 | (b5 << 8) | (b6 << 16) | (b7 << 24);

        // --- ALU variety ---
        let mut acc = black_box(x).wrapping_add(black_box(y));
        acc = acc.wrapping_sub(black_box(1));
        acc = acc ^ black_box(0x55);
        acc = acc | black_box(0x0F);
        acc = acc & black_box(0xFFFF);
        acc = acc.wrapping_shl(1);
        acc = acc.wrapping_mul(black_box(3));
        acc = acc
            .wrapping_add(b0)
            .wrapping_add(half)
            .wrapping_add(word_from_bytes);

        // --- counted loop + conditional branch (taken / not-taken) ---
        let mut i: u32 = 0;
        while i < 4 {
            if (i & 1) == 0 {
                acc = acc.wrapping_add(black_box(i + 10));
            } else {
                acc = acc.wrapping_sub(black_box(i));
            }
            i = i.wrapping_add(1);
        }

        // --- sub-word stores (sb/sh) + word store (sw) ---
        write_volatile(bytes.add(8), (acc & 0xFF) as u8);
        write_volatile(bytes.add(9), ((acc >> 8) & 0xFF) as u8);
        write_volatile(bytes.add(10), ((acc >> 16) & 0xFF) as u8);
        write_volatile(bytes.add(11), ((acc >> 24) & 0xFF) as u8);
        write_volatile(words.add(2), acc);
        write_volatile(words.add(3), acc.wrapping_add(1));

        // --- read-back load after store ---
        let rb_word = read_volatile(words.add(2));
        let rb_byte = read_volatile(bytes.add(8)) as u32;
        acc = acc.wrapping_add(black_box(rb_word)).wrapping_add(rb_byte);

        write_volatile(words.add(4), acc);
        let out = read_volatile(words.add(4));
        env::commit(&out);
    }
}
