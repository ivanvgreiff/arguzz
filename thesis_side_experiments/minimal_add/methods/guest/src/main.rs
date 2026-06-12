#![no_main]
#![no_std]

use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    static mut BUF: [u32; 4] = [3, 4, 0, 0];
    unsafe {
        let p = core::ptr::addr_of_mut!(BUF) as *mut u32;
        let x = read_volatile(p.add(0));
        let y = read_volatile(p.add(1));
        let s = black_box(x) + black_box(y);
        write_volatile(p.add(2), s);
        let r = read_volatile(p.add(2));
        env::commit(&r);
    }
}
