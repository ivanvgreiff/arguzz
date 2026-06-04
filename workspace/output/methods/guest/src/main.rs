#![allow(unconditional_panic)]
#![allow(arithmetic_overflow)]

use risc0_zkvm::guest::env;

/*

@field(4294967296)
circuit c0 (in0:bool, in1:field, in2:bool, in3:bool, in4:field) -> (out0:field, out1:bool, out2:bool, out3:field, out4:field, out5:bool):
    var0 = (1466990855 * 3197732170)
    out0 = (var0 & 3739915678)
    var1 = and(0, 4294967295)
    var2 = (F ? 798126737 : out0)
    var3 = (var2 == 0)
    var4 = (F ? 798126737 : out0)
    var5 = (var3 ? 1 : var4)
    var6 = (var1 % var5)
    var7 = (out0 & var6)
    var8 = (~ in1)
    var9 = (var7 >= var8)
    out1 = (in3 && var9)
    out2 = F
    out3 = 3953817345
    var10 = (! out1)
    var11 = (! var10)
    var12 = (! in0)
    var13 = (! F)
    var14 = (var12 ? var13 : in2)
    var15 = (var11 || var14)
    var16 = (out2 || var15)
    var17 = or(out3, 1979401237)
    var18 = (3805079419 + var17)
    out4 = (var16 ? 0 : var18)
    out5 = in2

*/

#[allow(non_snake_case, unused_comparisons, unused_parens, unused_variables)]
pub fn c0(in0: bool, in1: u32, in2: bool, in3: bool, in4: u32) -> (u32, bool, bool, u32, u32, bool) {
    
    macro_rules! and {
        ($a:expr, $b:expr) => {{
            let result: u32;
            unsafe {
                core::arch::asm!(
                    "and {result}, {a}, {b}",
                    result = out(reg) result,
                    a = in(reg) $a,
                    b = in(reg) $b,
                );
            }
            result
        }}
    }
    
    
    macro_rules! or {
        ($a:expr, $b:expr) => {{
            let result: u32;
            unsafe {
                core::arch::asm!(
                    "or {result}, {a}, {b}",
                    result = out(reg) result,
                    a = in(reg) $a,
                    b = in(reg) $b,
                );
            }
            result
        }}
    }
    
    let var0 = (1466990855_u32 * 3197732170_u32);
    let out0 = (var0 & 3739915678_u32);
    let var1 = and!(0_u32, 4294967295_u32);
    let var2 = (if false { 798126737_u32 } else { out0 });
    let var3 = (var2 == 0_u32);
    let var4 = (if false { 798126737_u32 } else { out0 });
    let var5 = (if var3 { 1_u32 } else { var4 });
    let var6 = (var1 % var5);
    let var7 = (out0 & var6);
    let var8 = (! in1);
    let var9 = (var7 >= var8);
    let out1 = (in3 && var9);
    let out2 = false;
    let out3 = 3953817345_u32;
    let var10 = (! out1);
    let var11 = (! var10);
    let var12 = (! in0);
    let var13 = (! false);
    let var14 = (if var12 { var13 } else { in2 });
    let var15 = (var11 || var14);
    let var16 = (out2 || var15);
    let var17 = or!(out3, 1979401237_u32);
    let var18 = (3805079419_u32 + var17);
    let out4 = (if var16 { 0_u32 } else { var18 });
    let out5 = in2;
    return (out0, out1, out2, out3, out4, out5);
}

/*

@field(4294967296)
circuit c1 (in0:bool, in1:field, in2:bool, in3:bool, in4:field) -> (out0:field, out1:bool, out2:bool, out3:field, out4:field, out5:bool):
    var0 = (1466990855 * 3197732170)
    out0 = (var0 & 3739915678)
    var1 = and(0, 4294967295)
    var2 = (F ? 798126737 : out0)
    var3 = (var2 == 0)
    var4 = (F ? 798126737 : out0)
    var5 = (var3 ? 1 : var4)
    var6 = (var1 % var5)
    var7 = (out0 & var6)
    var8 = (~ in1)
    var9 = (var7 >= var8)
    out1 = (in3 && var9)
    out2 = F
    out3 = 3953817345
    var10 = (! out2)
    var11 = (! var10)
    var12 = (! out1)
    var13 = (! var12)
    var14 = (! in0)
    var15 = (! F)
    var16 = (in2 && T)
    var17 = (var14 ? var15 : var16)
    var18 = (var13 || var17)
    var19 = (var11 || var18)
    var20 = (1 ^ 0)
    var21 = (var20 == 0)
    var22 = (1 ^ 0)
    var23 = (var21 ? 1 : var22)
    var24 = (1395709893 % var23)
    var25 = or(out3, 1979401237)
    var26 = (3805079419 + var25)
    out4 = (var19 ? var24 : var26)
    out5 = in2

*/

#[allow(non_snake_case, unused_comparisons, unused_parens, unused_variables)]
pub fn c1(in0: bool, in1: u32, in2: bool, in3: bool, in4: u32) -> (u32, bool, bool, u32, u32, bool) {
    
    macro_rules! and {
        ($a:expr, $b:expr) => {{
            let result: u32;
            unsafe {
                core::arch::asm!(
                    "and {result}, {a}, {b}",
                    result = out(reg) result,
                    a = in(reg) $a,
                    b = in(reg) $b,
                );
            }
            result
        }}
    }
    
    
    macro_rules! or {
        ($a:expr, $b:expr) => {{
            let result: u32;
            unsafe {
                core::arch::asm!(
                    "or {result}, {a}, {b}",
                    result = out(reg) result,
                    a = in(reg) $a,
                    b = in(reg) $b,
                );
            }
            result
        }}
    }
    
    let var0 = (1466990855_u32 * 3197732170_u32);
    let out0 = (var0 & 3739915678_u32);
    let var1 = and!(0_u32, 4294967295_u32);
    let var2 = (if false { 798126737_u32 } else { out0 });
    let var3 = (var2 == 0_u32);
    let var4 = (if false { 798126737_u32 } else { out0 });
    let var5 = (if var3 { 1_u32 } else { var4 });
    let var6 = (var1 % var5);
    let var7 = (out0 & var6);
    let var8 = (! in1);
    let var9 = (var7 >= var8);
    let out1 = (in3 && var9);
    let out2 = false;
    let out3 = 3953817345_u32;
    let var10 = (! out2);
    let var11 = (! var10);
    let var12 = (! out1);
    let var13 = (! var12);
    let var14 = (! in0);
    let var15 = (! false);
    let var16 = (in2 && true);
    let var17 = (if var14 { var15 } else { var16 });
    let var18 = (var13 || var17);
    let var19 = (var11 || var18);
    let var20 = (1_u32 ^ 0_u32);
    let var21 = (var20 == 0_u32);
    let var22 = (1_u32 ^ 0_u32);
    let var23 = (if var21 { 1_u32 } else { var22 });
    let var24 = (1395709893_u32 % var23);
    let var25 = or!(out3, 1979401237_u32);
    let var26 = (3805079419_u32 + var25);
    let out4 = (if var19 { var24 } else { var26 });
    let out5 = in2;
    return (out0, out1, out2, out3, out4, out5);
}


fn main() {
    // -- c0 --
    let c0_in0: bool = env::read();
    let c0_in1: u32 = env::read();
    let c0_in2: bool = env::read();
    let c0_in3: bool = env::read();
    let c0_in4: u32 = env::read();

    // -- c1 --
    let c1_in0: bool = env::read();
    let c1_in1: u32 = env::read();
    let c1_in2: bool = env::read();
    let c1_in3: bool = env::read();
    let c1_in4: u32 = env::read();



    //
    // Compute Circuit Outputs
    //

    // -- c0 --
    let (
        c0_out0,
        c0_out1,
        c0_out2,
        c0_out3,
        c0_out4,
        c0_out5,
    ) : (
        u32,
        bool,
        bool,
        u32,
        u32,
        bool,
    ) = c0(
        c0_in0,
        c0_in1,
        c0_in2,
        c0_in3,
        c0_in4,
    );

    // -- c1 --
    let (
        c1_out0,
        c1_out1,
        c1_out2,
        c1_out3,
        c1_out4,
        c1_out5,
    ) : (
        u32,
        bool,
        bool,
        u32,
        u32,
        bool,
    ) = c1(
        c1_in0,
        c1_in1,
        c1_in2,
        c1_in3,
        c1_in4,
    );

    //
    // Compare Outputs
    //

    // -- c0 x c1 --
    let diff_0_0 = c0_out0 ^ c1_out0;
    if diff_0_0 != 0 {
        env::commit(&0_u32);
        return; // abort
    }

    let diff_0_1 = c0_out1 ^ c1_out1;
    if diff_0_1 {
        env::commit(&1_u32);
        return; // abort
    }

    let diff_0_2 = c0_out2 ^ c1_out2;
    if diff_0_2 {
        env::commit(&2_u32);
        return; // abort
    }

    let diff_0_3 = c0_out3 ^ c1_out3;
    if diff_0_3 != 0 {
        env::commit(&3_u32);
        return; // abort
    }

    let diff_0_4 = c0_out4 ^ c1_out4;
    if diff_0_4 != 0 {
        env::commit(&4_u32);
        return; // abort
    }

    let diff_0_5 = c0_out5 ^ c1_out5;
    if diff_0_5 {
        env::commit(&5_u32);
        return; // abort
    }

    env::commit(&3735928559_u32);

}
