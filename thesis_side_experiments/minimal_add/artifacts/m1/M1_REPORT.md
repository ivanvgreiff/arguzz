# M1 Report — Add Constraint Universe (Baseline, No Mutation)

**Status:** PASS

Frozen add site from M0: Arguzz step 187, A4 step 185, cycle_idx 15424, major/minor 0/0.

## Baseline control (global signal silent)

- `<constraint_fail>` count: **0**
- Hook 3 family residues (GLOBAL control):
  - **memory**: nonzero=False
  - **u16**: nonzero=False
  - **u8**: nonzero=False
  - **cycle**: nonzero=False
- A4_GLOBAL_RESIDUE: **nonzero=False**

## Add local universe (phase=local witgen, major=0 minor=0)

**37 contexts** — denominator for bias comparison at the Add instruction class.

| # | loc (short) | label |
|---|-------------|-------|
| 1 | `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)` | U32 normalize/decompose — 32-bit value split into circuit-native limbs |
| 2 | `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:71)` | U32 normalize/decompose — 32-bit value split into circuit-native limbs |
| 3 | `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` | Decoder — instruction word decomposes to expected R-type ADD fields |
| 4 | `Decoder(zirgen/circuit/rv32im/v2/dsl/decode.zir:37)` | Decoder — instruction word decomposes to expected R-type ADD fields |
| 5 | `Decoder(zirgen/circuit/rv32im/v2/dsl/decode.zir:46)` | Decoder — instruction word decomposes to expected R-type ADD fields |
| 6 | `DoCycleTable(zirgen/circuit/rv32im/v2/dsl/inst.zir:21)` | DoCycleTable — instruction class selects MISC0 row in cycle table |
| 7 | `DoCycleTable(zirgen/circuit/rv32im/v2/dsl/inst.zir:22)` | DoCycleTable — instruction class selects MISC0 row in cycle table |
| 8 | `IsCycle(zirgen/circuit/rv32im/v2/dsl/mem.zir:61)` | IsCycle — memory-row cycle counters consistent with circuit cycle |
| 9 | `IsCycle(zirgen/circuit/rv32im/v2/dsl/mem.zir:62)` | IsCycle — memory-row cycle counters consistent with circuit cycle |
| 10 | `IsZero(zirgen/circuit/rv32im/v2/dsl/is_zero.zir:16)` | IsZero — zero-test helper used in decode/ALU plumbing |
| 11 | `IsZero(zirgen/circuit/rv32im/v2/dsl/is_zero.zir:18)` | IsZero — zero-test helper used in decode/ALU plumbing |
| 12 | `IsZero(zirgen/circuit/rv32im/v2/dsl/is_zero.zir:20)` | IsZero — zero-test helper used in decode/ALU plumbing |
| 13 | `MemoryIO(zirgen/circuit/rv32im/v2/dsl/mem.zir:69)` | MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step |
| 14 | `MemoryIO(zirgen/circuit/rv32im/v2/dsl/mem.zir:70)` | MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step |
| 15 | `MemoryIO(zirgen/circuit/rv32im/v2/dsl/mem.zir:71)` | MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step |
| 16 | `MemoryIO(zirgen/circuit/rv32im/v2/dsl/mem.zir:73)` | MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step |
| 17 | `MemoryIO(zirgen/circuit/rv32im/v2/dsl/mem.zir:74)` | MemoryIO — memory-argument row fields (addr/cycle/data) well-formed for this step |
| 18 | `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` | MemoryWrite@mem.zir:100 — companion WRITE consistency check (high limb / paired row) |
| 19 | `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` | MemoryWrite@mem.zir:99 — WRITE txn: written word must match the computed/read chain for this cycle |
| 20 | `Misc0(zirgen/circuit/rv32im/v2/dsl/inst_misc.zir:32)` | Misc0 — MISC0 ALU arm active (ADD path through inst_misc.zir) |
| 21 | `MiscInput(zirgen/circuit/rv32im/v2/dsl/inst_misc.zir:7)` | MiscInput — ALU operand inputs wired into MISC0 block |
| 22 | `NondetU16Reg(zirgen/circuit/rv32im/v2/dsl/lookups.zir:43)` | U16 lookup — register limb participates in U16 range lookup table (LogUp use-side) |
| 23 | `NormalizeU32(zirgen/circuit/rv32im/v2/dsl/u32.zir:46)` | U32 normalize/decompose — 32-bit value split into circuit-native limbs |
| 24 | `NormalizeU32(zirgen/circuit/rv32im/v2/dsl/u32.zir:52)` | U32 normalize/decompose — 32-bit value split into circuit-native limbs |
| 25 | `OneHot(zirgen/circuit/rv32im/v2/dsl/one_hot.zir:11)` | OneHot — one-hot mux selector for decode/execute routing |
| 26 | `OneHot(zirgen/circuit/rv32im/v2/dsl/one_hot.zir:9)` | OneHot — one-hot mux selector for decode/execute routing |
| 27 | `ReadSourceRegs(zirgen/circuit/rv32im/v2/dsl/inst.zir:49)` | ReadSourceRegs — rs1/rs2 register reads connected to execution unit |
| 28 | `Reg(<preamble>:6)` | Reg preamble — register file cell witness wiring |
| 29 | `U16Reg(zirgen/circuit/rv32im/v2/dsl/lookups.zir:51)` | U16 lookup — register limb participates in U16 range lookup table (LogUp use-side) |
| 30 | `loc(callsite( AssertBit ( zirgen/circuit/rv32im/v2/dsl/bits.zir :7:20...` | Bit witness — single-bit nondeterministic value constrained to {0,1} |
| 31 | `loc(callsite( AssertBit ( zirgen/circuit/rv32im/v2/dsl/bits.zir :7:20...` | Bit witness — single-bit nondeterministic value constrained to {0,1} |
| 32 | `loc(callsite( AssertTwit ( zirgen/circuit/rv32im/v2/dsl/bits.zir :38:...` | Twit witness — 2-bit nondeterministic value constrained to small range |
| 33 | `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) a...` | IsRead@mem.zir:79 — on a READ txn, word must equal prev_word on the same transaction (intra-txn consistency; does NOT prove cross-row memory closure — see PRESENTATION_DEEP_DIVE §Slide 2) |
| 34 | `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) a...` | IsRead@mem.zir:80 — high limb of READ word equals prev_word high limb (companion to :79) |
| 35 | `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zi...` | VerifyOpcodeF3F7 — decoded funct3/funct7 match the ADD opcode pattern |
| 36 | `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zi...` | VerifyOpcodeF3F7 — decoded funct3/funct7 match the ADD opcode pattern |
| 37 | `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zi...` | VerifyOpcodeF3F7 — decoded funct3/funct7 match the ADD opcode pattern |

## Accum-pass universe (phase=accum, whole trace)

**298 contexts** — accumulation machinery checks; **not** the thesis GLOBAL multiset (that is Hook 3). Full list in `accum_universe.json`.

## Bitmap reconciliation (Add context only)

- Verbose Add contexts: **37**
- Distinct bitmap buckets: **37**
- Collision groups: **0**
- All Add buckets have counter>0: **True**

Whole-program bitmap distinct buckets (for reference): local=1565, accum=294.

## Artifacts
- `artifacts/m1/M1_REPORT.json`
- `artifacts/m1/add_local_universe.json`
- `artifacts/m1/accum_universe.json`
- `artifacts/m1/baseline_full.txt`

**Opus gate:** M1 acceptance met. Await greenlight for **M2**.
