# E5 constraint distributions

Expected N per type-variant: **20**

Arguzz class-specific kinds (COMP/LOAD/STORE/BR) show **fired-conditional** rates as primary; raw all-sample rates included for comparison.

## Per type-variant

### a4 / COMP_OUT_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.600, P(i≥1)=0.600, P(inter≥1)=0.000, P(g≥1)=0.600
- guest_data_hit_rate=0.600
- triple histogram: `{'0/0/0': 8, '1/0/1': 12}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×12
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×12
  - `GLOBAL:family:memory residue nonzero` ×12

### a4 / INSTR_TYPE_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.000, P(g≥1)=0.400
- guest_data_hit_rate=0.600
- triple histogram: `{'1/0/0': 12, '1/0/1': 8}`
- top locs:
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×37
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×28
  - `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)` ×11
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×10
  - `GLOBAL:family:memory residue nonzero` ×8

### a4 / INSTR_WORD_MOD_FULL

- n=20, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.100, P(g≥1)=1.000
- guest_data_hit_rate=0.600
- triple histogram: `{'1/0/1': 18, '1/1/1': 2}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×20
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×19
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×19
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :97:18) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×18
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×5

### a4 / INSTR_WORD_MOD_SUR / funct3_xor

- n=20, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.000, P(g≥1)=1.000
- guest_data_hit_rate=0.600
- triple histogram: `{'1/0/1': 20}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×20
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :97:18) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×19
  - `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` ×1

### a4 / LOAD_VAL_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.650, P(i≥1)=0.650, P(inter≥1)=0.000, P(g≥1)=0.650
- guest_data_hit_rate=0.750
- triple histogram: `{'0/0/0': 7, '1/0/1': 13}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×13
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×13
  - `GLOBAL:family:memory residue nonzero` ×13

### a4 / MEM_VAL_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=0.950, P(inter≥1)=0.900, P(g≥1)=1.000
- guest_data_hit_rate=0.650
- triple histogram: `{'0/1/1': 1, '1/1/1': 17, '1/0/1': 2}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×20
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×18
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×18
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×17
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×17

### a4 / PRE_EXEC_REG_MOD / next_read

- n=20, crash_rate=0.000 (stages: none)
- reached=0.100, P(i≥1)=0.000, P(inter≥1)=0.100, P(g≥1)=0.100
- guest_data_hit_rate=0.100
- triple histogram: `{'0/0/0': 18, '0/1/1': 2}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×2
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×2
  - `GLOBAL:family:memory residue nonzero` ×2

### a4 / PRE_EXEC_REG_MOD / prev_write

- n=20, crash_rate=0.000 (stages: none)
- reached=0.100, P(i≥1)=0.100, P(inter≥1)=0.000, P(g≥1)=0.100
- guest_data_hit_rate=0.100
- triple histogram: `{'0/0/0': 18, '1/0/1': 2}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×2
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×2
  - `GLOBAL:family:memory residue nonzero` ×2

### a4 / STORE_OUT_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.000, P(g≥1)=1.000
- guest_data_hit_rate=0.900
- triple histogram: `{'1/0/1': 20}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×20
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×20
  - `GLOBAL:family:memory residue nonzero` ×20

### arguzz / BR_NEG_COND

- n=20, crash_rate=0.050 (stages: {'prove_error': 1})
- **fired** 12/20 (60.0%); fired-silent=25.0%
- **fired-conditional:** reached=0.667, P(i≥1)=0.667, P(inter≥1)=0.000, P(g≥1)=0.667
- all-sample (diluted): reached=0.400, P(i≥1)=0.400, P(inter≥1)=0.000, P(g≥1)=0.400
- guest_data_hit_rate=0.700
- triple histogram: `{'0/0/0': 4, '1/0/1': 8}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×9
  - `GLOBAL:family:memory residue nonzero` ×8

### arguzz / COMP_OUT_MOD

- n=20, crash_rate=0.100 (stages: {'prove_error': 2})
- **fired** 20/20 (100.0%); fired-silent=30.0%
- **fired-conditional:** reached=0.600, P(i≥1)=0.600, P(inter≥1)=0.000, P(g≥1)=0.000
- all-sample (diluted): reached=0.600, P(i≥1)=0.600, P(inter≥1)=0.000, P(g≥1)=0.000
- guest_data_hit_rate=0.600
- triple histogram: `{'1/0/0': 12, '0/0/0': 8}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×16
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×12
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×5
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×4
  - `ECall0(zirgen/circuit/rv32im/v2/dsl/inst_ecall.zir:203)` ×4

### arguzz / INSTR_WORD_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.400, P(i≥1)=0.400, P(inter≥1)=0.000, P(g≥1)=0.200
- guest_data_hit_rate=0.600
- triple histogram: `{'0/0/0': 10, '1/0/1': 2, '1/0/0': 6, '0/0/1': 2}`
- top locs:
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×28
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×4
  - `GLOBAL:family:memory residue nonzero` ×4
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×3
  - `loc(callsite( VerifyOpcode ( zirgen/circuit/rv32im/v2/dsl/inst.zir :91:19) at callsite( OpAUIPC ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :214:16) at  Misc2 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :71:30))))` ×1

### arguzz / LOAD_VAL_MOD

- n=20, crash_rate=0.000 (stages: none)
- **fired** 17/20 (85.0%); fired-silent=35.3%
- **fired-conditional:** reached=0.647, P(i≥1)=0.647, P(inter≥1)=0.000, P(g≥1)=0.059
- all-sample (diluted): reached=0.550, P(i≥1)=0.550, P(inter≥1)=0.000, P(g≥1)=0.050
- guest_data_hit_rate=0.750
- triple histogram: `{'0/0/0': 6, '1/0/1': 1, '1/0/0': 10}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×13
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×6
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×2
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :160:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×1
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :161:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×1

### arguzz / POST_EXEC_MEM_MOD

- n=20, crash_rate=0.100 (stages: {'preflight': 2})
- reached=0.900, P(i≥1)=0.900, P(inter≥1)=0.900, P(g≥1)=0.900
- guest_data_hit_rate=0.100
- triple histogram: `{'1/1/1': 18, '0/0/0': 2}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×19
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×18
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×18
  - `GLOBAL:family:memory residue nonzero` ×18
  - `GLOBAL:family:cycle residue nonzero` ×18

### arguzz / POST_EXEC_PC_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.250, P(i≥1)=0.250, P(inter≥1)=0.000, P(g≥1)=0.350
- guest_data_hit_rate=0.100
- triple histogram: `{'0/0/0': 13, '1/0/1': 5, '0/0/1': 2}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×7
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×6
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×2

### arguzz / POST_EXEC_REG_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.950, P(i≥1)=0.950, P(inter≥1)=0.950, P(g≥1)=0.950
- guest_data_hit_rate=0.100
- triple histogram: `{'1/1/1': 19, '0/0/0': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×20
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×20
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×19
  - `GLOBAL:family:memory residue nonzero` ×19
  - `GLOBAL:family:cycle residue nonzero` ×19

### arguzz / PRE_EXEC_MEM_MOD

- n=20, crash_rate=0.050 (stages: {'preflight': 1})
- reached=0.950, P(i≥1)=0.950, P(inter≥1)=0.900, P(g≥1)=0.950
- guest_data_hit_rate=0.100
- triple histogram: `{'1/1/1': 18, '0/0/0': 1, '1/0/1': 1}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×19
  - `GLOBAL:family:cycle residue nonzero` ×19
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×18
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×18
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×17

### arguzz / PRE_EXEC_PC_MOD

- n=20, crash_rate=0.000 (stages: none)
- reached=0.300, P(i≥1)=0.300, P(inter≥1)=0.000, P(g≥1)=0.400
- guest_data_hit_rate=0.100
- triple histogram: `{'0/0/0': 12, '1/0/1': 6, '0/0/1': 2}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×8
  - `GLOBAL:family:memory residue nonzero` ×8
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×2

### arguzz / PRE_EXEC_REG_MOD

- n=20, crash_rate=0.050 (stages: {'preflight': 1})
- reached=0.900, P(i≥1)=0.900, P(inter≥1)=0.900, P(g≥1)=0.900
- guest_data_hit_rate=0.100
- triple histogram: `{'1/1/1': 18, '0/0/0': 2}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×18
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×18
  - `GLOBAL:family:memory residue nonzero` ×18
  - `GLOBAL:family:cycle residue nonzero` ×18
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×17

### arguzz / STORE_OUT_MOD

- n=20, crash_rate=0.000 (stages: none)
- **fired** 20/20 (100.0%); fired-silent=20.0%
- **fired-conditional:** reached=0.800, P(i≥1)=0.800, P(inter≥1)=0.000, P(g≥1)=0.050
- all-sample (diluted): reached=0.800, P(i≥1)=0.800, P(inter≥1)=0.000, P(g≥1)=0.050
- guest_data_hit_rate=0.900
- triple histogram: `{'0/0/0': 4, '1/0/0': 15, '1/0/1': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×16
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×12
  - `GLOBAL:family:memory residue nonzero` ×1

## Stage rollups

- **a4:mem_read**: n=20 fired=20 crash=0.000 {} P(i/inter/g)_fired=(0.95/0.90/1.00)
- **a4:reg**: n=40 fired=40 crash=0.000 {} P(i/inter/g)_fired=(0.05/0.05/0.10)
- **a4:witness_value**: n=60 fired=60 crash=0.000 {} P(i/inter/g)_fired=(0.75/0.00/0.75)
- **a4:word_type**: n=60 fired=60 crash=0.000 {} P(i/inter/g)_fired=(1.00/0.03/0.80)
- **arguzz:in_place**: n=100 fired=89 crash=0.030 {'prove_error': 3} P(i/inter/g)_fired=(0.62/0.00/0.16)
- **arguzz:post**: n=60 fired=60 crash=0.033 {'preflight': 2} P(i/inter/g)_fired=(0.70/0.62/0.73)
- **arguzz:pre**: n=60 fired=60 crash=0.033 {'preflight': 2} P(i/inter/g)_fired=(0.72/0.60/0.75)

## Headline

Distribution study only — no matrix, no paired comparison. Crash stages count only `crashed==true` atoms (preflight vs prove_error); constraint rejects are not crashes.
