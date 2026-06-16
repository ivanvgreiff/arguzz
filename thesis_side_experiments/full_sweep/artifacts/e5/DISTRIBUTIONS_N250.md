# E5 constraint distributions

Expected N per type-variant: **250**

Arguzz class-specific kinds (COMP/LOAD/STORE/BR) show **fired-conditional** rates as primary; raw all-sample rates included for comparison.

## Per type-variant

### a4 / COMP_OUT_MOD

- n=250, crash_rate=0.000 (stages: none)
- reached=0.912, P(i≥1)=0.912, P(inter≥1)=0.000, P(g≥1)=0.912
- guest_data_hit_rate=0.912
- triple histogram: `{'0/0/0': 22, '1/0/1': 228}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×228
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×228
  - `GLOBAL:family:memory residue nonzero` ×228

### a4 / INSTR_TYPE_MOD

- n=250, crash_rate=0.000 (stages: none)
- reached=0.996, P(i≥1)=0.996, P(inter≥1)=0.060, P(g≥1)=0.356
- guest_data_hit_rate=0.912
- triple histogram: `{'1/0/0': 160, '1/0/1': 74, '1/1/1': 15, '0/0/0': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×276
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×152
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×113
  - `GLOBAL:family:memory residue nonzero` ×89
  - `AddrDecompose(zirgen/circuit/rv32im/v2/dsl/u32.zir:67)` ×19

### a4 / INSTR_WORD_MOD_FULL

- n=250, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.036, P(g≥1)=1.000
- guest_data_hit_rate=0.912
- triple histogram: `{'1/0/1': 241, '1/1/1': 9}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×250
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×213
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×200
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :97:18) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×174
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×81

### a4 / INSTR_WORD_MOD_SUR / funct3_xor

- n=250, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.000, P(g≥1)=1.000
- guest_data_hit_rate=0.912
- triple histogram: `{'1/0/1': 250}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×250
  - `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :97:18) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` ×200
  - `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` ×17
  - `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpSLLI ( zirgen/circuit/rv32im/v2/dsl/inst_mul.zir :56:20)))` ×9
  - `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpSUB ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :95:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :34:28))))` ×6

### a4 / LOAD_VAL_MOD

- n=250, crash_rate=0.000 (stages: none)
- reached=0.924, P(i≥1)=0.924, P(inter≥1)=0.000, P(g≥1)=0.924
- guest_data_hit_rate=0.932
- triple histogram: `{'0/0/0': 19, '1/0/1': 231}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×231
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×231
  - `GLOBAL:family:memory residue nonzero` ×231

### a4 / MEM_VAL_MOD

- n=250, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=0.972, P(inter≥1)=0.888, P(g≥1)=1.000
- guest_data_hit_rate=0.664
- triple histogram: `{'0/1/1': 7, '1/1/1': 215, '1/0/1': 28}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×250
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×222
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×222
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×222
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×222

### a4 / PRE_EXEC_REG_MOD / next_read

- n=250, crash_rate=0.000 (stages: none)
- reached=0.884, P(i≥1)=0.476, P(inter≥1)=0.884, P(g≥1)=0.800
- guest_data_hit_rate=0.868
- triple histogram: `{'0/0/0': 29, '0/1/1': 81, '1/1/1': 119, '0/1/0': 21}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×221
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×221
  - `GLOBAL:family:memory residue nonzero` ×200
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×93
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×81

### a4 / PRE_EXEC_REG_MOD / prev_write

- n=250, crash_rate=0.000 (stages: none)
- reached=0.552, P(i≥1)=0.552, P(inter≥1)=0.000, P(g≥1)=0.552
- guest_data_hit_rate=0.868
- triple histogram: `{'0/0/0': 112, '1/0/1': 138}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×138
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×138
  - `GLOBAL:family:memory residue nonzero` ×138

### a4 / STORE_OUT_MOD

- n=250, crash_rate=0.000 (stages: none)
- reached=1.000, P(i≥1)=1.000, P(inter≥1)=0.000, P(g≥1)=1.000
- guest_data_hit_rate=0.992
- triple histogram: `{'1/0/1': 250}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×250
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×250
  - `GLOBAL:family:memory residue nonzero` ×250

### arguzz / BR_NEG_COND

- n=250, crash_rate=0.004 (stages: {'prove_error': 1})
- **fired** 72/250 (28.8%); fired-silent=12.5%
- **fired-conditional:** reached=0.861, P(i≥1)=0.861, P(inter≥1)=0.000, P(g≥1)=0.861
- all-sample (diluted): reached=0.248, P(i≥1)=0.248, P(inter≥1)=0.000, P(g≥1)=0.248
- guest_data_hit_rate=0.932
- triple histogram: `{'0/0/0': 10, '1/0/1': 62}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×66
  - `GLOBAL:family:memory residue nonzero` ×62

### arguzz / COMP_OUT_MOD

- n=250, crash_rate=0.024 (stages: {'prove_error': 6})
- **fired** 150/250 (60.0%); fired-silent=14.7%
- **fired-conditional:** reached=0.813, P(i≥1)=0.813, P(inter≥1)=0.000, P(g≥1)=0.007
- all-sample (diluted): reached=0.488, P(i≥1)=0.488, P(inter≥1)=0.000, P(g≥1)=0.004
- guest_data_hit_rate=0.912
- triple histogram: `{'1/0/0': 121, '0/0/0': 28, '1/0/1': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×127
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×80
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×28
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×10
  - `ECall0(zirgen/circuit/rv32im/v2/dsl/inst_ecall.zir:203)` ×4

### arguzz / INSTR_WORD_MOD

- n=250, crash_rate=0.012 (stages: {'prove_error': 3})
- reached=0.360, P(i≥1)=0.360, P(inter≥1)=0.012, P(g≥1)=0.500
- guest_data_hit_rate=0.912
- triple histogram: `{'0/0/0': 91, '1/0/1': 53, '1/0/0': 34, '0/0/1': 69, '1/1/1': 3}`
- top locs:
  - `GLOBAL:family:memory residue nonzero` ×125
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×42
  - `DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)` ×32
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×28
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×19

### arguzz / LOAD_VAL_MOD

- n=250, crash_rate=0.000 (stages: none)
- **fired** 49/250 (19.6%); fired-silent=49.0%
- **fired-conditional:** reached=0.510, P(i≥1)=0.510, P(inter≥1)=0.000, P(g≥1)=0.020
- all-sample (diluted): reached=0.100, P(i≥1)=0.100, P(inter≥1)=0.000, P(g≥1)=0.004
- guest_data_hit_rate=0.932
- triple histogram: `{'0/0/0': 24, '1/0/1': 1, '1/0/0': 24}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×27
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×15
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :160:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×3
  - `loc(callsite( OpLW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :108:20) at  Mem0 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :55:10)))` ×3
  - `loc(callsite( OpLW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :109:20) at  Mem0 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :55:10)))` ×3

### arguzz / POST_EXEC_MEM_MOD

- n=250, crash_rate=0.060 (stages: {'preflight': 15})
- reached=0.940, P(i≥1)=0.856, P(inter≥1)=0.932, P(g≥1)=0.852
- guest_data_hit_rate=0.868
- triple histogram: `{'1/1/1': 211, '0/0/0': 15, '0/1/0': 21, '1/1/0': 1, '1/0/1': 2}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×233
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×221
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×214
  - `GLOBAL:family:memory residue nonzero` ×213
  - `GLOBAL:family:cycle residue nonzero` ×213

### arguzz / POST_EXEC_PC_MOD

- n=250, crash_rate=0.020 (stages: {'prove_error': 5})
- reached=0.432, P(i≥1)=0.432, P(inter≥1)=0.000, P(g≥1)=0.452
- guest_data_hit_rate=0.868
- triple histogram: `{'0/0/0': 136, '1/0/1': 107, '0/0/1': 6, '1/0/0': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×177
  - `GLOBAL:family:memory residue nonzero` ×113
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×11
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :160:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×4
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :161:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×1

### arguzz / POST_EXEC_REG_MOD

- n=250, crash_rate=0.068 (stages: {'preflight': 15, 'prove_error': 2})
- reached=0.908, P(i≥1)=0.840, P(inter≥1)=0.908, P(g≥1)=0.828
- guest_data_hit_rate=0.868
- triple histogram: `{'1/1/1': 207, '0/0/0': 23, '0/1/0': 17, '1/1/0': 3}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×224
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×216
  - `GLOBAL:family:memory residue nonzero` ×207
  - `GLOBAL:family:cycle residue nonzero` ×207
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×206

### arguzz / PRE_EXEC_MEM_MOD

- n=250, crash_rate=0.072 (stages: {'preflight': 18})
- reached=0.928, P(i≥1)=0.868, P(inter≥1)=0.920, P(g≥1)=0.860
- guest_data_hit_rate=0.868
- triple histogram: `{'1/1/1': 213, '0/0/0': 18, '1/0/1': 2, '1/1/0': 2, '0/1/0': 15}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×230
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×215
  - `GLOBAL:family:memory residue nonzero` ×215
  - `GLOBAL:family:cycle residue nonzero` ×215
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×208

### arguzz / PRE_EXEC_PC_MOD

- n=250, crash_rate=0.020 (stages: {'prove_error': 5})
- reached=0.532, P(i≥1)=0.532, P(inter≥1)=0.000, P(g≥1)=0.552
- guest_data_hit_rate=0.868
- triple histogram: `{'0/0/0': 111, '1/0/1': 132, '0/0/1': 6, '1/0/0': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×216
  - `GLOBAL:family:memory residue nonzero` ×138
  - `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` ×11
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :160:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×5
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :161:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×1

### arguzz / PRE_EXEC_REG_MOD

- n=250, crash_rate=0.052 (stages: {'preflight': 11, 'prove_error': 2})
- reached=0.928, P(i≥1)=0.868, P(inter≥1)=0.928, P(g≥1)=0.852
- guest_data_hit_rate=0.868
- triple histogram: `{'1/1/1': 213, '0/0/0': 18, '1/1/0': 4, '0/1/0': 15}`
- top locs:
  - `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` ×229
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×219
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×213
  - `GLOBAL:family:memory residue nonzero` ×213
  - `GLOBAL:family:cycle residue nonzero` ×213

### arguzz / STORE_OUT_MOD

- n=250, crash_rate=0.004 (stages: {'prove_error': 1})
- **fired** 99/250 (39.6%); fired-silent=12.1%
- **fired-conditional:** reached=0.869, P(i≥1)=0.869, P(inter≥1)=0.000, P(g≥1)=0.010
- all-sample (diluted): reached=0.344, P(i≥1)=0.344, P(inter≥1)=0.000, P(g≥1)=0.004
- guest_data_hit_rate=0.992
- triple histogram: `{'0/0/0': 13, '1/0/0': 85, '1/0/1': 1}`
- top locs:
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` ×86
  - `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` ×62
  - `GLOBAL:family:memory residue nonzero` ×1
  - `loc(callsite( OpLW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :109:20) at  Mem0 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :55:10)))` ×1
  - `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :161:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` ×1

## Stage rollups

- **a4:mem_read**: n=250 fired=250 crash=0.000 {} P(i/inter/g)_fired=(0.97/0.89/1.00)
- **a4:reg**: n=500 fired=500 crash=0.000 {} P(i/inter/g)_fired=(0.51/0.44/0.68)
- **a4:witness_value**: n=750 fired=750 crash=0.000 {} P(i/inter/g)_fired=(0.95/0.00/0.95)
- **a4:word_type**: n=750 fired=750 crash=0.000 {} P(i/inter/g)_fired=(1.00/0.03/0.79)
- **arguzz:in_place**: n=1250 fired=620 crash=0.009 {'prove_error': 11} P(i/inter/g)_fired=(0.62/0.00/0.31)
- **arguzz:post**: n=750 fired=750 crash=0.049 {'preflight': 30, 'prove_error': 7} P(i/inter/g)_fired=(0.71/0.61/0.71)
- **arguzz:pre**: n=750 fired=750 crash=0.048 {'preflight': 29, 'prove_error': 7} P(i/inter/g)_fired=(0.76/0.62/0.75)

## Headline

Distribution study only — no matrix, no paired comparison. Crash stages count only `crashed==true` atoms (preflight vs prove_error); constraint rejects are not crashes.
