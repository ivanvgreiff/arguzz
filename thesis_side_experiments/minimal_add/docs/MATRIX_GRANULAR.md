# E4 Granular Matrix — Arguzz × A4

Generated: 2026-06-13T04:52:30.271807+00:00

## Row counts

- Arguzz E1: **46** (incl. **7** PROVE_ERROR)
- A4 E2: **53** (FULL **39** + SUR **6** + MEM_VAL **8**)
- Matrix total: **99** (match expected: **True**)

## Verified findings (asserted)

- **Arguzz register (dest+src) = 0/0/1, failure_count=0**: PASS — s2=0/0/1 fc=0; s3=0/0/1 fc=0; s4=0/0/1 fc=0; s11=0/0/1 fc=0; s12=0/0/1 fc=0; s13=0/0/1 fc=0; s14=0/0/1 fc=0; s21=0/0/1 fc=0; s23=0/0/1 fc=0; s26=0/0/1 fc=0; s30=0/0/1 fc=0
- **Value kinds: Arguzz 1/0/0 vs A4-FULL 1/0/1**: PASS — LOAD_VAL_MOD/s0: 1/0/0 vs 1/0/1; LOAD_VAL_MOD/s1: 1/0/0 vs 1/0/1; LOAD_VAL_MOD/s2: 1/0/0 vs 1/0/1; LOAD_VAL_MOD/s3: 1/0/0 vs 1/0/1; LOAD_VAL_MOD/s4: 1/0/0 vs 1/0/1; COMP_OUT_MOD/s0: 1/0/0 vs 1/0/1 …
- **A4-SUR: rd/rs1/rs2 0/0/1; funct3/funct7 1/0/1**: PASS — rd=0/0/1; rs1=0/0/1; rs2=0/0/1; funct3_xor=1/0/1; funct3_slt=1/0/1; funct7_sub=1/0/1
- **A4 MEM_VAL interstep via IsRead@mem.zir**: PASS — load*/read_back=2/2/1; store=0/2/1; IsRead@mem.zir:79/80 in interstep

**All findings pass:** True

## Master matrix (i/inter/g per variant)

Grouped by semantic target. `—` = variant N/A for this row.

| target | Arguzz | A4-FULL | A4-SUR | A4-MEM_VAL |
|--------|--------|---------|--------|------------|
| add/COMP_OUT_MOD/s0 | 1/0/0 | 1/0/1 | — | — |
| add/COMP_OUT_MOD/s1 | 1/0/0 | 1/0/1 | — | — |
| add/COMP_OUT_MOD/s2 | 1/0/0 | 1/0/1 | — | — |
| add/COMP_OUT_MOD/s3 | 1/0/0 | 1/0/1 | — | — |
| add/COMP_OUT_MOD/s4 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s0 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s1 | — | — | — | — |
| add/INSTR_WORD_MOD/s10 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s11 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s12 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s13 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s14 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s15 | 2/0/1 | 2/0/1 | — | — |
| add/INSTR_WORD_MOD/s16 | 3/0/1 | 3/0/1 | — | — |
| add/INSTR_WORD_MOD/s17 | — | — | — | — |
| add/INSTR_WORD_MOD/s18 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s19 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s2 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s20 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s21 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s22 | 2/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s23 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s24 | 6/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s25 | — | — | — | — |
| add/INSTR_WORD_MOD/s26 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s27 | — | — | — | — |
| add/INSTR_WORD_MOD/s28 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s29 | — | — | — | — |
| add/INSTR_WORD_MOD/s3 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s30 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s4 | 0/0/1 | 0/0/1 | — | — |
| add/INSTR_WORD_MOD/s5 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s6 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s7 | — | — | — | — |
| add/INSTR_WORD_MOD/s8 | 1/0/0 | 1/0/1 | — | — |
| add/INSTR_WORD_MOD/s9 | — | — | — | — |
| load_x/LOAD_VAL_MOD/s0 | 1/0/0 | 1/0/1 | — | — |
| load_x/LOAD_VAL_MOD/s1 | 1/0/0 | 1/0/1 | — | — |
| load_x/LOAD_VAL_MOD/s2 | 1/0/0 | 1/0/1 | — | — |
| load_x/LOAD_VAL_MOD/s3 | 1/0/0 | 1/0/1 | — | — |
| load_x/LOAD_VAL_MOD/s4 | 1/0/0 | 1/0/1 | — | — |
| store/STORE_OUT_MOD/s0 | 1/0/0 | 1/0/1 | — | — |
| store/STORE_OUT_MOD/s1 | 1/0/0 | 1/0/1 | — | — |
| store/STORE_OUT_MOD/s2 | 1/0/0 | 1/0/1 | — | — |
| store/STORE_OUT_MOD/s3 | 1/0/0 | 1/0/1 | — | — |
| store/STORE_OUT_MOD/s4 | 1/0/0 | 1/0/1 | — | — |
| add/SUR/funct3_xor | — | — | 1/0/1 | — |
| add/SUR/funct3_slt | — | — | 1/0/1 | — |
| add/SUR/funct7_sub | — | — | 1/0/1 | — |
| add/SUR/rd | — | — | 0/0/1 | — |
| add/SUR/rs1 | — | — | 0/0/1 | — |
| add/SUR/rs2 | — | — | 0/0/1 | — |
| load_x/MEM_VAL/s0 | n/a | n/a | n/a | 2/2/1 |
| load_x/MEM_VAL/s1 | n/a | n/a | n/a | 2/2/1 |
| load_y/MEM_VAL/s0 | n/a | n/a | n/a | 2/2/1 |
| load_y/MEM_VAL/s1 | n/a | n/a | n/a | 2/2/1 |
| read_back/MEM_VAL/s0 | n/a | n/a | n/a | 2/2/1 |
| read_back/MEM_VAL/s1 | n/a | n/a | n/a | 2/2/1 |
| store/MEM_VAL/s0 | n/a | n/a | n/a | 0/2/1 |
| store/MEM_VAL/s1 | n/a | n/a | n/a | 0/2/1 |

## Per-field-class rollup

| field_class | n | sample layers |
|-------------|---|---------------|
| operation | 16 | 1/0/0, 1/0/1 |
| dest_reg | 12 | 0/0/1 |
| COMP_OUT_MOD | 10 | 1/0/0, 1/0/1 |
| src_reg | 10 | 0/0/1 |
| LOAD_VAL_MOD | 10 | 1/0/0, 1/0/1 |
| STORE_OUT_MOD | 10 | 1/0/0, 1/0/1 |
| format_change | 8 | 1/0/0, 1/0/1, 2/0/0, 2/0/1 |
| MEM_VAL_MOD | 8 | 0/2/1, 2/2/1 |
| control_flow | 7 | — |
| dest_reg_a0 | 2 | 0/0/1, 6/0/1 |
| funct3_slt | 1 | 1/0/1 |
| funct3_xor | 1 | 1/0/1 |
| funct7_sub | 1 | 1/0/1 |
| rd | 1 | 0/0/1 |
| rs1 | 1 | 0/0/1 |
| rs2 | 1 | 0/0/1 |

## Layer rollup

- Runs with interstep-local > 0: **8**
- IDs: `a4_memval_load_x_s0, a4_memval_load_x_s1, a4_memval_load_y_s0, a4_memval_load_y_s1, a4_memval_read_back_s0, a4_memval_read_back_s1, a4_memval_store_s0, a4_memval_store_s1`

## Per-run granular detail

### `a4_full_COMP_OUT_MOD_s0`
- **a4** variant=FULL COMP_OUT_MOD @add seed=0
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_COMP_OUT_MOD_s1`
- **a4** variant=FULL COMP_OUT_MOD @add seed=1
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_COMP_OUT_MOD_s2`
- **a4** variant=FULL COMP_OUT_MOD @add seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265914 provenance: (mutated - original) mod p pred=2013265914 obs=2013265914
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_COMP_OUT_MOD_s3`
- **a4** variant=FULL COMP_OUT_MOD @add seed=3
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_COMP_OUT_MOD_s4`
- **a4** variant=FULL COMP_OUT_MOD @add seed=4
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s0`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=0
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=4 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s10`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=10
- mutated: `0x00c58593` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `ADDI x11, x11, 12` (OP-IMM)
- fields_changed: ['opcode'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :102:19) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2013265889 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s11`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=11
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s12`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=12
- mutated: `0x008585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x8` (OP)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s13`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=13
- mutated: `0x00c785b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x15, x12` (OP)
- fields_changed: ['rs1'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s14`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=14
- mutated: `0x00d585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x13` (OP)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s15`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=15
- mutated: `0x9a780f93` | outcome: **CONSTRAINT_REJECT**
- layers: **2/0/1** (failure_count=2)
- decoded: `ADDI x31, x16, -1625` (OP-IMM)
- fields_changed: ['opcode', 'rd', 'rs1', 'rs2', 'funct7'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :102:19) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2013265889 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=77 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s16`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=16
- mutated: `0x20c5c493` | outcome: **CONSTRAINT_REJECT**
- layers: **3/0/1** (failure_count=3)
- decoded: `XORI x9, x11, 524` (OP-IMM)
- fields_changed: ['opcode', 'rd', 'funct3', 'funct7'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :102:19) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2013265889 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=4 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=16 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s18`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=18
- mutated: `0x00c5a5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SLT x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s19`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=19
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=4 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s2`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=2
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s20`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=20
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=4 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s21`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=21
- mutated: `0x00c58db3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x27, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s22`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=22
- mutated: `0x00c585a3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SB x12, 11(x11)` (STORE)
- fields_changed: ['opcode'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :102:19) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2013265905 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s23`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=23
- mutated: `0x00c584b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x9, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s24`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=24
- mutated: `0x00c58533` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x10, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg_a0
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s26`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=26
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s28`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=28
- mutated: `0x02c585b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `ADD x11, x11, x12` (OP)
- fields_changed: ['funct7'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=1 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s3`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=3
- mutated: `0x004585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x4` (OP)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s30`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=30
- mutated: `0x00c587b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x15, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s4`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=4
- mutated: `0x00e585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x14` (OP)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_full_INSTR_WORD_MOD_s5`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=5
- mutated: `0x00c595b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SLL x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=1 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s6`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=6
- mutated: `0x00c595b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SLL x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=1 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_INSTR_WORD_MOD_s8`
- **a4** variant=FULL INSTR_WORD_MOD @add seed=8
- mutated: `0x40c585b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SUB x11, x11, x12` (OP)
- fields_changed: ['funct7'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=32 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_LOAD_VAL_MOD_s0`
- **a4** variant=FULL LOAD_VAL_MOD @load_x seed=0
- mutated: `2` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_LOAD_VAL_MOD_s1`
- **a4** variant=FULL LOAD_VAL_MOD @load_x seed=1
- mutated: `2` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_LOAD_VAL_MOD_s2`
- **a4** variant=FULL LOAD_VAL_MOD @load_x seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265918 provenance: (mutated - original) mod p pred=2013265918 obs=2013265918
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_LOAD_VAL_MOD_s3`
- **a4** variant=FULL LOAD_VAL_MOD @load_x seed=3
- mutated: `4` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_LOAD_VAL_MOD_s4`
- **a4** variant=FULL LOAD_VAL_MOD @load_x seed=4
- mutated: `4` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_STORE_OUT_MOD_s0`
- **a4** variant=FULL STORE_OUT_MOD @store seed=0
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_STORE_OUT_MOD_s1`
- **a4** variant=FULL STORE_OUT_MOD @store seed=1
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_STORE_OUT_MOD_s2`
- **a4** variant=FULL STORE_OUT_MOD @store seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265914 provenance: (mutated - original) mod p pred=2013265914 obs=2013265914
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_STORE_OUT_MOD_s3`
- **a4** variant=FULL STORE_OUT_MOD @store seed=3
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_full_STORE_OUT_MOD_s4`
- **a4** variant=FULL STORE_OUT_MOD @store seed=4
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_load_x_s0`
- **a4** variant=MEM_VAL MEM_VAL_MOD @load_x seed=0
- mutated: `2654435764` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013234768
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013225418
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013234768
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013225418
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_load_x_s1`
- **a4** variant=MEM_VAL MEM_VAL_MOD @load_x seed=1
- mutated: `1013904229` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013203615
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013250451
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013203615
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013250451
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_load_y_s0`
- **a4** variant=MEM_VAL MEM_VAL_MOD @load_y seed=0
- mutated: `2654435765` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013234768
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013225418
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013234768
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013225418
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_load_y_s1`
- **a4** variant=MEM_VAL MEM_VAL_MOD @load_y seed=1
- mutated: `1013904230` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013203615
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013250451
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013203615
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013250451
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_read_back_s0`
- **a4** variant=MEM_VAL MEM_VAL_MOD @read_back seed=0
- mutated: `2654435768` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013234768
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013225418
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013234768
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013225418
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_read_back_s1`
- **a4** variant=MEM_VAL MEM_VAL_MOD @read_back seed=1
- mutated: `1013904233` | outcome: **CONSTRAINT_REJECT**
- layers: **2/2/1** (failure_count=4)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013203615
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:100)` residue=2013250451
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013203615
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013250451
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_store_s0`
- **a4** variant=MEM_VAL MEM_VAL_MOD @store seed=0
- mutated: `2654435761` | outcome: **CONSTRAINT_REJECT**
- layers: **0/2/1** (failure_count=2)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013234768
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013225418
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_memval_store_s1`
- **a4** variant=MEM_VAL MEM_VAL_MOD @store seed=1
- mutated: `1013904226` | outcome: **CONSTRAINT_REJECT**
- layers: **0/2/1** (failure_count=2)
- arguzz_mirror: n/a — no in-place memory-read mutation
- constraints:
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013203615
  - [interstep-local] `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :80:23) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` residue=2013250451
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_sur_funct3_slt`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x00c5a5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SLT x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: funct3_slt
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=2 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_sur_funct3_xor`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- fields_changed: ['funct3'] | field_class: funct3_xor
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=4 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_sur_funct7_sub`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x40c585b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/1** (failure_count=1)
- decoded: `SUB x11, x11, x12` (OP)
- fields_changed: ['funct7'] | field_class: funct7_sub
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpADD ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :90:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :33:28))))` residue=32 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `a4_sur_rd`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x00c58533` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x10, x11, x12` (OP)
- fields_changed: ['rd'] | field_class: rd
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_sur_rs1`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x00c505b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x10, x12` (OP)
- fields_changed: ['rs1'] | field_class: rs1
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `a4_sur_rs2`
- **a4** variant=SUR INSTR_WORD_MOD_SUR @add seed=0
- mutated: `0x00a585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x10` (OP)
- fields_changed: ['rs2'] | field_class: rs2
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_COMP_OUT_MOD_s0`
- **arguzz** variant=— COMP_OUT_MOD @add seed=0
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_COMP_OUT_MOD_s1`
- **arguzz** variant=— COMP_OUT_MOD @add seed=1
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_COMP_OUT_MOD_s2`
- **arguzz** variant=— COMP_OUT_MOD @add seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265914 provenance: (mutated - original) mod p pred=2013265914 obs=2013265914

### `arguzz_COMP_OUT_MOD_s3`
- **arguzz** variant=— COMP_OUT_MOD @add seed=3
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1

### `arguzz_COMP_OUT_MOD_s4`
- **arguzz** variant=— COMP_OUT_MOD @add seed=4
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1

### `arguzz_INSTR_WORD_MOD_s0`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=0
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpXOR ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :100:20)))` residue=2013265917 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s1`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=1
- mutated: `0xf9681a67` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `JALR x20, x16, -106` (JALR)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s10`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=10
- mutated: `0x00c58593` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `ADDI x11, x11, 12` (OP-IMM)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` residue=32 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s11`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=11
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s12`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=12
- mutated: `0x008585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x8` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s13`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=13
- mutated: `0x00c785b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x15, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rs1'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s14`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=14
- mutated: `0x00d585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x13` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s15`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=15
- mutated: `0x9a780f93` | outcome: **CONSTRAINT_REJECT**
- layers: **2/0/1** (failure_count=2)
- decoded: `ADDI x31, x16, -1625` (OP-IMM)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'rs1', 'rs2', 'funct7'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at callsite( OpADDI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :127:18) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :40:29))))` residue=32 provenance: non-scalar mutation
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013264284 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `arguzz_INSTR_WORD_MOD_s16`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=16
- mutated: `0x20c5c493` | outcome: **CONSTRAINT_REJECT**
- layers: **3/0/1** (failure_count=3)
- decoded: `XORI x9, x11, 524` (OP-IMM)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'funct7'] | field_class: format_change
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at  OpXORI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :132:18)))` residue=32 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :97:18) at  OpXORI ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :132:18)))` residue=2013265917 provenance: non-scalar mutation
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=512 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `arguzz_INSTR_WORD_MOD_s17`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=17
- mutated: `0x5335a66f` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `JAL x12, 372018` (JAL)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s18`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=18
- mutated: `0x00c5a5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `SLT x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpSLT ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :115:20)))` residue=2013265919 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s19`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=19
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpXOR ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :100:20)))` residue=2013265917 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s2`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=2
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s20`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=20
- mutated: `0x00c5c5b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `XOR x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpXOR ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :100:20)))` residue=2013265917 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s21`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=21
- mutated: `0x00c58db3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x27, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s22`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=22
- mutated: `0x00c585a3` | outcome: **CONSTRAINT_REJECT**
- layers: **2/0/0** (failure_count=2)
- decoded: `SB x12, 11(x11)` (STORE)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode'] | field_class: format_change
- constraints:
  - [intrastep-local] `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :96:19) at  OpSB ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :129:18)))` residue=16 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s23`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=23
- mutated: `0x00c584b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x9, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s24`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=24
- mutated: `0x00c58533` | outcome: **CONSTRAINT_REJECT**
- layers: **6/0/1** (failure_count=6)
- decoded: `ADD x10, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg_a0
- constraints:
  - [intrastep-local] `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :160:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( OpSW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :161:20) at  Mem1 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :73:10)))` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `AddrDecomposeBits(zirgen/circuit/rv32im/v2/dsl/u32.zir:87)` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( OpLW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :108:20) at  Mem0 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :55:10)))` residue=1 provenance: non-scalar mutation
  - [intrastep-local] `loc(callsite( OpLW ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :109:20) at  Mem0 ( zirgen/circuit/rv32im/v2/dsl/inst_mem.zir :55:10)))` residue=1 provenance: non-scalar mutation
  - [global] `GLOBAL:family:memory residue nonzero` residue=None

### `arguzz_INSTR_WORD_MOD_s25`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=25
- mutated: `0x3f0bd667` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `JALR x12, x23, 1008` (JALR)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s26`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=26
- mutated: `0x00c581b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x3, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s27`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=27
- mutated: `0x35fa17e7` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `JALR x15, x20, 863` (JALR)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s28`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=28
- mutated: `0x02c585b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `ADD x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct7'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at  OpMUL ( zirgen/circuit/rv32im/v2/dsl/inst_mul.zir :63:20)))` residue=2013265920 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s29`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=29
- mutated: `0x7f72226f` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `JAL x4, 143350` (JAL)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s3`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=3
- mutated: `0x004585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x4` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s30`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=30
- mutated: `0x00c587b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x15, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rd'] | field_class: dest_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s4`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=4
- mutated: `0x00e585b3` | outcome: **GLOBAL_REJECT**
- layers: **0/0/1** (failure_count=0)
- decoded: `ADD x11, x11, x14` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['rs2'] | field_class: src_reg
- constraints:
  - local constraints broken: NONE (failure_count=0); global memory residue: nonzero

### `arguzz_INSTR_WORD_MOD_s5`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=5
- mutated: `0x00c595b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `SLL x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpSLL ( zirgen/circuit/rv32im/v2/dsl/inst_mul.zir :49:20)))` residue=2013265920 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s6`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=6
- mutated: `0x00c595b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `SLL x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct3'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :103:18) at  OpSLL ( zirgen/circuit/rv32im/v2/dsl/inst_mul.zir :49:20)))` residue=2013265920 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s7`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=7
- mutated: `0x00c585f3` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `SYSTEM.0 x11, x11, 12` (SYSTEM)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_INSTR_WORD_MOD_s8`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=8
- mutated: `0x40c585b3` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- decoded: `SUB x11, x11, x12` (OP)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['funct7'] | field_class: operation
- constraints:
  - [intrastep-local] `loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32im/v2/dsl/inst.zir :104:18) at callsite( OpSUB ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :95:20) at  Misc0 ( zirgen/circuit/rv32im/v2/dsl/inst_misc.zir :34:28))))` residue=2013265889 provenance: non-scalar mutation

### `arguzz_INSTR_WORD_MOD_s9`
- **arguzz** variant=— INSTR_WORD_MOD @add seed=9
- mutated: `0xc622e263` | outcome: **PROVE_ERROR**
- layers: **—** (failure_count=0)
- decoded: `BLTU x5, x2, -2972` (BRANCH)
- original: `ADD x11, x11, x12` (0x00c585b3)
- fields_changed: ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | field_class: control_flow
- crash: Prover status=error @~37ms; host panic main.rs:106; verifier never ran
- constraints:
  - PROVE_ERROR: Prover status=error @~37ms; host panic main.rs:106; verifier never ran

### `arguzz_LOAD_VAL_MOD_s0`
- **arguzz** variant=— LOAD_VAL_MOD @load_x seed=0
- mutated: `2` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_LOAD_VAL_MOD_s1`
- **arguzz** variant=— LOAD_VAL_MOD @load_x seed=1
- mutated: `2` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_LOAD_VAL_MOD_s2`
- **arguzz** variant=— LOAD_VAL_MOD @load_x seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265918 provenance: (mutated - original) mod p pred=2013265918 obs=2013265918

### `arguzz_LOAD_VAL_MOD_s3`
- **arguzz** variant=— LOAD_VAL_MOD @load_x seed=3
- mutated: `4` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1

### `arguzz_LOAD_VAL_MOD_s4`
- **arguzz** variant=— LOAD_VAL_MOD @load_x seed=4
- mutated: `4` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1

### `arguzz_STORE_OUT_MOD_s0`
- **arguzz** variant=— STORE_OUT_MOD @store seed=0
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_STORE_OUT_MOD_s1`
- **arguzz** variant=— STORE_OUT_MOD @store seed=1
- mutated: `6` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265920 provenance: (mutated - original) mod p pred=2013265920 obs=2013265920

### `arguzz_STORE_OUT_MOD_s2`
- **arguzz** variant=— STORE_OUT_MOD @store seed=2
- mutated: `0` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=2013265914 provenance: (mutated - original) mod p pred=2013265914 obs=2013265914

### `arguzz_STORE_OUT_MOD_s3`
- **arguzz** variant=— STORE_OUT_MOD @store seed=3
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1

### `arguzz_STORE_OUT_MOD_s4`
- **arguzz** variant=— STORE_OUT_MOD @store seed=4
- mutated: `8` | outcome: **CONSTRAINT_REJECT**
- layers: **1/0/0** (failure_count=1)
- constraints:
  - [intrastep-local] `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` residue=1 provenance: (mutated - original) mod p pred=1 obs=1
