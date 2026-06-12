# E1 Arguzz summary (amended)

Host sha256 guard: `5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23` (frozen E0)
Log mtimes unchanged: **True** (no re-proofs)

## Value kinds (constraint-layer column)

| kind | role | seed | mutated | outcome | #intrastep | #interstep | #global | example |
|------|------|------|---------|---------|------------|------------|---------|---------|
| COMP_OUT_MOD | add | 0 | 6 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| COMP_OUT_MOD | add | 1 | 6 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| COMP_OUT_MOD | add | 2 | 0 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| COMP_OUT_MOD | add | 3 | 8 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| COMP_OUT_MOD | add | 4 | 8 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| LOAD_VAL_MOD | load_x | 0 | 2 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| LOAD_VAL_MOD | load_x | 1 | 2 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| LOAD_VAL_MOD | load_x | 2 | 0 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| LOAD_VAL_MOD | load_x | 3 | 4 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| LOAD_VAL_MOD | load_x | 4 | 4 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| STORE_OUT_MOD | store | 0 | 6 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| STORE_OUT_MOD | store | 1 | 6 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| STORE_OUT_MOD | store | 2 | 0 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| STORE_OUT_MOD | store | 3 | 8 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |
| STORE_OUT_MOD | store | 4 | 8 | CONSTRAINT_REJECT | 1 | 0 | 0 | intrastep-local: MemoryWrite(zirgen/circuit/rv32im |

## INSTR_WORD_MOD — by field class (constraint-layer runs only)

Original instruction: `ADD x11, x11, x12` (`0x00c585b3`).

**Key finding:** rd-only (`dest_reg`) AND src-reg-only (`src_reg`) mutations both produce **0 intrastep-local / 0 interstep-local / 1 global** under Arguzz — the executor stays self-consistent; only the global memory permutation catches the wrong register vs the fetched word.

### Per field_class aggregate

| field_class | n | intrastep | interstep | global | PROVE_ERROR | notes |
|-------------|---|-----------|-----------|--------|-------------|-------|
| control_flow | 7 | 0 | 0 | 0 | 7 | PROVE_ERROR |
| dest_reg | 6 | 0 | 0 | 6 | 0 | 0 local, 1 global (memory) |
| dest_reg_a0 | 1 | 1 | 0 | 1 | 0 | cascade: 6 local + 1 global (seed 24) |
| format_change | 4 | 4 | 0 | 2 | 0 | mixed local (+global) |
| operation | 8 | 8 | 0 | 0 | 0 | intrastep-local decode (VerifyOpcodeF3F7) |
| src_reg | 5 | 0 | 0 | 5 | 0 | 0 local, 1 global (memory) |

### INSTR_WORD_MOD per-run detail (excl. PROVE_ERROR layer counts)

| seed | mutated | fields_changed | field_class | outcome | intrastep | interstep | global |
|------|---------|----------------|-------------|---------|-----------|-----------|--------|
| 0 | `0x00c5c5b3` XOR x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 1 | `0xf9681a67` JALR x20, x16, -106 | ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 2 | `0x00c581b3` ADD x3, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 3 | `0x004585b3` ADD x11, x11, x4 | ['rs2'] | src_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 4 | `0x00e585b3` ADD x11, x11, x14 | ['rs2'] | src_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 5 | `0x00c595b3` SLL x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 6 | `0x00c595b3` SLL x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 7 | `0x00c585f3` SYSTEM.0 x11, x11, 12 | ['opcode'] | control_flow | PROVE_ERROR | — | — | — |
| 8 | `0x40c585b3` SUB x11, x11, x12 | ['funct7'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 9 | `0xc622e263` BLTU x5, x2, -2972 | ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 10 | `0x00c58593` ADDI x11, x11, 12 | ['opcode'] | format_change | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 11 | `0x00c581b3` ADD x3, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 12 | `0x008585b3` ADD x11, x11, x8 | ['rs2'] | src_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 13 | `0x00c785b3` ADD x11, x15, x12 | ['rs1'] | src_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 14 | `0x00d585b3` ADD x11, x11, x13 | ['rs2'] | src_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 15 | `0x9a780f93` ADDI x31, x16, -1625 | ['opcode', 'rd', 'rs1', 'rs2', 'funct7'] | format_change | CONSTRAINT_REJECT | 2 | 0 | 1 |
| 16 | `0x20c5c493` XORI x9, x11, 524 | ['opcode', 'rd', 'funct3', 'funct7'] | format_change | CONSTRAINT_REJECT | 3 | 0 | 1 |
| 17 | `0x5335a66f` JAL x12, 372018 | ['opcode', 'rd', 'funct3', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 18 | `0x00c5a5b3` SLT x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 19 | `0x00c5c5b3` XOR x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 20 | `0x00c5c5b3` XOR x11, x11, x12 | ['funct3'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 21 | `0x00c58db3` ADD x27, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 22 | `0x00c585a3` SB x12, 11(x11) | ['opcode'] | format_change | CONSTRAINT_REJECT | 2 | 0 | 0 |
| 23 | `0x00c584b3` ADD x9, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 24 | `0x00c58533` ADD x10, x11, x12 | ['rd'] | dest_reg_a0 | CONSTRAINT_REJECT | 6 | 0 | 1 |
| 25 | `0x3f0bd667` JALR x12, x23, 1008 | ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 26 | `0x00c581b3` ADD x3, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |
| 27 | `0x35fa17e7` JALR x15, x20, 863 | ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 28 | `0x02c585b3` ADD x11, x11, x12 | ['funct7'] | operation | CONSTRAINT_REJECT | 1 | 0 | 0 |
| 29 | `0x7f72226f` JAL x4, 143350 | ['opcode', 'rd', 'funct3', 'rs1', 'rs2', 'funct7'] | control_flow | PROVE_ERROR | — | — | — |
| 30 | `0x00c587b3` ADD x15, x11, x12 | ['rd'] | dest_reg | GLOBAL_REJECT | 0 | 0 | 1 |

## Arguzz control-flow crashes (PROVE_ERROR)

Seeds **1, 7, 9, 17, 25, 27, 29** inject a control-flow/format-changing word; the prover returns `Prover status=error` in ~37 ms, then the host panics at `main.rs:106` with **0** `<constraint_fail>` and the verifier never runs.

Arguzz `INSTR_WORD_MOD` to a control-flow/format-changing word crashes the prover pre-witgen (host panic main.rs:106), analogous to the `PRE_EXEC` preflight crash — upstream of all constraint evaluation and of the A4 hooks.

| seed | decoded instruction | field_class |
|------|---------------------|-------------|
| 1 | `JALR x20, x16, -106` | control_flow |
| 7 | `SYSTEM.0 x11, x11, 12` | control_flow |
| 9 | `BLTU x5, x2, -2972` | control_flow |
| 17 | `JAL x12, 372018` | control_flow |
| 25 | `JALR x12, x23, 1008` | control_flow |
| 27 | `JALR x15, x20, 863` | control_flow |
| 29 | `JAL x4, 143350` | control_flow |
