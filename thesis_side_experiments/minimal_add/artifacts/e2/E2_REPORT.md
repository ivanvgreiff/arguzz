# E2-FULL Report — A4 characterization on polynize

**Status:** PASS

## Dispatch
- Node: **polynize** / **debian-trixie** / `--allocation-duration 0`
- Host sha: `5337f9448d7946c5…` (frozen, no rebuild)
- Runs: 53 (Part A=39, B=6, C=8)

## Part A — A4 FULL mirrors (value-kind bias)
- **gate_pass:** True
- Value kinds Arguzz **1/0/0** vs A4-FULL **1/0/1**: True / True
- A4 FULL rows: 39/39

### Value-kind sample

| role/kind/seed | Arguzz i/inter/g | A4-FULL i/inter/g |
|--------------|------------------|-------------------|
| load_x/LOAD_VAL_MOD/s0 | 1/0/0 | 1/0/1 |
| add/COMP_OUT_MOD/s0 | 1/0/0 | 1/0/1 |
| store/STORE_OUT_MOD/s0 | 1/0/0 | 1/0/1 |

## Part B — INSTR_WORD_MOD_SUR (single-field at add)
- **gate_pass:** True
- **rd vs src asymmetry:** denied
- Evidence: rd=0/0/1, rs1=0/0/1, rs2=0/0/1: all register-field SUR variants are global-only (0/0/1), matching Arguzz dest/src_reg FULL mirrors. Operation SUR (funct3/funct7) adds intrastep decode (1/0/1).

| field | layers i/inter/g | outcome | example constraint |
|-------|------------------|---------|-------------------|
| funct3_xor | 1/0/1 | CONSTRAINT_REJECT | `intrastep-local: loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32i…` |
| funct3_slt | 1/0/1 | CONSTRAINT_REJECT | `intrastep-local: loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32i…` |
| funct7_sub | 1/0/1 | CONSTRAINT_REJECT | `intrastep-local: loc(callsite( VerifyOpcodeF3F7 ( zirgen/circuit/rv32i…` |
| rd | 0/0/1 | GLOBAL_REJECT | `—…` |
| rs1 | 0/0/1 | GLOBAL_REJECT | `—…` |
| rs2 | 0/0/1 | GLOBAL_REJECT | `—…` |

## Part C — MEM_VAL_MOD (A4-only interstep layer)
- **gate_pass:** True
- **interstep-local populated:** True
- **Arguzz mirror:** n/a — Arguzz has no in-place memory-read mutation; LOAD_VAL_MOD edits register side only

| role/txn/seed | A4-MEM_VAL i/inter/g | IsRead/MemoryRead |
|---------------|----------------------|-------------------|
| load_x/load_mem_read/s0 | 2/2/1 | yes |
| load_x/load_mem_read/s1 | 2/2/1 | yes |
| load_y/load_mem_read/s0 | 2/2/1 | yes |
| load_y/load_mem_read/s1 | 2/2/1 | yes |
| read_back/load_mem_read/s0 | 2/2/1 | yes |
| read_back/load_mem_read/s1 | 2/2/1 | yes |
| store/store_rmw_read/s0 | 0/2/1 | yes |
| store/store_rmw_read/s1 | 0/2/1 | yes |

## Combined matrix (Arguzz vs A4-FULL vs A4-SUR vs A4-MEM_VAL)

Format: intrastep/interstep/global. MEM_VAL Arguzz column = n/a.

| key | field_class | Arguzz | A4-FULL | A4-SUR | A4-MEM_VAL |
|-----|-------------|--------|---------|--------|------------|
| load_x/LOAD_VAL_MOD/s0 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| load_x/LOAD_VAL_MOD/s1 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| load_x/LOAD_VAL_MOD/s2 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| load_x/LOAD_VAL_MOD/s3 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| load_x/LOAD_VAL_MOD/s4 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/COMP_OUT_MOD/s0 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/COMP_OUT_MOD/s1 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/COMP_OUT_MOD/s2 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/COMP_OUT_MOD/s3 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/COMP_OUT_MOD/s4 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| store/STORE_OUT_MOD/s0 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| store/STORE_OUT_MOD/s1 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| store/STORE_OUT_MOD/s2 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| store/STORE_OUT_MOD/s3 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| store/STORE_OUT_MOD/s4 | None | 1/0/0 | 1/0/1 | n/a | n/a |
| add/INSTR_WORD_MOD/s0 | operation | 1/0/0 | 1/0/1 | n/a | n/a |
| add/INSTR_WORD_MOD/s2 | dest_reg | 0/0/1 | 0/0/1 | n/a | n/a |
| add/INSTR_WORD_MOD/s3 | src_reg | 0/0/1 | 0/0/1 | n/a | n/a |
| add/INSTR_WORD_MOD/s4 | src_reg | 0/0/1 | 0/0/1 | n/a | n/a |
| add/INSTR_WORD_MOD/s5 | operation | 1/0/0 | 1/0/1 | n/a | n/a |
| … | (47 total rows in JSON) | | | | |

**Overall gate passed:** True
