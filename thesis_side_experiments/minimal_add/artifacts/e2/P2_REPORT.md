# P2 Report — POS smoke on polynize

**Status:** PASS

## Dispatch
- Node: **polynize** / **debian-trixie**
- Allocation: `ivgreiff_260613_012322_505302`
- Wall: `2026-06-12T23:23:22Z` → `2026-06-12T23:27:23Z` (~4 min)
- Bundle: `/home/ivgreiff/thesis_minimal_add_thesis_d5eddb8309cf.tar.gz`

## P2 gate (POS ≡ WSL)
- **pos_eq_wsl_outcomes_layers**: True
- **constraint_fingerprint_determinism_pos**: True
- **arguzz_matches_e1 (POS)**: True

### Per-run comparison

| run_id | type | outcome (WSL=POS) | intrastep | interstep | global | POS≡WSL | constraint 2× |
|--------|------|---------------------|-----------|-----------|--------|---------|---------------|
| a4_COMP_OUT_MOD_s0 | a4 | CONSTRAINT_REJECT | 1/1 | 0/0 | 1/1 | ✔ | ✔ |
| a4_INSTR_WORD_MOD_s0 | a4 | CONSTRAINT_REJECT | 1/1 | 0/0 | 1/1 | ✔ | ✔ |
| a4_INSTR_WORD_MOD_s2 | a4 | GLOBAL_REJECT | 0/0 | 0/0 | 1/1 | ✔ | ✔ |
| a4_INSTR_WORD_MOD_s8 | a4 | CONSTRAINT_REJECT | 1/1 | 0/0 | 1/1 | ✔ | ✔ |
| a4_LOAD_VAL_MOD_s0 | a4 | CONSTRAINT_REJECT | 1/1 | 0/0 | 1/1 | ✔ | ✔ |
| a4_STORE_OUT_MOD_s0 | a4 | CONSTRAINT_REJECT | 1/1 | 0/0 | 1/1 | ✔ | ✔ |
| arguzz_COMP_OUT_MOD_s0 | arguzz | CONSTRAINT_REJECT | 1/1 | 0/0 | 0/0 | ✔ | ✔ |
| arguzz_INSTR_WORD_MOD_s0 | arguzz | CONSTRAINT_REJECT | 1/1 | 0/0 | 0/0 | ✔ | ✔ |
| arguzz_INSTR_WORD_MOD_s2 | arguzz | GLOBAL_REJECT | 0/0 | 0/0 | 1/1 | ✔ | ✔ |
| arguzz_INSTR_WORD_MOD_s8 | arguzz | CONSTRAINT_REJECT | 1/1 | 0/0 | 0/0 | ✔ | ✔ |
| arguzz_LOAD_VAL_MOD_s0 | arguzz | CONSTRAINT_REJECT | 1/1 | 0/0 | 0/0 | ✔ | ✔ |
| arguzz_STORE_OUT_MOD_s0 | arguzz | CONSTRAINT_REJECT | 1/1 | 0/0 | 0/0 | ✔ | ✔ |

## On-node shell determinism summary (informational)

`thesis_run_pos.sh` marked all runs FAIL in `determinism_summary.txt` because it compares raw log lines including **Prover timing strings** (`"time":"33.41s"`). **Constraint-fingerprint determinism passes** for all 12 runs (same gate as P1).


**Gate passed:** True
