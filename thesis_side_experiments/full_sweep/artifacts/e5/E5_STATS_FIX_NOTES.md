# E5 stats fix notes (re-aggregation only — no re-proving)

## Fix 1 — fired-conditional Arguzz class-specific kinds

Rates recomputed over samples where `<fault>` was emitted (`n_fired/n`).

| kind | n_fired/n | expected | match |
|------|-----------|----------|-------|
| BR_NEG_COND | 72/250 | 72/250 | ✓ |
| COMP_OUT_MOD | 150/250 | 150/250 | ✓ |
| LOAD_VAL_MOD | 49/250 | 49/250 | ✓ |
| STORE_OUT_MOD | 99/250 | 99/250 | ✓ |

Other Arguzz kinds and all A4 kinds: n_fired=n=250.

### Fired-conditional reached rate (selected)

- **BR_NEG_COND**: all-sample reached=24.8% → fired reached=86.1% (fired-silent=12.5%)
- **COMP_OUT_MOD**: all-sample reached=48.8% → fired reached=81.3% (fired-silent=14.7%)
- **LOAD_VAL_MOD**: all-sample reached=10.0% → fired reached=51.0% (fired-silent=49.0%)
- **STORE_OUT_MOD**: all-sample reached=34.4% → fired reached=86.9% (fired-silent=12.1%)

## Fix 2 — crash accounting

`crash_stages` tallies only `crashed==true` atoms, bucketed by backfilled stage.

- A4 crashes: **0** (expected 0)

| mutation_type | preflight | prove_error |
|---------------|-----------|-------------|
| BR_NEG_COND | 0 | 1 |
| COMP_OUT_MOD | 0 | 6 |
| INSTR_WORD_MOD | 0 | 3 |
| POST_EXEC_MEM_MOD | 15 | 0 |
| POST_EXEC_PC_MOD | 0 | 5 |
| POST_EXEC_REG_MOD | 15 | 2 |
| PRE_EXEC_MEM_MOD | 18 | 0 |
| PRE_EXEC_PC_MOD | 0 | 5 |
| PRE_EXEC_REG_MOD | 11 | 2 |
| STORE_OUT_MOD | 0 | 1 |

Total Arguzz crashed: 84

**Validation gate: PASS**
