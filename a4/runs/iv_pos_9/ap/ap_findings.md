# AP findings — IsRead planted bug (AP.B2)

## Summary

| Metric | Value |
|--------|------:|
| Corpus size (race-guest (0,1,0) screen) | 15 |
| E5 atoms_n250 (0,1,0) in repo | 21 |
| bench-isread ACCEPT | 0/15 |
| patched REJECT | 15/15 |
| Genuine soundness (mutated ≠ honest, bench accepts) | 0/15 |

## Circuit-level why — NEGATIVE RESULT (the IsRead hole is necessary but NOT sufficient)

> ⚠️ This auto-generated prose previously asserted bench witnesses "verify". The bracket **refutes** that: **bench-accept = 0/15**. Corrected below; see `AP_B2_GLOBAL_LOGUP_FINDING.md` for the full analysis.

`PRE_EXEC_REG_MOD next_read` edits a **register READ** txn's `word` (`word ≠ prev_word`).

- On **patched** (committed): the edit fires **exactly one** local constraint — `IsRead@ReadReg` (`mem.zir:79`), interstep-local. This is the `(0,1,0)` signature.
- On **bench-isread** (IsRead@ReadReg holed): that local failure disappears (bench local layers `{0,0,0}` for all 15). **But all 15 still reject** with **zero local constraint failures**, panicking `verify segment` (`verify_integrity`).

**Reason:** registers are memory-mapped; the **global** LogUp memory-permutation grand product independently binds the read value to the last write at that address. A4's single post-exec edit unbalances the already-committed accumulator, so the global argument rejects it regardless of the local IsRead hole. The `(0,1,0)` screening only counts per-row `<constraint_fail>` records and never sees the global LogUp imbalance (which surfaces only at `verify_integrity`), so the `(0,1,0)` label did not imply a single guardian.

## Genuine vs no-op
- **Genuine**: bench accepts AND `mutated_word ≠ original_word`. **0/15 — none.** The global memory argument is a redundant guardian for register-resident values.

## Bracket exceptions

- `race_0000_s51_txn15613` step=51 bench=False patched=False
- `race_0001_s54_txn15626` step=54 bench=False patched=False
- `race_0002_s56_txn15635` step=56 bench=False patched=False
- `race_0003_s57_txn15640` step=57 bench=False patched=False
- `race_0004_s58_txn15645` step=58 bench=False patched=False
- `race_0005_s60_txn15654` step=60 bench=False patched=False
- `race_0006_s62_txn15663` step=62 bench=False patched=False
- `race_0007_s64_txn15672` step=64 bench=False patched=False
- `race_0008_s1095_txn20018` step=1095 bench=False patched=False
- `race_0009_s1130_txn20162` step=1130 bench=False patched=False
- `race_0010_s1153_txn20257` step=1153 bench=False patched=False
- `race_0011_s1175_txn20352` step=1175 bench=False patched=False
- `race_0012_s1184_txn20388` step=1184 bench=False patched=False
- `race_0013_s1193_txn20427` step=1193 bench=False patched=False
- `race_0014_s1200_txn20461` step=1200 bench=False patched=False
