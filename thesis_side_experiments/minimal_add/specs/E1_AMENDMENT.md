# E1 AMENDMENT — re-analysis only (ZERO new proofs)

> **Run location:** This amendment re-analyzes the EXISTING logs/JSONs under
> `artifacts/e1/`. It must NOT re-prove anything. 0 prover runs ⇒ runs on WSL.
> Do **not** run `./build.sh`. Do **not** call the host. Pure log/JSON post-processing.

## Context (decided with the user)
E1's value-kind column is accepted as-is (provenance-verified). This amendment fixes
three soundness/clarity issues in the `INSTR_WORD_MOD` characterization and adds a
host guard. **Reuse existing `artifacts/e1/*.log` and `*_seed*.json`.** Re-emit
`arguzz_summary.md` and `E1_REPORT.{md,json}` from them.

---

## Task A — Relabel the 7 control-flow crashes as `PROVE_ERROR`

**Evidence (already confirmed):** seeds 1, 7, 9, 17, 25, 27, 29 of `INSTR_WORD_MOD`
all show in their logs: `<fault>` injected → `{"context":"Prover","status":"error"}`
in ~37 ms → host panic `panicked at host/src/main.rs:106` → verifier NEVER runs →
0 `constraint_fail`. These are **Arguzz-caused prover crashes** (control-flow word
derails execution pre-witgen), NOT verifier rejections.

**Do:**
1. Add a post-hoc reclassifier: if a run's log contains
   `"context":"Prover", "status":"error"` AND `panicked at host/src/main.rs:106`
   AND has 0 `constraint_fail` AND the verifier never logged success/error, set
   `outcome_class = "PROVE_ERROR"` (override the `VERIFY_REJECT` mislabel).
2. In each such per-run JSON, add `"crash_stage": "prove"`,
   `"crash_evidence": "Prover status=error @~37ms; host panic main.rs:106; verifier never ran"`,
   and set `layers` to `null` (not 0/0/0 — they did NOT pass the constraint layers).
3. **Exclude `PROVE_ERROR` rows from the constraint-layer (local/interstep/global)
   table**, but keep them in a separate section (Task D).

## Task B — Reorganize `INSTR_WORD_MOD` by FIELD CHANGED (the thesis axis)

Drop the RNG-"mode" framing entirely. For every `INSTR_WORD_MOD` run, decode BOTH
the original word (`0x00c585b3`, `ADD x11,x11,x12`) and the mutated word, then diff
the RISC-V fields and label which changed:

- `opcode`/`funct7`/`funct3` → **operation** change
- `rd` → **dest-reg** change
- `rs1` → **src1-reg** change
- `rs2` → **src2-reg** change
- (a single mutation may change several fields — list all)

Add to each per-run JSON: `"fields_changed": [...]` and a `"field_class"` summary
(one of: `operation`, `dest_reg`, `src_reg`, `reg+operation`, `format_change`).

**Expected mapping to confirm/report (from existing data):**
| field changed | example seeds | expected layer |
|---|---|---|
| funct3/funct7 (operation, valid OP) | 0,5,6,8,18,19,20 | intrastep-local decode (`VerifyOpcodeF3F7`) |
| rd only | 2,11,12,21,23,26,30 | **0 local, 1 global (memory)** |
| rs1 only | 13 | **0 local, 1 global (memory)** |
| rs2 only | 3,4,14 | **0 local, 1 global (memory)** |
| rd = a0/x10 (downstream base ptr) | 24 | cascade: 6 local + 1 global |
| opcode → control flow | 1,7,9,17,25,27,29 | PROVE_ERROR (Task A) |
| opcode → OP-IMM / store | 10,15,16,22 | mixed local (+global) |

Build a per-`field_class` aggregate table in `arguzz_summary.md`: for each class,
report n, and the distribution over {intrastep-local, interstep-local, global,
PROVE_ERROR}. **Explicitly call out that rd-only AND src-reg-only changes both land
0-local/1-global for Arguzz** (executor stays self-consistent; only the global
memory permutation catches the wrong register vs the fetched word).

## Task C — Remove the unsound 3-mode gate
Delete `instr_three_modes` / `instr_modes_complete` / `random_word_mode` from the
gate logic and report. Replace the gate item with **field-coverage**: PASS requires
at least one observed run in each of {operation-change, dest-reg-change,
src-reg-change}. (We already have all three.) Keep `random_word_mode` out of the
JSON, or keep it only as an explicitly-labeled `"rng_mode_heuristic_UNSOUND"` note.

## Task D — Report `PROVE_ERROR` as a finding
Add a short section to `arguzz_summary.md` titled **"Arguzz control-flow crashes
(PROVE_ERROR)"**: list the 7 seeds, the decoded instruction (JALR/JAL/BLTU/SYSTEM),
and one line: *"Arguzz `INSTR_WORD_MOD` to a control-flow/format-changing word crashes
the prover pre-witgen (host panic main.rs:106), analogous to the `PRE_EXEC` preflight
crash — upstream of all constraint evaluation and of the A4 hooks."* Excluded from
the constraint-layer comparison.

## Task E — Host sha-guard
Add a guard (shared helper, also used by E2/E3): assert
`sha256(target/release/thesis-minimal-host) == 5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23`
and refuse to proceed (and never auto-rebuild) if it differs. The frozen reference
copy is `frozen_host/thesis-minimal-host.e0frozen`.

---

## Gate (amended)
- value kinds: 1 intrastep-local, 0 interstep, 0 global each (unchanged) ✔
- `INSTR_WORD_MOD`: field-class table present; operation/dest-reg/src-reg all covered ✔
- 7 control-flow runs relabeled `PROVE_ERROR`, excluded from layer table, reported ✔
- modes gate removed; host sha-guard present ✔
- determinism unchanged (all `determinism_ok=true`) ✔
- NO new proofs were run (verify by mtimes of `artifacts/e1/*.log` unchanged) ✔
