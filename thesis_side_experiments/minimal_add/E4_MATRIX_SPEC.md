# E4 (data assembly) — complete granular Arguzz×A4 matrix

> **Analysis only — NO proving, NO host, NO POS.** Ingest the already-collected per-run
> JSONs from `artifacts/e1/` (Arguzz) and `artifacts/e2/pos_full/analysis/` (A4) and emit ONE
> complete, granular, machine-checked matrix. Runs on WSL. Do not re-run anything.

## Deliverable
`run_e4_matrix.py` + `artifacts/e4/`:
- `matrix.json` / `matrix.csv` — one row per run (every E1 + E2 run; NO sampling).
- `MATRIX_GRANULAR.md` — the human-readable granular table(s).
- `counts.json` — row-count + sanity checks.

## One row per run — required columns
For **every** run (Arguzz E1: value seeds + all INSTR_WORD seeds incl. the 7 PROVE_ERROR;
A4 E2: FULL mirrors + SUR + MEM_VAL):
- `fuzzer` (arguzz | a4), `variant` (— | FULL | SUR | MEM_VAL), `kind`, `role`, `seed`
- `inject_step`, `a4_step` (if applicable)
- `mutated_value` / `mutated_word_hex`, `decoded_instruction` (disassembly + opcode/rd/funct3/rs1/rs2/funct7 when a word), `original_instruction` (for INSTR rows)
- `fields_changed`, `field_class`
- `outcome_class`
- `layers`: `intrastep_local`, `interstep_local`, `global` (integer counts)
- **`constraints[]`** — the FULLY EXPANDED list of every broken constraint for this run, each
  with: `layer`, `full_loc` (complete ZIR loc, untruncated), `residue` (the `value` field),
  `cycle`, `step`, `major`, `minor`, and `provenance` (predicted vs observed + formula) when present.
- `crash_stage`/`crash_evidence` for PROVE_ERROR rows.
- `arguzz_mirror` note for MEM_VAL rows ("n/a — no in-place memory-read mutation").

## Granular markdown (`MATRIX_GRANULAR.md`)
1. **Master matrix table** grouped by semantic target (role/kind), columns:
   `Arguzz i/inter/g | A4-FULL i/inter/g | A4-SUR i/inter/g | A4-MEM_VAL i/inter/g`
   (n/a where a variant doesn't apply). One line per (role, kind, seed/field).
2. **Per-run granular detail** (one subsection per run): the mutated value/word + decoded
   instruction, outcome, and a bullet list of **every** broken constraint (full ZIR loc +
   residue + layer). For zero-failure rows (e.g. Arguzz register changes), **explicitly print
   `local constraints broken: NONE (failure_count=0); global memory residue: nonzero`** so the
   "global-only" cases are unmistakable.
3. A short **per-field-class** and **per-layer** rollup (who reaches which layer).

## Must be unmistakable in the output (verified findings — assert them)
- **Arguzz register changes (dest AND source: E1 seeds 2,11,21,23,26,30 (rd); 3,4,12,13,14 (rs1/rs2)) = `0/0/1`** — print `failure_count=0`, empty local+interstep, global memory residue only. Assert no `<constraint_fail>` for these rows.
- **Value kinds: Arguzz `1/0/0` vs A4-FULL `1/0/1`** (A4 adds global `memory`).
- **A4-SUR rd/rs1/rs2 all `0/0/1`** (asymmetry denied); funct3/funct7 SUR `1/0/1`.
- **A4 MEM_VAL load reads `2/2/1`, store_rmw_read `0/2/1`** with `IsRead@mem.zir:79/80` in the
  interstep bucket — the only interstep-populating rows.

## Gate
- Row counts match (Arguzz E1 all rows incl. 7 PROVE_ERROR; A4 = 39 FULL + 6 SUR + 8 MEM_VAL);
  print the tallies in `counts.json`.
- Every non-crash, non-zero row lists its full constraint loc(s) + residue; zero-failure rows
  explicitly labeled global-only.
- The four asserted findings above all hold (script asserts + reports).

## After this (Opus writes — not composer)
`A4_CONSTRAINTS_EXPLAINED.md` (A4 mutation→constraint→meaning→layer + Arguzz mirror contrast)
and the **E4 narrative**, wrapping this granular matrix with ZIR meaning + the bias story.
