# Isolated Minimal-Add Experiment Plan (Thesis §3.3.3)

Side experiment only. All artifacts live under `thesis_side_experiments/minimal_add/`.

## Hard constraints

| Rule | Implementation |
|------|----------------|
| No existing binary replaced | Binary name `thesis-minimal-host`; `CARGO_TARGET_DIR=./target` |
| No repo code modified | New tree only; `risc0-modified` linked read-only |
| No coupled Arguzz/A4 path | Skip `a4/arguzz_dependent/`, `a4.cli compare` |
| Modern A4 terminology | `step` = `user_cycle`; Add = `major=0`, `minor=0` |

## Guest

- **Program:** `li t0,3; li t1,4; add t2,t0,t1; commit 7`
- **Why:** One Add at a known step; operands match thesis hand example (3 + 4)

## Phase 0 — Pin artifacts

```bash
cd thesis_side_experiments/minimal_add && ./build.sh
export THESIS_HOST=./target/release/thesis-minimal-host
export THESIS_ELF=./target/riscv-guest/thesis-minimal-methods/thesis-minimal-guest/riscv32im-risc0-zkvm-elf/release/thesis-minimal-guest.bin
```

## Phase 1 — Baseline instruction card

```bash
$THESIS_HOST --trace 2>&1 | tee artifacts/baseline_trace.txt
```

- Find the Add line (`assembly` contains `add`, `major=0`, `minor=0`)
- Record Arguzz `step`, `pc`, registers
- A4 inspect (from repo root, read-only):

```bash
python -m a4.standalone.cli inspect \
  --elf "$THESIS_ELF" \
  --output artifacts/baseline_inspection.json
```

Align A4 step: `a4_pc = arguzz_pc + 4` (A4 records next PC).

## Phase 2 — Local constraints touched (unmutated)

```bash
A4_COVERAGE_TOUCH=1 CONSTRAINT_CONTINUE=1 \
  python -m a4.standalone.cli inspect \
  --elf "$THESIS_ELF" --verbose \
  --output artifacts/touch_inspection.json
```

Filter witgen output for Add step (`major=0`, `minor=0`) → **Touch Table**.

## Phase 3 — Arguzz mutation

Pick Add step `N` from baseline trace. Mutate source register (rs2 = 4 → corrupt).

```bash
$THESIS_HOST --trace --inject \
  --inject-step N --inject-kind PRE_EXEC_REG_MOD --seed 42 \
  2>&1 | tee artifacts/arguzz_mut_trace.txt
```

Parse: `<constraint_fail>`, Hook 3 `family_residues`, verifier outcome.

## Phase 4 — A4 mutation

Build `A4_MUTATION_CONFIG` for same logical site: `PRE_EXEC_REG_MOD`, `next_read`
on rs2 read txn at Add step (from inspection).

```bash
A4_MUTATION_CONFIG=artifacts/a4_mutation.json \
A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 CONSTRAINT_CONTINUE=1 \
  python -c "from a4.core.executor import run_a4_mutation; ..."
```

Parse same tags as Phase 3.

## Phase 5 — Constraint glossary (for prose)

| Signal | Plain meaning |
|--------|----------------|
| `IsRead@mem.zir` | Witness memory read does not match committed trace word |
| `MemoryWrite@mem.zir` | Register write txn inconsistent with read/set chain |
| `VerifyOpcodeF3@inst.zir` | Decoded opcode nibble mismatch (less common on reg mod) |
| Hook 3 `memory` family | Accumulator-phase memory mix residue ≠ 0 |

Sources: `a4/docs/global/PRESENTATION_DEEP_DIVE.md`, `GLOBAL_HOOKS_CATALOG_V2.md`.

## Phase 6 — Comparison matrix (thesis deliverable)

| Dimension | Arguzz (executor inject) | A4 (witness txn rewrite) |
|-----------|--------------------------|---------------------------|
| Injection site | `store_register` before step N | `word` on register READ txn |
| Typical local breaks | IsRead, MemoryWrite | IsRead, MemoryWrite |
| Global / Hook 3 | memory family residue | memory family residue |
| ALU add constraint name | Usually not the first failure | Usually not the first failure |

## Phase 7 — Thesis prose

Update §3.3.3 fictional table with observed constraint **names** and correct
bandit feedback sources (touch from witgen; global from accumulator Hook 3, not transcript).
