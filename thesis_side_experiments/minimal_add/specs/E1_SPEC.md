# E1 — Arguzz characterization (composer spec)

> **EXECUTION ENVIRONMENT (HARD RULE):** EVERYTHING runs on the **POS testbed**
> unless the batch is **≤10 prover runs**. E1 is ~90 proves (45 configs × 2
> determinism) → **POS**, not WSL. See `EXAMPLE_PLAN.md` §A3 and
> `bias_campaign/POS_NOTES.md`. (If E1 already ran on WSL, that was an exception to
> finish in-flight work; E2 onward must be POS.)

**Prereq:** E0 PASS. Read `EXAMPLE_PLAN.md` (esp. §A build/binary contract, §A2 flag
contract, §B mutation mechanics) and `artifacts/e0/site_card.json` first.
**Do not** modify anything outside `thesis_side_experiments/`. **Do not** rebuild or
touch the guest/host (E0 froze them); if `target/release/thesis-minimal-host` is
missing, run `./build.sh` once and re-confirm production `risc0-host` mtime unchanged.

## Objective
Characterize, for each of the four Arguzz mutation kinds, **exactly which circuit
constraints break** at the frozen instruction step, bucketed into the three thesis
layers (below). This is the **Arguzz column** only — no A4, no value alignment yet
(that is E2).

## Frozen targets (from E0 site card; pass as `--inject-step`)
| Arguzz kind | role | inject-step | what it mutates |
|---|---|---|---|
| `LOAD_VAL_MOD` | load_x | **193** | value loaded into `a2` (=3) |
| `COMP_OUT_MOD` | add | **195** | add result written to `a1` (=7) |
| `STORE_OUT_MOD` | store | **196** | data stored to `mem[a0+8]` (=7) |
| `INSTR_WORD_MOD` | add | **195** | the add's fetched instruction word (`0x00C585B3`) |

## How to run (use the harness — do NOT hand-roll host invocations)
Use `bias_campaign/run_arguzz.py::run_arguzz`, which sets the full `DEFAULT_ENV`
(all five flags) and `--trace --inject` for you. Host is the **minimal_add** host:
```python
from thesis_side_experiments.bias_campaign.run_arguzz import run_arguzz
HOST = "thesis_side_experiments/minimal_add/target/release/thesis-minimal-host"
rec = run_arguzz(HOST, guest_args=[], kind="COMP_OUT_MOD", step=195, seed=N,
                 log_path=Path("artifacts/e1/<kind>_seed<N>.log"))
```
`guest_args=[]` always (no host I/O). Never pass `A4_MUTATION_CONFIG` here, and never
set/unset `FAULT_INJECTION_ENABLED` (the host's `--inject` sets it; see §A2).

## Seeds
- Value kinds (`LOAD_VAL_MOD`, `COMP_OUT_MOD`, `STORE_OUT_MOD`): seeds **0–4** (value
  variety from `random_mod_of_u32`).
- `INSTR_WORD_MOD`: **sweep seeds until all three `random_word` modes are observed**
  (single-bit flip / multi-bit flip / full-random word). For each captured run record
  the **mutated word** (from the `<fault>` tag) and its **decoded instruction** via
  `a4.standalone.mutations.instr_word_mod_sur.RiscVInstruction.from_word(word)`
  (`.disassemble()`, `.format_name`). Keep going (e.g. seeds 0–30) until you have at
  least one run of each mode; report which seed produced which mode.

## What to capture per run
From the `RunRecord` returned by `run_arguzz` (and the raw log):
1. **Mutated value/word** — from `outcome.fault` / `target_desc` (the `<fault>` tag).
2. **Outcome class** — `outcome.outcome_class` (via `classify.py`).
3. **Constraint failures** — `run_common.failure_rows(outcome)` gives deduped rows
   with `{constraint_loc, phase, category, value, major, minor, cycle, step, pc}`.
4. **Global** — `run_common.global_failure_rows(outcome)` + `outcome.family_residues`.

## Three-layer bucketing (REQUIRED — do not stop at raw L1/L2/ACCUM/G)
`categorize.py` returns `L1 / L2 / ACCUM` for locals + family residues for global.
Re-map to the thesis layers, because L2 mixes intra- and inter-step:
- **intrastep-local** = all `L1` (decode/ALU, e.g. `VerifyOpcodeF3F7`, `DecodeInst`)
  **+** `MemoryWrite@mem.zir:99/100` (write-value == this-cycle's computed value).
- **interstep-local** = `IsRead@mem.zir:79/80` and `IsCycle@mem.zir:61/62`
  (cross-row memory consistency: `read.word == prev_word`, cycle ordering).
- **global** = any nonzero family residue (`memory`/`u16`/`u8`/`cycle`) **+** `ACCUM`.

Use `categorize.mem_zir_loc_matches(loc, "IsRead@mem.zir:79")` etc. to classify
mem.zir lines robustly (the host emits both `mem.zir:79` and `mem.zir :79`).

## Provenance (REQUIRED for every cited failure)
For each failure you highlight, show predicted residue == observed `value`
(BabyBear `p = 2013265921`). E.g. a value delta `d` shows as `value = (-d) mod p`
(`p - d` for small positive `d`). Confirm the residue matches the mutation delta and
note any ambiguity (e.g. linear propagation making two deltas share a residue).

## Determinism
Run every configuration **2×**; assert byte-identical categorized failure sets and
identical mutated value/word. Flag any nondeterminism instead of papering over it.

## Artifacts (under `artifacts/e1/`)
- `<kind>_seed<N>.log` raw output per run.
- `<kind>_seed<N>.json` parsed record: mutated value/word, decoded insn (for
  INSTR_WORD_MOD), outcome class, the three-layer buckets with example `loc`+residue.
- `arguzz_summary.md` table: `kind | role | seed | mutated | decoded | outcome |
  #intrastep-local | #interstep-local | #global | example loc+residue`.
- `E1_REPORT.{md,json}` with the gate booleans below.

## E1 gate (all must hold)
1. All four kinds run at the frozen steps; value kinds seeds 0–4; INSTR_WORD_MOD has
   all three `random_word` modes captured with decoded instructions.
2. Each configuration is **deterministic 2×** (identical categorized sets + values).
3. Every cited failure has **provenance** (predicted == observed residue).
4. Three-layer buckets reported per run (not just raw L1/L2/ACCUM/G).
5. No `PRE_EXEC_*` kinds used; no preflight crash (if any kind crashes, STOP and
   report the txn dump — do not work around it).
6. Production `risc0-host` mtime unchanged; only `thesis_side_experiments/` changed.

**Stop after E1 and report** the Arguzz column for Opus review before E2 (A4
replication). Do not start E2.
