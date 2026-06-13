# Example plan — semantically-aligned mutations: Arguzz vs A4

Goal: a small, foolproof, intuitive thesis example that shows **where each fuzzer's
mutations break circuit constraints**, classified into three layers:

- **intrastep-local** — a within-cycle check fails (instruction decode `L1`, or the
  intra-cycle `MemoryWrite` "write value == this cycle's computed value").
- **interstep-local** — a cross-row memory-consistency check fails (`IsRead`:
  `read.word != prev_word`, i.e. a value's *neighbor* access is stale).
- **global** — the permutation/lookup (memory or bytes) argument does not close
  (Hook-3 family/global residue nonzero).

The bias we want is **local vs interstep vs global**, NOT cascade vs non-cascade.
Background and caveats: `../ARGUZZ_A4_KNOWLEDGE_BASE.md`.

Arguzz kinds: `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `INSTR_WORD_MOD`.
A4 aligned kinds: `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`,
`INSTR_WORD_MOD_FULL`, **and `INSTR_WORD_MOD_SUR`** (single-field surgical).

---

## A. Build & binary contract (READ FIRST — no rebuild surprises)

There is **exactly one binary** for this example, and it supports both fuzzers:

```
thesis_side_experiments/minimal_add/target/release/thesis-minimal-host
```

Facts verified from the source tree (do not re-derive at run time):

1. **Build command:** `thesis_side_experiments/minimal_add/build.sh`. It sets
   `CARGO_TARGET_DIR=<minimal_add>/target` then `cargo build --release`. So the
   build writes **only** into `minimal_add/target/` and **never** touches
   `workspace/output/`. (`build.sh` lines 5–8.)
2. **What it links** (`host/Cargo.toml`): `risc0-zkvm` and `fuzzer_utils` from
   `/root/arguzz/workspace/risc0-modified/...`, with features
   `default = ["prove"]`, `prove = ["risc0-zkvm/prove", "risc0-zkvm/witgen_debug"]`.
   `witgen_debug` is the **same feature production uses** — all constraint hooks
   (`<constraint_fail>`, `<a4_touch_verbose>`, family/global residue) are compiled in.
3. **Guest rebuild:** the guest ELF is embedded via `methods/build.rs`
   (`risc0_build::embed_methods()`). **Any edit to
   `methods/guest/src/main.rs` requires re-running `./build.sh`** to recompile +
   re-embed the guest. There is no separate guest build step.
4. **Both fuzzers, one binary:**
   - **Arguzz** = host CLI flags `--trace --inject --inject-step S --inject-kind K
     --seed N` (host `main.rs` wires these via `fuzzer_utils::set_*`; `--inject`
     also calls `disable_assertions()`).
   - **A4** = env var `A4_MUTATION_CONFIG=cfg.json` (witness-stage hook in
     risc0-modified). No CLI flag.
5. **Guest takes NO arguments.** Operands are baked into the guest (see §C), so
   `guest_args = []` everywhere. (Do **not** copy the `--in1/--in4` args or the
   `risc0-host` default from `bias_campaign/guest_sites.py` — that default host is
   the unrelated c0/c1 differential binary and must not be used here.)
6. **Isolation gate:** before/after every build, stat
   `/root/arguzz/workspace/output/target/release/risc0-host` and assert its mtime is
   unchanged. Only files under `thesis_side_experiments/` may change. Never edit
   `workspace/` or `a4/` source (the `a4.*` Python is imported read-only; our
   editable harness is `thesis_side_experiments/bias_campaign/`).

Constraint-observation env (identical for both fuzzers), from
`bias_campaign/run_common.py::DEFAULT_ENV`:
```
CONSTRAINT_CONTINUE=1 A4_COVERAGE_TOUCH=1 A4_COVERAGE_TOUCH_VERBOSE=1
A4_FAMILY_RESIDUE=1 A4_GLOBAL_RESIDUE=1
```

Reusable, already-working APIs (all imported, not reimplemented):
- `a4.core.inspection_data.InspectionData.from_inspection(host, [])` → cycles + txns.
- `a4.core.executor.run_a4_inspection_with_step(host, [], step)` → txn dump at a step.
- `a4.core.executor.run_baseline(host, [], env)` → raw output.
- `a4.core.constraint_parser.parse_all_constraint_failures(output)`.
- `a4.core.touch_coverage.{parse_touch_bitmap, parse_accum_verbose_set, ...}`.
- `bias_campaign/classify.py::classify_run`, `categorize.py::{categorize_failure,
  categorize_failures}`, `run_arguzz.py::run_arguzz`, `run_a4.py::run_a4`.
- `bias_campaign/a4_config.py` (value kinds + `INSTR_WORD_MOD_FULL`); we extend it
  for forced values + `INSTR_WORD_MOD_SUR` (see E2/E3).

> `run_m0.py` is the proven template for the build + inspect + baseline flow, but it
> **hardcodes** the old single-add site (step 187, a4_step 185, cycle 15424, and
> "add s0,a0,a1"). The new `run_e0.py` must **generalize** site discovery and drop
> those constants.

---

## A2. Flag contract — what MUST be set, what must NEVER be touched

These were verified from `workspace/risc0-modified` source during the as-is
investigation. Getting them wrong either crashes the run, makes Arguzz and A4
non-comparable, or hides the constraint footprint. **Always invoke both fuzzers
through `run_arguzz.py` / `run_a4.py`, which merge `DEFAULT_ENV` for you — do not
hand-roll bare host invocations.**

### A2.1 The five env flags (all REQUIRED, identical for both fuzzers)
`DEFAULT_ENV` (`run_common.py`) sets all of these; the consequence of dropping each:

| Flag | Acts in | If missing |
|---|---|---|
| `CONSTRAINT_CONTINUE=1` | C++ `eqz` (`witgen.h`) | aborts on the **first** constraint failure → we lose the full footprint |
| `A4_COVERAGE_TOUCH=1` | Rust `hal/mod.rs` | **drops out of `StepMode::SeqForward`** → parallel-thread SIGSEGV risk + no touch sets + nondeterminism |
| `A4_COVERAGE_TOUCH_VERBOSE=1` | C++ ffi | no local/accum touch-verbose sets (need them for the touched "universe") |
| `A4_FAMILY_RESIDUE=1` | C++ ffi | no Hook-3 family residues → can't measure the **global** layer |
| `A4_GLOBAL_RESIDUE=1` | C++ ffi | no global residue → can't measure the **global** layer |

`A4_COVERAGE_TOUCH=1` is the dangerous one to forget: it is what forces **both**
fuzzers into `SeqForward` (the comment in `hal/mod.rs` says this avoids "SIGSEGV from
parallel thread corruption"). A bare `--inject` Arguzz run without it can crash or run
a different step mode and is **not comparable** to A4.

### A2.2 `FAULT_INJECTION_ENABLED` — set automatically, do NOT manage by hand
This C++ flag skips txn-cycle-mismatch `throw`s, **modular-indexes buffers to avoid
OOB**, and downgrades asserts — i.e. it is exactly what lets a mutated witness reach
the constraint evaluator so we *see* `<constraint_fail>` instead of an abort.
- **Arguzz:** the host sets it via `set_injection(true)` on `--inject` (and calls
  `disable_assertions()` during prove, then `enable_assertions()` before verify).
- **A4:** auto-set by the witgen when `A4_MUTATION_CONFIG` is present (no `--inject`,
  so the host keeps assertions enabled throughout).
Both paths end up with `FAULT_INJECTION_ENABLED=1` and both verify with assertions on.
**Never set or unset `FAULT_INJECTION_ENABLED` manually**, and never pass `--inject`
to an A4 run or `A4_MUTATION_CONFIG` to an Arguzz run.

### A2.3 The crash flags can't save you — so AVOID the crashing kinds
The `preflight.rs::wrap_memory_txns` OOB panic is **upstream of every flag above**
(`preflight.rs` has zero env checks) and its `ensure!` guard is commented out. It
fires only for **`PRE_EXEC_*` kinds**, which inject an *extra* same-cycle txn on a
register the instruction also touches (write→read self-reference → `diff` underflow).
**Our four chosen kinds are all Family-2 in-place edits** (`COMP_OUT_MOD`,
`LOAD_VAL_MOD`, `STORE_OUT_MOD`, `INSTR_WORD_MOD`): they modify a value/word already
in the instruction's single transaction and add **no** extra txn, so they never reach
that underflow. **Do not substitute a `PRE_EXEC_*` kind** for any of them.
(Arguzz injection deterministically re-fires in the preflight re-execution too, but
for Family-2 kinds that only yields a consistently propagated trace — no crash.)

### A2.4 Build features / determinism — leave them alone
- The host is built with `witgen_debug` (via `prove`), which forces the
  nondeterministic witness hint to the constant `1`. This is what makes the 2×
  determinism gate pass — **do not change host features**.
- **Do NOT set `RISC0_WITGEN_DEBUG`**: it only forces `SeqForward`, which
  `A4_COVERAGE_TOUCH` already guarantees. Keep the env identical for both fuzzers so
  the only difference between an Arguzz run and an A4 run is the injection mechanism.

---

## A2b. FROZEN host binary (comparability guard) — do NOT rebuild for E1–E4

A **parallel `inc3d`/POS campaign is actively modifying `workspace/risc0-modified`**
and rebuilding the production `risc0-host`. To keep E1↔E2↔E3 comparable, the
`minimal_add` host is **frozen** at the E0 build:
- path: `thesis_side_experiments/minimal_add/target/release/thesis-minimal-host`
- **sha256 `5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23`**
  (built 2026-06-12 04:08 EDT; used for E0 + E1).

**Every E1–E4 run must assert the host sha equals the frozen value and must NOT run
`./build.sh`.** If a rebuild ever becomes unavoidable, re-run E0 (confirm the
1580/298 touch universe + clean deterministic baseline) and re-run E1 before trusting
any new E2/E3 numbers. Add this sha-guard to `run_e2.py`/`run_e3.py`.

## A3. Execution environment — WHERE to run (POS vs WSL) — HARD RULE

**EVERYTHING runs on the POS testbed unless the batch is 10 prover runs or fewer.**
The WSL dev box is too weak for batch proving; use it only for ≤10 proves (E0
baseline, single-config debugging, quick smoke checks). Any sweep/batch with **>10**
prover invocations **must** run on POS.

- POS workflow, custom-binary wrinkle, pre-reservation, anti-patterns:
  `thesis_side_experiments/bias_campaign/POS_NOTES.md` (canonical:
  `a4/docs/precloud/POS_PLAYBOOK.md`). Build the host on WSL, copy to the name
  `risc0-host`, bundle, ship, dispatch with `--allocation-duration 0`. **minimal_add
  guest takes no inputs → `guest_args: []`.**
- Per-phase routing:
  - **E0** (≤10 clean proves: 1 trace + 2 baseline + inspection) → **WSL** OK.
  - **E1** (~45 configs × 2 determinism ≈ 90 proves) → **POS**.
  - **E2** (~45 A4 configs × 2 ≈ 90 proves) → **POS**.
  - **E3** (SUR fields × 2) → **POS** if >10, else WSL.
  - **E4** (analysis only, no proving) → **WSL**.
- **Open item (resolve before E2 dispatch):** the existing POS manifest infra
  (`a4/pos/run_campaign_pos.sh`, manifests) is **A4-centric** (`A4_MUTATION_CONFIG`).
  Arguzz `--inject` sweeps (E1) and our forced-value/SUR A4 configs (E2/E3) need
  either (a) our Python driver (`run_e*.py`) shipped and run **on-node** against the
  bundled host, or (b) a manifest extension that carries `--inject-step/-kind/-seed`
  and explicit config values. Design this POS execution path as the **first E2-prep
  task**; do not assume the stock A4 manifest covers Arguzz runs.

---

## B. Mutation mechanics (read before running)

### Arguzz value generator — `random_mod_of_u32(out)` (`rv32im.rs`)
`COMP_OUT_MOD`/`LOAD_VAL_MOD`/`STORE_OUT_MOD`. Selector 0–7:
`{0, 1, 0xffffffff, 0xfffffffe, random multi-bit flip, +1, −1, fully-random}`;
loops until `new != old`. Sample several seeds; **copy the value the run reports**.

### Arguzz word generator — `random_word(word)` (`rv32im.rs`)
`INSTR_WORD_MOD`. Selector 0–2: `{flip 1 bit in [2..31]; flip n∈[1..29] bits in
[2..30]; fully-random | 0x03}`, looping until the new word is **different AND decodes
to a valid instruction** (bits 0–1 untouched). **Sweep seeds to cover all 3 modes**;
record the decoded instruction kind. Placement: Arguzz mutates the **executed** word;
the instruction-fetch READ txn keeps the **original** word.

### A4 aligned kinds (`a4/standalone/mutations/` via `bias_campaign/a4_config.py`)
- **Value kinds** (`comp_out_mod`/`load_val_mod`/`store_out_mod`): rewrite the txn
  value in the witness. `create_config(target, mutated, output_path)`. For this
  example, **force `mutated` = exact Arguzz value** (bypass `pick_mutated_value`).
- **`INSTR_WORD_MOD_FULL`** (`instr_word_mod.py`): sets **both** `txn.word` and
  `txn.prev_word` to the mutated word → `IsRead` stays satisfied, failure targets
  **decode**. `create_config(target, mutated, output_path)`.
- **`INSTR_WORD_MOD_SUR`** (`instr_word_mod_sur.py`): decode (`RiscVInstruction`),
  `encode_with_mutation(field, new_value)` → new word, then
  `create_config(target, surgical_field, mutated_word, new_field_value, path)`.
  `mutation_type` is still `INSTR_WORD_MOD` (same Rust handler). Hypothesis: a
  single-field change (e.g. `FUNCT7` ADD→SUB) breaks **exactly one** intrastep-local
  decode constraint.

> Arguzz vs A4 `INSTR_WORD_MOD` are **mirror images**: same target word, but Arguzz
> changes the *executed* word (fetch txn original) while A4 changes the *fetched*
> word (execution effects original). Report the mirror; don't "fix" it.

---

## C. Guest — load → add → store → read-back (recreate)

Why not the single add: it cannot exercise `LOAD_VAL_MOD`/`STORE_OUT_MOD` (no
load/store), and the **interstep** layer is unreachable without a value being written
then read in a later step.

Recreate `methods/guest/src/main.rs` (operands baked in → host needs **no** I/O
change; output stays a single `u32`). Use **volatile** loads/stores so the compiler
emits real `Lw`/`Sw` (cannot fold/elide), and `black_box` so the add stays a real
R-type `Add`:

```rust
#![no_main]
#![no_std]
use risc0_zkvm::guest::env;
use core::ptr::{read_volatile, write_volatile};
use core::hint::black_box;
risc0_zkvm::guest::entry!(main);

fn main() {
    static mut BUF: [u32; 4] = [3, 4, 0, 0];
    unsafe {
        let p = core::ptr::addr_of_mut!(BUF) as *mut u32;
        let x = read_volatile(p.add(0));            // Lw  -> LOAD_VAL_MOD target
        let y = read_volatile(p.add(1));            // Lw
        let s = black_box(x) + black_box(y);        // Add -> COMP_OUT_MOD / INSTR_WORD_MOD target
        write_volatile(p.add(2), s);                // Sw  -> STORE_OUT_MOD target
        let r = read_volatile(p.add(2));            // Lw  (read-back = interstep oracle)
        env::commit(&r);                            // journal output = 7
    }
}
```

Each mutated value has a **downstream reader** (load x → the add; add s → the store;
store mem → the read-back), which is exactly what makes the interstep layer reachable
and surfaces the Arguzz-vs-A4 divergence. After building, the deduped trace must show,
in order, an `Lw`, `Lw`, `Add`, `Sw`, `Lw`; if the compiler reorders/merges, adjust
(separate `asm!` blocks or extra `black_box`) until the five instructions are
unambiguous. Baked output is `7`.

---

## D. Increments E0–E4 (each gated; hand to composer one at a time)

### E0 — Guest rebuild + site derivation + clean baseline

**Deliverable:** `minimal_add/run_e0.py` (modeled on `run_m0.py`, generalized) +
`artifacts/e0/` outputs.

**Steps (exact):**
1. Replace `methods/guest/src/main.rs` with §C. Stat the production host
   (`workspace/output/.../risc0-host`) → record mtime. Run `./build.sh`; assert
   exit 0, `target/release/thesis-minimal-host` exists, and **production mtime
   unchanged**.
2. Run `host --trace` (no env, no injection). Assert journal `"output":"7"` and
   `Verifier ... "status":"success"`. Save deduped trace (reuse
   `run_m0.dedupe_trace_lines`).
3. **Generalized site discovery** (no hardcoded steps): from the deduped trace,
   find the five target instructions by class + order using
   `bias_campaign/guest_sites.py` op-sets (`LOAD_OPS`, `COMPUTE_OPS`, `STORE_OPS`):
   the first `Lw` (= load x), the `Add`, the `Sw`, and the `Lw` after the `Sw`
   (= read-back). Record each `{role, arguzz_step, pc, instruction, assembly}`.
   Assert exactly one `Add`, ≥2 `Lw`, exactly one `Sw` in the guest body.
4. `data = InspectionData.from_inspection(host, [])`. Derive the **Arguzz→A4 step
   offset** generically via `guest_sites.infer_step_offset(trace_steps, cycles)`
   (do **not** assume −2). For each role compute `a4_step = arguzz_step + offset`
   and dump txns with `run_a4_inspection_with_step` to confirm the expected txn
   shape (load: rd WRITE; add: a0/a1 READ + rd WRITE; store: mem WRITE + rs2 READ;
   read-back: rd WRITE + mem READ).
5. **Site card:** write `artifacts/e0/site_card.json` mapping each role →
   `{arguzz_step, arguzz_pc, a4_step, cycle_idx, major, minor, txn summary}`.
6. **Baseline determinism:** run `run_baseline(host, [], DEFAULT_ENV)` **2×**;
   assert **0** `<constraint_fail>`, **0** nonzero family/global residues, and
   byte-identical local+accum touch-verbose sets across the two runs. Save the
   touched-constraint "universe" per target step (the set that *could* fail).

**E0 gate:** production mtime unchanged; baseline output 7 + verifier success;
0 failures / 0 global residue; touch sets reproducible 2×; site card frozen with all
five roles unambiguously identified and their A4 steps validated.

### E1 — Arguzz characterization (the four kinds)

**Deliverable:** `run_e1.py` + `artifacts/e1/` (raw logs + per-run JSON + a table).

For each `(kind, role)`: `COMP_OUT_MOD`@add, `LOAD_VAL_MOD`@load-x,
`STORE_OUT_MOD`@store, `INSTR_WORD_MOD`@add — using the frozen `arguzz_step`:
1. Run via `run_arguzz(host, [], kind, step=arguzz_step, seed=N, log_path=...)`.
   - Value kinds: a few seeds (e.g. 0–4) for value variety.
   - `INSTR_WORD_MOD`: **sweep seeds until all three `random_word` modes are
     observed** (single-bit, multi-bit, full-random); record each mutated word +
     its **decoded instruction** (use `RiscVInstruction.from_word`).
2. Per run capture: the exact mutated value/word from the `<fault>` tag (already in
   `RunRecord.outcome.fault` / `target_desc`); outcome class (`classify_run`);
   the **deduped, categorized** `<constraint_fail>` set via `failure_rows` +
   `categorize_failure(loc, phase)`, bucketed into **intrastep-local** (decode `L1`
   + `MemoryWrite@mem.zir`), **interstep-local** (`IsRead@mem.zir`), **global**
   (`global_failure_rows` / family residues); plus residue + ZIR provenance for each
   cited failure (predicted residue from the value delta == observed `value` field).
3. Write `artifacts/e1/<kind>_seed<N>.json` and an `arguzz_summary.md` table:
   columns `kind | role | seed | mutated value/word | decoded insn | outcome |
   #intrastep-local | #interstep-local | #global | example loc+residue`.

**E1 gate:** every `(kind, role)` yields a **deterministic** (2× identical)
categorized signature; for `INSTR_WORD_MOD` all three modes captured with decoded
kinds; every cited residue's provenance verified (predicted == observed).

### E2 — A4 semantic replication (aligned, FULL)

**Deliverable:** `run_e2.py`, an `a4_config.py` extension, + `artifacts/e2/`.

1. Extend `bias_campaign/a4_config.py` with a **forced-value** path (e.g.
   `build_a4_config(..., forced_value: Optional[int])` that, when set, skips
   `pick_mutated_value` and passes `forced_value` straight to the relevant
   `create_*_config`). For `INSTR_WORD_MOD_FULL`, force `word = exact Arguzz word`.
2. For **each E1 run**, build a config applying the **same semantic change at the
   same instruction step** (`a4_step = arguzz_step + offset` from E0):
   - `COMP_OUT_MOD`@add → force the add's rd WRITE value = Arguzz's value.
   - `LOAD_VAL_MOD`@load-x → force the load's rd value = Arguzz's value.
   - `STORE_OUT_MOD`@store → force the store's mem data = Arguzz's value.
   - `INSTR_WORD_MOD_FULL`@add → force the fetch word = Arguzz's word.
3. Run via `run_a4(host, [], cfg_path, ...)`; capture the categorized footprint
   identically to E1. Note explicitly the executed-word vs fetched-word **mirror**
   for the `INSTR_WORD_MOD` pair.

**E2 gate:** configs use the **exact** Arguzz value/word; runs deterministic 2×;
footprints categorized; A4 column filled per E1 row.

### E3 — A4 surgical (`INSTR_WORD_MOD_SUR`)

**Deliverable:** `run_e3.py`, a SUR builder in `a4_config.py`, + `artifacts/e3/`.

1. Add a SUR builder to `a4_config.py`: `t = instr_word_mod_sur.get_targets_at_step(
   a4_step_of_add, data)`; for a chosen `SurgicalField`, `new_word =
   t.instruction.encode_with_mutation(field, new_value)`; then
   `instr_word_mod_sur.create_config(t, field, new_word, new_value, path)`.
2. At the **add's** fetch step, apply `_SUR` to individual fields and record which
   constraint(s) each breaks — **run rd-only, rs1-only, rs2-only as separate
   single-field configs** (this is the controlled test Arguzz can't do):
   - `FUNCT7`: ADD→SUB (`0x00`→`0x20`) — same R-type, different op.
   - `FUNCT3`: ADD→XOR/SLT etc.
   - `RD` only: change destination register (keep value-producing operands).
   - `RS1` only / `RS2` only: change one source register.
   - `IMM`/`OPCODE`: note format-validity caveats (skip if it produces an invalid
     decode that crashes preflight; record that as a separate outcome).
3. Capture categorized footprint per field; compare against E1/E2 `INSTR_WORD_MOD`.

**Hypothesis to test (user):** Arguzz register changes (E1) land **0-local / 1-global**
for BOTH dest and source regs, because the executor stays self-consistent (reads the
mutated reg, computes with it, writes it) and only the global memory permutation
catches the mismatch vs the fetched word. A4 SUR edits the **witness AFTER** the
executor ran the original, so a **source-register** SUR change is expected to break
**a local consistency check (decoded operand vs the recorded read txn) AND global** —
i.e. >1 broken constraint, of a different nature than Arguzz. E3 must confirm/deny
this rd-vs-src asymmetry explicitly.

**E3 gate:** per-field footprint table (rd/rs1/rs2/funct3/funct7 each as its own
single-field config); confirm/deny the source-register asymmetry above; document each
constraint's nature; deterministic; host sha-guard (A2b) asserted.

### E4 — Side-by-side comparison + write-up

**Deliverable:** `artifacts/e4/COMPARISON.md` (+ a machine-readable matrix).

1. Build the matrix per `(role, semantic mutation)`: **Arguzz** vs **A4-FULL** vs
   **A4-SUR** footprints, bucketed intrastep-local / interstep-local / global, with
   example `loc`+residue and ZIR provenance.
2. State the measured bias: Arguzz concentrates in **intrastep-local** (executor
   propagation suppresses interstep); A4 adds **interstep-local + global** (surgical
   witness edit leaves neighbors stale); `_SUR` **pinpoints a single** local
   constraint. Include the `INSTR_WORD_MOD` mirror explanation.
3. Intuitive (non-ZIR) prose per selected example for the thesis.

**E4 gate:** a coherent, provenance-backed local/interstep/global story across all
roles, every claim reproducible and tied to a cited residue.

---

## E. Per-task validation (all increments)
- **Determinism:** 2× identical runs, byte-identical categorized failure sets.
- **Provenance:** every cited residue predicted from the value delta == observed.
- **Isolation:** only `thesis_side_experiments/` changed; production host mtime
  unchanged after every `./build.sh`.
- **Tools:** outcome class via `classify.py`; categories via `categorize.py`;
  offset/sites via `guest_sites.py`; A4 configs via `a4_config.py`; build via
  `build.sh`; host = `minimal_add/target/release/thesis-minimal-host`.

## F. Acceptance
A reproducible, provenance-backed, side-by-side comparison over one tiny
load-add-store-readback guest showing, per semantic mutation, **which layer
(intrastep-local / interstep-local / global) each fuzzer breaks** and why
(executor propagation vs witness surgical edit), including the `INSTR_WORD_MOD_SUR`
single-constraint demonstration.

---

# BATCH 2 — the remaining mutation kinds (E5/E6)

Batch 1 (E0–E4) covered the cleanly-pairable in-place kinds. Batch 2 covers **every
remaining mutation kind in both fuzzers**, characterizing each into the same
intrastep-local / interstep-local / global layers, and producing the same family of
markdowns. We **reuse the Batch-1 engine almost entirely** (see G.3).

## G.0 Complete mutation inventory (verified from source)

**Arguzz — 10 kinds total** (`risc0-modified/.../execute/rv32im.rs`):

| kind | when | what it does | Batch 1? |
|---|---|---|---|
| `COMP_OUT_MOD` | in-place | overwrite compute write value | ✅ done |
| `LOAD_VAL_MOD` | in-place | overwrite load write value | ✅ done |
| `STORE_OUT_MOD` | in-place | overwrite store mem value | ✅ done |
| `INSTR_WORD_MOD` | in-place | overwrite fetched word (executed) | ✅ done |
| `PRE_EXEC_PC_MOD` | pre-exec | `set_pc(random)` **before** fetch → executes a different instruction | ⬜ **E5** |
| `PRE_EXEC_MEM_MOD` | pre-exec | `store_memory(rand_addr, rand)` **before** exec → extra mem WRITE | ⬜ **E5** |
| `PRE_EXEC_REG_MOD` | pre-exec | `store_register(rand_reg, rand)` **before** exec → extra reg WRITE | ⬜ **E5** |
| `POST_EXEC_PC_MOD` | post-exec | `set_pc(random)` **after** exec → corrupts next-pc | ⬜ **E5** |
| `POST_EXEC_MEM_MOD` | post-exec | `store_memory(rand_addr, rand)` **after** exec → extra mem WRITE | ⬜ **E5** |
| `POST_EXEC_REG_MOD` | post-exec | `store_register(rand_reg, rand)` **after** exec → extra reg WRITE | ⬜ **E5** |

The 6 remaining Arguzz kinds are the **Family-1** ("inject/overwrite a whole
transaction via the executor") set. They use `ctx.set_pc / store_memory /
store_register`, which add **real extra transactions** that the executor then has to
account for. **Expectation (itself a key finding):** several of these will **crash in
the executor/preflight before any constraint is checked** — e.g. `PRE_EXEC_REG_MOD`
is the known same-cycle R/W OOB panic in `wrap_memory_txns`. That "crash-before-
constraints" behavior is the Family-1 bias signature and must be **recorded as an
outcome** (`PROVE_ERROR` / `preflight_crash`), not treated as a harness failure.

**A4 — 7 kinds total** (`a4/standalone/mutations/__init__.py`):

| kind | what it edits in the witness | Batch 1? |
|---|---|---|
| `COMP_OUT_MOD` / `LOAD_VAL_MOD` / `STORE_OUT_MOD` | a write value | ✅ done |
| `INSTR_WORD_MOD` (FULL + SUR) | fetched word / one field | ✅ done |
| `MEM_VAL_MOD` | a memory READ value | ✅ done |
| `PRE_EXEC_REG_MOD` | a register READ/WRITE txn word (strategies `next_read`→IsRead+MemoryWrite, `prev_write`→MemoryWrite) | ⬜ **E5** |
| `INSTR_TYPE_MOD` | `cycles[].major/minor` (the decoded op-type columns, **without** touching the word) | ⬜ **E5** |

## G.1 Honest pairing note (read before designing)

Batch 2 does **not** pair as cleanly as Batch 1 — say so in the write-up. The genuine
cross-fuzzer pairs and the orphans:

- **Register corruption pair:** Arguzz `POST_EXEC_REG_MOD` (executor extra reg write)
  ↔ A4 `PRE_EXEC_REG_MOD` (witness reg-txn edit). Same intent (a register holds the
  wrong value), opposite stage → expected to reproduce the Batch-1 bias shape
  (Arguzz crashes/propagates; A4 reaches `MemoryWrite`/`IsRead`).
- **Operation-type triple:** A4 `INSTR_TYPE_MOD` (major/minor) vs A4
  `INSTR_WORD_MOD_FULL` (word, Batch 1) vs Arguzz `INSTR_WORD_MOD` (Batch 1). Three
  routes to "execute the wrong op type" — `INSTR_TYPE_MOD` flips only the selector
  columns, so it should isolate the **decode** break without the fetched-word memory
  residue that `INSTR_WORD_MOD_FULL` adds. This is the A4-only analogue of SUR for the
  op-type axis.
- **Memory-write orphans:** Arguzz `PRE/POST_EXEC_MEM_MOD` write to a **random**
  address; A4's only memory kind (`MEM_VAL_MOD`, Batch 1) edits a **read**. Related
  but not identical — compare layer footprints, don't claim a strict mirror.
- **PC orphans (Arguzz-only):** `PRE/POST_EXEC_PC_MOD` have **no A4 counterpart** (A4
  exposes no PC mutation). On a straight-line guest these mostly redirect into
  arbitrary/illegal instructions → executor/preflight crash; record as the Arguzz-only
  control-flow signature.

So Batch 2's value is **(a)** complete per-kind layer coverage and **(b)** the two real
pairs above; frame it that way rather than forcing 1:1 comparisons.

## G.2 Guest program — reuse the frozen one (recommendation + tradeoff)

**Recommendation: keep the exact frozen guest + `thesis-minimal-host` (sha
`5337f944…`) for E5. Do NOT recompile.** Reasons:

- REG, MEM, and `INSTR_TYPE_MOD` mutations need no new instructions — the existing
  `load → add → store → read-back` steps + stack/heap are sufficient targets, and the
  E0 `site_card.json` already names the steps.
- Recompiling changes the host SHA and **breaks comparability with E0–E4** and the
  frozen-binary contract (§A2b). Batch 2 must stay on the same binary so the matrices
  compose.
- The PC-mod crashes on straight-line code are a **legitimate finding**, not a gap.

**Optional E6 (only if you want it):** to characterize *meaningful, non-crashing*
control-flow redirection (PC mods that land on a valid in-program branch/loop target),
we'd need a richer guest with an explicit branch/loop. That is a **separate** program
built into a **separate binary + its own E0-style site card + its own frozen SHA**, run
as an isolated mini-campaign so it never contaminates the Batch-1/E5 binary. Decision
deferred to you — E5 does **not** require it.

## G.3 What we reuse vs. what is new

**Reuse as-is (no changes):** frozen host + guest + `artifacts/e0/site_card.json`;
`bias_campaign/run_arguzz.py`; `thesis_side_experiments/pos/thesis_run_pos.sh`
(P2-certified thin path, incl. the `"time":"…"` determinism strip);
`analyze_logs.py` + `categorize.py` + `touch_parse.py` (layer bucketing is
kind-agnostic and already classifies `PROVE_ERROR` + `preflight_crash` from the E1
amendment); `host_guard.py`; the `run_e4_matrix.py` matrix pattern; the POS
reservation/dispatch flow on **polynize** (>10 proofs ⇒ POS, per A3/POS_NOTES).

**New / extend (small):**
1. `a4_config.py`: add an **`INSTR_TYPE_MOD`** builder (emit `{"mutation_type":
   "INSTR_TYPE_MOD","step":a4_step,"major":M,"minor":m}`; pick a target op-type, e.g.
   ADD→SUB or ADD→XOR via the same major/minor the executor would use). `PRE_EXEC_REG_MOD`
   builder already exists — reuse with both strategies.
2. `bake_e5.py`: enumerate Batch-2 configs (Arguzz: 6 kinds × the frozen steps × a small
   seed sweep; A4: `PRE_EXEC_REG_MOD` both strategies + `INSTR_TYPE_MOD`).
3. `run_e5.py`: clone `run_e2.py` (tmux-on-coinbase dispatch, one reset, loop configs,
   pull+analyze locally). Same determinism / provenance / isolation / sha-guard gates.

## G.4 Workspace cleanup (E5 step 0 — do FIRST, verify nothing breaks)

The folder has accumulated pre-E0 cruft. Reorganize **conservatively**:

- `docs/` ← move the four explanatory docs: `CONSTRAINTS_EXPLAINED.md`,
  `A4_CONSTRAINTS_EXPLAINED.md`, `E4_COMPARISON.md`, and a copy/move of
  `artifacts/e4/MATRIX_GRANULAR.md` (standalone — safe to move).
- `specs/` ← `EXAMPLE_PLAN.md`, `E1_SPEC.md`, `E1_AMENDMENT.md`, `E2_POS_PREP_SPEC.md`,
  `E2_FULL_SPEC.md`, `E4_MATRIX_SPEC.md` (and the forthcoming `E5_SPEC.md`).
- `_archive/` ← clearly-dead pre-E0 files: `run_m0.py`–`run_m3.py`, `run_phases.py`,
  `verify_crash_condition.py`, `EXPERIMENT_PLAN_V2.md`, old `PLAN.md`, old `README.md`,
  and stale `artifacts/{m0,m1,m2,m3,verify_crash}`, plus loose
  `artifacts/*.txt`, `instruction_card.json`, `comparison_matrix.json`,
  `a4_mut*`, `arguzz_mut*`, `baseline_trace.txt`, `step_185_dump.txt`,
  `inspection_summary.txt`, `run_phases.log`.
- **Keep the active engine scripts at top level** (`run_e0/e1/e2/e4_matrix.py`,
  `analyze_logs.py`, `bake_e2_*.py`, `apply_e1_amendment.py`, `host_guard.py`,
  `build.sh`, `host/`, `methods/`, `frozen_host/`, `target/`) — moving them risks
  breaking relative paths/imports.
- Add a fresh top-level `README.md` indexing: program, engine scripts, specs/, docs/,
  artifacts/e0..e5, archive.
- **Gate:** before moving any file, `grep`/git-verify nothing active imports it; after
  the move, re-run `python3 run_e4_matrix.py` and confirm it still emits the identical
  `artifacts/e4/` outputs (no proving). Only then proceed to E5 proper.

## G.5 E5 — execution & deliverables

1. **Cleanup** (G.4) and gate.
2. **Arguzz (E5-A):** run all 6 Family-1 kinds at the frozen steps (a few seeds each)
   via `run_arguzz`. For each, capture outcome (incl. crash class) + categorized
   layers + the `<fault>` info. Document which kinds crash (executor/preflight) vs.
   which reach constraints, and at which layer.
3. **A4 (E5-B):** `PRE_EXEC_REG_MOD` (both `next_read` and `prev_write` strategies) and
   `INSTR_TYPE_MOD` at the relevant steps; capture footprints identically; note the
   `INSTR_TYPE_MOD` vs `INSTR_WORD_MOD_FULL` (Batch-1) op-type contrast.
4. **Scale rule:** Batch 2 is >10 proofs ⇒ **POS on polynize** via the thin path.
5. **Deliverables (mirror Batch 1):**
   - `artifacts/e5/` raw logs + per-run JSON + `e5_summary.md`.
   - Extend the granular matrix: `run_e4_matrix.py` (or `run_e5_matrix.py`) ingests
     `e5` too → `MATRIX_GRANULAR.md` now covers **all kinds**.
   - Extend `CONSTRAINTS_EXPLAINED.md` (Arguzz Family-1) and
     `A4_CONSTRAINTS_EXPLAINED.md` (`PRE_EXEC_REG_MOD`, `INSTR_TYPE_MOD`) with the same
     mutation→constraint→meaning→layer treatment.
   - An `E5_COMPARISON.md` (or a new section in `E4_COMPARISON.md`) for the two real
     pairs + the orphan coverage + the Family-1 "crash-before-constraints" finding.

**E5 gate:** every kind classified into a layer **or** a recorded crash class;
determinism 2×; provenance for every cited residue; host sha-guard asserted;
POS≡(local spot-check) where feasible; all markdowns regenerated.
