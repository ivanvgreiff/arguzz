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

# BATCH 2 — per-mutation-type constraint-distribution study (E5, workspace `full_sweep/`)

**Philosophy (this is the whole point — read carefully).** This is **not** a paired
comparison and **not** a matrix. For **each fuzzer** and **each of its mutation types**,
we **execute that mutation type many times** (N = 10 pilot, then 100) across a guest, and
for **every single execution** we record what it broke. We then **aggregate into a
distribution per mutation type**. The questions we answer are *distributional*:

> "When A4 runs `MEM_VAL_MOD`, what is the distribution of constraint layers it breaks,
> how often does it crash, and how often does it hit guest data?" … and across types:
> "**During-execution** (Arguzz) mutations tend to break *this* distribution of
> constraints; **post-execution / witness** (A4) mutations break *that* distribution."

We don't pair an Arguzz run to an A4 run. We don't align steps. We don't build a matrix.
We **collect a pile of per-execution records and compute statistics from it.**

New sibling workspace: **`thesis_side_experiments/full_sweep/`** (keeps `minimal_add/` as
the frozen Batch-1 record). Reuse the Batch-1 analysis engine almost entirely (G.3).

## G.0 The per-execution record (the data atom) and the stats we compute

**Each execution** (one fuzzer, one mutation type, one sample = a distinct seed/target)
emits ONE JSON record:

```
{ fuzzer, mutation_type, sample_id,
  inject: { step, pc, instr_at_site, target_kind: reg|mem|pc|word|txn, target_addr_or_reg },
  target_region: guest_data | guest_code | stack | machine_kernel | bootloader | other,
  hits_guest_data: bool,
  outcome_class: ACCEPTED|CONSTRAINT_REJECT|GLOBAL_REJECT|VERIFY_REJECT|PREFLIGHT_CRASH|OTHER_CRASH,
  crashed: bool, crash_stage: executor|preflight|witgen|null,
  layers: { intrastep_local: int, interstep_local: int, global: int },
  constraints: [ {loc, category, residue, provenance_verified}, ... ] }     # granular, as Batch 1
```

**Aggregates computed per (fuzzer, mutation_type)** from the atoms:
- `n`, `crash_rate` (and breakdown by `crash_stage`), `reached_constraints_rate`.
- **Layer reach:** `P(intrastep≥1)`, `P(interstep≥1)`, `P(global≥1)`; mean count per
  layer; the histogram of `(i/inter/g)` triples.
- `guest_data_hit_rate` (esp. for the random-target Arguzz kinds).
- **Top constraints** broken (frequency table over `loc`).

**Stage rollups** (the headline grouping):
- Arguzz **pre-exec** (`PRE_EXEC_*`) · **in-place** (`COMP/LOAD/STORE_OUT_MOD`,
  `INSTR_WORD_MOD`, `BR_NEG_COND`) · **post-exec** (`POST_EXEC_*`).
- A4 **witness-value** (`COMP/LOAD/STORE_OUT_MOD`) · **witness-word/type**
  (`INSTR_WORD_MOD` FULL/SUR, `INSTR_TYPE_MOD`) · **witness-mem-read** (`MEM_VAL_MOD`) ·
  **witness-reg** (`PRE_EXEC_REG_MOD`).
→ report the layer distribution per stage family. This is the deliverable.

## G.0c Keep ALL raw information (lossless retention) + flag contract

**Rule: stats are derived; the raw evidence is never discarded.** Every analysis we
might later want must be reconstructable from disk **without re-running anything**. So we
retain three tiers:

1. **One-time, per-guest context (captured once in E5-E0, stored verbatim):** the full
   clean-baseline trace inspection — `A4_INSPECT` cycle dump + `A4_DUMP_ALL_TXNS` (every
   `cycle`/`txn` with step/pc/major/minor/addr/word), the memory-region map
   (`platform.rs`), the guest ELF + disassembly, and the recorded binary SHA. This is
   the shared "what does the program look like" reference for all atoms — captured once
   because the guest is deterministic, so it never changes across runs.
2. **Per-execution complete raw log (gzipped, kept forever):** the **entire** stdout+stderr
   of every run, containing every emitted tag — `<fault>` / `<a4_*>` mutation descriptors,
   **all** `<constraint_fail>` lines (loc + value), `<a4_touch_verbose>` touched-set,
   family residues, global residue, verifier result. Plus the exact `cmd`, `env`, and
   A4 config JSON used (full reproducibility). The raw log **is** the ground truth; the
   atom is just a parsed convenience view.
3. **Per-execution parsed atom (the G.0 JSON):** derived from the raw log; carries the
   `raw_log_path` + `config_path` back-pointers so any field can be re-derived/audited.

`compute_e5_stats.py` reads **only the atoms**; if we ever want a new metric we re-parse
the retained raw logs — no proofs re-run. (This is exactly how Batch 1's E4 matrix and
the source-register re-verification were done from retained logs.)

**Flag contract (run-time env only — nothing compiled, nothing outside the workspace):**
`CONSTRAINT_CONTINUE=1`, `A4_COVERAGE_TOUCH_VERBOSE=1`, `A4_FAMILY_RESIDUE=1`,
`A4_GLOBAL_RESIDUE=1` for **both** fuzzers (identical to Batch 1, so layer classification
is consistent); Arguzz adds its CLI `--inject …`; A4 adds `A4_MUTATION_CONFIG=…`. All of
these are already read by the existing binary — **verified present** in
`witgen/mod.rs`, `hal/mod.rs`, `rv32im-sys/kernels/cxx/{witgen.h,ffi.cpp}`,
`execute/rv32im.rs`. The `INSTR_TYPE_MOD` handler is also **already present**
(`witgen/mod.rs:262`); we only emit the config JSON it consumes.

> **Zero external changes confirmed.** Batch 2 adds only: (a) a new **guest** under
> `full_sweep/` (→ a new binary in `full_sweep/target/`), (b) an `INSTR_TYPE_MOD` config
> builder in `bias_campaign/a4_config.py`, (c) sampling/run/stats scripts. It touches
> **no** code in `workspace/risc0-modified/`, `a4/`, `fuzzer_utils/`, or any other
> binary, and never rebuilds the Batch-1 `minimal_add` binary.

## G.0a Complete mutation inventory (each is sampled N times)

**Arguzz — 11 kinds** (canonical enum `projects/risc0-fuzzer/risc0_fuzzer/kinds.py`
`InjectionKind`; handlers `risc0-modified/.../execute/rv32im.rs`):
`COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `INSTR_WORD_MOD`, `BR_NEG_COND`
(branch-only), `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`,
`POST_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD`.

**A4 — 7 kinds** (`a4/standalone/mutations/__init__.py`; handlers
`risc0-modified/.../prove/witgen/mod.rs`): `COMP_OUT_MOD`, `LOAD_VAL_MOD`,
`STORE_OUT_MOD`, `INSTR_WORD_MOD` (FULL + SUR), `MEM_VAL_MOD`, `PRE_EXEC_REG_MOD` (both
strategies), `INSTR_TYPE_MOD`.

Sample **every** type (incl. the Batch-1 types) on the new guest so all distributions are
measured on the same program. `BR_NEG_COND` requires a branch in the guest (G.2).

## G.0b Tracked metrics & non-issues (replaces the old "caveats")

Per your direction, the old comparability complications are now either a **tracked
metric** or a **non-issue**, not a blocker:

1. **Different stage** → **not a problem; it is the grouping axis** (during-exec vs
   post-exec vs witness distributions). No action needed.
2. **Arguzz random reg/addr/pc** → fine; **track `hits_guest_data` per execution** and
   report `guest_data_hit_rate` per type. No normalization required.
3. **Index/PC offset** → **dropped.** It only mattered for step-matched pairing. We do
   not pair, so **no offset derivation, no A4-step alignment** is needed.
4. **Crashes** → fine; **track `crash_rate` + `crash_stage` per type** (and which
   mutation caused it). A crash is a recorded outcome, not a discarded run. (Note for the
   write-up: the modified prover's commented-out `ensure!` may inflate Arguzz crash rate
   vs stock — mention as a caveat; an "Arguzz-clean" binary to measure the true rate is
   deferred.)
5. **Menu/orphan mismatch** → **irrelevant** (no matrix). Each fuzzer simply reports its
   own list of type-distributions.
6. **A4 selector / instruction-kind** → **irrelevant.** We force the mutation type
   directly and only read A4's mutation-induced constraint data; A4's bandit/zone
   architecture is not used and does not affect these per-type distributions.

## G.2 Guest program — one broad guest in a new binary

**Build a new BROAD guest in a SEPARATE binary in `full_sweep/`.** Per-proof time is
~unchanged vs a minimal guest (RISC0 pads to the same segment po2); breadth only adds more
**injection sites**, which is exactly what we want for sampling N executions per type.

**Required instruction coverage** (composer designs exact Rust; compile deterministically
— fixed iteration counts, baked operands, `read_volatile`/`write_volatile` + `black_box`):
- **Compute variety:** `add`, `sub`, `xor`/`or`/`and`, a shift (`sll`/`srl`), `mul`.
- **Memory variety:** `lb`/`lh`/`lw` loads and `sb`/`sh`/`sw` stores, plus a read-back.
- **Control flow:** ≥1 conditional **branch** exercised both taken and not-taken (for
  `BR_NEG_COND`), and a **counted loop** (backward jump) to give PC mods real targets.

The richer the instruction mix, the more distinct sites each type can sample.

**Site/region map (for `target_region` classification, NOT for pairing):** E5-E0 builds a
`site_card.json` listing the guest's instruction steps + the memory-map regions
(guest-code, guest-data/heap, stack, machine/kernel/bootloader) from
`.../execute/platform.rs`, so each execution's target can be classified guest vs
non-guest. **No Arguzz↔A4 offset is computed** (not needed).

**Isolation contract** (mirrors §A/§A2b):
- New guest + `host/` (host source reused verbatim) + `build.sh` + `target/` under
  **`full_sweep/`**, with its **own frozen `frozen_host/` + recorded SHA** after build.
- Building it must **never** touch `workspace/output/` or the `minimal_add` binary.
  Assert both SHAs (Batch-1 `5337f944…` unchanged; new sha recorded then frozen).
- **E5-E0 gate:** clean baseline run → verifier success + 0 residue + reproducible.

## G.3 Sampling design + what we reuse vs. build new

**Sampling (how we get N executions per type):**
- **Arguzz:** for type `K`, run N samples by sweeping `--inject-kind K` over the guest's
  instruction sites × seeds (for the random kinds, different seeds give different
  reg/addr/pc/word — that variety is the distribution we want). Record where each landed
  + its `target_region`.
- **A4:** for type `K`, enumerate/sample N valid target transactions of the right shape
  across the trace; build a config per sample.
- **N (recommended):** pilot **N=20** per type to validate the pipeline + see rough
  shapes; then **N=100** per type for the real distributions. Spread each type's N
  across its applicable sites (≈ `ceil(N/#sites)` seeds per site) so the distribution
  samples site variety, not just RNG variety. For the random-target kinds (PC/MEM/REG),
  N=100 already gives wide reg/addr/pc variety; bump to **N=200** for those if their
  guest-data-hit / crash distributions look under-sampled. Budget: 100×(11 Arguzz + 8 A4
  variants) ≈ 1900 runs ≈ **~1.6h** on one fast node; pilot ≈ ~12 min. (N is a knob — the
  retained raw logs mean we can always add more samples later and re-aggregate.)
- **Determinism:** we already proved determinism in Batch 1 — so **spot-check** a random
  ~10% of samples 2× (byte-identical categorized set), not every run, to preserve sample
  variety and budget.

**Reuse as-is:** `bias_campaign/run_arguzz.py`; `pos/thesis_run_pos.sh` (P2-certified thin
path + `"time"` strip); `analyze_logs.py` + `categorize.py` + `touch_parse.py` (layer
bucketing + crash classification); `host_guard.py`; POS dispatch on **polynize**.

**New / build:**
1. **New guest + binary** (G.2) + `run_e5_e0.py` (baseline + region map).
2. `a4_config.py`: add an **`INSTR_TYPE_MOD`** builder. `PRE_EXEC_REG_MOD` exists already.
3. `sample_e5.py`: enumerate the N-per-type sample set (Arguzz 11 + A4 8 variants), each
   tagged `fuzzer, mutation_type, sample_id, site`.
4. `run_e5.py`: clone `run_e2.py` dispatch; per execution emit the **G.0 atom** JSON.
5. `compute_e5_stats.py`: ingest all atoms → `e5_stats.json` + `DISTRIBUTIONS.md`
   (per-type tables + per-stage rollups + the headline layer distributions). **No
   matrix.**

## G.4 Workspace cleanup (E5 step 0 — do FIRST, verify nothing breaks)

The `minimal_add/` folder has accumulated pre-E0 cruft. Reorganize **conservatively**:

- `docs/` ← move the explanatory docs: `CONSTRAINTS_EXPLAINED.md`,
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
- The **new Batch-2 guest** gets its own sub-workspace (G.2), so it does not re-clutter
  `minimal_add/`.
- Add a fresh top-level `README.md` indexing: programs, engine scripts, specs/, docs/,
  artifacts/e0..e5, archive.
- **Gate:** before moving any file, `grep`/git-verify nothing active imports it; after
  the move, re-run `python3 run_e4_matrix.py` and confirm it still emits identical
  `artifacts/e4/` outputs (no proving). Only then proceed.

## G.5 E5 — execution & deliverables

1. **Cleanup** (G.4) + gate.
2. **E5-E0:** new broad guest, build, region map, clean baseline (G.2 gate). No offset.
3. **Pilot (N=10/type):** `sample_e5.py` → `run_e5.py` → atoms; `compute_e5_stats.py`.
   Sanity-check shapes (e.g. value kinds reach constraints; some Family-1 kinds crash;
   `BR_NEG_COND` actually fires on a branch). Fix anything before scaling.
4. **Full run (N=100/type)** on POS via the thin path. **Node:** `polynize` (and the
   user's other current nodes) are **busy ~30h** — so **reserve a NEW dedicated, fast
   (Tier S/A), non-shared node** from the many free ones, image **`debian-trixie`**
   (GLIBC 2.39+), per the POS hard rules in `bias_campaign/POS_NOTES.md` (calendar entry
   first; if at the 2-entry cap, edit an existing entry to add the node; never use a node
   another agent is using). The whole sweep fits comfortably in one allocation (~1.6h);
   only shard across multiple nodes if N is scaled way up later.
5. **Compute stats** from the atoms (no proving): per-type and per-stage distributions.
6. **Deliverables:**
   - `artifacts/e5/atoms/*.json` — one G.0 record per execution (the raw data).
   - `artifacts/e5/e5_stats.json` — per-(fuzzer,type) aggregates: `n`, `crash_rate`
     (by stage), `reached_constraints_rate`, layer-reach probabilities, mean layer
     counts, `(i/inter/g)` histogram, `guest_data_hit_rate`, top-constraint frequencies;
     plus the stage rollups.
   - `DISTRIBUTIONS.md` — readable per-type tables, the per-stage layer distributions
     (the headline: during-exec vs post-exec vs witness), and the granular notes (top
     constraints per type, crash modes, guest-data hit rates). **No matrix.**
   - **Extend** `CONSTRAINTS_EXPLAINED.md` (Arguzz `BR_NEG_COND` + PC/MEM/REG kinds) and
     `A4_CONSTRAINTS_EXPLAINED.md` (`PRE_EXEC_REG_MOD`, `INSTR_TYPE_MOD`) with the
     mutation→constraint→meaning→layer treatment for the new types.

**E5 gate:** every sampled execution produces a complete G.0 atom (layer counts **or** a
recorded crash class); N met per type; `BR_NEG_COND` exercised on a branch; determinism
spot-check (~10%) byte-identical; provenance verified on cited residues; both host SHAs
guarded; `e5_stats.json` + `DISTRIBUTIONS.md` regenerated from atoms.
