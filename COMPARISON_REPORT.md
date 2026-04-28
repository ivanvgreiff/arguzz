# Detailed Comparison: zkVMBlast trace-mutation vs A4 vs Arguzz

## Witness / Trace Mutation Approaches for RISC Zero Soundness Testing

This report provides a thorough, side-by-side comparison of three distinct approaches to testing RISC Zero prover soundness through witness or trace manipulation:

1. **zkVMBlast `trace-mutation`** (`zkvmBlast/trace-mutation/`) -- Malicious prover simulation that re-executes honest traces, mutates witness buffers or replays forged preflight, then attempts to prove and verify.
2. **A4** (`a4/`) -- Post-preflight trace mutation that patches risc0's `witgen/mod.rs` to corrupt the `PreflightTrace` struct before witness generation.
3. **Arguzz** (`workspace/risc0-modified/`) -- During-execution fault injection that hooks into `Emulator::step()` in the risc0 rv32im executor to corrupt live VM state.

---

## Table of Contents

- [1. Architecture Overview](#1-architecture-overview)
- [2. Where Mutation Happens in the RISC Zero Pipeline](#2-where-mutation-happens-in-the-risc-zero-pipeline)
- [3. zkVMBlast trace-mutation: Detailed Analysis](#3-zkvmblast-trace-mutation-detailed-analysis)
  - [3.1 Framework (lib.rs)](#31-framework-librs)
  - [3.2 RISC0 v2 Implementation](#32-risc0-v2-implementation)
  - [3.3 RISC0 v3 Implementation](#33-risc0-v3-implementation)
  - [3.4 Mutation Strategies](#34-mutation-strategies)
- [4. A4: Detailed Analysis](#4-a4-detailed-analysis)
  - [4.1 Injection Mechanism](#41-injection-mechanism)
  - [4.2 Mutation Types](#42-mutation-types)
  - [4.3 Step and Target Selection](#43-step-and-target-selection)
  - [4.4 Value Generation](#44-value-generation)
  - [4.5 Oracles and Coverage](#45-oracles-and-coverage)
- [5. Arguzz: Detailed Analysis](#5-arguzz-detailed-analysis)
  - [5.1 Injection Mechanism](#51-injection-mechanism)
  - [5.2 Injection Kinds](#52-injection-kinds)
  - [5.3 Value Generation](#53-value-generation)
  - [5.4 Fuzzer Loop and Step Selection](#54-fuzzer-loop-and-step-selection)
- [6. Comparative Analysis](#6-comparative-analysis)
  - [6.1 Mutation Point in the Pipeline](#61-mutation-point-in-the-pipeline)
  - [6.2 Mutation Type Mapping](#62-mutation-type-mapping)
  - [6.3 Value Generation Comparison](#63-value-generation-comparison)
  - [6.4 Step/Target Selection Comparison](#64-steptarget-selection-comparison)
  - [6.5 Oracle Comparison](#65-oracle-comparison)
  - [6.6 Coverage and Feedback Comparison](#66-coverage-and-feedback-comparison)
  - [6.7 RISC0 Internals Access](#67-risc0-internals-access)
  - [6.8 Proving Pipeline Comparison](#68-proving-pipeline-comparison)
- [7. Key Differences Summary](#7-key-differences-summary)
- [8. Unique Capabilities](#8-unique-capabilities)

---

## 1. Architecture Overview

### zkVMBlast trace-mutation

A Rust crate (`trace-mutation/`) that implements a `MaliciousProver` trait. It honestly executes a guest program, captures the full witness (data/code/global column buffers + `PreflightTrace`), applies a `MutationStrategy` to these artifacts, then manually drives the RISC Zero prover from the mutated witness and attempts verification. The crate depends on forked risc0 repos (`zkvms/risc0-v2` on branch `v2-pub`, `zkvms/risc0-v3` on branch `v3-pub`) where internal types have been made `pub` to allow external construction of `WitnessGenerator`, `Prover`, etc.

### A4

A Python + Rust hybrid system. Python orchestrates fuzzing (step selection, value generation, bandit scheduling, coverage tracking) and produces JSON mutation configs. Rust patches are injected into risc0's `prove/witgen/mod.rs` at build time, which read the JSON config after `segment.preflight()` returns and mutate the `PreflightTrace` struct in-place before witness generation proceeds normally. The standard risc0 prover then runs on the corrupted trace.

### Arguzz

A Python + Rust hybrid system. Python drives the fuzzer loop and generates execution parameters. Rust modifications live inside a forked risc0 executor (`workspace/risc0-modified/`), specifically in `Emulator::step()` within `rv32im.rs`. During guest execution, at a specified step number, the emulator corrupts live VM state (PC, registers, memory, instruction words, branch conditions, ALU outputs). The corrupted execution then flows through the standard segment/prove/verify pipeline.

---

## 2. Where Mutation Happens in the RISC Zero Pipeline

The RISC Zero proving pipeline has these stages:

```
Guest ELF → Executor (Emulator::step loop) → Session (Segments)
    → per Segment: preflight() → PreflightTrace
    → WitnessGenerator (scatter trace into column buffers)
    → Prover (commit groups, FRI, finalize → seal)
    → Receipt → Verifier
```

Each tool targets a different stage:

| Tool | Mutation Point | Stage |
|------|---------------|-------|
| **Arguzz** | Inside `Emulator::step()` | Executor (during execution) |
| **A4** | After `segment.preflight()`, before witness generation | Between preflight and witgen |
| **zkVMBlast** | After `WitnessGenerator::new()`, mutates captured buffers or replays forged preflight | After witgen (buffer mutation) or replayed preflight (forged execution) |

---

## 3. zkVMBlast trace-mutation: Detailed Analysis

### 3.1 Framework (lib.rs)

The framework defines three core abstractions:

**`CorruptionOutcome`** -- the result of a malicious proving attempt:
- `ProverRejected { reason }` -- the prover crashed or failed constraints
- `VerifierRejected { reason }` -- proof was produced but verifier rejected it
- `VerifierAccepted` -- **soundness bug**: verifier accepted a proof from corrupted data
- `HarnessError { reason }` -- infrastructure error (mutation not applicable, etc.)

`CorruptionOutcome::is_soundness_bug()` returns `true` only for `VerifierAccepted`.

**`MutationStrategy<Trace>`** -- trait with two methods:
- `fn name(&self) -> &str` -- human-readable name
- `fn mutate(&self, trace: &mut Trace) -> bool` -- mutate the trace in-place; returns `false` if the strategy is not applicable to this trace

**`MaliciousProver`** -- trait defining the simulation pipeline:
- `fn execute(&self) -> Result<Self::Trace>` -- honest execution, captures witness
- `fn prove_trace(&self, trace: Self::Trace) -> Result<Self::Proof>` -- prove from (possibly mutated) trace
- `fn verify(&self, proof: &Self::Proof) -> Result<()>` -- verify the proof
- `fn run(&self, strategy: &dyn MutationStrategy<Self::Trace>) -> CorruptionOutcome` -- orchestrates: execute → mutate → prove → verify

The `run` method maps failures as follows:
1. `execute()` fails → `HarnessError`
2. `mutate()` returns `false` → `HarnessError("mutation not applicable")`
3. `prove_trace()` fails → `ProverRejected`
4. `verify()` fails → `VerifierRejected`
5. `verify()` succeeds → `VerifierAccepted`

### 3.2 RISC0 v2 Implementation

**File: `trace-mutation/src/risc0_v2/mod.rs`**

The v2 prover captures witness data after honest execution:

**`SegmentWitness`** -- per-segment captured state:
```rust
pub struct SegmentWitness {
    pub inner_segment: Segment,      // the resolved segment
    pub output: Option<Output>,      // segment output claim
    pub index: u32,                  // segment index
    pub data_values: Vec<Val>,       // flattened data column buffer
    pub code_values: Vec<Val>,       // flattened code column buffer
    pub global_values: Vec<Val>,     // flattened global column buffer
    pub trace: PreflightTrace,       // cloned preflight trace
    pub rand_z: ExtVal,              // random challenge for permutation check
    pub cycles: usize,               // number of rows (= witgen.data.rows)
    pub po2: u32,                    // log2 of padded cycle count
}
```

**`Risc0Trace`** -- the full captured execution:
```rust
pub struct Risc0Trace {
    pub session: Session,
    pub segment_witnesses: Vec<SegmentWitness>,
}
```

**`execute()`** -- honest execution and witness capture:
1. Build `ExecutorEnv` with guest input, create `ExecutorImpl::from_elf`, call `run()` to get `Session`
2. For each segment in the session:
   - `segment.resolve()` to get the inner segment
   - Generate random `rand_z: ExtVal`
   - Call `WitnessGenerator::new(&hal, &circuit_hal, &segment.inner, StepMode::Parallel, rand_z)` -- this is the same code path as the real prover
   - Extract `data_values`, `code_values`, `global_values` via `.to_vec()` on the HAL buffers
   - Clone `witgen.trace` (the `PreflightTrace`)
   - Record `cycles = witgen.data.rows`

**`prove_trace()`** -- proving from captured (and possibly mutated) witness:
1. For each `SegmentWitness`, call `prove_from_witness()` to produce a seal
2. Decode `ReceiptClaim` from the seal, merge segment output
3. Build `SegmentReceipt` with the correct hash function and verifier parameters
4. **Critical**: For the last segment, patch `claim.output` to include the journal digest from `session.journal` (which may have been forged by `SubConfusion`)
5. Assemble `CompositeReceipt` → `Receipt`

**`prove_from_witness()`** -- low-level proving from flat buffers:
1. Reconstruct `MetaBuffer` objects for global/code/data from the flat `Vec<Val>` arrays with correct rows/cols dimensions (`REGCOUNT_GLOBAL`, `REGCOUNT_CODE`, `REGCOUNT_DATA`)
2. Allocate fresh `accum` buffer initialized to `Val::INVALID`
3. Create `Prover`, write seal version, commit `PROOF_SYSTEM_INFO` and `CIRCUIT_INFO`
4. Build header from globals + `po2`, hash and commit
5. `commit_group` for code and data register groups
6. Sample `mix_vals` from IOP
7. Build a `WitnessGenerator` struct with the mutated buffers and cloned `PreflightTrace`
8. Call `witgen.accum()` -- this is the accumulation/permutation check step that uses the `PreflightTrace`
9. `commit_group` for accum register group
10. `prover.finalize()` → seal

**File: `trace-mutation/src/risc0_v2/preflight.rs`**

This implements a **forged preflight** -- re-executing the segment with memory overrides:

**`MemoryOverride`**: `{ cycle: u32, addr: u32, forged_word: u32 }`

**`ForgedPreflight`** wraps a real `Preflight` and intercepts `load_u32()`:
- For `LoadOp::Peek`: delegates to inner (no trace recording)
- For `LoadOp::Record`: if the current cycle and address match an override, pushes a **self-canceling transaction** (`prev_cycle == cycle`) with the forged word and returns it
- Otherwise: delegates to inner

The self-canceling transaction (`prev_cycle == cycle`) is the core of the SubConfusion exploit: it creates a memory read that claims its previous value was set at the same cycle, which in v2 was not properly validated.

**`run_forged_preflight()`**: Runs a full preflight with the forged context:
1. `read_pages()` -- load initial memory
2. Body loop: `Emulator::new()`, `Risc0Machine::resume`, step until `user_cycles >= suspend_cycle`, then `suspend()`
3. `write_pages()`
4. `generate_tables()`, `wrap_memory_txns()`, `update_p2_zcheck()`
5. Return the forged `PreflightTrace`

**File: `trace-mutation/src/risc0_v2/witgen.rs`**

**`generate_witness_from_preflight()`**: Reimplements the post-preflight half of `WitnessGenerator::new()`:
1. Calculate `cycles = 1 << segment.po2`
2. Build global vector: `state_in` from segment claim, input digest, `trace.rand_z`, termination flags, shutdown cycle
3. Allocate code and data buffers
4. Set up `Injector`: for each row, scatter ecall/poseidon2/sha2/bigint backs from `trace.backs`
5. Call `circuit_hal.generate_witness(mode, &trace, &global, &data)` -- the C++ step execution
6. Zeroize buffers
7. Return `WitnessGenerator` with the forged trace

### 3.3 RISC0 v3 Implementation

The v3 implementation (`trace-mutation/src/risc0_v3/`) follows the same structure with key differences:

**`Risc0V3Trace`** adds a `mutation_error: Option<String>` field. When the forged preflight fails (specifically at `wrap_memory_txns()` which now validates `cycle != prev_cycle`), the error is stored rather than causing an immediate failure. `prove_trace()` checks for this and returns `Err` → `ProverRejected`.

**v3 `preflight.rs`** differences:
- `on_insn_start` takes `InsnKind` and `DecodedInstruction` (v2 took `&Instruction`)
- `run_forged_preflight` includes `read_povw_nonce()` before `read_pages()` (v3 PoVW mechanism)
- `wrap_memory_txns()` in v3 rejects self-canceling transactions where `cycle == prev_cycle`

**v3 `witgen.rs`** uses `PreflightResults` struct and `build_global_vec`/`build_injector` helper functions from the v3 circuit crate rather than manually constructing the global layout.

**v3 `SubConfusion::mutate()`** differences:
- On `run_forged_preflight` error: stores the error in `trace.mutation_error` and returns `true` (so `run()` proceeds to `prove_trace()`, which fails with `ProverRejected`)
- This models the expected behavior: v3 has the fix for GHSA-g3qg-6746-3mg9, so the forged preflight should be rejected

### 3.4 Mutation Strategies

zkVMBlast implements three strategies for RISC0:

**`Identity`**: No mutation. Returns `true` without modifying anything. Used as a baseline -- if the honest trace fails to prove/verify, the infrastructure has a bug.

**`FlipDataCell`**: Minimal buffer corruption.
- Takes an `index` parameter (default: 510)
- Adds `Val::ONE` to `data_values[index % len]` in the first non-empty segment
- This directly corrupts one field element in the data column buffer
- Expected outcome: `ProverRejected` or `VerifierRejected` (constraint mismatch)

**`SubConfusion`**: GHSA-g3qg-6746-3mg9 exploit reproduction.
1. For each segment, run honest `preflight()` and scan `cycles` in reverse for a `sub` instruction (`major == 0, minor == 1`)
2. Verify the transaction layout matches expected operands (hardcoded: `txns[base+1].word == 7`, `txns[base+2].word == 5`)
3. Record the `rs2` register's cycle and address from the transaction
4. Run `run_forged_preflight()` with a `MemoryOverride` that replaces the `rs2` read with the `rs1` value (making `sub` compute `rs1 - rs1 = 0` instead of `rs1 - rs2`)
5. Generate fresh witness from the forged preflight via `generate_witness_from_preflight()`
6. Replace the segment's `data_values`, `code_values`, `global_values`, `trace`, and `cycles`
7. Forge `session.journal` to `Journal::new(0u32.to_le_bytes())` (the result the forged computation would produce)
8. On v2: expected `VerifierAccepted` (the bug). On v3: expected `ProverRejected` (the fix).

---

## 4. A4: Detailed Analysis

### 4.1 Injection Mechanism

A4 injects mutation logic into risc0's `prove/witgen/mod.rs` at build time via Python-generated Rust patches.

**File: `a4/injection/patches/mod_rs_patch.py`**

The patch replaces `let trace = segment.preflight(rand_z)?;` with `let mut trace = segment.preflight(rand_z)?;` and inserts a large block of Rust code that:

1. Reads `A4_MUTATION_CONFIG` environment variable (path to a JSON file)
2. Sets `FAULT_INJECTION_ENABLED=1` (unless `A4_NO_FAULT_INJECTION=1`) to relax address-mismatch panics
3. Parses the JSON config using simple string-matching helpers (not a full JSON parser)
4. Dispatches to the appropriate mutation block based on `mutation_type`
5. Mutates `trace.cycles[]` and/or `trace.txns[]` in-place
6. Witness generation then proceeds normally with the corrupted trace

**File: `a4/injection/patches/hal_mod_rs_patch.py`**

Forces `StepMode::SeqForward` when `A4_MUTATION_CONFIG` is set. Without this, parallel witness generation causes SIGSEGV crashes because corrupted transaction data leads to out-of-bounds accesses in other threads.

### 4.2 Mutation Types

A4 implements 7 mutation types, each targeting different fields of the `PreflightTrace`:

#### INSTR_TYPE_MOD
- **What it mutates**: `trace.cycles[].major` and/or `trace.cycles[].minor` for the first cycle where `user_cycle == target_step`
- **Effect**: Changes the instruction type classification. For example, turning a MUL cycle (major 3) into a MISC cycle (major 0), or a regular instruction into an ECALL, SHA, Poseidon, or BigInt cycle type
- **No Arguzz equivalent**: Arguzz cannot change cycle types because cycle type classification happens during preflight, not during execution
- **JSON**: `{"mutation_type": "INSTR_TYPE_MOD", "step": N, "major": M, "minor": K}`
- **Python target selection**: Only selects steps where `cycle.major in {0..6}` (instruction cycles). Value generation picks from valid `(major, minor)` pairs 75% of the time, invalid pairs 25%

#### INSTR_WORD_MOD
- **What it mutates**: `trace.txns[fetch_txn_idx].word` AND `trace.txns[fetch_txn_idx].prev_word` (both set to the new word)
- **Target**: The instruction-fetch transaction at the cycle's `txn_idx`. Only fires for cycles with `major <= 6` or `major == 8` (instruction cycles or ECALL)
- **Effect**: Changes the instruction word stored in the trace, which will cause the witness to contain instruction data inconsistent with the execution
- **JSON**: `{"mutation_type": "INSTR_WORD_MOD", "step": N, "word": W}`
- **Value generation**: Two sub-variants:
  - `INSTR_WORD_MOD_FULL`: bit flip (1 bit), multi-bit flip, or random with low 2 bits `0x03`; validated to be a decodable RV32IM instruction
  - `INSTR_WORD_MOD_SUR` (surgical): field-level mutations of the RISC-V instruction encoding (e.g., change `rd`, `funct3`, immediate)

#### COMP_OUT_MOD
- **What it mutates**: `trace.txns[txn_idx].word` only (prev_word unchanged)
- **Target**: The last register WRITE transaction at the target step, for steps with `cycle.major in {0,1,2,3,4}` (compute instructions: MISC, MUL, DIV)
- **Effect**: Changes the computation result written to the destination register in the trace
- **JSON**: `{"mutation_type": "COMP_OUT_MOD", "step": N, "txn_idx": T, "word": W}`

#### LOAD_VAL_MOD
- **What it mutates**: `trace.txns[txn_idx].word` only (prev_word unchanged)
- **Target**: Same as COMP_OUT_MOD but only for `cycle.major == 5` (MEM0 load instructions)
- **Effect**: Changes the value loaded from memory that is written to the destination register
- **JSON**: `{"mutation_type": "LOAD_VAL_MOD", "step": N, "txn_idx": T, "word": W}`

#### STORE_OUT_MOD
- **What it mutates**: `trace.txns[txn_idx].word` only
- **Target**: The last memory WRITE transaction at the target step, for `cycle.major == 6` (MEM1 store instructions)
- **Effect**: Changes the value written to memory by a store instruction
- **JSON**: `{"mutation_type": "STORE_OUT_MOD", "step": N, "txn_idx": T, "word": W}`

#### PRE_EXEC_REG_MOD
- **What it mutates**: `trace.txns[txn_idx].word` only
- **Target**: A register transaction at the target step. Two strategies:
  - `next_read`: targets register READ transactions (changes a source register value)
  - `prev_write`: targets register WRITE transactions (changes a destination register value)
- **Rust validation**: Checks `txn.cycle % 2` matches the strategy (even = read, odd = write)
- **JSON**: `{"mutation_type": "PRE_EXEC_REG_MOD", "step": N, "txn_idx": T, "word": W, "strategy": "next_read"}`

#### MEM_VAL_MOD
- **What it mutates**: `trace.txns[txn_idx].word` only
- **Target**: Memory transactions that are NOT:
  - Instruction fetches (first READ at each step)
  - Register transactions (address in register file range)
  - Store final writes (covered by STORE_OUT_MOD)
- **Transaction types covered**:
  - `load_mem_read`: Data read from memory during a load instruction
  - `store_rmw_read`: The read-modify-write read during a store instruction
  - `other_mem_read` / `other_mem_write`: Memory traffic from system calls (SHA2, Poseidon2, BigInt precompiles)
- **JSON**: `{"mutation_type": "MEM_VAL_MOD", "step": N, "txn_idx": T, "word": W}`

#### Notable Absence: PRE_EXEC_PC_MOD
A4 explicitly does NOT support PC mutation because the circuit computes PC internally -- it is not read from the preflight trace.

### 4.3 Step and Target Selection

**Inspection phase**: Before fuzzing, A4 runs one execution with `A4_INSPECT=1` and `A4_DUMP_ALL_TXNS=1` to collect:
- All cycle info (`A4CycleInfo`: cycle_idx, step, pc, txn_idx, major, minor)
- All transaction info (`A4AllTxn`: txn_idx, step, txn_type, addr, cycle, word, prev_cycle, prev_word)

**Per-kind step filtering**: `InspectionData.get_valid_steps_for_kind(kind)` returns only steps where the mutation is applicable (e.g., COMP_OUT_MOD only returns steps with compute-instruction majors that have register write transactions).

**Non-bandit mode**: `ZonedStepSelector` divides valid steps into three zones:
- Init zone (step 0): 5% probability
- Core zone (all other steps except max): 90% probability
- Final zone (max step): 5% probability
- Within a zone, step selection is uniform random

**Bandit mode**: `DiscountedUCBScheduler` uses a two-level UCB1 bandit:
- **Level 1 (arm selection)**: Arms are `(mutation_kind, step_bucket)` tuples. Steps are bucketed into equal-sized ranges. UCB1 with discounted counts (`gamma` decay) selects the arm. Cold-start: any arm with 0 pulls is chosen uniformly.
- **Level 2 (step selection)**: Within the chosen arm's bucket, another UCB1 selects the specific step. Cold-start for unseen steps.

### 4.4 Value Generation

A4 has a rich set of value generators (`a4/standalone/value_generator.py`):

- **`RandomValueGenerator`**: Fully random 32-bit values
- **`BitFlipValueGenerator`**: Flip 1-5 random bits of the original value
- **`BoundaryValueGenerator`**: Select from: 0, 1, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, and `original +/- 1`
- **`ArithmeticValueGenerator`**: Add/subtract small deltas (1-16) or multiply/divide by small factors (2-8)
- **`SmartValueGenerator`**: Context-aware mutations considering instruction major/minor
- **`CompositeValueGenerator`**: Weighted mix of the above (configurable weights)

All generators expose `generate_different(original_value, context, max_retries)` which guarantees the returned value differs from the original.

The default fuzzer uses the `mixed` strategy (CompositeValueGenerator) which combines all strategies.

### 4.5 Oracles and Coverage

**Constraint failure oracle**: The primary oracle. With `CONSTRAINT_CONTINUE=1`, the patched risc0 prover logs `<constraint_fail>` tags when constraints fail instead of aborting. A4 parses these into `ConstraintFailure` objects with: cycle, step, pc, major, minor, constraint location (file:line), value, phase (local/global).

**Verifier acceptance oracle**: A4 parses subprocess output for JSON records with `"context":"Verifier"` and `"status":"success"`. If the verifier accepts a proof built from mutated data, that is a critical soundness bug.

**Proof generation check**: Detects whether the prover produced a proof at all (vs. crashing). Looks for `"verify segment"` in output (proof built but self-verification failed).

**Touch coverage bitmap**: With `A4_COVERAGE_TOUCH=1`, the patched risc0 emits a 65536-byte bitmap encoded as base64 in `<a4_touch_coverage>` tags. This tracks which execution paths in the prover were exercised, enabling coverage-guided fuzzing.

**Constraint coverage DB**: SQLite database records unique constraint failure locations. New coverage is detected when a previously-unseen `(constraint_loc, major, minor)` triple is encountered.

**Family residue tracking**: With `A4_FAMILY_RESIDUE=1`, tracks which constraint families have nonzero residues (global constraint violations that do not produce local failure lines).

**Bandit reward function** (`coverage_state.py`): Combines multiple signals:
- `T_new`: New touch bitmap bits (novelty)
- `T_rare`: Rarity of touched bitmap regions
- `F_new`: New constraint failure locations
- `F_rare`: Rarity of failure locations
- `Z`: Zero-failure rejection (rejected proof with no local failures -- potential global-only violation)
- `Q`: Quality penalty (penalizes too many distinct failures or repeated duplicates)
- Final reward: `r = min(1, Q * S)` where S combines the above; `ACCEPTED` forces `r = 1.0`

---

## 5. Arguzz: Detailed Analysis

### 5.1 Injection Mechanism

Arguzz modifies the risc0 rv32im emulator directly. The core struct is `RV32IMFaultInjectionContext`:

```rust
struct RV32IMFaultInjectionContext {
    trace_info_enabled: bool,   // log trace lines
    injection_enabled: bool,    // master injection switch
    injection_step: u64,        // which step to inject at
    injection_type: String,     // which kind of injection
    current_step: u64,          // counter, starts at 0
    rng: StdRng,                // seeded RNG for reproducibility
}
```

Configuration flows from CLI arguments through `fuzzer_utils` global state:
1. Generated host binary parses `--inject`, `--inject-step N`, `--inject-kind KIND`, `--seed S`
2. Calls `fuzzer_utils::set_injection(true)`, `set_seed(S)`, `set_injection_step(N)`, `set_injection_kind(KIND)`
3. Sets env var `FAULT_INJECTION_ENABLED=1` and disables assertions
4. `Emulator::default()` creates `RV32IMFaultInjectionContext::default()` which reads from `fuzzer_utils`
5. The emulator's `step()` function checks `is_injection(kind)` at each injection point

The injection gate requires ALL three conditions:
- `injection_enabled == true`
- `current_step == injection_step`
- `injection_type == kind`

`current_step` increments at the END of `Emulator::step()`, so step 0 is the first instruction.

When injection is enabled globally, several safety checks are bypassed:
- `check_insn_load` failure does not trap
- `word & 0x03 != 0x03` (invalid instruction encoding) does not trap
- Misaligned PC does not trap
- Misaligned load/store addresses do not trap

### 5.2 Injection Kinds

Within `Emulator::step()`, injections fire at specific points in this order:

```
1. pc = ctx.get_pc()
2. check_insn_load (bypassed if injection enabled)
3. >>> PRE_EXEC_PC_MOD: pc = random_pc(pc); ctx.set_pc(pc)
4. >>> PRE_EXEC_MEM_MOD: ctx.store_memory(random_addr, random_value)
5. >>> PRE_EXEC_REG_MOD: ctx.store_register(random_reg, random_value)
6. word = ctx.load_memory(pc.waddr())
7. low-bits check (bypassed if injection enabled)
8. >>> INSTR_WORD_MOD: word = random_word(word)
9. print_trace_info(pc, word)
10. exec_rv32im(ctx, word) → dispatches to step_compute/step_load/step_store
    Inside step_compute:
      10a. >>> BR_NEG_COND: cond = !cond (inside br_cond closure)
      10b. >>> COMP_OUT_MOD: out = random_mod_of_u32(out) (after match, before store_register)
    Inside step_load:
      10c. >>> LOAD_VAL_MOD: out = random_mod_of_u32(out) (after load, before store_register)
    Inside step_store:
      10d. >>> STORE_OUT_MOD: data = random_mod_of_u32(data) (after merge, before store_memory)
11. on_normal_end(kind)
12. >>> POST_EXEC_PC_MOD: pc = random_pc(pc); ctx.set_pc(pc) [pc is still fetch address]
13. >>> POST_EXEC_MEM_MOD: ctx.store_memory(random_addr, random_value)
14. >>> POST_EXEC_REG_MOD: ctx.store_register(random_reg, random_value)
15. fault_inj_ctx.step() [current_step += 1]
```

Detail on each kind:

#### PRE_EXEC_PC_MOD
- **Fires**: Before instruction fetch
- **Mutates**: Program counter via `ctx.set_pc()`
- **Value**: `random_pc(pc)` -- offset by 1 word (33%), 2-10 words (33%), or 11-1000 words (33%); forward or backward with equal probability
- **Effect**: Causes the emulator to fetch and execute a different instruction

#### POST_EXEC_PC_MOD
- **Fires**: After instruction execution
- **Mutates**: Program counter via `ctx.set_pc()`
- **Value**: `random_pc(pc)` where `pc` is the **original fetch address** (not the architectural next-PC produced by the instruction)
- **Effect**: Redirects execution flow after the current instruction

#### INSTR_WORD_MOD
- **Fires**: After fetching instruction word, before decode/execute
- **Mutates**: Local `word` variable
- **Value**: `random_word(word)` -- three strategies:
  - Single bit flip (bits 2-31, avoiding low 2 which must be `0x03`)
  - Multi-bit flip (1-29 random bits in positions 2-30)
  - Fully random word with low 2 bits forced to `0x03`
  - Loops until the resulting word decodes to a non-Invalid instruction kind
- **Effect**: Emulator executes a different instruction than what was fetched from memory

#### BR_NEG_COND
- **Fires**: Inside the `br_cond` closure in `step_compute`, only for branch instructions
- **Mutates**: Local `cond: bool`
- **Value**: `!cond` (negation)
- **Effect**: Taken branches become not-taken and vice versa

#### COMP_OUT_MOD
- **Fires**: After the instruction's match arm computes `out`, before `ctx.store_register(rd, out)`
- **Mutates**: Local `out: u32`
- **Value**: `random_mod_of_u32(out)` (see value generation below)
- **Effect**: Corrupts the computation result written to the destination register

#### LOAD_VAL_MOD
- **Fires**: After the load value is computed from memory data, before `ctx.store_register(rd, out)`
- **Mutates**: Local `out: u32`
- **Value**: `random_mod_of_u32(out)`
- **Effect**: Corrupts the value loaded from memory

#### STORE_OUT_MOD
- **Fires**: After the store data word is assembled, before `ctx.store_memory(addr, data)`
- **Mutates**: Local `data: u32`
- **Value**: `random_mod_of_u32(data)`
- **Effect**: Corrupts the value written to memory

#### PRE_EXEC_MEM_MOD / POST_EXEC_MEM_MOD
- **Fires**: Before/after instruction execution
- **Mutates**: Memory at a random address via `ctx.store_memory()`
- **Address**: 50% fully random, 50% derived from sp or gp register
- **Value**: 50% fully random, 50% `random_mod_of_u32(old_value_at_addr)`
- **No A4 equivalent for PRE_EXEC_MEM_MOD**: A4's MEM_VAL_MOD covers memory transactions within a step but not arbitrary memory writes before/after

#### PRE_EXEC_REG_MOD / POST_EXEC_REG_MOD
- **Fires**: Before/after instruction execution
- **Mutates**: Random register x1-x31 via `ctx.store_register()`
- **Value**: 50% fully random, 50% `random_mod_of_u32(old_register_value)`
- **A4 covers PRE_EXEC_REG_MOD** with `next_read`/`prev_write` strategies on specific register transactions

### 5.3 Value Generation

Arguzz uses three value generation methods on the `RV32IMFaultInjectionContext`:

**`random_pc(pc)`**: PC perturbation
- 33%: offset by 1 WORD_SIZE (4 bytes)
- 33%: offset by 2-10 words (8-40 bytes)
- 33%: offset by 11-1000 words (44-4000 bytes)
- 50% forward, 50% backward (with `saturating_sub` for underflow)

**`random_word(word)`**: Instruction word mutation
- Strategy 0: single bit flip (bit 2-31)
- Strategy 1: multi-bit flip (1-29 random bits in positions 2-30)
- Strategy 2: fully random word with `| 0x03`
- Retries until decoded instruction is not `Invalid` and word changed

**`random_mod_of_u32(out)`**: General value mutation
- 0: constant `0`
- 1: constant `1`
- 2: constant `0xFFFFFFFF`
- 3: constant `0xFFFFFFFE`
- 4: multi-bit XOR flip (1-31 random bits)
- 5: `saturating_add(1)`
- 6: `saturating_sub(1)`
- 7: fully random `u32`
- Retries until value changed

### 5.4 Fuzzer Loop and Step Selection

The Arguzz fuzzer loop (`libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/fuzzer.py`):

1. **Trace collection**: Execute without injection (`--trace` flag); parse `<trace>` lines into `Trace` object with `TraceStep` entries (step, pc, instruction kind, assembly)
2. **Injection candidate selection**: Build lookup from `InstrKind → [TraceStep]`. Filter to instruction kinds that have at least one enabled injection type.
3. **Kind selection**: Choose an `InstrKind` randomly from candidates. `InjectionKind.retrieve_injection_types()` determines which injection kinds are valid:
   - Always valid: `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `POST_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD`
   - Branch-only: `BR_NEG_COND`
   - Computation-only: `COMP_OUT_MOD`
   - Load-only: `LOAD_VAL_MOD`
   - Store-only: `STORE_OUT_MOD`
4. **Step selection**: Random choice among `TraceStep`s for the chosen `InstrKind`
5. **Injection kind selection**: Uniform random among valid injection kinds for that instruction type
6. **Execution**: Run with `--inject --seed S --inject-step N --inject-kind KIND`
7. **Result analysis**: Parse `<trace>` and `<fault>` lines; check for soundness issues (proof accepted despite fault)

### 5.5 Step Mapping Between Arguzz and A4

The `step_mapper.py` module maps Arguzz step numbers to A4 preflight step numbers. This is necessary because:
- Arguzz counts steps in the emulator (every `Emulator::step()` call)
- A4 uses `user_cycle` from preflight, which may differ due to extra cycles for crypto precompiles (SHA, Poseidon, BigInt add multiple cycles per user_cycle)

The mapping works by:
1. Building `pc → first_step` maps for both Arguzz traces and A4 cycles
2. Computing a median offset across common PCs
3. For a given Arguzz step at PC X: find A4 cycles at PC X+4 (preflight records PC after the step), then use the offset to disambiguate loop iterations

---

## 6. Comparative Analysis

### 6.1 Mutation Point in the Pipeline

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Pipeline stage** | After witness generation (captured buffers) or replayed forged preflight | After `segment.preflight()`, before witness generation | During `Emulator::step()` execution |
| **What is corrupted** | Flat column buffers (`data_values`, `code_values`, `global_values`) or entire `PreflightTrace` via forged re-execution | Individual fields of `PreflightTrace` (`cycles[]`, `txns[]`) | Live VM state (PC, registers, memory, instruction word) |
| **Proving path** | Manual `Prover` construction from flat buffers; reimplements `prove_from_witness` | Standard risc0 prover runs on corrupted `PreflightTrace` | Standard risc0 pipeline (corrupted execution → segment → preflight → witgen → prove) |
| **risc0 code changes** | None to risc0 source; uses forked repos with `pub` visibility | Rust patches injected into `witgen/mod.rs` and `hal/mod.rs` | Modifications to `rv32im.rs` (emulator), `fuzzer_utils` crate added |

### 6.2 Mutation Type Mapping

| Mutation concept | zkVMBlast | A4 | Arguzz |
|-----------------|-----------|-----|--------|
| **Instruction type change** | -- | `INSTR_TYPE_MOD` (changes `major`/`minor`) | -- |
| **Instruction word change** | -- | `INSTR_WORD_MOD` (changes fetch txn word) | `INSTR_WORD_MOD` (replaces fetched word before decode) |
| **Computation result change** | -- | `COMP_OUT_MOD` (changes register write txn) | `COMP_OUT_MOD` (changes `out` before writeback) |
| **Load value change** | -- | `LOAD_VAL_MOD` (changes register write txn) | `LOAD_VAL_MOD` (changes `out` before writeback) |
| **Store value change** | -- | `STORE_OUT_MOD` (changes memory write txn) | `STORE_OUT_MOD` (changes `data` before store) |
| **Register corruption** | -- | `PRE_EXEC_REG_MOD` (changes register txn) | `PRE_EXEC_REG_MOD` + `POST_EXEC_REG_MOD` |
| **Memory corruption** | -- | `MEM_VAL_MOD` (changes memory txn) | `PRE_EXEC_MEM_MOD` + `POST_EXEC_MEM_MOD` |
| **PC corruption** | -- | Not supported (circuit computes PC internally) | `PRE_EXEC_PC_MOD` + `POST_EXEC_PC_MOD` |
| **Branch condition flip** | -- | -- | `BR_NEG_COND` |
| **Single column cell flip** | `FlipDataCell` | -- | -- |
| **Forged preflight execution** | `SubConfusion` (replays execution with memory overrides) | -- | -- |
| **Journal forgery** | `SubConfusion` (forges `session.journal`) | -- | -- |
| **Precompile memory traffic** | -- | `MEM_VAL_MOD` (explicit `other_mem_read`/`other_mem_write`) | Indirect (corrupted memory may flow into precompiles) |

### 6.3 Value Generation Comparison

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Approach** | Fixed/targeted (FlipDataCell: +1; SubConfusion: specific operand swap) | Rich strategy library: random, bitflip, boundary, arithmetic, smart, composite | Seeded RNG with multiple strategies per method |
| **Boundary values** | None (hardcoded exploit values) | 0, 1, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF | 0, 1, 0xFFFFFFFF, 0xFFFFFFFE |
| **Bit flips** | `+Val::ONE` on field element | 1-5 random bit flips | 1-31 random bit XOR flips |
| **Context awareness** | Exploit-specific (knows the `sub` instruction layout) | `SmartValueGenerator` considers instruction major/minor | None (same `random_mod_of_u32` for all) |
| **Guarantees** | N/A | `generate_different()` ensures output differs from original | While-loop ensures output differs from original |
| **Configurability** | Hardcoded | Strategy selectable via config (`mixed`, `random`, `bitflip`, `boundary`, etc.) | Fixed strategies per method |

### 6.4 Step/Target Selection Comparison

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Granularity** | Per-segment (mutates one segment's witness) | Per-step (specific `user_cycle` in preflight) | Per-step (specific `current_step` in emulator) |
| **Selection method** | Scans for specific instruction pattern (SubConfusion: last `sub` in trace) | Zoned random (5%/90%/5% init/core/final) or bandit UCB1 | Uniform random among trace steps matching selected instruction kind |
| **Feedback-guided** | No | Yes (bandit reward from touch coverage + constraint novelty) | No |
| **Kind-aware** | N/A (strategy-specific targeting) | Per-kind valid step filtering via `get_valid_steps_for_kind()` | Per-kind valid injection filtering via `retrieve_injection_types()` |

### 6.5 Oracle Comparison

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Primary oracle** | `CorruptionOutcome`: verifier accepts → soundness bug | Constraint failure analysis + verifier acceptance check | Proof acceptance despite injected fault |
| **Constraint visibility** | None (prover either produces a seal or fails) | Full constraint failure parsing: location, type, cycle, step, phase | None (constraint failures cause prover crash) |
| **Failure classification** | Binary: `ProverRejected` / `VerifierRejected` / `VerifierAccepted` | Rich: crash type, constraint count/location, proof generated, proof verified, verifier accepted, global-only violations | Binary: proof accepted or not |
| **Family/residue analysis** | No | Yes (`A4_FAMILY_RESIDUE=1` tracks constraint family violations) | No |

### 6.6 Coverage and Feedback Comparison

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Execution path coverage** | None | Touch coverage bitmap (65536 bytes), merged across campaign | None |
| **Constraint coverage** | None | SQLite DB tracking unique `(constraint_loc, major, minor)` triples | None |
| **Feedback loop** | None (fixed strategies) | Bandit UCB1 with reward combining touch novelty, failure novelty, cascade penalty | None (random selection) |
| **Reproducibility** | Deterministic (same ELF → same result) | Seeded RNG for value generation; deterministic given seed + step + kind | Seeded RNG (`--seed S`); deterministic given seed + step + kind |

### 6.7 RISC0 Internals Access

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **risc0 fork** | Separate forked repos (`v2-pub`, `v3-pub`) with `pub` visibility patches | Patches injected into standard risc0 at build time | Modified risc0 in `workspace/risc0-modified/` |
| **Types used directly** | `PreflightTrace`, `WitnessGenerator`, `Prover`, `Preflight`, `Risc0Context`, `Emulator`, `Risc0Machine`, `MetaBuffer`, `Val`, `ExtVal`, `Session`, `Segment`, `ReceiptClaim`, `Receipt`, `CompositeReceipt` | `PreflightTrace` (via patched `witgen/mod.rs`): `trace.cycles[]`, `trace.txns[]` | `EmuContext` (PC, registers, memory), instruction `word`, branch `cond`, compute `out`, store `data` |
| **Circuit awareness** | Knows `REGCOUNT_*`, `REGISTER_GROUP_*`, `TAPSET`, seal version; manually constructs HAL buffers | Knows cycle major/minor types (0-12), transaction read/write semantics, register address range | Knows instruction kinds (`InsnKind`), register aliases |
| **Version support** | Explicit v2 and v3 with separate implementations | Single version (whatever risc0 is built) | Single version (whatever risc0-modified is) |

### 6.8 Proving Pipeline Comparison

| Aspect | zkVMBlast | A4 | Arguzz |
|--------|-----------|-----|--------|
| **Witness generation** | Either: (a) mutate captured flat buffers and rebuild `WitnessGenerator`, or (b) run forged preflight → `generate_witness_from_preflight()` | Standard `WitnessGenerator::new()` runs on mutated `PreflightTrace` | Standard pipeline (corrupted execution → standard preflight → standard witgen → standard prove) |
| **Prover invocation** | Manual: construct `Prover`, commit groups, sample mix, run accum, finalize | Standard risc0 prover (runs after witgen on corrupted trace) | Standard risc0 prover |
| **Receipt construction** | Manual: decode claim from seal, build `SegmentReceipt`, assemble `CompositeReceipt`, patch journal digest | Standard risc0 receipt construction | Standard risc0 receipt construction |
| **Verification** | `Receipt::verify(image_id)` | Parse subprocess output for verifier acceptance | Parse subprocess output for proof acceptance |

---

## 7. Key Differences Summary

### zkVMBlast vs A4

1. **Abstraction level**: zkVMBlast works with flat column buffers (`Vec<Val>`) and manually drives the prover; A4 works with structured `PreflightTrace` and lets the standard prover run.
2. **Mutation scope**: zkVMBlast can replace entire segment witnesses (SubConfusion) or flip individual field elements (FlipDataCell); A4 makes targeted, field-level mutations to specific transactions or cycle types.
3. **Strategy count**: zkVMBlast has 3 strategies (Identity, FlipDataCell, SubConfusion); A4 has 7 mutation types with rich value generation.
4. **Exploit reproduction**: zkVMBlast's SubConfusion is a targeted exploit reproduction (GHSA-g3qg-6746-3mg9); A4 is a general-purpose fuzzer.
5. **Forged execution**: zkVMBlast can re-execute with memory overrides (ForgedPreflight); A4 only modifies the trace after execution.
6. **Journal forgery**: zkVMBlast's SubConfusion forges `session.journal`; A4 does not modify the journal.
7. **Version comparison**: zkVMBlast explicitly tests v2 (vulnerable) vs v3 (fixed); A4 targets a single version.
8. **Coverage**: A4 has touch bitmap + constraint DB + bandit reward; zkVMBlast has no coverage feedback.

### zkVMBlast vs Arguzz

1. **Pipeline position**: zkVMBlast mutates after witness generation (or replays forged preflight); Arguzz mutates during execution.
2. **Mutation granularity**: zkVMBlast operates on field elements in column buffers or forged memory reads; Arguzz operates on live VM state (PC, registers, memory, instruction words).
3. **PC mutation**: Arguzz can mutate PC (PRE/POST_EXEC_PC_MOD); zkVMBlast cannot (it replays preflight which inherently follows the correct PC sequence, with only specific memory reads overridden).
4. **Branch condition**: Arguzz can flip branch conditions (BR_NEG_COND); zkVMBlast cannot.
5. **Proving approach**: zkVMBlast manually constructs the prover from flat buffers; Arguzz lets the corrupted execution flow through the standard pipeline.
6. **Scope of corruption**: Arguzz corruption propagates through the entire remaining execution (the fault at step N affects all subsequent steps); zkVMBlast corruption is scoped to specific buffer cells or a forged preflight of one segment.

### A4 vs Arguzz

1. **Pipeline position**: A4 mutates the preflight trace before witgen; Arguzz mutates execution state during the emulator step loop.
2. **PC mutation**: Arguzz supports PRE/POST_EXEC_PC_MOD; A4 cannot mutate PC (circuit computes it internally from the trace).
3. **Branch condition**: Arguzz has BR_NEG_COND; A4 has no equivalent.
4. **Cycle type mutation**: A4 has INSTR_TYPE_MOD (can change `major`/`minor`); Arguzz cannot change cycle types.
5. **Precompile coverage**: A4's MEM_VAL_MOD explicitly targets SHA2/Poseidon2/BigInt memory traffic; Arguzz only affects precompiles indirectly through corrupted memory/registers.
6. **Corruption propagation**: Arguzz fault at step N cascades through all subsequent execution; A4 mutation is localized to the specific trace field(s).
7. **Coverage feedback**: A4 has touch bitmap, constraint DB, and bandit reward; Arguzz has no coverage feedback.
8. **Constraint visibility**: A4 sees individual constraint failures with full metadata; Arguzz only sees pass/fail.
9. **Step alignment**: Steps are not identical between the two; `step_mapper.py` handles the mapping (Arguzz counts emulator steps; A4 uses preflight `user_cycle` which differs for multi-cycle instructions like precompiles).

---

## 8. Unique Capabilities

### Only in zkVMBlast
- **Forged preflight execution**: Can re-run segment execution with specific memory overrides, producing a coherent-but-wrong witness
- **Explicit v2 vs v3 testing**: Tests the same exploit against both versions to verify fix
- **Manual prover construction**: Full control over the proving pipeline (commit groups, FRI, finalize)
- **Journal forgery**: Can forge `session.journal` to match the forged computation output
- **Self-canceling transactions**: Creates `prev_cycle == cycle` transactions (the core of SubConfusion)
- **Multi-VM support**: Same framework also tests SP1, OpenVM, and Pico (different `MaliciousProver` implementations)

### Only in A4
- **Cycle type mutation** (`INSTR_TYPE_MOD`): Can change a cycle's major/minor classification
- **Touch coverage bitmap**: 65536-byte execution path coverage
- **Constraint failure parsing**: Full metadata on each constraint violation
- **Bandit-guided selection**: UCB1 over `(kind, step_bucket)` arms with discounted exploration
- **Family residue tracking**: Detects global-only constraint violations
- **Rich value generators**: 6 strategies including context-aware `SmartValueGenerator`
- **Surgical instruction mutation**: Field-level RISC-V encoding changes (rd, funct3, immediate)
- **Explicit precompile memory targeting**: MEM_VAL_MOD covers SHA2/Poseidon2/BigInt transaction types

### Only in Arguzz
- **PC mutation**: PRE_EXEC_PC_MOD and POST_EXEC_PC_MOD
- **Branch condition negation**: BR_NEG_COND
- **POST_EXEC_REG_MOD**: Register corruption after instruction execution
- **Corruption propagation**: Single fault cascades through all remaining execution
- **Trap bypass**: When injection is enabled, misaligned PC, misaligned memory access, invalid instruction encoding, and instruction fetch faults are all bypassed
- **Instruction decode validation**: `random_word()` loops until the corrupted word decodes to a valid `InsnKind`
