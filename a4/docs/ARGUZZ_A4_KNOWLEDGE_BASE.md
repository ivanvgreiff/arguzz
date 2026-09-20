# Arguzz vs A4 — Knowledge Base (everything we learned)

Authoritative reference for the Arguzz-vs-A4 work. Captures architecture, flags,
selection mechanisms, the operand-crash root cause, the constraint taxonomy, and
**all considerations for the future bias-statistics campaign**. Read this first
when resuming the statistics phase so there are no surprises.

Status: the **bias-statistics campaign is deferred** until A4's architecture is
finalized (see §7). Current focus: a single, foolproof **example** of a
semantically-similar mutation for Arguzz vs A4 (see `minimal_add/EXAMPLE_PLAN.md`).

---

## 1. The two fuzzers operate at different stages

| | Arguzz | A4 |
|---|---|---|
| Stage | **Executor** (during `Rv32imEmulator::step`) | **Witness** (post-execution trace records) |
| Mechanism | Mutates registers/memory/PC/instr-word *before/at* execution; the executor then **recomputes** everything downstream | Surgically rewrites a recorded transaction value in the witness; executor trace is untouched |
| Result trace | Self-consistent trace of a **different computation** | Internally **contradictory** trace (one value changed, rest unchanged) |
| Driver | `libs/zkvm-fuzzer-utils/.../fuzzer.py` + `projects/risc0-fuzzer/` (regenerates+rebuilds a metamorphic guest each run; `InjectionContext` schedules the target) | `a4/standalone/fuzzer.py` (semantic zones + bandit over `(kind, zone)` arms on a fixed guest's inspection data) |

Key consequence (thesis core): mutating "the same register" is **not the same
operation**. A4 breaks **local** memory-consistency constraints (the witness
contradicts itself). Arguzz produces a **locally-valid** witness for a wrong
computation, caught only **globally / at output** — unless its extra transaction
corrupts trace structure and crashes the prover (see §4).

---

## 2. Flags — what each does, and symmetry

Source of truth:
- `fuzzer_utils/src/lib.rs` — global state + macros.
- `risc0/circuit/rv32im/src/prove/hal/mod.rs:146-157` — step mode.
- `risc0/circuit/rv32im/src/prove/witgen/mod.rs:219-224` — A4 mutation hook.
- `risc0/circuit/rv32im-sys/kernels/cxx/{ffi,steps}.cpp` — C++ assert/throw bypass.

| Flag | Set by | Effect | Symmetric? |
|---|---|---|---|
| `FAULT_INJECTION_ENABLED` | **Arguzz**: `set_injection(true)` via `--inject` (`lib.rs:104-106`). **A4**: `witgen/mod.rs:224` when `A4_MUTATION_CONFIG` set. | Skips **C++ witgen asserts/throws** ("SKIP ASSERT"/"SKIP THROW") so witgen continues past mux/throw checks. Does **not** affect the executor or Rust panics. | **Yes** — both paths set it. |
| `disable_assertions()` | Arguzz only (`host main.rs:57`, under `--inject`) | Downgrades Rust `fuzzer_assert!` to warnings. A4 keeps them as hard asserts. | **No** (minor; dominant crashes are C++ asserts, equalized above). |
| `A4_COVERAGE_TOUCH[_VERBOSE]` | Campaign env (both) | Emits touch bitmap/verbose sets; **forces `StepMode::SeqForward`** (`hal/mod.rs:149`). | Yes when set for both. |
| `CONSTRAINT_CONTINUE` | Campaign env (both) | C++ `eqz` logs `<constraint_fail>` and continues instead of aborting. | Yes. |
| `A4_FAMILY_RESIDUE`, `A4_GLOBAL_RESIDUE` | Campaign env (both) | Emit Hook-3 family residues + global residue (global-argument failure detection). | Yes. |
| `RISC0_WITGEN_DEBUG` | not set by us | Would also force `SeqForward` + deterministic RNG. | n/a |

**Correction to an earlier mistake:** Arguzz does **not** run without
`FAULT_INJECTION_ENABLED`. Both fuzzers get it. The operand crash is **not** a
flag-competition artifact (see §4).

`SeqForward` is a legitimate, necessary instrumentation choice for collecting
constraint info from either fuzzer: it prevents parallel-thread corruption /
crashes during witgen and is required for touch-bitmap emission. It changes
witgen *ordering*, not *which constraints fail* (the executor, where Arguzz acts,
is upstream of it).

---

## 3. Selection mechanisms (native) vs what composer's pilot did

**Arguzz native:** `InjectionContext.arguments_from_trace(trace, random)` chooses
the `(step, kind)` from the trace using an instruction-type-aware scheduler
(`available_injections_lookup`, `preferred_instructions`) — i.e. roughly uniform
over instruction *types*, so rare instructions are over-sampled relative to their
frequency. Native guests are **generated metamorphic circuits**, rebuilt per run
(`fuzzer.py:729-734`), giving diverse logic. Constraint failures are parsed
natively (`fuzzer.py:803-832`, `trace.has_constraint_failures()` →
`log_constraint_failures_csv`, with instruction correlation).

**A4 native:** semantic zones (`step_selector.py`: INIT 5% / CORE 90% / FINAL 5%,
where INIT = step 0 / ECALL setup / POSEIDON) × bandit over arms
(`semantic_arm_universe.py`). **A4 DOES have machine/kernel arms** — INIT zone is
kernel/machine, and instruction-word arms include `major == 8` (ECALL)
(`semantic_arm_universe.py:61-62`).

**What composer's `bias_campaign` actually ran (NOT native for either):**
- Pinned Arguzz to `--inject-step` chosen by `sample_eligible_step` =
  `steps[seed % len]` over a **trace-ordered** list → first ~50 executor steps =
  **machine-mode bootloader**.
- "A4" = direct calls to six `a4.standalone.mutations.*` creators at that pinned
  step (no zones, no bandit) → a degenerate subset.
- Result: 33% of Arguzz injections landed in kernel space (pc ≥ `0xC0000000`);
  A4 "skipped" early steps because the wrapper found no target there (an artifact
  of the wrapper, **not** an A4 limitation). Inject steps capped at 528 while the
  trace runs ~4000. → The pilot's distributions are not trustworthy as a bias
  measurement. (Pilot DB/report retained at `bias_campaign/artifacts/c1/` for
  provenance only.)

---

## 4. The operand-register OOB crash — full root cause

**Symptom:** `PRE_EXEC_REG_MOD` targeting an add operand (`a0`/`a1`/`s0`) at the
add's own step → panic in `preflight.rs:227` ("cycle diff index OOB"), before any
constraint is evaluated. Verified exhaustively in M3 (`verify_crash_condition.py`):
operands crash; ~28 non-operand registers complete witgen with 4-7 constraint
failures; the crash tracks whether the injected register is actually touched by
the instruction at that step.

**Mechanism (definitive):**
1. `PRE_EXEC_REG_MOD` calls `ctx.store_register(reg, val)` **before** the
   instruction runs (`rv32im.rs:637`). Registers are memory-mapped, so this emits
   a **WRITE txn at the current cycle**.
2. The instruction then **reads** that same register the same cycle → a READ txn
   at the same cycle and address → `txn.prev_cycle == txn.cycle`.
3. `wrap_memory_txns` computes `diff = txn.cycle - 1 - txn.prev_cycle`
   (`preflight.rs:226`) → `u32` underflow → `cycles[(diff/2)]` index OOB → panic.
4. The guard that would have caught this — `ensure!(...)` at `preflight.rs:225` —
   **is commented out** (a fuzzer source edit). Stock RISC0 would `bail!` →
   graceful `Err` → clean "prover rejected" outcome, not a panic.

**Therefore:** the crash is **not** caused by A4 instrumentation, A4 step
selection, or any A4 env flag. It is: *(Arguzz's same-cycle WRITE+READ on one
address)* + *(the commented-out `ensure!`)*. It will occur for **native Arguzz**
through this modified prover whenever it injects a register/memory location at the
same cycle that location is accessed.

**Implications for an apples-to-apples register example:**
- A4 can surgically change `a1`'s READ value in the witness → **local** breaks
  (`IsRead@mem.zir:79`, `MemoryWrite@mem.zir:99`), each residue `p-5` for 4→9
  (validated in M2). Executor untouched.
- Arguzz cannot do that surgical change — its mechanism adds a txn. Injecting `a1`
  **at the add cycle** → OOB. The only architecturally clean Arguzz analogues are:
  - inject the operand **before** the consuming cycle (needs a gap between
    setting the operand and using it) → value propagates → **locally-consistent
    wrong trace → global/output reject, no local fail**; or
  - use `COMP_OUT_MOD` (mutate the add's *output*), which is a single WRITE value
    change with no same-cycle conflict → in the pilot this produced local L2
    failures (incl. `MemoryWrite`) for Arguzz, matching A4's `COMP_OUT_MOD` →
    **both break the same local constraint** (clean apples-to-apples).
- Restoring `ensure!` does **not** yield constraint info — it converts the panic
  into an `Err` at preflight, still before constraint evaluation. So it is not a
  path to a register-operand example.

---

## 5. Constraint taxonomy (validated via ZIR provenance, M1-M2)

- **L1 (LOCAL_INTRASTEP):** `phase=local`, `loc` not in `mem.zir`. Decode/ALU/range
  plumbing (DecodeInst, VerifyOpcodeF3F7, IsZero, OneHot, NormalizeU32, …).
- **L2 (LOCAL_INTERSTEP / memory-consistency):** `phase=local`, `loc` in `mem.zir`
  (`IsRead@79/80`, `MemoryWrite@99/100`, `IsCycle`, `MemoryIO`). This is where
  same-value/read-write chains and ADD-result enforcement live.
- **ACCUM:** `phase=accum` — accumulator-column update EQZ checks (machinery, not
  "global").
- **G (GLOBAL):** Hook-3 family residues (`memory`, `u16`, `u8`, `cycle`) +
  `A4_GLOBAL_RESIDUE`. Nonzero ⇒ whole-trace permutation/lookup argument failed.

BabyBear `p = 2013265921`. A constraint residue is `(LHS - RHS) mod p`; for a
value delta `old→new` the residue is `(old-new) mod p`. M2: `a1` 4→9 ⇒ `p-5` on
both `IsRead@79` (prev_word 4 vs witness 9) and `MemoryWrite@99` (data.low 4 vs
witness 9). Provenance rule: predicted residue from ZIR source must equal observed
— residue magnitude alone is insufficient (an earlier wrong model used lhs=7).

Add's local universe (M1, the c0/c1 add at major=0/minor=0): **37** local
constraint contexts; full list in `minimal_add/artifacts/m1/add_local_universe.json`.

---

## 6. Outcome taxonomy + classifier (validated, reusable)

8 classes: `PREFLIGHT_CRASH`, `OTHER_CRASH`, `ACCEPTED`, `CONSTRAINT_REJECT`,
`GLOBAL_REJECT`, `VERIFY_REJECT`, `VALID_NO_SIGNAL`, `NO_INJECTION`.

Classifier lives at `bias_campaign/classify.py` (validated in C0/C1). Critical fix
that must persist: a panic at `main.rs:*` is a **host harness panic** (the host
`panic!`s whenever `prove()` returns `Err`), **not** a prover crash. `prover_crash`
only fires on `preflight.rs` / `/witgen/` / `risc0/circuit` / `risc0/zkp`. On the
production host, **every** rejected proof panics at `main.rs:150` (the Prover-error
arm), so `CONSTRAINT_REJECT`/`VERIFY_REJECT`/`GLOBAL_REJECT` all carry
`host_panic=true`; that is expected.

`VERIFY_REJECT` semantics caveat: it means "proving failed with **no**
`<constraint_fail>` and **no** nonzero global residue" — *not* literally that the
verifier ran and rejected (the host never reaches the verifier when `prove` errs).
In the C1 pilot this bucket was heavily inflated by bootloader injections.

`categorize.py` maps `(loc, phase)` → L1/L2/ACCUM/G.

---

## 7. Considerations for the FUTURE statistics campaign (deferred)

Do not start until A4's final architecture is chosen. Currently **5 A4 variants**
are under consideration (zoned + multiple multi-armed-bandit variants); statistics
collected now would be obsoleted. When resuming, account for ALL of the following:

1. **Run each fuzzer in its NATIVE mode** (Arguzz: `projects/risc0-fuzzer` +
   `InjectionContext` scheduler + metamorphic guests; A4: `a4/standalone/fuzzer.py`
   with the chosen final selector). Do **not** cross-pin one fuzzer to the other's
   step decider (that is what invalidated the C1 pilot).
2. **Shared frozen guest corpus** for comparability: freeze N Arguzz-generated
   metamorphic guests (+ a few real examples) and run both fuzzers on the same
   ELFs. Tiny single-op guests (like minimal_add) are unrepresentative.
3. **Possible second "clean Arguzz" binary**: the modified prover (commented-out
   `ensure!`, downgraded asserts) converts some graceful rejects into crashes,
   which would **inflate Arguzz's crash category**. Consider an Arguzz build with
   original prover guards restored (keeping only the constraint-observation hooks)
   so crash-rate statistics reflect Arguzz, not the instrumentation. A4 needs the
   bypass to mutate; Arguzz mostly does not. Decide and document per-metric.
4. **Compare on failure CATEGORY (L1/L2/ACCUM/G), crash rate, and instruction
   class** — kind-agnostic. Do **not** force "aligned kinds"; each tool uses its
   own kind menu/frequencies.
5. **Selection bias is intrinsic and part of the result** in an as-is comparison
   (Arguzz uniform-over-instruction vs A4 zone+bandit). Frame it as end-to-end
   tool bias, not a single-variable contrast. Optionally also report a matched
   (same-site) contrast to isolate propagation.
6. **Crashes are data, not bugs to suppress.** "Arguzz aborts the prover before
   constraints are evaluated" is a legitimate, reportable bias datapoint.
7. **Soundness oracle differs** (Arguzz metamorphic/output-diff; A4 differential).
   For the constraint metric this is mostly irrelevant (we read the prover's
   constraint system); for soundness-escape accounting use each tool's own oracle.
8. **Scale/infra:** Arguzz rebuilds guests per run (slow); A4 needs per-guest
   inspection data + bandit state. Plan for POS (`bias_campaign/POS_NOTES.md`).
9. **Determinism:** fix master seeds; Arguzz uses per-run random64 + random circuit
   gen, A4 bandit is stateful.

---

## 8. File map

- Host (one binary, both paths): `workspace/output/host/src/main.rs`.
- Arguzz executor injection: `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/rv32im.rs`.
- Memory map / regs / majors: `.../execute/platform.rs`.
- Crash site: `.../prove/witgen/preflight.rs:216-236` (`wrap_memory_txns`, commented `ensure!` @225).
- A4 hook + `FAULT_INJECTION_ENABLED`: `.../prove/witgen/mod.rs:219-224`.
- Step mode: `.../prove/hal/mod.rs:146-157`.
- C++ assert bypass: `.../rv32im-sys/kernels/cxx/{ffi,steps}.cpp`.
- Arguzz native fuzzer: `libs/zkvm-fuzzer-utils/zkvm_fuzzer_utils/fuzzer.py`, `projects/risc0-fuzzer/`.
- A4 native: `a4/standalone/{fuzzer,step_selector,semantic_arm_universe,zone_classifier,bandit*}.py`.
- Measurement (reusable): `thesis_side_experiments/bias_campaign/{classify,categorize,touch_parse}.py`.
- Add example ground truth: `thesis_side_experiments/minimal_add/artifacts/{m1,m2}/`.
