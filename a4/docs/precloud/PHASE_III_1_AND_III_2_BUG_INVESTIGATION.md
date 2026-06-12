# Phase III.1 + III.2 Smoke Campaign — Investigation of the 5 "Bugs"

**Status**: Investigation complete  
**Source**: `phase31_smoke_output.txt` (50 mutations, `--selector uniform --b-count 16`)  
**Scope**: Determine whether the 5 verifier-accepted mutations are real soundness bugs or fuzzer artifacts, and explain *why*.

---

## 1. TL;DR

All five "bugs" found in the smoke campaign are **false positives caused by `INSTR_TYPE_MOD`**. The user's intuition is correct in spirit — the mutations did target trace fields that are *not* "data-bearing" — but the precise mechanism is sharper than "control vs data trace entries":

> **`INSTR_TYPE_MOD` modifies `cycles[].major` and `cycles[].minor` in the preflight trace. Those two fields are consumed *only by A4's diagnostic / coverage instrumentation* and never feed into the witness polynomial that the verifier checks. The proof commits to the same data as an unmutated run, the verifier rightly accepts, and our outcome classifier — which equates "verifier accepted a mutated run" with "BUG" — flags it as a soundness bug.**

This is not a verifier soundness bug; it is a fuzzer-side mutation that has no observable effect on the verifier-visible polynomial. Every other mutation kind in the smoke campaign that *did* perturb verifier-visible data was correctly rejected.

---

## 2. The five accepted mutations

Extracted directly from `phase31_smoke_output.txt`:

| # | Idx | Kind | Step | Original | Mutated | Local fails | Global fails | Outcome |
|---|-----|------|------|----------|---------|-------------|--------------|---------|
| 1 | [7]  | INSTR_TYPE_MOD | 3375 | `Sub  [0,1]`  | `SrlI [3,10]` ⚠INVALID | 3 (`MemoryWrite@99`, `OneHot@9`, `OneHot@11`) | 0 | ACCEPTED |
| 2 | [8]  | INSTR_TYPE_MOD | 971  | `AddI [0,7]`  | `Rem  [4,6]` | 3 (`VerifyOpcodeF3F7@102/103/104`) | 0 | ACCEPTED |
| 3 | [17] | INSTR_TYPE_MOD | 881  | `AddI [0,7]`  | `SrlI [4,2]` | 1 (`VerifyOpcodeF3F7@103`) | 0 | ACCEPTED |
| 4 | [31] | INSTR_TYPE_MOD | 3651 | `AddI [0,7]`  | `Or   [0,3]` | 4 (`MemoryWrite@99/100`, `VerifyOpcodeF3F7@102/103`) | 0 | ACCEPTED |
| 5 | [45] | INSTR_TYPE_MOD | 1222 | `Lw   [5,2]`  | `Unknown(5,6)` ⚠INVALID | 3 (`IllegalLoadOp@40`, `MemoryWrite@99/100`) | 0 | ACCEPTED |

Two structural observations:

1. **Every single accepted mutation is `INSTR_TYPE_MOD`.** No `COMP_OUT_MOD`, `MEM_VAL_MOD`, `INSTR_WORD_MOD_FULL`, `INSTR_WORD_MOD_SUR`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, or `PRE_EXEC_REG_MOD` was accepted.
2. **Every accepted mutation produced local constraint failures** (`dl ≥ 1`) and **zero global failures** (`dg = 0`). This is the diagnostic fingerprint we'll explain in §4.

For comparison, the only `INSTR_TYPE_MOD` that was rejected — run [33] — is genuinely informative:

| Idx | Kind | Step | Original | Mutated | dl | dg | Outcome | Why rejected |
|-----|------|------|----------|---------|----|----|---------|--------------|
| [33] | INSTR_TYPE_MOD | 3859 | **`JalR [2,4]`** (control flow!) | `Lw [5,2]` | 5 | 3 | REJECTED | Memory permutation violated — `x24/s8` got an unexpected write because the witness no longer reproduces JalR's link-register write |

So `INSTR_TYPE_MOD` only escapes detection when the *original* instruction is one whose effect is fully contained in the instruction word + memory transactions (arithmetic, immediate, load) and the mutated dispatch metadata happens to land on a step where downstream register/memory writes are unchanged. When `INSTR_TYPE_MOD` lands on a `JalR` or other instruction whose metadata genuinely participates in some witness-visible decision, it is correctly rejected.

---

## 3. What `INSTR_TYPE_MOD` actually does (mutation kind vs trace field)

The mutation is implemented in `a4/standalone/mutations/instr_type_mod.py` and applied by the modified prover in `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`.

### 3.1 What gets written

The Python side emits a config:

```json
{ "mutation_type": "INSTR_TYPE_MOD", "step": <n>, "major": <m>, "minor": <k> }
```

The Rust side at `witgen/mod.rs:262-288` consumes it and does **only** this:

```rust
for (cycle_idx, cycle) in trace.cycles.iter_mut().enumerate() {
    if cycle.user_cycle == target_step {
        if let Some(major) = new_major { cycle.major = major; }
        if let Some(minor) = new_minor { cycle.minor = minor; }
        ...
    }
}
```

That is, **it only writes two `u8` fields on a single `PreflightCycle` record**. It does *not* touch `cycle.pc`, `cycle.txn_idx`, `txns[].word`, `txns[].addr`, `txns[].prev_word`, register values, memory values, or any other field that could end up in the witness polynomial.

### 3.2 Where `cycle.major`/`cycle.minor` are read in the prover

A repository-wide search for `cycle.major`/`cycle.minor` in the prover code paths returns the following uses:

| File:line | Use | Affects witness? |
|-----------|-----|------------------|
| `risc0-modified/.../witgen/mod.rs:80` | Diagnostic `println!` (trace dump) | ❌ |
| `risc0-modified/.../witgen/mod.rs:262-288` | The mutation site itself | ❌ |
| `risc0-modified/.../witgen/mod.rs:297` | Filter `(cycle.major <= 6 ‖ == 8)` to find instruction/ECALL fetch cycles for `INSTR_WORD_MOD` only | ❌ (gating logic for *another* mutation kind) |
| `risc0-modified/.../witgen/mod.rs:312/350/395/440/512/567` | Diagnostic `println!` (`<a4_*_mod>` tags) | ❌ |
| `risc0-modified/.../prove/hal/mod.rs:184-186` | A3 inspection dump (`<a3_row_info>`, behind diagnostic env-var) | ❌ |
| `risc0-modified/.../witgen/preflight.rs:244` | `CycleState::from_u32((cycle.major - 7) * 8 + cycle.minor)` — Poseidon2 dispatch, **only when `major >= 7`** | ❌ for our mutations (we only target `major ∈ {0..6}`) |
| `risc0-modified/.../rv32im-sys/kernels/cxx/witgen.h:190-193` | A4 `<constraint_fail>` diagnostic `printf` | ❌ |
| `risc0-modified/.../rv32im-sys/kernels/cxx/ffi.cpp:122-123` | `a4_touch_mark()` — A4 touch coverage hash input | ❌ (instrumentation only) |
| `risc0-modified/.../rv32im-sys/kernels/cxx/ffi.cpp:309-310` | A4 lookup-record diagnostic | ❌ |

Every consumer of `cycle.major`/`cycle.minor` for `major ∈ {0..6}` falls into one of two buckets:

1. **A4 instrumentation** (`<constraint_fail>`, `<a3_row_info>`, `<a4_*_mod>`, `a4_touch_mark`) — added by us for fuzzing/coverage. Not part of upstream RISC0.
2. **Other mutations' gating** (`INSTR_WORD_MOD` uses `cycle.major <= 6 ‖ == 8` to find the right cycle — but it then mutates `txns[].word`, not `cycle.major`).

There is no production prover path that reads `cycle.major` or `cycle.minor` for `major ∈ {0..6}` and uses it to compute a value that ends up in the committed polynomial. Witness columns are populated from `txns[]` (instruction words, memory transactions) and the executor's reconstructed register file.

### 3.3 Consequence

Because the field is invisible to the production prover, the polynomial that the prover commits to is **byte-for-byte identical** to the polynomial it would have committed to without the mutation. The verifier therefore accepts. There is no cryptographic anomaly, no soundness gap, nothing for a verifier-side fix to address.

---

## 4. Why "local constraint failures fired but the verifier still accepted"

This is the question the per-run summary makes look paradoxical. The smoke output for [7] reads:

```
[7] INSTR_TYPE_MOD @ step 3375: 3 failures, ..., outcome: ACCEPTED, exit: 0 [proof:GENERATED] BUG!
    Local constraints hit (3 unique):
      - MemoryWrite@mem.zir:99
      - OneHot@one_hot.zir:11
      - OneHot@one_hot.zir:9
    Global: no permutation/lookup violations (local-only)
```

How can three local constraints fail and the verifier still emit `{"context":"Verifier","status":"success"}`?

The answer follows directly from §3 plus how the local-failure hook is implemented:

1. **The "local constraint failures" come from `<constraint_fail>` tags emitted by the C++ kernels (`witgen.h:190-193`).** These tags are A4's *eqz-evaluation observability hook*: every time the constraint evaluator evaluates an `eqz` to a non-zero value during witness generation, we print a tag. Tags are attributed via the *current* `cycle.major`/`cycle.minor` at the time of evaluation.

2. **The constraint evaluator for `VerifyOpcodeF3F7`, `OneHot`, etc. dispatches based on the cycle's metadata.** When we change `cycle.major=0,minor=7` (`AddI`) to `cycle.major=4,minor=6` (`Rem`), the evaluator runs the `Rem` constraint logic against witness columns that were filled by the *original* `AddI` execution. Of course it produces non-zero residues — `eqz` fails — and we see `<constraint_fail>` tags.

3. **`CONSTRAINT_CONTINUE=1` (set by A4) lets the prover keep going past these failures.** The prover does not abort. It builds the polynomial commitment from the witness columns it actually filled.

4. **The witness columns themselves are computed from `txns[]` and the executor state — neither of which was mutated.** So the polynomial commitment is the same one a clean run would produce. That commitment is what the verifier checks. Verifier passes.

5. **Our `<constraint_fail>` instrumentation is observational — it records what the *evaluator* computed when handed inconsistent metadata.** It does not modify the witness, the polynomial, or the proof. So failures appear in our local-failure log without being reflected in the verifier's view.

Concretely: the three "MemoryWrite/OneHot/VerifyOpcodeF3F7" failures we logged are the constraint evaluator complaining "you told me this cycle is `Rem` but the witness columns look like `AddI`" — and being told to continue. The proof never sees those complaints.

---

## 5. Reconciling with the user's "control vs data trace entries" hypothesis

Restating the user's hypothesis:

> "The bugs came because we executed mutations on control (non-data) related trace entries, and we ended up not actually creating a meaningful mutation, and that's why the zoned focuses on data-specific entries of the trace."

**The intuition is right; the mechanism has one extra precision.**

- **Right**: The mutations did target *control/metadata* fields rather than *data* fields, and produced no meaningful change to the verifier-visible state. That is exactly what makes them false bugs.
- **Right**: A mutation that doesn't change any verifier-visible value will look like an accepted "soundness bug" because by construction we did not corrupt anything the verifier checks.
- **Sharper than the original framing**: The "control vs data" axis isn't really "which trace *entry* was mutated" — every mutation in the campaign was applied at some instruction cycle. The actual axis is "which *field* of the trace entry is mutated":
  - **Data fields** consumed by the prover: `txns[].word`, `txns[].addr`, `txns[].prev_word`, register/memory values produced by the executor. Mutating these (`COMP_OUT_MOD`, `INSTR_WORD_MOD`, `MEM_VAL_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`) corrupts the witness, the verifier rejects.
  - **Metadata fields** consumed only by A4 instrumentation: `cycles[].major`, `cycles[].minor`. Mutating these (`INSTR_TYPE_MOD`) doesn't touch the witness, the verifier accepts → false bug.

The single edge case where `INSTR_TYPE_MOD` *is* effectively a data mutation is when the original instruction is a control-flow instruction (e.g. `JalR`) whose semantics produce a register/memory write that the executor would not have produced under the mutated decode. Run [33] is exactly that case: the mutation hit a `JalR` and the rejection followed.

### 5.1 Why the zoned selector "looks better" on this metric

The zoned selector and the uniform-arm selector both pick the mutation kind uniformly at random over the 8 kinds (see `fuzzer.py:311` and `fuzzer.py:669`: `self.rng.choice(self.MUTATION_KINDS)`). They differ only in *step* selection. So the rate of `INSTR_TYPE_MOD` runs is structurally the same. What differs is:

- The zoned selector concentrates mutations on certain step zones (Init / Core / Final). For `INSTR_TYPE_MOD`, the *step* it lands on doesn't actually change the false-positive rate — what matters is the original instruction at that step, and arithmetic/load instructions are common in any zone.
- The uniform-arm selector just makes the per-kind/step quota explicit. With 50 mutations and 8 kinds, ~6 of them land on `INSTR_TYPE_MOD`, and 5 of those happened to hit instructions where the metadata mutation was invisible.

So the user's secondary hypothesis ("the zoned focuses on data-specific entries") is *not* what's protecting the zoned selector from this issue. The zoned selector has the same problem; we just see it more starkly here because (a) the campaign is small, and (b) we're now explicitly diagnosing per-run outcomes.

---

## 6. Why no other mutation kind produced a "bug"

For each non-`INSTR_TYPE_MOD` kind in the smoke campaign, the mutation writes a field that *is* consumed by the prover:

| Kind | Field mutated | Prover consumer |
|------|---------------|-----------------|
| `COMP_OUT_MOD` | `txns[idx].word` (a write txn) | Memory-permutation argument and `MemoryWrite` constraints |
| `INSTR_WORD_MOD_FULL/SUR` | `txns[fetch].word` and `prev_word` | `VerifyOpcodeF3/F3F7`, decoder columns, downstream register writes |
| `LOAD_VAL_MOD` | `txns[load].word` | Loaded register value → permutation arg |
| `MEM_VAL_MOD` | `txns[mem_read].word` | Memory permutation, `IsRead`, `MemoryWrite` |
| `PRE_EXEC_REG_MOD` | Register file txn at the cycle before exec | Register read value → arithmetic constraints |
| `STORE_OUT_MOD` | `txns[store].word` | `MemoryWrite`, memory permutation |

Every one of these mutations corrupts a value that ends up in the polynomial commitment. The verifier sees the corruption and rejects. The smoke campaign confirms: 0/45 non-`INSTR_TYPE_MOD` mutations were accepted.

---

## 7. Why this matters for next steps

This finding has direct implications for the cloud campaign work scoped in `PRECLOUD_MASTER_PLAN.md`:

1. **The "BUG!" classifier is currently a noisy signal because of `INSTR_TYPE_MOD` false positives.** At full campaign scale (1000+ mutations), `INSTR_TYPE_MOD` will produce on the order of 100+ false bugs unless we either filter them post-hoc or stop running them.

2. **`INSTR_TYPE_MOD` does not probe verifier soundness in its current form.** The mutation only exercises A4's *instrumentation* path — it generates `<constraint_fail>` traffic and touches coverage buckets. That has value as a coverage-discovery vehicle (it gives us new `(family, major, minor)` triples) but it cannot, by construction, find a real soundness gap.

3. **Two clean ways to fix this in a follow-up subphase**:
   - **Option A — Reclassify**: change the outcome classifier so that `kind == INSTR_TYPE_MOD ∧ outcome == ACCEPTED ∧ dl > 0 ∧ dg == 0` is reported as `NO_EFFECT` (or a new `INSTRUMENTATION_ONLY` bucket) rather than `BUG!`. Cheap; preserves the coverage benefit.
   - **Option B — Make `INSTR_TYPE_MOD` actually witness-affecting**: pair it with an `INSTR_WORD_MOD` so that both `cycle.major/minor` *and* `txns[fetch].word` are changed coherently. Then the witness genuinely reflects the new instruction, the constraints fire for real reasons, and any acceptance is a real bug. This also subsumes the current `INSTR_WORD_MOD` mutation kind.
   - (**Option C — Drop it**: just remove `INSTR_TYPE_MOD` from the mutation set. Loses the coverage benefit; not recommended.)

4. **The Phase III.0 reward function still attributes correct credit to these runs.** Because they emit no global failures, `Q_glob = 1`, and the reward is driven by `Q_loc · Q_rep`. The 5 false bugs got `r = 1.000` from the BUG bonus, which under a bandit selector would over-incentivize `INSTR_TYPE_MOD`. Under uniform-arm (this campaign) the over-incentive is moot because rewards don't drive selection. Worth noting for any future bandit comparison runs: the BUG bonus and `INSTR_TYPE_MOD` together create a feedback loop that should be neutralized via Option A or B before re-running the bandit.

---

## 8. Confidence and caveats

- **High confidence** that all 5 accepted runs are `INSTR_TYPE_MOD` (direct grep of `phase31_smoke_output.txt`).
- **High confidence** in the source-code claim that `cycle.major`/`cycle.minor` for `major ∈ {0..6}` are not consumed by the production prover path. Verified by exhaustive grep across `workspace/risc0-modified/risc0/circuit/rv32im` and the C++ kernels; every match falls into instrumentation, the mutation site itself, or a Poseidon2 path that requires `major >= 7`.
- **Medium confidence** in the precise reason run [33] was rejected. The output shows both an executor-side address mismatch warning (`preflight=0x3fffc038, actual=0x00081795`) and a memory-permutation violation. The likely sequence is: mutating `JalR → Lw` causes the witness generator to either produce a different memory-write pattern or crash the preflight reconciliation; either way the verifier rejects. The claim that "INSTR_TYPE_MOD on a control-flow instruction *can* be witness-affecting" stands regardless of the exact failure mode.
- **No verifier soundness implication** from any of the 5 accepted runs.

---

## 9. Suggested next-step ordering

Given the above, the smallest set of changes that (a) preserves coverage value and (b) eliminates the false-positive noise before cloud campaigns:

1. (Phase III.3 candidate) Add the `INSTRUMENTATION_ONLY` outcome bucket to `fuzzer.py`'s outcome classifier and `analyze_campaign.py`'s parser. Default-classify `INSTR_TYPE_MOD` accepted runs into it (with a single-line reason field).
2. Add a `db.global_failures`/`failures` query to surface "true bug candidates" — runs where `outcome=ACCEPTED ∧ kind ≠ INSTR_TYPE_MOD ∧ dg = 0`. (At present that set is empty in the smoke campaign, which is the right behavior.)
3. Defer Option B (`INSTR_TYPE_MOD` + `INSTR_WORD_MOD` coherent pairing) to a later subphase; it's a more invasive change and not blocking for the cloud A/B campaign.
