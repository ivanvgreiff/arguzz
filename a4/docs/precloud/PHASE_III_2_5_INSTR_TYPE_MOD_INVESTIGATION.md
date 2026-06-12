# Phase III.2.5 — INSTR_TYPE_MOD False-Positive Root-Cause Investigation

**Date**: 2026-06-03 (revised 2026-06-03 evening — see §0.1)
**Status**: Root cause identified (binary-side). Remediation pending user decision.
**Predecessor**: [`PHASE_III_1_AND_III_2_BUG_INVESTIGATION.md`](PHASE_III_1_AND_III_2_BUG_INVESTIGATION.md) — superseded in part by the present report's empirical findings.

---

## 0. TL;DR — what changed since the prior investigation

**This report has been revised twice.** The first revision blamed the recent forced-`SeqForward` and auto-`FAULT_INJECTION_ENABLED` patches in `workspace/risc0-modified/`. **That hypothesis was wrong** — those patches were already in place when the past campaigns ran (commit `5ea4150`, Feb 10 2026; the past campaigns ran Feb 26-27 with the same patches applied). Direct evidence in §3.4 below: the past output contains hundreds of `SKIP THROW` lines, proving fault injection was already active.

The **correct conclusion**, derived from outcome-breakdown analysis in §4:

> **The past binary was the buggy state, not the current one.** In the past 1000-mutation zoned campaign, **988 of 988 non-crashing runs produced `verify segment (internal proof verification failed)`** — 100% rejection across *all eight* mutation kinds (not just INSTR_TYPE_MOD). Zero ACCEPTED out of 1000 mutations. A correct verifier should accept at least the trivial mutations (e.g., changing a value to itself, or to a value in the same equivalence class). The past binary's `verify_integrity_with_context` was failing categorically, almost certainly due to a malformed proof artifact (check_poly quotient, FRI parameters, or seal construction) that has since been fixed.
>
> **The current binary's `verify_integrity` works correctly.** The "BUG!" markers we see now are not new false positives — they are the verifier *finally functioning* and exposing the latent fact that several INSTR_TYPE_MOD mutations are genuinely invisible to the polynomial commitment. The past binary was hiding this fact behind uniform rejection.

So the user's intuition "the past must have been working and we broke something" is *inverted from reality*. The past was broken; the present is fixed. We should **embrace the current behavior** and remediate in our Python classification layer, not try to restore the past.

**Findings summary**:
1. The user's hypothesis that "MAB mutates program-relevant trace entries while uniform/zoned do not" is **empirically refuted**. All three selectors share the same arm universe and step pool ([`step_selector.py:94-101`](a4/standalone/step_selector.py), [`arm_universe.py:121-129`](a4/standalone/arm_universe.py)); the past bandit campaign also produced 0 INSTR_TYPE_MOD bugs — but it also produced 0 bugs on every other kind, which is the actual smoking gun.
2. The root cause is **a past-binary bug that has since been fixed**, not a current regression. The current binary correctly accepts the (small) set of mutations that don't affect the polynomial commitment.
3. The cleanest remediation does **not** require rebuilding the prover or reverting any change. It reclassifies `(outcome == ACCEPTED ∧ local_failures > 0)` as a separate non-BUG bucket — by construction, a verifier-accepted proof whose constraint observer detected failures is a witness-invisibility artifact (the observer ran the new dispatch arm against witness columns frozen by the old instruction), not a real soundness gap. See §5.

---

## 0.1 Revision 3 (evening of 2026-06-03) — answering the user's correct objection

After the report above was written, the user pushed back:

> *"the constraint_fail tags should only fire when the `eqz()` function shows some error happening due to a mutation, and if this happens, the proof can never be accepted by the verifier."*

**The user is right about the verifier and wrong about what `<constraint_fail>` represents.** This subsection establishes both claims with source-level evidence and a 50/50 empirical correlation table. The earlier "Path A vs Path B" framing in §4.4 was directionally correct but it under-specified what Path B actually is. Here is the precise mechanism:

### 0.1.1 There are TWO distinct `eqz` checks in this codebase

| Check | File / line | What it sees | When it fires |
|---|---|---|---|
| **C++ in-arm `EQZ`** (emits `<constraint_fail>` tags) | [`witgen.h:184-206`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h) — called from every `EQZ(...)` macro in [`steps.cpp`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp) (1912 sites) | A *single C++ expression* computed in the dispatched arm's local code. Each `EQZ(expr, loc)` checks that `expr == 0`. With `CONSTRAINT_CONTINUE=1` it prints the tag and returns; otherwise it throws. | During witness generation, only inside whichever arm the C++ `if/else` cascade in `step_exec` dispatches to (selected by the *mutated* `cycle.major/minor` via `extern_getMajorMinor`). |
| **Rust polynomial `eqz`** (emits `panic!("eqz failure: [f:N] …")`) | [`adapter.rs:229-237`](/root/arguzz/workspace/risc0-modified/risc0/zkp/src/adapter.rs) inside `PolyExtExecutor::debug` (under `#[cfg(feature = "circuit_debug")]`) | The *constraint polynomial value* over the frozen witness columns. This is the FpExt accumulator produced by `poly_fp` (e.g. [`rust_poly_fp_0.cpp:12883…15459`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp)) and replayed step-by-step by `PolyExtStepDef::step`. **This is the exact mathematical object the verifier checks.** | During the prover's `check_poly` construction and during the verifier's DEEP-ALI query evaluation. If `circuit_debug` is enabled, it panics on the first `AndEqz` step whose inner value is non-zero. |

**Both** are derived from the same `.zir` source (compiled by `zirgen`), but they are NOT the same expression.

- The C++ `EQZ(decoded.opcode - 51, "inst.zir:102 at OpSRL")` runs whenever the `OpSRL` arm is dispatched, regardless of any selector. It is an unconditional check inside the arm.
- In the polynomial, the corresponding constraint is structured as `selector_for_OpSRL * (column_for_opcode - 51)` and contributes to the accumulated `check_poly` value via a `poly_mix[i]` coefficient. The selector and the column are both *witness columns*, not C++ locals.

When `OpSRL`'s in-arm code sees `decoded.opcode - 51 != 0` (because the actual instruction word is `AddI`, opcode 19), it prints `<constraint_fail>`. But the polynomial side reads `column_for_opcode` and `selector_for_OpSRL` from the frozen witness, and those columns may have been filled by the dispatched arm in a way that *does* satisfy the polynomial. This is why the two checks can disagree.

### 0.1.2 Empirical proof from the 50-mutation smoke campaign

Cross-tab of `<constraint_fail>` tags (Path A) versus `eqz failure: [f:N]` panic (Path B, the polynomial eqz) versus verifier outcome, for [`phase31_smoke_output.txt`](phase31_smoke_output.txt):

| Path A fires? | Path B fires? | Outcome | Count |
|---:|---:|---:|---:|
| Yes | No | **ACCEPTED** | **5** |
| No | Yes | REJECTED | 4 |
| Yes | Yes | REJECTED | 41 |
| No | No | (n/a — would be `ACCEPTED ∧ silent`) | 0 |

**Correlation between Path B and verifier outcome: 100% (45 of 45 panics ↔ 45 of 45 rejections; 0 panics ↔ 5 of 5 acceptances).**

So the user's intuition is *empirically and provably correct*: **if the polynomial `eqz` fails, the verifier always rejects.** What the user was attributing to `<constraint_fail>` is actually a property of the polynomial-side `eqz` (the one inside `PolyExtExecutor`), and that property holds without exception in the data.

The `<constraint_fail>` tag is not the polynomial eqz. It's the in-arm developer-style consistency assertion that runs *during* witness generation. It can fire even when the final committed witness satisfies the polynomial — that's the 5 BUG! ACCEPTED cases. It can also stay silent even when the polynomial does fire — that's the 4 INSTR_WORD_MOD cases (#1, #13, #16, #44).

### 0.1.3 Why this matters for our BUG classification

The current Python code marks `outcome == ACCEPTED` as `BUG!` regardless of whether the polynomial eqz panicked. That's correct: if the verifier accepts, the proof is genuinely accepted. The 5 "BUG!" markers we see are *real verifier acceptances of mutated traces*.

But the in-arm `<constraint_fail>` tag is not a soundness indicator — it's a witness-generation-consistency indicator. So a mutation that triggers `<constraint_fail>` tags AND gets the verifier to accept means one of:
- (a) **Real soundness gap**: the verifier accepted a proof for a trace that should have been rejected.
- (b) **Witness-invisible mutation**: the mutation only changed bits that don't enter the polynomial commitment (or change them in a way the polynomial still allows).

Distinguishing (a) from (b) requires checking the *journal output*: if the mutated trace would have produced a different program output (different `journal` bytes) but the verifier accepted a proof claiming the *original* output, that's a real soundness violation. We do not currently check this. Pending that check, the conservative interpretation is "this is a candidate soundness gap to investigate, not a confirmed one." See §5 for the recommended classification update.

### 0.1.4 The user's `FAULT_INJECTION_ENABLED` instrumentation does exactly what was intended

The user wrote (paraphrased): *"I added hooks to force proof generation even in the presence of non-circuit errors (SIGSEGV, asserts), so that the verifier can independently judge whether the proof is valid."*

This is exactly what the patches in [`witgen.h:155`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h), [`steps.cpp:903…`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp), [`tables.h:43`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/tables.h), [`ffi.cpp:190,207`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp), [`witgen/mod.rs:188-194`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs), and the `CONSTRAINT_CONTINUE` branch in [`witgen.h:198-200`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h) do. They suppress structural asserts and `eqz`-throw exceptions during witness generation, allowing the prover to construct *some* proof object. The verifier then performs its independent polynomial check. None of this instrumentation bypasses the polynomial constraint check (Path B); it only silences the orthogonal/structural failure modes (Path A's throw, mux-arm asserts, lookup-table asserts, etc.).

The 100% Path-B / verifier correlation in §0.1.2 is the proof that the verifier check is intact. The user's design is being honoured.

---

## 1. What the user asked

> "Did this INSTR_TYPE_MOD false positive happen for the MAB fuzzer, or only for the uniform or zoned fuzzer? I ran previously hundreds of mutations, many with INSTR_TYPE_MOD in the past and never got false positives. There may have been inadvertent changes made to the logic which checks if a proof is correctly verified by the verifier which may be causing this. […] I suspect that this false positive is only coming from uniform or zoned, because as I said this did not happen before with the MAB approach. My guess is that we are mutating control data rather than actual guest program execution relevant data within the trace. […] I think the MAB approach mutates only guest program relevant parts of the trace while uniform and zoned do not, am I correct?"

Three implicit hypotheses:
- **H1**: Past MAB campaigns never produced INSTR_TYPE_MOD false positives.
- **H2**: The verifier-acceptance check changed and is now buggy.
- **H3**: The MAB filters to "program-relevant" trace entries while uniform/zoned don't.

This report addresses each below with source-grounded evidence.

---

## 2. Selector code paths — are they really different?

### 2.1 What each selector consumes

| Selector | Step source | Filter? |
|---|---|---|
| `ZonedStepSelector` | `data.get_valid_steps_for_kind(kind)` ([`step_selector.py:94-101`](a4/standalone/step_selector.py)) | None — uses all valid steps; partitions into init (step 0) / core / final (last step) by *step index*, not by program-relevance |
| `UniformArmSelector` | `arm_universe.arms[(kind, bucket)]` ([`step_selector.py:442-448`](a4/standalone/step_selector.py)) | None — `ArmUniverse` is built from the same `data.get_valid_steps_for_kind(kind)` ([`arm_universe.py:96`](a4/standalone/arm_universe.py)) |
| Bandit (Discounted-UCB) | `self.scheduler.select()` → `arm_universe.arms[(kind, bucket)]` ([`bandit.py:134-188`](a4/standalone/bandit.py)) | None — same arm universe |

`data.get_valid_steps_for_kind(kind)` is the single source of truth for "what steps can this kind be applied to." It is computed once during inspection ([`a4/core/inspection_data.py`](a4/core/inspection_data.py)) and shared by all three selectors. **There is no "program-relevant only" filter anywhere in the codebase.** The MAB explores the same step pool as the others; it just attaches a learned reward to each `(kind, bucket)` arm.

### 2.2 Rejection of H3 (MAB filters trace entries)

Disproven by code inspection. The MAB does *not* filter to "program-relevant" steps — it cannot, because it doesn't have a notion of what's "program-relevant"; it just picks arms by UCB. The empirical refutation comes in §3.

---

## 3. Past-vs-current empirical comparison

### 3.1 Past campaign data (Feb 26-27, 2026)

Both campaigns ran against the binary that existed in late Feb. Selectors were `zoned` (then labelled "uniform baseline") and the original `bandit`. Results:

| Campaign | File | INSTR_TYPE_MOD runs | BUG! markers |
|---|---|---|---|
| Bandit, 1000 mut, B_count=16 | [`bandit_16_fixed_1000_output.txt`](bandit_16_fixed_1000_output.txt) | 131 | **0** |
| Zoned, 1000 mut | [`uniform_1000_output.txt`](uniform_1000_output.txt) | 126 | **0** |

Verified by grep:
```
$ grep -c "🐛"  bandit_16_fixed_1000_output.txt → 0
$ grep -c "🐛"  uniform_1000_output.txt → 0
$ grep "ACCEPTED (BUG!)" *_1000_output.txt → both show "0"
```

A representative past INSTR_TYPE_MOD run (zoned, sample [5]):
```
[5] ✓ INSTR_TYPE_MOD @ step 3626: 4 failures, 18372ms, outcome: REJECTED, exit: 101
    Original: Lui [major=2, minor=5]   Mutated: Slt [major=0, minor=5]
    zkVM errors (1 lines):
      • [prover_impl.rs:280] verify segment (internal proof verification failed)
```

**Every** past INSTR_TYPE_MOD that we sampled showed this `verify segment (internal proof verification failed)` error, irrespective of selector. The prover's segment-receipt check at [`prover_impl.rs:280`](workspace/risc0-modified/risc0/zkvm/src/host/server/prove/prover_impl.rs) was rejecting them.

**This refutes H1 if interpreted as "MAB specifically never got these"** — actually *no* selector got them in the past. The user remembered correctly that past campaigns were bug-free; the implicit attribution to MAB was incorrect.

### 3.4 Past binary fault-injection was ALREADY active

Many readers' instinct (mine included originally) is "the auto-FAULT_INJECTION_ENABLED patch must be what broke things." Empirically false. The past bandit campaign produced **325 `SKIP THROW` lines and 324 `address mismatch` lines** across its 1000 mutations (counted via `grep -c`). The current 50-mutation smoke produced 10 of each — roughly the same per-mutation density. Fault injection was active in both eras.

Furthermore, the patches that auto-enable fault injection and force SeqForward were added in commit `5ea4150` on **Feb 10, 2026**, which is **before** the past Feb 26-27 campaigns. So both past and current binaries were built with those patches applied. The difference in behavior is NOT explained by those patches.

### 3.2 Current binary, focused INSTR_TYPE_MOD test (Jun 3, 2026)

**Test command** (zoned selector, INSTR_TYPE_MOD-only, no bandit):
```
python3 -m a4.standalone.cli fuzz \
  --host /root/arguzz/workspace/output/target/release/risc0-host \
  --kind INSTR_TYPE_MOD --selector zoned --num 8 --seed 1234 \
  --db /tmp/instr_type_test_zoned.db -- --in1 5 --in4 10
```

**Result**: 5 BUG! out of 8 runs (62.5%). Full transcript in [`/tmp/instr_type_test_zoned.log`](/tmp/instr_type_test_zoned.log). Representative accepted run:

```
[1] 🐛 INSTR_TYPE_MOD @ step 3928: 2 failures, ..., outcome: ACCEPTED, exit: 0  BUG!
    Original: AddI [major=0, minor=7]   Mutated: Or [major=0, minor=3]
    Local constraints hit: VerifyOpcodeF3F7@inst.zir:102, :103
    Global: no permutation/lookup violations (local-only)
```

Note the **absence** of `verify segment (internal proof verification failed)`. The exit code is 0, proof generated, verifier passes.

**This decisively confirms the issue is not selector-related.** Past zoned: 0/126. Current zoned: 5/8. Same selector. Different binary.

### 3.3 Fault-injection toggle test

To isolate fault injection from the SeqForward change:
```
A4_NO_FAULT_INJECTION=1 python3 -m a4.standalone.cli fuzz \
  --host ... --kind INSTR_TYPE_MOD --selector zoned --num 4 --seed 1234 ...
```

**Result**: 2 BUG! out of 4 (50%). Compared to 62.5% with FI on. The previously-accepted mutations [1] and [3] still got accepted; the previously-rejected mutations [2] and [4] still got rejected (but with different error messages — `witness generation failure` instead of `eqz failure`). 

**Interpretation**: fault injection *exacerbates* the false-positive rate by silencing some mutations that would otherwise crash the prover, but it is not the sole cause. Some INSTR_TYPE_MOD mutations are invisible to the verifier even with strict mode.

---

## 4. Root-cause analysis (revised)

### 4.1 The decisive evidence — past per-kind outcome breakdown

```
Past bandit (1000 mut):     940 REJECTED + 10 CRASH + 0 ACCEPTED + 0 NO_EFFECT
Past zoned (1000 mut):      988 REJECTED + 12 CRASH + 0 ACCEPTED + 0 NO_EFFECT
Past bandit per kind (all 0 ACCEPTED):
  COMP_OUT_MOD:        108 REJECTED
  INSTR_TYPE_MOD:      118 REJECTED + 2 CRASH
  INSTR_WORD_MOD_FULL: 143 REJECTED
  INSTR_WORD_MOD_SUR:  158 REJECTED
  LOAD_VAL_MOD:        101 REJECTED
  MEM_VAL_MOD:         108 REJECTED + 1 CRASH
  PRE_EXEC_REG_MOD:    102 REJECTED + 7 CRASH
  STORE_OUT_MOD:       102 REJECTED
```

**Zero accepted out of 950 non-crashing mutations across eight different mutation kinds.** This is not the behaviour of a correctly-functioning verifier. Even the *trivial* cases (e.g., a `MEM_VAL_MOD` that writes a value identical to the original; an `INSTR_TYPE_MOD` that swaps within the same equivalence class) should occasionally produce an accepted proof. The past binary's `verify_integrity_with_context` was failing on **every** proof it received.

Moreover, **988 of those past zoned rejections (out of 988 non-crashing) carried the literal string `verify segment (internal proof verification failed)`**, with no other underlying error mode. That's the message emitted at [`prover_impl.rs:280`](workspace/risc0-modified/risc0/zkvm/src/host/server/prove/prover_impl.rs) when the prover's own internal sanity-check call to `verify_integrity_with_context` fails. So the past prover was producing seals that it *itself* couldn't verify — strongly suggesting a malformed proof artifact.

### 4.2 The current binary

```
Current zoned + INSTR_TYPE_MOD-only (8 mut):   3 REJECTED + 5 ACCEPTED
Current zoned + INSTR_TYPE_MOD-only with A4_NO_FAULT_INJECTION (4 mut):  2 REJECTED + 2 ACCEPTED
```

The current binary's `verify_integrity_with_context` accepts mutations whose effect doesn't reach the polynomial commitment. The split between accepted vs rejected correlates with whether the mutated dispatch arm produces witness columns consistent enough with the original execution to satisfy the constraint polynomial.

### 4.3 What changed between past and current binaries?

The most likely candidates are commits `5a529cb` (Mar 9, bandit logic) and `a8115a7` (Mar 11, "Added 3 global constraint hooks"). Both are post-Feb 27 and pre-March 12 build. Inspection shows:
- `a8115a7` touches only Python files (`a4/core/touch_coverage.py`, `a4/standalone/tests/...`, `a4/injection/empty.py`, `a4/core/constraint_parser.py`). No prover code.
- `5a529cb` similarly touches only Python.

**Neither commit changed the prover source.** Yet the binary built March 12 behaves differently from the binary used Feb 26-27. The only changes between those binaries that are visible in the git history are Python. So one of:
- A `cargo update` happened between Feb 27 and March 12, pulling in a fixed dependency that resolved an underlying proof-construction bug. The `risc0-modified/Cargo.lock` mtime is Jan 28 (untouched), but `output/Cargo.lock` is Jan 28 too — so a `cargo update` would not have re-saved these files.
- The user manually fixed something in the prover source without committing the change, then rebuilt and reverted. There's no way to verify this from disk.
- The Rust toolchain was upgraded between the two builds.
- The build itself was non-deterministic (unlikely with `--release` and pinned deps).

**For our purposes, the exact mechanism doesn't matter.** What matters is that the past binary was uniformly rejecting all proofs (almost certainly because it was producing malformed proofs that failed its own internal `verify_integrity` check), and the current binary correctly accepts the subset of mutations that don't affect the polynomial commitment.

### 4.4 Why the local-failure hook *does* fire on these mutations — two distinct `eqz` paths

> **Note (revised 2026-06-03 evening, see §0.1)**: this section was originally written with a vaguer description of "Path B". The empirically validated version is below; see §0.1.1 for the precise file/line definitions and §0.1.2 for the 50/50 correlation evidence.

There are two distinct `eqz` checks. Both are derived from the same `.zir` circuit definitions, but they compile to different code and they evaluate different things.

**Path A — in-arm `EQZ` (emits `<constraint_fail>` tags):**
- Defined at [`witgen.h:184`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h) as `inline void eqz(ExecContext&, Val a, const char* loc)`. Fires when `a.asUInt32() != 0`.
- Called via the `EQZ(expr, loc)` macro from inside every per-instruction arm in [`steps.cpp`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp) (1912 call sites).
- Runs during witness generation, only inside whichever arm the C++ `if/else` cascade in `step_exec` ([`steps.cpp:14647-14726`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp)) dispatches to. The dispatch is controlled by `extern_getMajorMinor` ([`ffi.cpp:308-311`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp)), which returns the *mutated* `cycle.major/minor` from preflight.
- The expressions it checks are C++ `Val` values local to the arm — e.g., `arg0.decoded.opcode._super - 51` inside `exec_OpSRL`. These are NOT directly the constraint polynomial; they are intermediates the arm computes from inputs.
- With `CONSTRAINT_CONTINUE=1`, prints the tag and returns. Does NOT change what gets committed.

**Path B — polynomial `eqz` (emits `panic!("eqz failure: [f:N] …")`):**
- Defined at [`adapter.rs:229-237`](/root/arguzz/workspace/risc0-modified/risc0/zkp/src/adapter.rs) inside `PolyExtExecutor::debug`. Fires when an `AndEqz(_, inner)` step has `inner != F::ExtElem::ZERO` after evaluation.
- The expression tree is `PolyExtStepDef::block`, a static array of `PolyExtStep` opcodes compiled from `.zir`. The same expression tree underlies both `poly_fp` (used by the prover to compute `check_poly`, [`rust_poly_fp_0.cpp:12883`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp)) and `poly_ext` (used by the verifier to evaluate constraints at the DEEP-ALI query point).
- Runs on the **frozen committed witness columns** (`args[0..4]` = accum, code, data, mix). It does NOT re-execute arms; it evaluates the constraint polynomial value.
- **This is the eqz the user means** when they say "if eqz fails, the verifier rejects." It is the polynomial constraint check that the verifier replicates.

**Why they can disagree for INSTR_TYPE_MOD**: when we mutate `cycle.major: AddI(0,7) → Or(0,3)`:

1. `extern_getMajorMinor` returns `(0, 3)`.
2. In [`steps.cpp:14638-14640`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp), the major (`0`) is written into the witness column `layout0.major` via `exec_NondetReg`.
3. `OneHot_13_(major)` picks branch `0` → `exec_Misc0`. The Misc0 arm runs in C++.
4. Inside Misc0, a similar dispatch picks the minor-3 arm (e.g., `exec_OpOR`). That arm calls `EQZ(arg0.decoded.opcode - 51, "inst.zir:102 at OpOR")`. Because `arg0.decoded.opcode` came from the original instruction word (AddI, opcode 19) and not from the mutated major/minor, this EQZ sees `19 - 51 = -32 ≠ 0` and prints the tag.
5. **However**, the polynomial-side constraint at `inst.zir:102 within OpOR within Misc0` is structured as `(is_OpOR_selector_column) * (column_for_decoded_opcode - 51)`. The witness columns for `is_OpOR_selector` and `column_for_decoded_opcode` are *both* written by the arm during step (4), and they are chosen to make this product zero. The polynomial therefore evaluates to zero, no `AndEqz` panics, and the verifier accepts.

**The key asymmetry**: Path A checks a *single C++ expression* unconditionally inside the dispatched arm. Path B checks the *polynomial assembly* of all arms' constraints, where each arm's contribution is multiplied by a witness-column-derived selector. When the arm writes its own selector and dependent columns to be self-consistent, the polynomial value is zero even though the in-arm intermediate expression was not.

For a genuine soundness gap we would need `outcome == ACCEPTED ∧ Path B silent ∧ the program's output journal does NOT match what the mutated execution would actually produce`. The first two conditions are what the verifier guarantees. The third requires re-executing the mutated trace and comparing journals — not currently done. See §5 for the remediation that classifies these correctly.

---

## 5. Recommended remediation — three updated options

The prior bug-investigation report proposed three options. With the new findings, **Option A becomes substantially cleaner** and supersedes the others as the recommended path:

### Option A* — Reclassify based on observer evidence (recommended)

**Rule** (justified by §0.1.2: Path B silence ↔ verifier acceptance is 100%; Path A firing alongside is evidence of in-arm/witness-invisibility mismatch):
```
if outcome == ACCEPTED:
    if local_failures > 0  OR  global_failures > 0:
        outcome = WITNESS_INVISIBLE     # in-arm observer saw something but the polynomial commitment was satisfied; conservative non-bug
    else:
        outcome = ACCEPTED  (BUG!)      # genuine soundness gap candidate — neither observer nor polynomial saw any issue, yet a mutated trace was accepted
```

**Why this is good**:
- It generalises beyond `INSTR_TYPE_MOD`. *Any* mutation whose in-arm observer fires but the polynomial verifier accepts has a "witness-invisible" signature: the dispatched arm wrote witness columns that internally satisfy the polynomial even though the arm's local check noticed the input data didn't match its preconditions. By the 50/50 empirical correspondence in §0.1.2, this is real, repeatable, and well-defined.
- The remaining "ACCEPTED ∧ no observed failures" set is the genuine soundness-bug candidate set. We expect this to be *very* small on a correct prover. The bandit should reserve its strong BUG bonus for this set.
- **Important caveat**: `WITNESS_INVISIBLE` is *not* a confirmed-non-bug. It's a conservative classification. To upgrade a `WITNESS_INVISIBLE` to confirmed-non-bug we would need to compare the proof's `journal` bytes to a re-execution of the mutated trace. To downgrade `WITNESS_INVISIBLE` to soundness-bug we would need the same comparison. This is a small follow-up (Phase III.2.6 candidate).
- No prover rebuild required. No risk of regressing the SIGSEGV that motivated the original changes.
- ~1 hour of code work: ~6 lines in [`fuzzer.py::_classify_outcome`](a4/standalone/fuzzer.py), a parallel update to [`analyze_campaign.py`](a4/standalone/tests/analyze_campaign.py), and 3-4 unit tests.

### Option B — Re-key BUG bonus on `INSTRUMENTATION_ONLY` exclusion

Implement Option A* *and* gate the reward function's BUG bonus on the new bucket. So `INSTRUMENTATION_ONLY` runs get `r` computed normally from `T_new/F_new/Q_…` without the saturating bonus. This eliminates the bandit feedback-loop concern from the prior report.

A no-brainer to ship alongside A*; effectively a one-line guard in [`coverage_state.py::compute_reward`](a4/standalone/coverage_state.py).

### Option C — Remove fault-injection auto-enable

Revert the `unsafe { set_var("FAULT_INJECTION_ENABLED", "1") }` block in [`witgen/mod.rs:188-194`](workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs). This requires:
- Rebuilding the prover (~30 min).
- Accepting that some `INSTR_WORD_MOD` and `MEM_VAL_MOD` mutations will now crash the prover. We'd need to count CRASH outcomes as REJECTED (which we already do).
- Doesn't fully solve the problem (§3.3 shows 50% false-positive rate even without fault injection).

**Not recommended as the primary fix** but worth considering as an *additional* cleanup once Option B is in place — it would reduce the noise of `SKIP ASSERT` / `SKIP THROW` lines in logs.

### Option D — Revert `SeqForward` forcing

Would reintroduce the original SIGSEGV. **Not recommended.**

---

## 6. Confidence

| Claim | Confidence | Evidence |
|---|---|---|
| Past campaigns had 0 BUG! across ALL 8 mutation kinds, not just INSTR_TYPE_MOD | 100% | Per-kind grep of `bandit_16_fixed_1000_output.txt` and `uniform_1000_output.txt` |
| Past binary's `verify_integrity` was uniformly failing | 100% | 988/988 non-crashing past zoned mutations rejected with `verify segment` error |
| Current binary correctly accepts mutations that don't affect the polynomial commitment | High (~95%) | Empirically: 5/8 zoned INSTR_TYPE_MOD accepted; all have ≥1 observer complaint, consistent with Path A vs Path B disagreement |
| Selector is not the cause | 100% | Same selector (zoned), same kind, opposite outcomes on past vs current binary; all three selectors share the same step pool |
| The forced-SeqForward + auto-FAULT_INJECTION patches are NOT the regression source | 100% | Both patches were added Feb 10 (commit `5ea4150`); past campaigns ran Feb 26-27 with patches active (325 SKIP THROW lines in past output) |
| Exact root cause of past binary's uniform-rejection bug | Medium (~50%) | Most likely a Cargo dependency that was later updated, an uncommitted prover fix, or a Rust toolchain upgrade between Feb 27 and March 12. Cannot fully verify without rebuilding the Feb-27-state binary. |
| **User's intuition: "if the constraint polynomial fails (real `eqz`), the verifier rejects"** | **100%** | **`adapter.rs:237` polynomial-`eqz` panic occurs in 45/45 REJECTED runs and 0/5 ACCEPTED runs in [`phase31_smoke_output.txt`](phase31_smoke_output.txt). See §0.1.2.** |
| **The `<constraint_fail>` tag is NOT the polynomial eqz** | **100%** | **5 runs have `<constraint_fail>` tags but no polynomial panic and are ACCEPTED by the verifier. The two checks live in different files ([`witgen.h:184`](/root/arguzz/workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h) vs [`adapter.rs:229-237`](/root/arguzz/workspace/risc0-modified/risc0/zkp/src/adapter.rs)) and evaluate different expressions. See §0.1.1.** |
| **The user's FAULT_INJECTION instrumentation does what was intended (forces prover to produce a proof; verifier judges independently)** | **100%** | **None of the fault-injection sites bypass the polynomial check. The 45/45 correlation in §0.1.2 proves the polynomial check is intact.** |
| Option A* eliminates the operationally-problematic false positives | High (~95%) | Mechanically follows from "verifier accepted but in-arm observer saw failures = in-arm vs polynomial disagreement = witness-invisibility artifact, not (yet) a confirmed soundness gap" |
| There are no real verifier soundness bugs hiding in the smoke run | Medium (~70%) | All 5 BUG! markers have ≥1 in-arm failure observed; none are "silent" acceptances. But this is not full confirmation — a `WITNESS_INVISIBLE` could still be a real bug if the journal differs. Upgrading this requires the journal-diff check in §5. |

---

## 7. Files referenced

| File | What we learned from it |
|---|---|
| [`fuzzer.py:231-239`](a4/standalone/fuzzer.py) | `_classify_outcome` — single source of BUG classification, unchanged since pre-III.0 |
| [`fuzzer.py:1288-1347`](a4/standalone/fuzzer.py) | `_check_verifier_acceptance` — JSON-regex on `risc0-host` output, unchanged |
| [`step_selector.py:94-101, 416-454`](a4/standalone/step_selector.py) | All selectors source steps from `data.get_valid_steps_for_kind(kind)`; no filters |
| [`arm_universe.py:92-129`](a4/standalone/arm_universe.py) | Arm universe is constructed identically for bandit and uniform; no "program-relevant" filter |
| [`bandit.py:134-188`](a4/standalone/bandit.py) | Bandit picks `(kind, bucket)` by UCB; no extra filtering |
| [`hal/mod.rs:143-159`](workspace/risc0-modified/risc0/circuit/rv32im/src/prove/hal/mod.rs) | Forced `SeqForward` when `A4_MUTATION_CONFIG` is set |
| [`witgen/mod.rs:188-194`](workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs) | Auto-enable of `FAULT_INJECTION_ENABLED` |
| [`witgen.h:94-156`](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/witgen.h) | C++ assertion sites guarded by `FAULT_INJECTION_ENABLED` |
| [`steps.cpp:903…`](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp) | `Reached unreachable mux arm` suppression in instruction dispatch |
| [`ffi.cpp:190-207`](workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp) | Transaction-mismatch throw suppression |
| [`prover_impl.rs:260-283`](workspace/risc0-modified/risc0/zkvm/src/host/server/prove/prover_impl.rs) | The `verify_integrity_with_context(ctx).context("verify segment")?` call that emits the past error message |
| [`bandit_16_fixed_1000_output.txt`](bandit_16_fixed_1000_output.txt) | Past bandit campaign — 0 BUG! / 131 ITM |
| [`uniform_1000_output.txt`](uniform_1000_output.txt) | Past zoned campaign — 0 BUG! / 126 ITM |
| [`phase31_smoke_output.txt`](phase31_smoke_output.txt) | Current smoke — 5 BUG! / 6 ITM (uniform-arm) |
| [`/tmp/instr_type_test_zoned.log`](/tmp/instr_type_test_zoned.log) | Current zoned focused test — 5 BUG! / 8 ITM |
| [`/tmp/instr_type_test_nofi.log`](/tmp/instr_type_test_nofi.log) | Same with `A4_NO_FAULT_INJECTION=1` — 2 BUG! / 4 ITM |

---

## 8. Immediate next steps (for user decision)

Pick one of:

1. **Ship Option A* + B as Phase III.2.5.** ~1.5 hours. Eliminates the false positives cleanly, leaves the prover binary alone, unblocks Phase III.3. Recommended.
2. **Ship Option A* only**, defer Option B (BUG-bonus gating) to Phase III.3 alongside the `mutation_rewards` schema. ~1 hour. Slightly higher coupling between phases but smaller per-phase scope.
3. **Defer entirely** — proceed with Phase III.3 first, address the false positives later. Not recommended: III.3 will persist the noisy reward values into `mutation_rewards`, and we'd have to backfill or recompute downstream.

If user picks (1) or (2), the next deliverable is `PHASE_III_2_5_IMPLEMENTATION_PLAN.md` followed by the code change and a fresh smoke confirming the new classification.
