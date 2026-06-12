# Phase III.2.5 — False-Positive `BUG!` Investigation: Tracking & Plan

**Status:** RESOLVED (Jun 3, 2026). Root cause identified, fix applied,
empirically validated.

**TL;DR for catch-up readers:**

- The 5 `🐛 BUG!` markers in `phase31_smoke_output.txt` were NOT a campaign-
  logic bug, NOT a soundness bug in risc0's STARK, and NOT caused by our
  global-constraint hooks.
- They were caused by `circuit_debug` being enabled in
  `workspace/output/host/Cargo.toml`'s `prove` feature
  (`"risc0-zkvm/circuit_debug"`).
- `circuit_debug` is an UPSTREAM risc0 debug-only cargo feature that, when
  enabled, causes the prover to scan its check polynomial for any non-zero
  row, pick that row's `bad_z` as the DEEP-ALI query point z, and write z
  to the transcript; the verifier then READS z from the transcript instead
  of computing it via Fiat-Shamir, and the `check == result` test trivially
  passes at the chosen z. The verifier accepts the malformed proof.
- Fix: remove `circuit_debug` from `prove` in `host/Cargo.toml`. With this
  change, 5/5 `INSTR_TYPE_MOD` mutations correctly classify as REJECTED,
  and the unmutated baseline still verifies OK.
- See Section 9 for the smoking gun and Section 10 for the fix.

This document is the **single source of truth** for this investigation. Every
finding, every experiment, every dead end is recorded here.

---

## 1. Bedrock observations (verified)

| # | Observation | Evidence |
|---|-------------|----------|
| 1 | The 5 `BUG!` markers in `phase31_smoke_output.txt` are all `INSTR_TYPE_MOD`. | `grep "🐛" phase31_smoke_output.txt` |
| 2 | Each BUG! case has `dl > 0` (local failures) and `dg = 0` (no global broken). | Same file, in the result row |
| 3 | The one `INSTR_TYPE_MOD` that was REJECTED ([33]) has `dl=5, dg=3` and `G=memory`. | Same file |
| 4 | In OLD campaigns (`uniform_1000_output.txt`, `bandit_16_1000_output.txt`, `bandit_16_fixed_1000_output.txt`, Feb 26-27 2026) the campaign summary lines show **0** "ACCEPTED (BUG!)" mutations. | `grep -A2 "ACCEPTED (BUG)" *_output.txt` |
| 5 | The Python function `_check_verifier_acceptance` in `a4/standalone/fuzzer.py` is **byte-for-byte identical** between commit `5a529cb` (pre-global-hook) and current HEAD. | `python3` diff of extracted function bodies |
| 6 | `_check_verifier_acceptance` returns `True` if `<record>{"context":"Verifier", "status":"success"}</record>` is in `output`. | Function body |
| 7 | `_classify_outcome` returns "ACCEPTED" iff `result.verifier_accepted` is True. | `a4/standalone/fuzzer.py:232-238` |
| 8 | Re-running mutation [17] (AddI @ step 881 → SrlI) directly against the current `risc0-host` binary with the smoke-test env vars produces both `<constraint_fail>` AND `<record>{"context":"Verifier", "status":"success"}</record>` AND exit 0. | `/tmp/mut17_full.log` |
| 9 | Same run also emits `<a4_check_poly_scan>{"total_cycles":32768, "nonzero_cycles":1, "first_nonzero_cycles":[17508]}` and `<a4_poly_fp_summary>{"domain":131072, "nonzero_cycle_rows":1, "nonzero_extended":98304}`. | Same log |
| 10 | Re-running mutation [17] WITHOUT `CONSTRAINT_CONTINUE=1` produces panic (exit 101) and **no Verifier record at all**; the prover aborts in witness generation. | `/tmp/mut17_no_cc.log` |
| 11 | `risc0-host` binary `mtime = 2026-03-12 00:17`; last A4 commit before that is `a8115a7` (Mar 11) which added the 3 global constraint hooks. | `stat ./workspace/output/target/release/risc0-host` |
| 12 | Multiple `risc0-modified` source files (`witgen.h`, `ffi.cpp`, `eval_check.cpp`, `prove/witgen/mod.rs`, `zkp/src/prove/prover.rs`, `prove/hal/mod.rs`) have local uncommitted modifications; some mtimes are AFTER Mar 12 (so NOT in the current binary), some are before. | `git status` + `find -newer` checks |
| 13 | The current binary HAS the `<a4_check_poly_scan>` / `<a4_poly_fp_*>` / `<a4_family_residue>` / `<a4_family_stats>` tags in its output, even though the source files emitting these have mtimes AFTER Mar 12 — meaning either mtimes were touched-not-edited, or the binary was rebuilt after Mar 12 with these tags. | `/tmp/mut17_full.log` |

## 2. What we do NOT yet know

- Whether the OLD (Feb-built) `risc0-host` binary would honor `CONSTRAINT_CONTINUE` in `eqz` the same way the current one does, OR whether the OLD binary would have always panicked on the first `eqz` failure (regardless of env var).
- Whether the Python campaign classifier in OLD campaigns ever output `outcome: ACCEPTED, exit: 0` for any mutation. The "0 BUG!" counts in OLD logs could be because (a) it never happened, or (b) it happened but was classified differently somewhere.
- Whether the verifier in risc0 truly does accept the malformed proof, or whether it is some other layer (e.g. `receipt.verify(GUEST_ID)` reading a non-existent receipt and returning `Ok(())` by mistake, or our parser confusing the start record with the success record).
- The exact behaviour of `_classify_outcome` and the campaign loop end-to-end — i.e. what code path leads from a `<record>{"context":"Verifier", "status":"success"}</record>` line in `output` to a printed `🐛 BUG!`.
- Whether the campaign-side logic for CRASH detection is correctly separating crashes from rejections, AND whether maybe a path is wrongly labeling a crash as ACCEPTED.

## 3. Hypotheses currently on the table — RESOLVED

| # | Hypothesis | Argues for | Argues against | Final disposition |
|---|------------|-----------|----------------|-------------------|
| H1 | **Pure risc0 STARK soundness behavior (real risc0 bug or property)** | non-zero poly_fp and check_poly observed | OLD binary did NOT show this | **PARTIALLY TRUE in a narrow sense**: this is real risc0 BEHAVIOUR — but only under the `circuit_debug` cargo feature. The relevant code path is upstream and intentional. See H7. |
| H2 | **CONSTRAINT_CONTINUE didn't exist in OLD binary** | mutation 17 panics without CC=1 | OLD logs show 988-990 REJECTED with proof-generated markers, indicating CC was active in OLD too | **FALSIFIED.** CC was active in OLD too; OLD output also showed `[proof:GENERATED] exit 101 REJECTED`, identical to the current no-`circuit_debug` build. |
| H3 | **Campaign classifier or display bug** | unread code paths | function bodies look correct | **FALSIFIED.** Section 6 walk-through and Step 4's empirical test prove the classifier reads what risc0 emits. |
| H4 | **OLD vs NEW seed difference** | single REJECTED INSTR_TYPE_MOD had `dg>0` | OLD had 100+ INSTR_TYPE_MODs across multiple campaigns, all REJECTED | **FALSIFIED.** Even with the SAME mutation [17], NEW accepts and OLD-style (no-`circuit_debug`) rejects, deterministically. |
| H5 | **Display malfunction** | not yet read | summary matches per-run lines | **FALSIFIED.** Walk-through confirms identical boolean flows. |
| H6 | **Intermediate edits in risc0-modified C++/Rust changed the binary's behaviour** | partially edited recently | hard to confirm without rebuild | **PARTIALLY TRUE.** The actual cause is in `host/Cargo.toml` (an enable of `circuit_debug`), not in the C++/Rust source edits themselves. The C++/Rust source edits are pure instrumentation. See H7. |
| H7 (NEW) | **`circuit_debug` cargo feature is enabled in `prove`** | upstream risc0 code (`prove/prover.rs:208-220` and `verify/mod.rs:309-316`) gates an explicit "pick z = bad_z, write z to transcript, read z from transcript" mechanism on `circuit_debug` | n/a | **CONFIRMED.** With `circuit_debug` removed, mutation 17 → REJECTED. With `circuit_debug` present, mutation 17 → ACCEPTED. Baseline still verifies OK in both. 5-mutation batch confirms 5/5 REJECTED in the fix. |

## 4. The plan (incremental — do NOT skip steps)

### Step 0 — DO NOT MODIFY ANYTHING YET
Save the current state so we never lose what we have:
```bash
cp workspace/output/target/release/risc0-host /root/risc0-host.MAR12.bak
git -C workspace/risc0-modified diff > /root/risc0-modified.CURRENT.patch
git diff > /root/arguzz.CURRENT.patch
```

### Step 1 — Map the campaign code path end-to-end (read-only)
Walk through, in order, exactly what happens in `run_mutation` → `run_a4_mutation` → output parsing → outcome classification → print. Do NOT take any prior summary at face value. Write the flow into Section 6 of this doc as a numbered list with exact line numbers. Verify on each step:
- which env vars are set
- which `<record>` / `<constraint_fail>` / `<a4_*>` tags can possibly appear
- which Python regex consumes them
- which boolean field they map to
- which branch of `_classify_outcome` they hit
- which branch of `_print_mutation_result` produces `🐛` vs `✓` vs `💥` vs `○`

### Step 2 — Verify crash-vs-rejection separation
User said their old campaign had explicit logic to distinguish CRASH from REJECTED. Find that logic in the current campaign and verify it works. Specifically:
- find every place that touches `result.crashed`
- find every place that touches `result.exit_code`
- map the exit-code branches: 0 → ?, 101 → ?, 139 → CRASH, etc.
- verify in `_classify_outcome` and `_print_mutation_result`

### Step 3 — Clone old version of OUR repo and diff campaign logic
```bash
cd /tmp && rm -rf arguzz_pre_hooks
mkdir arguzz_pre_hooks && cd arguzz_pre_hooks
git clone /root/arguzz .
git checkout 5a529cb       # "final bandit logic before global constraint additions"
```
Diff each file under `a4/standalone/` and `a4/core/` between this snapshot and current.
We're looking for **any** divergence in:
- output parsing logic
- outcome classification logic
- print logic
- env vars passed to the subprocess
- how exit codes are interpreted
Document every meaningful difference in Section 7.

### Step 4 — Run the SAME mutation [17] against current binary, instrument every step
Run mutation 17 with full env vars set, save the raw output. Then run the campaign's parsing code on that raw output and print what `_classify_outcome` says. If it says ACCEPTED, we have empirical confirmation that the classifier is reading what risc0 emits and labelling it as ACCEPTED.

If for some reason it says something else when run via the campaign harness, we've found a display-layer bug.

### Step 5 — Rebuild risc0 from scratch and re-run the same mutation
We've been speculating about whether the current binary is or isn't "old". Just build it fresh, label it as the "post-March-edits" binary, and run the same mutation:
```bash
cp workspace/output/target/release/risc0-host /root/risc0-host.MAR12.bak  # already done in step 0
cd workspace/risc0-modified  # or wherever the cargo workspace root is for risc0-host
cargo build --release --bin risc0-host
```
Then re-run mutation 17. Result confirms: the current source produces this verifier-acceptance behavior or not.

### Step 6 — If step 5 still shows verifier acceptance, isolate which risc0-modified change introduced it
The submodule has uncommitted edits. Selectively revert chunks of the diff — one set at a time — and rebuild:
1. Revert eval_check.cpp instrumentation only → rebuild → test.
2. Revert prover.rs scan only → rebuild → test.
3. Revert ffi.cpp / witgen.h / witgen/mod.rs Hook 3 globals (NOT touch coverage, NOT a4 mutation block) → rebuild → test.
4. Revert hal/mod.rs SeqForward enforcement → rebuild → test.
5. Revert the witgen.h `eqz` modifications (touch_mark, constraint_fail printf, CONSTRAINT_CONTINUE return) → rebuild → test.
After each revert, run mutation [17]. The revert that flips the outcome from ACCEPTED to REJECTED is the smoking gun.

### Step 7 — Run a wider batch of INSTR_TYPE_MOD mutations on both binaries
Once we have a candidate smoking gun, run, say, 30 random INSTR_TYPE_MOD mutations on:
- the saved MAR12 binary
- the rebuilt new binary  
- (if applicable) a partially-reverted binary
And compare BUG! counts. This gives us statistical confidence.

### Step 8 — Decide on the fix
Once we know exactly what introduced the issue, decide:
- Is it a real bug we need to fix in risc0-modified?
- Is it a classifier issue we need to fix in a4 Python?
- Is it a fundamental property of CONSTRAINT_CONTINUE that we have to live with by re-classifying on the python side?

### Step 9 — Update master plan and investigation report
Once the root cause is known and the fix is applied, update:
- `PHASE_III_2_5_INSTR_TYPE_MOD_INVESTIGATION.md`
- `PRECLOUD_MASTER_PLAN.md`

## 5. Disciplined rules for this investigation

1. Never accept a hypothesis as truth without an experiment confirming it.
2. Never modify any file until the relevant step explicitly says so.
3. Every time the user is unconvinced of an explanation, **re-open** the hypothesis in Section 3 with a counter-argument and a new experiment.
4. When in doubt, **read** the actual code path top-to-bottom; do not pattern-match from memory.

## 6. Campaign code-path walk-through (verified Jun 3, 2026)

This section traces a single mutation from start to printed `BUG!` marker, by
function name and line number in current HEAD.

**Per-mutation entry point:** `A4Fuzzer._run_single_mutation`
(`a4/standalone/fuzzer.py:655-829`)

1. **Step / kind selection** (lines 664-710). For `--selector uniform` the
   selector returns `(kind, step)` together; for others, kind is fixed for the
   mutation and step is picked from the selector. Retry up to 10× if no valid
   target. If retries exhausted, returns None (counted as `stats.skipped_mutations`).
2. **Mutation config creation** (lines 691-710). `_create_mutation(kind, step)`
   produces the JSON config dict.
3. **Write config to tempfile** (lines 716-718).
4. **Subprocess invocation** (lines 720-724): `run_a4_mutation(host_binary,
   host_args, config_path)`. This lives in `a4/core/executor.py:171-221` and
   does the following:
   * Sets env: `A4_MUTATION_CONFIG=<path>`, `CONSTRAINT_CONTINUE=1`,
     `A4_COVERAGE_TOUCH=1`, `A4_FAMILY_RESIDUE=1`.
   * Runs `subprocess.run([host_binary, ...host_args], capture_output=True,
     text=True, env=...)` — captures both stdout and stderr.
   * Parses `<constraint_fail>` tags into a `List[ConstraintFailure]`.
   * Parses `<a4_touch_coverage>` into a bitmap.
   * Parses `<a4_family_residue>` and `<a4_family_detail>` into lists of dicts.
   * Returns a `MutationExecutionResult` with `stdout`, `stderr`,
     `combined_output` (stdout+stderr), `exit_code`, `failures`, `touch_bitmap`,
     `family_residues`, `family_details`.
5. **Outcome-relevant fields** are populated in `_run_single_mutation` lines
   730-761:
   * `output = exec_result.combined_output` (stdout + stderr).
   * `failures = exec_result.failures`
   * `exit_code = exec_result.exit_code` (return code of risc0-host)
   * `crashed = exit_code in (-11,-6,-8,-9,-10,139,134,136,137,138)` — i.e. only
     signals SIGSEGV/SIGABRT/SIGFPE/SIGKILL/SIGBUS, both as negative-signal
     (Python subprocess convention) and 128+signal (shell convention).
   * `proof_generated = _check_proof_generated(output, exit_code)`
     (`fuzzer.py:1188-1220`). Returns False if `crashed`; otherwise True if any
     of: `"verify segment" in output`, prover-success record present, or
     `"context":"Verifier"` substring present.
   * `proof_verify_failed = _check_proof_verification_failure(output)` —
     `"verify segment" in output`.
   * `verifier_accepted = _check_verifier_acceptance(output)` —
     `re.search(r'<record>\s*\{[^}]*"context"\s*:\s*"Verifier"[^}]*"status"\s*:\s*"success"[^}]*\}\s*</record>', output)`
     OR the equivalent with `status` / `context` swapped. If found, returns
     True; otherwise falls through to a substring scan that returns False on
     any rejection-pattern hit.
   * `broken_families, broken_addresses, is_global_only, global_contexts` from
     `_derive_global_info(exec_result, failures)` (lines 241-274), which inspect
     `exec_result.family_residues` (lookups for `nonzero == True`) and
     `exec_result.family_details`.
6. **MutationResult is constructed** (lines 763-783) with all of the above
   fields. No further parsing happens.
7. **Database recording** (lines 786-800).
8. **Outcome classification** in `_classify_outcome` (`fuzzer.py:231-239`):
   * If `verifier_accepted` → `"ACCEPTED"` (no other check overrides this)
   * elif `crashed` → `"CRASH"`
   * elif `failures or proof_verify_failed or broken_families` → `"REJECTED"`
   * else → `"NO_EFFECT"`
9. **Result printing** in `_print_mutation_result` (`fuzzer.py:1426-1467`):
   * Status emoji depends ONLY on `verifier_accepted`/`crashed`/`failures+others`/else.
   * `bug_marker = " BUG!" if result.verifier_accepted else ""`
   * `outcome = self._classify_outcome(result)` — printed but never affects the
     status emoji or BUG! string.

### Critical observations from this walk-through

* The `🐛` emoji AND the `BUG!` string are BOTH driven exclusively by
  `result.verifier_accepted`. There is no other path to either marker.
* `result.verifier_accepted` is set EXCLUSIVELY by `_check_verifier_acceptance`
  which returns True iff the JSON success record is in the captured output.
* `_check_verifier_acceptance` is byte-identical between commit `5a529cb` and
  current HEAD (Observation #5).
* If `BUG!` appears in a smoke output, the raw risc0-host output for that
  mutation MUST have contained the JSON success record.
* The classifier is NOT a display-layer bug: print path matches classifier path
  with the same boolean.
* The crash-vs-rejection branches DO distinguish crashes: `result.crashed`
  flips the emoji to `💥` and `_classify_outcome` returns `"CRASH"`. So a
  crashed prover would NOT print `BUG!`.

### What this means for the hypotheses

* **H3 (campaign classifier bug)** — Falsified for now. Code path is a clean
  chain `_check_verifier_acceptance(output) → verifier_accepted → BUG!`. There
  is no branch in this chain that misclassifies a crash or rejection as ACCEPTED.
* **H5 (display malfunction)** — Falsified. The print path uses the same
  boolean. If we print `BUG!`, then `verifier_accepted` is True, which means
  the JSON success record really was in the output.
* **H1, H2, H6** — still open. The proof MUST be reaching the verifier (we see
  the verifier success record). The question is now: why is the verifier
  returning success on a mutation that has a non-zero check_poly cycle.

## 7. OLD vs CURRENT diff in a4 standalone (verified Jun 3, 2026)

Cloned OLD repo at commit `5a529cb` ("final bandit logic before global
constraint additions") to `/tmp/arguzz_old`. Diffed every Python file under
`a4/standalone/` and `a4/core/`. Findings:

| File | Material change to classifier or run-time behaviour? |
|------|------------------------------------------------------|
| `a4/core/executor.py` | Added `A4_FAMILY_RESIDUE=1` env var; added parsing of `<a4_family_residue>` / `<a4_family_detail>` tags. **No change to subprocess args or to existing parsing.** Empirically verified (`/tmp/mut17_full.log` vs `/tmp/mut17_no_fr.log`): removing `A4_FAMILY_RESIDUE=1` does not change the outcome. |
| `a4/core/constraint_parser.py` | Added new `phase` field on `ConstraintFailure` (defaults to `"local"`). Pure addition, no logic change. |
| `a4/core/touch_coverage.py` | Added parsers for new tags (accum bitmap, family residue, family stats, family detail). Pure additions. |
| `a4/standalone/fuzzer.py::_classify_outcome` | Only diff: REJECTED branch now also fires on `result.broken_families`. ACCEPTED branch is UNCHANGED — still `if result.verifier_accepted`. |
| `a4/standalone/fuzzer.py::_print_mutation_result` | Status emoji branches are unchanged in semantics. `bug_marker = " BUG!" if result.verifier_accepted else ""` is byte-identical. Added a `global_marker` print. |
| `a4/standalone/fuzzer.py::_check_verifier_acceptance` | Byte-identical (already verified in Obs #5). |
| `a4/standalone/fuzzer.py::_check_proof_generated` | Compared: byte-identical. |
| `a4/standalone/fuzzer.py::_check_proof_verification_failure` | Compared: byte-identical (`return "verify segment" in output`). |
| `a4/standalone/fuzzer.py::_run_single_mutation` | Bookkeeping additions for global Hook 3 fields. Subprocess invocation and crash/proof/verifier-acceptance derivations are unchanged. |
| `a4/standalone/cli.py` | Added `--selector uniform` choice; no run-time change for `bandit`/`zoned`. |
| `a4/standalone/coverage_db.py` | New `global_failures` table; pure additive. |
| `a4/standalone/coverage_state.py` | Added `GlobalContext`, `derive_global_contexts`; reward fields. Pure additive. |
| `a4/standalone/step_selector.py` | Added `UniformArmSelector` class. Pure additive. |
| `a4/standalone/pilot_calibration.py` | Minor; check separately when relevant. |

**Conclusion of Step 3:** No change to a4 Python code can plausibly explain the
new BUG! markers. The only run-time-relevant change is `A4_FAMILY_RESIDUE=1` in
the env, which we already empirically ruled out.

The cause is therefore not in `a4/` — it is in the `risc0-host` binary (uncommitted
modifications to `risc0-modified`), or it is a property of the specific
random mutations chosen in the new vs old campaigns (H4), or it is a property
of risc0 itself (H1).

## 8. Experiment log

| Date | Experiment | Result | Conclusion |
|------|-----------|--------|-----------|
| 2026-06-03 | Run mutation [17] with CONSTRAINT_CONTINUE=1 on current binary | exit 0, Verifier success record present, 1 constraint_fail tag, check_poly nonzero on 1 cycle | The CURRENT binary produces this output; what the classifier does with it is a separate question. |
| 2026-06-03 | Run mutation [17] without CONSTRAINT_CONTINUE on current binary | exit 101, no Verifier record, prover panic | Without CONSTRAINT_CONTINUE the panic happens before the verifier runs. |
| 2026-06-03 | Diff `_check_verifier_acceptance` OLD vs CURRENT | byte-identical | Python classifier didn't change. |
| 2026-06-03 | Full walk-through of campaign code path | H3 (classifier bug) and H5 (display bug) falsified | The print path uses the same boolean as the classifier; both flow exclusively from `_check_verifier_acceptance(output)`. If `BUG!` is printed, the JSON success record really WAS in risc0's output. |
| 2026-06-03 | Examine crash branches for exit-code 101 (Rust `panic!`) | `crashed` is False for 101 (only signals 6/8/9/10/11 count as crash); a panic with `failures > 0` is classified `REJECTED`, status `✓` | A panicked OLD run does NOT slip into the ACCEPTED bucket. Whatever caused OLD `INSTR_TYPE_MOD @ step 3375` to print `exit: 101 [proof:GENERATED]` was a non-crash panic that happened AFTER witness-gen and produced a proof; the prover self-verification rejected it. |
| 2026-06-03 | OLD vs CURRENT a4/ diff (every file) | Only additive changes; classifier logic for ACCEPTED is byte-identical | Cause is in `risc0-host` binary or in random mutation selection, NOT in `a4/`. |
| 2026-06-03 | End-to-end classifier test on real risc0 output (`/tmp/step4_verify_classifier.py`) | exit_code=0, verifier_accepted=True, outcome=ACCEPTED, JSON success record literally present in output | The Python classifier and print path are working correctly. risc0-host is the one emitting "Verifier status:success" for a mutation with a constraint failure. The bug originates in the binary or in risc0 itself. |
| 2026-06-03 | Rebuilt `risc0-host` from current source (`cargo build --release`) and re-ran mutation 17 (`/tmp/mut17_rebuilt.log`) | Same outcome: 1 constraint_fail + 11 poly_fp_nonzero rows + 1 check_poly_scan nonzero cycle + Prover success + Verifier success, EXIT 0, ACCEPTED | The behavior is NOT a stale-binary artifact. The CURRENT source code reproduces it exactly. The cause is in source, not in a transient build state. |
| 2026-06-03 | Read `risc0/zkp/src/prove/prover.rs` and `risc0/zkp/src/verify/mod.rs` for the `circuit_debug` cfg gate | **SMOKING GUN**: with `circuit_debug` enabled, the prover scans `check_poly` for any non-zero row, picks that row's `bad_z` as the DEEP-ALI query point, writes z to the transcript; the verifier READS z from the transcript instead of computing it via Fiat-Shamir. `check(bad_z) == result(bad_z)` is then trivially satisfied at the bad point, so the verifier accepts. | This is an UPSTREAM risc0 debug-only feature, gated by the `circuit_debug` cargo feature. Our host's `Cargo.toml` has `prove = [..., "risc0-zkvm/circuit_debug"]`, which enables this path. WITHOUT `circuit_debug`, both prover and verifier use a Fiat-Shamir-sampled z; the check polynomial would have to be low-degree (FRI) AND result(z) = check(z) * V(z) at a uniform-random z, neither of which can hold for a proof whose underlying constraint polynomial is non-zero. |
| 2026-06-03 | Removed `circuit_debug` from `host/Cargo.toml`, rebuilt, re-ran mutation 17 (`/tmp/mut17_NO_circuit_debug.log`) | **EXIT 101 (panic), Prover status:error, verifier never reached, REJECTED.** check_poly is now 32768/32768 nonzero (zk_shift exposes the violation everywhere). | Conclusive proof that `circuit_debug` is the root cause. |
| 2026-06-03 | Sanity: unmutated baseline on no-`circuit_debug` binary (`/tmp/baseline_no_cd.log`) | EXIT 0, Prover success, Verifier success, 0 constraint failures | Disabling `circuit_debug` does not break legitimate proofs. |
| 2026-06-03 | 5-mutation INSTR_TYPE_MOD campaign on no-`circuit_debug` binary, seed 42 | 5/5 REJECTED, 0 BUG, 0 CRASH | Matches OLD-campaign distribution. Zero false positives. |

## 9. SMOKING GUN: the `circuit_debug` cargo feature

### 9.1 The exact code paths

**Prover** (`risc0/zkp/src/prove/prover.rs:208-220`):
```
cfg_if::cfg_if! {
    if #[cfg(feature = "circuit_debug")] {
        let z = if let Some(bad_z) = bad_z {
            self.iop.write_field_elem_slice(bad_z.subelems());
            bad_z
        } else {
            self.iop.random_ext_elem()
        };
    } else {
        let z = self.iop.random_ext_elem();
    }
}
```

`bad_z` is populated above (lines 146-157) by scanning the check polynomial
for any non-zero value:
```
#[cfg(feature = "circuit_debug")]
check_poly.view(|check_out| {
    for i in (0..domain).step_by(4) {
        if check_out[i] != H::Elem::ZERO {
            tracing::debug!("check[{i}] = 0x{:08x?}", check_out[i].to_u32_words()[0]);
            bad_z.get_or_insert(H::ExtElem::from_subfield(
                &H::Elem::ROU_FWD[self.po2].pow(i / 4),
            ));
        }
    }
    // assert!(bad_z.is_none());
});
```

So with `circuit_debug`: if there is ANY non-zero check-polynomial value
anywhere in the evaluation domain, the prover picks the corresponding
`bad_z` (= ω^(i/4) where i is the first non-zero index) as the DEEP-ALI
query point, and writes it into the transcript.

**Verifier** (`risc0/zkp/src/verify/mod.rs:309-316`):
```
cfg_if::cfg_if! {
    if #[cfg(feature = "circuit_debug")] {
        let z_slice = self.iop().read_field_elem_slice(F::ExtElem::EXT_SIZE);
        let z = F::ExtElem::from_subelems(z_slice.iter().cloned());
    } else {
        let z = self.iop().random_ext_elem();
    }
}
```

With `circuit_debug`, the verifier READS z from the transcript instead of
sampling via Fiat-Shamir. Whatever the prover wrote becomes z.

Then the verifier checks `check == result` at this z
(`risc0/zkp/src/verify/mod.rs:374-380`):
```
check *= (F::ExtElem::from_subfield(&three) * z).pow(self.tot_cycles) - F::ExtElem::ONE;
trace_if_enabled!("Check = {check:?}");
if check != result {
    tracing::debug!("check != result");
    return Err(VerificationError::InvalidProof);
}
```

Because the prover constructed the check polynomial so that, at z, the
DEEP-ALI relationship `check(z) * V(z) = constraint(z)` holds by
interpolation, equality at the chosen z is **always** satisfied — even when
the constraint polynomial is non-zero at trace rows (i.e. constraints
actually fail).

### 9.2 Why FRI also doesn't catch it

In production (no `circuit_debug`), the second line of defence is FRI's
low-degree test on the check polynomial. The check polynomial is computed as
`constraint / V`. If the constraint polynomial does not vanish on the
trace-row roots, the division has a non-trivial remainder, the prover commits
to a polynomial whose effective degree exceeds the FRI threshold, and FRI
detects the degree blow-up with overwhelming probability.

With `circuit_debug` the prover does the division anyway and commits to the
resulting (truncated) polynomial. FRI checks the COMMITTED polynomial is low
degree — which it is, because the prover only commits to the first N
coefficients. The information that "the high-degree tail is non-zero" never
reaches FRI directly; the only check that catches it is the `check == result`
test at z, which is bypassed by reading z from the transcript.

So with `circuit_debug` enabled, NEITHER the `check == result` test NOR FRI
catch the constraint violation.

### 9.3 Additional related cfg in the same path

`risc0/zkp/src/prove/prover.rs:45-46`:
```
// Convert f(x) -> f(3x), which effective multiplies coefficients c_i by 3^i.
#[cfg(not(feature = "circuit_debug"))]
hal.zk_shift(&coeffs, count);
```

`circuit_debug` also disables the ZK shift. This is the source of the comment
in `workspace/output/host/Cargo.toml:17`:

> `# With check polynomial scan (disables ZK shift, proof always invalid):`

The comment says "proof always invalid" because the proof loses its zero-
knowledge property (a debug-only state). It does NOT say "proof always
rejected" — and in fact, as we have shown, the verifier ACCEPTS the proof
with the `circuit_debug` feature enabled.

### 9.4 Why old runs did not exhibit this

Two plausible reasons, in order of likelihood:

**(a) The `circuit_debug` feature was added/enabled to the host `Cargo.toml`
between the OLD campaigns and now.** We do not have git history for
`workspace/output/host/Cargo.toml` because `output/` is `.gitignore`'d.
The comment block in the file ("ACTIVE: prove = [.., 'circuit_debug']") plus
the user's own recollection ("I needed to instrument hooks that force the
proof to be made so that we can have a malicious proof that then gets tested
by the verifier") strongly suggests `circuit_debug` was added later as part
of the malicious-proof workflow — but its true effect (verifier accepts
the malicious proof, instead of rejecting it as intended) was not
understood at the time.

**(b)** Random selection means old campaigns may not have hit a step where
a single `INSTR_TYPE_MOD` mutation produced a non-zero check polynomial.
This is plausible for very small old campaigns but increasingly improbable
for the longer ones we did.

### 9.5 Step 6 experimental confirmation — CONFIRMED

Procedure:
1. Saved the with-`circuit_debug` binary to `/tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak`.
2. Edited `workspace/output/host/Cargo.toml` to
   `prove = ["risc0-zkvm/prove", "risc0-zkvm/witgen_debug"]`
   (removed `circuit_debug`).
3. `cargo build --release` from `workspace/output` (13 min 47 s).
4. Re-ran mutation [17] with same env.

Result (`/tmp/mut17_NO_circuit_debug.log`):

* `<constraint_fail>` count: **1** (eqz still printed it, identical to before)
* `<a4_poly_fp_nonzero>` count: **20** (constraint polynomial still violated)
* `<a4_check_poly_scan>`: **32768 / 32768 nonzero cycles** (all cycles — because
  zk_shift now randomises every cycle row, exposing the violation everywhere)
* `<record>{"context":"Prover", "status":"error", "time":"65.87s"}</record>`
* Panic at `host/src/main.rs:150: verify segment`
* **EXIT CODE: 101**
* Verifier never reached

Verdict: with `circuit_debug` off, the prover's self-verification correctly
rejects the malformed proof and panics. The verifier never receives the
proof. The campaign's `_classify_outcome` returns **REJECTED**, exactly
matching OLD-campaign behaviour for this same mutation.

### 9.6 Step 7 wider confirmation — CONFIRMED

Ran 5 `INSTR_TYPE_MOD` mutations (`--selector zoned --seed 42 --num 5`)
through the campaign on the no-`circuit_debug` binary.

Result (full output in terminal):
```
Outcome breakdown:
  REJECTED (mutation detected): 5
  CRASH (segfault, etc.):       0
  NO_EFFECT:                    0
  ACCEPTED (BUG!):              0
  SKIPPED:                      0
```

5/5 REJECTED. Zero false positives. This matches the OLD campaign
distribution (which had 0 BUGs for INSTR_TYPE_MOD across hundreds of
mutations) exactly.

### 9.7 Sanity check — baseline still verifies

Ran the unmutated baseline (no `A4_MUTATION_CONFIG`) on the no-`circuit_debug`
binary. Result (`/tmp/baseline_no_cd.log`):
* Prover status:success
* Verifier status:success
* EXIT 0
* 0 constraint_fail

So removing `circuit_debug` does not break legitimate proofs — only stops
the verifier from being tricked into accepting malicious ones.

---

## 10. The fix

### 10.1 Immediate fix

**Remove `circuit_debug` from `workspace/output/host/Cargo.toml`.**

```diff
-prove = ["risc0-zkvm/prove", "risc0-zkvm/witgen_debug", "risc0-zkvm/circuit_debug"]
+prove = ["risc0-zkvm/prove", "risc0-zkvm/witgen_debug"]
```

This has already been applied as part of Step 6. The current build at
`workspace/output/target/release/risc0-host` (mtime Jun 3 22:20) is the
fixed binary. The original (with-`circuit_debug`) binary is at
`/tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak`.

### 10.2 Effect on the user's "malicious proof" workflow

The user's original intent was: produce a mutated witness, generate a proof
even though constraints fail, hand the proof to the verifier, and use the
verifier's accept/reject as the soundness oracle.

The current `circuit_debug` setup **broke** that workflow by making the
verifier always accept (debug-mode shortcut), which is the opposite of what
the user wanted.

With `circuit_debug` off:
* `CONSTRAINT_CONTINUE=1` still lets `eqz` return instead of throwing, so
  the witness is generated even though constraints fail.
* The prover finishes generating the proof.
* The prover's INTERNAL `verify_integrity_with_context` correctly rejects
  the malformed proof (because the check polynomial does not vanish on the
  trace-row roots, the verifier returns `InvalidProof`).
* The prover panics ("verify segment") because of `?` in `prover_impl.rs`.
* The host panics at `main.rs:150`. Exit 101.
* The campaign classifies this as REJECTED (correct).

**Crucially:** the verifier code that runs INSIDE the prover's self-check
is the EXACT same code that would run when the external `host::verify` is
called. So whether the verifier runs once (inside the prover) or twice (once
inside, once outside) does not change the verdict. The user's soundness
oracle is preserved: a malicious proof is rejected.

### 10.3 Optional refinement (for cleaner output)

If we want the external verifier to ALSO get called explicitly (so we see
a `"Verifier", "status":"error"` record for clarity rather than just a
Prover panic), we can modify `prover_impl.rs` to skip the prover's
self-verification under a new env var (e.g. `A4_SKIP_SELF_VERIFY=1`):

```rust
// prover_impl.rs around line 165
if std::env::var_os("A4_SKIP_SELF_VERIFY").is_none() {
    composite_receipt.verify_integrity_with_context(ctx)?;
}
```

This is **cosmetic only**. The verdict is identical either way. Recommend
deferring this until after we confirm production behaviour is stable.

### 10.4 Why this regression was not caught earlier

* `output/` is gitignored — there is no git history of the
  `Cargo.toml` change that added `circuit_debug` to the `prove` feature.
* The comment in the Cargo.toml mentioned "proof always invalid" which
  appeared to be a documentation of expected behaviour, masking the
  unintended verifier-acceptance side effect.
* The instrumentation (`<a4_check_poly_scan>`, `<a4_poly_fp_nonzero>`) was
  added AFTER `circuit_debug` was already enabled, so we never observed
  the contrast between "check polynomial non-zero AND prover rejects" vs
  "check polynomial non-zero AND prover accepts".
* The new global-constraint hook 3 work was unrelated; the `BUG!` markers
  were a pre-existing latent symptom that became visible because we started
  emitting per-mutation outcome lines through paths that now surface them.

### 10.5 Status of the experimental binary

* `workspace/output/target/release/risc0-host` (mtime Jun 3 22:20) — **FIXED**
  (no `circuit_debug`).
* `/tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak` — original, kept for diffing.
* `/root/arguzz_backups/risc0-host.MAR12.bak` — even older copy from Mar 12.
* `host/Cargo.toml` — currently in fixed state. **No commit yet** —
  user should review and commit explicitly.

---

## 11. Cross-check against `a4/docs/global/` (Jun 3, 2026)

User asked whether the Jun 3 finding is consistent with the markdowns under
`a4/docs/global/` (the global-hooks work).

### 11.1 What the global docs already say about `circuit_debug`

Reading every relevant doc end-to-end:

* `GLOBAL_HOOKS_CATALOG.md` (Mar 23) and `GLOBAL_HOOKS_CATALOG_V2.md`
  (Mar 23) describe Hook 2 ("Check Polynomial Scan") and state explicitly
  that it **requires the `circuit_debug` cargo feature**.
* `GLOBAL_HOOKS_CATALOG_V2.md::Recommended Configuration` says, verbatim:
  - **Standard campaigns (every run): Normal build (no circuit_debug).**
  - **Consistency validation campaigns (occasional): All env vars above PLUS
    `circuit_debug` feature flag. Proof always invalid (expected).**
  - **Deep debugging (rare, specific mutations): `circuit_debug` build for
    per-cycle check polynomial scan.**
* `GLOBAL_HOOKS_CATALOG.md::Hook 2` says:
  - "Interferes with proof? **YES** -- requires `circuit_debug` which
    disables ZK shift"
  - "Requires dual-mode? **YES** -- proof is always invalid with
    `circuit_debug`"
* `GLOBAL_HOOKS_CATALOG_V2.md::Hook 2`: "CRITICAL CAVEAT: `circuit_debug`
  disables the ZK shift, which makes the proof ALWAYS INVALID to the
  verifier. This means you CANNOT check for soundness bugs in the same run.
  You need a separate run without `circuit_debug` for verification."
* `Pro_Report_1.md` (Mar 10) is the **earliest** doc that mentions
  `circuit_debug`; it recommends adding `circuit_debug` instrumentation as
  the first Phase 1 experiment to settle H2.

The historical sequence is therefore:
* (pre-Mar 10) OLD campaigns ran on a `host/Cargo.toml` WITHOUT
  `circuit_debug`. The verifier correctly rejected malformed proofs.
* Mar 10: `Pro_Report_1.md` recommends `circuit_debug` instrumentation.
* ~Mar 11-12: Hook 2 implemented; `circuit_debug` is added to the host
  `prove` feature; binary rebuilt (mtime Mar 12 00:17).
* Mar ~22: Hook 3 (per-family residues, `A4_FAMILY_RESIDUE`) implemented;
  Hook 3 does **NOT** require `circuit_debug` and is documented as the
  "primary" global hook. Hook 2 is now superseded.
* But `circuit_debug` was **never removed** from `host/Cargo.toml`.
* Apr 28: NEW smoke campaign runs on that Mar 12 binary → 5 BUG! markers.

This is the exact scenario the docs warn about: a "Consistency validation"
configuration was left active for "Standard campaigns" by accident.

### 11.2 Are there inconsistencies with the global docs?

**No inconsistency at the operational level.** The recommended fix
("Standard campaigns: Normal build (no circuit_debug)") is exactly what we
applied. The docs already identified the correct configuration; we just
violated their recommendation by leaving the wrong feature flag enabled
when transitioning from Hook 2 to Hook 3.

**One subtle GAP in the docs** — but no inconsistency: the docs describe
**only one** of the two effects of `circuit_debug` on the verifier.

* **Effect A (documented in `GLOBAL_HOOKS_CATALOG_V2.md::Hook 2`):**
  `circuit_debug` disables the ZK shift in `make_coeffs`, so the trace is
  evaluated on the original domain (cycle rows) instead of the coset. This
  is what makes the check polynomial meaningful at cycle rows. The doc
  correctly notes that this side effect makes the proof "always invalid to
  the verifier" (i.e., non-ZK, structurally different).
* **Effect B (NOT documented, but the actual cause of the BUG! markers):**
  `circuit_debug` also activates an explicit `bad_z` mechanism in
  `risc0/zkp/src/prove/prover.rs:146-157, 208-220` and a matching
  read-z-from-transcript path in `risc0/zkp/src/verify/mod.rs:309-316`. The
  prover scans the check polynomial; if it finds any non-zero row, it picks
  `bad_z = ω^(i/4)` as the DEEP-ALI query point and writes it to the
  transcript. The verifier reads z from the transcript. The
  `check == result` test at `verify/mod.rs:377-380` then trivially passes
  because the prover constructed the check polynomial so it agrees with
  the constraint polynomial AT the chosen z by interpolation. The verifier
  returns Ok.

The docs' phrase "proof always invalid to the verifier" was interpreted at
the time as "verifier always rejects." The actual run-time behaviour is
the **opposite**: the verifier always **accepts**, because effect B
short-circuits the soundness check. The user's worry ("a verifier-accept
in this mode is meaningless") is correct; the docs just got the mechanism
half-right.

### 11.3 Why old INSTR_TYPE_MOD runs were rejected — confirmed

OLD campaigns (Feb 26-27) ran on a binary built BEFORE the `circuit_debug`
feature was added to `prove`. Without `circuit_debug`, the prover used
real Fiat-Shamir z, the prover's `verify_integrity_with_context`
self-check detected the constraint failure, the prover panicked with
`"verify segment"`, the host panicked at `main.rs:150`, exit 101. The
verifier was never reached. The campaign classified this as **REJECTED**.

The OLD-style behaviour was reproduced exactly by our Step 6 build (no
`circuit_debug`) on mutation [17]: same exit 101, same
`"context":"Prover", "status":"error"` record, same "verify segment"
panic. This is the same OLD-binary outcome.

Anomaly 3 in `PHASE1_5_INVESTIGATION_REPORT.md` is itself an explicit
demonstration of the toggle effect on cycle counts: runs 1-86 (with
`circuit_debug`) had `check_nz` in 1-9; runs 87-100 (after a rebuild
without `circuit_debug`) had `check_nz=32768` (coset evaluation). Our
Step 6 result matches this exactly: with `circuit_debug` mutation 17
shows 1 nonzero cycle; without `circuit_debug` it shows 32768/32768.
This is independent corroborating evidence from a different campaign of
the same on-the-fly effect.

### 11.4 Confidence level

**≥ 99%.** The remaining 1% is reserved for completeness; we cannot rule
out an unknown third effect of `circuit_debug` that could matter, but
since:

* the prover and verifier `circuit_debug` cfg-blocks are the ONLY places
  in `risc0/zkp/src/{prove,verify}` that gate behaviour on this feature
  flag (verified by grep);
* removing the feature produced the textbook expected behaviour (exit
  101, prover error, verify segment) on the EXACT same mutation;
* the docs' own recommendation matches our fix;
* the docs' own Anomaly 3 experiment matches our Step 6 experiment;

there is no remaining inconsistency between our finding and the global
docs. The fix is the recommended configuration; the docs were not wrong,
they were ignored by a stale `Cargo.toml` line.

### 11.5 Empirical re-test: SAME 5 BUG! mutations on the fixed binary

User asked: "if we run the new binary (our most up to date version) without
circuit_debug enabled, do these same instr_type_mod mutations cause rejections
now instead of acceptances?" Direct test:

The 5 BUG! mutations from `phase31_smoke_output.txt` (Apr 28 smoke campaign):

| # | step | original     | mutated                | smoke result | fixed-binary result |
|---|------|--------------|------------------------|--------------|---------------------|
| 7 | 3375 | Sub  (0,1)   | SrlI  (3,10) ⚠INVALID | ACCEPTED (BUG!) | **REJECTED** (exit 101, 3 constraint_fail, prover error) |
| 8 | 971  | AddI (0,7)   | Rem  (4,6)             | ACCEPTED (BUG!) | **REJECTED** (exit 101, 3 constraint_fail, prover error) |
| 17| 881  | AddI (0,7)   | SrlI (4,2)             | ACCEPTED (BUG!) | **REJECTED** (exit 101, 1 constraint_fail, prover error) |
| 31| 3651 | AddI (0,7)   | Or   (0,3)             | ACCEPTED (BUG!) | **REJECTED** (exit 101, 4 constraint_fail, prover error) |
| 45| 1222 | Lw   (5,2)   | Unknown(5,6) ⚠INVALID | ACCEPTED (BUG!) | **REJECTED** (exit 101, 3 constraint_fail, prover error) |

**5/5 of the original BUG! mutations are correctly REJECTED on the fixed
binary.** The mechanism is identical in every case: `eqz` prints its
`<constraint_fail>` tag (because of `CONSTRAINT_CONTINUE=1`), the witness
generator completes, the prover finalises the proof, the prover's internal
`verify_integrity_with_context` rejects it (because the check polynomial
does not vanish at the correct random `z`), the prover-level call site
returns the error, the host main panics at line 150 with "verify segment",
exit 101. The campaign correctly classifies this as REJECTED.

Logs preserved at `/tmp/mut{7,8,17,31,45}_FIXED.log` for reference.

### 11.6 Source code citations — the full end-to-end trace of `Ok(())`

This section documents the EXACT code path that produces
`<record>{"context":"Verifier", "status":"success"}</record>` when
`circuit_debug` is enabled and a constraint has failed. All line numbers are
in the current `risc0-modified` working tree.

**Step 1 — Prover detects the bad cycle.**

[`risc0/zkp/src/prove/prover.rs:143-157`](workspace/risc0-modified/risc0/zkp/src/prove/prover.rs):

```rust
#[cfg(feature = "circuit_debug")]
let mut bad_z = None;

#[cfg(feature = "circuit_debug")]
check_poly.view(|check_out| {
    for i in (0..domain).step_by(4) {
        if check_out[i] != H::Elem::ZERO {
            tracing::debug!("check[{i}] = 0x{:08x?}", check_out[i].to_u32_words()[0]);
            bad_z.get_or_insert(H::ExtElem::from_subfield(
                &H::Elem::ROU_FWD[self.po2].pow(i / 4),
            ));
        }
    }
    // assert!(bad_z.is_none());
});
```

The prover scans the check polynomial. The FIRST non-zero index `i` is
recorded as `bad_z = ω_{po2}^{i/4}` (a primitive root of unity at that
index). Note that the upstream `assert!(bad_z.is_none())` is **commented
out** — this is upstream's deliberate choice to allow proof generation
even when constraints fail. Without `circuit_debug`, this entire block is
absent and `bad_z` doesn't exist.

**Step 2 — Prover writes `bad_z` into the transcript and uses it as `z`.**

[`risc0/zkp/src/prove/prover.rs:208-220`](workspace/risc0-modified/risc0/zkp/src/prove/prover.rs):

```rust
// Now pick a value for Z, which is used as the DEEP-ALI query point.
cfg_if::cfg_if! {
    if #[cfg(feature = "circuit_debug")] {
        let z = if let Some(bad_z) = bad_z {
            self.iop.write_field_elem_slice(bad_z.subelems());
            bad_z
        } else {
            self.iop.random_ext_elem()
        };
    } else {
        let z = self.iop.random_ext_elem();
    }
}
```

Note `self.iop.write_field_elem_slice(bad_z.subelems())` on line 212 — this
APPENDS `bad_z`'s subelements to the proof transcript. Without
`circuit_debug`, z is sampled via Fiat-Shamir from the previously committed
data and NEVER written to the transcript (random_ext_elem doesn't write,
it just reads from the FS hash state).

**Step 3 — Prover constructs the rest of the proof so it agrees at z.**

Continuing in `finalize()`, the prover then evaluates each tap polynomial
at `z * ω^back` for the appropriate back-offsets, builds `coeff_u`
(interpolations of each tap), and INCLUDES the four `g_i` check-poly
coefficient blocks in `coeff_u` after the tap entries. By the construction
of the polynomial divisor relation
`constraint = check * Z` (with `Z(x) = (3x)^cycles - 1`), the verifier's
later reconstruction of `check(z)` from `coeff_u[num_taps..]` is **forced
to equal** `result(z) = validity_fn(poly_mix, eval_u(z))` AT THIS SPECIFIC
z. This is true mathematically regardless of whether the constraint
polynomial really vanishes on the trace-row roots — the prover's quotient
is computed by polynomial division (which the prover does anyway), and at
z, division and multiplication cancel out.

**Step 4 — Verifier reads `z` from the transcript.**

[`risc0/zkp/src/verify/mod.rs:307-316`](workspace/risc0-modified/risc0/zkp/src/verify/mod.rs):

```rust
// Get a pseudorandom DEEP query point
// See DEEP-ALI protocol from DEEP-FRI paper for details on DEEP query.
cfg_if::cfg_if! {
    if #[cfg(feature = "circuit_debug")] {
        let z_slice = self.iop().read_field_elem_slice(F::ExtElem::EXT_SIZE);
        let z = F::ExtElem::from_subelems(z_slice.iter().cloned());
    } else {
        let z = self.iop().random_ext_elem();
    }
}
```

With `circuit_debug`, `read_field_elem_slice(...)` consumes exactly the
`EXT_SIZE` (=4) field elements that the prover wrote in Step 2. The
verifier's `z` is now exactly the prover's `bad_z`. Without
`circuit_debug`, the verifier samples its own z via Fiat-Shamir
identically to the prover.

**Step 5 — The `check == result` test trivially passes at the chosen z.**

[`risc0/zkp/src/verify/mod.rs:347-380`](workspace/risc0-modified/risc0/zkp/src/verify/mod.rs):

```rust
let result = validity_fn(&poly_mix, &eval_u);
trace_if_enabled!("Computed polynomial: {result:?}");

// Now generate the check polynomial
// TODO: This currently treats the extension degree as hardcoded at 4 ...
let mut check = F::ExtElem::default();
let remap = [0, 2, 1, 3];
let fp0 = F::Elem::ZERO;
let fp1 = F::Elem::ONE;
for (i, rmi) in remap.iter().enumerate() {
    check += coeff_u[num_taps + rmi]     * z.pow(i) * F::ExtElem::from_subelems([fp1, fp0, fp0, fp0]);
    check += coeff_u[num_taps + rmi + 4] * z.pow(i) * F::ExtElem::from_subelems([fp0, fp1, fp0, fp0]);
    check += coeff_u[num_taps + rmi + 8] * z.pow(i) * F::ExtElem::from_subelems([fp0, fp0, fp1, fp0]);
    check += coeff_u[num_taps + rmi + 12]* z.pow(i) * F::ExtElem::from_subelems([fp0, fp0, fp0, fp1]);
}
let three = F::Elem::from_u64(3);
check *= (F::ExtElem::from_subfield(&three) * z).pow(self.tot_cycles) - F::ExtElem::ONE;
trace_if_enabled!("Check = {check:?}");
if check != result {
    tracing::debug!("check != result");
    return Err(VerificationError::InvalidProof);
}
```

This is the ONLY constraint-check the verifier does before delegating to
FRI. The check is `check == result` at point `z`. The prover's
construction in Step 3 guarantees this equality at `bad_z`, so the test
passes. **No `VerificationError::InvalidProof` is returned.**

In the non-`circuit_debug` case, `z` is a Fiat-Shamir random point and the
prover has no special construction at that point — so the equality holds
only if the constraint polynomial really vanishes on the trace-row roots
(i.e. the proof is honest). Otherwise the verifier rejects.

**Step 6 — FRI also passes because the committed check poly is low-degree.**

[`risc0/zkp/src/verify/mod.rs:425-441`](workspace/risc0-modified/risc0/zkp/src/verify/mod.rs):

```rust
let gen = <F::Elem as RootsOfUnity>::ROU_FWD[log2_ceil(domain)];
let hashfn = self.suite.hashfn.as_ref();
self.fri_verify(|idx| {
    let x = gen.pow(idx);
    let rows= self.merkle_verifiers.iter().map(...).collect::<Result<Vec<_>,_>>()?;
    let check_row = check_merkle.verify(self.iop().deref_mut(),hashfn, idx)?;
    let ret = self.fri_eval_taps(&combo_u, check_row, back_one, x, z, &rows, &tap_mix_pows, &check_mix_pows);
    Ok(ret)
})?;
```

FRI verifies that the COMMITTED check polynomial is low-degree. The prover
truncated the quotient to its low-degree part, so what's committed IS
low-degree (the commitment hides the "extra" high-degree information that
would otherwise reveal the constraint failure). FRI sees a perfectly
low-degree polynomial and accepts.

**Step 7 — `verify_validity` returns `Ok(())`.**

[`risc0/zkp/src/verify/mod.rs:442`](workspace/risc0-modified/risc0/zkp/src/verify/mod.rs):

```rust
        ...fri_verify(...)?;
        Ok(())  // <-- HERE
    }
```

**Step 8 — `verify()` returns `Ok(())`.**

[`risc0/zkp/src/verify/mod.rs:485-546`](workspace/risc0-modified/risc0/zkp/src/verify/mod.rs):

```rust
pub fn verify<F, C, CheckCode>(...) -> Result<(), VerificationError> {
    ...
    // Verify the evaluation of the validity polynomial to make sure
    // the constraints were not violated.
    verifier
        .verify_validity(|poly_mix, eval_u| circuit.poly_ext(poly_mix, eval_u, &[out, &mix]).tot)?;

    // There should be nothing else in the IOP, so verify that's the case.
    verifier.iop().verify_complete();
    Ok(())  // <-- HERE
}
```

**Step 9 — `risc0_circuit_rv32im::verify` returns `Ok(())`.**

[`risc0/circuit/rv32im/src/lib.rs:78-92`](workspace/risc0-modified/risc0/circuit/rv32im/src/lib.rs):

```rust
pub fn verify(seal: &[u32]) -> Result<(), VerificationError> {
    tracing::debug!("verify");

    // We don't have a `code' buffer to verify.
    let check_code_fn = |_: u32, _: &Digest| Ok(());

    if seal[0] != RV32IM_SEAL_VERSION {
        return Err(VerificationError::ReceiptFormatError);
    }

    let seal = &seal[1..];

    let hash_suite = Poseidon2HashSuite::new_suite();
    risc0_zkp::verify::verify(&CircuitImpl, &hash_suite, seal, check_code_fn)
    // returns Ok(()) on success
}
```

**Step 10 — `SegmentReceipt::verify_integrity_with_context` returns `Ok(())`.**

[`risc0/zkvm/src/receipt/segment.rs:69-...`](workspace/risc0-modified/risc0/zkvm/src/receipt/segment.rs):

```rust
pub fn verify_integrity_with_context(
    &self,
    ctx: &VerifierContext,
) -> Result<(), VerificationError> {
    ...
    tracing::debug!("SegmentReceipt::verify_integrity_with_context");
    risc0_circuit_rv32im::verify(&self.seal)?;
    ...
}
```

This is called both internally (by the prover's self-check, line 165 in
`prover_impl.rs`) and externally (by the host's `receipt.verify(GUEST_ID)`
call). Both call sites use the exact same code, exact same `z`, and
return the exact same verdict.

**Step 11 — Host prints `Verifier status:success`.**

[`workspace/output/host/src/main.rs:201-211`](workspace/output/host/src/main.rs):

```rust
match receipt.verify(RISC0_GUEST_ID) {
    Ok(_) => {
        println!(
            "<record>{{\
                \"context\":\"Verifier\", \
                \"status\":\"success\", \
                \"time\":\"{:.2?}\"\
            }}</record>",
            timer.elapsed()
        );
    },
    Err(error) => {
        println!(
            "<record>{{\
                \"context\":\"Verifier\", \
                \"status\":\"error\", \
                \"time\":\"{:.2?}\"\
            }}</record>",
            ...
        );
        panic!("{}", error);
    }
}
```

The `Ok(_)` arm fires because every `?` and `Ok(())` from Steps 7-10
returned cleanly. The campaign's `_check_verifier_acceptance` regex
matches this `success` record and the campaign prints `🐛 BUG!`.

**The complete chain:**

```
prover.rs:212  write z to transcript
verify/mod.rs:311  read z from transcript
verify/mod.rs:377  check==result PASSES at this prover-chosen z
verify/mod.rs:441  fri_verify PASSES (committed poly is low-degree)
verify/mod.rs:442  verify_validity returns Ok(())
verify/mod.rs:545  verify returns Ok(())
rv32im/lib.rs:91   risc0_circuit_rv32im::verify returns Ok(())
segment.rs:109     verify_integrity_with_context returns Ok(())
host/main.rs:202   prints Verifier status:success
fuzzer.py:1289     _check_verifier_acceptance returns True
fuzzer.py:233      _classify_outcome returns "ACCEPTED"
fuzzer.py:1439     bug_marker = " BUG!"
```

**Without `circuit_debug`:**

```
prover.rs:215  z is Fiat-Shamir random (NOT written to transcript)
verify/mod.rs:314  z is Fiat-Shamir random (same value, NOT read from transcript)
verify/mod.rs:377  check != result at this random z (Schwartz-Zippel: probability of equality is ~1/|field|)
verify/mod.rs:379  returns Err(VerificationError::InvalidProof)
```

But before any external verifier call, the prover ITSELF runs the same
verifier as a self-check at `prover_impl.rs:165` (called
"verify_integrity_with_context"), which returns the same Err. The `?`
propagates, the prover errors, the host panics with "verify segment",
exit 101. The classifier sees `failures > 0` and `verifier_accepted ==
False` and returns REJECTED.

**This source-level trace establishes the mechanism to 100% certainty.
The `Ok(())` is from `risc0/zkp/src/verify/mod.rs:442` (and propagates to
`:545`, `rv32im/src/lib.rs:91`, `segment.rs:109`). The reason it returns
Ok(()) instead of Err(InvalidProof) is the `circuit_debug`-gated z-read
on line 311 combined with the `circuit_debug`-gated bad_z scan + write on
prover.rs:146-157, 208-220.**

For completeness, the docs/global/ markdowns could optionally be updated
to:

1. Replace the phrase "proof always invalid to the verifier" with the
   more precise "**verifier reads the DEEP-ALI query point z from the
   proof transcript instead of computing it via Fiat-Shamir, so a
   verifier-accept in this mode does NOT certify the proof and a
   verifier-reject is also not informative**".
2. Add a note in `GLOBAL_HOOKS_CATALOG_V2.md::Recommended Configuration`
   that `host/Cargo.toml` is `.gitignore`'d, so the `circuit_debug`
   feature flag must be reviewed manually before each campaign batch.
3. Add a one-line CI / smoke-test guard that fails if a campaign starts
   with `circuit_debug` enabled (e.g. `risc0-host --version` could
   include the feature set).

None of these are necessary to unblock III.3.

## 9. Critical reframing after Section 6 walk-through

Combining (1) the empirical observation that OLD `INSTR_TYPE_MOD` runs showed
`exit: 101 [proof:GENERATED]` with 6 failures AND (2) the fact that
`_check_proof_generated` returns True specifically when `"verify segment"` is
in the output OR a Prover-success record is present, we can narrow what was
happening:

* **In OLD binary** for INSTR_TYPE_MOD: eqz DID return (otherwise we wouldn't
  see 6 `<constraint_fail>` tags). The prover finished generating the proof,
  then PANICKED in the prover's self-verification (the `"verify segment"`
  panic at prover_impl.rs:280). Exit code 101 was from this panic.
  `_check_proof_generated` saw `"verify segment"` in output → returned True →
  printed `[proof:GENERATED]`. `verifier_accepted` was False (verifier never
  ran because prover panicked). → REJECTED. **OLD prover self-verification
  REJECTS the proof.**
* **In NEW binary** for the BUG! cases: eqz also returns. The prover finishes
  generating the proof. The prover's self-verification ACCEPTS the proof
  (otherwise we wouldn't see `Prover status:success`). The external verifier
  in host/main.rs ALSO accepts. → ACCEPTED. **NEW prover self-verification
  ACCEPTS the proof.**

**The remaining question is concentrated on a single difference: the prover's
self-verification (`verify_integrity_with_context` called from
`prover_impl.rs:280`) ACCEPTS in NEW where it would have REJECTED in OLD, for
the same family of mutations.**

This change is in the risc0-modified binary, not in our Python. It could be:
- (a) our risc0 modifications changed what gets committed to the proof in a way
  that makes the proof self-verify successfully despite the constraint failure;
- (b) our risc0 modifications changed self-verification logic itself;
- (c) the OLD binary really was different (older state of risc0-modified) and
  has since been overwritten.

Step 5 (rebuild + test) plus Step 6 (selective revert + rebuild) will
distinguish these.
