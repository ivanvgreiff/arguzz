# Arguzz step-domain mismatch — root cause, scope, fix, and re-run plan (MASTER)

**Owner:** Track A (IV.POS.9). **Status:** investigation CLOSED (100% certainty, source-traced); fix
DESIGNED, awaiting user go-ahead to implement + re-run. **Created:** 2026-06-27.

**Companion:** `STEP_DOMAIN_MAPPING_DETAILS.md` (next to this file) is the extreme-detail reference for the
coordinate systems, the exact user-vs-machine-ecall divergence gate, why A4 is immune, the map construction, and
the per-pull self-check. Read it for any mechanism question.

This is the single master plan for fixing the semantic (step-counter domain) mismapping in the bandit
scheduler and for the campaigns that follow it. It supersedes the ad-hoc notes in
`a4/runs/iv_pos_9/a1/V6CTS_ROOTCAUSE_INVESTIGATION_PLAN.md` (which holds the raw investigation) and gates the
frozen Pro package (`a4/runs/iv_pos_9/a1/PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md`).

---

## 0. TL;DR

- **The bug (CORRECTED 2026-06-27).** The Arguzz arm's `step` (executor `current_step`) and `opcode_class`
  (executor mnemonic) are correct, and the injection (`--inject-step step`) hits the right instruction. But arm
  construction computes the arm's `zone` via `step_to_zone[step]` — indexing the **witgen-`user_cycle`-keyed**
  zone table with an **executor** step number. Since the two counters drift by the running host-ecall count
  (+8 at the divides), the **zone label is wrong**: the `core_div` arm actually holds `lw`/`ori`; the divides are
  injected but scattered into `core_memory_store`/`core_branch`. (Earlier framing — "injects on the wrong
  instruction" — was inverted; see §1.2.)
- **Scope (certain).** The mislabel affects **Arguzz-surface arms ONLY** → **V6_cTS entirely** and the
  **Arguzz portion of Hybrid_cTS**. The **A4 surface is correct** (its zone lookup indexes `step_to_zone` with a
  `user_cycle`, the coordinate the table is keyed in) → **V5_control and Hybrid's A4 portion are valid**.
  **V6_uniform's results are VALID** (round-robin; its zone label is unused).
- **Consequence.** The bandit's per-arm Beta posterior is keyed on a scrambled `zone`, so it cannot concentrate
  exploration on a semantic execution-unit (the divides are never grouped). **The V6_cTS-vs-V6_uniform comparison
  is CONFOUNDED.** The headline (uniform 9, cTS 0) is real, but its cause is this bug — not a property of cTS.
- **The fix is REBUILD-FREE.** The witgen↔executor map is built from the *existing* binary's `--trace`. No
  risc0/zirgen rebuild. Pure `a4/standalone` Python. **Arguzz's mutation-value logic and risc0 are NOT touched.**
- **The fix:** at arm construction (and the reward-zone lookup) compute `zone = step_to_zone[to_user[step]]` —
  translate the executor step to its `user_cycle` *before* the witgen-zone lookup (§4.3). `step`, `opcode_class`,
  and injection are unchanged. Guarded by a permanent per-pull closed-loop check (§4.4) that aborts if any arm's
  zone ≠ the true zone of the instruction it mutates.
- **Re-run:** V6_cTS + Hybrid_cTS only (6 seeds × 5000 each). V6_uniform + V5_control stay as-is (valid). Then
  re-run the replay oracle, recompute the now-unconfounded comparison, and only then revise the Pro package.

---

## 1. The bug (certain, source-traced)

### 1.1 Two step counters that drift

| counter | source | increments | consumed by |
|---|---|---|---|
| **executor `current_step`** | `rv32im.rs:33` (field), `:158-159` (++ per `step()`) | once per executed instruction (incl. every host ecall) | `--trace` (`:139`), `--inject-step` (`:154`), **and** the Arguzz arm `step`/`opcode_class` |
| **witgen `user_cycle`** | `preflight.rs:555`, only in `on_insn_end` (`:553-557`) | once per *retired guest* instruction; **skips machine/host ecalls** | the semantic-zone classifier (emitted as `"step"` at `mod.rs:135`) |

**The drift is +1 per *machine/host* ecall — NOT per ecall/mret (corrected 2026-06-27, source + binary).**
`current_step` bumps unconditionally for every instruction (`rv32im.rs:716`). `user_cycle` bumps only when
`exec_rv32im` returns `Some` (`rv32im.rs:670` → `on_insn_end`), and `step_system` returns `Some` only when the
ecall/mret dispatch returns `true`. Per `r0vm.rs:633`: **user** ecall (`user_ecall`, `:364`) → `Ok(true)` (counts);
`mret` (`:641`) → `Ok(true)` (counts); but **machine/host** ecall (`machine_ecall` → read/write/poseidon2/sha2/
bigint/terminate, all `Ok(false)`, `:397/512/546/560/574/588`) → `None` → `user_cycle` **not** bumped (it is
instead modeled via `on_ecall_cycle`, `preflight.rs:630`, which bumps the *plural* `user_cycles`, not the
singular). So `current_step − user_cycle` = running count of host ecalls (+ any exception traps): **0 before the
first host ecall, +8 by the divides.** VERIFIED on B2: 17 ecall/mret precede the remu (4 user + 8 machine + 5
mret) but drift is exactly **8 = the machine-ecall count**. The offset is **per-step (not constant, not
formulaic)**; the implemented map (`step_domain_map.py`) computes it rebuild-free by ordering the executor
`--trace`, dropping host ecalls (ecall mnemonic at a kernel pc), and mapping survivor *k* ↔ `user_cycle k`.

### 1.2 The crossed wire — it is the ZONE LOOKUP, not the injection (CORRECTED 2026-06-27, code + DB)

The earlier framing here ("arm steps are witgen-space, injected as executor → wrong instruction") was **inverted**.
The truth, from `semantic_arm_universe.build` (Arguzz branch, `:280-300`) + the race DB:

- The Arguzz arm `step` comes from `arguzz_bridge.get_valid_steps`, which iterates `baseline_trace` keys =
  **executor `current_step`**. So the arm step is an **executor** step, and `--inject-step step` hits the right
  instruction. `opcode_class` = `baseline_trace[step]` mnemonic = **executor** mnemonic → also correct.
- The bug is the third feature: `zone = step_to_zone.get(step)` (`:282`) indexes the **witgen-`user_cycle`-keyed**
  `step_to_zone` table with the **executor** step number. The same number is read as an executor index (for
  `opcode_class`/injection — correctly) and a witgen index (for `zone` — wrongly).
- Result: the **zone label is wrong**; the injection and `opcode_class` are right. The reward-path lookups
  `mutation_zone = step_to_zone[step]` and `cycle = data.get_cycle(step)` (`fuzzer.py:1218-1219`) mis-index the
  same way, so reward is attributed to the wrong zone.

### 1.3 The verified golden fact (binary B2 + race DB)

```
remu   : executor current_step = 444   |   witgen user_cycle = 436   (drift +8)
divu   : executor current_step = 449   |   witgen user_cycle = 441   (drift +8)
```

DB proof of the zone mislabel (V6_cTS, seed1234): the arm `INSTR_WORD_MOD|core_div|memory_load|step=436` exists —
`--trace[436]=Lw` (so `opcode_class=memory_load` is correct and the step is executor), while `zone=core_div`
came from `step_to_zone[436]`=`user_cycle 436`=remu. And the real remu (executor **444**) sits in
`INSTR_WORD_MOD|core_memory_store|arithmetic|step=444` and **was injected**. So the `core_div` arm holds `lw`/`ori`;
the divides are injected but scattered into `core_memory_store`/`core_branch`. Injection: correct. Grouping by
zone: scrambled.

### 1.4 Why it is not a cosmetic mislabel

The Beta posterior the bandit learns is **per arm = per (kind, zone, opcode_class, …)**. With the zone scrambled,
instructions are grouped under the wrong execution-unit, so the bandit cannot concentrate exploration on a
semantic unit (e.g. "the divider"): the divides are split across mislabeled zones and never isolated. The bandit
*did* learn (not a dead reward — see §3); it just learned over scrambled zone groupings. The CVE's divides are
reachable but never concentrated → the rare op is not targeted.

### 1.5 Full blast radius (systematic review 2026-06-27) — the reward is ALSO corrupted

A 2-agent census + a DB/map quantification (read-only) established the complete scope:

- **Quantified:** drift>0 begins at executor step **137** (first host ecall); across the 6 V6_cTS seeds, **69%
  of distinct injected Arguzz steps (1491/2143) carried a wrong zone** (the rest are the pre-first-ecall prefix
  or steps whose drifted index happens to share a major). The mislabel is the common case, not an edge case.
- **The reward signal is corrupted, not just the recorded label.** `bandit_success = 1 if (l_new+g_new+s_new)>0`
  (`reward_v2.py:60`). `l_new` (local constraint discoveries) is **clean** (uses the failure's own major/minor).
  But `s_new` (structural-cell novelty) is keyed on `(kind, mutation_zone, opcode_class(mutation_major), …)`
  (`reward_v2.py:171-174`, `structural_cells.py`) and `g_new` (compressed-global novelty) embeds
  `cycle_phase(mutation_zone)`/`opcode_class(mutation_major)` (`compressed_global_extractor.py:309-310`) — both
  read the **mislabeled** `mutation_zone`/`mutation_major`. A wrong key looks "novel", so the OR **inflates**
  `bandit_success` (spurious successes), worst on the no-discovery runs that dominate cTS. So the prior cTS reward
  was *inflated*, and `v2_scheduler.update_with_outcome` learned on it. ⇒ the re-run is necessary (not just a
  relabel), and the prior "≈9.3% success" was inflated.
- **Confirmed clean (no fix):** the entire A4 path (witgen→witgen), uniform *selection* (round-robin; zone is
  recording-only), the injection (always executor-correct), `opcode_class` (executor mnemonic), and `l_new`.

**Complete fix surface (all use the same `to_user` translation):**
| locus | file:line | role | priority |
|---|---|---|---|
| Arguzz arm `zone` | `semantic_arm_universe.py` build Arguzz branch (~:290) | arm definition (root — flows into `ArmKey`) | **must** |
| reward `mutation_zone` | `fuzzer.py` `_run_arguzz_cts_mutation` (~:1216) | feeds `s_new`/`g_new` → `bandit_success` | **must** |
| reward `mutation_major` | `fuzzer.py` `_run_arguzz_cts_mutation` (~:1217, `get_cycle`) | feeds `s_new`/`g_new` | **must** |
| record zone/major | `fuzzer.py` `_record_arguzz_mutation` (~:1179-1180) | CGC context persisted | should |
| telemetry zone/major | `fuzzer.py:660/680` → `telemetry_v2.py:181` (Arguzz caller `:1303`) | recorded label | should |
| uniform/legacy record | `v6_uniform_driver.py:157/177`, `v6_driver_v2.py:493-494` | recorded label (selection unaffected) | **DONE** 2026-06-27 (fixed w/ safe fallback; uniform not re-run) |

---

## 2. Scope — which arms / variants are affected (CERTAIN)

The deciding question: is the `zone` lookup indexed in the coordinate the `step_to_zone` table is keyed in
(witgen `user_cycle`)? A4 indexes it with a `user_cycle` → correct. Arguzz indexes it with an executor step
→ mislabeled.

| variant | surface(s) | arm `step` / `opcode_class` | `zone` lookup index | zone correct? | results valid? |
|---|---|---|---|---|---|
| **V6_uniform** | Arguzz | executor `--trace` (round-robin, not bandit) | n/a (zone label unused) | n/a | ✅ **VALID** |
| **V6_cTS** | Arguzz | executor (correct) | `step_to_zone[executor_step]` ❌ mis-indexed | **WRONG** | ❌ confounded |
| **V5_control** | A4 only | witgen `user_cycle` (correct) | `step_to_zone[user_cycle]` ✅ | correct | ✅ **VALID** |
| **Hybrid_cTS** | A4 + Arguzz | A4 witgen; Arguzz executor | A4 `[user_cycle]` ✅; Arguzz `[executor]` ❌ | mixed | ❌ Arguzz portion confounded |

(Injection and `opcode_class` are correct for every variant; only the Arguzz `zone` label is wrong.)

### 2.1 Why the A4 surface is correct (no fix needed)

Every A4 `A4_MUTATION_CONFIG` handler matches its `step` field against **`cycle.user_cycle`**, never the
executor counter: `INSTR_TYPE_MOD` (`mod.rs:325`), `INSTR_WORD_MOD` (`:352`), `COMP_OUT_MOD` (`:405`),
`LOAD_VAL_MOD` (`:451`), `STORE_OUT_MOD` (`:496`), `PRE_EXEC_REG_MOD` (`:568`), `MEM_VAL_MOD` (`:623`). The
txn-mutating kinds additionally pin the exact cell by **absolute `txn_idx`** into `trace.txns[]`
(`mod.rs:390-392`), and that `txn_idx` is itself derived from `user_cycle`-keyed inspection data
(`comp_out_mod.py:79,141-142`; `A4CycleInfo.step = user_cycle`, `trace_parser.py:25,46`). The A4 arm step-set is
built from the same `user_cycle` space (`semantic_arm_universe.py:262-278`, `inspection_data.py:172-248`). So
**arm-build space == zone-label space == mutation-apply space**, all `user_cycle`. There is no mismatch of any
kind on the A4 surface — not the Arguzz one, not a `cycle_idx`/txn-index variant.

### 2.2 Why V6_uniform is valid

`v6_uniform_driver.py` enumerates steps from the **executor `--trace`** (`parse_trace_steps`, `:103`,
unpacked `for step,_pc,instr,_asm in trace` at `:108`) and injects via `--inject-step` — the *same* executor
counter — so it hits the **intended** instruction. The only witgen-space quantity it touches is the recorded
**zone label** (`step_to_zone.get(step)`, `:157`), which is mislabeled-but-unused: it is round-robin over
instruction *kinds* (`ArguzzScheduler`, not the bandit), so the zone never steers selection. Its accept/find
results are sound. **No re-run needed.**

### 2.3 The answer to the three scoping questions

1. *Does it affect any variant running the bandit?* — It affects the bandit's **Arguzz arms** (V6_cTS + Hybrid's
   Arguzz portion). It does **not** affect the bandit's **A4 arms**.
2. *Does the bandit always get a wrong semantic understanding?* — On the **Arguzz surface, yes**: every arm whose
   step is after the first host ecall carries a wrong `zone` label (the instruction is mutated correctly, but
   filed under the wrong execution-unit). On the **A4 surface, no** — the zone is exact.
3. *Arguzz-only, or A4 too?* — **Arguzz-only.** A4 arms are correct.

---

## 3. State of the rest of the diagnosis (for completeness; both verified)

- **Reward was not dead.** `mutation_rewards.reward = 0` for V6_cTS is a *logging artifact*: legacy
  `compute_reward` returns all-zero `mode="crash"` when `touch_bitmap is None` (`coverage_state.py:190`), and the
  Arguzz path hard-codes `touch_bitmap=None` (`fuzzer.py:1226`). The bandit actually learns from
  `compute_bandit_success` (`reward_v2.py:60`), logged in `reward_counterfactuals.discovery_binary_reward`
  (456–475/seed ≈ 9.3% success; ~1650 adaptive Thompson picks/seed). The fix here does **not** require touching
  the reward path; it is already functioning. (If we later want `mutation_rewards` to be non-trivial for Arguzz,
  that is a separate logging cleanup, not part of this fix.)
- **Arm key is 5-field** `(surface, kind, zone, opcode_class, pre_post)` (`semantic_arm_universe.py:174-205`):
  V6_cTS = 417 arms (all Arguzz), V5 = 85 (2-field A4), Hybrid = 256 (85 A4 + 171 Arguzz).

These do not change the fix; they are recorded so the master plan is self-contained.

---

## 4. The fix

### 4.1 The invariant we must enforce (and keep enforced forever)

> For every Arguzz arm, the `zone` (and `opcode_class`) label MUST be the true zone/class of the instruction
> actually mutated at the arm's executor `--inject-step`.

`step` and `opcode_class` are already correct (executor space). Only `zone` is wrong, because it indexes the
witgen-keyed `step_to_zone` table with an executor step. The fix corrects that one index.

### 4.2 It is rebuild-free — the witgen↔executor step map (IMPLEMENTED + VALIDATED)

`a4/standalone/step_domain_map.py` builds the bijection on real guest instructions from the *existing* `--trace`
(no new binary output): order the executor steps, drop host ecalls (ecall mnemonic at a kernel pc), and map
survivor *k* ↔ `user_cycle k`. It exposes `to_user : current_step → user_cycle` (the direction the fix uses) and
`to_exec` (for tests/per-pull). Self-validating: contiguous executor stream; survivor count ≤ witgen
`total_steps`; the gap is trailing phantoms only (no `major≤6` Decode); monotone. **Validated on B2:**
`to_exec(436)=444 [RemU]`, `to_exec(441)=449 [DivU]`, phantom gap 1, 15 host ecalls. Deterministic per
`(guest,input)`; built once at bootstrap.

### 4.3 The fix — correct the zone lookup at arm construction (+ reward path)

Every Arguzz zone lookup must index `step_to_zone` with a `user_cycle`, not an executor step:

1. **`semantic_arm_universe.build`, Arguzz branch (`:282`):** replace `zone = step_to_zone.get(step)` with
   `zone = step_to_zone.get(to_user[step])`. Equivalently build `exec_step_to_zone[E] = step_to_zone[to_user[E]]`
   once and pass it in. `step` (executor) and `opcode_class` (executor mnemonic) are **unchanged** — already
   correct. Host-ecall executor steps (no `to_user` entry) → a boundary zone (`pre_ecall`) or dropped.
2. **`fuzzer._run_arguzz_cts_mutation` (`:1218-1219`):** the reward-zone/major lookups
   `mutation_zone = step_to_zone[step]` and `cycle = data.get_cycle(step)` must likewise use `to_user[step]`, so
   reward is attributed to the correct zone.

The injection (`--inject-step step`) is **not** changed — it was always correct. **Nothing on the A4 path or in
Arguzz's mutation-value logic changes.** This is the smallest correct change; the per-pull guard (§4.4) is what
makes it bulletproof.

### 4.4 Per-pull closed-loop guard (always on; the real guarantee)

On every Arguzz pull (arm `A=(kind, zone Z, class C, …)`, executor `step E`): **(Layer 1)** assert
`step_to_zone[to_user[E]] == Z` and `opcode_class_of(trace[E].mnemonic) == C`; on mismatch **raise and abort**.
**(Layer 2)** parse the pc the binary reports mutating (`print_injection_info`, `rv32im.rs`) and assert it equals
`trace[E].pc`. Together these make it impossible for an arm to carry a zone other than the true zone of the
instruction it mutates without the run failing loudly. (Full detail: `STEP_DOMAIN_MAPPING_DETAILS.md` §4.)

### 4.5 Isolation / non-goals (standing constraints)

- **Do NOT modify Arguzz's mutation logic or how it chooses mutation *values*** (the Rust `random_word` etc.).
  This fix is purely in the `a4/standalone` harness's *step-domain translation* — which instruction we point
  the existing injector at, not how it mutates.
- **No risc0 / zirgen rebuild** (the fix is rebuild-free). If implementation ever appears to require a rebuild,
  **STOP and flag the user first.**
- Do not touch the other worktrees / their binaries / their running jobs.

---

## 5. Testing — so the mismapping can never silently recur

The choice of A vs B does **not** by itself guarantee "always correct" — the *regression audit (T1)* does. T1
must run in CI and as a pre-campaign gate.

- **T1 — cross-counter invariant audit (the guarantee).** For a known guest, build the map; for **every Arguzz
  arm**, take each step in its set, compute the executor `--inject-step`, and assert the instruction at that
  executor step (from `--trace`) has a mnemonic whose class matches the arm's `zone` *and* `opcode_class`. Fail
  loudly listing every mismatch. This is exactly the invariant of §4.1 and would have caught the bug on day one.
  New file: `a4/audits/A6_arguzz_inject_step_consistency.py`.
- **T2 — map golden test.** On the CVE guest (binary B2), assert `remu: witgen 436 ↦ executor 444`,
  `divu: witgen 441 ↦ executor 449`, drift monotone non-decreasing, and every "real" executor instruction is
  covered. Pin the alignment so the next-vs-current-pc handling can't regress.
- **T3 — extend A2/A3 across the counter boundary.** `A2_zone_classifier_correctness.py` and
  `A3_arm_step_integrity.py` operate purely in witgen space → blind to this bug. Add an executor-space cross
  check (or a sibling `A2b`/`A3b`) that validates zone↔injected-instruction in executor space.
- **T4 — round-trip on the CVE guest.** After the fix, assert the `INSTR_WORD_MOD|core_div` arm injects on
  executor 444/449 (the divides) and that the count of divide-targeted Arguzz injections is comparable to
  uniform's divide share. This is the behavioral proof the fix works end-to-end.
- **T5 — determinism.** Extend `a4/standalone/tests/test_determinism.py` so the map + translated steps are
  reproducible for a fixed (guest, seed).
- **Gate.** Wire T1 (and T2) into the campaign launcher's pre-flight so no campaign can start with a mismapped
  arm universe.

---

## 6. Re-run plan (after the fix lands and T1–T5 pass)

1. **Re-run only the confounded variants:** V6_cTS and Hybrid_cTS, 6 seeds × N=5000 each, on binary B2
   (`output-a1vuln`), same dispatch infra (see `[[iv-pos9-sweep-dispatch]]` memory + the chain-guard `cd`
   gotcha). **Keep** the existing V6_uniform and V5_control DBs — they are valid (§2.1–2.2); re-running them
   would only add same-build noise and cost.
2. **Re-run the replay oracle** (`a4/runs/iv_pos_9/a1/cve_replay_oracle.py`) on the new cTS/Hybrid
   INSTR_WORD_MOD accepts → recompute CVE finds (remu→acc=0, divu→acc=9000028, honest=9000027).
3. **Recompute the comparison** — now **unconfounded**. Report cTS vs uniform CVE finds + the divide-targeting
   rate (how often each actually mutated executor 444/449).
4. **Caveat to carry forward (not a bug):** even after the fix, cTS may still trail uniform. A rare op is one
   *step inside one zone-arm* under cTS (diluted across ~19 zones then many steps) vs a full ≈1/40 *kind* share
   under uniform. That is a *legitimate scheduling property* and is precisely the architecture question for Pro.
   The fix makes the comparison *valid*; it does not predetermine the winner.

---

## 7. Downstream — Pro package

Only after §6 produces a fix-validated comparison:

- Rewrite `PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md` **§5.3** (currently frozen and known-WRONG: it told the
  dead-reward + coverage-starvation story). Replace with: the step-domain bug, the fix, and the *post-fix*
  cTS-vs-uniform numbers.
- Update `WHY_V6CTS_MISSES_THE_CVE.md` (already carries a superseding caveat) to point here.
- Only then ask Pro the architecture question (how to make cTS beat uniform on rare soundness ops without
  overfitting), now grounded in valid data.

---

## 8. Open decisions for the user (confirm before implementing)

1. **Fix option:** B (translate at injection, recommended — surgical, rebuild-free) vs A (canonical
   executor-space Arguzz arms, cleaner but larger). Default: **B now, A as a later refactor.**
2. **Re-run scope:** cTS + Hybrid only (recommended) vs also re-running uniform/V5 for a single same-build sweep.
3. **Go-ahead:** per standing constraint, any source change + campaign re-run is confirmed with the user before
   execution. This doc proposes; it does not yet act.

---

## Appendix — file:line index

| concern | location |
|---|---|
| executor `current_step` (field / ++ / inject match / trace emit) | `risc0-modified/.../execute/rv32im.rs:33` / `:158-159` / `:154` / `:139` |
| witgen `user_cycle` (++ / emit as "step") | `risc0-modified/.../prove/witgen/preflight.rs:555` / `mod.rs:135` |
| A4 handlers match `cycle.user_cycle == target_step` | `mod.rs:325,352,405,451,496,568,623` |
| A4 txn cell pinned by absolute `txn_idx` | `mod.rs:390-392` |
| zone classifier (witgen `user_cycle`) | `a4/standalone/zone_classifier.py:48,68,76`; `semantic_zones.py` |
| arm universe (5-field key / build / step-set intersection) | `a4/standalone/semantic_arm_universe.py:174-205,262-278` |
| `A4CycleInfo` fields (`cycle_idx,step,pc,major`) | `a4/core/trace_parser.py:24-28,45-49` |
| InspectionData step keying / valid-steps | `a4/core/inspection_data.py:59,121-123,172-248` |
| cTS Arguzz dispatch (pick → create → invoke) | `a4/standalone/fuzzer.py:1195-1300,1393` |
| Arguzz `--inject-step` emit | `a4/standalone/arguzz_invoke.py:134-135` |
| V6_uniform trace steps / zone label | `a4/standalone/v6_uniform_driver.py:103,108,154,157` |
| reward (legacy vs bandit) | `a4/standalone/coverage_state.py:190`; `reward_v2.py:60`; `fuzzer.py:1226` |

## Appendix — glossary

- **executor `current_step`** — the rv32im interpreter's per-instruction counter; what `--trace` and
  `--inject-step` use. Counts every ECALL/MRET micro-cycle.
- **witgen `user_cycle`** — the witness-generator's per-retired-instruction counter; what the zone classifier
  reads. Collapses ECALL/MRET micro-cycles. Drifts behind `current_step` by +1 per ECALL/MRET.
- **Arguzz surface** — during-execution fault injection (`--inject-step`, executor space).
- **A4 surface** — post-execution witness-cell mutation (`A4_MUTATION_CONFIG`, witgen `user_cycle` space).
- **zone** — semantic bucket of a step from its cycle `major` (e.g. major 4 → `core_div`).
- **confounded** — the cTS-vs-uniform comparison cannot be attributed to the schedulers because cTS's arm `zone`
  labels were systematically scrambled by this bug (instructions grouped under the wrong execution-unit).
