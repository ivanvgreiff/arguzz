# Step-domain mapping — the precise mechanics (companion to MASTER_PLAN.md)

**Status:** verified against source + the B2 binary (`output-a1vuln`, guest `--ctrl 7 --gseed 12345 --rounds 5`),
2026-06-27. This is the extreme-detail reference for *why* the bandit's Arguzz arms mis-target, *why* A4 arms do
not, and *exactly* how the fix maps coordinates and self-checks on every pull. Read `MASTER_PLAN.md` first for
the plan; this doc is the ground truth it rests on.

---

## 1. The coordinate systems (there are four; only two matter for the bug)

The VM emits several different "cycle/step" numbers. Conflating them is the entire bug, so define them exactly:

| name | lives in | one per | increments when | who reads it |
|---|---|---|---|---|
| **executor `current_step`** | execute pass (`execute/rv32im.rs:33`) | **every executed instruction** | `fault_inj_ctx.step()` at end of *every* `step<C>()` (`rv32im.rs:716`), unconditionally | `--trace` (`:140`) and **`--inject-step`** (`:154`) — i.e. the **Arguzz** injector |
| **witgen `user_cycle`** | witgen/preflight (`prove/witgen/preflight.rs:85`) | **retired *guest* instruction** | only in `on_insn_end` (`preflight.rs:555`) | the **zone classifier** (emitted as `"step"`, `mod.rs:135`) and the **A4** apply handlers |
| witgen `cycle_idx` | witgen | **ZK circuit cycle** (incl. Poseidon/control/IO/paging) | every `add_cycle*` push | indexing into `trace.cycles[]`; the `<a4_cycle_info>` line index |
| txn `cycle` | witgen txns | memory access | n/a — *computed* as `2·cycle_idx` (read) / `2·cycle_idx+1` (write) (`preflight.rs:572/607`) | the circuit's read/write phase split |

The bug is **`current_step` (Arguzz consumer) vs `user_cycle` (zone producer)**. `cycle_idx` and txn `cycle` are
documented here only so they are never confused with the two that matter. (Verified: `RawPreflightCycle` carries
`user_cycle` at `rv32im-sys/src/lib.rs`; `user_cycle` *singular* is bumped at exactly one site, `preflight.rs:555`;
the *plural* `user_cycles` at 474/640/679/690 is unrelated bookkeeping.)

---

## 2. Why `current_step` and `user_cycle` diverge — the exact gate (user vs machine ecall)

Both counters agree for ordinary instructions. They diverge at exactly one code gate.

**`current_step` counts everything.** `fault_inj_ctx.step()` (→ `current_step += 1`) runs at the end of every
`step<C>()` (`rv32im.rs:716`), no matter what the instruction was.

**`user_cycle` only counts instructions that "return Some".** It is bumped only inside `on_insn_end`
(`preflight.rs:555`), which is invoked only by `ctx.on_normal_end(kind)`, which the emulator calls only when
`exec_rv32im` returns `Some(kind)` (`rv32im.rs:670`). For system instructions, `step_system` returns
`Some(kind)` **iff** the dispatch returns `true` (`…?.then_some(kind)`).

**The dispatch is the user-vs-machine branch** (`r0vm.rs:633`):

```
fn ecall(&mut self) -> Result<bool> {
    if self.is_machine_mode() { self.machine_ecall() }   // host calls
    else                      { self.user_ecall() }      // guest syscall entry
}
```

| instruction | returns | `→ Some?` | `on_insn_end`? | `user_cycle` | `current_step` | net drift |
|---|---|---|---|---|---|---|
| normal (add/lw/remu/divu/…) | `Some` | yes | yes | **+1** | +1 | 0 |
| **user** ecall — `user_ecall` (`r0vm.rs:364`) | `Ok(true)` | yes | yes | **+1** | +1 | 0 |
| `mret` (`r0vm.rs:641-648`) | `Ok(true)` | yes | yes | **+1** | +1 | 0 |
| **machine/host** ecall — `machine_ecall` → `ecall_read/write/poseidon2/sha2/bigint/terminate`, **all `Ok(false)`** (`r0vm.rs:397/512/546/560/574/588`) | `Ok(false)` | **no** | **no** | **+0** | +1 | **+1** |
| exception `trap` (`r0vm.rs:668`) | `Ok(false)` | no | no | +0 | +1 | +1 |

A host ecall is instead modeled as circuit cycles via `on_ecall_cycle` (`preflight.rs:630`), which bumps the
*plural* `user_cycles`, **not** the singular `user_cycle`. So **a host ecall costs one `current_step` but zero
`user_cycle` → the two counters drift apart by exactly the running count of host ecalls (plus any traps).**

### 2.1 Measured proof on B2 (the divides)

`--trace` (executor) vs `A4_INSPECT` (witgen), same guest/input:

```
remu a4,a0,a1 :  executor current_step = 444   |  witgen user_cycle = 436   (drift +8)
divu s0,a2,a3 :  executor current_step = 449   |  witgen user_cycle = 441   (drift +8)
```

Before the remu the executor shows **17** ecall/mret: **4 user ecalls + 8 machine ecalls + 5 mrets**. The drift
is **exactly 8 = the machine-ecall count**. The 4 user ecalls and 5 mrets add zero — precisely as the table
predicts. So the drift is **not** "+1 per ecall/mret"; it is **+1 per machine/host ecall**, and it is **0 before
the first host ecall, then strictly increasing**. (Earlier notes saying "+1 per ECALL/MRET" are corrected.)

### 2.2 The same number means different instructions — and the bandit indexes it in BOTH spaces at once

Because of the +8 drift, the *number* 436 denotes different instructions in the two coordinate systems:

```
                       executor current_step 436 → `lw a0,16(sp)`     (pc 2099352)
witgen user_cycle 436  ───────────────────────────────────────────────────────────
                       is the remu                → `remu a4,a0,a1`   (pc 2099384, executor step 444)
```

**CORRECTED 2026-06-27 (code + DB; the earlier framing in this section was inverted).** The Arguzz arm `step`
is *not* a witgen `user_cycle` — it is an **executor `current_step`** (it comes from the `--trace` keys; see §4).
So the injection is **correct** and `opcode_class` (from the executor mnemonic) is **correct**. The bug is that
arm construction computes the third feature, `zone`, by indexing the **witgen-keyed** `step_to_zone` map with the
**executor** step number — `step_to_zone[E]` — so the *same number* `E` is read as an executor index (for
`opcode_class`/injection, correctly) **and** as a witgen index (for `zone`, wrongly). The result is a **zone
mislabel**, proven in the DB:

```
arm INSTR_WORD_MOD|core_div|memory_load|step=436   →  --trace[436]=Lw      (opcode_class=memory_load CORRECT; zone=core_div WRONG)
arm INSTR_WORD_MOD|core_memory_store|arith|step=444 →  --trace[444]=RemU   (opcode_class=arith CORRECT; zone=core_memory_store WRONG)
```

A `core_div|memory_load` arm at step 436 can only exist if 436 is an executor step (Lw→memory_load) whose zone
was mis-read as `step_to_zone[436]`=user_cycle-436=remu=core_div. So: **the `core_div` arm actually holds `lw`/`ori`;
the real divides (executor 444/449) are injected but mislabeled into `core_memory_store`/`core_branch`.** The
divides ARE reachable (the DB shows `INSTR_WORD_MOD` at step 444); they are just never *grouped* under one
execution-unit zone, so the bandit cannot concentrate on "the divider." Injection target: fine. Zone semantics:
scrambled.

### 2.3 The reward is ALSO corrupted — not just the recorded label (systematic review)

The same mis-indexed `mutation_zone`/`mutation_major` are **load-bearing inputs to the bandit's reward**, so the
bandit learned on a partly-fabricated signal. `bandit_success = 1 if (l_new + g_new + s_new) > 0` (`reward_v2.py:60`):

- **`l_new`** (local constraint discoveries) — **clean**: it reads the *failure's own* `(loc, major, minor)`
  from the prover output, not `mutation_zone`/`mutation_major`.
- **`s_new`** (structural-cell novelty) — **corrupted**: the cell is keyed on
  `(kind, mutation_zone, opcode_class(mutation_major), …)` (`reward_v2.py:171-174`, `structural_cells.py`). A wrong
  zone/major makes a *fabricated* cell look first-seen → `s_new=1`. This is the cold-start term that fires even
  when no constraint broke, so it flips `bandit_success` to 1 on runs that discovered nothing.
- **`g_new`** (compressed-global novelty) — **corrupted when residues exist**: it embeds
  `cycle_phase(mutation_zone)` / `opcode_class(mutation_major)` in the context key
  (`compressed_global_extractor.py:309-310`).

Net: the OR can only **inflate** `bandit_success` (a wrong key looks novel; it can't suppress a true `l_new` hit),
worst on the no-discovery runs that dominate cTS. So the prior cTS reward (≈9.3% "success") was **inflated**, and
`v2_scheduler.update_with_outcome(arm, …, success=bandit_success)` learned on it. **Consequence:** the re-run is
required (this is not a relabel), and the fix corrects the *inputs* (`mutation_zone`/`mutation_major` via
`_arguzz_zone_major`) at every Arguzz reward/record/telemetry locus — **`reward_v2.py` logic is unchanged**, which
is why the regression test asserts the reward *inputs* are now the true zone/major (T:
`test_reward_inputs_use_correct_zone_major`).

---

## 3. Why this does NOT affect A4 arms (the corrected reason)

The arm key has three step-derived features: `step` (where to mutate), `opcode_class` (static mnemonic class),
and `zone` (dynamic execution-unit). The whole question is **which coordinate each feature is computed in, and
whether the `zone` lookup is indexed in the coordinate its map was built in.**

`classify_zones`/`step_to_zone` is a **witgen-`user_cycle`-keyed** table: "what execution-unit zone does
`user_cycle U` belong to?" (`zone_classifier.py` reads `cycle.step`=`user_cycle`). It is *only* valid when
indexed by a `user_cycle`.

- **A4 arms** (`semantic_arm_universe.build`, A4 branch): the step-set comes from
  `data.get_valid_steps_for_kind` (iterates `data.cycles` → **`user_cycle`**), and `zone` comes from
  `zone_to_steps`/`classify_zones` (**`user_cycle`**). The mutation is applied by matching `cycle.user_cycle == S`
  (`mod.rs:325/352/...`). **Every step is a `user_cycle`, and the witgen zone table is indexed by a `user_cycle`.**
  Coordinate-consistent end to end → the zone is correct. ✅
- **Arguzz arms** (`semantic_arm_universe.build`, Arguzz branch): the step-set comes from
  `arguzz_bridge.get_valid_steps` which iterates `baseline_trace` keys → **executor `current_step`**;
  `opcode_class` comes from `baseline_trace[step]` (**executor** mnemonic) — both correct, and the injection
  (`--inject-step step`) is in the same executor space. **But `zone = step_to_zone.get(step)` indexes the
  witgen-keyed table with an *executor* step** (`semantic_arm_universe.py:282`). That one line crosses
  coordinates: it asks "what zone is `user_cycle E`?" when `E` is actually a `current_step`. ❌

So A4 is immune **not** because zones are surface-independent, but because A4 indexes the witgen zone table with a
witgen index, while Arguzz indexes the *same* table with an executor index. The bug is exactly one mis-indexed
lookup in the Arguzz branch — not a whole-surface mismatch, and not in the injection (which is correct).

**Analogy.** `step_to_zone` is a phone book keyed by *witgen* row number. A4 looks up its own witgen rows → right
number. Arguzz holds *executor* row numbers but looks them up in the witgen phone book by the bare number → it
reads the entry of a different person, because the executor book has extra rows (one per host ecall) so the same
ordinal points to a different line. The fix is to convert the executor row to its witgen row (`to_user[E]`) before
opening the witgen phone book.

### 3.1 The one place to be careful with A4, and why the divides are still clean

When several witgen cycles share one `user_cycle` (this happens for the `user_cycle` immediately following a host
ecall — the host-ecall cycles and the next Decode share a `user_cycle`), A4's locator must still pick the cycle
the zone classifier labeled. The code is built for this:

- The classifier's `_primary_decode_cycle(step)` takes the first cycle with `major ≤ 6` (`zone_classifier.py:29`),
  and its precedence labels any step containing a `major==8` cycle as `pre_ecall` / labels the following user-PC
  Decode as `post_ecall` (`:48-66`). So the classifier deterministically resolves the shared-`user_cycle` case.
- The A4 INSTR_WORD handler matches `user_cycle==S && (major≤6 || major==8)` and pins the fetch txn by
  `cycle.txn_idx` (`mod.rs:352-358`) — its comment explicitly accounts for "ECALL/CONTROL cycles first, then
  instruction."

This shared-`user_cycle` disambiguation is a **separate concern** from the cross-counter drift (it lives entirely
in `user_cycle` space and would exist even if Arguzz didn't). It is *not* known to be wrong, but to reach 100%
certainty it must be **proven by test** (see MASTER_PLAN T5 / §5 below), not assumed. **For the CVE specifically
it is a non-issue:** `user_cycle` 436/441 are ordinary single-cycle div instructions with no host ecall sharing
their `user_cycle` (verified — the nearest host ecalls are ~80 steps earlier), so the classifier's primary Decode,
the A4 handler, and the Arguzz target all refer to the same remu/divu. A4's div arms are exact.

### 3.2 V6_uniform is also clean (for the record)

`v6_uniform_driver.py` enumerates steps from `--trace` (executor `current_step`) and injects via `--inject-step` —
producer and consumer both executor — so it hits the intended instruction. Its recorded zone label is
`user_cycle`-space (wrong but never used to steer, since it is round-robin). Results valid.

---

## 4. The fix's mapping logic (and the per-pull self-check that guarantees correctness)

### 4.1 The map — IMPLEMENTED + VALIDATED (`a4/standalone/step_domain_map.py`)

The map is the bijection on real guest instructions, exposing **both** directions: `to_exec : user_cycle →
current_step` and `to_user : current_step → user_cycle`. **The corrected fix uses `to_user`** — to translate an
Arguzz arm's executor `step` to its `user_cycle` *before* indexing the witgen `step_to_zone` table (§4.2).
(`to_exec` is still used by the golden test and the per-pull pc check.) The offset
`current_step − user_cycle` = host ecalls + traps so far — **not** a constant, **not** a per-ecall/mret formula.
The implemented algorithm is simpler and more robust than PC alignment, and rebuild-free:

1. Capture the executor stream once: `host --trace` → ordered `(current_step, pc, mnemonic)`
   (the bootstrap already runs this for the arm universe).
2. **Drop host ecalls**: a trace line is a host (machine) ecall iff `mnemonic ∈ {Eany,ecall}` **and**
   `pc_in_kernel(pc)` (user ecalls have a user PC; `mret` keeps its own mnemonic). These are exactly the
   `Ok(false)` instructions that bump `current_step` but not `user_cycle`.
3. **The survivors are the witgen-visible instructions, in order** — so survivor *k* is `user_cycle k`.
   `to_exec(k) = survivors[k].current_step`. The host-ecall skips are what advance the offset.

Self-validation (in the builder, raises on failure): (a) the executor `current_step` stream is contiguous;
(b) survivor count `R ≤ total witgen user_cycles`; (c) the gap `[R, total)` contains **no** `major≤6` Decode —
i.e. it is only *trailing phantom* `user_cycle`s (the terminate/suspend/Poseidon special cycles carry the final
incremented `user_cycle` with no instruction behind it); (d) `to_exec` is strictly monotone with `to_exec(u) ≥ u`.
A wrong host-ecall accounting trips (b) (over-count) or (c) (under-count) instead of silently mis-targeting.

**Validated against B2** (`output-a1vuln`, `--ctrl 7 --gseed 12345 --rounds 5`, 2026-06-27):
`to_exec(436)=444 [RemU]`, `to_exec(441)=449 [DivU]`; witgen `total_steps=2375`, mapped `R=2374`,
**phantom gap = 1** (the trailing terminate `user_cycle 2374`, which carries only major 7/8/9/10 cycles),
**15 host ecalls** skipped; drift grows `0 → +4 → +8 (divides) → +14 (end)`. Contrast: today `--inject-step 436`
hits executor `Lw`; fixed, `--inject-step 444` hits `RemU`.

The map is deterministic for a fixed `(guest, input)` and is rebuilt per guest at bootstrap.

### 4.2 The fix (corrected) + the per-pull closed-loop verification

**The fix (arm construction + reward path).** Every Arguzz zone lookup must index the witgen `step_to_zone` table
with a `user_cycle`, not an executor step. Concretely:
- `semantic_arm_universe.build`, Arguzz branch: replace `zone = step_to_zone.get(step)` with
  `zone = step_to_zone.get(to_user[step])` (`step` is executor). Equivalently, build an executor-keyed
  `exec_step_to_zone[E] = step_to_zone[to_user[E]]` once and use it. `step` and `opcode_class` are unchanged
  (already correct in executor space). Host-ecall executor steps (no `to_user` entry) get a boundary zone
  (`pre_ecall`) or are dropped — they are not real guest instructions.
- `fuzzer._run_arguzz_cts_mutation`: the reward-zone/major lookups `mutation_zone = step_to_zone[step]` and
  `cycle = data.get_cycle(step)` must likewise use `to_user[step]`, so reward attribution is by the correct zone.

**The per-pull guarantee (always on; the real safety net).** Even with the fix, edge cases (pre/post-ecall shared
`user_cycle`, future guest shapes) could mis-map a single step. So check every pull and abort on mismatch:

- **Layer 1 — pre-injection assertion.** When the bandit pulls arm `A=(kind, zone Z, opcode_class C, pre_post)`
  and selects executor `step E`: assert `step_to_zone[to_user[E]] == Z` **and**
  `opcode_class_of(trace[E].mnemonic) == C`. On mismatch → **raise and abort**, logging `E, to_user[E], Z`.
- **Layer 2 — post-injection readback (from the binary).** The injector prints the pc it mutated
  (`print_injection_info(pc, …)`, `rv32im.rs`). Assert it equals `trace[E].pc` — the binary confirming it mutated
  the instruction the arm targeted. Catches any residual mapping error at the source, every pull.

With both, an Arguzz arm **cannot** be labeled with a zone other than the one its injected instruction truly
belongs to without the run failing loudly. The bandit is then provably pulling the zone it thinks it is.

### 4.3 Worked example (the CVE arm, post-fix)

```
build  : executor step E=444 (RemU)  -> to_user[444]=436 -> step_to_zone[436]=core_div   # zone now CORRECT
         => the (INSTR_WORD_MOD, core_div, arithmetic) arm now CONTAINS executor step 444 (and 449)
pick   : arm core_div, step E=444
Layer1 : trace[444]="RemU" ; step_to_zone[to_user[444]]=core_div ✓ ; class(RemU)=arithmetic ✓
inject : --inject-step 444 --inject-kind INSTR_WORD_MOD     # hits the remu (unchanged — already executor space)
Layer2 : <injection_info> pc == 2099384 (remu) ✓
```

Compare to today (broken): executor 444 (RemU) is mislabeled `step_to_zone[444]=core_memory_store`, so the remu
lands in the `core_memory_store` arm and the `core_div` arm holds `lw`/`ori` (executor 436/441). Layer 1 would
have aborted on those: `step_to_zone[to_user[436]]=core_mem ≠ core_div`. The injection itself was always correct;
only the **grouping** was wrong.

---

## 5. Tests required before POS (rigorous; expands MASTER_PLAN §5)

The headline test is **one invariant applied to BOTH surfaces** (T1), not two separate tests — because the whole
bug class is "the arm does not mutate what it thinks," which is surface-independent.

1. **T1 — mutation-target consistency (BOTH surfaces; the core guarantee).** The single invariant:
   *the cell actually mutated belongs to the semantic zone+class the arm declared.* For every arm of a known
   guest, with a per-surface "where did it land" probe:
   - **Arguzz arms:** for each step `S`, assert the `--trace` instruction at `to_exec(S)` has
     `zone == arm.zone` **and** `class == arm.opcode_class`. (Catches the cross-counter bug.)
   - **A4 arms:** assert the witgen cycle the A4 handler *actually selects* for `S` (replicating its
     `user_cycle==S && major` rule, cross-checked against the binary's `<a4_*_mod>` log) carries the zone the
     classifier labeled `S` — including the pre/post-ecall shared-`user_cycle` steps (closes §3.1).

   This is **no-prover** (needs only `--trace` + `A4_INSPECT`/`<a4_*_mod>`) and runs in minutes. It is the gate
   and would have caught the original bug on arm #1. **Yes — it tests both Arguzz and A4 under one bar.**
2. **T2 — map golden test.** `to_exec(436)=444`, `to_exec(441)=449`; monotone, `to_exec(u) ≥ u`; phantom gap is
   trailing-only; offset == host-ecall count so far. Must use a guest **with host ecalls**. (No prover.)
   *(Already passing against B2 — see §4.1.)*
3. **T3 — per-pull guard live test (prover).** Short cTS campaign with Layer-1+2 on: assert zero aborts on the
   correct build, and assert it **does** abort under a deliberately wrong `to_exec` (negative control — prove the
   guard fires).
4. **T4 — CVE round-trip (prover).** `core_div` arm injects on executor 444/449; Layer-2 readback pc ∈
   {2099384, 2099404}; confirm the committed output flips (the CVE actually triggers).
5. **T5 — determinism.** `to_exec` and all selections reproducible for fixed `(guest, seed)`. (No prover.)
6. **Gate.** T1+T2+T5 (no-prover) run first and in the campaign launcher pre-flight; Layer-1+2 stay **on**
   during the campaign (cheap, and the actual guarantee). No campaign starts, and none continues, with a
   mismapped pull.

---

## 5b. Implementation status (2026-06-27)

**DONE + validated without the prover:**
- `a4/standalone/step_domain_map.py` — the map (`to_user`/`to_exec` + `exec_step_zone_map`), self-validating.
- Arm-build fix: `SemanticArmUniverse.build(..., arguzz_step_to_zone=...)` (executor-keyed zone for Arguzz arms).
- Reward + CGC-record + telemetry fix: `A4Fuzzer._arguzz_zone_major()` used at the Arguzz reward/record loci;
  `_record_full_telemetry(zone_map=, major_override=)` for the Arguzz telemetry caller. Map built at bootstrap in
  `_setup_v2_bandit` (rebuild-free, reuses the captured `--trace`).
- Per-pull guards: `_assert_arguzz_target` (Layer 1: abort if arm.zone ≠ true zone or class mismatch) +
  `_assert_arguzz_injected_pc` (Layer 2: abort if the binary's reported pc ≠ targeted pc).
- Tests `a4/standalone/tests/test_step_domain_fix.py` (**7 pass, ~38s, no prover**): invariant **0/18909**
  violations fixed vs **8577** legacy (negative control); A4 arms consistent; map monotone; **guard fires** on a
  wrong zone; **reward inputs** are the true zone/major (`_arguzz_zone_major`, incl. remu→(core_div,4)); B2
  landmarks `core_div={444,449}`. 45 existing arm/bandit/telemetry tests still green.
- **Recording-only drivers now also fixed:** `v6_uniform_driver.py` and `v6_driver_v2.py` (legacy) translate
  executor→`user_cycle` before the zone/major lookup, with a safe fallback (recording-only ⇒ never abort a valid
  run). Each carries a docstring comment (what/when/why). Uniform's selection is round-robin and its finds are
  output-based, so results were always valid — this only corrects persisted labels; uniform is **not** re-run.

**PENDING (needs the prover / POS):** T3 (short fixed cTS campaign → zero guard aborts + negative control aborts)
and T4 (CVE round-trip: inject the divides, confirm pc readback + output flip), then the V6_cTS + Hybrid re-run.

## 6. One-line summary

`current_step` (executor; what Arguzz arm steps, `opcode_class`, and `--inject-step` use) counts every
instruction; `user_cycle` (witgen; what the `step_to_zone` table is keyed by) skips host ecalls; they drift by the
running host-ecall count. Arguzz arm construction looks up `zone = step_to_zone[executor_step]` — indexing the
witgen-keyed table with an executor number — so the **zone label is wrong** (the injection and `opcode_class` are
right). A4 indexes the table with a `user_cycle` → right. The fix translates the executor step to its `user_cycle`
(`to_user[E]`) **before** the zone lookup at arm construction, and **proves** on every pull that the arm's zone ==
the true zone of the instruction the binary actually mutated.
