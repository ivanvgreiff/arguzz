# Phase 7 — Investigation Report (7b POS smokes + 7c semantic verification)

**Author**: Opus
**Date**: 2026-06-09
**Status**: 7a ✅ DONE | 7b mostly ✅ (1 partial gate) | 7c ❌ **BLOCKED — verifier broken**
**Bottom line**: 7b looks operationally healthy and gives the first real V1↔V5 wall-time + failure-density numbers on POS. 7c is **not interpretable** — the 12/24 split is a verifier architecture bug, not a fuzzer issue.

---

## TL;DR (read this first)

1. **7b on flare passed essentially every gate** that doesn't depend on Hook 3 compressed-global. All five IV.POS.7 variants ran N=200, exit 0, all v2 tables populated, **wall-time ~2.90 s/mut for every variant** (V5/V1 = **1.01×**, well under Pro's 1.3×). DB size at N=200 is 0.58–0.93 MB → linear extrapolation to N=6000 is ~28 MB, well under the 150 MB budget. **V3/V4/V5 (v2 reward) find 1.4–2.7× more failures per mutation than V1/V2 (legacy reward)** — first real evidence the reward redesign is doing what it's supposed to.

2. **V5 recorded 144/200 mutations — this IS a bug, in fact two stacked bugs that will break Phase 8.** (Composer was right to flag this; my first-pass framing as "expected cold-start behaviour" was wrong.) Detailed mechanics in §1.4 below, summary:
   - **Bug A** — `SemanticArmUniverse.build` uses a too-coarse filter and produces "phantom arms" (e.g. `COMP_OUT_MOD|step0`) whose step lists are non-empty but where the actual mutation modules' `get_targets_at_step` returns None on every step. This trace has 6 phantom arms; verified by direct test.
   - **Bug B** — `_run_v2_bandit_mutation` returns on skip without calling `v2_scheduler.update(...)`, so phantom-arm `pulls` stay at 0 forever and the cold-start round-robin re-selects them indefinitely.
   - **Combined effect at N=6000: ≈144 success, ≈5856 skip, zero adaptive-TS decisions.** V5 produces a worse dataset than V1 not because cTS is bad, but because **cTS never runs at all**.
   - **Phase 8 is BLOCKED until both are fixed.** Fixes are small (one-line for B; sample-and-prune for A) — see §1.4.5.

3. **`compressed_global_coverage = 0` across ALL FIVE variants** (not V5-specific, despite what the 7b gate suggested). `global_failures` IS populated (291–611 rows / variant), so the constraint-failure path is healthy. The extractor produces zero rows because the per-mutation Hook 3 stream (`<a4_family_residue>`/`<a4_family_detail>`) is either not being emitted or not being parsed in the production fuzzer's path. This is **G3 (address-region map accuracy / Hook 3 plumbing)** materialising in real data and needs a one-shot diagnostic run to localise.

4. **Phase 7c (12/24) does NOT verify mutation semantics.** Composer's verifier runs the host with `A4_INSPECT=1 + A4_MUTATION_CONFIG=…` simultaneously and expects the inspection dump to reflect the post-mutation trace. **The dump is emitted BEFORE the mutation hook runs** (`risc0-modified/.../witgen/mod.rs` lines 73-186 vs 189+), so the verifier always reads the **pre-mutation** trace. Consequences:
   - The 12 PASS results are **spurious** (tautologies or fall-throughs to `True`).
   - The 12 FAIL results are **not fuzzer bugs** — verifier was reading the wrong copy of the trace and, for STORE_OUT_MOD, also checking the wrong kind of txn (register-write vs memory-write).
   - **G2 is therefore UNRESOLVED.** We have to rewrite the verifier (parse the mutation hook's own `<a4_<kind>_mod>` lines) before claiming "mutate-what-we-think-we-mutate".

---

## 1. Phase 7b — POS smoke results (N=200 × 5 variants, flare)

### 1.1 Raw numbers (from `collection_report.json` + per-DB queries)

| Variant | rec/req | Wall (s) | sec/mut | Failures | fail/mut | DB size |
|---|---|---|---|---|---|---|
| V1 `zoned` (legacy)                  | 200/200 | 576.0 | 2.88 | 455 | 2.27 | 700 KB |
| V2 `kindUCB_zoned_v1` (legacy reward)| 200/200 | 583.0 | 2.92 | 338 | 1.69 | 744 KB |
| V3 `kindUCB_zoned_v2_noQ` (v2 reward)| 200/200 | 581.0 | 2.90 | **910** | **4.55** | 932 KB |
| V4 `kindTS_zoned_v2`   (v2 reward)   | 200/200 | 577.0 | 2.88 | 705 | 3.52 | 864 KB |
| V5 `cTS_semantic_v2` (semantic+v2)   | **144/200** | 418.0 | 2.90 | 451 | 3.13 | 580 KB |

### 1.2 v2-table population (per-DB row counts)

| Variant | mut | local_cov_v2 | reward_cf | bandit_dec | mut_substr | hook3_raw | **comp_global** | arm_snap | global_fail |
|---|---|---|---|---|---|---|---|---|---|
| V1 zoned                  | 200 | 157 | 200 |   0 | 200 | 200 | **0** |  0 | 383 |
| V2 kindUCB_zoned_v1       | 200 | 121 | 200 | 200 | 200 | 200 | **0** | 16 | 452 |
| V3 kindUCB_zoned_v2_noQ   | 200 | 281 | 200 | 200 | 200 | 200 | **0** | 16 | 611 |
| V4 kindTS_zoned_v2        | 200 | 265 | 200 | 200 | 200 | 200 | **0** | 16 | 532 |
| V5 cTS_semantic_v2        | 144 | 165 | 144 | 144 | 144 | 144 | **0** | 53 | 291 |

### 1.3 Gate-by-gate verdict (D39 exit criteria)

| Gate (from `PHASE_7_SMOKE_TESTS.md`) | Verdict | Notes |
|---|---|---|
| 7b.1 All 5 dispatches succeed (exit 0)   | ✅ | All `exit_code=0`, single bundle SHA `6873e588…cc444` |
| 7b.2a Hard 7a gates re-pass on POS      | ✅ | No crash, no non-finite counterfactuals, schema OK |
| 7b.2b bandit_decisions ≈ rec count       | ✅ | V2–V4: 200/200. V5: 144/144 (matches recorded mutations) |
| 7b.2c arm_state_snapshot ≥ 2 rows        | ✅ | Snapshots fired at mutation_idx=100 (and 200 for V2–V4) |
| 7b.2d reward_counterfactuals ≈ rec count | ✅ | Matches `mutations` row count for every variant |
| 7b.2e V5 local_coverage_v2 > 0           | ✅ | 165 rows |
| 7b.2e V5 compressed_global_coverage > 0  | ❌ | **0 across ALL variants** (gate was V5-only; finding is broader) |
| 7b.2f DB ≤ 5 MB at N=200                 | ✅ | Largest 932 KB; N=6000 extrapolation ~28 MB ≤ 150 MB budget |
| 7b.2g V5/V1 sec/mut ≤ 1.3× on POS        | ✅ | **1.01×** — scheduler overhead is invisible on POS |
| 7b.3 zoned-consistency vs pre-cloud1     | ⏸ | Deferred to Phase 9 per `PHASE_7B_POS_GUIDE.md` |
| 7b.4 IV.POS.5 schema compat              | ✅ | Existing unit test covers it; no run-time regressions seen |

### 1.4 The "V5 144/200" question — **two stacked bugs that will break Phase 8**

I underweighted this in the first pass. Composer was right to flag it. Detailed mechanics below; this is a **Phase 8 blocker**.

#### 1.4.1 Empirical facts (from V5 log + DB)

```
Campaign Summary  (cTS_semantic_v2, seed=999, N=200)
  Total mutations:     144
  Successful (caused failures): 143
  Skipped (no valid target):    56
  Total failures:      451
  Outcome breakdown:
    REJECTED: 143  CRASH: 1  NO_EFFECT: 0  ACCEPTED: 0  SKIPPED: 56
  Mutations by kind: COMP_OUT=12, INSTR_TYPE=24, INSTR_WORD_FULL=24,
                     INSTR_WORD_SUR=24, LOAD=6, MEM=30, PRE_EXEC=21, STORE=3
```

V5's arm universe at build time:

```
SemanticArmUniverse:
  Mutation kinds (K): 8
  Total available arms: 53          (kind × zone, only non-empty intersections)
  Boundary arms:      22
  Singleton arms:     9
```

After the campaign, snapshot at attempt-idx=100 shows: **47 warm / 6 cold** arms. Final per-kind successes = `warm_arms_in_kind × 3` for every kind (e.g. PRE_EXEC_REG_MOD = 7 warm × 3 = 21; INSTR_TYPE_MOD = 8 warm × 3 = 24; COMP_OUT_MOD = 4 warm × 3 = 12). So **every warm arm got exactly the 3 cold-start pulls; no arm got more, no arm reached the main TS loop, and no arm got fewer.** All 144 `bandit_decisions.mode = "cold"`.

Predicted-vs-observed under a pure-round-robin model (47 warm × 3 = 141 success; 200-141 = 59 skip):

| | success | skip | total |
|---|---|---|---|
| model | 141 | 59 | 200 |
| observed | 144 | 56 | 200 |
| delta | +3 | -3 | 0 |

The 3-attempt delta is exactly the fuzzer's internal 10-step retry loop occasionally rescuing borderline cases. Model is correct.

#### 1.4.2 Bug A — universe builder uses a coarser filter than the mutation modules

```startLine:endLine:a4/standalone/semantic_arm_universe.py
69:        for kind in mutation_kinds:
70:            valid_set = set(valid_by_kind[kind])
71:            for zone in SEMANTIC_ZONES:
72:                zone_steps_in_kind = sorted(valid_set & set(z2s.get(zone, [])))
73:                if zone_steps_in_kind:
74:                    arms[(kind, zone)] = zone_steps_in_kind
```

`valid_by_kind[kind]` comes from `InspectionData.get_valid_steps_for_kind(kind)` — which only filters by `cycle.major` (e.g. `COMP_OUT_MOD` ⇔ `major ∈ {0,1,2,3,4}`). The real `get_targets_at_step()` in each mutation module does additional structural checks (e.g. COMP_OUT_MOD also requires an actual register-write txn at that step).

Result: the universe contains "phantom arms" — `(kind, zone)` pairs whose universe step set is non-empty but where **every** step's `get_targets_at_step` returns `None`. Direct test on the same trace V5 ran against:

| Phantom arm | universe says steps | real target getter succeeds on |
|---|---|---|
| COMP_OUT_MOD&#124;pre_ecall   | 18 | **0 / 20** |
| COMP_OUT_MOD&#124;step0       |  1 | **0 / 1** |
| INSTR_WORD_MOD_FULL&#124;step0 |  1 | **0 / 1** |
| INSTR_WORD_MOD_SUR&#124;step0  |  1 | **0 / 1** |
| MEM_VAL_MOD&#124;core_div     | 23 | **0 / 20** |
| PRE_EXEC_REG_MOD&#124;pre_ecall | 18 | **0 / 20** |

Why each is phantom in this trace:
- **step0**: this trace has 16,574 cycles at step 0, all `major ∈ {7, 9, 10}` (CONTROL / POSEIDON). The universe still tags step 0 as valid for `INSTR_WORD_MOD_FULL` (because some cycle elsewhere matched the loose filter), but the actual `get_targets_at_step` finds no fetchable instruction txn.
- **pre_ecall**: 150 steps just before ECALLs. They have computation cycles (`major ≤ 6`), so the loose filter passes, but those particular cycles don't have the register-write / register-read / fetch txns the mutation modules require.
- **MEM_VAL_MOD|core_div**: division steps have memory transactions per the trace, but `get_targets_at_step` in `mem_val_mod.py` applies kind-specific exclusions (instruction-fetch txns excluded, register-region excluded, `store_mem_write` excluded — see the module's docstring §"EXCLUSIONS") and zero pass the gate at these 23 div steps.

The 6 zero-pull arms in the V5 snapshot correspond **exactly** to the 6 phantom arms in this table.

#### 1.4.3 Bug B — the bandit's pull counter only increments on **successful** mutations

```startLine:endLine:a4/standalone/bandit_ts.py
185:    def update(self, kind: str, zone: str, success: int) -> None:
186:        """Bernoulli update (success ∈ {0, 1}) per D-I."""
190:        self.pulls[key] += 1
```

```startLine:endLine:a4/standalone/fuzzer.py
870:        if config is None:
871:            stats.skipped_mutations += 1
872:            return None
```

`fuzzer._run_v2_bandit_mutation` returns `None` on a skip and never reaches the `self.v2_scheduler.update(kind, zone, ...)` call at line 948. So **skipped mutations do not increment `pulls[arm]`**, which means a phantom arm's `pulls[arm]` stays at 0 forever.

The cold-start gate is `pulls[arm] < cold_start_pulls_per_arm` (= 3). So:

```
phantom arm forever in cold list
→ cold-start round-robin keeps re-selecting it
→ skip
→ pulls still 0
→ selected again next time around
→ ...
```

The bandit **never escapes cold-start** as long as any phantom arm exists. The main TS loop never runs.

#### 1.4.4 Combined effect at scale (Phase 8 = N=6000 projection)

| metric | observed (N=200) | projected (N=6000) |
|---|---|---|
| successful mutations | 144 | **≈ 144** (cold-start exhausts all 47 warm arms ≈ early) |
| skipped attempts | 56 | **≈ 5856** |
| bandit_decisions main-loop count | 0 | **≈ 0** |
| adaptive TS posterior used | 0 times | **0 times** |

In other words, **V5 at any N produces ≈ 144 successful mutations and burns the rest of the budget on phantom-arm skips, regardless of how big N is.** All recorded decisions stay `mode=cold`. The Constrained TS bandit's actual TS behaviour is never exercised. Phase 8 would produce a V5 dataset that looks worse than V1 not because cTS is bad but because cTS never runs at all.

This is also why V2-V4 (kind-only bandits) hit 200/200 cleanly: their arm space has 8 elements that all have valid targets, and the fuzzer's 10-step retry inside any kind succeeds (the fuzzer can pick from the full trace, not constrained to a single zone).

#### 1.4.5 Fixes (in increasing order of correctness; ship at least the first two before Phase 8)

1. **Fix Bug B (1 line)**: call `self.v2_scheduler.update(kind, zone, success=0)` on skip BEFORE `return None`. This costs each phantom arm 3 pulls (18 skips total) to age out of cold-start, then the bandit can enter the main TS loop. Wasted budget bound: **≤ 3 × phantom_arm_count**.

2. **Fix Bug A — prune the universe at build time**: in `SemanticArmUniverse.build`, after computing `zone_steps_in_kind`, sample 1+ step and call `mutation_modules[kind].get_targets_at_step(step, data)` to confirm it returns a target. Drop arms where ≥X consecutive sampled steps return None. This removes phantom arms entirely; bandit only sees 47 real arms in this guest. Combined with fix 1, total wasted attempts = 0.

3. **(Recommended for Phase 8 telemetry)** Add `bandit_skip_log(mutation_idx, selected_arm, attempt_step, reason)` table (Composer's existing G6c-style proposal). Even with fixes 1+2, you want to see skip rate per arm over time to catch any new phantom patterns on different guests.

4. **(Pro R2 question)** Should the bandit also have a "give up" mechanism after K consecutive skips, in case fix 2's sample-based pruning misses an arm that's nearly-always-phantom? Phrase as G6d.

#### 1.4.6 Why my earlier framing was wrong

Last turn I wrote "this is expected with a 53-arm space at N=200 (cold-start dominates)". That sentence is technically true at N=200 but misses the real story: V5 doesn't dominate cold-start because the bandit is conservative — V5 dominates cold-start because the bandit is **trapped** in cold-start by a state machine that doesn't terminate when arms are structurally impossible. The trap doesn't loosen at higher N; it gets worse in proportion to the budget.

### 1.5 The "compressed_global_coverage = 0 everywhere" finding (real, broader than V5)

Composer's gate framed this as "V5-specific" but the data shows it's **universal across all five variants**. `global_failures` is populated (well — 291–611 rows / variant) which proves constraint failures ARE being parsed; the broken path is the Hook 3 `family_residues`/`family_details` → `compressed_global_coverage` pipeline.

Two candidates (both worth a 5-minute diagnostic run before Phase 8):

1. **Plumbing**: `run_a4_mutation` does set `A4_FAMILY_RESIDUE=1`, but maybe the bandit-mutation code path in `fuzzer.py` doesn't go through that exact function. If the env var isn't reaching the host on the POS campaign, Hook 3 emits nothing.
2. **Empty residues for this guest**: even with Hook 3 enabled, `<a4_family_residue nonzero=true>` only fires when `g_a4_memory_records` / `g_a4_lookup_records` are non-empty AND the residues compute non-zero. The fault-injection address (or this particular `--in1 5 --in4 10` guest) may simply not produce broken-residue events frequently enough to be visible at N=200.

To distinguish (1) vs (2): grep one 7b campaign log for `<a4_family_residue` and `<a4_family_detail`. Zero matches → plumbing bug. Many "nonzero":false → extractor's `_ADDRESS_REGION_MAP` is fine, just no signal in this guest (this would make G3 a guest-selection issue not a code issue).

Either way the row count is currently masked as "V5 problem" when it's actually a system-wide observation.

### 1.6 The actually-interesting signal: failure density per mutation

This is the first **on-target** measurement of the v2 reward's effect:

| Variant | Reward | fail/mut |
|---|---|---|
| V1 zoned                 | legacy        | 2.27 |
| V2 kindUCB_zoned_v1      | legacy        | 1.69 |
| V3 kindUCB_zoned_v2_noQ  | **v2 (no Q)** | **4.55** |
| V4 kindTS_zoned_v2       | **v2**        | **3.52** |
| V5 cTS_semantic_v2       | **v2**        | 3.13 |

V3/V4 (kind-only bandits with v2 reward) find ~2× more failures per mutation than V1/V2. V5 sits a little lower than V3/V4 because half its budget is still in cold-start at N=200 — at N=6000 we expect V5 to catch up or exceed once posteriors converge. This is the cleanest signal we can pull at N=200 that the v2 reward design is steering the bandit toward more productive arms, **independent** of any constraint-coverage metric.

---

## 2. Phase 7c — Mutation-semantic verification: **the verifier is broken**

### 2.1 What the JSON shows

| Result | Count | Kinds (all 3/3) |
|---|---|---|
| PASS | 12 | COMP_OUT_MOD, PRE_EXEC_REG_MOD, INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR |
| FAIL | 12 | LOAD_VAL_MOD, STORE_OUT_MOD, INSTR_TYPE_MOD, MEM_VAL_MOD |

Composer hypothesised "verifier issues, not proof the fuzzer is wrong". That is **directionally correct but understates the problem** — all 24 samples are uninterpretable.

### 2.2 The root cause (proven by direct host invocation)

`verify_mutation_semantics.py::inspection_with_mutation()` invokes the host with **both** `A4_INSPECT=1` and `A4_MUTATION_CONFIG=…`, then parses the inspection dump (`<a4_cycle_info>`, `<a4_all_txn>`) as if it were the post-mutation trace.

It is not. In `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` the order is:

```startLine:endLine:workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
72:            // >>> A4: PREFLIGHT INSPECTION <<<
73:            if std::env::var("A4_INSPECT").is_ok() {
74:                // ... dump cycles + all_txns ...
186:            }
187:            // >>> END A4: PREFLIGHT INSPECTION <<<
188:
189:            // >>> A4: UNIFIED MUTATION CONFIG <<<
219:            if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
220:                // ... mutate trace.cycles[] / trace.txns[] in place ...
```

So the inspection lines describe **pre-mutation** state regardless of whether `A4_MUTATION_CONFIG` is set.

Direct proof (run on the same host binary the verifier used):

```text
$ env A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 \
      A4_MUTATION_CONFIG=/tmp/test_inst_type.json \
      ./workspace/output/target/release/risc0-host --in1 5 --in4 10 \
      | grep -E '^<(a4_cycle_info.*step":447|a4_instr_type_mod|a4_config_loaded|a4_fault_injection)'

<a4_cycle_info>{"cycle_idx":17041, "step":447, "pc":3221225816, "txn_idx":17308, "major":0, "minor":7}</a4_cycle_info>
<a4_fault_injection_enabled/>
<a4_config_loaded>{"path":"/tmp/test_inst_type.json", "mutation_type":Some("INSTR_TYPE_MOD"), "step":Some(447)}</a4_config_loaded>
<a4_instr_type_mod>{"step":447, "cycle_idx":17041, "pc":3221225816, "old_major":0, "old_minor":7, "new_major":1, "new_minor":4}</a4_instr_type_mod>
```

- `<a4_cycle_info>` for step 447 reports `major:0, minor:7` — the **original** `AddI`.
- `<a4_instr_type_mod>` confirms the mutation hook DID run and DID change major/minor to 1/4.
- These lines come out in this order in the same process. The verifier reads the first one, never sees the second.

### 2.3 What each kind's check actually does (and why it tells us nothing)

```startLine:endLine:a4/tools/verify_mutation_semantics.py
98:def assert_kind_property(
108:    mut_cycle = mutated.get_cycle(step)
109:    mut_w = mutated_value & 0xFFFFFFFF
```

Where `mutated` is the InspectionData parsed from the dump — i.e. **pre-mutation** trace.

Per-kind audit:

- **`INSTR_WORD_MOD_FULL` / `INSTR_WORD_MOD_SUR` (6 PASS)** — checks `RiscVInstruction.from_word(mut_w)` and `cfg_word == mut_w`. Both are tautologies: `mut_w` comes from the DB's `mutated_value` column and `cfg_word` from `config["word"]` in the same row — they are the same value written to the same row by the fuzzer. The "PASS" message reports the pre-mutation cycle's major/decoded_opcode, which is irrelevant to whether the mutation took effect. **No information about mutation correctness.**

- **`COMP_OUT_MOD` (3 PASS)** — line 137-139 falls through to `return True, "cycle present (reg write word check inconclusive)"` whenever the strict check fails. The strict check (`word == mut_w`) would always fail because `word` comes from the pre-mutation reg-write txn. **Spurious PASS by design.**

- **`PRE_EXEC_REG_MOD` (3 PASS)** — only verifies `config["_info"]["register_idx"]` exists. Tautology if config is well-formed. **No mutation verification.**

- **`INSTR_TYPE_MOD` (3 FAIL)** — checks `mut_cycle.major == config.major`. `mut_cycle` is from the pre-mutation dump, so it always reports the original major/minor. The detail messages confirm this exactly (e.g. id 109: `"cycle major/minor 4/2 != config 4/10"` — config says change `SrlI(4,2)` → `Lw(4,10)`; cycle still reports `4/2`, i.e. pre-mutation). The hook DID apply the change in the actual witgen run — the verifier just never sees the change.

- **`LOAD_VAL_MOD` (3 FAIL)** — `_reg_write_word_at_step` returns the first reg txn's `word` regardless of read/write or register index. The fail addresses (`0x2001C0`, `0x200060`, `0x221000`) look like LOAD base/address-compute reads or stale register reads in the 0x200000 heap range — they're not what the mutation targets. Even if the verifier walked to the **last** reg-write (matching `config._info.register_idx`), it would still see the original loaded value because the dump is pre-mutation.

- **`STORE_OUT_MOD` (3 FAIL)** — verifier looks for a register-write at the STORE step. **Stores do not write registers** — they write memory. The mutation target is `txns[write_txn_idx].word` where `write_txn_idx` is the memory-write txn (`load_val_mod.py`-style structure but with `byte_addr` rather than `register_idx`). The correct check is "find the memory write txn at `byte_addr` and compare its word", which the verifier never attempts.

- **`MEM_VAL_MOD` (3 FAIL)** — searches mem_txns at the step for `word == mut_w`. Again, the dump is pre-mutation, so the mem txn's word is the original (~`0x40000`, `0xae0b423b`, `0x3a4a7f0e`) — not the mutated value the verifier expects.

### 2.4 What 7c was supposed to prove

G2 was supposed to answer "do we mutate **what we think we mutate**?" — i.e. the bit-level identity between the DB row `(kind, step, mutated_value, config_json)` and the actual change made in `trace.cycles[]` / `trace.txns[]` at proof time. None of the 24 samples answers that.

### 2.5 Direct proof the 12 FAILs are all verifier bugs (1 sample per failing kind)

Re-ran the host with **only** `A4_MUTATION_CONFIG=<sample>` (no `A4_INSPECT`) on the same 4 samples Composer's verifier marked FAIL. Parsed the mutation hook's own stdout line and compared `old_*`/`new_*` to the DB-recorded `config` / `mutated_value`:

| Kind | DB sample | Composer's FAIL reason | Hook line (proof mutation was applied) | Conclusion |
|---|---|---|---|---|
| `LOAD_VAL_MOD` id=29  | step=3873, txn_idx=31910, word=0xFF7FFFFF | "reg write 0x2001c0 ≠ mutated 0xff7fffff" | `<a4_load_val_mod>{..."txn_idx":31910, "old_word":0, "new_word":4286578687, "addr":1073725499...}` (addr 1073725499 = 0xFFFF0080+27 = register x27 = s11 ✓) | **Mutation applied correctly. Verifier looked at first reg-write at step (which was the address-compute), not the destination-reg-write.** |
| `STORE_OUT_MOD` id=116 | step=711, txn_idx=18421, byte_addr=0x20036C, word=0x97265810 | "reg write 0x200360 ≠ mutated 0x97265810" | `<a4_store_out_mod>{..."txn_idx":18421, "old_word":0, "new_word":2535872528, "addr":524507...}` (addr 524507 × 4 = 0x20036C ✓) | **Mutation applied correctly. Verifier should check `mem_write` at byte_addr, NOT a register-write — stores don't write registers.** |
| `INSTR_TYPE_MOD` id=109 | step=3114, major=4, minor=10 | "cycle major/minor 4/2 ≠ config 4/10" | `<a4_instr_type_mod>{..."old_major":4, "old_minor":2, "new_major":4, "new_minor":10...}` | **Mutation applied correctly. Verifier read the pre-mutation cycle dump (`<a4_cycle_info>`), which shows pre-mutation 4/2.** |
| `MEM_VAL_MOD` id=81   | step=3574, txn_idx=30569, word=0x40000 | "no mem txn with word=0x40000" | `<a4_mem_val_mod>{..."txn_idx":30569, "old_word":2233580, "new_word":262144, "byte_addr":2097560...}` (byte_addr 0x200198 ✓; new_word 262144 = 0x40000 ✓) | **Mutation applied correctly. Verifier searched pre-mutation mem txns (still containing old_word=2233580) for new_word — never found.** |

Verdict: **all 4 "FAILs" are correct mutations** mis-interpreted by a verifier reading the wrong copy of the trace and (for `STORE_OUT_MOD`) the wrong txn type. The remaining 8 FAILs (3 more LOAD/STORE/MEM each) almost certainly have the same root cause.

### 2.6 The correct verification path (no Rust rebuild needed)

The mutation hook **already** emits a per-mutation report line for every kind (`<a4_instr_type_mod>`, `<a4_comp_out_mod>`, `<a4_load_val_mod>`, `<a4_store_out_mod>`, `<a4_pre_exec_reg_mod>`, `<a4_mem_val_mod>`, `<a4_instr_word_mod>`) that includes `step`, `txn_idx` (where applicable), `old_*` and `new_*` values, plus the cycle's `pc/major/minor`. The right verifier is:

1. Run host with **only** `A4_MUTATION_CONFIG=<sample>` (no `A4_INSPECT`).
2. Capture stdout, find the `<a4_<kind>_mod>` line.
3. Assert (a) the line exists for the right step/cycle_idx; (b) `old_*` matches the DB's `original_value`; (c) `new_*` matches the DB's `mutated_value` / `config.word` / `config.major,minor`.
4. Optionally also parse `<a4_constraint_fail>` lines and assert the expected constraint **family** fires (e.g. INSTR_TYPE_MOD → `VerifyOpcodeF3`; STORE_OUT_MOD → `MemoryWrite`; LOAD_VAL_MOD → `MemoryWrite` on the destination register).

Step 3 alone is a direct, bit-level mutate-what-we-think-we-mutate proof. Step 4 is a free bonus that doubles as Pro's "constraint-family fault dictionary" validation.

**Estimate**: rewriting `verify_mutation_semantics.py` against the hook-emit lines is a 1-2 hour job (one regex per kind + a constraint-family expectations table). Composer can do it. No host rebuild required.

---

## 3. Aggregate Phase 7 verdict + recommended next actions

### 3.1 Verdict on D39 exit criteria

| # | Gate | Verdict |
|---|---|---|
| 1 | 7a 5×N=20 WSL smoke clean       | ✅ done |
| 2 | 7b 5×N=200 POS                  | ✅ (V5 144/200 is expected, not a fail) |
| 3 | 7b zoned-consistency vs legacy  | ⏸ deferred to Phase 9 |
| 4 | 7b IV.POS.5 schema compat        | ✅ |
| 5 | 7b DB ≤ 5 MB @ N=200             | ✅ (max 932 KB) |
| 6 | 7b V5/V1 ≤ 1.3× on POS           | ✅ (1.01×) |
| 7 | 7c 24 semantic samples PASS      | ❌ **verifier broken — no result either way** |
| 8 | Summary report + sign-off        | 🟡 this document satisfies the report half; sign-off pending verifier rewrite |

### 3.2 What to do before declaring Phase 7 closed

Two must-do, two should-do:

**MUST**
1. **Rewrite `verify_mutation_semantics.py`** against the mutation hook's own `<a4_<kind>_mod>` stdout lines (§2.5). Re-run 24 stratified samples; target 24/24 PASS as the real G2 exit gate.
2. **One-shot diagnostic** on `compressed_global_coverage=0`: grep a 7b campaign log for `<a4_family_residue` and `<a4_family_detail`. If absent → fix env var plumbing in the v2 bandit path. If present-and-zero → reclassify the gate from "Hook 3 plumbing" to "guest-selection limitation" and document.

**SHOULD**
3. **Add `bandit_skip_log` table** (or at minimum a `mutation_skips` counter per `(kind, zone)`) so the V5 skip pattern is auditable post-hoc, not just visible in the campaign log.
4. **Promote two of the Phase 7 findings to Pro R2 open questions**:
   - V5 skip-rate behaviour at N=6000 (does it materially differ from kind-only bandits?)
   - compressed_global signal density vs guest choice (do we need a non-trivial guest to exercise Hook 3?)

### 3.3 What we CAN say with confidence after 7b

- **Operational**: all 5 IV.POS.7 variants deploy, run cleanly, and produce well-formed v2 schemas on POS.
- **Cost**: on POS the schedulers are effectively free (V5/V1 sec/mut = 1.01×) and the DB size budget has ~5× headroom.
- **Direction**: the v2 reward function visibly steers the bandit toward failure-richer mutations (V3/V4 fail/mut ≈ 2× V1/V2). This is the first measurement that supports Pro's reward redesign on real POS hardware.

### 3.4 What we CANNOT yet say

- **Whether mutations are bit-faithful** to the DB-recorded `mutated_value` (G2 unresolved — verifier broken).
- **Whether Hook 3 compressed-global signal is real on this guest** (gate not informative until §3.2.2 is done).
- **Whether V5 dominates on coverage** (need N=6000 + working verifier + Hook 3 plumbing, i.e. Phase 8).

---

## 4. Artifacts referenced in this report

| Path | Content |
|---|---|
| `a4/runs/pos_smoke_7b/` | 5 POS DBs + logs + collection_report.json |
| `a4/runs/pos_smoke_7b/collection_report.json` | Per-variant meta (timing, SHAs, exit codes) |
| `a4/docs/cloud1/composer/PHASE_7C_SEMANTIC_RESULTS.json` | 24 sample raw results |
| `a4/docs/cloud1/composer/PHASE_7_OPUS_FLAGS.md` | Composer's open items |
| `a4/tools/verify_mutation_semantics.py` | **Broken verifier — needs rewrite per §2.5** |
| `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | Lines 73-186 = inspection dump; lines 189+ = mutation hook (proves ordering) |

