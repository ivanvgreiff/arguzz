# Phase 7d — Architecture Audit (Pre-Phase-8 Hard Gate)

**Status:** ACTIVE (Inc 3 CLOSED 2026-06-12; Inc 4 / 5 pending; **Phase 8 LAUNCH AUTHORIZED with default parallelism per user override 2026-06-13** — Pro consult to follow)
**Replaces:** old Phase 7c (single verifier) as the gate to Phase 8.
**Blocks:** Phase 8 IV.POS.7 — was previously fully blocking; **user override (2026-06-13) lifts the block** so that the 5 variants can be tested with parallel processing for speed, and results + race writeup are presented to Pro jointly.

> **STANDING NOTE ADDED 2026-06-13 — race phenomenon & data preservation.** The B7 seed-reproducibility audit (Inc 3) discovered a ~0.7% per-mutation `delta_T` noise floor under default parallelism (~5× reduction under `RAYON_NUM_THREADS=1`). Full investigation in [`a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md`](../RACE_FINDING_AND_OPEN_QUESTIONS.md); G7 in [`CLOUD1_DECISIONS_FOR_PRO_R2.md`](../CLOUD1_DECISIONS_FOR_PRO_R2.md). **Master-plan items:**
> 1. **All Phase 7d Inc 3 audit DBs and logs** (`a4/audits/audit_output/inc3d/`) **MUST be preserved** indefinitely so we don't have to re-run experiments if Pro recommends revisiting the race.
> 2. **All Phase 7d Inc 3 markdowns** (`a4/docs/cloud1/composer/PHASE_7D_INC3*.md`, `PHASE_7D_INC3D_*.md`) **MUST be preserved** as the canonical record of the race investigation.
> 3. **Granular B1/B2/B3/B5 patch recovery is DEFERRED** unless Pro recommends revisiting. Recovery costs ~2 hours from `risc0-modified.CURRENT.patch` + patch-spec docs. The current binary works for Phase 8.
> 4. **The `workspace/risc0-modified` submodule SHOULD be git-tracked on a private branch** (procedure in `PHASE_7D_INC3_FINAL_REPORT.md` §8) so a future WSL wipe cannot lose work again.
> 5. **Source recovery (late 2026-06-13)**: 5 core A4-hooked submodule files (`ffi.cpp`, `steps.cpp`, `witgen.h`, `hal/mod.rs`, `witgen/mod.rs`) were wiped along with the docs and have been **recovered byte-identically to June 3 state** from `/root/arguzz_backups/risc0-modified.CURRENT.patch`. Full verification: 58/58 patched files match June 3 state byte-for-byte after restoration (zero post-June-3 changes lost for the 53 surviving files). Pre-recovery safety backup: `/root/arguzz_backups/pre_recovery_20260612_232446/`. **Primary-source verification** of `A4_COVERAGE_TOUCH=1 → SeqForward` gating (hal/mod.rs:149) and sequential dispatch (ffi.cpp:401) is now possible; the previously-secondary-source claims in `RACE_FINDING_AND_OPEN_QUESTIONS.md` are confirmed and the doc has been updated to note that poolstl is *less plausible* as the residual-race source than previously suggested (since witgen/accum are bypassed in poolstl path under `A4_COVERAGE_TOUCH=1`).

---

## 0. Why this exists (read this first)

Phase 7b/7c showed us we cannot trust a single verifier or a single smoke
campaign. The bandit / arm-universe / hook stack has too many independent
moving parts for any one check to give us "100% confidence." Phase 7d breaks
the question

> "is our new V5 cTS_semantic_v2 architecture actually doing what we claim
> for every variant, every mutation kind, every semantic zone?"

into **12 mechanical audits**, each of which proves ONE specific architectural
invariant and exits non-zero on violation. Together they form an inductive
chain from "the host's inspection dump is deterministic" up to "the bandit's
arm selection is what actually got executed and rewarded."

If any audit fails, the corresponding invariant is broken and Phase 8 results
on top of it would be uninterpretable.

The 12 audits are organized into two sub-phases that **must** be run in order:

| Sub-phase | Focus | Question it answers |
|---|---|---|
| **7d.1** (audits A1–A5) | Semantics & arm integrity | Are the arms and zones the bandit pulls from a true reflection of what's in the trace? |
| **7d.2** (audits B1–B11, plus B12 best-effort) | Variant correctness & isolation | Does each variant (V1–V5) actually execute only/exactly what its strategy claims? |

7d.1 must be all-green BEFORE 7d.2 starts. There is no point verifying
variants on top of a broken arm space.

> Read this document end-to-end before touching code. Each audit has the
> shape: `Goal → Why it matters → Acceptance gate → Script name → Expected
> output → Failure mode handling`.

---

## 1. Sub-phase 7d.1 — Semantics & arm integrity

### A1 — Trace determinism

**Goal:** the host's inspection dump (`A4_INSPECT=1 A4_DUMP_ALL_TXNS=1`) must
produce a byte-identical *architectural* trace across repeated runs.

**Why it matters:** we build the arm universe ONCE per campaign from the
baseline inspection. If the dump is non-deterministic in any field we depend
on (cycle structure, register transactions, addresses, txn ordering), then
the arm we select against the baseline is not the arm that runs during
mutation. Everything downstream silently lies.

**Acceptance gate:**
- For 3 independent host runs with the same args:
  - `data.cycles` (cycle_idx, step, pc, major, minor, txn_idx) → 100% identical across all 3 runs.
  - `data.all_txns` filtered to `txn_type == "reg"` → 100% identical.
  - `data.all_txns` filtered to `txn_type == "mem"` → ≥99.0% identical. Permitted variance: addresses in two host-controlled regions:
    - `HOST_ECALL_ADDR` region (`0x42000000` … `0x42000100`)
    - User journal/IO buffer region (per-guest; defined by audit, not hard-coded)
  - Documented bounded-variance addresses are listed in `audit_output/A1_nondet_addrs.json` and **must be filtered out at MEM_VAL_MOD target collection time** (see D42 below).

**Script:** `a4/audits/A1_trace_determinism.py` (Opus pre-implements; Composer extends with auto-update of non-det allow-list).

**Pre-run baseline numbers (sha2-host, --in1 5 --in4 10):**

| metric | value |
|---|---|
| cycles | 32768 (100% deterministic) |
| reg txns | 8780/8780 deterministic |
| mem txns | 25756/25944 deterministic (99.28%) |
| varying addrs | 188 unique, all at step 170 (4) + step 3929 (184) |
| address regions | `0x000884e6+` (4) — guest journal buffer; `0x41ffbbe0+` (184) — HOST_ECALL_ADDR region |

**Failure handling:**
- If cycle structure or reg txns differ: STOP. This is a foundational bug in
  the host inspection plumbing. Open a separate investigation issue; do not
  patch around it.
- If mem variance > 1% or extends to addresses outside the documented
  regions: investigate; may indicate new guest behavior or an inspection bug.

---

### A2 — Zone classifier semantic correctness

**Goal:** for every zone in `SEMANTIC_ZONES`, every step assigned to that
zone must satisfy the zone's first-principles predicate.

**Why it matters:** the bandit's whole premise in V5 is that `(kind, zone)`
arms cluster *semantically related* steps. If `core_div` actually contains
some `core_arithmetic` steps (because the classifier is buggy), then a
bandit pull "from core_div" is not actually exploring division-related
mutation behavior, and our rewards lie about what zone they came from.

**Per-zone predicates (exact):**

| zone | predicate that every step in the zone must satisfy |
|---|---|
| `step0` | step == 0 |
| `last_step` | step == `data.total_steps - 1` |
| `pre_ecall` | `ECALL_MAJOR=8` is in the major-set of the step's cycles (OR the step is the singleton step0/last_step, in which case the singleton zone wins) |
| `post_ecall` | step - 1 contains an ECALL cycle |
| `pre_mret` | (NOT YET IMPLEMENTED — empty for IV.POS.7) |
| `post_mret` | (NOT YET IMPLEMENTED) |
| `pre_halt` | (NOT YET IMPLEMENTED) |
| `post_halt` | (NOT YET IMPLEMENTED) |
| `core_arithmetic` | step has at least one cycle with major ∈ {0, 1, 2} |
| `core_mul` | major ∈ {3} present in step's cycles |
| `core_div` | major ∈ {4} present |
| `core_memory_load` | major ∈ {5} present |
| `core_memory_store` | major ∈ {6} present |
| `core_branch` | major ∈ {7} present (note: includes MRET/JAL/JALR — see classifier docstring) |
| `core_sha` | major ∈ {11} present |
| `core_poseidon` | major ∈ {9, 10} present |
| `core_other` | major ∈ {8, 12} present AND not assigned to a more-specific zone by boundary rules |

**Acceptance gate:**
- Spot-check ≥ 20 random steps per non-empty zone (or all steps if zone has fewer): every step's actual cycles satisfy the predicate above.
- 100% of steps in `data.total_steps` are assigned to exactly one zone.
- Zero overlap: no step belongs to two zones.
- Empty zones are documented (pre_mret/post_mret/pre_halt/post_halt + any guest-specific core zone) but do not count as failures.

**Script:** `a4/audits/A2_zone_classifier_correctness.py` (Opus pre-implements; ports the inline script used above).

**Pre-run baseline numbers (sha2-host, --in1 5 --in4 10):** all 17 zones pass; 3930/3930 steps classified; 0 overlap.

---

### A3 — Per-arm step-list integrity

**Goal:** for every arm `(kind, zone)` in `SemanticArmUniverse.arms`, every
step in `arms[(kind, zone)]` must satisfy BOTH:
1. The step belongs to `zone` (verified by A2 transitively).
2. `_MUTATION_MODULES[kind].get_targets_at_step(step, data)` returns a non-empty target (no phantom steps within real arms).

**Why it matters:** Phase 7 Bug A. Without per-step pruning, an arm's step
list contains "phantom" steps that the kind's mutation module rejects. The
bandit's step sampler picks uniformly from that list, so most pulls of a
sparse arm (e.g. `MEM_VAL_MOD|core_div` had 1/23 real targets pre-fix)
would produce skips and trap the bandit in cold-start. We've already
landed Composer's fix; this audit makes sure it stays landed and works
across guest input variations.

**Acceptance gate:**
- For every arm: `sum(1 for s in arms[(k,z)] if get_targets_at_step(s, data) is not None) == len(arms[(k,z)])`.
- The set of arms DROPPED by phantom pruning is logged and stable across re-runs (allow-list `EXPECTED_DROPPED_ARMS.json`).

**Script:** `a4/audits/A3_arm_step_integrity.py` (Opus pre-implements; reuses logic above).

**Pre-run baseline numbers:** 48 arms, 0 phantom steps within any kept arm, 5 arms dropped:

```
COMP_OUT_MOD|step0, COMP_OUT_MOD|pre_ecall,
INSTR_WORD_MOD_FULL|step0, INSTR_WORD_MOD_SUR|step0,
PRE_EXEC_REG_MOD|pre_ecall
```

---

### A4 — Universe completeness (no missing arms)

**Goal:** for every step `s` and every kind `k`, if
`get_targets_at_step(s, data)` returns a real target AND `s` is in some
zone `z`, then `(k, z) ∈ SemanticArmUniverse.arms` and `s ∈ arms[(k, z)]`.

**Why it matters:** Bug A (phantom arms) is the failure mode "we have arms
the bandit thinks are real but aren't." The DUAL failure is "there are real
(kind, step) opportunities the bandit cannot reach because they're not in
any arm." This audit catches that.

**Acceptance gate:**
- For each kind `k` in `_MUTATION_MODULES`:
  - For each step `s` in `data.total_steps`:
    - If `get_targets_at_step(s, data)` returns truthy AND `s ∈ classify_zones(data)`, then `s` must appear in `arms[(k, classify_zones(data)[s])]`.
- Zero violations.

**Script:** `a4/audits/A4_universe_completeness.py` (Composer implements; ~50 LOC).

**Special-case allow-list:** if a future audit reveals legitimate cases
where a real target should be excluded (e.g., the 188 non-deterministic
mem-txn addresses for MEM_VAL_MOD), document them in
`EXPECTED_EXCLUDED_TARGETS.json` and have the audit honor that list.

---

### A5 — Canonical kind × zone matrix

**Goal:** define a written, version-controlled matrix
(`a4/docs/cloud1/EXPECTED_ARMS.md`) that asserts which `(kind, zone)`
arms should exist for sha2-host with our standard inputs, and verify the
universe builder reproduces it byte-for-byte.

**Why it matters:** A3 and A4 are CIRCULAR — they trust the kind module
and the zone classifier together. If both have correlated bugs (e.g., both
agree that a step is "core_div" but it's actually `core_branch`), the
audits will pass and we'll never know. The canonical matrix is the
non-circular ground truth: someone looked at the trace by hand and wrote
down what arms SHOULD exist.

**Acceptance gate:**
- `EXPECTED_ARMS.md` lists, for sha2-host @ `--in1 5 --in4 10`, all 48
  expected arms with their expected step-counts (±5% tolerance for the
  step-count to allow minor drift from baseline traces).
- `audits/A5_canonical_match.py` builds the universe and diffs against
  `EXPECTED_ARMS.md`. Zero unexpected/missing arms.
- Re-run with `--in1 1 --in4 1` and `--in1 100 --in4 100`: the EXPECTED
  matrix is *updated* in the doc to enumerate per-input expected arms; the
  audit must pass for all three input variants.

**Script:** `a4/audits/A5_canonical_match.py` (Composer implements after Opus drafts the EXPECTED_ARMS.md skeleton with sha2-host baseline filled in).

**Pre-run baseline:** Opus drafts EXPECTED_ARMS.md from the A3 output above. Composer fills in the other input variants.

---

### A6 / E1 — Independent instruction decoding (semantic ground truth)

**Goal:** for every cycle with `major ∈ {0..7}` (instruction cycles), independently decode the actual instruction word at PC and verify that the trace's `(major, minor)` matches what RV32IM says it should be.

**Why it matters:** A2-A5 trust `cycle.major` to define zones. If `cycle.major` is wrong (e.g., the trace records major=4 but the actual instruction is JAL which should be major=7), the zone classifier puts the step in `core_div` but the step is actually a branch. The bandit pulls "core_div" but is exploring branch behavior. The most catastrophic class of "semantic mismatch" bug. We have never validated this assumption independently.

**Acceptance gate:**
- For ≥ 500 random cycles with major ∈ {0..7}:
  - Read the instruction fetch word from the cycle's fetch transaction (the txn at `cycle.txn_idx` if available, or via `INSTR_WORD_MOD`'s target getter).
  - Decode using `a4/core/insn_decode.py::INSN_KIND_NAMES` (kind = major*8 + minor) and confirm the decoded RV32IM instruction is consistent with the cycle's `(major, minor)`.
  - Zero violations.
- For cycles with major=7 (CONTROL0): the decode reveals whether the cycle is JAL/JALR/BEQ/BNE/BLT/BGE/BLTU/BGEU/MRET. **Emit a per-step classification report** that can be used later to detect MRET steps for D14 follow-up.
- Document any cases where decoding fails (instruction word not present, weird encoding) as known limitations.

**Script:** `a4/audits/E1_instruction_decode.py` (Composer; ~150 LOC). Depends on `a4/core/insn_decode.py` and `a4/standalone/mutations/instr_word_mod.py`.

**Resolves:** Q3 (core_div split?), Q8 (MRET detection), partially Q4.

---

### E6 — post_ecall window evidence (added Inc 1.5; supports D53)

**Goal:** measure empirically what happens at steps `e+1..e+5` after each ECALL in the trace. Captures PC distribution and region (user/kernel/other) to justify D53's redefinition of `post_ecall` as "first user-PC step in [e+1, e+5]" instead of "e+1 only."

**Acceptance gate:**
- All ECALL steps in baseline trace enumerated.
- For each offset (e+1..e+5): PC distribution + region classification reported.
- D53 verdict supported: ≥ 1 ECALL has its first user-PC return at offset > 1 (proves "e+1 only" misses cases).

**Pre-populated output:** `audit_output/E6_post_ecall_window_evidence.json` (Opus generated on baseline trace before Inc 1.5; Composer extends with B12 inputs).

**Status:** PASS (Opus-prepopulated; Composer re-runs after D53 lands to confirm classifier behaves as expected).

### E7 — Kernel-PC contamination survey (added Inc 1.5; supports D54 HYBRID)

**Goal:** measure how much of each "user-code" zone is actually at kernel-PC (`0xC0000000+`). Justifies D54's HYBRID approach (one `kernel_other` zone instead of per-zone splits).

**Acceptance gate:**
- For each zone in the current 17-zone universe: count steps with kernel-PC primary Decode cycle and report kernel %.
- Predicted kernel_other arm size reported.
- D54 verdict supported: at least 3 "core_*" zones have > 5% kernel contamination (validates need for HYBRID).

**Pre-populated output:** `audit_output/E7_kernel_contamination_survey.json` (Opus generated). Findings:
- step0: 100% kernel (singleton — keeps singleton classification via precedence)
- pre_ecall: 100% kernel (by D13 design)
- post_ecall: 56.25% kernel (D53 fixes this)
- core_mul: 34% kernel (significant — D54 reclassifies these)
- core_memory_load: 13.6% kernel

**Status:** PASS (Opus-prepopulated; Composer re-runs after D54 lands to confirm `kernel_other` arm count matches prediction (~357 steps).

### A7 / E3 — Multi-classification probe (open zone-policy questions)

**Goal:** for each "uncertain" arm in EXPECTED_ARMS.md (rows tagged 🟡), produce a per-arm dossier that answers the open question.

**Why it matters:** EXPECTED_ARMS.md lists 22 of 48 arms as 🟡 UNCERTAIN with specific open questions. Without resolving them, A5 must keep a wide ±20% tolerance and we cannot say with confidence that "the arm space is what we think it is" — only "the universe builder produced what we wrote down."

**Acceptance gate:** for each 🟡 arm, the audit emits a JSON report `audit_output/E3_<kind>_<zone>.json`:
- Sample 5-10 steps from the arm.
- For each sample step: list the cycle's (major, minor), the instruction word (if applicable), the txns at that step, and a short manual explanation of why the step IS or ISN'T legitimately in this arm.
- Decision: KEEP (the categorization is correct) / RECLASSIFY (move arm to different zone) / SPLIT (zone should be split into two) / NOOP (mutation produces no semantic effect; consider dropping).
- **Composer + user manually adjudicate each KEEP/RECLASSIFY decision.**
- After adjudication, the arm's status in EXPECTED_ARMS.md flips 🟡 → 🟢 (or arm is updated/removed).

**Script:** `a4/audits/E3_multi_classification_probe.py` (Composer; the script generates the dossiers; the human-in-the-loop part is in `composer/PHASE_7D_E3_REVIEW.md`).

**Resolves:** Q1, Q2, Q5, partially Q4.

---

### 7d.1 EXIT GATE

All of A1, A2, A3, A4, A5 PLUS E1 and E3 exit 0. Each audit's last line is `=== Ax RESULT: PASS ===` or `=== Ex RESULT: PASS (n arms reviewed, m KEEP, k RECLASSIFY) ===`.

**EXPECTED_ARMS.md status:** zero 🟡 rows remaining (all flipped to 🟢 after E3 review; any RECLASSIFY decisions reflected in the table).

**Then and only then**, 7d.2 begins.

---

## 2. Sub-phase 7d.2 — Variant correctness & isolation

### B1 — Hook fidelity (mutation lands where we say)

**Goal:** for ≥200 stratified mutations per variant (V1, V2, V3, V4, V5),
the mutation hook's emitted line confirms the mutation hit the expected
step AND the expected cycle's pre-mutation old value matches what the
baseline inspection said.

**Why it matters:** Phase 7c rev1 verifier silently skipped the old-value
check on 21/24 word-mutating samples because the DB didn't populate
`original_value`. Phase 7c rev2 verifier passed 24/24 but on closer
inspection it was the same softness. Bug A's INSTR_TYPE_MOD id=12 step=0
case showed the hook applies to a different cycle than the universe
intended at multi-cycle steps. We need an unambiguous, no-skip check.

**Pre-requisites (Composer fixes before B1 runs):**
1. **Verifier strict mode:** change every `if original_value:` short-circuit
   to `if original_value is not None:`. Add
   `hook.old_major/minor == config._info.original_major/minor` check for
   INSTR_TYPE_MOD.
2. **Uniform `original_value` recording:** every `create_config()` in
   `a4/standalone/mutations/*.py` MUST put the pre-mutation value into
   `config["_info"]["original_value"]` (consistent field name). The fuzzer
   additionally writes `mutations.original_value` as a dedicated DB column
   (schema migration test required).
3. **Multi-cycle disambiguation (D40):** see below.

**Acceptance gate:**
- For each variant V ∈ {V1..V5}, sample 200 mutations stratified across all 48 arms (or all of the variant's arms, kind-only for V2-V4, mixed for V1 uniform).
- For each sample:
  - `hook.step == config.step` (no step shift)
  - `hook.old_major == config._info.original_major` (no cycle shift within a step)
  - `hook.old_minor == config._info.original_minor`
  - `hook.old_word == config._info.original_value` for word-mutating kinds
  - `hook.new_word == config.word` (sanity; should never fail)
- Per variant: 200/200 PASS. Any failure dumps the divergence for analysis.

**Script:** `a4/tools/verify_mutation_semantics.py` (rewrite by Composer — supersedes Phase 7c v2 with strict mode + D40 awareness).

---

### B2 — Multi-cycle step disambiguation (D40 verification)

**Goal:** confirm that D40 (decision below — drop multi-cycle steps from
universe OR plumb cycle_idx through the hook) actually fixes the
INSTR_TYPE_MOD id=12 step=0 class of bug.

**Why it matters:** observed in Phase 7c rev2 — hook.old=7/0 ECALL but
config.exp_old=2/6 AddI. Verifier didn't catch because it never compared.
B1's strict mode WILL catch it now, but the underlying fix needs an explicit audit.

**Decision D40 candidates (Composer picks; documents in CLOUD1_DECISIONS_FOR_PRO_R2.md):**

- **(a) Plumb `cycle_idx` in mutation config** — the config schema gains a
  `cycle_idx` field that the hook in `mod.rs` uses to disambiguate which
  cycle within the step to mutate. Most precise. Requires Rust rebuild.
- **(b) Drop steps with multiple kind-matching cycles from the universe**
  — `_step_has_real_target` returns false for any step where multiple
  cycles match the kind's filter. Cleaner. Lose a small number of arms
  (step 0 mostly).

Preference: **(b)** unless it drops > 4 arms on the sha2-host trace. If
(b) drops too much, do (a).

**Acceptance gate:**
- D40 decision is documented.
- After fix, B1 produces 200/200 PASS for INSTR_TYPE_MOD across all variants.
- An additional `b2_specific_replay.py` script re-runs the original
  INSTR_TYPE_MOD id=12 step=0 case (from Phase 7c rev2) and confirms it
  now PASSES with the strict verifier.

**Script:** `a4/audits/B2_multicycle_replay.py` (Composer).

---

### B3 — Bandit math correctness (property-based)

**Goal:** verify each scheduler class implements its mathematical claim
correctly using property-based tests.

**Why it matters:** if the Beta posterior is wrong, or UCB1's exploration
bonus is mis-scaled, V5 might be sub-optimal not because the architecture
is wrong but because the math has a bug. We have unit tests
(`tests/test_bandit_ts.py`) but no property-based coverage of edge cases.

**Acceptance gate (4 property tests per scheduler):**

| Scheduler | Property test |
|---|---|
| `ConstrainedTSScheduler` | (1) `update(arm, 1)` increments alpha by 1, beta unchanged; (2) `update(arm, 0)` increments beta by 1; (3) `pulls[arm]` increments on every update; (4) when ANY arm has pulls < `cold_start_pulls_per_arm`, select() returns mode='cold' (round-robin) |
| `KindLevelUCBScheduler` | (1) UCB1 score = mean + sqrt(2 ln N / n_i) within floating-point tolerance; (2) untried arm always preferred to tried; (3) score monotonic in mean (with all else equal); (4) score monotonic in N (with same n_i) |
| `KindLevelTSScheduler` | (1)-(3) same as ConstrainedTS without the cold-start RR; (4) sample lies in [0,1] |

**Script:** `a4/standalone/tests/test_bandit_property.py` (Composer
extends; ~120 LOC).

---

### B4 — End-to-end bandit → DB traceability

**Goal:** for an N=50 instrumented smoke per variant, prove that the
(kind, [zone,] step) tuple emitted by the bandit equals the one executed
equals the one recorded in `mutations` equals the one in the hook output
equals the one the reward was attributed to.

**Why it matters:** off-by-one, swap, or shadow bugs anywhere in
`_run_v2_bandit_mutation` would produce a reward attributed to the wrong
arm. The bandit's learning then trains on a fiction. This audit is the
sole audit that pins down that no such bug exists.

**Acceptance gate:** for each of 50 mutations × 5 variants × 3 input
variants = 750 mutations:

| column | source |
|---|---|
| `bandit_kind`, `bandit_zone`, `bandit_step` | logged immediately after `v2_scheduler.select()` |
| `executed_kind`, `executed_step` | logged immediately after `_create_mutation()` |
| `db_kind`, `db_step` | `mutations` row |
| `hook_kind`, `hook_step` | mutation hook stdout line |
| `reward_attribution_arm` | `bandit_decisions` row (mode + arm_id) |
| `reward_v2` | `mutation_rewards` row |

For every row: all (kind, step) tuples agree. Variant-isolation
sub-check: V1's `bandit_zone` is always None (uniform); V2/V3/V4's
`bandit_zone` is always None (kind-only); V5's `bandit_zone` is always
in `SEMANTIC_ZONES`.

**Script:** `a4/audits/B4_bandit_db_traceability.py` (Composer; uses
existing `telemetry_v2.py` full mode + a one-shot fuzzer instrumentation
patch that's removed after the audit).

---

### B5 — Variant reward formula routing

**Goal:** confirm each variant routes its reward through the correct formula.

**Why it matters:** V2 uses the legacy multiplicative reward; V3/V4/V5 use
the v2 additive reward. If a variant accidentally uses the wrong formula,
the bandit's signal is contaminated.

**Acceptance gate:**
- Per-variant unit test: feed a fixed `(L_new, F_new, G_new, S_new, crash,
  repeat)` to the variant's reward computation; assert the output matches
  the expected formula (legacy multiplicative for V2; additive `sat()` for
  V3/V4/V5; V1 has no reward but still produces touch / failure stats).
- DB check: `mutation_rewards.reward_v2` is populated for V3/V4/V5; legacy
  reward column is populated for V2; both are populated for V1 (V1 logs
  both for comparison even though it doesn't use either).

**Script:** `a4/audits/B5_reward_formula_routing.py` (Composer; ~60 LOC).

---

### B6 — Coverage-delta correctness

**Goal:** confirm that `L_new`, `F_new`, `G_new`, `S_new` reported per
mutation represent the delta from THAT mutation alone, not cumulative.

**Why it matters:** the additive reward depends on these deltas. If they
accidentally reflect cumulative coverage (post - 0) instead of
(post - pre-this-mutation), the reward saturates after the first few
mutations and all subsequent arms look equally bad.

**Acceptance gate:**
- Run N=20 instrumented smoke. For mutation k, record:
  - `bitmap_before_k` = global bitmap immediately before mutation k
  - `bitmap_after_k` = global bitmap immediately after mutation k
  - `L_new_reported` = the value the reward computation used for mutation k
- Assert `L_new_reported == popcount(bitmap_after_k & ~bitmap_before_k)` for every mutation.
- Same for F_new (new constraint failures), G_new (new global contexts), S_new (new structural cells).

**Script:** `a4/audits/B6_coverage_delta.py` (Composer).

---

### B7 — Same-seed reproducibility

**Goal:** running variant V with seed S twice produces byte-identical
`mutations` and `bandit_decisions` rows.

**Why it matters:** science requires reproducibility. If two runs with
the same seed and same code produce different traces, our findings are
not reproducible. (Bounded variance from A1 must be filtered out before
diffing.)

**Acceptance gate:**
- For each variant V at N=50 with seed=999:
  - Run twice.
  - Diff `mutations` tables (excluding `executed_at` timestamp, excluding
    `original_value` for the 188 known non-det addresses).
  - Diff `bandit_decisions` tables.
  - Zero diff.

**Script:** `a4/audits/B7_seed_reproducibility.py` (Composer; runs locally, ~30 min total).

---

### B8 — Concurrent variant isolation (POS)

**Goal:** running 5 variants in parallel on POS produces the same DBs as
running them sequentially.

**Why it matters:** Phase 8 will run variants in parallel. If they share
mutable state (port collisions, shared temp directories, shared bandit
state files, RNG cross-talk), parallel runs differ from sequential and
Phase 8 results are non-reproducible.

**Acceptance gate:**
- POS dispatch 1: 5 sequential runs of V1–V5 at N=50, seed=999. Collect DBs `seq_V*.db`.
- POS dispatch 2: 5 parallel runs of V1–V5 at N=50, seed=999. Collect DBs `par_V*.db`.
- Diff `seq_Vi.db` vs `par_Vi.db` for each variant. Zero diff (modulo same
  filtering as B7).

**POS resources:** ~30 min for sequential + ~30 min for parallel.

**Script:** `a4/pos/run_audit_B8_concurrent.sh` + `a4/audits/B8_diff_concurrent.py` (Composer).

---

### B9 — DB schema integrity

**Goal:** every variant's resulting DB has all expected tables, schemas
match, foreign-key references hold.

**Why it matters:** silent schema drift between variants would make
Phase 9 comparison analysis incorrect.

**Acceptance gate (per-variant DB):**
- All expected tables present: `campaigns`, `mutations`, `bandit_decisions`,
  `arm_state_snapshot`, `mutation_rewards`, `mutation_substrategy`,
  `hook3_raw`, `local_coverage_v2`, `reward_counterfactuals`,
  `compressed_global_coverage`, `global_failures`, `failures`, `coverage`,
  `campaign_params`, `pilot_runs`.
- All tables have the schema produced by
  `coverage_db._create_tables()`. No extra columns; no missing columns.
- FK check: every `mutation_rewards.mutation_id` references an existing
  `mutations.id`; every `bandit_decisions.mutation_id` (if column exists)
  references an existing `mutations.id`.
- Mutation count equals the expected N.

**Script:** `a4/audits/B9_db_schema_integrity.py` (Composer; ~80 LOC).

---

### B10 — Compressed-global pipeline end-to-end

**Goal:** with the D8 platform.rs-aligned address map landed, the
`compressed_global_coverage` table is non-empty and addresses fall into
expected buckets.

**Why it matters:** Composer fixed the `_coerce_broken_addr/index`
extractor bug but we haven't yet verified the END-TO-END pipeline (host
→ Hook 3 extraction → DB → bucket assignment with D8) produces
non-trivial output.

**Acceptance gate:**
- From a B7/B4/B8 produced DB: `SELECT COUNT(*) FROM compressed_global_coverage WHERE region IS NOT NULL` ≥ 1.
- Region distribution matches platform.rs zones (no addresses bucketed as `unknown` for addresses inside known regions).
- Round-trip test: feed a synthetic Hook 3 dict with known address
  `0xFFFF0080` → expect region `user_regs`; with `0x42000020` → expect
  `host_ecall`; etc.

**Script:** `a4/audits/B10_compressed_global_e2e.py` (Composer).

---

### B11 — Scale stress (POS)

**Goal:** the full audit suite re-runs at N=500 per variant on POS — no
new violations vs N=50.

**Why it matters:** some bugs only appear at scale (memory growth, bandit
state saturation, DB index degradation). Phase 8 is N=6000; we need a
500-mut canary to catch scale-only regressions before committing the
full budget.

**Acceptance gate:**
- POS dispatch: V1–V5 each at N=500, seed=999.
- B7-style diff: doubling N from 50 → 500 should produce the same first-50
  mutations as the N=50 run (deterministic prefix).
- B4 re-runs on the N=500 results: all 5 × 500 = 2500 mutations pass
  bandit-DB traceability.
- B9 re-runs: schema integrity holds.
- Wall-time per variant ≤ 90 min (sanity).

**POS resources:** ~6 hours total (5 variants × ~70 min each).

**Script:** `a4/audits/B11_scale_stress.py` (Composer).

---

### B12 — Multi-input robustness (cheap variant of multi-guest)

**Goal:** all 7d.1 audits + B1, B4, B9 must pass for two ADDITIONAL input
variants of sha2-host: `--in1 1 --in4 1` and `--in1 100 --in4 100`.

**Why it matters:** the baseline guest run is one specific trace.
Input-sensitive bugs (e.g., a zone classifier that only works when ECALL
count is exactly 33) wouldn't be caught by single-trace audits.

**True second-guest test is DEFERRED to post-Phase-8** as it requires
building a second `risc0-host` binary (~2 hr build + integration work);
input variation is the cheap substitute that still catches most guest-shape
sensitivity.

**Acceptance gate:**
- For each of `--in1 1 --in4 1`, `--in1 100 --in4 100`:
  - A1, A2, A3, A4, A5 pass.
  - B1 passes (50 mutations per variant; smaller than baseline since this
    is a robustness check, not the primary acceptance).
  - B4 passes for 50 mutations × 5 variants × this input.
  - B9 passes.
- `EXPECTED_ARMS.md` is updated to enumerate per-input expected arms.

**Script:** `a4/audits/B12_multi_input.sh` (orchestrator that re-runs
A-suite and B1/B4/B9 with the alternate inputs).

---

### E2 — Failure-class fingerprinting (does this arm actually have bite?)

**Goal:** for every arm, run 5-10 mutations and characterize the resulting failure-class distribution. Flag arms that consistently produce zero failures (suggesting they don't "do" anything) or arms that produce surprisingly homogeneous failures (suggesting they may be redundant).

**Why it matters:** the universe builder's "arm is real" criterion is "the mutation module accepts the step." A weaker but separate criterion is "the mutation produces a CONSTRAINT FAILURE in the circuit." If an arm produces 0 failures across 10 mutations, it's bandit-noise: the bandit will pull it because the universe says it's real, but it produces no learning signal. This is not catastrophic (the v2 reward will eventually saturate it to low priority), but it's information the user should have.

**Acceptance gate:**
- For each arm in `SemanticArmUniverse.arms`: run 5 stratified mutations (different steps) via the existing fuzzer instrumentation.
- Per-arm report: `{n_mutations, n_with_failures, mean_failures_per_mut, dominant_failure_family, family_distribution}`.
- Emit `audit_output/E2_arm_bite.json`.
- Flag arms with `n_with_failures == 0` for manual review (E4); these are candidate "no-bite" arms.
- Flag arms whose `dominant_failure_family` is the same as ALL other arms in the same zone (within 90% concentration) as candidate "redundant" arms.

**Script:** `a4/audits/E2_arm_bite.py` (Composer; ~120 LOC; runs ~250 mutations = ~30 min local).

**Acceptance is informational, not blocking** — E2 produces a report; it does not fail Phase 7d unless > 5 arms produce zero failures (which would indicate a real universe-builder bug).

**Resolves:** Q4, Q6, partially Q3.

---

### E4 — Manual review queue (catch-all)

**Goal:** consolidate every "human judgment required" item from E1/E2/E3 + any other anomalies surfaced by B-audits, into a single review queue that Composer + user step through together.

**Why it matters:** some questions can't be answered by code. E.g., "should we extend post_ecall to e+2?" requires a research decision. E4 is the bookkeeping that prevents these items from being silently dropped.

**Acceptance gate:**
- `composer/PHASE_7D_REVIEW_QUEUE.md` exists and lists every item.
- Each item has either: (a) DECIDED + decision recorded, (b) DEFERRED + ticket reference for post-Phase-8, or (c) REJECTED + rationale.
- Zero items in PENDING state at 7d.2 exit gate.

**Script:** N/A (this is a markdown doc maintained by Composer; Opus reviews).

---

### E5 — Per-arm human-readable evidence pack (user-readable correctness proof)

**Goal:** produce a human-readable file for every kept arm in the universe that
serves as the user's PROOF of semantic-label correctness. After E5 runs, the
user (Ivan) can open any `audit_output/per_arm_evidence/<kind>_<zone>.md` and
see, with annotated variable names and definitions, exactly what mutation was
applied, what was observed in the trace, and Composer's verdict on whether
the arm's claimed semantics are CORRECT or INCORRECT.

**Why it matters:** every other audit produces JSON for machine consumption.
E5 is the audit the *user* reads. Without it, "all audits passed" is just
trust; with it, the user has a concrete worked example per arm that they can
spot-check independently.

**Format (one .md file per arm):**

```
# Arm: <kind> | <zone>

## Definitions used in this file
(quick reminder of any non-obvious variable: cycle.major, e (ECALL step),
 txn_type, etc. with pointer to cloud1/GLOSSARY.md for full reference)

## Bandit's CLAIM about this arm
- arm_id: <kind>|<zone>
- zone meaning (from semantic_zones.py): <human-readable definition of the zone>
- kind's allowed majors (from <mutation_module>.VALID_MAJORS): <list>
- expected: "every step in this arm is in zone <zone> AND has a valid <kind>
  target"

## EXAMPLE 1 — Composer's correct-classification candidate (always present)

(Composer picks the BEST evidence: a step where the audit decisively confirms
the arm's claim. Includes the full annotated trace below.)

### Step <N> details (from baseline InspectionData)
- step = <N>  (variable: integer step index in the trace)
- cycle_idx = <I>  (variable: index into trace.cycles[] for this step's
  primary cycle)
- cycle.major = <M>  (variable: instruction-class column, value <M> =
  <MAJOR_NAME> per glossary)
- cycle.minor = <m>  (variable: instruction sub-class; <M>*8+<m> =
  RV32IM kind "<KIND_NAME>")
- cycle.pc = 0x<HEX>  (variable: program counter, RISC0 records the
  next-PC convention)
- step's other cycles in trace: <list of (cycle_idx, major, minor)>
  (a step can have multiple cycles; we use the cycle the universe's
  get_targets_at_step selected)
- step's txns: <list of (txn_idx, txn_type, addr, word)>
  (per glossary: txn_type "reg" = register access, "mem" = memory access)

### Independent decode of the instruction
- raw instruction word at PC (read via INSTR_WORD_MOD's fetcher): 0x<HEX>
- decoded RISC-V mnemonic: "<add a0, a0, a0>"
- decoded major/minor: <M>/<m>
- CONSISTENT WITH cycle.major/minor? ✓ YES / ✗ NO
- (if NO, this row's verdict is FAIL; explain the divergence)

### Mutation that the audit ran
- config: <full JSON the audit sent>
- Hook stdout line emitted by host: <a4_<kind>_mod>{...}
- hook.old_word vs baseline txn.word at txn_idx: ✓ MATCH / ✗ DIFFER
- hook.step vs config.step: ✓ MATCH / ✗ DIFFER
- hook.old_major/minor (if INSTR_TYPE_MOD): ✓ MATCH expected / ✗ DIFFER

### Mutation outcome (from host run)
- exit_code: <int>
- failures emitted: <list of (constraint_name, family, location)>
- proof_generated: <bool>; proof_verify_failed: <bool>
- reward_v2 components: L_new=<n> F_new=<n> G_new=<n> S_new=<n> crash=<bool> repeat=<n>
- reward_v2 total: <float>

### Composer's verdict for this row
✓ SEMANTIC LABEL CORRECT
  - The mutation landed on a cycle whose actual major/minor is consistent with
    both the bandit's zone claim ("core_arithmetic" requires major ∈ {0,1,2}
    and our cycle has major=<M>) AND the kind's claim ("COMP_OUT_MOD operates
    on a compute instruction's destination-register WRITE, and the mutated txn
    is exactly that").
  - The resulting failures include `<inst_misc0>`, which is the constraint
    family expected for ALU-instruction integrity violations.
  - (Composer writes 2-3 sentences explaining their reasoning.)

OR

✗ SEMANTIC LABEL INCORRECT
  - The bandit claimed core_arithmetic but the actual cycle.major=<X> which
    maps to <ZONE_X>, not <zone>.
  - <divergence in any of cycle/decode/hook/outcome>.
  - (Composer writes 2-3 sentences; flag for E4 review queue.)

## EXAMPLE 2 — Composer's incorrect-classification candidate (only if found)

(Composer picks the WORST evidence: the step from this arm whose audit
either failed or was most ambiguous. Same format as EXAMPLE 1. If every
sample passed cleanly, write "No FAIL or AMBIGUOUS rows found in 50
sampled steps; this arm's labels are uniformly correct" and skip this
section.)

## Aggregate summary
- 50 steps from this arm were sampled (or all steps if arm has < 50)
- N (CORRECT): <number>
- N (INCORRECT): <number>
- N (AMBIGUOUS): <number>  (sent to E4 review queue)
- Overall arm-level verdict: ✓ CORRECT / ⚠ MIXED / ✗ INCORRECT
```

**Acceptance gate:**

- One `audit_output/per_arm_evidence/<kind>_<zone>.md` file exists for every
  arm in `SemanticArmUniverse.arms` (48 files for our baseline guest).
- Each file has EXAMPLE 1 (the correct-classification candidate) populated.
- Each file has EXAMPLE 2 (the incorrect-classification candidate) populated
  IF the audit found any incorrect/ambiguous row; otherwise explicit "none
  found" note.
- Top-level `audit_output/per_arm_evidence/README.md` is an index listing
  all 48 arms with their aggregate verdict (✓/⚠/✗) and links.
- All variables in evidence files have units/definitions or pointer to
  GLOSSARY.md.
- 0 arms with ✗ INCORRECT overall verdict at exit (any ✗ must be resolved
  via E4 or via a code fix + re-audit).

**Script:** `a4/audits/E5_per_arm_evidence.py` (Composer; ~250 LOC). This is
a big script: it runs ≤ 50 mutations per arm × 48 arms = ≤ 2400 mutations
total (~3 hr WSL). Reuses B1's verifier + B4's traceability instrumentation.

**Output:** `audit_output/per_arm_evidence/{<kind>_<zone>.md,README.md}`,
plus a top-level summary `composer/PHASE_7D_E5_SUMMARY.md` for Opus review.

**Resolves:** the user's request for per-arm proof of semantic correctness;
addresses E1/E2/E3 outputs in a unified user-readable form.

---

### 7d.2 EXIT GATE

All of B1–B11 pass on standard inputs. B12 passes on alternate inputs. E2
produces a report (informational). E4 review queue has zero PENDING items.

The full audit log is committed to
`a4/docs/cloud1/phases/PHASE_7D_FINAL_REPORT.md` (Opus writes after all
audits land).

**Then and only then**, Phase 8 IV.POS.7 begins.

---

## 3. Decision points to record

- **D40** (Composer chooses, documents in CLOUD1_DECISIONS_FOR_PRO_R2.md):
  multi-cycle step disambiguation — option (a) cycle_idx in config, or
  option (b) drop multi-cycle steps from universe. Preference (b).

- **D41** (Opus, this document): Phase 7d is split into 7d.1 (semantics)
  and 7d.2 (variants), gated sequentially. Composer cannot start 7d.2
  before 7d.1 exits all-green.

- **D42** (Opus, this document): the 188 non-deterministic mem-txn
  addresses found in A1 are excluded from MEM_VAL_MOD target collection
  via `EXPECTED_EXCLUDED_TARGETS.json` (a4/audits/ resource file). The
  allow-list is computed by A1 and consumed by `mem_val_mod.py` /
  `_step_has_real_target`.

- **D43** (Opus, this document): true second-guest robustness test is
  deferred to post-Phase 8. B12 uses input-variation as cheap substitute.

---

## 4. Roles and dependencies

| Audit | Who implements | Who runs | Depends on |
|---|---|---|---|
| A1 | Opus | Opus | — |
| A2 | Opus | Opus | A1 |
| A3 | Opus | Opus | A2 |
| A4 | Composer | Composer | A3 |
| A5 | Opus drafts doc, Composer writes script | Composer | A1-A4 |
| B1 | Composer | Composer | A4, D40, D42, pre-fixes #1 and #2 |
| B2 | Composer | Composer | D40 chosen |
| B3 | Composer | Composer | — |
| B4 | Composer | Composer | A4, B1, B3 |
| B5 | Composer | Composer | — |
| B6 | Composer | Composer | — |
| B7 | Composer | Composer | A1 (for non-det allow-list) |
| B8 | Composer | Composer (POS) | B7 |
| B9 | Composer | Composer | — |
| B10 | Composer | Composer | D8 fix landed |
| B11 | Composer | Composer (POS) | B1, B4, B9 |
| B12 | Composer | Composer | All of A-suite + B1/B4/B9 |

---

## 5. Run order (incremental)

See `composer/PHASE_7D_INCREMENTS.md` for a chunked breakdown with per-increment gates and report-back checkpoints. The high-level run order is:

1. **Increment 0** — Composer lands the 3 pre-fixes. Opus has already run A1/A2/A3 baseline. ✅ DONE.
2. **Increment 1** — 7d.1 audits A4, A5, E1, E3 (semantics & arms). ✅ DONE — surfaced Inc 1.5 work.
3. **Increment 1.5** — Composer implements D50 (`core_div`/`core_shr` split), D53 (`post_ecall` redefinition), D54 (HYBRID `kernel_other` zone). Regenerates EXPECTED_ARMS for affected arms. Runs E3b (MEM_VAL_MOD on non-memory majors per D55/Theme 6). Re-runs A3/A4/A5/E6/E7 to confirm new universe. Gate to Inc 2. See `composer/PHASE_7D_INC1_5_WORK.md`.
4. **Increment 2** — 7d.2 local audits B3, B5, B6, B9, B10, E2 (cheap-to-run, no big mutations).
5. **Increment 3** — 7d.2 fidelity audits B1, B2, B4, B7 (mutation fidelity + reproducibility).
6. **Increment 4** — POS audits B8, B11, B12.
7. **Increment 5** — **E5 per-arm evidence pack (user-readable)** + E4 manual review + final report. Phase 8 unblocks.

Each increment has its own acceptance gate and report. Composer reports back after each increment so we can course-correct before the next one starts.

---

## 6. Multi-guest plan (semantic-label correctness beyond this guest)

**The user's question:** "in order to ensure semantic label correctness, would
we need to explore multiple different guest programs in order to ensure we also
test this for arms that don't appear in our current guest but would in
others?"

**The answer:** YES, fully, with caveats. Splitting this into three layers:

### 6.1 What's verifiable with the current guest (c0c1_differential_guest)

For our baseline trace at `--in1 5 --in4 10`, only 48 (kind, zone) arms have
real targets. The Phase 7d audit suite (especially A4, A5, B1, B4, E5) gives
us strong evidence that those 48 arms have *correct* semantic labels for this
guest.

But this guest does NOT exercise:

| Arm-set | Why unobservable with this guest | Counts |
|---|---|---|
| `* | core_sha` | guest does no hashing; SHA accelerator (major=11) never invoked | 7 arms (one per non-NOOP kind) |
| `* | core_poseidon` | guest doesn't invoke Poseidon hash | 7 arms |
| `* | core_other` | major ∈ {8, 12} (BigInt) — guest does no BigInt ops | 7 arms |
| `* | pre_mret` | guest's only ECALL is HALT; no MRET | 7 arms |
| `* | post_mret` | same | 7 arms |
| `* | pre_halt` | classifier not yet implemented (Q8) | 7 arms |
| `* | post_halt` | same | 7 arms |

That's ~49 additional arms we have no semantic-correctness evidence for. The
universe builder *can* enumerate them (when a future guest triggers them), so
we want some confidence that the zone classifier + mutation module pair would
do the right thing if they fire.

### 6.2 What B12 (multi-input) actually catches

B12 reruns the same guest with `--in1 1 --in4 1` and `--in1 100 --in4 100`.
This catches:

- Input-sensitive zone classifier bugs (e.g., classifier hardcoded an offset).
- Step-count-sensitive bandit bugs.
- A1 non-determinism that varies with input size.

It does NOT catch:

- Bugs that only manifest for instruction classes the guest doesn't use.
- Missing zone definitions for unsupported classes.

### 6.3 Multi-guest plan (deferred to post-Phase 8, with rationale)

To verify semantic correctness for the remaining ~49 arms, we'd build at
least one additional guest that exercises:

- A SHA-using path → activates `core_sha` arms.
- A Poseidon-using path → activates `core_poseidon` arms.
- A BigInt-using path (or a syscall that triggers it) → activates `core_other`
  arms.
- An MRET-using path (typically a guest that exits abnormally or makes a
  custom syscall) → activates `pre_mret`, `post_mret`.

**Why deferred to post-Phase 8:**

1. Each additional guest is ~2 hr build + ~30 min audit re-run.
2. Phase 8 IV.POS.7 generates campaign data ONLY on the current guest, so
   semantic correctness for the unused arms doesn't affect Phase 8 results.
3. The unused arms simply will not be pulled — they're not part of the kept
   universe — so they cannot contaminate Phase 8 either.
4. The Phase 7d Final Report will EXPLICITLY DOCUMENT the unverified arms as
   a known limitation (`PHASE_7D_FINAL_REPORT.md §6.3`).

**Concrete options for the multi-guest phase** (Phase 9 candidate work):

- **Option A (cheap)**: use one of risc0's stock examples (e.g.
  `risc0/examples/hello-world`, `risc0/examples/json`, or
  `risc0/examples/password-checker`) which use SHA syscalls. Re-run Phase 7d
  A-suite and B1/B4/E5 against that guest. Estimated effort: 1 day per
  additional guest.
- **Option B (expensive)**: extend arguzz's CircIL to generate guests that
  exercise specific instruction classes (synthetic SHA-heavy, Poseidon-heavy,
  BigInt-heavy guests). Estimated effort: 1-2 weeks.

**Decision: pursue Option A in Phase 9 if Phase 8 results justify the
investment; otherwise leave as documented limitation.**

### 6.4 What E5 still gives us today

E5 produces per-arm evidence files only for arms that exist in this guest.
The non-existent arms will get a stub evidence file: "NOT EXERCISED BY THIS
GUEST; see §6.3 for the multi-guest plan to verify this arm." So the user has
a complete arm-by-arm record of what's verified and what's not.

---

## 7. Accelerator-targeted mutation kinds (deferred to Phase 11)

**The user's Inc 1 question:** *"should we really filter all major ∈ {9,10,11,12} for RV32IM mutation kinds?"*

**Answer:** Yes, for our current 7 mutation kinds — the filter is semantically correct and pragmatically necessary. But this leaves an architectural gap: **we have no mutation kinds that target accelerator cycles directly**.

### 7.1 Why the filter is correct for current kinds

Each of our 7 mutation kinds makes a specific semantic claim about what it
mutates. None of those claims apply to accelerator cycles:

| Kind | Mutation claim | Applies to Poseidon/SHA/BigInt? |
|---|---|---|
| COMP_OUT_MOD | Rewrite RV32IM destination register WRITE | No — accelerators write to memory regions, not regs |
| LOAD_VAL_MOD | Rewrite RV32IM `lw/lh/lb` load value | No — accelerators don't use scalar loads |
| STORE_OUT_MOD | Rewrite RV32IM `sw/sh/sb` store value | No |
| PRE_EXEC_REG_MOD | Rewrite a register READ before an RV32IM instr | No — accelerators read inputs from memory |
| INSTR_TYPE_MOD | Rewrite (major, minor) of an RV32IM Decode cycle | No — accelerator cycles aren't Decode cycles |
| INSTR_WORD_MOD_* | Rewrite fetched RV32IM instruction word | No — accelerators triggered by ECALL, not fetch |
| MEM_VAL_MOD | Rewrite any memory transaction value | **Yes** — UNFILTERED; reaches accelerator memory I/O |

So MEM_VAL_MOD is our only path into accelerator memory I/O for Phase 8.
That's coverage, but it's not direct "mutate the SHA block" coverage.

### 7.2 Why the filter is also pragmatically necessary

Without the filter, P3's multi-cycle count would include all the Poseidon
micro-cycles at step=0 (11,889 of them in our baseline), making EVERY step
appear "multi-cycle" and dropping the entire universe.

The filter is what KEEPS `step0`, mid-program Poseidon-adjacent steps, and
boot/terminator steps reachable.

### 7.3 What we're missing: hypothetical accelerator kinds

| Hypothetical kind | Targets | Cost to add | Value |
|---|---|---|---|
| `SHA_INPUT_MOD` | The 64-byte block fed to a SHA accelerator call | Medium — Rust hook for major=11 + parser | High — would surface SHA constraint family failures |
| `POSEIDON_INPUT_MOD` | The state fed to a Poseidon cycle | Medium-high | Medium — Poseidon used mostly for proving infrastructure, less for user code |
| `BIGINT_OPERAND_MOD` | The 256-bit operand to a BigInt op | Medium | Low — most guests don't use BigInt |

### 7.4 Why this is Phase 11 (post-Phase 9), not Phase 7d/8

1. **c0c1_differential_guest doesn't exercise any accelerators.** Adding
   SHA_INPUT_MOD now would create a kind with 0 valid steps on our baseline
   trace — wasted work.
2. **Phase 11 is most valuable PAIRED with Phase 10.** A SHA-using guest
   (e.g. risc0's `hello-world` example which uses sha256) would unlock both
   `core_sha` zone coverage AND give us a target for SHA_INPUT_MOD.
3. **Pro R2 may have opinions.** ChatGPT Pro's R2 review of Phase 8 results
   may recommend specific accelerator coverage priorities (e.g. "skip Poseidon,
   focus on SHA"). Deferring the decision lets us incorporate Pro's input.

### 7.5 Concrete Phase 11 plan (when it arrives)

When Phase 11 is triggered:
1. Read Pro R2's recommendations on accelerator priority.
2. Select 1-2 accelerator kinds to add (likely SHA_INPUT_MOD first if
   Phase 10 selected a SHA-using guest).
3. For each new kind: implement Rust hook, Python config schema, universe
   filter (e.g. SHA_INPUT_MOD: `cycle.major == 11`), value generator.
4. Run a Phase 7d-equivalent micro-audit suite (A4, A5, B1, E5 subset) on
   the new kind before letting it into the bandit's action space.
5. Update `EXPECTED_ARMS.md` with the new kind × zone matrix.

### 7.6 Where this lives in our master plan

- `CLOUD1_STATUS.md` row 11 — Phase 11 deferred entry.
- `CLOUD1_DECISIONS_FOR_PRO_R2.md` D49 — design principle that supports
  this deferral.
- This document §7 — full rationale (you are here).
