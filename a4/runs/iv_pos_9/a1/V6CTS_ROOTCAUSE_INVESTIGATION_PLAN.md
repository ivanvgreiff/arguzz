# Root-cause investigation: cTS arm definition, zero reward, and zone misclassification (before any Pro architecture question)

**Status: OPEN INVESTIGATION.** The diagnosis package (`PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md`) is frozen until
this resolves. Three database symptoms point at **source-level bugs/misconfigurations** in the cTS
campaign that must be understood with 100% certainty — otherwise any architectural advice to Pro is built on
sand. We are NOT going to Pro until every question below has a code-traced, verified answer.

## Verified symptoms (from the run databases; re-checked across all 6 V6_cTS seeds)
- **S1 — arm key is NOT just (kind, zone).** `bandit_decisions.selected_arm` values are 5-field tuples, e.g.
  `arguzz_exec_fault|INSTR_WORD_MOD|core_div|arithmetic|pre_exec` = (surface, kind, zone, opcode_class,
  pre_post). The campaign reported **417 arms**. (The package text said "(kind, zone)" — an oversimplification
  to fix once we know the truth.)
- **S2 — V6_cTS reward is identically ZERO.** All 5000 rows of `mutation_rewards` (reward, T_new, T_rare,
  F_new, F_rare, Q, S, …) are 0, in every one of the 6 seeds. Hybrid_cTS by contrast has ~2900/5000 reward>0
  (mean ≈0.20). So the bandit never learned on the pure-Arguzz surface.
- **S3 — the divide is not in the `core_div` arm.** The `INSTR_WORD_MOD|core_div` arm injects (per
  `mutations.step` joined to `bandit_decisions`) at steps **441 and 436** in every seed; the actual divide
  inject step **444 is classified into `core_memory_store`**. So the zone label is out of register with the
  inject-step space.
- **S4 — context:** cTS issued MORE INSTR_WORD_MOD (8470) than uniform (3757) and reached MORE constraint
  coverage (36 vs 34 locs/seed), yet found the bug 0 times (uniform 9). So the failure is targeting, rooted in
  S1–S3, not effort.

## Open questions — each needs a code-traced, verified answer
- **Q1 (arm definition).** What is the exact `ArmKey`? Which dimensions are *active* (non-constant) in the
  V6_cTS campaign vs collapsed? How are arms constructed (`semantic_arm_universe.py:295`), and from what input
  (the inspection data)? Across how many (zone × opcode_class × pre_post) arms is the divide instruction split?
  Did Hybrid/V5 use the same arm key or a different one?
- **Q2 (zero reward).** Where is the per-mutation reward/success computed, and what is passed to
  `ConstrainedTSScheduler.update(...)`? Why is it 0 for V6_cTS but non-zero for Hybrid? Is the *success the
  bandit learns from* the same as the logged `mutation_rewards.reward`, or could the bandit have learned from a
  different signal than what's logged? Is the reward tied to an A4-only coverage channel that pure-Arguzz never
  produces, or is the reward computation simply broken for the Arguzz surface?
- **Q3 (zone misclassification + indexing).** How is each step's zone computed (`zone_classifier.py` /
  `semantic_zones.py` / `inspection_data.py`)? What STEP INDEXING does the inspection data / arm step-set use,
  and is it the SAME counter as `--inject-step`? Why is inject-step 444 (the remu) labeled `core_memory_store`
  while `core_div` holds 441/436? Is this an off-by-N indexing offset, a major/minor misread, or a
  fetch-vs-compute cycle distinction? **Read the existing audits `a4/audits/A2_zone_classifier_correctness.py`
  and `a4/audits/A3_arm_step_integrity.py` — do they already flag this?**
- **Q4 (extent of misclassification).** Systematically: for each instruction kind / inject step, does the
  arm's zone match the actual instruction at that step? How many steps/arms are mislabeled? Is the whole
  zone↔step mapping shifted, or only specific zones? (Cross-check: `--trace` gives the true instruction per
  inject step; the inspection data / arm step-sets give the zone.)
- **Q5 (Hybrid vs V6_cTS).** Why did Hybrid's reward fire (≈0.20) but V6_cTS's stay 0? What in the surface /
  coverage / reward wiring differs? Does Hybrid's working reward mean Hybrid's zones/arms were also correct, or
  did Hybrid also suffer S3 (and just had a working reward)?

## Investigation method
1. Read the source of record (no rebuild): `semantic_arm_universe.py`, `semantic_zones.py`,
   `zone_classifier.py`, `core/inspection_data.py`, the campaign driver (`standalone/fuzzer.py` /
   `cli.py` / `v6_uniform_driver.py`), `bandit_ts.py`, `step_selector.py`, `arguzz_invoke.py`.
2. Read the existing audits `a4/audits/A2_zone_classifier_correctness.py`, `A3_arm_step_integrity.py` (and
   `audit_common.py`) — they may already answer Q3/Q4.
3. Verify every claim against the run DBs (`bandit_decisions`, `mutations`, `mutation_rewards`,
   `campaign_params`) and, where needed, against `--trace`/`A4_INSPECT` on the binary (read-only; no rebuild).
4. Determine for each Q whether the symptom is a genuine bug (to fix), a misconfiguration, or correct-but-
   surprising — with the exact code and a DB/measurement that confirms it.

## Findings — RESOLVED (3 deep-dive agents + own verification against binary & DBs; all consistent)

**Q1 — Arm definition (CERTAIN).** `ArmKey` is a 5-field frozen dataclass `(surface, kind, zone, opcode_class,
pre_post)` (`semantic_arm_universe.py:174-205`). The V6_cTS campaign used the FULL 5-field key: surface pinned
to `arguzz_exec_fault`; kind/zone/opcode_class/pre_post all active → **417 arms** (100% 5-field, verified in all
6 DBs). `zone` comes from the dynamic execution-unit major (major 4 → `core_div`); `opcode_class` comes from the
STATIC mnemonic (`div/rem`→arithmetic, loads→memory_load) — two independent sources that can disagree, which is
why both `INSTR_WORD_MOD|core_div|arithmetic` and `…|core_div|memory_load` exist. **The three variants use
DIFFERENT arm shapes:** V6_cTS = 417 arms, all 5-field arguzz; V5_control = 85 arms, all 2-field A4 (`kind|zone`,
`ArmKey.v5`); Hybrid_cTS = 256 arms, MIXED (85 two-field A4 + 171 five-field arguzz from a 4-kind subset). So my
"(kind, zone)" was wrong for V6_cTS. Source: `fuzzer.py:776-784` (per-strategy kinds), `:862-876` (build);
`arguzz_bridge.py:48-60,69-81,114-154`.

**Q3 — Zone misclassification is a STEP-COUNTER DOMAIN MISMATCH (CERTAIN, the dominant bug).** Two different
step counters exist and drift: the **executor `current_step`** (`rv32im.rs:33,158`) increments once per executed
instruction and is what BOTH `--trace` and `--inject-step` use (`rv32im.rs:139,154`); the **witgen `user_cycle`**
(`preflight.rs:555`, incremented only in `on_insn_end`) collapses multi-cycle expansions (ECALL/MRET
micro-cycles). The semantic-zone classifier reads witgen `user_cycle` (`zone_classifier.py`/`semantic_zones.py`;
`mod.rs:135` emits `cycle.user_cycle` as "step"). **Verified on the binary:** the `remu` is at executor step
**444** but witgen step **436** (drift +8; the drift grows +1 per ECALL/MRET from 0 early to +14 at program
end). So the `core_div` arm holds witgen steps {436,441}; injecting `--inject-step 436/441` (executor space)
hits `lw a0,16(sp)` / `ori a1,s1,256` — **NOT the divides**. And "inject-step 444 → core_memory_store" is
reading the witgen entry 444 (a store) while executor 444 is the remu. **The cTS path picks a step from the
witgen-space arm (`fuzzer.py:1393 pick_step_in_zone`) and feeds it to executor-space `--inject-step` — a genuine
domain mismatch.** Uniform is unaffected (its `instr_to_steps` is built in executor space via
`parse_trace_steps`, so it injects on the correct instruction; its zone label is wrong but uniform doesn't use
zones to select).

**Q4 — Extent (CERTAIN).** The mismatch affects EVERY cTS Arguzz injection after the first ECALL (the drift is 0
early, then grows). So cTS systematically injected at instructions OFFSET from the zone its arm intended; the
bandit's learning was attributed to the wrong arms. The actual divides (executor 444/449) were reachable only
incidentally — when an arm whose witgen step-set happens to contain witgen-444/449 was picked (witgen-444 is a
store → `core_memory_store` arm, 140 steps) — hence cTS's ≈2 INSTR_WORD on the divide.

**Q2 — Zero `mutation_rewards.reward` is a LOGGING ARTIFACT, NOT dead learning (CERTAIN; corrects my earlier
claim).** Two distinct reward objects: (i) the LEGACY `compute_reward` (`coverage_state.py:152-291`) logged to
`mutation_rewards` — it returns all-zero `mode="crash"` whenever `touch_bitmap is None` (`coverage_state.py:190`),
and the Arguzz dispatch path hard-codes `touch_bitmap=None` (`fuzzer.py:1226`); so pure-Arguzz V6_cTS logs all
zeros. (ii) `compute_bandit_success(l_new,g_new,s_new) = 1 if (l+g+s)>0 else 0` (`reward_v2.py:60`) — **this is
what the bandit actually learns from**, logged to `reward_counterfactuals.discovery_binary_reward`. **Verified:**
V6_cTS discovery_binary_reward = 456–475/seed (~9.3% success) and **~1650 adaptive Thompson picks/seed** — the
bandit DID learn. V6_cTS even populated MORE coverage than Hybrid (502 vs 252 CGC; 37685 vs 19171 failures).

**Q5 — Hybrid vs V6_cTS (CERTAIN).** Hybrid's `mutation_rewards` is non-zero only for its A4-surface mutations
(real touch_bitmap → legacy reward fires); its Arguzz-surface mutations zero out identically. So the difference
is purely which surface populates the legacy reward — the bandit's actual success signal worked for both.

## Bottom line (verified)
The dominant cause of cTS missing the bug is a **step-counter domain bug**: cTS schedules Arguzz mutations using
**witgen-`user_cycle`** zone arms but injects them via **executor-`current_step`** `--inject-step`, so its
zone-targeting points at the wrong instructions (off by the cumulative ECALL/MRET drift, +8 at the divides). The
bandit learned normally (not dead); the legacy reward zero was a logging artifact. **Therefore the V6_cTS vs
V6_uniform comparison in this race is CONFOUNDED** — cTS's scheduling logic was never fairly tested, because its
arm→step targeting was systematically misaligned. The headline (uniform 9, cTS 0) is real but its *cause* is the
implementation bug, not a property of constrained Thompson sampling.

**Consequence for the Pro package:** `PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md` §5.3 (dead reward; coverage-starvation)
is now known to be WRONG and must be rewritten before any architecture question — asking Pro to redesign a
scheduler based on bug-corrupted results would be invalid. Decide: (a) fix the witgen↔executor step mapping in
the cTS Arguzz path, (b) re-run the V6_cTS (and Hybrid) campaign, (c) only then compare and ask Pro.
