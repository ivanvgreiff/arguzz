# For Composer — the V0/V8 scheduler-ablation experiment (fresh-context onboarding + review)

**From:** Opus (Track A) · **Date:** 2026-06-28 · **Your job:** get up to speed on this experiment and **review the implementation** I just landed (commits on a feature branch; details below). You have no prior context — this doc is self-contained; deeper detail is in the 6-doc set under `a4/docs/cloud3/bug_race_a4_arguzz_scheduler/`.

## 1. The big picture (what project this is)
IV.POS.9 is a RISC Zero zkVM **soundness-fuzzing thesis**. Two mutation *surfaces* are compared: **A4** (post-execution single-trace-cell mutation) and **Arguzz** (during-execution fault injection). We run "**bug races**": fuzzing variants race to discover a planted soundness bug.
- The completed race = the **Seam-B VerifyOpcode** race: a "holed" `risc0-host` binary with one planted underconstraint (a removed `VerifyOpcode*` decode-equality). 4 variants × 10 seeds × N=5000. Result: the A4-surface variants (V5_control, Hybrid) find it; pure Arguzz (V6) cannot, because the bug is only reachable via the `INSTR_TYPE_MOD` mutation, which is absent from Arguzz's kind set. (Full analysis: `a4/runs/iv_pos_9/race/race_exploration.html` + `CONTAMINATION_IMPACT_VERIFICATION.md`.)

## 2. The new experiment (what I'm adding, and WHY)
The A4 scheduler (V5 = `cTS_semantic_v2`) has **two architectural components**: **arm semantics** (a `(kind, zone)` `SemanticArmUniverse` action space) and a **bandit** (constrained Thompson sampling with reward learning). To attribute the A4 scheduler's bug-finding to each component, we add two A4-surface variants and run a **2-factor ablation ladder**:

| variant | arm semantics | bandit | isolates |
|---|---|---|---|
| **V8** (new) | ❌ | ❌ | baseline — Arguzz instruction-balanced site selection, no arm structure, no learning |
| **V0** (new) | ✅ | ❌ | **V8→V0: do ARM SEMANTICS help?** |
| **V5** (exists) | ✅ | ✅ | **V0→V5: does the BANDIT help?** |

- **V0** = A4 mutations, **uniform over V5's exact `SemanticArmUniverse`** (no bandit). The "arm semantics, no learning" rung.
- **V8** = A4 mutations, but the site is chosen by **Arguzz's own scheduler** — balanced round-robin over the *distinct RISC-V instruction types* in the trace (rare instructions sampled as often as common ones), **no arms at all** — then a uniform A4 kind valid at that site. The "neither arm semantics nor bandit" rung.

The same race is re-run on the SAME seeds (1234–1243) × N=5000. The pure-Arguzz V6_uniform/V6_cTS + Hybrid carry the orthogonal cross-*surface* story (already done).

## 3. What I implemented (REVIEW THIS) — commits on branch `cloud2-sched-ablation`
**Isolation:** all work is on the feature branch `cloud2-sched-ablation` (off cloud2 `68d90aa`); **cloud2 is untouched** (it's shared — all tracks commit to it + build POS bundles from it; see `04_GIT_ISOLATION_AND_HANDOFF.md`). To review: `git checkout cloud2-sched-ablation`.
- `7e44d57` — planning docs.
- `d6fe4d5` — **the V0 + V8 selectors** (the code to review).

**Files changed** (`d6fe4d5`):
- `a4/standalone/step_selector.py` — `SemanticUniformArmSelector` (V0) + `ArguzzSchedA4Selector` (V8).
- `a4/standalone/fuzzer.py` — wiring: `__init__` defer, `run_campaign` dispatch, `_run_single_mutation` `is_uniform` branch, `_setup_a4_uniform_semantic` (V0), `_setup_v8_arguzz_sched` (V8). **Both are deliberately EXCLUDED from `V2_BANDIT_STRATEGIES`** (no reward update — the ablation point).
- `a4/standalone/cli.py` — `--selector` choices `a4_uniform_semantic` (V0), `a4_arguzz_sched` (V8).
- `a4/standalone/variants.py` — `V0_uniform`, `V8_arguzz_sched` (both `launcher=cli`, `surface=a4`).
- `a4/standalone/tests/test_semantic_uniform_arm_selector.py` (6), `test_arguzz_sched_a4_selector.py` (7).

**Both run as cli selectors** via the existing coupled `select_arm_then_step() → _run_single_mutation` path, so their run-DBs are schema-identical to V5's (analysis ingests them unchanged). I chose this over a `v6_uniform_driver` fork because it reuses A4 execution+recording (the earlier docs say "driver"; the selector is the refinement — see `05` STATUS).

### The one subtle, load-bearing piece to scrutinize — V8's step-domain translation
Arguzz's scheduler picks an **executor `current_step`**; an A4 `INSTR_TYPE_MOD` mutation is keyed by **witgen `user_cycle`** (the two counters drift by the running host-ecall count). V8 MUST translate executor→user_cycle (via `step_domain_map.to_user`, shipped + tested in `68d90aa`) before building the A4 config, or it silently mutates the *wrong* instruction. `ArguzzSchedA4Selector` does this and skips host-ecall steps (`user_cycle_of → None`). **Validated on the real holed binary:** step-map built (3346 real instrs / 19 host ecalls, self-validation passed), 200 picks all returned a valid `(kind, user_cycle)` pair (0 invalid), ITM reachable. **Please double-check this translation + the uniform-over-valid-kind logic** — it's the highest-risk part.

## 4. Test status (all green)
13 V0/V8 unit tests; V0 holed-binary micro-smoke (applied A4 mutations recorded); V8 real-binary setup+selector validation (above); existing variant/selector/race suites unaffected (56 passed in the combined run). To re-run: `python3 -m pytest a4/standalone/tests/test_semantic_uniform_arm_selector.py a4/standalone/tests/test_arguzz_sched_a4_selector.py -q`.

## 5. What remains (NOT yet done)
- **Inc 3 — analysis harness** (`race_lib.py`: add V0/V8 to the variant dicts + a scheduler-ablation figure + generalize the `_RID` regex). **DEFERRED**: `race_lib.py` currently holds *another track's uncommitted WIP* (a thesis relabel A4→"A3" + a `DISPLAY` dict). Editing it now would entangle the two. Do this after that relabel lands. Not on the critical path (analysis runs post-POS).
- **Inc 4 — fixed binary** (pre-POS): the holed binary is head `93bda33b`, which has a known contamination (3 A4 kinds — `TXN_PREV_WORD_MOD`/`TXN_PREV_CYCLE_MOD`/`CYCLE_DIFF_COUNT_MOD` — silently no-op; added later in `6556e8d7`). For the ablation we run on a **FIXED** binary (cherry-pick `6556e8d7` onto `workspace/risc0-seamb`, rebuild holed+control) and **re-run V0/V5/V8/Hybrid** (V6 is binary-invariant — reused). Recipe: `CONTAMINATION_IMPACT_VERIFICATION.md §5`. WHY fixed: the contamination inflates the *bandit's* (V5) ITM rate but not V0/V8's, so it would bias the ablation. (Full reasoning: `02 §Binary`.)
- **Inc 5 — POS dispatch** (USER-GATED): smoke (V0/V5/V8/Hybrid × 3 seeds × N=2000) then thesis (×10 × N=5000) into a collision-free namespace `a3seambfix` (so it never mixes with the contaminated thesis DBs — see `03_CAMPAIGN_INVENTORY.md`).

## 6. Where to read (depth, in order)
1. `bug_race_a4_arguzz_scheduler/00_OVERVIEW.md` — the design + all resolved decisions (read the "ROUND-2" block).
2. `01_VARIANT_DEFINITIONS.md` — V0/V8 precise defs (note: the ROUND-2 block in 00 supersedes the V8-over-arms parts).
3. `02_IMPLEMENTATION_HARNESS_POS.md` — harness + the binary decision.
4. `05_IMPLEMENTATION_INCREMENTS.md` — the increment/test-gate plan + STATUS.
5. `03_CAMPAIGN_INVENTORY.md` (DB separation), `04_GIT_ISOLATION_AND_HANDOFF.md` (git).
6. The code: `step_selector.py` (the two selector classes) + `fuzzer.py` `_setup_v8_arguzz_sched` / `_setup_a4_uniform_semantic`.

## 7. Specific things I'd like you to review
1. **V8 step-domain correctness** — does `ArguzzSchedA4Selector` translate + skip correctly? Any case where it could target the wrong `user_cycle`?
2. **Is option (b) faithful?** V8 picks a uniform A4 kind valid at the site (vs Arguzz's uniform-over-valid-injection-kinds). Agree this is the right "Arguzz scheduler over A4 mutations"?
3. **V0 = clean V5 ablation?** It uses `SemanticArmUniverse.build(data, active_a4_kinds)` (V5's exact call) — so V0/V5 differ only in scheduler. Confirm.
4. **The binary decision** (fixed + re-run V5/Hybrid) — agree it's required for an unbiased ablation?
5. Anything in the no-arms/no-bandit isolation that leaks (e.g., is either selector accidentally pulled into a reward-update path)?
