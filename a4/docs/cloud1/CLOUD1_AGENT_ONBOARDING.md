# Cloud1 — Agent Onboarding (Composer or any future agent)

**Audience**: Any AI agent (Composer, future Claude session, GPT-5-mini, etc.) being asked to work on cloud1 phases.
**Purpose**: Get you from "zero project knowledge" to "can implement a phase correctly" in ≤15 minutes of reading.

---

## TL;DR — read these 4 files first, in this order

| # | File | What you'll learn | Time |
|---|---|---|---|
| 1 | `a4/docs/cloud1/ProG_Report_2.md` | ChatGPT Pro's architectural recommendations (source of truth — do not deviate) | ~10 min |
| 2 | `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md` | The 9-phase plan, the meta-rules, the decisions D1-D15 | ~10 min |
| 3 | `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` | Every decision we made beyond Pro's spec, with full justifications | ~10 min |
| 4 | `a4/docs/cloud1/CLOUD1_STATUS.md` | What's done, what's next, current risks | ~2 min |

**Then** read the SPECIFIC phase doc you're being asked to implement, e.g. `a4/docs/cloud1/phases/PHASE_3_GLOBAL_CTX.md`.

**Then** read any retrospectives for ALREADY-DONE phases that touched the modules you'll modify (so you understand the existing patterns).

---

## Mental model in 60 seconds

We are building a **constraint-coverage-guided fuzzer** for **RISC Zero zkVM**.

Pipeline:
1. **Inspection** — run a guest binary once with `A4_INSPECT=1`, parse all `<a4_cycle_info>` and `<a4_all_txn>` lines into `InspectionData`. (Code: `a4/core/inspection_data.py`, `a4/core/trace_parser.py`.)
2. **Mutation selection** — a "step selector" picks which `(mutation_kind, step)` to mutate. The OLD strategies are `arm_uniform_b128`, `kind_uniform_zoned_step`, `ucb_kindbucket_b16`. The NEW strategy we're building is `cTS_semantic_v2` (Constrained Thompson Sampling over `(kind, semantic_zone)`).
3. **Mutation** — apply the mutation to the trace. (Code: `a4/standalone/mutations/*.py`.)
4. **Coverage observation** — run the modified trace through the prover, observe which constraints fired vs failed via Hook 1 (constraint registry) and Hook 3 (failure context).
5. **Reward** — convert coverage signals into a scalar reward.
6. **Bandit update** — feed reward back to the bandit; update arm posteriors.
7. **Log** — record every mutation, decision, reward, coverage delta into SQLite (`a4/standalone/coverage_db.py`).

The "smoking gun" from IV.POS.5 was that 4 critical constraints fire ONLY when `INSTR_TYPE_MOD` is applied at `user_cycle = 0` (step 0). The old `kind_uniform_zoned_step` strategy hit this 184× per campaign by accident; the bandit hit it 1-2×. Pro's recommendation is to make this structural (singleton arm with forced pulls), not accidental.

---

## Codebase layout (only what you need)

```
a4/
├── core/                          ← Trace parsing, inspection (DO NOT MODIFY)
│   ├── inspection_data.py         ← THE authoritative source for cycle major/minor mappings
│   ├── trace_parser.py            ← Parses <a4_cycle_info> and <a4_all_txn>
│   └── executor.py
├── standalone/                    ← THIS is where almost all cloud1 work lives
│   ├── coverage_db.py             ← SQLite schema (Phase 1 added 8 new tables)
│   ├── fuzzer.py                  ← Top-level orchestrator (CLI entry: a4/standalone/cli.py)
│   ├── arm_universe.py            ← LEGACY (kind × bucket) arm space — don't touch
│   ├── step_selector.py           ← ALL step selectors — append new classes here
│   ├── bandit.py                  ← LEGACY discounted-UCB — don't touch
│   ├── semantic_zones.py          ← cloud1 Phase 1: 17 zones + major mappings
│   ├── compressed_global.py       ← cloud1 Phase 1: GlobalMemoryCtx + GlobalLookupCtx
│   ├── structural_cells.py        ← cloud1 Phase 1: StructuralCell dataclass
│   ├── zone_classifier.py         ← cloud1 Phase 2: assigns step → zone
│   ├── semantic_arm_universe.py   ← cloud1 Phase 2: (kind × semantic_zone) arms
│   ├── mutations/                 ← Per-kind mutation implementations
│   └── tests/                     ← pytest suite — RUN OFTEN
├── docs/
│   ├── cloud1/                    ← THE plan + decisions + per-phase docs
│   │   ├── ProG_Report_2.md       ← Pro's recommendations (SOURCE OF TRUTH)
│   │   ├── CLOUD1_IMPLEMENTATION_PLAN.md
│   │   ├── CLOUD1_DECISIONS_FOR_PRO_R2.md
│   │   ├── CLOUD1_STATUS.md
│   │   ├── CLOUD1_AGENT_ONBOARDING.md (this file)
│   │   └── phases/
│   │       ├── PHASE_0_FREEZE_AND_SETUP.md   ← retrospective
│   │       ├── PHASE_1_SCHEMA.md              ← retrospective
│   │       ├── PHASE_2_SEMANTIC_ZONES.md      ← retrospective
│   │       └── PHASE_3..9 ...                 ← stubs to fill in
│   ├── precloud/                  ← PAUSED master plan — DO NOT continue work here
│   └── ...
└── runs/iv_pos_5/                 ← FROZEN — historical baseline, do not regenerate
```

---

## Mandatory protocol for every phase

Follow these steps EXACTLY for any phase you implement. If you're unsure, ASK before deviating.

### Before starting the phase

1. **Re-read `ProG_Report_2.md` sections relevant to this phase**, not just the phase doc. The phase doc maps Pro's sections → tasks; you need the original text to avoid drift.
2. Read the most recent done-phase retrospective to understand the file/module patterns we're using.
3. Run the full fast test suite to confirm a clean baseline before you start:
   ```bash
   cd /root/arguzz
   timeout 60 python -m pytest a4/standalone/tests/ -q --tb=line \
     --ignore=a4/standalone/tests/test_pilot_calibration.py \
     --ignore=a4/standalone/tests/test_run_replicates.py \
     --ignore=a4/standalone/tests/test_determinism.py \
     --ignore=a4/standalone/tests/test_phase02_baseline.py \
     --ignore=a4/standalone/tests/test_instr_word_mod_sur.py \
     --ignore=a4/standalone/tests/test_baseline_touch.py \
     --ignore=a4/standalone/tests/test_touch_coverage.py
   ```
   You should see something like `164 passed, 1 skipped`.

### During the phase

4. **Add only — never replace**. Old strategies (`arm_uniform_b128`, `kind_uniform_zoned_step`, `ucb_kindbucket_b16`) must remain runnable end-to-end. The old `ArmUniverse`, `BucketStepSelector`, and `BanditStepSelector` classes stay. The new code goes alongside with `semantic_` / `_v2` / `_ts` / `cTS_` suffixes.
5. **Authoritative sources** (do not guess):
   - For cycle `major` values: `a4/core/inspection_data.py::summary` lines 224-228 (NOT the abstract zone names — those don't tell you the integer).
   - For mutation-kind applicability rules: `a4/core/inspection_data.py::get_valid_steps_for_kind` lines 147-215.
   - For schema field names of any v2 table: `a4/standalone/coverage_db.py::_init_schema` (after Phase 1's additions, around lines ~XXX — grep for `bandit_decisions` etc.).
6. **Tests come WITH code, not after**. For every new class, write at least 5 unit tests using synthetic data (no host binary). Use the `_make_cycle` helper pattern from `test_zone_classifier.py`.
7. **NEVER use** `subprocess.run(["risc0-host", ...])` from a unit test — it requires the rust binary and is slow. Use synthetic `InspectionData(cycles=[...], all_txns=[], reg_txns=[])` instead.
8. **Run the fast test suite after every major code change**, not just at the end. Aim for sub-minute iterations.

### After the phase

9. Write the retrospective in `a4/docs/cloud1/phases/PHASE_N_*.md`. **It MUST start with a "TL;DR" section** (plain-English explanation, ≤3 paragraphs, how it fits into cloud1) and include:
   - Tasks-completed checklist
   - Exit-criteria status table
   - **Consistency check against ProG_Report_2.md** (table mapping Pro recs → implementation → ✅/⚠️/❌)
   - Files touched (new vs modified)
   - Decisions made/locked in this phase
   - 1-sentence preview of next phase
10. Update `a4/docs/cloud1/CLOUD1_STATUS.md`: change phase status to `✅ DONE`, add brief note.
11. If you made any choice not in Pro's report OR not already in `CLOUD1_DECISIONS_FOR_PRO_R2.md`, **add a new D-decision to that file** with: Pro spec / Our choice / Type (P/P-range/U) / Reasoning.
12. Run the full fast suite one final time. If anything regressed, FIX before declaring done.

---

## Hard rules — violating these breaks the plan

| Rule | Why |
|---|---|
| DO NOT modify `a4/core/*.py` | Inspection/parsing layer is frozen. Talk to a human before changing. |
| DO NOT regenerate or rewrite any file in `a4/runs/iv_pos_5/` | IV.POS.5 is the historical baseline Pro reviewed. Read-only. |
| DO NOT delete or rewrite `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` | D12: historical record. New diagnostics go in `iv_pos_7/`. |
| DO NOT add new mutation kinds, new guests, or change `N` from 6000 | Pro §11 — change order is: selector fix → re-run sha2-host → THEN guest expansion. |
| DO NOT amend or delete prior commits | Use new commits only. Existing history is the audit trail. |
| If a test is slow (>30s), DO NOT run it during iteration | Add it to the ignore list temporarily; only run before-and-after the phase. |
| DO NOT install new pip dependencies without permission | We're on POS servers with locked envs; pin everything. |

## Markdown ownership rules (NEW — read carefully)

**Composer is NOT allowed to edit Opus-owned markdowns.** This rule is enforced because:
- The audit trail must have two distinct voices: Composer's "here's what I built" vs Opus's reviewed "here's what passed review".
- If Composer edits an Opus-owned doc directly, we lose the diff that reveals Opus's review value-add.

### Opus-owned (DO NOT EDIT if you are Composer)

- `a4/docs/cloud1/CLOUD1_AGENT_ONBOARDING.md` (this file)
- `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md`
- `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md`
- `a4/docs/cloud1/CLOUD1_STATUS.md`
- `a4/docs/cloud1/ProG_Report_2.md`
- `a4/docs/cloud1/phases/PHASE_*.md` (any file here — these are the OFFICIAL retrospectives Opus writes)
- `a4/docs/precloud/**`
- `a4/runs/iv_pos_5/**`

### Composer-owned (you CAN edit if you are Composer)

- `a4/docs/cloud1/composer/PHASE_N_COMPOSER_SUMMARY.md` — your per-phase summary (template in `composer/README.md`)
- `a4/docs/cloud1/composer/PROPOSED_DECISIONS.md` — D-decision proposals; Opus moves accepted ones into `CLOUD1_DECISIONS_FOR_PRO_R2.md`
- `a4/docs/cloud1/composer/NOTES.md` — free-form scratch space if useful
- Anything new you create under `a4/docs/cloud1/composer/`
- Code under `a4/standalone/` (with the test/regression discipline below)
- Tests under `a4/standalone/tests/`

### After Composer's phase: Opus does the markdown work

1. Composer writes `composer/PHASE_N_COMPOSER_SUMMARY.md`.
2. Opus reads code + summary, runs tests, applies the skeptical review protocol (next section).
3. Opus writes the OFFICIAL `phases/PHASE_N_*.md` retrospective from scratch (NOT a copy of Composer's summary — a synthesis after review).
4. Opus updates `CLOUD1_STATUS.md` and any D-decisions in `CLOUD1_DECISIONS_FOR_PRO_R2.md`.
5. Composer's `PHASE_N_COMPOSER_SUMMARY.md` stays in the composer/ folder as the audit-trail record of what Composer claimed before review.

## Skeptical-review protocol (Opus uses this when reviewing Composer's phases)

The point of dual-agent work is two independent eyes on the same problem. To make that real, Opus follows this protocol BEFORE looking at Composer's diff:

1. **Re-read** the phase doc and the cited Pro sections. Do NOT look at the code Composer wrote yet.
2. **Write down what I would have done** for each major design decision (data structures, function signatures, control flow, test strategy). Aim for 5-10 bullet points.
3. **Now read Composer's code**, marking each design choice as:
   - ✅ same as what I'd have done (or better — be honest about cases where Composer's choice is cleaner)
   - ⚠️ different but defensible (note the difference)
   - ❌ wrong / worse / inconsistent (file a follow-up task)
4. **Run all tests** Composer wrote. Then write 3-5 ADDITIONAL adversarial tests probing edge cases Composer might not have considered. If any new test fails, that's a ❌.
5. **Read Composer's `PHASE_N_COMPOSER_SUMMARY.md`** and check for:
   - Honest description of choices (not just "I implemented the plan")
   - All silent-on-Pro choices flagged for D-decision review
   - Test results pasted verbatim
   - Self-flagged uncertainties
6. **Write the official retrospective** in `phases/PHASE_N_*.md` integrating: what landed, what was reviewed, what was changed by review, any new D-decisions, the consistency-check-against-Pro table.

Tripwire revisited: if step 3 produces more ❌ than ⚠️, OR step 4 finds a bug in Composer's tests, OR step 5 reveals Composer hid a silent choice — log it, fix it, and reassess after 1 more phase. Two consecutive triggers → revert to Opus-only.

---

## Soft conventions

- Python style: 4-space indent, type hints on public functions, dataclasses for value types (use `frozen=True` when hashable matters).
- Docstrings: explain WHY, not WHAT. Reference `ProG_Report_2.md §X.Y` whenever a design choice was directed by Pro.
- Test naming: `test_<unit>_<scenario>_<expected_outcome>`. Use `pytest` fixtures over module-level setup.
- File headers: include 1-paragraph module docstring linking to the relevant Pro section.

---

## Quick-reference: what's done and what's next

| Phase | Status | Key artifacts |
|---|---|---|
| 0 — Freeze & Setup | ✅ DONE | `CLOUD1_*` docs, strategy renaming |
| 1 — Schema | ✅ DONE | 3 new dataclass modules + 8 new SQLite tables |
| 2 — Semantic Zone Sampler | ✅ DONE | `zone_classifier.py`, `semantic_arm_universe.py`, `SemanticZoneStepSelector` |
| 3 — Compressed Global Ctx | ⚪ NEXT | `compressed_global_extractor.py` (compose with Hook 3 output) |
| 4 — Reward Redesign | ⚪ pending | additive reward: `L_new + F_new + G_new + S_new + crash_term + repeat_term` |
| 5 — Constrained TS Bandit | ⚪ pending | `ConstrainedTSScheduler` with 55/45 floor/adaptive split + Beta(1,1) prior |
| 6 — Extended Logging | ⚪ pending | wire `record_*` methods into the fuzzer loop |
| 7 — Local Smoke Tests | ⚪ pending | N≤200 runs on real `sha2-host`; validate plumbing end-to-end |
| 8 — IV.POS.7 Campaign | ⚪ pending | 5 variants × 10 seeds × N=6000 on POS |
| 9 — Report for Pro R2 | ⚪ pending | new diagnostic doc with cTS_semantic_v2 results |

---

## Useful shell aliases (set these at session start)

```bash
cd /root/arguzz                       # workspace root (always operate from here)
# Fast iteration test cmd:
alias pft='timeout 60 python -m pytest a4/standalone/tests/ -q --tb=line --ignore=a4/standalone/tests/test_pilot_calibration.py --ignore=a4/standalone/tests/test_run_replicates.py --ignore=a4/standalone/tests/test_determinism.py --ignore=a4/standalone/tests/test_phase02_baseline.py --ignore=a4/standalone/tests/test_instr_word_mod_sur.py --ignore=a4/standalone/tests/test_baseline_touch.py --ignore=a4/standalone/tests/test_touch_coverage.py'
# Full suite (slow, ~5 min):
alias pall='timeout 600 python -m pytest a4/standalone/tests/ -q --tb=line'
```

---

## Asking for clarification

If you encounter ANY of these, STOP and ask:
- A `D` decision in `CLOUD1_DECISIONS_FOR_PRO_R2.md` you don't understand.
- An ambiguity in `ProG_Report_2.md` (Pro's wording).
- A conflict between Pro's spec and what the existing code does.
- A test that fails for a reason you can't explain.
- A choice not covered by the plan or this onboarding doc.

Do not "make it work" by inventing an undocumented decision. Every silent-on-Pro choice MUST go through the D-decision process.

---

## Final sanity check before declaring a phase done

1. Did you write a TL;DR at the top of the retrospective?
2. Did all fast tests pass?
3. Did you update `CLOUD1_STATUS.md`?
4. Did you log every new D-decision in `CLOUD1_DECISIONS_FOR_PRO_R2.md`?
5. Did you do a final consistency check against `ProG_Report_2.md`?
6. Did you avoid modifying anything in `a4/core/`, `a4/runs/iv_pos_5/`, or `a4/docs/precloud/`?

If yes to all 6, you're done. Otherwise, finish what's missing.
