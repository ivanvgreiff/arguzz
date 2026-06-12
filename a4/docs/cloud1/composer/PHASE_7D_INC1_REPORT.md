# Phase 7d Increment 1 Report

## TL;DR

Increment 1 audits **A4, A5, E1, E3** are implemented and run on `c0c1_differential_guest` @ `--in1 5 --in4 10`. Acceptance gate **passes** for Inc 1 deliverables: A4 (44/44 arms have targets), A5 (44 arms match EXPECTED_ARMS adjusted for D40 −4), E1 (31 decode mismatches routed to E4 — do not block Inc 1), E3 (22 🟡 dossiers ready). **`EXPECTED_ARMS.md` not updated** — pending joint review session per instructions.

## Per-audit results

| Audit | Verdict | Output file | Notes |
|---|---|---|---|
| A4 | PASS | `a4/audits/audit_output/A4_module_targets.json` | 44 arms, 3 samples/arm, `n_arms_zero_targets=0`, all `success_rate=1.0` |
| A5 | PASS | `a4/audits/audit_output/A5_canonical_diff.json` | actual=44; 4 removed arms all D40-explained; 0 added; 0 step-count violations |
| E1 | PASS (informational) | `a4/audits/audit_output/E1_decode_ground_truth.json` | 4 arms below 95% match rate; 31 mismatches → `composer/PHASE_7D_REVIEW_QUEUE.md` |
| E3 | PASS | `a4/audits/audit_output/E3_uncertain_review.json` | 22 🟡 dossiers with 5 sample steps + draft verdicts each |

### A4 — Mutation module targets

- Script: `a4/audits/A4_mutation_module_target.py`
- Every arm: 3 random steps (seed=42), `get_targets_at_step` returns valid target with txn metadata.
- Summary: `{n_arms: 44, n_arms_success_rate_lt_1_0: 0, n_arms_zero_targets: 0}`

### A5 — Canonical match

- Script: `a4/audits/A5_canonical_match.py`
- Parsed 48 kept arms from `EXPECTED_ARMS.md` baseline table (fixed `\|` escaping in parser).
- **D40 adjustment:** 4 arms in doc but not in universe — all explained:

| removed arm | reason |
|---|---|
| INSTR_WORD_MOD_FULL\|last_step | D40 multi-cycle filter (Inc 0) |
| INSTR_WORD_MOD_FULL\|pre_ecall | D40 multi-cycle filter |
| INSTR_WORD_MOD_SUR\|last_step | D40 multi-cycle filter |
| INSTR_WORD_MOD_SUR\|pre_ecall | D40 multi-cycle filter |

- Remaining 44 arms: presence match + step counts within tolerance (🟡 arms use ±20%).

### E1 — Instruction decode ground truth

- Script: `a4/audits/E1_instruction_decode_ground_truth.py`
- First 10 steps per arm; independent `decode_insn_word` vs trace `(major, minor)`.
- **40/44 arms ≥95%** match rate on checked cycles.
- **4 arms below 95%:**

| arm | matches/checked | pattern |
|---|---|---|
| INSTR_TYPE_MOD\|pre_ecall | 0/10 | ECALL steps: trace major=8, decode major=7 (ECALL0 vs Eany) |
| MEM_VAL_MOD\|pre_ecall | 0/10 | same ECALL boundary pattern |
| MEM_VAL_MOD\|core_branch | 0/10 | major=7 minor mismatches (funct3 vs trace minor) — Q4 |
| MEM_VAL_MOD\|last_step | 0/1 | step 3929 ECALL 8-vs-7 pattern |

- Mismatches recorded in `composer/PHASE_7D_REVIEW_QUEUE.md` (DECODE_MISMATCH DM-1..DM-5).

### E3 — Uncertain arm review

- Script: `a4/audits/E3_uncertain_arm_review.py`
- 22 🟡 rows from `EXPECTED_ARMS.md`; 5 sample steps each with `classifier_reasoning` chain (Rules 1/2/3/6 per `zone_classifier.py`).
- **4 arms** no longer in universe (D40): draft verdict `DROP_D40`.
- **18 arms** in universe: draft `KEEP_PENDING_REVIEW` or `KEEP_PENDING_E2` / `KEEP_PENDING_E1`.
- Full JSON: `audit_output/E3_uncertain_review.json`

## EXPECTED_ARMS adjudication summary (proposed — pending joint review)

| Category | Count | Proposed action after joint review |
|---|---|---|
| 🟡 in universe | 18 | Adjudicate KEEP vs RECLASSIFY per E3 dossier |
| 🟡 D40-dropped | 4 | Move to Expected-DROPPED; update doc count 48→44 |
| E1 ECALL 8-vs-7 mismatches | 3 arms | Accept as taxonomy difference; document in D45/GLOSSARY |
| E1 core_branch minor mismatches | 1 arm | Joint review Q4 — keep or reclassify `MEM_VAL_MOD\|core_branch` |

**Do not update `EXPECTED_ARMS.md` until joint review completes.**

## New findings

1. **EXPECTED_ARMS.md parser** must normalize `COMP_OUT_MOD\|zone` escaped pipes — fixed in `audit_common.py`.
2. **E1 ECALL boundary:** steps with `cycle.major=8` (ECALL0) decode as `major=7` (Eany) from instruction word — systematic, not random trace corruption. Affects pre_ecall / last_step ECALL singletons.
3. **MEM_VAL_MOD\|core_branch:** 24 steps classified via Rule 6 `major=7 → core_branch`; E1 shows minor decode mismatches on all 10 sampled steps — ties to Q4 open question.

## Decisions to flag

- **D40 doc sync:** `EXPECTED_ARMS.md` still says 48 arms / lists 4 D40-removed arms as kept — update in joint review to match 44-arm reality (no new D-number; extends D40).
- **E1 ECALL exclusion:** propose excluding `major=8` cycles from strict decode-match gate (document for Inc 3 B1).

## Open items carried over

- E4 queue: `composer/PHASE_7D_REVIEW_QUEUE.md` (5 DECODE_MISMATCH groups + 22 UNCERTAIN_ARM)
- G2 still OPEN until B1 (Inc 3)
- D42 MEM_VAL nondet allow-list not applied (Inc 2+ scope)

## Acceptance gate self-check

- [x] A4 exit 0; every arm `success_rate > 0`; no zero-target arms
- [x] A5 exit 0; zero unexpected diffs (4 removals D40-explained)
- [x] E1: 4 arms below 95% — mismatches in E4 queue; does not block Inc 1
- [x] E3: all 22 🟡 arms have draft verdicts in JSON
- [x] `_meta.definitions` + GLOSSARY link in all four JSON outputs (D45)
- [ ] Joint review session — **NOT DONE** (required before Inc 1 closure / EXPECTED_ARMS update)

## Ready-to-proceed statement

Increment 1 audit **implementation and self-checks are green**. **Requesting joint review session** to adjudicate 22 🟡 arms and E1 DECODE_MISMATCH items before claiming 7d.1 fully closed and before starting **Increment 2** (B3, B5, B6, B9, B10, E2).

**STOP** — awaiting joint review + Opus GREEN to Inc 2.
