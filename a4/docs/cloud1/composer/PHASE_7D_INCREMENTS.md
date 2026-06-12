# Phase 7d — Incremental Work Plan for Composer

**Purpose:** Phase 7d has 16 audits (A1-A5, B1-B12, E1-E4). That's too
many to do in one batch. This document breaks the work into **6
increments**, each with its own gate, expected runtime, and report-back
checkpoint. After each increment, Composer reports results to user/Opus
and waits for green-light before starting the next increment.

**Source-of-truth specs:**
- Audit specifications: `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md`
- Canonical arm matrix: `a4/docs/cloud1/EXPECTED_ARMS.md`
- High-level brief: `a4/docs/cloud1/composer/PHASE_7D_COMPOSER_BRIEF.md`

**One rule:** do not start increment N+1 until increment N reports green
to user/Opus. We want to catch problems early, not at the end.

**On Composer's recently-closed Task 3/4/5:**
- **Task 3 (V5 N=200 validation) — ACCEPTED.** Bug A/B fixes confirmed
  working (200 mutations, 0 skips, 48 warm arms, mode-split exactly
  matches expected math: 48×3=144 cold, 56 remaining = 44 floor + 12
  singleton). Use this as runtime evidence in Increment 0's report.
- **Task 4 (G2 verifier 24/24) — REJECTED as G2 closure.** Same rev2 result
  Opus already critiqued: the `if original_value:` short-circuit silently
  skips the old-value check on 21/24 word-mutating samples; the
  INSTR_TYPE_MOD id=12 step=0 cycle-shift bug is not detected. G2 STAYS
  OPEN until Audit B1 with strict mode + uniform `original_value` passes.
  Do NOT mark G2 closed.
- **Task 5 (compressed_global 0 → 37) — ACCEPTED provisionally.** Fix
  works empirically; Audit B10 will formally verify regions are bucketed
  per the new D8 map. Move forward.

---

## Increment 0 — Pre-fixes (REQUIRED before any 7d.2 audit)

**Goal:** land the three architectural pre-fixes that B-audits depend on.

| # | Pre-fix | Files | Acceptance check |
|---|---|---|---|
| P1 | Verifier strict mode | `a4/tools/verify_mutation_semantics.py` | `if original_value:` → `if original_value is not None:`; add `hook.old_major/minor == config._info.original_major/minor` for INSTR_TYPE_MOD; re-run on Phase 7c rev2 sample set — expect ≥ 1 FAIL (do NOT relax) |
| P2 | Uniform `original_value` recording | all 8 `a4/standalone/mutations/*.py`, `coverage_db.py`, `fuzzer.py` | every `create_config()` puts pre-mutation value in `_info["original_value"]`; new DB column `mutations.original_value`; migration test passes; on fresh N=50 smoke, `COUNT(*) WHERE original_value = 0 AND kind != 'INSTR_TYPE_MOD'` ≤ 10% |
| P3 | D40 multi-cycle disambiguation | `a4/standalone/semantic_arm_universe.py` (option b — preferred) OR Rust + `fuzzer.py::_create_mutation` (option a) | choose option (b) unless it drops > 4 arms; document choice as D40; after fix, A3 produces ≥ 44 arms; the INSTR_TYPE_MOD id=12 step=0 case stops appearing in universe |

**Plus**: remove the dead-code `_PHANTOM_ARMS_PRODUCTION_TRACE` frozenset in `semantic_arm_universe.py` (Composer originally added this but the per-step pruning supersedes it; keep only for git history).

**Estimated time:** 4-6 hours.

**Gate:** all 3 pre-fixes land + full existing fast test suite passes (382+ tests) + A1/A2/A3 still PASS after pre-fixes land (re-run them; Opus has the scripts at `a4/audits/A{1,2,3}_*.py`).

**Report back:** `composer/PHASE_7D_INC0_REPORT.md` — what option for D40 you picked + arm count after fix + verifier strict-mode results on 24 old samples (expect failures; document them).

**Stop here.** Wait for Opus review before starting Increment 1.

---

## Increment 1 — Semantics & arms (7d.1: A4, A5, E1, E3)

**Goal:** prove the arm space and zone classifier are SEMANTICALLY correct, not just internally consistent.

| # | Audit | Script | Estimated time |
|---|---|---|---|
| A4 | Universe completeness | `a4/audits/A4_universe_completeness.py` (new, ~50 LOC) | 1 hr to write + 30 sec to run |
| A5 | Canonical match | `a4/audits/A5_canonical_match.py` (new, ~80 LOC, parses `EXPECTED_ARMS.md`) | 2 hr write + 1 min run |
| E1 | Instruction decoding | `a4/audits/E1_instruction_decode.py` (new, ~150 LOC, uses `a4/core/insn_decode.py`) | 3 hr write + 1 min run |
| E3 | Multi-classification probe | `a4/audits/E3_multi_classification_probe.py` (new, ~100 LOC) + `composer/PHASE_7D_E3_REVIEW.md` (manual write-up after running) | 2 hr write + 30 min run + 1 hr manual review with user |

**Acceptance per audit:**

- **A4**: zero (kind, step) tuples where `get_targets_at_step` returns truthy but the step isn't reachable through `arms[(kind, zone)]`.
- **A5**: universe builder output matches `EXPECTED_ARMS.md` exactly (arm presence) + step counts within tolerance. Includes alternate inputs (`--in1 1 --in4 1`, `--in1 100 --in4 100`) per `EXPECTED_ARMS.md`'s "TO BE FILLED" sections.
- **E1**: ≥ 500 random cycles independently decoded; cycle.major matches RV32IM decode in 100% of cases. **Major=7 (CONTROL0) classification report** emitted — Composer hands the report to user/Opus for the MRET-detection question (Q8 in `EXPECTED_ARMS.md`).
- **E3**: dossier produced for every 🟡 arm in `EXPECTED_ARMS.md`. Composer + user run through each one (1-hr session) and decide KEEP/RECLASSIFY/SPLIT/NOOP. Updated `EXPECTED_ARMS.md` has zero 🟡 rows remaining.

**Gate (7d.1 closes):** A4, A5, E1, E3 all PASS. `EXPECTED_ARMS.md` updated with 🟢/🔴 (RECLASSIFY) statuses. Composer writes `composer/PHASE_7D1_REPORT.md` with the audit results + the E3 adjudication decisions.

**Estimated total time:** 1-2 days.

**Report back:** the report + adjudication doc. Wait for Opus review.

---

## Increment 1.5 — HYBRID zone-classifier + Theme 6 investigation (D50, D53, D54, D55/Theme 6)

**Goal:** implement the joint-review decisions that came out of Inc 1's E3 adjudication. After this, the universe is HYBRID-correct and Inc 2 can start with confidence.

**Full work order:** `composer/PHASE_7D_INC1_5_WORK.md`. The high-level tasks:

| # | Task | Reference | Estimated time |
|---|---|---|---|
| 1 | Implement D50 — split `core_div` into `core_div` (DIV/REM, minor∈{4-7}) + `core_shr` (SRL/SRA, minor∈{0-3}) in `semantic_zones.py` + `zone_classifier.py` | D50 in DECISIONS file | 30 min |
| 2 | Implement D53 — redefine `post_ecall` in `zone_classifier.py` as "smallest k ∈ [1,5] where step e+k's Decode cycle is at user PC" | D53 + `audit_output/E6_post_ecall_window_evidence.json` | 1 hr |
| 3 | Implement D54 — add `kernel_other` zone in `semantic_zones.py`; insert into zone_classifier with precedence 4 (after singletons + pre_ecall/post_ecall, before core_*); user/kernel PC ranges from GLOSSARY | D54 + `audit_output/E7_kernel_contamination_survey.json` | 2 hr |
| 4 | Re-run A3 / A4 / A5 on new universe; expect ~50-52 arms (48 + core_shr + kernel_other × kinds), with ~357 steps in kernel_other family across applicable kinds | existing scripts | 30 min |
| 5 | Regenerate EXPECTED_ARMS.md baseline section with new arm table + tolerances. Move 4 D40-dropped arms to "Expected-DROPPED" section per D47. Remove the "PRE-HYBRID" disclaimer block. | EXPECTED_ARMS.md | 1 hr |
| 6 | Run E3b — characterize MEM_VAL_MOD on non-memory majors (Theme 6). Output: `audit_output/E3b_mem_val_non_memory_majors.json` with per-step txn_type breakdown for 848 `core_arithmetic` + 34 `core_mul` MEM_VAL_MOD steps | D55 / Theme 6 | 2 hr |
| 7 | Verify B6/E2 prerequisites still hold (no regressions in reward_v2 or bandit behavior for the renamed/reclassified arms) | existing fast tests | 30 min |
| 8 | Write `composer/PHASE_7D_INC1_5_REPORT.md` with all 7 acceptance gates | this doc | 1 hr |

**Acceptance gates (must all PASS before Inc 2):**
- A3: new universe arm count is within `[42, 60]` (sanity bounds; the EXPECTED_ARMS.md ≤60 invariant). The semantically meaningful check is A5 below — A3's only job is to produce the regenerated arm list.
- A4: every arm has `success_rate == 1.0`.
- A5: regenerated EXPECTED_ARMS.md matches actual A3 output with 0 add/remove violations and 0 step-count violations. **A5 is the binding gate — if A3 produces a surprising count, the question is "does A5 still pass against the regenerated EXPECTED_ARMS?" not "does A3 hit a magic threshold?"**
- E6 re-verification: `post_ecall` arm step count matches `len([e for ecall_step e in trace if first_user_pc_offset(e) is not None])`.
- E7 re-verification: `kernel_other` arm step count ≈ 357 (E7's prediction, ±5%).
- E3b: dossier produced for both `MEM_VAL_MOD|core_arithmetic` and `MEM_VAL_MOD|core_mul` arms.
- Full fast test suite still passes (382+).

**Estimated total time:** ~8-10 hours (1 work day).

**Report back:** `composer/PHASE_7D_INC1_5_REPORT.md`. Wait for Opus review before starting Increment 2.

---

## Increment 2 — Local 7d.2 audits, low-mutation set (B3, B5, B6, B9, B10, E2)

**Full work order:** `composer/PHASE_7D_INC2_WORK.md` (added 2026-06-09 after Inc 1.5 closure).

**Goal:** verify mathematical correctness of bandit/reward/coverage code paths + DB schema + compressed-global end-to-end. These don't require running many mutations.

| # | Audit | Script | Estimated time |
|---|---|---|---|
| B3 | Bandit math (property-based) | `a4/standalone/tests/test_bandit_property.py` | 3 hr write + ~5 min pytest |
| B5 | Reward formula routing | `a4/audits/B5_reward_formula_routing.py` (~60 LOC) + per-variant N=10 smoke | 2 hr write + 10 min run |
| B6 | Coverage-delta correctness | `a4/audits/B6_coverage_delta.py` (~100 LOC) + N=20 instrumented smoke | 3 hr write + 5 min run |
| B9 | DB schema integrity | `a4/audits/B9_db_schema_integrity.py` (~80 LOC) | 2 hr write + 1 min run |
| B10 | Compressed-global e2e | `a4/audits/B10_compressed_global_e2e.py` (~80 LOC) | 2 hr write + 1 min run |
| E2 | Failure-class fingerprinting | `a4/audits/E2_arm_bite.py` (~120 LOC) + ~250 mutations (5 per arm × 48) | 3 hr write + 30 min run |

**Acceptance per audit:** see `PHASE_7D_ARCHITECTURE_AUDIT.md`. All exit 0.

**Gate (Inc 2 closes):** B3, B5, B6, B9, B10 all PASS. E2 produces report (informational; only fails if > 5 arms produce 0 failures across 5 mutations each).

**Estimated total time:** 2-3 days.

**Report back:** `composer/PHASE_7D_INC2_REPORT.md` with per-audit summary + the E2 arm-bite report (which arms have weak/no signal).

---

## Increment 3 — 7d.2 fidelity audits (B1, B2, B4, B7) — **POS REQUIRED for B1**

**Full work order:** `composer/PHASE_7D_INC3_WORK.md` (added 2026-06-10 after Inc 2 closure).

**Goal:** prove that for every mutation, the bandit's selected arm equals the executed arm equals the DB-recorded arm equals the hook-emitted arm equals the reward-attributed arm. **This is the audit that GIVES YOU 100% CONFIDENCE.**

| # | Audit | Script | Mutation count | Estimated time |
|---|---|---|---:|---|
| B1 | Hook fidelity (strict) | `a4/audits/B1_hook_fidelity.py` (NEW; orchestrator) + existing `verify_mutation_semantics.py` strict mode | 5 variants × 200 = **1000** | 3 hr write + 45 min POS wall |
| B2 | Multi-cycle replay (D40 verification) | `a4/audits/B2_multicycle_replay.py` (~80 LOC) | 0 (universe query only; reuses B1 output) | 1.5 hr write + 5 min run |
| B4 | Bandit → DB traceability | `a4/audits/B4_bandit_db_traceability.py` (~150 LOC) + guarded `--debug-bandit-trace` flag | 5 variants × N=50 = **250** | 4 hr write + 30 min run (local or POS) |
| B7 | Same-seed reproducibility | `a4/audits/B7_seed_reproducibility.py` (~100 LOC) | 5 variants × 2 paired runs × N=50 = **500** | 2 hr write + 1 hr run (local or POS) |

**Inc 3 total mutation budget: 1750 host mutations** (1000 B1 + 250 B4 + 500 B7).

**POS guidance** (NEW policy added Inc 3 from Inc 2 lessons):
- **B1 MUST run on POS** — 1000 sequential local mutations is ~10 hr; POS 5-way is ~45 min wall.
- **B4 and B7 may run locally OR on POS** — both are < 60 min wall locally if no other host audit is running concurrently.
- **No two host-heavy audits run concurrently** on the same node (Inc 2 E2 was starved when run alongside B5/B6/B9).
- Manifest skeleton: `a4/pos/manifests/pos_audit_b1.json` (Composer creates from work order spec).

**Acceptance per audit:** see `PHASE_7D_ARCHITECTURE_AUDIT.md`. All exit 0. Specifically:
- B1: 1000/1000 PASS with strict mode, per-variant stratification documented.
- B2: D40 multi-cycle disambiguation verified; 4 D40-dropped arms confirmed absent from V5 universe; 0 multi-cycle violations in B1's 1000 mutations.
- B4: 250/250 mutations have all 6 source tuples agreeing (bandit / executor / DB / hook / bandit_decisions / mutation_rewards).
- B7: zero diff between paired runs (modulo the A1 non-det allow-list and the `executed_at` timestamp).

**Gate (Inc 3 closes):** B1, B2, B4, B7 all PASS + fast tests still ≥ 472.

**Estimated total time:** ~2-3 days (mostly script-writing + POS wall + report-writing; mutation execution is ~3 hours total wall when POS-parallelized).

**Report back:** `composer/PHASE_7D_INC3_REPORT.md`.

---

## Increment 4 — POS audits (B8, B11, B12)

**Goal:** verify that the architecture also works at scale and under parallel execution (POS scenarios).

| # | Audit | POS strategy | Estimated POS time |
|---|---|---|---|
| B8 | Concurrent isolation | dispatch 5 sequential + 5 parallel runs at N=50, diff DBs | 1 hour POS wall (run-overlap permitting) |
| B11 | Scale stress | dispatch 5 variants × N=500 + re-run B1+B4+B9 on resulting DBs | 6 hours POS wall |
| B12 | Multi-input robustness | re-run A1/A2/A3/A4/A5/B1/B4/B9 with `--in1 1 --in4 1` and `--in1 100 --in4 100` (POS or local) | 2-3 hours POS or 4 hours local |

**Acceptance:** see `PHASE_7D_ARCHITECTURE_AUDIT.md`. All exit 0.

**Special note for B12:** since the alternate inputs may unlock arms not present in baseline (e.g., `core_other` if BigInt is involved), Composer fills in the alternate-input sections of `EXPECTED_ARMS.md` BEFORE B12 runs (use A3 to generate the new arm table; manually adjudicate any new 🟡 arms following E3's process).

**Gate (Inc 4 closes):** B8, B11, B12 all PASS.

**Estimated total time:** 1-1.5 days POS + 4 hr local prep.

**Report back:** `composer/PHASE_7D_INC4_REPORT.md` with POS dispatch IDs and acceptance.

---

## Increment 5 — Per-arm evidence pack (E5) + Final review (E4) + report

**Goal:** produce the user-readable per-arm evidence files (E5), close out E4, write the Phase 7d wrap-up.

E5 is the audit the *user* reads. Without it, "all audits passed" is just trust; with it, the user has a concrete worked example per arm that they can spot-check independently. **E5 reuses code from B1 (verifier) and B4 (traceability)**, so Composer is not building anything new — just orchestrating per-arm output.

| Task | Owner | Output |
|---|---|---|
| Implement `a4/audits/E5_per_arm_evidence.py` | Composer | ~250 LOC; reads B1's verifier + B4's joined-trace dataframe; writes per-arm .md |
| Run E5 on 48 baseline arms | Composer | `audit_output/per_arm_evidence/<kind>_<zone>.md` × 48 + `README.md` index |
| Spot-check each evidence file uses GLOSSARY-correct variable labels | Composer self-review | per-file checklist in `composer/PHASE_7D_E5_SUMMARY.md` |
| Identify 1 CORRECT + (if exists) 1 INCORRECT row per arm | Composer | populated in each .md as "EXAMPLE 1 / EXAMPLE 2" |
| Generate stub evidence files for the ~49 multi-guest-only arms | Composer | one .md per non-exercised (kind, zone) pair noting "NOT EXERCISED — see PHASE_7D_ARCHITECTURE_AUDIT.md §6.3" |
| Maintain E4 review queue throughout Inc 1-4 | Composer | `composer/PHASE_7D_REVIEW_QUEUE.md` |
| Adjudicate remaining PENDING items (joint review session) | Composer + user + Opus | DECIDED / DEFERRED / REJECTED labels |
| Write `PHASE_7D_FINAL_REPORT.md` | Opus | summary of all 17 audit results + final 🟢 EXPECTED_ARMS.md status + E5 verdict summary + ready-for-Phase-8 attestation |
| Update CLOUD1_STATUS.md | Opus | Phase 7d → ✅ DONE; Phase 8 → ⚪ READY |

### E5 spec recap (full in PHASE_7D_ARCHITECTURE_AUDIT.md §E5)

Per arm: 50 stratified mutations (or all if arm has < 50 steps). Each mutation logs:

1. **The arm's CLAIM** — zone meaning + kind's allowed majors.
2. **The actual trace at this step** — cycle.major/minor/pc, all txns, with variable names + units defined inline.
3. **Independent re-decode of the instruction** — does it match cycle.major/minor?
4. **The mutation applied** — config + hook stdout + does hook.old == baseline.txn.word?
5. **The outcome** — exit code, failures, reward_v2 components.
6. **Verdict** — ✓ CORRECT or ✗ INCORRECT with 2-3 sentence justification.

Each evidence .md must reference the variable definitions in `a4/docs/cloud1/GLOSSARY.md` (or repeat them inline) so the user never has to guess what a field means.

### E5 acceptance gate

- 48 files exist for kept arms, each with EXAMPLE 1 populated.
- N (CORRECT) ≥ N (INCORRECT) per arm.
- Zero arms with ✗ INCORRECT aggregate verdict (any ✗ aggregate ⇒ E4 review session before exit).
- Top-level `audit_output/per_arm_evidence/README.md` is a one-page table of all 48 arms with ✓/⚠/✗ status and clickable links.

**Estimated E5 time:** 4-6 hr write + ~3 hr run (50 × 48 = 2400 mutations) + 1-2 hr Composer self-review.

**Gate (7d closes; Phase 8 unblocks):** all audits green, E5 evidence pack complete and user-reviewed, all E4 items resolved, final report written, status updated.

---

## Estimated total Phase 7d time

| Increment | Status | Time |
|---|---|---|
| 0 — Pre-fixes | ✅ DONE | 4-6 hours |
| 1 — Semantics audits | ✅ DONE | 1-2 days |
| 1.5 — HYBRID classifier + Theme 6 | ✅ DONE | ~1 day |
| 2 — Math/schema audits (B3/B5/B6/B9/B10/E2) | ✅ DONE (2026-06-10) | 2-3 days |
| 3 — Fidelity audits (B1/B2/B4/B7) | 🟡 NEXT | 2-3 days (POS for B1) |
| 4 — POS audits (B8/B11/B12) | ⚪ | 1-1.5 days (POS-bound) |
| 5 — E5 evidence pack + E4 wrap-up | ⚪ | 1 day |
| **Total** | | **8-11 days** (parallelizable across Composer + Opus; with no parallelism: ~11 days) |

For comparison: Phase 8 IV.POS.7 is N=6000 × 5 variants × 10 seeds = 300,000 mutations spread across multiple days on POS. Spending 6-9 days on Phase 7d to ensure those Phase 8 results are interpretable is a clear win.

---

## How to report back per increment

Each `PHASE_7D_INC{N}_REPORT.md` should have:

1. **Per-audit verdict** (PASS / FAIL / DEFERRED, with the actual numbers).
2. **Any new findings** (e.g., new 🟡 arm uncertainties discovered, surprising failure-class results, unexpected DB drift).
3. **Decisions taken** (any D-numbered decisions; flag for Opus review).
4. **Open items for next increment** (carry-overs into the E4 queue).
5. **One-line ready-to-proceed statement** (e.g., "Inc 1 is green; please confirm to start Inc 2.").

Opus will reply with a green-light or specific corrections.
