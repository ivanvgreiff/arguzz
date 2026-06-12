# Phase 7d — Master Orchestration (Chronological Plan)

**Purpose:** the single source-of-truth chronological timeline for Phase 7d.
Read this BEFORE starting any audit work.

**You are here:**

```
Phase 0-6 ──> Phase 7 ──> [Phase 7d ← YOU ARE HERE] ──> Phase 8 ──> Phase 9 ──> [Phase 10 deferred]
   DONE       SUPERSEDED      🟡 ACTIVE                  BLOCKED    PENDING       DEFERRED
                              Inc 0 next                  on 7d      on 8         post-8
```

**Phase 10** (multi-guest semantic-label generality) is documented as deferred
in `CLOUD1_STATUS.md` row 10 and `PHASE_7D_ARCHITECTURE_AUDIT.md §6`. It does
NOT gate Phase 8.

---

## Key documents (read these once, in order)

| # | Document | Read for |
|---|---|---|
| 1 | `a4/docs/cloud1/CLOUD1_STATUS.md` | Master phase status; where 7d sits in cloud1 |
| 2 | `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` | Locked decisions (D1-D45) — especially D40, D41, D42, D43, D44, D45 |
| 3 | `a4/docs/cloud1/GLOSSARY.md` | **REQUIRED**: every variable name, abbreviation, magic number used in audit output |
| 4 | `a4/docs/cloud1/EXPECTED_ARMS.md` | Canonical 48-arm matrix for our baseline guest + 22 🟡 uncertainty markers |
| 5 | `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md` | Full per-audit specification (17 audits) |
| 6 | `a4/docs/cloud1/composer/PHASE_7D_COMPOSER_BRIEF.md` | High-level Composer onboarding |
| 7 | `a4/docs/cloud1/composer/PHASE_7D_INCREMENTS.md` | Per-increment task tables (this doc references them) |
| 8 | **`a4/docs/cloud1/phases/PHASE_7D_ORCHESTRATION.md`** | **THIS DOC — chronological flow + gates + checkpoints** |

---

## Phase 7d at a glance

| # | Increment | Sub-phase | Audits | Owner | Est. time | Gate | Report-back file |
|---|---|---|---|---|---|---|---|
| 0 | Pre-fixes | — | P1, P2, P3 (+ cleanup) | Composer | 4-6 hr | All 3 land; fast suite passes; A1/A2/A3 re-run still PASS | `composer/PHASE_7D_INC0_REPORT.md` |
| 1 | Semantics & arms | 7d.1 | A4, A5, E1, E3 | Composer | 1-2 days | All exit 0; 🟡 arms adjudicated to 🟢 or DEFER | `composer/PHASE_7D_INC1_REPORT.md` |
| 2 | Math & schema | 7d.2 (local) | B3, B5, B6, B9, B10, E2 | Composer | 2-3 days | All exit 0; E2 informational | `composer/PHASE_7D_INC2_REPORT.md` |
| 3 | Fidelity | 7d.2 (local) | B1, B2, B4, B7 | Composer | 1.5-2 days | All exit 0; B1 strict mode 1000/1000 PASS | `composer/PHASE_7D_INC3_REPORT.md` |
| 4 | POS | 7d.2 (cloud) | B8, B11, B12 | Composer (POS) | 1-1.5 days | All exit 0; POS dispatch IDs recorded | `composer/PHASE_7D_INC4_REPORT.md` |
| 5 | Evidence + wrap | 7d.2 (local) | E5 (per-arm evidence), E4 close, final report | Composer + Opus | 1 day | E5: 48 evidence .md files + index; E4: 0 PENDING; final report written | `composer/PHASE_7D_INC5_REPORT.md` + `phases/PHASE_7D_FINAL_REPORT.md` |

**Total wall time:** 7-10 days (with sequential composer execution + opus review between increments).

**Gate between increments:** Composer must wait for **explicit "GREEN — proceed to Inc N+1" approval from Opus/user** before starting the next increment. No skipping ahead. No batching multiple increments without intermediate review.

---

## Chronological flow

### Composer's loop (per increment)

```
For each Increment N in [0, 1, 2, 3, 4, 5]:
  1. Read PHASE_7D_INCREMENTS.md §"Increment N"
  2. Read PHASE_7D_ARCHITECTURE_AUDIT.md §<audits in this increment>
  3. Implement the audits (write scripts in a4/audits/<AuditID>_<name>.py)
  4. Run them; save JSON output to a4/audits/audit_output/<AuditID>_*.json
  5. Verify the acceptance gate (see § per increment below)
  6. Write composer/PHASE_7D_INC<N>_REPORT.md with results, decisions, blockers
  7. STOP. Post the report and wait for Opus/user review
  8. If APPROVED: proceed to Increment N+1
  9. If CORRECTIONS REQUESTED: fix and re-report (don't proceed)
```

### Opus's loop (after each Composer report)

```
For each report Composer posts:
  1. Read report
  2. Verify acceptance gate ACTUALLY met (open JSON/MD outputs; spot-check 2-3 audits)
  3. Re-run 1 audit locally to confirm reproducibility (when feasible)
  4. Write decision: GREEN (Composer proceeds), AMBER (corrections needed), RED (rollback)
  5. Update CLOUD1_STATUS.md row 7d sub-state
  6. Post decision back to Composer + user
```

---

## Per-increment plan

Each section below contains: **inputs Composer needs**, **work**, **outputs Composer produces**, **acceptance gate**, **what Opus reviews**.

---

### Increment 0 — Pre-fixes

**Goal:** land the 3 architectural pre-fixes that all 7d.2 audits depend on.

**Inputs Composer reads (in order):**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 0"` (tasks)
2. `composer/PHASE_7D_COMPOSER_BRIEF.md §1` (pre-fix specifications)
3. `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` D40-D42 (multi-cycle / non-det context)
4. Existing files to modify: `a4/tools/verify_mutation_semantics.py`, `a4/standalone/mutations/*.py`, `a4/standalone/fuzzer.py`, `a4/standalone/coverage_db.py`, `a4/standalone/semantic_arm_universe.py`
5. (For context — read once) `a4/audits/A{1,2,3}_*.py` to understand the audit pattern

**Work:**
- **P1** — verifier strict mode: `if original_value:` → `if original_value is not None:`; add INSTR_TYPE_MOD hook.old_major/minor check
- **P2** — uniform `original_value` recording: every `create_config()` populates `_info["original_value"]`; new DB column `mutations.original_value`; migration test
- **P3** — D40 multi-cycle step disambiguation: pick option (b) [drop from universe] unless it drops > 4 arms; otherwise option (a) [Rust rebuild]
- **Cleanup** — remove dead `_PHANTOM_ARMS_PRODUCTION_TRACE` frozenset

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/tools/verify_mutation_semantics.py` (modified) | P1 changes |
| `a4/standalone/mutations/*.py` (8 files modified) | P2 changes — uniform original_value recording |
| `a4/standalone/fuzzer.py` (modified) | P2 — pass original_value to db.record_mutation |
| `a4/standalone/coverage_db.py` (modified) | P2 — new mutations.original_value column + migration |
| `a4/standalone/semantic_arm_universe.py` (modified) | P3 — multi-cycle filter + dead-code removal |
| `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` (D40 finalized) | Document option (a) vs (b) choice + arm-count cost |
| `composer/PHASE_7D_INC0_REPORT.md` | Section per pre-fix: change summary + test results + arm count after fix + verifier strict-mode results on existing 24-sample set (expect FAIL on at least the INSTR_TYPE_MOD id=12 case) |

**Acceptance gate (Composer self-checks before reporting):**
- [x] Full fast suite passes (382+ tests)
- [x] A1, A2, A3 re-run still PASS (Composer must re-run, not just trust prior results)
- [x] D40 documented in CLOUD1_DECISIONS_FOR_PRO_R2.md
- [x] On a fresh N=50 smoke: `SELECT COUNT(*) FROM mutations WHERE original_value=0 AND kind!='INSTR_TYPE_MOD'` ≤ 10% of rows
- [x] Verifier strict mode on existing Phase 7c rev2 samples produces at least 1 FAIL (the INSTR_TYPE_MOD id=12 cycle-shift case)

**What Opus reviews when Composer reports:**
1. Open `coverage_db.py` migration code, confirm safe upgrade for the existing `a4_coverage.db`
2. Open one of `mutations/*.py` and confirm `original_value` is populated for the pre-mutation `txn.word`, not the new value
3. Open `semantic_arm_universe.py` and confirm dead code removed + P3 fix logic
4. Run `a4/audits/A3_arm_step_integrity.py` myself; confirm arm count ≥ 44 (was 48; we allow ≤ 4 drop for D40 option b)
5. Run the verifier on a fresh N=20 smoke; confirm strict mode catches problems instead of silently passing

**Opus issues GREEN to proceed to Increment 1.** AMBER if any of the above fails.

---

### Increment 1 — Semantics & arms (7d.1)

**Goal:** prove that every kept arm corresponds to a real, semantically-correct (kind, zone) pair, and resolve all 🟡 uncertainty markers in EXPECTED_ARMS.md.

**Inputs Composer reads:**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 1"`
2. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md §A4, A5, E1, E3` (specs for each audit)
3. `cloud1/EXPECTED_ARMS.md` (the 22 🟡 arms + Q1-Q8 to resolve)
4. `cloud1/GLOSSARY.md` (variable definitions to inline in audit output)

**Work — implement 4 audit scripts:**

| Script | Lines | What it does |
|---|---|---|
| `a4/audits/A4_mutation_module_target.py` | ~80 | For every (kind, zone) arm, pick 3 random steps and verify mutation module's `get_targets_at_step` returns ≥ 1 valid target with non-empty txn list |
| `a4/audits/A5_canonical_match.py` | ~100 | Diff `SemanticArmUniverse.build()` output against `EXPECTED_ARMS.md` canonical table; flag added/removed/renamed arms |
| `a4/audits/E1_instruction_decode_ground_truth.py` | ~120 | For every arm's first 10 steps, fetch the raw instruction word and decode it independently; verify decoded major/minor matches `cycle.major/minor` |
| `a4/audits/E3_uncertain_arm_review.py` | ~80 | Generate an interactive review JSON: for each 🟡 arm in EXPECTED_ARMS.md, surface 5 concrete steps + classifier reasoning so user/Opus can adjudicate |

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/audits/audit_output/A4_module_targets.json` | per-arm: `{steps_tested, targets_found, success_rate}` |
| `a4/audits/audit_output/A5_canonical_diff.json` | added / removed / renamed arms; expected vs actual count |
| `a4/audits/audit_output/E1_decode_ground_truth.json` | per-arm: `{cycles_checked, decode_matches, decode_mismatches}` with full mismatch context |
| `a4/audits/audit_output/E3_uncertain_review.json` | per-🟡-arm: 5 example steps + classifier rationale + draft verdict |
| `cloud1/EXPECTED_ARMS.md` (updated) | 22 🟡 → 🟢 (resolved) or 🔵 (algorithmically derived) or DEFER (to Phase 9 review). Zero 🟡 at exit. |
| `composer/PHASE_7D_INC1_REPORT.md` | Per-audit verdict + EXPECTED_ARMS adjudication summary + any new decisions (D-numbered) |

**Acceptance gate:**
- [x] A4: every arm has ≥ 1 valid target per sampled step; 0 arms with `success_rate = 0`
- [x] A5: 0 unexpected diffs (or all diffs explained in INC1_REPORT)
- [x] E1: ≥ 95% decode-matches per arm; any mismatches sent to E4 review queue
- [x] E3: EXPECTED_ARMS.md has zero 🟡 markers; each prior 🟡 is now 🟢/🔵 or DEFER
- [x] **JOINT REVIEW SESSION** with Opus/user before declaring 7d.1 done (each 🟡 → 🟢 transition spot-checked)

**What Opus reviews:**
1. Open `EXPECTED_ARMS.md` and confirm all 🟡 are resolved with rationale
2. Re-run `A5_canonical_match.py`; verify the diff
3. Spot-check 3 E1 decode-mismatches (if any); confirm they're sent to E4
4. Spot-check 3 E3 verdicts; confirm rationale is sound
5. Pull-up joint review session if any 🟡 → 🟢 transition is suspect

**Opus issues GREEN to proceed to Increment 2.**

---

### Increment 2 — Math & schema (7d.2 local, cheap)

**Goal:** verify all the cheap-to-check math correctness audits (no big mutation campaigns; just inspection + small N=5-10 runs).

**Inputs Composer reads:**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 2"`
2. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md §B3, B5, B6, B9, B10, E2`
3. (For B10) the new D8 address-region map proposed in `phases/PHASE_7D_ARCHITECTURE_AUDIT.md` (which Composer must implement)

**Work — implement 6 audit scripts:**

| Script | Lines | What it does |
|---|---|---|
| `a4/audits/B3_reward_math.py` | ~80 | Replay 50 (success, failure_count, residue) tuples through `reward_v2.py`; assert output matches hand-computed expected |
| `a4/audits/B5_zone_kind_invariant.py` | ~60 | Check that for every arm `(kind, zone)`, all sampled steps have `cycle.major ∈ kind.VALID_MAJORS` |
| `a4/audits/B6_db_schema_sanity.py` | ~100 | Inspect schema of a fresh N=20 smoke DB; verify all 5 v2 tables present + correct dtypes + non-null constraints |
| `a4/audits/B9_bandit_floor_accounting.py` | ~120 | Verify epoch-level floor counts: each epoch should have exactly 55% (±2%) floor pulls + singleton-floor met before adaptive starts |
| `a4/audits/B10_compressed_global_regions.py` | ~100 | Verify D8 address-region map by running extractor on 200-mutation DB and checking 0 addresses land in "unknown" region |
| `a4/audits/E2_arm_bite.py` | ~120 | Per-arm: run 5 mutations, characterize failure-class distribution; flag no-bite arms (informational, not blocking) |

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/audits/audit_output/B{3,5,6,9,10}_*.json` | Per-audit results |
| `a4/audits/audit_output/E2_arm_bite.json` | Per-arm: `{n_mutations, n_with_failures, dominant_failure_family, family_distribution}` |
| `a4/standalone/compressed_global_extractor.py` (modified, if D8 map needed update) | Updated `_ADDRESS_REGION_MAP` aligned to `platform.rs` |
| `composer/PHASE_7D_INC2_REPORT.md` | Per-audit summary + E2 no-bite arm list (informational) |

**Acceptance gate:**
- [x] B3, B5, B6, B9, B10 all exit 0
- [x] E2 produces a report; ≤ 5 arms with `n_with_failures = 0` (more → potential universe-builder bug; flag for E4)
- [x] B10: 0 "unknown" addresses

**What Opus reviews:**
1. Open `compressed_global_extractor.py` if Composer updated D8 map; verify new map matches `platform.rs`
2. Spot-check 1 B3 hand-computed reward
3. Verify B9 floor percentage (should be ~55%; large drift = bug)
4. Check E2 no-bite list; decide if any need to be reclassified as universe bugs

**Opus issues GREEN to proceed to Increment 3.**

---

### Increment 3 — Fidelity audits (7d.2 local, heavy)

**Goal:** prove that for every mutation, the bandit's selected arm == executed arm == DB-recorded arm == hook-emitted arm == reward-attributed arm. This is the audit that GIVES YOU 100% CONFIDENCE.

**Inputs Composer reads:**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 3"`
2. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md §B1, B2, B4, B7`
3. Pre-fix P1 implementation (Composer's own work from Inc 0) — B1 reuses this strict verifier

**Work — implement 4 audit scripts + run 1000+ mutations:**

| Script | Lines | What it does |
|---|---|---|
| `a4/tools/verify_mutation_semantics.py` (already strict from P1) | — | Run on **200 stratified mutations × 5 variants = 1000 mutations** |
| `a4/audits/B2_multicycle_replay.py` | ~50 | Replay the INSTR_TYPE_MOD id=12 step=0 case (or its post-D40 equivalent); verify the strict verifier returns PASS |
| `a4/audits/B4_bandit_db_traceability.py` | ~120 | For 250 mutations: assert `bandit_decisions.kind == mutations.kind == hook.kind == reward_attribution.kind` (and same for zone/step) |
| `a4/audits/B7_seed_reproducibility.py` | ~80 | Run the same seed × 5 variants × 2 paired runs; assert DBs are bitwise-equal (modulo `executed_at` timestamps + D42 non-det allow-list) |

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/audits/audit_output/B1_strict_verifier.json` | 1000/1000 PASS expected; any FAIL gets full diff context |
| `a4/audits/audit_output/B2_multicycle.json` | Replay results — PASS or detailed failure |
| `a4/audits/audit_output/B4_traceability.json` | 250/250 with all 5 tuples agreeing; any disagreement → which tuple disagreed + DB row |
| `a4/audits/audit_output/B7_reproducibility.json` | Per-variant diff stats; should be ≈ 0 (timestamps + 188 allow-list addrs only) |
| `composer/PHASE_7D_INC3_REPORT.md` | Per-audit results + 1-line attestation: "fidelity verified end-to-end" |

**Acceptance gate:**
- [x] B1: 1000/1000 PASS (strict mode)
- [x] B2: PASS
- [x] B4: 250/250 agree
- [x] B7: 0 unexplained diffs

**What Opus reviews (MOST IMPORTANT INCREMENT):**
1. Open `B1_strict_verifier.json`; spot-check 5 random PASS rows by hand (read txn data + hook stdout)
2. Open `B4_traceability.json`; pick 3 mutations and trace them through the DB myself (`bandit_decisions` → `mutations` → `mutation_substrategy` → `mutation_value_class`)
3. Verify B7 diff stats — if anything beyond timestamps + D42 list shows up, RED
4. If any audit shows FAIL, full rollback to Inc 0 (this is the load-bearing increment)

**Opus issues GREEN to proceed to Increment 4.**

---

### Increment 4 — POS audits (7d.2 cloud)

**Goal:** verify the architecture works at scale and under POS execution conditions.

**Inputs Composer reads:**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 4"`
2. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md §B8, B11, B12`
3. `a4/docs/cloud1/PHASE_7B_POS_GUIDE.md` (POS dispatch how-to)
4. POS playbook `a4/docs/cloud1/POS_PLAYBOOK.md`

**Work — dispatch 3 POS audit batches:**

| Audit | POS dispatch | Estimated POS wall |
|---|---|---|
| B8 — Concurrent isolation | 5 sequential + 5 parallel runs at N=50, then `B8_concurrent_isolation.py` diffs DBs | 1 hr |
| B11 — Scale stress | 5 variants × N=500 + re-run B1+B4+B9 on resulting DBs | 6 hr |
| B12 — Multi-input robustness | re-run A1/A2/A3/A4/A5/B1/B4/B9 with `--in1 1 --in4 1` and `--in1 100 --in4 100` | 2-3 hr (POS or local) |

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/audits/audit_output/B{8,11}_*.json` | POS audit results |
| `a4/audits/audit_output/B12_input_variant_<args>_*.json` | Per-input-variant re-run results (×2 inputs) |
| `cloud1/EXPECTED_ARMS.md` (updated) | Fill in alternate-input arm sections (--in1 1 --in4 1 and --in1 100 --in4 100) |
| `composer/PHASE_7D_INC4_REPORT.md` | POS dispatch IDs + per-audit results + any new arms unlocked by alternate inputs |

**Acceptance gate:**
- [x] B8: PASS (no isolation issues)
- [x] B11: PASS (scale-stress holds B1 + B4 + B9)
- [x] B12: A-suite + B1 + B4 + B9 all PASS for both alternate inputs

**What Opus reviews:**
1. POS dispatch IDs recorded; spot-check 1 dispatch's logs for sanity
2. Verify B11 doesn't degrade B1 PASS rate (regression check)
3. Open updated EXPECTED_ARMS.md alternate-input sections; sanity-check arm counts

**Opus issues GREEN to proceed to Increment 5.**

---

### Increment 5 — Per-arm evidence pack (E5) + Final report (E4 + wrap)

**Goal:** produce the user-readable per-arm evidence files (E5), close E4 review queue, write the Phase 7d wrap-up.

**Inputs Composer reads:**
1. `composer/PHASE_7D_INCREMENTS.md §"Increment 5"`
2. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md §E5` (full file-format spec) + §E4
3. `cloud1/GLOSSARY.md` (variable definitions to inline)
4. Existing P1 verifier + B4 traceability dataframe (E5 reuses these)

**Work:**

| Task | Owner | Output |
|---|---|---|
| Implement `a4/audits/E5_per_arm_evidence.py` (~250 LOC) | Composer | Reads B1's verifier + B4's joined traceability dataframe; orchestrates per-arm output |
| Run E5: 50 stratified mutations × 48 kept arms | Composer | ~2400 mutations, ~3 hr WSL |
| Generate 48 per-arm .md files + index | Composer | `audit_output/per_arm_evidence/<kind>_<zone>.md` (×48) + `README.md` |
| Generate stub .md files for ~49 non-exercised arms | Composer | `audit_output/per_arm_evidence/<kind>_<zone>.md` (stub: "NOT EXERCISED — see §6.3 multi-guest plan") |
| Composer self-review: every file uses GLOSSARY-correct variable labels + EXAMPLE 1 + EXAMPLE 2 (if any) populated | Composer | per-file checklist in `composer/PHASE_7D_E5_SUMMARY.md` |
| Close E4 review queue: every PENDING item gets DECIDED / DEFERRED / REJECTED | Composer + user + Opus joint session | `composer/PHASE_7D_REVIEW_QUEUE.md` updated |
| Write `phases/PHASE_7D_FINAL_REPORT.md` | Opus | Summary of all 17 audits + final 🟢 EXPECTED_ARMS.md status + E5 verdict summary + ready-for-Phase-8 attestation |
| Update `CLOUD1_STATUS.md` | Opus | Phase 7d → ✅ DONE; Phase 8 → ⚪ READY |

**Outputs Composer produces:**

| File | Content |
|---|---|
| `a4/audits/E5_per_arm_evidence.py` | The orchestrator script |
| `a4/audits/audit_output/per_arm_evidence/<kind>_<zone>.md` × 48 | Per kept arm: full EXAMPLE 1 + (if any) EXAMPLE 2 per E5 spec format |
| `a4/audits/audit_output/per_arm_evidence/<kind>_<zone>.md` × ~49 (stubs) | Per non-exercised arm: "NOT EXERCISED — see §6.3" |
| `a4/audits/audit_output/per_arm_evidence/README.md` | One-page index table: all arms with ✓/⚠/✗/⚪ status + links |
| `composer/PHASE_7D_E5_SUMMARY.md` | Per-file checklist + aggregate verdict counts |
| `composer/PHASE_7D_REVIEW_QUEUE.md` (closed) | All items in DECIDED/DEFERRED/REJECTED state |
| `composer/PHASE_7D_INC5_REPORT.md` | E5 summary + E4 closure + handoff to Opus for final report |

**Acceptance gate:**
- [x] 48 per-arm .md files exist for kept arms; all have EXAMPLE 1
- [x] ~49 stub .md files exist for non-exercised arms
- [x] `per_arm_evidence/README.md` index page complete
- [x] 0 arms with ✗ INCORRECT aggregate verdict (any ✗ → E4 session)
- [x] E4 review queue has 0 PENDING items
- [x] Variable labels in every E5 file are GLOSSARY-traceable

**What Opus reviews:**
1. Open `per_arm_evidence/README.md` index; spot-check 5 random arm .md files end-to-end
2. Pick 1 arm where E5 reports ✗ INCORRECT (if any) and verify the divergence is real
3. Run a final regression sweep: full fast test suite + A1+A2+A3 (no regressions vs. start of Inc 0)
4. Write `phases/PHASE_7D_FINAL_REPORT.md` with:
   - Per-audit verdict table (all 17 audits)
   - EXPECTED_ARMS.md final state attestation
   - E5 verdict summary (X/48 ✓, Y/48 ⚠, Z/48 ✗)
   - "Ready for Phase 8 IV.POS.7" attestation
5. Update CLOUD1_STATUS.md row 7d → ✅; row 8 → ⚪ READY

**This closes Phase 7d. Phase 8 unblocks.**

---

## What happens AFTER Phase 7d (so you know what to plan for)

| Phase | When | What |
|---|---|---|
| **Phase 8** — IV.POS.7 Campaign | Immediately after Phase 7d closes | N=6000 × 5 variants × 10 seeds on POS; primary cloud1 deliverable |
| **Phase 9** — Pro Round 2 Report | After Phase 8 data is in | Statistical analysis + write-up for Pro |
| **Phase 10** — Multi-guest generality | Triggered AFTER Phase 9 if Pro R2 results justify investment | Re-run audit A-suite + B1/B4/E5 against ≥ 1 additional guest (e.g. risc0 SHA example) to verify the ~49 unverified arms |

---

## Composer escalation rules

| Scenario | Action |
|---|---|
| An audit unexpectedly fails | Do NOT silently fix it. Report it in the INC report; let Opus decide if it's a real bug, an audit bug, or a deferable. |
| A pre-fix unexpectedly affects > 4 arms | STOP. Don't proceed. Report and wait for D40 re-decision. |
| Acceptance gate is close but not strictly met (e.g. B1 999/1000 PASS instead of 1000) | STOP. Don't proceed. Report the 1 FAIL with full context; let Opus decide. |
| You discover a new uncertainty not in EXPECTED_ARMS.md | Add it as a new 🟡 row with a Q-numbered question; flag in the INC report. |
| You think an increment can be split into 2 sub-increments | Propose it in the INC report; don't unilaterally split. |
| You need information not in any doc | Read the source code referenced in `cloud1/GLOSSARY.md`. If still unclear, ask Opus in the INC report under "Open questions"; don't guess. |

---

## How Composer reports back per increment

Every `composer/PHASE_7D_INC<N>_REPORT.md` MUST have:

```markdown
# Phase 7d Increment <N> Report

## TL;DR
<one-paragraph: did Inc N's acceptance gate pass?>

## Per-audit results
| Audit | Verdict | Output file | Notes |
|---|---|---|---|
| <ID> | PASS / FAIL / DEFERRED | <path to JSON/MD> | <key numbers> |

## New findings
- <bug, surprise, new uncertainty: full description>

## Decisions taken
- <any D-numbered decision; flag for Opus review>

## Open items carried over
- <new E4 review queue entries>

## Acceptance gate self-check
- [ ] <checkbox for each gate item from this orchestration doc>

## Ready-to-proceed statement
"Increment N is green. Awaiting Opus GREEN to proceed to Increment N+1."

OR

"Increment N has blocker <X>. Awaiting Opus decision."
```

---

## Opus's per-increment response template

```markdown
**Increment <N> review** — <GREEN | AMBER | RED>

**Spot-checks performed:**
- <list what I read / re-ran>

**Findings:**
- <anything questionable I found, even if Composer didn't flag it>

**Decisions:**
- <any new D-decisions or revisions>

**Verdict:**
- GREEN — proceed to Inc N+1
- AMBER — fix the following, re-report: <list>
- RED — rollback Inc <M> changes; re-plan: <reason>
```

---

## End-of-Phase-7d checklist (Opus closes)

Before declaring Phase 7d done:
- [ ] All 17 audits exit 0 on the same code path (no audits passing on stale code)
- [ ] `EXPECTED_ARMS.md` has 0 🟡 markers (all resolved to 🟢/🔵 or DEFER)
- [ ] `composer/PHASE_7D_REVIEW_QUEUE.md` has 0 PENDING items
- [ ] `audit_output/per_arm_evidence/` has 48 kept-arm .md + ~49 stub .md + README.md
- [ ] `phases/PHASE_7D_FINAL_REPORT.md` written
- [ ] `CLOUD1_STATUS.md` row 7d → ✅ DONE; row 8 → ⚪ READY
- [ ] User has confirmed they reviewed at least 5 random per-arm evidence files
- [ ] Full fast suite passes from a fresh clone
