# Phase 7d — Increment 3 Work Order

**Purpose:** run the 4 FIDELITY audits that prove the bandit-selected arm is the executed arm is the DB-recorded arm is the hook-emitted arm is the reward-attributed arm. These audits are the **gating evidence for "100% confidence"** that Phase 7d was designed to deliver.

**Owner:** Composer
**Reviewer:** Opus
**Estimated time:** ~2-3 days (mostly host runtime; ~6-8 hours of POS wall + ~4 hours of script writing + ~2 hours of report writing)
**Predecessor:** Inc 2 ACCEPTED (6/6 audits PASS; bandit math + reward routing + coverage delta + DB schema + compressed-global pipeline + per-arm bite all verified)
**Gate to Inc 4:** all 4 audits PASS + report-back accepted

---

## 0. Required reading (DO FIRST)

1. `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md` §§ B1, B2, B4, B7
   — Per-audit specs. Each audit's "Goal / Why it matters / Acceptance gate / Script name" is canonical there.

2. `a4/docs/cloud1/composer/PHASE_7D_INC0_REPORT.md`
   — Pre-fix P1 (verifier strict mode) and P2 (uniform `original_value` recording) landed here. B1's strict mode depends on these.

3. `a4/docs/cloud1/composer/PHASE_7D_INC1_5_REPORT.md`
   — D40 multi-cycle disambiguation final form. B2 verifies this.

4. `a4/docs/cloud1/composer/PHASE_7D_INC2_REPORT.md`
   — Inc 2 baseline; B3/B5/B9 PASSED on the same code path you'll audit. Lessons learned:
     - Don't run multiple host-heavy audits in parallel on the same node (Inc 2 E2 hit empty-log starvation when run alongside B5/B6/B9).
     - Pre-validate audit-script JSONL/DB format compatibility before long runs (Inc 2 B6 took 3 iterations because of audit-format bugs).
     - `PYTHONUNBUFFERED=1` for any audit that emits progress logs over hours.

5. `a4/tools/verify_mutation_semantics.py`
   — The verifier B1 reuses. Pre-fix P1 added strict mode; do NOT relax it.

6. `a4/standalone/fuzzer.py::_run_v2_bandit_mutation` and `a4/standalone/cli.py`
   — The mutation execution path B4 traces end-to-end.

7. `a4/docs/cloud1/composer/PHASE_7B_POS_GUIDE.md`
   — POS dispatch mechanics. **Required reading for B1 if you haven't dispatched to POS recently.**

---

## 1. Variant inventory (same as Inc 2)

| Phase-doc name | CLI `--selector` value | Bandit type | Reward | Arm space |
|---|---|---|---|---|
| V1 | `zoned` | uniform-over-buckets (legacy) | legacy multiplicative | (kind, bucket) |
| V2 | `kindUCB_zoned_v1` | UCB1 (undiscounted) | legacy multiplicative | kind only |
| V3 | `kindUCB_zoned_v2_noQ` | UCB1 (undiscounted) | v2 additive (no Q_loc) | kind only |
| V4 | `kindTS_zoned_v2` | Thompson Sampling (Beta) | v2 additive | kind only |
| V5 | `cTS_semantic_v2` | Constrained Thompson Sampling | v2 additive + Bernoulli success | **(kind, semantic_zone)** ← uses the 48-arm HYBRID universe |

All 4 Inc 3 audits run against all 5 variants. B1's per-variant mutation count is **200** (per Audit spec §B1); B4 is **N=50/variant**; B7 is **N=50/variant × 2 runs**.

---

## 2. The 4 audit tasks

### B1 — Hook fidelity (STRICT, no skip)

**File to write/use:** `a4/tools/verify_mutation_semantics.py` (already in strict mode from P1 — DO NOT relax it).
**Orchestrator script to write:** `a4/audits/B1_hook_fidelity.py` (~80 LOC) — drives 5 variants × 200 stratified mutations through the verifier, aggregates pass/fail to `audit_output/B1_hook_fidelity.json`.

**What it checks (per mutation):**
- `hook.step == config.step` (no step shift)
- `hook.old_major == config._info.original_major` (no cycle shift within a step; D40 disambiguation)
- `hook.old_minor == config._info.original_minor`
- `hook.old_word == config._info.original_value` for word-mutating kinds
- `hook.new_word == config.word` (sanity)

**Mutation budget:** 5 variants × 200 mutations = **1000 host mutations**. At ~30-40 sec/mutation on host this is **~10 hours sequential**. On POS 16-way it's **~45 minutes wall**. **MUST run on POS.**

**Stratification requirement:** the 200 mutations per variant MUST be stratified across all arms the variant's selector can pick:
- V1 (`zoned`, kind-bucket): stratify across (kind, bucket) pairs from the legacy universe.
- V2-V4 (kind-only): stratify across the 7 kinds (~28-30 mutations per kind).
- V5 (kind-zone HYBRID): stratify across the 48 (kind, zone) arms (~4 mutations per arm).

If the natural bandit pulls don't cover all arms in 200 mutations, **force-cover** by setting `cold_start_pulls_per_arm` high enough to pull each arm at least once, then sample the remainder via the variant's natural mechanism. Document the forced-coverage configuration in the audit output.

**Acceptance gate:** for each variant V ∈ {V1..V5}: **200/200 PASS** with strict mode. Per-variant breakdown in JSON output. Any FAIL dumps the full divergence record (config + hook stdout line + baseline txn).

**Output file:** `audit_output/B1_hook_fidelity.json`:
```json
{
  "_meta": {...},
  "per_variant": {
    "V1": {"total": 200, "pass": 200, "fail": 0, "stratification": {...}, "failures": []},
    ...
  },
  "verdict": "PASS"
}
```

**Watch out:**
- The strict verifier from P1 expects `config._info.original_major/minor` for INSTR_TYPE_MOD and `config._info.original_value` for word-mutating kinds. P2 made all mutations populate this. If you find any kind missing `original_value`, **STOP and flag** — that's a regression from P2.
- D40 multi-cycle disambiguation should make INSTR_TYPE_MOD id=12 step=0 PASS now. If it FAILS, B2's investigation is what diagnoses it.
- The 188 D42 non-deterministic mem-txn addresses are excluded from MEM_VAL_MOD targets at universe-build time — they should never reach the verifier. If they do, that's a P3 bug.

**Estimated time:** 3 hr write (audit + POS manifest) + 45 min POS wall + 1 hr post-processing.

---

### B2 — Multi-cycle replay (D40 fix verification)

**File to write:** `a4/audits/B2_multicycle_replay.py` (~80 LOC). Standalone script; no POS.

**What it verifies:** the original Phase 7c rev2 failing case (INSTR_TYPE_MOD id=12 step=0 — hook reports `old=7/0 ECALL` but config expected `2/6 AddI`) is either:
- (a) **No longer in the universe** (D40 chose option b — drop multi-cycle steps), so this exact case can't be selected. Verify by querying `SemanticArmUniverse.build` and asserting no `(INSTR_TYPE_MOD, step=0)` entry where step 0 has multiple kind-matching cycles.
- (b) **In the universe but with correct cycle_idx routing** (D40 chose option a — plumb cycle_idx). Verify by running the case and confirming hook.old matches config._info.original_major/minor.

Inc 1.5 confirmed option (b) was NOT chosen; D40 is option (a) — drop. So B2 just asserts the universe excludes the case.

**Plus**: re-run the specific case with the current code path and confirm strict verifier exits clean (= "case is now correctly filtered out" rather than "case is now correctly handled").

**Acceptance gate:**
- Universe query: `(INSTR_TYPE_MOD, step=0)` is NOT in the kept-arms list (or step 0 is correctly in the single-cycle `step0` zone where its cycle is unambiguous).
- For all of B1's 1000 mutations, **zero** of them are at multi-cycle steps that don't have explicit disambiguation.
- The 4 D40-dropped arms (`INSTR_WORD_MOD_*|last_step`, `INSTR_WORD_MOD_*|pre_ecall`) confirmed absent from V5's universe.

**Output file:** `audit_output/B2_multicycle_replay.json`:
```json
{
  "_meta": {...},
  "d40_choice": "option_b_drop_multi_cycle_steps",
  "universe_query": {
    "step0_arms": ["INSTR_TYPE_MOD|step0", "MEM_VAL_MOD|step0", "PRE_EXEC_REG_MOD|step0"],
    "step0_cycles_per_arm": {"INSTR_TYPE_MOD|step0": 1, ...},
    "all_single_cycle": true
  },
  "d40_dropped_arms_absent": true,
  "b1_multicycle_violations": 0,
  "verdict": "PASS"
}
```

**Estimated time:** 1.5 hr write + 5 min run (no host execution beyond what B1 already did).

---

### B4 — Bandit → DB traceability

**File to write:** `a4/audits/B4_bandit_db_traceability.py` (~150 LOC) + small fuzzer instrumentation patch (one-shot guarded `--debug-bandit-trace` flag emitting a JSONL side-channel per mutation).

**What it checks (per mutation):** for an N=50 smoke per variant (250 mutations total), prove that these 6 sources all agree on `(kind, [zone,] step)`:

| Source | Where it's logged |
|---|---|
| `bandit_kind`, `bandit_zone`, `bandit_step` | immediately after `v2_scheduler.select()` in fuzzer |
| `executed_kind`, `executed_step` | immediately after `_create_mutation()` |
| `db_kind`, `db_step` | `mutations` row (queried after run) |
| `hook_kind`, `hook_step` | mutation hook stdout `<a4_<kind>_mod>{...}` line |
| `bandit_decisions_arm_id` | `bandit_decisions` row (mode + arm_id) |
| `reward_v2_arm` | `mutation_rewards` row attribution |

For each mutation: all 6 (kind, step) tuples agree (V5 also has zone). Variant-isolation sub-check:
- V1's `bandit_zone` is always `None` (uniform-bucket has no zone).
- V2/V3/V4's `bandit_zone` is always `None` (kind-only has no zone).
- V5's `bandit_zone` is always in `SEMANTIC_ZONES` (the 19 HYBRID zones).

**Mutation budget:** 5 variants × N=50 = **250 host mutations**. On host: ~2 hours sequential. On POS 16-way: ~10 minutes wall. **EITHER POS OR LOCAL is acceptable** for B4 — your call. If you run locally, do it AFTER E2-style audits to avoid host starvation.

**Acceptance gate:** 250/250 mutations have all 6 source tuples agreeing. Per-variant breakdown.

**Output file:** `audit_output/B4_bandit_db_traceability.json`:
```json
{
  "_meta": {...},
  "per_variant": {
    "V1": {"n_mutations": 50, "n_agreed": 50, "n_disagreed": 0, "isolation_check": {"bandit_zone_always_none": true}},
    ...
  },
  "verdict": "PASS"
}
```

**Watch out:**
- The `--debug-bandit-trace` flag MUST be removable (gate it strictly; default OFF). Same pattern as Inc 2's `--debug-coverage-delta`.
- Phase 6 telemetry already populates `bandit_decisions` and `arm_state_snapshot` at `--telemetry-level full`. B4 only needs to ADD a per-mutation JSONL emission with the inline bandit/executor/hook tuples (the DB tuples are already there).
- Hook stdout parsing: the format is `<a4_<kind>_mod>{json}`. Some kinds have nested JSON; use a tolerant parser.
- For V5: the `arm_id` field in `bandit_decisions` is `"<kind>|<zone>"`. Parse both halves.

**Estimated time:** 4 hr write (audit + JSONL + parser + assertion harness) + 30 min run (local or POS).

---

### B7 — Same-seed reproducibility

**File to write:** `a4/audits/B7_seed_reproducibility.py` (~100 LOC).

**What it checks:** for each variant V at N=50 with seed=999:
1. Run twice (call them `run_A` and `run_B`).
2. Diff `mutations` table between the two runs:
   - Exclude `executed_at` timestamp (always differs).
   - Exclude `original_value` for the 188 D42 non-det addresses (use `a4/audits/audit_output/A1_nondet_addrs.json`).
   - All other columns byte-identical.
3. Diff `bandit_decisions` table:
   - All columns byte-identical (no timestamps in this table).
4. Diff `mutation_rewards` table:
   - All columns byte-identical.

**Mutation budget:** 5 variants × 2 runs × N=50 = **500 host mutations**. On host: ~4 hours sequential. On POS 16-way: ~15 minutes wall. **EITHER POS OR LOCAL is acceptable.**

**Acceptance gate:** zero diff (after filtering) across all 5 variants. Per-variant breakdown.

**Output file:** `audit_output/B7_seed_reproducibility.json`:
```json
{
  "_meta": {...},
  "per_variant": {
    "V1": {"mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 0, "pass": true},
    ...
  },
  "filter_metadata": {
    "excluded_columns": ["mutations.executed_at"],
    "excluded_addresses_count": 188,
    "excluded_addresses_source": "audit_output/A1_nondet_addrs.json"
  },
  "verdict": "PASS"
}
```

**Watch out:**
- All 5 variants must use the same seed (999) for the two paired runs. Use `--seed 999`.
- The `compressed_global_coverage` table is currently sparse (only 21 rows on a V5 N=20 smoke per Inc 2 B10). Diff it too if rows exist; ignore if empty.
- `hook3_raw` and `local_coverage_v2` tables may have row-order dependence on insertion order; if your diff is naive row-by-row and finds reordering, sort first.
- If V1 (`zoned`) shows non-determinism with seed=999, that's a real bug — STOP and flag.

**Estimated time:** 2 hr write + 1 hr run (POS or local).

---

## 3. POS dispatch plan

### B1 manifest (REQUIRED — write this)

Create `a4/pos/manifests/pos_audit_b1.json`:

```json
{
  "_doc": "Phase 7d Inc 3 B1 hook fidelity audit — 5 variants × 200 stratified mutations = 1000 host mutations. POS dispatch parallelizes across variants. Each job runs --seed 999 with --telemetry-level full so verifier can read original_value from DB.",
  "name": "pos_audit_b1",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "jobs": [
    {"strategy": "zoned",                "seed": 999, "n": 200},
    {"strategy": "kindUCB_zoned_v1",     "seed": 999, "n": 200},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 999, "n": 200},
    {"strategy": "kindTS_zoned_v2",      "seed": 999, "n": 200},
    {"strategy": "cTS_semantic_v2",      "seed": 999, "n": 200}
  ]
}
```

**Dispatch procedure** (follow PHASE_7B_POS_GUIDE.md):
1. From WSL: build bundle with `bash a4/pos/prepare_bundle.sh --allow-dirty`.
2. User scp's `bundles/a4_campaign_*.tar.gz` to coinbase.
3. From coinbase: `bash a4/pos/run_campaign_pos.sh pos_audit_b1` (or equivalent dispatcher; check for an audit-specific runner — if none exists, follow `auto_run_ab_v1.sh` pattern).
4. Collect 5 DBs back to WSL: `scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b1_*.db ./a4/audits/audit_output/inc3_b1/`.

**Run-time expectation:** ~45 minutes POS wall (assuming 5 nodes available; 1 node = ~5 hours wall).

### B4 + B7 (optional POS, optional local)

**Recommendation: run B4 + B7 LOCALLY** *if* the host is idle (you're not running B1 concurrently). Each takes ~30-60 min, well within an evening session. POS is overkill for 250-500 mutations.

**If you choose POS for B4/B7**, copy the B1 manifest format with the smaller N values (50 for B4; 50 × 2 for B7's paired runs).

### B2 (no POS — pure local script)

B2 doesn't run host mutations; it just queries the universe and reads B1's output. No POS work.

---

## 4. Hard rules

1. **Don't change the bandit code, reward code, DB schema, verifier strict mode, or D40 logic.** B1-B7 are AUDITS, not refactors. If you find a bug, STOP and flag it.
2. **POS REQUIRED for B1.** 1000 sequential host mutations is ~10 hours; that's unreasonable to run locally without parallelism. POS gives you ~45 min wall.
3. **For local audits (B4/B7), do NOT run them concurrently with another host-heavy audit.** Inc 2's lesson: E2 was starved by parallel B5/B6/B9. One host audit at a time.
4. **`PYTHONUNBUFFERED=1`** for any audit emitting progress logs over more than 30 minutes.
5. **Telemetry level:** use `--telemetry-level full` for ALL smokes in Inc 3 — B1 needs `original_value`; B4 needs `bandit_decisions` + `arm_state_snapshot`; B7 needs row-level reproducibility.
6. **Smoke seeds:** seed=999 for all Inc 3 smokes (consistent with Inc 2). For B7, the SAME seed=999 is used for both paired runs (that's the point of reproducibility).
7. **B4 instrumentation must be REMOVABLE:** gate the `--debug-bandit-trace` flag strictly; default OFF. Same pattern as B6's `--debug-coverage-delta`.
8. **Audit-script format pre-validation:** before launching B1 on POS, run a 5-mutation local smoke with the strict verifier to confirm the audit-script reads the DB / hook stdout correctly. Inc 2's B6 took 3 iterations because of audit-format bugs caught only after long runs.
9. **No changes to fuzzer.py beyond the `--debug-bandit-trace` flag for B4** — and that flag is removed/disabled after B4 lands.

---

## 5. Acceptance gates (all must PASS)

| Gate | Criterion |
|---|---|
| B1 | 200/200 mutations PASS strict verifier for each of V1, V2, V3, V4, V5 (1000/1000 total). Per-variant stratification documented. |
| B2 | D40 multi-cycle disambiguation verified: no multi-cycle violations in B1's 1000 mutations; 4 D40-dropped arms confirmed absent from V5 universe. |
| B4 | 50/50 mutations per variant (250/250 total) have all 6 source tuples agreeing. Variant-isolation check passes. |
| B7 | Zero diff (after filtering executed_at + D42 addresses) across all 5 variants × 2 paired runs. |

**Plus:**
- Full fast test suite still passes (`pytest a4/standalone/tests/ -x` from repo root, ≥ 472).
- Audit-output JSONs are well-formed, GLOSSARY_META populated, verdict field set correctly.

---

## 6. Anti-patterns to avoid (lessons compounded across increments)

- ❌ Running B1 locally because "POS is too much trouble." 10 hours sequential vs 45 min POS — the trouble pays for itself in one audit.
- ❌ Running B4 and B7 simultaneously on the same host. They'll starve each other.
- ❌ Skipping the pre-validation 5-mutation smoke before B1 on POS. If the audit script has a parsing bug, you'll lose the entire 45-min POS window.
- ❌ Relaxing the verifier's strict mode to make B1 PASS. If something fails strict, that's a real bug — don't silently weaken the check.
- ❌ Letting B4's `--debug-bandit-trace` flag stay in fuzzer.py after the audit lands. Default OFF, gated path.
- ❌ Diffing B7's `compressed_global_coverage` naively when the table is sparse. Handle the empty/partial case explicitly.
- ❌ Hardcoding magic numbers (n_mutations=200, n_variants=5). Read from the manifest.
- ❌ Storing B1 mutation results in `audit_output/B1_hook_fidelity.json` AND `audit_output/B1_hook_fidelity.csv` AND a separate DB. Pick one — JSON for verdict + small summaries, optionally a single CSV for the 1000-row mutation-by-mutation table if it's > ~50 KB.
- ❌ Reporting "B1 PASS" without showing the per-variant stratification (how many mutations per arm). Stratification matters because if 195/200 hit the same arm, you've barely tested anything.

---

## 7. When you're done

Expected file changes:

```
a4/audits/B1_hook_fidelity.py                                     (NEW; orchestrator)
a4/audits/B2_multicycle_replay.py                                 (NEW)
a4/audits/B4_bandit_db_traceability.py                            (NEW)
a4/audits/B7_seed_reproducibility.py                              (NEW)
a4/standalone/fuzzer.py                                           (modified — guarded --debug-bandit-trace flag for B4 only)
a4/standalone/cli.py                                              (modified — --debug-bandit-trace CLI flag)
a4/pos/manifests/pos_audit_b1.json                                (NEW)
a4/audits/audit_output/B1_hook_fidelity.json                      (NEW)
a4/audits/audit_output/B2_multicycle_replay.json                  (NEW)
a4/audits/audit_output/B4_bandit_db_traceability.json             (NEW)
a4/audits/audit_output/B7_seed_reproducibility.json               (NEW)
a4/audits/audit_output/inc3_smokes/                               (NEW dir — B1/B4/B7 smoke DBs)
a4/docs/cloud1/composer/PHASE_7D_INC3_REPORT.md                   (NEW)
```

**Report structure (`PHASE_7D_INC3_REPORT.md`):**

```
# Phase 7d — Increment 3 Report

## Summary
- B1: PASS (1000/1000 hook fidelity, per-variant breakdown)
- B2: PASS (D40 disambiguation verified)
- B4: PASS (250/250 bandit→DB traceability)
- B7: PASS (5/5 variants reproducible with seed=999)
- Fast tests: PASS (≥ 472)

## Acceptance gate results
[table with per-audit numbers]

## Per-audit findings worth noting
### B1
- Stratification per variant: V1: kind-bucket distribution; V2-V4: per-kind distribution; V5: per-(kind,zone) distribution.
- Any failure mode mentioned (was strict mode triggered on anything weird?).

### B2
- D40 option chosen: (b) drop multi-cycle steps.
- 4 D40-dropped arms confirmed absent.

### B4
- Per-variant tuple-agreement breakdown.
- Variant-isolation sub-checks: V1 zone=None, V2-V4 zone=None, V5 zone ∈ SEMANTIC_ZONES.

### B7
- Per-variant diff counts (should all be 0 after filtering).
- Any tables not diffed (with reason).

## POS dispatch info (if used)
- Bundle SHA: <SHA>
- Manifest: pos_audit_b1.json
- Dispatch start / end time
- POS jobs IDs (for trace-back if needed)
- Per-job DB size + row counts (sanity)

## Open items / surprises
[anything notable]

## Ready-to-proceed
Inc 3 is green; please confirm to start Inc 4 (B8, B11, B12 — POS audits for concurrent isolation, scale stress, multi-input robustness).
```

STOP after writing the report. Wait for Opus review before starting Inc 4.

---

## 8. Why this increment matters (read this when you're tired)

Inc 0-2 verified the static and mathematical correctness of the architecture:
- Inc 0: pre-fixes (verifier strict mode, original_value uniformity, D40).
- Inc 1: semantics (arms are real, zones are real, decoded instructions match cycle.major).
- Inc 1.5: HYBRID classifier (kernel_other zone, post_ecall window, core_div/core_shr split).
- Inc 2: bandit math, reward routing, coverage delta, DB schema, compressed-global pipeline, per-arm bite.

Inc 3 is the FIRST increment that verifies the **end-to-end behavior** of a live mutation:

> When the bandit at time t picks arm A, does the mutation that ACTUALLY EXECUTES on the host correspond to arm A? Does the DB record arm A? Does the hook emit arm A? Does the reward update arm A?

If ANY of these chains breaks, the bandit is training on a fiction, and every Phase 8 result is a hallucination. **Inc 3 is the audit that, if passed, makes Phase 8 results scientifically interpretable.**

The 4 audits are designed to leave no escape:
- B1 catches "the mutation landed on a different cycle/step than configured."
- B2 catches the specific multi-cycle disambiguation pathology that bit us in Phase 7c rev2.
- B4 catches "the DB recorded a different arm than the bandit selected."
- B7 catches "running the same code with the same seed produces different results" (a sign of hidden non-determinism somewhere in the stack).

If all four PASS, you can credibly tell the user "the bandit decides X, the host does X, the DB knows X, the reward goes to X" with 100% confidence. That's the Phase 7d goal.
