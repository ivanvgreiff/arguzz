# D1.C Batch 1 — Composer Kickoff

**Branch:** `cloud2`
**Spec:** [`IV_POS_8_D1_C_SPEC.md`](../IV_POS_8_D1_C_SPEC.md) v0.3 (LOCKED; Ivan greenlit Q-C-* recommendations + v0.2/v0.3 audit fixes on 2026-06-17)
**Parent plan:** [`IV_POS_8_D1_REVISIT_PLAN.md`](../IV_POS_8_D1_REVISIT_PLAN.md) v0.6 §3.2 + §3.2.1
**Predecessor pattern:** D1.B Batches 1+1.5+1.5b+1.6+2+3 (commit `71dae77`; same `a4/runs/iv_pos_7/analysis/` analysis-only convention, same 30-DB Cat-A corpus via `cat_a_db_list()`)
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~1.5–2 days of focused Composer work (smaller than D1.B Batch 1 — fewer files, no extractor coordination)

---

## TL;DR for Composer

Implement Batch 1 of D1.C as defined in `IV_POS_8_D1_C_SPEC.md` v0.3 §2.1. This is the **`bug_proximity.py` foundation + 5 Tier-1 signal extractors + channel-reconstruction helper (Option A per §1.4) + `KIND_TO_SUBSTRATEGY_FIELDS` audit + 30-DB Tier-1 audit CSV + sanity plots**. Analysis-only — no production code edits whatsoever.

> **Read the spec first.** The spec is the source of truth; this kickoff document only adds the workflow framing and surfaces the load-bearing gotchas from the v0.2/v0.3 audit history.

**The single hardest constraint: this is analysis-only.** D1.C must NOT touch `a4/standalone/reward_v2.py`, `a4/standalone/fuzzer.py`, `a4/standalone/coverage_db.py`, `a4/standalone/compressed_global_extractor.py`, or anything else under `a4/standalone/`. Per spec §6 kickoff checklist: D2.B may be mid-flight on `_TXN_ROLE_BY_KIND` in `compressed_global_extractor.py`; do NOT edit that file. If you need a function from `a4/standalone/` (e.g., `extract_constraint_family` from `reward_v2.py`), IMPORT it — do not copy or modify.

**The second hardest constraint: channel-reconstruction commitment.** Per §1.4 Option A, the existing-channel set for Batch 1 is `{discovery_binary_reward, f_new_flag}` derived directly from `reward_counterfactuals` (no replay). Do NOT implement Option B (algebraic inversion — ruled out as underdetermined) or Option C (full replay — reserved for conditional Batch 1.5 only if Batch 3 triggers it). If you find yourself writing replay logic for `l_new`/`g_new`/`s_new` integers in Batch 1, stop and re-read §1.4.

---

## Scope (exactly what Batch 1 ships)

| File | Action | Rough size |
|---|---|---|
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | **NEW.** Module with `TIER1_SIGNALS` + `TIER2_METRICS` constants (per spec §1.2 — Tier-2 names declared as forward-decl for Batch 2 to fill in; Batch 1 only implements Tier-1), 5 Tier-1 signal extractor functions per §1.2 corrected APIs, `composite_substrategy_key()` helper per §1.4, `extract_existing_channels_per_db()` helper per §1.4 Option A, `extract_tier1_signals_per_db()` batch helper, `KIND_TO_SUBSTRATEGY_FIELDS: dict[str, tuple[str, ...]]` module constant populated empirically from the audit script | ~250–350 LOC |
| `a4/runs/iv_pos_7/analysis/test_bug_proximity.py` | **NEW.** ≥15 unit tests covering all 5 Tier-1 extractors + edge cases + composite-key construction across kinds + `f_new_flag` exact-proxy proof (test the three reward values: 0, 0.0001, 0.1896) + integration test on 1 real DB | ~250–350 LOC |
| `a4/runs/iv_pos_8/d1c/analysis/build_substrategy_field_audit.py` | **NEW.** Script: discover 30 Cat-A DBs via `cat_a_db_list()`; for each kind seen, count non-null occurrences per `mutation_substrategy` column; output `d1c_substrategy_field_audit.csv`; write the empirical `KIND_TO_SUBSTRATEGY_FIELDS` dict to stdout so it can be copy-pasted into `bug_proximity.py` (OR emit a Python file `bug_proximity_substrategy_fields_AUTO.py` that the module imports — your call, document the choice in the report) | ~80 LOC |
| `a4/runs/iv_pos_8/d1c/analysis/build_batch1_audit.py` | **NEW.** Script: discover 30 Cat-A DBs; for each, run `extract_tier1_signals_per_db()` + `extract_existing_channels_per_db()`; aggregate into `d1c_batch1_tier1_audit.csv` (150 rows: 30 DBs × 5 signals; columns per spec §2.1 task 6); sanity asserts (length == `COUNT(*) FROM mutations`, no NaN in fire_rate fields, fire_rate ∈ [0, 1]) | ~120 LOC |
| `a4/runs/iv_pos_8/d1c/analysis/build_batch1_plots.py` | **NEW.** Script: produce two PNG plots per spec §2.1 task 7 (signal × fire_rate_full histogram across 30 DBs; signal × fire_rate_post_local bar chart for 5 paired V5 seeds) | ~100 LOC |
| `a4/runs/iv_pos_8/d1c/d1c_substrategy_field_audit.csv` | **NEW artifact.** Kind × column × non-null-count across 30 DBs | data |
| `a4/runs/iv_pos_8/d1c/d1c_batch1_tier1_audit.csv` | **NEW artifact.** 150 rows: corpus × variant × seed × signal × fire_count × fire_rate_full × fire_rate_post_local × median_value (for continuous signals) | data |
| `a4/runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_full.png` | **NEW artifact.** Per-signal fire-rate histogram | image |
| `a4/runs/iv_pos_8/d1c/plots/d1c_batch1_fire_rate_post_local.png` | **NEW artifact.** Per-signal post-local fire-rate (paired V5 seeds) | image |
| `a4/docs/cloud2/composer/D1C_BATCH1_REPORT.md` | **NEW.** Composer-written report per workflow §5 below | ~3–5 pages |

**Total expected delta:** ~800–1000 LOC across ~5 source files + 4 data/image artifacts + 1 report. ~1.5–2 days at D1.B Batch 1 pace.

## NOT in Batch 1 (deferred to Batch 2 or Batch 3)

- **Any Tier-2 metric implementation** (Batch 2). The `TIER2_METRICS` constant in `bug_proximity.py` declares the 8 names as forward-decls (`TIER2_METRICS = ("pro_s5_verifier_accepted_invalid_count", ...)`) but no Tier-2 function bodies in Batch 1. Adding `def pro_s5_*` stubs that raise `NotImplementedError` is acceptable; implementing them is Batch 2.
- **Cross-correlation analysis** (Batch 3 — uses signals from Batch 1 + channels from Batch 1 + scipy.stats.pearsonr)
- **Shortlist composition / D1.E hand-off / Pro subsection / notebook** (Batch 3)
- **`d1c_tier2_schema.md`** (Batch 2 — D2.G coordination artifact)
- **`d1c_metrics_table.csv` / `d1c_paired_tests.csv` / `d1c_unpaired_means.csv`** (Batch 2)
- **Option C full replay** (conditional Batch 1.5 — only triggered if Batch 3 cross-correlation finds all 4 non-trivial Tier-1 signals have `|r| > 0.4` AND `disjoint_fire_rate < 0.3` per §1.4 lock decision)
- **Any production-code edits** (analysis-only by spec §3 + revisit plan §3.2)

If you find yourself touching any of the above, stop and confirm with Ivan before continuing.

---

## Workflow

1. **Read the spec end-to-end first.** Particularly:
   - §0.1.1 three-tier architecture + §0.1.2 D1.B saturation-inversion prereq narrative (so you understand WHY orthogonality + non-saturation are the gates)
   - §1.1 data sources table (which DB column each signal reads from)
   - §1.2 module-level constants + 5 Tier-1 corrected APIs + `f_new_flag` exact-proxy proof + `recent_marginal_discovery_rate` momentum/smoothing framing
   - §1.3 selection-criteria definitions (orthogonality, non-saturation, Cat-A/B labeling)
   - **§1.4 channel-reconstruction strategy — load-bearing.** Memorize the Option A commitment and the conditional Batch 1.5 trigger.
   - §2.1 Batch 1 task list (your scope)
   - §3 risk table (especially the `recent_marginal_discovery_rate` "expected high ρ" framing — Composer pushback B, captured intentionally as Bucket-C scalar-bandit candidate in Batch 3 shortlist)
2. **Open ONE PR for Batch 1**, squash-mergeable to `cloud2`. Branch name: `cloud2-d1c-batch1-bug-proximity`.
3. **Implementation order (recommended):**
   1. `bug_proximity.py` skeleton with module-level constants (`TIER1_SIGNALS`, `TIER2_METRICS`, `CORRELATION_THRESHOLD`, `NON_SATURATION_WINDOW`, `NON_SATURATION_MIN_FIRE_RATE`, `ROLLING_DISCOVERY_WINDOW`) — sets the public API surface
   2. The 5 Tier-1 extractor functions (smallest first: `f_new_flag` → `singleton_failure_flag` → `d_loc_le_2_flag` → `recent_marginal_discovery_rate` → `mutation_substrategy_uniqueness`). Each function gets its v0.3 docstring conventions: Cat-A/B tag, Pro Report 3 §X reference, source-table reference, computational-cost note. For `recent_marginal_discovery_rate`, paste the full v0.3 docstring (momentum/smoothing framing); do NOT rewrite it shorter.
   3. `composite_substrategy_key(kind, row)` helper — first version with a hardcoded `INSTR_WORD_MOD_SUR` fallback so unit tests have something to exercise
   4. `extract_existing_channels_per_db(db_path)` — reads `reward_counterfactuals.discovery_binary_reward` directly + derives `f_new_flag` from `fnew_only_reward > 0`. Two columns only per §1.4 Option A.
   5. `extract_tier1_signals_per_db(db_path)` — assembles per-pull signal dict using all 5 extractors
   6. Tier-2 forward-decl stubs (one-liners that `raise NotImplementedError("Batch 2 — see IV_POS_8_D1_C_SPEC.md §2.2")`)
   7. Unit tests in `test_bug_proximity.py` (synthetic inputs first; one real-DB integration test at the end)
   8. `build_substrategy_field_audit.py` — run it, copy the empirical `KIND_TO_SUBSTRATEGY_FIELDS` dict into `bug_proximity.py`, re-run any composite-key tests that now use the full empirical mapping
   9. `build_batch1_audit.py` — run it, verify CSV has 150 rows and sanity asserts pass
   10. `build_batch1_plots.py` — generate the 2 PNGs
   11. `D1C_BATCH1_REPORT.md`
4. **Self-checkpoint:** before submitting, manually run `pytest a4/runs/iv_pos_7/analysis/test_bug_proximity.py -q` and the full standalone suite (`pytest a4/standalone/tests/ -q`); both must be green. D1.B left ~497–499 standalone tests green; D1.C must not regress any.
5. **Write a Batch 1 report** (`composer/D1C_BATCH1_REPORT.md`) covering:
   - What you actually changed (with LOC counts per file)
   - Any deviations from the spec (and why) — especially if you found `mutation_substrategy` rows missing on any R2 DB (spec §3 marks this LOW risk per Composer's R2 V5 s1234 verification; if you find it on R2 V1 or any other DB, document and proceed with the V5+D1.A-only fallback)
   - The empirical `KIND_TO_SUBSTRATEGY_FIELDS` mapping you derived (paste the dict)
   - Test results (count + any flakes)
   - 2–3 sentence summary of what the Tier-1 audit CSV shows (e.g., "f_new_flag fires on ~X% of pulls; recent_marginal_discovery_rate decays from ~Y to ~Z over the campaign as expected"). Do NOT pre-judge orthogonality; that's Batch 3.
   - Any open questions or surprises for Ivan/Opus
   - Confirmation that NO production-code files were touched (run `git diff cloud2 -- a4/standalone/ | head` and paste the output)

---

## Pass criteria (Batch 1 ships)

- [ ] `a4/runs/iv_pos_7/analysis/bug_proximity.py` exists with all module-level constants from spec §1.2 + 5 Tier-1 extractor functions with v0.3-conformant docstrings (Cat-A/B tag, Pro §X ref, source-table ref, cost note)
- [ ] `composite_substrategy_key(kind, row)` helper exists and handles kind-specific NULL patterns
- [ ] `extract_existing_channels_per_db(db_path)` returns dict with keys `{"discovery_binary_reward", "f_new_flag"}` only (no replay) per §1.4 Option A
- [ ] `extract_tier1_signals_per_db(db_path)` returns dict with all 5 Tier-1 signal keys, lists of length `COUNT(*) FROM mutations`
- [ ] `KIND_TO_SUBSTRATEGY_FIELDS` populated empirically (not hand-guessed) from the 30-DB audit
- [ ] `TIER2_METRICS` constant declares 8 names per spec §1.2; Tier-2 function bodies raise `NotImplementedError` with a Batch-2 pointer
- [ ] `test_bug_proximity.py` has ≥15 tests; all green
- [ ] `f_new_flag` exact-proxy is tested with the three reward values 0, 0.0001, 0.1896 per spec §2.1 task 5
- [ ] `d_loc_le_2_flag` boundary tested at `d_loc=2` (fires) and `d_loc=3` (doesn't)
- [ ] `mutation_substrategy_uniqueness` tested with both an `INSTR_WORD_MOD_SUR` row and a `MEM_VAL_MOD` row (different non-null subsets) to confirm composite-key construction
- [ ] `d1c_substrategy_field_audit.csv` exists; covers all kinds present in the 30-DB corpus
- [ ] `d1c_batch1_tier1_audit.csv` exists with exactly 150 rows (30 DBs × 5 signals); no NaN in fire_rate fields
- [ ] 2 sanity plot PNGs exist
- [ ] Full standalone pytest sweep still green (no regressions)
- [ ] `git diff cloud2 -- a4/standalone/` shows ZERO changes (analysis-only enforcement)
- [ ] `D1C_BATCH1_REPORT.md` written per workflow step 5

---

## Where to look for help

| Question | Where to look |
|---|---|
| What does each Tier-1 signal mean / formula? | Spec §1.2 (function docstrings) + §0.2 Q-C-TIER1-CANDIDATES rationale |
| Why is `f_new_flag` derived from `fnew_only_reward > 0`? Why is that exact? | Spec §1.4 Rationale #2 (proof: `fnew_only_reward = 0.30 * sat(f_new, 1.0) = 0.30 * (1 - exp(-f_new))`; equals 0 iff `f_new = 0`) |
| Why don't we replay `l_new`/`g_new`/`s_new` integers in Batch 1? | Spec §1.4 Option A commitment + Rationale #1 (the bandit's actual learning signal is `discovery_binary_reward`, the OR of l+g+s; per-channel integers are reserved for conditional Batch 1.5) |
| Why is `recent_marginal_discovery_rate` expected to "fail" orthogonality? Is that bad? | Spec §1.3.3 expected-pattern note + §1.2 docstring momentum/smoothing framing. NOT a failure mode — captured intentionally as Bucket-C scalar-bandit candidate in Batch 3 shortlist (§2.3 task 3) |
| `mutation_substrategy` table — what columns are populated per kind? | Spec §1.1 (`coverage_db.py:356-369` schema) + §1.4 composite-key helper docstring. You'll DISCOVER the empirical mapping in Batch 1 task 3 — do NOT hand-guess it. |
| Where's the `cat_a_db_list()` helper? | Same place D1.B Batch 1 used it — `a4/runs/iv_pos_7/analysis/` or `a4/runs/iv_pos_8/d1b/analysis/`. Import it; do not redefine. |
| What's the 30-DB corpus exactly? | 10 R2 V1 + 10 R2 V5 + 10 D1.A new (V5-paired-static + decayexp + decayepoch). Same as D1.B Batch 1 audit. |
| Why is `verifier_accepted_invalid_count` Cat-A despite Pro §5 framing it as Cat-B-flavored? | Spec §1.2 docstring for `pro_s5_verifier_accepted_invalid_count` — D1.A spec `:539` locked the Cat-A SQL; the Pro §5-literal Cat-B variant is a different metric reserved for a later revision. NOT in Batch 1 scope anyway (Batch 2). |
| `mutation_substrategy` table missing on R2 V1? | Spec §3 risk table: LOW risk (Composer verified 6000 rows on R2 V5 s1234). If you find it missing on R2 V1, document in report and fall back to V5+D1.A subset for that one signal. |

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D1.C Batch 1 per the locked spec at `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` v0.3 (especially §2.1 task list + §1.4 channel-reconstruction Option A). Follow the workflow in `a4/docs/cloud2/composer/D1C_BATCH1_COMPOSER_KICKOFF.md`. Open one PR against `cloud2` named `cloud2-d1c-batch1-bug-proximity`. **D1.C is analysis-only — touch nothing under `a4/standalone/`.** Stop and ask before touching anything outside the Batch 1 scope listed in the kickoff. Pass criteria are the 14 checkboxes in the kickoff doc. Submit your work as a single PR plus a written report at `a4/docs/cloud2/composer/D1C_BATCH1_REPORT.md`.

---

*End of D1.C Batch 1 kickoff.*
