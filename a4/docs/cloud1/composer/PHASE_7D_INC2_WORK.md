# Phase 7d — Increment 2 Work Order

**Purpose:** run the 6 LOCAL audits that prove the variant infrastructure (bandit math, reward routing, coverage delta, DB schema, compressed-global pipeline, per-arm bite) is mathematically and structurally correct. These audits don't need many mutations and don't touch POS.

**Owner:** Composer
**Reviewer:** Opus
**Estimated time:** ~2-3 days (mostly write-time; runtime is small)
**Predecessor:** Inc 1.5 ACCEPTED (48-arm HYBRID universe is canonical)
**Gate to Inc 3:** all 6 audits PASS + report-back accepted

---

## 0. Required reading (DO FIRST)

1. `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md` §§ B3, B5, B6, B9, B10, E2
   — Per-audit specs. Each audit's "Goal / Why it matters / Acceptance gate / Script name" is canonical there.

2. `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` §§ D31, D32, D34, D38
   — These are the bandit-math / reward / telemetry decisions B3, B5, B6 must respect.

3. `a4/docs/cloud1/composer/PHASE_7D_INC1_5_REPORT.md`
   — The new 48-arm universe under HYBRID. Use these arms as canonical for E2.

4. `a4/standalone/bandit_ts.py`, `a4/standalone/reward_v2.py`, `a4/standalone/coverage_db.py`
   — The implementations under audit.

---

## 1. Variant inventory (you'll reference this often)

The 5 variants Phase 8 will run (from `cli.py:203-212`):

| Phase-doc name | CLI `--selector` value | Bandit type | Reward | Arm space |
|---|---|---|---|---|
| V1 | `zoned` | uniform-over-buckets (legacy) | legacy multiplicative | (kind, bucket) |
| V2 | `kindUCB_zoned_v1` | UCB1 (undiscounted) | legacy multiplicative | kind only |
| V3 | `kindUCB_zoned_v2_noQ` | UCB1 (undiscounted) | v2 additive (no Q_loc) | kind only |
| V4 | `kindTS_zoned_v2` | Thompson Sampling (Beta) | v2 additive | kind only |
| V5 | `cTS_semantic_v2` | Constrained Thompson Sampling | v2 additive + Bernoulli success | **(kind, semantic_zone)** ← uses the 48-arm HYBRID universe |

E2 runs on V5 (the 48-arm universe). B3 / B4 / B5 / B6 cover all 5.

---

## 2. The 6 audit tasks

### B3 — Bandit math correctness (property-based)

**File to write:** `a4/standalone/tests/test_bandit_property.py` (~120 LOC)

**Approach:** use `hypothesis` if it's already a dev dep (check `pyproject.toml` / `requirements*.txt`); otherwise write hand-rolled property loops with `random.Random(seed)`.

**Properties (per scheduler):**

| Scheduler | Property |
|---|---|
| `ConstrainedTSScheduler` | (1) `update(arm, 1)` increments `α` by exactly 1, `β` unchanged. (2) `update(arm, 0)` increments `β` by exactly 1, `α` unchanged. (3) `pulls[arm]` increments by exactly 1 on every `update` regardless of reward. (4) When ANY arm has `pulls[arm] < cold_start_pulls_per_arm` (default 3), `select()` returns `mode='cold'` and the selected arm has the lowest pull-count (deterministic round-robin per D29). |
| `KindLevelUCBScheduler` | (1) UCB1 score = `mean + c · sqrt(ln(t + 1) / n_i)` where `c = sched.c` (default `0.25` from `CalibratedParams.c_explore`, per D33), within `1e-9` floating-point tolerance. **NOTE (2026-06-10 RETROACTIVE FIX)**: this work order originally said `sqrt(2 · ln(N) / n_i)` — that's textbook UCB1 with c=√2 absorbed, NOT what the code does. The code uses an explicit `c` factor (D33: undiscounted UCB1 with c=0.25 for ablation continuity with IV.POS.5's calibrated value). Composer correctly tested the code's actual formula; the original work order spec was wrong. (2) For any pair (untried_arm, tried_arm), `score(untried) == +∞` > `score(tried)`. (3) Holding `n_i` and `N_total` fixed, score is monotonic non-decreasing in `mean`. (4) Holding `n_i` and `mean` fixed, score is monotonic non-decreasing in `N_total`. |
| `KindLevelTSScheduler` | (1)-(3) same as ConstrainedTS minus the cold-start round-robin. (4) Every `select()` draws a sample in `[0, 1]` for each arm (since Beta(α≥1, β≥1) has support in [0,1]). |

**Acceptance gate:** `pytest a4/standalone/tests/test_bandit_property.py -v` PASSES with all properties green. Use `Hypothesis.settings(max_examples=200)` or 200 manual random trials per property.

**Watch out:** the `cold_start_pulls_per_arm` default is in `ConstrainedTSScheduler.__init__`; don't hard-code 3 — read it from the instance.

**Estimated time:** 3 hr write + 5 min pytest.

### B5 — Variant reward formula routing

**File to write:** `a4/audits/B5_reward_formula_routing.py` (~80 LOC)

**Two-layer test:**

**Layer 1 — unit test:** for each of the 5 variants, instantiate the variant's reward computation function and feed a known input:
```python
test_input = {
    'L_new': 5, 'F_new': 2, 'G_new': 3, 'S_new': 1,
    'crash': 0, 'repeat': 0,
    # plus any legacy-reward fields needed
}
```
Assert the output matches the expected formula:
- V1 (`zoned`): legacy multiplicative — `Q_rep * Q_glob * S` (or whatever the legacy formula is in `step_selector.py`).
- V2 (`kindUCB_zoned_v1`): legacy multiplicative (same as V1).
- V3 (`kindUCB_zoned_v2_noQ`): v2 additive WITHOUT Q_loc term (per D31).
- V4 (`kindTS_zoned_v2`): v2 additive WITH all components.
- V5 (`cTS_semantic_v2`): v2 additive + Bernoulli success projection (per D32).

**Layer 2 — DB smoke check:** run a quick N=10 fuzz per variant. Verify in the resulting DBs:
- `mutation_rewards.reward_v2` IS populated for V3/V4/V5.
- `mutation_rewards.reward` (legacy column, if present) IS populated for V1/V2.
- V1 must populate BOTH columns (since V1 logs both for comparison; verify by reading `coverage_db.py::insert_mutation_reward`).

**Acceptance gate:** Layer 1 unit tests PASS for all 5 variants. Layer 2 smoke produces correct DB column population for all 5.

**Output file:** `audit_output/B5_reward_routing.json` with per-variant `{unit_test: PASS/FAIL, db_smoke: PASS/FAIL}`.

**Estimated time:** 2 hr write + 10 min run (5 × ~2 min smoke).

### B6 — Coverage-delta correctness

**File to write:** `a4/audits/B6_coverage_delta.py` (~120 LOC) + a small fuzzer instrumentation patch (a temporary boolean flag `--debug-coverage-delta`).

**The bug we're guarding against:** the additive reward depends on `L_new`, `F_new`, `G_new`, `S_new` being the DELTA from mutation `k` ONLY, not cumulative. If our code accidentally subtracts from `0` instead of from `bitmap_before_k`, every mutation looks maximally informative for the first few muts then zero thereafter.

**Approach:**
1. Add an instrumentation flag in `fuzzer.py` that, when set, captures `bitmap_before_k` and `bitmap_after_k` AROUND each mutation and dumps them to a JSONL side-channel file.
2. Run V5 with this instrumentation at N=20.
3. Read the JSONL; for each mutation compute `expected_L_new = popcount(bitmap_after_k & ~bitmap_before_k)`.
4. Read the DB's `mutation_rewards.l_new` for the same mutation_id.
5. Assert equality. Repeat for `f_new`, `g_new`, `s_new`.

**Acceptance gate:** 20/20 mutations have `db.l_new == expected_L_new` for all 4 delta components.

**Output file:** `audit_output/B6_coverage_delta.json` with `{n_mutations, n_matches, mismatches: [...]}` — mismatches must be empty.

**Watch out:**
- Use the EXACT same bitmap calculation the code uses — if `local_coverage_v2.py` uses `xxhash` or a particular hashing scheme, your reference calc must use the same.
- Remove the instrumentation patch after the audit (or keep it gated behind a flag).

**Estimated time:** 3 hr write + ~5 min run.

### B9 — DB schema integrity

**File to write:** `a4/audits/B9_db_schema_integrity.py` (~100 LOC)

**Approach:** read `coverage_db.py::_create_tables()` (or equivalent) and extract the canonical schema. For each DB produced by an N=10 smoke per variant:

1. Assert every expected table exists: `campaigns`, `mutations`, `bandit_decisions`, `arm_state_snapshot`, `mutation_rewards`, `mutation_substrategy`, `hook3_raw`, `local_coverage_v2`, `reward_counterfactuals`, `compressed_global_coverage`, `global_failures`, `failures`, `coverage`, `campaign_params`, `pilot_runs`.
2. For each table: compare `PRAGMA table_info(<table>)` against the canonical schema. NO extra columns. NO missing columns. Column types match.
3. Foreign-key validation: every `mutation_rewards.mutation_id` references an existing `mutations.id`. Every `bandit_decisions.mutation_id` (if column exists) references `mutations.id`.
4. Row-count sanity: `SELECT COUNT(*) FROM mutations` == N (10 for the smoke).

**Acceptance gate:** 5/5 variants pass all 4 checks.

**Output file:** `audit_output/B9_db_schema.json` with `{per_variant: {V1: {tables: ALL_PRESENT, schemas: MATCH, fks: VALID, n_mutations: 10}, ...}}`.

**Watch out:** the `mutations.original_value` column added in Inc 0 P2 must be in the canonical schema. If your B9 expected-schema is hardcoded, update it.

**Estimated time:** 2 hr write + 1 min run.

### B10 — Compressed-global pipeline end-to-end

**File to write:** `a4/audits/B10_compressed_global_e2e.py` (~100 LOC)

**Two checks:**

**Check 1 — DB-level:** from a V5 N=20 smoke DB (re-use B6's smoke if possible):
- `SELECT COUNT(*) FROM compressed_global_coverage WHERE region IS NOT NULL` ≥ 1.
- `SELECT DISTINCT region FROM compressed_global_coverage` returns ≥ 2 distinct regions (since our trace touches user_code, user_regs, host_io at minimum).
- No row has `region = 'unknown'` for addresses inside the platform.rs known regions (`0x00000000..0x0C000000`, `0x42000000..0x42000100`, `0xC0000000..0xFFFFFFFF`).

**Check 2 — round-trip unit test:** feed `compressed_global_extractor.py` synthetic Hook 3 dicts with known addresses:
- `0xFFFF0080` → expect region `user_regs`.
- `0x42000020` → expect region `host_ecall`.
- `0xC0000004` → expect region `kernel` (or whatever the canonical name is per D8).
- `0x00203f7c` → expect region `user_code`.

**Acceptance gate:** Check 1 passes AND Check 2 unit tests all PASS.

**Output file:** `audit_output/B10_compressed_global_e2e.json` with both checks' results.

**Note:** Composer's Task 5 fix from Inc 0-era (broken_addrs/broken_indices dict coercion) is what makes Check 1 non-empty. If this re-audit finds 0 rows again, the fix has regressed.

**Estimated time:** 2 hr write + 1 min run.

### E2 — Failure-class fingerprinting (informational)

**File to write:** `a4/audits/E2_arm_bite.py` (~150 LOC)

**Why this matters in plain English:** an arm is "real" (universe-builder accepts it) but that doesn't mean MUTATING THAT ARM ever produces a constraint failure. If an arm produces 0 failures across 5 mutations, the bandit will still pull it (because cTS rotates), but it produces zero learning signal. This audit measures per-arm "bite."

**Approach:**
1. For each of the 48 arms in V5's universe (read from `a4/audits/audit_output/A3_arms_in1_5_in4_10.json`):
   - Pick 5 random steps from the arm's `kept` step list (use seed=999 for determinism).
   - For each step: invoke the kind's `get_targets_at_step(step, data)`, pick the first target, build a mutation config, run the host with `A4_MUTATION_CONFIG` set, capture exit code + failure-class list.
2. Per arm, aggregate:
   - `n_mutations`: 5 (or fewer if arm has < 5 steps).
   - `n_with_failures`: how many of the 5 produced ≥ 1 constraint failure.
   - `mean_failures_per_mut`: average failure count.
   - `dominant_failure_family`: the constraint family that appears most often (using `failures.constraint_loc()` short form).
   - `family_distribution`: `{family: count}` map.
3. Emit `audit_output/E2_arm_bite.json` with per-arm rows.

**Acceptance gate (informational):**
- Audit completes for all 48 arms.
- Output produced.
- **Soft failure** (does NOT block Inc 3): if > 5 arms have `n_with_failures == 0`, flag them in E4 review queue (`composer/PHASE_7D_REVIEW_QUEUE.md`). The user/Opus will adjudicate.
- **Soft warning:** if > 3 arms in the same zone all have the same `dominant_failure_family` at > 90% concentration, flag as candidate-redundant in E4.

**Watch out:**
- Host runtime: 240 mutations × ~5 sec each ≈ 20 min. Run with `nohup` or in `tmux` if doing it locally.
- D42 non-determinism: MEM_VAL_MOD steps targeting the 188 non-det addresses will produce variable failures. Pre-filter them out of target selection.
- The 4 D40-dropped arms aren't in the universe; don't try to test them.

**Estimated time:** 3 hr write + ~30 min run.

---

## 3. Hard rules

1. **Don't change the bandit code, reward code, or DB schema.** B3-B10 are AUDITS, not refactors. If you find a bug, STOP and flag it; don't silently patch.
2. **Don't run on POS.** All Inc 2 work is local-only. POS audits are Inc 4.
3. **Telemetry level:** use `--telemetry-level full` for any smoke runs that need bandit_decisions / arm_state_snapshot data.
4. **Smoke seeds:** use `seed=999` for all Inc 2 smokes (consistent with prior increments; makes diffs comparable).
5. **Mutation count for smokes:** N=10 for B5/B9, N=20 for B6/B10. Don't go higher unless an audit's gate requires it.
6. **B6 instrumentation must be REMOVABLE:** if you add a `--debug-coverage-delta` flag to the fuzzer, gate it strictly so V5's normal path is unaffected. Default to OFF. Audit-only.
7. **Lessons from Inc 0/1.5:** report-back numbers from FRESH smoke runs only. Don't reuse a stale smoke DB if you've changed any code in between.

---

## 4. Acceptance gates (all must PASS)

| Gate | Criterion |
|---|---|
| B3 | property tests PASS for all 3 scheduler classes |
| B5 | per-variant reward unit test PASS + DB smoke shows correct column population |
| B6 | 20/20 mutations have `db.l_new/f_new/g_new/s_new == expected_delta` |
| B9 | 5/5 variant DBs have correct tables, schemas, FKs, row counts |
| B10 | compressed_global has ≥ 1 row with non-null region AND round-trip unit tests PASS |
| E2 | audit completes for all 48 arms; output produced; soft flags routed to E4 if needed (does NOT fail Inc 2) |

**Plus:** full fast test suite still passes (`pytest a4/standalone/tests/ -x` from repo root, ≥ 460).

---

## 5. Anti-patterns to avoid (lessons compounded across increments)

- ❌ Hardcoding magic numbers (cold_start_pulls=3, num_variants=5). Read them from canonical source.
- ❌ Assuming the legacy reward formula is what you think it is. Check `step_selector.py` / `coverage_db.py::insert_mutation_reward` for the actual call chain.
- ❌ Running B6/B10 against a smoke DB that was created BEFORE the Inc 1.5 HYBRID classifier landed. Use FRESH smokes.
- ❌ Conflating "passing all 5 variant smokes" with "passing all 5 variant correctness checks." V1's reward routing is different from V5's; spec each variant explicitly.
- ❌ Letting E2 block Inc 3. E2 is informational. If 5 arms come back with 0 bite, flag them and move on; don't fail Inc 2 over it.
- ❌ Wide diffs in a single commit. Each audit (B3, B5, B6, B9, B10, E2) is independently reviewable; commit them separately or at least keep their changes scoped.

---

## 6. When you're done

Expected file changes:

```
a4/standalone/tests/test_bandit_property.py                       (NEW)
a4/audits/B5_reward_formula_routing.py                            (NEW)
a4/audits/B6_coverage_delta.py                                    (NEW)
a4/audits/B9_db_schema_integrity.py                               (NEW)
a4/audits/B10_compressed_global_e2e.py                            (NEW)
a4/audits/E2_arm_bite.py                                          (NEW)
a4/standalone/fuzzer.py                                           (modified — guarded --debug-coverage-delta flag for B6 only)
a4/audits/audit_output/B5_reward_routing.json                     (NEW)
a4/audits/audit_output/B6_coverage_delta.json                     (NEW)
a4/audits/audit_output/B9_db_schema.json                          (NEW)
a4/audits/audit_output/B10_compressed_global_e2e.json             (NEW)
a4/audits/audit_output/E2_arm_bite.json                           (NEW)
a4/docs/cloud1/composer/PHASE_7D_INC2_REPORT.md                   (NEW)
a4/docs/cloud1/composer/PHASE_7D_REVIEW_QUEUE.md                  (updated if E2 surfaces soft failures)
```

**Report structure (`PHASE_7D_INC2_REPORT.md`):**

```
# Phase 7d — Increment 2 Report

## Summary
- B3: PASS (property tests for 3 scheduler classes)
- B5: PASS (5 variants reward routing verified)
- B6: PASS (20/20 coverage delta mutations match)
- B9: PASS (5/5 variant DBs schema-correct)
- B10: PASS (compressed_global e2e + round-trip)
- E2: DONE (informational; N arms flagged for E4 if any)

## Acceptance gate results
[table]

## Per-audit findings worth noting
[short summary per audit — anything surprising]

## E2 highlights (if any arms flagged)
- Zero-bite arms: [list with sample failure-class data]
- Candidate-redundant arms: [list]

## Files changed
[list]

## Open items / surprises
[anything notable]

## Ready-to-proceed
Inc 2 is green; please confirm to start Inc 3 (B1, B2, B4, B7 — fidelity audits with longer host runs).
```

STOP after writing the report. Wait for Opus review before starting Inc 3.
