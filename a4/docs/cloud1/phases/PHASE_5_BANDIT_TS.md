# Phase 5 — Constrained Thompson Sampling Bandit

**Status**: ✅ DONE (2026-06-08)
**Implementer**: Composer 2.5
**Reviewer**: Opus 4.7 (skeptical-review protocol)
**Pro reference**: `ProG_Report_2.md` §7.C, §7.D, §8 (Bernoulli signal), §8.1 (variant naming)
**Tests**: 13 Composer + 19 Opus adversarial = **32 bandit_ts tests**; fast suite **340 passed, 1 skipped** (was 308 after Phase 4).
**Files touched**: `a4/standalone/bandit_ts.py` (new, 370 LOC), `a4/standalone/tests/test_bandit_ts.py` (new, 175 LOC), `a4/standalone/tests/test_bandit_ts_adversarial.py` (new, ~300 LOC), `a4/standalone/fuzzer.py` (+~300 LOC: v2 setup, `_run_v2_bandit_mutation`, dispatch), `a4/standalone/cli.py` (+8 LOC: 4 new `--selector` choices), `composer/{PROPOSED_DECISIONS,PHASE_5_COMPOSER_SUMMARY}.md`.

> This is Phase 5's **post-completion retrospective** (Opus-owned). The Composer-facing plan that drove the implementation is preserved in git history at `phases/PHASE_5_BANDIT_TS.md@phase-4-handoff`; the version you're reading replaces it AFTER Composer's work was reviewed and approved.

---

## TL;DR (what was done; how it fits cloud1)

Composer delivered the **four IV.POS.7 bandit variants** (Pro §8.1) as wired-up selectors driven by a shared exec loop. From simplest to most adaptive:

| Variant | Internal name | Algorithm | Arm space | Reward signal | What it ablates |
|---|---|---|---|---|---|
| **V1** (baseline) | `uniform` (unchanged from Phase 0) | uniform draw | (kind, contiguous-step-bucket) | n/a | no learning |
| **V2** | `kindUCB_zoned_v1` | undiscounted UCB1 | kind only | **legacy** `compute_reward` | Same UCB+legacy reward = pre-cloud1 baseline anchor |
| **V3** | `kindUCB_zoned_v2_noQ` | undiscounted UCB1 | kind only | `compute_reward_v2` (no Q_loc) | V2→V3 isolates the **reward function** change |
| **V4** | `kindTS_zoned_v2` | Beta TS | kind only | `compute_bandit_success` (Bernoulli) | V3→V4 isolates **UCB→TS** algorithm change |
| **V5** (main candidate) | `cTS_semantic_v2` | Beta TS + 3-tier floor | **(kind, semantic_zone)** | `compute_bandit_success` (Bernoulli) | V4→V5 isolates **arm space** (kind-only → kind×zone) |

Each variant produces:
- A `BanditDecision` row per mutation → `bandit_decisions` table (Pro §12 — `arm_id`, `mode`, `score`, `runnerup_arm`, `runnerup_score`, `exploration`).
- An `arm_state_snapshot` row every 100 campaign mutations → for posterior-evolution plots.
- Every reward component + v2 reward + bandit_success persisted via Phase 4's component extractor.

**How it fits**: Phase 1-3 built the schema/zone/global-context plumbing; Phase 4 wrote the reward math; Phase 5 (this) writes the selection logic and wires both into the fuzzer loop; Phase 6 adds the rest of the logging; Phase 7 runs a real-host smoke; Phase 8 IV.POS.7 campaign; Phase 9 Pro Round 2 report.

---

## 1. Goal recap

(From the Composer-facing plan, summarized.)

Deliver three new scheduler classes (`ConstrainedTSScheduler`, `KindLevelUCBScheduler`, `KindLevelTSScheduler`) in `bandit_ts.py`, wire all four `--selector` choices into `fuzzer.py`+`cli.py`, persist `bandit_decisions` and `arm_state_snapshot` rows. **No pilot calibration (D2)**. Cold/singleton/floor priority per `PHASE_5_BANDIT_TS.md` §5.1.

---

## 2. Deviations from the original plan

| # | Original plan | What happened | Severity |
|---|---|---|---|
| ① | "step picking via `SemanticZoneStepSelector`" | `ConstrainedTSScheduler.select()` inlines uniform step pick from `steps_in_arm`; equivalent for non-singleton zones; selector still used as retry fallback in `_run_v2_bandit_mutation` | none (equivalent semantics; structural simplification) |
| ② | "`KindLevelUCBScheduler` uses CalibratedParams.gamma" implied | Used **undiscounted** UCB1 instead of `DiscountedUCBScheduler`-style | low (deliberate; documented as D33) |
| ③ | Full 500-mutation host smoke before declaring done | Partial smoke at N=89 only (wall-clock: ~32s/mutation = ~4.4h for 500) | low (Phase 7 will run N=200 on POS) |
| ④ | Snapshot trigger | Composer initially counted only successful mutations; **fixed mid-implementation** to use `mutation_num % 100 == 0` (campaign index, includes skips) | none (caught and fixed before delivery) |
| ⑤ | 4 D-decisions pre-flagged | Composer filed exactly 5 (D-E..D-I) | none |

All deviations documented in Composer's `PHASE_5_COMPOSER_SUMMARY.md` §4-§6.

---

## 3. Code changes

### 3.1 `a4/standalone/bandit_ts.py` (new file, 370 LOC)

Three scheduler classes + `BanditDecision` dataclass + `arm_id` helper.

**`ConstrainedTSScheduler.select()`** — strict 4-tier short-circuit:

```python
def select(self) -> BanditDecision:
    # 1. Cold-start (D28, D29 round-robin)
    cold = [a for a in self.arms if self.pulls[a] < self.cold_start_pulls_per_arm]
    if cold:
        chosen = self._pick_round_robin(sorted(cold))
        mode = "cold"
    else:
        # 2. Singleton floor (D10)
        singleton_need = [a for a in self.arms
                          if a in self._singleton_set
                          and self.pulls[a] < self.forced_singleton_pulls]
        if singleton_need:
            chosen = self._pick_round_robin(sorted(singleton_need))
            mode = "singleton"
        else:
            # 3. Per-epoch coverage floor (D9, D30)
            target = self._floor_target()
            under = [a for a in self.arms
                     if self.epoch_pulls[a] < target - _EPSILON]
            if under:
                chosen = min(under, key=lambda a: self.epoch_pulls[a])
                mode = "floor"
            else:
                # 4. Adaptive TS (D4, D32)
                thetas = self._sample_thetas()  # Beta(α, β) per arm
                sorted_arms = sorted(self.arms, key=lambda a: thetas[a], reverse=True)
                chosen, score, mode = sorted_arms[0], thetas[sorted_arms[0]], "adaptive"
    ...
```

**`KindLevelUCBScheduler`** — undiscounted UCB1, no zone axis:

```python
def _ucb(self, kind: str) -> float:
    n = self.pulls[kind]
    if n == 0:
        return float("inf")
    return self.reward_sum[kind] / n + self.c * math.sqrt(math.log(self.t + 1) / n)
```

(Note: `inf` only matters during cold-start; after each kind has been pulled ≥1, all UCB scores are finite. Verified.)

**`KindLevelTSScheduler`** — Beta(α, β) over kinds only; identical posterior arithmetic to ConstrainedTS but on a flat kind list.

### 3.2 `a4/standalone/fuzzer.py` (+~300 LOC)

- New module-level set `V2_BANDIT_STRATEGIES = {"kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ", "kindTS_zoned_v2", "cTS_semantic_v2"}`.
- New init path: when `selector_strategy in V2_BANDIT_STRATEGIES`, defer selector construction (needs `InspectionData`).
- New method `_setup_v2_bandit(num_mutations)`: builds the scheduler + arm universe + seeds `coverage_state` from baseline touch bitmap. **Bypasses pilot calibration entirely (D2)**; uses fixed `CalibratedParams(tau_new=35.0, tau_d=3.0, K_T_rare=31, gamma=0.9965)`.
- New method `_run_v2_bandit_mutation(mutation_num, total, stats)`: scheduler.select → mutation create (with up to 10 retries via `pick_step_in_zone` for cTS or `selector.select_step` for kind-only) → execute → compute legacy `reward` + `reward_v2` components + Bernoulli success → variant-specific scheduler update → persist mutation + failures + reward_diag + bandit_decision + (if `mutation_num % 100 == 0`) arm_state_snapshot.
- Updated `run_campaign()` dispatch: `if self.v2_scheduler is not None: result = self._run_v2_bandit_mutation(...)` precedes the legacy bandit/single paths.

**Variant-specific update dispatch** (the crux of D31/D32):
```python
if   self.selector_strategy == "kindUCB_zoned_v1":    self.v2_scheduler.update(kind, reward)        # legacy scalar
elif self.selector_strategy == "kindUCB_zoned_v2_noQ": self.v2_scheduler.update(kind, reward_v2)     # v2 scalar
elif self.selector_strategy == "kindTS_zoned_v2":     self.v2_scheduler.update(kind, bandit_success)  # Bernoulli
elif self.selector_strategy == "cTS_semantic_v2":     self.v2_scheduler.update(kind, zone, bandit_success)
```

### 3.3 `a4/standalone/cli.py` (+8 LOC)

`--selector` choices extended from `{zoned, guided, bandit, uniform}` to add the four v2 names. Help text updated.

### 3.4 Tests

**Composer's `test_bandit_ts.py`** (13 tests): cold-start floor, singleton floor, epoch floor enforcement, 1000-round convergence, snapshot row shape, UCB cold-start each kind once, UCB high-reward preference, TS posterior arithmetic.

**Opus's `test_bandit_ts_adversarial.py`** (19 tests): floor priority order pairwise (cold>singleton, singleton>epoch, epoch>adaptive), all-cold for N<150 with 50 arms (matches Composer's smoke obs), `first_non_cold_after_quota_exact`, round-robin seed-independence, epoch reset arithmetic (3 tests), UCB runnerup invariant (2 tests — documents tied-runnerup quirk + clear-winner case), determinism across 3 schedulers, Bernoulli posterior arithmetic (3 tests including bool coercion + unknown-arm no-op), empty-universe edge case, valid-step-in-arm invariant.

---

## 4. Test results

```
$ python -m pytest a4/standalone/tests/test_bandit_ts.py -v
13 passed in 0.22s

$ python -m pytest a4/standalone/tests/test_bandit_ts_adversarial.py -v
19 passed in 0.12s

$ pft  (full fast suite minus 7 long integration tests)
340 passed, 1 skipped in 31.68s
```

Math: 308 (post-Phase-4 baseline) + 13 (Composer bandit_ts) + 19 (Opus adversarial) = 340. **No regressions.**

### Host smoke (partial, wall-clock-bound)

Composer ran `cTS_semantic_v2` on real `risc0-host --in1 5 --in4 10`:
```
DB: /tmp/phase5_smoke100_tgiltjnc.db
elapsed_sec=5127  total=89  skipped=11  bandit_decisions=89  modes=[('cold', 89)]
```

**All 89 picks were `mode=cold`** — expected with ~50 (kind, zone) arms × cold_start=3 = 150 cold pulls before first `adaptive`. Validated my adversarial test `test_all_cold_until_quota_satisfied` against real-host arm cardinality. Full N=500 smoke deferred to Phase 7 (POS environment, ~4.4h locally).

`snapshots=0` was Composer's initial bug (counting only successful mutations); they fixed it to `mutation_num % 100 == 0`. With 89<100 a snapshot wasn't expected; first snapshot will fire at N=100 on the next run.

---

## 5. Acceptance criteria scorecard

| # | Plan exit criterion | Outcome |
|---|---|---|
| 1 | `bandit_ts.py` exports 3 schedulers + `BanditDecision` | ✅ all 4 in `__all__` |
| 2 | All ≥13 unit tests pass | ✅ 13 Composer + 19 Opus = 32 |
| 3 | Full fast suite still passes | ✅ 340 passed, 1 skipped |
| 4 | 4 new `--selector` choices in CLI | ✅ verified by import test |
| 5 | `bandit_decisions` + `arm_state_snapshot` rows wired | ✅ both `record_*` calls present in `_run_v2_bandit_mutation` |
| 6 | No pilot calibration (D2) | ✅ `_setup_v2_bandit` uses fixed `CalibratedParams`, never calls `calibrate_from_pilot` |
| 7 | No edits to `bandit.py`, `coverage_state.py`, `reward_v2.py` | ✅ all three `git diff` clean |
| 8 | D-decisions filed in `composer/PROPOSED_DECISIONS.md` | ✅ D-E..D-I + 5 promoted to D28-D32 by Opus, plus D33 (UCB undiscounted) added by Opus |
| 9 | `composer/PHASE_5_COMPOSER_SUMMARY.md` written from template | ✅ all 7 sections filled |

---

## 6. Opus's skeptical review — what I would have done independently

| Aspect | What I would have done | What Composer did | Verdict |
|---|---|---|---|
| Cold-start tie-break | `rng.choice(sorted(under_pulled))` | round-robin via `_cold_rr` counter | ✅ **Composer's is more rigorous** (deterministic fairness; seed-independent during cold-start) |
| Epoch-floor target denominator | `len(arms_with_pulls > 0)` (Composer Q3) | `len(self.arms)` (build-time) | ✅ **Composer's is correct** — floor should target the full arm space, not just visited ones |
| KindLevelUCB algorithm | Likely would have ported `DiscountedUCBScheduler` to be "equivalent to IV.POS.5" | Undiscounted UCB1 (clean V2↔V3 ablation, documented as D33) | ✅ **Composer's choice is better for the ablation structure** — but I flagged this as G5 since "exact IV.POS.5 rerun" isn't preserved. Pro may want to weigh in. |
| V3 reward signal | Initially I assumed `no_qloc_reward` counterfactual; then realized v2 has NO Q_loc by construction | Full `compute_reward_v2(...)` scalar | ✅ **Composer correctly identified that v2 IS the no-Q version**; counterfactual is for Phase 9 offline analysis |
| TS update signal | Bernoulli `compute_bandit_success` | Same | ✅ |
| Snapshot trigger | `mutation_num` (campaign index) | Same (after Composer's self-fix) | ✅ |
| Side-effect ordering in `update()` | Increment pulls/successes/epoch_pulls; reset on `_epoch_mutations >= epoch_size` | Same | ✅ |
| `select` empty-universe handling | Raise `RuntimeError` | Same | ✅ |
| KindLevelUCB runnerup when tied | Use `next((k for k in sorted_k if k != chosen), None)` | `sorted_k[1]` (can equal chosen if ties) | ⚠️ **Minor logging-quality quirk** — adversarial test `test_runnerup_can_equal_chosen_when_tied_FYI` documents this. Not a correctness bug; Phase 9 analysis can post-process. |
| KindLevelUCB cold-start | round-robin (matches ConstrainedTS) | `rng.choice(cold)` (random) | ⚠️ **Minor inconsistency** — kind-only schedulers use random tie-break, ConstrainedTS uses round-robin. Composer's D29 only applies to ConstrainedTS. Pre-IV.POS.7 not blocking; could be unified if Pro wants. |

**Net assessment**: Composer's implementation is correct. Two minor logging-quality quirks noted (UCB runnerup tie, kind-only random cold-start); both are non-blocking and documented. No required rewrites. One place Composer was BETTER than my sketch (round-robin cold-start for ConstrainedTS).

---

## 7. Insights (what we learned)

1. **Variant 2 is NOT a literal IV.POS.5 rerun.** Cloud1's arm space dropped the bucket axis (Pro §7.A), so a faithful replay would need a separate `ucb_kindbucket_b16_replay` variant. Composer's `kindUCB_zoned_v1` is a kind-only undiscounted-UCB1 baseline, chosen for V2↔V3 ablation symmetry. Flagged as G5 for Pro Round 2.

2. **All-cold for N≤150 with 50 arms is by construction, not a bug.** With 50 (kind, zone) arms × 3 cold-start pulls per arm, the first 150 mutations are necessarily mode=cold. Visible in Composer's host smoke (89/89 cold). My adversarial test now codifies this expectation.

3. **The two-tier "force protection" (cold + singleton) costs ~150-250 mutations of budget.** With 50 arms × 3 cold + ~10 singleton arms × 5 forced = ~200 mutations are "burned" on protection before pure adaptive TS kicks in. For an IV.POS.7 campaign at N=6000, that's 3-4% of budget — negligible.

4. **Epoch floor of 55% gives the adaptive layer ~45% of pulls per 100-mutation epoch.** Target per arm per epoch = `0.55 × 100 / num_arms`. For 50 arms, that's 1.1 pulls per arm per epoch as the floor. TS then gets to pick freely with the remaining 45 pulls. Pro's intended division-of-attention.

5. **Bernoulli signal makes Variant 4↔5 ablation cleaner.** Both use Beta-Bernoulli posteriors; the only structural difference is arm cardinality (8 kinds vs 50 kind×zone). Posterior arithmetic is identical, so any Phase 9 difference in arm-state evolution is attributable to arm space, not algorithm.

---

## 8. What's now possible

- **Phase 6** (extended logging) can add the remaining tables (`mutation_substrategy`, `hook3_raw`, `reward_counterfactuals` row writes, `pilot_runs` stays empty) without touching the bandit code.
- **Phase 7** can run a focused N=200 per-variant smoke on POS to verify (a) `bandit_decisions` modes show `adaptive` after N≈150, (b) `arm_state_snapshot` rows appear every 100 mutations, (c) v5's per-arm posterior diverges from v4's by N=200.
- **Phase 8** IV.POS.7 campaign: 5 variants × 10 seeds × 6000 mutations = 50 DBs.

---

## 9. Files touched (git-style)

```
A  a4/standalone/bandit_ts.py                            +370
A  a4/standalone/tests/test_bandit_ts.py                 +175
A  a4/standalone/tests/test_bandit_ts_adversarial.py     +300  (Opus)
M  a4/standalone/fuzzer.py                               +~298 (Composer; v2 setup, _run_v2_bandit_mutation, dispatch)
M  a4/standalone/cli.py                                  +8    (Composer; 4 new --selector choices)
M  a4/docs/cloud1/composer/PROPOSED_DECISIONS.md         +~95  (Composer; D-E..D-I)
A  a4/docs/cloud1/composer/PHASE_5_COMPOSER_SUMMARY.md   +~100 (Composer)
M  a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md         +D28..D33, +G5
M  a4/docs/cloud1/CLOUD1_STATUS.md                       Phase 5 done
M  a4/docs/cloud1/phases/PHASE_5_BANDIT_TS.md            this retrospective replaces the Composer-facing plan
```

No edits to `bandit.py`, `coverage_state.py`, `reward_v2.py`, `coverage_db.py`, or any Phase 1-3 module.

---

## 10. Consistency check against ProG_Report_2.md

| Pro §reference | Pro spec | Our implementation | Match? |
|---|---|---|---|
| §7.C floors | 50-60% reserved coverage floor; minimum pulls for boundary/rare zones | 55% epoch floor (D9), 5 forced singleton pulls (D10) | ✅ |
| §7.C cold-start | "guaranteed minimum pull count" for cold arms | 3 pulls/arm (D10) | ✅ |
| §7.D adaptive | Beta-Bernoulli Thompson sampling | `betavariate(α, β)` per arm | ✅ |
| §7.D Bernoulli signal | `success = 1 iff l_new + g_new + s_new > 0` | `compute_bandit_success` (D32) | ✅ |
| §8.1 variant table | V1 uniform, V2 kindUCB+legacy, V3 kindUCB+v2(noQ), V4 kindTS+v2, V5 cTS+semantic | All 4 wired into `--selector` | ✅ |
| §12 bandit_decisions | per-mutation row with arm, mode, score, runnerup | All fields populated | ✅ |
| §12 arm_state_snapshot | every E mutations, per-arm pulls + posterior | Snapshot at `mutation_num % 100 == 0`; rows include `posterior_alpha`, `posterior_beta`, `mean_reward` | ✅ |
| §9 no pilot | "remove calibration from the reward variants entirely" (D2 chose remove) | `_setup_v2_bandit` uses fixed `CalibratedParams`, no `calibrate_from_pilot` call | ✅ |
| §7.D no `KindLevelUCB` spec | (silent on UCB choice) | undiscounted UCB1 (D33) | ✅ (with G5 documented for Pro) |

---

## 11. Symbol reference

| Symbol | Defined in | Type | Meaning |
|---|---|---|---|
| `ConstrainedTSScheduler` | `bandit_ts.py:56` | class | V5 main candidate: kind×zone, 4-tier floor + Beta TS |
| `KindLevelUCBScheduler` | `bandit_ts.py:225` | class | V2, V3: kind-only undiscounted UCB1 |
| `KindLevelTSScheduler` | `bandit_ts.py:299` | class | V4: kind-only Beta TS |
| `BanditDecision` | `bandit_ts.py:30` | frozen dataclass | per-mutation logging payload: `kind, zone, step, arm_id, mode, score, runnerup_arm, runnerup_score, exploration` |
| `arm_id(kind, zone=None)` | `bandit_ts.py:44` | helper | `"INSTR_TYPE_MOD\|step0"` or `"INSTR_TYPE_MOD"` |
| `V2_BANDIT_STRATEGIES` | `fuzzer.py:93` | `frozenset` | the 4 IV.POS.7 selector names |
| `_setup_v2_bandit(num_mutations)` | `fuzzer.py:513` | method | constructs scheduler + universe; bypasses pilot |
| `_run_v2_bandit_mutation(...)` | `fuzzer.py:747` | method | one mutation tick under v2 bandit |
| `_step_to_zone` | `fuzzer.py:271` | `Dict[int, str]` | precomputed map from Phase 2's `classify_zones` |
| `_seen_local_v2 / _seen_compressed_global / _seen_structural` | `fuzzer.py:272-274` | in-memory sets | passed to Phase 4's `compute_reward_v2_components` |

---

## 12. Risks tracked forward

| Risk | Mitigation / next phase |
|---|---|
| All `mode="user"` in structural cells (config doesn't carry kernel-mode flag) | Phase 6/7 could inject privilege mode from cycle state once `InspectionData` exposes it. For IV.POS.7 the `S_new` cell space is at half size; acceptable. |
| UCB runnerup logging quirk (tied-runnerup may equal chosen) | Phase 9 SQL post-process if needed; non-blocking for live bandit |
| KindLevelUCB cold-start random vs ConstrainedTS round-robin | If Pro wants unified, change `rng.choice(cold)` → round-robin in `KindLevelUCBScheduler.select()` — 3-line change |
| V2 doesn't replicate IV.POS.5 exactly (G5) | Open question for Pro R2; can add `ucb_kindbucket_b16_replay` variant in follow-up if needed |
| Full 500-mutation smoke not run locally | Phase 7 will run N=200 on POS (the proper environment) |
| `_run_v2_bandit_mutation` retry uses different fallback paths for cTS vs kind-only | Tested via `test_select_returns_valid_step_in_arm`; no observed issue |

---

## 13. Composer's open questions (answered)

1. **Accept D28–D32 as official?** YES, promoted to D28-D33 with detailed justifications. **D33 added by Opus** for the undiscounted-UCB-vs-IV.POS.5 choice.
2. **Undiscounted UCB OK or share params.gamma?** Undiscounted is correct for the V2↔V3 ablation symmetry. Documented as D33; flagged to Pro as G5.
3. **Epoch-floor target use num_arms (build time) or only arms with pulls > 0?** Build-time `num_arms` is correct (your current implementation). Otherwise the floor would shrink as arms went unvisited, defeating the purpose.
4. **Re-run 500-mutation smoke locally?** No. Phase 7 N=200 on POS is the proper validation environment.

---

## 14. What Opus changed in OWN markdown after Composer finished

- `CLOUD1_DECISIONS_FOR_PRO_R2.md`: added **D28–D33** with detailed justifications; added **G5** (Variant 2 is not exact IV.POS.5 rerun); updated "If you wish to change…" reference list.
- `CLOUD1_STATUS.md`: marked Phase 5 done; decision-count 27 → 33; G-questions 4 → 5; Composer-quality risk row narrowed to "Phase 4 + 5 success — pattern fully confirmed".
- `phases/PHASE_5_BANDIT_TS.md`: this file replaces the Composer-facing plan (preserved in git history).
- `composer/*`: unchanged (Composer-owned per `composer/README.md` rules).
