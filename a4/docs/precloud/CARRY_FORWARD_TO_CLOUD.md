# Carry-Forward to Cloud — Consolidated Tracker

> **SUPERSEDED Jun 4, 2026 evening by `CARRY_FORWARD_TO_TESTBED.md`.**
>
> This file is preserved as a historical snapshot of the GCP-targeted plan; it captures the
> state of cross-phase concerns as of Jun 4 PM, before the pivot from Google Cloud to the
> university POS testbed. Do not edit. Read `CARRY_FORWARD_TO_TESTBED.md` for the live tracker.

# Carry-Forward to Cloud — Consolidated Tracker (historical, Jun 4 PM)

> **Purpose**: every cross-phase concern that the individual III.x reports identified as "keep in mind for IV / cloud", in ONE place. Created Jun 4, 2026 in response to "Each report in Phase III has takeaways and things to keep in mind for IV and cloud computations, are we keeping track of this?" — the answer was no, we weren't; this file fixes that.
>
> **How to use**: review this file before kicking off III.6, IV.0, IV.1, and IV.2. Each item has (a) source, (b) what it means for cloud, (c) status, (d) what action it implies.

---

## A — ProG_Report_1.md §5 minimal-checklist audit

Pro's explicit "minimal good-to-go checklist before cloud" from §5 of `ProG_Report_1.md`:

| # | Pro's requirement | Phase delivering it | Status |
|---|---|---|---|
| 1 | Implement global-aware reward via Option G (unified failure contexts) + revised U indicator | III.0 | ✅ DONE — `compute_reward` in `coverage_state.py:152-292` uses $F^{\text{ext}} = F^{\text{loc}} \cup F^{\text{glob}}$ end-to-end; U replaces Z. |
| 2 | Add counters/curves for $C_F^{\text{glob}}$, $C_F^{\text{ext}}$, $C_U$ | III.1 (structural) + III.3 (per-run rows) | ✅ DONE — `global_failures` table (III.1) + `mutation_rewards.U/d_glob/d_ext` columns (III.3). Curves are derivable by `SELECT SUM(...) OVER (ORDER BY mutation_id)`. |
| 3 | Run **local validation campaign (200-500 muts)** to sanity-check global contexts are nontrivial + reward differs across arms | III.6 | ⏳ PENDING — one-liner via `run_replicates.py` (III.4) |
| 4 | Run **cloud A/B with N=20k, R=5 replicates, B_count=16 fixed** | IV.1 | ⏳ PENDING — blocked on IV.0 (infra) and III.6 (local gate) |

**Two of four done. Two remain.** The third is the only thing blocking IV; the fourth IS IV.

---

## B — ProG_Report_1.md §6.1 primary endpoints — coverage audit

For each endpoint Pro names as "primary" or "secondary", confirm we have the data path to produce it:

| Endpoint | Definition | Where the data lives now | Plot path |
|---|---|---|---|
| $C_F^{\text{ext}}(t)$ | cumulative distinct extended (local ∪ global) failure contexts | `failures` + `global_failures` tables (III.1) | SQL window function over `mutations.id` |
| $C_F^{\text{glob}}(t)$ | cumulative distinct global contexts only | `global_failures` table (III.1) | `get_global_contexts_for_campaign` already implemented |
| $C_U(t)$ | cumulative count of U=1 runs | `mutation_rewards.U` (III.3) | `SELECT SUM(U) OVER (ORDER BY mutation_id) FROM mutation_rewards` |
| $C_T(t)$ | cumulative touch bitmap novelty | `mutation_rewards.delta_T` (III.3) | `SELECT SUM(delta_T) OVER (...) FROM mutation_rewards` |
| Histogram of $d_{\text{loc}}$ | distribution per run | `mutation_rewards.d_loc` (III.3) | `SELECT d_loc FROM mutation_rewards` |
| Histogram of $d_{\text{glob}}$ | distribution per run | `mutation_rewards.d_glob` (III.3) | `SELECT d_glob FROM mutation_rewards` |
| Histogram of $d_{\text{families}}$ | distribution per run | derivable from `global_failures` via `COUNT(DISTINCT family) GROUP BY mutation_id` | one SQL query at aggregation time |

All five primary endpoints + three secondary distributions are **SQL-authoritative** after III.3. The cloud aggregator does not need to parse any terminal logs.

---

## C — ProG_Report_1.md §8 boss-notebook coverage audit

Pro's recommended boss-notebook structure (§8), with implementation status:

| Pro's recommendation | Status | Notes |
|---|---|---|
| §8.1 4-number executive summary (final $C_F^{\text{glob}}$, $C_F^{\text{ext}}$, $C_U$, wall-clock/10k) with % improvement + CI | ⏳ pending IV.2 | Data path ready; need notebook cells |
| §8.2 plot 1: $C_F^{\text{glob}}(t)$ with CI bands | ⏳ pending IV.2 | Need bootstrap-CI over R=5 replicates |
| §8.2 plot 2: $C_F^{\text{ext}}(t)$ | ⏳ pending IV.2 | Same as above |
| §8.2 plot 3: near-acceptance quality (ECDF of $d_{\text{loc}}$ and $d_{\text{glob}}$) | ⏳ pending IV.2 | Data via `mutation_rewards.d_loc, d_glob` |
| §8.3 bandit-behaviour heatmap (time × arm × pull-frac) | ⏳ pending IV.2 | Data via `mutations.kind, step, executed_at` |
| §8.4 reframe Z events: "local-pass but global-fail" + "U" | ⏳ pending IV.2 | Both are SQL-derivable post-III.3 |
| §8.5 don't overemphasize mean reward | ⏳ remember | Notebook should show std(reward) per arm, not just mean |
| §8.6 Top-20 most interesting runs table | ⏳ pending IV.2 | Need a `SELECT ... ORDER BY (verifier_accepted DESC, U DESC, d_glob ASC)` join |

All eight items have a clear data path after Phase III work. None require new instrumentation.

---

## D — Per-Phase III.x report carry-forward items

### D.1 — From Phase III.0 (global-aware reward)

> Source: `PHASE_III_0_IMPLEMENTATION_REPORT.md` (not re-quoted here; the III.0 plan is what III.3 persists)

- ✅ The diag dict reflects all components Pro recommended. III.3 added schema-drift guardrails so any new field will surface a unit-test failure.
- ⚠️ **`tau_g` (global "too-broken" penalty scale) defaults to `2 * tau_d` per Pro §4.6** — this is calibrated once at pilot time. Cloud campaigns inherit this calibration from the pilot. *Action for IV.1*: log the calibrated `tau_g` per campaign so we can compare across replicates and confirm it's stable.

### D.2 — From Phase III.1 (DB schema for globals)

- ✅ `global_failures` table indexed on both `mutation_id` and `(family, address)` so aggregation queries are fast even at N=20k.
- ⚠️ **Cap is per Hook 3** (10 memory addrs, 20 lookup indices per family per mutation). At N=20k per campaign × 5 replicates × 5 strategies = 500k rows max per family — manageable.
- ⏳ **No retention policy.** Cloud DBs will grow. Action for IV.0: decide whether DBs are kept indefinitely (cheap on GCS) or purged after aggregation. **Recommend: keep all 5×3=15 raw DBs forever; downstream notebooks read directly from GCS.**

### D.3 — From Phase III.2 (uniform-arm selector)

- ✅ `UniformArmSelector` shares the same `ArmUniverse` as the bandit, so apples-to-apples comparison is valid. (Pro §6.2's "Uniform-Arm baseline" requirement.)
- ⚠️ **User explicitly chose to keep `zoned` in the comparison too** (3 selectors vs Pro's 2). This affects:
  - IV.1 cost: 3 × 5 = 15 cloud jobs per campaign batch, not 10. Roughly $\sim$50% more compute spend.
  - IV.2 plots: legend has 3 series, not 2.
  - Statistical power: pairwise tests become 3 instead of 1.

### D.4 — From Phase III.2.5 (circuit_debug fix)

> Source: `PHASE_III_2_5_FALSE_POSITIVE_TRACKING.md`

- ✅ Fix validated at 1000 muts: 0 false positives across all 8 mutation kinds.
- ⏳ **The fixed binary is at `workspace/output/target/release/risc0-host` (mtime Jun 3 22:20).** Cloud Dockerfile (IV.0 §11.2) must bake in **this** binary, NOT an older one from `workspace/risc0-modified/target/release/risc0-host` which may still have `circuit_debug` if that dir was built earlier. **Action for IV.0**: explicitly cite the source path with mtime check in `run_campaign.sh` startup.
- ⏳ **A backup of the buggy binary** at `/tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak` was kept for diffing. *Note*: `/tmp` does not survive reboot. If we want to keep it for posterity, move it to a stable location.

### D.5 — From Phase III.3 (reward-component persistence)

> Source: `PHASE_III_3_IMPLEMENTATION_REPORT.md` §7

1. ✅ **Schema-drift guardrail**: `test_full_compute_reward_roundtrip` fails if anyone adds a diag field without updating the schema. Cloud aggregator is protected.
2. ✅ **`mode` column** distinguishes crash / normal / accepted at the row level; cloud post-processing doesn't need fragile heuristics.
3. ✅ **`delta_T`, `delta_F` SQL-authoritative** — cumulative coverage curves are now a single window-function query.
4. ✅ **Per-mutation `Q_glob`** — answers Pro_Report_9 §5's open ablation question without re-running campaigns.
5. ✅ Backward compatibility validated against the 1000-mut DB (pre-III.3 code), no data disturbed.
6. ✅ Write cost negligible (< 1 ms vs ~70 s per `risc0-host` invocation).

### D.6 — From Phase III.4 (multi-seed replicate runner)

> Source: `PHASE_III_4_IMPLEMENTATION_REPORT.md` §7

1. ✅ **III.6 is now a one-liner**: `python -m a4.standalone.run_replicates --strategies uniform zoned bandit-16 --replicates 3 --num 200 ...`
2. ⏳ **Cloud keeps its own dispatcher** — `run_replicates.py` is local-only. IV.0's dispatcher fans out 5 seeds × 3 strategies = 15 single-seed jobs.
3. ✅ Parallel cap = `NCPU // 2` enforced; safe.
4. ✅ Manifest schema is forward-compatible; we can add `git_sha` etc. without breaking older readers.

### D.7 — From Phase III.5 (step-level cold-start)

> Source: `PHASE_III_5_IMPLEMENTATION_REPORT.md` (amended)

- ✅ Code matches Pro_Report_9.md §2.2 spec verbatim.
- ⚠️ **Operational step-level UCB is dead at our budget.** This is acknowledged as a design tradeoff (ProG_Report_1.md §2.1 raises it; §6.5 doesn't ask for a fix). The bandit's value is at the arm level (87% arm-UCB in postfix campaign).
- ⏳ **Master plan §10.4 acceptance criterion was wrong** — has been amended to remove the unreachable "step UCB > 0" gate. New criterion focuses on **arm-level** UCB fraction and reward-quality metrics.
- ⏳ **Hypothetical III.5b** (genuine architectural fix to make step-level matter) is **NOT on the cloud critical path** and is documented in `PHASE_III_5_IMPLEMENTATION_REPORT.md` §5.2 option (b). May revisit post-cloud if bosses ask "why does step level seem unused".

---

## E — What I got wrong about III.5 (full chain)

A single audit-trail entry because this was a real misunderstanding and the user caught it. Documenting it here so a future reader doesn't repeat it.

### E.1 The two distinct issues that the master plan §9 conflated

| Issue | Source | What it actually says | Whether the master plan §9 fix solves it |
|---|---|---|---|
| **A: arm- and step-level forced-exploration loop from decayed N** | [`Pro_Report_9.md §1.2`](../touch/Phase%20II/Pro_Report_9.md) | "select() never reaches the UCB branch. It always finds at least one arm with `N_a < n_min`, so it always does forced exploration" — caused by `gamma < 1` decaying `N_a` below `n_min`. **Fix**: use raw `m_a` counter (never decayed). | ✅ YES — bandit.py uses `arm_m == 0` and `step_m == 0` for cold-start, as Pro_Report_9 §2.2 prescribes. |
| **B: step-level UCB never fires because each arm has too many steps** | [`ProG_Report_1.md §2.1`](ProG_Report_1.md) | "step-level UCB never fired because each arm has too many candidate steps, so step selection remains cold-start/uniform". | ❌ NO — the raw-m fix doesn't change the structural arithmetic. With 246 steps / 7 pulls per arm, the set `{s : step_m[s]=0}` is non-empty forever at our budget. |

### E.2 The master plan §9.1 sentence that misled me (and originally was the wrong claim)

> "Pro §2.1 flags that step-level UCB never fires because each arm contains too many steps to ever exit cold-start. **The fix mirrors the arm-level cold-start fix already shipped in II.5a (raw `m_a` counter rather than decayed `N_a`).**"

This sentence wrongly implies that the Pro_Report_9 fix (which addresses issue A) ALSO solves issue B. It does not. The two issues have different root causes (decay vs sheer count of steps per arm) and require different mitigations.

### E.3 What ProG_Report_1.md actually says we should do about step-level

**Nothing concrete.** Pro identifies it as one of three reasons the old MAB looked similar to baseline (§2.1), notes "step-level policy not active" at N=1000 is unsurprising (§7.1), and explicitly recommends `B_count=16` for cloud A/B (§6.5) without proposing any architectural change to the step layer. The implicit position is:

> "Accept dead step-level UCB at our scale. The bandit's value is at the arm level. Don't restructure step-level before cloud."

### E.4 What I should have done originally

Said: "The code matches Pro_Report_9 spec; the master plan §9.5 acceptance ('Y > 0 in real campaign') is unreachable at our budget per ProG_Report_1.md §2.1 — let's amend it now instead of waiting for the campaign to confirm the impossible."

Instead I said: "Operational acceptance will be harvested from the postfix campaign when it finishes." The user correctly called this out. Amendments applied to master plan §9 + §10.4 and the III.5 report.

---

## F — Things to do BEFORE starting III.6

1. ✅ Master plan §9 amendment (DONE Jun 4)
2. ✅ Master plan §10.4 amendment to remove unreachable step-UCB cloud gate (DONE Jun 4)
3. ✅ This consolidated carry-forward tracker (THIS FILE)
4. ✅ Move `/tmp/risc0-host.WITH_CIRCUIT_DEBUG.bak` to a stable location — moved to `~/arguzz_backups/risc0-host.WITH_CIRCUIT_DEBUG.bak` (Jun 4 PM). Fixed-binary sha256 also pinned to `~/arguzz_backups/risc0-host.FIXED.sha256`.
5. ✅ One-page README for `a4/standalone/run_replicates.py` — written at `a4/standalone/README_run_replicates.md` (Jun 4 PM).

All five resolved. III.6 has begun: see `PHASE_III_6_IMPLEMENTATION_PLAN.md` (piggyback variant).

---

## G — Things to do BEFORE starting IV.0

These are the cloud-infra prerequisites that are NOT explicit in the master plan but that this tracker now surfaces:

1. ✅ **Fixed `risc0-host` binary baked into the cloud image with sha256 verification.**
   - Dockerfile takes `--build-arg EXPECTED_SHA256=...` and fails the build if the copied binary's hash differs.
   - `run_campaign.sh` re-records the sha256 at job startup and includes it in `campaign.meta.json`.
   - Pinned hash file: `~/arguzz_backups/risc0-host.FIXED.sha256` = `6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444` (Jun 4 PM).
2. ✅ **DB retention policy decided: KEEP ALL raw DBs forever on GCS.**
   - Reason: storage cost negligible (~50 MB × 15 = 0.75 GB at $0.02/GB-mo ≈ $0.015/mo); reproducibility benefit large.
   - Implementation: `run_campaign.sh` uploads `campaign.db`, `campaign.log`, `campaign.meta.json` to `gs://${A4_BUCKET}/results/<campaign>/<run_id>/`; no lifecycle rule applied.
   - Aggregation reads directly from GCS (no extract-and-purge step).
3. ✅ **`tau_g` logged per campaign** via the new `campaign_params` table (additive schema change Jun 4 PM).
   - `coverage_db.py`: `record_campaign_params` / `get_campaign_params` methods.
   - `fuzzer.py`: `_persist_campaign_params` hook called once per campaign, after the selector setup completes. Writes `tau_new, tau_d, tau_g, gamma, K_T_rare, b_count, selector, extra_json`.
   - 9 unit tests in `test_coverage_db_campaign_params.py` (passing).
   - Note: the currently running III.6 uniform + zoned campaigns won't populate this (they started before the code change); the bandit postfix campaign also doesn't. All future runs will. The boss notebook should handle both: SQL when present, fallback to log-parse when absent.
4. ✅ **Local re-run driver vs cloud dispatcher: documented in `a4/standalone/README_run_replicates.md`.** They are intentionally different tools; the local runner does not need containerization for IV.1.

**All four G-items resolved as of Jun 4 PM.** IV.0 is infra-ready; the remaining IV.0 work is the GCP-side setup itself (Artifact Registry repo, GCS bucket, `gcloud run jobs create`) which is in `a4/cloud/README.md`.

---

## H — Cross-cutting open questions that the master plan does not (yet) commit to

These are real questions the master plan punts on. They MUST be resolved before IV.1 or we'll burn cloud budget rediscovering them locally. **Proposed defaults in bold** — these become committed when the user confirms.

| # | Question | Why it matters | Proposed default | Where it should be answered |
|---|---|---|---|---|
| H.1 | **Should we ALSO run uniform-arm + zoned at $N=20$k in cloud?** Or just uniform-arm + bandit (Pro's recommendation), with zoned only at III.6? | Affects cloud cost by 50% (15 vs 10 jobs) | **Run all 3 strategies in IV.1** (uniform + zoned + bandit) so the boss can see all three head-to-head in the same notebook, justifying the extra $10. | IV.1 plan |
| H.2 | **At what N does step-level UCB start firing?** With B_count=16 and 246 steps/arm, you need ~31k step pulls just to coldstart every step at uniform — so at N=20k it's still dead. At N=50k it MAY start firing. | Determines whether III.5 (real architectural change) is needed before cloud, or whether the "accept dead step UCB" position holds. | **Accept dead step-UCB at N=5k (IV.1 default).** Add an IV.3 task to either (a) run one bandit replicate at N=50k post-cloud to see if step-UCB activates, or (b) restructure the step layer (Pro defers; we should too). Record Y/(X+Y) at step level in `mutation_rewards.extra_json` for diagnosis post-hoc. | IV.1 plan documents acceptance; IV.3 either probes or defers. |
| H.3 | **What's our stopping rule if cloud shows no separation by N=20k?** Pro §6.3 says "either reward is not informative, or the environment is truly flat for this guest program (bandit can't help)". | Hard call: do we (a) abort, (b) try weight A/B (IV.3), (c) try B_count=32 (Pro §6.5)? | **Two-strikes rule.** If IV.1 (N=5k) shows separation < 10% on $C_F^{\text{ext}}$ between bandit and uniform: try weight A/B (IV.3) with `tau_g, K_F_rare` swept. If THAT also fails, conclude "reward not informative for this guest" and put it in the boss notebook as a stated limitation. Do NOT chase B_count=32 first (cheaper to try weights). | IV.1 plan + IV.3 gate |
| H.4 | **Are we testing one guest program or several?** All the master plan and Pro work to date assumes the single `--in1 5 --in4 10` input. | The boss notebook should disclose this single-input limitation. | **One guest for IV.1.** Add a §15 master-plan note that multi-guest is explicitly deferred to V.x; the boss notebook discloses this loudly. Rationale: changing the guest invalidates the calibrated `tau_g, K_T_rare` etc., re-running calibration eats time we don't have. | IV.2 boss notebook (disclosed) + master plan §15 (deferred) |
| H.5 | **BigInt mutation kind for post-cloud expansion** | Pro §10 explicitly defers this. Just keep on roadmap. | **Defer to V.x.** Mention in boss notebook as "more kinds available; not enabled in this run to keep cost finite." | Master plan §15 |
| H.6 | **R=5 vs R=3 replicates** for IV.1 | R=5 is Pro's §6.4 recommendation; R=3 saves 40% cost ($31 → $18) at slightly wider CIs | **R=5.** Bandit variance across seeds is what the cloud A/B was designed to measure; halving R means halving statistical power. The extra $13 is cheap relative to the engineering time invested. | IV.1 plan |
| H.7 | **B_count fixed at 16 for IV.1** | Pro §6.5 explicit. The dead-step-UCB issue is a function of B_count and N (smaller B_count → more steps per arm → harder to coldstart). | **B_count = 16 fixed for IV.1.** Test B_count=32 as a knob in IV.3 if step-UCB matters to us post-IV.1. | IV.1 plan |

### Decision status

| # | Status | Locked in? |
|---|---|---|
| H.1 | **Proposed: all 3 strategies in IV.1** | ⏳ awaiting user confirmation |
| H.2 | **Proposed: accept dead step-UCB; defer architectural change** | ⏳ awaiting user confirmation |
| H.3 | **Proposed: two-strikes (weights then deferral)** | ⏳ awaiting user confirmation |
| H.4 | **Proposed: one guest; multi-guest deferred to V.x** | ⏳ awaiting user confirmation |
| H.5 | **Proposed: defer BigInt to V.x** | ⏳ awaiting user confirmation |
| H.6 | **Proposed: R=5** | ⏳ awaiting user confirmation |
| H.7 | **Proposed: B_count=16 fixed for IV.1** | ⏳ awaiting user confirmation |

All seven defaults are conservative ("do what Pro and the master plan already implied") or budget-protective ("don't sweep things we don't need to sweep"). If the user agrees with all defaults, lock them in by transcribing into master plan §12 (IV.1 spec).

---

## I — Master-plan diff (what changed Jun 4 PM in this audit)

```
M  a4/docs/precloud/PRECLOUD_MASTER_PLAN.md
   §9   (III.5):    status amended to distinguish code-faithfulness vs operational
   §10.4 (III.6):   acceptance criterion revised to remove unreachable step-UCB gate
A  a4/docs/precloud/CARRY_FORWARD_TO_CLOUD.md   (this file)
A  a4/docs/precloud/PHASE_III_5_IMPLEMENTATION_REPORT.md  (already amended Jun 4 PM)

(Jun 4 PM additions — IV.0-prep batch)
A  a4/docs/precloud/PHASE_III_6_IMPLEMENTATION_PLAN.md    (piggyback variant)
A  a4/cloud/Dockerfile                                    (sha256-verified build)
A  a4/cloud/run_campaign.sh                               (entrypoint + meta)
A  a4/cloud/dispatch.py                                   (Cloud Run Jobs dispatcher)
A  a4/cloud/README.md                                     (one-time GCP setup)
A  a4/notebooks/precloud_validation.ipynb                 (7-criterion gate)
A  a4/standalone/README_run_replicates.md
A  a4/standalone/tests/test_coverage_db_campaign_params.py (9 unit tests)
M  a4/standalone/coverage_db.py                           (+ campaign_params table)
M  a4/standalone/fuzzer.py                                (+ _persist_campaign_params)
A  ~/arguzz_backups/risc0-host.WITH_CIRCUIT_DEBUG.bak    (moved from /tmp)
A  ~/arguzz_backups/risc0-host.FIXED.sha256              (pinned hash)
```

---

## J — Triggered actions (do these next, in order)

1. **(DONE)** Amend master plan §9 + §10.4.
2. **(DONE)** Create this tracker.
3. **(DONE)** Move `risc0-host` backup to stable location.
4. **(DONE)** Pick III.6 variant: piggyback (3 campaigns at N=1000, 1 already done) over original 9-campaign §10.2 protocol. Plan written at `PHASE_III_6_IMPLEMENTATION_PLAN.md`.
5. **(DONE)** Pre-flight + launch the 2 missing III.6 campaigns (uniform + zoned at N=1000, seed=1234).
6. **(DONE in parallel while campaigns run)** Draft IV.0 infra: Dockerfile, run_campaign.sh, dispatch.py, cloud/README.md. All §G prerequisites baked in.
7. **(DONE in parallel)** Persist `tau_g` per campaign via new `campaign_params` table; 9 unit tests passing.
8. **(DONE in parallel)** Build `precloud_validation.ipynb` to compute the 7-criterion III.6 gate.
9. **(NEXT, ~6h wall)** Wait for III.6 campaigns to finish, run the notebook, compute gate verdict, write `PHASE_III_6_IMPLEMENTATION_REPORT.md`.
10. **(NEXT)** User reviews + locks in §H defaults; result transcribed to master plan §12.
11. **(NEXT, post-III.6 + post-§H lock-in)** Execute the GCP one-time setup from `a4/cloud/README.md` and submit `cloud_ab_v1` via `dispatch.py`.
