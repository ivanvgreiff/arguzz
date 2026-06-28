# Implementation, harness edits, binary decision, and POS run plan

> ⚠️ **SUPERSEDED — AS-BUILT differs from §A below.** Both V0 and V8 ship as **cli `--selector`s** (NOT drivers, NOT arm-round-robin): **V0 = `a4_uniform_semantic`** (`SemanticUniformArmSelector` over `SemanticArmUniverse.available_arms` — V5's same arm space) and **V8 = `a4_arguzz_sched`** (`ArguzzSchedA4Selector`: Arguzz instruction-balanced `.pick()` → `step_domain_map.to_user` translation → uniform A4 kind valid at that `user_cycle` (option b) → returns `(kind, user_cycle)` into the existing `_run_single_mutation` path, so the run-DB is analysis-compatible by construction). No new driver file; not in `V2_BANDIT_STRATEGIES` (no reward). Manifest gets a `--variants` filter. **Binary = FIXED + re-run V5 AND Hybrid** (40 jobs; reuse V6). The §Binary *analysis* below is correct; the §A V8/V0 code-shape is superseded — see commit `d6fe4d5`/`b660820` + `05` STATUS. (`_RID` generalization for the `a3seambfix` slug is still pending — `03`.)

Companion to `00_OVERVIEW.md` / `01_VARIANT_DEFINITIONS.md`. Verified file:line from the harness/architecture agents. **No code changed yet.**

## A. Code to write (the fuzzer side)
Order: build + locally smoke V0 and V8 **before** any registry/POS work (the `test_variant_launch_cmds` test, `tests/test_race.py:154`, iterates `CANONICAL_VARIANTS` and will fail until the launchers exist).

### A.1 New selectors
- **V0 (`SemanticUniformArmSelector`)** — `step_selector.py`, ~20 lines mirroring `UniformArmSelector` (`step_selector.py:416-454`) but over `SemanticArmUniverse.available_arms`: `arm = rng.choice(available_arms); step = rng.choice(steps_for_arm(arm)); return arm.kind, arm.zone, step`. No reward/update.
- **V8 (`RoundRobinArmSelector`)** — same file (or `bandit_ts.py` beside the schedulers), ~30 lines: a `_counter` over `available_arms`; `pick = least-pulled arm (rng tiebreak); bump; step = rng.choice(steps_for_arm(arm))`. No reward/update. (Mirrors `ArguzzScheduler._counter` discipline, ranged over A4 arms.)

### A.2 Wiring (the ~4 hardcoded dispatch sites — both selectors)
- `cli.py:205-221` — add the two selector names to `--selector choices`.
- `fuzzer.py:349-353` — add to the deferred-selector branch (build after inspection). Add a frozenset (e.g. `A4_NONBANDIT_SEMANTIC = {"V0_uniform","V8_arguzz_sched"}`) and OR it into the defer check. **Do NOT** add them to `V2_BANDIT_STRATEGIES` / `ALL_SEMANTIC_CTS_STRATEGIES` (that forces the bandit update path).
- `fuzzer.py:1838-1855` (`run_campaign` setup switch) — `elif strategy in A4_NONBANDIT_SEMANTIC:` → new `_setup_*` building `SemanticArmUniverse.build(self.data, self._active_mutation_kinds())` (A4-only, no `arguzz_kinds`) + the matching selector.
- Per-mutation run — route to an A4 single-mutation path (copy `_run_single_mutation` minus the scheduler/update; or generalize the `is_uniform` branch `fuzzer.py:1894-1910` to accept the semantic selector's `(kind,zone,step)` return). Recommend a tiny dedicated `_run_*` to avoid touching shared retry logic.
- These route through `run_a4_mutation` (the `A4_MUTATION_CONFIG` executor) ⇒ V0/V8 inherit the full A4 surface + telemetry/coverage schema for free.

### A.3 Registry — `variants.py:26`
```python
"V0_uniform":      VariantSpec(name="V0_uniform", launcher="cli", selector="V0_uniform",
                     driver_module=None, bernoulli_floor=False, applied_accounting=False,
                     surface="a4", archive_reuse=False, notes="A4 surface, semantic-uniform (no bandit) — scheduler-ablation floor"),
"V8_arguzz_sched": VariantSpec(name="V8_arguzz_sched", launcher="cli", selector="V8_arguzz_sched",
                     driver_module=None, bernoulli_floor=False, applied_accounting=False,
                     surface="a4", archive_reuse=False, notes="A4 surface, balanced round-robin (Arguzz-style, no bandit)"),
```
(Both `launcher="cli"` since we implement them as selectors, not drivers — simpler than a v6-style driver, and they route through the standard A4 fuzzer.)

## B. Harness — what's automatic vs must-edit
**Automatic (NO edit — derive from `CANONICAL_VARIANTS`):**
- `generate_race_manifests.py:23` `VARIANT_ORDER = tuple(CANONICAL_VARIANTS.keys())` + job-gen (`batch_rows:107`) — picks up new variants. **Side effect: default manifest jumps to 6×10=60 jobs** — restrict via `--variants` (§D).
- `generate_race_manifests.py` `_env_exports`/`_argv` — branch on `spec.launcher` (generic; cli variants get `A4_GLOBAL_RESIDUE=1` + `--telemetry-level full`).
- `markers.py`, `oracle.py` — fully variant-agnostic. The oracle find predicate `is_decode_divergent_itm` (`oracle.py:71`) handles V0/V8 ITM finds with zero change. The separate ablation lib (§E) imports them **read-only**.
- `fingerprint_guard.py` — keys off the *binary* (`planted_bug`/`load_rs2`), never the variant. No change.
- `dispatch_race.sh`, `chain_dispatcher.sh`, `prepare_race_bundle.sh` — manifest-row-blind plumbing. No change. (The repo-`cd`-before-guard fix applies to V0/V8 automatically.)
- `tests/test_race.py:134` `assert len(rows)==2*len(VARIANT_ORDER)` — auto-correct. `tests/test_race.py:154` `test_variant_launch_cmds` iterates `CANONICAL_VARIANTS` — gates that the V0/V8 launchers produce runnable argv.

**Must-edit (manifest/registry — shared infra, ALREADY landed):**
- `variants.py` `CANONICAL_VARIANTS` — `V0_uniform` / `V8_arguzz_sched` added (done).
- `generate_race_manifests.py` `--variants` filter — restricts the 6-variant default to the ablation set so it doesn't silently balloon to 60 jobs (done).

**Analysis = SEPARATE, self-contained harness (Ivan's separation directive — do NOT touch the published artifacts):**
- The published `race_lib.py` / `race_exploration.ipynb|.html` / `build_race_notebook.py` / `build_race_artifact.py` are the **LOCKED** 4-variant cross-surface-complementarity story on the **contaminated** `93bda33b` binary. They are **NOT edited** for the ablation.
- The scheduler ablation gets its **own folder** `a4/runs/iv_pos_9/race/sched_ablation/` with its own `sched_ablation_lib.py` (VARIANTS / COLORS / LABEL / SURFACE / a generalized `_RID` for the `a3seambfix` slug / `fig_scheduler_ablation`) + `build_sched_ablation_notebook.py` + its own `.ipynb`/`.html`.
- It **READS** the fixed-run DBs in `race/fix_thesis_results/` **in place** (never moves/modifies them) and **REUSES** `oracle.py` + `markers.py` (variant-agnostic) read-only by import. No cross-contamination of the published dataset.

## C. The BINARY decision (the consequential one — refines the harness agent)
V0/V8 are A4-surface ⇒ they hit the same 3 dead kinds (`TXN_PREV_WORD_MOD`/`TXN_PREV_CYCLE_MOD`/`CYCLE_DIFF_COUNT_MOD`) as V5/Hybrid on the head-`93bda33b` binary (`../../runs/iv_pos_9/race/CONTAMINATION_IMPACT_VERIFICATION.md`).

**The dead-arm distortion is scheduler-DEPENDENT, not a shared constant:**
- **V0 (uniform) & V8 (round-robin): binary-INVARIANT.** With no reward feedback, the 3 dead arms take a *fixed* share of draws whether they no-op (contaminated) or do real work (fixed). ITM's share — and thus the find count — is identical on either binary.
- **V5 (cTS bandit): binary-DEPENDENT (inflated on contaminated).** The dead arms earn ~0 reward → the bandit vacates them → the freed adaptive budget flows to ITM (the top live arm). On the fixed binary the 3 kinds earn real reward and reclaim adaptive budget → V5's ITM-rate (and find count) drops ~10–18% (the contamination-verification estimate).

⇒ On the **contaminated** binary, contaminated-V5 is inflated while V0/V8 are at their true rate → the V5-vs-{V0,V8} comparison **biases the ablation toward the bandit**. The bug-intrinsic `conditional_find_density` is clean but does *not* distinguish schedulers (the scheduler signal lives in `P(apply ITM)` / the find count — exactly what's distorted for V5).

**Options:**
- **(A) Same contaminated binary, run only V0+V8 (20 jobs), reuse published V5/Hybrid.** Cheapest. But the ablation's V5 column is contamination-inflated → the "bandit advantage" is overstated by ~10–18%. Defensible *only* if the writeup leans on `conditional_find_density` + `P(found)` and explicitly footnotes the V5 find-count inflation.
- **(B) Fixed binary, re-run V0 + V5 + V8 (+ optionally Hybrid) — RECOMMENDED.** Build the fixed binary (cherry-pick `6556e8d7` onto `workspace/risc0-seamb`; recipe in `CONTAMINATION_IMPACT_VERIFICATION.md §5`), then run the A4 trio on it. Gives a clean, unconfounded ablation AND retires the V5/Hybrid contamination footnote (the clean V5 number). The existing contaminated 40-run set stays as the published cross-surface complementarity result. Cost: 30 jobs (V0/V5/V8 ×10) or 40 (+Hybrid). V0/V8 are binary-invariant so they *could* run on either, but running the whole trio on one (fixed) binary removes any residual binary difference (head_sha, build nondeterminism) — cleanest.

**Recommendation: (B).** The whole point of the ablation is to attribute differences to the *scheduler*; option (A) leaves a known scheduler-correlated artifact in the most important comparison.

## D. POS run plan
- **DECISION = option B (fixed binary, 4 variants).** `--variants V0_uniform V5_control V8_arguzz_sched Hybrid_cTS` (40 jobs at ×10). The `--variants` filter is landed; default (no flag) = all 6 = 60 jobs, so the flag is **required**.
- **Same everything else:** seeds 1234–1243, N=5000, guest `--ctrl 7 --gseed 12345 --rounds 5`, 8-node EPYC pool, SSH-bypass + `chain_dispatcher` in tmux, `verifyopcode` guard profile.
- **SEPARATE results dir (separation directive):** pull the new DBs into `race/fix_thesis_results/` (smoke → `race/fix_smoke_results/pulled/`) — **never** the published `thesis_results/`. The separate ablation harness (§E) reads them there; the contaminated `thesis_results/` 4-variant dataset stays immutable.
- **Job/batch/ETA:** 4×10 = 40 jobs → 5 batches on 8 nodes. Per-mut ~2.2–3.3 s ⇒ ~4.6 h/job worst case ⇒ ~18–23 h. Fits an overnight / gapless reservation (resume-safe chain). Smoke 4×3 = 12 jobs → 2 batches.
- **Binary provenance (option B):** `EXPECT_HEAD_SHA` = the rebuilt fixed HEAD (the `6556e8d7` cherry-pick commit, distinct from `93bda33b`); `EXPECT_GUEST_ID` = re-read from the fixed binary (host-side handler shouldn't change the guest image — `build_seamb_fix.sh` asserts control==holed and reports it). Pass both via the manifest CLI (`--head-sha`/`--guest-id`); rebuild the bundle from `cloud2-sched-ablation`.
- **Bundle = `git archive HEAD`** (`prepare_race_bundle.sh:24`) ⇒ **commit the V0/V8 code (+ any `--variants` flag) BEFORE building the bundle** (same class as the dispatch_race.sh gotcha). Rebuild bundle after committing.
- **SMOKE FIRST (gate G-SMOKE):** V0+V8 (+V5 if option B) × 3 seeds × N=2000 → (i) prove the V8 launcher runs on POS, (ii) measure real V0/V8 per-mut timing for the thesis ETA, (iii) sanity: A4 surface ⇒ ITM-applied > 0 for both. Then dispatch the thesis N=5000.

## E. Analysis — a SEPARATE self-contained harness (NOT a patch to the published notebook)
Per Ivan's separation directive, the ablation analysis lives entirely in its **own folder** and never touches the published `race_lib.py`/`race_exploration.*`/`build_race_*`.

- **Folder:** `a4/runs/iv_pos_9/race/sched_ablation/`
  - `sched_ablation_lib.py` — its own `VARIANTS` (ladder order V8→V0→V5→Hybrid), `COLORS`/`LABEL`/`SURFACE`, a generalized `_RID` that matches the `a3seambfix` slug, `discover_runs` over `../fix_thesis_results/`, and `fig_scheduler_ablation`. Imports `oracle.py` + `markers.py` from the parent `race/` **read-only**.
  - `build_sched_ablation_notebook.py` + `sched_ablation_exploration.ipynb`/`.html` — the ablation's own notebook/artifact.
- **`fig_scheduler_ablation`** — the V8→V0→V5 ladder: a per-variant **`P(apply ITM)`** bar (the scheduler-attributable factor) annotated with `P(found)` (Wilson CI), and `conditional_find_density` shown ~constant (bug-intrinsic) → "the scheduler moves *how often ITM is applied*, not the per-ITM hit rate." Hybrid as a 4th bar (surface-mix reference).
- **Reads DBs in place:** `../fix_thesis_results/` (fixed run) — never the contaminated `thesis_results/`. No mixing of contaminated + fixed DBs in one dataset.
- **Oracle perf:** V0/V8 produce real ITM accepts to control-confirm (unlike zero-accept Arguzz) — run the oracle on a fast node or `--no-confirm` structural pass + a control-confirm sample (G-REPRO). V0 (uniform) may apply ITM at a different rate than V5 (cTS) ⇒ a different number of accepts to confirm. Control = `a4/builds/ap_seamb_fix/control/risc0-host` (the FIXED control).

## F. Caveats to record in the writeup
- Paired-seed RNG comparability across cli launchers is spec item A6 (`IV_POS_9_A3_SEAMB_RACE_SPEC §0.2`) — declared not load-bearing (we compare scheduler reachability, not RNG luck). V0/V5/V8 are all `cli` launchers ⇒ even closer than the V6_uniform-driver caveat.
- If option (A) is chosen, the V5 column's absolute find count is contamination-inflated (~10–18%); report `P(found)` + `conditional_find_density` as load-bearing and footnote it.
- The historical geometric V0 (Decision 1a) differs from the semantic V0 (1b) in arm discretization — if both are run, label them distinctly (`V0_uniform_geom` vs `V0_uniform_sem`).
