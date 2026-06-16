# D1.A — V5 Decaying-Floor Variant: Implementation Spec

**Parent plan:** `IV_POS_8_PRELIMINARY_PLAN.md` §3 D1.A
**Pro reference:** `ProG_Report_3.md` §7
**Status:** Locked-in — ready for Composer Batch 1 once §10 checklist confirmed

---

## 0. Goal recap

Pro §7 says V5's static 55% floor "is not a bug" but warns against leaving it frozen long-term. Pro proposes two alternative schedules:

```
Exponential decay:  floor_fraction(t) = max(0.20, 0.55 × exp(-local_coverage_seen / K))
Epoch-staged:       epochs 0–20: 0.55  |  21–40: 0.35  |  41+: 0.20
```

And explicitly warns: don't just sweep `coverage_floor_fraction` ∈ {0.50, 0.55, 0.60, 0.65}.

**D1.A deliverable to Pro (subsection inside D1 report):** results from V5-static vs V5-decay-exp vs V5-decay-epoch on 10 paired seeds × N=6000, with a verdict on whether dynamic decay improves over the static V5 baseline.

**Scope decisions (Ivan-confirmed):**

- **V5-static baseline = R2's existing V5 DBs** at `a4/runs/iv_pos_7/dbs/`. No re-run needed — back-compat is guaranteed by construction (`ConstantFloor(0.55)` → identical behavior) and verified by unit tests (golden-trace test in `test_bandit_ts.py`).
- **Local smoke abandoned.** Ivan's WSL hardware runs at ~46 sec/mut (22 mutations in 17 min = ~$0.65/mut); N=200 × 3 variants would be ~7.5 h wall. Anything ≥ 20 mutations runs on POS, not locally.
- **Pre-POS validation = integration tests + golden-trace test** (already complete in Batch 1/2). The first 8 production jobs (Batch 3, "smoke-gate") act as the deployment smoke before the rest of the 20-job campaign is committed.

---

## 1. Code architecture — what changes, where

### 1.1 Current state (verified from source)

| Symbol | Location | Current state |
|---|---|---|
| `ConstrainedTSScheduler` | `a4/standalone/bandit_ts.py:56` | `coverage_floor_fraction: float = 0.55` (constructor param, hardcoded constant) |
| `_floor_target()` | `bandit_ts.py:101` | `return self.coverage_floor_fraction * self.epoch_size / len(self.arms)` |
| V5 init | `a4/standalone/fuzzer.py:622–629` | `ConstrainedTSScheduler(self.semantic_arm_universe, seed=self.seed)` — all defaults, fixed 55% floor |
| Strategy choices | `a4/standalone/cli.py:205–214` | Fixed list including `cTS_semantic_v2`; no decay variants |
| V5 strategy whitelist | `fuzzer.py:103, 175` | `cTS_semantic_v2` in the v2-bandit dispatch set |
| Mutation counter | `bandit_ts.py:92, 194` | `_total_mutations` incremented in `update()` |
| Local discoveries counter | n/a in scheduler | Fuzzer's `db.record_failures()` returns `(total, new_coverage_count)` per mutation — sum of `new_coverage_count` IS the running `local_coverage_seen` |
| `campaign_params` table | `coverage_db.py:237` | Records `selector` + `extra_json` — used to persist `floor_schedule` config |

### 1.2 Proposed architecture

#### 1.2.1 New abstraction — `FloorSchedule` (in `bandit_ts.py`)

```python
class FloorSchedule:
    """Returns coverage_floor_fraction at a given scheduler state."""
    def current(self, *, total_mutations: int, local_discoveries: int) -> float: ...
```

Three concrete implementations:

| Class | Behavior | Params |
|---|---|---|
| `ConstantFloor` | Returns a fixed value (back-compat default) | `value: float = 0.55` |
| `ExponentialDecayFloor` | `max(floor_min, initial × exp(-local_discoveries / K))` | `initial=0.55, floor_min=0.20, K=50` |
| `EpochStageFloor` | Step function over `total_mutations`: piecewise constant | `stages: List[Tuple[int_lower_inclusive, float]]` = `[(0, 0.55), (2000, 0.35), (4000, 0.20)]` |

#### 1.2.2 `ConstrainedTSScheduler` changes

Add optional `floor_schedule: FloorSchedule = None` constructor param. If `None`, build `ConstantFloor(coverage_floor_fraction)` from existing `coverage_floor_fraction` arg — **back-compat preserved.**

`_floor_target()` becomes:
```python
def _floor_target(self) -> float:
    if not self.arms:
        return 0.0
    frac = self.floor_schedule.current(
        total_mutations=self._total_mutations,
        local_discoveries=self._local_discoveries,
    )
    return frac * self.epoch_size / len(self.arms)
```

New scheduler-internal counter: `self._local_discoveries: int = 0`. Updated **via external setter `update_local_coverage(n: int)`** that the fuzzer calls (Option B — Ivan-confirmed).

#### 1.2.3 Discovery counter plumbing — locked-in (Option B)

The fuzzer's `db.record_failures()` already returns `(total_recorded, new_coverage_count)` per mutation. The fuzzer accumulates this into a running counter and pushes to the scheduler:

```python
# fuzzer.py — in __init__ / reset
self._local_loc_discoveries: int = 0

# fuzzer.py — after each mutation, where record_failures is called
total_recorded, new_coverage = self.db.record_failures(mutation_id, failures)
self._local_loc_discoveries += new_coverage
if self.selector_strategy in {"cTS_semantic_v2", "cTS_semantic_v2_decayexp", "cTS_semantic_v2_decayepoch"}:
    self.v2_scheduler.update_local_coverage(self._local_loc_discoveries)
```

This is the **exact** value Pro means by `local_coverage_seen` — cumulative count of distinct legacy `constraint_loc` discovered so far, identical at end-of-run to `COUNT(*) FROM coverage` and to `local_context_final` in our metrics.

For `cTS_semantic_v2` (V5-static) the value is plumbed but ignored by `ConstantFloor` — no behavioral change.

#### 1.2.4 CLI / fuzzer strategy changes — **6 sites need updating, not 1**

Add two new selector strategy names (keep `cTS_semantic_v2` unchanged for back-compat):

| Strategy | Floor schedule | DB `selector` label |
|---|---|---|
| `cTS_semantic_v2` (existing) | `ConstantFloor(0.55)` — V5-static, identical to current production V5 | `cTS_semantic_v2` |
| `cTS_semantic_v2_decayexp` (new) | `ExponentialDecayFloor(initial=0.55, floor_min=0.20, K=50)` | `cTS_semantic_v2_decayexp` |
| `cTS_semantic_v2_decayepoch` (new) | `EpochStageFloor([(0, 0.55), (2000, 0.35), (4000, 0.20)])` | `cTS_semantic_v2_decayepoch` |

**Critical implementation detail (caught by Composer review):** `fuzzer.py` has **6 hardcoded `== "cTS_semantic_v2"` branches** that all share the semantic-zone code path. Decay variants must be admitted at every one of them; otherwise they silently fall into the kind-only branch.

Solution: define a module-level frozenset and replace all 6 equality checks with membership tests.

```python
# fuzzer.py — top of module
CTS_SEMANTIC_V2_FAMILY: frozenset[str] = frozenset({
    "cTS_semantic_v2",
    "cTS_semantic_v2_decayexp",
    "cTS_semantic_v2_decayepoch",
})
```

Then patch the 6 sites (verified by grep):

| Site | File:line | Current | Patched |
|---|---|---|---|
| Scheduler init dispatch | `fuzzer.py:622` | `if self.selector_strategy == "cTS_semantic_v2":` | `if self.selector_strategy in CTS_SEMANTIC_V2_FAMILY:` (+ inside the branch, switch on exact name to pick the FloorSchedule) |
| `select()` call | `fuzzer.py:846` | `== "cTS_semantic_v2"` | `in CTS_SEMANTIC_V2_FAMILY` |
| `bandit_zone` extraction | `fuzzer.py:863` | `== "cTS_semantic_v2"` | `in CTS_SEMANTIC_V2_FAMILY` |
| Zone-retry alt selection | `fuzzer.py:878` | `== "cTS_semantic_v2"` | `in CTS_SEMANTIC_V2_FAMILY` |
| Failed-config update | `fuzzer.py:889` | `== "cTS_semantic_v2"` | `in CTS_SEMANTIC_V2_FAMILY` |
| Post-mutation update | `fuzzer.py:1022` | `elif self.selector_strategy == "cTS_semantic_v2":` | `elif self.selector_strategy in CTS_SEMANTIC_V2_FAMILY:` |

Additionally:
- `cli.py:205–214` `--selector` choice list extended with the two new names
- `fuzzer.py:100–104` v2-bandit whitelist set (also a frozenset) extended with the two new names
- `fuzzer.py:175` `SELECTOR_LABEL_FOR_PARAMS` extended with the two new names → ensures DB's `campaign_params.selector` records the actual strategy name (not the family), so analysis pipelines can key on it without depending on `extra_json` alone

#### 1.2.5 Schema additions (small, forward-compatible)

While we're already touching `coverage_db.py` for `campaign_params.extra_json`, add three nullable columns on `mutations` table that D1.C needs (verified-missing in §1.3 schema audit):

| Column | Type | Default | Why |
|---|---|---|---|
| `proof_generated` | INTEGER (0/1) | NULL | Already computed in `MutationResult` but lost; D1.C metric `proof_generated_with_zero_residue_rejected` needs it |
| `proof_verify_failed` | INTEGER (0/1) | NULL | Same — computed and lost; needed for proof-outcome cross-tab |
| `elapsed_ms` | INTEGER | NULL | Already computed in `MutationResult.execution_time_ms`; needed for wall-clock metrics |

All three are NULL on legacy R2 DBs (use `ALTER TABLE … IF NOT EXISTS` pattern already used at `coverage_db.py:113–117` for `original_value`). New D1.A DBs populate them. **Zero risk** to existing DBs.

#### 1.2.6 Telemetry persistence — campaign_params.extra_json

`record_campaign_params` (`coverage_db.py:1190`) already accepts `extra` dict. Add:

```python
extra = {
    "floor_schedule_type": "constant" | "exponential" | "epoch",
    "floor_schedule_config": {
        # for exponential: {"initial": 0.55, "floor_min": 0.20, "K": 50}
        # for epoch: {"stages": [[0, 0.55], [2000, 0.35], [4000, 0.20]]}
        # for constant: {"value": 0.55}
    }
}
```

### 1.3 Schema audit — confirmed findings (drove §1.2.5 + revised D1.C scope)

Verified against `coverage_db.py` source:

| Need | Status | Evidence |
|---|---|---|
| `mutations.verifier_accepted` | **Already present** | `coverage_db.py:108` — populated by `_check_verifier_acceptance(output)` |
| `mutations.num_failures` | **Already present** | `coverage_db.py:107` — populated in `record_failures` |
| Per-mutation `d_loc`, `d_glob`, `d_ext` | **Already present** | `mutation_rewards` table — populated when `coverage_state` active (all bandit selectors qualify) |
| Per-mutation failure locs | **Already present** | `failures.constraint_loc` |
| `proof_generated`, `proof_verify_failed` | **MISSING** in DB | Computed in `MutationResult` (`fuzzer.py:761–762`) but never persisted → add per §1.2.5 |
| `elapsed_ms` per mutation | **MISSING** in DB | Computed in `MutationResult.execution_time_ms` but lost → add per §1.2.5 |
| `applied` vs `attempted` | Implicit | Skipped mutations don't call `record_mutation` → `COUNT(*) FROM mutations WHERE campaign_id=?` already = applied count |
| `floor_schedule` config | New | Persist via `campaign_params.extra_json` (existing mechanism) |

### 1.4 Why this design (defending choices)

| Choice | Why |
|---|---|
| New strategy names (not `--floor-schedule` flag) | V1–V5 are already differentiated by strategy name; analysis pipeline keys on strategy; less risk of accidental config drift; matches IV.POS.7 manifest pattern |
| `FloorSchedule` abstraction class | Keeps scheduler core clean; testable in isolation; extensible to future schedules |
| Back-compat default `ConstantFloor(0.55)` | Existing V5 strategy `cTS_semantic_v2` behaves bit-identically — no regression risk, no need for paid POS regression run |
| Option B faithful plumbing for `local_discoveries` | Uses `record_failures` return value (already computed); exact match to Pro's `local_coverage_seen` semantics |
| Epoch-stage in mutation-count space (not epoch-count) | `epoch_size=100` is internal scheduler concept; mutation_count is more interpretable and matches Pro's intent ("0–20 epochs" = first 2000 mutations at default epoch_size) |
| Schema columns added alongside (proof_generated etc.) | Cheap during this change; unlocks D1.C metrics without a second migration; legacy DBs unaffected |

---

## 2. Implementation steps (ordered, with Composer batches)

### Batch 1 — `FloorSchedule` + scheduler integration (~45 min)

**Composer tasks:**

| # | Task |
|---|---|
| 1.1 | Add `FloorSchedule` abstract base + three concrete classes to `bandit_ts.py`. Pure functional, no scheduler dependency yet |
| 1.2 | Add unit tests in `tests/test_floor_schedule.py`: constant returns same value; exponential decays monotonically and clips at floor_min (verify both regimes); epoch transitions at correct boundaries; all schedules return floats in [0, 1] |
| 1.3 | Extend `ConstrainedTSScheduler.__init__` to accept `floor_schedule` parameter (default None → `ConstantFloor(coverage_floor_fraction)`); add `_local_discoveries` counter; modify `_floor_target()` to use schedule |
| 1.4 | Add `update_local_coverage(n: int)` method for external plumbing |
| 1.5 | Extend tests in `test_bandit_ts.py`: scheduler with default args still passes existing tests; scheduler with `ConstantFloor(0.55)` produces identical decisions to legacy default for same seed; scheduler with `ExponentialDecayFloor` produces strictly decreasing `_floor_target()` over time; scheduler with `EpochStageFloor` produces step transitions at correct mutation counts |
| 1.6 | Run full test suite — all existing tests must still pass |

**Review checkpoint #1:** Verify back-compat (`ConstantFloor(0.55)` → identical to legacy), test coverage, no regressions.

### Batch 2 — CLI/fuzzer integration + schema + persistence + analysis discovery extension (~60 min)

**Composer tasks:**

| # | Task |
|---|---|
| 2.1 | Add two new strategy names to `cli.py` `--selector` choices and to `fuzzer.py` whitelist set |
| 2.2 | Add `CTS_SEMANTIC_V2_FAMILY` frozenset at module-level in `fuzzer.py` per §1.2.4 |
| 2.3 | Patch all **6 hardcoded `== "cTS_semantic_v2"` sites** in `fuzzer.py` (lines 622, 846, 863, 878, 889, 1022) to use `in CTS_SEMANTIC_V2_FAMILY`. Inside the line 622 branch, switch on exact `selector_strategy` to pick the matching `FloorSchedule` |
| 2.4 | Extend `SELECTOR_LABEL_FOR_PARAMS` at `fuzzer.py:175` with the two new names → DB `campaign_params.selector` records actual strategy name (not the family) |
| 2.5 | Add fuzzer → scheduler plumbing per §1.2.3: `self._local_loc_discoveries` counter + `update_local_coverage()` call after each mutation. Reset on `_reset_for_run`-style hooks |
| 2.6 | Add 3 nullable columns to `mutations` schema (`proof_generated`, `proof_verify_failed`, `elapsed_ms`) using the same `ALTER TABLE … IF NOT EXISTS` pattern as `original_value` at `coverage_db.py:113–117`. Extend `record_mutation` signature to accept these (default None) and populate from `MutationResult` at all 5 fuzzer call sites |
| 2.7 | Extend `_persist_campaign_params` (or wherever it's called) to write `extra={"floor_schedule_type": ..., "floor_schedule_config": ...}` for all three V5 variants |
| 2.8 | **Extend `discover.py` SELECTOR_TO_VARIANT** — add the two longer names BEFORE `cTS_semantic_v2` to avoid substring collision (the existing comment in discover.py already says "Longest selector first to avoid partial matches"). Map: `cTS_semantic_v2_decayexp` → `V5-decayexp`, `cTS_semantic_v2_decayepoch` → `V5-decayepoch`. Decision: keep R2's `cTS_semantic_v2` → `V5` mapping unchanged (so existing R2 analysis still parses as V5); D1.A analysis will key on `V5-decayexp` / `V5-decayepoch` for new variants and use `V5` for the R2-archive baseline |
| 2.9 | Add integration test in `tests/test_fuzzer_decay_schedules.py`: run each of three V5 variants for N=50 on a tiny inspection set; assert each produces non-empty DB with correct `campaign_params.extra_json` AND `campaign_params.selector`; assert new columns populated for new runs and NULL-tolerant for legacy DBs; assert mid-run `_local_loc_discoveries == COUNT(*) FROM coverage` at multiple checkpoints (belt-and-suspenders) |
| 2.10 | Add unit test for `discover.py.parse_db_path`: feeds names like `pos_iv_pos_8_d1a_b1_cTS_semantic_v2_decayexp_seed1234_n6000` and asserts it parses to `V5-decayexp`, not `V5` |

**Review checkpoint #2:** Verify all 6 fuzzer sites patched, CLI accepts new names, fuzzer dispatches correctly, persistence works, schema migration safe on existing DBs, `discover.py` correctly distinguishes decay from static, integration tests pass.

### Batch 3 — POS smoke-gate dispatch (8 jobs / ~5.5 h wall + checkpoint)

**Premise:** Local smoke abandoned (~46 sec/mut on Ivan's WSL is untenable). Instead, the first 8 of the 20 production jobs are dispatched together as a "smoke-gate" — they produce real D1.A data **and** act as a deployment sanity check before committing the remaining 12 jobs.

**Composer tasks:**

| # | Task |
|---|---|
| 3.1 | **Bundle build.** On WSL (cloud2 branch), confirm `risc0-host` exists at `workspace/output/target/release/risc0-host` (the cloud1 Inc 3 canonical binary, sha `6873e588...` per `PHASE_7D_INC5_WORK.md` §25). Run `bash a4/pos/prepare_bundle.sh --allow-dirty` (uncommitted Batch 1/2 work overlays into the bundle automatically — see `prepare_bundle.sh:116-125`). Verify `bundles/a4_campaign_<short>.tar.gz` produced. Record bundle SHA + git short SHA in the kickoff response. |
| 3.2 | **Manifest creation.** Create `a4/pos/manifests/iv_pos_8/d1a_b1.json` (smoke-gate, 8 jobs), `a4/pos/manifests/iv_pos_8/d1a_b2.json` (8 jobs), `a4/pos/manifests/iv_pos_8/d1a_b3.json` (4 jobs). Per-job pinning maps variant×seed to a specific `node_label`. See §5.2 of this spec for the locked layout. Hand-write the three files (small, ~30 lines each); no generator script needed for a 20-job campaign. |
| 3.3 | **Bundle deploy.** `rsync bundles/a4_campaign_<short>.tar.gz coinbase:~/`. Symlink `~/a4_campaign_iv_pos_8_d1a.tar.gz` → bundle. |
| 3.4 | **Calendar prerequisite** (Ivan does this): reserve all 8 nodes (flare octorand opulous polynize algofi gard goracle zone) for ≥ 20 h. Single multi-node reservation = 1 calendar event (within the 2-event cap per POS_PLAYBOOK §12.28). Composer waits for green-light before dispatching. |
| 3.5 | **Dispatch Batch 3 (smoke-gate).** From coinbase (in tmux): `python -m a4.pos.dispatch_pos --manifest a4/pos/manifests/iv_pos_8/d1a_b1.json --bundle ~/a4_campaign_iv_pos_8_d1a.tar.gz --nodes flare octorand opulous polynize algofi gard goracle zone --allocation-duration 0 --await`. The `--await` flag blocks until all 8 jobs report `.OK` markers. Expected wall: ~5.5 h (Tier-A is ~10% slower per IV.POS.7 evidence, sets the limit). |
| 3.6 | **Collect Batch 3 DBs.** `python -m a4.pos.collect_results_pos --campaign iv_pos_8_d1a_b1 --out a4/runs/iv_pos_8/d1a/dbs/`. Verify 8 DBs land. |
| 3.7 | **Batch 3 DB inspection** (pass criteria below). All 8 DBs must pass before Composer is allowed to dispatch Batch 4. |

**Pass criteria for Batch 3 (see §4.2 below for the full pre-flight + per-DB checklist).** Halt and report if ANY of these fail; do not auto-continue to Batch 4.

**Review checkpoint #3:** Opus + Ivan inspect Composer's Batch 3 report and the 8 new DBs (paired with the corresponding R2 V5-static seeds 1234–1237 in `a4/runs/iv_pos_7/dbs/`). Spot-check one paired seed end-to-end (V5-static vs V5-decayexp vs V5-decayepoch) to confirm decay behavior is visible at the bandit-decisions level (`floor` mode share differs from static). Greenlight required before Batch 4.

### Batch 4 — Production dispatch (remaining 12 jobs / ~11 h wall)

**Composer tasks:**

| # | Task |
|---|---|
| 4.1 | **Dispatch Batch 4a** (8 jobs, seeds 1238–1241 × 2 variants on all 8 nodes). `python -m a4.pos.dispatch_pos --manifest a4/pos/manifests/iv_pos_8/d1a_b2.json --bundle ... --nodes flare octorand opulous polynize algofi gard goracle zone --allocation-duration 0 --await`. ~5.5 h wall. |
| 4.2 | **Dispatch Batch 4b** (4 jobs, seeds 1242–1243 × 2 variants on 4 Tier-S nodes). `python -m a4.pos.dispatch_pos --manifest a4/pos/manifests/iv_pos_8/d1a_b3.json --bundle ... --nodes flare octorand opulous polynize --allocation-duration 0 --await`. ~5 h wall (Tier-S only — 4 Tier-A nodes idle, avoiding 10% Tier-A tax on the tail). |
| 4.3 | **Collect Batch 4 DBs.** `python -m a4.pos.collect_results_pos --campaign iv_pos_8_d1a_b2` and `--campaign iv_pos_8_d1a_b3`, both → `a4/runs/iv_pos_8/d1a/dbs/`. Verify 12 new DBs land. |
| 4.4 | **Full-campaign validation** (§4.4 below): 20 new DBs total (8 from Batch 3 + 12 from Batch 4), all `exit_code=0`, all `mutations=6000`, `campaign_params.extra_json` correct on every DB, new schema columns populated. Write `a4/runs/iv_pos_8/d1a/COLLECTION_REPORT.json` (analogous to IV.POS.7 `COLLECTION_REPORT_FINAL.json`). |

**Review checkpoint #4:** All 20 DBs land cleanly + COLLECTION_REPORT is GREEN. Greenlight for Batch 5 analysis.

### Batch 5 — Analysis + report subsection (~2 hours)

**Composer tasks:**

| # | Task |
|---|---|
| 5.1 | Create `a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py` reusing IV.POS.7 modules (`metrics.py`, `stats.py`). Variant set = V5-static (R2 archive — discovered via `discover.discover_dbs(Path("a4/runs/iv_pos_7/dbs"))` and filtered to `variant=="V5"`; actual layout is nested `dbs/pos_iv_pos_7_ts_b*_cTS_semantic_v2_seedYYYY_n6000/<dbfile>`), V5-decayexp (new, in `a4/runs/iv_pos_8/d1a/dbs/`), V5-decayepoch (new) |
| 5.2 | Generate CSVs: `d1a_metrics_table.csv` (**30 analysis rows = 10 V5-static from R2 archive + 10 V5-decayexp new + 10 V5-decayepoch new**), `d1a_paired_tests.csv` (V5-decayexp vs V5-static, V5-decayepoch vs V5-static, 10-seed paired t-tests), `d1a_floor_dynamics.csv` (per-variant per-time floor-mode share from `bandit_decisions` — V5-static has historical R2 data, decay variants have fresh data) |
| 5.3 | Generate plots in `a4/runs/iv_pos_8/d1a/plots/`: (1) theoretical floor-fraction curves for each schedule (no data needed); (2) cumulative coverage curves V5-static vs decay variants with std bands; (3) `local_context_final` bar with paired-test annotations; (4) bandit mode share over time (floor / adaptive / cold / singleton) per variant; (5) time-to-43 / time-to-46 distribution per variant |
| 5.4 | Draft D1.A subsection content (~2 pages): TL;DR + headline numbers + mechanism (mode shares) + verdict (does decay help / hurt / neutral, what scheduler ships for D2). Save as `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` |
| 5.5 | Report back with the 6 most important numbers + 5 plots for Ivan + Opus review |

**Review checkpoint #5:** Final D1.A subsection ready for inclusion in `IV_POS_8_D1_REPORT_FOR_PRO.md`.

---

## 3. Parameter choices (defended, not guessed)

### 3.1 K for exponential decay

Pro's form: `floor(d) = max(0.20, 0.55 × exp(-d / K))` where `d = local_coverage_seen`.

V5 baseline trajectory:
- Final mean `local_context_final` ≈ 46 (from R2)
- Discovery curve: most discoveries in first ~1500 mutations (per R2 plot 02), then slow climb
- Time-to-43: ~1017 mutations (per Pro §1)

For decay to be **meaningful but not crushing**, we want the floor to:
- Stay near 0.55 during the early discovery rush (~discoveries 0–15)
- Decay through the middle (~discoveries 15–35)
- Hit the 0.20 floor_min near saturation (~discoveries 40+)

**Verified table (computed via `python3 -c 'import math; max(0.20, 0.55 * math.exp(-d/K))'`):**

| K | floor @ 15 disc | floor @ 30 disc | floor @ 46 disc | Clip kicks in at d= | Interpretation |
|---|---:|---:|---:|---:|---|
| 15 | 0.2023 (at floor, just) | 0.2000 (clipped) | 0.2000 (clipped) | 16 | Too aggressive — clips right after 15 discoveries |
| 30 | 0.3336 | 0.2023 (at floor, just) | 0.2000 (clipped) | 31 | Decays through middle, clips at saturation |
| **50** | **0.4075** | **0.3018** | **0.2192** | **51** | **Smooth decay through whole V5 trajectory; clip just past 46-disc saturation** |
| 100 | 0.4734 | 0.4075 | 0.3472 | 102 | Too slow — barely decays even at final discoveries |

**Recommended: K = 50.** It produces a smooth, monotonic decay over V5's typical discovery range and only clips to `floor_min=0.20` at d=51 — i.e., just past V5's typical 46-disc saturation. This way the decay is continuously active throughout the campaign, with no abrupt floor-collision artifacts during the actively-discovering phase.

### 3.2 Epoch-stage boundaries

Pro's recommendation: epochs 0–20 = 0.55, 21–40 = 0.35, 41+ = 0.20.

Default `epoch_size = 100`. Translation to mutation count: epochs 0–20 = mutations 0–2000, etc.

At N=6000, this maps cleanly: 1/3 of the budget at each floor level. We use Pro's exact suggested boundaries:

```python
EpochStageFloor([(0, 0.55), (2000, 0.35), (4000, 0.20)])
```

No tuning rationale beyond "use Pro's defaults verbatim so results are directly attributable."

### 3.3 Other parameters held fixed (per V5 production defaults)

- `cold_start_pulls_per_arm = 3`
- `forced_singleton_pulls = 5`
- `epoch_size = 100`
- `prior_alpha = 1.0`, `prior_beta = 1.0`
- `N = 6000` (per-seed mutation budget)
- 10 paired seeds 1234–1243 (R2 / IV.POS.7 convention)

---

## 4. Tests we must run

### 4.1 Local unit tests (Batch 1 + 2)

| Test file | What it verifies |
|---|---|
| `tests/test_floor_schedule.py` (new) | `ConstantFloor(x)` returns x at every state; `ExponentialDecayFloor` is monotonic-decreasing in `local_discoveries`, returns `initial` at d=0, hits `floor_min` for large d (verified clip-on threshold); `EpochStageFloor` returns correct value at each stage boundary including transitions; all schedules return floats in [0, 1] |
| `tests/test_bandit_ts.py` (extended) | Back-compat: `ConstrainedTSScheduler()` with default args produces same RNG-driven decisions for given seed (golden-trace test); `ConstrainedTSScheduler(floor_schedule=ConstantFloor(0.55))` produces identical decisions to legacy default (proves wrapper is transparent); with `ExponentialDecayFloor` produces strictly decreasing `_floor_target()` over `update_local_coverage()` calls; with `EpochStageFloor` produces step transitions at correct mutation counts |
| `tests/test_fuzzer_decay_schedules.py` (new) | End-to-end: each new strategy name produces non-empty DB; `campaign_params.extra_json` records correct `floor_schedule_type` + config; `bandit_decisions` table has correct mode distribution; new schema columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`) populated; `_local_loc_discoveries` matches `COUNT(*) FROM coverage` at end-of-run |

### 4.2 Batch 3 (smoke-gate) pass criteria — required before Batch 4 is allowed

| Pre-flight check (before dispatch) | Pass criterion |
|---|---|
| `bash a4/pos/prepare_bundle.sh --allow-dirty` exits 0 | Bundle written; tar.gz contains the cloud2 changes (`grep -l ExponentialDecayFloor a4/standalone/bandit_ts.py` inside the bundle confirms new code is included) |
| `pytest a4/standalone/tests/ -q` (full suite) | 100% pass (494+ tests). Last run baseline: 494 passed / 7 skipped per Batch 2 report |
| `pytest a4/runs/iv_pos_7/analysis/test_discover_internal.py -q` | All discover-substring tests pass |
| All 8 nodes show in `pos calendar list-mine` for ≥ 20 h | Calendar reservation confirmed (Ivan-task) |
| Bundle SHA committed to docs | Record in Composer's kickoff response |

| Per-DB check (after Batch 3 dispatch, run on every one of 8 new DBs) | Pass criterion |
|---|---|
| DB count | exactly 8 (seeds 1234–1237 × 2 variants) |
| Exit code per job | `.OK` marker present on every node; no `.FAIL_rc*` |
| `mutations` row count per DB | exactly 6000 |
| `campaigns.ended_at` | non-NULL |
| `campaign_params.selector` | matches manifest strategy (`cTS_semantic_v2_decayexp` or `..._decayepoch`) |
| `campaign_params.extra_json.floor_schedule_type` | `"exponential"` for decayexp DBs, `"epoch"` for decayepoch DBs |
| `campaign_params.extra_json.floor_schedule_config` | `{"K": 50.0, "initial": 0.55, "floor_min": 0.20}` for decayexp; `{"boundaries": [[0, 0.55], [2000, 0.35], [4000, 0.20]], "epoch_size": 100}` for decayepoch |
| New schema columns | `proof_generated`, `proof_verify_failed`, `elapsed_ms` populated on all 6000 rows (no all-NULL columns) |
| `_local_loc_discoveries` end-of-run | matches `COUNT(*) FROM coverage` (integration test pattern at scale) |
| Decay-mode visibility | At least 1 of the 8 DBs has `bandit_decisions WHERE mode='floor' AND mutation_num > 200` — confirms decay schedule ACTUALLY engaged after cold-start (mut #144) at production scale. *N=200 local smoke wouldn't have shown this; N=6000 production data does.* |
| Pairing integrity | For each of seeds 1234–1237, the corresponding R2 V5-static DB exists in `a4/runs/iv_pos_7/dbs/` (paired analysis precondition) |

**If ANY check fails**: Composer reports the failure to Opus + Ivan immediately. Do NOT auto-continue to Batch 4. Possible recovery paths: re-dispatch failed nodes only (`dispatch_pos.py --retry-failed`); fix bug + new bundle; deeper investigation.

### 4.3 Batch 4 (production tail) pass criteria

| Per-DB check (12 new DBs from Batch 4a + 4b) | Pass criterion |
|---|---|
| Same per-DB checks as §4.2 | All 12 pass |

### 4.4 Full-campaign post-production sanity

| Check | Threshold |
|---|---|
| Total new DBs in `a4/runs/iv_pos_8/d1a/dbs/` | exactly 20 (10 seeds × 2 NEW variants) |
| `exit_code=0` | 20/20 |
| `mutations` row count | 6000 on every DB |
| `campaign_params.extra_json` | non-null, `floor_schedule_type` matches strategy on every DB |
| New schema columns | populated (not all-NULL) on every new DB |
| V5-static baseline | R2's existing DBs at `a4/runs/iv_pos_7/dbs/...cTS_semantic_v2.../` — used directly for paired analysis (10 seeds total: 1234–1243) |
| `COLLECTION_REPORT.json` | written at `a4/runs/iv_pos_8/d1a/COLLECTION_REPORT.json`; analogous schema to IV.POS.7 |

---

## 5. POS dispatch plan

### 5.1 Compute estimate

Calibrated from IV.POS.7 evidence (`PHASE_8_PLAN.md` §3): per-job wall ≈ 5 h on Tier-S EPYC 9354; ≈ 5.5 h on Tier-A EPYC 7543 (~10% slower); EPYC 9354 and EPYC 7543 race-equivalent for V5 (Inc 4 B11). Per-job wall sets the per-batch wall.

| Item | Value |
|---|---|
| Per-job wall (V5 at N=6000) | ~5 h Tier-S / ~5.5 h Tier-A |
| Jobs total | **20** (10 seeds × 2 NEW variants — V5-static reused from R2) |
| Nodes available | 8 (4 Tier-S: flare, octorand, opulous, polynize + 4 Tier-A: algofi, gard, goracle, zone) — *Ivan-confirmed 2026-06-16* |
| Batching | 3 sequential batches with a hard checkpoint after batch 1 |
| **Batch 3 (smoke-gate)** | 8 jobs on 8 nodes → ~5.5 h wall (Tier-A limits) |
| Checkpoint #3 | ~30 min Composer DB inspection + ~15 min Opus/Ivan review |
| **Batch 4a** | 8 jobs on 8 nodes → ~5.5 h wall |
| **Batch 4b** | 4 jobs on 4 Tier-S nodes → ~5 h wall (4 Tier-A idle on tail; avoids 10% Tier-A tax) |
| Collection + validation | ~1 h |
| **Total wall** | **~17.5 h** + ~2 h Composer setup/checkpoint/collection overhead ≈ ~19 h end-to-end |

**Savings vs original plan:** 10 fewer jobs (~15 node-hours) by reusing R2 V5-static DBs. **Savings vs 2-job gate option:** ~3 h total wall by sizing gate to all 8 nodes.

### 5.2 Manifest structure

Three hand-written manifest files at `a4/pos/manifests/iv_pos_8/`. Same JSON schema as IV.POS.7 (`pos_iv_pos_7_smoke.json` for reference). Variant pinning: each variant runs on 4 different nodes across the campaign (2 Tier-S + 2 Tier-A per variant), preserving race-equivalence assumptions (Inc 4 B11).

**`d1a_b1.json` — Batch 3 (smoke-gate), 8 jobs, seeds 1234–1237 × 2 variants on 8 nodes:**

| Variant | Seed | node_label |
|---|---:|---|
| `cTS_semantic_v2_decayexp` | 1234 | flare |
| `cTS_semantic_v2_decayepoch` | 1234 | octorand |
| `cTS_semantic_v2_decayexp` | 1235 | opulous |
| `cTS_semantic_v2_decayepoch` | 1235 | polynize |
| `cTS_semantic_v2_decayexp` | 1236 | algofi |
| `cTS_semantic_v2_decayepoch` | 1236 | gard |
| `cTS_semantic_v2_decayexp` | 1237 | goracle |
| `cTS_semantic_v2_decayepoch` | 1237 | zone |

**`d1a_b2.json` — Batch 4a, 8 jobs, seeds 1238–1241 × 2 variants on 8 nodes:** same node assignment by position (decayexp → flare/opulous/algofi/goracle; decayepoch → octorand/polynize/gard/zone), seeds 1238–1241.

**`d1a_b3.json` — Batch 4b, 4 jobs, seeds 1242–1243 × 2 variants on 4 Tier-S nodes:**

| Variant | Seed | node_label |
|---|---:|---|
| `cTS_semantic_v2_decayexp` | 1242 | flare |
| `cTS_semantic_v2_decayepoch` | 1242 | octorand |
| `cTS_semantic_v2_decayexp` | 1243 | opulous |
| `cTS_semantic_v2_decayepoch` | 1243 | polynize |

All jobs: `n=6000`, `telemetry_level="full"`, `image="debian-trixie"`, `no_internet=false`, `guest_args=["--in1", "5", "--in4", "10"]` (R2 standard per `pos_iv_pos_7_smoke.json`).

Per-variant node distribution across the full 20-job campaign:
- **V5-decayexp:** 10 seeds spread across flare ×3, opulous ×3, algofi ×2, goracle ×2 (≥1 of each tier)
- **V5-decayepoch:** 10 seeds spread across octorand ×3, polynize ×3, gard ×2, zone ×2 (≥1 of each tier)

This satisfies IV.POS.7's race-balanced-tiers heuristic without per-variant within-tier pinning (the latter is unnecessary given Inc 4 B11 race-equivalence between EPYC tiers).

### 5.3 Dispatch mechanism

Composer dispatches each batch as a single `python -m a4.pos.dispatch_pos --manifest ... --await` call from a tmux session on coinbase. Three sequential dispatches (1 per batch) with Opus/Ivan review checkpoint between Batch 3 and Batch 4a. No new orchestrator/chain-dispatcher needed — the dispatch_pos.py `--await` flag handles blocking on `.OK` markers natively. SSH-bypass fallback available if POS allocation is flaky.

---

## 6. Output structure (D1.A subsection)

The deliverable is a subsection inside `IV_POS_8_D1_REPORT_FOR_PRO.md`. Proposed structure:

```
## §3 D1.A — V5 floor schedule (response to Pro §7)

### §3.0 TL;DR
- Three V5 variants compared, testing TWO distinct hypotheses (Composer review insight):
  * V5-static (control, 55%)
  * V5-decayexp (K=50) — *discovery-triggered* decay: floor responds to coverage progress
  * V5-decayepoch (0/2000/4000) — *time-triggered* decay: floor responds to mutation budget elapsed
- Headline: <X% gain / -X% loss / no difference> on local_context_final
- Mechanism: <decay variants spend X% more on adaptive pulls / similar / less>
- Recommendation for D2: <ship V5-static / ship V5-decayexp / ship V5-decayepoch / inconclusive>

### §3.1 Setup
- Variants, parameters, K choice rationale (point to §3.1 of this spec for full table)
- Explicit framing: "decayexp tests whether the scheduler benefits from *adapting to its own progress* (more pulls on familiar arms once early discovery saturates); decayepoch tests whether the scheduler benefits from *adapting on a fixed schedule* regardless of how discovery actually progresses."
- Note: V5-static = R2 baseline (paired seeds; back-compat golden-trace-verified, not re-run)

### §3.2 Headline results
- Paired-test table V5-static vs V5-decayexp vs V5-decayepoch on local_context_final, AUC, time-to-43

### §3.3 Mechanism — where the budget went
- Floor / adaptive / cold / singleton share per variant
- Floor fraction over time plot — theoretical curves + observed curves (per variant)
- Cross-reference: does decayexp's adaptive share track local_coverage_seen as predicted? Does decayepoch's adaptive share rise cleanly at mutation 2000 / 4000?

### §3.4 What this means for D2
- Concrete recommendation for which floor schedule (if any) goes into Hybrid V7
- If decayexp wins → discovery-triggered floor is a generalizable architectural insight, port to Hybrid V7
- If decayepoch wins → simpler schedule, easier to ship
- If neither beats static → V5's 55% floor is genuinely calibrated for this workload; Hybrid V7 inherits it
```

Plots embedded:
1. Three floor-fraction curves (theoretical, illustrative)
2. Cumulative coverage curves with std bands
3. Final coverage bar with paired t-test annotations
4. Bandit mode share over time per variant
5. Time-to-43 / time-to-46 distribution per variant

---

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Back-compat break: wrapper accidentally changes V5 behavior | Batch 1 test 1.5 is a **golden-trace test**: same seed in legacy `ConstrainedTSScheduler` vs `ConstrainedTSScheduler(floor_schedule=ConstantFloor(0.55))` must produce identical decision sequences for N=100 steps. `ConstantFloor(0.55).current(...)` returns the same float as the legacy hardcoded `0.55`, so a passing golden-trace test rules out any divergence |
| **Substring collision in `discover.py`** (Composer-caught) | `cTS_semantic_v2_decayexp` would otherwise match the shorter `cTS_semantic_v2` first. Batch 2 task 2.8 fixes the SELECTOR_TO_VARIANT list (longest-first ordering); task 2.10 adds a unit test |
| **Decay variants silently fall into kind-only branch** (Composer-caught) | `fuzzer.py` has 6 hardcoded `== "cTS_semantic_v2"` sites. Batch 2 task 2.3 patches all 6 to use `CTS_SEMANTIC_V2_FAMILY` membership check |
| Plumbing `local_discoveries` from fuzzer to scheduler introduces a bug | Integration test in Batch 2 (task 2.9) asserts `_local_loc_discoveries == COUNT(*) FROM coverage` at MULTIPLE mid-run checkpoints, not just end-of-run |
| K=50 too aggressive or too conservative — decay produces no measurable effect | Even null result is Pro-relevant signal ("K=50 had no measurable effect over N=6000"); the mechanism plot (mode shares) still tells a story about scheduler internals |
| POS dispatch failure (we've had these) | Reuse IV.POS.7 chain-dispatcher (proven); SSH-bypass available as fallback |
| Epoch boundaries miss edge cases at N=6000 | Boundaries at 0, 2000, 4000 — well inside [0, 6000]; tests verify transitions |
| Schema migration breaks legacy DB analysis | New columns are nullable; `ALTER TABLE … IF NOT EXISTS` pattern proven safe (already used for `original_value`); all analysis SQL uses `COALESCE` or explicit NULL handling |
| `campaign_params.selector` records family name instead of actual strategy | Batch 2 task 2.4 extends `SELECTOR_LABEL_FOR_PARAMS` so the actual strategy name is recorded; analysis pipelines don't depend on `extra_json` alone |
| New strategy names break some downstream analysis pipeline | Search-and-add: extend `metrics.py` / `discover.py` variant maps in Batch 2 alongside scheduler changes (explicit in tasks 2.8, 2.10) |

---

## 8. Confirmed decisions (Ivan-locked)

| # | Decision | Rationale |
|---|---|---|
| D1 | Variant naming = `cTS_semantic_v2_decayexp` / `cTS_semantic_v2_decayepoch` | Matches existing `cTS_semantic_v2` convention; analysis pipelines key on these strings |
| D2 | K = 50 for exponential decay | Verified math (§3.1) shows smooth decay through V5's discovery range; clip at d=51 just past 46-disc saturation |
| D3 | Epoch boundaries = Pro's verbatim `(0, 2000, 4000)` | Attributes results to Pro's design |
| D4 | Discovery counter = **Option B** (faithful) via fuzzer `record_failures` return value | Exact match to Pro's `local_coverage_seen`; plumbing is trivial |
| D5 | Manifest naming = `a4/pos/manifests/iv_pos_8/d1a_b{1..3}.json` | Keeps subphase identity clear |
| D6 | DB destination = `a4/runs/iv_pos_8/d1a/dbs/` | Clean separation from R2 corpus |
| D7 | V5-static baseline = **R2 archive (no re-run)** | Back-compat guaranteed by construction (`ConstantFloor(0.55)`); verified by golden-trace unit test in `test_bandit_ts.py`; saves ~15 node-hours; paired analysis uses R2 V5 DBs |
| D8 | New schema columns (`proof_generated`, `proof_verify_failed`, `elapsed_ms`) added | Verified-missing from current schema; needed by D1.C; cheap to add now |
| D9 | Composer batch cadence = 5 batches as listed | Each is a natural review point |
| D10 | **Batch 3 redefined: POS smoke-gate dispatch (8 jobs, seeds 1234–1237 × 2 variants), not local smoke** | Ivan's WSL runs at ~46 sec/mut (Composer's partial run: 22 muts in 17 min, evidence in Batch 3 status report 2026-06-16); N=200 local would be ~7.5 h × 3 variants. Pre-POS gate value comes from integration tests + golden-trace test (already done in Batch 1/2). First 8 production jobs serve as the deployment smoke and contribute real D1.A data, with a hard human checkpoint before remaining 12 jobs dispatch. Resolved 2026-06-16 |
| D11 | **Dispatch pattern: 8 nodes for Batch 3 + 4a; 4 Tier-S only for Batch 4b** | Ivan confirmed 8 nodes available 2026-06-16 with longer reservation window. Sizing the gate to 8 jobs (vs 2) saves ~3 h total wall and gives 4× more validation data at the checkpoint with no per-batch wall penalty (~5.5 h is set by per-job time, not parallelism). Batch 4b shrinks to 4 jobs on Tier-S only to avoid 10% Tier-A tax on the tail |
| D12 | **No new orchestrator/chain-dispatcher; use `dispatch_pos.py --await` directly** | 3 sequential dispatches with human checkpoint between Batch 3 and Batch 4 is simpler than reusing `auto_run_iv_pos_7.sh` for a 3-batch campaign. Avoids new infrastructure |

---

## 9. D1.C preview — what overlaps with D1.A

(Detailed D1.C spec is its own document, but flagging here so we don't duplicate work.)

**Schema verification (§1.3) discovered:** most D1.C metrics are computable from EXISTING schema. The R2 V1–V5 corpus + new D1.A DBs both work:

| D1.C metric | Source data | Available on R2 DBs? |
|---|---|---|
| `verifier_accepted_invalid_count` | `mutations WHERE verifier_accepted=1 AND num_failures>0` | **Yes** |
| `mean / median / p95 d_loc` | `mutation_rewards.d_loc` | **Yes** (for bandit selectors with coverage_state active) |
| `singleton_failure_rate` | `failures` GROUP BY `mutation_id` HAVING COUNT=1 | **Yes** |
| `co_failure_graph_degree` | `failures` cross-join per mutation_id | **Yes** |
| `min_d_loc_per_target` | `failures` GROUP BY `constraint_loc` MIN | **Yes** |
| `applied_mutation_count` | `COUNT(*) FROM mutations` | **Yes** (skipped mutations don't get DB rows) |
| `proof_generated_with_zero_residue_rejected` | NEW columns from §1.2.5 + `mutation_rewards.d_loc/d_glob` | **No on R2** — only on new D1.A DBs (NaN for R2) |
| `wall_clock_per_mutation` | NEW `elapsed_ms` column | **No on R2** — only on new D1.A DBs |

This is **good news**: D1.C analysis can run on R2 V1, V5 + new D1.A DBs without expensive re-runs. V3/V4 are explicitly excluded per Ivan's earlier decision (deprioritized, not because data isn't available).

---

## 10. Effort estimate

| Batch | Status | Est. wall time | Cumulative |
|---|---|---:|---:|
| 1 — FloorSchedule + scheduler integration + golden-trace test | ✅ COMPLETE (Batch 1 report, 2026-06-16) | actual ~1 h | 1 h |
| 2 — CLI/fuzzer (6-site patch) + schema + persistence + `discover.py` extension + integration tests | ✅ COMPLETE (Batch 2 report, 2026-06-16) | actual ~2 h | ~3 h |
| 3 — POS smoke-gate (8 jobs, seeds 1234–1237 × 2 variants) + checkpoint | PENDING | bundle build ~15 min + manifest write ~10 min + dispatch wait ~5.5 h + 8-DB inspection ~30 min + Opus/Ivan review ~15 min | ~9.5 h |
| 4 — Production tail (Batch 4a: 8 jobs; Batch 4b: 4 jobs) + collection | PENDING | 4a ~5.5 h + 4b ~5 h + collection/validation ~1 h | ~21 h |
| 5 — Analysis (`build_d1a_artifacts.py`) + plots + subsection draft | PENDING | ~2 h Composer + ~30 min review | ~23.5 h |

**End-to-end wall for the full D1.A subphase: ~23.5 h** (~1 calendar day if started early). The POS compute dominates (~16 h of waiting); Composer's active time is ~4–5 h spread across that window.

**D1.A total: ~10 hours wall-clock**, of which ~4.5 hours is unattended POS compute. The Batch 2 expansion (from 45 → 60 min) absorbs Composer's two critical-fix recommendations.

---

## 11. Greenlight checklist before Composer Batch 1

Before sending Batch 1 kickoff to Composer, confirm:

- [ ] Ivan reviews this spec (decisions §8 locked, no remaining open questions)
- [ ] Composer review absorbed (§1.2.4 6-site fix, §2 Batch 2 task expansions, §7 risk additions)
- [ ] Branch is `cloud2` (confirmed)
- [ ] No conflicting work in flight (V6 companion is shipped + frozen)

When all four boxed, kick off Composer Batch 1 with this spec as the kickoff document.

**Workflow option (Composer review recommendation):** D1.A Batch 1 (scheduler/FloorSchedule) is pure code, no shared state with D1.B (CGC variant reanalysis on existing DBs). The two can run in parallel — one Composer thread on D1.A Batch 1, another on D1.B Batch 1. Ivan to decide if we go single-thread or parallel.

---

*End of D1.A spec. Ready for Composer Batch 1 on Ivan greenlight.*
