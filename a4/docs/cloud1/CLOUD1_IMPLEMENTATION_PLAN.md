# CLOUD1 Implementation Plan — Executing ProG_Report_2.md

**Source of truth**: `a4/docs/cloud1/ProG_Report_2.md` (ChatGPT Pro recommendations after IV.POS.5).
**Status**: LOCKED — all 12 design decisions confirmed 2026-06-08.
**Authors**: Cursor + Ivan Greiff.
**Date**: 2026-06-08.
**Companion**: `CLOUD1_DECISIONS_FOR_PRO_R2.md` — records every decision we made beyond Pro's explicit recommendations, with justifications, for transparency to ChatGPT Pro in Round 2.

---

## Agent division of labor (locked 2026-06-08)

| Agent | Role | Strengths leaned on |
|---|---|---|
| **Opus 4.7 (xhigh/max)** | Architecture, invariant reasoning, campaign design, critical review at end of each phase, debugging anomalies | Long-context, multi-file synthesis, design-intent grounding |
| **Composer 2.5 (fast)** | Bulk implementation to a spec, test scaffolding, mechanical refactors, harness/plumbing | Speed, cost, throughput |

**Per-phase contract** (Option A from `CLOUD1_AGENT_ONBOARDING.md`):
1. Composer reads `CLOUD1_AGENT_ONBOARDING.md` + the phase doc + the relevant `ProG_Report_2.md` sections.
2. Composer implements the phase, writes tests, runs the fast suite to green, and fills the retrospective.
3. **Opus reviews end-of-phase** (~15 min): checks TL;DR, consistency with Pro, D-decisions, hard-rule adherence.
4. If Opus finds drift, Opus files a single follow-up task; Composer fixes; only then move to next phase.

**Phase 3 exception**: Phase 3 is architecturally critical (compressed-global schema interpretation directly affects every `G_new` reward signal downstream). **Opus implements Phase 3 directly**. Composer picks up at Phase 4.

**Tripwire**: if Composer's review-fix cycle costs more Opus time than Opus would have spent doing the phase directly, we revert to Opus-only and log the failure mode for future reference.

---

## Meta-rules for this plan

1. **DO NOT deviate from ProG_Report_2.md.** Every concrete recommendation in that report has a phase below, marked with the report section number that introduced it (e.g. `[§7.A]`). If a phase has no section tag, it is an enabling/infrastructure step required to make the report's recommendations runnable.
2. **No phase begins until the previous phase passes its exit criteria.** This prevents the "let me just add one more thing" drift that bit us in IV.POS.5.
3. **The master plan (`a4/docs/precloud/PRECLOUD_MASTER_PLAN.md`) is on hold** until IV.POS.7 produces results that ChatGPT Pro reviews in a third round. After that round we revisit whether to continue the master plan or pivot further.
4. **No new mutation kinds, no N>6000 runs, no new guests** until phases 0-8 are done. Pro explicitly says this in `[§11]`.
5. **Every code change must be testable locally at N≤200 before going to POS.**
6. **Every phase retrospective MUST start with a "TL;DR — what did we do, and why does it matter for cloud1?" section** written in plain English (no jargon assumed). This is the user-facing summary; everything below it is reference detail. The TL;DR should:
   - Explain in 1-3 paragraphs what was actually built
   - Explain how it fits into the bigger picture (what enables what)
   - End with concrete numbers (LOC, tests, files) for at-a-glance status
7. **Re-read the relevant ProG_Report_2.md sections at the START of each phase**, not just at planning time. This catches drift between the plan and the source of truth.
8. **Every phase retrospective MUST contain a "Consistency check against ProG_Report_2.md" table** mapping Pro's recommendations → what we did → ✅/⚠️/❌.
9. **Every deviation (even cosmetic) MUST be recorded in `CLOUD1_DECISIONS_FOR_PRO_R2.md`.** ChatGPT Pro will review this in Round 2, so it must be complete and honest.

---

## 0. LOCKED design decisions (confirmed 2026-06-08)

All decisions confirmed by user. See `CLOUD1_DECISIONS_FOR_PRO_R2.md` for the detailed justification of each choice and which were made by us vs Pro.

| # | decision | choice | source |
|---|---|---|---|
| D1 | Seeds per variant for IV.POS.7 | **10** paired seeds (Pro's "better") | user override of my (a) recommendation |
| D2 | Pilot calibration in IV.POS.7 | **Remove pilot calibration entirely** (all variants use fixed defaults from `reward_v2.py`) | user-confirmed; Pro allowed this in §9 |
| D3 | Guest program scope | **sha2-host only** | user-confirmed; Pro §11 step 5 |
| D4 | Thompson sampling prior | **Beta(1, 1)** uniform | user-confirmed; Pro implicit (conjugate to Bernoulli) |
| D5 | Code layout | **Alongside existing in `a4/standalone/`** with `_semantic`/`_ts`/`_v2` suffixes | user-confirmed; Pro silent |
| D6 | Old strategy retention | **Keep all 3 runnable**, no archival | user-confirmed; Pro silent |
| D7 | Semantic zones not present in guest | **Define all 17 zones**, runtime-skip empty | user-confirmed; Pro silent |
| D8 | Compressed global context schema | **Verbatim from Pro §5** | user-confirmed |
| D9 | Constrained-TS floor / adaptive split | **55/45** (middle of Pro's 50-60% range) | user-confirmed; Pro range §7.C |
| D10 | Cold-start pulls per (kind, zone) arm | **3** pulls (matches old `_N_TARGET`) | user-confirmed; Pro silent |
| D11 | POS execution mode | **Continuous 3-parallel** multi-day | user-confirmed; proven from IV.POS.5 |
| D12 | `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` disposition | **Leave as historical record** + add top-line note | user-confirmed |

### Updated budget impact from D1 = 10 seeds

| variants × seeds × N | total mutations | sequential GPU-hours | wall-clock 3-parallel |
|---|---|---|---|
| 5 × **10** × 6000 = 50 runs | 300,000 | ~58h | ~19-20h |

Still feasible with continuous reservations. Plan Phase 8 timeline updated accordingly.

---

## Phase 0: Setup & Diagnostic Freeze (1 hour, no risk)

**Goal**: Lock IV.POS.5 results, organize cloud1 workspace, establish naming.

### 0.1 Freeze IV.POS.5 [Pro §14.1]
- [ ] Mark `a4/runs/iv_pos_5/CLOSURE.txt` as **FINAL — no further mutations to this campaign**
- [ ] Update `a4/docs/precloud/PRECLOUD_MASTER_PLAN.md` Status table: master plan PAUSED, cloud1 ACTIVE
- [ ] Add `a4/docs/cloud1/CLOUD1_STATUS.md` as the live status tracker (one row per phase below)

### 0.2 Rename strategies in code [Pro §9, §14.2]
- [ ] Add a `STRATEGY_DISPLAY_NAMES` dict that maps internal selector strings to Pro's names:
  - `uniform` → `arm_uniform_b128`
  - `zoned`   → `kind_uniform_zoned_step`
  - `bandit`  → `ucb_kindbucket_b16`
- [ ] DO NOT rename the internal selector strings (would break old DBs and analysis). Only display names.
- [ ] Add note to `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` top: "Strategies renamed per ProG_Report_2.md §14.2; internal names retained for DB compatibility."

### 0.3 Cloud1 folder structure
```
a4/docs/cloud1/
├── ProG_Report_2.md            (immutable input)
├── CLOUD1_IMPLEMENTATION_PLAN.md (this file)
├── CLOUD1_STATUS.md             (live tracker)
└── phases/
    ├── PHASE_1_SCHEMA.md
    ├── PHASE_2_SEMANTIC_ZONES.md
    ├── PHASE_3_GLOBAL_CTX.md
    ├── PHASE_4_REWARD.md
    ├── PHASE_5_BANDIT_TS.md
    ├── PHASE_6_LOGGING.md
    ├── PHASE_7_SMOKE_TESTS.md
    ├── PHASE_8_IV_POS_7.md
    └── PHASE_9_REPORT.md
```

### 0.4 Exit criteria for Phase 0
- All four bullets above checked.
- `CLOUD1_STATUS.md` created with Phase 0 = ✅ DONE.

---

## Phase 1: Schema & Data Model (2-3 hours, low risk)

**Goal**: Establish the data structures everything downstream depends on.

### 1.1 Define `SemanticZone` enum [Pro §7.A]
File: `a4/standalone/semantic_zones.py` (new)
```python
SEMANTIC_ZONES = [
    "step0", "last_step",
    "pre_ecall", "post_ecall",
    "pre_mret", "post_mret",
    "pre_halt", "post_halt",
    "core_arithmetic", "core_memory_load", "core_memory_store",
    "core_branch", "core_mul", "core_div",
    "core_sha", "core_poseidon", "core_other",
]
SINGLETON_ZONES = {"step0", "last_step"}  # forced 1-pull-minimum
BOUNDARY_ZONES  = {"step0", "last_step",
                   "pre_ecall", "post_ecall",
                   "pre_mret", "post_mret",
                   "pre_halt", "post_halt"}
```

### 1.2 Define `CompressedGlobalContext` schema [Pro §5]
File: `a4/standalone/compressed_global.py` (new)
```python
@dataclass(frozen=True)
class GlobalMemoryCtx:
    family: str           # "memory" (constant)
    address_region: str   # user|kernel|image|stack|heap|invalid|unknown
    address_bucket: int   # log2(page_size) bucket
    txn_role: str         # read|write|ifetch|register|prev_word|prev_cycle
    cycle_phase: str      # normal|ecall|mret|halt|boundary

@dataclass(frozen=True)
class GlobalLookupCtx:
    family: str           # "u8"|"u16"|"cycle"
    lookup_index_bucket: int
    producer_kind: str    # the mutation_kind that produced this lookup
    opcode_class: str     # alu|mem|mul|div|branch|ctrl|sha|other
```

### 1.3 Define `StructuralCell` tuple [Pro §6.3, §8.S_new]
File: `a4/standalone/structural_cells.py` (new)
```python
@dataclass(frozen=True)
class StructuralCell:
    kind: str                 # mutation kind name
    semantic_zone: str
    opcode_class: str         # alu|mem|mul|div|branch|ctrl|sha|other
    mode: str                 # user|machine
    txn_role: str             # read|write|ifetch|register|...
    sub_strategy: Optional[str] = None  # e.g. INSTR_WORD_MOD_SUR funct3
```

### 1.4 Extend `coverage_db.py` schema [Pro §12]
Add the following tables (idempotent CREATE IF NOT EXISTS):
- `bandit_decisions` (mutation_id, selected_arm, coldstart, score, runnerup_arm, runnerup_score, mode)
- `arm_state_snapshot` (campaign_id, mutation_idx, arm_id, pulls, discounted_pulls, mean_reward, posterior_alpha, posterior_beta, ts_extra_json)
- `reward_counterfactuals` (mutation_id, current_reward, no_qloc_reward, fnew_only_reward, discovery_binary_reward, compressed_global_reward)
- `mutation_substrategy` (mutation_id, opcode, rd, rs1, rs2, funct3, funct7, imm, byte_lane, bit_mask, value_class)
- `hook3_raw` (mutation_id, family, raw_json, compressed_ctx_json)
- `pilot_runs` (campaign_id, pilot_idx, raw_pilot_observation_json, calibrated_params_json)
- `compressed_global_coverage` (campaign_id, first_hit_mutation_id, family, ctx_json) [analog of existing `coverage` table but for compressed contexts]
- `local_coverage_v2` (campaign_id, first_hit_mutation_id, constraint_loc, major, minor) [extends current `coverage` with major/minor for L_new defined in §8]

### 1.5 Exit criteria for Phase 1
- All new files exist and are syntactically valid.
- `coverage_db.py` migration runs without error on a fresh DB and an existing IV.POS.5 DB.
- Unit test: round-trip insert/select for each new table on an empty DB.

---

## Phase 2: Semantic-Zone Step Sampler [Pro §7.A, §7.B]

**Goal**: Replace `(kind, contiguous step bucket)` arm structure with `(kind, semantic_zone)`.

### 2.1 Inspection-time zone classifier
File: `a4/standalone/zone_classifier.py` (new)

Input: `InspectionData` (has cycles, ECALLs, MRETs, halt).
Output: `Dict[int, str]` mapping each `user_cycle` to its `semantic_zone`.

Algorithm:
1. `step0` ← {0}
2. `last_step` ← {T-1}
3. For each ECALL cycle e: `pre_ecall.add(e-1)`, `post_ecall.add(e+1)` (clamped to [0, T-1])
4. Same for MRET, halt
5. For all remaining steps, classify by `cycles[step].major`:
   - 0/1/2 → `core_arithmetic` (ADD/SUB/AND/OR/XOR/SLT/SLL/SRL/SRA)
   - 3 → `core_mul`
   - 4 → `core_div`
   - 5 → `core_memory_load`
   - 6 → `core_memory_store`
   - 7 → `core_branch` (BEQ/BNE/BLT/BGE/JAL/JALR)
   - 8 → `core_sha`
   - 9 → `core_poseidon`
   - else → `core_other`
6. Conflict resolution: boundary zones take precedence over core zones.

Output: also `Dict[str, List[int]]` = zone → steps in that zone.

### 2.2 `SemanticArmUniverse`
File: `a4/standalone/semantic_arm_universe.py` (new)

Replaces `ArmUniverse`. Arms = `(kind, semantic_zone)` for which `data.get_valid_steps_for_kind(kind) ∩ zone_steps[zone]` is non-empty.

Methods:
- `available_arms` → List[(kind, zone)]
- `steps_in_arm(kind, zone)` → List[int]
- `singleton_arms()` → arms where `len(steps) == 1` (subset of `SINGLETON_ZONES`)
- `summary()` → print zone populations per kind

### 2.3 `SemanticZoneStepSelector` [Pro §7.B]
File: `a4/standalone/step_selector.py` (extend)

Class: `SemanticZoneStepSelector(StepSelector)`
- `select_arm_then_step()` → (kind, step):
  1. Pick `kind` uniformly from `MUTATION_KINDS`
  2. Pick `zone` from non-empty zones for that kind, weighted by `zone_weights` (configurable, default uniform-over-non-singletons + singleton floor handled separately)
  3. Pick `step` uniformly from `zone_steps[zone]`
- For singleton zones, this deterministically picks the singleton.

### 2.4 Exit criteria for Phase 2
- Zone classifier called on IV.POS.5 inspection data produces all 17 zones with sensible populations (step0=1, last_step=1, boundary zones small but non-zero, core_* covering bulk).
- `SemanticArmUniverse.summary()` printed and inspected for sanity (≥3 of 8 kinds compatible with `step0`, matching empirical data).
- Smoke test: 200 mutations with `SemanticZoneStepSelector`, verify step distribution shows ≥1 hit each on `step0` and `last_step`.

---

## Phase 3: Compressed Global Context [Pro §5, §6.4]

**Goal**: Replace raw global address coverage with semantic global contexts in the bandit reward signal.

### 3.1 Extractor implementation
File: `a4/standalone/compressed_global_extractor.py` (new)

Input: raw Hook 3 global failure entries (family, address, txn_idx, cycle, ...).
Output: `Set[GlobalMemoryCtx | GlobalLookupCtx]`.

Address region map (initial; refine after first run):
- `[0x00000000, 0x00400000)` → `image`
- `[0xC0000000, 0xFFFFFFFF]` → `kernel`
- `[0x70000000, 0x80000000)` → `stack`
- `[0x10000000, 0x70000000)` → `heap`
- `[0x80000000, 0xC0000000)` → `user`
- anything else → `invalid` if PC-derived, `unknown` otherwise

Address bucket: `floor(log2(addr))` (33 buckets, 0-32).

Cycle phase: from zone classifier (`normal | ecall | mret | halt | boundary`).

### 3.2 Coverage DB integration
- Insert into `compressed_global_coverage` on first-hit (analog of existing `coverage`).
- Keep raw `global_failures` table populated for diagnostics.

### 3.3 Exit criteria for Phase 3
- Re-run extractor on one IV.POS.5 DB; verify compression ratio (expect raw|global_failures| / |compressed_global_coverage| ≥ 50×).
- Verify all raw entries map to a non-null compressed context.

---

## Phase 4: Reward Redesign [Pro §6, §8]

**Goal**: Replace the multiplicative `Q_loc × Q_glob` gate with an additive marginal-discovery reward.

### 4.1 New reward function
File: `a4/standalone/reward_v2.py` (new)

```python
def sat(x: float, tau: float) -> float:
    return 1.0 - math.exp(-x / tau)

def compute_reward_v2(
    l_new: int,   # new local contexts (constraint_loc, major, minor)
    f_new: int,   # new local families (constraint file)
    g_new: int,   # new compressed global contexts
    s_new: int,   # new structural cells
    crash: bool,
    repeat: int,  # # already-seen local contexts hit again this mutation
) -> float:
    return (
        1.00 * sat(l_new, 1.0)
      + 0.30 * sat(f_new, 1.0)
      + 0.25 * sat(g_new, 3.0)
      + 0.15 * sat(s_new, 2.0)
      - 0.50 * (1.0 if crash else 0.0)
      - 0.05 * sat(repeat, 5.0)
    )

def compute_bandit_success(l_new: int, g_new: int, s_new: int) -> int:
    return 1 if (l_new + g_new + s_new) > 0 else 0
```

### 4.2 Update `coverage_state.py`
- Add `compute_reward_v2_components(...)` that returns the 6 components (l_new, f_new, g_new, s_new, crash, repeat) for both reward calculation AND counterfactual logging.
- Old `compute_reward()` retained for old strategies; new selectors use v2.

### 4.3 Counterfactual rewards [Pro §12]
For every mutation (regardless of which strategy is running), compute and store:
- `current_reward` (= v2)
- `no_qloc_reward` (v1 with Q_loc forced to 1.0)
- `fnew_only_reward` (a_Fn * F_new only)
- `discovery_binary_reward` (= bandit_success)
- `compressed_global_reward` (= 0.25 * sat(g_new, 3))

### 4.4 Exit criteria for Phase 4
- Unit tests for `sat()`, `compute_reward_v2()`, `compute_bandit_success()`.
- Replay test: run `compute_reward_v2` over the 30,000 zoned mutations from IV.POS.5; verify INSTR_TYPE_MOD's mean reward is now HIGHER than INSTR_WORD_MOD_SUR's (validates the Q_loc anti-discovery fix).

---

## Phase 5: Constrained Thompson Sampling Bandit [Pro §7.C, §7.D]

**Goal**: Replace `DiscountedUCBScheduler` with a constrained TS scheduler.

### 5.1 `ConstrainedTSScheduler`
File: `a4/standalone/bandit_ts.py` (new)

Configuration (defaults per D9, D10):
- `coverage_floor_fraction` = 0.55  (D9)
- `cold_start_pulls_per_arm` = 3    (D10)
- `prior_alpha`, `prior_beta` = 1.0, 1.0  (D4)
- `epoch_size` (E in Pro §7.C) = 100 mutations

Algorithm per mutation:
1. Cold-start phase: if any arm has `pulls < cold_start_pulls_per_arm`, pick one of those arms uniformly.
2. Otherwise within each epoch:
   a. Maintain a per-arm running pull count for this epoch.
   b. Compute `floor_target[arm] = coverage_floor_fraction / num_arms * E` (uniform kind allocation).
   c. If any arm's current epoch pulls are below its floor target, pick the most-under-floor arm.
   d. Otherwise: sample `theta_arm ~ Beta(alpha_arm, beta_arm)` for each arm, pick `argmax theta_arm`.
3. After mutation, update `alpha_arm += success`, `beta_arm += (1 - success)` where `success = compute_bandit_success(...)`.

Logging:
- Every selection: log to `bandit_decisions` (mutation_id, selected_arm, coldstart, sampled_theta, runnerup_arm, runnerup_theta, mode=cold|floor|adaptive).
- Every 100 mutations: snapshot all arm states to `arm_state_snapshot`.

### 5.2 Singleton zone forced pulls [Pro §7.A]
- For each singleton zone (e.g. `step0`), enforce `forced_singleton_pulls = max(cold_start_pulls_per_arm, 5)` (5 to guarantee enough INSTR_TYPE_MOD@step0 to catch the IV.POS.5 boundary constraints).
- These pulls count as "floor" pulls (don't decrement adaptive budget).

### 5.3 Pilot calibration removal [D2]
- If D2 = (a): `ConstrainedTSScheduler` does not run a pilot; uses fixed defaults.
- All v2 selectors use identical `CalibratedParams` (the current defaults from `_setup_coverage_tracking`).

### 5.4 Exit criteria for Phase 5
- Unit test: 1000 simulated rounds with synthetic reward (one arm has 50% success, others 5%), verify TS converges to favored arm but still pulls others ≥ floor.
- Smoke test: 500 mutations on real DB with `ConstrainedTSScheduler`, verify `bandit_decisions` table populated, `arm_state_snapshot` shows 5 snapshots, no exceptions.

---

## Phase 6: Extended Logging [Pro §12]

**Goal**: Add the rest of the diagnostic telemetry Pro requested (most already covered in Phase 1.4; this phase wires them into the fuzzer loop).

### 6.1 Wire logging into `fuzzer.py`
- After each mutation:
  - Compute and insert reward counterfactuals (Phase 4.3)
  - For INSTR_WORD_MOD_SUR: extract opcode/rd/rs1/rs2/funct3/funct7/imm from `config` and insert into `mutation_substrategy`
  - For all kinds where applicable: extract byte_lane, bit_mask, value_class
  - Insert raw Hook 3 family + compressed ctx into `hook3_raw`
- Pilot phase (if any): record raw observations and calibrated params (we plan to remove pilot per D2; this is only for backward compat with old strategies)

### 6.2 Add CLI flag `--telemetry-level`
- `none`: minimal logging (legacy)
- `standard`: existing logging (current default)
- `full`: all v2 tables populated (default for IV.POS.7)

### 6.3 Exit criteria for Phase 6
- Run 200 mutations of each variant locally with `--telemetry-level=full`
- Verify each new table has expected row count (~200 for per-mutation tables, ~2 for per-snapshot tables)
- Disk overhead ≤ 3× the legacy DB size for the same N

---

## Phase 7: Local Smoke Tests (1-2 hours)

**Goal**: Catch any issues before paying POS compute.

### 7.1 Variant smoke tests
For each of the 5 IV.POS.7 variants (defined in Phase 8.1), run N=200 mutations locally:
1. `zoned_current` (sanity)
2. `kind_UCB + zoned_step + current_reward`
3. `kind_UCB + zoned_step + no_Qloc_reward`
4. `kind_TS + zoned_step + discovery_reward`
5. `constrained_TS + semantic_zones + discovery_reward`

### 7.2 Verify each variant
- Completes without crash
- Produces a DB with all expected tables
- Schema migration works on old IV.POS.5 DBs (read-only compatibility)
- Telemetry-full mode produces non-empty rows in all new tables
- Disk size and wall-time are within 3× of zoned_current

### 7.3 Exit criteria for Phase 7
- All 5 variants pass.
- A summary report `phases/PHASE_7_SMOKE_REPORT.md` listing wall-clock, table-row counts, and any anomalies.

---

## Phase 8: IV.POS.7 Cloud Campaign [Pro §10]

**Goal**: Run the 5-variant ablation suite on POS.

### 8.1 Variant matrix [Pro §10]
| # | name | selector | step sampler | reward | success metric |
|---|------|----------|--------------|--------|----------------|
| 1 | `zoned_current`        | kind-uniform           | zoned 5/90/5         | v1 (current) | reference |
| 2 | `kindUCB_zoned_v1`     | UCB on kind            | zoned 5/90/5         | v1 (current) | tests step-prior fix in isolation |
| 3 | `kindUCB_zoned_v2_noQ` | UCB on kind            | zoned 5/90/5         | v2 (no Q_loc) | tests reward fix in isolation |
| 4 | `kindTS_zoned_v2`      | Thompson sampling on kind | zoned 5/90/5      | v2 (no Q_loc) | tests TS over UCB |
| 5 | `cTS_semantic_v2`      | Constrained TS over (kind, semantic_zone) | structural sampler | v2 (no Q_loc) | **main candidate** |

Notes:
- Variants 2-5 all share the new v2 reward components in logging, but only #3-#5 USE the v2 reward for selection.
- All variants use N=6000, identical 10 seeds (1234..1243), identical guest (sha2-host).
- No pilot calibration anywhere (D2).

### 8.2 POS dispatch plan [D11]
- 5 variants × 10 seeds = 50 runs.
- 3-parallel continuous reservation: ~20h wall-clock at ~70min/run.
- Use `auto_run_ab_v1_smart.sh` (proven from IV.POS.5) with `STRAT_LIST` extended to 5 variants.
- Calendar: 2 future reservations, rolling.

### 8.3 Collection and validation
- Reuse `collect_results_pos.py` (extend `STRAT_LIST` to 5).
- Validation: each DB has ≥5999 mutations, all new tables non-empty, no crash exceptions in stderr.

### 8.4 Exit criteria for Phase 8
- All 25 DBs collected and validated.
- `COLLECTION_REPORT_FINAL.json` created.
- `CLOSURE.txt` written.

---

## Phase 9: Analysis & Report for ChatGPT Pro Round 2 [Pro §10 metrics, §10 success criteria]

**Goal**: Compute metrics, apply success criteria, write report.

### 9.1 Primary metrics [Pro §10]
For each variant:
- `local_context_final` (mean ± σ across 5 seeds, max 46)
- `local_context_AUC` (cumulative coverage area under curve)
- `time_to_40`, `time_to_43`, `time_to_46` (mutations needed to reach N contexts)
- `per_seed_all_46_hit_rate` (fraction of 5 seeds reaching 46)
- `compressed_global_context_final` (using v2 compressed contexts)
- `crash_rate`
- `no_effect_rate`
- `allocation_entropy_by_kind`, `allocation_entropy_by_zone`

### 9.2 Success criteria [Pro §10]
A candidate "survives" if it satisfies AT LEAST ONE of:
1. Beats `zoned_current` on `local_context_AUC` (paired t-test p<0.05)
2. Matches `zoned_current` final coverage with lower variance (σ ratio < 0.7)
3. Reaches 43+ contexts materially earlier than `zoned_current` (time_to_43 / zoned's time_to_43 < 0.7)
4. Preserves local coverage while improving compressed-global coverage (Δglobal > 20%)
5. Discovers a context not in IV.POS.5's 46 (requires expanded universe — unlikely in this phase without new guests)

### 9.3 Output
- `a4/runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` (~50KB-100KB)
- `a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`
- Plots: AUC curves per variant, time-to-N stacked, kind/zone allocation heatmaps, reward counterfactual scatter

### 9.4 Exit criteria for Phase 9
- Report and notebook produced.
- All 25 DBs analyzed in notebook.
- Honest conclusion stated: either (a) at least one v2 variant beats zoned and we proceed to Pro Round 3 with recommendations for further refinement, or (b) no variant beats zoned and we report this honestly to Pro for a deeper diagnosis.

---

## What we explicitly DO NOT do in cloud1

- ❌ Run N=20k of the current bandit "to see if it eventually finds step 0" [Pro §10 explicitly warns against this]
- ❌ Hyperparameter grid search on `c_explore`, `gamma`, reward weights [Pro §10: "skip a large grid until structural tests are done"]
- ❌ Add new mutation kinds (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`) [Pro §11]
- ❌ Add new guests (BigInt, Poseidon, Keccak) [Pro §11; D3]
- ❌ Resume the master plan [user request]
- ❌ Change `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` substantively [D12]

---

## Time/effort estimate (assuming D1-D12 answered)

| phase | dev time | wall-clock | risk |
|---|---|---|---|
| 0 | 1h | 1h | none |
| 1 | 2-3h | 1d | low |
| 2 | 3-4h | 1d | medium (zone classifier correctness) |
| 3 | 2h | 1d | low |
| 4 | 2h | 1d | low |
| 5 | 4-6h | 2d | medium (TS correctness, floor logic) |
| 6 | 2h | 1d | low |
| 7 | 2h | 1d | low |
| 8 | 1h dispatch + ~58h compute (~20h wall-clock 3-parallel) | 3-4d | medium (POS scheduling) |
| 9 | 4h | 1-2d | low |
| **total** | ~25h dev + ~30h compute | **~10-14 days** | |

---

## Open questions and unknowns (NOT decisions, but flagged)

1. **Zone classifier accuracy at boundaries**: Pre/post-ECALL boundary cycle detection relies on the inspection data correctly tagging ECALL/MRET cycles. Need to verify this is exposed by `InspectionData`.
2. **Address region map**: my initial mapping in Phase 3.1 is best-guess. We may need to refine after running on IV.POS.5 data and seeing the actual address distribution.
3. **What if `cTS_semantic_v2` is identical to `zoned_current` in coverage**: then we have a clean negative result. Pro's §13 says this is publishable as a "structural priors beat adaptive selection" result. We should NOT panic and over-tune; that's exactly what Pro warned against.
4. **What if `cTS_semantic_v2` is WORSE than `zoned_current`**: then we have a deeper representational problem. Recommend pausing for Pro Round 3 before further iteration.

---

## Once IV.POS.7 is done

1. Generate report + notebook (Phase 9)
2. Send to ChatGPT Pro for Round 2 review
3. Wait for Pro's response
4. Decision point: continue cloud1 with refinements OR resume master plan OR pivot further
