# Phase 8 — IV.POS.7 Master Plan

**Status:** DRAFT (Opus, 2026-06-13 PM). Locks at Phase 7d closure.
**Owner:** Opus (plan + analysis), Composer (POS dispatch + collection)
**Source-of-truth references:**
- `a4/docs/cloud1/ProG_Report_2.md` — Pro Round 1 recommendations (what this campaign exists to answer)
- `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md` §Phase 8 — locked decisions
- `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` — D1-D55 + G1-G8 (open questions)
- `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` — race phenomenon Pro will see
- `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` — the prior Pro R1 markdown (template)
- `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb` — the prior Pro R1 notebook (template)
- `a4/docs/precloud/POS_PLAYBOOK.md` — POS operational truth
- `a4/pos/auto_run_ab_v1_smart.sh` — IV.POS.5's runner (template)
- `a4/pos/dispatch_audit.sh` — Phase 7d canonical dispatch wrapper (template)

---

## 0. TL;DR

Phase 8 = **the actual scientific experiment cloud1 was built for.** We run Pro's 5-variant ablation suite (`ProG_Report_2.md §10`) at N=6000 × 10 seeds = **50 POS runs, 300,000 mutations total**, and produce a packaged deliverable for Pro Round 2 containing:

1. **`MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`** — the big markdown (~80-120 KB) Pro reads first. Same structure/depth as the R1 diagnostic, retargeted at "does v2 beat v1?".
2. **`MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`** — reproducible analysis notebook with all plots/tables the markdown references, all cells executable end-to-end against the 50 DBs.
3. **`CLOUD1_DECISIONS_FOR_PRO_R2.md`** — already populated with D40-D55 + G1-G8 (race, disposition framework); ships as-is.
4. **`RACE_FINDING_AND_OPEN_QUESTIONS.md`** — Pro-facing race deep-dive; ships as-is.

**Wall-clock critical path: ~4 days elapsed** (1 day Phase 7d closure + 1.5 days POS compute on the batched-parallel ~35h plan + 1 day analysis + 1 day report writing).

**Three independent work tracks** that can proceed in parallel during the Phase 7d Inc 5 window:
- **Track A — Dispatch infrastructure** (Composer prep): build bundle, write manifests, harden orchestrator, validate on N=20 smoke. Spec in §3.
- **Track B — Notebook scaffold** (Opus, this plan): cell-by-cell spec; each cell ready to fill once DBs land. Spec in §5.
- **Track C — Markdown scaffold** (Opus, this plan): section-by-section spec mapping IV.POS.5 doc → IV.POS.7 doc. Spec in §6.

After POS completes: analysis becomes a **fill-in-the-blanks** exercise, not a design exercise. The data-to-deliverable time drops from "a week of figuring out what to show" (IV.POS.5 pattern) to "two days of running pre-specified cells and writing pre-specified prose."

---

## 1. What Pro asked for and what we must deliver

### 1.1 Pro's R1 prescription (`ProG_Report_2.md §10`)

> "Run IV.POS.7 as a 6000-mutation ablation suite. Use five paired seeds first. If feasible, ten is better, but five is enough to triage."

**The 5 variants** (Pro's §10 verbatim, mapped to our naming):

| # | Pro's name | Selector | Step sampler | Reward | What it isolates |
|---|---|---|---|---|---|
| **V1** | `zoned_current` | kind-uniform | zoned 5/90/5 | v1 | Reference (must stay in suite) |
| **V2** | `kindUCB_zoned_v1` | UCB on kind | zoned 5/90/5 | v1 | "Does copying zoned's step prior fix the mechanical gap?" |
| **V3** | `kindUCB_zoned_v2_noQ` | UCB on kind | zoned 5/90/5 | v2 (no Q_loc) | "Does the reward fix help in isolation?" |
| **V4** | `kindTS_zoned_v2` | Thompson sampling on kind | zoned 5/90/5 | v2 | "Does posterior sampling beat UCB on high-variance discovery?" |
| **V5** | `cTS_semantic_v2` | Constrained TS over (kind × semantic_zone) | structural sampler | v2 | **Main candidate.** Enforces kind + boundary floors; TS for remaining budget. |

### 1.2 Pro's success criteria (`ProG_Report_2.md §10`)

A variant "survives" if it satisfies **at least one** of:

1. Beats `zoned_current` on `local_context_AUC` (paired t-test p<0.05)
2. Matches `zoned_current` final coverage with lower variance (σ ratio < 0.7)
3. Reaches 43+ contexts materially earlier than `zoned_current` (time_to_43 / zoned's time_to_43 < 0.7)
4. Preserves local coverage while improving compressed-global coverage (Δglobal > 20%)
5. Discovers a context not in IV.POS.5's 46 (would require expanded universe — unlikely on this guest)

### 1.3 Pro's primary metrics (`ProG_Report_2.md §10`)

Per variant, averaged across 10 seeds:

- `local_context_final` (mean ± σ, max 46)
- `local_context_AUC` (∫ coverage(t) dt over t∈[0, 6000])
- `time_to_40`, `time_to_43`, `time_to_46`
- `per_seed_all_46_hit_rate` (fraction of 10 seeds reaching 46)
- `compressed_global_context_final` (using D8 v2 contexts)
- `crash_rate`
- `no_effect_rate`
- `allocation_entropy_by_kind` (Shannon entropy over 8 kinds)
- `allocation_entropy_by_zone` (Shannon entropy over 17 zones, V5 only)

### 1.4 Pro's required telemetry (`ProG_Report_2.md §12`)

All 50 DBs must have these tables populated (`--telemetry-level=full`):

- `bandit_decisions` — per-mutation arm/score/runner-up/mode
- `arm_state_snapshot` — every 100 mutations
- `reward_counterfactuals` — 5 reward functions computed per mutation
- `mutation_substrategy` — opcode/rd/rs1/.../byte_lane/bit_mask/value_class
- `hook3_raw` — raw + compressed contexts per mutation
- `pilot_runs` — empty for v2 (D2 removed pilot) but schema present
- `compressed_global_coverage` — per-mutation first-hit log
- `local_coverage_v2` — extended local coverage with major/minor

### 1.5 New things Pro will see in R2 that didn't exist in R1

| Item | What it is | Pro-facing location |
|---|---|---|
| **G7 — race phenomenon** | ~0.7% `delta_T` noise floor under default parallelism; documented end-to-end | `RACE_FINDING_AND_OPEN_QUESTIONS.md` (separate doc) + decisions G7 |
| **G8 — B1 disposition framework** | 6 documented exclusion categories (A/B/B2/C/D/D2) for B1 strict-verifier failures; ~4000 mutations / 0 unclassified | Decisions G8 (just added) + race doc §12.1a |
| **D40-D55** | 16 architectural decisions made during Phase 7d audit | Decisions D40-D55 |
| **Phase 7d audit attestation** | 17 audits, all green; per-arm evidence pack (E5) | Phase 7d final report (references in §6.10 of MAB markdown) |

These don't change what Phase 8 measures, but they DO change what gets shipped with the report. Pro will be asked to validate the disposition framework and the race characterization alongside the variant comparison.

---

## 2. Campaign specification (locked)

| Parameter | Value | Source |
|---|---|---|
| Variants | 5 (V1-V5 above) | Pro §10 + D5 |
| Seeds | 10 (1234..1243) | D1 |
| N (per run) | 6000 | Pro §10 |
| Guest | `sha2-host --in1 5 --in4 10` | D3 |
| Host binary | `workspace/output/target/release/risc0-host` (current build with all cloud1 code) | Phase 7d baseline |
| Telemetry | `full` (all v2 tables) | D35 |
| Pilot calibration | NONE | D2 |
| Parallelism on POS | default (Pro is being asked about G7) | user override 2026-06-13 |
| Total runs | 5 × 10 = **50** | D1 |
| Total mutations | 50 × 6000 = **300,000** | D1 |

**Decision rationale** (recap):
- 10 seeds (vs 5) per D1: doubles wall time but gives σ confidence for variance comparisons in success criterion 2.
- N=6000 per Pro §10: anchored to IV.POS.5's universe so the AUC comparison is meaningful. NOT bumping to N=10000 even though feasible — Pro explicitly warned against using brute-force N to "rescue" a misaligned bandit.
- Default parallelism per user override: trades ~0.7% noise floor for ~3× wall-time savings; presented to Pro alongside results.

---

## 3. Dispatch plan — batched-parallel, 8 nodes, ~35h wall (LOCKED 2026-06-13 PM)

> **Why this section was rewritten (2026-06-13 PM)**: the previous 5-parallel "1 dispatch = 1 seed across 5 variants" design produced a 52h wall. After verifying `polynize` is operational and that christer's reservation 1750 frees 4 Tier-A nodes at 03:00 UTC, we have access to **8 EPYC nodes** total. The 5-parallel model leaves 3 nodes idle. The new batched-parallel model fully saturates all 8 EPYC nodes and lands at ~35h — a 17h savings (~33% faster). The cost: per-variant pinning across all 10 seeds is no longer feasible (variants split 7+3 between Tier-S and Tier-A). We accept this because race noise is empirically ~0.7% (Inc 4 B11) and variant effects are ~10-15%; pinning was a "belt and suspenders" choice, not foundational. See §3.0 for the rationale, §3.11 for the Pro-facing disclosure.

### 3.0 Why dropping strict per-variant pinning does not break the V1-V5 comparison

The original 5-parallel design held one node per variant for all 10 seeds, so each variant's 10 seeds ran on identical hardware. The new design pins each variant to one Tier-S node for 7 seeds AND one Tier-A node for 3 seeds (V2-V5), and V1 spreads 10 seeds across the 4 Tier-A nodes. Three reasons this still answers Pro's R1 question:

1. **Race noise floor is ~0.7%; variant effects we're looking for are ~10-15%.** Per Inc 4 B11 raw pass-rate analysis, race-induced coverage noise on a single run is at most ~0.3 contexts out of 46. Pro's success criteria look for variant differences of 2-5+ contexts (V5 vs V1 on local_context_AUC) — that's a signal-to-noise ratio of 10-30×.
2. **Mean over 10 seeds reduces noise by √10 ≈ 3.16.** If V2's 7 Tier-S seeds run on flare and its 3 Tier-A seeds run on goracle, the per-node race noise (already small) averages out in the seed-level mean. The standard error of V2's mean coverage is roughly 0.1 contexts — far below the variant-level differences Pro is testing.
3. **EPYC-9354 and EPYC-7543 are race-equivalent in our setup.** Inc 4 B11 ran 5 variants across 5 nodes (including both EPYC tiers) and saw raw B1 pass rates of 468-499/500 with no systematic tier bias visible in the disposition framework. Race manifestation is roughly the same on both EPYC tiers; the only hardware difference is per-mutation wall time (~10% slower on Tier-A), which doesn't affect coverage outcomes — only how long the run takes.

For the relative ranking task ("which of V1-V5 is best on Pro's success criteria"), the design is sound. The cost is that variant-level σ might be slightly inflated by mixing tiers — but σ is reported as-measured, so Pro sees the true uncertainty in our numbers and judges accordingly.

### 3.1 Parallelism model: two independent tier runners on 8 EPYC nodes

8 EPYC nodes total: 4 Tier-S (flare, octorand, opulous, polynize) + 4 Tier-A (algofi, gard, goracle, zone). They become available at different times (Tier-A held by christer until 2026-06-14 03:00 UTC), so we treat them as **two independent pools with their own runners**:

| Tier | Pool | Nodes | Per-job wall | Becomes available |
|---|---|---|---|---|
| S | 4× EPYC 9354 (32c/64t) | flare, octorand, opulous, polynize | ~5.0h on N=6000 | 1751 active now, then chain reservations |
| A | 4× EPYC 7543 (32c/64t) | algofi, gard, goracle, zone | ~5.3h on N=6000 (~10% slower) | 1752 begins 03:00 UTC tomorrow |

**Why two runners not one greedy queue scheduler**:
- They use disjoint node pools and disjoint reservations — no coordination required.
- Each runner is the exact same code (`auto_run_iv_pos_7.sh --tier=s|a`) reading per-tier batch manifests.
- A queue scheduler would shave maybe 30 min off but add multi-day development cost.
- The runners can be launched at different times (Tier-S now, Tier-A at 03:00 UTC) without any inter-process coordination.

### 3.2 Job assignment (LOCKED)

50 total jobs = 5 variants × 10 seeds. Split 28+22 between tiers so both runners finish at ~35h:

**Tier-S runner — 7 batches × 4 jobs = 28 jobs**

Each batch is one seed across V2-V5; nodes passed in order `flare, octorand, opulous, polynize`:

| Batch | Seed | flare | octorand | opulous | polynize |
|---|---:|---|---|---|---|
| `ts_b1` | 1234 | V2 | V3 | V4 | V5 |
| `ts_b2` | 1235 | V2 | V3 | V4 | V5 |
| `ts_b3` | 1236 | V2 | V3 | V4 | V5 |
| `ts_b4` | 1237 | V2 | V3 | V4 | V5 |
| `ts_b5` | 1238 | V2 | V3 | V4 | V5 |
| `ts_b6` | 1239 | V2 | V3 | V4 | V5 |
| `ts_b7` | 1240 | V2 | V3 | V4 | V5 |

Per-variant Tier-S pinning is **perfect**: V2→flare always, V3→octorand always, V4→opulous always, V5→polynize always.

**Tier-A runner — 6 batches summing to 22 jobs**

Nodes passed in order `algofi, gard, goracle, zone`:

| Batch | algofi | gard | goracle | zone |
|---|---|---|---|---|
| `ta_b1` | V1 s=1234 | V1 s=1235 | V1 s=1236 | V1 s=1237 |
| `ta_b2` | V1 s=1238 | V1 s=1239 | V1 s=1240 | V1 s=1241 |
| `ta_b3` | V1 s=1242 | V1 s=1243 | V2 s=1241 | V3 s=1241 |
| `ta_b4` | V4 s=1241 | V5 s=1241 | V2 s=1242 | V3 s=1242 |
| `ta_b5` | V4 s=1242 | V5 s=1242 | V2 s=1243 | V3 s=1243 |
| `ta_b6` | V4 s=1243 | V5 s=1243 | — | — |

Per-variant Tier-A pinning when on Tier-A: V2→goracle, V3→zone, V4→algofi, V5→gard. V1 spreads across all 4 Tier-A nodes (algofi×3, gard×3, goracle×2, zone×2).

**Per-variant node distribution after the campaign** (also written to `_dispatch_plan.json`):

| Variant | Tier-S pinning (7 seeds) | Tier-A pinning (3 seeds) | V1 only (10 seeds) |
|---|---|---|---|
| V1 (`zoned`) | — | — | algofi×3, gard×3, goracle×2, zone×2 |
| V2 (`kindUCB_zoned_v1`) | flare×7 (seeds 1234–1240) | goracle×3 (seeds 1241–1243) | — |
| V3 (`kindUCB_zoned_v2_noQ`) | octorand×7 (1234–1240) | zone×3 (1241–1243) | — |
| V4 (`kindTS_zoned_v2`) | opulous×7 (1234–1240) | algofi×3 (1241–1243) | — |
| V5 (`cTS_semantic_v2`) | polynize×7 (1234–1240) | gard×3 (1241–1243) | — |

All manifests generated by `a4/pos/generate_iv_pos_7_manifests.py` (single source of truth); rerun any time the plan changes.

### 3.3 Wall-time budget

| Runner | Batches | Per-batch wall | Subtotal | Start delay | Total wall |
|---|---:|---:|---:|---:|---:|
| Tier-S | 7 × 4 jobs | 5.0h (EPYC 9354) | 35.0h | 0h (1751 covers Tier-S now*) | **~35h** |
| Tier-A | 6 (5 full + 1 of 2) | 5.3h (EPYC 7543) | 31.8h | 3.5h (christer's 1750 ends 03:00 UTC) | **~35.3h** |

\*Caveat: 1751 expires at 2026-06-14 01:55 UTC (~4h17m remaining as of 21:38 UTC). That's NOT enough for a single 5h batch. So in practice Tier-S also waits for 1752 (or an extension/replacement of 1751) covering its 4 nodes for ≥5h. If 1751 is extended OR a follow-on entry is created that starts immediately at 01:55 UTC, Tier-S can start sometime between now and 01:55 UTC; the auto-runner's reservation-aware wait handles either case.

**Effective wall = max(35.0, 35.3) ≈ 35 hours = ~1.5 calendar days.**

Add:
- Bundle build + N=20 smoke validation: ~1h (smoke can run on 1751 right now)
- Collection + per-DB validation post-campaign: ~1-2h

**Total elapsed: ~38 hours from when both reservations are active, ≈ 1.6 calendar days.**

### 3.3a Why this is the optimal wall given the infrastructure

Total compute = 50 jobs × ~5h ≈ 250 node-hours. Available capacity once both tiers are reserved is 8 nodes. Lower-bounding by capacity: 250 / 8 = 31.25h. The 35h wall is 12% above this theoretical floor — slack is from:
1. Batch granularity: a 22-job Tier-A runner needs 6 batches × 5.3h = 31.8h even though 22/4 = 5.5; the partial batch (2 jobs) still pays the full 5.3h wall.
2. Tier-A is ~10% slower than Tier-S per N=6000 run.
3. 3.5h Tier-A start delay (christer's reservation).

A full queue scheduler (one job per node, no batch boundaries) would land at ~33h instead of 35h — a 2h gain for several days of dev cost. Rejected on cost/benefit.

### 3.4 Bundle + binary

**Bundle**: `a4_iv_pos_7_<git_sha>.tar.gz` containing:
- `a4/` (whole codebase tree at Phase 7d closure commit)
- `workspace/output/target/release/risc0-host` (Inc 3 baseline binary SHA `6873e588…`, frozen since Inc 3)
- Manifests + dispatch scripts referenced below
- Git revision marker in `BUNDLE_INFO.txt`

**SHA verification**: the host binary in the bundle MUST match the Inc 3/4 audit baseline. The dispatch preflight (§3.7) checks this.

Build command:

```bash
cd /root/arguzz
git rev-parse --short HEAD > /tmp/sha.txt
tar --exclude='*.db' --exclude='__pycache__' --exclude='.git' \
    -czf ~/a4_iv_pos_7_$(cat /tmp/sha.txt).tar.gz \
    a4/ workspace/output/target/release/risc0-host
ls -lh ~/a4_iv_pos_7_*.tar.gz
ln -sf ~/a4_iv_pos_7_$(cat /tmp/sha.txt).tar.gz ~/a4_campaign_iv_pos_7.tar.gz
# Then rsync to coinbase
```

### 3.5 Orchestrator: `auto_run_iv_pos_7.sh` (parameterised by --tier)

One script handles both tiers via `--tier=s` / `--tier=a`. Two tmux sessions, two invocations:

```bash
# Tier-S runner (start when Tier-S reservation is live for >=5.5h):
tmux new -s ivpos7_ts
cd ~/arguzz && source /srv/testbed/pos/cli/venv3/bin/activate
bash a4/pos/auto_run_iv_pos_7.sh --tier=s 2>&1 | tee /tmp/iv_pos_7_tier_s/AUTORUN.log

# Tier-A runner (start at/after 03:00 UTC when 1752 begins):
tmux new -s ivpos7_ta
cd ~/arguzz && source /srv/testbed/pos/cli/venv3/bin/activate
bash a4/pos/auto_run_iv_pos_7.sh --tier=a 2>&1 | tee /tmp/iv_pos_7_tier_a/AUTORUN.log

# Smoke (N=20, all 5 strategies on 5 nodes; ~3 min wall):
bash a4/pos/auto_run_iv_pos_7.sh --smoke 2>&1 | tee /tmp/iv_pos_7_smoke/AUTORUN.log
```

**Key features (inherited from `auto_run_ab_v1_smart.sh` + Inc 4 patches)**:
- Reservation-aware wait (`MIN_RES_HR=5.5`): never launches a batch if reservation doesn't cover ≥5.5h.
- Per-batch dispatcher subprocess (`dispatch_pos.py --await`), with rc=255 retry from Inc 4.
- Post-batch DB-presence verification on the coinbase results mirror.
- Auto-substitute broken nodes from `BACKUP_TIER_S` / `BACKUP_TIER_A` lists (empty by default; user opts in).
- Sequential within a tier; the script does NOT attempt cross-tier coordination.
- Resume support: `--start-at=ts_b3` skips already-completed batches.

### 3.6 Manifest template (one example)

```json
{
  "_doc": "IV.POS.7 Tier-S batch 1/7. seed=1234, 4 jobs (V2..V5). Wall ~5h on EPYC 9354. Node order (matches orchestrator --nodes): flare=kindUCB_zoned_v1, octorand=kindUCB_zoned_v2_noQ, opulous=kindTS_zoned_v2, polynize=cTS_semantic_v2. Reference: PHASE_8_PLAN.md §3.2 (batched-parallel).",
  "name": "pos_iv_pos_7_ts_b1",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "jobs": [
    {"strategy": "kindUCB_zoned_v1",     "seed": 1234, "n": 6000, "b_count": 16, "telemetry_level": "full", "node_label": "flare"},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 1234, "n": 6000, "b_count": 16, "telemetry_level": "full", "node_label": "octorand"},
    {"strategy": "kindTS_zoned_v2",      "seed": 1234, "n": 6000, "b_count": 16, "telemetry_level": "full", "node_label": "opulous"},
    {"strategy": "cTS_semantic_v2",      "seed": 1234, "n": 6000, "b_count": 16, "telemetry_level": "full", "node_label": "polynize"}
  ]
}
```

All 13 batch manifests + smoke + `_dispatch_plan.json` regenerated by `python3 a4/pos/generate_iv_pos_7_manifests.py [--purge-old]`. The `_dispatch_plan.json` is the source of truth for what runs where; preflight verifies the manifests match it.

### 3.4 Bundle + binary

**Bundle**: `a4_iv_pos_7_<git_sha>.tar.gz` containing:
- `a4/` (the whole codebase tree at Phase 7d closure commit)
- `workspace/output/target/release/risc0-host` (Inc 3 baseline binary SHA `6873e588…`, frozen since Inc 3)
- Manifests + dispatch scripts referenced below
- Git revision marker in `BUNDLE_INFO.txt`

**SHA verification**: the host binary in the bundle MUST match the Inc 3/4 audit baseline. The dispatch preflight (§3.7) checks this.

Build command:

```bash
# On WSL, at Phase 7d closure commit:
cd /root/arguzz
git rev-parse --short HEAD > /tmp/sha.txt
tar --exclude='*.db' --exclude='__pycache__' --exclude='.git' \
    -czf ~/a4_iv_pos_7_$(cat /tmp/sha.txt).tar.gz \
    a4/ workspace/output/target/release/risc0-host
ls -lh ~/a4_iv_pos_7_*.tar.gz
# Then rsync to coinbase
```

### 3.5 Orchestrator: extend `auto_run_ab_v1_smart.sh`

The existing smart runner from IV.POS.5 is the right starting point — it has the reservation-aware wait logic that worked in IV.POS.5 and the Phase 7d patches (rc=255 retry, error containment) folded in. Extend to handle 10 dispatches × 5 jobs:

**New file**: `a4/pos/auto_run_iv_pos_7.sh` (don't modify the IV.POS.5 runner; preserve as reference).

**Key differences from `auto_run_ab_v1_smart.sh`**:

| Aspect | IV.POS.5 runner | IV.POS.7 runner |
|---|---|---|
| Dispatches | d1..d5 (5) | d1..d10 (10) |
| Nodes | flare, octorand, opulous (3) | flare, octorand, opulous, algofi, meld (5) (configurable; substitute backup if a node bricks) |
| MIN_RES_HR | 5.5 (for ~5h dispatch) | **2.0** (90-min dispatch fits in 2h slot; smaller reservations are easier to chain) |
| Manifests | `manifests/ab_v1/*.json` | `manifests/iv_pos_7/*.json` |
| Strategies in manifest | `uniform`, `zoned`, `bandit-16` | `zoned`, `kindUCB_zoned_v1`, `kindUCB_zoned_v2_noQ`, `kindTS_zoned_v2`, `cTS_semantic_v2` |
| Telemetry flag | not set (legacy) | `"telemetry_level": "full"` per manifest |
| Per-node attribution | one job per node | one job per node (cleaner since 5 nodes = 5 variants) |
| Dispatch await timeout retry | (none) | inherits Phase 7d patches: 3× retry on rc=255, node-side result-file fallback |
| Failure containment | `set -uo pipefail` (no -e) | `set -uo pipefail` + post-dispatch audit |
| Auto-substitute on node brick | (manual) | tries one substitute from `BACKUP_NODES` list; if substitute also bricks, halts that dispatch and continues with remaining 4-of-5 (will get a re-dispatch later) |

### 3.6 Manifest template

```json
{
  "_doc": "IV.POS.7 dispatch d1/10 (5-parallel, by-seed). 5 strategies x 1 seed = 5 jobs. Per-dispatch wall ~90min. flare=V1, octorand=V2, opulous=V3, algofi=V4, meld=V5.",
  "name": "pos_iv_pos_7_d1",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "telemetry_level": "full",
  "jobs": [
    {"strategy": "zoned",                  "seed": 1234, "n": 6000, "node_hint": "flare"},
    {"strategy": "kindUCB_zoned_v1",       "seed": 1234, "n": 6000, "node_hint": "octorand"},
    {"strategy": "kindUCB_zoned_v2_noQ",   "seed": 1234, "n": 6000, "node_hint": "opulous"},
    {"strategy": "kindTS_zoned_v2",        "seed": 1234, "n": 6000, "node_hint": "algofi"},
    {"strategy": "cTS_semantic_v2",        "seed": 1234, "n": 6000, "node_hint": "meld"}
  ]
}
```

**Note on `node_hint`**: dispatch_pos.py round-robins jobs to nodes in the order given on `--nodes`. We pass nodes in the same order as `jobs` in the manifest so V1 always lands on flare, V2 on octorand, etc. The `node_hint` field is documentation only (consumed by the per-dispatch summary writer, not by dispatch_pos.py).

Generation script for all 10 manifests: simple Python loop over seeds 1234-1243, outputs `pos_iv_pos_7_d{1..10}.json`. Trivial.

### 3.7 Pre-flight (mandatory before launch)

Write `a4/pos/iv_pos_7_preflight.py` (~150 LOC, mirrors `inc5_preflight.py` pattern):

| Check | Failure means |
|---|---|
| Host binary SHA matches Inc 3 baseline | Wrong binary — STOP |
| All 10 manifests parse + sum to 50 jobs | Manifest bug — STOP |
| `pos calendar list` shows ≥1 active reservation covering all 5 nodes | Pre-reserve before launching |
| All 5 nodes return `pos nodes show` cleanly | One is broken — substitute from BACKUP_NODES |
| Bundle SHA matches recorded SHA | Bundle corrupted — rebuild |
| Smoke run (N=20, 1 dispatch, all 5 strategies) completed in last 24h | Run it: ~5 min wall |
| Coinbase disk space ≥ 50 GB free | Free space first |
| Patched `dispatch_pos.py` from Inc 4 is in the bundle | Use the Phase 7d-hardened version |

Print `IV_POS_7 PREFLIGHT: PASS` or `FAIL — N issues`.

### 3.8 Calendar plan (batched-parallel model)

**Calendar state as of 2026-06-13 21:38 UTC** (verified via SSH):
- **1751** (ivgreiff): flare, meld, octorand, opulous, polynize | 19:55 → 01:55 UTC next day | ACTIVE NOW (~4h17m left)
- **1750** (christer): algofi, gard, goracle, zone | 22:00 → 03:00 UTC next day | blocking us from Tier-A
- **1752** (ivgreiff): algofi, flare, gard, goracle, octorand, opulous, polynize, zone | 03:00 → 09:00 UTC next day (~6h block covering ALL 8 EPYC nodes) ← **excellent starting point**

**What we need**:
- Tier-S nodes (flare, octorand, opulous, polynize) reserved continuously from now (or whenever the Tier-S runner can launch a batch) for ~35 hours.
- Tier-A nodes (algofi, gard, goracle, zone) reserved continuously from 03:00 UTC for ~33 hours.

**Recommended booking plan** (user action; ~5 minutes in the web calendar UI):

1. **Tier-A coverage is already in place for the first 6 hours via 1752** — no action needed for the first batch of each Tier-A node.

2. **Tier-S coverage is the gap to fill**:
   - Option A (clean): **Replace 1751** with a new entry covering only flare/octorand/opulous/polynize, starting now (or as early as the calendar allows) and running for the next ~36 hours.
   - Option B (no edit needed): leave 1751 alone (we won't use it for batches — only the smoke), then start Tier-S runner at 03:00 UTC when 1752 begins (it covers Tier-S nodes too). This costs 3.5h of Tier-S wall time (final wall becomes ~38h instead of ~35h) but requires zero calendar changes.

3. **Follow-on entries to chain past 09:00 UTC**:
   - After 1752 expires at 09:00 UTC, both runners need follow-on coverage. Pre-book in the largest blocks the testbed allows (typically 6-12h per entry per §12.28 of POS_PLAYBOOK).
   - Need ~5 follow-on entries each covering the 4 Tier-S OR 4 Tier-A nodes for the remaining ~26h of campaign wall.
   - The 2-cap on future entries means you can have at most 2 queued at any time; create new ones as old ones complete. The orchestrator's reservation-aware wait handles gaps automatically (sleeps until next qualifying entry becomes active).

**My recommendation**: Option B above (no edit to 1751; rely on 1752 to launch both tiers at 03:00 UTC simultaneously, then chain follow-ons). Lose 3.5h of wall but avoid touching the calendar UI for the next 5 hours. Net wall: ~38h vs ~35h — the user's choice.

**Use of 1751 (now active)**: run the N=20 smoke (~3 min) immediately to validate the pipeline end-to-end before launching the 35h campaign. The smoke needs only ~5 min of any 5-node reservation.

### 3.9 Collection

After all 13 batches complete (across both tier runners), on coinbase:

```bash
# Pull from POS testbed mirror (single directory per batch manifest)
mkdir -p ~/iv_pos_7_results
rsync -av /srv/testbed/results/$USER/a4/pos_iv_pos_7_*/ ~/iv_pos_7_results/

# Then rsync to WSL
rsync -av coinbase:~/iv_pos_7_results/ /root/arguzz/a4/runs/iv_pos_7/raw/
```

**Validation** (extend `collect_results_pos.py`):

Per DB (50 expected):
- `mutations` row count == 6000 (allow 5999 for off-by-one edge cases per IV.POS.5 pattern; reject anything below 5999)
- All 8 v2 tables non-empty (`bandit_decisions`, `arm_state_snapshot`, `reward_counterfactuals`, `mutation_substrategy`, `hook3_raw`, `compressed_global_coverage`, `local_coverage_v2`, `pilot_runs`-may-be-empty)
- `campaign_params.selector_strategy` matches the manifest's variant
- `campaign_params.seed` matches the manifest seed
- DB size between 50-150 MB (sanity bounds; per IV.POS.5 extrapolation)
- No stderr crash entries (check `stderr_logs` if present)

Per batch:
- All expected DBs present (4 for ts_b*, 4 for ta_b1..b5, 2 for ta_b6)
- Each batch's `dispatch_pos.py` returned rc=0 OR rc=255 with all DBs present (Inc 4 patch)

**Cross-check**: total = 50 DBs (28 Tier-S + 22 Tier-A). Per-variant counts (V1=10, V2=10, V3=10, V4=10, V5=10).

**Output**: `COLLECTION_REPORT_FINAL.json` with per-DB status, aggregate `50/50 PASSED` or list of issues.

### 3.10 Failure modes and recovery

| Failure | What to do |
|---|---|
| One node bricks during a batch | Substitute from `BACKUP_TIER_S`/`BACKUP_TIER_A`, re-dispatch just the affected (variant, seed) pair; flag in `RUN_LOG.md` |
| Batch rc=255 (POS coordinator timeout) | Patched orchestrator retries 3× + checks node-side result file (Inc 4 fix); if all retries fail AND no result file, halt that batch, ping for adjudication |
| One run produces <5999 mutations | Re-run just that (variant, seed) on the same node; flag in COLLECTION_REPORT |
| Race surfaces on a paired-seed B7 check (post-collection) | Document the affected (variant, seed) pair, keep the run in analysis (per Inc 4 finding the race affects bandit path but not constraint outcomes), flag in MAB markdown §race-effect |
| Bundle hash mismatch on a node | Re-rsync bundle, re-dispatch the batch (could indicate transient disk issue) |
| Calendar slot lost mid-batch | Auto-runner waits for next slot; documented anti-pattern §12.45 |
| Tier-A reservation booking blocked (2-cap full) | Wait for an existing entry to expire; orchestrator polls every `POLL_SEC=300` and resumes once a qualifying entry is active |

### 3.11 Pro-facing disclosure (what we tell ChatGPT Pro about this design)

Pro will receive (in `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` §5 — experimental setup) a 1-paragraph disclosure following the §3.0 reasoning:

> **POS hardware mix and pinning policy.** The 50 runs were distributed across 8 EPYC nodes via a batched-parallel scheduler that ran two independent tier runners simultaneously (Tier-S: 4× EPYC 9354; Tier-A: 4× EPYC 7543). Each variant was pinned to exactly one node per tier (e.g., V2 to flare on Tier-S, V2 to goracle on Tier-A). V2–V5 each ran 7 of 10 seeds on Tier-S and 3 of 10 seeds on Tier-A; V1 ran all 10 seeds on Tier-A distributed across the 4 nodes. We do not maintain strict same-node pinning for all 10 seeds of each variant. Justification: (a) Phase 7d Inc 4 B11 demonstrates race-induced noise is ~0.7% across the EPYC node set (well below the variant-level effects in Pro's success criteria, which target 10–30% relative differences); (b) the seed-level mean reduces per-node race noise by √10; (c) both EPYC tiers are race-equivalent (Inc 4 found no systematic tier bias in disposition outcomes). This design trades ~30% wall-time savings (35h vs 52h) for slightly higher variant-level σ. Variant σ is reported as-measured.

Pro is invited to validate this trade-off in `CLOUD1_DECISIONS_FOR_PRO_R2.md` as a new question **G9: "Is the batched-parallel POS design sound for the V1–V5 relative ranking task, or does the partial cross-tier pinning compromise the comparison enough to require a re-run with strict pinning?"**

---

## 4. Track A — what Composer does (POS work)

This is the work order Composer executes in Phase 8 launch. Same template as Inc 5 (PHASE_7D_INC5_WORK.md) — single contract, single ping at end.

### 4.1 Composer's checklist (batched-parallel model)

```
□ Read PHASE_8_PLAN.md end-to-end (this file)
□ Pull bundle from WSL: rsync ~/a4_iv_pos_7_<sha>.tar.gz to coinbase ~/
□ Symlink bundle to ~/a4_campaign_iv_pos_7.tar.gz so auto_run picks it up
□ Run preflight in coinbase mode:
    python3 a4/pos/iv_pos_7_preflight.py --mode coinbase
  -> must print 'IV_POS_7 PREFLIGHT: PASS'
□ Regenerate manifests (only if changed): python3 a4/pos/generate_iv_pos_7_manifests.py --purge-old
□ Run N=20 smoke (validates 5 strategies on any 5-node reservation):
    bash a4/pos/auto_run_iv_pos_7.sh --smoke 2>&1 | tee /tmp/iv_pos_7_smoke/AUTORUN.log
  -> SUMMARY.txt should show: pos_iv_pos_7_smoke OK
□ Pre-book calendar entries (see §3.8):
    Tier-S: covers flare/octorand/opulous/polynize for ~35h
    Tier-A: covers algofi/gard/goracle/zone for ~33h
    (or rely on 1752 + chain follow-ons; orchestrator handles either case)
□ Launch Tier-S runner in tmux:
    tmux new -s ivpos7_ts
    cd ~/arguzz && source /srv/testbed/pos/cli/venv3/bin/activate
    bash a4/pos/auto_run_iv_pos_7.sh --tier=s 2>&1 | tee /tmp/iv_pos_7_tier_s/AUTORUN.log
    Ctrl+B d to detach
□ Launch Tier-A runner in tmux (at/after 03:00 UTC):
    tmux new -s ivpos7_ta
    cd ~/arguzz && source /srv/testbed/pos/cli/venv3/bin/activate
    bash a4/pos/auto_run_iv_pos_7.sh --tier=a 2>&1 | tee /tmp/iv_pos_7_tier_a/AUTORUN.log
    Ctrl+B d to detach
□ Monitor via tmux attach + STATUS.txt; book follow-on reservations as needed
□ After both SUMMARY.txt files show all batches OK: rsync results to WSL per §3.9
□ Run python -m a4.pos.collect_results_pos validation; produce COLLECTION_REPORT_FINAL.json
□ Free POS allocations -k; commit (manifests + scripts + report) in ONE commit
□ Ping Opus ONCE with the final-ping format below
```

### 4.2 Composer's final ping format

```
IV.POS.7 dispatch complete. 50/50 DBs validated.
COLLECTION_REPORT: 50/50 PASS (or: N FAILED, see report)
Tier-S wall: <X>h (7 batches), Tier-A wall: <Y>h (6 batches)
Total elapsed: <Z>h
Anomalies: <list or 'none'>
Artifacts: a4/runs/iv_pos_7/raw/, COLLECTION_REPORT_FINAL.json
Commit: <sha>
POS state: freed, calendars cleared
```

No intermediate pings. Same Inc 5 rules: if anything fails outside the §3.10 recovery table, STOP and ping immediately with state.

---

## 5. Track B — Notebook spec (`MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`)

This is the analysis notebook Pro will execute end-to-end. Specified cell-by-cell so it can be **filled in directly** once the 50 DBs land.

**Source template**: `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_NOTEBOOK.ipynb` (17 cells, ~330 KB). The IV.POS.7 notebook extends this with 5-variant support, counterfactual analysis, per-arm posterior diagnostics, and the race + disposition framework displays.

### 5.1 Cell-by-cell spec

| # | Cell type | Purpose | Outputs | Reuses IV.POS.5 cell? |
|---|---|---|---|---|
| **C0** | markdown | Title, abstract, reproduce instructions, IV.POS.5 → IV.POS.7 deltas | — | New |
| **C1** | code | Setup: discover 50 DBs, set `STRATS = ['zoned', 'kindUCB_zoned_v1', 'kindUCB_zoned_v2_noQ', 'kindTS_zoned_v2', 'cTS_semantic_v2']`, `SEEDS = list(range(1234, 1244))`, color palette | print: `5 strategies × 10 seeds = 50 DBs found` | Adapt C1 (5 strats not 3) |
| **C2** | code | **Headline coverage table per-seed** — for each (strategy, seed) compute `local_context_final` from `local_coverage_v2` table | DataFrame: 5 strats × 10 seeds + mean ± σ row | Adapt C2 |
| **C3** | code | **PLOT 1: cumulative coverage curves** — 5 lines, one per strategy, with ±σ shaded band; x = mutation_idx, y = unique local contexts. Mark zoned's 43.4 and bandit-16's 37.4 from IV.POS.5 for reference | `iv_pos_7_plots/01_cumulative_coverage.png` | Adapt C3 (5 lines + reference horizontals) |
| **C4** | code | **PLOT 2: per-seed coverage box plot** — boxplot per strategy showing seed-level final coverage; overlay IV.POS.5 zoned (43.4) as horizontal | `02_coverage_boxplot.png` | Adapt C4 |
| **C5** | code | **PLOT 3: kind distribution per strategy** — bar chart of `kind` allocation % per strategy (from `mutations.kind`) | `03_kind_distribution.png` | Adapt C5 (mirror IV.POS.5 §3.x table) |
| **C6** | code | **PLOT 4 (NEW for v2): zone distribution per strategy** — for V5 only, bar chart of semantic zone allocation (from `bandit_decisions.selected_arm`); for V1-V4, fall back to step-zone (init/core/final 5/90/5 buckets) | `04_zone_distribution.png` | New |
| **C7** | code | **PLOT 5: AUC + time-to-N table** — DataFrame with columns: variant, local_context_AUC, time_to_40/43/46 (mean ± σ across seeds), per_seed_all_46_hit_rate | DataFrame + `05_auc_timetox.png` (stacked bar) | New (Pro §10 explicit) |
| **C8** | code | **THE SMOKING-GUN check: discovery rate per kind** — replicate IV.POS.5 §17.1 but across 5 strategies. Is `INSTR_TYPE_MOD` still the highest-discovery kind? Does V5's allocation reflect this? | DataFrame + `06_discovery_per_kind.png` | Adapt §17.1 |
| **C9** | code | **THE STEP-0 check: §17.16 redux** — for each variant, count mutations at `INSTR_TYPE_MOD step=0`. Compare to IV.POS.5: zoned=184, uniform=1, bandit=2. V5 with singleton-zone enforcement should land at 5+ per Pro D10 | DataFrame + `07_step0_count.png` (5-bar) | Adapt §17.16 |
| **C10** | code | **Constraint overlap (Venn analysis)** — what contexts does each variant hit? Which contexts are V5-only, V1-only, etc.? | Matplotlib Venn + table | Adapt §17.2 |
| **C11** | code | **Constraint discovery timeline** — line plot per variant, x = mutation_idx, y = unique contexts found. Vertical lines at IV.POS.5 milestones (where zoned reached 43.4) | `08_discovery_timeline.png` | Adapt §17.6 |
| **C12** | code | **PLOT 6 (NEW): Bandit allocation entropy over time** — for V2-V5 (bandit-driven), plot Shannon entropy of arm-pull distribution per 500-mutation window. Tests whether TS keeps probing weak arms vs collapsing to favorite | `09_entropy_over_time.png` | New |
| **C13** | code | **PLOT 7 (NEW): Per-arm posterior at end-of-campaign (V5 only)** — Beta posterior for each (kind, zone) arm in V5; sort by mean; color by mode (cold/singleton/floor/adaptive). Tests "does TS converge to discovery-aligned arms?" | `10_v5_posterior.png` + DataFrame | New |
| **C14** | code | **PLOT 8 (NEW): Reward counterfactual scatter** — for each strategy, scatter `current_reward` vs `no_qloc_reward` vs `discovery_binary_reward` vs `compressed_global_reward`. Tests whether v2 reward ranks INSTR_TYPE_MOD higher than v1 (the central H1 from R1) | `11_reward_counterfactual.png` | New (Pro §12 explicit) |
| **C15** | code | **Per-(strategy, kind) reward composition** — for each strategy and each kind, mean reward + decomposition into L_new/F_new/G_new/S_new/crash/repeat components | DataFrame + `12_reward_composition.png` | Adapt §17.3 (extend to v2 components) |
| **C16** | code | **Compressed-global coverage growth** — cumulative unique compressed-global contexts per strategy. Tests success criterion 4 (Δglobal > 20%) | `13_compressed_global.png` | New |
| **C17** | code | **Crash rate per kind per strategy** — replicates IV.POS.5 §17.19 across 5 strategies | DataFrame + `14_crash_rate.png` | Adapt §17.19 |
| **C18** | code | **B1 disposition snapshot** — run `B1_apply_disposition.py` on a stratified sample of mutations per strategy; report net pass rate. Tests "did the disposition framework hold at Phase 8 scale?" | DataFrame + per-strat disposition JSON in `iv_pos_7_analysis/` | New (G8 evidence) |
| **C19** | code | **Race effect estimate** — for each pair (V2, V3, V4, V5) compare paired-seed B7-style prefix check (just `delta_T` differences per row). Tests "did the race phenomenon affect AUC interpretability?" | Table + `15_race_effect.png` | New (G7 evidence) |
| **C20** | code | **Success criteria check** — programmatically apply Pro's 5 success criteria per variant; print PASS/FAIL per criterion per variant. The matrix is the headline result for Pro | DataFrame (5 variants × 5 criteria) | New (Pro §10 explicit) |
| **C21** | code | **Wall-time per mutation** — comparable hardware sanity check; report mean wall time per mutation per strategy. Confirms no variant is pathologically slow | DataFrame + `16_walltime.png` | Adapt §17.12 |
| **C22** | code | **Sanity: selector labeling verification** — replicates IV.POS.5 §17.15 for the 5 v2 strategies, proving DBs aren't mislabeled | Output: `all 50 DBs verified strategy-labeled correctly` | Adapt §17.15 |
| **C23** | code | **Summary** — one DataFrame with all primary metrics + success criteria for each variant; one final paragraph block (markdown cell) with TL;DR conclusion | DataFrame; markdown summary | Adapt §C17 |

**Plots directory**: `a4/runs/iv_pos_7/plots/`. All 16 plots (one per code-cell that emits a PNG) regenerable.

**Pre-Phase-8 prep for the notebook**:
- Composer (or Opus) writes the notebook NOW with all 23 cells, mock data placeholders where the data doesn't exist yet, and runs each cell to confirm it executes without error against a 1-DB smoke run.
- Once 50 DBs land, re-run all cells; output should match real data.

### 5.2 What's removed from IV.POS.5 notebook

- §17.17 (pilot calibration instability) — D2 removed pilot, so this section becomes "pilot table is empty by design; verified."
- §17.20 (U signal dead) — keep as a 1-line check (verify U still 0 across all strats); no need for a full plot.
- §17.21 (Q_rep firing rate) — v2 doesn't use Q_rep; replace with a note pointing at the reward counterfactual cell.
- §17.22 (d_ext distribution) — superseded by `local_coverage_v2` and `compressed_global_coverage` tables; collapse to 1 cell.

### 5.3 Critical reproducibility requirement

Pro will likely re-run cells to sanity-check our claims. Each cell:
- Must execute end-to-end with no manual intervention.
- Must take ≤30s per cell (defer expensive computations to a cached `iv_pos_7_analysis/` JSON layer).
- Must produce output that matches the markdown's text references.

---

## 6. Track C — Markdown spec (`MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`)

This is the big markdown Pro reads first (~80-120 KB target, slightly larger than IV.POS.5's 115 KB because it has more variants + the race/disposition story).

**Source template**: `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` (20 sections, 2105 lines). The IV.POS.7 markdown reuses the structure but is REtargeted at "did we fix what Pro told us was broken?"

### 6.1 Section map

| § | IV.POS.7 section (NEW name) | What it contains | IV.POS.5 analogue |
|---|---|---|---|
| **0** | TL;DR for Pro Round 2 | 1-page summary: what we did, what we found, where the deviations are, what we need Pro to validate | §0 (rewritten) |
| **1** | Goal: did cloud1 fix what R1 flagged? | Frames the campaign around Pro's R1 critique: representational failure, reward anti-correlation, UCB-on-mean misfit. For each, state whether the v2 architecture addresses it | §0 (extended) |
| **2** | The 5 variants — full spec | Per variant: selector algorithm, step sampler, reward function, expected behavior, what it isolates. Cross-references `bandit_ts.py`, `step_selector.py`, `reward_v2.py`, etc. | §3 (extended to 5 variants) |
| **3** | The v2 architecture (deep dive) | What changed since IV.POS.5: semantic zones, compressed global contexts, structural cells, marginal-discovery reward, constrained TS bandit. Cross-refs to CLOUD1_IMPLEMENTATION_PLAN.md per-phase docs | §4 (rewritten — this is a totally new architecture) |
| **4** | Reward function v2 (deep dive) | The new `compute_reward_v2(L_new, F_new, G_new, S_new, crash, repeat)`. Mathematical derivation, weight rationale (D24-D38), counterfactual formulas (D23) | §5 (rewritten — new reward) |
| **5** | Experimental setup (IV.POS.7) | 50 runs, 5 variants × 10 seeds, N=6000, same guest. POS hardware, parallelism, race notes. Cross-ref §6 (G7 race section) | §6 (extended) |
| **6** | Headline results | Per-variant final coverage + AUC + time-to-N table. Plot from notebook C7. Success criteria matrix (notebook C20) | §7 (extended for 5 variants) |
| **7** | Per-variant diagnostic | For EACH of V1-V5, a sub-section covering: allocation distribution (kind + zone), discovery rate per kind, reward decomposition, where it spends its budget, what arms TS converges to (V5 only) | §8-§10 (consolidated, 5 sub-sections) |
| **8** | The 5 R1 hypotheses — were they right? | For each of Pro's R1 §2-§4 hypotheses (boundary structure, Q_loc anti-discovery, UCB-on-mean misfit), evaluate against IV.POS.7 results. Did V5 fix the step-0 representational failure? Did the new reward rank INSTR_TYPE_MOD correctly? | §11 (rewritten) |
| **9** | The race phenomenon (G7) | High-level summary of the race, what we measured at scale in Phase 8, whether AUC interpretability is affected. **Detailed deep-dive in companion `RACE_FINDING_AND_OPEN_QUESTIONS.md`** | New (G7) |
| **10** | The B1 disposition framework (G8) | High-level summary of the 6 exclusion categories, the safety guard, why we can confidently report `net pass` rates. **Detailed deep-dive in `PHASE_7D_INC3D_B1_DISPOSITION.md`** | New (G8) |
| **11** | Phase 7d audit attestation | 17 audits ran, all green (or PASS-WITH-CAVEAT for B11 due to race). Per-arm E5 evidence pack exists with 48 ✓-CORRECT arms. Cross-ref `PHASE_7D_FINAL_REPORT.md` | New (Phase 7d outputs) |
| **12** | Allocation entropy + behavioral diagnostics | Per-variant Shannon entropy over kind + zone; entropy evolution over time (notebook C12). Per-arm posterior for V5 (notebook C13) | New (Pro §10 entropy metric) |
| **13** | Counterfactual reward analyses | Pro §12-requested 5 counterfactual rewards: current, no_qloc, fnew_only, discovery_binary, compressed_global. Per-strategy scatter from notebook C14 | New (Pro §12 explicit) |
| **14** | Compressed global coverage | Per-strategy unique compressed contexts hit (notebook C16); does v2 satisfy success criterion 4? | New (Pro §5 + criterion 4) |
| **15** | Honest conclusion | (a) Does V5 beat V1 on at least one success criterion? (b) If yes, by how much and what's the next question for Pro? (c) If no, what's the next hypothesis? Pro's R1 decision tree §13 governs this section | §11 + §13 (rewritten) |
| **16** | Open questions for Pro Round 2 | The G1-G8 questions reformatted as a numbered list with cross-refs to evidence in this doc; preceded by 1-paragraph context summarizing the experimental result | §15 (rewritten + extended to G8) |
| **17** | Appendix: full data dumps | Per-strategy aggregate tables (paste from notebook output): coverage matrix, reward decomposition, allocation table, discovery rate, crash rate. Same density as IV.POS.5 §16 | §16 (extended for 5 strats × 10 seeds) |
| **18** | Appendix: D-decisions touching Phase 8 | One-row-per-decision table for D40-D55, with column "appeared in Phase 8 as" — concrete result row that confirms or challenges each decision | New |
| **19** | Appendix: file map | Where every Pro-facing artifact lives in the repo (markdown + notebook + JSONs + plots + supporting docs) | §20 extended |

### 6.2 Section length budget (~120 KB total)

| § | Estimated KB |
|---|---:|
| 0 — TL;DR | 4 |
| 1 — Goal | 3 |
| 2 — 5 variants spec | 8 |
| 3 — v2 architecture | 12 |
| 4 — Reward v2 | 6 |
| 5 — Experimental setup | 4 |
| 6 — Headline results | 6 |
| 7 — Per-variant diagnostic | 25 |
| 8 — 5 R1 hypotheses | 8 |
| 9 — Race (G7) | 4 |
| 10 — B1 disposition (G8) | 4 |
| 11 — Phase 7d attestation | 3 |
| 12 — Entropy + behavior | 6 |
| 13 — Counterfactuals | 6 |
| 14 — Compressed global | 4 |
| 15 — Conclusion | 4 |
| 16 — Pro questions | 6 |
| 17 — Data dumps | 8 |
| 18 — D-decisions | 4 |
| 19 — File map | 1 |
| **Total** | **~126 KB** |

### 6.3 Mapping IV.POS.5 → IV.POS.7 prose

The IV.POS.7 markdown is **not a rewrite from scratch.** Many IV.POS.5 sections describe things that haven't changed (the target, the mutation kinds, the universe of 46 contexts, the POS infrastructure, the budget feasibility analysis). For those, the IV.POS.7 markdown should:

- COPY VERBATIM with a note `(unchanged from IV.POS.5 — included for self-containment)`.
- Cross-reference the IV.POS.5 markdown for the historical record where appropriate.

Sections that DO need rewriting (and which IV.POS.5 § they replace):

| IV.POS.7 § | What changes | IV.POS.5 § it replaces |
|---|---|---|
| §0 TL;DR | Headline result is now "V5 vs V1 by criterion" not "bandit vs zoned" | §0 |
| §2 Variants | 5 instead of 3 | §3 |
| §3 Architecture | All v2 components are new (semantic zones, compressed global, cTS, reward_v2) | §4 |
| §4 Reward | New formula | §5 |
| §6-7 Results | New data (Phase 8) | §7-§8 |
| §8 Hypotheses | Now reviews whether R1 hypotheses HELD post-fix | §11 |
| §9-10 Race + Disposition | New (didn't exist in R1) | — |
| §15 Conclusion | "Did v2 work?" not "Why does MAB underperform?" | §11 |
| §16 Open questions | Now G1-G8 (Pro can validate) | §15 |

### 6.4 Density principle

The R1 markdown succeeded with Pro because of **§17's per-section data density** (24 sub-sections of concrete tables, plots, mechanism analyses). The R2 markdown's §7 (Per-variant diagnostic, 5 sub-sections) and §17 (Data dumps) must replicate this density:

- Every claim has a number with provenance (`source: notebook C8`, `source: a4/runs/iv_pos_7/v5_seed1234.db`).
- Every plot has a 1-paragraph reading attached.
- Every per-variant sub-section has the same fixed sub-structure (allocation, discovery, reward decomp, drift over time, conclusion).

---

## 7. Track A/B/C parallelism schedule

| Hour 0 (Phase 7d Inc 5 GREEN) | Hour +12 | Hour +24 | Hour +48 | Hour +72 | Hour +96 |
|---|---|---|---|---|---|
| Composer pings Inc 5 done | | | | | |
| Opus writes PHASE_7D_FINAL_REPORT.md (Track 7d) | done | | | | |
| Composer builds bundle + writes preflight (Track A) | | done | | | |
| Composer N=20 smoke + manifest validation (Track A) | | done | | | |
| Composer reserves POS calendar slots (Track A) | | done | | | |
| **Composer launches IV.POS.7 dispatch (Track A)** | | | running | DONE | |
| Opus writes notebook scaffold with mock data (Track B) | | done | | | |
| Opus writes markdown scaffold with §1-§5 prose (Track C) | | | mostly done | | |
| **Collection + validation (Track A)** | | | | done | |
| Notebook fills in real data (Track B) | | | | | done |
| Markdown fills in results sections (Track C) | | | | | done |
| Final review + Pro package | | | | | done → ship |

**Critical path**: Composer's POS dispatch dominates (~24-48h). All other tracks can fit within that window.

---

## 8. Pre-launch checklist (before any POS work)

```
□ Phase 7d Inc 5 GREEN; final report written
□ PHASE_8_PLAN.md (this file) reviewed by user
□ Bundle built + SHA recorded
□ All 5 nodes available on POS calendar (or substitution plan ready)
□ Manifests generated + parsed
□ Auto-runner script written + smoke-tested
□ Preflight script written + passes
□ N=20 smoke run completes successfully (all 5 strategies, all v2 tables populated)
□ collect_results_pos.py extended for v2 table validation
□ Notebook scaffold written + executes against the N=20 smoke DB
□ Markdown scaffold written + §1-§5 + §11 + §16-§19 prose drafted
□ Calendar entries reserved (2 future at minimum)
□ User signs off on launch
```

---

## 9. Pro Round 2 deliverable package (final ship list)

When Phase 8 is complete and the analysis is written, the package sent to Pro is:

| File | Path | What Pro reads |
|---|---|---|
| **Pro R1 reply** (input) | `a4/docs/cloud1/ProG_Report_2.md` | (for Pro's reference — their own R1 doc) |
| **Pro R2 main report** | `a4/runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | Read first |
| **Pro R2 notebook** | `a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` | Reproducibility + plot regeneration |
| **Decisions doc** | `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` | D40-D55 + G1-G8 (the open questions doc) |
| **Race deep-dive** | `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` | Companion to §9 of main report |
| **Phase 7d final report** | `a4/docs/cloud1/composer/PHASE_7D_FINAL_REPORT.md` | Audit attestation (Pro can spot-check) |
| **Disposition framework** | `a4/docs/cloud1/composer/PHASE_7D_INC3D_B1_DISPOSITION.md` | G8 evidence |
| **Per-arm evidence** | `a4/audits/audit_output/per_arm_evidence/README.md` | E5 index Pro can sample from |
| **Plots** | `a4/runs/iv_pos_7/plots/*.png` (16 plots) | Referenced from main report |
| **Raw DBs** | `a4/runs/iv_pos_7/raw/*.db` (50 DBs) | Not for Pro to read; preserved for re-analysis |

---

## 10. What "done" looks like

Phase 8 is closed when:

- All 50 DBs validated and committed (or moved to long-term storage with manifest).
- `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` has all §0-§19 populated.
- `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` executes end-to-end with no manual intervention.
- All plots regenerable from the notebook.
- User has spot-reviewed the main report.
- Package shipped to Pro.

Pro Round 2 happens externally. After Pro responds, the decision branch in `PHASE_9_REPORT.md §80-90` triggers either (a) resume master plan, (b) launch cloud2, or (c) negative-result publication path.

---

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| POS testbed busy, 5 nodes hard to book together | Pre-book in 3h blocks, use auto-runner's reservation-wait logic; fall back to 2-3 parallel if needed |
| Bundle build fails / SHA drift | Build from a tagged commit; preflight checks SHA |
| V5's race causes one variant's AUC to drift significantly | Per Inc 4 measurement, aggregate impact is ~0.075 TVD on kind-pulls — meaningful but not killing. Disclose in §9 of report; per-seed variance bands cover it |
| One node bricks mid-campaign | BACKUP_NODES substitution; re-dispatch failed runs (documented in §3.10) |
| 50 DBs total ~5 GB; disk pressure | WSL has ≥100 GB free; pre-check in preflight |
| Notebook cells timeout against real 50-DB data | Defer expensive computations to pre-cached `iv_pos_7_analysis/*.json`; each cell reads cached data, not raw SQL |
| Pro asks for additional metrics not in Pro §10 | Notebook is reproducible; can add cells in <1 day of additional work |
| Race causes new failure mode in V5 we haven't seen | Per Inc 4 evidence, race only affects bandit reward path; constraint outcomes are 100% deterministic. Document if surfaced |
| One of the 50 runs produces fewer than expected mutations | §3.10 recovery: re-run just that (variant, seed); flag in COLLECTION_REPORT |

---

## 12. What's explicitly NOT in Phase 8 (deferred)

Per Pro's R1 §11 ordering and our D-decisions:

- ❌ New mutation kinds (TXN_PREV_*) — Pro §11 step 3
- ❌ New guests (BigInt, Poseidon, Keccak) — Pro §11 step 5, D3
- ❌ Hyperparameter grid on c_explore, gamma, reward weights — Pro §10
- ❌ N=10000+ runs — only if Phase 8 results motivate (Pro §10)
- ❌ D52 cycle_idx plumbing — D52 deferred to Phase 9 trigger
- ❌ Multi-guest verification (true second guest) — Phase 10
- ❌ Resume precloud master plan — gated on Pro Round 2 outcome

These are the post-Pro-R2 menu, NOT Phase 8 scope. If Pro's R2 motivates any of them, they go into a new "cloud2" plan after R2 lands.
