# V5 Architecture Guide — `cTS_semantic_v2` (Pro Round 2)

**Purpose:** Single intuitive reference for how V5 works end-to-end: arms, modes, rewards, updates, and step selection. Assembles material that previously lived across Phase 2/4/5 docs and `bandit_ts.py`.

**Audience:** Ivan, Pro reviewers, future-you. Not a substitute for source code — but enough to read the IV.POS.7 results without spelunking five files.

**Status:** Living doc (2026-06-15). Code source of truth: `a4/standalone/bandit_ts.py`, `a4/standalone/reward_v2.py`, `a4/standalone/semantic_zones.py`.

---

## Table of contents

0. [Design philosophy — why V5 is structured this way](#0-design-philosophy--why-v5-is-structured-this-way)
1. [What V5 is in one paragraph](#1-what-v5-is-in-one-paragraph)
2. [How it differs from V1 (zoned)](#2-how-it-differs-from-v1-zoned)
3. [The action space: 48 `(kind, zone)` arms](#3-the-action-space-48-kind-zone-arms)
4. [Selection: four modes (cold, singleton, floor, adaptive)](#4-selection-four-modes-cold-singleton-floor-adaptive)
5. [Why floor dominates but V5 wins early](#5-why-floor-dominates-but-v5-wins-early)
6. [Reward: scalar v2 vs Bernoulli bandit signal](#6-reward-scalar-v2-vs-bernoulli-bandit-signal)
7. [Posterior update (Thompson sampling)](#7-posterior-update-thompson-sampling)
8. [Step pick within an arm](#8-step-pick-within-an-arm)
9. [Counterfactual rewards (Pro §12)](#9-counterfactual-rewards-pro-12)
10. [Related docs map](#10-related-docs-map)
11. [Freezing V5 for competitions (A4 vs arguzz)](#11-freezing-v5-for-competitions-a4-vs-arguzz)

---

## 0. Design philosophy — why V5 is structured this way

### The problem IV.POS.5 revealed

IV.POS.5 was not “MABs don’t work for fuzzing.” It was: **this MAB was learning over the wrong abstraction, with a reward that punished the mutations that actually discover constraints.**

Three failures stacked:

1. **Wrong action space** — Kind-only arms (`INSTR_TYPE_MOD` vs `MEM_VAL_MOD`) hide *where* in the trace the mutation lands. The IV.POS.5 smoking gun was conjunctive: `INSTR_TYPE_MOD` **and** `step = 0` for several constraints. A kind-only bandit cannot express that joint.
2. **Allocation collapse** — UCB chased arms with high scalar reward / low variance (`INSTR_WORD_MOD_SUR`), starving high-discovery kinds (`INSTR_TYPE_MOD`). Discovery rate and mean reward were anti-correlated.
3. **Hand-crafted priors beat naive learning** — V1 (`zoned`) encoded structural fairness (uniform kinds + 5/90/5 step phases) without needing a reward signal. The bandit had to **earn** its adaptivity by beating that prior, not merely exist.

Pro’s Round 2 prescription (§7, §10) was therefore architectural, not “tune $\gamma$”:

> Make the bandit choose among **semantically meaningful** trace perturbation regions, and reward **marginal discovery** — not failure cardinality.

V5 is the embodiment of that sentence.

### Design principle 1: Representation before learning

**You cannot Thompson-sample your way out of a bad action space.**

V2–V4 added step priors and reward fixes to kind-only UCB/TS. They still lost kernel/ECALL locs because the bandit never chose arms like `INSTR_TYPE_MOD|pre_ecall` — those arms **did not exist**.

V5’s first move is **refining the arm grid** to $(\mathit{kind}, \mathit{semantic\_zone})$ — 48 populated arms for the baseline guest, built from inspection data + zone classifier ([`EXPECTED_ARMS.md`](EXPECTED_ARMS.md)). The bandit now asks: “which *circuit region* should I perturb, with which *mutation operator*?” — not just “which kind?”

**Philosophy:** In zkVM fuzzing, the hard part is **hitting the right trace coordinates**, not picking among eight coarse operators. Semantic zones are the coordinate system.

### Design principle 2: Constraints before posteriors

**Naive TS/UCB assumes every arm will eventually get enough pulls for the posterior to converge.** IV.POS.5 showed that assumption is false at $N=6000$: the “losing” arms are starved before their discovery signal accumulates.

V5 inverts the priority stack:

```text
hard constraints (cold, singleton, floor)  →  then  soft optimization (adaptive TS)
```

Not: “TS explores naturally.” Not: “raise UCB $c$.”

| Layer | Role | Philosophical stance |
|---|---|---|
| **Cold** | Lifetime minimum exposure per arm | *Epistemic humility* — you are not allowed to ignore an arm until you have tried it |
| **Singleton** | Boundary zones (`step0`, `last_step`) | *Structural prior as code* — IV.POS.5 proved boundary steps are not optional |
| **Floor** | Per-epoch fairness across 48 arms | *Anti-collapse insurance* — learning may not defund rare high-yield regions |
| **Adaptive** | Beta-TS on leftover budget | *Refinement, not discovery* — only runs when fairness obligations are met |

**Why ~94% floor is a feature, not a bug:** Adaptive TS, when it runs, concentrates on arms with high sampled $\theta$. Those arms pull ahead in `epoch_pulls`; others slip below the per-epoch target ($\approx 0.55 \times 100 / 48$ pulls per arm per 100 mutations). The scheduler immediately switches back to **floor** and pulls the stragglers. The system oscillates:

```text
TS concentrates  →  inequality within epoch  →  floor repairs  →  brief TS window  →  repeat
```

Net accounting over 6000 mutations: **floor does the discovery work** (forced visits to under-explored $(\mathit{kind}, \mathit{zone})$ pairs); **adaptive patches inequality** inside epochs when the fairness quota is temporarily satisfied.

That is why V5’s coverage curve jumps ahead of V1 by mutation 500 with only ~13 adaptive pulls: the early win is **cold + floor on the right arm space**, not “the bandit got smart at the end.”

### Design principle 3: Bernoulli discovery signal, not scalar reward

Scalar `compute_reward_v2` mixes discovery, crash penalty, repeat penalty, and saturation — exactly the soup that made IV.POS.5 rank `INSTR_TYPE_MOD` worst while it discovered the most.

V5’s TS update uses:

$$\mathrm{success} = \mathbb{1}[L_{\mathrm{new}} + G_{\mathrm{new}} + S_{\mathrm{new}} > 0]$$

**Philosophy:** The bandit’s job is **“did this arm find something new?”** — a Bernoulli question compatible with Beta posteriors. Scalar v2 remains for logging, counterfactuals, and human analysis (D32), but **must not drive TS updates** or you re-import the pathology.

### Design principle 4: Uniform step pick *inside* the zone

After the bandit picks $(\mathit{kind}, \mathit{zone})$, V5 picks a step **uniformly** within that zone’s step list.

**Philosophy:** The bandit’s job is **region selection**; within a semantically homogeneous region, we deliberately avoid a second nested bandit (which added variance and debugging surface in Phase II). V1’s 5/90/5 is a *different* geometry (init/core/final by step index); V5’s zones are *circuit-role* buckets (`core_mul`, `pre_ecall`, …). The bandit replaces V1’s coarse time buckets with finer semantic buckets.

### Design principle 5: Deterministic fairness, stochastic refinement

Mode **counts** per seed are fixed ($144 + 8 + 5615 + 233 = 6000$); **which arm** within a mode is seed-dependent (TS draws, round-robin tie breaks, step choice).

**Philosophy:** Reproducible **budget policy** (fairness contract) + stochastic **within-policy** choices. You can compare variants across seeds without wondering if one seed “got a different floor schedule.”

### What V5 is *not* trying to be

- **Not** a pure RL optimizer that discovers structure from scratch — V1’s zoned prior is **baked into** singleton + floor + zone definitions.
- **Not** a hyperparameter soup — Pro explicitly warned against grid-searching $c$, $\gamma$, weights before fixing representation ([`ProG_Report_2.md`](ProG_Report_2.md) §10).
- **Not** guest-agnostic magic — arm universe is **rebuilt per guest** from `InspectionData`; 48 arms is empirical for `sha2-host --in1 5 --in4 10`, not universal.

### One-sentence philosophy

**V5 is a constrained coverage scheduler that uses Thompson sampling only for the budget left over after enforcing semantic fairness — because zkVM constraint discovery is a structured search problem, not a stationary slot machine.**

---

## 1. What V5 is in one paragraph

**V5** (`cTS_semantic_v2`) is a **constrained Thompson sampler** over **48 arms** of the form `(mutation_kind, semantic_zone)` — e.g. `INSTR_TYPE_MOD|pre_ecall`. Each mutation:

1. **Select arm** via a 4-tier priority: cold-start → singleton floor → per-epoch coverage floor → adaptive Beta-TS.
2. **Pick a trace step** uniformly within that arm’s step list.
3. **Apply mutation**, run guest, score discoveries.
4. **Update** a Beta($\alpha$, $\beta$) posterior per arm with a **Bernoulli success** (did this mutation discover anything new?).

The design bet: IV.POS.5 failed because the bandit’s **action space was too coarse** (kind-only) and **allocation collapsed**. V5 fixes **representation** (kind×zone) and **allocation** (hard floors), not just reward tuning.

---

## 2. How it differs from V1 (zoned)

| | **V1 (`zoned_current`)** | **V5 (`cTS_semantic_v2`)** |
|---|---|---|
| Kind choice | **Uniform** over 8 kinds | **Constrained TS** over 48 `(kind,zone)` arms |
| Where in trace | **Zoned step sampler** (5% step0 / 90% core / 5% last step) | Step uniform **within** the chosen semantic zone |
| Learning | None (fixed schedule) | Beta posteriors + floors |
| Bandit table rows | 0 (`bandit_decisions` empty) | 6000 rows per run |
| Reward used for selection | N/A (no bandit) | Bernoulli `compute_bandit_success` |

**Common misconception:** V1 is **not** “random sampling within 3 zones.” It is:

- **Uniform over mutation kinds** (each kind gets ~⅛ of pulls).
- **Zoned step sampler** splits valid steps into **init / core / final** (step 0, middle, last step) with weights **5% / 90% / 5%** — see `ZonedStepSelector` in `step_selector.py`.

V1 is hand-crafted fairness; V5 is **learned allocation with fairness constraints** on a finer arm grid.

---

## 3. The action space: 48 `(kind, zone)` arms

### Mutation kinds (8)

`COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`, `INSTR_TYPE_MOD`, `MEM_VAL_MOD`, `INSTR_WORD_MOD_FULL`, `INSTR_WORD_MOD_SUR`.

### Semantic zones (~17 names, 48 populated arms for this guest)

Zones group trace **steps** by circuit role: `step0`, `pre_ecall`, `post_ecall`, `core_arithmetic`, `core_memory_load`, `core_mul`, …

An **arm** = one `(kind, zone)` pair such that at least one valid step exists in that zone for that kind. For `sha2-host --in1 5 --in4 10`:

- **48 kept arms**, **5 dropped** (empty cross-products) — canonical list in [`EXPECTED_ARMS.md`](EXPECTED_ARMS.md).
- Arm ID string: `INSTR_TYPE_MOD|pre_ecall` (logged in `bandit_decisions.selected_arm`).

### Building the universe

```
InspectionData (guest trace)
    → classify each step into a zone (semantic_zones.py)
    → intersect with per-kind valid steps (arm_universe.py)
    → SemanticArmUniverse.available_arms
```

Empty arms are skipped at runtime (decision D7).

---

## 4. Selection: four modes (cold, singleton, floor, adaptive)

`ConstrainedTSScheduler.select()` in `bandit_ts.py` checks tiers **in order**; first match wins.

```text
mutation N:
  if any arm has lifetime pulls < 3        → mode = cold
  else if any singleton arm has pulls < 5  → mode = singleton
  else if any arm below epoch floor target → mode = floor
  else                                     → mode = adaptive (Beta TS)
```

### Cold (144 pulls / 6000 = 2.4%)

- **What:** Round-robin among arms with **lifetime** `pulls[arm] < 3`.
- **Why:** Every `(kind,zone)` must be tried at least 3 times before TS can ignore it.
- **When:** Mutations **1–144** exclusively (48 arms × 3 pulls = 144).
- **Analogy:** Mandatory tasting menu — you must sample every dish before the restaurant takes your order seriously.

### Singleton (8 pulls)

- **What:** Round-robin among **singleton zones** (`step0`, `last_step`, …) until each has **5 lifetime pulls**.
- **Why:** Pro D10 — boundary steps are rare but high-leverage (IV.POS.5 step-0 smoking gun).
- **When:** Mutations **145–152** (after cold ends).

### Floor (5615 pulls = 93.6%)

- **What:** Each **epoch** (100 mutations), every arm must receive at least  
  `target = 0.55 × 100 / 48 ≈ 1.15` pulls. If any arm is below target, pick the most under-allocated arm (`mode = floor`).
- **Why:** Prevents TS from starving arms with good discovery but noisy early rewards (the IV.POS.5 INSTR_TYPE_MOD pathology).
- **Analogy:** FCC equal-time rule — every station gets a minimum number of plays per hour, regardless of current ratings.

### Adaptive (233 pulls = 3.9%)

- **What:** Sample $\theta_a \sim \mathrm{Beta}(\alpha_a, \beta_a)$ per arm; pick highest $\theta$.
- **Why:** Refine allocation **after** floors are met for the current epoch.
- **When:** Starts as early as mutation **~200**, but only when no arm is cold/singleton-underfulfilled/epoch-underfulfilled.

See [§0](#0-design-philosophy--why-v5-is-structured-this-way) for why the floor/adaptive oscillation is intentional.

### Floor vs cold — the distinction

| | **Cold** | **Floor** |
|---|---|---|
| **Counter** | Lifetime pulls per arm | Pulls **within current epoch** (resets every 100 mutations) |
| **Threshold** | 3 total | ~1.15 per epoch per arm |
| **Duration** | Ends permanently after mutation 144 | Repeats every epoch forever |
| **Goal** | “Try every arm at least once” | “Every arm gets fair share **this** epoch” |

Cold is **bootstrapping**; floor is **ongoing fairness**.

### Mode budget partition (why σ = 0 across seeds)

Per seed, counts are **always** 144 + 8 + 5615 + 233 = 6000. The algorithm is **deterministic in how many mutations fall into each mode bucket** given fixed hyperparameters (`cold_start_pulls_per_arm=3`, `epoch_size=100`, `coverage_floor_fraction=0.55`, 48 arms).

**Seed randomness** affects *which arm* within cold/floor/adaptive and *which step* inside the arm — not the mode totals. Hence `v5_mode_summary.csv` shows `std_pulls = 0.0` across seeds (not a bug).

---

## 5. Why floor dominates but V5 wins early

**Observation:** V5’s coverage curve pulls ahead of V1 **before** mutation 500, when only ~13 adaptive pulls have occurred.

| Mutation # | V5 mean locs | V1 mean locs | Adaptive pulls so far (V5) |
|---:|---:|---:|---:|
| 500 | 39.0 | 29.8 | 13 |
| 1000 | 42.3 | 34.9 | 33 |
| 2000 | 45.2 | 37.7 | 73 |
| 6000 | 46.4 | 42.9 | 233 |

**Interpretation:** The win is **not** “TS magic at the end.” It is:

1. **Cold (1–144):** Forces 3 pulls on **every** `(kind,zone)` including `INSTR_TYPE_MOD|pre_ecall`, `ControlMRET`-adjacent zones, etc.
2. **Floor (rest):** Keeps visiting under-explored zones V1’s kind-uniform + 5/90/5 step prior never prioritizes.
3. **Arm space:** Discovering `LRN@35/44/45` and `MRET@93` requires **specific (kind,zone) pairs**, not more adaptive pulls on `INSTR_WORD_MOD_SUR|core_arithmetic`.

Adaptive’s 233 pulls **fine-tune** within epochs; **floor + semantic zones** do the heavy lifting.

### Would 10× mutations make adaptive dominate?

**Unlikely with current hyperparameters.** Cold and singleton are **fixed counts** (144 + 8). Floor is **structural**: `coverage_floor_fraction = 0.55` reserves ~55% of each epoch’s budget for minimum per-arm coverage. At N = 60,000 you get more **epochs**, but the floor fraction is by design — adaptive stays a minority unless you change `coverage_floor_fraction` or `epoch_size`.

More mutations help **posterior precision** and **saturation past 46 locs**; they do not automatically shift mode mix toward adaptive.

---

## 6. Reward: scalar v2 vs Bernoulli bandit signal

Two rewards coexist (Phase 4 + Phase 5 decisions):

### Scalar `compute_reward_v2` (logging & analysis)

$$
R_{\mathrm{v2}} = 1.00\cdot\mathrm{sat}(L_{\mathrm{new}},1) + 0.30\cdot\mathrm{sat}(F_{\mathrm{new}},1) + 0.25\cdot\mathrm{sat}(G_{\mathrm{new}},3) + 0.15\cdot\mathrm{sat}(S_{\mathrm{new}},2) - 0.50\cdot\mathrm{crash} - 0.05\cdot\mathrm{sat}(\mathrm{repeat},5)
$$

where $\mathrm{sat}(x,\tau) = 1 - e^{-x/\tau}$.

- $L_{\mathrm{new}}$: new local `(loc, major, minor)` contexts
- $G_{\mathrm{new}}$: new compressed-global contexts
- $S_{\mathrm{new}}$: new structural cell in `(kind, zone, opcode_class)`
- **Not used** to update V5’s TS posterior (D32).

### Bernoulli `compute_bandit_success` (bandit update)

$$
\mathrm{success} = \mathbb{1}[L_{\mathrm{new}} + G_{\mathrm{new}} + S_{\mathrm{new}} > 0]
$$

Binary: did this mutation discover **anything** new (local, global, or structural)? This is what `ConstrainedTSScheduler.update()` feeds to Beta posteriors.

**Intuition:** TS needs a conjugate Bernoulli likelihood; scalar v2 is too continuous and crash-penalized for clean Beta updates.

---

## 7. Posterior update (Thompson sampling)

Per arm $a = (\mathit{kind}, \mathit{zone})$:

- Prior: $\mathrm{Beta}(1, 1)$ per arm (uniform).
- After each pull with success $s \in \{0,1\}$:

$$
\alpha_a \leftarrow \alpha_a + s,\quad \beta_a \leftarrow \beta_a + (1-s)
$$

- Adaptive selection: draw $\theta_a \sim \mathrm{Beta}(\alpha_a, \beta_a)$, pick $\arg\max_a \theta_a$.

**Floor/cold ignore posteriors** — they fire on pull counts, not $\theta$.

Epoch reset: every 100 mutations, `epoch_pulls[arm] ← 0` (floor counters only; lifetime `pulls` and $\alpha$, $\beta$ persist).

---

## 8. Step pick within an arm

After the bandit chooses `(kind, zone)`:

```python
steps = universe.steps_in_arm(kind, zone)
step = steps[0] if len(steps) == 1 else rng.choice(steps)
```

Uniform over valid steps in that zone for that kind. V2–V4 instead pick kind first, then delegate to `ZonedStepSelector` (5/90/5 over init/core/final) — **different geometry**.

---

## 9. Counterfactual rewards (Pro §12)

Every mutation (all variants, full telemetry) logs five **hypothetical** scores in `reward_counterfactuals` — computed **after** the run from what actually happened, without re-simulating.

| Field | Formula (simplified) |
|---|---|
| `current_reward` | `compute_reward_v2(...)` — **same v2 formula for all variants** |
| `discovery_binary_reward` | `compute_bandit_success(l_new, g_new, s_new)` |
| `no_qloc_reward` | Legacy reward with Q_loc stripped |
| `fnew_only_reward` | Family-newness term only |
| `compressed_global_reward` | Global-newness term only |

### Why V1 “ranks ITM high” in §6.5

**V1 does not use these rewards for selection.** But telemetry still computes them per mutation.

For V1 `INSTR_TYPE_MOD` mutations that **do occur** (~⅛ of pulls):

- They often trigger new constraint failures → high $L_{\mathrm{new}}$ → high `current_reward` (v2) and `discovery_binary_reward = 1`.

The §6.5 table averages these **per-mutation** scores over all ITM pulls in the campaign. ITM ranks #1 because **when you mutate instruction types, good things happen** — not because V1 “rewards” ITM during selection.

The IV.POS.5 bandit failure was the opposite: **kind-level UCB starved ITM pulls** (V2: 584 ITM pulls vs 51,144 `INSTR_WORD_MOD_SUR`) while ITM had the best **discovery rate per pull**. Counterfactual means hide that; discovery rate per kind (§6.1) exposes it.

---

## 10. Related docs map

| Need | Read |
|---|---|
| Pro’s original intent | [`ProG_Report_2.md`](ProG_Report_2.md) §7, §10, §12 |
| Zone definitions & arm universe | [`phases/PHASE_2_SEMANTIC_ZONES.md`](phases/PHASE_2_SEMANTIC_ZONES.md) |
| Reward formulas | [`phases/PHASE_4_REWARD.md`](phases/PHASE_4_REWARD.md) |
| Scheduler implementation & variants V1–V5 | [`phases/PHASE_5_BANDIT_TS.md`](phases/PHASE_5_BANDIT_TS.md) |
| Canonical 48-arm matrix | [`EXPECTED_ARMS.md`](EXPECTED_ARMS.md) |
| IV.POS.7 results narrative | [`../runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`](../runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md) |
| Implementation | `a4/standalone/bandit_ts.py`, `reward_v2.py`, `fuzzer.py` |
| Historical (pre-V5) LaTeX-style MAB doc | [`../touch/Phase II/MAB_ARCHITECTURE_REVIEW.md`](../touch/Phase II/MAB_ARCHITECTURE_REVIEW.md) |

---

## 11. Freezing V5 for competitions (A4 vs arguzz)

### Short answer

**For A4 bug-hunting competitions on RISC0 guests: yes — freeze the IV.POS.7-validated hyperparameters and selector (`cTS_semantic_v2`) as the production default**, unless the guest or mutation taxonomy changes enough to require rebuilding the arm universe. **Do not** treat arguzz (V6) as “the same knob” — it is a different engine with a different scheduler and no V5 bandit tables.

### What “freeze” means in practice

| Freeze (stable across competitions) | Rebuild per target (not frozen) |
|---|---|
| Selector: `cTS_semantic_v2` | `SemanticArmUniverse` from new guest’s `InspectionData` |
| `cold_start_pulls_per_arm = 3` | Zone classifier tweaks if trace shape changes |
| `forced_singleton_pulls = 5` | `EXPECTED_ARMS.md` row for new guest |
| `coverage_floor_fraction = 0.55` | Campaign budget $N$ (6000 vs 12000 — protocol choice) |
| `epoch_size = 100` | Seed list (1234–1243 or competition-specific) |
| `prior_alpha = prior_beta = 1.0` | |
| Bernoulli `compute_bandit_success` update | |
| 8-kind taxonomy (until Pro §11 sequence completes) | |

**Philosophy of freezing:** IV.POS.7 spent 50 runs × 6000 mutations to show V5 beats V1 on Pro’s criteria. Pro’s explicit instruction was **“freeze the current result; do not tune the bandit further as the main path.”** Competition fairness requires a **fixed policy**, not per-target hyperparameter tuning that overfits one guest.

Hyperparameters encode **fairness policy** (how much floor vs adaptive), not guest-specific magic numbers. The guest-specific part is the **arm universe** (which $(\mathit{kind}, \mathit{zone})$ pairs exist and how many steps each contains).

### What you would *not* freeze without a new ablation

- `coverage_floor_fraction` (0.55) — trades exploration breadth vs TS refinement; IV.POS.8-style sensitivity sweeps are the right way to move this, not ad-hoc per competition.
- Mutation-kind expansion (`TXN_PREV_*`, etc.) — Pro §11: add kinds **after** selector is stable, then re-ablate.
- Reward weights in v2 — logged only for V5 TS; changing them does not affect V5 selection today, but would break cross-campaign comparability in telemetry.

### A4 vs arguzz (V6) — different animals

| | **A4 V5 (`cTS_semantic_v2`)** | **arguzz (V6 internal baseline)** |
|---|---|---|
| Scheduler | Constrained TS over $(\mathit{kind}, \mathit{zone})$ | arguzz balanced round-robin (different design) |
| Mutation kinds | 8 A4 kinds | Additional arguzz-only kinds |
| Telemetry | `bandit_decisions`, `arm_state_snapshot`, floors | No bandit tables by design |
| IV.POS.7 role | **Protagonist** — 5/5 success criteria | **Exploratory negative control** (`INTERNAL_V0_V6_ANALYSIS.md`) |
| Competition stance | **Default A4 entry** after IV.POS.7 | Compare coverage/ranking; not a drop-in replacement for V5 |

**For a competition “A4 vs arguzz” narrative:** run both with **each tool’s native scheduler frozen at its validated defaults** — do not port V5 floors onto arguzz or arguzz kinds onto V5 without a new ablation. The comparison answers “structured constrained TS vs arguzz’s native search,” not “which hyperparameter set wins.”

### Recommended competition protocol (A4 side)

1. **Preflight:** `iv_pos_7_preflight`-style checks — host binary SHA, arm universe build, schema present.
2. **Pinned config:** `--selector cTS_semantic_v2`, `--telemetry-level full`, hyperparameters as in [Appendix A](#appendix-a--hyperparameters-v5-defaults).
3. **Per guest:** rebuild arm universe once; commit `EXPECTED_ARMS` row or generated arm count to competition packet.
4. **Seeds:** fixed public seed list (e.g. 10 seeds) — same as IV.POS.7 for continuity, or announce competition seeds in advance.
5. **Regression guard:** keep V1 (`zoned`) as calibration baseline on a subset of seeds (IV.POS.7 did this implicitly as C1–C5 reference).

### When to *unfreeze*

- New guest with materially different trace (recursion, different ECALL pattern) → rebuild universe; re-smoke on $N \leq 200$ before full campaign.
- IV.POS.8 (or successor) shows a floor fraction sweep beats 0.55 at same $N$ → protocol revision with documented ablation, not silent tweak.
- Pro Round 3 changes Bernoulli success definition → TS update changes; full re-ablation required.

---

## Appendix A — Hyperparameters (V5 defaults)

| Parameter | Value | Effect |
|---|---:|---|
| `prior_alpha`, `prior_beta` | 1.0 | Uniform Beta prior |
| `cold_start_pulls_per_arm` | 3 | → 144 cold mutations |
| `forced_singleton_pulls` | 5 | Singleton floor |
| `coverage_floor_fraction` | 0.55 | 55% of epoch budget → per-arm minimum |
| `epoch_size` | 100 | Floor counter reset period |
| `N` (campaign) | 6000 | IV.POS.7 protocol |

---

## Appendix B — Glossary

| Term | Meaning |
|---|---|
| **Arm** | `(mutation_kind, semantic_zone)` pair with ≥1 valid step |
| **Epoch** | Block of 100 mutations; floor quotas reset each epoch |
| **ITM** | `INSTR_TYPE_MOD` |
| **Local context** | One `constraint_loc` in legacy `coverage` table |
| **Bernoulli success** | 1 if any new local/global/structural discovery this mutation |

---

*End of guide.*
