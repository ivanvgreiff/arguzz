# Phase II.3 Detailed Implementation Plan: Discounted-UCB Bandit

This document is a **step-by-step, source-code-fact-based** plan for implementing **Phase II.3** (Discounted-UCB Bandit Scheduler). It implements the multi-armed bandit that uses the revised reward (Phase II.2R, verified in Phase II.2V) to adaptively schedule mutations.

**Rule**: No guesses. All statements are tied to file paths and code facts.

---

## 1. Prerequisites

### 1.1 What previous sub-phases delivered

| Sub-phase | Key deliverables | Files |
|-----------|-----------------|-------|
| II.0 | Baseline touch snapshot (1599 bitmap buckets, 1614 exact triples) | `baseline_touch.py` |
| II.1 | Arm universe: `ArmUniverse` class with `(kind, bucket) → [steps]` mapping, `pow2_clamp`, `B_count` derivation, `n_min` | `arm_universe.py` |
| II.1.5 | Pilot calibration: `CalibratedParams`, `calibrate_from_pilot`, `collect_pilot_stat` | `pilot_calibration.py` |
| II.2R | Revised reward: `CoverageState` with 5-component reward (T_new, T_rare, F_new, F_rare, Z) + revised Q (Q_dist × Q_rep) + weighted average; `compute_reward` / `update_state` with valid-run gating; baseline seeding | `coverage_state.py` |
| II.2V | Reward verified: 200-mutation campaign confirms reward variance across all 8 kinds (stdev 0.042–0.090), Z-events rewarded 2.7× higher, cascades suppressed | `run_diagnostic_campaign.py`, `PHASE_II_2V_IMPLEMENTATION_REPORT.md` |

### 1.2 What Phase II.3 implements

A new `DiscountedUCBScheduler` class that:

1. Selects an arm `(mutation_kind, step_bucket)` using Discounted-UCB
2. Selects a step within that arm using a nested Discounted-UCB
3. Receives reward feedback and updates its statistics
4. Handles forced exploration (n_min = 1)

### 1.3 What Phase II.3 does NOT do

- Does NOT modify `coverage_state.py`, `pilot_calibration.py`, or `arm_universe.py`
- Does NOT modify `fuzzer.py` (campaign loop integration is Phase II.4)
- Does NOT modify any C++ code
- Does NOT implement mutation value generation changes (p_local is deferred to II.5)

---

## 2. Source-of-Truth: Bandit Specification

The bandit specification is spread across Pro_Report_4 §7–8–10, Pro_Report_5 §11.1 D, and Pro_Report_7 §H–I. This section consolidates all specifications into a single authoritative reference.

### 2.1 Action space (from Pro_Report_4 §4, already implemented in arm_universe.py)

- Arms: `a = (k, b)` where k = mutation kind, b = step bucket index
- Available arms: `S_{k,b} ≠ ∅` (arm_universe.py `available_arms`)
- Steps within arm: `arm_universe.steps_in_arm(kind, bucket)` returns `List[int]`

From the II.2V campaign with N=1000: T=3930, B_count=32, 254 arms, avg 3.9 samples/arm.

### 2.2 Discounted-UCB over arms (Pro_Report_4 §7, Pro_Report_7 §H)

#### Per-arm state

For each arm `a = (k, b)`, maintain:
- `N_a`: discounted count (float, starts at 0)
- `S_a`: discounted reward sum (float, starts at 0)
- `t_a`: last update iteration (int, starts at 0)

#### Lazy decay (Pro_Report_4 §7.1)

At global iteration `t`, when accessing arm `a`:

```
N_a ← γ^(t - t_a) × N_a
S_a ← γ^(t - t_a) × S_a
t_a ← t
```

This avoids iterating over all arms every round.

#### Mean reward (Pro_Report_4 §7.1)

```
μ_a = S_a / max(N_a, ε)
```

#### UCB index (Pro_Report_4 §7.2)

Let `N_tot = Σ_a N_a` over all available arms (after lazy decay).

```
UCB(a) = μ_a + c × sqrt(log(1 + N_tot) / max(N_a, ε))
```

#### Selection rule

1. **Forced exploration**: If any available arm has `N_a < n_min`, select it (break ties uniformly at random among tied arms).
2. **UCB selection**: Otherwise, select arm with highest `UCB(a)` (break ties uniformly at random).

### 2.3 Nested Discounted-UCB over steps (Pro_Report_4 §8.1, Pro_Report_7 §I)

Once arm `a = (k, b)` is selected, choose a step `s ∈ S_{k,b}` using the **same** Discounted-UCB structure.

#### Per-step state

For each `(kind, step)` pair, maintain:
- `N_{k,s}`: discounted count
- `S_{k,s}`: discounted reward sum
- `t_{k,s}`: last update iteration

#### Step-level UCB

Let `N_tot^{(k,b)} = Σ_{s ∈ S_{k,b}} N_{k,s}` (sum over steps in this bucket only, NOT global).

```
UCB_step(s) = μ_{k,s} + c_s × sqrt(log(1 + N_tot^{(k,b)}) / max(N_{k,s}, ε))
```

#### Step-level forced exploration

If any step in `S_{k,b}` has `N_{k,s} < n_min_s`, select it.

### 2.4 Parameters (consolidated from Pro_Report_5 §11 + Pro_Report_7)

| Parameter | Value | Source | Where |
|-----------|-------|--------|-------|
| γ | Derived: `2^(-1/H)`, `H = clamp(N//5, 50, 300)` | Pro_Report_5 §11.1 D(20) | `CalibratedParams.gamma` (already exists) |
| c | 0.25 | HARD (Pro_Report_7 §H) | `CalibratedParams.c_explore` (already exists) |
| ε | 1e-6 | HARD (Pro_Report_4 §7.1) | Constant in bandit.py |
| n_min | 1 | HARD (Pro_Report_7 §2) | `ArmUniverse.n_min` (already computed) |
| γ_s | Same as γ | Pro_Report_7 §I | Use `CalibratedParams.gamma` |
| c_s | Same as c | Pro_Report_7 §I | Use `CalibratedParams.c_explore` |
| n_min_s | 1 | Pro_Report_7 §I | Same as arm-level |

### 2.5 Update protocol (Pro_Report_4 §7 + coverage_state.py contract)

After each run, the full update sequence is:

```
1. scheduler.select()                → (kind, step)
2. execute mutation                  → MutationExecutionResult
3. compute_reward(bitmap, failures, exit_code, outcome, proof_generated, state) → (reward, diag)
4. scheduler.update(kind, step, reward)   → updates arm + step bandit stats
5. update_state(bitmap, failures, exit_code, state)  → updates coverage state
```

**Critical**: `compute_reward` reads state BEFORE this run. `update_state` writes this run. The scheduler receives the reward from step 3.

### 2.6 Crash/invalid run handling (Pro_Report_7 §crash)

If crash or missing bitmap:
- `compute_reward` returns `(0.0, diag)` with mode="crash"
- The scheduler receives reward = 0.0 and updates its stats (so it learns to avoid crash-prone arms)
- `update_state` increments `total_runs` but does NOT update coverage frequencies

This is already implemented in `coverage_state.py` and does not need to change.

---

## 3. Source Code Context

### 3.1 Existing components the bandit must interface with

| Component | File | Interface |
|-----------|------|-----------|
| `ArmUniverse` | `arm_universe.py` | `.available_arms: List[(str, int)]`, `.steps_in_arm(kind, bucket) → List[int]`, `.n_min: int`, `.num_arms: int` |
| `CalibratedParams` | `pilot_calibration.py` | `.gamma: float`, `.c_explore: float` |
| `CoverageState` | `coverage_state.py` | `compute_reward(...)`, `update_state(...)`, `.seed_from_baseline(...)` |
| `ZonedStepSelector` | `step_selector.py` | `select_step(data, kind) → Optional[int]` — the EXISTING selector. The bandit will REPLACE this in Phase II.4. |
| `A4Fuzzer` | `fuzzer.py` | `run_campaign(num_mutations)` — the campaign loop. Will be modified in Phase II.4 to use the bandit. |

### 3.2 `CoverageGuidedSelector` stub

There is already a `CoverageGuidedSelector` stub in `step_selector.py` (lines 228-408). However, this stub follows a different architecture (zone-based + coverage history) and will NOT be used. The new `DiscountedUCBScheduler` is a standalone class in a new file `bandit.py`, not a StepSelector subclass.

**Rationale**: The bandit selects both kind AND step jointly (it picks arm = (kind, bucket), then picks step within bucket). The existing `StepSelector` interface only selects a step given a kind. The bandit's decision-making is fundamentally different.

---

## 4. Step-by-Step Implementation Plan

### Step II.3.1: Create `bandit.py` with `DiscountedUCBScheduler`

**Goal**: Implement the complete bandit scheduler as a standalone class.

**File**: `a4/standalone/bandit.py` (NEW)

**Class: `DiscountedUCBScheduler`**

Constructor arguments:
- `universe: ArmUniverse` — provides arm list and step lists
- `params: CalibratedParams` — provides γ, c_explore

Internal state:
- `t: int` — global iteration counter (starts at 0)
- `arm_N: Dict[Tuple[str, int], float]` — discounted count per arm
- `arm_S: Dict[Tuple[str, int], float]` — discounted reward sum per arm
- `arm_t: Dict[Tuple[str, int], int]` — last update iteration per arm
- `step_N: Dict[Tuple[str, int], float]` — discounted count per (kind, step)
- `step_S: Dict[Tuple[str, int], float]` — discounted reward sum per (kind, step)
- `step_t: Dict[Tuple[str, int], int]` — last update iteration per (kind, step)
- `rng: random.Random` — for tie-breaking

**Methods**:

#### `select(self) -> Tuple[str, int]`

Returns `(kind, step)`.

Algorithm:
1. Increment `self.t`
2. Apply lazy decay to all available arms: for each arm `a` in `universe.available_arms`, compute `N_a = γ^(t - t_a) × N_a` (only if `t_a < t`)
3. **Forced exploration (arm level)**: Collect all arms with `N_a < n_min`. If any, pick one uniformly at random.
4. **UCB selection (arm level)**: Compute `N_tot = Σ N_a`. For each arm, compute `UCB(a) = μ_a + c × sqrt(log(1+N_tot) / max(N_a, ε))`. Pick arm with highest UCB (break ties randomly).
5. Let chosen arm be `(kind, bucket)`.
6. Get `steps = universe.steps_in_arm(kind, bucket)`.
7. Apply lazy decay to all step states for steps in this bucket.
8. **Forced exploration (step level)**: Collect steps with `N_{k,s} < n_min_s`. If any, pick one randomly.
9. **UCB selection (step level)**: Compute `N_tot^{(k,b)} = Σ_{s ∈ steps} N_{k,s}`. For each step, compute step-level UCB. Pick step with highest UCB (break ties randomly).
10. Return `(kind, step)`.

**Implementation notes on lazy decay**:
- Lazy decay must be applied BEFORE reading N_a/S_a for UCB computation.
- When computing N_tot for the UCB exploration term, all arms must be decayed first. Since there are ≤ 254 arms (from our guest), iterating all is cheap.
- Step-level decay only iterates over steps in the chosen bucket (typically ~15 steps), which is trivially cheap.

#### `update(self, kind: str, step: int, reward: float) -> None`

Called after each run with the reward from `compute_reward`.

Algorithm:
1. Look up arm `(kind, bucket)` where `bucket = universe.bucket_for_step(step)`.
2. Update arm stats: `arm_N[a] += 1`, `arm_S[a] += reward`, `arm_t[a] = self.t`.
3. Update step stats: `step_N[(kind, step)] += 1`, `step_S[(kind, step)] += reward`, `step_t[(kind, step)] = self.t`.

**Important**: The update MUST happen at the current `self.t` (set during `select`), NOT at `t+1`. The select-then-update at the same `t` is the standard bandit protocol.

#### `summary(self) -> str`

Human-readable summary showing:
- Total iterations
- Top 10 arms by mean reward
- Bottom 10 arms by mean reward
- Number of arms with N_a > 0.5 (have been meaningfully explored recently)

#### `_decay_arm(self, arm: Tuple[str, int]) -> None`

Private helper: apply lazy decay to one arm.

```python
def _decay_arm(self, arm):
    dt = self.t - self.arm_t[arm]
    if dt > 0:
        decay = self.gamma ** dt
        self.arm_N[arm] *= decay
        self.arm_S[arm] *= decay
        self.arm_t[arm] = self.t
```

#### `_decay_step(self, key: Tuple[str, int]) -> None`

Private helper: apply lazy decay to one (kind, step) state.

Same structure as `_decay_arm` but using `step_N`, `step_S`, `step_t`.

---

### Step II.3.2: Unit tests for `DiscountedUCBScheduler`

**File**: `a4/standalone/tests/test_bandit.py` (NEW)

The following tests verify correctness without running the host binary:

#### Test 1: `test_forced_exploration`

Create a scheduler with a small universe (e.g., 3 arms, n_min=1). Call `select()` 3 times without calling `update()`. Verify that all 3 arms are selected (forced exploration ensures each is tried once).

#### Test 2: `test_lazy_decay`

Create a scheduler, select an arm, update with reward=1.0. Verify `arm_N[a] = 1.0`. Wait several iterations (call select/update on OTHER arms). Then check that `arm_N[a]` has decayed: `arm_N[a] ≈ γ^dt`.

#### Test 3: `test_ucb_exploits_best_arm`

Create scheduler with 3 arms. Update arm A with reward 0.5 (×5 times), arm B with reward 0.1 (×5 times), arm C with reward 0.3 (×5 times). Then call select() many times. Verify that arm A is selected most frequently (exploitation).

#### Test 4: `test_ucb_explores_unseen`

Create scheduler with 5 arms. Update 4 of them with rewards. Call select(). Verify the 5th (unsampled) arm is selected next due to high UCB exploration bonus.

#### Test 5: `test_step_level_selection`

Create scheduler where one arm has 3 steps. Update step 0 with high reward, step 1 with low reward, step 2 not at all. Call select() when this arm is chosen. Verify step 0 or step 2 is selected (step 0 for exploitation, step 2 for forced exploration).

#### Test 6: `test_discount_forgets_old_rewards`

Create scheduler, give arm A high reward early, then give arm B high reward later. After enough iterations, the discount should make arm B preferred over arm A (forgetting the old high reward).

#### Test 7: `test_crash_reward_updates`

Update an arm with reward=0.0 (crash). Verify it's reflected in the arm's mean (lowered). Verify the bandit avoids this arm in subsequent selections (lower UCB).

#### Test 8: `test_n_tot_uses_decayed_counts`

Verify that N_tot in the UCB formula is computed from DECAYED counts, not raw cumulative counts.

#### Test 9: `test_step_n_tot_scoped_to_bucket`

Verify that the step-level N_tot only sums steps within the selected bucket, not all steps globally.

#### Test 10: `test_deterministic_with_seed`

Create two schedulers with the same seed, same universe. Run the same sequence of select/update calls. Verify identical arm/step selections.

---

### Step II.3.3: Synthetic integration test

**Goal**: Verify the full select → reward → update loop works end-to-end with synthetic rewards (no host execution).

**Test**: `test_synthetic_campaign`

1. Create `ArmUniverse` from real `InspectionData` (using test fixture).
2. Create `CalibratedParams` with default values.
3. Create `CoverageState(params)` and `DiscountedUCBScheduler(universe, params)`.
4. Run 50 iterations:
   - `(kind, step) = scheduler.select()`
   - Generate synthetic reward based on kind (e.g., INSTR_TYPE_MOD → reward~0.15, others → reward~0.08)
   - `scheduler.update(kind, step, reward)`
5. Verify:
   - All 50 iterations completed without error
   - The scheduler summary shows INSTR_TYPE_MOD arms with higher mean reward
   - At least 10 distinct arms were explored

---

## 5. Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `a4/standalone/bandit.py` | **CREATE** | `DiscountedUCBScheduler` class |
| `a4/standalone/tests/test_bandit.py` | **CREATE** | Unit tests (10 tests + 1 integration test) |

No modifications to existing files.

---

## 6. Alignment with Master Plan

| Master plan reference | Phase II.3 coverage | Notes |
|----------------------|---------------------|-------|
| §4: "Unchanged from original. Discounted-UCB with lazy decay, forced exploration, nested step-level selection" | Steps II.3.1–II.3.3 | Fully covered |
| §5 II.3: "Implement after II.2V confirms reward is working" | II.2V complete, all 4 criteria PASS | Precondition met |
| Pro_Report_4 §7.1: Discounted statistics with lazy decay | `_decay_arm`, `_decay_step` | Exact implementation of the lazy decay formula |
| Pro_Report_4 §7.2: UCB index and selection | `select()` method | Exact implementation of UCB(a) formula |
| Pro_Report_4 §7.2: Forced exploration | `select()` method (step 3) | n_min=1 per Pro_Report_7 |
| Pro_Report_4 §8.1: Nested step-level bandit | `select()` method (steps 6-9) | Same structure, scoped N_tot |
| Pro_Report_7 §H: γ=0.995, c=0.25, ε=1e-6, n_min=1 | Via CalibratedParams | γ derived from budget; c, n_min already exist |
| Pro_Report_7 §I: γ_s=γ, c_s=c, n_min_s=1 | Step-level uses same params | Single parameter set for both levels |
| Pro_Report_4 §10.1: Data structures | arm_N/S/t, step_N/S/t dicts | Dict-based for simplicity (254 arms is tiny) |
| Pro_Report_7 §crash: Bandit gets reward=0 for crash | Via compute_reward (already returns 0) | No bandit-side change needed |

### Deviations from master plan

1. **`DiscountedUCBScheduler` is a standalone class, not integrated into `StepSelector` hierarchy**: The existing `StepSelector` abstract class has a `select_step(data, kind)` interface that presupposes the kind is already chosen. The bandit selects kind AND step jointly. Making the bandit a `StepSelector` subclass would require an awkward API where the "kind" parameter is ignored. A standalone class with `select() → (kind, step)` is cleaner and more truthful to the bandit's architecture. **Phase II.4** will wire this into the fuzzer's campaign loop.

2. **`CoverageGuidedSelector` stub is NOT used**: The existing stub in `step_selector.py` follows a different architecture (zone-based + coverage history tracking). The bandit replaces this conceptually. The stub will be removed or deprecated in Phase II.4.

3. **No modification to `ArmUniverse` or `CalibratedParams`**: Both already provide exactly what the bandit needs. `ArmUniverse.n_min` is already computed. `CalibratedParams.gamma` and `.c_explore` already exist with the correct values.

---

## 7. Dependencies for Phase II.4 (reminders)

Phase II.4 (Campaign Loop Integration) will:

1. Modify `fuzzer.py` to replace `ZonedStepSelector` with `DiscountedUCBScheduler` when coverage-guided mode is enabled
2. Add baseline seeding (`CoverageState.seed_from_baseline`) before pilot runs
3. Add pilot calibration phase (N_pilot runs) before switching to bandit selection
4. Wire `compute_reward` → `scheduler.update` → `update_state` into the campaign loop
5. Log per-run bandit diagnostics (selected arm, UCB scores, reward)

The bandit class created in Phase II.3 must have a clean enough API that Phase II.4 integration is straightforward.

---

## 8. Design Decisions and Rationale

### 8.1 Why dicts for bandit state (not arrays)?

Arms and steps are identified by tuples `(str, int)`. Using dicts keyed by these tuples is natural and avoids maintaining index mappings. The arm count (254) and step count (~3930) are small enough that dict overhead is negligible. This is consistent with how `CoverageState.fail_freq` already uses dicts.

### 8.2 Why lazy decay (not eager per-round decay)?

Eager decay would require iterating all arms (254) and all steps (~3930) every round. Lazy decay only touches the arms/steps that are accessed. In practice, `select()` must decay all 254 arms (to compute N_tot), so the arm-level saving is modest. But step-level saving is significant: we only decay the ~15 steps in the chosen bucket, not all 3930 steps.

### 8.3 Why tie-breaking with RNG (not arbitrary)?

UCB tie-breaking affects exploration behavior. Using the seeded RNG ensures deterministic campaigns (important for reproducibility) while avoiding bias from dict ordering or arm indexing.

### 8.4 Why n_min = 1 (not higher)?

Pro_Report_7 explicitly recommends n_min=1 because discounting already causes old observations to decay. If n_min=2, then arms whose counts decay below 2 would be forced-explored again, turning the campaign into a near-uniform sampler. With n_min=1, an arm needs only one "recent enough" observation to avoid forced exploration.

### 8.5 Why step-level N_tot is bucket-scoped (not global)?

Pro_Report_7 §I shows `N_tot^{(k,b)}` — the exploration bonus at the step level should reflect how well-explored THIS bucket's steps are, not all steps globally. If N_tot were global, a well-explored bucket A would inflate the exploration bonus for an unrelated bucket B, which is wrong.

---

## 9. Completion Checklist

- [ ] Step II.3.1: `bandit.py` created with `DiscountedUCBScheduler` (select, update, summary, lazy decay)
- [ ] Step II.3.2: `test_bandit.py` created with 10 unit tests + 1 synthetic integration test
- [ ] Step II.3.3: All tests pass
- [ ] No changes to existing files (coverage_state.py, pilot_calibration.py, arm_universe.py, fuzzer.py)

---

## 10. For Anyone New: What Phase II.3 Is and Why

### What

Phase II.3 implements a **Discounted-UCB multi-armed bandit scheduler** — the core intelligence that decides *which mutation to try next* during a fuzzing campaign. Instead of choosing mutation kinds and steps randomly (which is what the fuzzer does today), the bandit learns from each mutation's reward and steers future mutations toward regions of the search space that are most productive.

### Why

The fuzzer has 8 mutation kinds and ~3930 valid steps across 32 step buckets, giving 254 possible "arms" to pull. Random selection wastes mutations on arms that have stopped producing useful signal. The bandit:

- **Exploits**: concentrates on arms that produce high reward (new/rare coverage, novel failure contexts)
- **Explores**: tries under-sampled arms to discover if they're valuable
- **Adapts**: uses discounting to forget old rewards as the coverage landscape changes

### Why Discounted-UCB specifically

The reward is **non-stationary**: early in a campaign, many mutations produce novel coverage (high reward), but this novelty decays as more coverage is discovered. Standard UCB would over-commit to arms that were good early but have become mediocre. Discounted-UCB implements "forgetting" via an exponential discount factor γ, so the bandit tracks the *current* value of each arm.

### How it differs from other phases

| Phase | What it builds | Nature |
|-------|---------------|--------|
| II.2R | The reward function (what signal the bandit sees) | Mathematical formula |
| II.2V | Verification that the reward has meaningful variance | Diagnostic / analysis |
| **II.3** (this) | **The bandit itself (the brain that uses the reward to make decisions)** | **Algorithm / data structure** |
| II.4 | Wiring the bandit into the fuzzer's campaign loop | Integration / plumbing |

Phase II.3 is a **pure algorithm implementation** — it creates the decision-making engine in isolation, with no side effects on the fuzzer. Phase II.4 then plugs this engine into the real campaign.

---

## 11. New and Withheld Sections

**Sections retained**: All standard sections (Prerequisites, Source-of-Truth, Implementation Steps, Files, Alignment, Dependencies, Completion Checklist, For Anyone New).

**New sections**: 
- **§2 Source-of-Truth: Bandit Specification**: Added because the bandit specification is distributed across 3 Pro Reports. Consolidating it here ensures the implementation has a single authoritative reference. Previous plans didn't need this because their specifications were contained in one or two sections of one report.
- **§3 Source Code Context**: Added because Phase II.3 must interface with multiple existing components (`ArmUniverse`, `CalibratedParams`, `CoverageState`, `StepSelector`). Understanding these interfaces is essential for correct implementation.
- **§8 Design Decisions and Rationale**: Added because the bandit has several non-obvious architectural choices (dicts vs arrays, lazy vs eager decay, tie-breaking, n_min justification, N_tot scope) that deserve explicit rationale.

**Sections withheld**: None.

---

*End of Phase II.3 Implementation Plan.*
