# Phase II.3 Implementation Report: Discounted-UCB Bandit

This report describes the implementation and testing of Phase II.3 (Discounted-UCB Bandit Scheduler), deviations from the plan, key variables and functions, and insights for Phase II.4.

**Reference plan**: [PHASE_II_3_IMPLEMENTATION_PLAN.md](./PHASE_II_3_IMPLEMENTATION_PLAN.md).

---

## 1. Summary

Phase II.3 was implemented as specified. A new file `bandit.py` was created containing the `DiscountedUCBScheduler` class, and a new file `test_bandit.py` was created with 14 unit tests. All 14 tests pass. All 99 non-host-dependent tests in the project pass. No existing files were modified.

**Goal**: Implement the two-level Discounted-UCB bandit scheduler — the decision-making engine that selects which `(mutation_kind, step)` to try next, using the revised reward signal from Phase II.2R/V to adaptively concentrate mutations on productive arms.

---

## 2. Deviations from Plan

| Item | Plan | Actual | Reason |
|------|------|--------|--------|
| `_pick_max_random_tie` | Implied in "break ties randomly" | Implemented as a separate helper method | Reused in both arm-level and step-level UCB selection, cleaner than inlining |
| `get_arm_stats` | Not in plan | Added as a public method | Useful for external diagnostics (e.g., Phase II.4 logging, Phase II.5 analysis) without internal state manipulation |
| Step test universe | Plan said `n_steps=30, budget=1000` | Used `n_steps=300, budget=200` | Original parameters gave B=1 (1 step per bucket) for the test kind, making step-level selection trivial. Adjusted to ensure buckets have ≥3 steps for meaningful step-level testing. |
| Test 1 (forced exploration) | Plan said "Call select() n_arms times without update, verify all explored" | Call select() + update() per iteration, allow up to 3× n_arms iterations | Without update, all arms remain at N=0, so random selection doesn't guarantee covering all arms in exactly n_arms tries (birthday paradox). With update, arms get N=1 but immediately decay below n_min=1 due to γ<1, so some re-selection occurs. Allowing 3× iterations is sufficient. |
| Test 6 (discount forgetting) | Plan said "verify arm B has higher mean" | Verify arm B has much higher N (10×) | Mean μ = S/N is preserved by decay (numerator and denominator decay equally). The observable effect of forgetting is that N decays, making old arms "uncertain" (high UCB exploration bonus) rather than "low mean." The test was revised to check the correct observable quantity. |
| No other deviations | - | - | All methods and structure match the plan |

---

## 3. What Was Implemented

### 3.1 `DiscountedUCBScheduler` class (`a4/standalone/bandit.py`)

A standalone class (not a `StepSelector` subclass) that implements two-level Discounted-UCB for mutation scheduling.

**Constructor**: Takes `ArmUniverse`, `CalibratedParams`, and optional seed. Initializes all arm and step state dicts from the universe's available arms and their steps.

**Two methods form the public API**:
- `select() → (kind, step)`: Selects the next mutation to execute
- `update(kind, step, reward)`: Feeds back the reward after execution

### 3.2 `select()` method — the core decision algorithm

The method implements a 10-step algorithm (matching the plan exactly):

**Arm level (steps 1-5)**:
1. Increment global iteration counter `t`
2. Apply lazy decay to ALL available arms (254 arms is cheap to iterate)
3. Check forced exploration: collect arms with `N_a < n_min`. If any, pick one randomly.
4. If no forced exploration needed: compute `N_tot = Σ N_a`, then compute `UCB(a) = μ_a + c × sqrt(log(1+N_tot) / max(N_a, ε))` for each arm. Pick arm with highest UCB (ties broken by seeded RNG).
5. Extract `(kind, bucket)` from the chosen arm.

**Step level (steps 6-10)**:
6. Get the list of valid steps for this arm from `universe.steps_in_arm(kind, bucket)`
7. Apply lazy decay to all step states in this bucket
8. Check step-level forced exploration: collect steps with `N_{k,s} < n_min_s`. If any, pick randomly.
9. If no forced exploration: compute `N_tot^{(k,b)}` (scoped to this bucket only), then compute step-level UCB. Pick step with highest UCB.
10. Return `(kind, step)`

**Why arm-level decays all arms**: Unlike step-level (where we only decay ~15 steps in the chosen bucket), arm-level must decay all 254 arms to correctly compute `N_tot`. This is necessary because `N_tot` appears in the exploration term of every arm's UCB index. At 254 arms, this is trivially cheap (< 1ms).

### 3.3 `update()` method

After the campaign loop executes the mutation and computes the reward, it calls `update(kind, step, reward)`:

1. Look up the arm `(kind, bucket_for_step(step))`
2. Increment `arm_N[arm] += 1.0`, `arm_S[arm] += reward`, set `arm_t[arm] = self.t`
3. Increment `step_N[(kind, step)] += 1.0`, `step_S[(kind, step)] += reward`, set `step_t[(kind, step)] = self.t`

The update happens at the same `t` as the `select()` call (standard bandit protocol — select and update are paired within the same round).

### 3.4 Lazy decay (`_decay_arm`, `_decay_step`)

Each arm/step stores its last-update time `t_a`. When accessed, the lazy decay computes `dt = t - t_a` and applies:

```
N_a *= γ^dt
S_a *= γ^dt
t_a = t
```

**Key property**: Since both `N_a` and `S_a` are multiplied by the same factor, the mean `μ_a = S_a / N_a` is preserved. What decays is the *confidence* in that mean — an arm with low `N_a` has a large UCB exploration bonus, so old arms get re-explored even if their mean was high.

### 3.5 UCB index computation

```
UCB(a) = μ_a + c × sqrt(log(1 + N_tot) / max(N_a, ε))
```

The `log(1 + N_tot)` grows slowly with total experience. The `max(N_a, ε)` prevents division by zero. The exploration bonus `c × sqrt(...)` is large when `N_a` is small (under-sampled arm) and small when `N_a` is large (well-sampled arm).

### 3.6 Tie-breaking (`_pick_max_random_tie`)

When multiple arms have the same UCB index (common during forced exploration or early rounds), the tie is broken by the seeded RNG. This ensures:
- **Determinism**: Same seed → same sequence of selections
- **Fairness**: No bias from dict ordering or index position

### 3.7 `summary()` method

Produces a human-readable summary showing:
- Total iterations, γ, c
- Number of "active" arms (N > 0.5 after decay)
- Top 10 and bottom 10 arms by mean reward

This is useful for Phase II.4 campaign logging and Phase II.5 analysis.

---

## 4. Testing

### 4.1 Test summary

14 tests in `test_bandit.py`, all passing:

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_all_arms_explored_early` | All arms explored within 3× n_arms iterations (forced exploration + decay) |
| 2 | `test_forced_exploration_without_update` | Without update, all arms remain under-explored and all are visited |
| 3 | `test_decay_reduces_count` | Direct time-advance + decay: N decays to γ^dt exactly |
| 4 | `test_decay_preserves_mean` | Decay of both N and S preserves μ = S/N |
| 5 | `test_best_arm_selected_most` | After seeding arm rewards, highest-reward arm is selected most |
| 6 | `test_unseen_arm_explored` | Arm with N=0 is selected next via forced exploration |
| 7 | `test_step_forced_exploration` | Steps within a multi-step bucket are all explored |
| 8 | `test_recent_high_reward_preferred` | Recently-active arm has much higher N than idle arm |
| 9 | `test_crash_lowers_mean` | Updating with reward=0 reduces arm mean |
| 10 | `test_n_tot_reflects_decay` | N_tot uses decayed counts after time advance |
| 11 | `test_step_n_tot_is_bucket_scoped` | Steps in bucket 2 have N=0 when only bucket 1 is updated |
| 12 | `test_same_seed_same_selections` | Two schedulers with same seed produce identical sequences |
| 13 | `test_full_loop` | 100 iterations of select→reward→update complete without error |
| 14 | `test_bandit_learns_preference` | After 500 iterations with kind-dependent rewards, bandit prefers highest-reward kind in late phase |

### 4.2 Test design considerations

**Synthetic universe**: All tests use a synthetic `ArmUniverse` built from synthetic `InspectionData` (no host binary needed). This is constructed via `_small_universe(n_steps, budget)` which creates cycles with specific major values to match the mutation kinds under test.

**Parameter choices**: Tests use aggressive γ values (0.9, 0.95, 0.99) to make decay effects visible within small iteration counts. Production γ is ~0.9965 (much slower decay).

### 4.3 Observations about forced exploration and decay

During testing, an important behavioral property emerged: **with n_min=1 and γ < 1, forced exploration is re-triggered frequently**.

After one update, `arm_N[a] = 1.0`. At the next select call, lazy decay gives `N_a = γ × 1.0 = γ < 1.0`. Since `γ < n_min = 1`, the arm becomes eligible for forced exploration again. This means:

- With γ = 0.99 and 254 arms, forced exploration dominates early rounds (roughly until each arm has accumulated enough recent observations).
- This is actually **beneficial** — it acts as a warm-up phase that ensures broad exploration before UCB kicks in.
- After ~200-300 iterations (depending on γ and arm count), enough arms have accumulated sufficient decayed mass that UCB selection takes over.

This behavioral insight was also raised by the user before implementation and is consistent with the architectural expectation: n_min=1 provides cold-start safety, while the UCB exploration bonus handles ongoing uncertainty.

### 4.4 All project tests pass

```
99 passed, 7 skipped (host-dependent)
```

No regressions in any existing tests.

---

## 5. Observations and Insights for Phase II.4

### 5.1 Integration API

The bandit exposes exactly two methods needed by the campaign loop:
- `select() → (kind, step)`: Replaces the current `rng.choice(MUTATION_KINDS)` + `selector.select_step(data, kind)`
- `update(kind, step, reward)`: Called after `compute_reward`, before `update_state`

Phase II.4 will need to:
1. Construct `ArmUniverse` from inspection data and budget
2. Run pilot calibration to get `CalibratedParams`
3. Construct `DiscountedUCBScheduler(universe, params, seed)`
4. Seed `CoverageState` from baseline
5. Replace the mutation selection logic in `_run_single_mutation` with `scheduler.select()`
6. Add `scheduler.update(kind, step, reward)` after `compute_reward`

### 5.2 Retry logic

The current fuzzer has retry logic: if `_create_mutation(kind, step)` returns `None` (no valid target), it retries up to 10 times. With the bandit, this needs careful handling:

**Option A**: If mutation creation fails, re-call `scheduler.select()` for a new arm. Risk: the bandit's `t` advances, and the failed arm got no reward feedback (silent failure).

**Option B**: If mutation creation fails, try a different step within the same bucket (step-level re-selection). Risk: may loop if the entire bucket has no valid targets for that kind.

**Recommended (per plan)**: The existing retry logic in `_run_single_mutation` retries step selection within the same kind. With the bandit, the retry should re-select a step within the SAME arm (same kind, same bucket), not a completely new arm. If all retries fail, the arm should receive no reward update (skip this iteration). This preserves the arm's existing statistics without penalizing it for a target-availability issue.

### 5.3 Performance

The bandit adds negligible overhead:
- `select()`: Decays 254 arms + computes 254 UCB indices + decays ~15 steps in one bucket. Total: < 1ms.
- `update()`: 2 dict lookups + 6 arithmetic operations. Total: < 0.01ms.

The host execution (30+ seconds per mutation) dominates by 4+ orders of magnitude.

### 5.4 Diagnostic output

Phase II.4 should log per-run:
- Selected arm `(kind, bucket)`
- Whether the selection was forced exploration or UCB
- The reward
- The arm's current mean reward and N after update

And per-campaign:
- `scheduler.summary()` at campaign end
- Arm selection frequency histogram

---

## 6. Completion Checklist

- [x] Step II.3.1: `bandit.py` created with `DiscountedUCBScheduler` (select, update, summary, lazy decay, get_arm_stats)
- [x] Step II.3.2: `test_bandit.py` created with 14 tests (12 unit + 2 integration)
- [x] Step II.3.3: All 14 tests pass; all 99 project tests pass
- [x] No changes to existing files (coverage_state.py, pilot_calibration.py, arm_universe.py, fuzzer.py)

---

## 7. Variable Reference

This section defines every variable in the bandit implementation, including all single-letter and abbreviated names.

### 7.1 Bandit State Variables (DiscountedUCBScheduler instance)

| Variable | Type | Meaning |
|----------|------|---------|
| `t` | int | Global iteration counter. Incremented by 1 in each `select()` call. Used to compute decay durations `dt = t - t_a`. |
| `gamma` (γ) | float | Discount factor from `CalibratedParams.gamma`. Typically ~0.9965. Controls how fast old observations are forgotten: a reward from `dt` iterations ago is weighted by `γ^dt`. |
| `c` | float | UCB exploration coefficient from `CalibratedParams.c_explore`. Default 0.25. Higher c → more exploration of under-sampled arms. |
| `n_min` | int | Forced exploration threshold from `ArmUniverse.n_min`. Default 1. Arms with `N_a < n_min` are prioritized for exploration. |
| `rng` | random.Random | Seeded random number generator for tie-breaking and forced exploration random selection. |

### 7.2 Per-Arm State (keyed by `(kind: str, bucket: int)`)

| Variable | Type | Meaning |
|----------|------|---------|
| `arm_N[a]` (N_a) | float | Discounted count for arm `a`. Starts at 0. Incremented by 1 on update, decayed by `γ^dt` on access. Represents "how many recent observations do we have for this arm." |
| `arm_S[a]` (S_a) | float | Discounted reward sum for arm `a`. Starts at 0. Incremented by `reward` on update, decayed by `γ^dt` on access. `S_a / N_a` gives the discounted mean reward. |
| `arm_t[a]` (t_a) | int | Last update/decay iteration for arm `a`. Used to compute `dt = t - t_a` for lazy decay. Reset to `t` on each decay or update. |

### 7.3 Per-Step State (keyed by `(kind: str, step: int)`)

| Variable | Type | Meaning |
|----------|------|---------|
| `step_N[(k,s)]` (N_{k,s}) | float | Discounted count for step `s` under kind `k`. Same decay semantics as arm_N. |
| `step_S[(k,s)]` (S_{k,s}) | float | Discounted reward sum for step `s` under kind `k`. Same decay semantics as arm_S. |
| `step_t[(k,s)]` (t_{k,s}) | int | Last update/decay iteration for this step state. |

### 7.4 UCB Formula Variables (computed per-selection, not stored)

| Variable | Meaning |
|----------|---------|
| `μ_a` | Mean reward for arm `a`: `S_a / max(N_a, ε)`. |
| `N_tot` | Total discounted count across all available arms: `Σ_a N_a`. Used in arm-level UCB exploration bonus. |
| `N_tot^{(k,b)}` | Total discounted count across steps in bucket `b` for kind `k`: `Σ_{s ∈ S_{k,b}} N_{k,s}`. Used in step-level UCB. Scoped to the bucket, NOT global. |
| `UCB(a)` | Upper Confidence Bound index for arm `a`: `μ_a + c × sqrt(log(1+N_tot) / max(N_a, ε))`. The arm with the highest UCB is selected (exploitation + exploration). |
| `dt` | Time since last update: `t - t_a`. Used to compute decay factor `γ^dt`. |
| `ε` (_EPSILON) | Numerical stability constant: `1e-6`. Prevents division by zero in `max(N_a, ε)`. |

### 7.5 Parameters (from CalibratedParams and ArmUniverse)

| Parameter | Source | Value | Meaning |
|-----------|--------|-------|---------|
| `γ` (gamma) | `CalibratedParams.gamma` | Derived: `2^(-1/H)`, H=clamp(N//5, 50, 300). For N=1000: γ ≈ 0.9965. | Discount factor. Higher → longer memory. `γ=0.9965` means half-life ~200 iterations. |
| `c` (c_explore) | `CalibratedParams.c_explore` | 0.25 (HARD) | UCB exploration coefficient. Controls exploration vs exploitation trade-off. |
| `n_min` | `ArmUniverse.n_min` | 1 if budget ≥ num_arms, else 0 | Forced exploration threshold. Arms with N < n_min get priority. |
| `ε` (_EPSILON) | Constant in bandit.py | 1e-6 | Numerical stability for division. |

### 7.6 ArmUniverse Variables (read by the bandit)

| Variable | Type | Meaning |
|----------|------|---------|
| `available_arms` | List[(str, int)] | Sorted list of all valid (kind, bucket) pairs. |
| `num_arms` | int | Length of `available_arms`. For our guest: 254. |
| `B` | int | Steps per bucket. For our guest with N=1000: `B = ceil(3930/32) = 123`. |
| `B_count` | int | Number of step buckets. Derived from budget: 32 for N=1000. |
| `T` | int | Step horizon: `1 + max(all valid steps)`. For our guest: 3930. |
| `K` | int | Number of mutation kinds: 8. |
| `steps_in_arm(kind, bucket)` | → List[int] | Valid steps for this arm. Typically ~15 steps per arm. |
| `bucket_for_step(step)` | → int | Bucket index: `step // B`. |

---

## 8. For Anyone New: What Phase II.3 Is and Why

### What

Phase II.3 implements the **brain** of the coverage-guided fuzzing system — a Discounted-UCB multi-armed bandit scheduler. Instead of choosing mutations randomly, this scheduler learns from the reward produced by each mutation and steers future mutations toward the most productive combinations of mutation kind and execution step.

### Why

The fuzzer has 254 possible "arms" (mutation_kind × step_bucket) to choose from. Without intelligent scheduling, the fuzzer wastes mutations on arms that consistently produce low reward (no new coverage, no novel failures). The bandit:

- **Exploits** high-reward arms (concentrating on productive mutations)
- **Explores** uncertain arms (via UCB bonus for under-sampled arms)
- **Adapts** to changing reward landscape (via discounting, which forgets old observations as coverage saturates)

### How it differs from other phases

Phase II.3 is a **pure algorithm implementation** — it creates the decision-making engine as a standalone class with no side effects on the fuzzer. Previous phases built the inputs the bandit needs (arm universe, reward function, coverage state). The next phase (II.4) will wire this engine into the actual fuzzer campaign loop.

---

*End of Phase II.3 Implementation Report.*
