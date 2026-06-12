# Phase II.5a — Scheduler Fix Implementation Plan

Per Pro_Report_9: the bandit's UCB branch is dead code because forced exploration uses decayed N (which always falls below n_min=1.0 due to gamma discount). Fix: replace n_min-based forced exploration with raw-pull-count cold-start.

---

## Steps (from Pro_Report_9 §5)

| Step | What | Effort | Time |
|------|------|--------|------|
| **1** | Fix scheduler: cold-start via raw pull counts + selection mode logging | Medium | ~30 min |
| **2** | Simulation validation: verify UCB fires, pulls non-uniform, positive reward-pull correlation | Small | ~5 min |
| **3** | Rerun A/B: uniform 1000 (reuse existing) + bandit 1000 with B_count=16 + fixed scheduler | Campaign | ~6 hours |
| **4** | Update boss notebook with new data + "Bandit Health Check" section | Medium | ~30 min |

---

## Step 1: Fix the Scheduler

### 1.1 Changes to `bandit.py`

**`__init__`** (lines 48-79): Add raw pull counters.

Current:
```python
self.n_min = universe.n_min
```

Change to:
```python
# Raw pull counts for cold-start (never decayed)
self.arm_m: Dict[Tuple[str, int], int] = {}
for arm in universe.available_arms:
    self.arm_m[arm] = 0

self.step_m: Dict[Tuple[str, int], int] = {}
for arm in universe.available_arms:
    kind, bucket = arm
    for s in universe.steps_in_arm(kind, bucket):
        self.step_m[(kind, s)] = 0

# Selection mode counters (for logging)
self.stats_coldstart_arm: int = 0
self.stats_ucb_arm: int = 0
self.stats_coldstart_step: int = 0
self.stats_ucb_step: int = 0
```

Remove `self.n_min = universe.n_min` (no longer used).

**`select()`** (lines 121-170): Replace n_min-based forced exploration with cold-start.

Current arm-level (lines 135-147):
```python
under_explored = [a for a in arms if self.arm_N[a] < self.n_min]
if under_explored:
    chosen_arm = self.rng.choice(under_explored)
else:
    # UCB selection
```

Change to:
```python
cold_start = [a for a in arms if self.arm_m[a] == 0]
if cold_start:
    chosen_arm = self.rng.choice(cold_start)
    self.stats_coldstart_arm += 1
else:
    # UCB selection
    self.stats_ucb_arm += 1
```

Current step-level (lines 157-168):
```python
under_explored_steps = [s for s in steps if self.step_N[(kind, s)] < self.n_min]
if under_explored_steps:
    chosen_step = self.rng.choice(under_explored_steps)
else:
    # Step-level UCB
```

Change to:
```python
cold_start_steps = [s for s in steps if self.step_m[(kind, s)] == 0]
if cold_start_steps:
    chosen_step = self.rng.choice(cold_start_steps)
    self.stats_coldstart_step += 1
else:
    # Step-level UCB
    self.stats_ucb_step += 1
```

**`update()`** (lines 172-196): Increment raw pull counts.

After `self.arm_N[arm] += 1.0` (line 188), add:
```python
self.arm_m[arm] += 1
```

After `self.step_N[step_key] += 1.0` (line 194), add:
```python
self.step_m[step_key] += 1
```

**`summary()`** (lines 207-236): Add selection mode stats.

Add after the first line:
```python
total_sel = self.stats_coldstart_arm + self.stats_ucb_arm
if total_sel > 0:
    lines.append(f"  Arm selections: {self.stats_coldstart_arm} coldstart "
                 f"({self.stats_coldstart_arm/total_sel*100:.0f}%) + "
                 f"{self.stats_ucb_arm} UCB ({self.stats_ucb_arm/total_sel*100:.0f}%)")
total_step = self.stats_coldstart_step + self.stats_ucb_step
if total_step > 0:
    lines.append(f"  Step selections: {self.stats_coldstart_step} coldstart + "
                 f"{self.stats_ucb_step} UCB")
```

### 1.2 Changes to `arm_universe.py`

`n_min` is no longer consumed by the bandit. We can keep the field for backward compatibility but it's unused. No changes required — the bandit simply won't reference `universe.n_min` anymore.

### 1.3 Changes to `test_bandit.py`

Tests that reference `n_min` or "forced exploration" behavior need updating:
- `test_all_arms_explored_first`: Should still pass — cold-start (m=0) achieves the same initial behavior as n_min-based forced exploration.
- Tests checking `self.n_min`: Replace with checks on `self.arm_m`.
- Add a NEW test: `test_ucb_fires_after_coldstart` — verify that after all arms are pulled once, subsequent selections use UCB (stats_ucb_arm > 0).

### 1.4 Confidence: 100%

All changes are to `bandit.py` only (plus tests). The fix is exactly what Pro_Report_9 §2.2 specifies. No ambiguity.

---

## Step 2: Simulation Validation

### 2.1 Simulation script

Run the same simulation as in Pro_Report_9_Input but with the fixed logic. Verify:

1. **Cold-start completes** after exactly `num_arms` rounds (each arm pulled once)
2. **UCB fires** for all subsequent rounds
3. **Pull counts become non-uniform** under a synthetic reward landscape (e.g., arm 0 always returns reward=0.5, all others return 0.05)
4. **Correlation(mean_reward, pulls) > 0** after sufficient rounds

This can be done in pure Python, no RISC Zero binary needed.

### 2.2 What to check

```python
# After fixing bandit.py, create a scheduler with 128 arms and run 1000 rounds
# with synthetic rewards: high-reward arms should get more pulls.

scheduler = DiscountedUCBScheduler(universe, params, seed=42)

# Run 1000 rounds
for t in range(1000):
    kind, step = scheduler.select()
    # Assign reward based on arm identity
    arm = (kind, scheduler.universe.bucket_for_step(step))
    reward = 0.5 if arm in top_arms else 0.05
    scheduler.update(kind, step, reward)

# Check:
# 1. stats_coldstart_arm == num_arms (cold-start exactly once per arm)
# 2. stats_ucb_arm == 1000 - num_arms
# 3. Top arms have more pulls than bottom arms
```

### 2.3 Confidence: 100%

This is a deterministic test that runs in seconds.

---

## Step 3: Rerun A/B

### 3.1 Uniform baseline

**Reuse existing** `uniform_1000_output.txt` and `uniform_baseline_1000.db`. No need to rerun — the uniform campaign doesn't use the bandit.

### 3.2 Fixed bandit with B_count=16

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host workspace/output/target/release/risc0-host \
    --num 1000 \
    --selector bandit \
    --b-count 16 \
    --seed 777 \
    --kind all \
    --db bandit_16_fixed_1000.db \
    -- --in1 5 --in4 10 \
    2>&1 | tee bandit_16_fixed_1000_output.txt
```

With B_count=16: ~128 arms, ~128 cold-start rounds, ~818 UCB rounds. The summary output should show ~87% UCB selections.

### 3.3 Confidence: 95%

The 5% uncertainty is about whether the reward signal is strong enough to produce visible exploitation at 128 arms and 1000 mutations. Pro_Report_9 expects it will, but the empirical result may show only modest exploitation if the reward landscape is noisy.

---

## Step 4: Update Boss Notebook

### 4.1 Add "Bandit Health Check" section (Pro_Report_9 §4.1)

Three items before any coverage curves:

1. **Selection mode breakdown**: % cold-start vs UCB (arm + step level). Parse from summary output or add to the terminal output.
2. **Pull distribution histogram**: arm pull count histogram showing non-uniformity.
3. **Exploitation evidence**: scatter of arm mean reward vs pull count with Pearson r, computed in first half vs second half to show learning over time.

### 4.2 Fix uniform reward boxplot labels (Pro_Report_9 §4.2)

Change titles to:
- "Uniform (no scheduling): reward signal distribution by kind"
- "Bandit (scheduling): reward signal distribution by kind"
Add note: "Uniform computes reward only for analysis; it does not affect selection."

### 4.3 Add "high-quality run" cumulative curve (Pro_Report_9 §4.3)

New coverage metric: cumulative count of runs where `Q > 0.8` or `Z == 1`. This shows whether the bandit moves mass toward near-manifold behavior.

### 4.4 De-emphasize C_touch (Pro_Report_9 §4.4)

Touch coverage is dominated by INSTR_TYPE_MOD and saturates quickly. Keep it as a secondary metric or remove from the main comparison.

### 4.5 Narrative (Pro_Report_9 §5, Step 4)

1. "We built constraint-touch + constraint-fail observability."
2. "We defined a reward that prioritizes novelty/rarity + Z."
3. "Initial bandit had a forced-exploration trap (UCB was dead code)."
4. "We fixed it with principled cold-start design."
5. "Now we see exploitation: non-uniform arm pulls correlated with reward."

### 4.6 Confidence: 90%

The narrative depends on the fixed bandit actually showing exploitation (Step 3). If the reward signal is too noisy at 128 arms, we may need B_count=8 (64 arms) as a fallback.

---

## Files to Change

| File | Change |
|------|--------|
| `a4/standalone/bandit.py` | Add `arm_m`, `step_m` (raw pull counts). Replace `N < n_min` with `m == 0`. Add selection mode counters. Update `summary()`. Remove `n_min` reference. |
| `a4/standalone/tests/test_bandit.py` | Update forced-exploration tests. Add `test_ucb_fires_after_coldstart`. |
| `a4/notebooks/boss_presentation.ipynb` | Add health check section, fix labels, add high-quality runs curve, update narrative. |

---

## What NOT to Change

- **Reward function** (`coverage_state.py`): Working correctly. Do not touch.
- **Gamma derivation** (`pilot_calibration.py`): Keep gamma=0.9965 for now. Adjust only if exploitation doesn't show after fix.
- **Arm universe** (`arm_universe.py`): `n_min` field can stay for backward compat. Just don't use it in the bandit.
- **Fuzzer campaign loop** (`fuzzer.py`): No changes needed.
