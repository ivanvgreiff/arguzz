# Pro Report 9 Input: Bandit Architecture Diagnosis

We implemented a Discounted-UCB multi-armed bandit for coverage-guided fuzzing of RISC Zero (a zkVM). After running a 1000-mutation bandit campaign and comparing it against a 1000-mutation uniform-random baseline, **the results are virtually identical**. The bandit did not outperform random. We need you to diagnose why and recommend specific fixes.

---

## 1. The Problem in One Sentence

The bandit's Discounted-UCB selection logic **never fires**. 100% of all selections are forced exploration. The bandit is effectively a random selector.

---

## 2. Empirical Evidence

### 2.1 Campaign Results (1000 mutations each, same guest program, same seed)

| Metric | Uniform (random) | Bandit (254 arms) |
|--------|------------------|-------------------|
| Distinct failure contexts | 346 | 331 |
| Distinct constraint families | 33 | 36 |
| Z events | 104 | 99 |
| Mean reward | 0.0726 | 0.0742 |
| Crashes | 12 | 11 |

Kind selection is nearly identical (each kind at ~12.5% ± 1% in both campaigns). The bandit's kind distribution over time shows no exploitation trend — it fluctuates randomly.

### 2.2 Arm-level pull distribution (bandit campaign)

- 253 of 254 arms were pulled
- Pull distribution: min=1, p25=3, median=4, p75=4, max=6
- Pearson correlation between arm mean reward and pull count: r = 0.060 (essentially zero)

### 2.3 Simulation of forced exploration vs UCB

We simulated the `select()` method with the exact parameters used (gamma=0.9965, n_min=1.0, 254 arms, 946 bandit rounds):

| Configuration | Forced exploration % | UCB selection % |
|---------------|---------------------|-----------------|
| **Current: 254 arms, n_min=1.0, γ=0.9965** | **100%** | **0%** |
| 254 arms, n_min=0.5, γ=0.9965 | 88.6% | 11.4% |
| 254 arms, n_min=0.1, γ=0.9965 | 53.6% | 46.4% |
| 128 arms, n_min=1.0, γ=0.9965 | 74.7% | 25.3% |
| 64 arms, n_min=1.0, γ=0.9965 | 40.2% | 59.8% |
| 32 arms, n_min=1.0, γ=0.9965 | 19.9% | 80.1% |
| 2000 budget, 254 arms, n_min=1.0 | 100% | 0% |
| 10000 budget, 254 arms, n_min=1.0 | 100% | 0% |

**More budget does not help.** With n_min=1.0 and gamma=0.9965, UCB never fires regardless of budget size.

---

## 3. Root Cause Analysis

### 3.1 The forced-exploration trap

Here is the exact `select()` logic (from `bandit.py`):

```python
def select(self):
    self.t += 1
    
    # Decay ALL arms
    for arm in arms:
        self._decay_arm(arm)    # N_a *= gamma^(t - last_t)
    
    # Forced exploration: any arm with N_a < n_min gets priority
    under_explored = [a for a in arms if self.arm_N[a] < self.n_min]
    if under_explored:
        chosen_arm = random.choice(under_explored)
    else:
        # UCB selection (NEVER REACHED)
        chosen_arm = argmax(UCB_index)
```

And the `update()` logic:

```python
def update(self, kind, step, reward):
    arm = (kind, bucket)
    self.arm_N[arm] += 1.0    # N goes from decayed value to decayed + 1
    self.arm_S[arm] += reward
    self.arm_t[arm] = self.t
```

**The mechanism of the trap:**

1. Arm gets forced-explored. Before update, N_a was < 1.0 (e.g., 0.3).
2. After `update()`: N_a = 0.3 + 1.0 = 1.3. `arm_t = current_t`.
3. Next round: `select()` increments t, then decays: N_a = 1.3 × 0.9965 = 1.295. Still ≥ 1.0, so NOT forced-explored this round.
4. Round after that: N_a = 1.295 × 0.9965 = 1.291. Still ≥ 1.0.
5. After ~88 rounds with no pulls: N_a = 1.3 × 0.9965^88 ≈ 0.98 < 1.0. Forced-explored again.

But with 254 arms, each arm is only pulled every ~254 rounds on average. After 254 rounds without a pull: N_a = 1.3 × 0.9965^254 ≈ 0.55 < 1.0. So EVERY arm decays below n_min between pulls. The bandit perpetually cycles through forced exploration of all arms.

**The UCB selection branch (`else`) is dead code for these parameters.**

### 3.2 Why this wasn't caught earlier

- Pro_Report_7 recommended n_min=1 saying "higher values cause too much resampling under discounting." But n_min=1 combined with gamma < 1 causes 100% forced exploration.
- The test suite tested the bandit components in isolation (forced exploration works, UCB works, decay works) but never tested the system-level interaction where all arms perpetually decay below n_min.

---

## 4. The Reward Function (Working Correctly)

The reward function IS working — it differentiates mutation kinds with a 5x spread. The issue is purely in the scheduler, not the reward.

```
r = min(1, Q × S)

S = (a_Tn × T_new + a_Tr × T_rare + a_Fn × F_new + a_Fr × F_rare + a_Z × Z) / (sum of weights)

Q = Q_dist × Q_rep
Q_dist = exp(-d_fail / τ_d)
Q_rep = 1 if r_rep ≤ r_0, else exp(-(r_rep - r_0) / τ_r)
```

Mean rewards by kind (from the 1000-mutation bandit campaign):

| Kind | Mean reward | Primary driver |
|------|------------|---------------|
| INSTR_WORD_MOD_SUR | 0.154 | Z events (42.5% rate), high Q (0.808) |
| INSTR_WORD_MOD_FULL | 0.129 | Z events (39.7% rate), high Q (0.705) |
| INSTR_TYPE_MOD | 0.088 | Touch novelty (T_new=0.103), failure novelty (F_new=0.335), BUT low Q (0.307) |
| PRE_EXEC_REG_MOD | 0.055 | Moderate failure signal |
| COMP_OUT_MOD | 0.049 | Moderate failure signal |
| MEM_VAL_MOD | 0.049 | Moderate failure signal |
| LOAD_VAL_MOD | 0.032 | Low signal |
| STORE_OUT_MOD | 0.029 | Low signal |

Parameters:
- Weights: a_Tn=1.0, a_Tr=0.25, a_Fn=1.0, a_Fr=1.0, a_Z=1.0
- τ_T=35.0, τ_d=3.0, K_T_rare=31, τ_F_new=2.0, K_F_rare=2
- r_0=10, τ_r=25.0
- UCB c=0.25

---

## 5. The Arm Universe

- **8 mutation kinds** × **32 step buckets** = 256 possible arms (254 have valid steps)
- T (step horizon) = 3930, B (steps/bucket) = 123
- Each arm has ~15 valid steps on average
- `n_min = 1` (set to 1 when budget ≥ num_arms, else 0)

The arm universe is constructed once at campaign start and is static.

---

## 6. Gamma (Discount Factor) Derivation

```python
H = max(50, min(300, budget // 5))   # half-life in rounds
gamma = 2.0 ** (-1.0 / H)
```

For budget=1000: H = max(50, min(300, 200)) = 200, so gamma = 2^(-1/200) = 0.9965.

This means: every 200 rounds, an arm's N_a decays to 50% of its value. The purpose is to make the bandit "forget" old observations so it adapts to the non-stationary reward (novelty decays over time).

---

## 7. What We Want to Achieve

The bandit should:
1. **Explore initially** to build reward estimates for each arm
2. **Exploit** by preferring arms with higher estimated reward (e.g., spend more budget on INSTR_WORD_MOD_SUR which has 3-5x higher reward than STORE_OUT_MOD)
3. **Adapt** as the reward landscape changes (novelty decays, so early high-reward arms may become low-reward later)

Our goal is to **explore the constraint space more efficiently than uniform random** — discovering more distinct failure contexts, constraint families, and Z events per mutation budget.

---

## 8. Specific Questions for Diagnosis

1. **Is n_min the root cause?** Our simulation shows n_min=1.0 with gamma=0.9965 prevents UCB from ever firing. Is the fix simply lowering n_min, or is there a deeper design issue?

2. **Should n_min interact with gamma?** Perhaps n_min should be set dynamically based on gamma and the arm count, so that arms can "graduate" from forced exploration into UCB selection.

3. **Is the decay-on-select design correct?** Currently ALL arms are decayed every round (line 132-133: `for arm in arms: self._decay_arm(arm)`). This means even arms that were just pulled decay immediately in the next round. Should decay only apply to arms that were NOT selected?

4. **Is the number of arms (254) appropriate for budget 1000?** With 8 kinds and ~3.7 samples/arm, is the action space too fine-grained? Would coarser bucketing (e.g., 8 arms = 1 per kind, no step bucketing) be more appropriate at this budget?

5. **Should we use a different bandit algorithm entirely?** The Discounted-UCB was chosen for non-stationarity, but if the forced-exploration trap is a fundamental interaction issue, would Thompson Sampling, EXP3, or a simpler epsilon-greedy approach work better?

6. **Is the two-level (arm then step) structure adding value?** The step-level bandit has the same forced-exploration trap but worse (many more steps per bucket than arms total).

7. **What is the minimum fix to make the bandit functional?** We want the simplest change that enables UCB to actually fire while preserving the benefits of discounting for non-stationarity.

---

## 9. Full Source Code

### bandit.py (DiscountedUCBScheduler)

```python
class DiscountedUCBScheduler:
    def __init__(self, universe, params, seed=None):
        self.gamma = params.gamma       # 0.9965
        self.c = params.c_explore       # 0.25
        self.n_min = universe.n_min     # 1
        self.t = 0
        
        # Per-arm state
        self.arm_N = {arm: 0.0 for arm in universe.available_arms}   # discounted count
        self.arm_S = {arm: 0.0 for arm in universe.available_arms}   # discounted reward sum
        self.arm_t = {arm: 0 for arm in universe.available_arms}     # last update time
        
        # Per-step state (within each arm's bucket)
        self.step_N, self.step_S, self.step_t = {}, {}, {}
        for arm in universe.available_arms:
            kind, bucket = arm
            for s in universe.steps_in_arm(kind, bucket):
                self.step_N[(kind, s)] = 0.0
                self.step_S[(kind, s)] = 0.0
                self.step_t[(kind, s)] = 0

    def _decay_arm(self, arm):
        dt = self.t - self.arm_t[arm]
        if dt > 0:
            decay = self.gamma ** dt
            self.arm_N[arm] *= decay
            self.arm_S[arm] *= decay
            self.arm_t[arm] = self.t

    def select(self):
        self.t += 1
        arms = self.universe.available_arms
        
        # Decay all arms to current time
        for arm in arms:
            self._decay_arm(arm)
        
        # Forced exploration: pull any arm with N < n_min
        under_explored = [a for a in arms if self.arm_N[a] < self.n_min]
        if under_explored:
            chosen_arm = self.rng.choice(under_explored)
        else:
            # UCB selection
            n_tot = sum(self.arm_N[a] for a in arms)
            def arm_ucb(a):
                mu = self.arm_S[a] / max(self.arm_N[a], 1e-6)
                return mu + self.c * sqrt(log(1 + n_tot) / max(self.arm_N[a], 1e-6))
            chosen_arm = argmax(arm_ucb)
        
        kind, bucket = chosen_arm
        
        # Step-level selection (same structure: decay, forced explore, UCB)
        steps = self.universe.steps_in_arm(kind, bucket)
        for s in steps:
            self._decay_step((kind, s))
        under_explored_steps = [s for s in steps if self.step_N[(kind, s)] < self.n_min]
        if under_explored_steps:
            chosen_step = self.rng.choice(under_explored_steps)
        else:
            # Step-level UCB (scoped N_tot to this bucket)
            ...
        
        return kind, chosen_step

    def update(self, kind, step, reward):
        arm = (kind, self.universe.bucket_for_step(step))
        self.arm_N[arm] += 1.0
        self.arm_S[arm] += reward
        self.arm_t[arm] = self.t
        
        self.step_N[(kind, step)] += 1.0
        self.step_S[(kind, step)] += reward
        self.step_t[(kind, step)] = self.t
```

### Key parameter derivation

```python
# Gamma from budget
H = max(50, min(300, budget // 5))  # half-life
gamma = 2.0 ** (-1.0 / H)          # 0.9965 for budget=1000

# n_min from arm count
n_min = 1 if budget >= num_arms else 0   # always 1 for budget=1000, arms=254

# B_count from budget  
raw = budget // (K * N_TARGET)   # 1000 // (8 * 3) = 41
B_count = pow2_clamp(raw, 16, 128)  # 32
```

---

## 10. Context: What This System Does

This is a **constraint-coverage-guided fuzzer** for RISC Zero's zkVM. We mutate the post-execution trace (preflight data) of a RISC-V guest program — changing register values, memory values, instruction types, or instruction words at specific execution steps. Each mutation is fed back through the prover, and we observe which constraints fail. The goal is to find **underconstraints** (soundness bugs) where a mutation produces an invalid witness that the verifier still accepts.

The 8 mutation kinds target different aspects of the execution trace. The "step" dimension corresponds to which instruction in the program execution we mutate. Different steps have different constraint structures (e.g., arithmetic instructions vs memory operations vs control flow).

The bandit's job is to learn which (mutation_kind, step_region) combinations are most likely to produce interesting constraint-space exploration, and allocate more of the mutation budget to those productive arms.

---

## 11. What We Need From You

1. **Diagnose**: Confirm or correct our analysis of why the bandit is acting as a random selector.
2. **Recommend**: Specific parameter changes or code changes to make the bandit functional. We need changes that are simple, principled, and don't require a complete rewrite.
3. **Predict**: What results should we expect after the fix? How much better should the bandit perform vs uniform at 1000 mutations?
4. **Validate**: What test or simulation should we run to confirm the fix works BEFORE running a full 6-hour campaign?
