```Prompt
This prompt is split into two sections: 1) Main Prompt, 2) Context/Questions


# Section 1: Main Prompt

In your last answer you mentioned a lot of different techniques and options for our fuzzing architecture, and gave a general skeleton plan for implementing this. However, even though you did offer one specific recommendation, you still gave multiple other ones (incl. for the architecture which could allow for easier pen-and-paper analysis). However, now I want you to read through your previous answer and give me more concretely the exact architecture I should implement that is most likely to work (i.e. not overfit and maximizes chances of finding underconstraints). I want the most effective architecture possible so I am expecting you to do a lot of thinking and critical reasoning and base your arguments on facts from my ZIP file and well-reasoned research.

You spent most of your last output talking about different models and answering my questions, but this time I need you to critically reason and think through the model you recommended and actually choose every specific detail that remains left to be chosen and give a highly detailed and concrete architecture and high-level implementation plan which I can give to claude opus to transform into an actual source code level multi-phase implementation plan for me to then incrementally implement. I do not want you to give source code level details (unless highly useful), but rather focus on mathematical equations and specifications. If there is anything you do not specify, explain why and what must be done to complete those remaining specifications. 

You already have access to the PDF I uploaded along with the ZIP files which describe everything I have implemented so far, and you have to keep those in mind (reread them if it helps you) so that you know where I am, and what I have left to do. There are still a lot of variables and design choices left undecided. I want you to consider the data I have provided you as to how our fuzzing technique works and the sizes of the number of mutations and constraint touches I shared with you in making this decision. I am aware that you are not going to be able to provide specific values for every constant and parameter, but if you can, provide them, and if not, then include it in your implementation master plan as to what I should do with claude opus to figure out what those values should be (i.e. must I run experiments to make an educated estimation as to what my parameters should be?). 

Overall, I am mainly asking you to do two things:

1. Provide a concrete specification which defines as many things as you are able to define, explain why those are the best choices, and if there are still things which are better to-be-defined based on experiments/tests that I run in my RISC Zero fuzzing repo, then tell me what I should do and give guidance as to how to do them in order to finish up the entire architectural specification
2. Provide a master implementation plan (architectural level) which I can incrementally follow to implement the architecture which you think is most effective. Make sure that when you are choosing the architecture and the specifications around this architecture, that you have all the knowledge you need by reading our conversation and the ZIP file markdowns I provided. Again, if there are specific details which you deem are better defined by me after doing certain tests in the repo, let me know and give guidance. If you are able to confidently provide all specifications yourself and are confident that you have all the information you need to define everything, then do so.

Furthermore note that I plan on working with claude opus on the following (in the following order):
1. Implement the entire architecture for a fuzzing campaign working only on a single guest program with the same inputs and outputs
2. Figure out how to extract global constraint info and adapt the architecture to work with whatever we can extract (it is possible not all global constraint info is extractable)
3. Adapt the campaign to work with multiple guest programs with different inputs

Keep this in mind when structuring your implementation plan. I am guessing your implementation plan will mostly focus on "1. Implement the entire architecture for a fuzzing campaign working only on a single guest program with the same inputs and outputs".


# Section 2: Context/Questions

I do not want you to spend to much bandwidth answering these questions, nor too much of your output in providing detailed answers to these either if this takes away detail from your architectural specifications and implementation plan from section 1. The main thing I want you to focus on is in what I outlined in Section 1. This section is mostly to inform you of some of the remaining questions I have because it shows things which were left undefined by you. Keep these in mind when providing your report for section 1. These list out concerns that I have, so reason critically through these and make sure you provide an intelligent, well-reasoned decision regarding these questions/concerns, and make sure that you justify every detail regarding these concerns in your specification. Justification behind your specification decisions is very important, I need to know why we decide to do things the way we do, and if you decide against my inclinations, I need to understand why.

Context/Questions/Concerns behind what is not yet concretized:
1. Exact reward definition + weights
	- What is our rarity weighting formula, and do we apply it to touch, fail, or both
	- Is our reward counts or weighted sums or binary success?
2. What is the “coverage key” we actually use for touch?
	- Family vs context vs instance
	- Do we actually include lane, and what would it be?
	- Should lane go in here or not?
	- Should degenerate-case and other highly important cases go in here? I would think they should rather go into some other information process that values it rather than the coverage key since my first thought is that the coverage key should be a pure form that is 100% ensured to contain the info it must contain i.e. constraint loc, major/minor, because anything else I think might just add noise or put too much importance on things that are not the core thing we are searching for, but I am not sure.
3. What lanes should we choose?
	- Is PC even useful for distinguishing constraints? Wouldn't it just add noise?
	- I would think we would want to distinguish only among constraint types and major/minor, anything else I do not see how it helps us, especially if we begin doing campaigns among different guest programs with different inputs
	- I could see that step could be useful as we could (only when considering a campaign with one guest program and the same inputs) schedule mutations to over time concentrate within a certain step region that is deemed "interesting"
4. Should we use bucketing? You saw how many constraint failures and constraints touched we had, so wouldn't this just lose granularity unnecessarily?
	- If you are convinced we must use buckets, how do we choose the bucket size?
5. Regarding map size, should we not keep an exact set at the very least for debug on interesting runs? Also you saw how many constraints touched and failed we had in our test run (which is the normal guest program size and aspect we will be dealing with) so, here too, shouldn't we make it big enough for no collisions?
6. I could not list all the things we have not yet concretized, as this depends on the model and architecture we choose to implement next. Since in this prompt I ask you to decide on this architecture, make sure to also provide guidance (or actual specific values) on all variables/constants/etc 
```


---

Below is the **single concrete architecture** I think you should implement next (Phase II scheduling) that is (a) most likely to work in practice, (b) minimally “overfit” to one program while still being very effective for the single‑program campaign, and (c) cleanly extensible to global constraints + multi‑program later.

I’m going to be explicit about **every remaining design choice** you flagged: reward, rarity weighting, coverage key, lane/PC/step, bucketing, map size, collisions/debug, and the exact bandit structure.

---

# 0. What you already have (and what that implies)

From your Phase I docs/implementation:

- You now get a **touch bitmap per run** emitted from the prover/witgen path (via the `eqz` choke point). This is the right place to measure “touched” because it’s _post-gating_: if `eqz` is called for a constraint, that constraint was actually evaluated in that execution path.
    
- The touch map is an **AFL-style fixed bitmap** of size **MAP_SIZE = 65536** and is hashed on **(loc, major, minor)** (no step mixed in). You also verified an example run produced **1599 distinct buckets** and **192,676 total touches**. (This ratio also tells you counters are not that informative; the binary “touched vs not” signal will dominate.)
    
- Failure-only coverage is tiny: in a partial 24-mutation campaign you saw **K_total ≈ 43** distinct failing `(constraint_loc, major, minor)` contexts and per-mutation max distinct failures around 9. That means: **failure-coverage saturates extremely fast**; touch-coverage is the signal with the bandwidth you need.
    

So, for scheduling you should treat:

- **Touch** as the primary coverage signal,
    
- **Failures** as a _secondary_ signal (useful, but not the main driver),
    
- And you must plan for **touch novelty saturation**, otherwise a bandit reward becomes mostly zeros and stops learning.
    

---

# 1. Decide the “coverage key” (touch + fail)

## 1.1 Touch coverage key (what to use)

**Use exactly what your Phase I implementation already uses:**

[  
\textbf{TouchKey} := (\texttt{constraint_loc},\ \texttt{major},\ \texttt{minor})  
]

…and hash it into the bitmap.

**Do not include**:

- `pc` (too program-specific and noisy across multi-program),
    
- `step` (same),
    
- “lane” (unstable definition; also fragments the space and is likely to overfit),
    
- degenerate-case flags (use as _features_ for mutation selection, not as coverage keys).
    

**Why this is the best choice**

- It is _stable across builds_ and _stable across programs_ (constraint `.zir` loc + major/minor).
    
- It matches your current instrumentation.
    
- It keeps the coverage universe relatively small so MAP_SIZE=65536 isn’t instantly collision-saturated.
    
- Step/PC/lane can still be used to **choose where to mutate** (scheduler features) without polluting the coverage identity.
    

## 1.2 Failure coverage key

Keep your existing exact failure context ID:

[  
\textbf{FailKey} := (\texttt{constraint_loc},\ \texttt{major},\ \texttt{minor})  
]

Store as an _exact set_ (Python `set`) because it’s small and has zero collision ambiguity.

---

# 2. Bucketing: where it belongs and where it does NOT

## 2.1 Do NOT bucket the coverage key (touch)

You should not add `step_bucket` into the touch coverage key right now.

Reason: you already get plenty of touch signal (thousands of distinct buckets). Adding step bucket blows up the key space and will:

- increase collisions for MAP_SIZE=65536,
    
- and reduce generalization across multi-program.
    

## 2.2 DO bucket the _action space_ (scheduler)

Bucketing is extremely useful for reducing the learning problem.

Let (T) be total instruction steps in the trace. Define a step bucket size (B) and bucket index:

[  
b(s) = \left\lfloor \frac{s}{B} \right\rfloor,\quad b \in {0,\dots,B_{\text{count}}-1}  
]

Choose (B) so you get about 128 buckets:

[  
B := \text{round_to_power_of_two}\left(\left\lceil \frac{T}{128} \right\rceil\right)  
]

For typical traces (~20k steps), this will usually give **B = 128 or 256**, producing ~80–160 buckets. That’s a sweet spot.

**Key point:** bucketing here affects only **learning granularity** for the scheduler, not what “coverage” means.

---

# 3. The architecture you should implement

## 3.1 One sentence summary

Implement a **two-level scheduler**:

1. a **Discounted-UCB bandit** over **arms = (mutation_kind, step_bucket)**, using a reward that adapts from “new touch bits” to “rare touch bits” as novelty saturates;
    
2. within the chosen arm, choose a specific step by a cheap **nested-UCB (or ε-greedy)** over steps in that bucket for that mutation kind.
    

This is the highest ROI structure: it is simple, robust to nonstationarity, and will not collapse once novelty saturates.

---

# 4. Formal model

## 4.1 Action space

You already have a finite set of mutation kinds (k \in \mathcal{K}) (e.g., 8 kinds).

Let the trace have steps (s \in {0,\dots,T-1}).

For each kind (k), you have a set of valid target steps (S_k \subseteq {0,\dots,T-1}) from inspection.

Define buckets (b \in {0,\dots,B_{\text{count}}-1}). For each arm:

[  
a = (k,b)  
]

It’s **available** if:

[  
S_{k,b} := { s \in S_k : b(s) = b } \neq \emptyset  
]

So number of arms is at most (|\mathcal{K}| \cdot B_{\text{count}}) (typically 8 × ~128 = ~1024 arms), totally manageable.

---

## 4.2 Observations per run

Each run (t) produces:

- touch bitmap (X_t \in {0,\dots,255}^{M}) with (M=65536)
    
- touched index set:  
    [  
    U_t = { i : X_t[i] > 0 }  
    ]
    
- failure context set (exact):  
    [  
    F_t = {\text{FailKey}}  
    ]
    
- outcome (o_t \in {\text{ACCEPTED}, \text{REJECTED}, \text{CRASH}, ...})
    
- number of failures (n^{\text{fail}}_t := |F^{\text{instances}}_t|) (raw count) and/or number of distinct fail contexts (|F_t|)
    

(You already have all of this.)

---

# 5. Global state you should maintain during a campaign

You need three global coverage tracking structures:

## 5.1 Touch seen bitmap (boolean)

[  
G[i] \in {0,1},\quad G[i]=1 \iff \exists t': i \in U_{t'}  
]

Store as a Python `bytearray` or bitset (your existing `global_touch_bitmap` already plays this role if you treat `>0` as seen).

## 5.2 Touch frequency per bucket (for rarity)

[  
\text{freq}[i] = \sum_{t'} \mathbf{1}{i \in U_{t'}}  
]

Store as `array('I')` or `numpy.uint32` if you want speed; but plain Python lists of ints is also fine at 65536.

This is _not_ your current `max()` merged bitmap. Your current bitmap is useful for “seen”; but to do rarity properly you want **run-frequency**.

## 5.3 Failure frequency per FailKey

[  
\text{ffreq}[c] = \sum_{t'} \mathbf{1}{c \in F_{t'}}  
]

A dict keyed by `(constraint_loc, major, minor)`.

---

# 6. Reward definition (fully specified)

This is the main thing you asked to concretize. I’ll give you a reward that is:

- bounded (good for bandits),
    
- robust to novelty saturation,
    
- does not overfit to “garbage cascades”,
    
- and still aligns with the “malicious prover” viewpoint (coherence is treated as **execution quality / feedback completeness**, not “semantic realism”).
    

## 6.1 Core idea: switch from novelty to rarity when novelty saturates

Maintain a rolling window (e.g., last (W=50)) of `new_touch_count`.

Define:

[  
\Delta^{\text{new}}_t := |{ i \in U_t : G_{t-1}[i]=0 }|  
]

Define a saturation indicator:

[  
\text{sat}_t = \mathbf{1}\left{ \text{median}(\Delta^{\text{new}}_{t-W+1:t}) < 1 \right}  
]

So:

- If novelty is still happening, focus on novelty.
    
- If novelty has stalled, focus on “rare touched bits”.
    

### Why this matters

Your touch map will likely find new bits early, then quickly start returning 0 new bits. Without this switch, the bandit learns nothing after saturation.

## 6.2 Novelty score (bounded)

Use a smooth bounded transform:

[  
S^{\text{new}}_t := 1 - \exp\left(-\frac{\Delta^{\text{new}}_t}{\tau_{\text{new}}}\right)  
]

Suggested (\tau_{\text{new}} = 64).

Interpretation:

- 0 new bits → score 0
    
- ~64 new bits → ~0.63
    
- > > 64 new bits → saturates near 1
    

## 6.3 Rarity score (bounded, robust)

Define touch rarity weight using frequency _before_ updating with this run:

[  
w(i) := \frac{1}{\sqrt{1+\text{freq}_{t-1}[i]}}  
]

Now compute a run’s “rare touch” score by looking only at the **K rarest touched bits**, not all touched bits (this prevents “touch many common bits” from dominating):

Let (K_{\text{rare}} = 32). Let (R_t) be the set of indices in (U_t) with the **largest** (w(i)) (equivalently smallest freq), taking top (K_{\text{rare}}) (or fewer if (|U_t|<K)).

[  
S^{\text{rare}}_t := \frac{1}{K_{\text{rare}}}\sum_{i \in R_t} w(i)  
]

This is in (0,1], and strongly prefers runs that touch _rare_ buckets.

## 6.4 Failure novelty (secondary)

Failures are secondary, but still useful as a “you managed to exercise a check we hadn’t seen fail” signal.

Let:  
[  
\Delta^{\text{fail}}_t := |{ c \in F_t : \text{ffreq}_{t-1}[c]=0 }|  
]  
Then:  
[  
S^{\text{fail-new}}_t := 1 - \exp\left(-\frac{\Delta^{\text{fail}}_t}{\tau_{\text{fail-new}}}\right)  
]  
Suggested (\tau_{\text{fail-new}}=2).

## 6.5 Execution quality / coherence gating (minimal, not philosophically heavy)

This is where your “malicious prover can patch crashes” concern matters. The right framing is:

- We **do not** use coherence as “realism of a guest execution”.
    
- We use it as **feedback completeness**: do we get touch/fail info reliably? does the run progress far enough to be informative?
    

Define:

- If run is `CRASH` or touch bitmap missing: (Q_t = 0).
    
- Else define a soft penalty for “too many failures” (proxy for being way off-manifold / garbage cascade):
    

[  
Q_t := \exp\left(-\frac{n^{\text{fail}}_t}{\tau_{\text{fail-count}}}\right)  
]

Suggested (\tau_{\text{fail-count}} = 25).

This keeps you from aggressively chasing runs that produce enormous cascades of failures (which can otherwise inflate coverage signals in strange ways).

## 6.6 Final reward (bounded in [0,1])

Set weights:

- (\alpha = 1.0) for touch (primary)
    
- (\lambda = 0.2) for fail novelty (secondary)
    

Define the touch score depending on saturation:

[  
S^{\text{touch}}_t :=  
\begin{cases}  
S^{\text{new}}_t & \text{if } \text{sat}_t = 0 \  
S^{\text{rare}}_t & \text{if } \text{sat}_t = 1  
\end{cases}  
]

Then:

[  
r_t := \min\left(1,\ Q_t \cdot \frac{S^{\text{touch}}_t + \lambda S^{\text{fail-new}}_t}{1+\lambda}\right)  
]

**Special case:** if `ACCEPTED` (bug candidate), override:  
[  
r_t := 1  
]  
and push the configuration into a “bug queue” for local search/triage.

### Why this reward is the right tradeoff

- It starts by maximizing **true novelty** (AFL-like).
    
- Once novelty dries up, it continues optimizing toward **rare coverage** (AFLFast-like), which is crucial for reaching deep/rare constraint regimes.
    
- It does not require selectors from the DATA matrix (you already solved touch at the right layer).
    
- It doesn’t “overfit” to one program’s step/pc by baking step into coverage.
    
- It keeps the reward well-behaved for bandits.
    

---

# 7. Bandit model (fully specified)

Your environment is **non-stationary** because coverage novelty decays (a classic “rotting” effect). So plain UCB1 on cumulative means will over-commit based on early wins.

Implement **Discounted UCB** on the arms (a=(k,b)).

## 7.1 Discounted statistics

For each arm (a), store:

- discounted count (N_a)
    
- discounted reward sum (S_a)
    
- last update iteration (t_a)
    

At global iteration (t), when you need (N_a,S_a), lazily decay them:

[  
N_a \leftarrow \gamma^{(t-t_a)} N_a,\quad S_a \leftarrow \gamma^{(t-t_a)} S_a,\quad t_a \leftarrow t  
]

Suggested (\gamma = 0.995) (effective memory ~200 iterations).

Then mean:

[  
\mu_a = \frac{S_a}{\max(N_a,\epsilon)}  
]

## 7.2 UCB index and selection

Let (N_{\text{tot}} = \sum_a N_a) over available arms.

Define:

[  
\text{UCB}(a) = \mu_a + c \sqrt{\frac{\log(1+N_{\text{tot}})}{\max(N_a,\epsilon)}}  
]

Suggested (c = 0.25), (\epsilon=10^{-6}).

### Forced exploration

Before using UCB, ensure every available arm is sampled at least (n_{\min}) times recently:

- If (N_a < n_{\min}), prioritize it.
    
- Suggested (n_{\min}=2) or 3.
    

This avoids cold-start blindness.

---

# 8. Step selection inside an arm

Once you pick arm (a=(k,b)), you must choose a step (s \in S_{k,b}).

You have two reasonable options; I recommend the more effective one.

## 8.1 Recommended: nested discounted-UCB over steps

For each pair ((k,s)) store discounted step stats (N_{k,s}, S_{k,s}, t_{k,s}) and do the same discounted-UCB selection among the steps in that bucket.

This is cheap because bucket sizes are small (~128 steps). It will quickly concentrate on steps that actually yield new/rare touch.

## 8.2 Fallback simpler option (still decent)

ε-greedy:

- with prob 0.8 pick best step by mean reward,
    
- else pick random step in bucket.
    

If you want “most likely to work”, do nested-UCB.

---

# 9. Mutation-value generation inside (kind, step)

This is not the core of your prompt, but it _matters_ for underconstraints.

For each mutation kind (k), use a **two-mode distribution**:

- **coherence-preserving local moves** (small deltas / bit flips / “interesting constants”)
    
- **global jumps** (uniform random 32-bit, random immediate field, etc.)
    

Let (p_{\text{local}}) be probability of local move. Suggested:

- Start at (p_{\text{local}}=0.7) early,
    
- decay to (0.4) later (when exploration needs bigger jumps).
    

This is the lowest-effort way to avoid getting trapped in only tiny perturbations.

**Important:** This is where you should incorporate “degenerate case forcing” (rs1==rs2, aliasing, etc.) eventually — but as a mutation generator feature, not a coverage key.

---

# 10. Data structures you should implement (concretely)

## 10.1 Core scheduler state

- `Arms`: mapping `(kind, bucket) -> ArmState`
    
    - `ArmState: N, S, last_t, step_states (optional)`
        
- `StepStates`: mapping `(kind, step) -> StepState`
    
    - `StepState: N, S, last_t`
        
- `CoverageState`:
    
    - `seen_touch: bytearray(MAP_SIZE)` (0/1)
        
    - `freq_touch: array('I', MAP_SIZE)` (run-frequency)
        
    - `fail_seen: set[FailKey]`
        
    - `fail_freq: dict[FailKey, int]`
        
    - rolling window buffer of `new_touch_count` for saturation test
        

## 10.2 Debug / collision hygiene (strongly recommended)

Even if you keep the bitmap for scheduling, you should keep **exact evidence on interesting runs**:

- If `new_touch_count > 0` OR `ACCEPTED` OR “high reward”, persist:
    
    - the list of touched indices `sorted([i for i in range(M) if X_t[i]>0])`
        
    - and the list of fail contexts (you already have)
        
    - and the mutation config (you already have)
        

This makes it possible to:

- sanity-check collisions,
    
- reproduce,
    
- and do offline analysis without re-running.
    

This answers your “shouldn’t we keep an exact set at least for debug?” concern: **yes**—but only on _interesting_ runs so you don’t bloat storage.

---

# 11. Why this architecture is the best “most likely to work” choice

## 11.1 It directly matches your current observable signals

You already emit an AFL-style touch bitmap and exact failure contexts. This architecture consumes those _as-is_.

## 11.2 It avoids overfitting your coverage identity to a single program

Coverage identity stays at `(loc, major, minor)`. Step/PC are only used for **action selection**, and later you can reset/partition by program.

## 11.3 It solves the novelty-saturation problem

The novelty→rarity switch is what keeps scheduling informative after the first few hundred runs.

## 11.4 It handles nonstationarity explicitly

Discounted-UCB forgets old “good arms” once they stop producing value. Plain UCB1 will not.

## 11.5 It is extensible

- Add global constraints later: add another bitmap/frequency channel and add its score into the same reward.
    
- Add multiple programs later: either run separate schedulers per program, or a meta-bandit over programs (arms = program_id) allocating budget.
    

---

# 12. Master multi-phase implementation plan (architectural, not code)

You asked for a plan you can hand to Opus to convert into code tasks. Here it is.

## Phase II.0 — Instrumentation sanity + baseline

1. Run baseline (unmutated) with touch enabled, record:
    
    - baseline touched indices list
        
    - baseline distinct touched count
        
2. Confirm determinism: same mutation config → identical touch bitmap (you already have this test).
    

Deliverable: baseline coverage snapshot and “campaign state init” code.

---

## Phase II.1 — Build the arm universe from inspection

1. From your `InspectionData`, compute:
    
    - valid steps per kind: `S_k`
        
    - bucket assignment `b(s)`
        
    - `S_{k,b}` lists
        
2. Enumerate available arms `(k,b)`.
    

Deliverable: reproducible arm list and ability to sample random valid arm/step.

---

## Phase II.2 — Implement CoverageState + reward components

1. Implement / extend `CoverageState`:
    
    - seen bitmap
        
    - frequency array
        
    - failure seen/freq
        
    - rolling window of new_touch_count
        
2. Implement reward component extraction:
    
    - `new_touch_count`
        
    - `rare_touch_score` (top-K rare)
        
    - `new_fail_context_count`
        
    - `Q_t` from crash/touch missing + failure count
        

Deliverable: a function `compute_reward(run_result, coverage_state) -> (reward, diagnostics)` that is deterministic and unit-testable.

---

## Phase II.3 — Implement the bandit (Discounted-UCB)

1. Implement `DiscountedUCB` with lazy decay.
    
2. Add forced exploration.
    
3. Add nested step-level bandit (same structure) **or** ε-greedy.
    

Deliverable: a scheduler that, given current state, returns `(kind, step)`.

---

## Phase II.4 — Integrate scheduler into the campaign loop

1. Replace the current “selector” update with:
    
    - choose arm
        
    - choose step
        
    - execute mutation
        
    - compute reward
        
    - update coverage state
        
    - update bandit stats (arm + step)
        
2. Log per-run diagnostics:
    
    - selected arm
        
    - new_touch_count, rare_touch_score
        
    - new_fail_context_count
        
    - Q_t
        
    - final reward
        

Deliverable: end-to-end run of 200–500 mutations showing nontrivial adaptation (arm probabilities shift).

---

## Phase II.5 — A/B experiments to tune the few real parameters

Run 3 campaigns each for:

- Baseline uniform scheduling
    
- New bandit scheduling
    

Measure:

- total distinct touched buckets vs mutation count
    
- time-to-hit rare touch buckets (e.g., sum of rare scores)
    
- unique failure contexts
    
- crash rate
    
- wall-clock overhead (should be negligible)
    

Tune:

- bucket count target (128 vs 256)
    
- γ (0.99 vs 0.995)
    
- K_rare (16 vs 32 vs 64)
    
- τ_fail_count (penalty strength)
    
- λ (failure novelty weight)
    

Deliverable: a single config that is clearly better than uniform under your metrics.

---

## Phase II.6 — Persistence + resume (optional but recommended)

Persist:

- seen bitmap and freq array
    
- bandit states
    
- rolling window
    
- failure freq maps
    

Deliverable: resume campaign from DB/state file without losing learned policy.

---

## Phase II.7 — “Bug mode” exploitation loop (only if ACCEPTED happens)

If ACCEPTED is observed:

1. Freeze the exact mutation config.
    
2. Run minimization:
    
    - try to shrink delta
        
    - try adjacent steps
        
    - try alternative mutation kinds on same area
        
3. Store a “bug seed corpus” and allocate, say, 20% of future budget to local search around bug seeds.
    

Deliverable: immediate triage pipeline.

---

# 13. Very brief answers to your remaining concerns (only where they affect the architecture)

- **PC in the coverage key?** No. Too noisy across programs. Use PC/step only for _action selection_.
    
- **Lane in coverage key?** No. If it’s useful, treat it as a _feature_ later, not identity.
    
- **Degenerate-case in coverage key?** No. Make it a mutation generator feature and/or a separate “degenerate case campaign mode”.
    
- **Bucket size vs “losing granularity”?** Bucketing is for _learning the policy_, not for coverage measurement. You keep full coverage; you only reduce the bandit’s action space.
    
- **Map size: should we make it huge to avoid collisions?** Not initially. Your MAP_SIZE=65536 and observed ~1599 distinct buckets/run is already workable. Use “exact evidence on interesting runs” to debug collisions, and only increase MAP_SIZE if collisions are shown to materially harm scheduling.
    

---

# 14. One additional technique worth adding soon (high impact, low risk)

Add a second touch channel that tracks **major/minor coverage directly** (not hashed), because it’s cheap and interpretable.

Even if you keep the primary scheduler on touch bitmap, you can add a _constraint-regime coverage dashboard_ like:

- `touched_major[0..7]` counts
    
- `touched_major_minor[(major, minor)]` counts (sparse map)
    

This helps you reason about “are we exploring div/mul/mem paths” without having to invert a bitmap. It does not have to feed the bandit initially, but it becomes very useful once you move to multi-program and global constraints.

---

# 15. How the uploaded bandit paper influences this choice (just the actionable lesson)

The paper’s CMAB setup is different (they select multiple workers per round), but the transferable lesson is: **round-based / stage-based exploration** and **confidence-bound selection** are practical and analyzable tools, and they explicitly discuss how confidence-bound choice affects performance and regret. That supports our choice to:

- use a confidence-bound bandit (UCB-style),
    
- and explicitly implement stage transitions (novelty→rarity) rather than assuming stationarity.
    
