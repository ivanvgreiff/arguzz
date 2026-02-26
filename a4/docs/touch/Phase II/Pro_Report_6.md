```Prompt
I am continuing our work on constraint-coverage-guided fuzzing for RISC Zero. You previously provided Pro_Report_4.md (the concrete architecture specification which I copied and pasted in the Phase II/ folder) and Pro_Report_5.md (parameter calibration details which I copied and pasted into the Phase II/ folder). Since then, I have been working with Claude Opus to incrementally implement the architecture you specified.

**What has been implemented so far (Phase I + Phase II subphases 0-2):**
- Phase I: Full touch coverage instrumentation pipeline (C++ bitmap in witgen, base64 emission, Python parsing, fuzzer integration, determinism tests)
- Phase II.0: Baseline touch snapshot
- Phase II.1: Arm universe construction (bucketed action space)  
- Phase II.1.5: Pilot calibration functions
- Phase II.2: CoverageState class with compute_reward and update_state (your exact reward formulas from Pro_Report_4 section 6)

**What has NOT been implemented yet:**
- Phase II.3: Discounted-UCB bandit
- Phase II.4: Campaign loop integration
- Phase II.5-6: A/B experiments, persistence

**Before implementing the bandit (Phase II.3), I ran a 200-mutation diagnostic campaign** with a new verbose touch mode that captures exact (loc, major, minor) triples (not just the hashed bitmap). The results revealed several concerns about whether the reward function you designed is optimal for the empirical behavior of our constraint system. These concerns are documented in detail in `Phase II/Concerns.md`.

**I need you to:**
1. Read `Phase II/Concerns.md` carefully — it contains the empirical data, the specific architectural concerns, and my questions. It contains questions by claude, and questions by me. Note that claude is not as intelligent as a model as you, so critically analyze and think for yourself, rather than fully relying on Claude Opus's opinions as some 100% source of truth and perfection regarding what it suggests as improvements. 
2. Read the other Phase II markdowns as needed for context (the Table of Contents in Concerns.md maps each file). I also included the Phase I/ folder which contains archived markdowns going over the previous implementation reports which we already covered in our conversation. Just in case you need to refer to them, you have them there for detailed information.
3. Tell me whether the reward function from Pro_Report_4 needs to be revised before I implement the bandit, and if so, provide the specific revised formulas and any new parameters.
4. Briefly address each of the 5 questions in Concerns.md section 6.
5. MOST IMPORTANT: I need you to rethink and critically analyze ALL of the analytical formulae and parameter values you provided in Pro_Report_4.md and Pro_Report_5.md to see if they are still optimal for us moving forward. If it is the case that minor reworks (or no reworks at all) are required, then explain why. If it is the case that major reworks (or a big change in the architecture) are required, I need you to critically reason (and possibly do some research) in order to come up with the best possible architecture for this fuzzing approach of mine. Remember, we want to maximize our chances of finding soundness bugs i.e. proofs that verify but should not due to some hidden underconstraint(s) somewhere. That is our goal.

If you rework ANYTHING, I need you to provide me with the new analytical expressions or parameter values or whatever, and VERY IMPORTANT is that you explain why they are structured this way, and why you chose these exact decisions and not others. I do not want to overfit but I also want my architecture to work as effectively as possible in pursuit of my goal of finding soundness bugs in RISC Zero.

If you find that I need to do more offline campaigns to provide more data that I did not provide in the markdowns, let me know. It may be the case that you have all the information you need to decide on this final architecture that is ensured to be as effective as possible. If you have all the information you need, then give me the final architecture. If you do not, let me know what further information you need. Do I need to do some more campaigns offline (possibly with more mutations) in order to come up with the best architecture, or do you have enough information?

Claude thinks: "your architecture uses touch-bitmap novelty/rarity as the primary signal, but empirically, touch coverage saturates after 1 run for 7 of 8 mutation kinds (only INSTR_TYPE_MOD discovers new touch). Meanwhile, failure context_id (constraint_loc, major, minor) novelty is nonzero for 31% of runs across all kinds". This was a statement/question by claude opus.
```

Below is my best “lock-in” recommendation **before you implement Phase II.3 (Discounted-UCB)**, grounded in what your 200-mutation diagnostic campaign demonstrated in `Concerns.md`.

The headline is: **yes, revise the reward now**. The current reward (as specified in `Pro_Report_4.md`) was built around the assumption that **touch novelty/rarity is the high-bandwidth signal**. Your data shows that assumption is **false for 7/8 mutation kinds** in the single-program / fixed-input regime you’re implementing first.

---

## 0. What your 200-run data really implies

From `Concerns.md`, the key empirical facts (paraphrased) are:

- **Touch behavior**
    
    - Baseline: **1614** distinct exact touch triples
        
    - After 200: **2076** distinct exact touch triples (+462)
        
    - **INSTR_TYPE_MOD accounts for 454/462 ≈ 98%** of non-baseline new touch triples.
        
    - For “value mutations” (the other 7 kinds), **touch saturates essentially immediately**: you keep touching the same contexts.
        
- **Failure behavior**
    
    - **163 distinct failure context_ids** (where context_id = `(constraint_loc, major, minor)`).
        
    - **31% of runs** discover at least one **new** failure context_id.
        
    - Failure count distribution is tight (median 2, 75% at 3), with rare cascades (one 159-failure run).
        
- **Bitmap collision**
    
    - **35 collisions** at 2076 exact keys mapped into 65536 buckets → **1.7%**, matches expectation.
        
    - Per INSTR_TYPE_MOD run: bitmap loses **~1–4** new triples versus exact.
        

These imply something very concrete about your scheduler:

### Touch is a “selector-regime” signal, not a “value-space exploration” signal

In this post-exec-trace setting, most value mutations do **not** change which selector-gated constraints are evaluated; they change whether those already-evaluated constraints are satisfiable. So touch coverage is mostly telling you: _“which constraint families/selectors are active”_, which is primarily affected by **instruction-type mutations**.

### Failure context_ids are the _differentiating_ signal across most arms

If 7/8 mutation kinds yield essentially the same touched set, then **touch rarity becomes uniform** among those kinds, and **touch novelty is zero**. That means the bandit will not learn meaningful preferences among those arms unless you feed it another signal—your data says failure context novelty/rarity _is_ that signal.

So: **the bandit architecture can stay**, but **the reward must change** (or else the bandit will (i) collapse into INSTR_TYPE_MOD chasing touch novelty, and/or (ii) be almost indifferent among all value-mutation arms).

---

## 1. Decision: revise reward BEFORE implementing the bandit

### Why “revise now” (not later)?

Because Phase II.3’s discounted-UCB will start accumulating arm statistics immediately. If your reward is near-constant across most arms, you’ll get:

- weak learning,
    
- premature convergence to whatever produces the only nonzero variance (INSTR_TYPE_MOD touch deltas),
    
- and then you’ll have to decide whether to **reset bandit state** after you fix reward (which complicates experiments and interpretation).
    

So: **fix the reward first**, then implement the bandit on top of a reward that actually separates arms.

---

## 2. Concrete revised reward (fully specified)

I’m going to keep the spirit of your current design (bounded reward, novelty + rarity, “quality” multiplier), but modify it so that:

1. **failure-context signals become co-primary**,
    
2. **“quality” is tied to distinct failure contexts + cascade repeats**, not raw instance count alone,
    
3. **touch novelty is still rewarded**, but touch rarity is no longer assumed to be informative for value mutations.
    

### 2.1 Notation per run (t)

You already have:

- touch bitmap (B_t \in {0,\dots,255}^{M}), (M = 65536)
    
- list of failure instances ( \mathcal{L}_t ) (possibly with repeats)
    

Define:

- **Touched bucket set**:  
    [  
    U_t := { i \in [0,M): B_t[i] > 0 }  
    ]
    
- **Failure context set (distinct)**:  
    [  
    F_t := { (\text{loc}(f), \text{major}(f), \text{minor}(f)) : f \in \mathcal{L}_t }  
    ]
    
- Counts:
    
    - (n_{\text{fail}} := |\mathcal{L}_t|) (raw instances)
        
    - (d_{\text{fail}} := |F_t|) (distinct contexts in run)
        
    - (r_{\text{rep}} := \max(0, n_{\text{fail}} - d_{\text{fail}})) (repeat/cascade mass)
        

Global state you maintain:

- touch seen indicator (G[i] \in {0,1}) (your global bitmap >0 works)
    
- touch run-frequency (f_T[i] \in \mathbb{N}) (your `freq[i]`)
    
- failure run-frequency (f_F[c] \in \mathbb{N}) (your `fail_freq` **but should be per-run-per-context**, not per-instance)
    

Now define novelty counts:

- Touch novelty:  
    [  
    \Delta_T := |{ i \in U_t : G[i] = 0 }|  
    ]
    
- Failure-context novelty:  
    [  
    \Delta_F := |{ c \in F_t : f_F[c] = 0 }|  
    ]
    

### 2.2 Component scores

#### Touch novelty score

[  
T_{\text{new}} := 1 - \exp(-\Delta_T / \tau_T)  
]

#### Touch rarity score (optional but useful for INSTR_TYPE_MOD)

Define per-bucket rarity weight:  
[  
w_T(i) := \frac{1}{\sqrt{1 + f_T[i]}}  
]  
Let (K_T := \min(K_{T,\text{rare}}, |U_t|)), and let (\text{TopK}(U_t)) be the (K_T) indices in (U_t) with largest (w_T(i)).  
Then:  
[  
T_{\text{rare}} := \frac{1}{K_T} \sum_{i \in \text{TopK}(U_t)} w_T(i)  
]

#### Failure novelty score

[  
F_{\text{new}} := 1 - \exp(-\Delta_F / \tau_{F,\text{new}})  
]

#### Failure rarity score (THIS is what gives you bandwidth after novelty decays)

Per-context rarity weight:  
[  
w_F(c) := \frac{1}{\sqrt{1 + f_F[c]}}  
]  
Let (K_F := \min(K_{F,\text{rare}}, |F_t|)), TopK similarly. If (|F_t|=0), define (F_{\text{rare}} := 0).  
Then:  
[  
F_{\text{rare}} := \frac{1}{K_F} \sum_{c \in \text{TopK}(F_t)} w_F(c)  
]

#### Zero-local-fail indicator (deep local-sat signal)

[  
Z := \mathbf{1}[d_{\text{fail}} = 0]  
]

This directly captures your interesting empirical category **NO_FAIL_BUT_REJECTED** (local constraints didn’t fail, but something else rejected), which you should treat as “high-quality / promising” in the current local-only instrumentation world.

### 2.3 Execution-quality multiplier (Q)

Your current (Q = \exp(-n_{\text{fail}} / \tau)) has the “n_fail vs distinct” tension you noted.

Use a two-factor penalty:

#### Distinct-failure penalty

[  
Q_{\text{dist}} := \exp(- d_{\text{fail}} / \tau_{d})  
]

#### Cascade-repeat penalty (only kicks in for _real cascades_)

Use a threshold (r_0) to avoid penalizing small repeat counts:  
[  
Q_{\text{rep}} :=  
\begin{cases}  
1 & r_{\text{rep}} \le r_0 \  
\exp(-(r_{\text{rep}} - r_0)/\tau_{r}) & r_{\text{rep}} > r_0  
\end{cases}  
]

Final:

- If crash or missing bitmap: (Q := 0)
    
- Else:  
    [  
    Q := Q_{\text{dist}} \cdot Q_{\text{rep}}  
    ]
    

This does what you want:

- penalizes “more independent things are broken” via (d_{\text{fail}}),
    
- penalizes “one mutation blew up into lots of repeats” via (r_{\text{rep}}),
    
- but does **not** nuke a run merely because you collected many repeated instances.
    

### 2.4 Final reward

Use a **weighted average** of the informative components, then multiply by (Q):

Let weights (a_{Tn}, a_{Tr}, a_{Fn}, a_{Fr}, a_Z \ge 0). Define:

[  
S := \frac{  
a_{Tn} T_{\text{new}} + a_{Tr} T_{\text{rare}} + a_{Fn} F_{\text{new}} + a_{Fr} F_{\text{rare}} + a_Z Z  
}{  
a_{Tn} + a_{Tr} + a_{Fn} + a_{Fr} + a_Z  
}  
]

Reward:  
[  
r_t := \min(1, ; Q \cdot S)  
]

Override:

- If verifier ACCEPTED: set (r_t := 1).
    

---

## 3. Recommended default parameters (and which need calibration)

Your Question #11 in earlier prompts was about calibration; here’s the _updated_ version given the new empirical behavior.

### 3.1 Parameters to calibrate per campaign (cheap, robust)

These should be computed from a short pilot (e.g., 30–100 runs), **after seeding with a baseline** (more on that below):

1. **(\tau_T)** (touch novelty scale)  
    Calibrate from the distribution of **nonzero** (\Delta_T) during pilot _mutations_ (not baseline).
    

- Use: (\tau_T := \text{p75}({\Delta_T : \Delta_T>0}))
    
- Clamp: ([8, 128]) (recommend tighter than the old [16,256], because your incremental deltas are tens, not thousands).
    

2. **(\tau_d)** (distinct-failure penalty scale)  
    Calibrate from pilot distribution of (d_{\text{fail}}) (distinct fail contexts per run).
    

- Use: (\tau_d := \max(1, \text{p75}(d_{\text{fail}})))  
    Given your observed p75 ~ 3, you’d likely get (\tau_d \approx 3).
    

3. **(K_{T,\text{rare}})**  
    Your existing rule of thumb (≈2% of median |U| clamped [16,64]) is fine for touch.  
    Given |U| ~ 1600, you get ~32 (as you do).
    
4. **(\gamma)**, **(c_{\text{explore}})**, **(n_{\min})**  
    Your earlier derivations are still fine. No change needed.
    

### 3.2 Parameters that should be HARD (don’t overfit)

These should not be “micro-calibrated” from tiny pilots because the tail events are rare:

1. **(\tau_{F,\text{new}})**  
    Keep **2.0** as before. It maps Δ=1 to ~0.39, Δ=2 to ~0.63.
    
2. **Cascade threshold and slope**: (r_0, \tau_r)  
    Because repeat cascades are rare, calibrating them from pilot is unstable. Hardcode:
    

- (r_0 = 10) (don’t penalize tiny repeats)
    
- (\tau_r = 25) (penalize true cascades strongly)
    

### 3.3 Weights (a_{*}): what I recommend now

You want failure-context signals to actually matter for 7/8 kinds.

A robust starting point (not overfit, but aligned to your observed bandwidth):

- (a_{Tn} = 1.0) (new touch still matters when it happens)
    
- (a_{Tr} = 0.25) (touch rarity is mostly to keep INSTR_TYPE_MOD differentiated once novelty slows)
    
- (a_{Fn} = 1.0)
    
- (a_{Fr} = 1.0)
    
- (a_{Z} = 1.0) (explicitly reward no-local-fail)
    

This makes the failure side + zero-fail clearly co-primary.

**Why not make touch dominant?** Because your data says it won’t differentiate value mutations. Making it dominant would create “learns nothing / collapses to INSTR_TYPE_MOD” behavior.

---

## 4. A critical fix: baseline seeding must influence calibration (and ideally reward state)

Your Phase II.1.5 calibration (as currently described) has a structural issue:

- If the pilot starts from an **empty** global bitmap, the first run produces ~1600 “new bits”.
    
- That single point can force (\tau_T) to be huge (and/or clamped), making later “real novelty” events (Δ ~ 30–50) look tiny.
    

You already have Phase II.0 baseline capture. My recommendation:

### Treat baseline touch as “seed run 0” for coverage state

- Initialize `state.global_bitmap` and `state.freq` by merging the baseline bitmap and setting `freq[i]+=1` for touched indices.
    
- Then do pilot mutations and compute (\Delta_T) relative to that.
    

This makes (\tau_T) reflect _incremental_ novelty (the real thing you want), not the trivial “empty → baseline” jump.

Even if you don’t want baseline in the _reward_ conceptually, you **do** want baseline to avoid a meaningless calibration artifact.

---

## 5. Brief answers to the 5 questions in `Concerns.md` section 6

### Q1) Should reward be restructured to use failure context_ids as a primary signal?

**Yes.** In the current “single guest program, fixed inputs” phase, **touch is almost entirely a selector-regime signal** and gives near-zero variance for 7/8 mutation kinds after baseline. Failure context_ids give you a **middle-granularity, still-growing, arm-differentiating** signal (31% novelty rate), and they are the best thing you currently have that varies across value mutations.

Concretely: **failure novelty + failure rarity must be co-primary** with touch. Touch should remain present (to keep INSTR_TYPE_MOD exploration valuable), but it cannot be the main driver.

### Q2) Should we maintain a “failure context bitmap” alongside the touch bitmap?

**Not necessary right now.** You already have exact failure context_ids in Python, and the scale is small (163 distinct in 200 runs). A hashed failure bitmap:

- adds collision risk,
    
- adds complexity,
    
- doesn’t buy you much because dict/set operations are trivial at this scale.
    

If later you scale to massive multi-program campaigns and failure contexts become huge (tens of thousands), a bitmap might be worth it, but it is premature now.

### Q3) How should cascade penalty be refined?

Replace “penalize raw n_fail” with a penalty that separates:

- **how many distinct constraints are violated** ((d_{\text{fail}})),
    
- **how much repeat/cascade is happening** ((r_{\text{rep}})).
    

Use:  
[  
Q = \exp(- d_{\text{fail}}/\tau_d) \cdot Q_{\text{rep}}  
]  
with (Q_{\text{rep}}) only activating when repeats exceed a threshold (r_0).

This directly resolves the “Q nukes informative runs” concern.

### Q4) Is MAP_SIZE=65536 adequate given 1.7% collision rate?

**Yes, for now.** 1.7% collisions is small and matches theory. The undercount per INSTR_TYPE_MOD run (1–4 triples) is “noise,” and bandits tolerate noisy rewards.

I would only increase MAP_SIZE if:

- you later get into a regime where per-run touch deltas are often **1–2**, and collisions frequently erase them,
    
- or you scale to many programs and the number of distinct touch contexts grows enough that collisions become materially worse.
    

If you did increase, go to **131072 (2^17)**, not huge jumps, because output size scales linearly.

### Q5) Revise reward before bandit, or proceed and iterate?

**Revise before bandit.** The observed reward degeneracy for 7/8 kinds is exactly the kind of thing that makes bandit learning misleading and hard to interpret. You’ll get a cleaner experiment if Phase II.3 is built on a reward with real variance and meaningful structure.

---

## 6. What changes in Pro_Report_4/5 are “minor” vs “must change”

### Must change (based on the new data)

1. **Reward must include failure-context rarity (not just novelty)**
    
    - novelty will eventually decay; rarity remains informative.
        
2. **Reward must treat failure-context signal as co-primary**
    
    - otherwise bandit can’t differentiate among value-mutation arms.
        
3. **Q must not be based solely on raw `n_fail` instances**
    
    - use distinct vs repeats split.
        
4. **Remove or de-emphasize the rolling-window median saturation switch**
    
    - In your regime, median(Δtouch) is ~0 almost always → you effectively disable the novelty term at exactly the time you still want it to fire on the rare INSTR_TYPE_MOD novelty events.
        

### Likely fine to keep (no strong evidence against)

- Arm universe ((\text{kind}, \text{bucket})) with your budget-derived B_count.
    
- Discounted-UCB as the scheduler (nonstationarity is real; discounting is appropriate).
    
- MAP_SIZE=65536 for touch, given measured collision rate.
    
- Using (constraint_loc, major, minor) as the failure context key (your data explicitly supports this granularity jump).
    

---

## 7. Do you need more offline campaigns?

You can implement the revised reward now, but I do recommend **one more diagnostic** before you A/B the bandit:

### Run a 500–1000 mutation campaign with:

- your **actual fuzzer value generator** for INSTR_WORD_MOD_FULL (not the generic diagnostic one),
    
- logging:
    
    - cumulative distinct failure context_ids vs run index,
        
    - cumulative distinct touch triples vs run index,
        
    - counts of Z = (no-local-fail) per kind and per bucket.
        

The point is not to overfit parameters; it’s to confirm whether:

- the 31% failure novelty rate is sustained or front-loaded,
    
- which kinds/buckets produce Z-events,
    
- and whether failure rarity meaningfully differentiates arms after novelty decays.
    

Even if novelty decays, **F_rare** will still differentiate if different arms hit different failure contexts.

---

## 8. Net recommendation to Claude Opus (what to implement next)

Before Phase II.3:

1. **Update CoverageState / reward to the new formula** (touch + failure novelty/rarity + zero-fail + refined Q).
    
2. **Ensure `fail_freq` counts per-run-per-context**, not per-instance.
    
3. **Seed baseline touch into the global touch state before pilot** (or at least exclude the empty→baseline jump from τ calibration).
    
4. Re-run your 200-mutation diagnostic and verify:
    
    - reward variance exists across non-INSTR_TYPE_MOD arms,
        
    - Z-events get high reward,
        
    - cascades are suppressed but not “information-erased” incorrectly.
        

Then implement Phase II.3 bandit exactly as planned.
