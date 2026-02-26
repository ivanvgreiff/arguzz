```Prompt
I have the following questions (though the most important question is #11, so I want you to spend the most time critically thinking and reasoning about this question #11):


Questions

1. "This ratio also tells you counters are not that informative; the binary “touched vs not” signal will dominate". I don't understand the point here, how so?

2. "Failure-only coverage is tiny: in a partial 24-mutation campaign you saw K_total ≈ 43 distinct failing (constraint_loc, major, minor) contexts and per-mutation max distinct failures around 9. That means: failure-coverage saturates extremely fast; touch-coverage is the signal with the bandwidth you need." What do they mean here? Also it was only 24 mutation runs, so if I run more I might get more, should I verify? What exactly should I verify? I can run a 500 mutation campaign.

3. "Failure-only coverage is tiny: in a partial 24-mutation campaign you saw K_total ≈ 43 distinct failing (constraint_loc, major, minor) contexts and per-mutation max distinct failures around 9. That means: failure-coverage saturates extremely fast; touch-coverage is the signal with the bandwidth you need." Why is constraint failure not the main driver? How does this cause "bandit reward becomes mostly zeros and stops learning."?

4. How does "Adding step bucket blows up the key space"?

5. "For typical traces (~20k steps), this will usually give B = 128 or 256, producing ~80–160 buckets. That’s a sweet spot." shouldn't we run a mutation and see how many steps we get? Do we count first and last step which are many thousands of transactions cycles that only contain control info?

6. How is the touch bitmap {0, ... , 255}^(65536)? So it is an 8-bit value each along 2^16 dimensions? Where did these numbers come from?

7. You said the rolling window should be e.g. W = 50, but is this really the best value? What should it be and what factors should we take into consideration to decide this value? Why not just make W unbounded so we have access to all mutations runs?

8. Can you explain the intuition behind the sat_t expression via an example?

9. Provide intuition behind the expressions in your section 7 "Bandit model (fully specified)", as I am having trouble understanding why the expressions are structured the way they are and what meaning these bring.

10. For the additional technique you recommended in Section 14, if you think this is worth doing, shouldn't it be done during the implementation process? It seems you left it out and put it as a sidenote, but I need you to decide (if you have enough information and can make an educated decision without risk of making an uninformed/non-optimal decision) if this should be part of the main implementation. If so, how and when in the implementation plan? If not, why?

11: Overall, you provided a lot of hardcoded values, but which of these should remain hardcoded and which of these should be calibrated depending on mutation runs we do in experimental campaigns? Provide guidance as to how these should be decided. Maybe not all parameters require calibration from experimental campaigns, and maybe some parameters do. Maybe all do maybe all do not, so reason critically as to which (if any) should and how these should be decided. I am not just talking about the parameters you mentioned in Phase II.5, but there are more throughout the report not mentioned here. If we have any parameters which need to be calibrated or analytically derived from some expression based on results from experimental campaigns, where do these fit in within the master implementation plan? Ensure you look over all details you provided in your previous answer to ensure you do not miss any parameters/variables/constants etc. I will provide your answer back as a markdown so you do not lose access to anything, in case you cannot read your previous response. 
```

---

Below I’ll answer 1–10 crisply, then go very deep on **#11 (parameter hardcode vs calibration)**, including where each calibration step fits into the master plan you’re following. I’m referring to the architecture/spec you quoted (your saved copy in `Pro_Report_4.md`). 

---

## 1) Why does “192,676 total touches vs 1,599 distinct buckets” imply counters aren’t very informative?

Let:

* `distinct_touched = |U_t| = 1599` (number of nonzero indices in the bitmap for that run)
* `total_touches = Σ_i X_t[i] = 192,676` (sum of the per-index u8 counters)

Then the **average** count per touched index is:

[
\frac{192,676}{1599} \approx 120
]

That means: in a single run, a “touched constraint hash bucket” is typically being incremented **dozens to hundreds of times**.

Why this makes counters less useful (for scheduling):

1. **They mostly measure repetition, not reachability.**
   The STARK constraint evaluation pattern tends to touch the same constraint site over many rows/cycles; a large counter is often “this constraint is checked every cycle,” not “we hit something new/deep.”

2. **They saturate at 255 (u8).**
   If a bucket is incremented more than 255 times, it becomes indistinguishable from “touched 255 times.” So the magnitude becomes clipped exactly where the signal would otherwise be large.

3. **For coverage-guided scheduling, the “new vs seen” question is the high-value bit.**
   Whether `X_t[i] > 0` (touched at all) is what drives “new coverage.” The precise count tends to correlate with trace length and component repetition, not “new behaviors.”

Important nuance: **counters aren’t useless in general**. They are just usually not the right *primary* signal. In the architecture, we use:

* **binary touched per run** (`X_t[i]>0`) to compute `new_touch_count`,
* **cross-run frequency** (`freq[i] = #runs where i touched`) to compute rarity.

That cross-run frequency is informative; the within-run u8 counter is often not.

---

## 2) “Failure-only coverage is tiny.” What does that mean, and should you verify with 500 runs?

Meaning:

* Per run, the number of *distinct failing contexts* is small (≤ ~9 in your early data).
* Across 24 runs, the union reached ~43 distinct failing `(loc, major, minor)` contexts.

That is “tiny” compared to touch, where a single run can touch ~1,599 buckets.

### Should you verify with a 500-mutation campaign?

Yes—**verify the *shape* of the growth curve**, not just the final number. Specifically, run a longer campaign and plot:

1. **Unique failure contexts vs #mutations**
   [
   K(n) = \left|\bigcup_{t=1}^n F_t\right|
   ]
   If `K(n)` grows quickly then flattens (classic saturation), then “failure novelty” becomes sparse signal.

2. **Per-run distinct failures distribution**

   * histogram of `|F_t|`
   * fraction of runs with `Δfail_new_t > 0`

3. **Failure contexts by mutation kind**
   [
   K_k(n) = \left|\bigcup_{t:kind(t)=k} F_t\right|
   ]
   This tells you if some mutators systematically discover new failing contexts.

What to conclude:

* If after ~500 runs, `K(n)` is still rising meaningfully (not just +1 every 100 runs), then failure novelty can be weighted higher.
* If `K(n)` plateaus early, you treat failures as **secondary** because most runs produce no new failure contexts.

---

## 3) Why isn’t constraint failure the main driver? How does this lead to “reward mostly zeros”?

Two separate issues:

### (A) New-failure novelty becomes sparse

If your reward is primarily:

[
\Delta^{fail}*t = |{c\in F_t: ffreq*{t-1}[c]=0}|
]

…then once you’ve seen most failing contexts reachable by your current mutators, you get:

* `Δfail_t = 0` for the vast majority of runs.

So the bandit sees mostly zero reward and can’t distinguish arms well.

### (B) “More failures” is often the *wrong* direction for underconstraint hunting

An underconstraint bug is: **a wrong witness still passes verification**. That requires staying on/near the constraint manifold, not exploding into many obvious contradictions.

So optimizing for *count of failures* tends to push the search into “break everything early” land, which is great for finding robust checking but not optimal for finding the tiny degrees of freedom that slip through.

That’s why the architecture uses:

* touch/rarity (coverage exploration) as primary,
* failure novelty as secondary (still useful),
* and a mild penalty for huge failure cascades.

---

## 4) How does “adding step bucket blows up the key space”?

If you change:

[
\text{TouchKey}=(loc,major,minor)
]
to
[
\text{TouchKey}=(loc,major,minor,\text{step_bucket})
]

Then the number of potential unique keys increases by roughly a factor of `#buckets`.

Example:

* Suppose baseline has ~1,600 distinct `(loc,major,minor)` keys.
* Suppose you use 128 step buckets.

In the *worst case*, each constraint-context can appear in many buckets (and many do, across execution), giving up to:

[
1600 \times 128 = 204{,}800
]

You’re hashing into `MAP_SIZE=65,536`, so now your expected collisions jump dramatically. It also makes “coverage identity” far more program-specific.

That’s why bucketing belongs in the **action space** (choose where to mutate), not in the **coverage key** (what is touched).

---

## 5) “Typical traces 20k steps” — shouldn’t you measure T? And what about “control-only cycles”?

Yes: measure **T in the same coordinate system you mutate**.

* If your mutation target is `step` (instruction step index), then:

  * define (T := 1 + \max(\cup_k S_k)), where (S_k) is the set of valid steps for mutator kind (k).
* Ignore “cycles” that aren’t part of the mutatable step domain; they don’t matter for step bucketing.

If you have pre/post “control-only” regions that you *can’t* mutate (not in any `S_k`), they automatically drop out when you define `T` via union of valid steps.

---

## 6) Why is touch bitmap (X_t \in {0,\dots,255}^{65536})?

Because:

* `MAP_SIZE = 65536 = 2^16` entries (standard AFL-ish size; your implementation used this constant). 
* Each entry is an 8-bit saturating counter (`u8`) that can hold values 0..255.

So (X_t[i]) is “how many times (up to 255) did we mark this hashed bucket touched this run”.

---

## 7) Is W=50 best? Why not unbounded?

W is the window length used only for detecting “novelty saturation” (when to switch to rarity mode). An **unbounded** window is usually a mistake because novelty is highest early; your “median over all time” will stay >0 long after novelty has effectively died, so you never switch modes.

What to consider when choosing W:

* **Responsiveness**: how quickly should we switch once novelty dries up?
* **Noise**: `Δnew_t` may be noisy; too small W flips back and forth.
* **Campaign budget N**: W should be small relative to N so you’re not averaging over the whole campaign.

Rule-of-thumb for your setting:

* Use (W \in [30, 150])
* Choose (W \approx 0.05N) but clamp into that range.

So:

* N=1000 → W≈50 is reasonable
* N=500 → W≈25 (but clamp to ≥30 → W=30)
* N=5000 → W≈250 (but clamp to ≤150 → W=150)

If you want to avoid W entirely, replace the median test with an **exponentially-weighted moving average** (EWMA) of `Δnew_t` and compare to a threshold. That’s another viable design (less parameter sensitivity), but W=50 is fine as a v1.

---

## 8) sat_t intuition example

You defined:

[
\text{sat}*t = \mathbf{1}\left{\mathrm{median}(\Delta^{new}*{t-W+1:t}) < 1\right}
]

Since `Δnew` is an integer, “median < 1” is basically “median = 0”.

Example with W=10 (smaller window for illustration):

Suppose `Δnew` in last 10 runs is:
[
[4,1,0,0,0,0,0,0,0,0]
]
Median is 0 → sat_t = 1 (saturated).

If instead:
[
[3,2,1,1,1,0,0,0,0,0]
]
Sorted: `[0,0,0,0,0,1,1,1,2,3]`, median (avg of 5th and 6th) = (0+1)/2 = 0.5 < 1 → sat_t=1.

Interpretation:

* Once **more than half** of the last W runs produce **zero** new touch bits, you stop optimizing novelty and start optimizing rarity.

---

## 9) Intuition behind the discounted-UCB equations (why structured like this)

The bandit’s job is: pick an arm (a) that maximizes expected reward, but still explore uncertain arms.

### UCB structure

[
\text{UCB}(a) = \mu_a + c\sqrt{\frac{\log(1+N_{tot})}{N_a}}
]

* (\mu_a) = empirical mean reward for arm (a). (“exploitation”)
* The second term is an “uncertainty bonus”:

  * arms with small (N_a) get bigger bonus,
  * as total experience (N_{tot}) grows, (\log(1+N_{tot})) grows slowly, so exploration pressure grows slowly.

So UCB chooses arms that are either:

* proven good ((\mu_a) high), or
* insufficiently tried (bonus high).

### Why discounting

Your reward is non-stationary because “new coverage” diminishes as you discover bits. So an arm that was great early may become mediocre later.

Discounted stats implement forgetting:
[
N_a \leftarrow \gamma^{\Delta t} N_a,\quad S_a \leftarrow \gamma^{\Delta t} S_a
]

This means:

* recent history counts more,
* ancient history decays away.

A helpful way to think: choose a half-life (H) (in iterations) such that contributions from (H) steps ago are downweighted by 50%. Then:
[
\gamma = 2^{-1/H}
]

So discounting is a principled way to keep UCB “tracking” a drifting reward landscape.

---

## 10) Should the “major/minor direct coverage channel” be part of the main implementation?

Yes, but **as mandatory diagnostics**, not as a primary scheduling signal (yet).

Why it should be in the main implementation:

* It is extremely cheap to compute.
* It’s highly interpretable.
* It helps you debug whether your scheduler is actually driving exploration across instruction regimes.

Where to add it:

* Add it in **Phase II.2** (“CoverageState + reward components”) as additional logged statistics:

  * `maj_seen[8]` (or whatever range)
  * `maj_min_seen[(major,minor)]` counts

Don’t feed it into reward initially; just log it. Once you see the scheduler is biased (e.g., stuck in memory checks), you can optionally add a small term that rewards visiting underexplored majors/minors.

---

# 11) Parameter policy: which stay hardcoded vs calibrated, and how to decide each

This is the key part. I’m going to:

1. enumerate **every parameter** introduced in the architecture,
2. classify it into one of four buckets:

   * **HARD**: keep fixed (structural)
   * **DERIVED**: computed deterministically per campaign from trace/budget
   * **CALIBRATE ONCE**: estimate from a short pilot run, then freeze
   * **TUNE VIA A/B**: requires multi-campaign comparison to choose well
3. show **exactly where** each belongs in the master plan.

I’ll also call out one correction: the earlier suggestion “B_count target 128” can be **too many arms** for a 1000-run campaign. This should be derived from budget; see below.

---

## 11.1 Full parameter inventory (with decisions)

### A) Representation / coverage parameters

**(1) MAP_SIZE = 65536 (M=2^16)**

* Type: **HARD** initially
* Rationale: baseline touched indices ~1,600 ≈ 2.4% occupancy → collision rate should be low enough.
* When to change: only if collision evidence shows harm.

**How to validate collisions (cheap):**

* Keep exact “touched idx list” for interesting runs (you planned this).
* Additionally, **do one baseline run with MAP_SIZE doubled** (if feasible) and compare `|U_baseline|`. If it jumps noticeably, collisions were nontrivial → consider increasing map.

**(2) Counter type u8 (0..255)**

* Type: **HARD**
* Rationale: standard fuzzing bitmap; counts aren’t your primary signal anyway.

**(3) TouchKey = (constraint_loc, major, minor)**

* Type: **HARD**
* Rationale: stable across builds and programs; keeps key space manageable.

**(4) FailKey = (constraint_loc, major, minor)**

* Type: **HARD** (and stored exact set)
* Rationale: small cardinality; no collisions.

**(5) What counts as touched: `X_t[i] > 0`**

* Type: **HARD**
* Rationale: simplest/robust.

---

### B) Action space / bucketing parameters

This is where you should *not* hardcode “128 buckets” blindly. It should be derived from budget.

Let:

* (N) = campaign budget (#mutations)
* (|\mathcal{K}|) = #mutation kinds (≈8)
* (n_{\text{target}}) = desired average samples per arm before you expect meaningful learning (choose 2–5)

**(6) Number of step buckets (B_{\text{count}})**

* Type: **DERIVED**
* Recommended formula:

[
B_{\text{count}} := \text{pow2_clamp}\left(\left\lfloor \frac{N}{|\mathcal{K}| \cdot n_{\text{target}}}\right\rfloor,\ B_{\min},\ B_{\max}\right)
]

Where:

* (n_{\text{target}}=3) (good default)
* (B_{\min}=16), (B_{\max}=128)

Example with N=1000, |K|=8:

* (1000/(8\cdot 3) \approx 41) → pow2 → 32 buckets
* Arms ≈ 8×32 = 256 → you’ll actually have enough pulls per arm for learning.

This is **strictly better** than hardcoding 128 buckets for a 1000-run budget.

**(7) Bucket size B (steps per bucket)**

* Type: **DERIVED**
  Given (T) (mutatable step count), define:
  [
  B := \left\lceil \frac{T}{B_{\text{count}}}\right\rceil
  ]
  Optionally round B to a power of two for convenience.

**(8) T (step horizon)**

* Type: **DERIVED**
  [
  T := 1 + \max(\cup_k S_k)
  ]
  (using mutatable steps, not cycles)

**(9) Forced exploration minimum pulls n_min**

* Type: **DERIVED** (don’t hardcode “2 or 3”)
* Rule:

If (N \ge #arms), you can afford “pull each arm once”:

* set `n_min=1` (each arm must be tried once before exploitation)

If (N < #arms), you can’t:

* set `n_min=0` and rely on UCB bonus / random exploration probability.

So:
[
n_{\min} := \mathbf{1}[N \ge #arms]
]

This is important because otherwise you’ll implement an impossible requirement.

**(10) Nested step-level bandit vs ε-greedy**

* Type: **HARD** choice (architecture)
* I still recommend nested bandit, but if it’s heavy, ε-greedy is fine. Not a “calibration” parameter.

---

### C) Reward shaping parameters

These are the ones that should mostly be **calibrated from pilot statistics**, not hardcoded.

**(11) Rolling window W**

* Type: **DERIVED** from budget, or **CALIBRATE ONCE**
* I recommend **DERIVED**:

[
W := \mathrm{clamp}(\lfloor 0.05N\rfloor,\ 30,\ 150)
]

**(12) Saturation threshold “median < 1”**

* Type: **HARD**
* It is effectively “median == 0,” which is a clean, robust condition.

**(13) τ_new (novelty scaling)**

* Type: **CALIBRATE ONCE**
* Calibrate from pilot runs (see plan below):

Let (\mathcal{D} = {\Delta^{new}_t > 0}) from the first `N_pilot` runs.

Set:
[
\tau_{\text{new}} := \mathrm{percentile}_{75}(\mathcal{D})
]
Clamp into [16, 256] to avoid extremes.

This makes the novelty score saturate on “large but realistic” novelty, not too early, not too late.

**(14) Rarity weight w(i) = 1/sqrt(1+freq[i])**

* Type: **HARD** initially
* Optional later tuning: exponent β in `1/(1+freq)^β` could be tuned, but not necessary for v1.

**(15) K_rare (how many rare bits you average)**

* Type: **CALIBRATE ONCE** or **DERIVED**
* Derive from median touched set size:

Let (U = \mathrm{median}(|U_t|)) in pilot. Choose:
[
K_{\text{rare}} := \mathrm{clamp}(\lfloor 0.02U \rfloor,\ 16,\ 64)
]

If your median |U_t| ≈ 1600 → 0.02U ≈ 32 → matches the earlier value.

**(16) τ_fail_new (=2)**

* Type: **HARD** (low sensitivity)
  Because `Δfail_new` is small integer, τ=1–3 doesn’t matter much. Keep 2.

**(17) τ_fail_count (cascade penalty strength)**

* Type: **CALIBRATE ONCE**
  Calibrate from pilot distribution of total failure instances (or distinct failures), depending on what `n_fail` means for you.

Let `n_fail_t` be your chosen failure-count metric (recommend: raw total failure instances, not distinct contexts, because cascade manifests in raw count).

Set τ_fail_count to the 75th percentile of `n_fail_t` among non-crash runs:
[
\tau_{\text{fail-count}} := \mathrm{percentile}_{75}(n^{fail})
]

This makes “typical” runs get mild penalty, “cascades” get strong penalty.

**(18) λ (failure novelty weight)**

* Type: **TUNE VIA A/B** (but default low)
  Start λ=0.2 and treat it as a knob you tune with A/B campaigns:
* λ too high → chases failures, likely less underconstraint-friendly
* λ too low → ignores useful signal

Given your stated goal (soundness bugs), keeping λ small is safer.

**(19) Q_t definition (crash=0, else exp(-n_fail/τ_fail_count))**

* Type: **HARD** functional form + τ calibrated
  Functional form is fine; τ calibrated.

---

### D) Bandit hyperparameters (nonstationarity + exploration)

**(20) Discount factor γ**

* Type: **DERIVED** from desired half-life (H)
  Do not tune γ directly. Choose half-life in iterations and derive γ:

[
\gamma := 2^{-1/H}
]

Choose:
[
H := \mathrm{clamp}(\lfloor 0.2N \rfloor,\ 50,\ 300)
]

Examples:

* N=1000 → H=200 → γ ≈ 2^{-1/200} ≈ 0.9965
* N=500 → H=100 → γ ≈ 0.9931

This is cleaner than guessing 0.995.

**(21) UCB exploration coefficient c**

* Type: **TUNE VIA A/B** (moderate sensitivity)
  Default c=0.25 is reasonable, but you should A/B c ∈ {0.15, 0.25, 0.4}.
  It affects how aggressively you explore under-sampled arms.

**(22) ε (numerical stability) = 1e-6**

* Type: **HARD**
  Not a tuning parameter.

---

### E) Mutation-value generation parameters

These are often *more important* than bandit hyperparameters for underconstraint success rate.

**(23) p_local schedule (0.7→0.4)**

* Type: **TUNE VIA A/B**
  This controls whether you mostly do small coherent edits vs huge random jumps.
  You want enough “local” to stay near satisfiable, but enough “global” to discover new regimes.

A/B on something like:

* schedule A: 0.8→0.6
* schedule B: 0.7→0.4
* schedule C: fixed 0.6

Measure:

* crash rate
* median failure count
* near-accept indicators (if any)
* rare-touch score

**(24) “interesting constants” set**

* Type: **HARD** list (engineering), but can expand over time based on observed bug patterns.

---

### F) Bug-mode parameters (only relevant if ACCEPTED happens)

**(25) bug-local-search budget fraction (20%)**

* Type: **TUNE LATER**
  Don’t spend time tuning until you have at least one accepted proof.

---

## 11.2 Where calibration fits into your master plan

You asked: *where do these calibrations go in the plan, and what experiments are needed?*

### Add one explicit phase: Phase II.1.5 — Pilot calibration (new)

Insert this between “build arms” and “run bandit”.

**Phase II.1.5 — Pilot calibration (N_pilot runs)**

* Run `N_pilot = min(100, max(30, 0.05N))` random mutations with a simple scheduler:

  * uniform over mutation kind
  * uniform over valid steps within kind
* Collect for each run:

  * `Δnew_touch`
  * `|U_t|`
  * `n_fail_t`
  * runtime
* Compute:

  * `τ_new` (75th percentile of Δnew > 0)
  * `τ_fail_count` (75th percentile of n_fail among non-crashes)
  * `K_rare` (2% of median |U_t| clamped 16..64)
  * `W` from budget formula
  * `γ` from half-life formula
  * `B_count` from budget formula (or you can compute B_count before pilot)

Then freeze these parameters for the main campaign.

This gives you **data-driven calibration** without a full expensive A/B sweep.

### Phase II.5 remains for A/B tuning of the few true knobs

Keep Phase II.5 exactly as in the plan, but now the things you A/B should be only:

* `c` (exploration aggressiveness)
* `λ` (failure novelty weight)
* `p_local schedule`
* optionally `B_count` if you want, but if you derive it from budget you may not need to

That’s a manageable A/B workload.

---

## 11.3 What should NOT be calibrated (and why)

To keep the system from becoming a “hyperparameter zoo,” these should stay fixed initially:

* TouchKey definition (loc, major, minor): stability/generalization
* novelty→rarity architecture: solves reward sparsity
* rarity functional form `1/sqrt(1+freq)`: standard diminishing returns, robust
* `sat` threshold “median == 0”: robust integer logic
* `τ_fail_new = 2`: low sensitivity
* `ε = 1e-6`: numeric
* MAP_SIZE=65536 unless collision evidence appears

---

## 11.4 What you should explicitly verify in your repo once this is implemented

After implementing Phase II.1.5 + main bandit:

1. **Arm coverage**: how many arms got tried at least once?
   If too few, c too low or arm space too large → reduce B_count.

2. **Reward distribution**:

   * fraction of runs with nonzero reward before/after saturation
   * how quickly sat flips

3. **Sensitivity checks**:

   * A/B `c` and `p_local` first (these usually dominate)
   * only then A/B `λ`

4. **Collision sanity**:

   * baseline `|U|` should be stable across runs
   * if increasing MAP_SIZE changes `|U|` materially, collisions exist → consider MAP_SIZE bump

---

### One last meta-point (because it affects many parameters)

**The most important derived quantity is the ratio:**
[
\frac{\text{campaign budget } N}{\text{number of arms}}
]
If this ratio is ~1, you cannot learn much; you’re just exploring.
If it’s ~5–20, bandit adaptation starts to matter.

That’s why **B_count must be derived from N and |K|**, not hardcoded.