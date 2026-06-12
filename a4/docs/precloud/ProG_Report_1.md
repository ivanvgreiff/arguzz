I read **MAB_ARCHITECTURE_REVIEW.md** (current architecture description + issues + cloud-scaling questions) and **boss_presentation.html** (older results, pre–global-hook reward usage). I’m going to be blunt: **you should not launch large Google Cloud campaigns with the current “global-blind reward + Z bonus” unchanged**. The older results already show *why* the bandit looks “similar” to baseline under the metrics you care about, and your current architecture review identifies the precise mechanism: **Hook 3 global data is flowing into `MutationResult`, but `compute_reward()` still treats global behavior through a single coarse proxy (Z)**, so the bandit can only “learn” a very lossy objective. 

What follows is:

1. what the older notebook actually demonstrates (and what it doesn’t),
2. why it’s unsurprising it didn’t improve the specific coverage curves you expected,
3. the **single best** concrete modification to make before cloud, including explicit revised formulas,
4. a concrete cloud A/B plan that will actually answer your hypothesis, and
5. what to show (and not show) in a final boss-facing notebook.

---

## 1) What boss_presentation.html actually shows

Your older comparison (Uniform vs Bandit-16, 1000 mutations, same guest program / seed) reports:

* **Distinct failure contexts:** Uniform 346 vs Bandit-16 325
* **Distinct failure families:** Uniform 33 vs Bandit-16 30
* **Z events:** Uniform 104 vs Bandit-16 129
* **Mean reward:** Uniform 0.0726 vs Bandit-16 0.0804 

So the correct statement is:

* The bandit **did** learn something (it increased mean reward and increased Z events), but
* It **did not improve** “distinct local-failure coverage” (it was slightly worse).

That’s not a paradox. It’s exactly what you should expect when:

* your reward gives a **discrete, high-value bonus** for Z-like runs (no local fails but rejected), and
* you are evaluating success mainly with **local failure context/family growth**, which Z runs contribute little to in the old instrumentation regime. 

In other words: **the bandit optimized the objective you gave it**, but your *evaluation metric* was partly misaligned with that objective.

This matters because you are now in a different regime:

* You have global hooks (Hook 3) producing *broken-family and broken-index/address* information, but
* the reward is still mostly treating that world via an old proxy (“Z”). 

So a cloud run with the current reward will very likely scale up the same phenomenon: “learn to chase Z-like structure,” but not necessarily expand the specific coverage curves you’re plotting.

---

## 2) Why the old MAB looked “almost the same as baseline” (even if it wasn’t)

There are **three** independent reasons, all visible in your architecture review + notebook:

### 2.1 The bandit’s *step-level* learning wasn’t active

Your analysis indicates:

* Arm-level selection did use UCB for a large fraction of choices, but
* **step-level UCB never fired** because each arm has too many candidate steps, so step selection remains cold-start/uniform. 

So even if the arm-level bandit is nontrivial, your overall behavior was still close to:

> pick a (kind, bucket) somewhat intelligently; then pick an actual step basically at random.

That can absolutely look “close” to baseline if your baseline already spreads across buckets reasonably.

### 2.2 With 1000 mutations and ~128 arms, you get low pulls/arm

Your own numbers: with 128 arms, 1000 total pulls means ~8 pulls/arm on average (after pilot). That’s *tiny* for any UCB-style algorithm, especially with high noise and non-stationary novelty rewards.

So: you should not expect dramatic divergence at N=1000 unless reward differences between arms are huge.

### 2.3 Reward/coverage misalignment via the Z “cliff”

Your architecture review explicitly flags the core issue: Z runs get a large consistent contribution, but they do not discriminate *which* global structure is broken (memory vs u8 vs u16 vs cycle, and which indices/addresses). 

That creates a “binary cliff”:

* Either you hit Z and get a big bump,
* or you don’t and you’re competing on smaller, noisier components.

That cliff can drive the bandit to concentrate on a few mutation kinds that generate Z, at the expense of “failure context novelty,” which is exactly what your old curves report. 

---

## 3) The decisive pre-cloud change: stop being global-blind

Your review document calls this the “central question,” and it’s correct: **Hook 3 global data exists and is unused by the reward.** 

You listed Options A–G for integrating Hook 3 into the reward. 
I’m going to make a hard call:

### My recommendation: implement **Option G (unify failure contexts)**, with one surgical adjustment to Q

**Why Option G is the best pre-cloud move**

* It is the **cleanest architectural move**: you already have novelty/rarity machinery (`F_new`, `F_rare`, `fail_freq`) that is *exactly* the right abstraction for “interesting sparse events.”
* It avoids creating a new zoo of per-family weights (Option B/F) that you’ll end up arguing about in meetings.
* It converts the thing the bandit is currently “chasing blindly” (Z) into **high-bandwidth, structured reward**, so you can actually measure “constraint-space exploration” at the global level, not just local.

Option D (address-level rarity as a separate component) is also viable, but it adds another component/weight/state that you don’t need if you unify contexts properly.

### The one adjustment: don’t let global contexts break your cascade logic

Your current Q splits distinct-failure penalty vs cascade-repeat penalty (designed for local failures where you have many repeated instances). Global hook “failures” are already deduped (addresses/indices), so “repeat mass” doesn’t mean the same thing.

So the rule is:

* **Treat global contexts as “contexts” for novelty/rarity, but don’t let them inflate the cascade-repeat penalty.**
* Optionally add a mild “global-distance” penalty based on how many global contexts appear (to downweight extremely broken runs).

This preserves the intent of Q:

* “don’t chase garbage cascades”
  while allowing global failures to be rewarding and differentiating.

---

## 4) Explicit revised reward specification (cloud-ready)

I’m writing this in a way you can literally hand to Opus as the new spec.

### 4.1 Per-run observations

From one mutation run (t):

**Touch signal** (same as now):

* (U_t = { i : \text{touch_bitmap}[i] > 0 })

**Local failure contexts** (already exist):

* (F^{\text{loc}}_t = { (\text{constraint_loc}, \text{major}, \text{minor}) })
  (distinct per run)

Let:

* (d_{\text{loc}} = |F^{\text{loc}}_t|)
* (n_{\text{loc-inst}} = ) raw local failure instance count (including repeats)
* (r_{\text{rep}} = \max(0, n_{\text{loc-inst}} - d_{\text{loc}}))

**Global failure contexts** (newly used, from Hook 3 parsing):

Let the hook output provide:

* `broken_families ⊆ {memory, u8, u16, cycle}`
* `family_details`: lists of up to 10 memory addresses and up to 20 lookup indices per family (per your review). 

Define a canonical set of global contexts:

[
F^{\text{glob}}_t =
{ (\text{GLOBAL}, \ell, a) : a \in \mathcal{A}^{\ell}_t }
]

Where:

* For (\ell=\text{memory}), (a) is the broken memory address (or register-tagged address if you already canonicalize `x17` etc).
* For (\ell \in {\text{u8},\text{u16},\text{cycle}}), (a) is the broken lookup index.

Let:

* (d_{\text{glob}} = |F^{\text{glob}}_t|)

**Extended failure context set**:

[
F^{\text{ext}}_t = F^{\text{loc}}_t \cup F^{\text{glob}}*t
]
[
d*{\text{ext}} = |F^{\text{ext}}_t|
]

### 4.2 Global state

Maintain:

* Touch “seen” bitmap (G[i]) and run-frequency (f_T[i]) (as now)
* Extended failure run-frequency (f_F[c]) for contexts (c\in) union of local+global keys

**Crucial:** increment (f_F[c]) **once per run per context**, not per instance (you already made this design choice for locals; keep it for globals too).

### 4.3 Novelty terms

Touch novelty count (same):

[
\Delta_T = |{ i \in U_t : G[i]=0 }|
]

Failure-context novelty count (now includes global):

[
\Delta_F = |{ c \in F^{\text{ext}}_t : f_F[c] = 0 }|
]

### 4.4 Component scores

Keep your saturating transforms:

[
T_{\text{new}} = 1 - \exp(-\Delta_T/\tau_T)
]
[
F_{\text{new}} = 1 - \exp(-\Delta_F/\tau_F)
]

Rarity weights:

[
w_T(i)=\frac{1}{\sqrt{1+f_T[i]}}
\qquad
w_F(c)=\frac{1}{\sqrt{1+f_F[c]}}
]

Touch rarity (same as before, top-K):

[
T_{\text{rare}} = \frac{1}{K_T} \sum_{i \in \text{top-}K_T(U_t)} w_T(i)
]

Failure rarity (now over extended contexts):

[
F_{\text{rare}} = \frac{1}{K_F} \sum_{c \in \text{top-}K_F(F^{\text{ext}}_t)} w_F(c)
]

### 4.5 Replace Z with a properly-defined “unknown rejection” indicator

With global hooks in place, the original Z (“no local failures but rejected”) is no longer the right signal, because global failures are no longer invisible.

Define:

[
U = \mathbb{1}[\texttt{REJECTED} \wedge \texttt{proof_generated} \wedge d_{\text{loc}}=0 \wedge d_{\text{glob}}=0]
]

Interpretation:

* “passed all instrumented local constraints, and Hook 3 says no global family residue mismatch; yet verifier rejected.”
  This is *the* near-acceptance / instrumentation-gap regime. It deserves a bonus and a special log bucket.

### 4.6 Quality multiplier Q

Keep your intent:

* penalize lots of distinct local failures (far from coherent)
* penalize local cascades (repeat mass)
* optionally penalize very many global failures (very broken)

**Local distinct penalty**:

[
Q_{\text{loc}} = \exp(-d_{\text{loc}}/\tau_d)
]

**Local cascade penalty** (same as your current form, keyed off (r_{\text{rep}})):

[
Q_{\text{rep}} =
\begin{cases}
1 & r_{\text{rep}} \le r_0 \
\exp(-(r_{\text{rep}}-r_0)/\tau_r) & r_{\text{rep}} > r_0
\end{cases}
]

**Global “too-broken” penalty (new, mild)**:

[
Q_{\text{glob}} = \exp(-d_{\text{glob}}/\tau_g)
]

Set (\tau_g) noticeably larger than (\tau_d) (global is coarse/truncated; don’t over-penalize).

Finally:

* if crash or missing coverage: (Q=0)
* else:

[
Q = Q_{\text{loc}} \cdot Q_{\text{rep}} \cdot Q_{\text{glob}}
]

### 4.7 Final reward

Weighted average, then multiply by Q:

[
S = \frac{a_{T_n}T_{\text{new}} + a_{T_r}T_{\text{rare}} + a_{F_n}F_{\text{new}} + a_{F_r}F_{\text{rare}} + a_U U}{a_{T_n}+a_{T_r}+a_{F_n}+a_{F_r}+a_U}
]
[
r_t = \min(1, Q\cdot S)
]

Override:

* if verifier ACCEPTED: (r_t=1)

### 4.8 Default weights (explicit decision)

Given the empirical story in your older notebook (touch novelty heavily concentrated in ITYPE; Z heavily concentrated in IWORD), you want a reward that:

* still values touch novelty (so ITYPE stays relevant),
* strongly values failure-context novelty/rarity (now including global),
* gives unknown rejection a meaningful but not dominant bonus.

Use:

* (a_{T_n}=1.0)
* (a_{T_r}=0.25)
* (a_{F_n}=1.0)
* (a_{F_r}=1.0)
* (a_U=1.0)

That’s the **simplest** “co-primary” continuation of your existing philosophy, but with Z made semantically correct post-Hook-3.

---

## 5) Should you block on this before Google Cloud?

**Yes. Block.** Here’s why:

* Your current architecture review explicitly states Hook 3 signals exist but are not used by `compute_reward()`, and that Z is now the wrong coarse proxy. 
* The older results already show the bandit reallocated budget in pursuit of Z-like reward; scaling that up without integrating the global structure risks spending a lot of cloud budget optimizing a reward that does not expose the fine-grained “global constraint space.” 
* The modification above is **mechanical** and does not require new instrumentation—just using what you already collect.

If you skip this, a cloud run might still be “useful,” but it won’t answer your main hypothesis (“better constraint-space exploration”) because you’re still measuring global behavior with a single bucket.

---

## 6) Concrete cloud experiment plan that will actually answer the hypothesis

You want to answer:

> Does MAB discover “interesting constraint structure” faster than random?

Since ACCEPTED is still likely to be zero in early cloud runs, you need proxy endpoints.

### 6.1 Endpoints (what you should optimize / compare)

Define these **primary endpoints** (all cumulative curves over mutation index):

1. (C_F^{\text{ext}}(t)): cumulative distinct **extended failure contexts**

   * local contexts + global contexts (GLOBAL,family,index/address)

2. (C_F^{\text{glob}}(t)): cumulative distinct **global contexts only**

   * this is the “global constraint-space exploration” curve

3. (C_U(t)): cumulative count of **unknown rejections** (U=1)

   * “passed local + passed Hook3-global, still rejected”

Define **secondary** endpoints:

4. (C_T(t)): cumulative touch bitmap novelty (as you already do)

5. Distribution of “distance” measures:

   * histogram of (d_{\text{loc}})
   * histogram of (d_{\text{glob}})
   * histogram of (d_{\text{families}} = |\mathcal{G}_t|)

Those show whether the bandit is biasing toward “closer-to-valid” runs.

### 6.2 Baselines you must run

For A/B you need at least:

* **Uniform-Arm baseline**: sample arms uniformly from the same arm universe (kind × bucket), then sample step uniformly inside bucket.
  (This is a cleaner baseline than “zoned” if you want to isolate bandit effect.)

* **Bandit**: same arm universe, same pilot budget, then Discounted-UCB.

If you include a pilot in bandit, you must also “burn” the same number of runs in baseline for fairness (or analyze curves with pilot boundary clearly marked).

### 6.3 Budgets

Given 128 arms (8×16), 1000 runs is too small for stable learning. Your own scaling question already frames 5k/10k/50k/100k. 

Concrete decision:

* **Start with N = 20,000 per campaign** (Uniform vs Bandit).
  This yields ~156 pulls/arm on average at 128 arms. That’s enough for UCB to begin differentiating.

Then:

* If you see signal separation in curves, go to N=50k.
* If you see no separation by 20k, either:

  * reward is still not informative, or
  * the environment is truly “flat” for this guest program (bandit can’t help).

### 6.4 Replicates (statistical validity)

Single seed isn’t statistically valid (your review says this explicitly). 

Concrete decision:

* Run **R = 5 replicates per strategy** (Uniform and Bandit), with different RNG seeds, same guest program+inputs.
* Report:

  * mean curve and 95% bootstrap CI for each endpoint

This is cheap on cloud relative to arguing about one seed.

### 6.5 Arm count / bucket count scaling

You currently run with B_count=16 (128 arms). 

Concrete decision for cloud:

* Keep **B_count=16** for the first 20k A/B replicate batch.
  Rationale: isolate the reward/global integration effect first.

Then optionally test:

* **B_count=32** (256 arms) at N=50k if you want finer step-region resolution.

Do **not** change B_count and reward simultaneously in the first cloud experiment.

### 6.6 Weight A/B protocol (avoid combinatorial explosion)

Don’t grid-search all weights. Do this:

* Freeze weights as given above for the first cloud A/B.
* If bandit wins on (C_F^{\text{glob}}) and/or (C_F^{\text{ext}}), then explore weight sensitivity with *one-factor-at-a-time*:

Test only these 3 variants:

* Variant 0 (default): (a_U=1)
* Variant 1 (more near-acceptance): (a_U=2)
* Variant 2 (less near-acceptance): (a_U=0.5)

Everything else fixed.

---

## 7) Should you worry about the old notebook’s “no improvement”?

### 7.1 It’s not shocking at N=1000

At 1000 runs, the arm pulls are too small; step-level policy not active; and reward is coarse in the global regime. So yes, a big part of “why no improvement” is simply budget + mis-specified reward.

### 7.2 But there’s a deeper possibility

Even at large N, a bandit can’t create new reachable behaviors if:

* your mutation catalog mostly produces the same constraint structures, or
* the constraint system rejects quickly and deterministically no matter what, producing low-variance reward across arms.

Your own older notebook already suggests the reward “regimes” are basically:

* IWORD → Z-heavy, high-Q
* ITYPE → novelty-heavy, lower-Q

If the world truly collapses to those two regimes for that guest program, a bandit won’t look magical.

That’s why the global integration is so important: it creates new, structured differentiation inside “Z land.”

---

## 8) What to show bosses in the final Google Cloud notebook

You asked what’s signal vs noise. Here’s the boss-facing structure I’d recommend.

### 8.1 Executive summary: 4 numbers (not 40 plots)

At the top, for each strategy (averaged over R replicates):

* **Final (C_F^{\text{glob}})** at N (distinct global contexts discovered)
* **Final (C_F^{\text{ext}})** at N (distinct total failure contexts discovered)
* **Final (C_U)** (unknown rejections count)
* **Wall-clock per 10k mutations** (so they can price the improvement)

Include % improvement with CI.

### 8.2 Three “money plots”

1. **Cumulative global-context coverage curve**
   (C_F^{\text{glob}}(t)) with CI bands

2. **Cumulative extended-context coverage curve**
   (C_F^{\text{ext}}(t))

3. **Near-acceptance quality profile**
   Histogram or ECDF of (d_{\text{loc}}) and (d_{\text{glob}})
   (“Bandit shifts mass toward fewer broken constraints” is a meaningful claim.)

### 8.3 Show that the bandit is *actually* behaving like a bandit

One heatmap:

* x-axis = time (e.g., bins of 1k mutations)
* y-axis = arms (kind × bucket)
* value = fraction of pulls

You want to show exploitation evolves (not static random). If it stays uniform, that’s the story.

### 8.4 “Z events” should be reframed, not centered

Given Hook 3, raw Z is obsolete. Replace it with:

* “Local-pass but global-fail” rate
* “Local-pass and global-pass but reject (U)” rate

Those are much more interpretable post-global instrumentation.

### 8.5 Don’t overemphasize mean reward

Mean reward is useful only to show internal consistency (“the bandit optimized what it was told”). It is not, by itself, evidence of better constraint exploration.

### 8.6 Include a short table of “Top 20 most interesting runs”

Define “interesting” as:

* ACCEPTED (if any) first
* else U=1 (unknown rejection) next
* else smallest (d_{\text{glob}}) among global-only failures
* else rarest global contexts (highest (F_{\text{rare}}) contributions)

For each run, show:

* mutation kind, bucket, step
* broken families list
* broken indices/addresses
* verifier error string(s)

This is the part bosses (and auditors) remember.

---

## 9) Final decision: are you “good to go” for cloud as-is?

**No** — not if your aim is to run expensive campaigns and come back with a definitive statement about “constraint-space exploration.”

### The minimal “good to go” checklist

Before cloud runs, you should:

1. Implement **global-aware reward** via Option G (unified failure contexts) + the revised U indicator. 
2. Add counters/curves for (C_F^{\text{glob}}), (C_F^{\text{ext}}), and (C_U).
3. Run a **local validation campaign** (200–500 mutations) just to sanity-check:

   * global contexts are being extracted nontrivially
   * reward differs across arms and across runs
4. Then run the **cloud A/B** with N=20k, R=5 replicates, B_count=16 fixed.

If you do this, you’ll get a real answer. If you skip it, you risk spending cloud budget to rediscover that “bandit increases Z” without learning *which* global structures it’s exploring.

---

## 10) One “future but high-leverage” extension I’d keep on the roadmap

Your review notes BigInt global hooks don’t cover the BigInt polynomial accumulator, but BigInt failures still appear as local `phase:accum` failures when they happen. 

So: **don’t block on BigInt**.

But once your cloud experiment infra is running, you should absolutely add a mutation kind aimed at BigInt precompiles / ECALL dispatch if the guest program uses them (or create a guest that does). That’s an obvious “new constraint region” expansion.

---

If you want, paste (or attach) the *current* `compute_reward()` implementation and the parsed Hook 3 structure keys (what exactly your `MutationExecutionResult` contains). I can then map the spec above into the exact variable names and the minimal code changes you need before cloud.
