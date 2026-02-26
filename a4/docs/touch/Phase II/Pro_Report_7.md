## Answers to your 2 questions

### 1) “NO_FAIL_BUT_REJECTED” / Z term: does this just target global constraints (since we haven’t instrumented them yet), and is that a problem?

It will *often* target “something beyond your current local-constraint observability,” and that’s **not a problem**—it’s actually a feature **as long as Z is a *small* bonus and properly gated**.

**Why it’s useful right now (local-only world):**

* A run with **zero local failures** means you managed to stay on (or very near) the manifold defined by the *local* constraint system you can see.
* Yet it’s still **REJECTED**, so rejection is likely coming from one of:

  1. **Global constraints** you haven’t instrumented yet (e.g., permutation / lookup / grand-product style arguments),
  2. **Non-constraint checks** (internal proof verification checks, structural consistency checks, etc.),
  3. Or an edge case where local checks are not firing but something else is inconsistent.
* In all three cases, Z is a **proxy for “you got deep enough that local constraints aren’t trivially catching you.”** That’s one of the best “depth” proxies you have until global instrumentation lands.

**Why it’s *not* dangerous (if you implement it correctly):**

* In your revised reward, Z is only **one component inside a weighted average** and then multiplied by Q. With the default weights you pasted, Z cannot dominate by itself; it’s a mild upward push, not a takeover.
* The real risk would be if Z fired for “shallow rejects” (e.g., early aborts) and you started optimizing toward those. That’s solved by gating.

**So the explicit implementation decision I recommend:**
Define Z as:

[
Z ;=; \mathbf{1}{\texttt{outcome==REJECTED};\wedge;\texttt{proof_generated==True};\wedge;d_{\text{fail}}=0}
]

Not just “(d_{\text{fail}}=0)”.
This pins Z to the thing you *actually* care about: “no local failures **and** we got far enough to produce a proof that fails verification”.

**How it will evolve once you add global constraint hooks:**

* Many “Z events” will stop being Z, because they’ll become “global-fail events”, and will be scored by the global failure-context novelty/rarity channel instead.
* Z then becomes a *rarer* signal: “no local fail, no global fail, still rejected” (which is very interesting in its own right).

So: **keep Z now**, implement the gating above, and don’t worry that it’s “targeting globals” before you’ve instrumented them—it’s the best proxy you have.

---

### 2) Why should failure run-frequency be **per-run-per-context** and not per-instance?

Because “per-instance” is *structurally* distorted by cascades and will destroy the meaning of rarity.

You already observed the phenomenon: a single mutation can cause a cascade with a very large number of failure **instances** (e.g., 159), while the number of distinct failure **contexts** in that run may be small (say 2–10). In other words:

* instances measure: “how many times did the prover emit a failure line”
* contexts measure: “which distinct constraint contexts did we get into trouble with”

If you let the global rarity frequency (f_F[c]) be per-instance, then **one cascade run** can instantly make a context look “very common”, even though it may be rare *across runs*.

Concretely:

* Suppose context (c) is triggered in exactly 1 run, but repeats 100 times due to propagation.
* Per-instance would do: (f_F[c] \leftarrow 100).
* Your rarity weight (w_F(c)=1/\sqrt{1+f_F[c]}) becomes (\approx 1/\sqrt{101}\approx 0.1).
* You just told the bandit: “this is extremely common and uninteresting” — **even though it happened only once across the campaign**.

That’s wrong for exploration.

So the correct separation is:

* **Cross-run “document frequency”** (what we use for rarity):
  [
  f_F[c] \leftarrow f_F[c] + 1 \quad \text{for each } c \in F_t
  ]
  once per run per context.

* **Within-run cascade magnitude** (what we penalize separately):
  [
  r_{\text{rep}}=\max(0, n_{\text{fail}}-d_{\text{fail}})
  ]
  This captures “repeat mass” without corrupting rarity.

This is exactly the split your plan already states (and it’s the right split).

---

## Guidance on the master plan you pasted

Overall, the structure is good and the ordering is right: **reward rework → verify reward variance → then implement the bandit**. That is exactly what you want before committing to Phase II.3.

Below are the changes I recommend to make the plan fully explicit and remove the remaining “optional / TBD” items.

---

## Fix one inconsistency in your plan (important)

In your “HARD parameters” table you wrote:

* **TouchKey = (constraint_loc, major, minor)**

But your reward definition uses:

* (U_t = { i : \text{bitmap}[i] > 0 })

So the scheduler’s “touch identity” is the **bitmap index** (i \in [0,65535]), not the triple.

**Make this explicit in docs and code:**

* Scheduler touch identity = **TouchBucketID** (i) (hashed).
* Verbose touch triples exist as a **diagnostic / analysis channel**, not the scheduling channel.

That matches the intended design in Pro_Report_4 (bitmap for scheduling, exact evidence only on interesting runs).

---

## Resolve your “Open Questions” with explicit decisions

### Open Q1: K_F_rare calibration (too sensitive if it becomes 1)

You’re right to worry about `0.1 * median(d_fail)` collapsing to 1.

**Explicit decision:**

* **Do not calibrate K_F_rare. Hardcode it.**
* Set:
  [
  K_{F,\text{rare}} := 2
  ]
* Define:
  [
  K_F := \min(K_{F,\text{rare}}, |F_t|)
  ]
* And:
  [
  F_{\text{rare}} := \frac{1}{K_F}\sum_{\text{top-}K_F \text{ rarest } c\in F_t} \frac{1}{\sqrt{1+f_F[c]}}
  ]

**Why 2 is the right “fully-specified” choice:**

* It preserves the desired semantics: “reward runs that hit at least one or two rare failure contexts, even if accompanied by common ones.”
* It is stable when (|F_t|) is small (your empirical case), and still meaningful when (|F_t|) grows (future global constraints).
* It eliminates a fragile calibration knob.

So: remove `K_F_rare` from pilot calibration entirely.

---

### Open Q2: Weight sensitivity (what do we do now vs Phase II.5?)

Your Phase II.2V is the right place to sanity check defaults, **not to tune**.

**Explicit decision: keep your default weights for II.2R + II.2V:**

* (a_{Tn}=1.0)
* (a_{Tr}=0.25)
* (a_{Fn}=1.0)
* (a_{Fr}=1.0)
* (a_Z=1.0)

Rationale: this makes **failure novelty + failure rarity co-primary**, which matches the empirical finding that failure-context novelty has bandwidth even when touch novelty saturates.

Then in II.5 you do a *small* A/B grid (keep it minimal):

* Variant A (default): (1.0, 0.25, 1.0, 1.0, 1.0)
* Variant B (less Z): (1.0, 0.25, 1.0, 1.0, 0.5)
* Variant C (less touch novelty): (0.5, 0.25, 1.0, 1.0, 1.0)

Stop there. Don’t explode the grid.

This aligns with how fuzzing literature treats scheduling: you want a few robust schedules/weights rather than over-tuning (e.g., AFLFast and FairFuzz focus on rarity/rare branches rather than huge parameter sweeps). ([Marcel Böhme][1])

---

### Open Q3: Baseline seeding affects f_T and thus T_rare — is that correct?

**Yes, baseline seeding should increment f_T for baseline-touched buckets** (i.e., start them at 1), exactly as you suspected.

If you *don’t* seed frequency, then at time 0:

* baseline buckets have (f_T[i]=0)
* (w_T(i)=1/\sqrt{1+0}=1)
* so **T_rare becomes a constant ≈ 1 for almost every run**, especially in your empirical regime where most mutation kinds touch the same set immediately.

Baseline seeding turns frequency into a *prior* that makes rarity meaningful from the beginning.

**Explicit decision:**

* During CoverageState initialization:

  * set `seen_touch[i]=1` for all baseline-touched (i),
  * set `freq_touch[i]=1` for those (i).
* Do not increment fail_freq from baseline (baseline has no failures anyway).

This is consistent with the intended use of frequency arrays as run-frequency in Pro_Report_4’s scheduler state description.【141:11†Pro_Report_4.md†L11-L21】

---

## Fill the remaecisions from Pro_Report_4

### 1) Step selection: choose nested discounted-UCB, not ε-greedy

You already wrote this in the plan as “unchanged”, but here’s the explicit decision:

**Use nested discounted-UCB over steps** inside the chosen (kind, bucket).
This is the “most likely to work” choice because it quickly concentrates on steps that actually yield signal without hand tuning an ε. It’s also what was recommended originally.【141:0†Pro_Report_4.md†L53-L75】

**Explicit spec:**

* Mts for each (kind, step): (N_{k,s}, S_{k,s}, t_{k,s}).
* When an arm (k,b) is chosen, pick:
  [
  s \in S_{k,b} \text{ maximizing } \mu_{k,s} + c_s \sqrt{\frac{\log(1+N^{(k,b)}*{\text{tot}})}{\max(N*{k,s},\epsilon)}}
  ]
* Use:

  * (\gamma_s = \gamma = 0.995)
  * (c_s = c = 0.25)
  * (n_{\min,s} = 1)

This keeps the system coherent: one discount factor, one exploration constant.

---

### 2) Forced exploration: set n_min = 1 (not 2–3)

In Pro_Report_4, I suggested (n_{\min}=2) or 3 as a generic safe value.【141:0†Pro_Report_4.md†L40-L47】
Given your *actual ar00), and the fact you’re already using discounting (so old counts decay), **n_min=2 will cause too much repeated forced exploration**.

**Explicit decision:**

* Set forced exploration threshold:
  [
  n_{\min}=1
  ]
  for both arm-level and step-level.

That ensures every arm gets at least one sample “recently enough” under discounting, without turning the campaign into a uniform sampler.

---

### 3) Discounted-UCB parameters: keep γ=0.995, c=0.25, ε=1e-6 as defaults

These were already specified in Pro_Report_4.【141:0†Pro_Report_4.md†L14-L38】

* (\gamma = 0.995) gn on the order of a couple hundred iterations.
* (c = 0.25) is a moderate exploration bonus for bounded rewards.

This is also consistent with why discounted UCB exists in the first place: non-stationary reward landscapes (“rotting” rewards / novelty decay) break standard UCB1. ([arxiv.org][2])

So: keep these hardcoded for the first full test; tune only in Phase II.5 if needed.

---

### 4) Two-mode value generation: implement it now, but don’t add another arm dimension yet

In Pro_Report_4 I recommended a two-mode distribution (local coherent moves vs global jumps) controlled by (p_{\text{local}}).【141:0†Pro_Report_4.md†L78-L98】

**Explicit decision (best tradeoff right now):**

* Implemenation **as part of the mutation generator**, not the bandit.
* Use a *constant* (p_{\text{local}}=0.7) for Phase II.3–II.4 (first bandit integration).
* Only introduce a decay schedule or add “mode” into the arm space after you have baseline A/B results.

**Why this is the right sequencing:**

* The bandit is already learning a nonstationary environment (novelty/rarity evolves). Adding a time-varying (p_{\text{local}}) schedule at the same time is an extra confounder.
* You want your first UCB integration to be interpretable.

Then in Phase II.5 you can test:

* constant 0.7
* constant 0.5
* schedule 0.7→0.4

This is also in the spirit of mutation scheduling work like MOpt: you want the scheduling layer and the mutation layer separable so you can attribute gains correctly. ([USENIX][3])

---

## One more important “explicitness” change: define exactly what gets updated on CRASH / missing data

Right now, plans often accidentally “poison” coverage state with partial runs.

**Explicit decision:**

Let `valid_run` mean:

* has a touch bitmap, and
* parsed failures successfully, and
* not CRASH.

Then:

* If `valid_run == False`:

  * set (r_t := 0)
  * **update bandit stats** with reward 0 (so it learns to avoid these arms)
  * **do not update** coverage frequencies (`f_T`, `f_F`) or seen sets.

This prevents crashes from shifting rarity/novelty statistics.

---

## Final: your fully explicit “100% spec” for the architecture (as I recommend you implement it now)

This is the exact spec I would hand to Opus as the final ground truth for Phase II.3–II.4 implementation.

### A) Action space (unchanged)

* Arms (a=(k,b)) where:

  * (k) = mutation kind
  * (b) = step bucket
  * (S_{k,b}\neq \emptyset)

Bucketing remains an *action-space compression* tool, not a coverage definition tool.【141:6†Pro_Report_4.md†L24-L25】

### B) Global state

* Touch:

  * `seen_touch[i] ∈ {0,1}` for (i\in[0,65535])
  * `freq_touch[i] ∈ ℕ` = number o
* Fail contexts:

  * `fail_seen[c] ∈ {0,1}` (can be a set)
  * `fail_freq[c] ∈ ℕ` = number of valid runs whose (F_t) contained context (c)

### C) Per-run observations

From a run result:

* (U_t = { i : X_t[i] > 0})
* (F_t = {\text{distinct }(\text{constraint_loc},\text{major},\text{minor})\text{ in failures}})
* (n_{\text{fail}} =) number of failure instances (raw)
* (d_{\text{fail}} = |F_t|)
* (r_{\text{rep}} = \max(0, n_{\text{fail}} - d_{\text{fail}}))

### D) Novelty deltas (computed **before** updating global state)

* (\Delta_T = |{i\in U_t : seen_touch[i]=0}|)
* (\Delta_F = |{c\in F_t : fail_freq[c]=0}|)

### E) Score components

Parameters:

* (\tau_T) (calibrated once)
* (\tau_{F,\text{new}} = 2.0) (hard)
* (\tau_d) (calibrated once)
* (r_0 = 10) (hard)
* (\tau_r = 25) (hard)
* (K_{T,\text{rare}} = \text{round}(0.02\cdot |U_{\text{baseline}}|)) clamped to [16, 64]
* (K_{F,\text{rare}} = 2) (hard)
* (\epsilon = 10^{-6})

Scores:

* Touch novelty:
  [
  T_{\text{new}} = 1 - e^{-\Delta_T/\tau_T}
  ]

* Touch rarity:
  [
  w_T(i) = \frac{1}{\sqrt{1+freq_touch[i]}}
  ]
  Let (K_T=\min(K_{T,\text{rare}}, |U_t|)). Then
  [
  T_{\text{rare}} = \frac{1}{K_T}\sum_{\text{top-}K_T \text{ rarest } i\in U_t} w_T(i)
  ]

* Failure novelty:
  [
  F_{\text{new}} = 1 - e^{-\Delta_F/\tau_{F,\text{new}}}
  ]

* Failure rarity:
  [
  w_F(c) = \frac{1}{\sqrt{1+fail_freq[c]}}
  ]
  Let (K_F=\min(2,|F_t|)). Then
  [
  F_{\text{rare}} = \frac{1}{K_F}\sum_{\text{top-}K_F \text{ rarest } c\in F_t} w_F(c)
  ]
  If (|F_t|=0), set (F_{\text{rare}}=0).

* Z indicator (gated):
  [
  Z = \mathbf{1}{\texttt{outcome==REJECTED}\wedge \texttt{proof_generated==True}\wedge d_{\text{fail}}=0}
  ]

### F) Quality multiplier Q

If crash or missing bitmap: (Q=0).
Else:

* distinct-fail penalty:
  [
  Q_{\text{dist}} = e^{-d_{\text{fail}}/\tau_d}
  ]
* cascade penalty:
  [
  Q_{\text{rep}} =
  \begin{cases}
  1 & r_{\text{rep}}\le r_0\
  e^{-(r_{\text{rep}}-r_0)/\tau_r} & r_{\text{rep}} > r_0
  \end{cases}
  ]
* (Q = Q_{\text{dist}}\cdot Q_{\text{rep}})

### G) Final reward

Weights (hard for II.2V):

* (a_{Tn}=1.0)
* (a_{Tr}=0.25)
* (a_{Fn}=1.0)
* (a_{Fr}=1.0)
* (a_Z=1.0)

[
S = \frac{a_{Tn}T_{\text{new}} + a_{Tr}T_{\text{rare}} + a_{Fn}F_{\text{new}} + a_{Fr}F_{\text{rare}} + a_Z Z}{a_{Tn}+a_{Tr}+a_{Fn}+a_{Fr}+a_Z}
]

[
r_t = \min(1, Q\cdot S)
]

Override:

* If verifier ACCEPTED: (r_t=1).

### H) Bandit (Discounted-UCB) over arms

Use the discounted stats + lazy decay and UCB index from Pro_Report_4.【141:0†Pro_Report_4.md†L14-L38】

* (\gamma=0.995, c=0.25, \epsilon=10^{-6}, n_{\min}=1).

Discounted-UCB is a standard approach for nonstationaryg-window UCB are analyzed by Garivier & Moulines). ([arxiv.org][2])

### I) Nested step bandit inside chosen arm

Use the same discounted-UCB structure over steps in (S_{k,b}) (recommended in Pro_Report_4).【141:0†Pro_Report_4.md†L59-L75】

### J) Mutation value generation

Implement two-mode generator now (local vs global), but keep (p_{\text{local}}=0.7) constant for the first end-to-end bandit expL82-L94】

---

## Final “should anything be improved?” notes on your plan

1. **Add the Z gating condition** (REJECTED + proof_generated) exactly as above.
2. **Remove K_F_ it to 2.
3. **Fix the TouchKey naming**: scheduler uses bitmap indices; triples are diagnostic.
4. **Make crash/missing-bitmap update rules explicit** (bandit gets 0; coverage state not updated).
5. **Set forced exploration n_min=1** for discounted forced exploration (otherwise decay will force too much resampling).

Everything else in your Phase II.2R → II.2V → II.3 ordering looks correct.

---

## One “step back” justification (why this is still the best model)

This architecture is essentially: **rarity-guided coverage scheduling + nonstationary bandit control**.

That combination is well aligned with:

* classic fuzzing insights that *rarity* is a good proxy for “deep/interesting regions” (AFLFast / FairFuzz style logic), ([Marcel Böhme][1])
* empirical work showing mutation scheduling matters (MOpt), ([USENIX][3])
* and evidence that bandit schedulers are effective for fuzzing decision points (seed scheduling via Thompson sampling in T‑Scheduler; bandit fuzzing in other domains like MABFuzz). ([GitHub][4])

Given your constraint system’s strong nonstationarity (novelty decay, rarity drift), discounted-UCB is the right “simple but principled” choice. ([arxiv.org][2])

---

If you paste the open questions Opus raised outside the plan (or any diffs in `coverage_state.py` you’re about to implement), I can sanity-check the exact reward component computations and make sure nothing subtle (like update-order or counting rules) breaks the intended semantics.

[1]: https://mboehme.github.io/paper/CCS16.pdf?utm_source=chatgpt.com "Coverage-based Greybox Fuzzing as Markov Chain"
[2]: https://arxiv.org/abs/0805.3415?utm_source=chatgpt.com "On Upper-Confidence Bound Policies for Non-Stationary Bandit Problems"
[3]: https://www.usenix.org/conference/usenixsecurity19/presentation/lyu "MOPT: Optimized Mutation Scheduling for Fuzzers | USENIX"
[4]: https://github.com/asiaccs2024-t-scheduler/t-scheduler "GitHub - asiaccs2024-t-scheduler/t-scheduler"
