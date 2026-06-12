I read:

* `Pro_Report_9_Input.md` (scheduler diagnosis + simulation)
* `Q_and_A.md` (Claude’s take + a couple incorrect claims)
* `boss_presentation.ipynb` (what you plan to show your bosses)
* `1000_MUT_CAMPAIGN_REPORT.md` (full campaign report)

And the story is now very clear: **your bandit is behaving like random because, with the current scheduler logic, the UCB branch is effectively dead**. Your notebook is honestly reflecting reality; it’s not a visualization problem first — it’s a **scheduler correctness problem**.

Below is the concrete diagnosis, the minimum fix that makes the bandit “real,” what to rerun, and exactly how I’d reshape the boss notebook so it tells the right story.

---

## 1) Why the bandit looks identical to uniform

### 1.1 The critical fact

Per `Pro_Report_9_Input.md`, with your production parameters:

* **254 arms** (8 kinds × 32 buckets, 254 valid)
* **γ = 0.9965** (half-life ≈ 200 bandit rounds)
* **n_min = 1.0**
* **946 bandit rounds**

…the scheduler’s `select()` **never reaches the UCB selection branch**. It always finds at least one arm with `N_a < n_min`, so it always does *forced exploration*, which is random over `under_explored`. This is stated explicitly in the file:

> “The bandit's Discounted-UCB selection logic never fires. 100% of all selections are forced exploration.” (`Pro_Report_9_Input.md`, §1–§3)

The simulation table there confirms **0% UCB selection** for the current config, and “more budget does not help” under that logic.

### 1.2 The mechanism (why UCB is dead code)

Your forced exploration criterion is:

> under_explored = { a : discounted_N[a] < n_min }

But **discounted_N decays for every arm that isn’t pulled recently**. With many arms, there is always a long tail of arms not pulled in the last ~O(K) rounds, and their discounted N inevitably decays below 1.0.

Even in the “best case,” suppose an arm was just pulled and ended with `N_after ≈ 1.3` (as Pro_Report_9_Input’s example), after ~254 rounds (typical revisit timescale with ~254 arms), it becomes:

* ( N \approx 1.3 \cdot \gamma^{254} )
* ( \gamma^{254} \approx 0.9965^{254} \approx e^{254 \ln 0.9965} \approx e^{-0.89} \approx 0.41 )
* so ( N \approx 0.53 < 1.0 )

So by the time you revisit, it’s under-explored again. Therefore **there is essentially always at least one arm with N < 1** → `under_explored` non-empty → random choice → UCB never fires.

This is not an implementation accident; it’s a **design incompatibility**: “forced exploration defined in terms of discounted N” + “UCB only used when there are no under-explored arms” is structurally prone to “forced exploration forever.”

### 1.3 A second issue: step-level UCB is also (almost surely) dead

You use the same forced-explore logic at the **step level**, but with ~15 steps per bucket. A step that gets a single pull has (N=1) then decays to (0.9965) on the next time you revisit that bucket → `< 1` again. Unless you revisit the same bucket and repeatedly hit the same step quickly (unlikely early), the step-level `under_explored_steps` set is also basically always non-empty, so step-level UCB also rarely/never triggers.

So even if arm-level were fixed, step-level may still be mostly random unless fixed too.

---

## 2) The scheduler fix I recommend (minimal, principled, works)

### 2.1 The key change

**Never define forced exploration in terms of discounted N.** Discounted N is *recency-weighted evidence mass*. It *should* decay; that’s the point. It must not be used to decide “have we explored this arm enough to allow UCB?”

Instead:

* Use **raw pull counts** (non-decayed) for cold-start / minimum sampling, OR
* Use a simple **ever_pulled flag** (recommended).

Then, always run UCB once cold start is complete.

### 2.2 Fully explicit revised scheduler specification

Maintain per arm (a):

* (N_a, S_a, t_a): discounted count, discounted reward sum, last update time (same as today)
* (m_a \in \mathbb{N}): **raw pull count** (new; no decay)

Maintain per step ((k,s)):

* (N_{k,s}, S_{k,s}, t_{k,s}) (same)
* (m_{k,s}): raw pull count (new)

#### Decay (unchanged)

When you “touch” an arm’s state at global time (t):

* (N_a \leftarrow N_a \cdot \gamma^{t - t_a})
* (S_a \leftarrow S_a \cdot \gamma^{t - t_a})
* (t_a \leftarrow t)

#### Selection (arm-level)

At each round:

1. (t \leftarrow t+1)

2. **Cold-start set**:
   [
   U = { a \in \mathcal{A} : m_a = 0 }
   ]
   If (U \neq \emptyset), choose (a \sim \text{Uniform}(U)) and skip UCB.

3. Else compute:
   [
   N_{\text{tot}} = \sum_{a \in \mathcal{A}} N_a
   ]
   and for each arm:
   [
   \mu_a = \frac{S_a}{\max(N_a, \varepsilon)}
   ]
   [
   \text{UCB}(a) = \mu_a + c \sqrt{\frac{\ln(1+N_{\text{tot}})}{\max(N_a, \varepsilon)}}
   ]
   Choose (a = \arg\max \text{UCB}(a)) (break ties randomly with seeded RNG).

#### Selection (step-level within chosen arm)

Let the chosen arm be ((k,b)), with candidate steps (S(k,b)).

1. **Cold-start steps**:
   [
   U_s = { s \in S(k,b) : m_{k,s} = 0 }
   ]
   If non-empty, pick uniformly among (U_s).

2. Else compute bucket-scoped totals:
   [
   N^{(k,b)}*{\text{tot}} = \sum*{s \in S(k,b)} N_{k,s}
   ]
   [
   \mu_{k,s} = \frac{S_{k,s}}{\max(N_{k,s}, \varepsilon)}
   ]
   [
   \text{UCB}(k,s) = \mu_{k,s} + c_s \sqrt{\frac{\ln(1+N^{(k,b)}*{\text{tot}})}{\max(N*{k,s}, \varepsilon)}}
   ]
   Pick (s) by argmax, tie-break randomly.

Return ((k, s)).

#### Update

After reward (r):

* Decay chosen arm/step to current time (optional if you already decayed them in selection)
* (N_a \leftarrow N_a + 1)
* (S_a \leftarrow S_a + r)
* (m_a \leftarrow m_a + 1)
* (t_a \leftarrow t)

Same for step: (N_{k,s} += 1), (S_{k,s} += r), (m_{k,s} += 1), (t_{k,s} = t).

### 2.3 What to do with `n_min`

**Delete `n_min` entirely** (or set it to 0 and don’t use it). With the above, cold-start is handled by `m_a == 0` / `m_{k,s} == 0`, and thereafter UCB handles exploration naturally.

This is the “minimum fix” that preserves your intended algorithm (Discounted-UCB), preserves discounting, and makes UCB non-dead.

---

## 3) Parameters: what I would change immediately vs later

### 3.1 Immediate change: B_count (number of buckets) for a 1000-run campaign

Even after the scheduler is fixed, **254 arms is too fine-grained for 946 bandit rounds** if you expect strong exploitation you can show to bosses.

You want enough post-cold-start budget per arm to separate winners from losers. With 254 arms:

* cold-start costs ~254 runs (if you cold-start all arms)
* leaves ~692 runs for exploitation
* still only ~2–3 extra pulls/arm on average

That’s not much.

So for **your next “boss-facing” A/B** I recommend:

* **B_count = 16** (≈128 arms)

  * cold-start 128
  * leaves ~818 for exploitation
* optionally also run **B_count = 8** (≈64 arms) as a second point

This is not overfitting; it’s simply matching discretization to budget.

### 3.2 Gamma (discount rate)

Your current derivation gives half-life (H = 200) for budget 1000 (γ≈0.9965). That is *fine*, but it interacts with “how often an arm is revisited.”

Once you fix forced exploration, γ mostly affects adaptation speed, not correctness. I would not touch γ for the next run unless you still see no exploitation with B_count=16.

If you do adjust γ, I’d do it by one simple rule:

* set (H = \max(200, |\mathcal{A}|))

So with 128 arms you’d keep H=200; with 254 you’d use H=254.

### 3.3 Exploration coefficients

Keep:

* (c = 0.25) initially (as you have)
* (c_s = 0.25) or **smaller** (like 0.15) if step-level noise is huge

Tune later via A/B only after you’ve fixed the dead-UCB bug.

---

## 4) What to change in the boss notebook (this is your main concern)

Your current `boss_presentation.ipynb` is *not bad* — it’s just missing the one plot/table that would instantly explain why bandit ≈ uniform:

### 4.1 Add a “Bandit Health Check” section near the top

Add 3 items **before** any coverage curves:

1. **Arm-selection mode counts**

* % arm selections made by:

  * cold-start (m_a==0)
  * UCB
* Same for step-level:

  * cold-start (m_{k,s}==0)
  * UCB

In the current buggy run, this will show ~100% “forced exploration” (or in your new implementation, “cold-start” if you adopt my fix). In the fixed run, it should show:

* cold-start dominates early (first ~|A| rounds),
* then UCB dominates.

2. **Pull distribution across arms**

* histogram of arm pull counts
* plus max/min/median/p95

In your current run, it’s basically flat (min 1, max 6). That is evidence of “no exploitation.”

3. **Exploitation evidence**

* scatter: arm mean reward vs arm pull count (you already have)
* but explicitly annotate:

  * Pearson r
  * slope
  * and show it **over time** (e.g., compute r in first half vs second half)

If bandit is working, correlation should increase in later phases.

This is the fastest way to make the notebook *explain the problem* rather than just show “no difference.”

### 4.2 Fix one misleading item: “Uniform reward by kind”

Right now you have boxplots for reward by kind for uniform and bandit. That’s fine technically, but **bosses can misread it** as “uniform is also using rewards.”

Change the titles to:

* “Uniform (no scheduling): reward signal distribution by kind”
* “Bandit (scheduling): reward signal distribution by kind”

And add a one-liner: “Uniform computes reward only for analysis; it does not affect selection.”

### 4.3 Coverage curves: what matters, and what doesn’t

For boss-level “did we explore better?” I’d keep **exactly** these cumulative curves:

* distinct failure contexts over time (from DB)
* distinct families over time (from DB)
* Z events over time
* crashes over time

…and add **one more** that is closer to “bug discovery proxy”:

* **Cumulative count of “high-quality” runs**
  e.g., (Q > 0.8) OR (d_fail \le 1) OR (Z==1).
  Pick one threshold and be consistent. The point is to show the bandit is moving mass toward “near-manifold” behavior.

### 4.4 Do NOT emphasize touch-coverage in this boss notebook

Given your earlier findings: touch novelty is mostly driven by INSTR_TYPE_MOD and saturates quickly for other kinds. Touch is still important internally, but it’s not a strong headline metric for this specific presentation (unless you’re specifically pitching the instrumentation itself).

If you do include touch, include it as “incremental beyond baseline,” and ensure baseline seeding is symmetric between uniform and bandit.

---

## 5) What you should do next (concrete, non-broad)

### Step 1 — Fix the scheduler (required)

Implement the “cold-start via raw pull counts” fix above for both:

* arm-level
* step-level

And add logging counters:

* `arm_select_mode ∈ {COLDSTART, UCB}`
* `step_select_mode ∈ {COLDSTART, UCB}`

### Step 2 — Run a *cheap* validation before another 6-hour campaign

Before you run RISC0 again:

* Run your existing simulation (like in `Pro_Report_9_Input.md`) but now confirm:

  * UCB mode happens (non-zero)
  * pull counts become non-uniform
  * correlation(mean_reward, pulls) becomes positive under a synthetic reward landscape

This takes seconds and prevents another wasted 6-hour run.

### Step 3 — Rerun one A/B experiment that can actually show learning

Run:

* Uniform baseline: 1000
* Bandit: 1000 with **B_count=16** (and fixed scheduler)

Keep the same guest program + inputs + seed.

### Step 4 — Update the boss notebook narrative

Your headline becomes:

1. “We built constraint-touch + constraint-fail observability (local).”
2. “We defined a reward that prioritizes novelty/rarity + Z (deep rejections).”
3. “Initial bandit run matched baseline because UCB was never activated (forced-exploration trap).”
4. “We fixed it with a principled cold-start design.”
5. “Now we see exploitation: non-uniform arm pulls correlated with reward, plus improved proxy metrics (Z rate / Q-high).”

Even if coverage metrics don’t explode upward, “bandit is demonstrably making informed choices” is already a material technical milestone.

---

## 6) Two quick answers to your two questions

### Q1) “Z is probably targeting global constraint failures since we haven’t instrumented globals — is that a problem?”

Not a blocker for now.

With local-only instrumentation, **Z is exactly the best proxy you currently have** for “the mutation got past local checks and failed later.” That “later” might be:

* permutation/global arguments,
* internal proof verification,
* memory-preflight consistency checks,
* segment verification logic, etc.

So: yes, the bandit will learn to target Z-rich regimes (your reports show Z comes only from instruction-word mutations). That’s not inherently bad; it’s a reasonable “near-manifold / deep failure” proxy.

For the boss talk, just be explicit: “Z means: no *local* constraint failure observed, but proof rejected; we hypothesize global checks are catching it.”

### Q2) “Why run-frequency per-run-per-context and not per-instance?”

Because per-instance is dominated by cascades and back-propagation. You already see huge cascades (dozens to >100 failures in a run). Counting instances would inflate frequency for contexts that merely cascade more, not contexts that are more *informative* or more often *reachable*. Per-run-per-context makes rarity a function of *how often you can reach that context as a failure mode*, which is what you want for scheduling.

---

## 7) Bottom line

* Your notebook didn’t “fail to show improvements.”
  It correctly showed **no improvements** because **the scheduler never exploited**.

* The fix is not “tune c” or “run longer.”
  It’s a **small but fundamental change**: forced exploration must be based on **non-decayed** cold-start counts (or removed), otherwise UCB is dead code.

* After that fix, use **B_count=16** for 1000-run A/B so exploitation can show up clearly.

If you want, paste (or attach) the current `bandit.py` after your latest modifications and I’ll sanity-check that the selection-mode instrumentation and cold-start/UCB logic matches the spec above exactly.
