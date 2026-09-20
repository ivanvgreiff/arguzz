# The reward → learning pipeline, end to end (V5, V6-cTS, V7-Hybrid)

**Purpose.** A single, chronological, source-grounded trace of *what the reward actually is and how it connects to learning* for the three variants you are currently running — `V5_control` (`cTS_semantic_v2`), `V6_cTS` (`v6_cTS`), and `Hybrid_cTS` (`hybrid_cTS`). It answers, with no hand-waving and no obsolete machinery: **is the Bernoulli bit the one and only reward, where does it go, how does it enter the posterior, and are the $Q$ quality metrics used?** Everything below is the code path these three variants take *today* (verified against `fuzzer.py`, `bandit_ts.py`, `reward_v2.py`). Notation is the one from `chapter3_coverage_cgc_objective_grounding.md`. No diagrams — the connectivity is shown as an explicit chain $f(a)=b,\ g(b)=c,\dots$

---

## 0. The one-sentence answer

For all three current variants, the quantity the bandit **learns from is a single bit** $b(t)\in\{0,1\}$. It *is* the reward, in the bandit sense, and it goes into exactly one place — the chosen arm's Beta posterior, by incrementing a success counter. The two scalar rewards you have seen — the additive $r^{\text{disc}}$ and the quality-weighted $r^{\text{cov}}=\min(1,Q\cdot S)$ — are **computed and written to the database for analysis, then never read again by the scheduler.** Consequently **the $Q$ quality metrics play no role in learning** in any of these variants (and $r^{\text{cov}}$ is in fact identically $0$ for V6-cTS and Hybrid). The rest of this document proves and connects these statements step by step.

---

## 1. Scope: the three variants share one scheduler and one bit

| variant | selector string | surface | per-pull method | scheduler | floor | applied-accounting |
|---|---|---|---|---|---|---|
| V5 | `cTS_semantic_v2` | A4 (post-exec witness) | `_run_v2_bandit_mutation` | `ConstrainedTSScheduler` | `ConstantFloor(0.55)` | **off** |
| V6-cTS | `v6_cTS` | Arguzz (all 11 kinds) | `_run_arguzz_cts_mutation` | `ConstrainedTSScheduler` | `ConstantFloor(0.55)` | **on** |
| V7-Hybrid | `hybrid_cTS` | Arguzz (4 kinds) + A4 | `_run_arguzz_cts_mutation` | `ConstrainedTSScheduler` | `ConstantFloor(0.55)` | **on** |

*Source:* selectors and families — `fuzzer.py:141–156` (`ALL_SEMANTIC_CTS_STRATEGIES = {cTS_semantic_v2, …, v6_cTS, hybrid_cTS}`, `ARGUZZ_CTS_STRATEGIES = {v6_cTS, hybrid_cTS}`); floor schedules — `fuzzer.py:735–742`; applied-accounting — `fuzzer.py:776–784` (`v6_cTS`/`hybrid_cTS` → `True`, else `False`). All three instantiate the **same** `ConstrainedTSScheduler` (Beta–Bernoulli Thompson sampling); they differ only in the surface that produces mutations and in the one applied-accounting branch of §6.

The crucial consequence: **there is exactly one learning algorithm to trace**, and it consumes exactly one input. We now follow a single pull $t$ from selection back to the posterior.

---

## 2. The chronological chain for one pull $t$

Read each line as *"this function's output is the next function's input."* I name the intermediate objects exactly as before.

### Step A — selection: the policy emits an arm
$$
a_t \;=\; \pi\big(\mathcal{H}_{t-1}\big)
$$
$\pi$ is the `ConstrainedTSScheduler.select()` waterfall (cold-start → singleton → floor → adaptive). Only the **adaptive** tier reads the posterior; the other tiers ignore it (this is where the bit ultimately matters — Step H). *Source:* `bandit_ts.py:205` (`select`). The output $a_t$ (an `ArmKey`) feeds Step B.

### Step B — run: the mutation produces raw feedback
Executing $a_t$ yields the per-run feedback of Chapter 3:
$$
\text{run}_t \;\longmapsto\; \big(\,\Gamma_t,\ \{z \text{ broken}\},\ \sigma_t,\ \text{exit/outcome}\,\big),
$$
the local failure contexts $\Gamma_t$, the broken global tuples behind any nonzero $\operatorname{res}_{\mathcal F}$, the structural cell $\sigma_t$, and the run's outcome label (used only in Step F for the Arguzz variants). These feed Step C.

### Step C — components: feedback + prior coverage → novelty counts
A single function consumes the feedback **and** the accumulated coverage sets $\mathcal L_{t-1},\mathcal G_{t-1},\mathcal S_{t-1}$, and returns the novelty tuple:
$$
\big(\ell_{\text{new}},\,g_{\text{new}},\,s_{\text{new}},\,f_{\text{new}},\,r_{\text{seen}},\,\text{crash}\big)
\;=\; \mathrm{Comp}\big(\text{run}_t;\ \mathcal L_{t-1},\mathcal G_{t-1},\mathcal S_{t-1}\big),
$$
with the definitions established earlier,
$$
\ell_{\text{new}}=|\mathrm{set}(\Gamma_t)\setminus\mathcal L_{t-1}|,\quad
g_{\text{new}}=|\mathsf G_t\setminus\mathcal G_{t-1}|,\quad
s_{\text{new}}=\mathbb 1[\sigma_t\notin\mathcal S_{t-1}],\quad
r_{\text{seen}}=|\mathrm{set}(\Gamma_t)\cap\mathcal L_{t-1}|.
$$
$\mathrm{Comp}$ has a **side effect**: it folds this run into the coverage sets, $\mathcal L_t=\mathcal L_{t-1}\cup\mathrm{set}(\Gamma_t)$, and likewise $\mathcal G_t,\mathcal S_t$. *Source:* `compute_reward_v2_components`, `reward_v2.py:133–189`; called at `fuzzer.py:1473` (V5) and `fuzzer.py:1262` (Arguzz). The novelty tuple feeds Steps D **and** E (it branches into three consumers).

### Step D — the bit: novelty → the one learning signal
$$
\boxed{\,b(t)\;=\;\mathbb 1\big[\,\ell_{\text{new}}+g_{\text{new}}+s_{\text{new}}\;>\;0\,\big]\,}
$$
*Source:* `compute_bandit_success(l_new, g_new, s_new)`, `reward_v2.py:60–62`; called at `fuzzer.py:1486` (V5) and `1275` (Arguzz). Note $f_{\text{new}}$ is **not** an input to $b$. The output $b(t)$ feeds Step F — and **only** Step F.

### Step E — the two scalars: novelty → telemetry (a terminal node)
The same novelty tuple is also fed to two scalar reward functions:
$$
r^{\text{disc}} \;=\; 1.00\,\mathrm{sat}(\ell_{\text{new}},1)+0.30\,\mathrm{sat}(f_{\text{new}},1)+0.25\,\mathrm{sat}(g_{\text{new}},3)+0.15\,\mathrm{sat}(s_{\text{new}},2)-0.50\,\text{crash}-0.05\,\mathrm{sat}(r_{\text{seen}},5),
$$
with $\mathrm{sat}(x,\tau)=1-e^{-x/\tau}$ (`compute_reward_v2`, `reward_v2.py:41–57`; called `fuzzer.py:1482`/`1271`), and the quality-weighted legacy reward
$$
r^{\text{cov}} \;=\; \min\!\big(1,\ Q\cdot S\big),\qquad Q=Q_{\text{loc}}\,Q_{\text{rep}}\,Q_{\text{glob}},
$$
(`compute_reward`, called `fuzzer.py:1451`/`1252`). **These are the only place $Q$ appears.** Their outputs are written to the result/telemetry (`result.reward = r^{\text{cov}}$ at `fuzzer.py:1456`; $r^{\text{disc}}$ and $b$ recorded into the reward/counterfactual tables). **Neither value is passed to the scheduler** — trace forward from Step E and the next consumer is the database, full stop. There is no edge from $r^{\text{disc}}$ or $r^{\text{cov}}$ back into selection. (See §3 for the explicit dead-end argument and §4 for why $r^{\text{cov}}\equiv 0$ on the Arguzz variants.)

### Step F — update: the bit → the arm's counters
This is the single hand-off from "reward" to "learning." Only $b(t)$ enters.

- **V5** (`cTS_semantic_v2`): the dispatch at `fuzzer.py:1539–1546` lands on the `ALL_SEMANTIC_CTS_STRATEGIES` branch,
  $$
  \texttt{update}(k,\,z,\,b(t)) \;\Rightarrow\; \texttt{\_advance\_state}\big(\,\mathrm{ArmKey.v5}(k,z),\ b(t)\,\big).
  $$
  *Source:* `fuzzer.py:1546`; `bandit_ts.py:314–335`.
- **V6-cTS / Hybrid** (`v6_cTS`, `hybrid_cTS`): `fuzzer.py:1288`,
  $$
  \texttt{update\_with\_outcome}\big(a_t,\ \text{outcome},\ b(t)\big),
  $$
  which (with applied-accounting **on**) advances **only if the mutation was applied** — see §6.

In either case, when the arm advances, `_advance_state(a,b)` performs exactly (`bandit_ts.py:301–308`):
$$
\mathrm{pulls}[a]\mathrel{+}=1,\qquad \mathrm{successes}[a]\mathrel{+}=b(t).
$$
So $b(t)$ enters the learner by adding $1$ to a success counter when $b=1$, and $0$ when $b=0$. Nothing else from the pull touches the learner. The updated counters feed Step G.

### Step G — posterior: counters → Beta parameters
The arm's posterior is read directly off those two counters (`bandit_ts.py:176–180`, prior $\mathrm{Beta}(1,1)$ from `prior_alpha=prior_beta=1.0`, `bandit_ts.py:138–139`):
$$
\alpha_a \;=\; 1 + \mathrm{successes}[a] \;=\; 1+\!\!\sum_{s\le t:\,a_s=a}\! b(s),
\qquad
\beta_a \;=\; 1 + \big(\mathrm{pulls}[a]-\mathrm{successes}[a]\big) \;=\; 1+\!\!\sum_{s\le t:\,a_s=a}\!\big(1-b(s)\big).
$$
This is the *entire* dependence of the model on campaign history: $\alpha_a,\beta_a$ are just the prior plus the running counts of $b=1$ and $b=0$ on arm $a$. These feed Step H.

### Step H — close the loop: posterior → next selection
At the next adaptive-tier selection (`bandit_ts.py:202–203`, `select`),
$$
\theta_a \;\sim\; \mathrm{Beta}(\alpha_a,\beta_a)\quad\forall a,
\qquad a_{t'} \;=\; \arg\max_a \theta_a,
$$
which is Step A again, now informed by $b$. The loop is closed **only through the adaptive tier**; cold-start, singleton, and floor pulls select without consulting $\theta$ (so the bit influences only the fraction of pulls routed to the adaptive tier).

### The chain, collapsed
$$
a_t=\pi(\mathcal H_{t-1})\ \to\ \text{run}_t\ \to\ (\ell_{\text{new}},g_{\text{new}},s_{\text{new}})\ \xrightarrow{\ \mathbb 1[\cdot>0]\ } b(t)\ \to\ \mathrm{successes}[a_t]\ \to\ (\alpha_{a_t},\beta_{a_t})\ \to\ \theta_{a_t}\ \to\ a_{t'}.
$$
$r^{\text{disc}}$, $r^{\text{cov}}$ (hence $Q$), $f_{\text{new}}$, and the touch novelty $\delta_T$ branch off after Step C into telemetry and **do not appear anywhere on this line.**

---

## 3. The dead-ends, stated explicitly (why $Q$ and the scalars don't learn)

The user's worry is exactly right to check: several "reward-shaped" quantities are computed, and it must be pinned down which feed back. Here is the forward-reachability from each, in the current variants:

- $b(t)$ → `update`/`update_with_outcome` → `successes`/`pulls` → $(\alpha,\beta)$ → $\theta$ → selection. **Reaches the policy.**
- $r^{\text{disc}}$ → stored in the reward/counterfactual telemetry. **Consumed by: the database.** Searching the dispatch (`fuzzer.py:1539–1546`) and the Arguzz update (`fuzzer.py:1288`), `reward_v2` is never an argument to any scheduler call for these variants. **Does not reach the policy.**
- $r^{\text{cov}}=\min(1,Q\cdot S)$ → `result.reward`, telemetry. The only scheduler call that takes `reward` is the `kindUCB_zoned_v1` branch (`fuzzer.py:1540`), a **different, non-current** selector. For `cTS_semantic_v2`/`v6_cTS`/`hybrid_cTS`, `reward` is never passed to a scheduler. **Does not reach the policy.**
- $Q=Q_{\text{loc}}Q_{\text{rep}}Q_{\text{glob}}$ → exists only inside $r^{\text{cov}}$. Since $r^{\text{cov}}$ is a dead-end, **$Q$ is a dead-end.** It is logged (so you can analyze it offline) but it does not shape any current campaign's decisions.
- $f_{\text{new}}$, $\delta_T$ → telemetry / the legacy reward only; excluded from $b$. **Dead-ends w.r.t. learning.**

So the honest, complete statement is: *in V5, V6-cTS, and Hybrid, the scheduler's only history-dependent input is $b(t)$; every scalar reward and every quality metric is observational.*

---

## 4. Why $r^{\text{cov}}$ (and $Q$) is not just unused but **degenerate** on the Arguzz variants

For V6-cTS and Hybrid, the Arguzz path calls the legacy reward with **no touch bitmap**:
$$
r^{\text{cov}} = \texttt{compute\_reward}(\underbrace{\texttt{None}}_{\text{touch\_bitmap}},\,\dots)\quad(\text{fuzzer.py:1252–1253}).
$$
`compute_reward` gates to zero whenever the touch bitmap is absent (its crash/validity guard, `coverage_state.py:189–199`). Hence
$$
r^{\text{cov}} \equiv 0 \quad\text{for every V6-cTS / Hybrid pull,}
$$
and with it $Q$ is computed over a zeroed reward. This is a second, independent reason $Q$ cannot be doing anything for the Arguzz variants — even its logged value is constant. (On V5 the A4 path *does* supply a touch bitmap, so $r^{\text{cov}}\in[0,1]$ is a meaningful logged number there — but still never read by the scheduler.)

---

## 5. The single difference between V5 and V6-cTS/Hybrid: applied-accounting

The chain of §2 is identical for all three except at Step F, governed by `applied_accounting_mode` (`fuzzer.py:776–784`). Let $o_t\in\{\texttt{APPLIED},\texttt{SKIPPED},\texttt{ERROR}\}$ be the outcome.

- **V5** (accounting off, and it uses the plain `update`): the posterior advances on **every** pull,
  $$
  (\mathrm{pulls}[a_t],\ \mathrm{successes}[a_t]) \mathrel{+}= (1,\ b(t)).
  $$
- **V6-cTS / Hybrid** (accounting on, uses `update_with_outcome`, `bandit_ts.py:344–349`):
  $$
  \begin{cases}
  (\mathrm{pulls},\mathrm{successes})\mathrel{+}=(1,\ b(t)) & o_t=\texttt{APPLIED},\\[2pt]
  \text{no update (the pull is invisible to the posterior)} & o_t\in\{\texttt{SKIPPED},\texttt{ERROR}\}.
  \end{cases}
  $$

So the reward signal $b$ is the same expression in all three; the only difference is that the Arguzz variants **discard** pulls that did not actually apply, rather than scoring them as failures. (Note the contrast hidden in `update_with_outcome`: with accounting *off*, a non-applied pull would be scored $b=0$; with accounting *on*, it is dropped entirely — `bandit_ts.py:344–349`.)

---

## 6. The end-to-end model in one line

Putting Steps C–G together, the posterior that drives every current variant is, for each arm $a$ after $t$ pulls,
$$
\theta_a \,\big|\, \mathcal H_t \;\sim\; \mathrm{Beta}\!\Big(\,1+\!\!\sum_{s\in P_a(t)}\! b(s),\ \ 1+\!\!\sum_{s\in P_a(t)}\!\big(1-b(s)\big)\Big),
\qquad b(s)=\mathbb 1\big[\ell_{\text{new}}(s)+g_{\text{new}}(s)+s_{\text{new}}(s)>0\big],
$$
where $P_a(t)$ is the set of pulls charged to arm $a$ up to time $t$ — *all* of $a$'s pulls for V5, only its **applied** pulls for V6-cTS/Hybrid. There is no $Q$, no $r^{\text{disc}}$, no $r^{\text{cov}}$ in this expression, because there is none in the code path. That is the whole learning model.

---

## 7. Source map (so each claim is checkable)

| claim | file:line |
|---|---|
| variant → selector → family | `fuzzer.py:27–63` (variants), `141–156` (families) |
| floor = ConstantFloor(0.55) for all three | `fuzzer.py:735–742` |
| applied-accounting: v6/hybrid on, V5 off | `fuzzer.py:776–784` |
| V5 per-pull path + dispatch to `update(k,z,b)` | `fuzzer.py:1347`, `1539–1546` |
| Arguzz per-pull path + `update_with_outcome(a,o,b)` | `fuzzer.py:1195`, `1288` |
| components $\mathrm{Comp}$ (ℓ/g/s/f/repeat) | `reward_v2.py:133–189` |
| bit $b=\mathbb 1[\ell+g+s>0]$ | `reward_v2.py:60–62` |
| additive $r^{\text{disc}}$ + weights + $\mathrm{sat}$ | `reward_v2.py:34–57` |
| legacy $r^{\text{cov}}=\min(1,Q\!\cdot\!S)$, $Q$ factors | `coverage_state.py` (`compute_reward`; crash-gate `189–199`) |
| $r^{\text{cov}}$ called with `touch_bitmap=None` on Arguzz | `fuzzer.py:1252–1253` |
| `_advance_state`: pulls/successes increment | `bandit_ts.py:301–308` |
| posterior $\alpha,\beta$; prior Beta(1,1) | `bandit_ts.py:138–139, 176–180` |
| selection $\theta\sim\mathrm{Beta}$, argmax | `bandit_ts.py:202–203, 205` |
| `update` / `update_with_outcome` bodies | `bandit_ts.py:314–349` |

*All paths confirmed against the current code; the `kindUCB_*`/`kindTS_*` scalar-reward branches (`fuzzer.py:1540–1544`) and the decay-floor selectors (`cTS_semantic_v2_decayexp/epoch`) are **not** among the three variants in use and are excluded above.*
