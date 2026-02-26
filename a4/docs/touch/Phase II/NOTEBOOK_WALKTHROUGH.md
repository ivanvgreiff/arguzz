# Notebook Walkthrough: 1000-Mutation Bandit Campaign Analysis

A cell-by-cell guide to the `campaign_analysis.ipynb` notebook. Each section explains what the cell computes, what the visualization shows, why it's displayed that way, and what the key takeaways are.

---

## Cell 0 — Title (Markdown)

Sets the context: this notebook analyzes a 1000-mutation campaign using the Discounted-UCB bandit scheduler. This framing is important because the reader needs to know this is not a random-selection campaign — the bandit is actively choosing which (mutation_kind, step) to try next.

---

## Cell 1 — Data Loading and Setup (Code)

### What it does

1. Adds the project root to Python's import path so `a4.standalone.tests.analyze_campaign` can be imported.
2. Loads the terminal output file from the campaign using `parse_terminal()`, which regex-parses every pilot and bandit run line into structured `RunRecord` objects.
3. Separates pilot runs (50) from bandit runs (946).
4. Converts bandit runs into a pandas DataFrame with columns: `num`, `kind`, `step`, `n_fail`, `time_ms`, `outcome`, `reward`, `T_new`, `F_new`, `F_rare`, `Z`, `Q`, `is_pilot`, `new_touch`.
5. Creates short kind names (e.g., `INSTR_WORD_MOD_SUR` → `IWORD_S`) for readable axis labels.
6. Defines `KIND_ORDER` sorted from highest mean reward to lowest, so every chart uses a consistent left-to-right ordering that immediately communicates "best to worst."

### Key output

```
Loaded: 50 pilot + 946 bandit = 996 total
Calibrated: tau_T=35.0, tau_d=3.0, K_T_rare=31, gamma=0.9965
```

### Why it matters

The calibrated parameters tell us the reward function's sensitivity. tau_T=35 means finding 35 new touch buckets gives T_new ≈ 0.63. gamma=0.9965 means a half-life of ~200 iterations — the bandit forgets observations from 200+ rounds ago.

---

## Cell 3 — Reward Distribution by Mutation Kind (Code)

### What it computes

Two side-by-side plots from 946 bandit-mode runs:

**Left: Box plot** of reward distributions per kind. Shows median (line), interquartile range (box), and whiskers (non-outlier range). Outliers are hidden (`showfliers=False`) because the few very high rewards (0.25-0.39) compress the boxes visually.

**Right: Bar chart** of mean reward ± standard deviation, with a red dashed line at the overall campaign mean (0.074).

### What it shows

A clear **three-tier hierarchy**:
- **Tier 1** (mean > 0.1): IWORD_S (0.154), IWORD_F (0.129) — stand clearly above the red line
- **Tier 2** (mean 0.05-0.1): ITYPE (0.088), PRE_REG (0.055), COMP (0.049), MEM (0.049)
- **Tier 3** (mean < 0.04): LOAD (0.032), STORE (0.029) — well below the red line

The box plot adds nuance: IWORD_S has a high median (0.149) — most of its runs are rewarded, not just outliers. In contrast, ITYPE has a lower median (0.063) but a long upper tail (max 0.387), meaning its high rewards come from rare exceptional runs.

### Why displayed this way

The box plot shows the shape of the distribution (is high reward consistent or spiky?), while the bar chart with error bars gives a cleaner summary for quick comparison. Using both together is standard practice — the box plot prevents misleading conclusions from the bar chart alone (e.g., ITYPE's bar looks moderate, but the box plot shows its extreme variability).

### Key takeaway

The reward function succeeds at its core purpose: differentiating mutation kinds. The 5x spread between IWORD_S (0.154) and STORE (0.029) gives the bandit a strong signal to learn from.

---

## Cell 5 — Reward Component Breakdown (Code)

### What it computes

Two plots decomposing WHY each kind gets its reward level:

**Left: Stacked bar chart** of mean T_new (green), F_new (red), F_rare (orange) per kind. These are the three informative components of the weighted average S (T_rare is not shown because it's small and uniform; Z is shown separately).

**Right: Dual-axis chart** with Q (blue bars, left axis) and Z-event rate (red line with dots, right axis).

### What it shows

The stacked bar reveals that **different kinds get reward from different sources**:
- **ITYPE**: Tall bar dominated by F_rare (0.738, orange) and F_new (0.335, red), plus visible T_new (0.103, green). It's the only kind that produces new touch. But its Q is the lowest (0.307) because it causes many distinct failures.
- **IWORD_S**: Short stacked bar (low F_new, moderate F_rare) but the Z-event rate line shoots up to 42.5%. Its reward comes primarily from Z events and high Q (0.808).
- **STORE/LOAD**: Short bars, no Z, moderate Q — they simply don't produce much signal.

The dual-axis chart makes the Q vs Z trade-off visible: kinds with high Q (IWORD_S, IWORD_F) also have high Z rates, while kinds with low Q (ITYPE, PRE_REG) have zero Z. This is because Z requires d_fail=0, which also means Q_dist=exp(0)=1.

### Why displayed this way

A stacked bar is the right choice for showing component composition — you can see both the total signal magnitude and which components dominate. The dual-axis chart for Q and Z is necessary because they have different scales (Q is 0-1, Z rate is 0-45%) and both are crucial for understanding why some kinds earn high reward despite low component values.

### Key takeaway

The two paths to high reward: (1) ITYPE gets reward from *breadth* (many components firing) but is penalized by Q; (2) IWORD_S/F gets reward from *depth* (Z events, perfect Q) but has narrow component signal. This architecture correctly captures both exploration strategies.

---

## Cell 7 — Reward Trajectory Over Time (Code)

### What it computes

A two-panel vertically-stacked figure:

**Top: Reward trajectory** — scatter of per-run rewards (gray dots, alpha=0.15) overlaid with a rolling mean (red line, window=50) and campaign mean (blue dashed).

**Bottom: Z-event accumulation** — cumulative Z-event count (red line, left axis) and rolling Z rate in % (blue line, right axis).

### What it shows

**Top panel**: Reward starts high (~0.145 rolling mean) and decays to ~0.055 by run 500, then stabilizes. The gray scatter shows individual runs range from 0 to 0.39, but the rolling mean smooths this into a clear decay curve. This is **novelty saturation**: as the campaign discovers more failure contexts and touch buckets, fewer things are "new" or "rare."

The decay does NOT reach zero — the floor ~0.055 is maintained by:
- F_rare (which decreases slowly as failure context frequencies grow)
- Z events (which don't depend on novelty at all)

**Bottom panel**: Cumulative Z events grow linearly at roughly 10 per 100 runs throughout the entire campaign. The rolling Z rate fluctuates between 5-20% but stays consistently above zero. This is the **most important observation**: Z events are a stable, non-decaying signal.

### Why displayed this way

The scatter + rolling mean combination is essential: the scatter shows the high variance (individual runs range 0-0.39), while the rolling mean reveals the trend. Without the scatter, you'd miss the variance; without the rolling mean, you'd miss the trend. The shared x-axis between top and bottom panels allows visual correlation: you can see that Z events occur at a steady rate even as the overall reward decays.

### Key takeaway

Novelty saturation is real and significant (2.6x reward decay from start to end). But the reward doesn't collapse to zero, and Z events provide a steady ~10% signal throughout the entire campaign. The architecture handles nonstationarity correctly — the discount factor in the bandit means old high-reward observations from the novelty-rich early phase don't permanently bias the arm statistics.

---

## Cell 9 — Bandit Learning Curve (Code)

### What it computes

The campaign is split into 10 equal phases (~94 runs each), and for each phase, the selection frequency of each kind is computed as a percentage.

**Left: Stacked area chart** of kind selection % by phase. If the bandit were uniform, each kind would be at 12.5% (black dotted line).

**Right: Line chart** comparing the top 3 reward kinds (IWORD_S, IWORD_F, ITYPE, solid lines) against the bottom 3 (STORE, LOAD, MEM, dashed lines) over the 10 phases.

### What it shows

The stacked area chart shows that the kind distribution stays **remarkably uniform** across all 10 phases. No kind consistently dominates or disappears. The line chart confirms this: all lines hover near the 12.5% uniform baseline, with fluctuations of ±5%.

### Why displayed this way

The stacked area chart makes it immediately visible whether the total adds to 100% and whether any kind grows or shrinks over time. The line chart gives a cleaner comparison for specific kinds of interest. Showing both top-3 and bottom-3 on the same axes allows direct visual comparison of whether high-reward kinds are being selected more frequently than low-reward kinds.

### Key takeaway

**The bandit is NOT strongly exploiting at the kind level in 946 rounds.** With 254 arms and avg 3.7 samples/arm, the bandit is still in its exploration phase. This is expected from the theory (Pro_Report_5 said meaningful adaptation requires 3-5+ samples per arm, and many arms still have <2). A 2000+ mutation campaign would show clearer exploitation.

Note that the kind-level view is a coarse aggregation — 8 kinds across 32 buckets gives 254 arms, and the bandit operates at the arm level. Kind-level flatness does not rule out arm-level learning. Whether the bandit is actually exploiting at the arm level is tested explicitly in Section 10.

---

## Cell 11 — Failure Novelty Decay (Code)

### What it computes

**Left: Filled line chart** of the rolling rate of runs where F_new > 0 (i.e., the run discovered at least one new failure context_id). Window = 50.

**Right: Line chart** comparing rolling mean F_new (red) vs rolling mean F_rare (orange) over time.

### What it shows

**Left panel**: Failure novelty rate starts at ~39% and decays to ~6-7% by the end. The filled area makes the decay visually dramatic — you can see the "novelty budget" being consumed.

**Right panel**: F_new (red) drops rapidly toward zero, while F_rare (orange) drops much more slowly. By run 800+, F_new is near zero but F_rare still provides ~0.15-0.20 of signal. This is exactly the design intent: F_rare is the "long-tail" signal that keeps the reward informative after novelty saturates.

### Why displayed this way

The filled line chart for the rate (left) shows the *binary* question — how often does any novelty happen? The continuous line chart (right) shows the *magnitude* question — how strong are the components? Both perspectives matter: the rate tells you "is novelty still possible?", while the magnitude tells you "how much does it contribute to reward?"

### Key takeaway

The failure novelty rate decays from 39% to 6-7% over 946 runs but never reaches zero — there's still signal to be found at 1000 mutations. F_rare provides a stable differentiation mechanism that persists long after F_new exhausts, validating the architectural decision from Pro_Report_6 to make failure rarity a co-primary signal.

---

## Cell 13 — Z-Event Deep Dive (Code)

### What it computes

Three side-by-side plots:

**Left: Bar chart** of Z-event rate by kind. Only IWORD_S and IWORD_F have nonzero bars; the rest are gray.

**Center: Histogram** of Z-event temporal distribution — when during the campaign do Z events occur?

**Right: Histogram** of Z-event step distribution — where in the program execution do Z events occur?

### What it shows

**Left**: Only instruction-word mutations produce Z events: IWORD_S at 42.5% and IWORD_F at 39.7%. All other kinds produce zero Z events. The contrast between the two red bars and six gray bars is striking.

**Center**: Z events are distributed roughly uniformly across the campaign. There's no front-loading or back-loading. This confirms Z events are a *steady* signal, not an artifact of early novelty.

**Right**: Z events cluster at certain step regions. Some execution regions (certain step ranges) produce more Z events than others. This suggests there are specific program regions where mutations can pass local constraint checks — these are the most promising targets for underconstraint hunting.

### Why displayed this way

Three charts side by side give the three dimensions of Z-event analysis: *who* produces them (left), *when* in the campaign (center), and *where* in the program (right). The bar chart with red/gray coloring makes the "only two kinds" finding immediately visible. The histograms show distributions where point plots would be too noisy.

### Key takeaway

Z events are the single most important signal for underconstraint detection. They occur only for instruction-word mutations, at a stable 10% rate, and cluster at specific program regions. This tells us: (1) surgical/full instruction mutations are the best candidates for finding soundness bugs, and (2) there are specific execution regions more amenable to constraint bypass.

---

## Cell 15 — Cascade & Quality Analysis (Code)

### What it computes

**Left: Scatter plot** of n_fail (x-axis) vs reward (y-axis), colored by kind. X-axis clipped at 50 to focus on the non-cascade region (the 175-failure cascade would compress everything else).

**Right: Box plot** of Q (execution quality) distribution by kind.

### What it shows

**Left**: A clear "L-shaped" pattern. Runs with 0 failures can have high reward (up to 0.27 — Z events). Runs with 1-3 failures have moderate reward (0.05-0.25). Runs with 5+ failures cluster near zero reward. The scatter is colored by kind, showing that IWORD_S/F dots appear at the top (high reward, low n_fail) while STORE/LOAD dots cluster at the bottom-left.

**Right**: Q distribution differs dramatically by kind. IWORD_S has median Q near 0.8 (most of its runs have few/no failures). ITYPE has median Q near 0.2 (it consistently causes many distinct failures). This shows that Q is the mechanism that prevents ITYPE from dominating despite its high component scores.

### Why displayed this way

The scatter plot is the most honest way to show the n_fail → reward relationship because it shows every individual run. The clip at x=50 is necessary because a few extreme cascades (n_fail=175) would compress the interesting region. The box plot for Q by kind provides the distributional view that the scatter can't show clearly when points overlap.

### Key takeaway

The Q multiplier works as designed: it creates a soft gate where low-failure runs pass through (Q ≈ 0.5-1.0) and high-failure runs are suppressed (Q ≈ 0). The Q × S structure means a run must have BOTH interesting signal (high S) AND few failures (high Q) to earn high reward. This prevents the bandit from chasing garbage cascades.

---

## Cell 17 — Touch Coverage Growth (Code)

### What it computes

**Filled line chart** of cumulative new touch buckets discovered during the bandit phase (green, left axis), overlaid with the rolling mean of T_new (dashed green line, right axis).

### What it shows

The cumulative touch curve is roughly linear but with step-like jumps. Each jump corresponds to an INSTR_TYPE_MOD run that discovers 30-50 new buckets. Between jumps, the curve is flat (value mutations don't discover new touch). The T_new rolling mean shows small spikes corresponding to these jumps.

### Why displayed this way

The filled area under the cumulative curve makes the growth rate visually clear — the slope of the filled region represents the discovery rate. The dual axis with T_new rolling mean adds context: you can see that the spikes in T_new correspond to the steep parts of the cumulative curve.

### Key takeaway

Touch coverage growth is entirely driven by INSTR_TYPE_MOD mutations. This is consistent with the Phase II.2V findings: touch is a "selector-regime" signal, not a "value-space" signal. The linear growth suggests touch hasn't fully saturated at 946 runs — more INSTR_TYPE_MOD mutations would find more buckets.

---

## Cell 19 — Reward Heatmap: Kind x Step-Bucket (Code)

### What it computes

A heatmap where rows are mutation kinds, columns are step buckets (0-31), and cell color represents mean reward for that (kind, bucket) combination. Each cell in this heatmap corresponds to one bandit arm.

### What it shows

The heatmap reveals the **reward landscape** — which arms produce high reward. IWORD_S and IWORD_F rows are generally warmer (more red/orange) than STORE and LOAD rows (more yellow/white). Within each kind, certain buckets are hotter than others, revealing step regions that are particularly productive for that mutation type.

The 16x spread between the highest-reward and lowest-reward arms shows there is strong structure in this landscape — meaningful differences exist for the bandit to exploit.

### Why displayed this way

A heatmap is the natural visualization for a two-dimensional categorical grid. The `YlOrRd` colormap (yellow → orange → red) makes high-reward arms visually pop. This is the same structure the bandit uses internally — each cell is an arm — so the heatmap directly shows the reward landscape the bandit is navigating.

### Key takeaway

The reward landscape has strong arm-level structure (16x spread), which is a **precondition** for effective learning — it means there are productive arms worth exploiting. However, this heatmap shows which arms *have* high reward, not whether the bandit *selects* them more often. The next section (Cell 21) directly tests whether selection frequency correlates with reward.

---

## Cell 20 — Arm-Level Selection Analysis (Markdown)

Introduces the question that the reward heatmap alone cannot answer: does the bandit actually *select* high-reward arms more frequently? This is the critical test of whether learning is occurring.

---

## Cell 21 — Arm-Level Selection Analysis (Code)

### What it computes

Three side-by-side plots that directly test whether the bandit is exploiting high-reward arms:

**Left: Selection count heatmap** — same format as the reward heatmap (Cell 19), but showing how many times each arm was selected instead of its mean reward. By visually comparing this with the reward heatmap, the reader can see whether selection frequency aligns with reward.

**Center: Arm reward vs selection count scatter** — each dot is one arm. X-axis is the arm's mean reward, y-axis is how many times it was selected. A positive trend line slope and Pearson r would indicate the bandit is selecting high-reward arms more often. The correlation coefficient is shown in the title.

**Right: Second-half selection fraction scatter** — for each arm with ≥2 samples, the fraction of selections that came from the second half of the campaign (y-axis) is plotted against mean reward (x-axis). If the bandit is learning, high-reward arms should have a second-half fraction > 0.5 (selected more in the second half, after data has been gathered). A horizontal dashed line at 0.5 marks the balanced baseline.

### What it shows (from the 1000-mutation campaign)

The results are clear and sobering:

- **Reward-count correlation: r = 0.060** — essentially zero. The bandit is not selecting high-reward arms more frequently than low-reward arms.
- **Reward-2ndHalf correlation: r = -0.034** — essentially zero. There is no shift toward high-reward arms over the course of the campaign.
- **High-reward arms 2nd-half fraction: 0.480**, Low-reward: 0.540 — if anything, slightly opposite to what learning would predict.

### Why displayed this way

The scatter plot with trend line and Pearson r is the most direct and honest way to test for correlation. The heatmap comparison (left) provides a visual cross-reference that doesn't require statistical interpretation. The second-half fraction (right) tests temporal learning rather than just overall frequency.

### Key takeaway

**The bandit has NOT learned to exploit at the arm level in 946 rounds.** With only 3.7 samples per arm on average, the bandit simply does not have enough data to form reliable reward estimates and concentrate selections. The UCB exploration bonus, combined with the discount factor causing periodic re-exploration, keeps selection approximately uniform.

This is not a failure of the architecture — it's a sample-size limitation. The 254-arm action space requires substantially more mutations (2000+) before the bandit accumulates enough data per arm to confidently exploit. The reward landscape (16x spread in Cell 19) confirms there *is* structure to learn, but 946 rounds is insufficient to learn it.

---

## Cell 22 — Summary & What's Left (Markdown)

Summarizes the 5 key conclusions and 6 open questions. The conclusions are firmly established by the data; the open questions guide Phase II.5 and beyond.

---

## Cell 23 — Appendix A: Algorithm Specification (Markdown)

The complete mathematical specification of the coverage-guided bandit system in LaTeX. Includes coverage key definitions, per-run observations, global state, the full reward function (all 5 components + Q + weighted average), parameter table, and the end-to-end algorithm as a numbered procedure.

### Why it matters

This appendix serves as the single source of mathematical truth. Anyone reading the notebook can refer back to the appendix to understand exactly what "T_new" or "Q_dist" means in the formulas. It also serves as documentation for the system's architecture.

---

## Cell 24 — Campaign Summary (Code)

Prints the final summary statistics in text form: total runs, outcomes, mean reward, Z events, coverage. This is the "headline numbers" cell that captures the most important facts in a compact format.

---

## Overall Narrative

The notebook tells a coherent story in four acts:

1. **The reward works** (Cells 3, 5): The reward function creates a clear hierarchy among mutation kinds, driven by different component combinations. Two distinct paths to high reward exist: breadth (ITYPE) and depth (IWORD_S/F).

2. **The signal decays but persists** (Cells 7, 11): Novelty saturation causes reward to drop 2.6x over the campaign, but F_rare and Z events maintain a stable floor. The architecture handles nonstationarity correctly.

3. **The reward landscape has structure, but the bandit hasn't exploited it yet** (Cells 9, 19, 21): The reward heatmap shows a 16x spread across arms — there are productive arms worth exploiting. But the arm-level selection analysis (Cell 21) shows no correlation between arm reward and selection frequency (r = 0.060), and no temporal shift toward high-reward arms. With only 3.7 samples/arm, the bandit is still exploring. A longer campaign (2000+) is needed to observe exploitation.

4. **Z events are the crown jewel** (Cell 13): The most promising signal for finding underconstraints, steady at 10%, exclusive to instruction-word mutations, and clustering at specific program regions.

---

*End of Notebook Walkthrough.*
