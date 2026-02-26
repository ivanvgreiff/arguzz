# Notebook Improvement Recommendations

An assessment of each existing visualization's effectiveness, followed by recommendations for new cells that would provide additional insight.

---

## 1. Assessments of Existing Cells

### Cell 3 — Reward Distribution by Kind

**Effective?** Yes. The box plot + bar chart combination is the right approach for showing distributional differences.

**Improvement**: Add a **violin plot** as an alternative to the box plot. Violin plots show the full density shape, which would reveal that IWORD_S and IWORD_F have bimodal distributions (a cluster near 0.24 from Z events and a cluster near 0.05-0.10 from non-Z runs). The box plot hides this bimodality because it only shows quartiles.

### Cell 5 — Reward Component Breakdown

**Effective?** Mostly. The stacked bar is good for component composition.

**Improvement**: The stacked bar doesn't show T_rare, which is a component of the weighted average S. While T_rare is small (0.08-0.15 for most kinds), it contributes to the ITYPE reward. Adding it as a fourth segment (in a lighter green) would make the stacked bar fully complete. Currently, the stacked bar total doesn't match the actual S value because T_rare is missing.

**Improvement**: The dual-axis chart combines Q and Z rate, but Q has a richer story: it's Q_dist × Q_rep. A decomposition showing mean Q_dist and mean Q_rep separately per kind would reveal whether the penalty comes from distinct failures (Q_dist) or cascade repeats (Q_rep). For most kinds Q_rep ≈ 1 (cascades are rare), so the penalty is almost entirely from Q_dist.

### Cell 7 — Reward Trajectory

**Effective?** Yes. The scatter + rolling mean is the correct approach for noisy time series data.

**Improvement**: The bottom panel could benefit from a **dual-rate comparison**: overlay the rolling F_new rate alongside the Z rate, so you can see the "handoff" from novelty-driven reward to Z-event-driven reward. Currently, you need to look at Cell 7 and Cell 11 separately to see this transition.

### Cell 9 — Bandit Learning Curve

**Effective?** Partially. The stacked area chart is visually busy with 8 kinds. The line chart for top-3 vs bottom-3 is more readable.

**Improvement**: Replace the stacked area chart with a **grouped bar chart** showing the selection % deviation from uniform (i.e., `pct - 12.5%`) for each phase. Positive bars mean the kind is being selected more than uniform; negative bars mean less. This would make exploitation signals much more visible because you're looking at deviations, not absolute values clustered around 12.5%.

**Improvement**: Add a **cumulative regret or cumulative reward comparison** plot. Plot the cumulative reward the bandit achieved vs what a uniform-random policy would achieve (using the per-kind mean rewards). This is the most direct way to measure whether the bandit outperforms random selection. Even if the kind distribution looks uniform, the bandit may be selecting *better step regions within each kind*, producing higher total reward.

### Cell 11 — Failure Novelty Decay

**Effective?** Yes. The filled rate chart and the F_new vs F_rare comparison are informative.

**Improvement**: Add a **cumulative distinct failure context_id curve**. This would show the total number of unique (loc, major, minor) failure contexts discovered over time. Currently, we show the rate of novelty but not the absolute count. The cumulative curve would answer: "how many failure contexts have we mapped?" and "is the space approaching saturation?"

### Cell 13 — Z-Event Deep Dive

**Effective?** Yes. The three-panel layout covering kind, time, and space is thorough.

**Improvement**: The step histogram (right panel) would benefit from **overlaying the step density of non-Z runs** (in a lighter color) for comparison. This would show whether Z events are concentrated in specific step regions that are unusual, or whether they simply follow the general mutation distribution. If Z events cluster in regions that are under-represented in the overall mutation distribution, those regions deserve targeted investigation.

**Improvement**: Add a **Z-event detail table** listing the step and kind for each Z event. With only 99 events, a sortable table would allow manual inspection of whether specific step ranges are "Z-prone" across multiple runs.

### Cell 15 — Cascade & Quality Analysis

**Effective?** Mostly. The scatter plot is the right choice for showing the n_fail → reward relationship.

**Improvement**: The x-axis clip at 50 hides the extreme cascades (n_fail = 175). Add a **small inset** or annotation showing the full range (0-175) so the reader knows there are extreme outliers beyond the visible region.

**Improvement**: Add a **Q_dist vs Q_rep decomposition scatter** or table. For cascade runs (n_fail > 10), show both Q_dist and Q_rep values. This would demonstrate that the two-factor Q design from Pro_Report_6 is working: Q_dist penalizes distinct failures while Q_rep penalizes cascade repeats, and they act independently.

### Cell 17 — Touch Coverage Growth

**Effective?** Yes, but limited in insight because touch coverage is dominated by INSTR_TYPE_MOD.

**Improvement**: Color-code or annotate the cumulative curve with **which kind produced each jump**. Since touch novelty comes almost exclusively from INSTR_TYPE_MOD, you could mark ITYPE runs on the x-axis (tick marks or vertical lines) to show the direct correspondence between ITYPE selections and coverage jumps.

### Cell 19 — Reward Heatmap

**Effective?** Yes. The heatmap directly shows the arm-level landscape.

**Improvement**: Some cells may have very few observations (1-2 runs), making the mean unreliable. Add a **companion heatmap of sample counts** (number of runs per arm), or annotate cells with very few observations (<3) with a hatching pattern to indicate low confidence.

**Improvement**: Add **row and column marginals** — a bar on the right showing per-kind mean, and a bar on top showing per-bucket mean. This would show whether the reward structure is dominated by the kind dimension or the bucket dimension.

### Cell 22 — Campaign Summary

**Effective?** Yes as a compact reference, but purely text.

**Improvement**: This could be a formatted pandas table or a styled HTML summary rather than print statements, making it more visually consistent with the notebook.

---

## 2. Missing Cells That Would Provide New Insight

### Missing Cell A — Bandit vs Uniform Cumulative Reward

**What**: Plot cumulative reward for the actual bandit selections vs a hypothetical uniform-random baseline (compute per-kind mean reward, then the expected reward per round under uniform = mean of per-kind means).

**Why**: This is the most direct measure of bandit effectiveness. Even if the kind distribution looks uniform, the bandit may be selecting better step-bucket regions within kinds. Cumulative reward comparison would reveal this. If the bandit's cumulative reward line is above the uniform baseline, it's adding value.

**How**: `uniform_expected = df.groupby('kind_short')['reward'].mean().mean()`. Plot cumulative actual reward vs `i * uniform_expected` for each run i.

### Missing Cell B — Per-Kind Reward Over Time

**What**: For each kind separately, plot the rolling mean reward over time.

**Why**: The current analysis aggregates all kinds together in the reward trajectory (Cell 7). But different kinds may have different reward trajectories. ITYPE's reward may be more volatile (spiking when it finds new touch) while IWORD_S's reward may be more stable (driven by steady Z events). Seeing each kind's trajectory individually would reveal whether the bandit should treat different kinds differently.

### Missing Cell C — Arm UCB Index Evolution

**What**: For the top 5 and bottom 5 arms by final mean reward, plot the evolution of their UCB index over time (reconstructed from the reward and decay data).

**Why**: The UCB index is what the bandit actually uses to make decisions. Showing how it evolves for specific arms would illustrate the exploration/exploitation trade-off in action: early on, all arms have high UCB (exploration bonus dominates); later, arms with high mean reward keep high UCB while arms with low mean reward have UCB dominated by their low mean.

**Caveat**: This requires reconstructing the bandit state from the run data, which is possible but requires simulating the discount decay. It's a more advanced analysis.

### Missing Cell D — Crash Analysis

**What**: Show which kinds and step regions produce crashes, and whether the bandit learns to avoid them.

**Why**: 11 crashes occurred (all from PRE_EXEC_REG_MOD at step 0). Does the bandit reduce its selection of this arm over time? Plotting the selection rate of the crash-prone arm over phases would show if the reward=0 signal is causing the bandit to learn avoidance.

### Missing Cell E — Step Distribution Comparison

**What**: Histogram comparing the step distribution of bandit selections vs uniform random (the pilot phase can serve as the uniform reference).

**Why**: Even if kind distributions look similar, the bandit may be selecting different step regions. Comparing the step distributions would reveal if the bandit is spatially concentrating on specific program regions.

### Missing Cell F — F_rare Per-Kind Over Time

**What**: Plot rolling mean F_rare for each kind separately over time.

**Why**: F_rare is the key differentiating signal after novelty decays. Showing it per-kind would reveal whether all kinds see their F_rare decay at the same rate, or whether some kinds maintain higher F_rare longer. If IWORD_S maintains higher F_rare (because it hits rarer failure contexts), that explains part of its sustained high reward.

### Missing Cell G — Reward Correlation Matrix

**What**: Compute correlations between all reward components (T_new, T_rare, F_new, F_rare, Z, Q) and the final reward r.

**Why**: Would quantitatively answer "which component drives the reward the most?" The expected finding: Q and Z have the highest correlation with r, because Q acts as a gate (low Q → low r regardless of S) and Z provides large reward when it fires.

---

## 3. Summary of Priorities

| Priority | Improvement | Effort | Insight Value |
|----------|------------|--------|---------------|
| **High** | Missing Cell A: Bandit vs Uniform cumulative reward | Low | Directly answers "is the bandit helping?" |
| **High** | Missing Cell D: Crash avoidance learning | Low | Shows the bandit handles negative signal |
| **High** | Cell 9 improvement: Deviation-from-uniform bar chart | Low | Makes exploitation signal much more visible |
| **Medium** | Missing Cell B: Per-kind reward over time | Low | Reveals kind-specific reward dynamics |
| **Medium** | Cell 3 improvement: Violin plot for bimodality | Low | Shows Z-event driven bimodal distribution |
| **Medium** | Missing Cell E: Step distribution comparison | Low | Reveals spatial exploitation |
| **Medium** | Cell 11 improvement: Cumulative failure context curve | Low | Shows absolute coverage progress |
| **Low** | Missing Cell C: UCB index reconstruction | High | Pedagogically interesting but complex |
| **Low** | Missing Cell G: Correlation matrix | Low | Quantifies intuition already visible in charts |
| **Low** | Cell 19 improvement: Sample count companion heatmap | Low | Statistical rigor for heatmap |

---

*End of Notebook Improvement Recommendations.*
