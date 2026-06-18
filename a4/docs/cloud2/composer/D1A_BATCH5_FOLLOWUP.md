# D1.A Batch 5 — Follow-up tasks (after Opus review)

**Status:** Batch 5 artifacts approved (CSVs, plots, notebook, subsection draft all verified correct).
**Trigger:** Opus's review surfaced one major missing finding + 1 small bug + 2 cosmetic refinements that should be folded in **before** the parent `IV_POS_8_D1_REPORT_FOR_PRO.md` is assembled.

This follow-up is **additive only** — DO NOT regenerate the CSVs unless explicitly stated. The artifacts are correct; only the interpretation in `D1A_SUBSECTION.md` and one helper in `build_d1a_artifacts.py` need touching.

---

## Task FU-1 — Add **Finding C** to `D1A_SUBSECTION.md`

Add a new finding under the **Findings** section. Suggested wording:

```markdown
### Finding C — Mode sequence is seed-independent (only arm choice is stochastic)

Direct evidence from the DBs:

| DB | sha1 of mode sequence [200, 6000) |
|---|---|
| V5 seed 1234 | `2d14a156aca51190` |
| V5 seed 1235 | `2d14a156aca51190` ← identical |
| V5-decayexp seed 1234 | `c07da3955a8f0347` |
| V5-decayexp seed 1235 | `c07da3955a8f0347` ← identical |

The per-mutation_id `mode` (floor / adaptive) is **completely deterministic within a variant**; the random seed does not affect it. Only the *arm picked within a mode* is seed-dependent (V5-decayexp 1234 picks `INSTR_TYPE_MOD|core_memory_load` at an adaptive position; 1235 picks `INSTR_TYPE_MOD|step0`).

Three implications:

1. **Finding A's "48% floor share" is a pool-depletion cap, not a direct `floor_fraction=0.20` measure.** At low floor fractions, the floor pool depletes quickly and adaptive fills the gap. The Pro-relevant takeaway is unchanged (K=50 too small) but the mechanism is structural, not stochastic.
2. **V5-decayepoch is bit-identical to V5-static in mut[0, 2000).** Same mode at every mutation_id, same arm-selection rule, same RNG state (decayepoch uses floor=0.55 there, matching V5-static). Evidence: paired t-test for `time_to_43 V5-decayepoch vs V5` has `mean_diff=0.0` and `t_stat=NaN` across all 4 paired seeds — the four `time_to_43` values match exactly (1612/1585/1237/460).
3. **The current experiment has near-zero power to distinguish V5-static from V5-decayepoch on `local_context_final`**, because `local_context_final` saturates around mut ~2800 (median `time_to_46` for decayepoch), and 46 of the 47 final contexts land in mut[0, 2000) where decayepoch ≡ V5-static. Even at n=10 paired triplets the result would still be p≈1.0.
```

Place the new finding **after Finding B**, keeping A→B→C order.

---

## Task FU-2 — Update **Verdict** and **Recommendation** in `D1A_SUBSECTION.md`

Refine the existing Verdict (currently §"Verdict") to incorporate the power-limitation framing. Suggested rewrite:

```markdown
## Verdict

On n=4 paired triplets, decay variants show **no statistically significant improvement** in `local_context_final` vs V5-static (paired p > 0.18 for all coverage metrics).

**This is partly a power-limitation result, not just a null result** (see Finding C consequence #3):

- `V5-decayexp` saturates at the floor minimum within ~100 mutations (Finding A), so empirically behaves like `ConstantFloor(0.20)` — a meaningfully different rule from V5-static (`ConstantFloor(0.55)`), but the data does not show a coverage advantage.
- `V5-decayepoch` is **bit-identical to V5-static in mut[0, 2000)**, and our coverage metric saturates inside that range, so the test cannot distinguish them at any n with these boundaries.

**D2 recommendation:** retain **V5-static (`ConstantFloor(0.55)`)** as the V5 default. If decay is explored in D2:

1. For exponential: use **K ≥ 500** (or discovery-rate-normalized K) so the schedule provides a gradual decay rather than saturating instantly.
2. For epoch-staged: move boundaries **earlier** (e.g., 500 / 1000 rather than 2000 / 4000) so the staircase fires *inside* the coverage-discovery window. With current boundaries the schedule is mechanically incapable of moving `local_context_final` regardless of seed count.
3. Add a coverage metric that saturates later than mut~3000 (e.g., compressed-global-context or a coarser CGC grouping per D1.B) to give the schedule something to act on.
```

---

## Task FU-3 — Update **Limitations** in `D1A_SUBSECTION.md`

Append a fifth limitation:

```markdown
5. **Design-power limitation on decayepoch vs V5-static.** decayepoch ≡ V5-static in mut[0, 2000) by construction (deterministic mode + same floor schedule + same arm policy). Since `local_context_final` saturates in this range, the experiment has near-zero power to distinguish decayepoch from V5-static on this metric. More seeds would not fix this; earlier epoch boundaries or a later-saturating metric would.
```

---

## Task FU-4 — Fix empty cells in `d1a_paired_tests.csv` (build script one-liner)

`d1a_paired_tests.csv` line 12 (`time_to_43 V5-decayepoch vs V5`) currently has empty `t_stat`, `p_value`, `note` cells because `scipy.stats.ttest_rel` returns NaN/NaN when all differences are 0, and the code silently writes empty floats.

Patch `a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py` around line 240. Change:

```python
t_stat, p_val = stats.ttest_rel(aligned["a"], aligned["b"])
rows.append({
    ...
    "t_stat": float(t_stat),
    "p_value": float(p_val),
    "note": "",
})
```

To:

```python
diffs = aligned["a"] - aligned["b"]
if diffs.var(ddof=1) == 0 or diffs.eq(0).all():
    t_stat, p_val = float("nan"), float("nan")
    note = "identical values; t-stat undefined (zero variance in differences)"
else:
    t_stat, p_val = stats.ttest_rel(aligned["a"], aligned["b"])
    note = ""
rows.append({
    ...
    "t_stat": float(t_stat),
    "p_value": float(p_val),
    "note": note,
})
```

Re-run `build_d1a_artifacts.py` to refresh `d1a_paired_tests.csv` (everything else regenerates too; that's fine, the other numbers won't change). Verify line 12 now reads:

```
time_to_43,V5-decayepoch vs V5,4,1223.5,1223.5,0.0,nan,nan,identical values; t-stat undefined (zero variance in differences)
```

(or equivalent — what matters is `t_stat`/`p_value` are explicit `nan` and `note` is populated).

---

## Task FU-5 — Document `AUC_DENOM` magic constant (build script comment)

`a4/runs/iv_pos_8/d1a/analysis/build_d1a_artifacts.py` line 58: `AUC_DENOM = N_MUTATIONS * 46`. Add an explanatory comment:

```python
# Hardcoded against ~46 final contexts (R2 V5-static mean). V5 seed 1237 hits 48,
# so this denom is mildly low. AUC values can in principle exceed 1.0 if a DB
# discovers contexts very fast; in practice all observed values are < 1.0.
# If we ever see AUC > 1.0, switch to dynamic max(local_context_final) across set.
AUC_DENOM = N_MUTATIONS * 46
```

No code change, just the comment.

---

## Task FU-6 — Plot 5 cosmetic (notebook only, optional)

In `a4/runs/iv_pos_8/d1a/analysis/build_d1a_notebook.py` Plot 5 cell, replace the boxplots with strip-plots overlaying individual points for clarity at n=4:

```python
fig, axes = plt.subplots(1, 2, figsize=(10, 4))
for ax, col, title in zip(axes, ['time_to_43', 'time_to_46'], ['Time to 43 contexts', 'Time to 46 contexts']):
    for i, v in enumerate(vars_):
        vals = metrics[metrics.variant==v][col].dropna().astype(float).values
        x = np.full_like(vals, i, dtype=float) + np.random.uniform(-0.08, 0.08, len(vals))
        ax.scatter(x, vals, color=COLORS[v], s=40, alpha=0.7, edgecolor='black', linewidth=0.5)
        ax.hlines(vals.mean(), i-0.2, i+0.2, color=COLORS[v], lw=2)
    ax.set_xticks(range(len(vars_)))
    ax.set_xticklabels(vars_)
    ax.set_title(title)
    ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
show_plot(fig, PLOTS / '05_time_to_threshold.png')
```

Then re-execute the notebook:

```bash
jupyter nbconvert --to notebook --execute --inplace a4/runs/iv_pos_8/d1a/IV_POS_8_D1A_NOTEBOOK.ipynb
```

Skip if time-constrained — boxplots are tolerable, just suboptimal at n=4.

---

## Out of scope for this follow-up

| Out of scope | Why |
|---|---|
| Re-running `build_d1a_artifacts.py` other than as required by FU-4 | All other numbers are correct; only FU-4 changes one cell. |
| Touching `build_d1a_notebook.py` other than FU-6 (which is optional) | Notebook is correct as-is; FU-6 is cosmetic only. |
| Re-running the executed notebook | Only required if FU-6 is done. |
| Computing additional seeds (1239-1243 × decay variants) | Out of scope — see Limitation 4. Future spec only. |
| Investigating WHY ConstrainedTSScheduler's mode decision is seed-independent (code-level audit) | Out of scope for D1.A. Flag for D2 if interesting. |
| Modifying any code in `a4/standalone/` or `a4/runs/iv_pos_7/analysis/` | Same as Batch 5 kickoff — treat as read-only API. |
| `git commit` | Opus/Ivan review first. |

---

## Pass criteria for follow-up

| Check | Required state |
|---|---|
| FU-1: Finding C section added to `D1A_SUBSECTION.md` between Finding B and Verdict | Present with the 3 consequences listed |
| FU-2: Verdict rewritten to incorporate power-limitation framing | Mentions deterministic mode + boundary problem explicitly |
| FU-3: Limitation 5 appended | Present, references Finding C |
| FU-4: `d1a_paired_tests.csv` line 12 has `nan`/`nan`/note instead of empty cells | Verified by reading the CSV |
| FU-5: AUC_DENOM comment added | Code reads as specified |
| FU-6 (optional): Plot 5 is strip-plot, not boxplot | If done, file regenerated and notebook re-executed |
| `d1a_build_summary.json` unchanged | Numbers should not move from FU-4 (test logic doesn't change the means, only the notation for zero-variance case) |

When done, write a short addendum at `a4/docs/cloud2/composer/D1A_BATCH5_REPORT.md` (append to the existing file) noting which follow-ups completed and which skipped.

**Then wait for seed 1238 (ETA ~14:00 CEST) → run Task 5.4 refresh → final report.**
