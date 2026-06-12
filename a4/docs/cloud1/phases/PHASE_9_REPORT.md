# Phase 9 — Analysis & Report for ChatGPT Pro Round 2

**Status**: ⚪ PENDING (depends on Phase 8 complete)
**Owner**: Cursor + user
**Estimated effort**: 4 hours
**Risk**: low (analysis only)

---

## Tasks

### 9.1 Compute primary metrics [Pro §10]
For each of the 5 variants (averaging over 10 seeds):
- [ ] `local_context_final` (mean ± σ, max 46)
- [ ] `local_context_AUC` (∫ coverage(t) dt over t∈[0, 6000])
- [ ] `time_to_40`, `time_to_43`, `time_to_46` (mutations to reach N contexts; "never" if not reached)
- [ ] `per_seed_all_46_hit_rate` (count of seeds reaching 46 / 10)
- [ ] `compressed_global_context_final` (using v2 contexts)
- [ ] `crash_rate` (% of mutations that crashed)
- [ ] `no_effect_rate` (% of mutations with l_new=0, f_new=0, g_new=0, s_new=0)
- [ ] `allocation_entropy_by_kind` (Shannon entropy over 8 kinds)
- [ ] `allocation_entropy_by_zone` (Shannon entropy over 17 zones, where applicable)

### 9.2 Statistical tests
- [ ] Paired t-test: each variant vs `zoned_current` on `local_context_AUC`
- [ ] Paired t-test on `local_context_final`
- [ ] Variance ratio: variant σ / zoned σ
- [ ] Mann-Whitney U as robustness check

### 9.3 Success criteria check [Pro §10]
For each variant, mark which success criteria are satisfied:
- [ ] Criterion 1: AUC > zoned_current with p<0.05
- [ ] Criterion 2: Final coverage matches zoned with σ ratio <0.7
- [ ] Criterion 3: time_to_43 / zoned's time_to_43 < 0.7
- [ ] Criterion 4: local coverage ≥ zoned AND compressed-global > zoned + 20%
- [ ] Criterion 5: discovered a new context (only possible if universe expanded — unlikely without new guests; flag if yes)

### 9.4 Counterfactual analysis [Pro §12]
For all variants:
- [ ] Distribution of `current_reward` vs `no_qloc_reward`
- [ ] Distribution of `discovery_binary_reward` vs `current_reward`
- [ ] Heatmap: arm × reward type
- [ ] Confirm v2 ranks INSTR_TYPE_MOD higher than v1

### 9.5 Per-arm diagnostic (for cTS_semantic_v2)
- [ ] Arm pull distribution by mode (cold/singleton/floor/adaptive)
- [ ] Per-arm posterior at end of campaign
- [ ] Per-arm cumulative reward
- [ ] Identify which arms TS spent its adaptive budget on

### 9.6 Generate report
- [ ] `a4/runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`
  - TL;DR (1 paragraph)
  - Variant-by-variant results
  - Success criteria check
  - Counterfactual analysis
  - Honest conclusion (does v2 beat zoned? if so by how much? if not, what's the next hypothesis?)
  - Reference to `CLOUD1_DECISIONS_FOR_PRO_R2.md` (every choice we made beyond Pro spec)

### 9.7 Generate notebook
- [ ] `a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`
- [ ] All cells executable; all plots regenerable
- [ ] AUC curves, time-to-N stacked, kind/zone allocation heatmaps, reward counterfactual scatter

### 9.8 Send to ChatGPT Pro
- [ ] Package: `ProG_Report_2.md` (original Pro recommendations) + `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` (our results) + `CLOUD1_DECISIONS_FOR_PRO_R2.md` (our deviations and silent-point decisions)
- [ ] Awaiting Pro's response before next move

---

## Exit criteria

- Report and notebook produced
- All 50 DBs analyzed
- Honest conclusion stated
- Materials sent to Pro Round 2

---

## Decision tree post Pro Round 2

```
Pro Round 2 response →
├── "v2 architecture is good, proceed to step 5 (new guests)" →
│       resume master plan with semantic-zone architecture as baseline
├── "v2 architecture has issues X, Y" →
│       cloud2: a smaller targeted campaign fixing X, Y
└── "structural priors fundamentally dominate adaptive selection on this target" →
        publish IV.POS.7 as negative result; pivot to different research question
```

---

## Notes / decisions made during phase

(to be filled as work progresses)
