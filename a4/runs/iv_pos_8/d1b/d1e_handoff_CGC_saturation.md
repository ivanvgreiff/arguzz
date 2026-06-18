# D1.E Hand-off — CGC Saturation Profiles (L0 + D2 Reward CGC)

**From:** D1.B Batch 2/3  
**To:** D1.E spec authors (L0 rewire + counterfactual replay)  
**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.3 §0.1.1, §3.4  
**Date:** 2026-06-17

---

## Scope statement (read first)

**D1.B's CGC saturation does NOT drive `ExponentialDecayFloor.K`.** Per Pro §7 (`bandit_ts.py:98-100`), K is driven by `_local_discoveries` = cumulative legacy `coverage` row count. K characterization belongs in the **D1.E spec**, not this note.

**This hand-off feeds:**
1. **D1.E L0 design** — whether to replace production log2 bucketing
2. **D2 default CGC reward choice**

---

## 1. Per-variant CGC saturation

| CGC variant | `saturation_mutation_id` | `saturation_cgc_d` | `saturation_bin_avg_new_keys` |
|---|---:|---:|---:|
| `production_log2_corrected` | 3400 | 180 | 0.8 |
| `log4_explicit` | 1800 | 84 | 0.6 |
| `page_class` | 1300 | 67 | 0.8 |
| `region_only` | 1300 | 62 | 0.8 |

Definition: first 100-mut bin with &lt;1 new CGC key avg across paired V5 seeds (1234–1238). Source: `d1b_saturation_profile.csv`.

**Visual:** `plots/d1b_saturation_overlay_v5.png`, `plots/d1b_saturation_overlay_v5_norm.png`

---

## 2. Local saturation profile

| Metric | Mean | Median |
|---|---:|---:|
| `local_context_final` | 46.4 | 46 |
| `time_to_46` | **3221** | **3099** |

Source: `d1a_metrics_table.csv`, V5 paired seeds.

```sql
SELECT first_hit_mutation_id FROM coverage ORDER BY first_hit_mutation_id;
```

---

## 3. Overlay analysis

| L0 candidate | CGC sat. | Gap vs local (3221) | Remaining at mut 3221 |
|---|---:|---:|---:|
| **`production_log2_corrected`** | 3400 | **+179** | ~39 |
| `log4_explicit` | 1800 | −1421 | ~18 |
| `page_class` | 1300 | −1921 | ~18 |
| `region_only` | 1300 | −1921 | ~18 |

**Thin headroom honesty:** Production's +179 mut gap ≈ **1 new CGC key per 70 mutations** post-local-sat. All four L0 candidates are effectively exhausted by mut ~3500. **L0 alone cannot solve D1.A Finding F** (reward-signal saturation). D1.E must evaluate mechanisms beyond L0 bucketing.

---

## 4. D1.E recommendations

| Path | Recommendation |
|---|---|
| **L0** | **Keep `production_log2_corrected`** + Batch 1.6 `byte_addr` fix |
| **L0 swap to coarsened variants** | **Reject** |
| **L1 enrichment** | **Open design question** — see below |

### L1 enrichment (D1.E to design — not pre-answered)

`page_class` first-hits from the **same live failure stream** largely collapse into production first-hits. A naive OR of `g_new_production + g_new_page_class` is **redundant** at runtime.

D1.E spec should evaluate:

1. **Separate per-channel reward tracking** (independent posteriors per signal)
2. **Weighted reward boost** for page_class novelty
3. **Multi-objective bandit** (production vs semantic as separate dims)

Plus non-L0 candidates: D1.C bug-proximity, `s_new` weighting, Pro §7 Stage-2 channels.

None of these are D2 defaults from D1.B; D1.E picks one to test in forward-run.

---

## 5. Decay-variant interaction

decayexp +2.5% AUC under coarsened variants (p≈0.048, n=5). With K=50, floor is at `floor_min` by d≈7 — AUC delta likely cold-start artifact, not Stage-2 decay test. D1.E forward-run: **K≈200–300**.

---

## 6. Artifacts

| File | Purpose |
|---|---|
| `d1b_saturation_profile.csv` | CGC saturation |
| `d1b_metrics_table.csv` | Per-DB metrics |
| `d1b_paired_tests.csv` | Paired tests |
| `d1a_metrics_table.csv` | Local `time_to_46` |
| `d1b_recommendation.md` | Full recommendation |

---

## 7. K boundary (non-scope)

`ExponentialDecayFloor` reads `_local_discoveries` from legacy `coverage`. **This note does not provide K guidance.**
