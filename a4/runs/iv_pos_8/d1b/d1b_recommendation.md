# D1.B — CGC Coarsening Recommendation (D2 Default Reward Signal)

**Audience:** D2 design proposal + Ivan/Opus internal  
**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.3 §3.4  
**Corpus:** 20 decay-comparison DBs (corrected labeling, Batch 1.6 replay)  
**Date:** 2026-06-17

---

## TL;DR

**Keep `production_log2_corrected` as the D2 default CGC reward signal** (with the Batch 1.6 `byte_addr` field-priority fix applied in production). **Do not** replace L0 bucketing with `region_only`, `log4_explicit`, or `page_class`.

**Reasoning:** Only corrected production log2 has a CGC asymptotic-saturation point (mut ~3400) that lands **after** local catalog saturation (mean `time_to_46` ≈ **3221** on paired V5 seeds). Coarsened variants enter their asymptotic CGC regime at mut **1300–1800** — roughly **1400–1900 mutations before** local saturates.

**Honest ceiling:** Even production's post-local headroom is **thin** — +179 mut past local sat, ~39 keys remaining ≈ **one new CGC key per ~70 mutations** before campaign end. **None of the four L0 candidates provide robust long-window discrimination**; production is the **least-bad** option. D1.E must look **beyond L0 schema alone** (L1 enrichment, D1.C bug-proximity, `s_new` weighting) for the real fix.

**Secondary signal:** `V5-decayexp` shows a **barely-significant AUC advantage** (+2.5%, p≈0.048) under `page_class` and `region_only` on n=5 paired seeds. Likely cold-start propagation under K=50 (floor at floor_min by d≈7), **not** Pro's intended Stage-2 gradual decay. D1.E forward-run with K≈200–300 is the actual test.

**L1 enrichment:** Open question for D1.E — a naive `g_new_production OR g_new_page_class` is **redundant** when both derive from the same live failure stream (page_class collapses production keys). See §4.

---

## 1. Saturation overlay analysis (centerpiece)

![Absolute CGC saturation overlay](plots/d1b_saturation_overlay_v5.png)

![Normalized CGC saturation overlay](plots/d1b_saturation_overlay_v5_norm.png)

Black dashed line = local catalog saturation (mean `time_to_46` = 3221). Filled dots = per-variant CGC asymptotic saturation (`d1b_saturation_profile.csv`). Coarsened variants flatten **left** of local sat; production crosses local sat still climbing.

**Normalized reading:** At mut **3221** (local sat), coarsened variants are at **~84–85%** of their (smaller) final count with only **~18 keys** remaining; production is at **~82%** with **~39 keys** remaining (~2× absolute headroom). The inversion is clearest on the **absolute** plot: coarsened curves flatten toward their lower ceilings **before** mut 2000, while production keeps climbing past the local-sat line.

### 1.1 Local catalog saturation (from D1.A paired V5 seeds)

| Metric | Value |
|---|---:|
| Mean `time_to_46` | **3221** |
| Median `time_to_46` | **3099** |
| Mean `local_context_final` | **46.4** |

Source: `d1a_metrics_table.csv`, seeds 1234–1238, variant `V5`.

### 1.2 CGC saturation (from D1.B)

| CGC variant | `saturation_mutation_id` | `saturation_cgc_d` | Memory keys (V5 mean) |
|---|---:|---:|---:|
| `production_log2_corrected` | **3400** | 180 | 122.0 |
| `log4_explicit` | **1800** | 84 | 24.4 |
| `page_class` | **1300** | 67 | 14.5 |
| `region_only` | **1300** | 62 | 9.5 |

### 1.3 Overlay table

| L0 candidate | CGC sat. mut | Gap vs local | Keys remaining at mut 3221 | Post-local rate |
|---|---:|---:|---:|---|
| **`production_log2_corrected`** | 3400 | **+179** | ~39 / 216 | ~1 key / 70 mut |
| `log4_explicit` | 1800 | −1421 | ~18 / 120 | exhausted |
| `page_class` | 1300 | −1921 | ~18 / 110 | exhausted |
| `region_only` | 1300 | −1921 | ~18 / 105 | exhausted |

### 1.4 Inversion of Pro §11 intent + thin headroom

Pro's §11 hypothesis: semantic `page_class` would extend `bandit_success` discrimination past local saturation. **Empirically inverted:** fewer keys → faster CGC saturation → **shorter** post-local window if deployed as L0.

**Sharper Pro disclosure:** Pro's L0-swap idea was wrong for extending discrimination, but **no L0 candidate does well** — all four are effectively saturated by mut ~3400–3500. Production wins on relative ranking, not on providing a rich post-local learning window. D1.E's reward rewire must extend beyond L0 bucketing.

---

## 2. AUC analysis (decayexp-specific)

| CGC variant | Δ AUC (decayexp − V5) | p-value |
|---|---:|---:|
| `page_class` | +0.0253 | **0.0481** |
| `region_only` | +0.0259 | **0.0484** |
| `production_log2_corrected` | +0.0228 | 0.0588 |
| `log4_explicit` | +0.0234 | 0.0591 |

decayepoch: all p &gt; 0.19.

**Deeper caveat:** With K=50, decayexp reaches `floor_min` by d≈7 — virtually no active floor schedule after cold-start. The AUC delta vs V5-static likely propagates from **mut 0–100** exploration differences, not Pro's intended Stage-2 mechanism. D1.E with K≈200–300 tests the real design.

---

## 3. Final-count analysis

Paired `cgc_final`: no significant decay effect (all p &gt; 0.05). V5 mean **218.2** (all 10 DBs) vs **216.2** (paired 5 seeds).

---

## 4. D2 recommendation

| Decision | Recommendation |
|---|---|
| **D2 default CGC reward (L0)** | **`production_log2_corrected`** + Batch 1.6 `byte_addr` fix |
| **L0 swap to coarsened variants** | **Reject** |
| **L1 semantic enrichment** | **Open question for D1.E** (see below) |
| **decayexp AUC hint** | D1.E forward-run K≈200–300 |

### L1 enrichment — open question for D1.E (not pre-answered here)

When both signals derive from the **same live failure** with aligned extraction, `page_class` first-hits are largely a **subset** of production first-hits: page_class collapses many production `(region, log2_bucket, txn_role, cycle_phase)` keys into one semantic label. A naive OR:

```
bandit_success = 1 if (l_new OR g_new_production OR g_new_page_class OR s_new) > 0 else 0
```

adds **little or no signal** — `g_new_page_class` is dominated by `g_new_production`.

*(Note: Batch 2's `page_class` metric uses `global_failures` Path 3 while production uses hook3 replay Path 1, so post-hoc first-hit maps can diverge at ~3 mutations per DB. That is a methodology artifact, not a runtime L1 property.)*

**D1.E should evaluate richer mechanisms** — none recommended as D2 default here:

1. **Separate per-channel reward tracking** — independent Beta-Bernoulli posteriors per signal dimension
2. **Weighted reward boost** for page_class novelty (semantic hits worth more than geometric)
3. **Multi-objective bandit** — treat production and page_class novelty as separate dimensions (Pareto-style)

Also candidates outside L1 schema: D1.C bug-proximity signals, `s_new` weighting, Pro §7 Stage-2 channels (marginal discovery, cofailure, repairability).

---

## 5. Pro feedback solicited

1. Confirm `byte_addr` labeling field (NFP-10).
2. Saturation inversion + thin headroom: does Pro still want `page_class` as L0 given post-hoc evidence?
3. Which L1 enrichment mechanism should D1.E prototype?

---

## Provenance

| Artifact | sha256 |
|---|---|
| `d1b_metrics_table.csv` | `49aa8e0e9ae219f4e7c586fe3ffa3d3989399d8e2ee56438103da0b65e4343fb` |
| `d1b_paired_tests.csv` | `ce4300f7a90cb66ab8877bf460b23b9e8b4a37ea15c5df4c37695bb2f115ce3c` |
| `d1b_saturation_profile.csv` | `6c55062f19fa36f68b00984991d3320a38b265e42fb2ee2d99c0a909e7b0b196` |
| Base git commit (uncommitted D1.B work) | `4fce6649946300729937595a66543afda53a1f3d` |
