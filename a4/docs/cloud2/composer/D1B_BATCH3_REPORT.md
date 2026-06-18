# D1.B Batch 3 — Composer Report

**Spec:** `IV_POS_8_D1_B_SPEC.md` v0.4.3 §3.4  
**Scope:** Recommendation + D1.E hand-off + Pro-facing subsection  
**Branch:** `cloud2` (uncommitted)  
**Date:** 2026-06-17

---

## 1. Opus review response (critical verification)

Opus verified Batch 2 as **GREEN**; Batch 3 polish as **GREEN** with nuances.

| Opus claim | Verified? | Notes |
|---|---|---|
| Implementation + sanity invariants | ✅ | |
| AUC decayexp p≈0.048 | ✅ | |
| Saturation inversion (absolute plot) | ✅ | |
| L1 OR redundant at runtime | ✅ | 3 post-hoc divergences = Path-3 vs replay artifact |
| Thin production headroom (~1 key/70 mut) | ✅ | Incorporated |
| decayexp AUC = cold-start under K=50 | ✅ | Deepened |
| Normalized ">90% at mut 1500" | ❌ | Recompute: all variants ~63–67% at mut 1500; use absolute plot + remaining keys |
| Overlay plots embedded | ✅ | `d1b_saturation_overlay_v5.png` + `_norm.png` in notebook + deliverables |

**Correction applied in Batch 3 docs:** Opus cited local saturation at mut "~2500". Verified paired V5 mean `time_to_46` = **3221**, median **3099** (D1.A `d1a_metrics_table.csv`). Saturation inversion finding **direction unchanged** but gap arithmetic updated:

- production CGC sat vs local: **+179 mut** (not +900)
- page_class vs local: **−1921 mut** (worse than −1200)

The inversion is **stronger** with corrected local anchor: coarsened variants exhaust CGC discovery even earlier relative to local saturation than Opus's table suggested.

---

## 2. Deliverables

| File | Purpose | Status |
|---|---|---|
| `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` | D2 CGC default recommendation | ✅ |
| `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` | D1.E L0 hand-off (NOT K) | ✅ |
| `a4/runs/iv_pos_8/d1b/D1B_SUBSECTION.md` | Pro-facing subsection (D1A template) | ✅ |
| `a4/docs/cloud2/composer/D1B_BATCH2_REPORT.md` | Amended per Opus feedback | ✅ |

---

## 3. Recommendation summary

**D2 default:** `production_log2_corrected` + Batch 1.6 `byte_addr` fix.

**Reject L0 swap** to `page_class`, `region_only`, `log4_explicit` — saturation overlay shows coarsened variants enter asymptotic CGC regime ~1400–1900 mutations before local catalog saturates.

**L1 enrichment:** Open D1.E design question (naive OR redundant). See `d1b_recommendation.md` §4.

**decayexp AUC:** Promising n=5 hint; D1.E forward-run with K≈200–300.

---

## 4. Batch 3 exit criteria (§3.4)

| Criterion | Status |
|---|---|
| `d1b_recommendation.md` with saturation centerpiece | ✅ |
| `d1e_handoff_CGC_saturation.md` with local overlay + K non-scope | ✅ |
| `D1B_SUBSECTION.md` Pro disclosures (NFP-10 + page_class map) | ✅ |
| AUC + saturation-inversion surfaced explicitly | ✅ |
| Batch 1.5b chain-of-custody documented | ✅ |

**Pending:** Opus + Ivan review pass; Ivan squash commit; D2 ack on extractor patch.

---

## 5. D1.B state

```
Batch 1     ✅
Batch 1.5   ✅
Batch 1.5b  ✅ (user_dynamic)
Batch 1.6   ✅ (byte_addr fix + replay)
Batch 2     ✅ (verified by Opus)
Batch 3     ✅ (this report)
```

D1.B implementation complete pending review + commit.

**Polish pass (2026-06-17):** dates fixed; L1 OR-channel reframed as open D1.E question; thin headroom paragraph added; saturation overlay plots embedded in deliverables + notebook.
