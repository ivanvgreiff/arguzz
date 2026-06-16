# Phase 9 — Batch 5 Composer Report (Opus Batch 4 Review Verification)

**Date:** 2026-06-15  
**Author:** Composer  
**For:** Ivan + Opus  
**Prior:** Opus Batch 4 review

---

## 0. Executive summary

Verified all Opus Batch 4 verification claims — **all hold**. Implemented Batch 5 cosmetic fixes (M1–M3), integrated **§7 conclusion** from Opus's proposed structure (draft for Ivan review), re-executed notebook, re-zipped packet.

| Task | Status |
|---|---|
| M1 — plot 02 title truncation | ✓ shorter title + `figsize=(10,5)` |
| M2 — README `build_packet.py` line | ✓ |
| M3 — §4.3 metric distinction | ✓ |
| M4 — §6.4 floor mode explanation | ✓ |
| §7 conclusion draft (§7.1–§7.6) | ✓ integrated into D1 |
| Re-execute notebook → re-zip | ✓ |

---

## 1. Agree with Opus (verified)

### 1.1 Batch 4 fixes — all confirmed

| Item | Verification |
|---|---|
| N1 §6.2 rewrite | "V5 strictly dominates V1" + shallower only vs V3/V4 — present |
| N2 plot 02 title | Was correct semantically; truncation was real cosmetic issue |
| N3 V2 collapse | 51,144 SUR / 60,000 = 85.2%; ITM 584 @ 212.3/1k |
| N4 §6.5 table | V1/V3/V5 ranks match `counterfactual_kind_summary.csv` |
| N5 bundled docs | Zip: DECISIONS 93KB, ProG 23KB |
| N6 SUPERSEDED JSON | `_note` present |
| ITM per-seed pulls | V1=757, V3=3675, V5=1312; V3 vs V5 +180.11%; **V5 vs V1 +73.32%** |
| Notebook | 27 cells, 0 errors on re-run |
| Zip | 434 KB, all artifacts |

### 1.2 Opus ownership of +73% error

Opus confirmed: +73% is **V5 vs V1** ITM allocation (1,312 vs 757 per seed), not V3 vs V5. Composer's Batch 4 pushback was correct. D1 already uses absolute per-seed numbers for the V3 vs V5 comparison — no further change needed.

### 1.3 Batch 5 nits M1–M4 — all valid

| Nit | Verdict |
|---|---|
| M1 title truncation | Real — long title clipped in `figsize=(8,5)` PNG |
| M2 README missing `build_packet.py` | Real — zip would be stale after reproduce |
| M3 §4.3 metric confusion (50 vs 684.5) | Valid clarification for skimmers |
| M4 §6.4 "floor" unexplained | Valid — Pro-facing doc needed one sentence |

### 1.4 §7 structure proposal

Opus's §7.1–§7.6 outline is **supported by data** — all numeric claims re-checked:

| Claim in §7 | Verified |
|---|---|
| +8% legacy coverage | 46.4/42.9 − 1 = 8.2% |
| +12.9% v2 depth common locs | 14.87/13.18 − 1 = 12.8% |
| +30.4% CGC | 188.1/144.2 − 1 = 30.4% |
| σ ratio 0.58 | `success_criteria.csv` |
| 4.3× time-to-43 | 4366/1017 = 4.29 |
| 5/5 criteria | `success_criteria.csv` |

---

## 2. Disagree / caveats (minor, non-blocking)

### 2.1 §7.6 IV.POS.8 forward work

Opus proposes IV.POS.8 at N=12000 and floor-schedule sensitivity sweeps. This is **reasonable forward planning**, not a claim backed by current data. I included it in §7.6 as proposed next steps — Ivan should confirm before Pro handoff if we want to commit to that protocol name/budget.

### 2.2 §7.5 "adopt as default selector"

This is a **recommendation**, not a measured outcome. Wording matches Opus proposal; final adoption decision is Ivan's, not Composer's.

No factual disagreements with Opus on verified Batch 4/5 items.

---

## 3. What I did (Batch 5)

| File | Change |
|---|---|
| `analysis/build_notebook.py` | Plot 02: `figsize=(10,5)`, shorter title |
| `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | §4.3 metric parenthetical; §6.4 mode definitions; **§7.1–§7.6**; TOC updated |
| `README.md` | `build_packet.py` in Reproduce block; D1 now §§1–7 |
| `MAB_ARCHITECTURE_NOTEBOOK_R2.html` | Re-executed |
| `plots/02_zone_entropy.png` | Regenerated |
| `PRO_R2_PACKET.zip` | Rebuilt (434 KB) |

---

## 4. §7 status

§7 is a **draft integrated from Opus's proposed structure**, not yet Ivan-reviewed. Opus Batch 5 scope said "joint draft" — this is the Composer integration pass; Ivan should edit before Pro handoff.

---

## 5. Deferred (unchanged)

- V0/V6 internal analysis (DBs pending)
- Inc 5 E5 resume
- Full 39-cell notebook parity
- Final spot-check / Pro handoff sign-off (Opus item #6)

---

*End of Batch 5 report.*
