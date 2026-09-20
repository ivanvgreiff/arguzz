# REPORT — IV.POS.9 Track-B coverage, step-domain re-run campaign (DRAFT, in progress)

Living report for this campaign **only**. Provenance: `PROVENANCE.md`. Figures: `coverage_curves.html`.
All numbers are **cumulative distinct coverage at N=5000, seed 1234, FINAL CAMPAIGN ONLY** (see the
"restart-campaign" note below).

## ⚠️ Methodology note — restart campaigns (read this)
Some seed-1234 bandit jobs were **relaunched** during the chaotic early dispatch (dual dispatcher + the
coinbase memory throttle + greedy relaunches). Each relaunch appended a fresh **campaign** to the same
`run.db`, so those DBs hold multiple campaigns (e.g. `g1_cTS_s1234` = camp1:659 + camp2:530 + camp3:3989 +
**camp4:5000**). **The data is not broken** — the *final* campaign is always a clean, complete 5000-mutation
run; the earlier ones are interrupted partials. **But coverage tables aggregate across all campaigns**, so
summing them inflates CGC 2–3× for those jobs. The extractor therefore reads the **final campaign only**
(max `campaign_id`, re-indexed to 1..N) — verified to match the single-campaign runs of the same guest+variant
across other seeds (e.g. g0_cTS final-camp CGC 569 ≈ s1235 550 ≈ s1236 549). `jobs.csv.ncamp` records how
many campaigns each DB has (1 = clean, >1 = was restarted). **5 jobs affected, all seed-1234 bandits:**
g0_cTS, g0_Hybrid, g1_cTS, g1_Hybrid, g2_cTS.

## Coverage (seed 1234, N=5000, final campaign)

**Compressed Global Contexts (CGC):**
| guest | A3 Bandit (A4) | Arguzz | Arguzz Bandit | A3+Arguzz Bandit |
|---|---:|---:|---:|---:|
| g0_baseline | 321 | 495 | 569 | 439 |
| g1_ecall_control | 323 | 480 | 558 | 430 |
| g2_mem_stress | 303 | 497 | 558 | 445 |
| g3_accelerator | 316 | 498 | 569 | 442 |

**Constraint Locations (LOC):**
| guest | A3 Bandit (A4) | Arguzz | Arguzz Bandit | A3+Arguzz Bandit |
|---|---:|---:|---:|---:|
| g0_baseline | 45 | 33 | 35 | 49 |
| g1_ecall_control | 46 | 33 | 36 | 47 |
| g2_mem_stress | 45 | 36 | 36 | 48 |
| g3_accelerator | 45 | 34 | 36 | 47 |

**Local Contexts (CTX):** A4 ≈ 650–690 · Hybrid ≈ 575–620 · uniform ≈ 290–315 · cTS ≈ 280–300.

## Findings (preliminary — 1 seed)
1. **LOCAL coverage: A4 and Hybrid win, robustly.** ~45–49 constraint-locs vs ~33–36 for pure Arguzz, on every
   guest. The A4 surface (in V5 and Hybrid) ~doubles local-context coverage. **(Unaffected by the restart
   issue — local coverage saturates.)**
2. **GLOBAL (CGC): Arguzz family > A4, but the margin is modest and flat.** Corrected ordering:
   **cTS (~560) > uniform (~490) > Hybrid (~440) > A4 (~315)**. So Arguzz (uniform and bandit) beats A4 ~1.5–1.8×
   on global; A4 is the floor. The cTS bandit adds only **~15%** over plain uniform — not the 3× the
   uncorrected data suggested.
3. **No strong guest-dependence.** CGC is ~flat across g0–g3 for every variant. The earlier apparent "bandit
   collapses on g2/g3" was an **artifact**: g0/g1 seed-1234 bandit jobs were restart-inflated while g2/g3 were
   clean, manufacturing a fake guest effect. Gone after the fix.
4. **Hybrid is below uniform on CGC** — folding in the A4 surface helps local but slightly dilutes global breadth.

### Retracted (were artifacts of restart-campaign aggregation)
- ~~cTS wins global ~3× (1357/1829)~~ → real ~560.
- ~~bandit global advantage collapses on heavy guests~~ → no real guest-dependence.

## Caveats
- Single seed (1234) for the headline; 1235/1236 in progress (will give error bars + replication).
- V5_control (A4) is external (3-kind re-run, same 53c21894 binary; valid — A4 immune to step-domain bug).
- Fair-window N=5000, final campaign only.

## Refresh
`extract_curves.py` (final-campaign-only) on coinbase → split → `build_notebook.py`. Auto-picks newly-`.OK` jobs.
