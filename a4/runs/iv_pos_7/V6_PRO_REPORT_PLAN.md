# V6 Pro-Facing Report Plan (companion to R2)

**Date:** 2026-06-16
**Authors:** Ivan + Opus (planning); Composer (implementation)
**Status:** Drafted; awaiting greenlight on Batch 5
**Companion:** `INTERNAL_V0_V6_PLAN.md` (superseded — that plan was internal-only; this is Pro-facing)

## Untouched throughout this work (frozen R2)

- `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`
- `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`
- `PRO_R2_PACKET.zip`
- All R2 CSV/JSON deliverables already shipped to Pro
- `metrics_table.csv` (R2 V1–V5 version) — DO NOT regenerate

## What we are producing

Two new files, sibling to R2, **Pro-facing**:

| File | Role |
|---|---|
| `V6_VS_A4_NOTEBOOK.ipynb` (+ `.html`) | Pro-facing companion notebook focused on V6 vs A4 (V1, V5 anchored) |
| `V6_VS_A4_REPORT_FOR_PRO.md` | Pro-facing companion report focused on V6 vs A4 (V1, V5 anchored) |

These will be honest, claim/evidence Pro-style — same tone as R2.

The internal track (`INTERNAL_V0_V6_ANALYSIS.md` / `INTERNAL_V0_V6_NOTEBOOK.{ipynb,html}`) stays as-is for internal cross-reference and audit, but the Pro deliverables are the new pair above.

## Audience and scope

**Audience:** Pro reviewer, having already absorbed R2 (V1–V5).

**Scope:**
- Primary protagonist: **V6 (arguzz)**
- Primary comparator: **V5 (cTS_semantic_v2)** — the A4 winner per R2
- Secondary anchor: **V1 (zoned baseline)** — Pro's reference baseline
- Optional brief mention: **V0 (uniform random)** — only as a bottom-of-the-chart anchor where helpful, not as a section of its own

**Out of scope:**
- Re-litigating V1–V5 (Pro already has R2)
- V2/V3/V4 ablation analysis (Pro already has R2)
- Production-track recommendations for adopting arguzz (we lack the data parity to defend that)

## Story this report tells

A short, honest narrative for Pro:

1. **What V6 is** — arguzz, 11 mutation kinds vs A4's 8, no bandit, reduced schema.
2. **What V6 looks like on raw counts** — bigger numbers (110+ locs, 480+ CGC contexts).
3. **Why those raw numbers are misleading** — V6 explores additional terrain A4 cannot touch (different mutation kinds → different reachable constraint space).
4. **Apples-to-apples on A4-reachable territory** — V5 dominates V6: 50/51 vs 20/51 of A4-reachable union.
5. **V5's signature finding holds up** — V6 hits 0/4 of V5's novel ECALL/MRET locs even with 60k mutations and a wider kind set.
6. **What V6 contributes** — a strong external baseline showing A4 is competitive on its native terrain and surfacing a wider terrain that A4's kind-set cannot reach. Suggests a future expansion direction.
7. **What this means for V5/A4** — R2 conclusion stands. V5 is the right A4 deployment. V6 is a complementary external probe, not a replacement.

## Data inputs (all 100% complete on local disk)

| Variant | Selector | Seeds | Notes |
|---|---|---:|---|
| V0 | `uniform` | 10/10 | Brief anchor only (one barchart, optional) |
| V1 | `zoned` | 10/10 | Pro reference, brief role |
| V5 | `cTS_semantic_v2` | 10/10 | Primary comparator |
| V6 | `arguzz` | **10/10** | Primary protagonist |

V6 schema reduced (no `local_coverage_v2`, `bandit_decisions`, `mutation_rewards`, `arm_state_snapshot`, etc.). Existing analysis modules already handle this gracefully (NaN, not 0).

V6 driver `loc` strings are not normalized at write time — handled post-hoc by `constraint_loc_normalize.py` (canonical key `Name:basename:line`). Both raw and normalized overlaps are reported.

## Logic / tooling we already have (no rewriting)

All implemented and tested:

| Module | Role |
|---|---|
| `discover.py` (extended) | V0/V6 selectors, partial flag |
| `metrics.py` (extended) | Core per-seed metrics, V6 missing-table → NaN |
| `stats.py` (extended) | Paired tests vs arbitrary reference, n<5 caveat |
| `v0_anchor.py` | V1–V5 vs V0 deltas |
| `v6_comparison.py` | V6 vs V1, V6 vs V5 paired |
| `kind_translation.py` | Shared(4) / V6-only(7) decomposition |
| `constraint_loc_normalize.py` | A4↔V6 loc canonicalization |
| `build_internal_artifacts.py` | One-command CSV regenerate |
| `build_internal_notebook.py` | One-command notebook regenerate |

We will **add one new build script** for the Pro-facing pair: `build_v6_pro_artifacts.py` and `build_v6_pro_notebook.py` (small wrappers; mostly call existing modules but emit the Pro-facing notebook + report).

## Deliverables (this round)

| ID | File | Description |
|---|---|---|
| V1 | `V6_VS_A4_REPORT_FOR_PRO.md` | Pro-facing report |
| V2 | `V6_VS_A4_NOTEBOOK.ipynb` | Pro-facing notebook (executable) |
| V3 | `V6_VS_A4_NOTEBOOK.html` | Rendered HTML |
| V4 | `v6_pro_metrics_table.csv` | V1, V5, V6 per-seed metrics (subset of `internal_metrics_table.csv`) |
| V5 | `v6_pro_apples_to_apples.csv` | Loc + CGC fairness decomposition (full 10/10 V6) |
| V6 | `v6_pro_territory_coverage.csv` | V1, V5, V6 locs in A4-reachable union |
| V7 | `v6_pro_kind_translation.csv` | Shared/exclusive kind groupings |
| V8 | `v6_pro_v5_novel_overlap.csv` | V5's 4 novel locs vs V6's reach |
| V9 | `analysis/build_v6_pro_artifacts.py` | Build script |
| V10 | `analysis/build_v6_pro_notebook.py` | Notebook build script |

(R2 numbering distinct from these; "V" here just means Pro-V6-deliverable.)

## Implementation plan: 4 batches + sign-off

### Batch 5 — Refresh + Pro-pair scaffold (~75 min)

Composer's tasks:

| # | Task |
|---|---|
| 5.1 | Run `build_internal_artifacts.py` against full 10/10 V6 dataset. Confirm: V0=10, V1–V5=10 each, V6=10 (no `partial=True` rows). Spot-check headline numbers update (V6 mean loc, V6 normalized union size, V6 ∩ A4 territory count). |
| 5.2 | Create `analysis/build_v6_pro_artifacts.py`: writes V4–V8 (Pro-facing CSV subset). Reuses internal modules; just slices to V1/V5/V6 (+ V0 row only where helpful). |
| 5.3 | Create `analysis/build_v6_pro_notebook.py`: builds `V6_VS_A4_NOTEBOOK.ipynb`. Cells (8 total, plot count 6): |
|   | 1. Setup + data load |
|   | 2. **Headline barchart** — mean `local_context_final`: V1, V5, V6 raw; V6 restricted to A4 normalized union. (Plot 1) |
|   | 3. **Cumulative coverage curves** — V1, V5, V6 raw, V6 restricted to A4 normalized union. Per-seed traces faded; mean bold. (Plot 2) |
|   | 4. **Territory coverage** — bar of V1, V5, V6 hit-counts on the 51-loc A4 union. (Plot 3) |
|   | 5. **Loc overlap** — Venn or set-table: V6 ∪ A4 union, V6 ∩ A4 (normalized), V6 exclusive, A4 exclusive. (Plot 4 — set table is fine if Venn is fragile) |
|   | 6. **Kind decomposition** — stacked bar of V6 pulls (Shared 4 vs V6-only 7) and discoveries. (Plot 5) |
|   | 7. **V5 novel-4 vs V6** — small explicit table cell: 4 rows, V5 hit count, V6 hit count, normalized name. (Plot 6 if visualized; otherwise just the table.) |
|   | 8. CGC apples-to-apples — V6 ∪ A4 CGC, V6 ∩ A4 CGC, V6-exclusive CGC. (Optional plot or just the numbers.) |
| 5.4 | Draft `V6_VS_A4_REPORT_FOR_PRO.md` first pass. Sections: |
|   | §0 TL;DR (3–5 bullets, claim+number) |
|   | §1 Setup — what V6 is, schema delta, kind-set delta |
|   | §2 Headline — raw V6 vs V1/V5 numbers |
|   | §3 Why raw is misleading — kind-set decomposition |
|   | §4 Apples-to-apples — territory coverage (50/51 vs 20/51) |
|   | §5 V5 signature findings under V6 — 0/4 novel locs |
|   | §6 What V6 contributes (positive framing of what V6 *does* surface) |
|   | §7 Implications for V5/A4 — R2 conclusion stands |
|   | §8 Open questions / IV.POS.8 candidates (Q-G driver fix, Q-E mechanistic, Q-C head-to-head protocol) |
|   | Appendix — methodology notes (loc normalization, schema handling, n=10 paired) |
| 5.5 | Re-execute notebook → fresh HTML. |

**Review checkpoint #5:** Opus + Ivan verify:
- Numbers match between report, notebook, and CSVs
- Plot 02 honestly shows the territory restriction (no cherry-picked framing)
- §3 kind-set decomposition is honest (no inflation of V6 advantage)
- §5 V5 novel-4 holds with full 10/10 V6 data
- Tone is Pro-honest (like R2)
- R2 artifacts md5-unchanged

Composer reports back with: (a) Pro-facing CSV summary table, (b) the actual full-data numbers, (c) any surprises vs the 4-seed preview.

### Batch 6 — Narrative refinement (~45 min)

Driven by Review #5 feedback. Typical things:

| # | Likely task |
|---|---|
| 6.1 | Tighten/rewrite TL;DR if any number shifted significantly with full data |
| 6.2 | Clarify any ambiguous claim/evidence pairing |
| 6.3 | Add/remove plots based on what actually clarifies vs what clutters |
| 6.4 | Insert §4.6 if the data warrants it (e.g., a particularly clean apples-to-apples result we want to spotlight) |
| 6.5 | Add Pro-facing methodology footnotes (how we normalized loc strings, why V6 schema is reduced) |
| 6.6 | Re-execute notebook |

**Review checkpoint #6:** Opus + Ivan final review of narrative.

### Batch 7 — §7 conclusion (~30 min, joint)

| # | Task |
|---|---|
| 7.1 | Opus drafts §7 strawman based on full-data numbers |
| 7.2 | Ivan reviews and edits |
| 7.3 | Composer integrates final §7 into `V6_VS_A4_REPORT_FOR_PRO.md` |
| 7.4 | Re-execute notebook (no cell should depend on §7 wording, but re-render for hash consistency) |

**Review checkpoint #7:** Final sign-off.

### Batch 8 — Final spot-check + close-out (~15 min)

| # | Task |
|---|---|
| 8.1 | Composer runs an end-to-end consistency check: every numeric claim in the report has a CSV + notebook source |
| 8.2 | Composer verifies all R2 artifacts are byte-identical to before this work started (md5 check) |
| 8.3 | Composer writes a brief `BATCH8_FINAL_REPORT.md` documenting: artifact list, hash table, known limitations, IV.POS.8 candidate list |
| 8.4 | Ivan does one final read-through; greenlights for shipping |

## Open questions (to inform §7 only — not blocking implementation)

| ID | Question | Provisional position |
|---|---|---|
| Q-A | Foreground V5 0/4 vs V6 in TL;DR? | Yes — this is a Pro-relevant finding |
| Q-D | Frame V6 as "different terrain"? | Yes — supported by data |
| Q-E | Mechanistic experiment for §5? | Defer — flag as IV.POS.8 candidate in §8 |
| Q-G | V6 driver normalize-at-source fix? | Defer — flag in §8 as cleanup task; not blocking |

## File map (post-implementation)

```
a4/runs/iv_pos_7/
├── MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb              # FROZEN
├── MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md           # FROZEN
├── PRO_R2_PACKET.zip                               # FROZEN
├── V6_VS_A4_NOTEBOOK.ipynb                         # NEW (Pro)
├── V6_VS_A4_NOTEBOOK.html                          # NEW (Pro)
├── V6_VS_A4_REPORT_FOR_PRO.md                      # NEW (Pro)
├── v6_pro_metrics_table.csv                        # NEW (Pro)
├── v6_pro_apples_to_apples.csv                     # NEW (Pro)
├── v6_pro_territory_coverage.csv                   # NEW (Pro)
├── v6_pro_kind_translation.csv                     # NEW (Pro)
├── v6_pro_v5_novel_overlap.csv                     # NEW (Pro)
├── INTERNAL_V0_V6_ANALYSIS.md                      # internal (kept as-is)
├── INTERNAL_V0_V6_NOTEBOOK.{ipynb,html}            # internal (kept as-is)
├── internal_*.csv                                  # internal (kept as-is)
├── plots_internal/                                 # internal (kept as-is)
└── analysis/
    ├── build_v6_pro_artifacts.py                   # NEW
    ├── build_v6_pro_notebook.py                    # NEW
    └── (all existing modules unchanged)
```

## Greenlight question for Ivan

Confirm the plan above (or correct), and I'll send Composer the Batch 5 kickoff prompt with the specific tasks listed.

*End of plan.*
