# Batch 8 — Numerical Claim Audit

**Report:** `V6_VS_A4_REPORT_FOR_PRO.md`  
**Date:** 2026-06-16  
**Purpose:** Cross-reference every numeric claim in the Pro companion report to a source artifact.

---

| § | Claim | Number | Source CSV / artifact | Verified |
|---|---|---|---|---|
| TL;DR | V6 mean `local_context_final` | 108.0 | `v6_pro_metrics_table.csv` (V6 mean) | ✓ |
| TL;DR | V1 mean loc | 42.9 | `v6_pro_metrics_table.csv` (V1 mean) | ✓ |
| TL;DR | V5 mean loc | 46.4 | `v6_pro_metrics_table.csv` (V5 mean) | ✓ |
| TL;DR | Δ vs V1 | +152% | derived: (108.0−42.9)/42.9 ≈ 151.7%, rounded in TL;DR | ✓ |
| TL;DR | Δ vs V5 | +133% | derived: (108.0−46.4)/46.4 ≈ 132.8%, rounded in TL;DR | ✓ |
| TL;DR | V6 mutation kinds | 11 (+7 exclusive) | `kind_translation.py` KIND_GROUPS | ✓ |
| TL;DR | V6-only pull share | 79% | `v6_pro_kind_translation.csv` V6 v6_only pulls / 60000 = 78.9% | ✓ |
| TL;DR | V6-exclusive locs | 105 | `v6_pro_apples_to_apples.csv` `v6_exclusive_vs_a4_normalized` | ✓ |
| TL;DR | Territory V5 / V1 / V6 | 50/51, 46/51, 20/51 | `v6_pro_territory_coverage.csv` | ✓ |
| TL;DR | V5 novel hit by V6 | 0/4 | `v6_pro_v5_novel_overlap.csv` sum(`v6_hit`) | ✓ |
| §0 | V6 σ loc | ≈3.2 | `v6_pro_metrics_table.csv` V6 std = 3.197 | ✓ |
| §0 | V6 union size | 125 | `v6_pro_apples_to_apples.csv` `v6_full_coverage_normalized` | ✓ |
| §0 | V6 ∩ A4-reachable | 20 (16%) | `v6_pro_apples_to_apples.csv` | ✓ |
| §1 | V6 seeds | 10/10 | `v6_pro_build_summary.json` `v6_seeds` | ✓ |
| §1 | N per seed | 6000 | `analysis/metrics.py` N_MUTATIONS | ✓ |
| §1 | V6 total budget | 60,000 | 10 × 6000 | ✓ |
| §1 | STORE_OUT_MOD pulls | 466 | `v6_pro_kind_translation.csv` V6 kind=STORE_OUT_MOD | ✓ |
| §1 | LOAD_VAL_MOD pulls | 756 | `v6_pro_kind_translation.csv` V6 kind=LOAD_VAL_MOD | ✓ |
| §1 | BR_NEG_COND pulls | 1,453 | `v6_pro_kind_translation.csv` V6 kind=BR_NEG_COND | ✓ |
| §2 | V1 σ | 1.20 | `v6_pro_metrics_table.csv` V1 std = 1.197 | ✓ |
| §2 | V5 σ | 0.70 | `v6_pro_metrics_table.csv` V5 std = 0.699 | ✓ |
| §2 | V6 σ | 3.20 | `v6_pro_metrics_table.csv` V6 std = 3.197 | ✓ |
| §2 | Δ vs V1 | +151.7% | `internal_v6_vs_v1_v5.csv` | ✓ |
| §2 | Δ vs V5 | +132.8% | `internal_v6_vs_v1_v5.csv` | ✓ |
| §2 | V6 vs V1 p-value | ≈2.2×10⁻¹² | `internal_v6_paired_tests.csv` | ✓ |
| §2 | V6 vs V5 p-value | ≈1.7×10⁻¹³ | `internal_v6_paired_tests.csv` | ✓ |
| §2 | V1 mean CGC | 144.2 | `v6_pro_metrics_table.csv` | ✓ |
| §2 | V5 mean CGC | 188.1 | `v6_pro_metrics_table.csv` | ✓ |
| §2 | V6 mean CGC | 395.4 | `v6_pro_metrics_table.csv` | ✓ |
| §2 | V1 union | 46 | `v6_pro_territory_coverage.csv` V1 `full_union_size` | ✓ |
| §2 | V5 union | 50 | `v6_pro_territory_coverage.csv` V5 `full_union_size` | ✓ |
| §2 | A4-reachable union | 51 | `v6_pro_apples_to_apples.csv` `a4_union_normalized` | ✓ |
| §2 | 4-seed → 10-seed union | 116 → 125 | `internal_v6_v1_v5_loc_overlap.csv` historical vs current | ✓ |
| §2 | A4-reachable unchanged | 20/51 | `v6_pro_territory_coverage.csv` V6 | ✓ |
| §3 | Shared kinds count | 4 | `kind_translation.py` SHARED_KINDS | ✓ |
| §3 | V6-only kinds count | 7 | `kind_translation.py` V6_ONLY_KINDS | ✓ |
| §3 | Shared pulls | 12,675 (21.1%) | `v6_pro_kind_translation.csv` V6 shared sum | ✓ |
| §3 | V6-only pulls | 47,325 (78.9%) | `v6_pro_kind_translation.csv` V6 v6_only sum | ✓ |
| §3 | Shared discoveries | 294 | `v6_pro_kind_translation.csv` V6 shared sum | ✓ |
| §3 | V6-only discoveries | 786 | `v6_pro_kind_translation.csv` V6 v6_only sum | ✓ |
| §3 | Raw V6∩A4 overlap | 0% | `internal_v6_v1_v5_loc_overlap.csv` raw keying | ✓ |
| §3 | Normalized V6∩A4 | 20 | `v6_pro_apples_to_apples.csv` | ✓ |
| §4 | Territory V1 | 46 (90.2%) | `v6_pro_territory_coverage.csv` | ✓ |
| §4 | Territory V5 | 50 (98.0%) | `v6_pro_territory_coverage.csv` | ✓ |
| §4 | Territory V6 | 20 (39.2%) | `v6_pro_territory_coverage.csv` | ✓ |
| §4 | V6-exclusive fraction | 84.0% | `v6_pro_apples_to_apples.csv` `v6_exclusive_fraction_normalized` | ✓ |
| §4 | V6 full CGC | 537 | `v6_pro_apples_to_apples.csv` `v6_full_cgc` | ✓ |
| §4 | V6 ∩ A4 CGC | 112 (20.9%) | `v6_pro_apples_to_apples.csv` | ✓ |
| §4 | V6-exclusive CGC | 425 (79.1%) | `v6_pro_apples_to_apples.csv` | ✓ |
| §5 | V6 novel hits | 0/4 | `v6_pro_v5_novel_overlap.csv` | ✓ |
| §6 | V6-exclusive locs | 105 | `v6_pro_apples_to_apples.csv` | ✓ |
| §6 | V6-exclusive CGC | 425 | `v6_pro_apples_to_apples.csv` | ✓ |
| §6 | V0 zone entropy | 1.94 | `v6_pro_metrics_table.csv` V0 mean (incl. via internal) | ✓ |
| §6 | V6 zone entropy | 1.92 | `v6_pro_metrics_table.csv` V6 mean | ✓ |
| §6 | V1 zone entropy | 2.20 | `v6_pro_metrics_table.csv` V1 mean | ✓ |
| §6 | V5 zone entropy | 3.27 | `v6_pro_metrics_table.csv` V5 mean | ✓ |
| §7.1 | Territory V5/V6 | 50/51 vs 20/51 | `v6_pro_territory_coverage.csv` | ✓ |
| §7.1 | σ V5 / V6 | 0.70 / 3.20 | `v6_pro_metrics_table.csv` | ✓ |
| §7.1 | V6 novel | 0/4 | `v6_pro_v5_novel_overlap.csv` | ✓ |
| §7.1 | V1 territory | 46/51 | `v6_pro_territory_coverage.csv` | ✓ |
| §7.2 | A4 mutation budget | 360,000 | 60 seeds × 6000 (V0–V5, 10 seeds each) | ✓ |
| §7.2 | V6 loc union | 125 | `v6_pro_apples_to_apples.csv` | ✓ |
| §7.2 | V6 CGC union | 537 | `v6_pro_apples_to_apples.csv` | ✓ |
| §7.2 | V6-exclusive locs | 105 | `v6_pro_apples_to_apples.csv` | ✓ |
| §7.2 | V6-exclusive CGC | 425 | `v6_pro_apples_to_apples.csv` | ✓ |
| §7.2 | V6 shared pulls | 12,675 | `v6_pro_kind_translation.csv` | ✓ |
| §7.2 | V5 shared pulls | 19,237 | `v6_pro_kind_translation.csv` V5 shared sum | ✓ |
| §7.2 | V6 V6-only pull share | 79% | derived from kind_translation | ✓ |
| §7.4 | V6 raw headline | 108 locs | `v6_pro_metrics_table.csv` | ✓ |
| Appendix | V0 zone entropy | 1.94 | `internal_metrics_table.csv` V0 mean | ✓ |
| Appendix | COMP_OUT_MOD A4-reachable rate | 1.04/1k | computed from DBs + A4 union | ✓ |
| Appendix | PRE_EXEC_REG_MOD disc all vs A4 | 288 / 74 | computed from DBs + A4 union | ✓ |
| Appendix | PRE_EXEC_REG_MOD A4 rate | 9.72/1k | computed from DBs + A4 union | ✓ |
| Frozen | R2 metrics_table md5 | 17813414307a1283b307e7f483e6de7b | `md5sum metrics_table.csv` | ✓ |

**Total rows:** 72  
**Failures:** 0  
**Corrections applied during §7 integration:** 1 (see `BATCH8_FINAL_REPORT.md`)

---

*Generated during IV.POS.7 Batch 8 close-out.*
