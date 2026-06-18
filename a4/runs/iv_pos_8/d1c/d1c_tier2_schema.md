# D1.C Tier-2 schema (for D2.G consumption)

**Source CSV:** `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv`
**Corpus:** 30 Cat-A DBs (`cat_a_db_list()` from D1.B) — 10 R2 V1 + 10 R2 V5 + 10 D1.A decay
**Spec lock:** `IV_POS_8_D1_C_SPEC.md` v0.3 §1.2 + §2.2 task 1

## Schema

| Column | dtype | Pro reference | Category | NULL on | Notes |
|---|---|---|---|---|---|
| `corpus` | str | n/a | provenance | n/a | one of {V1, V5, D1A} |
| `variant` | str | n/a | provenance | n/a | one of {V1, V5, V5_decayexp, V5_decayepoch} |
| `seed` | int | n/a | provenance | n/a | |
| `cat_a_pro_s5_verifier_accepted_invalid_count` | int | Pro §5 | A | (never) | aligned to D1.A spec :539 SQL |
| `cat_a_pro_s5_co_failure_graph_degree_p95` | float | Pro §5 | A | (never) | p95 of co-failure graph node degree |
| `cat_a_pro_s5_singleton_failure_rate` | float | Pro §5 | A | (never) | ∈ [0, 1] |
| `cat_a_pro_s5_d_loc_p95` | int | Pro §5 / §8 | A | (never) | p95 of mutation_rewards.d_loc (integer-valued) |
| `cat_a_pro_s8_unique_locs_with_d_loc_le_2` | int | Pro §8 | A | (never) | ≤ local_context_final |
| `cat_a_pro_s8_unique_locs_with_d_glob_le_1` | int | Pro §8 | A | (never) | ≤ local_context_final |
| `cat_b_pro_s5_proof_generated_zero_residue_rejected_rate` | float \| null | Pro §5 | B | R2 V1, R2 V5 (no proof columns) | ∈ [0, 1] when present |
| `cat_b_pro_b_wall_clock_per_normalized_discovery` | float \| null | Revisit plan :160 | B | R2 V1, R2 V5 (no elapsed_ms) | mean elapsed_ms / local_context_final |

## D2.G usage

D2.G's `build_d2_artifacts.py` reads this CSV and computes the V5-vs-V6 comparison table.
Cat-A columns are populated on all 30 DBs; Cat-B columns are populated on the 10 D1.A DBs only.

Column names must match `cat_a_pro_s*` / `cat_b_pro_*` patterns exactly for drop-in consumption.
