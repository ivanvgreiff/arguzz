# D2.G Case Verdict (full campaign, seeds 1234/1235/1236)

**Case B** — V6-cTS ties V6-uniform on territory; Hybrid wins — hybrid surface + A4 terrain

Case B (n=3 seeds): V6-cTS ties V6-uniform on territory (doesn't beat); Hybrid wins — hybrid surface + A4 terrain. Gate = normalized territory only (F30): V6_cTS tie (~+1 loc, within margin) V6_uniform (locs 36.0 vs 35.0); Hybrid beats uniform on territory (48.3 vs 35.0). CGC reported but NOT gating: V6_cTS 618 vs uniform 487 (arm-weighting confound — IWM over-sampling inflates CGC without new locs). Soundness: 0 strong (F29 verified negative).

## Evidence summary

- Seeds: **3** (directional; paired p-values empty at n=3)
- Case gate: **survey_unique_normalized_locs** only (CGC not gating — F30)
- Territory union (all four variants): **52** normalized locs
- V6_cTS beats V6_uniform on territory: **False**
- Hybrid beats V6_uniform on territory: **True**

### Pooled territory (apples_to_apples)

- V6_uniform: **37** locs
- V6_cTS: **36** locs (+0 exclusive, uniform +1 exclusive)
- Hybrid: **49** locs

### Mean metrics (3 seeds)

| Comparison | locs (gate) | CGC (info only) | unique_useful (d_loc≤2) |
|---|---:|---:|---:|
| V6_cTS | 36.0 | 617.6666666666666 | 36.0 |
| V6_uniform | 35.0 | 487.0 | 18.333333333333332 |
| Hybrid_cTS | 48.333333333333336 | 506.3333333333333 | 40.0 |

## INSTR_WORD_MOD adaptive correction (F19 action 3)

| variant    |   seed |   early |   late |   iwm_share_delta_late_minus_early | adaptive_reduced_iwm   |
|:-----------|-------:|--------:|-------:|-----------------------------------:|:-----------------------|
| Hybrid_cTS |   1234 |  0.117  | 0.1092 |                            -0.0078 | True                   |
| Hybrid_cTS |   1235 |  0.1212 | 0.1122 |                            -0.009  | True                   |
| Hybrid_cTS |   1236 |  0.1132 | 0.1128 |                            -0.0004 | True                   |
| V5_control |   1234 |  0      | 0      |                             0      | False                  |
| V5_control |   1235 |  0      | 0      |                             0      | False                  |
| V5_control |   1236 |  0      | 0      |                             0      | False                  |
| V6_cTS     |   1234 |  0.288  | 0.354  |                             0.066  | False                  |
| V6_cTS     |   1235 |  0.2902 | 0.3538 |                             0.0636 | False                  |
| V6_cTS     |   1236 |  0.2908 | 0.3478 |                             0.057  | False                  |

## Paired tests (vs V6_uniform) — informational; territory gate uses locs only

| variant    | reference   | metric                        |   n_pairs |   mean_variant |   mean_reference |   mean_diff |   std_variant |   std_reference |   variance_ratio |   paired_t_stat |   paired_t_pvalue |   mannwhitney_u |   mannwhitney_pvalue | small_n_caveat   |
|:-----------|:------------|:------------------------------|----------:|---------------:|-----------------:|------------:|--------------:|----------------:|-----------------:|----------------:|------------------:|----------------:|---------------------:|:-----------------|
| Hybrid_cTS | V6_uniform  | survey_unique_normalized_locs |         3 |        48.3333 |          35      |     13.3333 |       0.57735 |         1       |         0.57735  |        40       |               nan |             9   |                  nan | True             |
| Hybrid_cTS | V6_uniform  | survey_cgc_final              |         3 |       506.333  |         487      |     19.3333 |       9.29157 |         7       |         1.32737  |         2.22584 |               nan |             9   |                  nan | True             |
| Hybrid_cTS | V6_uniform  | unique_locs_d_loc_le_2        |         3 |        40      |          18.3333 |     21.6667 |       1.73205 |         0.57735 |         3        |        18.0278  |               nan |             9   |                  nan | True             |
| V5_control | V6_uniform  | survey_unique_normalized_locs |         3 |        47.3333 |          35      |     12.3333 |       1.52753 |         1       |         1.52753  |        10.262   |               nan |             9   |                  nan | True             |
| V5_control | V6_uniform  | survey_cgc_final              |         3 |       371      |         487      |   -116      |       2.64575 |         7       |         0.377964 |       -37.9699  |               nan |             0   |                  nan | True             |
| V5_control | V6_uniform  | unique_locs_d_loc_le_2        |         3 |        31      |          18.3333 |     12.6667 |       1       |         0.57735 |         1.73205  |        19       |               nan |             9   |                  nan | True             |
| V6_cTS     | V6_uniform  | survey_unique_normalized_locs |         3 |        36      |          35      |      1      |       0       |         1       |         0        |         1.73205 |               nan |             7.5 |                  nan | True             |
| V6_cTS     | V6_uniform  | survey_cgc_final              |         3 |       617.667  |         487      |    130.667  |       2.3094  |         7       |         0.329914 |        38.6249  |               nan |             9   |                  nan | True             |
| V6_cTS     | V6_uniform  | unique_locs_d_loc_le_2        |         3 |        36      |          18.3333 |     17.6667 |       0       |         0.57735 |         0        |        53       |               nan |             9   |                  nan | True             |

## Caveats

- Single guest (`--in1 5 --in4 10`); directional only (n=3, `small_n_caveat=True`).
- Raw CGC must not gate Case A–E — arm-weighting confound (F30).
- V6_uniform `unique_locs_d_loc_le_2` uses F18 failures-derived path when sparse.
- Soundness: 0 strong residue (F29 verified negative on full triage).
