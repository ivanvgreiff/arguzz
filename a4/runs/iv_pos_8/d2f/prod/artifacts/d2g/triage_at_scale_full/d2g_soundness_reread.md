# Provisional soundness re-read

Source: `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full/d2g_accept_triage_all_variants.csv` (1423 classified rows)

**Divergent residue count:** 0

No strong / non-weak POST_EXEC_PC_MOD propagated rows in this CSV.

## Per-variant summary

| variant    |   seed |   n |   noop |   propagated |   hidden |   strong |   cf_inert |   word_truncated |   weak |
|:-----------|-------:|----:|-------:|-------------:|---------:|---------:|-----------:|-----------------:|-------:|
| Hybrid_cTS |   1234 |  82 |     72 |           10 |        0 |        0 |          0 |               13 |     10 |
| Hybrid_cTS |   1235 |  50 |     45 |            5 |        0 |        0 |          0 |               11 |      5 |
| Hybrid_cTS |   1236 |  32 |     29 |            3 |        0 |        0 |          0 |               10 |      3 |
| V6_cTS     |   1234 | 256 |    229 |           27 |        0 |        0 |         74 |               41 |     27 |
| V6_cTS     |   1235 | 144 |    133 |           11 |        0 |        0 |         67 |               21 |     11 |
| V6_cTS     |   1236 | 149 |    137 |           12 |        0 |        0 |         70 |               30 |     12 |
| V6_uniform |   1234 | 256 |    234 |           22 |        0 |        0 |        170 |                3 |     22 |
| V6_uniform |   1235 | 234 |    225 |            9 |        0 |        0 |        171 |                5 |      9 |
| V6_uniform |   1236 | 220 |    209 |           11 |        0 |        0 |        179 |                6 |     11 |