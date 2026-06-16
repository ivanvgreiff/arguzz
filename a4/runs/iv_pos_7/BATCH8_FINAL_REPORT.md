# Batch 8 — Final Close-Out Report

**Date:** 2026-06-16  
**Status:** IV.POS.7 Pro companion complete (v1.0)

---

## Deliverables shipped

| ID | File | md5 |
|---|---|---|
| V1 | `V6_VS_A4_REPORT_FOR_PRO.md` | `7029ba6590d5cfd651629d4d29adf79f` |
| V2 | `V6_VS_A4_NOTEBOOK.ipynb` | `3828772009164b893bb09e3df5dfaad6` |
| V3 | `V6_VS_A4_NOTEBOOK.html` | `c2193f1d3157031e61dbc09466981829` |
| V4 | `v6_pro_metrics_table.csv` | `969f383dc6aac11b93661023cf5e6d6a` |
| V5 | `v6_pro_apples_to_apples.csv` | `068b84bdacf016769a10f4eecd0970bd` |
| V6 | `v6_pro_territory_coverage.csv` | `1790ffd331c71b5aa045eee1ef04ec4d` |
| V7 | `v6_pro_kind_translation.csv` | `386e19a5e3e81a20b094a73c5d6968ee` |
| V8 | `v6_pro_v5_novel_overlap.csv` | `bbd933765d1de5a33688c526f975820c` |
| V9 | `analysis/build_v6_pro_artifacts.py` | (build script) |
| V10 | `analysis/build_v6_pro_notebook.py` | (build script) |
| Audit | `BATCH8_NUMBER_AUDIT.md` | 72 claims, 0 failures |

**Plots:** `plots_pro/01–07_*.png` (7 files)

---

## R2 freeze verification

| Artifact | md5 | Status |
|---|---|---|
| `metrics_table.csv` | `17813414307a1283b307e7f483e6de7b` | ✅ UNCHANGED |
| `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` | `23668aa0d0c176e81270ebe98b40d78b` | ✅ UNCHANGED |
| `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` | `10fd4d54a820bb4437caa963d1fa8179` | ✅ UNCHANGED |
| `PRO_R2_PACKET.zip` | `46186d1b949df7756eae6d0fd5ec7d6f` | ✅ UNCHANGED |

---

## Tests

`python3 -m pytest analysis/ -q` → **33/33 passed**

---

## §7 integration note (Opus strawman correction)

**One factual error in the agreed §7.2.2 strawman** was caught during Task 7.2 sanity checks:

| Strawman claim | Live data | Verdict |
|---|---|---|
| "V6 has more pulls on three of the four shared kinds (`COMP_OUT_MOD`, `PRE_EXEC_REG_MOD`, `STORE_OUT_MOD`)" | V5 pulls **exceed** V6 on **all four** shared kinds (e.g. `PRE_EXEC_REG_MOD`: V5 9,627 vs V6 7,613; `STORE_OUT_MOD`: V5 2,400 vs V6 466) | **Incorrect** |

**Integrated text (corrected):** V6 allocates **fewer** shared-kind pulls than V5 (12,675 vs 19,237) and spends 79% on V6-only kinds — yet still 20/51 territory and 0/4 novel locs.

**Minor wording fix in §7.5.2:** Example V6-only kinds changed from `PRE_EXEC_REG_MOD` (shared) to `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`.

All other strawman numbers verified against CSVs before integration.

---

## Known limitations

1. V6 `constraint_loc` normalization is post-hoc (Q-G deferred).
2. Zone entropy: V5 bandit-derived vs V0/V1/V6 classifier-derived — not directly comparable.
3. V6 lacks bandit / `local_coverage_v2` tables — mechanical R2 success criteria not stress-tested.
4. CGC overlap uses `ctx_key` — schema-compatible but distribution differs from A4 loc overlap.
5. §5 / §7 mechanism claims are correlational; Q-E needed for causal confirmation.

---

## IV.POS.8 candidate list (from §8 + §7.5)

| ID | Item |
|---|---|
| Q-E | Mechanistic: V6 with V5's 4 kinds only on paired seeds |
| Q-C | Head-to-head protocol with matched kind sets + normalized locs |
| Q-G | V6 driver normalize-at-source (`constraint_loc()`) |
| Q-D | "Different terrain" framing — **resolved yes** |

---

*End of IV.POS.7 Pro companion close-out.*
