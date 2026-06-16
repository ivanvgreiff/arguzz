# V6 vs A4 — Pro Companion Report (IV.POS.7)

**Author**: Ivan Greiff + Cursor (Composer + Claude Opus)  
**Date**: June 16, 2026  
**Purpose**: Pro-facing companion to `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`. Evaluates **V6 (arguzz)** against A4's V1 reference baseline and V5 winner, now with **10/10 paired seeds** (1234–1243, N=6000 each).

> **TL;DR for Pro**
>
> - **V6 raw counts look much larger** — mean **108.0** `constraint_loc`s per seed vs V1 **42.9** and V5 **46.4** (+152% / +133% on headline metric).
> - **Those raw numbers are misleading** — V6 runs **11 mutation kinds** (7 exclusive to arguzz); **79%** of V6 pulls land on kinds A4 cannot use, surfacing **105 V6-exclusive** locs A4 never reaches.
> - **On apples-to-apples A4 territory** (51-loc normalized union from V0–V5), **V5 still wins**: **50/51 (98%)** vs V6 **20/51 (39%)**; V1 reaches **46/51 (90%)**.
> - **R2's signature finding holds** — V6 hits **0/4** of V5's novel ECALL/MRET locs (`ControlLoadRootAndNonce@inst_control.zir:35/44/45`, `ControlMRET@inst_control.zir:93`) across 60k mutations.
> - **R2 conclusion stands** — V5 (`cTS_semantic_v2`) remains the right A4 deployment; V6 is a complementary external probe of wider constraint terrain, not a replacement.

**Companion artifacts**: `V6_VS_A4_NOTEBOOK.html`, `v6_pro_metrics_table.csv`, `v6_pro_apples_to_apples.csv`, `v6_pro_territory_coverage.csv`, `v6_pro_kind_translation.csv`, `v6_pro_v5_novel_overlap.csv`.

**Frozen (unchanged by this work)**: `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md`, `MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb`, `PRO_R2_PACKET.zip`, `metrics_table.csv` (md5 `17813414307a1283b307e7f483e6de7b`).

---

## Table of Contents

- [§0 TL;DR](#0-tldr)
- [§1 Setup — what V6 is](#1-setup--what-v6-is)
- [§2 Headline raw numbers](#2-headline-raw-numbers)
- [§3 Why raw is misleading](#3-why-raw-is-misleading)
- [§4 Apples-to-apples territory coverage](#4-apples-to-apples-territory-coverage)
- [§5 V5 signature findings under V6](#5-v5-signature-findings-under-v6)
- [§6 What V6 contributes](#6-what-v6-contributes)
- [§7 Implications for V5/A4](#7-implications-for-v5a4)
- [§8 IV.POS.8 candidates](#8-ivpos8-candidates)
- [Appendix — methodology](#appendix--methodology)

---

## §0 TL;DR

| Claim | Evidence (10 seeds × N=6000) |
|---|---|
| V6 discovers more locs on raw counts | V6 mean `local_context_final` = **108.0** (σ≈3.2) vs V1 **42.9**, V5 **46.4** |
| Raw advantage is mostly different terrain | V6 union = **125** locs; only **20** lie in A4-reachable union (**16%**); **105** are V6-exclusive |
| V5 wins on shared territory | Territory table: V5 **50/51**, V1 **46/51**, V6 **20/51** |
| V5's novel kernel/ECALL locs survive V6 | V6 hits **0/4** on R2's four novel locs (see `v6_pro_v5_novel_overlap.csv`) |
| R2 stands | V6 does not beat V5 where comparison is fair; it maps constraint space A4's kind-set cannot reach |

---

## §1 Setup — what V6 is

### Variants in scope

| Label | Selector | Role in this report |
|---|---|---|
| **V1** | `zoned` | Pro reference baseline (R2) |
| **V5** | `cTS_semantic_v2` | A4 winner (R2 protagonist) |
| **V6** | `arguzz` | External baseline — **protagonist of this report** |
| V0 | `uniform` | Optional floor anchor only (not analyzed in depth here) |

### What V6 changes vs A4

| Dimension | A4 (V1–V5) | V6 (arguzz) |
|---|---|---|
| Mutation kinds | 8 (4 shared with V6) | **11** (+7 V6-only kinds) |
| Selector | See selector breakdown below | No bandit; scheduler targets uniform over **applicable** kinds per instruction |
| DB schema | Full (`bandit_decisions`, `mutation_rewards`, `local_coverage_v2`, …) | Reduced — missing tables → **NaN** in metrics, not zero |
| `constraint_loc` format | `Name@basename.zir:line` | Raw path `Name(full/path/basename.zir:line)` — normalized post-hoc for overlap (see Appendix) |

**Selector breakdown (A4):**

| Variant | Mechanism |
|---|---|
| **V1** | Zoned step prior only — **no kind bandit** |
| **V2–V4** | Zoned step prior + kind bandit (UCB or TS variants) |
| **V5** | Zoned step prior + kind bandit + **semantic-zone** constrained TS |

**V6 scheduling note:** V6 has no bandit tables. Its scheduler *attempts* uniform-over-kinds, but the applicable-kind set varies per instruction (e.g., `STORE_OUT_MOD` only on store insns, `LOAD_VAL_MOD` only on loads). Observed V6 pull distribution (pooled 60k): `STORE_OUT_MOD` **466**, `LOAD_VAL_MOD` **756**, `BR_NEG_COND` **1,453** vs ~7,400–7,800 each for broadly applicable kinds — highly skewed despite uniform-over-applicable intent.

### Data completeness

| Variant | Seeds local | `partial` flag |
|---|---:|---|
| V1, V5 | 10/10 | False |
| V6 | **10/10** | **False** |

All V6 DBs: `exit_code=0`, `mutations=6000`. Total V6 budget: **60,000** mutations.

---

## §2 Headline raw numbers

These are the numbers Pro will notice first. They are **real** but **not apples-to-apples** (§3–§4 explain why).

### Primary metric — `local_context_final`

| Variant | mean | σ | Δ vs V1 | Δ vs V5 |
|---|---:|---:|---:|---:|
| V1 | 42.9 | 1.20 | — | — |
| V5 | 46.4 | 0.70 | +8.2% | — |
| **V6** | **108.0** | **3.20** | **+151.7%** | **+132.8%** |

Paired t-tests (n=10): V6 vs V1 p≈2.2×10⁻¹²; V6 vs V5 p≈1.7×10⁻¹³ on `local_context_final`. Large raw deltas are statistically significant — but significance on inflated universes does not imply superiority on A4-native terrain.

### Secondary — compressed global context (CGC)

| Variant | mean CGC |
|---|---:|
| V1 | 144.2 |
| V5 | 188.1 |
| V6 | **395.4** |

V6's CGC lift (+110% vs V5) similarly conflates V6-exclusive `ctx_key` space with A4-reachable contexts (§4, CGC row).

### Union sizes (normalized keys, pooled 10 seeds)

| Set | Count |
|---|---:|
| V6 full union | **125** |
| V1 union | 46 |
| V5 union | 50 |
| A4-reachable union (V0–V5, 60 seeds) | 51 |

**Note vs 4-seed preview:** Adding 6 more V6 seeds grew the full union **116 → 125** (+9 locs) but did **not** increase A4-reachable hits (**still 20/51**). New V6 discoveries are overwhelmingly V6-exclusive terrain.

**Artifacts:** `v6_pro_metrics_table.csv`, Plot 1 in `V6_VS_A4_NOTEBOOK.html`

---

## §3 Why raw is misleading

### Kind-set decomposition

V6 and A4 share **4 kinds**: `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `PRE_EXEC_REG_MOD`, `STORE_OUT_MOD`.

V6 adds **7 kinds** A4 cannot use: `BR_NEG_COND`, `INSTR_WORD_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_PC_MOD`, `POST_EXEC_REG_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`.

### Pull allocation (pooled 10 V6 seeds, 60k pulls)

| Kind group | Pulls | Share | Discoveries |
|---|---:|---:|---:|
| Shared (4 kinds) | 12,675 | **21.1%** | 294 |
| V6-only (7 kinds) | 47,325 | **78.9%** | 786 |

**Claim:** Roughly **four-fifths** of V6's sampling budget explores mutation kinds outside A4's toolchain. Raw loc/CGC counts therefore measure **different reachable constraint space**, not a fair head-to-head on A4's native kinds alone.

We deliberately **do not** claim "comparable discovery density on shared kinds" — V6's per-kind rates on shared kinds mix A4-reachable and V6-exclusive loc discoveries and would overstate V6's advantage. See Appendix for rates restricted to A4-reachable locs only.

### Loc string format artifact

Raw `constraint_loc` intersection between V6 and A4 is **0%** — an implementation naming difference, not zero semantic overlap. Analysis uses normalized key `Name:basename:line` (`constraint_loc_normalize.py`). After normalization, V6 ∩ A4-reachable = **20** locs.

**Artifacts:** `v6_pro_kind_translation.csv`, `internal_v6_kind_inventory.csv`, Plot 5 in notebook

---

## §4 Apples-to-apples territory coverage

**Definition:** The **51-loc A4-reachable union** = all distinct normalized `constraint_loc` values discovered by any V0–V5 seed (60 DBs). We ask: how many of those 51 does each variant hit?

| Variant | Locs in A4 territory | Coverage |
|---|---:|---:|
| V1 | 46 | 90.2% |
| V5 | **50** | **98.0%** |
| V6 | 20 | 39.2% |

On fair territory, **V5 dominates V6 by 2.5×** (50 vs 20) and edges V1 (46). V6's 108-loc headline is ~5× the territory-restricted count (~20 per-seed mean on the 51-loc set).

### Loc-level fairness (V6 union, normalized)

| Set | Count | Fraction of V6 union |
|---|---:|---:|
| V6 full | 125 | 100% |
| V6 ∩ A4-reachable | 20 | **16.0%** |
| V6-exclusive vs A4 | 105 | **84.0%** |

### CGC-level fairness (`ctx_key` overlap)

| Set | Count | Fraction of V6 CGC |
|---|---:|---:|
| V6 full CGC | 537 | 100% |
| V6 ∩ A4 CGC union | 112 | **20.9%** |
| V6-exclusive CGC | 425 | **79.1%** |

CGC and loc-level fractions align (~16–21% A4-reachable): V6's advantage is concentrated in space A4 cannot sample.

**Artifacts:** `v6_pro_territory_coverage.csv`, `v6_pro_apples_to_apples.csv`, Plots 2–4 and 7 in notebook

---

## §5 V5 signature findings under V6

R2 reported **4 novel locs** reached by V5 but not V1 across all 10 seeds:

| Normalized loc | V5 hit (10 seeds) | V6 hit (10 seeds) |
|---|---|---|
| `ControlLoadRootAndNonce:inst_control.zir:35` | ✓ | **✗** |
| `ControlLoadRootAndNonce:inst_control.zir:44` | ✓ | **✗** |
| `ControlLoadRootAndNonce:inst_control.zir:45` | ✓ | **✗** |
| `ControlMRET:inst_control.zir:93` | ✓ | **✗** |

**Result: V6 hits 0/4** even with 60k mutations and a wider kind set.

These locs sit in A4-reachable territory (they are in the V5 union). V6's failure to reach them despite 60k mutations and a wider kind set is **consistent with V5's cTS + semantic-zone mechanism being the load-bearing factor**, not raw mutation budget or kind-set breadth alone. Mechanistic confirmation deferred to IV.POS.8 (Q-E).

**Artifacts:** `v6_pro_v5_novel_overlap.csv`, Plot 6 in notebook

---

## §6 What V6 contributes

V6 is not a failed experiment — it answers a different question:

1. **External validation** — On A4-native terrain, a mature external fuzzer does **not** beat V5 (20/51 vs 50/51). A4 is competitive where the comparison is fair.
2. **Terrain expansion map** — V6 surfaces **105 normalized locs** (and **425 CGC contexts**) outside A4's reachable union. These are real constraint failures, not artifacts.
3. **Kind-set sensitivity** — Seven V6-only kinds (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, etc.) drive most discoveries. This suggests a **future A4 expansion direction**: selectively adopt high-yield arguzz kinds rather than replacing the bandit stack.
4. **No zone-targeting mechanism** — V6's step-classifier zone entropy is **1.92**, essentially identical to V0's **1.94** (uniform random) and below V1's classifier-derived **2.20**. V5's bandit-allocation zone entropy (**3.27**, computed from `bandit_decisions` when present) uses a **different methodology** (planned zone-arm allocation, not step classification) and is **not directly comparable** to V6's 1.92 — but it characterizes a deliberate zone exploration policy V6 lacks. V6 has no step-targeting or zone-bandit mechanism; its zone distribution reflects raw mutation-step geography under uniform-over-applicable-kind sampling.

---

## §7 Implications for V5/A4

### §7.1 What V6 confirms about R2

V6 is a strong stress-test of R2's claims, and the data confirms each one on **fair-comparison territory**:

| R2 claim | V6 stress-test result | Verdict |
|---|---|---|
| V5 is the strongest A4 variant on local coverage + variance | V5 reaches **50/51** of A4-reachable territory vs V6 **20/51**; V5 σ on `local_context_final` (0.70) tighter than V6 (3.20) | ✅ Confirmed |
| V5's 4 novel kernel/ECALL locs are not generic-fuzzer findings | V6 hits **0/4** with 60k mutations and a wider kind set | ✅ Confirmed (under the strongest external stress we can apply) |
| V1 is the right Pro baseline | V1 (46/51) still beats V6 (20/51) on A4-native territory | ✅ Confirmed |
| V5 passes mechanical success criteria | Not directly stress-tested (V6 lacks `local_coverage_v2`, `bandit_decisions`, `mutation_rewards`) — out of scope for V6 comparison | — |

### §7.2 Where V6 changes our understanding of A4

V6 does not replace V5, but it does **expand our picture of what A4 is missing**:

1. **Mutation-kind ceiling.** A4's 8 kinds reach a 51-loc constraint-fail union in 60 seeds × 6,000 mutations = **360,000 mutations**. V6 surfaces **125 normalized locs** (and **537 CGC contexts**) in 60,000 mutations, of which **105 locs and 425 CGC contexts** are unreachable to A4 entirely. The ceiling is **kind-set-limited**, not budget-limited.
2. **The mechanism question is real.** V5's win on A4-native territory (50 vs 20) and on the four novel locs (4 vs 0) is consistent with the cTS + semantic-zone mechanism being load-bearing on the constraint-loc subspace V5 targets. V6 allocates **fewer** shared-kind pulls than V5 (12,675 vs 19,237 on the four shared kinds) and spends **79%** of its budget on V6-only kinds — yet still reaches only 20/51 A4 territory and 0/4 novel locs. The gap is not explained by mutation budget or per-kind pull volume alone.

### §7.3 Where V6 does not change anything

1. **Deployment recommendation (unchanged):** Ship **V5 (`cTS_semantic_v2`)** as the A4 production selector. V6 is **not** a drop-in replacement: it loses on A4-native territory, lacks the bandit/counterfactual instrumentation A4 ships with, and operates on a different (broader, applicability-skewed) mutation-kind universe.
2. **R2's TL;DR claims, line by line, all survive V6 stress:** V5's local-coverage win, V5's novel-loc finding, V1's role as baseline. None of R2's deployment-relevant numbers move.

### §7.4 Honest readouts for Pro

What this report shows that R2 does not:

- A4 is competitive **where the comparison is fair**, not just within its own variant family.
- V6's 108-loc raw headline does **not** undermine the V5 narrative once kind-set and territory are controlled.
- A4 has a real expansion vector (V6-exclusive kinds), but reaching it is an explicit IV.POS.8 design question, not an IV.POS.7 deliverable.

What this report does **not** claim:

- That V5 is causally proven to be necessary for the 4 novel locs (mechanistic confirmation is Q-E).
- That V6 is "fundamentally weaker" — it is differently-scoped, with strengths in V6-exclusive terrain that A4 cannot currently reach.
- That V6 is ready for production parity with A4 — it lacks the schema, instrumentation, and scheduler primitives that R2's evaluation framework relies on.

### §7.5 Forward-pointing — three concrete IV.POS.8 questions this report opens

Already captured in §8 but listed here for narrative continuity:

1. **Mechanistic confirmation (Q-E).** Run V6 with V5's 4 kinds only on paired seeds. If V6-cut-down still misses the kernel/ECALL locs, the cTS+semantic-zone mechanism is implicated; if it hits them, the answer was in the kind set all along.
2. **Kind-set extension feasibility (Q-C / partial-Q-B).** Can A4 selectively adopt high-yield V6-only kinds (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`) within the existing bandit framework? This is the "best of both" question.
3. **Source-side normalization (Q-G).** Patch `v6_driver_v2.py` to write normalized `constraint_loc` strings — eliminates the post-hoc reconciliation and makes future A4↔V6 comparisons trivially apples-to-apples.

---

## §8 IV.POS.8 candidates

Open questions deferred from this companion report:

| ID | Question | Provisional next step |
|---|---|---|
| **Q-G** | V6 driver stores raw loc paths | Fix `v6_driver_v2.py` to call `constraint_loc()` at write time — removes 0% raw-overlap confusion |
| **Q-E** | Why does V6 miss V5's 4 novel locs? | Mechanistic experiment: run V6 with V5's 4 kinds only on paired seeds; isolate kind-set vs selector effects |
| **Q-C** | Fair arguzz vs A4 head-to-head | Protocol: match kind sets, matched budgets, normalized loc keys — then compare territory coverage |
| **Q-D** | Frame V6 as "different terrain"? | **Resolved yes** — supported by 79% V6-only pulls and 84% V6-exclusive locs |

---

## Appendix — methodology

### Loc normalization

- A4: `ConstraintFailure.short_loc()` → `Name@basename.zir:line`
- V6: raw JSON path → `Name(full/path/basename.zir:line)`
- Canonical analysis key: `Name:basename:line` (`analysis/constraint_loc_normalize.py`)
- Both raw and normalized overlaps are computed; **normalized** is used for all territory and fairness claims.

### Schema handling

V6 DBs lack `local_coverage_v2`, `bandit_decisions`, `mutation_rewards`, `arm_state_snapshot`. `analysis/metrics.py` returns **NaN** for missing fields; paired tests skip NaN metrics.

### Statistical notes

- n=10 paired seeds throughout; `small_n_caveat=False`; paired t-tests reported in `internal_v6_paired_tests.csv`
- A4-reachable union built from V0–V5 only (V6 excluded from union definition to avoid circularity)

### Zone entropy methodology

`allocation_entropy_by_zone` in `metrics.py` uses **`bandit_decisions` zone-arm counts when that table exists** (V2–V5); otherwise it falls back to **mutation step → zone classifier** (V0, V1, V6). Do not compare V5's 3.27 directly to V6's 1.92 — different sources. Classifier-comparable chain: V0 **1.94** ≈ V6 **1.92** < V1 **2.20**.

### Shared-kind discovery rates on A4-reachable locs only (V6, pooled 10 seeds)

Restricting V6 discoveries to the 51-loc A4-reachable union:

| Kind | Pulls | Disc (all locs) | Disc (A4-reachable only) | Rate (A4-reachable / 1k pulls) |
|---|---:|---:|---:|---:|
| `COMP_OUT_MOD` | 3,840 | 4 | 4 | 1.04 |
| `LOAD_VAL_MOD` | 756 | 0 | 0 | 0.00 |
| `STORE_OUT_MOD` | 466 | 2 | 2 | 4.29 |
| `PRE_EXEC_REG_MOD` | 7,613 | 288 | **74** | **9.72** |

`PRE_EXEC_REG_MOD` illustrates the inflation: 288 total discoveries collapse to **74** on A4 territory — most of that kind's yield is V6-exclusive terrain.

### Reproducibility

```bash
cd a4/runs/iv_pos_7
python3 analysis/build_v6_pro_artifacts.py
python3 analysis/build_v6_pro_notebook.py
jupyter nbconvert --execute --to html V6_VS_A4_NOTEBOOK.ipynb
```

Internal audit trail: `INTERNAL_V0_V6_ANALYSIS.md`, `internal_*.csv`

---

*End of report — V6 vs A4 Pro Companion v1.0 (IV.POS.7 closeout, June 16, 2026).*
*Frozen R2 artifacts unchanged: metrics_table.csv md5 17813414307a1283b307e7f483e6de7b.*
