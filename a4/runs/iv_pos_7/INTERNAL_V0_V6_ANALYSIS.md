# Internal V0/V6 Analysis — IV.POS.7 (non-Pro track)

**Date:** 2026-06-16  
**Audience:** Ivan, Opus, Composer (internal only)  
**Companion:** `INTERNAL_V0_V6_NOTEBOOK.ipynb` / `.html`  
**Frozen:** All R2 Pro deliverables (`MAB_ARCHITECTURE_*`, `PRO_R2_PACKET.zip`, `metrics_table.csv`, …)

**Status:** Draft §1–§5 (Batch 4). §6 conclusion deferred — joint draft after Review #4.  
**V6 data:** Partial — **4/10 seeds** at time of writing (seeds 1234–1237). Re-sync before final pass.

---

## §1 Goal and scope

### Questions this analysis answers

1. **V0 anchor** — Where does uniform random sit vs V1–V5? How much does the structured zoned prior (V0→V1) buy on local coverage, AUC, and CGC?
2. **V6 partial preview** — How does arguzz (V6) compare to V1 (zoned baseline) and V5 (cTS_semantic_v2) on shared metrics?
3. **V6 fairness** — V6 has 11 mutation kinds vs A4's 8. What fraction of V6's coverage advantage is **extra terrain** vs **overlap with A4-reachable space**?
4. **Implications for V5** — Does V6 invalidate the Pro-facing V5 narrative, or complement it?

### Variant map

| Label | Selector | Role |
|---|---|---|
| V0 | `uniform` | True random floor (no zoned prior, no bandit) |
| V1 | `zoned` | Pro reference baseline |
| V2–V4 | kindUCB/kindTS variants | Ablation ladder (R2) |
| V5 | `cTS_semantic_v2` | Pro protagonist |
| V6 | `arguzz` | External baseline (wider kind set, no bandit tables) |

### Out of scope

- Pro-facing reframing or R2 packet edits
- V6 bandit allocation (no `bandit_decisions` table by design)
- Final conclusion (§6) — pending joint review

### Data inventory (current)

| Variant | Seeds | Notes |
|---|---:|---|
| V0 | 10/10 | Complete |
| V1–V5 | 10/10 each | R2 set, unchanged |
| V6 | **4/10** | Seeds 1234–1237; `partial=True` in `internal_metrics_table.csv` |

---

## §2 V0 anchor results

Uniform random (V0) establishes the **unstructured floor** against which V1–V5 gains are measured.

### Headline numbers (10 seeds, N=6000)

| Metric | V0 mean | V1 mean | V1 Δ vs V0 | V5 mean | V5 Δ vs V0 |
|---|---:|---:|---:|---:|---:|
| `local_context_final` | 35.0 | 42.9 | **+22.6%** (p≈1.1e-7) | 46.4 | **+32.6%** |
| `local_context_AUC` | 189,086 | 228,142 | **+20.7%** (p≈2.3e-7) | 264,555 | **+39.9%** |
| `compressed_global_context_final` | 140.7 | 144.2 | **+2.5%** (p=0.053) | 188.1 | **+33.7%** |
| Zone entropy | 1.942 | 2.202 | +13.4% | 3.271 | +68.5% |

V0 cluster: mean=35.0, std=1.56, range [33, 38] — stable across seeds.

### O1 — Zoned prior buys sample efficiency, not CGC breadth

The V0→V1 CGC delta is **+2.5% with p=0.053**. The zoned step prior's CGC effect **does not reach significance at α=0.05**. Almost the entire V0→V5 CGC gain (+33.7%) comes from cTS_semantic_v2's mechanism (~31 percentage points), not from V1's zoned geometry.

### O2 — Where V1 actually helps

V1's gain over V0 is concentrated on **local coverage** (+22.6%) and **AUC** (+20.7%), not CGC. The structured prior is a **sample-efficiency device** for constraint-loc discovery, not a compressed-global discoverer.

### O6 — Zone entropy ceiling

V0 zone entropy is **1.94**, not log₂(11)≈3.46. Uniform step sampling does not yield uniform zone distribution because semantic zones are **size-imbalanced**. V5's 3.27 is meaningful relative to the empirical ~1.9–2.2 ceiling, not the theoretical maximum.

**Artifacts:** `internal_v0_anchor.csv`, `internal_v0_paired_tests.csv`, `internal_v0_sanity.json`

---

## §3 V6 partial preview (n=4)

V6 vs V1/V5 on seeds **1234–1237 only** (paired n=4; p-values suppressed, `small_n_caveat=True`).

| Comparison | V6 mean loc | Reference mean | Δ | Δ% |
|---|---:|---:|---:|---:|
| V6 vs V1 | 107.8 | 43.5 | +64.2 | +147.7% |
| V6 vs V5 | 107.8 | 46.5 | +61.2 | +131.7% |

| Metric | V6 mean | V1 mean | V5 mean |
|---|---:|---:|---:|
| CGC | 394.0 | 147.8* | 191.8* |
| Zone entropy | 1.916 | 2.20 | 3.27 |

\*Reference means on paired seeds 1234–1237 only.

V6 missing-table fields (`local_coverage_v2`, `crash_rate`, `no_effect_rate`) are **NaN**, not zero — paired tests skip them.

**Territory callout:** V6's 107.8-loc mean is on V6's **full** universe (including 96 V6-exclusive locs). On the **51-loc A4-reachable normalized union**, V6 reaches only **20/51 (39%)** vs V5's **50/51 (98%)** and V1's **46/51 (90%)**.

**Caveat:** 4/10 seeds. Re-run after full V6 collection before treating aggregates as final.

**Artifacts:** `internal_v6_vs_v1_v5.csv`, `internal_v6_paired_tests.csv`

---

## §4 V6 fairness decomposition

### §4.1 — constraint_loc format difference (implementation, not semantics)

A4 stores normalized locs via `ConstraintFailure.short_loc()` → `Name@basename.zir:line`.  
V6 driver (`v6_driver_v2.py`) stores **raw** `loc` from `<constraint_fail>` JSON → `Name(full/path/basename.zir:line)`.

**Impact:** Raw set intersection is **0/116 (0%)** — a naming artifact. Analysis uses normalized key `Name:basename:line` (`constraint_loc_normalize.py`). Future V6 runs should call `constraint_loc()` at write time.

### §4.2 — Loc-level apples-to-apples (normalized, 4 V6 seeds)

| Set | Count |
|---|---:|
| V6 full union | 116 |
| V6 ∩ A4-reachable (V0–V5 union, 60 seeds) | **20 (17.2%)** |
| V6-exclusive vs A4 | **96 (82.8%)** |
| A4-reachable union size | 51 |

### §4.3 — CGC-level apples-to-apples (ctx_key, M1)

| Set | Count |
|---|---:|
| V6 full CGC union | 483 |
| V6 ∩ A4 CGC union | **104 (21.5%)** |
| V6-exclusive CGC vs A4 | 379 (78.5%) |
| A4 CGC union (60 seeds) | 331 |

Loc overlap (17.2%) and CGC overlap (21.5%) tell the **same fairness story** in two views. CGC schemas are compatible, but V6 emits more `family=cycle` ctx_keys via POST_EXEC_* kinds.

### §4.4 — Kind-set decomposition and A4-territory coverage

| Group | Kinds | V6 pulls (4 seeds) | V6 discoveries (all locs) |
|---|---|---:|---:|
| Shared (4) | COMP/LOAD/STORE/PRE_EXEC_REG | 5,019 (20.9%) | 129 |
| V6-only (7) | PC_MOD, MEM_MOD, BR_NEG_COND, … | 18,981 (79.1%) | 302 |

V6 spends **~79% of budget on V6-only kinds**. Most exclusive locs come from that terrain.

**A4-territory framing** (preferred over per-pull rate comparisons — raw `kind_translation` discovery counts conflate V6-exclusive locs credited to shared-kind mutations):

| Variant | Locs in 51-loc A4-reachable union | Territory coverage |
|---|---:|---:|
| V1 (10 seeds) | 46 | 90% |
| V5 (10 seeds) | 50 | **98%** |
| V6 (4 seeds) | 20 | **39%** |

**On A4-reachable territory, V5 dominates V6 (50/51 vs 20/51).** V6's raw coverage advantage (116 vs 50 locs) comes entirely from **96 V6-exclusive locs** reached via 7 V6-only mutation kinds A4 cannot use — different terrain, not better fuzzing on the same terrain.

### §4.5 — V5 novel 4 vs V6 (critical internal finding)

V5's 4 novel kernel/ECALL locs vs V1 union:

- `ControlLoadRootAndNonce@inst_control.zir:35/44/45`
- `ControlMRET@inst_control.zir:93`

**V6 hit count: 0/4** (normalized keys, 4 seeds).

- V6 has **no** `ControlLoadRootAndNonce` locs at all.
- V6 max `ControlMRET` line is **92** (V5 reached **93**).

**Interpretation (hypothesis, not proven):** V5's `INSTR_TYPE_MOD` (A4-only kind) combined with semantic-zone arms may be load-bearing for these gates. V6's PC/MEM/REG-focused kinds explore different constraint space. Worth a mechanistic follow-up (Q-E) before surfacing to Pro.

**Artifacts:** `internal_v6_v1_v5_loc_overlap.csv`, `internal_v6_kind_translation.csv`, `internal_v6_apples_to_apples.csv`

---

## §5 Implications for the V5 narrative

### What this does NOT change

- **R2 Pro report stands.** V5 is still the winner within the A4 variant family (5/5 success criteria, 4 novel locs vs V1).
- V6 is not a drop-in replacement for V5's scheduler or mutation taxonomy.

### What this adds internally

1. **V0 anchor quantifies the zoned prior:** +22.6% local coverage, +2.5% CGC (n.s.). The cTS mechanism drives the CGC win, not V1's step geometry.
2. **V6 is a strong external baseline on raw counts** (107.8 vs 46.4 locs) but **~83% of its locs are outside A4-reachable space** — wider kind set, different terrain.
3. **V5's 4 novel locs are not generic-fuzzer findings** — arguzz with 24k mutations (4×6000) and a wider kind set still misses them at 4-seed preview. Strengthens V5 if surfaced to Pro (judgment call Q-A).
4. **Fair framing for V6:** On A4-reachable territory, **V5 still dominates V6 (50/51 vs 20/51)**. V6's larger raw count comes entirely from the 96 V6-exclusive locs it reaches via its 7 V6-only mutation kinds — **different terrain, not better fuzzing on the same terrain**. Do not use raw `kind_translation` per-pull rates (V6 shared-kind rate ~25.7/1k includes discoveries on V6-exclusive locs).

### Open questions (judgment — not blocking)

| ID | Question |
|---|---|
| Q-A | Surface V5 0/4 vs V6 to Pro in a future round? |
| Q-B | Adopt arguzz as complementary production track? |
| Q-C | Expand IV.POS.8 scope to include arguzz head-to-head? |
| Q-D | Frame V6 as "different terrain" vs "fundamentally stronger fuzzer"? |
| Q-E | Mechanistic investigation: why no ControlLoadRootAndNonce in V6? |
| Q-F | Disclose internal analysis existence to Pro? |
| Q-G | Fix V6 driver to write normalized `constraint_loc` via `ConstraintFailure.constraint_loc()` at source (~30 min). Removes need for `constraint_loc_normalize.py` on future runs. |

---

## §6 Conclusion

*Deferred — joint draft (Ivan + Opus) after Review #4 and optional V6 10/10 re-sync.*

---

## Appendix — Artifact index

| File | Description |
|---|---|
| `internal_metrics_table.csv` | V0–V6 per-seed metrics |
| `internal_v0_anchor.csv` | Δ vs V0 |
| `internal_v6_apples_to_apples.csv` | Loc + CGC fairness |
| `internal_v6_v1_v5_loc_overlap.csv` | Raw + normalized set decomposition |
| `internal_v6_territory_coverage.csv` | V1/V5/V6 locs within 51-loc A4 union |
| `INTERNAL_V0_V6_NOTEBOOK.html` | Rendered plots |

*End of draft.*
