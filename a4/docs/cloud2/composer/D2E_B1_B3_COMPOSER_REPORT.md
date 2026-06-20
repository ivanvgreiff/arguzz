# D2.E Phase 3 — B1–B3 Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_E_SPEC.md`](../IV_POS_8_D2_E_SPEC.md) v1.0 LOCKED  
**Date:** 2026-06-20  
**HEAD:** `7182237` (+ D2.C through D2.E uncommitted)  
**Status:** B1–B3 complete — **not committed**

---

## 0. Critical review — disposition

| Spec claim | Verdict | Pushback? |
|---|---|---|
| 6 gates across 3 batches before POS | **Agree** — implemented A–F + L5 mimic | None |
| Gate A extends D2.A `short_loc()` parity | **Agree** — unit pairs + mocked v6_cTS e2e | None |
| Gate B must resolve F15 (V5 archive) first | **Agree** — confirmed gap; escalated, not papered over | None |
| Gate C = standing F13 CGC regression | **Agree** — V6-uniform POS DB + mocked Hybrid | Minor residual (§6) |
| Gate E closes ISS-DD-1 via offline L1 recompute | **Agree** — DB join + `compute_l1_flags` replay | None |
| ≤10 real-binary cap for L2 | **Agree** — gated `A4_REAL_BINARY=1`, N=5 | None |
| D2.F blocked until checklist green | **Partial** — Gate B **AMBER (F15)** pending Ivan decision | See §5 |

**Blockers for D2.E implementation:** none.  
**Blocker for D2.F:** F15 decision (fresh V5 re-run vs D2.G adapter).

### Pushback / partial coverage (non-blocking)

1. **Gate C Hybrid “both surfaces”** — `test_d2e_cgc_parity.py` asserts CGC/GF non-empty on a mocked Hybrid run but does **not** split CGC rows by A4 vs Arguzz surface. Acceptable as F13 smoke; full surface split remains D2.F N≥50 territory.

2. **Gate F per-variant e2e determinism** — spec §2.6 asks for “each fresh variant reproducible at fixed seed.” Implemented: V5 scheduler trace + Bernoulli golden trace. **Not implemented:** byte-identical fuzzer decision traces for `v6_uniform` / `v6_cTS` / `hybrid_cTS` at N≤10 (D2.C component traces + golden V5 gate deemed sufficient pre-POS). Recommend Opus accept or add one fixture in D2.F smoke.

3. **Gate E import surface** — analysis modules must import as `a4.runs.iv_pos_7.analysis.*` (relative-import package), not bare `sys.path` insert into `analysis/`.

---

## 1. Pre-flight & sweep

```text
Baseline (post D2.D):  780 passed / 27 skipped
D2.E tests only:       39 passed / 3 skipped
Full standalone sweep: 819 passed / 31 skipped (+39 new; +4 gated skips)
V5 Tier-1 + Tier-2:    PASSED (via aggregator import)
Bernoulli golden:      PASSED (via aggregator import)
```

Skipped (expected): `test_d2e_variant_e2e_smoke` ×3 without `A4_REAL_BINARY=1`.

---

## 2. Batch 1 — parity core (Gates A, B, D)

### 2.1 Files

| File | Gate |
|---|---|
| `a4/standalone/tests/d2e_helpers.py` | Shared schema/loc helpers, V5 path, F15 gap detection |
| `test_d2e_normalize_loc_parity.py` | **A** |
| `test_d2e_cross_variant_schema_parity.py` | **B** + **D** |

### 2.2 Gate A

- Parametrized A4 `callsite(...)` vs V6 `Name(path:L)` pairs → identical `short_loc()`
- Mocked `v6_cTS` campaign (15 pulls): all `failures.constraint_loc` and `coverage.constraint_loc` match `Name@basename:line` regex

### 2.3 Gate B + F15

**V5 R2 archive** (`a4/runs/iv_pos_7/dbs/.../pos_iv_pos_7_ts_b1_cTS_semantic_v2_seed1234_n6000.db`):

| Check | Result |
|---|---|
| Core comparability tables present | ✅ all 12 tables |
| `failures.constraint_loc` normalized | ✅ sample rows `Name@basename:line` (no `callsite(`) |
| `mutations.outcome` | ❌ column absent |
| `reward_counterfactuals` L1 columns | ❌ absent |
| CGC / global_failures | ✅ CGC=183, GF=15062 |
| D2.G `compute_metrics_for_db` | ✅ ingests (Gate E) |

**Fresh variants:** reference DB + V6-uniform POS smoke DB have full schema including `outcome` + L1 columns.

### 2.4 Gate D

- Registry parity: `v6_cTS` / `hybrid_cTS` → `applied_accounting_mode=True`; V5 equiv → False
- Mocked campaign: all `mutations.outcome` non-NULL, `applied` dominant

---

## 3. Batch 2 — e2e + POS mimic (Gates C, F, L5)

### 3.1 Files

| File | Gate |
|---|---|
| `test_d2e_cgc_parity.py` | **C** |
| `test_d2e_variant_e2e_smoke.py` | **B/C/D** (real-binary, gated) + **F** |
| `test_d2e_pos_path_mimic.py` | **L5** |

### 3.2 Gate C

- V6-uniform POS smoke DB (D2.C N=50 artifact): CGC≥1, GF≥1
- Mocked Hybrid: CGC≥1, GF≥1 after Arguzz path with family residues

### 3.3 Gate L5

- `d2d_checkpoint_smoke.json`: 4 jobs, N≤10, all selectors present
- `run_campaign_pos.sh`: `v6_uniform` branch present
- V5 archive opens, 6000 mutations, selector contains `cTS_semantic_v2`

### 3.4 Gate F (partial)

- Bernoulli V6-cTS golden trace (delegates to D2.B test)
- V5 scheduler decision-trace stability (50-step replay)

---

## 4. Batch 3 — ingestion dry-run + checklist (Gate E, aggregator)

### 4.1 Files

| File | Gate |
|---|---|
| `test_d2e_d2g_ingestion_dryrun.py` | **E** |
| `test_d2e_pos_readiness.py` | Aggregator |
| `a4/docs/cloud2/POS_READINESS_CHECKLIST.md` | Artifact |

### 4.2 Gate E

- `compute_metrics_for_db` on V5 archive + V6-uniform smoke DB
- `counterfactual_by_kind_frame` / `per_loc_v2_cells_frame` on `iv_pos_7/dbs` root
- **ISS-DD-1 closure:** mocked v6_cTS DB — offline replay of L1 columns from `mutation_rewards.d_loc` + failure counts + `mutation_substrategy` matches logged `reward_counterfactuals` rows (watch `d_loc=0`: must not use `d_loc or 999`)

### 4.3 Checklist

[`POS_READINESS_CHECKLIST.md`](../POS_READINESS_CHECKLIST.md) — Gates A,C,D,E,F **GREEN**; Gate B **AMBER (F15)**.

---

## 5. F15 — answer for Ivan (pre-D2.F)

**Question:** Does the R2 V5 archive have `outcome` + normalized loc?

| Item | V5 archive | Fresh variants |
|---|---|---|
| Normalized `failures.constraint_loc` | **Yes** — already `Name@basename:line` | Yes |
| `mutations.outcome` | **No** — column missing | Yes |
| L1 columns on `reward_counterfactuals` | **No** | Yes (nullable) |
| CGC / GF populated | **Yes** | Yes |
| D2.G legacy metrics ingest | **Yes** | Yes |

**Recommendation:** If D2.G needs per-variant **applied-pull rate** or **L1 channel re-audit on V5_control**, schedule a **fresh V5 POS re-run** (mirror V6_uniform treatment). If V5 is baseline for territory/CGC/decision metrics only, a **documented NULL-outcome adapter** in D2.G is sufficient — but decide explicitly before D2.F dispatch.

---

## 6. Residuals carried forward

| ID | Severity | Note |
|---|---|---|
| **F15** | HIGH | Gate B AMBER — Ivan decision required before D2.F |
| **DE-PI-4** | Low–Med | Hybrid CGC not split by surface in Gate C |
| **Gate F gap** | Low | No per-variant fuzzer golden traces for fresh variants |
| **ISS-DD-1** | Closed | Gate E offline L1 recompute |

---

## 7. Production code changes

**None.** D2.E is test + checklist only (per spec §0.2).

---

*End of D2.E B1–B3 report.*
