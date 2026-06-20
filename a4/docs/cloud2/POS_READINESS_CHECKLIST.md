# IV.POS.8 — POS Readiness Checklist (D2.E)

**Generated:** 2026-06-20  
**Spec:** [`IV_POS_8_D2_E_SPEC.md`](IV_POS_8_D2_E_SPEC.md) v1.0  
**Baseline sweep:** 780 passed / 27 skipped (pre-D2.E)  
**D2.F must not start until all blocking gates are green.**

---

## Gate status (Gates A–F)

| Gate | Description | Status | Notes |
|------|-------------|--------|-------|
| **Gate A** | Normalized-loc parity (`short_loc` all paths) | **GREEN** | Unit + mocked v6_cTS e2e; failures/coverage canonical |
| **Gate B** | Schema + telemetry parity (4 variants + V5 archive) | **AMBER — F15** | Fresh variants OK; **V5 R2 archive missing `mutations.outcome` + L1 columns** |
| **Gate C** | CGC parity (F13 regression) | **GREEN** | V6-uniform POS DB + mocked Hybrid both non-empty CGC/GF |
| **Gate D** | Applied-accounting + outcome consistency | **GREEN** | v6_cTS/Hybrid applied=True; outcomes non-NULL on fresh runs |
| **Gate E** | D2.G ingestion dry-run | **GREEN** | `metrics.py`, `counterfactuals.py`, `per_loc_v2.py` ingest V5 archive + V6 smoke DB |
| **Gate F** | Determinism / golden traces | **GREEN** | V5 Tier-1/Tier-2 + Bernoulli golden traces |

---

## F15 — V5 archive schema gap (REQUIRES IVAN DECISION)

**Archive:** `a4/runs/iv_pos_7/dbs/.../pos_iv_pos_7_ts_b1_cTS_semantic_v2_seed1234_n6000.db`

**Present and compatible:**
- All comparability tables (`compressed_global_coverage`, `global_failures`, `bandit_decisions`, etc.)
- CGC=183, global_failures=15062, mutations=6000
- `failures.constraint_loc` already canonical (`Name@basename:line`)
- D2.G `compute_metrics_for_db` ingests successfully

**Missing vs fresh-variant schema:**
| Table | Missing columns |
|-------|-----------------|
| `mutations` | `outcome`, `proof_generated`, `proof_verify_failed`, `elapsed_ms` |
| `reward_counterfactuals` | `bandit_success_l1`, `l1_substrategy_uniqueness`, `l1_d_loc_le_2`, `l1_singleton_failure` |

**Options (decide before D2.F):**
1. **Fresh V5 re-run** on POS (like V6_uniform) — full schema parity for D2.G applied-pull / L1 re-audit metrics
2. **Documented V5-archive adapter in D2.G** — treat NULL outcome as implicit "applied"; skip L1 columns for archive rows only

**Recommendation:** Fresh V5 re-run if D2.G needs per-variant applied-pull rate or L1 channel re-audit on V5_control; adapter OK if V5 is comparison baseline on legacy metrics only (local_context_final, CGC, territory).

---

## Real-binary smoke (≤10 mutations, gated `A4_REAL_BINARY=1`)

| Variant | Test module | Local status |
|---------|-------------|--------------|
| V6_uniform | `test_d2e_variant_e2e_smoke.py` | Gated — run with `A4_REAL_BINARY=1` |
| V6_cTS | `test_d2e_variant_e2e_smoke.py` | Gated |
| Hybrid_cTS | `test_d2e_variant_e2e_smoke.py` | Gated |
| V5_control | Archive reuse — no fresh run required for checkpoint |

---

## POS manifest stub

`a4/pos/manifests/iv_pos_8/d2d_checkpoint_smoke.json` — 4 jobs, N=10 each. **Execution is D2.F.**

---

## Regression gates (must stay green)

- `test_d2c_golden_trace_v5_decision_seq.py`
- `test_d2c_golden_trace_v5_db_byte_identity.py`
- `test_d2_bernoulli_floor_golden_trace.py`

---

*End of POS readiness checklist.*
