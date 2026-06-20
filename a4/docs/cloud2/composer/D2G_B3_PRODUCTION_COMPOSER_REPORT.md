# D2.G B1/B2/B3 Production Composer Report — Batch 1 (N=10000, seeds 1234/1235)

**Date:** 2026-06-20  
**Author:** Composer  
**Scope:** Opus-CP review follow-through + first-batch processing  
**Data:** 8 DBs at `a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1/` (already pulled locally — Opus pull directive was outdated)  
**Artifacts:** `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/`

---

## 1. Opus review items — disposition

| Item | Action | Status |
|------|--------|--------|
| Regenerate stale smoke B1 channel CSV (F20) | Re-ran `build_d2_artifacts.py --phase b1` on smoke | Done — `skipped_other` gone, C5 present |
| Neutralize lingering `🐛` in fuzzer per-mutation status | `fuzzer.py:2757` → `⚠` + comment fix | Done |
| Commit D2.G + fuzzer fixes | This commit | Done |
| Pull batch-1 DBs | Already local (8× N=10000) | Not needed |
| Run B1 on N=10000 | `--phase b1` on prod | Done |
| Build triage-at-scale (DG-1) | `triage_at_scale.py` + manifest + 132 local tier-2 reruns | Done |
| Build B3 scores + Case | `d2g_scores.py`, `d2g_case.py`, `arm_occupancy.py`, `--phase b3` | Done |

**No pushback** on Opus review — both loose ends were valid; arm-occupancy kind parsing needed a fix discovered during B3 (see §5).

---

## 2. Minor fixes applied

### 2.1 Fuzzer ACCEPTED labeling (complete)

- Per-mutation marker: `" ACCEPTED"` (was `BUG!`)
- Summary line: `ACCEPTED (prover success)` without 🐛
- Alert line: `⚠ ACCEPTED: N mutations … (triage separately)`
- Per-row status emoji: `⚠` (was `🐛`) with honest comment

### 2.2 Smoke B1 channel CSV regenerated

Before (stale): `V6_cTS,1234,skipped_other,4`  
After: `V6_cTS,1234,C5,4` — F20 fix reflected in deliverable.

---

## 3. B1 on batch-1 N=10000 — four Opus checks

### 3.1 CGC field collapse (`cycle_phase` at N=10000)

| variant | seed | distinct_cycle_phase | collapsed? |
|---------|------|---------------------|------------|
| V5_control | 1234/1235 | 3 | No |
| V6_uniform | 1234 | 3 | No |
| V6_uniform | 1235 | **2** | No (≥2 values) |
| V6_cTS | 1234/1235 | 3 | No |
| Hybrid_cTS | 1234/1235 | 3 | No |

**Verdict:** `cycle_phase` does **not** collapse to 1 at N=10000 (unlike the N=100 V6_uniform smoke observation). All variants retain ≥2 distinct values. No `has_collapse=True` rows.

### 3.2 C1/C2/C5 channel split (F20 fix)

Summary counts (both seeds combined):

| variant | C1 | C2 | C5 | accepted | applied_other |
|---------|---:|---:|---:|---------:|--------------:|
| V5_control | 12730 | 0 | 0 | 0 | 7107 |
| V6_uniform | 13595 | 4796 | 985 | 585 | 0 |
| V6_cTS | 10957 | 6978 | 1045 | 986 | 0 |
| Hybrid_cTS | 12165 | 2497 | 387 | 304 | 4516 |

**Verdict:** C5 mapped from `outcome='skipped'` only — no `skipped_other`. V6_cTS/Hybrid show expected C5 guest-panic channel.

### 3.3 Territory: V6_cTS vs V6_uniform at scale

| bucket | count |
|--------|------:|
| common_all_four | 33 |
| arguzz_only / v6_exclusive | 1 (`Poseidon0:inst_p2.zir:470`) |
| union_all_four | **50** normalized locs |

Mean unique normalized locs (2 seeds):

| variant | locs | CGC final | local_context_final |
|---------|-----:|----------:|--------------------:|
| V6_uniform | 35.0 | 488.5 | 35.0 |
| V6_cTS | 36.0 | **617.0** | 36.0 |
| Hybrid_cTS | **48.5** | 508.5 | 48.5 |
| V5_control | 46.5 | 370.5 | 46.5 |

**Verdict:** V6_cTS slightly ahead on locs (+1.0 mean) and clearly ahead on CGC (+128.5). Hybrid wins on locs (+13.5 vs uniform) with modest CGC gain (+20). Territory union = 50 normalized locs across all four.

### 3.4 INSTR_WORD_MOD adaptive correction (F19 action 3)

Bandit `selected_arm` uses 5-pipe Hybrid format (`arguzz_exec_fault|KIND|zone|opcode|pre_post`). Kind parser fixed to use segment [1] when surface prefix present.

| variant | early IWM share | late IWM share | Δ late−early | adaptive reduced? |
|---------|----------------:|---------------:|-------------:|:-----------------:|
| V6_cTS 1234 | 28.8% | 35.4% | **+6.6%** | **No** |
| V6_cTS 1235 | 29.0% | 35.4% | **+6.4%** | **No** |
| Hybrid 1234 | 11.7% | 10.9% | −0.8% | Yes |
| Hybrid 1235 | 12.1% | 11.2% | −0.9% | Yes |

**Verdict:** V6_cTS **increases** INSTR_WORD_MOD allocation in the late campaign — the adaptive phase does **not** correct cold-start over-sampling; it amplifies it. Hybrid shows a small reduction. Raw accept counts reflect this: V6_cTS **986** accepts vs V6_uniform **585** (~1.7×) — mostly INSTR_WORD_MOD (843/986 on seed 1234).

**Confound flag:** Any V6_cTS “win” on raw accepts or INSTR_WORD_MOD-heavy territory must be normalized per-kind before claiming soundness signal.

---

## 4. Triage-at-scale (DG-1)

### 4.1 Tier-1 (all accepts, DB-only)

| metric | value |
|--------|------:|
| Raw accepts (`soundness_signal=true`) | **1875** |
| Tier-1 hidden global reject | **0** |
| Tier-1 pending tier-2 | 1875 |

No Hook-3 hidden rejects among accepted rows.

### 4.2 Deduped rerun manifest

- Global dedupe `(kind, step)`: **742** unique jobs
- Hybrid_cTS-only dedupe (B3 gate variant): **132** jobs
- POS chain manifest: `triage_at_scale/d2g_triage_rerun.chain`
- CSV manifest: `triage_at_scale/d2g_triage_rerun_manifest.csv`

Full-scale tier-2 for all 742 jobs is **not** run locally (~9h est.); manifest is ready for `chain_dispatcher` on coinbase.

### 4.3 Tier-2 local sample — Hybrid_cTS (132/132 complete, ~58 min)

| class | count |
|-------|------:|
| accepted_noop | 93 |
| accepted_propagated_candidate | 39 |

| evidence | count |
|----------|------:|
| (none — byte-identical) | 57 |
| cosmetic (branch unused-target) | 36 |
| **weak** (data-instruction used operand) | **39** |
| strong | 0 |

**Interpretation:** 39/132 (30%) Hybrid deduped accepts are **weak propagated candidates** — same pattern as smoke step 3939. **Zero strong** (no post-inject divergence). **Zero confirmed bugs.** Extrapolated to 1875 raw accepts: expect majority noop/cosmetic, non-trivial weak tier requiring D3/post-state digest.

Output: `triage_at_scale/d2g_accept_triage_tier2_sample.csv`

---

## 5. B3 — provisional Case read

**Provisional Case A** (V6-cTS beats V6-uniform on locs **and** CGC; Hybrid also beats uniform on both).

| comparison | locs | CGC |
|------------|-----:|----:|
| V6_cTS vs V6_uniform | 36.0 vs 35.0 ✓ | 617 vs 488.5 ✓ |
| Hybrid vs V6_uniform | 48.5 vs 35.0 ✓ | 508.5 vs 488.5 ✓ |

**Caveats (locked):**
- n=2 seeds only — **provisional** until batch 2 (seed 1236)
- Paired tests have `small_n_caveat=True` (p-values suppressed)
- Soundness counts are post-triage for Hybrid sample only; full campaign triage pending
- INSTR_WORD_MOD confound active on V6_cTS

Full verdict: `prod/artifacts/d2g/d2g_case_verdict.md`

---

## 6. Code delivered (B3)

| module | purpose |
|--------|---------|
| `arm_occupancy.py` | Kind allocation early/late + IWM adaptive correction |
| `d2g_scores.py` | S3/S4/S5 score assembly |
| `d2g_case.py` | Case A–E determination + markdown verdict |
| `triage_at_scale.py` | DG-1 tier-1, manifest, chain file, local tier-2 |
| `build_d2_artifacts.py` | Extended with `--phase b3`, `--tier2-variant`, `--skip-local-tier2` |

Existing B1/B2 modules unchanged except `arm_occupancy` kind parser fix.

---

## 7. Tests run

```
pytest a4/runs/iv_pos_8/d2g/test_triage_semantics.py  — 4 passed
pytest a4/runs/iv_pos_8/d2g/test_d2g_smoke.py::TestD2GSmokeB1 — 8 passed
A4_REAL_BINARY=1 pytest …::TestD2GSmokeB2Oracle — 1 passed (prior session)
```

---

## 8. What remains (B4 / batch 2)

1. **Batch 2** seed 1236 lands → re-run full pipeline on 12 DBs
2. **Full triage-at-scale:** dispatch `d2g_triage_rerun.chain` for remaining variants / global 742 dedupe
3. **Final Case verdict** with 3 seeds + complete post-triage soundness_score
4. **D3 sketch** targeting weak-tier candidates (39 Hybrid + extrapolated hundreds campaign-wide)
5. **Pro report + plots** (`d2g_plots.py` not yet built)

---

## 9. Pushback / corrections

1. **Opus “DBs not local”** — outdated; all 8 batch-1 DBs were already at `d2f/prod/d2f_prod_b1/` when this work started.
2. **Arm occupancy bug found during B3** — initial kind parser used segment [0] (`arguzz_exec_fault`) not [1] (`INSTR_WORD_MOD`); fixed before final case verdict regeneration. First B3 run wrote stale zero IWM shares; corrected in `d2g_instr_word_mod_correction.csv` and `d2g_case_verdict.md`.
3. **Case A is directional, not significant** — with n=2 we report Case A as provisional hypothesis support, not statistical proof.
