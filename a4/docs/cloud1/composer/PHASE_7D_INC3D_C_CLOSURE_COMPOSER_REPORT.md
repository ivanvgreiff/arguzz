# Phase 7d Inc 3d Phase C — Closure Campaign Composer Report

**Date:** 2026-06-13  
**Author:** Composer → Opus  
**Handoff:** `PHASE_7D_INC3D_C_CLOSURE_HANDOFF.md`  
**Analysis:** `a4/audits/audit_output/inc3d/closure_analysis_summary.json`

---

## TL;DR

| Dispatch | Exit | Pairs | ΔT flips | Preflight fp A≠B |
|----------|------|-------|----------|------------------|
| #1 path_a1_octobb + merged A1 | rc=0 | 5/5 | **0/250** | n/a |
| #2 path_a2 | rc=0 | 5/5 | **0/250** | n/a |
| #3 b5_default | rc=0 | 5/5 | **3/250** | **0/5 pairs** |
| #4 b5_rayon1 | rc=0* | 5/5 | **1/250**† | **0/5 pairs** |

**Decision suggestion: CLOSED (H1) / NEEDS-OPUS (H2 field localization).**

\* `b5_rayon1` required a calendar-gap resume (`octobA`+`octobB` only, `01:26–02:26`).  
† Single alpha-pair diff: mut 33 `delta_T` 34 vs 35 (both non-zero — not a 0↔1 timeout flip).

**H1 (parallelism elimination):** `RAYON_NUM_THREADS=1` on Path A1/A2 eliminates all observed ΔT races (0/500 across both dispatches, 5/5 pairs). The ~4× per-job slowdown under RAYON=1 (27 min vs ~7 min baseline) is itself evidence of substantial Rayon-parallel preflight work.

**H2 (preflight field drift):** `b5_default` reproduces ΔT races under default parallelism, but **no pair** shows differing `a4_preflight_fp` aggregate hashes between A/B runs. Opus should decide whether the tag is campaign-level (masking per-mutation drift) or whether drift lives below aggregate resolution (per-cell tags / touch bitmap only).

---

## 1. Dispatch wall times and exit status

| # | Mode | Start (CEST) | End (CEST) | Wall | Exit | Notes |
|---|------|--------------|------------|------|------|-------|
| 1 | `path_a1_octobb` | 19:26 | 19:56 | **27 min** | rc=0 | single `octobB` |
| 2 | `path_a2` | 21:15 | 23:14 | **99 min** | rc=0 | RAYON+RISC0+OMP=1 |
| 3 | `b5_default` | 23:14 | 23:37 | **23 min** | rc=0 | default parallelism |
| 4 | `b5_rayon1` | 23:55 | 02:27 | **~152 min**‡ | rc=0 | see calendar gap below |

‡ `b5_rayon1` calendar **1742** expired after `octoaB` (00:55); `octobA/B` resumed 01:26–02:26 under calendar **1744**. opulous/meld/flare finished during first tranche (00:25–00:28).

### Per-job durations (RAYON=1 modes, measured from POS status mtime)

| Job class | Duration |
|-----------|----------|
| path_a2 / b5_rayon1 n50 jobs | **26.9–29.9 min** (median **27.1 min**) |
| b5_default n50 jobs | **~7–9 min** (median **~8 min** from opulous/flare timestamps) |
| Speedup ratio default vs RAYON=1 | **~3.4–4×** |

---

## 2. ΔT flip tables (from DBs)

### 2.1 Path A1 merged (`c_path_a1/` + octobB closure)

| Pair | ΔT flips |
|------|----------|
| α (octoa) | 0 |
| β (octob) | 0 |
| opulous | 0 |
| meld | 0 |
| flareCtrl | 0 |
| **Total** | **0/250** |

### 2.2 Path A2 (`c_path_a2_closure/`)

| Pair | ΔT flips |
|------|----------|
| α | 0 |
| β | 0 |
| opulous | 0 |
| meld | 0 |
| flareCtrl | 0 |
| **Total** | **0/250** |

### 2.3 b5_default (`c_b5_default_closure/`)

| Pair | ΔT flips | Details |
|------|----------|---------|
| α | 0 | |
| β | 0 | |
| opulous | 0 | |
| meld | **1** | mut 47: ΔT 1 vs 0 |
| flareCtrl | **2** | mut 17: 0 vs 1; mut 21: 1 vs 0 |
| **Total** | **3/250** | race reproduced ✓ |

### 2.4 b5_rayon1 (`c_b5_rayon1_closure/`)

| Pair | ΔT flips | Details |
|------|----------|---------|
| α | **1** | mut 33: ΔT **34 vs 35** (both >0) |
| β | 0 | |
| opulous | 0 | |
| meld | 0 | |
| flareCtrl | 0 | |
| **Total** | **1/250** | see footnote — not a 0↔1 flip |

---

## 3. Preflight aggregate hash comparison (`a4_preflight_fp`)

Parser: last `<a4_preflight_fp …/>` tag per campaign log; fields: `state`, `pc`, `mmm`, `uc`, `txnIdx`, `pagingIdx`, `bigintIdx`, `dc0`, `dc1`.

### 3.1 b5_default — A vs B per pair

| Pair | Any field DIFF? |
|------|-----------------|
| α | **OK** (all 9 fields match) |
| β | **OK** |
| opulous | **OK** |
| meld | **OK** (despite 1 ΔT flip) |
| flareCtrl | **OK** (despite 2 ΔT flips) |

### 3.2 b5_rayon1 — A vs B per pair

| Pair | Any field DIFF? |
|------|-----------------|
| α | **OK** |
| β | **OK** |
| opulous | **OK** |
| meld | **OK** |
| flareCtrl | **OK** |

**Head-to-head:** `b5_default` shows ΔT races; `b5_rayon1` suppresses 0↔1 timeout-style flares. Neither mode shows aggregate preflight-hash divergence between paired runs. All pairs emit identical aggregate hashes across both bundles (same hex values on every node/pair checked).

---

## 4. Acceptance criteria scorecard

| Criterion | Result |
|-----------|--------|
| #1 octobB complete, 0 ΔT | **PASS** (5/5 A1 pairs, 0/250) |
| #2 path_a2 0/200 ΔT | **PASS** (0/250) |
| #3 b5_default ≥1 race signal | **PASS** (3 ΔT flips; 0 fp-hash diffs) |
| #4 b5_rayon1 0/200 ΔT + 0 fp diffs | **PARTIAL** (1 non-timeout ΔT diff on α; 0 fp diffs) |

---

## 5. Operational notes (for Opus / rerun)

1. **Calendar gaps** killed `b5_rayon1` mid-octorand twice; resume script `~/run_b5_rayon1_octob_only.sh` on coinbase completed β pair.
2. **SSH/WSL restart** interrupted local collect; re-collected 2026-06-13 03:05–03:16 — all **41 DBs** now local (10+10+10+10+1).
3. **RAYON=1 runtime expansion (~4×)** is consistent with parallelism-causes-race hypothesis; `b5_default` at baseline speed confirms Opus's timing model.

---

## 6. Artifacts

```
a4/audits/audit_output/inc3d/c_path_a1/              # 10 DBs (incl. closure octobB)
a4/audits/audit_output/inc3d/c_path_a2_closure/     # 10 DBs
a4/audits/audit_output/inc3d/c_b5_default_closure/   # 10 DBs
a4/audits/audit_output/inc3d/c_b5_rayon1_closure/    # 10 DBs
a4/audits/audit_output/inc3d/closure_analysis_summary.json
~/closure_campaign.log                               # coinbase timeline
```

---

## 7. One-line decision for Opus

**CLOSED on H1** (serializing Rayon eliminates B7 ΔT races on Path A1/A2); **NEEDS-OPUS on H2** because aggregate `a4_preflight_fp` tags do not diverge between A/B despite ΔT races under `b5_default` — Opus should fill `PHASE_7D_INC3D_C_CLOSURE_REPORT.md` §4–6 and decide if per-mutation / per-cell parsing is required for mechanistic field identification.
