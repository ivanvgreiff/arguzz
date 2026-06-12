# Phase 7d Inc 3d Phase C Path A1 — Composer report

**Date**: 2026-06-12  
**Host SHA**: `632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1` (Inc 3d B P1, no rebuild)  
**Knob**: `RAYON_NUM_THREADS=1` (Path A1)  
**Calendar**: entry **1727** (`flare`, `meld`, `octorand`, `opulous`, 09:20–15:20 CEST)

---

## Verdict (Composer → Opus)

| Metric | Result |
|--------|--------|
| Complete pairs (A+B) | **4 / 5** (missing **β octobB** only) |
| Total ΔT flips (complete pairs) | **0 / 200** mutations |
| vs B P1 baseline | opulous + flare had ΔT races → **vanished** under `RAYON_NUM_THREADS=1` |
| **Decision** | **B7 closure candidate** — parallelism elimination works on all measured pairs |

Formal handoff rule asked for 5/5 pairs; **β is 1 run short** (`octobB`) due to POS node contention, not race signal.

---

## Pair reward-diff summary (first clean run, 09:20 batch)

| Pair | Complete | ΔT flips | B P1 baseline ΔT |
|------|----------|----------|------------------|
| α (octoa) | yes | **0** | 0 |
| β (octob) | **no** (missing B) | — | 0 |
| opulous | yes | **0** | 1 (mut 29) |
| meld | yes | **0** | 0 |
| flareCtrl | yes | **0** | 1 (mut 30) |

Source: `a4/audits/audit_output/inc3d/c_path_a1/quick_summary.json` (9 DBs from first successful dispatch before retry).

---

## Run history / blockers

1. **First dispatch** (calendar 1726): 9/10 — `octobB` missed when calendar expired mid-octorand sequence.
2. **Retry** (calendar 1727): aborted — `bav` held `octorand` allocation; parallel B-side allocates failed quota; `octoaA` hung.
3. **`octobB` poll** (12×60s): `octorand` still allocated by `bav` — could not dispatch.

**Recommendation for Opus**: Accept B7 closure on 4/5 pairs with 0/200 ΔT flips, or wait for `octobB` one-shot when `octorand` is free (β baseline was 0 in B P1 anyway).

---

## Artifacts

```
a4/audits/audit_output/inc3d/c_path_a1/     # 9 DBs + logs (first run)
a4/audits/audit_output/inc3d/c_path_a1/quick_summary.json
~/inc3d_c_a1_dispatch.log                    # first partial (coinbase)
~/inc3d_c_a1_retry.log                       # failed retry (coinbase)
```

---

## Phase 8 mitigation (if Opus confirms)

Set on all POS launches:

```bash
export RAYON_NUM_THREADS=1
# via dispatcher: A4_RAYON_THREADS=1 in manifest (Path A1 pattern)
```

Path B5 (preflight fingerprint) remains optional for upstream RISC Zero bug localization.
