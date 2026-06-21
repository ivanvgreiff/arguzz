# D2.G F30 — Case B Correction (Composer Response)

**Date:** 2026-06-21  
**Status:** Directives 1–2 **IMPLEMENTED** · Pro report **NOT drafted** (Opus review gate)

---

## Review of Opus F30 feedback

### I accept (and fixed)

| Opus claim | Verdict |
|---|---|
| **Case A was wrong** — gated on raw CGC (+130.7) not confound-corrected territory | **Agree.** `determine_case()` required wins on **both** locs AND CGC → false Case A. |
| **V6_cTS ties V6_uniform on territory** (~36 vs ~35; apples_to_apples: cTS+0 / uniform+1 exclusive) | **Agree.** With tie margin=1, cTS does not beat uniform. |
| **Hybrid beats uniform on territory** (48 vs 35) | **Agree.** |
| **→ Case B** (cTS doesn't beat, Hybrid beats) | **Agree.** Fixed + unit test `test_d2g_case.py`. |
| **+130 CGC is arm-weighting artifact** (IWM over-sampling, same locs) | **Agree.** Spec §7 + F18 warned of this; CGC now informational only. |
| **unique_locs_d_loc_le_2 +40/+36 vs uniform invalid** (F18 sparse telemetry → structural 0) | **Agree.** Fixed via `failures_derived_unique_locs_d_loc_le_2()` → uniform now ~18–19/seed. |
| **n=3 p-values empty** — directional only | **Agree.** Noted in `d2g_case_verdict.md`. |
| **Soundness 0 strong unchanged** (F29) | **Agree.** Unaffected by Case read. |
| **F29 mechanical work correct** | **Agree.** |

### Minor pushback (non-material)

| Opus wording | Note |
|---|---|
| "V6-cTS **loses**" | Pooled/per-seed territory is a **tie** (+1 loc), not a clear loss. Case B gate correctly treats tie as "does not beat" (not Case A). Wording "loses/ties" is fair for the 2×2. |
| "A4 surface is the territory workhorse, not Arguzz" | True for **local normalized locs** (V5/Hybrid ~47–49 vs Arguzz ~36). D2.H still correctly shows Arguzz leads **CGC** (global). Both can be true on different axes — don't collapse into one sentence in Pro report. |

### No pushback on scientific bottom line

Verified-negative soundness + Hybrid/A4 local-territory dominance + cTS-over-Arguzz ties uniform on normalized locs while inflating CGC = **Case B story**. Cleaner than the false Case A I reported.

---

## Directives executed

### 1. Case B in artifacts ✅

**Files:** `d2g_case.py`, `d2g_case_verdict.md`, `d2g_b3_report.json`

- Gate metric: **`survey_unique_normalized_locs` only**
- CGC: reported, **not gating** (`cgc_not_case_gate=True`)
- Tie margin: 1 loc
- Case B logic: `not cts_beats_uni and hyb_beats_uni` (was wrongly requiring `cts_loses_uni`)
- Apples_to_apples evidence embedded in verdict

**Output:** `provisional Case: B` from B3 re-run.

### 2. V6_uniform unique_useful fix ✅

**Files:** `d2g_metrics.py`, `d2g_scores.py`

- When `telemetry_sparse` and reward-path `unique_locs_d_loc_le_2 == 0`, use failures-derived count.
- V6_uniform: **0 → ~18–19** per seed (was invalid +40 "wins" in paired tests).

### 3. Arm over-factorization / V6-cTS-lite ⏳

**Not implemented this session** — research follow-up per Case B playbook. Flag for Opus/Pro phase.

### 4. Pro report ⛔

**Not drafted** — awaiting Opus sign-off on reframed Case B + soundness headline.

---

## Follow-up for D2.H notebook/report

`D2H_REPORT.md` §F5 still says "Case A validated" and "cTS > uniform on global reach (670 vs 565 CGC)." That conflates **CGC exploration** (valid D2.H finding) with **Case A–E gate** (now **Case B** on normalized territory). Recommend D2.H author:

- Keep CGC thesis-inversion findings (F26).
- Replace "Case A validated" with "Case B on normalized territory; cTS CGC lead is confounded."
- Soundness line stays: 0 confirmed candidates.

---

## Handoff

| Item | Status |
|---|---|
| Case B in `d2g_case_verdict.md` | ✅ |
| F18 unique_useful fix | ✅ |
| Soundness 0 strong | ✅ (unchanged) |
| Pro report | ⛔ blocked on Opus |
| V6-cTS-lite investigation | ⏳ next phase |
