# Phase 7d Inc 3c — B7 Phase δ closure report

**Date**: 2026-06-11  
**Owner**: Composer  
**Plan**: SPREAD (`SPREAD=1`, calendar entry 1723)  
**Host**: patched `c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332`  
**Bundle**: built from `53b9f71+` with verbose-passthrough `executor.py` fix  
**Artifacts**: `a4/audits/audit_output/inc3c/` + `diffs/`

---

## ⚠️ Sanity gate status — STOP for Opus review

Per `PHASE_7D_INC3C_WORK.md` §4, parsing completed but **two sanity gates failed** before B7 can be declared closed:

| Gate | Expected | Observed | Status |
|------|----------|----------|--------|
| Flare negative control | 0 reward diffs | **2** row diffs (1 `delta_T` flip at mut 21) | **FAIL** |
| Octorand pairs (2×50) | ~2 `delta_T` racy bits | **1** (`delta_T` flip at mut 27 in α only; β clean) | marginal |
| SPREAD Tier-S siblings | opulous + meld each 0 → octorand-specific | opulous **0**, meld **2** row diffs (1 `delta_T` at mut 36) | **FAIL** (suggests Tier-S-wide, not octorand-only) |
| Verbose tags in logs | present | **49–50** `<a4_touch_verbose>` per log | **PASS** (fuzzer passthrough fix confirmed) |

**Composer stopped short of claiming B7 closure.** The `racy_context_summary.json` clustering is clean and likely actionable, but flare/meld anomalies must be reconciled with Inc 3b (flare was 0/50 on pre-fix host) before Opus traces witgen.

---

## Verdict (provisional)

| Metric | Value |
|--------|-------|
| Octorand intra-pair `delta_T` diff rate (2 pairs × 50 muts) | **1 / 100** mutations |
| Flare control intra-pair diff rate | **2 / 50** row diffs (**1** `delta_T`) |
| Tier-S siblings (opulous / meld) | **0 / 50** / **2 / 50** |
| Racy constraint context(s) | **`(FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291), 9, 5)`** — 5/5 verbose diffs |
| Single-context race? | **YES** (100% of verbose symmetric diffs; 1 context, `occurrences=5`) |

---

## Section 1 — Pair reward-diff summary

| Pair | Node | n | seed | Racy mut IDs | Kind / step | `delta_T` signs (A→B) |
|------|------|---|------|--------------|-------------|------------------------|
| α (octoa) | octorand | 50 | 999 | **27** | `MEM_VAL_MOD` / 3259 | 0→1 |
| β (octob) | octorand | 50 | 999 | — | — | — |
| opulous | opulous | 50 | 1000 | — | — | — |
| meld | meld | 50 | 1001 | **36**, 48 | `LOAD_VAL_MOD` / 2066; `MEM_VAL_MOD` / 3810 | 0→1; 0/0 (reward-only) |
| flareCtrl | flare | 50 | 999 | **21**, 39 | `STORE_OUT_MOD` / 3347; `INSTR_TYPE_MOD` / 3813 | 0→1; 0/0 (reward-only) |

**`delta_T` flips (true racy touch bits):** 3 across SPREAD (α-27, meld-36, flare-21).  
**Reward-only row diffs (no `delta_T` flip):** meld-48, flare-39 — still show the same verbose context bit flip (see §2).

---

## Section 2 — Verbose context analysis

Parser: `a4/audits/inc3c_parse_phase_delta.py --plan spread`  
Verbose diff tool: `a4/audits/B7_verbose_touch.py` (pair-mate symmetric diff; block index resolved by scanning `mutation_id±{1,2}` candidates).

| Pair | mut_id | extra | missing | `(loc, major, minor)` | verbose_block_index |
|------|--------|-------|---------|------------------------|---------------------|
| α | 27 | 1 | 0 | `FieldToWord(…/inst_p2.zir:291)`, 9, 5 | 25 |
| meld | 36 | 1 | 0 | same | 34 |
| meld | 48 | 1 | 0 | same | 46 |
| flareCtrl | 21 | 1 | 0 | same | 19 |
| flareCtrl | 39 | 1 | 0 | same | 37 |

Every divergent mutation shows **exactly one** extra context on the B run (`|extra|+|missing| == 1`), consistent with a single touch-bit flip in the coverage bitmap.

---

## Section 3 — Racy context clustering

```json
{
  "by_context": [
    {
      "loc": "FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)",
      "major": 9,
      "minor": 5,
      "occurrences": 5
    }
  ],
  "total_racy_bits": 5,
  "plan": "spread",
  "n_pairs_analyzed": 5,
  "verbose_files": 5
}
```

Full file: `a4/audits/audit_output/inc3c/diffs/racy_context_summary.json`

**Interpretation:** All captured racy verbose diffs — including flare control and meld, not only octorand — cluster on a **single** `(loc, major, minor)` family in `inst_p2.zir:291` major=9 minor=5. This is the key deliverable for Opus code trace, but the cross-node spread contradicts the Inc 3b hypothesis that only octorand races.

---

## Section 4 — Open items for Opus

1. **Flare control regression**: Inc 3b (pre-fix host) had flare intra-pair **0/50**; Inc 3c (patched host + verbose passthrough) has **1/50** `delta_T` + **1/50** reward-only, both mapping to the same `inst_p2.zir:291` context. Is this (a) low-rate environmental race now visible with verbose host, (b) patched-host side effect despite §6.2 safety argument, or (c) SPREAD run variance?

2. **Tier-S-wide vs octorand-specific**: meld shows the **same** context bit at mut 36/48; opulous is clean. Microcode: flare `0xa10113e`, octorand `0xa101116` (Inc 3b fingerprints). Does meld share octorand's revision?

3. **Octorand rate**: only α pair hit (1/100 `delta_T`); β reproducibility check was clean. Acceptable sampling variance or race intermittency?

4. **Reward-only diffs without `delta_T` flip** (meld-48, flare-39): verbose still shows the `inst_p2.zir:291` bit extra on B — investigate whether reward aggregation reads a different field than `delta_T` or timing of bitmap snapshot differs.

5. **Parser fix landed**: `B7_verbose_touch.py` now pair-scans block indices (`mutation_id-2` / `mutation_id-1`) to align 49 verbose blocks with 50 DB mutations. Re-run parse after any new captures.

6. **Next step (await Opus)**: Trace `FieldToWord(…/inst_p2.zir:291)` major=9 minor=5 through witgen; optional atomic-increment host experiment per work order §6 **only on Opus request**.

---

## Capture metadata

| Item | Value |
|------|-------|
| Dispatcher | `a4/pos/run_inc3c_phase_delta.sh` with `SPREAD=1`, `--allocation-duration 0` |
| Nodes | octorand + opulous + meld + flare (parallel under one calendar entry) |
| Logs | 10 × `pos_inc3c_phase_delta_zoned_seed*_n50_*.log` (49–50 verbose tags each) |
| DBs | 10 matching `*.db` |
| Diffs | `a4/audits/audit_output/inc3c/diffs/{pair_reward_summary,racy_context_summary,B7_*.json,verbose_*}.json` |
