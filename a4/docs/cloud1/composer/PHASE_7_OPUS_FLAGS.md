# Phase 7 — Items for Opus Review

**Date**: 2026-06-09 (superseded for blockers — see `PHASE_7_PROGRESS.md`)  
**Author**: Composer (post-7b / partial-7c)

---

## 1. V5 skip rate (144/200) — **not logged per attempt**

**Observation**: `cTS_semantic_v2` on flare completed with `exit_code=0` but only **144/200** mutations recorded; log reports **56 skips** (`no valid target`).

**DB gap**: Skipped bandit selections are **not** written to SQLite. Opus can see:
- Successful `bandit_decisions.selected_arm` (`KIND|zone`, no step)
- `mutations.kind` + `step` for successes
- Final `arm_state_snapshot` (6 arms with 0 pulls: e.g. `COMP_OUT_MOD|step0`, `INSTR_WORD_MOD_SUR|step0`)
- Campaign `.log` with total skip count only

**Tool**: `python a4/tools/analyze_cts_skips.py --db <V5.db> --log <V5.log>`

**Proposal for Opus**: Add `bandit_skip_log` table (arm, zone, step, attempt) or require `verbose=True` on diagnostic reruns before Phase 8.

**Not a calendar issue**: meta shows ~7 min wall, `num_requested=200`, `num_recorded=144`, `exit_code=0`.

---

## 2. `compressed_global_coverage=0` on all 7b variants

Including `zoned` with 200 mutations. May be guest/trace limitation, not V5 bug. 7b checker gate on V5 only may be too strict.

---

## 3. Phase 7c — **rewritten per Opus §2.6** (hook stdout parser)

Old verifier (pre-mutation `A4_INSPECT` trace) retired. New path: `A4_MUTATION_CONFIG` only → parse `<a4_<kind>_mod>` lines.

Re-run after rewrite; target **24/24 PASS**. Results → `PHASE_7C_SEMANTIC_RESULTS.json`.

## 3b. Hook 3 / compressed_global — **resolved (extractor bug)**

See `PHASE_7_HOOK3_DIAGNOSTIC.md`. Log grep was inconclusive (stdout not in `.log`); one-shot host + DB audit localized to `broken_addrs` dict vs int in `compressed_global_extractor.py` (fixed).

---

## 4. Artifacts for Opus

| Path | Content |
|------|---------|
| `a4/runs/pos_smoke_7b/` | All 5 POS DBs + logs |
| `a4/tools/analyze_cts_skips.py` | Skip/arm coverage summary |
| `a4/tools/check_smoke_db.py` | 7a/7b gates (V5 fails compressed_global + row count) |
| `a4/docs/cloud1/composer/PHASE_7B_POS_GUIDE.md` | Opus operational guide |

---

## 5. Recommended Opus decisions

1. Accept 7b with V5 at 144/200 + document skip investigation, or re-run V5 at higher N?
2. Defer or relax `compressed_global_coverage` 7b gate?
3. Own/fix `verify_mutation_semantics.py` assertions vs defer 7c to Phase 9?
4. Prioritize `bandit_skip_log` for Phase 8?
