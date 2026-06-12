# Phase 0 — Setup & Diagnostic Freeze

**Status**: ✅ DONE (2026-06-08)
**Owner**: Cursor
**Actual effort**: ~30 min
**Risk taken**: none

---

## TL;DR — what did we do, and why does it matter for cloud1?

**Plain English**: Before writing any new code, we put a freeze on the old campaign (IV.POS.5) and prepared the workspace so the next campaign (IV.POS.7) is unambiguous. We did THREE small things:

1. **Wrote "FROZEN — do not touch" on IV.POS.5's closure file** and put a "PAUSED — see cloud1" banner on the old master plan. This prevents anyone (us, future agents, ChatGPT Pro) from accidentally treating the old plan as still active.
2. **Renamed the three strategies for display only**: `uniform` is now shown as `arm_uniform_b128`, `zoned` as `kind_uniform_zoned_step`, `bandit` as `ucb_kindbucket_b16`. This is purely a label change — the internal names in our 15 IV.POS.5 SQLite databases are untouched, so all old analysis still works. ChatGPT Pro asked for these names in `ProG_Report_2.md §14.2` because the old names hid important behavioral differences between strategies.
3. **Built the folder scaffold for cloud1**: 1 master plan, 1 decisions doc (for Pro Round 2), 1 status tracker, and 10 per-phase markdown files. Now every phase has a "home" for tasks and retrospectives.

**How this fits**: Phase 0 is the setup that lets every subsequent phase (1-9) be self-contained. It's the boring infrastructure that prevents bugs like "wait, which plan are we following?" mid-campaign.

---

## Tasks (final)

### 0.1 Freeze IV.POS.5 [Pro §14.1] ✅
- [x] `a4/runs/iv_pos_5/CLOSURE.txt` exists (from IV.POS.5 wrap-up)
- [x] Appended "FROZEN 2026-06-08 (cloud1 Phase 0)" block to `CLOSURE.txt` with explicit pointers to cloud1 documents and the strategy rename
- [x] Added 🛑 PAUSED banner to `a4/docs/precloud/PRECLOUD_MASTER_PLAN.md` top-of-doc

### 0.2 Rename strategies in code [Pro §9, §14.2] ✅
- [x] Added `STRATEGY_DISPLAY_NAMES` dict and `display_strategy_name()` helper to `a4/standalone/fuzzer.py` (above class `A4Fuzzer`)
- [x] Internal selector strings UNCHANGED (preserves DB compat with all IV.POS.1-5 data)
- [x] Added top-line note to `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` documenting the rename

### 0.3 Cloud1 folder structure ✅
- [x] `a4/docs/cloud1/` exists
- [x] `CLOUD1_IMPLEMENTATION_PLAN.md` (24KB, locked)
- [x] `CLOUD1_DECISIONS_FOR_PRO_R2.md` (14KB, all 12 decisions documented)
- [x] `CLOUD1_STATUS.md` created
- [x] `phases/` subfolder created with 10 stub files

---

## Tests run

- [x] `python -c "from a4.standalone.fuzzer import ..."` — import works
- [x] `display_strategy_name()` verified for all 8 mapped names + fallback
- [x] **104 targeted unit tests passed** (`test_arm_universe`, `test_bandit`, `test_uniform_arm_selector`, `test_pilot_calibration`, `test_coverage_state` — 1 skip, 0 fail in 2.7s). Full test suite includes some slow integration tests that we'll re-run after Phase 6.

## Exit criteria — ALL MET

- [x] All 0.1, 0.2, 0.3 bullets checked
- [x] Targeted unit tests pass
- [x] `CLOUD1_STATUS.md` updated: Phase 0 = ✅ DONE
- [x] User cleared us to proceed to Phase 1 (in the same message as Phase 0 request)

---

## Files touched in Phase 0

| file | change |
|---|---|
| `a4/runs/iv_pos_5/CLOSURE.txt` | appended freeze block |
| `a4/docs/precloud/PRECLOUD_MASTER_PLAN.md` | added 🛑 PAUSED banner at top |
| `a4/standalone/fuzzer.py` | added `STRATEGY_DISPLAY_NAMES` + `display_strategy_name()` (above A4Fuzzer class) |
| `a4/runs/iv_pos_5/MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` | added 2026-06-08 rename note in header |

---

## Deviations from CLOUD1_IMPLEMENTATION_PLAN.md

None. All Phase 0 tasks executed exactly as planned in §Phase 0 of the plan.

## Extras (unplanned but desirable additions)

1. Pre-populated `STRATEGY_DISPLAY_NAMES` with the 4 new IV.POS.7 variant names (`kindUCB_zoned_v1`, `kindUCB_zoned_v2_noQ`, `kindTS_zoned_v2`, `cTS_semantic_v2`). These all map to themselves (identity), but having them in the dict makes future code references uniform. They were not requested explicitly in Phase 0 but are needed by Phase 5 anyway.
2. Added `bandit-16` alias to `STRATEGY_DISPLAY_NAMES` (separate from `bandit`) because IV.POS.5 plots used the hyphenated form.

## Consistency check against ProG_Report_2.md

| Pro reference | What we did | Match? |
|---|---|---|
| §14.2 "Rename them and stop treating them as symmetric baselines: uniform → arm_uniform_b128, zoned → kind_uniform_zoned_step, bandit → ucb_kindbucket_b16" | Implemented exactly as specified, display-only (internal preserved for DB compat) | ✅ |
| §14.1 "Freeze the current result. Do not tune the current bandit further as the main path." | CLOSURE.txt now explicitly says FROZEN; PRECLOUD_MASTER_PLAN.md now says PAUSED | ✅ |
| §9 "Lock calibration" | Deferred to Phase 5 (will remove pilot per D2; no code change in Phase 0) | ✅ |

No deviations.
