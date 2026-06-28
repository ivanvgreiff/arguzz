# Implementation increments + test gates (V8 = option b; binary = fixed; branch = isolated)

**Date:** 2026-06-28. Decisions all locked (see `00 ROUND-2`). Each increment ends with a TEST GATE; do not proceed until green. All code lands on the feature branch (`04`).

## Inc 0 — Isolation (feature branch off cloud2)
- Branch `cloud2-sched-ablation` off `cloud2` HEAD. Work + commit there; keep `cloud2` clean.
- **Gate:** branch exists; `cloud2` HEAD unchanged; existing test suite green on the branch (baseline).

## Inc 1 — V0: `SemanticUniformArmSelector` (arm semantics, NO bandit)
- New selector over `SemanticArmUniverse.available_arms`: uniform-pick arm → uniform-pick step in arm. NO reward/update.
- Wire: `cli.py` (+`V0_uniform` `--selector` choice), `fuzzer.py` (defer branch + `_setup_v0_uniform` building `SemanticArmUniverse.build(data, a4_kinds)` A4-only + a `_run_*` that does NOT call the bandit/`record_bandit_decision`), `variants.py` (`V0_uniform`, launcher=cli, surface=a4, no bandit).
- **Gate:** (i) new unit test — V0 draws over the A4 semantic arm universe, applies A4 mutations incl. ITM, calls no bandit update; (ii) `test_variant_launch_cmds` green; (iii) local micro-smoke `cli fuzz --selector V0_uniform --num 10` on the existing holed binary records ≥1 applied INSTR_TYPE_MOD, no crash.

## Inc 2 — V8: `v8_arguzz_a4_driver.py` (NO arm semantics, NO bandit)
- Fork `v6_uniform_driver.py`. Per pick: `ArguzzScheduler.pick()` → `(instr, exec_step, _)`; **translate `U = step_domain_map.to_user(exec_step)`** (skip if None = host ecall); **assert** `class(trace[exec_step]) == class(get_cycle(U))`; choose A4 kind = **uniform over A4 kinds valid at `U`** (option b); build the A4 mutation config; `run_a4_mutation`; `CoverageDB.record_mutation(kind=<chosen>, config=<dict>, outcome='applied', verifier_accepted=<parsed>)`.
- `variants.py` (`V8_arguzz_sched`, launcher=driver, driver_module=`a4.standalone.v8_arguzz_a4_driver`, surface=a4, no bandit).
- **Gate:** (i) unit test — the executor→user_cycle translation matches `step_domain_map` on a known trace; the kind choice is uniform over `inspection_data.get_valid_kinds_at(U)` (incl. ITM where major≤6); the recorded row shape satisfies `oracle.extract_accepts` + `is_decode_divergent_itm` + `markers`; (ii) `test_variant_launch_cmds` green; (iii) local micro-smoke `--num 10` records A4 mutations at instruction-balanced sites incl. ≥1 ITM, no crash, no class-mismatch assert.

## Inc 3 — Analysis harness (6-variant ablation)
- `race_lib.py`: add `V0_uniform`/`V8_arguzz_sched` to VARIANTS (ladder order: V8, V0, V5, then Hybrid, V6_cTS, V6_uniform) + COLORS/LABEL/SURFACE; **generalize `_RID`** to match the `a3seambfix` slug; add `fig_scheduler_ablation` (the V8→V0→V5 ladder: `P(apply ITM)` + `P(found)` + `conditional_find_density`). `build_race_notebook.py` (+ ablation section, bump `assert imgs`). `build_race_artifact.py` (ON/OFF/SUB + ladder panel).
- **Gate:** race unit tests green (incl. the `_RID` change); a dry build of the notebook/artifact on existing data runs with 0 cell errors + the new figure present.

## Inc 4 — Fixed binary + manifest/guard (pre-POS; on the shared risc0-seamb worktree)
- Cherry-pick `6556e8d7` onto `workspace/risc0-seamb`; rebuild holed+control → `a4/builds/ap_seamb_fix/`; read new head_sha + guest_image_id.
- Manifest: the `--variants` filter (exists, `61ae36a`); set `EXPECT_HEAD_SHA`=new; slug `a3seambfix`; new result dirs + `.gitignore`.
- **Gate:** `strings` shows the 3 kinds present (were 0) + ITM present; a `TXN_PREV_CYCLE_MOD` replay APPLIES (num_failures>0, not invalid-config); fingerprint guard passes (planted_bug/none, load_rs2=1, new head); Stage-0 ground truth re-run green on the fixed binaries.

## Inc 5 — POS (USER-GATED)
- Smoke: V0/V5/V8/Hybrid × 3 seeds × N=2000 → confirm V8 launcher on POS, measure per-mut timing, ITM>0 for all four. Then thesis ×10 × N=5000 (40 jobs) into `a3seambfix_race_thesis`; reuse contaminated V6_uniform/V6_cTS (binary-invariant; labelled).
- **Gate:** user approval + G-SMOKE; resume-safe chain; analysis reads the fixed dataset separately from the contaminated `thesis_results/`.

**Process:** implement an increment → run its tests → report green/red → only then proceed. Double-check each against the code (the agent file:line refs are a map, not gospel — verify before editing).
