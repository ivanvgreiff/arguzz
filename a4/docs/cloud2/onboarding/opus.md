You are the D2-focused Opus for the IV.POS.8 zkVM-fuzzing project (RISC Zero; A4 = post-execution trace mutation vs Arguzz = during-execution fault injection). This is a fresh conversation — you have no prior context, so catch up from the docs/code below before doing anything.

Your task this session: write the D2.C Batch 1 kickoff markdown → a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_KICKOFF.md — the self-contained doc Composer will implement from. You do not write production code; you write the kickoff that instructs Composer. D2.C = Arguzz integration; Batch 1 = the primitive layer (arguzz_invoke.py) + a real-binary smoke (gating) + a V5 golden-trace regression test.

Repo state (HEAD = dfd0ebe): D2.A done; D2.B done/closed (PS-1 removed 5 dead A4 kinds; PS-2 fixed _TXN_ROLE_BY_KIND); A4Fuzzer.MUTATION_KINDS = 11 kinds; D2.C is NOT implemented (no arguzz_invoke.py/arguzz_bridge.py/v6_uniform_driver.py yet); D2.C spec = v0.4 DRAFT.

Read in this order (don't skip the code):

Plan & why:
1. a4/docs/cloud2/New_Master.md — the governing forward plan. §0 (hierarchy), §1 (locked decisions), §2 Phase 0+1 (your phase), §6 (spec/batch index).
2. a4/docs/cloud2/pro_checkin_attachments/ProG_Report_4.md — Pro's requirements behind New_Master. §1 (keep/drop), §2 Phase 0/1, Q3 (L1 stays inactive), Q4 (accept signal/no-op), §6 (suggestions).
3. a4/docs/cloud2/separate-planning/central-planning-1.md — the repo-state synthesis + flag ledger (fastest catch-up). Read fully if you can; at minimum §0 (nomenclature), the ⚑ flags section (F6/F7/F9/F10 are corrections you MUST internalize), §5 (NFP index), §6B.1 (D2.A), §6B.2 (D2.B).

The spec you implement from (read fully — this IS your Batch 1 source):
4. a4/docs/cloud2/IV_POS_8_D2_C_SPEC.md (v0.4). Focus §1 (goal; the 4 kinds; two-tier 11/4), §1.3 (3-layer architecture), §1.6 (5-layer testing framework), §3.1 (codebase landscape = the file list), §4.1–4.7 (file-by-file change list), §5 (per-kind mechanism), §6.1 (outcome classifier = Option C, prover_status-PRIMARY — critical), §6.2 (4-channel + C5), §11 Batch 1 (the tasks you turn into a kickoff), §14 (acceptance).

Architectural-decision context:
5. a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md — NFP-1 (5-tuple ArmKey), NFP-3 (RNG strategy), NFP-5 (A4_DUMP_POST_MUT), NFP-10 (byte_addr — already fixed), NFP-11 (3 live/5 dead A4 kinds).
6. a4/docs/cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md — §9 (the 4-channel rejection model), FIE semantics, the soundness guard, and the at_read/at_write Path-A/Path-B distinction (the V6 analog your outcome classifier must handle).

Code to read at HEAD (do not write the kickoff before reading these):
- a4/runs/iv_pos_7/drivers/v6_driver_v2.py — frozen reference; arguzz_invoke.py is refactored from its run_inject + tag parsing + outcome classification (spec §4.1 maps what moves where).
- a4/arguzz_dependent/arguzz_parser.py — ArguzzFault.parse, ArguzzTrace; arguzz_invoke imports these (don't rewrite the regexes).
- a4/arguzz_dependent/arguzz_runner.py — the deprecated predecessor (task 1.3 adds a deprecation docstring; note its guest_crashed / "verify segment" rejection logic).
- a4/standalone/bandit_ts.py — MutationOutcome enum (~line 57) that the classifier maps to; cTS scheduler (for the V5 golden trace).
- a4/standalone/semantic_arm_universe.py — ArmKey (lines 174–182, NOT bandit_ts.py) + SemanticArmUniverse (for the Batch-1 arm-space calc).
- a4/standalone/compressed_global_extractor.py — _TXN_ROLE_BY_KIND (~line 161; task 1.2 makes the ARGUZZ-kind role extensions permanent here) and confirm the byte_addr fix (~line 222) is intact.
- a4/standalone/coverage_db.py, a4/standalone/fuzzer.py, a4/core/constraint_parser.py (short_loc), a4/core/touch_coverage.py (parse_family_residues etc.) — arguzz_invoke re-exports/uses these (spec §4.1).
- a4/standalone/tests/test_d2a_*.py + test_d2b_*.py — templates for the test layers + golden-trace pattern.
- a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_KICKOFF.md — use as the format template for your kickoff.
- The R2 V6 oracle DB in spec §1.1/§5.5 (pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000.db) — source of canned stdout for the mock test + the outcome-distribution oracle.

Critical facts to get RIGHT (these have bitten us — do not repeat):
- Outcome classifier = Option C, prover_status-PRIMARY (NOT host_panic-first). The old "~95% panic / ~5% applied" framing was a classifier artifact. Corrected distribution on the R2 V6 DB: ~94.6% APPLIED (≈91.6% APPLIED+REJECTED [C1 local-tag + C2 global/"verify segment" with no local tag] + ~2.95% APPLIED+ACCEPTED) + only ~5.2% true SKIPPED + <0.2% edge. C5 = prover_status="start" AND host_panic ONLY, not "any panicked-at string." Mapping: success→APPLIED+soundness_signal; error+failures→APPLIED; error+no-failures→APPLIED+failure_recording_gap (Path B); start+panic→SKIPPED; timeout→ERROR.
- _detect_host_panic checks BOTH "panicked at" AND "Guest panicked:" (v6_driver_v2 only checks the former — adopt the broader check).
- arguzz_invoke.py is the NEW primitive; arguzz_runner.py is DEPRECATED — import ArguzzFault from arguzz_parser; do not revive arguzz_runner.
- V6-cTS = all 11 Arguzz kinds; Hybrid-cTS = 4 selected (MUTATION_KINDS_ARGUZZ_FULL / _SELECTED). Batch 1 is just the primitive, but the arm-space calc uses these.
- applied_accounting_mode is NOT yet wired in fuzzer.py — that's D2.C Batch 3 (task 3.2a), NOT Batch 1. Don't include it.
- The byte_addr fix (NFP-10) is already in compressed_global_extractor.py — don't reintroduce the bug; task 1.2 only moves the ARGUZZ _TXN_ROLE_BY_KIND extensions in permanently.
- The V5 golden trace (cTS_semantic_v2) must stay byte-identical — Batch 1 only adds the Arguzz primitive, so it's a no-op for the V5 path; capture the golden trace fresh on current HEAD (post-1.5e), not vs the old archive.

Do this FIRST (Phase 0), before writing the kickoff: the D2.C spec has two drift items to fix → lock it to v0.5: (1) the §7 arm-certainty-stack S5 row still says "all D2.C arms pre_exec" — contradicts v0.4's 5-pre_exec/6-post_exec convention; (2) the parent header cites D2_PLAN "v0.15 §3" — bump to v0.16. Fix both, lock v0.5, then write the kickoff against the locked spec. (Batch 1's primitive doesn't depend on the S5 content, but lock the spec first.)

Process norms: verify every claim against the repo at HEAD dfd0ebe — several older docs are superseded (IV_POS_8_D2_PLAN.md carries a SUPERSEDED banner; use New_Master.md for sequencing). Don't trust a doc's numbers/citations without a code check.

Deliverable: D2C_BATCH1_COMPOSER_KICKOFF.md — covering the Batch 1 task list (1.1–1.10 from spec §11), per-task file targets + exact APIs, the test layers (mock / outcome-mapping unit / real-binary smoke [gating] / V5 golden-trace), the acceptance gates, and an explicit "Composer: read these files first" list. End with the report-back expectation (D2C_BATCH1_COMPOSER_REPORT.md).

---
If you'd like, I can save this as a4/docs/cloud2/composer/D2C_BATCH1_OPUS_ONBOARDING.md so you just point the new conversation at one file ("read this, then proceed") instead of pasting the whole thing — and so it's reusable for the next batch's fresh session. Want me to write it?