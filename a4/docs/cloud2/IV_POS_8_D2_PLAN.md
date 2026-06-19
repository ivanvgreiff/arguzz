# IV.POS.8 D2 (Hybrid V7) — Implementation Plan

**Branch:** `cloud2`
**Date opened:** 2026-06-16
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Status:** **DRAFT v0.15** — D2.B **CLOSED**. §9c postscript (D2.B-PS-1) landed: 5 W-17/W-18 dead kinds removed from `A4Fuzzer.MUTATION_KINDS`, dead-kind registration guard inverted in `test_d2b_arm_registration.py`. Batch 4 at `2e1d97b`; mechanism report + audits at HEAD. **Next:** Pro check-in materials, then D2.C kickoff.
**Parent:** [`IV_POS_8_PRELIMINARY_PLAN.md`](./IV_POS_8_PRELIMINARY_PLAN.md) — the 4-deliverable master plan
**Sibling specs (D1):** [`IV_POS_8_D1_A_SPEC.md`](./IV_POS_8_D1_A_SPEC.md) (locked, running on POS)
**Sibling specs (D2):** [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) (D2.A — foundation; in review)

## Changelog

- **v0.15 (2026-06-19, D2.B-PS-1 postscript):** D2.B **CLOSED**. Removed 5 dead kinds (`CYCLE_MODE_MOD`, `TXN_ADDR_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`, `CYCLE_STATE_MOD`) from `A4Fuzzer.MUTATION_KINDS` per W-17/W-18 audits. Inverted `test_dead_kinds_excluded_from_registry` guard. Added explanatory comment block above `MUTATION_KINDS` with W-17/W-18 mechanism references. Per-kind Python modules + Rust handlers + attestation/unit tests for the 5 excluded kinds remain on disk as regression sentinels (per §9c design). §9c status: **Done.** Next: Pro check-in materials, then D2.C kickoff.
- **v0.14 (2026-06-19, D2.B Batch 4):** D2.B marked **FEATURE-COMPLETE (postscript pending)**. Delivered `test_d2b_arm_registration.py`, `test_d2b_campaign_smoke.py`, `test_d2b_real_binary_campaign.py`, POS manifest `a4/pos/manifests/iv_pos_8/d2b_smoke.json`. §9c postscript **Status: Pending — triggered by Batch 4 commit.** W-17b ready for Opus execution. Pro-facing mechanism reference: [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md).
- **v0.13 (2026-06-18, post Batch 3 txn dead-arm audit):** **W-18** execution-derived witness-key dead-arm class for B.4/B.5; §6d empirical column populated; §9c postscript scope expanded to 5 dead kinds (B.3–B.7). v0.12: W-17b, §9c postscript.
- **v0.11 (2026-06-18, post D2.B Batch 2 dead-arm audit):** Batch 2 attestation confirms B.3 `CYCLE_MODE_MOD` is a **W-17 dead arm** on sha2-host user-instruction cycles (trace mutates; witness column preset from `set_cycle` overwritten by `step_Top`'s `exec_Reg(inst_result.new*, ...)`). **B.6 `CYCLE_PC_MOD` and B.7 `CYCLE_STATE_MOD` are predicted dead on the same mechanism** — Batch 3 attestation MUST treat live rejection as an audit failure requiring reconciliation with [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md). Added **W-17** to §9a; new **§6d** prediction table; §6c S3 extended with Layer 3b witness-persistence note; §9b clarifies guard fires for dead arms too (investigation distinguishes W-16 vs W-17). Full proof: [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md) + [`D2B_BATCH2_COMPOSER_REPORT.md`](./composer/D2B_BATCH2_COMPOSER_REPORT.md) §Appendix.
- **v0.9 (2026-06-17, latest):** Catch-up after D1-chat productivity burst. D1 chat landed D1.B Batch 1 + D1.C investigation (commits `71dae77`, `3a8487c`); added NFP-7 (page_class), NFP-8 (paired-test corpus), NFP-9 (D1.E reward rewire scope), and **NFP-10 (`addr` vs `byte_addr` field-priority bug)** to `IV_POS_8_NOTES_FOR_PRO.md`. **NFP-10 has been verified independently against `compressed_global_extractor.py:216` — fix is already in cloud2; field-priority tuple is now `("byte_addr","addr","address")`.** New `IV_POS_8_D1_REVISIT_PLAN.md` introduces **D1.E sub-deliverable** (V5 reward rewire + decay re-run) which **HALTS waiting for D2.B Batch 1.5e** to merge. Pro-presentation timing changed: end-of-D2.B becomes interim Pro check-in, with D2.C/D2.D/D2.E/D2.F/D2.G proceeding after Pro greenlight. Plan changes captured:
  - **§9a watchlist extended** — added W-12 (Batch 1.5e merge signal for D1.E sync), W-13 (NFP-10 revert guard for D2.B §4.7 edits), W-14 (Pro-presentation pivot to end-of-D2.B).
  - **D2.B spec v0.5 minor edits** — §4.7 gets NFP-10 awareness paragraph + `rg` sanity-check snippet; Batch 1.5e task gets explicit "commit message must contain 'Batch 1.5e' literal" instruction for D1 chat's git-log poll signal.
  - **No D2.B redesign needed.** NFP-10 affects `address_region`/`address_bucket` labeling (a different function in the same file); D2.B's `_TXN_ROLE_BY_KIND` edits are additive and independent. Layer 3/Layer 4 attestation tests don't go through `_coerce_broken_addr`. Q5 + Q6 locks unchanged.
- **v0.8 (2026-06-17):** D2.B §6 LOCKED at v0.5 after Ivan reviewed two Composer-review cycles. Key locks:
  - **Q5: Option A** (Pro-valid `MEMORY_TXN_ROLES` only; per-kind D2.G pivots on `producer_kind`) — surfaced to Pro in new doc `IV_POS_8_NOTES_FOR_PRO.md` (NFP-4) so Pro can request schema bump in IV.POS.9 if wanted.
  - **Q6: Variant-specific kind subsets** (V5_control = 8 kinds + D1.A archive reuse; V5_expanded/Hybrid/V6 = larger subsets) — surfaced as NFP-2.
  - **15 secondary recommendations** accepted as Opus/Composer aligned: broad CYCLE_MODE scope, §3 value-gen heuristics, lean-ship B.8, per-batch CI gate, snake_case, 4 batches, Rust-first with 1.0a before 1.1, pause-on-build-failure, Option A bandit wiring (Q11), exclude fetch/register helpers, hardcode CycleState, shared signature helper, A1 post-mut dump.
  - **New Batch 1.5e**: `PRE_EXEC_REG_MOD` retrofix (mirrors B.1 Option A; A4-only; does NOT touch Arguzz). Pure cleanup of a cloud1-era dead-code path where two strategies were implemented in Rust+Python but the fuzzer hardcoded `next_read`. Surfaced as NFP-6.
  - **New §9a watchlist** (W-1 through W-11) — tracks every "decide X now, revisit at Y if Z" commitment so we don't forget.
  - **New §9b soundness-bug guard** — clean-success outcomes must be cross-verified with `A4_DUMP_POST_MUT` dump before drop; if trace changed but no constraint failed and no error emitted → STOP and surface to Pro (potential soundness bug).
  - **New sibling doc**: `IV_POS_8_NOTES_FOR_PRO.md` — running architectural index for Pro (6 entries today).
- **v0.7 (2026-06-17):** Composer review of D2.B v0.3 spec incorporated. Substantive findings ALL verified against code:
  - **`inspection_data.py::get_valid_steps_for_kind`** — was missing from spec §4 file change list; without these branches, new kinds get zero arms even with Python modules and Rust handlers. Added to spec §4.4 with explicit per-kind step rules.
  - **B.1 two-strategy bandit wiring** — v0.3 claimed PRE_EXEC_REG_MOD's two strategies are separate bandit arms; verified false (`fuzzer.py:1639` hardcodes `strategy="next_read"`; `semantic_arm_universe.py:91` only probes `next_read`). Q11 rewritten with three options; recommend Option A (one kind string, RNG picks strategy per pull).
  - **`_MAJOR_FILTER_KINDS` membership** — v0.3 said "add all 8"; that set is curated (line 83 comment: "MEM_VAL_MOD has no major filter"). Only B.6 added in v0.4; B.1/B.2/B.4/B.5/B.3/B.7/B.8 follow MEM_VAL_MOD's txn-presence-filter pattern.
  - **Layer 3 dump-diff infrastructure** — v0.3 implicitly assumed `A4_INSPECT=1 + A4_MUTATION_CONFIG` would yield a post-mutation dump; in witgen/mod.rs the inspection block runs BEFORE the mutation block (verified lines 72-187 vs 189-601), so the dump is pre-mutation only. New Q17 + Batch 1.0a task: add `A4_DUMP_POST_MUT=1` witgen hook (~30 LOC).
  - **Minor:** §3.5 citation corrected from `pre_exec_reg_mod.py:486` to `witgen/mod.rs:486` (Rust file). Q3 (B.8 fate) revised from "lean drop" to "lean ship" — `preflight.rs:227,306` actively populate diff_count. B.7 §5.3 strict-no-cascade softened to "tentatively strict; investigate state-transition witness-layout interaction in Batch 1.0b".
  - **Plan body cleanup:** lines 110, 196, 241-258 still showed "3 kinds"; updated to 8 (3 high-priority + 5 medium-risk per Pro §8 + §15.3). Provenance framing clarified: the 5 medium-risk are *Pro's named candidates*, not pure taxonomy fills.
  - D2.B effort estimate unchanged (10–14 d); spec is sharper, not larger.
- **v0.6 (2026-06-17):** D2.B deep-research pass per Ivan instruction:
  - Read `a4/docs/standalone/MUTATION_TAXONOMY.md` (the authoritative reference for A4 mutations) end-to-end + sampled existing A4 mutation modules (`comp_out_mod.py`, `pre_exec_reg_mod.py`, `instr_word_mod_sur.py`).
  - Documented **where the mutations live in the risc0 proving pipeline**: between `Segment::preflight(rand_z)` (which produces `PreflightTrace`) and `WitnessGenerator::new(preflight_results)` (which builds witness columns). The A4 mutation dispatcher modifies `trace.cycles[]` or `trace.txns[]` IN PLACE; downstream witness generation reads the mutated trace as if genuine.
  - Per-kind designs in spec v0.3 §3 grounded in: (a) field semantic from `RawPreflightCycle` / `RawMemoryTransaction` structs, (b) constraint surface implications, (c) parallel patterns from existing mutations.
  - Key architectural finding: **B.1 (TXN_PREV_WORD_MOD) should ship with two strategies** mirroring PRE_EXEC_REG_MOD's `at_read`/`at_write` pattern, because mutating `prev_word` at a READ triggers IsRead failure while mutating at a WRITE triggers MemoryWrite cascade — genuinely different constraint surfaces.
  - Corrected v0.2 inaccuracies (spec v0.3 Appendix A): `diff_count` is `[u32; 2]` not single u32; B.1 has no `prev_cycle != 0` filter; B.3 scope is "any cycle" (broad, not restrictive); B.4 explicitly HIGH RISK with fetch + register exclusions; `txn.cycle` LSB-only semantics for B.5; B.6 scope is instruction cycles only.
  - Layer 3 testing methodology refined to risk-tiered strictness: strict-no-cascade for low-risk kinds (B.1 at_read, B.2, B.3); cascade-permissive-with-signature for high-risk kinds (B.4, B.5, B.6, B.7, B.8). Composer Batch 1 writes shared `assert_trace_diff_matches_signature` helper.
  - Open question count grew 10 → 16 (added Q11–Q16 from deep dive): two-strategy decision for B.1; fetch/register exclusions for B.4 and B.5; CycleState enum extraction approach; B.8 fate gating on Rust-side investigation; cascade signature spec format.
- **v0.5 (2026-06-17, late):** D2.B scope expansion + binary capability resolution:
  - **D2.B scope expanded to all 8 of Pro's A4 wish-list kinds** per Ivan instruction. Now covers high-priority (TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD) **plus** medium-risk (TXN_ADDR_MOD, TXN_CYCLE_PHASE_MOD, CYCLE_PC_MOD, CYCLE_STATE_MOD, CYCLE_DIFF_COUNT_MOD).
  - **Binary capability question resolved** by inspecting `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`. State C confirmed: zero Rust handlers exist for the 8 new D2.B kinds, but the extension pattern is mechanical (~50–80 LOC per kind) following the existing 7 handlers.
  - D2.B effort revised from 5–7 d to **10–14 d** (Rust + Python + attestation tests).
  - D2.B spec v0.1 → v0.2 with: (a) expanded 8-kind scope, (b) clear binary-capability resolution, (c) explicit 5-layer testing methodology in plain language (Layers 1–5), with Layer 4 cross-check identified as the **100%-certainty proof** for each kind, (d) §6 open questions rewritten in plain English with explicit recommendations + justifications + counterfactuals.
- **v0.4 (2026-06-17):** Post D2.A completion pass:
  - D2.A merged to `cloud2` (Batch 1 `b844e8e`, Batch 2 `7b66fb9` + report-fix `4fce664`). 510 tests green, schema migration deployed, V5 byte-identity confirmed via golden trace, applied-accounting scheduler-side ready, `mutations.outcome` column live, normalize-parity verified.
  - `v6_driver_v2.py` recovered + archived at `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (608 lines, `balanced_round_robin` + `v2.1_utf8safe`). The §2.2 driver-archaeology task in D2.C is now resolved — the driver is in tree, just not yet modernized.
  - D2.B + D2.C specs drafted in parallel (`IV_POS_8_D2_B_SPEC.md` v0.1, `IV_POS_8_D2_C_SPEC.md` v0.1) — both pending Ivan review of §6 open questions before Composer kickoff.
  - Branch convention dropped: single `cloud2` branch, direct commits, no feature branches, no PRs (Ivan v0.4 decision).
- **v0.3 (2026-06-16):** Ivan-review pass v2:
  - Ivan accepted all 11 D2.A spec §6 open-question recommendations → D2.A spec locked at v0.2 (see `IV_POS_8_D2_A_SPEC.md` §8).
  - Ivan flagged that the v0.2 plan validated the new arm fields only by D2.D/D2.E. **Mitigation locked in D2.A v0.2:** new Batch 1 scheduler-level synthetic test (`test_d2a_arm_shape_arguzz_simulation.py`) exercises all 5 fields with non-trivial values; full arm-shape correctness gated at end of D2.A.
  - Ivan emphasized that the `v6_arguzz` driver is in the repo and needs a better search. Search to-date is documented in §2.2 (negative result across cloud2/main git history, sibling repos, backup patches); elevated to an explicit D2.C task §4 with concrete next-step leads for Composer.
  - Ivan noted branch flexibility allows overwriting old code if helpful for the 2→5 tuple refactor. Opus recommendation (locked in D2.A spec §8 cross-cutting decision): **keep back-compat overload** — surface is ~5 lines, payoff is V5 RNG byte-identity + R2 V5 archive reuse (~3 h POS savings).
- **v0.2 (2026-06-16):** Ivan-review pass v1:
  - D2.0 (Pro-facing design proposal) dropped as a separate sub-deliverable. Workflow is now "opus plan → composer implementation report → review → iterate" per sub-deliverable; final Pro-facing document is assembled at the end of D2 by summarizing the accumulated plan + reports. Sub-deliverable count drops from 8 to 7.
  - "Single biggest unknown" (§2) updated with evidence: V6 R2 DBs already contain all 7 of Pro's V6 kind menu items (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`, `POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_PC_MOD`, plus `PRE_EXEC_REG_MOD`). The "binary survey spike" is collapsed from 1 day to a ~30-minute smoke check.
  - `a4/arguzz_dependent/` file map clarified (§2): only `arguzz_runner.py` and `arguzz_parser.py` are reused for D2; rest of the directory (`cli.py`, `comparison.py`, `step_mapper.py`, `mutations/`) is from the obsolete "find a matching A4 mutation for each Arguzz fault" workflow and stays untouched.
  - Normalized-loc-at-source clarified (§2 + D2.A spec): V5 DBs already normalize at write-time (via `ConstraintFailure.short_loc()` in `record_failures`). Only V6 R2 DBs ship raw `Name(zirgen/.../file.zir:line)` strings, because the V6 driver bypassed `short_loc()`. D2.A only needs a parity test for V5 + a deprecation marker on the post-hoc normalizer.

---

## 0. Context — what this document is and is not

### Why this chat exists (the fork)

Ivan forked the original IV.POS.8 chat into two parallel tracks:

| Track | What it does | Status |
|---|---|---|
| **Track-α (the "POS finish" chat)** | Watch D1.A POS Batches 3 and 4 land, collect 20 DBs, validate, build `D1A_SUBSECTION.md` + companion plots/CSVs. Then sequentially handle D1.B (CGC variant reanalysis) and D1.C (metric stack instrumentation). Bundles into `IV_POS_8_D1_REPORT_FOR_PRO.md` + notebook. | running |
| **Track-β (this chat)** | Build the **D2 (Hybrid V7) implementation and Pro-facing design proposal** in parallel, so that when Track-α finishes and Pro greenlights the D2 design, we can dispatch the D2 POS campaign **immediately** instead of waiting weeks. | starting now |

This split is the same incremental-delivery argument that justified the 4-deliverable structure in `IV_POS_8_PRELIMINARY_PLAN.md` §1 — we want to minimize idle time while Pro is reviewing D1.

### What this document is

A **master plan** for everything Track-β does. It is the analogue of `IV_POS_8_D1_A_SPEC.md` but one level up: it defines the sub-deliverables, their dependencies, the open questions, and the order Composer will work in. It is **not** itself an implementation spec — each sub-deliverable will get its own spec (D2.A_SPEC, D2.B_SPEC, …) that Composer reviews before implementing.

### What this document is not

- It is **not** the Pro-facing document. That is `IV_POS_8_D2_DESIGN_PROPOSAL.md` (= sub-deliverable D2.0 below).
- It is **not** committing Track-β to anything before Ivan reviews it. Composer does not start work from this document. Each sub-deliverable spec gets its own Ivan + Opus review.
- It does **not** revisit D1 scope. D1.B / D1.C / D1.X are owned by Track-α.

---

## 1. What D2 is (recap from preliminary plan + Pro report)

Pro's §15 Priority 1 (Hybrid V7) and Priority 3 (pure-A4 expansion) are the core of D2. Pro's words:

> A4-V5 semantic-zone scheduler + selected V6-only kinds + applied-mutation-aware accounting + normalized loc and CGC telemetry. Run V5 vs V6-uniform vs V6-cTS vs Hybrid-cTS, 10 paired seeds, N=6000.

Pro additionally specified (§8 Track B, §15 Priority 3) a pure-A4 kind expansion:

> 1. TXN_PREV_WORD_MOD  2. TXN_PREV_CYCLE_MOD  3. CYCLE_MODE_MOD  4. TXN_CYCLE_PHASE_MOD  5. CYCLE_PC_MOD

The preliminary plan §3.D recommended a **curated subset for the first D2 ship** — 4 V6 kinds + 3 A4 kinds — to keep the arm-space size manageable. Pro can expand on review.

### Arm shape Pro recommended

```
arm = (mutation_surface, mutation_kind, semantic_zone, opcode_class, pre/post)
where mutation_surface ∈ {A4_trace_cell, arguzz_exec_fault}
```

### Variants to compare (4)

| Variant | Surface | Scheduler | Notes |
|---|---|---|---|
| **V5** (control) | `A4_trace_cell` only (current 8 kinds) | V5 cTS_semantic_v2 (constant floor 0.55) | Reuse D1.A static archive |
| **V6-uniform** | `arguzz_exec_fault` only | Arguzz native (uniform over applicable) | Current `a4.arguzz_dependent.cli` path, kept honest |
| **V6-cTS** | `arguzz_exec_fault` only | V5 scheduler over Arguzz kinds | Tests "does cTS help Arguzz?" |
| **Hybrid-cTS** | both surfaces | V5 scheduler over union arm-space | The headline architecture |

### Compute (target, paired)

- 10 paired seeds × 4 variants × N=6000 = **40 jobs**, ~12 h wall on 8 POS nodes (sequential across ~2–3 reservations).
- V5 reuse from D1.A archive cuts this to **30 new jobs** (~9 h wall).

---

## 2. What the codebase already gives us (grounded, not guessed)

| Asset | Path | Reuse plan in D2 |
|---|---|---|
| V5 cTS semantic-zone scheduler | `a4/standalone/bandit_ts.py` (`ConstrainedTSScheduler`, `FloorSchedule` family from D1.A) | Carries directly into V6-cTS and Hybrid-cTS |
| V5 standalone fuzzer | `a4/standalone/fuzzer.py` | Refactored to dispatch by arm-shape, not hardcoded kind ifs |
| 8 pure-A4 mutation kinds | `a4/standalone/mutations/{comp_out_mod, instr_type_mod, instr_word_mod, instr_word_mod_sur, load_val_mod, mem_val_mod, pre_exec_reg_mod, store_out_mod}.py` | Stay as-is; D2.B adds 8 new ones (3 high-priority + 5 medium-risk per Pro §8 + §15.3) using the same pattern |
| Arguzz subprocess runner | `a4/arguzz_dependent/arguzz_runner.py` (115 lines, clean) | **REUSED** in D2.C as the subprocess primitive for V6-cTS / Hybrid-cTS Arguzz-arm dispatch |
| Arguzz `<fault>` / `<trace>` parser | `a4/arguzz_dependent/arguzz_parser.py` (180 lines, already covers `INSTR_WORD_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`, `PRE_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`, `POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, and a generic `unknown` fallback for `BR_NEG_COND` / `POST_EXEC_PC_MOD`) | **REUSED** in D2.C; we may extend the parser with explicit `BR_NEG_COND` / `POST_EXEC_PC_MOD` info formats once we see what the binary emits |
| ~~`a4/arguzz_dependent/cli.py`~~ | obsolete | Old "find a matching A4 mutation for each Arguzz fault" comparison harness. **NOT used by D2.** Stays untouched. |
| ~~`a4/arguzz_dependent/mutations/*`~~ | obsolete | A4 mutation wrappers paired with Arguzz faults for the comparison workflow above. **NOT used by D2.** |
| ~~`a4/arguzz_dependent/step_mapper.py`, `comparison.py`~~ | obsolete | Supporting modules for the obsolete comparison workflow. **NOT used by D2.** |
| Normalized loc map | `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py` (analysis-time normalizer) | **No write-time work in D2.A.** V5 DBs already normalize at write-time via `ConstraintFailure.short_loc()` (verified — see §2.1). The post-hoc normalizer stays as a compat shim for legacy R2 V6 DBs only. |
| Coverage DB schema | `a4/standalone/coverage_db.py` (post-D1.A: now has `proof_generated`, `proof_verify_failed`, `elapsed_ms` columns) | Reused; D2.A adds one more nullable column `mutations.outcome` (`APPLIED` / `SKIPPED` / `ERROR`) |
| POS dispatch playbook | `a4/docs/precloud/POS_PLAYBOOK.md` + `dispatch_pos.py` + `collect_results_pos.py` + `prepare_bundle.sh` | Identical workflow to D1.A — no infra changes |

### 2.1 Resolved: the "single biggest unknown" — V6 binary kind coverage

The v0.1 draft flagged "Arguzz binary's true kind coverage" as the load-bearing unknown for D2.C. **Empirically resolved 2026-06-16 by inspecting an existing R2 V6 DB** (`a4/runs/iv_pos_7/dbs/pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000/`). `SELECT DISTINCT kind FROM mutations` returns:

```
PRE_EXEC_MEM_MOD      ← Pro priority 2 ✓
POST_EXEC_REG_MOD     ← Pro priority 5 ✓
INSTR_WORD_MOD        ← Pro priority 1 ✓
PRE_EXEC_REG_MOD      ✓
POST_EXEC_PC_MOD      ← Pro priority 7 ✓
POST_EXEC_MEM_MOD     ← Pro priority 6 ✓
BR_NEG_COND           ← Pro priority 4 ✓
LOAD_VAL_MOD          ✓
PRE_EXEC_PC_MOD       ← Pro priority 3 ✓
STORE_OUT_MOD         ✓
COMP_OUT_MOD          ✓
```

**All seven of Pro's §15 Priority 1 V6 kinds are already emitted by the Arguzz binary** (the 4 the curated D2 v1 needs, plus the 3 others Pro listed as expansion candidates). The previous concern that D2.C might need a Rust-side binary extension is closed.

What this changes for the plan:
- D2.C's "binary survey spike" collapses from "~1 day" to a ~30-minute smoke check (one `subprocess.run` per kind, confirm `<fault>` round-trips).
- D2.C's effort estimate drops from 5–10 days to **3–5 days** (just wrapping + applied-accounting + arm-shape integration).
- We no longer need the §5 Q6 "expand to 7+5 later" caveat for V6 capacity reasons; capacity is already in the binary. Curation (4+3 in v1 vs 7+5) is now a pure scope-management call, not a capability gate.

### 2.2 The `v6_arguzz` driver — search trail and elevation to D2.C task

**Status:** **NOT YET LOCATED**. Ivan (2026-06-16) flagged that the driver "is certainly in this repo and requires better searching" — we agree the search to-date was insufficient; documenting the negative result here so Composer can pick up the trail in D2.C.

**Signatures we know the driver has** (from R2 V6 DB `campaigns` / `campaign_params` rows):

| Field | Value |
|---|---|
| `campaigns.kind` | `"v6_arguzz"` |
| `campaign_params.selector` | `"arguzz"` |
| `campaign_params.extra_json.scheduler` | `"balanced_round_robin"` |
| `campaign_params.extra_json.driver_version` | `"v2.1_utf8safe"` |
| `campaign_params.extra_json.num` | `6000` |
| `campaign_params.extra_json.compressed_extractor` | `"a4.compressed_global_extractor"` (Python module reference — the driver IS Python and imports our `a4` package) |
| `campaigns.host_binary` | `/root/a4_campaign/bin/risc0-host` (same binary V5 uses; the driver loops `subprocess.run(risc0-host, ...)`) |

**Searches already performed (all negative):**

| Search | Result |
|---|---|
| `git log --all -S "v6_arguzz"` and `git log --all -S "balanced_round_robin"` | 0 commits, across `cloud2` + `main` + their remote refs |
| `git log --all -S "v2.1_utf8safe"` | 0 commits |
| `git log --all --diff-filter=AM --name-only` filtered for `v6.*driver` / `arguzz.*driver` | 0 matches (only analysis files in `a4/runs/iv_pos_7/`) |
| `git ls-tree -r {cloud2,main}` filtered for `v6` / `arguzz` | only `a4/arguzz_dependent/*` (already mapped — irrelevant) and `a4/runs/iv_pos_7/*` analysis |
| `rg "v6_arguzz\|balanced_round_robin"` against `/root/zk-fuzz-lab`, `/root/raw-zk-fuzz-lab`, `/root/zkVMs`, `/root/arguzz_backups` | 0 hits |
| `grep` over `arguzz_backups/*.patch` | 0 hits |

**Leads for D2.C (Composer to investigate):**

1. **`workspace/risc0-modified/`** — there is a small possibility the Rust host binary writes campaign/`bandit_decisions` rows directly when run in a "v6 driver mode" via an `--driver=balanced_round_robin` CLI flag. Search `workspace/risc0-modified/` for `coverage_db`, `INSERT INTO campaigns`, `balanced_round_robin` literal in Rust files. Our search timed out on this dir; Composer should use a more targeted glob (e.g., only `src/main.rs`, `host/**.rs`).
2. **POS management node history** — the R2 V6 campaign was dispatched from POS in early Q-G 2026 (Apr–May). The driver may be a transient script that lives only in the POS user's home directory and was never committed back. Run `git reflog --all`, `git stash list`, and check `git fsck --lost-found` on this repo. If still nothing, ask Ivan whether to ssh to the POS management node and snapshot `~/scripts/` or similar.
3. **`a4/cloud/` historical paths** — the V6 driver might have lived in `a4/cloud/` (referenced by `a4/standalone/dispatch_pos.py` as "Replaces the GCP `a4/cloud/dispatch.py`"). Search `git log --all -- 'a4/cloud/*'`. Files there were likely deleted in the GCP→POS migration but may still be in tree history.
4. **`arguzz_backups/pre_recovery_*` + `arguzz_backups/filesystem_snapshots`** — Ivan's recovery snapshots. Composer should `tar tzf` or `ls -R` these directories looking for Python files matching `*v6*` or `*arguzz*driver*`.

**If still not found after the above:** D2.C builds a thin Python equivalent driver (~150 lines), using:
- `arguzz_runner.run_arguzz_mutation()` as the subprocess primitive (already in tree, 115 lines, clean)
- `arguzz_parser.parse_fault()` and `parse_trace()` for output parsing
- `a4.standalone.coverage_db.A4CoverageDB.record_mutation` for DB writes (this guarantees normalized-loc + applied-accounting via the same `record_failures` path)
- `balanced_round_robin` scheduling is trivial: round-robin over the 11 inventoried V6 kinds

Either way, **D2.C ships a Python `v6_arguzz` driver** — the question is whether we recover the original or build a new one. The new one is preferred from a maintenance standpoint anyway (it auto-uses D2.A's `outcome` column + normalized loc, which the original bypassed).

---

## 3. Sub-deliverable breakdown

D2 is split into **seven sub-deliverables**. The diagram below shows dependencies; the table after gives names and brief scope. (D2.0 from v0.1 — a separate Pro-facing design proposal — is dropped per Ivan v0.2 review: documentation accumulates per sub-deliverable as "opus plan + composer report + review", and the Pro-facing document is assembled by summarizing those at the end of D2.)

```
D2.A (foundation: arm-shape refactor + applied accounting + normalized telemetry)
       │
       ├─────▶ D2.B (pure-A4 kind expansion — 8 kinds: 3 high + 5 medium)
       │
       ├─────▶ D2.C (V6 integration — Arguzz binding via arguzz_runner)
       │              │
       │              ▼
       └─────▶ D2.D (variant CLI/fuzzer dispatch — 4 variants)
                       │
                       ▼
                D2.E (integration tests + golden traces + tiny smoke)
                       │
                       ▼
                D2.F (POS dispatch — 40 jobs / 30 new + V5 archive reuse)
                       │
                       ▼
                D2.G (analysis + final D2 Pro-facing report + notebook + D3 sketch)
```

### Summary table

| ID | Title | Output (code-side) | Output (doc-side) | Depends on | Status / Effort |
|---|---|---|---|---|---|
| **D2.A** | Foundation: arm-shape + applied accounting + normalized-telemetry verification | `bandit_ts.py`, `semantic_arm_universe.py`, `fuzzer.py`, `coverage_db.py` patches | [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) v0.2 LOCKED | D1.A merged | **DONE** (Batch 1 + 2 merged at `7b66fb9`, 510 tests green) |
| **D2.B** | Pure-A4 kind expansion — **8 kinds from Pro's bullet list** (3 LIVE: B.1, B.2, B.8; 5 dead-arm excluded per W-17/W-18: B.3–B.7, sentinel tests retained) | 8 Rust handlers in `witgen/mod.rs` + 8 Python modules + `inspection_data.py::get_valid_steps_for_kind` branches + Layer 3 dump-post-mut hook + risk-tiered attestation tests + Batch 4 cross-cutting/smoke tests + §9c postscript | [`IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) v0.5.4 LOCKED; mechanism report [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md) | D2.A landed | **CLOSED** (Batch 4 at `2e1d97b`, postscript at v0.15) |
| **D2.C** | V6 integration via Arguzz subprocess primitive + bridge + modernized v6_driver | `arguzz_invoke.py` + `mutations/arguzz_bridge.py` + `v6_uniform_driver.py` (modernized v6_driver_v2.py) | [`IV_POS_8_D2_C_SPEC.md`](./IV_POS_8_D2_C_SPEC.md) v0.1 DRAFT | D2.A landed | 3–5 d (binary capacity confirmed — see §2.1 + driver recovered) |
| **D2.D** | Variant CLI/fuzzer dispatch (4 variants) | `cli.py`, `fuzzer.py` patches; new `--selector` family extensions | `IV_POS_8_D2_D_SPEC.md` | D2.A+D2.B+D2.C landed | 2–3 d |
| **D2.E** | Integration tests + golden traces + tiny smoke | `tests/test_d2_*.py`, optional `analysis/d2_smoke_check.py` | `IV_POS_8_D2_E_SPEC.md` | D2.D landed | 3–4 d |
| **D2.F** | POS dispatch (30 new jobs + V5 archive reuse) | `a4/pos/manifests/iv_pos_8/d2_b{1,2,3}.json`; kickoff docs | section in master plan; Composer kickoff doc | D2.E green | 12–18 h POS wall + 1 d setup |
| **D2.G** | Analysis + Pro-facing report (summarized from accumulated plan/reports) + D3 sketch | `analysis/build_d2_artifacts.py`, plots, CSVs | `IV_POS_8_D2_REPORT_FOR_PRO.md`, `IV_POS_8_D2_NOTEBOOK.ipynb`, `IV_POS_8_D3_DESIGN_PROPOSAL.md` | D2.F DBs collected | 5–7 d |

**Total wall-clock estimate (this chat's portion before POS):** ~3–5 weeks of focused work, matching the original "5–7 weeks after D1 sign-off" target in `IV_POS_8_PRELIMINARY_PLAN.md` §2. D2.C's drop from 5–10 d to 3–5 d (capacity-confirmed per §2.1) shaves ~3–5 d off the top end.

---

## 4. Sub-deliverable scopes (one paragraph each — full specs come later)

### D2.A — Foundation: arm-shape refactor + applied-mutation accounting + normalized-telemetry verification

The single most important sub-deliverable, because everything else layers on it. Three changes:

1. **Arm-shape abstraction in `bandit_ts.py`.** Replace the current `(mutation_kind, semantic_zone)` arm tuple with the 5-tuple `(mutation_surface, mutation_kind, semantic_zone, opcode_class, pre_post)`. `mutation_surface` ∈ `{"A4_trace_cell", "arguzz_exec_fault"}`. Back-compat is mandatory: V5 cTS_semantic_v2 with surface fixed to `A4_trace_cell` and pre_post collapsed must produce the **identical** decision sequence under a fixed RNG seed (golden trace test).
2. **Applied-mutation accounting.** Pro flagged this explicitly (§8): "The scheduler must count only **applied** Arguzz mutations as pulls." For A4 kinds this is a no-op (all A4 mutations apply). For Arguzz kinds with skip rate ~21%, this means: when the arm is pulled and Arguzz returns "no-op / not applicable," the scheduler must (a) not credit a pull, (b) re-pick. Implementation: introduce a `MutationOutcome` enum `{APPLIED, SKIPPED, ERROR}`; only `APPLIED` advances scheduler state. Schema: one new nullable column `mutations.outcome TEXT` (forward-compatible like D1.A).
3. **Normalized loc + CGC telemetry at source.** Currently we normalize loc strings post-hoc via the Q-G driver (`a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py`). Pro wants normalization **inline**, written directly to the DB during fuzzing. Migrate `short_loc()` and CGC computation into the fuzzer's `record_mutation` path so the DB ships with `mutations.normalized_loc` and `mutations.compressed_global_context` populated. (Open question — see §5.)

**Tests:** golden-trace identity for V5 under new arm-shape, applied-vs-attempted unit test on a synthetic mock surface, normalized-loc parity test against existing Q-G output on R2 V5 DBs.

### D2.B — Pure-A4 kind expansion (8 kinds total)

**Per [`IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) v0.3+** — eight new mutation kinds in `a4/standalone/mutations/`, each modeled on the existing pattern (cf. `instr_word_mod_sur.py`, `pre_exec_reg_mod.py`). Each kind gets a Rust handler in `witgen/mod.rs`, a Python module, registry plumbing (`semantic_arm_universe.py`, `fuzzer.py`, and **`inspection_data.py::get_valid_steps_for_kind`** — added in v0.4 per Composer review), and risk-tiered attestation tests.

**Provenance of the 8 kinds:**
- **3 priority-ordered by Pro** (ProG_Report_3.md §15.3): `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`
- **5 "medium-risk candidates" Pro listed** (§8): `TXN_ADDR_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`, `CYCLE_STATE_MOD`, `CYCLE_DIFF_COUNT_MOD`

These 8 are the union of Pro's bullet list — the second 5 are *Pro's named candidates*, not pure taxonomy fills.

| Priority | Kind | Targeted field | Risk |
|---|---|---|---|
| **High** | `TXN_PREV_WORD_MOD` | `txns[i].prev_word` (two strategies: at_read / at_write) | Low |
| **High** | `TXN_PREV_CYCLE_MOD` | `txns[i].prev_cycle` | Low |
| **High** | `CYCLE_MODE_MOD` | `cycles[i].machine_mode` | Low |
| **Medium** | `TXN_ADDR_MOD` | `txns[i].addr` | HIGH (mitigated by `FAULT_INJECTION_ENABLED`) |
| **Medium** | `TXN_CYCLE_PHASE_MOD` | `txns[i].cycle` LSB only | Medium |
| **Medium** | `CYCLE_PC_MOD` | `cycles[i].pc` (major 0-6 only) | Medium |
| **Medium** | `CYCLE_STATE_MOD` | `cycles[i].state` | Medium |
| **Medium** | `CYCLE_DIFF_COUNT_MOD` | `cycles[i].diff_count[idx]` (array, one element at a time) | Medium |

Pro's wider §8 catalog (`CYCLE_INDEX_MOD`, `REG_TXN_NON_INSN_MOD`, `BIGINT_DATA_MOD`, `CRYPTO_STATE_MOD`, `ECALL_BACK_MOD`, `STRUCTURAL_MOD`) is **deferred to a future IV.POS cycle** per Pro §15 last paragraph ("delay high-risk structural/accelerator-internal mutations").

### D2.C — V6 kind integration via `arguzz_runner` bridge

Four layers, in order:

0. **Driver archaeology (Composer spike, ≤2 h).** Locate the original `v6_arguzz` driver per §2.2 leads (`workspace/risc0-modified/`, `a4/cloud/` git history, `arguzz_backups/`, reflog/stash/fsck). If found, snapshot it and decide whether to revive-and-modify or replace. If not found after ≤2 h, proceed to layer 2 (build new). **This is the elevated explicit task per Ivan 2026-06-16.**
1. **Binary survey (Composer spike, ~30 min).** Empirically confirmed in §2.1 — all 7 of Pro's V6 kinds are emitted by the current binary. The "survey" is now a quick smoke-check confirming the binary at `bin/risc0-host` still works the same way (one `subprocess.run` per kind, confirm `<fault>` round-trips through `arguzz_parser`). Significantly cheaper than the v0.1 1-day estimate.
2. **Bridge module** (`a4/standalone/mutations/arguzz_bridge.py`). Wraps `arguzz_runner.run_arguzz_mutation(...)` in the same interface as the pure-A4 mutators expose (`find_mutation_target / create_config / dispatch`). Internal implementation: shell to Arguzz binary, parse stdout via `arguzz_parser`, lift to the scheduler's `MutationOutcome`. **Crucially: writes its `record_mutation` calls through `A4CoverageDB`, so normalized-loc + applied-accounting + `outcome` column all work automatically** (no bypassing of `short_loc()` like the R2 V6 driver did).
3. **Wiring** four V6 kinds into the union arm-space: `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`. Per §2.1 the binary supports all four (and 3 more for future expansion). Each kind gets:
   - A coupling from D2.A's `ArmKey(surface="arguzz_exec_fault", kind=<kind>, zone=<from parser>, opcode_class=<derived>, pre_post=<derived>)`
   - A `pre_post` classification (per D2.A §1.1: `PRE_EXEC_*` → `pre_exec`, `POST_EXEC_*` → `post_exec`, `INSTR_WORD_MOD` and `BR_NEG_COND` → `pre_exec` provisionally)
   - An `opcode_class` derivation from the cycle's major at the fault step (via `semantic_zones.major_to_opcode_class()`)

**Tests:** mock the Arguzz subprocess in unit tests (we already have parser fixtures); integration test runs one real Arguzz invocation per kind on a known input; parity test asserts D2.C's DB outputs are equivalent to a sampled R2 V6 DB (with normalized-loc + `outcome` column being the only differences).

**Cross-cutting note from D2.B (added 2026-06-17):** D2.B Q11 locks an **intra-pull strategy-selection pattern** for B.1 `TXN_PREV_WORD_MOD` — single `MUTATION_KINDS` entry, RNG-picked `at_read`/`at_write` strategy per pull, strategy stored in config JSON for reproducibility. If any of D2.C's 4 Arguzz kinds turn out to have analogous "two-mode" structure (e.g. `INSTR_WORD_MOD` Arguzz fault might support both opcode-substitution and field-corruption strategies depending on Arguzz binary internals), **D2.C's spec should reuse the same Option-A pattern** rather than introducing a separate plumbing convention. To check: when D2.C's binary survey (layer 1) catalogs the `<fault>` tag's strategy field per kind, note any kind with multiple strategy values and decide per-kind whether to expose them as RNG-picked sub-strategies. **Decision deferred to D2.C spec drafting; not a D2.B blocker.**

### D2.D — Variant CLI/fuzzer dispatch (4 variants)

Add `--variant` (or `--selector` family extension) to `a4/standalone/cli.py`, mapping to the four variants:

| Variant | `--selector` flag | Surfaces active | Floor schedule |
|---|---|---|---|
| V5 | `cTS_semantic_v2` (existing) | A4_trace_cell only | constant 0.55 (existing) |
| V6-uniform | `v6_uniform` (new) | arguzz_exec_fault only | n/a (uniform over applicable) |
| V6-cTS | `v6_cTS` (new) | arguzz_exec_fault only | constant 0.55 (V5 schedule reused) |
| Hybrid-cTS | `hybrid_cTS` (new) | both | constant 0.55 (V5 schedule reused) |

Each variant gets a `STRATEGY_DISPLAY_NAMES` entry and a `_floor_schedule_for_strategy(...)` branch (mirrors the D1.A pattern). The "selector → arm-shape filter" mapping is one new helper. We deliberately keep D2 floor-schedule = constant 0.55 across all variants for v1 — Pro hasn't asked for decay in Hybrid yet. If D1.A decay wins, we add a decay variant in a D2 follow-up.

### D2.E — Integration tests + golden traces + tiny smoke

The "we know what we built is doing what we think it's doing" sub-deliverable. Five layers:

1. **Golden-trace identity test.** Same RNG seed, run V5 selector pre- and post-D2.A; assert identical decision sequence + identical DB row count + identical `local_context_final`. Already required by D2.A, repeated here as a regression catcher.
2. **Arm-space coverage assertion.** For each variant, run N=20 mutations with `--seed 42` and assert the `arm_history` includes only arms allowed by the variant (e.g., Hybrid-cTS arm history must contain ≥1 arm with `surface=arguzz_exec_fault` AND ≥1 with `surface=A4_trace_cell`).
3. **Applied-accounting smoke.** For V6-cTS, run N=40 mutations and assert `COUNT(mutations WHERE outcome="APPLIED") < N` (skip rate > 0) but the scheduler's `total_pulls` matches the applied count. Catches the "Pro's pulls=applied" requirement in code, not just spec.
4. **Normalized-loc parity.** Run V5 selector under D2 fuzzer for N=40, dump normalized loc strings, compare against running the Q-G driver on the same DB post-hoc. ≥99% agreement (small residual from Q-G normalizer being stable but not bit-identical to inline implementation; deviations are inspected once).
5. **POS-style tiny smoke (optional).** N=200 per variant on POS (~30 min per variant on 1 node, 4 variants on 4 nodes in parallel = ~30 min wall). Same rationale as D1.A Batch 3 smoke-gate. **Skip** if §4 layers 1–4 pass and we trust the architecture; **run** if §4 reveals any flakiness.

### D2.F — POS dispatch

Three batches:

- **D2.F.1 (smoke-gate, 8 jobs):** 2 paired seeds × 4 variants on 8 nodes. ~5.5 h wall on Tier-A limit. Mirrors D1.A Batch 3 design. Pass criterion: all 8 DBs structurally identical, arm-shape coverage assertion holds, applied-accounting smoke as in D2.E layer 3.
- **D2.F.2 (production tail, ~22 jobs):** 8 paired seeds × 4 variants − 8 already in F.1 − 10 V5 jobs reusable from D1.A static archive = 22 new jobs. On 8 nodes that's ~3 sequential dispatches (~16 h wall). **Or** 24 new jobs if we don't reuse V5 archive (decision in §5 Q3).
- **Reservations:** 3 contiguous 6 h calendar entries (mirroring D1.A pattern).

Total D2 POS compute: **~22–32 h wall** depending on V5 archive reuse, on 8 Tier-A/S nodes.

### D2.G — Analysis + Pro-facing report

Mirrors D1.G in spirit:

- `analysis/build_d2_artifacts.py` — single script that ingests 30–40 DBs, writes per-variant CSVs and the headline comparison table (V5 vs V6-uniform vs V6-cTS vs Hybrid-cTS on all D1.C Category A metrics + normalized-territory split per V6 companion §3). D2.G's `build_d2_artifacts.py` consumes columns prefixed `cat_a_pro_s*` from `d1c_metrics_table.csv` per `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md`.
- `IV_POS_8_D2_REPORT_FOR_PRO.md` — Pro-facing narrative. Structure: TL;DR / methodology / per-variant numbers / answers-to-Pro's-§15-Priority-1 question / open questions for D3 design.
- `IV_POS_8_D2_NOTEBOOK.ipynb` — companion plots / interactive exploration.
- `IV_POS_8_D3_DESIGN_PROPOSAL.md` — what D2 ships to Pro alongside the report (mirroring the D1+D2-design pattern). Sketches bug-isolation layer scope. Track-β owns drafting this once D2.G is largely done; Track-α may pre-feed bug-proximity findings from D1.C.

---

## 5. Open questions for Ivan (must answer before Composer touches anything)

These mirror the "open questions" pattern from `IV_POS_8_D1_A_SPEC.md` §8. None of them have defensible default answers from me alone — they all involve a strategy choice.

| # | Question | My recommendation | Why I'm not just defaulting |
|---|---|---|---|
| **Q1** | **Arm-shape: do we collapse `opcode_class` and `pre_post` when surface=A4_trace_cell?** A4 trace-cell mutations don't have a natural pre/post split. Three options: (a) leave them as `(A4_trace_cell, kind, zone, "n/a", "n/a")` arms — keeps arm count down, breaks symmetry; (b) split A4 kinds into pre/post pairs synthetically — symmetric but possibly meaningless; (c) leave A4 unsplit and only Arguzz arms get the full 5-tuple — explicit asymmetry. | **(a)** Use "n/a" sentinel for fields that don't apply to a surface. Keeps reasoning simple, doesn't fabricate distinctions. Pro can request (b) if symmetric arm-space is important. | (b) inflates arm space ×2 with no semantic basis; (c) is hard to reason about in metrics. |
| **Q2** | **Where does normalized loc live?** (a) compute inline in fuzzer at `record_failures` time → DB ships normalized; (b) keep Q-G driver post-hoc → DB ships raw, normalize at analysis time. | **(a)** Inline. Matches Pro's §15 "normalized loc and CGC telemetry" ask and kills Q-G overhead for D2 onward. Risk: inline implementation drift from Q-G driver — mitigated by D2.E layer 4 parity test. | (b) is the smaller-change path but defers a Pro-explicit ask, which we'd then have to do later. Better to do it now. |
| **Q3** | **V5 archive reuse for D2 comparisons.** Reuse D1.A V5-static DBs (10 seeds, sealed) OR re-run V5 under the new D2 fuzzer? | **Reuse if D2.A back-compat tests pass.** Saves 10 jobs (~3 h wall). Justification mirrors D1.A Q14 — back-compat by construction + golden-trace test. **If D2.A back-compat fails** for any reason, fall back to fresh V5 run inside D2. | The added compute is small (~3 h on 8 nodes), but reuse is the cleaner story for Pro (paired analysis vs same baseline). |
| **Q4** | **V6-uniform — re-run, or accept R2 V6 archive?** R2 has 10 seeds of V6-uniform at N=6000 already in `a4/runs/iv_pos_7/dbs/`. | **Reuse R2 V6 archive.** Same logic as Q3 — saves 10 jobs. **Only re-run** if D2 introduces a new fairness control we couldn't have applied retroactively (e.g., normalized-loc-at-source — but that's an analysis-time alignment, not a re-run reason). | Honest accounting: the R2 V6 archive was produced under `a4/arguzz_dependent/cli.py` not the D2 fuzzer, so the DB schema and code path will differ. If we reuse, we MUST document this fairly in D2.G. |
| **Q5** | **Compute target: still N=6000?** Pro explicitly said "Use 10 paired seeds, N=6000 first." | **Yes, N=6000 in v1.** Defer "longer N for Hybrid" to a possible v2 if Pro signals interest. | We have no signal from Pro that N=6000 was an under-shoot; staying with Pro's number is the conservative choice. |
| **Q6** | **Kind menu sizing.** Preliminary plan recommended 4 V6 + 3 A4 = 7 kinds. Pro listed 7 V6 + 5 A4 = 12 total. | **Curated 4+3 in v1; expandable.** Reasons: (a) arm-space size: 4 V6 kinds × 5 zones × 4 opcode_class × 2 pre/post = 160 Arguzz arms alone, already large; (b) D2 turnaround value: faster ship enables Pro course-correction; (c) Pro explicitly said "selectively adopt" not "all." Document a clean upgrade path in D2.0 so Pro can ask for 12. | This is THE biggest strategic choice in D2. Worth Pro feedback explicitly. |
| **Q7** | **V6-cTS as a separate variant, or only Hybrid-cTS?** Pro listed both, but V6-cTS is informationally a subset of Hybrid-cTS. | **Keep both as separate variants.** Pro asked for both; comparing V6-uniform → V6-cTS isolates "does cTS help Arguzz alone?" which is a different question than Hybrid. Cost of running V6-cTS is 10 extra jobs (~3 h). Worth it for the ablation. | Skipping V6-cTS saves compute but loses an ablation Pro explicitly named. |
| **Q8** | **CGC variant for D2 reward.** Pro asked for analysis of three (region-only / log4 / log2) in D1.B and hinted at "coarser CGC" for production. D1.B will recommend one. | **Default D2 reward to the same CGC as V5 used (= log4 — current production)** until D1.B finishes and recommends otherwise. D2 can pivot before POS dispatch. | If we wait for D1.B, D2 is gated on Track-α. Default-and-pivot keeps Track-β unblocked. |
| **Q9** | **Applied-mutation accounting — strict or loose?** Strict: `outcome=APPLIED` advances scheduler state, `SKIPPED` triggers re-pick. Loose: log outcome but still advance regardless. | **Strict.** It's what Pro literally asked for and is the only honest comparison vs V6-uniform (which also uniformly samples until applied). | Loose is easier to implement (no re-pick logic in scheduler), but it dilutes the Hybrid comparison. Pro's wording was unambiguous. |
| **Q10** | **D2 timeline target.** Track-α's D1 horizon is "2–3 weeks." D2's preliminary horizon is "5–7 weeks after D1 sign-off." | **5 weeks of focused Track-β work** ending at "D2.E green + D2.0 finalized." After that, dispatch D2.F immediately upon Pro greenlight. Track-α landings within those 5 weeks just shorten the post-greenlight wait. | We could aim shorter, but D2.C binary-survey is a real wildcard. 5 weeks lets us absorb that risk. |
| **Q11** | **D2 sub-deliverable review cadence with Pro.** Just one Pro review at end (D2.0 + D2 report bundled), or interim Pro checkpoint after D2.0 alone? | **One Pro review at the end.** D2.0 is too detailed to ship in isolation — Pro needs the D1 results context to react meaningfully. Plus interim ship inflates Pro's review load. | The R2 + V6 round established Pro likes "results + plan" bundles; D2.0 alone is just plan. |

---

## 6. Tests + verification strategy (what "doing what we think it's doing" means)

A4 has been bitten before by integration bugs that pass unit tests but produce silently wrong DBs (cf. `PRE_EXEC_REG_MOD` mis-classification, §7.2.2 pull-direction flip from R2). D2 is structurally riskier because of the arm-shape refactor + subprocess bridge. Concrete verification gates:

### Per sub-deliverable

| Gate | Sub-deliverable | What it asserts | Where it lives |
|---|---|---|---|
| Golden trace | D2.A | V5 selector pre/post arm-shape refactor produces byte-identical decisions for seed=42, N=200 | `tests/test_d2_golden_trace.py` |
| Dump diff | D2.B | Each new A4 kind mutates only the field it claims to, on 5 sample traces per kind | `tests/test_d2_pure_a4_kinds.py` |
| Arguzz binary survey | D2.C | Documented in `IV_POS_8_D2_C_SPEC.md` §1; lists every distinct `fault.kind` the binary emits | `analysis/d2_arguzz_kind_survey.py` |
| Subprocess mock | D2.C | Bridge module behaves correctly under faked Arguzz stdout (APPLIED / SKIPPED / ERROR fixtures) | `tests/test_d2_arguzz_bridge.py` |
| Variant arm coverage | D2.D | For each variant, only allowed arm-shape tuples ever appear in `arm_history` | `tests/test_d2_variant_dispatch.py` |
| Applied accounting smoke | D2.E | V6-cTS at N=40: `COUNT(outcome=APPLIED) < N` AND `scheduler.total_pulls == COUNT(outcome=APPLIED)` | `tests/test_d2_applied_accounting.py` |
| Normalized-loc parity | D2.E | Inline normalization vs Q-G post-hoc: ≥99% agreement on V5 DB | `analysis/d2_normalize_parity.py` |
| POS smoke (optional) | D2.E | If all above pass, optional 4-variant POS smoke at N=200 each | `a4/pos/manifests/iv_pos_8/d2_smoke.json` |
| End-to-end DB validator | D2.F | Each of 30 production DBs passes structural validator (mirrors D1.A `validate_d1a_dbs.py`) | `a4/runs/iv_pos_8/d2/validate_d2_dbs.py` |

### Non-POS test budget

Everything except the optional smoke runs on the WSL dev box (~3–5 min for the full new test surface). All gates are deterministic, all use fixed seeds. CI pattern: same `pytest a4/standalone/tests/` invocation we use today, with the addition of `tests/test_d2_*.py`.

### POS test budget

We aim to need only the D2.F.1 smoke-gate (8 jobs, ~5.5 h wall, doubles as production data per Q3/Q4) — no extra POS smoke. If D2.E layer 5 surfaces flakiness we add an N=200 smoke on 1 node (~30 min wall) before the gate.

---

## 6c. Arm semantic certainty stack (added 2026-06-18, post-Batch 1 review)

The §6 table covers the **gates** but understates how certainty stacks across layers. This section makes the layered story explicit so future Composer/Opus pairs know what's covered and what isn't.

**Question this addresses:** "If we pull arm `(TXN_PREV_WORD_MOD, core_arithmetic)` on step 1234, can we prove (a) step 1234 really belongs in `core_arithmetic`, (b) the kind really mutates the right field on that step, (c) the variant we're running really should have access to this arm, and (d) the bandit history really reflects what got pulled?" The answer is *yes*, but only by stacking six layers, each of which protects a different invariant.

### Layer S1 — Zone classifier correctness (`zone_classifier.py`)

| | |
|---|---|
| **What it protects** | Each user_cycle is assigned to the correct one of 19 `SEMANTIC_ZONES` per the D13/D50/D53/D54 precedence rules |
| **Authoritative source** | `a4/standalone/semantic_zones.py` (zone list) + `a4/standalone/zone_classifier.py` (assignment logic) |
| **Current coverage** | One canonical spot pin: `test_mem_val_kernel_other_has_targets` (cloud1 D54 — step 3921 on sha2-host must land in `kernel_other`, not `core_div`). No systematic per-step audit. |
| **Known gap** | If the classifier silently drifts for steps not covered by D54, downstream S2–S6 won't catch it. Currently we rely on the classifier being cloud1-frozen. |
| **Mitigation (planned)** | W-15: when D2.D variant filtering lands, add a sampled audit (N=100 random (step, kind) pulls, assert zone matches classifier) |

### Layer S2 — Arm universe construction (`semantic_arm_universe.py`)

| | |
|---|---|
| **What it protects** | The (kind, zone) lattice phantom-prunes correctly: arms exist iff `steps(kind) ∩ steps(zone) ≠ ∅` AND at least one step has a real target |
| **Authoritative source** | `SemanticArmUniverse.build()` + `_cycle_matches_kind_filter` + `_step_has_real_target` |
| **Current coverage** | `test_v5_phantom_arm_pruning::test_production_arm_count_in_d40_range` — V5 control 8-kind universe size stays in [44, 52] on sha2-host (count regression) |
| **Known gap** | Count test doesn't prove **which** arms survived — just that the total is in range. A drifted classifier that produced wrong-but-same-count arm sets would still pass. |
| **Mitigation** | Spot pin (D54 step 3921) at the per-arm level lives in `test_mem_val_kernel_other_has_targets` |

### Layer S3 — Per-kind trace-field attestation (D2.B Layers 2–4)

| | |
|---|---|
| **What it protects** | When a kind is pulled, the Rust handler actually mutates the trace field the kind claims (`<a4_kind>` evidence tag), the post-mutation trace dump confirms only that field changed (`<a4_post_mut_dump>` window), and the two views agree |
| **Authoritative source** | Per-kind attestation tests: `test_d2b_<kind>_attestation.py` using `_test_helpers/diff_signature.py` |
| **Current coverage (post D2.B Batch 2)** | B.1 both strategies; B.2 `TXN_PREV_CYCLE_MOD`; B.3 `CYCLE_MODE_MOD` (trace edit confirmed) |
| **Critical insight from Batch 1** | Rejection is observed across **four independent channels** (see §9b updated section); the attestation guard must accept all four, not just `<constraint_fail>` |
| **Critical insight from Batch 2 (B.3 audit)** | **Layer 3 (S3) is necessary but not sufficient.** A post-mut dump from the **trace struct** proves the Rust handler ran; it does **not** prove the mutation persisted into **witness columns** used by constraints. Fields written only via `set_cycle` preset (`cycle.pc`, `cycle.state`, `cycle.machine_mode`) are overwritten during `step_Top` by `exec_Reg(ctx, inst_result.new*, ...)` — see **W-17** and **§6d**. Future attestation for set_cycle kinds should add **Layer 3b** (witness-column persistence check) if/when a dump hook becomes available. |
| **Known gap** | Does NOT prove the mutation hit a step in the **right zone** — only that it hit the right field. Cross-checking against the classifier is S1 × S3, not yet automated. Does NOT prove witness-level effect for set_cycle fields (Layer 3b gap above). |

### Layer S4 — Cross-kind registry consistency (`test_d2b_arm_registration.py`)

| | |
|---|---|
| **What it protects** | All N D2.B kinds are registered consistently across the 5 plumbing files: `MUTATION_KINDS`, `_MUTATION_MODULES`, `_cycle_matches_kind_filter`, `_step_has_real_target`, `_TXN_ROLE_BY_KIND`, `inspection_data.get_valid_steps_for_kind`, `_BANDIT_TRACE_MOD_TAGS` |
| **Authoritative source** | Cross-cutting Layer 1 test in **D2.B Batch 4** — `test_d2b_arm_registration.py` |
| **Current coverage** | None until Batch 4. Manual review of each batch's plumbing diff is the interim check. |

### Layer S5 — Variant kind dispatch (`test_d2_variant_dispatch.py`)

| | |
|---|---|
| **What it protects** | Variant gating: V5_control may only emit the 8 V5 kinds; Hybrid_cTS may emit 16 A4 + 4 V6 kinds; etc. No variant pulls outside its declared kind subset |
| **Authoritative source** | **D2.D** spec (not yet drafted as a Composer kickoff); plan §6 row "Variant arm coverage" |
| **Current coverage** | None — D2.D is downstream. The phantom test's `V5_CONTROL_KINDS_8` pinning is a *defensive* measure that anticipates this layer. |

### Layer S6 — Campaign arm_history audit (`tests/test_d2_applied_accounting.py`, `validate_d2_dbs.py`)

| | |
|---|---|
| **What it protects** | After a real (or mocked) campaign run: every row in `arm_history` references an `ArmKey` that's a member of the variant's allowed kinds; outcomes are accounted (APPLIED vs SKIPPED vs ERROR); applied-pull counts agree with scheduler |
| **Authoritative source** | **D2.E** tests + **D2.F** end-to-end DB validator |

### What this stack does and does NOT guarantee

**Does guarantee** (with current D2.B Batch 1 work in place):
- A pulled arm produced exactly the trace edit it claimed (S3)
- V5 control universe size is regression-pinned (S2)
- One canonical zone misassignment cannot regress silently (S1 D54 pin)
- Soundness-bug guard catches verifier acceptance of edited traces (S3 + §9b)

**Does NOT guarantee** (gaps acknowledged):
- The classifier is correct for ALL 19 zones × all reachable steps (S1 — only spot-pinned)
- The full arm set after pruning is semantically correct, just that the count is plausible (S2)
- Cross-kind registry consistency before Batch 4 lands (S4)
- Variant filtering enforced before D2.D lands (S5)

**Where each gap closes:**

```
S1 systematic audit → W-15 (D2.D + sampling test)
S2 per-arm correctness → S1 × S3 cross-check (post D2.D)
S4 cross-kind consistency → D2.B Batch 4
S5 variant filtering → D2.D spec + tests
S6 campaign-level audit → D2.E + D2.F
```

**Why this stack matters:** A4's whole value proposition depends on us being able to say "we mutated X in zone Y of N traces and observed M failures." If any layer silently breaks, the per-variant comparison numbers we ship to Pro become meaningless. The stack exists because cloud1 learned the hard way (R2 § 7.2.2 pull-direction flip; D54 kernel mis-bucketing).

---

## 6d. Batch 3 attestation predictions — set_cycle dead-arm class (added 2026-06-18, post Batch 2 audit)

**Purpose:** Lock expectations **before** Batch 3 implementation so we can look back at the audit with 100% certainty. If attestation contradicts a prediction, **stop and reconcile** — do not silently relabel the outcome.

**Authoritative audit:** [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md)

### Mechanism (proven on B.3, extrapolated to B.6/B.7)

```
trace.cycles[N].field mutated
  → build_injector / set_cycle presets witness column from trace
  → hal.scatter writes preset into data buffer
  → step_Top row N: exec_Reg(ctx, inst_result.new*, column) STORE overwrites preset
  → constraints read execution-derived columns only (top.zir next_* chain)
  → verifier may accept (proof attests unmutated execution) — NOT W-16
```

**Live path contrast:** txn fields (`trace.txns[]`) and some cycle fields (`diff_count`, `major`/`minor` via externs, `machine_mode` on paging cycles via `extern_nextPagingIdx`) are read directly from trace during witgen — **no set_cycle overwrite**.

### Batch 3 per-kind attestation expectations (sha2-host, user-instruction cycles)

| Kind | Trace field | Witness path | **Expected attestation outcome** | If outcome differs → |
|------|-------------|--------------|----------------------------------|----------------------|
| **B.3** `CYCLE_MODE_MOD` | `machine_mode` | set_cycle → overwritten | **CONFIRMED DEAD** (Batch 2): guard fires, verifier accepts, xfail documented | N/A — baseline |
| **B.4** `TXN_ADDR_MOD` | `txns[].addr` | execution-derived `addrElem` in `MemoryIO`; trace addr sanity-check only | **CONFIRMED DEAD (W-18)** — Batch 3 empirical + [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md) | Investigate if live rejection appears |
| **B.5** `TXN_CYCLE_PHASE_MOD` | `txns[].cycle` LSB | execution-derived `memCycle` (2×cycle±1); trace LSB unused in witness | **CONFIRMED DEAD (W-18)** — same audit | Investigate if live rejection appears |
| **B.6** `CYCLE_PC_MOD` | `cycle.pc` | set_cycle → **confirmed** same overwrite as B.3 (`steps.cpp:14739-14740`) | **CONFIRMED DEAD (W-17)** — Batch 3 attestation | **Reconcile audit** if live |
| **B.7** `CYCLE_STATE_MOD` | `cycle.state` | set_cycle → **confirmed** same overwrite as B.3 (`steps.cpp:14743`) | **CONFIRMED DEAD (W-17)** — Batch 3 attestation | **Reconcile audit** if live |
| **B.8** `CYCLE_DIFF_COUNT_MOD` | `diff_count[]` | `extern_getDiffCount` reads trace directly | **CONFIRMED LIVE** — `cycle` Hook 3 family | Reconcile if dead |

### Attestation pattern for predicted-dead kinds (B.6, B.7)

Mirror B.3 Batch 2 attestation (`test_d2b_cycle_mode_mod_attestation.py`):

1. Layers 2–4 pass (trace edit confirmed)
2. Enable `A4_FAMILY_RESIDUE=1`; pass all four channels to `check_soundness_bug_guard`
3. **Assert** `SoundnessBugSuspected` fires (`guard_fired == True`)
4. `pytest.xfail()` with dead-arm rationale citing W-17 + audit doc

**Failure mode that triggers audit reconciliation:** Any predicted-dead kind shows C1/C2/C3 rejection **or** guard does **not** fire while verifier accepts. Either case means our set_cycle overwrite model is incomplete.

### Scope qualification (do not over-claim)

Predictions apply to **sha2-host user-instruction cycles** (major 0–6) unless attestation explicitly targets paging/ECALL majors. B.3 may be **live on paging cycles** via `extern_nextPagingIdx` — unproven dead globally. Batch 3 kickoff should note this when selecting attestation targets for B.6/B.7.

---

## 7. What ships to Pro at the end of D2

Single bundle (matching the D1 + D2-design pattern):

- **`IV_POS_8_D2_REPORT_FOR_PRO.md`** — the headline narrative
- **`IV_POS_8_D2_NOTEBOOK.ipynb`** — companion plots / drill-down
- **`IV_POS_8_D3_DESIGN_PROPOSAL.md`** — Track-β drafts the D3 (bug-isolation layer) design so Pro can react to "where we go next" alongside D2 results

Plus the underlying artifacts: 30 new DBs (or 40 if we don't reuse archives), variant comparison CSVs, kind-survey output, normalize-parity report.

---

## 8. What this plan deliberately does NOT include

- **No D3 implementation.** D3 sketch goes into `IV_POS_8_D3_DESIGN_PROPOSAL.md` (text only), to be shipped with D2. D3 implementation starts in Track-β only after Pro greenlights it.
- **No D4 (multi-guest).** Out of scope until D3 ships.
- **No D1 re-work.** Track-α owns D1.B / D1.C / D1.D / D1 report.
- **No changes to V5 itself** beyond what D2.A refactors (back-compat-preserving). V5 production stays as-is; only its scheduler is generalized.
- **No new POS infrastructure.** Same `dispatch_pos.py` / `collect_results_pos.py` / `prepare_bundle.sh` workflow as D1.A.
- **No alternate guests.** D2 runs on the current sha2-host guest (same as R2 + D1.A). Multi-guest is D4.

---

## 9. What we tackle FIRST (concrete next steps)

In order:

1. **Ivan reviews this plan v0.1** — confirm sub-deliverable split, answer §5 open questions, edit / reject as needed
2. **Lock the §5 answers** into this document as v0.2 (analogous to `IV_POS_8_D1_A_SPEC.md` §8 "Decisions Confirmed")
3. **Draft D2.A spec** (`IV_POS_8_D2_A_SPEC.md`) and Composer-review it before any code
4. **Draft D2.0 v0.1** (`IV_POS_8_D2_DESIGN_PROPOSAL.md`) in parallel with D2.A spec — it's the Pro-facing document and stays a living draft until D2.E green
5. **Draft D2.B and D2.C spike specs** (D2.C survey is the gating wildcard — start it first if Composer cycles are available)
6. **Composer Batch 1 — D2.A foundation** (arm-shape refactor + applied accounting). Tightest review checkpoint of the whole D2 because everything depends on it.
7. **In parallel after D2.A merges:** Composer Batches 2a (D2.B kinds), 2b (D2.C bridge), 2c (D2.0 finalization) — these are independent
8. **Composer Batch 3 — D2.D variant dispatch + D2.E tests**
9. **Composer Batch 4 — D2.F POS dispatch + collection**
10. **Composer Batch 5 — D2.G analysis + report assembly**
11. **Track-α + Track-β merge for the Pro ship** — D1 report + D2 report + D2.0 + D3 design proposal as one bundle

Composer-batch granularity is the same as D1.A: per-batch spec + per-batch Ivan/Opus review checkpoint, no surprises.

---

## 9a. Deferred-decisions watchlist (added 2026-06-17)

These are decisions we intentionally made "go with X for now, revisit at Y if Z". This section exists so we don't forget to actually revisit. Each row tracks the original decision, the trigger that would cause us to revisit, the deliverable where we check, and the fallback.

| ID | Decision (locked v0.4) | Revisit at | Trigger to flip | Fallback if triggered |
|---|---|---|---|---|
| **W-1** | Q1: `CYCLE_MODE_MOD` broad scope (any cycle) | **D2.G** analysis | <1% constraint-failure rate outside `pre_ecall`/`post_ecall`/`pre_mret`/`post_mret` zones | Restrict to 4 boundary zones in D3 (~3-4× arm reduction) |
| **W-2** | Q2: §3 value-gen mix percentages (heuristic) | **D2.G** analysis | Per-kind failure-rate or distinct-residue counts skewed for any single mix-bucket | Retune via DB without spec revision (`outcome` column already supports this) |
| **W-3** | Q3: B.8 ships, classified via 3-way bucket | **D2.B Batch 1.0b** report | All 5 sample B.8 mutations produce clean-success AND post-mut dump verifies trace changed (= dead arm, not soundness bug) | Drop B.8 from D2.B kind registry; document negative result |
| **W-4** | Q5: Pro-valid `MEMORY_TXN_ROLES` only (Option A); per-kind via `producer_kind` | **D2.G** review with Pro | Pro signals they want a `cycle_meta` (or per-field) txn_role enum | Land schema bump in IV.POS.9 |
| **W-5** | Q6: Variant-specific kind subsets; V5 control = 8 kinds + D1.A archive reuse | **D2.E** golden-trace smoke + **D2.F** POS dispatch | Variant subset CLI mis-filters and emits ≠8 kinds in V5_control mutation stream | Roll back to 16-kind unified registry; rerun V5 (~3 h compute) |
| **W-6** | Q11: B.1 Option A (one kind, RNG-picked strategy per pull) | **D2.G** per-strategy outcome breakdown | One strategy dominates rewards >80% on the SAME zone | Split to Option B (two kinds) in D3 |
| **W-7** | NFP-6: `PRE_EXEC_REG_MOD` retrofix lands in D2.B Batch 1.5e | **D2.G** analysis | Post-retrofix `PRE_EXEC_REG_MOD` failure rates show no `prev_write`-attributable signal | Revert retrofix; document as one-strategy-suffices |
| **W-8** | Q15: `CycleState` enum hardcoded from `platform.rs` | **Any risc0 pin bump** | Pin to a new risc0 commit | Re-extract enum; bump `cycle_state_mod.py` constant |
| **W-9** | Q17 / NFP-5: Layer 3 via `A4_DUMP_POST_MUT=1` Rust hook (Option A1) | **D2.B Batch 1.0a** smoke | Rust patch fails to build or doesn't emit expected tags | Fall back to Option B (tag-only Layer 3), explicitly downgrade "100% certainty" claim |
| **W-10** | Q8: 4 batches (Batch 3 = B.4-B.8, 5 kinds) | **D2.B Batch 2 completion** | Batch 3 attestation churn exceeds ~1 week with one kind blocking | Isolate B.4 in its own sub-batch |
| **W-11** | Pro's wider §8 catalog (BIGINT_DATA_MOD, CRYPTO_STATE_MOD, etc.) deferred to a future IV.POS cycle | **IV.POS.9** scoping | Pro explicitly requests in D2.G review | Add as IV.POS.9 D-series |
| **W-12** | D2.B Batch 1.5e merge is the SYNC point that unblocks D1.E (per `IV_POS_8_D1_REVISIT_PLAN.md` §4.1) | **End of D2.B Batch 1** | Batch 1 merges but commit message does not contain literal "Batch 1.5e" string | Manually ping D1 chat with the commit hash + force-update `NOTES_FOR_PRO.md` revision history so D1 chat catches the signal |
| **W-13** | NFP-10 byte_addr fix (`compressed_global_extractor.py:216`) must not be reverted during D2.B's §4.7 edits | **D2.B Batch 1 Composer review** | Composer commit diff shows line 216 reverted from `("byte_addr","addr","address")` to `("addr","byte_addr","address")` | Block merge; require Composer to re-apply NFP-10 fix; flag as instruction-comprehension miss |
| **W-14** | Pro-presentation timing changed (was D2.G end, now end of D2.B) — interim Pro check-in becomes the gate for D2.C kickoff | **End of D2.B Batch 4** | Pro does not greenlight D2 continuation OR Pro requests scope changes that invalidate D2.C/D2.D drafts | Pause D2.C kickoff; re-spec per Pro feedback; document scope shift in `IV_POS_8_D2_PLAN.md` v0.9+ |
| **W-15** | S1 zone classifier has only the D54 spot pin — no systematic per-(step, zone) audit (cf. §6c) | **D2.D variant filtering kickoff** | A run shows arm `(kind, zoneX)` pulling steps the classifier doesn't actually map to `zoneX` | Add sampled audit: N=100 random `(step, kind)` pulls from a D2.D run, assert zone matches classifier; if mismatches found, harden classifier before D2.E |
| **W-16** | Soundness-bug guard's rejection channels (post D2.B Batch 1 Issue #6) — guard accepts `<constraint_fail>` OR `verify segment` OR `<a4_family_residue nonzero=true>` (Hook 3) OR `<a4_error>` as rejection; fires only on `verifier_accepted=True` after edit | **Each D2.B kind attestation** | Any new kind reaches Layer 4 with all four channels silent AND verifier accepts — re-investigate; do not relax guard | Surface as NFP candidate; consult mem.zir / lookups.zir source to find which constraint the kind should have broken; either fix kind to actually exercise that constraint, or document as known soundness gap with Pro disclosure |
| **W-17** | **`set_cycle` overwrite dead-arm class** — `trace.cycles[N].pc / .state / .machine_mode` preset via `set_cycle` (`witgen/mod.rs:1063-1075`) but overwritten by `step_Top`'s `exec_Reg(inst_result.new*, ...)` (`steps.cpp:14739-14745` → `exec_NondetReg` STORE). B.3 **confirmed dead** (Batch 2). B.6 and B.7 **confirmed dead** (Batch 3). | **D2.B Batch 3 attestation** | Predicted-dead set_cycle kind shows live rejection OR guard does not fire while verifier accepts | Re-read [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md); update §6d + W-17. |
| **W-18** | **Execution-derived witness-key dead-arm class (txn fields)** — `trace.txns[i].addr` and `trace.txns[i].cycle` LSB are mutated in trace but **never enter witness columns**. `extern_getMemoryTxn(addrElem)` takes execution-derived address; returns only `prevCycle`, `prevWord`, `word`. Witness addr/phase come from DSL `MemoryIO(addr, memCycle)` execution args (`mem.zir:65-75`, `88-101`). B.4 and B.5 **confirmed dead** on sha2-host user memory txns (Batch 3 + [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)). Distinct from W-17 (not set_cycle overwrite). `FAULT_INJECTION_ENABLED` suppresses sanity **throws** on addr/cycle mismatch but does **not** suppress Hook 3 or verify segment. | **D2.B Batch 3 attestation + txn audit** | B.4 or B.5 shows live rejection with witness path audit showing mutated field in committed column | Stop merge; investigate W-16 vs incomplete audit. If confirmed dead → xfail + drop from `MUTATION_KINDS` at §9c postscript. |
| **W-17b** | **Dead-arm campaign exclusion implemented via registry absence** — confirmed-dead kinds are excluded from campaigns by deliberately NOT being in `A4Fuzzer.MUTATION_KINDS` (rather than via runtime filter logic). All campaign kind-selection paths (`_run_pilot` line 453, `ArmUniverse` lines 419/816, `_run_one_mutation` line 1402, `SemanticArmUniverse.build` line 729) read from the same `MUTATION_KINDS` registry, so absence is structurally enforced. Python module + Rust handler + `_MUTATION_MODULES` registration + `inspection_data.get_valid_steps_for_kind` branches + attestation tests + unit tests all KEPT so the W-17 mechanism remains under continuous verification (attestation tests bypass the registry — they import the module directly and reference the kind string literally). Decision rationale: avoiding runtime filter logic eliminates bypass risk (the registry IS the filter). | **D2.B postscript task (§13)** — runs after Batch 4 completes; performed by Opus | A new code site is introduced that uses `MUTATION_KINDS` for a purpose where dead kinds should NOT be filtered (e.g., a kind-implementation audit) — would need to use a different source-of-truth | Add a parallel `IMPLEMENTED_KINDS_ALL` constant if needed, but only when an actual use case appears. Until then, the registry-exclusion approach is sufficient. |

**Convention:** when one of these triggers fires, the team's first action is to **read the row's "Fallback" column** and check whether the fallback is still viable given current state. Then re-decide.

---

## 9b. Soundness-bug guard (added 2026-06-17; revised 2026-06-18 post-Batch 1 Issue #6)

**Rule:** any "clean success" outcome MUST be cross-checked against ALL FOUR rejection channels before being classified as a "dead arm" or soundness bug.

### The four rejection channels (verified against `a4/standalone/fuzzer.py:345` production rejection logic)

| Channel | Source | What it catches | Env var to enable |
|---|---|---|---|
| **C1 — `<constraint_fail>` (Path A)** | `witgen.h:184-206` (`eqz()`) — fires on local witgen EQZ during arm exec or accum phase | Constraint violations the in-arm code checks directly (e.g., `IsRead.dataLow == dataHigh` on a READ) | `CONSTRAINT_CONTINUE=1` (to continue past first failure for full diagnostic) |
| **C2 — `verify segment` panic (Path B)** | `risc0-host/main.rs:150` — fires when `prove::prove()` returns `Err` because prover's `verify_integrity_with_context` rejects | The polynomial / `check_poly` constraint over committed witness columns — the **mathematically authoritative** check that the verifier replicates. Catches violations Path A misses (e.g., B.1 `at_write` where mutated `prev_word` breaks memory permutation but no local EQZ checks `oldTxn.data == prev_word`). | Always emitted |
| **C3 — `<a4_family_residue>{"nonzero":true}` (Hook 3)** | `ffi.cpp:510-518` — fires when per-family permutation/lookup residue is non-zero after accum phase | Per-family diagnostic of WHICH constraint family broke (`memory`, `u16`, `u8`, `cycle`); semantically richer than `verify segment` because it tells you the family, not just "something broke" | `A4_FAMILY_RESIDUE=1` (REQUIRED — without this, Hook 3 is silent even when the memory permutation is broken) |
| **C4 — `<a4_error>`** | A4 dispatcher in `witgen/mod.rs` | Mutation skipped or errored before/during application (e.g., strategy mismatch, txn_idx out of range) | Always emitted |

**True soundness bug (W-16) = (mutation applied) AND (trace changed) AND (ALL FOUR channels silent) AND (verifier_accepted=True) AND (witness columns genuinely corrupted).**

**Dead arm (W-17 / W-18) = same guard trigger (trace changed + verifier accepts + all channels silent) BUT witness columns were NOT corrupted** — W-17: trace preset overwritten before constraints bind; W-18: execution-derived witness keys never read mutated txn fields. Investigation (source-level witgen path audit) distinguishes W-16 from W-17/W-18. B.3 Batch 2 and B.4/B.5 Batch 3 are templates: call guard → assert it fires → document dead arm via xfail; **do not** treat guard fire alone as W-16.

In particular, **C2 alone catches what C1 misses** — this is the Path A vs Path B asymmetry documented in `a4/docs/precloud/PHASE_III_2_5_INSTR_TYPE_MOD_INVESTIGATION.md` §0.1. C3 (Hook 3) provides redundant + family-attributable signal.

### Why this matters — empirical from D2.B Batch 1 Issue #6

`TXN_PREV_WORD_MOD at_write` mutation on sha2-host:
- C1 (`<constraint_fail>`): **silent** — `MemoryWrite` in `mem.zir:95-101` calls `IsForward` but NOT `IsRead`; its only EQZ checks are `newTxn.data == data` (lines 99-100). Mutated `prev_word` flows into `oldTxn.dataLow/dataHigh` but is never locally EQZ'd.
- C2 (`verify segment`): **fires** — `check_poly` reports 32768/32768 cycles non-zero; `verify_integrity_with_context` rejects
- C3 (Hook 3 memory family residue): **expected to fire** when enabled — `extern_memoryDelta` records mutated `prev_word` into the residue accumulator; `res_memory` should be non-zero, emitting `<a4_family_residue>{"family":"memory","nonzero":true,...}`
- C4 (`<a4_error>`): **silent** — strategy validates, mutation applies cleanly
- Verifier acceptance: **never observed** (prover panics at `main.rs:150` before any seal is produced)

**Verdict:** NOT a soundness bug; rejected via C2. Composer's initial guard was C1+C4-only (missed C2 and C3); the post-Issue #6 fix added C2. **W-16 tracks the remaining wiring of C3** into the attestation flow.

### Implementation requirements for D2.B attestation tests

Every `test_d2b_<kind>_attestation.py` MUST:

1. Set **`A4_FAMILY_RESIDUE=1`** in the host-run env so C3 is emitted
2. Parse `<a4_family_residue>` tags using `a4.core.touch_coverage.parse_family_residues`
3. Pass all four channels' state to `check_soundness_bug_guard`:
   ```python
   check_soundness_bug_guard(
       mutation_applied=True,
       trace_changed=bool(diffs),
       constraint_failed="constraint_fail" in mut_out.lower(),
       error_emitted="<a4_error>" in mut_out,
       proof_verify_failed="verify segment" in mut_out,
       broken_families_nonzero=any(fr.get("nonzero") for fr in parse_family_residues(mut_out)),
       verifier_accepted=False,  # would be True only if a verifiable receipt was produced
   )
   ```
4. The guard MUST fire ONLY when all four channels are silent AND `verifier_accepted=True`.

### Affected files

- `a4/standalone/tests/_test_helpers/diff_signature.py` — extend `check_soundness_bug_guard` to accept `broken_families_nonzero` parameter as a third independent rejection channel (current state post-Issue #6: only `proof_verify_failed` was added; Hook 3 is still missing)
- All D2.B attestation tests — must enable `A4_FAMILY_RESIDUE=1` and pass Hook 3 state to the guard
- D2.G analysis pipeline MUST classify outcomes by which channel rejected (for Pro telemetry)

This rule applies retroactively to existing kinds too — if a smoke shows an existing kind has a clean-success path that wasn't trace-verified across all four channels, log it as an incident and re-test.

---

## 9c. D2.B postscript: dead-arm registry exclusion (added 2026-06-18, scheduled post-Batch-4)

**Task ID:** D2.B-PS-1 ("postscript 1") — runs **after** D2.B Batch 4 completes and **before** D2.C kickoff.
**Owner:** Opus (single small commit).
**Trigger:** Batch 4 commit landed on `cloud2` (`2e1d97b`).
**Status:** **Done (v0.15, 2026-06-19).** 5 dead kinds removed; dead-kind registration guard inverted to `test_dead_kinds_excluded_from_registry` (assert `isdisjoint`); explanatory comment block added above `MUTATION_KINDS` with W-17/W-18 mechanism references. Per-kind modules/handlers/tests retained as regression sentinels.
**Authority:** W-17 + W-17b in §9a. Rationale audited 2026-06-18 (see Cursor chat IV.POS.8 D2 thread — "why not finish D2.B first then edit MUTATION_KINDS").

### Why this exists

D2.B Batch 2 confirmed B.3 `CYCLE_MODE_MOD` is a W-17 dead arm on sha2-host user-instruction cycles. Batch 3 attestation will either confirm or falsify the prediction that B.6 `CYCLE_PC_MOD` and B.7 `CYCLE_STATE_MOD` are dead via the same `set_cycle`/`exec_Reg` overwrite mechanism. Dead arms must NOT enter campaign kind-selection paths because:

1. They pollute campaign DB with `ACCEPTED` rows that look like baseline successes but came from mutated-trace inputs (misleading reward signal).
2. They waste bandit budget that should go to signal-generating kinds.
3. They contaminate per-kind statistics (failure-rate denominators get inflated).

**Architectural decision (W-17b):** exclusion is implemented via **registry absence** — confirmed-dead kinds are simply not added to `A4Fuzzer.MUTATION_KINDS`. No filter logic is introduced; the registry IS the campaign list. Attestation tests are unaffected because they import the Python module directly and reference the kind string literally; they do not iterate `MUTATION_KINDS`.

### Verified safety (no architectural malfunction risk)

Pre-implementation audit (2026-06-18) confirmed `MUTATION_KINDS` size variation does not break any campaign code path:

- `compute_N_pilot(budget)` — depends on budget only.
- `prior_alpha/prior_beta` — per-arm hardcoded, no kind-count normalization.
- `ConstantFloor(0.55)` and other floor schedules — hardcoded values.
- `b_count` / bucket count — per-kind, kind-count independent.
- `num_arms` — derived from `len(kinds) × buckets`; fewer kinds → fewer arms is correct behavior.
- `test_v5_phantom_arm_pruning.py` — pinned to `V5_CONTROL_KINDS_8` (hardcoded), unaffected.
- `test_semantic_arm_universe.py` — uses explicit subsets, not the full registry.
- Audit scripts (`B1_hook_fidelity.py:96`) — using `A4Fuzzer.MUTATION_KINDS` directly is **correct** for auditing the production set; dead arms should not be in scope.
- Standalone test campaigns (`run_diagnostic_campaign.py` etc.) — have their own local `MUTATION_KINDS = [...]` constants, independent.

### Tasks (single commit, Batch 4 postscript)

1. Edit `a4/standalone/fuzzer.py` `MUTATION_KINDS`:
   - Remove `CYCLE_MODE_MOD` (B.3 — confirmed dead in Batch 2).
   - Remove `TXN_ADDR_MOD` (B.4) and `TXN_CYCLE_PHASE_MOD` (B.5) — confirmed dead W-18 (Batch 3 audit).
   - Remove `CYCLE_PC_MOD` (B.6) and `CYCLE_STATE_MOD` (B.7) — confirmed dead W-17 (Batch 3).
   - Add a comment block explaining the registry-exclusion pattern with W-17/W-18 links.
2. Invert these unit-test assertions and add a `# W-17 dead arm` comment:
   - `test_d2b_cycle_mode_mod_unit.py:83` — `assert "CYCLE_MODE_MOD" in fuzzer.MUTATION_KINDS` → `assert "CYCLE_MODE_MOD" not in fuzzer.MUTATION_KINDS`
   - `test_d2b_batch3_unit.py:53` — same inversion for any confirmed-dead Batch 3 kind.
   - Per-kind unit tests for B.6 / B.7 (Composer writes these in Batch 3) — same inversion for the confirmed-dead kinds.
3. Add postscript-completion entry to `IV_POS_8_NOTES_FOR_PRO.md` (this becomes a new NFP entry summarizing the W-17 dead-arm class for Pro).
4. Update §9a W-17 / W-17b state to "implemented" with the commit hash.
5. Update `IV_POS_8_D2_B_SPEC.md` §5.4 / §7 Batch 3 with the postscript completion.

### Reconciliation rule (if any predicted-dead kind attests live)

If Batch 3 attestation shows B.6 or B.7 actually live (rejection channel fires), the audit reconciliation rule in §6d applies BEFORE this postscript runs. The live kind stays in `MUTATION_KINDS`; only confirmed-dead kinds are removed by this postscript.

### Optional follow-up: full deletion of dead-arm code (D2.B-PS-2)

After §9c (D2.B-PS-1) lands and the cleanup has been stable for at least one D2.G analysis run, we may decide to **fully delete** all code, tests, and Rust handlers for confirmed-dead kinds rather than keeping them inert in the repo. The decision criteria:

- The dead-arm mechanism (W-17 / future W-18 etc.) is documented in the spec / NOTES_FOR_PRO so we don't lose the architectural lesson.
- The deletion commit references the prior implementation commit hashes so anyone can `git checkout <hash>` to recover the code if a future RISC Zero version changes the witgen pipeline and renders the dead arm live again.
- The deletion is a single explicit commit ("D2.B-PS-2: delete W-17 dead-arm implementations") rather than a creep across multiple changes.
- W-17b / §9c remains in this plan as historical record of the decision sequence.

**Rationale for the option:** the dead-arm Python modules / Rust handlers / attestation tests carry maintenance cost (build time, test runtime, code complexity) for zero campaign signal. Git history is sufficient backup. Keeping the W-17 mechanism documentation (which IS valuable) does NOT require keeping the code. This is a deferred decision — execute only if the cost outweighs the "continuous verification of the W-17 prediction" benefit. Status: **TBD, post-D2.G**.

### Why we don't do this DURING Batch 3

- Composer's kickoff already instructs to add B.6/B.7 to `MUTATION_KINDS` and assert membership in unit tests. Changing rules mid-batch causes churn.
- The cleanup decision per kind depends on attestation outcomes that Composer hasn't reported yet.
- No campaigns run during D2.B (POS dispatch is D2.F). The "dead arms in registry" window during Batch 3/4 is theoretical only — no real campaign pollution.

---

## 10. Why this plan is right (TL;DR for Ivan)

- **Faithful to Pro's Priority 1 + Priority 3** — Hybrid V7 + pure-A4 expansion, with all of Pro's normalizations (applied accounting, source-time normalized loc, semantic arm-space)
- **Foundation-first** (D2.A before everything) — the arm-shape refactor is the load-bearing piece; everything downstream is incremental
- **Bridge over reimplementation** (D2.C uses `arguzz_runner` instead of porting V6 to Python) — the right cost/risk tradeoff per Pro's explicit "selectively adopt" language
- **Conservative arm-space sizing** (4 V6 + 8 A4 kinds = 12 total, not 7+5+more) — keeps v1 turnaround fast; Pro can expand to BIGINT_DATA_MOD / CRYPTO_STATE_MOD / etc. in a future cycle
- **Tracks A and B parallel-safe** — Track-β doesn't block on D1 except for D1.B's CGC variant pick (and Q8 default-and-pivot covers that)
- **Test gates at every step** — golden trace, dump diff, binary survey, applied-accounting smoke, normalize parity, end-to-end DB validator. No DB ships to Pro that hasn't passed each
- **POS infra is unchanged** — same playbook as D1.A; the only new artifact is `validate_d2_dbs.py` and 3 manifests
- **Reversible at every Composer checkpoint** — if D2.A back-compat fails, we don't ship D2; if D2.C binary survey rules out a kind, we drop it from v1 and document

---

*End of D2 master plan v0.1. Open questions in §5 need Ivan's answer before any spec drafting begins. D2.A spec will be the first child document, drafted only after §5 is resolved.*
