# IV.POS.8 D2.C — V6 / Arguzz Integration Spec

**Branch:** `cloud2` (direct commit, no feature branches)
**Date opened:** 2026-06-17
**Date last revised:** 2026-06-19 (v0.5)
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Status:** **LOCKED v0.5** — Phase 0 drift resolved (§7 S5 `pre_post`; companion doc sweep). V6-cTS = all 11 Arguzz kinds; Hybrid-cTS = 4 selected. Awaiting Opus Batch 1 kickoff.
**Parent:** [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) v0.16 §3 (sub-deliverable D2.C)
**Predecessors:**
- [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) v0.2 LOCKED — D2.A foundation merged at `7b66fb9` (5-tuple `ArmKey`, `MutationOutcome` enum, normalized telemetry)
- [`IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) v0.5.4 LOCKED — D2.B closed at `e2c2256` (3 LIVE + 5 dead A4 kinds; postscript landed)
- [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md) — Pro-facing mechanism explanation (W-17/W-18 dead-arm proofs, 4-channel rejection model)
- [`ProG_Report_3.md`](./ProG_Report_3.md) §3, §8, §13–15 — Pro's V6 integration requirements
**Sibling specs:** D2.D (variant CLI/fuzzer dispatch) and D2.E (integration tests) — out of D2.C scope; D2.C provides their building blocks.

---

## 0. What this document is

The implementation spec for **D2.C — V6 / Arguzz integration**. D2.C brings the Arguzz exec-fault mutation kinds into the bandit-eligible arm space (full 11-kind set for V6-cTS; the 4 high-yield kinds Pro selected for Hybrid-cTS), alongside modernizing the recovered `v6_driver_v2.py` so V6-uniform campaigns write through `CoverageDB` (gaining D2.A's outcome column, normalized telemetry, and full A4 schema parity).

**Workflow:** v0.1 → v0.2 (12 open questions LOCKED + per-kind mechanism analysis) → Composer pre-flight audit (2026-06-19) → v0.3 (Option C outcome mapping, D2.A-aligned 7-class taxonomy, two-tier golden trace, applied-accounting wiring as explicit Batch 3 task) → v0.4 (V6-cTS kind-set scope corrected from 4 → 11 per Pro `ProG_Report_3.md` §9; Hybrid-cTS keeps the 4 selected kinds; constants split; arm-space estimate updated) → scoped Composer review on the v0.4 change axis → **v0.5 LOCK (Phase 0: §7 S5 `pre_post` drift fix + companion doc sweep)** → Composer Batch 1 kickoff → Composer reports → Ivan + Opus review → iterate → D2.C closed (D2.D unblocked).

**What is new in v0.4 (vs v0.3 — V6-cTS kind-set scope correction):**

- §1.1 + §3.4 + §4.2 + §4.3 + §4.4 — **V6-cTS uses all 11 Arguzz `ENABLED_KINDS`; Hybrid-cTS uses the 4 selected.** Pro's `ProG_Report_3.md` §9 (lines 277-302) explicitly distinguishes "V6-cTS: Arguzz kinds **only**, but selected by constrained TS" (i.e., the same kind set as V6-uniform — all 11) from "Hybrid-cTS: A4-V5 kinds + **selected** Arguzz kinds in one shared arm space" (the 4 high-yield kinds). v0.3 conflated the two by using a single 4-kind constant for both variants, which would have made the V6-uniform-vs-V6-cTS comparison confounded (it would have tested *scheduler change AND kind-set restriction simultaneously* rather than scheduler alone). v0.4 splits the kind-list into `MUTATION_KINDS_ARGUZZ_FULL` (11 kinds, V6-cTS) and `MUTATION_KINDS_ARGUZZ_SELECTED` (4 kinds, Hybrid-cTS).
- §1.1 — **Two scope tables.** Hybrid-cTS scope (4 selected kinds, Pro `ProG_Report_3.md` §8 Track A priority list lines 228-238) preserved as-is; new V6-cTS scope table lists all 11 `ENABLED_KINDS` (= the kinds `v6_driver_v2.py:168-173` already runs and the R2 V6 DB exercises). Rationale block clarifies that the "Why these 4" reasoning (overlap with A4 trace-cell arms in pure-A4) applies only to the Hybrid-cTS subset, not to V6-cTS standalone (which has no A4 arms to overlap with). **(v0.4 citation fix:** v0.2/v0.3/v0.4-initial cited "§15.2" for the 4-kind selection; that was wrong — Pro's §15 is "The next IV.POS.8 priority order" with §15.2 being the Bug-isolation layer, not kind selection. The 4 kinds come from §8 Track A's priority list. Composer caught this in the v0.4 scoped review.)
- §1.2 — **Arm-space estimate split per variant.** V6-cTS standalone: 11 kinds × ~10 zones × 7 opcode classes × {pre_exec, post_exec} = ~770–1540 raw → **~200–350 actual** after applicability filtering (BR_NEG_COND/COMP_OUT_MOD/LOAD_VAL_MOD/STORE_OUT_MOD are instruction-class-restricted; POST_EXEC_PC_MOD usefully populated only on branches/jumps). Hybrid-cTS standalone: ~390 raw → ~160–240 actual (unchanged from v0.3). The V6-cTS standalone estimate touches Pro's "300 arms — consider reducing" advisory threshold (§9 Q9); Batch 2 measures actuals before any reduction is decided.
- §1.2 — **`pre_post` field varies for the additional 7 kinds.** v0.3 had all 4 D2.C kinds at `pre_exec`. v0.4 adds the convention: PRE_EXEC_*, INSTR_WORD_MOD, BR_NEG_COND → `pre_exec`; POST_EXEC_*, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD → `post_exec`. This finally gives D2.A's `pre_post` axis non-trivial values on both sides (it was effectively `pre_exec`-only in v0.3).
- §4.2 — **`valid_injection_kinds_for_instr` lifted to verbatim copy of `v6_driver_v2.py:176-191`** (full 11-kind dispatch with BRANCHES/COMPUTATIONS/LOADS/STORES instruction-class restrictions). v0.3 restricted this to the 4-kind subset; v0.4 restores the full version.
- §4.3 — **Parameter signature change.** `SemanticArmUniverse.build(include_arguzz_kinds: bool = False)` → `SemanticArmUniverse.build(arguzz_kinds: Optional[List[str]] = None)`. `None` (default) preserves V5-shape behavior; passing a list (`MUTATION_KINDS_ARGUZZ_FULL` or `_SELECTED`) emits Arguzz arms restricted to that kind list. This is the cleanest API for D2.D's per-strategy wiring.
- §4.4 — **Strategy → kind-list wiring.** When `selector_strategy == "v6_cTS"`: `arguzz_kinds = MUTATION_KINDS_ARGUZZ_FULL`. When `selector_strategy == "hybrid_cTS"`: `arguzz_kinds = MUTATION_KINDS_ARGUZZ_SELECTED`. (Internal wiring only; CLI exposure is still D2.D.)
- §4.8 + §11 + §14 — **Test parametrization expanded.** Arm-construction test (`test_d2c_arguzz_arm_construction.py`) now parametrizes over **both kind-lists** (FULL=11 and SELECTED=4) × 7 opcode classes × per-kind `pre_post`, with applicability filtering (was 4 × 7 with all-applicable assumption). Cross-cutting registration test (`test_d2c_arm_registration.py`) parametrizes over `MUTATION_KINDS_ARGUZZ_FULL` as a **single 11-kind superset** × 6 assertion layers = **66 total cases** (up from 24); the 4 SELECTED Hybrid-cTS kinds are a subset of FULL, so their registration is implicitly covered. Acceptance criteria §14 #7 reconciled accordingly.
- §5.5 — **R2 outcome analysis scope clarified.** Item 6's "D2.C 4-kind subset (2446 of 6000 rows)" is now framed as the **Hybrid-cTS-relevant slice** (the 4 selected kinds restricted from 11). For V6-cTS, the full 6000-row corpus applies — the 91.6 % APPLIED+REJECTED / 5.2 % SKIPPED Option C numbers in items 1-5 already reflect the full 11-kind data and need no revision.
- §9 Q9 + §10 + §11 Batch 2 acceptance — **Arm-count estimates split per variant.** "~160–240 (Hybrid-cTS)" + "~200–350 (V6-cTS)" replaces the single "~160–240" estimate. Batch 2 acceptance gates remain "if either exceeds 300, propose reductions" — the existing safety valve covers both variants.
- §13 + §14 — LOC bumps (~+30 LOC for the FULL constant + the additional 7-kind opcode-class derivation paths). Acceptance criteria #2 reworded to mention both Arguzz-kind constants. Acceptance criteria #7 reconciled to 66 cases.

**What was new in v0.3 (vs v0.2 — incorporating Composer's pre-flight audit):**

- §5.5 — **Panic-narrative reversal.** v0.2's "94.6% panic / ~5% APPLIED" framing was a CLASSIFIER ARTIFACT of `v6_driver_v2.py:479` checking `host_panic` BEFORE `prover_status`. The actual breakdown from the R2 V6 DB (`pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000.db`) is: **94.6% APPLIED total** (5674/6000), of which 91.6% are APPLIED+REJECTED (5497/6000 — Path A + Path B together) and 2.95% are APPLIED+ACCEPTED-with-soundness-flag (177/6000), plus 5.2% true SKIPPED (pre-prover guest crash) and <0.2% edge/timeout. The 94.6% APPLIED bandit pull credit (and 91.6% positive-reward signal) must NOT be thrown away as ERROR.
- §6.1 + §9 Q4 — **Outcome mapping flipped to prover_status-primary (Option C).** Old logic (`host_panic → ERROR`) is gone. New: `prover_status="success"` → APPLIED+soundness_signal; `prover_status="error" AND has_failures` → APPLIED; `prover_status="error" AND not has_failures` → APPLIED + `failure_recording_gap=True` (Path B / verify-segment panic); `prover_status="start" AND host_panic` → SKIPPED (true C5); timeout/edge → ERROR.
- §6.2 — **C5 redefined.** Was: any "panicked at" string. Now: `prover_status="start" AND host_panic` only (~5.2% of rows, not 94.6%).
- §9 Q8 + §1.2 + §4.2 + §7 S5 — **Opcode-class taxonomy aligned to D2.A LOCKED 7 classes**: `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`. v0.2's abbreviated 6-class set (`arith`/`mem_load`/etc., with `ecall_mret` collapsed into `system`) was a contradiction with `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 line 48 and the synthetic test at `test_d2a_arm_shape_arguzz_simulation.py:34-38`. `pre_post = "pre_exec"` (not `"pre"`).
- §4.6 — **`major_to_opcode_class` already EXISTS** at `semantic_zones.py:101`. v0.2's "NEW function added" claim was wrong. v0.3 documents the two-taxonomy split: arm-shape `opcode_class` (D2.A 7-class set, used in `arguzz_bridge.MAPPING_INSTR_TO_OPCODE_CLASS` for bandit identity) vs CGC `OPCODE_CLASS_BY_MAJOR` (8-class set `alu`/`mul`/`div`/`mem`/`branch_or_ctrl`/`poseidon`/`sha`/`other`, used in `compressed_global_extractor` for telemetry compression). These are intentionally different abstraction levels.
- §3.3 + §3.5 — **False D2.B applied-accounting claim removed.** v0.2 stated "D2.B's POS N=100 confirmed `applied_accounting_mode=True` works correctly under load." Verified false: `applied_accounting_mode` is never set in `fuzzer.py` (`grep` returns no matches). Wiring `applied_accounting_mode=True` for `hybrid_cTS` and `v6_cTS` is now an explicit Batch 3 task. ArmKey citation fixed to `semantic_arm_universe.py:174-182` (not `bandit_ts.py`; bandit_ts imports it on line 25).
- §1.1 §4.1 — **`_detect_host_panic` checks BOTH** `"panicked at"` AND `"Guest panicked:"`. v6_driver_v2 only checks the former (single grep match at line 479); `arguzz_runner.py:89` checks both. The new primitive adopts the broader check.
- §4.4 + §8 — **`soundness_signal` ownership pinned**: primitive sets the boolean on `ArguzzInvocationResult.soundness_signal`; bridge/driver copies it to the row's `config_json`. Single owner, single direction.
- §11 task 1.7 — **Golden trace upgraded to two-tier**: Batch 1 lays down a cheap decision-sequence parity fixture (matches D2.A/D2.B precedent, <1s); Batch 3 adds a full DB byte-identity gate (modulo timestamps) AFTER `_dispatch_arm` refactor lands, to catch any downstream config-serialization drift.
- §13 — Test baseline: **609 passed, 19 skipped, 1 xfailed** (v0.2 said 18 skipped; verified actual is 19). NB: HEAD `e2c2256` IS the §9c postscript commit ("d2.b-ps-1: remove 5 dead arms from MUTATION_KINDS"), so this baseline is correctly post-postscript; v0.3's earlier "(post-§9c)" qualifier was technically accurate, just the count was off by one.
- §14 #7 + §11 Batch 4 acceptance — **Registration test reconciled to 24 cases** (4 D2.C kinds × 6 layers). v0.2 had a "96 cases (×4 instr-class coverage)" multiplier in §14 that was inconsistent with §4.8's "24 cases" definition. Instr-class coverage is the arm-construction test's job (§4.8 `test_d2c_arguzz_arm_construction.py`), not the registration test's.

**What is new in v0.2 (kept for historical context):**

- §1.5 — Empirical context from D2.B; 3-live / 5-dead A4 split.
- §5 — Per-kind mechanism analysis for all 4 V6 kinds.
- §6.3 — prove_success / soundness signal handling.
- §7 — Arm semantic certainty stack S1–S6 for V6 arms.
- §11 — Four-batch Composer breakdown with per-task acceptance gates.
- §14 — Acceptance criteria as hard gates for D2.C closure.

---

## Table of contents

1. [Goal](#1-goal)
2. [Non-goals](#2-non-goals-deliberately-out-of-d2c-scope)
3. [Codebase landscape](#3-codebase-landscape)
4. [Detailed change list (file by file)](#4-detailed-change-list-file-by-file)
5. [Per-kind mechanism analysis](#5-per-kind-mechanism-analysis-new-in-v02)
6. [Outcome classification + 4-channel rejection model adapted to Arguzz](#6-outcome-classification--4-channel-rejection-model-adapted-to-arguzz-new-in-v02)
7. [Arm semantic certainty stack for V6 arms](#7-arm-semantic-certainty-stack-for-v6-arms-new-in-v02)
8. [Decision matrix — primitive vs bridge vs driver](#8-decision-matrix--primitive-vs-bridge-vs-driver-responsibilities)
9. [Open questions — LOCKED (Q4 & Q8 v0.3)](#9-open-questions--locked-q4--q8-rewritten-in-v03)
10. [Decisions confirmed](#10-decisions-confirmed)
11. [Composer task breakdown](#11-composer-task-breakdown)
12. [Risks + mitigations](#12-risks--mitigations)
13. [What ships at the end of D2.C](#13-what-ships-at-the-end-of-d2c)
14. [Acceptance criteria](#14-acceptance-criteria)

---

## 1. Goal

D2.C delivers **three coordinated outputs**, layered for clean reuse across V6-uniform and (post-D2.D) V6-cTS / Hybrid-cTS campaigns:

1. **A subprocess primitive** (`a4/standalone/arguzz_invoke.py`) — a clean Python wrapper around `risc0-host --inject --inject-step <s> --inject-kind <k> --seed <s>` with parsing of `<trace>`, `<fault>`, `<constraint_fail>`, family residues, and prover-status tags. Returns a typed `ArguzzInvocationResult`. **Single source of truth** for Arguzz invocation.

2. **A bandit dispatcher** (`a4/standalone/mutations/arguzz_bridge.py`) — adapts the primitive to A4Fuzzer's `_create_mutation` contract for arms with `surface=arguzz_exec_fault`, so V6-cTS and Hybrid-cTS (D2.D) can natively schedule Arguzz mutations through the same `cTS_semantic_v2` selector as A4 mutations.

3. **A modernized V6-uniform driver** (`a4/standalone/v6_uniform_driver.py`) — drop-in successor to `v6_driver_v2.py` that:
   - Writes through `CoverageDB` (D2.A schema, with `outcome` column, normalized `constraint_loc`)
   - Uses the new `arguzz_invoke` primitive (single source of truth)
   - Preserves Arguzz's balanced-round-robin scheduler verbatim (so V6-uniform stays "Arguzz-faithful" as the baseline)

### 1.1 The Arguzz mutation kinds — per-variant scope (Pro `ProG_Report_3.md` §9 + §8 Track A)

D2.C exposes the Arguzz exec-fault mutation kinds in **two scope tiers** because Pro's `ProG_Report_3.md` §9 (lines 277-302) prescribes different kind sets for the two cTS-driven variants:

| Variant | Kind set | Constant | Pro reference |
|---------|----------|----------|---------------|
| **V6-cTS** (Arguzz scheduling test) | **All 11 `ENABLED_KINDS`** (§1.1.A below) — the same kind set V6-uniform runs | `MUTATION_KINDS_ARGUZZ_FULL` | `ProG_Report_3.md` §9 lines 283-285: "Arguzz kinds **only**, but selected by constrained TS" |
| **Hybrid-cTS** (A4-aug architecture) | **4 selected kinds** (§1.1.B below) — the top-4 of Pro's Track A priority list | `MUTATION_KINDS_ARGUZZ_SELECTED` | `ProG_Report_3.md` §9 lines 287-288: "A4-V5 kinds + **selected** Arguzz kinds in one shared arm space" + §8 Track A lines 228-238 priority list (top-4 selection rationale) |

**Why two scopes (not one):** the V6-uniform-vs-V6-cTS comparison is meant to isolate **scheduler effect alone** (uniform-over-applicable vs constrained-Thompson-sampling), so V6-cTS must use the same kind set as V6-uniform. If V6-cTS were restricted to 4 kinds while V6-uniform runs all 11, the comparison would confound scheduler effect with kind-set-restriction effect, defeating the experiment's purpose. Hybrid-cTS is a different question — there the goal is to **import** Arguzz terrain into the A4 arm space without double-counting against the existing A4 trace-cell arms, so a curated 4-kind subset (those that least overlap with A4's pure-A4 kinds) is correct.

#### 1.1.A V6-cTS scope: all 11 ENABLED_KINDS (Arguzz binary-supported)

`v6_driver_v2.py:168-173` defines `ENABLED_KINDS` as 11 entries, all of which the R2 V6 DB exercises with non-trivial row counts:

| # | Kind | What Arguzz does | Arguzz `<fault>` info shape | Instr-class restriction (`v6_driver_v2.py:176-191`) | R2 V6 DB rows |
|---|---|---|---|---|---|
| 1 | `INSTR_WORD_MOD` | Replace the instruction word the host is about to execute with a fully random `u32` | `"word:X => word:Y"` | All instructions | 752 |
| 2 | `PRE_EXEC_PC_MOD` | Mutate the PC immediately before fetch (forces the host to fetch from a wrong address) | `"pc:X => pc:Y"` | All instructions | 796 |
| 3 | `PRE_EXEC_MEM_MOD` | Mutate a heuristically-chosen memory address right before the cycle executes | `"MEM[$0xADDR] = VAL"` | All instructions | 756 |
| 4 | `PRE_EXEC_REG_MOD` | Mutate a register value before the cycle executes | `"reg[N] = VAL"` | All instructions | 744 |
| 5 | `BR_NEG_COND` | Invert a branch condition (BEQ → !BEQ, etc.) at the executing branch | (kind-only fault tag; no info shape) | `BRANCHES` only | 142 |
| 6 | `POST_EXEC_PC_MOD` | Mutate the PC immediately after execution (between this cycle's commit and the next fetch) | `"pc:X => pc:Y"` | All instructions (most informative on jumps/branches) | 722 |
| 7 | `POST_EXEC_MEM_MOD` | Mutate a memory address immediately after the cycle commits | `"MEM[$0xADDR] = VAL"` | All instructions | 767 |
| 8 | `POST_EXEC_REG_MOD` | Mutate a register value after the cycle's writeback | `"reg[N] = VAL"` | All instructions | 826 |
| 9 | `COMP_OUT_MOD` | Mutate the computational output of an ALU/multiplier/divider before commit | `"out:X => out:Y"` | `COMPUTATIONS` only (ALU ops; defined per `v6_driver_v2.py`) | 376 |
| 10 | `LOAD_VAL_MOD` | Mutate the value returned by a memory load instruction | `"out:X => out:Y"` | `LOADS` only (lb/lh/lw/lbu/lhu) | 76 |
| 11 | `STORE_OUT_MOD` | Mutate the value being stored to memory by a store instruction | `"out:X => out:Y"` | `STORES` only (sb/sh/sw) | 43 |

**Total R2 V6 DB rows:** 752 + 796 + 756 + 744 + 142 + 722 + 767 + 826 + 376 + 76 + 43 = **6000** (confirms uniform-over-applicable scheduler exercises all 11 kinds at non-trivial rates; the lower-row kinds are simply less applicable due to instruction-class rarity in the trace).

**Pre/post classification (v0.4 convention for the `pre_post` arm-shape axis, D2.A LOCKED):**
- `pre_exec`: kinds 1-5 (`INSTR_WORD_MOD`, `PRE_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `BR_NEG_COND`) — fault is injected before the cycle's logic executes.
- `post_exec`: kinds 6-11 (`POST_EXEC_*`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`) — fault is injected at or after the cycle's commit/writeback.

This is the first version of the spec where the `pre_post` axis carries non-trivial both-side values; in v0.3 all 4 kinds were `pre_exec`.

#### 1.1.B Hybrid-cTS scope: 4 selected kinds (Pro `ProG_Report_3.md` §8 Track A priority 1-4)

| # | Kind | What Arguzz does | Arguzz `<fault>` info shape | Pro Track A rank |
|---|---|---|---|---|
| **C.1** | `INSTR_WORD_MOD` | Replace the instruction word the host is about to execute with a fully random `u32` | `"word:X => word:Y"` | **§8 Track A #1** |
| **C.2** | `PRE_EXEC_MEM_MOD` | Mutate a heuristically-chosen memory address right before the cycle executes | `"MEM[$0xADDR] = VAL"` | **§8 Track A #2** |
| **C.3** | `PRE_EXEC_PC_MOD` | Mutate the PC immediately before fetch (forces the host to fetch from a wrong address) | `"pc:X => pc:Y"` | **§8 Track A #3** |
| **C.4** | `BR_NEG_COND` | Invert a branch condition (BEQ → !BEQ, etc.) at the executing branch | (kind-only fault tag; no info shape) | **§8 Track A #4** |

**Why these 4 for Hybrid-cTS (and only these 4):** Pro flagged them as the **top-4 in §8 Track A**'s "import high-yield Arguzz-style kinds into the V5 scheduler" priority list (`ProG_Report_3.md` lines 228-238). The remaining 3 entries in Track A's priority list (#5 POST_EXEC_REG_MOD, #6 POST_EXEC_MEM_MOD, #7 POST_EXEC_PC_MOD) plus the un-listed kinds (`PRE_EXEC_REG_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`) overlap heavily with A4's existing pure-A4 kinds in `a4/standalone/mutations/` (e.g., A4 already mutates register values and post-execution memory via the trace-cell surface) — bringing them into Hybrid as separate `arguzz_exec_fault` arms would duplicate coverage with the existing A4 trace-cell arms in the same shared arm space and dilute the Hybrid-cTS bandit's signal. **For V6-cTS standalone this concern does not apply** because V6-cTS has no A4 arms in its arm space — it's Arguzz-only.

**Binary capacity confirmed for both tiers.** The R2 V6 DB exercises all 11 kinds (counts above); for the 4-kind Hybrid subset the totals are INSTR_WORD_MOD 752, PRE_EXEC_MEM_MOD 756, PRE_EXEC_PC_MOD 796, BR_NEG_COND 142. The Arguzz binary supports both scope tiers — **no Rust work required for D2.C** (unlike D2.B, which needed 8 Rust handlers).

### 1.2 Arm-shape mapping (D2.A §1.1 + §8)

D2.C is **where the 5-field `ArmKey` actually gets exercised with non-`n/a` values for all 5 fields**, including (v0.4) non-trivial both-side values for `pre_post`:

| Kind | `surface` | `mutation_kind` | `semantic_zone` | `opcode_class` (per-instruction at step) | `pre_post` | Hybrid-cTS scope? | V6-cTS scope? |
|---|---|---|---|---|---|---|---|
| `INSTR_WORD_MOD` | `arguzz_exec_fault` | `INSTR_WORD_MOD` | from `step_to_zone` (e.g., `core_arithmetic`) | `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system` | `pre_exec` | ✅ | ✅ |
| `PRE_EXEC_PC_MOD` | `arguzz_exec_fault` | `PRE_EXEC_PC_MOD` | zone | as above | `pre_exec` | ✅ | ✅ |
| `PRE_EXEC_MEM_MOD` | `arguzz_exec_fault` | `PRE_EXEC_MEM_MOD` | zone | as above | `pre_exec` | ✅ | ✅ |
| `PRE_EXEC_REG_MOD` | `arguzz_exec_fault` | `PRE_EXEC_REG_MOD` | zone | as above | `pre_exec` | ❌ | ✅ |
| `BR_NEG_COND` | `arguzz_exec_fault` | `BR_NEG_COND` | zone | **`branch` only** (BR_NEG_COND is BRANCHES-only per `v6_driver_v2.py:183-184`) | `pre_exec` | ✅ | ✅ |
| `POST_EXEC_PC_MOD` | `arguzz_exec_fault` | `POST_EXEC_PC_MOD` | zone | as above | `post_exec` | ❌ | ✅ |
| `POST_EXEC_MEM_MOD` | `arguzz_exec_fault` | `POST_EXEC_MEM_MOD` | zone | as above | `post_exec` | ❌ | ✅ |
| `POST_EXEC_REG_MOD` | `arguzz_exec_fault` | `POST_EXEC_REG_MOD` | zone | as above | `post_exec` | ❌ | ✅ |
| `COMP_OUT_MOD` | `arguzz_exec_fault` | `COMP_OUT_MOD` | zone | **ALU subset only** (`COMPUTATIONS` per `v6_driver_v2.py:185-186` ≈ `arithmetic`) | `post_exec` | ❌ | ✅ |
| `LOAD_VAL_MOD` | `arguzz_exec_fault` | `LOAD_VAL_MOD` | zone | **`memory_load` only** (`LOADS` per `v6_driver_v2.py:187-188`) | `post_exec` | ❌ | ✅ |
| `STORE_OUT_MOD` | `arguzz_exec_fault` | `STORE_OUT_MOD` | zone | **`memory_store` only** (`STORES` per `v6_driver_v2.py:189-190`) | `post_exec` | ❌ | ✅ |

**Note on taxonomy alignment (v0.3 LOCKED, preserved in v0.4):** the opcode_class strings used here match `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 line 48 (the 7-class set + `n/a`). The 7-class set is also what the synthetic test at `test_d2a_arm_shape_arguzz_simulation.py:34-38` exercises. This is **distinct** from `semantic_zones.OPCODE_CLASS_BY_MAJOR` (an 8-class set: `alu`/`mul`/`div`/`mem`/`branch_or_ctrl`/`poseidon`/`sha`/`other`) which is the **CGC/telemetry** taxonomy used by `compressed_global_extractor` for global-context compression. The two taxonomies serve different purposes (arm identity vs telemetry compression) and intentionally have different granularities (`memory_load` vs `memory_store` are split in arm-shape but lumped as `mem` in CGC). See §4.6 for the full discussion.

**Note on `pre_post` axis (v0.4):** v0.3 had all 4 D2.C kinds at `pre_exec`, leaving the `pre_post` axis effectively unidirectional. v0.4's expansion to 11 kinds gives the axis non-trivial both-side values: 5 `pre_exec` kinds + 6 `post_exec` kinds. The convention used: kinds whose Arguzz mechanism intercepts state **before the cycle's logic executes** are `pre_exec` (PRE_EXEC_*, INSTR_WORD_MOD, BR_NEG_COND); kinds whose mechanism intercepts state **at or after the cycle's commit/writeback** are `post_exec` (POST_EXEC_*, COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD). LOAD_VAL_MOD and STORE_OUT_MOD are classified as `post_exec` because they intercept the *result* of the load/store after the address has been computed; this is the post-execution intercept point even though the cycle itself hasn't fully committed yet.

**This is the moment the synthetic test in D2.A §4.6 / §1.2 was rehearsing**: in D2.C, real Arguzz fuzzing produces arm pulls with non-trivial `opcode_class` AND non-trivial `pre_post` (v0.4: with both `pre_exec` and `post_exec` populated for V6-cTS). The cTS scheduler's per-arm counts and Beta posteriors become meaningful per-opcode-class AND per-pre_post for the first time.

**Arm-space estimate (sha2-host, post-D2.B-postscript):**

| Surface | Kinds | Zones (active) | Opcode classes | Pre/post | Raw arm count | After applicability filtering |
|---|---|---|---|---|---|---|
| `A4_trace_cell` (V5-shape) | 11 (8 V5 + 3 D2.B-live) | ~10 | n/a | n/a | 110 | ~50–80 |
| `arguzz_exec_fault` (Hybrid-cTS scope, 4 SELECTED kinds) | 4 | ~10 | **7** (D2.A-aligned) | **1 (pre_exec)** for 4-kind set | **280** (4 × 10 × 7 × 1) | **~110–160** (BR_NEG_COND collapses to branch class only — per-zone count drops from 28 to ~10; `ecall_mret` / `system` arms are empty on sha2-host today but reserved per D2.A) |
| `arguzz_exec_fault` (V6-cTS scope, 11 FULL kinds) | 11 | ~10 | **7** (D2.A-aligned) | **2** (`pre_exec` for 5 kinds, `post_exec` for 6 kinds — per §1.1.A convention) | **~770** (5 pre_exec kinds × 10 zones × 7 classes × 1 + 6 post_exec kinds × 10 zones × 7 classes × 1; `BR_NEG_COND`/`COMP_OUT_MOD`/`LOAD_VAL_MOD`/`STORE_OUT_MOD` are class-restricted but counted in raw) | **~200–350 actual** (BR_NEG_COND collapses to branch only ≈ 10; COMP_OUT_MOD ≈ arithmetic only ≈ 10; LOAD_VAL_MOD ≈ memory_load only ≈ 10; STORE_OUT_MOD ≈ memory_store only ≈ 10; the remaining 7 unrestricted kinds populate all 7 classes × 10 zones with sha2-host's instruction mix giving ~5–8 zones with non-empty class-specific arms) |
| **Hybrid V7 total (Hybrid-cTS variant)** | 11 A4 + 4 Arguzz selected = 15 effective | ~10 | mixed | mixed | **~390** raw | **~160–240 actual** |
| **V6-cTS total (V6-cTS variant)** | 0 A4 + 11 Arguzz full | ~10 | 7 | 2 | **~770** raw | **~200–350 actual** |

**Both variants are within Pro's "100s of arms" soft ceiling** (`ProG_Report_3.md` §17), but **V6-cTS is approaching the 300-arm "consider reducing" advisory threshold** mentioned in §9 Q9. The existing reduction levers (merge `jump` into `branch` opcode_class; drop zones with <5 steps) remain available; Batch 2 measurement reports actual numbers and Composer proposes reductions only if needed. The bandit's early-exploration phase: V6-cTS at ~300 arms × ~3 pulls/arm = ~900 mutations for minimal coverage; Hybrid-cTS at ~200 arms × ~3 pulls/arm = ~600 mutations. Both well within the planned N=6000 budget. **Concrete arm-space measurement is required during D2.C Batch 2** (the cross-cutting test asserts the exact arm count after the bridge wires into `SemanticArmUniverse.build(arguzz_kinds=...)`); the prediction here is a soft sanity check.

### 1.3 Three-layer architecture

The cleanest way to share Arguzz invocation across V6-uniform AND V6-cTS / Hybrid-cTS is **layered**:

```
┌──────────────────────────────────────────────────────────────────┐
│ DRIVER LAYER  (Python entry points)                              │
│                                                                  │
│  v6_uniform_driver.py        A4Fuzzer (selector=hybrid_cTS)      │
│  (balanced-round-robin       (cTS_semantic_v2 over Hybrid arms)  │
│   scheduler, V6-faithful)    (D2.D wires this up)                │
│            │                          │                          │
│            ↓                          ↓                          │
└────────────┼──────────────────────────┼──────────────────────────┘
             │                          │
┌────────────┼──────────────────────────┼──────────────────────────┐
│ BRIDGE LAYER                                                     │
│                                                                  │
│            │                  mutations/arguzz_bridge.py         │
│            │                  (adapts primitive to A4's          │
│            │                   _create_mutation contract for     │
│            │                   surface=arguzz_exec_fault arms)   │
│            │                          │                          │
│            ↓                          ↓                          │
└────────────┼──────────────────────────┼──────────────────────────┘
             │                          │
┌────────────┴──────────────────────────┴──────────────────────────┐
│ PRIMITIVE LAYER                                                  │
│                                                                  │
│              a4/standalone/arguzz_invoke.py                      │
│  (subprocess + UTF-8-safe decode + tag parsers + outcome mapper) │
│                                                                  │
│                          │                                       │
│                          ↓                                       │
│              risc0-host --inject --inject-step S --inject-kind K │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Why three layers (not two):**

- **Layer separation isolates the brittle subprocess + parsing concerns** in `arguzz_invoke.py`. Both downstream consumers (driver, bridge) get a typed `ArguzzInvocationResult` and don't have to know about UTF-8 decode, regex tags, `subprocess.TimeoutExpired`, or panic-string heuristics.
- **`v6_driver_v2.py` recovery confirms the pattern**. It hand-rolled all three layers in 608 lines; D2.C refactors out the primitive cleanly without behavioral change.
- **`a4/arguzz_dependent/arguzz_runner.py` is the obsolete predecessor** — it has the same primitive job but with worse output handling (uses `text=True` which crashes on non-UTF-8 bytes; `v6_driver_v2` explicitly fixed this with `_decode_safe`). D2.C **does not reuse** `arguzz_runner.py`; we adopt `v6_driver_v2`'s improved invocation logic. See §9 Q1.

### 1.4 V6-uniform driver: modernize, not preserve as-is

Two options for `v6_driver_v2.py`:

| Option | Pros | Cons |
|---|---|---|
| **(A) Keep `v6_driver_v2.py` as-is, only use it for V6-uniform** | Zero behavioral risk; bit-identical R2 reproduction | Doesn't get D2.A's `outcome` column or normalized `constraint_loc`; can't be compared head-to-head with V5/Hybrid using the same analysis scripts; duplicates schema definitions; perpetuates `constraint_loc_normalize.py` post-hoc normalization for V6 DBs |
| **(B) Replace with `v6_uniform_driver.py` that writes through `CoverageDB`** | Single schema across all variants; full A4 telemetry parity; D2.G analysis works uniformly; `outcome` column for free; normalized `constraint_loc` at write-time | Schema diff vs R2: R2 V6 DBs have raw `constraint_loc`, new V6 DBs will have `Name@basename:line`. D2.G's cross-variant analysis must normalize R2 historically once (already exists as `constraint_loc_normalize.py`). |

**Locked: Option B (replace).** Per §9 Q3. D2.G analysis hinges on cross-variant comparability; if V6-uniform DBs have a different schema, we re-invent the post-hoc normalizer for every analysis. **And** the R2 V6 DBs are post-hoc-normalized today via `constraint_loc_normalize.py` — going through `CoverageDB` means we get the same canonicalization at write-time, which is exactly the D2.A §3.4 principle ("write canonical, don't normalize after").

`v6_driver_v2.py` stays archived at `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` as a frozen reference implementation. The active V6-uniform driver becomes `a4/standalone/v6_uniform_driver.py`.

### 1.5 Empirical context from D2.B (NEW in v0.2)

**Why D2.C matters more after D2.B's findings.** D2.B implemented 8 A4 mutation kinds Pro requested, of which **only 3 are LIVE** (`TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD`) — the other 5 (`CYCLE_MODE_MOD`, `TXN_ADDR_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`, `CYCLE_STATE_MOD`) are mechanism-proven dead arms (W-17 `set_cycle` overwrite for the cycle fields, W-18 execution-derived witness keys for the txn fields). They are removed from `A4Fuzzer.MUTATION_KINDS` post-§9c.

This means **the post-D2.B A4 trace-cell arm space is 11 kinds** (8 V5 + 3 D2.B-live), not 16. ProG_Report_3 §13 explicitly argued the A4 catalog was the ceiling, and D2.B has now narrowed that ceiling further than expected.

**D2.C is the relief valve.** The 4 V6 kinds inject mutations during execution, perturbing the guest's register/memory/PC/branch state and letting the VM naturally propagate the consequences through subsequent cycles. This is **mechanically distinct** from A4's post-execution trace-cell mutations, which D2.B confirmed are limited to fields that (a) actually enter the witness via `extern_*` returns AND (b) survive the `set_cycle` overwrite mechanism. V6 mutations sit upstream of the trace altogether — they corrupt the execution itself, then the preflight trace is generated from the corrupted execution, then the witness is generated from that trace. The trace then encodes a *consistent corruption* that A4's single-cell mutations cannot easily produce.

The Pro-facing significance: **post-D2.C, the Hybrid-cTS campaign has 11 LIVE A4 arms + 4 Arguzz arms = 15 effective mutation kinds**, with the 11 covering deep witness-internal surfaces and the 4 covering execution-time perturbations. The V6-cTS variant additionally exercises 11 Arguzz kinds standalone. This is the "Hybrid V7" architecture ProG_Report_3 §15 prescribed (Track A from §8 + scheduler swap from §9).

**Reference:** [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md) §10 (campaign implications) + [`IV_POS_8_NOTES_FOR_PRO.md`](./IV_POS_8_NOTES_FOR_PRO.md) NFP-11 (dead/live A4-kind split).

### 1.6 When do we actually test the mutations work? (per D2.B §1.4)

D2.B's 5-layer testing framework adapted to D2.C:

| # | Layer | What it asserts | When (Composer batch) | Gating? |
|---|---|---|---|---|
| **1** | **Subprocess mock test** (`tests/test_d2c_arguzz_invoke_mock.py`) | Stub `subprocess.run` to return canned Arguzz stdout (sampled from R2 V6 logs). `arguzz_invoke.run()` parses correctly: extracts faults, failures, family residues; sets outcome correctly for all 5 cases (timeout/panic/prove_success/prove_error w. failures/prove_error w/o failures). **Pure Python, no binary.** | Batch 1 | No |
| **2** | **Real-binary single-mutation test** (`tests/test_d2c_arguzz_invoke_real_binary.py`) | Gated on `A4_REAL_BINARY=1`: invoke `arguzz_invoke.run()` against the real `risc0-host` binary once per kind (C.1–C.4) at a single appropriate step. Assert: at least 1 `<fault>` tag parsed; outcome ∈ {APPLIED, ERROR}; `wall_s < 90` (timeout). **This is the binary-level smoke gate for D2.C.** | Batch 1 | **YES** (binary capacity de-risking) |
| **3** | **Bridge wiring test** (`tests/test_d2c_arguzz_bridge.py`) | Stub `arguzz_invoke.run()` with canned `ArguzzInvocationResult`. Verify `arguzz_bridge.create_mutation_for_arm(ArmKey(surface="arguzz_exec_fault", ...), step, ...)` produces a sensible config + invocation, and that `outcome` flows back to `MutationOutcome` correctly. **Mocked invocation, real bandit.** | Batch 2 | No |
| **4** | **Arm-construction test** (`tests/test_d2c_arguzz_arm_construction.py`) | Synthetic `InspectionData`. `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL)` AND `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED)` produce arms with 5-field `ArmKey`; opcode_class derived correctly for branch/arith/load/store; class-restricted kinds (BR_NEG_COND/COMP_OUT_MOD/LOAD_VAL_MOD/STORE_OUT_MOD) only appear when their respective instruction class is present in the trace; `pre_post` matches `_PRE_POST_BY_KIND[kind]`. **Unit-level, no subprocess.** | Batch 2 | No |
| **5** | **V6-uniform driver end-to-end smoke** (`tests/test_d2c_v6_uniform_driver_smoke.py`) | Gated on `A4_REAL_BINARY=1`: run `v6_uniform_driver.py main(num=50)` once against the dev box's `risc0-host`. Assert: DB has 50 `mutations` rows, ≥6 of the 11 ENABLED_KINDS appear (with the 4 SELECTED kinds guaranteed present), `outcome` column populated, `coverage.constraint_loc` is `Name@basename:line` format (normalized), `compressed_global_coverage` rows present. | Batch 3 | **YES** (driver smoke gate) |
| **6** | **A4Fuzzer Hybrid integration smoke** (`tests/test_d2c_hybrid_smoke.py`) | Stub `arguzz_invoke.run()`; run `A4Fuzzer.run_campaign(N=50, selector="hybrid_cTS")`; assert both `surface=A4_trace_cell` and `surface=arguzz_exec_fault` arms get pulled, both contribute to `mutations.outcome=applied`, cTS scheduler counts pulls separately for each surface. (NB: a real `hybrid_cTS` selector is D2.D's job — this test uses a temporary `--selector` hook that Batch 4 wires for testing only; it's a forerunner.) | Batch 4 | No (forerunner; D2.D will harden) |
| **7** | **POS smoke (D2.E)** | 4-variant N=200 mini-smoke. Confirms V6-uniform, V6-cTS, Hybrid-cTS all produce non-empty DBs on the real POS infrastructure. | D2.E (after D2.D lands) | (D2.E concern) |

**Layer 2 is the load-bearing real-binary gate.** Layer 2 covers the 4 SELECTED kinds (Batch 1 scope; Hybrid-cTS-relevant); the additional 7 V6-cTS-only kinds are exercised at the kind-string level via Layer 1 mock and operationally via Layer 5 (V6-uniform real-binary smoke) — adequate coverage for the v0.4 expanded scope without bloating Batch 1's gated test set. If the dev box's `risc0-host` doesn't emit `<fault>` tags for one of the 4 SELECTED kinds, we discover it in Batch 1; if one of the 7 V6-cTS-only kinds fails, Batch 3's Layer 5 smoke catches it. The R2 V6 DBs serve as a sanity-check oracle: we already know what good Arguzz output looks like for all 11 kinds.

**Layer 5 is the schema-parity gate.** This is where we confirm the modernized V6-uniform driver produces DBs pairwise-comparable with V5/Hybrid DBs (the linchpin of D2.G analysis).

---

## 2. Non-goals (deliberately out of D2.C scope)

- **Pure-A4 kind expansion** — already done in D2.B (closed at `e2c2256`).
- **Variant CLI / fuzzer dispatch (D2.D)** — D2.C provides the primitives; D2.D wires them up.
- **POS smoke (D2.E)** — D2.C ships local-only tests.
- **POS dispatch (D2.F)** — D2.E's gate.
- **Arguzz binary changes** — binary is treated as a black-box; capacity already verified.
- **`a4/arguzz_dependent/arguzz_runner.py` revival** — explicitly deprecated; new code path is `arguzz_invoke.py`. We **do not delete** `arguzz_runner.py` but we mark its docstring as legacy/deprecated. See §9 Q1.
- **`a4/arguzz_dependent/arguzz_parser.py` revival** — partially adopted: the `ArguzzFault` dataclass and regex patterns are battle-tested; the new `arguzz_invoke.py` **imports** from it (does not duplicate the regex logic). See §9 Q2.
- **Subprocess pooling / parallelism** — single-process, single-subprocess at a time; this is what `v6_driver_v2.py` does in production R2 runs and what Pro's "applied-mutation accounting" requires.
- **Variant comparison analysis (D2.G)** — D2.C ships infrastructure; D2.G produces the per-variant findings.
- **A new bandit scheduler family** — D2.C does NOT change `bandit_ts.py`'s scheduler algorithm. The cTS scheduler from D2.A handles 5-tuple arms uniformly; D2.C just provides arm construction + dispatch wiring.
- **The other 7 V6 ENABLED_KINDS** (`POST_EXEC_*`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD`) — Pro deprioritized; out of scope.

---

## 3. Codebase landscape

### 3.1 Already in tree

| File | Status | Role in D2.C |
|---|---|---|
| `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (608 lines) | Recovered in D2.A; frozen | Reference implementation. The scheduler + parsing patterns are copied into the new layered architecture. **Do NOT modify.** |
| `a4/arguzz_dependent/arguzz_runner.py` (116 lines) | Obsolete; will be deprecated | Legacy. `CONSTRAINT_CONTINUE=1` env-var pattern is useful, but `text=True` subprocess kwarg is a known bug `v6_driver_v2` fixed. **Add deprecation docstring (§4.7); do not delete.** |
| `a4/arguzz_dependent/arguzz_parser.py` (181 lines) | Partially adopted | `ArguzzFault.parse()` regex handlers for 6 fault formats (word, out, data, pc, reg_assign, mem_assign) are reused verbatim via re-import from `arguzz_invoke.py`. **Do NOT modify.** |
| `a4/standalone/compressed_global_extractor.py` | Already supports V6 kinds via runtime `_TXN_ROLE_BY_KIND` patches in `v6_driver_v2.py` (lines 74–84) | **D2.C makes these patches permanent** (move them into `_TXN_ROLE_BY_KIND` directly so V6-uniform doesn't have to patch at runtime). |
| `a4/core/inspection_data.py` | Existing — provides `InspectionData.from_inspection(host, args)` | Reused as-is in `v6_uniform_driver.py` bootstrap. |
| `a4/standalone/zone_classifier.py` | Existing — `classify_zones(insp) → Dict[step, zone]` | Reused as-is. |
| `a4/standalone/semantic_zones.py` | Existing — `SEMANTIC_ZONES`, `major_minor_to_core_zone()`, **`major_to_opcode_class()` (already exists at line 101)** | Reused unchanged. v0.2 erroneously claimed D2.C adds this helper; it already exists. See §4.6 for the two-taxonomy split. |
| `a4/standalone/bandit_ts.py` | D2.A foundation — `MutationOutcome`, `ConstrainedTSScheduler`, `applied_accounting_mode` (imports `ArmKey` from `semantic_arm_universe` on line 25) | **Read-only consumer.** D2.C does NOT modify the scheduler. |
| `a4/standalone/coverage_db.py` | D2.A foundation — `CoverageDB.record_mutation(outcome=...)` etc. | Driver layer calls these. |
| `a4/standalone/semantic_arm_universe.py` | D2.A foundation — **defines `ArmKey`** (5-tuple dataclass at lines 174-182) + `SemanticArmUniverse.build()` with V5-shape arms | **D2.C extends** with `arguzz_kinds: Optional[List[str]] = None` parameter (v0.4: replaces v0.3's `include_arguzz_kinds: bool` toggle for per-strategy kind-list passthrough). |
| `a4/standalone/fuzzer.py` | D2.B closed — A4-only mutation dispatch in `_create_mutation` | **D2.C extends** with a new dispatch branch for `surface=arguzz_exec_fault` arms. |

### 3.2 D2.A foundation in use

- `bandit_ts.MutationOutcome` enum (`APPLIED`, `SKIPPED`, `ERROR`) — D2.C maps Arguzz raw outcomes (timeout, panic, prove_success, prove_error w. failures, prove_error w/o failures, other) onto this enum.
- `bandit_ts.ConstrainedTSScheduler.update_with_outcome(arm, outcome, success)` — D2.C's bridge calls this for `surface=arguzz_exec_fault` arms; `applied_accounting_mode=True` ensures only APPLIED counts as a pull (matches Pro's spec §8).
- `ArmKey(surface, kind, zone, opcode_class, pre_post)` constructor — D2.C uses the **full 5-field constructor** for Arguzz arms (NOT `ArmKey.v5()`).
- `mutations.outcome` column (D2.A nullable) — D2.C populates this for every V6-uniform mutation row.
- `ConstraintFailure.short_loc()` — D2.C ensures V6 `failures.constraint_loc` writes go through this normalization at write-time.
- `extract_compressed_global_contexts` / `to_storage_rows` (`compressed_global_extractor.py`) — reused as-is for V6 CGC computation.

### 3.3 D2.B contribution to D2.C

D2.B introduced or hardened several pieces that D2.C depends on or aligns with:

- **The 4-channel rejection model** (`IV_POS_8_D2_B_MECHANISM_REPORT.md` §9): channels C1 (`<constraint_fail>`), C2 (verify segment panic), C3 (`<a4_family_residue>` Hook 3), C4 (`<a4_error>` A4-dispatcher). D2.C **adapts** this to V6 mutations in §6: C1/C2/C3 are reused; C4 is N/A (no A4 dispatcher in the Arguzz path); a new **C5** channel is added but narrowly scoped (`prover_status="start" AND host_panic` — the **real** pre-prover guest crash, ~5.2% of R2 V6 rows; v0.2 incorrectly inflated this to "95% of mutations").
- **The §9c postscript cleanup of `MUTATION_KINDS`** — guarantees that when D2.C wires Arguzz arms in, `SemanticArmUniverse.build()` sees the cleanest A4 arm set (no dead arms inflating arm counts).
- **The cross-cutting registration test pattern** (`test_d2b_arm_registration.py`) — D2.C's Batch 4 cross-cutting test follows the same template (parametrized over surfaces × kinds × layers).
- **The soundness-bug guard** (D2.B §9b) — for D2.C's prove_success bucket, a SoundnessBugSuspected-class signal is raised when (a) the mutation was applied (Arguzz reports a fault was injected) AND (b) the verifier accepted the proof. See §6.3.
- **The 4-channel rejection model (NFP-11)** — D2.C extends this to V6 mutations: C1 (`<constraint_fail>`), C2 (`verify segment` panic / Path B), C3 (Hook 3 family residue), C4 N/A (no A4 dispatcher), plus a new C5 channel (`prover_status="start" AND host_panic` — the true pre-prover guest crash, ~5.2% of R2 V6 rows, not the 94.6% figure cited in v0.2). The 1407 `prover_status="error" AND not has_failures` rows from R2 V6 are the V6-equivalent of the D2.B at_write Path B finding (constraint detected at global polynomial level, not local witgen EQZ) — they should count as APPLIED+REJECTED and be tagged `failure_recording_gap=True`.

**Note (v0.3 correction):** v0.2 stated *"D2.B's POS N=100 confirmed `applied_accounting_mode=True` works correctly under load. D2.C inherits this with no scheduler changes."* This is **false**. `applied_accounting_mode` is never set anywhere in `fuzzer.py` (`grep applied_accounting_mode a4/standalone/fuzzer.py` returns no matches). D2.B's POS run used `bandit-16` (the legacy scheduler interface), not `cTS_semantic_v2` with `applied_accounting_mode=True`. Wiring `applied_accounting_mode=True` for `hybrid_cTS` / `v6_cTS` AND replacing `v2_scheduler.update(kind, zone, success)` with `update_with_outcome(arm, outcome, success=...)` on the Arguzz paths is an explicit **Batch 3 task** (§11.3.2a). V5_control keeps `applied_accounting_mode=False` so the golden trace stays byte-identical.

### 3.4 D2.D's role (out of scope, but informs D2.C design)

D2.D wires four variants:

- **V5_control** — existing A4Fuzzer with `selector_strategy="cTS_semantic_v2"`, surface=`A4_trace_cell` only.
- **V5_expanded** — V5 schedule but with the 11 post-postscript A4 kinds (V5 + 3 D2.B-live).
- **V6-uniform** — `python -m a4.standalone.v6_uniform_driver` (the modernized V6 driver).
- **V6-cTS** — `A4Fuzzer` with `selector_strategy="cTS_semantic_v2"` over Arguzz-only arms.
- **Hybrid-cTS** — `A4Fuzzer` with `selector_strategy="cTS_semantic_v2"` over A4 + Arguzz arms together.

D2.C **enables** V6-uniform, V6-cTS, and Hybrid-cTS by providing the primitive + bridge. The CLI flags + variant selection are D2.D's responsibility. **However**, D2.C must expose the right hooks for D2.D to call:

- `SemanticArmUniverse.build(data, mutation_kinds, arguzz_kinds: Optional[List[str]] = None)` — kind-list parameter (v0.4 signature change). `None` (default) preserves V5-shape behavior; passing a list emits Arguzz arms restricted to that kind list.
- `A4Fuzzer._create_mutation(kind, step, surface=...)` — surface-aware dispatch (D2.C extends the existing `_create_mutation` with a new branch).
- **Two kind-list constants** (v0.4 split, defined in `a4/standalone/mutations/arguzz_bridge.py`):
  - `MUTATION_KINDS_ARGUZZ_FULL = ("PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD", "BR_NEG_COND", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD", "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD")` — all 11 ENABLED_KINDS, used by **V6-cTS**. Order matches `v6_driver_v2.py:168-173` verbatim for trace-comparability with the V6-uniform driver.
  - `MUTATION_KINDS_ARGUZZ_SELECTED = ("INSTR_WORD_MOD", "PRE_EXEC_MEM_MOD", "PRE_EXEC_PC_MOD", "BR_NEG_COND")` — Pro's §8 Track A priority 1-4 subset, used by **Hybrid-cTS**.

**D2.D wiring expectation (per §4.4):**

```python
if selector_strategy == "v6_cTS":
    arguzz_kinds = MUTATION_KINDS_ARGUZZ_FULL          # 11
elif selector_strategy == "hybrid_cTS":
    arguzz_kinds = MUTATION_KINDS_ARGUZZ_SELECTED      # 4
else:
    arguzz_kinds = None                                # V5-shape only
universe = SemanticArmUniverse.build(data, kinds, arguzz_kinds=arguzz_kinds)
```

### 3.5 Pre-flight due-diligence checklist (NEW in v0.2)

Before Composer kicks off Batch 1, the following must be confirmed (Opus does this; ≤1 hour):

| Check | Status | Source |
|---|---|---|
| Arguzz binary supports all 11 D2.C ENABLED_KINDS at the binary level (V6-cTS scope) | ✅ Confirmed via R2 V6 DB `pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000.db` — all 11 kinds present (counts in §1.1.A; row totals 752, 796, 756, 744, 142, 722, 767, 826, 376, 76, 43 = 6000) | §1.1.A, §5.5 |
| `ArguzzFault.parse()` handles all 11 V6-cTS kinds' `<fault>` formats | ✅ Confirmed — `arguzz_parser.py` lines 56–131 cover the 6 fault formats (`word`, `out`, `data`, `pc`, `reg_assign`, `mem_assign`) which is the union over all 11 kinds; `BR_NEG_COND` is a kind-only tag with no info shape | §1.1.A |
| `v6_driver_v2.py` is in tree and readable | ✅ Confirmed — `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` 608 lines | §3.1 |
| `MutationOutcome` enum has the right values | ✅ Confirmed — `bandit_ts.py` line 57 `MutationOutcome(str, Enum) {APPLIED, SKIPPED, ERROR}` | §3.2 |
| `ConstrainedTSScheduler.applied_accounting_mode` code path exists | ✅ Confirmed in `bandit_ts.py` lines 310–322 (the flag and `update_with_outcome` are implemented). **Not yet wired in `fuzzer.py`** — D2.B's POS N=100 used `bandit-16` (legacy interface), NOT `cTS_semantic_v2` with `applied_accounting_mode=True`. Wiring it for `hybrid_cTS`/`v6_cTS` is an explicit Batch 3 task (§11.3.2a). v0.2 claimed "D2.B POS N=100 exercised it" — that was false; v0.3 corrects it. | §3.2 + §11.3.2a |
| 5-tuple `ArmKey` constructor accepts arbitrary surface | ✅ Confirmed — `semantic_arm_universe.py` lines 174–182, dataclass with `surface: str` (NB: `bandit_ts.py` imports it on line 25; v0.2 cited the wrong file) | §3.2 |
| `CoverageDB.record_mutation(outcome=...)` accepts string | ✅ Confirmed — `coverage_db.py` line 740, `outcome: Optional[str]` parameter | §3.2 |
| `compressed_global_extractor._TXN_ROLE_BY_KIND` is patchable | ✅ Confirmed — currently a module-level dict; D2.C makes the V6 extensions permanent (§4.6) | §3.1 |
| `classify_zones(insp)` works with a baseline trace | ✅ Confirmed — `zone_classifier.py` line 37 takes `InspectionData` | §3.1 |

**All preconditions met.** D2.C Batch 1 can kick off as soon as the spec is locked.

---

## 4. Detailed change list (file by file)

### 4.1 `a4/standalone/arguzz_invoke.py` (NEW — primitive layer)

| Item | Detail |
|---|---|
| `ArguzzInvocationResult` dataclass | Fields: `rc: int`, `outcome: MutationOutcome` (from D2.A), `prover_status: str` (`"success"`/`"error"`/`"none"`), `wall_s: float`, `faults: list[ArguzzFault]`, `failures: list[ConstraintFailure]`, `family_residues: list`, `family_details: list`, `global_residue: dict`, `host_panic: bool`, `crash_reason: str`, `traces: list[ArguzzTrace]` (for offset computation), `raw_stdout: str` (kept for debugging, may be large but capped at 4 KB tail for memory safety). |
| `run(host: str, host_args: list[str], step: int, kind: str, seed: int, *, timeout: float = 90.0, env: Optional[dict] = None) -> ArguzzInvocationResult` | Pure function. Replicates `v6_driver_v2.py::run_inject` + tag parsing + outcome classification. Returns a fully-populated `ArguzzInvocationResult`. **Single source of truth for Arguzz invocation.** |
| `_decode_safe(b: bytes \| None) -> str` | Copied verbatim from `v6_driver_v2.py` lines 328–340. UTF-8 safe decode with `errors='replace'`; handles raw register/memory dumps in panic stack traces. |
| `_classify_outcome(rc: int, host_panic: bool, prover_status: str, has_failures: bool) -> tuple[MutationOutcome, dict]` | **prover_status-PRIMARY** mapping (LOCKED in §9 Q4 v0.3 — Option C). Returns `(outcome, extra_tags)` where `extra_tags` may include `{"soundness_signal": True}` or `{"failure_recording_gap": True}`. Decision tree (top to bottom; first match wins): (1) `rc==124` → `(ERROR, {})` (timeout); (2) `prover_status=="success" AND not host_panic` → `(APPLIED, {"soundness_signal": True})` (Arguzz fault injected + verifier accepted — either accepted-invalid bug or fault-no-op); (3) `prover_status=="error" AND has_failures` → `(APPLIED, {})` (Path A — local witgen EQZ caught the mutation, happy path); (4) `prover_status=="error" AND not has_failures` → `(APPLIED, {"failure_recording_gap": True})` (Path B — prover errored at global polynomial / verify-segment level without emitting `<constraint_fail>` tags; bandit credits as APPLIED, D2.G triages via Hook 3 channel C3); (5) `prover_status=="start" AND host_panic` → `(SKIPPED, {})` (true C5 — prover started, guest crashed before prover finished; this is the ~5.2% pre-prover bucket from R2 V6); (6) `prover_status=="start" AND has_failures` → `(APPLIED, {})` (Path A fired during witgen, prover record still showing "start" because the panic happened before the prover emitted a final status; the constraint_fail tags are the authoritative signal); (7) anything else → `(ERROR, {})` (edge: 8 rows in R2 V6 with `outcome="other"`, `prover_status="start"`, no failures — unclear semantics, treat as ERROR until triaged). **Rationale:** v0.2 mapped 5497 of 6000 R2 V6 rows (91.6%) to ERROR via `host_panic → ERROR`. That threw away the bandit signal for every mutation that the prover successfully detected. v0.3 routes these to APPLIED, matching Pro's applied-mutation accounting intent and giving the bandit useful feedback. |
| `_detect_host_panic(stdout: str) -> tuple[bool, str]` | True if `"panicked at " in stdout` **OR** `"Guest panicked:" in stdout`. v6_driver_v2 only checks the former (single grep match at line 479); `arguzz_runner.py:89` checks both. The new primitive adopts the broader check to catch guest-side panic patterns the legacy driver misses. Returns the panic line (capped at 256 chars) as the crash reason. |
| Re-exports for downstream | `ArguzzFault` (from `a4.arguzz_dependent.arguzz_parser`), `ArguzzTrace` (same), `ConstraintFailure` (from `a4.core.constraint_parser`), `parse_family_residues` / `parse_family_detail` / `parse_global_residue` (from `a4.core.touch_coverage`). |
| Logging | Quiet by default. Module-level logger `a4.arguzz_invoke` available for `--debug` runs. |
| Kind-list constants | **Defined in `a4/standalone/mutations/arguzz_bridge.py`** (§4.2), NOT in the primitive — the primitive itself is kind-agnostic. The bridge module exposes both `MUTATION_KINDS_ARGUZZ_FULL` (11) and `MUTATION_KINDS_ARGUZZ_SELECTED` (4). The primitive accepts an arbitrary kind string at the `--inject-kind` CLI level; it does not enforce kind-list membership. (v0.4 cleanup: v0.3 erroneously listed a `MUTATION_KINDS_ARGUZZ` constant here as if it lived in the primitive; that was a v0.3 cross-section inconsistency.) |

**No env var bleeding:** `CONSTRAINT_CONTINUE=1` is set in the subprocess env only (per `v6_driver_v2.py` line 451). No reliance on the parent process env. `arguzz_invoke.run()` constructs the subprocess env as `{**os.environ, "CONSTRAINT_CONTINUE": "1"}` and `A4_FAMILY_RESIDUE=1` if the caller passes it explicitly (D2.B Soundness Bug Guard requirement; opt-in).

### 4.2 `a4/standalone/mutations/arguzz_bridge.py` (NEW — bridge layer)

| Item | Detail |
|---|---|
| Module docstring | "Bridge layer between A4Fuzzer's bandit scheduler and the Arguzz subprocess primitive. For arms with `surface=arguzz_exec_fault`, this module is the analog of `a4.standalone.mutations.*_mod` modules for A4 arms." |
| `ArguzzBridgeTarget` dataclass | Fields: `step: int`, `kind: str`, `instruction: str`, `opcode_class: str`, `pre_post: str` (v0.4: no longer hardcoded to `"pre_exec"`; derived per kind from the `_PRE_POST_BY_KIND` constant — see below). **No `config_json` written to disk** — Arguzz takes step + kind directly via CLI. |
| `_PRE_POST_BY_KIND` constant (v0.4 NEW) | Module-level dict mapping kind → `pre_exec` / `post_exec`. Per §1.2 v0.4 convention: `{"INSTR_WORD_MOD": "pre_exec", "PRE_EXEC_PC_MOD": "pre_exec", "PRE_EXEC_MEM_MOD": "pre_exec", "PRE_EXEC_REG_MOD": "pre_exec", "BR_NEG_COND": "pre_exec", "POST_EXEC_PC_MOD": "post_exec", "POST_EXEC_MEM_MOD": "post_exec", "POST_EXEC_REG_MOD": "post_exec", "COMP_OUT_MOD": "post_exec", "LOAD_VAL_MOD": "post_exec", "STORE_OUT_MOD": "post_exec"}`. Both `MUTATION_KINDS_ARGUZZ_FULL` (V6-cTS) and `MUTATION_KINDS_ARGUZZ_SELECTED` (Hybrid-cTS) draw from this dict; the SELECTED 4-kind subset is uniformly `pre_exec`. |
| `MUTATION_KINDS_ARGUZZ_FULL` constant (v0.4 NEW) | Tuple of all 11 `ENABLED_KINDS` matching `v6_driver_v2.py:168-173` order. Consumed by `selector_strategy="v6_cTS"`. |
| `MUTATION_KINDS_ARGUZZ_SELECTED` constant (v0.4 NEW; replaces v0.3's `MUTATION_KINDS_ARGUZZ`) | Tuple of 4 kinds from Pro's §8 Track A priority list 1-4 (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`). Consumed by `selector_strategy="hybrid_cTS"`. |
| `get_targets_at_step(step: int, data: InspectionData, kind: str) -> list[ArguzzBridgeTarget]` | Returns `[ArguzzBridgeTarget(...)]` if `step` is a valid Arguzz target for `kind` (per `valid_injection_kinds_for_instr(instr)` logic from `v6_driver_v2.py` lines 176–191), else `[]`. The Arguzz scheduler's per-instruction validity is the source of truth. The returned `pre_post` field is taken from `_PRE_POST_BY_KIND[kind]`. |
| `get_valid_steps(data: InspectionData, kind: str) -> list[int]` | Returns all steps whose instruction class allows `kind`. Restrictions per `v6_driver_v2.py:176-191`: `BR_NEG_COND` → BRANCHES only; `COMP_OUT_MOD` → COMPUTATIONS only; `LOAD_VAL_MOD` → LOADS only; `STORE_OUT_MOD` → STORES only; the other 7 kinds (`INSTR_WORD_MOD`, `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`, `POST_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD`) → all instructions. |
| `valid_injection_kinds_for_instr(instr: str) -> list[str]` | Copied **verbatim from `v6_driver_v2.py` lines 176–191** (full 11-kind dispatch — v0.4 lift; v0.3 had only the 4-kind subset). Returns the sorted intersection of `result & set(ENABLED_KINDS)`. The full implementation: starts with the 7 always-applicable kinds (PRE_EXEC_PC_MOD, POST_EXEC_PC_MOD, INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, POST_EXEC_MEM_MOD, PRE_EXEC_REG_MOD, POST_EXEC_REG_MOD); adds `BR_NEG_COND` if `instr in BRANCHES`; adds `COMP_OUT_MOD` if `instr in COMPUTATIONS`; adds `LOAD_VAL_MOD` if `instr in LOADS`; adds `STORE_OUT_MOD` if `instr in STORES`. The instruction-class sets (`BRANCHES`, `COMPUTATIONS`, `LOADS`, `STORES`) are also copied verbatim from `v6_driver_v2.py`. |
| `create_mutation_for_arm(arm: ArmKey, step: int, host: str, host_args: list[str], seed: int, data: InspectionData, *, timeout: float = 90.0) -> tuple[MutationOutcome, ArguzzInvocationResult, dict]` | The bridge entry point. Takes an arm + step picked by `A4Fuzzer`'s scheduler, calls `arguzz_invoke.run(host, host_args, step, arm.kind, seed, timeout=timeout)`, returns `(outcome, result, config)` where `config` is the dict the fuzzer will write to `mutations.config_json`. |
| `MAPPING_INSTR_TO_OPCODE_CLASS` | Dict mapping risc0 instruction names to D2.A LOCKED `opcode_class` values. **Seven classes** (per §9 Q8 v0.3, matching `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 line 48): `arithmetic` (add, sub, xor, or, and, slt, sltu, sll, srl, sra, mul, mulh, mulhsu, mulhu, div, divu, rem, remu, lui, auipc, all `*i` immediate variants), `memory_load` (lb, lh, lw, lbu, lhu), `memory_store` (sb, sh, sw), `branch` (beq, bne, blt, bge, bltu, bgeu), `jump` (jal, jalr), `ecall_mret` (eany, mret), `system` (ebreak, invalid). NB: `ecall_mret` is separate from `system` in D2.A; do **not** merge them (v0.2 had them merged into a 6-class set — corrected in v0.3 because: (a) Pro's ProG_Report_3 treats ECALL/MRET as semantically distinct due to machine-mode transitions, and (b) the D2.A synthetic test at `test_d2a_arm_shape_arguzz_simulation.py:34-38` already exercises the distinction). |
| `opcode_class_for_step(step: int, data: InspectionData, baseline_trace: dict[int, str]) -> str` | Wrapper that looks up the instruction at `step` (from `baseline_trace`, populated during `v6_uniform_driver.py` bootstrap or `A4Fuzzer.__init__`) and returns its opcode_class. Falls back to `"system"` for unknown instructions. |

### 4.3 `a4/standalone/semantic_arm_universe.py` (EXISTING — extend)

| Change | Detail |
|---|---|
| New argument: `arguzz_kinds: Optional[List[str]] = None` (v0.4 — replaces v0.3's `include_arguzz_kinds: bool`) | Default `None` (preserves V5 behavior — no Arguzz arms emitted). When a list (typically `MUTATION_KINDS_ARGUZZ_FULL` or `MUTATION_KINDS_ARGUZZ_SELECTED`), iterates over the supplied kinds × applicable steps × opcode_class × per-kind pre_post to add Arguzz arms with full 5-field `ArmKey`. **Caller picks the kind list**; the universe builder does not embed any per-strategy logic. This keeps `semantic_arm_universe.py` strategy-agnostic; the strategy → kind-list mapping lives in `fuzzer.py` (§4.4). |
| New argument: `baseline_trace: Optional[dict[int, str]] = None` | Map `step → instruction_name` for opcode-class derivation. Required when `arguzz_kinds is not None`. Captured during bootstrap (host `--trace`). |
| Arguzz arm construction loop | For each `kind in arguzz_kinds`: for each step in `arguzz_bridge.get_valid_steps(data, kind)`: derive `zone = step_to_zone.get(step, "core_other")`, derive `opcode_class = arguzz_bridge.opcode_class_for_step(step, data, baseline_trace)`, derive `pre_post = arguzz_bridge._PRE_POST_BY_KIND[kind]` (v0.4: per-kind, not hardcoded), emit `ArmKey(surface=ARGUZZ_EXEC_FAULT, kind=kind, zone=zone, opcode_class=opcode_class, pre_post=pre_post)`. |
| `arm_id_for_decision()` (D2.A) | Already returns 5-pipe string for non-v5-shape arms — no change. |
| `valid_steps_by_kind` extended | When `arguzz_kinds is not None`, includes per-kind step lists for each Arguzz kind in the supplied list (so the cTS scheduler can select a step within the arm). |

**Backwards compatibility:** existing call sites use `SemanticArmUniverse.build(data, kinds)` without the new args; this remains equivalent to V5 behavior with V5-shape ArmKey arms. **Golden trace test must continue to pass** post-change. (v0.4 note: the parameter rename from `include_arguzz_kinds: bool` to `arguzz_kinds: Optional[List[str]]` is internal to D2.C — no downstream caller exists yet because v0.3 was DRAFT not LOCKED, so the rename is free.)

### 4.4 `a4/standalone/fuzzer.py` (EXISTING — extend dispatch)

| Change | Detail |
|---|---|
| Add `selector_strategy` extensions | New strategies recognized: `"hybrid_cTS"`, `"v6_cTS"`. **Per-strategy kind-list wiring (v0.4):** `v6_cTS` calls `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL)` — all 11 ENABLED_KINDS — AND filters to Arguzz-only arms (`surface == ARGUZZ_EXEC_FAULT`); `hybrid_cTS` calls `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED)` — 4 kinds from Pro's §8 Track A priority list — and keeps both A4 and Arguzz arms in the shared arm space. Implementation hook: `STRATEGY_DISPLAY_NAMES` and `CTS_SEMANTIC_V2_FAMILY` get the new entries. (NB: full CLI exposure is D2.D's job; D2.C just adds the constants + internal wiring.) Concrete code shape: <br>`if selector_strategy == "v6_cTS":`<br>`    arguzz_kinds = MUTATION_KINDS_ARGUZZ_FULL`<br>`    arguzz_only = True`<br>`elif selector_strategy == "hybrid_cTS":`<br>`    arguzz_kinds = MUTATION_KINDS_ARGUZZ_SELECTED`<br>`    arguzz_only = False`<br>`else:`<br>`    arguzz_kinds = None  # V5-shape only`<br>`    arguzz_only = False` |
| `_create_mutation(kind, step)` dispatch | New branch: when the picked arm has `surface=ARGUZZ_EXEC_FAULT`, dispatch to `arguzz_bridge.create_mutation_for_arm(arm, step, self.host_binary, self.host_args, iter_seed, self.data, timeout=self.arguzz_timeout)`. Returns a different shape than the A4 path: `(config: dict, mutated_value: int, original_value: int)` is replaced by `(arguzz_result: ArguzzInvocationResult, config: dict)` — see new `_dispatch_arm()` helper below. |
| `_dispatch_arm(arm: ArmKey, step: int, mutation_num: int) -> MutationResult` | NEW helper that wraps both dispatch paths. For `surface=A4_TRACE_CELL`: existing logic (build config, write JSON, call `run_a4_mutation`). For `surface=ARGUZZ_EXEC_FAULT`: call `arguzz_bridge.create_mutation_for_arm`, then construct a `MutationResult` from the `ArguzzInvocationResult`. **Refactoring guard:** the A4-side path must be byte-identical pre- and post-refactor under fixed RNG (golden trace test required). |
| `_record_arguzz_mutation(arm, step, result, config, stats)` | NEW helper. Writes the row to `mutations` table via `CoverageDB.record_mutation(...)` with: `kind=arm.kind`, `config_json=json.dumps(config)`, `outcome=result.outcome.value` (so D2.A's `outcome` column gets populated for Arguzz too), `verifier_accepted=(result.prover_status == "success")`, `proof_generated=(result.prover_status != "none")`, `proof_verify_failed=(result.prover_status == "error" and len(result.failures) > 0)`, `elapsed_ms=int(result.wall_s * 1000)`. |
| Failures + CGC | Iterate `result.failures` and call `CoverageDB.record_failures(mut_id, result.failures)` (existing API, uses normalized `short_loc`). Iterate `result.family_details` and call `extract_compressed_global_contexts(family_residues=result.family_residues, family_details=result.family_details, mutation_kind=arm.kind, mutation_zone=arm.zone, mutation_major=cycle.major)`; persist via `CoverageDB.record_compressed_global_first_hit(...)` (existing). |
| `arguzz_timeout: float = 90.0` instance attribute | Settable via constructor; default 90 s matches `v6_driver_v2`. |
| Soundness-bug check for prove_success | **Ownership (v0.3):** the primitive (`arguzz_invoke._classify_outcome`) is the **single owner** of the soundness_signal decision; it sets `ArguzzInvocationResult.soundness_signal = True` and includes `{"soundness_signal": True}` in the returned `extra_tags` dict. The fuzzer driver copies this boolean to the row's `config_json["soundness_signal"]` and logs a `WARNING` via `a4.arguzz_bridge` logger (`"prove_success while applied at step=%d kind=%s zone=%s opcode_class=%s — possible soundness signal or fault-no-op"`). The warning is **non-fatal**. Bridge layer does NOT independently re-derive the signal; it only forwards. This is the same direction as the failure_recording_gap flag (primitive sets, driver copies). |

### 4.5 `a4/standalone/v6_uniform_driver.py` (NEW — modernized driver layer)

Effectively `v6_driver_v2.py` refactored to use the new primitive + `CoverageDB`:

| Change vs `v6_driver_v2.py` | Detail |
|---|---|
| Replace `run_inject` + inline tag parsers | Use `arguzz_invoke.run()` — returns `ArguzzInvocationResult` with everything pre-parsed. |
| Replace inline `DB_SCHEMA` | Use `CoverageDB` from `a4.standalone.coverage_db`. |
| Replace `cur.execute("INSERT INTO mutations ...")` | Use `CoverageDB.record_mutation(...)` (gets normalized `constraint_loc` + `outcome` column for free). |
| Replace `cur.execute("INSERT INTO failures ...")` | Use `CoverageDB.record_failures(...)` (existing API; uses `short_loc` normalization). |
| Replace `cur.execute("INSERT INTO global_failures ...")` | Use `CoverageDB.record_global_failures(...)` (or whatever the existing helper is named in D2.A; see Composer Batch 3 to confirm exact API name). |
| Replace `cur.execute("INSERT INTO compressed_global_coverage ...")` | Use `CoverageDB.record_compressed_global_first_hit(...)` (existing). |
| **Keep** `ArguzzScheduler` (balanced round-robin) class verbatim | This is the V6-faithful baseline; **do not touch** the scheduling algorithm. Move it into `v6_uniform_driver.py` as-is. |
| **Keep** the bootstrap (host `--trace` + `InspectionData` + `classify_zones`) verbatim | Same as `v6_driver_v2.py` lines 389–430. |
| Remove `_TXN_ROLE_BY_KIND` runtime patches | Move into `compressed_global_extractor.py` permanently (see §4.6) so V6-uniform doesn't have to patch at runtime. |
| **CLI args**: same as `v6_driver_v2.py` | `--host`, `--db`, `--seed`, `--num`, `--progress-every`, `--label`, host_args after `--`. |
| `extra_json` shape | Preserved with `driver_version` bump (LOCKED in §9 Q5): `{"num": ..., "scheduler": "balanced_round_robin", "driver_version": "v3_d2c", "compressed_extractor": "a4.compressed_global_extractor", "primitive": "a4.standalone.arguzz_invoke"}`. |
| Iteration seed scheme | Preserved exactly (LOCKED in §9 Q6): `iter_seed = args.seed * 1_000_000 + i`. |
| Module entry | `python -m a4.standalone.v6_uniform_driver` (sets the canonical invocation; D2.D's CLI also exposes it via `--variant=v6_uniform`). |
| Bandit metadata | `selector` field in `campaign_params` is `"arguzz_balanced_rr"` (not `"arguzz"` as in R2; this clarifies the driver-version semantics). |

### 4.6 `a4/standalone/compressed_global_extractor.py` (EXISTING — extend)

| Change | Detail |
|---|---|
| Merge `_ARGUZZ_KIND_ROLE_EXTENSIONS` permanently into `_TXN_ROLE_BY_KIND` | Per `v6_driver_v2.py` lines 74–84. The `setdefault` pattern is preserved (no overwrite of existing entries). |
| `_TXN_ROLE_BY_KIND` additions | `"PRE_EXEC_PC_MOD": "ifetch"`, `"POST_EXEC_PC_MOD": "ifetch"`, `"BR_NEG_COND": "ifetch"`, `"POST_EXEC_REG_MOD": "register"`, `"PRE_EXEC_MEM_MOD": "read"`, `"POST_EXEC_MEM_MOD": "write"`. These are the v6_driver_v2 lines 74–81. (v0.4: v0.3's note "only the 4 D2.C kinds are exposed via `MUTATION_KINDS_ARGUZZ`" is stale — V6-cTS exposes all 11 kinds via `MUTATION_KINDS_ARGUZZ_FULL`, so the `POST_EXEC_*` `_TXN_ROLE_BY_KIND` entries are now operationally consumed by V6-cTS, not just forward-compat. Hybrid-cTS still uses the 4-kind `_SELECTED` subset and so consumes only the `PRE_EXEC_*` and `BR_NEG_COND` entries.) |
| `major_to_opcode_class()` helper | **ALREADY EXISTS** at `semantic_zones.py:101` (v0.3 correction; v0.2 erroneously said "NEW function added"). Currently used by `compressed_global_extractor.py:295` (line `opcode_class = major_to_opcode_class(mutation_major)` for CGC tag construction), `reward_v2.py`, and 2 tests. **The label set is intentionally different from `arguzz_bridge.MAPPING_INSTR_TO_OPCODE_CLASS`** — see the two-taxonomy block below. D2.C does NOT modify this helper or `OPCODE_CLASS_BY_MAJOR`. |

#### Two-taxonomy split (v0.3 clarification)

There are **two distinct opcode-class taxonomies** in the codebase. They serve different purposes; D2.C uses both at different layers:

| Taxonomy | Source | Classes | Granularity | Used for |
|----------|--------|---------|-------------|----------|
| **Arm-shape `opcode_class`** (D2.A LOCKED) | `arguzz_bridge.MAPPING_INSTR_TO_OPCODE_CLASS` (new in D2.C) + the synthetic test fixture `test_d2a_arm_shape_arguzz_simulation.py:34-38` | 7: `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system` (+ `n/a` for V5-shape arms) | Per-instruction (fine-grained: `memory_load` vs `memory_store` split) | Bandit ARM IDENTITY — drives `ArmKey.opcode_class`, used by cTS scheduler to allocate pulls across opcode classes |
| **CGC `OPCODE_CLASS_BY_MAJOR`** (semantic_zones.py:86-98) | `semantic_zones.OPCODE_CLASS_BY_MAJOR` + `major_to_opcode_class()` helper | 8: `alu`, `mul`, `div`, `mem`, `branch_or_ctrl`, `poseidon`, `sha`, `other` | Per-major (coarser: `mem` lumps load+store; finer: separates `mul`/`div` from `alu`) | TELEMETRY compression — feeds CGC `producer_kind` / `opcode_class` for compressed-global-coverage rows |

**Why two taxonomies are correct:**

- **Arm identity (bandit)** wants per-load/per-store distinction so the cTS scheduler can learn that BR_NEG_COND arms aren't comparable to LOAD_VAL_MOD arms. Lumping load+store would hide an actionable signal.
- **CGC telemetry** wants coarse, ALWAYS-defined classes so global-context compression collapses adjacent broken-address contexts to the same bucket. Splitting load/store doubles the CGC cardinality without making rejection signals more compressible. The CGC also wants `mul`/`div` split (different constraint-family fingerprints) but doesn't care about ecall vs other system instructions (both produce the same global-context signature).
- **The two are mappable** where they overlap: `arithmetic` ⊇ `{alu, mul, div}`; `memory_load ∪ memory_store` = `mem`; `branch ∪ jump` ⊆ `branch_or_ctrl`; `ecall_mret ∪ system` ⊆ `other`. D2.G analysis can pivot between them without re-fuzzing.

**Cross-cutting test (Batch 2):** asserts that for any instruction the bridge classifies as `arithmetic`, the corresponding `major` (when looked up via `major_to_opcode_class`) returns a value in `{alu, mul, div}`. Catches drift in the mapping if RISC-V semantics shift in either direction.

(v0.2's §4.6 prose claiming "major 0 = ECALL → `system`; major 1–4 = compute → `arith`" is **factually wrong** about the actual `OPCODE_CLASS_BY_MAJOR` content — major 0 is `"alu"`, not `"system"`/ECALL — and v0.2 also conflated the two taxonomies. v0.3 removes the prose entirely; the table above is authoritative.)

### 4.7 `a4/arguzz_dependent/arguzz_runner.py` (EXISTING — deprecate)

| Change | Detail |
|---|---|
| Add deprecation docstring at module top | "**Legacy / R2-compat only.** D2.C onward, Arguzz invocation lives in `a4/standalone/arguzz_invoke.py` (UTF-8-safe subprocess, `MutationOutcome` mapping, `ConstraintFailure` parsing via `short_loc`, soundness-signal flagging). Do not import this module in new code. This file remains in tree for R2-era scripts that still reference it (`a4/arguzz_dependent/*` analyses); deletion deferred to IV.POS.9 cleanup." |
| **No code changes** | Keep the module functional for any in-tree script that still uses it. |

### 4.8 New tests

| Test file | Layer | Asserts | Real binary? | Composer batch |
|---|---|---|---|---|
| `tests/test_d2c_arguzz_invoke_mock.py` | 1 (mock) | `arguzz_invoke.run()` parses canned Arguzz stdout correctly; outcome mapping covers all 5 cases (timeout, panic, prove_success, prove_error w. failures, prove_error w/o failures); UTF-8-safe decode handles non-UTF-8 bytes; `host_panic` detection works for both `"panicked at"` and `"Guest panicked:"`; `traces` are extracted; `family_residues`/`family_details` are extracted. | No | 1 |
| `tests/test_d2c_outcome_mapping.py` | 1 (unit) | `_classify_outcome` covers all 7 boundary cases of the Option C decision tree (§6.1 v0.3): (1) timeout `rc=124` → ERROR; (2) `prover_status="success" + not host_panic` → APPLIED + `soundness_signal=True`; (3) `prover_status="error" + has_failures` → APPLIED (Path A); (4) `prover_status="error" + not has_failures` → APPLIED + `failure_recording_gap=True` (Path B); (5) `prover_status="start" + has_failures` → APPLIED (Path A mid-witgen); (6) `prover_status="start" + host_panic` → SKIPPED (true C5); (7) other → ERROR. Also asserts `_detect_host_panic` matches BOTH `"panicked at"` AND `"Guest panicked:"` (v6_driver_v2 only checks the former). | No | 1 |
| `tests/test_d2c_arguzz_invoke_real_binary.py` | 2 (real, gated) | Real `risc0-host`, 4 kinds × 1 invocation each (at known-good steps from a baseline `--trace`). Assert: at least 1 fault tag parsed per kind; outcome ∈ {APPLIED, ERROR}; `wall_s < 90` (no timeout); host doesn't crash on the invocation pattern itself. **Gating: failure here blocks D2.C; if a kind has zero faults emitted, the dev binary needs investigation.** | **Yes** (`A4_REAL_BINARY=1`) | 1 |
| `tests/test_d2c_arguzz_bridge.py` | 3 (mock bridge + real bandit) | Stub `arguzz_invoke.run()` with deterministic results. `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED)` AND `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL)` both produce non-empty Arguzz arm sets on synthetic InspectionData (v0.4: parametrized over both kind-lists). `A4Fuzzer._dispatch_arm()` correctly routes `surface=ARGUZZ_EXEC_FAULT` arms to the bridge. `MutationOutcome` flows back to `update_with_outcome` correctly. `mutations.outcome` column is populated for Arguzz rows. | No (stubbed primitive) | 2 |
| `tests/test_d2c_arguzz_arm_construction.py` | 2 (unit) | **v0.4 expanded:** parametrized over **both kind-lists** (FULL=11 and SELECTED=4) and **all 7 D2.A-LOCKED opcode classes**. Asserts: (a) for each kind in the supplied list, at least one arm is emitted on synthetic `InspectionData` containing the kind's applicable instruction class (BR_NEG_COND requires a branch instr; COMP_OUT_MOD requires an ALU instr; LOAD_VAL_MOD requires a load; STORE_OUT_MOD requires a store; the other 7 require any instr); (b) `opcode_class` matches `MAPPING_INSTR_TO_OPCODE_CLASS` for representative instructions across all 7 classes; (c) `pre_post` matches `_PRE_POST_BY_KIND[kind]` (5 `pre_exec`, 6 `post_exec` for FULL; 4 `pre_exec` for SELECTED); (d) total arm count for FULL is in the predicted range (~200–350); for SELECTED ~110–160. | No (synthetic InspectionData) | 2 |
| `tests/test_d2c_v6_uniform_driver_smoke.py` | 5 (real, gated) | Real binary, N=50 run. Assert: 50 `mutations` rows; **at least 6 of the 11 ENABLED_KINDS present** (V6-uniform's balanced-RR over 11 kinds yields ~4-5 invocations per kind at N=50, but applicability filtering — STORE_OUT_MOD requires stores in the trace, etc. — may exclude some kinds; 6/11 is a robust floor); the 4 SELECTED kinds (INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND) MUST all be present (always-applicable except BR_NEG_COND which requires branches; sha2-host has branches); `outcome` column populated; `coverage.constraint_loc` is `Name@basename:line`; `compressed_global_coverage` non-empty; `extra_json` field has `driver_version="v3_d2c"`. | **Yes** (`A4_REAL_BINARY=1`) | 3 |
| `tests/test_d2c_hybrid_smoke.py` | 6 (forerunner) | Stub `arguzz_invoke.run()`. Run `A4Fuzzer.run_campaign(N=50, selector_strategy="hybrid_cTS")`. Assert: both `surface=A4_trace_cell` AND `surface=arguzz_exec_fault` arms get pulled (≥1 each); `update_with_outcome` is called for both surfaces; cTS scheduler's `total_pulls` counter matches the APPLIED count. **NB: this is a forerunner for D2.D's real Hybrid-cTS wiring; D2.D will harden the full CLI integration.** | No | 4 |
| `tests/test_d2c_arm_registration.py` | 1 (cross-cutting) | Mirror of `test_d2b_arm_registration.py`. Parametrized over (surface, kind) × 6 layers (Python module exists, registry entry, valid steps non-empty for at-least-one step, opcode_class derivation, semantic_arm_universe entry, dispatch wiring). **v0.4 expanded:** 11 V6-cTS Arguzz kinds × 6 layers = **66 cases** (was 24 in v0.3 with the 4-kind subset). The test parametrizes over `MUTATION_KINDS_ARGUZZ_FULL` (the superset). The Hybrid-cTS scope is implicitly covered since `MUTATION_KINDS_ARGUZZ_SELECTED ⊂ MUTATION_KINDS_ARGUZZ_FULL`. | No | 4 |
| `tests/test_d2c_golden_trace_v5_decision_seq.py` | 1 (regression — Tier 1) | Run `ConstrainedTSScheduler` over a synthetic universe at fixed seed (mirror of `test_d2a_back_compat_golden_trace.py:15-26`); assert byte-identical `(arm_id, mode)` tuple sequence against a JSON fixture captured during Batch 1. **<1s test wall time; catches RNG drift from `_dispatch_arm` refactor.** | No | 1 |
| `tests/test_d2c_golden_trace_v5_db_byte_identity.py` | 1 (regression — Tier 2, NEW in v0.3) | Run `A4Fuzzer.run_campaign(N=20, selector_strategy="cTS_semantic_v2", seed=42)` against a mocked-binary fixture (Layer 5 mock); assert DB content (mutations + failures + coverage rows minus timestamps + run-specific IDs) is byte-identical to the v0.3 reference DB captured after Batch 3 tasks 3.1/3.2 land. **~10s test wall time; catches downstream serialization drift (config_json key reordering, extra fields, mutation-row column shifts) that the Tier-1 decision-sequence test misses.** | No (mocked binary) | 3 (task 3.2b) |

### 4.9 Files that **must not change** in D2.C

| File | Reason |
|---|---|
| `a4/standalone/bandit_ts.py` | D2.A foundation; no scheduler change. |
| `a4/standalone/coverage_db.py` | D2.A schema; no migrations. |
| `a4/standalone/mutations/*.py` (existing A4 kinds) | A4 modules untouched. |
| `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` | Frozen reference; do not modify. |
| `a4/standalone/cli.py` | D2.D's responsibility. |
| `a4/arguzz_dependent/arguzz_parser.py` | Preserve as-is; D2.C imports from it. |
| `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | D2.C has zero Rust dependencies (Arguzz handles the injection on the host side, not the prover side). |

---

## 5. Per-kind mechanism analysis (NEW in v0.2)

For each of the 4 SELECTED kinds (Pro `ProG_Report_3.md` §8 Track A priority 1-4 — the Hybrid-cTS scope), this section provides: (a) the Arguzz mechanism (what the binary does), (b) the post-injection propagation flow, (c) the expected witgen behavior (which constraint families catch it), (d) the expected outcome distribution from R2 V6 DB data.

**v0.4 scope note:** the 7 additional V6-cTS-only kinds (`PRE_EXEC_REG_MOD`, `POST_EXEC_PC_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_REG_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`) follow analogous mechanism patterns: the `POST_EXEC_*` family mirrors their `PRE_EXEC_*` counterparts but at the post-commit intercept point; `COMP_OUT_MOD` mutates ALU outputs with a flow analogous to `INSTR_WORD_MOD` but on the data path; `LOAD_VAL_MOD`/`STORE_OUT_MOD` mutate memory transaction values with flows analogous to `PRE_EXEC_MEM_MOD` but on specific instruction classes. Pro's §8 Track A priority list ranked the 3 POST_EXEC_* kinds at #5/#6/#7 (lower priority for Hybrid due to A4 overlap) and did not list COMP_OUT_MOD / LOAD_VAL_MOD / STORE_OUT_MOD / PRE_EXEC_REG_MOD; all 7 are operationally correct for V6-cTS where the goal is "Arguzz-as-Arguzz with cTS scheduling." Detailed per-kind §5.5-style empirical analysis for the 7 additional kinds is deferred to D2.G post-campaign analysis (no D2.C blocker).

### 5.1 `INSTR_WORD_MOD` (C.1) — random instruction word replacement

**Arguzz mechanism:** at the targeted step, before the host's fetcher reads the instruction word, Arguzz overwrites the instruction word in the host's memory with a fully random `u32`. The fetcher then reads the corrupted word; the decoder decodes whatever opcode/operand combination it parses; the executor runs the mis-decoded instruction.

**Propagation flow:**
1. Random `u32` overwrites `mem[pc]` immediately before fetch.
2. Fetcher reads corrupted word → decoder produces a (possibly invalid) `(major, minor, operands)` triple.
3. Executor runs the (mis-decoded) instruction → register file / memory / PC state diverges from the "honest" execution.
4. All subsequent cycles run on this corrupted state.
5. Preflight trace records the corrupted instruction's `major`/`minor`/`txn` actions.
6. Witgen produces a witness consistent with the corrupted trace (since the trace is now self-consistent).

**Expected witgen behavior (constraint families that catch it):**
- `lookup` family: the corrupted `(major, minor)` may not exist in the instruction lookup table → constraint failure at the `MajorOnehot`/`MinorOnehot` extern.
- `memory` family: if the corrupted instruction writes to a different addr than the honest one (different store offset), the memory permutation argument fails.
- `cycle` family: less likely to catch this directly (cycle table records what actually happened).
- `decode` family: invalid opcodes hit the decode-validity constraints.

**Per-fault tag format:** `<fault>{"step":N,"pc":P,"kind":"INSTR_WORD_MOD","info":"word:X => word:Y"}</fault>` (parsed by `ArguzzFault.parse` → `info_type="word"`).

**ProG_Report_3 priority:** §8 Track A #1 — highest priority Arguzz kind to import into Hybrid. R2 V6 DB: 752 of 6000 rows.

### 5.2 `PRE_EXEC_MEM_MOD` (C.2) — pre-execution memory write

**Arguzz mechanism:** at the targeted step, before the cycle executes, Arguzz writes a random value to a heuristically-chosen memory address (typically near the SP / heap / data region; the binary's heuristic is opaque). The cycle then executes and may read from that address (via a `lw`/`lb`/etc.), receiving the mutated value.

**Propagation flow:**
1. Mutated `mem[addr]` write happens immediately before cycle N.
2. If cycle N is a load that reads from `addr` (overlapping with the mutated address): the load receives the mutated value; subsequent computations use it; eventually propagates to memory writes / register state / branch decisions.
3. If cycle N doesn't read `addr`: the mutation is dormant; later cycles may read it, or it may sit unobserved forever.
4. The memory permutation argument records the WRITE the mutation made (Arguzz's pre-exec write is observable as a memory transaction).

**Expected witgen behavior:**
- `memory` family: the pre-exec write becomes a memory transaction that must reconcile with reads; if the read-write structure is now inconsistent, the permutation argument fails.
- `lookup` family: rarely.
- `cycle` family: if the mutated value affects PC computation (branch target), can desync cycle counts.

**Per-fault tag format:** `<fault>{"step":N,"pc":P,"kind":"PRE_EXEC_MEM_MOD","info":"MEM[$0xADDR] = VAL"}</fault>` (parsed by `ArguzzFault.parse` → `info_type="mem_assign"`, `original_value=addr`, `mutated_value=val`).

**ProG_Report_3 priority:** §8 Track A #2. R2 V6 DB: 756 of 6000 rows. **Highest interest for accepted-invalid signals** — Arguzz emphasized that PRE_EXEC_MEM_MOD often produces "naturally coherent" execution-time perturbations (per `ProG_Report_3` §3) because the rest of the trace is produced by execution after the fault.

### 5.3 `PRE_EXEC_PC_MOD` (C.3) — pre-fetch PC mutation

**Arguzz mechanism:** at the targeted step, before the host fetches the instruction, Arguzz overwrites the PC register with a mutated value. The fetcher then fetches from the wrong address; the decoder decodes whatever it finds there; the executor runs that instruction.

**Propagation flow:**
1. PC overwrite happens immediately before fetch at step N.
2. Fetcher reads `mem[corrupted_pc]` instead of `mem[honest_pc]`.
3. Decoder produces a `(major, minor, operands)` based on whatever is at `mem[corrupted_pc]` — typically valid-but-wrong (since it's a real instruction at some other PC) but occasionally invalid (if the address is in a non-instruction region).
4. Executor runs the wrong instruction; state diverges as in INSTR_WORD_MOD but the divergence is different in character (PC corruption affects subsequent instr fetches differently from random-word corruption).
5. The `pc` field in cycle records reflects the corrupted PC.

**Expected witgen behavior:**
- `memory` family: the instruction-fetch transaction is at the wrong address → permutation argument may fail.
- `cycle` family: the cycle's `pc` differs from what `prev_cycle`'s state predicted → `next_pc` constraint may fail.
- `lookup` family: if the fetched word doesn't decode validly, the lookup fails.

**Per-fault tag format:** `<fault>{"step":N,"pc":P,"kind":"PRE_EXEC_PC_MOD","info":"pc:X => pc:Y"}</fault>` (parsed by `ArguzzFault.parse` → `info_type="pc"`).

**ProG_Report_3 priority:** §8 Track A #3. R2 V6 DB: 796 of 6000 rows.

### 5.4 `BR_NEG_COND` (C.4) — branch condition inversion

**Arguzz mechanism:** at a branch instruction's execution step (only `beq`/`bne`/`blt`/`bge`/`bltu`/`bgeu`), Arguzz flips the branch decision. If the honest execution would take the branch, Arguzz makes it fall through; if honest falls through, Arguzz takes it.

**Propagation flow:**
1. At step N (a branch cycle), Arguzz forces the opposite branch outcome.
2. Cycle N+1's PC is `pc + 4` (fall-through) when honest would have been `pc + offset` (taken), or vice versa.
3. The mis-branched execution continues; depending on whether the now-skipped/now-taken code modifies state differently, the divergence cascades.
4. The "branch taken" predicate in the trace is the inverted value.

**Expected witgen behavior:**
- `decode` family: the branch-condition computation in the witness should be `(rs1 op rs2)` evaluated under field arithmetic; if the trace records the inverted decision, this constraint fails.
- `cycle` family: `next_pc` will be the post-inversion PC, which may not match what the `taken_flag × offset` arithmetic produces.
- `memory` family: less likely (BR_NEG_COND doesn't touch memory directly).

**Per-fault tag format:** `<fault>{"step":N,"pc":P,"kind":"BR_NEG_COND","info":""}</fault>` (kind-only fault; `ArguzzFault.parse` falls through to the `unknown` info_type).

**ProG_Report_3 priority:** §8 Track A #4. R2 V6 DB: 142 of 6000 rows (lowest of the 4; branch instructions are a small fraction of the trace, so BR_NEG_COND opportunities are scarce).

### 5.5 Empirical observations from R2 V6 DBs (REWRITTEN in v0.3)

> **v0.3 reversal of v0.2 finding.** v0.2 claimed "94.6% panic / 2.95% prove_success / 0% prove_error" and concluded the bandit's APPLIED-pull rate is ~5%. **This was a classifier artifact**, not the actual semantics. `v6_driver_v2.py:479` checks `host_panic = "panicked at " in stdout` BEFORE checking `prover_status`, so 91.6% of the rows that v0.2 called "panic" actually had `prover_status="error"` — the prover ran, detected the mutation, then the host panicked after. Those are APPLIED+REJECTED mutations, not pre-prover crashes. v0.3 reclassifies and rewrites all downstream implications.

Spot-checked `pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000.db` (seed 1243, N=6000, 11-kind V6 Arguzz campaign):

**Joint distribution (`outcome` × `prover_status` × `has_failures`):**

```sql
SELECT json_extract(config_json,'$.outcome'),
       json_extract(config_json,'$.prover_status'),
       CASE WHEN num_failures > 0 THEN 'yes' ELSE 'no' END,
       COUNT(*)
FROM mutations GROUP BY 1, 2, 3 ORDER BY 4 DESC;
```

| `outcome` | `prover_status` | `has_failures` | count | % |
|-----------|-----------------|----------------|-------|---|
| panic     | error           | yes            | 3955  | 65.9 % |
| panic     | error           | no             | 1407  | 23.4 % |
| panic     | start           | no             | 314   |  5.2 % |
| prove_success | success     | no             | 177   |  2.95 % |
| other     | start           | yes            | 135   |  2.25 % |
| other     | start           | no             | 8     |  0.13 % |
| timeout   | none            | no             | 4     |  0.07 % |
| **Total** |                 |                | **6000** | 100 % |

**Semantic reclassification (Option C, v0.3):**

| Bucket | Source rows | Count | % | Bandit treatment |
|--------|-------------|-------|---|-------------------|
| **APPLIED + REJECTED (Path A — local constraint failures)** | panic/error/has_fail (3955) + other/start/has_fail (135) | 4090 | 68.2 % | APPLIED; `failure_recording_gap = False` |
| **APPLIED + REJECTED (Path B — global polynomial / verify-segment)** | panic/error/no_fail | 1407 | 23.4 % | APPLIED; `failure_recording_gap = True` (D2.G disambiguates via Hook 3 channel) |
| **APPLIED + ACCEPTED (prove_success — soundness signal)** | prove_success/success | 177 | 2.95 % | APPLIED; `soundness_signal = True` |
| **SKIPPED (true C5 — guest died before prover finished)** | panic/start | 314 | 5.2 % | SKIPPED |
| **ERROR (timeout)** | timeout/none | 4 | 0.07 % | ERROR |
| **ERROR (edge — unclear)** | other/start/no_fail | 8 | 0.13 % | ERROR until triaged |

**Bandit credits ~94.6 % of mutations as APPLIED pulls** (5674 / 6000 under `applied_accounting_mode=True`). Of those 5674 APPLIED pulls: **5497 are APPLIED+REJECTED (91.6 % of all mutations)** — the bandit's primary positive-reward signal — and 177 are APPLIED+ACCEPTED-with-soundness-flag (2.95 %). Compared to v0.2's "5 % APPLIED, 95 % panic-ERROR" framing under the host_panic-primary classifier, Option C recovers **~89 percentage points of bandit pull credit** that v0.2 was discarding.

**Key findings (v0.3):**

1. **Path B is the V6 analog of D2.B's at_write finding (NFP-11).** The 1407 rows where `prover_status="error"` but no `<constraint_fail>` tag appeared are mutations that the prover detected at the **global polynomial / verify-segment** level (Path B), not via local witgen EQZ (Path A). This is the same mechanism D2.B documented for the A4 `at_write` case. D2.C tags these with `failure_recording_gap=True`; D2.G can cross-check Hook 3 family-residue data (`A4_FAMILY_RESIDUE=1`) to confirm the constraint was caught and which family it landed in.

2. **The "0 % prove_error" finding in v0.2 was a labeling artifact, not a missing rejection channel.** All 5362 panic+error rows ARE prove_error semantically (prover ran + reported error); v6_driver_v2 just labels them as "panic" because the host died after. D2.C's outcome label is `APPLIED` (semantic), not "panic" / "prove_error" (label-level).

3. **2.95 % prove_success is the soundness-signal bucket.** This is unchanged from v0.2 framing, but the **denominator** changes: 177 prove_success out of 5674 APPLIED mutations = 3.1 % of applied (not 2.95 % of all attempts). For D2.G triage, these are the highest-EV rows.

4. **5.2 % true SKIPPED (C5)** is the **real** "pre-prover guest crash" rate, not the 94.6 % v0.2 claimed. These are the rows where the prover record shows `"start"` (the prover began but never reported success/error) AND the host emitted `"panicked at"`. The mutation didn't reach the witness; the bandit should not credit it as a pull.

5. **BR_NEG_COND has ~5× lower yield** (142 vs ~750 for the other 3 SELECTED kinds and ~744-826 for 6 of the 7 always-applicable V6-cTS kinds) — unchanged from v0.2. This is the structural rarity of branch instructions in the trace; the cTS bandit handles arm-count heterogeneity natively. Note: STORE_OUT_MOD (43) and LOAD_VAL_MOD (76) are even more arm-rare in V6-cTS scope due to instruction-class restrictions; cTS handles those identically.

6. **Scope note (v0.4):** items 1-5 above are computed across the **full 6000-row R2 V6 corpus** (all 11 ENABLED_KINDS), so they apply directly to **V6-cTS** (which uses all 11 kinds, per §1.1.A). For the **Hybrid-cTS slice** (the 4 SELECTED kinds — INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND, totaling 2446 of 6000 rows), the per-pattern breakdown is:

   | Pattern | Count |
   |---------|-------|
   | panic/error/has_fail | 1403 |
   | panic/error/no_fail | 828 |
   | panic/start | 107 |
   | prove_success | 79 |
   | other/start/has_fail | 22 |

   Same Option C semantics apply — ~91 % of Hybrid-relevant rows are prover-reached rejections, not pre-prover guest crashes. **The bandit-signal-recovery argument (~89 percentage points reclaimed from ERROR) holds for both V6-cTS and Hybrid-cTS variants.**

7. **Sample `config_json` from a v0.2-era INSTR_WORD_MOD row:** `{"kind": "INSTR_WORD_MOD", "step": 3028, "instruction": "beq", "iter_seed": 1243000004, "wall_s": 3.263, "rc": 101, "prover_status": "error", "prover_time": "3.25s", "outcome": "panic", "zone": "core_arithmetic", "major": 1}`. This row is a textbook Option C re-classification target: under v6_driver_v2 it's `outcome="panic"`, but `prover_status="error"` AND there were constraint failures (verifiable by joining to the `failures` table on `mutation_id`) → v0.3 classifies as `APPLIED` (and the new V6-uniform driver will write `outcome="applied"` directly to the D2.A `mutations.outcome` column).

**Therefore (v0.3):**

- **The dominant V6 outcome is APPLIED+REJECTED (91.6 %)**, not panic. D2.C's bandit signal is healthy; the v0.2 worry about "applicability skew" was a measurement bug, not a real skew. ProG_Report_3 §8's "applied-mutation accounting" intent is fully realizable with this classifier.
- **The 1407 Path B rows demand the `failure_recording_gap` tag.** Without it, D2.G analysts will see 1407 mutations with `outcome="applied"` but zero rows in `failures` and incorrectly conclude they were no-ops. The tag is the disambiguator.
- **The soundness-signal infrastructure (§6.3) is genuinely useful** at the corrected 2.95 % rate (~180 candidates per 6000-mutation campaign), and even more valuable now that we're not drowning in false-ERROR signal.
- **Per-kind comparison with D2.B's A4-side findings:** in D2.B, the 11 LIVE A4 kinds produced ~100 % rejection rates (every applied mutation triggered ≥1 constraint or Hook 3 residue). V6 mutations produce **94 % APPLIED with 96.9 % of those rejected** (5497/5674) — comparable to A4, not "9× worse" as v0.2 framed it. **D2.C preserves the cross-variant comparability story Pro depends on for D2.G analysis.**

---

## 6. Outcome classification + 4-channel rejection model adapted to Arguzz (NEW in v0.2)

### 6.1 Outcome enum mapping (REWRITTEN in v0.3 — Option C: prover_status-primary)

The Arguzz primitive emits a 5-tuple raw outcome: `(rc, host_panic, prover_status, has_constraint_failures, has_family_residues)`. The primitive (`arguzz_invoke._classify_outcome`) maps this to D2.A's `MutationOutcome` enum **prover-status-primary**:

```text
input: (rc, host_panic, prover_status, has_failures)
        ──────────────────────────────────────────────
rc == 124
    → (MutationOutcome.ERROR, {})                               # timeout

prover_status == "success" AND not host_panic
    → (MutationOutcome.APPLIED, {"soundness_signal": True})     # potential accepted-invalid

prover_status == "error" AND has_failures
    → (MutationOutcome.APPLIED, {})                             # Path A — local witgen EQZ caught it

prover_status == "error" AND not has_failures
    → (MutationOutcome.APPLIED, {"failure_recording_gap": True})  # Path B — verify-segment / global poly

prover_status == "start" AND has_failures
    → (MutationOutcome.APPLIED, {})                             # Path A fired; prover record never finalized

prover_status == "start" AND host_panic
    → (MutationOutcome.SKIPPED, {})                             # true C5 — guest died before prover finished

otherwise
    → (MutationOutcome.ERROR, {})                               # edge (other/start/no_fail; 8 rows in R2 V6)
```

**Why prover_status-primary (Option C) instead of v0.2's host_panic-primary:**

v0.2 mapped `host_panic == True → MutationOutcome.ERROR` unconditionally. This was equivalent to v6_driver_v2.py:479's `host_panic` check before `prover_status`, and threw away 91.6% of bandit signal (5497 of 6000 R2 V6 rows) because the prover detected the mutation cleanly before the host crashed.

v0.3 keys off `prover_status` first. The only case where `host_panic` is decisive is when `prover_status="start"` — i.e., the prover began but never reported `success` or `error`, AND the host panicked. That's the **true** pre-prover guest crash (314 rows / 5.2% in R2 V6); the bandit shouldn't credit it as a pull.

Concretely:

- **Pro's "applied-mutation accounting" (ProG_Report_3 §8)** requires that only mutations that actually exercise the witness count as pulls. Both `prove_success` and `prove_error+failures` exercised the witness end-to-end → APPLIED.
- **Path A vs Path B (NFP-11):** `prove_error+failures` is Path A (local witgen EQZ tags the constraint at the failure site); `prove_error+no_failures` is Path B (witgen survives, prover detects inconsistency at the polynomial/verify-segment level). Both are valid rejection channels; both are APPLIED. The `failure_recording_gap` flag distinguishes them for D2.G's downstream analysis (e.g., correlation with Hook 3 family residues).
- **`prover_status="start" + has_failures`** is a narrow case where local witgen EQZ fired but the prover record never advanced past "start" (typically because the panic happened mid-witgen). The `<constraint_fail>` tag is the authoritative signal; APPLIED.
- **The soundness_signal is a TAG**, not a separate outcome. The row is APPLIED for bandit scheduling; the tag flags it for D2.G triage (cross-reference with `failures`, `global_failures`, Hook 3 residue to disambiguate accepted-invalid bug vs fault-no-op).
- **The `failure_recording_gap` is also a TAG**, set in the same `extra_tags` dict and copied by the driver into `config_json`. Both tags are non-fatal; both are post-hoc analysis hooks.

### 6.2 4-channel rejection model for V6 mutations

D2.B established a 4-channel rejection model for A4 mutations (`IV_POS_8_D2_B_MECHANISM_REPORT.md` §9):

| Channel | Symptom | Source |
|---|---|---|
| **C1** | `<constraint_fail>` tag | Local witgen EQZ (Path A) |
| **C2** | `verify segment` panic | Polynomial/global memory argument (Path B) |
| **C3** | `<a4_family_residue family=... nonzero/>` | Hook 3 per-family residue (opt-in via `A4_FAMILY_RESIDUE=1`) |
| **C4** | `<a4_error>` | A4 dispatcher error |

For V6 mutations, C4 is **N/A** (no A4 dispatcher in the Arguzz invocation path). However, a new **C5** channel emerges:

| Channel | Symptom | Source (V6) | R2 V6 frequency |
|---|---|---|---|
| **C1** | `<constraint_fail>` tag (Path A) | Same as A4 — local witgen EQZ | 4090 rows (68.2 %) |
| **C2** | `verify segment` panic / global polynomial (Path B) | Same as A4; D2.C also covers `prove_error` with no constraint_fail tags emitted (the 1407 NFP-11-equivalent rows) | 1407 rows (23.4 %) |
| **C3** | `<a4_family_residue ...>` | Same as A4 (Hook 3 is host-side; works for any source of mutation) | gated on `A4_FAMILY_RESIDUE=1`; not in default R2 V6 |
| **C4** | (N/A) | (no A4 dispatcher) | n/a |
| **C5** | `prover_status="start" AND host_panic` — true pre-prover guest crash | V6-specific — guest died **before** the prover could finalize a status | **314 rows (5.2 %)** |

**C5 redefinition (v0.3):** v0.2 defined C5 as "any `panicked at` match" (which catches 94.6% of R2 V6 rows). v0.3 narrows C5 to **`prover_status="start" AND host_panic` only** (~5.2%). The other ~89% of `panicked at` rows have `prover_status="error"` — meaning the prover ran cleanly, detected the mutation, then the host panicked afterward. Those go to C1 (if `has_failures`) or C2 (if not). The narrower definition matches the actual semantic: C5 = "prover record emitted only `status=start`, never finalized to `success` or `error`, and the host panicked — i.e., the mutation reached the prover boundary but the prover never made a verdict"; C1/C2 = "prover ran end-to-end and rejected the proof".

**Implication for D2.C:** the soundness-bug guard (D2.B §9b) is V6-extended: a `SoundnessBugSuspected` warning is raised when *all* of C1, C2, C3, and C5 are silent AND `prove_success` is observed. This is the prove_success-signal handling (§6.3).

**Why C5 doesn't apply to A4 mutations:** A4 mutates the post-execution preflight trace; the execution has already completed at that point, so the guest cannot panic mid-execution. The only A4 "guest-side" failure is a CONFIG dispatcher error (which is C4).

### 6.3 The prove_success / soundness signal handling

**Trigger condition:** `result.outcome == APPLIED AND result.prover_status == "success" AND not host_panic`. This is the ~3 % bucket from R2 V6 DBs.

**What happens** (ownership per §4.4 and §8: primitive owns the decision; driver/fuzzer copies and logs):

1. The **primitive** (`arguzz_invoke._classify_outcome`) sets `ArguzzInvocationResult.soundness_signal = True` and includes `{"soundness_signal": True}` in the returned `extra_tags` dict.
2. The **driver** (the V6-uniform driver, or the A4Fuzzer's `_record_arguzz_mutation` on the Hybrid path) copies `extra_tags["soundness_signal"]` into `config_json["soundness_signal"]` for the row.
3. The **fuzzer** (via `_record_arguzz_mutation`, or the V6-uniform driver directly) emits a `WARNING` via the `a4.arguzz_bridge` logger: `"prove_success while applied at step=%d kind=%s zone=%s opcode_class=%s — possible soundness signal or fault-no-op"`.
4. The cTS scheduler still credits the arm with an APPLIED pull (so the bandit can learn).
5. D2.G analysis filters `mutations WHERE json_extract(config_json, '$.soundness_signal') = 1` to triage:
   - Cross-reference with `coverage` table: if the mutation produced no new constraint_loc AND no new compressed_global_context, it's likely a **fault-no-op** (Arguzz fault didn't propagate to a witness-relevant register/memory cell).
   - Cross-reference with `failures` and `global_failures` tables: must both be empty for a real soundness signal.
   - Re-run the mutation locally with `A4_FAMILY_RESIDUE=1` to check Hook 3 channel for hidden residue.

**Comparison with D2.B's soundness guard:** D2.B's guard was for A4 mutations where the mutation was applied + trace changed + no rejection. For V6, the equivalent is "mutation was applied (Arguzz fault tag present) + guest didn't panic + prover succeeded + no failures". The structural difference: A4 can verify the trace changed via the post-mutation dump (Layer 3); V6 relies on Arguzz's own confirmation that a fault was injected (the `<fault>` tag). Both signals are non-decisive on their own — they need D2.G's triage to disambiguate.

### 6.4 Comparison with D2.B's A4-side rejection model

| Aspect | D2.B (A4 trace-cell) | D2.C (Arguzz exec-fault) |
|---|---|---|
| Mutation surface | Post-execution preflight trace fields | Mid-execution register/memory/PC/branch state |
| Mutation timing | Between execution and witgen | During execution |
| Dominant outcome (v0.3 corrected) | APPLIED (~80 %), SKIPPED (~15 %), ERROR (~5 %) | **APPLIED+REJECTED (~91.6 %), APPLIED+ACCEPTED-with-soundness-signal (~2.95 %), true SKIPPED / C5 (~5.2 %), ERROR (~0.2 %)** |
| Verifier accepts (non-soundness) | Dead-arm structural mechanism (W-17/W-18) | Fault-didn't-propagate semantic mechanism |
| 4-channel coverage | C1, C2, C3, C4 | C1, C2, C3, C5 (no C4) — with `failure_recording_gap` flag distinguishing Path A (C1) from Path B (C2) |
| Soundness-bug trigger | Trace changed + verifier accepted + no rejection in any channel | Arguzz fault injected + `prover_status="success"` + not host_panic + no failures + no global_failures |
| Disambiguation | D2.B Mechanism Report §5–§8 + Layer 3 trace-dump | D2.G analysis with post-hoc residue check + `failure_recording_gap`/`soundness_signal` tag joins |

---

## 7. Arm semantic certainty stack for V6 arms (NEW in v0.2)

D2.B §6c introduced a 6-layer "semantic certainty stack" (S1–S6) to verify that each arm is semantically correct. D2.C adapts this for V6 arms:

| Layer | What it verifies | V6 source / test |
|---|---|---|
| **S1 — Surface determination** | Every arm with `surface=arguzz_exec_fault` corresponds to an Arguzz binary capability | `semantic_arm_universe.py` only adds Arguzz arms when `arguzz_kinds is not None` (v0.4 parameter signature). Cross-cutting test asserts no Arguzz arm has `kind` outside the supplied kind list (FULL or SELECTED). |
| **S2 — Kind validity per instruction** | Class-restricted kinds (BR_NEG_COND → branches; COMP_OUT_MOD → ALU; LOAD_VAL_MOD → loads; STORE_OUT_MOD → stores) only appear on their applicable instruction class; the other 7 always-applicable kinds (INSTR_WORD_MOD, PRE_EXEC_PC_MOD, POST_EXEC_PC_MOD, PRE_EXEC_MEM_MOD, POST_EXEC_MEM_MOD, PRE_EXEC_REG_MOD, POST_EXEC_REG_MOD) appear for all instrs | `arguzz_bridge.valid_injection_kinds_for_instr` (verbatim from `v6_driver_v2.py:176-191`). Tested in `test_d2c_arguzz_arm_construction.py` Layer 2 (parametrized over both kind-lists). |
| **S3 — Zone classification** | Each arm's `zone` matches the target step's zone | `step_to_zone = classify_zones(InspectionData)`, then `arm.zone == step_to_zone[arm_step]`. Tested in arm-construction test. |
| **S4 — Opcode class derivation** | Each arm's `opcode_class` matches the target step's instruction class | `MAPPING_INSTR_TO_OPCODE_CLASS[instr] == arm.opcode_class`. Tested in arm-construction test (parametrized over representative instrs of each of the 7 D2.A-LOCKED classes: `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`). |
| **S5 — Pre/post designation** | Each Arguzz arm's `pre_post` matches `_PRE_POST_BY_KIND[kind]` (D2.A LOCKED strings `"pre_exec"` / `"post_exec"`, not v0.2's abbreviated `"pre"`). FULL (11 kinds): 5 × `pre_exec` + 6 × `post_exec`. SELECTED (4 kinds): all `pre_exec`. | `_PRE_POST_BY_KIND` in `arguzz_bridge.py`; tested in `test_d2c_arguzz_arm_construction.py` (c) and cross-cutting registration path. |
| **S6 — Cross-cutting consistency** | After `_dispatch_arm` runs, the row in `mutations` table has: `kind=arm.kind`, `step` matching the arm-step, `config_json.zone == arm.zone`, `config_json.opcode_class == arm.opcode_class` | Cross-cutting Batch 4 test (`test_d2c_arm_registration.py`). |

**Cross-link to D2.B:** D2.B's certainty stack covered the same layers but with A4-specific source (e.g., S3 was `step_to_zone` from a different code path; D2.C reuses the same `classify_zones` function). The S1 differentiation between `A4_trace_cell` and `arguzz_exec_fault` surfaces is the new D2.C concern.

---

## 8. Decision matrix — primitive vs bridge vs driver responsibilities

| Concern | Primitive (`arguzz_invoke`) | Bridge (`arguzz_bridge`) | Driver (`v6_uniform_driver` / A4Fuzzer) |
|---|---|---|---|
| Subprocess invocation | ✅ owns | uses | uses (via bridge or directly) |
| Tag parsing (`<fault>`, `<trace>`, `<constraint_fail>`) | ✅ owns | uses | uses |
| UTF-8 safe decode | ✅ owns | n/a | n/a |
| Outcome classification (rc/panic/prover_status → MutationOutcome) | ✅ owns | passes through | uses |
| `soundness_signal` flag setting | ✅ **single owner** — sets `ArguzzInvocationResult.soundness_signal: bool` AND returns `{"soundness_signal": True}` in `extra_tags` | passes through unchanged (does NOT independently re-derive) | copies `extra_tags["soundness_signal"]` into `config_json["soundness_signal"]` for the row; emits WARNING log; no other action |
| `failure_recording_gap` flag setting | ✅ **single owner** — sets `extra_tags["failure_recording_gap"]` when `prover_status="error" AND not has_failures` (Path B / verify-segment case) | passes through unchanged | copies into `config_json["failure_recording_gap"]`; no log (Path B is expected behavior, not warning-worthy) |
| Arm-shape construction (5-tuple `ArmKey`) | n/a | n/a | ✅ (via `semantic_arm_universe`) |
| Picking step/kind | n/a | ✅ (validates kind for instr at step) | ✅ (scheduler picks the arm) |
| DB writes (`mutations`, `failures`, `coverage`, `compressed_global_coverage`) | n/a | n/a | ✅ (via `CoverageDB`) |
| Scheduler logic | n/a | n/a | ✅ (round-robin in V6-uniform driver, cTS in A4Fuzzer) |
| `_TXN_ROLE_BY_KIND` extensions | n/a | n/a (already in `compressed_global_extractor`) | imports + uses |
| Applied-mutation accounting | n/a (just sets outcome) | n/a (passes outcome to scheduler) | ✅ (`update_with_outcome(applied_accounting_mode=True)`) |

**Clean separation; no circular dependencies.** The dependency graph is:
```
v6_uniform_driver.py ─┐
                      ├─→ arguzz_invoke.py ─→ arguzz_parser.py (re-import)
A4Fuzzer ──→ arguzz_bridge.py ─┘
                      ↓
              CoverageDB, MutationOutcome, ArmKey, SemanticArmUniverse
```

---

## 9. Open questions — **LOCKED (Q4 & Q8 REWRITTEN in v0.3)**

All 12 questions from v0.1 are resolved here. Each entry: `**LOCKED:** <decision> — <one-line rationale>`. v0.3 rewrote Q4 (outcome mapping → Option C / prover_status-primary) and Q8 (opcode taxonomy → D2.A-aligned 7-class) per Composer's pre-flight audit; the other 10 questions are unchanged from v0.2.

### Q1 — `a4/arguzz_dependent/arguzz_runner.py` keep or delete?

**LOCKED: Keep, deprecate** (`§4.7`). Per D2.A pattern (`constraint_loc_normalize.py`), legacy modules get a docstring banner but aren't removed. R2 archaeological scripts may still reference it. Deletion deferred to IV.POS.9 cleanup.

### Q2 — `arguzz_parser.py` import from or copy?

**LOCKED: Import from it.** The 6-format `ArguzzFault.parse()` is well-tested; rewriting risks introducing format-handling bugs. `arguzz_invoke.py` imports `ArguzzFault`, `ArguzzTrace`, `parse_all_faults`, `parse_all_traces` from `a4.arguzz_dependent.arguzz_parser`. (NB: this is the only `a4/standalone/` → `a4/arguzz_dependent/` import; it's an explicit allowed exception to the "standalone is self-contained" rule.)

### Q3 — V6-uniform driver: keep `v6_driver_v2.py` as production, OR replace?

**LOCKED: Replace** (per §1.4). `v6_driver_v2.py` stays as frozen reference in `a4/runs/iv_pos_7/drivers/` for R2 reproducibility. Active driver becomes `a4/standalone/v6_uniform_driver.py`. Schema parity argument is decisive; D2.G analysis hinges on cross-variant comparability.

### Q4 — Outcome mapping (REWRITTEN in v0.3 — Option C: prover_status-primary)

**LOCKED (v0.3): Option C — prover_status-primary classifier with `failure_recording_gap` tagging.** See §6.1 for the full decision tree. Key invariants:

- `prover_status == "error" AND has_failures` → **APPLIED** (Path A — local witgen EQZ).
- `prover_status == "error" AND not has_failures` → **APPLIED** with `failure_recording_gap = True` (Path B — verify-segment / global polynomial). v0.2 mapped this to ERROR; that was wrong. These are the 1407 NFP-11-equivalent rows from the R2 V6 DB.
- `prover_status == "success"` → **APPLIED** with `soundness_signal = True` (potential accepted-invalid; D2.G triages).
- `prover_status == "start" AND host_panic` → **SKIPPED** (true C5 — guest died before prover finished; the actual 5.2 % bucket, not the 94.6 % v0.2 attributed to panic).
- `rc == 124` → **ERROR** (timeout).

**v0.2's `host_panic` is checked BEFORE `prover_status` rule is REVERSED in v0.3.** That rule perpetuated `v6_driver_v2.py:479`'s label-priority bug (host_panic check at line 479 runs before prover_status check at line 484), which caused the 91.6 % bandit-signal loss documented in §5.5. v0.3 keys off `prover_status` first; `host_panic` is only decisive when `prover_status == "start"`.

**Why this is consistent with Pro's applied-mutation accounting (ProG_Report_3 §8):** Pro's intent is "only mutations that actually exercise the witness count as pulls". A mutation that the prover detected (Path A or Path B) DID exercise the witness — the prover ran end-to-end and reported a fault. A mutation that the guest crashed before the prover could finalize a status did NOT exercise the witness — SKIPPED. The distinction is `prover_status`, not `host_panic`.

### Q5 — V6-uniform driver `extra_json` shape: preserve?

**LOCKED: Preserve, with version bump.** `driver_version: "v3_d2c"` (was `"v2.1_utf8safe"`). Other fields preserved verbatim; new field `primitive: "a4.standalone.arguzz_invoke"`. D2.G analysis can distinguish R2 V6 DBs from D2.C V6 DBs by this field. Changing the schema would break R2 reproducibility scripts that parse it.

### Q6 — Iteration seed scheme

**LOCKED: Preserve exactly.** `iter_seed = args.seed * 1_000_000 + i` (from `v6_driver_v2.py` line 469). V6-uniform on the same `--seed` produces the *same step/kind/iter_seed sequence* as R2 V6, modulo (a) the bandit-level differences for V6-cTS/Hybrid (D2.D) and (b) any cTS-internal RNG changes. This preserves the "control vs treatment" comparison story across cycles.

### Q7 — Arguzz arm `zone` from target step vs broken constraint?

**LOCKED: Target step's zone.** Per `v6_driver_v2.py` line 493 (`zone = step_to_zone.get(step, "core_other")`). The zone is derived from the instruction the mutation targets, NOT from where constraint failures land post-execution. This matches A4's pre-execution-mutation semantic. For arm-shape on the scheduling side, pre-zone is correct; post-execution zone derivation is what `compressed_global_extractor` already groups CGC for.

### Q8 — `opcode_class` taxonomy (REWRITTEN in v0.3 — D2.A-aligned, 7 classes)

**LOCKED (v0.3): 7 classes — matches `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 line 48 verbatim.**

- `arithmetic` — `add`, `sub`, `xor`, `or`, `and`, `slt`, `sltu`, `sll`, `srl`, `sra`, `mul`, `mulh`, `mulhsu`, `mulhu`, `div`, `divu`, `rem`, `remu`, `lui`, `auipc`, and all `*i` immediate variants
- `memory_load` — `lb`, `lh`, `lw`, `lbu`, `lhu`
- `memory_store` — `sb`, `sh`, `sw`
- `branch` — `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`
- `jump` — `jal`, `jalr`
- `ecall_mret` — `eany`, `mret` (separate from `system` because ECALL/MRET trigger machine-mode transitions and zkVM-specific kernel handling; D2.A treats them as a distinct class)
- `system` — `ebreak`, `invalid`

**v0.2 used 6 abbreviated classes (`arith`/`mem_load`/etc., with `ecall_mret` merged into `system`).** That was a direct contradiction of D2.A LOCKED §1.1 line 48 AND of the synthetic test at `test_d2a_arm_shape_arguzz_simulation.py:34-38` (which uses `"arithmetic"`, `"memory_load"`, `"memory_store"`, `"branch"`, `"system"`, `"pre_exec"`, `"post_exec"`). v0.3 restores D2.A alignment so:
- The synthetic test stays meaningful (its arm IDs are reachable).
- `D2.D`/`D2.E`/`D2.G` don't have to re-translate strings between D2.A and D2.C.
- Pro's per-class breakdown in D2.G can distinguish `ecall_mret` from `system` natively.
- The single source of truth is D2.A, not a forked-and-abbreviated D2.C copy.

**This is the arm-shape opcode_class taxonomy** — distinct from the CGC `OPCODE_CLASS_BY_MAJOR` taxonomy in `semantic_zones.py` (see §4.6 two-taxonomy block).

**If Pro pushes back on this taxonomy in D2.G, opcode_class is a string column, so we can re-classify in analysis without re-fuzzing.**

### Q9 — Hybrid arm-space size: ceiling concern?

**LOCKED: Calculate during Composer Batch 2; report in `D2C_BATCH2_COMPOSER_REPORT.md`.** Pro's `ProG_Report_3.md` §17 cited "100s of arms" as the soft ceiling. v0.4 estimates split per variant:

- **Hybrid-cTS** (4 SELECTED Arguzz kinds + 11 A4 kinds): **~160–240 actual arms** for sha2-host. Within Pro's ceiling.
- **V6-cTS** (11 FULL Arguzz kinds, no A4): **~200–350 actual arms** for sha2-host. **Touches the 300-arm "consider reducing" advisory**, but is still within "100s." Likely fine; Batch 2 measures.

If either variant's actual count exceeds 300, available reductions: (a) reduce opcode_class cardinality (merge `jump` into `branch`), or (b) drop zones below a min-step threshold (e.g., a zone with <5 steps could be collapsed). For V6-cTS specifically, an additional lever is (c) reduce `pre_post` granularity for kinds where pre-vs-post yields don't differ in early-pulls data (e.g., merge `PRE_EXEC_MEM_MOD` and `POST_EXEC_MEM_MOD` arms into kind-only arms if applicability is identical). **Don't pre-decide; let actual data inform.**

### Q10 — Composer batch granularity: one big batch or three?

**LOCKED: Four sub-batches.**
- **Batch 1**: Primitive + Layer 1/2 tests (mock + real-binary smoke) + outcome mapping + golden-trace V5 regression test.
- **Batch 2**: Bridge + arm-construction + Layer 3/4 tests.
- **Batch 3**: V6-uniform driver + Layer 5 end-to-end smoke.
- **Batch 4**: Hybrid integration smoke + cross-cutting registration test + plan v0.16 update + final report.

Each batch is gated by the prior batch's acceptance criteria (§11). Single big batch is ~1500 LOC + ~9 tests — too large for clean review.

### Q11 — Timeout: 90 s like v6_driver_v2 or shorter?

**LOCKED: Configurable; default 90 s.** Per v6_driver_v2. Test code uses `timeout=30` to fail fast (the real-binary tests in `tests/test_d2c_arguzz_invoke_real_binary.py` use `timeout=30` to avoid 90 s waits per kind on test failures). The bridge and driver expose `timeout` as a parameter; CLI flag is `--timeout=90`.

### Q12 — CLI flag contract test for `--inject-kind`?

**LOCKED: Implicit via Batch 1 Layer 2 (4 SELECTED kinds) + Layer 5 V6-uniform smoke (≥6 of the 11 ENABLED_KINDS).** Real-binary single-mutation per kind exercises the `--inject-kind` flag for the 4 SELECTED kinds in Batch 1, and Batch 3's V6-uniform driver smoke exercises ≥6 of the 11 (all 4 SELECTED guaranteed; up to 7 of the V6-cTS-only kinds incidentally). If the flag changed in the binary, every Layer 2 invocation would fail. No separate contract test needed; that would just duplicate the gating signal.

---

## 10. Decisions confirmed

| Question | Resolution | Rationale | Resolved on |
|---|---|---|---|
| Q1 | Keep `arguzz_runner.py`, deprecate via docstring | Match D2.A pattern; reversible | v0.2 |
| Q2 | Import `ArguzzFault` etc. from `arguzz_parser.py` | Well-tested; don't duplicate | v0.2 |
| Q3 | Replace `v6_driver_v2.py` with new `v6_uniform_driver.py` (write through `CoverageDB`) | Schema parity for D2.G | v0.2 |
| Q4 | **Option C (v0.3) — prover_status-primary.** `prover_status="error" + has_failures` → APPLIED (Path A); `prover_status="error" + no failures` → APPLIED + `failure_recording_gap=True` (Path B); `prover_status="start" + host_panic` → SKIPPED (true C5); `prover_status="success" + not host_panic` → APPLIED + `soundness_signal=True`. v0.2's "host_panic checked first → ERROR" rule REVERSED (perpetuated v6_driver_v2's 91.6 % signal loss). | v0.3 |
| Q5 | Preserve `extra_json` shape; bump `driver_version="v3_d2c"`; add `primitive` field | Disambiguates R2 vs D2.C DBs | v0.2 |
| Q6 | Preserve `iter_seed = args.seed * 1_000_000 + i` | R2 reproducibility | v0.2 |
| Q7 | Arguzz arm `zone` from target step (not broken-constraint cycle) | Matches A4 pre-mutation semantic | v0.2 |
| Q8 | **7 opcode classes (v0.3, D2.A-aligned): `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`.** Matches `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 line 48 verbatim. v0.2's 6-class abbreviation was a contradiction with D2.A and is corrected. | v0.3 |
| Q9 | Defer to Batch 2 measurement. **Hybrid-cTS predicted ~160–240** (4 SELECTED Arguzz + 11 A4); **V6-cTS predicted ~200–350** (11 FULL Arguzz, no A4). v0.2 said ~150–230 under the now-abandoned 6-class taxonomy; v0.3 said ~160–240 under the D2.A 7-class taxonomy but assumed both variants used 4 kinds (incorrect per Pro `ProG_Report_3.md` §9, fixed in v0.4). | Don't pre-decide; data-driven | v0.4 |
| Q10 | Four Composer batches | Clean review gates | v0.2 |
| Q11 | Timeout configurable; default 90 s; test code uses 30 s | Match v6_driver_v2 baseline | v0.2 |
| Q12 | CLI flag tested implicitly via Layer 2 | Don't duplicate the gating signal | v0.2 |

---

## 11. Composer task breakdown

All four batches assume the §9 LOCKED decisions (as updated in v0.3 for Q4 and Q8) hold. Each batch lists tasks, acceptance gate, expected delivery wall-clock.

### Batch 1 — Primitive layer + real-binary smoke + V5 golden trace

**Goal:** Build `arguzz_invoke.py` + prove it works with the real risc0-host binary + lock in a V5 golden trace for downstream regression-catching.

**Estimated wall-clock:** 1.5–2 days of focused work + 0.5 d for the report.

| Task | File(s) | Notes |
|---|---|---|
| 1.1 | Write `arguzz_invoke.py` | `run()`, `ArguzzInvocationResult`, `_decode_safe`, `_classify_outcome`, `_detect_host_panic`. Re-exports from `arguzz_parser`. |
| 1.2 | Move `_TXN_ROLE_BY_KIND` patches into `compressed_global_extractor.py` permanently | §4.6 |
| 1.3 | Add deprecation docstring to `arguzz_runner.py` | §4.7 |
| 1.4 | Mock test (`test_d2c_arguzz_invoke_mock.py`) | Layer 1; canned Arguzz stdout fixtures (sampled from R2 V6 DBs' raw stdout if available, else hand-crafted to cover all 5 outcome buckets including the prove_success edge). |
| 1.5 | Outcome-mapping unit test (`test_d2c_outcome_mapping.py`) | Layer 1 |
| 1.6 | **Real-binary smoke** (`test_d2c_arguzz_invoke_real_binary.py`) | Layer 2 — **gating**. 4 kinds × 1 invocation each. Document any binary surprises in batch report. |
| 1.7 | V5 golden-trace **DECISION-SEQUENCE parity** test (`test_d2c_golden_trace_v5_decision_seq.py`) | Layer 1 regression — Tier 1 (cheap, fast). Capture a reference JSON of `(arm_id, mode)` tuples for N=200 selections at fixed seed using `ConstrainedTSScheduler` over a synthetic universe (mirror of `test_d2a_back_compat_golden_trace.py:15-26` pattern). Subsequent runs must produce byte-identical decision sequence. **<1s test wall time; matches D2.A/D2.B precedent.** **Scope:** catches changes to `ConstrainedTSScheduler` internals, `SemanticArmUniverse` arm-construction, and `arm_id_for_decision` formatting. **Does NOT exercise `A4Fuzzer._dispatch_arm`** (the test instantiates the scheduler directly with a synthetic universe; no fuzzer/dispatch in the call graph). Dispatch-refactor drift is covered by Tier-2 (task 3.2b) which runs `A4Fuzzer.run_campaign` against a mocked binary. |
| 1.8 | Arm-space size calculation (per Q9); report in batch report | Calc only — no code change. Sanity-check against §1.2 estimate. |
| 1.9 | Full pytest sweep | All previously-green tests still green + new tests pass. |
| 1.10 | Write `D2C_BATCH1_COMPOSER_REPORT.md` | Layer 2 proof; arm-space size estimate; any binary surprises. |

**Acceptance gate (Batch 1):**
- All Layer 1 tests green.
- Layer 2 real-binary test green for all **4 SELECTED kinds** (≥1 fault tag parsed each). Layer 2 covers the Hybrid-cTS-relevant subset; the additional 7 V6-cTS-only kinds are validated via Layer 1 mock (kind-string parametrization) at Batch 1 and via Layer 5 V6-uniform smoke at Batch 3.
- **Tier-1 V5 golden trace (decision-sequence parity)** identity confirmed (Tier-2 DB byte-identity is a Batch 3 gate per task 3.2b).
- `_classify_outcome` unit test covers all 7 decision-tree branches (Option C v0.3), including `failure_recording_gap=True` on `prover_status="error" AND not has_failures` and `soundness_signal=True` on `prover_status="success"`.
- `_detect_host_panic` test verifies both `"panicked at"` AND `"Guest panicked:"` are matched (v6_driver_v2 only checks the former; the new primitive must catch both).
- Full pytest sweep at or above the post-D2.B count (609 passed, 19 skipped, 1 xfailed — no regressions).
- Composer report submitted.

### Batch 2 — Bridge layer + arm-construction

**Goal:** Wire Arguzz arms into `SemanticArmUniverse`; build the bridge dispatcher; verify arm space.

**Estimated wall-clock:** 1 d + 0.5 d for the report.

| Task | File(s) | Notes |
|---|---|---|
| 2.1 | Write `mutations/arguzz_bridge.py` | §4.2; `ArguzzBridgeTarget` (with per-kind `pre_post`), `_PRE_POST_BY_KIND`, `MUTATION_KINDS_ARGUZZ_FULL` (11), `MUTATION_KINDS_ARGUZZ_SELECTED` (4), `get_targets_at_step`, `get_valid_steps`, `valid_injection_kinds_for_instr` (verbatim from `v6_driver_v2.py:176-191`, all 11 kinds), `create_mutation_for_arm`, `MAPPING_INSTR_TO_OPCODE_CLASS`, `opcode_class_for_step`. |
| 2.2 | Extend `semantic_arm_universe.py` with `arguzz_kinds: Optional[List[str]] = None` parameter (v0.4 signature) | §4.3 |
| 2.3 | Arm-construction unit test (`test_d2c_arguzz_arm_construction.py`) | Layer 4 |
| 2.4 | Bridge wiring test (`test_d2c_arguzz_bridge.py`) | Layer 3 |
| 2.5 | Arm-space size measurement | Run `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL)` AND `SemanticArmUniverse.build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED)` on real sha2-host `InspectionData`; report **both** exact arm counts (V6-cTS standalone + Hybrid-cTS scope). Compare against §1.2 estimates (~200–350 / ~160–240). |
| 2.6 | Full pytest sweep | All previously-green + new tests. |
| 2.7 | Write `D2C_BATCH2_COMPOSER_REPORT.md` | Bridge + arm-construction summary; arm-space measurement; any Q9 follow-up (if count >300, propose reductions). |

**Acceptance gate (Batch 2):**
- All Layer 3 / Layer 4 tests green.
- Arm-space measurement within or close to the §1.2 estimates: **Hybrid-cTS ~160–240; V6-cTS ~200–350** (v0.4 split per variant). If either exceeds 300 and the cTS bandit's cold-start cost becomes a concern, Composer proposes reductions before Batch 3 (V6-cTS at ~350 arms × ~3 pulls/arm ≈ 1050 cold-start mutations is still well within N=6000, so reduction is "consider", not "must").
- Full pytest sweep clean.
- Composer report submitted.

### Batch 3 — V6-uniform driver + end-to-end smoke + Fuzzer extension

**Goal:** Modernize `v6_driver_v2` → `v6_uniform_driver`; extend `fuzzer.py` with Arguzz dispatch; ship D2.A schema parity.

**Estimated wall-clock:** 1.5–2 d + 0.5 d for the report.

| Task | File(s) | Notes |
|---|---|---|
| 3.1 | Write `a4/standalone/v6_uniform_driver.py` | §4.5; preserves `ArguzzScheduler` verbatim; replaces inline SQL with `CoverageDB`. |
| 3.2 | Extend `a4/standalone/fuzzer.py` with `_dispatch_arm()` helper + Arguzz dispatch branch + `_record_arguzz_mutation` | §4.4. **Tier-1 Golden-trace V5 test from Batch 1 (task 1.7) must still pass post-refactor.** |
| **3.2a** | **Wire applied-mutation accounting for Arguzz dispatch paths** | NEW v0.3 task. For `selector_strategy in {"hybrid_cTS", "v6_cTS"}`: instantiate `ConstrainedTSScheduler(..., applied_accounting_mode=True)` (currently unused anywhere in `fuzzer.py`; confirmed via `grep applied_accounting_mode a4/standalone/fuzzer.py` → no matches as of `e2c2256`). Replace `v2_scheduler.update(kind, zone, success)` with `update_with_outcome(arm, outcome, success=...)` on the Arguzz-side path only. **V5_control (`selector_strategy="cTS_semantic_v2"`) keeps `applied_accounting_mode=False`** so the Tier-1 golden trace stays byte-identical and the V5 RNG sequence is preserved. |
| **3.2b** | **Tier-2 V5 golden-trace DB byte-identity gate** (`test_d2c_golden_trace_v5_db_byte_identity.py`) | NEW v0.3 task. After tasks 3.1 + 3.2 land, run `A4Fuzzer.run_campaign(N=20, selector_strategy="cTS_semantic_v2", seed=42)` against a mocked-binary fixture (Layer 5 mock), commit the resulting DB content (mutations + failures + coverage rows, minus timestamps + run-specific IDs) as the v0.3 reference fixture. Subsequent runs must produce byte-identical DB content. **~10s wall time; catches any downstream serialization drift the Tier-1 decision-sequence test misses (e.g., config_json key reordering, extra fields, mutation-row column changes).** Tier 2 is a Batch 3 gate, not Batch 1, because the refactor lands in Batch 3 — there's nothing to validate until then. |
| 3.3 | **End-to-end smoke** (`test_d2c_v6_uniform_driver_smoke.py`) | Layer 5 — **gating**. Real binary, N=50; assert schema, kinds, outcome column, normalized constraint_loc, CGC. |
| 3.4 | Schema-parity check | Produce a 50-mutation V6 DB; inspect schema vs an R2 V6 DB (with normalized constraint_loc); document differences (outcome column added; constraint_loc normalized at write-time). |
| 3.5 | Soundness-signal smoke | Verify `soundness_signal=true` rows appear when `prove_success` occurs in the N=50 run (probably 0–2 rows). |
| 3.6 | Full pytest sweep | All previously-green + new tests. |
| 3.7 | Write `D2C_BATCH3_COMPOSER_REPORT.md` | DB schema parity proof; Layer 5 results; soundness-signal smoke results. |

**Acceptance gate (Batch 3):**
- Layer 5 test green.
- DB schema matches `CoverageDB` (with `outcome` column populated for Arguzz mutations).
- **Tier-1 V5 golden trace (decision sequence) still passes** (refactor didn't break A4-side path RNG).
- **Tier-2 V5 golden trace (DB byte-identity) green** (task 3.2b — catches downstream serialization drift).
- **`applied_accounting_mode=True` wired for `hybrid_cTS`/`v6_cTS` only** (task 3.2a — V5_control unaffected).
- Soundness-signal smoke produces well-formed (even if zero) tagged rows, AND `failure_recording_gap` flag appears on `prover_status="error"` rows without `<constraint_fail>` tags (the Path B / NFP-11-equivalent case).
- Composer report submitted.

### Batch 4 — Hybrid integration smoke + cross-cutting registration + closure

**Goal:** Validate the Hybrid-cTS path end-to-end (forerunner); cross-cutting kind-registration test; close D2.C.

**Estimated wall-clock:** 1 d + 0.5 d for the report.

| Task | File(s) | Notes |
|---|---|---|
| 4.1 | Write `test_d2c_hybrid_smoke.py` | Layer 6 — stubbed primitive; mocked `selector_strategy="hybrid_cTS"` (D2.D will harden the full CLI). |
| 4.2 | Write `test_d2c_arm_registration.py` | Cross-cutting Layer 1 over **11 V6-cTS Arguzz kinds × 6 assertion layers = 66 cases** (v0.4 expansion from 24; mirror of `test_d2b_arm_registration.py`). |
| 4.3 | Update `IV_POS_8_D2_PLAN.md` D2.C status row → "DONE"; bump to v0.16 | §4 task table |
| 4.4 | Full pytest sweep | All green. |
| 4.5 | Optional: arm-space size sensitivity analysis | If arm count >250, run a small sweep removing/merging zones to find a "minimal Hybrid arm space" baseline for D2.D's consideration. |
| 4.6 | Write `D2C_BATCH4_COMPOSER_REPORT.md` | Final D2.C summary; Layer 6 results; arm-registration cross-cutting summary; any open items for D2.D. |

**Acceptance gate (Batch 4 + D2.C closure):**
- Layer 6 forerunner green.
- Cross-cutting registration test green (**66 cases: 11 V6-cTS Arguzz kinds × 6 assertion layers**, v0.4 expansion). The 4 SELECTED Hybrid-cTS kinds are a subset; their registration is implicitly covered. (History: v0.2 had a contradictory "96 cases = 4 × 6 × 4 instr-class" figure; v0.3 honored §4.8's 24-case definition for the 4-kind subset; v0.4 expands to 66 for the FULL kind-list. Instr-class coverage remains the **arm-construction test's** job, `test_d2c_arguzz_arm_construction.py`, parametrized over the 7 D2.A-LOCKED opcode classes, NOT the registration test's.)
- Plan v0.16 reflects D2.C → DONE.
- Composer report submitted.
- **D2.C is closed; D2.D unblocked.**

---

## 12. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Layer 2 real-binary test** fails for one of the 4 SELECTED kinds — dev binary doesn't actually support it | Low (we have R2 V6 DBs proving all 11 ENABLED_KINDS — including all 4 SELECTED — emit faults), but possible if dev binary is stale | Composer logs the actual `--inject-kind` output; if empty, escalate; dev binary may need rebuild from `risc0-modified`. **v0.4 addition:** if a V6-cTS-only kind (one of the additional 7) fails at Layer 5 smoke in Batch 3 but the 4 SELECTED kinds pass at Layer 2 in Batch 1, that's a separate regression class — escalate but don't block Batch 1 closure. |
| `arguzz_parser.py` `ArguzzFault.parse()` regex misses a fault format Arguzz binary now emits (drift since v6_driver_v2 days) | Low | Compare canned R2 V6 outputs to current binary output in Batch 1 Layer 2; document any drift in batch report |
| `CoverageDB.record_mutation` API doesn't fit the V6-uniform driver's data flow | Medium | Batch 3 task 3.4 is the place to surface this; may require minor `CoverageDB` extension (added in D2.C scope if needed) |
| Hybrid arm-space too large (Q9 > 300 arms) | Medium | Batch 2 task 2.5 surfaces this early; Composer proposes reductions before Batch 3 |
| `_dispatch_arm` refactor in `fuzzer.py` breaks the A4-side path (V5 golden trace fails) | Medium | Batch 1 task 1.7 lays down the golden trace; Batch 3 task 3.2 must keep it passing. If it breaks, refactor with smaller surgical changes |
| Outcome mapping (Q4) produces misleading APPLIED-count metrics | Low | Document Q4 decision in `D2C_BATCH1_REPORT.md`; D2.G analysis can re-classify if needed |
| Schema diff between R2 V6 DBs (raw constraint_loc) and D2.C V6 DBs (normalized constraint_loc) breaks legacy R2 analysis scripts | Medium | Document explicitly in §1.4 + Batch 3 report; D2.G's "compare V6 R2 vs V6 D2.C" plot will need a one-time R2 normalization pass (already exists as `constraint_loc_normalize.py`) |
| The `--inject-kind` flag isn't on the dev binary (only the prod / POS binary) | Low | Batch 1 Layer 2 surfaces this immediately; Composer reports back |
| **Soundness-signal infrastructure** produces no rows for the entire D2.C smoke runs (N=50 too small to hit the 3% rate) | Medium | Expected — N=50 × 3% = 1.5 rows. Batch 3 task 3.5 explicitly notes "probably 0–2 rows" and verifies *the wiring* not the *count*. The signal will activate at POS scale (D2.F). |
| **Bandit pull rate under prover_status-primary classifier (v0.3 Option C)** — bandit credits ~94 % of mutations as APPLIED pulls | Verified from R2 V6 DB cross-tab (§5.5) | v0.2's "95 % panic → low APPLIED" framing was a CLASSIFIER ARTIFACT, not a real skew. v0.3's prover_status-primary mapping yields ~94 % APPLIED (5674/6000), of which ~91.6 % are REJECTED (positive bandit signal) and ~2.95 % are ACCEPTED-with-soundness-signal. **No skew bug; no N-bump needed.** If Pro D2.G analysis wants finer disambiguation between Path A (C1) and Path B (C2) rejections, the `failure_recording_gap` flag is the join key. |
| The two `MAPPING_INSTR_TO_OPCODE_CLASS` (instr-level, in `arguzz_bridge`) and `major_to_opcode_class` (major-level, in `compressed_global_extractor`) drift apart over time | Low | Both are derived from the same RISC-V taxonomy; cross-cutting test asserts they agree where they overlap. |
| Soundness-signal warning logs are noisy in POS campaigns (~180 warnings per 6000 mutations) | Medium | Use `logging.getLogger("a4.arguzz_bridge").setLevel(WARNING)`; in POS the logs are persisted anyway; provide a per-campaign aggregate count in `D2C_BATCH3_COMPOSER_REPORT.md`. |
| The arm-space asymmetry (BR_NEG_COND has ~10× fewer arms than the always-applicable Arguzz kinds; STORE_OUT_MOD / LOAD_VAL_MOD / COMP_OUT_MOD even fewer in V6-cTS scope) confuses analysis | Low | Document explicitly in `IV_POS_8_NOTES_FOR_PRO.md` (NFP-12 or similar) so D2.G analysts know per-arm counts are heterogeneous in **both Hybrid-cTS (4-kind) and V6-cTS (11-kind) variants**. |

---

## 13. What ships at the end of D2.C

**New code:**
- `a4/standalone/arguzz_invoke.py` (~300 LOC; primitive)
- `a4/standalone/mutations/arguzz_bridge.py` (~250 LOC; bridge)
- `a4/standalone/v6_uniform_driver.py` (~400 LOC; modernized driver)

**Extended code:**
- `a4/standalone/semantic_arm_universe.py` — `arguzz_kinds: Optional[List[str]]` parameter (v0.4: replaces `include_arguzz_kinds: bool`; same ~50 LOC)
- `a4/standalone/fuzzer.py` — `_dispatch_arm`, Arguzz dispatch branch, `_record_arguzz_mutation`, per-strategy kind-list wiring (v0.4: ~+10 LOC over v0.3 for the FULL-vs-SELECTED branch, total ~160 LOC)
- `a4/standalone/compressed_global_extractor.py` — permanent merge of `_ARGUZZ_KIND_ROLE_EXTENSIONS` into `_TXN_ROLE_BY_KIND` (~10 LOC; `major_to_opcode_class` is NOT added — it already exists in `semantic_zones.py:101`, per §4.6)
- `a4/arguzz_dependent/arguzz_runner.py` — deprecation docstring (≤10 LOC)

**New tests** (10 files; ~750 LOC total — v0.3 split the golden trace into Tier-1 + Tier-2):
- `tests/test_d2c_arguzz_invoke_mock.py` (Layer 1)
- `tests/test_d2c_outcome_mapping.py` (Layer 1)
- `tests/test_d2c_arguzz_invoke_real_binary.py` (Layer 2, gated)
- `tests/test_d2c_arguzz_bridge.py` (Layer 3)
- `tests/test_d2c_arguzz_arm_construction.py` (Layer 4)
- `tests/test_d2c_v6_uniform_driver_smoke.py` (Layer 5, gated)
- `tests/test_d2c_hybrid_smoke.py` (Layer 6, forerunner)
- `tests/test_d2c_arm_registration.py` (cross-cutting)
- `tests/test_d2c_golden_trace_v5_decision_seq.py` (regression — Tier 1, Batch 1)
- `tests/test_d2c_golden_trace_v5_db_byte_identity.py` (regression — Tier 2, NEW in v0.3, Batch 3 after refactor lands)

**Documentation:**
- `D2C_BATCH1_COMPOSER_REPORT.md` through `D2C_BATCH4_COMPOSER_REPORT.md` (4 reports)
- `IV_POS_8_D2_C_SPEC.md` v0.5 LOCKED (this document — post-Composer-audit incorporation [v0.3] + V6-cTS kind-set scope correction [v0.4] + Phase 0 drift fix [v0.5])
- `IV_POS_8_D2_PLAN.md` v0.15 → v0.16 (D2.C row → DONE). **Forward variant kind sets** (authoritative in `New_Master.md` §1 + ProG_Report_4): `V6_uniform`/`V6_cTS` = **11 Arguzz kinds**; `Hybrid_cTS` = **11 live A4 + 4 selected Arguzz**; `V5_expanded` = **11 live A4** (post-D2.B-PS-1). Older plan/NFP tables stating "4 V6" or "16 A4" are superseded.
- Optional: `IV_POS_8_NOTES_FOR_PRO.md` NFP-12 (Arguzz arm-space asymmetry + soundness-signal triage protocol)

**Frozen reference (unchanged):** `a4/runs/iv_pos_7/drivers/v6_driver_v2.py`

**Test count expectation (v0.3 corrected):**
- Pre-D2.C baseline: **609 passed, 19 skipped, 1 xfailed** (verified via `python -m pytest tests/ -q --ignore=tests/test_run_replicates.py` at commit `e2c2256` = "d2.b-ps-1: remove 5 dead arms from MUTATION_KINDS"). v0.2 said "18 skipped" — wrong by one. The baseline IS post-§9c-postscript because HEAD `e2c2256` is the postscript commit itself (MUTATION_KINDS = 11 entries, 5 dead arms removed).
- Post-D2.C: ~670–685 passed (Δ ~60 new logical cases — Layer 1 mock + outcome mapping + arm-construction parametrized over both kind-lists + bridge wiring + cross-cutting registration over the 11-kind FULL superset (66 cases, v0.4 expansion); 2 layers gated on real binary).
- Full sweep gate: all previously-green tests still green + new tests pass.

---

## 14. Acceptance criteria (NEW in v0.2)

D2.C is **closed** when ALL of these hold:

1. **All four Composer batches** complete with their respective acceptance gates met (§11).
2. **`A4Fuzzer.MUTATION_KINDS`** is unchanged from `e2c2256` (11 kinds: 8 V5 + 3 D2.B-live). D2.C does **not** add anything to `MUTATION_KINDS` — Arguzz kinds live in **two separate constants**, `MUTATION_KINDS_ARGUZZ_FULL` (11) for V6-cTS and `MUTATION_KINDS_ARGUZZ_SELECTED` (4) for Hybrid-cTS, in `a4/standalone/mutations/arguzz_bridge.py`. Both are only included via `SemanticArmUniverse.build(arguzz_kinds=...)` (v0.4 parameter signature).
3. **`arguzz_kinds=None`** produces byte-identical behavior to pre-D2.C — V5 golden-trace test passes.
4. **Layer 2 real-binary smoke** is green for the 4 SELECTED kinds on the dev box (Batch 1 scope; Layer 2 is gated and the 4-kind subset is sufficient to validate the primitive — the additional 7 V6-cTS kinds are exercised by the same primitive code path at the kind-string level, which the mock test in Layer 1 covers).
5. **Layer 5 V6-uniform driver smoke** is green: 50 mutations, **≥6 of the 11 ENABLED_KINDS present** (matches `test_d2c_v6_uniform_driver_smoke.py` assertion in §4.8), with the 4 SELECTED kinds (INSTR_WORD_MOD, PRE_EXEC_MEM_MOD, PRE_EXEC_PC_MOD, BR_NEG_COND) MUST all be present (these 4 are always-applicable except BR_NEG_COND which requires branches; sha2-host has branches, and balanced-RR over 11 kinds at N=50 produces ~4-5 invocations per kind, comfortably above the ≥6/11 floor). `outcome` column populated; `coverage.constraint_loc` is `Name@basename:line`; `compressed_global_coverage` non-empty; `extra_json` field has `driver_version="v3_d2c"`.
6. **Layer 6 Hybrid forerunner** is green: stubbed primitive, 50-mutation campaign with both surfaces pulled (Hybrid-cTS uses 4 SELECTED Arguzz kinds + 11 A4 kinds).
7. **Cross-cutting arm registration test** green: **11 V6-cTS Arguzz kinds × 6 assertion layers = 66 cases** (v0.4 expansion from 24 in v0.3). The Hybrid-cTS scope (4 SELECTED kinds × 6 layers = 24 cases) is implicitly covered since `MUTATION_KINDS_ARGUZZ_SELECTED ⊂ MUTATION_KINDS_ARGUZZ_FULL`. (v0.3 reconciliation history: v0.2 §11 Batch 4 acceptance said "96 cases = 4 × 6 × 4 instr-class coverage"; v0.3 honored §4.8's 24-case definition; v0.4 expands to 66 cases for the FULL kind-list.)
8. **`v6_driver_v2.py`** is unchanged at `a4/runs/iv_pos_7/drivers/v6_driver_v2.py`.
9. **R2 V6 DB schema parity** documented in Batch 3 report (with normalized `constraint_loc` + `outcome` column as the deliberate diffs).
10. **Plan v0.16** reflects D2.C → DONE; D2.D unblocked.
11. **`workspace/risc0-modified/`** unchanged (D2.C is host-side only).
12. **Soundness-signal infrastructure** is wired (Batch 3 task 3.5) even if no signals fire in the N=50 smoke (the wiring is what matters for POS-scale runs).

**Deferred to D2.D / D2.E / D2.F / D2.G:**
- CLI flag wiring (`--selector=hybrid_cTS`, `--selector=v6_cTS`, `--variant=v6_uniform`) — D2.D
- Integration tests with real bandit + variant flag combinations — D2.E
- POS dispatch for 4-variant campaigns — D2.F
- Cross-variant statistical analysis (V5 vs V5_expanded vs V6-uniform vs V6-cTS vs Hybrid-cTS) — D2.G
- Soundness-signal triage (the ~3 % prove_success rows from POS-scale runs) — D2.G

---

*End of D2.C spec v0.5 — LOCKED. Phase 0 complete (2026-06-19).*

**Next steps:** Opus drafts Batch 1 kickoff; Composer implements per spec §11 once kickoff is issued.

**v0.5 changelog (vs v0.4 — Phase 0 drift fix):**

1. §7 **S5** — `pre_post` row corrected: per-kind `_PRE_POST_BY_KIND` (5 `pre_exec` + 6 `post_exec` for FULL; 4 `pre_exec` for SELECTED), not "all `pre_exec`".
2. §13 plan-update note — forward variant kind sets aligned to `New_Master.md` §1 / ProG_Report_4 (V6-cTS = 11; Hybrid = 11 live A4 + 4 Arguzz; not "16 A4 + 4 V6").
3. Companion doc sweep (outside `separate-planning/`): `IV_POS_8_NOTES_FOR_PRO.md` NFP-2 variant table; `IV_POS_8_D2_PLAN.md` §6c S5 layer; `IV_POS_8_D2_B_SPEC.md` Q6 supersession pointer.
4. Parent-citation bump — header `Parent:` line corrected from `D2_PLAN v0.15 §3` → `v0.16 §3` (D2_PLAN advanced to v0.16 at the D2.B-PS-2 postscript; the D2.C parent pointer had lagged a version).
5. Spec status → **LOCKED v0.5**; Phase 0 closed.

**v0.4 changelog (vs v0.3):**

1. §0 (this changelog), §1.1 (two-tier scope tables), §1.2 (arm-shape map covers all 11 kinds + per-kind `pre_post` + per-variant arm-space), §3.1 (semantic_arm_universe row), §3.4 (FULL/SELECTED constants + per-strategy wiring), §3.5 (binary support 4 → 11), §4.1 (kind-list constants moved to bridge), §4.2 (`valid_injection_kinds_for_instr` lifted to 11; `_PRE_POST_BY_KIND` constant; `MUTATION_KINDS_ARGUZZ_FULL` / `_SELECTED`), §4.3 (`arguzz_kinds: Optional[List[str]]` parameter), §4.4 (per-strategy kind-list wiring code shape), §4.6 (TXN_ROLE forward-compat note → operational note), §4.8 (arm-construction parametrize over 11 + 4; bridge test parametrize over both kind-lists; V6-uniform smoke ≥6 of 11; cross-cutting registration 24 → 66), §5 (per-kind analysis scope note), §5.5 item 6 (4-kind subset → Hybrid slice; full 11-kind data applies for V6-cTS), §7 S1, §9 Q9 (per-variant arm-count estimates), §10 Q9 row (v0.4 source), §11 tasks 2.2/2.5/4.2 + Batch 1/Batch 3/Batch 4 acceptance gates, §12 risk row, §13 (LOC bumps + extended code description + locked-version line), §14 (#2/#3/#4/#5/#6/#7 reconciliation).
2. **V6-cTS scope: 4 → 11 Arguzz `ENABLED_KINDS`** (per Pro `ProG_Report_3.md` §9 lines 277-302: V6-cTS = "Arguzz kinds **only**, but selected by constrained TS"). Hybrid-cTS keeps the 4 SELECTED kinds (Pro `ProG_Report_3.md` §8 Track A priority 1-4 list, lines 228-238 — v0.4-final citation fix; v0.2/v0.3 erroneously cited "§15.2", which is actually Pro's "Bug-isolation layer" sub-section, not kind selection). Without the V6-cTS scope split, V6-uniform-vs-V6-cTS would test scheduler effect AND kind-set restriction simultaneously, defeating the comparison's purpose.
3. **Constants split.** `MUTATION_KINDS_ARGUZZ` (v0.3) → `MUTATION_KINDS_ARGUZZ_FULL` (11; V6-cTS) + `MUTATION_KINDS_ARGUZZ_SELECTED` (4; Hybrid-cTS). Both defined in `a4/standalone/mutations/arguzz_bridge.py`.
4. **Parameter signature.** `SemanticArmUniverse.build(include_arguzz_kinds: bool = False)` → `SemanticArmUniverse.build(arguzz_kinds: Optional[List[str]] = None)`. Caller picks the kind list; the universe builder is strategy-agnostic. The strategy → kind-list mapping lives in `fuzzer.py`.
5. **`valid_injection_kinds_for_instr` lifted** to verbatim copy of `v6_driver_v2.py:176-191` (full 11-kind dispatch with BRANCHES/COMPUTATIONS/LOADS/STORES instruction-class restrictions). v0.3 had only the 4-kind subset.
6. **`pre_post` axis non-trivial.** v0.3 had all 4 kinds at `pre_exec`. v0.4 introduces the convention (per §1.1.A): 5 `pre_exec` kinds + 6 `post_exec` kinds. `_PRE_POST_BY_KIND` constant is added to `arguzz_bridge.py`. This finally exercises D2.A's `pre_post` arm-shape axis on both sides.
7. **Arm-space estimates split.** Hybrid-cTS ~160-240 (unchanged); V6-cTS ~200-350 (NEW; touches 300-arm advisory). Both within Pro's "100s" ceiling. Reduction levers (`jump`-into-`branch` opcode_class merge; <5-step zone collapse; pre/post merge if data-uninformative) remain available; Batch 2 measurement reports actuals before any reduction.
8. **Test parametrization expanded.** Arm-construction test: 4 kinds × 7 classes (v0.3) → both kind-lists × 7 classes × per-kind pre_post (v0.4). Cross-cutting registration test: 24 cases (v0.3) → 66 cases (single parametrization over `MUTATION_KINDS_ARGUZZ_FULL` × 6 assertion layers, v0.4); Hybrid scope is implicitly covered by the SELECTED-subset (no separate test block needed).
9. **Empirical analysis re-anchored.** §5.5 items 1-5 (R2 V6 outcome breakdown) computed across the full 6000-row corpus → apply directly to V6-cTS. The 4-kind subset (2446 rows) becomes the "Hybrid-cTS slice" referenced in §5.5 item 6. The 91.6% APPLIED+REJECTED / 5.2% SKIPPED Option C numbers do not change.
10. **Acceptance criteria reconciliation.** §14 #2 (constants split into FULL + SELECTED), #3 (`arguzz_kinds=None` instead of `include_arguzz_kinds=False`), #5 (V6-uniform smoke covers ≥6 of 11), #7 (registration test 66 cases).

**v0.3 changelog (vs v0.2):**

1. §0, §1.2, §1.5, §3.3, §3.5, §4.1, §4.2, §4.4, §4.6, §4.8, §5.5, §6.1, §6.2, §6.4, §7 S5, §8, §9 Q4, §9 Q8, §10 Q4/Q8 rows, §11 tasks 1.7/3.2a/3.2b + Batch 1/Batch 3/Batch 4 acceptance gates, §12 line 849, §13 baseline + new tests, §14 #7.
2. Outcome mapping flipped from `host_panic`-primary to `prover_status`-primary (Option C). 91.6 % of bandit signal recovered.
3. Opcode-class taxonomy realigned to D2.A LOCKED 7-class set (`arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`); `pre_post` = `"pre_exec"`.
4. `_detect_host_panic` checks both `"panicked at"` AND `"Guest panicked:"`.
5. `soundness_signal` + `failure_recording_gap` ownership pinned to primitive layer.
6. `major_to_opcode_class` documented as EXISTING (not new); two-taxonomy split (arm-shape vs CGC) made explicit.
7. False D2.B applied-accounting POS claim removed; explicit Batch 3 wiring task added (3.2a).
8. ArmKey citation corrected: `semantic_arm_universe.py:174-182` (not `bandit_ts.py`).
9. Test baseline corrected: 19 skipped (not 18). HEAD `e2c2256` ("d2.b-ps-1: remove 5 dead arms from MUTATION_KINDS") IS the §9c postscript commit, so the baseline is correctly post-postscript; the `(post-§9c)` qualifier is accurate, just the count was off by one in v0.2.
10. Registration test case count reconciled to 24 (§4.8's definition); ×4 instr-class multiplier in §14 #7 removed (that's the arm-construction test's parametrization).
11. Golden trace upgraded to two-tier: Tier-1 decision-sequence parity in Batch 1 (<1s, matches D2.A/D2.B precedent) + Tier-2 DB byte-identity in Batch 3 (~10s, catches downstream serialization drift after the `_dispatch_arm` refactor lands).
