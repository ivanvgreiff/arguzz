# Cloud1 — Decisions Made Beyond Pro's Recommendations

**Audience**: ChatGPT Pro, Round 2 review (after IV.POS.7 runs).
**Purpose**: Transparently record every concrete design decision we made while implementing your `ProG_Report_2.md` recommendations. Where you gave a specification, we followed it. Where you left a choice open OR were silent on a detail, we made a decision — and this document records each such decision with our justification, so you can flag any you disagree with when reviewing IV.POS.7 results.

**Source of truth for recommendations**: `a4/docs/cloud1/ProG_Report_2.md` (your output to us).
**Source of truth for implementation plan**: `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md`.

---

## Decision summary table

For each decision: was it (P) Pro-specified, (P-range) Pro gave a range/set of options, or (U) you (Pro) were silent and we (Ivan + Cursor) decided?

| # | Topic | Pro spec | Our choice | Type |
|---|---|---|---|---|
| D1 | Seeds per variant (IV.POS.7) | §10 "five paired seeds first. If feasible, ten is better, but five is enough to triage" | **10 seeds** | P-range |
| D2 | Pilot calibration | §9 "use one deterministic shared calibration profile across all strategies, or remove calibration from the reward variants entirely" | **Remove pilot calibration entirely** | P-range |
| D3 | Guest program scope | §11 step 5: "Add new guest programs that exercise BigInt/Poseidon/Keccak/control paths" — but as step 5, AFTER selector fix and re-run | **sha2-host only for IV.POS.7** (defer new guests to post-Pro-R2) | P |
| D4 | Thompson sampling prior | implied by §7.D Bernoulli success target; specific prior not stated | **Beta(1, 1) uniform** | U |
| D5 | Code layout | not addressed | **Alongside existing in `a4/standalone/`** with `_v2`/`_semantic`/`_ts` suffixes; old strategies remain importable | U |
| D6 | Old strategy retention | §14.2 only says to rename | **Keep all 3 runnable**: `arm_uniform_b128`, `kind_uniform_zoned_step`, `ucb_kindbucket_b16` | U |
| D7 | Semantic zones not present in current guest | §7.A lists 17 zones but does not address absent zones | **Define all 17, runtime-skip empty** zones so code is portable to future guests | U |
| D8 | Compressed global context schema | §5 specifies fields verbatim | **Adopt verbatim** | P |
| D9 | Constrained-TS floor / adaptive split | §7.C: "50-60% reserved coverage floor + 40-50% adaptive" | **55/45** | P-range |
| D10 | Cold-start pulls per (kind, zone) arm before TS | §7.A says "guaranteed minimum pull count" for singleton arms; no number for the general TS cold-start | **3 pulls per arm** (matches old `_N_TARGET=3` convention) | U |
| D11 | POS execution mode | not addressed | **Continuous 3-parallel** multi-day reservation | U |
| D12 | `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` disposition | §14.2 only addresses code/strategy renaming | **Leave the diagnostic as historical record** + add a top-line note noting renaming; do not rewrite | U |
| D13 | ECALL cycle itself: which zone? | §7.A lists `pre_ecall`/`post_ecall` as adjacency zones; silent on the ECALL cycle itself | **Classify the ECALL cycle as `pre_ecall`** (boundary zone); `post_ecall` = e+1 | U |
| D14 | MRET and halt adjacency in Phase 2 | §7.A lists `pre_mret`/`post_mret`/`pre_halt`/`post_halt` | **Leave EMPTY for IV.POS.7** (no separate `major` for MRET / halt in `InspectionData`; deferred to post-IV.POS.7) | U (limitation) |
| D15 | `BIGINT0` (major=12) zone | not addressed (Pro listed `core_sha`/`core_poseidon` but no `core_bigint`) | **Map BIGINT → `core_other`** (no semantic distinction in Phase 2) | U |
| D16 | Source of `txn_role` and `cycle_phase` in `GlobalMemoryCtx` | §5 lists allowed values but does not specify whether they come from the per-failure metadata (which Hook 3 does not expose) or the mutation context | **Derive from the MUTATION CONTEXT**: txn_role from mutation kind, cycle_phase from semantic zone of mutation step | U |
| D17 | `address_bucket` scheme for `GlobalMemoryCtx` | §5: "page or log2-range bucket" — choice of scheme left open | **log2-range bucket**: `floor(log2(max(addr, 1)))` → 32 buckets max | P-range |
| D18 | `lookup_index_bucket` scheme for `GlobalLookupCtx` | §5: lists field but does not specify bucket scheme | **log2-range bucket** (same as D17, for consistency) | U |
| D19 | Compressed-global per-run safety cap | not addressed | **64 per run** (3-4× the natural cardinality of ~10-20) | U |
| D20 | Constraint-family extraction from `constraint_loc` | §6.1 gives examples (`inst_mem, inst_mul, ...`) but no parse grammar | **Primary**: substring between `@` and `.zir` via `re.compile(r"@([^@]+?)\.zir")`. **Fallback**: prefix before `@` if no match; else stripped full string. | P-range |
| D21 | Definition of `repeat` | §8: "number of already-seen local contexts hit again" | **Campaign-level set semantics**: `\|{(constraint_loc, major, minor) in this run's failures : tuple was already in seen_local_v2 BEFORE this run}\|`. NOT within-run cascade. | P |
| D22 | Set vs multiset for `l_new` within one run | §6.1: "New local semantic context" | **SET semantics** within a run; 5 instances of the same `(loc, major, minor)` contribute 1 to `l_new`. | P (strong implication) |
| D23 | `no_qloc_reward` formula in `reward_counterfactuals` | §12 names the counterfactual but doesn't give a formula | Forced `Q_loc = 1.0` in legacy formula → `no_qloc_reward = min(1.0, Q_rep * Q_glob * S)` for `mode=normal`; `0.0` for `crash`; `1.0` for `accepted`. | U |
| D24 | Default `txn_role` in `txn_role_for_kind` | §5 lists allowed values; no rule for unmapped kinds | **`read`** as default. Most common role for raw memory operations; least likely to mislead downstream classification. Documented as a known approximation, not a derivation from cycle data. | U |
| D25 | Geometric residue in compressed global ctx | §5 specifies `address_region` + `address_bucket`; we adopted both | **Adopted verbatim, but flagged for Pro R2** — see "Open question for Pro" section below. The 7 regions × 32 log2 buckets = 224 keys per `(txn_role, cycle_phase)` is 19 orders of magnitude smaller than raw 2^32, but still encodes a coarse geometric signal. We follow Pro §5 literally; if Pro wants strictly non-geometric (e.g. region-only) we can collapse buckets. | P (with concern logged) |
| D26 | Unknown-family handling in compressed-global extractor | not addressed | **Silent skip + future logging**: current Phase 3 extractor returns `[]` for unknown families. Phase 7 will add a 1-line `logger.warning("unknown hook3 family: %s", fam)` so any Hook-3 evolution doesn't go unnoticed. Not changing the extraction logic. | U |
| D27 | Retroactive correction to Phase 2 "MAJOR_TO_CORE_ZONE bug" framing | n/a | Phase 2 retrospective described the fix as a "bug in mappings". More precisely: the original Phase 1 map was built by aligning Pro's *zone-name listing order* with positional integers, ignoring that two different `major` schemes exist (`insn_decode.major` = `kind // 8` with 8 values 0–7, vs `cycle.major` = circuit execution-phase enum with 13 values 0–12). The map was a hybrid that matched NEITHER scheme. The "fix" was to commit to `cycle.major` (the one `zone_classifier.py` actually receives via `InspectionData.cycles[step].major`). See `phases/PHASE_2_SEMANTIC_ZONES.md` §6 for the corrected framing. | U (clarification) |
| D28 | Floor-constraint priority order in `ConstrainedTSScheduler` | §7.C describes cold-start + boundary floors + adaptive TS; no explicit ordering when multiple constraints bind | **cold (`pulls < 3`) → singleton (`pulls < 5`) → epoch (`epoch_pulls < 0.55·E/n`) → adaptive TS**. Strict short-circuit at each level. | P-range |
| D29 | Cold-start tie-breaking among under-pulled arms | silent | **Round-robin** (deterministic) over sorted arm list, not `rng.choice`. | U |
| D30 | Whether cold/singleton pulls count toward epoch floor | silent | **Yes** — `epoch_pulls[arm]` increments on every `update()`, regardless of selection mode. Avoids double-allocating the 55% budget. | U |
| D31 | Kind-level UCB reward signal for Variant 3 (`kindUCB_zoned_v2_noQ`) | §8.1 names ablation axis "v2 (no Q_loc)" | **Full `compute_reward_v2(...)` scalar**, NOT `no_qloc_reward` counterfactual. v2 IS the "no Q_loc" reward (v2 has no Q_loc by construction); the counterfactual is for offline ablation analysis (Phase 9), not live UCB. | P-range |
| D32 | Thompson sampling update signal (Variants 4 & 5) | §7.D + §8 `compute_bandit_success` | `KindLevelTSScheduler` and `ConstrainedTSScheduler` call `update(arm, compute_bandit_success(l_new, g_new, s_new))` — int 0/1 Bernoulli, NOT scalar `compute_reward_v2`. Scalar v2 still computed and stored for logging/Phase 9. | P |
| D33 | `KindLevelUCBScheduler` uses undiscounted UCB1, not legacy DiscountedUCB | not addressed; Pro §7.D steers toward TS | **Undiscounted UCB1** (`mean + c·√(ln t / n)`), c=0.25. Reasoning: V2↔V3 must share UCB algorithm for clean reward ablation; replicating IV.POS.5's two-level discounted UCB would also require the bucket axis (no longer present). Net deviation: V2 is NOT an exact IV.POS.5 rerun; it's a kind-only undiscounted UCB baseline. | U |
| D34 | `value_class` taxonomy for `mutation_substrategy` | §6.1 names `zero \| small \| large \| bit_pattern`; no algorithm | **XOR-bit-count heuristic**: `mut==0`→zero; `XOR ≠ 0 ∧ popcount(XOR) ≤ 4`→bit_pattern; `mut < 256 ∨ wrap(\|mut−orig\|) < 256`→small; else→large. | U (heuristic — see G6) |
| D35 | Default `--telemetry-level` per selector | §6.3 intent: full for IV.POS.7, standard for legacy | **`full`** when `selector_strategy ∈ V2_BANDIT_STRATEGIES`, else **`standard`**. Explicit CLI override always wins. | P-range |
| D36 | `hook3_raw.raw_json` schema | §12 says "raw family details if small enough"; no schema | **`{"family_residues": [...], "family_details": [...]}`** with keys omitted when empty. `compressed_ctx_json` stores a JSON list of compressed context dicts (D17/D18 schema). | U |
| D37 | `mutation_substrategy` for `MEM_VAL_MOD` without explicit `byte_lane` | §12 names byte_lane/bit_mask; fuzzer config lacks byte_lane | **`bit_mask = original XOR mutated` (32-bit); `byte_lane = min(31, max(0, XOR.bit_length() − 1))`** — index of highest differing bit. Zero XOR → `byte_lane=0, bit_mask=None`. | U |
| D38 | `bandit_decisions` / `arm_state_snapshot` gating under `--telemetry-level=standard` | not addressed | **Both gated to `full`** in v2 path (Composer's "one knob" consolidation). Net effect: default for v2 is `full` so production is unaffected; only explicit `standard` with a v2 selector would silently disable bandit logging. Tradeoff: simpler mental model vs. footgun on explicit downgrade. See G6 for Pro's verdict. | U |
| D39 | Phase 7 hybrid structure (3 sub-phases: local 7a, POS 7b, semantic 7c) | not addressed | **Three-stage smoke**: (7a) 5 variants × N=20 on WSL — catches crashes/NaN/schema cheaply (~50 min, $0 POS cost). (7b) 5 variants × N=200 on POS — budget-relevant measurements (DB size at extrapolated N=6000 ≤ 150 MB; V5/V1 wall-time ≤ 1.3×). (7c) 24-sample stratified mutation-semantic verification on V5 DB — resolves G2 internally by proving we mutate what we think we mutate. ALL THREE required for Phase 7 exit. User-approved 2026-06-08. SUPERSEDED by Phase 7d (D41). | U |
| D40 | Multi-cycle step disambiguation (Phase 7d) | not addressed | **Pick option (b) — drop multi-cycle steps from universe — unless it drops > 4 arms** (in which case fall back to option (a): plumb `cycle_idx` through mutation config and Rust hook in `witgen/mod.rs`). Phase 7c rev2 evidence: INSTR_TYPE_MOD id=12 step=0 hook applied to wrong cycle at multi-cycle step (hook old=7/0 ECALL but config exp_old=2/6 AddI). Rationale: cleaner, no Rust rebuild, addresses root cause. Composer confirms final choice + documents arm-count cost during Phase 7d.1 work. | U |
| D41 | Phase 7d split (semantics gate before variants gate) | not addressed | **Phase 7d = 7d.1 (semantics & arms: A1-A5) + 7d.2 (variants & isolation: B1-B12), gated sequentially**. 7d.1 must exit all-green before 7d.2 starts. Rationale: no point verifying variants on top of broken arm space; variant correctness cannot fall out of Phase 8 runs because Phase 8 results would be invalidated by any variant bug. Phase 7d replaces Phase 7c as Phase 8 gate. | U |
| D42 | Non-deterministic mem-txn allow-list for MEM_VAL_MOD targets | not addressed | **Exclude 188 addresses identified by Phase 7d Audit A1 from MEM_VAL_MOD targets** via auto-generated `a4/audits/audit_output/A1_nondet_addrs.json` (host I/O regions `0x42000000+` HOST_ECALL_ADDR and `0x000884e6+` user journal buffer at steps 170, 3929). Without this, MEM_VAL_MOD's `original_value` baseline disagrees with actual runtime in ≤0.7% of mem txns; verifier strict mode would falsely fail. Cycle structure + reg txns are 100% deterministic; arms targeting reg writes are unaffected. | U |
| D43 | True second-guest robustness test (B12) | not addressed | **Defer true second-guest test to post-Phase-8**; Phase 7d Audit B12 uses input variation (`--in1 1 --in4 1`, `--in1 100 --in4 100`) as cheap substitute. Rationale: building a second `risc0-host` binary linked to a different guest requires ~2 hours of build + integration work which is not on the Phase 8 critical path. Input variation still catches input-sensitivity bugs in the architecture; guest-shape robustness check can be done in Pro Round 2 follow-up. | U |
| D44 | Per-arm human-readable evidence pack (E5) | not addressed | **Add Audit E5 as Increment 5 of Phase 7d.** Produces one `audit_output/per_arm_evidence/<kind>_<zone>.md` per kept arm (48 for current guest) with EXAMPLE 1 (Composer's correct-classification candidate) + EXAMPLE 2 (worst/incorrect row, if found). Reuses B1 verifier + B4 traceability dataframes; no new infrastructure. Acceptance: zero arms with ✗ INCORRECT aggregate verdict; any ✗ requires E4 review or code fix. Purpose: gives user concrete per-arm evidence for semantic-label correctness rather than just "all audits passed" trust. | L (Phase 7d) |
| D45 | Variable definitions in audit output (D45 convention) | not addressed | **All Phase 7d audit output (JSON + markdown) MUST define every non-obvious variable inline OR via link to `cloud1/GLOSSARY.md`.** JSON outputs include a top-level `_meta: {glossary: <path>, definitions: {<var>: <desc>}}` block. Markdown outputs reference the glossary at the top of each file. This is non-negotiable per Composer brief. Enforced via E5 acceptance gate. | L (Phase 7d) |
| D46 | ECALL major=8 vs decoded major=7 taxonomy | not addressed | **Accept as expected behavior.** RISC0 circuit places ECALL execution in its own cycle table (`cycle.major=8` ECALL0); RV32IM encoding has ECALL as a SYSTEM instruction (`decoded.major=7 minor=0` Eany, opcode `0x73`). Both correct from respective perspectives. Inc 3 Audit B1 strict verifier MUST accept either `cycle.major == decoded.major` OR `(cycle.major == 8 AND decoded.major == 7 AND decoded.minor == 0)`. Documented in `cloud1/GLOSSARY.md` §Cycle terminology. Resolves Inc 1 E4 queue items DM-1, DM-2, DM-5. | L (Inc 1) |
| D47 | The 4 D40-dropped INSTR_WORD_MOD arms — formal disposition | not addressed | **Move `INSTR_WORD_MOD_{FULL,SUR}\|{last_step,pre_ecall}` to "Dropped by D40" section of `EXPECTED_ARMS.md`.** These arms lost their only valid steps to the P3 multi-cycle filter (last_step = HALT+cleanup multi-cycle; pre_ecall = ECALL+adjacent instr multi-cycle for the major≤6 OR major==8 filter). Not recoverable without D40 option (a) Rust rebuild; out of scope for Phase 7d/8. Composer to update EXPECTED_ARMS.md after Inc 1 joint review completes. | L (Inc 1) |
| D48 | Split `core_branch` zone into `core_branch_user` + `core_branch_kernel` (Q4 resolution) | not addressed | **Split based on PC range** in `zone_classifier.py`. Current `core_branch` (major=7 only) was found to conflate user-mode branches (Beq/Jal/JalR at user PC range `0x00040400..0x0C000000`) with kernel/trap control flow (mret/Eany/trap-handler returns at kernel PC range `0xC0000000..0xFFFEFFFF`). E1 Audit (Inc 1) found 5-7 of 10 sampled steps in `MEM_VAL_MOD\|core_branch` were at kernel PCs — semantic-label correctness violation. New zones added to `SEMANTIC_ZONES`. Pre-fix **P4** lands between Inc 1 closure and Inc 2 start; Composer re-runs A1-A5 + E1 + E3 on the new universe before Inc 2. SEMANTIC_ZONES count: 17 → 18. Resolves Inc 1 E4 queue items DM-3, DM-4 + Q4 in `EXPECTED_ARMS.md`. | L (Inc 1) |
| D49 | Arm enumeration is dynamic per guest, never permanent | implicit in Pro §7.A | **Confirm explicitly:** `SemanticArmUniverse.build()` enumerates the full kind × zone cross-product (currently 8 × 17 = 136 pairs; post-D48: 8 × 18 = 144) and keeps only non-empty pairs per trace. Empty arms in c0c1_differential (`core_sha`, `core_poseidon`, `pre_mret`, etc.) are NOT removed from the codebase; they auto-populate in any future guest that exercises them. This is the design principle that makes Phase 10 multi-guest work without code changes. Used to clarify Inc 1 review: splitting `core_branch` does not "lose" arms for future guests; it gives them more granular zones to populate. | L (Inc 1) |

---

## Detailed justifications

### D1 — 10 seeds (Pro range: 5-10)

You wrote (§10): *"Use five paired seeds first. If feasible, ten is better, but five is enough to triage."*

We picked **10**. Reasoning:
- Ivan's POS infrastructure has now been proven (IV.POS.5) for multi-day continuous-reservation runs. 5 vs 10 seeds is roughly 10h vs 20h wall-clock at 3-parallel — both fit within our weekly POS calendar quota.
- IV.POS.5 had σ across 5 seeds of 0.49 (zoned) to 1.96 (uniform) for final coverage. With high-variance strategies (UCB, TS), 5 seeds may be too few to detect a 2-context AUC gap with p<0.05.
- Pro's "ten is better" is interpreted as a quality preference; we satisfy it.

**Risk if Pro disagrees**: 10 seeds doubles compute cost. If Pro now says 5 was sufficient and 10 was waste, the cost is wall-clock, not coverage.

### D2 — Remove pilot calibration entirely (Pro range: shared profile OR remove)

You wrote (§9): *"For IV.POS.7, use one deterministic shared calibration profile across all strategies, or remove calibration from the reward variants entirely."*

We picked **remove entirely**. Reasoning:
- Your new reward (§8) has fixed weights (1.00, 0.30, 0.25, 0.15, -0.50, -0.05) and fixed saturation taus (1, 1, 3, 2, 5). Nothing remains to calibrate.
- The old pilot calibrated `tau_new`, `tau_d`, `K_T_rare`, `gamma`. The first two are subsumed by your fixed taus. `K_T_rare` and `gamma` are not used in TS (no discounting; rarity is captured via `g_new`).
- Removing the pilot avoids the IV.POS.5 anti-pattern where bandit's pilot consumed 100 of 6000 mutations AND produced cross-seed variance in calibrated params (§17.17 of `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md`).
- All 5 IV.POS.7 variants therefore start with identical fixed `CalibratedParams` and identical reward functions (only the SELECTION strategy differs).

**Note**: we still LOG a "pilot_runs" table for completeness, populated only by variants that we'd want to compare on if Pro later decides to re-introduce calibration. For IV.POS.7 this table will be empty for all 5 variants.

### D3 — sha2-host only (Pro: not until step 5)

You wrote (§11): *"The right order is: 1. Fix action representation and reward... 2. Demonstrate the selector behaves sensibly against zoned. 3. Add TXN_PREV_WORD_MOD and TXN_PREV_CYCLE_MOD. 4. Re-run with semantic zones and constrained exploration. 5. Add new guest programs that exercise BigInt/Poseidon/Keccak/control paths."*

IV.POS.7 is your steps 1-2. We are NOT doing 3, 4, or 5 in cloud1.

Reasoning:
- A clean A/B against the IV.POS.5 zoned baseline requires the SAME universe (46 contexts). Adding guests would change the universe (likely 60-80+), breaking the comparison.
- The "main candidate" variant (`cTS_semantic_v2`) must demonstrate value on the universe Pro saw zoned win on; otherwise the comparison is muddy.

**Risk if Pro disagrees**: if Pro later says "you should have at least one auxiliary guest to validate semantic zone generalization", we can run a single second-guest variant in a follow-up campaign at low marginal cost.

### D4 — Beta(1, 1) prior (Pro: silent)

You did not specify a TS prior. We picked **Beta(1, 1)** uniform.

Reasoning:
- Beta is the conjugate prior to Bernoulli, which matches your `success = 1 if (l_new + g_new + s_new) > 0 else 0` target.
- Beta(1, 1) is the standard uninformative prior used in TS literature (Russo et al. 2018, Chapelle & Li 2011) for binary-reward bandits.
- Cold-start (D10 = 3 pulls minimum per arm) means TS begins selecting at pull #4 per arm, by which point posterior mass is heavily updated by data — prior choice has limited effect.
- We considered Jeffreys Beta(0.5, 0.5) but it bimodally concentrates on extreme means, which is undesirable for a discovery task with smooth success-rate prior.
- We considered an empirical prior from IV.POS.5 data, but that would re-introduce the calibration variance we removed in D2 AND couple v2 behavior to v1 data — bad for clean experimental design.

**Risk if Pro disagrees**: choice of prior matters only in first ~5 pulls/arm post-cold-start. Beta(1,1) is the most defensible default.

### D5 — Code layout: alongside existing with suffixes (Pro: silent)

You did not specify a code layout. We picked **alongside existing in `a4/standalone/`** with `_v2`/`_semantic`/`_ts` suffixes.

Reasoning:
- IV.POS.7 Variant 1 requires `zoned_current` (the old `ZonedStepSelector`). Old strategies must remain runnable.
- A clean `a4/standalone/v2/` subpackage forces either code duplication (`arm_universe.py`, `coverage_state.py` shared by both versions) or careful boundary maintenance (cross-imports between v1 and v2 modules).
- "Alongside with suffixes" minimizes refactor risk and lets us reuse shared helpers (`db.record_mutation()`, `host_runner.run_a4_mutation()`, etc.) without duplication.
- Post-IV.POS.7, if v2 wins decisively, we can reorganize into a clean `v2/` subpackage with full information.

Files we create (new, alongside existing):
- `a4/standalone/semantic_zones.py` — zone enum + classifier
- `a4/standalone/semantic_arm_universe.py` — `(kind, zone)` arm space
- `a4/standalone/step_selector.py` — extended with `SemanticZoneStepSelector` (new class in same file as `ZonedStepSelector`)
- `a4/standalone/compressed_global.py` — `GlobalMemoryCtx`, `GlobalLookupCtx`
- `a4/standalone/compressed_global_extractor.py` — raw → compressed
- `a4/standalone/structural_cells.py` — `StructuralCell` dataclass
- `a4/standalone/reward_v2.py` — new reward function
- `a4/standalone/bandit_ts.py` — `ConstrainedTSScheduler`
- `a4/standalone/coverage_db.py` — extended with new tables (in-place edit)
- `a4/standalone/fuzzer.py` — extended with new selector dispatch branches (in-place edit)

### D6 — Keep all 3 old strategies runnable (Pro: silent)

You only said to rename them (§14.2). We chose to keep all 3 runnable.

Reasoning:
- IV.POS.7 Variant 1 (`zoned_current`) MUST be runnable as the reference.
- Removing `arm_uniform_b128` and `ucb_kindbucket_b16` saves nothing (no disk, no compile time) but removes the option to run sanity ablations.
- Renaming for display only: internal selector string names are kept (`uniform`, `zoned`, `bandit`) to maintain DB schema compatibility with IV.POS.5 data. A `STRATEGY_DISPLAY_NAMES` dict provides Pro's rename for human-facing output.

### D7 — Define all 17 zones, runtime-skip empty (Pro: silent on absent zones)

You defined 17 semantic zones in §7.A. We define all 17 in code; the `SemanticArmUniverse` builder skips arms with zero valid steps for the current guest.

Reasoning:
- The IV.POS.5/IV.POS.7 sha2-host guest does NOT use Poseidon (its `core_poseidon` arm will have zero valid steps). It also has limited MRET activity, so `pre_mret`/`post_mret` may be small but non-empty.
- Hardcoding only the zones present in this guest would require code changes for every new guest. Defining all 17 upfront makes the code guest-portable.
- Runtime-skip prevents empty zones from being selected (no degenerate sampling).

### D8 — Compressed global context schema verbatim (Pro: explicit)

We adopt your §5 schemas verbatim:
```text
GLOBAL_MEMORY: family, address_region, address_bucket, txn_role, cycle_phase
GLOBAL_LOOKUP: family, lookup_index_bucket, producer_kind, opcode_class
```

**Address region map (REVISED 2026-06-10 to reflect the actual implementation in `a4/standalone/compressed_global_extractor.py::_ADDRESS_REGION_MAP`).**

| Range (lo..hi, half-open) | Label | Source / rationale |
|---|---|---|
| `[0x00000000, 0x00010000)` | `zero_page` | RISC0 zero page; should never see real txns here |
| `[0x00010000, 0xBFFF0000)` | `user` | Bulk user address space (code + data + heap + stack folded together — see §Coarseness note below) |
| `[0xBFFF0000, 0xC0000000)` | `user_bigint` | RISC0 BigInt scratch region (256-bit BigInt operand staging area) |
| `[0xC0000000, 0xFF000000)` | `kernel` | RISC0 kernel handler region (matches `platform.rs` MEPC kernel base) |
| `[0xFFFF0000, 0xFFFF0080)` | `machine_regs` | Machine-mode register file (CSRs) |
| `[0xFFFF0080, 0xFFFF0100)` | `user_regs` | User-mode register file (x0-x31) |
| `[0xFFFF0100, 0xFFFF1000)` | `machine_special` | Machine-mode special registers (MEPC, MTVAL, MCAUSE) |
| `[0xFFFF1000, 0xFFFF2000)` | `ecall_dispatch` | ECALL trampoline dispatch table |
| `[0xFFFF2000, 0x100000000)` | `trap_dispatch_and_beyond` | Trap dispatch + any addresses above |
| else | `invalid` | Includes the gap `[0xFF000000, 0xFFFF0000)`; PC-derived addresses outside known regions |

**Origin of the revision**: the original D8 (above this entry, pre-2026-06-10) was a paper sketch written during Phase 4 onboarding before any extractor code existed. It guessed at `image/heap/stack/user` ranges. The current map was refined incrementally during Phase 7 as Composer aligned the extractor with `platform.rs` constants (USER_START, USER_END, MEPC kernel base, MACHINE_REGS_ADDR, USER_REGS_ADDR, etc.) so the extractor would produce valid output on real Hook 3 streams. The doc was never back-updated until Inc 2 review surfaced the drift; this entry now records the truth-of-implementation.

**§Coarseness note (for Pro review — see Q12 in EXPECTED_ARMS.md)**:

The `user` row above swallows ~3 GB of address space (`0x10000` to `0xBFFF0000`). Specifically, addresses in these notable subregions are NOT given distinct labels:

| Subregion | Range | Currently labelled |
|---|---|---|
| User code (image text segment, per `platform.rs` USER_START..USER_END) | `[0x00200000, 0x00400000)` | `user` |
| User data / heap | `[0x10000000, ~)` | `user` |
| User stack | `[0x70000000, 0x80000000)` | `user` |
| HOST_ECALL_ADDR communication buffer | `[0x42000000, 0x42000100)` | `user` |

So the `address_region` field on `GLOBAL_MEMORY` is a **9-valued enum that's coarse for bulk address space and fine for control regions**. The fine-grained address differentiation in the bulk user space comes from the **`address_bucket`** field (log2-sized bucket of the raw address) which is independent. The bandit's `G_new` reward therefore primarily fires on "I touched a new ~64KB-aligned chunk" rather than "I touched a semantically distinct memory region."

**Why this is probably fine**: Pro's §3 of ProG_Report_2 explicitly warned that raw global address coverage is noisy ("this axis is dominated by memory addresses and may have low semantic interest"). The current map's coarseness in user space matches that warning — we kept the region enum small on purpose. We weight `G_new` lowest of the four reward deltas (0.25 coefficient) for the same reason.

**Why Pro may want it refined**: if Pro expects `address_region` to discriminate HOST_ECALL_ADDR (a guest-host communication channel — semantically distinct from regular user memory) or to surface heap/stack pressure separately, we'd add 3-4 more rows to `_ADDRESS_REGION_MAP`. This is a ~1-hour code change + a re-smoke. Decision is Pro's; see Q12.

**Risk if Pro disagrees**: as above, easily revised. The schema field itself (`address_region`) is locked; only the enum population differs.

**Empirical observation from B10**: on a V5 N=20 smoke, `compressed_global_coverage` produced 21 rows, 10 with `address_region`, drawn from only 2 distinct labels (`user`, `zero_page`). So in practice during this smoke we only exercised 2 of the 9 enum values. Larger N or different guests will exercise more.

### D9 — 55/45 floor/adaptive split (Pro range: 50-60% / 40-50%)

You wrote (§7.C): *"50-60% reserved coverage floor [...] 40-50% adaptive"*. We picked **55/45**.

Reasoning:
- IV.POS.5 showed that floor-style allocation (zoned's kind-fairness + 5/90/5 step prior) outperforms 100% adaptive (UCB). The dominant factor was the floor.
- Leaning slightly toward the floor (55 > 50) is consistent with that finding.
- Not going all the way to 60 leaves more budget for TS to demonstrate adaptive value over a pure floor.
- 55 is exactly the middle of your range.

### D10 — 3 cold-start pulls per arm (Pro: silent on TS cold-start)

You specified "guaranteed minimum pull count" for singleton arms (§7.A) but did not give a number for the general TS cold-start.

We picked **3 pulls per arm** before TS takes over. Reasoning:
- Matches the old `_N_TARGET = 3` convention in `arm_universe.py`, providing continuity.
- Beta(1,1) updated by 3 pulls has posterior parameter sum of 5, which is enough for meaningful variance estimation.
- With ~50 (kind × semantic_zone) arms expected for sha2-host and N=6000: cold-start cost = 50 × 3 = 150 mutations = 2.5% of budget. Cheap.
- Alternative 1 pull: too aggressive — Beta(1,1) updated to (2,1) makes posterior mean = 0.67, which can dominate the next several pulls.
- Alternative 5 pulls: 250 mutations = 4% of budget on pure exploration, also fine but slightly more wasteful.

**Separately** (§7.A): for singleton zones (`step0`, `last_step`), we enforce a higher forced pull count of `max(3, 5) = 5` pulls. This guarantees the IV.POS.5 "smoking gun" scenario (INSTR_TYPE_MOD@step=0) is sampled at least 5 times in cTS_semantic_v2.

### D11 — Continuous 3-parallel POS reservation (Pro: silent)

You did not address POS scheduling. We use the proven IV.POS.5 pattern of continuous 3-parallel reservations with rolling 6-hour blocks.

### D12 — Leave IV.POS.5 diagnostic as historical (Pro: silent on existing reports)

You said to rename strategies in code (§14.2). We rename in code AND add a top-line note to `MAB_DIAGNOSTIC_FOR_CHATGPT_PRO.md` documenting the renaming, but do not rewrite the document.

Reasoning:
- The diagnostic is what you (Pro) reviewed; rewriting it would erase the record of what your analysis was based on.
- IV.POS.7's new report (Phase 9) will use the new names throughout from inception.

### D13 — ECALL cycle itself classified as `pre_ecall` (Pro: silent)

You (§7.A) list `pre_ecall` and `post_ecall` as adjacency zones but do not specify what zone the **ECALL cycle itself** (the cycle with `major == 8`, i.e. ECALL0) belongs to.

Two natural options:
- (A) Add a new zone `ecall` (18 zones total, deviates from your list of 17)
- (B) Place the ECALL cycle in either `pre_ecall` or `post_ecall`

We chose **(B), and specifically `pre_ecall`** (the ECALL cycle goes to `pre_ecall`; `post_ecall` becomes `e+1`).

Reasoning:
- ECALL-related constraints we observed in IV.POS.5 (e.g. `ECallHostReadSetup@inst_ecall.zir:70`, `ControlUserECALL@inst_control.zir:75/77/78`) fire **at the ECALL cycle or its immediate neighbors** — i.e. before the ECALL is fully consumed. Labeling `e → pre_ecall` keeps these constraints inside a boundary zone where the floor-and-cTS policy reaches them.
- This adds zero zones to your list (minimal deviation).
- The alternative `e → post_ecall` would mean post_ecall includes both the ECALL cycle AND `e+1`, blurring the meaning of "post".

**Risk if you disagree**: easy fix — change `e → pre_ecall` to `e → post_ecall` and re-run IV.POS.7 phase 8. Mechanically trivial, ~1 LOC change in `zone_classifier.py`.

### D14 — MRET and halt adjacency LEFT EMPTY for IV.POS.7 (Pro: implied, deferred)

You list 4 MRET/halt-adjacency zones (`pre_mret`, `post_mret`, `pre_halt`, `post_halt`) in §7.A. In our current `InspectionData`, **MRET and halt are not separately tagged** — both fall under `major == 7` (CONTROL0), distinguished only by sub-opcode bits we don't currently expose.

For IV.POS.7 we **leave these 4 zones empty** for sha2-host:
- MRET cycles fall into `core_branch` (major 7) via the major-fallback.
- The last user_cycle (T-1) is captured by `last_step` regardless of what instruction it is.

Reasoning:
- The IV.POS.5 smoking gun was about `INSTR_TYPE_MOD@step=0`, not MRET/halt. So this limitation does NOT compromise the main scientific test of cTS_semantic_v2 against the IV.POS.5 baseline.
- Adding MRET/halt detection requires either (a) extending the host's `A4_INSPECT` output to tag MRET/halt cycles, or (b) inferring them from instruction-word patterns. Both are feasible but out-of-scope for the current phase plan.
- Consistent with D7: the 4 zones are DEFINED (in `semantic_zones.py`) and the arm universe will runtime-skip them. When future work populates them, no schema or scheduler change is needed.

**Risk if you disagree**: we add a post-Pro-R2 task to extend `A4_INSPECT` and re-classify. The bandit code does not need to change.

### D15 — BIGINT0 (major=12) cycles → `core_other` (Pro: silent)

You listed 17 zones (§7.A) including `core_sha`, `core_poseidon`, but not `core_bigint` or `core_keccak`. RISC Zero's circuit has a separate BIGINT0 major (12) per `a4/core/inspection_data.py::summary` lines 224-228.

We map `major == 12 → core_other`. Reasoning:
- sha2-host (our only Phase 8 guest) does not invoke BIGINT operations, so `core_other` is rarely populated in practice — no information is lost.
- When we add a guest that USES BigInt (post-Pro-R2, per D3), we may add `core_bigint` as a new zone. Until then it's premature.
- Same principle would apply to Keccak: zone could be added when a Keccak-using guest is added.

### D16 — `txn_role`/`cycle_phase` in `GlobalMemoryCtx` derived from MUTATION CONTEXT, not from per-failure metadata (Pro: silent)

Your §5 schema for `GLOBAL_MEMORY` lists `txn_role` and `cycle_phase` as compressed-context fields, but Hook 3's raw output exposes only per-family residues + per-family broken addresses/indices. It does NOT label individual failures with txn_role (read/write/ifetch/...) or cycle_phase (normal/ecall/mret/...). Two interpretations of §5 are possible:

(a) **Per-failure derivation**: each broken-address entry would need a metadata tag from a richer Hook (Hook 3 extension or new Hook 4). Out-of-scope for IV.POS.7.

(b) **Mutation-context derivation**: use the MUTATION's own context (its kind, target step's zone, target cycle's major) to populate these fields for every broken address in this run.

We chose **(b)**, with explicit mappings:

```
txn_role(mutation_kind):
    INSTR_WORD_MOD*, INSTR_TYPE_MOD          → ifetch
    LOAD_VAL_MOD, MEM_VAL_MOD                → read
    STORE_OUT_MOD                            → write
    PRE_EXEC_REG_MOD, COMP_OUT_MOD           → register
    (unknown)                                → read

cycle_phase(zone):
    step0, last_step                         → boundary
    pre_ecall, post_ecall                    → ecall
    pre_mret, post_mret                      → mret
    pre_halt, post_halt                      → halt
    all core_*                               → normal
```

Reasoning:
- Hook 3 cannot be extended without C++ changes; (a) is blocked on infra work not in scope.
- The compressed context's purpose is to provide a **stable semantic identifier** for novelty signals. The mutation context provides a deterministic, hashable label that compresses raw addresses correctly: two `INSTR_TYPE_MOD@step=0` mutations targeting different user-region addresses still collapse to the same `(memory, user, bucket_X, ifetch, boundary)` context once their addresses share a log2 bucket.
- This makes the `G_new` reward fire for **new (kind, zone, region, bucket) combinations**, which is roughly what Pro's §5 example is meant to capture.
- Risk: if your intended semantics was strictly per-failure (interpretation a), then `cycle_phase` will report the phase of the MUTATION, not the phase of the cycle where the residue mathematically lives. For trace-global properties like memory consistency, these often differ (the residue summarizes the whole trace). We accept this approximation; results will show whether it discriminates usefully.

If you (Pro) want per-failure metadata, the next-round task is: extend the Hook 3 emitter to attach `(failing_cycle, failing_txn_idx)` to each broken_addr, then re-derive cycle_phase from that.

### D17 — `address_bucket` = log2-range bucket (Pro range: "page or log2-range")

§5 says: *"address_bucket = page or log2-range bucket"*. We picked **log2-range**.

Reasoning:
- Page-based (`addr >> 12`) would yield up to 1M buckets, far too many for novelty tracking.
- log2-based yields ≤32 buckets, comfortably small.
- Pages cluster adjacent addresses (e.g. 0x80001000 and 0x80002000 go to different pages); log2 clusters by magnitude (these collapse to one bucket).
- Pro's intent is to prevent the bandit from optimizing "different memory byte touched". Log2 is the strictly stronger compression.

### D18 — `lookup_index_bucket` = log2-range (Pro: silent on bucket scheme)

§5 lists the field but does not specify a bucket scheme. We picked the same log2 scheme as D17 for consistency.

Reasoning:
- u8 indices live in [0, 255] → 8 buckets max.
- u16 indices live in [0, 65535] → 16 buckets max.
- cycle indices live in [0, trace_length] → ~12-13 buckets for N=6000 traces.
- Uniform compression scheme across both memory and lookup contexts makes downstream analysis simpler.

### D19 — Compressed-global per-run safety cap = 64 (Pro: silent)

Pro did not address caps. The old `derive_global_contexts` had a cap of 120 (commented as 4× the natural Hook 3 cap of 30 per family). We picked **64** for the compressed version.

Reasoning:
- Compression collapses many raw addresses to few contexts. Natural cardinality per run is ~10-20.
- 64 = 3-4× natural cap, generous enough that defensive truncation should never fire in practice.
- Truncation is deterministic (sorted by ctx_key) so any edge-case truncation is reproducible.

---

### D20 — Constraint-family extraction via `@…\.zir` regex

You specified families by example (`inst_mem, inst_mul, inst_div, inst_control, mem, u32, one_hot`) but did not give a parse grammar. Composer (Phase 4) inspected `ConstraintFailure.short_loc()` patterns 1–2 in `a4/core/constraint_parser.py`, which always emit `Name@file.zir:line`, and chose `re.compile(r"@([^@]+?)\.zir")` as primary parse + name-prefix fallback. Opus's adversarial tests (10 cases including double `@`, double `.zir`, multi-underscore `inst_ecall`, Unicode, empty filename) confirm graceful degradation: empty filename `X@.zir:1` falls back to prefix `"X"` (not empty string), nested `@` picks the segment containing `.zir`. Risk if Pro wanted a different rule: one-line edit to `extract_constraint_family()`.

### D21 — `repeat` = campaign-level retread count (Pro §8 literal)

Pro §8 wording is "number of already-seen local contexts hit again". This is campaign-level (across the run's history), not within-run (within this mutation's failures). Composer's interpretation (set semantics; tuples that were already in `seen_local_v2` before this run) matches Pro literally; my Phase 4 doc had listed within-run cascade (`r_rep = n_fail - d_loc`) as option (a) "safest default" — that interpretation is SUPERSEDED by Pro's clearer §8 text.

### D22 — SET semantics for `l_new` within a single run

Pro §6.1 says "New local semantic context: `(constraint_loc, major, minor)`" — context is a key, not a count. Multiset would let one cascade-heavy mutation (e.g., INSTR_TYPE_MOD with 30 MemLoadInput firings) earn 30× the reward of a single new context, which is exactly the over-counting Pro §6 wanted to avoid by replacing `Q_loc × …`.

### D23 — `no_qloc_reward = min(1.0, Q_rep * Q_glob * S)` for `mode=normal`

Pro §12 names the counterfactual but did not give a closed form. Composer derives it from the legacy `compute_reward` diagnostics dict (reading existing `S`, `Q_rep`, `Q_glob`, `mode` fields without modifying `coverage_state.py`):

```text
mode == "crash"    → 0.0
mode == "accepted" → 1.0
otherwise          → min(1.0, Q_rep * Q_glob * S)   # i.e. force Q_loc=1.0 in r = min(1, Q*S)
```

This is the natural anti-`Q_loc` ablation Pro §12 wants. If Pro intended `Q_rep` or `Q_glob` to also be neutralized, that's a separate counterfactual (would be `s_only_reward` or similar) and we'd add it as a new column.

### D24 — Default `txn_role = "read"` for unmapped kinds

`txn_role_for_kind` maps each `mutation_kind` to one of `{read, write, ifetch, register, prev_word, prev_cycle}`. Most current kinds have a clear mapping (INSTR_TYPE_MOD → ifetch; STORE_OUT_MOD → write; etc.); for any unmapped or future kind, we return `"read"` as a defensive default. Reasoning: "read" is the most common role in raw memory operations, so it minimizes misleading-zone risk if a future kind is added without updating the map. Alternative defaults considered: `"ifetch"` (would over-attribute to instruction fetches), raising (would crash valid runs). This is an APPROXIMATION, not a derivation from cycle data — we have no per-failure transaction metadata from Hook 3 (see D16). If Pro thinks any current kind is mismapped, point us to the correct role and we will fix.

### D25 — Geometric residue concern in compressed global ctx (FLAGGED)

You warned in §6 against over-counting "different memory byte touched". Our adopted §5 schema includes `address_region` (7 bins) and `address_bucket` (32 log2 bins). The compression from raw 2^32 addresses → 224 keys per `(txn_role, cycle_phase)` is a 19-orders-of-magnitude reduction, but it still encodes a coarse geometric signal: two failures in different log2 buckets within the same region produce DIFFERENT compressed keys, contributing 2 to `g_new` instead of 1.

Defensible interpretation: we followed Pro §5 literally — Pro DID specify `address_bucket` as a field. Concern worth flagging: if Pro intended bucket as a coarse "is this a stack vs heap" signal only, then 32 buckets per region may still let the bandit reward "memory scanning" mutations more than Pro intended. Two possible relaxations Pro might prefer:
- (R1) Drop `address_bucket` entirely; use region-only (collapses to 7 keys × txn_role × cycle_phase).
- (R2) Coarser bucketing (e.g. log4-range = 16 buckets, or page-level = 1024-byte pages = 22 buckets max within a 4MB region).

We are sticking with Pro §5 literal until Pro Round 2; see "Open question for Pro #G1" below.

### D26 — Silent skip + future-log for unknown Hook 3 families

`extract_compressed_global_contexts` returns `[]` for any `family` not in `{memory, lookup}` (the only two currently emitted by Hook 3 per `risc0/circuit/rv32im-cuda/ffi.cpp:hook3_compute_family_residues`). Composer's review (Opus) flagged: in case Hook 3 evolves to emit `bytes`/`u8`/`u16`/`cycle` family details, silent skip would lose that signal. Phase 7 hardening will add:

```python
import logging
log = logging.getLogger(__name__)
# ... inside loop, before `continue` on unknown family:
log.warning("compressed_global_extractor: unknown Hook 3 family %r, skipping", fam)
```

Not a code change in Phase 3 / 4 (cost: 1 line in Phase 7). Documented here so Pro knows the intended handling.

### D27 — Retro-clarification of Phase 2 "major-map bug"

The Phase 2 retrospective described `MAJOR_TO_CORE_ZONE` as having "wrong mappings for majors 8-12" and a "naming bug". More precisely:

RISC Zero uses TWO different `major` schemes that the original Phase 1 map confused:

1. **`insn_decode.DecodedInsn.major = kind // 8`** — RV32IM instruction-kind major (8 values, 0–7). E.g., `major=7` is the `{Eany, Mret}` enum slot.
2. **`A4CycleInfo.major`** — circuit execution-phase enum (13 values, 0–12) per `a4/core/inspection_data.py:224-228`: `0–2=MISC0/1/2`, `3=MUL0`, `4=DIV0`, `5=MEM0` (load), `6=MEM1` (store), `7=CONTROL0`, `8=ECALL0`, `9=POSEIDON0`, `10=POSEIDON1`, `11=SHA0`, `12=BIGINT0`.

For majors **0–6** both schemes agree (RV32IM instruction cycles); for **7+** they diverge (control / ECALL / accelerator cycles). `zone_classifier.py` reads `cycle.major` (scheme 2) via `InspectionData.cycles[step]`, so `MAJOR_TO_CORE_ZONE` MUST follow scheme 2.

The original Phase 1 map had `8 → core_sha` and `9 → core_poseidon` — this matched neither scheme. Composer was right to question the framing: it was a confused mental model (built by mapping Pro's `core_sha`/`core_poseidon` zone names to consecutive integers in Pro's listing order), not a typo. The Phase 2 "fix" was to commit to `cycle.major`. Documented here so the reframing is on record.

---

## Open questions for Pro Round 2

(Items we want Pro's explicit verdict on, beyond the D-decisions above.)

### G1 — Is `address_bucket` (log2-range, 32 bins per region) too geometric?

See D25 above for context. Concretely: do you want us to (a) keep §5 verbatim (status quo), (b) drop `address_bucket` (region-only), or (c) use a coarser bucketing? IV.POS.7 will run with (a). Open to switching for a follow-up if you flag this.

### G2 — Phase 7 should add a "guest-trace mutation-semantic verification" step — **RESOLVED INTERNALLY 2026-06-08**

~~Phase 7 currently runs a 30-mutation smoke test that checks rows exist in v2 tables. Suggested addition: take ONE known guest trace, apply ONE controlled mutation (e.g. INSTR_TYPE_MOD at step 0 forcing kind 0→26), then re-inspect the trace and ASSERT the cycle's `kind` actually changed AND `MemLoadInput@inst_mem.zir:8` actually fired.~~

**Status (2026-06-08)**: user signed off on adding this as a required exit criterion of Phase 7. See `phases/PHASE_7_SMOKE_TESTS.md` §7c. Method: stratified random sample of 3 mutations per kind from V5's POS smoke DB, re-execute and diff guest trace before/after, assert kind-specific mutation property. All 24 samples must PASS for Phase 7 exit.

We will reference the outcome in the Pro R2 report ("we added this step internally; here are the results") rather than ask Pro to decide. Not flagging as an open question anymore.

### G3 — `_ADDRESS_REGION_MAP` accuracy on real `sha2-host`

Map currently follows conventional RISC Zero layout (image at `[0x00000000, 0x00400000)`, kernel at `[0xC0000000, 0xFFFFFFFF]`, etc.). NOT yet verified against the real `sha2-host` binary's linker layout or against PC ranges in IV.POS.5 inspection traces. Phase 7 task: run extractor on IV.POS.5 Hook 3 outputs, check that no addresses land in `"unknown"`; if they do, extend the map.

### G4 — `txn_role_for_kind` source-of-truth verification

Mapping derived from reading each mutation kind's implementation. Phase 7 task: for each existing kind, run a single mutation, capture Hook 3 raw output, and check that the addresses/indices touched are consistent with the predicted role (e.g., STORE_OUT_MOD mutations should produce `write` transactions, not `read`).

### G6 — Two Phase 6 follow-up questions (low priority)

**G6a — value_class heuristic vs generator-source provenance**: Our XOR-bit-count classifier (D34) tags ANY value pair with low-bit XOR as `bit_pattern`, including incidental low-XOR pairs from non-bit-flip generators (e.g., 100→50 has 4-bit XOR → tagged `bit_pattern` even though it came from a random/boundary generator). A more semantic alternative: derive `value_class` from the source value-generator (`BitFlipValueGenerator → bit_pattern`, `BoundaryValueGenerator → small`, etc.). This would require threading the generator-strategy label through the mutation config. For Phase 9 stratification by `value_class`, either is workable; Pro's preference would be useful before any refactor.

**G6b — `bandit_decisions` gating under explicit `--telemetry-level=standard`**: Currently (D38), explicit `--telemetry-level=standard` with a v2 selector silently disables `bandit_decisions` and `arm_state_snapshot` logging. Composer's intent was "one knob for all v2 tables". Alternative: bandit logging IS the v2 selector's primary telemetry (not optional), so should always log regardless of telemetry level for v2 paths. Default behavior (`full`) is unaffected; only matters for explicit downgrade. Pro's verdict?

### G5 — Variant 2 (`kindUCB_zoned_v1`) is NOT an exact IV.POS.5 baseline

IV.POS.5's "ucb_kindbucket_b16" used a **two-level discounted UCB** (kind × bucket, with `γ=0.9965`). Our Variant 2 is **kind-only undiscounted UCB1** + the new `ZonedStepSelector` for step picking. Reason: for ablation cleanliness V2↔V3 must share the UCB algorithm; replicating IV.POS.5 exactly would require the bucket axis (no longer present in the cloud1 arm space).

Question for Pro: do you want a literal IV.POS.5 rerun as a separate Variant 1.5 (e.g. `ucb_kindbucket_b16_replay`), or is the Variant 2 "kind-only undiscounted UCB1 + zoned step + legacy reward" baseline sufficient to anchor the reward ablation? IV.POS.7 will run with the latter; we can add a literal replay variant in a follow-up campaign if Pro disagrees.

---

### D28 — Floor priority order (cold → singleton → epoch → adaptive)

Pro §7.C names the three constraint types but doesn't pin order. Our short-circuit ordering ensures:
- **Cold-start first** (3 pulls/arm): no posterior is sampled until each arm has minimal data. Prevents Beta(1,1) prior from over-influencing early TS picks.
- **Singleton next** (5 forced pulls): protects the IV.POS.5 "smoking gun" (`INSTR_TYPE_MOD@step0`) from being starved by a high-variance posterior on a single observation.
- **Epoch floor third** (55% of epoch budget spread over all arms): enforces the "minimum coverage" constraint while leaving 45% for the adaptive layer to chase high-mean arms.
- **Adaptive TS last**: only fires when all floors are satisfied; uses Beta posterior to pick the arm with highest sampled θ.

Reversal cost: re-order the four `if` branches in `ConstrainedTSScheduler.select()`. Tested by `test_singleton_beats_epoch_floor`, `test_epoch_floor_beats_adaptive`.

### D29 — Cold-start round-robin (deterministic, not random)

`_pick_round_robin(sorted(under_pulled_arms))` cycles through under-pulled arms by index. Two arms tied at `pulls=0` will alternate strictly, not be picked randomly. Reason: deterministic fairness — no arm can be unlucky enough to "always" lose a coin flip while others drain. Verified by `test_cold_round_robin_not_random` (same picks across different seeds during the cold-start phase).

### D30 — Cold/singleton/floor pulls all count toward `epoch_pulls`

A single counter; all `update()` calls increment `epoch_pulls[arm]`. Alternative ("only count explicit floor-mode pulls") would double-allocate: a singleton with 5 forced pulls in the first 5 mutations of an epoch would then ALSO need its 0.55·100/n_arms ≈ 11 floor pulls, totaling 16+ pulls on that arm per epoch — way over budget.

### D31 — Variant 3 reward signal = full `reward_v2`, NOT `no_qloc_reward` counterfactual

The naming `_v2_noQ` is **shorthand** for "v2 reward, which structurally has no Q_loc". Pro's intent (§8.1) is to ablate the REWARD FUNCTION while holding the SELECTION algorithm constant against Variant 2. Concretely:
- V2: same UCB + LEGACY reward = `compute_reward(...)` (has Q_loc penalty)
- V3: same UCB + V2 reward = `compute_reward_v2(...)` (no Q_loc by construction)

The `no_qloc_reward` counterfactual stored in `reward_counterfactuals` is for **offline analysis** (Phase 9 cross-strategy comparison): "what would Variant 2's bandit have ranked things if it had used the no-Q_loc version of the LEGACY reward?". That's a different question from "what reward does Variant 3's bandit optimize?".

If Pro intended V3 to use the counterfactual `no_qloc_reward` LIVE, we'd swap the line in `_run_v2_bandit_mutation` from `self.v2_scheduler.update(kind, reward_v2)` to `self.v2_scheduler.update(kind, no_qloc_reward)`. One-line change.

### D32 — TS update uses Bernoulli `compute_bandit_success`, not scalar reward

`KindLevelTSScheduler` and `ConstrainedTSScheduler` both call `update(arm, success: int)`. The Beta posterior conjugates to Bernoulli observations; passing scalar continuous reward (range `[-0.55, +1.70]` for v2) would violate the conjugacy and require switching to Beta-binomial or Normal-Normal. Pro §7.D and §8 `compute_bandit_success` definition pin this choice. Scalar v2 reward is STILL computed and recorded for `bandit_decisions.extra_json` / Phase 9 analysis.

### D33 — KindLevelUCBScheduler is undiscounted UCB1 (not legacy DiscountedUCB)

Two reasons:
1. **Ablation cleanliness**: V2 and V3 must share the same UCB algorithm to make the V2↔V3 reward ablation interpretable. Both use undiscounted UCB1 with `c_explore=0.25` (taken from `CalibratedParams.c_explore`).
2. **Pro §7.D direction**: Pro recommends moving toward TS for adaptivity; legacy DiscountedUCB stays in `bandit.py` for legacy strategies but is not extended.

V2 is therefore NOT an exact IV.POS.5 rerun (see G5 above). It's a kind-only undiscounted-UCB1 baseline. The original IV.POS.5 `ucb_kindbucket_b16` data is still available in `a4/runs/iv_pos_5/` for anchor comparisons.

### D34 — `value_class` taxonomy via XOR-bit-count heuristic

Pro §6.1 names the four classes but gives no algorithm. Composer's heuristic:

```python
if mut == 0:                                      return "zero"
xor = orig ^ mut
if xor != 0 and xor.bit_count() <= 4:             return "bit_pattern"
if mut < 256 or abs_wrap(mut − orig) < 256:       return "small"
return "large"
```

**Discovered design property** (Opus adversarial tests): the heuristic tags MANY incidental low-XOR mutations as `bit_pattern`, even when the mutation didn't come from `BitFlipValueGenerator`. Examples: `100→50` (XOR=0x56, 4 bits → bit_pattern); `200→100` (XOR=0xAC, 4 bits → bit_pattern). This is structurally correct (XOR is low-bit by definition), but may not match Pro's semantic intent that `bit_pattern` mean "produced by a bit-flipping value generator". See G6a for the alternative we could implement (provenance-based).

Risk if Pro disagrees: one function change in `classify_value_class()`. Phase 9 stratification by `value_class` will need to be re-interpreted accordingly.

### D35 — `--telemetry-level` defaults: `full` for v2, `standard` for legacy

`default_telemetry_level(selector_strategy, V2_BANDIT_STRATEGIES)` returns `"full"` if the selector is one of the four v2 variants, else `"standard"`. Explicit CLI `--telemetry-level=...` always wins.

Reasoning: Pro §6.3 says IV.POS.7 needs the v2 tables populated for Phase 9 ablation. Forcing users to remember `--telemetry-level=full` on every IV.POS.7 run would be a footgun (someone forgets, campaign runs without counterfactuals, can't be replayed). Default-by-selector eliminates that.

Side effect: legacy `zoned`/`bandit` strategies default to `standard` (matches pre-cloud1 behavior). Users wanting full v2 tables on legacy paths must pass `--telemetry-level=full` explicitly.

### D36 — `hook3_raw.raw_json` schema

`{"family_residues": [...], "family_details": [...]}` JSON object. Keys are OMITTED when empty (e.g., a mutation with no `family_details` produces `{"family_residues": [...]}` only). `compressed_ctx_json` is a JSON list of compressed-context dicts (D17 / D18 schemas).

Reasoning: lossless preservation of both Hook 3 payloads; separates raw from compressed for offline analysis. Matches Phase 1 `record_hook3_raw` round-trip tests.

### D37 — `MEM_VAL_MOD` `byte_lane` / `bit_mask` from XOR

The fuzzer config does not currently carry `byte_lane` for `MEM_VAL_MOD` mutations (it would need to come from the mutation construction code). Composer derives both fields from `original_value XOR mutated_value`:

```python
xor = (original_value ^ mutated_value) & 0xFFFFFFFF
bit_mask = xor if xor else None
byte_lane = min(31, max(0, xor.bit_length() − 1)) if xor else 0
```

This gives the **index of the highest differing bit** (0–31). Limitation: if the mutation changes BOTH a low byte and a high byte (e.g., XOR=0x80000001 → bit_length=32 → byte_lane=31), `byte_lane` records only the high one. This is an approximation; the full XOR mask in `bit_mask` preserves the actionable signal for offline analysis.

### D38 — `bandit_decisions` / `arm_state_snapshot` gated to `full`

Composer's Phase 6 consolidation moved both bandit-logging calls in the v2 path under `if self.telemetry_level == "full":`. Tradeoff:
- **Pro**: single knob for all v2 telemetry; mental model simplicity.
- **Con**: explicit `--telemetry-level=standard` with a v2 selector silently drops bandit logs.

Default for v2 is `full`, so production is unaffected. Only matters if user explicitly downgrades to `standard`. See G6b for Pro's preference; alternative (always log on v2 paths) is a 5-line move outside the `full` guard.

### D39 — Phase 7 hybrid structure (3 sub-phases)

The original Phase 7 plan (`PHASE_7_SMOKE_TESTS.md@phase-5-handoff`) ran 5 variants × N=200 entirely on WSL. Two problems were identified during Phase 6 review (user discussion 2026-06-08):

1. **Budget measurements that depend on HOST hardware** (DB size scaling, V5/V1 wall-time ratio against Pro's 1.3× ceiling) are unreliable when measured on WSL but extrapolated to POS — POS is bare metal and runs at very different per-mutation cost.
2. **Mutation-semantic verification** (G2) needed a concrete home; checking that rows exist (plumbing) is not the same as checking that we mutated what we think (semantics).

Resolved with a **three-sub-phase structure** (`PHASE_7_SMOKE_TESTS.md` §7a/7b/7c):

| Sub-phase | Where | What | Why |
|---|---|---|---|
| 7a | WSL | 5 variants × N=20, full telemetry | Catch crashes / NaN / schema bugs cheaply in a tight iterate loop. Hard gates: zero crashes, zero NaN, all v2 tables populated. |
| 7b | POS (`coinbase`) | 5 variants × N=200, full telemetry | Budget-relevant measurements: DB size at N=200 → extrapolate to 6000 ≤ 150 MB; V5/V1 wall-time ≤ 1.3×; zoned-consistency vs legacy code path. |
| 7c | local re-execution from POS DBs | 24 stratified mutation samples (3 per kind), trace-diff before/after | Resolves G2: ground-truth confirmation that each kind mutates the intended semantic property. All 24 must PASS. |

All three required for Phase 7 exit. Sequential: 7a hard gates must pass before paying for 7b POS time; 7c runs after 7b on Variant-5 DB (only V5 exercises all 8 kinds via `cTS_semantic_v2`).

Risk if Pro disagrees: this is a process decision, not a code change; can be re-scoped freely between R2 review and Phase 8 launch.

---

## Phase 7d additions (Architecture Audit decisions)

These decisions emerged during Phase 7d setup and Inc 0 / Inc 1 joint review. They define the audit-suite gating Phase 8 and any zone-classifier / arm-universe changes that result from the audit findings. Pro should review these alongside the original 1-39 decisions.

### D40 — Multi-cycle step disambiguation (drop-from-universe, option b)

**Problem (discovered Phase 7c rev2 → Inc 0 P1 verification):** Some `(kind, step)` pairs are ambiguous because the step contains multiple cycles that match the kind's major filter. Example: an INSTR_TYPE_MOD `(filter major≤6)` at a pre_ecall step that contains BOTH a major=8 ECALL cycle AND an adjacent major=0 ALU cycle. The Python-side target builder and the Rust hook each picked a "first matching cycle" but used independent heuristics, sometimes disagreeing. Result: the hook landed on a different cycle than Python expected; the strict verifier (P1) correctly flagged this as `cycle_shift_at_step` on 1 of 24 INSTR_TYPE_MOD samples in Inc 0.

**Decision:** Option (b) — `SemanticArmUniverse._step_has_real_target` additionally requires `_matching_cycles_at_step(kind, step) == 1`. Steps with >1 matching cycle for the kind's filter are dropped from that kind's arm.

**Why option (b) over option (a):** Option (a) (add explicit `cycle_idx` field to mutation config + Rust hook) is architecturally cleaner but requires Rust changes and broader plumbing — out of scope for Phase 7d. Option (b) is safe, conservative, and fits in Python-only changes.

**Cost (measured on baseline, Inc 0 + Inc 1 audits):**
- Drops 4 arms total: `INSTR_WORD_MOD_FULL|last_step`, `INSTR_WORD_MOD_FULL|pre_ecall`, `INSTR_WORD_MOD_SUR|last_step`, `INSTR_WORD_MOD_SUR|pre_ecall`.
- For 6 of 7 RV32IM kind groups the step-drop rate is 0.0%; INSTR_WORD_MOD_* drops 0.8% of matching steps (concentrated at ECALL boundaries).
- MEM_VAL_MOD is EXEMPT from the multi-cycle filter — it targets `(step, txn_idx)` directly, not `(step, cycle)`, so the Rust hook unambiguously identifies the target regardless of cycle count.

**See also: D52** for the proper architectural fix (deferred to Phase 9).

**Pro review hook:** if Pro wants to recover the 4 dropped arms in Phase 9+, D52 is the path.

### D41 — Phase 7d split into 7d.1 (semantics) and 7d.2 (variants), sequential gating

Phase 7d's 17 audits are split into two sub-phases that must run in order:

- **7d.1** = A1-A5 + E1, E3 (semantics & arm integrity). Question: "is the arm space we present to the bandit a true reflection of trace semantics?"
- **7d.2** = B1-B12 + E2, E4, E5 (variant correctness & isolation + user-readable evidence). Question: "does each variant execute exactly what its strategy claims, and can we prove every arm pull semantically?"

7d.1 must be fully green before 7d.2 starts. The two sub-phases are further broken into 6 incremental work units (`composer/PHASE_7D_INCREMENTS.md`) with per-increment gates and report-back checkpoints. See `phases/PHASE_7D_ARCHITECTURE_AUDIT.md` for per-audit specs.

### D42 — Non-deterministic mem-txn allow-list (A1 finding → MEM_VAL_MOD targeting exclusion)

A1 found 188 specific mem-txn addresses whose `word` field varies across host runs. All cluster at step 170 (4 addresses) and step 3929 (184 addresses). Both are in host-controlled I/O regions:
- `0x000884e6+` (4 addresses) — guest journal/output buffer
- `0x41ffbbe0+` (184 addresses) — HOST_ECALL_ADDR region (the host writes IPC channel data)

These are excluded from MEM_VAL_MOD target collection via `EXPECTED_EXCLUDED_TARGETS.json` consumed by `mem_val_mod.py::_step_has_real_target`. Rationale: if we mutate a txn whose baseline word is non-deterministic, the strict verifier cannot distinguish "mutation took effect" from "host wrote a different value this run." Excluding them protects verifier signal.

### D43 — Multi-guest verification deferred to Phase 10 (post-Phase-8)

Phase 7d only verifies the 48 (kind, zone) arms exercised by `c0c1_differential_guest`. The ~49 arms in `core_sha`, `core_poseidon`, `core_other`, `pre_mret`, `post_mret`, `pre_halt`, `post_halt` zones are documented as UNVERIFIED in `EXPECTED_ARMS.md` and tracked as Phase 10 work. B12 (multi-input robustness) is the cheap-substitute within Phase 7d: re-runs A1-A5 + B1, B4, B9 with `--in1 1 --in4 1` and `--in1 100 --in4 100` to catch arm-presence regressions but does not unlock fundamentally new arms (same guest, only inputs differ).

**Rationale for deferring true second-guest test to Phase 10:** the candidate second guests are (a) risc0 stock SHA example (~1 day; unlocks `core_sha`), or (b) extending arguzz's CircIL to emit MRET/halt-rich code (~1-2 weeks). Either is meaningful only AFTER Phase 8 results justify the investment. See `PHASE_7D_ARCHITECTURE_AUDIT.md §6` for full rationale.

### D44 — E5 per-arm human-readable evidence pack (added as Inc 5 of Phase 7d)

Pro's Phase 7d audit suite originally had 16 mechanical audits. During Inc 1 design we added **E5**: 48 markdown evidence files (one per kept arm) showing, per arm, ≥ 1 mutation with the arm's CLAIM + actual trace + independent re-decode + hook stdout + outcome + ✓/✗ verdict. Purpose: give the user a concrete worked example per arm they can spot-check independently, rather than relying on aggregate pass/fail counts from B1/B4.

E5 reuses B1's verifier and B4's traceability dataframe; no new infrastructure. Estimated 4-6 hr write + ~3 hr run (50 × 48 = 2400 mutations) + 1-2 hr review.

### D45 — Variable-definition convention for audit output

All Phase 7d audit output (JSON + markdown) must define every non-obvious variable either inline or via link to `a4/docs/cloud1/GLOSSARY.md`. Examples: `major` and `minor` must reference the inspection_data.py:194-228 source; `e` in zone definitions must be defined as "the step containing a major=8 ECALL cycle"; `txn.cycle` vs `cycle_idx` vs `user_cycle` must be explicitly distinguished. Composer is required to follow this convention; per-arm evidence files (E5) include a template at the top of each .md.

**Rationale:** user spent significant time during Inc 0/1 reviews trying to decode magic numbers (`major=8`, `txn.cycle = 2×cycle_idx+1`). The GLOSSARY exists; pointing to it costs zero per audit.

### D46 — ECALL 8-vs-7 taxonomy ACCEPTED as semantic (Theme 0)

**Discovery (E1 / DM-1, DM-2, DM-5):** When the RV32IM decoder is applied to the fetch word at ECALL steps (e.g. step 170, step 3929), it returns `major=7, minor=0` (Eany). But the trace `cycle.major` for the same step is `8/0` (ECALL0). This affects 3 of 31 E1 mismatches.

**Disposition:** ACCEPT this as a deliberate circuit-side taxonomy difference, NOT a bug. Explanation:
- The RV32IM **instruction encoding** of an ECALL is the SYSTEM opcode with funct12=0, which `insn_decode.py` correctly classifies as the `Eany` kind (major=7 minor=0).
- The ZK **circuit**, however, gives ECALL its own dedicated `ECALL0` cycle type (major=8) because ECALL setup constraints (jumping to the kernel trap handler) are semantically different from regular branches. The host's preflight code intentionally maps the same instruction encoding to two different circuit major columns depending on context.

**Action:** Exclude major=8 cycles from the strict E1 gate in B1. Document this 8/7 split in GLOSSARY as canonical. Do NOT modify the decoder or the cycle classifier.

### D47 — Formal disposition of 4 D40-dropped arms (Theme 0)

The 4 arms dropped by D40 (`INSTR_WORD_MOD_FULL|last_step`, `INSTR_WORD_MOD_FULL|pre_ecall`, `INSTR_WORD_MOD_SUR|last_step`, `INSTR_WORD_MOD_SUR|pre_ecall`) are formally moved from the "kept" section of `EXPECTED_ARMS.md` to the "Expected-DROPPED" section. Each gets a `dropped_reason: "D40 — multi-cycle step ambiguity"` note. The 🟡 UNCERTAIN flag is replaced with 🔴 DROP_D40.

**Pro review hook:** if D52 (cycle_idx disambiguation) is implemented in Phase 9, these arms move back to the "kept" section.

### D48 — core_branch user/kernel split — **SUPERSEDED by D54** (Theme 1)

**Original proposal (joint review Theme 1):** Split `core_branch` into `core_branch_user` (user-PC major=7 steps) and `core_branch_kernel` (kernel-PC major=7 steps) to disambiguate MRET/Eany kernel control flow from user branches.

**Status: SUPERSEDED by D54.** The HYBRID approach (D54) introduces a single `kernel_other` zone that catches ALL kernel-PC steps regardless of major, including kernel-PC major=7 steps. Under D54, `core_branch` becomes implicitly user-only (the kernel ones get classified as `kernel_other` first by the precedence rule). No separate `core_branch_kernel` arm is needed.

**Why D48 was retained for documentation:** during joint review the user explicitly approved the user/kernel concept for `core_branch`. D54 preserves that concept but generalizes it: instead of splitting every "core_*" zone, ONE new zone catches all kernel cycles.

### D49 — Dynamic arm enumeration clarification (Theme 1)

**User question (joint review):** "if we drop an arm from one guest, does it disappear from the codebase forever?"

**Answer (clarified):** No. `SemanticArmUniverse.build()` runs PER-GUEST at fuzzer startup. The 48 arms for `c0c1_differential_guest @ --in1 5 --in4 10` are computed by intersecting that guest's actual trace with the kind-filter rules. A DIFFERENT guest (or even the same guest with different inputs) re-runs the universe builder and may produce a completely different arm set — including arms that are empty here (like `*|core_sha` if SHA is invoked).

**Implication for Phase 7d:** the arms we audit reflect THIS guest. Phase 10 multi-guest work re-runs the universe builder per guest and audits each separately.

### D50 — `core_div` / `core_shr` split (Theme 2)

**Discovery (E1 + dynamic check):** Major=4 (DIV0) in the ZK circuit covers BOTH:
- Real divides: `DIV`, `DIVU`, `REM`, `REMU` (minor ∈ {4, 5, 6, 7})
- Shift-rights: `SRL`, `SRA`, `SRLI`, `SRAI` (minor ∈ {0, 1, 2, 3})

These are semantically distinct (arithmetic divide vs bit-shift) but happen to share a circuit table due to circuit-optimization concerns. Lumping them under one zone label hides the distinction from the bandit.

**Decision:** Split `core_div` into two zones:
- `core_div` = major=4 with minor ∈ {4, 5, 6, 7} (DIV/DIVU/REM/REMU)
- `core_shr` = major=4 with minor ∈ {0, 1, 2, 3} (SRL/SRA/SRLI/SRAI)

**Cost:** ~30 min Composer for zone classifier change; arm count goes from 8 `*|core_div` arms (one per applicable kind) to 8 `*|core_div` + 8 `*|core_shr` = 16 arms in this zone family. May produce some empty zones if the guest exercises only one side.

**Naming rationale:** User chose `core_div` (drops the "_real" suffix from my proposal) and `core_shr` for the new zone. Cleaner.

### D51 — `pre_ecall` includes the ECALL cycle itself — clarifying note (Theme 3)

**Original spec (D13):** the ECALL cycle (major=8) is classified as `pre_ecall`, NOT as a separate `at_ecall` zone, because the ECALL setup constraints fire AT the ECALL cycle and the bandit should be able to target them under the same arm.

**Theme 3 clarification:** the `INSTR_TYPE_MOD|pre_ecall` arm has 18 steps after D40 (pre_ecall has 32 total; 14 get dropped because they're multi-cycle steps containing both the major=8 ECALL cycle AND an adjacent major≤6 cycle). The remaining 18 are steps where the kind's filter finds a single Decode-state cycle to mutate — typically the setup instruction immediately before ECALL.

**Action:** add a clarifying note to GLOSSARY.md explaining that `pre_ecall` is *not* "the step before ECALL" but "the boundary zone containing AND immediately around the ECALL cycle, after D40 disambiguation."

### D52 — `cycle_idx` disambiguation — DEFERRED to Phase 9 (Theme 3 follow-up)

**The proper architectural fix for D40's multi-cycle problem.** Add an explicit `target_cycle_idx` field to mutation configs; pass it through to the Rust hook; the hook targets that exact cycle_idx instead of using its own first-match heuristic. Recovers the 4 arms dropped by D40 and is required for clean accelerator-targeted kinds (Phase 11).

**Why deferred:** requires Rust hook modifications across ~8 mutation kinds + corresponding Python config schema changes. Estimated ~1-2 days. Phase 7d's mandate is "verify the existing architecture is sound"; expanding scope to add new plumbing dilutes that mandate.

**Trigger for implementation:** any of (a) Phase 8 results show the 4 dropped arms would have been valuable, (b) Phase 11 accelerator kinds are added (they cannot ship without cycle_idx plumbing), (c) Pro R2 explicitly requests it.

### D53 — `post_ecall` redefined as "first user-PC step in window [e+1, e+5]" (Theme 4)

**Discovery (Theme 4 empirical investigation, `audit_output/E6_post_ecall_window_evidence.json`):** I had originally claimed (without evidence) that post_ecall = `e+1` is the "first user instruction after ECALL." Empirical check on all 87 ECALLs in the baseline trace showed this is WRONG in 46% of cases. The actual pattern:

| Offset | Unique PCs | Top PC | % | What it is |
|---|---|---|---|---|
| `e+1` | 6 | 0xc0000158 | 46% | Kernel trap handler (in 46% of cases); user code (in 42%) |
| `e+2` | 6 | 0xc000015c | 46% | Still in kernel handler |
| `e+3` | 7 | 0xc000015c | 46% | Kernel handler — often contains another ECALL (kernel's mret-back) |
| `e+4` | 10 | (mix) | 35% | Mostly user code starts here |
| `e+5` | 10 | (mix) | 35% | User code; increasing PC diversity |

The "post-ECALL transient" is NOT a single step. It's 1-3 kernel-handler steps followed by user-code return.

**Decision:** Under HYBRID (D54), `post_ecall` is redefined as **the first user-PC step `e+k` for the smallest `k ∈ [1, 5]` where the Decode cycle is at user PC**. The intermediate kernel-handler steps fall into `kernel_other` automatically.

**Why not Pro's original "e+1 only" definition:** Pro recommended boundary zones to capture ECALL semantics. Empirically, the user-side semantic effect occurs at the user-code RETURN POINT, which is e+1 in 42% of cases but e+2..e+4 in the remaining 58%. Defining post_ecall as "the first user-PC return" captures this cleanly.

**Pro review hook:** this expands the universe by 0 zones (post_ecall already exists) but tightens its semantic. If Pro disagrees, can revert to "e+1 only" with one line change.

### D54 — HYBRID kernel/user PC split: add ONE `kernel_other` zone (Theme 5)

**Discovery (Theme 5 empirical investigation, `audit_output/E7_kernel_contamination_survey.json`):** Multiple "user-code" zones contain kernel-PC steps:
- `step0`: 1 Decode cycle, at pc=0xc0000004 (kernel boot)
- `core_div`: includes step 3921 (kernel halt cleanup at pc=0xc00000dc)
- `core_branch`: D48's original discovery — kernel MRET at major=7
- `post_ecall`: kernel trap handler at PC range 0xc0000xxx for 1-3 steps (D53)

**Quantitative:** of 3891 total steps with Decode cycles, 375 (9.6%) are at kernel PC (range `0xC0000000..0xC1000000`). The remaining 3516 (90.4%) are at user PC (range `0x00200000..0x00400000`). Kernel is the minority but non-trivial.

**Decision: HYBRID** (over BROAD or NARROW alternatives). Add a single new zone `kernel_other` that catches ALL kernel-PC steps not already classified as `pre_ecall` (the ECALL itself has kernel PC but is semantically a boundary). Existing zones (`core_arithmetic`, `core_div`, `core_branch`, etc.) implicitly become user-only via classifier precedence.

**Why HYBRID over BROAD:**
- BROAD would split every "core_*" zone into `_user` and `_kernel` variants (~13 new arms × 8 kinds). Many kernel zones would be sparse (1-10 steps each) → bandit cold-start cost.
- HYBRID adds ONE new zone collecting all kernel cycles into one fat arm per kind. Cleaner per-arm signal.
- HYBRID is a STRICT COARSENING of BROAD: we can always refine kernel_other into per-major variants in a future phase if Phase 8 shows it's hot. Going from BROAD back to HYBRID is harder.

**Classifier precedence (after D54):**
1. `step0` / `last_step` (singleton) — exclusive
2. `pre_ecall` (contains ECALL cycle — even if kernel PC; D13 unchanged)
3. `post_ecall` (first user-PC step in [e+1, e+5]; D53)
4. **`kernel_other`** (any remaining step where the primary Decode cycle is at kernel PC)
5. `core_*` (existing major-based zones, now implicitly user-only)
6. `pre_mret` / `post_mret` / `pre_halt` / `post_halt` (currently empty; Q8)

**Cost:** ~2 hr Composer for classifier change + A4/A5 re-run on new universe. Expected new arm count: 48 (current) + ~7 (one `kernel_other` arm per kind that has kernel-PC steps with matching majors). The 4 D40-dropped arms remain dropped.

**Why this is the "stronger architecture":** without kernel_other, Phase 8 results for `core_arithmetic` are contaminated by ~3-5% kernel-PC steps. With kernel_other, those are reclassified, and Phase 8 reward signal for `core_arithmetic` cleanly reflects user-code mutations only. Pro can interpret per-zone results without "is this signal from user or kernel?" confusion.

**Pro review hook:** if Pro thinks BROAD (per-major kernel splits) is preferable for IV.POS.7 interpretability, escalate after Phase 8 by splitting `kernel_other` into `kernel_arithmetic`, `kernel_div`, etc. HYBRID's coarsening makes this a future expansion, not a do-over.

### D55 — Theme 6 + Theme 7 dispositions (joint review closes)

**Theme 6 (MEM_VAL_MOD on non-memory majors):** kept as Inc 1.5 investigation work. Composer must produce `audit_output/E3b_mem_val_non_memory_majors.json` characterizing the txn distribution for the 848 `MEM_VAL_MOD|core_arithmetic` steps and 34 `MEM_VAL_MOD|core_mul` steps (txn_type breakdown, addr region breakdown, examples). User and Opus will adjudicate in Inc 1.5 review whether these are real memory consistency txns or scratch-buffer artifacts.

**Theme 7 (ultra-rare arms):** verified empirically. `MEM_VAL_MOD|core_div` step 3921 is a kernel halt-cleanup at pc=0xc00000dc with 3 mem-txns in the register file region (`0xffff00xx`); NOT in D42 allow-list. Under D54 (HYBRID), this step reclassifies into `kernel_other`, so the ultra-rare singleton arm naturally disappears from `core_div`. Status: accepted; will be re-verified by A5 after D54 lands.

---

## Implementation deviations from Pro recommendations

Every implementation decision is either (a) following your explicit spec, (b) picking a value within a range you specified, or (c) a choice on a question you didn't address.

### Cosmetic / name-only deviations (recorded for transparency)

| § | Pro term | Our term | Reason |
|---|---|---|---|
| §12 | `arm_state_log` | `arm_state_snapshot` (SQLite table name) | Better reflects that we snapshot every E mutations, not log every change. Schema and semantics identical. |
| §12 | `hook3_raw_or_semantic` | `hook3_raw` (SQLite table name) | Cleaner identifier. Both raw payload AND compressed context are stored as JSON columns (`raw_json`, `compressed_ctx_json`) inside this table. |

### Structural-property observations (no deviation; documented for Pro)

| Observation | Implication |
|---|---|
| `(INSTR_TYPE_MOD, pre_ecall)` is **structurally empty** for every guest | INSTR_TYPE_MOD only applies to majors 0-6 (per `inspection_data.py:194-197`); ECALL cycles have major=8. The new arm space correctly omits this arm via D7 (runtime-skip empty). For `INSTR_WORD_MOD` (which DOES apply to major=8), the arm IS populated. |
| Empty arms are SKIPPED, not represented as 0-step entries | The bandit's denominator is `num_arms` of populated arms only; no division-by-zero risk. |

If after reviewing IV.POS.7 results you wish to change any of D4, D5, D6, D7, D9, D10, D11, D12, D13, D14, D15, D16, D18, D19, D23, D24, D26, D27, D29, D30, D33, D34, D36, D37, D38, or D39 (the U-type decisions where you were silent) — or D17 / D25 / D28 / D31 / D35 (P-range / P-with-concern) — please flag them in your Round 2 response and we will revisit in a follow-up campaign. **Top of the agenda: G1 (geometric residue concern with `address_bucket`), G5 (V2 baseline interpretation), G6a/b (value_class heuristic, bandit_decisions gating).**

---

## What IV.POS.7 will deliver to Pro Round 2

1. `a4/runs/iv_pos_7/MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` (~50-100KB)
   - All metrics from your §10
   - All 5 success criteria applied
   - Per-variant analysis
   - Reward counterfactuals across all strategies
   - Honest conclusion (whether v2 candidate beats zoned)
2. `a4/runs/iv_pos_7/MAB_ARCHITECTURE_NOTEBOOK_R2.ipynb` (reproducible)
3. 50 SQLite DBs (5 variants × 10 seeds)
4. This decisions document, updated with any corrections discovered during implementation.
