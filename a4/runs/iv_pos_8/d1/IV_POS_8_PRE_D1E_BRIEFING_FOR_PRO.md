# IV.POS.8 — Pre-D1.E Briefing for Pro

**Audience:** ChatGPT Pro (architectural-design review).
**Purpose:** Chronological summary of the IV.POS.8 work that has fed into the D1.E reward-rewire spec. This is the "what we built, what we found, what we decided, why" briefing — written so Pro can validate the reasoning chain **before** D1.E spec-locks and the V5 + decay re-run dispatches on POS.
**This is NOT the final D1 report.** That deliverable (`IV_POS_8_D1_REPORT_FOR_PRO.md`) folds D1.A + D1.B + D1.C + D1.E together at Stage 4 (after D1.E completes). This briefing exists earlier in the pipeline so Pro can confirm or correct the architectural framing while the choices are still cheap to revise.
**Branch:** `cloud2`
**Author:** Opus
**Status:** **DRAFT v0.3 — covers completed work through 2026-06-18.** D1.C extension landed (§4); D2.B is now DONE (§5 updated); D1.E spec drafted (§6 updated); briefing now reflects the post-1.5e world where `PRE_EXEC_REG_MOD` strategy is RNG-picked, breaking strict byte-identity of the D1.A V5 archive for fresh runs.

---

## 0. TL;DR — Where we are right now

We have completed **five load-bearing deliverables** since IV.POS.8 began:

| # | Deliverable | Commit | Status | What it produced |
|---|---|---|---|---|
| 1 | **D1.A** — V5 decaying floor variants (analysis on existing scheduler + binary reward) | `1db0e88` then `4fce664` | **FROZEN** with 6 Findings (A–F) and 8 Limitations | Diagnosis: floor-decay alone is insufficient; reward signal saturation is the binding constraint |
| 2 | **D2.A** — 5-tuple ArmKey refactor + `mutations.outcome` column + applied accounting | `b844e8e` then `7b66fb9` | **DONE** | Scheduler shape that D1.E, D2.B, D2.C, D2.D all build on. V5 byte-identity preserved **for the ArmKey refactor itself** (D2.A exit criterion); see post-1.5e caveat in §2.4 — the D1.A V5 archive remains a paired baseline for D2.A regression purposes, but is **not** a fresh-run substitute for D1.E V5-static post-`78d036c` |
| 3 | **D1.B** — CGC coarsening variants (3 alternates evaluated; corrected baseline) | `71dae77` | **DONE** | Recommendation: keep corrected `production_log2_corrected` as L0; coarsenings saturate EARLIER than local; L1 enrichment via D1.C is the primary remaining lever |
| 4 | **D1.C** — bug-proximity metric stack (Tier-1 per-mutation signals + Tier-2 per-campaign metrics) | `3a8487c` | **DONE** | 3 L1 OR-channel candidates pass D1.E pre-screening; singleton-failure rate is the only Tier-2 decay discriminator (p=2.6e-06); `f_new` L1 channel dead on V5 |
| 5 | **D2.B** — eight new pure-A4 mutation kinds + attestation hook + `PRE_EXEC_REG_MOD` retrofix (NFP-6 Batch 1.5e) + dead-arm cleanup | `78d036c` → `f81523c` → `4e5150a` → `2e1d97b` → `e2c2256` | **DONE** | The narrow D1.E sync dependency (NFP-6 `PRE_EXEC_REG_MOD` RNG retrofix) landed at `78d036c`. D2.B's other batches (new kinds, attestation hook, PS-1 dead-arm cleanup) feed D2 variants (V6, Hybrid-cTS), NOT D1.E. **D1.E sync gate is satisfied.** |

D1.E (the V5 + decay re-run under enriched reward path) is the **integration point** for D1.A + D1.B + D1.C + D2.A + the specific `PRE_EXEC_REG_MOD` retrofix portion of D2.B. The other D2.B work happens in parallel and does NOT enter D1.E.

**This briefing chronologically narrates each completed deliverable so Pro can see the decision provenance.** Pro disclosure asks are surfaced inline (look for **❓ Pro ask**). The full Notes-for-Pro index (NFP-1 through NFP-10) is at `a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md` for deeper reading.

---

## 1. D1.A — Decay-floor variants on the existing scheduler (FROZEN)

### 1.1 What we did

We ran two V5 floor-decay variants alongside the R2 V5-static baseline on the V5 catalog (48 semantic arms; existing `ConstrainedTSScheduler` with per-epoch integer per-arm quota; existing `bandit_success = 1 if (l_new + g_new + s_new) > 0 else 0` binary composite reward at `reward_v2.py:60-62`):

| Variant | Floor schedule | Seeds (final n) |
|---|---|---:|
| V5-static (R2 baseline) | `ConstantFloor(0.55)` | 1234–1243 (n=10) |
| V5-decayexp | `ExponentialDecayFloor(0.55, 0.20, K=50)` — discovery-triggered | 1234–1238 (n=5 paired) |
| V5-decayepoch | `EpochStageFloor([(0, 0.55), (2000, 0.35), (4000, 0.20)])` | 1234–1238 (n=5 paired) |

Original spec asked for n=10 paired triplets; a POS daemon failure capped us at n=5 paired (5 V5-static unpaired added for variance estimation).

### 1.2 What we found — six Findings (A–F)

| ID | Finding | Evidence |
|---|---|---|
| **A** | **K=50 saturates fast (not a bug, but a parameter mistake).** Pro's `max(0.20, 0.55 × exp(-d/K))` with K=50 hits `floor_min=0.20` after ~50 local discoveries. We accumulate ~150+/1000 mut. Decayexp behaves like `ConstantFloor(0.20)` for mut ~100–6000. Useful K range is ~200–300 (NOT K=500+, which would never transition in our 6000-mut run). | Empirical 48% floor-mode share post mut 200 vs V5-static's 96% |
| **B** | **`bandit_decisions.extra_json` is NULL.** Schema column exists but `ConstrainedTSScheduler` never populates it. Per-decision `floor_fraction_at_decision` not persisted. | Direct SQL inspection on all 20 DBs |
| **C** | **Mode sequence is seed-independent within each variant.** sha1 of `mode` sequence [200, end) is identical across all 10 V5-static seeds (`2d14a156aca51190`), all 5 decayexp seeds (`c07da3955a8f0347`), all 5 decayepoch seeds (`32a3abd14125281a`). Seed only affects WHICH arm is picked at adaptive positions, NOT the mode schedule. | Direct hashing per `D1A_SUBSECTION.md` §Finding C |
| **D** | **Scheduler geometry only supports ~3 mode regimes.** Per-arm quota is integer-checked: `target = floor_frac × 100 / 48`. Crossing each integer in `target` shifts mode share by an entire 48-pull pass. The scheduler has only `{~0%, ~48%, ~96%}` mode regimes (no ~75%, no ~25%). Pro's `[0.55, 0.35, 0.20]` epoch tiers collapse to a **2-tier** policy (0.55→96%, 0.35→48%, 0.20→48%) — the 0.35→0.20 boundary at mut=4000 is mechanically invisible. | Code analysis at `bandit_ts.py:180-187`, verified against per-DB mode share |
| **E** | **Post-boundary discovery is empirically tied.** In mut[2000, 6000) where decayepoch's policy diverges from V5-static, both variants discovered **exactly the same 10 contexts in total across 5 seeds**. Per-seed differences are ±1 to ±2; aggregate Δ = 0. | Direct first-discovery-time counts per seed |
| **F** | **We tested only HALF of Pro §7 Stage 2.** Pro §7 (`ProG_Report_3.md:175-196`) proposes both (a) floor decay AND (b) richer TS reward signals (recent marginal discovery, low-cofailure, repairability, underexplored zones). D1.A tested (a) only. The bandit's reward is a single Bernoulli bit; once `l_new`/`g_new`/`s_new` saturate together (local at ~46, CGC at ~186–189), adaptive mode has nothing to differentiate arms on — giving it 13× more decision share (decayexp's 52% vs V5's 4%) produces zero gain on the saturated metric. | `reward_v2.py:60-62` + paired-test p > 0.62 across all three pairwise comparisons + Finding E |

### 1.3 What we decided

**Decay variants are NOT killed.** D1.A's FROZEN scope is explicitly limited to "V5 catalog with existing sparse binary composite reward." The negative we measure is consistent with reward-signal saturation, NOT with decay being intrinsically bad. To either salvage decay variants or defensibly kill them in the final Pro deliverable, we must rewire the bandit reward path. **This is the entire motivation for D1.E.**

Tentative D2 recommendation (revisable after D1.E):

| Setting | Decision | Rationale |
|---|---|---|
| V5-only default | Keep `ConstantFloor(0.55)` | No evidence for switching |
| Decay variants in D2 scope | Keep | Remain candidates under enriched reward signals (D1.E) and Hybrid V7 (Pro Priority-1) |
| Future decay K | K ≈ 200–300 (NOT 50, NOT 500+) | Per Finding A — lands the available mode-transition in the saturation tail |
| Future epoch schedule | 2-tier `[(0, 0.55), (1000, 0.35)]` | Per Finding D — drop the no-op third tier |
| Block on reward signal | YES | Per Finding F — wire at least one richer signal before re-testing decay |

### 1.4 What this informs in D1.E

- **D1.E exists because of Finding F.** The point of D1.B + D1.C is to give the bandit something to learn on after the floor decays.
- **D1.E retunes K to ~200–300 per Finding A** and drops the no-op third epoch tier per Finding D.
- **D1.E re-runs V5-static + V5-decayexp + V5-decayepoch on 5 paired seeds × 3 variants = 15 jobs** under the rewired reward path. Same paired-seed structure as D1.A to enable direct comparison.

### 1.5 ❓ Pro asks

None at the D1.A stage beyond the standard "the decay diagnosis is preliminary; final verdict awaits D1.E." Frozen subsection is at `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` with all numbers, plots, and full Findings text.

---

## 2. D2.A — 5-tuple ArmKey refactor + `mutations.outcome` column (DONE)

### 2.1 What we did

D2.A is the **scheduler-shape foundation** for everything downstream. Two Composer batches:

- **Batch 1 (commit `b844e8e`):** Promoted `ArmKey` from `Tuple[str, str]` (kind, zone) to a `@dataclass(frozen=True)` with 5 string fields — `(surface, kind, zone, opcode_class, pre_post)`. Added `ArmKey.v5(kind, zone)` factory that collapses opcode_class and pre_post to `"n/a"`. Added `MutationOutcome` enum + skeleton `update_with_outcome()` method on `ConstrainedTSScheduler` (no fuzzer wiring yet). Added golden-trace test asserting V5 byte-identity under the new ArmKey.
- **Batch 2 (commit `7b66fb9`):** Added `mutations.outcome` column. Wired fuzzer-side outcome plumbing (`_outcome_for(result)` + `_mutation_record_kwargs` extension). End-to-end normalize verification. V5 byte-identity re-confirmed.

### 2.2 What we found

- **V5 byte-identity is preserved by the ArmKey refactor itself** (D2.A exit criterion: under the 5-field ArmKey + back-compat overload, fresh V5 reproduced the R2 archive byte-for-byte). This was the goal of NFP-1 — make the schema change cost-free for V5. **Caveat (added post-1.5e):** strict byte-identity to the D1.A V5 archive no longer holds for a *fresh* V5 run AFTER D2.B Batch 1.5e (commit `78d036c`), because `PRE_EXEC_REG_MOD` is now RNG-picked per pull instead of hardcoded `next_read` (see §5.3). The D1.A archive remains a valid paired baseline for D2.A's ArmKey-refactor regression purposes; for D1.E's V5-static control we use a fresh run under the post-1.5e codebase (D1.E spec §0.2 Q-E-RETROFIX-ABLATION Option B).
- **The 5-tuple is needed for Hybrid V7's Arguzz-shape arms** (`surface="arguzz_exec_fault"`, distinct `opcode_class` per fault) and for finer A4-side learning if Pro ever wants it (e.g., per-opcode-class reward profiles).
- **`mutations.outcome` resolves D1.A Finding B partially.** While `bandit_decisions.extra_json` remains NULL (Finding B), the new `outcome` column provides per-pull outcome classification that the bandit's `update_with_outcome()` consumes; D1.E's reward-rewire builds on top of this column.

### 2.3 What we decided — **NFP-1** (Notes for Pro)

| Decision | Rationale | Disclosure |
|---|---|---|
| Keep 2-tuple back-compat overload (`ArmKey.v5(...)`) | ~5 lines of code; preserves V5 RNG byte-identity **across the D2.A refactor itself** (D1.A archive reusable for D2.A regression baseline). Note: a separate post-1.5e change to `PRE_EXEC_REG_MOD` strategy selection breaks strict byte-identity for fresh V5 runs vs the D1.A archive — see §2.4 caveat | `NFP-1` |
| `surface` axis distinguishes A4 vs Arguzz; A4 arms always `surface="a4_witness_mut"` | Required for D2.D's `Hybrid_cTS` to mix A4 and Arguzz kinds without arm-key collisions | `NFP-1` |
| Tests verify `is_v5_shape()` for archive-reuse-eligible arms | Guards against silent V5-shape drift | `NFP-1` |

### 2.4 What this informs in D1.E

- **D1.E uses V5-shape ArmKeys throughout** (D1.E does NOT touch surface / opcode_class / pre_post axes — those are for D2 variants). V5-shape ArmKey behavior is preserved under D2.A's refactor.
- **D1.E's reward rewire writes to `reward_counterfactuals` + `mutations.outcome`**, both of which are already in production schema thanks to D2.A.
- **D1.E paired-test baseline is a fresh V5-static run, NOT the D1.A archive** — because post-1.5e (commit `78d036c`) `PRE_EXEC_REG_MOD` is RNG-picked per pull, breaking strict byte-identity with the D1.A archive. Per D1.E spec §0.2 Q-E-RETROFIX-ABLATION we adopted **Option B (15 jobs: 5 V5-static + 5 decayexp + 5 decayepoch all post-rewire post-retrofix)**. The D1.A archive is supplementary context, not the primary paired baseline. See §5.3 + §6.4 for the confound disclosure.

### 2.5 ❓ Pro asks

None at the D2.A stage — the refactor is internal-architecture-only; Pro does not need to confirm or revise the ArmKey shape. NFP-1 documented for posterity.

---

## 3. D1.B — CGC coarsening variants (DONE; with a load-bearing bug fix)

### 3.1 What we did

Originally a small analysis-only deliverable (3 coarsening functions + paired tests). **Expanded mid-flight** because Batch 1 audit data surfaced a production extractor bug (NFP-10, §3.5 below) that required a Batch 1.6 fix and post-hoc replay before any of the coarsening analysis could be trusted.

Final scope shipped in commit `71dae77`:

| Batch | Deliverable |
|---|---|
| 1 | Three coarsening functions (`region_only`, `log4_explicit`, `page_class`) in `analysis/cgc_variants.py`; 30-DB Cat-A layout-validation audit |
| 1.5 | Initial `page_class` ELF-derived layout for the sha2-host inspection guest |
| 1.5b | `user_dynamic` page_class label added — refined `page_class` semantics to eliminate the residual `user_other` band |
| 1.6 | **NEW (Composer audit found the bug):** `_coerce_broken_addr` field-priority fix in `compressed_global_extractor.py`; replay tooling reconstructs corrected metrics from preserved `hook3_raw` |
| 2 | Re-analysis on 20-row decay paired corpus under all 4 coarsenings (4 = production_log2_corrected + 3 alternates) |
| 3 | Saturation overlay plots, D2 recommendation, D1.E hand-off, Pro-facing subsection |

### 3.2 What we found — three headline findings

**Finding (1): Saturation inversion** (the central result)

D1.B Batch 2 measured CGC saturation timing across all 4 L0 candidates, overlaid against local saturation (`time_to_46`).

| L0 candidate | CGC saturation mut | Keys remaining at local sat (mut 3221) | Post-local rate |
|---|---:|---:|---|
| `production_log2_corrected` | ~3400 | **39** | ~1.4 new keys/100 mut |
| `log4_explicit` | ~1800 | 18 | ~0.6 new keys/100 mut |
| `page_class` | ~1300 | 18 | ~0.6 new keys/100 mut |
| `region_only` | ~1300 | 18 | ~0.6 new keys/100 mut |

**Coarsened variants saturate 1400–1900 mut EARLIER than local saturation** — the opposite of what Pro §11's "maybe page_class" hint was intended to achieve. Swapping production for `page_class` as L0 **shrinks** the post-local `g_new` discriminating window, not extends it.

Visual evidence:

![Absolute CGC saturation vs local](../d1b/plots/d1b_saturation_overlay_v5.png)

![Normalized CGC saturation vs local](../d1b/plots/d1b_saturation_overlay_v5_norm.png)

(Black dashed line = mean local `time_to_46` = mut 3221.)

**Finding (2): Thin headroom for ALL L0 candidates**

Even production's best-case post-local headroom is only +179 mutations / ~39 keys — about **1 new CGC key per 70 mutations** after local saturation. None of the four L0 schemes provide robust long-window discrimination; production is **least-bad**. **L0 schema-swap alone cannot fix D1.A's adaptive-TS-no-signal problem; L1 enrichment is needed.**

**Finding (3): decayexp +2.5% AUC hint, barely significant**

Paired tests on decayexp vs V5-static AUC under coarsened variants showed p≈0.048 at n=5 — likely a cold-start artifact of K=50 collapsing to `ConstantFloor(0.20)` per D1.A Finding A, NOT Pro's intended Stage-2 decay benefit. **D1.E forward-run with K≈200–300 is needed to confirm or kill this.**

### 3.3 What we decided — **NFP-7** (page_class definition)

D1.B evaluated three coarsenings; the most substantive choice was the definition of `page_class`, which Pro hinted at in §11 without naming the exact definition.

| Variant | Definition | Reasoning |
|---|---|---|
| `region_only` | `(family, address_region)` — drops bucket entirely | Coarsest variant |
| `log4_explicit` | `(family, address_region, floor(log2(addr) / 2))` — strictly coarser than production log2 | Control / sanity |
| `page_class` | `(family, page_class)` where `page_class` is a **semantic memory-use class** derived from the inspected guest's ELF | Replaces geometric bucket with semantic intent |

**`page_class` is OUR definition, not Pro's.** Pro §11 wrote "maybe `page_class`, not raw/log2 bucket" without naming what `page_class` means. We picked:

- **Reading (a) — semantic memory-use class** = `{stack, text, rodata, data_bss, heap, host_ecall, user_dynamic, user_other}` derived from the guest ELF + `memory.rs` platform constants + GLOSSARY `HOST_ECALL_ADDR`
- **Rejected** Reading (b) "coarser geometric page index" (just log4 by another name — already covered by `log4_explicit`)
- **Rejected** Reading (c) "region + access pattern" (duplicates `txn_role`)

**Verified `page_class` layout for sha2-host guest (workspace/output Jun 3 2026 build):**

| page_class | Range | Source |
|---|---|---|
| `stack` | `[0x00010000, 0x00200800)` | `memory.rs` STACK_TOP=0x00200400 grows down |
| `text` | `[0x00200800, 0x00219db8)` | ELF `.text` + alignment pad |
| `rodata` | `[0x00219db8, 0x0022133c)` | ELF `.rodata` + `.eh_frame` (folded) |
| `data_bss` | `[0x0022133c, 0x00221488)` | ELF `.data` + `.bss`, ending at `_end` |
| `heap` | `[0x00221488, 0x42000000)` | Bump heap from `_end` to HOST_ECALL |
| `host_ecall` | `[0x42000000, 0x42000100)` | GLOSSARY / D42 |
| `user_dynamic` | `[0x42000100, 0xBFFF0000)` | Batch 1.5b addition — eliminates `user_other` residual |
| `user_other` | residual | Catch-all; gate triggers if > 15% (currently 0.0% on sha2-host) |
| `user_bigint` | `[0xBFFF0000, 0xC0000000)` | Pass-through (one semantic class — accelerator I/O) |

### 3.4 What we decided — **NFP-8** (paired-test corpus)

D1.B uses two distinct corpora for two distinct jobs:

| Corpus | Size | Composition | Purpose |
|---|---:|---|---|
| Cat-A layout-validation | 30 rows | 10 R2 V1 + 10 R2 V5 + 10 D1.A decay | Confirms `page_class` layout covers all observed addresses |
| Decay paired-comparison tests | 20 rows | 10 R2 V5-static + 5 D1.A decayexp + 5 D1.A decayepoch | Tests whether decay variants are statistically distinguishable from V5-static under each coarsening |

**V1 deliberately excluded from decay paired tests** — V1 is a different scheduler family (b1/cTS V1), not a V5 variant. Including V1 would confound the V5-static ↔ V5-decay contrast with V1 ↔ V5 differences.

Statistical power on the decay test is **5 paired triples** — small, by design. D1.E expands this via the V5-rewired forward run.

### 3.5 What we discovered — **NFP-10** (the byte_addr bug)

**During D1.B Batch 1 audit, Composer found that production CGC memory keys had `address_region ∈ {user, zero_page}` only across all 30 audited DBs — despite parallel `global_failures` rows on the same DBs showing rich geography** (`user_regs ≈ 34%`, `kernel ≈ 11%`, `machine_regs ≈ 6%`, etc.). Opus independently verified the bug with SQL on three DBs.

**The bug:** `_coerce_broken_addr` in `compressed_global_extractor.py:216` checked fields in order `("addr", "byte_addr", "address")` and returned the first present value. Hook 3 emits BOTH:
- `addr` = circuit **word** address (index into witness memory addressing, e.g., `USER_REG_BASE = 0x3FFFC020` for registers)
- `byte_addr = addr × 4` = 32-bit VM **byte** address (the address D8 `address_region()` and ELF `page_class` are defined on)

The bug fed word-addresses into `address_region()` (which expects byte-addresses), causing **53–59% memory CGC region mis-classification across audited DBs**.

| DB | Memory rows | Region mismatch | Stored regions | True regions via byte_addr |
|---|---:|---:|---|---|
| V5 s1234 | 13670 | **58.9%** | `{user, zero_page}` (2) | `{user, user_regs, kernel, machine_regs, machine_special, ecall_dispatch, user_bigint, zero_page, invalid}` (9) |
| V1 s1234 | 11376 | 53.2% | Same 2 | Same 9 |
| D1.A decayexp s1234 | 14650 | 55.7% | Same 2 | Same 9 + `trap_dispatch_and_beyond` |

**Invariant verified:** `byte_addr == addr × 4` for 13670/13670 memory dicts on V5 s1234 (zero exceptions). Same on V1 and D1.A samples.

**The fix (Batch 1.6):** Patch field priority to `("byte_addr", "addr", "address")`. Replay tooling reconstructs corrected metrics from preserved `hook3_raw` for R2 + D1.A; cloud2 forward runs (D1.E, D2.*) use the patched extractor natively.

**What is NOT affected by the bug:**

- **Lookup families (cycle, u8, u16):** UNAFFECTED — they route through `_coerce_broken_index` (different function, different fields)
- **Local channel / `local_context_final` / `coverage`:** UNAFFECTED — local rewards come from constraint_loc strings, not addresses
- **Arms / scheduler / `bandit_decisions`:** UNAFFECTED — arm targeting doesn't use this extractor
- **`f_new` family novelty:** UNAFFECTED — family-level, not per-address
- **Hook 3 residue math itself:** Correct — the C++ correctly uses `addr` for the permutation hash; the bug is only in the *downstream Python extractor's labeling of broken addresses for CGC key construction*

**Impact on Pro's prior R2 conclusions:**

| Claim made to Pro in PROG_REPORT_2 / Brief | Status after fix |
|---|---|
| D8 `user` band is huge (~3 GiB); code/heap/stack collapse | **Still true** — D8 design unchanged |
| `address_bucket` (log2) is dominant discriminator within `user` | **Partially true** — `txn_role` and `cycle_phase` also contribute; the user band collapse was made WORSE by the bug folding `user_regs/kernel` into `user` |
| V5 mean CGC ≈ 188; V1 ≈ 144; V5 > V1 by ~30% | **Direction preserved**, absolute counts understated. Replay shows +13–20% more total keys; V5 > V1 holds |
| Memory channel under `region_only`/`log4` coarsenings is "dead" | **Partially true** — those coarsenings still collapse heavily, but with `byte_addr` the post-hoc `region_only` count goes from 2 to 9 distinct memory labels |
| `page_class` is necessary to add semantics inside `user` | **Still true** — `page_class` is complementary to a correct `address_region`, not redundant |

### 3.6 What this informs in D1.E

- **D1.E L0 baseline is `production_log2_corrected`** (post-`byte_addr` fix), NOT page_class or any other coarsening. D1.B Batch 3's recommendation `d1b_recommendation.md` is the load-bearing input here, reaffirmed in `d1e_handoff_CGC_saturation.md`.
- **D1.E forward runs use the patched extractor natively** — Batch 1.6 already landed in cloud2 main; D1.E does not need to re-coordinate the fix.
- **D1.E DOES need L1 enrichment** (D1.C's job) because L0 schema-swap alone cannot extend the post-local discriminating window. D1.B's saturation-inversion finding is the empirical evidence motivating D1.E's L1 dependency on D1.C.

### 3.7 ❓ Pro asks (the load-bearing ones)

These are the disclosures Pro should explicitly confirm or correct before D1.E spec-locks:

**❓ Pro ask (NFP-7 Q-PC-4) — `page_class` semantic definition.** When you read the D1.B subsection, please confirm:

1. Whether **semantic memory-use class** matches your "maybe page_class" intent (we picked Reading (a) `{stack, text, rodata, data_bss, heap, host_ecall, user_dynamic, user_other}`).
2. Whether you want `.eh_frame` folded into `rodata` (current) or split as its own class.
3. Whether `user_bigint` should be sub-split or pass-through (current).
4. Whether the **ELF-mandatory derivation recipe** is acceptable (Batch 1.5 hard-fails if guest ELF is missing — no silent fallback to empirical bucketing).

If you correct any of these, D1.B's `page_class` definition gets re-run; this does NOT block D1.E (which uses `production_log2_corrected` regardless), but it affects D2.G's V5-vs-V6 comparison table and the final Pro deliverable's framing.

**❓ Pro ask (NFP-10) — `byte_addr` fix + post-hoc replay acceptability.** Please confirm:

1. **`byte_addr` is the correct field** for VM-region and page-class labeling (we believe yes based on D8 + ELF semantics + the explicit `ffi.cpp:590-593` calculation `byte_addr = (uint64_t)addr * 4`).
2. **Post-hoc replay from `hook3_raw` is acceptable** for D1.B / R2 corrected metrics. Re-dispatch would cost ~5–7 hours POS compute for ~10% additional rigor; we believe replay is sufficient because local/AUC/`local_context_final` are unaffected by the memory-CGC bug, so frozen D1.A subsection conclusions stand on local-channel data.
3. If you want **legally-clean bandit trajectory under corrected reward** (i.e., re-dispatch instead of post-hoc replay), say so before D1.E dispatches its 15 POS jobs and we can include a re-dispatch of R2 V1-V5 in the same POS reservation window.

---

## 4. D1.C — Bug-proximity metric stack (DONE — committed `3a8487c`)

### 4.1 Status as of 2026-06-17

**DONE.** Spec was locked at v0.3 (`a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md`). Composer shipped Batches 1+2+3 plus a post-implementation systematic audit (`a4/docs/cloud2/composer/D1C_AUDIT_REPORT.md`). All work was squash-committed as **`3a8487c "Check d1.c"`** on `cloud2`.

**Full Pro-facing details** are in `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` (will fold into Stage 4 final D1 report) and `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` (full reference). This section is the chronological narrative; the subsection has the per-signal catalog with construction details.

### 4.2 What we did

D1.C tested **all 8 of Pro Report 3 §5/§8 bug-proximity metrics** (per-campaign Tier-2) and **5 candidate per-mutation reward signals** (Tier-1) on a 30-DB Cat-A corpus:

- 10 R2 V1 DBs (b1/cTS V1 — context only)
- 10 R2 V5 DBs (b1/cTS V5_semantic_v2 — primary D1.E target)
- 10 D1.A decay DBs (V5_decayexp + V5_decayepoch, 5 paired seeds each)

**Tier-1 signals tested** (per-mutation; Pro §7 Stage 2 reward-signal candidates + two derived from Pro §5/§8 catalog):

| Signal | Source idea | Result |
|---|---|---|
| `f_new_flag` | Pro §8 + NFP-9 "free" L1 channel — `fnew_only_reward > 0` proxy for `f_new ≥ 1` | **DEAD post-local on V5** (~0% fire rate); see Finding A below |
| `recent_marginal_discovery_rate` | Pro §7 Stage 2 "recent marginal discovery" — 100-pull rolling mean of `discovery_binary_reward` | **Passes gates** — surprise: spec expected ρ ≈ 0.4-0.7 by construction, actual ≤ 0.114 (Finding B) |
| `singleton_failure_flag` | Per-pull form of Pro §5 singleton-failure rate | **Passes gates**; per-campaign form is THE Tier-2 decay discriminator (Finding C) |
| `mutation_substrategy_uniqueness` | Proxy for Pro §7 Stage 2 "underexplored semantic zones" — first occurrence of composite `(kind, substrategy)` key | **Passes gates with best orthogonality** (max \|ρ\| = 0.069); rank 1 in shortlist |
| `d_loc_le_2_flag` | Per-pull form of Pro §8 d_loc analytics (`mutation_rewards.d_loc ≤ 2`) | **Passes gates with highest fire rate** (60.7%); opposite-saturation caveat (Finding D) |

**Tier-2 metrics tested** (per-campaign; Pro §5/§8 catalog + 2 derived):

`pro_s5_verifier_accepted_invalid_count`, `pro_s5_co_failure_graph_degree_p95`, `pro_s5_singleton_failure_rate`, `pro_s5_d_loc_p95`, `pro_s8_unique_locs_with_d_loc_le_2`, `pro_s8_unique_locs_with_d_glob_le_1`, `pro_s5_proof_generated_zero_residue_rejected_rate` (Cat-B), `pro_b_wall_clock_per_normalized_discovery` (Cat-B).

Gates were `fire_rate(post_local_window=[3000, 6000)) > 5%` (non-saturation) and `max |Pearson ρ| < 0.4` (orthogonality vs `discovery_binary_reward` + `f_new_flag` via spec §1.4 "Option A" — no per-pull replay).

### 4.3 What we found — five headline findings

#### Finding A — Pro's "free f_new L1 channel" is empirically dead on V5

`fnew_only_reward > 0` (exact proxy for `f_new ≥ 1`) fires on **0.17%** of pulls full-campaign and **~0%** post-local on the V5 corpus. NFP-9's "free engineering addition" framing is technically true (already computed in `reward_v2.py`) but **practically vacuous on this catalog** — OR-ing it into `bandit_success` adds essentially zero new signal post-local. **Likely re-activates on Hybrid V7** if V6-only kinds discover new constraint families.

NFP-9's narrative is being tightened in the notes index from "free useful" to "free but empirically zero-value on V5; available for non-V5 catalogs."

#### Finding B — Orthogonality surprise (`recent_marginal_discovery_rate` passes)

Pro §7 Stage 2 listed "recent marginal discovery" as a candidate adaptive-bandit reward signal. The spec docstring predicted that a rolling mean of `discovery_binary_reward` would correlate ρ ≈ 0.4-0.7 with the instant bit "by construction." **Reality post-local: max |ρ| = 0.114 (discretized at 0.05); max continuous Pearson 0.134.**

The mechanism: once `discovery_binary_reward` becomes sparse post-local (~3% fire rate on V5), the 100-pull rolling mean also stays low and decouples from the instant bit. **Pro gains a 4th L1 candidate that the spec did not predict would be available as a binary OR channel.**

#### Finding C — Singleton-failure rate discriminates V5-decay from V5-static (p = 2.6e-06)

Of 8 Tier-2 metrics, **only `pro_s5_singleton_failure_rate` significantly separates decay variants from V5-static**:

| Comparison | Mean A | Mean B | p (paired t, n=5) |
|---|---:|---:|---:|
| V5_decayexp vs V5-static | 12.93% | 16.69% | **2.6 × 10⁻⁶** |
| V5_decayepoch vs V5-static | 13.44% | 16.69% | **9.7 × 10⁻⁵** |
| V5_decayexp vs V5_decayepoch | 12.93% | 13.44% | 0.059 (n.s.) |

Decay variants find **~22% fewer singleton failures** than V5-static. This is the FIRST statistically significant per-campaign metric to discriminate decay variants — D1.A's `local_context_final` paired tests were all n.s. at p > 0.62.

**Two plausible architectural interpretations, both consistent with the data:**
- **(a)** Decay schedules push the bandit toward exploring mutations that break MULTIPLE constraint_locs simultaneously (higher d_loc). Weak supporting evidence: `d_loc_p95` is +1 on decayexp vs V5 across all 5 paired seeds (Wilcoxon p = 0.0625, smallest possible at n=5). If true, decay is finding **more complex failure modes**.
- **(b)** Decay schedules MISS the singleton-failure mutations entirely. If true, decay is **less efficient at surgical bug witnesses**.

**D1.C cannot distinguish (a) from (b).** D1.E forward-run with the singleton signal wired into L1 is the only way to tell — if decay's gradient improves with the singleton signal, (b) is supported; if it doesn't, (a) is.

#### Finding D — Top-3 L1 OR-channel candidates pass D1.E pre-screening

Three new per-mutation signals pass both gates on the V5 catalog, ordered by rank score `(1 / max|ρ|) × mean_fire_rate_post_local`:

| Rank | Signal | Mean post-local fire | Max \|ρ\| | Disjoint-fire vs `discovery_binary_reward` |
|---:|---|---:|---:|---:|
| 1 | `mutation_substrategy_uniqueness` | 33.7% | 0.069 | 98.1% |
| 2 | `d_loc_le_2_flag` | 60.7% | 0.239 | 99.3% |
| 3 | `singleton_failure_flag` | 16.5% | 0.082 | 99.6% |
| 4th alt. | `recent_marginal_discovery_rate` | 15.8% | 0.114 | — (continuous) |

**Opposite-saturation caveat (rank 2):** `d_loc_le_2_flag` at 60%+ post-local fire risks pushing `bandit_success` always-on — the OPPOSITE failure mode from saturation. D1.E must cap L1 OR channels at ≤ 3 per revisit plan §3.3 and consider non-naive compositions.

#### Finding E — D1.C has zero NFP-10-class field-priority dependency

Composer's systematic audit verified `git grep` over `bug_proximity.py` shows zero references to `compressed_global_coverage`, `byte_addr`, or `address_region`. The NFP-10 class of bug (wrong field fed to a downstream function, plausible aggregates) **cannot apply** to this metric stack. The closest semantic schism is crash-mode `d_loc = 0` with non-empty `failures` (~1.1% of pulls; 100% are `mode='crash'`; bounded < 0.2 pp impact on `d_loc_le_2_flag` post-local fire rate; traced to `coverage_state.py:190-198`).

### 4.4 Critical scope disclaimer

**Every D1.C result is scoped to the V5_semantic_v2 catalog under the cTS scheduler.** We did NOT test under:

| Architecture | Why results might differ |
|---|---|
| **Hybrid-cTS** (Pro §15 Priority 1) | Expanded arm count (V5 + V6-only kinds). `mutation_substrategy_uniqueness` fire rate would likely change; `f_new_flag` near-deadness may not hold if V6 kinds introduce new families; `singleton_failure_rate` decay discrimination may differ. |
| **V7** (Pro §15 Priority 3 — new TXN_PREV_*, CYCLE_* kinds) | Different reachability surface; new kinds each need substrategy-field audit; `INSTR_TYPE_MOD` all-NULL degeneracy may not generalize. |
| **Arguzz-with-thompson** (Pro §14 ablation) | Different scheduler dynamics; post-local sparse-discovery regime that drove the orthogonality surprise may not hold. |

**A Tier-1 re-audit on the first Hybrid-cTS campaign is recommended before wiring L1 in any Hybrid V7 architecture.** D1.E's V5-only forward run uses the V5-scoped shortlist as-is.

### 4.5 What D1.C did NOT claim

1. That L1 enrichment will help the bandit — D1.E forward-run is the causal test
2. That signals generalize to Hybrid V7 / V7 / Arguzz-with-thompson — see §4.4
3. That `f_new_flag` is universally dead — only on V5 catalog
4. That the singleton-decay discrimination explains decay's overall behavior — separate from D1.A's `local_context_final` n.s. result

### 4.6 Hand-off to D1.E

| Artifact | Use |
|---|---|
| `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` | Full reference: per-signal catalog, gates, bucket assignments |
| `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` | D1.E spec input — recommended L1 wiring + decay disclosures |
| `a4/runs/iv_pos_8/d1c/d1c_metrics_table.csv` | D2.G headline comparison table feed |
| `a4/runs/iv_pos_8/d1c/d1c_tier2_schema.md` | D2.G `build_d2_artifacts.py` column schema lock |
| `a4/runs/iv_pos_7/analysis/bug_proximity.py` | Tier-1/Tier-2 extractors (analysis-only — no production paths touched) |

### 4.7 ❓ Pro asks

1. **Endorsement of Top-3 L1 shortlist** (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`) for D1.E L1 wiring, or pushback if Pro wants different signals prioritized given the V5-only scope.
2. **Architectural interpretation of singleton decay finding** (§4.3 Finding C interpretations a vs b) — Pro may have prior intuition that breaks the tie before D1.E forward-run.
3. **Acknowledgment that `f_new` L1 channel is dead on V5** but stays available for Hybrid V7 — Pro may want this called out explicitly in NFP-9 vs deferred.
4. **Hybrid V7 re-audit timing** — should D1.E gate on a Hybrid V7 sanity pass first, or is V5-only D1.E sufficient as the architectural test of L0+L1 rewire?
5. **Tier-2 metric schema** for D2.G consumption (locked in `d1c_tier2_schema.md`; Pro may want column rename / additions before D2.G consumes).

---

## 5. D2.B — Eight new pure-A4 kinds + attestation hook + `PRE_EXEC_REG_MOD` retrofix (DONE)

### 5.1 Status as of 2026-06-18

**DONE.** Spec was locked at v0.5 (`a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md`). Composer shipped the full batch sequence in the parallel D2 chat:

| Batch | Commit | Content |
|---|---|---|
| Batch 1.5e (NFP-6) | `78d036c` | `PRE_EXEC_REG_MOD` retrofix — fuzzer RNG-picks `next_read`/`prev_write` per pull; arm universe ORs both. **This is the only D2.B batch in the D1.E critical path.** |
| Batch 2 | `f81523c` | (D2 chat narrative) |
| Batch 3 | `4e5150a` | (D2 chat narrative) |
| Batch 4 | `2e1d97b` | Cross-cutting + smoke; D2.B feature-complete |
| Post-Batch cleanup | `e2c2256` | PS-1: remove 5 dead arms from MUTATION_KINDS |

### 5.2 What D2.B delivered

| Component | Purpose | Relevance to D1.E |
|---|---|---|
| **Eight new A4 kinds** (3 high-priority + 5 medium) per `NFP-2` | Implements Pro's complete §8 + §15.3 wish list of pure-A4 mutation kinds | NOT in D1.E critical path — these feed D2 variants (V5-expanded, Hybrid-cTS), not V5-static + decay re-run |
| **NFP-3: `TXN_PREV_WORD_MOD` single registry kind, RNG-picked strategy** | Bandit treats `at_read` and `at_write` as one arm; fuzzer RNG-picks per pull | NOT in D1.E critical path — V5 catalog only uses existing 8 kinds |
| **NFP-4: `txn_role` mappings for 8 new kinds** | All map to Pro-valid `MEMORY_TXN_ROLES`; per-kind D2.G pivots on `producer_kind` | NOT in D1.E critical path — D1.E doesn't introduce new kinds |
| **NFP-5: Layer 3 attestation hook (`A4_DUMP_POST_MUT=1`)** | New ~30 LOC Rust hook in `workspace/risc0-modified/.../witgen/mod.rs` — emits post-mutation state dumps for cross-check | NOT in D1.E critical path — V5 mutations are already well-tested; D1.E doesn't need new attestation |
| **NFP-6: `PRE_EXEC_REG_MOD` retrofix (Batch 1.5e, commit `78d036c`)** | Existing kind had two Rust strategies (`next_read`/`prev_write`) but fuzzer hardcoded `next_read` and arm universe only probed it. Half the designed surface was dead. Retrofix: fuzzer RNG-picks per pull (`fuzzer.py:1685-1686`) + arm universe ORs both. | **YES — D1.E SYNC POINT (NOW SATISFIED).** This alters V5 mutation behavior. D1.E's V5 baseline runs AFTER this fix landed, so the new baseline matches the post-D2.B codebase. |
| **PS-1: dead-arm cleanup (commit `e2c2256`)** | Removed 5 obsolete mutation kinds from `MUTATION_KINDS` registry to match D2.B's actual final kind set | NOT in D1.E critical path — D1.E uses the existing 8 V5 kinds; PS-1 dropped only obsolete dead-code kinds |

**The D1.E ↔ D2.B sync gate is satisfied.** Only `PRE_EXEC_REG_MOD` retrofix (Batch 1.5e, ~10 LOC at `fuzzer.py:1685-1686`) is in the D1.E critical path, and it's landed. The other D2.B work feeds D2.D / D2.G — NOT D1.E.

### 5.3 Why the PRE_EXEC_REG_MOD retrofix matters for Pro

**D1.A V5 control archive remains valid** (frozen history, run under hardcoded `next_read`). Fresh V5 reruns AFTER Batch 1.5e would diverge from the D1.A archive because of the new per-pull RNG draw.

**D1.E's V5-static baseline IS a fresh re-run** (because D1.E's whole point is to test V5 under the rewired reward path). So D1.E's fresh V5 baseline uses the **new** `PRE_EXEC_REG_MOD` strategy mix. Comparing D1.E's rewired V5 against D1.A's archived V5 requires Pro to mentally separate:

- **Reward-signal effect (D1.E's hypothesis):** rewired reward vs binary composite
- **Mutation-coverage effect (D2.B Batch 1.5e side effect):** dual-strategy `PRE_EXEC_REG_MOD` vs hardcoded `next_read`

We will explicitly call this confound out in the D1.E subsection (and ideally re-run D1.A's V5-static under the new code as a control if POS reservation allows — see §6.4 below).

### 5.4 ❓ Pro asks (D2.B is DONE; these are the live disclosures)

1. **`PRE_EXEC_REG_MOD` retrofix confound for D1.E V5-static.** Per D1.E spec §0.2 Q-E-RETROFIX-ABLATION we adopted **Option B** (15 jobs, fresh V5 post-rewire post-retrofix; NOT comparing against the D1.A archive directly). The D1.A V5 archive remains as supplementary context. If Pro prefers Option C (Option B + 10 extra pre-retrofix decay jobs to isolate the retrofix from the rewire), we can add that as a +1 reservation block (~3.5 h compute) — but the D1.E v1 plan does NOT include it.
2. **Acknowledgment of NFP-4 `txn_role` mapping decisions.** We mapped the 8 new D2.B kinds to Pro-valid `MEMORY_TXN_ROLES`; Pro can request a `cycle_meta` schema bump in IV.POS.9 if finer per-kind separation is wanted.
3. **PS-1 dead-arm cleanup.** D2.B post-batch cleanup dropped 5 obsolete kinds from `MUTATION_KINDS` (commit `e2c2256`). This is internal hygiene — Pro just needs to know the final kind catalog is what shipped, not the pre-cleanup union.

---

## 6. D1.E preview — what we will wire (and what Pro will see)

### 6.1 D1.E's three components

Per `IV_POS_8_D1_REVISIT_PLAN.md` v0.6 §3.3 + `NFP-9` (with the 2026-06-17 update) + D1.E spec v0.1 (`IV_POS_8_D1_E_SPEC.md`):

**(A) Reward rewire** in `a4/standalone/reward_v2.py` + `a4/standalone/fuzzer.py`:

| Layer | Change | Source |
|---|---|---|
| **L0** | Keep production `compressed_global_context` log2 bucketing (D1.B Batch 1.6 corrected). NOT a swap — keep what we have, because D1.B Finding (1) showed coarsenings make the post-local window WORSE. | D1.B `d1b_recommendation.md` + `d1e_handoff_CGC_saturation.md` |
| **L1** | Extend `compute_bandit_success` to OR-in the **top 3 D1.C Bucket-A signals**: `mutation_substrategy_uniqueness`, `d_loc_le_2_flag` (with opposite-saturation guard), `singleton_failure_flag`. **`f_new > 0` is NOT wired into L1 for V5** per the NFP-9 update — D1.C empirically found `f_new_flag` fires on ~0.17% of pulls full-campaign and ~0% post-local on the V5 corpus (Bucket B — non-saturation failure). Engineering hook for `f_new` remains in place for future Hybrid V7 re-evaluation where V6-only kinds may re-activate the channel. | D1.C `d1e_handoff_L1_signals.md` + NFP-9 update |
| **L2** | **OUT OF SCOPE for D1.E v1.** Replacing Beta-Bernoulli TS with scalar-reward bandit (so we can use continuous-valued signals like `recent_marginal_discovery_rate` directly) is a Layer-2 architectural change deferred to D2 or follow-on. The 4th-alternate D1.C signal (`recent_marginal_discovery_rate`) is flagged for this future work. | NFP-9 |

**(B) K + epoch retune** per D1.A Finding A + Finding D:

| Parameter | D1.A value | D1.E value |
|---|---|---|
| Decayexp K | 50 (saturated by d=7) | **200–300** (transition lands in saturation tail at d≈27–41); final value locked after D1.E Batch 0 legacy-`coverage` SQL pass |
| Epoch boundaries | `[(0, 0.55), (2000, 0.35), (4000, 0.20)]` (third tier is no-op per Finding D; class is `EpochStageFloor`) | **`[(0, 0.55), (1000, 0.35)]`** (drop the no-op third tier; move boundary earlier so staircase fires inside discovery window) |

K target derivation uses `_local_discoveries` saturation (cumulative legacy `coverage.first_hit_mutation_id` count per `fuzzer.py:691-699`, per Pro §7 verbatim formula `floor_fraction(t) = max(0.20, 0.55 × exp(-local_coverage_seen / K))`). NOT changed by D1.B/D1.C — K stays anchored to local survey progress per Pro's intent.

**(C) POS re-run** — 5 paired triplets × 3 variants (V5-static, V5-decayexp, V5-decayepoch) = **15 jobs (Option B)** under the rewired reward path AND the post-1.5e codebase. Same paired-seed structure as D1.A (seeds 1234–1238) for direct comparability, though strict byte-identity to the D1.A V5 archive no longer holds (see §2.4 + §6.4). The V5-static run is FRESH, not a re-use of the D1.A archive.

### 6.2 What Pro will see after D1.E

A **direct paired comparison** of three V5 floor schedules under the **rewired reward signal**:

- If decay variants now show statistically significant gains on at least one of (a) `local_context_final`, (b) corrected `compressed_global_context_final`, (c) any of the D1.C Tier-2 bug-proximity metrics — then Pro §7 Stage 2 is partially validated and decay variants survive into D2.
- If decay variants STILL show no significant difference — then either (a) Pro's Stage 2 hypothesis is empirically wrong for the V5 catalog (decay-alone-isn't-enough), or (b) there's a Layer-2 (scalar bandit) requirement we haven't met. D1.E result will distinguish (a) vs (b) by examining whether the rewired binary OR `bandit_success` actually has more post-local discrimination than the original.

### 6.3 D1.E sync requirements (all DONE; spec is greenlight-pending)

| Requirement | Owner | Status |
|---|---|---|
| D1.B `production_log2_corrected` baseline | D1.B (Composer + Opus, commit `71dae77`) | **DONE** |
| D1.C Tier-1 shortlist + `d1e_handoff_L1_signals.md` | D1.C Batch 3 (commit `3a8487c`) | **DONE** |
| D2.B Batch 1.5e `PRE_EXEC_REG_MOD` retrofix | D2.B Composer (commit `78d036c`); full D2.B done at `e2c2256` | **DONE** |
| D1.E spec draft (Q-E-* defaults proposed) | Opus (`a4/docs/cloud2/IV_POS_8_D1_E_SPEC.md` v0.2 — Composer audit issues fixed: schema-correct persistence in `reward_counterfactuals`, post-1.5e regression golden trace, post-local opposite-saturation pre-flight, `EpochStageFloor` naming, `l1_signals.py` extractor wiring, in-memory `diag["d_loc"]`) | **DRAFT v0.2** |
| Ivan greenlight on D1.E spec Q-E-* defaults | Ivan | **PENDING** |
| D1.E Batch 0 (legacy `coverage` SQL pass to lock K + epoch boundaries) | Composer (after Ivan greenlight) | NOT STARTED |

### 6.4 Pro-visible decision: D1.E V5-static baseline resolution

**Decision made (D1.E spec §0.2 Q-E-RETROFIX-ABLATION):** Adopted **Option B** — D1.E uses a fresh V5-static run under post-1.5e + post-rewire codebase as the paired-test baseline (5 V5-static + 5 decayexp + 5 decayepoch = 15 jobs total). The D1.A V5 archive is supplementary context, not the primary paired baseline.

**Rationale:**
- Post-1.5e `PRE_EXEC_REG_MOD` is RNG-picked per pull (`fuzzer.py:1685-1686`) — strict byte-identity with D1.A archive is gone.
- The L1 rewire changes the bandit's pull pattern, so even the same kind catalog produces different trajectories. Reusing D1.A V5 archive would conflate "did rewire help?" with "did retrofix change V5 baseline?".
- Option B costs ~5.5h compute (within one reservation block); fresh V5 is justifiable per revisit plan §3.3 Composer-point-5 rationale.

**Pro-facing confound disclosure:** D1.E V5-static vs D1.A V5 archive comparison confounds two changes — (i) the L1 reward rewire (D1.E's hypothesis test) and (ii) the `PRE_EXEC_REG_MOD` strategy mix change (D2.B Batch 1.5e side-effect). D1.E v1 subsection will explicitly call this out. **If Pro prefers** clean separation of (i) from (ii), we can add **Option C** (+10 pre-retrofix decay-variant jobs, one extra reservation block ~3.5h) — but the D1.E v1 default is Option B.

### 6.5 ❓ Pro asks at the D1.E preview stage

1. **Endorsement of L1 wiring** — 3 D1.C signals naively OR'd into `compute_bandit_success` per spec Q-E-L1-COMPOSITION / Q-E-L1-SIGNALS. Pro may want a non-naive composition (per-channel reward, weighted, multi-objective) per `d1b_recommendation.md` §4 — that is an open question deferred from D1.B and explicitly out-of-scope for D1.E v1; if Pro wants it pulled in, we re-spec.
2. **Endorsement of K + epoch retune targets** — K ≈ 200-300 anchored to legacy `coverage` saturation; epoch boundaries `[(0, 0.55), (1000, 0.35)]`. D1.E Batch 0 pins exact K from the SQL pass.
3. **Option B vs Option C decision** (§6.4) — do we add the +10-job pre-retrofix decay-variant ablation to isolate the rewire from the retrofix?
4. **Hybrid V7 re-audit timing** — should D1.E gate on a Hybrid V7 sanity pass first, or is V5-only D1.E sufficient as the architectural test of L0+L1 rewire? (Per D1.C scope disclaimers — all D1.C signal gates were measured on V5 only.)

---

## 7. Where to read more

| Topic | File |
|---|---|
| D1.A frozen subsection (Findings A–F, Limitations 1–8) | `a4/runs/iv_pos_8/d1a/D1A_SUBSECTION.md` |
| D1.B Pro-facing subsection (saturation overlay + recommendation) | `a4/runs/iv_pos_8/d1b/D1B_SUBSECTION.md` |
| D1.B → D1.E hand-off (L0 baseline rationale) | `a4/runs/iv_pos_8/d1b/d1e_handoff_CGC_saturation.md` |
| D1.B `page_class` ELF layout | `a4/runs/iv_pos_8/d1b/d1b_page_class_layout.md` |
| D1.B variant recommendation | `a4/runs/iv_pos_8/d1b/d1b_recommendation.md` |
| D1.C spec (DONE at `3a8487c`) | `a4/docs/cloud2/IV_POS_8_D1_C_SPEC.md` v0.3 |
| D1.C Pro-facing subsection | `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` |
| D1.C full signal reference (self-contained explainer) | `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` |
| D1.C D1.E hand-off | `a4/runs/iv_pos_8/d1c/d1e_handoff_L1_signals.md` |
| D1.C systematic audit report | `a4/docs/cloud2/composer/D1C_AUDIT_REPORT.md` |
| D2.A spec (DONE at `7b66fb9`) | `a4/docs/cloud2/IV_POS_8_D2_A_SPEC.md` v0.2 |
| D2.B spec (DONE — final commit `e2c2256`) | `a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md` v0.5 |
| D1.E spec (DRAFT v0.2; Ivan greenlight on Q-E-* pending before Batch 0 kickoff) | `a4/docs/cloud2/IV_POS_8_D1_E_SPEC.md` |
| D1 revisit plan (the master plan that spawned this briefing) | `a4/docs/cloud2/IV_POS_8_D1_REVISIT_PLAN.md` v0.6 |
| Notes for Pro index (NFP-1 through NFP-10) | `a4/docs/cloud2/IV_POS_8_NOTES_FOR_PRO.md` |

---

## 8. Revision history

| Date | Author | Change |
|---|---|---|
| 2026-06-17 | Opus | Initial draft v0.1 — covers completed work through 2026-06-17: D1.A (frozen), D2.A (done at `7b66fb9`), D1.B (done at `71dae77`). Placeholder structures for D1.C (in progress), D2.B (in progress), D1.E preview. Embeds Pro disclosure asks NFP-7 Q-PC-4, NFP-10 byte_addr fix + post-hoc replay acceptability, NFP-9 D1.E L0+L1 framing, NFP-6 D1.A V5-static re-run decision. |
| 2026-06-17 | Opus | v0.2 — extended §4 with D1.C completed status, 5 headline findings, scope disclaimer, 5 Pro asks (after D1.C commit `3a8487c`). |
| 2026-06-18 | Opus | **v0.3 — post-Composer-audit refresh.** Updated TL;DR table to reflect D2.B DONE (commits `78d036c` → `e2c2256`). Refined D2.A "V5 byte-identity" claims to clarify the byte-identity is for the ArmKey refactor itself; post-1.5e `PRE_EXEC_REG_MOD` RNG change breaks strict byte-identity for fresh runs (§2.4 + §6.4). Updated §5 to DONE status with all D2.B commits + live Pro asks. Fixed §6.1 L1 row to remove `f_new > 0` per NFP-9 update + D1.C empirical finding (was previously listed as a "free" L1 channel — but D1.C found ~0% post-local fire on V5). Refreshed §6.3 sync requirements table (all DONE; spec greenlight-pending). Reframed §6.4 as "decision made: Option B" with Option C still available if Pro prefers cleaner separation. Added §6.5 with 4 live Pro asks at the D1.E preview stage. Updated §7 file index with D1.C subsection/shortlist/handoff/audit + D2.B DONE + D1.E spec draft. |

*End of `IV_POS_8_PRE_D1E_BRIEFING_FOR_PRO.md` v0.3.*
