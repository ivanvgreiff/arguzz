# IV.POS.8 — Notes for Pro

**Purpose:** Running log of architectural decisions made during IV.POS.8 (cloud2) development that Pro needs to understand before reading the deliverable-level reports (D1.A report, D2.G report, etc.).

This is **not** the final Pro-facing report — that lives at `IV_POS_8_D2_REPORT_FOR_PRO.md` (assembled at D2.G). This is a running architectural index Pro can read to grasp *why* the system is built the way it is, with no surprises at deliverable time.

**Format:** one decision per section, ordered by chronology. Each entry includes the decision, the alternative considered, the rationale, and any constraints Pro should be aware of going forward.

---

## Index

- [NFP-1: ArmKey 5-tuple — back-compat preserved for V5 archive reuse](#nfp-1-armkey-5-tuple--back-compat-preserved-for-v5-archive-reuse)
- [NFP-2: D2.B kinds — 8 from Pro's bullet list, variant-specific subsets](#nfp-2-d2b-kinds--8-from-pros-bullet-list-variant-specific-subsets)
- [NFP-3: B.1 `TXN_PREV_WORD_MOD` — single registry kind, RNG-picked strategy per pull](#nfp-3-b1-txn_prev_word_mod--single-registry-kind-rng-picked-strategy-per-pull)
- [NFP-4: D2.B CGC `txn_role` — Pro-valid roles only; per-kind D2.G pivots on `producer_kind`](#nfp-4-d2b-cgc-txn_role--pro-valid-roles-only-per-kind-d2g-pivots-on-producer_kind)
- [NFP-5: Layer 3 attestation — new Rust `A4_DUMP_POST_MUT=1` hook is load-bearing](#nfp-5-layer-3-attestation--new-rust-a4_dump_post_mut1-hook-is-load-bearing)
- [NFP-6: `PRE_EXEC_REG_MOD` retrofix — pure A4 cleanup landing alongside D2.B Batch 1](#nfp-6-pre_exec_reg_mod-retrofix--pure-a4-cleanup-landing-alongside-d2b-batch-1)
- [NFP-7: D1.B CGC coarsening variants — region_only / log4_explicit / page_class; `page_class` is a substantive substitution of Pro's hint](#nfp-7-d1b-cgc-coarsening-variants--region_only--log4_explicit--page_class-page_class-is-a-substantive-substitution-of-pros-hint)
- [NFP-8: D1.B paired-test corpus — V5-static + decay variants only (20 rows); V1 excluded from decay paired tests](#nfp-8-d1b-paired-test-corpus--v5-static--decay-variants-only-20-rows-v1-excluded-from-decay-paired-tests)
- [NFP-9: D1.E reward rewire — L0 + L1 only; K stays anchored to `_local_discoveries` per Pro §7](#nfp-9-d1e-reward-rewire--l0--l1-only-k-stays-anchored-to-_local_discoveries-per-pro-7)
- [NFP-10: Hook 3 `addr` vs `byte_addr` field-priority bug — production CGC memory regions mis-labeled across all V1-V5 + D1.A; post-hoc replay corrects R2/D1.A; cloud2 forward runs fixed](#nfp-10-hook-3-addr-vs-byte_addr-field-priority-bug--production-cgc-memory-regions-mis-labeled-across-all-v1-v5--d1a-post-hoc-replay-corrects-r2d1a-cloud2-forward-runs-fixed)
- [NFP-11: D2.B dead/live A4-kind split — 3 live + 5 dead arms on sha2-host](#nfp-11-d2b-deadlive-a4-kind-split--3-live--5-dead-arms-on-sha2-host)

---

## NFP-1: ArmKey 5-tuple — back-compat preserved for V5 archive reuse

**Decision:** Refactored the bandit-arm identity from a 2-tuple `(kind, zone)` to a 5-tuple `ArmKey(surface, kind, zone, opcode_class, pre_post)`. **Kept** the 2-tuple back-compat overload (`ArmKey.v5(kind, zone)` collapses opcode_class and pre_post to `"n/a"`).

**Alternative considered:** Break the 2-tuple shape — every old call site updates to 5-tuple.

**Rationale:**
- The 5-tuple is needed for Hybrid V7's Arguzz-shape arms (`surface="arguzz_exec_fault"`, distinct `opcode_class` per fault) and for finer A4-side learning if you ever want it.
- The back-compat overload is ~5 lines and preserves V5's RNG byte-identity, which means the D1.A static V5 archive (10 sealed DBs, ~3 h compute) remains a valid baseline for paired D2 comparisons.
- Without back-compat we'd rerun V5 under the new fuzzer; ~3 h compute saved per cycle.

**What Pro should know going forward:**
- The 5-tuple is *always* used as the dict key in `SemanticArmUniverse.arms`.
- A4 kinds populate `opcode_class="n/a"` and `pre_post="n/a"` (the v5 shape).
- Arguzz kinds (D2.C) populate all 5 fields.
- Tests verify `is_v5_shape()` for archive-reuse-eligible arms.

**Source:** `IV_POS_8_D2_A_SPEC.md` v0.2 §1 + §8 (cross-cutting decision); merged at `7b66fb9`.

---

## NFP-2: D2.B kinds — 8 from Pro's bullet list, variant-specific subsets

**Decision:** D2.B implements **all 8** of Pro's named pure-A4 kinds (3 priority-ordered from §15.3 + 5 medium-risk candidates from §8):
- High: `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, `CYCLE_MODE_MOD`
- Medium: `TXN_ADDR_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`, `CYCLE_STATE_MOD`, `CYCLE_DIFF_COUNT_MOD`

**Critical detail for Pro: variant-specific kind subsets.** The global `MUTATION_KINDS` registry is the union of all 20 kinds (8 existing + 8 D2.B + 4 D2.C). D2.D variants filter this:

| Variant | Kind subset | Archive |
|---|---|---|
| `V5_control` | 8 existing kinds only | **D1.A archive reuse** |
| `V5_expanded` (optional) | 16 A4 kinds | Fresh run |
| `Hybrid_cTS` | 16 A4 + 4 V6 kinds | Fresh run |
| `V6_uniform` / `V6_cTS` | 4 V6 kinds | Fresh run |

**Why this matters:** Without variant filtering, naive registry expansion would silently break D1.A archive comparability (paired V5 baseline ↔ D2 variants becomes apples-to-oranges).

**Pro's §8 wider catalog** (`CYCLE_INDEX_MOD`, `REG_TXN_NON_INSN_MOD`, `BIGINT_DATA_MOD`, `CRYPTO_STATE_MOD`, `ECALL_BACK_MOD`, `STRUCTURAL_MOD`) is **deferred to a future IV.POS cycle** per Pro §15 last paragraph.

**Source:** `IV_POS_8_D2_B_SPEC.md` v0.4 §1.0 + Q6.

---

## NFP-3: B.1 `TXN_PREV_WORD_MOD` — single registry kind, RNG-picked strategy per pull

**Decision:** B.1 ships with **two Rust strategies** (`at_read` flips `prev_word` at a READ txn; `at_write` flips at a WRITE txn). Both produce genuinely different constraint failures (`IsRead` vs `MemoryWrite` chain). But the bandit treats them as **one arm-kind** — `MUTATION_KINDS` has a single `"TXN_PREV_WORD_MOD"` entry; the fuzzer RNG-picks the strategy per pull.

**Alternative considered:** Two distinct kind strings (`TXN_PREV_WORD_MOD_AT_READ`, `_AT_WRITE`). Rejected because it doubles arm-space and breaks D1.A archive semantics for marginal per-strategy learning.

**Rationale:**
- Smallest registry footprint preserves variant-specific subset clarity.
- Strategy is logged in the per-mutation config JSON → reproducible from DB.
- Bandit learns "this zone responds to strategy mix" via outcome aggregation (acceptable v1 tradeoff; not full per-strategy reward learning).

**Tradeoff Pro should know:** the bandit cannot favor `at_read` over `at_write` (or vice versa) per zone — it only sees aggregate reward. If D2.G shows one strategy dominates, we can split to Option B in D3.

**Source:** `IV_POS_8_D2_B_SPEC.md` v0.4 §3.1 + Q11.

---

## NFP-4: D2.B CGC `txn_role` — Pro-valid roles only; per-kind D2.G pivots on `producer_kind`

**Decision:** All 8 D2.B kinds map to **Pro-valid `MEMORY_TXN_ROLES`** (the 6-tuple `(read, write, ifetch, register, prev_word, prev_cycle)` from `compressed_global.py:52-54`). Per-kind attribution for D2.G analytics pivots on `producer_kind` (the full mutation kind string, already in `GLOBAL_LOOKUP` schema).

| Kind | `txn_role` |
|---|---|
| B.1 `TXN_PREV_WORD_MOD` | `prev_word` (Pro-reserved) |
| B.2 `TXN_PREV_CYCLE_MOD` | `prev_cycle` (Pro-reserved) |
| B.4 `TXN_ADDR_MOD` | `read` or `write` (from target txn parity) |
| B.5 `TXN_CYCLE_PHASE_MOD` | `read` (fetch excluded per Q14) |
| B.3, B.6, B.7, B.8 (cycle-meta) | `read` default |

**Alternative considered:** Extend `MEMORY_TXN_ROLES` with a new `"cycle_meta"` role (and possibly `"addr_meta"`) and coordinate a Pro schema bump. Rejected for v1 to keep D2.B critical path clean; **flagged for Pro D2.G review:** if Pro wants finer `txn_role` semantics for cycle-meta kinds, we ship the schema extension in a follow-up cycle.

**Rationale:**
- `producer_kind` is the right separation axis for per-kind analytics.
- `txn_role` was designed (D16, see `compressed_global.py:36-46`) as a memory-family proxy, not field-name taxonomy.
- Existing tests (`test_compressed_global_extractor.py:152, 480`) assert `role ∈ MEMORY_TXN_ROLES` — extending would have to land coordinated with Pro.

**For Pro at D2.G review:** if you want a separate `cycle_meta` (or per-field) role enum, signal in the D2.G review and we land a schema bump in IV.POS.9.

**Source:** `IV_POS_8_D2_B_SPEC.md` v0.4 §4.7 + Q5.

---

## NFP-5: Layer 3 attestation — new Rust `A4_DUMP_POST_MUT=1` hook is load-bearing

**Decision:** D2.B's "100%-certainty" test stack relies on Layer 3 ("the trace state actually changed in the way the dispatcher tag claims"). This requires **a new ~30 LOC Rust hook** in `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`: `A4_DUMP_POST_MUT=1` env var that emits `<a4_post_mut_dump>` tags for each mutated cycle/txn after the mutation match arm completes.

**Why this matters for Pro:** Without this hook, Layer 3 would compare two *pre-mutation* dumps (because the inspection block at `mod.rs:72-187` runs *before* the mutation block at `mod.rs:189-601`). The "100% certainty" claim would be **false** — Layer 4's cross-check would compare the dispatcher tag against itself via two paths that never observed post-mutation state.

**Cost:** One small Rust patch shipped in D2.B Batch 1.0a; not a new infrastructure project.

**Source:** `IV_POS_8_D2_B_SPEC.md` v0.4 §5 + Q17.

---

## NFP-6: `PRE_EXEC_REG_MOD` retrofix — pure A4 cleanup landing alongside D2.B Batch 1

**Decision:** The existing `PRE_EXEC_REG_MOD` kind has had two strategies documented (`next_read`, `prev_write`) and both implemented in Python (`pre_exec_reg_mod.py:67`) and Rust (`witgen/mod.rs:462-535`) since cloud1. **But the fuzzer hardcodes `next_read`** (`fuzzer.py:1639`), and the arm universe only probes `next_read` (`semantic_arm_universe.py:90-91`). Half the designed surface is dead in production.

D2.B Batch 1 ships a small retrofix (task 1.5e, ~10 LOC):
- `fuzzer.py::_create_mutation` — RNG picks `next_read`/`prev_write` per pull (same Option A pattern as B.1)
- `semantic_arm_universe.py::_step_has_real_target` — OR both strategies

**This is A4-only.** It does NOT touch Arguzz's separate `PRE_EXEC_REG_MOD` fault (subprocess to Arguzz binary, parsed via `<fault>` tag) — Arguzz mutation strategies are deliberately unchanged because we want to compare Arguzz's external execution-time fault model against A4's witness-time mutation model.

**What Pro should know:**
- D1.A V5 control archive **remains valid** (frozen history, run under hardcoded `next_read`).
- Fresh V5 reruns (if any) would diverge from archive due to the new per-pull RNG draw. None planned — plan v0.7 line 100 reuses D1.A archive.
- Post-D2.B, `PRE_EXEC_REG_MOD` will explore both strategies — coverage signal improves; arm-level reward may differ from R2 numbers (Pro should expect a Pro-visible delta if comparing R2 PRE_EXEC_REG_MOD failure rates against D2 numbers).

**Source:** `IV_POS_8_D2_B_SPEC.md` v0.4 §7 Batch 1.5e; this `NFP-6` entry.

---

## NFP-7: D1.B CGC coarsening variants — region_only / log4_explicit / page_class; `page_class` is a substantive substitution of Pro's hint

**Decision:** D1.B evaluates **three** alternative coarsenings of the compressed-global-context (CGC) bucketing in our R2 corpus and recommends one as the **D2 default CGC reward signal**:

| Variant | Key shape | Coarsens what |
|---|---|---|
| `region_only` | `(family, address_region)` | Drops `address_bucket` entirely — coarsest variant |
| `log4_explicit` | `(family, address_region, floor(log2(addr) / 2))` | Halves production's `log2` bucket count; strictly coarser than production |
| `page_class` | `(family, page_class)` where `page_class` is a **semantic memory-use class** within `user` / `user_bigint` | Replaces geometric `address_bucket` with semantic intent |

**Critical: `page_class` is OUR definition, not Pro's.** Pro §11 wrote "maybe `page_class`, not raw/log2 bucket" without naming the definition. We chose a concrete one — please confirm or correct in your R3 feedback.

**Q-PC-1: page_class semantic meaning** — Reading (a) "semantic memory-use class" — `{stack, text, rodata, data_bss, heap, host_ecall, user_other}` derived from the inspected guest's runtime memory layout. **Rejected** Reading (b) "coarser geometric page index" (just `log4` by another name — already covered by `log4_explicit`) and Reading (c) "region + access pattern" (duplicates `txn_role`).

**Q-PC-2: page_class layout source — ELF MANDATORY** (Composer + Opus audit 2026-06-17). Boundaries derived deterministically from:
1. The **inspected guest's ELF** (`workspace/output/target/riscv-guest/risc0-methods/risc0-guest/riscv32im-risc0-zkvm-elf/release/risc0-guest`, 248292 bytes, verified present, `readelf -S` parseable) — provides `.text` / `.rodata` / `.eh_frame` / `.data` / `.bss` / `_end` ranges. **Guest-specific** (changes per guest binary).
2. **zkVM platform `memory.rs`** (`workspace/risc0-modified/risc0/zkvm/platform/src/memory.rs`) — provides `STACK_TOP=0x00200400`, `TEXT_START=0x00200800`, `GUEST_MAX_MEM=0xC0000000` for stack/heap-upper-bound anchors. **Guest-agnostic** zkVM constants.
3. **GLOSSARY / D42** — `HOST_ECALL_ADDR` MMIO buffer at `[0x42000000, 0x42000100)`.

**Empirical address histograms are validation-only** (`user_other` fraction gate ≤ 15%), NOT a layout source. Batch 1.5 **hard-fails** if the ELF is missing (runs `cargo build --release` instruction); no silent fallback to empirical bucketing.

**Q-PC-3: page_class application scope** — Only splits `user` / `user_bigint` (the bulk bands Pro complained about). For all other `address_region` values (kernel, machine_regs, etc.), `page_class = address_region` (pass-through). Keeps semantic clarity where Pro cared, no noise elsewhere.

**Q-PC-EHF: `.eh_frame` treatment** — **Folded into `rodata`**. The ELF has a small `.eh_frame` section (`[0x0021d744, 0x0022033c)`, ~11 KB) for C++/Rust unwind metadata. Read-only, semantically adjacent to rodata. Splitting it would create a page_class with very few hits (Rust panics + unwind walks only). Documented in the layout artifact.

**Verified `page_class` layout for sha2-host (workspace/output guest, Jun 3 2026 build):**

| page_class | Range | Source |
|---|---|---|
| `stack` | `[0x00010000, 0x00200800)` | `memory.rs` `STACK_TOP=0x00200400` grows down into the band below `TEXT_START` |
| `text` | `[0x00200800, 0x00219db8)` | ELF `.text` (extends up to `.rodata.addr` to absorb 1028 B alignment pad) |
| `rodata` | `[0x00219db8, 0x0022133c)` | ELF `.rodata` + `.eh_frame` (folded) |
| `data_bss` | `[0x0022133c, 0x00221488)` | ELF `.data` + `.bss`, ending at symbol `_end` |
| `heap` | `[0x00221488, 0x42000000)` | Bump heap from `_end` to HOST_ECALL |
| `host_ecall` | `[0x42000000, 0x42000100)` | GLOSSARY / D42 |
| `user_other` | remainder in `user` band | Catch-all; Batch 1.5 gate triggers escalation if > 15% |

`user_bigint = [0xBFFF0000, 0xC0000000)` is pass-through (one semantic class — accelerator I/O).

**What Pro should know:**
- **Page_class layout changes per guest.** This table is valid for the `workspace/output` sha2-host guest only. Different guest programs (different `.text` / `.rodata` / `.data` / `.bss` sizes and VMAs, different `_end`) require re-derivation. D1.B ships a **derivation recipe**, not magic numbers. Batch 1.5 emits `d1b_guest_elf_layout.json` with `guest_elf_sha256` for provenance.
- **Folklore rejection.** Earlier internal docs (`PHASE_3_GLOBAL_CTX.md`, `CLOUD1_DECISIONS_FOR_PRO_R2.md` D8 §G3) had heap/stack ranges (`heap [0x10000000, 0x70000000)`, `stack [0x70000000, 0x80000000)`) that were Phase-3 paper sketches **never shipped to production**. The verified ELF layout above contradicts them; production `_ADDRESS_REGION_MAP` was always one fat `user` band. See `IV_POS_8_D1_B_SPEC.md` §0.4 for the full provenance audit.
- **D1.B is post-hoc analysis on existing DBs** (R2 V1 + R2 V5 + D1.A decay = 30 rows). No fuzzer reruns; no production-extractor changes. D2 picks up the recommended coarsening for forward runs.
- **First-hit semantics.** All four variants (production_log2 + 3 D1.B coarsenings) compute curves from per-(family, coarsened-key) `MIN(mutation_id)`. This matches production CGC's `first_hit_mutation_id` semantics so curves are comparable.

**Q-PC-4 disclosure request:** When you read the D1.B subsection in the final D1 report, please confirm:
1. Whether semantic memory-use class matches your "maybe page_class" intent (Q-PC-1).
2. Whether you want `.eh_frame` folded into `rodata` or split as its own class (Q-PC-EHF).
3. Whether `user_bigint` should be sub-split or pass-through (currently pass-through).
4. Whether the ELF-mandatory derivation recipe is acceptable, or you prefer a different boundary source.

**Source:** `IV_POS_8_D1_B_SPEC.md` v0.3.1 §0.1–0.4, §1.2, §3.2; `IV_POS_8_D1_REVISIT_PLAN.md` v0.4 §3.1; this `NFP-7` entry.

---

## NFP-8: D1.B paired-test corpus — V5-static + decay variants only (20 rows); V1 excluded from decay paired tests

**Decision:** D1.B uses **two distinct corpora** for two distinct jobs:

| Corpus | Size | Composition | Purpose |
|---|---|---|---|
| Cat-A layout-validation | **30 rows** | 10 R2 V1 + 10 R2 V5 + 10 D1.A decay | Confirms `_PAGE_CLASS_USER_LAYOUT` covers all observed addresses across our whole audited corpus (broader = stronger `user_other ≤ 15%` gate) |
| Decay paired-comparison tests | **20 rows** | 10 R2 V5-static + 5 D1.A decayexp + 5 D1.A decayepoch | Tests whether decay variants are statistically distinguishable from V5-static **under each coarsening** |

**V1 deliberately excluded from decay paired tests.** V1 is a different scheduler family (b1/cTS V1), not a V5 variant. Including V1 would confound the V5-static ↔ V5-decay contrast with V1 ↔ V5 differences.

**Paired structure:**
- 5 **fully-paired triples** (V5-static, decayexp, decayepoch) on shared seeds 1234-1238 → the actual paired-test units
- 5 **additional V5-static rows** on seeds 1240-1244 → improves V5 baseline mean/variance estimation; no decay pair

**What Pro should know:**
- Statistical power on the decay test is **5 paired triples** — small, by design. Expanding requires re-running decay variants under matched seeds (D1.E spec handles forward-run re-execution after the reward rewire).
- D1.B is **frozen-DB analysis only** — no new compute, no extractor changes, no Layer 3 attestation. Results are upper bound for what a hindsight coarsening can show; if D1.B finds no signal, the right conclusion is "neither coarsening alone discriminates V5/decay" — NOT "decay variants are dead." (D1.E retests after enriching the reward signal.)
- The 30-row Cat-A audit uses V1 only for layout-coverage breadth — V1's `address_region` and `byte_addr` distributions are informative even though V1 isn't a V5 variant.

**Source:** `IV_POS_8_D1_B_SPEC.md` v0.3.1 §0.2, §3.1 task 1, §7.1; `IV_POS_8_D1_REVISIT_PLAN.md` v0.4 §3.1; this `NFP-8` entry.

---

## NFP-9: D1.E reward rewire — L0 + L1 only; K stays anchored to `_local_discoveries` per Pro §7

**Decision:** D1.E (the re-run of decay variants after D1.B + D1.C land) rewires the bandit reward signal at **two layers only**:

| Layer | Change | Purpose |
|---|---|---|
| **L0** | Replace production `compressed_global_context` log2 bucketing in `compressed_global_extractor.py` with D1.B's recommended coarsening (or keep log2 and add a coarsened channel) | `g_new` keeps discriminating past `_local_discoveries` saturation |
| **L1** | Extend `compute_bandit_success` to OR-in one or more Tier-1 per-mutation D1.C bug-proximity signals (top 3 from `d1c_signal_shortlist.md`: `mutation_substrategy_uniqueness`, `d_loc_le_2_flag` with opposite-saturation guard, `singleton_failure_flag`). `f_new > 0` was originally listed here as a "free" addition (already computed in `reward_v2.py:compute_reward_v2_components` but excluded from today's Bernoulli) but **D1.C empirically found it dead on V5** (~0% post-local fire rate; see UPDATE 2026-06-17 below). Keep available as engineering hook for non-V5 catalogs (Hybrid V7) where new constraint families may re-activate it. | Extends `bandit_success` discriminating window |

**Layer 2 (replace Beta-Bernoulli TS with scalar-reward bandit) is explicitly OUT of D1.E v1 scope.** Pro §7 Stage 2 does not literally require it; binary suffices if OR-of-signals is informative. Defer to D2 or follow-on.

**`ExponentialDecayFloor.K` is NOT changed by D1.E.** K stays driven by `_local_discoveries` (cumulative legacy `coverage` table row count, per Pro §7 verbatim formula `floor_fraction(t) = max(0.20, 0.55 * exp(-local_coverage_seen / K))`). Verified in production at `bandit_ts.py:98-100`. An earlier internal draft considered driving the floor from CGC discoveries instead — this was **removed as anti-Pro**: it would prevent the floor from decaying on local saturation, defeating Pro's whole staged-exploration design.

**The point of D1.B + D1.C is to give adaptive TS something meaningful to optimize on AFTER the floor decays as Pro designed.** D1.A's failure (FROZEN in `D1A_SUBSECTION.md`) was that the existing `bandit_success` signal saturated at the same time `_local_discoveries` did — adaptive mode had no discriminating signal left once the floor was low. The fix is to enrich `bandit_success`, NOT to change what K decays on.

**What Pro should know:**
- D1.E will recompute K from `SELECT COUNT(*) FROM coverage` cumulative curves on existing DBs (cheap SQL pass) — this is `_local_discoveries` saturation, distinct from D1.A's `local_context_final ≈ 46` metric which counts `local_coverage_v2` rows (different dedup granularity).
- Forward-run K may shift further once L0+L1 land, because better TS exploitation changes which arms get pulled, which affects how fast `coverage` grows. D1.E spec will note this.
- D1.A decay variants are NOT yet discarded — D1.A's FROZEN report (`D1A_SUBSECTION.md`) explicitly limits its scope to "old sparse binary reward signal." D1.E re-tests under enriched signals before any deprecate recommendation.

**Source:** `IV_POS_8_D1_REVISIT_PLAN.md` v0.4 §3.3 + §4 (D1.E section); `IV_POS_8_D1_B_SPEC.md` v0.3.1 §0.1.1; `D1A_SUBSECTION.md` Limitations 6-8; this `NFP-9` entry.

**UPDATE 2026-06-17 (D1.C commit `3a8487c`):** D1.C empirically tested `f_new > 0` as a Tier-1 L1 OR-channel candidate on the 30-DB Cat-A corpus (10 V1 + 10 V5 + 10 D1.A decay). Result: `fnew_only_reward > 0` (exact proxy for `f_new ≥ 1`) fires on **0.17%** of pulls full-campaign and **~0%** post-local on the V5 corpus. **0 of 30 DBs pass the 5% non-saturation gate.** Family-novelty events are concentrated very early in V5 campaigns and don't extend the bandit signal post-local.

**Tightened framing:**
- **Engineering cost:** still free (computation already in `reward_v2.py:148-156`, just not OR'd into `compute_bandit_success`).
- **Practical value on V5:** **zero post-local discrimination.** Wiring it into D1.E's L1 OR on the V5 catalog adds essentially no information.
- **Practical value on Hybrid V7 / V7-only:** **unknown — possibly re-activated.** V6-only kinds (per Pro §15 Priority 1) discover constraint families V5 cannot reach; `f_new` may fire materially more often on those catalogs. Re-audit required before assuming.

**D1.E decision (committed for V5 forward run):** Do NOT OR `f_new > 0` into L1 on the V5 + decay re-run. Keep the engineering hook in place so a future Hybrid V7 forward run can flip it on after a Tier-1 re-audit on Hybrid V7 telemetry. The top-3 D1.C L1 candidates (`mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, `singleton_failure_flag`) replace `f_new` as the load-bearing L1 signals for D1.E.

**Sources for this update:** `a4/runs/iv_pos_8/d1c/D1C_SUBSECTION.md` §5.1 + Finding C; `a4/runs/iv_pos_8/d1c/d1c_signal_shortlist.md` §5.1; D1.C commit `3a8487c`.

---

## NFP-10: Hook 3 `addr` vs `byte_addr` field-priority bug — production CGC memory regions mis-labeled across all V1-V5 + D1.A; post-hoc replay corrects R2/D1.A; cloud2 forward runs fixed

**Decision:** Patch `_coerce_broken_addr` in `a4/standalone/compressed_global_extractor.py:216` to prefer the `byte_addr` field over `addr` when both are present in a Hook 3 broken-address dict. Issue affects production CGC memory key labeling across every R2 V1-V5 run, every D1.A decay run, and (until patched) D2.* runs. Post-hoc replay from preserved `hook3_raw` table reconstructs corrected memory CGC metrics without re-dispatching campaigns.

**Discovery context:** D1.B Batch 1 audit (2026-06-17) found that stored production CGC memory keys had `address_region ∈ {user, zero_page}` only across all 30 audited DBs, despite parallel `global_failures` rows showing rich geography (`user_regs ≈ 34%`, `kernel ≈ 11%`, `machine_regs ≈ 6%`, etc.) on the same DBs. Composer root-cause analysis traced this to field priority in `_coerce_broken_addr`. Opus independently verified the bug + impact with SQL replay on three DBs (V5 s1234, V1 s1234, D1.A decayexp s1234).

**The bug:**

| Field | What Hook 3 emits | What it means | Correct use |
|---|---|---|---|
| `addr` | `uint32_t addr` from `A4MemoryRecord` struct (`ffi.cpp:113`) | **Circuit word address** — index into the witness memory addressing scheme (e.g., `USER_REG_BASE = 0x3FFFC020` for registers) | Hook 3 residue math hash (`ffi.cpp:553-556`) — correct |
| `byte_addr` | `(uint64_t)addr * 4` computed at `ffi.cpp:590` | **32-bit VM byte address** in guest address space (used by D8 region map, ELF layout) | D8 `address_region()`, `address_bucket = log2(byte_addr)`, ELF `page_class` — correct |

**Invariant verified:** `byte_addr == addr * 4` for 13670/13670 memory dicts on V5 s1234 (zero exceptions). Same invariant holds on V1 s1234 (11376/11376) and D1.A decayexp s1234 (14650/14650).

**Bug:** `_coerce_broken_addr` checks fields in order `("addr", "byte_addr", "address")` and returns the first present value. Hook 3 emits both `addr` and `byte_addr` in every dict, so production extractor always took `addr`. Applying `address_region()` (defined on byte addresses per `platform.rs`) to a word address mis-classifies any address whose word-vs-byte VM bands differ.

**Quantified impact (verified by Opus independent SQL 2026-06-17):**

| DB | Memory rows | Region mismatch (addr-region ≠ byte-region) | Above 4G (D42 territory) | Stored CGC memory regions | True regions via byte_addr |
|---|---|---|---|---|---|
| V5 s1234 | 13670 | 58.9% | 0.64% | `{user: 52, zero_page: 37}` | `{user, user_regs, kernel, machine_regs, machine_special, ecall_dispatch, user_bigint, zero_page, invalid}` — 9 regions |
| V1 s1234 | 11376 | 53.2% | 0.47% | `{user: 36, zero_page: 33}` | Same 9 regions (different counts) |
| D1.A decayexp s1234 | 14650 | 55.7% | 0.33% | `{user: 52, zero_page: 43}` | Same 9 regions + `trap_dispatch_and_beyond` |

**Important — what is NOT affected:**

- **Lookup families (`cycle`, u8, u16):** UNAFFECTED. They route through `_coerce_broken_index` (different function, different fields `index`/`idx`/`lookup_index`). Stored lookup CGC counts are correct.
- **Local channel / `local_context_final` / `local_coverage_v2` / `coverage`:** UNAFFECTED. Local rewards come from constraint_loc strings, not addresses.
- **Arms / scheduler / `bandit_decisions`:** UNAFFECTED. Arm targeting doesn't use this extractor.
- **`f_new` / family novelty:** UNAFFECTED. Family-level novelty is per-family, not per-address.
- **Hook 3 residue math itself:** Correct. The C++ correctly uses `addr` (word-aligned) for the permutation hash; the bug is only in the *downstream Python extractor's labeling of broken addresses for CGC key construction*.

**What IS affected:**

- Memory CGC `ctx_json.address_region` for every key in every R2 V1-V5 + D1.A `compressed_global_coverage` table
- Memory CGC `ctx_json.address_bucket` for the same keys (`address_bucket` is computed from the same coerced address; under the bug it's `log2(word_addr)` instead of `log2(byte_addr) = log2(word_addr) + 2`; bucket *labels* shift by -2 but distinct *count* is approximately preserved)
- Per-mutation `g_new` and the bandit `bandit_success` bit (since both depend on the corrected first-hit map). Replay on V1/V5 seeds (Composer) shows +13-20% more total CGC keys with `byte_addr`, modest impact on `bandit_success` bit-rate.

**Impact on Pro's prior R2 conclusions:**

| Claim made to Pro | Status after fix |
|---|---|
| D8 `user` band is huge (~3 GiB), code/heap/stack collapse | **Still true** — D8 design unchanged |
| `address_bucket` (log2) is the dominant discriminator within `user` | **Partially true** — `txn_role` and `cycle_phase` also contribute; the `user` band collapse was made WORSE by the bug folding `user_regs/kernel` traffic into `user` |
| V5 mean CGC ≈ 188; V1 mean CGC ≈ 144; V5 > V1 by ~30% | **Direction preserved**; absolute counts understated. Replay on V1/V5 seeds shows +13-20% more total keys; V5 > V1 holds |
| Memory channel under the proposed D1.B coarsenings (`region_only`, `log4`) is "dead" with no variance | **Partially true** — those coarsenings still collapse heavily, but with `byte_addr` the post-hoc region_only count goes from 2 to 9 distinct labels (memory subset) and log4_explicit gets more headroom. Memory was ALSO masked by the bug, not just by the coarsening choice |
| Pro's recommended `page_class` is necessary to add semantics inside `user` | **Still true** — even after fix, the `user` band remains the bulk of guest RAM traffic and lacks ELF-level structure. `page_class` is complementary to a correct `address_region`, not redundant |

**Why post-hoc replay (not re-dispatch) is sufficient:**

- `hook3_raw` table preserves the **raw Hook 3 payload per mutation** for all R2 + D1.A DBs (~6000 rows per DB). Replay reconstructs the corrected `compressed_global_coverage` deterministically.
- Local channel + AUC + `local_context_final` results are unaffected (different code paths), so frozen D1.A subsection conclusions stand.
- Bandit trajectory under corrected reward would be technically different — but only marginally, because most pulls trip `bandit_success` via `l_new` or `s_new` regardless of memory-CGC labeling. Exact-trajectory questions are forward-run questions (D1.E).
- Re-dispatching 50 jobs × 6000 mutations would cost ~5-7 hours POS compute for ~10% additional rigor; not warranted before Pro disclosure.

**Forward-run policy:**

- **All cloud2 IV.POS.8 forward runs use the patched extractor.** No old-extractor runs after Batch 1.6 lands.
- D1.E forward runs (decay variants re-run after L0+L1) will use the patched extractor natively. No special handling needed.
- D2.B production CGC integration uses patched extractor by default.

**What Pro should know:**

1. The R2 V1-V5 numbers we sent in `PROG_REPORT_2` and the brief are **directionally correct** (V5 > V1 holds, AUC trends preserved) but **memory-CGC absolute counts are understated by ~10-20% and per-region distributions are wrong** (everything mis-labeled as `user` or `zero_page`). We will append corrected post-hoc tables to D1.B Pro-facing subsection.
2. Pro's `page_class` recommendation in `ProG_Report_3.md` §11 remains valid. Fixing `address_region` does NOT make `page_class` redundant — `page_class` refines guest-binary semantics INSIDE `user` (where D8 is deliberately coarse), while corrected `address_region` recovers the 9-region D8 diversity LOST to the bug. They are complementary axes.
3. The `user` band's intentional coarseness is preserved by design — D8 doesn't split guest RAM by code/heap/stack at the VM-region level. `page_class` from ELF is still the right tool for that.
4. **Ask:** Pro confirms (a) `byte_addr` is the correct field for VM-region and page-class labeling (we believe yes based on D8 + ELF semantics + the explicit `ffi.cpp` calculation), and (b) post-hoc replay is acceptable for D1.B / R2 corrected metrics (re-dispatch only warranted if Pro wants legally-clean bandit trajectory under corrected reward).

**Source:** `IV_POS_8_D1_B_SPEC.md` v0.4 §3.2.5 (Batch 1.6); `D1B_BATCH1_REPORT.md` §7 (Batch 1.6 amendment, to be drafted by Composer); `compressed_global_extractor.py:216` (the fix); `coverage_db.py:162-173` (corrected comment already landed); `ffi.cpp:113, 553-556, 590-593` (C++ ground truth); this `NFP-10` entry.

---

## NFP-11: D2.B dead/live A4-kind split — 3 live + 5 dead arms on sha2-host

**Decision:** Of the **8 A4 mutation kinds Pro requested** for D2.B expansion, attestation on sha2-host (user-instruction cycles, `--in1 5 --in4 10`) shows **3 are live bandit signals** and **5 are dead arms** (trace mutates; witness unchanged; verifier accepts).

**Live kinds (constraint rejection fires):**

| Kind | Mechanism | Hook 3 family |
|------|-----------|---------------|
| B.1 `TXN_PREV_WORD_MOD` | `getMemoryTxn` returns mutated `prevWord` → memory delta | `memory` |
| B.2 `TXN_PREV_CYCLE_MOD` | `getMemoryTxn` returns mutated `prevCycle` → memory delta | `memory` + `cycle` |
| B.8 `CYCLE_DIFF_COUNT_MOD` | `extern_getDiffCount` reads trace directly | `cycle` |

**Dead-arm kinds (telemetry-only on sha2-host):**

| Kind | Watchlist | Mechanism |
|------|-----------|-----------|
| B.3 `CYCLE_MODE_MOD` | W-17 | `set_cycle` preset overwritten by `step_Top` `exec_Reg(newMode)` |
| B.4 `TXN_ADDR_MOD` | W-18 | Witness addr = execution `addrElem`; trace `txn.addr` sanity-check only |
| B.5 `TXN_CYCLE_PHASE_MOD` | W-18 | Witness phase = execution `memCycle`; trace LSB unused |
| B.6 `CYCLE_PC_MOD` | W-17 | `set_cycle` preset overwritten by `exec_Reg(newPc)` |
| B.7 `CYCLE_STATE_MOD` | W-17 | `set_cycle` preset overwritten by `exec_Reg(newState)` |

**Why this matters for D2.G:**

- `V5_expanded={16 A4 kinds}` in registry includes all 8 Pro-requested kinds, but **campaign-effective live set on sha2-host is ~11 kinds** (3 txn/cycle live + 8 pre-existing live − 5 dead among the 8 new).
- Dead arms remain implemented + attested (xfail) for continuous verification; **D2.B-PS-1 postscript** (post-Batch-4) removes them from `MUTATION_KINDS` so bandit does not waste pulls.
- This is **not a soundness bug (W-16)** — proofs attest original execution; witness columns were not corrupted.

**Mechanistic proof:**

- **Self-contained narrative for Pro:** [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](./IV_POS_8_D2_B_MECHANISM_REPORT.md) — full source-level explanation of W-17, W-18, the 4-channel rejection model, and an inventory of remaining un-mutated preflight fields with plausible-live candidates for the next mutation-studies batch.
- W-17: [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH2_DEAD_ARM_AUDIT.md)
- W-18: [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)

**Qualification:** Dead-arm claims scoped to **sha2-host user-instruction memory txns** unless noted. Paging/ECALL cycle classes may differ (same qualification as B.3 paging caveat in Batch 2 audit).

**Source:** [`D2B_BATCH3_COMPOSER_REPORT.md`](./composer/D2B_BATCH3_COMPOSER_REPORT.md); [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) v0.13 §6d, W-17, W-18; this `NFP-11` entry.

---

*Pro: this doc grows as decisions are made. Each entry links back to the spec where the decision is implemented and tested. Ask Opus to add an entry when you see an architectural choice you want surfaced at D2.G review.*
