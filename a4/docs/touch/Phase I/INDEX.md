# Touch Coverage Documentation Index

This folder (`a4/docs/touch/`) contains all planning and implementation documents for **Phase I: Constraint-Failure-Guided Coverage**. Phase I consists of **Phase 0** (Baseline + Observability) and **Phase 3** (Touch Coverage v2 / Per-Constraint Touched). Phase 1 (touch v1 via easy selectors) and Phase 2 (coverage-guided scheduling) from the original roadmap were skipped or deferred; Phase I goes directly from stable IDs and baseline (Phase 0) to per-constraint touch instrumentation (Phase 3).

**Naming clarification**: "Phase I" (Roman numeral) is the umbrella that encompasses sub-phases 0.1, 0.2, 3.1, 3.2, 3.3, and 3.4 (Arabic numerals). Phase II (scheduling, corpus, bandits) follows separately and is not yet planned in detail.

---

## Conceptual Foundation

| File | Contents |
|------|----------|
| [Pro_Report_1.md](./Pro_Report_1.md) | Original prompt and external expert report defining the constraint-coverage concept: 3-level coverage model (family/context/instance), "violated" vs "touched" coverage, AFL-style bitmap design, mutation guidance via bandits and rarity weighting, coherence scoring. |
| [Pro_Report_2.md](./Pro_Report_2.md) | Follow-up Q&A: selectors in the DATA matrix, lanes, step_bucket, residuals, bitmap data structure trade-offs, coherence score details, multi-phase roadmap (Phases 0–7), and additional ideas (witness-delta analysis, mutation-constraint influence graph, degenerate-case features). |

---

## High-Level Plan

| File | Contents |
|------|----------|
| [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) | Master plan for all of Phase I. Defines: bucket necessity analysis (§0.1), touch accuracy / EQZ-is-active proof (§0.2), source-of-truth facts (§1), Phase 0 deliverables (§2), Phase 3 design (§3: semantics, C++ storage/emission, Python parsing/merge, executor/fuzzer integration, constants), implementation order (§4), files to touch (§5), what Phase I does not include (§6). |

---

## Phase 0: Baseline + Observability

### Phase 0.1 — Stable IDs, Determinism Test (Python only)

| File | Contents |
|------|----------|
| [PHASE_0_1_IMPLEMENTATION_PLAN.md](./PHASE_0_1_IMPLEMENTATION_PLAN.md) | Step-by-step plan: canonical ID documentation (Step 0.1.1), `context_id()` and `context_id_with_step_bucket()` (Step 0.1.2), determinism test (Step 0.1.3), touch-accuracy note (Step 0.1.4), no-regressions check (Step 0.1.5). |
| [PHASE_0_1_IMPLEMENTATION_REPORT.md](./PHASE_0_1_IMPLEMENTATION_REPORT.md) | Implementation results: all steps completed, determinism confirmed, key variables (`context_id`, `signature`, `constraint_loc`), deviations, insights for Phase 0.2. |

### Phase 0.2 — Baseline Run, Key-Space Measurement (Python only)

| File | Contents |
|------|----------|
| [PHASE_0_2_IMPLEMENTATION_PLAN.md](./PHASE_0_2_IMPLEMENTATION_PLAN.md) | Step-by-step plan: re-run determinism test (Step 0.2.1), baseline run with zero failures (Step 0.2.2), short campaign + distinct `context_id` measurement (Step 0.2.3), optional minimal-program check (Step 0.2.4), optional baseline touch note (Step 0.2.5). |
| [PHASE_0_2_IMPLEMENTATION_REPORT.md](./PHASE_0_2_IMPLEMENTATION_REPORT.md) | Implementation results: determinism passed, baseline zero-failures confirmed, K_total=43 (failure data), per-run max=9, step_bucket not required for MAP_SIZE=65536, `run_baseline` and DB helpers added. |

---

## Phase 3: Touch Coverage v2 (Per-Constraint Touched)

### Phase 3.1 — C++ Touch Accumulator (C++ only, no emission)

| File | Contents |
|------|----------|
| [PHASE_3_1_IMPLEMENTATION_PLAN.md](./PHASE_3_1_IMPLEMENTATION_PLAN.md) | Step-by-step plan: bitmap and constants in `ffi.cpp` (Step 3.1.1), FNV-1a hash and `a4_touch_mark` (Step 3.1.2), declaration and call from `eqz` Val overload (Step 3.1.3), clear + debug print in SeqForward (Step 3.1.4), build and verify (Step 3.1.5). Also: Phase 0 takeaways table, Val vs ExtVal analysis, env/stdio header avoidance rationale. |
| [PHASE_3_1_IMPLEMENTATION_REPORT.md](./PHASE_3_1_IMPLEMENTATION_REPORT.md) | Implementation results: all steps completed, C++ compiles, key variables (`kA4TouchMapSize`, `g_a4_touch_bitmap`, `a4_touch_hash`, `a4_touch_mark`), deviations, insights for Phase 3.2. |

### Phase 3.2 — C++ Emission + Python Parser + Executor Wiring (C++ + Python)

| File | Contents |
|------|----------|
| [PHASE_3_2_IMPLEMENTATION_PLAN.md](./PHASE_3_2_IMPLEMENTATION_PLAN.md) | Step-by-step plan: C++ base64 encoder and `<a4_touch_coverage>` emission (Step 3.2.1), Python `touch_coverage.py` module (Step 3.2.2), executor sets `A4_COVERAGE_TOUCH=1` + `touch_bitmap` field (Step 3.2.3), unit tests (Step 3.2.4), integration verification (Step 3.2.5). Also: encoding choice rationale (base64), "For Anyone New" explainer. |
| [PHASE_3_2_IMPLEMENTATION_REPORT.md](./PHASE_3_2_IMPLEMENTATION_REPORT.md) | Implementation results: all steps completed, 16 unit tests pass, integration verified (1599 distinct buckets, 192676 total touches, ~2.4% occupancy), key variables (`a4_base64_encode`, `parse_touch_bitmap`, `count_new_bits`, `merge_into_global`), insights for Phase 3.3. |

### Phase 3.3 — Fuzzer Integration (Python fuzzer only)

| File | Contents |
|------|----------|
| [PHASE_3_3_IMPLEMENTATION_PLAN.md](./PHASE_3_3_IMPLEMENTATION_PLAN.md) | Step-by-step plan: `MutationResult.new_touch` (Step 3.3.1), `CampaignStats` touch fields (Step 3.3.2), global bitmap init (Step 3.3.3), per-mutation compute/merge (Step 3.3.4), stats accumulation (Step 3.3.5), per-mutation print (Step 3.3.6), campaign summary (Step 3.3.7), optional combined selector reward (Step 3.3.8), optional bitmap persistence (Step 3.3.9). |
| [PHASE_3_3_IMPLEMENTATION_REPORT.md](./PHASE_3_3_IMPLEMENTATION_REPORT.md) | Implementation results: 7 required + 1 optional step completed, 5-mutation campaign verified (touch saturates after first run at 1599 buckets), touch saturation analysis, key variables (`new_touch`, `global_touch_bitmap`, `new_touch_count`, `total_distinct_touched`), insights for Phase 3.4. |

### Phase 3.4 — Documentation + Touch Determinism Test (Final Phase I)

| File | Contents |
|------|----------|
| [PHASE_3_4_IMPLEMENTATION_PLAN.md](./PHASE_3_4_IMPLEMENTATION_PLAN.md) | Step-by-step plan: touch determinism test (Step 3.4.1), README update (Step 3.4.2), centralized constants reference (Step 3.4.3), optional FNV-1a in Python (Step 3.4.4), run all tests (Step 3.4.5). Also: Phase I completion summary. |
| [PHASE_3_4_IMPLEMENTATION_REPORT.md](./PHASE_3_4_IMPLEMENTATION_REPORT.md) | Final Phase I report: all steps completed, 3 determinism tests + 16 unit tests pass, **centralized touch coverage reference (§7)** with all constants/hash/encoding/occupancy in one place, Phase I completion summary, insights for Phase II. |

---

## Quick Reference: Where to Find What

| If you need... | Read... |
|----------------|---------|
| The overall design and rationale | [PHASE_I_IMPLEMENTATION_PLAN.md](./PHASE_I_IMPLEMENTATION_PLAN.md) |
| All constants (MAP_SIZE, hash, encoding, occupancy) in one place | [PHASE_3_4_IMPLEMENTATION_REPORT.md §7](./PHASE_3_4_IMPLEMENTATION_REPORT.md) |
| How the C++ bitmap and hash work | [PHASE_3_1_IMPLEMENTATION_REPORT.md §4](./PHASE_3_1_IMPLEMENTATION_REPORT.md) |
| How the C++↔Python bridge works (emission + parsing) | [PHASE_3_2_IMPLEMENTATION_REPORT.md](./PHASE_3_2_IMPLEMENTATION_REPORT.md) |
| How the fuzzer uses touch coverage | [PHASE_3_3_IMPLEMENTATION_REPORT.md](./PHASE_3_3_IMPLEMENTATION_REPORT.md) |
| What "touched" means and why EQZ = active | [PHASE_I_IMPLEMENTATION_PLAN.md §0.2](./PHASE_I_IMPLEMENTATION_PLAN.md) |
| The original conceptual framework (external expert reports) | [Pro_Report_1.md](./Pro_Report_1.md) and [Pro_Report_2.md](./Pro_Report_2.md) |
| What Phase II needs to build next | [PHASE_3_4_IMPLEMENTATION_REPORT.md §8–§9](./PHASE_3_4_IMPLEMENTATION_REPORT.md) |
