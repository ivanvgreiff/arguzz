# D2 Phase 2 (Bernoulli Floor) — B1 Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md`](../IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md) v1.0 LOCKED  
**Date:** 2026-06-20  
**HEAD:** `7182237c8245e7a5d7c1309d3f38671c25f4934e` (+ D2.C + Bernoulli B1 uncommitted)  
**Status:** B1 complete — **not committed**

---

## 0. Critical review — disposition

| Spec claim | Verdict | Pushback? |
|---|---|---|
| Single tier-3 fork only; tiers 1/2/4 unchanged | **Agree** — verified `select()` at `bandit_ts.py:215-252`; edit is scoped to the else-branch after singleton drain. | None |
| `bernoulli_floor` flag orthogonal to `FloorSchedule` | **Agree** — same `floor_schedule.current(...)` source; only consumption mode differs. | None |
| Gate = `ARGUZZ_CTS_STRATEGIES` only | **Agree** — matches `fuzzer.py:143`; decay variants stay on integer quota. | None |
| V5 byte-identity is existential gate | **Agree** — legacy branch duplicated (not refactored) to avoid RNG drift. | None |
| ~25 LOC production footprint | **Agree** — actual: ~28 LOC in `bandit_ts.py`, ~6 in `fuzzer.py`. | None |
| No POS job needed | **Agree** — pure scheduler logic; real-binary validation deferred to Phase 3. | None |
| PI-5: ships ConstantFloor(0.55), not decay | **Acknowledged** — documented; not a blocker. Immediate V6-cTS/Hybrid behavior = ~55% floor share (vs quota's coarser realized share). | None (clarity only) |
| Optional legacy "≤3 regimes" contrast test | **Soft pushback** — with ~15-arm test universe, legacy quota still yields 4 distinct rounded shares `{0.21,0.35,0.56,0.84}`. Replaced optional contrast with a positive Bernoulli discrimination test (p=0.20 vs p=0.35 differ by ≥0.08 and track nominal). Headline linearity tests are the proof Finding D is fixed. | Minor — spec marked contrast optional |

**Blockers:** none. Proceeded with implementation.

---

## 1. Pre-flight (recorded)

```text
V5 golden traces (before edit):  3 passed
Full sweep (after B1):           757 passed, 27 skipped, 8 warnings in 515.8s
Spec baseline cited:             729 passed (D2.C lock); tree had grown to 745 before B1 (+12 new)
```

Pre-flight checks:
- Construction site: `fuzzer.py:816` `ConstrainedTSScheduler(...)`
- Family gate: `ARGUZZ_CTS_STRATEGIES = frozenset({"v6_cTS", "hybrid_cTS"})`
- Tier-2 byte-identity snapshot: **does not** include `campaign_params` (only `mutations`, `failures`, `coverage`) → safe to add `bernoulli_floor` to `extra_json` for Arguzz strategies only.

---

## 2. Production changes

### 2.1 `a4/standalone/bandit_ts.py`

**Added** `bernoulli_floor: bool = False` to `ConstrainedTSScheduler.__init__` (default OFF).

**Modified** tier-3 in `select()`:

| Path | Trigger | RNG |
|---|---|---|
| `bernoulli_floor=True` | `rng.random() < floor_schedule.current(...)` | `random()` then optional `betavariate` × n |
| `bernoulli_floor=False` (V5) | integer quota `epoch_pulls < target` | unchanged — no `random()` before `_sample_thetas` |

Floor pick when Bernoulli says "floor": `min(self.arms, key=epoch_pulls)` — same as legacy.

Adaptive block **duplicated** in Bernoulli branch (not factored) per spec §2.2 note — preserves V5 byte-identical legacy path.

### 2.2 `a4/standalone/fuzzer.py`

**Construction site** (`_setup_v2_bandit`):

```python
bernoulli_floor=(self.selector_strategy in ARGUZZ_CTS_STRATEGIES),
```

**Provenance** (`_persist_campaign_params`): append `"bernoulli_floor": True` to `extra_json` **only** for Arguzz cTS strategies (V5 blob unchanged).

---

## 3. Tests added

### 3.1 Layer-1 — `test_d2_bernoulli_floor.py` (11 tests + 3 parametrized = 12 collected)

| Test | Asserts |
|---|---|
| `test_realized_floor_share_matches_constant_p` ×4 | p ∈ {0.20,0.35,0.55,0.80}, N=4000, share within ±0.03 |
| `test_bernoulli_distinguishes_nominal_p_legacy_does_not_track` | p=0.20 vs 0.35 separated by ≥0.08, each within ±0.03 of nominal |
| `test_epoch_stage_floor_windows` | EpochStageFloor windows ≈ 0.55 / 0.35 / 0.20 |
| `test_hard_guarantees_before_floor_adaptive` | cold + singleton quotas honored |
| `test_all_floor_spreads_epoch_pulls_evenly` | frac=1.0 → min/max epoch_pulls differ ≤1 per epoch |
| `test_skipped_pulls_do_not_advance_floor_clock` | applied_accounting_mode; SKIPPED don't skew share |
| `test_same_seed_same_trace` | determinism |
| `test_v6_cts_enables_bernoulli_hybrid_does_too` | fuzzer wiring: v6_cTS/hybrid=True, cTS_semantic_v2=False |

### 3.2 Layer-2 — `test_d2_bernoulli_floor_golden_trace.py`

Fixture: `fixtures/d2_bernoulli_v6_cts_decision_seq_seed777_n200.json`  
Config: `bernoulli_floor=True`, `ConstantFloor(0.55)`, seed=777, N=200, `_small_universe()`.  
Modes seen: `{cold, singleton, floor, adaptive}`.

### 3.3 Layer-3 — V5 unchanged (existing gates)

```text
test_d2c_golden_trace_v5_decision_seq.py     — PASSED (byte-identical)
test_d2c_golden_trace_v5_db_byte_identity.py — PASSED (byte-identical)
test_d2a_back_compat_golden_trace.py         — PASSED
test_bandit_ts.py                            — PASSED
test_floor_schedule.py                       — PASSED
```

---

## 4. Sweep results

```text
757 passed, 27 skipped, 8 warnings in 515.80s
Delta vs pre-B1 tree: +12 tests (745 → 757)
```

No regressions. V5 golden traces byte-identical.

---

## 5. PI-8 follow-up (non-blocking)

`record_bandit_decision` is wired in the fuzzer's full-telemetry path (`fuzzer.py:1506`) for cTS mutations. D2.G can derive realized floor share from `bandit_decisions.mode` counts. No code change needed for Phase 2.

---

## 6. Files touched

| File | Change |
|---|---|
| `a4/standalone/bandit_ts.py` | `bernoulli_floor` param + tier-3 fork |
| `a4/standalone/fuzzer.py` | wiring + optional `extra_json` provenance |
| `a4/standalone/tests/test_d2_bernoulli_floor.py` | NEW — Layer-1 + wiring |
| `a4/standalone/tests/test_d2_bernoulli_floor_golden_trace.py` | NEW — Layer-2 |
| `a4/standalone/tests/fixtures/d2_bernoulli_v6_cts_decision_seq_seed777_n200.json` | NEW — golden fixture |
| `a4/docs/cloud2/IV_POS_8_D2_BERNOULLI_FLOOR_SPEC.md` | §8 checklist + §12 changelog |
| `a4/docs/cloud2/New_Master.md` | Phase-2 row → DONE |
| `a4/docs/cloud2/composer/D2_BERNOULLI_FLOOR_B1_COMPOSER_REPORT.md` | this file |

**Frozen (untouched):** `bandit.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `arguzz_bridge.py`, `v6_uniform_driver.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`, `workspace/risc0-modified/`.

---

## 7. Acceptance checklist (spec §8)

- [x] All items green (see spec §8 for detail).

---

## 8. What this unblocks

Phase 3 checkpoint campaigns (`V5_control / V6_uniform / V6_cTS / Hybrid_cTS`) may proceed once D2.D variant CLI wiring lands. Bernoulli floor is live for `v6_cTS` and `hybrid_cTS` at `ConstantFloor(0.55)`.

---

*End of D2 Bernoulli Floor B1 report.*
