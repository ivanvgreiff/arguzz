# D2.D Phase 3 — B1–B3 Composer Report

**Branch:** `cloud2`  
**Spec:** [`IV_POS_8_D2_D_SPEC.md`](../IV_POS_8_D2_D_SPEC.md) v1.0 LOCKED  
**Date:** 2026-06-20  
**HEAD:** `7182237` (+ D2.C + Phase 2 + D2.D uncommitted)  
**Status:** B1–B3 complete — **not committed**

---

## 0. Critical review — disposition

| Spec claim | Verdict | Pushback? |
|---|---|---|
| CLI gap is only `--selector` choices | **Agree** — verified `cli.py:205-218`; `A4Fuzzer` already handles both strategies | None |
| POS path works once CLI accepts selectors | **Agree** — `run_campaign_pos.sh` else-branch passes strategy through | None |
| L1 wiring at both reward sites (Arguzz + A4) | **Agree** — `_run_arguzz_cts_mutation` ~1221, A4 cTS path ~1422 | None |
| Observe-only: `success=` unchanged | **Agree** — inactivity proof passes (decisions + update bits identical L1 on/off) | None |
| D1.E substrate split (F14) | **Agree** — built logging only; no activation, no saturation guard | None |
| 3 batches vs New_Master 2 | **Agree with Opus split** — L1 has distinct V5-safety surface | None |
| Cross-check vs `bug_proximity.py` import | **Flag ISS-DD-1** — module uses relative imports; test uses inline reference predicates instead | Minor — see §6 |

**Blockers:** none. Implemented all three batches.

---

## 1. Pre-flight

```text
Baseline (spec):     757 passed / 27 skipped
Post D2.D sweep:     780 passed / 27 skipped (+23 new; +1 gated real-binary skipped without A4_REAL_BINARY)
V5 Tier-1 + Tier-2:  PASSED (byte-identical)
Tier-2 snapshot:     mutations/failures/coverage only — reward_counterfactuals NOT in byte-identity gate
```

---

## 2. Batch 1 — Variant dispatch

### 2.1 `cli.py`

Added `v6_cTS` and `hybrid_cTS` to `fuzz --selector` choices + help text.

### 2.2 `variants.py` (NEW)

- `VariantSpec` + `CANONICAL_VARIANTS` for all 4 checkpoint variants
- `resolve_variant()` / `variant_launch_command()` reference helpers
- Descriptive only — no parallel execution path

### 2.3 Manifest stub

`a4/pos/manifests/iv_pos_8/d2d_checkpoint_smoke.json` — 4 jobs (cTS_semantic_v2 fresh-equiv, v6_uniform, v6_cTS, hybrid_cTS), N=10 each. POS execution is D2.F.

### 2.4 Tests

`test_d2d_variant_dispatch.py` — registry parity vs live `A4Fuzzer` config, CLI acceptance.

---

## 3. Batch 2 — Per-variant validation

`test_d2d_variant_smoke.py`:

| Test | Result |
|---|---|
| `v6_cTS` pulls only Arguzz kinds | PASS |
| `hybrid_cTS` pulls Arguzz SELECTED + A4 kinds | PASS |
| F9 applied-accounting (`v6_cTS`, APPLIED/SKIPPED mix) | PASS — pulls advance only on APPLIED |

No additional production code beyond B1.

---

## 4. Batch 3 — Inactive L1 logging

### 4.1 `l1_signals.py` (NEW)

Ported predicates from `bug_proximity.py`:
- `d_loc_le_2`, `singleton_failure`, `substrategy_uniqueness`
- `composite_substrategy_key`, `KIND_TO_SUBSTRATEGY_FIELDS`
- `INSTR_TYPE_MOD` excluded from substrategy signal
- `bandit_success_l1_counterfactual(base, flags)`

### 4.2 `coverage_db.py`

`reward_counterfactuals` +4 nullable columns via `ALTER TABLE`:
- `bandit_success_l1`, `l1_substrategy_uniqueness`, `l1_d_loc_le_2`, `l1_singleton_failure`

`record_reward_counterfactuals(...)` extended with optional kwargs (default NULL = back-compat).

### 4.3 `telemetry_v2.py`

`record_full_telemetry(..., l1_logging=False, **l1_cols)` forwards L1 columns when `l1_logging=True`.

### 4.4 `fuzzer.py`

- `self.l1_logging = True` (default); `self._l1_substrategy_seen` reset per campaign
- `_compute_l1_payload()` — observe-only; gated to `ALL_SEMANTIC_CTS_STRATEGIES`
- Wired at Arguzz reward site (~1221) and A4 cTS site (~1422)
- **`update_with_outcome(..., success=bandit_success)` UNCHANGED** (base bit)
- `discovery_binary_reward` unchanged (still base `compute_bandit_success`)

### 4.5 Tests

`test_d2d_l1_logging.py`:
- Extractor unit tests + reference-definition cross-check
- Schema migration (NULL on legacy rows)
- **Inactivity proof:** decisions + update success bits identical L1 on vs off
- L1 columns populated when logging on + telemetry full

`test_d2d_cli_v6_cts_real_binary.py` — Layer-5 gated (`A4_REAL_BINARY=1`, N=5).

---

## 5. Sweep results

```text
780 passed, 27 skipped, 8 warnings in ~893s
Delta vs Phase-2-complete: +23 tests
```

V5 golden traces: byte-identical. Phase 2 Bernoulli tests: green. `test_reward_v2.py`: green.

---

## 6. Flags / ISS annex

| ID | Issue | Severity | Resolution |
|---|---|---|---|
| **ISS-DD-1** | `bug_proximity.py` cannot be imported as standalone module (relative `.metrics` import). Layer-1 cross-check uses inline reference predicates matching ported definitions. | Low | Acceptable; production uses `l1_signals.py` only. D2.G offline analysis still uses `bug_proximity.py` in package context. |
| **F14** | D1.E must reuse D2.D substrate for activation — not implemented here (by design). | Info | Flagged for D1 pair per spec §3.4.1. |

---

## 7. Files touched

| File | Change |
|---|---|
| `a4/standalone/cli.py` | B1 — selector choices |
| `a4/standalone/variants.py` | B1 — NEW registry |
| `a4/standalone/l1_signals.py` | B3 — NEW extractors |
| `a4/standalone/fuzzer.py` | B3 — L1 observe-only wiring |
| `a4/standalone/telemetry_v2.py` | B3 — L1 column forwarding |
| `a4/standalone/coverage_db.py` | B3 — schema + record API |
| `a4/pos/manifests/iv_pos_8/d2d_checkpoint_smoke.json` | B1 — NEW |
| `test_d2d_variant_dispatch.py` | B1 — NEW |
| `test_d2d_variant_smoke.py` | B2 — NEW |
| `test_d2d_l1_logging.py` | B3 — NEW |
| `test_d2d_cli_v6_cts_real_binary.py` | B3 — NEW (gated) |
| `IV_POS_8_D2_D_SPEC.md` | §9 + §13 |
| `New_Master.md` | D2.D → DONE |

**Frozen (untouched):** `bandit_ts.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `arguzz_bridge.py`, `v6_driver_v2.py`, `semantic_zones.py`, `workspace/risc0-modified/`. (`v6_uniform_driver.py` untouched — registry references it only.)

---

## 8. What this unblocks

- **D2.E** integration tests
- **D2.F** POS 4-variant checkpoint dispatch (manifest stub ready)
- **D2.G** can re-audit L1 channels from logged columns on V6/Hybrid fresh runs

---

## 9. Acceptance checklist

All spec §9 items green (see spec for detail).

---

*End of D2.D B1–B3 report.*
