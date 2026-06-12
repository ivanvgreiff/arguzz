# Phase 7d — Increment 2 Report

## Summary

All 6 local audits PASS or DONE (informational). Variant infrastructure (bandit math, reward routing, coverage delta, DB schema, compressed-global pipeline, per-arm bite) verified on fresh `seed=999` smokes.

| Audit | Status |
|---|---|
| B3 bandit property tests | **PASS** — 12/12 properties green |
| B5 reward formula routing | **PASS** — unit + 5-variant DB smoke |
| B6 coverage-delta correctness | **PASS** — 20/20 mutations match |
| B9 DB schema integrity | **PASS** — 5/5 variants |
| B10 compressed-global e2e | **PASS** — DB + round-trip |
| E2 arm bite (informational) | **DONE** — 48/48 arms, 0 zero-bite |
| Fast tests | **PASS** — 472 passed (≥460 gate) |

## Acceptance gate results

| Gate | Status | Numbers |
|---|---|---|
| B3 | **PASS** | 12 property tests (3 scheduler classes × 4 properties) |
| B5 | **PASS** | 5/5 variants: unit tests + correct DB column population |
| B6 | **PASS** | 20/20 `l_new/f_new/g_new/s_new` match independent recompute |
| B9 | **PASS** | 5/5 DBs: tables, schemas, FKs, `n_mutations=10` |
| B10 | **PASS** | 21 compressed_global rows; 2+ regions; round-trip 4/4 |
| E2 | **DONE** | 48 arms × ≤5 muts; 0 zero-bite; no E4 soft flags |
| Fast tests | **PASS** | 472 passed, 7 skipped |

## Per-audit findings

### B3 — Bandit math

- `test_bandit_property.py` uses 200-trial hand-rolled loops (no hypothesis dep).
- `KindLevelUCBScheduler` formula tested against implementation: `mean + c·√(ln(t+1)/n)` with `c=0.25` (not canonical UCB1 `√2` — matches code, not textbook UCB1).

### B5 — Reward routing

- V1 (`zoned`): `mutation_rewards` + `reward_counterfactuals` both populated (full telemetry).
- V2 (`kindUCB_zoned_v1`): legacy `mutation_rewards.reward` for UCB update.
- V3/V4/V5: `reward_counterfactuals.current_reward` (= v2 additive) populated.
- V4/V5 bandit updates use Bernoulli `compute_bandit_success` per D32 (not tested in B5 DB layer; covered by B3 + fuzzer code path).

### B6 — Coverage delta

- Guarded `--debug-coverage-delta` flag added to `fuzzer.py` / `cli.py` (default OFF).
- JSONL side-channel captures `seen_*_before` + failures + Hook3 payload for independent recompute.
- First run hit `StructuralCell` serialization bug (fixed); second run 16/20 (g_new DB round-trip); third run **20/20 PASS**.
- Smoke DB retained at `audit_output/inc2_smokes/b6_v5.db` for B10 reuse.

### B9 — Schema

- Canonical schema extracted from fresh `CoverageDB._init_schema()` including `mutations.original_value` (Inc 0 P2).
- All 15 expected tables present; no extra columns; FK integrity on `mutation_rewards` and `bandit_decisions`.

### B10 — Compressed global

- DB check: 21 rows, 10 with `address_region` in ctx_json; regions `user`, `zero_page`.
- Round-trip: `0xFFFF0080→user_regs`, `0x42000020→user` (D8; work-order alias `host_ecall`), `0xC0000004→kernel`, `0x00203F7C→user`.

### E2 — Arm bite

- **48/48 arms** probed (5 stratified steps/arm, `seed=999`).
- **0 zero-bite arms** — every arm produced ≥1 constraint failure across sampled mutations.
- Dominant families: mostly `mem` for compute/load/store arms; richer mix (`inst`, `inst_ecall`, `u32`) at boundaries.
- No soft flags → no E4 review-queue updates required.

## E2 highlights

No arms flagged. All 48 HYBRID universe arms show bite under direct host mutation.

## Files changed

| File | Change |
|---|---|
| `a4/standalone/tests/test_bandit_property.py` | NEW — B3 |
| `a4/audits/B5_reward_formula_routing.py` | NEW |
| `a4/audits/B6_coverage_delta.py` | NEW |
| `a4/audits/B9_db_schema_integrity.py` | NEW |
| `a4/audits/B10_compressed_global_e2e.py` | NEW |
| `a4/audits/E2_arm_bite.py` | NEW |
| `a4/audits/audit_common.py` | `INC2_VARIANTS`, `run_fuzz_smoke()` |
| `a4/standalone/fuzzer.py` | guarded `--debug-coverage-delta` (B6 only) |
| `a4/standalone/cli.py` | `--debug-coverage-delta` CLI flag |
| `audit_output/B5_reward_routing.json` | generated |
| `audit_output/B6_coverage_delta.json` | generated |
| `audit_output/B9_db_schema.json` | generated |
| `audit_output/B10_compressed_global_e2e.json` | generated |
| `audit_output/E2_arm_bite.json` | generated |
| `audit_output/inc2_smokes/b6_v5.db` | B6/B10 smoke artifact |

**Not changed (per hard rules):** bandit/reward/DB-schema core logic.

## Open items / surprises

1. **E2 runtime ~2.3h** for 240 host mutations when run solo; initial parallel launch with B5/B6/B9 caused starvation (empty log for hours). Restart with `PYTHONUNBUFFERED=1` + solo host access completed cleanly.
2. **B6 first-pass failures** were audit-script recompute bugs (Hook3 DB parse, `StructuralCell` JSON, `crash`/`repeat` omitted) — not fuzzer delta bugs.
3. **Fast tests: 472** (not 460+12 from Inc 1.5) — includes new `test_bandit_property.py` (+12). Run from repo root (`pytest a4/standalone/tests/`).

## Ready-to-proceed

Inc 2 is green. Awaiting Opus review before Increment 3 (B1, B2, B4, B7 — fidelity audits with longer host runs).
