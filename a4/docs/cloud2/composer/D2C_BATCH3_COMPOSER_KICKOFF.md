# D2.C Batch 3 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) **v0.5 LOCKED** + **§15 living-issue annex** (ISS-1…ISS-7 — you own resolving ISS-6/ISS-7 and the Batch-3 halves of the rest)
**Governing plan:** [`../New_Master.md`](../New_Master.md) §2 Phase 1 · **Parent:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.16 §3
**Mechanism reference:** [`../IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md) §9 (4-channel rejection; Path A/Path B)
**Predecessors:** D2.C **Batch 1** (primitive `arguzz_invoke.py`) + **Batch 2** (bridge `arguzz_bridge.py` + `semantic_arm_universe.build(arguzz_kinds=…)`), both reviewed & greenlit — see [`D2C_BATCH1_COMPOSER_REPORT.md`](./D2C_BATCH1_COMPOSER_REPORT.md), [`D2C_BATCH2_COMPOSER_REPORT.md`](./D2C_BATCH2_COMPOSER_REPORT.md). Working-tree baseline: **654 passed, 21 skipped** (ignore-replicates path, verified 2026-06-20).
**Issued by:** Opus (planning), post-Batch-2 review
**Expected effort:** ~1.5–2 days focused work + ~0.5 day for the report. **This is the largest D2.C batch.**

---

## TL;DR for Composer

Implement **D2.C Batch 3** per `IV_POS_8_D2_C_SPEC.md` v0.5 §11 "Batch 3" (tasks 3.1 → 3.7): the **active driver + fuzzer Arguzz dispatch + D2.A schema parity**. Three code deliverables:

1. **`a4/standalone/v6_uniform_driver.py` (NEW)** — `v6_driver_v2.py` modernized: replace `run_inject` + inline tag parsers with `arguzz_invoke.run()`; replace inline SQL with `CoverageDB`; **keep `ArguzzScheduler` (balanced round-robin) and the `host --trace` bootstrap verbatim**.
2. **`a4/standalone/fuzzer.py` extension** — recognize `selector_strategy in {"v6_cTS", "hybrid_cTS"}`; capture a `baseline_trace`; build the universe with `arguzz_kinds`; add a `_dispatch_arm()` helper that routes A4 vs Arguzz arms; record Arguzz rows (with the D2.A `outcome` column); wire `applied_accounting_mode=True` for the two Arguzz strategies only (task 3.2a).
3. **Tier-2 V5 golden-trace DB byte-identity gate** (task 3.2b) — the new regression that catches downstream serialization drift the Tier-1 decision-sequence test can't see.

Plus the **Layer-5 real-binary end-to-end smoke** (gating, task 3.3), the schema-parity check (3.4), and the soundness-signal smoke (3.5).

**The two load-bearing constraints of this batch:**
- **The A4-side path must be byte-identical pre/post refactor under fixed RNG.** The **Tier-1 V5 golden trace** (`test_d2c_golden_trace_v5_decision_seq.py`, from Batch 1) AND the **new Tier-2 DB byte-identity** gate (task 3.2b) both guard this. `cTS_semantic_v2` (V5) keeps `arguzz_kinds=None` and `applied_accounting_mode=False`.
- **The D2.A `outcome` column must be populated for Arguzz rows** via `result.outcome.value`, so the bandit-signal accounting (Option C) survives into the DB.

---

## Composer: read these files first (in this order, before writing any code)

**Docs:**
1. `IV_POS_8_D2_C_SPEC.md` **v0.5** — especially **§4.4** (`fuzzer.py` dispatch extension — code shape for the strategy wiring, `_dispatch_arm`, `_record_arguzz_mutation`, soundness-signal ownership), **§4.5** (`v6_uniform_driver.py` change list), **§4.6** (two-taxonomy split — you consume both taxonomies; do NOT touch `OPCODE_CLASS_BY_MAJOR`), **§9 Q5/Q6** (LOCKED `extra_json` shape + iteration-seed scheme), **§11 Batch 3** (tasks 3.1–3.7), **§14** (acceptance), and **§15 ISS-1/ISS-3/ISS-6/ISS-7** (you resolve ISS-6/ISS-7 and consume the ISS-1/ISS-3 decisions).
2. This kickoff.
3. `IV_POS_8_D2_B_MECHANISM_REPORT.md` §9 — Path A (`prover_status="error"` + `<constraint_fail>`) vs Path B (`error` + no local tag → `failure_recording_gap`); the soundness guard. Your `_record_arguzz_mutation` derives `proof_verify_failed` from exactly this.

**Code (read at the post-Batch-2 working tree — do NOT write before reading these):**
4. `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` — **the source you refactor `v6_uniform_driver.py` from.** Copy **verbatim**: `ArguzzScheduler` (balanced round-robin), the bootstrap (lines 389–430: `host --trace` → `InspectionData` → `classify_zones`), CLI args, the `iter_seed = args.seed * 1_000_000 + i` scheme. **Replace** `run_inject`/tag parsers → `arguzz_invoke.run()` and inline SQL → `CoverageDB`. Do NOT modify this file.
5. `a4/standalone/arguzz_invoke.py` (Batch 1) + `a4/standalone/mutations/arguzz_bridge.py` (Batch 2) — `run()` returns `ArguzzInvocationResult`; `create_mutation_for_arm(arm, step, host, host_args, seed, data, *, timeout)` returns `(outcome, result, config)` with `include_trace=False` baked in. **Read-only — do not edit.**
6. `a4/standalone/fuzzer.py` — **your edit target.** Key anchors: `CTS_SEMANTIC_V2_FAMILY` (line 126), `STRATEGY_DISPLAY_NAMES` (192), `__init__` (267, `selector_strategy`), the universe build at **line 747** (`SemanticArmUniverse.build(self.data, kinds)`), `_run_v2_bandit_mutation` (**line 979** — the cTS per-mutation method; `decision = self.v2_scheduler.select()` → `kind, zone, step`), `_create_mutation(kind, step)` (line 1012, A4 path), and the DB-recording block (lines 944–958: `record_mutation`, `record_failures`, `record_global_failures`).
7. `a4/standalone/bandit_ts.py` — `BanditDecision` (line 31: `kind, zone, step, arm_id`), `ArmKey.parse` (semantic_arm_universe.py:208), `ConstrainedTSScheduler.update_with_outcome` (line 310) + `applied_accounting_mode` (146, 156). Read-only.
8. `a4/standalone/coverage_db.py` — `record_mutation(campaign_id, kind, step, mutated_value, config, txn_idx=None, verifier_accepted=False, original_value=0, *, proof_generated=None, proof_verify_failed=None, …)` (line 726), `record_failures(mutation_id, failures)` (781), `record_global_failures(mutation_id, global_contexts)` (1022), `record_compressed_global_first_hit(campaign_id, mutation_id, ctx_key, family, ctx_json)` (615). **Confirm the exact `record_mutation` kwargs — the spec assumed an `outcome=` kwarg; verify it exists or find how D2.A persists the `outcome` column (see §A below).** Read-only.
9. `a4/standalone/compressed_global_extractor.py` — `_TXN_ROLE_BY_KIND` (Batch 1 added the 6 Arguzz entries) + `extract_compressed_global_contexts(...)`. Confirm the role entries are present (you consume them). The §4.6 permanent-merge is already done — **do not re-do it**.
10. `a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py` (Tier-1, Batch 1) + `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` — the Tier-1 gate + the byte-identity pattern for the Tier-2 test you write (task 3.2b).
11. `a4/docs/cloud2/composer/D2C_BATCH2_COMPOSER_KICKOFF.md` + reports — format precedent + the inherited facts (arm space FULL=437/SELECTED=180, **Opus ruling: KEEP 437, no reduction**; ISS-1 `include_trace=False`).

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

```bash
# 1. Batch 1+2 present and green
git rev-parse HEAD && git status --short
python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py 2>&1 | tail -3
# → record the floor (working-tree baseline = 654 passed, 21 skipped). New Batch-3 tests add to this.

# 2. The Tier-1 V5 golden trace passes NOW (you must keep it byte-identical through the fuzzer refactor)
python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py -q

# 3. Confirm the real record_mutation signature + how the `outcome` column is written (ISS / §A)
grep -n 'def record_mutation' a4/standalone/coverage_db.py
grep -n 'outcome' a4/standalone/coverage_db.py | head -20
# → If record_mutation has NO `outcome=` kwarg, STOP and report how D2.A populates mutations.outcome
#   (there may be a separate setter or the column may be derived). Do NOT invent a column write.

# 4. Confirm v6_cTS / hybrid_cTS are NOT yet known strategies
grep -n 'v6_cTS\|hybrid_cTS' a4/standalone/fuzzer.py    # → no hits yet (you add them)

# 5. applied_accounting_mode is NOT wired in fuzzer today (Batch 3 task 3.2a wires it)
grep -n 'applied_accounting_mode' a4/standalone/fuzzer.py   # → no hits

# 6. ArmKey round-trips via parse (ISS-6 mechanism)
python -c "from a4.standalone.semantic_arm_universe import ArmKey, ARGUZZ_EXEC_FAULT; a=ArmKey(ARGUZZ_EXEC_FAULT,'INSTR_WORD_MOD','core_arithmetic','arithmetic','pre_exec'); assert ArmKey.parse(str(a))==a; print('ArmKey round-trip OK')"
```

If check #3 surprises you (no `outcome=` kwarg), **stop and report** — that determines how task 3.2 + 3.4 are written.

---

## Scope — exactly what Batch 3 ships

### Spec sections this batch implements
- **§4.5** `a4/standalone/v6_uniform_driver.py` (NEW — active driver)
- **§4.4** `fuzzer.py` strategy wiring + `_dispatch_arm` + `_record_arguzz_mutation` + soundness-signal forwarding
- **§11 Batch 3** task list 3.1 → 3.7 (incl. 3.2a applied-accounting, 3.2b Tier-2 byte-identity)
- **§1.6 / §4.8** test Layer 5 (real-binary driver smoke, gating) + Tier-2 DB byte-identity
- **§14** acceptance gates for Batch 3
- **§15** ISS-6 (ArmKey recovery), ISS-7 (fuzzer baseline_trace), + the Batch-3 augmentation that closes ISS-5's deferred assertions

### Files touched

| File | Action | Rough size |
|---|---|---|
| `a4/standalone/v6_uniform_driver.py` **(NEW)** | Refactor of `v6_driver_v2.py`: `arguzz_invoke.run()` + `CoverageDB`; verbatim `ArguzzScheduler` + bootstrap; `driver_version="v3_d2c"`. | ~300–400 LOC |
| `a4/standalone/fuzzer.py` | `v6_cTS`/`hybrid_cTS` recognition + per-strategy kind-list wiring; `baseline_trace` capture (ISS-7); `_dispatch_arm()` (ISS-6); `_record_arguzz_mutation()`; `applied_accounting_mode` wiring (3.2a); soundness-signal forwarding. | ~120–180 LOC |
| `a4/standalone/tests/test_d2c_v6_uniform_driver_smoke.py` **(NEW)** | Layer 5 — **GATING**, `A4_REAL_BINARY=1`, N=50 real run; schema/kinds/outcome/CGC asserts. | ~150 LOC |
| `a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py` **(NEW)** + fixture | Tier-2 — mocked-binary `run_campaign(N=20, cTS_semantic_v2, seed=42)`; DB byte-identity. | ~80 LOC + fixture |
| (optional) `a4/standalone/tests/test_d2c_arguzz_bridge.py` | **Augment** with the deferred ISS-5 assertions now that `_dispatch_arm` exists (routing + `outcome` column). | ~30 LOC |

**Total expected delta:** ~650–850 LOC. All Python; **zero Rust**.

---

## NOT in Batch 3 (deferred — do not start these)

| Item | Where it ships |
|---|---|
| CLI flags `--selector=hybrid_cTS` / `--selector=v6_cTS` / `--variant=v6_uniform` (full exposure) | **D2.D** (Batch 3 adds only the internal constants + wiring; §4.4 NB) |
| `test_d2c_hybrid_smoke.py` (Layer 6 forerunner) + `test_d2c_arm_registration.py` (66-case cross-cutting) | **Batch 4** |
| Any **arm-space reduction** (ISS-2 ruled KEEP 437) | not in D2.C |
| Changes to `arguzz_invoke.py`, `arguzz_bridge.py`, `bandit_ts.py`, `semantic_arm_universe.py`, `arguzz_parser.py`, `v6_driver_v2.py`, `OPCODE_CLASS_BY_MAJOR`/`semantic_zones.py`, `workspace/risc0-modified/` | **None** — §4.9 "must not change" |

If you find yourself editing `bandit_ts.py` or `semantic_arm_universe.py`, **stop** — Batch 3 should not need to (ISS-6 uses the existing `ArmKey.parse`; ISS-7 uses the existing `build(arguzz_kinds=…)`).

---

## §A — The `outcome` column (resolve in pre-flight, then proceed)

D2.A added a `mutations.outcome` column. Spec §4.4 assumes `record_mutation(..., outcome=result.outcome.value)`. **Verify the real mechanism** (pre-flight #3). Two acceptable outcomes:
- **If `record_mutation` accepts `outcome=`** (or a kwarg via `**self._mutation_record_kwargs(...)`): pass `result.outcome.value` (`"applied"`/`"skipped"`/`"error"`).
- **If the column is written elsewhere** (e.g. a `_mutation_record_kwargs` builder or a post-insert setter): follow that same path for Arguzz rows — do not add a parallel write.

Document which path you took in the report. **The acceptance gate requires `mutations.outcome` to be non-NULL for Arguzz rows in the N=50 Layer-5 run.**

---

## Tracked issues you must honor / resolve (spec §15)

When you resolve one, **flip its Status in spec §15 to `RESOLVED` (append the commit/batch)** and note it in the report.

| ID | What you do in Batch 3 | How it closes |
|----|------------------------|---------------|
| **ISS-6** (ArmKey recovery) | In `_dispatch_arm` / `_run_v2_bandit_mutation`, recover the selected arm with **`ArmKey.parse(decision.arm_id)`** and branch on `arm.surface == ARGUZZ_EXEC_FAULT`. **Do NOT extend `BanditDecision`** (keeps the Tier-1 golden trace byte-identical). | RESOLVED once dispatch routes by surface and both golden traces stay green. |
| **ISS-7** (fuzzer `baseline_trace`) | For `v6_cTS`/`hybrid_cTS` only, capture a `host --trace` `baseline_trace` in `_setup` (same bootstrap as `v6_driver_v2.py:389-430`) and pass it to `SemanticArmUniverse.build(self.data, kinds, arguzz_kinds=…, baseline_trace=…)`. V5/A4 strategies keep `arguzz_kinds=None`, capture no trace. | RESOLVED once the capture is wired and the V5 golden trace is byte-identical. |
| **ISS-5** (deferred B2 assertions) | Optionally augment `test_d2c_arguzz_bridge.py` with the now-possible `_dispatch_arm` routing + `mutations.outcome` assertions, OR cover them in the Layer-5 smoke. | Fully closes ISS-5 (B2 resolved the scope; B3 lands the deferred coverage). |
| **ISS-1** (residual) | No action — the D2.G fault-corroboration residual stays OPEN. `include_trace=False` is already shipped in the bridge; the driver also uses inject-only. | Leave the residual OPEN. |
| **ISS-3** (consumed) | The `build` guard already exists (Batch 2). Just make sure the fuzzer passes a non-None `baseline_trace` for Arguzz strategies (ISS-7) so it never trips the guard at runtime. | Already RESOLVED; just don't regress it. |

---

## Critical correctness facts (do NOT repeat these)

1. **A4-side byte-identity.** The refactor must not change the A4 dispatch path's RNG draws or DB serialization. `cTS_semantic_v2` (V5) keeps `arguzz_kinds=None` + `applied_accounting_mode=False`. **Run Tier-1 after every fuzzer edit**; land Tier-2 (3.2b) to lock DB serialization.
2. **Soundness-signal ownership.** The **primitive** (`arguzz_invoke._classify_outcome`) is the SINGLE owner of `soundness_signal`. The driver/fuzzer only **copy** `result.soundness_signal` into `config_json["soundness_signal"]` and emit a non-fatal `WARNING`. Do NOT re-derive it in the driver/bridge/fuzzer.
3. **`outcome` column from `result.outcome.value`.** This is how Option C's bandit signal reaches the DB. Path A (`error`+failures) and Path B (`error`+no-failures → `failure_recording_gap`) both map to `APPLIED`. Don't collapse them to "rejected".
4. **`proof_verify_failed = (prover_status == "error" and len(failures) > 0)`**, `verifier_accepted = (prover_status == "success")`, `proof_generated = (prover_status != "none")` — per §4.4. Mirror these exactly for Arguzz rows.
5. **Keep `ArguzzScheduler` + bootstrap verbatim** in `v6_uniform_driver.py`. The V6-uniform baseline's faithfulness depends on the balanced round-robin being untouched. Only the invocation + persistence layers change.
6. **LOCKED `extra_json` + seed scheme.** `driver_version="v3_d2c"`, `scheduler="balanced_round_robin"`, `selector="arguzz_balanced_rr"`; `iter_seed = args.seed * 1_000_000 + i`. Don't drift these (§9 Q5/Q6).
7. **`applied_accounting_mode=True` for `v6_cTS`/`hybrid_cTS` ONLY** (task 3.2a). V5_control stays `False`. On the Arguzz path, replace `v2_scheduler.update(kind, zone, reward)` with `update_with_outcome(arm, outcome, success=…)`.

---

## Per-task detail

### Task 3.1 — `a4/standalone/v6_uniform_driver.py` (NEW) — §4.5
Refactor `v6_driver_v2.py`: (a) `ArguzzScheduler` + the `host --trace`/`InspectionData`/`classify_zones` bootstrap copied **verbatim**; (b) per-injection: `result = arguzz_invoke.run(host, host_args, step, kind, iter_seed, timeout=90.0)` (inject-only, `include_trace=False`); (c) persist via `CoverageDB.record_mutation` (+ `outcome`), `record_failures`, `record_global_failures`, `record_compressed_global_first_hit` — no inline SQL; (d) `extra_json`/seed/CLI per Facts #6; (e) entry `python -m a4.standalone.v6_uniform_driver`.

### Task 3.2 — `fuzzer.py` strategy wiring + `_dispatch_arm` — §4.4 (ISS-6, ISS-7)
- Add `v6_cTS`/`hybrid_cTS` to `STRATEGY_DISPLAY_NAMES` and `CTS_SEMANTIC_V2_FAMILY` (so the cTS setup + `_run_v2_bandit_mutation` cTS branch handle them). Per-strategy kind-list (§4.4 code shape): `v6_cTS → arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL, arguzz_only=True`; `hybrid_cTS → arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED, arguzz_only=False`; else `arguzz_kinds=None`.
- **ISS-7:** capture `baseline_trace` (host `--trace`) for the two Arguzz strategies and pass it into the `SemanticArmUniverse.build(...)` call at line 747.
- **ISS-6:** in `_run_v2_bandit_mutation`, after `decision = self.v2_scheduler.select()`, recover `arm = ArmKey.parse(decision.arm_id)` and call `_dispatch_arm(arm, step, mutation_num)`.
- `_dispatch_arm`: `surface=A4_TRACE_CELL` → existing `_create_mutation`/`run_a4_mutation` logic (unchanged); `surface=ARGUZZ_EXEC_FAULT` → `arguzz_bridge.create_mutation_for_arm(arm, step, self.host_binary, self.host_args, iter_seed, self.data, timeout=self.arguzz_timeout)` → build a `MutationResult` from the `ArguzzInvocationResult` → `_record_arguzz_mutation`. Add `arguzz_timeout: float = 90.0` instance attr.
- `_record_arguzz_mutation`: write via `CoverageDB.record_mutation(... outcome=result.outcome.value ...)` per §A + Facts #3/#4; `record_failures(mut_id, result.failures)`; CGC via `extract_compressed_global_contexts(family_residues=…, family_details=…, mutation_kind=arm.kind, mutation_zone=arm.zone, mutation_major=cycle.major)` → `record_compressed_global_first_hit(...)`; copy `soundness_signal` to `config_json` + non-fatal WARNING.

### Task 3.2a — applied-mutation accounting — §11 task 3.2a
For `selector_strategy in {hybrid_cTS, v6_cTS}`: construct the cTS scheduler with `applied_accounting_mode=True`; on the Arguzz dispatch path replace `v2_scheduler.update(kind, zone, reward)` with `update_with_outcome(arm, outcome, success=…)`. **V5_control keeps `applied_accounting_mode=False`** (golden-trace invariant).

### Task 3.2b — Tier-2 V5 golden-trace DB byte-identity — §4.8
After 3.1+3.2 land: `A4Fuzzer.run_campaign(N=20, selector_strategy="cTS_semantic_v2", seed=42)` against a mocked-binary fixture; serialize DB content (mutations + failures + coverage rows, minus timestamps + run-specific IDs); commit as reference fixture; assert byte-identity on re-run. ~10s. Catches config_json key-reordering / extra-field / column drift the Tier-1 test misses.

### Task 3.3 — Layer-5 real-binary driver smoke — **GATING** — §4.8
`A4_REAL_BINARY=1`, N=50 via `v6_uniform_driver`. Assert: 50 `mutations` rows; **≥6 of 11 ENABLED_KINDS present** AND all 4 SELECTED kinds present; `outcome` column populated; `coverage.constraint_loc` is `Name@basename:line`; `compressed_global_coverage` non-empty; `extra_json.driver_version == "v3_d2c"`. Skip gracefully without the env var.

### Task 3.4 — schema-parity check — §11 task 3.4
Produce a 50-mutation V6 DB; diff schema vs an R2 V6 DB; document the expected deltas (`outcome` column added; `constraint_loc` normalized at write-time). Report only.

### Task 3.5 — soundness-signal smoke — §11 task 3.5
In the N=50 run, verify `soundness_signal=true` rows are well-formed (likely 0–2) AND `failure_recording_gap` appears on any `prover_status="error"` row with no `<constraint_fail>` tag (Path B). Report counts.

### Task 3.6 — full pytest sweep
`python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py` — ≥ the 654/21 floor + new Batch-3 tests; **Tier-1 + Tier-2 golden traces green**; no regression.

### Task 3.7 — write `D2C_BATCH3_COMPOSER_REPORT.md`
See [Report deliverable](#report-deliverable).

---

## Test layers in Batch 3

| # | Layer | File | Gating? |
|---|---|---|---|
| 5 | Real-binary driver end-to-end smoke | `test_d2c_v6_uniform_driver_smoke.py` | **YES** |
| 1 | Tier-2 V5 golden-trace DB byte-identity | `test_d2c_golden_trace_v5_db_byte_identity.py` | **regression gate** |
| 1 | Tier-1 V5 golden trace (inherited) | `test_d2c_golden_trace_v5_decision_seq.py` | **must stay byte-identical** |

---

## Acceptance gate (Batch 3 ships when ALL hold)

- [ ] `v6_uniform_driver.py` runs `python -m a4.standalone.v6_uniform_driver` end-to-end; `ArguzzScheduler` + bootstrap verbatim; `arguzz_invoke.run()` + `CoverageDB` (no inline SQL); `driver_version="v3_d2c"`; `iter_seed` scheme preserved.
- [ ] `fuzzer.py` recognizes `v6_cTS`/`hybrid_cTS`; per-strategy `arguzz_kinds` wiring; `_dispatch_arm` routes by `arm.surface` via `ArmKey.parse(decision.arm_id)` (**ISS-6**); `baseline_trace` captured for Arguzz strategies (**ISS-7**); `arguzz_timeout` attr present.
- [ ] `mutations.outcome` populated for Arguzz rows (`result.outcome.value`); `verifier_accepted`/`proof_generated`/`proof_verify_failed` per Fact #4.
- [ ] **`applied_accounting_mode=True` for `v6_cTS`/`hybrid_cTS` only** (task 3.2a); V5_control unaffected; Arguzz path uses `update_with_outcome`.
- [ ] **Tier-1 golden trace byte-identical** AND **Tier-2 DB byte-identity green** (task 3.2b).
- [ ] Layer-5 real-binary smoke green (`A4_REAL_BINARY=1`, N=50): ≥6/11 kinds + all 4 SELECTED present; `outcome` populated; `constraint_loc` normalized; CGC non-empty; `extra_json.driver_version="v3_d2c"`. Output pasted in report.
- [ ] Soundness-signal smoke: well-formed tagged rows + `failure_recording_gap` on Path B rows (counts reported).
- [ ] Schema-parity documented (outcome column + normalized constraint_loc).
- [ ] Pytest sweep ≥654/21 + new Batch-3 tests; no regression.
- [ ] `arguzz_invoke.py`, `arguzz_bridge.py`, `bandit_ts.py`, `semantic_arm_universe.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`, `workspace/risc0-modified/` unchanged.
- [ ] **Spec §15 updated:** ISS-6 → RESOLVED, ISS-7 → RESOLVED, ISS-5 → fully closed (deferred assertions landed); ISS-1 residual left OPEN.
- [ ] `D2C_BATCH3_COMPOSER_REPORT.md` submitted.

---

## Workflow

1. **Pre-flight** (checklist above) — record the 654/21 floor; confirm Tier-1 passes now; **resolve §A (`outcome` column mechanism)**.
2. **Read** §4.4/§4.5/§15 + `v6_driver_v2.py` + the fuzzer anchors.
3. **Implement in order:** 3.1 driver → 3.2 fuzzer dispatch (run Tier-1 after each edit) → 3.2a applied-accounting → 3.2b Tier-2 fixture+test → 3.3 Layer-5 smoke (run locally with binary) → 3.4 schema parity → 3.5 soundness smoke → 3.6 sweep → update spec §15 → 3.7 report.
4. **Single commit to `cloud2`** (no feature branch, no PR). Co-authored-by line included.
5. **Self-checkpoint:** acceptance 100% green; both golden traces byte-identical, before committing.

---

## Report deliverable

`a4/docs/cloud2/composer/D2C_BATCH3_COMPOSER_REPORT.md`:

1. **Pre-kickoff checklist output** (incl. the §A `outcome`-column finding + Tier-1-passes-now line).
2. **What was implemented** — per-task LOC counts.
3. **`outcome` column** — which write path (§A) you used; Arguzz rows non-NULL proof.
4. **A4-side byte-identity** — Tier-1 before/after; Tier-2 fixture captured + asserted (paste both).
5. **Layer-5 smoke output** — `A4_REAL_BINARY=1` N=50 run: kinds present, outcome distribution, CGC rows, `driver_version`. Any binary surprises.
6. **Soundness-signal + failure_recording_gap** counts.
7. **Schema-parity** diff vs R2 V6.
8. **Spec §15 status changes** — ISS-6/ISS-7/ISS-5 flips.
9. **Test counts** vs the 654/21 floor.
10. **Deviations** + **open questions** for Batch 4 (hybrid forerunner + cross-cutting registration + closure).

---

## Hand-off statement (paste when delegating to Composer)

> Implement D2.C Batch 3 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_C_SPEC.md` **v0.5** §11 "Batch 3" (tasks 3.1–3.7) and the §15 issue annex. Follow `a4/docs/cloud2/composer/D2C_BATCH3_COMPOSER_KICKOFF.md`. Commit directly to `cloud2`, single commit, no feature branch, no PR. Batch 3 is the **active driver + fuzzer Arguzz dispatch**: ship `a4/standalone/v6_uniform_driver.py` (refactor of `v6_driver_v2.py` onto `arguzz_invoke.run()` + `CoverageDB`, keeping `ArguzzScheduler` + bootstrap verbatim, `driver_version="v3_d2c"`), extend `fuzzer.py` to recognize `v6_cTS`/`hybrid_cTS` (per-strategy `arguzz_kinds`; capture `baseline_trace` for Arguzz strategies = ISS-7; `_dispatch_arm` routing via `ArmKey.parse(decision.arm_id)` = ISS-6; `_record_arguzz_mutation` populating the `outcome` column; `applied_accounting_mode=True` for the two Arguzz strategies only = task 3.2a), and add the Layer-5 real-binary smoke (gating) + the Tier-2 DB byte-identity gate (task 3.2b). Load-bearing: the A4-side path must be byte-identical pre/post refactor — `cTS_semantic_v2` keeps `arguzz_kinds=None`/`applied_accounting_mode=False`; run the Tier-1 golden trace after every fuzzer edit and land Tier-2. The `mutations.outcome` column must be non-NULL for Arguzz rows (`result.outcome.value`); the primitive owns `soundness_signal`, the fuzzer only forwards it. Do NOT touch `arguzz_invoke.py`, `arguzz_bridge.py`, `bandit_ts.py`, `semantic_arm_universe.py`, `v6_driver_v2.py`, or `OPCODE_CLASS_BY_MAJOR`. First resolve §A (how D2.A writes `mutations.outcome`) in pre-flight. Update spec §15 (ISS-6/ISS-7 → RESOLVED, ISS-5 fully closed). Pass criteria = the acceptance checklist. Submit `a4/docs/cloud2/composer/D2C_BATCH3_COMPOSER_REPORT.md`.

---

*End of D2.C Batch 3 kickoff. Report back at `D2C_BATCH3_COMPOSER_REPORT.md`; Opus reviews, updates spec §15, then issues the Batch 4 (hybrid forerunner + cross-cutting registration + closure) kickoff.*
