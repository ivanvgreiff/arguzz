# D2.C Batch 4 — Composer Kickoff (Hybrid forerunner + cross-cutting registration + ISS cleanup + closure)

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) **v0.5 LOCKED** + **§15 living-issue annex** (ISS-1…ISS-9 + the **POS-run policy**)
**Governing plan:** [`../New_Master.md`](../New_Master.md) §2 Phase 1 · **Parent:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.16 §3
**POS SSOT:** [`../../precloud/POS_PLAYBOOK.md`](../../precloud/POS_PLAYBOOK.md) — **read §0, the canonical-dispatch-templates block at top, and §6 workflow before any real-binary run >10 mutations.**
**Predecessors:** D2.C **Batches 1–3** implemented & reviewed (greenlit 2026-06-20). Working-tree baseline: **655 passed, 27 skipped** (ignore-replicates path, re-verified 2026-06-20).
**Issued by:** Opus (planning), post-Batch-3 review
**Expected effort:** ~1–1.5 days + ~0.5 day report. Closes D2.C.

---

## TL;DR for Composer

Batch 4 **closes D2.C**. It has five strands:

1. **Layer-6 Hybrid forerunner** (`test_d2c_hybrid_smoke.py`) — **stubbed primitive**, `hybrid_cTS`, both surfaces pulled. *(No real binary → runs local.)*
2. **Cross-cutting registration** (`test_d2c_arm_registration.py`) — 11 Arguzz kinds × 6 layers = **66 cases**. *(No mutations → local.)*
3. **ISS-9 — bridge reconciliation** (cleanup of a Batch-3 deviation): add an optional `env=` param to `arguzz_bridge.create_mutation_for_arm` and route **both** `fuzzer._run_arguzz_cts_mutation` and `v6_uniform_driver` through it, so the bridge is the single Arguzz entry point again and the Batch-2 bridge test guards the production path.
4. **ISS-8 — POS validation of the Arguzz real-binary path** (resolves the CGC/Hook-3 question + complies with the POS-run policy): re-run the V6-uniform driver at **N≥50 on POS** (NOT locally), collect the DB, and report kind-coverage / outcome-distribution / whether `compressed_global_coverage` is populated on the POS binary.
5. **Closure**: plan status → DONE, full sweep, `D2C_BATCH4_COMPOSER_REPORT.md`.

**Two things changed since the Batch-3 kickoff you must internalize:**
- **POS-run policy (spec §15):** *any* test/script running **>10 real-binary mutations** at once MUST be dispatched on **POS** via `a4/pos/dispatch_audit.sh` + a manifest — **not** inside `pytest`. Local real-binary gating tests are capped at **≤10 mutations**. This is why the Batch-3 Layer-5 N=50 (run locally at ~771 s) must move to POS (task 4.4 below).
- **Batch 4 MAY touch `arguzz_bridge.py`** (for ISS-9) — it is *removed* from the "must not change" list **for this batch only**, and only for the `env=` addition. Everything else in §4.9 stays frozen.

---

## Composer: read these files first

**Docs:**
1. `IV_POS_8_D2_C_SPEC.md` **v0.5** — **§11 Batch 4** (tasks 4.1–4.6), **§4.8** (Layer-6 + registration test rows), **§14 / §11 Batch-4 acceptance**, and **§15** (ISS-8, ISS-9, and the **POS-run policy** — you own resolving ISS-8 + ISS-9).
2. `POS_PLAYBOOK.md` — the canonical-dispatch-templates table at the very top + §0 (current state) + §6 (workflow). You will produce a manifest and dispatch the driver smoke per this doc.
3. `D2C_BATCH3_COMPOSER_REPORT.md` §10 (the deviations you're cleaning up — D3 CGC, D5 bridge bypass) + this kickoff.

**Code:**
4. `a4/standalone/mutations/arguzz_bridge.py` — `create_mutation_for_arm` (your ISS-9 edit target: add `env`). 
5. `a4/standalone/fuzzer.py` — `_run_arguzz_cts_mutation` (fuzzer.py:1138) + `_record_arguzz_mutation` (1083); route the former through the bridge for ISS-9. `ALL_SEMANTIC_CTS_STRATEGIES` / `ARGUZZ_CTS_STRATEGIES` (143/151) for the hybrid smoke.
6. `a4/standalone/v6_uniform_driver.py` — route its `arguzz_run(...)` call through `create_mutation_for_arm` too (ISS-9), keeping the locked `extra_json`/seed scheme.
7. `a4/standalone/tests/test_d2b_arm_registration.py` — the **template** for the 66-case `test_d2c_arm_registration.py`.
8. `a4/standalone/tests/test_d2c_arguzz_bridge.py` — augment with the now-possible dispatch assertion (production path uses the bridge after ISS-9).
9. `a4/pos/manifests/iv_pos_8/d2b_smoke.json` — the **manifest template** for your D2.C POS smoke; `a4/pos/dispatch_audit.sh` + `a4/pos/chain_dispatcher.sh` (per POS_PLAYBOOK) for dispatch.

---

## Pre-kickoff sanity checklist

```bash
git rev-parse HEAD && git status --short
python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py 2>&1 | tail -3   # → 655 passed, 27 skipped floor
python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py a4/standalone/tests/test_d2c_golden_trace_v5_db_byte_identity.py -q   # → 3 passed (must stay green through ISS-9)
grep -n 'def create_mutation_for_arm' a4/standalone/mutations/arguzz_bridge.py    # ISS-9 target
grep -n 'arguzz_run(' a4/standalone/fuzzer.py a4/standalone/v6_uniform_driver.py  # the two call sites to reroute
```

---

## Per-task detail

### Task 4.1 — Layer-6 Hybrid forerunner `test_d2c_hybrid_smoke.py` — §4.8
**Stubbed primitive (no real binary → local).** Monkeypatch `arguzz_invoke.run` (and/or the bridge) so `A4Fuzzer.run_campaign(N=50, selector_strategy="hybrid_cTS", seed=…)` runs without a binary. Assert: **both** `surface=A4_TRACE_CELL` AND `surface=ARGUZZ_EXEC_FAULT` arms get pulled (≥1 each); `update_with_outcome` is called for both surfaces; the cTS `total_pulls` matches the APPLIED count. (N=50 here is fine **because the primitive is stubbed** — no real mutations run. The POS rule is about *real-binary* mutations.) Forerunner for D2.D's real Hybrid CLI wiring.

### Task 4.2 — cross-cutting registration `test_d2c_arm_registration.py` — §4.8
Mirror `test_d2b_arm_registration.py`. Parametrize over `MUTATION_KINDS_ARGUZZ_FULL` (11) × 6 assertion layers = **66 cases**: (1) Python module exists; (2) registry entry; (3) `get_valid_steps` non-empty for ≥1 step (synthetic trace); (4) `opcode_class` derivation; (5) `SemanticArmUniverse` entry; (6) dispatch wiring (`ArmKey.parse` → `surface=ARGUZZ_EXEC_FAULT` routes to the Arguzz path). No mutations → local.

### Task 4.3 — ISS-9 bridge reconciliation (cleanup) — §15 ISS-9
- **`arguzz_bridge.create_mutation_for_arm`:** default subprocess env = `{"A4_FAMILY_RESIDUE": "1", "A4_COVERAGE_TOUCH": "1"}` (F13 co-trigger — Hook-3 capture requires both; do **not** use `A4_MUTATION_CONFIG`). Optional `env: Optional[dict] = None` merges on top. Forwarded to `arguzz_invoke.run(..., env=...)`. Keep `include_trace=False`.
- **`fuzzer._run_arguzz_cts_mutation`:** route through `create_mutation_for_arm` (no inline `arguzz_run` / duplicate config).
- **`v6_uniform_driver`:** route through `create_mutation_for_arm` (construct `ArmKey` from scheduler pick + zone/opcode_class/pre_post). Merge driver-specific config fields onto bridge `config`.
- **Augment `test_d2c_arguzz_bridge.py`** — assert default env includes both co-triggers; production path uses bridge after ISS-9.
- **Gate:** Tier-1 + Tier-2 golden traces stay byte-identical.

### Task 4.4 — ISS-8 scale validation on POS — §15 ISS-8 + POS-run policy
**Prerequisite (F13 — do this BEFORE POS):** locally run ≤10 real mutations and assert `compressed_global_coverage` **and** `global_failures` are non-empty with the corrected bridge env. This resolves ISS-8 as a **config bug** (missing `A4_COVERAGE_TOUCH`), not an "Arguzz has no CGC channel" limitation.

**POS job (scale confidence, not root-cause diagnosis):**
1. **Layer-5 local test** (`test_d2c_v6_uniform_driver_smoke.py`) stays at **N≤10** — wiring, `outcome`, normalized `constraint_loc`, `driver_version`, **CGC + global_failures non-empty** (strict asserts after F13 fix).
2. **Author POS manifest** `a4/pos/manifests/iv_pos_8/d2c_v6_uniform_smoke.json` for `v6_uniform_driver --num 50`.
3. **Dispatch on POS** per POS_PLAYBOOK. Collect DB.
4. **Report from POS DB:** N=50 outcome distribution, distinct kinds (≥6/11 + all 4 SELECTED), CGC/global_failures counts — confirms corrected path at scale.

*Do **not** write "Arguzz variants have no CGC channel" if CGC is empty — that was the Batch-3 misdiagnosis. If CGC is still empty **after** the co-trigger fix locally, escalate as a new investigation.*

*If POS access unavailable:* stage manifest + dispatch command; mark **BLOCKED-ON-POS**; ISS-8 local half still RESOLVED if ≤10-mutation proof passes.

### Task 4.5 — plan status → DONE — §11 task 4.3
Update `IV_POS_8_D2_PLAN.md` D2.C row → **DONE** (the plan is already v0.16 — just flip the status + add a one-line completion note; no version bump needed unless the plan's own convention requires it — confirm before bumping).

### Task 4.6 — full sweep — §11 task 4.4
`python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py` — ≥ the 655/27 floor + the 2 new test files (Layer-6 + registration), no regression, both golden tiers green. *(Arm-space sensitivity sweep — spec task 4.5 — is **moot**: ISS-2 ruled KEEP 437. Skip it; note in report.)*

### Task 4.7 — `D2C_BATCH4_COMPOSER_REPORT.md`
See below.

---

## NOT in Batch 4

| Item | Where |
|---|---|
| CLI flags `--selector=v6_cTS`/`hybrid_cTS`/`--variant=v6_uniform` | **D2.D** |
| POS reservation/calendar management | **Ivan/Eddie** (you author the manifest + dispatch command) |
| Arm-space reduction | not in D2.C (ISS-2 KEEP 437) |
| ISS-1 D2.G fault-corroboration residual | **D2.G** |
| Edits to `bandit_ts.py`, `semantic_arm_universe.py`, `arguzz_invoke.py`, `v6_driver_v2.py`, `semantic_zones.py`, `arguzz_parser.py`, `workspace/risc0-modified/` | **None** (frozen). `arguzz_bridge.py` is editable **only** for the ISS-9 `env=` addition. |

---

## Acceptance gate (Batch 4 + D2.C closure)

- [ ] Layer-6 Hybrid forerunner green: both surfaces pulled; `update_with_outcome` called for both; stubbed primitive (local).
- [ ] Cross-cutting registration green: **66 cases** (11 Arguzz kinds × 6 layers).
- [ ] **ISS-9 RESOLVED:** `create_mutation_for_arm` takes `env=`; `fuzzer._run_arguzz_cts_mutation` **and** `v6_uniform_driver` both route through it; bridge test augmented to guard the production path; Tier-1 + Tier-2 golden traces byte-identical.
- [ ] **ISS-8 addressed:** Layer-5 local test reduced to N≤10; POS manifest authored; POS N≥50 driver smoke dispatched (or BLOCKED-ON-POS with everything staged); CGC presence on the POS binary reported; ISS-8 flipped to RESOLVED (with the empty-vs-nonempty verdict) or left OPEN if blocked.
- [ ] Full sweep ≥655/27 + 2 new tests; no regression; both golden tiers green.
- [ ] `IV_POS_8_D2_PLAN.md` D2.C row → DONE.
- [ ] Spec §15 updated: ISS-9 → RESOLVED; ISS-8 → RESOLVED or OPEN(BLOCKED-ON-POS); POS-run policy honored.
- [ ] `D2C_BATCH4_COMPOSER_REPORT.md` submitted.

---

## Report deliverable — `D2C_BATCH4_COMPOSER_REPORT.md`

1. Pre-flight output (655/27 floor + golden traces green).
2. Per-task summary + LOC.
3. **ISS-9:** before/after of the dispatch path; proof both fuzzer + driver call `create_mutation_for_arm`; golden traces byte-identical.
4. **ISS-8:** POS manifest + dispatch command; POS run result (outcome distribution, kinds, **CGC/global_failures populated? yes/no**) OR BLOCKED-ON-POS staging; the empty-vs-nonempty verdict + its D2.G implication.
5. Layer-6 + registration test output.
6. Final sweep counts vs 655/27.
7. **D2.C closure statement**: all batches done, plan flipped, §15 residuals remaining (ISS-1 D2.G; ISS-8 if blocked), F12 carried to D2.F.
8. Open items for **D2.D** (CLI wiring of the new strategies/variant).

---

## Hand-off statement (paste when delegating to Composer)

> Implement D2.C Batch 4 (closure) per `IV_POS_8_D2_C_SPEC.md` v0.5 §11 "Batch 4" + the §15 annex, following `a4/docs/cloud2/composer/D2C_BATCH4_COMPOSER_KICKOFF.md`. Commit directly to `cloud2`, single commit. Ship: (1) `test_d2c_hybrid_smoke.py` (Layer-6, **stubbed** primitive, `hybrid_cTS`, both surfaces pulled — local); (2) `test_d2c_arm_registration.py` (66 cases = 11 Arguzz kinds × 6 layers); (3) **ISS-9 cleanup** — add optional `env=` to `arguzz_bridge.create_mutation_for_arm` and route **both** `fuzzer._run_arguzz_cts_mutation` and `v6_uniform_driver` through it (the bridge is editable for this only; keep Tier-1 + Tier-2 golden traces byte-identical); (4) **ISS-8 POS validation** — reduce the Layer-5 local test to **N≤10**, author a POS manifest (model `a4/pos/manifests/iv_pos_8/d2b_smoke.json`) for `python -m a4.standalone.v6_uniform_driver … --num 50`, dispatch on **POS** per `POS_PLAYBOOK.md` (NOT locally — the POS-run policy forbids >10 real mutations in pytest), and report whether `compressed_global_coverage` is populated on the POS binary (resolving the CGC question); if POS is unavailable, stage the manifest+command and mark BLOCKED-ON-POS; (5) flip `IV_POS_8_D2_PLAN.md` D2.C → DONE; (6) full sweep ≥655/27 + new tests; (7) update spec §15 (ISS-9 RESOLVED; ISS-8 RESOLVED/blocked). Submit `D2C_BATCH4_COMPOSER_REPORT.md`. Do NOT touch any frozen file except `arguzz_bridge.py` (env= only).

---

*End of D2.C Batch 4 kickoff. Report back at `D2C_BATCH4_COMPOSER_REPORT.md`; Opus does the full D2.C reconciliation review, then D2.C → DONE and hand-off to D2.D (CLI wiring).*
