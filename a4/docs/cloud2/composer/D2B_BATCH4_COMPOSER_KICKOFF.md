# D2.B Batch 4 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) **v0.5.4 LOCKED + audit patch**, **§7 Batch 4** + **§4.8** + **§5.5**
**Parent plan:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) **v0.13** — W-17, W-18, §6c, §6d, §9b, §9c
**Predecessor audits (must internalize):**
- W-17 audit (B.3 dead arm): [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md)
- W-18 audit (B.4/B.5 dead arms): [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)
**Companion Pro-facing doc:** [`../IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md) — self-contained explanation of the live/dead split and the next-target inventory; **read §9 (4-channel rejection model) and Appendix A (preflight-field → extern map) before writing the smoke tests**.
**Predecessor commit:** Batch 3 + W-18 audit (commit hash TBD — paste in the Batch 4 report)
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~1–2 days. **No new mutation kinds, no Rust handlers, no audit risk.** Pure cross-cutting validation + smoke wiring.

---

## TL;DR for Composer

Implement **D2.B Batch 4** as defined in spec §7 Batch 4 — three new test files (Layer 1 cross-cutting + Layer 5 mocked smoke + Layer 5 real-binary smoke) plus plan/spec/report updates that close D2.B as `feature-complete`.

**Crucially: Batch 4 is the *last Composer batch* of D2.B.** After Batch 4 commits, Opus runs the **§9c postscript (D2.B-PS-1)** to remove the 5 confirmed dead kinds from `A4Fuzzer.MUTATION_KINDS`. Batch 4 must leave the registry **untouched** — all 8 D2.B kinds (B.1–B.8) plus the 8 pre-existing V5 kinds still in `MUTATION_KINDS`. The smoke tests will exercise the dead kinds as a side effect; that's expected and correct (see §6 below).

| Task | File | Layer | Tests added |
|------|------|-------|-------------|
| **4.1** | `a4/standalone/tests/test_d2b_arm_registration.py` | Layer 1 cross-cutting | ~6 logical tests |
| **4.2** | `a4/standalone/tests/test_d2b_campaign_smoke.py` | Layer 5 mocked-binary | ~3 logical tests |
| **4.3** | `a4/standalone/tests/test_d2b_real_binary_campaign.py` | Layer 5 real-binary (gated on `A4_REAL_BINARY=1`; **runs on POS, not locally** — see §POS Dispatch below) | ~1–2 logical tests |
| **4.4** | Update master plan (`IV_POS_8_D2_PLAN.md` → **v0.14**) — D2.B status = DONE-feature-complete (postscript pending) |
| **4.5** | `D2B_BATCH4_COMPOSER_REPORT.md` |

---

## Read in this order before writing code

1. **Spec §7 Batch 4** (~3 lines) — the task list.
2. **Spec §4.8** — test taxonomy; confirms 18 logical tests across the per-kind unit/attestation files + the 3 Batch-4 files.
3. **Spec §4.9** — files that must NOT change (registry, bandit, CGC core, MUTATION_TAXONOMY).
4. **Plan v0.13 §9c** — the postscript task and Batch 4's relationship to it. Read carefully: the postscript is **Opus's task post-Batch-4**, not yours.
5. **Mechanism report** ([`../IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md)):
   - §9 (4-channel rejection model) — how the smoke tests should interpret outcomes.
   - Appendix A (preflight-field → extern map) — for the registration test, this is the authoritative cross-reference.
6. **Existing per-kind unit + attestation tests** (`a4/standalone/tests/test_d2b_*_unit.py` and `*_attestation.py`) — use these as templates for the registration test's assertions.
7. **POS Playbook** ([`../../precloud/POS_PLAYBOOK.md`](../../precloud/POS_PLAYBOOK.md)) — **REQUIRED for task 4.3** (the real-binary smoke runs on POS, not locally). Read end-to-end at least once; then re-read with focus on:
   - **§★ Canonical Dispatch Templates** (top of file)
   - **§3.4–§3.5** (tier-aware node assignment)
   - **§4** (image + bundle preparation)
   - **§5.4** (KEY INVARIANTS — no `--env`, infile shebang, etc.)
   - **§6** (end-to-end workflow diagram)
   - **§12 Anti-patterns** (every entry — these are bugs we've already paid for)
8. **Existing POS manifest template** — `a4/pos/manifests/iv_pos_8/d1a_b1.json` (most recent IV.POS.8 schema; clone and adapt for task 4.3).

---

## Task 4.1 — `test_d2b_arm_registration.py` (Layer 1 cross-cutting)

**Purpose:** A single test file that, for every kind in `A4Fuzzer.MUTATION_KINDS`, asserts the kind is **fully wired** at every layer of the dispatch chain. This is the meta-test that catches "added the Python module but forgot the CGC role" or "added the Rust handler but not the registry entry" type bugs.

### 4.1.a — Required assertions per kind

For every `kind in A4Fuzzer.MUTATION_KINDS`, assert all of the following:

| Layer | Assertion | How to check |
|-------|-----------|--------------|
| **Python module** | A `_*Mutation` class exists in `a4/standalone/mutations/` with a `MUTATION_KIND` class attribute equal to `kind` | Import lookup table + `inspect.getmembers` |
| **`_MUTATION_MODULES` registry** | `kind` maps to a module in the fuzzer's module registry | Direct dict lookup in `A4Fuzzer` |
| **`get_valid_steps_for_kind` branch** | `inspection_data.py:get_valid_steps_for_kind(kind, ...)` returns a non-None value (or raises a documented exception for unsupported kinds — e.g., V5 kinds that don't go through this path) | Call on a fixture trace; check return type |
| **Rust handler** | `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` has a match arm for `kind` | Grep for the kind literal in `mod.rs`; assert at least one match |
| **`SemanticArmUniverse` filter** | `_cycle_matches_kind_filter` (or equivalent step-validity check) handles `kind` without panicking | Construct a synthetic step, call the filter, assert it returns a bool |
| **CGC `_TXN_ROLE_BY_KIND`** (only for txn-targeting kinds) | `_TXN_ROLE_BY_KIND[kind]` is present and matches a value in `MEMORY_TXN_ROLES` | Dict lookup; for cycle-only kinds, assert NOT present (negative test) |

### 4.1.b — Implementation pattern

Use a **parametrized pytest test**, one parameter per kind in `A4Fuzzer.MUTATION_KINDS`. Each parametrization runs all 6 assertions. Failure on any kind shows up as a single test ID like `test_arm_registration[TXN_PREV_WORD_MOD]::python_module`.

```python
@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_python_module_exists(kind):
    assert kind in _MUTATION_MODULES, f"Kind {kind} missing from _MUTATION_MODULES"
    # ... etc

@pytest.mark.parametrize("kind", sorted(A4Fuzzer.MUTATION_KINDS))
def test_rust_handler_match_arm_exists(kind):
    # grep for kind literal in mod.rs
    # ...
```

**One file, multiple parametrized test functions, one per assertion layer.** Keep functions focused.

### 4.1.c — Expected count

- `MUTATION_KINDS` currently has **16 kinds** (8 V5 + 8 D2.B).
- 6 assertion functions × 16 kinds = **96 logical test cases**.
- For some V5 kinds, certain assertions don't apply (e.g., V5 kinds may not use `get_valid_steps_for_kind`). Use `pytest.skip()` with a clear reason in those cases — **do not** silently allow them to pass without checking.

### 4.1.d — Negative tests (important)

In addition to the per-kind positive tests, add a **negative test** that asserts the **dead kinds are still registered** (since Batch 4 leaves them in `MUTATION_KINDS`):

```python
def test_dead_kinds_still_in_registry_pre_postscript():
    # Pre-§9c postscript, all 5 dead kinds must still be registered.
    # After the postscript lands, this test will need its assertion inverted.
    # Tagged with a marker so the postscript task knows to flip it.
    DEAD_KINDS = {"CYCLE_MODE_MOD", "TXN_ADDR_MOD", "TXN_CYCLE_PHASE_MOD",
                  "CYCLE_PC_MOD", "CYCLE_STATE_MOD"}
    assert DEAD_KINDS.issubset(A4Fuzzer.MUTATION_KINDS), (
        "Dead kinds removed prematurely. The §9c postscript is Opus's task "
        "post-Batch-4; do not remove these in Batch 4."
    )
```

This is the **guardrail against accidental scope creep into the §9c postscript.**

---

## Task 4.2 — `test_d2b_campaign_smoke.py` (Layer 5 mocked-binary)

**Purpose:** End-to-end fuzzer dispatch validation without running the actual prover. The mocked binary lets us run hundreds of mutations cheaply to confirm:
- Every kind gets selected by the bandit/round-robin scheduler eventually.
- Every selection produces a valid `MutationConfig` JSON that the dispatcher accepts.
- The CGC extractor produces correct `producer_kind` / `txn_role` tags for the simulated outcomes.
- `MutationOutcome` accounting (APPLIED / SKIPPED / ERROR) tallies correctly.

**This is NOT a constraint-coverage test.** Constraint coverage is the per-kind attestation tests' job.

### 4.2.a — Mutation count guidance

| Mode | Per kind | Total | Rationale |
|------|----------|-------|-----------|
| **Mocked-binary smoke** | **50 mutations per kind** | 16 × 50 = **800 mutations** | Cheap (no prover); validates dispatch + telemetry stability under volume |
| Real-binary smoke (4.3) | **3 per LIVE kind, 1 per DEAD kind** | (3 × 11 live) + (1 × 5 dead) = **38 mutations** | Each mutation ≈ 14 min; total ≈ 9 hours. Trade-off between confidence and CI time. |

Rationale for the per-kind counts in mocked smoke:

- **50 per kind** is a sweet spot. Smaller numbers (5–10) don't exercise the bandit's exploration/exploitation balance enough to surface dispatch flakiness. Larger numbers (200+) don't add information because the dispatch path is deterministic given the mock.
- For the **dead kinds**: 50 mutations is fine in mocked smoke. The dispatch path is what's being tested, not the dead-arm effect. The dead kinds will register as "applied, no rejection" — that's the expected mocked outcome (the mock binary doesn't run the prover, so no rejection can happen).

### 4.2.b — Required assertions

For each kind in `MUTATION_KINDS`, after running 50 mutations:

1. **Dispatch coverage:** every kind in `MUTATION_KINDS` was selected at least once. (Sanity check on bandit/round-robin.)
2. **No exceptions:** the fuzzer ran 800 iterations without raising. (Catches dispatch-path crashes.)
3. **`MutationOutcome` distribution:** count of `APPLIED` vs `SKIPPED` vs `ERROR` outcomes is recorded; `ERROR` count is 0 (any error means a dispatch bug). `SKIPPED` is allowed (target unavailable for that step).
4. **CGC tag well-formedness:** every `APPLIED` outcome produces a CGC record with valid `producer_kind` and (if applicable) `txn_role` values from the enumerated sets.

### 4.2.c — Mock-binary infrastructure

Reuse the existing D2.A test infrastructure if a mock exists; if not, build a minimal `MockA4Binary` that:
- Accepts a `MutationConfig` JSON path via env or arg.
- Reads the config, "applies" the mutation (just emits the `<a4_mutation_applied/>` tag).
- Emits a benign success-path trace stub (no real prover invocation).
- Returns exit code 0.

The mock should be a tiny Python script or stub. **It does not call any Rust code.** This is what makes the smoke cheap.

If no D2.A mock exists, **document this as a missing infrastructure piece** and either:
- (a) Build it in Batch 4 and include in this file.
- (b) Defer the real Layer 5 smoke to D2.E (integration tests), and have Batch 4's 4.2 task be a *unit-test-style* smoke that just calls the fuzzer's mutation-selection logic in a loop without any binary invocation.

**Recommended:** (b) — Batch 4 is not the right place to build infrastructure. Limit 4.2 to a mutation-selection-loop smoke that doesn't invoke any binary. The full Layer 5 mocked smoke (with a mock binary) is deferred to D2.E.

### 4.2.d — Test ID conventions

Name the parametrized test functions clearly so failures localize:
- `test_dispatch_coverage_all_kinds_selected`
- `test_no_exceptions_under_load`
- `test_mutation_outcome_distribution`
- `test_cgc_tag_well_formed`

---

## Task 4.3 — `test_d2b_real_binary_campaign.py` (Layer 5 real-binary, gated, runs on POS)

**Purpose:** End-to-end sanity check that the full A4 pipeline (preflight → mutation → witgen → prover → verifier → outcome telemetry) works for each kind on a real binary, under bandit-driven dispatch (vs the per-kind attestation tests which exercise one kind at a time).

**Gating + dispatch venue:**
- `@pytest.mark.skipif(not os.getenv("A4_REAL_BINARY"), reason="...")` on every test in this file. This matches the existing pattern in every per-kind attestation test.
- **The actual real-binary run is dispatched on POS, not on Ivan's local machine** (Ivan's local hardware is too slow for any campaign-scale work). Composer's job is to **write the test file** and **write the dispatch instructions** so Ivan can launch it on POS. Composer does NOT dispatch on POS themselves — see §POS Dispatch below.
- Composer's pre-commit verification: run the test file locally with `A4_REAL_BINARY=1 A4_SMOKE_N=5 pytest tests/test_d2b_real_binary_campaign.py -v` (N=5 is a quick smoke that finishes in ~5-10 minutes on Ivan's local; just confirms the test file's wiring is correct). The real N=100 run happens on POS post-commit.

### 4.3.a — Mutation count and parametrization

**N = 100 mutations** for the POS run; parametrize via `A4_SMOKE_N` env var (default 100) so Composer can run smaller smokes locally to verify wiring.

| Mode | N | Where | Wall (estimated) |
|------|---|-------|--------------------|
| Composer pre-commit verification | 5–10 | Local | ~5–10 min |
| POS run (post-commit, Ivan dispatches) | 100 | 1 × Tier S node (e.g. `flare`) | ~30–60 min |

Why 100 (up from the original spec's 38):
- POS Tier S is ~8–10× faster than local; the original 38 was a runtime-constrained floor, not a confidence-constrained floor.
- N=100 ensures bandit-driven dispatch pulls all 16 kinds (bandit's early-exploration phase touches each arm; by pull ~32 all are sampled with high probability).
- N=100 keeps the wall budget under 1 hour (well under a POS allocation window).
- Per-kind expected coverage under bandit: live kinds ~8–12 muts each (exploitation phase), dead kinds ~3–5 muts each (exploration only). Both are enough for the assertions below.

### 4.3.b — Campaign parameters

| Parameter | Value | Note |
|-----------|-------|------|
| Binary | `sha2-host` | Consistent with all D2.B attestation work |
| Strategy | `bandit-16` | What production-D2.F will use; test what we ship |
| Seed | 1234 | Single seed; diversity is D2.F's job |
| `--max-mutations` / N | 100 (from `A4_SMOKE_N` env, default 100) | See §4.3.a |
| Coverage DB | Write a single shard locally on the POS node; `pos_upload` to the result folder | Use the standard `a4 fuzz` invocation as in IV.POS.4 |
| `A4_REAL_BINARY` | `1` | Gates the test |
| `A4_FAMILY_RESIDUE` | `1` | Enables Hook 3 channel-3 emission (consistent with all other attestation runs) |

### 4.3.c — Required assertions inside the test

After the campaign run completes (Composer encodes these in the test file; Ivan runs them post-POS-dispatch by copying the result DB back and re-running pytest pointing at it):

1. **Mutation count:** at least `0.8 * N` mutations were attempted (some may be skipped due to step-validity filters).
2. **All-kinds-selected:** every kind in `MUTATION_KINDS` (16) was selected at least once.
3. **Live-kind rejection rate sanity:** at least one mutation per live kind (11) produced a rejection signal (constraint failure or family residue or verify-segment panic). If a live kind produces ZERO rejections across all its attempts, **fail loudly** — regression indicator.
4. **Dead-kind silence (regression sentinel):** all attempts on the 5 dead kinds (B.3, B.4, B.5, B.6, B.7) produced **no rejection** per the proven W-17/W-18 mechanism. If a dead kind suddenly fires a rejection, **fail loudly** — the audit was wrong and we need to investigate.
5. **Coverage DB record count:** the campaign wrote N records to the DB matching the attempted-mutation count.

These assertions read the local coverage DB shard from the POS run. Composer structures the test so that after Ivan rsyncs the DB back to `a4/runs/d2b_pos_smoke/<node>/...`, running `A4_REAL_BINARY=1 A4_SMOKE_DB=<path>.db pytest tests/test_d2b_real_binary_campaign.py -v` evaluates the assertions on the POS-collected data.

**Critical:** assertion 4 makes the dead kinds **active regression sentinels** — any future RISC-0 architecture change that makes a dead arm live will show up here as a failed assertion. This is the long-term value of keeping the dead kinds wired in the test suite (separate from the per-kind attestation xfails, which are static documentation).

### 4.3.d — POS Dispatch (what Composer writes, what Ivan runs)

**Composer's deliverable for POS:** in addition to the test file, write a short dispatch HOWTO in the Batch 4 report (`D2B_BATCH4_COMPOSER_REPORT.md`) so Ivan can execute the POS run without further instructions.

**Required reading before writing the HOWTO:** `a4/docs/precloud/POS_PLAYBOOK.md` **end-to-end at least once**, then re-read with focus on:
- **§★ Canonical Dispatch Templates** (top of file) — `chain_dispatcher.sh` is the current default; `dispatch_audit.sh` is the simpler single-manifest fallback.
- **§3.4–§3.5** — tier-aware node assignment (Tier S = EPYC 9354; Tier A = EPYC 7543).
- **§4** — image (`debian-bookworm`) + bundle preparation (`a4/pos/prepare_bundle.sh`).
- **§5.4** — KEY INVARIANTS (no `--env`, infile shebang, `await_id` is 1-arg, `free` is one-shot, max 2 future allocations).
- **§6** — end-to-end workflow diagram.
- **§12 Anti-patterns** — ALL of them. The whole section is "things we've already tripped on". The most relevant for a single-job smoke: §12.36 (single-job allocation pattern), §12.37 (`ALLOC_DURATION=0` claims pre-reserved calendar entry; `=120` makes a new one), §12.43 (never `free <node>` without `-k` if you own the calendar entry), §12.45 (node hung in `ERR booting` → substitute, don't retry).

**Composer does NOT execute any POS commands themselves.** All Composer does is:
1. Write `test_d2b_real_binary_campaign.py` (gated; parametrized by `A4_SMOKE_N` and `A4_SMOKE_DB`).
2. Write the dispatch HOWTO in the Batch 4 report.
3. Optionally: copy an existing manifest as a template and adapt — recommended template is `a4/pos/manifests/iv_pos_8/d1a_b1.json` (most recent IV.POS.8 schema). Save the new manifest to `a4/pos/manifests/iv_pos_8/d2b_smoke.json`.

**The HOWTO Composer writes should look approximately like this** (Composer fills in the manifest details):

```markdown
### Running D2.B Batch 4 task 4.3 on POS

1. From local machine, build bundle on the current `cloud2` HEAD:
   bash a4/pos/prepare_bundle.sh
   # → bundles/a4_campaign_<git-short>.tar.gz

2. SCP to coinbase:
   scp -P 10022 bundles/a4_campaign_<git>.tar.gz ivgreiff@coinbase.net.in.tum.de:~/

3. SSH to coinbase + activate venv:
   ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
   source /srv/testbed/pos/cli/venv3/bin/activate
   cd ~/arguzz

4. Verify reservation covers a Tier S node (e.g. flare):
   pos nodes show flare -l processor   # expect EPYC 9354
   pos allocations list -f mine

5. Dispatch (single-manifest, fits §12.36 pattern):
   ALLOC_DURATION=0 bash a4/pos/dispatch_audit.sh \
       a4/pos/manifests/iv_pos_8/d2b_smoke.json \
       flare

6. Wait for job to finish (~30–60 min); monitor with:
   tail -f /tmp/dispatch_audit_<ts>.log

7. Copy the result DB back to local:
   scp -P 10022 -r ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4/d2b_smoke/<ts>/flare/ ./a4/runs/d2b_smoke/

8. Evaluate assertions:
   A4_REAL_BINARY=1 A4_SMOKE_DB=a4/runs/d2b_smoke/.../d2b_smoke.db \
       pytest a4/standalone/tests/test_d2b_real_binary_campaign.py -v
   # expect: 1 passed (or named subtests)
```

**The actual manifest Composer creates** (`a4/pos/manifests/iv_pos_8/d2b_smoke.json`) should be a minimal single-job manifest cloned from `d1a_b1.json` with these parameters adapted:

- Job name: `d2b_smoke_v1`
- Strategy: `bandit-16`
- Binary: `sha2-host` (path as the existing template uses)
- Seed: `1234`
- N: `100`
- Env vars to set (per playbook §5.4 invariant — passed via `pos_set_variable`, not `--env`): `A4_REAL_BINARY=1`, `A4_FAMILY_RESIDUE=1`, plus whatever flags the bandit campaign needs.
- Output DB filename: `d2b_smoke_bandit_seed1234_n100.db`

Composer should **not** invent new manifest structure; just adapt the existing template field-by-field.

### 4.3.e — Pre-commit local smoke (Composer's responsibility)

Before committing Batch 4, Composer runs:

```bash
A4_REAL_BINARY=1 A4_SMOKE_N=5 pytest a4/standalone/tests/test_d2b_real_binary_campaign.py -v
```

N=5 finishes in ~5-10 min on Ivan's local hardware. This confirms:
- The test file's wiring is correct (campaign runs without crash).
- The assertions evaluate on a tiny DB (some assertions may "trivially pass" or be `pytest.xfail` at N=5 because bandit can't realistically cover 16 kinds in 5 pulls — that's fine; the wiring is what we're checking).

Document the N=5 result in the Batch 4 report ("local pre-commit smoke: N=5, X mutations attempted, no crashes, wiring confirmed; POS N=100 run pending Ivan dispatch per §4.3.d HOWTO").

---

## Task 4.4 — Update master plan (v0.13 → v0.14)

In `a4/docs/cloud2/IV_POS_8_D2_PLAN.md`:

1. **Bump version header** to `v0.14`.
2. **Update §8 task breakdown** — mark D2.B as `FEATURE-COMPLETE (postscript pending Opus)`.
3. **§9c postscript section** — add a status line: `Status: Pending. Triggered by Batch 4 commit.`
4. **Reading order** — add a top-level reference to [`IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md) as the Pro-facing reference for D2.B.
5. **Watchlist** — mark W-17b (campaign exclusion) as "ready for execution by Opus."

**Do NOT** remove any kinds from `MUTATION_KINDS` in Batch 4. That's the postscript.

---

## Task 4.5 — `D2B_BATCH4_COMPOSER_REPORT.md`

Standard composer report template (follow the Batch 1/2/3 report shape):

- **Executive summary** — what was delivered, test counts before/after.
- **Per-task report** — for each of 4.1–4.4, what was implemented and what the test results look like.
- **Test counts** — final pytest output (e.g., `545 passed, 7 xfailed`).
- **Smoke results** — for 4.2: dispatch coverage table, outcome distribution. For 4.3 (if A4_REAL_BINARY was set): per-kind rejection rate, dead-kind silence confirmation.
- **Files changed** — comprehensive list.
- **D2.B closure checklist:**
  - ☐ All 8 D2.B kinds implemented with Python + Rust + attestation
  - ☐ 4-channel rejection model integrated
  - ☐ Soundness guard wired
  - ☐ NFP-11 documented (Opus)
  - ☐ Mechanism report drafted (Opus)
  - ☐ §9c postscript pending (Opus)
- **Open items for D2.C** — nothing should be blocking; if there is, flag it.

---

## Pre-kickoff sanity (run before writing code)

```bash
cd /root/arguzz
git rev-parse --abbrev-ref HEAD   # → cloud2
git log --oneline -5
# Should show the Batch 3 commit + W-18 audit at HEAD
git status                         # Should be clean before Batch 4 starts

# Confirm Batch 3 deliverables are in place:
ls a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py
ls a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py
ls a4/standalone/tests/test_d2b_cycle_pc_mod_attestation.py
ls a4/standalone/tests/test_d2b_cycle_state_mod_attestation.py
ls a4/standalone/tests/test_d2b_cycle_diff_count_mod_attestation.py
ls a4/docs/cloud2/composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md
ls a4/docs/cloud2/IV_POS_8_D2_B_MECHANISM_REPORT.md   # new Opus doc

# Confirm pytest baseline is green (excluding xfails for dead kinds):
cd a4/standalone && pytest tests/ -x -q --tb=no  # should pass; expect ~545-passed, ~5-7 xfailed
```

If any of those checks fail, **stop and report** before proceeding.

---

## Acceptance criteria

A Batch 4 commit is acceptable when **all** of the following hold:

| # | Criterion | How verified |
|---|-----------|--------------|
| 1 | `test_d2b_arm_registration.py` created, all 96 logical parametrized cases pass (or skip with documented reason) | `pytest tests/test_d2b_arm_registration.py -v` |
| 2 | `test_d2b_campaign_smoke.py` created, 4 logical tests pass on mocked/loop smoke | `pytest tests/test_d2b_campaign_smoke.py -v` |
| 3 | `test_d2b_real_binary_campaign.py` created, gated on `A4_REAL_BINARY=1`, default-skipped; **N=5 local pre-commit smoke executed successfully** (Composer); **POS HOWTO + manifest written for Ivan** | `pytest tests/test_d2b_real_binary_campaign.py -v` → all skipped without env var; `A4_REAL_BINARY=1 A4_SMOKE_N=5 pytest ...` runs successfully; HOWTO in Batch 4 report; manifest at `a4/pos/manifests/iv_pos_8/d2b_smoke.json` |
| 4 | Plan bumped to v0.14, D2.B marked feature-complete-postscript-pending | Read the file |
| 5 | `D2B_BATCH4_COMPOSER_REPORT.md` written | Read the file |
| 6 | **No kinds removed from `MUTATION_KINDS`** — the registry is identical to post-Batch-3 | `git diff` shows no changes to `A4Fuzzer.MUTATION_KINDS` |
| 7 | **No new mutation kinds added** — Batch 4 is test-only | `git diff` shows no new files under `a4/standalone/mutations/` |
| 8 | **No Rust handler changes** — `mod.rs` is unchanged from post-Batch-3 | `git diff workspace/risc0-modified/...` is empty |
| 9 | Full suite passes: `pytest tests/ -x` returns 0 (with documented xfails for dead kinds remaining) | Full pytest run |

---

## Out of scope for Batch 4

These are explicitly **NOT** Batch 4's job:

- **Removing dead kinds from `MUTATION_KINDS`** — that's the §9c postscript, Opus's task post-Batch-4.
- **Inverting unit-test asserts for dead kinds** — also postscript.
- **Pro check-in materials** — Opus drafts these after the postscript.
- **D2.C kickoff** — comes after Pro check-in.
- **Any new mutation kinds** — D2.B kind set is locked.
- **Any modifications to the existing 8 per-kind unit/attestation test files** — they're complete and locked.
- **Running the POS dispatch yourself** — Composer writes the test file + manifest + HOWTO; Ivan executes the POS dispatch. Do not SSH into coinbase, do not allocate nodes, do not call any `pos` commands. Composer's local pre-commit smoke is at N=5; the full N=100 is Ivan's POS run.
- **Modifying any POS infrastructure** (`a4/pos/dispatch_audit.sh`, `chain_dispatcher.sh`, `run_campaign_pos.sh`, `prepare_bundle.sh`) — these are battle-tested; adding a new manifest is the only POS change in scope.
- **Real-binary smoke at higher N than 100** — bigger volume is D2.F's job, not Batch 4.
- **Building a full mock-binary infrastructure** — if no clean mock exists, use the mutation-selection-loop variant (§4.2.c option (b)).

---

## Common pitfalls (learn from Batch 1–3)

1. **Don't bypass the soundness guard.** The dead-kind attestation tests (B.3, B.4, B.5, B.6, B.7) all assert the guard fires before `pytest.xfail`. Batch 4 inherits this pattern — don't write any new test that `xfail`s without first asserting the guard's expected behavior. (Batch 2 lesson.)
2. **Don't infer "always" from "first valid target".** The smoke tests should iterate across many targets, not just the first step that has a valid txn. (Batch 3 §A2 lesson.)
3. **The `at_write` case is structurally different.** When testing B.1 in the smoke, accept that `at_write` mutations may show no local `<constraint_fail>` and still be live via Hook 3. The 4-channel rejection model is what catches this. (Batch 1 lesson.)
4. **CGC `txn_role` is `addr` for B.4 even though B.4 is dead.** The role mapping reflects what the kind *would* mutate, not whether the mutation is effective. The smoke should validate the mapping is present, not assume the dead-arm finding changes the role taxonomy. (NFP-4 lesson.)
5. **`pytest.xfail` runtime call only accepts `reason`.** No `strict` kwarg. (My earlier API mistake — don't repeat.)
6. **Always commit with the literal "Batch 4"** in the commit message header so future audits can find it via `git log --grep`.
7. **POS manifest must not include `--env KEY=VAL`** — per playbook §5.4 invariant. Per-job parameters go through `pos_set_variable` in the bundled runner script. The existing manifests in `a4/pos/manifests/iv_pos_8/` already follow this — copy their structure.
8. **POS infile scripts MUST start with `#!/bin/bash`** — playbook §5.4 (and §12 anti-pattern). The existing `a4/pos/run_campaign_pos.sh` already does this; if Composer needs a smoke-specific runner, it MUST shebang the first line.
9. **`ALLOC_DURATION=0` claims a pre-existing calendar entry** (playbook §12.37). If Ivan's reservation already covers the node, the HOWTO should use `ALLOC_DURATION=0`. If unsure, the HOWTO should mention both modes.

---

## Suggested commit message

```
d2.b batch 4: cross-cutting + smoke (D2.B feature-complete)

- test_d2b_arm_registration.py: Layer 1 parametrized cross-cutting
  (96 cases across 16 kinds × 6 assertion layers)
- test_d2b_campaign_smoke.py: Layer 5 mutation-selection-loop smoke
  (800 mocked-mutation iterations, dispatch + outcome telemetry)
- test_d2b_real_binary_campaign.py: Layer 5 real-binary smoke
  (gated on A4_REAL_BINARY=1; N=100 default, parametrized by A4_SMOKE_N;
   runs on POS — manifest at a4/pos/manifests/iv_pos_8/d2b_smoke.json;
   dispatch HOWTO in batch report)
- a4/pos/manifests/iv_pos_8/d2b_smoke.json: single-job Tier-S manifest
- Plan v0.14: D2.B feature-complete, §9c postscript pending Opus
- Report: D2B_BATCH4_COMPOSER_REPORT.md

D2.B feature-complete; Opus owns §9c postscript and Pro check-in.
```

---

## Quick answers to Ivan's pre-kickoff questions

**Q1: Will Batch 4 still test the dead arms?**

**A:** Yes, in three distinct ways:

1. **Registration test (4.1):** asserts the dead kinds are still registered in `MUTATION_KINDS`. This is a guardrail against the §9c postscript accidentally running in Batch 4. After the postscript lands, this assertion gets inverted by Opus.
2. **Mocked smoke (4.2):** the round-robin dispatcher will select the dead kinds; the mock binary "applies" them silently. This validates the dispatch path works for all 16 kinds.
3. **Real-binary smoke (4.3):** the dead kinds get ~1 mutation each. The expected outcome is "no rejection" — this is the **regression sentinel** for the dead-arm proof. If a dead kind suddenly fires a rejection here, the audit was wrong and we need to investigate.

After §9c postscript runs (Opus's task post-Batch-4):
- The registration test gets its dead-kind assertion inverted (assert NOT in registry).
- The mocked smoke no longer selects dead kinds (because they're not in `MUTATION_KINDS`).
- The real-binary smoke no longer selects dead kinds.
- The per-kind attestation tests for dead kinds remain on disk as documentation + regression sentinels (they explicitly construct a mutation for the dead kind and assert it produces no rejection).

**Q2: Should we do a higher number of mutations in Batch 4 just to be sure?**

**A:** Yes, modestly. **Bumped from the original spec's 38 → N=100** because the real-binary smoke now runs on POS Tier S (not on Ivan's slow local), making the per-mutation cost ~10× cheaper. N=100 keeps the wall budget under 1 hour while ensuring bandit's early-exploration phase reliably touches all 16 kinds. See §4.3.a for the full reasoning.

The mocked smoke does get a generous mutation count (**800 mocked iterations** = 50 per kind). The mock costs nothing, and bandit-dispatch quality benefits from volume.

Summary: be **generous in mocked smoke** (cheap, high-information), **modest in real-binary smoke on POS** (N=100, ~1 hour wall), and **defer comprehensive real-binary coverage to D2.F**.

---

## After Batch 4 commits — Opus's next moves

For Composer's awareness (no action required):

1. Opus runs the **§9c postscript (D2.B-PS-1)**:
   - Remove `CYCLE_MODE_MOD`, `TXN_ADDR_MOD`, `TXN_CYCLE_PHASE_MOD`, `CYCLE_PC_MOD`, `CYCLE_STATE_MOD` from `A4Fuzzer.MUTATION_KINDS`.
   - Invert the dead-kind registration assertion in `test_d2b_arm_registration.py`.
   - Add a comment block to `MUTATION_KINDS` explaining the W-17/W-18 exclusion.
   - Bump plan to v0.15, mark D2.B fully closed.
   - Single small commit.
2. Opus prepares **Pro check-in materials**:
   - D2.B summary, mechanism report, NFP-11, dead/live split, soundness guard demo.
   - Decision points for Pro on D2.C scope and acceptance of the 11-effective-kinds set.
3. **Pro check-in** — gate for D2.C kickoff.
4. **D2.C kickoff** — V6 kind integration via 3-layer architecture (already drafted at `IV_POS_8_D2_C_SPEC.md` v0.1).

---

*End of kickoff. Questions? Ping Ivan/Opus before writing code. Pre-kickoff sanity must succeed before any new code lands.*
