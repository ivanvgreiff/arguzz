# Phase 7d — Composer Brief

> **READ ORDER (do this once before starting any work):**
> 1. **`phases/PHASE_7D_ORCHESTRATION.md`** — master chronological plan; gates between every increment; review templates. **This is your single source of truth.**
> 2. This brief (orientation + pre-fixes).
> 3. `composer/PHASE_7D_INCREMENTS.md` (per-increment task tables).
> 4. `phases/PHASE_7D_ARCHITECTURE_AUDIT.md` (full spec for every audit).
> 5. `cloud1/GLOSSARY.md` — **MANDATORY: every variable name, abbreviation, magic number used in audit output. Reference this in every audit output file.**
> 6. `cloud1/EXPECTED_ARMS.md` (canonical arm matrix; 22 🟡 markers + Q1-Q8 open questions to resolve in Inc 1).
>
> Do NOT start Phase 8 work — Phase 8 is BLOCKED on Phase 7d.
> Do NOT start Phase 10 work — multi-guest verification is deferred (post-Phase 8). Phase 7d only verifies the 48 arms of our current guest.
>
> **Workflow:** complete Increment N → write `composer/PHASE_7D_INC<N>_REPORT.md` → STOP and wait for Opus's GREEN response → start Increment N+1. No batching, no skipping. Increment 0 is next.

## Verdicts on your recently-closed Task 3/4/5

You reported these as closed but Opus is overriding two of them:

- **Task 3 (V5 N=200 validation) → ACCEPTED.** Numbers check out (48×3=144 cold exactly; 56 remaining = 44 floor + 12 singleton matches the math). Bug A/B fixes are real. Use this as runtime evidence in Increment 0's report; it gives us confidence the bandit architecture WORKS, but does not substitute for the formal audits (B3, B4, B7).
- **Task 4 (G2 verifier 24/24) → REJECTED as G2 closure.** Same rev2 result Opus already critiqued in earlier message: `if original_value:` short-circuits on 21/24 word-mutating samples and never compares hook.old_word vs DB.original_value; the INSTR_TYPE_MOD id=12 step=0 cycle-shift bug is silently missed because the verifier doesn't check hook.old vs config.exp_old. **G2 stays OPEN until Audit B1 with strict mode + uniform `original_value` passes.** Do not mark G2 closed in CLOUD1_STATUS or DECISIONS docs.
- **Task 5 (compressed_global 0 → 37) → ACCEPTED PROVISIONALLY.** Fix works empirically (37 contexts on 200 mutations is reasonable ~18%). Audit B10 will formally verify the regions are bucketed per the new D8 platform.rs map. Move forward.

---

## 0. TL;DR — what changed and why

After reviewing your Phase 7 fixes and the Task 4 (24/24) verifier output,
Opus found three real gaps:

1. **The Task 4 verifier silently skipped its own old-value check on
   21/24 word-mutating samples** because `if original_value:` short-circuits
   when `original_value == 0` and most kinds don't populate that field.
2. **Task 4 also missed a real cycle-shift bug** in INSTR_TYPE_MOD id=12
   step=0 (hook old=7/0 ECALL, config exp_old=2/6 AddI) — the mutation
   landed on the wrong cycle at a multi-cycle step and the verifier didn't
   compare hook.old vs config.exp_old.
3. **We have no end-to-end audit that proves the bandit's selected arm is
   the one that actually got executed and rewarded** for any variant.
4. **Some of our zone/arm categorizations are UNCERTAIN** (22 of 48 arms tagged 🟡 in EXPECTED_ARMS.md). For these we made a categorization choice without external evidence; if the choice is wrong, the bandit pulls "core_div" but is actually exploring shift-right behavior, or pulls "MEM_VAL_MOD|core_branch" on memory txns that aren't actually constraint-checked.

These are not "tweaks" — they are gaps big enough that V5 vs V1 results
in Phase 8 would be uninterpretable. So Phase 7d is a new gating phase
with **16 audits** (A1-A5, B1-B12, E1-E4) organized into two sub-phases:

| sub-phase | audits | gate |
|---|---|---|
| 7d.1 | A1–A5 + E1 + E3 (semantics & arms, including instruction-decode ground truth and uncertain-arm review) | run BEFORE 7d.2 |
| 7d.2 | B1–B12 + E2 + E4 (variants & isolation + arm-bite report + manual review queue) | run AFTER 7d.1 green |

Phase 8 stays blocked until ALL audits exit 0 on the SAME code path, EXPECTED_ARMS.md has zero 🟡 rows, and the E4 review queue has zero PENDING items.

Opus has already done:
- Drafted `phases/PHASE_7D_ARCHITECTURE_AUDIT.md` (full spec).
- Drafted `cloud1/EXPECTED_ARMS.md` (canonical kind×zone matrix with 🟡/🟢/🔵 status markers; sha2-host baseline filled).
- Drafted `composer/PHASE_7D_INCREMENTS.md` (your day-to-day increment plan).
- Implemented + ran **A1, A2, A3** on baseline. All three PASS. Scripts at `a4/audits/A{1,2,3}_*.py`. Output at `a4/audits/audit_output/`.

Your job (follow `PHASE_7D_INCREMENTS.md` step by step):
1. **Increment 0** — land 3 pre-fixes (§1 below).
2. **Increment 1** — implement A4, A5, E1, E3. **Joint review session with user/Opus** to adjudicate 🟡 arms.
3. **Increment 2** — implement B3, B5, B6, B9, B10, E2 (cheap local audits).
4. **Increment 3** — implement B1, B2, B4, B7 (fidelity audits).
5. **Increment 4** — dispatch B8, B11, B12 on POS.
6. **Increment 5** — E4 wrap + Opus writes final report.

**Report back after each increment. Wait for green-light before starting the next.**

---

## 1. Pre-fixes you must land FIRST (before any 7d.2 audit)

These are required by B1, B2, B4. Do them in this order:

### 1.1 — Verifier strict mode

File: `a4/tools/verify_mutation_semantics.py`

- Change every `if original_value:` short-circuit to `if original_value is not None:` so that `original_value == 0` is treated as a real check, not a skip.
- For INSTR_TYPE_MOD: add `hook["old_major"] == cfg["_info"]["original_major"] and hook["old_minor"] == cfg["_info"]["original_minor"]` check. If mismatch, the verifier returns FAIL with reason `cycle_shift_at_step`.
- Re-run on the existing Phase 7c rev2 sample set. EXPECT FAILURES — that is the point. Do not relax the gate; fix the underlying bugs (which will be Pre-fix 1.2 and 1.3 below) and re-run until you get a clean PASS.

Acceptance: verifier on the same 24 samples reveals exactly one INSTR_TYPE_MOD failure (id=12 step=0) at first. After 1.2 + 1.3 land, all 24 pass.

### 1.2 — Uniform `original_value` recording

Files: `a4/standalone/mutations/*.py` (all 8 modules), `a4/standalone/fuzzer.py`, `a4/standalone/coverage_db.py`

- Every mutation kind's `create_config()` MUST place the pre-mutation
  value in `config["_info"]["original_value"]` (same field name across all
  kinds; for INSTR_TYPE_MOD keep `original_major`/`original_minor` as well).
  For COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD,
  INSTR_WORD_MOD_FULL, INSTR_WORD_MOD_SUR, MEM_VAL_MOD: this is the txn's
  `word` field before mutation.
- Add a new column to the `mutations` table: `original_value INTEGER NOT
  NULL DEFAULT 0`. Migration test: read an old DB without the column
  (e.g. one of the `a4/runs/...` DBs), confirm migration succeeds and
  populates 0 for old rows.
- The fuzzer passes `original_value` (already returned by `_create_mutation`) to `db.record_mutation()`.

Acceptance: after running a fresh smoke at N=50, `SELECT COUNT(*) FROM mutations WHERE original_value = 0 AND kind NOT IN ('INSTR_TYPE_MOD')` is small (only mutations targeting genuinely-zero baseline values). Compare against `SELECT COUNT(*) FROM mutations` — expect at most ~10% zeros (not 100% as today).

### 1.3 — Multi-cycle step disambiguation (D40)

This is the fix for the INSTR_TYPE_MOD id=12 step=0 bug. Two options:

**Option (a) — `cycle_idx` in config (precise; requires Rust rebuild)**
- Extend mutation config schema with `cycle_idx` field (the index into `data.cycles[]` for the cycle to mutate, not just the step).
- Update Rust hook in `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` to consume `cycle_idx` when present and apply mutation only to that exact cycle.
- Update `a4/standalone/fuzzer.py::_create_mutation` to populate `cycle_idx` from the target.

**Option (b) — drop multi-cycle steps from universe (cheaper; no Rust rebuild)**
- In `_step_has_real_target` in `semantic_arm_universe.py`: count how many cycles at the step match the kind's major filter; if > 1, return False.
- Verify with A3 that this drops at most 4 additional arms.

**Pick option (b) unless it drops > 4 arms.** Document the choice as **D40 in `cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md`** with the arm-count cost and rationale.

Acceptance: after the fix, B2 audit (`a4/audits/B2_multicycle_replay.py`)
re-runs the INSTR_TYPE_MOD id=12 step=0 case (or its replay equivalent
on the post-fix universe) and the strict verifier returns PASS.

---

## 2. Audit work — see PHASE_7D_INCREMENTS.md for the per-day plan

Do not skip ahead. `composer/PHASE_7D_INCREMENTS.md` breaks the 16 audits
into 6 increments, each with:
- Specific scripts to write (with rough LOC estimates)
- Acceptance gate per audit
- Estimated time
- What to put in the per-increment report
- A clear "stop here, wait for green-light" checkpoint

If an audit specification is unclear, the source of truth is
`phases/PHASE_7D_ARCHITECTURE_AUDIT.md` (one section per audit with full
goal / why-it-matters / acceptance / failure-handling).

If a CATEGORIZATION question is unclear (e.g., "which steps actually
belong to core_div?"), the source of truth is `cloud1/EXPECTED_ARMS.md`
which lists 8 open questions (Q1-Q8) that the E-audits answer.

---

## 3. Resources

- Audit specs: `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md`
- Canonical matrix: `a4/docs/cloud1/EXPECTED_ARMS.md`
- Existing audit scripts: `a4/audits/A{1,2,3}_*.py`
- Existing baseline output: `a4/audits/audit_output/A1_nondet_addrs.json`, `a4/audits/audit_output/A3_arms_in1_5_in4_10.json`
- Pre-fix scope:
  - `a4/tools/verify_mutation_semantics.py` (§1.1)
  - `a4/standalone/mutations/*.py` + `coverage_db.py` + `fuzzer.py` (§1.2)
  - `a4/standalone/semantic_arm_universe.py` OR Rust hook + `fuzzer.py::_create_mutation` (§1.3)
- POS allocations:
  - B8: ~1 hr POS (5 sequential + 5 parallel @ N=50)
  - B11: ~6 hrs POS (5 × N=500)
  - B12 alternate inputs: ~1 hr POS (or local)

---

## 4. Anti-patterns to AVOID (lessons from Phase 7)

- ❌ Do NOT relax an audit's gate when it FAILS — fix the bug; the audit
  exists to catch the bug.
- ❌ Do NOT pre-populate "expected to fail" fields with default values to
  make audits pass (this is what made Task 4's 24/24 misleading).
- ❌ Do NOT call an audit "DONE" until it has been re-run on a clean code
  path with all dependencies landed.
- ❌ Do NOT run Phase 8 acceptance numbers (e.g. mode != 'cold' ≥ 1 from
  Task 3) as if they're 7d gates. Those are sanity checks; the real
  gates are A/B/E audits.
- ❌ Do NOT add hard-coded `_PHANTOM_ARMS_PRODUCTION_TRACE` allow-lists
  (you wrote one in `semantic_arm_universe.py` that's currently dead
  code — please remove it; the per-step pruning supersedes it).
- ❌ Do NOT mark Task 4 / G2 as closed based on the 24/24 from rev2.
  Opus has rejected that closure (see top of this brief). G2 closes via
  Audit B1 in Increment 3.
- ❌ Do NOT skip the E3 multi-classification probe by relabeling 🟡 arms
  to 🟢 without the dossier + adjudication. The 🟡 arms exist because we
  don't know what they're actually doing; assuming they're fine defeats
  the audit.

- ✓ DO write each audit so it produces a JSON artifact in
  `a4/audits/audit_output/` for reproducibility.
- ✓ DO commit ALL audit scripts to git (even the local-only ones).
- ✓ DO record any deviation from the spec in `composer/PHASE_7D2_REPORT.md` with the reason.

---

## 5. Open questions you can flag back (do not wait for answers; proceed where unambiguous)

- For B11 N=500: if any audit takes > 90 min for a single variant on POS, ping back so we can decide whether to scale down or split.
- If D40 option (b) drops more than 4 arms, ping back BEFORE implementing — we may need (a) instead.
- If B7 reproducibility fails on a variant due to RNG plumbing, ping back with the diff before patching the RNG (it might indicate a real bug worth fixing properly).

That's the brief. Begin with §1.1 (verifier strict mode), then §1.2, then
§1.3, then 7d.1 audits A4/A5, then 7d.2 audits in the order listed in §2.2.
