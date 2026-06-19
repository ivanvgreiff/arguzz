# D2.B Batch 4 — Report Fixup Directive (Composer)

**Status:** Pre-commit cleanup of `D2B_BATCH4_COMPOSER_REPORT.md`.
**Issued by:** Ivan (per Opus's audit).
**Scope:** Report-only edits. **Do not** touch test code, manifest, plan, or registry — those are all correct as committed in working tree.

---

## Why this fixup exists

Opus audited the Batch 4 deliverable end-to-end (independently re-ran every test, queried the POS DB directly, diffed `fuzzer.py` / `mod.rs`, and cross-checked all of Composer's numeric claims). **The deliverable is sound; the report has three numeric errors and a few framing gaps that need to be corrected before commit so the audit trail stays clean for Pro.**

The "Ivan override" claim (§Pushback item 1) is **confirmed legitimate** — Ivan authorized full POS execution out-of-band. No change needed there.

---

## Required fixes (apply in this exact order)

### Fix 1 — Executive summary table row count

**File:** `D2B_BATCH4_COMPOSER_REPORT.md` §Executive summary table.

**Current (wrong):**

```
| 4.1 | `test_d2b_arm_registration.py` | 98 passed, 3 xfailed (NFP-4 txn_role drift) |
```

**Replace with:**

```
| 4.1 | `test_d2b_arm_registration.py` | 94 passed, 3 xfailed (NFP-4 txn_role drift) |
```

**Audit detail:** 6 parametrized layers × 16 kinds = 96 cases + 1 dead-kind guardrail = 97 cases total. Three of those xfail (the 3 NFP-4 drift kinds), leaving **94 passed**. Opus reproduced the count with a clean rerun:

```
======================== 94 passed, 3 xfailed in 0.55s =========================
```

Also update the "Test delta" sentence below the table:

**Current:** "+98 parametrized registration cases + 4 smoke + 1 gated real-binary evaluator (~103 new logical cases; 1 skipped without `A4_REAL_BINARY`)."

**Replace with:** "+97 parametrized registration cases (94 passed, 3 xfailed) + 4 smoke + 1 gated real-binary evaluator (~102 new logical cases; 1 skipped without `A4_REAL_BINARY`)."

---

### Fix 2 — Task 4.1 bash example output

**File:** §Task 4.1 — arm registration.

**Current (wrong):**

```bash
cd a4/standalone && PYTHONPATH=/root/arguzz pytest tests/test_d2b_arm_registration.py -q
# 93 passed, 3 xfailed
```

**Replace with:**

```bash
cd a4/standalone && PYTHONPATH=/root/arguzz pytest tests/test_d2b_arm_registration.py -q
# 94 passed, 3 xfailed
```

(Same arithmetic as fix 1.)

---

### Fix 3 — Dead-kind attempt total

**File:** §Pushback item 3 — "11 live kinds" — CLARIFIED.

**Current (wrong):**

```
| Dead (5) | B.3–B.7 | 0 rejections (21 total attempts) |
```

**Replace with:**

```
| Dead (5) | B.3–B.7 | 0 rejections (27 total attempts) |
```

**Audit detail:** Per-kind dead-arm pulls in the POS DB:

```
CYCLE_MODE_MOD:        6 attempts, 0 rejections
CYCLE_PC_MOD:          7 attempts, 0 rejections
CYCLE_STATE_MOD:       6 attempts, 0 rejections
TXN_ADDR_MOD:          6 attempts, 0 rejections
TXN_CYCLE_PHASE_MOD:   2 attempts, 0 rejections
                       ─────────────────────────
Total:                27 attempts, 0 rejections
```

This **27** is exactly the number the fuzzer printed as "27 potential bugs!" in §Pushback item 6 — see Fix 4 below.

---

### Fix 4 — Reframe "27 potential bugs" (§Pushback item 6)

**Current:**

```
### 6. Campaign exit_code=2 on POS — INFORMATIONAL

`run_campaign_pos.sh` reported rc=2 after fuzzer printed "27 potential bugs!" — DB complete (100 mutations, meta `exit_code: 2`). Dispatcher await also hit transient HTTP errors (poslib); results uploaded via EXIT trap. Smoke assertions pass on DB content.
```

**Replace with:**

```
### 6. Campaign exit_code=2 on POS — EXPECTED EMPIRICAL SIGNATURE (not a soundness suspicion)

`run_campaign_pos.sh` reported rc=2 after the fuzzer printed "27 potential bugs!" — DB complete (100 mutations, meta `exit_code: 2`). The dispatcher await also hit transient HTTP errors (poslib); results uploaded via EXIT trap. **All smoke assertions pass on DB content** because the 27 cases are the exact predicted set:

The fuzzer's "potential bug" counter increments whenever a mutation is APPLIED, the trace bytes were demonstrably changed in Python preflight, and the verifier still accepts the proof. Under the W-17/W-18 mechanism (see [`../IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md) §5–§8 and the audits [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md), [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md`](./D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md)), this is exactly the empirical signature we expected for the 5 dead arms: the trace fields they mutate are overwritten by `set_cycle` (W-17) or excluded from the extern return tuple (W-18) before they reach the witness, so the proof correctly verifies despite the trace mutation.

The smoke-test regression sentinel (`evaluate_campaign_db`'s strict-mode dead-kind assertion) is precisely what converts "27 unexplained verifier-accepts" into "27 expected dead-arm verifier-accepts." Cross-validation:

| Dead kind | Attempts | Rejections | Predicted by audit |
|-----------|----------|------------|---------------------|
| `CYCLE_MODE_MOD` (B.3) | 6 | 0 | W-17 dead |
| `CYCLE_PC_MOD` (B.6) | 7 | 0 | W-17 dead |
| `CYCLE_STATE_MOD` (B.7) | 6 | 0 | W-17 dead |
| `TXN_ADDR_MOD` (B.4) | 6 | 0 | W-18 dead |
| `TXN_CYCLE_PHASE_MOD` (B.5) | 2 | 0 | W-18 dead |
| **Total** | **27** | **0** | matches fuzzer's "27 potential bugs!" |

If any of these 27 had fired a rejection, `evaluate_campaign_db` would have failed strict-mode — that's the long-term regression sentinel value of keeping the dead kinds wired in this test (separate from the per-kind attestation xfails, which are static documentation).
```

---

### Fix 5 — Honestly document criterion #3 (local N=5) as not-met

**File:** §Pushback item 4 — "Local N=5 pre-commit smoke — PARTIAL / DOCUMENT."

**Current ends with:**

```
Recommendation for kickoff v2: local wiring smoke at N=60 minimum for bandit, or use A4_SMOKE_DB from POS only.
```

**Append the following paragraph below it:**

```
**Compliance note:** Kickoff acceptance criterion #3 specifies "N=5 local pre-commit smoke executed successfully." This was attempted, hit a test bug (now fixed in working tree), and was **not re-run locally** — the POS N=100 evaluation took its place. Criterion #3 is therefore **not met as written**, but the equivalent confidence signal (real-binary campaign smoke against a sufficient-N DB) is delivered via POS, which is a strictly stronger validation (16/16 kinds covered, dead-arm regression sentinel exercised, strict-mode assertions active). Recommend treating this as a kickoff-text bug rather than a deliverable bug, and adopting "local N≥60 OR `A4_SMOKE_DB` from POS" as the criterion language in any future analog kickoff.
```

---

### Fix 6 — Clean-commit POS caveat

**File:** §Task 4.3 — real-binary smoke + POS, just before the "POS results" table.

**Insert this paragraph:**

```
**Bundle-commit caveat:** the POS bundle was built with `prepare_bundle.sh --allow-dirty --skip-host-sha`, so the meta.json's `git_commit` field records the Batch 3 head (`4e5150a7a725...`) plus a dirty overlay of the Batch 4 test files. The host_sha256 is still recorded (`24f23a0de02b...`); `--skip-host-sha` only disabled validation, not recording. For the registry/mod.rs invariants this is moot — both are unchanged from Batch 3 — but a clean-commit POS re-validation can be requested by Pro if needed for the audit trail. The smoke assertions evaluated against the resulting DB are unaffected.
```

---

## What stays unchanged

- All test code, manifest, plan v0.14 bump — unchanged. Opus re-ran each test and verified.
- The §Pushback item 1 ("Ivan override") claim is correct — Ivan authorized POS end-to-end. No edit needed there.
- The D2.B closure checklist is correctly populated.
- The §Files changed table is accurate.
- The §Opus follow-ups list is accurate.

---

## Verification command after fixes

```bash
# These three numbers should now appear in the report:
grep -E "94 passed|27 total attempts" a4/docs/cloud2/composer/D2B_BATCH4_COMPOSER_REPORT.md

# Expected output (three lines):
#   | 4.1 | `test_d2b_arm_registration.py` | 94 passed, 3 xfailed (NFP-4 txn_role drift) |
#   # 94 passed, 3 xfailed
#   | Dead (5) | B.3–B.7 | 0 rejections (27 total attempts) |
```

Once the six fixes are applied, Ivan will commit Batch 3 docs + mechanism report + Batch 4 deliverables together, then Opus will execute the §9c postscript.

---

*End of fixup directive.*
