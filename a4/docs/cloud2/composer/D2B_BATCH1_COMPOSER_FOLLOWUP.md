# D2.B Batch 1 — Composer Follow-up Report (Opus review fixes)

**Date:** 2026-06-18  
**Status:** Fixes #1–#3 + #5a landed in working tree; **NOT committed** (awaiting Opus re-review)  
**Blocker:** `at_write` attestation triggers **SoundnessBugSuspected** — see Issue #2b below

---

## Opus items addressed

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Phantom arm test → `V5_CONTROL_KINDS_8` | ✅ | `test_v5_phantom_arm_pruning.py` pinned; bounds 44–52 |
| 2 | `test_layers_2_3_4_at_write` | ⚠️ Partial | Test added; **soundness guard fires** (see #2b) |
| 3 | Use `assert_trace_diff_matches_signature` | ✅ | Both attestation methods; fixed helper to use global `txn_idx` |
| 4 | Commit "Batch 1.5e" | ⏸ | Not committed per Opus instruction |
| 5 | Full suite re-run | ✅ | See pytest section |
| 5a | §5.3 spec hygiene | ✅ | B.1/B.2 rows clarified (trace vs constraint cascade) |

**Extra fix:** `collect_txn_field_diffs` now uses dict `txn_idx` field (was using zip index → false failures with signature helper).

**Nit:** `test_d2b_pre_exec_reg_mod_two_strategy.py` import changed to module import (avoids pytest double-collection).

---

## Issue #2b — SOUNDNESS GUARD on `at_write` (STOP per Opus)

**Observed:** `test_layers_2_3_4_at_write` passes Layers 2–3 (evidence tag + post-mut dump + strict signature with `cascade=[]`), then **`check_soundness_bug_guard` raises `SoundnessBugSuspected`**.

**Manual repro (same target as test):**
- Target: step 1, txn_idx 15417, strategy `at_write`
- `<a4_txn_prev_word_mod>` emitted ✅
- `<a4_post_mut_dump>` shows `prev_word` changed ✅
- `parse_all_constraint_failures()` → **0 failures**
- No `<a4_error>`
- Only diagnostic: `<a4_fault_injection_enabled/>`

**`at_read` on same trace:** PASS including soundness guard (constraint failures present).

**Interpretation (for Opus/Ivan):** Not a signature-helper false positive — the witness run genuinely accepts (or at least emits no parsed constraint failures) after a trace edit that Layer 3 confirms. This is exactly §9b / NFP candidate territory. **Did NOT relax signature or disable guard** per Opus guidance.

**Next decision needed before merge:**
1. Is this expected for early-step WRITE `prev_word` on sha2-host (document + adjust guard criteria)?
2. Is CONSTRAINT_CONTINUE / failure tag parsing missing WRITE-path failures?
3. Is this a real soundness concern requiring Pro disclosure?

---

## Pytest results (post-fix)

### Targeted
```text
pytest test_v5_phantom_arm_pruning.py test_d2b_txn_prev_word_mod_unit.py test_d2b_pre_exec_reg_mod_two_strategy.py -q
14 passed in 131.31s
```
(1 phantom + 13 D2.B unit — golden trace no longer double-collected in retrofix file)

### Attestation (`A4_REAL_BINARY=1`)
```text
test_layers_2_3_4_at_read   PASSED  (~104s)
test_layers_2_3_4_at_write    FAILED  SoundnessBugSuspected (~104s)
1 failed, 1 passed in 207.95s
```

### Full suite (default, no `A4_REAL_BINARY`)
```text
pytest a4/standalone/tests/ -q
527 passed, 9 skipped, 0 failed in 821.69s (~13m41s)
```
*(527 items collected; attestation `at_write`/`at_read` skip without `A4_REAL_BINARY=1`)*

Expected skips: attestation (2 without env), other gated host tests.

---

## Files changed in this follow-up

| File | Change |
|------|--------|
| `test_v5_phantom_arm_pruning.py` | `V5_CONTROL_KINDS_8`, bounds 44–52, comment |
| `test_d2b_txn_prev_word_mod_attestation.py` | Shared runner, `at_write` test, signature helper |
| `_test_helpers/diff_signature.py` | `txn_idx` from dict in diffs |
| `test_d2b_pre_exec_reg_mod_two_strategy.py` | Module import for golden trace |
| `IV_POS_8_D2_B_SPEC.md` | §5.3 B.1/B.2 wording |

---

## NFP-10 guard (unchanged)
```text
grep byte_addr a4/standalone/compressed_global_extractor.py → line 217 preserved
```
