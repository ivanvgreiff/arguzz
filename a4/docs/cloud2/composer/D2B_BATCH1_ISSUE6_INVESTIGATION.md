# D2.B Batch 1 — Issue #6 Investigation Report

**Date:** 2026-06-18  
**Subject:** `at_write` attestation `SoundnessBugSuspected` — root cause analysis  
**Verdict:** **NOT a soundness bug (Hypothesis A rejected).** Guard false positive due to incomplete rejection-channel coverage. **Hypothesis B rejected** on this trace. **Hypothesis C confirmed** (failure via prover panic, not `<constraint_fail>` tags).

---

## Executive summary

`TXN_PREV_WORD_MOD` **`at_write`** mutations **do break the trace** (Layer 2+3 pass) and **do cause proof rejection**, but rejection appears as:

- `exit_code=101`
- stderr: `panicked at host/src/main.rs:150:13: verify segment`
- stdout: `<record>{"context":"Prover", "status":"error", ...}`

There are **zero** parsed `<constraint_fail>` tags on the `at_write` path, while **`at_read`** on the same step emits `IsRead@mem.zir:79`.

The production fuzzer **already treats `"verify segment"` as effective rejection** (`fuzzer._check_proof_verification_failure`). The attestation soundness guard did not — hence the false alarm.

**Fix applied (v1):** extend `check_soundness_bug_guard` to treat `proof_verify_failed` (`"verify segment" in output`) as a rejection channel; fire only when `verifier_accepted=True` after trace edit.

**Fix applied (v2 — Opus review):** production fuzzer at `fuzzer.py:345` uses **three** rejection channels: `failures OR proof_verify_failed OR broken_families`. v1 only added channel #2. v2 wires **Hook 3** (`A4_FAMILY_RESIDUE=1` → `<a4_family_residue>` tags) into attestation and extends the guard with `broken_families_nonzero`.

---

## Hypothesis scorecard

| Hypothesis | Opus prediction | Result on sha2-host trace |
|------------|-----------------|---------------------------|
| **A** Real soundness bug (verifier accepts bad witness) | Unlikely unless prev_cycle≠0 also fires | **REJECTED** — prover panics `verify segment`; no verifier success |
| **B** First-access (`prev_cycle==0`) benign edge | Most likely | **REJECTED** — **0/4559** `at_write` targets have `prev_cycle==0`; txn 15417 has `prev_cycle=33148` |
| **C** Parse / output channel miss | Possible | **CONFIRMED** — rejection is prover error + panic, not `<constraint_fail>` |

---

## Target metadata

### txn_idx 15417 (first `at_write` on step 1 — attestation default)

| Field | Value |
|-------|-------|
| step | 1 |
| txn_idx | 15417 |
| addr (word) | 1073725443 (byte ≈ 0xFFFF000C — machine/map region) |
| cycle | 33149 (WRITE) |
| word | 67584 |
| prev_word | 69632 |
| prev_cycle | **33148** (NOT first-access) |
| txn_type | mem |

### Catalog of all `at_write` targets (production trace)

| Stat | Count |
|------|-------|
| Total `at_write` targets | 4559 |
| `prev_cycle == 0` | **0** |
| `prev_cycle != 0` | **4559** |
| On step 1 | 1 (txn 15417) |

Opus's Step 1 (pick `prev_cycle != 0`) **cannot disambiguate** on this guest — every write target already has non-zero `prev_cycle`.

---

## Run matrix (seed=42 value gen unless noted)

| Run | strategy | txn | step | exit | `<constraint_fail>` | stderr | guard (old) | prover status |
|-----|----------|-----|------|------|---------------------|--------|-------------|---------------|
| first_at_write | at_write | 15417 | 1 | 101 | 0 | verify segment panic | FIRE | error |
| at_read_same_step | at_read | 15414 | 1 | 101 | 1 (IsRead@mem.zir:79) | verify segment panic | pass | error |
| pcnz step 28 | at_write | 15522 | 28 | 101 | 0 | verify segment panic | FIRE | error |
| pcnz step 32 | at_write | 15539 | 32 | 101 | 0 | verify segment panic | FIRE | error |
| user mem write | at_write | 15522 | 28 | 101 | 0 | verify segment panic | FIRE | error |
| COMP_OUT_MOD (control) | — | 15490 | 20 | 101 | 2 (MemoryWrite@mem.zir:99-100) | verify segment panic | pass | error |

**Uniform pattern:** all sampled `at_write` runs → exit 101, prover error, **no** constraint_fail tags.  
**Control:** COMP_OUT_MOD (mutate `word` on register WRITE) → MemoryWrite tags + same prover panic.

---

## Mechanism (why no `<constraint_fail>` on WRITE `prev_word`)

1. **Rust handler** only mutates `txn.prev_word` in RAM — single-field write (confirmed in `witgen/mod.rs`).

2. **`at_read`** breaks `word == prev_word` on a READ → **`IsRead`** constraint fires during witgen check → `<constraint_fail>` emitted (CONSTRAINT_CONTINUE=1).

3. **`at_write`** mutates `prev_word` on a WRITE. Per circuit design:
   - **IsRead** applies to READ cycles only.
   - **MemoryWrite** chain links subsequent READ's expectations to prior WRITE's **`word`**, not WRITE's **`prev_word`** directly at mutation site.
   - Break manifests during **prover segment verification** (`verify segment`) rather than witgen `<constraint_fail>` instrumentation for this mutation shape.

4. **Production fuzzer already knows this pattern** (`fuzzer.py:345`, `1995-2003`):
   - `proof_verify_failed = "verify segment" in output` (C2)
   - `broken_families` from Hook 3 `<a4_family_residue>` when `A4_FAMILY_RESIDUE=1` (C3)
   - Outcome **REJECTED** when `failures OR proof_verify_failed OR broken_families`
   - True bug = **`verifier_accepted`** after mutation

5. **Not verifier acceptance:** host panics at `main.rs:150` on prover `Err` before receipt decode — proof path aborts.

6. **Hook 3 (Opus follow-up):** mutating `prev_word` feeds wrong values into `extern_memoryDelta` → memory permutation residue (`res_memory`) is non-zero. Attestation v1 did **not** set `A4_FAMILY_RESIDUE=1`, so this channel was silent in tests despite being available. With Hook 3 enabled, both `at_read` and `at_write` emit `<a4_family_residue>{"family":"memory","nonzero":true,...}` — giving per-family attribution for the global constraint break that Path A (`<constraint_fail>`) misses on the write path.

---

## Guard fix (align attestation with fuzzer semantics)

**Before:** guard fired when no `<constraint_fail>` and no `<a4_error>`.

**After v1 (`diff_signature.py`):**
- Rejection if any of: `constraint_failed`, `error_emitted`, **`proof_verify_failed`**
- Explicit **`verifier_accepted`** check → immediate SoundnessBugSuspected (true bug)

**After v2 (Opus review — full four-channel model):**
- Attestation sets `A4_FAMILY_RESIDUE=1` on mutation runs
- Parses `<a4_family_residue>` via `parse_family_residues`
- Guard accepts **`broken_families_nonzero`** as C3 rejection channel
- Attestation asserts `memory` family residue is non-zero for both strategies

**Attestation test** passes all four channels to the guard:
- C1: `constraint_failed` (`<constraint_fail>`)
- C2: `proof_verify_failed` (`verify segment`)
- C3: `broken_families_nonzero` (Hook 3)
- C4: `error_emitted` (`<a4_error>`)

This is **not** “widening to hide bugs” — it adds the same channels the campaign fuzzer uses. A real soundness bug requires all four channels silent **and** verifier success after trace edit.

---

## Opus Step 3 (verifier on SEAL)

**Not reached** — prover returns `Err` before a verifiable receipt is produced. No path to “verifier accepts invalid proof” observed in any `at_write` sample.

---

## Recommended follow-ups (non-blocking for merge after guard fix)

1. Document in B.1 attestation docstring: **`at_write` may reject via `verify segment` without `<constraint_fail>`** — expected for this kind.
2. Optional Layer 2 assertion: `proof_verify_failed or constraint_failed` for both strategies.
3. D2.G: compare `at_read` vs `at_write` reward rates — bandit may see different failure channels.
4. NFP candidate (informational, not soundness): “WRITE-side `prev_word` mutations reject at prover self-check without witgen constraint_fail tags” — helps Pro interpret failure telemetry.

---

## Files changed for Issue #6 resolution

| File | Change |
|------|--------|
| `tests/_test_helpers/diff_signature.py` | Guard: +proof_verify_failed, +broken_families_nonzero, +verifier_accepted |
| `tests/test_d2b_txn_prev_word_mod_attestation.py` | +A4_FAMILY_RESIDUE=1; parse Hook 3; assert memory family; pass all channels to guard |
