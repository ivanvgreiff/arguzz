# D2.C Batch 1 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) **v0.5 LOCKED** (Phase 0 drift resolved 2026-06-19)
**Governing plan:** [`../New_Master.md`](../New_Master.md) §2 Phase 1 (Build D2.C) · **Parent:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.16 §3
**Requirements behind the plan:** [`../pro_checkin_attachments/ProG_Report_4.md`](../pro_checkin_attachments/ProG_Report_4.md) §2 Phase 1, Q4 (accept signal), §7 (thesis)
**Notes for Pro:** [`../IV_POS_8_NOTES_FOR_PRO.md`](../IV_POS_8_NOTES_FOR_PRO.md) — NFP-1 (5-tuple ArmKey), NFP-3 (RNG), NFP-10 (byte_addr), NFP-11 (3 live/5 dead A4 kinds)
**Mechanism reference:** [`../IV_POS_8_D2_B_MECHANISM_REPORT.md`](../IV_POS_8_D2_B_MECHANISM_REPORT.md) §9 (4-channel rejection; Path A/Path B)
**Predecessors:** D2.A (`7b66fb9` — 5-tuple `ArmKey`, `MutationOutcome`, `outcome` column) · D2.B CLOSED (`e2c2256`→`dfd0ebe`; PS-1 removed 5 dead A4 kinds, PS-2 fixed `_TXN_ROLE_BY_KIND`). HEAD = `dfd0ebe`.
**Issued by:** Opus (planning), on the locked v0.5 spec
**Expected effort:** ~1.5–2 days focused work + ~0.5 day for the report.

---

## TL;DR for Composer

Implement **D2.C Batch 1** as defined in `IV_POS_8_D2_C_SPEC.md` v0.5 §11 "Batch 1" (tasks 1.1 → 1.10). Batch 1 is the **primitive layer** of the Arguzz integration: one new file `a4/standalone/arguzz_invoke.py` (the single source of truth for invoking `risc0-host --inject`), plus a small permanent move of the Arguzz `_TXN_ROLE_BY_KIND` extensions, a deprecation docstring, and four tests (mock, outcome-mapping unit, a **gating** real-binary smoke, and a Tier-1 V5 golden-trace regression fixture).

**Batch 1 ships NO bridge, NO driver, NO `fuzzer.py` change, NO scheduler change.** Those are Batches 2/3/4. The primitive is **kind-agnostic** — it accepts any `--inject-kind` string and parses/classifies whatever the binary emits. The 11-vs-4 kind-set distinction (V6-cTS vs Hybrid-cTS) lives in `arguzz_bridge.py`, which is **Batch 2**.

**The single load-bearing constraint of this batch:** `arguzz_invoke._classify_outcome` MUST implement the **Option C, `prover_status`-PRIMARY** decision tree (spec §6.1). This is *not* the legacy `host_panic`-first logic from `v6_driver_v2.py:480-490`. Getting this wrong silently throws away ~91.6 % of the bandit signal — exactly the bug v0.3 corrected. See [Critical correctness facts](#critical-correctness-facts-do-not-repeat-these) below.

---

## Composer: read these files first (in this order, before writing any code)

**Docs:**
1. `IV_POS_8_D2_C_SPEC.md` **v0.5** — the source of truth. Read fully, but especially: §1 (goal; 3 outputs), §1.3 (3-layer architecture), §1.6 (the 7-layer test framework — Batch 1 owns Layers 1, 2, and the Tier-1 golden trace), §4.1 (`arguzz_invoke.py` API — your primary deliverable), §4.6 (`_TXN_ROLE_BY_KIND` move), §4.7 (`arguzz_runner.py` deprecation), §6.1 (Option C outcome mapping — **the critical one**), §6.2 (4-channel + C5), §11 Batch 1 (tasks 1.1–1.10), §14 (acceptance).
2. This kickoff — workflow framing + pass criteria.
3. `IV_POS_8_NOTES_FOR_PRO.md` NFP-10 (byte_addr — already fixed; do not revert) and NFP-11 (Path A vs Path B; the live/dead A4 split that motivates D2.C).
4. `IV_POS_8_D2_B_MECHANISM_REPORT.md` §9 (the 4-channel rejection model + at_read/at_write Path-A/Path-B distinction — the V6 analog your `_classify_outcome` must mirror).

**Code (read at HEAD `dfd0ebe` — do NOT write the primitive before reading these):**
5. `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` — **the frozen reference.** `arguzz_invoke.run()` is refactored from its `run_inject` (lines 343–364), `_decode_safe` (328–340), the regex parsers (91–123), and the outcome block (467–490). **Adopt the improved invocation logic; REPLACE the outcome block with Option C.** Do NOT modify this file.
6. `a4/arguzz_dependent/arguzz_parser.py` — `ArguzzFault.parse` (6 fault formats: word/out/data/pc/reg_assign/mem_assign), `ArguzzTrace`, `parse_all_faults`, `parse_all_traces`. **Re-import these; do NOT rewrite the regexes.** Do NOT modify this file.
7. `a4/arguzz_dependent/arguzz_runner.py` — the DEPRECATED predecessor. Note its `text=True` subprocess bug (line 67 — the thing `_decode_safe` exists to avoid) and its `guest_crashed` heuristic (84–106). Task 1.3 only adds a deprecation docstring; **do not revive it.**
8. `a4/standalone/bandit_ts.py` — `MutationOutcome(str, Enum)` at line 57 (`APPLIED`/`SKIPPED`/`ERROR`) is the enum your classifier returns. `applied_accounting_mode` (146, 156) and `update_with_outcome` (310) exist but are **NOT your concern in Batch 1** (Batch 3 task 3.2a wires them). Read-only.
9. `a4/standalone/semantic_arm_universe.py` — `ArmKey` 5-tuple dataclass at lines 174–182 (`surface, kind, zone, opcode_class, pre_post`); `ARGUZZ_EXEC_FAULT = "arguzz_exec_fault"` at line 170. Used by the Tier-1 golden trace (task 1.7) and the arm-space calc (task 1.8). No edits in Batch 1.
10. `a4/standalone/compressed_global_extractor.py` — `_TXN_ROLE_BY_KIND` at line 161 (task 1.2 target) and the byte_addr fix in `_coerce_broken_addr` at lines 223–234 (NFP-10 — **must stay intact**, byte_addr checked first).
11. `a4/core/constraint_parser.py` — `ConstraintFailure` + `parse_all_constraint_failures` + `short_loc()` (line 55). The primitive's `failures` field is `list[ConstraintFailure]` parsed via `parse_all_constraint_failures` (NOT v6_driver_v2's raw-dict `_CFAIL_RE`), so failures carry normalized `short_loc` downstream.
12. `a4/core/touch_coverage.py` — `parse_family_residues` (179), `parse_family_detail` (217), `parse_global_residue` (231). Re-export these from the primitive.
13. `a4/standalone/tests/test_d2a_back_compat_golden_trace.py` — the **exact template** for task 1.7's Tier-1 golden trace (uses `ConstrainedTSScheduler`, `_decision_trace`, `_small_universe`, seed=42, n=200, fixture JSON).
14. `a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_KICKOFF.md` — the format precedent for this kickoff (and for your report).

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

Composer MUST run each and paste output into the Batch 1 report:

```bash
# 1. On cloud2, working tree state recorded
git rev-parse HEAD                      # → dfd0ebe... (or note the current commit)
git status --short                      # record pre-existing doc edits; do not revert them

# 2. Establish the REAL green baseline at your starting commit (do NOT trust a hardcoded number)
python -m pytest a4/standalone/tests/ -q 2>&1 | tail -3
# Record the exact "N passed, M skipped, K xfailed" line. The spec cites
# "609 passed, 19 skipped, 1 xfailed" (post-D2.B), but 649 tests now collect —
# capture YOUR actual baseline and require new tests to not regress it.

# 3. NFP-10 byte_addr fix present — DO NOT revert during task 1.2
grep -n 'byte_addr' a4/standalone/compressed_global_extractor.py
# → expect line ~230: for key in ("byte_addr", "addr", "address"):

# 4. The 6 Arguzz role extensions are NOT yet in the static dict (task 1.2 adds them)
grep -n 'PRE_EXEC_PC_MOD\|POST_EXEC_PC_MOD\|BR_NEG_COND\|POST_EXEC_REG_MOD\|PRE_EXEC_MEM_MOD\|POST_EXEC_MEM_MOD' a4/standalone/compressed_global_extractor.py
# → expect NO hits in _TXN_ROLE_BY_KIND (they are runtime-patched only by v6_driver_v2.py:74-84 today)

# 5. The reference driver + parser are present and readable
ls -l a4/runs/iv_pos_7/drivers/v6_driver_v2.py a4/arguzz_dependent/arguzz_parser.py

# 6. MutationOutcome enum + ArmKey location confirmed
grep -n 'class MutationOutcome' a4/standalone/bandit_ts.py          # → ~line 57
grep -n 'class ArmKey' a4/standalone/semantic_arm_universe.py        # → ~line 174
```

If any check surprises you (esp. #3 missing, or #4 already present), **stop and report** rather than improvising.

---

## Scope — exactly what Batch 1 ships

### Spec sections this batch implements
- **§4.1** `a4/standalone/arguzz_invoke.py` (NEW — the primitive)
- **§4.6** `compressed_global_extractor.py` `_TXN_ROLE_BY_KIND` permanent move (task 1.2 only — NOT the two-taxonomy / `MAPPING_INSTR_TO_OPCODE_CLASS` work, which is Batch 2)
- **§4.7** `arguzz_runner.py` deprecation docstring
- **§1.6** test Layers 1 (mock + outcome unit), 2 (real-binary smoke, gating), and the Tier-1 golden trace
- **§6.1 / §6.2** outcome classification (Option C) + C5 channel definition
- **§11 Batch 1** task list 1.1 → 1.10
- **§14** acceptance items #3 (golden trace), #4 (Layer 2 smoke)

### Files touched

| File | Action | Rough size |
|---|---|---|
| `a4/standalone/arguzz_invoke.py` **(NEW)** | The primitive. `ArguzzInvocationResult` dataclass, `run()`, `_decode_safe`, `_classify_outcome` (Option C), `_detect_host_panic` (both panic strings), re-exports from `arguzz_parser`/`constraint_parser`/`touch_coverage`. Kind-agnostic. | ~220–280 LOC |
| `a4/standalone/compressed_global_extractor.py` | Add the 6 Arguzz kind→role entries to `_TXN_ROLE_BY_KIND` permanently (task 1.2). **DO NOT touch `_coerce_broken_addr` / the byte_addr lines (NFP-10).** | ~6 LOC |
| `a4/arguzz_dependent/arguzz_runner.py` | Add a deprecation docstring at module top (task 1.3). **No code change.** | ~8 LOC docstring |
| `a4/standalone/tests/test_d2c_arguzz_invoke_mock.py` **(NEW)** | Layer 1 mock — stub `subprocess.run`, canned Arguzz stdout, assert parsing + outcome for all 5 buckets. | ~180 LOC |
| `a4/standalone/tests/test_d2c_outcome_mapping.py` **(NEW)** | Layer 1 unit — all 7 `_classify_outcome` branches + `_detect_host_panic` both strings. | ~120 LOC |
| `a4/standalone/tests/test_d2c_arguzz_invoke_real_binary.py` **(NEW)** | Layer 2 — **GATING**, `A4_REAL_BINARY=1`, 4 SELECTED kinds × 1 invocation. | ~150 LOC |
| `a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py` **(NEW)** + `tests/fixtures/d2c_golden_v5_decision_seq_seed42_n200.json` **(NEW)** | Layer 1 regression Tier-1 — capture + lock the V5 decision sequence at fixed seed. | ~40 LOC + fixture |

**Total expected delta:** ~700–900 LOC across 7 files (1 primitive + 1 tiny extractor edit + 1 docstring + 4 test files + 1 fixture). All Python; **zero Rust**.

---

## NOT in Batch 1 (deferred — do not start these)

| Item | Where it ships |
|---|---|
| `mutations/arguzz_bridge.py`, `MUTATION_KINDS_ARGUZZ_FULL` (11) / `_SELECTED` (4), `_PRE_POST_BY_KIND`, `MAPPING_INSTR_TO_OPCODE_CLASS`, `valid_injection_kinds_for_instr`, `get_valid_steps`, `create_mutation_for_arm` | **Batch 2** (§4.2) |
| `semantic_arm_universe.build(arguzz_kinds=...)` parameter; real Arguzz arm construction | **Batch 2** (§4.3) |
| `v6_uniform_driver.py`; `fuzzer.py` `_dispatch_arm` / `_record_arguzz_mutation` / Arguzz dispatch branch | **Batch 3** (§4.4, §4.5) |
| **`applied_accounting_mode=True` wiring** + `update_with_outcome` on the Arguzz path | **Batch 3 task 3.2a** — explicitly NOT Batch 1 |
| Tier-2 V5 golden-trace DB byte-identity gate | **Batch 3 task 3.2b** (there is nothing to byte-compare until the dispatch refactor lands) |
| Hybrid forerunner smoke; cross-cutting 66-case arm-registration test | **Batch 4** |
| Any change to `bandit_ts.py`, `coverage_db.py`, `v6_driver_v2.py`, `arguzz_parser.py`, `workspace/risc0-modified/` | **None** — these are in the §4.9 "must not change" list |

If you find yourself editing anything in the "must not change" list, **stop and confirm**.

---

## Critical correctness facts (do NOT repeat these — they have bitten us)

1. **Outcome classifier = Option C, `prover_status`-PRIMARY.** NOT `host_panic`-first. The legacy `v6_driver_v2.py:480-490` checks `host_panic` before `prover_status`; that mislabels ~91.6 % of rows as "panic" when the prover actually ran end-to-end and *detected* the mutation. The corrected R2 V6 distribution is **~94.6 % APPLIED** (≈91.6 % APPLIED+REJECTED = C1 local-tag + C2 global/"verify segment" with no local tag, + ~2.95 % APPLIED+ACCEPTED) + only ~5.2 % true SKIPPED + <0.2 % edge. Implement the §6.1 decision tree exactly (reproduced in task 1.1 below).
2. **`_detect_host_panic` checks BOTH `"panicked at"` AND `"Guest panicked:"`.** `v6_driver_v2.py:479` only checks the former. Adopt the broader check (mirrors `arguzz_runner.py:89`).
3. **`arguzz_invoke.py` is the NEW primitive; `arguzz_runner.py` is DEPRECATED.** Import `ArguzzFault`/`ArguzzTrace` from `arguzz_parser`; import `ConstraintFailure`/`parse_all_constraint_failures` from `constraint_parser`. Do NOT revive or import `arguzz_runner`.
4. **C5 is narrow.** C5 = `prover_status="start" AND host_panic` ONLY (the true pre-prover guest crash, ~5.2 %). It is NOT "any panicked-at string." Most `panicked at` rows have `prover_status="error"` and are C1/C2 → APPLIED.
5. **byte_addr fix (NFP-10) is already in `compressed_global_extractor.py`.** `_coerce_broken_addr` checks `("byte_addr", "addr", "address")` with byte_addr first. Task 1.2 ONLY adds 6 `_TXN_ROLE_BY_KIND` entries — do not touch `_coerce_broken_addr`.
6. **`applied_accounting_mode` is NOT wired in `fuzzer.py`, and Batch 1 does NOT wire it.** That is Batch 3 task 3.2a. Don't import it, don't reference it.
7. **The V5 golden trace must stay byte-identical.** Batch 1 changes nothing on the scheduler / arm-construction / dispatch path, so the V5 decision sequence is a no-op for this batch. **Capture the Tier-1 fixture fresh on the current HEAD** (post-1.5e) — do NOT compare against any old archive. As a cross-check, the captured sequence should equal the existing `d2a_golden_v5_trace_seed42_n200.json` (since nothing on that path changed); note any difference loudly in the report.
8. **The primitive is kind-agnostic.** It does NOT enforce the 11-vs-4 kind lists; those constants live in `arguzz_bridge.py` (Batch 2). `run()` passes whatever `kind` string it's given straight to `--inject-kind`.

---

## Per-task detail

### Task 1.1 — `a4/standalone/arguzz_invoke.py` (the primitive) — §4.1

`ArguzzInvocationResult` dataclass fields:
`rc: int`, `outcome: MutationOutcome`, `prover_status: str` (`"success"`/`"error"`/`"start"`/`"none"`), `wall_s: float`, `faults: list[ArguzzFault]`, `failures: list[ConstraintFailure]`, `family_residues: list`, `family_details: list`, `global_residue: dict`, `host_panic: bool`, `crash_reason: str`, `traces: list[ArguzzTrace]`, `soundness_signal: bool` (set by the classifier), `extra_tags: dict` (carries `soundness_signal` / `failure_recording_gap`), `raw_stdout: str` (**capped at a 4 KB tail** for memory safety).

`run(host: str, host_args: list[str], step: int, kind: str, seed: int, *, timeout: float = 90.0, env: Optional[dict] = None) -> ArguzzInvocationResult`
- Replicates `v6_driver_v2.py::run_inject` (lines 343–364): build `[host, "--inject", "--inject-step", str(step), "--inject-kind", kind, "--seed", str(seed), *host_args]`, `subprocess.run(capture_output=True)` **in bytes mode (no `text=True`)**, wrap `TimeoutExpired` → `rc=124`, last-resort `except` → `rc=125`.
- Subprocess env = `{**os.environ, "CONSTRAINT_CONTINUE": "1"}`; if the caller passes `A4_FAMILY_RESIDUE` (or any `env` dict), merge it on top. No reliance on parent-process env leakage.
- Decode with `_decode_safe(p.stdout) + _decode_safe(p.stderr)`.
- Parse: `faults = parse_all_faults(stdout)`; `traces = parse_all_traces(stdout)`; `failures = parse_all_constraint_failures(stdout)`; `family_residues = parse_family_residues(stdout) or []`; `family_details = parse_family_detail(stdout) or []`; `global_residue = parse_global_residue(stdout)`. Parse `prover_status` via the v6_driver_v2 `_PROVER_REC_RE` pattern (`parse_prover_status` returns `("none", None)` when absent — keep that semantics).
- `host_panic, crash_reason = _detect_host_panic(stdout)`.
- `outcome, extra_tags = _classify_outcome(rc, host_panic, prover_status, has_failures=len(failures) > 0)`; set `result.soundness_signal = extra_tags.get("soundness_signal", False)`.

`_decode_safe(b: bytes | None) -> str` — copy verbatim from `v6_driver_v2.py:328-340`.

`_detect_host_panic(stdout: str) -> tuple[bool, str]` — `True` if `"panicked at " in stdout` **OR** `"Guest panicked:" in stdout`; return the first matching panic line as `crash_reason` (capped at 256 chars).

`_classify_outcome(rc, host_panic, prover_status, has_failures) -> tuple[MutationOutcome, dict]` — **Option C decision tree, first match wins:**

```text
rc == 124                                   → (ERROR,   {})                                # timeout
prover_status == "success" and not host_panic → (APPLIED, {"soundness_signal": True})       # accepted-invalid OR fault-no-op
prover_status == "error"   and has_failures   → (APPLIED, {})                               # Path A (local witgen EQZ)
prover_status == "error"   and not has_failures → (APPLIED, {"failure_recording_gap": True}) # Path B (verify-segment/global poly)
prover_status == "start"   and has_failures   → (APPLIED, {})                               # Path A mid-witgen, prover never finalized
prover_status == "start"   and host_panic     → (SKIPPED, {})                               # true C5 (pre-prover guest crash)
otherwise                                     → (ERROR,   {})                               # edge (other/start/no_fail)
```

Re-exports (so downstream Batches 2/3 import from one place): `ArguzzFault`, `ArguzzTrace` (from `a4.arguzz_dependent.arguzz_parser`); `ConstraintFailure` (from `a4.core.constraint_parser`); `parse_family_residues`, `parse_family_detail`, `parse_global_residue` (from `a4.core.touch_coverage`). Module-level logger `a4.arguzz_invoke`, quiet by default.

### Task 1.2 — move `_TXN_ROLE_BY_KIND` Arguzz extensions in permanently — §4.6

Add these 6 entries to the static `_TXN_ROLE_BY_KIND` dict in `compressed_global_extractor.py` (these are the runtime `setdefault` patches from `v6_driver_v2.py:74-84`):

```python
"PRE_EXEC_PC_MOD":   "ifetch",
"POST_EXEC_PC_MOD":  "ifetch",
"BR_NEG_COND":       "ifetch",
"POST_EXEC_REG_MOD": "register",
"PRE_EXEC_MEM_MOD":  "read",
"POST_EXEC_MEM_MOD": "write",
```

`PRE_EXEC_REG_MOD` (`register`) and `COMP_OUT_MOD` (`register`) are already present — do not duplicate. `LOAD_VAL_MOD`/`STORE_OUT_MOD`/`INSTR_WORD_MOD` are already present. **Do not touch `_coerce_broken_addr` (NFP-10).**

### Task 1.3 — deprecate `arguzz_runner.py` — §4.7

Add a module-top deprecation docstring (verbatim text in spec §4.7): legacy / R2-compat only; D2.C onward uses `arguzz_invoke.py`; do not import in new code; deletion deferred to IV.POS.9. **No code change.**

### Task 1.4 — mock test `test_d2c_arguzz_invoke_mock.py` (Layer 1) — §4.8

Monkeypatch `subprocess.run` to return canned Arguzz stdout (sample from R2 V6 raw stdout if available; else hand-craft to cover all 5 buckets: timeout, prove_success, prove_error+failures, prove_error+no-failures, start+panic). Assert: faults/failures/family residues extracted; outcome correct per bucket; `_decode_safe` survives non-UTF-8 bytes; both panic strings detected; traces extracted.

### Task 1.5 — outcome-mapping unit test `test_d2c_outcome_mapping.py` (Layer 1) — §4.8

Drive `_classify_outcome` directly across all **7** branches (assert outcome AND the `extra_tags` payload, incl. `failure_recording_gap=True` on error+no-failures and `soundness_signal=True` on success). Separately assert `_detect_host_panic` matches BOTH `"panicked at"` AND `"Guest panicked:"`.

### Task 1.6 — real-binary smoke `test_d2c_arguzz_invoke_real_binary.py` (Layer 2) — **GATING** — §4.8

Gated on `A4_REAL_BINARY=1` (skip gracefully otherwise; stay green in CI). For the **4 SELECTED kinds** — `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND` — invoke `arguzz_invoke.run()` once each at a known-good step (pick a branch step for `BR_NEG_COND` from a baseline `host --trace`). Assert per kind: ≥1 `<fault>` tag parsed; `outcome ∈ {APPLIED, ERROR}`; `wall_s < 90`. **If any of the 4 emits zero faults, this is a gating failure — stop and document the binary surprise in the report.** (The other 7 V6-cTS-only kinds are covered at the kind-string level by Layer 1 here and operationally by Layer 5 in Batch 3.)

### Task 1.7 — Tier-1 V5 golden-trace `test_d2c_golden_trace_v5_decision_seq.py` (Layer 1 regression) — §4.8

Mirror `test_d2a_back_compat_golden_trace.py` exactly: instantiate `ConstrainedTSScheduler(_small_universe(), seed=42)`, run `_decision_trace(sched, n=200, successes=[1 if i%7==0 else 0 ...])`, and **capture** the `(arm_id, mode)` tuple sequence to `tests/fixtures/d2c_golden_v5_decision_seq_seed42_n200.json` **freshly on the current HEAD**. The test then asserts byte-identity against that fixture. <1 s. **Scope:** catches drift in `ConstrainedTSScheduler`, `SemanticArmUniverse` arm-construction, `arm_id_for_decision`. Does NOT exercise `A4Fuzzer._dispatch_arm` (that's Tier-2 / Batch 3). Cross-check: the captured sequence should equal the existing D2.A fixture; flag any difference.

### Task 1.8 — arm-space size calculation (report only, no code) — §11 task 1.8 / §1.2

From a baseline `host --trace` of sha2-host, count applicable steps per kind and estimate the arm count for **FULL (11 kinds)** and **SELECTED (4 kinds)** using `kind × zone × opcode_class × pre_post` with applicability filtering (BR_NEG_COND→branch only, COMP_OUT_MOD→arithmetic only, LOAD_VAL_MOD→load only, STORE_OUT_MOD→store only; the other 7 unrestricted). Compare against §1.2 estimates: **V6-cTS ~200–350**, **Hybrid-cTS ~110–160**. Pure calculation; the precise measurement is Batch 2 task 2.5. Document in the report; flag if either looks likely to exceed 300 (Suggestion 2 trigger).

### Task 1.9 — full pytest sweep
`python -m pytest a4/standalone/tests/ -q` — all previously-green tests still green + new tests pass; no regression below the baseline captured in pre-flight step 2.

### Task 1.10 — write `D2C_BATCH1_COMPOSER_REPORT.md`
See [Report deliverable](#report-deliverable).

---

## Test layers in Batch 1 (from §1.6)

| # | Layer | File | Gating? |
|---|---|---|---|
| 1 | Subprocess mock | `test_d2c_arguzz_invoke_mock.py` | No |
| 1 | Outcome-mapping unit | `test_d2c_outcome_mapping.py` | No |
| 2 | **Real-binary single-mutation smoke** | `test_d2c_arguzz_invoke_real_binary.py` | **YES** (binary de-risking) |
| 1 | V5 golden trace (Tier-1, decision-sequence) | `test_d2c_golden_trace_v5_decision_seq.py` | regression gate |

Layers 3/4 (bridge + arm-construction) are Batch 2; Layer 5 (driver smoke) Batch 3; Layer 6 (hybrid forerunner) + cross-cutting registration Batch 4; Tier-2 DB byte-identity Batch 3.

---

## Acceptance gate (Batch 1 ships when ALL hold)

- [ ] All Layer 1 tests green (mock + outcome-mapping + Tier-1 golden trace).
- [ ] Layer 2 real-binary smoke green for **all 4 SELECTED kinds** (≥1 fault tag parsed each), under `A4_REAL_BINARY=1`, run locally by Composer with output pasted in the report.
- [ ] `_classify_outcome` unit test covers all **7** decision-tree branches, including `failure_recording_gap=True` (error+no-failures, Path B) and `soundness_signal=True` (success).
- [ ] `_detect_host_panic` test verifies BOTH `"panicked at"` AND `"Guest panicked:"`.
- [ ] Tier-1 V5 golden-trace identity confirmed against the freshly-captured HEAD fixture (cross-checked against the D2.A fixture; differences flagged).
- [ ] `_TXN_ROLE_BY_KIND` has the 6 new Arguzz entries; **NFP-10 byte_addr lines unchanged** (grep before & after, both pasted in report).
- [ ] `arguzz_runner.py` carries the deprecation docstring; no code change.
- [ ] Arm-space calc reported (FULL + SELECTED), compared to §1.2.
- [ ] Full pytest sweep at or above the pre-flight baseline (no regressions).
- [ ] `v6_driver_v2.py`, `arguzz_parser.py`, `bandit_ts.py`, `coverage_db.py`, `workspace/risc0-modified/` all unchanged.
- [ ] `D2C_BATCH1_COMPOSER_REPORT.md` submitted.

---

## Workflow

1. **Pre-flight** (checklist above) → paste output in report; record the real test baseline.
2. **Read** the locked spec end-to-end + NFP-10/NFP-11 + this kickoff + the 5 code files in the read-list.
3. **Implement in order:** 1.1 primitive → 1.2 `_TXN_ROLE_BY_KIND` → 1.3 deprecation docstring → 1.4 mock test → 1.5 outcome-mapping unit → 1.6 real-binary smoke (run locally with the binary) → 1.7 golden-trace capture + test → 1.8 arm-space calc → 1.9 full sweep → 1.10 report.
4. **Single commit to `cloud2`** (no feature branch, no PR). Co-authored-by line included.
5. **Self-checkpoint:** the acceptance checklist must be 100 % green before committing.

---

## Report deliverable

At the end of Batch 1, write `a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_REPORT.md` covering:

1. **Pre-kickoff checklist output** (all commands, incl. the real test baseline line).
2. **What was implemented** — per-task summary with LOC counts.
3. **Option C classifier** — confirm the 7-branch tree shipped exactly; note any ambiguity found vs real binary output.
4. **Layer 2 real-binary smoke output** — paste `A4_REAL_BINARY=1 python -m pytest test_d2c_arguzz_invoke_real_binary.py -v`; per-kind fault counts + outcomes; **any binary surprises** (a kind emitting zero faults is a gating failure — call it out).
5. **NFP-10 revert guard** — grep of the byte_addr lines BEFORE and AFTER the task-1.2 edit.
6. **Golden trace** — confirm Tier-1 fixture captured fresh at HEAD; cross-check vs the D2.A fixture (equal / differs + why).
7. **Arm-space calc** — FULL + SELECTED estimates vs §1.2 (~200–350 / ~110–160); flag if >300.
8. **Test counts** — final `pytest -q` tally vs baseline.
9. **Deviations** from spec/kickoff (and why).
10. **Open questions / surprises** for Ivan/Opus, and any items that affect Batch 2 (bridge) design.

---

## Hand-off statement (paste when delegating to Composer)

> Implement D2.C Batch 1 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_C_SPEC.md` **v0.5** (tasks 1.1 through 1.10). Follow the workflow in `a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_KICKOFF.md`. Commit directly to `cloud2`, single commit, no feature branch, no PR. Batch 1 is the **primitive layer only** — ship `a4/standalone/arguzz_invoke.py`, the `_TXN_ROLE_BY_KIND` move, the `arguzz_runner.py` deprecation docstring, and four tests; ship NO bridge, NO driver, NO `fuzzer.py`/scheduler change, and do NOT wire `applied_accounting_mode`. The one load-bearing requirement: `_classify_outcome` MUST be the Option C `prover_status`-PRIMARY 7-branch tree (spec §6.1), not the legacy `host_panic`-first logic. `_detect_host_panic` must match BOTH `"panicked at"` AND `"Guest panicked:"`. Import `ArguzzFault` from `arguzz_parser` (do not revive `arguzz_runner`). Do NOT touch the NFP-10 byte_addr lines in `compressed_global_extractor.py`. Capture the V5 Tier-1 golden trace fresh on current HEAD. The Layer 2 real-binary smoke (`A4_REAL_BINARY=1`, 4 SELECTED kinds) is the gating test — run it locally and paste output. Pass criteria are the acceptance checklist in the kickoff. Submit `a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_REPORT.md`.

---

*End of D2.C Batch 1 kickoff. Report back at `D2C_BATCH1_COMPOSER_REPORT.md`; Opus reviews, then issues the Batch 2 (bridge) kickoff.*
