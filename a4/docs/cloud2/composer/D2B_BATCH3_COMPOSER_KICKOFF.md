# D2.B Batch 3 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) **v0.5.3 LOCKED + audit patch**
**Parent plan:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) **v0.11** — adds **W-17 `set_cycle` dead-arm class** + **§6d Batch 3 attestation prediction table** + **§6c S3** witness-vs-trace note + **§9b** W-16 / W-17 distinction
**Audit predecessor:** [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md) — proves B.3 is a W-17 dead arm; predicts B.6 and B.7 dead on the same mechanism
**Notes for Pro:** [`../IV_POS_8_NOTES_FOR_PRO.md`](../IV_POS_8_NOTES_FOR_PRO.md) — NFP-3, NFP-5, NFP-6 still apply; B.3 dead-arm finding will become an NFP at D2.G writeup
**Predecessor commit:** Batch 2 (commit hash TBD — paste in the Batch 3 report; should contain literal "Batch 2")
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~3–5 days of focused Composer work (5 kinds: B.4, B.5, B.6, B.7, B.8). No Rust infrastructure to build; no retrofix; templates already exist from Batch 1 + Batch 2.

---

## TL;DR for Composer

Implement **D2.B Batch 3** as defined in `IV_POS_8_D2_B_SPEC.md` §7 "Batch 3" — **five** new pure-A4 mutation kinds with **two distinct attestation patterns** (live and predicted-dead):

| Kind | Field | Pattern | Expected outcome | Template |
|------|-------|---------|-------------------|----------|
| **B.4** `TXN_ADDR_MOD` | `txns[i].addr: u32` | **LIVE** (extern-read path, HIGH RISK + `FAULT_INJECTION_ENABLED=1`) | C2 + C3 `memory` family | B.1 `at_read` |
| **B.5** `TXN_CYCLE_PHASE_MOD` | `txns[i].cycle: u32` (LSB only) | **LIVE** (extern-read path, deterministic XOR — NO `value` in config) | C2 + C3 `memory` family | B.2 `TXN_PREV_CYCLE_MOD` (no value field — see §3.5) |
| **B.6** `CYCLE_PC_MOD` | `cycles[i].pc: u32` | **PREDICTED DEAD** (W-17 — `set_cycle`/`exec_Reg` overwrite) | Guard fires → assert → xfail | B.3 `CYCLE_MODE_MOD` |
| **B.7** `CYCLE_STATE_MOD` | `cycles[i].state: u32` | **PREDICTED DEAD** (W-17 — same mechanism) | Guard fires → assert → xfail | B.3 `CYCLE_MODE_MOD` |
| **B.8** `CYCLE_DIFF_COUNT_MOD` | `cycles[i].diff_count: [u32; 2]` (one element) | **LIVE** (`extern_getDiffCount` reads trace at `ffi.cpp:254`) | C2 + C3 `memory` family | B.3 cycle-window template + B.2 attestation pattern |

**Read in this order before writing code:**

1. **`D2B_BATCH2_DEAD_ARM_AUDIT.md` in full** — this is the proof B.6 and B.7 should be dead. Internalize the **`set_cycle` preset → `step_Top` overwrite via `exec_Reg(inst_result.new*, ...)`** mechanism. If you can't restate the proof in your own words, re-read.
2. **`IV_POS_8_D2_PLAN.md` v0.11 §6d** — Batch 3 attestation prediction table with the **reconciliation rule**: if any predicted-dead kind shows live rejection, **STOP** Batch 3, re-read the audit, find the missed witness path, and either confirm or demote the prediction.
3. **`IV_POS_8_D2_PLAN.md` v0.11 §6c S3 + §9b** — witness-vs-trace distinction + 4-channel rejection model. (Already known from Batch 1/2.)
4. **`IV_POS_8_D2_B_SPEC.md` v0.5.3** sections:
   - **§3.4** B.4 design (txn_role mapping, `FAULT_INJECTION_ENABLED=1`, fetch + register exclusions)
   - **§3.5** B.5 design (deterministic LSB XOR, no value field, fetch exclusion)
   - **§3.6** B.6 design + **PREDICTED DEAD** attestation block
   - **§3.7** B.7 design + **PREDICTED DEAD** attestation block + CycleState enum reference
   - **§3.8** B.8 design (`diff_count` array, `index ∈ {0,1}`)
   - **§4.4** `get_valid_steps_for_kind` rules for new kinds
   - **§4.5** registry plumbing (which kinds added to `_MAJOR_FILTER_KINDS`)
   - **§4.7** txn_role mapping (B.4 = `addr`, B.5 = `cycle_phase`, B.8 = `diff_count`)
   - **§5.3** cascade signatures
   - **§5.4** Batch 3 attestation predictions table (the locked expectation contract)
5. **Batch 1 + 2 deliverables on disk** — these are the canonical templates:
   - `a4/standalone/mutations/txn_prev_word_mod.py` (Python module, txn-level mutation)
   - `a4/standalone/mutations/txn_prev_cycle_mod.py` (Python module, txn-level mutation with `extern_memoryDelta` style)
   - `a4/standalone/mutations/cycle_mode_mod.py` (Python module, cycle-level)
   - `a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py` (LIVE pattern with Hook 3)
   - `a4/standalone/tests/test_d2b_txn_prev_cycle_mod_attestation.py` (LIVE pattern, txn cycle)
   - `a4/standalone/tests/test_d2b_cycle_mode_mod_attestation.py` (PREDICTED DEAD pattern — **B.3 attestation is the template for B.6 and B.7**)
   - `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` (handler match arms + post-mut dump hooks already in place)
   - `a4/standalone/tests/_test_helpers/diff_signature.py` (already includes `collect_cycle_field_diffs` + `broken_families_nonzero` — **DO NOT change the helper**)
6. This kickoff document.

**Single hardest constraint:** the **audit reconciliation rule** for B.6 and B.7. If either of those two kinds shows live rejection (C1/C2/C3 fires), it means the Batch 2 audit missed a witness path. **STOP, report the live-rejection finding in the Batch 3 report, and wait for Opus**. Do not paper over the surprise with xfail; do not silently relabel; do not skip the reconciliation. This is exactly the W-17 → audit-failure → reconcile path described in §6d.

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

Paste output in the Batch 3 report.

```bash
# 1. On cloud2 branch, working tree clean post-Batch-2
cd /root/arguzz
git rev-parse --abbrev-ref HEAD            # → cloud2
git log --oneline -3                       # most recent should be the Batch 2 commit
git status                                 # should be clean

# 2. Batch 2 deliverables present
ls -la a4/standalone/mutations/cycle_mode_mod.py a4/standalone/mutations/txn_prev_cycle_mod.py
ls -la a4/standalone/tests/test_d2b_cycle_mode_mod_attestation.py
ls -la a4/standalone/tests/test_d2b_txn_prev_cycle_mod_attestation.py

# 3. Cycle-window dump helper from Batch 2 is in place
rg "a4_dump_post_mut_cycle_window" workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs

# 4. Helper has cycle-level diff support from Batch 2
rg "collect_cycle_field_diffs|broken_families_nonzero" a4/standalone/tests/_test_helpers/diff_signature.py

# 5. CycleState enum snapshot exists from Batch 1.0b (for B.7 value generation)
ls -la a4/standalone/mutations/_cycle_state_enum.py

# 6. Existing Hook 3 family residue piping (NFP-10 fix at ce62fb6 must still be present)
rg "byte_addr" workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs | head -5
# Expected: byte_addr referenced where Hook 3 emits family residues (NOT addr)

# 7. The full test suite from Batch 2 passes baseline
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/ -q
# Expected: previous Batch 2 pass count (e.g. 544 passed, 11 skipped, 1 xfailed for B.3)

# 8. Tags from Batch 1/2 still parse
rg "A4PostMutDump|A4TxnPrevWordMod|A4TxnPrevCycleMod|A4CycleModeMod" a4/core/trace_parser.py
```

If any of these fail, **stop and report** — do not start implementation.

---

## Per-kind file change matrix

### Files to MODIFY (existing)

| File | Purpose | Per-kind change |
|------|---------|-----------------|
| `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | Rust dispatcher | Add 5 new `match` arms (B.4–B.8) following B.1/B.2/B.3 handlers; each emits its evidence tag and calls the existing post-mut dump (txn-window for B.4/B.5; cycle-window for B.6/B.7/B.8) |
| `a4/core/trace_parser.py` | Tag parsers | Add parsers for 5 new evidence tags + 0 new infrastructure (post-mut tags from Batch 1/2 cover B.6–B.8) |
| `a4/standalone/fuzzer.py` | Mutation dispatch | Add 5 entries to `MUTATION_KINDS`; add 5 branches in `_create_mutation` (B.4 with strategy mix, B.5 deterministic, B.6/B.7 cycle-level, B.8 with `index` field) |
| `a4/standalone/semantic_arm_universe.py` | Arm universe | Register 5 new modules; update `_cycle_matches_kind_filter` and `_step_has_real_target` per §4.5 |
| `a4/core/inspection_data.py` | `get_valid_steps_for_kind` | Add 5 branches per §4.4 (B.4/B.5 → non-fetch txn steps; B.6 → major 0–6 cycles; B.7/B.8 → any cycle except step 0) |
| `a4/standalone/compressed_global_extractor.py` | CGC | Add to `_TXN_ROLE_BY_KIND`: B.4=`addr`, B.5=`cycle_phase`, B.8=`diff_count` per §4.7 (B.6/B.7 are cycle-level — no txn role) |

### Files to CREATE (new)

Per-kind Python module + unit test + attestation test:

| Kind | Python module | Unit test | Attestation test |
|------|---------------|-----------|-------------------|
| B.4 | `a4/standalone/mutations/txn_addr_mod.py` | `a4/standalone/tests/test_d2b_txn_addr_mod_unit.py` | `a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py` |
| B.5 | `a4/standalone/mutations/txn_cycle_phase_mod.py` | `a4/standalone/tests/test_d2b_txn_cycle_phase_mod_unit.py` | `a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py` |
| B.6 | `a4/standalone/mutations/cycle_pc_mod.py` | `a4/standalone/tests/test_d2b_cycle_pc_mod_unit.py` | `a4/standalone/tests/test_d2b_cycle_pc_mod_attestation.py` |
| B.7 | `a4/standalone/mutations/cycle_state_mod.py` | `a4/standalone/tests/test_d2b_cycle_state_mod_unit.py` | `a4/standalone/tests/test_d2b_cycle_state_mod_attestation.py` |
| B.8 | `a4/standalone/mutations/cycle_diff_count_mod.py` | `a4/standalone/tests/test_d2b_cycle_diff_count_mod_unit.py` | `a4/standalone/tests/test_d2b_cycle_diff_count_mod_attestation.py` |

### Files NOT to touch

- `a4/standalone/tests/_test_helpers/diff_signature.py` — helper already has txn + cycle diff collectors and the 4-channel guard. **Read-only** for Batch 3.
- `a4/standalone/tests/test_v5_phantom_arm_pruning.py` — pinned to `V5_CONTROL_KINDS_8` in Batch 1; should not need updating (verify bounds tolerate +5 new kinds: `MUTATION_KINDS` length now ~52–57; existing bounds of `44–58` should hold, but **check and report**).

---

## Attestation pattern — LIVE kinds (B.4, B.5, B.8)

Mirror `test_d2b_txn_prev_word_mod_attestation.py` (B.1) **exactly**, including:

1. `A4_FAMILY_RESIDUE=1` env var so Hook 3 emits `<a4_family_residue>` tags
2. Compute `broken_families` from parsed family-residue tags
3. Call `check_soundness_bug_guard(...)` **without** wrapping in try/except — guard MUST NOT fire (proof should be rejected via C1/C2/C3)
4. Assert `assert_trace_diff_matches_signature(diff, expected_signature)` with the per-kind signature from §5.3
5. Assert at least one of:
   - `"constraint_fail" in mut_out.lower()` (C1)
   - `"verify segment" in mut_out` (C2)
   - `bool(broken_families)` (C3)

If the guard fires for a kind we expect live, **that is a finding** — investigate why no rejection channel triggered. Do NOT xfail to bypass.

### Hook 3 per-kind family expectations (LIVE kinds)

| Kind | Expected `broken_families` | Why |
|------|----------------------------|-----|
| B.4 `TXN_ADDR_MOD` | `{"memory"}` (potentially also `paging` if address mutates into a paging-table region — accept but don't require) | Address is the permutation key for memory chain — `extern_getMemoryTxn` reads `txn.addr` directly |
| B.5 `TXN_CYCLE_PHASE_MOD` | `{"memory"}` | Cycle LSB drives read/write classification at `mod.rs:486-487` (`let is_read = txn.cycle % 2 == 0;`) |
| B.8 `CYCLE_DIFF_COUNT_MOD` | `{"memory"}` (diff_count tracks memory-permutation state) | `extern_getDiffCount` at `ffi.cpp:254` reads `ctx.preflight.cycles[].diffCount[]` directly into memory family witness |

If a LIVE kind shows a different family fire, that's diagnostic data — record it in the Batch 3 report.

---

## Attestation pattern — PREDICTED DEAD kinds (B.6, B.7)

Mirror `test_d2b_cycle_mode_mod_attestation.py` (B.3) **exactly**, including:

1. `A4_FAMILY_RESIDUE=1` (so we positively confirm Hook 3 is silent too — channel C3 part of the guard model)
2. Run Layers 2–4 (trace mutates, Layer 3 dump confirms mutation in trace struct)
3. Parse rejection channels (C1/C2/C3/C4)
4. Wrap `check_soundness_bug_guard(...)` in `try/except SoundnessBugSuspected` — guard MUST fire (trace changed + all channels silent + verifier accepts)
5. Assert `guard_fired == True` with the W-17 reconciliation message
6. `pytest.xfail("...")` — **runtime call, no `strict=` kwarg** (that's a decorator-only parameter; runtime `pytest.xfail()` takes only `reason`)
7. Xfail rationale text references both:
   - `D2B_BATCH2_DEAD_ARM_AUDIT.md` — the precedent
   - The specific overwrite line in `steps.cpp` for this kind (B.6 → 14739-14740; B.7 → 14743)

### If a PREDICTED DEAD kind actually rejects

**Stop Batch 3 immediately**. This means the Batch 2 audit missed a witness path for this field. Do NOT just relabel it as LIVE and move on — the audit document needs to be reconciled:

1. Mark the kind in the Batch 3 report as **AUDIT FAILURE — RECONCILE REQUIRED**
2. Capture the exact rejection channel (C1 / C2 / C3 family) and any constraint-fail messages
3. Inspect `ffi.cpp` for extern reads of the field (`extern_get*` functions referencing `cycle.pc` for B.6, `cycle.state` for B.7)
4. Wait for Opus before deciding the corrective action (either: confirm an alternate live path and update §6d / W-17; or: deeper Rust trace to find what made this case live)

This is exactly the audit-reconciliation contract baked into plan §6d.

---

## Per-kind implementation notes (gotchas)

### B.4 `TXN_ADDR_MOD` — HIGH RISK

- **`FAULT_INJECTION_ENABLED=1`** is auto-set by the dispatcher at `witgen/mod.rs` ~line 224 when `A4_MUTATION_CONFIG` is present. **You do NOT need to set this manually.** Verify by reading mod.rs and confirming the env-set is still present (NFP-10 commit and Batch 1/2 should not have touched it).
- **Exclusions** (Q12 + Q13 LOCKED): exclude instruction-fetch txns AND register txns. Reuse `mem_val_mod._is_instruction_fetch()`. Register exclusion: txn addr in range `[0, 31 * 4]` (or whatever the canonical register address range is — verify against existing register-related code).
- **Value generation** per spec §3.4: 40% same-region nudge, 30% same-major redirect, 30% wild random.
- **Cascade**: expect possibly multiple `<constraint_fail>` tags (same-address chain breakage cascades through downstream same-address txns). Per §5.3, cascade is permitted. Signature: `{primary: "addr", allowed_cascade: ["word", "prev_word", "prev_cycle"]}`.

### B.5 `TXN_CYCLE_PHASE_MOD` — deterministic XOR

- **No `value` field in config.** The Python module does NOT call any `generate_new_value`. The Rust handler XORs the LSB unconditionally.
- **Exclusion** (Q14 LOCKED): exclude instruction-fetch txns. Reuse same helper as B.4.
- Confirm `mod.rs:486-487` still has `let is_read = txn.cycle % 2 == 0;` (this is the constraint-driven classification).
- Signature: `{primary: "cycle", allowed_cascade: []}` (LSB flip should be surgical — no cascade expected).

### B.6 `CYCLE_PC_MOD` — PREDICTED DEAD

- **Scope**: instruction cycles only (`major ∈ [0, 6]`) per taxonomy §3.12 and spec §3.6.
- Value generation: 40% nearby, 30% jump-target style, 30% random — all 4-byte aligned. (Even though predicted dead, we still generate values: the mutation must change the trace to trigger Layer 3 verification of the mutation-applied-but-witness-unchanged pattern.)
- **Attestation expectation**: mirror B.3. The reconciliation block above governs the failure mode.
- Hook 3 family expectation if alive (i.e., if audit reconciliation needed): likely `pc_paging` or `memory` — but **PREDICTED DEAD means no families fire**. If `pc_paging` IS in the family list, that itself is a finding.

### B.7 `CYCLE_STATE_MOD` — PREDICTED DEAD

- **CycleState enum source of truth** (Q15 LOCKED): use `a4/standalone/mutations/_cycle_state_enum.py` (already exists from Batch 1.0b). Do NOT re-extract from `platform.rs` — that's a W-8 re-extraction task only on risc0 pin bumps.
- Value generation: pick a different `CycleState` enum variant (deterministic random pick).
- Attestation: mirror B.3 → PREDICTED DEAD → guard fires → xfail.
- If alive: the audit missed an extern path for `cycle.state`. Note Composer claim in Batch 2 audit: "no `extern_getState` found". If B.7 rejects, find what we missed.

### B.8 `CYCLE_DIFF_COUNT_MOD` — LIVE via extern_getDiffCount

- **`diff_count: [u32; 2]`** is an array. Per Q3 LOCKED + spec §3.8 strategy (A): mutate one element. Config has `index ∈ {0, 1}` and `diff_count` value.
- **Live path confirmed**: `extern_getDiffCount` at `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp:254` reads `ctx.preflight.cycles[cycleU32 / 2].diffCount[cycleU32 % 2]` — direct trace read, no overwrite. Same live-read pattern as B.1/B.2/B.5.
- **NOTE on Q3 / W-3**: if B.8 attestation shows the field is dead (no constraint fail + verifier accepts), the W-3 watchlist entry says "drop only if dead proven AND trace changes verified". This means a guard-fires + xfail path for B.8, NOT silent skip. But based on `extern_getDiffCount` evidence, **B.8 is predicted LIVE**.

---

## Workflow

Sub-sequence | Tasks | Layer gate
---|---|---
**3.0** | Sanity checks above + record state | Pre-flight
**3.1** | B.4 Rust handler + trace_parser tag + Python module + unit tests | Layers 1+2
**3.2** | B.4 fuzzer registry + arm universe + `get_valid_steps_for_kind` + CGC `txn_role` | Layer 1
**3.3** | B.4 attestation test (LIVE pattern) | Layers 2–5
**3.4–3.6** | B.5 same shape as 3.1–3.3 | Layers 1–5
**3.7–3.9** | B.6 same shape (PREDICTED DEAD attestation pattern) | Layers 1–5 (test xfails)
**3.10–3.12** | B.7 same shape (PREDICTED DEAD) | Layers 1–5 (test xfails)
**3.13–3.15** | B.8 same shape (LIVE) | Layers 1–5
**3.16** | Phantom-arm-pruning bounds check + commit + Batch 3 report | Final gate

W-10 escape hatch: if any single kind blows past 1.5 days of attestation churn, **stop and split** into a separate sub-batch (paste the issue in the Batch 3 report, propose isolation). Composer should not silently grind on a stuck kind.

---

## Test commands

```bash
# Full Batch 3 attestation pass (mirror Batch 2 expectation)
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/ -q
# Expected: 5 new attestation tests pass (B.4/B.5/B.8 live, B.6/B.7 xfail)
# Total expected: previous_count + 5 passed (with 2 of them xfail)

# Per-kind isolated re-runs (useful if attestation churn hits)
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py -v -s
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py -v -s
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/test_d2b_cycle_pc_mod_attestation.py -v -s        # xfail expected
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/test_d2b_cycle_state_mod_attestation.py -v -s     # xfail expected
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest a4/standalone/tests/test_d2b_cycle_diff_count_mod_attestation.py -v -s

# Sanity: phantom arm pruning still pinned to V5 8 kinds
pytest a4/standalone/tests/test_v5_phantom_arm_pruning.py -v
```

---

## Pass criteria (Batch 3 ready to commit)

All must hold:

1. **All 3 LIVE attestation tests pass** (B.4, B.5, B.8) with the expected Hook 3 family fires (memory family at minimum)
2. **Both PREDICTED DEAD attestation tests xfail with W-17 rationale** (B.6, B.7) — guard fires, assertion confirms, xfail reason references the audit doc
3. **No new test failures** in the existing suite (Batch 1 + Batch 2 tests still green)
4. **Phantom-arm-pruning test still passes** with `V5_CONTROL_KINDS_8` pinning intact and bounds tolerating new `MUTATION_KINDS` size
5. **NFP-10 preserved** (`byte_addr` priority in Hook 3 family-residue emission still intact at the same location as Batch 2 — grep verification in the Batch 3 report)
6. **Batch 3 report `D2B_BATCH3_COMPOSER_REPORT.md`** delivered with:
   - Pre-kickoff sanity checklist output
   - Per-kind Layer 1–4 evidence (parser fires, unit tests pass, mutation visible in trace, attestation outcome)
   - **Hook 3 family residue table** per LIVE kind (what fired, what didn't)
   - **B.6 + B.7 dead-arm confirmation lines** (guard fired? xfail recorded? rationale linked to audit?)
   - Full test suite run with counts
   - Any audit-reconciliation surprises (should be zero — but if any, full reconciliation analysis with proposed §6d / W-17 amendments)
7. **Audit reconciliation rule honored**: if B.6 or B.7 rejects, the report STOPS Batch 3 with a "RECONCILE REQUIRED" header and the per-kind analysis — do not paper over

If pass criteria 1–5 all hold and report is complete, commit Batch 3 directly to `cloud2`:

```
D2.B Batch 3: B.4/B.5/B.8 live + B.6/B.7 W-17 dead arms confirmed.

- 3.1-3.6: TXN_ADDR_MOD (B.4) + TXN_CYCLE_PHASE_MOD (B.5) Rust handlers,
           Python modules, attestation — both LIVE via extern paths,
           memory family residue fires per Hook 3
- 3.7-3.12: CYCLE_PC_MOD (B.6) + CYCLE_STATE_MOD (B.7) implementation;
            attestation confirms PREDICTED DEAD per W-17 / §6d (guard
            fires, verifier accepts, xfailed with audit cross-ref)
- 3.13-3.15: CYCLE_DIFF_COUNT_MOD (B.8) Rust handler + Python module +
             attestation — LIVE via extern_getDiffCount (ffi.cpp:254),
             memory family residue fires
- 3.16: phantom-arm-pruning bounds verified for MUTATION_KINDS expansion

Hook 3 findings: B.4/B.5/B.8 memory family fires;
B.6/B.7 all channels silent + verifier accept (W-17 dead arms confirmed).
NFP-10 byte_addr field-priority fix preserved.
Tests: <new total> passed, <skips>, 3 xfailed (B.3 + B.6 + B.7 dead arms).

Plan v0.11 + Spec v0.5.3 audit predictions confirmed.

Co-authored-by: Cursor <cursoragent@cursor.com>
```

If any pass criterion fails (especially #2 audit reconciliation), **do not commit**. Write the report, paste the failure, and wait.

---

## Watchlist references (read before commit)

- **W-3** — `CYCLE_DIFF_COUNT_MOD` ship gate. Confirmed via Batch 3 attestation: keep B.8 if LIVE (expected); xfail-with-W-3-rationale only if dead.
- **W-6** — B.1 strategy split: irrelevant to Batch 3 but mentioned for context (B.4/B.5 are single-strategy).
- **W-8** — CycleState enum re-extraction on risc0 pin bumps (Batch 3 uses snapshot only).
- **W-10** — Batch 3 isolation: split if attestation churn > 1.5 days per kind.
- **W-15** — zone classifier audit (deferred to D2.D — not Batch 3 work).
- **W-16** — soundness-bug guard (real bug case): triggered if any kind shows trace mutates + verifier accepts AND we can prove the field IS in a witness path. The Batch 2 audit reframed B.3 from W-16 to W-17 by tracing the overwrite mechanism — B.6/B.7 we expect to follow.
- **W-17** — `set_cycle` overwrite dead-arm class: the central watchlist entry for B.6/B.7. The reconciliation rule lives here.

---

## Cross-references

- Spec sections: §3.4 (B.4), §3.5 (B.5), §3.6 (B.6), §3.7 (B.7), §3.8 (B.8), §4.4/§4.5/§4.7 (plumbing), §5.3/§5.4 (cascade + Batch 3 predictions)
- Plan sections: §6c (S1–S6 arm semantic stack), §6d (Batch 3 attestation prediction table), §9a (W-17), §9b (4-channel rejection + W-16/W-17 distinction)
- Audit: `D2B_BATCH2_DEAD_ARM_AUDIT.md` (full proof for B.3, prediction basis for B.6/B.7)
- Reports: `D2B_BATCH1_COMPOSER_REPORT.md`, `D2B_BATCH2_COMPOSER_REPORT.md`
- Templates: `a4/standalone/tests/test_d2b_cycle_mode_mod_attestation.py` (B.3 PREDICTED DEAD template), `a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py` (B.1 LIVE template)

---

**Composer ready to start when commit is in.**
