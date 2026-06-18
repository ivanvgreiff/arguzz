# D2.B Batch 3 — TXN Dead-Arm Audit Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) **v0.5.3 LOCKED + audit patch**
**Parent plan:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) **v0.12** (§6c arm-semantic stack, §6d Batch 3 attestation prediction table, §9b 4-channel rejection model, W-15/W-16/W-17/W-17b)
**Audit predecessor:** [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md) — sets the bar for "mechanism-proven" dead-arm classification
**Report predecessor:** [`D2B_BATCH3_COMPOSER_REPORT.md`](./D2B_BATCH3_COMPOSER_REPORT.md) — empirical B.4/B.5 dead-arm finding
**Issued by:** Ivan, on Opus's recommendation post-Batch-3 audit
**Expected effort:** ~1–2 days of focused witgen source-reading + writeup. No new Rust handler code, no new tests beyond minor patches.

---

## TL;DR for Composer

Batch 3 attestation **empirically** showed B.4 `TXN_ADDR_MOD` and B.5 `TXN_CYCLE_PHASE_MOD` are dead arms on sha2-host: trace mutates, all rejection channels silent, verifier accepts. **The mechanism is unproven.**

For B.3 we proved the dead-arm mechanism in [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md) by tracing `set_cycle` → `step_Top` overwrite via `exec_Reg(inst_result.newMode, ...)`. For B.4/B.5 we have only the **hypothesis** from your own Batch 3 report:

> "txn.addr and txn.cycle (phase) may be execution-derived in witness columns while prev_word / prev_cycle read mutated trace into memory delta — analogous in effect to W-17 but on txn fields, not yet traced in source."

This audit closes that gap. Without it, the soundness-guard pattern (mutation applied + trace changed + all channels silent + verifier accepts) is consistent with three different root causes:

| Root cause | Implication |
|---|---|
| **(a) True dead arm** | Field never enters witness for any guest; W-18 watchlist entry; harmless |
| **(b) Soundness bug** | Field enters witness, constraints don't catch it; **W-16 incident**, surface to Pro immediately |
| **(c) FAULT_INJECTION_ENABLED silencing** | Field enters witness, constraints fire, but the auto-set env var suppresses the channel; **test methodology gap**, need to disable FIE and re-test |

The soundness guard alone cannot distinguish these — they all produce the same observable. This audit must produce a mechanistic ruling.

**Read in this order:**

1. [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md) — the bar; structure your audit doc the same way
2. [`D2B_BATCH3_COMPOSER_REPORT.md`](./D2B_BATCH3_COMPOSER_REPORT.md) — your own empirical findings
3. `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` — extern functions that read trace data into witness
4. `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` — dispatcher (especially the `FAULT_INJECTION_ENABLED` set site ~line 224)
5. `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs` — txn preflight construction; where does `txn.addr` originate?
6. `zirgen/zirgen/circuit/rv32im/v2/dsl/` — DSL for memory constraints; especially anything that consumes `txn.addr` or the cycle phase classification

---

## Pre-kickoff sanity checklist (run before any source reading)

Paste output in the audit doc.

```bash
cd /root/arguzz
git rev-parse --abbrev-ref HEAD          # → cloud2
git log --oneline -3
git status                               # Batch 3 work still in working tree, uncommitted

# Confirm the empirical finding still reproduces (single test, ~2 min each)
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest \
    a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py -v -s
A4_REAL_BINARY=1 A4_FAMILY_RESIDUE=1 pytest \
    a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py -v -s
# Both should xfail with the "unexpected dead arm" rationale
```

If either fails (or passes), the empirical baseline has shifted — STOP and report before audit.

---

## Primary task: prove B.4 and B.5 dead arms mechanistically

Produce `a4/docs/cloud2/composer/D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` structured like the Batch 2 audit. Required sections:

### 1. Terminology (precision required)

Same table format as Batch 2 audit §1, adapted to txn fields:

| Term | Meaning for B.4 |
|---|---|
| Trace mutation | `trace.txns[i].addr` changed in RAM before witgen — TRUE (Layer 3 dump proves) |
| Witness mutation | Committed witness columns that constraints actually read, derived from the mutated `addr` — **to be determined** |
| No-op | Nothing changed in trace — **WRONG** (trace changed) |
| Dead arm | Mutation applies to trace struct but no witness column ever reflects the mutated value | **claim under audit** |
| Soundness bug (W-16) | Witness column reflects mutated value, constraints accept the corrupted witness | **must rule out** |

### 2. Hypothesis statements (from Batch 3 report)

For B.4: "`txn.addr` is execution-derived in witness columns; the trace's `addr` field is used only as a permutation-argument lookup key that is re-verified against an execution-side addr."

For B.5: "`txn.cycle` LSB encodes read/write phase but is execution-derived in witness columns; the trace's phase bit is overridden or unused."

These are the claims to verify or disprove.

### 3. Source-level trace for B.4 (`txn.addr`)

Walk the path from `trace.txns[i].addr` to any witness column that depends on it. Required line references for each step:

- **3a. Where is `txn.addr` populated in preflight?** (`preflight.rs` — preflight cycle/txn construction)
- **3b. Which externs in `ffi.cpp` read `ctx.preflight.txns[].addr` directly?**
  - Identify every `extern_*` function that touches `txn.addr` or any field derived from it.
  - For each: what does it return? Which DSL/zir code is the consumer? Which witness column receives the value?
  - **Especially important:** `extern_getMemoryTxn` and any variants (`extern_getMemoryTxnReg`, etc.) — these are the most likely B.1/B.2 LIVE path.
- **3c. Does any extern READ `txn.addr` separately from the txn structure as a whole?**
  - If `extern_getMemoryTxn` returns the entire txn (all fields), then `addr` reaches the witness automatically.
  - If a separate `extern_getAddr` or similar exists, it might READ `txn.addr` in a way that bypasses the prev_word/prev_cycle path.
- **3d. What constraints in `zirgen/circuit/rv32im/v2/dsl/` consume the address?**
  - Find the DSL definitions for the memory permutation argument.
  - Verify whether the constraint checks `mutated_addr == execution_derived_addr` or just reads `mutated_addr` directly into the witness without cross-checking.
  - Identify the LOCATION of any cross-check (DSL line + generated `steps.cpp` line if relevant).
- **3e. Does `FAULT_INJECTION_ENABLED=1` change the behavior of step 3d?**
  - Find the dispatcher line that sets this env var (`witgen/mod.rs` ~line 224).
  - Trace how it affects downstream code — does it suppress throws? Suppress witness writes? Suppress Hook 3 emission?
  - **Critical disambiguation:** is the silence we observe in B.4 due to (a) no constraint to break, or (c) a constraint that breaks but gets silenced?

### 4. Source-level trace for B.5 (`txn.cycle` LSB / phase)

Same structure as §3 but for the cycle LSB:

- **4a.** Where is `txn.cycle` populated (LSB encoding read/write phase)?
- **4b.** Where does `let is_read = txn.cycle % 2 == 0` (mentioned in spec §3.5, `mod.rs:486-487`) feed?
- **4c.** Which externs use `txn.cycle` as a whole vs the LSB specifically?
- **4d.** What DSL constraints classify a memory txn as read vs write? Do they read from the trace's `txn.cycle` LSB or from execution state?
- **4e.** Same FAULT_INJECTION_ENABLED disambiguation as §3e.

### 5. Disambiguation tests (REQUIRED)

You MUST perform at least one of these to rule out FAULT_INJECTION_ENABLED silencing (root cause (c) above):

**Option α — Static disambiguation:**
Read the FAULT_INJECTION_ENABLED handling code (every site in Rust + C++ kernels). Document explicitly what it suppresses and what it lets through. If it provably does NOT suppress Hook 3 family residue emission or `verify segment` panics, then root cause (c) is ruled out.

**Option β — Empirical disambiguation:**
Modify the dispatcher to TEMPORARILY disable `FAULT_INJECTION_ENABLED` for one attestation run (just B.4). Run the attestation again. If output changes (e.g., a `verify segment` panic appears, or `<constraint_fail>` tags emit), then root cause (c) was masking signal — revisit the methodology. If output is identical (still verifier-accept, still silent channels), then FIE was not masking, and the dead-arm classification stands.

State which option you used and why.

### 6. Comparison: B.1/B.2 (LIVE) vs B.4/B.5 (dead) on the same txn

Pick **txn 15415 step 1** (mentioned in your Batch 3 report). For this single txn:

| Mutation | Field | Witness path (per audit) | Constraint that should fire | Actual channel observed |
|---|---|---|---|---|
| B.1 `TXN_PREV_WORD_MOD` | `txn.prev_word` | … | … | `memory` Hook 3 family |
| B.2 `TXN_PREV_CYCLE_MOD` | `txn.prev_cycle` | … | … | `memory` + `cycle` |
| B.4 `TXN_ADDR_MOD` | `txn.addr` | … | … | silent + verifier accept |
| B.5 `TXN_CYCLE_PHASE_MOD` | `txn.cycle` LSB | … | … | silent + verifier accept |

Fill in the "Witness path" and "Constraint that should fire" columns from your source reading. If B.1/B.2 share a witness path with B.4/B.5 (same `extern_getMemoryTxn` returning all fields), explain the divergence — why does mutating one field of the same txn fire the channel and another not?

This is the key test of the hypothesis. The hypothesis predicts that B.4/B.5 fields are RE-DERIVED in the witness (so the trace mutation doesn't matter), while B.1/B.2 fields are READ from the trace into the witness directly. The audit must verify or disprove this structurally.

### 7. Certainty table

End with a Batch-2-style certainty table:

| Statement | Certainty | Source |
|---|---|---|
| B.4 trace `addr` mutated | 100% | Layer 3 dump |
| B.4 witness column for addr is re-derived from execution state | TBD% | `<source citation>` |
| B.4 dead arm on sha2-host user txns | TBD% | composition of above |
| B.4 dead arm on ALL guests / cycle types | TBD% | <qualify if not exhaustive> |
| B.4 NOT a soundness bug | TBD% | composition |
| FAULT_INJECTION_ENABLED rules out as masking factor | TBD% | §5 |
| (Same six rows for B.5) | | |

### 8. Verdict

For each of B.4 and B.5, state ONE of:

- **TRUE DEAD ARM (mechanism-proven)** — witness path traced; constraints verified; FIE ruled out as masking. Promote to W-18 in plan §9a.
- **SOUNDNESS BUG SUSPECTED (W-16 incident)** — witness path reaches a constraint that should have rejected but didn't. **STOP audit; escalate to Ivan immediately; do not proceed with Batch 3 commit.**
- **INCONCLUSIVE** — source reading didn't fully resolve. Document what's still unknown, what additional evidence would resolve it, and proceed with caution (don't promote to W-18 yet).

### 9. Reconciliation rule (if SOUNDNESS BUG SUSPECTED)

If the audit determines either B.4 or B.5 is a real soundness bug (root cause (b)):

1. **Stop the audit at the verdict line; do not finish remaining sections.**
2. **Do not commit Batch 3.**
3. **Surface to Ivan immediately** with the source-level evidence of which witness column accepts the mutated value and which constraint should have rejected.
4. The B.3 W-17 framework allows us to identify dead arms; this would be the first W-16 (real soundness gap) found by the framework — exactly what the soundness-bug guard was built to catch.
5. Becomes an NFP candidate for Pro disclosure (NFP-11 in `IV_POS_8_NOTES_FOR_PRO.md` — surface the bug + the prover/circuit version it exists in).

---

## Secondary task: confirm B.6/B.7 have no extern read path (optional, encouraged)

Composer's Batch 3 report flagged honest uncertainty: "For B.6/B.7 we're confident on the tested cycle class but haven't proven 'never live on any cycle type'." While you're already in the witgen source, do a quick `grep extern_getPc` / `grep extern_getState` / `grep -r "cycles\[.*\]\.pc" workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/` to enumerate every external read of `cycle.pc` and `cycle.state`. Expected result: only `set_cycle` reads them (which is overwritten per W-17). If you find a different read site, that's a new live path → audit reconciliation per §6d.

Document the grep results in the audit doc §A1 (appendix) — even if the result is "no extern path found", the explicit enumeration is the evidence that locks in the B.6/B.7 dead-arm classification.

---

## Minor patches required (commit alongside audit doc)

### Patch 1: AUDIT NOTE wording fix in B.4/B.5 attestation tests

The current message is logically inverted. In both files, replace:

`a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py:105-108`:

```python
pytest.fail(
    "AUDIT NOTE: TXN_ADDR_MOD showed live rejection — spec predicted LIVE; "
    "reconcile witness path for txn.addr"
)
```

with:

```python
pytest.fail(
    "AUDIT FAILURE — RECONCILE REQUIRED: TXN_ADDR_MOD showed live rejection. "
    "Batch 3 empirical dead-arm finding contradicted on this target. "
    "Investigate which witness path reached the constraint; reconcile against "
    "D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md."
)
```

`a4/standalone/tests/test_d2b_txn_cycle_phase_mod_attestation.py:102-104`:

```python
pytest.fail(
    "AUDIT NOTE: TXN_CYCLE_PHASE_MOD showed live rejection — spec predicted LIVE; reconcile"
)
```

with:

```python
pytest.fail(
    "AUDIT FAILURE — RECONCILE REQUIRED: TXN_CYCLE_PHASE_MOD showed live rejection. "
    "Batch 3 empirical dead-arm finding contradicted on this target. "
    "Reconcile against D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md."
)
```

Rationale: if rejection fires, the spec's LIVE prediction was correct; the empirical Batch 3 dead-arm finding is what's contradicted. The old wording inverts cause and effect.

### Patch 2: B.4 cascade tightening to `[]`

`a4/standalone/tests/test_d2b_txn_addr_mod_attestation.py:96-100`:

```python
assert_trace_diff_matches_signature(
    diffs,
    {"primary": {"txn_idx": target.txn_idx, "field": "addr", "old": target.original_addr, "new": new_addr},
     "cascade": ["word", "prev_word", "prev_cycle", "cycle"]},
)
```

becomes:

```python
assert_trace_diff_matches_signature(
    diffs,
    {"primary": {"txn_idx": target.txn_idx, "field": "addr", "old": target.original_addr, "new": new_addr},
     "cascade": []},
)
```

Rationale: the Rust handler only mutates `txn.addr` on one txn. No other txn's fields should change in the **trace** post-handler. The current cascade list allowed permissive verification; tightening it would catch any future regression where the handler accidentally touches more than `addr`.

If the tightened test FAILS, that itself is an important finding — it means the handler is doing more than it claims. Don't relax it back; investigate the unexpected cascade.

---

## Documentation requirements

### "Broader scan" appendix in the audit doc

Your report claimed B.4/B.5 were "scanned much more broadly (multiple steps and txns)" while only one target is in the regression suite. Document the manual scan results in the audit doc §A2 (appendix):

```
B.4 TXN_ADDR_MOD scan log:
  - Step 1, txn 15415 (register-region): dead-arm pattern observed
  - Step 1, txn 15420 (heap region): <outcome>
  - Step 16, txn N: <outcome>
  - Step 24, txn N: <outcome>
  - Step 26, txn N: <outcome>
  - Step 28, txn N: <outcome>
  - Step 100, txn N: <outcome>
  - Step 500, txn N: <outcome>
  - Step 1000, txn N: <outcome>
B.5 TXN_CYCLE_PHASE_MOD scan log: (same format)
```

Fill in the actual (step, txn_idx) pairs you scanned plus the per-target outcome. If a scan was done outside the test (e.g., by manually editing the attestation `_find_target` or running a one-off script), describe the methodology.

This is required for the audit to count as "evidence beyond the single-target attestation test".

### Plan + spec updates (after audit verdict)

If verdict is **TRUE DEAD ARM** for both kinds, you (Composer) make the following doc updates as part of the same commit as the audit:

1. **Plan §9a**: add **W-18** watchlist entry for the txn-field dead-arm class, parallel to W-17:
   - Description: txn fields where the witness is execution-derived rather than trace-read (B.4 `addr`, B.5 `cycle.lsb`).
   - Witness mechanism: <one-line cite from audit §3/§4>
   - Trigger: same-target live rejection on a future binary or guest — reconcile against audit.
   - Fallback: drop from `MUTATION_KINDS` at D2.B postscript §9c (joins B.3 + predicted B.6/B.7 + now confirmed B.4/B.5).
2. **Plan §6d**: extend Batch 3 attestation predictions table — mark B.4/B.5 actual outcomes as `DEAD (W-18)` with audit cross-ref.
3. **Spec §5.4**: same — mark B.4/B.5 confirmed dead, link audit.
4. **Spec §3.4 + §3.5**: append "Attestation outcome (Batch 3 — CONFIRMED dead arm via W-18)" subsections analogous to §3.3 for B.3.
5. **Plan §9c**: update D2.B-PS-1 task list to include B.4/B.5 removal from `MUTATION_KINDS` (5 dead kinds total: B.3 + B.4 + B.5 + B.6 + B.7).
6. **`IV_POS_8_NOTES_FOR_PRO.md`**: add NFP-11 documenting the dead-arm split for Pro — among Pro's 8 requested A4 kinds, 3 are live (B.1, B.2, B.8) and 5 are dead arms (B.3 W-17, B.4 W-18, B.5 W-18, B.6 W-17, B.7 W-17). Cite mechanism for each.

If verdict is **INCONCLUSIVE**, skip the plan/spec promotion and leave the empirical findings in the report. Open follow-up task in plan §9c for the next round of investigation.

If verdict is **SOUNDNESS BUG SUSPECTED**, do nothing else — escalate.

---

## Pass criteria

All must hold before commit:

1. `D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md` exists with all §1–§9 sections populated.
2. Each Opus claim / hypothesis is verified or disproved with line-referenced source citations (no speculation).
3. FAULT_INJECTION_ENABLED disambiguation is explicit (Option α or β from §5).
4. Comparison table §6 has all 4 rows filled with witness path + constraint identification.
5. Certainty table §7 has every row at ≥90% (or you explicitly flag the lower-confidence rows).
6. Verdict §8 is one of {TRUE DEAD ARM, SOUNDNESS BUG SUSPECTED, INCONCLUSIVE}. No fence-sitting.
7. Patch 1 + Patch 2 applied to the attestation tests.
8. Broader scan appendix §A2 populated with actual scan data.
9. If verdict is TRUE DEAD ARM: plan §9a (W-18), §6d, §9c + spec §5.4, §3.4, §3.5 + `IV_POS_8_NOTES_FOR_PRO.md` (NFP-11) all updated.
10. Audit doc cross-references the Batch 2 audit and the Batch 3 report.

---

## Commit sequencing

When pass criteria 1–10 hold, commit Batch 3 + the audit + the patches together:

```
D2.B Batch 3: 5 kinds implemented (B.4–B.8) + dead-arm audit.

- Rust handlers in witgen/mod.rs for all 5 kinds
- 5 Python mutation modules, 5 attestation tests, unit tests (13 passed)
- Plumbing: semantic_arm_universe, inspection_data, CGC, registry,
  trace_parser, _MAJOR_FILTER_KINDS
- Infrastructure: a4_cycle_info / a4_post_mut_cycle_dump extended with
  state, diff_count_0/1

Empirical attestation outcomes (sha2-host, --in1 5 --in4 10):
- B.4 TXN_ADDR_MOD       — DEAD ARM (W-18, mechanism-proven via audit)
- B.5 TXN_CYCLE_PHASE_MOD — DEAD ARM (W-18, mechanism-proven via audit)
- B.6 CYCLE_PC_MOD       — DEAD ARM (W-17 confirmed)
- B.7 CYCLE_STATE_MOD    — DEAD ARM (W-17 confirmed)
- B.8 CYCLE_DIFF_COUNT_MOD — LIVE (cycle Hook 3 family)

Audit: D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md proves W-18 dead-arm mechanism
for txn.addr and txn.cycle.lsb via <one-line mechanism summary>.
FAULT_INJECTION_ENABLED ruled out as masking via <Option α/β>.

Plan v0.12 → v0.13: W-18 added; §6d empirical column populated;
§9c postscript scope expanded to 5 dead kinds.
Spec v0.5.3 → v0.5.4 audit patch: §3.4, §3.5, §5.4 marked confirmed dead.
NFP-11 in NOTES_FOR_PRO documents the dead/live A4-kind split for Pro.

Tests: 559 passed, 7 skipped, 5 xfailed (B.3 + B.4 + B.5 + B.6 + B.7
documented dead arms), 2 failed (pre-existing test_run_replicates).

Co-authored-by: Cursor <cursoragent@cursor.com>
```

If verdict is SOUNDNESS BUG SUSPECTED or INCONCLUSIVE, do NOT commit Batch 3 yet — instead post the audit findings + escalation. Ivan will decide next steps.

---

## What I am NOT asking you to do

- Re-run the full attestation suite (the ~14 minute one). Single-target re-runs in the sanity checklist suffice.
- Write new Rust handlers or modify existing ones (except optionally for the empirical Option β disambiguation, which you'd revert before commit).
- Update the kickoff document (`D2B_BATCH3_COMPOSER_KICKOFF.md`) retroactively — historical record.
- Change the dispatch logic for B.6/B.7 paging cycles unless you find a real live path during the secondary task §A1 grep.
- Make a decision about removing dead arms from `MUTATION_KINDS` — that's the §9c postscript, post-Batch-4, owned by Opus.

---

## Cross-references

- [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md) — Batch 2 audit (the bar)
- [`D2B_BATCH3_COMPOSER_REPORT.md`](./D2B_BATCH3_COMPOSER_REPORT.md) — Batch 3 implementation report
- [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) §6c, §6d, §9a (W-17/W-17b), §9b, §9c
- [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) §3.4, §3.5, §5.4, §5.5
- Source files: `ffi.cpp`, `steps.cpp`, `witgen/mod.rs`, `witgen/preflight.rs`, `zirgen/circuit/rv32im/v2/dsl/`

---

**Composer ready to start the audit when sanity checklist completes.**
