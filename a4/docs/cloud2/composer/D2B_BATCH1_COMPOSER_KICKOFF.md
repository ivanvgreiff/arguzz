# D2.B Batch 1 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) **v0.5.1 LOCKED**
**Parent plan:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.9
**Notes for Pro:** [`../IV_POS_8_NOTES_FOR_PRO.md`](../IV_POS_8_NOTES_FOR_PRO.md) — read NFP-3, NFP-5, NFP-6, NFP-10 before starting
**Predecessors:** D2.A Batch 1 (`b844e8e`) + D2.A Batch 2 (`7b66fb9`) merged to `cloud2`; D1.B Batch 1 (`71dae77`) + D1.C (`3a8487c`) also in `cloud2`
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~3–4 days of focused Composer work (Rust handler + Python module + 5-layer attestation test)

---

## TL;DR for Composer

Implement **D2.B Batch 1** as defined in `IV_POS_8_D2_B_SPEC.md` §7 "Batch 1" (tasks 1.0a through 1.10). This is the **load-bearing batch** of D2.B: it ships the Layer 3 attestation infrastructure (a new ~30 LOC Rust hook), B.1 `TXN_PREV_WORD_MOD` end-to-end (Rust handler + Python module + registry plumbing + tests), and the `PRE_EXEC_REG_MOD` retrofix (NFP-6, ~10 LOC A4-only cleanup).

**Read in this order before writing code:**

1. The locked spec (`IV_POS_8_D2_B_SPEC.md` v0.5.1) — source of truth for all design decisions
2. NFP-3, NFP-5, NFP-6, NFP-10 in `IV_POS_8_NOTES_FOR_PRO.md` — context for why each piece matters to Pro
3. This kickoff document — workflow framing + pass criteria
4. `IV_POS_8_D2_PLAN.md` §9a watchlist W-12, W-13 — the two D1-chat-coordination concerns that affect THIS batch

**Single hardest constraint:** the Layer 3 dump-post-mut hook (task 1.0a) MUST land and be verified on an existing kind (e.g., COMP_OUT_MOD) *before* any B.1 handler work begins. Without it, B.1's attestation test (task 1.8) is broken by construction — Layer 3 would compare two pre-mutation dumps because the inspection block in `witgen/mod.rs` runs at lines ~72–187, *before* the mutation block at lines ~189–601. See spec Q17 + NFP-5 for the full rationale.

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

Composer MUST verify each of these and paste the output in the Batch 1 report:

```bash
# 1. On cloud2 branch, working tree clean
git branch --show-current        # → cloud2
git status                       # → clean (no uncommitted changes)

# 2. D2.A foundation tests pass
pytest a4/standalone/tests/ -q   # → ≥510 passed (D2.A Batch 2 baseline)

# 3. NFP-10 byte_addr fix is in place — DO NOT revert during §4.7 edits
grep -n 'byte_addr.*addr.*address' a4/standalone/compressed_global_extractor.py
# → expect line 216: for key in ("byte_addr", "addr", "address"):

# 4. PRE_EXEC_REG_MOD hardcode is still in place — Batch 1.5e will fix it
grep -n 'strategy="next_read"' a4/standalone/fuzzer.py
# → expect line 1639: targets = get_pre_exec_reg_targets(step, self.data, strategy="next_read")

# 5. Locate the unified A4 mutation dispatcher in witgen
grep -n '"PRE_EXEC_REG_MOD"' workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
# → expect line 462: (Some("PRE_EXEC_REG_MOD"), Some(target_step)) =>

# 6. risc0-modified submodule is initialized (Rust build will fail without this)
ls workspace/risc0-modified/risc0/circuit/rv32im/Cargo.toml
# → expect file exists
```

If any of these fail, **stop and report** rather than improvising.

---

## Scope (exactly what Batch 1 ships)

### Spec sections this batch implements

- **§1.5** Layer 3 infrastructure (the post-mutation dump hook)
- **§3.1** B.1 `TXN_PREV_WORD_MOD` — two strategies (`at_read`, `at_write`), Option A bandit wiring (one kind string, RNG-picked strategy per pull)
- **§4.1** Rust changes to `witgen/mod.rs`
- **§4.2** Rust build + binary deploy
- **§4.3** Python module `mutations/txn_prev_word_mod.py`
- **§4.4** `inspection_data.py::get_valid_steps_for_kind` extension (B.1 branch only in Batch 1)
- **§4.5** `semantic_arm_universe.py` registration (B.1 only in Batch 1)
- **§4.6** `fuzzer.py` `MUTATION_KINDS` registry + `_create_mutation` dispatch (B.1 + PRE_EXEC_REG_MOD retrofix)
- **§4.7** `compressed_global_extractor.py` `_TXN_ROLE_BY_KIND` entry for B.1 (Pro-valid role per Q5 Option A)
- **§5** 5-layer testing methodology, applied to B.1
- **§7 Batch 1** task list (1.0a → 1.10)

### Files touched

| File | Action | Rough size |
|---|---|---|
| `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | (1.0a) Add `A4_DUMP_POST_MUT=1` post-mutation dump hook — emits `<a4_post_mut_dump>` tags after each mutation match arm completes. (1.1) Add B.1 Rust handler (`TXN_PREV_WORD_MOD`) with both `at_read` and `at_write` strategies. Pattern: extend the existing match block between MEM_VAL_MOD (line 588) and the fallback. | ~30 LOC (1.0a) + ~80 LOC (1.1) = ~110 LOC |
| `a4/core/trace_parser.py` | Add `parse_post_mut_dump(output)` mirroring `parse_all_all_txns` / `parse_all_a4_cycles`. Used by attestation test to read the post-mut dump tags. | ~40 LOC |
| `a4/standalone/mutations/txn_prev_word_mod.py` (NEW) | B.1 Python module: `TxnPrevWordModTarget` dataclass, `get_targets_at_step(step, data, strategy="at_read")` (supports both strategies), `create_config(target, mutated_value, strategy)`, value-generation per spec §3.1. Pattern: model on `pre_exec_reg_mod.py` (closest precedent — two-strategy structure). | ~250 LOC |
| `a4/core/inspection_data.py` | Add B.1 branch to `get_valid_steps_for_kind`: any step with at least one txn (no major filter). Per spec §4.4. | ~5 LOC |
| `a4/standalone/semantic_arm_universe.py` | Add B.1 to `_MUTATION_MODULES` dict. Add B.1 branch to `_cycle_matches_kind_filter` (txn-presence filter, not major filter). Add B.1 branch to `_step_has_real_target` that **ORs both strategies** (mandatory per Q11 Option A — see spec §6 Q11 plumbing step 3). Do NOT add B.1 to `_MAJOR_FILTER_KINDS` (txn-based, follows MEM_VAL_MOD pattern). | ~30 LOC |
| `a4/standalone/fuzzer.py` | Add `"TXN_PREV_WORD_MOD"` to `MUTATION_KINDS` constant. Add B.1 branch to `_create_mutation(kind, step)`: RNG-picks `at_read`/`at_write`, calls `get_targets_at_step(step, data, strategy=strategy)`, builds config with `strategy` field. **(1.5e) PRE_EXEC_REG_MOD retrofix:** change line 1639 from hardcoded `strategy="next_read"` to `strategy = self.rng.choice(["next_read", "prev_write"])` (and pass through to config). | ~40 LOC (B.1) + ~10 LOC (retrofix) |
| `a4/standalone/compressed_global_extractor.py` | Add `"TXN_PREV_WORD_MOD": "prev_word"` to `_TXN_ROLE_BY_KIND` (line ~161 area). **DO NOT MODIFY line 216 `_coerce_broken_addr`** — that's the NFP-10 byte_addr fix; preserve it as-is. | ~2 LOC |
| `a4/standalone/tests/_test_helpers/diff_signature.py` (NEW) | Shared `assert_trace_diff_matches_signature(diff, expected_signature)` helper per Q16 spec. Minimal v1: signature = `{"primary": {"txn_idx": int, "field": str, "old": int, "new": int}, "cascade": Optional[List[str]]}`. Helper compares actual diff against signature; raises descriptive AssertionError. Also implements the SOUNDNESS-BUG GUARD per plan §9b: raise `SoundnessBugSuspected` when `applied=True` AND post-mut dump confirms field changed AND no constraint failed AND no error emitted. | ~120 LOC |
| `a4/standalone/tests/test_d2b_txn_prev_word_mod_unit.py` (NEW) | Layer 1 unit tests for B.1 Python module. Covers: target selection for both strategies, config building, value-gen distribution sanity, fuzzer dispatch picks strategy via RNG, registry membership. NO real binary. | ~180 LOC |
| `a4/standalone/tests/test_d2b_pre_exec_reg_mod_two_strategy.py` (NEW) | Companion unit test for the PRE_EXEC_REG_MOD retrofix (task 1.5f). Covers: fuzzer dispatch RNG-picks both strategies across many seeds; `_step_has_real_target` ORs both; no regression in existing PRE_EXEC_REG_MOD behavior under seed=42 (the seed used in the D2.A golden trace, which is itself a scheduler-only test and stays green). | ~80 LOC |
| `a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py` (NEW) | **Layers 2 + 3 + 4** attestation test for B.1. Runs the real risc0-host binary with `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 A4_DUMP_POST_MUT=1 A4_MUTATION_CONFIG=...`. Verifies: (Layer 2) `<a4_txn_prev_word_mod>` evidence tag emitted with correct `old_value`/`new_value`/`strategy`; (Layer 3) post-mut dump shows `txn[i].prev_word` changed to the expected value AND nothing else in the touched window changed (per `assert_trace_diff_matches_signature`); (Layer 4) cross-check: Layer 2 tag + Layer 3 dump agree on the exact change. Gated by `A4_REAL_BINARY=1` env var per Q4. | ~200 LOC |

**Total expected delta:** ~1100 LOC across 11 files (Rust + Python + tests). ~3–4 days at D2.A Batch 1 pace.

### Pre-implementation investigations (task 1.0b)

Before writing B.1 handler code, Composer MUST resolve two open questions:

**(a) CycleState enum extraction (Q15)** — extract the full enum from `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs` (or wherever `enum CycleState` lives — `rg "enum CycleState" workspace/risc0-modified/` should find it). Snapshot the values + numeric assignments into a Python constant at `a4/standalone/mutations/_cycle_state_enum.py` (this file is for B.7 in a later batch but the enum is needed for context now). Document the file path + commit hash in the Batch 1 report.

**(b) B.8 diff_count constraint linkage (Q3)** — `preflight.rs:227, 306` populate the field; zirgen reads it via `get_diff_count`. Grep the zirgen circuit source to find which constraint(s) consume `get_diff_count`. Report findings to Batch 1 report so Q3 can be locked at Batch 3 (when B.8 ships). This is a ~30-minute investigation, not a B.8 implementation — B.8 ships in Batch 3.

These are written into the Batch 1 report; they do not gate Batch 1 acceptance, but they de-risk Batches 2 and 3.

---

## NOT in Batch 1 (deferred)

| Item | Where it ships |
|---|---|
| B.2 `TXN_PREV_CYCLE_MOD`, B.3 `CYCLE_MODE_MOD` | Batch 2 |
| B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD`, B.8 `CYCLE_DIFF_COUNT_MOD` | Batch 3 |
| Cross-cutting `test_d2b_arm_registration.py` (covers all 8 kinds) | Batch 4 |
| Campaign smoke test `test_d2b_campaign_smoke.py` (mocked binary) | Batch 4 |
| D2.D variant CLI changes (variant-specific kind subsets per Q6) | D2.D (separate deliverable) |
| Any changes to `bandit_ts.py`, `coverage_db.py` schema, `reward_v2.py` | None — these are foundation files locked in D2.A (per spec §4.9 "must not change") |
| D1.E reward rewire (`compute_bandit_success` extension) | D1 chat owns this; D1.E waits for THIS batch's 1.5e to merge before starting |

If you find yourself touching anything in the "must not change" list, **stop and confirm with Ivan**.

---

## Critical instructions for specific tasks

### Task 1.0a — `A4_DUMP_POST_MUT=1` Rust hook

This is the load-bearing infrastructure for Layer 3 attestation. Without it, Layer 4's "100% certainty" claim is false (per NFP-5).

Implementation pattern: at the END of each mutation match arm in `witgen/mod.rs` (e.g., after the `<a4_pre_exec_reg_mod>` evidence tag emission), add a conditional block:

```rust
if std::env::var("A4_DUMP_POST_MUT").is_ok() {
    // Emit <a4_post_mut_dump> tag(s) for the modified row(s).
    // Format mirrors the existing <a4_txn>/<a4_cycle> dump format from inspection block.
    // For txn mutations: dump the modified txn + same-addr neighbors in [-2, +2] window.
    // For cycle mutations: dump the modified cycle + neighbors in [-1, +1] window.
    println!("<a4_post_mut_dump>{{\"kind\":\"...\", \"txn_idx\":..., \"field\":\"...\", \"new_value\":...}}</a4_post_mut_dump>");
}
```

Smoke-verify on `COMP_OUT_MOD` BEFORE writing the B.1 handler:
1. Build the binary with the hook added but no B.1 handler yet
2. Run a COMP_OUT_MOD mutation with `A4_DUMP_POST_MUT=1`
3. Confirm `<a4_post_mut_dump>` appears in stdout with the expected `word` change

If the smoke fails, the rest of Batch 1 is blocked. **Stop and report.**

### Task 1.5e — `PRE_EXEC_REG_MOD` retrofix — MANDATORY commit-message convention

**The commit that lands this batch MUST contain the literal string `"Batch 1.5e"` in its commit message** (subject line OR body). This is the signal mechanism D1 chat uses to detect that D1.E can resume (per `IV_POS_8_D1_REVISIT_PLAN.md` §4.3 Option B and D2 plan §9a W-12).

Recommended commit message format for Batch 1:

```
D2.B Batch 1: A4_DUMP_POST_MUT hook + TXN_PREV_WORD_MOD (B.1) + PRE_EXEC_REG_MOD retrofix (Batch 1.5e).

- 1.0a: New <a4_post_mut_dump> Rust hook in witgen/mod.rs gated by A4_DUMP_POST_MUT=1
- 1.0b: CycleState enum extracted + B.8 diff_count constraint linkage findings reported
- 1.1: B.1 TXN_PREV_WORD_MOD Rust handler (at_read + at_write strategies)
- 1.4: mutations/txn_prev_word_mod.py with two-strategy targeting
- 1.5a-d: Registry plumbing (inspection_data, semantic_arm_universe, fuzzer MUTATION_KINDS + _create_mutation, compressed_global_extractor _TXN_ROLE_BY_KIND)
- 1.5e: PRE_EXEC_REG_MOD retrofix — RNG-picks next_read/prev_write per pull (NFP-6, A4-only, unblocks D1.E)
- 1.5f: Companion test for retrofix
- 1.6: B.1 unit test
- 1.7: Shared assert_trace_diff_matches_signature helper with soundness-bug guard
- 1.8: B.1 attestation test (Layers 2+3+4) gated by A4_REAL_BINARY=1

Tests: <N> passed (D2.A Batch 2 baseline 510 + new tests).

Co-authored-by: Cursor <cursoragent@cursor.com>
```

### Task 1.5e — what the retrofix MUST do (NFP-6 detail)

`a4/standalone/fuzzer.py:1639` — change the existing line:

```python
elif kind == "PRE_EXEC_REG_MOD":
    targets = get_pre_exec_reg_targets(step, self.data, strategy="next_read")
```

To RNG-pick strategy per pull:

```python
elif kind == "PRE_EXEC_REG_MOD":
    strategy = self.rng.choice(["next_read", "prev_write"])
    targets = get_pre_exec_reg_targets(step, self.data, strategy=strategy)
    # ... existing target selection code ...
    config["strategy"] = strategy  # ensure config dict includes the strategy field for Rust dispatcher
```

`a4/standalone/semantic_arm_universe.py:90-91` — change the existing:

```python
if kind == "PRE_EXEC_REG_MOD":
    t = mod.get_targets_at_step(step, data, strategy="next_read")
```

To OR both strategies:

```python
if kind == "PRE_EXEC_REG_MOD":
    t_read  = mod.get_targets_at_step(step, data, strategy="next_read")
    t_write = mod.get_targets_at_step(step, data, strategy="prev_write")
    t = t_read or t_write  # step is real if EITHER strategy has a target
```

This is **A4-only**. Do NOT touch any Arguzz code path (subprocess to Arguzz binary, `<fault>` parsing). Arguzz mutation strategies are deliberately unchanged per Ivan's instruction.

### Task 1.5d — `compressed_global_extractor.py` NFP-10 revert guard

Composer MUST verify before AND after editing this file:

```bash
grep -n 'byte_addr.*addr.*address' a4/standalone/compressed_global_extractor.py
# → MUST hit line 216: for key in ("byte_addr", "addr", "address"):
```

Run this check both before starting the edit and as the FINAL step of the Batch 1 report's diff summary. If the grep fails after editing, the NFP-10 fix has been reverted — **stop and re-apply**.

The only change to this file in Batch 1 is adding ONE entry to `_TXN_ROLE_BY_KIND` (around line 161):

```python
"TXN_PREV_WORD_MOD":    "prev_word",
```

The other 7 D2.B kinds get their entries in Batches 2-3 — do not add them prematurely.

### Task 1.7 — Soundness-bug guard (plan §9b)

The shared diff helper MUST raise `SoundnessBugSuspected` when:
- The mutation dispatcher tag claims `applied=True`
- The post-mut dump confirms the targeted field actually changed (Layer 3 verified)
- BUT no `<constraint_fail>` was emitted for the mutation
- AND no `<a4_error>` was emitted

This is the *exact* failure mode A4 was designed to discover — a mutation that genuinely broke the trace but the zirgen circuit accepted it as valid. If this fires in Batch 1, **stop, capture the full trace excerpt, and surface to Ivan immediately** with a draft Pro disclosure ready (NFP candidate).

```python
class SoundnessBugSuspected(AssertionError):
    """Raised when a mutation applied + trace changed + no constraint failed + no error emitted.

    This is the exact failure mode A4 is designed to discover. Do NOT catch this in test code.
    Surface immediately for Pro disclosure.
    """
```

### Task 1.8 — Attestation test gating

Gate the real-binary test on `A4_REAL_BINARY=1` env var per Q4. The test should:
- Skip (pytest.skip) gracefully when the env var is not set
- Run the full Layer 2/3/4 cross-check when set
- Be invoked by Composer locally before committing Batch 1 (paste the output in the report)
- Continue working in CI without the env var being set (so CI without the binary stays green)

---

## Workflow

1. **Pre-flight (Pre-kickoff sanity checklist above).** Paste verification output in Batch 1 report.
2. **Read** the locked spec end-to-end + NFP-3, NFP-5, NFP-6, NFP-10 + this kickoff.
3. **Implement in this order:**
   1. **1.0a** — Layer 3 Rust hook → smoke-verify on COMP_OUT_MOD → cargo build → re-test → commit-ready (do not commit yet; integrate with rest of batch)
   2. **1.0b** — CycleState enum extraction + B.8 grep findings → write to report
   3. **1.1** — B.1 Rust handler in `witgen/mod.rs`
   4. **1.2** — Rust build (`cd workspace/risc0-modified && cargo build --release -p risc0-circuit-rv32im` or whichever package owns mod.rs — document the actual command used)
   5. **1.3** — Smoke-check existing kinds (run one COMP_OUT_MOD mutation; verify `<a4_comp_out_mod>` still emits)
   6. **1.4** — Python module `txn_prev_word_mod.py`
   7. **1.5a → 1.5d** — Registry plumbing in dependency order: `inspection_data` → `semantic_arm_universe` → `fuzzer` → `compressed_global_extractor`
   8. **1.5e** — PRE_EXEC_REG_MOD retrofix (10 LOC, 2 files)
   9. **1.5f** — Retrofix unit test
   10. **1.6** — B.1 unit test (Layer 1)
   11. **1.7** — Shared signature helper with soundness-bug guard
   12. **1.8** — B.1 attestation test (Layers 2+3+4)
   13. **1.9** — Full pytest sweep
   14. **1.10** — Write Batch 1 report at `a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_REPORT.md`
4. **Single commit to `cloud2`.** No feature branch, no PR. Commit message MUST contain literal "Batch 1.5e" (see retrofix section above for full recommended format).
5. **Self-checkpoint before committing:** the pass-criteria checklist below must be 100% green.

---

## Pass criteria (Batch 1 ships)

### Infrastructure
- [ ] `A4_DUMP_POST_MUT=1` env var triggers `<a4_post_mut_dump>` tag emission in `witgen/mod.rs` after each mutation match arm
- [ ] Hook verified on existing `COMP_OUT_MOD` smoke (Batch 1.0a deliverable)
- [ ] `parse_post_mut_dump` parser in `a4/core/trace_parser.py` round-trips the tag

### B.1 Rust + Python
- [ ] B.1 Rust handler in `witgen/mod.rs` validates `strategy` field (`"at_read"` or `"at_write"`), mutates the correct `txns[i].prev_word`, emits `<a4_txn_prev_word_mod>` evidence tag with `txn_idx`, `old_value`, `new_value`, `strategy`
- [ ] B.1 Rust handler refuses to mutate a READ txn under `at_write` strategy (and vice versa), emitting `<a4_error>` with strategy-mismatch message (mirrors PRE_EXEC_REG_MOD pattern at mod.rs:499-503)
- [ ] `mutations/txn_prev_word_mod.py` exports `TxnPrevWordModTarget`, `get_targets_at_step(step, data, strategy)`, `create_config(target, mutated_value, strategy)`
- [ ] Both strategies (`at_read`, `at_write`) return ≥0 targets on the sha2-host inspection corpus

### Registry plumbing
- [ ] `inspection_data.py::get_valid_steps_for_kind("TXN_PREV_WORD_MOD")` returns non-empty list on the sha2-host inspection corpus
- [ ] `semantic_arm_universe.py` builds at least one `ArmKey.v5("TXN_PREV_WORD_MOD", <zone>)` arm
- [ ] `semantic_arm_universe.py::_step_has_real_target` ORs BOTH B.1 strategies (the v0.4 Q11 mandatory requirement)
- [ ] `fuzzer.py::_create_mutation` for B.1 RNG-picks strategy per pull; strategy logged in config dict; both strategies observed across a 200-pull RNG sweep
- [ ] `compressed_global_extractor.py::_TXN_ROLE_BY_KIND["TXN_PREV_WORD_MOD"] == "prev_word"` (Pro-valid role per Q5 Option A)

### NFP-10 revert guard
- [ ] `compressed_global_extractor.py:216` still reads `for key in ("byte_addr", "addr", "address"):` — verified by `grep` BEFORE and AFTER the §4.7 edit; both grep outputs pasted in the Batch 1 report

### NFP-6 PRE_EXEC_REG_MOD retrofix (Batch 1.5e)
- [ ] `fuzzer.py:1639` no longer hardcodes `strategy="next_read"`; uses `self.rng.choice(["next_read", "prev_write"])` instead
- [ ] `semantic_arm_universe.py:90-91` ORs both strategies for PRE_EXEC_REG_MOD
- [ ] `test_d2b_pre_exec_reg_mod_two_strategy.py` passes; both strategies observed across an N=200 RNG sweep
- [ ] D2.A golden trace test (`test_d2a_back_compat_golden_trace.py`) still passes (it tests the scheduler decision trace, NOT `_create_mutation`, so the retrofix is invisible to it)
- [ ] Commit message contains the literal string "Batch 1.5e" (signal for D1 chat per `IV_POS_8_D1_REVISIT_PLAN.md` §4.3)

### Layer 1 unit tests
- [ ] `test_d2b_txn_prev_word_mod_unit.py` passes — covers target selection both strategies, config building, value-gen sanity, fuzzer dispatch RNG-pick, registry membership
- [ ] `test_d2b_pre_exec_reg_mod_two_strategy.py` passes — covers retrofix dispatch + arm universe OR + no regression

### Layer 2/3/4 attestation
- [ ] `test_d2b_txn_prev_word_mod_attestation.py` passes when `A4_REAL_BINARY=1` set (Composer runs this locally before committing; pastes output in report)
- [ ] Skips gracefully when env var not set
- [ ] Both `at_read` and `at_write` strategies exercised in the attestation test
- [ ] `assert_trace_diff_matches_signature` helper used; soundness-bug guard armed and not triggered

### Investigations
- [ ] CycleState enum extracted from `platform.rs` (or wherever it lives), snapshot written to `a4/standalone/mutations/_cycle_state_enum.py`; commit hash + line number documented in report
- [ ] B.8 `diff_count` constraint linkage investigation completed; findings (which zirgen constraint family consumes `get_diff_count`) documented in report

### Regression
- [ ] Full pytest sweep `pytest a4/standalone/tests/ -q` shows ≥513 passed (D2.A Batch 2 baseline 510 + 3 new test files in Batch 1 with at least 1 logical test each; expect more)
- [ ] No D2.A or D1.* tests regressed
- [ ] `cargo build --release` on `workspace/risc0-modified` succeeds; new binary deployed where Python harness expects it

### Commit hygiene
- [ ] Single commit on `cloud2` (no feature branch, no PR)
- [ ] Commit message contains literal "Batch 1.5e" string
- [ ] Co-authored-by line included

---

## Quick reference

| Question | Where to look |
|---|---|
| Why is the Rust dump-post-mut hook load-bearing? | NFP-5 in `IV_POS_8_NOTES_FOR_PRO.md`; spec §6 Q17 |
| Why is B.1 a single kind with RNG-picked strategy, not two kinds? | NFP-3 in `NOTES_FOR_PRO`; spec §6 Q11 (Option A justification + plumbing detail) |
| Why is PRE_EXEC_REG_MOD getting a retrofix in this batch? | NFP-6 in `NOTES_FOR_PRO`; spec §7 Batch 1 task 1.5e |
| Why must `compressed_global_extractor.py:216` not be touched? | NFP-10 in `NOTES_FOR_PRO`; this kickoff §"Task 1.5d revert guard" |
| Why is the commit message format strict about "Batch 1.5e"? | `IV_POS_8_D1_REVISIT_PLAN.md` §4.3; plan §9a W-12 |
| What txn_role does B.1 use? Why not "prev_word_meta"? | Spec §4.7 + Q5 (Pro-valid roles only; per-kind D2.G via `producer_kind`) |
| What's the soundness-bug guard? | Plan §9b; this kickoff §"Task 1.7 — Soundness-bug guard" |
| How do I model B.1 on PRE_EXEC_REG_MOD? | Spec §3.1; `pre_exec_reg_mod.py` is the template (two-strategy structure) |
| Where do I add the new match arm in `witgen/mod.rs`? | Spec §4.1 — between MEM_VAL_MOD (line 588) and the fallback error (line 589) |
| Where is the existing PRE_EXEC_REG_MOD Rust handler I'm modeling on? | `witgen/mod.rs:462-535` |
| What's the cargo build target? | Spec §4.2 documents the expected pattern; Composer Batch 1 records the actual command used |
| Why is B.8 investigation in Batch 1 (1.0b) when B.8 ships in Batch 3? | De-risk: confirm `diff_count` has a constraint consumer before Batch 3 commits to handler work |
| What if `A4_DUMP_POST_MUT` smoke fails on COMP_OUT_MOD? | Stop and report. Rest of Batch 1 is blocked. Q17 fallback (Option B tag-only Layer 3) is the documented alternative but requires explicit Ivan approval. |
| What if Rust build fails? | Spec §6 Q10 — pause + report. Don't burn cycles on opaque build issues. |
| What if the soundness-bug guard fires? | This kickoff §"Task 1.7" — STOP, capture trace, surface to Ivan immediately with draft NFP candidate. Do NOT catch the exception in test code. |
| Where does D1 chat watch for the "Batch 1.5e" merge signal? | `IV_POS_8_D1_REVISIT_PLAN.md` §4.1 SYNC row and §4.3 Option B (git log poll for "Batch 1.5e" string) |

---

## Watchlist items relevant to this batch (from plan §9a)

| ID | Watch | Trigger | If triggered, do… |
|---|---|---|---|
| W-9 | Layer 3 dump-post-mut Rust hook (Option A1) | Rust patch fails to build or doesn't emit expected tags | Stop. Report. Don't proceed to B.1 handler. Q17 fallback (Option B tag-only) requires explicit Ivan approval. |
| W-12 | Batch 1.5e merge signal for D1.E sync | Commit message does not contain literal "Batch 1.5e" | Amend commit message before push OR manually ping D1 chat with hash |
| W-13 | NFP-10 revert guard | `grep 'byte_addr.*addr.*address' compressed_global_extractor.py` returns no match after Batch 1 edit | Re-apply NFP-10 fix from `71dae77` BEFORE committing. Flag in report. |
| W-7 | NFP-6 PRE_EXEC_REG_MOD retrofix | Post-retrofix `PRE_EXEC_REG_MOD` reward rate drops by >50% across the 5 D2.A synthetic-test seeds | Surface in report; D2.G investigates whether `prev_write` is materially worse than `next_read` |

---

## Report deliverable

At the end of Batch 1, Composer writes `a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_REPORT.md` covering:

1. **Pre-kickoff sanity checklist output** (all 6 commands' outputs pasted)
2. **What was implemented** — per-task summary with LOC counts
3. **Cargo build invocation** — the actual command used, where the binary lives, hash of the new binary
4. **A4_DUMP_POST_MUT smoke** — output of running COMP_OUT_MOD with the hook before B.1 lands
5. **CycleState enum** — extracted values + line numbers + commit hash from `platform.rs`
6. **B.8 diff_count linkage** — which zirgen constraint family consumes `get_diff_count`; recommendation for Batch 3
7. **NFP-10 revert guard verification** — `grep` output before AND after the §4.7 edit
8. **Attestation test output** — paste the `A4_REAL_BINARY=1 pytest test_d2b_txn_prev_word_mod_attestation.py -v` output
9. **Soundness-bug guard status** — armed; not triggered; if triggered, full trace excerpt
10. **Test counts** — `pytest a4/standalone/tests/ -q` final tally
11. **Deviations from spec/kickoff** (and why)
12. **Open questions / surprises** for Ivan/Opus

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D2.B Batch 1 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md` v0.5.1 (tasks 1.0a through 1.10). Follow the workflow in `a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_KICKOFF.md`. **Commit directly to `cloud2`, single commit, no feature branch, no PR. The commit message MUST contain the literal string "Batch 1.5e" so D1 chat detects the merge and unblocks D1.E.** Run the pre-kickoff sanity checklist before touching any code; paste output in the Batch 1 report. Stop and ask before touching anything outside the Batch 1 scope. Specific guards: (a) DO NOT revert the NFP-10 byte_addr fix at `compressed_global_extractor.py:216`; (b) Layer 3 hook (1.0a) must smoke-pass on COMP_OUT_MOD before any B.1 handler work begins; (c) if the soundness-bug guard fires, STOP and surface to Ivan with full trace excerpt. Pass criteria are the 30+ checkboxes in the kickoff doc. Submit a written report at `a4/docs/cloud2/composer/D2B_BATCH1_COMPOSER_REPORT.md`.

---

*End of D2.B Batch 1 kickoff.*
