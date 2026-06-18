# D2.B Batch 2 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_B_SPEC.md`](../IV_POS_8_D2_B_SPEC.md) **v0.5.2 LOCKED**
**Parent plan:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) **v0.10** (post-Batch 1; §6c arm-semantic-stack + §9b 4-channel rejection model + W-15/W-16 added)
**Notes for Pro:** [`../IV_POS_8_NOTES_FOR_PRO.md`](../IV_POS_8_NOTES_FOR_PRO.md) — NFP-3, NFP-5, NFP-6 still relevant; Hook 3 finding from Issue #6 will become a new NFP candidate when D2.G ships
**Predecessor:** D2.B **Batch 1 (`78d036c`)** — commit message contains literal "Batch 1.5e" (W-12 sync signal already emitted to D1.E)
**Issued by:** Ivan, on Opus's recommendation
**Expected effort:** ~2–3 days of focused Composer work (no Rust infrastructure to build, no retrofix — straight kind addition for both B.2 and B.3)

---

## TL;DR for Composer

Implement **D2.B Batch 2** as defined in `IV_POS_8_D2_B_SPEC.md` §7 "Batch 2" — two new pure-A4 mutation kinds:

- **B.2 `TXN_PREV_CYCLE_MOD`** — mutates `txns[i].prev_cycle: u32` (memory permutation temporal-ordering invariant). Single strategy, single target per step. Modeled on `comp_out_mod.py`.
- **B.3 `CYCLE_MODE_MOD`** — mutates `cycles[i].machine_mode: u8` (privilege bit; 0=user, 1=machine). Deterministic flip, no value-gen RNG needed. Modeled on `instr_type_mod.py`.

**Read in this order before writing code:**

1. **`IV_POS_8_D2_PLAN.md` v0.10** — especially **§6c** (arm semantic certainty stack: S1–S6 layers + known gaps) and the **rewritten §9b** (four-channel rejection model: C1=`<constraint_fail>`, C2=`verify segment`, C3=`<a4_family_residue>` Hook 3, C4=`<a4_error>`). These are NEW since Batch 1 and they define how Batch 2 attestation tests MUST behave.
2. **The locked spec** `IV_POS_8_D2_B_SPEC.md` v0.5.2 §3.2 (B.2) + §3.3 (B.3) + §4.4 (`get_valid_steps_for_kind` rules) + §4.5 (registry plumbing) + §4.7 (txn_role mapping) + §5.3 (cascade signatures)
3. **Batch 1 deliverables on disk** — they are the canonical template:
   - `a4/standalone/mutations/txn_prev_word_mod.py` (Python module pattern)
   - `a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py` (5-layer attestation with Hook 3)
   - `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs:620-680` (Rust handler pattern)
   - `a4/standalone/tests/_test_helpers/diff_signature.py` (already includes the C3 `broken_families_nonzero` channel — DO NOT change the helper)
4. This kickoff document.

**Single hardest constraint:** the Layer 3 Rust hook (`A4_DUMP_POST_MUT=1`) and the soundness guard already exist from Batch 1. You should NOT re-implement them. Each new kind's attestation test reuses the helper + guard + Hook 3 parsing pattern from B.1 verbatim. Only the **expected family** in the Hook 3 assertion differs per kind (see §"Hook 3 per-kind family expectations" below).

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

Paste output in the Batch 2 report.

```bash
# 1. On cloud2 branch, working tree clean post-Batch-1
git branch --show-current        # → cloud2
git log --oneline -1             # → 78d036c Batch 1.5e D2.B (or later)
git status                       # → clean (no uncommitted changes)

# 2. Batch 1 deliverables present
ls a4/standalone/mutations/txn_prev_word_mod.py
ls a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py
ls a4/standalone/tests/_test_helpers/diff_signature.py

# 3. Batch 1 attestation test still passes (~3 min, smoke-only)
A4_REAL_BINARY=1 pytest a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py -v
# → 2 passed (at_read + at_write)

# 4. Full Batch 1 baseline test count
pytest a4/standalone/tests/ -q --collect-only 2>&1 | tail -1
# → record the number for the post-Batch-2 comparison

# 5. NFP-10 byte_addr fix still in place — DO NOT revert during §4.7 edits
grep -n 'byte_addr.*addr.*address' a4/standalone/compressed_global_extractor.py
# → expect line 216: for key in ("byte_addr", "addr", "address"):

# 6. Batch 1 plumbing is the template — verify the B.1 entries exist
grep -n 'TXN_PREV_WORD_MOD' a4/standalone/fuzzer.py
grep -n 'TXN_PREV_WORD_MOD' a4/standalone/semantic_arm_universe.py
grep -n 'TXN_PREV_WORD_MOD' a4/standalone/compressed_global_extractor.py
grep -n 'TXN_PREV_WORD_MOD' a4/core/inspection_data.py
# → all should hit; these are the patterns you mirror for B.2 + B.3

# 7. Locate where to add new Rust match arms (after B.1, before fallback)
grep -n 'TXN_PREV_WORD_MOD\|=> {' workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs | head -20
# → B.1 arm at line 620; new arms go AFTER B.1's closing brace and BEFORE the fallback `_ =>` arm
```

If any of these fail (especially #3 — the real-binary attestation), **stop and report**.

---

## Scope (exactly what Batch 2 ships)

### Spec sections this batch implements

- **§3.2** B.2 `TXN_PREV_CYCLE_MOD` — single strategy (no READ/WRITE split — spec §3.2 "Single strategy (no read/write split needed)")
- **§3.3** B.3 `CYCLE_MODE_MOD` — broad scope per taxonomy authority (any cycle except step 0), deterministic flip
- **§4.1** Rust changes to `witgen/mod.rs` (two NEW match arms)
- **§4.3** Two NEW Python modules
- **§4.4** `inspection_data.py::get_valid_steps_for_kind` — TWO new branches (B.2 + B.3 only)
- **§4.5** `semantic_arm_universe.py` — register TWO new modules, add TWO `_cycle_matches_kind_filter` branches; **no additions to `_MAJOR_FILTER_KINDS`** (per spec §4.5: B.2 is txn-based, B.3 is broad-scope cycle-based)
- **§4.6** `fuzzer.py` — TWO new `MUTATION_KINDS` entries + TWO new `_create_mutation` dispatch branches
- **§4.7** `compressed_global_extractor.py` — TWO new `_TXN_ROLE_BY_KIND` entries (Option A Pro-valid roles per Q5 LOCKED)
- **§5** 5-layer testing methodology, per Batch 1's canonical pattern + the new Hook 3 (C3) channel wiring from D2 plan §9b
- **§7 Batch 2** — task list (2.1 → 2.8 below)

### Files touched

| File | Action | Rough size |
|---|---|---|
| `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs` | (2.1) Add B.2 Rust handler. (2.2) Add B.3 Rust handler. Insert BOTH between B.1's closing brace (current ~line 680) and the fallback `_ =>` arm. Each handler ends by calling `a4_dump_post_mut_*` (B.2: reuse `a4_dump_post_mut_txn_window`; B.3: NEW `a4_dump_post_mut_cycle_window` helper if not already present from Batch 1 — confirm by `rg 'a4_dump_post_mut_cycle' workspace/risc0-modified/`). Evidence tag names: `<a4_txn_prev_cycle_mod>` for B.2, `<a4_cycle_mode_mod>` for B.3. | ~70 LOC (B.2) + ~70 LOC (B.3) + maybe ~30 LOC (cycle window helper if missing) = ~140–170 LOC |
| `a4/core/trace_parser.py` | Add `parse_txn_prev_cycle_mod(output)` + `parse_cycle_mode_mod(output)` mirroring `parse_txn_prev_word_mod` (which Batch 1 added). If the cycle-window post-mut dump uses a new tag name (e.g. `<a4_post_mut_cycle_dump>`), add its parser too. | ~50 LOC |
| `a4/standalone/mutations/txn_prev_cycle_mod.py` (NEW) | B.2 Python module. Dataclass `TxnPrevCycleModTarget(step, cycle_idx, txn_idx, addr, original_prev_cycle, original_cycle)`. `get_targets_at_step(step, data)` returns ALL txns at the step (no READ/WRITE filter — both relevant per spec §3.2). `create_config(target, mutated_value)` writes `{"mutation_type":"TXN_PREV_CYCLE_MOD","step":S,"txn_idx":I,"prev_cycle":V}`. **Value generation** per spec §3.2: 35% off-by-N (±1, ±5, ±100), 35% bounded random in `[1, original_cycle - 1)`, 30% unbounded u32; **exclude 0** and **exclude `original_cycle`** itself. Use `random.Random(seed)` API like `txn_prev_word_mod.py`. | ~180 LOC |
| `a4/standalone/mutations/cycle_mode_mod.py` (NEW) | B.3 Python module. Dataclass `CycleModeModTarget(step, cycle_idx, original_mode, major, minor)`. `get_targets_at_step(step, data)` returns single target (the cycle at that step) **if** `step != 0` AND `cycle.machine_mode` is defined (per spec §3.3). `create_config(target)` writes `{"mutation_type":"CYCLE_MODE_MOD","step":S,"mode":(1 - original_mode)}` — **deterministic bit flip, no RNG**. Single strategy, single target. | ~140 LOC |
| `a4/standalone/mutations/__init__.py` | Re-export 2 new modules (mirror B.1 entry from Batch 1) | ~4 LOC |
| `a4/core/inspection_data.py::get_valid_steps_for_kind` | Add 2 new branches per spec §4.4: <br>**B.2:** identical to B.1 — "All steps with at least one txn (i.e. `cycle.step in data._step_to_all_txns`); no major filter". <br>**B.3:** "Any cycle except step 0 (per §3.3 broad scope)". | ~10 LOC |
| `a4/standalone/semantic_arm_universe.py` | Import the 2 new mutation modules; add 2 entries to `_MUTATION_MODULES`. Add B.2 branch to `_cycle_matches_kind_filter` (txn-presence filter, same shape as B.1). Add B.3 branch (broad cycle filter, no major restriction). Add 2 branches to `_step_has_real_target` (single-strategy lookups — no OR-of-strategies for B.2 or B.3). **Do NOT add either kind to `_MAJOR_FILTER_KINDS`** per spec §4.5. | ~50 LOC |
| `a4/standalone/fuzzer.py` | Add `"TXN_PREV_CYCLE_MOD"` and `"CYCLE_MODE_MOD"` to `MUTATION_KINDS`. Add 2 new branches to `_create_mutation(kind, step)`: <br>**B.2** dispatches to `txn_prev_cycle_mod.get_targets_at_step` + `create_config`; selects a random target, generates value via `txn_prev_cycle_mod.generate_new_value(target, self.rng)`. <br>**B.3** dispatches to `cycle_mode_mod.get_targets_at_step` + `create_config`; no RNG value generation (deterministic flip). | ~50 LOC |
| `a4/standalone/compressed_global_extractor.py` | Add to `_TXN_ROLE_BY_KIND` at line ~174 area (right after the `"TXN_PREV_WORD_MOD": "prev_word"` line added in Batch 1): <br>`"TXN_PREV_CYCLE_MOD": "prev_cycle"` (Pro-valid per Q5 LOCKED Option A — see spec §4.7 lines 819-836). <br>`"CYCLE_MODE_MOD": "read"` (cycle-meta default per Q5 LOCKED Option A — see spec §4.7 line 832). <br>**DO NOT MODIFY line 216 `_coerce_broken_addr`** — NFP-10 fix. | ~3 LOC |
| `a4/standalone/tests/test_d2b_txn_prev_cycle_mod_unit.py` (NEW) | Layer 1 unit tests for B.2: target selection on synthetic InspectionData; config building; value-gen mix sanity (≥30% within `[1, cycle-1)`); exclusion of 0 and `original_cycle`; fuzzer dispatch wires up. | ~150 LOC |
| `a4/standalone/tests/test_d2b_cycle_mode_mod_unit.py` (NEW) | Layer 1 unit tests for B.3: target selection at any non-zero step; deterministic flip is `1 - original_mode`; step 0 produces no target; fuzzer dispatch wires up. | ~120 LOC |
| `a4/standalone/tests/test_d2b_txn_prev_cycle_mod_attestation.py` (NEW) | **Layers 2 + 3 + 4** for B.2. Mirror `test_d2b_txn_prev_word_mod_attestation.py` structure: set `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1 A4_DUMP_POST_MUT=1 A4_FAMILY_RESIDUE=1` on the mutation run; parse `<a4_txn_prev_cycle_mod>` evidence, `<a4_post_mut_dump>`, and `<a4_family_residue>`; assert primary diff signature with `cascade=[]` (strict — per spec §5.3); **assert `"memory"` in broken families** (B.2's expected Hook 3 family — see §"Hook 3 per-kind family expectations" below); pass all 4 channels to `check_soundness_bug_guard`. Gated by `A4_REAL_BINARY=1`. | ~180 LOC |
| `a4/standalone/tests/test_d2b_cycle_mode_mod_attestation.py` (NEW) | **Layers 2 + 3 + 4** for B.3. Mirror the same structure. **One difference from B.2:** the Hook 3 family assertion is **`broken_families` is non-empty** (any family OR `verify segment` fired) — B.3 is **NOT expected to break the `memory` family** because `machine_mode` does not feed `extern_memoryDelta`. See §"Hook 3 per-kind family expectations" below for the rationale; if the empirical result shows a *specific* family always fires (e.g. only `u8` because mode is range-checked), update the assertion to that specific family in the report. | ~180 LOC |

**Total expected delta:** ~1100–1300 LOC across 12 files. ~2–3 days at Batch 1 pace.

### Investigation that's already done (do NOT redo)

- ✅ Layer 3 `A4_DUMP_POST_MUT=1` Rust hook — landed in Batch 1; smoke-verified.
- ✅ `parse_post_mut_dump` parser — landed in Batch 1.
- ✅ `assert_trace_diff_matches_signature` + `check_soundness_bug_guard` helpers — landed in Batch 1, including the C3 `broken_families_nonzero` channel from the Issue #6 follow-up.
- ✅ Hook 3 (`A4_FAMILY_RESIDUE=1`) wiring pattern — established in `test_d2b_txn_prev_word_mod_attestation.py`. Copy that file as the starting template; only the kind name, expected family, parser, and target-finding need swapping.

### Pre-implementation investigation (task 2.0)

Before writing the B.2 + B.3 handlers, **confirm by reading source** (no changes — read only):

1. **B.3 cycle-window post-mut dump helper.** Run `rg 'a4_dump_post_mut_cycle' workspace/risc0-modified/`. If a `a4_dump_post_mut_cycle_window` (or equivalent) helper does NOT exist yet, B.3's Rust handler will need a new one parallel to `a4_dump_post_mut_txn_window` from Batch 1. The shape: dump the modified cycle + `[-1, +1]` neighbors (per spec §1.5 / Q17). Document in the report whether this helper had to be added.
2. **B.2 single-strategy confirmation.** Re-read spec §3.2 line 311 ("A single strategy suffices"). Note in the Batch 2 report that you understand B.2 is *not* analogous to B.1's two-strategy structure — you do NOT add an `at_read/at_write` field to its config, and you do NOT OR two strategies in `_step_has_real_target`.
3. **B.3 deterministic-flip confirmation.** Re-read spec §3.3 line 404 ("Value generation is deterministic bit-flip (`1 - original_mode`); no RNG needed since the field is binary"). Note in the report that B.3's `create_config` takes NO `random.Random` argument — this is the only B.* kind in D2.B with no value-gen RNG.

These investigations gate **only the design correctness of the code you write**, not the build. They are ~15-min reads.

---

## NOT in Batch 2 (deferred)

| Item | Where it ships |
|---|---|
| B.4 `TXN_ADDR_MOD`, B.5 `TXN_CYCLE_PHASE_MOD`, B.6 `CYCLE_PC_MOD`, B.7 `CYCLE_STATE_MOD`, B.8 `CYCLE_DIFF_COUNT_MOD` | **Batch 3** (per Q8 LOCKED — 5 kinds together; W-10 triggers fallback isolation of B.4 if churn exceeds ~1 week) |
| Cross-cutting `test_d2b_arm_registration.py` (all 8 kinds, S4 layer of §6c) | **Batch 4** |
| Campaign smoke `test_d2b_campaign_smoke.py` (Layer 5, mocked binary) | **Batch 4** |
| Any changes to `bandit_ts.py`, `coverage_db.py` schema, `reward_v2.py` | **None — D2.A foundation, locked** |
| D2.D variant CLI changes (variant-specific kind subsets per Q6) | **D2.D** (separate deliverable) |
| W-15 sampled (kind, zone) audit | **D2.D** kickoff (per W-15 trigger in plan §9a) |

If you find yourself touching anything in the "must not change" list, **stop and confirm with Ivan**.

---

## Critical instructions

### 1. Hook 3 attestation pattern (mandatory per plan §9b; NEW since Batch 1)

Every attestation test in Batch 2 MUST follow the four-channel rejection pattern established in `test_d2b_txn_prev_word_mod_attestation.py` (post Issue #6 v2 fix). Concretely:

```python
mut_result = _run_host(
    {
        "A4_INSPECT": "1",
        "A4_DUMP_ALL_TXNS": "1",
        "A4_DUMP_POST_MUT": "1",
        "A4_FAMILY_RESIDUE": "1",   # MANDATORY — enables C3 Hook 3 emission
    },
    cfg_path,
)
mut_out = _combined_output(mut_result)

# ... evidence tag + post-mut-dump assertions ...

family_residues = parse_family_residues(mut_out)
assert family_residues is not None, (
    "Hook 3: missing <a4_family_residue> tags (is A4_FAMILY_RESIDUE=1 set?)"
)
broken_families = [fr["family"] for fr in family_residues if fr.get("nonzero")]

# Per-kind assertion — see "Hook 3 per-kind family expectations" below
assert <PER_KIND_ASSERTION>, (
    f"Hook 3: <per-kind explanation>; broken={broken_families}"
)

check_soundness_bug_guard(
    mutation_applied=True,
    trace_changed=bool(diffs),
    constraint_failed="constraint_fail" in mut_out.lower(),
    error_emitted="<a4_error>" in mut_out,
    proof_verify_failed="verify segment" in mut_out,
    broken_families_nonzero=bool(broken_families),
    verifier_accepted=_verifier_accepted(mut_out),
)
```

Do NOT relax this. The guard accepts FOUR rejection channels (C1–C4) and only fires when all four are silent AND `verifier_accepted=True`. If it fires on B.2 or B.3, STOP and surface to Ivan immediately (same W-16 protocol as Issue #6).

### 2. Hook 3 per-kind family expectations (GROUNDED ON FACTS — read carefully)

The Hook 3 residue accumulators in `ffi.cpp:480-523` track FOUR families: `memory`, `u8`, `u16`, `cycle`. Which family fires for each kind depends on **which extern record stream the mutation enters**.

| Kind | What field is mutated | Which extern records | Expected Hook 3 family | Assertion in attestation test |
|---|---|---|---|---|
| **B.1 `at_read`** (Batch 1, verified) | `prev_word` on a READ txn | `extern_memoryDelta` records `(addr, cycle, dataLow=prev_word.low, dataHigh=prev_word.high, count=-1)` for oldTxn | **`memory`** (confirmed by Batch 1 attestation: `broken_families == ['memory']`) | `assert "memory" in broken_families` |
| **B.1 `at_write`** (Batch 1, verified) | `prev_word` on a WRITE txn | Same as above — extern record carries mutated value | **`memory`** (confirmed by Batch 1 attestation: `broken_families == ['memory']`) | `assert "memory" in broken_families` |
| **B.2 `TXN_PREV_CYCLE_MOD`** (Batch 2 — expected) | `prev_cycle` on any txn | `extern_memoryDelta` records `cycle=prev_cycle` for oldTxn (per `mem.zir:67` — `MemoryArg(-1, addr, ret.prevCycle, ret.prevData)`); mutation changes the cycle hash component `r_mem_cycle * Fp(rec.cycle)` | **`memory`** (prev_cycle feeds the memory hash via `r_mem_cycle`; ALSO may affect `cycle` family via the cycle-ordering lookup but `memory` is the primary expected signal) | `assert "memory" in broken_families` |
| **B.3 `CYCLE_MODE_MOD`** (Batch 2 — empirical) | `cycle.machine_mode: u8` on a cycle row | **NOT a memory extern.** `machine_mode` does NOT feed `extern_memoryDelta` directly. It selects which constraint family is active per cycle (per spec §3.3 "gates which constraint family is active"). | **`u8`** (mode is a u8 range-checked value) OR **NONE** (if the mode-coherence constraint is in the constraint polynomial directly, not via a lookup). Empirical question. | `assert broken_families OR "verify segment" in mut_out` — i.e. ACCEPT EITHER (a) any non-empty Hook 3 OR (b) C2 alone. Then document which one fired in the report so Batch 2 closure can pin the assertion. |

**Why the B.3 assertion is intentionally weaker:** based on the four-channel model (plan §9b), it is empirically possible for B.3 to fail via Path B (`verify segment`) alone if the privilege-mode coherence constraint is a global polynomial check that doesn't surface in any of the four Hook 3 families. This is the SAME class of asymmetry that B.1 `at_write` exhibited (no `<constraint_fail>` tag because `IsRead` doesn't run on `MemoryWrite`). B.3 may or may not have this asymmetry — we won't know until we run it.

**For the B.3 report:** if `broken_families` is non-empty, name the specific family in the kickoff report and tighten the assertion to that family in a subsequent commit. If `broken_families` is consistently empty across 3 sampled mutations, log this as an NFP candidate (informational, not soundness — same class as B.1 `at_write`) and pin the assertion to "C2 fires alone".

### 3. Spec §5.3 cascade signatures (verbatim)

From spec line 892-893:

> | B.2 | Strict-no-cascade in trace (constraint cascade = downstream `prev_cycle` chain failure at witness time, not a post-mut trace diff) |
> | B.3 | Strict-no-cascade (metadata only) |

For **both** B.2 and B.3, the trace-diff signature is `cascade=[]`. Mutating `prev_cycle` does not cause any other txn's `prev_cycle` to be re-written in the post-mut dump (the chain failure surfaces at witness time, not in the trace memory). Mutating `machine_mode` is a single-cycle metadata edit with no downstream cycle changes.

If `assert_trace_diff_matches_signature` reports unexpected cascade for either kind, **stop and investigate** — it may indicate the Rust handler is doing more than it should.

### 4. NFP-10 revert guard (same as Batch 1)

Before AND after `compressed_global_extractor.py` edits:

```bash
grep -n 'byte_addr.*addr.*address' a4/standalone/compressed_global_extractor.py
# → MUST hit line 216: for key in ("byte_addr", "addr", "address"):
```

The only change to this file in Batch 2 is adding TWO entries to `_TXN_ROLE_BY_KIND` (around line 174, after the B.1 entry):

```python
"TXN_PREV_CYCLE_MOD":   "prev_cycle",
"CYCLE_MODE_MOD":       "read",
```

Both per spec §4.7 Q5 LOCKED Option A. **DO NOT** add the remaining 5 kinds (B.4–B.8) — those land in Batch 3.

### 5. Soundness-bug guard

Already wired into the Batch 1 helper (`a4/standalone/tests/_test_helpers/diff_signature.py`). Each Batch 2 attestation test MUST call `check_soundness_bug_guard` with all four channels per the canonical pattern in §1 above. If `SoundnessBugSuspected` is raised:
1. **STOP.** Do not catch the exception in test code.
2. Capture: full mutation config JSON, full `mut_out` stdout+stderr (truncate at 50KB), evidence tag, post-mut dump, `parse_family_residues` output.
3. Surface to Ivan immediately with a draft NFP candidate (template: same as Issue #6 — but documenting a *new* failure class, not the known Path A vs Path B asymmetry).
4. Per W-16: a fired guard indicates the kind reached Layer 4 with all four channels silent. This is the failure mode A4 was designed to discover. Treat it as a finding, not a test bug.

### 6. Commit message convention

Single commit on `cloud2`. Commit message should reference Batch 2 explicitly so the watchlist can audit the sequence:

```
D2.B Batch 2: TXN_PREV_CYCLE_MOD (B.2) + CYCLE_MODE_MOD (B.3) with Hook 3 attestation.

- 2.0: Cycle-window post-mut helper investigation + B.2 single-strategy / B.3 deterministic-flip confirmation
- 2.1: B.2 Rust handler in witgen/mod.rs (emits <a4_txn_prev_cycle_mod> + post-mut dump)
- 2.2: B.3 Rust handler in witgen/mod.rs (emits <a4_cycle_mode_mod> + cycle-window post-mut dump)
- 2.3: trace_parser additions for both kinds
- 2.4: mutations/txn_prev_cycle_mod.py + mutations/cycle_mode_mod.py
- 2.5: Registry plumbing (inspection_data, semantic_arm_universe, fuzzer MUTATION_KINDS + _create_mutation, compressed_global_extractor _TXN_ROLE_BY_KIND)
- 2.6: Layer 1 unit tests for both kinds
- 2.7: Layers 2-4 attestation tests for both kinds (Hook 3 enabled per plan §9b)
- 2.8: Full pytest sweep + per-kind Hook 3 family findings

Tests: <N> passed (Batch 1 baseline 527 + new tests).
Hook 3 findings: B.2 memory family (expected); B.3 <family observed or "C2-only">.

Co-authored-by: Cursor <cursoragent@cursor.com>
```

There is NO sync-signal literal requirement for Batch 2 (W-12 was Batch-1-specific).

---

## Workflow

1. **Pre-kickoff sanity checklist** (above). Paste output in Batch 2 report.
2. **Read** plan §6c + §9b (NEW in v0.10), spec §3.2 + §3.3 + §4.4 + §4.5 + §4.7 + §5.3, this kickoff.
3. **Implement in this order:**
   1. **2.0** — Cycle-window helper investigation (read-only); B.2/B.3 design confirmations → write to report
   2. **2.1** — B.2 Rust handler in `witgen/mod.rs`
   3. **2.2** — B.3 Rust handler in `witgen/mod.rs` (+ cycle-window post-mut helper if missing)
   4. **2.3** — Rust build (`cd workspace/risc0-modified && cargo build --release` — document the exact command used)
   5. **2.4** — Smoke-check: existing kinds still work (run one B.1 `at_read` mutation; verify `<a4_txn_prev_word_mod>` still emits)
   6. **2.5** — Python modules (`txn_prev_cycle_mod.py`, `cycle_mode_mod.py`) + trace_parser additions + `__init__.py` re-exports
   7. **2.6** — Registry plumbing in dependency order: `inspection_data` → `semantic_arm_universe` → `fuzzer` → `compressed_global_extractor`
   8. **2.7** — Layer 1 unit tests for both kinds
   9. **2.8** — Layer 2/3/4 attestation tests for both kinds (Hook 3 channel mandatory)
   10. **2.9** — `A4_REAL_BINARY=1 pytest <both attestation files> -v` (paste output in report)
   11. **2.10** — Full pytest sweep (`pytest a4/standalone/tests/ -q`; record N passed)
   12. **2.11** — Write Batch 2 report at `a4/docs/cloud2/composer/D2B_BATCH2_COMPOSER_REPORT.md`
4. **Single commit to `cloud2`.** No feature branch, no PR.
5. **Self-checkpoint before committing:** the pass-criteria checklist below must be 100% green.

---

## Pass criteria (Batch 2 ships)

### Infrastructure

- [ ] No new Rust infrastructure files — Layer 3 hook is already in place from Batch 1 (verify with `rg 'A4_DUMP_POST_MUT' workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs`)
- [ ] If a cycle-window post-mut helper had to be added, it mirrors `a4_dump_post_mut_txn_window` (cycle row + `[-1, +1]` neighbors)
- [ ] `parse_txn_prev_cycle_mod` + `parse_cycle_mode_mod` round-trip the new tags

### B.2 Rust + Python

- [ ] B.2 Rust handler validates `txn_idx` and `prev_cycle` fields; mutates `trace.txns[idx].prev_cycle`; emits `<a4_txn_prev_cycle_mod>` evidence tag with `step, txn_idx, addr, old_prev_cycle, new_prev_cycle, cycle, word, prev_word`
- [ ] B.2 Rust handler errors via `<a4_error>` when `txn_idx >= trace.txns.len()` or fields missing
- [ ] B.2 Rust handler calls `a4_dump_post_mut_txn_window(&trace, "TXN_PREV_CYCLE_MOD", idx)` at the end (under `A4_DUMP_POST_MUT=1`)
- [ ] `mutations/txn_prev_cycle_mod.py` exports `TxnPrevCycleModTarget`, `get_targets_at_step(step, data)`, `create_config(target, mutated_value)`, `generate_new_value(target, rng)`
- [ ] Value-generation excludes 0 AND `original_cycle`; mix is approximately 35/35/30 across off-by-N / bounded / unbounded random
- [ ] `get_targets_at_step` returns all txns at the step (no READ/WRITE filter — per spec §3.2)

### B.3 Rust + Python

- [ ] B.3 Rust handler validates `mode` field (0 or 1); finds the cycle row where `cycle.user_cycle == target_step`; mutates `cycle.machine_mode`; emits `<a4_cycle_mode_mod>` evidence tag with `step, cycle_idx, pc, old_mode, new_mode, major, minor`
- [ ] B.3 Rust handler errors via `<a4_error>` when `mode` is not 0 or 1, or no matching cycle found
- [ ] B.3 Rust handler dumps the modified cycle + neighbors under `A4_DUMP_POST_MUT=1`
- [ ] `mutations/cycle_mode_mod.py` exports `CycleModeModTarget`, `get_targets_at_step(step, data)`, `create_config(target)`
- [ ] B.3 config has NO value-gen RNG (deterministic flip `1 - original_mode`)
- [ ] `get_targets_at_step(0, ...)` returns no target; `get_targets_at_step(N>0, ...)` returns one

### Registry plumbing

- [ ] `inspection_data.py::get_valid_steps_for_kind("TXN_PREV_CYCLE_MOD")` and `..("CYCLE_MODE_MOD")` both return non-empty lists on sha2-host inspection corpus
- [ ] `semantic_arm_universe.py` builds at least one `ArmKey.v5("TXN_PREV_CYCLE_MOD", <zone>)` and one `ArmKey.v5("CYCLE_MODE_MOD", <zone>)`
- [ ] Neither B.2 nor B.3 added to `_MAJOR_FILTER_KINDS` (per spec §4.5)
- [ ] `fuzzer.py::_create_mutation` for B.2 picks a random target and generates value via RNG; for B.3 uses deterministic flip
- [ ] `compressed_global_extractor.py::_TXN_ROLE_BY_KIND["TXN_PREV_CYCLE_MOD"] == "prev_cycle"` and `..["CYCLE_MODE_MOD"] == "read"`

### NFP-10 revert guard (same as Batch 1)

- [ ] `compressed_global_extractor.py:216` still reads `for key in ("byte_addr", "addr", "address"):` — verified by `grep` BEFORE and AFTER the §4.7 edit; both grep outputs pasted in the Batch 2 report

### Layer 1 unit tests

- [ ] `test_d2b_txn_prev_cycle_mod_unit.py` passes — target selection, value-gen exclusion of 0 + `original_cycle`, fuzzer dispatch
- [ ] `test_d2b_cycle_mode_mod_unit.py` passes — deterministic flip, step-0 exclusion, fuzzer dispatch

### Layer 2/3/4 attestation (Hook 3 mandatory)

- [ ] `test_d2b_txn_prev_cycle_mod_attestation.py` passes with `A4_REAL_BINARY=1` set; sets `A4_FAMILY_RESIDUE=1` on mutation run; parses Hook 3; asserts `"memory" in broken_families`; passes all 4 channels to guard
- [ ] `test_d2b_cycle_mode_mod_attestation.py` passes with `A4_REAL_BINARY=1` set; sets `A4_FAMILY_RESIDUE=1`; parses Hook 3; uses the wider B.3 assertion (`broken_families OR "verify segment"`); records WHICH channels fired in the report
- [ ] Both tests use `assert_trace_diff_matches_signature` with `cascade=[]` (strict-no-cascade per spec §5.3)
- [ ] Soundness-bug guard is armed and not triggered in either case (if triggered, STOP per §"Critical instructions" point 5)
- [ ] Both attestation tests skip gracefully when `A4_REAL_BINARY` is unset

### Regression

- [ ] Full pytest sweep `pytest a4/standalone/tests/ -q` shows ≥545 passed (Batch 1 baseline 527 + ~18 new logical tests across 4 new test files; conservative lower bound)
- [ ] No regression in Batch 1 attestation: `A4_REAL_BINARY=1 pytest a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py -v` still 2 passed
- [ ] No D2.A or D1.* tests regressed
- [ ] `cargo build --release` on `workspace/risc0-modified` succeeds; new binary deployed where Python harness expects it

### Commit hygiene

- [ ] Single commit on `cloud2`
- [ ] Commit message follows the recommended format in §"Critical instructions" point 6
- [ ] Co-authored-by line included
- [ ] No accidental edits to files in §"NOT in Batch 2"

---

## Quick reference

| Question | Where to look |
|---|---|
| What's the four-channel rejection model? | Plan §9b (v0.10) |
| Why is the Hook 3 attestation pattern mandatory? | Plan §9b implementation requirements; this kickoff §"Critical instructions" point 1 |
| What family should B.2 break? | Spec §3.2 + this kickoff §"Hook 3 per-kind family expectations" |
| What if B.3 has empty Hook 3 broken_families? | Acceptable per the kickoff's weaker B.3 assertion; document which channel fired (C2 vs C3); log NFP candidate |
| Why is B.2 a single strategy (no `at_read`/`at_write` split)? | Spec §3.2 line 311 — "both rely on `prev_cycle` for ordering checks. A single strategy suffices." |
| Why doesn't B.3 use value-gen RNG? | Spec §3.3 line 404 — "deterministic bit-flip (`1 - original_mode`); no RNG needed since the field is binary" |
| What txn_role does B.2 use? Why not `"prev_cycle_meta"`? | Spec §4.7 + Q5 LOCKED Option A (Pro-valid roles only; per-kind D2.G via `producer_kind`) |
| What txn_role does B.3 use? Why `"read"`? | Spec §4.7 — cycle-meta kinds default to `"read"` per Q5 LOCKED Option A line 832 |
| What's the cascade expectation for B.2 / B.3? | Spec §5.3 lines 892-893 — both `cascade=[]` |
| Where do I add the new match arms? | After B.1's closing brace (~line 680 in `witgen/mod.rs`), before the fallback `_ =>` arm |
| Where's the Python module template? | `a4/standalone/mutations/txn_prev_word_mod.py` (B.1) — but adapt to single-strategy for B.2, deterministic for B.3 |
| Where's the attestation test template? | `a4/standalone/tests/test_d2b_txn_prev_word_mod_attestation.py` (B.1, post Issue #6 v2 fix) — verbatim Hook 3 pattern |
| What if `assert_trace_diff_matches_signature` fires? | Investigate the Rust handler — it's doing more than spec §5.3 allows |
| What if soundness guard fires? | STOP, capture, surface — same W-16 protocol as Issue #6 |
| What if Rust build fails? | Spec §6 Q10 — pause + report. Don't burn cycles on opaque build issues. |

---

## Watchlist items relevant to this batch (from plan §9a v0.10)

| ID | Watch | Trigger | If triggered, do… |
|---|---|---|---|
| **W-15** | S1 zone classifier systematic audit (NOT yet implemented) | Any unexpected (kind, zone) pairing in B.2/B.3 attestation runs | Note in report; full audit happens at D2.D kickoff per W-15 |
| **W-16** | Soundness-bug guard channels (post Issue #6) | A B.2 or B.3 attestation reaches Layer 4 with all four channels silent AND verifier accepts | STOP, capture full evidence, surface to Ivan with NFP candidate template (mirror Issue #6 investigation structure) |
| **W-5** | Q6 variant kind subsets | N/A in Batch 2 (D2.D not yet implemented) | n/a |
| **W-10** | Batch 3 churn isolation | N/A in Batch 2 | n/a |

---

## Report deliverable

At the end of Batch 2, Composer writes `a4/docs/cloud2/composer/D2B_BATCH2_COMPOSER_REPORT.md` covering:

1. **Pre-kickoff sanity checklist output** (all 7 commands pasted)
2. **Task 2.0 investigation findings** (cycle-window helper presence; B.2/B.3 design confirmations)
3. **What was implemented** — per-task summary with LOC counts
4. **Cargo build invocation** — actual command, binary location, hash of new binary
5. **Smoke check** that existing B.1 + COMP_OUT_MOD kinds still emit their evidence tags with the new binary
6. **NFP-10 revert guard verification** — `grep` output before AND after the §4.7 edit
7. **B.2 attestation output** — paste the `A4_REAL_BINARY=1 pytest test_d2b_txn_prev_cycle_mod_attestation.py -v` output; confirm `"memory" in broken_families`
8. **B.3 attestation output** — paste the `A4_REAL_BINARY=1 pytest test_d2b_cycle_mode_mod_attestation.py -v` output; document **which channels fired** (C1/C2/C3/C4) and which Hook 3 family if any (or "C2-only / Path B alone")
9. **Soundness-bug guard status** — armed; not triggered; if triggered, full trace excerpt + NFP draft
10. **Test counts** — `pytest a4/standalone/tests/ -q` final tally (expect ≥545)
11. **Hook 3 family findings table** — empirical observation for B.2 and B.3 (informs the canonical Batch 3 family-expectation table for B.4–B.8)
12. **Deviations from spec/kickoff** (and why)
13. **Open questions / surprises** for Ivan/Opus

---

## Hand-off statement (paste this when delegating to Composer)

> Implement D2.B Batch 2 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_B_SPEC.md` v0.5.2 §3.2 (B.2 `TXN_PREV_CYCLE_MOD`) and §3.3 (B.3 `CYCLE_MODE_MOD`). Follow the workflow in `a4/docs/cloud2/composer/D2B_BATCH2_COMPOSER_KICKOFF.md`. **Commit directly to `cloud2`, single commit, no feature branch, no PR.** Run the pre-kickoff sanity checklist before touching code; paste output in the Batch 2 report. **Mandatory:** every attestation test MUST enable `A4_FAMILY_RESIDUE=1` and pass all four rejection channels (C1–C4) to `check_soundness_bug_guard` per the canonical pattern in `test_d2b_txn_prev_word_mod_attestation.py` (Batch 1, post Issue #6 v2 fix) — this is the four-channel rejection model from plan §9b v0.10. Specific guards: (a) DO NOT revert the NFP-10 byte_addr fix at `compressed_global_extractor.py:216`; (b) DO NOT modify Batch 1 deliverables (`txn_prev_word_mod.py`, B.1 attestation test, `diff_signature.py`, `witgen/mod.rs` B.1 arm); (c) if the soundness-bug guard fires on either kind, STOP and surface to Ivan with full trace excerpt. Pass criteria are the 30+ checkboxes in the kickoff doc's "Pass criteria" section. Submit a written report at `a4/docs/cloud2/composer/D2B_BATCH2_COMPOSER_REPORT.md` documenting which Hook 3 family fired for each kind (critical input for Batch 3's per-kind family expectations).

---

*End of D2.B Batch 2 kickoff. Predecessor: Batch 1 (`78d036c` — Batch 1.5e D2.B).*
