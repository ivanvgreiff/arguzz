# Phase 7d — Increment 1.5 Work Order

**Purpose:** implement joint-review decisions D50, D53, D54 (HYBRID kernel classifier + post_ecall redefinition + core_div split) and the D55/Theme 6 investigation. After this, the universe is HYBRID-correct and Inc 2 can start.

**Owner:** Composer
**Reviewer:** Opus
**Estimated time:** ~8-10 hours
**Gate to Inc 2:** all 7 acceptance gates green + report-back accepted

---

## 0. Required reading (DO THIS FIRST — don't skip)

You MUST read these before touching code:

1. `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` §§ D40, D46-D55
   — The decisions you're implementing. Pro will review these; your code must match the docs.

2. `a4/audits/audit_output/E6_post_ecall_window_evidence.json`
   — Opus's empirical evidence for D53. PC distribution at e+1..e+5 across all 87 ECALL boundaries.

3. `a4/audits/audit_output/E7_kernel_contamination_survey.json`
   — Opus's empirical evidence for D54. Per-zone kernel-PC contamination %; predicted kernel_other size = ~357 steps.

4. `a4/docs/cloud1/GLOSSARY.md` § "User vs kernel PC ranges"
   — The canonical USER (`0x00200000..0x00400000`) and KERNEL (`0xC0000000..0xC1000000`) ranges.

5. `a4/docs/cloud1/EXPECTED_ARMS.md` — top of file has the "PRE-HYBRID" disclaimer block. Your Task 5 removes it after regeneration.

---

## 1. The 8 tasks

### Task 1 — D50: Split `core_div` into `core_div` + `core_shr`

**Files to modify:**
- `a4/standalone/semantic_zones.py` — add `"core_shr"` to `SEMANTIC_ZONES` tuple; update `MAJOR_TO_CORE_ZONE` to be a function that takes (major, minor) since major=4 now disambiguates by minor
- `a4/standalone/zone_classifier.py` — update zone assignment for major=4 cycles to inspect minor

**Concrete change:**
```python
# semantic_zones.py
SEMANTIC_ZONES = (
    # ... existing ...
    "core_div",   # was: major=4 ALL; now: major=4 AND minor in {4,5,6,7} (DIV/DIVU/REM/REMU)
    "core_shr",   # NEW: major=4 AND minor in {0,1,2,3} (SRL/SRA/SRLI/SRAI)
    # ... rest unchanged ...
)
```

**Acceptance:** zone classifier emits `core_shr` for any step whose primary Decode cycle has major=4 AND minor ∈ {0,1,2,3}; `core_div` for minor ∈ {4,5,6,7}.

**Note:** D50 changes the partition rule for major=4 but does NOT change the cycle classification done by `inspection_data.py`. We're only changing which zone a step gets assigned to in `zone_classifier.py`.

### Task 2 — D53: Redefine `post_ecall`

**File to modify:** `a4/standalone/zone_classifier.py`

**Current definition (find and replace):** `post_ecall` = step at `ecall_step + 1`.

**New definition:** for each step `e` containing an ECALL cycle (major=8), find the smallest `k ∈ [1, 5]` such that step `e + k` exists AND has a Decode cycle (major ≤ 6) at user PC (`0x00200000 ≤ pc < 0x00400000`). That step is assigned to `post_ecall`. If no such k exists, no step gets the `post_ecall` label for this ECALL.

**Reference data:** `audit_output/E6_post_ecall_window_evidence.json` shows the empirical distribution of "first user-PC offset" across all 87 ECALLs in the baseline trace.

**Acceptance:**
- New `post_ecall` step count for baseline ≈ 30-32 (close to original 33, but with the kernel-handler intermediate steps moved out).
- For at least one ECALL, the assigned post_ecall step is at offset > 1 (proves the window logic works).

### Task 3 — D54: Add `kernel_other` zone

**Files to modify:**
- `a4/standalone/semantic_zones.py` — add `"kernel_other"` to `SEMANTIC_ZONES`
- `a4/standalone/zone_classifier.py` — implement classifier precedence:

```
For each step s:
    primary = first Decode cycle (major <= 6) at step s; if none, fall through to legacy rules
    if s == 0: zone = step0
    elif s == total_steps - 1: zone = last_step
    elif s contains an ECALL cycle (major=8): zone = pre_ecall      # D13
    elif s is the first user-PC step in [e+1, e+5] window: zone = post_ecall  # D53
    elif primary.pc in KERNEL_RANGE: zone = kernel_other            # D54 NEW
    elif major == 4 and minor in {0,1,2,3}: zone = core_shr         # D50
    elif major == 4 and minor in {4,5,6,7}: zone = core_div         # D50
    else: zone = MAJOR_TO_CORE_ZONE[major]                          # core_arithmetic, core_mul, etc.
```

**Constants** (put in `semantic_zones.py` or a new `pc_ranges.py`):
```python
KERNEL_PC_RANGE = (0xC0000000, 0xC1000000)
USER_PC_RANGE   = (0x00200000, 0x00400000)
```

**Acceptance:**
- `kernel_other` exists in `SEMANTIC_ZONES`.
- After classification, `kernel_other` arm size ≈ 357 steps (E7's prediction, ±5%).
- Specifically, step 0 stays in `step0`, the ECALL cycle stays in `pre_ecall`; OTHER kernel-PC steps (boot setup, kernel handler, kernel MRET, kernel halt cleanup) go to `kernel_other`.

### Task 4 — Re-run A3 / A4 / A5

**Scripts to run:**
```bash
python3 -m a4.audits.A3_arm_step_integrity --in1 5 --in4 10
python3 -m a4.audits.A4_mutation_module_target --in1 5 --in4 10
python3 -m a4.audits.A5_canonical_match --in1 5 --in4 10
```

**Expected outputs:**
- A3: `audit_output/A3_arms_in1_5_in4_10.json` — universe should have ~50-52 arms (48 original - 4 D40 dropped + new core_shr arms + new kernel_other arms).
- A4: still PASS — `success_rate=1.0` for every new arm.
- A5: PASS once you regenerate EXPECTED_ARMS (Task 5 below) — until then expect a diff.

**If any of these FAIL:** STOP. Either the classifier changes have a bug OR EXPECTED_ARMS needs updating. Report back with the failure details; don't try to patch over it.

### Task 5 — Regenerate EXPECTED_ARMS.md

**File to modify:** `a4/docs/cloud1/EXPECTED_ARMS.md`

**Changes:**
1. **REMOVE** the "⚠️ HYBRID ZONE-CLASSIFIER CHANGES PENDING" disclaimer block at the top.
2. **REGENERATE** the "Kept arms" table from A3 output. Specifically:
   - Old `core_div` rows should now reflect post-D50 step count (only DIV/REM steps).
   - New `core_shr` rows for each kind that has matching steps.
   - New `kernel_other` rows for each kind that has matching steps.
   - `post_ecall` rows: step count should DECREASE (some moved to kernel_other / lost to no-user-in-window).
   - 🟡 UNCERTAIN markers: most should now be 🟢 CONFIRMED (the open questions Q3, Q4 about core_div semantics are answered by D50; the post_ecall window question (Q2) is answered by D53).
3. **UPDATE** the "Expected-DROPPED arms" section: add the 4 D40-dropped arms with `dropped_reason: "D40"`. (Originally we had 5 expected-dropped; after D40 we have 9 total: 5 originals + 4 D40-dropped.)
4. **UPDATE** "Zones EMPTY on this guest" table: probably stays the same (sha/poseidon/mret/halt still empty).
5. **UPDATE** the "Open questions" section: mark Q2, Q3, Q4 as RESOLVED. Add Q11 (already in file).
6. **UPDATE** invariants section: arm count is now ≤ 55 (was ≤ 53).

**Acceptance:** after your update, A5 PASSES against your new file.

### Task 6 — E3b: MEM_VAL_MOD on non-memory majors (D55 / Theme 6)

**New script:** `a4/audits/E3b_mem_val_non_memory_majors.py`

**Goal:** characterize what's actually being mutated for `MEM_VAL_MOD|core_arithmetic` (848 steps) and `MEM_VAL_MOD|core_mul` (34 steps in the OLD universe; some may reclassify after D54). Under D54, count from the NEW universe (post-HYBRID).

**Per-arm output structure (`audit_output/E3b_mem_val_non_memory_majors.json`):**
```json
{
  "audit_id": "E3b",
  "guest": "c0c1_differential_guest",
  "host_args": ["--in1", "5", "--in4", "10"],
  "arms_analyzed": [
    "MEM_VAL_MOD|core_arithmetic",
    "MEM_VAL_MOD|core_mul"
  ],
  "per_arm": {
    "MEM_VAL_MOD|core_arithmetic": {
      "total_steps": 848,
      "total_mem_txns": <sum>,
      "txn_type_breakdown": {
        "instruction_fetch": <n>,
        "user_data_read": <n>,
        "user_data_write": <n>,
        "register_file_access": <n>,
        "other_mem_read": <n>,
        "other_mem_write": <n>
      },
      "addr_region_breakdown": {
        "user_code_0x00200000+": <n>,
        "user_data_0x10000000+": <n>,
        "register_file_0xffff0000+": <n>,
        "host_io_0x42000000+": <n>,
        "kernel_0xc0000000+": <n>,
        "other": <n>
      },
      "examples": [
        {"step": <N>, "primary_decode_pc": "0x...", "txn_idx": <N>, "addr": "0x...", "txn_type": "...", "interpretation": "..."},
        ... 5 examples min ...
      ],
      "interpretation": "<your text explaining what these mem-txns actually represent semantically — RAM consistency proofs of register reads? user data accesses adjacent to ALU ops? document with confidence based on the data>"
    },
    "MEM_VAL_MOD|core_mul": { ... same structure ... }
  },
  "verdict": "Are these mem-txns real targetable user-meaningful mutations, or are they internal scratch operations? Justify."
}
```

**Acceptance:** the dossier exists; user/Opus can read it and decide whether to keep, drop, or restrict these arms.

### Task 7 — Verify no regressions

Run the existing fast test suite:
```bash
cd a4 && python3 -m pytest standalone/tests/ -x --tb=short
```

Expect: ≥ 382 tests pass.

If any test fails: the failure is likely in zone-classifier-dependent code. Fix it. Common breakage points:
- Tests that assert specific arm names (e.g., `assert "core_div" in arm_universe`) — update them for the new zones.
- Tests that count zones — should now be 19 instead of 17.

### Task 8 — Write `PHASE_7D_INC1_5_REPORT.md`

**File to create:** `a4/docs/cloud1/composer/PHASE_7D_INC1_5_REPORT.md`

**Structure:**
```
# Phase 7d — Increment 1.5 Report

## Summary
- D50 implemented: core_div / core_shr split
- D53 implemented: post_ecall redefinition
- D54 implemented: kernel_other zone (HYBRID)
- E3b investigation: Theme 6 dossier produced

## Acceptance gate results
| Gate | Status | Numbers |
|---|---|---|
| A3 arm count | PASS/FAIL | new=N (expected ≥50) |
| A4 success_rate | PASS | 1.0 across all arms |
| A5 canonical match | PASS | matches updated EXPECTED_ARMS |
| E6 verification | PASS | post_ecall count = N (expected 30-32) |
| E7 verification | PASS | kernel_other count = N (expected ~357) |
| E3b dossier | DONE | audit_output/E3b_mem_val_non_memory_majors.json |
| Fast tests | PASS | N tests |

## New arm counts (per-kind, per-zone breakdown)
[Table from your A3 output]

## Files changed
- semantic_zones.py
- zone_classifier.py
- EXPECTED_ARMS.md (regenerated)
- audit_output/A3_*, A4_*, A5_*, E3b_*

## Open items / surprises
[Anything unexpected — even small things]

## Ready-to-proceed
Inc 1.5 is green; please confirm to start Inc 2.
```

---

## 2. Hard rules

1. **Don't change `inspection_data.py`.** The cycle major/minor classification is correct; we're only changing zone assignment.
2. **Don't touch Rust hooks.** D52 (cycle_idx plumbing) is deferred to Phase 9. Your Python-only changes must not require any host changes.
3. **Don't break existing zone names.** `core_arithmetic`, `core_mul`, `core_div`, etc. keep their existing names. ONLY `core_div` changes meaning (D50: now DIV-only). New zones are ADDED (`core_shr`, `kernel_other`); none are removed.
4. **Don't add `core_branch_user` / `core_branch_kernel`** — D48 was superseded by D54.
5. **All changes must be deterministic.** No "approximately" classifiers. Given the same trace, same step → same zone.
6. **Document any deviation.** If you discover a reason D50/D53/D54 can't be implemented as spec'd, STOP. Write up the issue and ask for guidance — don't pick an alternative interpretation silently.

---

## 3. Anti-patterns to avoid (lessons from prior increments)

- ❌ Reporting a smoke test result based on stale data (Inc 0 P2 lesson). Always re-run after the fix lands.
- ❌ Modifying `EXPECTED_ARMS.md` before A3/A5 confirm the change. Regeneration must come from audit output, not from your imagination.
- ❌ Lumping unrelated changes into one commit. Each of D50/D53/D54 should be a separately-reviewable change with its own test verification.
- ❌ Skipping the disclaimer-block removal at the top of EXPECTED_ARMS. The PRE-HYBRID disclaimer was Opus's signal that the file is stale; removing it is your signal that it's now current.

---

## 4. When you're done

Run `git status` and verify these files changed (no others, except possibly tests):

```
a4/standalone/semantic_zones.py
a4/standalone/zone_classifier.py
a4/audits/E3b_mem_val_non_memory_majors.py            (new)
a4/audits/audit_output/A3_arms_in1_5_in4_10.json      (regenerated)
a4/audits/audit_output/A4_module_targets.json         (regenerated)
a4/audits/audit_output/A5_canonical_diff.json         (regenerated)
a4/audits/audit_output/E3b_mem_val_non_memory_majors.json (new)
a4/docs/cloud1/EXPECTED_ARMS.md                       (regenerated baseline section)
a4/docs/cloud1/composer/PHASE_7D_INC1_5_REPORT.md     (new)
a4/standalone/tests/*.py                              (only if you needed test updates)
```

Then report back per Task 8.
