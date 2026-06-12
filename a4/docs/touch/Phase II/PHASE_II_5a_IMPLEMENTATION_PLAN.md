# Phase II.5a Implementation Plan: A/B Comparison + Boss-Facing Notebook

---

## 0. Table of Contents

1. [Goal and Context](#1-goal-and-context)
2. [Scope Boundary](#2-scope-boundary)
3. [Task Breakdown](#3-task-breakdown)
4. [Task 1: Coverage Tracking in Non-Bandit Mode](#4-task-1-coverage-tracking-in-non-bandit-mode)
5. [Task 2: B_count Override for Reduced-Arm Campaign](#5-task-2-b_count-override-for-reduced-arm-campaign)
6. [Task 3: Analysis Script Updates](#6-task-3-analysis-script-updates)
7. [Task 4: Run Uniform Baseline Campaign](#7-task-4-run-uniform-baseline-campaign)
8. [Task 5: Run Reduced-Arm Bandit Campaign](#8-task-5-run-reduced-arm-bandit-campaign)
9. [Task 6: Boss-Facing Notebook](#9-task-6-boss-facing-notebook)
10. [Testing Strategy](#10-testing-strategy)
11. [Files to Change](#11-files-to-change)
12. [Deviations from Higher-Level Plans](#12-deviations-from-higher-level-plans)
13. [Variable Reference](#13-variable-reference)
14. [For Anyone New](#14-for-anyone-new)

---

## 1. Goal and Context

**Goal**: Produce a boss-facing presentation notebook that answers three questions (Pro_Report_8 §1):
1. Did we explore the constraint space better than before (random)?
2. Did the scheduler learn something nontrivial?
3. Why does that increase our odds of finding a soundness bug?

**Why now**: We have a complete 1000-mutation bandit campaign (Phase II.4), but no uniform control run. Without an A/B comparison, we cannot claim "better than random." Pro_Report_8 identifies this as the single biggest gap.

**Input**: Existing 1000-mutation bandit campaign data (terminal output in `/root/.cursor/projects/root-arguzz/terminals/633840.txt`).

**Output**:
- Two new campaigns: 1000-mutation uniform baseline + 1000-mutation bandit with B_count=16
- A new notebook (`boss_presentation.ipynb`) with A/B comparison and executive summary

---

## 2. Scope Boundary

### In scope (this sub-phase)
- Coverage tracking (reward diagnostics) in non-bandit mode
- B_count CLI override for reduced-arm bandit campaign
- Updated analysis script for dual-campaign parsing
- Running the 1000-mutation uniform baseline campaign
- Running the 1000-mutation reduced-arm bandit campaign (B_count=16)
- Creating the boss-facing notebook with three-way comparison

### Out of scope (explicitly deferred)
- **Step 0 crash fix for PRE_EXEC_REG_MOD** → deferred to AFTER both new campaigns complete, so all three campaigns (existing bandit, new uniform, new reduced-arm bandit) run under identical conditions
- **Z signature clustering** → Phase III.0
- **Weight tuning A/B** → Phase II.5b
- **Persistence/resume** → Phase II.6

### Rationale for deferring step 0 crash fix

The existing 1000-mutation bandit campaign (Phase II.4) was run WITHOUT the step 0 fix, meaning PRE_EXEC_REG_MOD could select step 0 and crash. For a perfectly fair A/B comparison, both new campaigns must operate under the same conditions. If we applied the step 0 fix only to the new campaigns, the comparison would be asymmetric (the bandit campaign has 11 wasted crash iterations that the new campaigns wouldn't have). The step 0 fix is tracked in the master plan and will be applied before any future campaigns.

---

## 3. Task Breakdown

| Task | Description | Effort | Dependencies |
|------|-------------|--------|--------------|
| **1** | Coverage tracking in non-bandit mode | Medium | None |
| **2** | B_count CLI override for reduced-arm campaign | Small | None |
| **3** | Analysis script updates | Medium | Task 1 |
| **4** | Run uniform baseline campaign (1000 mut) | ~6 hours (wall clock) | Tasks 1, 3 |
| **5** | Run reduced-arm bandit campaign (1000 mut, B_count=16) | ~6 hours (wall clock) | Tasks 2, 3 |
| **6** | Boss-facing notebook | Medium-Large | Tasks 3, 4, 5 |

Tasks 1 and 2 can be implemented in parallel.
Tasks 4 and 5 can run sequentially (or on separate machines if available).
Total code changes: ~200-250 lines across 5 files + new notebook.

---

## 4. Task 1: Coverage Tracking in Non-Bandit Mode

### Problem

`_run_single_mutation` (lines 514-651 of `fuzzer.py`) does NOT compute reward diagnostics. `MutationResult.reward` defaults to 0.0 and `reward_diag` defaults to `None` (lines 92-93). Since `_print_mutation_result` only prints the reward diagnostic line when `result.reward_diag is not None` (line 1246), non-bandit campaigns produce no per-run coverage metrics. This means the analysis script gets all-zero reward fields for uniform campaigns, making A/B comparison impossible.

### Solution overview

Add a lightweight CoverageState initialization path for non-bandit mode, and compute reward + update state after each mutation. No bandit logic (no pilot, no arms, no UCB) — just the coverage tracking and reward computation.

### 4.1: Initialization in `__init__`

**Current code** (lines 187-191):
```python
self.scheduler: Optional[DiscountedUCBScheduler] = None
self.coverage_state: Optional[CoverageState] = None
self.arm_universe: Optional[ArmUniverse] = None
self._pilot_count: int = 0
```

These are already initialized unconditionally (outside the `if selector_strategy == "bandit"` block at lines 173-176). `self.coverage_state` starts as `None` in all modes. **No change needed here.**

### 4.2: New method `_setup_coverage_tracking`

Add a new method below `_setup_bandit` (after line 343):

```python
def _setup_coverage_tracking(self) -> None:
    """Initialize CoverageState for non-bandit mode (reward diagnostics only, no bandit)."""
    if self.verbose:
        print("\n--- COVERAGE TRACKING SETUP ---")
        print("Capturing baseline touch...")
    
    baseline = capture_baseline_touch(self.host_binary, self.host_args)
    
    if self.verbose:
        print(f"  Baseline: {baseline.distinct_buckets} bitmap buckets")
    
    params = CalibratedParams(
        tau_new=35.0,
        tau_d=3.0,
        K_T_rare=31,
        gamma=0.9965,
    )
    
    self.coverage_state = CoverageState(params)
    self.coverage_state.seed_from_baseline(baseline.bitmap)
    
    if self.verbose:
        print(f"  Calibrated: τ_T={params.tau_new:.1f}, τ_d={params.tau_d:.1f}, "
              f"K_T_rare={params.K_T_rare}, γ={params.gamma:.4f}")
        print("--- COVERAGE TRACKING READY ---\n")
```

**Critical detail — Calibration print format**: The print on the second-to-last verbose line uses the EXACT same format as `_setup_bandit` (line 325-326): `Calibrated: τ_T={...}, τ_d={...}, K_T_rare={...}, γ={...}`. This is required because `analyze_campaign.py` uses `CALIB_RE` (line 47: `re.compile(r'Calibrated: .+=(.+), .+=(.+), .+=(\d+), .+=(.+)')`) to extract calibration metadata. Using the same format ensures the analysis script can parse both campaign types identically.

**Critical detail — Fixed parameters**: We hardcode `tau_T=35.0, tau_d=3.0, K_T_rare=31, gamma=0.9965` to match the values calibrated by the existing bandit campaign's pilot. This ensures the reward function evaluates mutations identically in both campaigns. If we used different parameters, a given mutation at a given coverage state would produce different rewards between campaigns, invalidating the comparison.

**Critical detail — `gamma` usage**: `gamma` is stored in `CalibratedParams` but is only used by `DiscountedUCBScheduler` (not by `CoverageState` or `compute_reward`). Setting `gamma=0.9965` has no effect on reward computation in non-bandit mode, but we include it for consistency and so the CALIB_RE parser captures it.

**Critical detail — No pilot coverage merging**: In `_setup_bandit` (lines 332-337), pilot run coverage data is merged into `CoverageState.global_bitmap` and `CoverageState.freq` before the first bandit-mode mutation. In the non-bandit mode, there's no pilot phase, so coverage tracking starts from baseline-only. This means the first few uniform runs may show slightly higher novelty than the first bandit-mode runs (which had 50 pilot runs already "spent"). This is correct behavior — it reflects the real cost of the pilot phase.

### 4.3: Call `_setup_coverage_tracking` in `run_campaign`

**Current code** (lines 481-488):
```python
if self.selector_strategy == "bandit":
    self._setup_bandit(num_mutations, stats)
    main_budget = num_mutations - self._pilot_count
    start_idx = self._pilot_count
else:
    main_budget = num_mutations
    start_idx = 0
```

**Change**: Add `_setup_coverage_tracking()` in the `else` branch:
```python
else:
    main_budget = num_mutations
    start_idx = 0
    self._setup_coverage_tracking()
```

### 4.4: Add reward computation to `_run_single_mutation`

**Current code ends at** (lines 641-651):
```python
# Phase 3.3: Touch coverage — count new bits and merge into global bitmap
if exec_result.touch_bitmap is not None:
    new_touch = count_new_bits(exec_result.touch_bitmap, self.global_touch_bitmap)
    merge_into_global(exec_result.touch_bitmap, self.global_touch_bitmap)
    result.new_touch = new_touch

# Update guided selector if applicable
if hasattr(self.selector, 'record_mutation'):
    self.selector.record_mutation(step, new_coverage + result.new_touch)

return result
```

**Insert AFTER line 645 (touch tracking), BEFORE line 647 (guided selector)**:

```python
if self.coverage_state is not None:
    outcome = self._classify_outcome(result)
    reward, diag = compute_reward(
        exec_result.touch_bitmap, failures, exit_code,
        outcome, proof_generated, self.coverage_state,
    )
    result.reward = reward
    result.reward_diag = diag
    update_state(exec_result.touch_bitmap, failures, exit_code, self.coverage_state)
```

**Why this position in the function**: The `compute_reward → update_state` ordering is the same contract used by `_run_bandit_mutation` (lines 413-425): compute_reward reads state BEFORE this run's contribution, then update_state writes it. The variables `exec_result`, `failures`, `exit_code`, and `proof_generated` are all in scope (defined at lines 571, 581, 582, 595 respectively).

**Why `self.coverage_state is not None` guard**: In bandit mode, `_run_single_mutation` is not called (the main loop calls `_run_bandit_mutation` instead, line 494). But we add the guard defensively. In non-bandit mode, `_setup_coverage_tracking` sets `self.coverage_state` before the loop begins, so this condition is True.

**What this enables**: After this change, the `_print_mutation_result` method (line 1246: `if result.reward_diag is not None`) will print the reward diagnostic line for non-bandit runs:
```
       r=0.154  T_new=0.00 F_new=0.05 F_rare=0.30 Z=1 Q=0.81
```
This makes the terminal output format identical to bandit campaigns, so `analyze_campaign.py` can parse both without changes to its core regex patterns (`BANDIT_RE` and `REWARD_RE` both match).

### 4.5: Verification of regex compatibility

The non-bandit output line format (from `_print_mutation_result`, line 1241):
```
  [152] ✓ COMP_OUT_MOD @ step 2261: 3 failures, 1234ms, outcome: REJECTED, exit: 0 [proof:GENERATED] [+2 new] [+5 touch]
```

- `BANDIT_RE` (`\[(\d+)\] [^\s]+ (\w+) @ step (\d+): (\d+) failures?, (\d+)ms, outcome: (\w+)`) — **matches** ✓. The `[^\s]+` matches emoji status icons; the regex uses `search()` so trailing fields don't prevent matching.
- `REWARD_RE` (`r=([\d.]+)\s+T_new=...`) — **matches** the reward diagnostic line printed when `reward_diag is not None` ✓.
- `TOUCH_RE` (`\[([+-]\d+) touch\]`) — **matches** `[+5 touch]` ✓.

---

## 5. Task 2: B_count Override for Reduced-Arm Campaign

### Problem

`ArmUniverse.__init__` (line 106 of `arm_universe.py`) computes `B_count` automatically from budget:
```python
raw = budget // (self.K * _N_TARGET)
self.B_count = pow2_clamp(raw, _B_MIN, _B_MAX)
```
For budget=1000 and K=8, this gives `raw = 1000 // 24 = 41`, clamped to `B_count = 32`. There's no way to override this from outside.

For the reduced-arm campaign, we want `B_count = 16`, giving ~127 arms and ~7-8 samples/arm (vs 254 arms and ~3.7 samples/arm at B_count=32).

### 5.1: Add `b_count_override` to `ArmUniverse.__init__`

**Current signature** (line 72):
```python
def __init__(self, data, budget, mutation_kinds):
```

**New signature**:
```python
def __init__(self, data, budget, mutation_kinds, b_count_override=None):
```

**Change in body** (replace lines 104-109):
```python
# Step 3: Compute B_count
if b_count_override is not None:
    self.B_count = b_count_override
elif self.K > 0 and budget > 0:
    raw = budget // (self.K * _N_TARGET)
    self.B_count = pow2_clamp(raw, _B_MIN, _B_MAX)
else:
    self.B_count = _B_MIN
```

### 5.2: Thread `b_count_override` through `A4Fuzzer`

**`A4Fuzzer.__init__`** (line 138): Add parameter `b_count_override: Optional[int] = None` and store it:
```python
self.b_count_override = b_count_override
```

**`A4Fuzzer._setup_bandit`** (line 242): Pass to ArmUniverse:
```python
self.arm_universe = ArmUniverse(
    self.data, num_mutations, self.MUTATION_KINDS,
    b_count_override=self.b_count_override,
)
```

### 5.3: Add `--b-count` CLI argument

**In `cli.py`** (after line 209):
```python
fuzz_parser.add_argument("--b-count", type=int, default=None,
                        help="Override bucket count for bandit arm universe (default: auto)")
```

**In `cmd_fuzz`** (line 48): Add to constructor call:
```python
with A4Fuzzer(
    host_binary=str(host_binary.absolute()),
    host_args=host_args,
    db_path=args.db,
    kind=args.kind,
    selector_strategy=args.selector,
    value_strategy=args.values,
    seed=args.seed,
    verbose=True,
    b_count_override=args.b_count,
) as fuzzer:
```

---

## 6. Task 3: Analysis Script Updates

### Current state

`a4/standalone/tests/analyze_campaign.py`:
- `RunRecord` has 14 fields (lines 22-36): `num, kind, step, n_fail, time_ms, outcome, reward, T_new, F_new, F_rare, Z, Q, is_pilot, new_touch`
- `parse_terminal` parses pilot runs (`PILOT_RE`), bandit runs (`BANDIT_RE`), reward diagnostics (`REWARD_RE`), touch (`TOUCH_RE`), and calibration (`CALIB_RE`)
- Analysis assumes "bandit vs pilot" split but works for uniform campaigns (pilot=empty, all runs matched by `BANDIT_RE`)

### 6.1: Add `new_coverage` field to `RunRecord`

```python
@dataclass
class RunRecord:
    # ... existing fields ...
    new_touch: int = 0
    new_coverage: int = 0  # NEW: distinct new failure context_ids
```

### 6.2: Add `NEWCOV_RE` regex

After line 46 (`TOUCH_RE`):
```python
NEWCOV_RE = re.compile(r'\[\+(\d+) new\]')
```

**Format matched**: `[+5 new]` (from `_print_mutation_result` line 1214: `f" [+{result.new_coverage} new]"` when `result.new_coverage > 0`).

### 6.3: Parse `new_coverage` in `parse_terminal`

In the `BANDIT_RE` match block (lines 80-92), after the TOUCH_RE match (lines 87-89):
```python
bm = BANDIT_RE.search(line)
if bm:
    rec = RunRecord(...)
    tm = TOUCH_RE.search(line)
    if tm:
        rec.new_touch = int(tm.group(1))
    nm = NEWCOV_RE.search(line)     # NEW
    if nm:                           # NEW
        rec.new_coverage = int(nm.group(1))  # NEW
    runs.append(rec)
    pending_reward = rec
    continue
```

### 6.4: Add cumulative metric computation functions

New standalone functions (append to the module):

```python
def compute_cumulative_metrics(runs: List[RunRecord]) -> dict:
    """Compute per-run cumulative coverage metrics.
    
    Returns dict with lists:
      'cum_touch': cumulative new touch buckets
      'cum_coverage': cumulative new failure context_ids
      'cum_Z': cumulative Z events
      'cum_crash': cumulative crashes
    """
    cum_touch, cum_cov, cum_z, cum_crash = [], [], [], []
    t, c, z, cr = 0, 0, 0, 0
    for r in runs:
        t += r.new_touch
        c += r.new_coverage
        z += r.Z
        cr += 1 if r.outcome == "CRASH" else 0
        cum_touch.append(t)
        cum_cov.append(c)
        cum_z.append(z)
        cum_crash.append(cr)
    return {
        'cum_touch': cum_touch,
        'cum_coverage': cum_cov,
        'cum_Z': cum_z,
        'cum_crash': cum_crash,
    }


def compute_auc_normalized(curve: list) -> float:
    """Normalized AUC: area / (n * final_value). Higher = faster discovery."""
    if not curve or curve[-1] == 0:
        return 0.0
    return sum(curve) / (len(curve) * curve[-1])


def compute_t80(curve: list) -> int:
    """Iterations to reach 80% of final value. Returns len(curve) if never reached."""
    if not curve or curve[-1] == 0:
        return len(curve)
    target = 0.8 * curve[-1]
    for i, v in enumerate(curve):
        if v >= target:
            return i + 1
    return len(curve)
```

### 6.5: What does NOT need to change

- `BANDIT_RE` already matches non-bandit output format (verified in Task 1 §4.5).
- `REWARD_RE` already matches reward diagnostic lines from both modes.
- `PILOT_RE` simply won't match anything in non-bandit campaigns (correct behavior — `pilot` list will be empty).
- The `analyze` function's `pilot`/`bandit` split (line 109-110) works correctly: for uniform campaigns, all runs land in `bandit` (misleading name but functionally correct).

---

## 7. Task 4: Run Uniform Baseline Campaign

### Command

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host workspace/risc0-modified/target/release/r0vm \
    --num 1000 \
    --selector zoned \
    --seed 777 \
    --kind all \
    --db uniform_baseline_1000.db \
    -- --in1 5 --in4 10
```

### Key parameters matching existing bandit campaign

| Parameter | Bandit campaign | Uniform campaign | Match? |
|-----------|----------------|------------------|--------|
| Guest program | `r0vm` | `r0vm` | ✓ |
| Guest args | `--in1 5 --in4 10` | `--in1 5 --in4 10` | ✓ |
| Seed | 777 | 777 | ✓ (same RNG sequence start) |
| Mutation kinds | All 8 | All 8 | ✓ |
| Step 0 available | Yes (caused 11 crashes) | Yes (may cause crashes) | ✓ |
| Step selection | Bandit (kind,bucket) | Zoned (5%/90%/5%) | Different (by design) |
| Kind selection | Bandit (per arm) | Uniform random | Different (by design) |
| Reward computation | CoverageState + compute_reward | CoverageState + compute_reward | ✓ (same params) |
| Total mutations | 1000 (50 pilot + 946 bandit + 4 skip) | 1000 | Similar |

### Estimated time

~6 hours based on the bandit campaign's 23s/mutation average. Each mutation requires one full prove+verify cycle. No bandit overhead.

### Output

Terminal output file will be the data source for analysis. The terminal file is automatically saved by Cursor.

---

## 8. Task 5: Run Reduced-Arm Bandit Campaign

### Command

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host workspace/risc0-modified/target/release/r0vm \
    --num 1000 \
    --selector bandit \
    --b-count 16 \
    --seed 777 \
    --kind all \
    --db bandit_16_1000.db \
    -- --in1 5 --in4 10
```

### Expected arm universe with B_count=16

| Metric | B_count=32 (existing) | B_count=16 (new) |
|--------|----------------------|------------------|
| B_count | 32 | 16 |
| B (steps/bucket) | ceil(3930/32) = 123 | ceil(3930/16) = 246 |
| Max possible arms | 8 × 32 = 256 | 8 × 16 = 128 |
| Expected actual arms | ~254 | ~127 (some buckets may be empty for LOAD/STORE) |
| Avg samples/arm | ~3.7 | ~7.4 |
| Pilot mutations | ~50 | ~50 |
| Bandit mutations | ~946 | ~946 |

With ~7.4 samples/arm, the bandit should show clearer exploitation patterns than at 3.7 samples/arm (Pro_Report_8 §3).

### Estimated time

~6 hours, same as other campaigns.

---

## 9. Task 6: Boss-Facing Notebook

### File

`a4/notebooks/boss_presentation.ipynb` — a NEW notebook separate from the existing `campaign_analysis.ipynb`.

### Structure (following Pro_Report_8 §1)

**Cell 0: Title + Executive Summary (Markdown)**

One-slide summary block:
- What changed: from random scheduling → bandit scheduling using (touch, failure-context, Z) reward
- What we can now measure: touched constraints (local) + failing contexts (local) + post-local rejection (Z)
- Headline results: [filled in after campaigns complete]
- Limitations: no global constraint instrumentation yet; Z is "post-local rejection" not "global constraint ID"

**Cell 1: Data Loading (Code)**

Load all three terminal output files (existing bandit-32, new uniform, new bandit-16). Parse into DataFrames. Compute cumulative metrics.

```python
BANDIT32_FILE = '...'
UNIFORM_FILE = '...'
BANDIT16_FILE = '...'

b32_runs, b32_meta = parse_terminal(BANDIT32_FILE)
uni_runs, uni_meta = parse_terminal(UNIFORM_FILE)
b16_runs, b16_meta = parse_terminal(BANDIT16_FILE)
```

Parameterize file paths at the top (Pro_Report_8 hygiene note).

**Cells 2-3: Section B — "Did we explore more?" (Markdown + Code)**

Four overlay plots (three lines each: uniform=dashed red, bandit-32=solid blue, bandit-16=solid green), same x-axis (run index):

1. **Cumulative distinct failure context_ids** vs run index
2. **Cumulative distinct touch buckets** vs run index
3. **Cumulative Z events** vs run index
4. **Cumulative crashes** vs run index

Below the plots, a summary table:

| Metric | Uniform | Bandit-32 | Bandit-16 | Δ (B32 vs Uni) | Δ (B16 vs Uni) |
|--------|---------|-----------|-----------|----------------|----------------|
| Final failure contexts | | | | | |
| Final touch buckets | | | | | |
| Final Z events | | | | | |
| AUC (norm) | | | | | |
| t_80 | | | | | |

**Cells 4-5: Section C — "What did the bandit learn?" (Markdown + Code)**

For both bandit campaigns (B_count=32 and B_count=16):

1. **Reward heatmap** (kind × bucket) — mean reward per arm
2. **Selection count heatmap** (kind × bucket) — how often each arm was selected
3. **Top 15 arms table**: kind, bucket, pulls, mean reward, Z rate, mean Q

The top-arms table is what Pro_Report_8 says is "usually the 'aha' that convinces people it isn't random."

For the reduced-arm campaign, we expect to see clearer exploitation: higher-reward arms should be selected more frequently since each arm has ~7.4 samples (vs ~3.7).

**Cells 6-7: Section D — "Why Z events matter" (Markdown + Code)**

- Z event rate by kind (bar chart, all three campaigns)
- Z event step distribution (histogram)
- Brief Z-by-bucket heatmap
- Narrative: "Z means the mutation passed all local constraint checks but the proof was still rejected. This indicates failure in non-instrumented checks (likely global constraints). Runs closest to passing all checks are the most interesting for underconstraint detection."

**Cells 8-9: Section E — Quality and Crashes (Markdown + Code)**

Tightened per Pro_Report_8:
- **Crash table**: crashes by (kind, step) across all campaigns
- **Cascade table**: top 5 cascades with n_fail and reward
- One statement: "The Q multiplier suppresses cascades (near-zero reward for n_fail > 10 runs)."

**Cell 10: Appendix — Algorithm Specification (Markdown)**

LaTeX algorithm spec, reused from existing notebook.

### Notebook hygiene (Pro_Report_8 §1)

- Parameterize terminal file paths at the top
- Derive `B` from campaign metadata, not hardcode
- Consistent color scheme: uniform=red dashed, bandit-32=blue solid, bandit-16=green solid

---

## 10. Testing Strategy

| Test | Method | Expected outcome |
|------|--------|------------------|
| Coverage tracking: reward printed | Run `--selector zoned --num 3 --verbose` and check output | Reward diagnostic line (`r=... T_new=... F_new=... F_rare=... Z=... Q=...`) printed for each mutation |
| Coverage tracking: calibration metadata | Same test run | `Calibrated: τ_T=35.0, τ_d=3.0, K_T_rare=31, γ=0.9965` printed |
| B_count override | Run `--selector bandit --num 35 --b-count 16 --verbose` | Arm universe summary shows `Bucket count: 16` instead of 32 |
| Analysis script: new_coverage parsing | Parse a terminal file with `[+N new]` tags | `RunRecord.new_coverage` populated correctly |
| Analysis script: uniform campaign parsing | Parse the uniform campaign output | All runs parsed (no pilot), reward fields populated |
| Cumulative metrics | Compute on parsed data | Monotonically non-decreasing curves |
| AUC/t_80 | Compute on test data | Reasonable values (AUC in [0,1], t_80 < total runs) |
| Notebook execution | `jupyter nbconvert --execute` | All cells execute without error, all plots rendered |

### Smoke test sequence (before full campaigns)

1. Apply Task 1 + Task 2 code changes
2. Run `--selector zoned --num 5 --verbose --seed 42` → verify reward diagnostics printed
3. Run `--selector bandit --b-count 16 --num 35 --verbose --seed 42` → verify B_count=16 in arm summary
4. Parse both terminal outputs with updated `analyze_campaign.py` → verify RunRecords populated

---

## 11. Files to Change

| File | Task | Change | Lines (est.) |
|------|------|--------|-------------|
| `a4/standalone/fuzzer.py` | **1** | Add `_setup_coverage_tracking()` method (~20 lines), add reward computation in `_run_single_mutation` (~10 lines), add `b_count_override` parameter to `__init__` and `_setup_bandit` (~5 lines) | ~35 |
| `a4/standalone/arm_universe.py` | **2** | Add `b_count_override` parameter to `__init__`, conditional B_count logic | ~5 |
| `a4/standalone/cli.py` | **2** | Add `--b-count` argument, pass to `A4Fuzzer` | ~3 |
| `a4/standalone/tests/analyze_campaign.py` | **3** | Add `new_coverage` field, `NEWCOV_RE` regex, parsing logic, cumulative metric functions, AUC/t_80 functions | ~60 |
| `a4/notebooks/boss_presentation.ipynb` | **6** | New notebook | ~500 (new file) |

---

## 12. Deviations from Higher-Level Plans

| Deviation | Justification |
|-----------|---------------|
| Step 0 crash fix deferred | User directive: both new campaigns must be "perfectly similar" to the existing bandit campaign, which did NOT have the fix. Fix will be applied after all three campaigns complete. |
| Z signature clustering not included | User directive: deferred to after campaigns. Pro_Report_8 recommends it but it's separable from A/B comparison. |
| Reduced-arm campaign included in II.5a (not II.5b) | User directive: run both campaigns (uniform + reduced-arm) as part of the first task. Originally the master plan had this in II.5b. |
| Using hardcoded calibration params for non-bandit mode instead of pilot calibration | Design decision: ensures identical reward computation between campaigns. The existing bandit campaign calibrated tau_T=35.0, tau_d=3.0, K_T_rare=31 from its pilot. Using the same values for the uniform campaign makes the reward diagnostics directly comparable. Running a separate pilot for the uniform campaign would produce different parameters, invalidating the comparison. |
| Three-way comparison instead of two-way | We have three campaigns: existing bandit-32, new uniform, new bandit-16. Showing all three gives the most complete picture (uniform baseline, original bandit, improved bandit). |

---

## 13. Variable Reference

| Variable | Type | Meaning |
|----------|------|---------|
| `coverage_state` | `CoverageState` | Global coverage tracking: touch bitmap, failure frequencies. Used for reward computation in both bandit and non-bandit modes. |
| `b_count_override` | `Optional[int]` | CLI-specified bucket count override. If `None`, B_count is auto-derived from budget. If set (e.g., 16), overrides the formula. |
| `B_count` | `int` | Number of step buckets. 32 for existing campaign, 16 for reduced-arm campaign. |
| `B` | `int` | Steps per bucket: `ceil(T / B_count)`. 123 for B_count=32, 246 for B_count=16. |
| `C_fail(t)` | curve | Cumulative distinct failure context_ids at run t. Derived from `new_coverage` per-run values. |
| `C_touch(t)` | curve | Cumulative distinct touch buckets at run t. Derived from `new_touch` per-run values. |
| `C_Z(t)` | curve | Cumulative Z events at run t. Derived from `Z` per-run values. |
| `AUC` | scalar | Normalized area under cumulative curve: `sum(curve) / (n * final_value)`. Range [0,1]. Higher = faster discovery. Value of 1.0 means everything was discovered in the first run; value of 0.5 means linear growth. |
| `t_80` | scalar | Number of iterations to reach 80% of the campaign's final value for a given metric. Lower = faster discovery. |
| `new_coverage` | `int` | Per-run count of newly discovered failure context_ids (from DB `INSERT OR IGNORE` counting newly inserted rows). |
| `new_touch` | `int` | Per-run count of newly discovered touch bitmap buckets (from `count_new_bits`). |
| `tau_T` | `float` | Touch novelty scaling parameter. T_new = 1 - exp(-delta_T / tau_T). Value: 35.0 (calibrated from pilot). |
| `tau_d` | `float` | Distinct-failure penalty scaling. Q_dist = exp(-d_fail / tau_d). Value: 3.0. |
| `K_T_rare` | `int` | Number of rarest touched buckets to average for T_rare. Value: 31. |
| `gamma` | `float` | Bandit discount factor. Half-life = ln(2) / ln(1/gamma) ≈ 200 iterations. Not used by CoverageState. |

---

## 14. For Anyone New

### What Phase II.5a is

This sub-phase bridges the gap between "we built a bandit scheduler" (completed in II.4) and "we can show it works better than random" (needed for the presentation). The core deliverable is a **boss-facing notebook** with an **A/B comparison** between the bandit scheduler and a uniform-random baseline, plus a reduced-arm bandit run to show clearer exploitation.

### Why it's structured this way

The implementation is split into **six sequential tasks** because each depends on the previous:
1. We add coverage tracking to non-bandit mode (so both campaigns produce comparable metrics)
2. We add B_count override (so we can run a reduced-arm bandit)
3. We update the analysis script (so it can parse and compare all campaigns)
4. We run the uniform baseline campaign (~6 hours)
5. We run the reduced-arm bandit campaign (~6 hours)
6. We build the notebook (visualization and analysis)

### How it differs from other sub-phases

Previous sub-phases (II.0-II.4) were about **building** the bandit architecture piece by piece. This sub-phase is about **validating** it against a control. We're not adding new algorithmic capabilities — we're producing the evidence needed to answer "does the bandit actually help?" and presenting it in a format suitable for non-technical stakeholders.

### What comes after

- **Step 0 crash fix**: Applied after all campaigns complete (deferred from this sub-phase to maintain experimental consistency)
- **Phase III.0**: Cluster Z events by reject signature (cheap insight into what Z actually represents)
- **Phase III.1**: Instrument global constraints in RISC Zero

---

*End of Phase II.5a Implementation Plan (Revised).*
