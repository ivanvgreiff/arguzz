# C0 — Parity Harness + Constraint-Category Classifier (composer spec)

**Goal of C0:** build the foundational, reusable machinery for the whole campaign and **prove it
correct against known ground truth** before we run anything at scale. Nothing statistical yet — C0 is
about *trustworthy primitives*.

**Primary metric this enables:** for any run, classify each *targeted* and *failed* constraint into
**L1 (local intra-step) / L2 (local interstep = memory-consistency) / ACCUM / G (global)** — see
PLAN.md §4.0. C0 must produce these category counts for both fuzzers and validate them on cases whose
answers we already know (M2, `verify_crash`).

**Hard isolation:** all new files under `thesis_side_experiments/bias_campaign/`. Import `a4/` parsers
**read-only** (no edits to `a4/`, `workspace/`). Validate on the **minimal_add host**
(`thesis_side_experiments/minimal_add/target/release/thesis-minimal-host`) because we have exact ground
truth there. Confirm production `risc0-host` mtime unchanged at the end.

---

## Deliverables (all under `thesis_side_experiments/bias_campaign/`)

### 1. `categorize.py` — the constraint-category classifier (pure functions)
```python
def categorize_failure(loc: str, phase: str) -> str:
    # phase == "accum"                      -> "ACCUM"
    # phase == "local" and "mem.zir" in loc -> "L2"   (interstep / memory-consistency)
    # phase == "local"                      -> "L1"   (intra-step)
    # else: raise / "UNKNOWN" (log)

def categorize_failures(failures) -> dict:
    # returns {"L1": n, "L2": n, "ACCUM": n} counting ConstraintFailure objects

def categorize_touched(local_verbose: list[str], accum_verbose: list[str]) -> dict:
    # each context string is "loc|major|minor"
    # returns {"L1": n, "L2": n, "ACCUM": n} over the TOUCHED universe
    # (L1/L2 from local_verbose by mem.zir rule; ACCUM = len(accum_verbose))

def global_failed(family_residues, global_residue) -> dict:
    # returns {"memory": bool, "u16": bool, "u8": bool, "cycle": bool, "any": bool}
    # "any" => the GLOBAL (G) category fired
```
Reuse the known L2 set as a sanity assertion: `mem.zir` locs are `IsRead@79/80`,
`MemoryWrite@99/100`, `IsCycle@61/62`, `MemoryIO@69-74`.

### 2. `classify.py` — fuzzer-agnostic outcome classifier
```python
@dataclass
class RunOutcome:
    outcome_class: str        # see PLAN.md §2
    injected: bool            # a <fault> at the target step present
    fault: dict | None        # {kind, step, target (reg/addr), value}
    failures: list            # parsed ConstraintFailure list
    family_residues: list | None
    global_nonzero: bool
    verifier_success: bool
    panic_loc: str | None
    preflight_crash: bool

def classify_run(combined_output: str, target_step: int | None) -> RunOutcome
```
Implement the §2 precedence exactly: `PREFLIGHT_CRASH` (panic at `preflight.rs`), then `OTHER_CRASH`,
`ACCEPTED` (verifier success after injection), `CONSTRAINT_REJECT` (≥1 `<constraint_fail>`),
`GLOBAL_REJECT` (no local fails but global residue nonzero), `VERIFY_REJECT`, `VALID_NO_SIGNAL`,
`NO_INJECTION`.

### 3. `run_arguzz.py` — single Arguzz injection
```python
def run_arguzz(host, guest_args, kind, step, seed, extra_env=None, timeout=300) -> RunOutcome
# cmd: [host, "--trace", "--inject", "--inject-step", step,
#       "--inject-kind", kind, "--seed", seed] + guest_args
# default extra_env: {CONSTRAINT_CONTINUE:1, A4_COVERAGE_TOUCH:1,
#                     A4_COVERAGE_TOUCH_VERBOSE:1, A4_FAMILY_RESIDUE:1, A4_GLOBAL_RESIDUE:1}
# capture stdout+stderr; classify_run(...)
```

### 4. `run_a4.py` — single A4 mutation
```python
def run_a4(host, guest_args, config_path, extra_env=None, timeout=300) -> RunOutcome
# reuse a4.core.executor.run_a4_mutation OR replicate its env
# (A4_MUTATION_CONFIG, CONSTRAINT_CONTINUE=1, A4_COVERAGE_TOUCH=1,
#  A4_COVERAGE_TOUCH_VERBOSE=1, A4_FAMILY_RESIDUE=1, A4_GLOBAL_RESIDUE=1); classify_run(...)
```
For C0, reuse the existing M2 mutation config `../minimal_add/artifacts/m2/a4_mutation.json`
(PRE_EXEC_REG_MOD on a1, next_read, 4→9).

### 5. Reuse these `a4/` parsers (read-only; add `sys.path.insert(0, ROOT.parent.parent)`)
- `a4.core.constraint_parser.parse_all_constraint_failures` → fields `loc, phase, major, minor, value, cycle, step, pc`.
- `a4.core.touch_coverage.parse_family_residues`, `parse_global_residue`.
- Local + accum **verbose touch** tags `<a4_touch_verbose>…</a4_touch_verbose>` and
  `<a4_accum_touch_verbose>…</a4_accum_touch_verbose>` — reuse the regex already used in
  `../minimal_add/run_m1.py` (do not re-implement divergently).
- `a4.common.trace_parser.parse_all_faults` → `ArguzzFault(step, pc, kind, target_register, mutated_value)`.

### 6. `test_categorize.py` — unit tests for `categorize.py`
Hand-built cases covering each category and the mem.zir boundary (e.g. `IsRead@mem.zir:79`→L2,
`DecodeInst@inst.zir:29`→L1, an `phase=accum` loc→ACCUM, a family residue→G).

### 7. `c0_validate.py` + `artifacts/c0/C0_REPORT.{md,json}`
Run the validation matrix below, apply `classify` + `categorize`, emit the report.

---

## Validation matrix (minimal_add host; ground truth known)

| Case | Fuzzer | Invocation | Expected outcome | Expected FAIL categories |
|---|---|---|---|---|
| **baseline** | none | no `--inject`, full env | `VALID_NO_SIGNAL`/clean, verifier success | none |
| **A4-a1** | a4 | M2 config (PRE_EXEC_REG_MOD a1 4→9) | `CONSTRAINT_REJECT` | **L2** = {`IsRead@mem.zir:79`, `MemoryWrite@mem.zir:99`}, both value **2013265916 (p−5)**; **G** = memory nonzero; L1=0, ACCUM=0 |
| **Arguzz-a1** | arguzz | seed **32**, step **187**, PRE_EXEC_REG_MOD | `PREFLIGHT_CRASH` (`preflight.rs:227`) | none (no eval reached) |
| **Arguzz-s9** | arguzz | seed **0**, step **187**, PRE_EXEC_REG_MOD | `CONSTRAINT_REJECT` (7 fails) | categorize the 7 → report L1/L2/ACCUM split + G |

**Targeting check (A4-a1):** parse the local verbose touch set, run `categorize_touched`; cross-check
the total against M1's **37** local contexts (`../minimal_add/artifacts/m1/add_local_universe.json`) and
report the L1/L2 split (mem.zir contexts ≈ IsRead+MemoryWrite+IsCycle+MemoryIO).

**Determinism:** run every case **twice**; assert identical `outcome_class` + category counts + failure
value sets.

---

## Acceptance gate (all must pass)
1. `test_categorize.py` passes.
2. **A4-a1 reproduces M2 exactly:** outcome `CONSTRAINT_REJECT`; FAIL categories L2={IsRead@79,
   MemoryWrite@99} both value 2013265916; G memory nonzero; L1=0/ACCUM=0.
3. **Arguzz-a1 → `PREFLIGHT_CRASH`** at `preflight.rs:227`, 0 failures.
4. **Arguzz-s9 → `CONSTRAINT_REJECT`**, 7 failures, categorized into L1/L2/ACCUM (+G if any).
5. **Targeting:** A4-a1 touched-set categorization totals the 37-context universe; L1/L2 split reported.
6. **Determinism:** 2× identical for all cases.
7. `C0_REPORT.{md,json}` emitted; no files outside `bias_campaign/` changed; production `risc0-host`
   mtime unchanged.

## Report back to Opus (for review before C1)
Provide, per case: invocation, `outcome_class`, FAIL category counts {L1,L2,ACCUM,G-families},
the raw failure locs+values, and (A4-a1) the TARGET category split vs the 37-universe. Plus: determinism
result, unit-test result, isolation confirmation, and total runtime. Flag any case where the observed
categories deviate from the table so we can reconcile before scaling.
```
Reproduce: cd /root/arguzz && python3 thesis_side_experiments/bias_campaign/c0_validate.py
```
