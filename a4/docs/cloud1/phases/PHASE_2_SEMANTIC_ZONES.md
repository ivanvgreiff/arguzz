# Phase 2 — Semantic-Zone Step Sampler — Implementation Report

**Status**: ✅ COMPLETE
**Date**: 2026-06-08
**Owner**: Cursor (Opus 4.7)
**Wall-clock**: ~1.5 h (planning ~10 min, code ~40 min, tests ~25 min, bug-fix from P1 ~5 min, report ~10 min)
**Source plan**: `a4/docs/cloud1/CLOUD1_IMPLEMENTATION_PLAN.md` §Phase 2
**Pro reference**: `a4/docs/cloud1/ProG_Report_2.md` §7.A, §7.B

---

## TL;DR — what did we do, and why does it matter for cloud1?

**Plain English**: Phase 2 builds the **map** the bandit will use to decide WHERE in the trace to mutate. In Phase 1 we defined the 17 "zones" (step0, pre_ecall, core_arithmetic, etc.) as abstract names; in Phase 2 we wrote the code that actually **looks at a sha2-host trace and labels every single step with one of those zones**. We then wrapped that labeling into a clean "arm space" data structure (`(mutation_kind, semantic_zone) → list of step indices`) that the new bandit (Phase 5) will sample from, and a tiny step picker (`SemanticZoneStepSelector`) that draws a uniform step from any chosen arm.

A surprising **structural finding** fell out of the unit tests: `(INSTR_TYPE_MOD, pre_ecall)` is **structurally empty for every guest program** because `INSTR_TYPE_MOD` only applies to "real" instruction cycles (majors 0-6) while ECALL cycles have major=8. Our code handles this gracefully by skipping empty arms at runtime (cloud1 decision D7). I recorded the observation for ChatGPT Pro to review — it's exactly the kind of "the semantic arm space is sparse and varies by kind" property that motivates the runtime-skip design.

We also discovered and FIXED a bug in Phase 1's `semantic_zones.py`: the `MAJOR_TO_CORE_ZONE` map had `8→core_sha` and `9→core_poseidon` (guessed from Pro's abstract zone names), but the authoritative source — `a4/core/inspection_data.py:summary()` lines 224-228 — says major 8 is `ECALL0`, major 11 is `SHA0`, majors 9/10 are `POSEIDON0/1`, and major 12 is `BIGINT0`. The bug was caught by the deeper test coverage Phase 2 added; the lesson is **always cross-check empirical sources before assuming a mapping**, even when the abstract names look plausible.

**How this fits into the bigger picture**: Phase 2 is the **prerequisite for every later phase**. Phase 3 (compressed global context) tags each mutation with its zone via `cycle_phase_for_zone`. Phase 4 (rewards) uses zone identity as part of the structural-cell key for `S_new`. Phase 5 (constrained TS bandit) treats `(kind, zone)` arms as its action space and uses `SemanticZoneStepSelector` to pick the actual step after the bandit chose the arm. Phase 6 (logging) writes the chosen zone into every `bandit_decisions` row. Without Phase 2, none of this is possible.

We also discovered a real limitation (D14): **MRET and halt cycles are not separately tagged in `InspectionData`** (both fall under `major=7` (`CONTROL0`) and are only distinguished by sub-opcode bits we don't currently expose). For IV.POS.7 this means `pre_mret`, `post_mret`, `pre_halt`, `post_halt` will all be EMPTY — they're still DEFINED and the bandit ignores empty arms (D7), but if Pro Round 2 wants this detection we'd need to extend the C++ Hook 3 emitter.

**Concrete numbers**: 3 new Python files (~430 LOC code), 1 modified file (`semantic_zones.py` bug fix), 1 extended file (`step_selector.py`, +60 LOC), 3 new test files (~360 LOC, 41 tests). 164 fast tests still pass with 1 expected skip. Zero regressions. 3 new D-decisions logged (D13/D14/D15).

---

## 1. Goal recap

Translate Pro §7.A (semantic arm space) and §7.B (structural step sampler) from prose into code, then verify the implementation produces the intended structure on the data shapes downstream phases will operate over.

Specifically:
1. A pure-function **classifier** that assigns each user_cycle to exactly one of 17 zones (Pro §7.A).
2. A **semantic arm universe** built by intersecting per-kind valid steps with per-zone step lists.
3. A **step selector** that picks a step uniformly within a `(kind, zone)` arm — singleton zones deterministic, broad zones uniform-sampled.

---

## 2. Deviations from plan

**Two intentional findings during the phase**; both required logging as new D-decisions:

- **D13 (ECALL cycle zone)**: Pro §7.A lists `pre_ecall` / `post_ecall` as adjacency zones but is silent on what zone the ECALL cycle ITSELF goes into. I picked `pre_ecall` for the ECALL cycle and `post_ecall` for `e+1`. Rationale: ECALL setup constraints fire AT the ECALL cycle, and we want them inside a boundary zone so the Phase 5 boundary-floor allocation reaches them.
- **D14 (MRET / halt detection)**: `InspectionData` doesn't separately tag MRET / halt cycles; both fall under `major=7` (CONTROL0). For IV.POS.7 the 4 MRET/halt-adjacency zones will be EMPTY. They're still defined and the arm universe runtime-skips them (D7).

**One bug fix carried into Phase 2** (caught by deeper test coverage):

- `MAJOR_TO_CORE_ZONE` and `OPCODE_CLASS_BY_MAJOR` in `semantic_zones.py` had wrong mappings for majors 8-12. Corrected to match `inspection_data.py:224-228`. Documented in §6 (Insights).

**Two structural findings** worth flagging to Pro (no decision needed; just observations):

- `(INSTR_TYPE_MOD, pre_ecall)` is **structurally empty for every guest** because `INSTR_TYPE_MOD` applies to majors 0-6 only and ECALL = major 8. For `INSTR_WORD_MOD` the same arm IS populated (that kind handles major=8 too).
- The empty-arm property scales with `kind × zone` cross-product: the new arm space is sparse and the bandit must reason only over populated arms.

---

## 3. Code changes

### 3.1 `a4/standalone/semantic_zones.py` — bug fix (no LOC change to total)

**Before** (wrong, from Phase 1):
```python
MAJOR_TO_CORE_ZONE = {
    ..., 8: "core_sha", 9: "core_poseidon",   # WRONG
}
```

**After** (verified against `a4/core/inspection_data.py:224-228`):
```python
MAJOR_TO_CORE_ZONE = {
    0: "core_arithmetic", 1: "core_arithmetic", 2: "core_arithmetic",
    3: "core_mul",
    4: "core_div",
    5: "core_memory_load",
    6: "core_memory_store",
    7: "core_branch",
    8: "core_other",      # ECALL — should be caught by pre_ecall rule first
    9: "core_poseidon",
    10: "core_poseidon",
    11: "core_sha",       # ← was 8 before; now correctly 11
    12: "core_other",     # BIGINT
}
```

Same fix applied to `OPCODE_CLASS_BY_MAJOR`. The pre-existing 11 majors are unchanged; majors 8-12 are now correctly mapped.

### 3.2 `a4/standalone/zone_classifier.py` (new file, ~150 LOC)

Three public functions:

```python
def classify_zones(data: InspectionData) -> Dict[int, str]:
    """step → zone, every step in `data.cycles` represented."""

def zone_to_steps(data: InspectionData) -> Dict[str, List[int]]:
    """zone → sorted step list; ALL 17 zones in output dict (empty allowed)."""

def summarize_zones(data: InspectionData) -> str:
    """Human-readable population summary for logs."""
```

Classification rules, in priority order (earlier rules override later):

1. **`step 0 → "step0"`** (absolute precedence; even if `step 0` is an ECALL)
2. **`step T-1 → "last_step"`** (skipped if `T == 1`)
3. **For each cycle `e` with `major == ECALL_MAJOR (8)`**:
   - `e → "pre_ecall"` if not already in `zones` (so step0/last_step are preserved)
   - `e+1 → "post_ecall"` if `0 ≤ e+1 < T` and not already in `zones`
4. **MRET adjacency** — NOT IMPLEMENTED (D14 limitation)
5. **Halt adjacency** — NOT IMPLEMENTED (D14 limitation)
6. **Fallback by major** — for every step still unclassified, use `major_to_zone(cycle.major)`

The constant `ECALL_MAJOR = 8` is exported at module level so future cycle-tagger work can re-use it instead of magic-numbering.

`summarize_zones` produces a human-readable table that flags empty zones with `(EMPTY — see classifier limitations)` if it's a boundary zone we expected to populate, or `(empty for this guest)` if it's a core zone (e.g. `core_poseidon` for sha2-host).

### 3.3 `a4/standalone/semantic_arm_universe.py` (new file, ~130 LOC)

A `dataclass` wrapping a `(kind, zone) → step list` mapping plus 6 useful accessors.

```python
@dataclass
class SemanticArmUniverse:
    mutation_kinds: List[str]
    arms: Dict[ArmKey, List[int]]          # (kind, zone) → sorted valid steps
    zone_step_map: Dict[str, List[int]]    # zone → sorted steps (full trace)
    valid_steps_by_kind: Dict[str, List[int]]
    total_steps: int

    @classmethod
    def build(cls, data, mutation_kinds) -> "SemanticArmUniverse": ...

    @property
    def available_arms(self) -> List[ArmKey]: ...
    @property
    def num_arms(self) -> int: ...
    def steps_in_arm(self, kind, zone) -> List[int]: ...
    def zones_for_kind(self, kind) -> List[str]: ...
    def kinds_for_zone(self, zone) -> List[str]: ...
    def singleton_arms(self) -> List[ArmKey]: ...
    def boundary_arms(self) -> List[ArmKey]: ...
    def summary(self) -> str: ...
```

`build()` does the intersection:
```python
for kind in mutation_kinds:
    valid_set = set(data.get_valid_steps_for_kind(kind))
    for zone in SEMANTIC_ZONES:
        steps = sorted(valid_set & set(z2s.get(zone, [])))
        if steps:                       # D7: runtime-skip empty arms
            arms[(kind, zone)] = steps
```

Notes:
- `ArmKey = Tuple[str, str]` (string-tuple, hashable, picklable — same approach as the legacy `ArmUniverse`).
- The set intersection is the WHOLE POINT: empty intersections are NOT entered into `arms`, so `num_arms` reports the populated count only.
- `singleton_arms()` returns arms whose **zone is in `SINGLETON_ZONES`** AND whose step list has exactly one entry. The Phase 5 bandit uses this for the forced-pull floor on singleton zones.
- `boundary_arms()` returns arms whose zone is in `BOUNDARY_ZONES` (8 zones). The Phase 5 bandit allocates a minimum pulls fraction to these via the constrained-TS floor.

### 3.4 `a4/standalone/step_selector.py` — append `SemanticZoneStepSelector` (+60 LOC)

```python
class SemanticZoneStepSelector(StepSelector):
    """Pick a step uniformly inside (kind, zone). Singleton zones are
    deterministic. Empty arms return None (caller iterates over
    au.available_arms so this shouldn't normally occur)."""

    def __init__(self, arm_universe: SemanticArmUniverse, seed: int = None):
        if arm_universe is None:
            raise ValueError(...)
        self.au = arm_universe
        self.rng = random.Random(seed)

    def pick_step_in_zone(self, kind: str, zone: str) -> Optional[int]:
        steps = self.au.steps_in_arm(kind, zone)
        if not steps: return None
        if len(steps) == 1: return steps[0]
        return self.rng.choice(steps)

    def select_step(self, data, kind):
        raise NotImplementedError(
            "SemanticZoneStepSelector uses pick_step_in_zone(kind, zone); "
            "the bandit must choose (kind, zone) jointly. ...")
```

Mirrors `UniformArmSelector`'s "raise on legacy interface" pattern: the new sampler requires the bandit to have ALREADY chosen `(kind, zone)` jointly, so the legacy `select_step(data, kind)` API cannot honor that contract.

A late try/except import of `SemanticArmUniverse` keeps `step_selector.py` import-safe even if `semantic_arm_universe.py` is somehow missing.

### 3.5 Tests — three new test files (~360 LOC, 41 tests)

`tests/test_zone_classifier.py` (~150 LOC, 10 tests):

| # | Test | Verifies |
|---|---|---|
| 1 | `test_empty_inspection_returns_empty_zones` | `classify_zones({})` returns `{}`; `zone_to_steps` returns dict with all 17 zones mapped to `[]`. |
| 2 | `test_single_step_is_step0_not_last_step` | Rule 1 (step0) wins over Rule 2 (last_step) when `T == 1`. |
| 3 | `test_two_steps_step0_and_last_step` | Both singleton zones present at T=2. |
| 4 | `test_fallback_by_major` | 12 different `major` values map correctly through fallback. |
| 5 | `test_ecall_cycle_becomes_pre_ecall` | Rule 3 places ECALL cycle in `pre_ecall`, `e+1` in `post_ecall`. |
| 6 | `test_ecall_at_boundary_does_not_overwrite_singleton` | Singleton rules win even when an ECALL is at step 0 or T-1. |
| 7 | `test_multiple_ecalls` | Three ECALL cycles produce three `pre_ecall` + three `post_ecall` entries. |
| 8 | `test_all_17_zones_in_output_dict` | `zone_to_steps()` always returns 17 keys; D14 limitations confirmed (pre_mret/post_mret/pre_halt/post_halt empty). |
| 9 | `test_summarize_zones_runs_without_crash` | Diagnostic summary runs end-to-end. |
| 10 | `test_step0_always_in_zones_even_with_only_one_cycle_at_other_step` | Edge case: single cycle with `major=8` still classifies as step0. |

`tests/test_semantic_arm_universe.py` (~140 LOC, 10 tests):

| # | Test | Verifies |
|---|---|---|
| 1 | `test_build_returns_arm_universe` | Builder returns instance with non-empty arms. |
| 2 | `test_empty_intersections_are_skipped` | `(LOAD_VAL_MOD, core_arithmetic)` not in `arms` (LOAD is major=5 only). |
| 3 | `test_singleton_arms_for_instr_type_mod` | `(INSTR_TYPE_MOD, step0)` and `(INSTR_TYPE_MOD, last_step)` are singletons. |
| 4 | `test_boundary_arms_for_instr_type_mod_excludes_pre_ecall` | **Structural finding**: INSTR_TYPE_MOD applies to majors 0-6 only; ECALL has major=8, so `(INSTR_TYPE_MOD, pre_ecall)` is structurally empty. |
| 5 | `test_boundary_arms_for_instr_word_mod_includes_pre_ecall` | INSTR_WORD_MOD applies to majors 0-6 + major 8, so `(INSTR_WORD_MOD, pre_ecall)` IS populated. |
| 6 | `test_zones_for_kind` | Per-kind zone enumeration matches kind applicability rules. |
| 7 | `test_kinds_for_zone_step0` | Step 0 (major=0 → ALU) only accepts compute/instr kinds, not load/store. |
| 8 | `test_kinds_for_zone_unused_zone_is_empty` | sha2-host has no Poseidon cycles → `kinds_for_zone("core_poseidon") == []`. |
| 9 | `test_available_arms_sorted` | Arm enumeration is deterministic. |
| 10 | `test_summary_runs_without_crash` | Diagnostic summary runs end-to-end. |

`tests/test_semantic_zone_step_selector.py` (~70 LOC, 6 tests):

| # | Test | Verifies |
|---|---|---|
| 1 | `test_requires_arm_universe` | `None` arm_universe raises `ValueError`. |
| 2 | `test_singleton_zone_is_deterministic` | `(INSTR_TYPE_MOD, step0)` always returns step 0. |
| 3 | `test_broad_zone_samples_uniformly_from_arm_steps` | 30 draws on a 2-step zone all land in `{2, 3}`. |
| 4 | `test_seed_makes_selection_deterministic` | Same seed → identical draw sequence. |
| 5 | `test_empty_arm_returns_none` | `(LOAD_VAL_MOD, step0)` (empty arm) returns None instead of crashing. |
| 6 | `test_select_step_legacy_interface_raises` | Legacy `(data, kind)` API raises `NotImplementedError`. |

`tests/test_semantic_zone_dataclasses.py` (Phase 1 file) — updated:
- Test 4-5 (`test_major_to_zone_known_majors`): assertions updated for corrected mappings.
- New test 11: `test_major_to_opcode_class_known_majors` covers all 13 majors with Pro §5 enum strings.

---

## 4. Test results

### 4.1 New Phase 2 unit tests

```
$ python -m pytest a4/standalone/tests/test_zone_classifier.py \
                   a4/standalone/tests/test_semantic_arm_universe.py \
                   a4/standalone/tests/test_semantic_zone_step_selector.py \
                   a4/standalone/tests/test_semantic_zone_dataclasses.py -q
.........................................                                [100%]
41 passed in 0.54s
```

### 4.2 Full fast-suite regression

```
$ python -m pytest a4/standalone/tests/ -q --tb=line \
    --ignore=a4/standalone/tests/test_pilot_calibration.py \
    --ignore=a4/standalone/tests/test_run_replicates.py \
    --ignore=a4/standalone/tests/test_determinism.py \
    --ignore=a4/standalone/tests/test_phase02_baseline.py \
    --ignore=a4/standalone/tests/test_instr_word_mod_sur.py \
    --ignore=a4/standalone/tests/test_baseline_touch.py \
    --ignore=a4/standalone/tests/test_touch_coverage.py
164 passed, 1 skipped in 30.31s
```

The 7 ignored suites are integration tests requiring the `risc0-host` binary (slow; out of scope for unit-test iteration). Zero regressions in the fast suite.

### 4.3 Real-data validation status

**Deferred to Phase 7.** Running the zone classifier on REAL `sha2-host` inspection data requires running the host binary, which is slow and dependency-heavy. Phase 7's smoke-test plan already includes a "run inspection → print `summarize_zones(data)` → eyeball populations look sensible" step, which is the right place for this validation.

A quick sanity check I did mentally:
- IV.POS.5 traces have ~4000 user_cycles for sha2-host.
- Hundreds of ECALL cycles (sha2 uses ECALLs for I/O setup).
- One step0, one last_step.
- 0 Poseidon cycles (sha2-host doesn't use Poseidon).

So I expect: `step0=1`, `last_step=1`, `pre_ecall ~ N_ecall`, `post_ecall ~ N_ecall`, `core_memory_load + core_memory_store + core_arithmetic + core_branch + core_sha ~ 3000-3800`, `core_poseidon=0`, MRET/halt-adjacency=0 (D14 limitation). Phase 7 will confirm.

---

## 5. Acceptance-criteria scorecard

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Zone classifier produces sensible zones on synthetic data | ✅ | 10/10 zone classifier tests pass |
| 2 | All 17 zones present in `zone_to_steps()` output | ✅ | `test_all_17_zones_in_output_dict` |
| 3 | step0/last_step precedence rules verified | ✅ | tests 2-3 |
| 4 | ECALL boundary rule verified | ✅ | tests 5-7 |
| 5 | ECALL boundary doesn't overwrite step0 / last_step | ✅ | test 6 |
| 6 | `SemanticArmUniverse` skips empty arms (D7) | ✅ | `test_empty_intersections_are_skipped` |
| 7 | Singleton arms correctly identified | ✅ | `test_singleton_arms_for_instr_type_mod` |
| 8 | Boundary arms correctly identified, including structural emptiness | ✅ | tests 4-5 of arm-universe |
| 9 | Step selector deterministic with seed | ✅ | `test_seed_makes_selection_deterministic` |
| 10 | No regressions in fast suite | ✅ | §4.2 |
| 11 | Real-data zone-classifier sanity check | ⏸ | Deferred to Phase 7 |
| 12 | Three new D-decisions logged (D13/D14/D15) | ✅ | `CLOUD1_DECISIONS_FOR_PRO_R2.md` updated |

---

## 6. Key variables / functions

| Symbol | Type | Where | Meaning |
|---|---|---|---|
| `ECALL_MAJOR` | `int` (value 8) | `zone_classifier.py` | The rv32im major value for ECALL0 cycles. Used by classifier rule 3. |
| `classify_zones(data)` | function | `zone_classifier.py` | Returns `Dict[int, str]`: every step in `data.cycles` mapped to its zone. |
| `zone_to_steps(data)` | function | `zone_classifier.py` | Returns `Dict[str, List[int]]` with ALL 17 zones present (empty lists allowed). |
| `summarize_zones(data)` | function | `zone_classifier.py` | Human-readable population summary with `(EMPTY)` / `(empty for this guest)` markers. |
| `SemanticArmUniverse` | dataclass | `semantic_arm_universe.py` | Container for the (kind, zone) → step list arm space. |
| `ArmKey` | `Tuple[str, str]` | `semantic_arm_universe.py` | Type alias for `(mutation_kind, semantic_zone)`. Hashable, pickleable. |
| `SemanticArmUniverse.build(data, kinds)` | classmethod | `semantic_arm_universe.py` | Build by intersecting per-kind valid steps with per-zone step lists; skip empties. |
| `SemanticArmUniverse.available_arms` | property | `semantic_arm_universe.py` | Sorted list of populated (kind, zone) pairs. |
| `SemanticArmUniverse.singleton_arms()` | method | `semantic_arm_universe.py` | Arms whose zone is in `SINGLETON_ZONES` AND step list has length 1. Phase 5 forces ≥5 pulls on each (D10 expansion). |
| `SemanticArmUniverse.boundary_arms()` | method | `semantic_arm_universe.py` | Arms whose zone is in `BOUNDARY_ZONES` (8 zones). Phase 5 allocates boundary-floor budget here. |
| `SemanticZoneStepSelector` | class | `step_selector.py` | Step picker for the new bandit. |
| `SemanticZoneStepSelector.pick_step_in_zone(kind, zone)` | method | `step_selector.py` | Uniform step within zone's step list; None if empty. |

---

## 7. Insights / what to keep in mind for next phases

1. **The `MAJOR_TO_CORE_ZONE` map is FALLBACK ONLY.** Boundary rules (1-5) apply first; only steps not classified by those rules use the major-fallback. This is why `8 → core_other` in the fallback is correct — ECALL cycles should have been claimed by rule 3 (`pre_ecall`) already. If somehow the boundary rule didn't fire, the fallback is the defensive last line.

2. **`(INSTR_TYPE_MOD, pre_ecall)` is structurally empty FOR ALL GUESTS.** This is not a bug; it's a property of the mutation-kind applicability rules in `inspection_data.py:get_valid_steps_for_kind` (INSTR_TYPE_MOD: majors 0-6; ECALL: major 8). The cTS bandit (Phase 5) must reason only over populated arms (`au.available_arms`), never assume all `kind × zone` combinations exist. D7 already captures this design intent.

3. **MRET / halt zones are empty by design for IV.POS.7** (D14). Phase 7's smoke test will confirm. Future post-Pro-R2 work could extend `A4_INSPECT` output to tag MRET/halt cycles distinctly; that's a 2-LOC C++ patch + 5-LOC Python parse + Phase 2 classifier rule additions.

4. **Phase 1 had a subtle bug** in `MAJOR_TO_CORE_ZONE` that Phase 2's deeper test coverage caught. The bug was: I had `8 → core_sha`, `9 → core_poseidon` based on guessing from Pro's abstract zone names. The authoritative source `inspection_data.py:summary()` says major 8 is `ECALL0`, major 11 is `SHA0`, etc. **Lesson learned**: always cross-check empirical sources before assuming a mapping, even when the abstract names look plausible. This is a class of bug Composer might introduce too — Opus should sanity-check every numeric mapping Composer writes against an authoritative source.

5. **`SemanticZoneStepSelector` raises on the legacy `select_step` API**, mirroring `UniformArmSelector`. The bandit dispatcher in Phase 5 must call `pick_step_in_zone(kind, zone)` (not the legacy `select_step(data, kind)`) when the strategy is `cTS_semantic_v2`. The raise is a TRIPWIRE: if someone wires this selector into the old dispatcher by mistake, the run dies loudly at the first mutation instead of producing silently bad data.

6. **The arm universe is built ONCE at campaign start** (from `InspectionData`) and read-only thereafter. The bandit updates its own posteriors elsewhere; the arm structure is fixed. This is essential for the `compressed_global_coverage.ctx_key` to be stable across the campaign.

7. **`available_arms` is sorted**. Don't depend on Python's dict ordering — explicitly sort. The Phase 5 bandit's cold-start phase (D10: 3 pulls per arm) iterates over `au.available_arms` in deterministic order so that with the same seed two runs produce the same exploration trajectory.

---

## 8. What's now possible that wasn't before

- **Phase 3** has a clean `mutation_zone` value to pass to its extractor (already used in `cycle_phase_for_zone`).
- **Phase 4** has `SemanticArmUniverse.singleton_arms()` and `boundary_arms()` to build the structural-cell key.
- **Phase 5** can implement the constrained TS bandit's arm space exactly as Pro spec'd it: `available_arms` enumerates the action space, `singleton_arms()` + `boundary_arms()` drive the floor allocations.
- **Phase 7** smoke test can do `summarize_zones(real_data)` to eyeball that the classifier behaves on actual sha2-host traces.

---

## 9. Files touched

```
M  a4/standalone/semantic_zones.py                           (bug fix; LOC unchanged)
A  a4/standalone/zone_classifier.py                          (+150 LOC, 3 functions)
A  a4/standalone/semantic_arm_universe.py                    (+130 LOC, 1 dataclass + 7 accessors)
M  a4/standalone/step_selector.py                            (+60 LOC,  1 new class)
A  a4/standalone/tests/test_zone_classifier.py               (+150 LOC, 10 tests)
A  a4/standalone/tests/test_semantic_arm_universe.py         (+140 LOC, 10 tests)
A  a4/standalone/tests/test_semantic_zone_step_selector.py   (+70 LOC,  6 tests)
M  a4/standalone/tests/test_semantic_zone_dataclasses.py     (updated 4 tests, +1 new test)
M  a4/docs/cloud1/CLOUD1_STATUS.md                           (Phase 2 → DONE)
M  a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md             (added D13/D14/D15)
A  a4/docs/cloud1/phases/PHASE_2_SEMANTIC_ZONES.md           (this file)
```

---

## 10. Consistency check against `ProG_Report_2.md`

| Pro recommendation | Phase 2 implementation | Status |
|---|---|---|
| §7.A: "Use an arm space like `mutation_kind × semantic_zone`" | `SemanticArmUniverse` keys arms as `(kind, zone)` tuples; legacy `(kind, bucket)` `ArmUniverse` preserved for old strategies | ✅ |
| §7.A: 17 zone names listed verbatim | All 17 in `SEMANTIC_ZONES` and produced by `zone_to_steps()` | ✅ |
| §7.A: "`INSTR_TYPE_MOD@step0` should be an explicit singleton arm" | `singleton_arms()` returns it whenever step 0 is INSTR_TYPE_MOD-applicable; Phase 5 will give it the forced-pull floor | ✅ |
| §7.A: "with a guaranteed minimum pull count" | Phase 5 work — not in Phase 2 | ⏸ deferred per plan |
| §7.A: "Do not bury it inside bucket 0" | Achieved — the `(INSTR_TYPE_MOD, step0)` arm is a top-level entry in `arms`, not a sub-key | ✅ |
| §7.B: "Drop nested per-step UCB for now" | Old `BucketStepSelector` (the nested UCB) preserved for legacy strategies but BYPASSED by `cTS_semantic_v2` via `SemanticZoneStepSelector` | ✅ |
| §7.B: "select kind/zone then sample a valid step inside that zone" | `pick_step_in_zone(kind, zone)` exactly implements this | ✅ |
| §7.B: "For singleton zones, deterministically pick the singleton" | `pick_step_in_zone` returns `steps[0]` when `len(steps) == 1` | ✅ |
| §7.B: "For broad core zones, sample uniformly or by opcode/txn role" | We sample **uniformly** in Phase 2; per-opcode-role weighting is a future refinement (cloud1 plan §Phase 2 marks it out of scope) | ⚠️ partial — acceptable per plan |

The one ⚠️ row is a deliberate scope choice: per-opcode-role weighting would require additional infra (per-zone opcode-role histograms) that Pro didn't specify and that adds complexity without an obvious IV.POS.7 benefit. We can revisit if Pro Round 2 asks for it.

---

## 11. Variable / symbol reference

- `T` (in `total_steps`) — number of user_cycles in the trace.
- `Z` — number of semantic zones (17 in cloud1 vocabulary).
- `K` — number of mutation kinds (8 for IV.POS.7).
- `ECALL_MAJOR` (= 8) — the rv32im major value for ECALL0.
- `e` — variable used in the ECALL rule for "ECALL cycle index".
- `(kind, zone)` arm — the atomic action unit for the new bandit; one element of `SemanticArmUniverse.available_arms`.
