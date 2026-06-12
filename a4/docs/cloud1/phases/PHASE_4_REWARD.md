# Phase 4 — Reward Redesign

**Status**: ✅ DONE (2026-06-08)
**Implementer**: Composer 2.5
**Reviewer**: Opus 4.7 (skeptical-review protocol)
**Pro reference**: `ProG_Report_2.md` §6.1, §8, §12
**Tests**: 38 Composer + 34 Opus adversarial = **72 reward_v2 tests**; fast suite **308 passed, 1 skipped** (was 236 after Phase 3).
**Files touched**: `a4/standalone/reward_v2.py` (new, 234 LOC), `a4/standalone/tests/test_reward_v2.py` (new, 344 LOC), `a4/standalone/tests/test_reward_v2_adversarial.py` (new, ~250 LOC), `a4/docs/cloud1/composer/{PROPOSED_DECISIONS,PHASE_4_COMPOSER_SUMMARY}.md` (new).

> This is Phase 4's **post-completion retrospective** (Opus-owned). The Composer-facing plan that drove the implementation is preserved in git history at `phases/PHASE_4_REWARD.md@phase-3-handoff`; the version you're reading replaces it AFTER Composer's work was reviewed and approved.

---

## TL;DR (what was done; how it fits cloud1)

Composer implemented the Pro §8 additive reward as pure functions in `reward_v2.py`. The new reward has six components:

```text
reward_v2 = 1.00·sat(L_new, 1) + 0.30·sat(F_new, 1) + 0.25·sat(G_new, 3)
          + 0.15·sat(S_new, 2) − 0.50·crash − 0.05·sat(repeat, 5)
```

with `sat(x, tau) = 1 − exp(−x/τ)` (saturating; bounded). Each `*_new` is a marginal-discovery count (new local context / family / compressed global / structural cell). `crash` is binary; `repeat` counts retread of already-seen local contexts.

A second function `compute_bandit_success(l_new, g_new, s_new) → {0,1}` is the Bernoulli signal Phase 5's Thompson sampler will consume (note `f_new` and `repeat` are deliberately NOT in this).

A third function `compute_counterfactuals(components, legacy_diag) → 5 values` produces the per-mutation rows for `reward_counterfactuals` (Phase 1 SQLite table) so Phase 9 can compare 5 reward variants without re-running campaigns.

The component extractor `compute_reward_v2_components(exec_result, seen_*, kind, zone, major)` is a PURE function (no DB access; takes pre-loaded sets, mutates them in place). Phase 6 will hydrate the seen-sets from the DB once per run and pass them in.

**How it fits**: Phase 1 (schema) gave us the tables → Phase 2 (zones) gave us `mutation_zone` for the S_new key → Phase 3 (compressed-ctx) gave us the `g_new` source → Phase 4 (this) wires reward math on top → Phase 5 will plug TS on top → Phase 6 will wire fuzzer loop → Phase 7 smoke-tests on POS → Phase 8 IV.POS.7 campaign → Phase 9 Pro Round 2.

---

## 1. Goal recap

(From the Composer-facing plan, lightly summarized.)

Deliver 4 pure functions and ≥20 unit tests, with NO fuzzer-loop wiring and NO modification of legacy `compute_reward`. Lock 4 likely D-decisions (D-A family parse, D-B repeat definition, D-C set semantics for l_new, D-D no_qloc formula) explicitly in `composer/PROPOSED_DECISIONS.md` before coding around them.

---

## 2. Deviations from the original plan

| # | Original plan | What happened | Severity |
|---|---|---|---|
| ① | "Replay validation script on IV.POS.5 DB" was marked optional | Skipped — no `iv_pos_5/*.db` files in this workspace clone | low (replay is sanity-only; unit tests cover correctness) |
| ② | `f_new` was expected to take a dedicated `seen_families` set | Composer derives families inline from `seen_local_v2` each call | low (correctness identical; minor O(\|seen_local\|) cost per call — flagged for Phase 6 to add a dedicated set if hydration overhead matters) |
| ③ | Plan listed Pro §8 `repeat = …` ambiguously | Pro §8 wording "already-seen local contexts hit again" is actually unambiguous (campaign-level) — Composer correctly used Pro §8 over the plan's option (a) | none (plan was wrong; Composer was right; doc fixed via D21) |
| ④ | 4 D-decisions pre-flagged | Composer filed exactly 4 (D-A..D-D), each with rationale and a "Risk if wrong" reversal-cost | none |

All deviations documented in Composer's `PHASE_4_COMPOSER_SUMMARY.md` §4 and §5.

---

## 3. Code changes (with snippets)

### 3.1 `a4/standalone/reward_v2.py` (new file, 234 LOC)

Pure-function reward layer. Composes with Phase 3's extractor for `g_new` and Phase 1's `StructuralCell` for `s_new`.

```python
# Pro §8 verbatim
def compute_reward_v2(l_new, f_new, g_new, s_new, crash, repeat) -> float:
    return (
        1.00 * sat(float(l_new), 1.0)
      + 0.30 * sat(float(f_new), 1.0)
      + 0.25 * sat(float(g_new), 3.0)
      + 0.15 * sat(float(s_new), 2.0)
      - 0.50 * (1.0 if crash else 0.0)
      - 0.05 * sat(float(repeat), 5.0)
    )

def compute_bandit_success(l_new, g_new, s_new) -> int:
    return 1 if (l_new + g_new + s_new) > 0 else 0
```

`sat(x, tau)` handles the `tau=0` edge case by returning `0.0` (instead of `ZeroDivisionError`), which is the right defensive default since `tau=0` means "always saturated".

The component extractor:

```python
def compute_reward_v2_components(
    exec_result, seen_local_v2, seen_compressed_global, seen_structural,
    mutation_kind, mutation_zone, mutation_major,
) -> RewardComponents:
    crash = _is_crash_or_missing_telemetry(exec_result)
    local_contexts = _failure_local_contexts(exec_result)   # SET of (loc, major, minor)

    l_new  = sum(1 for ctx in local_contexts if ctx not in seen_local_v2)
    repeat = sum(1 for ctx in local_contexts if ctx in     seen_local_v2)

    seen_families = {extract_constraint_family(loc) for loc, _, _ in seen_local_v2}
    run_families  = {extract_constraint_family(loc) for loc, _, _ in local_contexts}
    f_new = sum(1 for fam in run_families if fam not in seen_families)

    compressed_ctxs = extract_compressed_global_contexts(
        exec_result.family_residues, exec_result.family_details,
        mutation_kind, mutation_zone, mutation_major,
    )
    g_new = sum(1 for ctx in compressed_ctxs
                if ctx.to_json_str() not in seen_compressed_global)

    cell  = _build_structural_cell(mutation_kind, mutation_zone, mutation_major, exec_result)
    s_new = 0 if cell in seen_structural else 1

    # Side effects: only AFTER all _new counts are computed
    seen_local_v2.update(local_contexts)
    for ctx in compressed_ctxs:
        seen_compressed_global.add(ctx.to_json_str())
    seen_structural.add(cell)

    return {"l_new": l_new, "f_new": f_new, "g_new": g_new,
            "s_new": s_new, "crash": crash, "repeat": repeat}
```

Side-effect ordering is correct: all `*_new` counts use the PRE-RUN state of the seen-sets; updates happen at the end. Phase 6 can rely on this when batching multiple runs.

The counterfactual function:

```python
def compute_counterfactuals(components, legacy_reward_diag) -> CounterfactualRewards:
    return {
        "current_reward":           compute_reward_v2(*components_as_args),
        "no_qloc_reward":           _compute_no_qloc_reward(legacy_reward_diag),
        "fnew_only_reward":         0.30 * sat(float(f_new), 1.0),
        "discovery_binary_reward":  compute_bandit_success(l_new, g_new, s_new),
        "compressed_global_reward": 0.25 * sat(float(g_new), 3.0),
    }
```

D-A family-parse regex:

```python
_FAMILY_AT_ZIR_RE = re.compile(r"@([^@]+?)\.zir")

def extract_constraint_family(constraint_loc: str) -> str:
    if not constraint_loc: return "unknown"
    m = _FAMILY_AT_ZIR_RE.search(constraint_loc)
    if m: return m.group(1)
    if "@" in constraint_loc: return constraint_loc.split("@", 1)[0]
    return constraint_loc.strip()
```

### 3.2 `a4/standalone/tests/test_reward_v2.py` (Composer, 344 LOC, 38 tests)

Six test classes mirroring the §2.4 plan: `TestSat`, `TestComputeRewardV2`, `TestComputeBanditSuccess`, `TestExtractConstraintFamily`, `TestComputeRewardV2Components`, `TestComputeCounterfactuals`, `TestMisc`. All synthetic; no host binary.

### 3.3 `a4/standalone/tests/test_reward_v2_adversarial.py` (Opus, ~250 LOC, 34 tests)

Written during review to stress the three areas Composer asked us to interrogate. Coverage:

| Area | Tests | Hardest input survived |
|---|---|---|
| Malformed family parse | 10 | `X@.zir:1`, `Outer@Inner@inst.zir:1`, `X@a.zir.zir:1`, unicode `bär.zir`, hex-as-filename `0x80001000.zir`, `inst_ecall` multi-underscore |
| `repeat` on zero-failure runs | 5 | 1000-entry history + empty failures → still `repeat=0`; 5 dup failures of same context with that context already in history → `repeat=1` (set semantics) |
| Counterfactual consistency | 7 (parametrized over 10 component combos) | `current_reward == compute_reward_v2(*components)` exact match; `no_qloc` clamp at 1.0; counterfactuals independent of unrelated components |
| Stateful invariants | 3 | Side-effect ordering; no double-count; monotonic set growth |

---

## 4. Test results

Composer's suite:
```
$ python -m pytest a4/standalone/tests/test_reward_v2.py -v
38 passed in 0.24s
```

Opus's adversarial suite:
```
$ python -m pytest a4/standalone/tests/test_reward_v2_adversarial.py -v
34 passed in 0.20s
```

Full fast suite (post-Phase-4):
```
$ pft
308 passed, 1 skipped in 30.34s
```

Baseline at end of Phase 3 was 236 passed. New tests: 38 (Composer) + 34 (Opus). 236 + 38 + 34 = 308. **No regressions.**

---

## 5. Acceptance criteria scorecard

| # | Plan exit criterion | Outcome |
|---|---|---|
| 1 | `reward_v2.py` exports 5 public functions | ✅ `sat`, `compute_reward_v2`, `compute_bandit_success`, `extract_constraint_family`, `make_local_v2_ctx_key`, `compute_reward_v2_components`, `compute_counterfactuals` (also exported, 7 total) |
| 2 | All ≥20 unit tests pass | ✅ 38 pass (Composer) + 34 pass (Opus adversarial) |
| 3 | Full fast suite still passes | ✅ 308 passed, 1 skipped |
| 4 | No `fuzzer.py` edits | ✅ `git diff a4/standalone/fuzzer.py` shows only pre-existing Phase 0 `STRATEGY_DISPLAY_NAMES` change (not introduced by Phase 4) |
| 5 | No `coverage_state.py` edits | ✅ `git diff a4/standalone/coverage_state.py` empty |
| 6 | `composer/PHASE_4_COMPOSER_SUMMARY.md` written from template | ✅ all 7 sections filled |
| 7 | D-A..D-D filed in `composer/PROPOSED_DECISIONS.md` | ✅ all 4 with rationale + reversal cost |
| 8 | Coefficients and taus verbatim from Pro §8 | ✅ verified by inspection |

---

## 6. Opus's skeptical review — what I would have done independently

I sketched the design BEFORE reading Composer's code (per the protocol in `CLOUD1_AGENT_ONBOARDING.md`). Side-by-side:

| Aspect | What I would have done | What Composer did | Verdict |
|---|---|---|---|
| `sat` with `tau ≤ 0` | Raise `ValueError` | Return `0.0` (saturated) | ✅ **Composer's defensive default is better** — `tau=0` shouldn't crash a run |
| Family-parse regex | `r"@(.+?)\.zir"` (anything non-greedy) | `r"@([^@]+?)\.zir"` (anything-non-@ non-greedy) | ✅ **Composer's is more correct** — excludes nested `@` from family name |
| `seen_families` storage | Separate `Set[str]` arg passed in | Derived from `seen_local_v2` each call | ⚠️ Functionally identical; Composer's is O(\|seen_local\|) per call. Acceptable for ≤6000 mutations/campaign; Phase 6 can add the dedicated set if hydration overhead matters. Documented as Phase 4 deviation ②. |
| `repeat` definition | Considered both within-run (option a) and campaign retread (option b); deferred to Pro §8 | Went straight to Pro §8 literal | ✅ **Composer was right to read Pro §8 literally**; my plan-doc option (a) was a hedge that Pro's wording obviates |
| `mode` in StructuralCell | Took from `config.get("mode")` default `"user"` | Same | ✅ Matches my Phase 1 schema docstring (`mode = "user" \| "machine"` = privilege mode, not execution outcome) |
| Side-effect ordering | Compute all `*_new` first, then update sets | Same | ✅ |
| Crash detection | `_is_crash(exit_code)` OR `touch_bitmap is None` | Same (`_is_crash_or_missing_telemetry`) | ✅ Matches legacy gating |
| `no_qloc_reward` for `mode=normal` | `min(1, Q_rep * Q_glob * S)` | Same | ✅ |
| Counterfactual table cardinality | 5 values per Pro §12 | 5 values | ✅ |

**Net assessment**: Composer's implementation is correct, conservative, and in two places (`sat` defensive default; family regex excluding nested `@`) BETTER than what I would have written. No bugs found; no required rewrites.

---

## 7. Insights (what we learned / what's now possible)

1. **Pro §8 is more prescriptive than the Phase 4 plan recognized.** The plan's `repeat` "option (a) is safest" hedge was unnecessary; Pro §8 says exactly what to do. Lesson for future plans: re-read Pro before listing "safest default" options.
2. **Set semantics are the right default for both `l_new` and `repeat`.** Anywhere Pro uses "context" as a noun, it means a tuple-key, not an occurrence count. This is consistent across Pro §6.1, §7, §8.
3. **The new reward decouples reward-magnitude from failure-cascade-density.** Under the old multiplicative formula, INSTR_TYPE_MOD's "30 MemLoadInput failures = 30× the Q_loc penalty" was the central pathology. Under v2: 30 failures of the same context contribute `l_new = 1, repeat = 29`, so reward is `1.00·sat(1) − 0.05·sat(29, 5) ≈ 0.632 − 0.05·1.0 ≈ 0.58` (positive, dominated by discovery). 30 failures of 30 DIFFERENT contexts: `l_new = 30, repeat = 0` → `1.00·sat(30) − 0 ≈ 1.0` (saturated). Bandit will preferentially seek high-diversity arms. This is exactly Pro §6's intent.
4. **Counterfactual ablation cost is ~0.** Composer's `compute_counterfactuals(components, legacy_diag)` is O(1) per mutation; Phase 6 can populate `reward_counterfactuals` for every mutation in IV.POS.7 (50 DBs × 6000 = 300K rows) at negligible cost.
5. **Family parser handles ALL `short_loc` patterns Composer & Opus could construct.** Pattern 1 (`callsite(Name(path/file.zir:line:col))`) and Pattern 2 (`Name(zirgen/.../file.zir:line)`) both produce `Name@file.zir:line` after `short_loc()`, then the regex extracts `file`. Edge cases (empty filename, double @, double .zir, unicode, hex addresses) all degrade gracefully.

---

## 8. What's now possible

- **Phase 5** can implement the constrained-TS scheduler reading `compute_bandit_success` as its Bernoulli signal — no further reward work needed.
- **Phase 6** can wire the fuzzer to call `compute_reward_v2_components()` per mutation, persist components to `mutations` (Phase 1 columns), then call `compute_counterfactuals()` and write to `reward_counterfactuals`. The pure-function discipline means Phase 6 is plumbing, not logic.
- **Replay analysis** in Phase 9 can re-derive v2 reward over historical IV.POS.5 DBs by hydrating `seen_*` sets from `coverage`/`global_failures` tables; Composer's optional replay script can become a Phase 9 deliverable.

---

## 9. Files touched (git-style)

```
A  a4/standalone/reward_v2.py                            +234
A  a4/standalone/tests/test_reward_v2.py                 +344
A  a4/standalone/tests/test_reward_v2_adversarial.py     +250  (Opus)
A  a4/docs/cloud1/composer/PROPOSED_DECISIONS.md         +120  (Composer)
A  a4/docs/cloud1/composer/PHASE_4_COMPOSER_SUMMARY.md   +89   (Composer)
M  a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md         +8 D-decisions (D20-D27), +4 open Qs (G1-G4)
M  a4/docs/cloud1/CLOUD1_STATUS.md                       Phase 4 done
M  a4/docs/cloud1/phases/PHASE_4_REWARD.md               this retrospective replaces the Composer-facing plan
```

Plus Opus updates to `CLOUD1_STATUS.md` and this file. No changes to `fuzzer.py`, `coverage_state.py`, `coverage_db.py`.

---

## 10. Consistency check against ProG_Report_2.md

| Pro §reference | Pro spec | Our implementation | Match? |
|---|---|---|---|
| §6.1 components | `L_new, F_new, G_new, S_new` defined as counts of new entities | All four as `int` counts; set semantics enforced | ✅ |
| §8 coefficients | `1.00, 0.30, 0.25, 0.15, −0.50, −0.05` | Verbatim | ✅ |
| §8 taus | `(1, 1, 3, 2, _, 5)` (crash has no tau) | Verbatim | ✅ |
| §8 sat function | `sat(x, τ) = 1 − exp(−x/τ)` | Same; with τ≤0 defensive 0.0 (Pro-silent) | ✅ |
| §8 Bernoulli success | `1 if L_new + G_new + S_new > 0 else 0` (f_new NOT in this) | Verbatim | ✅ |
| §8 repeat | "number of already-seen local contexts hit again" | Campaign-level retread; set semantics (D21) | ✅ |
| §6.1 family examples | `inst_mem, inst_mul, inst_div, inst_control, mem, u32, one_hot` | Regex extracts these from `@…\.zir` (D20) | ✅ |
| §6.3 structural cell | `mutation_kind × semantic_zone × opcode_class × mode × txn_role` | Plus optional `sub_strategy` (Phase 1) | ✅ (+sub_strategy ⊇ Pro) |
| §12 counterfactuals | 5 reward variants per mutation | All 5 returned by `compute_counterfactuals` | ✅ |
| §12 `no_qloc_reward` | Named, formula not given | Force `Q_loc=1.0` in legacy `min(1, Q*S)` (D23) | ✅ (with D23 documented) |

---

## 11. Symbol reference

| Symbol | Defined in | Type | Meaning |
|---|---|---|---|
| `sat(x, τ)` | `reward_v2.py:34` | `(float, float) → float` | Pro §8 saturating transform |
| `compute_reward_v2(l, f, g, s, crash, repeat)` | `reward_v2.py:41` | `→ float` | Pro §8 reward |
| `compute_bandit_success(l, g, s)` | `reward_v2.py:60` | `→ int ∈ {0,1}` | TS Bernoulli signal |
| `extract_constraint_family(loc)` | `reward_v2.py:65` | `str → str` | D20 regex parse |
| `make_local_v2_ctx_key(loc, major, minor)` | `reward_v2.py:81` | `→ str` | matches `local_coverage_v2.ctx_key` |
| `compute_reward_v2_components(...)` | `reward_v2.py:133` | `→ RewardComponents` | extracts L/F/G/S/crash/repeat from exec_result |
| `compute_counterfactuals(comp, legacy_diag)` | `reward_v2.py:205` | `→ CounterfactualRewards` | 5 reward variants per Pro §12 |
| `RewardComponents` | `reward_v2.py:27` | `Dict[str, Union[int, bool]]` | output shape of component extractor |
| `CounterfactualRewards` | `reward_v2.py:28` | `Dict[str, Union[int, float]]` | output shape of counterfactual function |
| `StructuralCell` | `structural_cells.py:32` | frozen dataclass | Phase 1; used as `seen_structural` key |
| `_is_crash_or_missing_telemetry` | `reward_v2.py:105` | helper | combines legacy `_is_crash` + `touch_bitmap is None` |

---

## 12. Risks tracked forward

| Risk | Mitigation / next phase |
|---|---|
| `f_new` recomputation cost O(\|seen_local\|) per call | Phase 6 can add dedicated `seen_families: Set[str]` and pass alongside `seen_local_v2`. ~6000 mutations × ~300 contexts = 1.8M string parses per campaign in worst case = still <1s. Not blocking. |
| `mode` always `"user"` in practice | `config` doesn't carry kernel-mode flag yet; Phase 6 can inject `mode` from cycle's privilege state once `InspectionData` exposes it. Until then `S_new` cell space is half its full size. |
| Family parse on long-form `loc` (no `@`) | Fallback returns the FULL stripped string; `f_new` would over-count if some failures arrive in long form and others in short form (different keys for same family). Phase 6 must ensure all failures use `f.constraint_loc()` (short form) before passing to extractor. |
| Geometric residue in `g_new` (see D25 / G1) | Flagged to Pro for Round 2; possible relaxation post-IV.POS.7 |

---

## 13. What Opus changed in OWN markdown after Composer finished

- `CLOUD1_DECISIONS_FOR_PRO_R2.md`: added D20–D27 with detailed justifications; added "Open questions for Pro Round 2" section (G1–G4); updated the trailing "If you wish to change…" reference list.
- `CLOUD1_STATUS.md`: marked Phase 4 done; decision-count 19 → 27; active-risk row about Composer quality narrowed to "Phase 4 success — pattern confirmed for Phase 5".
- `phases/PHASE_4_REWARD.md`: this file replaces the Composer-facing plan (preserved in git history).
- `composer/*`: unchanged (Composer-owned per `composer/README.md` rules).
