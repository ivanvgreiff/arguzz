# Phase 6 — Extended Logging

**Status**: ✅ DONE (2026-06-08)
**Implementer**: Composer 2.5
**Reviewer**: Opus 4.7 (skeptical-review protocol)
**Pro reference**: `ProG_Report_2.md` §6.1 (value_class), §12 (tables, bandit_decisions, arm_state_snapshot, hook3_raw, reward_counterfactuals, mutation_substrategy)
**Tests**: 13 Composer + 29 Opus adversarial = **42 telemetry_v2 tests**; fast suite **382 passed, 1 skipped** (was 340 after Phase 5).
**Files touched**: `a4/standalone/telemetry_v2.py` (new, 262 LOC), `a4/standalone/tests/test_telemetry_v2.py` (new, 174 LOC), `a4/standalone/tests/test_telemetry_v2_adversarial.py` (new, ~330 LOC), `a4/standalone/fuzzer.py` (+~100 LOC: telemetry_level field, `_init_full_telemetry_state`, `_record_full_telemetry`, path wiring in all 3 mutation paths), `a4/standalone/cli.py` (+11 LOC: `--telemetry-level` flag), `composer/{PROPOSED_DECISIONS,PHASE_6_COMPOSER_SUMMARY}.md`.

> This is Phase 6's **post-completion retrospective** (Opus-owned). The Composer-facing plan that drove the implementation is preserved in git history at `phases/PHASE_6_LOGGING.md@phase-5-handoff`; this retrospective replaces it after review.

---

## TL;DR (what was done; how it fits cloud1)

Composer added the **extended telemetry layer** that populates the 5 v2 SQLite tables introduced in Phase 1 — `reward_counterfactuals`, `mutation_substrategy`, `hook3_raw`, `local_coverage_v2`, `compressed_global_coverage`. These were schema-only after Phase 1; Phase 6 makes them WRITTEN for every mutation when the fuzzer runs at `--telemetry-level=full`.

The new module `telemetry_v2.py` provides 4 pure-ish helpers + one orchestrator:

| Function | What it produces |
|---|---|
| `classify_value_class(orig, mut)` | one of `zero \| bit_pattern \| small \| large` — for `mutation_substrategy.value_class` |
| `extract_mutation_substrategy(kind, config, orig, mut)` | dict of `(opcode, rd, rs1, rs2, funct3, funct7, imm, byte_lane, bit_mask, value_class)` — per-kind, decoded fields per Pro §12 |
| `build_hook3_payload(residues, details, kind, zone, major)` | `(raw_json, compressed_ctx_list)` for `hook3_raw` |
| `record_full_telemetry(db, cid, mid, …)` | writes ALL 5 v2 tables for one mutation; returns reward components |
| `default_telemetry_level(selector, v2_set)` | `"full"` for v2 selectors, `"standard"` for legacy |

The fuzzer's three mutation paths (`_run_single_mutation`, `_run_bandit_mutation`, `_run_v2_bandit_mutation`) all call `_record_full_telemetry()` when `telemetry_level == "full"`. The v2 path additionally writes `bandit_decisions` and (every 100 mutations) `arm_state_snapshot` inside the same `full` guard (Composer's "one knob" consolidation, D38).

CLI gains `--telemetry-level {none, standard, full}`; default is **auto-derived from the selector** (D35).

**How it fits**: Phase 1 created the schema → Phase 2-3 produced the data needed for v2 reward components → Phase 4 wrote the reward math + counterfactual function → Phase 5 wired the bandit + persisted bandit_decisions ad-hoc → Phase 6 (this) consolidates all the per-mutation v2 writes into one orchestrator + adds the remaining 3 tables (counterfactuals, substrategy, hook3_raw) → Phase 7 smoke-tests on POS → Phase 8 IV.POS.7 → Phase 9 Pro Round 2.

---

## 1. Goal recap

Make every per-mutation v2 telemetry row that the Phase 9 analysis needs actually appear in the DB. No fuzzer-loop logic changes; only logging.

---

## 2. Deviations from the original plan

| # | Original plan | What happened | Severity |
|---|---|---|---|
| ① | "Compute reward counterfactuals after each mutation regardless of selector" | Done, but gated by `telemetry_level != "none"` — `none` skips counterfactuals entirely (mass storage optimization) | low (none-level is opt-in; default behavior unchanged) |
| ② | "bandit_decisions written for every v2 mutation" | Now gated by `telemetry_level == "full"` (Composer's D38 consolidation) | low (default for v2 is `full`; production unaffected) |
| ③ | "Standard substrategy fields per kind" | All 10 fields present (opcode/rd/rs1/rs2/funct3/funct7/imm/byte_lane/bit_mask/value_class); unused fields are `None` | none (Pro-compliant superset) |
| ④ | 200-mutation exit smoke before declaring done | Partial smoke at N=10 only (~25s/mutation locally) | low (Phase 7 will run N=200 on POS) |
| ⑤ | 4 D-decisions pre-flagged | Composer filed exactly 4 (D-J..D-M), promoted to D34-D37; Opus added D38 (gating policy) | none |

All deviations documented in Composer's `PHASE_6_COMPOSER_SUMMARY.md` §4-§5.

---

## 3. Code changes

### 3.1 `a4/standalone/telemetry_v2.py` (new file, 262 LOC)

```python
def classify_value_class(original_value: int, mutated_value: int) -> str:
    orig = original_value & 0xFFFFFFFF
    mut = mutated_value & 0xFFFFFFFF
    if mut == 0: return "zero"
    xor = orig ^ mut
    if xor != 0 and xor.bit_count() <= 4: return "bit_pattern"  # boundary: <=4 bits
    if mut < 256: return "small"
    diff = (mut - orig) & 0xFFFFFFFF
    if diff < 256 or (0xFFFFFFFF - diff) < 256: return "small"   # wrap-aware
    return "large"
```

**`extract_mutation_substrategy(kind, config, original_value, mutated_value)`** dispatches per kind:
- `INSTR_WORD_MOD_SUR/FULL/MOD` → decode word via `RiscVInstruction.from_word(mutated_value)`; populate opcode/rd/rs1/rs2/funct3/funct7/imm.
- `LOAD/STORE/COMP/MEM_VAL/PRE_EXEC` → `value_class`.
- `MEM_VAL_MOD` additionally → `bit_mask = orig^mut`, `byte_lane = min(31, max(0, XOR.bit_length() − 1))`.

**`build_hook3_payload`** returns `(raw_obj, compressed_list)` per D36; raw is the verbatim Hook 3 JSON, compressed list is post-Phase-3-extractor.

**`record_full_telemetry(db, campaign_id, mutation_id, kind, step, exec_result, config, original_value, mutated_value, legacy_reward_diag, step_to_zone, seen_*, components=None)`** — the orchestrator:
1. Resolve `mutation_major` (prefer `exec_result._mutation_major` set by fuzzer from cycle data; fallback to `failures[0].major`; else 0).
2. If `components` not pre-passed, call `compute_reward_v2_components(...)` (Phase 4).
3. Compute counterfactuals → `record_reward_counterfactuals` (Phase 1).
4. Extract substrategy → `record_mutation_substrategy`.
5. Build hook3 payload → `record_hook3_raw`.
6. For each NEW local context in failures → `record_local_v2_first_hit`.
7. For each NEW compressed global context → `record_compressed_global_first_hit`.
8. Return components (so caller knows what was recorded).

Notably, **NaN/inf sanitization** in `_sanitize_reward()` — any non-finite reward becomes `0.0` before SQLite write. Defensive against pathological reward math.

### 3.2 `a4/standalone/fuzzer.py` (+~100 LOC)

- New constructor param `telemetry_level: Optional[str] = None`; if `None`, auto-derive via `default_telemetry_level(selector_strategy, V2_BANDIT_STRATEGIES)`. Validates against `TELEMETRY_LEVELS`.
- New `_init_full_telemetry_state()` — initializes `_step_to_zone`, `_seen_local_v2`, `_seen_compressed_global`, `_seen_structural` IF `telemetry_level == "full"`. Called from both legacy setup AND v2 setup paths.
- New `_record_full_telemetry(mutation_id, **kw)` — wrapper that no-ops if not `full`, otherwise sets `_mutation_major` on exec_result and calls `record_full_telemetry`.
- Call wired into all three mutation paths:
  - `_run_single_mutation` (legacy) → calls `_record_full_telemetry` unconditionally; method no-ops when not `full`.
  - `_run_bandit_mutation` (legacy bandit) → same.
  - `_run_v2_bandit_mutation` (v2 bandit) → calls `_record_full_telemetry` AND (within the same `if full:` block) `record_bandit_decision` + `record_arm_state_snapshot` every 100 campaign mutations.

### 3.3 `a4/standalone/cli.py` (+11 LOC)

```python
fuzz_parser.add_argument(
    "--telemetry-level",
    dest="telemetry_level",
    default=None,
    choices=["none", "standard", "full"],
    help="Logging depth: none (minimal), standard (legacy default), "
         "full (all v2 tables; default for IV.POS.7 selectors)",
)
```

`A4Fuzzer(..., telemetry_level=args.telemetry_level, ...)` — `None` triggers auto-derive.

### 3.4 Tests

**Composer's `test_telemetry_v2.py`** (13 tests): value_class for 4 buckets; default_telemetry_level for v2 and legacy; mutation_substrategy for LOAD/MEM_VAL/INSTR_WORD_SUR; hook3 payload empty + D36 shape; `record_full_telemetry` writes all v2 tables.

**Opus's `test_telemetry_v2_adversarial.py`** (29 tests): value_class boundary cases (MSB / signed negative / exactly-4-bit XOR / wrap-around), unknown-kind no-op, PRE_EXEC_REG_MOD included in value_class (D34 superset acknowledgment), MEM_VAL zero-XOR / high-bit-XOR, hook3 both-fields case + JSON round-trip, crash with empty seen_structural (s_new=1, reward ≈ −0.44 by design), crash with warm structural (reward = −0.50 exactly), mutation_major fallback chain (cycle → failure → 0), duplicate-failure dedup, SQLite round-trip for all 5 counterfactual columns.

---

## 4. Test results

```
$ python -m pytest a4/standalone/tests/test_telemetry_v2.py -v
13 passed in 0.71s

$ python -m pytest a4/standalone/tests/test_telemetry_v2_adversarial.py -v
29 passed in 6.84s

$ pft  (full fast suite)
382 passed, 1 skipped in 35.84s
```

Math: 340 (post-Phase-5) + 13 (Composer) + 29 (Opus) = 382. **No regressions.**

### Host smoke (partial, wall-clock-bound)

Composer ran `cTS_semantic_v2 --telemetry-level=full` N=10:
```
elapsed_sec=247  completed=7  skipped=3
reward_counterfactuals=7  mutation_substrategy=7  hook3_raw=7
bandit_decisions=7  local_coverage_v2=28  compressed_global_coverage=0
nan_rows=0
```

Every completed mutation has matching rows in counterfactual / substrategy / hook3 / bandit tables. Counterfactuals are finite. `compressed_global_coverage=0` is expected — no NEW compressed contexts on this short run. The 200-mutation and 6000-mutation size budget checks are deferred to Phase 7 on POS hardware (~4h+ locally per N=500 batch).

---

## 5. Acceptance criteria scorecard

| # | Plan exit criterion | Outcome |
|---|---|---|
| 1 | v2 tables wired per-mutation when `full` | ✅ all 5 tables verified by `test_writes_all_v2_tables` and adversarial `test_all_five_columns_round_trip_finite` |
| 2 | Counterfactuals finite (NaN-protected) | ✅ `_sanitize_reward()` + 3 adversarial tests |
| 3 | `--telemetry-level` CLI | ✅ verified by import test + D35 default tests |
| 4 | All 3 fuzzer paths support full telemetry | ✅ `_record_full_telemetry` called from `_run_single_mutation`, `_run_bandit_mutation`, `_run_v2_bandit_mutation` |
| 5 | Legacy strategies runnable | ✅ 382-test suite passes including all Phase 0-5 tests |
| 6 | 200-mutation smoke all tables | ⏳ deferred to Phase 7 (POS env) |
| 7 | DB ≤ 150 MB @ 6000 mut | ⏳ deferred to Phase 7 |
| 8 | D-decisions filed | ✅ D-J..D-M promoted to D34-D37; D38 added by Opus |

---

## 6. Opus's skeptical review — what I would have done independently

| Aspect | What I would have done | What Composer did | Verdict |
|---|---|---|---|
| `value_class` algorithm | Tag by SOURCE generator (BitFlip→bit_pattern, etc.) | XOR-bit-count heuristic | ⚠️ **Composer's is simpler but tags incidental low-XOR as bit_pattern** — adversarial test `test_load_val_mod_no_instr_decode` discovered 100→50 (4-bit XOR) is tagged bit_pattern despite not coming from bit-flipper. Flagged as G6a for Pro. Both approaches are workable; provenance-based would be more semantic. |
| `mutation_major` extraction | Take from `cycle` directly (always available via `_step_to_zone` lookup) | `exec_result._mutation_major` set by fuzzer, with `failures[0].major` fallback | ✅ Composer's approach is more defensive; works when called with a non-fuzzer exec_result (tests). Magic underscore attribute is slightly awkward but documented. |
| NaN/inf handling in counterfactuals | Raise if non-finite | `_sanitize_reward()` returns 0.0 | ✅ **Composer's is more production-friendly** — a single bad reward shouldn't crash a 6000-mutation campaign |
| Side-effect ordering | Mutate `seen_*` BEFORE writing rows | Same (via `compute_reward_v2_components` which updates sets) | ✅ |
| `byte_lane` for MEM_VAL_MOD | Get from config; raise if missing | Derive from XOR with `byte_lane = (XOR.bit_length() - 1)` clamp | ✅ **Composer's is pragmatic** — config doesn't carry byte_lane today; XOR-based approximation works |
| `hook3_raw` schema | `{"residues": [...], "details": [...]}` | `{"family_residues": [...], "family_details": [...]}` | ✅ Composer's matches Phase 1 round-trip test naming |
| `bandit_decisions` gating | Always log on v2 paths (Phase 5 behavior) | Gated under `full` (Composer's "one knob") | ⚠️ **Subtle behavior change from Phase 5** — explicit `--telemetry-level=standard` with v2 selector silently drops bandit logs. Default unchanged (v2→full→logged). Documented as D38 and G6b. |
| `PRE_EXEC_REG_MOD` in value_class | Pro listed only LOAD/STORE/COMP — would have followed Pro literally | Included as harmless superset | ✅ Composer's is a defensible expansion; matches all value-mutating kinds; my adversarial test pins it down. |

**Net assessment**: Composer's implementation is correct. Two stylistic deltas worth flagging to Pro (G6a — value_class heuristic, G6b — bandit_decisions gating); neither is a blocker. No required rewrites. Composer was BETTER than my sketch on NaN handling and `byte_lane` pragmatism.

---

## 7. Insights (what we learned)

1. **`value_class` is XOR-driven, not provenance-driven.** Many "small numeric" mutations from non-bit-flip generators end up tagged `bit_pattern` because their XOR happens to be ≤4 bits. Phase 9 stratification by `value_class` should be interpreted as "XOR bit-count cluster", not "value-generator type". Real fix (if Pro wants) requires threading generator-strategy through mutation config; cheap to add later.

2. **Crash + empty seen_structural ≠ pure −0.50 reward.** The S_new term still grants `0.15·sat(1,2) ≈ +0.094` for novel structural cells even on crashed runs. Net crash reward: ~−0.44 (first time on that arm) → −0.50 (after arm is warm). This is a Pro §6.3 design property — novelty of (kind, zone, opcode, mode, txn_role) combinations is rewarded regardless of outcome. Documented by `test_crash_exec_result_still_writes_rows` and `test_crash_with_warm_structural_set_pure_minus_05`.

3. **NaN/inf-protection is necessary.** Pathological inputs (e.g., legacy reward with `Q_rep=0, Q_glob=0, S=0` and `mode=normal`) can produce 0.0 cleanly, but a defensive `_sanitize_reward()` was added in case future reward math introduces div-by-zero. Costs nothing in normal runs.

4. **The `mutation_major` extraction fallback chain is robust to test environments.** In real fuzzer use, the fuzzer sets `exec_result._mutation_major` from `cycle.major`. In tests, it falls back to `failures[0].major` or 0. Both paths covered.

5. **Telemetry consolidation reduces fuzzer-loop branching.** Before Phase 6, the v2 path had ad-hoc `record_bandit_decision` and `record_arm_state_snapshot` calls. After Phase 6, all per-mutation v2 writes are funneled through `_record_full_telemetry()`, with the gating decision in ONE place. Easier to reason about than scattered conditionals.

---

## 8. What's now possible

- **Phase 7** can run a focused N=200 per-variant smoke and verify:
  - 5 v2 tables populated for every completed mutation
  - `local_coverage_v2` first-hit semantics correct across the run
  - `compressed_global_coverage` rows appear when Hook 3 produces broken_addrs/broken_indices
  - DB size at N=6000 ≤ 150 MB (Pro's budget)
- **Phase 9** can run the full counterfactual analysis post-hoc on every IV.POS.7 DB without re-running campaigns.
- **Legacy compatibility preserved**: `--telemetry-level=standard` (legacy default for `zoned`/`bandit`/`uniform`) produces IV.POS.5-equivalent DBs. Cross-campaign analysis tools that read pre-cloud1 DBs still work.

---

## 9. Files touched (git-style)

```
A  a4/standalone/telemetry_v2.py                             +262
A  a4/standalone/tests/test_telemetry_v2.py                  +174
A  a4/standalone/tests/test_telemetry_v2_adversarial.py      +330  (Opus)
M  a4/standalone/fuzzer.py                                   +~100 (Composer; telemetry_level, _init_full_telemetry_state, _record_full_telemetry, path wiring)
M  a4/standalone/cli.py                                      +11   (Composer; --telemetry-level flag)
M  a4/docs/cloud1/composer/PROPOSED_DECISIONS.md             +~95  (Composer; D-J..D-M + Phase 4-5 index)
A  a4/docs/cloud1/composer/PHASE_6_COMPOSER_SUMMARY.md       +92   (Composer)
M  a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md             +D34..D38, +G6a, +G6b
M  a4/docs/cloud1/CLOUD1_STATUS.md                           Phase 6 done
M  a4/docs/cloud1/phases/PHASE_6_LOGGING.md                  this retrospective replaces the Composer-facing plan
```

No edits to `bandit.py`, `coverage_state.py`, `reward_v2.py`, `bandit_ts.py`, or Phase 1-3 modules.

---

## 10. Consistency check against ProG_Report_2.md

| Pro §reference | Pro spec | Our implementation | Match? |
|---|---|---|---|
| §6.1 value_class | `zero \| small \| large \| bit_pattern` | All 4 present (D34) | ✅ (classification heuristic flagged as G6a) |
| §12 reward_counterfactuals | 5 columns | All 5 written per mutation via `record_reward_counterfactuals` | ✅ |
| §12 mutation_substrategy | per-kind fields | All 10 fields present; per-kind dispatch | ✅ |
| §12 hook3_raw | raw + compressed Hook 3 details | Both via `build_hook3_payload` (D36) | ✅ |
| §12 bandit_decisions | per-mutation row | Written under `full` (D38) | ✅ (default unaffected) |
| §12 arm_state_snapshot | "every E mutations" | E=100 via `mutation_num % 100 == 0` | ✅ |
| §12 local_coverage_v2 | first-hit table | Written via `record_local_v2_first_hit` per distinct failure | ✅ |
| §12 compressed_global_coverage | first-hit table | Written via `record_compressed_global_first_hit` per distinct ctx | ✅ |

---

## 11. Symbol reference

| Symbol | Defined in | Type | Meaning |
|---|---|---|---|
| `TELEMETRY_LEVELS` | `telemetry_v2.py:31` | `frozenset` | `{"none", "standard", "full"}` |
| `default_telemetry_level(sel, v2_set)` | `telemetry_v2.py:34` | function | D35 auto-derivation |
| `classify_value_class(orig, mut)` | `telemetry_v2.py:41` | function | D34 taxonomy |
| `extract_mutation_substrategy(kind, cfg, orig, mut)` | `telemetry_v2.py:77` | function | per-kind dispatch; returns 10-key dict |
| `build_hook3_payload(...)` | `telemetry_v2.py:117` | function | `(raw, compressed)` tuple per D36 |
| `_sanitize_reward(val)` | `telemetry_v2.py:150` | helper | NaN/inf → 0.0 |
| `record_full_telemetry(...)` | `telemetry_v2.py:157` | orchestrator | writes 5 v2 tables; returns components |
| `_init_full_telemetry_state` | `fuzzer.py:533` | method | initializes `seen_*` sets when `full` |
| `_record_full_telemetry` | `fuzzer.py:543` | method | no-op if not `full`; sets `_mutation_major`; calls `record_full_telemetry` |
| `self.telemetry_level` | `fuzzer.py:252` | str | one of TELEMETRY_LEVELS |

---

## 12. Risks tracked forward

| Risk | Mitigation / next phase |
|---|---|
| `value_class` heuristic mismatches Pro's intent (G6a) | Phase 9 stratification will reveal whether bit_pattern bucket is too inclusive; if so, provenance-based fix is ~20 LOC |
| Explicit `--telemetry-level=standard` with v2 silently disables bandit logs (D38 / G6b) | Default for v2 is `full`; production unaffected. Doc + Pro verdict in R2. |
| DB size at N=6000 unknown | Phase 7 will measure on POS; if >150 MB, add column compression or move `hook3_raw.raw_json` to separate file |
| Counterfactual NaN/inf possible from pathological legacy diag | `_sanitize_reward()` returns 0.0; logged separately if needed |
| Inflight mutations spanning epoch boundary | `arm_state_snapshot` triggered every 100; snapshot captures POST-update state; safe |

---

## 13. Composer's open question (answered)

**Q1: "should v2 selectors with explicit `--telemetry-level=standard` still log bandit_decisions, or is gating everything behind `full` the intended behavior?"**

A: **Current behavior (gated to `full`) is acceptable as the default policy.** Documented as D38. Default for v2 selectors is `full`, so production runs are unaffected. The only impact is if a user EXPLICITLY downgrades a v2 run to `standard`, which is unusual. Alternative (always log bandit_decisions on v2 paths regardless of telemetry level) is a 5-line move outside the `full` guard if Pro disagrees — flagged as **G6b** for Pro Round 2.

---

## 14. What Opus changed in OWN markdown after Composer finished

- `CLOUD1_DECISIONS_FOR_PRO_R2.md`: added **D34–D37** (Composer's D-J..D-M promoted) + **D38** (bandit_decisions gating policy). Added **G6a / G6b** open questions. Updated "If you wish to change…" reference list.
- `CLOUD1_STATUS.md`: marked Phase 6 done; decision count 33 → 38; G-questions 5 → 6 (counting G6 as G6a+G6b is still one entry).
- `phases/PHASE_6_LOGGING.md`: this file replaces the Composer-facing plan.
- `composer/*`: unchanged (Composer-owned).
