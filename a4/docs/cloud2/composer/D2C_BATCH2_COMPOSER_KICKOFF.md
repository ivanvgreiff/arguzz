# D2.C Batch 2 — Composer Kickoff

**Branch:** `cloud2` (commit directly — no feature branch, no PR)
**Spec:** [`../IV_POS_8_D2_C_SPEC.md`](../IV_POS_8_D2_C_SPEC.md) **v0.5 LOCKED** + **§15 living-issue annex** (ISS-1 … ISS-5 — read it, you own resolving several)
**Governing plan:** [`../New_Master.md`](../New_Master.md) §2 Phase 1 (Build D2.C) · **Parent:** [`../IV_POS_8_D2_PLAN.md`](../IV_POS_8_D2_PLAN.md) v0.16 §3
**Requirements behind the plan:** [`../pro_checkin_attachments/ProG_Report_4.md`](../pro_checkin_attachments/ProG_Report_4.md) §2 Phase 1, §6 (arm-space suggestions)
**Notes for Pro:** [`../IV_POS_8_NOTES_FOR_PRO.md`](../IV_POS_8_NOTES_FOR_PRO.md) — NFP-1 (5-tuple ArmKey)
**D2.A spec (opcode_class source of truth):** [`../IV_POS_8_D2_A_SPEC.md`](../IV_POS_8_D2_A_SPEC.md) v0.2 LOCKED §1.1 — the **7 LOCKED opcode classes**
**Predecessor (this batch builds on it):** **D2.C Batch 1** — the primitive `a4/standalone/arguzz_invoke.py` (Option C `_classify_outcome`, `_detect_host_panic`, re-exports) + `_TXN_ROLE_BY_KIND` move + `arguzz_runner` deprecation + 4 tests. See [`D2C_BATCH1_COMPOSER_REPORT.md`](./D2C_BATCH1_COMPOSER_REPORT.md). (Batch 1 is in the working tree; commit it before starting Batch 2 if it is not yet committed.)
**Issued by:** Opus (planning), on the locked v0.5 spec, post-Batch-1 review
**Expected effort:** ~1 day focused work + ~0.5 day for the report.

---

## TL;DR for Composer

Implement **D2.C Batch 2** per `IV_POS_8_D2_C_SPEC.md` v0.5 §11 "Batch 2" (tasks 2.1 → 2.7): the **bridge layer + arm-construction**. Two code deliverables:

1. **`a4/standalone/mutations/arguzz_bridge.py` (NEW)** — the analog of the A4 `mutations/*_mod` modules, but for `surface=arguzz_exec_fault` arms. It owns the **11-vs-4 kind lists**, the **per-kind `pre_post`** convention, the **instruction→opcode_class** mapping, the per-instruction kind-validity logic (lifted verbatim from `v6_driver_v2.py`), and `create_mutation_for_arm` (the single entry point that calls the Batch-1 primitive `arguzz_invoke.run()`).
2. **`a4/standalone/semantic_arm_universe.py` extension** — add the `arguzz_kinds: Optional[List[str]] = None` + `baseline_trace: Optional[dict[int,str]] = None` parameters so the cTS arm universe can emit full 5-field Arguzz `ArmKey`s.

Plus two tests (Layer 3 bridge-wiring, Layer 4 arm-construction) and **task 2.5 — the authoritative arm-space measurement** (this is where ISS-2's 437 estimate gets confirmed or corrected on real data).

**Batch 2 ships NO `fuzzer.py` change, NO `_dispatch_arm`, NO driver, NO scheduler change, and does NOT wire `applied_accounting_mode`.** Those are Batch 3. The bridge is exercised in Batch 2 against a **real bandit but a stubbed primitive** (no real binary in the unit tests).

**The single load-bearing constraint of this batch:** the `semantic_arm_universe.build` extension MUST be a **pure no-op when `arguzz_kinds is None`** (the default). The **V5 Tier-1 golden trace** (`test_d2c_golden_trace_v5_decision_seq.py`, shipped in Batch 1) runs through this exact code path and **must stay byte-identical**. If it changes, you broke back-compat.

---

## Composer: read these files first (in this order, before writing any code)

**Docs:**
1. `IV_POS_8_D2_C_SPEC.md` **v0.5** — especially **§4.2** (`arguzz_bridge.py` full API — your primary deliverable), **§4.3** (`semantic_arm_universe` extension), **§1.2** (per-kind arm-shape map + arm-space bands), **§7 S1/S2/S5** (arm-certainty stack — what the tests assert), **§11 Batch 2** (tasks 2.1–2.7), **§14** (acceptance #2/#3/#5), and **§15** (the living-issue annex — ISS-1 through ISS-5 are yours to honor/resolve).
2. This kickoff — workflow framing + pass criteria.
3. `IV_POS_8_D2_A_SPEC.md` v0.2 LOCKED §1.1 — the **7 opcode classes** (`arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`). `MAPPING_INSTR_TO_OPCODE_CLASS` must land on **exactly these strings** — do not invent new ones, do not merge `ecall_mret` into `system`.

**Code (read at the post-Batch-1 working tree — do NOT write the bridge before reading these):**
4. `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` — **the frozen reference.** Copy **verbatim**: `ENABLED_KINDS` (lines 168–173 → `MUTATION_KINDS_ARGUZZ_FULL`), the instruction-class sets `BRANCHES`/`COMPUTATIONS`/`LOADS`/`STORES` and `INSTR_KINDS`, and `valid_injection_kinds_for_instr` (lines 176–191). **Do NOT modify this file.**
5. `a4/standalone/arguzz_invoke.py` **(Batch 1, your dependency)** — `run(host, host_args, step, kind, seed, *, timeout=90.0, include_trace=False, env=None) -> ArguzzInvocationResult`. `create_mutation_for_arm` calls this. Note the `include_trace` param (see ISS-1 below for the policy you must apply). Read-only.
6. `a4/standalone/semantic_arm_universe.py` — `ArmKey` 5-tuple (lines 174–205: `surface, kind, zone, opcode_class, pre_post`; `ArmKey.v5(...)` for the legacy 2-field shape); `ARGUZZ_EXEC_FAULT = "arguzz_exec_fault"` (line 170); `SemanticArmUniverse.build` (lines 247–280 — the method you extend), `zone_to_steps`, `SEMANTIC_ZONES`, `_filter_real_target_steps`. **This is your edit target (task 2.2).**
7. `a4/standalone/bandit_ts.py` — `ConstrainedTSScheduler`, `MutationOutcome` (line 57), and **`update_with_outcome` (line 310)** + `applied_accounting_mode` (146, 156) — both **already exist**. The Layer-3 bridge test drives `update_with_outcome` directly with a real scheduler. Read-only in Batch 2.
8. `a4/standalone/compressed_global_extractor.py` — confirm Batch 1's `_TXN_ROLE_BY_KIND` Arguzz entries are present (Batch 2 does not touch this file).
9. `a4/standalone/tests/test_d2a_arm_shape_arguzz_simulation.py` — the **template** for the Layer-4 arm-construction test (synthetic `InspectionData`, 5-field `ArmKey` assertions, `applied_accounting_mode=True` usage at line 74).
10. `a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py` **(Batch 1)** — the byte-identity gate you must NOT break. Run it before and after task 2.2.
11. `a4/docs/cloud2/composer/D2C_BATCH1_COMPOSER_KICKOFF.md` + `D2C_BATCH1_COMPOSER_REPORT.md` — format precedent + the Batch-1 facts you inherit (arm-space FULL=437/SELECTED=180 estimate; all 4 SELECTED kinds → `prover_status="error"`+failures → `APPLIED`).

---

## Pre-kickoff sanity checklist (run BEFORE writing any code)

Composer MUST run each and paste output into the Batch 2 report:

```bash
# 1. Batch 1 is present (committed or in the working tree) and green
git rev-parse HEAD
git status --short
ls -l a4/standalone/arguzz_invoke.py            # → Batch-1 primitive present

# 2. Establish the post-Batch-1 green baseline (D2-regression path = ignore replicates)
python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py 2>&1 | tail -3
# Record this number — it is your Batch-2 floor (Batch 1 added the mock / outcome-mapping /
# golden-trace tests on top of the 616/17 D2.B baseline; the real-binary test skips without
# A4_REAL_BINARY=1). New Batch-2 tests must not drop the green count.

# 3. The V5 Tier-1 golden trace passes NOW (you must keep it byte-identical)
python -m pytest a4/standalone/tests/test_d2c_golden_trace_v5_decision_seq.py -q

# 4. Bridge does NOT yet exist; semantic_arm_universe has NO arguzz_kinds param yet
ls a4/standalone/mutations/arguzz_bridge.py 2>&1     # → No such file (you create it)
grep -n 'arguzz_kinds' a4/standalone/semantic_arm_universe.py   # → no hits yet (task 2.2 adds it)

# 5. The verbatim-copy sources are readable
grep -n 'ENABLED_KINDS\|def valid_injection_kinds_for_instr\|^BRANCHES\|^COMPUTATIONS\|^LOADS\|^STORES\|^INSTR_KINDS' a4/runs/iv_pos_7/drivers/v6_driver_v2.py

# 6. ArmKey shape + update_with_outcome confirmed
grep -n 'class ArmKey\|ARGUZZ_EXEC_FAULT' a4/standalone/semantic_arm_universe.py
grep -n 'def update_with_outcome' a4/standalone/bandit_ts.py     # → ~line 310
```

If any check surprises you (esp. #3 failing before you touch anything, or #4 already present), **stop and report** rather than improvising.

---

## Scope — exactly what Batch 2 ships

### Spec sections this batch implements
- **§4.2** `a4/standalone/mutations/arguzz_bridge.py` (NEW — the bridge)
- **§4.3** `a4/standalone/semantic_arm_universe.py` `build(arguzz_kinds=…, baseline_trace=…)` extension
- **§1.6 / §4.8** test Layer 3 (bridge wiring) + Layer 4 (arm-construction)
- **§11 Batch 2** task list 2.1 → 2.7
- **§14** acceptance #2 (FULL/SELECTED constants), #3 (`arguzz_kinds` parameter)
- **§15** ISS-1 (apply `include_trace=False` policy), ISS-2 (measure + decide), ISS-3 (guard), ISS-4 (coverage test), ISS-5 (bridge-test scope)

### Files touched

| File | Action | Rough size |
|---|---|---|
| `a4/standalone/mutations/arguzz_bridge.py` **(NEW)** | The bridge. `ArguzzBridgeTarget` dataclass, `_PRE_POST_BY_KIND`, `MUTATION_KINDS_ARGUZZ_FULL` (11), `MUTATION_KINDS_ARGUZZ_SELECTED` (4), `BRANCHES`/`COMPUTATIONS`/`LOADS`/`STORES`/`INSTR_KINDS` (verbatim), `valid_injection_kinds_for_instr` (verbatim), `get_valid_steps`, `get_targets_at_step`, `MAPPING_INSTR_TO_OPCODE_CLASS`, `opcode_class_for_step`, `create_mutation_for_arm`. | ~200–260 LOC |
| `a4/standalone/semantic_arm_universe.py` | Extend `build()` with `arguzz_kinds` + `baseline_trace` params + the Arguzz arm-construction loop + the ISS-3 guard. **`arguzz_kinds=None` path must be byte-identical to today.** | ~40–70 LOC |
| `a4/standalone/tests/test_d2c_arguzz_bridge.py` **(NEW)** | Layer 3 — stubbed primitive + real bandit; bridge routing + `update_with_outcome` + ISS-4 mapping-coverage assertion. | ~150 LOC |
| `a4/standalone/tests/test_d2c_arguzz_arm_construction.py` **(NEW)** | Layer 4 — synthetic `InspectionData`; parametrized over FULL+SELECTED × 7 opcode classes × per-kind `pre_post`; applicability + count-range assertions. | ~180 LOC |
| `a4/standalone/mutations/__init__.py` | Create only if the `mutations/` package has no `__init__.py` (check first). | 0–1 LOC |

**Total expected delta:** ~570–760 LOC across 4–5 files. All Python; **zero Rust**.

---

## NOT in Batch 2 (deferred — do not start these)

| Item | Where it ships |
|---|---|
| `a4/standalone/v6_uniform_driver.py` | **Batch 3** (§4.5) |
| `fuzzer.py` `_dispatch_arm()` / Arguzz dispatch branch / `_record_arguzz_mutation` | **Batch 3** (§4.4) — **even though §4.8's Layer-3 row mentions `_dispatch_arm`, that part is Batch 3 (see ISS-5)** |
| `applied_accounting_mode=True` wiring in `fuzzer.py`; `update_with_outcome` on the *fuzzer* dispatch path | **Batch 3 task 3.2a** (Batch 2 calls `update_with_outcome` only from the test, not from fuzzer) |
| `mutations.outcome` column population on real Arguzz rows | **Batch 3** (needs the driver/fuzzer write path) |
| Tier-2 V5 golden-trace **DB** byte-identity gate | **Batch 3 task 3.2b** |
| Hybrid forerunner smoke; cross-cutting 66-case registration test | **Batch 4** |
| Any **reduction** of the arm space (merging opcode classes, dropping zones) | **NOT Batch 2** — Batch 2 *measures + proposes*; reduction needs Opus/Ivan sign-off (ISS-2) |
| Changes to `bandit_ts.py`, `arguzz_invoke.py`, `arguzz_parser.py`, `coverage_db.py`, `v6_driver_v2.py`, `compressed_global_extractor.py`, `workspace/risc0-modified/` | **None** — §4.9 "must not change" |

If you find yourself editing anything in the "must not change" list, **stop and confirm**.

---

## Tracked issues you must honor (spec §15) — and how to close them

Batch 1 surfaced ISS-1/ISS-2; Batch 2 design adds ISS-3/ISS-4/ISS-5. **When you resolve one, flip its Status in the spec §15 table to `RESOLVED` (append the resolving commit/batch) and note the resolution in your Batch-2 report.** Do not delete rows — keep the audit trail.

| ID | What you do in Batch 2 | How it closes |
|----|------------------------|---------------|
| **ISS-1** (`include_trace` / `--trace`) | `create_mutation_for_arm` calls `arguzz_invoke.run(..., include_trace=False)` — **do not pass `True`**. Rationale: the bandit/outcome path is `prover_status`-PRIMARY; `_classify_outcome` never reads `<fault>` tags, so faults are not needed for the production loop, and `--trace` at N=6000 would bloat stdout. Add a one-line comment at the call site citing ISS-1. | Flip ISS-1's bridge half to **RESOLVED** (`include_trace=False` policy shipped). The D2.G fault-corroboration sub-item stays OPEN — leave it. |
| **ISS-2** (arm space > 300) | Task 2.5: measure the **real** FULL + SELECTED counts via `SemanticArmUniverse.build` on actual sha2-host `InspectionData`. Report both. **If FULL > 300** (Batch-1 estimate says 437 — expect this), write a short **reduction proposal** (do NOT implement): which lever (a) merge `jump`→`branch` opcode_class, (b) drop zones with <5 steps, (c) merge `pre_post` where it doesn't split arms — with the resulting projected count for each. Defer the decision to Opus/Ivan. | Leave ISS-2 **OPEN** but update its row with the measured count + your proposal. It closes when Opus/Ivan rule on reduce-vs-keep. |
| **ISS-3** (`baseline_trace` provenance) | In `build()`: if `arguzz_kinds is not None and baseline_trace is None`, **`raise ValueError`** (fail loud — never silently bucket the whole trace to `"system"`). The Layer-4 test synthesizes a `baseline_trace`; task 2.5 captures a real one via `host --trace`. | Flip ISS-3 to **RESOLVED** once the guard + tests land. |
| **ISS-4** (`MAPPING_INSTR_TO_OPCODE_CLASS` completeness) | Layer-3 bridge test asserts **every instruction in `INSTR_KINDS` maps to a non-`system` class** (or, for `ebreak`/`invalid`/`eany`/`mret`, to its intended class) — i.e. no *known* RV32IM mnemonic silently hits the `"system"` fallback. Task 2.5 logs any **real-trace** instruction that hit the fallback. | Flip ISS-4 to **RESOLVED** once the coverage test passes and task-2.5's fallback log is clean. |
| **ISS-5** (Layer-3 scope vs `_dispatch_arm`) | Scope `test_d2c_arguzz_bridge.py` to **bridge + real bandit ONLY**: `create_mutation_for_arm` (stubbed `arguzz_invoke.run`) → `(outcome, result, config)` → `ConstrainedTSScheduler.update_with_outcome(arm, outcome)`. **Do NOT** assert `A4Fuzzer._dispatch_arm` routing or `mutations.outcome` population — those need Batch 3. | Flip ISS-5 to **RESOLVED** once the bridge-scoped test lands; note in the report that the `_dispatch_arm`/outcome-column assertions are deferred to a Batch-3 augmentation. |

---

## Critical correctness facts (do NOT repeat these)

1. **`arguzz_kinds=None` is a pure no-op.** The default `build(data, mutation_kinds)` call must produce **byte-identical** arms to today. The Arguzz loop runs **only** when `arguzz_kinds is not None`, and is **separate** from the existing A4 `mutation_kinds` loop (Arguzz kinds are NOT in `data.get_valid_steps_for_kind` — they use `arguzz_bridge.get_valid_steps`). Run the Tier-1 golden trace before & after.
2. **5-field `ArmKey` for Arguzz arms.** `ArmKey(surface=ARGUZZ_EXEC_FAULT, kind=kind, zone=zone, opcode_class=opcode_class, pre_post=_PRE_POST_BY_KIND[kind])` — never `ArmKey.v5(...)` for Arguzz arms (that's the legacy 2-field A4 shape).
3. **`pre_post` is per-kind, NOT all-`pre_exec`.** Use `_PRE_POST_BY_KIND` (§4.2): FULL = **5 `pre_exec`** (`INSTR_WORD_MOD`, `PRE_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `BR_NEG_COND`) + **6 `post_exec`** (`POST_EXEC_PC_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_REG_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`). SELECTED's 4 are all `pre_exec`. This was v0.4's S5 drift fix — do not regress it.
4. **`valid_injection_kinds_for_instr` is verbatim, all 11 kinds.** Copy `v6_driver_v2.py:176-191` exactly (7 always-applicable + `BR_NEG_COND` on `BRANCHES` + `COMP_OUT_MOD` on `COMPUTATIONS` + `LOAD_VAL_MOD` on `LOADS` + `STORE_OUT_MOD` on `STORES`), returning the sorted intersection with `ENABLED_KINDS`. Do NOT rewrite it from memory; copy it.
5. **7 opcode classes, exactly.** `MAPPING_INSTR_TO_OPCODE_CLASS` targets the D2.A LOCKED strings: `arithmetic`, `memory_load`, `memory_store`, `branch`, `jump`, `ecall_mret`, `system`. **`ecall_mret` is separate from `system`** (do not merge — D2.A `test_d2a_arm_shape_arguzz_simulation.py:34-38` exercises the distinction).
6. **The bridge writes NO config file to disk.** Arguzz takes `step` + `kind` directly via CLI; `create_mutation_for_arm` returns the `config` dict in-memory for the fuzzer to persist later (Batch 3). Do not invent a JSON-on-disk path.
7. **`include_trace=False`** in `create_mutation_for_arm` (ISS-1). The outcome classifier is `prover_status`-based and does not need fault tags.

---

## Per-task detail

### Task 2.1 — `a4/standalone/mutations/arguzz_bridge.py` (the bridge) — §4.2

Module docstring (§4.2): *"Bridge layer between A4Fuzzer's bandit scheduler and the Arguzz subprocess primitive. For arms with `surface=arguzz_exec_fault`, this module is the analog of the `a4.standalone.mutations.*_mod` modules for A4 arms."*

**Constants (verbatim copies from `v6_driver_v2.py` where noted):**
- `MUTATION_KINDS_ARGUZZ_FULL` — tuple of all 11 `ENABLED_KINDS` in `v6_driver_v2.py:168-173` order: `("PRE_EXEC_PC_MOD", "POST_EXEC_PC_MOD", "INSTR_WORD_MOD", "BR_NEG_COND", "COMP_OUT_MOD", "LOAD_VAL_MOD", "STORE_OUT_MOD", "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD", "PRE_EXEC_REG_MOD", "POST_EXEC_REG_MOD")`.
- `MUTATION_KINDS_ARGUZZ_SELECTED` — `("INSTR_WORD_MOD", "PRE_EXEC_MEM_MOD", "PRE_EXEC_PC_MOD", "BR_NEG_COND")` (Pro Track-A priority 1–4).
- `_PRE_POST_BY_KIND` — the 11-entry dict from §4.2 (5 `pre_exec` + 6 `post_exec`, listed in Critical Fact #3).
- `BRANCHES`, `COMPUTATIONS`, `LOADS`, `STORES`, `INSTR_KINDS` — **verbatim** from `v6_driver_v2.py`.
- `MAPPING_INSTR_TO_OPCODE_CLASS` — every instruction in `INSTR_KINDS` → one of the 7 D2.A classes (§4.2 enumerates the membership: `arithmetic` = add/sub/xor/or/and/slt/sltu/sll/srl/sra/mul/mulh/mulhsu/mulhu/div/divu/rem/remu/lui/auipc + all `*i` immediate variants; `memory_load` = lb/lh/lw/lbu/lhu; `memory_store` = sb/sh/sw; `branch` = beq/bne/blt/bge/bltu/bgeu; `jump` = jal/jalr; `ecall_mret` = eany/mret; `system` = ebreak/invalid).

**Functions:**
- `valid_injection_kinds_for_instr(instr: str) -> list[str]` — **verbatim** `v6_driver_v2.py:176-191`.
- `get_valid_steps(data: InspectionData, kind: str) -> list[int]` — all steps whose instruction class allows `kind` (§4.2: class-restricted kinds gated to their class; the other 7 → all steps).
- `get_targets_at_step(step, data, kind) -> list[ArguzzBridgeTarget]` — `[ArguzzBridgeTarget(...)]` if `step` is valid for `kind`, else `[]`. `pre_post` taken from `_PRE_POST_BY_KIND[kind]`.
- `opcode_class_for_step(step, data, baseline_trace) -> str` — look up the instruction at `step` from `baseline_trace`, return `MAPPING_INSTR_TO_OPCODE_CLASS.get(instr, "system")`.
- `create_mutation_for_arm(arm: ArmKey, step: int, host: str, host_args: list[str], seed: int, data: InspectionData, *, timeout: float = 90.0) -> tuple[MutationOutcome, ArguzzInvocationResult, dict]` — calls `arguzz_invoke.run(host, host_args, step, arm.kind, seed, timeout=timeout, include_trace=False)` **(ISS-1)**; returns `(result.outcome, result, config)` where `config` is the dict the fuzzer will persist to `mutations.config_json` in Batch 3 (include at minimum: `kind`, `step`, `pre_post`, `opcode_class`, `seed`, `soundness_signal`).

**`ArguzzBridgeTarget` dataclass:** `step: int`, `kind: str`, `instruction: str`, `opcode_class: str`, `pre_post: str`. No `config_json` to disk (Fact #6).

### Task 2.2 — extend `semantic_arm_universe.py` `build()` — §4.3

New signature:
```python
@classmethod
def build(cls, data, mutation_kinds, *, arguzz_kinds=None, baseline_trace=None): ...
```
- **ISS-3 guard:** `if arguzz_kinds is not None and baseline_trace is None: raise ValueError("baseline_trace required when arguzz_kinds is set")`.
- The existing A4 `mutation_kinds` loop is **unchanged**.
- **New, separate** Arguzz loop (only when `arguzz_kinds is not None`): for each `kind in arguzz_kinds`, for each `step in arguzz_bridge.get_valid_steps(data, kind)`: `zone = step_to_zone.get(step, "core_other")`; `opcode_class = arguzz_bridge.opcode_class_for_step(step, data, baseline_trace)`; `pre_post = arguzz_bridge._PRE_POST_BY_KIND[kind]`; accumulate `step` under `ArmKey(surface=ARGUZZ_EXEC_FAULT, kind=kind, zone=zone, opcode_class=opcode_class, pre_post=pre_post)`.
- Extend `valid_steps_by_kind` to include per-Arguzz-kind step lists when `arguzz_kinds is not None`.
- **Back-compat:** with `arguzz_kinds=None`, the returned `SemanticArmUniverse` is byte-identical to today (V5 golden trace gate).
- Import `arguzz_bridge` lazily inside the Arguzz branch (avoid a top-level import cycle if one exists).

### Task 2.3 — arm-construction unit test `test_d2c_arguzz_arm_construction.py` (Layer 4) — §4.8

Synthetic `InspectionData` (mirror `test_d2a_arm_shape_arguzz_simulation.py`), no subprocess. Parametrize over **both** kind-lists (FULL=11, SELECTED=4) and assert:
- (a) for each kind, ≥1 arm emitted when the kind's applicable instruction class is present (BR_NEG_COND needs a branch; COMP_OUT_MOD needs an ALU instr; LOAD_VAL_MOD a load; STORE_OUT_MOD a store; the other 7 need any instr);
- (b) `opcode_class` matches `MAPPING_INSTR_TO_OPCODE_CLASS` for ≥1 representative instr of each of the 7 classes (incl. an `ecall_mret` case distinct from `system`);
- (c) `pre_post == _PRE_POST_BY_KIND[kind]` for every emitted arm (FULL: 5 pre / 6 post; SELECTED: 4 pre);
- (d) `arguzz_kinds=None` (default) emits **only** V5-shape A4 arms — no `ARGUZZ_EXEC_FAULT` arms;
- (e) **ISS-3:** `build(arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED, baseline_trace=None)` raises `ValueError`.

### Task 2.4 — bridge wiring test `test_d2c_arguzz_bridge.py` (Layer 3) — §4.8, ISS-4, ISS-5

**Bridge + real bandit, stubbed primitive (ISS-5 scope).**
- Monkeypatch `arguzz_invoke.run` to return a canned `ArguzzInvocationResult` for each outcome bucket (APPLIED via error+failures; APPLIED+soundness_signal via success; SKIPPED via start+panic).
- Assert `create_mutation_for_arm(ArmKey(surface=ARGUZZ_EXEC_FAULT, kind="INSTR_WORD_MOD", ...), step, ...)` returns the expected `(outcome, result, config)`, that `include_trace=False` was passed to `run` (assert via the mock's call kwargs — **ISS-1**), and that `config` carries `kind`/`step`/`pre_post`/`opcode_class`.
- Drive a **real** `ConstrainedTSScheduler.update_with_outcome(arm, outcome)` with the returned outcome; assert it does not raise and updates arm stats.
- **ISS-4 coverage assertion:** `assert all(MAPPING_INSTR_TO_OPCODE_CLASS.get(i, "system") != "system" or i in {"ebreak", "invalid"} for i in INSTR_KINDS)` — i.e. every known RV32IM mnemonic maps to its intended class; only the genuine `system` members fall through.
- **Do NOT** import `A4Fuzzer` or assert `_dispatch_arm` / `mutations.outcome` (Batch 3).

### Task 2.5 — arm-space size **measurement** (authoritative) — §11 task 2.5, ISS-2

This replaces Batch 1's paper estimate with a real measurement.
1. Capture a real `step→instruction` `baseline_trace` from a sha2-host `host --trace` (the same way `v6_driver_v2` does). Build the matching real `InspectionData`.
2. Run `SemanticArmUniverse.build(data, [], arguzz_kinds=MUTATION_KINDS_ARGUZZ_FULL, baseline_trace=bt)` and `... arguzz_kinds=MUTATION_KINDS_ARGUZZ_SELECTED ...`. Report `num_arms` for **both**.
3. Compare to §1.2 bands (V6-cTS ~200–350; Hybrid-cTS ~110–160) and to Batch 1's estimate (FULL=437 / SELECTED=180). Explain any delta (e.g. bridge filtering / phantom-zone pruning that the paper estimate didn't account for).
4. **ISS-4:** log every real-trace instruction that hit the `"system"` fallback (expected: none beyond `ebreak`/`invalid`).
5. **ISS-2:** if FULL > 300 (expected), write the reduction proposal (levers + projected counts) — **proposal only**, no implementation.

### Task 2.6 — full pytest sweep
`python -m pytest a4/standalone/tests/ -q --ignore=a4/standalone/tests/test_run_replicates.py` — at or above the post-Batch-1 floor you recorded in pre-flight, plus the 2 new Batch-2 test files, no pre-existing test regressed. **The Tier-1 V5 golden trace MUST still pass byte-identically.**

### Task 2.7 — write `D2C_BATCH2_COMPOSER_REPORT.md`
See [Report deliverable](#report-deliverable).

---

## Test layers in Batch 2 (from §1.6 / §4.8)

| # | Layer | File | Gating? |
|---|---|---|---|
| 3 | Bridge wiring (mocked primitive + real bandit) | `test_d2c_arguzz_bridge.py` | No |
| 4 | Arm-construction (synthetic InspectionData) | `test_d2c_arguzz_arm_construction.py` | No |
| 1 | V5 Tier-1 golden trace (inherited from Batch 1) | `test_d2c_golden_trace_v5_decision_seq.py` | **regression gate — must stay byte-identical** |

Layer 5 (driver smoke) is Batch 3; Layer 6 (hybrid forerunner) + cross-cutting registration Batch 4; Tier-2 DB byte-identity Batch 3.

---

## Acceptance gate (Batch 2 ships when ALL hold)

- [ ] `arguzz_bridge.py` exists with all §4.2 constants/functions; `valid_injection_kinds_for_instr` + the instruction-class sets are **verbatim** from `v6_driver_v2.py`.
- [ ] `MUTATION_KINDS_ARGUZZ_FULL` = 11 kinds (v6_driver order); `MUTATION_KINDS_ARGUZZ_SELECTED` = the 4 SELECTED; `_PRE_POST_BY_KIND` = 5 pre / 6 post.
- [ ] `semantic_arm_universe.build(arguzz_kinds=…, baseline_trace=…)` emits 5-field `ArmKey` Arguzz arms; `arguzz_kinds=None` is a **byte-identical no-op** (Tier-1 golden trace passes).
- [ ] **ISS-3 guard:** `build(arguzz_kinds=…, baseline_trace=None)` raises `ValueError` (test asserts it).
- [ ] Layer-4 arm-construction test green: applicability (a), opcode_class (b), `pre_post` (c), no-op default (d), guard (e).
- [ ] Layer-3 bridge test green, **scoped to bridge + real bandit** (ISS-5); asserts `include_trace=False` passed to `run` (ISS-1); ISS-4 mapping-coverage assertion passes.
- [ ] **Task 2.5 measurement done:** real FULL + SELECTED arm counts reported vs §1.2 + Batch-1 estimate; fallback-instruction log clean (ISS-4); if FULL > 300, reduction proposal written (ISS-2, proposal only).
- [ ] Pytest sweep (ignore-replicates path) at or above the recorded post-Batch-1 floor + 2 new test files; no regression; **Tier-1 golden trace byte-identical**.
- [ ] `bandit_ts.py`, `arguzz_invoke.py`, `arguzz_parser.py`, `coverage_db.py`, `compressed_global_extractor.py`, `v6_driver_v2.py`, `workspace/risc0-modified/` all unchanged.
- [ ] **Spec §15 updated:** ISS-1 (bridge half) → RESOLVED; ISS-3, ISS-4, ISS-5 → RESOLVED (with commit refs); ISS-2 row updated with measured count + proposal (stays OPEN pending Opus/Ivan ruling).
- [ ] `D2C_BATCH2_COMPOSER_REPORT.md` submitted.

---

## Workflow

1. **Pre-flight** (checklist above) → paste output; record the post-Batch-1 test floor; confirm the golden trace passes NOW.
2. **Read** §4.2/§4.3/§15 of the spec + D2.A §1.1 + the verbatim-copy sources in `v6_driver_v2.py`.
3. **Implement in order:** 2.1 bridge → 2.2 `build()` extension (run the golden trace immediately after) → 2.3 arm-construction test → 2.4 bridge test → 2.5 measurement → 2.6 full sweep → update spec §15 statuses → 2.7 report.
4. **Single commit to `cloud2`** (no feature branch, no PR). Co-authored-by line included.
5. **Self-checkpoint:** acceptance checklist 100% green before committing; the golden trace must be byte-identical.

---

## Report deliverable

At the end of Batch 2, write `a4/docs/cloud2/composer/D2C_BATCH2_COMPOSER_REPORT.md` covering:

1. **Pre-kickoff checklist output** (incl. the post-Batch-1 test floor + the golden-trace-passes-now line).
2. **What was implemented** — per-task summary with LOC counts.
3. **Bridge API** — confirm the verbatim copies (`valid_injection_kinds_for_instr`, instruction-class sets) match `v6_driver_v2.py`; confirm `_PRE_POST_BY_KIND` split (5 pre / 6 post) and the 7-class mapping.
4. **`build()` no-op proof** — Tier-1 golden trace byte-identical before & after task 2.2 (paste both runs).
5. **Layer-3 + Layer-4 test output** — paste; confirm ISS-1 (`include_trace=False`), ISS-3 (guard), ISS-4 (coverage) assertions.
6. **Task 2.5 measurement** — real FULL + SELECTED arm counts, vs §1.2 and vs Batch-1's 437/180; fallback-instruction log; **if FULL > 300, the reduction proposal** (levers + projected counts).
7. **Spec §15 status changes** — list which ISS-* you flipped to RESOLVED (with rationale) and the updated ISS-2 row.
8. **Test counts** — final tally vs the post-Batch-1 floor.
9. **Deviations** from spec/kickoff (and why).
10. **Open questions / surprises** for Ivan/Opus, and anything that affects Batch 3 (driver + fuzzer dispatch) design — especially the ISS-2 reduce-vs-keep decision and the ISS-1 D2.G fault-corroboration residual.

---

## Hand-off statement (paste when delegating to Composer)

> Implement D2.C Batch 2 per the locked spec at `a4/docs/cloud2/IV_POS_8_D2_C_SPEC.md` **v0.5** §11 "Batch 2" (tasks 2.1–2.7) and the §15 issue annex. Follow the workflow in `a4/docs/cloud2/composer/D2C_BATCH2_COMPOSER_KICKOFF.md`. Commit directly to `cloud2`, single commit, no feature branch, no PR. Batch 2 is the **bridge layer + arm-construction**: ship `a4/standalone/mutations/arguzz_bridge.py` (with `MUTATION_KINDS_ARGUZZ_FULL`/`_SELECTED`, `_PRE_POST_BY_KIND`, the verbatim `valid_injection_kinds_for_instr` + instruction-class sets from `v6_driver_v2.py`, `MAPPING_INSTR_TO_OPCODE_CLASS` onto the 7 D2.A LOCKED classes, and `create_mutation_for_arm` calling `arguzz_invoke.run(..., include_trace=False)`), extend `semantic_arm_universe.build` with `arguzz_kinds`/`baseline_trace` (raising `ValueError` when `arguzz_kinds` is set but `baseline_trace` is None), and add the Layer-3 bridge test (bridge + real bandit only — no `_dispatch_arm`) and the Layer-4 arm-construction test. Ship NO `fuzzer.py`/driver/scheduler change and do NOT wire `applied_accounting_mode`. The one load-bearing requirement: `build(arguzz_kinds=None)` must be a byte-identical no-op so the Tier-1 V5 golden trace stays identical — run it before and after. Honor spec §15 ISS-1 (`include_trace=False`), ISS-3 (guard), ISS-4 (mapping-coverage test), ISS-5 (bridge-test scope), and measure the real FULL/SELECTED arm counts for ISS-2 (propose reductions if FULL > 300 — proposal only). Update the §15 statuses you resolve. Pass criteria are the acceptance checklist in the kickoff. Submit `a4/docs/cloud2/composer/D2C_BATCH2_COMPOSER_REPORT.md`.

---

*End of D2.C Batch 2 kickoff. Report back at `D2C_BATCH2_COMPOSER_REPORT.md`; Opus reviews, updates spec §15, then issues the Batch 3 (driver + fuzzer dispatch) kickoff.*
