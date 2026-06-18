# IV.POS.8 D2.C — V6 / Arguzz Integration Spec

**Branch:** `cloud2` (direct commit, no feature branches)
**Date opened:** 2026-06-17
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Status:** **DRAFT v0.1** — needs Ivan review + §6 open-question resolution before Composer kickoff
**Parent:** [`IV_POS_8_D2_PLAN.md`](./IV_POS_8_D2_PLAN.md) v0.4 §3 (sub-deliverable D2.C)
**Predecessor:** [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) v0.2 LOCKED (D2.A foundation — merged at `7b66fb9`)
**Sibling:** [`IV_POS_8_D2_B_SPEC.md`](./IV_POS_8_D2_B_SPEC.md) v0.1 DRAFT (pure-A4 kind expansion — independent of D2.C)

---

## 0. What this document is

The implementation spec for **D2.C — V6/Arguzz integration**. Brings four Arguzz exec-fault mutation kinds into the bandit-eligible arm space, alongside modernizing the recovered `v6_driver_v2.py` so V6-uniform campaigns write through `CoverageDB` (gaining D2.A's outcome column, normalized telemetry, full A4 schema parity).

**Workflow:** Ivan reviews this draft → §6 open questions resolved → spec locked → Composer Batch 1 kickoff → Composer reports → Ivan + Opus review → iterate → D2.C complete.

---

## 1. Goal

D2.C delivers three coordinated outputs:

1. **A subprocess primitive** (`a4/standalone/arguzz_invoke.py`) — clean Python wrapper around `risc0-host --inject --inject-step <s> --inject-kind <k> --seed <s>` with parsing of `<trace>`, `<fault>`, `<constraint_fail>`, family residues, and prover-status tags. Returns a typed `ArguzzInvocationResult`.
2. **A bandit dispatcher** (`a4/standalone/mutations/arguzz_bridge.py`) — adapts the primitive to A4Fuzzer's `_create_mutation` contract for `surface=arguzz_exec_fault` arms, so V6-cTS and Hybrid-cTS (D2.D) can natively schedule Arguzz mutations through the same `cTS_semantic_v2` selector.
3. **A modernized V6-uniform driver** (`a4/standalone/v6_uniform_driver.py`) — drop-in replacement for `v6_driver_v2.py` that:
   - Writes through `CoverageDB` (D2.A schema, with `outcome` column, normalized `constraint_loc`)
   - Uses the new `arguzz_invoke` primitive (single source of truth for Arguzz invocation)
   - Preserves the balanced-round-robin scheduler verbatim (so V6-uniform stays "Arguzz-faithful" as the baseline)

### 1.1 The four V6 mutation kinds (Pro's Priority 2)

| # | Kind | What Arguzz does | Arguzz `<fault>` tag form |
|---|---|---|---|
| **C.1** | `INSTR_WORD_MOD` | Replace the instruction word the host is about to execute with a fully random `u32` | `"word:X => word:Y"` |
| **C.2** | `PRE_EXEC_MEM_MOD` | Mutate a random memory address right before the cycle executes; pick the address heuristically | `"MEM[$0xADDR] = VAL"` |
| **C.3** | `PRE_EXEC_PC_MOD` | Mutate the PC immediately before fetch (forces the host to fetch from a wrong address) | `"pc:X => pc:Y"` |
| **C.4** | `BR_NEG_COND` | Invert a branch condition (BEQ → !BEQ, etc.) at the executing branch | (kind-only fault tag) |

**Why these 4 (not the full 11 ENABLED_KINDS in v6_driver_v2.py):** Pro flagged these specifically in `ProG_Report_3.md` §13–14 as the V6 kinds with high coverage-yield-per-cost. The other 7 enabled kinds (`POST_EXEC_*`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD`) overlap heavily with A4's existing kinds (COMP_OUT_MOD, LOAD_VAL_MOD, STORE_OUT_MOD, PRE_EXEC_REG_MOD are all already pure-A4 kinds in `a4/standalone/mutations/`).

**Binary capacity is confirmed.** Per the earlier v0.2 → v0.3 master-plan investigation: existing R2 V6 DBs contain rows for all 7 kinds Pro requested, including all 4 of C.1–C.4. The Arguzz binary already supports these — no Rust work needed for D2.C.

### 1.2 Arm-shape mapping (D2.A §1.1 + §8)

D2.C is where the **5-field `ArmKey` actually gets exercised with non-`n/a` values for all 5 fields**. The mapping for each V6 kind:

| Kind | `surface` | `mutation_kind` | `semantic_zone` | `opcode_class` | `pre_post` |
|---|---|---|---|---|---|
| `INSTR_WORD_MOD` | `arguzz_exec_fault` | `INSTR_WORD_MOD` | from `step_to_zone` (e.g., `core_arithmetic`) | from instruction at step (e.g., `arith`, `mem_load`, `branch`, `system`) | `pre` (mutation applied before exec) |
| `PRE_EXEC_MEM_MOD` | `arguzz_exec_fault` | `PRE_EXEC_MEM_MOD` | zone | `arith`/`mem_load`/etc. of containing cycle | `pre` |
| `PRE_EXEC_PC_MOD` | `arguzz_exec_fault` | `PRE_EXEC_PC_MOD` | zone | `arith`/etc. of containing cycle | `pre` |
| `BR_NEG_COND` | `arguzz_exec_fault` | `BR_NEG_COND` | zone | `branch` (only branch ops are valid targets) | `pre` |

**This is the moment the synthetic test in D2.A §4.6 / §1.2 was rehearsing**: in D2.C, real Arguzz fuzzing produces arm pulls with non-trivial `opcode_class` and `pre_post`. The scheduler's arm-coverage logic (counts per arm, success rates per arm) becomes meaningful per-opcode-class.

### 1.3 Three-layer architecture

The cleanest way to share Arguzz invocation across V6-uniform AND V6-cTS / Hybrid-cTS is layered:

```
┌──────────────────────────────────────────────────────────────────┐
│ Driver layer (Python entry points)                               │
│                                                                  │
│  v6_uniform_driver.py     A4Fuzzer (selector=hybrid_cTS)         │
│  (balanced-round-robin    (cTS_semantic_v2 over Hybrid arms)     │
│   scheduler, V6-faithful) (D2.D wires this up)                   │
│            │                          │                          │
│            ↓                          ↓                          │
└────────────┼──────────────────────────┼──────────────────────────┘
             │                          │
┌────────────┼──────────────────────────┼──────────────────────────┐
│ Bridge layer                                                     │
│                                                                  │
│            │                  mutations/arguzz_bridge.py         │
│            │                  (adapts primitive to A4's          │
│            │                   _create_mutation contract for     │
│            │                   surface=arguzz_exec_fault arms)   │
│            │                          │                          │
│            ↓                          ↓                          │
└────────────┼──────────────────────────┼──────────────────────────┘
             │                          │
┌────────────┴──────────────────────────┴──────────────────────────┐
│ Primitive layer                                                  │
│                                                                  │
│              a4/standalone/arguzz_invoke.py                      │
│  (subprocess + UTF-8-safe decode + tag parsers + outcome mapper) │
│                                                                  │
│                          │                                       │
│                          ↓                                       │
│              risc0-host --inject --inject-step S --inject-kind K │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Why three layers (not two):**

- **Layer separation isolates the brittle subprocess + parsing concerns** in `arguzz_invoke.py`. Both downstream consumers (driver, bridge) get a typed `ArguzzInvocationResult` and don't have to know about UTF-8 decode, regex tags, or `subprocess.TimeoutExpired`.
- **`v6_driver_v2.py` recovery confirms the pattern.** It hand-rolled all three layers in 608 lines; we just refactor out the primitive cleanly.
- **`a4/arguzz_dependent/arguzz_runner.py` is the obsolete predecessor** — it has the same primitive job but with worse output handling (uses `text=True` which crashes on non-UTF-8 bytes; v6_driver_v2 explicitly fixed this with `_decode_safe`). D2.C **does not reuse** `arguzz_runner.py`; we adopt v6_driver_v2's improved invocation logic. See §6 Q1.

### 1.4 V6-uniform driver: modernize, not preserve as-is

Two options for `v6_driver_v2.py`:

| Option | Pros | Cons |
|---|---|---|
| **(A) Keep `v6_driver_v2.py` as-is, only use it for V6-uniform** | Zero behavioral risk; bit-identical R2 reproduction | Doesn't get D2.A's outcome column or normalized constraint_loc; can't be compared head-to-head with V5/Hybrid using the same analysis scripts; duplicates schema definitions |
| **(B) Replace with `v6_uniform_driver.py` that writes through `CoverageDB`** | Single schema across all variants; full A4 telemetry parity; D2.G analysis works uniformly; outcome column for free | Schema diff vs R2: R2 V6 DBs have raw `constraint_loc`, new V6 DBs will have `Name@basename:line` — D2.G analysis must normalize R2 historically for comparison |

**Recommended: (B) Replace.** D2.G analysis hinges on cross-variant comparability; if V6-uniform DBs have a different schema, we re-invent the post-hoc normalizer for every analysis. **And** the R2 V6 DBs are post-hoc-normalized today via `constraint_loc_normalize.py` — going through `CoverageDB` means we get the same canonicalization at write-time, which is exactly the D2.A §3.4 principle ("write canonical, don't normalize after").

We keep `v6_driver_v2.py` archived in `a4/runs/iv_pos_7/drivers/` as a reference implementation. The active V6-uniform driver becomes `a4/standalone/v6_uniform_driver.py`.

### 1.5 When do we actually test the mutations work? (Ivan question, 2026-06-17)

Per D2.B §1.4: testing is layered. For D2.C, here's where each layer fires:

| # | Layer | What it asserts | When (Composer batch) |
|---|---|---|---|
| **1** | **Subprocess mock test** (`tests/test_d2c_arguzz_invoke_mock.py`) | Stub `subprocess.run` to return canned Arguzz stdout (sampled from real R2 V6 logs). `arguzz_invoke.run()` parses correctly: extracts faults, failures, sets outcome correctly (timeout=ERROR, panic=ERROR, prove_success=APPLIED, prove_error=APPLIED, etc.). **Pure Python, no binary.** | Batch 1 |
| **2** | **Real-binary single-mutation test** (`tests/test_d2c_arguzz_invoke_real_binary.py`) | Gated on `A4_REAL_BINARY=1`: invoke `arguzz_invoke.run()` against the real risc0-host binary once per kind (C.1–C.4). Assert: at least 1 `<fault>` tag parsed; outcome mapped to APPLIED or APPLIED-with-failures; no unhandled exceptions. **This is the binary-level smoke** for D2.C. | Batch 1 (gates onward work) |
| **3** | **Bridge wiring test** (`tests/test_d2c_arguzz_bridge.py`) | Stub `arguzz_invoke.run()`; verify `arguzz_bridge.create_mutation_for_arm(ArmKey(surface="arguzz_exec_fault", ...), step)` produces a sensible config + invocation, and that `outcome` flows back to `MutationOutcome` correctly. **Mocked invocation, real bandit.** | Batch 2 |
| **4** | **V6-uniform driver end-to-end smoke** (`tests/test_d2c_v6_uniform_driver_smoke.py`) | Gated on `A4_REAL_BINARY=1`: run `v6_uniform_driver.py main(num=50)` once against the dev box's risc0-host. Assert: DB has 50 rows in `mutations`, all 4 kinds appear at least once, `outcome` column populated, `coverage.constraint_loc` is `Name@basename:line` format (normalized), `compressed_global_coverage` rows present. | Batch 3 |
| **5** | **A4Fuzzer Hybrid integration smoke** (`tests/test_d2c_hybrid_smoke.py`) | Stub `arguzz_invoke.run()`; run `A4Fuzzer.run_campaign(N=50, selector="hybrid_cTS")`; assert: both `surface=A4_trace_cell` and `surface=arguzz_exec_fault` arms get pulled, both contribute to `mutations.outcome=applied`, the cTS scheduler counts pulls separately for each surface. | Batch 4 (after D2.D variant lands; OR a forerunner with mock variant selection) |
| **6** | **POS smoke (D2.E)** | 4-variant N=200 mini-smoke. Confirms V6-uniform, V6-cTS, Hybrid-cTS all produce non-empty DBs on the real POS infrastructure. | D2.E (after D2.D) |

**Layer 2 is the load-bearing real-binary gate.** If the dev box's risc0-host doesn't actually emit `<fault>` tags for one of the 4 kinds, we discover it here, not in POS. The R2 V6 DBs serve as a sanity-check oracle: we already know what good Arguzz output looks like.

**Layer 4 is the schema-parity gate.** This is where we confirm the modernized V6-uniform driver produces DBs that are pairwise-comparable with V5/Hybrid DBs in D2.G analysis.

## 2. Non-goals (deliberately out of D2.C scope)

- **Pure-A4 kind expansion (D2.B)** — independent track
- **Variant CLI / fuzzer dispatch (D2.D)** — D2.C provides the primitives; D2.D wires them up
- **POS smoke (D2.E)** — D2.C ships local-only tests
- **Arguzz binary changes** — binary is treated as a black-box; we already verified capacity
- **`a4/arguzz_dependent/arguzz_runner.py` revival** — explicitly deprecated; new code path is `arguzz_invoke.py`. We do not delete `arguzz_runner.py` but we mark its docstring as legacy/deprecated. See §6 Q1.
- **`a4/arguzz_dependent/arguzz_parser.py` revival** — partially adopted (the `ArguzzFault` dataclass and regex patterns are battle-tested; the V6 parsing in v6_driver_v2 is regex-only). D2.C uses parser.py's parsing code via re-export from `arguzz_invoke.py`. See §4.1 + §6 Q2.
- **Subprocess pooling / parallelism** — single-process, single-subprocess at a time; this is what v6_driver_v2 does in production R2 runs

## 3. Codebase landscape

### 3.1 Already in tree

| File | Status | Role in D2.C |
|---|---|---|
| `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (608 lines) | Recovered in D2.A | Reference implementation; the scheduler + parsing patterns are copied into the new layered architecture |
| `a4/arguzz_dependent/arguzz_runner.py` (116 lines) | Obsolete | Legacy; ENV `CONSTRAINT_CONTINUE=1` pattern is useful, but `text=True` subprocess kwarg is the bug v6_driver_v2 fixed |
| `a4/arguzz_dependent/arguzz_parser.py` (181 lines) | Partially adopted | `ArguzzFault.parse()` regex handlers for all 5 fault formats (word, out, data, pc, reg_assign, mem_assign) are reused as-is via re-import from `arguzz_invoke.py` |
| `a4/standalone/compressed_global_extractor.py` | Already supports V6 kinds via `_TXN_ROLE_BY_KIND` mapping (v6_driver_v2 patches it in lines 74–84) | D2.C makes these patches permanent (move them into `_TXN_ROLE_BY_KIND` directly) |
| `a4/core/inspection_data.py` | Existing — provides `InspectionData.from_inspection(host, args)` | Reused as-is in `v6_uniform_driver.py` bootstrap |
| `a4/standalone/zone_classifier.py` | Existing — provides `classify_zones(insp)` | Reused as-is |

### 3.2 D2.A foundation in use

- `bandit_ts.MutationOutcome` enum (APPLIED, SKIPPED, ERROR) — D2.C maps Arguzz outcomes (timeout, panic, prove_success, prove_error, other) onto this enum
- `bandit_ts.ConstrainedTSScheduler.update_with_outcome()` — D2.C's bridge calls this for `surface=arguzz_exec_fault` arms
- `ArmKey.v5()` factory — D2.C **also uses the full 5-field constructor** for arguzz arms (NOT v5()) — see §4.3
- `mutations.outcome` column — D2.C populates this for every V6-uniform mutation row
- `ConstraintFailure.short_loc()` — D2.C ensures V6 `failures.constraint_loc` writes go through this normalization

### 3.3 D2.D's role (out of scope, but informs D2.C design)

D2.D will wire the four variants:

- **V5 (control)**: existing A4Fuzzer with `selector_strategy="cTS_semantic_v2"` over A4-only arms
- **V6-uniform**: `python v6_uniform_driver.py` (the modernized v6_driver)
- **V6-cTS**: `A4Fuzzer` with `selector_strategy="cTS_semantic_v2"` over Arguzz-only arms (using `mutations/arguzz_bridge.py`)
- **Hybrid-cTS**: `A4Fuzzer` with `selector_strategy="cTS_semantic_v2"` over A4 + Arguzz arms together

D2.C **enables** V6-uniform, V6-cTS, and Hybrid-cTS by providing the primitive + bridge; the CLI flags + variant selection are D2.D's responsibility.

## 4. Detailed change list (file by file)

### 4.1 `a4/standalone/arguzz_invoke.py` (NEW — primitive layer)

| Item | Detail |
|---|---|
| `ArguzzInvocationResult` dataclass | Fields: `rc: int`, `outcome: MutationOutcome` (from D2.A), `prover_status: str` (success/error/none), `wall_s: float`, `faults: list[ArguzzFault]`, `failures: list[ConstraintFailure]`, `family_residues: list`, `family_details: list`, `global_residue: dict`, `raw_stdout: str` (kept for debugging, may be large) |
| `run(host, host_args, step, kind, seed, timeout=90)` | Pure function; replicates v6_driver_v2's `run_inject` + tag parsing + outcome classification. Returns `ArguzzInvocationResult`. **Single source of truth for Arguzz invocation.** |
| `_decode_safe(b)` | Copied from v6_driver_v2 — UTF-8 safe decode for non-UTF-8-clean panic dumps |
| `_classify_outcome(rc, stdout, prover_status, has_failures)` | Maps to `MutationOutcome`: `rc=124 → ERROR (timeout)`; `"panicked at" in stdout → ERROR (panic)`; `prover_status="success" → APPLIED`; `prover_status="error" and has_failures → APPLIED` (constraint check fired = mutation was applied); `prover_status="error" and not has_failures → ERROR` (guest crashed before constraint check, matching arguzz_runner.py guest_crashed logic); `else → APPLIED` (catch-all) |
| Re-exports | `ArguzzFault` (from `arguzz_parser.py`) and `ConstraintFailure` (from `a4.core.constraint_parser`) for downstream convenience |
| Logging | Quiet by default; structured INFO logging available via `logging.getLogger("a4.arguzz_invoke")` for debugging |

**No env var bleeding:** `CONSTRAINT_CONTINUE=1` is set in the subprocess env only (per v6_driver_v2). No reliance on the parent process env.

### 4.2 `a4/standalone/mutations/arguzz_bridge.py` (NEW — bridge layer)

| Item | Detail |
|---|---|
| Acts as a "pseudo-mutation-module" | Implements the same surface as `instr_word_mod_sur.py` etc., but for `surface=arguzz_exec_fault` arms |
| `ArguzzBridgeTarget` dataclass | Fields: `step, kind, instruction, opcode_class, pre_post="pre"`. **No config_json written to disk** — Arguzz takes step + kind directly via CLI |
| `get_targets_at_step(step, data, kind)` | Returns an `ArguzzBridgeTarget` if `step` is a valid Arguzz target for `kind` (per `valid_injection_kinds_for_instr(instr)` logic from v6_driver_v2 lines 176–192). The Arguzz scheduler's per-instruction validity is the source of truth. |
| `get_valid_steps(data, kind)` | Returns all steps whose instruction class allows `kind`. |
| `create_mutation_for_arm(arm: ArmKey, step: int, host, host_args, seed) -> tuple[MutationOutcome, ArguzzInvocationResult]` | The bridge entry: takes an arm + step picked by `A4Fuzzer`'s scheduler, calls `arguzz_invoke.run()`, returns the outcome + raw result. Fuzzer uses the outcome for `update_with_outcome()` and stores the result in `mutations.config_json + failures + global_failures` etc. |
| `MAPPING_TO_OPCODE_CLASS` | Dict mapping risc0 instruction names to D2.A §1.1's `opcode_class` values. E.g., `"add"→"arith"`, `"lw"→"mem_load"`, `"sw"→"mem_store"`, `"beq"→"branch"`, `"jal"→"jump"`, `"eany"→"system"`, etc. |

### 4.3 `a4/standalone/semantic_arm_universe.py` (EXISTING — extend)

| Change | Detail |
|---|---|
| New arm-construction path for Arguzz arms | When building the universe, add Arguzz arms with **full 5-field `ArmKey`** (NOT `ArmKey.v5()`): `ArmKey(surface="arguzz_exec_fault", mutation_kind=k, semantic_zone=z, opcode_class=oc, pre_post="pre")`. This is what D2.A §1.1 was preparing for. |
| `_ARGUZZ_KINDS` constant | Tuple of the 4 Arguzz kinds: `("INSTR_WORD_MOD", "PRE_EXEC_MEM_MOD", "PRE_EXEC_PC_MOD", "BR_NEG_COND")` |
| `build()` extended | After existing A4-arm loop, iterate over Arguzz kinds: for each kind × valid step → derive zone, opcode_class → emit Arguzz arm |
| `arm_id_for_decision()` (D2.A added) | Already returns 5-pipe string for non-v5-shape arms — no change |
| **Toggle:** `include_arguzz_kinds: bool = False` parameter | Default False (preserves V5 behavior). Set True for V6-cTS and Hybrid-cTS variants (D2.D wires this). |

### 4.4 `a4/standalone/fuzzer.py` (EXISTING — extend)

| Change | Detail |
|---|---|
| `_create_mutation(kind, step)` dispatch | New branch: if the picked arm's surface is `arguzz_exec_fault`, dispatch to `arguzz_bridge.create_mutation_for_arm(...)` instead of writing a config file. Returns a different shape: `ArguzzInvocationResult` instead of `(config_path, mutated_value, original_value)`. |
| `_run_v2_bandit_mutation(arm, step, ...)` | When dispatching to bridge, skip the `subprocess.run(host, --mutation-config, ...)` path that A4 mutations use. The bridge's `create_mutation_for_arm` invokes the host directly via `--inject`. |
| `_record_arguzz_mutation(arm, step, result: ArguzzInvocationResult)` (NEW helper) | Writes the row to `mutations` table with: `kind=arm.mutation_kind`, `config_json=json.dumps({"kind":k, "step":s, "instruction":instr, "iter_seed":seed, "wall_s":w, "rc":r, "prover_status":p, "outcome":out, "zone":z, "major":m})`, `outcome=result.outcome.value` (so D2.A's outcome column gets populated for Arguzz too). |
| Failures + CGC | Iterate `result.failures` and write via `record_failure` (existing); iterate `result.family_details` and call `extract_compressed_global_contexts` (existing). |

### 4.5 `a4/standalone/v6_uniform_driver.py` (NEW — modernized driver layer)

Effectively `v6_driver_v2.py` refactored to:

| Change vs v6_driver_v2.py | Detail |
|---|---|
| Replace `run_inject` + tag parsers | Use `arguzz_invoke.run()` |
| Replace inline `DB_SCHEMA` | Use `CoverageDB` from `a4.standalone.coverage_db` |
| Replace `cur.execute("INSERT INTO mutations ...")` | Use `CoverageDB.record_mutation(...)` (gets normalized `constraint_loc` + `outcome` column for free) |
| Replace `cur.execute("INSERT INTO failures ...")` | Use `CoverageDB.record_failure(...)` |
| Replace `cur.execute("INSERT INTO global_failures ...")` | Use `CoverageDB.record_global_failure(...)` |
| Replace `cur.execute("INSERT INTO compressed_global_coverage ...")` | Use `CoverageDB.record_compressed_global_coverage(...)` (or whatever the existing helper is named) |
| **Keep** the `ArguzzScheduler` (balanced round-robin) class verbatim | This is the V6-faithful baseline; do not touch |
| **Keep** the bootstrap (host --trace + InspectionData + classify_zones) verbatim | Same as v6_driver_v2 lines 389–430 |
| **Keep** the `_TXN_ROLE_BY_KIND` patches | Move into `compressed_global_extractor.py` permanently (see §4.6) so V6-uniform doesn't have to patch at runtime |
| **CLI args**: same as v6_driver_v2 | `--host`, `--db`, `--seed`, `--num`, `--progress-every`, `--label`, host_args after `--` |
| Module entry: `python -m a4.standalone.v6_uniform_driver` | Or via D2.D's variant CLI |

### 4.6 `a4/standalone/compressed_global_extractor.py` (EXISTING — extend)

| Change | Detail |
|---|---|
| Merge `_ARGUZZ_KIND_ROLE_EXTENSIONS` permanently into `_TXN_ROLE_BY_KIND` | Per v6_driver_v2 lines 74–84. The `setdefault` pattern is preserved (no overwrite of existing entries). |
| `_TXN_ROLE_BY_KIND` additions | `PRE_EXEC_PC_MOD: "ifetch"`, `POST_EXEC_PC_MOD: "ifetch"`, `BR_NEG_COND: "ifetch"`, `POST_EXEC_REG_MOD: "register"`, `PRE_EXEC_MEM_MOD: "read"`, `POST_EXEC_MEM_MOD: "write"`. These are the lines 74–81 in v6_driver_v2; they should live in the canonical extractor file. |

### 4.7 `a4/arguzz_dependent/arguzz_runner.py` (EXISTING — deprecate)

| Change | Detail |
|---|---|
| Add deprecation docstring | "**Legacy / R2-compat only.** D2.C onward, Arguzz invocation lives in `a4/standalone/arguzz_invoke.py` (UTF-8-safe subprocess, MutationOutcome mapping, ConstraintFailure parsing via short_loc). Do not import this module in new code." |
| No code changes | Keep the module functional for any in-tree script that still uses it; just signal away new use |

### 4.8 New tests

| Test file | Layer | Asserts | Real binary? |
|---|---|---|---|
| `tests/test_d2c_arguzz_invoke_mock.py` | 1 (mock) | `arguzz_invoke.run()` parses canned Arguzz stdout correctly; outcome mapping covers all 5 cases (timeout, panic, prove_success, prove_error_with_failures, prove_error_without_failures) | No |
| `tests/test_d2c_arguzz_invoke_real_binary.py` | 2 (real, gated) | Real binary, 4 kinds × 1 invocation each. Assert: at least 1 fault tag parsed per kind; outcome in {APPLIED, ERROR}; `wall_s < 90` (timeout). | **Yes** (gated on `A4_REAL_BINARY=1`) |
| `tests/test_d2c_arguzz_bridge.py` | 3 (mock bridge + real bandit) | Bandit picks an Arguzz arm; bridge dispatches; outcome flows to `update_with_outcome` correctly | No (stubbed primitive) |
| `tests/test_d2c_arguzz_arm_construction.py` | 2 (unit) | `SemanticArmUniverse.build(include_arguzz_kinds=True)` produces arms with 5-field ArmKey; opcode_class derived correctly for branch / arith / load / etc. | No (synthetic InspectionData) |
| `tests/test_d2c_v6_uniform_driver_smoke.py` | 4 (real, gated) | Real binary, N=50 run. Assert: 50 `mutations` rows; all 4 kinds present; `outcome` column populated; `coverage.constraint_loc` is `Name@basename:line`; `compressed_global_coverage` non-empty | **Yes** (gated on `A4_REAL_BINARY=1`) |
| `tests/test_d2c_outcome_mapping.py` | 1 (unit) | `_classify_outcome` covers all 8 boundary cases of (rc, stdout, prover_status, has_failures); guest_crashed semantics (no failures + prover error → ERROR) is correct | No |

### 4.9 Files that **must not change** in D2.C

- `a4/standalone/bandit_ts.py` (D2.A foundation; no scheduler change)
- `a4/standalone/coverage_db.py` (D2.A schema; no migrations)
- All existing `a4/standalone/mutations/*.py` (A4 kinds untouched)
- `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (frozen reference; do not modify)
- `a4/standalone/cli.py` (D2.D)
- `a4/arguzz_dependent/arguzz_parser.py` (preserve as-is; D2.C imports from it)

## 5. Decision matrix — primitive vs bridge vs driver responsibilities

| Concern | Primitive (`arguzz_invoke`) | Bridge (`arguzz_bridge`) | Driver (`v6_uniform_driver` or A4Fuzzer) |
|---|---|---|---|
| Subprocess invocation | ✅ owns | uses | uses (via bridge or directly) |
| Tag parsing (`<fault>`, `<trace>`, `<constraint_fail>`) | ✅ owns | uses | uses |
| UTF-8 safe decode | ✅ owns | n/a | n/a |
| Outcome classification | ✅ owns | passes through | uses |
| Arm-shape construction | n/a | n/a | ✅ (via `semantic_arm_universe`) |
| Picking step/kind | n/a | ✅ (validates kind for instr at step) | ✅ (scheduler picks the arm) |
| DB writes | n/a | n/a | ✅ |
| Scheduler logic | n/a | n/a | ✅ (round-robin in V6-uniform driver, cTS in A4Fuzzer) |
| `_TXN_ROLE_BY_KIND` extensions | n/a | n/a (already in `compressed_global_extractor`) | imports + uses |

Clean separation; no circular deps.

## 6. Open questions (D2.C-specific; need Ivan resolution before Composer kickoff)

| # | Question | My recommendation | Why I'm asking, not deciding |
|---|---|---|---|
| **Q1** | **`a4/arguzz_dependent/arguzz_runner.py` — keep or delete?** | **Keep, deprecate.** Per D2.A pattern (`constraint_loc_normalize.py`), legacy modules get a docstring banner but aren't removed. The R2 archaeological scripts may still reference it. | Deletion is irreversible; deprecation is reversible. We can fully delete in IV.POS.9 cleanup. |
| **Q2** | **`a4/arguzz_dependent/arguzz_parser.py` — import from it, or copy the regex parsing into `arguzz_invoke.py`?** | **Import from it.** The 5-format `ArguzzFault.parse()` is well-tested; rewriting risks introducing format-handling bugs. Copying is also fine if Ivan wants the new modular layer to have zero dependencies on `a4/arguzz_dependent/`. | Importing keeps the parser in its tested location; copying isolates D2.C from `arguzz_dependent/` cleanup risk. |
| **Q3** | **V6-uniform driver: keep `v6_driver_v2.py` as the production driver and ship `v6_uniform_driver.py` as additional, OR replace v6_driver_v2 entirely?** | **Replace.** Per §1.4, the schema-parity argument is decisive. v6_driver_v2 stays as a frozen reference in `a4/runs/iv_pos_7/drivers/` for R2 reproducibility, but not as the active driver. | Keeping both creates confusion + dual maintenance burden; the recovery story (v6_driver_v2 → modernized v6_uniform_driver) is cleaner. |
| **Q4** | **Outcome mapping for `prover_status="error" and has_failures=True`.** Is this APPLIED (the mutation triggered the constraint check, which is the whole point) or ERROR? | **APPLIED.** The mutation took effect (we got constraint failures from the prover — that's the whole point). The prover then exited with error because failures are fatal. This is the desired behavior of the mutation, not a primitive failure. | This is a subtle semantic choice. Pro's intent for "applied" was "the mutation actually mutated the witness". Constraint failures confirm that yes, it did. The arguzz_runner.py "guest_crashed" check (line 86–92) is for the case where there are *zero* failures AND prover error — i.e., the guest died before the prover could check constraints. **That** case is ERROR. |
| **Q5** | **Should V6-uniform driver carry over v6_driver_v2's `extra_json` shape?** (`{"num": ..., "scheduler": "balanced_round_robin", "driver_version": "v2.1_utf8safe", "compressed_extractor": "a4.compressed_global_extractor"}`) | **YES, with a version bump.** Set `driver_version: "v3_d2c"`. Other fields preserved. This lets D2.G analysis distinguish R2 V6 DBs from D2.C V6 DBs. | Changing the extra_json schema breaks R2 reproducibility scripts that parse it; preserving with version bump is the careful move. |
| **Q6** | **Iteration seed scheme for V6-uniform driver.** v6_driver_v2 uses `iter_seed = args.seed * 1_000_000 + i`. Reproducibility requires preserving this. | **Preserve exactly.** v6_driver_v2 is a known-good baseline; we should not change RNG seeding without reason. | If the seeding scheme changes, V6-uniform on the same `--seed` produces different results vs R2 — undermines the "control vs. treatment" comparison story. |
| **Q7** | **Arguzz arms inherit `mutation_zone` from the **target step's zone** (instr that's about to execute), not from the **broken constraint's zone** (post-execution).** Is this right? | **YES.** Per v6_driver_v2 line 493 (`zone = step_to_zone.get(step, "core_other")`), the zone is derived from the instruction the mutation targets. This matches A4's semantic for pre-execution mutations. | Post-execution zone derivation could pull from constraint failure cycle, but that's how `compressed_global_extractor` already groups CGC; for arm-shape on the schedule side, pre-zone is correct. |
| **Q8** | **`opcode_class` derivation — from the instruction class at the targeted step.** What canonical taxonomy? | **6 classes:** `arith` (ADD, SUB, XOR, OR, AND, SLT, SLTU, SLL, SRL, SRA, MUL, DIV, REM, LUI, AUIPC, IMM variants), `mem_load` (LB, LH, LW, LBU, LHU), `mem_store` (SB, SH, SW), `branch` (BEQ, BNE, BLT, BGE, BLTU, BGEU), `jump` (JAL, JALR), `system` (ECALL, MRET, EBREAK). | This is a key arm-discriminator now that opcode_class is populated. Pro will want to see per-class coverage breakdown in D2.G. |
| **Q9** | **Hybrid-cTS arm space size.** With 8 V5 kinds + 3 D2.B kinds + 4 D2.C kinds × 6 opcode_classes × ~10 zones — could be 200–500 arms. Is this within Pro's acceptable bandit-arms range? | **Calculate during Composer Batch 1; report in `D2C_BATCH1_REPORT.md`.** Pro's ProG_Report_3.md §17 cited "100s of arms" as the soft ceiling; if we exceed it, we may need to either (a) reduce opcode_class cardinality (merge `jump` into `branch`), or (b) drop zones below a min-step threshold. | Don't pre-decide; let actual data inform. |
| **Q10** | **Composer Batch granularity.** One big batch (primitive + bridge + driver) or three sub-batches? | **Three sub-batches:** Batch 1 = primitive + binary-real-gate test; Batch 2 = bridge + arm-construction; Batch 3 = V6-uniform driver + end-to-end smoke. Each gated on prior. | Single batch is ~800 LOC + ~6 tests — too big for clean review. Three batches give us cleaner gates. |
| **Q11** | **Should `arguzz_invoke.py` time out at 90s like v6_driver_v2, or shorter for tests?** | **Configurable; default 90s.** Per v6_driver_v2 timeout. Test code uses `timeout=30` to fail fast. | Hard-coding 90s would make the primitive un-testable without long waits. |
| **Q12** | **Do we need a smoke for the `--inject-kind` CLI flag itself (Arguzz binary contract)?** | **Implicit** via Batch 1 test 2 (real-binary single-mutation per kind). If the flag changed, the binary call would fail. We don't need a separate "does the flag still exist" test. | Some teams add a contract test for every CLI flag they depend on; for D2.C the kind-coverage test subsumes it. |

## 7. Composer task breakdown (proposed)

Pending §6 lock-in; not started.

### Batch 1 — Primitive layer + real-binary smoke

**Goal:** Build `arguzz_invoke.py` + prove it works with the real risc0-host binary.

| Task | File(s) | Notes |
|---|---|---|
| 1.1 | Write `arguzz_invoke.py` | `run()`, `ArguzzInvocationResult`, `_decode_safe`, `_classify_outcome` |
| 1.2 | Move `_TXN_ROLE_BY_KIND` patches into `compressed_global_extractor.py` permanently | §4.6 |
| 1.3 | Add deprecation docstring to `a4/arguzz_dependent/arguzz_runner.py` | §4.7 |
| 1.4 | Mock test (`test_d2c_arguzz_invoke_mock.py`) | Layer 1 |
| 1.5 | Outcome-mapping unit test (`test_d2c_outcome_mapping.py`) | Layer 1 |
| 1.6 | **Real-binary smoke** (`test_d2c_arguzz_invoke_real_binary.py`) | Layer 2 — **gating** |
| 1.7 | Arm-space size calculation (per Q9); report in batch report | Calc only — no code change here |
| 1.8 | Full pytest sweep | ≥515 tests green |
| 1.9 | Write `D2C_BATCH1_COMPOSER_REPORT.md` | Layer 2 proof; arm-space size; any binary surprises |

**Pass criteria for Batch 1:** real-binary test passes for all 4 kinds; mock tests green; full pytest green; report submitted.

### Batch 2 — Bridge layer + arm-construction

**Goal:** Wire Arguzz arms into `SemanticArmUniverse`; build the bridge dispatcher.

| Task | File(s) | Notes |
|---|---|---|
| 2.1 | Write `mutations/arguzz_bridge.py` | §4.2 |
| 2.2 | Extend `semantic_arm_universe.py` with `include_arguzz_kinds=True` toggle | §4.3 |
| 2.3 | Arm-construction unit test (`test_d2c_arguzz_arm_construction.py`) | Layer 2 |
| 2.4 | Bridge wiring test (`test_d2c_arguzz_bridge.py`) | Layer 3 |
| 2.5 | Full pytest sweep | ≥517 tests green |
| 2.6 | Write `D2C_BATCH2_COMPOSER_REPORT.md` | Bridge + arm-construction summary |

**Pass criteria for Batch 2:** layer-3 test green; bandit `select()` returns 5-field ArmKey arms with `surface=arguzz_exec_fault`; report submitted.

### Batch 3 — V6-uniform driver + end-to-end smoke

**Goal:** Modernize v6_driver_v2 → v6_uniform_driver; ship D2.A schema parity.

| Task | File(s) | Notes |
|---|---|---|
| 3.1 | Write `a4/standalone/v6_uniform_driver.py` | §4.5 |
| 3.2 | Extend `a4/standalone/fuzzer.py` with Arguzz-arm dispatch in `_create_mutation` + `_record_arguzz_mutation` | §4.4 |
| 3.3 | **End-to-end smoke** (`test_d2c_v6_uniform_driver_smoke.py`) | Layer 4 — **gating** |
| 3.4 | Full pytest sweep | ≥518 tests green |
| 3.5 | Sanity-check: produce a 50-mutation V6 DB; inspect schema vs R2 V6 DBs (with normalized constraint_loc) | Composer notes which fields are now normalized at write-time |
| 3.6 | Write `D2C_BATCH3_COMPOSER_REPORT.md` | DB schema parity proof; layer-4 results |

**Pass criteria for Batch 3:** layer-4 test green; DB schema matches `CoverageDB` (with `outcome` column populated for Arguzz mutations); report submitted.

### Batch 4 — Hybrid integration smoke (cross-cuts with D2.D)

**Goal:** Validate the Hybrid-cTS path end-to-end before D2.D variant CLI lands.

| Task | File(s) | Notes |
|---|---|---|
| 4.1 | Write `test_d2c_hybrid_smoke.py` | Layer 5 — stubbed primitive; mocked variant selection |
| 4.2 | Full pytest sweep | ≥519 tests green |
| 4.3 | Update `IV_POS_8_D2_PLAN.md` D2.C status row | "DONE" |
| 4.4 | Write `D2C_BATCH4_COMPOSER_REPORT.md` | Final D2.C summary |

**Pass criteria for Batch 4:** Hybrid test green; cTS scheduler shows pulls from both surfaces; report submitted.

## 8. Decisions Confirmed

(empty until Ivan resolves §6)

| # | Question | Resolution | Resolved on |
|---|---|---|---|
| — | — | — | — |

## 9. Risks + mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Real-binary test (Layer 2) fails for one of the 4 kinds — binary doesn't actually support it on the dev box | Low (we have R2 V6 DBs proving all 4 emit faults), but possible if dev binary is stale | Composer logs the actual `--inject-kind` output; if empty, escalate; dev binary may need rebuild |
| `arguzz_parser.py` `ArguzzFault.parse()` regex misses a fault format Arguzz binary now emits (drift since v6_driver_v2 days) | Low | Compare canned R2 V6 outputs to current binary output in Batch 1; document any drift |
| `CoverageDB.record_mutation` API doesn't fit the V6-uniform driver's data flow (e.g., needs different fields) | Medium | Batch 3 task 3.5 is the place to surface this; may require minor `CoverageDB` extension (added in D2.C scope if needed) |
| Hybrid arm-space too large (Q9 > 500 arms) | Medium | Batch 1 task 1.7 surfaces this early; if exceeded, descope opcode_classes per Q9 fallback |
| `_create_mutation` dispatch in `fuzzer.py` becomes too branchy (A4 path + Arguzz path) | Low | Refactor into two helper methods if it crosses ~80 LOC; clean separation between A4 and Arguzz dispatch |
| Outcome mapping (Q4) produces misleading APPLIED-count metrics (e.g., timeouts count as ERROR but feel like "the mutation was applied, the prover just took too long") | Low | Document Q4 decision in `D2C_BATCH1_REPORT.md`; D2.G analysis can re-classify if needed |
| Schema diff between R2 V6 DBs (raw constraint_loc) and D2.C V6 DBs (normalized constraint_loc) breaks legacy R2 analysis scripts | Medium | Document explicitly in §1.4 + Batch 3 report; D2.G's "compare V6 R2 vs V6 D2.C" plot will need a one-time R2 normalization pass (already exists as `constraint_loc_normalize.py`) |
| The `--inject-kind` flag isn't on the dev binary (only the prod / POS binary) | Low | Batch 1 real-binary test surfaces this immediately; Composer reports back |

## 10. What ships at the end of D2.C

- 1 new primitive module (`a4/standalone/arguzz_invoke.py`)
- 1 new bridge module (`a4/standalone/mutations/arguzz_bridge.py`)
- 1 new driver module (`a4/standalone/v6_uniform_driver.py`)
- Extension of `semantic_arm_universe.py` with Arguzz-arm support (toggle)
- Extension of `fuzzer.py`'s `_create_mutation` + new `_record_arguzz_mutation`
- Permanent merge of `_TXN_ROLE_BY_KIND` Arguzz extensions into `compressed_global_extractor.py`
- Deprecation docstring on `a4/arguzz_dependent/arguzz_runner.py`
- 6 new test files (1 mock per-layer, 2 real-binary gated, 3 unit + integration)
- ~519 tests green total (510 D2.A + ~5–9 new logical D2.B + ~5–6 new logical D2.C — final count depends on D2.B landing first)
- 4 Composer reports (1 per batch) + this spec annotated with Decisions Confirmed
- D2 plan updated with "D2.C → DONE"
- Frozen reference: `a4/runs/iv_pos_7/drivers/v6_driver_v2.py` (unchanged)

---

*End of D2.C spec v0.1. Open questions Q1–Q12 in §6 need Ivan's answer before Composer Batch 1 kickoff. Binary capacity is **confirmed** (per R2 V6 DBs); the binary-level real-test in Layer 2 is the main de-risking gate.*
