# IV.POS.8 D2 (Hybrid V7) — Implementation Plan

**Branch:** `cloud2`
**Date opened:** 2026-06-16
**Author:** Ivan + Opus (planning); Composer (implementation, future batches)
**Status:** **DRAFT v0.3** — Ivan reviewed v0.2; D2.A spec locked at v0.2 (`IV_POS_8_D2_A_SPEC.md`); v6_arguzz driver search elevated to explicit D2.C task with search leads documented
**Parent:** [`IV_POS_8_PRELIMINARY_PLAN.md`](./IV_POS_8_PRELIMINARY_PLAN.md) — the 4-deliverable master plan
**Sibling specs (D1):** [`IV_POS_8_D1_A_SPEC.md`](./IV_POS_8_D1_A_SPEC.md) (locked, running on POS)
**Sibling specs (D2):** [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) (D2.A — foundation; in review)

## Changelog

- **v0.3 (2026-06-16):** Ivan-review pass v2:
  - Ivan accepted all 11 D2.A spec §6 open-question recommendations → D2.A spec locked at v0.2 (see `IV_POS_8_D2_A_SPEC.md` §8).
  - Ivan flagged that the v0.2 plan validated the new arm fields only by D2.D/D2.E. **Mitigation locked in D2.A v0.2:** new Batch 1 scheduler-level synthetic test (`test_d2a_arm_shape_arguzz_simulation.py`) exercises all 5 fields with non-trivial values; full arm-shape correctness gated at end of D2.A.
  - Ivan emphasized that the `v6_arguzz` driver is in the repo and needs a better search. Search to-date is documented in §2.2 (negative result across cloud2/main git history, sibling repos, backup patches); elevated to an explicit D2.C task §4 with concrete next-step leads for Composer.
  - Ivan noted branch flexibility allows overwriting old code if helpful for the 2→5 tuple refactor. Opus recommendation (locked in D2.A spec §8 cross-cutting decision): **keep back-compat overload** — surface is ~5 lines, payoff is V5 RNG byte-identity + R2 V5 archive reuse (~3 h POS savings).
- **v0.2 (2026-06-16):** Ivan-review pass v1:
  - D2.0 (Pro-facing design proposal) dropped as a separate sub-deliverable. Workflow is now "opus plan → composer implementation report → review → iterate" per sub-deliverable; final Pro-facing document is assembled at the end of D2 by summarizing the accumulated plan + reports. Sub-deliverable count drops from 8 to 7.
  - "Single biggest unknown" (§2) updated with evidence: V6 R2 DBs already contain all 7 of Pro's V6 kind menu items (`INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`, `POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_PC_MOD`, plus `PRE_EXEC_REG_MOD`). The "binary survey spike" is collapsed from 1 day to a ~30-minute smoke check.
  - `a4/arguzz_dependent/` file map clarified (§2): only `arguzz_runner.py` and `arguzz_parser.py` are reused for D2; rest of the directory (`cli.py`, `comparison.py`, `step_mapper.py`, `mutations/`) is from the obsolete "find a matching A4 mutation for each Arguzz fault" workflow and stays untouched.
  - Normalized-loc-at-source clarified (§2 + D2.A spec): V5 DBs already normalize at write-time (via `ConstraintFailure.short_loc()` in `record_failures`). Only V6 R2 DBs ship raw `Name(zirgen/.../file.zir:line)` strings, because the V6 driver bypassed `short_loc()`. D2.A only needs a parity test for V5 + a deprecation marker on the post-hoc normalizer.

---

## 0. Context — what this document is and is not

### Why this chat exists (the fork)

Ivan forked the original IV.POS.8 chat into two parallel tracks:

| Track | What it does | Status |
|---|---|---|
| **Track-α (the "POS finish" chat)** | Watch D1.A POS Batches 3 and 4 land, collect 20 DBs, validate, build `D1A_SUBSECTION.md` + companion plots/CSVs. Then sequentially handle D1.B (CGC variant reanalysis) and D1.C (metric stack instrumentation). Bundles into `IV_POS_8_D1_REPORT_FOR_PRO.md` + notebook. | running |
| **Track-β (this chat)** | Build the **D2 (Hybrid V7) implementation and Pro-facing design proposal** in parallel, so that when Track-α finishes and Pro greenlights the D2 design, we can dispatch the D2 POS campaign **immediately** instead of waiting weeks. | starting now |

This split is the same incremental-delivery argument that justified the 4-deliverable structure in `IV_POS_8_PRELIMINARY_PLAN.md` §1 — we want to minimize idle time while Pro is reviewing D1.

### What this document is

A **master plan** for everything Track-β does. It is the analogue of `IV_POS_8_D1_A_SPEC.md` but one level up: it defines the sub-deliverables, their dependencies, the open questions, and the order Composer will work in. It is **not** itself an implementation spec — each sub-deliverable will get its own spec (D2.A_SPEC, D2.B_SPEC, …) that Composer reviews before implementing.

### What this document is not

- It is **not** the Pro-facing document. That is `IV_POS_8_D2_DESIGN_PROPOSAL.md` (= sub-deliverable D2.0 below).
- It is **not** committing Track-β to anything before Ivan reviews it. Composer does not start work from this document. Each sub-deliverable spec gets its own Ivan + Opus review.
- It does **not** revisit D1 scope. D1.B / D1.C / D1.X are owned by Track-α.

---

## 1. What D2 is (recap from preliminary plan + Pro report)

Pro's §15 Priority 1 (Hybrid V7) and Priority 3 (pure-A4 expansion) are the core of D2. Pro's words:

> A4-V5 semantic-zone scheduler + selected V6-only kinds + applied-mutation-aware accounting + normalized loc and CGC telemetry. Run V5 vs V6-uniform vs V6-cTS vs Hybrid-cTS, 10 paired seeds, N=6000.

Pro additionally specified (§8 Track B, §15 Priority 3) a pure-A4 kind expansion:

> 1. TXN_PREV_WORD_MOD  2. TXN_PREV_CYCLE_MOD  3. CYCLE_MODE_MOD  4. TXN_CYCLE_PHASE_MOD  5. CYCLE_PC_MOD

The preliminary plan §3.D recommended a **curated subset for the first D2 ship** — 4 V6 kinds + 3 A4 kinds — to keep the arm-space size manageable. Pro can expand on review.

### Arm shape Pro recommended

```
arm = (mutation_surface, mutation_kind, semantic_zone, opcode_class, pre/post)
where mutation_surface ∈ {A4_trace_cell, arguzz_exec_fault}
```

### Variants to compare (4)

| Variant | Surface | Scheduler | Notes |
|---|---|---|---|
| **V5** (control) | `A4_trace_cell` only (current 8 kinds) | V5 cTS_semantic_v2 (constant floor 0.55) | Reuse D1.A static archive |
| **V6-uniform** | `arguzz_exec_fault` only | Arguzz native (uniform over applicable) | Current `a4.arguzz_dependent.cli` path, kept honest |
| **V6-cTS** | `arguzz_exec_fault` only | V5 scheduler over Arguzz kinds | Tests "does cTS help Arguzz?" |
| **Hybrid-cTS** | both surfaces | V5 scheduler over union arm-space | The headline architecture |

### Compute (target, paired)

- 10 paired seeds × 4 variants × N=6000 = **40 jobs**, ~12 h wall on 8 POS nodes (sequential across ~2–3 reservations).
- V5 reuse from D1.A archive cuts this to **30 new jobs** (~9 h wall).

---

## 2. What the codebase already gives us (grounded, not guessed)

| Asset | Path | Reuse plan in D2 |
|---|---|---|
| V5 cTS semantic-zone scheduler | `a4/standalone/bandit_ts.py` (`ConstrainedTSScheduler`, `FloorSchedule` family from D1.A) | Carries directly into V6-cTS and Hybrid-cTS |
| V5 standalone fuzzer | `a4/standalone/fuzzer.py` | Refactored to dispatch by arm-shape, not hardcoded kind ifs |
| 8 pure-A4 mutation kinds | `a4/standalone/mutations/{comp_out_mod, instr_type_mod, instr_word_mod, instr_word_mod_sur, load_val_mod, mem_val_mod, pre_exec_reg_mod, store_out_mod}.py` | Stay as-is; D2.B adds 3 new ones using the same pattern |
| Arguzz subprocess runner | `a4/arguzz_dependent/arguzz_runner.py` (115 lines, clean) | **REUSED** in D2.C as the subprocess primitive for V6-cTS / Hybrid-cTS Arguzz-arm dispatch |
| Arguzz `<fault>` / `<trace>` parser | `a4/arguzz_dependent/arguzz_parser.py` (180 lines, already covers `INSTR_WORD_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`, `PRE_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`, `POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, and a generic `unknown` fallback for `BR_NEG_COND` / `POST_EXEC_PC_MOD`) | **REUSED** in D2.C; we may extend the parser with explicit `BR_NEG_COND` / `POST_EXEC_PC_MOD` info formats once we see what the binary emits |
| ~~`a4/arguzz_dependent/cli.py`~~ | obsolete | Old "find a matching A4 mutation for each Arguzz fault" comparison harness. **NOT used by D2.** Stays untouched. |
| ~~`a4/arguzz_dependent/mutations/*`~~ | obsolete | A4 mutation wrappers paired with Arguzz faults for the comparison workflow above. **NOT used by D2.** |
| ~~`a4/arguzz_dependent/step_mapper.py`, `comparison.py`~~ | obsolete | Supporting modules for the obsolete comparison workflow. **NOT used by D2.** |
| Normalized loc map | `a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py` (analysis-time normalizer) | **No write-time work in D2.A.** V5 DBs already normalize at write-time via `ConstraintFailure.short_loc()` (verified — see §2.1). The post-hoc normalizer stays as a compat shim for legacy R2 V6 DBs only. |
| Coverage DB schema | `a4/standalone/coverage_db.py` (post-D1.A: now has `proof_generated`, `proof_verify_failed`, `elapsed_ms` columns) | Reused; D2.A adds one more nullable column `mutations.outcome` (`APPLIED` / `SKIPPED` / `ERROR`) |
| POS dispatch playbook | `a4/docs/precloud/POS_PLAYBOOK.md` + `dispatch_pos.py` + `collect_results_pos.py` + `prepare_bundle.sh` | Identical workflow to D1.A — no infra changes |

### 2.1 Resolved: the "single biggest unknown" — V6 binary kind coverage

The v0.1 draft flagged "Arguzz binary's true kind coverage" as the load-bearing unknown for D2.C. **Empirically resolved 2026-06-16 by inspecting an existing R2 V6 DB** (`a4/runs/iv_pos_7/dbs/pos_iv_pos_7_v6_b2_arguzz_seed1243_n6000/`). `SELECT DISTINCT kind FROM mutations` returns:

```
PRE_EXEC_MEM_MOD      ← Pro priority 2 ✓
POST_EXEC_REG_MOD     ← Pro priority 5 ✓
INSTR_WORD_MOD        ← Pro priority 1 ✓
PRE_EXEC_REG_MOD      ✓
POST_EXEC_PC_MOD      ← Pro priority 7 ✓
POST_EXEC_MEM_MOD     ← Pro priority 6 ✓
BR_NEG_COND           ← Pro priority 4 ✓
LOAD_VAL_MOD          ✓
PRE_EXEC_PC_MOD       ← Pro priority 3 ✓
STORE_OUT_MOD         ✓
COMP_OUT_MOD          ✓
```

**All seven of Pro's §15 Priority 1 V6 kinds are already emitted by the Arguzz binary** (the 4 the curated D2 v1 needs, plus the 3 others Pro listed as expansion candidates). The previous concern that D2.C might need a Rust-side binary extension is closed.

What this changes for the plan:
- D2.C's "binary survey spike" collapses from "~1 day" to a ~30-minute smoke check (one `subprocess.run` per kind, confirm `<fault>` round-trips).
- D2.C's effort estimate drops from 5–10 days to **3–5 days** (just wrapping + applied-accounting + arm-shape integration).
- We no longer need the §5 Q6 "expand to 7+5 later" caveat for V6 capacity reasons; capacity is already in the binary. Curation (4+3 in v1 vs 7+5) is now a pure scope-management call, not a capability gate.

### 2.2 The `v6_arguzz` driver — search trail and elevation to D2.C task

**Status:** **NOT YET LOCATED**. Ivan (2026-06-16) flagged that the driver "is certainly in this repo and requires better searching" — we agree the search to-date was insufficient; documenting the negative result here so Composer can pick up the trail in D2.C.

**Signatures we know the driver has** (from R2 V6 DB `campaigns` / `campaign_params` rows):

| Field | Value |
|---|---|
| `campaigns.kind` | `"v6_arguzz"` |
| `campaign_params.selector` | `"arguzz"` |
| `campaign_params.extra_json.scheduler` | `"balanced_round_robin"` |
| `campaign_params.extra_json.driver_version` | `"v2.1_utf8safe"` |
| `campaign_params.extra_json.num` | `6000` |
| `campaign_params.extra_json.compressed_extractor` | `"a4.compressed_global_extractor"` (Python module reference — the driver IS Python and imports our `a4` package) |
| `campaigns.host_binary` | `/root/a4_campaign/bin/risc0-host` (same binary V5 uses; the driver loops `subprocess.run(risc0-host, ...)`) |

**Searches already performed (all negative):**

| Search | Result |
|---|---|
| `git log --all -S "v6_arguzz"` and `git log --all -S "balanced_round_robin"` | 0 commits, across `cloud2` + `main` + their remote refs |
| `git log --all -S "v2.1_utf8safe"` | 0 commits |
| `git log --all --diff-filter=AM --name-only` filtered for `v6.*driver` / `arguzz.*driver` | 0 matches (only analysis files in `a4/runs/iv_pos_7/`) |
| `git ls-tree -r {cloud2,main}` filtered for `v6` / `arguzz` | only `a4/arguzz_dependent/*` (already mapped — irrelevant) and `a4/runs/iv_pos_7/*` analysis |
| `rg "v6_arguzz\|balanced_round_robin"` against `/root/zk-fuzz-lab`, `/root/raw-zk-fuzz-lab`, `/root/zkVMs`, `/root/arguzz_backups` | 0 hits |
| `grep` over `arguzz_backups/*.patch` | 0 hits |

**Leads for D2.C (Composer to investigate):**

1. **`workspace/risc0-modified/`** — there is a small possibility the Rust host binary writes campaign/`bandit_decisions` rows directly when run in a "v6 driver mode" via an `--driver=balanced_round_robin` CLI flag. Search `workspace/risc0-modified/` for `coverage_db`, `INSERT INTO campaigns`, `balanced_round_robin` literal in Rust files. Our search timed out on this dir; Composer should use a more targeted glob (e.g., only `src/main.rs`, `host/**.rs`).
2. **POS management node history** — the R2 V6 campaign was dispatched from POS in early Q-G 2026 (Apr–May). The driver may be a transient script that lives only in the POS user's home directory and was never committed back. Run `git reflog --all`, `git stash list`, and check `git fsck --lost-found` on this repo. If still nothing, ask Ivan whether to ssh to the POS management node and snapshot `~/scripts/` or similar.
3. **`a4/cloud/` historical paths** — the V6 driver might have lived in `a4/cloud/` (referenced by `a4/standalone/dispatch_pos.py` as "Replaces the GCP `a4/cloud/dispatch.py`"). Search `git log --all -- 'a4/cloud/*'`. Files there were likely deleted in the GCP→POS migration but may still be in tree history.
4. **`arguzz_backups/pre_recovery_*` + `arguzz_backups/filesystem_snapshots`** — Ivan's recovery snapshots. Composer should `tar tzf` or `ls -R` these directories looking for Python files matching `*v6*` or `*arguzz*driver*`.

**If still not found after the above:** D2.C builds a thin Python equivalent driver (~150 lines), using:
- `arguzz_runner.run_arguzz_mutation()` as the subprocess primitive (already in tree, 115 lines, clean)
- `arguzz_parser.parse_fault()` and `parse_trace()` for output parsing
- `a4.standalone.coverage_db.A4CoverageDB.record_mutation` for DB writes (this guarantees normalized-loc + applied-accounting via the same `record_failures` path)
- `balanced_round_robin` scheduling is trivial: round-robin over the 11 inventoried V6 kinds

Either way, **D2.C ships a Python `v6_arguzz` driver** — the question is whether we recover the original or build a new one. The new one is preferred from a maintenance standpoint anyway (it auto-uses D2.A's `outcome` column + normalized loc, which the original bypassed).

---

## 3. Sub-deliverable breakdown

D2 is split into **seven sub-deliverables**. The diagram below shows dependencies; the table after gives names and brief scope. (D2.0 from v0.1 — a separate Pro-facing design proposal — is dropped per Ivan v0.2 review: documentation accumulates per sub-deliverable as "opus plan + composer report + review", and the Pro-facing document is assembled by summarizing those at the end of D2.)

```
D2.A (foundation: arm-shape refactor + applied accounting + normalized telemetry)
       │
       ├─────▶ D2.B (pure-A4 kind expansion — 3 kinds)
       │
       ├─────▶ D2.C (V6 integration — Arguzz binding via arguzz_runner)
       │              │
       │              ▼
       └─────▶ D2.D (variant CLI/fuzzer dispatch — 4 variants)
                       │
                       ▼
                D2.E (integration tests + golden traces + tiny smoke)
                       │
                       ▼
                D2.F (POS dispatch — 40 jobs / 30 new + V5 archive reuse)
                       │
                       ▼
                D2.G (analysis + final D2 Pro-facing report + notebook + D3 sketch)
```

### Summary table

| ID | Title | Output (PR-side) | Output (doc-side) | Depends on | Rough effort |
|---|---|---|---|---|---|
| **D2.A** | Foundation: arm-shape + applied accounting + normalized-telemetry verification | `bandit_ts.py`, `semantic_arm_universe.py`, `fuzzer.py`, `coverage_db.py` patches | [`IV_POS_8_D2_A_SPEC.md`](./IV_POS_8_D2_A_SPEC.md) | D1.A merged (we have `FloorSchedule` + new schema cols) | 4–6 d |
| **D2.B** | Pure-A4 kind expansion (TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD) | 3 new files under `a4/standalone/mutations/` + tests | `IV_POS_8_D2_B_SPEC.md` (one section per kind) | D2.A landed (kinds register on arm-shape) | 5–7 d |
| **D2.C** | V6 integration via `arguzz_runner` bridge | bridge module + V6 driver (Python equivalent of the `v6_arguzz` extra_driver path, see §2.1) | `IV_POS_8_D2_C_SPEC.md` | D2.A landed | 3–5 d (binary capacity confirmed — see §2.1) |
| **D2.D** | Variant CLI/fuzzer dispatch (4 variants) | `cli.py`, `fuzzer.py` patches; new `--selector` family extensions | `IV_POS_8_D2_D_SPEC.md` | D2.A+D2.B+D2.C landed | 2–3 d |
| **D2.E** | Integration tests + golden traces + tiny smoke | `tests/test_d2_*.py`, optional `analysis/d2_smoke_check.py` | `IV_POS_8_D2_E_SPEC.md` | D2.D landed | 3–4 d |
| **D2.F** | POS dispatch (30 new jobs + V5 archive reuse) | `a4/pos/manifests/iv_pos_8/d2_b{1,2,3}.json`; kickoff docs | section in master plan; Composer kickoff doc | D2.E green | 12–18 h POS wall + 1 d setup |
| **D2.G** | Analysis + Pro-facing report (summarized from accumulated plan/reports) + D3 sketch | `analysis/build_d2_artifacts.py`, plots, CSVs | `IV_POS_8_D2_REPORT_FOR_PRO.md`, `IV_POS_8_D2_NOTEBOOK.ipynb`, `IV_POS_8_D3_DESIGN_PROPOSAL.md` | D2.F DBs collected | 5–7 d |

**Total wall-clock estimate (this chat's portion before POS):** ~3–5 weeks of focused work, matching the original "5–7 weeks after D1 sign-off" target in `IV_POS_8_PRELIMINARY_PLAN.md` §2. D2.C's drop from 5–10 d to 3–5 d (capacity-confirmed per §2.1) shaves ~3–5 d off the top end.

---

## 4. Sub-deliverable scopes (one paragraph each — full specs come later)

### D2.A — Foundation: arm-shape refactor + applied-mutation accounting + normalized-telemetry verification

The single most important sub-deliverable, because everything else layers on it. Three changes:

1. **Arm-shape abstraction in `bandit_ts.py`.** Replace the current `(mutation_kind, semantic_zone)` arm tuple with the 5-tuple `(mutation_surface, mutation_kind, semantic_zone, opcode_class, pre_post)`. `mutation_surface` ∈ `{"A4_trace_cell", "arguzz_exec_fault"}`. Back-compat is mandatory: V5 cTS_semantic_v2 with surface fixed to `A4_trace_cell` and pre_post collapsed must produce the **identical** decision sequence under a fixed RNG seed (golden trace test).
2. **Applied-mutation accounting.** Pro flagged this explicitly (§8): "The scheduler must count only **applied** Arguzz mutations as pulls." For A4 kinds this is a no-op (all A4 mutations apply). For Arguzz kinds with skip rate ~21%, this means: when the arm is pulled and Arguzz returns "no-op / not applicable," the scheduler must (a) not credit a pull, (b) re-pick. Implementation: introduce a `MutationOutcome` enum `{APPLIED, SKIPPED, ERROR}`; only `APPLIED` advances scheduler state. Schema: one new nullable column `mutations.outcome TEXT` (forward-compatible like D1.A).
3. **Normalized loc + CGC telemetry at source.** Currently we normalize loc strings post-hoc via the Q-G driver (`a4/runs/iv_pos_7/analysis/constraint_loc_normalize.py`). Pro wants normalization **inline**, written directly to the DB during fuzzing. Migrate `short_loc()` and CGC computation into the fuzzer's `record_mutation` path so the DB ships with `mutations.normalized_loc` and `mutations.compressed_global_context` populated. (Open question — see §5.)

**Tests:** golden-trace identity for V5 under new arm-shape, applied-vs-attempted unit test on a synthetic mock surface, normalized-loc parity test against existing Q-G output on R2 V5 DBs.

### D2.B — Pure-A4 kind expansion (TXN_PREV_WORD_MOD, TXN_PREV_CYCLE_MOD, CYCLE_MODE_MOD)

Three new mutation kinds in `a4/standalone/mutations/`, each modeled on the existing pattern (cf. `instr_word_mod_sur.py`). Each kind gets:
- A `find_mutation_target(...)` (where in the trace to mutate)
- A `create_config(...)` (parameterization)
- A `MUTATIONS_TXN_PREV_WORD_MOD.spec.md` style design note (in the mutation file or a sibling)
- Unit tests verifying the mutation actually changes the targeted field and only that field (dump diff: before/after JSON)
- Integration into the `MUTATION_KINDS` registry in `fuzzer.py`

The kinds in scope (priority order from Pro §8 Track B):

| Kind | Targeted field | Why Pro wants it |
|---|---|---|
| `TXN_PREV_WORD_MOD` | `txns[i].prev_word` | Memory consistency / sequential-write ordering surface |
| `TXN_PREV_CYCLE_MOD` | `txns[i].prev_cycle` | Temporal-ordering surface for the memory permutation argument |
| `CYCLE_MODE_MOD` | `cycles[i].mode` (user vs kernel) | ECALL/MRET boundary surface — high-value per V5 results |

`TXN_CYCLE_PHASE_MOD` and `CYCLE_PC_MOD` are explicit candidates for **expansion in a follow-up** if Pro requests them in their D2-design review — pre-wired in D2.0 but not implemented in v1.

### D2.C — V6 kind integration via `arguzz_runner` bridge

Four layers, in order:

0. **Driver archaeology (Composer spike, ≤2 h).** Locate the original `v6_arguzz` driver per §2.2 leads (`workspace/risc0-modified/`, `a4/cloud/` git history, `arguzz_backups/`, reflog/stash/fsck). If found, snapshot it and decide whether to revive-and-modify or replace. If not found after ≤2 h, proceed to layer 2 (build new). **This is the elevated explicit task per Ivan 2026-06-16.**
1. **Binary survey (Composer spike, ~30 min).** Empirically confirmed in §2.1 — all 7 of Pro's V6 kinds are emitted by the current binary. The "survey" is now a quick smoke-check confirming the binary at `bin/risc0-host` still works the same way (one `subprocess.run` per kind, confirm `<fault>` round-trips through `arguzz_parser`). Significantly cheaper than the v0.1 1-day estimate.
2. **Bridge module** (`a4/standalone/mutations/arguzz_bridge.py`). Wraps `arguzz_runner.run_arguzz_mutation(...)` in the same interface as the pure-A4 mutators expose (`find_mutation_target / create_config / dispatch`). Internal implementation: shell to Arguzz binary, parse stdout via `arguzz_parser`, lift to the scheduler's `MutationOutcome`. **Crucially: writes its `record_mutation` calls through `A4CoverageDB`, so normalized-loc + applied-accounting + `outcome` column all work automatically** (no bypassing of `short_loc()` like the R2 V6 driver did).
3. **Wiring** four V6 kinds into the union arm-space: `INSTR_WORD_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD`, `BR_NEG_COND`. Per §2.1 the binary supports all four (and 3 more for future expansion). Each kind gets:
   - A coupling from D2.A's `ArmKey(surface="arguzz_exec_fault", kind=<kind>, zone=<from parser>, opcode_class=<derived>, pre_post=<derived>)`
   - A `pre_post` classification (per D2.A §1.1: `PRE_EXEC_*` → `pre_exec`, `POST_EXEC_*` → `post_exec`, `INSTR_WORD_MOD` and `BR_NEG_COND` → `pre_exec` provisionally)
   - An `opcode_class` derivation from the cycle's major at the fault step (via `semantic_zones.major_to_opcode_class()`)

**Tests:** mock the Arguzz subprocess in unit tests (we already have parser fixtures); integration test runs one real Arguzz invocation per kind on a known input; parity test asserts D2.C's DB outputs are equivalent to a sampled R2 V6 DB (with normalized-loc + `outcome` column being the only differences).

### D2.D — Variant CLI/fuzzer dispatch (4 variants)

Add `--variant` (or `--selector` family extension) to `a4/standalone/cli.py`, mapping to the four variants:

| Variant | `--selector` flag | Surfaces active | Floor schedule |
|---|---|---|---|
| V5 | `cTS_semantic_v2` (existing) | A4_trace_cell only | constant 0.55 (existing) |
| V6-uniform | `v6_uniform` (new) | arguzz_exec_fault only | n/a (uniform over applicable) |
| V6-cTS | `v6_cTS` (new) | arguzz_exec_fault only | constant 0.55 (V5 schedule reused) |
| Hybrid-cTS | `hybrid_cTS` (new) | both | constant 0.55 (V5 schedule reused) |

Each variant gets a `STRATEGY_DISPLAY_NAMES` entry and a `_floor_schedule_for_strategy(...)` branch (mirrors the D1.A pattern). The "selector → arm-shape filter" mapping is one new helper. We deliberately keep D2 floor-schedule = constant 0.55 across all variants for v1 — Pro hasn't asked for decay in Hybrid yet. If D1.A decay wins, we add a decay variant in a D2 follow-up.

### D2.E — Integration tests + golden traces + tiny smoke

The "we know what we built is doing what we think it's doing" sub-deliverable. Five layers:

1. **Golden-trace identity test.** Same RNG seed, run V5 selector pre- and post-D2.A; assert identical decision sequence + identical DB row count + identical `local_context_final`. Already required by D2.A, repeated here as a regression catcher.
2. **Arm-space coverage assertion.** For each variant, run N=20 mutations with `--seed 42` and assert the `arm_history` includes only arms allowed by the variant (e.g., Hybrid-cTS arm history must contain ≥1 arm with `surface=arguzz_exec_fault` AND ≥1 with `surface=A4_trace_cell`).
3. **Applied-accounting smoke.** For V6-cTS, run N=40 mutations and assert `COUNT(mutations WHERE outcome="APPLIED") < N` (skip rate > 0) but the scheduler's `total_pulls` matches the applied count. Catches the "Pro's pulls=applied" requirement in code, not just spec.
4. **Normalized-loc parity.** Run V5 selector under D2 fuzzer for N=40, dump normalized loc strings, compare against running the Q-G driver on the same DB post-hoc. ≥99% agreement (small residual from Q-G normalizer being stable but not bit-identical to inline implementation; deviations are inspected once).
5. **POS-style tiny smoke (optional).** N=200 per variant on POS (~30 min per variant on 1 node, 4 variants on 4 nodes in parallel = ~30 min wall). Same rationale as D1.A Batch 3 smoke-gate. **Skip** if §4 layers 1–4 pass and we trust the architecture; **run** if §4 reveals any flakiness.

### D2.F — POS dispatch

Three batches:

- **D2.F.1 (smoke-gate, 8 jobs):** 2 paired seeds × 4 variants on 8 nodes. ~5.5 h wall on Tier-A limit. Mirrors D1.A Batch 3 design. Pass criterion: all 8 DBs structurally identical, arm-shape coverage assertion holds, applied-accounting smoke as in D2.E layer 3.
- **D2.F.2 (production tail, ~22 jobs):** 8 paired seeds × 4 variants − 8 already in F.1 − 10 V5 jobs reusable from D1.A static archive = 22 new jobs. On 8 nodes that's ~3 sequential dispatches (~16 h wall). **Or** 24 new jobs if we don't reuse V5 archive (decision in §5 Q3).
- **Reservations:** 3 contiguous 6 h calendar entries (mirroring D1.A pattern).

Total D2 POS compute: **~22–32 h wall** depending on V5 archive reuse, on 8 Tier-A/S nodes.

### D2.G — Analysis + Pro-facing report

Mirrors D1.G in spirit:

- `analysis/build_d2_artifacts.py` — single script that ingests 30–40 DBs, writes per-variant CSVs and the headline comparison table (V5 vs V6-uniform vs V6-cTS vs Hybrid-cTS on all D1.C Category A metrics + normalized-territory split per V6 companion §3).
- `IV_POS_8_D2_REPORT_FOR_PRO.md` — Pro-facing narrative. Structure: TL;DR / methodology / per-variant numbers / answers-to-Pro's-§15-Priority-1 question / open questions for D3 design.
- `IV_POS_8_D2_NOTEBOOK.ipynb` — companion plots / interactive exploration.
- `IV_POS_8_D3_DESIGN_PROPOSAL.md` — what D2 ships to Pro alongside the report (mirroring the D1+D2-design pattern). Sketches bug-isolation layer scope. Track-β owns drafting this once D2.G is largely done; Track-α may pre-feed bug-proximity findings from D1.C.

---

## 5. Open questions for Ivan (must answer before Composer touches anything)

These mirror the "open questions" pattern from `IV_POS_8_D1_A_SPEC.md` §8. None of them have defensible default answers from me alone — they all involve a strategy choice.

| # | Question | My recommendation | Why I'm not just defaulting |
|---|---|---|---|
| **Q1** | **Arm-shape: do we collapse `opcode_class` and `pre_post` when surface=A4_trace_cell?** A4 trace-cell mutations don't have a natural pre/post split. Three options: (a) leave them as `(A4_trace_cell, kind, zone, "n/a", "n/a")` arms — keeps arm count down, breaks symmetry; (b) split A4 kinds into pre/post pairs synthetically — symmetric but possibly meaningless; (c) leave A4 unsplit and only Arguzz arms get the full 5-tuple — explicit asymmetry. | **(a)** Use "n/a" sentinel for fields that don't apply to a surface. Keeps reasoning simple, doesn't fabricate distinctions. Pro can request (b) if symmetric arm-space is important. | (b) inflates arm space ×2 with no semantic basis; (c) is hard to reason about in metrics. |
| **Q2** | **Where does normalized loc live?** (a) compute inline in fuzzer at `record_failures` time → DB ships normalized; (b) keep Q-G driver post-hoc → DB ships raw, normalize at analysis time. | **(a)** Inline. Matches Pro's §15 "normalized loc and CGC telemetry" ask and kills Q-G overhead for D2 onward. Risk: inline implementation drift from Q-G driver — mitigated by D2.E layer 4 parity test. | (b) is the smaller-change path but defers a Pro-explicit ask, which we'd then have to do later. Better to do it now. |
| **Q3** | **V5 archive reuse for D2 comparisons.** Reuse D1.A V5-static DBs (10 seeds, sealed) OR re-run V5 under the new D2 fuzzer? | **Reuse if D2.A back-compat tests pass.** Saves 10 jobs (~3 h wall). Justification mirrors D1.A Q14 — back-compat by construction + golden-trace test. **If D2.A back-compat fails** for any reason, fall back to fresh V5 run inside D2. | The added compute is small (~3 h on 8 nodes), but reuse is the cleaner story for Pro (paired analysis vs same baseline). |
| **Q4** | **V6-uniform — re-run, or accept R2 V6 archive?** R2 has 10 seeds of V6-uniform at N=6000 already in `a4/runs/iv_pos_7/dbs/`. | **Reuse R2 V6 archive.** Same logic as Q3 — saves 10 jobs. **Only re-run** if D2 introduces a new fairness control we couldn't have applied retroactively (e.g., normalized-loc-at-source — but that's an analysis-time alignment, not a re-run reason). | Honest accounting: the R2 V6 archive was produced under `a4/arguzz_dependent/cli.py` not the D2 fuzzer, so the DB schema and code path will differ. If we reuse, we MUST document this fairly in D2.G. |
| **Q5** | **Compute target: still N=6000?** Pro explicitly said "Use 10 paired seeds, N=6000 first." | **Yes, N=6000 in v1.** Defer "longer N for Hybrid" to a possible v2 if Pro signals interest. | We have no signal from Pro that N=6000 was an under-shoot; staying with Pro's number is the conservative choice. |
| **Q6** | **Kind menu sizing.** Preliminary plan recommended 4 V6 + 3 A4 = 7 kinds. Pro listed 7 V6 + 5 A4 = 12 total. | **Curated 4+3 in v1; expandable.** Reasons: (a) arm-space size: 4 V6 kinds × 5 zones × 4 opcode_class × 2 pre/post = 160 Arguzz arms alone, already large; (b) D2 turnaround value: faster ship enables Pro course-correction; (c) Pro explicitly said "selectively adopt" not "all." Document a clean upgrade path in D2.0 so Pro can ask for 12. | This is THE biggest strategic choice in D2. Worth Pro feedback explicitly. |
| **Q7** | **V6-cTS as a separate variant, or only Hybrid-cTS?** Pro listed both, but V6-cTS is informationally a subset of Hybrid-cTS. | **Keep both as separate variants.** Pro asked for both; comparing V6-uniform → V6-cTS isolates "does cTS help Arguzz alone?" which is a different question than Hybrid. Cost of running V6-cTS is 10 extra jobs (~3 h). Worth it for the ablation. | Skipping V6-cTS saves compute but loses an ablation Pro explicitly named. |
| **Q8** | **CGC variant for D2 reward.** Pro asked for analysis of three (region-only / log4 / log2) in D1.B and hinted at "coarser CGC" for production. D1.B will recommend one. | **Default D2 reward to the same CGC as V5 used (= log4 — current production)** until D1.B finishes and recommends otherwise. D2 can pivot before POS dispatch. | If we wait for D1.B, D2 is gated on Track-α. Default-and-pivot keeps Track-β unblocked. |
| **Q9** | **Applied-mutation accounting — strict or loose?** Strict: `outcome=APPLIED` advances scheduler state, `SKIPPED` triggers re-pick. Loose: log outcome but still advance regardless. | **Strict.** It's what Pro literally asked for and is the only honest comparison vs V6-uniform (which also uniformly samples until applied). | Loose is easier to implement (no re-pick logic in scheduler), but it dilutes the Hybrid comparison. Pro's wording was unambiguous. |
| **Q10** | **D2 timeline target.** Track-α's D1 horizon is "2–3 weeks." D2's preliminary horizon is "5–7 weeks after D1 sign-off." | **5 weeks of focused Track-β work** ending at "D2.E green + D2.0 finalized." After that, dispatch D2.F immediately upon Pro greenlight. Track-α landings within those 5 weeks just shorten the post-greenlight wait. | We could aim shorter, but D2.C binary-survey is a real wildcard. 5 weeks lets us absorb that risk. |
| **Q11** | **D2 sub-deliverable review cadence with Pro.** Just one Pro review at end (D2.0 + D2 report bundled), or interim Pro checkpoint after D2.0 alone? | **One Pro review at the end.** D2.0 is too detailed to ship in isolation — Pro needs the D1 results context to react meaningfully. Plus interim ship inflates Pro's review load. | The R2 + V6 round established Pro likes "results + plan" bundles; D2.0 alone is just plan. |

---

## 6. Tests + verification strategy (what "doing what we think it's doing" means)

A4 has been bitten before by integration bugs that pass unit tests but produce silently wrong DBs (cf. `PRE_EXEC_REG_MOD` mis-classification, §7.2.2 pull-direction flip from R2). D2 is structurally riskier because of the arm-shape refactor + subprocess bridge. Concrete verification gates:

### Per sub-deliverable

| Gate | Sub-deliverable | What it asserts | Where it lives |
|---|---|---|---|
| Golden trace | D2.A | V5 selector pre/post arm-shape refactor produces byte-identical decisions for seed=42, N=200 | `tests/test_d2_golden_trace.py` |
| Dump diff | D2.B | Each new A4 kind mutates only the field it claims to, on 5 sample traces per kind | `tests/test_d2_pure_a4_kinds.py` |
| Arguzz binary survey | D2.C | Documented in `IV_POS_8_D2_C_SPEC.md` §1; lists every distinct `fault.kind` the binary emits | `analysis/d2_arguzz_kind_survey.py` |
| Subprocess mock | D2.C | Bridge module behaves correctly under faked Arguzz stdout (APPLIED / SKIPPED / ERROR fixtures) | `tests/test_d2_arguzz_bridge.py` |
| Variant arm coverage | D2.D | For each variant, only allowed arm-shape tuples ever appear in `arm_history` | `tests/test_d2_variant_dispatch.py` |
| Applied accounting smoke | D2.E | V6-cTS at N=40: `COUNT(outcome=APPLIED) < N` AND `scheduler.total_pulls == COUNT(outcome=APPLIED)` | `tests/test_d2_applied_accounting.py` |
| Normalized-loc parity | D2.E | Inline normalization vs Q-G post-hoc: ≥99% agreement on V5 DB | `analysis/d2_normalize_parity.py` |
| POS smoke (optional) | D2.E | If all above pass, optional 4-variant POS smoke at N=200 each | `a4/pos/manifests/iv_pos_8/d2_smoke.json` |
| End-to-end DB validator | D2.F | Each of 30 production DBs passes structural validator (mirrors D1.A `validate_d1a_dbs.py`) | `a4/runs/iv_pos_8/d2/validate_d2_dbs.py` |

### Non-POS test budget

Everything except the optional smoke runs on the WSL dev box (~3–5 min for the full new test surface). All gates are deterministic, all use fixed seeds. CI pattern: same `pytest a4/standalone/tests/` invocation we use today, with the addition of `tests/test_d2_*.py`.

### POS test budget

We aim to need only the D2.F.1 smoke-gate (8 jobs, ~5.5 h wall, doubles as production data per Q3/Q4) — no extra POS smoke. If D2.E layer 5 surfaces flakiness we add an N=200 smoke on 1 node (~30 min wall) before the gate.

---

## 7. What ships to Pro at the end of D2

Single bundle (matching the D1 + D2-design pattern):

- **`IV_POS_8_D2_REPORT_FOR_PRO.md`** — the headline narrative
- **`IV_POS_8_D2_NOTEBOOK.ipynb`** — companion plots / drill-down
- **`IV_POS_8_D3_DESIGN_PROPOSAL.md`** — Track-β drafts the D3 (bug-isolation layer) design so Pro can react to "where we go next" alongside D2 results

Plus the underlying artifacts: 30 new DBs (or 40 if we don't reuse archives), variant comparison CSVs, kind-survey output, normalize-parity report.

---

## 8. What this plan deliberately does NOT include

- **No D3 implementation.** D3 sketch goes into `IV_POS_8_D3_DESIGN_PROPOSAL.md` (text only), to be shipped with D2. D3 implementation starts in Track-β only after Pro greenlights it.
- **No D4 (multi-guest).** Out of scope until D3 ships.
- **No D1 re-work.** Track-α owns D1.B / D1.C / D1.D / D1 report.
- **No changes to V5 itself** beyond what D2.A refactors (back-compat-preserving). V5 production stays as-is; only its scheduler is generalized.
- **No new POS infrastructure.** Same `dispatch_pos.py` / `collect_results_pos.py` / `prepare_bundle.sh` workflow as D1.A.
- **No alternate guests.** D2 runs on the current sha2-host guest (same as R2 + D1.A). Multi-guest is D4.

---

## 9. What we tackle FIRST (concrete next steps)

In order:

1. **Ivan reviews this plan v0.1** — confirm sub-deliverable split, answer §5 open questions, edit / reject as needed
2. **Lock the §5 answers** into this document as v0.2 (analogous to `IV_POS_8_D1_A_SPEC.md` §8 "Decisions Confirmed")
3. **Draft D2.A spec** (`IV_POS_8_D2_A_SPEC.md`) and Composer-review it before any code
4. **Draft D2.0 v0.1** (`IV_POS_8_D2_DESIGN_PROPOSAL.md`) in parallel with D2.A spec — it's the Pro-facing document and stays a living draft until D2.E green
5. **Draft D2.B and D2.C spike specs** (D2.C survey is the gating wildcard — start it first if Composer cycles are available)
6. **Composer Batch 1 — D2.A foundation** (arm-shape refactor + applied accounting). Tightest review checkpoint of the whole D2 because everything depends on it.
7. **In parallel after D2.A merges:** Composer Batches 2a (D2.B kinds), 2b (D2.C bridge), 2c (D2.0 finalization) — these are independent
8. **Composer Batch 3 — D2.D variant dispatch + D2.E tests**
9. **Composer Batch 4 — D2.F POS dispatch + collection**
10. **Composer Batch 5 — D2.G analysis + report assembly**
11. **Track-α + Track-β merge for the Pro ship** — D1 report + D2 report + D2.0 + D3 design proposal as one bundle

Composer-batch granularity is the same as D1.A: per-batch spec + per-batch Ivan/Opus review checkpoint, no surprises.

---

## 10. Why this plan is right (TL;DR for Ivan)

- **Faithful to Pro's Priority 1 + Priority 3** — Hybrid V7 + pure-A4 expansion, with all of Pro's normalizations (applied accounting, source-time normalized loc, semantic arm-space)
- **Foundation-first** (D2.A before everything) — the arm-shape refactor is the load-bearing piece; everything downstream is incremental
- **Bridge over reimplementation** (D2.C uses `arguzz_runner` instead of porting V6 to Python) — the right cost/risk tradeoff per Pro's explicit "selectively adopt" language
- **Conservative arm-space sizing** (4+3 kinds, not 7+5) — keeps v1 turnaround fast; Pro can expand on D2.0 review
- **Tracks A and B parallel-safe** — Track-β doesn't block on D1 except for D1.B's CGC variant pick (and Q8 default-and-pivot covers that)
- **Test gates at every step** — golden trace, dump diff, binary survey, applied-accounting smoke, normalize parity, end-to-end DB validator. No DB ships to Pro that hasn't passed each
- **POS infra is unchanged** — same playbook as D1.A; the only new artifact is `validate_d2_dbs.py` and 3 manifests
- **Reversible at every Composer checkpoint** — if D2.A back-compat fails, we don't ship D2; if D2.C binary survey rules out a kind, we drop it from v1 and document

---

*End of D2 master plan v0.1. Open questions in §5 need Ivan's answer before any spec drafting begins. D2.A spec will be the first child document, drafted only after §5 is resolved.*
