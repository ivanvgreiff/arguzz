# E5_SPEC — per-mutation-type constraint-distribution study (for Composer)

Implements **BATCH 2** of `EXAMPLE_PLAN.md` (section G). Read G.0–G.5 first; this spec is
the concrete, ordered build instructions. **This is a distribution study, not a matrix
and not a paired comparison.** For each fuzzer and each mutation type, run the mutation
**N times** across a diverse guest, keep **all** raw evidence, and compute per-type and
per-stage layer distributions.

---

## 0. NON-NEGOTIABLES (read before touching anything)

### 0.1 Isolation — do NOT affect any binary outside this workspace
- The ONLY new compiled artifact is a **new guest + host binary** under
  **`thesis_side_experiments/full_sweep/`**. Its build MUST write exclusively into
  `full_sweep/target/` via `CARGO_TARGET_DIR` (copy the `minimal_add/build.sh` pattern).
- **MUST NOT** write to, rebuild, or change the mtime of:
  - `workspace/output/target/release/risc0-host` (production differential host),
  - `thesis_side_experiments/minimal_add/target/release/thesis-minimal-host` (Batch-1
    frozen binary, sha `5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23`),
  - any source under `workspace/risc0-modified/`, `a4/`, `libs/`, `projects/`.
- The host links `risc0-zkvm` + `fuzzer_utils` from `workspace/risc0-modified/` as
  **read-only path dependencies**; cargo compiles them INTO `full_sweep/target/`, so the
  risc0-modified tree is never mutated. **Verify this** with the mtime guard in 0.3.
- **No code changes anywhere outside `thesis_side_experiments/`.** The `INSTR_TYPE_MOD`
  A4 handler already exists in `workspace/risc0-modified/.../witgen/mod.rs:262`, and all
  needed env flags are already compiled in. We only emit configs and set env.

### 0.2 Keep ALL information (lossless) — see EXAMPLE_PLAN G.0c
Stats are derived; raw evidence is never discarded. Three tiers, all on disk:
1. **One-time guest context** (from E5-E0): full trace inspection + region map + ELF
   disassembly + binary sha.
2. **Per-execution full raw log** (gzipped): the entire stdout+stderr (every tag), plus
   the exact `cmd`, `env`, and A4 config JSON.
3. **Per-execution parsed atom** (JSON) with back-pointers to (1) and (2).
`compute_e5_stats.py` reads only atoms; new metrics later are re-derived from retained
raw logs with **zero re-proving**.

### 0.3 Mtime/SHA guard (run before and after every build; fail loudly on change)
```
stat -c '%Y %n' workspace/output/target/release/risc0-host \
  thesis_side_experiments/minimal_add/target/release/thesis-minimal-host
sha256sum thesis_side_experiments/minimal_add/target/release/thesis-minimal-host   # == 5337f944...
```
Record both before the E5 build; assert unchanged after. Use the existing
`minimal_add/host_guard.py` (extend it to also check the production host mtime).

### 0.4 Flag contract (run-time env only — identical to Batch 1, for both fuzzers)
`CONSTRAINT_CONTINUE=1`, `A4_COVERAGE_TOUCH_VERBOSE=1`, `A4_FAMILY_RESIDUE=1`,
`A4_GLOBAL_RESIDUE=1`. Arguzz adds CLI `--inject --inject-kind K --inject-step S --seed N`
(via `bias_campaign/run_arguzz.py`). A4 adds `A4_MUTATION_CONFIG=cfg.json`. For the
one-time context capture only, also use `A4_INSPECT=1` and `A4_DUMP_ALL_TXNS=1`.

---

## 1. STEP 0 — workspace cleanup (minimal_add), then gate
Do this first; it is independent of the science.
- Create `minimal_add/docs/`, `minimal_add/specs/`, `minimal_add/_archive/`.
- **Move** (git mv) into `docs/`: `CONSTRAINTS_EXPLAINED.md`, `A4_CONSTRAINTS_EXPLAINED.md`,
  `E4_COMPARISON.md`, and a copy of `artifacts/e4/MATRIX_GRANULAR.md`.
- **Move** into `specs/`: `EXAMPLE_PLAN.md`, `E1_SPEC.md`, `E1_AMENDMENT.md`,
  `E2_POS_PREP_SPEC.md`, `E2_FULL_SPEC.md`, `E4_MATRIX_SPEC.md`, `E5_SPEC.md` (this file).
- **Move** into `_archive/`: `run_m0.py`–`run_m3.py`, `run_phases.py`,
  `verify_crash_condition.py`, `EXPERIMENT_PLAN_V2.md`, old `PLAN.md`, old `README.md`,
  and stale artifacts `artifacts/{m0,m1,m2,m3,verify_crash}`, plus loose
  `artifacts/{*.txt,instruction_card.json,comparison_matrix.json,a4_mut*,arguzz_mut*,baseline_trace.txt,step_185_dump.txt,inspection_summary.txt,run_phases.log}`.
- **Keep at top level:** `run_e0/e1/e2/e4_matrix.py`, `analyze_logs.py`, `bake_e2_*.py`,
  `apply_e1_amendment.py`, `host_guard.py`, `build.sh`, `host/`, `methods/`,
  `frozen_host/`, `target/`, `artifacts/{e0,e1,e2,e4}`.
- **Before moving:** `grep`/git-verify nothing active imports a to-be-archived file.
- Write a fresh `minimal_add/README.md` indexing program/engine/specs/docs/artifacts.
- **GATE:** re-run `python3 run_e4_matrix.py`; confirm `artifacts/e4/` outputs are
  byte-identical (no proving). Only then continue.

---

## 2. STEP 1 — new workspace `full_sweep/` + diverse guest + build

### 2.1 Layout
```
thesis_side_experiments/full_sweep/
  build.sh                # CARGO_TARGET_DIR=<full_sweep>/target; cargo build --release
  host/                   # COPY minimal_add/host verbatim (same Cargo.toml deps/features)
  methods/                # COPY minimal_add/methods; only guest/src/main.rs differs
  methods/guest/src/main.rs   # the NEW diverse guest (2.2)
  frozen_host/            # populated after build with the new binary + recorded sha
  target/                 # build output (gitignored)
  a4_config_ext.py        # INSTR_TYPE_MOD builder (or extend bias_campaign/a4_config.py)
  run_e5_e0.py            # baseline + context capture
  sample_e5.py            # enumerate the sample set
  run_e5.py               # dispatch + atom emit + raw-log retention
  compute_e5_stats.py     # atoms -> stats + DISTRIBUTIONS.md
  artifacts/e5/           # context/, atoms/, raw/, e5_stats.json, DISTRIBUTIONS.md
```
`build.sh` MUST mirror `minimal_add/build.sh` exactly except for the target dir name, and
MUST NOT touch `workspace/output` or `minimal_add/target`.

### 2.2 The diverse guest (`methods/guest/src/main.rs`)
Deterministic, no host args (operands baked), `read_volatile`/`write_volatile` +
`core::hint::black_box` to force real `Lw`/`Sw`/`Lb`/`Lh`/`Sb`/`Sh`/ALU/branch/loop
instructions (so the optimizer can't fold them). Must contain, at minimum:
- **Compute variety:** `add`, `sub`, `xor`, `or`/`and`, a shift (`<<`/`>>`), and a `mul`
  on `black_box`ed operands.
- **Memory variety:** a small `[u32; K]` (or byte buffer) on the stack/heap with **byte,
  half, and word** loads and stores (`lb`/`lh`/`lw`/`sb`/`sh`/`sw`), plus a **read-back**
  load of a value just stored.
- **Control flow:** a **counted loop** (e.g. `for i in 0..4`, fixed bound → a backward
  branch/jump) whose body accumulates, and **at least one `if` that is taken on some
  iterations and not-taken on others** (so a branch instruction is exercised both ways
  for `BR_NEG_COND`).
- Commit a single final `u32` (function of all the above) so the baseline output is fixed
  and any mutation that changes the result is detectable.
Keep the trace small (tens–low hundreds of user steps). Document the intended instruction
at each source line in a comment block (for sanity, not relied upon).

### 2.3 Build + freeze
- Run the 0.3 guard (record production + minimal_add mtimes/sha).
- `./build.sh`; re-run the guard → assert the two external binaries are **unchanged**.
- Copy `full_sweep/target/release/<host-bin>` → `full_sweep/frozen_host/`, record its
  `sha256` in `full_sweep/frozen_host/SHA256`. All later steps assert this new sha.

---

## 3. STEP 2 — E5-E0 baseline + one-time context capture
Clone `minimal_add/run_e0.py` → `run_e5_e0.py`. **No Arguzz↔A4 offset is computed.**
1. **Clean baseline** (no injection, flag contract on): run twice; assert verifier
   success, committed output stable, **0** `<constraint_fail>` and **0** nonzero residue,
   and the two runs' categorized sets are byte-identical. Save both raw logs.
2. **Context capture** (once): run with `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1`; save the full
   dump to `artifacts/e5/context/trace_inspection.txt.gz`. Parse it into
   `context/cycles.json` (every cycle: idx, step, pc, major, minor, txn_idx) and
   `context/txns.json` (every txn: idx, step, type reg|mem, addr, cycle, word, prev_*).
3. **Region map** `context/region_map.json`: read `workspace/risc0-modified/.../execute/
   platform.rs` for the memory map (user-register base, RAM/user region, machine/kernel
   region, and the kernel pc threshold — KB notes kernel pc ≥ `0xC0000000`,
   `USER_REGS_BASE` word addr `1073725472`). Emit address/pc → region classifier rules:
   `guest_code` (guest ELF text), `guest_data` (guest RAM/heap/globals), `stack`,
   `machine_kernel`, `bootloader`, `other`. This classifier is used to fill
   `target_region` / `hits_guest_data` for every execution.
4. **Site list** `context/sites.json`: the guest's instruction steps grouped by
   applicability — `compute` (for COMP/INSTR_TYPE/INSTR_WORD), `load`, `store`, `branch`
   (for BR_NEG_COND), and `any` (for PC/MEM/REG/INSTR_WORD). Derive from `cycles.json`
   (major/minor) + disassembly; save the guest objdump to `context/guest.objdump.txt`.
**GATE:** baseline clean + reproducible; context + region map + sites written; new-host
sha matches frozen.

---

## 4. STEP 3 — `INSTR_TYPE_MOD` A4 builder (only real code addition)
In `full_sweep/a4_config_ext.py` (preferred) or by extending
`bias_campaign/a4_config.py`, add a builder that emits the config the existing handler
consumes (`witgen/mod.rs:262`):
```json
{"mutation_type": "INSTR_TYPE_MOD", "step": <a4_step>, "major": <M>, "minor": <m>}
```
- Pick the target `(major,minor)` to be a *different valid op-type* than the cycle's
  original (e.g. ADD→SUB, ADD→XOR) using the same `InsnKind/8`, `InsnKind%8` mapping the
  circuit uses. Provide a small helper to enumerate candidate `(major,minor)` per site.
- Reuse the existing `PRE_EXEC_REG_MOD` builder (both `next_read` and `prev_write`
  strategies) and the existing FULL/SUR/MEM_VAL/value builders unchanged.
Add a unit smoke test: build one config of each A4 type-variant against `context/`,
assert JSON shape + that the targeted step/txn exists.

---

## 5. STEP 4 — `sample_e5.py` (enumerate the sample set)
Produce `artifacts/e5/sample_set.json`: a flat list of sample descriptors, **N per
type-variant**, each:
```
{ sample_id, fuzzer: "arguzz"|"a4", mutation_type, variant,           # variant e.g. SUR field, REG strategy
  site: {step, pc, instr, applicability}, seed,                       # arguzz: seed drives value/target
  a4_config_path: <path or null> }                                    # a4: pre-baked config
```
**Type-variants (20):**
- **Arguzz (11):** `COMP_OUT_MOD` (compute sites), `LOAD_VAL_MOD` (load sites),
  `STORE_OUT_MOD` (store sites), `INSTR_WORD_MOD` (compute+mem sites), `BR_NEG_COND`
  (branch sites), `PRE_EXEC_PC_MOD`, `POST_EXEC_PC_MOD`, `PRE_EXEC_MEM_MOD`,
  `POST_EXEC_MEM_MOD`, `PRE_EXEC_REG_MOD`, `POST_EXEC_REG_MOD` (PC/MEM/REG at `any` sites).
- **A4 (9):** `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `INSTR_WORD_MOD_FULL`,
  `INSTR_WORD_MOD_SUR`, `MEM_VAL_MOD`, `PRE_EXEC_REG_MOD/next_read`,
  `PRE_EXEC_REG_MOD/prev_write`, `INSTR_TYPE_MOD`.
**Spreading:** distribute each type-variant's N across its applicable sites
(≈ `ceil(N/#sites)` seeds per site). For Arguzz random-target kinds (PC/MEM/REG) the seed
varies the random reg/addr/pc; for value kinds the seed varies the injected value; for
INSTR_WORD the seed varies the new word. For A4, pre-bake one config per sample (varying
target txn/site, and for SUR the field, for value kinds a varied value).
**N parameter:** `--n` (pilot 20, full 100, or 250). Print the resulting run count.

---

## 6. STEP 5 — `run_e5.py` (dispatch on POS, emit atoms, retain raw)
Clone the `minimal_add/run_e2.py` dispatch (tmux-on-coinbase for disconnect safety; one
node reset; loop the sample set through `pos/thesis_run_pos.sh`; pull logs locally).
**POS node:** `polynize` + the user's other current nodes are **busy ~30h** — reserve a
**NEW dedicated, fast (Tier S/A), non-shared** node, image **`debian-trixie`**, per
`bias_campaign/POS_NOTES.md` (calendar entry first; edit an existing entry if at the
2-entry cap; never use another agent's node). Optionally **shard** the sample set across
several free nodes for wall-time (see budget below).

For **each sample**, on the node, run the frozen new host with the flag contract:
- Arguzz: `run_arguzz`-style CLI (`--inject --inject-kind … --inject-step … --seed …`).
- A4: `A4_MUTATION_CONFIG=<cfg>`.
Capture the **complete** stdout+stderr → `artifacts/e5/raw/<sample_id>.log.gz`. Then parse
(reusing `analyze_logs.py` + `bias_campaign/{categorize,touch_parse,classify}.py`) into
`artifacts/e5/atoms/<sample_id>.json` per the schema in §8, including `target_region` /
`hits_guest_data` via `context/region_map.json`, and back-pointers `raw_log_path` +
`config_path` + `cmd` + `env`.
**Determinism:** re-run a random ~10% of samples a 2nd time; assert byte-identical
categorized constraint set (not raw timing). Record pass/fail in `atoms/<id>.json`.
**Crashes are data:** on preflight/executor/witgen crash, still emit a complete atom with
`crashed=true`, `crash_stage`, `outcome_class`, empty layers — never drop the sample.

---

## 7. STEP 6 — `compute_e5_stats.py` + `DISTRIBUTIONS.md`
Read **only** `artifacts/e5/atoms/*.json` (no proving). Emit:
- `artifacts/e5/e5_stats.json` — per `(fuzzer, mutation_type[, variant])`: `n`,
  `crash_rate` + breakdown by `crash_stage`, `reached_constraints_rate`,
  `P(intrastep>=1)`, `P(interstep>=1)`, `P(global>=1)`, mean count per layer, the
  `(i/inter/g)` triple histogram, `guest_data_hit_rate`, and a top-`loc` frequency table.
  Plus **stage rollups** (Arguzz pre/in-place/post; A4 witness-value/word-type/mem-read/
  reg) with the aggregated layer distribution per stage family.
- `artifacts/e5/DISTRIBUTIONS.md` — readable: one section per type-variant (the table
  above + top constraints + crash modes + guest-data hit rate), then the **headline**
  per-stage layer distributions (during-exec vs post-exec vs witness), then a short
  "what this shows" prose. **No matrix.**
Assert: every atom parsed; per-type `n` == requested N (minus any that legitimately had
no valid site, which must be logged).

---

## 8. The atom schema (exact)
```json
{
  "sample_id": "arguzz__PRE_EXEC_REG_MOD__s0012",
  "fuzzer": "arguzz",
  "mutation_type": "PRE_EXEC_REG_MOD",
  "variant": null,
  "seed": 12,
  "inject": { "step": 207, "pc": 2099284, "instr_at_site": "add a1,a1,a2",
              "target_kind": "reg", "target_addr_or_reg": "a4" },
  "target_region": "guest_data",
  "hits_guest_data": true,
  "outcome_class": "PREFLIGHT_CRASH",
  "crashed": true,
  "crash_stage": "preflight",
  "layers": { "intrastep_local": 0, "interstep_local": 0, "global": 0 },
  "constraints": [
     { "loc": "...mem.zir:79...", "category": "interstep-local",
       "residue": "p-5", "provenance_verified": true }
  ],
  "global_families": [ {"family":"memory","address":null} ],
  "fault_info": "<fault>{...}</fault> or <a4_*> tag verbatim",
  "determinism": { "checked": true, "identical": true },
  "raw_log_path": "artifacts/e5/raw/arguzz__PRE_EXEC_REG_MOD__s0012.log.gz",
  "config_path": null,
  "cmd": "…", "env": { "CONSTRAINT_CONTINUE":"1", … },
  "host_sha256": "<new full_sweep binary sha>"
}
```
`category` ∈ {`intrastep-local`,`interstep-local`,`global`} per `categorize.py`
(intrastep = decode/ALU `L1` + `MemoryWrite@mem.zir`; interstep = `IsRead@mem.zir`;
global = family/global residue). Keep the granular `constraints[]` for every run.

---

## 9. POS budget (so you can plan the allocation)
~20 type-variants. Per-proof ≈ 3–4 s on a fast node (verbose-touch forces `SeqForward`;
includes full raw-log capture). Plus ~10% determinism spot-checks.
| N/type | runs (+10%) | 1 node | 4 nodes (sharded) |
|---|---|---|---|
| 20 (pilot) | ~440 | ~25–30 min | ~8 min |
| 100 | ~2,090 | ~2–2.5 h | ~35 min |
| **250** | **~5,500** | **~4.5–6 h** | **~1.5 h** |
For **N=250**, reserve one fast node for ~6 h, **or** shard the `sample_set.json` across
~4 free nodes (each runs a disjoint slice; merge atoms locally) for ~1.5 h.

---

## 10. STEP 7 — extend the explanatory docs
In `minimal_add/docs/` (post-cleanup): extend `CONSTRAINTS_EXPLAINED.md` with Arguzz
`BR_NEG_COND` + the PC/MEM/REG kinds, and `A4_CONSTRAINTS_EXPLAINED.md` with
`PRE_EXEC_REG_MOD` + `INSTR_TYPE_MOD` — same mutation→constraint→meaning→layer treatment,
now backed by the E5 distributions (cite representative atoms + the per-type stats).

---

## 11. ACCEPTANCE GATES (all must pass)
1. **Isolation:** production host + `minimal_add` binary mtimes/sha unchanged across the
   whole run; no source modified outside `thesis_side_experiments/`.
2. **Cleanup gate:** `run_e4_matrix.py` reproduces identical `artifacts/e4/` after reorg.
3. **E5-E0:** clean baseline reproducible (0 fail / 0 residue); context + region_map +
   sites + objdump captured; new-host sha frozen.
4. **Coverage:** all 20 type-variants sampled; `BR_NEG_COND` actually fired on a branch
   (raw log shows a branch instr at the site); requested N met per type (log exceptions).
5. **Retention:** every sample has a gzipped full raw log + a complete atom with
   back-pointers; nothing dropped (crashes included).
6. **Determinism:** ~10% spot-check byte-identical categorized sets.
7. **Provenance:** for scalar value mutations, cited residue == predicted (old−new) mod p
   where derivable; flag non-scalar as such.
8. **Outputs:** `e5_stats.json` + `DISTRIBUTIONS.md` regenerate from atoms with no
   proving; per-stage headline distributions present.

## 12. Suggested order of work
Step 0 (cleanup+gate) → Step 1 (workspace+guest+build+freeze) → Step 2 (E5-E0+context) →
Step 3 (INSTR_TYPE_MOD builder + smoke) → Step 4 (sample_e5, **pilot N=20**) → Step 5
(run pilot on a reserved node) → Step 6/7 (stats+docs on pilot) → review → scale to the
chosen N (100 or 250), sharding if desired.
