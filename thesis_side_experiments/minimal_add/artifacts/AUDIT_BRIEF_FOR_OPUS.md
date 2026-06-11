# Opus Audit Brief: Minimal-Add Thesis Side Experiment

**Purpose:** Enable a from-scratch audit of code, methodology, and claimed results for thesis §3.3.3 grounding work.  
**Auditor:** Read this first, then follow file pointers in order.  
**Date produced:** 2026-06-11  
**Workspace root:** `/root/arguzz`

---

## 1. Executive summary

A side experiment was added under `thesis_side_experiments/minimal_add/` to replace the fictional c0c1 example in `a4/docs/thesis.md` §3.3.3 with an evidence-backed minimal guest (`3 + 4 → 7` via one R-type `add`). It compares:

- **Arguzz:** executor-stage `PRE_EXEC_REG_MOD` (patched RISC Zero, `store_register` before inject step)
- **A4:** witness-stage `PRE_EXEC_REG_MOD` (preflight txn `word` rewrite via `A4_MUTATION_CONFIG`)

**Hard constraint honored:** No files under `workspace/output/`, production `risc0-host`, `c0c1_differential_guest`, or core `a4/` pipeline code were modified. New code lives only in `thesis_side_experiments/minimal_add/`. The experiment **reads** `a4/` Python modules and **links** (path dependency) `workspace/risc0-modified/` without editing them.

**Primary deliverables:**

| Artifact | Path |
|----------|------|
| Human results summary | `thesis_side_experiments/minimal_add/artifacts/RESULTS.md` |
| Machine comparison | `thesis_side_experiments/minimal_add/artifacts/comparison_matrix.json` |
| Repro driver | `thesis_side_experiments/minimal_add/run_phases.py` |
| Isolated host binary | `thesis_side_experiments/minimal_add/target/release/thesis-minimal-host` |

---

## 2. What the auditor should verify (priority checklist)

### P0 — Correctness of core claims

1. **Guest add site identification**  
   - Arguzz trace: steps 185–187 at `artifacts/baseline_trace.txt` lines ~189–191: `li a0,3`, `li a1,4`, `add s0,a0,a1`.  
   - Verify `run_phases.py` hardcodes `ARGUZZ_ADD_STEP=187`, `ARGUZZ_ADD_PC=2099232` match parsed trace (not derived automatically in script).

2. **Arguzz vs A4 step alignment**  
   - A4 `A4CycleInfo.pc` is **next PC after instruction** (`a4/core/trace_parser.py:26`).  
   - Script aligns Add by `pc == ARGUZZ_ADD_PC + 4` → A4 step **185**, while Arguzz numbers the same logical Add at step **187** (Δ=+2 on Arguzz side).  
   - Verify `instruction_card.json` txns (a0 READ 3, a1 READ 4, s0 WRITE 7) belong to A4 step 185 / cycle_idx 15424.

3. **Asymmetric mutation targets (important)**  
   - **Arguzz** (seed 42): `artifacts/arguzz_mut.txt` contains `<fault>{"step":187,...,"info":"t0 = 1068323197"}</fault>` — corrupts **t0**, not operand **a1**.  
   - **A4**: deliberately mutates **a1** READ txn 15057, word 4→9 (`artifacts/a4_mutation.json`).  
   - Comparison is **not** “same register, two mechanisms”; it is “same inject step / same Add cycle, different mutation semantics.” Auditor should judge whether thesis prose overstates equivalence.

4. **Arguzz Hook 3 null is inconclusive**  
   - `run_phases.py` Arguzz subprocess does **not** set `A4_FAMILY_RESIDUE=1`.  
   - `comparison_matrix.json` shows `"hook3_families": null` for Arguzz — means **tag not emitted**, not proven absence of global failure.  
   - A4 path uses `run_a4_mutation()` which sets `A4_FAMILY_RESIDUE=1` (`a4/core/executor.py:192–197`).

5. **Phase 2 touch table is empty / broken**  
   - `artifacts/touch_at_add.txt` is empty.  
   - `run_phases.py:94` filters for `"step": {a4_step}` inside `<a4_touch_coverage>` lines, but baseline touch output is a **single bitmap blob** (`artifacts/touch_baseline.txt`), not per-step JSON. Phase 2 as implemented does not produce usable touch-at-add data.

### P1 — Mechanism vs interpretation

6. **Arguzz `PRE_EXEC_REG_MOD` implementation** — random register, not txn-targeted:  
   `workspace/risc0-modified/risc0/circuit/rv32im/src/execute/rv32im.rs:626–637`  
   Uses `random_register_addr()` (range 1..31) and `store_register` **before** instruction fetch at inject step.

7. **A4 `PRE_EXEC_REG_MOD` implementation** — txn-targeted witgen rewrite:  
   `workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs:462–525`  
   Mutates `trace.txns[idx].word` per JSON config; logs `<a4_pre_exec_reg_mod>`.

8. **Constraint failure names**  
   - Both runs: `IsRead` @ `mem.zir:79` (verbose loc string in JSON).  
   - A4 only: `MemoryWrite` @ `mem.zir:99`.  
   - Neither: explicit ALU “rs1+rs2=rd” named constraint — verify against ZIR / `PRESENTATION_DEEP_DIVE.md`.

9. **Why IsRead at Add step when Arguzz corrupted t0?**  
   - Add operands a0/a1 unchanged in assembly; auditor should trace whether failure is on txn 15055 (non-register addr `524808` in instruction card) or another read in cycle 15424, and whether executor corruption of t0 affects witness/trace recording. **Potential overclaim in RESULTS.md** if causality is not t0→IsRead.

### P2 — Documentation / hygiene

10. Guest source comment says `li t0,3; li t1,4; add t2,...` but compiled code uses **a0, a1, s0** (see trace).  
11. `baseline_trace.txt` and mutation logs contain **duplicated trace sections** (~line 3018 repeats from step 0) — likely full prove pipeline logging trace twice; dedupe before counting steps.  
12. `inspection_summary.txt` reports **2950** A4 steps; Arguzz trace runs to ~2961 — explain offset (Poseidon/boot cycles, counting differences per `GLOSSARY.md`).

---

## 3. Directory map (all relevant code)

### 3.1 Side experiment (NEW — only tree created for this work)

```
thesis_side_experiments/minimal_add/
├── README.md                 # Isolation contract, build/run instructions
├── PLAN.md                   # Phase plan (some steps outdated vs run_phases.py)
├── build.sh                  # CARGO_TARGET_DIR=./target; builds thesis-minimal-host
├── Cargo.toml                # Workspace: host, methods, methods/guest
├── run_phases.py             # Automated phases 1–4 + comparison matrix
├── .gitignore                # Ignores target/
├── host/
│   ├── Cargo.toml            # deps: thesis-minimal-methods, risc0-zkvm, fuzzer_utils
│   └── src/main.rs           # Stripped host: trace/inject flags only, no guest inputs
├── methods/
│   ├── Cargo.toml            # risc0-build embed; metadata.risc0 methods=["guest"]
│   ├── build.rs              # risc0_build::embed_methods()
│   └── src/lib.rs            # include!(OUT_DIR/methods.rs)
├── methods/guest/
│   ├── Cargo.toml
│   └── src/main.rs           # Single inline asm add; env::commit(7)
├── target/                   # ISOLATED build artifacts (large; gitignored)
│   ├── release/thesis-minimal-host
│   └── riscv-guest/.../thesis-minimal-guest.bin
└── artifacts/                # Experiment outputs (audit primary evidence)
    ├── RESULTS.md
    ├── comparison_matrix.json
    ├── instruction_card.json
    ├── inspection_summary.txt
    ├── baseline_trace.txt
    ├── step_185_dump.txt
    ├── touch_baseline.txt
    ├── touch_at_add.txt      # EMPTY (filter bug)
    ├── arguzz_mut.txt
    ├── a4_mut.txt
    ├── a4_mutation.json
    └── run_phases.log
```

**Embedded guest constants** (generated at build):

`thesis_side_experiments/minimal_add/target/release/build/thesis-minimal-methods-*/out/methods.rs`  
→ `THESIS_MINIMAL_GUEST_ELF`, `THESIS_MINIMAL_GUEST_ID`

### 3.2 Production paths explicitly NOT modified

| Path | Role | Audit note |
|------|------|------------|
| `workspace/output/target/release/risc0-host` | Production host + c0c1 guest | Must be unchanged |
| `workspace/output/methods/guest/src/main.rs` | c0c1 differential guest | Untouched |
| `a4/` package Python/Rust injection | Modern A4 pipeline | Read-only import from experiment |
| `a4/arguzz_dependent/` | Legacy coupled compare | **Not used** (known broken `compare` CLI) |
| `a4/docs/thesis.md` | Thesis draft §3.3.3 | **Not yet updated** with experiment numbers |

### 3.3 Patched RISC Zero (read-only dependency)

Path: `workspace/risc0-modified/`

| Component | Path | Relevance |
|-----------|------|-----------|
| Arguzz inject hooks | `risc0/circuit/rv32im/src/execute/rv32im.rs` | `PRE_EXEC_REG_MOD`, trace `<trace>`, `<fault>` |
| Inject step counter | `fuzzer_utils/src/lib.rs` | `inc_step`, `is_injection_at_step`, seed/kind |
| Random reg selection | `rv32im.rs` `RV32IMFaultInjectionContext` ~273–285 | `random_register_addr`, `random_register_u32` |
| A4 witgen mutation hook | `risc0/circuit/rv32im/src/prove/witgen/mod.rs` | `A4_MUTATION_CONFIG`, inspection dumps |
| A4 inspect tags | Same file + preflight | `<a4_cycle_info>`, `<a4_txn>`, `<a4_step_txns>` |
| Constraint failures | Circuit codegen / witgen | `<constraint_fail>` |
| Hook 3 | Accumulator phase (see catalog) | `<a4_family_residue>` |

Production host `workspace/output/host/src/main.rs` is a **superset** (guest I/O args `in0`–`in4`); thesis host is minimal copy without those args.

### 3.4 A4 Python (read-only, modern standalone path)

| Module | Path | Role in experiment |
|--------|------|-------------------|
| Inspection container | `a4/core/inspection_data.py` | `from_inspection()` sets `A4_INSPECT=1`, `A4_DUMP_ALL_TXNS=1` |
| Execution primitives | `a4/core/executor.py` | `run_a4_inspection_with_step`, `run_a4_mutation`, `run_baseline` |
| Trace parsing | `a4/core/trace_parser.py` | `A4CycleInfo`, `A4Txn`, parsers |
| Constraint parsing | `a4/core/constraint_parser.py` | `ConstraintFailure`, field is **`loc`** not `constraint` |
| Touch / Hook3 parsing | `a4/core/touch_coverage.py` | `parse_family_residues`, `parse_touch_bitmap` |
| PRE_EXEC_REG_MOD targets | `a4/standalone/mutations/pre_exec_reg_mod.py` | `get_targets_at_step`, `create_config` |
| CLI (not used directly) | `a4/standalone/cli.py` | `inspect` subcommand equivalent to manual inspection |

**Avoid for methodology:** `a4/arguzz_dependent/cli.py`, `a4/docs/arguzz-dependent/`

### 3.5 Authoritative documentation

| Doc | Path | Use |
|-----|------|-----|
| Modern terminology | `a4/docs/cloud1/GLOSSARY.md` | step=user_cycle, mutation kinds, PC zones |
| Onboarding | `a4/docs/cloud1/CLOUD1_AGENT_ONBOARDING.md` | Pipeline overview |
| Global hooks | `a4/docs/global/GLOBAL_HOOKS_CATALOG_V2.md` | Hook 1/2/3, env vars |
| Constraint plain English | `a4/docs/global/PRESENTATION_DEEP_DIVE.md` | IsRead, MemoryWrite meanings |
| Thesis draft under test | `a4/docs/thesis.md` | §3.3.3 fictional step 209 example |

---

## 4. Experiment methodology (exact commands & env)

### 4.1 Build isolated host

```bash
cd /root/arguzz/thesis_side_experiments/minimal_add
./build.sh
# → target/release/thesis-minimal-host
```

`build.sh` sets `CARGO_TARGET_DIR=$ROOT/target` so production `workspace/output/target` is never written.

Host links same patched crates as production:

- `risc0-zkvm` → `workspace/risc0-modified/risc0/zkvm`
- `fuzzer_utils` → `workspace/risc0-modified/fuzzer_utils`

Features: `prove`, `witgen_debug` (no `circuit_debug` — see production host comment in `workspace/output/host/Cargo.toml`).

### 4.2 Reproduce all phases

```bash
cd /root/arguzz
python3 thesis_side_experiments/minimal_add/run_phases.py
```

**Phase sequence inside `run_phases.py`:**

| Phase | Action | Env / CLI | Output |
|-------|--------|-----------|--------|
| 1 | `InspectionData.from_inspection(host, [])` | `A4_INSPECT=1`, `A4_DUMP_ALL_TXNS=1` | `inspection_summary.txt`, `instruction_card.json` |
| 1b | `run_a4_inspection_with_step(host, [], a4_step=185)` | `A4_DUMP_STEP=185` | `step_185_dump.txt` |
| 2 | `run_baseline(..., A4_COVERAGE_TOUCH=1, CONSTRAINT_CONTINUE=1)` | touch bitmap | `touch_baseline.txt`, `touch_at_add.txt` (broken) |
| 3 | subprocess host inject | `--trace --inject --inject-step 187 --inject-kind PRE_EXEC_REG_MOD --seed 42` | `arguzz_mut.txt` |
| 4 | `create_config` + `run_a4_mutation` | `A4_MUTATION_CONFIG`, `CONSTRAINT_CONTINUE=1`, `A4_COVERAGE_TOUCH=1`, `A4_FAMILY_RESIDUE=1` | `a4_mutation.json`, `a4_mut.txt` |
| 6 | JSON matrix | parses `<constraint_fail>`, `<a4_family_residue>` | `comparison_matrix.json` |

**Constants hardcoded in script:**

```python
ARGUZZ_ADD_STEP = 187
ARGUZZ_ADD_PC = 2099232
SEED = 42
HOST = thesis_side_experiments/minimal_add/target/release/thesis-minimal-host
```

### 4.3 Manual spot-check commands

```bash
# Baseline trace (no inject)
thesis_side_experiments/minimal_add/target/release/thesis-minimal-host --trace

# Arguzz inject only
thesis_side_experiments/minimal_add/target/release/thesis-minimal-host \
  --trace --inject --inject-step 187 --inject-kind PRE_EXEC_REG_MOD --seed 42

# A4 inspect summary
cd /root/arguzz && python3 -m a4.standalone.cli inspect \
  --host thesis_side_experiments/minimal_add/target/release/thesis-minimal-host
```

---

## 5. Recorded results (for cross-check)

Source of truth: `artifacts/comparison_matrix.json` (2026-06-11 run).

### 5.1 Pinned site

| Field | Value |
|-------|-------|
| Guest semantic Add | `add s0, a0, a1` with a0=3, a1=1=4, result 7 |
| Arguzz inject step | 187 (pc 0x001FFBC0) |
| A4 witgen step | 185 (pc field 0x001FFBC4 = next PC after add) |
| major / minor | 0 / 0 |
| Baseline journal output | `"output":"7"` in trace tail |

### 5.2 Arguzz mutation (seed 42)

| Field | Value |
|-------|-------|
| Fault line | `<fault> step 187, PRE_EXEC_REG_MOD, t0 = 1068323197` |
| exit_code | -11 (SIGSEGV) |
| `<constraint_fail>` count parsed | 1 |
| loc | IsRead @ mem.zir:79 (verbose callsite string) |
| `<a4_family_residue>` | **none** (env not set) |

### 5.3 A4 mutation

| Field | Value |
|-------|-------|
| Config | step 185, txn_idx 15057, word 9, strategy next_read, register a1 |
| `<a4_pre_exec_reg_mod>` | logged in `a4_mut.txt` line 6 |
| exit_code | 101 |
| `<constraint_fail>` | IsRead @ mem.zir:79 **and** MemoryWrite @ mem.zir:99 |
| Hook 3 | memory family nonzero; u16/u8/cycle zero |

### 5.4 Instruction card transactions (A4 step 185)

From `instruction_card.json`:

| txn_idx | register | R/W | word | prev_word |
|---------|----------|-----|------|-----------|
| 15055 | (mem addr 524808) | READ | 11863091 | 11863091 |
| 15056 | a0 | READ | 3 | 3 |
| 15057 | a1 | READ | 4 | 4 |
| 15058 | s0 | WRITE | 7 | 0 |

---

## 6. Known gaps, bugs, and overclaims (author self-assessment)

These are areas where the prior agent’s work may be wrong or incomplete — **prioritize auditor time here**.

1. **Apples-to-oranges comparison:** Arguzz mutates random `t0`; A4 mutates `a1` by design. Fair comparison requires either (a) Arguzz hook that targets rs2/a1, or (b) A4 mutation on t0 read at same step, or (c) thesis wording that explicitly allows asymmetric targets.

2. **Hook 3 asymmetry:** Only A4 run enables `A4_FAMILY_RESIDUE=1`. Claim “Arguzz: no Hook 3” is **methodologically weak** — should rerun Arguzz with that env var or soften claim to “Hook 3 not measured.”

3. **Phase 2 not delivered:** `touch_at_add.txt` empty; `RESULTS.md` still references it. Touch bitmap needs different extraction (decode bitmap + cycle index for step 185 / major 0).

4. **Hardcoded steps:** Add step discovered manually once; script does not parse `baseline_trace.txt` to find Add. Rebuild with different compiler flags could shift steps silently.

5. **Step offset documentation:** PLAN.md mentions `a4_pc = arguzz_pc + 4` for alignment; actual **step numbers** differ by 2 (185 vs 187). PC+4 rule is correct for A4 next-PC field; step index offset is separate.

6. **Guest “minimal” claim:** Trace still ~2950+ steps (runtime, commit, crypto). Only **one** guest-authored R-type Add exists; many other Adds are libc/runtime (`artifacts/baseline_trace.txt` grep `"instruction":"Add"`).

7. **Parser fix history:** First `run_phases.py` run failed on `ConstraintFailure.constraint` → fixed to `.loc`. Auditor should confirm no other parser assumptions.

8. **Thesis not updated:** `a4/docs/thesis.md` §3.3.3 still contains fictional step 209 / x1,x2,x3 table with internal contradictions — experiment results not yet merged.

9. **README guest comment:** Says `t0/t1/t2`; actual registers `a0/a1/s0`.

---

## 7. Suggested audit procedure (ordered)

1. Confirm production binary mtime unchanged: `workspace/output/target/release/risc0-host` vs `thesis-minimal-host`.  
2. Read guest source + disassembly if needed: `methods/guest/src/main.rs`.  
3. Parse `artifacts/baseline_trace.txt` steps 185–192; confirm Add site.  
4. Read `a4/core/trace_parser.py` comment on `pc` = next PC.  
5. Verify A4 alignment: find cycle in `step_185_dump.txt` with major=0, minor=0, matching txns.  
6. Read Arguzz inject code path in `rv32im.rs` (when `is_injection_at_step` fires relative to `inc_step`).  
7. Reproduce seed-42 Arguzz run; confirm `<fault>` register choice deterministic from seed.  
8. Apply `a4_mutation.json` manually with `run_a4_mutation`; diff `a4_mut.txt`.  
9. Evaluate IsRead causality for Arguzz t0 corruption (register file / txn graph).  
10. Rerun Arguzz with `A4_FAMILY_RESIDUE=1` + `CONSTRAINT_CONTINUE=1` to test Hook 3 claim.  
11. Fix or reject Phase 2 touch extraction.  
12. Compare constraint loc strings to `PRESENTATION_DEEP_DIVE.md` and ZIR sources under `workspace/risc0-modified/risc0/circuit/rv32im/`.  
13. Review `RESULTS.md` / planned thesis prose against evidence; flag overclaims.

---

## 8. Reproduce matrix (exit codes observed)

| Run | Command / env | exit_code | Notes |
|-----|---------------|-----------|-------|
| Baseline prove | `--trace` | 0 | output 7, verifier success |
| Arguzz inject | `--inject ... step 187 seed 42` | -11 | after IsRead fail |
| A4 mutation | `A4_MUTATION_CONFIG=...` | 101 | IsRead + MemoryWrite + Hook3 memory |

---

## 9. Related conversation context

Full agent transcript (methodology debates, c0c1 vs minimal guest, isolation requirements):

`/root/.cursor/projects/root-arguzz/agent-transcripts/0d9e4f23-4a0e-4572-b325-97e62232a7f0/0d9e4f23-4a0e-4572-b325-97e62232a7f0.jsonl`

Search keywords: `minimal_add`, `thesis_side_experiments`, `PRE_EXEC_REG_MOD`, `step 187`, `isolation`.

---

## 10. Files the auditor can ignore

- `thesis_side_experiments/minimal_add/target/**` except built binary + `methods.rs` (build noise, ~3400 files)  
- `a4/audits/**`, `a4/pos/**` (unrelated campaigns)  
- `a4/arguzz_dependent/**` (explicitly deprecated for this experiment)  
- Duplicate second half of `baseline_trace.txt` (artifact quirk, not source code)

---

*End of audit brief.*
