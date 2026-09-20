# Arguzz-A4 — Bandit-Scheduled Soundness Fuzzing for RISC Zero

This repository contains the **A4 fuzzing architecture**: a learning-scheduled soundness/completeness
fuzzer for the [RISC Zero](https://github.com/risc0/risc0) zkVM. It drives a **custom-instrumented
RISC Zero prover** with two complementary mutation surfaces, selected by a **constrained Thompson-Sampling
bandit**, and scores mutations against a soundness oracle and a semantic coverage model.

It began as a fork of the multi-zkVM [Arguzz](#upstream-arguzz-framework) framework (still preserved here),
but the A4 work — everything under [`a4/`](a4/) plus the instrumented RISC Zero in [`workspace/`](workspace/) —
is self-contained and targets RISC Zero only. **New to this repo? This README + [`a4/builds/README.md`](a4/builds/README.md)
are the two files to read first.**

> ⚠️ **Some prover binaries in this repo are DELIBERATELY UNSOUND** (they contain a planted underconstraint or
> a real CVE). Never treat a binary as a normal RISC Zero without checking its fingerprint — see
> [Binaries & safety](#5-binaries--safety).

---

## Quickstart

```bash
# 1. Clone WITH the instrumented RISC Zero submodule (the instrumentation is committed — no injection step):
git clone git@github.com:ivanvgreiff/arguzz.git && cd arguzz
git submodule update --init --recursive          # fetches workspace/risc0-modified @ arguzz/b7-race-instrumentation

# 2. Build a sound coverage binary (prereqs: rustup + rzup — see §3):
bash a4/scripts/build_sweep_binary.sh g0_baseline   # -> a4/builds/sweep/28e53771_clean__g0_baseline/risc0-host

# 3. Verify the binary is sound, then run a variant (here: A3+Arguzz Bandit):
HOST=a4/builds/sweep/28e53771_clean__g0_baseline/risc0-host
python -m a4.pos.fingerprint_guard $HOST --profile sweep --require-handlers current10
python -m a4.standalone.cli fuzz --host $HOST --db run.db --seed 1234 --num 5000 --selector hybrid_cTS
```
All 6 variants + their launch commands are in §2; the full build recipe in §3; **read §5 before using any binary.**

---

## 1. The architecture in one picture

```
   Python bandit fuzzer  (a4/standalone)                Instrumented RISC Zero  (workspace/risc0-modified)
   ┌───────────────────────────────────┐               ┌──────────────────────────────────────────────┐
   │ bandit picks an ARM (kind, zone…)  │  subprocess   │ compiled-in hooks:                             │
   │ → builds a mutation config / flags │ ────────────► │  • Arguzz during-exec fault injection (rv32im) │
   │ → runs risc0-host                  │   env vars +  │  • A4 post-exec trace-cell mutation (witgen)   │
   │ ← parses verifier accept/reject,   │  --inject /   │  • Hook 3 coverage/residue (ffi.cpp)           │
   │    coverage, constraint failures   │  A4_* config  │  • local-constraint touch-marking (witgen.h)   │
   │ → updates posterior, records DB    │ ◄──────────── │                                                │
   └───────────────────────────────────┘               └──────────────────────────────────────────────┘
```

The fuzzer never patches source at runtime. **All instrumentation is compiled into the binary**; the Python
side chooses *which* mutation to apply *per iteration* via environment variables and `--inject` CLI flags.

**Two mutation surfaces:**
- **Arguzz** — *during-execution* fault injection (mutate the fetched instruction word, a register, PC, a
  computed result, … as the emulator runs). Faults **propagate** through execution.
- **A3** (called `A4` in code identifiers) — *post-execution* edits of a recorded `PreflightTrace` cell
  (instruction type, a memory transaction's `prev_word`/`prev_cycle`, a cycle's `diff_count`, …). Single-cell,
  **non-propagating**.

The two surfaces are complementary: each reaches soundness bugs the other structurally cannot (see
[Experiments & results](#experiments--results)).

---

## 2. The variants

The canonical registry is [`a4/standalone/variants.py`](a4/standalone/variants.py) (`CANONICAL_VARIANTS`);
`variant_launch_command()` there generates the exact launch argv. Six variants:

| Thesis name | Code name | Surface | Scheduler | Role |
|---|---|---|---|---|
| **Arguzz** | `V6_uniform` | Arguzz (during-exec) | balanced round-robin, no bandit | **baseline** |
| **Arguzz Bandit** | `V6_cTS` | Arguzz | constrained Thompson Sampling (cTS) | Arguzz + learning |
| **A3 Bandit** | `V5_control` | A3 (post-exec trace-cell) | cTS bandit | the novel A3 surface |
| **A3+Arguzz Bandit** | `Hybrid_cTS` | both | cTS bandit | combined surfaces |
| **V0** | `V0_uniform` | A3 | semantic-arm uniform, no bandit | scheduler-ablation rung |
| **V8** | `V8_arguzz_sched` | A3 | Arguzz-style round-robin, no arms | scheduler-ablation rung |

`Arguzz` is the baseline; `V0`/`V8` exist for the scheduler ablation ladder **V8 → V0 → V5** (does arm
structure help? does the bandit help?).

**Launch commands** (`<host>` = a `risc0-host` binary from [`a4/builds/`](a4/builds/); `<guest args>` are
passed to the guest):

```bash
# Arguzz (baseline) — dedicated driver:
python -m a4.standalone.v6_uniform_driver --host <host> --db run.db --seed 1234 --num 5000 -- <guest args>

# All other variants — cli fuzz with a --selector:
python -m a4.standalone.cli fuzz --host <host> --db run.db --seed 1234 --num 5000 --selector <SEL> -- <guest args>
#   Arguzz Bandit        --selector v6_cTS
#   A3 Bandit            --selector cTS_semantic_v2
#   A3+Arguzz Bandit     --selector hybrid_cTS
#   V0 (ablation)        --selector a4_uniform_semantic
#   V8 (ablation)        --selector a4_arguzz_sched
```

---

## 3. Building the instrumented RISC Zero from a clone

**You do NOT need to run any Python "injection" step to add the instrumentation** — it is committed in the
RISC Zero submodule branch, so a clone builds it directly.

> **Why this differs from upstream Arguzz (important — this is a common point of confusion).** Upstream Arguzz
> fuzzes six zkVMs it does *not* own, so it keeps them as **stock** external repos and **injects** the
> instrumentation *at install time* with Python (`… install --zkvm-modification`, implemented in
> `libs/zkvm-fuzzer-utils/`). The A4 work targets **only** RISC Zero, so instead we made a **persistent fork**
> ([`ivanvgreiff/risc0`](https://github.com/ivanvgreiff/risc0), branch `arguzz/b7-race-instrumentation`) and
> **committed the instrumentation into it**. Pinning that exact commit as a submodule gives every researcher
> byte-identical instrumented source with nothing to inject at clone time.
> [`a4/injection/`](a4/injection/) holds the *same* patcher logic upstream uses, but we ran it **once** and
> committed the result — it is imported by **nothing** in the fuzzing path and exists only to re-derive the
> hooks if the fork is ever rebased onto a newer upstream RISC Zero.
>
> **Proof:** a fresh `git clone` of the branch already contains every hook — with no build-time patch step:
> ```bash
> git clone --depth 1 -b arguzz/b7-race-instrumentation git@github.com:ivanvgreiff/risc0.git /tmp/r0 && \
> grep -c RV32IMFaultInjectionContext /tmp/r0/risc0/circuit/rv32im/src/execute/rv32im.rs && \
> grep -c A4_MUTATION_CONFIG        /tmp/r0/risc0/circuit/rv32im/src/prove/witgen/mod.rs && \
> grep -c a4_touch_mark             /tmp/r0/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp && \
> ls /tmp/r0/fuzzer_utils/src/lib.rs        # all present -> instrumentation is committed, not injected
> ```

**Prerequisites (once):**
- **Rust** via `rustup` — toolchains are pinned per-workspace by `rust-toolchain.toml` (auto-selected: `1.88`
  for `risc0-modified`, `1.85` for `workspace/output`). No root `rust-toolchain.toml`.
- **`rzup`** with the default RISC Zero guest toolchain — required to compile the RISC-V guest ELF
  (`risc0_build::embed_methods` resolves the C++/Rust guest toolchains via `rzup`). Install separately
  (it is *not* installed by any script in this repo).
- **Python 3** with the repo root on `PYTHONPATH` (all launchers are `python -m a4.…`).

**Steps:**
```bash
git clone <this-repo> arguzz && cd arguzz
git submodule update --init --recursive     # pulls workspace/risc0-modified @ arguzz/b7-race-instrumentation

# Build a host binary (pick the script for the binary family you want):
bash a4/scripts/build_sweep_binary.sh g0_baseline   # clean coverage binary for a guest
bash a4/scripts/build_seamb_fix.sh                  # Seam-B planted-bug pair (control + holed)
bash a4/scripts/build_ap_binaries.sh                # dead Seam-A pair (control + holed)
# (the CVE binaries a1_cve / a1_cve_patched / a1_cve_b3_handlers are built manually per
#  a4/docs/cloud3/IV_POS_9_A1_VULN_BUILD_SPEC.md)
```
Every build script ultimately runs `cargo build --release -p risc0-host` against the **already-instrumented**
worktree; the only source-mutation step any script performs is applying a *planted-bug* patch
(`ap_verifyopcode_patch.py` / `ap_isread_patch.py`) for the deliberately-holed binaries. Each script bakes a
provenance fingerprint into the binary and archives it read-only under `a4/builds/`.

**Reproducibility notes:**
- Builds are **not byte-identical** (embedded absolute build paths shift the guest `image_id`); the
  **`fingerprint.json` is the trust anchor**, not a bit-identical rebuild. A rebuilt binary is
  *functionally equivalent* and fingerprint-verifiable.
- `a4/injection/` is a **legacy re-derivation tool** — it re-applies the A4 hooks if the fork is ever rebased
  onto a fresh upstream RISC Zero. It is **not** used in the normal build/run path.

---

## 4. What's in the instrumented RISC Zero

Against stock RISC Zero (base `ebd64e43`, PR #3305) the instrumented tree modifies **67 files**. The load-bearing
hooks (all committed on branch `arguzz/b7-race-instrumentation`):

| Instrumentation | File(s) | Purpose |
|---|---|---|
| **A4 post-exec mutation handlers** | `circuit/rv32im/src/prove/witgen/mod.rs` | 15 `A4_MUTATION_CONFIG` match arms editing recorded preflight trace cells |
| **Arguzz during-exec fault injection** | `circuit/rv32im/src/execute/rv32im.rs` | `RV32IMFaultInjectionContext`; INSTR_WORD_MOD, PRE/POST_EXEC_*, BR_NEG_COND, COMP/LOAD/STORE_OUT |
| **Hook 3 coverage / residue** | `circuit/rv32im-sys/kernels/cxx/ffi.cpp` | touch bitmap, per-family LogUp residues, global grand-product residue |
| **Local-constraint touch-marking** | `.../kernels/cxx/witgen.h` | `eqz()` → `a4_touch_mark` + `<constraint_fail>` + `CONSTRAINT_CONTINUE` |
| **Fault-injection control plane** | new `fuzzer_utils` crate | `set_injection()` bridges Rust↔C++ via `FAULT_INJECTION_ENABLED` |
| **Residue / witness localization** | `eval_check.cpp`, `zkp/src/prove/prover.rs`, `circuit/rv32im/src/prove/hal/mod.rs` | poly-nonzero scanners; A3 witness-cell harness (`A3_CONFIG`) |

Notes: **zirgen is NOT modified** for the clean instrumented binary (it builds from checked-in generated
kernels with stock zirgen). **CUDA has no Hook 3** (coverage/residue are CPU-only). `A4_MEM_FINGERPRINT`
(named in an old commit message) was never implemented.

**Runtime interface (env vars the Python fuzzer sets):** `A4_MUTATION_CONFIG` (JSON → post-exec mutation),
`A4_COVERAGE_TOUCH[_VERBOSE]`, `A4_FAMILY_RESIDUE`, `A4_GLOBAL_RESIDUE`, `A4_INSPECT`, `A4_DUMP_*`,
`A3_INSPECT`/`A3_CONFIG`, `CONSTRAINT_CONTINUE`, and `FAULT_INJECTION_ENABLED` (set indirectly by
`fuzzer_utils`). During-execution Arguzz faults are configured via the `risc0-host --inject …` CLI flags.

---

## 5. Binaries & safety

Compiled `risc0-host` binaries live under [`a4/builds/`](a4/builds/) (git-ignored — too large for GitHub;
each has a tracked `fingerprint.json` + `sha256.txt`). **Read [`a4/builds/README.md`](a4/builds/README.md)
before using any of them.**

⚠️ **Several binaries are deliberately unsound and will ACCEPT invalid proofs.** A binary is safe for general
use **only if `planted_bug == none` AND `load_rs2_present == 1`**. The `load_rs2_present: 0` flag marks the
CVE-vulnerable builds even though their `planted_bug` reads `none`. Verify any binary with:

```bash
python -m a4.pos.fingerprint_guard a4/builds/<dir>/risc0-host --emit-json
```

| Status | Binaries |
|---|---|
| ✅ **SOUND** | `sweep/*` (g0–g3), all `*/control`, `a1_cve_patched`, `ap/patched` |
| ⛔ **PLANTED-UNSOUND** | `ap_seamb/bench-verifyopcode`, `ap_seamb_fix/bench-verifyopcode` (decode hole), `ap/bench-isread` (dead Seam-A) |
| ⛔ **CVE-VULNERABLE** | `a1_cve`, `a1_cve_b3_handlers` (rs1==rs2 double-read) |

---

## 6. Experiments & results

All final experiments are under [`a4/runs/iv_pos_9/`](a4/runs/iv_pos_9/):

- **Coverage sweep** — [`sweep/campaign_stepdomain_rerun/`](a4/runs/iv_pos_9/sweep/campaign_stepdomain_rerun/):
  the 4 variants over 4 guest programs (g0 metamorphic mixed-arithmetic, g1 syscall/control, g2 memory-stress,
  g3 accelerator/SHA). Local-context and CGC coverage curves + territory bars.
- **Seam-B bug race** (`INSTR_TYPE_MOD` finds a planted VerifyOpcode decode hole) —
  [`race/`](a4/runs/iv_pos_9/race/) + [`ap/`](a4/runs/iv_pos_9/ap/). A3-surface variants find it; pure Arguzz
  structurally cannot.
- **CVE bug race** (`INSTR_WORD_MOD` finds CVE-2025-52484, the rs1==rs2 double-read) —
  [`a1/`](a4/runs/iv_pos_9/a1/) + [`cve_postfix_analysis/`](a4/runs/iv_pos_9/cve_postfix_analysis/). The mirror:
  Arguzz-surface variants find it; pure A3 cannot.

> **Semantic-mapping fix:** the Arguzz-surface coverage results were re-run after fixing a step-domain
> zone-mapping bug (commit `68d90aa`, 2026-06-27). The **post-fix** coverage data lives in
> `campaign_stepdomain_rerun/` — treat the older `sweep/data/*.db` as superseded.

---

## 7. Repo layout

```
a4/                     THE A4 architecture (self-contained; imports nothing from libs/ or projects/)
  standalone/           core fuzzer: cli, bandit (bandit_ts), variants.py, selectors, coverage, reward
  core/                 executor / trace_parser / touch_coverage / inspection_data
  mutations/            A4 mutation-kind modules + arguzz_bridge
  common/, arguzz_dependent/   helpers the fuzzer imports
  builds/               compiled risc0-host binaries (git-ignored) + tracked fingerprints — SEE its README
  runs/iv_pos_9/        the final experiments (coverage sweep + two bug races)
  scripts/              build scripts (build_sweep_binary.sh, build_seamb_fix.sh, build_ap_binaries.sh) + patches
  pos/                  POS dispatch + fingerprint_guard.py
  docs/                 plans, reports, thesis material
  injection/            legacy hook re-derivation tool (not in the normal path)
workspace/
  risc0-modified/       the instrumented RISC Zero (git submodule @ arguzz/b7-race-instrumentation)
  output/               canonical build harness (host + guest methods) — tracked source
zirgen/                 RISC Zero circuit DSL (submodule; stock for the clean binary)
projects/, libs/, scripts/, UPSTREAM_README.md   the original multi-zkVM Arguzz framework (see below)
```

### Code map — the Python fuzzing architecture (where to look / what to edit)

This is the *host* side (the RISC Zero *instrumentation* side is mapped in §4).

| Concern | File | Role |
|---|---|---|
| **Variant registry** | `a4/standalone/variants.py` | the 6 canonical variants + `variant_launch_command()` |
| **Entry point** | `a4/standalone/cli.py` | the `fuzz` command; `--selector` → variant dispatch |
| **Baseline driver** | `a4/standalone/v6_uniform_driver.py` | launches `Arguzz` (`V6_uniform`) |
| **Main fuzz loop** | `a4/standalone/fuzzer.py` | `A4Fuzzer`: runs `risc0-host`, applies the mutation, scores accept/reject + coverage, records the run DB |
| **Bandit** | `a4/standalone/bandit_ts.py` | `ConstrainedTSScheduler` (cTS) — the learning scheduler |
| **Arm space** | `a4/standalone/semantic_arm_universe.py` | the `(kind, zone)` arm universe + step-domain map (the `68d90aa` fix) |
| **Non-bandit selectors** | `a4/standalone/step_selector.py` | the uniform (`V0`) and Arguzz-sched (`V8`) selectors |
| **Mutation kinds** | `a4/standalone/mutations/` | per-kind config builders; `arguzz_bridge.py` bridges the Arguzz surface |
| **Coverage & reward** | `a4/standalone/{coverage_state,reward_v2,compressed_global,compressed_global_extractor}.py` | the semantic coverage model (local contexts + CGC) and reward |
| **Runtime injection glue** | `a4/standalone/arguzz_invoke.py` | builds the `risc0-host --inject …` invocation for the Arguzz surface |
| **Oracle** | `a4/runs/iv_pos_9/race/oracle.py` | confirms a soundness find (control-replay) |
| **Binary guard** | `a4/pos/fingerprint_guard.py` | verify a binary's fingerprint + handler set before use |

Key docs: `a4/docs/ARGUZZ_A4_KNOWLEDGE_BASE.md`, `a4/runs/iv_pos_9/a1/BINARY_REGISTRY_AND_NOMENCLATURE.md`,
`a4/docs/cloud3/SEAMB_PLANTED_UNDERCONSTRAINT_REPORT.md`.

---

## Upstream Arguzz framework

This repo is a fork of the multi-zkVM **Arguzz** framework (Jolt / NexusVM / OpenVM / Pico / RISC Zero / SP1),
which is preserved intact under [`projects/`](projects/), [`libs/`](libs/), and [`scripts/`](scripts/). The A4
work does not use it. Its original documentation is kept verbatim in
[`UPSTREAM_README.md`](UPSTREAM_README.md) (build/run instructions, CSV formats, bug trophies).
