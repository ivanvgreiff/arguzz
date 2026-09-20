# AP.B2 Opus Follow-Up — Composer Report

**Date:** 2026-06-22  
**Context:** Opus independently verified vendor-workflow scripts and issued five ordered flags. This report records agreement, actions taken, and the concrete next steps.

---

## 1. Agreement with Opus verification

I re-checked every load-bearing claim Opus marked ✅. **Full agreement — no corrections.**

| Opus claim | Composer verification |
|------------|-------------------------|
| Vendored model | `rv32im-sys/build.rs` compiles committed `kernels/cxx/*.cpp` only; no zirgen at cargo time |
| `eval_check.cpp` exclusion | Not in `BUILD.bazel` OUTS; hand-written CPU driver with A4 hooks; 0 IsRead terms |
| Constraint poly in REGEN_PATHS | `rust_poly_fp_*.cpp` + `poly_ext.rs` + `info.rs` — all listed in `ap_zirgen_regen.sh` |
| Bootstrap install safety | `install_from_bazel` copies only bazel-emitted paths; `ffi.cpp` / `witgen.h` / `eval_check.cpp` not codegen outputs |
| `restore_committed_circuit()` safe | A4 harness is in git HEAD (`witgen.h` eqz logging committed); regen scripts restore circuit dirs only |
| `--from-regen` mixed-generator fix | Patched ← `zirgen_control`, bench ← `zirgen_holed`, both df6fb9d snapshots |
| Option B default | Sound: AP bracket is within-binary; honest-gate is the real correctness condition |

**Bottom line:** Direction and script structure are correct. The only true blocker is **proving gen_zirgen builds in this environment** (Opus flag B).

---

## 2. Opus flags — response and actions

### Flag B (blocker): gen_zirgen unbuilt

**Opus:** Treat “build gen_zirgen + one codegen run” as an isolated checkpoint before chaining control-regen → honest-gate.

**Action taken:**

Created `a4/scripts/ap_zirgen_build_spike.sh`:

```bash
USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_build_spike.sh        # stages 1+2
USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_build_spike.sh --stage 1  # gen_zirgen only
```

- Stage 1: `bazel build //zirgen/Main:gen_zirgen`
- Stage 2: `bazel build //zirgen/circuit/rv32im/v2/dsl:codegen`
- Logs: `a4/runs/iv_pos_9/ap/build_spike.log`

Updated `ap_zirgen_regen.sh` header to require spike first.

**Runtime status (this environment):**

A prior `control-check` run (equivalent to stage 2) has been **in progress ~25+ min** at last check:

| Phase | Status |
|-------|--------|
| Bootstrap compile | ✅ Done |
| Bazel server start | ✅ Done |
| LLVM/hermetic toolchain | ✅ Fetched |
| **Conda env solve** (`rules_conda` + `environment.yml`) | ⏳ **In progress** — `conda install` + `repodata.json` fetch |

This matches Opus’s “conda-in-bazel rabbit hole” warning. The build is not failed; it is slow. **No chained regen/honest-gate should run until spike completes.**

Expected failure modes if it eventually fails:

- Conda solve timeout / network to conda-forge
- LLVM compile OOM on constrained hosts
- Missing system deps for hermetic_cc_toolchain

Fallback (only if spike fails after full attempt): locate pre-generated OUTS from a RISC Zero release matching v4.0.0 / `RV32IM:v2rev2___` and vendor-copy manually — last resort, loses holed `.zir` codegen unless another machine runs zirgen.

---

### Flag A: Re-resolve (0,1,0) corpus on df6fb9d control

**Opus:** Corpus `ap_corpus_010.json` was derived on committed circuit; `(step, txn_idx)` transfer under Option B is plausible but unproven.

**Reasoning:**

- Corpus entries key on `(step, txn_idx)` + `next_read` strategy — runtime mutation targets, not compile-time circuit IDs.
- IsRead removal changes **constraints**, not the guest execution trace for honest/mutated witgen paths.
- **Mutated-V0 smoke is the drift detector:** if indices miss under df6fb9d control, `patched_rejects` or `bench_accepts` will fail.

**Action taken:**

Extended `_v0_mutated_smoke()` in `ap_b1_verify.py` to emit:

- `corpus_step`, `corpus_txn_idx`
- `patched_circuit_source`, `bench_circuit_source` from `fingerprint.json`
- `corpus_resolution_note` — explicit that corpus is from committed-circuit POS screen and is valid under Option B **only when** `patched_circuit_source == zirgen_control`

**No corpus re-screen yet** — correct per Opus: wait until df6fb9d control host exists, then mutated-V0 gate validates or fails. Re-screen only if gate fails with evidence of index drift (not before regen completes).

---

### Flag C: Confirm AP stays on segment/fast path

**Opus:** Low risk — failure was literally `verify segment`.

**Verified:**

```156:159:workspace/output/host/src/main.rs
    let opts = ProverOpts::fast(); // linear in size of proof
    // let opts = ProverOpts::succinct(); // requires a big timeout
    let prover = default_prover();
    let prove_info = match prover.prove_with_opts(executor_env, RISC0_GUEST_ELF, &opts) {
```

```278:280:workspace/risc0-modified/risc0/zkvm/src/host/server/prove/prover_impl.rs
        receipt
            .verify_integrity_with_context(ctx)
            .context("verify segment")?;
```

AP uses **segment prove + segment verify** (`ProverOpts::fast()`), not succinct/recursion lift. Regen changes `info.rs`/`taps.rs` but the in-binary circuit is self-consistent; honest-gate covers soundness. **No action required beyond this confirmation.**

---

### Flag D: Commit `witgen/mod.rs`

**Opus:** Live `A4_MUTATION_CONFIG` hook is uncommitted (+345 lines); stash/checkout during regen could lose it.

**Verified:**

```
 M risc0/circuit/rv32im/src/prove/witgen/mod.rs  (+345 lines)
```

**Action taken (without git commit — user must approve commits):**

- Snapshot: `a4/builds/ap/harness-snapshots/witgen_mod.rs.20260622`
- SHA256: `90906b0d55e0e9089c1cb474f6dcc059a0c6a17d72846964a331f2c1892dfd55`

**Recommendation:** Commit to `workspace/risc0-modified` on branch `arguzz/b7-race-instrumentation` before any `git checkout` of broader paths. Regen scripts currently checkout only circuit artifact dirs, not `prove/witgen/mod.rs` — but committing removes the risk entirely.

---

### Flag E (implicit): Run control-check / semantic-diff opportunistically

**Opus:** Cheap once gen_zirgen builds; upgrades to Option A for free if they pass.

**Plan:** After spike success and `control-regen`:

1. `bash a4/scripts/ap_zirgen_regen.sh control-check` — byte-normalized diff vs committed
2. `bash a4/scripts/ap_zirgen_regen.sh semantic-diff` — PolyExt opcode sequence + `info.rs` mix constants

Neither blocks Option B if they fail.

---

## 3. What I did NOT undo

All vendor-workflow work from the prior session remains in place:

- `ap_zirgen_regen.sh` (Option B pipeline)
- `ap_zirgen_semantic_diff.py`
- `build_ap_binaries.sh --from-regen` self-consistent pair
- GP1 loosened witgen + loc-tag gate
- `--honest-only` gate

Only **additions** this session: build spike script, witgen snapshot, mutated-V0 metadata, segment-path confirmation, this report.

---

## 4. Ordered next steps (when Bazel completes)

```
[BLOCKED NOW] USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_build_spike.sh
              └─> or wait for in-flight control-check to finish (same codegen target)

1. bash a4/scripts/ap_zirgen_regen.sh control-regen
   └─> snapshot: a4/builds/ap/regen-snapshots/control-<sha>/

2. bash a4/scripts/ap_zirgen_regen.sh honest-gate          [HARD]
   └─> df6fb9d unmodified proves+verifies guest

3. (optional) control-check + semantic-diff               [Option A upgrade]

4. bash a4/scripts/ap_zirgen_regen.sh holed-regen
   └─> snapshot: a4/builds/ap/regen-snapshots/holed-<sha>/

5. bash a4/scripts/build_ap_binaries.sh --from-regen
   └─> fingerprints: circuit_source zirgen_control / zirgen_holed

6. python3 a4/scripts/ap_b1_verify.py                     [HARD]
   └─> GP1 zero ReadReg loc-tags; V0 mutated w/ circuit_source metadata

7. python3 a4/scripts/ap_b2_replay.py --bracket-only
   └─> GP4/GP5 — first real (0,1,0) theory test
```

**Before step 1:** commit or preserve `witgen/mod.rs` (snapshot already saved).

---

## 5. Files touched this session

| File | Change |
|------|--------|
| `a4/scripts/ap_zirgen_build_spike.sh` | **New** — isolated gen_zirgen + codegen checkpoint |
| `a4/scripts/ap_zirgen_regen.sh` | Header: spike prerequisite |
| `a4/scripts/ap_b1_verify.py` | Mutated-V0 corpus/circuit_source metadata (flag A) |
| `a4/builds/ap/harness-snapshots/witgen_mod.rs.20260622` | **New** — witgen/mod.rs backup (flag D) |
| `a4/runs/iv_pos_9/ap/AP_B2_OPUS_FOLLOWUP_REPORT.md` | This document |

---

## 6. Decision summary

| Question | Answer |
|----------|--------|
| Agree with Opus? | **Yes** — verification matches independent checks |
| Undo prior work? | **No** — structurally sound; only add spike + metadata |
| Option A vs B? | **B default**; A checks opportunistic post-spike |
| Immediate action? | **Wait for / monitor build spike** (conda solve in flight) |
| Blocker? | gen_zirgen/codegen bazel build — everything else is queued behind it |

The `(0,1,0)` theory and full GP4/GP5 bracket remain untested until steps 1–6 complete successfully.
