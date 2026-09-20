# AP.B2 Vendor Workflow Clarification — Composer Report

**Date:** 2026-06-22  
**Trigger:** User clarified `/root/arguzz/zirgen` is a local reference clone, not part of the normal repo. Opus analyzed how risc0-modified actually obtains constraints and reshaped the plan.

---

## 1. Do I agree with Opus?

**Yes — fully, on every substantive point.** I verified the claims independently before changing direction.

### Verified: constraints are vendored, not generated at build time

```30:38:workspace/risc0-modified/risc0/circuit/rv32im-sys/build.rs
fn build_cpu_kernels() {
    rerun_if_changed("kernels/cxx");
    KernelBuild::new(KernelType::Cpp)
        .files(glob_paths("kernels/cxx/*.cpp"))
        ...
        .compile("risc0_rv32im_cpu");
}
```

- `poly_ext.rs`, `info.rs`, `taps.rs` are committed Rust under `risc0/circuit/rv32im/src/zirgen/`
- Loc-comments like `zirgen/circuit/rv32im/v2/dsl/mem.zir` are baked-in text from offline codegen
- Arguzz `.gitmodules` only lists `workspace/risc0-modified` — **no zirgen submodule**
- Circuit crate version: `risc0-circuit-rv32im` **4.0.0**, protocol `RV32IM:v2rev2___` in `info.rs`

**Conclusion:** RISC Zero runs zirgen offline, checks output into the repo. Our `/root/arguzz/zirgen` clone is reference-only; cargo never invokes it.

### Verified: A4 harness is separate from zirgen output

Bootstrap `rv32im_v2` copies only bazel-emitted files matching `*.cpp`, `*.cu`, `*.rs`, etc. from `//zirgen/circuit/rv32im/v2/dsl:codegen`.

**Not in zirgen OUTS** (from `BUILD.bazel`): `ffi.cpp`, `witgen.h`, `eval_check.cpp`.

These contain A4 instrumentation and **must not be wiped** by regen:

| File | A4 content |
|------|------------|
| `kernels/cxx/witgen.h` | Enhanced `eqz()` logging, `a4_touch_mark`, constraint_fail JSON |
| `kernels/cxx/ffi.cpp` | `A4_COVERAGE_TOUCH`, `A4_MUTATION_CONFIG`, family/global residue |
| `kernels/cuda/ffi.cu` | Same hooks (CUDA path) |
| `rv32im/src/prove/witgen/mod.rs` | `A4_MUTATION_CONFIG`, dump hooks |

Bootstrap install is selective — a sloppy manual `cp -r` would be dangerous; bootstrap itself is safe **if we only install via bootstrap rules** (which we do).

### Opus Option A vs Option B

| | Option A (comparability) | Option B (pragmatic) |
|--|--------------------------|----------------------|
| Goal | Prove df6fb9d == committed generator | AP self-consistent on df6fb9d |
| Patched baseline | Committed circuit (or df6fb9d if match proven) | df6fb9d **unmodified** regen |
| Bench | df6fb9d holed regen | df6fb9d holed regen |
| Joinable with CVE/sweep? | Yes, if semantic diff passes | **No** — AP isolated |
| Hard gate | Byte/semantic diff + honest proof | **Honest proof only** |

**My decision: Option B**, with Option A checks as **informational**.

Reasoning (not guesses):

1. **No pin exists** in risc0-modified for which zirgen produced v4.0.0 — protocol string match is necessary, not sufficient.
2. **AP already uses separate binaries** with internal patched-control bracket; it does not require the committed circuit for patched if both arms share the same generator.
3. **CVE/sweep tracks** should stay on committed circuit — documented isolation, not a build dependency.
4. **Hard gate** Opus identified is correct and cheaper: df6fb9d unmodified regen must prove+verify the guest honestly. Without that, no zirgen revision is usable.

If `control-check` or `semantic-diff` later passes, we can **upgrade** to Option A without redoing holed regen.

---

## 2. Do I need to undo prior work?

**No full undo.** Prior work remains valid; one workflow assumption needed correction.

| Prior work | Still valid? | Change |
|------------|--------------|--------|
| Route 2 dead-end diagnosis | ✓ | Keep |
| GP1 loc-tag gate (form-agnostic) | ✓ | Keep |
| GP1 loosened witgen checks | ✓ | Keep |
| Mutated V0 smoke as authoritative gate | ✓ | Keep |
| `ap_zirgen_regen.sh` | ✓ | **Revised** (see below) |
| `control-check` as **hard** blocker | ✗ | Demoted to informational (Option A) |
| `--from-regen` patched = git committed | ✗ | **Fixed** — patched = df6fb9d control snapshot |
| df6fb9d assumed == committed generator | ✗ | Removed assumption |

**What I did NOT undo:**

- GP1 fixes in `ap_b1_verify.py`
- Route 2 surgical patch script (legacy path; unused after regen)
- `.zir` edits in zirgen clone (`MemoryReadNoIsRead`)

---

## 3. What I changed this session (exact diffs)

### 3.1 `a4/scripts/ap_zirgen_regen.sh` — rewritten for vendor workflow

**Before:** Single `control-check` hard gate assuming df6fb9d byte-reproduces committed artifacts.

**After:** Multi-step Option B pipeline:

| Command | Purpose | Gate type |
|---------|---------|-----------|
| `control-regen` | Stash holed `.zir`, bootstrap **install** unmodified, snapshot to `a4/builds/ap/regen-snapshots/control-<sha>/` | Required before honest-gate |
| `control-check` | Bootstrap `--check` vs committed (after `git checkout` to strip Route 2 patches) | **Soft** — Option A info |
| `honest-gate` | Restore control snapshot, build patched, `--honest-only` verify | **Hard** |
| `holed-regen` | Restore holed `.zir`, bootstrap install, snapshot to `regen-snapshots/holed-<sha>/` | Required before bracket |
| `semantic-diff` | Compare PolyExt opcode sequences (ignores loc comments) | **Soft** — Option A info |

**Snapshot scope:** Explicit `REGEN_PATHS` list — zirgen-generated files only, excludes `ffi.cpp`, `witgen.h`, `eval_check.cpp`.

**Bug fixed:** Bootstrap CLI uses positional `rv32im-v2`, not `--circuit rv32im-v2`.

### 3.2 `a4/scripts/build_ap_binaries.sh` — Option B pair

**Before (`--from-regen`):** Patched from git-committed circuit, bench from holed snapshot — **mixed generators** (wrong).

**After:**

- `--from-regen`: patched ← control snapshot, bench ← holed snapshot (both df6fb9d)
- `--control-only`: patched only (for honest-gate)
- Fingerprints include `zirgen_head_sha` and `circuit_source` (`zirgen_control` / `zirgen_holed` / `committed` / `surgical`)

### 3.3 `a4/scripts/ap_b1_verify.py`

- Loosened witgen checks (function-name level) — **unchanged from prior session, still valid**
- Added `--honest-only` for df6fb9d control-regen gate
- Loc-tag scan includes `steps.cpp` / `steps.cu`

### 3.4 `a4/scripts/ap_zirgen_semantic_diff.py` — new

Compares `PolyExtStep::Op(args)` sequences and `info.rs` mix constants between committed tree and control snapshot. For Option A comparability without requiring byte-identical loc comments.

### 3.5 Infrastructure

- Installed **bazelisk** with `USE_BAZEL_VERSION=6.0.0` (matches `zirgen/.bazelversion`)
- Started `control-check` (first attempt failed on CLI; second attempt was running Bazel LLVM fetch when interrupted)

---

## 4. Correct workflow going forward

```
1. USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_regen.sh control-regen
   └─> snapshot: a4/builds/ap/regen-snapshots/control-<sha>/

2. bash a4/scripts/ap_zirgen_regen.sh honest-gate          [HARD — must pass]
   └─> df6fb9d unmodified circuit proves+verifies guest

3. (optional) bash a4/scripts/ap_zirgen_regen.sh control-check
   (optional) bash a4/scripts/ap_zirgen_regen.sh semantic-diff
   └─> if pass: AP joinable with CVE/sweep on committed circuit

4. bash a4/scripts/ap_zirgen_regen.sh holed-regen
   └─> snapshot: a4/builds/ap/regen-snapshots/holed-<sha>/
   └─> overwrites: steps, poly_fp, poly_ext, info.rs, taps, layout, eval_check_*

5. bash a4/scripts/build_ap_binaries.sh --from-regen
   └─> patched = control snap, bench = holed snap (no ap_isread_patch.py)

6. python3 a4/scripts/ap_b1_verify.py
   └─> GP1: zero IsRead@ReadReg loc-tags; V0 mutated smoke [HARD]

7. python3 a4/scripts/ap_b2_replay.py --bracket-only
   └─> GP4/GP5 only after step 6 passes
```

**Isolation rule:** Document in AP reports that post-regen AP binaries use `circuit_source: zirgen_*` and must not be cross-compared with CVE/sweep numbers from `circuit_source: committed` unless Option A checks pass.

---

## 5. Bazel build status

| Attempt | Result |
|---------|--------|
| 1 | Failed: `--circuit` CLI typo |
| 2 | In progress: bootstrap compiled, Bazel 6.0.0 analyzing/fetching LLVM + conda env (~15+ min elapsed at interrupt) |

**Cost remains real:** First `//zirgen/circuit/rv32im/v2/dsl:codegen` build requires pinned LLVM/MLIR. This is unavoidable for any regen path — but we no longer need byte-match to committed as prerequisite.

---

## 6. Current gate snapshot (Route 2 tree — pre-regen)

From `ap_b1_verify.json` (still valid):

| Gate | Pass | Notes |
|------|------|-------|
| GP1 loc-tags | FAIL | 108 ReadReg tags (surgical Route 2) |
| GP1 witgen (loosened) | PASS | Function-name checks survive regen |
| V0 honest | PASS | Both hosts (surgical patch) |
| V0 mutated | **FAIL** | Authoritative — bracket invalid |

Route 2 binaries (`808152f1…`) remain **invalid for GP4/GP5**.

---

## 7. Answers to your questions

**Do you agree?** Yes. Opus's vendor-model analysis is correct and changes the *weight* of gates, not the *direction* (regen still required).

**Undo prior work?** No. Correct the mixed-generator `--from-regen` bug and demote byte-identical pin from hard to soft gate.

**Proceed how?** Option B with honest-gate hard stop. Option A checks run when Bazel completes but do not block AP if honest-gate passes.

**Educated vs guessed:**

- *Verified:* build.rs vendoring, no zirgen submodule, harness file separation, BUILD.bazel OUTS list
- *Decision:* Option B default — justified by AP's isolated binary design + absent pin, not by assumption df6fb9d is wrong
- *Not yet verified:* df6fb9d honest proof (blocked on Bazel build completion)

---

## 8. Files touched (this + prior session)

| File | Status |
|------|--------|
| `a4/scripts/ap_zirgen_regen.sh` | Rewritten for Option B vendor workflow |
| `a4/scripts/ap_zirgen_semantic_diff.py` | New |
| `a4/scripts/build_ap_binaries.sh` | Fixed `--from-regen` for self-consistent pair |
| `a4/scripts/ap_b1_verify.py` | Loosened GP1 + `--honest-only` |
| `a4/runs/iv_pos_9/ap/AP_B2_OPUS_REVIEW_RESPONSE.md` | Prior Opus gap response (partially superseded by this doc) |
| `a4/runs/iv_pos_9/ap/AP_B2_VENDOR_WORKFLOW_REPORT.md` | This document |

**Next action when Bazel is ready:** Run `control-regen` → `honest-gate` → (optional comparability) → `holed-regen` → full verify + bracket.
