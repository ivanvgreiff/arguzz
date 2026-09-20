# AP.B2 — State of Play + Root-Cause Diagnosis (handoff for stronger model)

**Date:** 2026-06-23
**Author:** Opus (review of Composer's AP.B2 circle report + independent on-disk verification)
**Purpose:** Give a precise, evidence-grounded picture of where the AP planted-IsRead-bug track
actually stands, correct two misdiagnoses in `AP_B2_CIRCLE_REPORT.md`, and hand a clean decision
to a more powerful reviewer. Companion to the journey log `a4/docs/cloud3/AP_TRACK_AUDIT_LOG.md`.

---

## 0. Bottom line (read this first)

The AP.B2 failure is **not** a science failure, **not** a df6fb9d-vs-guest incompatibility, and
**not** a guest/circuit-pairing problem (Composer's two hypotheses). It is a **build-plumbing bug**:

> The regen scripts copy the generated **Rust** circuit files (`poly_ext.rs`, `info.rs`,
> `taps.rs`) into ever-deeper **nested `src/zirgen/zirgen/zirgen/...` directories** that cargo
> never compiles, while the **C++ kernels** copy to the correct place. So every binary was built
> from **df6fb9d C++ kernels + the STALE COMMITTED Rust verifier** — an inconsistent prover/verifier
> pairing. The Rust constraint polynomial that `verify_integrity` evaluates **still has full
> `IsRead@ReadReg`**.

This is the **same "wrong layer" failure as Route 2**, re-introduced through a different mechanism.
The hole reached the C++ witgen/prover but never reached the Rust verifier poly. Therefore the
honest-gate, the mutated-V0 smoke, and the 0/15 bracket are **all invalid measurements** of the
underconstraint theory — the theory remains **genuinely untested**.

**The fix is small and mechanical** (correct the copy targets + rebuild both binaries fully from
df6fb9d). The toolchain problem that ate most of the time is **solved and should not be redone.**

---

## 1. Hard evidence (verified on disk this session)

### 1.1 The canonical Rust verifier file is stale committed
`risc0/circuit/rv32im/src/zirgen/poly_ext.rs` is what cargo compiles (via `src/zirgen/mod.rs`):
- `git status` → **clean** (unmodified = committed content)
- `IsRead ( ...mem.zir:79` → **127** occurrences (full IsRead present)
- `MemoryReadNoIsRead` → **0** (the hole is absent)

### 1.2 The regen output landed in ignored nested dirs
`find .../src/zirgen -name poly_ext.rs` returns **five** copies:
```
src/zirgen/poly_ext.rs                                  ← canonical (compiled; STALE committed)
src/zirgen/zirgen/poly_ext.rs                           ← regen output (ignored)
src/zirgen/zirgen/zirgen/poly_ext.rs                    ← ignored
src/zirgen/zirgen/zirgen/zirgen/poly_ext.rs             ← ignored
src/zirgen/zirgen/zirgen/zirgen/zirgen/poly_ext.rs      ← ignored
```
The control/holed snapshots themselves store the Rust files one level too deep
(`.../src/zirgen/zirgen/poly_ext.rs`), and they *do* contain real changes
(holed snapshot: `MemoryReadNoIsRead` = 185, genuine `IsRead@79` reduced) — confirming the
codegen worked; only the **destination path** is wrong.

### 1.3 The cause in the scripts
`a4/scripts/ap_zirgen_regen.sh`:
```
REGEN_PATHS=( "risc0/circuit/rv32im/src/zirgen"  ... )   # a DIRECTORY entry
# snapshot_regen / restore_snapshot:
rsync -a "$src/$rel" "$RISC0/$rel"                        # rel is a dir, dest exists
```
`rsync -a SRC_DIR DEST_DIR` with no trailing slash and an existing dest copies `SRC_DIR`
*inside* `DEST_DIR` → `DEST_DIR/zirgen/`. Repeated each run → unbounded nesting. The C++ kernels
are listed as **individual files** (`.../steps.cpp`, etc.), so file→file rsync lands them
correctly. That asymmetry is exactly the observed split: **C++ updated, Rust stale.**
(`install_codegen_artifacts()` copying from `bazel-bin/.../dsl` into `src/zirgen` has the same
class of target bug.)

### 1.4 Binary fingerprints (both df6fb9d, identical instrumentation)
From `ap_b1_verify.json` / `fingerprint.json`:
- `patched`: `circuit_source=zirgen_control`, `zirgen_head=df6fb9d…`, `load_rs2_present=1`, `planted_bug=none`
- `bench-isread`: `circuit_source=zirgen_holed`, `zirgen_head=df6fb9d…`, `load_rs2_present=1`, `planted_bug=isread`

---

## 2. Why this explains every observed failure

| Observation (from `ap_b1_verify.json` / bracket) | Explanation under the path bug |
|---|---|
| **Bracket 0/15 bench accepts** | The Rust `verify_integrity` poly (stale committed) **still enforces `IsRead@ReadReg`**. A mutated (diverged) register read violates it → reject. The hole was only in the C++ kernels. **Identical to the Route 2 "wrong layer" failure.** |
| **mutated-V0 `mutated_bench_accepts=false`** | Same reason — verifier still has IsRead. |
| **`patched` honest verify = false, `bench` honest verify = true** | Symptom of **inconsistent, non-reproducible build states** (path nesting + evolving scripts + leftover stale files across many rebuilds), not a meaningful circuit signal. Do not over-interpret it (see §3). |
| **GP1 reports 699 `IsRead@ReadReg` tags** | Partly a **regex false-positive**: the pattern `IsRead \(.*ReadReg \(` matches `MemoryReadNoIsRead ( … ReadReg`. Partly it's reading a **stale/committed** poly. GP1 is unreliable until both the regex and the file-path are fixed. |

---

## 3. Corrections to Composer's diagnosis

1. **"df6fb9d control ≠ committed guest" → NOT supported.** The guest image_id is computed from the
   ELF and is **circuit-independent**; a fully self-consistent df6fb9d build (prover **and** verifier
   both df6fb9d) should prove+verify the guest regardless of whether df6fb9d matches the committed
   circuit. The honest-verify failure is explained by the **C++/Rust inconsistency** (§1), not guest
   pairing. **Rebuilding the guest/methods is unnecessary.**
2. **"Option B's hard gate is fundamentally unsatisfiable" → NOT established.** It was never honestly
   tested, because no binary was ever built with a consistent df6fb9d Rust verifier.
3. **Still genuinely OPEN (do not assume either way):** whether df6fb9d's circuit is *identical* to the
   committed v4.0.0 circuit. The `control-check`/`semantic-diff` never completed. This matters only
   for **comparability** (Option A), not for AP's internal validity — but it forbids **mixing**
   df6fb9d C++ with committed Rust (which is exactly the bug we hit).

---

## 4. What is REAL and done (do NOT redo)

| Asset | Status |
|---|---|
| **Toolchain solved** — native host build (gcc 13.3), conda pruned, **no zig** | ✅ `gen_zirgen` builds in ~26 min, no OOM, on this 11 GiB box. **POS not needed.** |
| Key insight: drop `--config=bootstrap_linux_amd64`; build with host toolchain `--spawn_strategy=local` | ✅ proven |
| `regen-snapshots/{control,holed}-df6fb9dda1c2/` | ✅ exist; codegen content correct (only stored one dir too deep) |
| Holed codegen genuinely removes IsRead on ReadReg in C++ + (nested) Rust | ✅ (holed snapshot has `MemoryReadNoIsRead`) |

**The only thing standing between us and a real test is the file-copy target + a clean rebuild.**

---

## 5. The science is still UNTESTED

We have **never** run a bracket against a circuit whose **Rust verifier poly** has the IsRead hole.
So the central question — *does removing `IsRead@ReadReg` make a single-cell `(0,1,0)` register-read
mutation verify (bench accept) while the patched control rejects?* — is **open**. The global-LogUp
"stays balanced" residual (flagged in the spec and `PLANTED_BUG_FEASIBILITY.md`) is still the real
unknown. Estimated ~55–70% the IsRead hole works; Seam B (decode-binding, ~64% hit-rate) is the
documented fallback.

---

## 6. Recommended fix (for the reviewer to approve)

1. **Fix the copy targets** in `ap_zirgen_regen.sh` (and `install_codegen_artifacts`): copy the Rust
   circuit files to the **canonical** `src/zirgen/` (file→file, or `rsync -a SRC/ DEST/` with trailing
   slashes / explicit filenames). Prefer reusing the **real bootstrap tool** (`cargo run -- rv32im-v2`,
   whose `Rule::copy("*.rs","src/zirgen")` path logic is correct) over the hand-rolled copy that
   introduced the bug — fix its cwd issue instead of bypassing it.
2. **Clean the damage:** `git checkout HEAD -- risc0/circuit/rv32im/src/zirgen` and delete the nested
   `src/zirgen/zirgen[/zirgen…]` dirs, so the tree is pristine before reinstalling.
3. **Rebuild BOTH binaries fully from df6fb9d** (consistent C++ **and** Rust): patched ← control,
   bench ← holed. Never mix df6fb9d C++ with committed Rust.
4. **Honest-gate** on the rebuilt patched: must prove+verify the guest (now a real test of df6fb9d
   self-consistency). Expected to pass.
5. **Fix GP1**: regex `(?<![A-Za-z])IsRead \(` (exclude `MemoryReadNoIsRead`) **and** point it at the
   canonical `src/zirgen/poly_ext.rs`. Re-confirm zero genuine `IsRead@ReadReg` in the *compiled* poly.
6. **Refresh/validate the corpus** on the df6fb9d patched-control circuit before trusting the bracket
   (the committed-circuit `(step, txn_idx)` may not map). The mutated-V0 gate is the drift catch.
7. **Then** run mutated-V0 + the 15-config bracket — the first real test of the theory.

---

## 7. Decision points for the reviewer

1. **Confirm the root cause** (path-doubling → stale Rust verifier) and that the fix is plumbing, not science.
2. **Approve full-df6fb9d Option B** (both arms from df6fb9d) as the rebuild, with no C++/Rust mixing.
3. **Comparability:** do we still want the (soft) `semantic-diff` to learn if df6fb9d == committed, or
   accept AP as isolated (Option B) and skip it?
4. **Orchestration mandate:** all remaining steps run via a **single foreground script** that exits on
   first failure and verifies PID/log growth — no agent background handoffs (the 600s-timeout kills and
   `ENOENT` Windows-cwd launches wasted hours and produced false "running" states).

---

## 8. Process failures to stop repeating (from this run)

- Background jobs launched from a Windows-style cwd → `spawn /bin/bash ENOENT`, reported as "started."
- Long Bazel builds hit the 600s agent timeout; parent died; logs froze and were misread as "hung."
- A holed `.zir` edit invalidates the Bazel cache → **30–40 min** rebuild, repeatedly under-estimated.
- A **false honest-gate PASS** from a mixed/partial workspace masked the path bug.
- Rebuilding binaries repeatedly without fixing the actual C++/Rust inconsistency.

---

## 9. Evidence index

| Path | What |
|---|---|
| `a4/runs/iv_pos_9/ap/ap_b1_verify.json` | Authoritative gate results (V0/GP1/GP2) |
| `a4/builds/ap/{patched,bench-isread}/fingerprint.json` | Both df6fb9d; control vs holed |
| `a4/builds/ap/regen-snapshots/{control,holed}-df6fb9dda1c2/` | Codegen output (stored one dir too deep) |
| `workspace/risc0-modified/.../src/zirgen/poly_ext.rs` | Canonical Rust verifier — **stale committed** (127 IsRead@79, 0 NoIsRead) |
| `workspace/risc0-modified/.../src/zirgen/zirgen[/zirgen…]/poly_ext.rs` | 4 nested mis-targeted copies |
| `a4/scripts/ap_zirgen_regen.sh` | `REGEN_PATHS` dir-entry + rsync nesting bug |
| `a4/runs/iv_pos_9/ap/AP_B2_CIRCLE_REPORT.md` | Composer's post-mortem (facts mostly right; root cause wrong) |
| `a4/docs/cloud3/AP_TRACK_AUDIT_LOG.md` | Full track history |
