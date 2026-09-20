# AP Track — Consolidated Audit Log (planted IsRead bug)

**Purpose.** One authoritative record of the AP (planted-bug) track: what we are trying to
do, every approach we tried, *why each failed or was abandoned*, the decisions we made and
their rationale, and the current forward plan. Read this before proposing anything on AP so
we **do not go in circles**. All claims here were verified against source at the cited
locations; where something is still unproven it is marked **UNVERIFIED**.

Last updated: 2026-06-22 (post vendor-model clarification).

---

## 0. TL;DR of current state

- **Goal:** a second soundness bug on top of the CVE that is findable by a **single
  post-execution A4 trace edit** and still produces a RISC Zero proof that *verifies*.
- **Chosen mechanism:** remove the `IsRead` constraint **only on the register-read path**
  (`ReadReg` → `MemoryReadNoIsRead`), leaving RAM loads / instruction fetch / paging intact.
- **Where we are:** the bug must be cut into the **constraint polynomial**, not just witgen.
  Surgical hand-patching of the generated polynomial is **unfeasible** (proven below). The
  path forward is **regenerating the circuit from zirgen** (Route 1).
- **Key clarification (2026-06-22):** `/root/arguzz/zirgen` is a **reference clone**, not the
  build pipeline. RISC Zero **vendors** (checks in) zirgen-generated circuit files; the cargo
  build only *compiles* them. So "Route 1" = run zirgen offline → copy generated files in →
  cargo build (mimic the vendor workflow).
- **Chosen strategy:** **Option B** — regenerate *both* `patched` (control) and `bench-isread`
  from the `df6fb9d` zirgen clone; keep AP isolated from the CVE/sweep tracks (which stay on
  the committed circuit). Hard gate = `df6fb9d` unmodified circuit must honestly prove+verify
  the guest. Comparability checks (`control-check`, `semantic-diff`) are **soft** and, if they
  pass, upgrade us to Option A "for free."
- **Blocking item:** nobody has yet built `gen_zirgen` in this environment. The whole plan is
  gated on that build succeeding. **UNVERIFIED.**

---

## 1. The objective (why AP exists)

The IV.POS.9 race compares Arguzz-style (during-execution) vs A4-style (post-execution
single-cell) fault injection on **bug-finding**. The real CVE-2025-52484 (`rs1==rs2`
double-read) is structurally **Arguzz-native**: exploiting it requires a *coherent* witness
(diverged read **and** recomputed result), which a single post-exec edit cannot produce
(the present `C_local` constraint trips). So A4 likely cannot win the CVE race.

To give A4 a fair, real target we **plant a second, disclosed underconstraint** engineered for
a single-cell `PRE_EXEC_REG_MOD` edit. It is labeled synthetic in the thesis and fingerprinted.

- Oracle for the planted bug: **internal trace-soundness** (witness read ≠ honest read), not
  the strong journal oracle (post-exec edits can't change the already-committed journal).
- Bench binaries are **separate by design** (OCP decision): `bench-cve` (CVE only),
  `bench-isread` (planted only, on patched tree), `patched` (control). They are **never** the
  same binary — a combined binary would contaminate both races.

---

## 2. The mechanism (verified)

`MemoryRead` enforces `IsRead` (old/new txn data equal) + `IsForward` + `GetData`. `ReadReg`
uses `MemoryRead`. Instruction fetch (`DecodeInst`) and RAM `lw/sw` also use `MemoryRead`.

Plant = add `MemoryReadNoIsRead` (everything except `IsRead`) and route **only `ReadReg`**
through it. RAM/fetch keep `IsRead`. Source of truth:
`zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir` (IsRead at `:79`) and `inst.zir` (`ReadReg`).

Effect: mutating a register-read `word` while leaving `prev_word` produces a witness that is
internally self-consistent (the same mutated txn feeds `getMemoryTxn`) but encodes a register
value that no honest execution produced → **accept on bench, reject on patched**.

---

## 3. Timeline of approaches — what we tried and what we learned

| # | Approach | Outcome | Lesson (do not repeat) |
|---|----------|---------|------------------------|
| 1 | Make the **CVE itself** A4-findable with one edit | Rejected in research | `C_local` is present at the CVE site; a lone read edit leaves a stale result → reject. CVE needs a coherent/propagating fault (Arguzz). **Don't retry single-cell CVE.** |
| 2 | **AP.B1**: cut `IsRead` out of **witgen** (`steps.cpp`): add `exec_MemoryReadNoIsRead`, redirect `exec_ReadReg` | GP1/GP2/V0-honest passed | Honest proofs verify, but this only touches the *witgen* copy of the constraint. |
| 3 | **AP.B2 screen** (POS, 600 jobs) | 15 `(0,1,0)` hits on patched host | Screen oracle = layer signature, **not** verifier-accept. A `(0,1,0)` signature does **not** imply bench will accept. |
| 4 | **AP.B2 bracket** (15 configs × 2 hosts, local) | **FAILED**: both hosts panic `verify segment` (exit 101). bench: 0 logged failures, `(0,0,0)`; patched: 1 IsRead failure, `(0,1,0)` | **Root cause:** the hole was in witgen only. The proof's validity is checked against the **constraint polynomial**, which still enforced `IsRead@ReadReg`. |
| 5 | **Route 2 surgical patch** of the constraint polynomial: zero `IsRead@ReadReg` in `rust_poly_fp_{0..3}.cpp` (72 sites) + `poly_ext.rs` `Sub` (16 sites) | **FAILED** mutated-V0: honest proofs verify, but mutated configs still reject on bench | `poly_ext.rs` still has **26 `PolyExtStep::AndEqz`** sites enforcing `IsRead@ReadReg`. The polynomial is a **compositional DAG with shared sub-expressions and folded AND-EQZ terms**; hand-removing terms breaks wire indices or honest proofs. **Surgical patching is unfeasible — do not retry.** |
| 6 | **Pivot to Route 1** (regen from zirgen) | Decided | Only a consistent regeneration removes the constraint from *all* representations (`steps`, `rust_poly_fp_*`, `poly_ext.rs`, `info.rs`, `taps`, eval_check, layout) at once. |
| 7 | **Vendor-model clarification** (user: zirgen clone is reference-only) | Reshaped plan | See §4. The build doesn't run zirgen; it compiles vendored files. So we mimic the vendor workflow and the *zirgen version* becomes the central question. |

### The mechanism behind the `verify segment` failure (settled)
`host/src/main.rs` calls `prove_with_opts(...)`; on `Err` it `panic!("verify segment")`. That
error comes from the prover's internal `verify_integrity_with_context`, which evaluates the
**constraint polynomial**. The A4 flags (`CONSTRAINT_CONTINUE`, `FAULT_INJECTION`) only affect
the **witgen `eqz`** (log-and-continue) — they do **not** touch `verify_integrity`. So a
witgen-only hole yields **0 logged failures yet still rejects**. Confirmed the campaign's own
accept-oracle (`_classify_outcome`: `soundness_signal = (prover_status=="success")`) is
verify-based and identical to the bracket oracle → the bracket oracle was **correct**, the
build was wrong.

---

## 4. How RISC Zero gets the constraints (verified vendor model)

- `risc0/circuit/rv32im-sys/build.rs` only **compiles** committed `kernels/cxx/*.cpp` via
  `KernelBuild`; it never invokes zirgen. `poly_ext.rs`, `info.rs`, `taps.rs` are committed
  Rust source under `risc0/circuit/rv32im/src/zirgen/`.
- **No `.gitmodules` entry, no pinned zirgen commit, no codegen/bootstrap** in risc0-modified.
- Circuit crate: `risc0-circuit-rv32im 4.0.0`, protocol `RV32IM:v2rev2___` (in `info.rs`).
- `/root/arguzz/zirgen` (HEAD `df6fb9d`, 2026-01-20) is a **user-added reference clone**.
  Its codegen target `//zirgen/circuit/rv32im/v2/dsl:codegen` emits exactly the vendored set
  with `--protocol-info=RV32IM:v2rev2___` (matches committed `info.rs`).

**Consequence:** there is **no recorded pin** proving `df6fb9d` is the exact zirgen that
produced the committed v4.0.0 circuit. Matching protocol string is **necessary, not
sufficient** (one protocol rev can span many commits). Hence Option A vs Option B (§5).

### Bootstrap copy mechanism (verified safe for A4 harness)
`bootstrap rv32im_v2` uses `install_from_bazel` with glob rules (`*.cpp`→`kernels/cxx`,
`*.rs`→`src/zirgen`, etc.). It is **driven by the bazel output files** (only the codegen
OUTS). `ffi.cpp`, `witgen.h`, `eval_check.cpp`, `ffi.cu`, and `src/prove/witgen/mod.rs` are
**not** codegen outputs, so the globs never write them → **the A4 instrumentation harness is
preserved** across `bootstrap install`.

- `eval_check.cpp` (CPU): hand-written driver, **0** `IsRead` terms, **23** A4 markers, **not**
  in OUTS → correctly excluded from regen. The constraint polynomial lives in
  `rust_poly_fp_*.cpp` and `poly_ext.rs`, both of which **are** regenerated.
- A4 harness (`ffi.cpp`/`witgen.h`/`eval_check.cpp`) is **committed in HEAD** of risc0-modified
  → `git checkout HEAD -- kernels/cxx` (used in `control-check`) restores versions that already
  contain the instrumentation. **No wipe risk.**
- `src/prove/witgen/mod.rs` (the `A4_MUTATION_CONFIG` injection hook) is **uncommitted** (` M`).
  It survives current scripts (they only `git checkout` `src/zirgen`+`kernels/`), but it is
  **fragile** — see flag D.

---

## 5. The decision: Option B (with Option A as a free upgrade)

| | Option A (comparability) | **Option B (chosen default)** |
|--|--------------------------|-------------------------------|
| patched baseline | committed circuit (only if proven == df6fb9d) | `df6fb9d` **unmodified** regen |
| bench | `df6fb9d` holed regen | `df6fb9d` holed regen |
| joinable with CVE/sweep numbers? | yes (if semantic-diff passes) | **no — AP isolated** |
| hard gate | byte/semantic diff + honest proof | **honest proof only** |

**Why Option B is correct (evidence, not guess):**
1. No zirgen pin exists → can't *assume* `df6fb9d` == committed generator.
2. AP already uses **separate binaries with an internal patched/bench bracket**; the race is
   **within-binary** (variants compete on the same `bench-isread`), so it does not need the
   committed circuit.
3. CVE/sweep tracks stay on the committed circuit; their numbers are never cross-compared with
   AP's. (This matches OCP's prior "separate binaries" decision and the de-prioritized `bench-AB`.)
4. The hard gate (honest prove+verify on `df6fb9d` unmodified) is cheaper and is the real
   correctness condition: if it fails, no zirgen revision is usable anyway.

If `control-check`/`semantic-diff` later pass, we **upgrade to Option A** without redoing the
holed regen. Run them opportunistically once `gen_zirgen` is built (they're cheap).

---

## 6. Forward pipeline (authoritative)

```
0. Build gen_zirgen once (Bazel 6.0.0 + LLVM/MLIR fetch). CHECKPOINT — see flag B.
1. ap_zirgen_regen.sh control-regen   # unmodified .zir → bootstrap install → snapshot control-<sha>
2. ap_zirgen_regen.sh honest-gate     # [HARD] build patched from control snap; honest prove+verify
3. (opt) control-check / semantic-diff # [SOFT] if pass → Option A (AP joinable)
4. ap_zirgen_regen.sh holed-regen     # MemoryReadNoIsRead .zir → install → snapshot holed-<sha>
5. build_ap_binaries.sh --from-regen  # patched=control snap, bench=holed snap (both df6fb9d)
6. ap_b1_verify.py                    # [HARD] GP1 zero IsRead@ReadReg loc-tags + mutated-V0 smoke
7. ap_b2_replay.py --bracket-only     # GP4/GP5 — only meaningful after step 6 passes
```

**Isolation rule:** post-regen AP binaries carry `circuit_source: zirgen_{control,holed}` in
their fingerprint and must **not** be cross-compared with `circuit_source: committed`
(CVE/sweep) numbers unless `semantic-diff` passes.

---

## 7. Open risks / flags

- **A — (0,1,0) corpus / mutated-V0 target must be re-resolved on the df6fb9d control.**
  The corpus (`ap_corpus_010.json`) and E5 atoms were derived on the **committed** circuit.
  Targets are resolved at runtime by `(step, txn_idx)`, and IsRead removal does not change the
  witgen *trace* (same memory transactions), so indices *should* transfer — **but this is
  unproven under Option B.** Mitigation already in place: the **mutated-V0 hard gate** (step 6)
  catches corpus/circuit drift. Ensure the mutated-V0 config is resolved against the
  **df6fb9d patched-control**, not a committed-circuit inspection.

- **B — `gen_zirgen` build is unproven and the toolchain fetch is heavy (LLVM/MLIR; a conda env
  was observed).** The entire plan is gated on it. Treat "build `gen_zirgen` + run codegen
  once and see the OUTS files appear" as an **isolated checkpoint** before wiring the full
  pipeline. Do not start `control-regen→honest-gate` until `gen_zirgen` demonstrably builds.

- **C — circuit-identity coupling outside `src/zirgen`.** Regen changes `info.rs`/`taps.rs`.
  For the **segment (fast) prove+verify** path AP uses, the in-binary circuit is
  self-consistent and `honest-gate` covers it. Risk only arises if AP ever hits the
  recursion/succinct path or a hardcoded control-ID/allowed-ids table. Low risk; confirm AP
  stays on the segment path (the failure was literally `verify segment`).

- **D — `src/prove/witgen/mod.rs` A4 hook is uncommitted.** It is the live mutation-injection
  point and is working-tree-only. Given the regen scripts do a lot of `git stash`/`git
  checkout`, **commit it (or snapshot it)** so it can't be silently lost.

- **E — Option B forfeits the "same circuit, two bugs" narrative.** Acceptable: OCP already
  de-prioritized the combined `bench-AB` build. If we later want it, Option A (semantic-diff
  pass) gives it without rework.

---

## 8. Invariants — settled facts, do not relitigate

1. Witgen-only holes never produce a real accept; the **constraint polynomial** is what
   `verify_integrity` checks. Any soundness plant must remove the constraint from the
   polynomial (`rust_poly_fp_*` + `poly_ext.rs`), never just the witgen `eqz`.
2. Surgical hand-patching of `poly_ext.rs` is **unfeasible** (compositional DAG + 26 `AndEqz`
   folds). Use zirgen regen.
3. The bracket/campaign accept-oracle is **verify-based and correct**; a `(0,1,0)` layer
   signature is a *screen* heuristic, not an accept predictor.
4. The build only **compiles vendored files**; zirgen is offline. Regen = generate → copy in.
5. `bootstrap install` only writes codegen OUTS; the A4 harness (`ffi.cpp`/`witgen.h`/
   `eval_check.cpp`/`mod.rs`) is preserved.
6. CVE is Arguzz-native; the planted IsRead bug is the A4 target. Separate binaries always.

---

## 9. Artifact index

| Artifact | Path | Status |
|----------|------|--------|
| This audit log | `a4/docs/cloud3/AP_TRACK_AUDIT_LOG.md` | authoritative |
| Planted-bug spec | `a4/docs/cloud3/IV_POS_9_AP_PLANTED_ISREAD_SPEC.md` | current |
| Root-cause (witgen vs poly) | `a4/docs/cloud3/AP_B2_ROOT_CAUSE.md` | settled |
| Vendor-workflow report (Composer) | `a4/runs/iv_pos_9/ap/AP_B2_VENDOR_WORKFLOW_REPORT.md` | verified correct |
| Regen pipeline | `a4/scripts/ap_zirgen_regen.sh` | ready (gated on gen_zirgen build) |
| Build (Option B pair) | `a4/scripts/build_ap_binaries.sh --from-regen` | fixed (no mixed generators) |
| Verify gates | `a4/scripts/ap_b1_verify.py` (+`--honest-only`) | GP1 loc-tags + mutated-V0 |
| Semantic diff (soft Option A) | `a4/scripts/ap_zirgen_semantic_diff.py` | new |
| Corpus | `a4/runs/iv_pos_9/ap/ap_corpus_010.json` | re-validate on df6fb9d (flag A) |
| Route 2 surgical patch | `a4/scripts/ap_isread_patch.py` | **legacy/invalid** for bracket |
| Binaries | `a4/builds/ap/{patched,bench-isread}/risc0-host` | Route-2 builds invalid; rebuild via regen |
