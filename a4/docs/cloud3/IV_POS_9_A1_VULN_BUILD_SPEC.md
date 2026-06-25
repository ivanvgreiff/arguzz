# IV.POS.9 — Spec A1: Vulnerable build + commit validation + deterministic repro

**Version:** v0.3 — **B2 COMPLETE · CVE thesis race LIVE on POS** · **Date:** 2026-06-25 (orig 2026-06-21) · **Author:** Opus (OCP).
**Governing plan:** [`New_Master.md`](./New_Master.md) Track A, Step A1. **Mechanism authority:** [`BUG_MECHANISM_VERIFIED.md`](./BUG_MECHANISM_VERIFIED.md). **Trigger contract:** [`../../runs/iv_pos_9/a1/a1_canonical_trigger.md`](../../runs/iv_pos_9/a1/a1_canonical_trigger.md). **Build+dispatch report:** [`../../runs/iv_pos_9/a1/B2_FORWARD_PORT_AND_DISPATCH_REPORT.md`](../../runs/iv_pos_9/a1/B2_FORWARD_PORT_AND_DISPATCH_REPORT.md).
**Requirements traced:** ProG_Report_5 §3/§3.5/§5 Step 1; locked decisions **L3, L4, L5, L13, L14**; gates **G1, G2, G4, G5, G9, G10**.
**Status:** **A1 GATES PASSED → CVE RACE DISPATCHED.** **Role:** **A1 is the universal hard gate** — nothing in A2/A3 (or any CVE race run) starts until A1's gates pass.

### Live progress (2026-06-25) — B2 DONE, race LIVE
- **B2 (instrumented vulnerable MODE-1 host) BUILT + VERIFIED + DISPATCHED.** `a4/builds/a1_cve/risc0-host`
  (sha256 `dbe89d23…`), built from `workspace/risc0-a1-vuln` @ `98387806`. The A4 instrumentation was
  **forward-ported** from the ebd64e43 API onto `98387806`'s monolithic `prove`/`WitnessGenerator::new`
  (codegen left byte-identical to `98387806`; fix #3181 reverted in `witgen/preflight.rs`). Full method:
  the B2 report (linked above).
- **Gates:** G1/G2 (load_rs2_present=0, planted_bug=none, codegen 0-diff vs 98387806) ✅; G10 (fingerprint
  self-emit + guard `--profile race` PASS on all 8 nodes) ✅; **honest prove → `output=9000027`, Verifier
  success** ✅; exploit candidate on B2 (`v6_uniform` `INSTR_WORD_MOD` accept in core_arithmetic) ✅.
- **CVE thesis race LIVE on POS** (tmux `chain_cve_thesis`, 8 fast nodes, 40 jobs = 4 variants × 10 seeds
  × N=5000, RUN_PREFIX=cve, guard race). Batch 1 verified recording on all 8 nodes after cold-start.
  ~23 h ETA. Analysis (strong journal oracle, mirror-complementarity) is the remaining step (A1.B3 / race).
- **A2 guest:** `remu a0,a1`+`divu a2,a3` (rs1≠rs2, 1-bit-apart), guest_image_id
  `2819774008,269738887,…,829874012`. A single `INSTR_WORD_MOD` flip aliases rs2→rs1 (Framing B = G4 path).

### Live progress (2026-06-24)
- **G1/G2 source gate — PASSED (verified live).** `98387806`: `fn load_rs2` count **0** (two separate `load_register(rs1)` @326 / `(rs2)` @327); fix `67f2d81` + base `ebd64e43` have it. In-tree vulnerable generated circuit (`steps.cpp` 30k, `poly_ext.rs` 20k, `info.rs`) **committed at `98387806`** ⇒ build needs **no zirgen regen** (this is what blocked the *separate* AP planted-IsRead track; it does NOT block A1).
- **Trigger contract written** (`a1_canonical_trigger.md`) — the deterministic target B1 confirms / B3 reproduces.
- **B1 (MODE-2 existence proof) RUNNING.** MODE-2 is wired for `98387806` (frozen vuln source, `0xDEADBEEF` oracle, public fork reachable). The turnkey `refind.sh`/`helper.sh` flow is **podman**-based and we have only **docker**, so B1 runs the fuzzer in its **canonical Dockerfile env** (drift-free) instead — building the image now.

### ⚠️ Track isolation (HARD — do NOT contaminate the concurrent work)
A1 runs **while the A3 Seam-B race is live on POS** and the Track-B sweep + AP track exist. A1 MUST stay isolated:
- **MODE-2 (B1)** clones a **fresh** risc0 (the DanielHoffmann91 fork) **inside the docker container** to its own dir — it touches none of the local clones. Build context is the minimal `/tmp/r0fuzz-ctx` (libs + the fuzzer only), never the repo root.
- **MODE-1 (B2)** will use a **dedicated fresh worktree** for `98387806` (e.g. `workspace/risc0-a1-vuln`) with its **own cargo `--target-dir`** — **never** `workspace/risc0-modified` (AP, dirty @ 6556e8d7), `workspace/risc0-seamb` (the A3 race binary's tree), or `workspace/risc0-clean-28e53771` (Track-B). Never run a broad `pkill cargo` (kills other tracks' builds).
- **POS:** A1 does **NOT** dispatch any POS jobs (it is local-only). The CVE POS batch is A3-for-the-CVE, gated on A1 passing — and on **different** nodes than Track-B, assigned by Ivan.
- **Binaries:** A1's vulnerable build is fingerprinted `load_rs2_present=0` and lives under `a4/builds/` in its **own** dir; it is never bundled for a sweep (G12/L13).

---

## 0. Scope

### 0.1 What A1 IS
A1 produces a **trusted vulnerable target** and **confirms the verified bug mechanism end-to-end**, so the race that follows is measuring real soundness discovery on a build we can *prove* is the right one. Concretely, A1 delivers:
1. **(A1.B1)** the original Arguzz fuzzer (MODE 2) **re-finding** the bug at the vulnerable commit — an independent existence proof (G9) and a MODE-2-level pre-fix-accepts / post-fix-rejects record.
2. **(A1.B2)** an **instrumented MODE-1 `risc0-host` built at the vulnerable commit**, passing the source/circuit vulnerability gates (G1/G2), plus the **build-provenance fingerprint mechanism** (G10) applied to *both* the vulnerable and the patched build.
3. **(A1.B3)** a **deterministic MODE-1 repro** — a hand-specified **coherent, propagating** read-divergence fault that the pre-fix build **accepts as a proof of a wrong result** (G4) and the post-fix build **rejects** (G5) — plus a per-variant characterization of whether each variant's register-mutation propagates (which decides findability).

### 0.2 What A1 is NOT
- **Not the race.** No four-variant competition, no metrics, no Kaplan-Meier (that is A3). A1 only proves the target is real and the mechanism fires on demand.
- **Not the race guests.** A1.B3 builds a *minimal throwaway* `rs1==rs2` repro guest sufficient for the deterministic repro; the production Race-guest A/B are A2's job (A2 may formalize A1's minimal guest as Race-guest A).
- **Not Track B.** Track B runs on the patched tree (L13); A1 only *also* stamps the patched build's fingerprint so the sweep's G12 has something to assert against.

### 0.3 The one-paragraph mechanism A1 is built around (from `BUG_MECHANISM_VERIFIED.md`)
The bug (CVE-2025-52484 / risc0 #3181 / zirgen #238) is a **same-source-register double-read** soundness hole: when an instruction encodes `rs1 == rs2` (e.g. `remu x3,x5,x5`), the pre-fix circuit performs two unconstrained reads of that one register in one cycle. The exploit is a **coherent** witness in which the second read **diverges** (`read_rs2 ≠ read_rs1`) **and the result is recomputed to match** (`rem(read_rs1, read_rs2) == result`), so the *present* local-compute constraint holds and **only the missing second-read memory constraint is violated**. A **during-execution (propagating) fault** produces this naturally (this is how Arguzz found it); a **single-cell post-execution edit does not** (it leaves the result stale and trips the present local-compute constraint). This distinction drives every A1 design choice below.

---

## 1. Facts A1 builds on (verified — do not re-litigate)
| Fact | Evidence |
|---|---|
| Bug = same-register (`rs1==rs2`) double-read divergence; exploit needs a **coherent/propagating** fault | `BUG_MECHANISM_VERIFIED.md` (the #3181 `load_rs2` diff) |
| Vulnerable commit `98387806` lacks `fn load_rs2` (two separate `load_register` reads); patched base `ebd64e43` and fix `67f2d81` have it | `git show <c>:risc0/circuit/rv32im/src/execute/rv32im.rs` |
| Vulnerable circuit is **committed in-tree** as generated code (no external Zirgen fetch) | #3181 regenerated `steps.cpp`/`poly_ext.rs`/`layout.*` in-tree |
| MODE-2 is already wired for `98387806`: commit in `RISC0_AVAILABLE_COMMITS_OR_BRANCHES`; frozen vulnerable source `injection_sources/rv32im_rs_9838780.py`; `0xDEADBEEF` metamorphic oracle | `projects/risc0-fuzzer/risc0_fuzzer/settings.py:7-23,36`; `injection_sources/__init__.py:26-27` |
| Toolchain matches: `RUST_TOOLCHAIN_VERSION = "1.85.0"`; `98387806` (May) is after the 1.85 bump (`4c65c85a`, Mar) | `settings.py:25` |
| Back-port is small: applying the A4 instrumentation patch onto a `98387806` worktree = **49/60 files byte-clean**, residue = `steps.cpp` assert-wrap regex (134→125 sites) + 3 Rust merges (`hal/mod.rs`, `witgen/mod.rs`, `preflight.rs`) | tested last turn; `IV_POS_8_BACKPORT_SCOPING.md` |

---

## 2. Deliverables → gates (A1 acceptance)
| Deliverable | Gate(s) | Pass condition |
|---|---|---|
| D1 — MODE-2 re-finds the bug at `98387806` | **G9** | a soundness finding is recorded; `check` at `98387806` → `fixed=False`, `check` at `67f2d81` → `fixed=True` |
| D2 — instrumented vulnerable MODE-1 `risc0-host` | **G1, G2** | built binary's source lacks `load_rs2` (two reads present); circuit compiled from in-tree generated files (no newer-Zirgen codegen at build) |
| D3 — build fingerprint mechanism (both builds) | **G10** | each `risc0-host` emits a machine-readable fingerprint (risc0 HEAD SHA · `load_rs2`-present flag · instrumentation hash · `RISC0_GUEST_ID`) |
| D4 — deterministic coherent repro | **G4, G5** | the propagating read-divergence fault → **pre-fix ACCEPTS a proof of a wrong committed output**; the **identical** fault → **post-fix REJECTS** |
| D5 — per-variant propagation characterization | (feeds G6/G7/A3) | documented: for V5/V6_uniform/V6_cTS/Hybrid, whether the register-mutation arm propagates (during-exec recompute) or is a single post-exec cell edit |

**A1 is complete only when G1, G2, G4, G5, G9, G10 all pass.** A failure routes to §6 fallbacks.

---

## 3. Batch A1.B1 — MODE-2 existence proof + MODE-2 pre/post-fix record (G9)

**Why first:** MODE-2 is the *cheapest, already-wired* path to prove the target is genuinely vulnerable, before we invest in the MODE-1 back-port. It also independently pins the canonical trigger that A1.B3 and A2 must reproduce.

**Steps:**
1. **Install vulnerable risc0 (MODE 2).** `risc0-fuzzer install <vuln_dir> --commit-or-branch 98387806fe8348d87e32974468c6f35853356ad5 --zkvm-modification`. This clones `RISC0_ZKVM_GIT_REPOSITORY` (the DanielHoffmann91 fork), switches to the commit (`zkvm_repository/install.py:15-34`), and overwrites `risc0/circuit/rv32im/src/execute/rv32im.rs` with the frozen instrumented `rv32im_rs_9838780.py` selected by commit hash (`injection_sources/__init__.py:26-27`, applied in `injection.py:18-43`).
2. **Run the fuzzer with fault injection.** `risc0-fuzzer run --commit-or-branch 98387806… --zkvm <vuln_dir> --out <find_dir> --seed <S> --fault-injection --timeout <T>`. The soundness oracle is metamorphic output divergence vs `RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF` (`settings.py:36`; divergence check `libs/.../fuzzer.py:447-464`); a finding is logged (`record_finding`, `fuzzer.py:841-852`; columns in `csvlogger.py:488-496`: `fuzzer_id,run_id,iteration_id,timestamp,runtime,circuit_seed,input_flags,is_injection`).
   - *Throughput note:* `TIMEOUT_PER_RUN = 4 min`, `TIMEOUT_PER_BUILD = 2 h` (`settings.py:48-49`). If the random scheduler is slow to hit the `rs1==rs2` path, **curate a guest seed** that contains a same-register `remu`/`divu` (see §3 risk below) rather than relying on luck.
3. **Record the canonical trigger.** From the finding's `injection.csv`/trace, capture: the instruction shape (confirm `rs1==rs2`), which operand read was diverged, the diverged value, and how acceptance-of-wrong manifests (committed output ≠ `0xDEADBEEF`-derived expected). **This record is the contract A1.B3 and A2 reproduce.**
4. **MODE-2 pre/post-fix via `check` (the clean G9 + a MODE-2-level G4/G5).** Re-run the recorded finding with `risc0-fuzzer check <findings.csv> --commit-or-branch <c> --zkvm <dir> --out <dir>` at:
   - `98387806` (vulnerable) → `checked_findings.csv` `fixed=False` (bug reproduces) — `checker.py:165-199`.
   - `67f2d81` (the #3181 fix) → `fixed=True` (bug gone).
   This is an *independent* (MODE-2) confirmation that the commit pair brackets the fix, before MODE-1 work.

**Outputs:** `findings.csv` + `checked_findings.csv` (both commits) + a short `a1b1_canonical_trigger.md` (the trigger contract). **Gate: G9.**

**Risks:** (a) the random MODE-2 scheduler may not emit an `rs1==rs2` op within the timeout — mitigate with a curated guest/seed (the MODE-2 project generator + `--no-schedular`); (b) building risc0 at the commit needs the rzup toolchain + system deps per `projects/risc0-fuzzer/Dockerfile` — run in that container. NOT-in-repo: the exact buggy instruction sequence is not commented in the frozen source; we derive it from the trigger record, not from prose.

---

## 4. Batch A1.B2 — Instrumented vulnerable MODE-1 build + provenance fingerprint (G1, G2, G10)

**Goal:** an instrumented `risc0-host` that (a) is built at the vulnerable commit, (b) is *proven* vulnerable, and (c) is *self-identifying*.

### 4.1 Get an instrumented + vulnerable `risc0-host`
Evaluate two routes; pick the lower-conflict one (lean route i):
- **Route (i) — forward-port (preferred).** Apply the A4 instrumentation diff (`ebd64e43 → 28e53771`) onto a `98387806` worktree. Tested: 49/60 byte-clean; residue = (a) `steps.cpp` — re-run the **assert-wrap regex** (wrap each `assert(0 && "Reached unreachable mux arm")` with the `FAULT_INJECTION_ENABLED` gate; 125 sites at the bug commit) and (b) 3 small 1-hunk Rust merges (`hal/mod.rs` SeqForward block, `witgen/mod.rs` A4 hooks incl. the 1 uncommitted dirty change, `preflight.rs` cycle-diff). The byte-clean set already includes the load-bearing C++ hooks (`ffi.cpp`, `witgen.h`, `eval_check.cpp`) and coverage rides via `witgen.h`'s `EQZ` macro (the bug commit's native `steps.cpp` issues 1868 `EQZ()` calls).
- **Route (ii) — revert #3181 on the current instrumented tree.** Swap the executor `load_rs2` **and** the regenerated circuit files (`steps.cpp`/`poly_ext.rs`/`layout.*`) back to pre-fix; **reverting only the 17-line executor is insufficient** (soundness lives in the regenerated constraint). Likely touches *more* files than (i).
- **Build** `risc0-host` (the embedded guest builds with it via `workspace/output/methods/build.rs::embed_methods()`); toolchain 1.85.0 already matches.

### 4.2 Vulnerability gates (do these before trusting the binary)
- **G1 (source):** assert the built tree's `risc0/circuit/rv32im/src/execute/rv32im.rs` has **no `fn load_rs2`** and shows two separate `load_register(decoded.rs1)` / `load_register(decoded.rs2)` reads.
- **G2 (circuit):** confirm the rv32im circuit compiles from the **committed generated files** at `98387806` (no build step regenerating from a newer Zirgen). Document the build graph evidence (the `*-sys` crate uses the in-tree `.cpp`/`.cu`; no `zirgen` codegen invocation).

### 4.3 Provenance fingerprint (G10) — the mechanism (applies to BOTH builds)
Define a single fingerprint and apply it to the vulnerable build **and** re-stamp the patched build (the current tree, needed for G5 + the sweep's G12). Fingerprint fields:
- `risc0_head_sha` — `git -C workspace/risc0-modified rev-parse HEAD`.
- `load_rs2_present` — derived at build from the source (`grep -c 'fn load_rs2' …/rv32im.rs`); **vulnerable ⇔ 0, patched ⇔ 1**. This is the behavioral/source invariant, not a spoofable label.
- `instrumentation_hash` — hash over the A4-instrumented files (so a stale/missing-instrumentation binary is caught).
- `guest_image_id` — the embedded `RISC0_GUEST_ID` (`[u32;8]`, generated `methods/build.rs:221`, used `host/src/main.rs:201`).

**Stamping/emitting (the open implementation choice — §8 open item 6 of the master; A1 picks one):**
- **Recommended:** stamp the four fields into a build-time `fingerprint.json` next to the binary in `prepare_bundle.sh` (it already computes `host_sha256` + `git_commit` at `:88,149-161`) **and** make the host *emit* them via the existing `<record>{…JSON…}</record>` stdout pattern (`host/src/main.rs:70+`) gated on `A4_INSPECT_FINGERPRINT=1` (so the dispatcher can read them straight from the deployed binary, not just a side file). The `guest_image_id` is the only net-new value to surface from the binary; the other three come from build context.

### 4.4 Re-validate the harness on the vulnerable build
Run the MODE-1 smoke harness against the new binary: confirm `A4_INSPECT=1` still parses into `InspectionData`, the coverage/`EQZ`-touch tags still emit, and `arguzz_invoke.py::_classify_outcome` (`:88-107`) still classifies. *Coverage loc IDs will differ from the patched tree (different circuit) — expected; do not compare to D2.H numbers (§2.4).*

**Outputs:** the vulnerable `risc0-host` + its `fingerprint.json`; the re-stamped patched fingerprint; a build log proving G1/G2. **Gates: G1, G2, G10.**

---

## 5. Batch A1.B3 — Deterministic coherent repro + per-variant propagation characterization (G4, G5, D5)

**Goal:** trigger the bug *on demand* in MODE 1 and prove the pre/post-fix bracket — then characterize which variants' arms can do it.

### 5.1 The minimal repro guest
Build a minimal throwaway guest that **encodes `rs1==rs2`**: inline-asm `remu x3, x5, x5` with `x5` sourced from input via a `black_box`/input barrier so the compiler cannot const-fold `a%a→0` or allocate two registers. **G3-style check:** `objdump -d` the compiled guest ELF and confirm an executed `remu`/`divu` with **identical rs1==rs2 register fields**. Honest result: `x5 % x5 = 0`. (This guest is the seed A2 may promote to Race-guest A.)

### 5.2 The coherent, propagating fault
Implement the deterministic fault as a **during-execution operand divergence** on the rs2-read of the `rs1==rs2` op, so the executor **recomputes** the result and the witness is coherent (`read_rs1=a, read_rs2=b≠a, result=rem(a,b)`), violating **only** the missing second-read memory constraint. Concretely in MODE 1:
- The trace records each read as a `RawMemoryTransaction{addr,cycle,word,prev_cycle,prev_word}` (registers memory-mapped at `USER_REGS_BASE = 0xFFFF0080/4`); for the op at user-step N the two reads are `txn K` and `txn K+1` (both `addr=base+5`, `cycle=2N`), the write is `txn K+2` (`cycle=2N+1`) — per `preflight.rs`. `A4_MUTATION_CONFIG` (consumed `witgen/mod.rs:245-702`) addresses one txn by `txn_idx`.
- **Use the propagating (Arguzz) path, not a lone post-exec cell edit.** A single post-execution edit of `txn K+1.word` leaves `txn K+2` (result) stale → trips the present local-compute constraint → rejected (this is the whole point of §0.3). The deterministic fault must either (a) drive the during-execution `FAULT_INJECTION_ENABLED` operand-mutation hook (the same hook MODE 2 uses) so the result recomputes, or (b) apply a **coordinated** edit of both the rs2-read and the result cell to a coherent pair. A1.B3 picks the route that the MODE-1 framework already supports and documents it; if neither exists deterministically, A1.B3 specifies the **minimal new primitive** A2 must build (a "coherent same-register divergence" arm) — but A1 still produces a *hand-wired* coherent witness to prove the bug fires.

### 5.3 Pre/post-fix validation table (G4, G5)
| build | `load_rs2` | same fault applied | proof verifies? | committed output | verdict |
|---|---|---|---|---|---|
| vulnerable (`98387806`) | absent | coherent rs2-read divergence | **ACCEPTS** | wrong (≠ honest 0) | **G4 pass** |
| patched (current tree) | present | identical fault | **REJECTS** | — | **G5 pass** |

Cross-check the trigger shape against A1.B1's MODE-2 canonical trigger (same op, same divergence, same accept-of-wrong).

### 5.4 Per-variant propagation characterization (D5)
For each variant arm that touches a source-register read (V5_control A4 reg-mod; V6_uniform/V6_cTS Arguzz reg-mod; Hybrid's reg-mod — **check whether it is the Arguzz/propagating flavor or the A4/single-cell flavor**, since the 4 imported Arguzz kinds historically excluded `PRE_EXEC_REG_MOD` as a name-duplicate of the A4 kind), document **whether the mutation propagates** (recompute → coherent) or is a single post-exec cell edit. This is the input to A3's per-variant findability prediction and to G6/G7. **Record it; do not assume.**

**Outputs:** the minimal repro guest + its disassembly proof; the deterministic fault spec; the G4/G5 table; `a1b3_variant_propagation.md`. **Gates: G4, G5.**

---

## 6. Risks, fallbacks, open implementation questions
1. **Back-port build fails to compile** (deps/codegen at the old commit). *Fallback:* try route (ii); if both fail, fall back to a **MODE-2-only race** for the Arguzz variants (loses the controlled MODE-1 A4/Hybrid comparison — flag to Ivan before accepting) or select the nearest genuinely-vulnerable commit that builds (L5 fallback; the completeness bug `4c65c85a` is **out of scope**).
2. **Commit already patched / Zirgen pulled at build.** G1/G2 catch this; if G2 fails (build regenerates from a newer Zirgen), the in-tree assumption is wrong → escalate (this would also affect L5).
3. **MODE-2 random scheduler doesn't hit `rs1==rs2`** within timeout → curate the guest/seed (§3).
4. **No deterministic coherent fault exists in MODE 1 today** (per the agent audit, a single `txn_idx` edit is non-propagating; a "coherent same-register divergence" primitive is likely net-new). A1.B3 must either drive the during-exec hook or hand-wire a coordinated witness; if it must defer the *productized* primitive to A2, A1 still delivers a hand-wired G4/G5 proof.
5. **Fingerprint stamping mechanism** (build-file vs host emit vs `A4_INSPECT` tag) — A1.B2 chooses; recommended = both a `fingerprint.json` and an `A4_INSPECT_FINGERPRINT=1` host emit (§4.3). The dispatcher-side assertion is G11/G13 (A3.B1 / B1.B1), not A1.
6. **A4/Hybrid findability is a genuine unknown** (§0.3 / `BUG_MECHANISM_VERIFIED.md`): the leading prediction is V5 cannot find it on the strong oracle; A1's D5 + the A3 race settle it. A1 must **not** bake in either answer.

---

## 7. Acceptance checklist (A1 done ⇔ all pass)
- [ ] **G9** — MODE-2 re-finds the bug at `98387806`; `check` → `fixed=False` at vuln, `fixed=True` at fix.
- [ ] **G1** — built vulnerable binary's source lacks `load_rs2` (two reads present).
- [ ] **G2** — circuit built from in-tree generated files; no newer-Zirgen codegen.
- [ ] **G10** — both builds emit the 4-field fingerprint (incl. `load_rs2_present` 0/1 + `guest_image_id`).
- [ ] **G4** — deterministic coherent fault → pre-fix ACCEPTS a proof of a wrong output.
- [ ] **G5** — identical fault → post-fix REJECTS.
- [ ] **D5** — per-variant propagation documented.
- [ ] Smoke harness re-validated on the vulnerable build (inspection/coverage tags parse).

**Handoff to A2:** the canonical trigger (B1), the vulnerable+fingerprinted `risc0-host` (B2), the minimal repro guest + the coherent-fault spec / new-primitive requirement (B3), and the per-variant propagation table (D5). A2 builds Race-guest A/B, the productized coherent-divergence arm (selectable by every scheduler — G7), and the dual oracle.

---

## 8. Inventory (reads / produces)
**Reads:** `projects/risc0-fuzzer/` (cli.py, settings.py, zkvm_repository/{install,injection}.py, injection_sources/`rv32im_rs_9838780.py`); `libs/zkvm-fuzzer-utils/.../{fuzzer,checker,csvlogger}.py`; `workspace/risc0-modified/risc0/circuit/rv32im/src/{execute/rv32im.rs, prove/witgen/{mod,preflight}.rs}` + `rv32im-sys/kernels/cxx/{ffi.cpp,witgen.h,steps.cpp}`; `workspace/output/{methods/build.rs, host/src/main.rs}`; `a4/core/executor.py`, `a4/standalone/{arguzz_invoke.py, mutations/, coverage_db.py}`; `a4/pos/{prepare_bundle.sh, run_campaign_pos.sh, chain_dispatcher.sh, generate_d2f_manifests.py}`; `IV_POS_8_BACKPORT_SCOPING.md`.
**Produces:** vulnerable `risc0-host` + `fingerprint.json` (both builds); `a1b1_canonical_trigger.md`; `findings.csv`+`checked_findings.csv`; minimal repro guest + disasm proof; deterministic-fault spec; G4/G5 validation table; `a1b3_variant_propagation.md`; build logs evidencing G1/G2.

---

## 9. Batch summary (for KICKOFF authoring)
| Batch | Delivers | Gates | Blocks |
|---|---|---|---|
| **A1.B1** | MODE-2 existence proof + canonical trigger + MODE-2 pre/post-fix (`check`) | G9 | — |
| **A1.B2** | instrumented vulnerable `risc0-host` + fingerprint mechanism (both builds) + harness re-validation | G1, G2, G10 | A1.B1 (trigger informs guest curation; not strictly blocking) |
| **A1.B3** | minimal `rs1==rs2` repro guest + coherent propagating fault + G4/G5 table + per-variant propagation | G4, G5 | A1.B2 (needs the vulnerable build) |

*Sequencing:* B1 ∥ B2 can start together (B1 is MODE-2, B2 is MODE-1 build); **B3 needs B2**. A1 gate (G1–G5,G9,G10) opens A2.
