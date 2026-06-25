# A1.B2 — Vulnerable instrumented `risc0-host` (rs1==rs2 CVE) + CVE race dispatch

**Status: COMPLETE — CVE thesis race LIVE on POS (2026-06-25).** B2 (the vulnerable, instrumented
MODE-1 host @ `98387806`) is built, locally verified (honest prove + exploit candidate), bundled,
deployed to the 8 fast nodes (all 8 passed the `race` fingerprint guard), and the 40-job thesis chain
(`chain_cve_thesis`) is recording mutations on every node. This is the **mirror** of the A3 Seam-B race:
the rs1==rs2 underconstraint (CVE-2025-52484 / risc0 #3181) is **Arguzz-findable, A4-resistant**.

---

## 1. The goal and why it was hard
We need **one** `risc0-host` that is simultaneously:
- the **vulnerable circuit** (rs1==rs2 underconstraint present — a field-only rs2:=rs1 alias on a
  3-register op proof-verifies with a wrong committed output), and
- carries **our full 4-variant instrumentation** (executor fault hooks for Arguzz/V6 `INSTR_WORD_MOD`;
  the witgen single-cell mutation surface + coverage for A4/V5; the `A4_INSPECT_FINGERPRINT` provenance
  tag; markers/telemetry).

**The tension:** the vulnerable circuit only exists *cleanly* at `98387806` (its committed generated
circuit — `poly_ext.rs` 20k, `steps.cpp` 30k, `info.rs`, taps — is the pre-fix one, so building there
needs **no zirgen regen**; this is what makes A1 tractable where the AP planted-IsRead track was blocked).
But our A4 instrumentation (`28e53771`+`93bda33b`) was authored on `ebd64e43` — a **later, patched** base
whose circuit **Rust API differs** from `98387806`. `98387806` is the *direct parent* of the fix
`67f2d81c` (#3181), and the fix **regenerated the entire codegen** — reverting it surgically is
infeasible, so we forward-port the instrumentation onto `98387806` instead.

The naive `git cherry-pick -n -X theirs 28e53771` produced a Frankenstein: it grafted the ebd64e43-API
prove path (`preflight`/`prove_core`/`PreflightResults`) and witgen plumbing onto a tree whose
`SegmentProver` trait only declares the monolithic `prove(segment)` → **11 compile errors** in
`prove/hal/mod.rs` (7) and `prove/witgen/mod.rs` (4).

## 2. The forward-port (the surgical fix) — `workspace/risc0-a1-vuln` @ `98387806`
Worktree HEAD = `98387806` with the instrumentation as uncommitted working-tree changes. Codegen left
**byte-identical to `98387806`** (verified: `poly_ext.rs`, `info.rs`, `steps.cpp` all 0-diff).

**a) `prove/hal/mod.rs` — graft, don't refactor.** Reverted to `98387806`'s clean monolithic
`fn prove(&self, segment) -> Result<Seal>` and grafted **only** the load-bearing A4 hook: force
`StepMode::SeqForward` when `A4_MUTATION_CONFIG` or `A4_COVERAGE_TOUCH` is set (the ebd64e43
`preflight`/`prove_core`/`PreflightResults` split — and the dead-for-the-race `A3_INSPECT`/`A3_CONFIG`
blocks — were dropped; the race harness drives `A4_*`, never `A3_*`). `+11 lines`.

**b) `prove/witgen/mod.rs` — graft the A4 trace-mutation surface.** Reverted to `98387806`'s clean
monolithic `WitnessGenerator::new(hal, circuit_hal, segment, mode, rand_z)`, made `let mut trace =
segment.preflight(rand_z)?`, and spliced the instrumentation's A4 blocks (PREFLIGHT INSPECTION +
UNIFIED MUTATION CONFIG, instr lines 72–601) immediately after preflight. These mutate `trace.cycles[]`
(`INSTR_TYPE_MOD`) / `trace.txns[]` (`INSTR_WORD_MOD`, `COMP_OUT_MOD`, `PRE_EXEC_REG_MOD`, …) before the
witness is generated — exactly the surface the 4 variants exercise. The structs match across both bases
(`PreflightTrace.{cycles,txns,backs,rand_z}`, `RawPreflightCycle.{pc,major,minor,user_cycle,txn_idx}`), so
the graft compiled with no field drift. The ebd64e43 plumbing (`PreflightResults`/`build_injector`/
`build_global_vec`/`hal_generate_witness`) is **not** brought — 98387806's monolithic `new()` doesn't
need it. `+534 lines`.

**c) Re-open the vulnerability that the cherry-pick had half-closed.** The fix #3181 touched three Rust
files; the executor (`execute/rv32im.rs`: two `ctx.load_register(decoded.rs2)` reads, no `load_rs2`) and
`r0vm.rs` (`SAFE_WRITE_ADDR.waddr()`, no `+j`) were already at the vulnerable `98387806` form, but
`prove/witgen/preflight.rs` had leaked the fixed cycle-diff arithmetic. Reverted it to `98387806`:
```
- let diff = txn.cycle - 1 - txn.prev_cycle;   // fixed (#3181, + the dropped ensure!)
+ let diff = txn.cycle - txn.prev_cycle;        // vulnerable @98387806 — no same-cycle ensure
```
This is the only change that makes the witgen consistent with the vulnerable codegen (an off-by-one here
would have made honest proofs fail).

**d) Fingerprint provenance.** `load_rs2_present` is **self-declared at build time** via
`option_env!("A4_LOAD_RS2_PRESENT").unwrap_or("1")` (host `main.rs`), not auto-detected. Built with
`A4_LOAD_RS2_PRESENT=0 A4_PLANTED_BUG=none A4_RISC0_HEAD_SHA=98387806…` so the binary self-reports the
vulnerable profile the guard asserts. Toolchain bumped `1.85`→`1.88` (idna_adapter MSRV); fuzzer_utils
path collisions repointed `risc0-modified`→`risc0-a1-vuln`.

## 3. Local verification (before any POS batch)
- **Fingerprint** (`A4_INSPECT_FINGERPRINT=1`): `planted_bug=none, load_rs2_present=0,
  risc0_head_sha=98387806…, guest_image_id=[2819774008,269738887,492358372,594138501,3395406058,
  845810525,2646011585,829874012]`. Guard `--profile race` → **PASS**.
- **Honest prove** (`--ctrl 7 --gseed 12345 --rounds 5`): committed `output=9000027` (= `9·1000003+0`,
  the predicted honest value for `x=9,y=12602`: `remu=9, divu=0`), **Verifier success**. Confirms the
  preflight revert is consistent with the vulnerable codegen and the binary proves end-to-end.
- **Exploit candidate** (the actual race tool, `v6_uniform_driver`, on B2): within the first 2 mutations,
  an `INSTR_WORD_MOD` at `step=459` in `zone=core_arithmetic` proved successfully
  (`verifier_accepted=1, proof_verify_failed=0`) — a soundness signal on B2's mutation surface.
- **Mechanism certainty** rests on **G4** (prior session, deterministic): on `98387806` the rs2:=rs1
  alias → proof verifies with wrong output; B2's codegen is **byte-identical** to that. The POS race
  with the strong journal oracle (control-confirm vs the patched build) is the at-scale classification.

## 4. The A2 guest (`workspace/output-a1vuln/methods/guest`)
`remu {o}, a0, a1` + `divu {o}, a2, a3`, operands pinned by inline asm so rs1≠rs2 with **source
registers 1-bit-apart** (a0=x10/a1=x11; a2=x12/a3=x13). A single `INSTR_WORD_MOD` bit-flip aliases
rs2→rs1 (Framing B — the empirically-confirmed G4 path): the executor recomputes `rem(x,x)=0` →
coherent → verifies with output ≠ 9000027. A4's *post-exec* word edit doesn't recompute the result
cell ⇒ `C_local` fires ⇒ rejected. **Hence the mirror: V6/Hybrid expected to find it, V5/A4 not.**

## 5. Dispatch (reusing the A3 runbook, CVE-parameterized)
The generator + wrapper were parameterized (defaults unchanged → 13/13 Seam-B regression tests pass):
`generate_race_manifests.py` gains `--profile/--head-sha/--guest-id/--host-bin/--run-prefix`;
`dispatch_race.sh` gains env `GUARD_PROFILE/HEAD_SHA/GUEST_ID/RUN_PREFIX`. Committed @ `6961a2e`.

- **Bundle:** `prepare_race_bundle.sh HOLED=a4/builds/a1_cve/risc0-host` → `git archive HEAD` + B2 binary
  → `bundles/a4_campaign_cve_6961a2ec6074.tar.gz` (525 M, host sha256 `dbe89d23…`, verified to ship B2).
- **Stage:** scp → coinbase `/tmp/ivg_race/` (sha256 `41d0a10f…`); repo extracted from the bundle (no git).
- **Deploy + guard:** `dispatch_race.sh … flare octorand opulous polynize algofi gard goracle zone` with
  `GUARD_PROFILE=race HEAD_SHA=98387806… RUN_PREFIX=cve GUEST_ID=… STAGE=thesis N=5000`. **All 8 nodes
  passed the `race` guard** (`load_rs2_present=0, planted_bug=none` — vulnerable binary loaded on
  debian-trixie). 40-job manifest written; chain launched in tmux `chain_cve_thesis`.
- **Batch-1 verified recording** (after ~6 min cold-start, all proc=1):
  | node | variant·seed | muts | acc |
  |---|---|---|---|
  | flare | V5_control·1234 | 92 | 35 |
  | octorand | V6_uniform·1234 | 153 | 6 |
  | opulous | V6_cTS·1234 | 143 | 8 |
  | polynize | Hybrid_cTS·1234 | 92 | 33 |
  | algofi | V5_control·1235 | 77 | 25 |
  | gard | V6_uniform·1235 | 136 | 4 |
  | goracle | V6_cTS·1235 | 131 | 7 |
  | zone | Hybrid_cTS·1235 | 77 | 25 |

  ~2–3 s/mut steady-state ⇒ N=5000 ≈ 4.3 h/job; 40 jobs / 8 nodes = **5 batches ≈ ~23 h**. (Raw `acc`
  includes benign no-op accepts; CVE finds = oracle-classified rs2-alias accept-of-wrong, post-hoc.)

## 6. Artifacts + provenance
| artifact | path |
|---|---|
| B2 binary (vuln, instrumented) | `a4/builds/a1_cve/risc0-host` (sha256 `dbe89d23…`) + `fingerprint.json`, `sha256.txt` |
| B2 source tree | `workspace/risc0-a1-vuln` @ `98387806` (codegen 0-diff; hooks in `prove/hal`, `prove/witgen`; fix reverted in `witgen/preflight.rs`) |
| build dir | `workspace/output-a1vuln` (toolchain 1.88; built with `A4_LOAD_RS2_PRESENT=0 A4_RISC0_HEAD_SHA=98387806…`) |
| bundle | `bundles/a4_campaign_cve_6961a2ec6074.tar.gz` (525 M) |
| dispatch infra (committed @6961a2e) | `a4/pos/generate_race_manifests.py`, `a4/pos/race/dispatch_race.sh`, `a4/runs/iv_pos_9/a1/verify_b2.sh` |
| local exploit-candidate DB | `a4/runs/iv_pos_9/a1/cve_smoke_v6.db` (+ `logs/cve_smoke_v6.log`) |
| POS results (live) | coinbase `/srv/testbed/results/ivgreiff/a4/cve_race_thesis/`; chain tmux `chain_cve_thesis`, log `/tmp/chain_cve_thesis.log` |

## 7. What remains
- Race completes in ~23 h (5 batches). Monitor via `tail -F /tmp/chain_cve_thesis.log` (CHAIN_COMPLETE).
- Pull run.dbs → `a4/runs/iv_pos_9/race/cve_results/`; run the **strong journal oracle** (accept +
  committed output ≠ 9000027; control-confirm vs a patched build = G5) to classify the rs2-alias finds.
  Expected: V6/Hybrid find it, V5/A4 ≈ 0 — the mirror of A3 (where A4 found the VerifyOpcode bug,
  Arguzz couldn't), establishing **bidirectional complementarity**.
