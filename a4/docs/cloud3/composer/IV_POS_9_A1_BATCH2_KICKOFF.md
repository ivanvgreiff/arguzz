# Composer Kickoff — A1.B2: Instrumented vulnerable build + provenance fingerprint

**Parent spec:** [`../IV_POS_9_A1_VULN_BUILD_SPEC.md`](../IV_POS_9_A1_VULN_BUILD_SPEC.md) §4 · **Batch:** A1.B2 · **Status:** READY (can run in parallel with A1.B1)
**Gates this batch satisfies:** **G1, G2, G10** · **Reviewer:** Opus.

---

## 0. Objective
Produce an **instrumented MODE-1 `risc0-host` built at the vulnerable commit `98387806`** that is (a) **proven vulnerable** at the source/circuit level (G1/G2) and (b) **self-identifying** via a build-provenance fingerprint (G10). Also stamp the fingerprint on the **patched** build (the current tree), since the sweep (Track B / G12) and the A1.B3 post-fix check both need it. This is the binary the entire race will run on — getting its provenance right is the whole point of L13/L14.

## 1. Context you need
- **Current tree is patched.** `workspace/risc0-modified` @ `28e53771` sits on base `ebd64e43`, which **has** the #3181 fix (`fn load_rs2`). It cannot find the bug. We need the same A4 instrumentation **on the vulnerable commit**.
- **The back-port is small and pre-scoped** ([`../../cloud2/IV_POS_8_BACKPORT_SCOPING.md`](../../cloud2/IV_POS_8_BACKPORT_SCOPING.md)): applying the instrumentation diff (`ebd64e43 → 28e53771`) onto a `98387806` worktree was tested → **49/60 files byte-clean**; residue = `steps.cpp` (a mechanical assert-wrap regex, 125 sites at the bug commit) + 3 one-hunk Rust merges (`hal/mod.rs`, `witgen/mod.rs`, `preflight.rs`). The heavy C++ hooks (`ffi.cpp`, `witgen.h`, `eval_check.cpp`) are byte-clean; coverage rides via `witgen.h`'s `EQZ` macro (the bug commit's `steps.cpp` already issues 1868 `EQZ()` calls). Toolchain 1.85.0 matches.
- **Fingerprint surfaces already half-exist:** `RISC0_GUEST_ID: [u32;8]` is generated at build (`workspace/risc0-modified/risc0/build/src/lib.rs:221`) and used in `workspace/output/host/src/main.rs:201`; the host already emits `<record>{…JSON…}</record>` to stdout (`host/src/main.rs:70+`); `a4/pos/prepare_bundle.sh:88,149-161` already computes `host_sha256` + `git_commit` into `bundle.json`; `run_campaign_pos.sh:174-181` already FATALs on a host-sha mismatch. The DB `campaigns` table (`a4/standalone/coverage_db.py:83-93`) has an idempotent `ALTER TABLE` migration pattern (`:113-124`).

## 2. Deliverables
1. **Vulnerable `risc0-host`** built at `98387806` with the A4 instrumentation transplanted (route (i) forward-port preferred; see spec §4.1 for route (ii) and why it's likely larger).
2. **G1 evidence:** the built tree's `rv32im.rs` has **no `fn load_rs2`** and two separate `load_register(decoded.rs1)`/`load_register(decoded.rs2)` reads.
3. **G2 evidence:** the rv32im circuit compiled from the **in-tree committed generated files** (no build step regenerating from a newer Zirgen) — document the build-graph evidence.
4. **Fingerprint mechanism (G10):** every `risc0-host` carries `{risc0_head_sha, load_rs2_present (0=vuln/1=patched), instrumentation_hash, guest_image_id}` — written to a build-time `fingerprint.json` next to the binary **and** emitted by the host on `A4_INSPECT_FINGERPRINT=1` (reuse the `<record>` pattern). Apply to **both** the vulnerable build and a re-stamp of the patched build.
5. **Harness re-validation:** the MODE-1 smoke harness runs on the vulnerable binary — `A4_INSPECT=1` parses into `InspectionData`, coverage/`EQZ`-touch tags emit, `arguzz_invoke.py::_classify_outcome` (`:88-107`) classifies.

## 3. Steps
1. **Transplant (route i):** create a worktree at `98387806`; apply the instrumentation diff; resolve the residue — re-run the `steps.cpp` assert-wrap over the bug commit's 125 sites; hand-merge the 3 Rust hunks (incl. the 1 uncommitted `witgen/mod.rs` change). Build `risc0-host` (`cargo build --release` in `workspace/output`; the guest embeds via `methods/build.rs::embed_methods()`). If route (i) hits a wall, evaluate route (ii) per spec §4.1.
2. **G1 check:** `git show <built-commit>:risc0/circuit/rv32im/src/execute/rv32im.rs | grep -c 'fn load_rs2'` → **0**; confirm the two separate reads. Fail hard otherwise.
3. **G2 check:** confirm no `zirgen`/codegen step runs at build; the `rv32im-sys` crate uses the in-tree `.cpp`/`.cu`. Record evidence.
4. **Fingerprint:** compute the four fields at build; emit `fingerprint.json`; add an `A4_INSPECT_FINGERPRINT=1` emit path in `host/src/main.rs` (new `<record>` with `guest_image_id` from `RISC0_GUEST_ID`, plus the three build-context fields passed in via build env/file). Re-stamp the patched build the same way. (Dispatcher-side *assertion* of this fingerprint is G11/G13 — **not** this batch; this batch only makes the binary self-identifying.)
5. **Re-validate harness** on the vulnerable binary (smoke run; confirm inspection + coverage tags parse). Note: coverage loc IDs differ from the patched-tree D2.H numbers (different circuit) — **expected**; do not compare.

## 4. Acceptance (G1, G2, G10)
- [ ] Vulnerable `risc0-host` builds and runs a smoke proof.
- [ ] **G1:** source lacks `load_rs2`; two separate source-register reads present.
- [ ] **G2:** documented evidence the circuit is the in-tree vulnerable one (no newer-Zirgen codegen).
- [ ] **G10:** both builds emit the 4-field fingerprint; `load_rs2_present` = 0 (vuln) / 1 (patched); `guest_image_id` matches the embedded `RISC0_GUEST_ID`.
- [ ] Smoke harness parses inspection/coverage on the vulnerable binary.

## 5. Guardrails
- **Treat the build + smoke run as the gate, not the "~1–2 h" estimate.** The transplant is the means; a working, provably-vulnerable, fingerprinted binary is the end.
- **Do not** wire the dispatcher assertion here (that's A3.B1/B1.B1). This batch makes the binary *self-identifying*; it does not enforce.
- **Do not** compare the vulnerable build's coverage numbers to D2.H (different circuit — §2.4).
- Keep the vulnerable and patched binaries in **clearly separated, labelled** locations so they can never be confused downstream.

## 6. Definition of done
A provably-vulnerable, fingerprinted `risc0-host` exists (G1/G2/G10), the patched build is re-stamped, and the smoke harness runs on it. Hand the vulnerable binary + both `fingerprint.json`s to A1.B3 (which needs the vulnerable build for G4 and the patched build for G5).
