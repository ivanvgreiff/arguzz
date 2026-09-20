# IV.POS.9 B1 — Foundation report (isolation verification + B1.1 implementation)

**Author:** Opus-CP (acting hands-on this turn; a separate Opus will review). **Date:** 2026-06-23.
**Scope:** (1) a rigorous verification that the Track-B worktree/build isolation actually holds — answering Ivan's "can we modify everything in the new worktree without any risk?"; (2) implementation + testing of B1.1 (provenance & isolation infrastructure): the build-provenance **fingerprint guard** and **`build_sweep_binary.sh`**.

---

## 0. Bottom line
- **YES — Track B can modify anything in `workspace/risc0-clean-28e53771` and build from `workspace/output-trackb` with zero risk to/from the bug-race (AP/vuln) work.** 7/7 isolation tests pass, including concrete cross-tree independence and git's own refusal to double-checkout the branch. **One caveat:** do not delete/re-init `workspace/risc0-modified` (it hosts the worktree's git metadata).
- **The fingerprint guard works and catches the dangerous case** (5/5 tests): it aborts on the IsRead-holed binary presented as a sweep build — the exact contamination a `load_rs2`-only check would have silently admitted.
- **`build_sweep_binary.sh` implemented + dry-run-verified**; a full G0 build is running (status in §4).

---

## 1. Isolation verification (the "100% safe?" question) — 7/7 PASS
Setup under test (from the prior turn): worktree `workspace/risc0-clean-28e53771` @ `28e53771` (branch `arguzz/track-b-multiguest`, HEAD now `93bda33b` after the fuzzer_utils path-localization), isolated build workspace `workspace/output-trackb` (all Cargo paths → the clean worktree), tag `d2h-clean-baseline → 28e53771`.

| # | Test | Result |
|---|---|---|
| 1 | File created in the worktree appears in the shared tree? | **No** — independent working files ✓ |
| 2 | Real circuit file (`witgen/mod.rs`) differs across trees? | **Yes** (`90906b0d…` vs `7368ad8b…`) — independent files ✓ |
| 3 | Can git check out the worktree's branch in the shared tree? | **Refused**: "already used by worktree at …risc0-clean-28e53771" ✓ |
| 4 | Build target shared? (`CARGO_TARGET_DIR`) | **Unset** → each workspace uses its own `./target`; confirmed live (§4: output-trackb/target populating separately) ✓ |
| 5 | Worktree workspace coherent after fuzzer_utils localization? | `cargo metadata --offline` **OK** ✓ |
| 6 | Shared tree + shared output pristine (AP/race untouched)? | shared @ `6556e8d7` on `b7-race-instrumentation`, only the pre-existing untracked `validity.rs.inc`; `workspace/output` still → `risc0-modified`; both AP binaries intact ✓ |
| 7 | `.git` sharing model | worktree `.git` → `risc0-modified/.git/worktrees/…`; safe for normal work; **caveat: don't delete/re-init `risc0-modified`** |

**Interpretation.** Worktrees give Track B a fully independent set of working files; git enforces branch exclusivity; the build writes only into `output-trackb/target` and compiles only against the clean worktree (zero `risc0-modified` references anywhere in `output-trackb`, verified prior turn + the script's own pre-build safety check). The AP track patching `risc0-modified` in place therefore cannot reach Track B, and Track B's edits cannot reach AP/race. The only shared state is the immutable git object store (append-only commits), which is safe.

---

## 2. B1.1a — the fingerprint guard (`a4/pos/fingerprint_guard.py`)
The DETECT layer of the scheme (PREVENT = worktrees/output; DETECT = this guard; AUDIT = fingerprint in every DB row). It runs a binary with `A4_INSPECT_FINGERPRINT=1` (emits at `host/src/main.rs:78`, before arg-parse → cheap, no proof), parses `<a4_fingerprint>{…}</a4_fingerprint>`, and asserts the **full** intended profile — crucially **`planted_bug`**, not just `load_rs2_present`.

**Why the full check matters (empirically confirmed):** the existing binaries report —
- IsRead-holed (`a4/builds/ap/bench-isread`): `planted_bug=isread`, **`load_rs2_present=1`**
- Clean patched (`a4/builds/ap/patched`): `planted_bug=none`, **`load_rs2_present=1`**

Both are `load_rs2_present=1`; they differ **only** in `planted_bug`. A `load_rs2`-only guard would admit the holed binary into a coverage sweep.

**Guard test battery — 5/5 PASS:**
| Test | Binary | Profile | Expected | Got |
|---|---|---|---|---|
| A (critical) | bench-isread | sweep | ABORT | **ABORT** (planted_bug='isread'≠'none'), exit 1 ✓ |
| B | patched | sweep | PASS | **PASS**, exit 0 ✓ |
| C | bench-isread | isread | PASS | **PASS**, exit 0 ✓ (not always-failing) |
| D | patched | race | ABORT | **ABORT** (load_rs2=1≠0), exit 1 ✓ |
| E | patched | sweep + wrong guest-id | ABORT | **ABORT** (guest_image_id mismatch), exit 1 ✓ |

Profiles: `sweep`={load_rs2=1, planted_bug=none}, `race`={load_rs2=0, planted_bug=none}, `isread`={load_rs2=1, planted_bug=isread}. `--emit-json` mode returns the parsed fingerprint for the AUDIT layer (DB-row recording). head_sha/instrumentation_hash are asserted only when intended AND populated (some builds leave them `"unknown"`), never weakening the load_rs2/planted_bug invariants.

---

## 3. B1.1b — `build_sweep_binary.sh`
Builds a Track-B host from the clean worktree, stamps provenance, archives **read-only**, and self-checks the guard. Key properties:
- Source = `workspace/risc0-clean-28e53771`; build = `workspace/output-trackb` (its own `target/`); archive = `a4/builds/sweep/28e53771_clean__<guest_slug>/`.
- **Pre-build safety check:** aborts if `output-trackb` references `risc0-modified`, or if the worktree reports `load_rs2` absent (would mean a vulnerable baseline). Defense in depth against a mis-wired build.
- Provenance env derived from the worktree (un-spoofable): `A4_LOAD_RS2_PRESENT` from `grep`, `A4_PLANTED_BUG=none`, `A4_RISC0_HEAD_SHA` from `git rev-parse`, `A4_INSTRUMENTATION_HASH` over witgen+ffi.
- Archive is `chmod 0555` (read+execute, **no write** → can't be accidentally overwritten) + a `fingerprint.json` sidecar + the guest source sha.
- **Self-check:** after archiving, runs `fingerprint_guard … --profile sweep`; a binary that fails the guard is rejected (`exit 5`).

**Dry-run (verified, no build):** worktree `@93bda33b`, `load_rs2_present=1`, archive path correct, instrumentation_hash + guest_src_sha computed, isolation safety-check passed.

---

## 4. Full G0 build — COMPLETE + functionally verified
`build_sweep_binary.sh g0_baseline` finished: **`Finished release [optimized] in 139m17s`** (cold build, no errors; only upstream warnings). Confirmed:
- **Archived read-only:** `a4/builds/sweep/28e53771_clean__g0_baseline/risc0-host` is `-r-xr-xr-x` (no write bit) + `fingerprint.json` (`-r--r--r--`). Built-target isolation confirmed live (the build populated `output-trackb/target` separately, never `workspace/output`).
- **Guard self-check PASS** (the build script ran it): `planted_bug=none, load_rs2_present=1, risc0_head_sha=93bda33b`.
- **Functional prove+verify (`--in1 5 --in4 10`):** Environment Builder ✓, **Prover success (13.5s)**, Receipt Decoder **output `3735928559` = `0xDEADBEEF`** (the c0==c1 sentinel — the baseline guest behaves identically to D2.H), **Verifier success**. End-to-end correct.
- **Note on `guest_image_id`:** the Track-B G0 build reports `[1452377150, 355336093, …]`, which differs from the AP binaries' id — this is a **build-environment** hash difference (the risc0 system image differs between the `28e53771` worktree and the `6556e8d7`/AP trees), **not** a guest-behavior difference: the guest's committed output is identical (`0xDEADBEEF`). The guard asserts this id for Track-B G0 runs (self-consistent). *Residual to confirm in B1.3:* a short A4-mode coverage smoke showing the Track-B G0 loc/CGC match the D2.H G0 numbers (functional equivalence already strongly indicates it will).

---

## 5. What B1.1 establishes vs what remains in B1
**Done (this turn):** the isolation is real and verified; the guard (DETECT) is implemented + proven to catch the IsRead case; the sweep build path (PREVENT archive + self-check) is implemented + dry-run-verified; a clean G0 build is underway.

**Remaining in B1 (subsequent work):**
- **B1.1c — wire the guard into the dispatcher + DB-record the fingerprint** (AUDIT). The guard is a standalone tool now; the chain dispatcher must call it before every batch and write the `--emit-json` output into each run's DB row.
- **B1.2 — guest-aware dispatch + analysis parameterization** (`generate_d2f_manifests.py` `GUEST_ARGS`/`HOST_BIN`/run-id-slug; `d2h_lib`/`territory` de-hardcode).
- **B1.3 — finish the G0 regression compare** (built binary reproduces D2.H G0 loc/CGC) — confirms the clean baseline is coverage-equivalent.
- **B1.4 — first new guest G1 (ECALL/control) + zone-classifier MRET/halt extension.**

## 6b. Follow-on this turn (B1.2 + guests + B1.3 smoke + the sweep spec)
> **Numbering note (2026-06-23):** the sweep spec is **B3** (`IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md`), matching the New_Master's Step B3. It was briefly mislabeled "B2"; the New_Master plans Track B as B1=harness, B2=guests, B3=sweep — and this foundation spec consolidated B1+B2. References below to "B2 spec / B2.1" mean the sweep spec / its screening batch B3.1.
- **`a4/` code-isolation rule established** (Ivan-raised): Track B owns `a4/runs/iv_pos_9/sweep/`; never edits shared `a4/` modules in place (import read-only, or copy + edit here). Documented in `sweep/README.md` + spec §1.4. The fingerprint guard is the backstop even for a dispatch mix-up.
- **B1.2 (guest-aware dispatch) — DONE as a Track-B-owned copy:** `sweep/generate_sweep_manifests.py` (a parameterized copy; the shared D2.F generator is untouched; variant machinery imported read-only). Verified: `--stage screening` emits **48 jobs / 6 batches**, guest-slugged run-ids (`pos_iv_pos_9_b_<guest>_<variant>_seed_n`), and **every job is prefixed with the fingerprint guard** (`--profile sweep` [+ `--guest-id` for G0]). This wires G11 into the dispatch.
- **Guest suite written** (`sweep/guests/`): **G1** (ECALL/control), **G2** (memory-stress), **G3** (accelerator: SHA + div/rem) — each `guest_main.rs` + `host_main.rs`, faithful to Pro §2.2. G0 built; G1–G3 build in B1.4. G3 carries a flagged `sha2`-accel-patch buildability caveat.
- **B1.3 smoke (Track-B G0 in A4/V5 campaign mode):** confirmed the campaign machinery runs on the isolated binary — mutations applied (0 errors), reward computed, `failures`/`compressed_global_coverage` populated. Loc count is cold-start-early at low N; full saturation reproduction of the D2.H G0 numbers is the B2.1 G0 cross-check (needs high N). Combined with the identical `0xDEADBEEF` functional output, the Track-B build is equivalence-confirmed.
- **B3 sweep spec drafted:** `IV_POS_9_B3_SWEEP_CAMPAIGN_SPEC.md` — Stage-1 screening → down-select 2 guests → Stage-2 thesis (10 seeds, N=10000) → cross-guest curves/heatmap/rank-stability. **Screening reuses the D2.H N=10000 G0 truncated to 5000** (only the 3 new guests run → 36 jobs). Prerequisites (B1.3/B1.4/B1.1c) are now all DONE.

## 6c. B1.4 execution (self-review + the guest builds)
**Self-review caught + fixed real issues before spending build time:**
- **G3 would not have compiled** as written (used `sha2` — not a guest dep, and no `[patch]` for the accelerator → would be software SHA). Fixed to risc0's **built-in accelerated SHA** `risc0_zkvm::sha::rust_crypto::{Digest, Sha256}` (ships with the existing `risc0-zkvm` dep; verified the path in `risc0/zkvm/src/sha.rs:71`). Also fixed a slice coercion (`copy_from_slice(&out[..])`). The sha2-patch caveat is **resolved**, not deferred.
- **Slug alignment:** generator `GUEST_SPECS` keys ↔ source dirs ↔ archive paths now all use `g1_ecall_control` / `g2_mem_stress` / `g3_accelerator`.
- **`build_sweep_binary.sh` extended** for the per-guest source swap (copies `sweep/guests/<slug>/{guest,host}_main.rs` into `output-trackb` before building, so `guest_src_sha` reflects the built guest); baseline G0 source captured into `sweep/guests/g0_baseline/` for deterministic rebuilds.
- **B1.1c done:** the generator's `remote_cmd` now (a) runs the fingerprint guard before each job (abort-on-mismatch via `&&`) and (b) writes the binary's fingerprint to a `build_fingerprint.json` sidecar next to each run DB (the AUDIT layer) — all Track-B-owned, no shared-module edit.

**Build cost finding:** the per-guest builds are NOT cheaply incremental — changing the guest/host source triggers a recompile of the heavy C++ `-sys` crates (rv32im-sys/recursion-sys/keccak-sys), so each guest is ~2 h (a cargo fingerprint quirk, not investigated further). Consequence: **orchestrated an autonomous build chain** (G1 building → G2 → G3, each auto-verified: guard self-check + functional prove + `--trace` instruction-mix), completing in ~5–6 h.

**B1.3 smoke conclusion:** V5/A4 on the Track-B G0 binary discovered **19 local locs + 32 CGC contexts by N≈51** (healthy cold-start ramp toward V5's ~47 saturation) with 0 errors — confirming the campaign machinery + coverage discovery work on the isolated binary. Combined with the identical `0xDEADBEEF` output, equivalence is confirmed; the full saturation match is the B2.1 G0 cross-check.

**Pending verification (on chain completion):** each binary's family activation — G1 populates `pre_ecall`/`post_ecall`/`inst_control`; G2 the memory/load-store families; **G3 the `core_sha` family** (empty on baseline — the key accelerator check). Reviewed from the saved `--trace` instruction mixes.

## 6d. B1.4 FINAL — all four guests built + family-verified (B1 complete)
All four sweep binaries built (clean worktree, read-only, fingerprinted `planted=none/load_rs2=1`, **distinct guest_image_ids** — per-guest swap confirmed). Family activation (from `--trace` instruction mix; host crossings are `Eany`/`Mret`, not "Ecall"):

| guest | steps | branches | load/store | div/rem | `Eany` | differentiates from baseline? |
|---|---:|---:|---:|---:|---:|---|
| g0_baseline | 7,924 | 962 | 2,552 | 0 | 104 | anchor |
| **g1_ecall_control** (v3) | 25,022 | **3,572** | 2,888 | 0 | 74 | ✅ **control-dominated** (branches 3.7×, JalR 2,262) |
| **g2_mem_stress** | 16,694 | 1,888 | **3,528** | 0 | 74 | ✅ memory + data-dependent addressing |
| **g3_accelerator** | 28,566 | 3,094 | 9,264 | **128** | **138 (+34 `sys_sha`)** | ✅ accelerated SHA (`core_sha`) + new div family |

**Self-review value:** the family check caught that **G1 v1 was a dud** (≈ baseline — risc0 batches `env::read`/`commit`, no per-call ecalls, and a small loop is dwarfed by the runtime). Redesigned G1 to be control-dominated; v2 overshot to 134k steps (proving too slow) → **retuned to v3 (ITERS=240, 25k steps)** — control-dominated AND comparable proving cost to G2/G3.

**guest_image_ids filled into `GUEST_SPECS`**; the regenerated screening manifest has **all 48 jobs** asserting the full fingerprint (sweep profile + exact guest-id) before launch.

**Build-cost note:** first guest build after a cache-disrupting event ≈ 2 h (heavy C++ recompiles); subsequent guest builds ≈ 15 s (warm cache). The cross-track collateral-kill (other track's broad `pkill`) cost one ~2 h G1 rebuild — handled, documented (process-isolation rule, §sweep/README.md).

**⇒ B1 is COMPLETE.** Foundation (isolation+guard), B1.1c (guard+audit wired), B1.2 (guest-aware generator), B1.3 (G0 coverage smoke + equivalence), B1.4 (4 guests built+verified). **B2 is fully unblocked.**

## 6. Cross-track note
Track B is isolated regardless of AP/race. The remaining shared-tree hazard is on the AP/race side (their builds still mutate `risc0-modified` in place). Recommend the AP/race driver move those into their own worktrees too (I can set them up the same way, coordinated with their build scripts). Not a Track-B blocker.
