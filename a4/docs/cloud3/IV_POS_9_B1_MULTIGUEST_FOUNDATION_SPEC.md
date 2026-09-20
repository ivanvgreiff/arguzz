# IV.POS.9 — Spec B1: Multi-guest foundation — provenance isolation + guest-aware pipeline + first focused guest

**Track:** B (multi-guest coverage sweep — the *generalization* claim). **Governing:** `ProG_Report_5.md` §2; `New_Master.md` (cloud3) §L7/L8/L13/L14, gates G10–G13.
**Author:** Opus-CP (planning). **Status:** DRAFT for Ivan+Opus review before Composer starts.
**Date:** 2026-06-23.

---

## 0. Why this spec exists, and why it can run NOW (in parallel with Track A)

Pro (ProG_Report_5 §0) sequences **race first, sweep second** — but that is a *results-priority* ordering, not a build dependency. The multi-guest sweep (Track B) is an **independent claim** (coverage generalization) with **no data dependency** on the known-bug race (Track A): it runs entirely on the **current patched tree** (the D2.H build), reuses the guest-agnostic D2.G/D2.H metric/triage stack, and needs none of Track A's vulnerable binary or race results. So Track-B *preparation* (this spec) can proceed in parallel with the (slow) Track-A race, with one hard precondition: **physical binary/source isolation must be established FIRST, before Track A reverts or builds anything that could clobber the patched build Track B depends on.** That isolation is B1's first and load-bearing deliverable.

**Compute note (not a blocker for B1):** the *full* sweep campaign is expensive (New_Master compute-reality: Stage-1 screening ≈ 180 run-hours, Stage-2 thesis ≈ 600 run-hours). B1 is build+parameterize+smoke only (cheap, local/few-node). The expensive campaign (B2/B3) is scheduled around Track A's POS usage — but nothing about B1 waits on Track A.

### What B1 is NOT
- **Not the screening/thesis sweep** (4 guests × 4 variants × N=5000/10000) — those are B2/B3.
- **Not Track A.** B1 never touches the vulnerable commit `98387806` or the bug guest. B1 builds **only patched-tree** binaries (`load_rs2_present=1`).
- **Not new analysis math.** D2.G/D2.H loc/CGC/territory/triage logic is reused; B1 only *de-hardcodes* it for multiple guests.

---

## 1. The binary-contamination problem (Ivan's #1 concern) — and the isolation scheme

**⚠️ The world is THREE circuit variants, not two (CONFIRMED from source + existing binaries — correction from the Track-A reviewer).** A binary is `(risc0 source variant) × (embedded guest)`. The guest is **compile-time-embedded** (`workspace/output/methods/build.rs::embed_methods()`), so every guest is a distinct build. The three source variants are:
| variant | `load_rs2_present` | `planted_bug` | tree state | used by |
|---|:--:|:--:|---|---|
| **clean-patched** | 1 | `none` | D2.H base, unmodified | **Track B + all coverage** |
| **isread-holed (AP)** | **1** | `isread` | patched tree + `ap_isread_patch.py` (a *circuit* hole in `poly_ext.rs`/`steps.cpp`) | Track A (AP planted-bug) |
| **vuln** | 0 | `none` | commit `98387806` (no `load_rs2`) | Track A (bug race) |

**The trap my first draft fell into:** I modeled `{patched, vuln}` and asserted only `load_rs2_present==1`. But the **isread-holed AP binary also reports `load_rs2_present==1`** (it's built on the patched tree) — so a `load_rs2`-only guard would **pass an isread-holed binary into a sweep slot → a coverage run silently executes on a holed circuit** (the exact correctness-fatal failure the scheme exists to prevent). Verified: `host/src/main.rs:49` exposes `planted_bug` (default `none`); `a4/builds/ap/bench-isread/fingerprint.json` already reports `planted_bug: isread`, `load_rs2_present: 1`. **The AP build (`build_ap_binaries.sh`) already mutates the shared tree in place** (`RISC0_DIR=workspace/risc0-modified`, applies `ap_isread_patch.py`, builds, copies out) — so the in-place-mutation hazard is *live today*, not just a Track-A-future risk.

**The scheme — three layers (prevent · detect · audit). Formalizes New_Master L13/L14 + gates G10–G13 into on-disk structure, for all THREE variants.**

### 1.1 PREVENT — physical separation from a pinned clean baseline (source + output)
- **Pin the clean baseline = the D2.H build commit `28e53771`** (NOT the current HEAD `6556e8d7`, which added race-prep `witgen/mod.rs` mutation-replay hooks on Jun 22, *after* the D2.H campaign). `6556e8d7` touches only `witgen/mod.rs` (fault-injection path), not the circuit — but Track B uses `28e53771` for **provable D2.H coverage comparability**, and B1.3 confirms equivalence. *(This is exactly Ivan's instinct — "go back to the commit when Pro responded and branch outwards." Correct — with the mechanism caveat below.)*
- **Source: ONE git worktree PER variant, derived from the clean baseline; the shared tree is NEVER mutated in place by anyone.** Use **`git worktree add`** (separate physical dirs sharing `.git`), **NOT** branch-checkouts in one directory — a `git checkout` mutates the working tree in place, which IS the contamination (it's what `build_ap_binaries.sh` does today). Branching alone does *not* isolate; worktrees do.
  - `workspace/risc0-modified/` (or a fresh `workspace/risc0-clean-28e53771/`) @ **`28e53771`** → **Track B + coverage.**
  - `workspace/risc0-isread/` @ patched + IsRead patch → **AP planted-bug** (AP's in-place patching moves here).
  - `workspace/risc0-vuln-98387806/` @ `98387806` → **bug race.**
- **Output: per-build provenance archive, never a shared overwrite path.** Align with the existing `a4/builds/` convention (AP already uses `a4/builds/ap/{patched,bench-isread}/`). The cargo dir (`workspace/output/target`) is **scratch**; the moment a build finishes, archive to a unique **read-only** path whose key includes the **variant** (so clean and isread of the same commit+guest do NOT collide):
  ```
  a4/builds/sweep/<commit_label>_<variant>__<guest_slug>/
      risc0-host            # chmod 0444 — a stray cargo build lands in scratch, not here
      fingerprint.json      # G10 fields (incl. planted_bug, isread_scope) + guest_src.sha256 + ts
  ```
  e.g. `28e53771_clean__g0_baseline/`, `28e53771_clean__g1_ecall/`. The dispatcher launches **from the archived path**, never from `workspace/output/target/release`.

### 1.2 DETECT — FULL-fingerprint assertion before every run (G11)
The G10 emission already exists (`host/src/main.rs:45`, `A4_INSPECT_FINGERPRINT=1` → `<a4_fingerprint>{…}</a4_fingerprint>` with `risc0_head_sha`, `load_rs2_present`, **`planted_bug`**, `isread_scope`, `instrumentation_hash`, `guest_image_id`). B1 builds the **assertion**:
- Each build script sets the compile-time env **from the actual worktree** — `A4_LOAD_RS2_PRESENT` from `grep -c 'fn load_rs2'` (un-spoofable behavioral invariant), `A4_PLANTED_BUG` set only by the AP build, `A4_RISC0_HEAD_SHA` from `git rev-parse`, plus `RISC0_GUEST_ID`. The fingerprint **cannot lie.**
- The dispatcher, before every batch, asserts the **FULL intended set**, not a subset: for Track B / sweep → **`load_rs2_present==1` AND `planted_bug=="none"` AND `instrumentation_hash==expected` AND `guest_image_id==intended`.** Any mismatch → **hard abort.** (`planted_bug=="none"` is the field that distinguishes clean from isread — the one my draft missed.)
- **Positive test of the guard (a B1 gate):** point a sweep slot at the **existing `a4/builds/ap/bench-isread/risc0-host`** (`load_rs2=1, planted_bug=isread`) and confirm the dispatcher **aborts** — this is the exact case a `load_rs2`-only guard would wrongly admit, so it is the test that proves the `planted_bug` check works (not just a `load_rs2=0` stub).

### 1.3 AUDIT — fingerprint in every DB row (G11)
Every run writes its asserted fingerprint — `risc0_head_sha`, `load_rs2_present`, **`planted_bug`**, `instrumentation_hash`, `guest_image_id`, `guest_slug` — into a row of its `run.db` (a `build_provenance` table or `campaign_params.extra_json`). Post-hoc, any DB is *provably* the intended clean-patched build + intended guest — no run trusted on faith (New_Master L14). *(Note: the historical D2.H campaign DBs predate the fingerprint mechanism and record no commit — the D2.H baseline is pinned from git history (`28e53771`, pre-`6556e8d7`), and B1.3 re-establishes it under the new fingerprinted flow.)*

**Why this is "100% certain", not just careful — and why worktrees alone aren't enough (answering Ivan's "wouldn't that solve everything?"):** the clean-baseline + worktree move solves the **source** layer (no in-place mutation — the biggest, scariest hazard, and the one AP triggers today). But it does NOT alone stop a *built* binary being deployed to the wrong run-slot. The full guarantee needs all three layers: §1.1 makes a cross-variant source overwrite physically impossible (separate worktrees; read-only variant-keyed archives); §1.2 makes a wrong-binary run impossible to *launch* (the FULL-fingerprint guard — incl. `planted_bug` — aborts first, on un-spoofable source-derived invariants); §1.3 makes one impossible to *hide*. Worktrees-from-clean-baseline **+** the 3-layer fingerprint scheme together = 100%; worktrees alone ≈ 80% (the dangerous 80%, but not all). Track A's symmetric obligations (vuln: assert `load_rs2=0`; isread: assert `planted_bug=isread` + positive bug repro, per A1/AP/G12) mirror this; B1 owns the clean-patched/sweep side and the shared guard code.

### 1.4 The `a4/` CODE layer — a fourth isolation rule (Ivan-raised, 2026-06-23)
The worktree split isolates the *circuit/binary*, but `a4/` (Python/dispatch/analysis/guest source) is in the **shared `/root/arguzz` repo** (branch `cloud2`). If two tracks edit the **same** `a4/` file, they collide — silently altering each other's tooling. **RULE (best practice):** **Track B owns all its modifiable dispatch/analysis/guest code under `a4/runs/iv_pos_9/sweep/`, and NEVER edits a shared `a4/` module in place** — it either imports a stable guest-agnostic module read-only, or **copies it into `sweep/` and edits the copy** ("recreate and keep in our workspace"). Track A keeps its code in *its* own files (`a4/scripts/build_ap_*`, `ap_isread_patch.py`, its race dirs). Genuinely-shared, parameterized, write-once infra (the fingerprint guard `a4/pos/fingerprint_guard.py`; the uniquely-named `build_sweep_binary.sh`) is used read-only by both — neither forks it. This makes `a4/`-level cross-track contamination impossible by construction, and the fingerprint guard (§1.2) is the backstop even for a dispatch mix-up. Full statement + layout: `a4/runs/iv_pos_9/sweep/README.md`.

---

## 2. Batches

### B1.1 — Provenance & isolation infrastructure *(do FIRST; protects all three variants)*
**Build:** (a) **worktree split from the pinned clean baseline `28e53771`** — a clean Track-B worktree, plus migrate AP to `workspace/risc0-isread/` and the race to `workspace/risc0-vuln-98387806/`, so **no variant mutates the shared tree in place** (coordinate with the active AP/Track-A driver — §5); (b) `build_sweep_binary.sh <guest_slug>` that builds on the clean worktree, sets the source-derived fingerprint env (`A4_LOAD_RS2_PRESENT` from grep, `A4_PLANTED_BUG=none`, head SHA, guest id), and archives to **read-only** `a4/builds/sweep/28e53771_clean__<guest_slug>/` (binary + `fingerprint.json` + `guest_src.sha256`); (c) the dispatcher **FULL-fingerprint assertion** (§1.2 — incl. `planted_bug=="none"`) + **DB recording** (§1.3), wired into `prepare_bundle.sh` / the chain dispatcher.
**Gate (G10/G11):** the guard **aborts** when pointed at the existing `a4/builds/ap/bench-isread/risc0-host` (`load_rs2=1, planted_bug=isread`) — the case a `load_rs2`-only guard would wrongly admit — **and** at a `load_rs2=0` stub; a correct clean-patched binary passes and writes its full fingerprint to the DB; two different-guest clean binaries archive to distinct read-only paths and report distinct `guest_image_id`.

### B1.2 — Guest-aware dispatch + analysis parameterization *(COPY into `sweep/`, do NOT edit shared modules in place — §1.4)*
**Build (Track-B-owned copies under `a4/runs/iv_pos_9/sweep/`, never in-place edits of the shared `iv_pos_8` modules):**
- `sweep/generate_sweep_manifests.py` — a Track-B **copy** of `generate_d2f_manifests.py`, parameterized: takes a **guest spec** `{slug, host_bin_path, guest_args}` (replacing the hardcoded `GUEST_ARGS:34` / `HOST_BIN:36`); run-id becomes `pos_iv_pos_9_b_<guest_slug>_<variant>_seed<seed>_n<n>`. The shared original is left untouched (Track A may use it).
- per-guest host path is passed via the guest spec (no edit to `triage_at_scale.py`'s shared default; import its functions read-only).
- analysis: copy only what must change (`d2h_lib`'s hardcoded prod dirs/run-names; `territory.py`'s hardcoded `V5_ECALL_MRET_SIGNATURE` loc set) into `sweep/`; **reuse the guest-agnostic metric/triage CORE read-only** (import, don't fork). Outputs land in `a4/runs/iv_pos_9/sweep/<guest_slug>/`.
**Reuse (no change needed):** per-guest `A4_INSPECT` arm-universe regeneration is already automatic (`semantic_arm_universe.py` rebuilds `classify_zones` + arms from *that guest's* trace; empty arms auto-prune — New_Master §"per-guest inspection is automatic"); D2.G/D2.H loc/CGC/triage derive from the DB and are guest-agnostic.
**Gate:** a dry-run manifest for 2 guests × 4 variants emits guest-slugged run-ids + correct per-guest host paths; the analysis stack runs against a guest_slug arg with no hardcoded `sha2`/prod-dir references.

### B1.3 — Re-validate the baseline guest (G0) through the new flow *(regression anchor)*
**Build:** rebuild the **existing** baseline guest (the CircIL metamorphic diff guest, `--in1 5 --in4 10`) via `build_sweep_binary.sh g0_baseline` → archived/fingerprinted; run a small smoke (4 variants × 2 seeds × N=2000) through the guest-aware dispatcher.
**Gate:** the fingerprint asserts patched + the correct `guest_image_id`; the per-guest metrics/CGC/territory **reproduce the D2.H reference shape** for G0 (loc ≈ baseline, the Case-B / orthogonality signals consistent) — i.e. the parameterization did not change results on the known guest. This is the safety check that B1.2 is behavior-preserving before any *new* guest is trusted.

### B1.4 — First focused guest: G1 (ECALL/control-heavy)
**Why this guest first:** Pro §2.2 + D2.H both flag **control/decode (`inst_control`) as A4's strongest, most guest-sensitive family** (Hybrid's A4-dilution missed rare A4-only control locs). The ECALL/control guest is the cleanest test of whether A4's local-control edge is enduring or a baseline-guest artifact — and it's the priority new guest.
**Build:** (a) guest source per Pro §2.2 (repeated `env::read`/`env::commit`, branches around commits, conditional early exits, enough user/kernel crossings to populate ECALL-adjacent zones) + matching host `Args` (input-ABI re-sync, New_Master gap); (b) **extend the zone classifier** — `zone_classifier.py` today classifies `pre_ecall`/`post_ecall` but **never** `pre_mret`/`post_mret`/`pre_halt`/`post_halt` (all collapse under `major=7`) and doesn't bucket paging cycles (New_Master gap). Extend the **Python** classifier (decode the instruction word from `--trace`) and/or add `A4_INSPECT` tags in witgen — **not a new C++ binary**; (c) `build_sweep_binary.sh g1_ecall` → archived/fingerprinted.
**Gate:** G1 builds patched + fingerprinted; `A4_INSPECT` shows the ECALL/control zones are **populated** (non-empty, unlike on G0 where they're rare); a 4-variant × 2-seed × N=2000 smoke produces guest-tagged DBs with sensible per-guest loc/CGC/territory; the new MRET/halt zones classify (validated against a hand-decoded sample of the trace).

---

## 3. Deliverables
- `workspace/binaries/patched_6556e8d7__{g0_baseline,g1_ecall}/` (read-only binaries + fingerprints).
- `build_sweep_binary.sh`, the dispatcher fingerprint-assertion + DB-recording, the worktree split.
- Guest-parameterized `generate_d2f_manifests.py` / analysis stack; `a4/runs/iv_pos_9/sweep/<guest_slug>/` outputs.
- G1 ECALL guest source + host Args + the extended zone classifier.
- A short `B1_REPORT.md`: the isolation scheme as-built + the G10/G11 guard test result + the G0 regression check + the G1 smoke.

## 4. Subsequent specs (outline only — written later, one at a time)
- **B2 — build G2 (memory-stress + branch) & G3 (accelerator/Poseidon/BigInt) + Stage-1 screening sweep** (4 guests × 4 variants × 3 seeds × N=5000, patched-fingerprint-asserted). Down-select the 2 most informative guests (load-bearing for feasibility — New_Master compute-reality).
- **B3 — Stage-2 thesis sweep** on the 2 selected guests (≥10 seeds, N=10000) + **cross-guest aggregation** (per-guest two-panel curves + the cross-guest rank/coverage heatmap, Pro §2.3) + rank-stability of the Case-B / local-A4 / global-Arguzz orthogonality.

## 5. Risks / immediate actions
- **🔴 IMMEDIATE #1 — the in-place hazard is LIVE NOW (not future).** `build_ap_binaries.sh` already mutates the shared `workspace/risc0-modified` tree in place (applies `ap_isread_patch.py`, builds, copies out). The tree is git-clean *this moment* only because the build reverts afterward — but every AP build is a contamination window, and if a Track-B build races it (or AP leaves it half-applied) the sweep silently runs on a holed circuit. **Action: move ALL three variants to their own worktrees from the pinned clean baseline `28e53771`, and forbid in-place mutation of the shared tree by ANYONE (AP + race, not just race).** Coordinate with the AP/Track-A driver **who is actively building right now** — Composer has started (contrary to the "before Composer starts" framing); the worktree split must be sequenced with its current work, not assumed pre-start.
- **🔴 IMMEDIATE #2 — capture the clean baseline before it's lost.** B1.3's clean-G0 regression anchor must be built from the `28e53771` worktree **independent of** AP's in-place patching. Do the worktree split + capture the clean baseline first; if AP's IsRead hole is applied (or half-applied) to the shared tree when B1.3 runs, the anchor is silently corrupted.
- **Guest input-ABI re-sync is per-guest hand work** (`env::read` ↔ host `Args`) — a build won't link if mismatched, but a *silent* arg-order swap could mis-feed inputs; the `guest_src.sha256` + a per-guest smoke (B1.4 gate) catch it.
- **Don't over-trust the baseline as "validated pipeline" for exotic guests** — G3 (accelerator/Poseidon) may activate families (and currently-dead A4 paging/cycle kinds) the baseline never exercised; B1 only proves the flow on G0+G1, B2 stress-tests it.
- **Compute contention with Track A** on POS — B1 is cheap (smoke); schedule the B2/B3 campaigns around the race's node usage.
