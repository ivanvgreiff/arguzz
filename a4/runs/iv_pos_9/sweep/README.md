# Track B (multi-guest coverage sweep) — code home + the `a4/` isolation rule

**This directory is Track-B's exclusive workspace for all *modifiable* Python/dispatch/guest code.**
Track A (bug race / AP planted-bug) NEVER edits anything here, and Track B NEVER edits Track A's code.

## Why this exists (the `a4/` contamination hazard — and the rule that prevents it)
The git-worktree split isolates the **circuit/binary** layer (Track B builds only from
`workspace/risc0-clean-28e53771` via `workspace/output-trackb`; the bug-race/AP track patches
`workspace/risc0-modified` in place — they cannot touch each other). **But `a4/` is in the *shared*
`/root/arguzz` repo (branch `cloud2`).** If two tracks edit the *same* `a4/` Python file, they collide
— one track's change silently alters the other's tooling.

**RULE (best practice — confirmed):**
1. **Track B owns all its modifiable dispatch/analysis/guest code HERE** (`a4/runs/iv_pos_9/sweep/`).
2. **Track B NEVER edits a shared `a4/` module in place.** To use shared logic, either
   (a) **import it read-only** (a stable, guest-agnostic module — never modify it), or
   (b) **copy it into this directory and edit the copy** ("recreate and keep in our workspace").
3. Track A's code lives in *its* own places (`a4/scripts/build_ap_*`, `a4/scripts/ap_isread_patch.py`,
   its race dirs). Neither track touches the other's files.

This makes `a4/`-level cross-track contamination impossible by construction (no shared file is edited
by two tracks), the same way the worktree split makes circuit contamination impossible.

## The backstop (defense in depth)
Even if dispatch code ever pointed a run at the wrong binary, the **fingerprint guard**
(`a4/pos/fingerprint_guard.py`) asserts each binary's provenance (`load_rs2_present`, `planted_bug`,
`guest_image_id`) **before every run** and aborts on mismatch — so an `a4/` code mix-up can never
*silently* run the wrong circuit. The guard is shared, parameterized infra (profiles `sweep`/`race`/
`isread`); both tracks use it read-only — neither forks it.

## What lives here (Track-B-owned)
- `guests/<slug>/` — each new guest's `guest_main.rs` + `host_main.rs` + notes (the source the sweep builds).
- `generate_sweep_manifests.py` (B1.2) — Track-B copy of the manifest generator, guest-parameterized
  (the shared `a4/pos/generate_d2f_manifests.py` is **not** edited; we copy + adapt here).
- Track-B analysis adapters (B1.2/B3) — copies of any `d2h_lib`/`territory` logic Track B must change.
- Track-B sweep outputs land under `a4/runs/iv_pos_9/sweep/<guest_slug>/`.

## What is shared (read-only — do NOT fork per track)
- `a4/pos/fingerprint_guard.py` (provenance guard — parameterized, both tracks).
- `a4/scripts/build_sweep_binary.sh` (Track-B build; uniquely named, non-colliding with `build_ap_binaries.sh`).
- The stable, guest-agnostic metric/triage CORE (imported, never edited): we reuse the math, copy only
  what we must parameterize.

## ⚠️ PROCESS isolation (4th layer — added after a cross-track incident, 2026-06-23)
Both tracks build with the **identical** command `cargo build --release -p risc0-host` (from different
worktrees). So **`pkill -f "cargo build..."` from EITHER track kills BOTH** — this happened once
(the other track's broad pkill collateral-killed a Track-B build). RULE:
- **Never** kill builds by the shared command. Target **only your own** by workspace path
  (`pkill -f "output-trackb"` for Track B; `…seamb`/your-worktree for the other) or by **PID**
  (Track-B build chain writes its PID to `a4/builds/sweep/.trackb_build.pid`).
- **Resource courtesy:** the box is 8-core/11 GB; two concurrent heavy risc0 C++ builds can OOM
  (and the OOM killer is itself a collateral-kill). The Track-B build chain is **memory-gated**
  (waits for ≥5 GB free before each build) + `nice -n 10` + `CARGO_BUILD_JOBS=4`. Prefer to
  **stagger** the two tracks' builds when possible.

## Build/source layout (recap)
- Source (Track B): `workspace/risc0-clean-28e53771` @ `28e53771` (clean D2.H baseline, branch `arguzz/track-b-multiguest`).
- Build workspace: `workspace/output-trackb` (own `target/`; all Cargo paths → the clean worktree).
- Archived binaries: `a4/builds/sweep/28e53771_clean__<guest_slug>/risc0-host` (read-only) + `fingerprint.json`.
