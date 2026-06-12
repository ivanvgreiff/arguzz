# Incident — WSL working-tree wipe, Jun 12 2026

## What happened

Between **12:30 and 12:42 UTC-4** on Jun 12 2026, **82 tracked files** in
`/root/arguzz/` and **5 files in the `workspace/risc0-modified` submodule**
disappeared from the working tree. The pattern was surgical: every file that
was *tracked* in the B4 commit (`4112808`) was deleted; every *untracked* file
was preserved.

The user reports a "computer crash + shut off" during the gap.

## Affected paths

- `a4/audits/` (all)
- `a4/standalone/` (all — the entire fuzzer)
- `a4/cloud/` (all)
- `a4/core/` (all, including `executor.py`)
- `a4/pos/` (all tracked files, including `prepare_bundle.sh`,
  `run_campaign_pos.sh`, `dispatch_pos.py`, `collect_inc3d_results.sh`)
- `a4/tools/`
- `workspace/output/host/Cargo.toml`
- `.gitignore`
- submodule: `risc0/circuit/rv32im-sys/kernels/cxx/{ffi.cpp,steps.cpp,witgen.h}`,
  `risc0/circuit/rv32im/src/prove/{hal/mod.rs,witgen/mod.rs}`

## What survived

- All untracked Composer reports in `a4/docs/cloud1/composer/` (these were
  on disk because `a4/docs/` was being silently `.gitignore`d — they were
  never in git but happened not to be deleted).
- All POS result DBs in `a4/audits/audit_output/inc3d/c_path_a1/` (untracked
  campaign output).
- All files outside the affected paths (e.g. `thesis_side_experiments/`
  modifications, `workspace/output/target/release/risc0-host` binary).

## What was permanently lost

- **B1/B2/B3/B4/B5 patches to the risc0-modified submodule source.** These were
  applied to the working tree but never committed in the submodule (the
  submodule HEAD was at `ebd64e43`, an upstream commit, with no Phase B/C
  commits). The patches were ~600 lines of C++ instrumentation across `ffi.cpp`
  and `steps.cpp`. They survive ONLY as compiled binaries:
  - `/root/arguzz_backups/risc0-host.FIXED.bin` (B P1, sha `632094ef…`)
  - `/root/arguzz_backups/risc0-host.B5.1bd8e9ec` (B5, sha `1bd8e9ec…`)
- **In-flight Opus docs** (Phase C):
  - `PHASE_7D_INC3D_C_PLAN.md`
  - `PHASE_7D_INC3D_C_PATH_A_HANDOFF.md`
  - `PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md`
  - `PHASE_7D_INC3D_C_PATH_A1_OPUS_ANALYSIS.md`
  - `PHASE_7D_INC3D_B2_OPUS_ANALYSIS.md`
  All were in `a4/docs/cloud1/composer/` and never tracked (gitignored).
  Reconstructable from conversation transcripts but not 1:1.

## What was recovered

- Tracked main-repo files: `git restore` from HEAD (`4112808`) brought back
  all 82 deleted files.
- Phase C script edits: re-applied to the restored files based on the
  cross-checked reference copies inside the
  `a4_campaign_41128084f473.BP1.tar.gz` bundle (which was built at 01:20
  before the wipe and contains the dirty-overlay copy of all Phase C edits).
  Diff vs BP1 reference is empty or cosmetic only.
- `run_inc3d_phase_c.sh`: recreated as the **refined 6-mode** version (adds
  `path_a1_octobb`, `b5_default`, `b5_rayon1`, `INC3D_C_RUN_TAG`) that
  superseded BP1's 4-mode version.
- `PHASE_7D_INC3D_C_CLOSURE_HANDOFF.md`: rewritten from conversation state.

## Root cause hypothesis

**WSL2 hard-crash + ext4 journal anomaly is the most likely explanation.** A
9-minute cargo build had completed minutes earlier, producing heavy VHDX I/O.
Windows-side VHDX maintenance combined with a sudden host shutdown can in
rare cases cause filesystem-level inconsistencies. No git command in the
reflog explains the deletions, and no `rm` is in bash history.

This is **not proven** — but no alternative explanation fits the evidence.

## Preventive measures going forward

1. **Commit checkpoints aggressively.** Phase work should be committed after
   every meaningful script edit or every 30 minutes, NOT batched at "end of
   phase".
2. **`a4/docs/` is now tracked.** The .gitignore rules `a4/docs/*` and
   `a4/docs` have been removed. Do NOT re-add them. Use targeted ignores
   (e.g. `a4/docs/audit_output/`) if specific subdirs need to be excluded.
3. **Backup critical binaries to `~/arguzz_backups/`** as soon as they're
   built. The B5 binary is the only artifact carrying the lost source
   patches; without the backup we would have nothing.
4. **Submodule patches must be committed in the submodule** before they're
   built. A `cd workspace/risc0-modified && git commit -am 'WIP: BN patch'`
   is cheap insurance.
5. **Consider `wsl --shutdown` between heavy build cycles** to give the VHDX
   a clean state.

## Timeline

| Time (UTC-4) | Event |
|---|---|
| 01:20 | BP1 bundle built (snapshot of Phase C edits in dirty overlay) |
| 12:19 | B5 host binary build completes (`/workspace/output/target/release/risc0-host`, sha `1bd8e9ec`) |
| 12:30 | User runs `prepare_bundle.sh`, hits SHA mismatch error (files still present) |
| 12:33 | Working-tree wipe occurs (deduced from `a4/pos/` directory mtime) |
| 12:42 | User notices `prepare_bundle.sh` missing |
| 12:43–13:00 | Recovery: restore tracked files, re-apply Phase C edits, recreate dispatcher + closure handoff, backup B5 binary, rebuild bundle |
| 13:03 | First recovery commit pushed (`41dc02d`) — scripts only |
| 13:11 | Discovered `.gitignore` was silently ignoring all `a4/docs/` for the entire project; fixed |
| 13:1X | This commit: docs + .gitignore fix + this incident report |
