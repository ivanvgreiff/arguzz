# Phase 7D · Inc 3 — Final Report (CLOSURE)

**Status:** FILLED 2026-06-12 — Inc 3 CLOSED.
**Date authored:** 2026-06-12 (skeleton); filled 2026-06-12.
**Author:** Opus
**Inputs:**
- `PHASE_7D_INC3_REPORT.md` (Composer's mid-Inc-3 report)
- `PHASE_7D_INC3D_B1_DISPOSITION.md` (B1 closure)
- `PHASE_7D_INC3D_C_CLOSURE_REPORT.md` (B7 closure — filled)
- `RACE_FINDING_AND_OPEN_QUESTIONS.md` (Pro-facing standalone race writeup)
- B2/B4 verdicts unchanged from Composer's mid-Inc-3 report

---

## 1. Executive summary

| Gate | Verdict | Source |
|---|---|---|
| B1 — Hook fidelity | **PASS WITH DOCUMENTED EXCLUSIONS** (963/963 effective after E1/G2 exclusions; 37/1000 raw failures all pre-existing dispositioned) | `PHASE_7D_INC3D_B1_DISPOSITION.md` |
| B2 — Multi-cycle replay | **PASS** (universe queries; D40 disposition enforced) | `PHASE_7D_INC3_REPORT.md` §B2 |
| B4 — Bandit→DB traceability | **PASS** (250/250) | `PHASE_7D_INC3_REPORT.md` §B4 |
| B7 — Seed reproducibility | **CLOSED with mitigation + known mechanism gap** — race in proof / witgen path produces ~0.70% noise floor in touch coverage under default parallelism; `RAYON_NUM_THREADS=1` reduces to ~0.14% (5×). Honest gap: there is a second C++ `poolstl` parallelism source we cannot isolate without re-recovering wiped source. | `PHASE_7D_INC3D_C_CLOSURE_REPORT.md`, `RACE_FINDING_AND_OPEN_QUESTIONS.md` (revised 2026-06-13) |

**Inc 3 verdict: CLOSED.** Phase 7d Architecture Audit is complete pending Inc 4 (if Pro confirms it's needed) and Inc 5 (Pro consult). Phase 8 large-scale fuzzing can launch as soon as Pro signs off on the race-noise treatment in §3.4.

## 2. What Inc 3 set out to audit

Inc 3 audited the fuzzing infrastructure for four invariants:

| Audit | Question being asked | What "PASS" means |
|---|---|---|
| **B1** | Are mutation hook tags faithful — i.e., does the host's per-mutation receipt match the original DB capture on replay? | Each captured mutation can be replayed deterministically and produces an identical receipt (modulo documented multi-cycle / ECALL exceptions) |
| **B2** | Are multi-cycle steps and the D40 disposition handled correctly in mutation generation? | No invalid arms reach the universe; multi-cycle steps either resolve unambiguously or are dropped per D40 |
| **B4** | Does every bandit decision map cleanly to a corresponding DB row, and vice versa? | Bandit traces and DB mutations are 1-to-1; no orphan rows or untraced bandit pulls |
| **B7** | Same seed, same DB schema, same code → are paired runs reproducible? | Paired DBs are byte-identical modulo timestamps and the documented D42 nondet address allowlist |

## 3. Headline findings

### 3.1 B1 — Hook Fidelity (PASS-w-exclusions)

Strict verifier reported 37/1000 failures (5/5 variants raw FAIL). All
37 failures fit pre-existing dispositions (Inc 1 E1 review queue +
PHASE_7_PROGRESS.md INSTR_TYPE_MOD multi-cycle disposition):

- 22× `INSTR_TYPE_MOD` step=0 boot Auipc multi-cycle ambiguity
- 8× `MEM_VAL_MOD` step=3929 ECALL last_step
- 7× other ECALL-adjacent (`major=8`) cycles

After applying documented exclusions: **963/963 = 100% effective pass rate.**

ZERO failures involve `major=9` (Poseidon2) — i.e., B1 does not surface
the B7 race, confirming the two gates probe independent failure modes.

### 3.2 B2 — Multi-cycle Replay (PASS)

D40 disposition (option (b): drop multi-cycle steps for major-filter
kinds) was applied to the V5 arm universe. 4 D40-dropped arms confirmed
absent. `b1_multicycle_violations = 0` after B1 closure.

### 3.3 B4 — Bandit→DB Traceability (PASS)

250/250 bandit decisions traced cleanly to DB rows on POS run
`2026-06-11_05-45-54_378654` (campaign `pos_audit_b4`). No orphans.
`--debug-bandit-trace` JSONL captured per mutation; bandit_step
post-retry resolution fix validated.

### 3.4 B7 — Seed Reproducibility (CLOSED)

This was the headline rabbithole of Inc 3. Initial POS run (Jun 11)
flagged reward-key divergences on V1/V3/V4 (`mutation_rewards` differ;
mutations + bandit_decisions 0 diff). Investigation arc:

| Sub-phase | What it did | Outcome |
|---|---|---|
| Inc 3b | Rigid pair re-runs on the same node | Race reproduces; not campaign-level confounder |
| Inc 3c | SPREAD plan + verbose touch tags | All divergences cluster on `FieldToWord(inst_p2.zir:291)` major=9 minor=5 (Poseidon2) |
| Inc 3d Phase A3 | Local-reproducer attempts (sequential, pair-concurrent, different mutations) | Race does not reproduce on WSL2 (0 divergences in 70+ independent obs); POS-only |
| Inc 3d Phase B (B1/B2/B3) | Verbose-tag self-id + FTW291 targeted logging + per-phase counter | Confirmed race is in a code path that runs every execution (mutation-independent); same race appears in non-bitmap verbose-tag stream |
| Inc 3d Phase B4 | Memory transaction fingerprinting | 24-cycle pervasive divergence found, classified as aggregate-ordering noise; did not localize race |
| Inc 3d Phase C Path A | `RAYON_NUM_THREADS=1` (and belt-and-suspenders `RISC0_THREADS=1` + `OMP_NUM_THREADS=1`) interventional test | path_a1 (RAYON=1, BP1): 0/200 flips, all 7 DB tables byte-identical A vs B; path_a2 (all three): 0/250 flips |
| Inc 3d Phase C Path B5 | Per-field FNV-1a fingerprint of preflight state, with vs without RAYON=1 | b5_default: 3/250 flips; b5_rayon1: 1/250 (non-binary). **Preflight aggregate FP bit-identical A vs B in 250/250 muts × both modes** — race is downstream of preflight state |

**Root cause (REVISED 2026-06-13 after second-pass binary audit):**
Non-deterministic intermediate state computation during constraint /
polynomial evaluation under parallel scheduling, producing a 1-bit toggle
in the `lowIsZero` branch decision that gates whether the FTW291 EQZ
check is evaluated. The race is a **measurement artifact** in touch-coverage
tracking — it does NOT affect proof validity, constraint failures, or
final witness state (all of which are bit-identical A vs B even when ΔT
flips). It only affects which constraints are recorded as "touched" by a
given mutation.

**Honesty correction (2026-06-13)**: prior versions of this report claimed
the race localized to a single Rust `into_par_iter` in `cpu.rs:180`. A
second-pass audit revealed (a) `risc0-zkp` HAL has ~15 additional Rayon
parallel sites and (b) the compiled binary contains a SECOND parallelism
system — C++ `poolstl` with `std::thread` — used inside `cpu_witgen` and
`cpu_accum`, NOT controlled by `RAYON_NUM_THREADS`. We have not yet
isolated which of these contributes to the residual leak under
`RAYON=1`. Full mechanism breakdown in `RACE_FINDING_AND_OPEN_QUESTIONS.md`
§4 and §8 (revised 2026-06-13).

**Race rate by intervention** (combined across all investigations, recomputed
2026-06-13 from raw DB `delta_T` flip data):

| Configuration | Sample | `ΔT` Flips | Per-mut rate |
|---|---|---|---|
| Default parallelism (BP1+B5 binaries, p1+p2+b2+b5_default) | 1000 paired muts | 7 | ~0.70% |
| `RAYON_NUM_THREADS=1` (path_a1 + path_a2 + b5_rayon1) | 700 paired muts | 1 | ~0.14% |
| **Reduction ratio** | | | **~5×** |

The earlier "1.7% / 12×" figures conflated `delta_T` flips with verbose-tag
block divergences (different metric, noisier denominator) and used a smaller,
biased sample. The corrected numbers are smaller in absolute terms (0.70% vs
1.7%) and the reduction ratio is more modest (5× vs 12×). The qualitative
conclusion (RAYON=1 reduces but doesn't eliminate the race) is unchanged.

**Mitigation (chosen, see D47 in `CLOUD1_DECISIONS_FOR_PRO_R2.md`):**
**USER OVERRIDE 2026-06-13** — Phase 8 will launch with default parallelism
for speed (4× faster). Race + Pro questions will be presented to Pro after
results. If Pro flags noise as material, re-run with `RAYON=1`.

**Residual leak** (1/700 with RAYON=1, on B5 binary mut 33: ΔT 34↔35):
four candidate explanations (B5-instrumentation timing perturbation; C++
poolstl as second parallelism source; statistical noise; Rayon lazy-init
timing). Cannot distinguish at current N. See Pro Q2 in
`RACE_FINDING_AND_OPEN_QUESTIONS.md` for whether this is worth chasing.

## 4. What Inc 3 did NOT audit (deferred / out-of-scope)

- Bandit convergence rate / sample efficiency (not a fidelity audit; possibly Inc 4)
- Coverage metric semantic accuracy (separate audit if needed; possibly Inc 4)
- End-to-end large-run scale stress (Phase 8 territory)
- Soundness of the underlying RISC0 zkVM (out of arguzz scope; we report the Rayon race as a touch-coverage artifact, not a zkVM bug)
- Mechanism localization beyond `eval_check` (would require Phase B6: per-cell Poseidon2 fingerprinting; not done because mitigation is sufficient)
- Source-code-level fix for the Rayon race (upstream RISC0 territory; could file an issue)

These items, if needed, belong in Inc 4 or later.

## 5. Open items going forward

| Item | Owner | Priority |
|---|---|---|
| **Phase 8 launches with default parallelism for speed** (USER OVERRIDE 2026-06-13). Race + notebook + `RACE_FINDING_AND_OPEN_QUESTIONS.md` + G7 in DECISIONS doc presented to Pro WITH Phase 8 results. If Pro flags noise as material, re-run with `RAYON=1`. | User → Pro | **In-flight; Pro consult comes after Phase 8 results** |
| Restore `risc0-modified` submodule SOURCE (`ffi.cpp`, `steps.cpp`, `witgen.h`, `hal/mod.rs`, `witgen/mod.rs`) from June 3 patch + B1/B2/B3/B5 patch specs | Opus + user | **DEFERRED unless Pro recommends revisiting the race phenomenon** (binary works; source is only needed if we revisit). See "Master plan note — race-related artifacts" §8 below. |
| **Git-track the `risc0-modified` submodule's A4 instrumentation branch** so the wipe cannot recur | User | **HIGH — recommended ASAP** (the WSL wipe was preventable; uncommitted working-tree changes were the root cause of the loss). See §8 for procedure. |
| Inc 4 scope definition (currently undefined; per user 2026-06-13: definitions exist in wiped markdowns to be recovered; do not redefine from scratch) | User + Opus | High — to be opened AFTER current race investigation closes |
| Inc 5 scope definition (Pro consult round) | User + Pro | Medium — can run in parallel with Phase 8 |
| Phase 8 methodology section noting the ±1 touch-bit Poseidon2 noise floor (~0.7% under default parallelism; ~0.14% under RAYON=1) | Opus + Pro | **Required before Phase 8 publication** |
| Optionally: harden `B1_hook_fidelity.py` to apply exclusion filter natively | Composer/Opus | Low — current disposition note is sufficient |
| Optionally: file an upstream RISC0 issue about the parallel-execution `delta_T` race | User | Low — mitigation works; ecosystem-nice-to-have |

---

## 8. Master plan note — race-related artifacts (added 2026-06-13)

**Purpose:** If Pro reviews `RACE_FINDING_AND_OPEN_QUESTIONS.md` and concludes the noise floor IS material (recommending we revisit), we will need:
1. The full B1/B2/B3/B5 patch source (currently wiped from working tree; recoverable from `risc0-modified.CURRENT.patch` + the Composer patch-spec docs).
2. All Phase 7d Inc 3 experimental data (currently intact in `a4/audits/audit_output/inc3d/` — preserve indefinitely).
3. All Phase 7d Inc 3 analysis (this doc + `RACE_FINDING_AND_OPEN_QUESTIONS.md` + `PHASE_7D_INC3D_C_CLOSURE_REPORT.md` — preserve indefinitely).

**Decision (2026-06-13):**
- **Don't proactively rebuild B1/B2/B3/B5 patches now** — saves 1-2 days of WSL build work that isn't on the critical path.
- **DO preserve all existing experimental data and analysis** for future revisit. The `a4/audits/audit_output/inc3d/` directory tree (~50 DBs + ~50 logs + analysis JSONs) is small (<200 MB) and stays in the repo permanently. Patch specs in `a4/docs/cloud1/composer/PHASE_7D_INC3D_*_PATCH_SPEC.md` stay in the repo permanently.
- **DO start git-tracking `workspace/risc0-modified`'s A4 instrumentation branch ASAP** — see procedure below — so any future patch work doesn't get lost.
- **If Pro recommends revisit**: re-apply patches from June 3 base + spec docs (~2 hours), rebuild (~50-80 minutes), re-dispatch (~30 minutes per campaign), reload data into existing notebook templates.

**Git-tracking procedure for `risc0-modified` submodule** (recommended for user to execute soon):
```bash
cd /root/arguzz/workspace/risc0-modified
# Create a working branch off the current upstream tag
git checkout -b arguzz/a4-instrumentation-MAIN
# Add all currently-deleted-but-needed files via patch recovery
git apply /root/arguzz_backups/risc0-modified.CURRENT.patch  # Jun 3 base
# (Then re-apply B1/B2/B3/B5 patches incrementally as per their spec docs)
git add -A
git commit -m "A4 instrumentation: B1+B2+B3+B5 patches (recovered post-wipe)"
# DO NOT push to upstream risc0/risc0 — this is private branch only
git remote add arguzz-private https://github.com/<user>/risc0-modified  # one-time
git push -u arguzz-private arguzz/a4-instrumentation-MAIN
```
Once this is done, the wipe scenario becomes recoverable from git regardless of WSL filesystem state.

## 6. Artifacts (paths)

| Artifact | Path |
|---|---|
| B1 verifier shards | `a4/audits/audit_output/b1_verify_shards/B1_V{1..5}.json` |
| B1 DBs (5 variants × 200 mut) | `a4/audits/audit_output/inc3_b1/` (or coinbase symlinks) |
| B2 audit output | (see Composer's Inc 3 report) |
| B4 audit output | `a4/audits/audit_output/inc3_b4/` |
| B7 / Inc 3c diffs | `a4/audits/audit_output/inc3c/diffs/` |
| B7 / Inc 3d Phase B (B P1) | `a4/audits/audit_output/inc3d/p{1,2}/` |
| B7 / Inc 3d Phase B (B4 mem fp) | `a4/audits/audit_output/inc3d/b2/` |
| B7 / Inc 3d Phase C | `a4/audits/audit_output/inc3d/c_*/` |
| Recovery commit (post-wipe) | `41dc02d` on `origin/main` |

## 7. Bundles & binaries

| Bundle | host_sha256 | Purpose | Status |
|---|---|---|---|
| BP1 (B-Phase-Patched 1) | `632094ef…` | B1/B2/B3 instrumented host; used for Path A1/A2 | Preserved at `~/arguzz/bundles/a4_campaign_41128084f473.BP1.tar.gz` + coinbase `~/INC3D_PHASE_C_BUNDLE.tar.gz` |
| B5 | `1bd8e9ec…` | Adds preflight FNV-1a fingerprinting | Preserved at `~/arguzz/bundles/a4_campaign_41128084f473.B5.tar.gz` + coinbase `~/INC3D_PHASE_C_B5_BUNDLE.tar.gz` + backup `/root/arguzz_backups/risc0-host.B5.1bd8e9ec` |

**Important caveat — source-code recovery status (updated 2026-06-12 22:30 ET):**
The source-code patches in the `workspace/risc0-modified` submodule were destroyed
during the Jun 12 WSL wipe at 12:33 ET. **The patches were never committed to the
submodule's git history** (its reflog has exactly one entry: the original upstream
clone `ebd64e43`). Recovery state:

| Asset | Status |
|---|---|
| Working binary `1bd8e9ec…` (B5) | ✅ Intact in `workspace/output/target/release/risc0-host` + `/root/arguzz_backups/risc0-host.B5.1bd8e9ec` |
| Working binary `632094ef…` (BP1) | ✅ Inside coinbase bundles + on POS as part of `INC3D_PHASE_C_BUNDLE.tar.gz` |
| Compiled object files (with hooks) | ✅ `workspace/output/target/release/build/risc0-circuit-rv32im-sys-*/out/*.o` (timestamped Jun 12 12:11-12:15, just before the wipe) |
| Submodule source June 3 base patch | ✅ `/root/arguzz_backups/risc0-modified.CURRENT.patch` (5.0 MB, Jun 3 21:37) — recovers all hook files (`ffi.cpp`, `steps.cpp`, `witgen.h`, `hal/mod.rs`, `witgen/mod.rs`) at June 3 state |
| Patch specs for Jun 3 → Jun 12 deltas (B1, B2, B3, B5) | ✅ `a4/docs/cloud1/composer/PHASE_7D_INC3D_B_PATCH_SPEC.md`, `..._B2_PATCH_SPEC.md`, `..._C_PATH_B5_PATCH_SPEC.md` |
| Cursor transcripts | ✅ 6 sessions in `/root/.cursor/projects/root-arguzz/agent-transcripts/` |

**Recovery procedure** (~1-2 hours, not blocking the audit closure):
1. Apply `risc0-modified.CURRENT.patch` to recover Jun 3 base of all A4 hooks.
2. Re-apply B1/B2/B3 patches from `PHASE_7D_INC3D_B_PATCH_SPEC.md` (~50 lines).
3. Re-apply B5 patch from `PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md` (~80 lines).
4. Rebuild and verify host SHA matches the working binary (`1bd8e9ec…` for B5, `632094ef…` for BP1).
5. Commit to `arguzz/b7-race-instrumentation` branch (so this never happens again).

## 8. Sign-off

**Inc 3 is closed.** Inc 4 may proceed once its scope is defined.

`<signature line for user + Pro after review>`
