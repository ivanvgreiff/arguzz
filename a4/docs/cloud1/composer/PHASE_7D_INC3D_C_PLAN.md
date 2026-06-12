# Phase 7d Inc 3d — Phase C: Maximal B7 closure plan

**Date**: 2026-06-12
**Goal**: Settle B7 with 100% certainty, identify the exact zkVM bug if present, build a reproducer suitable for upstream submission.
**Trigger**: B4 (memory fingerprint) localized the race source to "upstream of witgen". This phase confirms it experimentally and pinpoints the exact field.

---

## Where we are

From `PHASE_7D_INC3D_B2_OPUS_ANALYSIS.md` (B4 result):
- Race is real, POS-only, ~1–2% rate per paired mutation.
- Race manifests at user-phase Poseidon2, userCycle 3929 (per Inc 3d B P1 B2 trace).
- Race is **NOT** in `extern_memoryDelta` records (B4 confirmed memory-record determinism in the user phase).
- By elimination: race is in **PreflightCycle data** built by the Rust executor before witgen.

## What we need to do

Three sequential experiments:

| Phase | What | Bundle | Wall time | Confirms |
|---|---|---|---|---|
| **C-A** | POS dispatch with `RAYON_NUM_THREADS=1` (then if needed: with `--num-threads 1` for `thread::scope`-equivalents) | existing **B P1** host (no rebuild) | 30 min × 1 or 2 passes | Whether disabling Rust parallelism eliminates the race |
| **C-B5** | New zkVM patch: hash `PreflightTrace.{cycles[*], txns[*], bigintBytes[*]}` at witgen entry; POS dispatch with `A4_PREFLIGHT_FINGERPRINT=1` | new B5 host (rebuild ~1 hr) | 30 min dispatch | Whether preflight data diverges A vs B; which field; at which cycle |
| **C-B6** | Build a single-binary, single-node reproducer that triggers the race ≥50% of the time without the fuzzer | none (script + harness) | 1–2 hr | Reproducible test case for upstream RISC Zero bug report |

C-A and C-B5 can run in parallel on POS (different bundles, different reservations).

---

## Phase C-A — Parallelism elimination test

**Hypothesis**: The race is caused by `rayon::into_par_iter` and/or `thread::scope` in the Rust executor's preflight phase. Setting `RAYON_NUM_THREADS=1` forces sequential preflight; if the race vanishes, that confirms parallelism is the cause.

**No rebuild required.** Same B P1 host (sha `632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`). Just add env vars at dispatch.

**Dispatch plan**: same SPREAD as B Pass 1 (5 pairs, 50 muts each = 250 paired comparisons), with these env additions:

- Pass 1: `RAYON_NUM_THREADS=1` only
- Pass 2 (only if Pass 1 still shows race): `RAYON_NUM_THREADS=1` AND `RISC0_THREADS=1` (covers thread::scope where applicable) AND `OMP_NUM_THREADS=1`

**Pass / fail criteria**:

- **Pass A1 → 0/250 racy ⇒ Rust parallelism is the cause. STOP. Document and move to Phase 8 with `RAYON_NUM_THREADS=1` as a launcher default.**
- Pass A1 → ≥1/250 racy and Pass A2 → 0/250 racy ⇒ thread::scope is the additional culprit. STOP. Document both env vars as Phase 8 default.
- Both passes show race ⇒ Rust parallelism is NOT the (sole) cause. Move to C-B5 results to localize further.

Composer handoff: `PHASE_7D_INC3D_C_PATH_A_HANDOFF.md`.

---

## Phase C-B5 — Preflight fingerprinting

**Patch**: instrument `risc0_circuit_rv32im_cpu_witgen` (entry of witgen FFI). Before any witgen work, hash:
- `preflight->cycles[i]` for `i in 0..lastCycle`: per-field FNV-1a aggregates (state, pc, major/minor/mode, userCycle, txnIdx, pagingIdx, bigintIdx, diffCount[0], diffCount[1]).
- `preflight->txns[i]` for `i in 0..txnsLen`: per-field aggregates (addr, cycle, word, prevCycle, prevWord).
- `preflight->bigintBytes`: single hash.
- Per-cell hashes for cycles where `userCycle in [3920, 3940]` (the known race region from B P1 B2 trace).
- Opt-in wide mode (`A4_PREFLIGHT_FINGERPRINT_WIDE=1`): per-cell hashes for ALL cycles where `userCycle > 0`.

**Gate env**: `A4_PREFLIGHT_FINGERPRINT=1`.

**What the data tells us**:
- If any aggregate hash differs A vs B → preflight has a divergent field → bug confirmed in Rust executor. The per-field aggregates name **which field** (state vs pc vs txnIdx etc.).
- The per-cell hashes for userCycle ~3920–3940 localize **which cycle index** first diverges.
- If aggregate hashes match A vs B → race is downstream of preflight (in witgen lookup tables, accum, or elsewhere) and we'd need a B6 patch covering those.

**Composer handoff**: `PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md`.

---

## Phase C-B6 — Reproducer construction

After C-A and C-B5 results:

- If C-A passes: write a one-page summary doc (`A4_REPRODUCER_PARALLELISM.md`) showing:
  1. Same binary + same mutation on POS multi-core EPYC, run twice → ~1–2% chance of touch bitmap divergence
  2. Same binary + same mutation + `RAYON_NUM_THREADS=1` → 0% divergence
  3. Recommendation: set this env in Phase 8 launcher
  
- If C-B5 localizes a specific field: write a self-contained reproducer (`A4_REPRODUCER_PREFLIGHT_<FIELD>.md`) showing:
  1. Minimal RISC-V program (probably similar to flare mutation 30 input) that triggers the racy preflight cycle
  2. Run N times on POS multi-core, count divergences
  3. Diff PreflightCycle's `<FIELD>` between runs to show the racy data
  4. Link to `risc0/circuit/rv32im/src/execute/preflight.rs` (or wherever the field is written) with annotation of the racy line(s)
  5. If determinable: which RISC Zero version was first affected
  
  Output: a 1-pager + a runnable shell script. Suitable for issue submission to risc0/risc0.

---

## Coordinate timeline

```
T+0      User reviews this plan, approves
T+5min   User sends Path A handoff to Composer (or runs themselves on coinbase)
T+5min   User rebuilds B5 host locally (~1 hr WSL build)
         | (in parallel)
T+10min  Composer dispatches Path A on POS (needs reservation)
T+40min  Path A results: collect, audit
T+1h     B5 host built; bundle prepared
T+1h     Composer dispatches B5 on POS (needs reservation)
T+1h30m  B5 results: collect, audit
T+2h     Opus writes consolidated closure report
T+3h     Reproducer doc (depending on outcomes)
T+4h     Phase 8 launch authorized
```

Realistic with reservation slot acquisition: T+6 hours wall time, mostly waiting on POS.

---

## Decision rules

After Path A + B5:
- **If Path A eliminates race AND B5 confirms preflight divergence in the parallelism-only configuration**: clean story — Rust parallelism in preflight causes racy struct writes. Mitigation = `RAYON_NUM_THREADS=1`. Move to Phase 8.
- **If Path A eliminates race but B5 with `RAYON_NUM_THREADS=1` shows NO preflight divergence**: parallelism affects something else (maybe in-place mutation of an `Rc` or shared cache). The fix is still `RAYON_NUM_THREADS=1`; the localization stays open as a future deep-dive.
- **If Path A does NOT eliminate race**: parallelism is not the (sole) cause. B5 results are critical. If B5 still shows preflight divergence, the race is in a non-threaded part of the executor (cache, allocator, BIOS-derived rand). If B5 shows NO preflight divergence, the race is downstream (lookup tables, accum). In either case, write follow-up patch.

---

## Living checklist

- [ ] User: review and approve plan
- [ ] User: send Path A handoff to Composer  
- [ ] User: start B5 host rebuild on WSL
- [ ] Composer: reserve POS slot for Path A
- [ ] Composer: dispatch Path A Pass 1 (`RAYON_NUM_THREADS=1`)
- [ ] Composer: collect Path A Pass 1 results
- [ ] Opus: analyze Path A Pass 1; decide if Pass 2 needed
- [ ] Composer: (conditional) dispatch + collect Path A Pass 2
- [ ] User: scp B5 bundle to coinbase
- [ ] Composer: reserve POS slot for B5 (can overlap Path A reservation if multi-node alloc)
- [ ] Composer: dispatch B5
- [ ] Composer: collect B5 results
- [ ] Opus: analyze B5; identify divergent field/cycle
- [ ] Opus: write `PHASE_7D_INC3D_C_CLOSURE_REPORT.md`
- [ ] Opus: write reproducer doc (form depends on outcomes)
- [ ] User: decide Phase 8 launch posture
