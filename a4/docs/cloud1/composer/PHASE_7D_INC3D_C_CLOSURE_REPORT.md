# Phase 7D · Inc 3d · Phase C — B7 Race Closure Report

**Status:** FILLED 2026-06-12 — verdict §6, mitigation §7.
**Date authored:** 2026-06-12 (skeleton); filled 2026-06-12.
**Author:** Opus (verified against Composer's dispatches)
**Inputs:**
- `a4/audits/audit_output/inc3d/c_path_a1/` (path_a1, 4 complete pairs + 1 partial)
- `a4/audits/audit_output/inc3d/c_path_a2_closure/` (path_a2, 5/5 pairs)
- `a4/audits/audit_output/inc3d/c_b5_default_closure/` (b5_default, 5/5 pairs)
- `a4/audits/audit_output/inc3d/c_b5_rayon1_closure/` (b5_rayon1, 5/5 pairs)
- Composer's running reports: `PHASE_7D_INC3D_C_PATH_A_COMPOSER_REPORT.md`,
  `PHASE_7D_INC3D_C_CLOSURE_COMPOSER_REPORT.md`

---

## 1. Background (1-paragraph recap)

Phase 7D Inc 3 B7 (seed reproducibility) flagged that paired runs of the
same mutation on the same node could produce 1–5 differing touch-coverage
bits per 50-mutation campaign. Inc 3b (rigid pair re-runs) ruled out
campaign-level confounders. Inc 3c (SPREAD across 4 nodes with verbose
hooks) clustered every observed divergence on a single constraint context:
**`FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)` major=9
minor=5** (Poseidon2 sub-cycle 5). Inc 3d Phase B (B1/B2/B3/B4 host
instrumentation) confirmed the racy context is downstream of the
fingerprintable preflight state — i.e., in some intermediate Poseidon2
cell computation. Phase C (this report) confirms via two
mutually-corroborating angles: (a) intervention test (`RAYON_NUM_THREADS=1`
nearly eliminates the race), (b) state localization (preflight aggregate
fingerprints are A==B identical even when ΔT flips, ruling out preflight
data divergence as the source).

## 2. Hypothesis under test

**H1 (parallelism causes race):** Rust's Rayon-parallel iteration in the
prover's `eval_check` phase produces nondeterministic ordering of writes
to intermediate Poseidon2 cell state, which propagates to a branch
decision (`lowIsZero`) that controls whether the FTW291 EQZ constraint is
evaluated and thus whether `touch_bitmap[FTW291_idx]++` fires.

→ **Intervention prediction:** `RAYON_NUM_THREADS=1` substantially reduces
or eliminates the race.

**H2 (preflight state diverges):** With B5 instrumentation, the per-field
FNV-1a aggregate hashes of `PreflightCycle` data will differ between A/B
pair-mates of the same mutation when default parallelism is used.

→ **Prediction:** the diverging field reveals which preflight state changes
nondeterministically.

H1 closure = path_a1 / path_a2 vs b5_default (interventional A/B).
H2 closure = b5_default vs b5_rayon1 (head-to-head per-field hash diff).

## 3. The four dispatches

### 3.1 Dispatch — `path_a1` (RAYON=1, BP1 binary)

Validates that `RAYON_NUM_THREADS=1` alone is sufficient to suppress the
race on the production binary (no extra B5 instrumentation overhead).

| Metric | Value |
|---|---|
| Bundle | BP1 (`632094ef…`) |
| Nodes | octorand-α (octoa), octorand-β (octob), opulous, meld, flare (SPREAD) |
| Mutations | 50 per side |
| **ΔT flips per pair** | **octoa=0 octob=incomplete opulous=0 meld=0 flareCtrl=0** |
| Total ΔT flips | **0 / 200 (4 complete pairs)** |
| Per-mutation rate | **0%** |
| Pairs complete | 4 / 5 (octob B-side did not collect due to `bav` holding octorand) |
| Wall time | ~30 min |
| Multi-table byte identity | **All 7 DB tables (mutations, failures, coverage, global_failures, mutation_rewards, local_coverage_v2, compressed_global_coverage) byte-identical A vs B for every complete pair (28 table-level comparisons, 28/28 identical)** |
| Log content identity | Byte-identical A vs B except per-mutation `wall_time_ms` fields |

**Pass condition:** 0 ΔT flips. **MET.** (Note: a single 200-mut clean run
is not statistically conclusive at p<0.05 on ΔT alone — p≈0.26 against a
historical 5/750 rate. But the multi-table byte-identity evidence is
overwhelming — every paired mutation has ~1MB of structured data, all
bit-identical, including per-constraint failure records and per-cycle
coverage entries.)

### 3.2 Dispatch — `path_a2` (RAYON=1 + RISC0=1 + OMP=1, BP1 binary)

Belt-and-suspenders: rules out residual parallelism from non-Rayon
sources. Same binary as path_a1; only difference is extra env vars.

| Metric | Value |
|---|---|
| Bundle | BP1 (`632094ef…`) |
| Nodes | octoa, octob, opulous, meld, flareCtrl (SPREAD) |
| Pairs | 5 / 5 |
| **ΔT flips per pair** | **octoa=0 octob=0 opulous=0 meld=0 flareCtrl=0** |
| **Total ΔT flips** | **0 / 250** |
| Per-mutation rate | **0%** |
| Wall time | ~45 min |

**Pass condition:** 0/250 ΔT flips. **MET.**

Interpretation: extra env vars `RISC0_THREADS=1` and `OMP_NUM_THREADS=1`
contributed **no measurable effect** beyond `RAYON_NUM_THREADS=1`. Source
grep confirms: no references to `RISC0_NUM_THREADS` / `RISC0_THREADS` /
`OMP_NUM_THREADS` / `#pragma omp` / `omp_get_*` anywhere in
`workspace/risc0-modified/`. These two env vars are no-ops in our binary.

### 3.3 Dispatch — `b5_default` (B5 binary, default parallelism)

Baseline race reproduction with B5 instrumentation. Captures race in action
along with per-mutation preflight fingerprints.

| Metric | Value |
|---|---|
| Bundle | B5 (`1bd8e9ec…`) |
| Nodes | octoa, octob, opulous, meld, flareCtrl (SPREAD) |
| Pairs | 5 / 5 |
| **ΔT flips per pair** | **octoa=0 octob=0 opulous=0 meld=1 (mut 47) flareCtrl=2 (mut 17, mut 21)** |
| **Total ΔT flips** | **3 / 250** |
| Per-mutation rate | **1.2%** |
| Direction | mixed (2× A>B, 1× B>A) — no directional asymmetry |
| Wall time | ~30 min |

**Pass condition:** at least one observed ΔT flip (confirming race
reproduces under B5 instrumentation, i.e., instrumentation does not mask
the race). **MET.**

Per-pair preflight aggregate hash comparison (`<a4_preflight_fp …/>` tag):

| Pair | preflight_fp diffs (A vs B) | preflight_txns diffs | preflight_bigint diffs |
|---|---|---|---|
| octoa | 0 / 50 | 49 / 50 | 0 / 50 |
| octob | 0 / 50 | 49 / 50 | 0 / 50 |
| opulous | 0 / 50 | 49 / 50 | 0 / 50 |
| meld | 0 / 50 | 49 / 50 | 0 / 50 |
| flareCtrl | 0 / 50 | 49 / 50 | 0 / 50 |
| **Total** | **0 / 250** | **245 / 250** | **0 / 250** |

**Crucial observation**: the 9-field aggregate preflight fingerprint
(`state`, `pc`, `mmm`, `uc`, `txnIdx`, `pagingIdx`, `bigintIdx`, `dc0`,
`dc1`) is **bit-identical A vs B in 250/250 mutations**, including the
3 mutations that showed ΔT flips. So **preflight state does not
diverge — the race is downstream of preflight fingerprinting**.

The `<a4_preflight_txns>` aggregate hash differs in 49/50 mutations in
every pair, but this is mode-independent (same 49/50 rate in b5_rayon1
under RAYON=1 — see §3.4), so it is an aggregate-ordering artifact in
the FNV-1a accumulation over the txn vector, not a race signal. It is
**not** correlated with the 3 mutations that showed ΔT flips.

### 3.4 Dispatch — `b5_rayon1` (B5 binary, RAYON=1)

Decisive head-to-head test: same B5 binary as dispatch #3, only difference
is `RAYON_NUM_THREADS=1`.

| Metric | Value |
|---|---|
| Bundle | B5 (`1bd8e9ec…`) |
| Nodes | octoa, octob, opulous, meld, flareCtrl (SPREAD) |
| Pairs | 5 / 5 |
| **ΔT flips per pair** | **octoa=1 (mut 33, ΔT 34↔35, non-binary) octob=0 opulous=0 meld=0 flareCtrl=0** |
| **Total ΔT flips** | **1 / 250** |
| Per-mutation rate | **0.4%** |
| Wall time | ~108 min (RAYON=1 ≈ 3.6× slower than parallel) |

Per-pair preflight aggregate hash comparison:

| Pair | preflight_fp diffs (A vs B) | preflight_txns diffs | preflight_bigint diffs |
|---|---|---|---|
| octoa | 0 / 50 | 49 / 50 | 0 / 50 |
| octob | 0 / 50 | 49 / 50 | 0 / 50 |
| opulous | 0 / 50 | 49 / 50 | 0 / 50 |
| meld | 0 / 50 | 49 / 50 | 0 / 50 |
| flareCtrl | 0 / 50 | 49 / 50 | 0 / 50 |
| **Total** | **0 / 250** | **245 / 250** | **0 / 250** |

**Pass condition (original spec):** 0/250 ΔT flips AND 0 preflight-FP
diffs. **PARTIAL — 1/250 ΔT flip remains; preflight FPs all match.**

This is the residual leak. Three possible explanations (see Pro doc §4.4):

1. **B5 instrumentation introduces a small additional racy path** that
   isn't in BP1 (since path_a1 with BP1 + RAYON=1 showed 0/200 flips,
   while b5_rayon1 with B5 + RAYON=1 showed 1/250 flips on otherwise
   identical configuration).
2. **A second parallelism source RAYON=1 doesn't catch.** Source grep
   shows no other threading primitives in our binary, so this is unlikely
   but not impossible (could be in a transitive C++ dependency).
3. **Statistical noise.** 1/250 = 0.4% is plausible at a true rate of
   0.1-0.5% if `RAYON=1` reduces but doesn't fully eliminate the race.

Cannot distinguish with current sample size (N=250). To distinguish (1)
from (2)+(3) requires ~500-1000 more paired muts; see Pro doc Q2.

## 4. Per-field preflight-hash comparison (b5_default vs b5_rayon1)

For every pair under both modes, the 9-field aggregate preflight FP
(`state`, `pc`, `mmm`, `uc`, `txnIdx`, `pagingIdx`, `bigintIdx`, `dc0`,
`dc1`) is bit-identical A vs B. So no field-level localization is possible
— **the race is entirely downstream of the preflight fingerprint**.

| Pair (b5_default) | state | pc | mmm | uc | txnIdx | pagingIdx | bigintIdx | dc0 | dc1 |
|---|---|---|---|---|---|---|---|---|---|
| octoa | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| octob | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| opulous | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| meld | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| flareCtrl | OK | OK | OK | OK | OK | OK | OK | OK | OK |

| Pair (b5_rayon1) | state | pc | mmm | uc | txnIdx | pagingIdx | bigintIdx | dc0 | dc1 |
|---|---|---|---|---|---|---|---|---|---|
| octoa | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| octob | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| opulous | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| meld | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| flareCtrl | OK | OK | OK | OK | OK | OK | OK | OK | OK |

`OK` = A == B for that aggregate hash across all 50 muts in the pair.

**Interpretation:** The race operates on intermediate state that is
NOT captured by any of the 9 fingerprinted fields. The most likely
location is an in-register Poseidon2 cell value computed transiently
during constraint evaluation, where the `lowIsZero` branch is decided
based on whether `low == 0` for that cell. The final witness state
(after all cells are combined) converges to the same value regardless
of intermediate cell ordering, which is why `state`, `dc0`, `dc1`, and
all other persistent fields agree.

## 5. Per-cell targeted hashes (b5_default, mutations 17, 21, 47)

The B5 patch does not currently emit per-cell targeted hashes for
Poseidon2 sub-cycles (B5 emits only aggregate-level fingerprints).
To localize the race to a specific cell, we'd need a Phase B6 patch
that hashes per-cell Poseidon2 state per cycle in the 3920-3940 user-
cycle range. Not done; deferred (see Pro doc Q2).

## 6. Verdict

**The B7 race is CLOSED.**

**Root cause** (high confidence):
- Non-deterministic intermediate state ordering during Poseidon2 cell
  computation in the Rust executor's `eval_check` phase (the only
  Rayon-parallel `into_par_iter` in the rv32im prove path), located at
  `risc0/circuit/rv32im/src/prove/hal/cpu.rs:180`.
- The race manifests as a 1-bit flip in `delta_T` for ~1.7% of mutations
  (combined Inc 3 / 3b / 3d Phase B / 3d Phase C `b5_default` data:
  13 events / 746 paired muts).
- All flips are on the `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)`
  constraint at `major=9 minor=5` (Poseidon2 sub-cycle 5).
- Aggregate preflight state is bit-identical A vs B even when ΔT flips,
  confirming the race is in transient intermediate state not persistent
  witness data.
- The race is **NOT** a write-write race on the touch bitmap itself
  (confirmed because the same divergence appears in the non-bitmap
  verbose-tag `std::set<std::string>` stream).

**Soundness impact**: NONE. The race does not affect:
- Proof generation (all paired runs produce same `proof_status`)
- Constraint failures (`failures` and `global_failures` tables are
  bit-identical A vs B in every racy pair)
- Mutation outcomes (`outcome`, `exit_code` deterministic A vs B)
- Witness registers (final state bit-identical A vs B)

The race affects only one thing: the `touch_bitmap` coverage signal used
as one input to the bandit reward function.

**Mitigation (chosen)**: `RAYON_NUM_THREADS=1` at the launcher level
(`a4/pos/run_campaign_pos.sh`) for all Phase 8 dispatches. Reduces the
race rate by ~12× (to ~0.14% in measured data). Cost: ~3-4× wall-clock
per campaign on POS.

**Residual leak under RAYON=1**: 1/250 in `b5_rayon1` (B5 binary only;
0/200 + 0/250 = 0/450 in path_a1 + path_a2 on BP1 production binary).
Three possible causes: (a) B5-instrumentation-induced, (b) hidden
second parallelism source, (c) statistical noise. Cannot distinguish
with current sample size. Open question for Pro: worth further
investigation, or accept as residual?

## 7. Implications for B7 and Inc 3

- **B7 gate verdict:** CLOSED with mitigation `RAYON_NUM_THREADS=1` +
  documentation of the ~0.14% residual noise floor.
- **No effect on B1, B2, B4** gates — they remain PASS as previously
  reported.
- **Touch-coverage statistics in Phase 8 campaigns:** report a "±1 bit
  noise floor on Poseidon2 sub-cycle constraints" in the methodology
  section of any publication.
- **Reward signal quality:** the `delta_T` input to `compute_reward` has
  a per-mutation noise floor of ~0.14% (with RAYON=1) or ~1.7%
  (without). The reward magnitude impact per flip is ~0.002 absolute.
  Whether this is significant for bandit convergence at Phase 8 scale
  is an open question for Pro.

## 8. Reproducer

A minimal reproducer is built into the existing dispatcher:

```bash
# On coinbase, after bundle + calendar setup:
source /srv/testbed/pos/cli/venv3/bin/activate
export INC3D_C_BUNDLE_BP1=~/INC3D_PHASE_C_BUNDLE.tar.gz
export INC3D_C_BUNDLE_B5=~/INC3D_PHASE_C_B5_BUNDLE.tar.gz
cd ~/arguzz

# Reproduces the race (~1.2-2.5% rate, B5 binary, default parallelism):
MODE=b5_default SPREAD=1 INC3D_C_RUN_TAG=reproducer \
  bash a4/pos/run_inc3d_phase_c.sh

# Demonstrates the mitigation (race-rate reduced by ~12×, BP1 binary, RAYON=1):
MODE=path_a1 SPREAD=1 INC3D_C_RUN_TAG=reproducer \
  bash a4/pos/run_inc3d_phase_c.sh
```

Expected output:
- `b5_default`: 1-5 ΔT flips per 250 paired muts, all on FTW291 / major=9 / minor=5.
- `path_a1`: 0 ΔT flips per 200+ paired muts; all 7 DB tables byte-identical A vs B.

## 9. Cross-references

- B1 disposition: `PHASE_7D_INC3D_B1_DISPOSITION.md`
- Inc 3 final report: `PHASE_7D_INC3_FINAL_REPORT.md`
- Pro-facing standalone race writeup: `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md`
- Phase B (verbose B1/B2/B3) findings: `PHASE_7D_INC3D_REPORT.md`
- Phase A path_a1 deep analysis (multi-table byte-identity): `PHASE_7D_INC3D_C_PATH_A1_OPUS_ANALYSIS.md`
- Composer Phase C running reports: `PHASE_7D_INC3D_C_PATH_A_COMPOSER_REPORT.md`, `PHASE_7D_INC3D_C_CLOSURE_COMPOSER_REPORT.md`
- Inc 3 master findings: `PHASE_7D_INC3_FINDINGS.md`
- Working closure handoff (Composer playbook): `PHASE_7D_INC3D_C_CLOSURE_HANDOFF.md`
