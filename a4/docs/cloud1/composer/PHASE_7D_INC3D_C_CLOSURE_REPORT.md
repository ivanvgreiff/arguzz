# Phase 7D · Inc 3d · Phase C — B7 Race Closure Report

**Status:** SKELETON — fill tables marked `<TBD>` after Composer's Phase C
dispatches complete (path_a1_octobb, path_a2, b5_default, b5_rayon1).
**Date authored:** 2026-06-12 (skeleton)
**Author:** Opus
**Inputs (when filled):**
- `a4/audits/audit_output/inc3d/c_path_a1/` (already collected)
- `a4/audits/audit_output/inc3d/c_path_a1_octobb_closure/` (after dispatch #1)
- `a4/audits/audit_output/inc3d/c_path_a2_closure/` (after dispatch #2)
- `a4/audits/audit_output/inc3d/c_b5_default_closure/` (after dispatch #3)
- `a4/audits/audit_output/inc3d/c_b5_rayon1_closure/` (after dispatch #4)
- Composer's running report in `PHASE_7D_INC3D_C_PATH_A_COMPOSER_REPORT.md`

---

## 1. Background (1-paragraph recap)

Phase 7D Inc 3 B7 (seed reproducibility) flagged that paired runs of the
same mutation on the same node could produce 1–5 differing touch-coverage
bits per 50-mutation campaign. Inc 3b (rigid pair re-runs) ruled out
campaign-level confounders. Inc 3c (SPREAD across 4 nodes with verbose
hooks) clustered every observed divergence on a single constraint context:
**`FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)` major=9
minor=5** (Poseidon2 sub-cycle). Inc 3d Phase B (B1/B2/B3/B4 host
instrumentation) confirmed the racy context is structurally prior to
witgen — i.e., in the Rust executor's preflight phase — and ruled out the
memory-record path. Phase C (this report) provides the closing argument
via two mutually-corroborating angles.

## 2. Hypothesis under test

**H1 (parallelism causes race):** The preflight phase uses Rayon for
parallel iteration over cycles. The order in which parallel workers
write to the touch-bitmap for `FieldToWord:291` is nondeterministic;
serializing the worker pool (`RAYON_NUM_THREADS=1`) eliminates the
divergence.

**H2 (preflight state diverges):** With B5 instrumentation, the per-field
FNV-1a aggregate hashes of `PreflightCycle` data will differ between A/B
pair-mates of the same mutation when default parallelism is used, and be
identical when `RAYON_NUM_THREADS=1` is used.

H1 closure = path_a1 + path_a1_octobb (5/5 pairs, 0 ΔT flips).
H2 closure = b5_default vs b5_rayon1 (head-to-head per-field hash diff).

## 3. The four dispatches

### 3.1 Dispatch #1 — `path_a1_octobb`

Completes the missing octorand-β pair from the prior path_a1 run (4/5 pairs
done with 0 ΔT flips; this dispatch finishes the 5th).

| Metric | Value |
|---|---|
| Bundle | B P1 (`632094ef…`) |
| Nodes | octorand (single node) |
| Mutations | 50 |
| ΔT flips on octobB pair | `<TBD>` |
| Pairs complete in A1 + this | 5 / 5 |
| Wall time | `<TBD>` |

**Pass condition:** 0 ΔT flips on octobB pair.

### 3.2 Dispatch #2 — `path_a2` (scorched-earth single-thread)

`RAYON_NUM_THREADS=1` + `RISC0_THREADS=1` + `OMP_NUM_THREADS=1`. Rules out
residual parallelism inside RISC0 internals or OpenMP-spawned threads.

| Metric | Value |
|---|---|
| Bundle | B P1 (`632094ef…`) |
| Nodes | octorand + opulous + meld + flare (SPREAD) |
| Pairs | 5 (α-octo, β-octo, opulous, meld, flare) |
| ΔT flips per pair | α=`<TBD>` β=`<TBD>` opulous=`<TBD>` meld=`<TBD>` flare=`<TBD>` |
| Total ΔT flips | `<TBD>` / 200 |
| Wall time | `<TBD>` |

**Pass condition:** 0/200 ΔT flips.

### 3.3 Dispatch #3 — `b5_default` (B5 fingerprint, default parallelism)

Default Rayon parallelism. Captures race in action with full preflight
fingerprinting. Per-field aggregate hashes emitted before witgen.

| Metric | Value |
|---|---|
| Bundle | B5 (`1bd8e9ec…`) |
| Nodes | octorand + opulous + meld + flare (SPREAD) |
| Pairs | 5 |
| ΔT flips per pair | `<TBD>` |
| Pairs with any `a4_preflight_*` aggregate hash diff | `<TBD>` / 5 |
| Wall time | `<TBD>` (~30 min expected, NO RAYON=1) |

**Pass condition:** at least one observed race signal — either ΔT flip OR
preflight-hash diff between paired runs. This confirms the race
reproduces under B5 instrumentation (instrumentation overhead does not
mask the race).

### 3.4 Dispatch #4 — `b5_rayon1` (B5 fingerprint, RAYON=1)

`RAYON_NUM_THREADS=1` + B5 fingerprint. The decisive head-to-head test.

| Metric | Value |
|---|---|
| Bundle | B5 (`1bd8e9ec…`) |
| Nodes | octorand + opulous + meld + flare (SPREAD) |
| Pairs | 5 |
| ΔT flips per pair | `<TBD>` |
| Pairs with any `a4_preflight_*` aggregate hash diff | `<TBD>` / 5 |
| Wall time | `<TBD>` (~108 min expected, RAYON=1) |

**Pass condition:** **0/200 ΔT flips AND zero diff in any
`a4_preflight_*` aggregate hash across pairs.**

## 4. Per-field preflight-hash comparison (b5_default vs b5_rayon1)

Filled from the `<a4_preflight_fp …/>` tags emitted at the start of each
campaign (one per mutation). For each pair (A vs B), compare the
emitted aggregate hashes field-by-field.

### 4.1 `b5_default` (race present, default parallelism)

| Pair | state | pc | mmm | uc | txnIdx | pagingIdx | bigintIdx | dc0 | dc1 |
|---|---|---|---|---|---|---|---|---|---|
| octorand-α | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |
| octorand-β | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |
| opulous | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |
| meld | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |
| flare | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |

(Each cell: `OK` = A == B; `DIFF(<field name>)` = A != B at this field)

### 4.2 `b5_rayon1` (race suppressed by RAYON=1)

| Pair | state | pc | mmm | uc | txnIdx | pagingIdx | bigintIdx | dc0 | dc1 |
|---|---|---|---|---|---|---|---|---|---|
| octorand-α | `<TBD>` | … | … | … | … | … | … | … | … |
| octorand-β | … | … | … | … | … | … | … | … | … |
| opulous | … | … | … | … | … | … | … | … | … |
| meld | … | … | … | … | … | … | … | … | … |
| flare | … | … | … | … | … | … | … | … | … |

**Expected outcome (H2 confirmation):** `b5_default` shows DIFF on at least
one field for at least one pair; `b5_rayon1` shows all OK.

The diverging field tells us *which preflight state changes nondeterministically* under parallel
Rayon scheduling. Most likely candidates (based on Phase B findings):
`dc0` (diffCount[0]) or `txnIdx` — these are touched by Poseidon2 cycles.

## 5. Per-cell targeted hashes (b5_default, userCycle 3920–3940)

If the race is in the userCycle 3920–3940 region (Poseidon2-heavy), B5
also emits per-cell hashes. For each pair under `b5_default`, list the
diverging cells.

| Pair | userCycle | Diverging field | A hash | B hash |
|---|---|---|---|---|
| `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` | `<TBD>` |
| … | … | … | … | … |

## 6. Verdict

> **<TBD — fill after all 4 dispatches land>**
>
> Template:
>
> ```
> The B7 race is CLOSED.
>
> Root cause: Rayon-parallel execution within the executor's preflight
> phase produces nondeterministic ordering of writes to the touch
> bitmap at `FieldToWord(zirgen/circuit/rv32im/v2/dsl/inst_p2.zir:291)`
> major=9 minor=5 (Poseidon2 sub-cycle). The diverging preflight field
> is <FIELD NAME from §4.1>.
>
> Mitigation: set `RAYON_NUM_THREADS=1` in the host environment. Cost:
> ~4x runtime per campaign (verified in path_a1/a2/b5_rayon1 measurements).
>
> Alternative disposition: accept the race for fuzzing campaigns where
> the cost matters, since the race is a touch-coverage measurement
> artifact (not a soundness bug — the racy bit is in WHICH constraint
> was credited as "touched", not in whether constraints pass/fail).
> ```

## 7. Implications for B7 and Inc 3

- **B7 gate verdict:** CLOSED (with the above mitigation OR with the
  documented disposition). Update `PHASE_7D_INC3_REPORT.md` Inc 3 status
  table.
- **No effect on B1, B2, B4.** Those gates remain as previously reported.
- **Touch-coverage statistics in future fuzzing campaigns:** be aware that
  with default parallelism, touch coverage on Poseidon2 cycles is
  noise-prone by ~1–5 bits per 50 mutations. For statistical reporting,
  either run with `RAYON_NUM_THREADS=1` or report touch coverage as
  "±5 bits noise floor" in the methodology section.

## 8. Reproducer

A minimal reproducer is built into the dispatcher itself:

```bash
# On coinbase, after bundle + calendar setup:
source /srv/testbed/pos/cli/venv3/bin/activate
export INC3D_C_BUNDLE_BP1=~/INC3D_PHASE_C_BUNDLE.tar.gz
export INC3D_C_BUNDLE_B5=~/INC3D_PHASE_C_B5_BUNDLE.tar.gz
cd ~/arguzz

# Reproduces the race (race present):
MODE=b5_default SPREAD=1 INC3D_C_RUN_TAG=reproducer \
  bash a4/pos/run_inc3d_phase_c.sh

# Demonstrates the fix (race absent + hashes identical):
MODE=b5_rayon1 SPREAD=1 INC3D_C_RUN_TAG=reproducer \
  bash a4/pos/run_inc3d_phase_c.sh
```

## 9. Cross-references

- B1 disposition: `PHASE_7D_INC3D_B1_DISPOSITION.md`
- Inc 3 final report: `PHASE_7D_INC3_FINAL_REPORT.md`
- Phase B (B1/B2/B3 instrumentation): `PHASE_7D_INC3D_B_COMPOSER_REPORT.md`
- Phase B (B4 mem fingerprint): `PHASE_7D_INC3D_B2_COMPOSER_REPORT.md`
- Phase C (Path A1 first pass): `PHASE_7D_INC3D_C_PATH_A_COMPOSER_REPORT.md`
- Working closure handoff: `PHASE_7D_INC3D_C_CLOSURE_HANDOFF.md`
