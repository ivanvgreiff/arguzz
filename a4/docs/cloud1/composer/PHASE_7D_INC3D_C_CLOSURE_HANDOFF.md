# Phase 7D · Inc 3d · Phase C — Closure Campaign Handoff

**Status:** ready for Composer to execute.
**Goal:** achieve **100% certainty** on the race condition root cause via two mutually-corroborating angles (Path A1/A2 = parallelism elimination test; B5 = preflight-data fingerprinting) and produce a reproducer-ready signal.

> **Note (Jun 12, 12:42 UTC-4):** This document was recreated from
> conversation state after a working-tree wipe deleted the original.
> Composer should treat this version as authoritative. Other companion
> docs (`PLAN`, `PATH_A_HANDOFF`, `PATH_B5_PATCH_SPEC`, the Opus
> analyses) are being recreated in parallel and are nice-to-have for
> historical context only — the procedural content lives here.

---

## 1. Context (1-paragraph recap)

Inc 3b/3c established: paired runs of the same mutation on the same node produce
differing constraint-touch coverage and occasionally differing ΔT (timeout)
flips. All measurement-artifact hypotheses (verbose perturbation, log-line
ordering, schema noise) were ruled out in Phase A. Phase B (B1/B2/B3/B4)
instrumented the host's verbose tagger, FieldToWord:291 counter, and memory
record fingerprint; conclusion was that the diverging signal is **structurally
prior to witgen** — i.e., the executor's Rust preflight phase is what drifts
between paired runs. **Path A1** (RAYON_NUM_THREADS=1, partial 4/5 pairs)
produced **0/200 ΔT flips** on every complete pair including the previously
racy `opulous` and `flare`. Strong signal but not formal 5/5.

Phase C closes the loop with four dispatches.

## 2. What you have on coinbase (artifacts)

| Artifact | Path | host_sha256 | Purpose |
|---|---|---|---|
| B P1 bundle (no B5 fp) | `~/INC3D_PHASE_C_BUNDLE.tar.gz` | `632094ef…` | Path A1 / A1-octobB / A2 |
| B5 bundle (preflight fp) | `~/INC3D_PHASE_C_B5_BUNDLE.tar.gz` | `1bd8e9ec…` | b5_default / b5_rayon1 |

Both bundles contain the Phase C launcher knobs in `run_campaign_pos.sh`
(`A4_PREFLIGHT_FINGERPRINT`, `A4_RAYON_THREADS`, `A4_RISC0_THREADS`,
`A4_OMP_THREADS`).

If either bundle is missing or has a wrong SHA, **stop and ping Opus** — do
not improvise.

## 3. The four dispatches

Each dispatch follows the same envelope:

```bash
source /srv/testbed/pos/cli/venv3/bin/activate
export INC3D_C_BUNDLE_BP1=~/INC3D_PHASE_C_BUNDLE.tar.gz
export INC3D_C_BUNDLE_B5=~/INC3D_PHASE_C_B5_BUNDLE.tar.gz
cd ~/arguzz
```

Then pick the dispatch.

### 3.1 Dispatch #1 — `path_a1_octobb` (complete the missing pair from prior A1)

**Calendar requirement:** single-node reservation on `octorand` (~7 min).
**Bundle:** B P1.

```bash
MODE=path_a1_octobb \
INC3D_C_RUN_TAG=closure \
  bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_path_a1_octobb_closure.log
```

After completion, copy the result into the path_a1 directory so the analysis
treats it as the missing octobB:

```bash
INC3D_PASS=c_path_a1_octobb_closure bash a4/pos/collect_inc3d_results.sh
cp a4/audits/audit_output/inc3d/c_path_a1_octobb_closure/pos_inc3d_phase_c_path_a1_octobb_closure_zoned_seed999_n50_octobB.* \
   a4/audits/audit_output/inc3d/c_path_a1/ 2>/dev/null || true
```

(If the file-naming differs slightly because RUN_TAG appended `_closure`, just
ensure both A and B halves of the octorand-β pair land in `c_path_a1/` so a
diff script can pair them.)

### 3.2 Dispatch #2 — `path_a2` (scorched-earth single-thread)

**Calendar requirement:** SPREAD plan, ~30 min, 4 nodes
(octorand + opulous + meld + flare).
**Bundle:** B P1.

```bash
MODE=path_a2 SPREAD=1 \
INC3D_C_RUN_TAG=closure \
  bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_path_a2_closure.log

INC3D_PASS=c_path_a2_closure bash a4/pos/collect_inc3d_results.sh
```

Purpose: rule out residual parallelism from RISC0 internals + OpenMP. If
path_a1 already gave 0/200 and path_a2 also gives 0/200, the parallelism
hypothesis is locked.

### 3.3 Dispatch #3 — `b5_default` (B5 preflight fingerprint, default parallelism)

**Calendar requirement:** SPREAD plan, ~30 min, 4 nodes.
**Bundle:** B5.

```bash
MODE=b5_default SPREAD=1 \
INC3D_C_RUN_TAG=closure \
  bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_b5_default_closure.log

INC3D_PASS=c_b5_default_closure bash a4/pos/collect_inc3d_results.sh
```

Purpose: with the race present (default parallelism), capture which preflight
field-aggregate hash differs between A/B runs. The targeted per-cell hashes
(userCycle 3920–3940) should localize the exact diverging cell(s).

### 3.4 Dispatch #4 — `b5_rayon1` (B5 preflight fingerprint, RAYON=1)

**Calendar requirement:** SPREAD plan, ~30 min, 4 nodes.
**Bundle:** B5.

```bash
MODE=b5_rayon1 SPREAD=1 \
INC3D_C_RUN_TAG=closure \
  bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_b5_rayon1_closure.log

INC3D_PASS=c_b5_rayon1_closure bash a4/pos/collect_inc3d_results.sh
```

Purpose: head-to-head against `b5_default`. If `b5_rayon1` shows all preflight
aggregate hashes identical between A/B paired runs while `b5_default` shows at
least one aggregate hash differing, **that is the mechanistic closure** —
parallelism causes preflight to drift; serializing parallelism eliminates the
drift; and we know which preflight field carries the drift.

## 4. Calendar choreography (matters!)

For the three SPREAD dispatches you should follow the Inc 3c phase δ pattern
that already works:

1. Reserve **one** multi-node calendar entry covering octorand + opulous +
   meld + flare (~30 min each). It is fine to reserve all three SPREAD
   campaigns back-to-back as separate entries — they share the same node set
   so reservations of equal length can be queued.
2. The dispatcher uses `--allocation-duration 0`, which claims the
   *pre-existing* reservation rather than creating a new one. **Do not** omit
   the calendar pre-reservation; without it the dispatcher will refuse to
   launch.

For Dispatch #1 (`path_a1_octobb`) you only need a single-node reservation on
`octorand` (~7 min). Wait for `bav` to release octorand if it is currently
allocated.

## 5. Acceptance criteria for "100% certainty"

| Run | Pass condition |
|---|---|
| #1 path_a1_octobb | octorand-β pair complete (5/5 total A1 pairs); 0 ΔT flips |
| #2 path_a2 | 0/200 ΔT flips across all 4 complete pairs |
| #3 b5_default | At least 1 race observation (ΔT flip OR per-cell hash diff) — confirms race is reproducible with B5 instrumentation |
| #4 b5_rayon1 | 0/200 ΔT flips AND zero diff in any `a4_preflight_*` aggregate hash across pairs |

If all four conditions hold, we have closure: parallelism in preflight is the
cause; serializing it eliminates both the symptom and the underlying
mechanism, and B5 isolates which preflight field carries the noise.

If #3 produces 0 diffs (race didn't trigger this session), do **not** treat
that as closure — the race is intermittent. Ping Opus to decide whether to
re-roll #3 with more pairs or add octorand variants.

## 6. What to send back to Opus

After all four dispatches complete, post a brief Composer report to
`a4/docs/cloud1/composer/PHASE_7D_INC3D_C_CLOSURE_COMPOSER_REPORT.md`
containing:

- Wall time and exit status per dispatch
- For each MODE: number of ΔT flips per pair, sourced from the DBs
- For `b5_default` vs `b5_rayon1`: per-field comparison table of
  `a4_preflight_fp` aggregate hashes (state, pc, mmm, uc, txnIdx, pagingIdx,
  bigintIdx, dc0, dc1) for each pair (A vs B). Highlight any pair where any
  field hash differs.
- Path A1 octobB pair: ΔT flips.
- A one-line decision suggestion (CLOSED / NEEDS-RERUN / NEEDS-OPUS).

Opus will then write the closure report and reproducer.

## 7. Failure handling

- **Bundle SHA mismatch:** stop, do not proceed. Re-pull bundles or ask
  Opus to rebuild.
- **Dispatcher complains about missing Phase C launcher knobs:** the
  bundle is stale; rebuild with `prepare_bundle.sh --skip-host-sha
  --allow-dirty` and re-scp.
- **Calendar denied:** the campaign relies on a pre-existing reservation;
  re-reserve with the required nodes and retry.
- **POS variable `unknown`:** typically means `set_variables` silently
  no-op'd. Check `/tmp/a4_boot_diag.log` on the failing node; rerun
  dispatch.

---

**Tag this handoff as `Inc 3d Phase C — closure` in any commit message.**
