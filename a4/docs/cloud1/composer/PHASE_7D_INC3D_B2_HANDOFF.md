# Phase 7d Inc 3d Phase B2 — Composer handoff

**Goal:** Final root-cause instrumentation. Phase B1+B2+B3 proved the race is real and identified its visible symptom (FTW291@9,5 extra context on flare P1 mut 30). Phase B2 (B4 patch) adds memory-record fingerprinting to pinpoint the exact cycle where memory operations first diverge between paired runs.

**Status:** Opus has applied the B4 patch to `arguzz/b7-race-instrumentation`, updated `executor.py`, `dispatch_pos.py`, `run_campaign_pos.sh`, written the new dispatcher `run_inc3d_phase_b2.sh`, and updated the collector. **Ready for build + dispatch.**

---

## What's new

| Component | Change |
|-----------|--------|
| `ffi.cpp` | Added B4 patch: emits `<a4_mem_total_hash records="N" hash="…"/>` and `<a4_mem_cycle_hash cycle="N" count="K" hash="…"/>` per phase when `A4_MEM_FINGERPRINT=1` |
| `a4/core/executor.py` | Regex extended to capture the new tags; new `passthrough_mem` gate |
| `a4/pos/dispatch_pos.py` | `JobSpec` extended with `mem_fingerprint: bool`; mapped to `A4_MEM_FINGERPRINT=1` pos var |
| `a4/pos/run_campaign_pos.sh` | Reads `A4_MEM_FINGERPRINT` pos var, exports if `=1` |
| `a4/pos/run_inc3d_phase_b2.sh` | NEW — single-pass dispatcher; same SPREAD plan, drops verbose/FTW trace |
| `a4/pos/collect_inc3d_results.sh` | `PASS=b2` path support |

Full patch spec in `PHASE_7D_INC3D_B2_PATCH_SPEC.md`.

---

## Steps for you to do (in order)

### 1. User rebuilds the host (~5–10 min on WSL2)

This is NOT your job — Ivan will do it locally on WSL2 (single source file `ffi.cpp` changed, no `steps.cpp` rebuild).

After build, Ivan reports the new SHA. You'll need it for the bundle.

### 2. You prep `INC3D_B2_BUNDLE`

```bash
cd ~/arguzz
git pull   # gets the latest a4/core/executor.py, a4/pos/* changes, and B2 patch spec
bash a4/pos/prepare_bundle.sh --host workspace/output/target/release/risc0-host --allow-dirty
mv bundles/a4_campaign_*.tar.gz ~/INC3D_B2_BUNDLE.tar.gz
# verify
tar -xOf ~/INC3D_B2_BUNDLE.tar.gz a4_campaign/bundle.json | grep host_sha256
sha256sum ~/INC3D_B2_BUNDLE.tar.gz
```

Confirm the host SHA matches what Ivan reported.

Upload to Coinbase:
```bash
scp ~/INC3D_B2_BUNDLE.tar.gz coinbase:~/INC3D_B2_BUNDLE.tar.gz
```

### 3. Pre-reservation

Same as Inc 3c/3d: ONE multi-node calendar entry (`octorand + opulous + meld + flare`) for ~45 min. Confirm with Ivan when ready.

### 4. Dispatch (one focused pass)

```bash
ssh coinbase
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz && git pull   # get the new dispatcher script

export INC3D_B2_BUNDLE=~/INC3D_B2_BUNDLE.tar.gz
bash a4/pos/run_inc3d_phase_b2.sh 2>&1 | tee ~/inc3d_b2_dispatch.log
```

This runs the SAME SPREAD plan as Inc 3c/3d Phase B (4 parallel nodes, 5 pairs total, 50 muts each), but with `A4_MEM_FINGERPRINT=1`. **No verbose, no FTW trace** — keeps logs small.

Expected wall time: ~25 min (similar to Pass 2). Per-log size: ~50–80 MB (mem_cycle_hash tags are numerous but each is small).

### 5. Collect

From WSL or coinbase:
```bash
INC3D_PASS=b2 bash ~/arguzz/a4/pos/collect_inc3d_results.sh
```

Artifacts land in `a4/audits/audit_output/inc3d/b2/`.

### 6. Hand back to Opus

Once collection is done, post back to Ivan with:
- New bundle SHA confirmation
- Per-pair log path summary
- Any dispatch anomalies (none expected)

Opus will compute the per-cycle hash diff between paired logs and produce the root-cause report.

---

## What I expect to find (so Composer can sanity-check)

After diff:
- **All pairs:** `<a4_mem_total_hash>` differs A vs B (already proven via residue)
- **For each pair, the FIRST cycle where `cycle_hash` differs** tells us when divergence starts
- Cross-reference with the cycle ↔ userCycle mapping in Pass 1 logs:
  - If divergence starts mid-Poseidon2 hash operation at the racy userCycle → upstream witgen race
  - If divergence is pervasive across all cycles → executor scheduling race
  - If divergence is concentrated at user-mode instruction cycles → memory subsystem race (most likely)

The data will definitively answer "where in the host does A and B start to differ?" — which is the LAST unknown.

---

## What to NOT change

- Same SPREAD layout as Inc 3c/3d (don't reduce node count even though we could — keeps comparison valid)
- Same seed (999 / 1000 / 1001 per node)
- Same n=50 mutations
- Same `--allocation-duration 0` (claim pre-existing reservation)

If POS is shorthanded and you can only get a subset of nodes, run **flare alone** (it's the one that raced in Phase B Pass 1). Flare alone is enough to confirm the result.

---

## Total estimated turnaround

- User build: 5–10 min
- You bundle + scp: 5 min
- You reserve + dispatch + wait: 30 min
- Collect: 5 min
- Opus analysis + report: 30 min

**Total ~1.5 hours wall clock.** Then B7 is fully closed and we can move to Phase 8.
