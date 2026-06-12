# Phase 7d Inc 3d Phase C — Path B5 patch spec + Composer handoff

**Date**: 2026-06-12
**Owner**: Opus → User (build) → Composer (dispatch)
**Goal**: Fingerprint the entire `PreflightTrace` (cycles + txns + bigintBytes) at witgen entry to identify the exact diverging field/cycle if Path A doesn't kill the race (or to confirm the parallelism diagnosis if Path A does).
**Parent plan**: `PHASE_7D_INC3D_C_PLAN.md`
**Branch**: `arguzz/b7-race-instrumentation` (same as B1/B2/B3/B4 patches)

---

## Patch overview

**One file**: `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp`
**One function**: `risc0_circuit_rv32im_cpu_witgen` (entry point, before the `try` block)
**Activation**: env var `A4_PREFLIGHT_FINGERPRINT=1` (or `=...WIDE=1` for full-trace per-cell hashes)

The patch hashes `preflight->{cycles, txns, bigintBytes}` field-by-field. Output is XML-tagged so the executor passthrough re-emits it into the campaign log. **No witgen work happens before the hashing; no allocator pressure inside the loop (FNV-1a is pure arithmetic).**

### Tag schema emitted (per `cpu_witgen` invocation, i.e., per mutation)

```
<a4_preflight_fp cycles="..." state="..." pc="..." mmm="..." uc="..."
    txnIdx="..." pagingIdx="..." bigintIdx="..." dc0="..." dc1="..."/>
<a4_preflight_txns count="..." addr="..." cycle="..." word="..." prevCycle="..." prevWord="..."/>
<a4_preflight_bigint count="..." hash="..."/>
<a4_preflight_cell cycle="..." userCycle="..." pc="..." major="..." minor="..." mode="..." txnIdx="..." dc0="..." dc1="..." hash="..."/>  (one per cycle where 3920 <= userCycle <= 3940, or all cycles if WIDE)
```

### Output size estimate

- Aggregate tags: ~3 lines × 50 muts = 150 lines per log. Negligible.
- Targeted per-cell (userCycle 3920–3940): ~30 cells × 50 muts = 1.5K lines. ~200 KB.
- Wide mode: ~10K cycles × 50 muts = 500K lines. ~75 MB per log. Same magnitude as B4 logs.

Recommend **non-wide first** (cheap, decisive) then **wide** only if non-wide localization is insufficient.

---

## Files changed

The patch is **already applied** in the workspace as of commit-pending. Confirm:

```bash
grep -n "a4_preflight_fp" workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
# expect: line near top of risc0_circuit_rv32im_cpu_witgen
grep -n "a4_preflight" a4/core/executor.py
# expect: 4 matches in _A4_DIAG_LINE_RE + 1 in passthrough loop
grep -n "A4_PREFLIGHT_FINGERPRINT" a4/pos/run_campaign_pos.sh a4/pos/dispatch_pos.py
# expect: 2 matches in run_campaign_pos.sh, 2 matches in dispatch_pos.py
```

If any of these are missing, the patch wasn't fully overlayed — re-run StrReplace.

---

## Step-by-step (User on WSL)

### 1. Verify branch + patch present

```bash
cd /root/arguzz/workspace/risc0-modified
git status   # should show modified risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
git branch --show-current   # should be arguzz/b7-race-instrumentation
grep -c "a4_preflight" risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
# expect: ≥4
```

### 2. Rebuild risc0-host (~50–80 min on WSL)

**Important — wrong path will fail with "no bin target risc0-host":** `risc0-host` is built from `workspace/output/`, NOT `workspace/risc0-modified/`. The modified `ffi.cpp` in `risc0-modified/` is picked up via the `risc0-zkvm` path dependency.

```bash
cd /root/arguzz/workspace/output
# Force C++ kernel clean rebuild (cargo's rerun-if-changed on ffi.cpp is
# technically correct but conservative; this guarantees the new lines land):
cargo clean -p risc0-circuit-rv32im-sys
cargo build --release
sha256sum target/release/risc0-host
# RECORD the new SHA — different from both 625e722e (B4) and 632094ef (B P1).
```

If build fails: check the `auto fnv_mix32_local = [](uint64_t h, uint32_t v)` lambda — older clang versions may complain about the closure type; switching to a free `static inline` function is the fallback. Open the spec source for the alternative.

### 3. Local smoke test (optional but recommended, ~2 min)

```bash
cd /root/arguzz
A4_PREFLIGHT_FINGERPRINT=1 A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 \
    A4_MUTATION_CONFIG='{"kind":"NONE"}' \
    workspace/risc0-modified/target/release/risc0-host \
    --in1 5 --in4 10 2>&1 | grep "a4_preflight" | head -10
```

Expect to see:
- 1 `<a4_preflight_fp cycles="..." state="..." .../>`
- 1 `<a4_preflight_txns count="..." .../>`
- 1 `<a4_preflight_bigint count="..." hash="..."/>`
- ~20 `<a4_preflight_cell ... userCycle="392X" .../>` (for cycles in target window)

Without `A4_PREFLIGHT_FINGERPRINT=1`: 0 lines (zero overhead).

### 4. Build bundle on WSL

```bash
cd /root/arguzz
cp workspace/risc0-modified/target/release/risc0-host /tmp/risc0-host.B5
bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host.B5 --allow-dirty
NEW=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
# Verify bundle has B5 host
tar -xOf "$NEW" a4_campaign/bundle.json | grep host_sha256
# And launcher with Phase C knobs
tar -xOf "$NEW" a4_campaign/repo/a4/pos/run_campaign_pos.sh | grep A4_PREFLIGHT_FINGERPRINT
scp "$NEW" coinbase:~/INC3D_PHASE_C_B5_BUNDLE.tar.gz
```

---

## Step-by-step (Composer on coinbase)

### 5. Pre-reserve POS (web UI)

Same 4-node entry as Path A (`flare + octorand + opulous + meld`), ~45 min. Wait for start_date.

### 6. Dispatch B5 (non-wide first)

```bash
ssh coinbase
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz && git pull
export INC3D_C_BUNDLE=~/INC3D_PHASE_C_B5_BUNDLE.tar.gz

INC3D_C_MODE=b5 SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh \
    2>&1 | tee ~/inc3d_c_b5_dispatch.log
```

Wall: ~30 min. Logs ~5 MB each (aggregate + 30-cycle window).

### 7. Collect

```bash
INC3D_PASS=c_b5 bash a4/pos/collect_inc3d_results.sh
# → a4/audits/audit_output/inc3d/c_b5/
```

### 8. Quick handback summary

```bash
cd ~/arguzz
python3 - <<'PY' > a4/audits/audit_output/inc3d/c_b5/b5_handback.json
import sqlite3, glob, os, re, json
DIR = "a4/audits/audit_output/inc3d/c_b5"
TAG_FP = re.compile(r'<a4_preflight_fp cycles="(\d+)" state="([0-9a-f]+)" pc="([0-9a-f]+)" '
                    r'mmm="([0-9a-f]+)" uc="([0-9a-f]+)" txnIdx="([0-9a-f]+)" '
                    r'pagingIdx="([0-9a-f]+)" bigintIdx="([0-9a-f]+)" '
                    r'dc0="([0-9a-f]+)" dc1="([0-9a-f]+)"/>')
TAG_TXN = re.compile(r'<a4_preflight_txns count="(\d+)" addr="([0-9a-f]+)" cycle="([0-9a-f]+)" '
                     r'word="([0-9a-f]+)" prevCycle="([0-9a-f]+)" prevWord="([0-9a-f]+)"/>')
TAG_BI = re.compile(r'<a4_preflight_bigint count="(\d+)" hash="([0-9a-f]+)"/>')

def parse_log(path):
    fps, txns, bis = [], [], []
    with open(path) as f:
        for line in f:
            m = TAG_FP.search(line)
            if m: fps.append(m.groups()); continue
            m = TAG_TXN.search(line)
            if m: txns.append(m.groups()); continue
            m = TAG_BI.search(line)
            if m: bis.append(m.groups()); continue
    return fps, txns, bis

pairs = {}
for log in sorted(glob.glob(f"{DIR}/*.log")):
    name = os.path.basename(log).replace(".log", "")
    side = "A" if name.endswith("A") else "B"
    key = name[:-1]
    pairs.setdefault(key, {})[side] = log

out = {"pairs": {}}
for key in sorted(pairs):
    p = pairs[key]
    if "A" not in p or "B" not in p: continue
    fpA, txnA, biA = parse_log(p["A"])
    fpB, txnB, biB = parse_log(p["B"])
    n = min(len(fpA), len(fpB))
    diffs = []
    for i in range(n):
        a, b = fpA[i], fpB[i]
        if a != b:
            field_names = ["state","pc","mmm","userCycle","txnIdx","pagingIdx","bigintIdx","dc0","dc1"]
            different_fields = [field_names[j] for j in range(9)
                                if a[j+1] != b[j+1]]
            diffs.append({"mut_idx": i, "fields": different_fields})
    out["pairs"][key] = {
        "n_mut_blocks_A": len(fpA),
        "n_mut_blocks_B": len(fpB),
        "preflight_fp_diff_mut_count": len(diffs),
        "diffs_sample_first_5": diffs[:5],
    }
print(json.dumps(out, indent=2))
PY
cat a4/audits/audit_output/inc3d/c_b5/b5_handback.json
```

### 9. Decision based on B5 results

| Result | What it means | Next step |
|---|---|---|
| 0 preflight_fp diffs across all pairs | Preflight data is bit-identical A vs B → race is downstream of witgen entry (somewhere we haven't tagged: probably lookup tables or accum) | Need a B6 patch (extra scope), or accept Path A mitigation if it worked |
| ≥1 diffs and `field` is consistently the same (e.g., always `dc0` or always `pagingIdx`) | We've localized the racy field in PreflightCycle | Identify the Rust code that writes that field; report upstream |
| Diffs in many fields, sometimes different ones | Cascading divergence — one early diff propagates. Need wide mode + per-cell to find FIRST divergent cycle | Re-dispatch with `INC3D_C_MODE=b5_wide` |

### 10. (Optional) Wide mode for first-cycle localization

Only if (3) above — non-wide showed diffs but they cascade across fields. Wide emits per-cell hashes for every cycle so we can find the exact first divergent cycle:

```bash
INC3D_C_MODE=b5_wide SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh \
    2>&1 | tee ~/inc3d_c_b5_wide_dispatch.log
INC3D_PASS=c_b5_wide bash a4/pos/collect_inc3d_results.sh
```

Logs ~75 MB each. Wall ~30 min.

### 11. Handback

Write `PHASE_7D_INC3D_C_PATH_B5_COMPOSER_REPORT.md` with:
- Bundle SHA used (your new B5 host SHA)
- Per-pair `preflight_fp_diff_mut_count`
- For pairs with diffs: which fields differ; whether consistent or cascading
- Wall time + any anomalies
- Pointer to per-cell logs if wide mode was needed

---

## What this experiment proves

Combined with Path A:

| Path A | B5 | Conclusion |
|---|---|---|
| race killed | preflight diffs in `path_a1` log show 0 too | Rust parallelism in preflight is the root cause. Mitigation = `RAYON_NUM_THREADS=1`. Suitable for upstream bug report. |
| race killed | preflight diffs still present | Parallelism causes divergence at a higher layer (Rust-side struct that produces same witgen-relevant data via different path); harder to localize. Likely fix = `RAYON_NUM_THREADS=1` anyway. |
| race survives | preflight diffs present | Race is not just parallelism but is in preflight. B5 fields tell us which. May need to disable threading at a different layer (`thread::scope`). |
| race survives | 0 preflight diffs | Race is downstream of preflight (in lookup tables or accum). Need follow-up B6 patch. |

In all four outcomes we have actionable next steps.

---

## Files index

| Path | Change | Purpose |
|---|---|---|
| `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp` | **+~95 lines** at entry of `risc0_circuit_rv32im_cpu_witgen` | B5 preflight fingerprinting |
| `a4/core/executor.py` | regex + passthrough updated | recognize + emit `<a4_preflight_*>` tags |
| `a4/pos/run_campaign_pos.sh` | reads `A4_PREFLIGHT_FINGERPRINT{,_WIDE}` | propagate from POS var to env |
| `a4/pos/dispatch_pos.py` | adds `preflight_fingerprint{,_wide}` fields | manifest → POS var |
| `a4/pos/run_inc3d_phase_c.sh` | modes `b5`, `b5_wide` | dispatcher |
| `a4/docs/cloud1/composer/PHASE_7D_INC3D_C_PATH_B5_PATCH_SPEC.md` | This file | spec + handoff |
