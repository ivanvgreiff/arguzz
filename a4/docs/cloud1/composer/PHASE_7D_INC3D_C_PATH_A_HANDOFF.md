# Phase 7d Inc 3d Phase C — Path A Composer handoff

**Date**: 2026-06-12
**Owner**: Opus → Composer
**Goal**: Test whether Rust-side parallelism in the executor is the root cause of B7 race.
**Parent plan**: `PHASE_7D_INC3D_C_PLAN.md`
**Cousin docs**: `PHASE_7D_INC3D_B2_OPUS_ANALYSIS.md` (motivation)

---

## TL;DR for Composer

We've localized the B7 race to "upstream of witgen" via B4 memory-fingerprint analysis. The likely culprit is `rayon::into_par_iter` in the Rust executor's preflight builder, which can produce a non-deterministic `Vec<PreflightCycle>` under POS multi-core load (32-core EPYC 9354). Path A directly tests this by **re-dispatching the existing B P1 host** with `RAYON_NUM_THREADS=1` to force sequential preflight.

**No new host build.** Reuse the Inc 3d B P1 host (`632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`). The only change is a refreshed bundle that picks up updated launcher scripts (`run_campaign_pos.sh` + `dispatch_pos.py`) which now read new POS variables `A4_RAYON_THREADS`, `A4_RISC0_THREADS`, `A4_OMP_THREADS`. **Same binary inside.**

---

## What you need to do

### 1. Pull latest scripts (you may need a `git pull`)

Files modified on `main` for Phase C:
- `a4/pos/run_campaign_pos.sh` — reads `A4_{RAYON,RISC0,OMP}_THREADS` and exports the corresponding native env vars
- `a4/pos/dispatch_pos.py` — adds `rayon_threads`, `risc0_threads`, `omp_threads`, `preflight_fingerprint{,_wide}` fields to `JobSpec`
- `a4/pos/run_inc3d_phase_c.sh` — new SPREAD dispatcher with mode select
- `a4/pos/collect_inc3d_results.sh` — handles `INC3D_PASS=c_<mode>`

### 2. Rebuild bundle on WSL (Ivan)

Ivan: please run on WSL to refresh the bundle so the new launcher knobs land in `a4_campaign/repo/a4/pos/run_campaign_pos.sh`. Same B P1 host binary, just updated scripts overlayed:

```bash
cd /root/arguzz

# Confirm the B P1 host is still pinned somewhere on WSL.
# If you still have the binary used for Inc 3d B P1:
ls -lh /root/arguzz/workspace/output/target/release/risc0-host
sha256sum /root/arguzz/workspace/output/target/release/risc0-host
# expect: 632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1

# Rebuild bundle (no rebuild of the host needed — same binary)
bash a4/pos/prepare_bundle.sh \
    --host /root/arguzz/workspace/output/target/release/risc0-host \
    --allow-dirty

ls -lh bundles/a4_campaign_*.tar.gz | tail -1
# Verify the new bundle has the Phase C knobs in run_campaign_pos.sh:
NEW=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
tar -xOf "$NEW" a4_campaign/repo/a4/pos/run_campaign_pos.sh | grep A4_RAYON_THREADS
# expect: A4_RAYON_THREADS=$(pos_get_variable A4_RAYON_THREADS 2>/dev/null || echo "")
# and:    export RAYON_NUM_THREADS="$A4_RAYON_THREADS"

# SCP to coinbase
scp "$NEW" coinbase:~/INC3D_PHASE_C_BUNDLE.tar.gz
```

### 3. (Composer) Pre-reserve POS

Reserve the SAME 4-node entry as Inc 3d B (`flare + octorand + opulous + meld`) via the **POS web calendar UI** for ~45 min. **You cannot create reservations via CLI** — only the web UI permits multi-node calendar entries that bypass the 2-future-entries quota. Wait for `start_date` to actually pass before dispatching.

If the previous calendar entry 1726 is still active and has remaining time, you can reuse it directly.

### 4. (Composer) Dispatch Path A Pass A1

```bash
ssh coinbase
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz && git pull   # pick up dispatcher updates
export INC3D_C_BUNDLE=~/INC3D_PHASE_C_BUNDLE.tar.gz

INC3D_C_MODE=path_a1 SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh \
    2>&1 | tee ~/inc3d_c_a1_dispatch.log
```

Expected wall: ~28 min (same as B P1 wall, no instrumentation overhead).

### 5. (Composer) Collect

```bash
# from WSL or coinbase:
INC3D_PASS=c_path_a1 bash a4/pos/collect_inc3d_results.sh
# → DBs and logs in a4/audits/audit_output/inc3d/c_path_a1/
```

### 6. (Composer) Quick diff (for the handback)

Compute reward diffs A-vs-B per pair (delta_T flips):

```bash
cd ~/arguzz
python3 - <<'PY' > a4/audits/audit_output/inc3d/c_path_a1/quick_summary.json
import sqlite3, glob, os, json
DIR = "a4/audits/audit_output/inc3d/c_path_a1"
dbs = sorted(glob.glob(f"{DIR}/*.db"))
pairs = {}
for db in dbs:
    name = os.path.basename(db).replace(".db", "")
    side = "A" if name.endswith("A") else "B"
    key = name[:-1]
    pairs.setdefault(key, {})[side] = db
summary = {"path": "path_a1", "pairs": {}}
for key in sorted(pairs):
    p = pairs[key]
    if "A" not in p or "B" not in p: continue
    ca = sqlite3.connect(p["A"]); cb = sqlite3.connect(p["B"])
    qa = list(ca.execute(
        "SELECT m.id, m.kind, mr.delta_T, mr.reward FROM mutations m "
        "LEFT JOIN mutation_rewards mr ON m.id = mr.mutation_id ORDER BY m.id"))
    qb = list(cb.execute(
        "SELECT m.id, m.kind, mr.delta_T, mr.reward FROM mutations m "
        "LEFT JOIN mutation_rewards mr ON m.id = mr.mutation_id ORDER BY m.id"))
    ra, rb = {r[0]: r for r in qa}, {r[0]: r for r in qb}
    dT = []
    other = []
    for mid in sorted(set(ra)|set(rb)):
        a, b = ra.get(mid), rb.get(mid)
        if a is None or b is None: continue
        if a[2] != b[2]:
            dT.append({"mid": mid, "kind": a[1], "A": a[2], "B": b[2]})
        elif a[3] != b[3]:
            other.append({"mid": mid, "kind": a[1], "reward_diff": a[3] - b[3]})
    summary["pairs"][key] = {"n": len(ra), "delta_T_flips": dT, "other_reward_diffs": other}
print(json.dumps(summary, indent=2))
PY
cat a4/audits/audit_output/inc3d/c_path_a1/quick_summary.json
```

### 7. Decision rule

| Path A1 result | Decision |
|---|---|
| 0 ΔT flips across all 5 pairs | **Race vanished.** Rust parallelism confirmed as cause. STOP. Report back. Opus closes B7. |
| ≥1 ΔT flip but fewer than B P1 baseline (1–2/50) | Partial mitigation. Run Path A2 (multi-thread knobs all off). |
| ~1–2 ΔT flips (same rate as B P1) | Parallelism not the cause. Proceed to B5 (preflight fingerprint). |

For Path A2, only run if A1 was partial mitigation:

```bash
INC3D_C_MODE=path_a2 SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh \
    2>&1 | tee ~/inc3d_c_a2_dispatch.log
INC3D_PASS=c_path_a2 bash a4/pos/collect_inc3d_results.sh
```

### 8. Handback to Opus

Write `PHASE_7D_INC3D_C_PATH_A_COMPOSER_REPORT.md` with:
- Bundle SHA used (must match B P1 sha `632094ef…`)
- Per-pair ΔT flip count (from `quick_summary.json`)
- Decision based on the rule above
- Time to next reservation slot if Path A2 needed
- Any anomalies (SIGSEGV count, dispatch errors)

---

## Bundle integrity checks

The new `run_inc3d_phase_c.sh` dispatcher will **fail** to start if:
- Bundle host SHA doesn't match `632094ef…` (for path_a modes) — we should add a per-mode check, but for now it just prints the SHA; Composer please verify by eye.
- Bundle `run_campaign_pos.sh` doesn't contain `A4_RAYON_THREADS` (means bundle was built from old scripts).
- Bundle `executor.py` doesn't contain `_A4_DIAG_LINE_RE` (means executor passthrough not present).

If you see the second failure: Ivan needs to rebuild the bundle on WSL after `git pull`-ing the Phase C launcher updates.

---

## What this tells the world

If Path A1 eliminates the race, we have proven:
1. The B7 race is **caused by Rust-side parallelism in the RISC Zero v2 executor's preflight phase**.
2. `RAYON_NUM_THREADS=1` is a sufficient and minimally invasive mitigation.
3. We can launch Phase 8 with this env var set as a default on POS launches.
4. Subsequent work (Phase B5) can localize which specific PreflightCycle field is non-determinism-prone, suitable for a clean upstream bug report to RISC Zero — but Phase 8 doesn't need to wait for that.

This is a fast (~30 min) experiment with decisive yes/no answer. Run it ASAP.

---

## Files index

| Path | Purpose |
|---|---|
| `a4/pos/run_inc3d_phase_c.sh` | New dispatcher for Phase C (path_a1, path_a2, b5, b5_wide modes) |
| `a4/pos/run_campaign_pos.sh` | Updated: reads `A4_{RAYON,RISC0,OMP}_THREADS`, `A4_PREFLIGHT_FINGERPRINT{,_WIDE}` |
| `a4/pos/dispatch_pos.py` | Updated: new `JobSpec` fields for Phase C knobs |
| `a4/pos/collect_inc3d_results.sh` | Updated: handles `INC3D_PASS=c_<mode>` |
| `a4/docs/cloud1/composer/PHASE_7D_INC3D_C_PLAN.md` | Overall Phase C plan (A + B5 + B6) |
| `a4/docs/cloud1/composer/PHASE_7D_INC3D_C_PATH_A_HANDOFF.md` | This file |
