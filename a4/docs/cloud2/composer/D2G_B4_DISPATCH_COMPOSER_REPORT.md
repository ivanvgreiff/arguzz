# D2.G B4 Dispatch — Composer Report (ISS-4 + POS greenlight)

**Date:** 2026-06-20  
**Author:** Composer  
**Spec:** `IV_POS_8_D2_G_SPEC.md` v1.2 (ISS-4 RESOLVED)  
**Commit:** `65b7683` — kind-aware dedup, batched chain, dispatch tooling  
**Status:** POS dispatch **greenlit**; local fallback run **in progress** from dev (no coinbase SSH)

---

## Executive summary

Opus greenlit the **1022-job** tier-2 triage chain after ISS-4 (kind-aware dedup + `triage_run_id` collision fix). I implemented the remaining infra gaps, fixed a **chain batching defect** that would have stacked ~128 concurrent jobs per node, added a one-command POS pipeline (`dispatch_d2g_triage.sh`), and started a **resumable local run** because this environment cannot reach POS nodes (SSH to `flare` times out; coinbase requires port 10022).

| Item | Status |
|------|--------|
| ISS-4 dedup + run_id | ✅ Done (`65b7683`) |
| Chain batching (128×8) | ✅ Done (see §3 — necessary fix) |
| Dispatch automation | ✅ `a4/pos/dispatch_d2g_triage.sh` |
| POS preflight/dispatch | ⏸ Blocked here — operator on coinbase |
| Local `run_manifest` (1022) | 🔄 Running (4 workers, resumable) |
| Item 2 soundness re-read | ⏸ After collect completes |

---

## 1. Agreement with Opus greenlight

**No pushback** on the dispatch decision or the two post-collection reminders:

1. **Lead = divergent residue**, not raw 484 PEPC — expect mostly `cf_inert`; only `propagated_candidate`/`strong` (or non-weak PEPC propagated) matter for soundness.
2. **n=2 provisional** — STOP at batch-2 holds; no paired p-values until seed 1236.

I independently re-verified before acting:

| Check | Result |
|-------|--------|
| Manifest jobs | 1022 (538 IWM + 484 PEPC) |
| Unique `run_id`s | 1022 (all include `_is{iter_seed}`) |
| PEPC preservation | 484 = 143 V6_cTS + 341 V6_uniform (zero collapse) |
| Offline tests | 25/25 pass (21 unit + dedup/chain + semantics) |
| Smoke oracle | Unchanged (single-variant IWM) |

---

## 2. ISS-4 implementation (recap)

### Kind-aware dedup (`propagation_triage.dedupe_accepts_for_rerun`)

| Kind | Dedup key | Rows |
|------|-----------|-----:|
| `INSTR_WORD_MOD` | `(variant, kind, step)` | 538 |
| `POST_EXEC_PC_MOD` | `(variant, kind, step, iter_seed)` | 484 |
| Other (future) | `(variant, kind, step, iter_seed)` | — |

Prod DB verification: **0** IWM `(variant, step)` groups with >1 fault word tuple.

### `triage_run_id` collision fix

Format: `triage_{variant}_s{seed}_{kind}_step{step}_is{iter_seed}`

Applied in: chain manifest, `run_one` fallback, `run_tier2_local`, `smoke`, `run_manifest`.

Without this, same-step PEPC siblings would overwrite JSON in the shared `/tmp/d2g_triage_results` directory — silently undoing the 484-row preservation.

---

## 3. Chain batching fix (pushback / additional finding)

**Problem:** The original chain put all 1022 jobs in **one batch** (`d2g_triage_rerun`). `chain_dispatcher.sh` launches **every job in a batch concurrently** (background `nohup` per job). With round-robin node assignment, each node would receive **~128 simultaneous** `run_one` processes — violating the 1-per-node concurrency rule (POS_PLAYBOOK §12.53) and likely thrashing memory/CPU.

**Fix:** `write_chain_manifest` now emits **128 batches** of up to 8 jobs (`d2g_triage_rerun_w0001` … `w0128`), one job per node per batch — matching the D2.F production pattern (8 jobs per batch).

**Artifacts:**

- `a4/pos/manifests/iv_pos_8/d2g_triage_b4.chain` (committed)
- `a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_triage_rerun.chain` (regenerated; gitignored)

**Estimated POS wall time:** 128 batches × ~80–120 s/job ≈ **3–4 hours** unattended (8-way parallel, POLL_SEC=30).

---

## 4. New tooling

### `triage_at_scale.py` subcommands

| Command | Purpose |
|---------|---------|
| `preflight` | SSH each node: host binary + import `dedupe_accepts_for_rerun` |
| `gather` | SCP `/tmp/d2g_triage_results/*.json` from all 8 nodes → `merged/` |
| `run_manifest` | Resumable local/POS substitute; `--workers N`, skip existing JSON |
| `collect` | Merge JSON → CSV (unchanged) |
| `smoke` | ≤10 jobs (unchanged) |

### `soundness_reread.py` CLI

```bash
python3 -m a4.runs.iv_pos_8.d2g.soundness_reread \
  d2g_accept_triage_all_variants.csv \
  --out-json d2g_soundness_reread.json \
  --out-md d2g_soundness_reread.md
```

### `a4/pos/dispatch_d2g_triage.sh` (coinbase)

```bash
# From coinbase with POS SSH:
REPO=/path/to/arguzz bash a4/pos/dispatch_d2g_triage.sh preflight
bash a4/pos/dispatch_d2g_triage.sh dispatch      # chain_dispatcher, ~3-4h
bash a4/pos/dispatch_d2g_triage.sh postcollect   # gather + collect + soundness
# Or: bash a4/pos/dispatch_d2g_triage.sh all
```

**Important:** `chain_dispatcher` pulls **chainjob** stdout/meta dirs, **not** triage JSON. The `gather` step is mandatory before `collect`.

---

## 5. What ran in this environment

### POS (blocked)

```
ssh flare  → ConnectTimeout (no route from dev/WSL)
preflight  → hangs/timeouts on all 8 nodes
```

Dispatch must run from **coinbase** (`ssh -p 10022 ivgreiff@coinbase.net.in.tum.de`) per POS_PLAYBOOK.

### Local fallback (started)

Because the user asked to “take care of all items” and POS is unreachable here, a resumable local run was started:

```bash
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale run_manifest \
  a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_triage_rerun_manifest.csv \
  --results-dir a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/run_one_results \
  --host workspace/output/target/release/risc0-host \
  --workers 4
```

- **Log:** `/tmp/d2g_run_manifest.log`
- **Progress:** check `run_one_results/*.json` count (target 1022)
- **ETA:** ~5–6 h at 4 workers × ~80 s/job
- **Resume-safe:** re-run the same command to skip completed JSONs

**Pushback note:** If coinbase POS dispatch runs in parallel, use **one** result source for Item 2 — do not double-merge. Prefer POS results when available (policy: >10 mutations → POS).

### Post-collect (when 1022 JSONs exist)

```bash
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale collect \
  a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/run_one_results \
  --out a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_accept_triage_all_variants.csv \
  --report a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_triage_collect_report.json

python3 -m a4.runs.iv_pos_8.d2g.soundness_reread \
  a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_accept_triage_all_variants.csv \
  --out-json a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_soundness_reread.json \
  --out-md a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_soundness_reread.md
```

---

## 6. Operator checklist (coinbase)

1. **Sync repo** on all 8 nodes to `65b7683` (or later on `cloud2`).
2. **Preflight:** `bash a4/pos/dispatch_d2g_triage.sh preflight` — all 8 nodes must report `ok: true`.
3. **Verify host:** `/root/a4_campaign/bin/risc0-host` executable on each node.
4. **Dispatch:** `bash a4/pos/dispatch_d2g_triage.sh dispatch` (tmux recommended).
5. **Gather:** `bash a4/pos/dispatch_d2g_triage.sh postcollect` — merges 8 nodes' JSONs, writes CSV, runs soundness re-read.
6. **Review Item 2:** read `d2g_soundness_reread.md` — divergent residue count is the soundness lead.

---

## 7. Expected Item 2 outcome (provisional)

Based on smoke (6/6 PEPC → `cf_inert`, 0 strong) and F27/F26 framing:

| Expectation | Rationale |
|-------------|-----------|
| PEPC mostly `cf_inert` noop | INV1 §2c — `pc+4` on committed next PC is proof-inert |
| IWM mostly noop (`word_truncated`, `cosmetic`, `cf_inert` N/A) | F25 proof-invisible |
| **Divergent residue likely 0** | Honest read if empty: “no soundness candidates in batch-1” |
| Case verdict | Still **provisional at n=2** — batch-2 gate unchanged |

---

## 8. Files changed (this session)

| File | Change |
|------|--------|
| `propagation_triage.py` | Kind-aware `dedupe_accepts_for_rerun` |
| `triage_at_scale.py` | `triage_run_id`, batched chain, preflight/gather/run_manifest |
| `soundness_reread.py` | CLI entrypoint |
| `dispatch_d2g_triage.sh` | One-command POS pipeline |
| `d2g_triage_b4.chain` | 1022 jobs / 128 batches |
| `test_propagation_triage_unit.py` | +3 tests (dedup + chain batching) |
| `IV_POS_8_D2_G_SPEC.md` | ISS-4 RESOLVED + chain batching note |
| `D2G_B4_COMPOSER_REPORT.md` | Updated job counts / operator steps |

---

## 9. Next steps

| Step | Owner | When |
|------|-------|------|
| POS dispatch (preferred) | Operator on coinbase | Now |
| Local run completion | Background on dev | ~5–6 h if POS not used |
| Item 2 soundness re-read | Auto after collect | After 1022 JSONs |
| Batch-2 (seed 1236) | Campaign | When DBs land |
| Paired p-values / final Case | D2.G | After n≥3 |

---

## 10. Changelog entry (for spec §15)

| Date | Author | Notes |
|------|--------|-------|
| 2026-06-20 | Composer | ISS-4 RESOLVED: kind-aware dedup (1022 jobs), `triage_run_id` iter_seed suffix, chain split into 128×8 batches, `dispatch_d2g_triage.sh` + gather/preflight/run_manifest CLI. POS greenlit; local fallback run started from dev. |
