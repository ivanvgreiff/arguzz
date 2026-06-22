# D2.G Full-Campaign Triage — Kickoff & Directives (Opus-CP → Composer/D2-opus)

**Date:** 2026-06-21 · **Author:** Opus-CP · **Status:** cleared to run
**Context:** full 4×3 campaign (12 jobs, N=10000) complete + pulled to `a4/runs/iv_pos_8/d2f/prod/`. Classification logic finalized (F25 + F27). Data-integrity investigated (F28).

---

## 1. VERDICT: the data is valid — proceed. Do NOT re-run the campaign.

I investigated all 12 DBs directly. Every data-integrity check that matters PASSES (outcome populated, L1 logged, CGC/GF non-empty, canonical locs, Hybrid dual-surface). The exit gate's 5/12 "failures" are **false alarms**:

- **V6_cTS applied rate ~0.94 "outside [0.75,0.92]" (×3): gate mis-calibration.** The band assumed a ~13% cold-start "tax" of *skips*. That model is wrong — **cold-start pulls execute (applied), they don't skip** (V6_cTS: 1409 `cold` decisions, only 96 skipped). Real skips ~5–6% = "no valid mutation site," shared with V6_uniform (~5%). cTS is genuinely adaptive (437/437 arms; modes adaptive/cold/floor; top-kind INSTR_WORD_MOD 32.5% vs uniform's flat ~13%). The comparison is valid.
- **V5 mutation count 9999/9998 (×2): benign.** Runs complete; 1–2 unrecorded crash iterations out of 10000.

**I already fixed the gate** (`a4/pos/validate_d2f_f1_gate.py`): recalibrated band + a direct cTS-adaptivity check (distinct arms ≥100, modes ⊇ {adaptive,floor}) + `MUTATION_COUNT_TOL=5`. Re-ran → **12/12 PASS**. No action needed from you on the gate.

---

## 2. RUN THIS: full triage on ALL 12 jobs (3 seeds × 4 variants) — on POS, not local

### ⚠️ The mistake just made (do not repeat): the `triage_at_scale_b4` manifest is **batch-1 only** (seeds 1234/1235; **seed 1236 missing**), and it was being run on **local WSL**. Both Composer efforts were on that incomplete manifest. Two root causes:
- the manifest was built with `collection_root` = the batch-1 subdir (so `flat_db_list` saw only 8 DBs);
- the `pipeline` default `--tier2-variant Hybrid_cTS` **filters the manifest** to one variant — you must pass `--tier2-variant all`.

### ✅ I (Opus-CP) already built + verified the correct full manifest:
```
a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full/
  d2g_triage_rerun_manifest.csv   ← 1423 dedup'd reruns, ALL 12 DBs
  d2g_triage_rerun.chain
  d2g_raw_accepts.csv, d2g_tier1_pass.csv, d2g_triage_at_scale_report.json
```
Coverage (verified): 2795 raw accepts (2062 INSTR_WORD_MOD + 733 POST_EXEC_PC_MOD) → **1423 dedup'd** (690 IWM + 733 PEPC; PEPC does NOT dedup by ISS-4 — `random_pc` is iter_seed-dependent). All 3 seeds × 3 Arguzz variants present (V5 = 0 accepts, correctly absent). tier1_hidden_global_reject = 0.

The build command (re-run on coinbase ONLY if coinbase has all 12 DBs; else rsync my manifest dir to coinbase):
```
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale pipeline \
  a4/runs/iv_pos_8/d2f/prod \           # <-- PARENT dir containing BOTH d2f_prod_b1 AND d2f_prod_b2
  --out .../triage_at_scale_full --tier2-variant all --no-local-tier2
```
**MANDATORY pre-dispatch check** (catches the batch-1 mistake): `cut -d, -f1,2 d2g_triage_rerun_manifest.csv | sort -u` must list seeds **1234, 1235, AND 1236**. If 1236 is missing → wrong `collection_root`, STOP and rebuild.

### Dispatch on POS — all 8 nodes
```
REPO=<coinbase arguzz> \
MANIFEST_DIR=$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full \
TRIAGE_NODES="<all 8 reserved nodes>" \           # default is only 5 (pact stoi idex meld tinyman) — use all 8
D2G_BASELINE_CACHE=/tmp/d2g_baseline_cache \      # see code-currency note below — ~2x speedup
bash a4/pos/dispatch_d2g_triage.sh all
```

### 🔑 Code-currency (the OTHER way to repeat the stale-logic mistake — classification runs ON-node):
- HEAD (`aad829b`) already has the current logic — F25 (`b_off % 4`) + scoped F27 (`_CONTROL_FLOW_ONLY_KINDS = {POST_EXEC_PC_MOD}`, BR_NEG_COND excluded). **Confirm coinbase + every node is checked out at `aad829b` or later** before dispatch.
- **Two uncommitted working-tree perf/portability changes** (in the WSL checkout, NOT yet in HEAD) matter for POS: (a) **lazy pandas import** — `run_one` nodes that lack pandas will otherwise fail at module import; (b) **`D2G_BASELINE_CACHE` disk cache** — without it, EACH of the 1423 jobs recomputes the baseline trace = a *second* full prove per job (~2x total cost). Commit + push these (review them first — they're logic-neutral), then set `D2G_BASELINE_CACHE` at dispatch. If you skip them: confirm nodes have pandas and accept ~2x runtime.

### Expected results (state them, then verify — don't assume)
- **`POST_EXEC_PC_MOD` accepts (≈733, V6 only): expect mostly `cf_inert` noop** (the `+4`-on-sequential overwrite; INV1/INV2 = 30/30 `pc:N=>N+4`). The lead is only any **divergent residue** (`strong`) — flag those individually.
- **`INSTR_WORD_MOD` accepts (≈2062): byte-identical→`none`, not-taken-branch→`cosmetic`, full-word same-aligned-word→`word_truncated`, else→`weak`.**
- **Hybrid: 100% `INSTR_WORD_MOD`** (it excludes `POST_EXEC_PC_MOD`).

### Validation gates on the triage output (report these)
- The 8-accept smoke oracle still reproduces **8/0/0** (regression check).
- For every `POST_EXEC_PC_MOD` classified `cf_inert`: confirm the post-inject PC stream is identical (the tier is keyed on that). If ANY `POST_EXEC_PC_MOD` accept shows post-inject divergence, surface it as `strong` — that is the real soundness lead.
- Count any `strong`/`weak` residue per variant — that, not raw accept counts, is the **soundness** signal.

---

## 3. THEN: the Case read — on soundness counts, not coverage

Only after the all-variant triage: re-read the Case A–E gate using **soundness-candidate counts** (post-triage), separately from the coverage read (locs/CGC, already provisional Case A). Report both. If the divergent residue is ~0 across variants (likely, per INV1), say so plainly — the headline becomes coverage/territory, and Hybrid's exclusion of `POST_EXEC_PC_MOD` is moot (those are no-ops anyway).

**Then** add batch-2 already landed (seed 1236) → you now have n=3 seeds; compute the paired stats (they were `nan` at n=2).

---

## 4. Division of labor
- **You (Composer/D2-opus):** the mechanical run — Tier-1 extract, dedup, chain_dispatcher `--trace` reruns, classify, assemble the metrics/scores/Case artifacts, regenerate the stale CSVs.
- **Me (Opus-CP):** I've verified data integrity, fixed the gate, and locked the classification logic. Hand me the regenerated triage output + the soundness-count Case read for review before any Pro-facing report.

Report back: the dedup'd rerun count, the per-variant class/evidence distribution, the `POST_EXEC_PC_MOD` cf_inert-vs-residue split, and any `strong`/`weak` residue you'd call a candidate.
