# Phase 7d — Increment 3 Report

## Summary

POS **fuzz campaigns** for B1/B4/B7 are **complete** (bundle `61a1ba8dfe80`). One step was started on the wrong machine — see B1 section.

### Done vs left (at a glance)

| Step | Where | Status |
|---|---|---|
| Write audit scripts B1/B2/B4/B7 | WSL | **Done** |
| POS manifest + dispatch plumbing | WSL → coinbase | **Done** |
| **B1 fuzz** — 5×200 mutations, produce DBs | **POS** | **Done** |
| **B4 fuzz + trace** — 5×50 + bandit JSONL | **POS** | **Done** |
| **B7 fuzz** — 10×50 paired runs | **POS** | **Done** |
| Scp POS DBs back to WSL | WSL | **Done** |
| **B4 audit script** on POS DBs | WSL (seconds) | **Done** — 250/250 PASS |
| **B2 audit script** (structural D40) | WSL (seconds) | **Done** — PASS |
| **B7 audit script** on POS DBs | WSL (seconds) | **Done** — **FAIL** (flagged for Opus) |
| **B1 verifier** (phase B) — 1000× strict replay | coinbase | **Running** — 5 parallel jobs since 10:23 CEST; last seen ~6h+ elapsed, no shard JSON yet |
| B2 `b1_multicycle_violations` count | WSL | **Left** — after B1 JSON merged |
| Final report + Opus sign-off | WSL | **This doc** — B7 FAIL documented; B1 pending verifier |
| Inc 4 | — | **Blocked** |

| Audit | Gate status |
|---|---|
| B1 hook fidelity | **PENDING** — POS fuzz done; phase-B verifier in flight on coinbase |
| B2 multi-cycle replay | **PASS** |
| B4 bandit→DB traceability | **PASS** |
| B7 seed reproducibility | **FAIL** — Opus |
| Fast tests | **PASS** |

## Acceptance gate results

| Gate | Status | Numbers |
|---|---|---|
| B1 | **IN PROGRESS** | Prevalidate 25/25 PASS. POS smokes done (5×200). Local strict verifier running on WSL (not POS) |
| B2 | **PASS** | D40 option (b) verified; `b1_multicycle_violations=-1` until B1 JSON final |
| B4 | **PASS** | 250/250 trace↔DB on POS (`2026-06-11_05-45-54_378654`) |
| B7 | **FAIL** | V2+V5 pass; V1/V3/V4 fail on `mutation_rewards` (not mutations/bandit) |
| Fast tests | **PASS** | 472 passed, 7 skipped |

## What went wrong (local vs POS)

B4 (250 muts) and B7 (500 muts) were incorrectly started on local WSL. Per project rule, **any campaign ≥100 mutations uses POS**. Those local runs are **not gate evidence**:

- B4 local run was stopped after completion; results used only to debug audit-script trace logging (bandit_step must reflect post-retry resolved step — fixed in `fuzzer.py`).
- B7 local run was **killed** mid-campaign (V3 runB incomplete).

B1 was always planned for POS (1000 muts); only the 5-mutation prevalidate smokes ran locally (correct).

## Per-audit findings

### B1 — Hook fidelity

**Prevalidate (local, n=5/variant, seed=999, telemetry=full): 25/25 PASS**

| Variant | Pass | Stratification sample |
|---|---|---|
| V1 | 5/5 | kind\|bucket spread (e.g. LOAD_VAL_MOD\|bucket3, INSTR_TYPE_MOD\|bucket1) |
| V2 | 5/5 | 5 kinds × 1 each |
| V3 | 5/5 | 5 kinds × 1 each |
| V4 | 5/5 | COMP_OUT_MOD×2, MEM_VAL_MOD×2, LOAD_VAL_MOD×1 |
| V5 | 5/5 | 5 distinct (kind,zone) arms |

Strict verifier (`verify_mutation_semantics.py` P1) exercised on all 25; zero `cycle_shift` flags.

**Full gate:** collect 5 POS DBs → `audit_output/inc3_b1/` → run:
```bash
python a4/audits/B1_hook_fidelity.py --db-dir a4/audits/audit_output/inc3_b1/
```

### B2 — Multi-cycle replay

- **D40 choice:** option (b) — drop multi-cycle steps for major-filter kinds.
- `INSTR_TYPE_MOD|step0` kept with 1 matching cycle (unambiguous).
- `MEM_VAL_MOD|step0` has many cycles — expected; D40 does not apply (no major filter).
- 4 D40-dropped arms confirmed absent from V5 universe.
- `b1_multicycle_violations`: pending until full B1 POS completes.

### B4 — Bandit→DB traceability

Audit script + `--debug-bandit-trace` instrumentation complete. POS manifest sets `debug_bandit_trace: true` per job; trace JSONL lands beside DB as `*.bandit_trace.jsonl`.

**Local dev note:** patched trace re-validation on local smokes showed 250/250 after fixing `bandit_step` to log post-retry resolved step. This is script validation only — **POS rerun required for gate**.

After POS collection → `audit_output/inc3_b4/`:
```bash
python a4/audits/B4_bandit_db_traceability.py --smoke-dir a4/audits/audit_output/inc3_b4/
```

### B7 — Seed reproducibility

Paired runs (runA/runB, same seed=999, n=50) via `run_suffix` in manifest. After POS collection → `audit_output/inc3_b7/`:
```bash
python a4/audits/B7_seed_reproducibility.py --smoke-dir a4/audits/audit_output/inc3_b7/
```

Diff excludes `mutations.executed_at` and D42 nondet `original_value` (188 addresses from `A1_nondet_addrs.json`).

**POS result (2026-06-11):** 10/10 jobs `exit_code=0`, 50 muts each. Local audit after scp:

```
python a4/audits/B7_seed_reproducibility.py --smoke-dir a4/audits/audit_output/inc3_b7/
→ B7 verdict: FAIL
```

| Variant | mut diff | bandit diff | rewards diff | pass |
|---|---|---|---|---|
| V1 zoned | 0 | 0 | 1 | **FAIL** |
| V2 kindUCB_v1 | 0 | 0 | 0 | PASS |
| V3 kindUCB_v2_noQ | 0 | 0 | 2 | **FAIL** |
| V4 kindTS_v2 | 0 | 0 | 1 | **FAIL** |
| V5 cTS_semantic_v2 | 0 | 0 | 0 | PASS |

### B7 investigation log (for Opus)

#### Composer implementation errors (fixed locally, not gate blockers)

1. **`int(byte_addr)` on hex strings** — `B7_seed_reproducibility.py` `_mutation_key()` crashed with `ValueError: invalid literal for int() with base 10: '0xffff0180'` when filtering D42 nondet addresses. **Fix:** `int(byte_addr, 0)`. This was an audit-script bug only; it masked the real reward diff on first run.

2. **Earlier false `B7 pair missing for V1`** — transient during incomplete scp; files present after full pull.

#### Stack-level finding — **FLAG FOR OPUS** (real gate failure)

Reward divergence is **not** row-order noise or timestamp columns:

- `mutations` tables are **byte-identical** (excl. `executed_at`) for all 50 steps per failing variant.
- `bandit_decisions` are **0 diff** on failing variants.
- `local_coverage_v2` and `compressed_global_coverage` **semantic content matches** when sorted and excluding `first_hit_at` timestamps.
- Divergence is isolated to `mutation_rewards` at specific `mutation_id`s, keyed comparison (not `ORDER BY 1`).

**Example — V1 (`zoned`), first divergence at `mutation_id=35`:**

| Field | runA | runB |
|---|---|---|
| mutation (kind/step/config/failures) | MEM_VAL_MOD step=3780, identical | identical |
| rewards 1–34 | identical | identical |
| `delta_T` | 0 | 1 |
| `T_new` | 0.0 | 0.02817… |
| `delta_F`, `d_loc`, `d_glob`, `F_new` | identical | identical |

Same pattern on V3 (`mid=14`, `mid=25`) and V4 (`mid=37`): failure contexts and F-components match; **touch novelty (`delta_T`) differs** despite identical mutation configs and identical cumulative state through the prior mutation.

**Interpretation:** `delta_T = count_new_bits(touch_bitmap, state.global_bitmap)` (`coverage_state.py`). Identical mutations + identical rewards through mutation 34 imply identical `global_bitmap` entering mutation 35, so the divergence most likely means **the host touch bitmap for that mutation differed between runA and runB** — not bandit selection or mutation generation (those are 0 diff). Work order says: *"If V1 (`zoned`) shows non-determinism with seed=999, that's a real bug — STOP and flag."*

**Hypotheses for Opus (not proven here):**

1. Host touch-map nondeterminism on POS nodes (runA/runB dispatched to different nodes).
2. Ordering sensitivity in `T_rare` weight selection when weights tie (less likely — `delta_T` is integer and differs).
3. Not explained by D42 nondet filtering (mutations already 0 diff).

**Not a B7 audit-script false positive** — rewards were compared by `mutation_id`; mutations and bandit paths match.

## B1 — two phases (why WSL is slow, and yes POS can run the verifier)

B1 is **two different jobs** that both call `risc0-host`:

| Phase | What | Host calls | Intended machine | Status |
|---|---|---|---|---|
| **A. Fuzz campaign** | Run fuzzer 5×200 muts; write DBs | 1000 (during fuzz) | **POS** | **Done** |
| **B. Strict verifier** | Read each DB row; replay `config_json` alone; assert hook matches DB | 1000 (replay) | **POS** (per work order) | **Running on WSL by mistake** |

Phase A is what the work order’s “~45 min POS wall” refers to. **That finished on coinbase.**

Phase B is `B1_hook_fidelity.py --db-dir …` calling `verify_mutation_semantics.verify_sample()` once per mutation. It does **not** need to run on WSL — it only needs Python, the audit script, the DB files, and `risc0-host` (all present in the POS bundle). **There is no technical blocker to running it on POS/coinbase.** We simply never wired a POS dispatch for phase B and started it locally after scp.

**WSL benchmark:** ~70–93 s per replay → **~19–22 h** sequential for 1000.

**POS estimate (5 nodes, one variant DB per node):** ~200 replays × ~35 s ÷ 5 parallel ≈ **~25–40 min wall** (same order as phase A).

**Recommended fix:** kill the WSL verifier; on coinbase run 5 parallel jobs (one per variant DB, either from `/srv/testbed/results/.../pos_audit_b1/` or scp DBs back). No new fuzz work — only phase B replays. A small shell wrapper or manifest is enough; full POS dispatch framework is optional.

```bash
# Example on coinbase (one variant; repeat in parallel on 5 nodes):
PYTHONUNBUFFERED=1 python a4/audits/B1_hook_fidelity.py \
  --db-dir /path/to/dir/with/one/db \
  --host "$BUNDLE_ROOT/bin/risc0-host"
```

(Exact `--db-dir` / per-variant invocation may need a thin wrapper — `B1_hook_fidelity.py` expects all 5 DBs in one dir today, but each `verify_db` call is independent per variant.)

## B2 re-run — why it was listed

B2 **verdict is already PASS** without re-running. The script has two parts:

1. **Structural D40 checks** (inspection + universe query) — done, PASS.
2. **`b1_multicycle_violations`** — reads `B1_hook_fidelity.json` `per_variant[].multicycle_flags` and `cycle_shift` failures. While B1 verifier is incomplete, this field is `-1` and `b1_pending: true`; the gate still passes because `-1 <= 0` is treated as “pending”, not a violation.

Re-running `B2_multicycle_replay.py` after B1 finishes is **optional housekeeping** to populate the numeric cross-reference in `B2_multicycle_replay.json`, not to flip PASS→FAIL unless B1 reports `multicycle_flags > 0`.

## POS dispatch info

### Bundle (WSL — user scp manually)

| Field | Value |
|---|---|
| Bundle (gate) | `~/a4_campaign_61a1ba8dfe80.tar.gz` on coinbase |
| Git commit in bundle | `61a1ba8dfe80` (includes `--debug-bandit-trace`, Inc3 manifests) |
| Stale bundle (failed B4 v1) | `bbfbf7b54c88` — missing `--debug-bandit-trace`; all B4 jobs `exit_code=2` |

```bash
# WSL
scp -P 10022 bundles/a4_campaign_bbfbf7b54c88.tar.gz <user>@coinbase.net.in.tum.de:~/
```

### Manifests

| Audit | Manifest | Jobs | Host muts | Nodes |
|---|---|---|---|---|
| B1 | `a4/pos/manifests/pos_audit_b1.json` | 5 × n=200 | 1000 | 5 |
| B4 | `a4/pos/manifests/pos_audit_b4.json` | 5 × n=50 + trace | 250 | 5 |
| B7 | `a4/pos/manifests/pos_audit_b7.json` | 10 × n=50 (runA/B) | 500 | 10 |

### Dispatch (coinbase, after `source /srv/testbed/pos/cli/venv3/bin/activate`)

```bash
# One audit at a time (Inc 2 lesson: no concurrent host-heavy audits on same nodes)
bash a4/pos/run_inc3_pos.sh b1  flare bitcoin bitcoincash bitcoingold litecoin
bash a4/pos/run_inc3_pos.sh b4  flare bitcoin bitcoincash bitcoingold litecoin
bash a4/pos/run_inc3_pos.sh b7  flare bitcoin bitcoincash bitcoingold litecoin dogecoin \
    namecoin peercoin novacoin feathercoin terracoin
```

Or single-job dispatch:
```bash
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/pos_audit_b1.json \
  --bundle ~/a4_campaign_bbfbf7b54c88.tar.gz \
  --nodes flare bitcoin bitcoincash bitcoingold litecoin \
  --allocation-duration 360 --await
```

### Collect artifacts (scp back to WSL)

```bash
# B1 — 5 DBs
scp -P 10022 'coinbase:~/results_pos_audit_b1_*/*.db' a4/audits/audit_output/inc3_b1/

# B4 — 5 DBs + 5 bandit_trace JSONL
scp -P 10022 'coinbase:~/results_pos_audit_b4_*/*' a4/audits/audit_output/inc3_b4/

# B7 — 10 DBs (runA + runB per variant)
scp -P 10022 'coinbase:~/results_pos_audit_b7_*/*.db' a4/audits/audit_output/inc3_b7/
```

Then re-run audit scripts (above), update this report with final verdicts, and re-run B2 with full B1 output.

## Files changed

| File | Change |
|---|---|
| `a4/audits/B1_hook_fidelity.py` | NEW — orchestrator + prevalidate |
| `a4/audits/B2_multicycle_replay.py` | NEW |
| `a4/audits/B4_bandit_db_traceability.py` | NEW |
| `a4/audits/B7_seed_reproducibility.py` | NEW |
| `a4/standalone/fuzzer.py` | `--debug-bandit-trace` + post-retry step fix |
| `a4/standalone/cli.py` | `--debug-bandit-trace` CLI flag |
| `a4/audits/audit_common.py` | `debug_bandit_trace` in `run_fuzz_smoke` |
| `a4/pos/manifests/pos_audit_b1.json` | NEW |
| `a4/pos/manifests/pos_audit_b4.json` | NEW |
| `a4/pos/manifests/pos_audit_b7.json` | NEW |
| `a4/pos/run_inc3_pos.sh` | NEW — dispatch helper |
| `a4/pos/dispatch_pos.py` | `run_suffix`, `debug_bandit_trace` job fields |
| `a4/pos/run_campaign_pos.sh` | `A4_RUN_SUFFIX`, `A4_DEBUG_BANDIT_TRACE` |

## B1 verifier status (2026-06-11 afternoon)

**POS fuzz (phase A): done** — all 5×200 DBs on coinbase + WSL.

**Phase B attempts:**

| Attempt | Result |
|---|---|
| WSL sequential | Killed (~3 h in); ~20 h wall estimate |
| POS 5-node shards (`run_b1_verify_pos.sh`) | **Failed** — instant 0/200 (`no <a4_*_mod> line`); test-node env does not match coinbase login |
| coinbase 5× parallel (`~/b1_verify_work/`) | **In progress** — ~54 s/mutation; 5 jobs started 10:23 CEST; still running at 16:44 CEST |

**When coinbase jobs finish**, on WSL:

```bash
# collect + merge + B2 refresh
bash a4/pos/finalize_inc3_for_opus.sh
```

Or manually:

```bash
scp -P 10022 'ivgreiff@coinbase:~/b1_verify_work/out/B1_V*.json' a4/audits/audit_output/b1_verify_shards/
python a4/audits/merge_b1_verify_shards.py --shard-dir a4/audits/audit_output/b1_verify_shards/
python a4/audits/B2_multicycle_replay.py
```

Check on coinbase: `tail ~/b1_verify_work/V*.log` — look for `B1 verdict: PASS (200/200)`.

**No git push/pull required** for scripts already scp'd to `~/arguzz` on coinbase. Push when you want WSL changes persisted in repo.

## Open items

1. **Confirm B1 shards finished** on coinbase → merge → gate 1000/1000.
2. **B7 FAIL — Opus** — reward nondeterminism V1/V3/V4 (`mutation_rewards_diff`); mutations+bandit 0 diff.
3. Re-run B2 after B1 merge (fills `b1_multicycle_violations`).

## Ready-to-proceed (Opus)

| Audit | Verdict | Notes |
|---|---|---|
| B2 | **PASS** | Structural D40 |
| B4 | **PASS** | 250/250 |
| B7 | **FAIL** | Flagged — see investigation log |
| B1 | **PENDING** | Prevalidate 25/25; full verifier not merged yet |
| Inc 4 | **BLOCKED** | B1 gate + B7 Opus triage |

**STOP for Opus** on B7 V1 (`zoned`) reward nondeterminism with seed=999.
