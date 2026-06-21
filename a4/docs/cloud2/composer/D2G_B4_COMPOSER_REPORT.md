# D2.G B4 Composer Report — Retriage infrastructure + batch-1 readiness

**Date:** 2026-06-20  
**Author:** Composer  
**Spec:** `IV_POS_8_D2_G_SPEC.md` v1.2 (F21–F27 settled)  
**Kickoff:** `D2G_B4_COMPOSER_KICKOFF.md`

---

## Executive summary

I agree with Opus/D2-opus on the classification settlement (F25/F27 scoped, 3939→`word_truncated`, POST_EXEC_PC_MOD→`cf_inert`, stale Hybrid triage invalid). **Item 0 is complete.** **Item 1 manifest regenerated (1022 jobs, ISS-4 dedup fix)** but **POS dispatch is blocked** from this environment (no SSH to test nodes). **Item 2 is provisional only** (smoke sample, not full campaign). **Item 3 STOP** as directed (batch-2 seed 1236 not available).

**Do not use** the prior `d2g_accept_triage_tier2_sample.csv` (132 Hybrid rows, pre-F22/F24 evidence set).

---

## Pushback / agreement

| Topic | Verdict |
|-------|---------|
| F25 `b_off % 4 == 0` gate | **Agree** — verified in code + 22 unit tests |
| F27 `cf_inert` for POST_EXEC_PC_MOD only | **Agree** — BR_NEG_COND stays weak; non-empty window guard correct |
| 3939 → `word_truncated` noop (8/0/0 oracle) | **Agree** — smoke oracle updated |
| Prior Hybrid 132-row triage stale | **Agree** — evidence set was `{",weak,cosmetic}` only |
| 484 POST_EXEC_PC_MOD mostly no-op | **Agree** — smoke: 6/6 sampled = `cf_inert`, fault `pc:N=>N+4` |
| `run_one` chain gap | **Agree** — was a real blocker; now fixed |
| ISS-4 dedup `(kind,step)` only | **Agree** — cross-variant + PEPC iter_seed collapse; fixed to 1022 jobs |
| F27 scope pushback (exclude BR_NEG_COND) | **Agree** — no dissent |

**Minor fixes applied during this work:**
- Chain manifest initially used local `workspace/.../risc0-host`; corrected to `/root/a4_campaign/bin/risc0-host` via `default_pos_host()`.
- **ISS-4 (2026-06-20):** kind-aware dedup + `triage_run_id(..., iter_seed)` so same-step PEPC jobs do not overwrite JSON on POS.

---

## Item 0 — BLOCKER (code) ✅ COMPLETE

### Changes (`triage_at_scale.py`)

| Component | Description |
|-----------|-------------|
| **`run_one`** | Single accept → live `tier2_classify` → `classify_semantics`; JSON to `--results-dir/{run_id}.json` + stdout |
| **`collect`** | Merge `*.json` → CSV + aggregated report JSON |
| **`smoke`** | ≤10 local `run_one` jobs + collect (POS rule compliant) |
| **`--tier2-variant all`** | All variants; 1022 deduped jobs (538 IWM + 484 PEPC; ISS-4) |
| **`default_pos_host()`** | Chain uses `/root/a4_campaign/bin/risc0-host` |
| **`triage_run_id()`** | Includes `iter_seed` for unique per-job JSON on POS |

### ≤10-job local smoke (Item 0.4)

Command:
```bash
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale smoke \
  a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_triage_rerun_manifest.csv \
  --results-dir /tmp/d2g_b4_smoke_results \
  --out /tmp/d2g_b4_smoke_collected.csv --limit 10
```

**Result (10 rows, current logic):**

| evidence | count | kinds |
|----------|------:|-------|
| `cf_inert` | 6 | POST_EXEC_PC_MOD (all `pc:N=>N+4`) |
| `weak` | 2 | INSTR_WORD_MOD |
| `cosmetic` | 1 | INSTR_WORD_MOD |
| `` (none) | 1 | INSTR_WORD_MOD |

**Proof new logic ran:** evidence set includes `cf_inert` (absent from stale report).

`pytest a4/runs/iv_pos_8/d2g/test_triage_at_scale.py` — **1 passed** (3 run_one round-trips + collect).  
Offline unit tests — **22 passed**.

---

## Item 1 — Regenerate all-variant triage ⏸ BLOCKED ON POS

### 1.1 Manifest generated ✅

```
python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale pipeline \
  a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1 \
  --out a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4 \
  --tier2-variant all --no-local-tier2
```

| metric | value |
|--------|------:|
| Raw accepts | 1875 |
| INSTR_WORD_MOD | 1391 |
| POST_EXEC_PC_MOD | 484 |
| Tier-1 hidden | 0 |
| **Deduped jobs** | **1022** (538 INSTR_WORD_MOD + 484 POST_EXEC_PC_MOD) |

Deduped breakdown (ISS-4: IWM per `(variant,step)`; PEPC per `(variant,step,iter_seed)`):

| variant | INSTR_WORD_MOD | POST_EXEC_PC_MOD |
|---------|---------------:|-----------------:|
| V6_cTS | 194 | 143 |
| V6_uniform | 303 | 341 |
| Hybrid_cTS | 41 | 0 |

Artifacts:
- `triage_at_scale_b4/d2g_triage_rerun_manifest.csv`
- `triage_at_scale_b4/d2g_triage_rerun.chain` (1022 jobs, 1022 unique run_ids)
- `triage_at_scale_b4/d2g_triage_at_scale_report.json`

Post-fix smoke (3 jobs on regenerated manifest): cosmetic / weak / noop — live classifier confirmed.

### 1.2 Repo-sync + POS dispatch ❌ NOT RUN FROM HERE

- SSH to `flare` (and other nodes) **times out** from this environment.
- **Operator action required:**
  1. Sync `/root/a4_campaign/repo` on all 8 nodes to commit containing F22–F27 + `run_one` + ISS-4 dedup
  2. Verify `/root/a4_campaign/bin/risc0-host` exists on each node; verify hash of `propagation_triage.py`
  3. Dispatch: `chain_dispatcher.sh triage_at_scale_b4/d2g_triage_rerun.chain`
  4. **Gather** all 8 nodes' `/tmp/d2g_triage_results/*.json` into one directory, then:
     `python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale collect <merged_dir> --out d2g_accept_triage_all_variants.csv`

**Confirmed:** chain jobs call live `run_one` → `tier2_classify` → `classify_semantics` (no cache).

---

## Item 2 — Provisional soundness re-read (INCOMPLETE)

Full Item 2 requires Item 1 completion. Below is **smoke-sample only** (n=10, V6_uniform seed1234 only).

### Smoke sample (n=10)

| class | count |
|-------|------:|
| accepted_noop | 8 |
| accepted_propagated_candidate | 2 |

### Divergent residue (smoke)

**Count: 0** — no `evidence=strong` rows; no non-weak POST_EXEC_PC_MOD propagated.

Weak INSTR_WORD_MOD rows in smoke (not soundness leads until D3):
- step 70: fault `4291196435=>3217454611`
- step 3415: fault `1488531=>35042963`

### Structural expectations (DB-level, triage-independent)

- Raw accepts: **1875** — unchanged regardless of classifier version
- POST_EXEC_PC_MOD: **484** — expect **mostly `cf_inert` noop** after full retriage
- Soundness lead = **divergent residue only** (`strong` or non-weak POST_EXEC_PC_MOD propagated)
- Hybrid: **0 POST_EXEC_PC_MOD** accepts (kind list excludes it — definitional, not evidentiary)

### Provisional Case (coverage — unchanged from B3)

Still **Case A directionally on locs+CGC** at n=2 — but **soundness Case must wait** for full triage + batch-2. Paired p-values remain `nan`.

Helper added: `soundness_reread.py` for post-collect aggregation.

---

## Item 3 — STOP ✅

Batch-2 (seed 1236) campaign jobs not finished / not pulled. No fabricated n≥3 statistics.

---

## Tests

| suite | result |
|-------|--------|
| `test_propagation_triage_unit.py` + `test_triage_semantics.py` | 22 passed |
| `test_triage_at_scale.py` (A4_REAL_BINARY=1) | 1 passed |
| B2 smoke oracle (prior session, 8/0/0 F22/F24) | unchanged |

---

## Files changed (this session)

| file | change |
|------|--------|
| `triage_at_scale.py` | `run_one`, `collect`, `smoke`, `--tier2-variant all`, POS host |
| `test_triage_at_scale.py` | Item 0 smoke test |
| `soundness_reread.py` | Item 2 aggregation helper |

---

## Next steps (operator)

1. **Commit + push** this branch; sync repo on all POS nodes
2. **Dispatch** `d2g_triage_rerun.chain` (1022 jobs)
3. **Collect** → `d2g_accept_triage_all_variants.csv`
4. Run `soundness_reread.py` on full CSV → update Case on **soundness counts**
5. When batch-2 lands → final Case at n≥3

---

## Stale artifacts — do not use

| path | reason |
|------|--------|
| `triage_at_scale/d2g_accept_triage_tier2_sample.csv` | Pre-F22/F24, Hybrid-only |
| `triage_at_scale/d2g_triage_at_scale_report.json` | Stale evidence counts |

Use `triage_at_scale_b4/` manifest + post-POS collect output instead.
