# D2.G Full-Campaign Triage — Composer Report (COMPLETE)

**Date:** 2026-06-21  
**Author:** Composer (takeover after dual-Composer stop)  
**Spec:** [`IV_POS_8_D2_G_SPEC.md`](../IV_POS_8_D2_G_SPEC.md) · Kickoff: [`D2G_FULL_TRIAGE_KICKOFF.md`](D2G_FULL_TRIAGE_KICKOFF.md)  
**Status:** **COMPLETE** — ready for Opus-CP review (soundness-count Case read below)

---

## Executive summary

Full POS triage finished successfully: **1423/1423 deduped reruns OK**, collected locally, manifest completeness **1423/1423 (ISS-5 PASS)**. Smoke oracle **8/0/0 PASS** (pytest + deduped prod cross-check). **Zero strong divergent residue.** Soundness signal is entirely **110 weak `accepted_propagated_candidate`** rows (108 INSTR_WORD_MOD + 2 POST_EXEC_PC_MOD); no `strong` evidence anywhere.

**Headline for Opus:** POST_EXEC_PC_MOD is **731/733 cf_inert** (99.7%); the 2 weak PEPC rows show **no post-inject PC/trace divergence** — not soundness leads under F27 criteria. Hybrid has **zero PEPC accepts** (100% INSTR_WORD_MOD as expected). The Case read on soundness counts supports **coverage/territory as the headline**, not soundness alarm.

---

## Dispatch results

| Metric | Value |
|---|---|
| Manifest | `triage_at_scale_full/` — 1423 deduped jobs, seeds **1234/1235/1236** ✅ |
| Nodes | flare polynize octorand opulous algofi zone gard goracle (8/8) |
| Chain | 178 batches, **1423 OK**, 0 failures |
| Wall time | **57m20s** (17:49:19 → 18:46:39 UTC) |
| Per-job avg | **~2.4s** with warm `D2G_BASELINE_CACHE` |
| Log | `/tmp/d2g_triage_chain_v3.log` on coinbase |

---

## Collect + validation gates

| Gate | Result |
|---|---|
| Gather | 1425 JSON on disk (2 stale extras from prior partial runs) |
| Manifest completeness (ISS-5) | **1423/1423, 0 missing** ✅ |
| Smoke oracle (pytest, real binary) | **8/0/0 PASS** (315s) |
| Smoke oracle (deduped prod cross-check) | **8/0/0**, step 3939 = `word_truncated` ✅ |
| tier1 hidden_global_reject | **0** (from manifest build) |
| Divergent residue (`strong`) | **0** |

**Deliverables (local):**
```
a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full/
  d2g_accept_triage_all_variants.csv      ← 1425 rows (1423 manifest-matched)
  d2g_triage_collect_report.json
  d2g_soundness_reread.json
  d2g_soundness_reread.md
```

---

## Per-variant class / evidence distribution (manifest-matched, n=1423)

### Overall class counts

| class | count |
|---|---|
| `accepted_noop` | 1313 |
| `accepted_propagated_candidate` | 110 |
| `accepted_hidden_global_reject` | 0 |

### Overall evidence counts

| evidence | count | meaning |
|---|---|---|
| `cf_inert` | 731 | POST_EXEC_PC_MOD provably inert (F27) |
| (empty) | 244 | INSTR_WORD_MOD byte-identical disasm |
| `cosmetic` | 198 | branch target-only change, not taken |
| `word_truncated` | 140 | full-word store/load, same word address |
| `weak` | 110 | propagated candidate (fail-safe tier) |

### By variant × kind × class (aggregated)

| variant | kind | noop | propagated | cf_inert | weak |
|---|---|---:|---:|---:|---:|
| Hybrid_cTS | INSTR_WORD_MOD | 146 | 18 | 0 | 18 |
| V6_cTS | INSTR_WORD_MOD | 288 | 48 | 0 | 48 |
| V6_cTS | POST_EXEC_PC_MOD | 213 | 2 | 213 | 2 |
| V6_uniform | INSTR_WORD_MOD | 148 | 42 | 0 | 42 |
| V6_uniform | POST_EXEC_PC_MOD | 518 | 0 | 518 | 0 |

Hybrid: **164 accepts triaged**, all INSTR_WORD_MOD (no PEPC by design).

---

## POST_EXEC_PC_MOD cf_inert vs residue split (the soundness lead)

| bucket | count | notes |
|---|---|---|
| **cf_inert** (noop) | **731 / 733** (99.7%) | Identical post-inject PC stream — matches INV1/INV2 expectation |
| **weak propagated** | **2** | V6_cTS only; seeds 1234 + 1235, both step 3961 |
| **strong** | **0** | No divergent residue |

**The 2 weak PEPC rows (only non-cf_inert PEPC):**

| variant | seed | step | iter_seed | post_inject_pc_changed | post_inject_trace_changed |
|---|---|---:|---:|---|---|
| V6_cTS | 1234 | 3961 | 1234009820 | False | False |
| V6_cTS | 1235 | 3961 | 1235000175 | False | False |

These are **`weak` fail-safe**, not `strong` — no post-inject divergence detected. **Not soundness leads** under F27/Opus criteria. Opus should confirm whether step-3961 PEPC at campaign scale warrants manual inspection or is expected edge-case routing to `weak`.

V6_uniform PEPC: **518/518 cf_inert**, zero residue.

---

## INSTR_WORD_MOD propagated residue (108 weak, 0 strong)

All 108 INSTR_WORD_MOD `accepted_propagated_candidate` rows carry **`weak` evidence** only — sub-word / unconfirmed-alignment fail-safe (F23). Zero `strong`. By variant:

| variant | weak propagated |
|---|---:|
| Hybrid_cTS | 18 |
| V6_cTS | 48 |
| V6_uniform | 42 |

These are **expected triage noise**, not confirmed soundness violations — consistent with F24 fail-safe design.

---

## Soundness-count Case read (provisional, for Opus)

**Soundness signal:** ~0. All 110 propagated rows are `weak`; zero `strong`; PEPC divergent residue = 0 under F27 definition.

**Implication for Case A–E gate:** Re-read using soundness-candidate counts should **not** flip the coverage-led Case A read. Hybrid's exclusion of POST_EXEC_PC_MOD is **moot** — those accepts are no-ops anyway (731/733 cf_inert).

**Coverage read** (separate, already provisional from B1 metrics refresh): unchanged by this triage — locs/CGC territory metrics stand.

**Paired stats n=3 seeds:** Not yet computed this session — B1 metrics CSVs refreshed locally; paired stats still pending (was `nan` at n=2).

---

## What Opus got right (confirmed)

| Opus finding | Outcome |
|---|---|
| `triage_at_scale_b4` was batch-1 only | Confirmed — wrong manifest |
| Full manifest = 1423 deduped, all 3 seeds | Confirmed |
| 8-node D2.F campaign dispatch (not local, not 5-node pool) | Done correctly |
| POST_EXEC_PC_MOD → mostly cf_inert | **731/733 (99.7%)** |
| Applied rate ~0.94 not a cTS bug | Unchanged — gate 12/12 PASS |
| D2G_BASELINE_CACHE ~2× speedup | **~2.4s/job** vs ~45–60s without cache |
| Do NOT re-run 12-job campaign | Honored |

---

## Bugs found and fixed (this session)

| # | Bug | Fix | Commit |
|---|---|---|---|
| 1 | argparse REMAINDER swallowed `--run-id` | Arg order in `write_chain_manifest()` | `e35413b` |
| 2 | `set -u` unbound `$D2G_BASELINE_CACHE` in launcher echo | Literal path in mkdir | `ce0b485` |
| 3 | coinbase no pandas | Gather via bash SCP on coinbase; collect/soundness locally | operational |
| 4 | coinbase can't git pull | SCP deploy of changed files | operational |

---

## Open flags for Opus-CP

1. **2 weak PEPC at step 3961** — inspect or accept as fail-safe? No post-inject divergence; not `strong`.
2. **2 stale JSON extras** on nodes (1425 gathered vs 1423 manifest) — harmless; consider `rm /tmp/d2g_triage_results/*.json` before future runs.
3. **Lazy pandas import** for `triage_at_scale.py` still not committed — gather/collect module import fails on coinbase without pandas. Recommend commit for POS portability.
4. **Paired stats n=3** — still TODO after Opus triage review.
5. **Pro-facing report** — blocked until Opus reviews this output.

---

## Disagreements

**None on Opus analysis or directives.**

---

## Handoff checklist for Opus-CP

- [x] Dedup rerun count: **1423**
- [x] Per-variant class/evidence distribution (tables above)
- [x] PEPC cf_inert vs residue: **731 cf_inert / 2 weak / 0 strong**
- [x] Smoke oracle: **8/0/0**
- [x] Divergent residue list: **empty**
- [ ] Opus review → authorize Pro-facing report
- [ ] Paired stats n=3 seeds
