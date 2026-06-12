# Phase 7d Inc 3d Phase B — Composer POS capture report

**Date**: 2026-06-12  
**Owner**: Composer  
**Git**: `1c67a0b` (coinbase, post-pull)  
**Host**: `632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`  
**Bundle**: `~/INC3D_B_BUNDLE.tar.gz` on coinbase  
**Calendar**: entry **1726** (`octorand + opulous + meld + flare`, 6h window)

---

## Executive summary

| Item | Status |
|------|--------|
| Pass 1 dispatch (verbose + B2 trace) | **COMPLETE** (~28 min wall) |
| Pass 2 dispatch (B3 only, no verbose) | **COMPLETE** (~24 min wall) |
| Artifact collection (10+10 DBs, 10+10 logs) | **COMPLETE** |
| B1 self-id attrs in logs | **PASS** (49–50 tags/run, 100% with `mut="…"`) |
| B2 `<a4_ftw>` trace passthrough | **PASS** (~22k lines/run, ~10 MB logs) |
| B3 `<a4_ftw291_95_count>` passthrough | **PASS** (both passes; non-zero when FTW291 touched) |
| Octorand race reproduction | **NOT THIS RUN** (0/100 reward diffs both passes) |
| Verbose-perturbation hypothesis (P1 vs P2) | **INCONCLUSIVE** — races still occur without verbose (P2 meld mut 5) |

**Hand back to Opus** for `B7_verbose_touch.py` B1-attr parsing and B2 trace analysis on flare P1 mut 30 (confirmed FTW291 alignment).

---

## Dispatch metadata

```
Pass 1: INC3D_PASS=1 SPREAD=1  campaign=pos_inc3d_phase_b_p1
        A4_COVERAGE_TOUCH_VERBOSE=1  A4_FTW291_TRACE=1  A4_MUTATION_SHA256=per-mut (executor)
Pass 2: INC3D_PASS=2 SPREAD=1  campaign=pos_inc3d_phase_b_p2
        (no verbose, no FTW trace; B3 counter only)
```

Coinbase logs: `~/inc3d_p1_dispatch.log`, `~/inc3d_p2_dispatch.log`  
Node dispatch logs: `~/inc3d_out_p1/{octo,opulous,meld,flare}.log`, `~/inc3d_out_p2/…`

---

## Artifacts (local)

```
a4/audits/audit_output/inc3d/
  p1/   # Pass 1 — 10 × .db + .log
  p2/   # Pass 2 — 10 × .db + .log
  inc3d_analysis_summary.json
```

Remote POS paths:
- `/srv/testbed/results/ivgreiff/a4/pos_inc3d_phase_b_p1/`
- `/srv/testbed/results/ivgreiff/a4/pos_inc3d_phase_b_p2/`

---

## Section 1 — Instrumentation sanity

### Pass 1 (verbose + B2)

| Check | Result |
|-------|--------|
| Log size per run | ~10 MB (not 100 MB; B2 present but smaller than worst-case estimate) |
| `<a4_touch_verbose>` open tags | 49 (most nodes) or 50 (opulous) per run |
| Tags with B1 `mut="…"` attr | **100%** of verbose open tags |
| B1 sample | `mut="79b099973d91103a…"` (sha256), `pid="…"`, `seq="0"` |
| `<a4_ftw cycle=…>` lines | ~22,344 per 50-mut run |
| `<a4_ftw291_95_count>` tags | 98 per run (49 muts × witgen+accum) |
| Launcher confirms | `[run_campaign_pos] A4_COVERAGE_TOUCH_VERBOSE=1` + `A4_FTW291_TRACE=1` |

### Pass 2 (B3 only)

| Check | Result |
|-------|--------|
| Log size | ~0.1 MB (no verbose, no B2 — as expected) |
| Verbose tags | **0** |
| B3 counter tags | **98–100** per run (still emitted) |
| B2 lines | **0** |

---

## Section 2 — Pair reward-diff summary

### Pass 1

| Pair | Node | Racy rows | ΔT flips | Racy mut IDs | Kind |
|------|------|-----------|----------|--------------|------|
| α (octoa) | octorand | 0 | 0 | — | — |
| β (octob) | octorand | 0 | 0 | — | — |
| opulous | opulous | 0 | 0 | — | — |
| meld | meld | 0 | 0 | — | — |
| flareCtrl | flare | **1** | **1** | **30** | `INSTR_WORD_MOD_FULL` step=3541 |

### Pass 2

| Pair | Node | Racy rows | ΔT flips | Racy mut IDs | Kind |
|------|------|-----------|----------|--------------|------|
| α (octoa) | octorand | 0 | 0 | — | — |
| β (octob) | octorand | 0 | 0 | — | — |
| opulous | opulous | 0 | 0 | — | — |
| meld | meld | **1** | **1** | **5** | `PRE_EXEC_REG_MOD` step=834 |
| flareCtrl | flare | 0 | 0 | — | — |

### Comparison with Inc 3c (same SPREAD plan, host `c2e77443…`)

| Pair | Inc 3c racy | Inc 3d P1 | Inc 3d P2 |
|------|-------------|-----------|-----------|
| alpha | 1 (mut 27) | 0 | 0 |
| beta | 0 | 0 | 0 |
| opulous | 0 | 0 | 0 |
| meld | 2 | 0 | 1 (mut 5) |
| flareCtrl | 2 | 1 (mut 30) | 0 |

Race is **intermittent** (~1/50 rate); octorand did not fire this session.

---

## Section 3 — B3 / verbose alignment (key proof for Opus)

### Flare Pass 1 — mut 30 (only ΔT flip)

Triple correlation without fuzzy block-index guessing:

| Signal | Value |
|--------|-------|
| Reward diff | `mutation_id=30`, `delta_T` 0→1 |
| B3 counter | `flareCtrlB` witgen `value="1"` at **mutation index 28** (0-based) |
| Verbose symdiff | block **[28]**: extra `('FieldToWord(…/inst_p2.zir:291)', 9, 5)` on B vs A |

Same `(loc, major, minor)` family as Inc 3c clustering. B1 attrs + B3 index confirm block 28 ↔ mut 30 ↔ FTW291 touch.

### Meld Pass 2 — mut 5

| Signal | Value |
|--------|-------|
| Reward diff | `mutation_id=5`, `PRE_EXEC_REG_MOD`, `delta_T` 1→0 |
| B3 counter | `melddA` witgen `value="1"` at index **6** (~mut 4–5) |
| Verbose | N/A (Pass 2 — no verbose blocks) |

Suggests race can manifest on non-FTW291 mutations (or B3 index mapping off-by-one near mut 5). Opus to adjudicate.

### Octorand (both passes)

All B3 counters `value="0"` on all 200 octorand mutations — **no FTW291@9,5 touch divergence captured** this run.

---

## Section 4 — Pass 1 vs Pass 2 (verbose perturbation test)

**Question**: Does the race require `std::set<std::string>` verbose tracking?

| Observation | Implication |
|-------------|-------------|
| P1 flare racy at mut 30 (with verbose) | Race observed with verbose ON |
| P2 flare **clean** (no verbose) | Not a simple "verbose always triggers race" |
| P2 meld **racy** at mut 5 (no verbose) | Race **still occurs** without verbose perturbation |
| P1 octorand clean, P2 octorand clean | No octorand data point this session |

**Provisional**: verbose `std::set` is **not necessary** for race manifestation (P2 meld counterexample). P1 vs P2 diff rates on same pair are not directly comparable because races are low-rate and pair-mates are independent stochastic draws.

---

## Section 5 — Open items for Opus

1. **Update `B7_verbose_touch.py`** to parse B1 `mut=` / `seq=` attrs — flare P1 mut 30 is the golden alignment case.
2. **Mine B2 `<a4_ftw>` traces** on `flareCtrlA` vs `flareCtrlB` at mut 30 for `(arg0, low, high)` divergence.
3. **Octorand re-run** may be needed — 0/200 this session vs Inc 3c 1/100; race is intermittent.
4. **Meld P2 mut 5** — `PRE_EXEC_REG_MOD` with B3 nonzero but different kind than Inc 3c meld hits; investigate whether this is same mechanism or unrelated jitter.
5. **Block index convention**: B3 index 28 ↔ DB `mutation_id=30` ↔ verbose block 28 — confirm whether baseline consumes mutation 1 (49 verbose blocks / 50 muts pattern persists with B1 attrs).

---

## Section 6 — File index for review

| Path | Contents |
|------|----------|
| `a4/audits/audit_output/inc3d/p1/*.log` | Pass 1 campaign logs (verbose + B2 + B3) |
| `a4/audits/audit_output/inc3d/p2/*.log` | Pass 2 campaign logs (B3 only) |
| `a4/audits/audit_output/inc3d/p1/*.db` | Pass 1 SQLite reward DBs |
| `a4/audits/audit_output/inc3d/p2/*.db` | Pass 2 SQLite reward DBs |
| `a4/audits/audit_output/inc3d/inc3d_analysis_summary.json` | Machine-readable pair summary |
| `a4/docs/cloud1/composer/PHASE_7D_INC3D_B_COMPOSER_REPORT.md` | This report |

**No dispatch anomalies** (no SIGSEGV, no calendar misses, all 20 runs awaited successfully).
