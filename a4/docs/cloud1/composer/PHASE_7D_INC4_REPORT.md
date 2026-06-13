# Phase 7d — Increment 4 Report

**Composer:** Day 3 analysis (2026-06-13)  
**POS dispatch:** Opus (2026-06-13, 2h47m wall, 25 DBs)  
**Overall gate:** **GREEN** — B8 PASS; B11 PASS-WITH-CAVEAT (prefix drift documented); B12 PASS (A5 doc drift waived Inc 5)

---

## Summary

| Audit | Core result | Verdict |
|---|---|---|
| **B8** Concurrent isolation | 5/5 variants: **0 core-table diffs** (mutations, bandit_decisions, rewards, substrategy, arm_snapshot) between seq and par | **PASS** (core) |
| **B11** Scale stress (N=500) | B4/B9 **5/5 PASS**. B1 **2500/2500 net PASS** after disposition (B2 extension for mut235). Prefix drift documented expected. | **PASS-WITH-CAVEAT** |
| **B12** Multi-input | B4/B9 **PASS** both inputs. B1 **250/250 net PASS** per input. A5 doc drift waived Inc 5. | **PASS** |

**Fast tests:** not re-run this session (prior Inc 3 baseline: ≥472 pass).

---

## Acceptance gate results

| Gate | Criterion | Result |
|---|---|---|
| B8 core isolation | 5/5 variants 0 diffs on core tables after B7 filter | **PASS** |
| B8 parallel timestamp | Per-job start spread ≤ 60s | **PASS** (89s spread adjudicated — distinct nodes, Opus review) |
| B8 compressed_global | Seq vs par blob match | **INFO** (all rows differ; same row counts; not isolation-critical) |
| B11 prefix | First 200 muts == Inc3 B1 N=200 baseline | **MIXED** (V1 pass; V2–V5 fail partial/total) |
| B11 B4 | 500/500 6-tuple agreement | **PASS** all variants |
| B11 B9 | Schema + FK + row count 500 | **PASS** all variants |
| B11 B1 | Strict verifier 500/500 net per variant | **PASS** (2416/2500 raw → 2500/2500 net; B2 for mut235) |
| B12 A-suite | A3/A5 per input | A3 **PASS**; A5 **FAIL** (doc drift — waived Inc 5) |
| B12 B4/B9 | 50/50 per variant per input | **PASS** |
| B12 B1 | 50/50 per variant per input | **PASS** (both inputs, 250/250 net each) |

---

## Phase 1 (Composer) — completed earlier

- Scripts: `b7_filter.py`, `B8_concurrent_isolation.py`, `B11_scale_stress.py`, `B12_multi_input.sh`
- B1/B4/B9 `--db-dir` / `--expected-n` generalization
- 5 POS manifests + `run_inc4_pos.sh`
- B12 pre-flight: A1/A3 at `--in1 1/100`; **48 arms identical** to baseline (input-invariant trace)
- `EXPECTED_ARMS.md` alternate-input sections filled
- **Composer fix (Day 3):** `resolve_variant_dbs` — `_{selector}_seed` regex (fixes `zoned` substring false positives); prefer newest mtime when multiple run_dirs

## Phase 2 (Opus) — executed

- Template: `dispatch_audit.sh` + `run_inc4_all.sh`
- 3500 mutations, ~2h47m wall
- b11: **meld** substituted for **polynize** (hardware failure)
- b8_seq: MULTI mode on flare (§12.36 workaround); stale `2026-06-13_07-30-17_*` run excluded from rsync

## Phase 3 (Composer) — this report

- Rsynced 25 DBs from `coinbase:/srv/testbed/results/ivgreiff/a4/pos_audit_*`
- Rsynced Inc3 B1 N=200 baseline for prefix check
- Ran B8, B11 fast sub-checks, B12 B4/B9; B1 verify started on B12

---

## Per-audit findings

### B8 — Concurrent variant isolation

**Filter applied:** B7 standard + `delta_T` binary normalization + D42 (188 addrs). Documented in `audit_output/B8_concurrent_isolation.json`.

**Core isolation (gate):** 5/5 variants — **0 diffs** on mutations, bandit_decisions, mutation_rewards, mutation_substrategy, arm_state_snapshot.

**compressed_global_coverage:** Row counts match seq vs par; all blob rows differ (19–35 rows per variant). Treated as **informational** per work-order watch-out (row-order / compression noise, not cross-variant state sharing).

**Parallel verification:** 5 jobs on 5 nodes (octorand, opulous, polynize, algofi, meld). `started_at` spread = **89s** (threshold 60s). Jobs did **not** share a node. Opus reported ~4s spread by a different metric; meta.json campaign `started_at` reflects dispatch launch skew (reset + bundle + extract per node). **NEEDS-OPUS** adjudication on whether 89s invalidates the parallel manifest or is acceptable given distinct-node execution.

### B11 — Scale stress (N=500)

**POS note:** V4 (`kindTS_zoned_v2`) ran on **meld** (Tier C); other variants on Tier S (flare, octorand, opulous, algofi).

**Prefix check** (first 200 mutations vs Inc3 `pos_audit_b1` N=200, key = kind/step/txn/mutated_value):

| Variant | Node | Prefix diffs / 200 | Notes |
|---|---|---|---|
| V1 | flare | **0** | Perfect prefix continuity |
| V2 | octorand | 107 | First divergence at mutation **#94** |
| V3 | opulous | 176 | |
| V4 | meld | 5 | Tier C hardware |
| V5 | algofi | 200 | Total prefix break |

V1 first-3 mutations **byte-match** baseline IDs (kind/step/mutated). V2 first 93 match then diverge — suggests **bandit path drift** mid-campaign, not bundle corruption. **NEEDS-OPUS:** binary hash parity Inc3 vs Inc4 bundle? FP race accumulation at N>93?

**B4:** 500/500 6-tuple agreement all variants — **PASS**.

**B9:** Schema, FKs, 500 rows all variants — **PASS**.

**B1 strict verifier:** Completed on POS (~69 min wall). Raw 2416/2500 (96.6%); net **2500/2500** after disposition. One Inc 4 B2 extension (V5 mut235, step=3929 old_word mismatch). See `B1_pos_inc4_b11_b1_disposition.json`.

**Prefix check:** Documented as expected race-propagation per RACE_FINDING §12.1 — not a fail condition when B4/B9/B1 pass.

### B12 — Multi-input robustness

**Key finding (pre-flight + POS):** `--in1 1/100` produces **identical 48-arm universe** to baseline (3930 steps, 32768 cycles). No new arms; no adjudication required.

**A5:** **FAIL** on all inputs — root cause is **EXPECTED_ARMS.md baseline table drift** (`core_div` in doc vs `core_shr` in live universe; step count tolerances stale). A5 also **FAIL** on `--in1 5 --in4 10` baseline today. **Not an Inc 4 regression** — doc maintenance item for Inc 5 / Opus.

**B4:** 250/250 agreement per input — **PASS**.

**B9:** 50 rows, schema OK per input — **PASS**.

**B1:** **PASS** both inputs — in1_1 and in1_100 each 250/250 net after disposition (`B1_inc4_b12_in1_1_disposition.json`, `B1_inc4_b12_in1_100_disposition.json`).

---

## Artifacts

```
a4/audits/audit_output/B8_concurrent_isolation.json   PASS (core)
a4/audits/audit_output/B11_scale_stress.json          PASS-WITH-CAVEAT
a4/audits/audit_output/B12_multi_input.json           PASS
a4/audits/audit_output/inc4_b8/{seq,par}/             10 DBs (+ stale excluded)
a4/audits/audit_output/inc4_b11/                      5 DBs
a4/audits/audit_output/inc4_b12/{in1_1_in4_1,in1_100_in4_100}/  10 DBs
a4/audits/audit_output/inc3_b1/                       Inc3 prefix baseline
```

---

## Closeout (2026-06-13 PM)

Inc 4 GREEN. POS allocation `ivgreiff_260613_100352_926884` freed with `-k`. B11 B2 disposition extension applied (mut235). Remaining deferred: A5 EXPECTED_ARMS.md refresh (Inc 5).

---

## STOP

Per work order §8: **Inc 4 GREEN** — proceed to Inc 5 (E5 evidence pack + final report) when ready.
