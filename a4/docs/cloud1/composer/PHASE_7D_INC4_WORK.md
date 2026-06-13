# Phase 7d — Increment 4 Work Order

**Purpose:** run the 3 POS audits that prove the architecture works at SCALE and under PARALLEL EXECUTION (Phase 8's actual operating regime). These are the last fidelity gates before Inc 5 (E5 evidence pack + final report) and Phase 8 launch.

**Owner:** Composer
**Reviewer:** Opus
**Estimated time:** ~1-1.5 days (mostly POS wall + ~6 hours of script writing + ~2 hours of report writing)
**Predecessor:** Inc 3 CLOSED (B1 PASS-with-exclusions 963/963 effective; B2/B4 PASS; B7 CLOSED with documented Poseidon2 race — see `composer/PHASE_7D_INC3_FINAL_REPORT.md` and `RACE_FINDING_AND_OPEN_QUESTIONS.md`)
**Gate to Inc 5:** all 3 audits PASS + report-back accepted

---

## ⚡ STATUS — Phase 2 POS dispatch executed (Jun 13 2026, by Opus)

**All 25 DBs landed on POS. Composer: skip to Day 3 (analysis + report).** ✓

| Audit | DBs on POS | Mut counts | Notes |
|---|---|---|---|
| `pos_audit_b8_seq` | 5 (each in own `<run_dir>/flare/`) | 50 × 5 | Dispatched via MULTI mode (5 sub-dispatches on flare; per POS_PLAYBOOK §12.36 workaround). The stale `2026-06-13_07-30-17_002685/flare/cTS_semantic_v2.db` (muts=250) is from the BROKEN pre-template run; **EXCLUDE from analysis** (newest 5 run_dirs only). |
| `pos_audit_b8_par` | 5 (in `<run_dir>/<node>/`) | 50 × 5 | Parallel timestamps within 4 sec — true parallel ✓ |
| `pos_audit_b12_in1_1_in4_1` | 5 | 50 × 5 | Same template, SINGLE mode |
| `pos_audit_b12_in1_100_in4_100` | 5 | 50 × 5 | Same |
| `pos_audit_b11` | 5 | 500 × 5 | **`meld` substituted for `polynize`** (polynize hit `NodeDidNotBoot` mid-reset, see POS_PLAYBOOK §12.45). meld variant = `kindTS_zoned_v2` on Tier C — slightly different hardware than the other 4 Tier S nodes; flag in report. |

**Canonical dispatch template** (use for any future audit — auto-handles single + multi mode):
```bash
bash a4/pos/dispatch_audit.sh <manifest.json> <node1> [node2] ...
```

**Orchestrator that drove this run** (sequential, fire-and-forget under nohup/tmux):
```bash
bash a4/pos/run_inc4_all.sh
```

Logs at `coinbase:/tmp/inc4_logs/`. Master log at `/tmp/inc4_logs/run_inc4_all.log`. Per-dispatch logs at `/tmp/inc4_logs/<manifest_stem>{__<variant>}.log`.

**Calendar coverage**: entries 1747 (07:53→13:53 UTC, used) + 1748 (13:53→19:53 UTC, safety net per §12.40 still active — free with `pos calendar delete --id 1748 <node>` per node once analysis is complete).

**Composer Day 3 sequence** (skip Day 1 + 2):
1. WSL rsync DBs back (use `--exclude '2026-06-13_07-30-17_*'` for b8_seq to skip the stale broken DB):
   ```bash
   cd /root/arguzz
   RSYNC="rsync -av --partial -e 'ssh -p 10022' ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4"
   mkdir -p a4/audits/audit_output/inc4_b8/{seq,par}
   mkdir -p a4/audits/audit_output/inc4_b11
   mkdir -p a4/audits/audit_output/inc4_b12/{in1_1_in4_1,in1_100_in4_100}
   eval "$RSYNC/pos_audit_b8_seq/ a4/audits/audit_output/inc4_b8/seq/ --exclude '2026-06-13_07-30-17_*'"
   eval "$RSYNC/pos_audit_b8_par/ a4/audits/audit_output/inc4_b8/par/"
   eval "$RSYNC/pos_audit_b11/ a4/audits/audit_output/inc4_b11/"
   eval "$RSYNC/pos_audit_b12_in1_1_in4_1/ a4/audits/audit_output/inc4_b12/in1_1_in4_1/"
   eval "$RSYNC/pos_audit_b12_in1_100_in4_100/ a4/audits/audit_output/inc4_b12/in1_100_in4_100/"
   ```
2. Run analyzers (`B8_concurrent_isolation.py`, `B11_scale_stress.py`, `B12_multi_input.sh`). `audit_common.py:resolve_variant_dbs` was patched to use `rglob` so the POS `<run_dir>/<node>/` layout is walked correctly.
3. Write `PHASE_7D_INC4_REPORT.md` with the meld-substitute note for b11.

---

---

## 0. Required reading (DO FIRST)

1. `a4/docs/cloud1/phases/PHASE_7D_ARCHITECTURE_AUDIT.md` §§ B8, B11, B12, §6 (multi-guest plan)
   — Per-audit specs. Each audit's "Goal / Why it matters / Acceptance gate / Script name" is canonical there.

2. `a4/docs/cloud1/composer/PHASE_7D_INC3_FINAL_REPORT.md` (specifically §3.4 race closure)
   — **CRITICAL**: documents the ~0.70% `delta_T` flip rate under default parallelism. B8's and B11's diff checks MUST account for this; see §3 of this doc for the exact filter to apply.

3. `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` §4, §8
   — Background on the race source (FieldToWord(inst_p2.zir:291) Poseidon2). You don't need to fix this; just inherit B7's filter rules in your diff logic.

4. `a4/docs/cloud1/composer/PHASE_7D_INC3_REPORT.md` §B7
   — The B7 filter rules you'll inherit: exclude `executed_at`, exclude 188 D42 non-det addresses, exclude `mutation_rewards.delta_T` flips that fit the Poseidon2 race signature.

5. `a4/docs/cloud1/composer/PHASE_7D_INC2_REPORT.md`
   — Inc 2 lessons: don't run host-heavy audits in parallel on the same node (E2 was starved by B5/B6/B9).

6. `a4/docs/cloud1/EXPECTED_ARMS.md`
   — Canonical arm matrix (HYBRID, 48 arms for baseline `--in1 5 --in4 10`). B12 will need to ADD two new sections for the alternate inputs (`--in1 1 --in4 1` and `--in1 100 --in4 100`); these sections exist as "TO BE FILLED" placeholders today.

7. `a4/docs/cloud1/composer/PHASE_7B_POS_GUIDE.md`
   — POS dispatch mechanics. **Required reading for B8/B11** if you haven't dispatched to POS recently.

8. `a4/audits/B1_hook_fidelity.py`, `a4/audits/B4_bandit_db_traceability.py`, `a4/audits/B9_db_schema_integrity.py`
   — B11 RE-RUNS these on its N=500 output DBs. B12 also re-runs B1 and B4. Make sure they accept a `--db-dir <path>` flag (or add one if they don't already; they were written to find DBs in `audit_output/inc3_b{1,4}/` by convention — generalize).

---

## 0.5 Chronology — WSL vs POS work split (HARD RULE: > 10 mutations → POS)

Any audit running more than 10 mutations MUST dispatch to POS. WSL is for trace/universe analysis, DB readers, smoke pre-validation, and report writing — not for bulk mutation campaigns.

### Day 1 — Script writing & B12 pre-flight (WSL only, ≤ 5 mutations)

| Step | Where | Mutations | What |
|---|---|---|---|
| 1.1 | WSL | 0 | Write `B8_concurrent_isolation.py` (~120 LOC) |
| 1.2 | WSL | 0 | Write `B11_scale_stress.py` (~150 LOC, integrates B1/B4/B9 re-runs) |
| 1.3 | WSL | 0 | Write `B12_multi_input.sh` (~60 lines) |
| 1.4 | WSL | 0 | Modify `B1_hook_fidelity.py` / `B4_bandit_db_traceability.py` / `B9_db_schema_integrity.py` to accept `--db-dir` flag |
| 1.5 | WSL | 0 | Write 5 POS manifests (b8_seq, b8_par, b11, b12 × 2 inputs) |
| 1.6 | WSL | 0 | B12 pre-flight: run A1 + A3 at alternate inputs (`--in1 1 --in4 1` and `--in1 100 --in4 100`). Both are pure trace/universe analyzers — A1 typically runs ≤ 2 paired traces (under the 10-mut threshold); A3 runs 0 host mutations |
| 1.7 | WSL | 0 | Manually adjudicate any new arms surfaced by A3 (E3-style mini-session); update `EXPECTED_ARMS.md` with the two filled alternate-input sections |
| 1.8 | WSL | ≤ 5 | Pre-validation smoke (5 mutations end-to-end) to confirm DB format + parser compatibility for B8/B11 audit scripts. Throwaway DB. |

### Day 2 — POS dispatch (ALL mutation-running on POS, 3500 muts total)

**Per-mutation wall on Tier S Zen 4 EPYC 9354 node** (Inc 3 B1 measured Jun 11): ~2.85 sec/mut (V1-V4), ~3.5 sec/mut (V5 cTS, variant-heavy because 48-arm constrained TS). Per-dispatch setup overhead: ~5 min (alloc/image/reset/bundle/extract). **Tier E nodes (`bitcoin*`, `litecoin*`) are 8-10× slower — DO NOT USE.** See "Node selection" §4 for the canonical playbook tier table.

| Step | Where | Mutations | POS wall (4 Tier S + 1 Tier C) | What |
|---|---|---|---|---|
| 2.0 | WSL → coinbase | — | ~5 min | Install Inc 3 baseline binary, build bundle, scp (see §4 "Bundle / binary selection") |
| 2.1 | **POS (5 nodes parallel)** | **250** | ~8 min | `pos_audit_b8_par`: 5 variants × N=50 SIMULTANEOUS on 5 different nodes (verify per-job start ts within 60 sec → true parallel). Tier C OK here. |
| 2.2 | **POS (1 Tier S node serial)** | **250** | ~18 min | `pos_audit_b8_seq`: 5 variants × N=50 SEQUENTIAL on `flare` (or any Tier S) |
| 2.3 | **POS (5 nodes parallel)** | **250** | ~8 min | `pos_audit_b12_in1_1_in4_1`: 5 variants × N=50 with `--in1 1 --in4 1`. Tier C OK. |
| 2.4 | **POS (5 nodes parallel)** | **250** | ~8 min | `pos_audit_b12_in1_100_in4_100`: 5 variants × N=50 with `--in1 100 --in4 100`. Tier C OK. |
| 2.5 | **POS (4 Tier S nodes parallel)** | **2500** | ~48 min | `pos_audit_b11`: 5 variants × N=500. **Tier S ONLY** — do not include `meld`/`tinyman` (Tier C bottlenecks V5 to ~70 min). |

**Day 2 POS total: 3500 mutations.** Wall time depends on Tier S node count actually allocated (Tier S = AMD EPYC 9354 Zen 4 only: `flare`, `octorand`, `opulous`, `polynize` per POS_PLAYBOOK §3.1):

| Allocation scenario | B11 wall (heaviest) | Total Inc 4 wall (serial in 1 calendar entry) |
|---|---|---|
| **4 Tier S nodes** (`flare octorand opulous polynize`) | ~48 min (1 node runs 2 variants; V1+V4 ≈ 48 min) | **~90 min** |
| **3 Tier S nodes** (one of polynize unavailable) | ~72 min (one node runs V1+V5 = 53 min OR V2+V3 = 48 min depending on order) | **~110 min** |
| **3 Tier S + 1 Tier A** (`algofi` substitutes for the 4th Zen 4) | ~50 min | **~95 min** |
| **3 Tier S + 1 Tier C** (`meld` substitutes — Tier C is ~3× slower) | **~70-75 min** (Tier C node bottlenecks on V5) — **NOT RECOMMENDED for B11** | ~115 min |
| **Tier E fallback** (`bitcoin*`/`litecoin*`) | ~6 hr | ~10 hr — **DO NOT USE** |

**`meld` and `tinyman` are Tier C (Intel Xeon Gold 6312U), NOT Tier S.** Confirmed via POS_PLAYBOOK §3.1. Acceptable for B8/B12 (N=50, ~7 min/variant on Tier C) but do NOT add them to B11's node list — round-robin assignment would put V5 (cTS, heaviest) on the slowest node and bottleneck the whole campaign.

**2-allocation parallel acceleration**: per POS_PLAYBOOK §12.37, the 2-cap is on CALENDAR ENTRIES, not nodes. If you reserve a SECOND multi-node entry on disjoint Tier S/A nodes, you can split B11 (allocation 1) from B8+B12 ×3 (allocation 2) and finish in ~50 min wall. Requires 8-10 Tier S/A nodes total, which is unlikely given current contention (POS_PLAYBOOK §3.1: 4 Tier S nodes exist total in the system).

**Dispatch order rationale**: B8_par first (cheapest + validates true parallelism early), then B8_seq (1-node bottleneck, OK to run while planning B11), then B12 ×2 (quick wins), then B11 (heaviest, last so a failure doesn't block earlier audits' DBs from being collected).

### Day 3 — Analysis & report (WSL only, 0 new mutations)

All B-audit "analyzers" are pure DB readers — they consume the POS-produced DBs and don't execute the host.

| Step | Where | Mutations | What |
|---|---|---|---|
| 3.0 | coinbase → WSL | — | scp 25 DBs back: 5 (b8_seq) + 5 (b8_par) + 5 (b11) + 5 (b12_small) + 5 (b12_large) |
| 3.1 | WSL | 0 | Run `B8_concurrent_isolation.py`: apply B7 filter (incl. delta_T binary normalization per §3 of this doc) + diff `seq_V*.db` vs `par_V*.db`. Emit `audit_output/B8_concurrent_isolation.json` |
| 3.2 | WSL | 0 | Run `B11_scale_stress.py`: re-run B1 strict verifier + B4 traceability check + B9 schema check on each N=500 DB; compute "deterministic prefix" check vs B1's N=200 baseline. Emit `audit_output/B11_scale_stress.json` |
| 3.3 | WSL | 0 | Run `B12_multi_input.sh`: for each alternate input, re-run A2/A4/A5 trace analyzers + B1/B4/B9 DB analyzers on the per-input DBs. Emit `audit_output/B12_multi_input.json` |
| 3.4 | WSL | 0 | Write `composer/PHASE_7D_INC4_REPORT.md`; STOP for Opus review |

**Day 3 total: 0 mutations; ~6-8 hours of analysis + writing.**

### Inc 4 grand total

- **POS mutations**: 3500 (B8: 500, B11: 2500, B12: 500)
- **WSL mutations**: ≤ 5 (pre-validation smoke only)
- **POS wall (5 nodes)**: ~3 hr total
- **WSL wall**: ~15-20 hours total (script writing + adjudication + analysis + report)
- **Calendar time**: ~3 days (1 writing + 1 POS + 1 analysis); could compress to 2 days if pre-flight + writing fits in one focused session

### Critical-path summary

```
[Day 1 WSL]
  Write scripts + manifests ──┐
                              ├──► Pre-validation smoke (≤ 5 muts, WSL) ──┐
  B12 pre-flight A-suite (0 muts, WSL) ──► Adjudicate new arms ──► Update EXPECTED_ARMS.md
                                                                              │
                                                                              ▼
[Day 2 POS]                                                                   │
  Bundle + scp ─► b8_seq ─► b8_par ─► b11 ─► b12 (×2 inputs)                  │
                  (serialize on POS to avoid B11 starving other dispatches)   │
                                                                              ▼
[Day 3 WSL]                                                                   │
  scp DBs back ─► B8 diff ─► B11 re-run ─► B12 re-run ─► Write INC4_REPORT.md ─► STOP for Opus review
```

---

## 1. Variant inventory (same as Inc 2/3)

| Phase-doc name | CLI `--selector` value | Bandit type | Reward | Arm space |
|---|---|---|---|---|
| V1 | `zoned` | uniform-over-buckets (legacy) | legacy multiplicative | (kind, bucket) |
| V2 | `kindUCB_zoned_v1` | UCB1 (undiscounted) | legacy multiplicative | kind only |
| V3 | `kindUCB_zoned_v2_noQ` | UCB1 (undiscounted) | v2 additive (no Q_loc) | kind only |
| V4 | `kindTS_zoned_v2` | Thompson Sampling (Beta) | v2 additive | kind only |
| V5 | `cTS_semantic_v2` | Constrained Thompson Sampling | v2 additive + Bernoulli success | **(kind, semantic_zone)** ← uses the 48-arm HYBRID universe |

All 3 Inc 4 audits run against all 5 variants. B8: N=50 ×2 modes (seq+par). B11: N=500. B12: N=50 × 2 alternate inputs.

---

## 2. The 3 audit tasks

### B8 — Concurrent variant isolation (POS)

**Files to write:**
- `a4/audits/B8_concurrent_isolation.py` (~120 LOC) — diff orchestrator
- `a4/pos/run_audit_B8_concurrent.sh` (~40 lines) — dispatch wrapper
- `a4/pos/manifests/pos_audit_b8_seq.json` (N=50, runs SEQUENTIALLY one at a time)
- `a4/pos/manifests/pos_audit_b8_par.json` (N=50, runs all 5 variants IN PARALLEL on 5 nodes)

**What it verifies:** running 5 variants in parallel on POS produces byte-identical DBs (modulo B7 filter) to running them sequentially. If parallel ≠ sequential, the variants are SHARING MUTABLE STATE (port collisions, shared temp dirs, shared bandit state files, RNG cross-talk) and Phase 8's 50-run × 10-seed × 5-variant parallel campaign would produce non-reproducible data.

**Mutation budget:** 5 variants × N=50 × 2 modes (seq + par) = **500 host mutations**. POS wall: ~30 min seq + ~30 min par = ~1 hr.

**Diff procedure (per variant V):**
1. Load `seq_V.db` and `par_V.db`.
2. Apply **B7 filter** to both (excludes `executed_at` + 188 D42 addresses + delta_T Poseidon2 flips):
   - Drop column `mutations.executed_at` from comparison.
   - Drop rows where `mutations.address` ∈ `audit_output/A1_nondet_addrs.json`.
   - **NEW for Inc 4** (race-aware): for `mutation_rewards`, normalize `delta_T` to a categorical "0 vs >0" before diff (this absorbs the ~0.7% Poseidon2 noise floor; aggregate reward sign is what matters for variant isolation).
3. Compare every other column byte-for-byte across:
   - `mutations` (kind, step, original_value, exit_code, failures, etc.)
   - `bandit_decisions` (mode, arm_id, prior_q, posterior_q, etc.)
   - `mutation_rewards` (after delta_T normalization)
   - `mutation_substrategy` (zone/bucket assignment)
   - `arm_state_snapshot` (every snapshot at the same mutation_idx should match)
4. ACCEPT if every column-wise diff is 0 (after filter).

**Acceptance gate:** 5/5 variants show 0 unfiltered diffs between `seq_V.db` and `par_V.db`. If any variant shows ≥ 1 diff that isn't filterable, STOP and dump the divergence record.

**Output file:** `audit_output/B8_concurrent_isolation.json`:
```json
{
  "_meta": {...},
  "filter_applied": {
    "executed_at_excluded": true,
    "d42_addresses_excluded_count": 188,
    "delta_t_normalized_to_binary": true,
    "reason_for_delta_t_normalization": "Inc 3 B7 closure: ~0.7% Poseidon2 race-noise floor on delta_T; aggregate sign is what isolation actually requires"
  },
  "per_variant": {
    "V1": {"mutations_diff": 0, "bandit_decisions_diff": 0, "mutation_rewards_diff": 0, "arm_state_snapshot_diff": 0, "pass": true},
    ...
  },
  "verdict": "PASS"
}
```

**Watch out:**
- The PARALLEL POS dispatch MUST actually run all 5 variants on 5 different nodes AT THE SAME TIME (not serial across one node). Check the manifest's `parallel: true` (or whatever POS calls it; see PHASE_7B_POS_GUIDE.md) is set correctly. If POS internally serializes the 5 jobs, your B8 audit measures NOTHING.
- Sanity check before launching: print the POS dispatch's per-job start timestamps; if they're within 60 seconds of each other for all 5 jobs in the parallel manifest, you're truly parallel.
- The shared temp dir bug class: variants writing to `/tmp/risc0-*` could collide. If diff fails on `compressed_global_coverage` row order, look for this.
- RNG cross-talk: if variants share a process-wide RNG (unlikely but possible), parallel runs could see different seeds. Each variant should use its own seeded RNG explicitly.

**Estimated time:** 4 hr write (audit + 2 manifests + wrapper) + ~1 hr POS wall + 1 hr post-processing.

---

### B11 — Scale stress (POS)

**Files to write:**
- `a4/audits/B11_scale_stress.py` (~150 LOC) — runs B1/B4/B9 re-runs on N=500 DBs + computes the "deterministic prefix" check vs N=50 baseline
- `a4/pos/manifests/pos_audit_b11.json` (N=500, 5 variants, seed=999)

**What it verifies:** the full audit suite still passes at N=500 — no scale-only bugs (memory growth, bandit state saturation, DB index degradation). Phase 8 is N=6000, so N=500 is a 10× canary.

**Sub-checks (per variant V at N=500):**

1. **Deterministic prefix vs B1's N=200 baseline**: the first 200 mutations of the N=500 run must equal B1's N=200 baseline (after B7 filter incl. delta_T normalization). This proves N=500 isn't introducing extra randomness in the prefix.
2. **B1 re-run on the full N=500**: 500/500 PASS the strict verifier (modulo the same documented exclusions B1 uses — see `PHASE_7D_INC3D_B1_DISPOSITION.md`).
3. **B4 re-run on N=500**: all 500 mutations have 6-tuple agreement (same as Inc 3 B4 spec; just larger N).
4. **B9 re-run on N=500**: schema integrity holds — all expected tables present with correct schemas, FK references intact, mutation count == 500.
5. **Wall-time sanity**: each variant ≤ 90 min on POS (= ~10.8 sec/mutation including bandit + host + DB I/O). If any variant exceeds this, log it but don't fail unless > 2× (suggests a per-mut leak).

**Mutation budget:** 5 variants × N=500 = **2500 host mutations**. POS wall: ~6 hr at 70 min/variant on 1 node, or ~70 min if 5 nodes parallel.

**Acceptance gate:**
- For each variant: prefix-equal-baseline PASS, B1 re-run PASS, B4 re-run PASS, B9 re-run PASS.
- Aggregate: 5/5 variants on all 4 sub-checks.
- Wall time ≤ 90 min per variant (informational; soft fail = log + flag in report; hard fail = > 2× budget).

**Output file:** `audit_output/B11_scale_stress.json`:
```json
{
  "_meta": {...},
  "per_variant": {
    "V1": {
      "n_mutations": 500,
      "prefix_check": {"baseline_n": 200, "diffs": 0, "pass": true},
      "b1_rerun": {"pass": 500, "fail": 0, "documented_exclusions": 7, "effective_pass_rate": 1.0},
      "b4_rerun": {"agreed": 500, "disagreed": 0},
      "b9_rerun": {"tables_present": 15, "schema_ok": true, "fk_ok": true, "row_count": 500},
      "wall_seconds": 4500,
      "pass": true
    },
    ...
  },
  "verdict": "PASS"
}
```

**Watch out:**
- B11 reruns 3 prior audits (B1, B4, B9). All three were written to expect specific DB paths (`inc3_b1/V*.db`, `inc3_b4/V*.db`). Either generalize their script signatures to take `--db-dir`, or call them programmatically with a `db_path` argument. **Pick one pattern and use it consistently.**
- B1's documented exclusions (22 INSTR_TYPE_MOD multi-cycle + 8 MEM_VAL_MOD ECALL last_step + 7 ECALL-adjacent major=8) are PER-CAMPAIGN and SCALE WITH N. At N=500 instead of N=200, expect ~2.5× as many exclusion-eligible failures — that's not a regression. Document the per-variant expected exclusion count BEFORE the run so the report doesn't conflate "scale stress found a bug" with "we hit more multi-cycle steps because N is larger."
- Memory growth: B11 should `top` the POS process every 10 min and log peak RSS. If RSS grows monotonically and crosses 4 GB, that's a real leak — flag it.
- Bandit state saturation: V5 cTS has Bernoulli posteriors that can saturate at α + β > 1000. If any arm's posterior is degenerate at N=500, that's a real finding (would degrade Phase 8 exploration). Log per-arm (α, β) at end of run.

**Estimated time:** 5 hr write (orchestrator + re-run integration) + ~6 hr POS wall (or 70 min if 5 nodes parallel) + 1 hr post-processing.

---

### B12 — Multi-input robustness (POS REQUIRED)

**Files to write:**
- `a4/audits/B12_multi_input.sh` (~60 lines, orchestrator) — runs WSL-only A-suite re-runs + WSL-only B1/B4/B9 analyzers on POS-produced DBs
- (no new audit script — B12 reuses existing A1/A2/A3/A4/A5/B1/B4/B9 with input flags)

**What it verifies:** the audit suite isn't accidentally hardcoded to the specific trace shape of `--in1 5 --in4 10`. Two alternate inputs:
- `--in1 1 --in4 1` (minimal — fewer ECALLs, smaller trace)
- `--in1 100 --in4 100` (large — more ECALLs, larger trace)

**Computation split** (per the "> 10 mutations → POS" rule):

| Step | Where | Mutations | Reason |
|---|---|---|---|
| A1, A2, A3, A4, A5 re-runs at alt inputs | WSL | 0 each (trace analysis only) | A-suite scripts are pure trace/universe analyzers; they don't execute host mutations |
| B1 + B4 mutation campaigns at alt inputs | **POS** | 5 × N=50 = 250 per input (500 total) | > 10 mutations per the rule; combine B1 and B4 into ONE campaign per input (one DB serves both verifiers) |
| B1 verifier + B4 traceability + B9 schema analysis | WSL | 0 (reads the POS-produced DBs) | All three "audits" here are pure DB readers, not mutation runners |

**Pre-flight (REQUIRED before B12 POS dispatch — runs on WSL):**

1. **(WSL, 0 muts)** Re-compute non-det allowlists for alternate inputs:
   ```
   python -m a4.audits.A1_trace_determinism --in1 1   --in4 1   -o audit_output/A1_nondet_addrs_in1_1_in4_1.json
   python -m a4.audits.A1_trace_determinism --in1 100 --in4 100 -o audit_output/A1_nondet_addrs_in1_100_in4_100.json
   ```
   A1 typically runs ≤ 2 paired traces and emits the non-det address set — well under the 10-mut threshold.
2. **(WSL, 0 muts)** Enumerate per-input arms:
   ```
   python -m a4.audits.A3_arm_step_integrity --in1 1   --in4 1   -o audit_output/A3_arms_in1_1_in4_1.json
   python -m a4.audits.A3_arm_step_integrity --in1 100 --in4 100 -o audit_output/A3_arms_in1_100_in4_100.json
   ```
3. Compare per-input arm sets to baseline 48-arm universe:
   - Arms PRESENT in alt-input but ABSENT in baseline: these are NEW arms unlocked by the input variation. Typically expect `core_sha` to fire on the larger input if the guest does extra hashing rounds. **For each new arm: Composer adjudicates following E3's process — needs human-readable 🟢/🔴 verdict.** If unsure, mark as 🟡 and flag to Opus.
   - Arms ABSENT in alt-input but PRESENT in baseline: these are arms the smaller input doesn't exercise. Document but don't fail.
4. **Update `EXPECTED_ARMS.md`**: fill in the two "TO BE FILLED" sections (`--in1 1 --in4 1 expected arms` and `--in1 100 --in4 100 expected arms`) with the A3 output + any 🟢/🔴 verdicts.

**Then dispatch on POS, per alternate input:**

Each input gets ONE POS campaign (5 variants × N=50 = 250 mutations). The resulting DBs feed both B1 (hook fidelity verifier) AND B4 (bandit→DB traceability) AND B9 (schema check) on WSL — no need for separate B1 / B4 campaigns.

**Then re-run on WSL (per alternate input, after DBs collected):**

| Audit | What gets run on WSL | Mutations |
|---|---|---|
| A2, A4, A5 | Trace + universe analyzers vs alternate-input baseline | 0 |
| B1 | Strict verifier on the per-input DB (reads `mutations` rows + parses hook stdout) | 0 |
| B4 | 6-tuple agreement check (reads DB tables) | 0 |
| B9 | Schema integrity check (reads DB tables) | 0 |

**Mutation budget:** 2 inputs × 5 variants × N=50 = **500 host mutations on POS**. POS wall: ~30 min per input × 2 = ~1 hr total on 5 nodes parallel.

**Acceptance gate (per alternate input):**
- A1, A2, A3 PASS (no regressions; new arms documented in updated EXPECTED_ARMS.md).
- A4 PASS: every arm in this input's universe has `success_rate == 1.0`.
- A5 PASS: this input's universe matches the new `EXPECTED_ARMS.md` section exactly.
- B1 PASS: 50/50 per variant (with appropriate exclusions documented per Inc 3 B1 disposition).
- B4 PASS: 50/50 per variant 6-tuple agreement.
- B9 PASS: schema intact on new DBs.

**Output file:** `audit_output/B12_multi_input.json`:
```json
{
  "_meta": {...},
  "per_input": {
    "in1_1_in4_1": {
      "arms_in_universe": <count>,
      "new_arms_vs_baseline": ["<kind>|<zone>", ...],
      "dropped_arms_vs_baseline": ["<kind>|<zone>", ...],
      "A_suite": {"A1": "PASS", ...},
      "B1": {"per_variant": {...}},
      "B4": {"per_variant": {...}},
      "B9": {"per_variant": {...}},
      "expected_arms_md_updated": true,
      "verdict": "PASS"
    },
    "in1_100_in4_100": {...}
  },
  "verdict": "PASS"
}
```

**Watch out:**
- **A3 might enumerate brand-new arms** for `--in1 100 --in4 100` (e.g., `core_other|kernel_other` if BigInt is triggered). **Do NOT just rubber-stamp 🟢** — do the E3 adjudication mini-session: open the GLOSSARY, look at what the cycles actually do, and write a 1-paragraph adjudication. If you can't decide, flag to Opus for joint review.
- If A5 FAILS on `--in1 100 --in4 100` because EXPECTED_ARMS.md doesn't yet have that section filled, that's a workflow ordering bug — the EXPECTED_ARMS.md update MUST happen first (per the pre-flight step above).
- The `--in1 1 --in4 1` input may have so few mutations that some kinds have 0 valid steps. If `INSTR_WORD_MOD_*` has 0 targets at `--in1 1`, that's not a bug — it's the guest not hitting an instruction word mutation point for that input. Document and move on.
- The 188 D42 non-deterministic mem-txn addresses (from `audit_output/A1_nondet_addrs.json`) were computed on `--in1 5 --in4 10`. **For alternate inputs, you need to RE-COMPUTE the non-det allowlist** by running A1 with the alternate input. Don't reuse the baseline allowlist — that's how silent verifier passes happen.

**Estimated time:** 6 hr (3 hr orchestrator + arm adjudication + ~3 hr local run, or ~2 hr POS).

---

## 3. The B7 race filter (REQUIRED for B8 + B11 diff logic)

Both B8 and B11 do "diff DBs" checks. Inc 3 closed B7 with a documented ~0.70% `delta_T` flip rate on `mutation_rewards` under default parallelism. Your diff logic MUST handle this without false alarms.

**The filter (applies to mutations table, bandit_decisions table, mutation_rewards table, arm_state_snapshot table):**

```python
def b7_filter_for_diff(left_db, right_db):
    """
    Apply Inc 3 B7's filtering rules before diffing two DBs.
    Returns (filtered_left, filtered_right) ready for byte-wise comparison.
    """
    # 1. Drop executed_at timestamp (always differs)
    DROP_COLS = {
        'mutations': ['executed_at'],
        'bandit_decisions': [],   # no timestamps
        'mutation_rewards': [],
        'arm_state_snapshot': ['snapshot_at'],
    }

    # 2. Drop 188 D42 non-deterministic mem-txn addresses
    NON_DET_ADDRS = json.load(open('audit_output/A1_nondet_addrs.json'))

    # 3. For mutation_rewards: normalize delta_T to binary (0 vs >0)
    #    Reason: ~0.7% Poseidon2 race noise on delta_T under default parallelism.
    #    The *sign* of delta_T (covered new territory? yes/no) is what matters
    #    for variant isolation; the exact bit count is not.
    def normalize_delta_t(df):
        df['delta_T_binary'] = (df['delta_T'] > 0).astype(int)
        return df.drop(columns=['delta_T'])

    # 4. For arm_state_snapshot: posterior_q values are float64 and may
    #    differ by ~1 ULP under different memory orderings; treat as equal
    #    if absolute diff < 1e-9.
    return filtered_left, filtered_right
```

**Document this filter explicitly** in both B8 and B11 audit JSONs (see `filter_applied` field in the output spec above). Reviewers (Opus + user + Pro) will want to see exactly what was excluded and why.

**Alternative**: dispatch the B8 and B11 POS jobs with `RAYON_NUM_THREADS=1` to reduce noise floor 5× to ~0.14%. This costs ~4× wall but produces a CLEANER diff (you may not need the delta_T binary normalization). Trade-off:

| Option | Wall | Diff cleanliness | Recommendation |
|---|---|---|---|
| Default parallelism + B7 filter | 1× wall, ~0.7% delta_T noise | Need binary normalization; small risk of false positive | **Pick this** for consistency with Phase 8 (which launches default per user override) |
| `RAYON_NUM_THREADS=1` | 4× wall, ~0.14% noise | Cleaner diff but slower | Only if Phase 8 plan changes to RAYON=1 mode |

**Default: use default parallelism + B7 filter.** Document the choice in INC4_REPORT.

---

## 4. POS dispatch plan

### B8 manifests (REQUIRED — write these)

`a4/pos/manifests/pos_audit_b8_seq.json`:
```json
{
  "_doc": "Phase 7d Inc 4 B8 SEQUENTIAL — 5 variants run one at a time on a single node. Combined with pos_audit_b8_par.json for concurrent-isolation diff.",
  "name": "pos_audit_b8_seq",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "parallel": false,
  "jobs": [
    {"strategy": "zoned",                "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v1",     "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 999, "n": 50},
    {"strategy": "kindTS_zoned_v2",      "seed": 999, "n": 50},
    {"strategy": "cTS_semantic_v2",      "seed": 999, "n": 50}
  ]
}
```

`a4/pos/manifests/pos_audit_b8_par.json`:
```json
{
  "_doc": "Phase 7d Inc 4 B8 PARALLEL — 5 variants run simultaneously on 5 different nodes. Combined with pos_audit_b8_seq.json for concurrent-isolation diff. Verify per-job start timestamps are within 60 sec of each other (true parallel).",
  "name": "pos_audit_b8_par",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "parallel": true,
  "jobs": [
    {"strategy": "zoned",                "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v1",     "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 999, "n": 50},
    {"strategy": "kindTS_zoned_v2",      "seed": 999, "n": 50},
    {"strategy": "cTS_semantic_v2",      "seed": 999, "n": 50}
  ]
}
```

### B11 manifest (REQUIRED — write this)

`a4/pos/manifests/pos_audit_b11.json`:
```json
{
  "_doc": "Phase 7d Inc 4 B11 SCALE STRESS — 5 variants × N=500 each. Recommend parallel on 5 nodes for ~70 min wall total; otherwise ~6 hr sequential.",
  "name": "pos_audit_b11",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "5", "--in4", "10"],
  "parallel": true,
  "jobs": [
    {"strategy": "zoned",                "seed": 999, "n": 500},
    {"strategy": "kindUCB_zoned_v1",     "seed": 999, "n": 500},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 999, "n": 500},
    {"strategy": "kindTS_zoned_v2",      "seed": 999, "n": 500},
    {"strategy": "cTS_semantic_v2",      "seed": 999, "n": 500}
  ]
}
```

### B12 manifests (REQUIRED — write these)

`a4/pos/manifests/pos_audit_b12_in1_1_in4_1.json`:
```json
{
  "_doc": "Phase 7d Inc 4 B12 multi-input @ --in1 1 --in4 1 — 5 variants × N=50 each. Resulting DBs feed B1+B4+B9 analyzers on WSL.",
  "name": "pos_audit_b12_in1_1_in4_1",
  "image": "debian-trixie",
  "no_internet": false,
  "guest_args": ["--in1", "1", "--in4", "1"],
  "parallel": true,
  "jobs": [
    {"strategy": "zoned",                "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v1",     "seed": 999, "n": 50},
    {"strategy": "kindUCB_zoned_v2_noQ", "seed": 999, "n": 50},
    {"strategy": "kindTS_zoned_v2",      "seed": 999, "n": 50},
    {"strategy": "cTS_semantic_v2",      "seed": 999, "n": 50}
  ]
}
```

`a4/pos/manifests/pos_audit_b12_in1_100_in4_100.json`: identical to above but with `"guest_args": ["--in1", "100", "--in4", "100"]` and `"name": "pos_audit_b12_in1_100_in4_100"`.

### Node selection (CRITICAL for speed)

**Canonical source: `POS_PLAYBOOK.md §3.1` — Complete node × CPU inventory (captured Jun 6 18:00 UTC via `pos nodes show <n> -l processor`).** ALWAYS verify there before guessing.

| Tier | CPU | Nodes (per playbook §3.1) | Speed vs D-1518 | Use for Inc 4? |
|---|---|---|---|---|
| **S** | AMD EPYC 9354 (Zen 4, 32c/64t), 2022 | `flare`, `octorand`, `opulous`, `polynize` | **~8-10×** | **Yes — primary for B11** |
| **A** | AMD EPYC 7543 (Zen 3, 32c/64t), 2021 | `algofi`, `gard`, `goracle`, `zone` | **5.9× measured** | Fallback if Tier S unavailable |
| **B** | Intel Xeon Gold 6421N (Sapphire Rapids), 2023 | `pact`, `stoi` | ~5-7× | Fallback |
| **C** | Intel Xeon Gold 6312U (Ice Lake, 24c/48t), 2021 | `idex`, `meld`, `tinyman`, `yieldly` | ~2-3× | **OK for B8/B12 (N=50); NOT for B11 V5** (would bottleneck) |
| **D** | Intel Xeon D-2166NT (Skylake-D, 12c/24t), 2017 | `tentacle` | ~2× | Avoid |
| **E** | Intel Xeon D-1518 (Broadwell-DE), 2015 | `bitcoin*`, `litecoin*`, `dogecoin*`, `ether*` | **1× (baseline)** | **DO NOT USE — 8-10× slower than Tier S** |
| **F** | Intel Xeon E5-1650 v4 (Broadwell-EP), 2016 | `mtgox` | ~1.5× | Avoid |

**Measured per-mut wall** (POS_PLAYBOOK §3.1):
- Tier S (EPYC 9354): estimated 1.7-2.0 sec/inv; **2.85 sec/mut measured V1-V4 in Inc 3 B1**, **~3.5 sec/mut estimated V5 cTS**
- Tier A (EPYC 7543 `algofi`): 3.25 sec/inv measured
- Tier C (Xeon Gold 6312U): ~7-9 sec/inv estimated (untested)
- Tier E (D-1518 `bitcoin`): 19.1 sec/inv measured

### Calendar / allocation quota

**Canonical source: `POS_PLAYBOOK.md §12.37`** (Jun 6 21:00 — last major playbook update).

> The "2-future-entries cap" (§12.28) is on **CALENDAR ENTRIES, not on ACTIVE ALLOCATIONS or on NODES.** ONE calendar entry can cover MULTIPLE nodes (verified via web calendar UI; user reserved `flare+octorand+opulous` as one entry id=1646).

**Workflow**:
1. User pre-reserves nodes via the web calendar UI as **ONE multi-node entry** (covers all needed nodes).
2. The dispatcher runs with `--allocation-duration 0` (= `duration=None`) to **claim the existing reservation** rather than create a new entry.
3. Without `--allocation-duration 0`, the dispatcher would create a new calendar entry per dispatch, bumping past the 2-cap.

**Anti-pattern §12.37 watch-out**: "pre-existing reservation may not be claimable before its start_date even if you own it." Confirm with `pos allocations list | grep $USER` before dispatching.

`run_inc4_pos.sh` now uses `ALLOC_DURATION=${ALLOC_DURATION:-0}` to default to claiming pre-reservations. Override with `ALLOC_DURATION=120 bash a4/pos/run_inc4_pos.sh ...` if you need to create a fresh entry.

### Bundle / binary selection (Inc 3 baseline for apples-to-apples B11 prefix check)

**Required binary for Inc 4: `6873e588…cc444`** — the original "FIXED" baseline that Inc 3 B1/B4/B7 ran with (verified via `audit_output/inc3_b4/*.meta.json`). B11's prefix-equality check compares the first 200 of N=500 mutations against Inc 3 B1's N=200 baseline DBs; using a different binary risks non-trivial divergence (B5/BP1 add instrumentation tags that could perturb mutation outcomes despite being "harmless" for behavior).

**Where the binary lives**: `/root/arguzz_backups/risc0-host.FIXED.bin` (verified sha `6873e588…`).

**The `risc0-host.FIXED.sha256` file may be corrupted to BP1's sha (`632094ef…`)** — restore before bundling:
```bash
echo "6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444" > /root/arguzz_backups/risc0-host.FIXED.sha256
```

**Bundle prep**:
```bash
# Install the Inc 3 baseline binary into workspace
cp /root/arguzz_backups/risc0-host.FIXED.bin workspace/output/target/release/risc0-host

# Build bundle — sha check now passes (no --skip-host-sha needed)
bash a4/pos/prepare_bundle.sh --allow-dirty

# scp ONE bundle (not the glob)
LATEST=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
scp -P 10022 "$LATEST" ivgreiff@coinbase.net.in.tum.de:~/
```

**Fallback** (if you only have the B5 binary and don't want to swap): `bash a4/pos/prepare_bundle.sh --allow-dirty --skip-host-sha` will produce a B5 bundle. B11 prefix-check might show ~0.7% delta_T noise (B7 filter absorbs it) but isn't strictly apples-to-apples with Inc 3 baseline. Not recommended.

### Dispatch procedure

1. **WSL — install Inc 3 baseline binary, build bundle, scp** (see "Bundle / binary selection" above for details):
   ```bash
   cp /root/arguzz_backups/risc0-host.FIXED.bin workspace/output/target/release/risc0-host
   bash a4/pos/prepare_bundle.sh --allow-dirty
   LATEST=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
   scp -P 10022 "$LATEST" ivgreiff@coinbase.net.in.tum.de:~/
   ```

2. **User pre-reserves nodes via web calendar UI** as ONE multi-node entry covering all Tier S nodes you want (per POS_PLAYBOOK §12.37). Verify reservation is ACTIVE (not pending future start) via `pos allocations list | grep $USER` before dispatching.

3. **Coinbase — dispatch with `ALLOC_DURATION=0`** (default in updated `run_inc4_pos.sh`; claims existing reservation rather than creating a new entry):

   ```bash
   source /srv/testbed/pos/cli/venv3/bin/activate
   cd ~/arguzz

   # ONLY Tier S nodes for B11; meld/tinyman OK to add for B8/B12 (Tier C, smaller campaigns)
   TIER_S="flare octorand opulous polynize"          # B11 only — strict Tier S
   AUDIT_NODES="flare octorand opulous polynize meld" # B8 + B12 — can include meld

   bash a4/pos/run_inc4_pos.sh b8_par  $AUDIT_NODES   # ~8 min  (validates true parallelism)
   bash a4/pos/run_inc4_pos.sh b8_seq  flare          # ~18 min (1 Tier S node)
   bash a4/pos/run_inc4_pos.sh b12_1   $AUDIT_NODES   # ~8 min  (meld OK at N=50 ~7 min)
   bash a4/pos/run_inc4_pos.sh b12_100 $AUDIT_NODES   # ~8 min
   bash a4/pos/run_inc4_pos.sh b11     $TIER_S        # ~48 min (NO meld; would bottleneck V5)
   # Total wall: ~90 min on 4 Tier S nodes + 1 Tier C node, single calendar entry
   ```

   **DO NOT use the example node list (`flare bitcoin bitcoincash bitcoingold litecoin`) in `run_inc4_pos.sh` docstring** — `bitcoin*` are Tier E (~19 sec/mut, 8-10× slower than Tier S) and will balloon B11 to ~6 hr. Override with Tier S only for B11.

   **3-Tier-S fallback** (`polynize` reservation not yet active): use `flare octorand opulous` only for B11 → ~72 min wall (one node runs V1+V5 = 53 min worst-case). Total Inc 4 wall: ~110 min.

4. Collect resulting DBs back to WSL:
   ```
   scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b8_seq_*.db   ./a4/audits/audit_output/inc4_b8/seq/
   scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b8_par_*.db   ./a4/audits/audit_output/inc4_b8/par/
   scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b11_*.db      ./a4/audits/audit_output/inc4_b11/
   scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b12_in1_1_in4_1_*.db ./a4/audits/audit_output/inc4_b12/in1_1_in4_1/
   scp ivgreiff@coinbase:~/a4_campaign/runs/.../pos_audit_b12_in1_100_in4_100_*.db ./a4/audits/audit_output/inc4_b12/in1_100_in4_100/
   ```

---

## 5. Hard rules

1. **Don't change the bandit code, reward code, DB schema, verifier strict mode, or D40 logic.** B8/B11/B12 are AUDITS. If you find a bug, STOP and flag.
2. **B8's PARALLEL manifest MUST actually run in parallel.** Verify by checking per-job start timestamps post-dispatch (within 60 sec of each other). If POS internally serializes, B8 measures nothing — STOP and re-configure the manifest.
3. **B7 filter MUST be applied to B8 and B11 diff logic.** Otherwise ~0.7% Poseidon2 race noise will produce false alarms. See §3 above.
4. **For B12, RE-COMPUTE the D42 non-det address allowlist with alternate inputs.** Don't reuse the baseline allowlist (`A1_nondet_addrs.json` was computed for `--in1 5 --in4 10`).
5. **For B12, UPDATE `EXPECTED_ARMS.md` BEFORE running A5.** Otherwise A5 will fail because no expected list exists for the alternate input.
6. **Don't run B11 and B8 (or B11 and B12) on POS simultaneously inside the same calendar entry.** B11 needs all 4 Tier S nodes for ~48 min wall; serialize: B8_par → B8_seq → B12 ×2 → B11 (B8_par first to validate parallelism early, B11 last so a failure doesn't block earlier audits' DBs from being collected). True parallelism via a SECOND calendar entry is only worthwhile if you have 8+ disjoint Tier S/A nodes (rare).
7. **HARD RULE: anything > 10 mutations runs on POS, not WSL.** B8 (500 muts), B11 (2500 muts), B12 (500 muts) all dispatch to POS. The only WSL mutations in Inc 4 are pre-validation smoke (≤ 5 muts). All A-suite re-runs and B1/B4/B9 re-runs in Inc 4 are pure trace/DB analyzers and run on WSL with 0 mutations.
8. **`PYTHONUNBUFFERED=1`** for any audit emitting progress logs over 30+ minutes (B11 specifically).
9. **Telemetry level:** `--telemetry-level full` for all Inc 4 smokes (B8/B11/B12) — re-run audits depend on `bandit_decisions` + `arm_state_snapshot` + `mutation_rewards`.
10. **Smoke seeds:** seed=999 for all Inc 4 smokes (consistent with Inc 2/3).
11. **Pre-validation:** before launching B11 on POS, run a 5-mutation local smoke with the B1/B4/B9 re-runners to confirm the audit-script reads the new-format DB correctly. Inc 2 B6 took 3 iterations from format bugs caught only after long POS runs.
12. **No new fuzzer flags or instrumentation needed for Inc 4.** All audits use existing `--debug-bandit-trace` (B4) and `--debug-coverage-delta` (B6) flags if at all; no new fuzzer hooks.

---

## 6. Acceptance gates (all must PASS)

| Gate | Criterion |
|---|---|
| B8 | 5/5 variants: 0 unfiltered diffs between `seq_V.db` and `par_V.db` (using B7 filter incl. delta_T binary normalization). Parallel manifest verified actually parallel (per-job start ts within 60 sec). |
| B11 | 5/5 variants × 4 sub-checks: prefix-equal-baseline, B1 re-run, B4 re-run, B9 re-run all PASS. Wall ≤ 90 min/variant (informational; soft fail = log). |
| B12 | 2 alternate inputs × A1/A2/A3/A4/A5 + B1/B4/B9 = 16 audits all PASS. EXPECTED_ARMS.md updated with new sections. New 🟡 arms adjudicated. |

**Plus:**
- Full fast test suite still passes (`pytest a4/standalone/tests/ -x` from repo root, ≥ 472).
- Audit-output JSONs are well-formed, verdict field set, filter_applied field documented.
- EXPECTED_ARMS.md updated for B12's two alternate inputs.

---

## 7. Anti-patterns to avoid (lessons compounded across increments)

- ❌ Running B8's "parallel" manifest serially (because POS defaulted to serial). Verify true parallelism via timestamps.
- ❌ Skipping the B7 filter on B8/B11 diff logic. You WILL get false alarms from the ~0.7% Poseidon2 noise.
- ❌ Reusing baseline `A1_nondet_addrs.json` for B12's alternate inputs. Re-compute per input.
- ❌ Running A5 in B12 before updating EXPECTED_ARMS.md for the alternate input. Workflow ordering matters.
- ❌ Running B11 on POS alongside any other audit. 6 hours of single-tenant wall is a real cost; share carefully.
- ❌ Rubber-stamping new arms from B12 as 🟢 without E3-style adjudication. New arms = new categorization decisions = flag to Opus.
- ❌ Hardcoding `inc3_b1/V*.db` path in B1's re-runner so B11 can't reuse it. Generalize via `--db-dir` (or programmatic call signature).
- ❌ Reporting "B11 PASS" without per-variant exclusion counts. At N=500 the absolute exclusion count is ~2.5× B1's N=200 — show the math.
- ❌ Forgetting to verify that B8's diff actually compares ALL relevant tables. The 4 tables in §B8 above are the minimum; if you find others worth diffing (`coverage`, `failures`, `local_coverage_v2`), include them.
- ❌ Treating the B12 `--in1 1` run's "0 INSTR_WORD_MOD targets" as a bug. It's the guest not hitting the mutation point. Document and move on.

---

## 8. When you're done

Expected file changes:

```
a4/audits/B8_concurrent_isolation.py                                (NEW)
a4/audits/B11_scale_stress.py                                       (NEW)
a4/audits/B12_multi_input.sh                                        (NEW; bash orchestrator)
a4/audits/B1_hook_fidelity.py                                       (modified — add --db-dir flag if not present)
a4/audits/B4_bandit_db_traceability.py                              (modified — add --db-dir flag if not present)
a4/audits/B9_db_schema_integrity.py                                 (modified — add --db-dir flag if not present)
a4/pos/run_audit_B8_concurrent.sh                                   (NEW)
a4/pos/manifests/pos_audit_b8_seq.json                              (NEW)
a4/pos/manifests/pos_audit_b8_par.json                              (NEW)
a4/pos/manifests/pos_audit_b11.json                                 (NEW)
a4/pos/manifests/pos_audit_b12_in1_1_in4_1.json                     (NEW)
a4/pos/manifests/pos_audit_b12_in1_100_in4_100.json                 (NEW)
a4/audits/audit_output/B8_concurrent_isolation.json                 (NEW)
a4/audits/audit_output/B11_scale_stress.json                        (NEW)
a4/audits/audit_output/B12_multi_input.json                         (NEW)
a4/audits/audit_output/inc4_b8/seq/V*.db                            (NEW dir — B8 sequential DBs)
a4/audits/audit_output/inc4_b8/par/V*.db                            (NEW dir — B8 parallel DBs)
a4/audits/audit_output/inc4_b11/V*.db                               (NEW dir — B11 scale stress DBs)
a4/audits/audit_output/inc4_b12/in1_1_in4_1/                        (NEW dir — B12 small-input DBs)
a4/audits/audit_output/inc4_b12/in1_100_in4_100/                    (NEW dir — B12 large-input DBs)
a4/audits/audit_output/A1_nondet_addrs_in1_1_in4_1.json             (NEW — B12 re-computed allowlist)
a4/audits/audit_output/A1_nondet_addrs_in1_100_in4_100.json         (NEW)
a4/audits/audit_output/A3_arms_in1_1_in4_1.json                     (NEW)
a4/audits/audit_output/A3_arms_in1_100_in4_100.json                 (NEW)
a4/docs/cloud1/EXPECTED_ARMS.md                                     (modified — fill in 2 alternate-input sections)
a4/docs/cloud1/composer/PHASE_7D_INC4_REPORT.md                     (NEW)
```

**Report structure (`PHASE_7D_INC4_REPORT.md`):**

```
# Phase 7d — Increment 4 Report

## Summary
- B8: PASS (0 unfiltered diffs across 5 variants; true parallel verified)
- B11: PASS (5/5 variants × 4 sub-checks at N=500)
- B12: PASS (2 alternate inputs × 8 audits each; X new arms adjudicated to 🟢)
- Fast tests: PASS (≥ 472)

## Acceptance gate results
[table with per-audit numbers]

## Per-audit findings worth noting
### B8
- Filter applied: B7 standard + delta_T binary normalization (per §3 of work order).
- Per-job parallel-start timestamps: max spread <X seconds (true parallel confirmed).
- Per-variant unfiltered-diff counts (should all be 0).
- Tables diffed: <list>.

### B11
- Wall time per variant: <table>.
- Memory growth across run: peak RSS per variant.
- Bandit state at end of N=500: any near-degenerate (α, β) posteriors?
- Documented exclusion counts per variant (scaled from B1's N=200 baseline).

### B12
- New arms unlocked by --in1 100 --in4 100: <list with adjudication verdicts>.
- Arms dropped from --in1 1 --in4 1: <list> (informational).
- EXPECTED_ARMS.md sections filled.

## POS dispatch info
- Bundle SHA: <SHA>
- Manifests dispatched: pos_audit_b8_seq, pos_audit_b8_par, pos_audit_b11.
- Dispatch start / end times.
- POS jobs IDs (for trace-back).

## Open items / surprises
[anything notable]

## Ready-to-proceed
Inc 4 is green; please confirm to start Inc 5 (E5 per-arm evidence pack + E4 review queue closure + Phase 7d Final Report).
```

STOP after writing the report. Wait for Opus review before starting Inc 5.

---

## 9. Why this increment matters (read this when you're tired)

Inc 0-3 verified the architecture works correctly for a SINGLE variant at SMALL scale on SEQUENTIAL execution. Inc 4 closes the last 3 gaps before Phase 8:

> **B8**: When 5 variants run AT THE SAME TIME on POS (Phase 8's actual configuration), do they corrupt each other? If yes, Phase 8 measures cross-talk, not bandit behavior.
>
> **B11**: When N grows from 50 → 500, does anything degrade (memory leak, bandit saturation, DB index slowdown)? If yes, Phase 8's N=6000 will produce unrepresentative data in the tail.
>
> **B12**: Does the audit suite still hold when we vary the guest input? If our pipeline is accidentally hardcoded to `--in1 5 --in4 10` (e.g., zone classifier with magic offsets), Phase 8 generalizes nothing.

The 3 audits are designed to leave no escape:
- B8 catches "variants share mutable state in parallel execution."
- B11 catches "scale-only bugs that don't appear at N=50."
- B12 catches "input-sensitive bugs the baseline trace hides."

If all three PASS, you can credibly tell Pro: "the 5 variants run independently, the architecture scales linearly to at least N=500, and the audit suite generalizes across guest inputs." That's the last evidence Phase 8 needs to launch with confidence.

---

## 10. After Inc 4 closes → Inc 5 preview

Inc 5 is the user-facing closeout:
- **E5 per-arm evidence pack**: ~250-LOC orchestrator that reuses B1's verifier + B4's traceability dataframe. Produces 48 human-readable `.md` files (one per kept arm) showing exactly what mutation was applied, what was observed in the trace, and Composer's verdict on whether the arm's claimed semantics are CORRECT. ~3 hr WSL run.
- **E4 review queue**: joint session (Composer + user + Opus) to close every PENDING item in `composer/PHASE_7D_REVIEW_QUEUE.md` to DECIDED / DEFERRED / REJECTED.
- **Phase 7d Final Report**: Opus writes `phases/PHASE_7D_FINAL_REPORT.md` summarizing all 17 audits + 🟢 EXPECTED_ARMS.md + ready-for-Phase-8 attestation.
- **Phase 8 unblocks** once Inc 5 is signed off.

Estimated Inc 5 time: ~1 day total.
