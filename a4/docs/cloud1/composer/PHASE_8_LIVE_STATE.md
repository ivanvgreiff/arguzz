# Phase 8 (IV.POS.7) — Live Execution State

> **Read this file FIRST in any new context window.** It's the canonical handoff document for the in-flight IV.POS.7 campaign.

## TL;DR — what's running
- **50 fuzz jobs** planned across **13 batches** (7 Tier-S `ts_b1`..`ts_b7` + 6 Tier-A `ta_b1`..`ta_b6`). See `_dispatch_plan.json` produced by `a4/pos/generate_iv_pos_7_manifests.py`.
- All dispatches use **SSH-bypass** (see POS_PLAYBOOK §12.52), not `pos.*` commands. Nodes stay booted with `debian-trixie` image and bundle at `/root/a4_campaign/`.
- **Watcher**: `tmux ivpos7_bypass_watch` on coinbase. Polls each node every 60s, auto-scps `.db` to canonical results dir on completion. Log: `/tmp/iv_pos_7_ssh_bypass/watcher.log`.
- **Canonical results dir**: `/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_<batch>/<run_id>/`.

## Variant labeling (CRITICAL — easy to get wrong)
Per the canonical research-design table:

| # | Pro's name | Strategy in code | Step sampler | Reward | What it isolates |
|---|---|---|---|---|---|
| **V1** | `zoned_current` | `zoned` (kind-uniform) | zoned 5/90/5 | v1 | Reference (baseline) |
| **V2** | `kindUCB_zoned_v1` | `kindUCB_zoned_v1` | zoned 5/90/5 | v1 | Does copying zoned's step prior fix the mechanical gap? |
| **V3** | `kindUCB_zoned_v2_noQ` | `kindUCB_zoned_v2_noQ` | zoned 5/90/5 | v2 no Q_loc | Does the reward fix help in isolation? |
| **V4** | `kindTS_zoned_v2` | `kindTS_zoned_v2` | zoned 5/90/5 | v2 | Does TS beat UCB on high-variance discovery? |
| **V5** | `cTS_semantic_v2` | `cTS_semantic_v2` | structural sampler | v2 | **Main candidate.** kind×zone constrained TS + boundary floors |
| **V0** | *(to be added after 50 done)* | `uniform` | — | — | True random floor — anchors the ranking |

**Don't confuse V-numbers with display order.** Strategy name in the DB filename is the source of truth.

## Campaign structure
- N = 6000 mutations per job
- Seeds = 1234..1243 (10 seeds)
- 5 variants × 10 seeds = 50 jobs
- Tier-S (EPYC 9354, fast) carries V2-V5 pinned: flare=V2, octorand=V3, opulous=V4, polynize=V5
- Tier-A (EPYC 7543, slower) carries V1 baseline + spillover

## Node tiers
- **Tier-S** (4 nodes, EPYC 9354): flare, octorand, opulous, polynize
- **Tier-A** (4 nodes, EPYC 7543): algofi, gard, goracle, zone

## Batch plan (canonical, from generate_iv_pos_7_manifests.py)
Tier-S — each batch is 4 jobs, same seed across all 4 nodes, variants pinned per node:
```
ts_b1: seed=1234   ts_b2: seed=1235   ts_b3: seed=1236   ts_b4: seed=1237
ts_b5: seed=1238   ts_b6: seed=1239   ts_b7: seed=1240
```
Tier-A — first 2 batches are V1 baseline replicates; b3-b6 spill V2-V5:
```
ta_b1: V1 @ 1234,1235,1236,1237
ta_b2: V1 @ 1238,1239,1240,1241
ta_b3: V1@1242, V1@1243, V2@1241, V3@1241
ta_b4: V4@1241, V5@1241, V2@1242, V3@1242
ta_b5: V4@1242, V5@1242, V2@1243, V3@1243
ta_b6: V4@1243, V5@1243  (only 2 jobs)
```
Tier-A node assignments (from canonical manifest):
```
algofi  → first  job in each batch
gard    → second
goracle → third
zone    → fourth
```

## Status as of Mon Jun 15 22:17 CEST — ★ V6 (ARGUZZ) DEPLOYED IN STANDBY, V0 RUNNING ★

### Mon 22:17 CEST snapshot
- **V1-V5 main (50 jobs): all DONE.** `chain_tier_s` CHAIN_COMPLETE 17:22 CEST; `chain_tier_a` CHAIN_COMPLETE 20:03 CEST.
- **V0 (uniform, 10 jobs): 8/10 in flight.** Goracle/zone/opulous/polynize/flare/octorand running first V0 (started 17:41 CEST). algofi/gard running V0 (started 20:01 CEST). 2 chain-queued (u_b2 seeds 1242, 1243 on flare+octorand).
- **V6 (arguzz, 10 jobs): WAIT-AND-FIRE WRAPPERS RUNNING.** 4 tmux sessions (`v6_wait_idle`, `v6_wait_tier_s_early`, `v6_wait_tier_s_late`, `v6_wait_tier_a`) polling V0 chain logs. Will auto-fire `chain_v6_*` the moment their trigger fires. NO manual intervention needed.

### V6 deployment summary (Jun 15 22:17 CEST)
| Chain | Wrapper tmux | Trigger | Nodes | Seeds | Driver | ETA-finish (CEST) |
|---|---|---|---|---|---|---|
| `chain_v6_idle` | `v6_wait_idle` | `CHAIN_COMPLETE name=v0_idle` (~23:25 Mon) | goracle, zone | 1234,1235 then b2: 1242,1243 | `/root/v6/v6_driver_v2.py` | **~12:00 Tue** (b1a→b2 chain) |
| `chain_v6_tier_s_early` | `v6_wait_tier_s_early` | `BATCH_COMPLETE name=pos_iv_pos_7_u_b1b` (~22:41 Mon) | opulous, polynize | 1236, 1237 | same | ~04:40 Tue |
| `chain_v6_tier_s_late` | `v6_wait_tier_s_late` | `CHAIN_COMPLETE name=v0_tier_s` (~03:41 Tue) | flare, octorand | 1240, 1241 | same | ~09:40 Tue (≈40min past 1792 end) |
| `chain_v6_tier_a` | `v6_wait_tier_a` | `CHAIN_COMPLETE name=v0_tier_a` (~01:50 Tue) | algofi, gard | 1238, 1239 | same | ~07:50 Tue |

**Final V6 finish: ~12:00 Tue** (limited by chain_v6_idle's batch 2). **Total: 60 + 10 = 70 DBs at campaign end.**

### V6 driver: metric parity with V0-V5 ★ verified ★
- File: `/tmp/v6_driver_v2.py` on jump host; `/root/v6/v6_driver_v2.py` on all 8 prod nodes (synced via `v6_sync_driver.sh`).
- Uses `a4.standalone.compressed_global_extractor.extract_compressed_global_contexts` (the EXACT extractor used by V0-V5 inside `a4.standalone.cli fuzz`). Same `cycle_phase`, `address_region`, `address_bucket`, `lookup_index_bucket`, `opcode_class` axes.
- Bootstrap: TWO subprocess host calls (~10 s total):
  1. `host --trace` → instruction-to-steps map for the arguzz balanced round-robin scheduler.
  2. `InspectionData.from_inspection()` (i.e. `A4_INSPECT=1 A4_DUMP_ALL_TXNS=1`) → step→major + step→zone via `classify_zones()`.
- Patches `_TXN_ROLE_BY_KIND` (in-memory only, no A4 source change) to map arguzz-only kinds (`PRE/POST_EXEC_PC_MOD`, `BR_NEG_COND`, `POST_EXEC_REG_MOD`, `PRE/POST_EXEC_MEM_MOD`) into A4's existing role vocabulary `{ifetch, read, write, register}` — keeps ctx_key SPACE identical across V0-V6.
- DB schema: `campaigns`, `campaign_params`, `mutations`, `failures`, `global_failures`, `coverage`, `compressed_global_coverage` — all present and integrity=ok. Optional A4 tables (`bandit_decisions`, `arm_state_snapshot`, `mutation_substrategy`) intentionally MISSING since arguzz has no bandit. `variant_rank_v3.py` handles missing tables gracefully.
- Verified ctx_key format **byte-identical** to V0 production: e.g.
  - V0: `{"address_bucket": 29, "address_region": "user", "cycle_phase": "normal", "family": "memory", "txn_role": "register"}`
  - V6: `{"address_bucket": 19, "address_region": "user", "cycle_phase": "normal", "family": "memory", "txn_role": "register"}`

### V6 end-to-end pipeline verified
End-to-end smoke (Jun 15 22:13 CEST): `chain_dispatcher.sh` ran a single-job N=20 V6 on idex via `/tmp/v6_smoke_dispatcher.manifest`. Wall 82 s, exit 0, `.OK` marker created, scp pulled `meta.json + stdout.log + stderr.log + DB` (90 KB, 32 cgc rows) to canonical results dir. Smoke artifacts cleaned.

### V6 deployment plumbing files (jump host)
| File | Purpose |
|---|---|
| `/tmp/v6_driver_v2.py` | The driver |
| `/tmp/gen_v6_manifests.py` | Emits the 4 V6 manifests |
| `/tmp/v6_idle.manifest`, `/tmp/v6_tier_s_early.manifest`, `/tmp/v6_tier_s_late.manifest`, `/tmp/v6_tier_a.manifest` | Chain dispatcher inputs |
| `/tmp/v6_wait_idle.sh`, `/tmp/v6_wait_tier_s_early.sh`, `/tmp/v6_wait_tier_s_late.sh`, `/tmp/v6_wait_tier_a.sh` | Wait-and-fire wrappers (running in tmux now) |
| `/tmp/v6_sync_driver.sh` | Pushes driver to all 8 prod nodes + sanity-checks (host SHA, A4 import) |
| `/tmp/v6_deploy.sh` | Master orchestrator (fires all 4 wait wrappers) |
| `/tmp/chain_v6_*.log` (will be created at fire-time) | Per-chain dispatcher logs |

---


### Phase 8 main (50 jobs) — 49/50 done
| Batch  | Status         | Wall    | When (CEST)             |
|--------|----------------|---------|------------------|
| ts_b1  | ✓ DONE         | 5h 10m  | 03:00 → 08:10 Sun |
| ts_b2  | ✓ DONE         | 5h 10m  | 08:42 → 13:52 Sun |
| ts_b3  | ✓ DONE         | 4h 55m  | 15:30 → 20:30 Sun |
| ts_b4  | ✓ DONE         | ~5h     | 20:48 Sun → 01:47 Mon |
| ts_b5  | ✓ DONE         | ~5h     | 02:19 → 07:14 Mon |
| ts_b6  | ✓ DONE (chain) | 4h 58m  | 07:26 → 12:24 Mon |
| ts_b7  | ✓ DONE (chain) | ~5h     | 12:24 → **17:22 Mon** |
| ta_b1  | ✓ DONE¹        | 5h 45m  | 08:42 → 14:27 Sun |
| ta_b2  | ✓ DONE         | 5h 31m  | 15:36 → 21:07 Sun |
| ta_b3  | ✓ DONE         | ~5h 30m | 21:30 Sun → 03:03 Mon |
| ta_b4  | ✓ DONE (chain) | ~5h 30m | 03:27 → 09:01 Mon |
| ta_b5  | ✓ DONE (chain) | ~5h 33m | 09:01 → 14:33 Mon |
| ta_b6  | 🟢 RUNNING (chain, 2 jobs) | est 5h45m | 14:33 → ~20:05 Mon |

¹ **ta_b1 was destroyed Jun 14 06:10 UTC by §12.48 bug** (cross-tier free pollution killed 4 fuzzers mid-run); re-ran 08:42 UTC, completed 14:27 UTC. Original killed dir `2026-06-14_03-00-16_565136/` retained but has 0 .db files. Re-run dir `2026-06-14_08-42-25_695151/` has all 4 DBs.

Also **§12.47 bug Jun 14**: nested loop var collision skipped ts_b2/b3/b4/b5 in dispatch (no destruction — never started); patched + re-ran in order Jun 14 onwards. All present in canonical.

### V0 (uniform) — 6/10 running, 4 chain-queued
| Batch  | Status         | Nodes                 | Seeds       | When (CEST)          |
|--------|----------------|-----------------------|-------------|----------------------|
| u_b1a  | 🟢 RUNNING (chain_v0_idle) | goracle, zone     | 1234, 1235  | 17:41 → ~23:25 Mon  |
| u_b1b  | 🟢 RUNNING (chain_v0_tier_s) | flare, octorand, opulous, polynize | 1236-1239 | 17:41 → ~22:41 Mon |
| u_b1c  | ⏳ chain-queued (chain_v0_tier_a) | algofi, gard | 1240, 1241 | fires after ta_b6 (~20:05) → ~01:50 Tue |
| u_b2   | ⏳ chain-queued (chain_v0_tier_s batch 2) | flare, octorand | 1242, 1243 | fires after u_b1b (~22:41) → **~03:41 Tue** (24 min past res 1784, accepted) |

**Total 60 DBs at campaign end (50 main + 10 V0). Final ETA: ~03:41 Tue Jun 16.**

## ★ V0 deployment (Jun 15 17:40 CEST) — 3 parallel chains ★
- **`chain_v0_idle`** tmux: manifest `/tmp/v0_idle.manifest` (1 batch, 2 jobs on goracle+zone), log `/tmp/chain_v0_idle.log`. Fired immediately on idle nodes (Tier-A spillover, 0 risk).
- **`chain_v0_tier_s`** tmux: manifest `/tmp/v0_tier_s.manifest` (2 batches: 4+2 jobs on Tier-S). Fired by `v0_wait_tier_s.sh` after detecting `chain_tier_s` CHAIN_COMPLETE (gap = 19 min, just because deploy happened ~19min after ts_b7 finished).
- **`chain_v0_tier_a`** tmux: NOT YET — `v0_wait_tier_a.sh` polling `chain_tier_a.log` for CHAIN_COMPLETE, will fire on algofi+gard when ta_b6 finishes (~20:05 CEST).
- **`v0_wait_tier_s`** tmux: DONE its job (will exit naturally).
- **`v0_wait_tier_a`** tmux: still polling.

### Why 3 chains, not 1?
The chain dispatcher fires batches sequentially within a single manifest. V0 needs to use 3 node groups that become available at DIFFERENT times (idle now / Tier-S 17:24 / Tier-A 20:00). One chain would force all jobs to wait for the slowest group; 3 parallel chains let each group start the moment its nodes free up.

### Safety guard caught a fresh §12.53 #2 regression
First v0_deploy.sh attempt ABORTED at pre-flight: "goracle: HAS 1 a4.standalone process(es)". Was the **same `pgrep -f` self-match bug** from §12.53 #2 — the ssh shell running `pgrep -fc 'a4.standalone'` had that string in its own argv, so pgrep matched itself. Fixed by switching to `ps -C python3 -o cmd= --no-headers | grep -c a4.standalone` (counts only python3 processes, not the ssh shell). To be added as gotcha #7 in §12.53.

## Operating rules going forward (HARD)
1. **DO NOT manually fire any launcher script for u_b1c (algofi+gard) or u_b2 (flare+octorand batch 2).** The chain dispatchers will do it.
2. **All dispatches use SSH-bypass** (POS_PLAYBOOK §12.52). Never invoke `pos allocations allocate` on the 8 production nodes while chains are running — POS would reset them and kill the fuzzers.
3. **Reservation hard edge**: 1784 expires 03:00 Tue. u_b2 (flare+octorand seeds 1242-1243) finishes ~03:41 Tue → user committed to adding a small reservation 03:00-05:00 Tue on flare+octorand to cover the 24-min overrun.
4. **Timezones**: all user-facing times in **CEST** (UTC+2). Chain dispatcher logs in UTC.
5. **For any unexpected state**: chain dispatchers abort with `exit 4` (fail-safe). Read the tmux session's tail before relaunching.

## ★ Chain dispatcher cutover (Jun 15 07:26 CEST) — autonomous from here ★
- Old `ivpos7_bypass_watch` tmux session **killed**.
- `chain_tier_s` tmux session **active** — manifest `/tmp/tier_s.manifest` (ts_b6 + ts_b7), log `/tmp/chain_tier_s.log`.
- `chain_tier_a` tmux session **active** — manifest `/tmp/tier_a.manifest` (ta_b4 + ta_b5 + ta_b6), log `/tmp/chain_tier_a.log`.
- **Safety verified at cutover**: ta_b4 (in-flight) correctly emitted `LAUNCH_SKIP_INFLIGHT` for all 4 jobs (algofi/gard/goracle/zone). Process check via `check_state.sh` (fork-free /proc scan). All 4 ta_b4 fuzzers still at 3h 58m elapsed AFTER cutover (proves no competitor was spawned).
- **No more manual handovers needed.** When ts_b6 completes, chain_tier_s auto-fires ts_b7. When ta_b4 completes, chain_tier_a auto-fires ta_b5; same for ta_b5→ta_b6. CHAIN_COMPLETE on each side when its manifest is exhausted.
- **Monitoring**: `ssh coinbase 'tail -F /tmp/chain_tier_s.log /tmp/chain_tier_a.log'`.
- **Resume-safe**: if either tmux dies, just `tmux new -d -s <session> "MANIFEST=... bash chain_dispatcher.sh"` — already-completed jobs are skipped via `.OK` resume check, in-flight jobs via the `RUNNING` process check.

## Operating rules going forward (HARD)
1. **DO NOT manually fire any launcher script for ts_b7, ta_b5, or ta_b6.** The chain dispatchers will do it. Firing manually risks the exact in-flight collision we just engineered around (the chain dispatcher would detect the manual fuzzer as in-flight, skip launching — but you'd have wasted compute).
2. **All dispatches use SSH-bypass** (POS_PLAYBOOK §12.52). Never invoke `pos allocations allocate` on flare/octorand/opulous/polynize/algofi/gard/goracle/zone while chains are running — POS would reset them and kill the fuzzers.
3. **Timezones**: all user-facing times in **CEST** (UTC+2). Chain dispatcher logs in UTC.
4. **For any unexpected state**: chain dispatcher aborts with `exit 4` (fail-safe). Read the tmux session's tail before relaunching to understand why.

## Operating rules (HARD)
1. **Fire next batch the instant a tier's previous batch completes.** Do not wait for the sibling tier. (Cost of waiting = ~5h per wasted slot.)
2. **All dispatches use SSH-bypass** (see playbook §12.52). Never invoke `pos allocations allocate` while SSH-bypass fuzzers are running on the same nodes — POS resets them and kills the fuzzers.
3. **The watcher's JOBS list must be updated each time you launch a new batch** so it polls the right run_ids. Restart pattern: `tmux kill-session -t ivpos7_bypass_watch; tmux new -d -s ivpos7_bypass_watch "bash /tmp/iv_pos_7_watcher_<batch_pair>.sh >> /tmp/iv_pos_7_ssh_bypass/watcher.log 2>&1"`.
4. **Timezones**: all user-facing times in **CEST** (UTC+2). Coinbase server clock is CEST. Watcher logs are in UTC (because `date -u` in the script) — convert when reporting to user.

## SSH-bypass dispatcher template (per batch)
Generate from `/tmp/ssh_bypass_launcher_v2.sh` pattern. Key bits:
- JOBS array: `"<node> <strategy> <seed> <batch_name> <N>"` × N_jobs
- Per-node launcher in `/tmp/_node_<NODE>_launcher.sh` is `scp`'d to `<NODE>:/root/ssh_bypass_<RUN_ID>.sh` then `ssh -n -f <NODE> "chmod +x <path> && nohup <path> </dev/null >/dev/null 2>&1 &"`.
- On-node launcher creates `meta.json`, runs `python3 -m a4.standalone.cli fuzz --selector <S> --num <N> --seed <S> --db <DB_PATH> --telemetry-level full -- --in1 5 --in4 10`, touches `.OK` or `.FAIL_rc<N>` marker.

## Watcher template
`/tmp/iv_pos_7_ssh_bypass_watcher.sh` pattern. JOBS list = `"<node> <batch> <run_id>"` × 8. Polls each node every 60s, scps `.db` + meta files when `.OK` appears, emits `SENTINEL_BYPASS_*` log lines.

## Status verification script
On coinbase:
```bash
# Per-node liveness
for n in flare octorand opulous polynize algofi gard goracle zone; do
    r=$(timeout 5 ssh -o ConnectTimeout=3 $n "ps -C python3 -o etimes=,cmd= --no-headers 2>/dev/null | grep -F a4.standalone | head -1" 2>/dev/null | xargs)
    [ -z "$r" ] && echo "$n DEAD" || echo "$n ALIVE $r"
done
# Watcher health
tail -3 /tmp/iv_pos_7_ssh_bypass/watcher.log
# Done DBs
find /srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_*/ -name "*.db" | wc -l
```

## Variant ranking analysis script
`/tmp/_variant_rank2.py` on coinbase. Walks all completed DBs, extracts `compressed_global_coverage`, `local_coverage_v2`, `coverage`, `failures`, `global_failures` counts, computes per-variant means, prints ranking. Re-run as new DBs land.

**Current preliminary ranking** (after 16 DBs):
1. V5 cTS_semantic_v2 — compressed_gc=187 (clear leader)
2. V1 zoned (baseline) — 149
3. V4 kindTS_zoned_v2 — 142
4. V3 kindUCB_zoned_v2_noQ — 134
5. V2 kindUCB_zoned_v1 — 88 (clear last, Q_loc trapping)

Failure efficiency (failures per compressed_gc, lower=better):
- V5: 98 ← best
- V1: 106
- V4: 174 (cascade-trapped)
- V3: 183 (cascade-trapped)

## V0 addition (DEPLOYED Jun 15 17:40 CEST)
- 10 jobs `--selector uniform`, seeds 1234..1243 (identical seed range to V1-V5 for per-seed pairing)
- Distributed across all 8 EPYC nodes (max parallelism, not Tier-S-pinned as originally planned — was suboptimal):
  - **goracle, zone** (Tier-A, idle since ta_b5 14:33 Mon) — 1 batch × 2 jobs, seeds 1234-1235
  - **flare, octorand, opulous, polynize** (Tier-S, fired after ts_b7 17:22 Mon) — 1 batch × 4 jobs seeds 1236-1239 + 1 batch × 2 jobs (flare+octorand) seeds 1242-1243
  - **algofi, gard** (Tier-A, fires after ta_b6 ~20:05 Mon) — 1 batch × 2 jobs seeds 1240-1241
- Rationale: anchors ranking with true-random floor; strengthens V5 vs random argument.
- Strategy spec confirmed: `--selector uniform` → `UniformArmSelector` (no bandit, no zoned sampler, no reward signal). Smoke verified Jun 15 17:09 on goracle: RC=0, integrity ok, schema matches V1-V5, `bandit_decisions=0` as expected.
- Hardware mix notes: 4 of 10 V0 jobs on Tier-A (EPYC 7543), 6 on Tier-S (EPYC 9354). Mixed-hardware variance acceptable per PHASE_8_PLAN §3.10 (Inc 4 B11: <1% race noise across EPYC tiers). V0 has zero bandit-state, so the 0.7% bandit-race noise specifically does NOT apply to V0 — only the standard small EPYC-vs-EPYC variation.
- TODO: update `generate_iv_pos_7_manifests.py` + `PHASE_8_PLAN.md` post-completion to document V0 inclusion.

## Critical bugs already burned & their playbook entries
- §12.47: bash loop var collision (cost 1 day; fix: `local j; for ((j=...))`)
- §12.48: cross-tier allocation free (cost 5h; fix: filter by NODES_ARR subset + use JSON output)
- §12.49: contiguous reservation merge (saves 35 min/boundary)
- §12.50: ALLOWED_OWNERS caveat (calendar enforce stays strict even with widened filter)
- §12.51: `local -n` namerefs unreliable in tmux+venv
- §12.52: **★ SSH-BYPASS dispatch** (the technique we're using now)

## Calendar
- ivgreiff reservation 1756 active 21:00 Sun → 03:00 Mon CEST (6h)
- frezabek's 1754 expired 19:00 Sun
- After 1756 expires we'd need new calendar entries OR keep SSH-bypassing if nobody else is competing for the nodes.

## SSH connectivity
- Management node: `ssh -p 10022 -o HostKeyAlias=coinbase.net.in.tum.de ivgreiff@131.159.14.65`
- From coinbase to test node: just `ssh <node>` (e.g. `ssh flare`). Test nodes are root-passwordless from coinbase. No POS auth needed.

## Files of interest
- Local: `a4/docs/precloud/POS_PLAYBOOK.md` (canonical reference, §12.52 = SSH bypass)
- Local: `a4/docs/cloud1/composer/PHASE_8_PLAN.md` (campaign design)
- Local: `a4/pos/generate_iv_pos_7_manifests.py` (canonical plan source)
- Coinbase: `/tmp/iv_pos_7_ssh_bypass/watcher.log` (live event stream)
- Coinbase: `/tmp/iv_pos_7_ssh_bypass_watcher.sh` (watcher template)
- Coinbase: `/tmp/ssh_bypass_launcher_*.sh` (per-batch dispatchers)
- Coinbase: `/tmp/_variant_rank2.py` (ranking analysis)
- Coinbase results: `/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_*/`
