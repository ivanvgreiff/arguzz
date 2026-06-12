# Phase 8 — IV.POS.7 Cloud Campaign

**Status**: ⚪ PENDING (depends on Phase 7 complete + POS calendar slots reserved)
**Owner**: Cursor + user
**Estimated effort**: 1h dispatch setup + ~20h wall-clock + 1h collection
**Risk**: medium (POS scheduling)

---

## Tasks

### 8.1 POS calendar reservation [D11]
- [ ] Verify 2-future-entry calendar quota is empty (or use up to 2 rolling reservations)
- [ ] Reserve 4 consecutive 6-hour blocks on 3 nodes (= 18 GPU-hours per block × 4 blocks = 72 GPU-hours capacity vs ~58 needed)
- [ ] Run start: choose evening so overnight blocks chain cleanly

### 8.2 Dispatch script
Extend `auto_run_ab_v1_smart.sh`:
- [ ] `STRAT_LIST=("zoned" "kindUCB_zoned_v1" "kindUCB_zoned_v2_noQ" "kindTS_zoned_v2" "cTS_semantic_v2")`
- [ ] `SEED_LIST=(1234 1235 1236 1237 1238 1239 1240 1241 1242 1243)` (10 seeds per D1)
- [ ] `NUM_MUTATIONS=6000`
- [ ] `TELEMETRY_LEVEL=full`
- [ ] Total runs: 5 × 10 = 50 runs

### 8.3 Per-block dispatch sequence
On each 6-hour block (3 parallel nodes):
- [ ] Each node handles 1 run at a time
- [ ] Run wall-time ~70min → 5 runs per node per block → 15 runs per 6-hr block
- [ ] 50 runs / 15 per block = ~3.4 blocks → 4 blocks reservation is safe

### 8.4 Live monitoring
- [ ] `tmux session ivpos7_dispatch` with one window per node
- [ ] Heartbeat check every 1 hour: number of completed runs vs schedule
- [ ] If a run crashes: dispatch script auto-retries once with same seed

### 8.5 Collection
- [ ] After all runs complete: `scp` all 50 DBs to local
- [ ] Run `python -m a4.pos.collect_results_pos --strategies "zoned,kindUCB_zoned_v1,kindUCB_zoned_v2_noQ,kindTS_zoned_v2,cTS_semantic_v2" --seeds "1234..1243" --num-mutations 6000`
- [ ] Validate: each DB has ≥5999 mutations, all new tables non-empty
- [ ] Write `COLLECTION_REPORT_FINAL.json`

### 8.6 Closure
- [ ] Write `a4/runs/iv_pos_7/CLOSURE.txt` with:
  - Campaign window (start_ts, end_ts)
  - Total runs, total mutations
  - Per-variant min/max/mean coverage
  - Anomalies (crashes, retries, slow runs)

---

## Exit criteria

- All 50 DBs collected and validated
- `COLLECTION_REPORT_FINAL.json` shows 50/50 PASSED
- `CLOSURE.txt` written
- User signs off on proceeding to Phase 9 (analysis)

---

## Notes / decisions made during phase

(to be filled as work progresses)
