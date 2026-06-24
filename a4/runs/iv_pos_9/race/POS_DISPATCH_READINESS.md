# A3 Seam-B race — POS dispatch readiness (SSH-bypass)

**Date:** 2026-06-23 · **Author:** Opus (OCP). Dispatch method = **SSH-bypass + `chain_dispatcher.sh` in tmux** (POS_PLAYBOOK §12.52/§12.53 — NO `pos allocations allocate`, which would trigger eviction §12.39).

## READY (verified this session)
- **Harness green:** 13 unit tests + Stage-0 ground truth PASS (`A3_1_REPORT.md`). Oracle control-checks every accept (falsifier genuinely tested).
- **Bundle built + verified:** `bundles/a4_campaign_race_69c6c2622714.tar.gz` (533M) — ships the **holed** binary (`a4_campaign/bin/risc0-host`, sha `53ee6663…` = bench-verifyopcode) + the committed repo (verifyopcode guard profile present). No `a4/builds` bloat.
- **SSH-bypass wrapper:** `a4/pos/race/dispatch_race.sh` — deploys bundle to assigned nodes, fingerprint-guards each (`--profile verifyopcode`), generates the manifest with the real nodes, launches `chain_dispatcher.sh` in a **race-namespaced** tmux session (no collision with the concurrent Track-B OCP). Pure SSH-bypass; never calls `pos allocations allocate`.
- **Nodes probed (read-only, from coinbase):** flare, octorand, opulous, polynize (Tier-S EPYC 9354) + algofi, gard, goracle, zone (Tier-A EPYC 7543) — **all 8 booted, debian-trixie (GLIBC 2.39 ✓), idle (no fuzzer running).**

## BLOCKERS before dispatch (need Ivan)
1. **Node assignment.** All 8 are idle now, but the concurrent Track-B (sweep) OCP shares this pool. Confirm which nodes are Track A's for the smoke (12 jobs = 4 variants × 3 seeds; ≤8 nodes → 2 waves, or assign 8 → ~1.5 waves). Default ask: all 8 (smoke is short, ~3–4 h at ~2.5–3 s/mut).
2. **Code on coinbase.** coinbase `~/arguzz` is on `main` @ `41dc02d` and **lacks** my cloud2 work (no verifyopcode profile, no `dispatch_race.sh`/`generate_race_manifests.py`). cloud2 is not on origin. To run the dispatcher on coinbase, sync via either:
   - **(recommended) push cloud2 → origin, then a Track-A worktree on coinbase:** `git -C ~/arguzz fetch origin cloud2 && git -C ~/arguzz worktree add ~/arguzz-race cloud2` — isolated from the shared `~/arguzz` (main) the Track-B OCP uses; run `dispatch_race.sh` from `~/arguzz-race`.
   - **(alt) scp** the 3 scripts into a Track-A dir on coinbase (no push), at the cost of a partial tree for imports.

## Dispatch sequence (once unblocked)
```
# (this box) push cloud2; scp the bundle
git push origin cloud2
scp -P 10022 bundles/a4_campaign_race_69c6c2622714.tar.gz ivgreiff@coinbase.net.in.tum.de:~/
# (coinbase) Track-A worktree + launch in tmux
git -C ~/arguzz fetch origin cloud2 && git -C ~/arguzz worktree add ~/arguzz-race cloud2
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz-race
BUNDLE=~/a4_campaign_race_69c6c2622714.tar.gz STAGE=smoke N=2000 \
  bash a4/pos/race/dispatch_race.sh <assigned nodes...>
# monitor: tail -F /tmp/chain_race_smoke.log ; results -> ~/race_results/race_smoke/
```
After the smoke completes: pull DBs, run `oracle.py` + `markers.py`, read the **real fast-node per-mut time + cTS ITM-rate** → set S2's data-driven N (the budget gate before A3.3).
```
