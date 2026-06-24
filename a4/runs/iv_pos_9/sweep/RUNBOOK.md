# IV.POS.9 Track-B Multi-Guest Screening Sweep — POS RUNBOOK

**Purpose:** run, from scratch and with **zero ambiguity**, the Track-B multi-guest coverage
screening sweep on the POS testbed. This is the document to follow if we ever redo this.

**Scope of this run:** 3 new guests × 4 variants × 3 seeds × **N=5000** = **36 jobs** (screening
only; thesis parked). G0 baseline is **reused** from the D2.H N=10000 campaign (truncated), not re-run.

---

## 0. TL;DR — the whole thing in 8 commands (assumes build + bundle already exist)

```bash
# (all from the dev box; `coinbase` is the ssh alias defined in §2)
scp bundles/sweep_<short>.tar.gz coinbase:/tmp/ivg_sweep/                       # 1. ship bundle
ssh coinbase 'cd /tmp/ivg_sweep && rm -rf a4_campaign && tar xzf sweep_<short>.tar.gz'   # 2. extract
ssh coinbase 'bash /tmp/ivg_sweep/reprobe2.sh'                                  # 3. which nodes are ssh-reachable?
# 4. (only for nodes that are "No route to host"): pos nodes reset <node>   — see §6
ssh coinbase 'BUNDLE=/tmp/ivg_sweep/sweep_<short>.tar.gz \
  bash /tmp/ivg_sweep/a4_campaign/repo/a4/runs/iv_pos_9/sweep/deploy_sweep_nodes.sh pact stoi idex meld tinyman'  # 5. deploy
ssh coinbase 'PYTHONPATH=/tmp/ivg_sweep/a4_campaign/repo python3 \
  /tmp/ivg_sweep/a4_campaign/repo/a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py \
  --stage screening --guests g1_ecall_control g2_mem_stress g3_accelerator \
  --seeds 1234 1235 1236 --nodes pact stoi idex meld tinyman --out /tmp/ivg_sweep/screening.chain'  # 6. manifest
ssh coinbase 'tmux new-session -d -s sweepb3 "MANIFEST=/tmp/ivg_sweep/screening.chain \
  CHAIN_NAME=sweepb3 RESULTS_BASE=/tmp/ivg_sweep/results LOG_FILE=/tmp/ivg_sweep/chain.log POLL_SEC=30 \
  bash /tmp/ivg_sweep/a4_campaign/repo/a4/runs/iv_pos_9/sweep/chain_dispatcher.sh 2>&1 | tee -a /tmp/ivg_sweep/chain_console.log"'  # 7. launch
ssh coinbase 'tail -f /tmp/ivg_sweep/chain.log'                                # 8. monitor
```

---

## 1. Mental model (read this first — it prevents 90% of the mistakes)

- **Two layers, do not confuse them (this cost us an hour):**
  - **Calendar RESERVATION** = your *right* to the nodes (`pos calendar list`). **This is what matters.**
  - **Live ALLOCATION** = who has the node booted *this second* (`pos allocations list`). **Ignore it.**
    Another user squatting an allocation on a node you have *reserved* is irrelevant — see §6.
- **Dispatch mechanism = SSH-BYPASS (POS_PLAYBOOK §12.52).** Raw `ssh` from coinbase to a *booted*
  node works **regardless of allocation/ownership**. You do **NOT** run `pos allocations allocate`
  (it can trigger an eviction/reset, §12.39, and it fails if a squatter holds the node). You just
  `ssh node` + run. `chain_dispatcher.sh` *is* the SSH-bypass driver.
- **The ONLY thing SSH-bypass can't do is boot a node.** A node stuck at `No route to host` (POS says
  "booted" but it isn't routable) needs `pos nodes reset <node>` (~3 min, blocking). Nothing else does.
- **coinbase is the launchpad**, not the compute. The chain runs in `tmux` on coinbase and SSHes to the
  test nodes. The dev box (where you build) reaches coinbase over SSH; it cannot reach the test nodes directly.

---

## 2. Access / identity (exact, non-obvious)

- coinbase SSH is **port 10022, user `ivgreiff`** (NOT port 22 / root — that's refused). Dev-box `~/.ssh/config`:
  ```
  Host coinbase
      HostName coinbase.net.in.tum.de
      Port 10022
      User ivgreiff
      StrictHostKeyChecking no
      ServerAliveInterval 30
  ```
- coinbase → test nodes: `ssh <bare-nodename>` as **root**, key already present, no prompt. Test node
  names (idex, meld, …) only resolve **from coinbase**, not from the dev box (so no ProxyJump from dev).
- **coinbase `~` is over quota.** Stage everything in **`/tmp/ivg_sweep/`** (tmpfs, 60 GB free). Never `~`.

## 3. Nodes (this run)

| node | CPU | ~s/mut | notes |
|---|---|---|---|
| pact, stoi | Xeon Gold 6421N | ~5 | were squatted by `susm` but reachable+idle → SSH-bypass runs fine |
| idex, meld, tinyman | Xeon Gold 6312U (Tier C) | ~8 | meld/tinyman came up `No route to host` → needed `pos nodes reset` |
| **zone** | EPYC 7543 | 3.2 | **RESERVED FOR TRACK A — never use for the sweep** |

## 4. The guests (sizing is load-bearing — see §10 for why)

- All three sized to **2¹⁴ (~12.6–13k executed steps)** → **~3.2 s/mut, identical to the sha2 baseline**.
  Proving cost is *flat* from 2¹³→2¹⁴ (risc0 min segment); it only jumps at **2¹⁵** — the old oversized
  guests (16–29k steps) were 2¹⁵ and ~5–6× slower. **Keep guests ≤ ~14k steps.**
- Size is **input-driven** via `--rounds`, so re-sizing needs **no rebuild** (just change `GUEST_SPECS`):

| guest | rounds | steps | family signal vs baseline | guest_image_id (first word) |
|---|---|---|---|---|
| g1_ecall_control | **55** | 12,660 | branch+jump 3,186 (**2.7×**) | 1065889426… |
| g2_mem_stress | **130** | 12,998 | load/store 2,680 (1.21×) + data-dep addressing | 3043401936… |
| g3_accelerator | **4** | 12,646 | **core_sha active** (baseline = 0) | 2463764742… |

- **Caveat:** g3's `div`/`rem` does **not** surface as Div/Rem in the trace (toolchain lowering) — g3's real
  new family is **core_sha**, not `inst_div`. Don't claim inst_div activation for g3.
- Full image IDs live in `generate_sweep_manifests.py` `GUEST_SPECS` and are asserted per-job by the guard.

## 5. Build (dev box; warm cache ≈ 10–20 s/guest)

```bash
# per-guest binary (clean worktree → output-trackb → read-only archive + fingerprint + guard self-check)
bash a4/scripts/build_sweep_binary.sh g1_ecall_control   # repeat for g2_mem_stress, g3_accelerator
# bundle (repo + 3 binaries + Track-B POS scripts, self-contained)
bash a4/runs/iv_pos_9/sweep/build_sweep_bundle.sh        # -> bundles/sweep_<gitshort>.tar.gz (~209 MB)
```
- The bundle's git-short changes whenever **Track A commits to cloud2** (shared branch). Always ship the
  **freshly named** tarball; `run_sweep_pos.sh` auto-picks the newest `sweep_*.tar.gz`.
- Build provenance is enforced: guard asserts `planted_bug=none, load_rs2_present=1` + per-guest image_id
  on every node and before every job. A holed/vuln binary can never silently run the sweep.

## 6. Bring nodes online (SSH-bypass + the one reset case)

```bash
ssh coinbase 'bash /tmp/ivg_sweep/reprobe2.sh'   # prints "UP <node>" or "No route to host"
```
- **Reachable nodes:** nothing to do — deploy + run directly (SSH-bypass). Do **not** allocate.
- **`No route to host` node** that POS lists as "booted": flaky boot (§12.45). Fix = **`pos nodes reset <node>`**
  (blocking, ~3 min) then re-probe. This is the *only* POS-orchestrator command we use, and only to boot.
- **Do NOT `pos allocations allocate`** — unnecessary (reservation already grants the right) and risky (§12.39).

## 7. Dispatch

```bash
# manifest over the LIVE reachable nodes (run_ids are node-independent; resume-safe)
ssh coinbase 'PYTHONPATH=/tmp/ivg_sweep/a4_campaign/repo python3 \
  /tmp/ivg_sweep/a4_campaign/repo/a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py \
  --stage screening --guests g1_ecall_control g2_mem_stress g3_accelerator \
  --seeds 1234 1235 1236 --nodes <live nodes> --out /tmp/ivg_sweep/screening.chain'
# launch the Track-B chain dispatcher in tmux (SSH-bypass, self-driving, resume-safe)
ssh coinbase 'tmux new-session -d -s sweepb3 "MANIFEST=/tmp/ivg_sweep/screening.chain CHAIN_NAME=sweepb3 \
  RESULTS_BASE=/tmp/ivg_sweep/results LOG_FILE=/tmp/ivg_sweep/chain.log POLL_SEC=30 \
  bash /tmp/ivg_sweep/a4_campaign/repo/a4/runs/iv_pos_9/sweep/chain_dispatcher.sh 2>&1 | tee -a /tmp/ivg_sweep/chain_console.log"'
```
- Uses the **Track-B copy** `a4/runs/iv_pos_9/sweep/chain_dispatcher.sh` — NOT the shared `a4/pos/chain_dispatcher.sh`
  (Track A owns that). The two tracks must never edit each other's POS scripts.
- Manifest format: `batch|node|run_id|remote_cmd`. One job per node per batch. run_id = `pos_iv_pos_9_b_<guest>_<variant>_seed<seed>_n<N>`.

## 8. Monitor

```bash
ssh coinbase 'tail -30 /tmp/ivg_sweep/chain.log'        # CHAIN_START / BATCH_START / LAUNCHED / HEARTBEAT done=k/n / BATCH_COMPLETE
ssh coinbase 'bash /tmp/ivg_sweep/verify_only.sh'       # per-node fuzz_running=yes + current rundir
# results land in /tmp/ivg_sweep/results/<run_id>/run.db (scp'd back on each job's .OK)
```

## 9. Widen the node pool / resume after an interruption (resume-safe)

The chain skips any job whose `.OK` marker exists on its node, and *detects a still-RUNNING* job by run_id
(won't relaunch it). So to add nodes (e.g. after meld/tinyman boot) or recover after a crash:

```bash
# regenerate the manifest with the wider/live node set, then relaunch the chain — it picks up where it left off
ssh coinbase 'tmux kill-session -t sweepb3'   # stop the old chain
# (re-run §7 with the new --nodes list)
```
- **Node reboots wipe `/root/a4_campaign`** → you must **re-deploy** (§5 bundle, deploy_sweep_nodes.sh) to any
  node that rebooted before relaunching the chain there.

## 10. ⚠️ Gotchas & lessons (each one cost real time)

1. **Per-mut cost is FLAT ≤ 2¹⁴, then jumps at 2¹⁵.** Baseline (7,924 steps) and the 2¹⁴ guests both prove
   at ~3.2 s/mut; the original 16–29k-step guests hit 2¹⁵ and ran ~5–6× slower. **Always keep guests ≤ ~14k steps.**
   Confirm with the DB's `elapsed_ms` column (per-mutation proving wall), not wall-clock of a tiny smoke
   (a fresh binary pays a **~178 s one-time prover-key setup** that dwarfs an N=8 smoke but is noise at N=5000).
2. **Reservation boundary = the #1 completion risk.** An N=5000 job is ~7–11 h on these Intel nodes — longer
   than a 6-h reservation block. If a node frees/reboots at a block boundary, the in-flight job dies and the
   bundle is wiped → restart from zero. **Solution: reserve the nodes as one CONTIGUOUS/gapless window**
   long enough to cover a job. (No data lost — chain is resume-safe — but no *progress* across a reset.)
3. **coinbase SSH = port 10022, user ivgreiff.** Port 22 / root is refused; default ssh tries IPv6 first and
   fails ("Network is unreachable") — there's no global IPv6 on the dev box. Use the alias in §2.
4. **coinbase `~` is over quota** → stage in `/tmp/ivg_sweep/`.
5. **`grep -v "Warning: Permanently"` will silently eat a node's whole status line** if its output also
   contains the first-time host-key warning. Use `ssh -o LogLevel=ERROR` to suppress the warning instead.
6. **Don't `pos allocations allocate`**; don't touch zone; reset only a genuinely-stuck `No route to host` node.
7. **Track isolation:** Track B = clean `28e53771` tree only (`load_rs2=1, planted=none`), owns
   `a4/runs/iv_pos_9/sweep/` (including its own `chain_dispatcher.sh` copy). Never edit shared `a4/pos/`
   scripts in place; never broad-`pkill` a shared cargo/python command (kills the other track's work — target
   by run-dir path or PID).

## 11. Track-B file inventory (all under `a4/runs/iv_pos_9/sweep/`)

| file | role |
|---|---|
| `generate_sweep_manifests.py` | builds the `batch\|node\|run_id\|remote_cmd` manifest; `GUEST_SPECS` (rounds, image_ids); `DEFAULT_NODES` (the 5, no zone) |
| `deploy_sweep_nodes.sh` | SSH-bypass deploy: scp bundle → node, extract, verify imports + guard each guest |
| `chain_dispatcher.sh` | **Track-B frozen copy** of the SSH-bypass dispatcher (do not edit `a4/pos/` original) |
| `run_sweep_pos.sh` | one-command orchestrator (probe → deploy → generate → launch); use for resume |
| `build_sweep_bundle.sh` | builds the self-contained `sweep_<short>.tar.gz` |
| `guests/<slug>/guest_main.rs`, `host_main.rs` | guest sources (sizes in §4) |
| `RUNBOOK.md` | this file |
| (shared infra) `a4/scripts/build_sweep_binary.sh`, `a4/pos/fingerprint_guard.py` | per-guest build + the provenance guard |

---
## 12. Run log — 2026-06-24

- **02:26 CEST** — chain `sweepb3` launched on 3 reachable nodes (pact, stoi, idex); batch 1 (g1 × V5/V6u/V6c, seed1234) proving.
- **02:42–02:47** — meld + tinyman were `No route to host`; `pos nodes reset meld tinyman` (user-approved) → up in ~30 s → bundle deployed (guard OK).
- **02:47 CEST** — regenerated 5-node manifest (36 jobs / **8 batches**), relaunched chain. The 3 in-flight jobs were correctly `LAUNCH_SKIP_INFLIGHT` (not restarted); meld→g1·Hybrid, tinyman→g2·V5 launched. **All 5 nodes confirmed `fuzz_running=yes`.** ✅ Screening dispatched and self-driving.
- Verified facts this run: coinbase = port 10022 / ivgreiff; stage in `/tmp/ivg_sweep`; SSH-bypass (no allocate); per-mut ~3.2 s on the 2¹⁴ guests (= baseline) + ~178 s one-time setup; `pos nodes reset` is the only orchestrator command used (to boot stuck meld/tinyman). Reservation boundary handling delegated to contiguous reservations (user-managed).
- **Open:** N=5000 jobs (~7–11 h) exceed a 6-h block → require gapless reservations to *complete* (chain loses no data on a kill, just reruns). Monitor each boundary.

*Status: screening RUNNING on 5 nodes as of 2026-06-24 02:47 CEST. Append completion stats when the 36 jobs finish.*
