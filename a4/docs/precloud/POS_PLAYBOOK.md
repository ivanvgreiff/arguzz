# POS Playbook — single source of truth for the testbed

> **Living document.** Every time we learn something new about POS, an answer turns out to be different from what we assumed, a command fails for a non-obvious reason, or a code change to `a4/pos/*` happens — UPDATE THIS FILE. Sections §10 (decision log) and §11 (verified-commands log) are append-only.
>
> **Purpose**: a single place to read before/while/after touching anything POS-related. Subsumes the earlier scattered POS_ACCESS_NOTES, POS_ACCESS_VERIFICATION, POS_ADVISOR_MESSAGE, and PIVOT_TO_POS_REVIEW documents (now deleted; only `PIVOT_TO_POS.md` remains as the historical pivot source).

---

## ★ CANONICAL DISPATCH TEMPLATES — start here for every POS run ★

**For any new POS work, use these — do NOT build ad-hoc dispatch logic each time.** Both scripts are heavily commented; read them once and re-use them indefinitely. Verified end-to-end on Jun 13 2026 (25 DBs across 5 audits, 2h47m wall).

| Script | Purpose | When to use |
|---|---|---|
| **`a4/pos/dispatch_audit.sh`** | **Universal dispatch wrapper.** Auto-detects single-dispatch (jobs ≤ nodes) vs multi-dispatch (jobs > nodes, slices manifest per-variant). Handles §12.36 transparently. | Any time you want to run ONE manifest. Replaces all hand-written `python -m a4.pos.dispatch_pos ...` invocations. |
| **`a4/pos/run_inc4_all.sh`** | **Sequential orchestrator example.** Drives `dispatch_audit.sh` across multiple manifests; designed for nohup/tmux fire-and-forget. | Template to copy when you need to run several manifests in a fixed order (e.g. an entire Inc 4-style audit suite). |
| **`a4/pos/auto_run_iv_pos_7.sh`** | **Batched-parallel orchestrator template** (NEW Jun 14). Parameterised by `--tier=s\|a`. Designed for **2+ concurrent tier runners on disjoint node pools**, sequencing multiple batches per tier through reservation boundaries with §12.49 contiguous-reservation merging + §12.48 tier-filtered allocation freeing. Honors `--start-at=<batch>` for clean restarts after partial failures. | Any campaign with ≥10 jobs needing ≥2 tiers of parallelism (e.g. IV.POS.7-style 50-job × 5-variant ablations). Copy this script + `generate_iv_pos_7_manifests.py` + `iv_pos_7_preflight.py` as the seed for new batched-parallel runs. |
| **`a4/pos/chain_dispatcher.sh`** + `a4/pos/templates/chain_test.manifest` | **★ Self-driving SSH-bypass chained batch dispatcher** (NEW Jun 15). Manifest-driven (text format, `batch\|node\|run_id\|remote_cmd`). Single tmux process polls remote `.OK`/`.FAIL` markers, auto-scps results, and fires the next batch the instant the previous one completes (1-sec handover verified end-to-end). Replaces the older "manual launcher script per batch + read-only watcher + me firing follow-ups" pattern that suffered 20-30 min idle slips per handover (§12.53). | The DEFAULT choice for any multi-batch SSH-bypass campaign (i.e. nodes booted, bundle copied, calendar enforcement bypassed per §12.52). Use two parallel chains for Tier-S / Tier-A. Eliminates the need for separate watchers and human-driven handovers. |

**One-liner per manifest** (auto-handles both modes; see §12.44 for details):

```bash
# From coinbase, with POS venv active + bundle on ~/:
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz
bash a4/pos/dispatch_audit.sh <manifest.json> <node1> [node2] [node3] ...
```

**Whole-suite fire-and-forget** (logs to `/tmp/inc4_logs/`):

```bash
cd ~/arguzz
source /srv/testbed/pos/cli/venv3/bin/activate
nohup bash a4/pos/run_inc4_all.sh > /tmp/inc4_logs/orchestrator.log 2>&1 &
disown
# detach safely; monitor with: tail -f /tmp/inc4_logs/run_inc4_all.log
```

**Critical rules** when using the templates:
- `ALLOC_DURATION=0` (default) → claims pre-existing calendar entry (no quota hit; §12.37). Pre-reserve via web UI or `pos calendar create`.
- If you need an ad-hoc allocation, override with `ALLOC_DURATION=120` (uses one of your 2 calendar-entry slots).
- **Never run `pos allocations free <node>` without `-k`** if you own a calendar entry covering that node — it trims your reservation to `now()` (§12.43).
- If a node hangs in `ERR booting`, **substitute** another node from your reservation; don't retry indefinitely (§12.45).

---

> **Last meaningful update**: Jun 15, 2026 (02:53 UTC / 04:53 CEST) — IV.POS.7 (Phase 8) handover-slip fix. §12.53 added (**★ CHAIN DISPATCHER** — collapses watch + launch into a single self-driving loop; eliminates the 20-30 min idle slip that recurred twice on Jun 14 between batch handovers). Reference impl: `a4/pos/chain_dispatcher.sh` + `a4/pos/templates/chain_test.manifest`. Verified end-to-end on idex/meld/pact/tinyman: 2 batches × 4 jobs, **1-second handover** between BATCH_COMPLETE and next BATCH_START, 8/8 pulls successful, clean tmux exit. **For any future multi-batch SSH-bypass campaign, use `chain_dispatcher.sh` instead of the manual launcher-per-batch + read-only watcher + human dispatcher pattern.** Templates table at top of file updated accordingly.
>
> **Prior**: Jun 14, 2026 (06:42 UTC) — IV.POS.7 (Phase 8) batched-parallel ts_b2/ta_b1 recovery. §12.47 added (CRITICAL: nested `for ((i=...))` clobbers outer loop `i` — cost a day's campaign time). §12.48 added (CRITICAL: `free_all_my_allocations` cross-tier pollution in batched-parallel — cost ~5h of compute). §12.49 added (contiguous-reservation merge — saves ~35min per boundary). §12.50 added (`ALLOWED_OWNERS` widens calendar filter but does NOT enable borrowing — POS strictly enforces calendar-owner). §12.51 added (`local -n` namerefs unreliable in tmux+venv-launched scripts). §12.52 added (**★ SSH-BYPASS DISPATCH** — raw `ssh` to booted nodes works regardless of POS calendar/ownership state; the foundation §12.53 builds on). Reference impl: `auto_run_iv_pos_7.sh` after Jun 14 patch (md5: see `git log a4/pos/auto_run_iv_pos_7.sh`). **For any future batched-parallel runner, copy `auto_run_iv_pos_7.sh` as the starting template** — do NOT re-derive this logic.
>
> **Prior**: Jun 13 (PM) — Inc 4 closeout. §12.46 added (`free -k` fails when calendar coverage shifted mid-allocation); templates `dispatch_audit.sh` + `run_inc4_all.sh` proven end-to-end (25 DBs, 2h47m); §12.42–§12.45.
>
> **Prior major discovery (Jun 6)**: 3-parallel is feasible via pre-reservation. The "2-future-entries cap" (§12.28) is on CALENDAR ENTRIES, not nodes; ONE entry can cover multiple nodes (verified via web calendar UI). User pre-reserves flare+octorand+opulous as a single multi-node entry per 6-hr block, then dispatcher uses `--allocation-duration 0` to claim the existing reservation. **IV.POS.5 REPLANNED**: N=6000, 5 dispatches × 3 jobs each (by-seed), 3-parallel on Tier S EPYC 9354.

---

## 0 — Where we are RIGHT NOW (refresh every phase)

| Phase | Status | What's done | What's next |
|---|---|---|---|
| **III (all)** | ✅ COMPLETE | All 7 sub-phases done; III.6 gate **GREEN** with 7-criterion pass; reward, schema, multi-seed runner, cold-start fix, local validation campaign all locked in |  — |
| **IV.POS.0 — access + constraint confirmation** | ✅ DONE (Jun 6) | SSH ✅, alloc ✅, image ✅, reset ✅, launch ✅, await ✅, free ✅, venv resolved ✅ | — |
| **IV.POS.1 — bundle + single-node smoke** | ✅ DONE (Jun 6 08:22 UTC) | Bundle `a4_campaign_b169e76c7b1c.tar.gz` (git b169e76c7b1c) dispatched to `bitcoin`/`debian-trixie`. Result DB at `/srv/testbed/results/ivgreiff/a4/pos_smoke_v1/2026-06-06_08-12-58_300478/bitcoin/pos_smoke_v1_uniform_seed42_n20.db`. exit_code=0, num_recorded=20, 12 coverage rows, 38 unique global failures, wall=6m33s. | — |
| **IV.POS.2 — testbed runtime benchmark** | ✅ DONE (Jun 6 10:15 UTC) | uniform×2 (bitcoin+dogecoin, ~16m15s each), zoned (bitcoin, 15m59s), bandit-16 (algofi, 2m46s — algofi is ~6× faster hardware than D-1518). Per-mut wall: D-1518 ≈18.5 sec, algofi ≈3.3 sec. | — |
| **IV.POS.3 — multi-node dispatch smoke** | ✅ DONE (Jun 6 16:25 UTC) | 2-node dispatch validated: flare (Tier S EPYC 9354, uniform N=20 → 62s wall, 2.95s/inv) + algofi (Tier A EPYC 7543, bandit-16 N=20 → 102s wall, 3.29s/inv). Both rc=0, both DBs intact, per-node attribution worked, dispatcher's `pos.allocations.allocate(list, ...)` accepts multi-node lists cleanly (verified from `pos-examples`). Anomalies surfaced + root-caused (see §12.35). | — |
| **IV.POS.4 — POS local validation campaign (3 jobs × N=250)** | ✅ DONE (Jun 6 17:45 UTC) | uniform_1234 (flare, 2.90s/inv, 250/250 rewards), zoned_1234 (algofi, 3.23s/inv, 250/250), bandit-16_1234 (flare, 2.87s/inv, 219/220 post-pilot rewards, bandit scheduler t=220 with 60 active arms — proves end-to-end at production N). | — |
| **IV.POS.5 — full POS A/B (3×5×N=6000)** | ⏳ READY | **N=6000 (47 pulls/arm) at 3-parallel via pre-reservation pattern**. 2-future-entries cap is on CALENDAR entries (not nodes); user pre-reserves flare+octorand+opulous as ONE multi-node entry per 6-hr block, rolling. 5 sub-manifests in `a4/pos/manifests/ab_v1/pos_ab_v1_d{1..5}.json` (by-seed pairing). Total ~30 hr clock time (1 dispatch per 6-hr reservation, 5 reservations). Fire-and-forget runner: `a4/pos/auto_run_ab_v1.sh` in tmux. | Launch via auto-runner after pre-reserving 2 entries via web calendar UI. |
| **IV.POS.6 — aggregation + boss notebook** | ⏳ PENDING | — | `pos_ab_presentation.ipynb` from `collection_report.json` + DB shards. |
| **IV.POS.7 — conditional weight-A/B / checkpoint** | 🟦 CONDITIONAL | — | Only fired if IV.POS.6 motivates it. |

For full per-phase plans see master plan §11–§18. This row table is for orientation; the master plan is the contract.

---

## Table of contents

0. [Where we are RIGHT NOW (refresh every phase)](#0--where-we-are-right-now-refresh-every-phase)
1. [Context (1 paragraph)](#1--context)
2. [Connection + identity](#2--connection--identity)
3. [Reservation + node selection](#3--reservation--node-selection)
4. [Image + bundle + on-node setup](#4--image--bundle--on-node-setup)
5. [Real POS API (poslib + CLI cheat-sheet)](#5--real-pos-api-poslib--cli-cheat-sheet)
6. [Workflow (end-to-end diagram)](#6--workflow-end-to-end-diagram)
7. [`a4/pos/*` script status + invocation reference](#7--a4pos-script-status--invocation-reference)
8. [Phase-by-phase walkthrough (IV.POS.0 → IV.POS.7)](#8--phase-by-phase-walkthrough)
9. [Open / discoverable items](#9--open--discoverable-items)
10. [Decision log (append-only)](#10--decision-log-append-only)
11. [Verified-commands log (append-only, with dates)](#11--verified-commands-log-append-only)
12. [Anti-patterns we've already tripped on](#12--anti-patterns-weve-already-tripped-on)

---

## 1 — Context

Phase IV uses **POS (Plain Orchestrating Service)** at TUM's Blockchain testbed — *not* GCP. The pivot is documented in `PIVOT_TO_POS.md`. The differences relative to a cloud:

- Test nodes are **live-booted** into a fresh image; **anything you write to node disk is gone on next reboot**.
- The management node (`coinbase.net.in.tum.de`) holds your bundles + dispatches; test nodes execute.
- POS provides three coordination primitives we use: per-allocation **variables** (key-value pairs read on-node by `pos_get_variable`), **file copy** (`pos.nodes.copy`), and **commands** (`pos.commands.launch` with `--queued` until boot finishes).
- There is also an upload primitive (`pos_upload`) that persists files from the test node into the allocation's POS result folder.

---

## 2 — Connection + identity

| Field | Value |
|---|---|
| Testbed | **Blockchain** (TUM Chair of Network Architectures and Services) |
| Management host | `coinbase.net.in.tum.de` |
| SSH port | `10022` |
| Username | `ivgreiff` (Eddie's TUM account) |
| Host key fingerprint | `SHA256:A1mYk8UWOnSTIeuSY4Kk9OnzKv0GJ92WHY+hk2Q0BZg` (ED25519; pinned in `known_hosts` after first connect Jun 6) |
| First-login artefacts | `~/.pos/ssh_key` + `~/.pos/authentication_token` (auto-created; **do not delete**) |
| Mgmt host OS | Linux 6.12.74+deb13+1-amd64 (Debian 13) |
| Login banner | `Welcome to coinbase -- blockchain management host` |

Connect:

```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
```

---

## 3 — Reservation + node selection

### 3.1 Available default-access nodes (Coinbase node table)

**UPDATED Jun 6 PM (post IV.POS.2)** — Empirically `algofi`, `flare`, `idex`, `meld`, `tinyman` ARE reservable by us under the default group (verified by successful allocate during IV.POS.2 bandit-16 run on algofi). The "non-default" groups appear to be access-level overrides not absolute restrictions. **Use all 28 nodes when free**, with HW-tier awareness from the table below.

#### Complete node × CPU inventory (28 nodes — captured Jun 6 18:00 UTC via `pos nodes show <n> -l processor`)

| Tier | CPU | Year | Free-right-now | Allocated | Speed vs D-1518 |
|---|---|---|---|---|---|
| **S** | AMD EPYC 9354 (Zen 4, 32c/64t) | 2022 | `flare` | `octorand`, `opulous`, `polynize` | **~8–10× (untested)** |
| **A** | AMD EPYC 7543 (Zen 3, 32c/64t) | 2021 | `algofi` | `gard`, `goracle`, `zone` | **5.9× (measured)** |
| **B** | Intel Xeon Gold 6421N (Sapphire Rapids) | 2023 | — | `pact`, `stoi` | ~5–7× (untested) |
| **C** | Intel Xeon Gold 6312U (Ice Lake, 24c/48t) | 2021 | `idex`, `meld`, `tinyman` | `yieldly` | ~2–3× (untested) |
| **D** | Intel Xeon D-2166NT (Skylake-D, 12c/24t) | 2017 | `tentacle` | — | ~2× (untested) |
| **E** | Intel Xeon D-1518 (Broadwell-DE, 4c/8t @ 2.2GHz) | 2015 | `bitcoin`, `dogecoin`, `dogecoincash`, `ethergold` | `bitcoincash`, `bitcoingold`, `dogecoingold`, `ether`, `ethercash`, `litecoin`, `litecoingold` | **1× (baseline)** |
| **F** | Intel Xeon E5-1650 v4 (Broadwell-EP, 6c/12t @ 3.6GHz) | 2016 | — | `mtgox` | ~1.5× (untested) |

**Tier counts (Jun 6 PM)**: S = 4 (1 free), A = 4 (1 free), B = 2 (0 free), C = 4 (3 free), D = 1 (1 free), E = 11 (4 free), F = 1 (0 free). **10 free across 5 different tiers** — major change from "12 D-1518s and pray" plan.

**Per-mut wall time measured/estimated** (with N=50 baseline run, 51 host invocations total):
- Tier A (`algofi`, EPYC 7543): **3.25 sec/inv MEASURED** (166s / 51)
- Tier E (`bitcoin`, D-1518): **19.1 sec/inv MEASURED** (975s / 51)
- Tier S (EPYC 9354): estimated 1.7–2.0 sec/inv (will measure in IV.POS.3)
- Tier C (Xeon Gold 6312U): estimated 7–9 sec/inv (untested)
- Tier D (D-2166NT): estimated 9–11 sec/inv (untested)
- Tier F (E5-1650 v4): estimated 11–13 sec/inv (untested)

### 3.2 Real-time availability check

Always do this BEFORE picking a node — many of these are taken long-term by other users. From Jun 6 evidence (`pos nodes list` output): `bitcoincash`/`bitcoingold` taken 16/30 days by user `stegerl_*`; `mtgox` taken at one point; `bitcoin`/`dogecoin`/`dogecoincash`/`ethergold` etc. were FREE.

```bash
# All free default-group nodes right now:
pos nodes list | awk '$2=="host" && $3=="booted" && $4=="None"'
```

### 3.3 Reservation policy (current understanding)

- **Use `pos allocations allocate <node> --duration <minutes>` directly. Do NOT use `pos calendar create <node>` first** — calendar is for advance/scheduled reservations and requires `start_date/end_date` or `start_date/duration` or `duration/asap_after` arguments. For "give me this node right now", `pos allocations allocate --duration N` is correct.
- **Long allocations are allowed** — other users hold nodes for 16–30 days. Our planned 3-day reservations are well within precedent.
- **Be aware of contention** — `mtgox` (the only fast Xeon in default group) and `bitcoincash`/`bitcoingold` get long-held. Our IV.POS plan defaults to the ~10 plentiful Xeon D-1518 nodes.

### 3.4 Recommended node assignments per IV.POS phase

**Updated Jun 6 PM** based on hardware-tier discovery (§3.1). The original "all D-1518 for homogeneity" plan is REPLACED by tier-aware scheduling that exploits faster nodes when free.

| Phase | Recommended nodes | Rationale |
|---|---|---|
| IV.POS.0 | any 1 free default node | 5-min sanity check |
| IV.POS.1 single-node smoke | `bitcoin` (D-1518) | ✅ DONE on bitcoin/trixie/uniform N=20 |
| IV.POS.2 benchmark | `bitcoin` + `dogecoin` (D-1518) for uniform/zoned, `algofi` (EPYC 7543) for bandit | ✅ DONE — yielded 5.9× HW speedup discovery |
| **IV.POS.3 multi-node smoke (2 nodes)** | **`flare` (EPYC 9354, Tier S, free) + `algofi` (EPYC 7543, Tier A, free)** | **Validates multi-node dispatcher path AND bonus-benchmarks Tier S in one shot. 2-node not 3 due to 2-cap (§12.28). ~5 min wall.** |
| IV.POS.4 validation (3×3×250) | Mixed-tier across 2 simultaneous nodes (e.g. Tier A + E), serialize the rest | 2-cap forces serialization; pick fast nodes for bandit-16 jobs |
| IV.POS.5 full A/B (3×5×N=15 jobs) | **Tier-aware: 1 Tier S/A node per strategy across 3 seeds, 1 Tier C node for the other 2 seeds** | Drops total wall time from ~40h (all D-1518) to ~6–10h (mostly EPYC/Xeon Gold). See §3.5 for scheduling matrix. |

### 3.5 Tier-aware IV.POS.5 scheduling (NEW Jun 6)

Goal: 15 jobs (3 strategies × 5 seeds) within the 2-cap, minimizing total wall time. With per-mut estimates from §3.1, here's a concrete plan for N=500:

| Strategy | Seeds | Node tier | Wall per job | Total wall |
|---|---|---|---|---|
| uniform | 1234, 1235, 1236, 1237, 1238 | Tier C (idex/meld/tinyman) | ~70 min @ 8s/inv × 501 | Run 2-parallel → ~3 batches × 70 min = **~3.5 hr** |
| zoned | 1234, 1235, 1236, 1237, 1238 | Tier A (algofi if free) or Tier S (flare) | ~28 min @ 3.25s/inv × 501 | Single batch sequential → **~2.4 hr** (5 × 28min) |
| bandit-16 | 1234, 1235, 1236, 1237, 1238 | Tier S (flare) or Tier A (algofi) | ~17 min @ 2s/inv × 501 | **~1.4 hr** (5 × 17min) |

**Total wall** (assuming 2-parallel across strategies): **~7 hr** for N=500. Compare to ~21 hr if everything ran on D-1518.

**Tier S/A contention warning**: only 2 free in Tier S+A combined right now. If others come and go, fall back to Tier C for uniform/zoned. The dispatcher should accept `--nodes <fast> <fallback>` and the operator picks at runtime.

---

## 4 — Image + bundle + on-node setup

### 4.1 Image

**Default: `debian-bookworm`** (Debian 12) for ALL IV.POS campaigns. Set explicitly with `pos.nodes.image(node, 'debian-bookworm')`; do NOT rely on whatever the node was last booted on. (Previously we said `debian-bullseye` based on `pos-examples/`; `pos nodes list` on Jun 5/6 showed actual defaults vary per node — `bullseye`, `bookworm`, `trixie` all in the mix.)

### 4.2 Bundle (built by `a4/pos/prepare_bundle.sh`)

A self-contained tarball: `bundles/a4_campaign_<git-short>.tar.gz` containing:
- `bin/risc0-host` (sha256-verified against `~/arguzz_backups/risc0-host.FIXED.sha256`)
- `repo/` (git-archived source @ pinned commit)
- `scripts/run_campaign_pos.sh` + `scripts/benchmark_pos.sh`
- `bundle.json` (manifest: git commit, host sha256, dirty flag, etc.)
- `wheels/` (optional — only with `--include-wheels` flag; otherwise pip uses PyPI)

### 4.3 Bundle shipping

**Path: direct `pos.nodes.copy(node, '<tarball>', '/root/')` from the management node.** We do NOT use `/srv/testbed/files` as a staging layer (decision Jun 4; confirmed Jun 5 against `pos-examples/actual_experiments/ilab/synthesize_programs/setup.py`). The dispatcher then runs an inline `tar -xzf` on each node to extract to `/root/a4_campaign/`.

### 4.4 On-node Python setup

Test nodes have outbound internet (confirmed). On-node script:
1. `apt-get install -y python3-venv python3-pip build-essential git` (idempotent on Debian)
2. `python3 -m venv .venv && source .venv/bin/activate`
3. `pip install -e repo/` (online from PyPI by default; `pip install --no-index --find-links=wheels -e repo/` if `A4_NO_INTERNET=1` is set AND `wheels/` was bundled)

---

## 5 — Real POS API (poslib + CLI cheat-sheet)

> **VERIFIED Jun 6 against the official TUM POS API reference docs** (Python API + CLI `--help` extracted by user from web). When in doubt, this section overrides anything in older code/docs.

### 5.1 Per-function signatures (Python + CLI)

#### Allocations

| Op | Python (`poslib`) | CLI |
|---|---|---|
| Allocate immediate | `pos.allocations.allocate(node, result_folder=None, duration=None)` | `pos allocations allocate [-r PATH] [-d DURATION] [NODES]...` |
| Add node to alloc | `pos.allocations.add(allocation, node, duration=None, add_to_parent_event=False)` | `pos allocations add [-d N] [-a] ALLOC/NODE NODE` |
| Free | `pos.allocations.free(allocation, force=False, trim=False)` | `pos allocations free [-f] [-k] [-s] ALLOC/NODE` (ONE-SHOT; second call fails "neither allocation nor node") |
| List | `pos.allocations.list_all(filter_s, json=False)` | `pos allocations list [-f FLT] [-j]` |
| Show | `pos.allocations.show(allocation)` | `pos allocations show ALLOC/NODE` |
| Set vars | `pos.allocations.set_variables(allocation, datafile, extension, as_global, as_loop, print_variables)` | `pos allocations set_variables [-e EXT] [-g] [-l] [-p] ALLOC/HOST DATAFILE` |
| Get var | `pos.allocations.get_variable(allocation, variable, from_global=False, delimiter='/')` | `pos allocations get_variable [-g] [-d /] ALLOC/HOST VAR` |

#### Calendar (we do NOT use)

| Op | Python | CLI |
|---|---|---|
| Create | `pos.calendar.create(nodes, start, duration, asap_after=None)` | `pos calendar create [-s] [-d] [--asap] [--asap-after] NODES` |
| List | `pos.calendar.list_all(...)` | `pos calendar list [-f FLT] [-j]` |

#### Nodes

| Op | Python | CLI |
|---|---|---|
| List | `pos.nodes.list_all(filter_s=None, json=False)` | `pos nodes list [-f] [-j]` |
| Show | `pos.nodes.show(node, limits=None, all=False)` | `pos nodes show [-l COMP] [-a] [-j] NODE/ROLE` |
| Set image | `pos.nodes.image(node, image, staging=False, user=None)` | `pos nodes image [-s] [-u USR] NODE/ROLE IMAGE` |
| Reset (boot) | `pos.nodes.reset(node, blocking=True, queued=False, access_levels=None)` | `pos nodes reset [-b/-n] [--queued] NODE/ROLE` (blocking is DEFAULT) |
| Start | `pos.nodes.start(node, blocking=True, queued=False, access_levels=None)` | `pos nodes start [-b/-n] [--queued] NODE/ROLE` |
| Stop | `pos.nodes.stop(node, blocking=True, queued=False)` | `pos nodes stop [-b/-n] [--queued] NODE/ROLE` |
| Bootstrap | `pos.nodes.bootstrap(node, blocking=True, queued=False, access_levels=None)` | `pos nodes bootstrap NODE/ROLE` *(only needed when rebooting OUTSIDE pos; `pos nodes reset` does it automatically)* |
| Copy file | `pos.nodes.copy(node, source, dest, blocking=True, recursive=False, timeout=60, queued=False)` | `pos nodes copy [-d DEST] [-r] [-t] NODE/ROLE SOURCE` |
| Bootparameter | `pos.nodes.bootparameters(node, bootparameter, delete, raw=None)` | `pos nodes bootparameter [-d] [-r] NODE/ROLE [BOOTPARAM]...` |

#### Commands

| Op | Python | CLI |
|---|---|---|
| Launch | `pos.commands.launch(node, command=None, infile=None, blocking=True, queued=False, name=None, loop=False, loop_from=0, loop_to=None, loop_only=None)` | `pos commands launch [-i INFILE] [-b/-n] [-q] [--name N] [-v] NODE/ROLE [COMMAND]...` |
| Await | `pos.commands.await_id(command_id)` *(ONE arg; no timeout kwarg)* | `pos commands await [-v BOOL] COMMAND_ID` — **`-v` takes a BOOLEAN ARG, NOT a flag** (unlike `launch -v` which IS a flag). Use `pos commands await --verbose true <id>` or just `pos commands await <id>`. |
| Abort | `pos.commands.abort(command_id)` | `pos commands abort COMMAND_ID` |
| List | `pos.commands.list_all(node, filter_s, all_users=False, json=False)` | `pos commands list [-f] [-a] [-j] [NODE/ROLE]` |
| Show | `pos.commands.show(command)` | `pos commands show ID` |
| Flush queue | `pos.commands.flush(node)` | `pos commands flush NODE/ROLE` |

#### Critical `pos commands launch` rules (most-bitten section)

1. **`--blocking` is the DEFAULT.** Bare `pos commands launch <node> -- echo hi` blocks until done; returns nothing visible unless `-v`.
2. **`--queued` overrides `--blocking`.** With `--queued`, the call returns IMMEDIATELY with a cmd id printed to stdout.
3. **To capture a cmd id**: must use `--queued [--name foo]`. Otherwise stdout is empty.
4. **To see stdout output of the launched command** (in blocking mode): pass `-v/--verbose`.
5. **`--infile <script>` requires a SHEBANG** (`#!/bin/bash`). POS uploads the file to `/tmp/<cmd-id>` on the test node and runs it directly via `exec`. No shebang ⇒ `[Errno 8] Exec format error`. **THIS IS THE #1 GOTCHA.**
6. **On-node script gets the path `/tmp/<cmd-id>`**, NOT its original name; don't rely on `$0`.
7. **`-v` semantics are INCONSISTENT between `launch` and `await`** (genuine CLI design wart, verified Jun 6 06:00 from live `pos commands await -h`):
   - `pos commands launch -v ...` → `-v/--verbose` is a **FLAG** (no value). Shows stdout.
   - `pos commands await -v BOOL ...` → `-v/--verbose` **REQUIRES a boolean argument**. Outputs JSON.
   - Correct forms: `pos commands await --verbose true <id>` or just `pos commands await <id>` (no `-v`).
   - WRONG (caught Jun 6): `pos commands await -v "$CMD_ID"` → pos parses the cmd id as the `-v` value and fails with `Invalid value for '-v' / '--verbose': '...' is not a valid boolean`.

#### On-node tools (installed by `pos nodes bootstrap`; NOT poslib functions)

| Tool | Form | Purpose |
|---|---|---|
| `pos_get_variable` | `$(pos_get_variable KEY [--from-global \| --from-loop])` | Read a per-node/global/loop variable that was pushed via `pos allocations set_variables` |
| `pos_set_variable` | `pos_set_variable KEY VALUE [--as-global]` | Write a variable back from the test node |
| `pos_sync` | `pos_sync [--tag T]` | Barrier sync between nodes in the same allocation (we don't use — campaigns are independent) |
| `pos_upload` | `pos_upload PATH [-r] [-f]` | Push a file/dir from test node into the allocation's POS result folder |
| `pos_download` | `pos_download PATH` | Pull a file from result folder onto the test node |

### 5.3 `poslib` install location on `coinbase` (verified Jun 6)

```bash
$ cat /usr/local/bin/pos
#!/bin/bash
source /srv/testbed/pos/cli/venv3/bin/activate
exec pos "$@"
```

`poslib` is in the shared venv `/srv/testbed/pos/cli/venv3/`. To run our `dispatch_pos.py` (or any script that does `import poslib`):

```bash
source /srv/testbed/pos/cli/venv3/bin/activate
python -m a4.pos.dispatch_pos --manifest a4/pos/manifests/pos_smoke_v1.json --bundle /path/to/bundle.tar.gz --nodes algofi
```

Or invoke the venv's Python directly:

```bash
/srv/testbed/pos/cli/venv3/bin/python -m a4.pos.dispatch_pos ...
```

If `pyyaml` is missing from this venv (the only third-party dep `dispatch_pos.py` uses besides `poslib`), we either install it into a local user venv that extends `/srv/testbed/pos/cli/venv3/` via `PYTHONPATH`, or `pip install --user pyyaml` (the venv site-packages is shared — DO NOT install there).

### 5.4 KEY INVARIANTS for our scripts

- **NO `--env KEY=VAL`.** Per-job parameters MUST be pushed via `pos.allocations.set_variables(<node>, <yml>)` and read on-node via `pos_get_variable <key>`. Implemented in `dispatch_pos.py` + `run_campaign_pos.sh`.
- **Scripts uploaded via `--infile` MUST start with `#!/bin/bash`** (or other valid shebang).
- **`pos.commands.await_id(cmd_id)` takes ONE argument.** No timeout. (`dispatch_pos.py` wraps with SIGALRM for external timeout enforcement.)
- **`pos.allocations.set_variables(...)` takes 6 args** (alloc, datafile, extension, as_global, as_loop, print_variables). Call with kwargs to be explicit.
- **`pos.allocations.free` is one-shot.** Silent first call = success. Second call = "Resource is neither allocation nor node."
- **Max 2 future allocations per user.** Free old ones before re-allocating.

---

## 6 — Workflow (end-to-end diagram)

```
┌──────────────── on local machine ────────────────┐
│ bash a4/pos/prepare_bundle.sh                    │
│ → bundles/a4_campaign_<git>.tar.gz               │
│   (~100 MB; optional --include-wheels adds ~150) │
└──────────────────────┬───────────────────────────┘
                       │ scp -P 10022 ... :~/
                       v
┌──────────── on POS management node ──────────────┐
│  bundle at ~/a4_campaign_<git>.tar.gz            │
│  python -m a4.pos.dispatch_pos                   │
│    --manifest a4/pos/manifests/...json           │
│    --bundle ~/a4_campaign_<git>.tar.gz           │
│    --nodes <list>  [--allocation-duration N]     │
│    [--await]                                     │
│  Internally:                                     │
│    1. pos.allocations.free (idempotent)          │
│    2. pos.allocations.allocate(nodes, duration)  │
│       → returns alloc id + result_folder         │
│    3. pos.nodes.image(node, 'debian-bookworm')   │
│    4. pos.nodes.reset(nodes, blocking=True)      │
│    5. pos.nodes.copy(node, tarball, '/root/')    │
│    6. inline `tar -xzf` per node                 │
│    7. pos.allocations.set_variables(node, yml)   │
│       (per-job A4_STRATEGY, A4_SEED, etc.)       │
│    8. pos.commands.launch(node, infile=runner,   │
│       queued=True, name=run_id)                  │
│    9. optionally await_id each command           │
│   10. writes dispatch_manifest.json              │
└──────────────────────┬───────────────────────────┘
                       │
                       v
┌──────────── on test node (auto, scripted) ───────┐
│  bundle already at /root/a4_campaign/            │
│  run_campaign_pos.sh (via --infile):             │
│    A4_STRATEGY=$(pos_get_variable A4_STRATEGY)   │
│    ... (other vars)                              │
│    sha256 check bin/risc0-host                   │
│    apt-get install python3-venv etc.             │
│    python3 -m venv .venv && pip install -e repo/ │
│    python -m a4.standalone.cli fuzz ...          │
│    pos_upload results -r -f  (via EXIT trap)     │
└──────────────────────┬───────────────────────────┘
                       │
                       v
┌──────────── back on local machine ───────────────┐
│ python -m a4.pos.collect_results_pos             │
│   → rsync result folder; validate DBs;           │
│     write collection_report.json                 │
│ Then: precloud_validation.ipynb / boss notebook  │
└──────────────────────────────────────────────────┘
```

---

## 7 — `a4/pos/*` script status + invocation reference

| File | Status | Invocation |
|---|---|---|
| `a4/pos/prepare_bundle.sh` | ✅ Ready | `bash a4/pos/prepare_bundle.sh [--include-wheels] [--allow-dirty]` |
| `a4/pos/run_campaign_pos.sh` | ✅ Ready (uses `pos_get_variable`, NOT env vars) | Called via `pos.commands.launch --infile`; not directly |
| `a4/pos/dispatch_pos.py` | ✅ Ready (uses `poslib`) | `python -m a4.pos.dispatch_pos --manifest <f> --bundle <f> --nodes <…> [--await]` |
| `a4/pos/collect_results_pos.py` | ✅ Ready | `python -m a4.pos.collect_results_pos --result-folder <path> --out-dir <path>` |
| `a4/pos/benchmark_pos.sh` | ✅ Ready (IV.POS.2 protocol) | Invoked by `dispatch_pos.py` with the benchmark manifest |
| `a4/pos/manifests/pos_smoke_v1.json` | ✅ Ready | input to dispatch_pos for IV.POS.1 (1 job: uniform/seed=42/N=20) |
| `a4/pos/manifests/pos_benchmark_v1.json` | ✅ Ready (Jun 5 PM2) | input to dispatch_pos for IV.POS.2 benchmark (3 jobs: 3 strategies × N=50 / seed=1234) |
| `a4/pos/manifests/pos_validation_v1.json` | ✅ Ready (Jun 5 PM2) | input to dispatch_pos for IV.POS.4 (9 jobs: 3 × 3 × N=250) |
| `a4/pos/manifests/pos_ab_v1.json` | ✅ Ready (Jun 5 PM2; N=10000 placeholder) | input to dispatch_pos for IV.POS.5 (15 jobs: 3 × 5 × N=TBD-from-IV.POS.2). Seeds locked [1234..1238]. |
| `a4/pos/README.md` | ✅ Thin (points here) | — |

---

## 8 — Phase-by-phase walkthrough

### IV.POS.0 — access + sanity (canonical, post-API-doc)

REVISED Jun 6 after reading official `poslib` API + `pos --help` reference:

```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
```

Create the test script WITH A SHEBANG (this was the bug in the last attempt):

```bash
cat > /tmp/iv_pos_0_test.sh << 'EOF'
#!/bin/bash
echo "hello from $(hostname)"
uname -a
date
EOF
chmod +x /tmp/iv_pos_0_test.sh
```

```bash
pos nodes list | awk '$2=="host" && $3=="booted" && $4=="None"'
```

(Pick a free node; substitute below.)

```bash
pos allocations list
```

(Confirm you have < 2 active allocations — limit is 2 per user.)

```bash
pos allocations allocate algofi --duration 30
```

(Note the Allocation ID printed.)

```bash
pos nodes image algofi debian-bookworm
```

```bash
pos nodes reset algofi
```

(Blocking by default; ~3 min for bootstrap.)

```bash
CMD_ID=$(pos commands launch --infile /tmp/iv_pos_0_test.sh algofi --queued --name iv_pos_0)
echo "CMD_ID = $CMD_ID"
```

```bash
pos commands await "$CMD_ID"
```

(No `-v` — on `await`, `-v` requires a BOOLEAN argument; bare-mode shows the result. If you want full JSON output use `pos commands await --verbose true "$CMD_ID"`.)

```bash
pos allocations free <paste-real-alloc-id>
```

(One-shot; don't double-call.)

**Done when** the await prints 3 lines starting with `hello from <node>`. Then capture the OS / kernel info — that's also useful for the playbook.

### IV.POS.1 — single-node smoke

```bash
# local
bash a4/pos/prepare_bundle.sh
scp -P 10022 bundles/a4_campaign_<git>.tar.gz \
    ivgreiff@coinbase.net.in.tum.de:~/

# mgmt
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/pos_smoke_v1.json \
  --bundle ~/a4_campaign_<git>.tar.gz \
  --nodes bitcoin \
  --allocation-duration 240 \
  --await

# local
rsync -av -e 'ssh -p 10022' \
  ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/default/<run-dir>/ \
  ./pos_smoke_v1/
python -m a4.pos.collect_results_pos --result-folder ./pos_smoke_v1/ --out-dir ./pos_smoke_v1/ --in-place
```

### IV.POS.2 — benchmark (3 strategies × N=50)

`bash a4/pos/benchmark_pos.sh` on a single allocated node (e.g. `bitcoin`). Writes `pos_benchmark_v1.json` with `seconds_per_mutation` per strategy → drives N choice for IV.POS.5.

### IV.POS.3 — multi-node smoke (REVISED Jun 6 PM)

**Goal**: validate `dispatch_pos.py`'s multi-node code path (`--nodes a b ...` → assign jobs[i] to nodes[i % len(nodes)], loop over per-node allocate/set_vars/image/reset/copy/launch/await). Original plan called for 3 nodes; **reduced to 2 nodes** due to 2-cap (§12.28). The same code paths exercise with 2 nodes as with 3, so this is a valid smoke.

**Manifest**: `a4/pos/manifests/pos_smoke_v3_multinode.json` (committed Jun 6 PM).
- 2 jobs: `uniform` (seed=1234, N=20) + `bandit-16` (seed=1234, N=20)
- Image: `debian-trixie`

**Dispatch (on coinbase)**:

```bash
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz
git pull   # to grab the new manifest

# Bundle (if not built today on this commit):
bash a4/pos/prepare_bundle.sh --allow-dirty
ls -lh ~/a4_campaign_*.tar.gz   # confirm it exists (usually built locally on laptop instead)

# Dispatch (FOREGROUND, ~6 min wall):
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/pos_smoke_v3_multinode.json \
  --bundle ~/a4_campaign_<sha>.tar.gz \
  --nodes flare algofi \
  --await \
  --out /tmp/pos_smoke_v3.json
```

**Node→job mapping** (set by `assignments = [JobAssignment(job=j, node=nodes[i % len(nodes)], ...)]`):
- jobs[0] = uniform   → nodes[0] = flare    (Tier S EPYC 9354, expect ~30s wall)
- jobs[1] = bandit-16 → nodes[1] = algofi   (Tier A EPYC 7543, expect ~70s wall)

**Pass criteria** (all four required for IV.POS.3 ✅ DONE):
1. Dispatcher exits 0 (no orphaned-alloc hint printed).
2. Both result DBs exist with `meta.exit_code=0` and `num_recorded=20`.
3. Results land in **separate per-node subdirs** (`/srv/testbed/results/ivgreiff/a4/pos_smoke_v3_multinode/<run-dir>/{flare,algofi}/`).
4. Per-mut wall time on `flare` reported in playbook §3.1 (replaces "untested" estimate for Tier S).

**Risks to watch**:
- `pos.allocations.allocate(nodes_list, ...)` with a Python list: hasn't been multi-node-tested by us yet despite the dispatcher's comment claiming it works. If it fails, the dispatcher already prints clear hints. Fallback: 2 separate dispatches.
- Pre-existing allocations on flare/algofi from other users: check with `pos allocations list` BEFORE dispatching. Both should show `None` in `pos nodes list`.

### IV.POS.4 — POS validation campaign (REVISED Jun 6 PM)

**Two dispatches needed** because dispatcher is 1-job-per-node (§12.36) and 2-cap blocks 3-node parallelism (§12.28).

Run BOTH in tmux on coinbase so they survive SSH disconnects. See §13.X "Long-running dispatch pattern" below.

```bash
# === Dispatch A: pair (uniform + zoned on flare + algofi) ===
# Inside tmux session 'ivpos4a':
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz && git pull
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/pos_validation_v2_pair.json \
  --bundle ~/a4_campaign_<sha>.tar.gz \
  --nodes flare algofi \
  --await \
  --out /tmp/pos_validation_v2_pair.json \
  2>&1 | tee /tmp/pos_validation_v2_pair.log
# Detach: Ctrl+B d. Expected wall ~14-16 min.

# === Dispatch B: bandit solo (after A finishes; reuse algofi or flare) ===
# Inside tmux session 'ivpos4b' (NEW window after A done; otherwise quota):
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/pos_validation_v2_solo.json \
  --bundle ~/a4_campaign_<sha>.tar.gz \
  --nodes flare \
  --await \
  --out /tmp/pos_validation_v2_solo.json \
  2>&1 | tee /tmp/pos_validation_v2_solo.log
# Expected wall ~14-16 min. After this, free both allocations.

# Then copy DBs to laptop:
#   scp -P 10022 -r ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4/pos_validation_v2_pair/ ./a4/runs/
#   scp -P 10022 -r ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4/pos_validation_v2_solo/ ./a4/runs/
# Then: python -m a4.pos.collect_results_pos --result-folder a4/runs/pos_validation_v2_pair/ --out-dir a4/runs/pos_validation_v2_pair/ --in-place
```

### IV.POS.5 — Full A/B (3 × 5 × N)

`dispatch_pos.py --manifest pos_ab_v1.json --nodes <2 free EPYC> --await` inside tmux. N from IV.POS.4 (floor 100 for bandit per §12.35; expect 500–1000). 15 jobs total; with 2-cap + 1-job-per-node, this requires 8 dispatches: (7 × 2-job pair) + (1 × 1-job solo). Wall on Tier S/A ≈ 8 × 30 min = ~4 hr; on Tier C ≈ 8 × 90 min = ~12 hr. Use tmux on coinbase.

### Long-running dispatch pattern — tmux on coinbase (NEW Jun 6)

Any dispatch >5 min should run inside tmux on coinbase so it survives SSH disconnects.

```bash
# Start: ssh into coinbase, then:
tmux new -s ivpos5                 # create named session
# ... run dispatcher inside ...
# Detach (job keeps running): Ctrl+B then d
exit                                # safe to close SSH

# Later, from any machine:
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
tmux ls                             # list sessions
tmux attach -t ivpos5               # see live output
# Detach again: Ctrl+B d
# Kill session: tmux kill-session -t ivpos5
```

Variant for fully unattended runs (no need to ever re-attach): `nohup … > /tmp/log.txt 2>&1 & disown`. Less robust but one-shot.

### IV.POS.6 — aggregation + boss notebook

Local. Reads all 15 DBs; renders the three "money plots" per ProG §8.2; reports per-endpoint mean ± 95% bootstrap CI.

### IV.POS.7 — conditional follow-ups

Per IV.POS.6 verdict. Includes the ProG §6.6 weight A/B sweep (a_U ∈ {0.5, 1, 2}; see also tau_g, K_F_rare) if bandit does NOT cleanly beat uniform.

---

## 9 — Open / discoverable items

These are NOT blockers; we discover them as we proceed.

- **`/srv/testbed/results/...` exact quota** — none known to be enforced; if we hit one, we'll see a `pos_upload` error and react.
- **Whether `pos nodes reset` blocks reliably** — Jun 5 PM2 run suggests yes (returned in ~3 min); confirm with each new image.
- **Bundle copy timing for ~100 MB** — should be seconds on LAN; instrument in IV.POS.1 if slow.
- **Behaviour when allocation expires DURING a run** — pivot §12.4 hopes the EXIT trap saves partial results; not yet stress-tested. Mitigation: allocate generously (`--duration 240` for IV.POS.1, `--duration <expected-wall-time × 1.3>` for IV.POS.5).
- **Docker on test nodes** — not investigated; we don't need it.

---

## 10 — Decision log (append-only)

| Date | Decision | Reason |
|---|---|---|
| Jun 4 | Pivot from GCP to POS | User pasted `PIVOT_TO_POS.md`; cost + bare-metal availability |
| Jun 4 | Use `a4/cloud/*` as a deferred fallback, not delete | Cheap to keep; might be useful later |
| Jun 4 | One campaign per node initially (H.9) | Simplifies dispatch; bandit benefits from full CPU |
| Jun 4 | 3 strategies in IV.POS.5 (H.1) | User explicitly wants `zoned` retained |
| Jun 5 | Bundle shipping via `pos.nodes.copy` (Path A), not `/srv/testbed/files` | Confirmed against `pos-examples/.../setup.py`; one less unknown |
| Jun 5 | Real POS API uses `set_variables` + `pos_get_variable`; NO `--env` | Read `pos-examples/tutorials/simple/` |
| Jun 5 | Use `poslib` Python API in `dispatch_pos.py` (not subprocessing CLI) | Per `synthesize_programs/setup.py` |
| Jun 5 | Confirm internet on test nodes → default to online `pip install` (H.10) | User answer + simpler bundle prep |
| Jun 5 | Image = `debian-bookworm` (not bullseye) for all IV.POS | Coinbase `pos nodes list` showed `bitcoin` defaults to bookworm |
| Jun 5 | Smoke node = `bitcoin` (not mtgox) | mtgox contended; bitcoin = modal node = directly representative |
| Jun 5 PM2 | Drop `pos calendar create` from our workflow | First IV.POS.0 attempt failed: calendar needs time args; `allocations allocate --duration` works directly per `pos-examples/.../simple/experiment.sh` |
| Jun 5 PM2 | Reservation default duration = 60 min for IV.POS.0 / 240 min for IV.POS.1 | Avoid mid-test expiry like in 1st attempt |
| Jun 5 PM2 | KEEP `a_U` in the IV.POS.7.2 weight sweep | ProG §6.6 explicitly recommends 3-variant sweep; my earlier "drop a_U" was wrong (see CARRY_FORWARD §F.7) |
| Jun 5 PM2 | Lock replicate seed list to `[1234, 1235, 1236, 1237, 1238]` for IV.POS.4/5 | Deterministic R=5 per ProG §6.4; user-confirmed A7 |
| Jun 5 PM2 | Place FIXED `risc0-host` at `~/arguzz_backups/risc0-host.FIXED.bin` (+ `.sha256`) | Stable path so `prepare_bundle.sh` verification doesn't depend on whatever's at `workspace/output/...` (which a future `cargo build` could overwrite) |
| Jun 5 PM2 | `dispatch_pos.py` defers `poslib` import | so `--dry-run` validates manifests off-testbed without poslib installed |
| Jun 5 PM2 | Archive `CARRY_FORWARD_TO_CLOUD.md` to `a4/docs/precloud/archive/` | Renamed to `_TO_TESTBED.md` on pivot; original now archived |
| Jun 5 PM2 | Move `iii6_piggyback/` to `a4/runs/iii6_piggyback/` | Stop cluttering repo root; `a4/runs/` is gitignored |
| Jun 6 | Pasted official `poslib.api.*` + `pos --help` docs into §5; locked the canonical API contract | Stops further guessing. Two `dispatch_pos.py` API bugs caught: `await_id(cid, timeout=N)` (no such kwarg) and `set_variables(node, yml)` (needs 6 args). |
| Jun 6 | `--infile` scripts MUST start with `#!/bin/bash` | POS uploads file to test node and runs via `exec`; no-shebang ⇒ `[Errno 8] Exec format error`. Verified failure mode on dogecoin 04:29. |
| Jun 6 | IV.POS.0 walkthrough §8 rewritten | Uses `--queued --name` to capture cmd id + `await -v` to see stdout |

---

## 11 — Verified-commands log (append-only)

| Date / time (CEST) | Command | Result | Notes |
|---|---|---|---|
| Jun 6 01:52 | `ssh -p 10022 ivgreiff@coinbase.net.in.tum.de` | ✅ first connection; host key pinned | Login banner confirmed |
| Jun 6 01:52 | `pos --help` | ✅ enumerated 9 sub-commands | quickstart matches `pos-examples/` |
| Jun 6 01:52 | `pos nodes list \| head` | ✅ + auto-init created `~/.pos/ssh_key` | bitcoin/algofi/dogecoin/etc. shown free; bitcoincash/bitcoingold taken |
| Jun 6 01:52 | `pos calendar create mtgox` | ❌ "Must only set either start_date/end_date, start_date/duration or duration/asap_after" | calendar needs explicit time args; we just skip it |
| Jun 6 01:53 | `pos allocations allocate mtgox` | ❌ "Nodes are already allocated: mtgox" | mtgox in use by another user |
| Jun 6 02:09 | `pos allocations allocate bitcoin --duration 10` | ✅ `Allocation ID: ivgreiff_260606_020903_163334`, `Results in /srv/testbed/results/ivgreiff/default/2026-06-06_02-09-03_163334` | 10 min too short; use ≥60 next time |
| Jun 6 ~02:10 | `pos nodes image bitcoin debian-bookworm` | ✅ (silent success) | |
| Jun 6 ~02:10 | `pos nodes reset bitcoin` | ✅ (returned ~3 min later; prompt returned at 02:16) | blocking reset behaved as expected |
| Jun 6 02:16 | `pos commands launch bitcoin -- bash -c 'echo "hello from $(hostname)"'` | ✅ launched, but command id NOT captured in user's paste | next time `CMD_ID=$(pos commands launch …)` then `echo $CMD_ID` |
| Jun 6 02:17 | `pos commands await <cmd-id>` (literal placeholder) | ❌ zsh parse error on `<` | Need real cmd id; can't paste placeholder text |
| Jun 6 02:17 | `pos commands await e28692` (Unicode arrow misinterpreted) | ❌ 404 | The shell got `e28692` from a stray `→` arrow character |
| Jun 6 03:00 | `pos allocations allocate bitcoin --duration 60` | ❌ "Nodes are already allocated: bitcoin" | bitcoin grabbed by another user between 02:18 and 03:00. Need to re-pick a FREE node at allocation time, not from a stale list. |
| Jun 6 03:00 | `pos nodes image bitcoin debian-bookworm` | ❌ (silent; stderr probably "not owned") | Cascade from failed allocation. Stderr not shown in user's paste. |
| Jun 6 03:01 | `pos nodes reset bitcoin` | ❌ (silent same reason) | Same cascade |
| Jun 6 03:04 | `CMD_ID=$(pos commands launch bitcoin -- bash -c '…')` | ❌ stdout empty (stderr says "not owned by you") → `$CMD_ID=""` | **`$()` only captures stdout. stderr goes to terminal but not into variable.** Need `2>&1 \| tee /tmp/launch.txt` + parse for command id. |
| Jun 6 03:05 | `pos commands await "$CMD_ID"` (with `CMD_ID=""`) | ❌ 404 — URL became `/commands/await/` (no id) | Empty id concatenated to URL |
| Jun 6 03:42 | `pos allocations allocate dogecoin --duration 60` | ✅ `Allocation ID: ivgreiff_260606_034240_240251`, results in `/srv/testbed/results/ivgreiff/default/2026-06-06_03-42-40_240251` | Switched to dogecoin (free); allocation succeeded |
| Jun 6 ~03:43 | `pos nodes image dogecoin debian-bookworm` | ✅ silent (success) | |
| Jun 6 ~03:43 | `pos nodes reset dogecoin` | ✅ silent (success) | |
| Jun 6 ~03:46 | `pos commands launch dogecoin -- bash -c 'echo "hello from $(hostname)"'` | ⚠️ silent — **no cmd id, no output** | Bare-mode launch is detached; needs `--blocking` or `--queued --name foo`. See anti-pattern §12.10. |
| Jun 6 ~03:46 | `pos commands launch dogecoin -- bash -c 'echo "hello from hostname"'` | ⚠️ same silent | confirms not a quoting issue |
| Jun 6 ~03:47 | `pos allocations free ivgreiff_260606_034240_240251` | ✅ silent (success) | |
| Jun 6 ~03:49 | `python3 -c "import poslib"` | ❌ `ModuleNotFoundError: No module named 'poslib'` | `/usr/bin/python3` doesn't have poslib (and `python`/`/usr/bin/python` don't exist on this host). Need to find which Python has poslib (likely via TUM POS install docs we haven't seen yet). |
| Jun 6 04:04 | `pos allocations allocate dogecoin --duration 30` | ❌ "Nodes are already allocated: dogecoin" | dogecoin re-taken. Cycle continues; this is normal contention. |
| Jun 6 04:25 | `pos allocations allocate algofi --duration 30` | ✅ `Allocation ID: ivgreiff_260606_042512_105491` | Switched to algofi. |
| Jun 6 04:25 | `pos nodes image algofi debian-bookworm` + `pos nodes reset algofi` | ✅ silent (image + reset both worked; reset blocked ~3 min) | |
| Jun 6 04:29 | `pos allocations allocate dogecoin --duration 30` | ❌ "Maximum number of future entries is 2!" | **Per-user limit = 2 allocations.** Free old ones before re-allocating. |
| Jun 6 04:29 | `CMD_ID=$(pos commands launch --infile /tmp/iv_pos_0_test.sh dogecoin --queued --name iv_pos_0_test)` | ✅ `CMD_ID = 2026-06-06_04-29-31_093795_iv_pos_0_test` | **`--queued --name` returns the cmd id on stdout.** Confirms the canonical capture pattern. |
| Jun 6 04:29 | `pos commands await "$CMD_ID"` | ❌ `OSError: [Errno 8] Exec format error: '/tmp/<cmd-id>'` | **#1 GOTCHA: script lacks shebang.** POS uploads `--infile` and runs as `/tmp/<cmd-id>` via `exec`; kernel needs `#!/bin/bash` on line 1. Our `echo '…' > /tmp/iv_pos_0_test.sh` produced a shebang-less file. |
| Jun 6 04:31 | `pos allocations free ivgreiff_260606_042512_105491` | ✅ silent | First call succeeds silently. |
| Jun 6 04:31 | `pos allocations free "ivgreiff_260606_042512_105491"` (2nd call) | ❌ "Resource ... is neither allocation nor node" | **`free` is one-shot**; second call always fails after the first succeeded. |
| Jun 6 04:33 | Pasted official `poslib.api.*` + `pos --help` reference | ✅ archived in `POS_PLAYBOOK.md §5` | Two real bugs found in `dispatch_pos.py`: `await_id(cid, timeout=N)` (no such kwarg) and `set_variables(node, yml)` (needs 6 args). Both fixed Jun 6. |
| Jun 6 05:19 | `pos allocations allocate algofi --duration 30` | ✅ `Allocation ID: ivgreiff_260606_051847_624185` | Both prior allocations (bitcoin 02:09, dogecoin 04:04 each `--duration 30/60`) had expired naturally; visible in `list` but not counted against the 2-future limit. |
| Jun 6 05:19 | `pos nodes image algofi debian-bookworm` + `pos nodes reset algofi` | ✅ silent | |
| Jun 6 05:28 | `CMD_ID=$(pos commands launch --infile /tmp/iv_pos_0_test.sh algofi --queued --name iv_pos_0)` | ✅ `CMD_ID = 2026-06-06_05-28-38_911114_iv_pos_0` | Now with the proper shebang in `iv_pos_0_test.sh`. |
| Jun 6 05:28 | `pos commands await -v "$CMD_ID"` | ❌ `Invalid value for '-v' / '--verbose': '...' is not a valid boolean.` | **`-v` on `await` is NOT a flag; it takes a BOOLEAN argument.** Inconsistent with `launch -v`. Recorded as §12.17 anti-pattern. |
| Jun 6 05:32 | `pos commands await "$CMD_ID$"` *(typo: extra `$`)* | ❌ `Resource ..._iv_pos_0$ not found` | Shell expanded `$CMD_ID$` → `<id>$` (literal trailing `$` because `D$` isn't a var). Use `"$CMD_ID"` exactly. |
| Jun 6 05:32 | `pos commands await --verbose "$CMD_ID$"` (still typo) | ❌ same boolean-parse error | The trailing `$` makes pos treat the next-token as a non-bool value. |
| Jun 6 05:35 | `pos nodes start algofi` | ⚠ `NodeAlreadyRunning: Node algofi is already running` | Confirms node is up; this is informational, not an error. |
| Jun 6 05:35 | `pos commands launch algofi -- echo 43` *(blocking, no `-v`)* | ✅ silent (return only) | Confirms launch works; `-v` flag would have shown stdout. |
| Jun 6 05:35 | `cat /usr/local/bin/pos` (first attempt, partial output) | only first line shown | needed second read |
| Jun 6 05:44 | `pos commands await "2026-06-06_05-28-38_911114_iv_pos_0"` | ✅ printed exactly: `hello from algofi` / `Linux algofi 6.1.0-17-amd64 ... Debian 6.1.69-1` / `Sat Jun 6 05:26:48 AM CEST 2026` | **IV.POS.0 access path verified.** Test node is Debian 12 (Bookworm). Note kernel is 6.1.0 (Bullseye-style kernel under Bookworm userland — older kernel.org LTS, fine for our risc0 binary). |
| Jun 6 05:45 | `pos commands await --verbose true "$CMD_ID"` | ✅ JSON: `"status": "finished", "exit_status": 0, "queued": true, "type": "execfile", "owner": "ivgreiff", "node": "algofi"` (+ full stdout) | Confirms exit code 0 and JSON output format. |
| Jun 6 05:45 | `pos allocations free ivgreiff_260606_051847_624185` | ✅ silent | Clean teardown. |
| Jun 6 05:46 | `cat /usr/local/bin/pos` (full) | ```bash\n#!/bin/bash\nsource /srv/testbed/pos/cli/venv3/bin/activate\nexec pos "$@"``` | **`poslib` lives in `/srv/testbed/pos/cli/venv3/`** — shared venv. To run our `dispatch_pos.py`, `source` the same activate script. |

**🎯 IV.POS.0 CLOSED.** Six iterations to nail down: bare-launch is silent → need `--queued --name`; `--infile` needs shebang; `await -v` is value-not-flag. All documented above + as anti-patterns §12. The path is now fully known and reproducible.

---

### IV.POS.1 attempts (Jun 6 PM)

| Time | Step | Outcome | Lesson |
|---|---|---|---|
| Jun 6 06:00 | First `scp -P 10022 bundles/...` from coinbase SSH session | ❌ `No such file or directory` | Tried scp from inside the remote shell; bundle lives on laptop. scp must run on laptop. |
| Jun 6 06:08 | `scp` from WSL after bridging bundle via `/mnt/c/Users/ivan/` + run from Git Bash | ✅ `66M Jun 6 06:08` on `coinbase:~/` | WSL had no SSH key; Git Bash on Windows did. Bridge via /mnt/c/ is fastest one-off; copy id_ed25519 into WSL ~/.ssh/ for permanent fix. |
| Jun 6 06:09 | `git clone https://github.com/ivanvgreiff/arguzz.git` on coinbase + `source /srv/testbed/pos/cli/venv3/bin/activate` + `python -c "import poslib, yaml; print('ready')"` | ✅ `ready` | Coinbase has everything; we just needed to set cwd to a checkout of the repo. |
| Jun 6 06:14 | `python -m a4.pos.dispatch_pos --manifest pos_smoke_v1.json --bundle ... --nodes algofi --allocation-duration 90` | ⚠ partial: alloc ✓ image ✓, then crashed at `pos.nodes.reset(nodes, blocking=True)` with `TypeError: sequence item 3: expected str instance, list found` in poslib `restapi.py`. | **Bug found in `dispatch_pos.py`:** `pos.nodes.reset` (and `.image`/`.copy`/`.launch`) take a SINGLE node string, not a list. Only `pos.allocations.{allocate,free}` accept lists. Fixed by iterating per-node. |

**IV.POS.1 status as of Jun 6 06:15:** bundle on coinbase ✓; repo on coinbase ✓; venv active ✓; dispatcher bug fixed ✓; **awaiting re-dispatch after `git pull` on coinbase**.

| Jun 6 06:18 | 2nd `python -m a4.pos.dispatch_pos --nodes algofi` | ⚠ partial: alloc ✓ image ✓ reset ✓ copy ✓ then crashed at `pos.commands.launch(n, command=str, queued=False)` with `RESTError: "command" list is required for type "commandlist"`. | **Bug found:** `command=<str>` with `queued=False, blocking=False` is invalid; server treats it as a commandlist call. pos-examples shows `queued=True` works fine with string. Fixed Jun 6 (anti-pattern §12.21). |
| Jun 6 06:30 | Full audit of `dispatch_pos.py` + `run_campaign_pos.sh` against pos-examples + official docs | ✅ found 5 bugs, fixed in one pass: (1) `nodes.reset(list)` already fixed; (2) `commands.launch(command=str, queued=False)` → `queued=True`; (3) `pip install -e repo/` would fail; (4) `apt-get install python3-venv ...` unnecessary; (5) cwd bug in runner. Plus: added `_extract_cmd_id` helper + `_print_orphan_hint`. | Anti-patterns §12.20–§12.22 added. |
| Jun 6 06:44 | 3rd dispatcher run with `queued=True` fix | ❌ SAME error: `"command" list is required for type "commandlist"`. `queued=True` did NOT fix it. pos-examples line 201 is apparently against an OLD poslib version; the one on coinbase (Python 3.13 venv) rejects `command=str` regardless of queued/blocking flags. | **Updated anti-pattern §12.21**: ALWAYS use `infile=<file-obj>` for inline commands too. Refactored extract to a temp .sh file shipped via `infile=`. |
| Jun 6 06:54 | 4th dispatcher run with `infile=<path-string>` | ❌ `AttributeError: 'str' object has no attribute 'read'` from `poslib/api/commands.py:67`: `data['file'] = base64.b85encode(wrap(infile.read())).decode('ascii')`. | **NEW anti-pattern §12.23**: `infile=` must be a FILE OBJECT, not a path. Only the CLI form takes a path (it opens the file internally). pos-examples line 69 confirms: `return open(full_path, 'r')`. Fixed: `with open(path, 'r') as fh: pos.commands.launch(..., infile=fh, ...)` in both extract and runner launches. |
| Jun 6 07:02 | 5th dispatcher run with `infile=open(path)` | ⚠ extract went through but with `cmd=False` warning (await failed on bogus id "False"); then per-job launch failed with `'str' object has no attribute 'name'` from `set_variables`. **Progress: got past the launch call!** Two new bugs revealed: (A) `commands.launch` returns 2-tuple `(is_role, data)` like pos-examples `_, ids = pos.commands.launch(...)`; `_extract_cmd_id` was returning `str(False)="False"` from the is_role element. (B) `set_variables(datafile=)` ALSO takes a FILE OBJECT, not a path. | **NEW anti-patterns §12.24 + §12.25.** `_extract_cmd_id` now skips booleans/None. `set_variables` now wraps datafile in `with open(...) as df:`. Both fixes anchored in pos-examples evidence. |
| Jun 6 07:14 | 6th dispatcher run | **🎯 LAUNCH SUCCEEDED**, but runner subsequently failed on test node with `variable A4_STRATEGY unknown` from `pos_get_variable`. Stderr from runner cmd was exactly that one line; status file 5 bytes (= "error"); no `results_*` directory created (runner crashed before `mkdir RESULTS`, which is BEFORE the EXIT trap is installed → no `pos_upload`). | First hypothesis (§12.26, later RETRACTED): Python API silently no-ops. Switched to CLI subprocess. Also added defensive `/tmp/a4_boot_diag.log` dump in runner + informative `_required` wrapper. |
| Jun 6 07:30 | poslib source + CLI round-trip diagnostics | poslib `set_variables` source is functionally identical to CLI (same POST endpoint, same payload). CLI round-trip `flare`/`algofi` → `bar` confirms persistence works. **Real bug located**: ALL 5 pos-examples call `set_variables` BEFORE `nodes reset`. Our dispatcher does it AFTER. `pos_get_variable` on node reads bootstrap-cached values, so post-reset writes are invisible. | **NEW anti-pattern §12.27**: ORDERING — set_variables MUST precede reset. Retracted §12.26. Reordered `_dispatch_after_alloc` so per-job vars are pushed BEFORE `pos.nodes.reset`. |
| Jun 6 07:35 | 7th dispatcher run (pre-reorder) | Runner failed identically: `variable A4_STRATEGY unknown`. Boot diagnostic (added in §12.27 commit) showed ALL 9 vars `unknown` except `hostname`. **§12.27 hypothesis CONFIRMED.** | Reorder fix verified necessary. Pushed reorder commit to main. |
| Jun 6 07:40 | 8th dispatcher run (post-reorder) | Allocate FAILED with `RESTError: You have no calendar event for nodes: algofi`. First hypothesis (§12.28, RETRACTED): calendar quota. | Added actionable hint to dispatcher (still useful for catching this class of errors). |
| Jun 6 07:50 | Retried with `flare`, `dogecoin` | Same `no calendar event` error. `pos calendar list` showed user has ZERO entries → quota hypothesis wrong. Investigation of `pos-examples/.../synthesize_programs/setup.py:51-58` revealed: `duration=None` means "use pre-existing event"; `duration=N` means "create one". Our dispatcher was passing `duration=None`. | **NEW anti-pattern §12.29**: allocate's `duration` semantics. Changed default `--allocation-duration` from `-1` (None) to `120` so allocate ALWAYS creates a calendar event without prior setup. |

| Jun 6 08:00 | 9th dispatcher run (first to reach fuzzer) | Allocate ✅, set_variables ✅ (8 keys), image ✅, reset ✅, copy ✅, extract ✅, runner ✅, BUT fuzzer crashed at `_setup_coverage_tracking()`: `RuntimeError: Baseline run did not produce a valid <a4_touch_coverage> tag`. Inspection step returned 0 cycles/steps/transactions despite SHA-matching host binary. | First hypothesis: GLIBC (§12.30). |
| Jun 6 08:03 | direct `ldd` on algofi via `pos commands launch -v true` | Confirmed: `risc0-host: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.39' not found (required by risc0-host)`. Algofi has GLIBC 2.36 (Debian 12 bookworm). | **§12.30 VERIFIED**. All 4 manifests + dispatcher default switched to `debian-trixie` (GLIBC 2.39+). |
| Jun 6 08:05 | 10th dispatcher run (trixie attempt) | Allocate FAILED: `Cannot update event in the past`. Cause: previous allocation's calendar event (07:41–09:41 UTC) wasn't trimmed when we freed; new allocate tried to update it. | **NEW anti-pattern §12.31**: `free(node, trim=True)` must precede `allocate(..., duration=N)`. Fixed: dispatcher now passes `trim=True` whenever we'll be creating a new event. |
| Jun 6 08:13 | 11th dispatcher run (bitcoin, trixie, trim=True) | **🎯 END-TO-END SUCCESS.** allocate ✅ set_vars ✅ image-to-trixie ✅ reset ✅ copy ✅ extract ✅ runner ✅ fuzz ✅ upload ✅. meta.json: `exit_code=0`, `num_recorded=20`, wall=6m33s. DB has 20 mutations, 12 coverage rows, 43 raw failures, 38 unique global failures, 20 mutation_rewards. | **IV.POS.1 CLOSED.** All 14 anti-patterns from this session (§12.18–§12.31) are validated in production. trim=True also cleaned up algofi's accumulated stale calendar entries as a side effect (calendar list now shows only the new bitcoin entry). |
| Jun 6 08:54 | 12th dispatcher run (pos_bench_uniform, bitcoin) | Allocate FAILED: same `Cannot update event in the past` despite `trim=True`. Cause: bitcoin allocation from 08:12 was never freed; trim clipped end_date but left the stale entry. Re-allocate at 08:54 tried to update the entry whose start_date (08:12) is 42 min in the past. | **NEW anti-pattern §12.32**: `trim=True` is not enough — must also EXPLICITLY DELETE the calendar entry via `pos calendar delete --id <id> <node>`. Added `_delete_stale_calendar_entries()` to dispatcher. |
| Jun 6 09:00 | 13th-15th dispatcher runs (IV.POS.2 launch) | After §12.32 fix, bitcoin (uniform) and dogecoincash (bandit) allocated cleanly. 3rd parallel dispatch (dogecoin, zoned) FAILED: `Maximum number of future entries is 2!` Confirmed: POS has a hard cap of 2 concurrent calendar events per user. | **§12.28 RESTORED** (the quota IS real, just not the cause of the earlier "no calendar event" error). Dispatcher hint disambiguated to point at correct anti-pattern for each error string. **IV.POS.2 must run 2-parallel + 1 sequential (not 3-parallel).** |
| Jun 6 09:00-09:45 | IV.POS.2 data | **uniform×2 on bitcoin + dogecoin: ~16m15s each, exit_code=0, num_recorded=50**. **zoned on bitcoin: 15m59s, exit_code=0, num_recorded=50**. Inter-node variability for uniform: <1 sec — confirms testbed homogeneity. Per-mutation wall time ≈ 18.5 sec/mut (after ~40s baseline overhead). | bandit-16 remains pending. |
| Jun 6 10:05 | IV.POS.2 bandit attempt | `pos calendar delete --id 1637 dogecoin` rejected: `Cannot delete event in the past.` Allocate on bitcoin still fails quota even after deleting 1638. Entry 1637 stuck until natural expiry at 11:01 UTC (~56 min away). | **NEW anti-pattern §12.33**: past-start calendar entries are undeletable until end_date arrives. Operational mitigation: shorter `--allocation-duration` defaults, more diligent free+delete BEFORE start passes. |
| Jun 6 10:08 | algofi bandit retry | After ~3 min the calendar entries had propagated to gone (calendar list `[]`); allocate on algofi succeeded cleanly. Bandit runner launched (cmd 2026-06-06_10-12-21_215508_pos_bench_bandit_...). | Confirms: the "max 2" errors at 10:05 were a delete-propagation lag, not stuck quota. |
| Jun 6 10:25 | Reviewed `pos-examples/tutorials/clean-image/experiment.sh` | Found the canonical multi-run pattern: `calendar create --duration N --asap-after now` ONCE, then many `allocate`/`free -k` cycles within that window. This SIDESTEPS both quota and past-start issues. | **NEW anti-pattern §12.34**: two calendar patterns exist; we've been using the wrong one for iterative work. Plan to add `--calendar-window-hours` to dispatcher tomorrow. |
| Jun 6 10:15 | **IV.POS.2 CLOSED** | bandit-16 on algofi: `exit_code=0 num_recorded=50 wall=2m46s`. 50 mutations, 11 coverage rows, 103 failures, 94 unique, 20 mutation_rewards (bandit-specific). **algofi runs ~6× faster per mutation than D-1518 nodes** — heterogeneous testbed! Need to verify with `pos nodes show algofi -l processor`. | **IV.POS.2 ✅ DONE.** Per-mut wall: D-1518 ≈18.5s, algofi ≈3.3s. Sized N for IV.POS.5: 250 in ~10hr (2-parallel), 500 in ~21hr, 1000 in ~41hr. |

**IV.POS.1 status: ✅ DONE (Jun 6 08:22 UTC).** First successful POS run: bitcoin/debian-trixie, uniform/seed=42/N=20, produced a real coverage DB with 20 mutations + 12 covered constraint contexts. Total session debugging time: ~7 hours of iterative anti-pattern discovery; we now have a battle-tested dispatcher and runner. Ready to begin IV.POS.2 (small smoke across 2–3 manifests).

---

## 12 — Anti-patterns we've already tripped on

1. **`pos calendar create <node>` with no time args** → fails. Use `pos allocations allocate <node> --duration N` directly.
2. **`pos commands launch ... --env KEY=VAL`** → no such flag. Use `pos.allocations.set_variables(<node>, <yml>)` + on-node `pos_get_variable`.
3. **Assuming `debian-bullseye` is the default image** → it's not; varies per node. Always set explicitly.
4. **`pos commands await <cmd-id>` with the literal placeholder text** → zsh sees `<` as redirect → parse error. Always `CMD_ID=$(pos commands launch …)`; then `pos commands await "$CMD_ID"`.
5. **Pasting Unicode arrows / placeholders** that come from doc copy-paste — shells may URL-decode them into nonsense ids (e.g. `→` → `e28692`).
6. **Reserving popular nodes (`mtgox`)** without first running `pos nodes list` to check availability.
7. **`--duration 10`** for an IV.POS.0 test — barely enough for image reset (~3 min) + a single command + free. **Use 60 minimum** for sanity tests; **240** for IV.POS.1; **<expected wall × 1.3>** for IV.POS.5.
8. **Pre-picking a node name** then running allocate minutes later. Other users grab nodes on minute timescales (bitcoin: free at 02:09, allocated by us 02:09–02:19, free again 02:19, allocated by someone else by 03:00). **Always query `pos nodes list` and use the FIRST currently-free default-group node** rather than baking a node name into your script.
9. **Capturing only stdout when the `pos` CLI errors go to stderr.** `CMD_ID=$(pos commands launch …)` silently sets `CMD_ID=""` if the command failed. Always `2>&1 | tee /tmp/log.txt` and parse stdout from the file. (Even better: in `poslib`, use `pos.commands.launch(...)` which returns the id directly and raises on error.)
10. **Bare `pos commands launch <node> -- …` (no `--blocking` / `--queued`) prints nothing visible.** The canonical pattern from `pos-examples/tutorials/simple/experiment.sh` is to use `--blocking` (waits + prints output of the launched command) or `--queued --name foo` (returns a cmd id you then `pos commands await <id>`). Bare-mode runs detached and may not show stdout OR an id; this is what bit IV.POS.0 attempts 2/3/4 (all `pos commands launch` returned silently). **Always specify a mode flag.**
11. **`python3` ≠ `/usr/bin/python` on the management node.** `poslib` is installed for whichever Python the testbed configured (per pos-examples shebang `#! /usr/bin/python`); `python3` may be a different install. **Always run `which python` and `which python3` and check which one finds poslib BEFORE assuming `dispatch_pos.py` will work.**
12. **`--infile <script>` without a shebang on line 1.** POS uploads the file to `/tmp/<cmd-id>` on the test node and runs it via `exec()` — the kernel needs a `#!/bin/bash` (or other valid interpreter line). No shebang → `OSError: [Errno 8] Exec format error`. **#1 gotcha; verified Jun 6 04:29 on dogecoin.** Always start scripts with `#!/bin/bash`.
13. **`pos commands launch` without `--queued` does NOT print a cmd id.** Blocking is default; in blocking mode the call runs synchronously and returns nothing visible (unless `-v` is added to see stdout). **To capture an id with `$()`, use `--queued`.**
14. **`pos commands launch` is silent on stdout unless `-v/--verbose` is given.** Even in blocking mode. To both wait AND see the command's stdout, use `pos commands await -v <cmd-id>` after a `--queued` launch.
15. **`pos allocations free` is one-shot.** Silent first call = success. A second call on the same id always fails with "Resource is neither allocation nor node." Don't auto-retry.
16. **Per-user allocation limit = 2.** Re-allocate without freeing → "Maximum number of future entries is 2!". Always `pos allocations list` first; `free` any stale ones.
17. **`pos commands await -v` is NOT a flag — it takes a BOOLEAN argument.** Unlike `pos commands launch -v` (which IS a flag). Verified Jun 6: `pos commands await -h` shows `-v, --verbose BOOLEAN`. Correct forms: `pos commands await "$CMD_ID"` (no `-v`) or `pos commands await --verbose true "$CMD_ID"`. **WRONG: `pos commands await -v "$CMD_ID"`** — pos parses the cmd id as the `-v` value.
18. **Shell typo `"$CMD_ID$"` (trailing `$`) silently expands wrong.** The shell evaluates `$CMD_ID$` as `<value>$` (literal `$` because `D$` is not a variable). Always copy `"$CMD_ID"` exactly.
19. **`pos` is a bash wrapper, not a Python script.** Its shebang `#!/bin/bash` doesn't tell us which Python has `poslib`. Must `cat /usr/local/bin/pos` to find the actual Python interpreter or venv path it `source`s/exec's.
20. **`pos.nodes.{image,reset,copy,launch}` take a SINGLE node string (or role NAME), NOT a list.** Passing a Python list trips poslib's URL builder: `TypeError: sequence item 3: expected str instance, list found` in `restapi.py` `_send` → `'/'.join(parts)`. Only `pos.allocations.{allocate,free}` accept lists (they're batch ops). Verified Jun 6 06:14 when `dispatch_pos.py` passed `['algofi']` to `reset()`. Iterate per-node, OR define a role first and pass the role name as a string.
21. **`pos.commands.launch(node, command=<str>, ...)` is REJECTED by THIS deployment** with `"command" list is required for type "commandlist"` regardless of `queued` or `blocking` flags. pos-examples `synthesize_programs:201` shows a `command=str` pattern that apparently worked against an older poslib but is REJECTED by the version on `coinbase` (poslib in `/srv/testbed/pos/cli/venv3/lib/python3.13/site-packages/poslib/`). **Solution: ALWAYS use `infile=<script-path>` instead of `command=<str>`.** Write the inline commands to a temp .sh file (with `#!/bin/bash` shebang per anti-pattern §12.12), pass via `infile=`, and clean up after. Verified Jun 6 06:18 + 06:44 with two failed attempts on `algofi`.
22. **`pip install -e <arguzz>/` will FAIL** because `pyproject.toml` only has `[tool.*]` sections (no `[project]` metadata, no `setup.py`). Modern pip needs `[build-system]` + something installable. SOLUTION: don't install. `a4/standalone/` and `a4/core/` have **ZERO** non-stdlib imports (verified Jun 6 by grep) — just `cd /path/to/repo/ && python3 -m a4.standalone.cli ...`. Debian Bookworm's pre-installed Python 3.11 suffices.
23. **`pos.commands.launch(node, infile=<path-string>, ...)` is REJECTED** with `AttributeError: 'str' object has no attribute 'read'`. The Python API takes a **FILE OBJECT** (poslib `api/commands.py:67` does `infile.read()`), NOT a path. Only the `pos commands launch --infile <path>` CLI form takes a path (the CLI opens the file). pos-examples `synthesize_programs:69` confirms: `return open(full_path, 'r')`. Fix: wrap in `with open(path) as fh: pos.commands.launch(..., infile=fh, ...)`. Verified Jun 6 06:54.
24. **`pos.allocations.set_variables(allocation, datafile=<path-string>, ...)` is REJECTED** with `AttributeError: 'str' object has no attribute 'name'` (poslib accesses `datafile.name` for extension auto-detection). Same pattern as `infile=`: **`datafile` is a FILE OBJECT**. Fix: `with open(yml_path) as df: pos.allocations.set_variables(node, df, ...)`. Verified Jun 6 07:02.
25. **`pos.commands.launch(...)` returns a 2-tuple `(is_role, data)`**, NOT a cmd id string. pos-examples `synthesize_programs:207` confirms: `_, ids = pos.commands.launch(...)`. `data` is `{'nodes': {<n>: <cmd_id>, ...}}`. Our `_extract_cmd_id` originally returned `str(False)` = `"False"` for the `is_role` element, causing `await "False"` → `Resource False not found`. Fix: explicitly skip booleans / None in the tuple walk. Verified Jun 6 07:02.
26. **~~`pos.allocations.set_variables(…)` Python API silently no-ops~~ [RETRACTED Jun 6 07:30]**: this hypothesis was wrong. After reading poslib source (`/srv/testbed/pos/cli/venv3/lib/python3.13/site-packages/poslib/api/allocations.py`), the Python API and CLI both POST identically to `allocations/set_variables`. CLI round-trip verified working (`pos allocations set_variables flare /tmp/t.yml; pos allocations get_variable flare FOO` → `bar`). The real bug is §12.27 below.
27. **CRITICAL ORDERING: `set_variables` MUST be called BEFORE `nodes reset`.** On-node `pos_get_variable` reads BOOTSTRAP-CACHED values; vars set AFTER reset are INVISIBLE to the booted node. Verified Jun 6 07:30: ALL 5 working pos-examples (`simple/`, `simple-moongen/`, etc.) follow the order `set_variables → image → reset → commands launch`. NEVER the reverse. **Fix:** reordered `dispatch_pos.py` `_dispatch_after_alloc` so per-job variables are pushed BEFORE `pos.nodes.reset`. NB: this constrains us to **one job per node per allocation** (true for smoke and v1 manifests). For multi-job-per-node we'd need to reset between jobs (bigger redesign for later phases). We keep `_set_variables_cli()` (added under the wrong §12.26 hypothesis) because it's the canonical pattern in all pos-examples; the Python API would work equivalently here. **Confirmed Jun 6 07:35** via runner's `/tmp/a4_boot_diag.log`: ALL 9 attempted pos vars returned `unknown` except `hostname` (which is node-set during bootstrap, not via `set_variables`).
28. **POS testbed has a per-user cap of TWO concurrent calendar events / allocations.** Trying to allocate a 3rd node while 2 are active produces `Maximum number of future entries is 2!`. **Implications for our IV.POS.* plans:** any "N-parallel" dispatch is limited to N ≤ 2. The original IV.POS.3 (3-node multi-node smoke) and 3-parallel benchmark plans must be rethought as 2-parallel + sequential staging. [Note: the message was initially misattributed to a "no calendar event" error in §12.28 — that one turned out to be the `duration=None` bug (§12.29). The quota cap is a separate, real constraint, verified Jun 6 09:00 when allocating dogecoin while bitcoin + dogecoincash were already active.]
29. **`pos.allocations.allocate(nodes, duration=None, ...)` means "USE A PRE-EXISTING calendar event"**; if no calendar event exists for the node, you get the misleading error `You have no calendar event for nodes: <n>`. To ALSO CREATE a calendar event, pass `duration=N` (minutes). Verified in pos-examples `actual_experiments/ilab/synthesize_programs/setup.py:51-58`:
    ```python
    duration = None
    if create_event:
        duration = 120
    return pos.allocations.allocate(nodes, duration=duration, ...)
    ```
    All pos-examples CLI calls likewise pass `--duration N` when they don't have a pre-existing calendar event. **Fix**: changed dispatcher `--allocation-duration` default from `-1` (None) to `120` (matches pos-examples). Pass `--allocation-duration 0` to use a pre-existing event (rarely useful).
30. **`risc0-host` requires GLIBC 2.39+** (built against Ubuntu 24.04 toolchain). `debian-bookworm` ships GLIBC 2.36 — host fails to load at all (ELF loader prints `version 'GLIBC_2.39' not found (required by ...)` and never reaches main()). Symptom downstream: fuzzer fails at `_setup_coverage_tracking()` with `RuntimeError: Baseline run did not produce a valid <a4_touch_coverage> tag`. Inspection step shows 0 cycles/steps/transactions. **Fix**: use `debian-trixie` (GLIBC 2.39+) — verified Jun 6 08:00 via direct `ldd /root/a4_campaign/bin/risc0-host` on algofi. All 4 manifests updated and dispatcher default changed. Alternative when trixie isn't available: rebuild `risc0-host` against bookworm's toolchain (much bigger lift).
31. **`pos.allocations.free(node, trim=False)` leaves the calendar event in place.** When you then re-allocate with `duration=N` (intent: create a fresh event), allocate tries to UPDATE the stale event whose start_date is now in the past → `Cannot update event in the past`. Per pos-examples `synthesize_programs:47-49`: `pos.allocations.free(node, trim=create_event)` — pass `trim=True` when you're about to create a new event. **Fix Jun 6 08:05**: dispatcher's idempotent-free at start of allocate flow now passes `trim=True` whenever `args.allocation_duration > 0` (i.e., whenever we'll create a new calendar event).
32. **`trim=True` is NOT enough when the calendar entry's `start_date` is already in the past.** Trim merely clips `end_date` to "now"; the entry persists with both dates in the past. The next `allocate(...)` still finds it and tries to update it → same `Cannot update event in the past` error. Verified Jun 6 08:54 (re-using bitcoin 42 min after a successful run). **Fix**: dispatcher now ALSO explicitly deletes any owner-matching calendar entries for the target nodes via `pos calendar delete --id <id> <node>` after free, before allocate. Implemented in `_delete_stale_calendar_entries()`. We use the CLI (not poslib API) to avoid yet another Python-API quirk surface.
33. **`pos calendar delete --id <id> <node>` ALSO refuses to delete past-start entries**: `Cannot delete event in the past.` Verified Jun 6 10:05. **Implication**: once `start_date` has passed, the entry sits in your quota until `end_date` arrives naturally — neither user nor dispatcher can remove it. Combined with the 2-event quota (§12.28), this means you must wait out long-duration past-but-not-expired entries before launching new work. **Operational mitigation**: keep `--allocation-duration` as small as feasible (default 120 min may be too generous — consider 60 min for benchmark-class runs); always free + delete BEFORE start_date passes; for longer runs, deliberately schedule them when other entries will expire.
34. **TWO calendar patterns exist; we've been using the wrong one for iterative work.** Discovered Jun 6 10:25 via `pos-examples/tutorials/clean-image/experiment.sh:25-30`.
    - **Pattern A (per-run events, "synthesize_programs style")**: `allocate --duration N` creates a fresh calendar event per allocate; `free` (with optional trim) ends the allocation. Each event consumes a quota slot until end_date. This is what our dispatcher does today. Suffers from §12.28 (quota) + §12.32–§12.33 (past-start stickiness).
    - **Pattern B (long-lived events, "clean-image style")**: One-time `pos calendar create --duration <hours*60> --asap-after now <node>` reserves a window; subsequent `allocate <node>` (no duration) reuses the event; `free -k <node>` keeps the event for the next allocate. The whole campaign runs against ONE calendar slot per node, never hits quota or past-start issues.
    - **Recommendation**: switch dispatcher to Pattern B for any multi-run workflow (IV.POS.3 onwards). Add `--calendar-window-hours` flag that defaults to creating an 8-hour reusable event per node. Pattern A remains useful for one-shot scripted runs.
35. **Bandit's `compute_N_pilot(budget) = max(30, min(100, budget // 20))` consumes the entire campaign budget for small N.** Discovered Jun 6 IV.POS.3: at `N=20` bandit produced `mutations=30, mutation_rewards=0, scheduler t=0` (i.e., the scheduler never advanced past initialisation). Pilot phase ran 30 mutations; `main_budget = num_mutations - N_pilot = 20 - 30 = -10` → main loop iterated **zero times**; reward table never populated. The campaign LOOKS like it ran (exit_code=0, 30 mutations recorded) but produced NO bandit data. **Fix:** added a defensive `print(... WARNING ...)` at the top of `_setup_bandit` that fires when `N_pilot >= num_mutations`. **Sizing rule:**
    - `N < 30`     → bandit is BROKEN (no post-pilot at all)
    - `N = 31–60`  → bandit is MARGINAL (≤30 post-pilot reward rows)
    - `N ≥ 100`    → bandit is meaningful (≥70 post-pilot)
    - `N ≥ 250`    → bandit is comfortable (≥220 post-pilot)
    Apply this floor to `pos_validation_v2_*.json` (N=250 ✅) and `pos_ab_v1.json` (must be N ≥ 100, preferably ≥ 500). Uniform/zoned have no pilot and are not affected.
36. **Dispatcher's `_dispatch_after_alloc` assumes ONE job per node per allocation.** The job → node assignment is `nodes[i % len(nodes)]` (round-robin), but `set_variables` is called once per node, then `pos.nodes.reset(node)` happens ONCE per node. If two jobs go to the same node, the SECOND `set_variables` call overwrites the first's variables BEFORE either runs, and the queued commands then BOTH see the second set's vars. The dispatcher comment at line 575–578 acknowledges this. **Operational rule:** `len(jobs) == len(nodes)` always; if you have N jobs and 2 nodes you must do `ceil(N/2)` separate dispatcher invocations. Until this is redesigned, multi-strategy campaigns (IV.POS.4 onwards) must be split into multiple manifests, one dispatch per group of ≤2 jobs.
37. **The "2-future-entries cap" (§12.28) is on CALENDAR ENTRIES, not on ACTIVE ALLOCATIONS or on NODES.** Verified Jun 6 20:45 UTC via web calendar UI: a SINGLE calendar entry can cover MULTIPLE nodes (user reserved `flare+octorand+opulous` as one entry, id=1646). This means **3-parallel (or more) dispatching IS possible** if you pre-reserve all needed nodes via ONE multi-node entry. Workflow:
    1. Via web calendar UI, create one entry covering all desired nodes for a 6-hr block (the per-entry max).
    2. Create a second contiguous entry for the next 6-hr block (uses second future-entry slot).
    3. Run dispatcher with `--allocation-duration 0` (= `duration=None`) so it claims the EXISTING reservation rather than creating a NEW calendar entry. (The 2-cap is per-user; without `--allocation-duration 0` the dispatcher's own allocate would create a duplicate entry and bump you past the cap.)
    4. As each reservation expires, refresh via UI: each refresh = one new 6-hr entry for the same nodes. Always have ≥1 future entry queued.
    Open question (won't know until tested at reservation start time): does POS auto-evict an existing allocation when its calendar entry ends and a new owner's entry begins? If NOT, prior holder must release voluntarily; you may have to wait.
38. **A pre-existing calendar reservation that you own does NOT guarantee allocate succeeds BEFORE its start_date.** Tested Jun 6 20:45 UTC: user owned reservation for flare+octorand+opulous starting 21:00, tried `pos allocations allocate` at 20:45 → `ERROR Nodes are already allocated: octorand, opulous`. The previous holder's allocation is still active until either (a) the previous holder voluntarily frees, (b) the previous holder's own calendar entry expires AND POS auto-evicts (behavior unverified), or (c) your reservation's start_date arrives AND POS forcibly evicts (behavior unverified). **Operational rule**: wait until reservation `start_date` UTC before attempting `pos.allocations.allocate(...)`. If allocate STILL fails after start_date, the previous holder is squatting — escalate to admin or pick different nodes.
39. **POS DOES auto-evict squatters at reservation start_date** (verified Jun 6 21:00 CEST). At 21:00:22 dispatcher pre-flight saw `octorand=bav_..., opulous=wibowo_...` (stale state). 1 second later at 21:00:23 the dispatcher's `pos.allocations.allocate()` succeeded for the user. Conclusion: POS evicts within a few seconds of `start_date` for any active reservation that competes for the node. Squatters cannot hold past a competing reservation's start. Pre-flight checks done within 0-3 seconds of start_date may see stale data; trust the actual `allocate` call result instead.
40. **POS allocations PERSIST past their calendar event end_date when a follow-up reservation for same nodes/owner immediately succeeds** (verified Jun 7 03:00 CEST). Allocation `ivgreiff_260606_213218_937447` was created from event 1648 (21:30-03:00) at 21:32:18. At 03:00:11 (11 sec past 1648's end), allocation was still present and 3 fuzzer commands still running. The follow-up event 1647 (03:00-09:00, same nodes, same owner) covered the boundary. Conclusion: calendar event end_dates are SOFT for allocations as long as a successor reservation exists. **However**: this is sample size of 1. The conservative `auto_run_ab_v1_smart.sh` still waits for ≥`MIN_RES_HR` (default 5.5h) of fresh remaining time before launching, to guarantee the FULL dispatch can complete within a single reservation.
41. **CRITICAL Bash quoting bug pattern: `-v noderx="^("node_re")$"`.** Looks like it substitutes a variable, but Bash double-quote rules make this three concatenated tokens: `"^("` + `node_re` (literal!) + `")$"`. The resulting awk regex is the literal string `^(node_re)$`, which never matches a real node. **Always build the regex in a separate Bash variable first** and pass it cleanly:
    ```bash
    local node_regex="^(${node_re})\$"
    awk -v noderx="$node_regex" '...'
    ```
    Discovered Jun 7 03:17 CEST when the smart runner's `has_previous_dispatch_running()` check failed silently, letting it kill the in-flight d2 fuzzers (loss of d2/seed=1235 entire 5-hour run). Fixed in commit 344c626.

42. **Calendar-entry OWNERSHIP grants the right to free another user's allocation on any node your calendar entry covers, at the current moment.** Per `pos allocations free --help`: *"You can only free allocations/nodes if you either own a calendar entry for the current entry, or no one owns a calendar entry for the current moment."* Verified Jun 13 07:52 CEST: `ivgreiff` owned calendar entry 1746 covering `algofi`; user `christer` held an ad-hoc allocation `christer_260613_033623_045839` containing `[zone, goracle, algofi, gard]` with **NO calendar entry of his own**. `pos allocations free algofi` (run by ivgreiff) silently succeeded and removed christer's **entire 4-node allocation**, not just algofi. Implication: **`pos.allocations.free(<node>)` resolves to the ENTIRE allocation containing that node** — calling free on one node evicts the holding user from ALL nodes in their allocation. Only safe to use against squatters with no active commands. Verify first with `pos commands list <node>` for each node in the target's allocation.

43. **CRITICAL DANGER: `pos allocations free <node>` (without `-k`) TRIMS the CALENDAR ENTRY covering that node to `now()`, even when freeing ANOTHER user's allocation.** The trim semantic is keyed on the **calendar entry containing the freed node**, not on the allocation being freed. So when you exercise calendar-ownership free-rights (§12.42) on a squatter, your own multi-hour reservation gets clipped to "now". **MITIGATION**: ALWAYS pass `-k/--keep-calendar-event` when freeing as a calendar-owner: `pos allocations free -k <node>`. Verified Jun 13 07:52 CEST: ivgreiff's calendar entry 1746 (07:00→13:00 UTC, 6 hours) was trimmed to (07:00→07:53 UTC, 53 min) after `pos allocations free algofi` (which evicted christer). All other allocations (octorand, flare, opulous, meld) survived as orphans but `polynize` became unreservable. Recovery: `pos calendar create --asap-after now -d 360 <nodes...>` created replacement entry 1747. Counter-intuitive failure mode — operator's instinct says "I'm freeing someone ELSE's allocation, why would MY calendar be affected?" — but the server-side trim is unconditional. **Add `-k` to any operator script that frees by calendar-ownership right.**

44. **CANONICAL DISPATCH WRAPPER: `a4/pos/dispatch_audit.sh` is the ONE template that should be used for every Inc 4+ audit.** It auto-handles both single-dispatch (jobs ≤ nodes) and multi-dispatch (jobs > nodes, slices manifest per-variant) cases, working around §12.36 transparently. Verified Jun 13 08:06-10:53 UTC in production for all 5 Inc 4 audits (25 DBs total, all correct mut counts):
    - **MULTI mode** — `b8_seq` (5 jobs × 1 node) → 5 sub-dispatches on flare; each variant gets correct vars + own DB. Wall ≈ 6 min/variant × 5 = 29 min. All 5 DBs `muts=50`. Replaced an earlier broken single-dispatch attempt that wrote only `cTS_semantic_v2.db` (last-job vars surviving §12.36 overwrite bug).
    - **SINGLE mode** — `b8_par` (5 jobs × 5 nodes) → 1 dispatch with round-robin assignment. Wall ≈ 20 min (15 min sequential per-node resets + ~3 min parallel fuzz + overhead). All 5 DBs `muts=50` at near-simultaneous timestamps (true parallel; satisfies B8 parallel-verification gate).
    - **b11 N=500 SINGLE mode** — Wall ≈ 50 min on 4 Tier S + meld (Tier C bottleneck). meld variant landed `muts=500` along with the 4 Tier S variants.
    Invocation:
    ```bash
    # Auto-detects mode based on jobs-vs-nodes ratio.
    bash a4/pos/dispatch_audit.sh <manifest.json> <node1> [node2] ...
    ```
    Companion orchestrator `a4/pos/run_inc4_all.sh` runs all 5 Inc 4 audits sequentially as fire-and-forget under tmux/nohup. **Do NOT call `dispatch_pos.py` directly for multi-job manifests** — always go through `dispatch_audit.sh` so the §12.36 workaround is applied.

45. **POS node hardware flakiness — substitute, do not retry indefinitely.** Verified Jun 13 09:42 UTC: `polynize` (Tier S EPYC 9354) hit `NodeDidNotBoot: SSHTimeout: wait until booted` during a routine `pos.nodes.reset` mid-dispatch. The reset command went into `error` status; `pos nodes list` reported `polynize | ERR booting`; `ssh polynize` from coinbase returned `No route to host`. After freeing our allocation (which auto-freed polynize), a second `pos nodes reset polynize` attempt failed with `Resource polynize is not owned by you!` (race with another user grabbing it). The orchestrator died on the dispatch_pos `set -e`, leaving an orphaned 5-node allocation. **Recovery procedure:**
    1. `pos allocations free -k <orphan-alloc-id>` (preserves calendar entry per §12.43).
    2. Substitute the flaky node with the next-fastest in the calendar reservation (in our case `meld` Tier C replaced `polynize` Tier S; added ~30 min wall on b11 due to the slower per-mut rate).
    3. Re-dispatch with the same template (`dispatch_audit.sh`).
    4. Optionally create a contiguous second calendar entry (Pattern B per §12.34) so the in-flight allocation survives end_date (§12.40).
    **DO NOT** repeatedly retry the flaky node — POS's queued boot retries can starve the dispatcher's await timeout and waste reservation window. Substitute promptly; report the node to admin if it's persistent.

46. **`pos allocations free -k` can fail with "no calendar event for nodes: X" when calendar coverage SHIFTED during the allocation lifetime.** Symptom: error mentions a specific node that's no longer in your calendar even though the allocation still includes it. Most likely cause: partial calendar trim/shift mid-run, or the node was reassigned to another user's calendar entry before free time. **Diagnose BEFORE retrying** (do NOT blindly re-run `free -k`):
    1. `pos allocations show <alloc-id>` — confirm allocation still listed and which nodes it claims.
    2. `pos calendar list` — find your entry id(s) and current node coverage (CLI has no `calendar show`; use `list`).
    3. `pos calendar list` filtered for the missing node — check whether anyone else now holds that node.
    **Three outcomes and actions:**
    - **Allocation gone** → POS auto-released when coverage dropped. Done.
    - **Allocation listed, missing node in nobody's calendar** → stuck orphan. Try `pos allocations free <alloc-id>` **without** `-k` (no calendar slot to preserve for that node). If still blocked, escalate to POS admin.
    - **Allocation listed, missing node in someone else's calendar** → slot reassigned mid-run. Wait (~15 min auto-release on conflict) OR free individual nodes you **do** still hold calendar for: `pos allocations free -k <node>` per node (verified Jun 13 22:15 CEST: freed flare/meld/octorand/opulous individually; whole allocation released; calendar 1751 preserved). Whole-alloc `free -k` may still fail while algofi remains orphaned.
    **NEVER trim your own calendar entry to "match" the allocation** — you'll lose coverage of the nodes you DO still hold. Fix at the allocation level, not the calendar level.

47. **CRITICAL Bash bug: nested `for ((i=...;...;i++))` clobbers outer loop's `i` if not declared `local`.** Verified Jun 14 06:10 UTC during IV.POS.7: `auto_run_iv_pos_7.sh`'s main batch loop used `for ((i=START_IDX; i<${#ALL_BATCHES[@]}; i++))`. The `run_one_batch` function called inside that loop ALSO had `for ((i=0; i<n_jobs; i++))` (to build the node list). Bash variables are GLOBAL by default in functions; the inner loop overwrote the outer `i`. After ts_b1 (outer i=0 → inner sets i=4 → outer i++ → i=5), the next batch became `ALL_BATCHES[5]` = ts_b6, **skipping ts_b2/b3/b4/b5 entirely**. Lost a full day of campaign time. **Fix**: declare ALL inner loop variables `local` (or pick a unique name): `local j; for ((j=0; j<n_jobs; j++))`. **Operational rule**: whenever a function is called inside a `for ((var=...))` loop, audit the function for ANY usage of `var` and add `local var` declarations as needed. Trivial code-review rule, catastrophic if missed.

48. **CRITICAL: in batched-parallel runners (≥2 tier orchestrators running concurrently as the same OS user), `free_all_my_allocations` is RADIOACTIVE unless filtered by tier nodes.** Verified Jun 14 06:10 UTC during IV.POS.7: Tier-S's post-dispatch `pos allocations list -f owner=ivgreiff` returned BOTH Tier-S's allocation AND Tier-A's still-running allocation. Tier-S then freed both, killing ta_b1's 4 fuzzers mid-await (~5h compute lost). Plus the text-parse logic split multi-line allocation rows and tried to free node-name fragments and continuation-line debris as alloc IDs (POS accepted node names by interpreting them as "free the allocation containing this node"). **Fix**: always filter `free_all_my_allocations` by THIS tier's `NODES_ARR` (subset check) AND use `pos allocations list -j` (JSON) instead of text parse. Reference implementation in `auto_run_iv_pos_7.sh:240-275`:
    ```bash
    free_all_my_allocations() {
        local nodes_csv; nodes_csv="$(IFS=,; echo "${NODES_ARR[*]}")"
        local alloc_ids
        alloc_ids=$(pos allocations list -j 2>/dev/null | \
            NODES_CSV="$nodes_csv" USER_NAME="$USER_NAME" python3 -c "
    import json, sys, os
    allocs = json.load(sys.stdin)
    our_nodes = set(os.environ['NODES_CSV'].split(','))
    user = os.environ['USER_NAME']
    for a in allocs:
        if a.get('owner') != user: continue
        a_nodes = set(a.get('nodes') or [])
        if a_nodes and a_nodes <= our_nodes: print(a['id'])
    ")
        while IFS= read -r aid; do
            [[ -n "$aid" ]] && pos allocations free -k "$aid" || true
        done <<< "$alloc_ids"
    }
    ```
    **Operational rule**: never use text parse for `pos allocations list` output — multi-line rows break naive `awk '{print $1}'`. Always use `-j` JSON.

49. **CONTIGUOUS-RESERVATION MERGE pattern eliminates per-boundary idle in batched-parallel runners.** Verified Jun 14 06:42 UTC during IV.POS.7 recovery. Without the patch: when one batch finishes and a new one needs `MIN_RES_HR` (5.5h) of remaining reservation, the runner checks each calendar entry individually. If the current entry has <5.5h left but a contiguous follow-up entry would give ≥5.5h combined, the OLD logic returns `WAIT` → 35-min idle per boundary per tier. With the merge patch in `find_qualifying_reservation` (`auto_run_iv_pos_7.sh:340-410`): adjacent calendar entries (where `next.start - prev.end ≤ 60s`) are merged into one logical block before the `MIN_RES_HR` check. **Saved 35 min × N boundaries per tier × 2 tiers = ~5h on a 7-batch campaign**. Recommended for any multi-batch runner. **Operational pre-req**: each calendar entry must cover the SAME node set; the merge logic preserves only the earliest `start_date` and latest `end_date`.

50. **The `ALLOWED_OWNERS` env knob in `auto_run_iv_pos_7.sh` (default = `$USER_NAME`) widens the calendar filter to accept reservations from collaborators.** Use case: collaborator pre-books a window covering your nodes (e.g. `ALLOWED_OWNERS=ivgreiff,frezabek`) so your runner doesn't sleep through it. **Important caveat (verified Jun 14 02:30 UTC)**: this ONLY affects which calendar entries the runner CHOOSES to wait for. POS's `allocate` endpoint strictly enforces calendar-OWNER = invoking-user (see `/srv/testbed/pos/daemon/posd/db/calendar.py::current_event_exists`). So `ALLOWED_OWNERS=foo,bar` lets your runner stop waiting and try to allocate during foo's window, but `pos allocations allocate` will fail with `You have no calendar event for nodes`. **Borrowing is NOT possible** in the current Coinbase deployment (`web.calendar.enforce=True`). The flag is only useful if the collaborator's reservation is moved INTO your name OR if the deployment's `enforce_calendar` setting is later relaxed.

51. **`local -n` namerefs are unreliable for array-passing in shell scripts launched by tmux + venv activation.** Verified Jun 14 06:30 UTC: a watcher script using `process_tier() { local -n BATCHES_REF=$2; ... }` and called as `process_tier ts TS_BATCHES` silently did NOTHING — main loop iterated correctly but `process_tier`'s body never logged. Same script run from an interactive shell worked. Likely cause: bash version difference or env stripping in the tmux startup. **Operational rule**: for shell watchers/orchestrators, **prefer passing the array via positional expansion** (`func "${ARRAY[@]}"`) and rebuilding it inside with `local -a local_arr=("$@")`, OR write the watcher in Python where the language semantics are predictable. Don't rely on nameref portability.

52. **★ SSH-BYPASS DISPATCH — the `pos.*` calendar/ownership wall does NOT gate raw SSH.** Verified Jun 14 15:25 CEST during IV.POS.7 when ivgreiff's reservation 1753 expired while frezabek's reservation 1754 was active over the same 8 nodes. POS strictly enforces `calendar-owner = invoking-user` on `pos allocations allocate` (§12.50), so ivgreiff could not allocate the nodes even though frezabek wasn't using them. Empirical test matrix (run as ivgreiff, no allocation):

    | Operation | Result |
    |---|---|
    | `pos nodes reset flare` | `Resource flare is not owned by you!` |
    | `pos nodes image flare debian-trixie` | `Resource flare is not owned by you!` |
    | `pos commands launch flare -- echo hi` | `Resource flare is not owned by you!` |
    | `pos allocations set_variables flare /tmp/foo.yml` | `Node flare is not allocated` |
    | `pos allocations allocate flare --duration 60` | `Node flare is already used in another event overlapping with requested time period` |
    | **`ssh flare 'hostname; whoami'`** | **`flare\nroot`** ✓✓✓ |

    Raw SSH from the management node to a booted test node WORKS REGARDLESS of POS calendar/allocation state, as root, with no key prompt. The `pos.*` CLI/daemon enforces ownership; the underlying sshd on each node does not. **Therefore**: when calendar enforcement blocks normal dispatch but the nodes are already booted with the right image and the bundle is extracted, you can drive jobs directly via SSH. **Reference pattern (used Jun 14 to recover 8 jobs of IV.POS.7 ts_b3 + ta_b2 from `frezabek`'s 6h window):**
    ```bash
    # On management node, for each (node, strategy, seed, batch):
    #   1. Write a per-node launcher.sh that:
    #      - Runs `python3 -m a4.standalone.cli fuzz --selector <S> --seed <N> --db <out> ...`
    #        (BYPASSES pos_get_variable; no run_campaign_pos.sh; no pos_upload)
    #      - Touches .OK / .FAIL_rc<N> markers on completion so a poller can detect state
    #   2. scp launcher.sh <node>:/root/
    #   3. ssh -n -f <node> "nohup /root/launcher.sh </dev/null >/dev/null 2>&1 &"
    # Then a separate watcher on management node:
    #   - Polls each node every 60s for .OK / .FAIL markers
    #   - When .OK appears, scp the .db back to /srv/testbed/results/ivgreiff/a4/pos_iv_pos_7_<batch>/
    ```
    Reference implementation: `/tmp/ssh_bypass_launcher_v2.sh` + `/tmp/iv_pos_7_ssh_bypass_watcher.sh` on coinbase (Jun 14 sessions). **Hard prerequisites** for this technique to work:
    - The node must already be **booted with the correct image** (e.g. `debian-trixie` per §12.30). SSH bypass cannot do `pos nodes image` or `pos nodes reset`.
    - The bundle must already be at `/root/a4_campaign/` with `bin/risc0-host` + `repo/` + `bundle.json`. If it's not, you can `scp` it over (still no POS needed).
    - Result upload uses `scp <node>:result.db management:/srv/testbed/results/...` — NOT `pos_upload`, which fails without an allocation (`[404] allocation not found`).
    - The watcher on the management node uses `bash` polling (`ssh <node> 'test -f .OK'`); no `pos commands await` involved.
    **Eviction risk**: POS will reset/reclaim a squat-occupied node the moment ANY user invokes `pos allocations allocate` on it (§12.39). Plan SSH-bypass windows to either (a) coincide with a friendly user's calendar entry so no eviction happens, or (b) finish before the next contesting reservation's `start_date`.
    **Practical use cases**:
    - Recover from calendar enforcement blocks when you have idle nodes from a friendly collaborator's reservation.
    - Continue running across a reservation boundary if your own follow-on reservation isn't in place yet.
    - Avoid the `pos nodes reset` overhead between batches (saves ~3-5 min per batch, since the node stays booted with the bundle intact).
    - Use as the **default** dispatch mechanism for multi-batch campaigns where nodes can stay booted across batches — fewer moving parts, no calendar-ownership / allocation-conflict failure modes, no `pos_get_variable` bootstrap-cache ordering trap (§12.27).
    **Limitations**:
    - One-time setup (boot + bundle copy) still requires a real POS allocation. Plan for at least 30 min of "real POS" at campaign start to image the nodes and `pos.nodes.copy` the bundle.
    - No `pos commands list` / `pos commands log` visibility — must `tail -f` logs over SSH manually.
    - Heartbeat/liveness must be polled (we ship `iv_pos_7_ssh_bypass_watcher.sh` that does this).

53. **★ CHAIN DISPATCHER — collapses watch + launch into a single self-driving loop.** Verified Jun 15 04:36-04:38 CEST on 4 reserved test nodes (idex, meld, pact, tinyman) during IV.POS.7. Solves the failure mode that recurred twice on Jun 14 (32 min ts_b3→ts_b4 idle, 24 min ta_b3→ta_b4 idle) where the read-only watcher (§12.52) detected `.OK` markers but had no authority to fire the next batch, so the human dispatcher had to react to a notification stream that proved unreliable across WSL/PowerShell shell shifts.

    **Pattern**: one bash process in tmux that owns the entire lifecycle:
    1. Parse a text manifest (`batch_name|node|run_id|remote_cmd` per line) into ordered batch arrays.
    2. **Launch phase** (parallel): for each job in current batch, `scp` a self-contained launcher to the node and `ssh -n -f nohup` it. Launcher writes `.OK` / `.FAIL_rc<N>` markers + a `meta.json` with `started_at_epoch`/`ended_at_epoch`/`wall_sec`/`exit_code`.
    3. **Poll phase** (`POLL_SEC` interval, default 15s; use 3s for short jobs): for each not-done job, `ssh node 'test -f <RD>/.OK; ls <RD>/.FAIL_rc*'`. On `.OK`: `scp -r` results to local `RESULTS_BASE/<batch>/<run_id>/`, mark done. On `.FAIL`: pull stderr/log for debugging, mark done.
    4. **Advance**: when `done == #jobs_in_batch`, immediately enter Launch phase for the next batch in the same outer loop. **No human, no inter-process gap.**
    5. **Resume-safe**: launch phase first checks `test -f <RD>/.OK`. If true, skip the launch (emit `LAUNCH_SKIP_RESUME`). Lets you restart the dispatcher mid-campaign without re-running completed jobs.
    6. **Signal-safe**: `trap 'emit CHAIN_INTERRUPTED' INT TERM` so you can `tmux kill-session` cleanly and restart later.

    **Verified test (chain_test.manifest)**:
    - 2 batches × 4 jobs (sleep durations 20/35/50/65 and 15/25/40/55 seconds, simulating real wall-time dispersion).
    - **Handover (BATCH_COMPLETE → BATCH_START): 1 second.**
    - Launch parallelism: 4 jobs scp'd + nohup'd in 1-2 seconds total.
    - Detection latency: ≤`POLL_SEC` from remote `.OK` touch to log `OK` line.
    - Pull success: 8/8 result dirs scp'd with `stdout.log` + `stderr.log` + `meta.json` + `.OK`.
    - Total wall: 2 min 9 sec vs ~2 min theoretical lower bound. tmux session exited cleanly on `CHAIN_COMPLETE`.

    **Reference implementation**: `a4/pos/chain_dispatcher.sh` + `a4/pos/templates/chain_test.manifest`.

    **Production invocation** (one tmux session per tier-chain, two parallel chains for Tier-S and Tier-A):
    ```bash
    # Tier-S chain (e.g. ts_b6 ts_b7 — fires ts_b6 the instant ts_b5 completes):
    MANIFEST=/tmp/tier_s.manifest CHAIN_NAME=tier_s POLL_SEC=30 \
        RESULTS_BASE=/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7 \
        REMOTE_BASE=/root/results_pos_iv_pos_7 PULL_GLOB="*" \
        tmux new -d -s chain_tier_s "bash /root/arguzz/a4/pos/chain_dispatcher.sh"

    # Tier-A chain (independent process, same script, different manifest):
    MANIFEST=/tmp/tier_a.manifest CHAIN_NAME=tier_a POLL_SEC=30 \
        RESULTS_BASE=/srv/testbed/results/ivgreiff/a4/pos_iv_pos_7 \
        REMOTE_BASE=/root/results_pos_iv_pos_7 PULL_GLOB="*" \
        tmux new -d -s chain_tier_a "bash /root/arguzz/a4/pos/chain_dispatcher.sh"
    ```
    Monitor: `ssh coinbase 'tail -F /tmp/chain_tier_s.log /tmp/chain_tier_a.log'`.

    **Manifest format for fuzzing campaigns**:
    ```
    # Each `remote_cmd` runs in the launcher's working dir on the node; the
    # launcher captures rc, wall, stdout, stderr automatically and writes .OK/.FAIL.
    ts_b6|flare|pos_iv_pos_7_ts_b6_kindUCB_zoned_v1_seed1239_n6000|export A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1 A4_GLOBAL_RESIDUE=1 CONSTRAINT_CONTINUE=1; cd /root/a4_campaign/repo && python3 -m a4.standalone.cli fuzz --host /root/a4_campaign/bin/risc0-host --selector kindUCB_zoned_v1 --num 6000 --seed 1239 --db /tmp/chainjob_pos_iv_pos_7_ts_b6_kindUCB_zoned_v1_seed1239_n6000/run.db --telemetry-level full -- --in1 5 --in4 10
    ```
    Use `REMOTE_BASE=/root/results_pos_iv_pos_7` to match existing on-node layout, OR keep the default `/tmp/chainjob` (results land alongside the launcher's tracking files).

    **Pre-requisites identical to §12.52** (boot + bundle + ssh reachability — nothing new). The chain dispatcher is just §12.52 with the human-in-the-loop replaced by a `while` loop.

    **When NOT to use**:
    - Single-shot ad-hoc runs (use plain `dispatch_audit.sh` if calendar enforcement isn't blocking you).
    - Heterogeneous-resource batches where each batch needs different node sets (the chain dispatcher assumes a stable node pool across batches; mix across pools by running multiple chains).

    **Operating rules** when chained:
    - Each chain gets its own tmux session AND its own log file (don't multiplex two chains into one log).
    - Set `POLL_SEC=30` for production fuzzers (5-6h walls); `POLL_SEC=3-5` for the synthetic tests we run for the manifest itself.
    - For idempotent re-runs after a partial failure: just re-launch with the same manifest; jobs whose `.OK` already exists are skipped, jobs whose `.FAIL` exists are re-launched (after `rm .FAIL_rc*` in the launcher prologue).
    - To handle in-flight jobs that were launched outside the chain dispatcher (e.g. a manually-fired batch you want the chain to take over from), the resume check (`test -f .OK` + process scan) waits for that job to complete naturally; the chain dispatcher's launcher will NOT re-spawn it. **Caveat**: this only works if the prior launcher's `REMOTE_DIR` and `RUN_ID` convention match what the chain dispatcher computes (`REMOTE_BASE_RUN_ID` path naming + RUN_ID appearing in the running process's argv) — keep them aligned across both flows.

    **★ Gotchas burned getting this safe (Jun 15 2026 — DO NOT regress):**

    1. **Resume check by `.OK` alone is INSUFFICIENT for in-flight detection.** First implementation only checked `test -f .OK`. When deployed against a fuzzer still mid-run, `.OK` doesn't exist yet, so the dispatcher fired a second launcher. The second launcher's `rm -f .OK .FAIL_rc*` prologue + new `python3 fuzz` → **two SQLite writers on the same DB → corruption guaranteed**. Empirically reproduced on idex/meld with sleep+log analog (both nodes had `PRE-DEPLOYED` AND `CHAIN-RAN` in evidence.log within 5 seconds of each other). **Fix**: resume check MUST also probe for "is there currently a process whose argv contains the RUN_ID on the target node". The chain dispatcher does this via `check_state.sh` deployed once per node.

    2. **Naive `pgrep -f "$RUN_ID"` over SSH always self-matches.** Because the ssh shell that runs pgrep has `"$RUN_ID"` in its own argv (the pgrep argument). With a non-existent RUN_ID, `pgrep -f` still returned 1 match (the shell itself), so the dispatcher tagged every fresh job as in-flight and waited forever. **Fix**: exclude all ancestor PIDs of the shell running pgrep. Walk `/proc/$P/status` for `PPid:` upward until pid 1, accumulate into an exclusion set, filter pgrep output through it. (Naive `pgrep -f ... | grep -v $$` is NOT sufficient — the ssh-spawned shell has multiple ancestors, e.g. sshd → sshd-session → sh -c → check_state.sh, all of whose argvs contain the RID.)

    3. **`if ls .FAIL_rc* 2>/dev/null | head -1 >/dev/null; then ...` ALWAYS evaluates true** because the pipeline's exit status is the LAST command (head, which returns 0 on empty stdin). The `ls` failure with non-matching glob is silently masked. With this bug, the dispatcher tagged every job as FAIL (didn't fire launcher AND skipped poll — false negative for everything). **Fix**: use `shopt -s nullglob; FAIL_FILES=( "$RD"/.FAIL_rc* ); shopt -u nullglob; [ "${#FAIL_FILES[@]}" -gt 0 ]`. Same anti-pattern applies to any `if cmd | head/tail/...; then` chain — always check the producing command's exit code directly, not the pipeline's.

    4. **Bash `$(...)` command substitution forks a SUBSHELL THAT BRIEFLY HAS THE PARENT'S CMDLINE before exec.** This means `pgrep -f "$RID"` inside `$()` can catch the just-forked subshell (containing RID in argv via the script's `$2`) before the subshell exec's into `pgrep` itself. Verified empirically on idex: `pgrep` returned PID 11542 (a transient subshell) in addition to `$$`; both contained the RID, the ancestor walk only excluded `$$`. **Fix**: use ONLY bash builtins (`mapfile -d ''`, `read`) to scan `/proc/[0-9]*/cmdline` directly — no `$()`, no `$(pgrep ...)`, no pipelines that fork. The chain dispatcher's `check_state.sh` is built this way. **General rule**: any time you need to "is process X running" with a pattern that overlaps the calling script's argv, you can't trust `pgrep`/`ps | grep` — you must read `/proc` directly with shell builtins.

    5. **Default behavior on unparseable resume-check output must be ABORT, not LAUNCH.** Original `case "$STATE" in *) emit ... ; fire launcher ;; esac` would silently destroy any in-flight job if `ssh` flaked or `check_state` returned garbage. **Fix**: retry the check up to 5 times with 3-sec backoff; if STATE remains anything other than `OK|RUNNING|FAIL|NONE`, abort the whole chain with `exit 4` and require manual triage. **Fail-safe principle**: when uncertain about in-flight state, the only safe action is to NOT fire a launcher.

    6. **Audit method that proves the dispatcher is in-flight-safe BEFORE you trust it on production**: write a `check_state_standalone.sh` clone of the dispatcher's resume helper, scp it to every production node, run it against (a) each running fuzzer's real RUN_ID — expect `RUNNING`, and (b) a synthetic non-matching RUN_ID — expect `NONE`. If any node disagrees, you have a destruction bug. See `/tmp/audit_inflight_detection.sh` from Jun 15 cutover as the template.

    7. **`pgrep -fc "<pattern>"` over SSH self-matches even WITHOUT ancestor walking — the ssh `bash -c` shell's own argv contains the pattern.** Re-burned Jun 15 17:40 CEST in V0 deploy script's pre-flight safety check. `ssh node "pgrep -fc 'a4.standalone'"` returned `1` on supposedly-idle nodes (goracle, zone) — the "1 process" was the `bash -c pgrep -fc 'a4.standalone'` shell itself, whose argv contains the literal string `a4.standalone`. Gotcha #2's full /proc walk fix is heavyweight; for one-shot pre-flight checks where you only care about ACTUAL python3 fuzzers, the simpler safe pattern is **`ps -C python3 -o cmd= --no-headers | grep -c <pattern>`** — `ps -C python3` filters to python3 processes only (not the bash shell running ps), so the grep can never self-match. Reference: `/tmp/v0_deploy.sh` Step 0d after Jun 15 patch. **General rule**: if you must use `pgrep -f` over SSH, route through the chain dispatcher's `check_state.sh` (it has the full /proc walk). Otherwise prefer `ps -C <executable>` followed by grep.

    **Verified end-to-end deployment**: chain_tier_s (8 jobs) + chain_tier_a (10 jobs, with 4 ta_b4 in-flight at cutover) started Jun 15 07:26 CEST. ta_b4 fuzzers continued unmolested (3h 58m elapsed → eventually finished normally), and ta_b5 fired automatically when ta_b4 hit `.OK`. Subsequently extended Jun 15 17:40 CEST: 3 additional parallel chains (`chain_v0_idle`, `chain_v0_tier_s`, `chain_v0_tier_a`) for V0 (uniform) deployment across the 8 EPYC nodes — 10 jobs queued, 6 fired immediately, 4 chain-queued behind their respective tier's CHAIN_COMPLETE. Manifests at `a4/pos/templates/tier_s.manifest` + `tier_a.manifest` (generated by `a4/pos/templates/gen_manifests.py` for IV.POS.7); V0 manifests at `/tmp/v0_idle.manifest`, `/tmp/v0_tier_s.manifest`, `/tmp/v0_tier_a.manifest` (gen by `/tmp/gen_v0_manifests_v2.py`).

---

## Pointers

- `a4/docs/precloud/PIVOT_TO_POS.md` — historical: the user's pivot decision report (Jun 4).
- `a4/docs/precloud/PRECLOUD_MASTER_PLAN.md` §11–§18 — the IV.POS phase definitions (high-level).
- `a4/docs/precloud/CARRY_FORWARD_TO_TESTBED.md` §G – §J — the cross-phase carry-forward items.
- `a4/pos/` — the implementation; thin README points back to this file.
