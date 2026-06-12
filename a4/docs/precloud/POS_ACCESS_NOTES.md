# POS Access Notes — IV.POS.0

> **Status (Jun 5, 2026):** Partially filled in by user. Items marked **TBD-DISCOVER** are intentionally deferred — we discover them as we proceed (no quotas expected, paths are conventional). The advisor email (`POS_ADVISOR_MESSAGE.md`) is **NOT needed** for the questions answered here; we have enough to start.
>
> Source of authority: TUM Chair of Network Architectures and Services — Blockchain testbed node table (pasted Jun 5, 2026 PM).

---

## 1 — Testbed identity and access (pivot §13.1)

| Question | Answer |
|---|---|
| **Assigned testbed** | **Blockchain testbed** ✅ |
| Management node hostname | **`coinbase.net.in.tum.de`** ✅ |
| SSH access pattern | `ssh -p 10022 <username>@coinbase.net.in.tum.de` ✅ |
| SSH port | `10022` (per testbed docs) |
| SSH username | _Eddie's TUM username_ |
| POS access already granted? | _user confirms yes (account exists)_ |
| Group membership required for chosen nodes? | **default access group is sufficient** for our chosen nodes (see §2) |

## 2 — Allowed nodes — DETAILED NODE SELECTION

> **Source:** Coinbase blockchain testbed node table (pasted Jun 5 PM).
> **Pivot §15.6**: one campaign per node initially.
> **Pivot §13.2**: prefer compute-oriented nodes (CPU-bound workload, no GPU needed).

### 2.1 Available default-access nodes (no special group required)

These are in the `default` access group, so we can reserve them without algorand/slicestestbed permissions:

| Node | CPU | Cores | RAM | Notes |
|---|---|---|---|---|
| `bitcoin` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" group |
| `bitcoincash` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `bitcoingold` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `dogecoin` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `dogecoincash` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `dogecoingold` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `ether` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `ethercash` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `ethergold` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `litecoin` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `litecoincash` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `litecoingold` | Intel Xeon D-1518 @ 2.20 GHz | 4 | 128 GB | "default" |
| `mtgox` | Intel Xeon E5-1650 v4 @ 3.60 GHz | 6 | 128 GB | "default" — **fastest per-core** |
| `tentacle` | Intel Xeon D-2166NT @ 2.00 GHz | 12 | 128 GB | "default" — most cores in default group |

**Total: 14 default-access nodes.** This is enough for our 15-campaign IV.POS.5 with one wrap (or 15 if we skip one and rerun later).

### 2.2 Node-selection plan per phase

> **Updated Jun 5 PM after first access attempt:** `mtgox` was allocated by another user; `bitcoincash` and `bitcoingold` are similarly held long-term by another user (`stegerl_*`, 16–30 days). `bitcoin`, `algofi`, `dogecoin`, `dogecoincash` confirmed FREE at 01:52 CEST. **Always run `pos nodes list` before locking in node choices.**

| Phase | Recommended node(s) | Rationale |
|---|---|---|
| **IV.POS.1 single-node smoke** | `bitcoin` (Xeon D-1518) — was `mtgox` but mtgox is contended | Use a representative D-1518 directly: we lose ~50% per-node speed but we get smoke + benchmark in one go (the smoke node IS a typical IV.POS.5 node). |
| **IV.POS.2 benchmark** | Same `bitcoin` (Xeon D-1518 @ 2.20 GHz, 4c, 128 GB) | The modal node for IV.POS.5; benchmark applies directly. |
| **IV.POS.3 multi-node smoke** | 3 × free Xeon D-1518 (e.g. `bitcoin`, `dogecoin`, `dogecoincash`) | Homogeneous; one per strategy. Confirm freshness via `pos nodes list` before launch. |
| **IV.POS.4 POS validation campaign (3×3×250)** | 9 × free Xeon D-1518 (run `pos nodes list \| grep 'host.*booted.*None'` to enumerate) | 9 parallel jobs. |
| **IV.POS.5 full A/B (3×5×N)** | 12+ × free Xeon D-1518; batch if necessary (15 jobs / 12 nodes = 2 batches) | Default homogeneous (Xeon D-1518); if 12+ free, single batch; otherwise sequential batches. AVOID mtgox/tentacle for IV.POS.5 to keep CPU homogeneous unless we have a specific reason. |

**Default-group nodes likely to compete with us** (Jun 5 evidence): `mtgox`, `bitcoincash`, `bitcoingold`. Plan around them; don't rely on them.

### 2.3 Expected per-mutation runtime (vs laptop = 21–24 s/mut)

The laptop ran at ~21–24 s/mut on Xeon-class hardware (uniform: 24.2s, zoned: 21.6s, bandit-postfix: 20.6s) on an 8-core machine. Predicted POS performance:

| Node type | Clock | Cores | Predicted s/mut | Confidence |
|---|---|---|---|---|
| Xeon D-1518 @ 2.20 GHz, 4c | 2.20 GHz | 4 | **~25–35 s/mut** (slower than laptop) | Medium — fewer cores + lower clock vs laptop |
| mtgox: Xeon E5-1650 v4 @ 3.60 GHz, 6c | 3.60 GHz | 6 | **~15–20 s/mut** (faster than laptop) | Medium — higher clock |
| tentacle: Xeon D-2166NT @ 2.00 GHz, 12c | 2.00 GHz | 12 | **~22–28 s/mut** (similar) | Low — more cores but lower clock |

**Conclusion: POS testbed gives us ~12× parallelism (12 homogeneous nodes), NOT a per-node speedup.** Bench tells the real story.

## 3 — Reservation policy (pivot §13.3)

| Question | Answer |
|---|---|
| Can I reserve nodes for 3 uninterrupted days? | **Assume YES for now** ✅ (confirmed via your H.8 default + advisor not contradicting) |
| Long CPU-bound jobs OK on chosen nodes? | **YES** ✅ |
| Are reservations extendable / auto-released on expiry? | **TBD-DISCOVER** (we will see what `pos allocations` reports; per pivot §12.4 the upload-on-EXIT trap mitigates) |

## 4 — POS file staging (pivot §13.4)

| Question | Answer |
|---|---|
| Can normal users write to `/srv/testbed/files`? | **TBD-DISCOVER** (likely yes; we'll try `pos.nodes.copy(...)` first which avoids /srv/testbed/files entirely — see §11) |
| Required subdirectory convention | **TBD-DISCOVER** |
| Quota | **No quota expected** (per user reply) |
| Are files visible to all nodes in my allocation? | **TBD-DISCOVER** |

> **Key insight from `pos-examples/actual_experiments/ilab/synthesize_programs/setup.py`**: the testbed has a `pos.nodes.copy(role, src, dst, recursive=True)` API that copies files **directly from the management node to test nodes** — bypassing `/srv/testbed/files` and `pos_download` entirely. This is the path we'll prefer; it avoids needing to know the `/srv/testbed/files` convention up front.

## 5 — POS result storage (pivot §13.5)

| Question | Answer |
|---|---|
| Where do `pos_upload` artifacts go? | `pos.allocations.allocate(...)` **returns a `result_folder`** (per `synthesize_programs/setup.py`); this is where `pos_upload` writes |
| Recommended naming | **per `pos.allocations.allocate(..., result_folder='ourname')`** — caller-controlled |
| Quota | **No quota expected** (per user reply) |
| `pos_upload` supports `-r` recursive + `-f` force | **YES** (per pivot §4.6) |

## 6 — Internet availability (pivot §13.6)

| Question | Answer |
|---|---|
| Outbound internet on test nodes? | **YES** ✅ |
| Outbound internet on management node? | YES (implied) |
| PyPI / GitHub reachable? | YES (per user reply) |

> **§H.10 decision (user)**: "we have outbound internet there so do whats best given we have internet". My choice given the answer: **prefer simple online `pip install`** for the first POS smoke (faster bundle prep, smaller bundle), and **add a `--include-wheels` fallback** so we can switch to offline if any single-node smoke shows pip flakiness or hidden firewall rules. This is reversible.

## 7 — Debian image (pivot §13.7)

| Question | Answer |
|---|---|
| Standard image to boot | **`debian-bookworm`** ✅ (Jun 5 PM correction; the `pos nodes list` shows mixed defaults per node — bullseye, bookworm, trixie. `bitcoin` is currently booted on bookworm. We will explicitly set `debian-bookworm` for ALL IV.POS campaigns for reproducibility.) |
| Python 3 installed | YES (standard Debian; verify on smoke) |
| `python3-venv` available | YES (we `apt-get install -y python3-venv` defensively in setup) |
| `build-essential` available | YES (we `apt-get install -y build-essential` defensively) |
| `git` available | YES (we `apt-get install -y git` defensively) |
| Rust toolchain available? | NO needed — `risc0-host` is prebuilt in the bundle |
| `apt-get install` allowed? | YES (root on test nodes; standard testbed convention) |
| Root access on test node? | YES (standard testbed convention) |

## 8 — Docker / container support (pivot §13.8, NON-BLOCKING)

| Question | Answer |
|---|---|
| Docker installed on test nodes? | **TBD-DISCOVER** (likely no on plain debian-bullseye; doesn't matter — we don't use Docker per pivot §5) |
| Docker allowed? | **TBD-DISCOVER** — non-blocking |

## 9 — POS command details (pivot §13.9) — CONFIRMED FROM `pos-examples/`

This is the part that needed clarification, and `pos-examples/` resolved it definitively.

| Question | Answer (from pos-examples) |
|---|---|
| How to pass per-node parameters? | **`pos allocations set_variables <node> <yml-file>`** (per-node) or `--as-global` (whole allocation) or `--as-loop` (POS-native cross-product). Read on node via `pos_get_variable a/b/c [--from-global \| --from-loop]`. |
| How to run a script | **`pos commands launch --infile <local-script> <node> --queued --name <label>`**. `--queued` = runs after node boot. `--blocking` = wait inline; `--non-blocking` = return command id. |
| How to retrieve stdout/stderr | `pos commands await <id>` — and `pos_upload` from on-node script for arbitrary files. |
| Boot from clean image | **`pos nodes image <node> debian-bullseye`** then **`pos nodes reset <node> --non-blocking`** (NOT `pos nodes start`; `reset` is the reboot-to-image command). |
| Get hostname inside script | `pos_get_variable hostname` (always defined). |
| Python API available? | **YES — `poslib`** module: `pos.allocations.allocate(...)`, `pos.commands.launch(...)`, `pos.nodes.copy(...)`, `pos.nodes.reset(...)`, `pos.commands.await_id(...)`, `pos.roles.add(...)`, `pos.allocations.free(...)`. |

**Critical consequence:** my earlier guess in `a4/pos/dispatch_pos.py` (`--env KEY=VAL`) was wrong. The real flow is:

```python
# Push per-job vars to the allocation under the node
pos.allocations.set_variables(node, <yaml-with-A4_STRATEGY-etc>)
# Push the runner script via --infile and queue it
pos.commands.launch(node, infile='run_campaign_pos.sh', queued=True, name=...)
# Inside the script:
A4_STRATEGY=$(pos_get_variable A4_STRATEGY)
A4_SEED=$(pos_get_variable A4_SEED)
...
```

Equivalent (preferred): use the `poslib` Python API in `dispatch_pos.py` rather than subprocessing the `pos` CLI. Easier error handling.

I am revising both `dispatch_pos.py` and `run_campaign_pos.sh` to match this correct API (separate commit).

## 10 — Existing examples (pivot §13.10) — DONE

| Question | Answer |
|---|---|
| `pos-examples` repo location | **Cloned to `pos-examples/` at the repo root** (user did this Jun 5) |
| `simple-loop` example | `pos-examples/tutorials/simple/` (with `experiment.sh`, per-node `setup.sh` + `measurement.sh`, global/local/loop YAML vars) |
| Python dispatch example | `pos-examples/actual_experiments/ilab/synthesize_programs/setup.py` — full `poslib` workflow (allocate → roles → reset → copy deps → distribute programs → launch script → await → free) |
| Results upload | `pos-examples/tutorials/results/upload_to_zenodo.sh` — confirms `pos results publish upload --result-folder <path>` is the post-experiment endpoint |

---

## 11 — Updated dispatch design (post-pos-examples reading)

The pivot to POS opened up two paths; pos-examples confirms **Path A is the right default**:

### Path A (recommended): direct `pos.nodes.copy` + `pos commands launch --infile`

Pros:
- Bypasses the `/srv/testbed/files` path entirely (one less unknown).
- Bundle is shipped per-allocation rather than staged centrally.
- Matches the real `synthesize_programs/setup.py` pattern.
- The `--infile` mechanism is documented and tested in pos-examples.

Cons:
- Re-uploads the bundle to each node on each campaign (we have 15 nodes; bundle ~100 MB; 1.5 GB total transfer, runs in seconds on testbed LAN).
- Slightly chattier with the management node.

### Path B (fallback): central `/srv/testbed/files` + `pos_download`

Use only if Path A turns out to be unreliable or per-allocation copy is too slow.

**Decision:** implement Path A first. Keep Path B in `dispatch_pos.py` as a `--bundle-strategy=copy|staged` flag (default `copy`).

---

## 12 — Open items NOT blocking IV.POS.1

These are discoverable AS we proceed; not gating:

- Exact `/srv/testbed/files` path convention (we won't need it if Path A works).
- Exact quota on results folder (likely none; we'd hear about it if breached).
- Whether mtgox + tentacle reservation/use is "first come first served" or competitive (we'll find out from `pos calendar list`).

## 13 — Acceptance criteria (per master plan §11.4)

> **Updated Jun 5, 2026 PM after first user attempt** — see `POS_ACCESS_VERIFICATION_JUN5.md` for details. The earlier `pos calendar create` step was wrong (it requires time args we weren't supplying); the simpler `pos allocations allocate --duration N` direct call is what the `pos-examples/tutorials/simple/experiment.sh` actually uses.

- [x] **DONE Jun 5 ~01:52 CEST**: User can `ssh -p 10022 ivgreiff@coinbase.net.in.tum.de`
- [x] **DONE**: `pos --help` runs successfully on the management host
- [x] **DONE**: `pos nodes list | head` lists nodes with allocations + images
- [ ] **PENDING**: Allocate a FREE node + run a trivial command end-to-end:
  ```bash
  # 1. Check what's free (don't assume mtgox — it was taken in our first try)
  pos nodes list

  # 2. Pick a free Xeon D-1518 (e.g. bitcoin)
  pos allocations allocate bitcoin --duration 10
  # → returns an allocation id

  # 3. Set image + boot
  pos nodes image bitcoin debian-bookworm
  pos nodes reset bitcoin                # blocking; ~3 minutes

  # 4. Trivial command
  pos commands launch bitcoin -- bash -c 'echo "hello from $(hostname)"'
  # → returns a command id

  # 5. Wait
  pos commands await <cmd-id>

  # 6. Free
  pos allocations free <alloc-id>
  ```

Once those 6 steps work end-to-end, IV.POS.0 is done and IV.POS.1 starts.

---

## 14 — Quick-reference: chosen first-smoke setup (UPDATED Jun 5 PM)

```text
testbed:        Blockchain
management:     coinbase.net.in.tum.de (SSH port 10022)
your username:  ivgreiff
image:          debian-bookworm                      # was bullseye; corrected after pos nodes list
smoke node:     bitcoin    (Xeon D-1518 @ 2.2 GHz, 4 cores, 128 GB)  # was mtgox; mtgox contended
benchmark node: bitcoin    (same node; smoke == benchmark)
multi-node smoke: bitcoin, dogecoin, dogecoincash    (run pos nodes list to confirm freshness)
validation campaign (3×3×250): 9 × free Xeon D-1518 (enumerate via pos nodes list)
full A/B (3×5×N): 12+ × free Xeon D-1518; 15 jobs / 12 nodes = 2 batches if needed
bundle ship:    `pos.nodes.copy` (Path A; bypasses /srv/testbed/files)
internet:       available → simple online `pip install` first; offline-wheels as fallback
reservation:    `pos allocations allocate <node> --duration <minutes>`   # NO pos calendar create
```
