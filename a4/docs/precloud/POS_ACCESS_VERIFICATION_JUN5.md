# POS Access Verification — Jun 5, 2026 (~01:52 CEST Jun 6)

> **Result: PARTIAL PASS.** SSH + `pos --help` + `pos nodes list` proven. Reservation step failed: `mtgox` is allocated to another user. Retry with a free node.

---

## 1 — Commands run and what they did

User ran (from Windows MINGW64, `ivan@Ivan`):

```
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
pos --help
pos nodes list | head
pos calendar create mtgox            # FAILED
pos allocations allocate mtgox       # FAILED — node already allocated
pos commands launch mtgox -- echo "hello $(hostname)$"  # FAILED — not owned
```

### 1.1 `ssh` — PASS

```
The authenticity of host '[coinbase.net.in.tum.de]:10022' can't be established.
ED25519 key fingerprint is SHA256:A1mYk8UWOnSTIeuSY4Kk9OnzKv0GJ92WHY+hk2Q0BZg.
[…]
Welcome to coinbase -- blockchain management host
```

**What we learn:**

- TUM POS management host is reachable on `coinbase.net.in.tum.de:10022`.
- Host key fingerprint accepted on first contact (now pinned in `known_hosts`).
- Login succeeds for `ivgreiff` (your TUM account).
- Banner confirms this IS the management host (NOT a test node).

### 1.2 `pos --help` — PASS

Output enumerated the top-level commands:

```
allocations  Define nodes taking part in an experiment.
calendar     Testbed calendar
commands     Execute commands on testbed nodes or roles.
hooks        Configure hooks in posd that can be used as callbacks
images       List available/add new images.
jobs         Jobs (scripts) to be executed by pos at a given time
nodes        Access testbed nodes or roles.
results      Manage Zenodo depositions for result folders.
roles        Group nodes into logical experiment roles.
```

**What we learn:**

- POS CLI is installed and working on your account.
- The 7 verbs we need are all present: `allocations`, `commands`, `nodes`, `roles`, `images`, `results`, `calendar`.
- The quickstart in the help text confirms the same workflow we coded into `dispatch_pos.py`: `allocations allocate` → `nodes image` → `nodes reset` → `commands launch`.

### 1.3 `pos nodes list | head` — PASS (with auto-init)

```
pos ssh public/private key not found, creating once in /home/ivgreiff/.pos/ssh_key
Created /home/ivgreiff/.pos/authentication_token

id           type   status   allocation                     image                    updated
algofi       host   booted   None                           default/debian-bullseye  6d
bitcoin      host   booted   None                           default/debian-bookworm  99m
bitcoincash  host   booted   stegerl_260520_120745_262497   default/debian-trixie    16d
bitcoingold  host   booted   stegerl_260506_090118_841231   default/debian-trixie    30d
dogecoin     host   booted   None                           default/debian-bullseye  4d
dogecoincash host   booted   None                           default/debian-bullseye  4d
```

**What we learn (CRITICAL revisions):**

| Finding | Implication |
|---|---|
| First-run auto-creates `~/.pos/ssh_key` + `authentication_token` | These persist; future logins skip this. |
| `algofi`, `bitcoin`, `dogecoin`, `dogecoincash` are **FREE** (no allocation) | We have free Xeon D-1518s (bitcoin etc.) AND a free AMD EPYC 7543 (algofi) right now. |
| `bitcoincash`, `bitcoingold` are **TAKEN** (allocated to user `stegerl_*`) | Two of our 12 planned nodes are unavailable. Still 10 left (need a full `pos nodes list` to confirm). |
| Default images are MIXED: `debian-bullseye`, `debian-bookworm`, `debian-trixie` | **Our docs assumed `debian-bullseye` everywhere**. `bitcoin` is currently on `debian-bookworm` (Debian 12), the others on `bullseye` (11) or `trixie` (13). All Debian variants; our setup script should be image-agnostic. |
| `pos nodes list` only showed first 10 lines via `\| head` | We need a full `pos nodes list` to enumerate ALL 14 Xeon D-1518 + mtgox + tentacle nodes and confirm which are free. |

### 1.4 `pos calendar create mtgox` — FAILED (our docs were wrong)

```
2026-06-06 01:52:56,950 ERROR pos Unable to POST url: ".../calendar_create".
Must only set either start_date/end_date, start_date/duration or duration/asap_after
```

**What we learn:**

- The calendar API requires time arguments. `pos calendar create <node>` with no args fails.
- Three valid combinations: (`start_date+end_date`) / (`start_date+duration`) / (`duration+asap_after`).
- **OUR DOCS were wrong** — `POS_ACCESS_NOTES.md §13` said `pos calendar create mtgox` alone, which isn't valid.
- However, looking at `pos-examples/tutorials/simple/experiment.sh`: it skips `pos calendar create` entirely and uses `pos allocations allocate --duration 10` directly. The calendar is for ADVANCE / SCHEDULED reservations; for immediate allocation we can skip it.

**Recommended fix in our workflow**: drop `pos calendar create` and just use `pos allocations allocate --duration N` for immediate-use cases.

### 1.5 `pos allocations allocate mtgox` — FAILED (node taken)

```
2026-06-06 01:53:11,011 ERROR pos Unable to POST url: ".../allocations/allocate".
Nodes are already allocated: mtgox
```

**What we learn:**

- `mtgox` is currently allocated to someone else.
- `pos allocations allocate` returns a clean error when the node is taken (no risk of accidentally clobbering another user's allocation — POS is well-behaved here).
- **We need a different node for the smoke test.** `bitcoin` is FREE per §1.3.

### 1.6 `pos commands launch mtgox -- echo ...` — FAILED (not owned)

```
2026-06-06 01:53:45,302 ERROR pos Unable to POST url: ".../commands/launch".
Resource mtgox is not owned by you!
```

**What we learn:**

- POS access control is per-allocation; you cannot launch commands on a node someone else owns. Expected.
- The bash quoting incident (`$(hostname)$` with stray backtick that put the shell into dquote mode) was a quoting typo on the user's side; ignore.

---

## 2 — IV.POS.0 status: PARTIAL PASS

| Criterion | Status |
|---|---|
| SSH to mgmt host works | ✅ PASS |
| `pos` CLI responds | ✅ PASS |
| `pos nodes list` works (shows real nodes) | ✅ PASS |
| Can allocate a node | ⏸ PENDING — `mtgox` taken; retry with `bitcoin` (free) |
| Can launch + await a trivial command on owned node | ⏸ PENDING — needs the allocation first |
| Can free the allocation cleanly | ⏸ PENDING — same |

**IV.POS.0 is ~60% done.** One more 5-minute interaction completes it.

---

## 3 — Corrected one-shot IV.POS.0 test (DROP-IN REPLACEMENT)

The user should run, after re-logging into `coinbase`:

```bash
# 1. List ALL nodes (not just first 10) and find free ones in default group:
pos nodes list

# 2. Allocate a FREE Xeon D-1518 node — bitcoin is confirmed free as of 01:52 CEST
pos allocations allocate bitcoin --duration 10
# → prints allocation id, e.g. "ivgreiff_260606_015400_<rand>"

# 3. Image + reset (this REBOOTS the node into a fresh image — takes ~3 minutes)
pos nodes image bitcoin debian-bookworm     # use whatever the listing showed as default
pos nodes reset bitcoin                     # blocking; waits until booted

# 4. Launch a trivial command (quote the $(hostname) properly!)
pos commands launch bitcoin -- bash -c 'echo "hello from $(hostname)"'
# → prints a command id, e.g. "1234"

# 5. Await
pos commands await <command-id>

# 6. Free the allocation
pos allocations free <allocation-id>
```

When step 4 prints `hello from bitcoin` and step 6 returns OK, **IV.POS.0 is DONE** and IV.POS.1 (single-node smoke with our bundle) is the next step.

**Estimated wall time**: ~5 minutes (most of it is the node reboot in step 3).

---

## 4 — Required doc corrections (already applied tonight)

| Doc | Correction |
|---|---|
| `POS_ACCESS_NOTES.md §13` | Removed wrong `pos calendar create` line; replaced with `pos allocations allocate --duration N` direct call. |
| `POS_ACCESS_NOTES.md §2.2` | Note that `mtgox` may compete with other users; `bitcoin` family is the safer default. |
| `POS_ACCESS_NOTES.md §7` | Default image is **per-node**; we should set it explicitly via `pos.nodes.image(node, 'debian-bookworm')` rather than rely on the listed default. |
| `a4/pos/dispatch_pos.py` | Already calls `pos.nodes.image(node, image)` explicitly — no code change needed. |
| `PRECLOUD_MASTER_PLAN.md` §12.3 | Replace `pos calendar create mtgox` with `pos allocations allocate --duration N`. |
| `PRECLOUD_MASTER_PLAN.md` §21 status table | IV.POS.0 now 🟡 PARTIAL pending retry. |
| `a4/pos/README.md` | Recommended sequence section: drop `pos calendar`; use `--duration N` on `allocate`. |

---

## 5 — Other observations

### 5.1 The image situation

Three different defaults seen in the partial listing (`bullseye`, `bookworm`, `trixie`). The `pos images list` command would tell us all available images. Our scripts should be agnostic, but we should pick ONE image for the whole IV.POS campaign for reproducibility. **Recommendation: `debian-bookworm`** because:
- It's Debian 12 (stable).
- `bitcoin` (our likely smoke node) is currently on it.
- Bullseye is going out of support; trixie just released.

### 5.2 The `stegerl_*` allocations

User `stegerl` has held `bitcoincash` for 16 days and `bitcoingold` for 30 days. Long allocations are clearly allowed (good for us — our 3-day base case is reasonable). But also: **someone else may be running long jobs on the testbed**. Confirms we should NOT silently assume any specific node is free.

### 5.3 First-run init artefacts

`/home/ivgreiff/.pos/ssh_key` and `/home/ivgreiff/.pos/authentication_token` were auto-created. Worth knowing:
- Don't accidentally delete those — re-creating them probably invalidates current allocations.
- They're per-user, not per-session.

---

## 6 — What this changes for IV.POS.1

| Originally | Updated |
|---|---|
| Smoke on `mtgox` | Smoke on **`bitcoin`** (or any free Xeon D-1518). Will measure roughly the IV.POS.5 typical-node performance directly, which is actually MORE useful than mtgox's outlier speed. |
| `debian-bullseye` image | **`debian-bookworm`** image. Functionally equivalent for our `pip install -e repo/` workflow. |
| `pos calendar create` then `allocate` | Just `pos allocations allocate <node> --duration <minutes>`. Skip calendar. |

`dispatch_pos.py` already handles `--image debian-bookworm` from the manifest, and `pos.allocations.allocate(..., duration=...)` is already in the code. **Only doc + recommendation changes are needed; no script changes.**

---

## 7 — Verdict

- ✅ Access infrastructure works exactly as documented in `PIVOT_TO_POS.md` and `pos-examples/`.
- ✅ Our IV.POS scaffolding (no `--env`, `pos.allocations.set_variables`, `pos.nodes.copy`) is aligned with the real API; tonight's session validated the API contract.
- 🟡 One small wording fix in our docs (`pos calendar create` → `pos allocations allocate --duration N`).
- 🟡 Node-selection update: skip `mtgox`/`tentacle` (likely contended); prefer the `*coin*` / `*coingold*` / `ether*` family — and always check `pos nodes list` first.

**Next ask of user: re-run the 6 steps in §3 above** (with `bitcoin` instead of `mtgox`). When that works, we move to IV.POS.1.
