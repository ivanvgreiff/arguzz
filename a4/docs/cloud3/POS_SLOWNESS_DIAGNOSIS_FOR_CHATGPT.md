# Diagnose / validate: severe slowness on a shared 4-core testbed gateway ("POS"), while another user is unaffected

I collected diagnostics and have a **leading diagnosis**. I want you to **challenge or confirm** it, tell me if
I've mis-ruled-out anything, and give me the best remediation order. The decisive data point is in §4.

---

## 0. RESOLVED (2026-06-28) — per-user 8 GiB memory-cgroup throttle

**Root cause found and confirmed.** coinbase enforces a **per-user `memory.max = 8 GiB`** systemd slice. cgroup v2
charges **page cache + tmpfs** to the slice, so staging ~2.7 GB of tarballs + `rsync` + 10–30 MB DB pulls filled
it. Measured on coinbase:
- `memory.current = 8,107,819,008` (7.55 GiB) vs `memory.max = 8,589,934,592` (8 GiB) → **94% of cap**.
- `memory.events: high = 16,948,425` (16.9M reclaim-throttle events), `max 0`, `oom 0` → relentless throttle, no OOM.
- `cpu.stat throttled_usec = 0` (not CPU), `pids.current = 27` (not process count).
- host `vmstat`: `st 0  wa 0  id 91–98%` → the box itself is idle → it's **only this user's slice** (explains
  "others unaffected" + "started ~2 days ago" when the staged footprint crossed the cap).
- `time /bin/true` ≈ 2 s; `ssh -v` showed multi-second gaps on **purely local** ops (reading
  `/etc/ssh/ssh_config`); ControlMaster multiplexing did NOT help → it's per-PROCESS reclaim, not per-connection.

**Ruled out** (all measured fine): node CPU/RAM, home disk/inode quota, known_hosts/GSSAPI, SSH conn/auth setup,
host CPU/steal/iowait. **Fix:** delete large files charged to the slice (deploy bundles + binary in `/tmp` are
already on the nodes; `harvest/`), stop big `scp`/`rsync` on coinbase, and **read result DBs in place** (sqlite
over ssh returning scalars, never copy 10–30 MB files). The brief below is preserved as the original
investigation.

---

## 1. Topology

- **POS** = bare-metal testbed at TU Munich. I reach it through one shared **gateway/login host** `coinbase`
  (`coinbase.net.in.tum.de`, sshd :10022, user `ivgreiff`), shared by **70 logged-in users**.
- **Compute nodes** (`gard goracle idex meld tinyman yieldly algofi stoi pact`) are reachable **only via
  `coinbase`**, by bare hostname, over an **internal LAN**. I have 9 reserved.
- **Path A** (my automation host → `coinbase`, public internet) has a **known client-side egress throttle on
  my end** — ignore it. **Path B** (`coinbase` ↔ nodes, internal LAN) is where the puzzle is.

## 2. My workload (the load I generate)
- **9 nodes**, each running **3 concurrent CPU-pegged zkVM prover/fuzzer processes** (`a4.standalone`); some
  jobs are memory-heavy.
- On **`coinbase`**: a Python dispatcher polling 9 nodes every 240 s via ssh; **two overlapping `pull_all.py`**
  each `scp`-ing 10–30 MB SQLite DBs from all 9 nodes in series; interactive ssh. → many concurrent ssh/scp
  forks as `ivgreiff`.

## 3. Original symptom
A single `scp` of a 10–30 MB SQLite file over the internal LAN **times out after 300 s** (should be <5 s). One
node intermittently `UNREACHABLE`. Days ago: `disk quota exceeded` in my **home** dir (fixed by freeing 2.2 GB)
and an HTTP 401 on the web UI.

## 4. DIAGNOSTICS COLLECTED (the decisive part)

**`coinbase`:**
```
uptime:   up 104 days, 70 users,  load average: 6.38, 6.01, 5.32      # load ~6 on...
nproc:    4                                                            # ...only 4 CORES → ~1.6x oversubscribed
free -h:  Mem 125Gi total / 94Gi available ; Swap: 0B                  # NO memory pressure, NO swap
du -sh /tmp/ivg_sweep: 2.7G                                            # my staging
cgroup:   cpu.max = "max"        (no CPU limit)
          io.max  = (empty)      (no IO limit)
          memory.max = 8589934592 (8 GB per user slice)
systemctl user-<uid>.slice: CPUQuotaPerSecUSec=infinity, IOWeight=[not set], MemoryMax=8G
quota -s / repquota: command absent (no output)
dmesg / sshd_config: permission denied (inconclusive)

# ps -u ivgreiff (top CPU): a transferring scp's sftp subsystem pegs a core:
  83.9% CPU   ssh ... -s -- stoi sftp        # scp data path, CPU-bound on crypto
  12.4% CPU   ssh ... -s -- tinyman sftp
   ...        scp -p stoi:/tmp/.../run.db /tmp/ivg_sweep/harvest/...   (the 30MB pulls)
```

**Timing probes — THE KEY EVIDENCE:**
```
time scp -p gard:/etc/hostname /tmp/_t1          → 33.3 s   for a 5-BYTE file
time ssh gard 'dd if=/dev/zero bs=1M count=30 |cat>/dev/null' → 11 s  (transfer is node-local; ~10s = ssh setup)
```
A 5-byte transfer taking 33 s rules out disk and bandwidth — it is almost entirely **SSH
connection-setup/handshake time, and it is CPU-bound.** A 30 MB pull then = slow handshake + a trickle transfer
(crypto on contended cores at both ends, the node also running 3 pegged provers) → 300 s timeout.

## 5. My leading diagnosis (please challenge)
**`coinbase` is a 4-core box oversubscribed to load ~6 by 70 users, and SSH handshake + scp/sftp encryption are
CPU-bound. So every ssh/scp pays a ~10–33 s CPU-contended setup tax, and each large scp burns a whole core on
crypto. My own workload — overlapping `pull_all.py` spawning many concurrent multi-MB scp transfers + a 240 s
9-node poller — adds a connection/transfer storm that saturates the few cores, so *my* sessions crawl. A
colleague who isn't generating that storm is unaffected. The node ends are also CPU-saturated (3 provers each),
compounding the handshake/transfer cost.**

This is the intersection of (a) a tiny, heavily shared gateway and (b) self-inflicted connection+transfer load —
**not disk, not quota, not a per-user throttle.**

### What I believe I've RULED OUT (tell me if I'm wrong)
- **Disk full / per-user disk quota as the *speed* cause** — 94 GiB RAM free, no swap, and a *5-byte* scp still
  took 33 s (disk-irrelevant). The earlier `disk quota exceeded` was a *home*-dir issue, already fixed; current
  staging is 2.7 G. (I'll still clean it for hygiene.)
- **Per-user cgroup CPU/IO throttle** — `cpu.max=max`, `CPUQuotaPerSecUSec=infinity`, `IOWeight` unset. Only an
  8 GB per-slice memory cap exists, not hit on `coinbase`.
- **Memory pressure / swapping on `coinbase`** — Swap 0B, 94 GiB available.

### Residual uncertainties I want your view on
1. Could the **8 GB per-slice `memory.max`** be biting on the **compute nodes** (where the zkVM prover RSS may be
   large) → cgroup memory reclaim/thrash that slows node-side sshd/scp? (I haven't measured node `free`/RSS.)
2. Is **sshd `MaxStartups`/`MaxSessions`** (couldn't read sshd_config) plausibly behind the intermittent
   `UNREACHABLE`, given my connection churn?
3. How to cleanly attribute the scp stall to **client(coinbase) handshake CPU** vs **server(node) sshd CPU** vs
   **on-wire** — beyond the 5-byte probe?

## 6. Proposed remediation (please reorder / add)
1. **Kill the duplicate `pull_all.py`** — stop the concurrent-connection storm.
2. **SSH multiplexing** so each node is connected once and reused (kills the per-op 10–33 s handshake tax):
   ```
   Host gard goracle idex meld tinyman yieldly algofi stoi pact
       ControlMaster auto
       ControlPath ~/.ssh/cm-%r@%h:%p
       ControlPersist 600
   ```
3. **Stop transferring DBs; query them in place** — run `sqlite3` over the multiplexed ssh and return only the
   small metric scalars (KB, not 10–30 MB files).
4. If a transfer is unavoidable: `-C` (compress; SQLite compresses well) + a fast cipher
   (`-c aes128-gcm@openssh.com`/`chacha20-poly1305`), and **serialize** (don't parallelize scp on a 4-core host).
5. Reduce poll concurrency; `nice`/`ionice` heavy local work.
6. Hygiene: trim `/tmp/ivg_sweep` (2.7 G). Separately, check whether node prover RSS approaches the 8 GB slice
   cap.

## 7. Questions
1. Does the **5-byte-scp-took-33 s** probe, plus load 6 on 4 cores / 70 users / no swap / no cgroup CPU cap,
   confirm "CPU-bound SSH setup on an oversubscribed shared gateway" as the dominant cause? If not, what else?
2. Is there anything in the data suggesting a **non-self-inflicted** component I should escalate to POS admins
   (e.g. the box is simply undersized for 70 users, or a runaway from another user)?
3. Best **one-command** way to prove whether multiplexing fixes it (expected: 2nd+ connection ~instant)?
4. Anything risky about ControlMaster on a shared host I should know (stale sockets, fanout limits)?

### One-paragraph summary
On a shared 4-core gateway (load ~6, 70 users, no swap, no per-user CPU/IO cgroup cap, only an 8 GB mem cap), a
*5-byte* scp takes 33 s and a 30 MB scp times out at 300 s, while a colleague is unaffected. I read this as
CPU-bound SSH handshake/crypto on an oversubscribed box, amplified by my own concurrent-connection + multi-MB
transfer storm — not disk/quota/throttle. I want you to confirm or break that, flag anything I mis-ruled-out
(esp. node-side 8 GB memory cap and sshd MaxStartups), and give the best remediation order.
