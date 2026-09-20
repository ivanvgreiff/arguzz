# POS Greedy-Dispatch Handoff — operating the IV.POS.9 sweep on a throttled POS

**Audience:** an LLM agent taking over orchestration of the IV.POS.9 Track-B sweep on the TUM **POS** testbed
while the agent↔gateway link is throttled. **Goal of this doc:** everything you need to keep the run alive,
monitor it, recover nodes, and finish — without re-discovering the traps that already cost us hours.

**Status at handoff (2026-06-28 ~08:11Z):** step-domain re-run is **live** on the **greedy dispatcher**
(`greedyq.py`), 9 nodes, state **9 done / 9 running / 18 queued**, ETA ~Jun 29 morning CEST.

> Companion docs (read these for the *why*): `POS_THROTTLED_DISPATCH_HANDOFF.md` (inbound throttle field-manual
> from another track), `rerun_sweep_dueto_mismapping/01–05` (findings → plan → hygiene → runbook → history),
> `a4/docs/precloud/POS_PLAYBOOK.md` (the canonical POS reference — §numbers cited throughout).

---

## 0. TL;DR / quickstart

```text
Gateway:    ssh -p 10022 ivgreiff@coinbase.net.in.tum.de   (alias: coinbase)
Nodes:      reachable ONLY via coinbase, by bare hostname (gard, goracle, idex, meld,
            tinyman, yieldly, algofi, stoi, pact). Login uses SSH-bypass (works regardless
            of POS "allocation" — see §2).
Staging:    everything lives in   coinbase:/tmp/ivg_sweep/
Dispatcher: coinbase:/tmp/ivg_sweep/greedyq.py   (detached python3 -u; logs to greedyq.log)
Monitor:    bash /tmp/ivg_sweep/nodecheck.sh     (per-node job + mutations-in)
            tail -30 /tmp/ivg_sweep/greedyq.log  (done/running/queued heartbeats)
```

**Three rules you must not break:**
1. **Every** coinbase `ssh`/`scp` from the agent sandbox needs **`dangerouslyDisableSandbox: true`** (§3.1).
2. **Never paste multi-line text** (heredocs *or* long base64) into the coinbase shell — it mangles. **scp a
   file, then run a short command** (§3.2).
3. Under heavy throttle, **the human runs coinbase commands** (their direct link is reliable; yours times out).
   You prepare scripts + scp them; they execute (§3.3).

---

## 1. What you're operating (the experiment — brief)

**IV.POS.9 Track-B multi-guest coverage sweep.** Question: does the RISC Zero zkVM **soundness-fuzzing method
generalize across guest programs?** Design = **4 variants × 4 guests × 3 seeds × N=5000 mutations**.

| code variant | thesis display name | what it is |
|---|---|---|
| `V5_control` | A3 Bandit | A4 = **post-execution** witness-cell mutation, cTS bandit, A4 surface |
| `V6_uniform` | Arguzz | Arguzz = **during-execution** fault injection, round-robin (uniform) |
| `V6_cTS` | Arguzz Bandit | Arguzz + cTS bandit |
| `Hybrid_cTS` | A3+Arguzz Bandit | union of A4 + Arguzz surfaces (heaviest variant) |

Guests: `g0_baseline` (sha2-like), `g1_ecall_control`, `g2_mem_stress`, `g3_accelerator` (~2¹⁴ steps).
Metrics: **local** constraint-loc coverage (`coverage` table) + **CGC** = compressed global coverage
(`compressed_global_coverage` table). **Headline claim:** Arguzz wins CGC (global), A4 wins local.

**Why this is the THIRD run (the two bugs the re-runs fix) — critical, do not mix data:**
- **Bug A — 3-kind contamination (F35):** V5/Hybrid ran 3 A4 mutation kinds (`TXN_PREV_WORD_MOD`,
  `TXN_PREV_CYCLE_MOD`, `CYCLE_DIFF_COUNT_MOD`) against a binary lacking their witgen handlers → silent
  `<a4_error>invalid config` skip → **false accepts**. Fixed by rebuilding risc0 at **`53c21894`**
  (cherry-pick `6556e8d7`).
- **Bug B — step-domain / zone mismapping (this re-run):** Arguzz bandit arms computed
  `zone = step_to_zone[executor_step]`, but that table is keyed by witgen `user_cycle`; the two drift by the
  running host-ecall count → **every Arguzz zone label scrambled** (selection + CGC labels). Fixed **rebuild-free
  in Python at `68d90aa`**. A4 (`V5_control`) indexes with `user_cycle` → immune.

**Net scope of THIS run:** re-run `V6_uniform + V6_cTS + Hybrid_cTS` × g0–g3 × seeds 1234/1235/1236 = **36 jobs**.
`V5_control` is **NOT** re-run — it is kept from the 3-kind re-run (A4-only; the step-domain fix is a no-op for
it). Final data assembly: V5 from the 3-kind re-run + the three Arguzz variants from this run.

---

## 2. POS access model (the part people get wrong)

- **Gateway-only:** nodes are not directly routable. You `ssh` to **coinbase**, and from coinbase you `ssh
  <bare-hostname>` (e.g. `ssh gard`). Node `/root` persists across logins; `pos nodes reset` reimages it.
- **Reservation vs allocation — internalize this:**
  - **Reservation** = your *entitlement* to a node for a calendar window (set in the POS UI calendar). **This is
    what matters.** If you hold the reservation, you may use the node.
  - **Allocation** = a transient *control claim* (who currently "owns" the booted instance). Allocation is
    **NOT required to run jobs** — SSH-bypass lets you log in and run regardless of who holds the allocation
    (POS_PLAYBOOK §12.52). Do **not** block on "node X is allocated to someone else."
  - **Allocation matters ONLY for `pos nodes image` / `pos nodes reset`** (re-imaging the OS). So you need it
    *only* when a node booted the wrong OS and must be re-imaged (§4). For everything else, ignore allocation.
  - If a node you hold the reservation for is squat-allocated by someone else and you must re-image it, use the
    **calendar-owner free-right** (POS_PLAYBOOK §12.42): `pos allocations free -k <node>` — **the `-k` is
    MANDATORY** (§12.43; without it, POS trims *your* calendar instead of just freeing the allocation). Then
    `pos allocations allocate <node>`.
  - **Don't free/reset a node that has live jobs** — `free` releases the whole allocation. Only re-image nodes
    with no running work.

---

## 3. The non-negotiable operational gotchas

### 3.1 Sandbox egress (the #1 time-sink)
From the agent sandbox, **every** `ssh`/`scp` to coinbase MUST pass **`dangerouslyDisableSandbox: true`** to the
Bash tool. Without it the sandbox throttles/blocks egress and logins fail **intermittently** with `exit 255` /
"Timeout, server not responding" — which looks **exactly** like a coinbase-side CPU throttle but is not. With it,
logins land fast. **We lost ~an hour treating the sandbox throttle as a coinbase cap.** Sanity check (should
return instantly): `ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'echo ALIVE; uptime'`.

### 3.2 Never paste multi-line text into the coinbase shell
Heredocs get mangled (lines merge/truncate — we once got `--out $RUN/ste` instead of `…/stepfix.chain`, and a
corrupted `tmux` command silently killed a run; the stray `ste` file is still in `/tmp/ivg_sweep/` as evidence).
**And long base64 one-liners mangle too** on terminal paste (`base64: invalid input`). **The robust pattern:**
`scp` the script file to coinbase yourself (small files transfer fine even when throttled), then have a **short**
`bash /tmp/x.sh` command run it. For node-side launches, the dispatcher base64-encodes the *remote_cmd* and pipes
it through `base64 -d` over a single `ssh` arg — that's fine because it's not a human paste.

### 3.3 Who runs commands
When coinbase is **severely** throttled, the **human operator runs the coinbase commands** (their direct
terminal link is reliable; the sandbox link times out mid-command and silently drops launches). Your job becomes:
prepare + `scp` the scripts, hand the human a **short** command to run, and read the logs they paste back. When
the link is healthy you can drive directly (sandbox-disabled). **Detached, log-to-file** is mandatory either way
(see §5) so a dropped connection never kills the orchestrator.

### 3.4 Don't stack heavy processes on coinbase
coinbase is a **shared** login host (user `ivgreiff`). Running two orchestrators + a result-pulling dispatcher at
once saturated the shared CPU and starved logins (self-inflicted "throttle"). Run **one** dispatcher. Before
launching greedy, confirm no `chain_dispatcher.sh` / stray dispatcher is alive (`pgrep -af chain_dispatcher.sh`).

---

## 4. The OS-image requirement (silent killer)

`risc0-host` is built on **debian-trixie** and needs **GLIBC 2.39**. The POS per-node **default image is
debian-bookworm** (GLIBC 2.36) — POS_PLAYBOOK §4.1. A node that boots bookworm **cannot execute the binary**
(`GLIBC_2.39 not found`); cli jobs then die at `capture_baseline_touch` with the misleading message:

> *"Baseline run did not produce a valid `<a4_touch_coverage>` tag"*  (POS_PLAYBOOK §12.30)

**Whenever you reset/re-image a node you MUST set the image FIRST:**
```
pos nodes image <node> debian-trixie     # MUST come BEFORE reset
pos nodes reset <node>                    # boots trixie; wait up to ~14 min for keyed
```
A reset **without** the image line silently boots bookworm and the node fails the run-gate. We hit this exactly
on **pact** (2026-06-28). The fix is re-image to trixie + reset — **never drop the node** for this.

**Lesson:** the hash-gate proves the binary *file* is correct; it does **not** prove it *runs* on that OS. So
admit a node only after **both** a hash-gate **and** a run-gate (the node must actually execute the binary and
emit `<a4_touch_coverage>`).

---

## 5. The greedy dispatcher (`greedyq.py`) — full spec

### 5.1 Why greedy (vs the batch dispatcher)
The original `chain_dispatcher.sh` runs **batches with a barrier**: it splits the 36 jobs into batches of
N (= node count) and **waits for the slowest job in a batch before starting the next batch**. Because job time is
wildly variable by variant (uniform ≈ 4 h, cTS ≈ 6 h, Hybrid ≈ 9 h), the fast nodes **idle for hours** every
batch waiting on the all-Hybrid nodes. On 9 nodes that's ~28–30 h with most nodes idle much of the time.

**`greedyq.py` removes the barrier:** one flat pool of 36 jobs; the instant a node's current job finishes it
grabs the **next queued job** (any job, node-agnostic) and launches it. No idle. Same 36 jobs finish in ~21 h on
9 nodes — **~7–9 h saved**. The job→node assignment in the manifest is ignored; greedy treats the manifest purely
as the **list of `run_id → remote_cmd`** to execute.

### 5.2 How it works (the algorithm)
1. **Logs `GREEDY_START` immediately** (liveness — so you can confirm it's alive even before the first poll).
2. Parses the manifest (`stepfix.chain`) into `CMD[run_id] = remote_cmd` and `ORDER = [run_id, …]`.
3. **Adopts existing state** (so it can take over a running batch with zero rework):
   - `done` = run_ids that already have a result dir under `results_stepfix/*/<rid>`, **plus** any node showing a
     node-side `.OK` marker for that rid.
   - `running[node]` = detected via `pgrep -af a4.standalone` → extract the `pos_iv_pos_9_b_…_n5000` id.
   - `queue` = ORDER minus done minus running.
   - Logs `GREEDY_READY done=… running=… queued=…`.
4. **Greedy loop** (poll every `POLL=240 s` — deliberately slow; a 4-min poll is *lighter* on ssh than the
   batch dispatcher's 60 s, and nothing needs faster reaction):
   - For each node with a running job: check for `.OK` (rc 0 **or 2** = success) or `.FAIL_rc*`. On completion,
     `scp -r` the node's `/tmp/chainjob_<rid>` to `results_stepfix/greedy/<rid>`, mark done, log `DONE`.
   - For each free node with a non-empty queue: `queue.pop(0)`, launch it (base64-wrapped `nohup` over a single
     `ssh -n -f`), log `LAUNCH`.
   - Log a `HEARTBEAT done=x/36 running=y queued=z | <per-node current job>`.
   - Exit + log `GREEDY_COMPLETE` when `done == 36`.

Launch wrapper per job: `mkdir -p /tmp/chainjob_<rid>; cd it; rm -f .OK .FAIL_rc*; ( <remote_cmd> ) > stdout.log
2> stderr.log; rc=$?; [ rc∈{0,2} ] && touch .OK || touch .FAIL_rc$rc`. (**rc 2 = success** — it's the "finding
present" exit code, not an error.)

### 5.3 Launch / restart it
Detached, log-to-file, survives connection drops:
```
cd /tmp/ivg_sweep && setsid nohup python3 -u greedyq.py >/dev/null 2>&1 &
```
It's **idempotent and resume-safe**: on restart it re-adopts `done`/`running` from results + `.OK` + `pgrep`, so
relaunching after a crash never re-runs completed jobs and never double-launches a job already running on a node.
(Confirm it took: `grep GREEDY_READY /tmp/ivg_sweep/greedyq.log | tail -1`.)

### 5.4 Full source (`coinbase:/tmp/ivg_sweep/greedyq.py`)
```python
#!/usr/bin/env python3
"""Greedy per-node work-queue dispatcher (slow poll). No batch barrier: a node grabs the
next queued job the instant its current one finishes. Adopts the running batch state.
Logs GREEDY_START immediately so liveness is confirmable; 4-min poll = very light on ssh."""
import subprocess, time, os, base64, glob, sys
RUN="/tmp/ivg_sweep"; RES=f"{RUN}/results_stepfix/greedy"; MAN=f"{RUN}/stepfix.chain"; LOG=f"{RUN}/greedyq.log"
NODES="gard goracle idex meld tinyman yieldly algofi stoi pact".split()
SSHO=["-o","ConnectTimeout=12","-o","BatchMode=yes","-o","StrictHostKeyChecking=no","-o","LogLevel=ERROR"]
POLL=240  # 4 minutes — light
os.makedirs(RES, exist_ok=True)
def log(m):
    with open(LOG,"a") as f: f.write(f"[{time.strftime('%H:%M:%SZ',time.gmtime())}] {m}\n")
def ssh(n,c,t=20):
    try: return subprocess.run(["ssh",*SSHO,n,c],capture_output=True,text=True,timeout=t).stdout.strip()
    except Exception: return ""
log(f"GREEDY_START v2 poll={POLL}s nodes={len(NODES)}")      # EARLY: confirms alive
CMD={}; ORDER=[]
try:
    for ln in open(MAN):
        if not ln.startswith("sweep_b"): continue
        p=ln.rstrip("\n").split("|",3)
        if len(p)==4: CMD[p[2]]=p[3]; ORDER.append(p[2])
except Exception as e:
    log(f"FATAL parse: {e}"); sys.exit(1)
log(f"manifest jobs={len(ORDER)}")
done=set(); running={n:None for n in NODES}
for rid in ORDER:
    if glob.glob(f"{RUN}/results_stepfix/*/{rid}"): done.add(rid)
log(f"seed done-from-results={len(done)}; probing nodes...")
for n in NODES:
    cur=ssh(n,"pgrep -af a4.standalone 2>/dev/null | grep -oE 'pos_iv_pos_9_b_[a-z0-9_]+_n5000' | head -1")
    if cur in CMD: running[n]=cur
    ok=ssh(n,'for d in /tmp/chainjob_pos_iv_pos_9_b_*/; do [ -f "${d}.OK" ] && basename "$d"; done')
    for b in ok.split():
        rid=b.replace("chainjob_","")
        if rid in CMD: done.add(rid)
    log(f"  probe {n}: running={running[n] or '-'}")
queue=[r for r in ORDER if r not in done and r not in running.values()]
log(f"GREEDY_READY done={len(done)} running={sum(1 for v in running.values() if v)} queued={len(queue)}")
def launch(n,rid):
    rd=f"/tmp/chainjob_{rid}"
    wrap=(f'RD={rd}; mkdir -p "$RD"; cd "$RD"; rm -f .OK .FAIL_rc*; '
          f'( {CMD[rid]} ) >"$RD/stdout.log" 2>"$RD/stderr.log"; rc=$?; '
          f'if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then touch "$RD/.OK"; else touch "$RD/.FAIL_rc$rc"; fi')
    b=base64.b64encode(wrap.encode()).decode()
    ssh(n,f"echo {b} | base64 -d > /tmp/launch_{rid}.sh",t=20)
    try: subprocess.run(["ssh","-n","-f",*SSHO,n,f"nohup bash /tmp/launch_{rid}.sh </dev/null >/dev/null 2>&1 &"],timeout=20)
    except Exception: pass
    log(f"LAUNCH node={n} rid={rid}")
while len(done) < len(ORDER):
    try:
        for n in NODES:
            cur=running[n]
            if cur:
                st=ssh(n,f"test -f /tmp/chainjob_{cur}/.OK && echo OK; ls /tmp/chainjob_{cur}/.FAIL_rc* 2>/dev/null|head -1")
                if "OK" in st or "FAIL_rc" in st:
                    try: subprocess.run(["scp","-r",*SSHO,f"{n}:/tmp/chainjob_{cur}",f"{RES}/{cur}"],timeout=900)
                    except Exception: pass
                    done.add(cur); log(f"DONE node={n} rid={cur} [{len(done)}/{len(ORDER)}]"); running[n]=None; cur=None
            if cur is None and queue:
                running[n]=queue.pop(0); launch(n,running[n])
        log(f"HEARTBEAT done={len(done)}/{len(ORDER)} running={sum(1 for v in running.values() if v)} queued={len(queue)} | "
            + " ".join(f"{n}:{'-' if not running[n] else running[n].split('_b_')[-1][:20]}" for n in NODES))
    except Exception as e:
        log(f"loop-error (continuing): {e}")
    if len(done) >= len(ORDER): break
    time.sleep(POLL)
log("GREEDY_COMPLETE")
```

### 5.5 Known greedy gotchas
- **"Greedy died" is almost always a dropped launch, not a bug.** Earlier deaths were the throttled sandbox ssh
  cutting the `setsid`/launch mid-command. Launch it from a reliable session (or have the human do it), and
  confirm `GREEDY_START` appears in the log immediately after.
- **`FAIL_rc*` does not auto-retry.** A failed job stays failed; greedy moves on. To retry, delete the node-side
  `.FAIL_rc*` + result dir and re-add the rid to the queue (or just relaunch greedy after fixing the node — it
  re-queues anything without a result dir / `.OK`).
- **Leftover jobs from a prior dispatcher** keep running via `nohup` even after you kill that dispatcher (this is
  why algofi/stoi showed `g2_mem_stress` jobs the greedy didn't launch — harmless; they produce valid results,
  but greedy will re-run those rids from its queue → minor duplicate compute, not data corruption).
- **`NODES` is hard-coded** in the script. To add/remove a node, edit the `NODES=` line and relaunch (resume-safe).

---

## 6. Monitoring

### 6.1 The two commands
```
tail -30 /tmp/ivg_sweep/greedyq.log      # done/running/queued + LAUNCH/DONE events
bash    /tmp/ivg_sweep/nodecheck.sh       # per-node: current job / mutations-in / live procs
```

### 6.2 Reading `greedyq.log`
- `GREEDY_START` → alive. `GREEDY_READY done=… running=… queued=…` → adopted state.
- `LAUNCH node=… rid=…` → a job started. `DONE node=… rid=… [k/36]` → a job finished + result pulled.
- `HEARTBEAT done=k/36 running=y queued=z | <node:job …>` → every 4 min; the authoritative progress line.
- `GREEDY_COMPLETE` → all 36 done.

### 6.3 Reading `nodecheck.sh` (and its one quirk)
It prints, per node, `current-job  muts=N  procs=N`. **Quirk:** "current job" is the **most-recently-modified**
`/tmp/chainjob_*/` dir (`ls -dt … | head -1`), so if a leftover job's dir was touched more recently than the
greedy's job, it shows the **leftover**, not the greedy's current job. Cross-check against `greedyq.log`'s
HEARTBEAT for the authoritative current job. `procs` = live `a4.standalone` processes (≈3 per active job; a node
running two jobs shows ~6).

### 6.4 The DB-inflation factor (do not misread progress)
`muts` = `count(*) from mutations` in the node's `run.db`. **For `V6_uniform` this equals the true mutation count
(target N=5000).** **For `V6_cTS` and `Hybrid_cTS` the row count is inflated ~1.5×** (extra bandit/candidate
bookkeeping rows), so divide by ~1.5 to estimate true progress. A job is done at **true** count 5000, i.e. cTS/
Hybrid finish around ~7500 db rows. `muts` *growing* between checks = healthy; *stuck* = investigate that node.

### 6.5 ETA computation (the method)
1. From `nodecheck.sh`, get each running job's true progress = `muts ÷ (1.5 if cTS/Hybrid else 1) ÷ 5000`.
2. Elapsed since the job launched (from `greedyq.log` LAUNCH time) ÷ progress = that job's total time → gives
   measured **per-variant** durations. Current empirical: **uniform ≈ 4 h, cTS ≈ 6 h, Hybrid ≈ 9 h**.
3. Remaining campaign work = Σ(remaining jobs × their variant time). Remaining is evenly split across variants
   (batch boundaries take equal counts of each). Wall-clock ≈ **(total remaining job-hours ÷ node count)** plus
   ~10–15 % for tail imbalance, **floored by the longest single job** (~9–10 h Hybrid). 27 jobs left on 9 nodes
   ⇒ ~19–21 h ⇒ **Jun 29 ~05:00–07:00 CEST**. The 9 Hybrid jobs dominate the tail — watch them.

---

## 7. The job model (manifest, remote_cmd, gates)

### 7.1 Manifest (`stepfix.chain`) line format
Pipe-delimited, 4 fields: `batch | node | run_id | remote_cmd`. The greedy uses only `run_id` + `remote_cmd`
(node-agnostic). Lines start with `sweep_b` (the greedy filters on that prefix). Generated by:
```
PYTHONPATH=$REPO python3 $SWEEP/generate_sweep_manifests.py --stage screening \
  --guests g0_baseline g1_ecall_control g2_mem_stress g3_accelerator \
  --variants V6_uniform V6_cTS Hybrid_cTS --seeds 1234 1235 1236 \
  --nodes "<verified GOOD nodes>" --out /tmp/ivg_sweep/stepfix.chain
```
(`$REPO=/root/a4_campaign/repo` on a node, or the coinbase copy under `a4_campaign/repo`; `$SWEEP=$REPO/a4/runs/
iv_pos_9/sweep`.)

### 7.2 What a `remote_cmd` does (per job, on the node)
1. **G11 fingerprint guard** — asserts the binary is the right one before fuzzing: `planted_bug=none`,
   `risc0_head_sha=53c21894`, `load_rs2_present=1`, correct `guest_image_id`. **Aborts the job if mismatched**
   (this is the last line of defense against running the wrong binary). Zero step-domain guard aborts have been
   observed in this run = the fixed files are in place.
2. Emits a fingerprint record, sets env, runs the fuzzer (`python -m a4.standalone…`) for N=5000, writing
   `run.db` under the job's `/tmp/chainjob_<rid>/` dir.

### 7.3 The hash-gate (correct-files guarantee) — reference sha256 (first 16)
A node is admitted to the run **only if all 8 match** (4 Python files at `68d90aa` + 4 per-guest binaries at
`53c21894`):
```
py : semantic_arm_universe e9e14567351a0030   fuzzer            6e6b12ef43e857ca
     step_domain_map        f9072f03fd17d8d4   v6_uniform_driver b7707c46f758acad
bin: g0 f70f8c6a408274ec  g1 527d71f584ba94dd  g2 58d74710993a59b6  g3 5653b24d555cab35
```
This gate already caught real problems: algofi (missing binaries), pact/stoi (no repo) — excluded until fixed.
The overlay is idempotent; re-applying never hurts. The fix is **rebuild-free** (Python-only) — recovery never
needs a risc0 rebuild.

---

## 8. Node recovery (reset/reimage/deploy)

Use this when a node is unreachable, has no repo, or booted the wrong OS. **Only for nodes with no live jobs.**
```
# (only if squat-allocated by another user and you hold the reservation)
pos allocations free -k <node>            # -k MANDATORY (§12.43)
pos allocations allocate <node>
pos nodes image <node> debian-trixie      # MUST precede reset (§4)
pos nodes reset <node>                     # wait up to ~14 min for keyed
# then deploy:
#  1. if /root/a4_campaign/repo/a4/standalone missing → scp the 287MB bundle + tar -xzf -C /root/
#  2. scp the 40KB overlay + tar -xzf -C /root/a4_campaign/repo/
#  3. hash-verify 4 py + 4 binaries (§7.3); admit ONLY if all 8 match
#  4. run-gate: the node must actually execute the binary + emit <a4_touch_coverage>
```
**Deploy gotchas:** parallelize the node fan-out (`& … wait`); sequential over ~9 nodes is the slow trap. The
287 MB bundle scp **stalls/freezes mid-transfer** to a fresh node — use **`rsync --partial --append`**, which
resumes through stalls (we saw 139→171→222→269→287 MB across resumes). For a **Python-only** fix on a node that
already has the bundle, push only the 40 KB overlay.

---

## 9. Failure modes & recovery

| symptom | cause | fix |
|---|---|---|
| ssh to coinbase `exit 255` / timeout, intermittent | sandbox egress throttle (not coinbase) | `dangerouslyDisableSandbox: true`; or have the human run it |
| greedy stops logging / no heartbeats | process died (usually a dropped launch) | relaunch `setsid nohup python3 -u greedyq.py &` (resume-safe) |
| a node's `muts` stuck, no growth | job hung / node wedged | check `procs`; if 0 and no `.OK`, the job died → clear `.FAIL_rc*` + result dir, relaunch greedy to re-queue |
| job exits `.FAIL_rc1` + stderr `FileNotFoundError …risc0-host` | missing/wrong binary on that node | re-deploy bundle + re-hash-gate that node |
| cli job dies at `capture_baseline_touch` "no `<a4_touch_coverage>`" | node booted bookworm (GLIBC<2.39) | re-image trixie + reset (§4) — do NOT drop the node |
| two dispatchers running, double-launches | forgot to kill the batch dispatcher | `pgrep -af chain_dispatcher.sh` / `tmux ls`; kill the batch one; greedy is sole orchestrator |
| nodecheck shows a job greedy didn't launch | leftover `nohup` job from a prior dispatcher | harmless; ignore (greedy re-runs that rid; minor dup) |

**Fallback if greedy is unworkable:** the batch `chain_dispatcher.sh` is resume-safe (skips node-side `.OK`) and
can be relaunched in a tmux session — but it has the idle problem (§5.1). Greedy is strictly better here; only
fall back if greedy itself can't be kept alive.

---

## 10. File inventory

### On coinbase: `/tmp/ivg_sweep/`
| file | what |
|---|---|
| `greedyq.py` | **the greedy dispatcher** (current; 3761 B) |
| `greedyq.log` | greedy's log (heartbeats, LAUNCH/DONE) |
| `nodecheck.sh` | per-node monitor |
| `stepfix.chain` | **the 36-job manifest** for this run (36609 B) |
| `results_stepfix/greedy/` | greedy-pulled result dirs (this run) |
| `results_stepfix/sweep_b1/` | batch-1 results adopted as "done" |
| `results_rerun/`, `results_miss/` | **the 3-kind re-run** results (V5 source for final data) |
| `results/` | original (Jun 24) run — **pre-both-fixes, quarantine** |
| `sweep_05450d8442b2.tar.gz` | **287 MB bundle** (repo + per-guest binaries) — the deploy artifact |
| `stepfix_overlay.tgz` | **40 KB** step-domain-fix overlay (4 .py at `68d90aa`) |
| `a4_campaign/repo/` | the a4 checkout (generator, dispatchers live under `a4/runs/iv_pos_9/sweep/`) |
| `chain_dispatcher.sh` | the **batch** dispatcher (fallback only), under `a4_campaign/repo/.../sweep/` |
| `greedy_dispatcher.py` | an **older** greedy variant (3474 B) — **use `greedyq.py`, not this** |
| `ste` | a corrupted-paste artifact (evidence of the heredoc-mangle bug); ignore |
| `*.tar.gz` (sweep_37f8…, _69c6…, _bbbb…) | older/abandoned bundles; ignore |

### On each node: `/root/a4_campaign/`
`{repo/, builds/sweep/28e53771_clean__<guest>/risc0-host}`. Jobs run in `/tmp/chainjob_<rid>/` with `run.db`,
`stdout.log`, `stderr.log`, and `.OK` / `.FAIL_rc*` markers. `/root` survives logins; `pos nodes reset` wipes it.

### In the repo (this machine)
- `a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py` — manifest generator (`--guests --variants --seeds
  --nodes --out`).
- `a4/runs/iv_pos_9/sweep/chain_dispatcher.sh` — batch dispatcher (fallback).
- `a4/builds/sweep/28e53771_clean__<guest>/risc0-host` — the per-guest binaries (risc0 `53c21894`).
- `a4/docs/cloud3/rerun_sweep_dueto_mismapping/` — 01 findings · 02 plan · 03 hygiene · 04 runbook · 05 history.
- `a4/docs/cloud3/arguzz_step_domain_fix/` — the step-domain bug analysis (MASTER_PLAN + mapping details).
- `a4/docs/precloud/POS_PLAYBOOK.md` — canonical POS reference (§4.1 image default, §12.30 GLIBC, §12.42/.43
  free-right, §12.52 SSH-bypass).

### Current node roster (9, all hash+run-gated)
`gard, goracle, idex, meld, tinyman, yieldly, algofi, stoi, pact`. (Track A holds the Tier-S nodes
flare/octorand/opulous/polynize; their `pos` zone is Track A's — don't touch.)

---

## 11. What to do at 36/36 (data hygiene — don't plot buggy data)

Per `rerun_sweep_dueto_mismapping/03_DATA_HYGIENE_AND_MAPPING.md`:
1. Pull all `results_stepfix/greedy/<rid>/run.db` locally.
2. **Quarantine** the pre-fix `a4/runs/iv_pos_9/sweep/data/` → `_QUARANTINE_pre_stepdomain_fix/` (it's the Jun 24
   run — pre both fixes).
3. Build `data_clean/` as the **only** notebook read-path, assembled as: **V5_control** from the 3-kind re-run
   (`results_rerun`/`results_miss`) + **V6_uniform / V6_cTS / Hybrid_cTS** from this run (`results_stepfix`).
   Stamp a `PROVENANCE.md` manifest (which db → which variant/guest/seed → which run).
4. Regenerate the per-guest coverage notebook + HTML from `data_clean/` only; add a refuse-to-plot guard if any
   db lacks the provenance stamp.
5. **Re-derive the CGC headline** on the now-unconfounded data; update MASTER_REPORT; re-assess any retracted
   findings (e.g. F2). Map each `variant → DISPLAY name → PNG` exactly (table in 03).

---

## 12. Quick reference card

```text
ALIVE?      ssh coinbase 'echo ALIVE; uptime'                       (dangerouslyDisableSandbox)
GREEDY?     ssh coinbase 'pgrep -af greedyq.py; tail -5 /tmp/ivg_sweep/greedyq.log'
PROGRESS    ssh coinbase 'bash /tmp/ivg_sweep/nodecheck.sh'
RELAUNCH    cd /tmp/ivg_sweep && setsid nohup python3 -u greedyq.py >/dev/null 2>&1 &
NO 2ND DISP pgrep -af chain_dispatcher.sh   (must be empty)
REIMAGE     pos nodes image <n> debian-trixie ; pos nodes reset <n>   (image FIRST)
RECLAIM     pos allocations free -k <n> ; pos allocations allocate <n>   (-k mandatory)
RULES       (1) dangerouslyDisableSandbox on every coinbase call
            (2) scp files, never paste multi-line / long-base64
            (3) under throttle, the human runs coinbase commands; you prep + scp
            (4) one dispatcher only; detached + log-to-file always
```
