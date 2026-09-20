# POS Operations Under the Throttled Environment — Handoff for the Next Agent

**Date:** 2026-06-27. **Author:** the agent that ran the step-domain-fix validation (N=1000) +
the unconfounded re-run (V6_cTS/Hybrid × seeds 1234–1239 × N=5000) on POS.

**Read this if:** you need to dispatch or analyze POS campaigns *from the agent sandbox* while
coinbase is in the current slow/flaky state. It is a field manual, not theory — every pattern
here was forced by a failure I hit this session. The canonical runbook is
`a4/runs/iv_pos_9/race/POS_RUNBOOK.md`; this doc is the throttle-survival overlay on top of it.

---

## 0. TL;DR — the five rules that actually matter

1. **Never run multi-step coinbase work inline.** Launch it as ONE detached job on coinbase
   (`setsid nohup bash /tmp/x.sh > /tmp/x.log 2>&1 < /dev/null &`) and read its log in a later,
   separate ssh. A dropped session (frequent) otherwise SIGHUP-kills your work mid-flight.
2. **Move bytes, not blobs.** Push *scripts* sandbox→coinbase as inline base64 (tens of KB). Never
   scp multi-MB DBs or the 525 MB bundle through the sandbox↔coinbase link (~5–85 KB/s, and it
   congests coinbase's sshd for everyone).
3. **Analyze ON the node, return text.** Run `python3` (sqlite3) on the node that holds the DB and
   print ~2 KB of results. Do NOT download the DB — it's slow *and* WAL-malformed (see §5).
4. **Do heavy compute on the EPYC nodes, never on coinbase.** Fuzzing, proving, even gzip — all on
   the (unthrottled) nodes. coinbase is only a relay for light ssh and tiny scp.
5. **Serialize your coinbase logins, parallelize the node fan-out.** One sandbox→coinbase session
   at a time (parallel logins congest). Inside that session, fan out to nodes with `&`…`wait`.

---

## 1. Topology — how POS is reached from the sandbox

```
[agent sandbox] --ssh-p10022--> [coinbase gateway] --ssh(internal)--> [flare/octorand/...nodes]
```

- **Gateway:** `ssh -p 10022 ivgreiff@coinbase.net.in.tum.de`. From the sandbox you MUST pass
  `dangerouslyDisableSandbox: true` to the Bash tool (the default sandbox blocks egress; GitHub
  push/pull works sandboxed-off, so code travels via `origin/cloud2`, not scp).
- **Nodes** are reached ONLY from coinbase (`ssh <node>` on coinbase resolves them; the sandbox
  cannot reach them directly). Node tiers by speed (use fastest-first):
  - Tier-S (EPYC 9354, ~2 s/mut): `flare octorand opulous polynize`
  - Tier-A (EPYC 7543, ~3.25 s/mut): `gard goracle zone`
  - Tier-B (Xeon 6421N): `pact stoi`  ·  Tier-C (Xeon 6312U, ~7–9 s/mut): `idex meld tinyman yieldly`
- **SSH-bypass:** any already-booted node is reachable via coinbase **regardless of the `pos
  calendar` reservation**. Do NOT `pos allocations allocate/free` (it evicts/reboots). Jobs keep
  running on booted nodes even after your reservation window lapses (extend the reservation only so
  another user's reservation doesn't reclaim/reboot the node).
- Per-node bundle lives at `/root/a4_campaign/` (`bin/risc0-host` = the B2 vulnerable binary;
  `repo/` = the a4 checkout). Deployed once; reused across campaigns.

---

## 2. The throttle — symptoms, likely cause, what NOT to do

**Symptoms this session:** sandbox→coinbase login takes 2–4 min and *intermittently fails*
(`exit 255`, "Timeout, server coinbase not responding") even with a 240 s ConnectTimeout; scp
crawls at ~5 KB/s; gzip and even coinbase→node scp receive are slow. System load/RAM/disk on
coinbase are all fine (`free`, `df` healthy) — so it is **not** memory/disk.

**Most likely cause:** coinbase is a shared account (`ivgreiff`) and appears CPU-capped per-account
(~6–22%). Any busy process on that account (yours or another user's runaway watcher) starves
sshd/scp/gzip. It is self-inflicting: the more concurrent work you pile on coinbase, the worse new
logins get. (The user states there is no intentional quota — treat it as an unexplained but real
effective cap and engineer around it.)

**What NOT to do (all of these I did and regretted):**
- ❌ A retry-loop/monitor that re-SSHes coinbase every N seconds — it perpetuates the congestion and
  never clears. Half-dead SIGKILLed sessions pile up.
- ❌ Bulk transfer (525 MB bundle, or even a 4 MB DB) sandbox↔coinbase — congests sshd; the bundle
  ran ~85 KB/s and a single DB pull ran ~5 KB/s and still timed out.
- ❌ Inline multi-step work over one ssh — the session drops and kills it.
- ❌ Parallel sandbox→coinbase logins — they compete for the cap and all stall.

**ssh options that help:**
`-o ConnectTimeout=200 -o GSSAPIAuthentication=no -o ServerAliveInterval=15 -o ServerAliveCountMax=15`
plus `-o BatchMode=yes -o StrictHostKeyChecking=no` on the coinbase→node hops.

---

## 3. The dispatch pattern that works — node-direct detached chain

This is how the N=5000 re-run was launched and is the template for any campaign here.

**Idea:** a single bash script that runs *detached on coinbase* and, per node, runs that node's
jobs sequentially; nodes run in parallel. ALL heavy work (overlay extract, fuzzing) happens ON the
node. coinbase only fires light ssh launches and `test -f .done` polls.

Skeleton (the real one is `scratchpad/cve_rerun.sh` this session):
```bash
SSH="ssh -o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=no"
HB=/root/a4_campaign/bin/risc0-host
run_node() {            # $1=node ; rest = variant:seed specs (selector == variant name)
  local node=$1; shift
  for spec in "$@"; do
    local v=${spec%%:*} seed=${spec##*:} rid="${v}_seed${seed}_n5000"
    while [ "$($SSH $node 'ps -C python3 -o cmd= --no-headers|grep -c a4.standalone')" != "0" ]; do sleep 30; done   # wait idle
    $SSH $node "tar -xzf /root/fix_overlay_68d90aa.tar.gz -C /root/a4_campaign/repo 2>/dev/null; \
       rm -f /root/rerun_${rid}.done; nohup bash -c 'export A4_COVERAGE_TOUCH=1 ...; \
       cd /root/a4_campaign/repo && python3 -m a4.standalone.cli fuzz --host $HB --db /root/rerun_${rid}.db \
       --seed $seed --num 5000 --selector $v --telemetry-level full -- --ctrl 7 --gseed 12345 --rounds 5 \
       > /root/rerun_${rid}.log 2>&1; echo \$? > /root/rerun_${rid}.rc; touch /root/rerun_${rid}.done' \
       >/dev/null 2>&1 & echo started"
    while [ "$($SSH $node "test -f /root/rerun_${rid}.done && echo y")" != "y" ]; do sleep 60; done   # wait done
  done
}
run_node flare    v6_cTS:1234 v6_cTS:1235 v6_cTS:1236 &
run_node octorand v6_cTS:1237 v6_cTS:1238 v6_cTS:1239 &
run_node opulous  hybrid_cTS:1234 hybrid_cTS:1235 hybrid_cTS:1236 &
run_node polynize hybrid_cTS:1237 hybrid_cTS:1238 hybrid_cTS:1239 &
wait
```
Launch it (the only inline ssh; returns immediately):
```bash
B64=$(base64 -w0 scratchpad/cve_rerun.sh)
ssh ...coinbase "echo '$B64' | base64 -d > /tmp/cve_rerun.sh && \
   setsid nohup bash /tmp/cve_rerun.sh >/dev/null 2>&1 < /dev/null & sleep 2; pgrep -f cve_rerun.sh"
```

**Why per-node sequential + nodes parallel:** 12 jobs on 4 Tier-S nodes = 3 jobs/node, ~3.4 h
(v6_cTS) / ~4.1 h (hybrid, slower — more accepts → more proving) each → ~9.6–12 h wall. Adding the
3 idle Tier-A nodes only shaves ~0.6 h (Tier-A is ~40 % slower) and needs slow deploys, so it
wasn't worth it. **The selector string == the variant name** (`v6_cTS`, `hybrid_cTS`,
`cTS_semantic_v2` for V5; uniform uses `python3 -m a4.standalone.v6_uniform_driver` instead).

**Fix overlay:** `/root/fix_overlay_68d90aa.tar.gz` is a ~48 KB `git archive HEAD -- <changed files>`
already on each node; re-extracting it is idempotent. To ship a new code change: commit → push
`origin/cloud2`, `git archive` the changed paths, base64 it onto each node, `tar -xzf` into
`/root/a4_campaign/repo`. Never re-deploy the whole bundle.

---

## 4. The analysis pattern that works — on-node, never download

The fastest correct way to read results is to run the analyzer **on the node** and return text.

```bash
# coinbase-side wrapper, run detached; pushes a tiny analyzer to each node and runs it there
for n in flare octorand opulous polynize; do
  scp -o ConnectTimeout=30 /tmp/analyze.py "$n":/tmp/analyze.py 2>/dev/null
  ( echo "===[$n]==="; ssh ... "$n" "python3 /tmp/analyze.py /root/<db>" ) &
done; wait
```
`analyze.py` opens the DB read-only (`sqlite3.connect("file:<db>?mode=ro", uri=True)`) and prints
counts. This returns ~2 KB across coinbase instead of moving a 4 MB DB. The schema you'll use most
(`mutations` table): `kind, step, verifier_accepted, proof_generated, proof_verify_failed, outcome`;
arm/zone label is in `bandit_decisions.selected_arm` (5-field `surface|kind|zone|opclass|pre_post`);
reward in `mutation_rewards` (continuous; **0 for the v6/arguzz path by design** — real signal is
`reward_counterfactuals.bandit_success_l1`); decoded instr in `mutation_substrategy`
(`opcode,funct3,funct7,rs1,rs2` — **absent for V6_uniform**). Divide steps: executor **444/449**
(arguzz `step`), user_cycle **436/441** (A4 `step`).

If you truly must download a DB (e.g., for the replay-oracle that needs the file locally),
checkpoint WAL first then pull with a long timeout: on the node
`python3 -c "import sqlite3;c=sqlite3.connect('/root/x.db');c.execute('PRAGMA wal_checkpoint(TRUNCATE)');c.close()"`
then `scp` — budget ~15 min per 4 MB file and run it detached.

---

## 5. Gotchas that cost me hours (so they don't cost you)

- **WAL malformed copies.** The fuzzer writes SQLite in WAL mode. A `.db` copied without its `-wal`
  sidecar (or copied mid-run) opens as `database disk image is malformed`. The
  `/tmp/ivg_race/n1000*` copies were also grabbed *mid-run* (510 KB–1 MB vs the true 2.3–4.5 MB).
  → Always read on-node, or `wal_checkpoint(TRUNCATE)` before copying. Waiting longer does NOT fix a
  malformed snapshot.
- **`rc=2` on completed jobs is benign.** Every finished N=5000 fuzz job exited rc=2 yet the DB has
  `muts=5000/5000` with full accept/telemetry rows. It's a post-loop exit code, not a crash. Verify
  by row counts, not exit status.
- **Nested-quoting hell.** `ssh node "python3 -c \"...f'{x}'...\""` breaks (the f-string quotes
  collide). Always push a `.py` file (base64) and run it, never `python3 -c` with quotes inside.
- **`pgrep`/`ps` for liveness.** Idle check = `ps -C python3 -o cmd= --no-headers | grep -c
  a4.standalone` (0 = free). Progress = on-node `ls -la /root/rerun_*.db` + the `.done`/`.rc` markers.
- **scp hangs at CLOSE under load** (all bytes delivered, process won't exit). If a dispatcher
  stalls there, kill the scp once the destination file == full size ("scp-unhanger").
- **13-node probes:** parallelize them on coinbase (`( ssh … ) & … wait`) → ~15 s instead of ~3 min
  sequential. A sequential loop inside a single outer ssh will blow your ConnectTimeout.

---

## 6. Command templates (copy-paste)

```bash
# (a) parallel idle-check of all reserved nodes (returns in ~login+15s)
ssh ...coinbase 'for n in flare octorand opulous polynize gard goracle zone idex meld tinyman pact stoi yieldly; do
  ( r=$(timeout 14 ssh -o ConnectTimeout=9 -o BatchMode=yes -o StrictHostKeyChecking=no $n \
       "ps -C python3 -o cmd= --no-headers 2>/dev/null|grep -c a4.standalone" 2>/dev/null); \
    echo "$n: a4jobs=${r:-UNREACHABLE}" ) & done; wait'

# (b) launch any multi-step job detached (survives session drop)
B64=$(base64 -w0 local.sh); ssh ...coinbase "echo '$B64'|base64 -d>/tmp/j.sh; \
   setsid nohup bash /tmp/j.sh >/tmp/j.log 2>&1 </dev/null & sleep 2; pgrep -f j.sh"

# (c) read a detached job's log (separate, bounded ssh)
ssh ...coinbase "pgrep -f j.sh>/dev/null && echo RUNNING || echo DONE; cat /tmp/j.log"
```

---

## 7. State of the campaigns this doc came from

- **Validation (N=1000, seed 1234, 4 variants):** done; fix confirmed (V6_cTS `core_div`→exec
  444/449 only). DBs on nodes as `/root/cvefix_*.db`. See
  `arguzz_step_domain_fix/N1000_VALIDATION_RESULTS.md`.
- **Re-run (N=5000, seeds 1234–1239, V6_cTS + Hybrid):** launched 14:34 UTC as detached coinbase
  chain (`cve_rerun.sh`, PID seen as 1259812), 12 jobs on the 4 Tier-S nodes, DBs
  `/root/rerun_<variant>_seed<s>_n5000.db`. ~4/12 done by 19:00 UTC; all 12 ETA ~02:55 UTC Jun 28.
- **Baseline:** original race DBs (incl. valid V6_uniform) are LOCAL at
  `a4/runs/iv_pos_9/race/cve_results/*/run.db` — analyze those with plain local `sqlite3`, no POS.
- **Pending:** recompute the comparison over all 6 seeds + run `a4/runs/iv_pos_9/a1/
  cve_replay_oracle.py` to classify divide-step accepts as confirmed CVE vs benign.
