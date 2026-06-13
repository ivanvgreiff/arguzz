# Phase 7d Inc 4 — Final handoff to Composer (POS work only)

**From:** Opus
**Date:** 2026-06-13 (PM)
**Status going in:** B8 PASS, B12 in1_1 PASS (100% B1 net), B12 in1_100 + B11 pending B1 only
**Status target:** Inc 4 **GREEN** — gate clear for Inc 5 (E5 evidence pack)

This handoff supersedes any earlier "Day 3 next steps" notes. Everything below is **POS-only work**. All WSL-side work is already done by Opus (state shown in §2). **Do all of §3 before reporting back; do not partial-complete.** If anything fails, follow §3.5.

---

## 1. What's already done (Opus, 2026-06-13 PM)

### 1.1 Code (committed to working tree on WSL, untracked / unpushed)

- `a4/pos/dispatch_b1_verify_pos.py` — patched with:
  - HTTP-retry logic in `_await_id_silently` (3 retries, exp backoff on `Unable to GET url`-style transient errors)
  - Node-side result-file fallback check (`_check_node_result_file`) before declaring an await failure
- `a4/pos/run_inc4_b1_verify_pos.sh` — patched with:
  - Per-dispatch error containment (does NOT abort the suite if one dispatch returns nonzero)
  - Post-dispatch audit step (SSHs each node, verifies result JSON, prints summary table)
  - Exit-code semantics: 0 always (so subsequent campaigns run); audit table tells you the actual outcome
- `a4/pos/collect_inc4_b1_results.sh` — NEW collection script that rsyncs all 3 campaigns × 5 variants × B1 result JSONs from POS nodes into `~/arguzz_b1_collect/` on coinbase
- `a4/pos/dispatch_pos.py` `_await_id_silently` — same retry logic (benefits all callers)
- `a4/audits/B1_apply_disposition.py` — NEW post-hoc disposition tool that applies the Inc 3 documented exclusions (`PHASE_7D_INC3D_B1_DISPOSITION.md` categories A/B/C/D) to any B1 result JSON dir

### 1.2 Data (in `a4/audits/audit_output/`)

- `inc4_b12_b1/in1_1/B1_V{1..5}.json` — pulled from POS nodes; B12 in1_1 strict verifier complete
- `B1_inc4_b12_in1_1_disposition.json` — disposition applied: **245/250 raw (98.0%) → 250/250 net (100%) PASS**. All 5 fails categorized A=2, B=1, C=1, D=1 — exactly matching Inc 3 disposition. **0 unclassified, 0 race-fingerprint.**
- `B12_multi_input.json` — updated: `per_input.in1_1_in4_1.B1 = "PASS"`, `verdict = "PASS"`

### 1.3 Docs

- `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` §12 (new) — full audit×race-manifestation mapping for Pro
- `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` G7 — short pointer + new Q5 referencing race §12
- `a4/docs/cloud1/composer/PHASE_7D_INC4_OPUS_REVIEW.md` — adjudicates all NEEDS-OPUS flags
- `a4/docs/precloud/POS_PLAYBOOK.md` — header pointer to canonical templates added

### 1.4 What needs Composer attention but is NOT in this handoff

- Eventually: refresh `EXPECTED_ARMS.md` (`core_div` → `core_shr` drift) for A5 to pass cleanly. **Defer to Inc 5.**

---

## 2. POS state at handoff time

| Resource | Value | Status |
|---|---|---|
| Allocation | `ivgreiff_260613_100352_926884` | **Active**, ~7h remaining |
| Calendar entry 1747 (primary) | 6 nodes flare+meld+algofi+opulous+octorand+? | Active until ~13:53 UTC tomorrow |
| Calendar entry 1748 (backup) | (overflow coverage) | Active until 19:53 UTC (today) |
| Bundle on coinbase | `~/a4_campaign_1afc0bd74d8b.tar.gz` (134 MB) | Already extracted to all 5 nodes |
| B12 in1_1 B1 results on nodes | `/root/b1_verify_results/pos_inc4_b12_b1_in1_1_V{1..5}/B1_V{1..5}.json` | Present — already pulled to WSL by Opus |
| B12 in1_100 B1 results | — | **NOT YET RUN** (orchestrator died on rc=255 false-failure before reaching this step) |
| B11 B1 results | — | **NOT YET RUN** (same cause) |

---

## 3. Composer's tasks (in order — execute all, then report back)

### 3.1 Push the patched scripts to coinbase

```bash
# From WSL:
cd /root/arguzz
rsync -av \
    a4/pos/dispatch_b1_verify_pos.py \
    a4/pos/run_inc4_b1_verify_pos.sh \
    a4/pos/collect_inc4_b1_results.sh \
    a4/pos/dispatch_pos.py \
    a4/audits/B1_apply_disposition.py \
    -e 'ssh -p 10022' \
    ivgreiff@coinbase.net.in.tum.de:~/arguzz/

# verify on coinbase
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de \
    'cd ~/arguzz && head -5 a4/pos/run_inc4_b1_verify_pos.sh && head -5 a4/audits/B1_apply_disposition.py'
```

Expected: both files show the recent headers (set -uo pipefail, NEW disposition header). If the rsync fails or stale files appear, **STOP and investigate** before proceeding.

### 3.2 Re-launch the two missing B1 verify campaigns on coinbase

```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
cd ~/arguzz
source /srv/testbed/pos/cli/venv3/bin/activate

# Pass our existing allocation so we don't re-allocate or consume calendar quota
export INC4_ALLOC_ID="ivgreiff_260613_100352_926884"

# Launch BOTH remaining campaigns in one go. The patched orchestrator will
# now continue past any single-campaign rc=255 issues, and at the end will
# SSH each node to verify result JSONs landed.
nohup bash a4/pos/run_inc4_b1_verify_pos.sh b12_100 "$INC4_ALLOC_ID" \
    > /tmp/inc4_b1_verify_b12_100.log 2>&1 &
echo "B12 in1_100 PID=$!"

# Wait for B12 in1_100 to finish (sequential on the SAME allocation — they share nodes)
wait

nohup bash a4/pos/run_inc4_b1_verify_pos.sh b11 "$INC4_ALLOC_ID" \
    > /tmp/inc4_b1_verify_b11.log 2>&1 &
echo "B11 PID=$!"
wait

echo "BOTH DONE"
tail -40 /tmp/inc4_b1_verify_b12_100.log /tmp/inc4_b1_verify_b11.log
```

**Estimated wall time:**
- B12 in1_100 verify (5 vars × 50 muts each on 5 nodes in parallel): ~15-25 min
- B11 verify (5 vars × 500 muts each on 5 nodes in parallel): ~60-90 min
- **Total: ~75-115 min** if nothing else goes wrong

**If a node hits hardware flakiness (cf. polynize anti-pattern §12.45):**
- The orchestrator now logs the failure and continues; check the post-dispatch audit table at the bottom of each log
- If a single variant didn't land, manually re-launch JUST that variant (see §3.5)
- Do NOT free the allocation until §3.4

### 3.3 Collect, apply disposition, and update audits — all 3 campaigns

```bash
# Still on coinbase:
bash a4/pos/collect_inc4_b1_results.sh
ls -la ~/arguzz_b1_collect/*/

# rsync to WSL
exit  # back to WSL terminal
cd /root/arguzz
rsync -av -e 'ssh -p 10022' \
    ivgreiff@coinbase.net.in.tum.de:~/arguzz_b1_collect/ \
    a4/audits/audit_output/inc4_b1/

# Apply disposition + verdict for each campaign
for tag in pos_inc4_b12_b1_in1_1 pos_inc4_b12_b1_in100 pos_inc4_b11_b1; do
    python3 -m a4.audits.B1_apply_disposition \
        --in-dir a4/audits/audit_output/inc4_b1/$tag \
        --output a4/audits/audit_output/B1_${tag}_disposition.json \
        --label $tag
done
```

Expected output: 3 lines, one per campaign, each reading approximately:
```
[B1 disposition] <tag>: raw X/Y (Z%) -> net Y/Y (100.0%) [PASS]
```

If ANY campaign reports `[REVIEW]` (i.e. unclassified failures other than A/B/C/D), STOP and look at the "needs_review" array in that disposition JSON. Possibilities:
- New failure class we haven't seen before → flag for Opus
- New D42 nondet address → propose adding to allowlist
- Race-class failure (`inst_p2.zir:291` in detail) → unexpected, flag for Opus

### 3.4 Update B12 and B11 audit JSONs with the B1 results

Update `a4/audits/audit_output/B12_multi_input.json`:
- `per_input.in1_100_in4_100.B1` ← "PASS" (from disposition output)
- `per_input.in1_100_in4_100.B1_detail` ← `{raw_pass_rate, net_pass_rate, ...}` from disposition
- `per_input.in1_100_in4_100.verdict` ← "PASS" iff B1=PASS && B4=PASS && B9=PASS (A5 doc-drift waived)
- top-level `verdict` ← "PASS" iff both per_input verdicts PASS

Update `a4/audits/audit_output/B11_scale_stress.json`:
- For each V<n>, add `b1_rerun = {verdict, raw_pass_rate, net_pass_rate}` from disposition
- For each V<n>, set `pass = true` iff B4=PASS AND B9=PASS AND B1=PASS (prefix-drift is documented as EXPECTED via RACE_FINDING §12, not a fail condition)
- Top-level: add `verdict = "PASS"`

Use the same pattern as the existing B12 update I did (in `a4/audits/audit_output/B1_inc4_b12_in1_1_disposition.json` → folded into `B12_multi_input.json`). Reference my §1.2 above for the schema.

### 3.5 If something STILL fails after the patches

If the post-dispatch audit table at the bottom of a `run_inc4_b1_verify_pos.sh` log shows `→ X/5 variants found` with X<5, here's the manual recovery for the missing variant(s):

```bash
# On coinbase. Identify the missing variant (e.g. V3 for B11):
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de
cd ~/arguzz
source /srv/testbed/pos/cli/venv3/bin/activate

# Manually re-launch ONE variant (replace <variant>, <node>, <campaign>):
python -m a4.pos.dispatch_b1_verify_pos \
    --manifest a4/pos/manifests/pos_inc4_b11_b1.json \
    --bundle ~/a4_campaign_1afc0bd74d8b.tar.gz \
    --nodes opulous \  # the failed node
    --image debian-trixie \
    --allocation-id "$INC4_ALLOC_ID" \
    --await --await-timeout 7200 \
    --out dispatch_recovery.json

# Or if a node is genuinely flaky, substitute another from our allocation
# (anti-pattern §12.45). Currently allocation has: flare, meld, algofi,
# opulous (+ whatever's in calendar 1747's "?" slot).
```

### 3.6 Free POS resources and report back

```bash
# After ALL 3 campaigns have results in WSL AND audit JSONs updated:
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de

# CRITICAL: -k flag is essential to preserve calendar (anti-pattern §12.43)
pos allocations free -k ivgreiff_260613_100352_926884

# Free calendar entries (or let them expire)
pos calendar list | grep ivgreiff   # find entry IDs
# If 1747 / 1748 are still in the list and you want to free them early:
pos calendar delete --id 1747 <one-of-the-nodes>
pos calendar delete --id 1748 <one-of-the-nodes>
```

Update `a4/docs/cloud1/composer/PHASE_7D_INC4_REPORT.md`:
- Change overall gate from NEEDS-OPUS to **GREEN**
- B8: PASS (with note about 89s timestamp gate adjudication per Opus review §1)
- B11: PASS-WITH-CAVEAT (prefix drift documented as expected race-propagation; reference RACE_FINDING §12.1 row "B11 prefix-strict match (V2/V3/V4/V5)")
- B12: PASS (B1 in1_1 250/250 net, B1 in1_100 ___/250 net; A5 doc-drift waived to Inc 5)
- Add an "Inc 4 closeout" section pointing to:
  - `a4/audits/audit_output/B11_scale_stress.json` (updated)
  - `a4/audits/audit_output/B12_multi_input.json` (updated)
  - `a4/audits/audit_output/B8_concurrent_isolation.json` (unchanged)
  - `a4/audits/audit_output/B1_*_disposition.json` (3 files)
  - `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` §12 (race-manifestation map)
  - `a4/docs/cloud1/composer/PHASE_7D_INC4_OPUS_REVIEW.md` (Opus adjudication)

Then commit (single commit, since user approves it):
- All updated audit JSONs
- All patched scripts
- All updated docs
- New scripts: `B1_apply_disposition.py`, `collect_inc4_b1_results.sh`
- The 5 B12 in1_1 B1 result JSONs I pulled today
- (Inc 5 backlog items remain untouched)

Reply with:
1. Disposition results for all 3 campaigns (one line each, e.g. "B12 in1_100: raw 247/250 → net 250/250 PASS")
2. Updated B11 / B12 verdicts
3. Final report path
4. POS resource cleanup confirmation
5. Any unclassified failures or anomalies

---

## 4. Acceptance criteria for Inc 4 GREEN

- [x] B8 core isolation: 5/5 zero diffs (DONE)
- [x] B8 timestamp gate: 89s adjudicated PASS (Opus, see review)
- [x] B11 N=500 B4: 5/5 PASS (DONE)
- [x] B11 N=500 B9: 5/5 PASS (DONE)
- [x] B11 prefix divergence: documented as expected race-propagation, NOT a regression (RACE_FINDING §12)
- [ ] **B11 B1 strict: 5/5 net PASS after disposition** ← Composer §3.2-3.4
- [x] B12 A3: 48-arm universe stable across inputs (DONE)
- [x] B12 B4/B9: PASS both inputs (DONE)
- [x] B12 in1_1 B1: 250/250 net PASS after disposition (DONE — Opus)
- [ ] **B12 in1_100 B1: 250/250 net PASS after disposition** ← Composer §3.2-3.4
- [x] B12 A5: doc-drift waived to Inc 5
- [ ] **Final report updated, POS resources freed, commit landed** ← Composer §3.6

---

## 5. Why this handoff exists (lesson learned)

The Composer-launched B1 verify on B12 in1_1 actually completed successfully on all 5 nodes — but the POS coordinator had transient HTTP timeouts on 3 nodes during the `await_id` call, returning rc=255 to the orchestrator. The orchestrator's `set -e` then killed the script before B12 in1_100 + B11 ran, AND no one noticed because the per-node result files were sitting silently on each node.

Fixes (§1.1):
1. `dispatch_b1_verify_pos.py` retries transient HTTP errors before declaring failure
2. `dispatch_b1_verify_pos.py` falls back to node-side result-file check if retries exhaust
3. `run_inc4_b1_verify_pos.sh` doesn't abort the suite on a single dispatch failure
4. `run_inc4_b1_verify_pos.sh` audits result-file presence on every node at the end
5. New `collect_inc4_b1_results.sh` can recover results even if the orchestrator never saw them

**Going forward**: every orchestrator that drives POS dispatches should have (1) HTTP retry, (2) result-file fallback, (3) per-step error containment, (4) post-run audit. If you write a new orchestrator, copy the pattern from `run_inc4_b1_verify_pos.sh`.
