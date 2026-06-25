# A3 race — POS dispatch RUNBOOK (SSH-bypass, tmux)

**Single source of truth for dispatching a bug-race campaign on POS.** Captures the exact,
*verified* procedure + every gotcha hit during the A3 Seam-B smoke (2026-06-24) and its fix, so
the real `rs1==rs2` race runs with **zero surprises**. Method = **SSH-bypass + `chain_dispatcher.sh`
in tmux** (POS_PLAYBOOK §12.52/§12.53). **Never `pos allocations allocate`** — it evicts/resets the
node (§12.39); raw SSH to a booted node needs no allocation.

> **Status: SMOKE GREEN (2026-06-24).** Full pipeline verified end-to-end on the 8-node fast pool:
> deploy ✅, fingerprint guard ✅ (8/8 verifyopcode), chain ✅, **12/12 jobs `.OK` + `run.db` pulled**,
> mutations recorded ✅. Steady-state **~2.0–3.3 s/mut** (octorand 2.2, flare 3.0, zone 3.3) ⇒ a thesis
> **N=5000 job ≈ 4.6 h worst case → fits a 6 h reservation block.** Complementarity already visible at
> N=120 (§9). The one bug that nearly cost the race — the guard `ModuleNotFoundError` death — is
> **fixed + regression-locked** (gotcha #7); read it before re-running.

---

## 0. Roles / isolation (two OCPs share POS)
- **Track A (this work):** the bug race. Namespace EVERYTHING under `race`/`ivg_race`.
- **Track B (other OCP):** the multi-guest sweep — runs concurrently (`tmux sweepb3`, `/tmp/ivg_sweep/`, its own nodes). **NEVER** touch its tmux session, `/tmp/ivg_sweep`, or its nodes; never `pos allocations free/allocate` anything (could evict it).
- Track A uses: `/tmp/ivg_race/` (bundle+repo), tmux `chain_race_smoke`/`chain_race_thesis`, results `/srv/testbed/results/ivgreiff/a4/a3seamb_race_*`, the 8 fast nodes the user assigns.

## 1. Prerequisites (Ivan / one-time)
1. **Nodes reserved + booted on `debian-trixie`** (GLIBC 2.39 — risc0-host will NOT load on bookworm, §12.30). Fast pool: `flare octorand opulous polynize` (Tier-S EPYC 9354) + `algofi gard goracle zone` (Tier-A EPYC 7543), ~2.5–3 s/mut.
2. SSH from coinbase to each node works (`ssh <node> hostname` → root). SSH-bypass cannot boot/image — that needs a real allocation by the reservation owner.
3. Confirm nodes are **idle** (not Track-B's): `ps -C python3 -o cmd= --no-headers | grep -c a4.standalone` → 0.

## 2. Build + stage the bundle (local box)
```bash
# clean Track-A bundle: git-archive HEAD + the HOLED binary, NO dirty overlay
# (prepare_bundle.sh --allow-dirty sweeps in a4/builds/*/risc0-host -> 922M; this is ~533M)
bash a4/pos/race/prepare_race_bundle.sh        # -> bundles/a4_campaign_race_<sha>.tar.gz
# GOTCHA: build it AFTER committing dispatch_race.sh, or the git-archive omits it (it runs on
# coinbase, so a missing one means you must scp it separately — see step 3).
git push origin cloud2                          # coinbase pulls code via the bundle, not git (see 3)
```
**Stage to coinbase `/tmp` — NOT `~/`** (home is over per-user quota: `Disk quota exceeded`; `/tmp`=tmpfs 59G free, `/srv/testbed/results`=1.2T free):
```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'mkdir -p /tmp/ivg_race'
scp -P 10022 bundles/a4_campaign_race_<sha>.tar.gz ivgreiff@coinbase.net.in.tum.de:/tmp/ivg_race/
```

## 3. Track-A repo on coinbase (from the bundle — NOT git)
**GOTCHA: coinbase cannot `git fetch`** (origin is HTTPS; no GitHub creds in the non-interactive
session → `could not read Username for 'https://github.com'`). Do NOT change the shared repo's
remote (Track-B uses it). The bundle already contains the full committed repo, so extract THAT:
```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de '
  rm -rf /tmp/ivg_race/repo && mkdir -p /tmp/ivg_race/repo
  tar -xzf /tmp/ivg_race/a4_campaign_race_<sha>.tar.gz -C /tmp/ivg_race/repo --strip-components=2 a4_campaign/repo'
# if dispatch_race.sh wasnt committed at bundle-build time, scp it in:
scp -P 10022 a4/pos/race/dispatch_race.sh ivgreiff@coinbase.net.in.tum.de:/tmp/ivg_race/repo/a4/pos/race/
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'chmod +x /tmp/ivg_race/repo/a4/pos/race/dispatch_race.sh'
```
Verify on coinbase: `grep -c verifyopcode .../a4/pos/fingerprint_guard.py` ≥1; `dispatch_race.sh`,
`generate_race_manifests.py`, `chain_dispatcher.sh` all present.

## 4. LAUNCH (one command — deploy + guard + chain in tmux)
```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de '
  source /srv/testbed/pos/cli/venv3/bin/activate 2>/dev/null || true
  cd /tmp/ivg_race/repo
  REPO=/tmp/ivg_race/repo \
  BUNDLE=/tmp/ivg_race/a4_campaign_race_<sha>.tar.gz \
  RESULTS_BASE=/srv/testbed/results/ivgreiff/a4/a3seamb_race_smoke \
  STAGE=smoke N=2000 \
    bash a4/pos/race/dispatch_race.sh flare octorand opulous polynize algofi gard goracle zone'
```
`dispatch_race.sh` does, per node: scp+extract bundle → `fingerprint_guard --profile verifyopcode`
(ABORT rc 87 if not the holed binary) → generate the manifest with the real nodes → `tmux new -d
-s chain_race_smoke` running `chain_dispatcher.sh` (which scp's a launcher + `nohup`s the remote_cmd,
polls `.OK`/`.FAIL`, scp's `run.db` back). **RESULTS_BASE must be `/srv` or `/tmp`, NOT `~/`** (quota).

**LOAD-BEARING (gotcha #7):** each manifest `remote_cmd` MUST begin `cd /root/a4_campaign/repo && …`
BEFORE the guard, because `chain_dispatcher.sh`'s launcher `cd`s into the *run-dir* first — without
the repo-`cd`, `python -m a4.pos.fingerprint_guard` dies with `ModuleNotFoundError: No module named
'a4'` and its inline `|| exit 87` silently kills the launcher (no marker, no stderr). The fixed
`generate_race_manifests.py:remote_cmd` emits this; `test_manifest_generator` asserts it. If you
edit the generator, keep the repo-`cd` first.

## 5. Monitor (it's in tmux — survives disconnect)
```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'tail -F /tmp/chain_race_smoke.log'   # batch/launch/OK/FAIL
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'tmux ls'                              # chain_race_smoke alive?
# per-node fuzzer + progress:
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'ssh <node> "ps -C python3 -o cmd= --no-headers | grep -c a4.standalone"'
```
**COLD START vs DEATH — how to tell them apart (this is the crux):**
- **Cold start (NORMAL):** after LAUNCH each job runs the guard (cold-loads the 100 MB binary) → `cli
  fuzz` inspection (another full host run) → the **first mutation pays a one-time ~89 s prover-key
  setup** (visible as a single `elapsed_ms ≈ 89000` spike, e.g. gard's first mut in the smoke). So the
  first `mutations` row can take **several minutes**. During this window `proc≥1` (a `python`/`risc0-host`
  IS running) but `run.db` has 0 rows. That is fine.
- **Death (the bug we hit):** `proc=0` on a node with **no `.OK`/`.FAIL` marker and no `meta.json`** =
  the launcher itself exited early. The tell: `stdout.log` frozen at the `CMD:` line, **no `stderr.log`
  file at all**. (A 0-byte `run.db` is a RED HERRING — `sqlite3.connect` in your *probe* scripts creates
  it; always open the DB read-only: `connect("file:…?mode=ro", uri=True)`.) Root cause + fix = gotcha #7.
- **Liveness check that doesn't lie:** `ps -eo args | grep -c "[a]4.standalone"` (proc), `stat -c%s
  run.db` + a **read-only** mutation count, and `tail .../stdout.log`. proc≥1 → alive (maybe cold);
  proc=0 + no marker → dead → read gotcha #7.

## 6. Collect + analyze (after the chain completes — `CHAIN_COMPLETE` in the log)
```bash
# DBs are scp'd by chain_dispatcher to RESULTS_BASE on coinbase. Pull to the local box:
rsync -av -e 'ssh -p 10022' ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4/a3seamb_race_smoke/ ./a4/runs/iv_pos_9/race/smoke_results/
# per (variant,seed) DB -> oracle (control-confirm @ VerifyOpcode) -> markers:
python3 a4/runs/iv_pos_9/race/oracle.py <db> --control a4/builds/ap_seamb/control/risc0-host \
        --head-sha 93bda33b4f95f29acc9ddce1e225cdf949c83874 --out <db>.oracle.json
# then markers.py over all runs -> race_markers.json (+ measure real per-mut time + cTS ITM-rate -> S2 N)
```
**Oracle PERF (matters at thesis scale):** the oracle control-confirms EVERY accept by *re-running the
control binary* on the identical mutation. On the **dev box that is ~30 s/accept** (so a V5_control DB
with ~40 accepts ≈ 20 min; all 40+ thesis DBs would be hours). For the thesis run, **run the oracle on a
fast POS node** (deploy the control binary there once — it proves at ~3 s) or use `--no-confirm` for a
fast structural pass first (trusts F8 construction; finds = INSTR_TYPE_MOD accepts) and reserve the full
control-confirm for the candidate finds only. A read-only per-variant `accepts-by-kind` query (§9) gives
the complementarity signal *immediately*, with no control re-runs at all.

## 7. The REAL race (rs1==rs2 CVE) — what changes vs this smoke  **[WIRED 2026-06-25]**
- **Binary:** the A1 vulnerable build `B2` (`a4/builds/a1_cve/risc0-host`, head `98387806`,
  fingerprint `load_rs2_present=0, planted_bug=none`, sha256 `dbe89d23…`). Guard `--profile race`.
  Built from `workspace/risc0-a1-vuln` (98387806 vulnerable codegen byte-identical; A4 hooks
  forward-ported onto the monolithic `prove`/`WitnessGenerator::new`; fix #3181 reverted in
  `execute/rv32im.rs`+`r0vm.rs`+`witgen/preflight.rs`). **Locally verified before dispatch:** honest
  prove → `output=9000027, Verifier success`; guard race PASS.
- **Guest:** the A2 `rs1==rs2` guest (`workspace/output-a1vuln/methods/guest`: `remu a0,a1`+`divu a2,a3`,
  source regs 1-bit-apart so a single `INSTR_WORD_MOD` flip aliases rs2→rs1). guest_image_id
  `2819774008,269738887,492358372,594138501,3395406058,845810525,2646011585,829874012`.
- **Oracle:** strong journal oracle (accept + wrong committed output) PRIMARY; the find = an
  `INSTR_WORD_MOD` accept whose mutated op is a same-register `remu`/`divu` (rs2==rs1) with
  output ≠ 9000027. Arguzz/Hybrid expected to find (during-exec recompute = coherent); V5/A4 not
  (post-exec edit leaves result incoherent ⇒ C_local fires). Everything else IDENTICAL — reuse §2–§6.
- **The generator + wrapper are now CVE-parameterized** (defaults stay Seam-B). Launch (on coinbase):
  ```bash
  REPO=/tmp/ivg_race/repo BUNDLE=/tmp/ivg_race/a4_campaign_cve_<sha>.tar.gz \
  RESULTS_BASE=/srv/testbed/results/ivgreiff/a4/cve_race_thesis \
  GUARD_PROFILE=race HEAD_SHA=98387806fe8348d87e32974468c6f35853356ad5 RUN_PREFIX=cve \
  GUEST_ID=2819774008,269738887,492358372,594138501,3395406058,845810525,2646011585,829874012 \
  STAGE=thesis N=5000 \
    bash a4/pos/race/dispatch_race.sh flare octorand opulous polynize algofi gard goracle zone
  ```

## 8. Gotchas log (each cost time the first time — DO NOT repeat)
| # | symptom | cause | fix |
|---|---|---|---|
| 1 | `scp ... ~/` silently fails; `Disk quota exceeded` | per-user home quota (home FS itself had 72G free) | stage bundle in `/tmp/ivg_race`; results in `/srv/testbed/results` |
| 2 | coinbase `git fetch` → `could not read Username for https://github.com` | origin is HTTPS, no creds in non-interactive SSH | use the **bundle's** repo as the Track-A checkout (no git); never change the shared remote |
| 3 | `dispatch_race.sh MISSING` in the extracted repo | bundle built (git-archive HEAD) BEFORE the script was committed | scp the script in, or rebuild the bundle at a HEAD that includes it |
| 4 | `pyfuzz=0`, no `mutations` rows right after LAUNCH | **cold start** (guard cold-loads binary; `cli fuzz` inspects before mutating) | wait 1–3 min; confirm via `stdout.log`; not a failure |
| 5 | (avoided) eviction of a running campaign | `pos allocations allocate/free` on a node | NEVER allocate; SSH-bypass only; leave Track-B's nodes/tmux/`/tmp/ivg_sweep` alone |
| 6 | 922M bundle | `prepare_bundle.sh --allow-dirty` overlays `a4/builds/*/risc0-host` | use `prepare_race_bundle.sh` (git-archive only) → ~533M |
| **7** | **jobs die ~immediately: `proc=0`, no `.OK`/`.FAIL`, no `meta.json`, `stdout.log` frozen at `CMD:`, no `stderr.log`; guard PASSES when run by hand** | `chain_dispatcher.sh`'s launcher `cd`s into the run-dir; the per-job guard `python -m a4.pos.fingerprint_guard` ran from there → `ModuleNotFoundError: No module named 'a4'` → its inline `\|\| { …; exit 87; }` **killed the launcher** before any marker. (Worked by hand only because we always `cd`'d into the repo first; the sweep works because its manifest sets the import path before its guard.) | `remote_cmd` must `cd /root/a4_campaign/repo &&` **BEFORE** the guard — fixed in `generate_race_manifests.py:remote_cmd`, asserted by `test_manifest_generator`. **NB:** the 0-byte `run.db` was a red herring — `sqlite3.connect` in the *probe* scripts created it; always open DBs `mode=ro`. |

## 9. Smoke results (2026-06-24, N=120 × 4 variants × 3 seeds, 8-node fast pool)
First fully-green end-to-end run after the gotcha-#7 fix. All **12/12 jobs `.OK`**, `run.db` pulled, analyzed.

**Timing (steady-state `elapsed_ms`, EPYC pool):** octorand 2.2 s/mut, flare 3.0, zone 3.3 (+ one-time
~89 s prover-key setup on the first mutation). ⇒ **thesis N=5000 ≈ 4.6 h/job worst case → fits a 6 h block.**

**Complementarity (oracle + markers on the real DBs):**
| variant | P(found) | mean ITM applied | conditional find density | note |
|---|---|---|---|---|
| V5_control (A4) | **0.67** (2/3) | 18.0 | 0.037 (≈ predicted ~4%) | finds the planted VerifyOpcode hole |
| Hybrid_cTS | **0.67** (2/3) | 9.0 | 0.074 | finds it (has the A4 surface) |
| V6_cTS (Arguzz) | **0.00** (0/3) | **0.0** | `None` | **0 INSTR_TYPE_MOD applied → bug off its surface** |
| V6_uniform (Arguzz) | **0.00** (0/3) | **0.0** | `None` | same — structural complementarity |

The pure-Arguzz variants apply **zero** INSTR_TYPE_MOD (it is absent from `MUTATION_KINDS_ARGUZZ_*`),
so the A4-findable bug is *structurally unreachable* for them — the headline thesis claim, visible
already at N=120. Their other accepts (INSTR_WORD_MOD / TXN_PREV_* / CYCLE_DIFF_COUNT_MOD) are benign
no-ops the oracle's `@VerifyOpcode` locus check excludes (`non_planted_accept`). Projected to N=5000:
~28 finds each for A4/Hybrid (tight CI), 0/0 for Arguzz (with power). Artifacts in `smoke_results/`
(`pulled/` DBs, `markers_out/race_markers.json` + CSVs, `*.oracle.json`).

**Fast complementarity query (no control re-runs) — the §6 read-only `accepts-by-kind`:**
```python
# per (variant): accepts (verifier_accepted=1) grouped by kind; INSTR_TYPE_MOD accepts == planted-find candidates
sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute(
  "SELECT kind,COUNT(*) FROM mutations WHERE outcome='applied' AND verifier_accepted=1 GROUP BY kind")
```
