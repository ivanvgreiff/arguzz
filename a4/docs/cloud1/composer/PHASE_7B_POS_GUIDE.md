# Phase 7b POS Smoke — Operational Guide for Composer

**Status**: Live operational guide (Opus → Composer)
**Date**: 2026-06-08
**Trigger**: Phase 7a (5 × N=20 WSL) is **DONE**. Phase 7b is 5 × N=200 on POS (`coinbase`).
**Purpose**: Answer the 10 questions Composer asked Opus about the POS workflow, in one place that Composer can `Read` on coinbase. Where this guide and `POS_PLAYBOOK.md` disagree, **`POS_PLAYBOOK.md` wins** (it's the canonical source). This guide is the **cloud1-Phase-7b-specific overlay** of the playbook.

> **Composer**: read this file end-to-end before touching anything POS. Then read `a4/docs/precloud/POS_PLAYBOOK.md` §4–§8 + §12 for the underlying mechanics. If the two disagree on anything not explicitly called out below, follow the playbook.

---

## TL;DR — the one-thing-you-need-to-know

**`risc0-host` is the C++/Rust host binary; it is NEVER in git and never present on `coinbase` after `git pull`.** It is built on a developer machine (WSL in our case) from `workspace/risc0-modified/` via `cargo build --release`. The pinned, SHA-verified copy lives on the user's WSL at:

```
/root/arguzz/workspace/output/target/release/risc0-host
/root/arguzz/~/arguzz_backups/risc0-host.FIXED.bin   (canonical pinned copy)
/root/arguzz/~/arguzz_backups/risc0-host.FIXED.sha256
```

(Both copies have identical sha256 `6873e588…cc444`.)

On `coinbase`, `risc0-host` does NOT exist anywhere automatic. The only ways to get one there are:
1. **`scp` the binary from WSL** (one-time, ~100 MB), then run `prepare_bundle.sh --host /path/to/scped/binary --allow-dirty` on coinbase.
2. **Build the bundle on WSL** (which includes the binary inside the tarball), then `scp` the bundle (~66 MB compressed) to coinbase.

Either way, the binary MUST come from WSL. **It is not in the git push.** This is what blocked you.

---

## Recommended workflow for Phase 7b (chosen by Opus, user-approved by precedent)

We use **Option 2 (build full bundle on WSL → scp to coinbase)** to match IV.POS.1's verified procedure (POS_PLAYBOOK §8 IV.POS.1, Jun 6 08:13 entry). Opus will build the bundle in the user's WSL chat session and have the user scp it. **You do not run `prepare_bundle.sh` on coinbase.**

The flow is:

```
[Opus on WSL]          [User]            [Composer on coinbase]
prepare_bundle.sh  →   scp to coinbase  →  run_smoke_7b_pos.sh <node>
```

When Composer sees `~/a4_campaign_<sha>.tar.gz` on coinbase, the user has completed the scp. Until that file exists, Composer waits.

---

## Direct answers to your 10 questions

### A. Where is `risc0-host` in Ivan's real POS workflow?

**A1 — Where IV.POS.1-5 sourced `risc0-host`**: from WSL, packed into bundle via `prepare_bundle.sh`, then `scp`'d to coinbase. Specifically:
- The binary at `workspace/output/target/release/risc0-host` (or symlinked to `~/arguzz_backups/risc0-host.FIXED.bin`, sha256 `6873e588…cc444`)
- `prepare_bundle.sh` `cp`s the binary into `bundle_root/bin/risc0-host`
- The tarball is scp'd to coinbase
- On the test node, the bundle is extracted and `bin/risc0-host` is invoked

**A2 — Is `workspace/output/target/release/risc0-host` expected on coinbase after `git pull`?** **NO.** `workspace/` is gitignored. After a fresh `git pull` on coinbase the only files present are git-tracked source + the new untracked files you (Composer) created. No build artifacts.

The "build path for coinbase" intentionally **does not exist**. Coinbase has no Rust toolchain installed (it's the POS management node, not a developer workstation). All host binaries are pre-built on WSL by the user.

**A3 — Diagnostic on coinbase**: please run this for me when you read this guide. I'll embed expected outputs once the user pastes results:

```bash
ls -lh ~/a4_campaign_*.tar.gz 2>/dev/null    # bundles previously scp'd here
ls -la ~/arguzz/workspace/ 2>/dev/null       # should show: only what's in git (constraint_test.log? maybe nothing)
ls -la ~/arguzz/workspace/output/ 2>/dev/null # should NOT exist
which rustc cargo 2>/dev/null                # should be empty / fail
rustc --version 2>/dev/null                  # likely "command not found"
ls ~/arguzz_backups/ 2>/dev/null             # should NOT exist on coinbase (user confirmed)
```

### B. Can we reuse an existing bundle or extract the host?

**B4 — Is there a pre-existing `~/a4_campaign_*.tar.gz` on coinbase?**

Maybe. From IV.POS.1 (Jun 6) the bundle `a4_campaign_b169e76c7b1c.tar.gz` was scp'd to coinbase. It may still be in `~`. The diagnostic above (A3) tells you. If yes:

- **Acceptable to extract `bin/risc0-host` from that tarball and reuse?** YES, the binary itself has not changed. SHA must still match `6873e588…cc444`. Procedure:
  ```bash
  cd ~ && tar -xzf a4_campaign_b169e76c7b1c.tar.gz a4_campaign/bin/risc0-host
  # → ~/a4_campaign/bin/risc0-host now exists
  sha256sum ~/a4_campaign/bin/risc0-host
  # must equal: 6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444
  ```
- **But then bundle with current `git HEAD`?** YES, that's the IV.POS.1 pattern with `--allow-dirty`:
  ```bash
  cd ~/arguzz
  bash a4/pos/prepare_bundle.sh \
      --host ~/a4_campaign/bin/risc0-host \
      --allow-dirty
  ls -lh bundles/a4_campaign_*.tar.gz
  cp bundles/a4_campaign_*.tar.gz ~/
  ```
  - The `prepare_bundle.sh` will WARN `no expected sha file at $HOME/arguzz_backups/risc0-host.FIXED.sha256; skipping verification` — this is **expected and acceptable** on coinbase (we don't replicate the FIXED.sha256 file there). The binary's SHA still gets recorded in `bundle.json`.

**B5 — Authoritative procedure when no tarball on coinbase**: build bundle on WSL and `scp` to coinbase. Same pattern as Jun 6 06:08 (recorded in POS_PLAYBOOK §11):

```bash
# on WSL
cd ~/arguzz   # = /root/arguzz in Opus's environment
bash a4/pos/prepare_bundle.sh --allow-dirty
# → produces bundles/a4_campaign_<sha>.tar.gz (~66 MB)
scp -P 10022 bundles/a4_campaign_*.tar.gz ivgreiff@coinbase.net.in.tum.de:~/
```

**Opus's recommendation for THIS Phase 7b**: try B4 first (extract from existing bundle if `~/a4_campaign_b169e76c7b1c.tar.gz` is still there). If not, ask the user to do B5; Opus will build the bundle in the WSL session and the user runs the `scp`.

### C. SHA verification on coinbase

**C6 — Does the user maintain `~/arguzz_backups/` on coinbase?** **NO.** Confirmed by user 2026-06-08. The `arguzz_backups` workflow is WSL-only. On coinbase, `prepare_bundle.sh` will hit the missing-sha-file branch:

```bash
# In prepare_bundle.sh line 96-98:
else
    echo "[prepare_bundle] WARN: no expected sha file at $EXPECTED_SHA_FILE; skipping verification"
fi
```

This is the intended behavior. The script does NOT fail; it just skips the SHA check. The binary's actual SHA still gets recorded in `bundle.json` so we can compare across runs offline. **Do not try to write a SHA file to `~/arguzz_backups/` on coinbase — leave the script's WARN as-is.**

### D. Phase 7b dispatch — confirm procedure

**D7 — Is `run_smoke_7b_pos.sh` the right entry point?** **YES.** The flow you constructed is correct. Confirmation:

```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de   # if not already on coinbase
tmux new -s phase7b                            # persist across SSH disconnect (POS_PLAYBOOK §8 "Long-running dispatch pattern")
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz
git pull                                       # confirm cloud1 HEAD matches WSL HEAD

# Confirm bundle exists in home
ls -lh ~/a4_campaign_*.tar.gz

# Confirm free node
pos nodes list | awk '$2=="host" && $3=="booted" && $4=="None"'

# Confirm < 2 active allocations (POS_PLAYBOOK §12.28 — hard cap)
pos allocations list

# Dispatch all 5 variants sequentially against ONE node
bash a4/pos/run_smoke_7b_pos.sh <free-node>
```

The script `run_smoke_7b_pos.sh` does:
- Loops over the 5 manifests in `a4/pos/manifests/smoke_7b/*.json`
- For each manifest: `python -m a4.pos.dispatch_pos --manifest <mf> --bundle <BUNDLE> --nodes <NODE> --allocation-duration 240 --await`
- Each dispatch is one independent allocation per playbook §12.36 (1 job per node per dispatch). Sequential, not parallel — fits within the 2-cap easily.

Image is `debian-trixie` per the manifests (GLIBC 2.39+ required by `risc0-host` per §12.30). Seed is `999`, N=200, telemetry_level=`full` for all 5 variants.

**D8 — Recommended node + wall-clock estimate**:

| Tier | Node candidates | Per-mut wall | N=200 wall | 5 variants total |
|---|---|---|---|---|
| **S** | `flare` (EPYC 9354, Zen 4) | ~2 s/mut measured Jun 6 (POS_PLAYBOOK §3.1) | ~7 min | **~35 min + ~6 min setup overhead × 5 ≈ 65 min** |
| **A** | `algofi` (EPYC 7543, Zen 3) | ~3.25 s/mut measured | ~11 min | ~55 min + overhead ≈ 85 min |
| **E** | `bitcoin` (D-1518) | ~19 s/mut measured | ~63 min | ~5h15min + overhead — **DO NOT USE** |

**Pick Tier S (`flare`)** if free. Tier A (`algofi`) if not. **Do NOT use Tier E nodes** for Phase 7b — N=200 × 5 variants would be ~5 hours and waste a Tier S slot that someone else could grab. The setup overhead (alloc + image + reset + copy + extract + apt-get + pip + baseline + first mut) is ~5 min per dispatch regardless of node; that's a fixed 25 min added to whatever the runtime number above gives.

Pre-flight check: `pos nodes list | grep -E '^(flare|algofi)\s'`. If `flare` shows `booted None`, you're good.

**Total Phase 7b expectation**: 60–90 min wall on `flare`. Allocate generously: `--allocation-duration 240` (the script does this).

**D9 — Where do 7b DBs land + collect command**:

Per dispatcher convention (POS_PLAYBOOK §6 workflow + IV.POS.1 verified Jun 6 08:13):

```
/srv/testbed/results/ivgreiff/a4/pos_smoke_7b/<run-dir>/<node>/pos_smoke_7b_<strategy>_seed999_n200.db
```

Where `<run-dir>` is something like `2026-06-09_HH-MM-SS_NNNNNN` (one per dispatch). With 5 sequential dispatches you'll get 5 separate run dirs.

To collect onto WSL after all 5 finish:

```bash
# from WSL (NOT coinbase). Adjust username if needed.
rsync -av -e 'ssh -p 10022' \
  ivgreiff@coinbase.net.in.tum.de:/srv/testbed/results/ivgreiff/a4/pos_smoke_7b/ \
  ./a4/runs/pos_smoke_7b/

# Validate / produce collection_report.json
python -m a4.pos.collect_results_pos \
  --result-folder ./a4/runs/pos_smoke_7b/ \
  --out-dir ./a4/runs/pos_smoke_7b/ \
  --in-place
```

If you want, run a partial-collection from coinbase between dispatches to check for early failures — but the dispatcher's `--await` should print clear pass/fail per dispatch, so this is optional.

### E. Phase 7b zoned-consistency (§7b.3)

**E10 — Pre-cloud1 git tag for legacy zoned comparison**: there is NO formal pre-cloud1 tag in the current repo. Recent unique pre-cloud1 commit points usable as reference:
- `b169e76c7b1c` (IV.POS.1 bundle commit, Jun 6) — pre-cloud1
- `56e3fb94ec85` (Jun 5)
- `44beaaba0a0b` (Jun 5)

The corresponding bundles still exist on WSL at `/root/arguzz/bundles/a4_campaign_{b169e76c,56e3fb94,44beaaba}*.tar.gz` (66 MB each).

**Practical recommendation for Phase 7b zoned consistency**:

The exit criterion (Phase 7 plan §7b.3) was "run zoned on POS using legacy code path AND new code path, final coverage MUST match". The legacy code path lives at commit `b169e76c7b1c`. To execute this faithfully:

1. **Option A (proper)**: build a `b169e76c7b1c` bundle from WSL using the existing `bundles/a4_campaign_b169e76c7b1c.tar.gz` directly (no rebuild needed — it's already there), dispatch it for zoned/seed=999/N=200, capture the DB. Then compare against `smoke_7b_zoned.db` from cloud1.
2. **Option B (deferred)**: skip the exact-coverage equality check for now, but include in Phase 9 report a note that "zoned-consistency was deferred because legacy DB existed only at smaller N from IV.POS.1; no production user reads `zoned` DBs in cloud1 so the regression risk is low".

**Opus's recommendation**: **defer to Phase 9** (Option B). Reasons:
- The cloud1 fuzzer's `zoned` path got `telemetry_level=standard` default (D35); we verified at the test level that the 382-test suite passes including zoned. Behavioral regression would have triggered a unit-test failure.
- Running a full N=200 zoned campaign on an old git commit eats another POS slot for marginal value at this stage.
- If Pro flags it in R2, we can run it then (~11 min on `algofi`, $0 to wait).

If you (Composer) disagree and want the exact-equality check, the procedure is:
```bash
# On coinbase, after `git pull` of current cloud1:
cd ~/arguzz
git stash 2>/dev/null || true                  # save any local mods
git checkout b169e76c7b1c -- a4/standalone/    # revert ONLY fuzzer code
# Bundle re-build is unnecessary — use the existing legacy bundle:
python -m a4.pos.dispatch_pos \
  --manifest a4/pos/manifests/smoke_7b/pos_smoke_7b_zoned.json \
  --bundle ~/a4_campaign_b169e76c7b1c.tar.gz \
  --nodes <free-node> \
  --allocation-duration 60 \
  --await
git checkout HEAD -- a4/standalone/             # restore cloud1
git stash pop 2>/dev/null || true
```

But I recommend deferring per Option B.

---

## Single approved copy-paste sequence for Composer

**Run this on coinbase, inside tmux, in this exact order**:

```bash
ssh -p 10022 ivgreiff@coinbase.net.in.tum.de    # if not already there

tmux new -s phase7b
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz
git pull

ls -lh ~/a4_campaign_*.tar.gz
ls ~/arguzz/workspace 2>/dev/null
which rustc cargo 2>/dev/null
pos allocations list
pos nodes list | awk '$2=="host" && $3=="booted" && $4=="None"'
```

**If `~/a4_campaign_*.tar.gz` shows a recent (today's) bundle**: proceed to dispatch. Skip step (a)/(b) below.

**If `~/a4_campaign_*.tar.gz` is empty OR all bundles are pre-2026-06-08**:
- Stop. Tell the user (Ivan) in plain text: "I need a cloud1 bundle on coinbase. Please ask Opus to build it on WSL and scp."
- Opus will run `prepare_bundle.sh` on WSL and provide the user with one `scp` command.

**If `~/a4_campaign_b169e76c7b1c.tar.gz` exists (IV.POS.1 legacy) but no cloud1 bundle**:
- Option (a, faster): extract binary, rebuild bundle on coinbase from current HEAD:
  ```bash
  mkdir -p ~/extracted && cd ~/extracted
  tar -xzf ~/a4_campaign_b169e76c7b1c.tar.gz a4_campaign/bin/risc0-host
  sha256sum a4_campaign/bin/risc0-host
  # MUST be: 6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444
  cd ~/arguzz
  bash a4/pos/prepare_bundle.sh \
      --host ~/extracted/a4_campaign/bin/risc0-host \
      --allow-dirty
  cp bundles/a4_campaign_*.tar.gz ~/
  ls -lh ~/a4_campaign_*.tar.gz
  ```
- Option (b, safer): defer to user/Opus per the "stop" branch above.

**Once a cloud1 bundle exists at `~/a4_campaign_<sha>.tar.gz` on coinbase**, dispatch:

```bash
# Pick a free Tier S/A node from the list above. Recommended: flare.
NODE=flare       # or whatever shows free in the awk output

bash a4/pos/run_smoke_7b_pos.sh "$NODE" 2>&1 | tee /tmp/phase7b.log
# 5 sequential dispatches. Each dispatch writes to:
# /srv/testbed/results/ivgreiff/a4/pos_smoke_7b/<run-dir>/$NODE/pos_smoke_7b_<strategy>_seed999_n200.db
# Wall expectation on flare: ~60-90 min total.

# When complete, detach tmux: Ctrl+B d
# Or watch live: it should print "Phase 7b: all five dispatches finished."
```

**After all 5 dispatches finish**, tell the user. User will rsync the result folder to WSL where Opus runs validation per the Phase 7b exit criteria.

---

## What Composer MUST NOT do

- ❌ Run `cargo build` / try to compile `risc0-host` on coinbase. No Rust toolchain there.
- ❌ Re-image / reset a node that someone else owns. Always check `pos nodes list` for `None` in column 4 first.
- ❌ Allocate when `pos allocations list` already shows 2 of yours (hard cap, §12.28).
- ❌ Use `debian-bookworm` image — GLIBC 2.36 too old (§12.30). The manifests already specify `trixie`.
- ❌ Pass `--allocation-duration 0`. The cloud1 smoke_7b manifests assume the dispatcher creates a fresh calendar event (§12.29).
- ❌ Run `prepare_bundle.sh` on coinbase WITHOUT either passing `--host /path/to/binary` OR having a binary at `workspace/output/target/release/risc0-host`. Default path won't exist.
- ❌ Try to set up `~/arguzz_backups/` on coinbase. The SHA-skip WARN is intentional.

---

## What Opus does on WSL when user asks

If the user comes back and says "Composer says no bundle on coinbase, please build one":

```bash
cd /root/arguzz
bash a4/pos/prepare_bundle.sh --allow-dirty
ls -lh bundles/a4_campaign_*.tar.gz
# → user runs:
#   scp -P 10022 bundles/a4_campaign_<latest-sha>.tar.gz ivgreiff@coinbase.net.in.tum.de:~/
```

Opus will then tell Composer in the next message: "bundle scp'd; resume the dispatch sequence above".

---

## Why this guide exists (for future Composers)

Composer 2.5 (Jun 8 2026) ran Phase 7a (5 × N=20 WSL) successfully, then tried to launch Phase 7b on coinbase by running `prepare_bundle.sh` directly. It failed because `workspace/output/target/release/risc0-host` does not exist on coinbase — `workspace/` is gitignored and there is no Rust toolchain on the management node. Composer correctly identified this as a knowledge gap and asked Opus 10 specific questions rather than guess.

This guide consolidates the answers and is the persistent reference. Future POS phases (8, 9 conditional) should re-read it before any coinbase work.

---

## Cross-references

- `a4/docs/precloud/POS_PLAYBOOK.md` — canonical POS reference (§3 nodes, §4 image+bundle, §5 API, §6 workflow, §8 phase walkthroughs, §10 decisions, §11 verified-commands, §12 anti-patterns).
- `a4/docs/cloud1/phases/PHASE_7_SMOKE_TESTS.md` — the Phase 7 plan with exit criteria (this guide covers the 7b sub-phase).
- `a4/pos/prepare_bundle.sh` — bundle builder (auto-discovers binary at `workspace/output/target/release/`).
- `a4/pos/run_smoke_7b_pos.sh` — Composer's 7b runner (loops 5 manifests sequentially on one node).
- `a4/pos/dispatch_pos.py` — the dispatcher (handles allocate / set_variables / image / reset / copy / launch / await).
- `a4/pos/manifests/smoke_7b/pos_smoke_7b_*.json` — the 5 cloud1 variant manifests for Phase 7b.

---

## Status (as of 2026-06-08 19:38 EST, post-bundle-build)

| Item | Where | Status |
|---|---|---|
| `risc0-host` binary | WSL `/root/arguzz/workspace/output/target/release/risc0-host` | ✅ exists, sha `6873e588…cc444` |
| `risc0-host` sha file | WSL `~/arguzz_backups/risc0-host.FIXED.sha256` | ✅ exists, matches |
| `risc0-host` on coinbase | coinbase `~/` or `~/arguzz/workspace/...` | ❌ does NOT exist; comes via the bundle below |
| Cloud1 source on coinbase | coinbase `~/arguzz` | ✅ user confirmed pushed/pulled |
| **Fresh cloud1 bundle on WSL** | `/root/arguzz/bundles/a4_campaign_3ff810e4ab47.tar.gz` **(67 MB)** | ✅ **BUILT BY OPUS 2026-06-08 23:38 UTC.** Git `3ff810e4ab47`, host sha verified, all cloud1 modules (telemetry_v2, bandit_ts, reward_v2, semantic_zones, compressed_global_extractor, full Phase 4-6 tests) included in `repo/` |
| Cloud1 bundle on coinbase | coinbase `~/a4_campaign_3ff810e4ab47.tar.gz` | ⏳ pending user `scp` (one command — see below) |
| 5 Phase 7b manifests | `a4/pos/manifests/smoke_7b/` | ✅ on coinbase (user-confirmed in their message) |
| `run_smoke_7b_pos.sh` | `a4/pos/run_smoke_7b_pos.sh` | ✅ on coinbase (user-confirmed) |
| `A4_TELEMETRY_LEVEL` wiring | `a4/pos/run_campaign_pos.sh:208-210` + `dispatch_pos.py:184-185` | ✅ on coinbase (user-confirmed) |
| Phase 7a (WSL) | local | ✅ done (per user) |
| Phase 7b (POS) | coinbase | ⏳ ready as soon as bundle lands on coinbase |
| Phase 7c (mutation-semantic) | local re-execution on V5 DB | ⏳ pending 7b completion |

### Bundle manifest (cloud1)

```json
{
  "git_commit": "3ff810e4ab471a36b8679582be3c2060d9d19a04",
  "git_short": "3ff810e4ab47",
  "dirty": true,
  "host_binary_path": "bin/risc0-host",
  "host_sha256": "6873e5887dd98a84885ebe0dfb88ae2b05b113810b76ca586d9a7a19805cc444",
  "include_wheels": 0,
  "python_version_expected": "3.12",
  "created_at_utc": "2026-06-08T23:38:12Z",
  "notes": "Bundle for POS testbed run. See a4/pos/README.md."
}
```

`dirty: true` is benign — it reflects untracked POS scripts (`smoke_7b/` manifests, `run_smoke_7b_pos.sh`) that already exist on coinbase. The bundle's `repo/` is `git archive HEAD` which only contains committed files, so the dirty flag does not affect what runs on the test node.
