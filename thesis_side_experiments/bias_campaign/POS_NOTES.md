# POS deployment notes (condensed) — for scaling the bias campaign

**Condensed local crib for running our custom host on the POS testbed (C2+ scale-out).**
**Canonical source is `a4/docs/precloud/POS_PLAYBOOK.md` — read it FIRST and defer to it on any conflict.**
Read PLAYBOOK §0 (status), §3 (reservations), §4 (image/bundle), §6 (workflow), §7 (scripts), §12 (anti-patterns, all of them). Skim `a4/pos/README.md`. The cloud1 `PHASE_7B` guide is older overlay-style — defer to PLAYBOOK.

**IGNORE (stale / different effort, will mislead):** any `PHASE_7D_*` / `PHASE_7D_INC3D*` doc, and anything referencing `INC3D_B_BUNDLE` / `INC3D_B2_BUNDLE` (those are the active *main-fuzzer* bundles, not ours).

## HARD RULE: POS vs WSL threshold
**EVERYTHING runs on POS unless the batch is 10 prover runs or fewer.** WSL is for
≤10 proves only (baselines, single-config debugging, smoke checks). Any sweep/batch
with **>10** proves → POS. Applies to the minimal_add example E-series too: E0 = WSL
(≤10 clean proves), E1/E2 = POS (~90 proves each), E3 = POS if >10, E4 = WSL (analysis
only). Arguzz `--inject` sweeps and forced-value/SUR A4 configs need our Python driver
shipped + run on-node (stock manifests are A4_MUTATION_CONFIG-centric) — design that
path before E2 dispatch.

## Why we need POS
The dev box (WSL) is slow; coinbase/POS nodes run campaigns. **No Rust toolchain on coinbase** — always
**build on WSL and ship the binary**. `workspace/` is gitignored on coinbase, so it can't rebuild.

## Workflow (3 steps)
1. **Build locally (WSL).** Our binary is custom (`thesis-minimal-host` for minimal_add; the bias
   campaign drives the production `risc0-host`).
2. **Bundle:** `bash a4/pos/prepare_bundle.sh --host <binary> --allow-dirty` → `~/bundles/a4_campaign_<gitsha>.tar.gz` (binary + sha-verified manifest + repo source).
3. **Dispatch (from coinbase)** against a **pre-reserved** calendar slot:
   `python -m a4.pos.dispatch_pos --manifest <m.json> --bundle <tarball> --nodes <node> --allocation-duration 0 --await`.

## Custom-binary wrinkle (load-bearing)
Bundle scripts hardcode the name `risc0-host`. The on-node `a4/pos/run_campaign_pos.sh` just exec's
whatever is at `bin/risc0-host` in the bundle.
- **Option A (preferred):** copy/symlink our binary to `risc0-host` before bundling:
  `cp target/release/thesis-minimal-host /tmp/risc0-host && bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host --allow-dirty`
- **Option B:** fork `prepare_bundle.sh` + `run_campaign_pos.sh` into `thesis_side_experiments/pos/` (more isolation, more upkeep).
- **Guest ELF is baked into the host** at build time via the `methods/` crate — it travels inside the binary; do **not** ship guest ELF separately.

## Pre-reservation (the first thing that bites)
POS allows only **2 future calendar entries per user**, and dispatch defaults to creating one → quota
errors if you already hold entries. Correct pattern:
1. POS **web calendar UI** → reserve node(s) for the duration (45–60 min small jobs).
2. **Wait until the slot's `start_date` has actually passed** (can't claim early — anti-pattern §12.37).
3. Dispatch with **`--allocation-duration 0`** → claims the existing reservation instead of creating one.
Applies even to a 5-minute single-node test. Web UI is the only way to reserve.

## Bundle SHA
`prepare_bundle.sh` checks `~/arguzz_backups/risc0-host.FIXED.sha256` (won't exist for our custom
binary → harmless warning). Verify ourselves: `sha256sum <binary>`. `bundle.json` records the actual SHA.

## Top anti-patterns (full list PLAYBOOK §12)
1. Dispatch without pre-reserving → quota error. Always reserve via web UI first.
2. Claiming a reservation before its `start_date` → fails. Wait for wall-clock start.
3. `prepare_bundle.sh` on a dirty tree without `--allow-dirty` → refuses. Use `--allow-dirty`.
4. Forgetting `workspace/` is gitignored on coinbase → can't rebuild there. Build on WSL, scp.
5. **Manifest `guest_args` mismatch** → silent runtime failures. **minimal_add guest takes NO inputs →
   `"guest_args": []`**; the production c0/c1 guest uses `["--in1","5","--in4","10"]`.

## End-to-end template (single node smoke; `bitcoin` = slow smoke node)
```bash
# 1. WSL build
cd /root/arguzz/thesis_side_experiments/minimal_add && ./build.sh
cp target/release/thesis-minimal-host /tmp/risc0-host
# 2. WSL bundle
cd /root/arguzz && bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host --allow-dirty
ls -lh bundles/a4_campaign_*.tar.gz   # newest is yours
# 3. ship
scp bundles/a4_campaign_<sha>.tar.gz coinbase:~/THESIS_SIDE_BUNDLE.tar.gz
# 4. POS web UI: reserve bitcoin ~30 min, starting now/+5min
# 5. coinbase dispatch (after start_date passes)
ssh coinbase
source /srv/testbed/pos/cli/venv3/bin/activate
cd ~/arguzz && git pull
python -m a4.pos.dispatch_pos --manifest a4/pos/manifests/pos_smoke_v1.json \
    --bundle ~/THESIS_SIDE_BUNDLE.tar.gz --nodes bitcoin \
    --allocation-duration 0 --await --await-timeout 1800
```
`pos_smoke_v1.json` = known-good 20-mutation uniform job; template new manifests from `a4/pos/manifests/`.

## Collect results
- Land at `/srv/testbed/results/ivgreiff/a4/<campaign>/<timestamp>/<node>/`.
- `python -m a4.pos.collect_results_pos --result-folder <path> --out-dir <local>` (pulls + validates),
  or `scp -P 10022 -r coinbase:/srv/testbed/results/ivgreiff/a4/<campaign>/ ./local/.`

## Sanity check you're on the right machine (coinbase)
```bash
ls -la ~/arguzz/workspace/output/ 2>/dev/null   # should NOT exist
which rustc cargo 2>/dev/null                    # should be empty
ls ~/bundles/ 2>/dev/null                         # may show stale main-fuzzer bundles
```

## Escalation
- New failure mode not in PLAYBOOK §12 → append to PLAYBOOK §10 (decision log) or §12 (append-only).
- POLICY questions (node tier, calendar etiquette) → ask Ivan. MECHANICS → re-read PLAYBOOK §12 first.

## Campaign relevance
- **C0/C1** run locally (small N) — POS not required.
- **C2 (aggregate, N≥500/kind) and C3 (matched)** are the POS-scale phases: bundle the production
  `risc0-host`, template a manifest from `pos_smoke_v1.json` with `guest_args=["--in1","5","--in4","10"]`,
  pre-reserve, dispatch with `--allocation-duration 0`, collect with `collect_results_pos`.
- Our shared-schema DB writers must run **on-node** (inside `run_campaign_pos.sh` flow) or post-process
  collected raw logs locally — decide in C2 design.
