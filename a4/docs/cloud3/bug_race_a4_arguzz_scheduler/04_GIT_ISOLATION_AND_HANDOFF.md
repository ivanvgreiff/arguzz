# Git isolation strategy + handoff note to the other tracks

**Date:** 2026-06-27. Verified repo state below. Question answered: *how do we modify shared a4/ Python (fuzzer.py, cli.py, step_selector.py, variants.py, + a new V8 driver) without affecting the other tracks' workspaces, with a clean revert path?*

## Verified facts that decide the strategy
- `a4/` Python lives in the **main arguzz repo**; current branch **`cloud2`** (single working tree at `/root/arguzz`), HEAD `68d90aa`, **pushed** (`cloud2…origin/cloud2`).
- **`cloud2` is SHARED — all tracks commit to it.** Recent commits: Track-B/sweep (`61ae36a`, `05450d8`, `487c8e6`, `55a1b39`), CVE/A1 (`d5051be`, `6961a2e`), step-domain (`68d90aa`), our A3 (`f98c3f7`).
- POS bundles are built with **`git archive HEAD`** (`prepare_race_bundle.sh:24`) — i.e. they snapshot whatever branch you build from.
- The other tracks' RUNNING POS campaigns use **frozen bundles already deployed** — our edits cannot touch them. BUT the **sweep re-run** (`sweepb3_stepfix`, launched ~06-28 per memory) and any future re-bundle would pick up whatever is on `cloud2` at build time.

## Verdict: **feature branch off `cloud2` — do NOT "commit on cloud2 and revert."**
Why not commit-and-revert: `cloud2` is **shared + pushed**; reverting pushed history interleaved with other tracks' commits is destructive, and any track that re-bundles from `cloud2` between our commit and our revert silently ships our V0/V8 code. The sweep is actively re-running — that risk is live, not hypothetical.

### The workflow
1. **Branch:** `git branch cloud2-sched-ablation cloud2` (off HEAD `68d90aa`). Do all V0/V8 Python work + commits there.
2. **Isolate the working tree** (so `/root/arguzz` stays on `cloud2`, untouched for the other tracks): `git worktree add /root/arguzz-sched cloud2-sched-ablation`. Edit + commit the Python in the worktree. (The risc0 build worktrees under `workspace/risc0-*` are separate git checkouts shared by path; the fixed-binary cherry-pick happens in `workspace/risc0-seamb` per `CONTAMINATION_IMPACT_VERIFICATION.md §5`, independent of this arguzz branch. `a4/builds/*` binaries are gitignored, copied in after build.)
3. **Build the POS bundle from the feature branch** (`git archive HEAD` inside the worktree) → it carries V0/V8; `cloud2` bundles do not.
4. **`cloud2` stays clean** → other tracks' running campaigns AND any future `cloud2` re-bundles are unaffected.
5. **Revert = delete the branch** (`git branch -D` / `git worktree remove`) — zero impact on `cloud2` history.
6. **Merge to `cloud2` only after** the fixed-binary campaign is validated AND the other tracks have confirmed they've finished any `cloud2` re-bundling — then `git checkout cloud2 && git merge cloud2-sched-ablation` (or a PR). This makes V0/V8 the shared baseline once it's safe.

### Why this is also right for "this is the last rework for now"
A feature branch costs ~nothing and gives a clean merge-when-ready. Even as the last rework, isolating it until validated (the V8 step-domain bridge is the kind of thing you want proven on POS before it lands on the shared branch) is strictly safer than editing `cloud2` in place.

## Handoff note (send to the Track-B/sweep + CVE OCPs)
> **Heads-up — Track A is adding two A4 scheduler variants (V0, V8) on a feature branch, NOT on cloud2.**
> - Branch `cloud2-sched-ablation` (off cloud2 `68d90aa`) adds TWO cli `--selector`s in `step_selector.py`: `a4_uniform_semantic` (V0) + `a4_arguzz_sched` (V8 = Arguzz instruction-balanced site → A4 mutation), their `fuzzer.py` wiring, the `cli.py` choices, and `variants.py` entries. It touches `a4/standalone/{fuzzer,cli,step_selector,variants}.py` only (no new driver file; V8 reuses the cli `_run_single_mutation` path).
> - **`cloud2` is unchanged.** Your running POS campaigns (frozen bundles) are unaffected. If you re-bundle from `cloud2` (e.g. another sweep re-run), you will NOT pick up V0/V8 — by design.
> - We will **not merge to cloud2** until our fixed-binary campaign validates and you confirm you've finished any cloud2 re-bundling. Tell us if you have a cloud2 build pending so we time the merge around it.
> - We are also building a FIXED Seam-B binary (cherry-pick `6556e8d7` onto `workspace/risc0-seamb`) — isolated to our worktree; `risc0-clean-28e53771`@`53c21894` (sweep), `risc0-modified`@`6556e8d7` (AP/race), `risc0-a1-vuln`@`088a0753` (CVE) are untouched.

## What we modify (for the handoff record) — AS BUILT
- `a4/standalone/variants.py` — +2 `VariantSpec` (`V0_uniform`, `V8_arguzz_sched`).
- `a4/standalone/cli.py` — +2 `--selector` choices (`a4_uniform_semantic`, `a4_arguzz_sched`).
- `a4/standalone/step_selector.py` — +`SemanticUniformArmSelector` (V0) + `ArguzzSchedA4Selector` (V8).
- `a4/standalone/fuzzer.py` — V0 + V8 wiring (defer + `_setup_a4_uniform_semantic`/`_setup_v8_arguzz_sched` + the `is_uniform` run-dispatch; NOT in `V2_BANDIT_STRATEGIES`).
- `a4/pos/generate_race_manifests.py` — `--variants` filter (so the registry add doesn't balloon the default manifest to 6×seeds).
- (No new driver file — V8 is a cli selector reusing `_run_single_mutation`.)
- `a4/scripts/build_seamb_fix.sh` — fixed-binary build driver (Inc 4).
- **Analysis = NEW separate folder `a4/runs/iv_pos_9/race/sched_ablation/`** (`sched_ablation_lib.py` + `build_sched_ablation_notebook.py` + notebook). **DEFERRED** until fixed-run DBs exist. Per Ivan's separation directive, the published `race_lib.py`/`race_exploration.*`/`build_race_*` are **NOT edited** — the ablation harness imports `oracle.py`/`markers.py` read-only and reads `fix_thesis_results/` in place.
- (NO edits to `race_lib.py`, `race_exploration.*`, `build_race_*`, `markers.py`, `oracle.py`, `fingerprint_guard.py`, `chain_dispatcher.sh`, or any Track-B/sweep file.)
