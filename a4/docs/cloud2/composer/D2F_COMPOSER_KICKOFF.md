# D2.F — Composer Kickoff (POS deployment of the four-variant checkpoint)

**Spec:** [`../IV_POS_8_D2_F_SPEC.md`](../IV_POS_8_D2_F_SPEC.md) **v1.0 LOCKED** — read it in full first.
**POS SSOT:** [`../../precloud/POS_PLAYBOOK.md`](../../precloud/POS_PLAYBOOK.md) — the top dispatch-template table + **§12.52–§12.53 (SSH-bypass `chain_dispatcher`)** + §12.37/§12.43/§12.49 (reservations).
**Gate:** `POS_READINESS_CHECKLIST.md` (D2.E) is GREEN; full sweep **819 passed / 31 skipped**; F15 resolved (fresh V5).

You're deploying the four-variant checkpoint to POS, **fully unattended**, via the `chain_dispatcher.sh` SSH-bypass auto-chainer (launch a batch across all 8 nodes → poll `.OK`/`.FAIL` → auto-scp results → fire next batch, ~1s handover, with `check_state.sh` in-flight protection against double-launch DB corruption).

## Locked campaign parameters
- **4 fresh variants, all N=10000:** `V5_control` (`cli fuzz --selector cTS_semantic_v2`), `V6_uniform` (`v6_uniform_driver`), `V6_cTS` (`--selector v6_cTS`), `Hybrid_cTS` (`--selector hybrid_cTS`). `--telemetry-level full`; guest args `-- --in1 5 --in4 10`.
- **F15 = fresh V5 re-run** (NOT archive reuse). The R2 V5 archive lacks `outcome` + L1 columns; fresh V5 is behavior-identical (golden-trace-protected, no Bernoulli, ConstantFloor 0.55, applied-accounting off) but with current telemetry. Archive → reference only.
- **Nodes (8, Ivan-reserved):** `flare polynize octorand opulous algofi zone gard goracle`. 1 job/node concurrently (no SQLite contention).
- **Replicates: R=3 (seeds 1234, 1235, 1236) = 12 jobs → 2 chain batches** (Batch1 = 4 variants × {1234,1235} on 8 nodes; Batch2 = 4 variants × {1236} on 4 nodes). **Confirm R with Ivan** — the generator is seed-list-parameterized; R=2 (1 batch) or R=4 (2 full batches) are one-liners.
- **run_id convention:** `pos_iv_pos_8_d2f_<variant>_seed<seed>_n<N>`.
- **Per-variant launch commands come from `a4/standalone/variants.py` `CANONICAL_VARIANTS`** — do NOT hand-write them; the generator pulls them so dispatch can't drift from the registry.

## Operational context from Ivan (important)
- **Jobs survive reservation expiry.** `chain_dispatcher` launches detached `nohup` jobs over SSH; they keep running even after the calendar window ends. The reservation only keeps the nodes *held* (not reclaimed/reset). Ivan reserves a **12h window + re-reserves every 6h** to hold the 8 nodes contiguously — so the ~17h R=3 campaign is safe. **(F16 is therefore a hold-the-nodes note, not a job-kill risk.)**
- **Reservation timing:** starts shortly, **Ivan will move it earlier once you're ready for POS**. So do **Batch 1 (local, no POS) first**, then ping Ivan to start the window for Phase A.
- **You may commit** (Ivan's commit rules allow it for you/Opus). Ivan has already committed the D2.x + Bernoulli code.

## Pre-flight gates (before any POS dispatch)
1. **Bundle freshness (F17 — critical).** The bundle MUST contain the committed D2.C/D2.D/D2.E/Bernoulli code. Ivan committed it, so: confirm `HEAD` contains the new logic, build the bundle from `HEAD` (not a stale ref), and **grep the extracted bundle** for `bernoulli_floor` (`bandit_ts.py`), `v6_cTS`/`hybrid_cTS` in the `cli.py` `--selector` choices, `DEFAULT_ARGUZZ_SUBPROCESS_ENV` (`arguzz_bridge.py`), and `l1_signals.py`. **Do not dispatch until all four are present in the bundle.**
2. **Binary:** the bundled `risc0-host` is the modified build that emits `<constraint_fail>` + `<a4_family_residue>` under the campaign env (the F13 binary; sha-verify against the archive build family).
3. **D2.E checklist green** (it is) — F15 row now resolved fresh (no longer AMBER).

## Batch 1 — generator + F.1 smoke (do the generator LOCALLY first; POS only for the smoke)
- **`a4/pos/generate_d2f_manifests.py`** (NEW) — emits the `chain_dispatcher` text manifests (`batch|node|run_id|remote_cmd`) for F.1 and F.2, mapping (variant, seed) → (batch, node, run_id, command-from-`variants.py`). Parameterize seeds / N / node-list. Commit it + the generated `d2f_smoke.chain` / `d2f_production.chain` manifests.
- **`a4/standalone/tests/test_d2f_manifest_generator.py`** (NEW, local) — assert: well-formed lines; commands match `variants.py`; all 8 nodes covered; correct seeds/N; no two concurrent jobs on one node.
- **F.1 smoke (POS, 8 jobs, N=100):** 4 variants × 2 seeds. **Phase A** (boot 8 nodes + copy/extract bundle, per POS_PLAYBOOK SSH-bypass setup) then **Phase B** (`chain_dispatcher` on `d2f_smoke.chain`, POLL_SEC=15, under tmux). **F.1 GATE — all must hold on the collected POS DBs:** 8 DBs auto-pulled; each passes the D2.E POS-readiness checks (schema / normalized-loc / `outcome` non-NULL / applied-accounting); **CGC + global_failures non-empty for every Arguzz variant (F13 at scale)**; **Hybrid shows CGC rows from BOTH the A4-family AND Arguzz-family surfaces** (the surface-split deferred from D2.E Gate C — assert both at N=100); V5 fresh DB has `outcome` + L1 columns populated. **Report the F.1 verdict and STOP for review before F.2.**

## Batch 2 — F.2 production tail (only after F.1 green + Opus review)
- Fire `chain_dispatcher` on `d2f_production.chain` (N=10000, R seeds, POLL_SEC=30) under tmux; ~17h unattended (V5 is the ~8.2h critical-path job per batch).
- **Exit gate (D2.F §7):** re-run the D2.E parity suite on the **N=10000** DBs — all 4 variants × R must be comparable (schema / loc / `outcome` / CGC incl. Hybrid both-surface / applied-accounting / sane outcome distribution). Any variant×seed failing → re-run just that job (`chain_dispatcher` skips `.OK` jobs on re-fire). Produce the **collection manifest** for D2.G (variant, seed, N, path, row counts, outcome distribution, CGC counts).

## Stop-and-report triggers
- F17 bundle check fails (missing any of the 4 symbols) → **stop, rebuild bundle**.
- F.1 gate fails any check (esp. empty CGC, or Hybrid missing a surface, or V5 missing `outcome`) → **stop, report** — that's a real pre-scale find, not something to push past.
- A node hangs in `ERR booting` → substitute another from the reservation (§12.45); don't retry indefinitely.
- Any job's launch command doesn't match `variants.py` → stop (don't hand-patch the manifest; fix the generator).

Report each batch as `composer/D2F_<phase>_REPORT.md`. F.1 first, await Opus review, then F.2.
