# IV.POS.8 — Phase 3 Spec: D2.F — POS deployment of the four-variant checkpoint

**Version:** v1.0 — **LOCKED FOR IMPLEMENTATION** (authored by Opus-CP acting as D2-Opus, 2026-06-20)
**Phase:** New_Master §2 **Phase 3** (the four-variant POS checkpoint) · Pro: `ProG_Report_4.md` §Phase 3
**Governing plan:** [`New_Master.md`](New_Master.md) §2 Phase 3 (D2.F row), §1 LOCKED variant set
**POS SSOT:** [`../precloud/POS_PLAYBOOK.md`](../precloud/POS_PLAYBOOK.md) — **read the top dispatch-template table, §12.52–§12.53 (SSH-bypass chain dispatcher), §12.37/§12.43/§12.49 (reservations) before dispatching.**
**Hard gate:** **`POS_READINESS_CHECKLIST.md` (D2.E) must be GREEN before F.2.**
**Predecessors (closed):** D2.C, Bernoulli, D2.D, **D2.E** (pre-POS integration gate, complete; full sweep 819 passed / 31 skipped).
**Produces:** the four-variant campaign DBs that **D2.G** (Phase 4) analyzes.

---

## 0. Scope & non-goals

### 0.1 What D2.F IS
The **production POS deployment** of the four-variant checkpoint — the first time the integrated stack runs at scale. It (a) **decides F15** (fresh V5 re-run — §2), (b) builds the **fully-automated, unattended dispatch** the user asked for (the `chain_dispatcher.sh` SSH-bypass auto-chaining: launch a batch across all reserved nodes, poll completion markers, auto-pull results, fire the next batch with ~1s handover, zero manual intervention), and (c) **collects + validates** the result DBs through the D2.E gates at POS scale so D2.G can analyze comparable data.

Campaign: **4 variants × R seeds × N=10000**, fresh on `sha2-host`, across the **8 reserved nodes** (`flare, polynize, octorand, opulous, algofi, zone, gard, goracle`).

### 0.2 What D2.F is NOT
- **NOT the analysis** (territory/scores/report) — that's D2.G. D2.F stops at "comparable DBs collected + D2.E gates pass at scale."
- **NOT new product code** — variants/dispatch/telemetry all landed in D2.C–E. D2.F adds **operational tooling** (a manifest generator + runbook) + **the F15 fresh-V5 config**, and may fix only deployment-surfaced bugs.
- **NOT multi-guest** — single-guest (`sha2-host`) checkpoint only (Pro D7: multi-guest comes before any "beats Arguzz" headline).
- **NOT re-deciding** the variant set, mappings, or L1-inactivity (locked upstream).

### 0.3 The reframed-thesis reminder (what this campaign must let D2.G answer)
Per ProG_Report_4 §7, the checkpoint answers **"does V6-cTS beat V6-uniform on the same 11 Arguzz kinds?"** and **"does Hybrid-cTS beat V6-uniform on total useful territory?"** — directionally, on one guest. Not a paper-level conclusion. This sizing/rigor target informs the modest replicate count (§1.2).

---

## 1. The campaign matrix

### 1.1 Variants (all FRESH — see F15, §2)
| Variant | Launch (via `variants.py` registry) | N | Bernoulli | applied-accounting | Surface |
|---|---|---|---|---|---|
| **V5_control** | `cli.py fuzz --selector cTS_semantic_v2` | 10000 | off | off | A4 |
| **V6_uniform** | `python -m a4.standalone.v6_uniform_driver` | 10000 | n/a (round-robin) | n/a | Arguzz |
| **V6_cTS** | `cli.py fuzz --selector v6_cTS` | 10000 | on (ConstantFloor 0.55) | on | Arguzz |
| **Hybrid_cTS** | `cli.py fuzz --selector hybrid_cTS` | 10000 | on (ConstantFloor 0.55) | on | A4+Arguzz |

`--telemetry-level full` for all (D2.G needs reward_counterfactuals + L1 columns + substrategy). Guest args `-- --in1 5 --in4 10` (matches the archive baseline). Env per variant is set by `run_campaign_pos.sh`/the bridge (`A4_COVERAGE_TOUCH=1`, `A4_FAMILY_RESIDUE=1`, `CONSTRAINT_CONTINUE=1`; cli path adds `A4_GLOBAL_RESIDUE=1`).

### 1.2 N and replicates
- **N = 10000** for all four variants (Ivan-locked, overriding the prior "6000-for-archive-comparability" — since F15 makes every variant fresh, archive-N comparability is moot; F12 cold-start-fairness for the cTS variants is satisfied at 10000: 437×3 = 1311 cold pulls ≈ 13% vs ~22% at 6000).
- **R = replicate seeds. Default R=3 (seeds 1234, 1235, 1236) = 12 jobs.** Rationale: Pro framed this as a directional single-guest checkpoint, not a paper-level study; N=10000 already gives low per-run variance; 3 seeds guard against a seed fluke without over-spending the reservation. **The generator is seed-list parameterized** — R=2 (1 batch, fastest) or R=4 (clean 2×8 batches) are one-line changes if Ivan's reservation window dictates.

### 1.3 Timing (measured from the archives — drives the reservation, §10 F16)
| Variant | s/mut (sequential, measured) | N=10000 wall |
|---|---|---|
| V5 (A4) | ~2.95 (archive: 6000 in 4h55m) | **~8.2h ← critical path** |
| V6_uniform / V6_cTS (Arguzz) | ~2.46 (archive: 6000 in 4h06m) | ~6.8h |
| Hybrid (A4+Arguzz) | ~2.5–2.9 (mix) | ~7–8h |
- **Batch wall-time = the slowest job in the batch ≈ 8.5h (V5-gated).**
- **`A4_COVERAGE_TOUCH` forces sequential (SeqForward) mode** — this is *required* for CGC (the F13 mechanism) and is non-negotiable; the ~2.5–3 s/mut is the sequential prover cost, not overhead to optimize away.

### 1.4 Job → node layout (8 reserved nodes)
- R=3 → 12 jobs → **2 chain batches**: Batch 1 = 8 jobs (4 variants × {1234,1235}) across all 8 nodes; Batch 2 = 4 jobs (4 variants × {1236}) across 4 nodes. ≈ 2 × 8.5h ≈ **~17h unattended**.
- Each job pinned 1-per-node (no two jobs share a node concurrently → no SQLite contention). Slow V5 jobs spread one-per-batch so they don't serialize.
- `chain_dispatcher` auto-advances Batch 1 → Batch 2 on completion (no human handover).

---

## 2. F15 decision — **FRESH V5 re-run** (LOCKED by Opus-CP per Ivan's delegation)

**Decision: V5_control is a FRESH POS run at N=10000, not R2-archive reuse.** The R2 V5 archive becomes historical reference only — exactly the treatment V6_uniform already got.

**Evidence (verified directly):** the R2 V5 archive (`pos_iv_pos_7_ts_b1_cTS_semantic_v2_seed1234_n6000.db`) **lacks `mutations.outcome` and the L1 `reward_counterfactuals` columns**, though it has normalized loc + CGC (183/15062).

**Why fresh, not an adapter:**
1. **Ivan's own precedent.** V6_uniform was locked fresh "for schema/outcome parity in D2.G" (New_Master §1). The V5 archive has the *identical* gap (no `outcome`) — consistency demands the same fix.
2. **N moved to 10000.** The only reason to reuse the archive was N=6000 comparability; that's gone now that all variants are fresh at 10000.
3. **D2.G needs `outcome` for V5.** Pro's Phase-4 metrics (applied-pull count, skip/error rate, C1/C2/C5 split, outcome distribution) require the `outcome` column the archive lacks; an adapter would special-case V5 and leave it un-auditable for L1.
4. **Behavior is unchanged.** V5_control fresh = `cTS_semantic_v2`, ConstantFloor 0.55, **no Bernoulli**, A4-only, applied-accounting **off** — byte-identical decisions to the archive (golden-trace-protected), just with the current telemetry columns. This honors Pro's "do not change the deployed A4 baseline behavior" (it's the same behavior; only telemetry is richer) and is distinct from the deferred `V5_fresh_bernoulli` ablation.
5. **Compute is available** — 8 nodes reserved; V5 is one more job per batch.

**Net:** one uniform ingestion path in D2.G, full L1 baseline, no adapter debt. F15 → RESOLVED (fresh). Closes the AMBER in `POS_READINESS_CHECKLIST.md`.

---

## 3. Dispatch architecture — unattended auto-chaining (the user's ask)

### 3.1 The tool: `chain_dispatcher.sh` (POS_PLAYBOOK §12.53)
A single tmux process that, per batch: SSH-bypass-launches each job (`ssh -n -f nohup` a generated launcher that runs the campaign, writes `meta.json`, and `touch`es `.OK`/`.FAIL_rc$RC`), then **polls** every node for `.OK`/`.FAIL` markers, **auto-scps** the result DB the instant a job finishes, and on `BATCH_COMPLETE` **immediately fires the next batch** (~1s handover). It uses a per-node `check_state.sh` **in-flight probe** (scans `/proc` for the run_id) so a re-fire never double-launches a running job into the same SQLite DB (corruption guard — §12.53 Gotcha #1). **This is exactly the "send everything, auto-detect completion, safely dispatch next, no manual intervention" capability requested.**

Manifest format (text): `batch_name|node|run_id|remote_cmd`.

### 3.2 Two-phase deployment
- **Phase A — boot + bundle (one-time, calendar allocation).** `python -m a4.pos.dispatch_pos` (or `dispatch_audit.sh`) to allocate the 8 reserved nodes (`--allocation-duration 0` to claim the pre-existing reservation), image `debian-trixie`, reset, and copy+extract the campaign **bundle** to each node. (The chain dispatcher then drives execution over SSH, bypassing per-job calendar churn — §12.52.)
- **Phase B — chained execution.** Fire `chain_dispatcher.sh` with the generated manifest; it runs Batch 1 → Batch 2 unattended, auto-pulling DBs to `RESULTS_BASE`.

### 3.3 F.1 smoke-gate → F.2 production tail (New_Master)
- **F.1 — smoke-gate (8 jobs, small N).** 4 variants × 2 seeds at **N=100** (≈ minutes/job), one chain batch across 8 nodes. **Purpose:** prove the *entire* POS path end-to-end (boot → bundle → chain-launch → completion-detect → auto-pull → ingestible DB) and that D2.E's gates pass on **real POS DBs**, *before* committing ~17h. **F.1 gate (all must hold):** 8 DBs auto-collected; each passes the D2.E POS-readiness checks (schema/normalized-loc/outcome/applied-accounting); **CGC + global_failures non-empty for every Arguzz variant (F13 at scale)**; **Hybrid shows CGC from BOTH surfaces** (the Gate-C surface-split deferred from D2.E — assert A4-family and Arguzz-family CGC rows both present at N=100); V5 fresh DB has `outcome` + L1 columns populated.
- **F.2 — production tail.** Only after F.1 is green: 4 variants × R seeds at **N=10000** (§1.2/§1.4), auto-chained.

---

## 4. Deliverables

| Deliverable | What | Notes |
|---|---|---|
| `a4/pos/generate_d2f_manifests.py` | **NEW** — emits the `chain_dispatcher` text manifests for F.1 (N=100, 2 seeds) and F.2 (N=10000, R seeds), mapping each (variant, seed) → (batch, node, run_id, remote_cmd). Per-variant command pulled from **`variants.py` `CANONICAL_VARIANTS` / `variant_launch_command`** (single source of truth — no hand-written commands). Seed-list + N + node-list parameterized. | run_id convention: `pos_iv_pos_8_d2f_<variant>_seed<seed>_n<N>`. remote_cmd includes the env exports + `cd repo && <launch>`. |
| `a4/pos/manifests/iv_pos_8/d2f_smoke.chain` + `d2f_production.chain` | **NEW** — the generated chain manifests (committed for reproducibility/audit). | |
| `a4/docs/cloud2/composer/D2F_DISPATCH_RUNBOOK.md` | **NEW** — the exact operator runbook (§6): reservation, bundle build, Phase A, Phase B, monitoring, collection, validation, recovery. | Fire-and-forget under tmux. |
| `a4/standalone/tests/test_d2f_manifest_generator.py` | **NEW** — unit test: generator produces well-formed `batch|node|run_id|cmd` lines; commands match `variants.py`; 8 nodes covered; seeds/N correct; no two concurrent jobs on one node. | Local, no POS. |
| `a4/docs/cloud2/composer/D2F_*_REPORT.md` | Per-phase reports (F.1 results + gate verdict; F.2 collection summary). | |

**No production-code changes expected.** If a deployment bug surfaces (e.g., a launch command wrong for a variant), fix minimally + add a generator regression test.

---

## 5. Pre-flight gates (ALL required before Phase A)

1. **`POS_READINESS_CHECKLIST.md` GREEN** (D2.E) — with **F15 now resolved fresh** (Gate B no longer AMBER).
2. **⛔ Bundle freshness (F17).** The bundle MUST contain the current D2.C/D2.D/D2.E/Bernoulli code. **These are uncommitted in the working tree.** If the bundle is built via `git archive HEAD`, it will ship **stale code** and the entire campaign is invalid. **Action: commit the D2.x + Bernoulli work (or build the bundle from the working tree), then verify the bundle's `bandit_ts.py`/`fuzzer.py`/`cli.py`/`variants.py`/`l1_signals.py`/`arguzz_bridge.py` contain the new logic** (e.g., grep the extracted bundle for `bernoulli_floor`, `v6_cTS` in cli choices, `DEFAULT_ARGUZZ_SUBPROCESS_ENV`). Do not dispatch until confirmed.
3. **Binary integrity.** `risc0-host` in the bundle is the modified build (sha-verified) that emits `<constraint_fail>` + `<a4_family_residue>` under the campaign env (the F13 binary). Confirm it's the same build family as the archives.
4. **Reservation covers the run (F16).** Each node reserved for ≥ the batch wall-time (~8.5h/batch; ~17h for R=3's two batches on the same nodes). A single N=10000 V5 job (~8.2h) **does not fit a 6-hr block** — use contiguous/merged reservations (§12.49) or a long block. Confirm with Ivan before Phase B.
5. **8 nodes healthy + reserved**: `flare, polynize, octorand, opulous, algofi, zone, gard, goracle`. Substitute any that hang in `ERR booting` (§12.45).
6. **F.1 smoke-gate green** before F.2 (§3.3).

---

## 6. Operator runbook (summary — full in `D2F_DISPATCH_RUNBOOK.md`)
1. **Commit + build bundle** (F17): commit D2.x; build `a4_campaign_<git>.tar.gz`; verify it contains the new code.
2. **Reserve** the 8 nodes for the campaign window (F16) via the calendar UI.
3. **Generate manifests:** `python a4/pos/generate_d2f_manifests.py --phase smoke` and `--phase production --seeds 1234 1235 1236`.
4. **Phase A (boot+bundle):** `dispatch_audit.sh`/`dispatch_pos.py` with `--allocation-duration 0` to claim the reservation, image+reset+copy bundle to all 8 nodes.
5. **F.1:** fire `chain_dispatcher.sh` with `d2f_smoke.chain` (POLL_SEC=15), under tmux; watch `tail -f` the chain log; on `CHAIN_COMPLETE`, run the F.1 gate (§3.3) on the collected DBs.
6. **F.2 (only if F.1 green):** fire `chain_dispatcher.sh` with `d2f_production.chain` (POLL_SEC=30), under tmux; unattended ~17h.
7. **Collect + validate:** DBs auto-pulled to `RESULTS_BASE`; rsync to local `a4/runs/iv_pos_8/d2f/`; run the D2.E POS-readiness checks against the N=10000 DBs (schema/loc/outcome/CGC/applied-accounting parity across all 4 variants × R).
8. **Hand off to D2.G** with the validated DB set + a collection manifest (variant, seed, N, path, row counts, outcome distribution, CGC counts).

---

## 7. Completion, collection & validation
- **Completion detection:** `chain_dispatcher` `.OK`/`.FAIL_rc$RC` markers + `meta.json` (wall_sec, exit_code) per job. A `.FAIL` job is re-runnable individually (re-add its line, re-fire — `check_state.sh` skips the completed ones).
- **Collection:** automatic scp of `*.db *.log *.meta.json` to `RESULTS_BASE/<batch>/<run_id>/` as each `.OK` appears.
- **Validation (the D2.F exit gate):** run the D2.E gates on the collected N=10000 DBs — **all 4 variants × R must**: have non-NULL `outcome`; canonical normalized loc; non-empty CGC (Arguzz variants + Hybrid both surfaces); consistent schema; sane outcome distribution (APPLIED-dominant). Any variant/seed failing → re-run that job; do not hand a partial/incomparable set to D2.G.

---

## 8. Batch structure
- **B1 — Generator + F.1 smoke.** `generate_d2f_manifests.py` + `test_d2f_manifest_generator.py` + the runbook; dispatch F.1 (8 jobs, N=100); report F.1 gate verdict. **Gate:** F.1 green (incl. Hybrid both-surface CGC + F13 at scale).
- **B2 — F.2 production tail.** Dispatch the N=10000 campaign (R seeds, auto-chained); collect; run the D2.F exit-gate validation; emit the collection manifest for D2.G. **Gate:** all 4×R DBs validated comparable.

---

## 9. Acceptance checklist
- [ ] **F15 resolved fresh** — V5_control is a fresh N=10000 run; archive demoted to reference.
- [ ] Bundle freshness (F17) confirmed — bundle contains D2.C/D/E/Bernoulli code.
- [ ] `generate_d2f_manifests.py` emits valid chain manifests from `variants.py`; generator test green.
- [ ] **F.1 smoke green** — full POS path validated; D2.E gates pass on real POS DBs; CGC non-empty per Arguzz variant; **Hybrid both-surface CGC**; V5 fresh has outcome+L1.
- [ ] **F.2 collected** — 4 variants × R seeds × N=10000 DBs auto-pulled.
- [ ] **D2.F exit gate** — all DBs validated comparable (schema/loc/outcome/CGC/applied-accounting); collection manifest produced.
- [ ] Reservation covered the run (no jobs killed at a block boundary).
- [ ] New_Master D2.F → DONE; hand-off to D2.G.

---

## 10. Risks / flags

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| **F16 — reservation < job time** | N=10000 V5 job ~8.2h > a 6-hr POS block → job killed at the boundary, wasting ~8h. | **High** | §5.4: reserve contiguous/long blocks (~8.5h/batch, ~17h for R=3); confirm with Ivan before Phase B. Batch wall is V5-gated. |
| **F17 — stale bundle** | D2.C/D/E/Bernoulli are **uncommitted**; a `git archive HEAD` bundle ships old code → entire campaign invalid. | **High** | §5.2 pre-flight: commit (or working-tree-bundle) + grep the extracted bundle for the new symbols before dispatch. |
| **DF-1 — double-launch DB corruption** | Re-firing a batch while a job runs corrupts its SQLite DB. | Med | `chain_dispatcher`'s `check_state.sh` in-flight `/proc` probe (built-in); never run two jobs on one node concurrently (1-per-node layout). |
| **DF-2 — CGC empty at scale** | The F13 env regresses on the POS binary/shell → empty CGC → checkpoint useless for territory. | Med | F.1 gate asserts CGC non-empty at N=100 **before** the 17h tail; bridge default env + `run_campaign_pos.sh` both set `A4_COVERAGE_TOUCH=1`. |
| **DF-3 — node failure mid-campaign** | A reserved node dies during F.2. | Med | `.FAIL` job is individually re-runnable; substitute a node (§12.45); chain skips `.OK` jobs on re-fire. |
| **DF-4 — incomparable DBs reach D2.G** | A subtle per-variant gap slips F.1 but bites at scale. | Low–Med | The D2.F exit gate (§7) re-runs the full D2.E parity suite on the **N=10000** DBs, not just F.1's N=100. |
| **DF-5 — replicate count too low** | R=3 may under-power a close V6-cTS-vs-V6-uniform call. | Low | Pro: directional checkpoint, not paper-level; N=10000 lowers per-run variance; R is one-line bumpable; multi-guest expansion (with more R) is the real rigor pass later. |
| **DF-6 — Hybrid surface-split CGC unverified pre-scale** | D2.E deferred it (Composer pushback). | Low | Folded into the F.1 gate (§3.3) — asserted at N=100 on real POS Hybrid DB. |

---

## 11. Sequencing & dependencies
- **Depends on:** D2.E green (`POS_READINESS_CHECKLIST.md`), F15 (resolved here), a fresh committed bundle (F17).
- **Blocks:** D2.G (Phase 4 analysis) — needs the validated 4-variant DB set + collection manifest.
- **Carry-forward / resolved:** F12 (cold-start fairness — satisfied at N=10000), F15 (resolved fresh), ISS-1 (D2.G fault-corroboration residual — D2.G).

---

## 12. Changelog
| Date | Author | Version | Notes |
|---|---|---|---|
| 2026-06-20 | Opus-CP (acting D2-Opus) | v1.0 LOCKED | Initial spec. **F15 → fresh V5 re-run** (archive lacks `outcome`/L1; consistency with V6_uniform; N→10000 moots archive comparability). Campaign: 4 fresh variants × R=3 × N=10000 on 8 reserved nodes; unattended via `chain_dispatcher.sh` SSH-bypass auto-chaining (F.1 N=100 smoke → F.2 N=10000 tail). Deliverables: `generate_d2f_manifests.py` (driven by `variants.py`) + chain manifests + runbook. Surfaced **F16** (reservation < ~8.2h V5 job) + **F17** (uncommitted-code bundle staleness) as high-severity pre-flight gates. Timing measured from archives (V5 ~2.95 s/mut, V6 ~2.46). Grounded in POS_PLAYBOOK §12.52–53, `chain_dispatcher.sh`, `dispatch_pos.py`, `run_campaign_pos.sh`, `variants.py`. |
