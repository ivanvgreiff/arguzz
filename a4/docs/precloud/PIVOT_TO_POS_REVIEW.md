# Pivot to POS — Review and Disposition

**Date:** Jun 4, 2026 (evening)
**Trigger:** `PIVOT_TO_POS.md` (the ChatGPT Pro report) — user no longer using GCP, will use the university POS testbed.
**Author:** Claude
**Status of running work at this point:** uniform + zoned campaigns at N=1000 seed=1234 still running sequentially in `/root/arguzz/iii6_piggyback/`, expected to finish ~04:00 AM Jun 5. **Not touching them.**

---

## 0 — Why this document exists

The user asked me to:

1. Read `PIVOT_TO_POS.md` in full ✅
2. Decide what to undo / redo from work I did earlier today
3. Decide what changes in the master plan
4. Pivot carefully so we don't lose any detail
5. List to-dos: before campaigns finish vs after
6. Surface what awaits user sign-off

This document is the disposition of (2) and (3). The to-dos are at the end + in `CARRY_FORWARD_TO_TESTBED.md` (renamed from CARRY_FORWARD_TO_CLOUD.md in this same pivot).

---

## 1 — Mental-model shift (per pivot §17)

| Old model (GCP) | New model (POS testbed) |
|---|---|
| Cloud Run Jobs | `pos commands launch` / `pos commands await` |
| Artifact Registry image | Tarball bundle in `/srv/testbed/files`, fetched with `pos_download` |
| GCS for results | `pos_upload` to the experiment result folder |
| Docker is central | Docker is optional, **not** default |
| Elastic auto-scaling | Fixed node reservation (e.g. 3 days) |
| Cost in USD | Cost in node-hours + reservation slot |
| Per-job timeout (24h) | Per-reservation window (3 days assumed, advisor-confirmed) |
| Stateless containers | **Stateless bare-metal** (live-booted OS image; reboot loses local data) |

The critical operational consequence of going bare-metal-stateless: every script that runs on a test node must (a) bootstrap from a downloaded bundle, (b) run, (c) **upload artifacts before the node is freed** (otherwise everything is lost).

---

## 2 — Disposition of each artifact I created/modified today

### 2.1 KEEP unchanged (research-side, platform-agnostic)

These are all things the pivot doc §2 ("what remains valid") explicitly preserves.

| Artifact | Type | Why it's platform-agnostic |
|---|---|---|
| `a4/standalone/coverage_db.py` + new `campaign_params` table | code | Records `tau_g, gamma, B_count, selector`. Useful whether the run was local, GCP, or POS. 9 unit tests pass. |
| `a4/standalone/fuzzer.py` `_persist_campaign_params` hook | code | Same — fires once per campaign, irrespective of orchestrator. |
| `a4/standalone/tests/test_coverage_db_campaign_params.py` | test | Pure schema tests; no orchestrator coupling. |
| `a4/standalone/tests/test_bandit.py` III.5 test | test | Bandit-internal; no orchestrator coupling. |
| `a4/standalone/README_run_replicates.md` | docs | `run_replicates.py` is the local runner; useful for III.6 local gate even under POS, and for benchmark scaffolding (IV.POS.2). |
| `~/arguzz_backups/risc0-host.FIXED.sha256` | persistent file | Binary hash pin — POS bundle prep needs this too (§2.3 below). |
| `~/arguzz_backups/risc0-host.WITH_CIRCUIT_DEBUG.bak` | persistent file | Forensic backup; still useful. |
| `a4/docs/precloud/PHASE_III_{0..5}*` reports | docs | Phase III is platform-agnostic per pivot §2.1. |
| `a4/docs/precloud/PHASE_III_6_IMPLEMENTATION_PLAN.md` | docs | Local validation gate — still required per pivot §2.4. Needs one cross-ref update (see §2.2 below). |
| `a4/notebooks/precloud_validation.ipynb` | analysis | Reads DBs + logs; doesn't care if they came from local, GCS, or POS. |
| Running uniform + zoned campaigns | data | Producing III.6 evidence. Not touching. |

**Nothing in this category needs revision.**

### 2.2 KEEP but lightly REFRAME (small text edits)

| Artifact | What changes | What stays |
|---|---|---|
| `CARRY_FORWARD_TO_CLOUD.md` | Rename → `CARRY_FORWARD_TO_TESTBED.md`. §G items reframed as "GCP-deferred-as-optional-backend" rather than "DONE for IV.0". §H decisions reframed for POS (node count, reservation, benchmark-first; no $$). | §A–E (audits), §F (III.6 prereqs), §I (file diff), and the research-side §G items (tau_g, retention as a *concept*) |
| `PHASE_III_6_IMPLEMENTATION_PLAN.md` | Replace "IV.0" → "IV.POS.4" cross-reference. (III.6 *is* the local mirror of IV.POS.4 per pivot §2.4 and §11/IV.POS.4.) | Everything else |
| `PRECLOUD_MASTER_PLAN.md` §11–§14 | Full rewrite (see §3 below) | §1–§10 (Phase III research-side); §15 (deferrals); §16 (success criteria, but reword "cloud" → "testbed campaign"). |

### 2.3 KEEP under a new "optional Docker backend" framing

The pivot §15.3 says "Docker can be a later optional backend." So I am NOT deleting `a4/cloud/`. Instead:

| Artifact | Disposition | Why keep |
|---|---|---|
| `a4/cloud/Dockerfile` | Add a "DEFERRED OPTIONAL BACKEND" header. Keep file. | Per pivot §5: Docker may revisit later for reproducibility, **after** POS basics work. Image already builds with sha256-verification, which is reusable IP. |
| `a4/cloud/run_campaign.sh` | Add "DEFERRED OPTIONAL BACKEND" header. Keep file. The core (env-driven, DB+log+meta JSON, sha256 record) is **shared** with `run_campaign_pos.sh`; the only difference is upload mechanism (`gsutil cp` vs `pos_upload`). | The core entry-point pattern is reused in POS. Keeping it side-by-side will help when/if we ever revisit Docker. |
| `a4/cloud/dispatch.py` | Add "DEFERRED OPTIONAL BACKEND" header. Keep file. | The core (manifest → enumerate `(strategy, seed)` → per-pair launch + result manifest) is reused; only the underlying launcher (`gcloud run jobs execute` vs `pos commands launch`) differs. `dispatch_pos.py` will be its sister. |
| `a4/cloud/README.md` | Add a banner pointing to `a4/pos/README.md` as the primary path. Add "this is the deferred optional Docker/GCP backend." | One-stop signpost. |

### 2.4 CREATE NEW (POS-native, per pivot §10 + §16)

| File | Purpose | Pivot ref |
|---|---|---|
| `a4/pos/README.md` | One-stop entry-point for POS workflow | §10.1, §16 |
| `a4/pos/prepare_bundle.sh` | Build the tarball with repo + risc0-host + scripts + manifest | §10.2 |
| `a4/pos/run_campaign_pos.sh` | Test-node entrypoint: pos_download bundle → run → pos_upload results | §10.3 |
| `a4/pos/dispatch_pos.py` | Management-node dispatcher: enumerate `(strategy, seed)` and launch per node via `pos commands launch` | §10.4 |
| `a4/pos/collect_results_pos.py` | Pull artifacts from POS result folder, validate DBs | §10.5 |
| `a4/pos/benchmark_pos.sh` | IV.POS.2 benchmark protocol: 3 strategies × N=50, write `pos_benchmark_v1.json` | §9.1, §IV.POS.2 |
| `a4/pos/manifests/.gitkeep` | Manifest directory | §10.1 |
| `a4/docs/precloud/POS_ACCESS_NOTES.md` | IV.POS.0 output: blocked on advisor; scaffold the questions | §11/IV.POS.0, §13 |
| `a4/docs/precloud/POS_ADVISOR_MESSAGE.md` | Drop-in message text for the advisor (§14 of pivot) | §14 |

### 2.5 DELETE / DISCARD (NOTHING)

Nothing. Per pivot §15.1: "Do not delete the research plan." All my recent work either survives as-is, is kept under a deferred-backend banner, or is reframed text-only.

---

## 3 — Master plan changes (high level)

### 3.1 §11+ structure — old vs new

**Old structure (the part being replaced):**

```
§11 Phase IV.0 — Cloud infrastructure (Cloud Run, Artifact Registry, GCS)
    §11.1 Platform choice
    §11.2 Image (Dockerfile)
    §11.3 Entrypoint (run_campaign.sh with gsutil)
    §11.4 Dispatcher (gcloud run jobs execute)
    §11.5 Cost estimation ($31 for 75k muts)
    §11.6 Checkpointing (deferred)
    §11.7 Acceptance criteria
§12 Phase IV.1 — Cloud A/B campaign
§13 Phase IV.2 — Cloud aggregation + boss notebook
§14 Phase IV.3 — Cloud weight A/B (deferred)
```

**New structure (per pivot §11/§16):**

```
§11 Phase IV.POS.0 — POS access and constraint confirmation
    Output: POS_ACCESS_NOTES.md
    Blocked on: advisor reply
§12 Phase IV.POS.1 — Bundle + single-node smoke test
    Output: a4/pos/prepare_bundle.sh, a4/pos/run_campaign_pos.sh, smoke DB/log
§13 Phase IV.POS.2 — Testbed runtime benchmark
    Output: pos_benchmark_v1.json (the s/mut number that sets N)
§14 Phase IV.POS.3 — Multi-node dispatch smoke
    Output: dispatch_pos.py + 3 small campaign DBs
§15 Phase IV.POS.4 — POS local validation campaign (3×3×250 on POS)
    Output: 9 DBs/logs, validation notebook re-run
§16 Phase IV.POS.5 — Full POS A/B campaign (3×5×N, N chosen from benchmark)
    Output: 15 DBs/logs, collection_report.json
§17 Phase IV.POS.6 — Aggregation + boss notebook
    Output: pos_ab_presentation.ipynb
§18 Phase IV.POS.7 — Optional checkpointing / larger N (only if motivated)

(§19/§20: old §15 deferrals + §16 success criteria, lightly reworded)
```

The old §11.5 cost calculation ($31 for 75k muts at GCP) is replaced by §13 (benchmark) + §14/§15/§16 sizing math driven by `safe_budget = 0.7 × reservation_seconds` per pivot §9.2.

### 3.2 What does NOT change in the master plan

- §1–§10 (Phase III, all sub-phases): **untouched**. Research-side, platform-agnostic per pivot §2.1.
- §15.x (originally about checkpoint deferral): rename heading, keep substance.
- §16 (success criteria): reword "cloud" → "testbed campaign"; same metrics.

### 3.3 Cross-cutting wording changes

| Old phrase | New phrase |
|---|---|
| "cloud A/B" | "testbed A/B" or "POS A/B campaign" |
| "Cloud Run job" | "POS-dispatched campaign" |
| "GCS results" | "POS result folder" |
| "Cloud Run timeout (24h)" | "POS reservation window (3 days assumed)" |
| "cost estimate" | "resource estimate" or "node-hour estimate" |
| "Artifact Registry image" | "campaign bundle" |

I will do a global find-replace in the master plan once I rewrite §11–§17.

---

## 4 — III.6 implications (the campaigns currently running)

### 4.1 Are the running campaigns still valid for the new plan?

**Yes, fully.** Per pivot §2.4: "Before any large POS campaign, the revised plan should still run a smaller validation campaign." The pivot's IV.POS.4 explicitly re-uses the local validation gate concept. Our III.6 piggyback (3 strategies × 1 seed × 1000 muts) is a stronger local gate than the original §10.2 protocol (3 × 3 × 250). The gate criteria and notebook all stand.

So the running campaigns are:

- Still producing local validation evidence (III.6 gate).
- A useful sanity check that the fixed binary + post-III.3 schema work at production scale **on this laptop** (a proxy for "on a real machine").
- **Not** a substitute for IV.POS.2 (testbed-specific benchmark): the per-mutation runtime measured on this 8-core WSL machine ≠ what we'll measure on a POS test node.

### 4.2 What changes in the III.6 plan doc

Only a single cross-reference line: where the III.6 plan says "IV.0 unblocked", it should say "IV.POS.0 unblocked" (which in practice means "we can start the POS access/confirmation phase").

### 4.3 What about `mutation_rewards` / `campaign_params` being absent from these runs?

Recap from this morning:
- Postfix bandit (pre-III.3): no `mutation_rewards`, no `campaign_params`. Notebook handles it via terminal-log fallback.
- Running uniform + zoned (post-III.3, pre-`campaign_params`): have `mutation_rewards`, NO `campaign_params` (the `campaign_params` table addition happened AFTER they were launched; their fuzzer.py is the pre-change version held in memory). **All future POS campaigns will populate both tables.**

This is fine for III.6 gate. The notebook is already permissive.

---

## 5 — Anything we wasted today?

Looking carefully:

- `a4/cloud/Dockerfile` (~80 lines): NOT wasted. Per pivot §5.3, Docker remains a possible future backend; the sha256-verification pattern is reusable; the binary-bake idea will inform the POS bundle prep.
- `a4/cloud/run_campaign.sh` (~90 lines): ~70 of those lines (env-driven entry, CLI build, meta JSON, sha256 record, exit-code propagation) are reusable for `run_campaign_pos.sh`. The 20 lines doing `gsutil cp` are GCP-specific and not reused.
- `a4/cloud/dispatch.py` (~180 lines): ~150 of those lines (manifest schema, Cartesian enumeration, per-pair launch, manifest writeback) are reusable for `dispatch_pos.py`. The 30 lines wrapping `gcloud run jobs execute` are GCP-specific.
- `a4/cloud/README.md` (~70 lines): GCP setup — mostly not reused. Becomes a footnote.

**Total revision cost: roughly 50 lines of GCP-specific code rewritten as POS code.** The research-side work (schema, hook, tests) costs zero revision.

The "wasted" cost is small. The new structure (cloud/ side-by-side with pos/) is also a useful safety net: if POS turns out to be impossibly bureaucratic, we have a working GCP fallback already half-built.

---

## 6 — Decisions I am making in this pivot (no user input required)

These are mechanical / obvious-from-pivot-doc:

1. **Keep `a4/cloud/`** as deferred optional backend, with banners. Do not delete.
2. **Create `a4/pos/`** as the new primary orchestration directory.
3. **Rename** `CARRY_FORWARD_TO_CLOUD.md` → `CARRY_FORWARD_TO_TESTBED.md`. Update content for POS.
4. **Rewrite master plan §11–§14** as §11–§18 with IV.POS.0–7 structure per pivot §11.
5. **Keep all running campaigns** as III.6 local validation. They become Phase III.6 evidence, not IV.POS.4 evidence.
6. **Mark all §H decisions as deprecated** in the carry-forward (they were GCP-specific: $/replicate, R=5 vs R=3 by cost). New §H is benchmark-driven.

---

## 7 — Decisions that NEED the user / advisor

These come from pivot §13 — the user must obtain answers from their advisor/admin. **None can be answered by me.** They go in `POS_ACCESS_NOTES.md` and the supervisor email draft.

1. Which testbed? (Blockchain / Baltikum / iLab / Space / Simpsons)
2. Which nodes? (compute-oriented vs network-paired)
3. How many nodes can I reserve, for how long? (3-day base case assumed)
4. Outbound internet on test nodes?
5. `/srv/testbed/files` write path + quota?
6. POS result folder location + quota?
7. Standard Debian image to boot with?
8. Docker allowed/installed? (default: no Docker; revisit later)
9. Long CPU-bound jobs OK on chosen nodes?

These block IV.POS.0 → IV.POS.7. They do NOT block:
- Drafting the POS scaffolding scripts (we know the API shape; values like node name are env vars)
- The currently running III.6 campaigns
- Reviewing III.6 results when they finish
- Drafting the master plan rewrite
- Sending the supervisor email itself

---

## 8 — Net diff summary

```
a4/standalone/coverage_db.py            UNTOUCHED (already done; platform-agnostic)
a4/standalone/fuzzer.py                  UNTOUCHED
a4/standalone/tests/                     UNTOUCHED
a4/standalone/README_run_replicates.md   UNTOUCHED
a4/notebooks/precloud_validation.ipynb   UNTOUCHED
~/arguzz_backups/                        UNTOUCHED

a4/cloud/Dockerfile                      add deferred-backend banner
a4/cloud/run_campaign.sh                 add deferred-backend banner
a4/cloud/dispatch.py                     add deferred-backend banner
a4/cloud/README.md                       add deprecation banner; point to a4/pos/

a4/docs/precloud/CARRY_FORWARD_TO_CLOUD.md   rename to CARRY_FORWARD_TO_TESTBED.md
                                              (update §G, §H, §J for POS)
a4/docs/precloud/PHASE_III_6_PLAN.md         cross-ref "IV.0" → "IV.POS.0"
a4/docs/precloud/PRECLOUD_MASTER_PLAN.md     rewrite §11–§14 → §11–§18 (IV.POS structure)

NEW:
a4/pos/README.md                              POS-first workflow
a4/pos/prepare_bundle.sh                      bundle prep
a4/pos/run_campaign_pos.sh                    test-node entrypoint
a4/pos/dispatch_pos.py                        management-node dispatcher
a4/pos/collect_results_pos.py                 results puller / DB validator
a4/pos/benchmark_pos.sh                       benchmark protocol (IV.POS.2)
a4/pos/manifests/.gitkeep                     manifest dir
a4/docs/precloud/POS_ACCESS_NOTES.md          IV.POS.0 scaffold (blocked on advisor)
a4/docs/precloud/POS_ADVISOR_MESSAGE.md       supervisor email draft
a4/docs/precloud/PIVOT_TO_POS_REVIEW.md       this document
```

Nothing deleted. ~5 doc-text edits. ~7 new scaffolding files. All research-side work intact.
