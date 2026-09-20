# Step-domain mismatch — impact on the IV.POS.9 Track-B multi-guest sweep

**Owner:** Track-B (multi-guest coverage sweep). **Status:** analysis CLOSED, source-grounded; re-run
DESIGNED, awaiting go-ahead. **Created:** 2026-06-27.

**Upstream bug docs (Track A — read for the full mechanism):**
`a4/docs/cloud3/arguzz_step_domain_fix/MASTER_PLAN.md`,
`…/STEP_DOMAIN_MAPPING_DETAILS.md`, `…/N1000_VALIDATION_RESULTS.md`.
This document is the **Track-B-specific** impact analysis: how that bug lands on *our* four variants and
*our* coverage metrics, what data is valid, and what must be re-run. The companion docs in this directory are
the [re-run plan](02_RERUN_PLAN.md) and the [data-hygiene/mapping plan](03_DATA_HYGIENE_AND_MAPPING.md).

---

## 1. The bug, in one paragraph (Track A's finding)

The VM exposes two step counters that **drift**: the executor `current_step` (bumps on *every* executed
instruction, including host/machine ecalls) and the witgen `user_cycle` (bumps only on *retired guest*
instructions — skips host ecalls). The drift at any point = the running count of host ecalls so far (0 before
the first host ecall, then strictly increasing; +8 by the divides on the CVE guest). The bandit's **Arguzz**
arms take their `step` and `opcode_class` from the executor `--trace` (correct), and `--inject-step` hits the
right instruction (correct) — **but** arm construction computes the third feature,
`zone = step_to_zone[step]`, indexing the **`user_cycle`-keyed** zone table with an **executor** step number.
So the **zone label is systematically wrong** for every Arguzz arm whose step is after the first host ecall
(69% of distinct injected Arguzz steps across Track A's 6 cTS seeds). The injection and `opcode_class` are
right; only the *grouping by execution-unit zone* is scrambled. The **A4** surface indexes the same table with
a `user_cycle` → correct. The fix (committed `68d90aa`, pure-Python, **rebuild-free**) translates the executor
step to its `user_cycle` (`to_user[E]`) before the zone lookup.

---

## 2. Why this hits Track-B harder than Track A

Track A's question is **CVE find-rate** (a committed-output property), which is sound for uniform and only
needs the *selection* corrected for the bandit. **Track-B's deliverables are the coverage metrics
themselves** — the per-guest curves and tables of **local constraint-locs** and **CGC contexts** (compressed
global coverage), plus the cross-variant CGC headline ("during-execution / Arguzz wins CGC; post-execution /
A4 wins local"). Two of those metrics are computed *from* the mutation's zone/major:

- **CGC (`compressed_global_coverage`)** — `compressed_global_extractor.py` builds each context key from
  `cycle_phase(mutation_zone)` and `opcode_class(mutation_major)` (verified: the module's own header lists
  `cycle_phase ← mutation step's semantic zone` and `opcode_class ← major_to_opcode_class(mutation_major)`).
  **So for every Arguzz surface the CGC context key embeds the mislabeled zone/major** → the distinct-CGC
  count is computed on wrong keys (a wrong key reads as a new context; it cannot collapse a real one → the
  count is biased, generally *inflated*).
- **Structural cells (`s_new`)** — keyed on `(kind, semantic_zone, opcode_class, …)`
  (`structural_cells.py`) → same mislabel dependence; feeds `bandit_success`, so the **bandit's reward was
  inflated** on the cTS/Hybrid runs (it learned on a partly fabricated signal).
- **Local coverage (`coverage` table)** — derived from each failure's *own* `(loc, major, minor)`, **not**
  from `mutation_zone`. The recording is **clean**. *But* for the bandit variants the *trajectory* is still
  confounded, because which mutations get run is steered by the scrambled-zone bandit.

Net: the headline metric (CGC) is the one most exposed, and it is exposed on **every Arguzz-touching variant
— including V6_uniform**, whose CGC labels are wrong even though its *selection* is sound.

---

## 3. Per-variant impact (the four Track-B variants)

Variant → surface map (verified in `a4/standalone/variants.py`):

| variant | launcher | selector | surface |
|---|---|---|---|
| **V5_control** | cli | `cTS_semantic_v2` | A4 only |
| **V6_uniform** | driver | (round-robin) | Arguzz |
| **V6_cTS** | cli | `v6_cTS` | Arguzz (bandit) |
| **Hybrid_cTS** | cli | `hybrid_cTS` | A4 + Arguzz |

Impact, separated by what's actually affected:

| variant | selection | local-cov metric | CGC / structural metric | verdict |
|---|---|---|---|---|
| **V5_control** | A4 zone correct (indexes table with `user_cycle`) | clean | **clean** | ✅ **VALID — no re-run** |
| **V6_uniform** | round-robin → **sound** (zone unused for selection) | clean | ❌ **mislabeled** zone/major embedded in CGC | ⚠️ **re-run** (CGC) |
| **V6_cTS** | bandit on **scrambled** zone → confounded | confounded (selection) | ❌ confounded | ❌ **RE-RUN** |
| **Hybrid_cTS** | Arguzz portion scrambled → confounded | confounded | ❌ confounded | ❌ **RE-RUN** |

Why V5 is provably safe (justifies keeping it): the fix diff (`git show 68d90aa --stat`) touches only the
**Arguzz branch** of `semantic_arm_universe.build` (new `arguzz_step_to_zone=` param), `fuzzer`'s Arguzz
reward/record loci (`_arguzz_zone_major`), and the uniform/legacy drivers. The **A4 arm-build branch and the
A4 mutation path are untouched**, and the A4 witgen handlers live in the (already-3-kind-patched) binary, not
the Python. So running V5_control with or without the fix produces identical data.

---

## 4. The two-bug interaction (3-kind contamination × step-domain)

Track-B already has one correction in flight — the **3-kind binary mismatch** (F35:
`CONTAMINATION_AND_FIX_3KIND.md`), fixed in the binary (`53c21894`) and re-run for V5/Hybrid. The step-domain
bug is **independent** (Python harness, Arguzz-only). The two compose as follows:

| variant | 3-kind (binary) | step-domain (Python) | best current data | net action |
|---|---|---|---|---|
| **V5_control** | fixed in the just-finished re-run | N/A (no-op for A4) | the 3-kind re-run — **valid** | pull & **keep** |
| **V6_uniform** | N/A (uses no A4 kinds) | **buggy** | original sweep (Jun 24) — CGC labels wrong | **re-run w/ fix** |
| **V6_cTS** | N/A | **buggy** | original sweep (Jun 24) — confounded | **re-run w/ fix** |
| **Hybrid_cTS** | fixed in the just-finished re-run | **buggy** | the 3-kind re-run — *still* step-domain-confounded | **re-run w/ fix** |

The key trap: **the Hybrid_cTS half of the just-completed 3-kind re-run is NOT usable.** It corrected the
binary (3-kind) but ran the pre-fix bundle (`05450d8`, before `68d90aa`), so its Arguzz arms still carried
scrambled zones. Only the **V5_control half** of that re-run survives.

---

## 5. Data inventory & current state (where every byte lives)

1. **`a4/runs/iv_pos_9/sweep/data/{g1,g2,g3}_{variant}.db`** (12 files, dated **Jun 24**) — the **original**
   screening sweep, **pre-both-fixes**. This is **what the notebook reads today**
   (`build_sweep_notebook.py` → `{DATA}/{guest}_{v}.db`). Every Arguzz variant here is step-domain-buggy and
   V5/Hybrid are additionally 3-kind-contaminated. ⇒ **all 12 are unusable; must be quarantined** (see
   [03](03_DATA_HYGIENE_AND_MAPPING.md)).
2. **coinbase `/tmp/ivg_sweep/results_rerun/` + `results_miss/`** — the just-completed **3-kind re-run**
   (V5_control + Hybrid_cTS, guests g0/g1/g2/g3 × seeds 1234/1235/1236, **24/24 complete**, binary
   `53c21894`, bundle `05450d8` *without* the step-domain fix). **V5_control = valid (12 jobs, pull & keep);
   Hybrid_cTS = step-domain-confounded (12 jobs, discard, re-run).**
3. **g0 baseline** — the notebook historically pulled g0 from the cross-binary D2.F PROD run
   (`pos_iv_pos_8_d2f_{v}…`), which F35 **retired** (cross-binary reuse hazard). The 3-kind re-run produced a
   **fresh same-binary g0**; treat g0 like any other guest (its V5 is valid; its Arguzz variants must be
   re-run).

---

## 6. Bottom line

- **Valid as-is (keep):** **V5_control**, all four guests × three seeds — pull from the 3-kind re-run.
- **Must re-run with the step-domain fix:** **V6_cTS** and **Hybrid_cTS** (confounded selection *and*
  metrics).
- **Should re-run with the fix:** **V6_uniform** — its selection is sound, but its **CGC/structural labels
  are wrong**, and CGC is the Track-B headline metric (see [02 §3](02_RERUN_PLAN.md) for the cheaper
  recompute-instead-of-rerun alternative and the recommendation).
- **Local coverage** is recording-clean everywhere, but its *trajectory* is only trustworthy where selection
  is unconfounded (V5, uniform) — so it does **not** rescue V6_cTS / Hybrid.
- The fix is **rebuild-free**: same per-guest binaries (`28e53771_clean__*`, already 3-kind-patched), only
  the Python (HEAD `68d90aa`) changes. The re-run bundle is `git archive HEAD` + those binaries.
- **The fix was validated (N=1000) only on Track A's CVE guest**, not on our g0/g1/g2/g3 — so a **per-guest
  validation gate is mandatory before the full re-run** (see [02 §2](02_RERUN_PLAN.md)).
