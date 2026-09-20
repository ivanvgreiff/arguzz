# Sweep history & data provenance — how many times we ran it, why, and which DBs are which

**Purpose:** an exact, auditable record of every time the IV.POS.9 Track-B multi-guest sweep was run, why each
re-run happened, and which databases belong to which run — so we never confuse valid and invalid data again.

## Accuracy note — this is reconstructed from sources of truth, NOT from memory

I do **not** have perfect recall of this (the working session was long and context was summarized). Everything
below is reconstructed from **authoritative, queryable sources**, and that is where 100 % accuracy lives:

1. **Git log** (primary, dated) — `git log --date=short -- a4/runs/iv_pos_9 a4/standalone/step_domain_map.py a4/docs/cloud3/...`. Each infra/fix/re-run is a commit.
2. **Per-DB fingerprint** — every run dir has `build_fingerprint.json` (binary sha, `risc0_head_sha`,
   `guest_image_id`) written by the G11 guard at launch, plus the bundle git-short. This proves which binary +
   (with the bundle short) which Python a given `run.db` was produced with. **This is the ground truth for
   "which sweep does this DB belong to."**
3. **Coinbase chain logs + results dirs** — `chain_{rerun,miss,stepfix}.log` and
   `results_{rerun,miss,stepfix}/` are timestamped per-job records (launch, OK/FAIL, pull).
4. **The narrative docs** — `CONTAMINATION_AND_FIX_3KIND.md` (F35), `arguzz_step_domain_fix/` (step-domain),
   and this directory.

Where a count or seed-set below is not yet re-confirmed against (2)/(3), it is flagged **[verify]**.

---

## The three sweep runs

| # | name / when (git) | variants run | binary | Python harness | DBs (location) | status |
|---|---|---|---|---|---|---|
| **1** | **Original** — Jun 24 (`2e96e14`→`487c8e6`) | all 4 (V5, V6_uniform, V6_cTS, Hybrid) | a **mixed/older** build; g0 **reused cross-binary** from D2.F | pre-both-fixes | `a4/runs/iv_pos_9/sweep/data/{g1,g2,g3}_{variant}.db` (Jun 24) + g0 from `iv_pos_8/d2f/.../pos_iv_pos_8_d2f_{v}_seed1234_n10000` | **ALL INVALID** |
| **2** | **3-kind re-run** — Jun 26–27 (tooling `61ae36a`) | V5_control + Hybrid_cTS | `53c21894` (3-kind-patched) | bundle `05450d8` — **no** step-domain fix | coinbase `/tmp/ivg_sweep/results_rerun/` + `results_miss/` (24/24) | **V5 valid; Hybrid invalid** |
| **3** | **step-domain re-run** — Jun 27–28 (fix `68d90aa`) | V6_uniform + V6_cTS + Hybrid_cTS | `53c21894` (same) | overlay at `68d90aa` (step-domain fix) | coinbase `/tmp/ivg_sweep/results_stepfix/` | **running** (8 nodes after the GLIBC fix) |

### Why each re-run happened (the two errors)

- **Error A — 3-kind binary mismatch (F35).** The Original sweep's V5/Hybrid jobs ran A4 mutation kinds
  `TXN_PREV_WORD_MOD` / `TXN_PREV_CYCLE_MOD` / `CYCLE_DIFF_COUNT_MOD` against a clean binary that **lacked
  their witgen handlers** (added later in `6556e8d7`), so those kinds hit an `invalid config` fallback and were
  **silently skipped and recorded as accepts**. Also §0.1: g0 was reused from a **different binary**
  (cross-binary). → triggered **Sweep #2** on the 3-kind-patched binary `53c21894`.
  (Refs: `CONTAMINATION_AND_FIX_3KIND.md`, `THREE_KIND_INVESTIGATION_REPORT.md`, ledger F35.)
- **Error B — Arguzz step-domain (zone) mismapping.** Arguzz arms computed `zone = step_to_zone[executor_step]`
  while that table is keyed by witgen `user_cycle`; the two drift by the host-ecall count, so every Arguzz
  arm's zone label (and the CGC/structural reward inputs) was scrambled. Affects **V6_cTS + Hybrid's Arguzz
  portion** (selection + metrics) and **V6_uniform's CGC labels**. V5_control (A4-only) is immune. → triggered
  **Sweep #3** with the Python fix `68d90aa` (rebuild-free; same binary). (Refs: `arguzz_step_domain_fix/`,
  `01_FINDINGS_AND_IMPACT.md`.)

### Operational disruptions (NOT re-runs — same campaign, just restarts)

These cost time but did **not** change the data's validity; recorded so the timeline isn't misread as more
re-runs than there were:
- Sweep #2: node churn / reservation boundary reset killed in-flight jobs → resume-safe restarts + a reroute of
  6 missing seed-1236 jobs (`results_miss/`).
- Sweep #3: (a) sandbox-egress throttle masquerading as a coinbase CPU cap (fixed by `dangerouslyDisableSandbox`);
  (b) a mangled heredoc paste that killed a launch; (c) **node `pact` reimaged to Debian 12 (bookworm)** whose
  glibc < 2.39 → the trixie-built binary won't execute there → dropped pact, run continues on 8 trixie nodes.
  (See `04_EXECUTION_RUNBOOK.md`.)

---

## Final valid-data lineage (what the notebook must use)

| variant | comes from | binary | step-domain fix | why valid |
|---|---|---|---|---|
| **V5_control** | Sweep #2 (`results_rerun`/`results_miss`) | `53c21894` | n/a (A4-only; fix is a no-op) | 3-kind fixed; step-domain doesn't touch A4 |
| **V6_uniform** | Sweep #3 (`results_stepfix`) | `53c21894` | yes (`68d90aa`) | correct CGC/zone labels |
| **V6_cTS** | Sweep #3 (`results_stepfix`) | `53c21894` | yes | unconfounded selection + metrics |
| **Hybrid_cTS** | Sweep #3 (`results_stepfix`) | `53c21894` | yes | both surfaces correct |

Everything from Sweep #1 (`data/*.db`) and the Hybrid half of Sweep #2 is **superseded → quarantine, never
plot** (see `03_DATA_HYGIENE_AND_MAPPING.md`).

## To confirm any DB's provenance (the 100 %-accurate check)

For a given `run.db`, read its sibling `build_fingerprint.json`: `risc0_head_sha` must be
`53c21894…` and `guest_image_id` must match the guest; the bundle git-short tells you the Python (`68d90aa` for
Arguzz variants, ≥`05450d8` acceptable only for V5). A DB whose fingerprint doesn't match its claimed sweep is
contaminated and must not enter `data_clean/`.
