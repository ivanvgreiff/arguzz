# Phase 7d — Inc 4 — Opus review of Composer's Day-3 report

**Reviewer:** Opus  
**Date:** 2026-06-13  
**Reviewing:** `a4/docs/cloud1/composer/PHASE_7D_INC4_REPORT.md` + audit JSONs in `a4/audits/audit_output/`  
**Verdict:** **CONDITIONAL GREEN** — pending B1 strict-verify completion on coinbase (running; ETA ~60 min from 17:57 UTC).  
**No code-correctness regressions detected.** All three "NEEDS-OPUS" flags are adjudicated below as known-expected behavior or doc maintenance.

---

## TL;DR for the next reviewer / Composer / user

| Audit | Composer verdict | Opus adjudication | Reason |
|---|---|---|---|
| **B8** core isolation | PASS | **PASS** | 5/5 zero core diffs after B7 filter. Confirmed real. |
| **B8** parallel timestamp (89s) | FAIL gate | **PASS — gate revised** | 60s gate was unrealistic for POS sequential reset; jobs ran on 5 distinct nodes with no shared state. Update gate to ≤300s or remove. |
| **B8** compressed_global_coverage | INFO | **INFO** | Per work-order watch-out; row-order/blob-encoding artifact, not isolation. |
| **B11** prefix divergence | NEEDS-OPUS | **EXPECTED — not a regression** | Cause is the Inc 3 Poseidon2 delta_T race propagating through bandit reward → confirmed below by spot-check (2 delta_T flips in first 93 muts of V2). |
| **B11** B4 / B9 | PASS | **PASS** | Trusted; within-run consistency holds. |
| **B11** B1 strict verifier | NOT RUN | **In progress on coinbase** | Composer started it correctly via `run_inc4_b1_verify_pos.sh all`. Expect PASS given B4/B9 clean and pre-divergence reward identity. |
| **B12** A3 | PASS | **PASS** | Input-invariant trace (48 arms) confirmed. |
| **B12** A5 | FAIL | **WAIVED (doc drift)** | Composer's diagnosis is correct — A5 fails on baseline `--in1 5` too. Fix in Inc 5 (refresh EXPECTED_ARMS.md). |
| **B12** B4 / B9 | PASS | **PASS** | Trusted. |
| **B12** B1 strict verifier | IN PROGRESS | **In progress on coinbase** | Composer's queue. |

**If B1 verify lands clean → declare GREEN, proceed to Inc 5 (E5 evidence pack).**

---

## Adjudications in detail

### 1. B8 — 89s parallel-start spread → PASS

**Gate:** Work order §B8 said `parallel jobs must start within 60s`. Observed: **89s** (meld 06:50:21 → polynize 06:51:50).

**Why the gate was wrong:** It was set without knowing that `dispatch_pos.py` runs `pos.nodes.reset(n, blocking=True)` **sequentially per node** (3 min each in worst case) before launching anything. The actual job-launch loop with `queued=True` is fast (~5 sec), but the per-node bundle copy + extract await happens after sequential resets, producing per-node spread that scales with node count and reset variance.

**What actually matters for isolation:**
- Did jobs run on **distinct** nodes? **YES** — algofi, meld, octorand, opulous, polynize (5 nodes, no overlap).
- Did concurrent variants share mutable state? **NO** — the 5/5 zero core-diff result IS the isolation evidence.
- Is 89s within "concurrent" semantics for this testbed? **YES** — even at 89s spread, all 5 jobs ran within the same wall-time window (each variant runs ~25 min, so overlap = ~24 min).

**Action items:**
- Update §B8 gate in next work order: `parallel jobs must run on distinct nodes AND start within 300s of each other`.
- Add anti-pattern §12.46 (or extend §12.36) describing dispatch_pos's sequential-reset bottleneck.

### 2. B8 — `compressed_global_coverage` row diffs → INFO (not a failure)

Per work-order watch-out: "compressed coverage blobs may differ in row order or compression even when content matches." Row counts match between seq and par (19, 22, 28, 35 etc.); blob bytes differ. Composer correctly excluded this from the isolation gate.

**No action needed.** Optionally add to E5: a check that the **decoded coverage cell-counts** (not raw blobs) match seq vs par, to give an apples-to-apples result.

### 3. B11 — prefix divergence → EXPECTED ARCHITECTURAL PROPERTY

This is the most consequential finding in Composer's report. I spot-checked V2 (octorand, `kindUCB_zoned_v1`) and confirmed the mechanism precisely:

**Spot-check evidence (Opus, 2026-06-13):**
```
INC3 V2 (N=200) vs INC4 V2 (N=500) prefix
─────────────────────────────────────────
First divergence at:           mutation #94
Mutations[1..93] kind/step/txn/val:  IDENTICAL (0 diffs)
  ↳ confirms host binary chose same mutations deterministically
Mutations[1..93] num_failures:       IDENTICAL (0 diffs)
Mutations[1..93] verifier_accepted:  IDENTICAL (0 diffs)
  ↳ confirms host binary's per-mutation outcomes are deterministic

mutation_rewards[1..93]:
  delta_T mismatches:   2 / 93  ← Poseidon2 race (~2% rate, consistent with Inc3 ~0.7-1%)
    #70: INC3 dT=0 → INC4 dT=1   (race-induced flip)
    #91: INC3 dT=1 → INC4 dT=0   (race-induced flip)
  reward float diffs:   5 / 93  ← downstream of dT flips

By mut #94 the UCB posterior had drifted enough to choose a different arm.
From #94 onward, divergence cascades through bandit path.
```

**This is the Inc 3 Poseidon2 race (B7 closure) doing exactly what we predicted it would do in bandit-driven runs:**
- delta_T values fluctuate stochastically (~1-2% of rows flip 0 ↔ small int).
- delta_T enters the reward function (Q_loc, Q_rep, T_new).
- Reward perturbations accumulate in UCB / Thompson Sampling posteriors.
- Posterior drift eventually changes arm ranking → divergent path from that mutation forward.

**Why V1 has 0 prefix diffs:** V1 (`zoned`) is *uniform-over-zones*, not bandit-driven. Same seed + same input universe → identical mutation sequence regardless of reward noise.

**Why V4 has only 5/200:** V4 is `kindTS_zoned_v2` (Thompson Sampling). TS smooths reward estimates more heavily than UCB; it took longer for the posterior to flip an arm decision. (It also ran on meld, a different uarch, so its `delta_T` flip pattern might genuinely differ from the others, but the small diff count argues the within-strategy robustness story is the dominant factor.)

**Why V2 / V3 / V5 diverge progressively more:** Stronger contextual signals (UCB-with-zone, semantic gating) amplify small reward noise into bigger posterior shifts.

**Why this is NOT a regression:**
- B4 (6-tuple agreement, internal) **PASSES** for all 5 variants.
- B9 (schema/FK/row count) **PASSES** for all 5 variants.
- The host binary produces deterministic outcomes for identical mutations (the 93-row identity above).
- The divergence is in the *bandit's exploration trajectory* under documented noise — exactly what the framework is designed to tolerate.

**Implications for Phase 8 / production:**
- N-large bandit runs are NOT byte-reproducible across repeated runs with same seed.
- Aggregate metrics (cell-counts hit, faults found, arm-coverage) ARE preserved within 0.5-7.5% TVD for kind-level strategies and ~24% TVD for V5's 48-arm fine grain (see RACE_FINDING_AND_OPEN_QUESTIONS.md §12 for the full per-variant breakdown).
- **No new doc needed** — the observed consequences have been appended as §12 of the existing `a4/docs/cloud1/RACE_FINDING_AND_OPEN_QUESTIONS.md` (the canonical race writeup for Pro), with a new sub-question extending §9 Q1.

**Action items:**
- Pending: B1 strict verifier on the N=500 DBs (currently running on coinbase via Composer's `dispatch_b1_verify_pos`). Expectation: PASS — the host binary's per-mutation behavior is deterministic, so each proof should verify.
- If B1 passes: change B11 verdict to PASS-WITH-CAVEAT and remove the prefix-strict-match gate from future work orders. Replace with a weaker "V1 deterministic prefix matches; bandit variants documented as non-reproducible under Poseidon2 race."
- Inc 5 doc deliverable: short writeup of "what is and isn't reproducible" with this evidence.

### 4. B12 — A5 EXPECTED_ARMS.md drift → WAIVED for Inc 4; fix in Inc 5

Composer's diagnosis is correct:
- A3 (live arm enumeration) PASSES for both `--in1 1 --in4 1` and `--in1 100 --in4 100`: 48 arms, identical to baseline universe.
- A5 (live ↔ doc cross-check) FAILS because EXPECTED_ARMS.md lists `core_div` but the live universe has `core_shr`. Also fails on the *baseline* `--in1 5 --in4 10` today.
- The doc drift predates Inc 4 — A3 is the source of truth for "are we hitting the same arms?", and it's clean.

**Action items:**
- Inc 5 backlog: `Refresh a4/audits/audit_output/EXPECTED_ARMS.md baseline table (core_shr, current step-count tolerances)`. Re-run A5 against refreshed doc and confirm PASS.
- Optional: weaken A5 in Composer's audit scripts to flag drift as `INFO` not `FAIL` when A3 passes (since A3 is canonical).

### 5. B1 strict verifier — in progress on coinbase

Composer correctly punted the WSL B1 run (2500 mutations × strict verify ≈ 6+ hrs) and is running on coinbase instead via:
```bash
bash a4/pos/run_inc4_b1_verify_pos.sh all ivgreiff_260613_100352_926884
```

Status (2026-06-13 18:00 UTC): On B12 `in1_1_in4_1` (1/3); nodes booting (algofi reset 95s in). ETA ~60–90 min for all three campaigns.

**Expected outcome:** PASS for all 3 campaigns. Rationale:
- B4 (6-tuple internal consistency) passed for every DB → every mutation's `num_failures` & `verifier_accepted` are internally consistent with the recorded mutation.
- The Poseidon2 race only affects `delta_T` (touch coverage), not proof-acceptance outcomes.
- Per-mutation determinism was confirmed in the V2 spot-check above (93/93 rows agree on `num_failures` + `verifier_accepted`).

**Composer's `dispatch_b1_verify_pos.py` is well-written** — clean adapter over `dispatch_pos`, one-variant-per-node, supports allocation reuse. No issues found in inspection. Suggest folding it (or its single-shard form) into `dispatch_pos.py` as a `--verify` mode in Inc 5 rather than keeping a separate file long-term, but no need to refactor now.

---

## What Composer did well

1. **Cleanly separated the resolve_variant_dbs bug** from the data: `*zoned*` substring would silently grab the wrong DB for `kindUCB_zoned_v1` if naïvely globbed. The new `_{selector}_seed` regex is the right fix. Composer noticed this before me; well caught.
2. **rsynced ALL artifacts** including the Inc3 N=200 baseline for prefix check. Made my spot-check reproducible.
3. **Did not falsely promote B11 / B12 to PASS.** Held the line at NEEDS-OPUS pending B1. Good audit discipline.
4. **Wrote a real report with evidence**, not just verdicts. Cited row counts, divergence indices, and the specific failure mode for each gate.
5. **Did NOT push code commits** without approval (per workspace rules).

## What needs handoff back to user / Composer

1. **WAIT for B1 verify on coinbase to complete** (~17:57 → ~19:00 UTC). Composer should re-run B11/B12 audit scripts once verifier_pass column is populated and update the audit JSONs in place.
2. **POS cleanup once B1 done:**
   - `pos allocations free -k ivgreiff_260613_100352_926884` (KEEP-CALENDAR flag essential per §12.43)
   - Then free calendar entries 1747 and 1748:
     - `pos calendar list | grep ivgreiff` to find the IDs
     - `pos calendar free <id>` (or whatever the right verb is — check `pos calendar --help`; if not, just let them expire at 19:53 UTC)
3. **Commit pending** (per todo t8): templates `dispatch_audit.sh`, `run_inc4_all.sh`, `dispatch_b1_verify_pos.py`, `run_inc4_b1_verify_pos.sh`; playbook updates §12.42-§12.45 + new "★ CANONICAL DISPATCH TEMPLATES" header section; audit JSONs; report + this review; `audit_common.py` `rglob` fix.
4. **Inc 5 backlog items** (do NOT do in Inc 4):
   - Refresh EXPECTED_ARMS.md
   - (Done in this session) Aggregate-impact analysis appended to `RACE_FINDING_AND_OPEN_QUESTIONS.md §12` — bandit-prefix divergence story is now documented in the canonical race doc, not a separate file.
   - Optional: revise B8 timestamp gate to 300s; weaken A5 to INFO when A3 passes
   - Optional: fold `dispatch_b1_verify_pos.py` into `dispatch_pos.py --verify`

---

## Final answers to Composer's explicit asks

| Composer question | Opus answer |
|---|---|
| **B8 89s vs 60s gate — adjudicate?** | PASS the run. The 60s gate was unrealistic for POS sequential reset. Distinct-nodes + zero-core-diff = isolation confirmed. New default gate: 300s. |
| **B11 prefix drift — binary parity? FP race?** | **FP race (Poseidon2 delta_T) propagating through bandit reward.** Confirmed by spot-check (2 delta_T flips in first 93 muts of V2 → posterior drift → divergent arm at #94). Binary is identical (same `6873e588…` SHA on both runs). **No regression.** |
| **B11 B1 verifier — run on coinbase or WSL overnight?** | Coinbase (already running via Composer's script). |
| **B12 A5 — refresh or waive?** | Waive for Inc 4 (drift pre-dates this audit; A3 is canonical). Refresh in Inc 5. |
| **B12 B1 — await Composer or re-run locally?** | Await Composer (coinbase). |
| **Calendar cleanup** | After B1 verify completes: `pos allocations free -k <alloc>`, then `pos calendar free 1747` and `1748` (or let them expire at 19:53 UTC). |
