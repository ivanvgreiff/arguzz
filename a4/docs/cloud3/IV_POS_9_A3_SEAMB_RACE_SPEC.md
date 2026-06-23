# IV.POS.9 — Spec A3 (first instance): the A4-findable-bug RACE on POS (Seam-B / VerifyOpcode)

**Version:** v0.1 — DRAFT for Ivan + separate-Opus review · **Date:** 2026-06-23 · **Author:** Opus (OCP).
**Track:** A (known-bug detection race — the security claim). **Governing:** `ProG_Report_5.md` §3; `New_Master.md` (cloud3) §L4/L9/L11/L13/L14, gates G10–G13.
**This spec establishes the REUSABLE race harness** (campaign config + bug oracle + markers + POS dispatch + unit tests + a new `verifyopcode` fingerprint profile) and runs its **FIRST campaign**: the four variants racing to find the **certified A4-findable VerifyOpcode underconstraint** (`AP_SEAMB_RESULT.md`). The `rs1==rs2` CVE race (needs A1+A2) reuses this harness later.

> **Why this campaign first (Ivan's call):** we have a *certified* A4-findable bug now (Seam-B). Racing the 4 variants on it (a) **validates the race harness on a bug whose answer we know** (A4 must find it; we have 12 certified finds), and (b) produces the **A4 side of the complementarity claim** — does even pure Arguzz (`V6_uniform`) find an A4-surface bug? (Hypothesis: **no**.) This runs on POS while the `rs1==rs2` arm (A1/A2) is built.

---

## 0. Scope, non-goals, and the headline question

**Headline question.** On a binary whose ONLY planted soundness hole is the removed `VerifyOpcode*` decode-equality, **which of the four variants discover it, how often, and at what mutation count?**

**Variants** (`a4/standalone/variants.py`): `V5_control` (a4), `V6_uniform` (arguzz), `V6_cTS` (arguzz), `Hybrid_cTS` (hybrid). All four race. **No stop-on-first-bug** — every campaign runs the full N; we record *each* find and its mutation index.

**Expected result (the hypothesis we are TESTING, not assuming):** the A4-surface variants (`V5_control`, `Hybrid_cTS`) apply `INSTR_TYPE_MOD` → trigger the hole → find it (fast, repeatedly); the pure-Arguzz variants (`V6_uniform`, `V6_cTS`) do **not** apply `INSTR_TYPE_MOD` and so **never** find it. Confirming this is the complementarity evidence. **The campaign must be able to falsify it** (if `V6_uniform` finds it, that is a real and important result).

**Non-goals.** Not the `rs1==rs2` CVE race (that's A1/A2/later). Not a coverage sweep (Track B, separate OCP). No claim that "MAB beats Arguzz" — this is a complementarity/findability measurement.

### 0.1 Empirically validated this session (live, on the actual binaries)
- **The campaign runs on the holed binary** and records per mutation `kind`, `verifier_accepted`, and a **replayable `config_json`** (A4_MUTATION_CONFIG-compatible). Confirmed via a real `V5_control` (cTS_semantic_v2) run, N=12.
- **Per-mutation cost ≈ 30 s** (full prove+verify, `ProverOpts::fast`, `CONSTRAINT_CONTINUE=1`). N=12 took 6:20 incl. one-time inspection. **This sets the budget** (§5).
- **Raw `verifier_accepted` is NOISY → the control-reject discriminator is MANDATORY.** In the N=12 run, `cTS` applied `COMP_OUT_MOD` (0/4 accept) and `CYCLE_DIFF_COUNT_MOD` (**8/8 accept**) — and a sampled `CYCLE_DIFF_COUNT_MOD` accept **also verifies on the control** (benign; accepts on both). So a naive "verifier_accepted ⇒ bug" would massively over-count. The §2 oracle (holed-accept **∧** control-reject@VerifyOpcode) is exactly what excludes these. *(This is the empirical justification for the whole oracle design.)*
- **The cTS selector explores many kinds; INSTR_TYPE_MOD is not necessarily early.** None of the first 12 were INSTR_TYPE_MOD. So the bug's `first_find_idx` is "when the selector first lands an INSTR_TYPE_MOD that hits the hole" — precisely the speed signal we measure (and why we run a real N, not a hand-picked config).

---

## 1. Binaries, guest, and the contamination guardrail (HARD)

| role | path | fingerprint (must assert) |
|---|---|---|
| **bug binary** (race target) | `a4/builds/ap_seamb/bench-verifyopcode/risc0-host` | `planted_bug=verifyopcode`, `load_rs2_present=1`, head `93bda33b`, guest_image_id = Seam-B guest |
| **control** (oracle ground-truth) | `a4/builds/ap_seamb/control/risc0-host` | `planted_bug=none`, `load_rs2_present=1`, same head + guest |

- **Guest:** the Seam-B minimal ALU guest (944 AddI cycles; `workspace/output-seamb/methods/guest/src/main.rs`). Host args `--ctrl 7 --gseed 12345 --rounds 5`. (Contextual/decoy guest is a later refinement; the minimal guest gives the cleanest first signal.)
- **New fingerprint profile** — add to `a4/pos/fingerprint_guard.py` `PROFILES`:
  ```python
  "verifyopcode": {"load_rs2_present": 1, "planted_bug": "verifyopcode"},
  ```
- **CONTAMINATION GUARDRAIL (Ivan-mandated, L14/G10–G13):** every race job is **guard-prefixed** — `python -m a4.pos.fingerprint_guard <host> --profile verifyopcode` must exit 0 *before* the campaign runs; a nonzero exit **aborts the job** and is recorded. The control binary FAILS the `verifyopcode` profile (planted_bug=none) — so a misbundled binary cannot be silently raced. The bundle's `host_sha256` is asserted == the archived holed binary's sha (`prepare_bundle.sh`). The fingerprint is recorded into every run DB row. **No race run is trusted on faith.**

---

## 2. The bug oracle — "a variant found the planted bug"

A mutation is a **confirmed find** iff, on the **bug binary**, the prover+verifier **accept** a proof of a trace that **genuinely violates the decode binding**, AND the **control** binary **rejects** that identical mutation at `VerifyOpcode`. Concretely, three conditions:

1. **Applied & decode-divergent.** The mutation genuinely changed the instruction-type field (`INSTR_TYPE_MOD` with `mutated (major,minor) ≠ original`; `MutationOutcome.APPLIED`, not a skip/no-op). For non-INSTR_TYPE_MOD mutations, "decode-divergent" is defined by the control-reject locus (below).
2. **Bug binary ACCEPTS.** `verifier_accepted == True` on the holed binary (`fuzzer.py:_check_verifier_acceptance`; real prove+verify, `CONSTRAINT_CONTINUE` OFF).
3. **Control REJECTS at `VerifyOpcode`** (ground truth). Re-running the *identical recorded mutation config* on the control binary fails verify with a `VerifyOpcode*` constraint (`inst.zir:102/103/104`).

**No-op exclusion (critical for a clean denominator):** a mutation that accepts on the control too (type unchanged / no valid target / result identical AND decode identical) is **not** a find. The control-reject (condition 3) is exactly the discriminator and is the authority — it rules out the "trivially-verifies" mirage that sank the `(0,1,0)` screening.

**Cost-bounded implementation.** The hot-loop campaign runs only on the **bug binary** and records, per mutation: `verifier_accepted`, `mutation_type`, original & mutated `(major,minor)`, the full replayable config, and the mutation index. **Post-hoc**, the harness re-runs **only the accepted-and-decode-divergent** mutations on the control binary to confirm condition 3 and classify each as `planted_bug_find` / `noop` / `other_soundness`. (Accepts are a minority; for the Arguzz variants they should be ~0, so this is cheap.) Optional fast-path: an `INSTR_TYPE_MOD` accept with `mutated≠original` is a planted find by construction (control-reject at VerifyOpcode is guaranteed — verified for all 12+44 in `AP_SEAMB_RESULT.md`), so control re-run there is a *spot-check*, not per-find.

---

## 3. Markers — how we judge variant performance (the deliverable metrics)

Recorded per mutation (already in `coverage_db.mutations`): `id` (the mutation **index**, 1..N), `mutation_type`, `verifier_accepted`, config. Derived per **(variant, seed)**:

| marker | definition |
|---|---|
| `found` | ≥1 confirmed planted find in N |
| `first_find_idx` | mutation index of the **first** confirmed find; **censored = N+1** if not found |
| `n_finds` | count of confirmed planted finds in N |
| `n_applied` | mutations genuinely applied (fair denominator; excludes skips/no-ops) |
| `find_density` | `n_finds / n_applied` |
| `find_kinds` | histogram of `mutation_type` among finds (expect: all `INSTR_TYPE_MOD`) |

Aggregated per **variant** across ≥10 paired seeds (same seed set across all 4 variants — pairing controls the RNG):

- **`P(found)`** — fraction of seeds with a find (headline: A4≈1.0, Arguzz≈0).
- **First-find distribution** — median / IQR / min / max of `first_find_idx`, and the **discovery CDF** (Kaplan–Meier-style "mutations-to-first-find" curve per variant; ProG §3).
- **Mean `find_density`** and **`n_applied`** per variant.
- **`find_kinds` rollup** — confirms the bug is found via `INSTR_TYPE_MOD` (the expected mechanism), and that Arguzz variants applied **zero** `INSTR_TYPE_MOD` (explaining their 0 finds) — or surfaces a surprise.

**Censoring is reported, never imputed:** variants that don't find it in N are "not found in N (censored)". All raw per-mutation rows are retained for re-analysis.

---

## 4. Campaign driver (reuse) + what's new

**Reuse as-is:** the variant launchers (`variants.py::variant_launch_command` → `cli.py fuzz` for V5/V6_cTS/Hybrid, `v6_uniform_driver` for V6_uniform), the per-mutation record + `verifier_accepted` (`fuzzer.py:536-537`), `coverage_db`. **Each variant already does a full prove+verify per mutation against the host binary** — so pointing `--host` at the holed binary makes `verifier_accepted` reflect the holed verdict. No driver changes needed for the hot loop.

**New (small, well-tested) code:**
- `a4/pos/fingerprint_guard.py` — add `verifyopcode` profile.
- `a4/runs/iv_pos_9/race/oracle.py` — the post-hoc confirmation + classification (§2) reading a run DB, replaying accepts on control.
- `a4/runs/iv_pos_9/race/markers.py` — the §3 marker extraction (per-(variant,seed) + per-variant aggregate + discovery CDF) → `race_markers.json` + per-variant CSVs.
- `a4/pos/generate_race_manifests.py` — clone of `generate_d2f_manifests.py`; emits (variant × seed × N) jobs, **host = holed binary**, **guard-prefixed with `--profile verifyopcode`**, run-id `pos_iv_pos_9_a3seamb_<variant>_seed<seed>_n<N>`.

---

## 5. Budgets (ProG L9, adapted — NO stop-on-first-bug)

| stage | scope | where | gate |
|---|---|---|---|
| **A3.S0 — deterministic ground truth** | the 12 certified finds + a no-op + a result-changing reject, replayed through the **oracle** | local | oracle returns exactly: 12 `planted_bug_find`, no-op→not-a-find, result-changer→not-an-accept. **Negative control:** a short campaign on the *control* binary yields **0** finds. |
| **A3.S1 — smoke** | 4 variants × 3 paired seeds × **N=2000** | POS (small) | all 12 DBs complete with the **verifyopcode** fingerprint; markers extract cleanly; **A4 variants find it, Arguzz variants' `INSTR_TYPE_MOD` count = 0**; pipeline end-to-end validated before scaling |
| **A3.S2 — thesis** | 4 variants × **≥10 paired seeds** × **N=5000** (extend censored-but-interesting to N=10000) | POS (full) | full markers + discovery CDFs; `race_markers.json` + CSVs; per-job fingerprint recorded |

Run full N at every stage (record all finds + indices). **Local = Stage-0 + unit tests only; all full campaigns run on POS** (parallelized across the node pool).

**POS cost model (grounded in the measured ≈30 s/mutation, full prove+verify):**
- per job ≈ `N × 30 s` + ~1 min setup → **N=2000 ≈ 17 h/job**, N=5000 ≈ 42 h/job, N=1000 ≈ 8.5 h/job.
- wall-clock ≈ `ceil(jobs / nodes) × per-job` (round-robin, `DEFAULT_NODES`=8 EPYC).
- **A3.S1** (12 jobs, N=2000): `ceil(12/8)=2` waves × 17 h ≈ **~1.5 days**.
- **A3.S2** (40 jobs, N=2000): `ceil(40/8)=5` waves × 17 h ≈ **~3.5 days**. At N=5000 ≈ ~9 days.

**Recommendation:** N=2000 for the first thesis run (≈5 days total for S1+S2 on 8 nodes) — enough to capture A4's `first_find_idx` + density and to confidently establish Arguzz=0 (pure-Arguzz applies **zero** INSTR_TYPE_MOD, so even N=1000 settles it). Extend to N=5000 only for variants/seeds where it changes a conclusion, or if more nodes are available. *(Optimization for later, NOT this run: a witgen+global-residue "would-verify" check (`CONSTRAINT_CONTINUE`+`A4_GLOBAL_RESIDUE`, no STARK) is ~5–6× cheaper and faithful for this decode bug since it checks local **and** global; it must be cross-validated against the full-prove result before being trusted — deferred to keep this first campaign maximally certain.)*

---

## 6. Unit tests (MUST pass before A3.S1 dispatch — the certainty layer)

Implemented under `a4/runs/iv_pos_9/race/tests/` (pytest), each fast + deterministic:

1. **`test_fingerprint_profile`** — `assert_fingerprint(holed, **verifyopcode)` → PASS; `assert_fingerprint(control, **verifyopcode)` → FAIL (planted_bug mismatch); a sweep/vuln fingerprint → FAIL. (Contamination guard works both ways.)
2. **`test_oracle_confirmed_find`** — feed the oracle a recorded `INSTR_TYPE_MOD` accept from the 12 (e.g. `s1091 AddI→Sub`): classified `planted_bug_find` (control rejects @ VerifyOpcode).
3. **`test_oracle_noop_excluded`** — a type-unchanged / no-target mutation (accepts on control too) → **not** a find.
4. **`test_oracle_result_changer`** — `AddI→And` (rejected on holed at MemoryWrite) → not an accept → not a find (scope intact).
5. **`test_markers_extraction`** — a synthetic DB with finds at known indices → correct `first_find_idx`, `n_finds`, `find_density`, censoring (=N+1 when none).
6. **`test_markers_discovery_cdf`** — synthetic multi-seed → correct per-variant CDF + median.
7. **`test_manifest_generator`** — emits the right job count (variants×seeds), each with the **holed** host path, a `verifyopcode` guard prefix, and a unique run-id; no control binary referenced as a race target.
8. **`test_variant_launch_cmds`** — all 4 variants produce a valid argv (`--host` holed, `--db`, `--seed`, `--num`); driver vs cli launcher correct.
9. **`test_noop_denominator`** — `n_applied` excludes skips (the fair denominator).
10. **`test_ground_truth_s0`** (integration, gated on binaries present) — replays the 12 + negative-control through the full oracle→markers path → 12 finds on holed, 0 on control.

**Gate G-UT:** all unit tests green AND A3.S0 ground-truth green ⇒ A3.S1 may dispatch.

---

## 7. Correctness gates (POS-time protection — all BLOCKING)

| gate | check |
|---|---|
| **G-UT** | §6 unit tests + A3.S0 ground truth green |
| **G-FP** (per job) | `fingerprint_guard --profile verifyopcode` exit 0 before the campaign; recorded into the DB; nonzero ⇒ abort job |
| **G-BUNDLE** | bundle `host_sha256` == archived holed binary sha; guard embedded in `run_campaign_pos.sh` wrapper |
| **G-NEG** | a control-binary campaign (a few seeds) yields 0 confirmed finds — the harness does not false-positive |
| **G-SMOKE** | A3.S1 DBs complete; markers extract; A4 variants find, Arguzz `INSTR_TYPE_MOD` count = 0; verified before A3.S2 |
| **G-REPRO** | every find's mutation config is replayable (control re-run reproduces the accept/reject) |

---

## 8. Batches

- **A3.1 — harness + unit tests + ground truth (A3.S0).** Add `verifyopcode` profile; write `oracle.py`, `markers.py`, `generate_race_manifests.py`, the wrapper that embeds the guard into `run_campaign_pos.sh`; all §6 unit tests + A3.S0. *Gate: G-UT, G-NEG.* (Local; no POS.)
- **A3.2 — smoke (A3.S1).** Bundle the holed binary; dispatch 4×3×2000 to POS; extract markers; confirm G-SMOKE. *Gate: G-FP, G-BUNDLE, G-SMOKE.*
- **A3.3 — thesis (A3.S2).** Dispatch 4×≥10×5000 (extend censored to 10000); full markers + discovery CDFs. *Gate: G-REPRO; all DBs fingerprinted.*
- **A3.4 — analysis + writeup.** `race_markers.json` + per-variant CSVs + discovery-CDF plot + a results doc (P(found), first-find, density, find-kinds; the complementarity verdict). Feeds the thesis Track-A "A4 side."

---

## 9. Risks & mitigations

| risk | mitigation |
|---|---|
| A4 variant's selector doesn't actually pick `INSTR_TYPE_MOD` (cTS down-weights it) → no finds | G-SMOKE checks per-variant `find_kinds` + `INSTR_TYPE_MOD` application count; if a variant applies it but cTS rarely schedules it, that's a *real* finding about the scheduler (report it), not a harness bug |
| Hybrid's A4-kind subset excludes `INSTR_TYPE_MOD` | confirm the hybrid kind set in A3.1 (read the selector); if excluded, note it — Hybrid then finds it only via its A4 kinds that ARE included |
| Wrong binary bundled → race on clean/sweep binary finds nothing | G-FP + G-BUNDLE (the `verifyopcode` profile fails on any other binary) |
| No-op accepts inflate finds | §2 control-reject discriminator + `test_oracle_noop_excluded` |
| POS cost of control re-runs | only accepted+decode-divergent mutations re-run on control; Arguzz accepts ≈ 0 |
| Minimal guest too easy (A4 finds at idx≈1, no spread) | acceptable for the findability/complementarity claim; if a *speed* spread is wanted, add the contextual decoy guest (later) |

## 10. Reuse for the `rs1==rs2` CVE race (later)
Same harness, swapped inputs: bug binary = the A1 vulnerable build (`98387806`, `--profile race`); guest = the A2 `rs1==rs2` race guests; oracle ground-truth = the strong journal oracle (accept + wrong committed output) + trace-soundness (L4). The markers, dispatch, unit-test scaffolding, and gates carry over unchanged. **Expected mirror result:** Arguzz/Hybrid find the CVE; pure A4 does not (the value/memory bug is permutation-bound — `AP_SEAMB_OPTION_B_ANALYSIS.md`). The two races together = the full complementarity table.
