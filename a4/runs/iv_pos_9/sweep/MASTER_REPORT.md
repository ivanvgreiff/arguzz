# IV.POS.9 Track-B — Multi-Guest Coverage Sweep: MASTER REPORT

**Living document.** Headline findings up top; an accumulating **Investigated-Questions ledger**
(each question → grounded answer → evidence pointer) in the middle; raw **evidence appendix** at the bottom.
Every claim is grounded in the run DBs, not in design intent. Update this as the campaign progresses.

- **Campaign:** 3 new guests (g1 control, g2 memory, g3 accelerator) + g0 sha2 baseline (reused, D2.F N=10000 truncated to 5000) × 4 variants × 3 seeds × N=5000.
- **Variants / methods:** `V5_control` = **A4** cTS (post-execution trace-cell mutation, selector `cTS_semantic_v2`, 78 arms); `V6_uniform` = **Arguzz** uniform (during-execution fault injection, `arguzz_invoke`); `V6_cTS` = **Arguzz** cTS (`v6_cTS`, 415 arms); `Hybrid_cTS` = A4+Arguzz blend (~250 arms).
- **Status (this revision):** batch 1 complete — **g1 (all 4 variants) + g0 baseline** analyzed at seed 1234. g2/g3 mid-campaign (batch 2+). Per-guest coverage curves: `notebooks/sweep_coverage_curves.{ipynb,html}`.
- **Coverage curves convention:** one figure per guest, 4 variants overlaid (local + CGC). The rigorous generalization read is **within-variant across guests** (same variant on g0 vs g1/g2/g3); cross-variant comparison is confounded by different selectors/extractors.

---

## 1. Headline findings (as of batch 1: g0 + g1, seed 1234)

- **F1 — Local constraint-loc territory is guest-INVARIANT.** g1 (control-heavy) and g0 (sha2) cover ~95% the *same* local locs (±0–2 of ~33–48 per variant; see §A4). The circuit's local-loc set is small and saturated by the runtime + the A4 mutation surface, so a control guest does **not** add local territory. → **Local-loc coverage is not a discriminating axis between guests**; the down-select (B3.2) should lean on CGC + candidate distribution.
- **F2 — CGC breadth and the benign-candidate surface ARE strongly guest-dependent.** g1·V5 produced **1534 accepted (benign) mutations vs g0·V5's 0** — dominated by cycle/memory-permutation metadata kinds (`TXN_PREV_WORD/CYCLE_DIFF/PREV_CYCLE`). The control guest exposes a huge don't-care surface that sha2 lacks.
- **F3 — The A4-local / Arguzz-global orthogonality holds and is mechanistically grounded.** A4 (V5/Hybrid) reaches more *local* locs (46–48 vs 33–35); Arguzz (V6) reaches far more *global* CGC contexts (440–598 vs 184). The cause is the fault timing — see Q2/Q3.
- **F4 — Zero real soundness violations** on any variant/guest: every accepted mutation has `num_failures=0` (no constraint actually broke). Correct for clean binaries (load_rs2=1, planted_bug=none). Bug-finding is Track A's job; this is a coverage-generalization run.
- **F5 — Per-mutation proving cost ~3.2–4.1 s** on the Intel sweep nodes (these run faster than the playbook's old Tier-C estimate). Local coverage saturates by ~mut 2000; CGC still climbing at 5000 (last new context @4873) → N=10000 would add ~0 local, ~15–25% more CGC (diminishing).
- **F6 — Arguzz's global-failure behavior is strongly BIMODAL: it either *bypasses* the global layer (0 failures) or *destroys* it (a flood).** Of 4769 applied Arguzz mutations (g1·V6_uniform): **32% produce 0 global failures (bypass)**, **53% produce 10+ (destroy)**, only 15% in between. The split is by *what is corrupted*: **value-output** kinds (LOAD/STORE/COMP) are caught (if at all) by one *local* per-row constraint and never enter the global arguments → **bypass (E[#global]≈0)**; **machine-STATE** kinds (PRE/POST_EXEC_MEM/REG) propagate through downstream cycles → the global memory-permutation + cycle-lookup arguments register many distinct inconsistencies → **destroy (E[#global]≈12–13)**. A4 lives almost entirely in the local/bypass regime. **This is the expected-value story behind Q2/Q3** (A4 E[#global|fire]=3.0 vs Arguzz 9.8–10.7). Worked proof — two replayed injections with full trace + broken-constraint tables — in **`EVIDENCE_arguzz_bypass_vs_destroy.md`**.

---

## 2. Investigated-Questions ledger

### Q1 — At what point (out of 5000 mutations) does adaptive scheduling turn on, for each guest?

**Answer (from `bandit_decisions.mode`, first row with `mode != 'cold'`):**

| variant (method) | arms | cold-start pulls | **adaptive ON @ mutation** | guest-dependent? |
|---|---|---|---|---|
| V5_control (A4) · g0 sha2 | 78 | 234 | **235** | no |
| V5_control (A4) · g1 control | 78 | 234 | **235** | no — identical |
| V6_cTS (Arguzz) · g0 sha2 | 415 | 1370 | **1371** | yes |
| V6_cTS (Arguzz) · g1 control | 415 | 1303 | **1304** | yes |
| Hybrid_cTS · g0 sha2 | ~258 | 806 | **807** | yes |
| Hybrid_cTS · g1 control | ~249 | 775 | **776** | yes |
| V6_uniform | n/a | n/a | never (uniform — no bandit) | — |

**Why:** cold-start does a fixed **3 pulls per arm** before any reward-driven (Thompson) selection.
- **A4 turns on at mut 235 on *both* guests** because its arm space (78 = mutation-kind × semantic-zone) is fully enumerable up front → cold-start = 3×78 = 234 regardless of guest.
- **Arguzz turns on ~1300–1370** (and is guest-dependent) because it has **415 arms** (during-execution loci = cycle × kind) discovered *progressively* as execution reveals them, so the cold phase is ~5× longer and depends on the guest's execution.
- **Caveat:** the `ConstantFloor 0.55` keeps exploration high *after* adaptive turns on. For V5, post-cold modes were floor 3707 / adaptive 1045 / singleton 14 → reward-driven "adaptive" (exploit) is only **~22%** of pulls; ~78% remain uniform-floor exploration throughout. So "adaptive on" marks where exploitation *begins*, not where it dominates.

*Evidence: Appendix A.*

---

### Q2 — Why do during-execution (Arguzz) mutations win on CGC over post-execution (A4) mutations?

**Answer:** because each *during-execution* fault **propagates forward** through the remaining
execution and touches ~3× more global-coverage contexts per mutation, whereas a *post-execution*
mutation is a point-corruption of a finalized cell with no forward execution left to carry it.

Grounded numbers (g1, N=5000):

| variant | type | CGC (final) | **mean global-failures / mutation** | distinct cycle-phases / addr-regions | arms |
|---|---|---|---|---|---|
| V5_control | A4 (post-exec) | 184 | **3.0** | 3 / 10 | 78 |
| V6_uniform | Arguzz (during-exec) | 440 | **10.7** | 3 / 9 | — |
| V6_cTS | Arguzz (during-exec) | 598 | **9.8** | 3 / 10 | 415 |
| Hybrid_cTS | blend | 330 | 5.5 | 3 / 10 | ~250 |

Three grounded points:
1. **It's a footprint effect, not a reach effect.** All variants span the *same* breadth (3 cycle-phases, ~10 address-regions); the difference is **density** — Arguzz touches ~3.3× more distinct contexts *per mutation*, and roughly the same number of mutations fire any global failure (3242 vs 3089). So it's not that more mutations fire; each Arguzz fault fires *wider*.
2. **The cause is fault timing.** Arguzz injects mid-execution → the corrupted value flows into every subsequent cycle that consumes it → those downstream cycle/memory/lookup constraints all register as distinct CGC contexts. A4 rewrites a finalized cell after execution → only that cell's immediate row/lookup constraints register → narrow footprint.
3. **Larger locus space too.** Arguzz exposes 415 injection arms (cycle × kind) vs A4's 78, feeding more (producer_kind, locus) combinations into the CGC context space.

**Holds on both guests** (g0 baseline: Arguzz CGC 428/560 vs A4 337) → architectural property, not a g1 artifact. This *is* the Arguzz-global half of the A4-local/Arguzz-global orthogonality.

*Evidence: Appendix B.*

---

### Q3 — A4 almost always co-fires a global failure whenever it has a local failure (P≈1, except INSTR_TYPE_MOD). Doesn't that mean A4 fails *more* global constraints and should get *more* CGC? Why doesn't it?

**Answer: no — `P(global | local)` measures *reliability* (does ≥1 global fire), not *volume* or *diversity*.** The observation is correct but the inference doesn't follow. A4 co-fires global **reliably but narrowly**; Arguzz co-fires **slightly less reliably but ~3× more widely**, and CGC counts *distinct contexts*, so Arguzz wins.

Grounded numbers (g1, conditional on a failure):

| method | P(global\|local), aggregate | **E[#global \| ≥1 global]** | E[#*distinct* global \| ≥1] |
|---|---|---|---|
| A4 (V5) | 0.89 (most kinds **1.00**; INSTR_TYPE_MOD **0.74**) | **3.0** | **3.0** |
| Arguzz (V6_uniform) | 0.87 | **10.7** | **10.7** |
| Arguzz (V6_cTS) | 0.81 | **9.8** | **9.8** |

Two decisive facts:
1. **Reliability ≠ volume.** A4's `P(global|local)≈1` (verified per-kind: INSTR_WORD_MOD_SUR/FULL, COMP/STORE/LOAD = 1.00, MEM_VAL_MOD = 0.99, **INSTR_TYPE_MOD = 0.74** — exactly your exception) means it *deterministically* fires ≥1 global failure. But the *count* when it fires is only **3.0**, vs Arguzz's **10.7** — A4 fires ~3.3× *fewer* global failures per mutation. So even on raw global-failure count, A4 does **not** "fail more global."
2. **Each global failure is a distinct context.** `E[#distinct-global | ≥1] == E[#global | ≥1]` for *every* kind (the two columns are identical — see §C). So per-mutation distinct-context count = the global-failure count: A4 ≈ 3 distinct/mut, Arguzz ≈ 10.7. CGC is the *union of distinct contexts over all mutations*, so Arguzz accrues ~3.3× faster → final CGC 440–598 vs 184.

**Why A4 is reliable-but-narrow:** a post-execution point-corruption of one cell *deterministically* breaks the small, **fixed** set of global lookups that single cell participates in (e.g., its one memory-permutation entry) — hence P≈1, but only ~3 contexts. A during-execution fault propagates, so it hits ~10 *different* downstream contexts — slightly less deterministic per any one context (P 0.81–0.87) but far wider.

Per-kind texture (g1): Arguzz's state-perturbation kinds carry the width — `PRE/POST_EXEC_MEM_MOD` and `PRE/POST_EXEC_REG_MOD` fire **E[#global]≈12–13** (injected register/memory state propagates broadly), vs A4's widest kind `INSTR_TYPE_MOD` at 5.1. Arguzz's `INSTR_WORD_MOD` is only 3.3 (mutating an instruction word propagates less, like A4) — consistent: width tracks *state* propagation, not instruction edits.

**One-line resolution:** "always co-fires" = reliability; "more CGC" needs *distinct-context volume*. A4 is reliable-but-narrow (~3 distinct/mut); Arguzz is wide (~10.7 distinct/mut) → Arguzz wins CGC.

*Evidence: Appendix C.*

---

## 3. Open / pending

- g2 (memory) and g3 (accelerator) curves + within-variant deltas — pending batch completion. g3 is the one likely to add genuine *local* territory (new `inst_sha` locs; already glimpsed: g1·V6_cTS uniquely hit `Sha0@inst_sha`).
- Cross-seed bands (seeds 1235/1236) — pending.
- Down-select (B3.2) criteria should weight CGC + candidate distribution, not local-loc count (per F1).

---

# Appendix — Evidence

All numbers below are computed from the run DBs (g0: `a4/runs/iv_pos_8/d2f/prod/...n10000`, truncated to `id<=5000`; g1: `a4/runs/iv_pos_9/sweep/data/g1_*.db`). Verified integrity: each run = 5000 mutations, correct binary (sha256 == canonical + fingerprint guard: planted_bug=none, load_rs2=1, matching guest_image_id), 0 accepted-with-constraint-failure.

## Appendix A — Adaptive-on (source: `bandit_decisions`)
- Signal: per-mutation `mode` ∈ {cold, floor, adaptive, singleton} + `exploration` (1/0). "Adaptive on" = first `mode != 'cold'`.
- V5 (A4, 78 arms): cold=234 → **adaptive@235** on g0 *and* g1 (identical). Post-cold modes: floor 3707 / adaptive 1045 / singleton 14; exploration 1/0 = 3721/1045.
- V6_cTS (Arguzz, 415 arms): cold 1370 (g0) / 1303 (g1) → **adaptive@1371 / 1304**.
- Hybrid (~250 arms): cold 806 (g0) / 775 (g1) → **adaptive@807 / 776**.
- V6_uniform: no bandit tables (uniform; `mutation_rewards`/`bandit_decisions` empty).
- Cold-start rule inferred: V5 cold = 234 = exactly 3×78 → 3 pulls/arm; Arguzz cold ≈ 3×(arms discovered so far), hence guest-dependent.

## Appendix B — CGC propagation footprint (sources: `compressed_global_coverage`, `global_failures`)
g1, N=5000, per variant: CGC final | total global-failures | mutations with ≥1 global-failure | mean global-failures per such mutation | distinct cycle-phases | distinct address-regions:
```
V5 (A4 post-exec)   CGC=184 | gfail=9419  | muts=3089 | mean=3.0  | phases=3 | regions=10
V6_uniform (Arguzz) CGC=440 | gfail=34841 | muts=3242 | mean=10.7 | phases=3 | regions=9
V6_cTS (Arguzz)     CGC=598 | gfail=27375 | muts=2798 | mean=9.8  | phases=3 | regions=10
Hybrid_cTS          CGC=330 | gfail=18064 | muts=3308 | mean=5.5  | phases=3 | regions=10
```
g0 baseline CGC (truncated to 5000): V5=337, V6_uniform=428, V6_cTS=560, Hybrid=447 — Arguzz > A4 on g0 too.

## Appendix C — Co-occurrence + global-failure volume per kind (sources: `mutations`, `failures`, `global_failures`)
Columns: kind | n | P(global|local) | E[#global | ≥1 global] | E[#distinct global | ≥1] | E[#local | ≥1 local].
Note `E[#distinct global] == E[#global]` throughout → every global failure is a distinct (family,address).

**g1 V5_control — A4 (post-exec), aggregate P(g|l)=0.89, E[#g|g≥1]=3.0:**
```
INSTR_TYPE_MOD       1217  0.74   5.1   5.1   4.8     <- the exception you noticed
MEM_VAL_MOD           607  0.99   2.4   2.4   4.7
TXN_PREV_WORD_MOD     513   nan   0.0   0.0   0.0     <- never fail (the benign accepts, F2)
CYCLE_DIFF_COUNT_MOD  512   nan   0.0   0.0   0.0
TXN_PREV_CYCLE_MOD    509   nan   0.0   0.0   0.0
PRE_EXEC_REG_MOD      472   0.94   1.4   1.4   3.4
INSTR_WORD_MOD_SUR    384   1.00   2.4   2.4   1.5
INSTR_WORD_MOD_FULL   376   1.00   4.1   4.1   2.7
COMP_OUT_MOD          204   1.00   1.0   1.0   1.8
STORE_OUT_MOD         104   1.00   1.0   1.0   1.9
LOAD_VAL_MOD          102   1.00   1.0   1.0   1.9
```
**g1 V6_uniform — Arguzz (during-exec), aggregate P(g|l)=0.87, E[#g|g≥1]=10.7:**
```
POST_EXEC_PC_MOD      670  1.00   7.6
POST_EXEC_REG_MOD     653  0.96  12.6   <- injected register state propagates broadly
PRE_EXEC_MEM_MOD      645  0.96  13.0
PRE_EXEC_PC_MOD       643  0.99   7.3
INSTR_WORD_MOD        639  0.63   3.3   <- instruction-word edit propagates little (≈ A4)
POST_EXEC_MEM_MOD     632  0.95  13.3
PRE_EXEC_REG_MOD      618  0.95  12.4
COMP_OUT_MOD          302  0.05  10.0
BR_NEG_COND           107  1.00   6.8
LOAD_VAL_MOD           53  0.00   0.0
STORE_OUT_MOD          38  0.00   0.0
```
**g1 V6_cTS — Arguzz (during-exec), aggregate P(g|l)=0.81, E[#g|g≥1]=9.8** (same shape: PRE/POST_EXEC_MEM/REG ≈ 12–13; INSTR_WORD_MOD = 3.5).

**Reading:** A4 kinds co-fire reliably (P≈1) but narrowly (E[#global] 1–5, mostly ≤2.4); Arguzz *state*-perturbation kinds fire 12–13. The width tracks state propagation, not edit reliability — which is why A4's near-certain co-firing still yields less CGC.

## Appendix D — Local-loc territory (source: `coverage`)
g1 vs g0 local-loc set difference (seed 1234, ≤5000), per variant — ~95% shared:
```
V5:     g0=47 g1=46  shared=46  g1-only=0  g0-only=1 (ControlMRET:93)
V6u:    g0=33 g1=33  shared=32  g1-only=1 (ECallTerminate)  g0-only=1 (PoseidonEcall@inst_p2)
V6_cTS: g0=34 g1=35  shared=33  g1-only=2 (OpLHU, Sha0@inst_sha)  g0-only=1 (OpSH)
Hybrid: g0=47 g1=48  shared=47  g1-only=1 (IllegalMulOp)  g0-only=0
```

## Appendix E — Saturation & cost (g1·V6_uniform)
Cumulative coverage by mutation index: local 16(@50) → 29(@500) → 32(@2000) → 33(@4000, last @3377); CGC 79(@50) → 229(@500) → 342(@2000) → 440(@5000, last new @4873). Per-mut elapsed_ms median ~3.2–4.1 s; one-time prover setup ~178 s/job. → N=10000 adds ~0 local, ~15–25% CGC.

---
*Generated 2026-06-24 from batch-1 DBs. Regenerate the curves via `python3 a4/runs/iv_pos_9/sweep/build_sweep_notebook.py`. Append new investigated questions to §2 with an evidence section here.*
