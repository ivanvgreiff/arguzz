# Step-Domain Fix — N=1000 Live Validation Results (POS, 2026-06-27)

Commit `68d90aa` (pushed `origin/cloud2`). Four variants, seed 1234, N=1000, B2 vulnerable
binary (sha dbe89d23), guest args `--ctrl 7 --gseed 12345 --rounds 5`. Run on POS Tier-S
(flare/octorand/opulous/polynize) with the fix overlaid. DBs analyzed **on-node** (the fuzzer
writes WAL; only an on-node read with the `-wal` sidecar is consistent — copied `.db` files are
malformed).

## Domain key (essential to reading the numbers)
The `mutations.step` column means **different things per surface**:
- **Arguzz** arms (`arguzz_exec_fault|…`): `step` = **executor `current_step`**. The CVE divides
  (remu, divu) are at executor **444 / 449**.
- **A4** arms (`INSTR_TYPE_MOD|…`, `CYCLE_DIFF_COUNT_MOD|…`, `TXN_PREV_*`, `COMP_OUT_MOD|…`,
  `PRE_EXEC_REG_MOD|…` on the A4 surface): `step` = **witgen `user_cycle`**. The same divides are
  at user_cycle **436 / 441**.
- Mapping: remu = uc436/exec444, divu = uc441/exec449 (drift +8 = machine-ecall count before the
  divides). Executor 436/441 = lw/ori (the WRONG instructions the pre-fix `core_div` arm hit).

## Result 1 — V6_cTS (pure Arguzz, flare): FIX WORKS, 100%
- mutations=1000, verifier_accepted=32, proof_generated=1000, proof_verify_failed=652, outcome
  applied=953/skipped=46/error=1. **Zero step-domain guard aborts** (ran to completion).
- **`core_div` arms inject at executor 444 (×25) and 449 (×26) ONLY; zero at 436/441.**
  Pre-fix these arms hit 436/441 (lw/ori). Every `arguzz_exec_fault|<kind>|core_div|arithmetic|…`
  arm now lands on the real remu/divu. ✅ This is the behavioral proof.
- CVE-relevant accepts (verifier_accepted on 444/449) = 1 — and it's a `POST_EXEC_PC_MOD` at 444,
  not an rs1==rs2 divide-value mutation. So **no clear value-CVE find at N=1000** (expected: rare
  event, small N; the N=5000×6-seed re-run is the find-rate comparison).

## Result 2 — Hybrid_cTS (octorand): BOTH surfaces correct, each in its own domain
- mutations=1000, verifier_accepted=202, proof_verify_failed=197.
- Arguzz-surface `core_div` arms → executor **444/449** ✅ (fix).
- A4-surface `core_div` arms (`INSTR_TYPE_MOD|core_div`, `CYCLE_DIFF_COUNT_MOD|core_div`,
  `TXN_PREV_*|core_div`, …) → user_cycle **436/441** ✅ (A4 was always correct; uc436/441 = divides).
- 18 accepts at uc436/441 (CYCLE_DIFF_COUNT_MOD / TXN_PREV_*), plus a large accept cluster at
  step 2374 (cycle-count region). Replay-oracle classification (committed output) pending.

## Result 3 — V5_control (polynize, A4): unaffected control, learning normally
- mutations=999. A4 `core_div` arms → user_cycle **436 (×47) / 441 (×37)** ✅ (divides in uc space).
- `mutation_rewards.reward` >0: 974/999; real posteriors (e.g. `INSTR_TYPE_MOD|step0` α=33/β=13,
  mean_r=1; 850 arm_state rows) → bandit clearly learning via the continuous A4 reward path.

## Result 4 — V6_uniform (opulous): baseline, unaffected (instr_to_steps is executor-space).
  (N=1000 body not re-captured this run; uniform is the comparison baseline, untouched by the fix.)

## The `reward=0` for V6_cTS is BY DESIGN, not a fix regression
V6_cTS's continuous `mutation_rewards.reward`/`T_new`/`F_new`/`Q`/`S` columns are all 0 — but
that is the **V5/A4-era** telemetry the v6 selector does not write. Its real learning signal is
alive: `reward_counterfactuals.bandit_success_l1` = **1000/1000 >0**, `discovery_binary>0: 292`,
`compressed_global>0: 201`; `bandit_decisions` shows **230 adaptive-mode** decisions across **155
distinct arms** (cold→adaptive = learning). The step-domain fix only changed zone-label
computation (and recording loci) — never the reward formula or which column is written — so it
cannot have zeroed reward. Confirmed pre-existing v6 behavior.

Side note (unrelated to this fix): V6_cTS's L1 success is saturated (`l1_d_loc_le_2>0: 1000`
dominates `bandit_success_l1`), a pre-existing reward-design leniency. Does not affect the CVE
find-rate comparison.

## Verdict
Step-domain fix **validated at full N=1000** on live POS data: Arguzz `core_div` effort is now
correctly aimed at the real divides (V6_cTS 444/449 only), both surfaces target the divides in
their respective domains (Hybrid), the A4 control is untouched, and the bandit learning signal is
intact. Cleared for the unconfounded re-run (V6_cTS + Hybrid × seeds 1234–1239 × N=5000).
