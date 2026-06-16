# Pro Round 2 — Decisions Brief (IV.POS.7)

**Audience:** ChatGPT Pro — Round 2 architecture review
**Date:** 2026-06-16
**Packet contents:** this brief + `MAB_ARCHITECTURE_REPORT_FOR_PRO_R2.md` (results narrative) + `MAB_ARCHITECTURE_NOTEBOOK_R2.html` (plots)
**Variant labels in this brief:** we ran 5 of the 9 ablations you listed in ProG_Report_2 §9 (A–I). Throughout this brief, we use your §9 letters as the primary labels, with our internal `V`-numbers in parentheses. Full mapping in §3.

> **A note on terminology.** Where this brief uses a term that does not appear in `ProG_Report_2.md`, we define it inline on first use. Where we engineered an approach to a question you did not specify (notably the semantic-zone classifier in §2 and the constrained-TS schedule in §3), we provide the full mechanism so you can evaluate it.
>
> **Brief structure.** §1–§6 are about what we ran and what we want your verdict on. §7 surfaces things you didn't ask for but might want. §8 lists on-request material. **§9 (appendix)** is a forward-looking inventory of A4 mutation kinds we have *not* implemented, included as input for §6-Q3 (extending A4 vs. hybridizing with arguzz).

---

## §1 Compliance map — your `ProG_Report_2.md` → our implementation

Each row maps a §-numbered recommendation in your report to what IV.POS.7 actually ran. Verification pointers reference packet contents only.

| Your § | Your recommendation | What we did | Verify in |
|---|---|---|---|
| §7.A | Replace `(kind, bucket)` arms with `(kind, semantic_zone)`; explicit boundary singletons | 19 zones implemented (your 17 + 2 we added; see §2); 48 populated `(kind, zone)` arms for sha2-host; `step0` and `last_step` get forced minimum pulls | §2 of this brief; results report §2 |
| §7.B | Drop nested per-step UCB; sample step within zone | Step picked uniformly from the chosen arm's step list (no nested bandit) | §3 of this brief |
| §7.C | Constrained bandit: 50–60% reserved coverage floor + adaptive remainder | `coverage_floor_fraction = 0.55` (middle of your range); observed mode mix at N=6000 is ~94% floor / ~4% adaptive (see §3) | §3 of this brief |
| §7.D | Prefer Thompson sampling over discounted UCB; Bernoulli success target | Constrained TS with `Beta(1,1)` uninformative prior; bandit update uses `success = 1 iff (L_new + G_new + S_new) > 0` per your §8 spec | §3 of this brief; results report §6.5 |
| §8 | Reward formula with saturation; weights `(1.00, 0.30, 0.25, 0.15, −0.50, −0.05)`; taus `(1, 1, 3, 2, 5)` | Adopted **verbatim** as the scalar `compute_reward_v2`. Used for logging and counterfactual analysis; **not** the TS update signal (per your §7.D Bernoulli preference) | Results report §6.1, §6.5 |
| §9 | Lock calibration across strategies | Pilot calibration **removed entirely** (your fixed weights/taus subsume what would have been calibrated) | §4-D2 |
| §9 | 9 ablation variants (A–I) | Ran **5 of 9**: B (V1), G (V2), G with no-Q_loc (V3), H (V4), I (V5). Variants A, C, D, E, F not run; rationale in §3 mapping table | §3 of this brief |
| §10 | 5-variant 6000-mutation ablation | 5 variants × 10 seeds (1234–1243) × N=6000; 50/50 databases passed collection validation | Results report §3–§5 |
| §10 | 5 success criteria (beat zoned on AUC / variance / speed / CGC / novel discovery) | Mechanical evaluation: variant I (V5) = **5/5**; variant H (V4) = 0/5; variant G with no-Q_loc (V3) = 1/5; variant G (V2) = 0/5; baseline B (V1) used as reference | Results report §5 |
| §10 | 8 primary metrics (`local_context_final`, `local_context_AUC`, `time_to_40/43/46`, `compressed_global_context_final`, `crash_rate`, `no_effect_rate`, allocation entropy by kind and zone) | All 8 computed for 50 databases | Results report §4, Appendix A |
| §10 | Seeds: 5 minimum, 10 preferred | 10 seeds | Results report §3 |
| §10 | Do **not** run legacy bandit at N=20k as main test | Skipped; structural ablation at N=6000 instead | Results report §7.6 |
| §11 | Fix selector and reward before expanding mutation kinds or guests | Honored — same 8-kind universe and same guest as IV.POS.5 | §4-D3 |
| §12 | Add specific telemetry tables (`bandit_decisions`, `arm_state_log`, `reward_counterfactuals`, `mutation_substrategy`, `hook3_raw_or_semantic`, `pilot_runs`) | All 6 implemented and populated. `pilot_runs` is empty by design per your §9 calibration-lock recommendation | Results report §6.5 |
| §14 | 7 concrete next steps | Steps 1–6 complete; step 7 (new kinds) intentionally deferred per your §11 | This brief is steps 1–6 closeout |

---

## §2 Architectural detail: how the arm space was actually built

This section is the most engineering-intensive part of IV.POS.7 and the place where we made the most decisions you did not specify. Provided in detail so you can evaluate the mechanism.

### §2.1 — Vocabulary

These are terms we use below; only **major**, **step**, and **cycle** appear in your prior report.

| Term | Definition |
|---|---|
| **Cycle** | One row in the RISC0 execution trace (your §2). Each cycle has a `major` opcode-class code (your terminology) and a `minor` sub-opcode. |
| **Step** | A logical RV32IM instruction; one step contains one or more consecutive cycles (e.g. a DIV step is multiple cycles). The `step` index is what `INSTR_TYPE_MOD@step=0` in your IV.POS.5 analysis refers to. |
| **Decode cycle** | A cycle whose major ≤ 6, i.e. a normal RV32IM ALU / mem / branch / mul / div cycle (not ECALL=major 8, not POSEIDON=major 9/10, not SHA=major 11, not BIGINT=major 12, not CONTROL=major 7). |
| **Primary Decode cycle** (for a step) | The first cycle at that step with major ≤ 6. Used to determine the step's PC and opcode class. |
| **User PC range** | `[0x00200000, 0x00400000)` — the guest program memory. |
| **Kernel PC range** | `[0xC0000000, 0xC1000000)` — kernel boot, trap handlers, MRET cleanup. |
| **Hook 3** | The C++ hook in the modified RISC0 host that runs during witness generation (`step_Top`). It records EVERY memory transaction and EVERY lookup-table usage from the trace (in our test trace: ~69k memory records, ~184k lookup records). After witgen, it reads the verifier's randomness from the mix buffer and computes a per-family LogUp residue for each of 4 families: **memory permutation**, **U8 range check**, **U16 range check**, **cycle ordering**. A non-zero residue for a family means that family's permutation/lookup argument failed to balance — i.e. **a global constraint failure was localized to that family**. The output is one `<a4_family_residue>` tag per family (`nonzero: true|false` + the FpExt residue when non-zero). Hook 3's purpose is therefore **(a) global constraint failure detection per family**, and **(b) raw memory/lookup records that downstream code uses to localize WHICH addresses or values broke the family-level constraint**. Your §12 calls the schema slot for this output `hook3_raw_or_semantic`. |
| **Singleton zone** | A zone containing exactly 1 step value (e.g. `step0` is always the single step 0). Opposite of a "broad" zone that contains many steps. |
| **Arm** | A `(mutation_kind, semantic_zone)` pair with ≥ 1 valid step. |
| **Phantom arm** | A `(kind, zone)` pair that looks non-empty when computed coarsely (`per-kind valid steps ∩ zone steps`) but where every step in the intersection rejects the mutation module's `get_targets_at_step` probe. These get dropped. |
| **CGC** | Shorthand for `compressed_global_context` (the schema you defined in your §5: `GLOBAL_MEMORY` and `GLOBAL_LOOKUP` with `address_region`, `address_bucket`, `txn_role`, `cycle_phase`, etc.). When you see "CGC delta" or "CGC keys" in this brief, it refers to this. |

### §2.2 — The 8 mutation kinds (same as IV.POS.5)

`INSTR_TYPE_MOD`, `INSTR_WORD_MOD_FULL`, `INSTR_WORD_MOD_SUR`, `MEM_VAL_MOD`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, `STORE_OUT_MOD`, `PRE_EXEC_REG_MOD`. Unchanged from your IV.POS.5 analysis. Per your §11, we do not expand the kind universe in IV.POS.7.

### §2.3 — The 19 semantic zones

Your §7.A listed 17 zones. We added 2.

| Source | Zone | Notes |
|---|---|---|
| **Your §7.A** (singleton boundary) | `step0`, `last_step` | Singleton zones — exactly 1 step each. |
| **Your §7.A** (boundary adjacency) | `pre_ecall`, `post_ecall`, `pre_mret`, `post_mret`, `pre_halt`, `post_halt` | The 4 MRET/halt zones are **empty** on sha2-host (see §2.5). |
| **Your §7.A** (core) | `core_arithmetic`, `core_memory_load`, `core_memory_store`, `core_branch`, `core_mul`, `core_div`, `core_sha`, `core_poseidon`, `core_other` | `core_sha` / `core_poseidon` / `core_other` are empty on sha2-host (see §2.5). |
| **We added** | `core_shr` | Splits your `core_div` because RV32IM's major=4 ("DIV0" in the circuit) actually contains BOTH DIV/REM (minors 4–7) AND SRL/SRA (minors 0–3) in the same major code. Without a split, shift-right operations are lumped into `core_div`. Single new zone; no other changes to your core_* set. |
| **We added** | `kernel_other` | Catches Decode cycles whose primary PC is in the kernel range (`0xC0000000+`). Empirical finding: 9.6% of Decode-cycle steps in the sha2-host baseline trace are at kernel PC (kernel boot, MRET cleanup, trap handler). Without this zone, those steps were ~3–5% contaminating each `core_*` zone. We chose the HYBRID design (one new `kernel_other` zone, all `core_*` zones become implicitly user-only by classifier precedence) over the BROAD alternative (split every `core_*` into `_user`/`_kernel` variants, which would have added ~13 new sparse arms). |

### §2.4 — Classifier precedence

Your §7.A specified what the zones are but not how to resolve a step that could match multiple. Our precedence rules (each rule applied in order; first match wins):

1. **`step0`** — step index 0.
2. **`last_step`** — step index `total_steps − 1`.
3. **`pre_ecall`** — any step containing a cycle with `major = 8` (ECALL). This includes the ECALL cycle itself, which was a choice you did not specify (D13). Rationale: ECALL-setup constraints fire AT the ECALL cycle, and we want them inside a boundary zone so the constrained-TS boundary floor reaches them.
4. **`post_ecall`** — for each ECALL at step `e`, the **first** step in `[e+1, e+5]` whose primary Decode cycle is at user PC. This is a window rather than a fixed `e+1`, because the kernel often handles the ECALL for several cycles before returning to user code (D53).
5. **`kernel_other`** — any step whose primary Decode cycle is at kernel PC, not already in a higher-precedence zone.
6. **`core_*`** — fallback to `major → zone` mapping; major=4 is split per §2.3 into `core_div` (minors 4–7) or `core_shr` (minors 0–3) (D50).

### §2.5 — Sha2-host's actual zone populations

**Important caveat about the "sha2-host" guest.** The name is misleading: **the guest does NOT perform SHA hashing.** Despite the name, `sha2-host` is the **ZirGen circuit-equivalence checker** — a small Rust program with `risc0_zkvm::guest::env::read` that reads two copies of 5 inputs (`in0: bool, in1: u32, in2: bool, in3: bool, in4: u32`), runs two synthesized field-arithmetic circuits `c0()` and `c1()` against each, and commits the index of the first output position where they disagree. The instruction mix is:

- **ALU operations**: integer multiply, AND/OR/NOT/XOR (some via inline RISC-V `asm!` macros to prevent constant folding), modulo, equality, ≥
- **Boolean operations**: `&&`, `||`, `?:` conditionals
- **No shift-right ops** (`SRL`/`SRA`) in the data path — only one `wrapping_shl(1)` in our test guest, and the synthesized circuits use `^`/`&`/`|`/`+`/`*` operators rather than shifts
- **No SHA hashing** at all (not `risc0_zkvm::sha::Impl`, not RustCrypto `sha2`)
- **No explicit BigInt / Poseidon / Keccak / MRET-rich code**
- **No input-dependent control flow** in the data path: c0/c1 are short straight-line functions (≈ 25–30 source statements each) with no loops; the host's input values flow through `env::read` and the field-arithmetic computation but do not branch the execution shape. This is why the arm space at `--in1 1, --in4 1` and `--in1 100, --in4 100` is bit-identical to the `--in1 5, --in4 10` baseline (§2.7).

The classifier produces, on this guest at `--in1 5 --in4 10` (3930 steps total):

| Zone | Steps |
|---|---:|
| `step0` | 1 |
| `last_step` | 1 |
| `pre_ecall` | 33 (includes 33 ECALL cycles) |
| `post_ecall` | 32 (one ECALL's `e+1..e+5` window was kernel-only) |
| `kernel_other` | ~370 (9.6% of total) |
| `core_arithmetic` | 2443 |
| `core_memory_load` | 678 |
| `core_memory_store` | 596 |
| `core_branch` | 24 |
| `core_mul` | 100 |
| `core_div` | 23 |
| `core_shr` | 0 |
| `core_other` | 0 |
| `core_sha` | 0 |
| `core_poseidon` | 0 |
| `pre_mret`, `post_mret`, `pre_halt`, `post_halt` | 0 each |

**8 of 19 zones are empty on sha2-host.** Reasons (some are classifier limitations, but the majority reflect the guest's narrow instruction mix described above):
- **4 MRET/halt zones empty** — **classifier limitation, not guest-driven**: `InspectionData` (our baseline-trace inspector) does not separately tag MRET vs ordinary branch cycles. Both fall under `major=7` (`CONTROL0`); distinguishing them requires either re-decoding the instruction word or extending the C++ inspector. **We have not done either.** Even if we did, this guest has no MRET-rich code, so these zones would likely remain sparse here regardless. Q5 (multi-guest) might unblock both — a guest with rich MRET use would force the inspector extension AND would populate the zones.
- **`core_sha` empty** — **guest-driven**: the guest does no SHA hashing whatsoever (see disclaimer above). A guest using `risc0_zkvm::sha::Impl` would populate this (major=11).
- **`core_poseidon` empty** — **guest-driven**: major=9/10 cycles appear only at step 0 (Poseidon-based image-ID setup), which is already captured by the `step0` singleton; no in-program Poseidon use.
- **`core_other` empty** — **guest-driven**: no major=12 (BigInt) cycles; major=8 cycles are exclusively ECALL handling (captured by `pre_ecall`).
- **`core_shr` empty** — **guest-driven**: the synthesized `c0`/`c1` circuits use `&`/`|`/`^`/`+`/`*` operators and one `shl` (left shift = `SLL`, major=4, classified as `core_arithmetic`); no `SRL`/`SRA` (major=5/6) appear in the trace.

**Implication for generalizability.** Because the guest exercises a narrow slice of RV32IM, **we cannot empirically verify the classifier's behavior on the empty zones** from sha2-host alone. The 4 MRET/halt zones additionally have a known classifier gap. The arm universe and classifier code are guest-portable (re-derived per guest from `InspectionData`), but the empirical evidence we present is from a guest where most of the diversity-affording zones are simply not exercised. This is why Q5 (multi-guest at a richer workload) is the next-priority experiment.

### §2.6 — Per-guest dynamic arm universe

The arm universe is **rebuilt per guest** at fuzzer startup from `InspectionData`. The 48-arm count is empirical for sha2-host; a guest exercising the empty zones above would automatically extend the arm set without any code change. The classifier and zone definitions are guest-portable.

### §2.7 — Arm count derivation for sha2-host

Naive intersection of "valid steps per kind" with "steps per zone" gives 53 candidate arms.

- **5 phantom arms dropped** by the per-kind `get_targets_at_step` probe: `COMP_OUT_MOD|step0`, `COMP_OUT_MOD|pre_ecall`, `INSTR_WORD_MOD_FULL|step0`, `INSTR_WORD_MOD_SUR|step0`, `PRE_EXEC_REG_MOD|pre_ecall`. These are intersections where every step rejects the mutation (e.g. step 0 has no compute-instruction write transaction for `COMP_OUT_MOD`).
- **No more arms dropped at this stage on sha2-host.**

**= 48 final arms** for sha2-host baseline. (Other inputs of the same guest — we verified `--in1 1 --in4 1` and `--in1 100 --in4 100` — produce identical 48-arm sets with identical step counts.)

### §2.8 — One ambiguity we resolved by dropping

Four `(kind, zone)` candidates exist where the underlying step contains multiple cycles matching the kind's major filter, and the C++ hook vs the Python target-builder use independent "first-matching-cycle" heuristics that occasionally disagree. We chose to **drop these ambiguous steps from the arm** rather than pick one heuristic (D40). Concretely, `INSTR_WORD_MOD_{FULL,SUR}|last_step` and `INSTR_WORD_MOD_{FULL,SUR}|pre_ecall` lost steps that had multi-cycle ambiguity. The arm count above (48) reflects this drop.

### §2.9 — Singletons that DO exist for sha2-host

Per the canonical arm matrix, 6 arms have exactly 1 valid step (and therefore deterministic step selection): `INSTR_TYPE_MOD|step0`, `MEM_VAL_MOD|step0`, `PRE_EXEC_REG_MOD|step0`, `MEM_VAL_MOD|last_step`, `INSTR_WORD_MOD_FULL|last_step`, `INSTR_WORD_MOD_SUR|last_step`. Your §7.A's instruction *"INSTR_TYPE_MOD@step0 should be an explicit singleton arm with a guaranteed minimum pull count"* is satisfied by this set plus the singleton floor in §3.

---

## §3 Architectural detail: how the constrained-TS scheduler actually runs

This is the variant I (V5) selector — the main candidate. Other variants (V1–V4) use simpler selectors that we describe briefly at the end.

### §3.1 — Four-tier priority

You specified the floor/adaptive split (§7.C) but not the ordering when multiple constraints could fire. Our priority stack (each tier checked in order; first match selects the arm):

```text
For each mutation N from 1 to 6000:
    if any arm has lifetime pulls < 3            → mode = cold
    else if any singleton arm has pulls < 5      → mode = singleton
    else if any arm below per-epoch floor target → mode = floor
    else                                         → mode = adaptive (Beta TS)
```

The mode counts per seed are deterministic for fixed hyperparameters and arm count (σ = 0 across seeds for mode totals); seed randomness only affects *which* arm within a mode and *which* step inside the arm. This makes cross-variant comparison clean (no seed-driven mode-mix drift).

### §3.2 — Cold-start: 144 pulls (2.4% of budget)

- Every arm must receive at least 3 lifetime pulls before TS is allowed to ignore it. With 48 arms, this fixes the first 144 mutations to round-robin cold pulls. No exceptions.
- You did not specify this; we chose 3 as a minimum sample size for the Bernoulli signal.

### §3.3 — Singleton floor: 8 pulls (0.1%)

- After cold, the 6 singleton arms are topped up to 5 lifetime pulls each (cold already gave them 3, so this adds at most 2 per arm; the math actually yields 8 total singleton-mode pulls because some singletons already exceeded 3 during cold round-robin).
- You did specify *"explicit minimum pulls for boundary zones"* in §7.C; we operationalize "minimum" as 5 for singleton arms specifically.

### §3.4 — Per-epoch floor: ~5615 pulls (93.6%)

- **Epoch** = block of 100 mutations.
- Within each epoch, each arm should receive at least `coverage_floor_fraction × epoch_size / num_arms = 0.55 × 100 / 48 ≈ 1.15` pulls.
- If any arm is below its target, the scheduler enters floor mode and picks the most under-allocated arm (round-robin tie-break).
- Why 0.55: middle of your §7.C 50–60% range, slightly toward the floor side.
- The 93.6% observed dominance is structural: with 48 arms and a per-arm-per-epoch quota, the floor is hard to satisfy without using most of the budget on it. This is NOT a bug; see §3.6 for why this is intentional.

### §3.5 — Adaptive Thompson sampling: ~233 pulls (3.9%)

- Each arm `a` has a `Beta(α_a, β_a)` posterior, starting from `Beta(1, 1)` uninformative prior.
- Adaptive selection: draw `θ_a ~ Beta(α_a, β_a)` for each arm; pick `argmax θ`.
- Posterior update on each pull: `α_a += success`, `β_a += (1 − success)`, where `success = 1 iff (L_new + G_new + S_new) > 0` (your §7.D + §8 spec).
- **Posterior updates run for every pull regardless of mode** (cold/singleton/floor/adaptive all update); only the selection rule differs.

### §3.6 — Why floor dominance is intentional

V5 (variant I) outperforms V1 (variant B) on the local-coverage curve by mutation 500 — when only ~13 adaptive pulls have occurred. The win is not "TS got smart late"; the win is **"cold + floor on the right arm space."** Forcing every `(kind, zone)` arm to be visited (especially `INSTR_TYPE_MOD|pre_ecall`, the kernel/ECALL-adjacent arms, etc.) is what finds the 4 novel kernel/ECALL constraints variant B never reaches. The adaptive TS pulls refine within epochs when the fairness quota is temporarily satisfied; they do not drive the headline result.

A natural Pro-facing question: *would 10× more mutations let adaptive dominate?* No, because cold (144) and singleton (8) are fixed counts and the floor fraction is set at 0.55 of every epoch's budget. More mutations → more epochs → same fraction floor / adaptive. We would need to lower `coverage_floor_fraction` (or raise `epoch_size` so quotas are easier to satisfy) to shift the mix. This is exactly the IV.POS.8(b) sweep candidate in §6-Q4.

### §3.7 — Reward signal: two coexisting

We compute and store TWO rewards per mutation; only one drives TS.

| Reward | Formula | Used for |
|---|---|---|
| **Scalar v2** | `1.00·sat(L_new, 1) + 0.30·sat(F_new, 1) + 0.25·sat(G_new, 3) + 0.15·sat(S_new, 2) − 0.50·crash − 0.05·sat(repeat, 5)` (your §8 verbatim, with `sat(x, τ) = 1 − exp(−x/τ)`) | Logging, counterfactual analysis, the `reward_counterfactuals` table from your §12 |
| **Bernoulli success** | `1 iff (L_new + G_new + S_new) > 0` (your §8 `bandit_success` definition) | TS posterior updates (only) |

Scalar v2 is conjugacy-violating for Beta (range `[−0.55, +1.70]`) so it cannot directly update TS. Conversely, Bernoulli success collapses information we want for offline analysis (e.g., did the mutation cause 5 new contexts or 1?). The dual-reward design is operationally clean: bandit gets the conjugate signal, analysts get the full-fidelity scalar.

### §3.8 — Step pick within an arm

After the bandit picks `(kind, zone)`:
- Singleton zones (`step0`, `last_step`) deterministically pick their one step.
- Broad zones pick a step uniformly at random from the arm's step list.

There is NO nested bandit; this is your §7.B recommendation operationalized.

### §3.9 — V1–V4 (variants B, G, G-with-no-Q_loc, H) for contrast

- **Variant B (V1, baseline reference)**: kind chosen uniformly from the 8 kinds; step chosen by a fixed 5/90/5 prior over init/core/final (steps 0 / interior / last_step). No bandit, no learning, no zones.
- **Variant G (V2)**: undiscounted UCB1 over the 8 kinds with exploration constant `c = 0.25`; step chosen by the same 5/90/5 prior; reward is the legacy IV.POS.5 scalar (with `Q_loc`).
- **Variant G with no-Q_loc (V3)**: same selector as V2; reward is the new scalar v2 (which structurally has no `Q_loc` because the multiplicative gate is gone). **Live optimization is on the v2 scalar**, not on an offline counterfactual.
- **Variant H (V4)**: Beta(1,1) Thompson sampling over the 8 kinds (no zones); same step prior as V2; same v2 reward as V3.

All four of these use the kind-only arm space and the zoned step prior. Variant I (V5) is the only one that uses semantic zones as arms.

---

## §4 Decisions worth flagging (interpretation-affecting)

The architectural-detail sections (§2 and §3) cover the engineering. The decisions below are interpretation-affecting choices that don't fit naturally above.

| # | Decision | Our choice | Why it matters |
|---|---|---|---|
| **D1** | Seeds per variant (your §10: 5–10) | **10** | Observed effect size for variant I vs B (final = +3.5 locs, σ ratio = 0.58) is detectable at n=10; 5 would have left variant H (paired-t p≈0.09 on AUC) genuinely ambiguous. |
| **D2** | Calibration (your §9: "shared profile OR remove entirely") | **Removed entirely** | Your fixed weights and taus leave nothing to calibrate. All 5 variants start from identical reward parameters; the only differences are the selector strategy. Clean experimental control vs the IV.POS.5 pilot-calibration confound. |
| **D3** | Guest scope | **sha2-host only**, `--in1 5 --in4 10`. Same as IV.POS.5. | Preserves the 46-context empirical universe you analyzed in IV.POS.5 for a clean A/B against variant B (V1). New guests deferred per your §11 step 5; see §6-Q5. |
| **D8** | `address_region` granularity in the compressed-global-context schema (your §5) | **9 region labels** in our implementation (`a4/standalone/compressed_global_extractor.py::_ADDRESS_REGION_MAP`): `zero_page` `[0x00000000, 0x00010000)`, `user` `[0x00010000, 0xBFFF0000)`, `user_bigint` `[0xBFFF0000, 0xC0000000)`, `kernel` `[0xC0000000, 0xFF000000)`, `machine_regs` `[0xFFFF0000, 0xFFFF0080)`, `user_regs` `[0xFFFF0080, 0xFFFF0100)`, `machine_special` `[0xFFFF0100, 0xFFFF1000)`, `ecall_dispatch` `[0xFFFF1000, 0xFFFF2000)`, `trap_dispatch_and_beyond` `[0xFFFF2000, 0x100000000)`. Gaps (e.g. `[0xFF000000, 0xFFFF0000)`) fall to the catch-all label `invalid`. The `user` band covers user code, data, heap, stack, AND the `HOST_ECALL_ADDR` MMIO buffer at `[0x42000000, 0x42000100)` (which therefore lands in `user`). | Fine-grained for control/kernel; coarse for user-mode addresses (one `user` label for ~3 GiB of address space). The geometric residue your §5 warned against ("rewarding different memory byte touched") is then encoded in `address_bucket = floor(log2(addr))` ∈ [0, 31], applied within each region — so for `region = user`, `address_bucket` is the only fine-grained discriminator. Pairs with §6-Q1. If you opt for region-only (drop bucket), each region collapses to ~1 key per `(txn_role, cycle_phase)`. |
| **D16** | `txn_role` and `cycle_phase` derivation (your §5 schema; you did not specify the source) | **Derived from the mutation's (kind, zone)**, not from per-failure Hook 3 metadata | Hook 3 emits one record per failure but does not tag each record with a `txn_role`. We use the mutation's kind (e.g., `STORE_OUT_MOD → write`) and the mutation's zone (e.g., `pre_ecall → ecall`) as proxies. **Consequence**: all failures from one mutation share one CGC key, so variant I's +30.4% CGC delta over variant B partly reflects `(kind, zone)` allocation diversity rather than pure memory-pattern diversity. The primary metric (`local_context_final`) is unaffected. Documented in results report §6.5. |
| **D17** | `address_bucket` scheme (your §5: "page or log2-range bucket") | **log2-range, 32 bins** | The only reward-design knob we could pick freely. See §6-Q1 for whether this should change in IV.POS.8. |
| **D31** | Variant G with no-Q_loc (V3) reward signal | **Live `compute_reward_v2` scalar**, not the `no_qloc_reward` counterfactual stored offline | **Important for V3 vs V5 ablation interpretation.** Variant G and variant G-with-no-Q_loc share the UCB selector; the difference between them is solely the reward (legacy scalar vs new v2 scalar). But the difference between G-with-no-Q_loc (V3) and variant I (V5) is **two-dimensional**: (i) UCB → constrained TS, (ii) kind-only arms → semantic-zone arms. V5's 5/5 success vs V3's 1/5 cannot be attributed to reward redesign alone — the selector + arm-space changes are the load-bearing innovation. |
| **D33** | Variant G (V2) is NOT a literal IV.POS.5 replay | **Undiscounted UCB1 with `c = 0.25`**, kind-only (no bucket axis) | V2 and V3 must share the same UCB algorithm for a clean reward ablation. Reproducing IV.POS.5's two-level discounted UCB would also require the bucket axis, which we deprecated. V2's allocation collapse (85% of late-epoch pulls on `INSTR_WORD_MOD_SUR`, final = 31.8/46) reproduces the pathology you diagnosed in IV.POS.5 under cleaner conditions. If you want a literal replay variant in IV.POS.8, see §6-Q4(b). |
| **D43** | Multi-guest verification (your §11 step 5) | **Deferred to Phase 10** | IV.POS.7 only validates on sha2-host. We verified input-invariance by re-running with `--in1 1` and `--in1 100`; arm space identical. **Not** tested on a second guest. See §6-Q5. |

---

## §5 Pro §9 ablation mapping — variants A–I vs what we ran

| §9 letter | Your description | What we ran | Status |
|---|---|---|---|
| **A** | `kind_uniform + uniform_valid_step` | — | **Not run.** Closest is an internal V0 (uniform-over-kinds + uniform-over-steps); analysis deferred, not in this packet. |
| **B** | `kind_uniform + zoned_step` | **V1** (`zoned_current`) | ✓ Reference baseline. |
| **C** | `kind_uniform + singleton_boundary_step` | — | Boundary handling is embedded in variant B's 5/90/5 prior AND in variant I's singleton floor, but not isolated as a standalone variant. |
| **D** | `arm_uniform_b16` | — | **Not run.** IV.POS.5 arm-uniform anti-pattern. |
| **E** | `arm_uniform_b128` | — | **Not run.** Same reason. |
| **F** | `kind_UCB + uniform_valid_step` | — | **Not run.** Same step-prior confound as A; UCB selector tested in G and G-with-no-Q_loc. |
| **G** | `kind_UCB + zoned_step + current_reward` | **V2** (`kindUCB_zoned_v1`) — legacy IV.POS.5 reward + zoned-step prior | ✓ Reward ablation anchor. |
| **G\*** | G with `no_Qloc_reward` | **V3** (`kindUCB_zoned_v2_noQ`) — new v2 reward + zoned-step prior | ✓ Reward ablation pair with V2 (D31 clarification applies). |
| **H** | `kind_TS + zoned_step + discovery_reward` | **V4** (`kindTS_zoned_v2`) — Bernoulli TS + v2 reward + zoned-step prior | ✓ Selector ablation. |
| **I** | `constrained_TS + semantic_zone_step + discovery_reward` | **V5** (`cTS_semantic_v2`) — constrained TS + semantic zones + v2 reward | ✓ **Main candidate (5/5 criteria)**. |

**Why these 5 and not the others.** The 5 variants we ran form a clean factorial isolation: (V2 vs V3) isolates legacy reward → v2 reward; (V3 vs V4) isolates kindUCB → kindTS; (V4 vs V5) isolates kind-only arms → semantic-zone arms + constraint floors. Variants A, C, D, E, F either reproduce known anti-patterns (D/E from IV.POS.5) or are too close to V1/V2/V5 to add isolation power.

**What §9 isolation we still lack.** No standalone "singleton boundary only" (C); no bucket-count sweep (D/E); no kind_UCB with uniform step prior in the production suite (F). If any of these would change your evaluation, name it; each costs ~3.5 hours wall-clock per seed on our infrastructure.

---

## §6 Open questions for your reasoning

These materially shape IV.POS.8 design or the path to beating arguzz. The numbering continues from your existing question framing (Q1, Q2, Q4, Q5 from your §6/§7/§10; Q3 is new).

### Q1 — Is `address_bucket` (log2-range, 32 bins) too geometric?

Your §5–§6 warned against rewarding "different memory byte touched." We adopted §5 verbatim with log2 bucketing (D17), but `address_region × address_bucket` produces up to 32 keys per region, which encodes a coarse geometric signal — particularly in user-mode addresses, where almost everything (code, data, heap, stack, HOST_ECALL_ADDR buffer) maps to `region = user` and `address_bucket` is the only fine-grained discriminator within that region (D8).

Variant I's +30.4% compressed-global-context delta over variant B is real either way; the question is whether the metric is rewarding the *right* signal.

- **(a)** Status quo: 32 log2 bins per region.
- **(b)** Drop `address_bucket` entirely; region-only. (User-space CGC collapses to ~1 key per `(txn_role, cycle_phase)`.)
- **(c)** Coarser bucketing: log4 → 16 bins, or page-level → ~22 bins per 4MB user-space block.

**Your verdict for IV.POS.8?**

### Q2 — Is the parallel-execution noise floor acceptable for the headline variant comparison?

We discovered during validation that paired runs of the same mutation + same seed + same node + same binary occasionally differ on a single Poseidon2 sub-cycle, caused by a Rust Rayon + C++ poolstl race. The race never changes constraint pass/fail decisions (those are bit-identical A vs B) — only the bandit reward telemetry drifts.

| Configuration | Rate of single-cycle difference | Wall-clock cost |
|---|---|---|
| Default parallelism | ~0.7% of mutation pairs | 1× |
| `RAYON_NUM_THREADS=1` | ~0.14% (residual likely from C++ poolstl) | 3–4× slower |

Aggregate impact at N=500 per variant: kind-pull total-variation-distance ≤ 0.075 across variants; on variant I's 48-arm fine-grained allocation, TVD reaches 0.24; failure-constraint IoU 74–100% across variants.

1. Is 0.7% reward-signal noise acceptable at N=6000 × 10 seeds for the V1–V5 comparison?
2. Given the aggregate TVD, should we report variant I's wins with wider error bars, run 20 seeds in IV.POS.8, or enable `RAYON_NUM_THREADS=1` *selectively* on variant I (most race-sensitive)?
3. Worth filing an upstream RISC0 issue documenting the parallel-execution non-determinism, or is this strictly a fuzzing-noise concern that doesn't affect production zkVM users?

### Q3 — Forward architecture: complementary arguzz kinds, or pure-A4 semantic refinement?

**Background you may not have.** A4 (variants B–I) and arguzz attack the zkVM at *different layers*:

- **arguzz** mutates the executing program at the **pre-/post-execution boundary of a single RISC-V instruction**. Its mutation kinds (11 in total, from a parallel N=250-per-kind triple-distribution audit at `thesis_side_experiments/full_sweep/artifacts/e5/TRIPLES_N250.md`) fall into three architectural groups: **(i) instruction-rewrite** (`INSTR_WORD_MOD` rewrites the 32-bit instruction at the targeted step, `BR_NEG_COND` negates a branch condition, `LOAD_VAL_MOD` / `STORE_OUT_MOD` / `COMP_OUT_MOD` rewrite the value involved in a load/store/compute), **(ii) pre-execution state** (`PRE_EXEC_REG_MOD`, `PRE_EXEC_MEM_MOD`, `PRE_EXEC_PC_MOD` perturb a register / memory cell / PC right before the instruction runs), and **(iii) post-execution state** (`POST_EXEC_REG_MOD`, `POST_EXEC_MEM_MOD`, `POST_EXEC_PC_MOD` perturb the same right after). arguzz is instruction-aware: each mutation kind is a no-op (`<fault>` tag absent) when the kind does not apply to the instruction at the selected step, so the effective applied-rate per kind varies with the guest's opcode mix. Strength: reachability via valid-then-perturbed executions; pre-/post-state mutations propagate through the rest of the trace via real RISC-V semantics, and the same triple-distribution audit shows arguzz cascades much more across cycles than A4 (interstep-fire rate ≈ 55% pooled across applied trials vs ≈ 23% for A4), producing a qualitatively different constraint-failure pattern.
- **A4** mutates **trace cells** (registers, mem-txns, control words) at the circuit-witness layer *post*-execution. Mutations are surgical — one cell per witness — and target named constraint sites directly. Strength: precision and per-mutation locality; in the same audit, A4 mutations almost never produce a "no constraint broken" outcome (0.0% on the pooled trial set), whereas arguzz's pre-/post-PC mutations can leave the trace internally consistent (e.g. `POST_EXEC_PC_MOD` has ≈ 21% triples with no broken constraint, because the perturbed PC is still a valid jump target).

Empirically these surfaces overlap heavily but are not identical. Variant I found 4 kernel/ECALL contexts (`ControlLoadRootAndNonce@inst_control.zir:{35,44,45}`, `ControlMRET@inst_control.zir:93`) that variant B does not reach. Direct A4-vs-arguzz quantification on the IV.POS.7 ablation surface (V6) is in flight and deliberately deferred from this packet (§7 item 4); we will deliver the head-to-head numbers in a separate report.

**Two long-term paths to beating arguzz on bugs-per-wall-clock:**
- **(P1) Hybrid scheduler.** Add arguzz-style instruction-word mutations as new kinds in A4's constrained TS, extending the `(kind, zone)` arm space. Variant I's selector would allocate budget adaptively between trace-cell and instruction-word mutations. ~2-week integration sprint.
- **(P2) Pure-A4 deepening.** Refine the semantic zones further (split `kernel_other` per opcode class; add MRET/halt detection by extending the C++ inspector); add the two TXN_PREV mutation kinds from your §11 step 3. Stays pure A4; each increment is a 2–3 day audit cycle.

**Which trajectory has higher expected discovery yield per engineering day, given the IV.POS.7 evidence in the results report?** Secondary: is there a third path we are not considering?

### Q4 — IV.POS.8 scope and protocol

Five candidates; we want your prioritization.

- **(a)** Variant I at **N=12000** paired-seed asymptote test — confirms whether the +30.4% CGC gap closes or widens at larger N. Cheap (~24h wall-clock).
- **(b)** Variant I hyperparameter sensitivity sweep around `coverage_floor_fraction` (0.50, 0.55, 0.60, 0.65) and singleton minimum pulls (3, 5, 8) — confirms 0.55 is robust. Medium (~3 days).
- **(c)** A4 vs arguzz head-to-head on a normalized metric (mutations per discovery, wall-clock per discovery, A4-reachable territory only) — answers Q3 with clean N=10 V6 data. Expensive (~1 week incl. arguzz instrumentation).
- **(d)** Reward signal refinement: variant I's per-pull discovery rate for `INSTR_TYPE_MOD` *dropped* vs variant B (30.4 → 19.9 per 1000 pulls) while absolute discoveries rose (230 → 261) because variant I allocates 73% more pulls there. The Bernoulli success signal doesn't distinguish "first discovery on a saturated arm" from "first discovery on an explorable arm." At variant I's near-saturation in the legacy 46-context universe, should the reward include a **decay term** for arms whose marginal contexts are nearly exhausted, or is the floor schedule sufficient regardless?
- **(e)** Stay A4-only until multi-guest work lands (Q5).

If you can only pick one, which? Full prioritization if possible.

### Q5 — Generalization to a second guest (your §11 step 5)

The arm universe is **dynamic per guest** (§2.6). Empty zones today (`pre_mret`, `post_mret`, `pre_halt`, `post_halt`, `core_sha`, `core_poseidon`, `core_other`, `core_shr`) would auto-populate on guests that exercise them — **provided** the classifier limitations are addressed (MRET/halt detection currently requires extending the C++ inspector; see §2.5).

Two candidate next guests:
- **(g1)** RISC0 stock SHA example — ~1 day work, would populate `core_sha`. Cheap.
- **(g2)** Code that exercises MRET / halt-rich paths (e.g., a guest that explicitly triggers user-mode trap handling) — would require extending the C++ inspector (~1 week) before the 4 MRET/halt zones become non-empty.

**Should g1 be in IV.POS.8 as cheap insurance, or wait for a campaign dedicated to multi-guest validation?**

---

## §7 Things you might want, surfaced even though you didn't ask

Things we did, found, or could not do that aren't directly part of your §-numbered recommendations but may shape your reasoning. Each summarized in one line; deeper material on request (§8).

| Item | One-line summary | Why surface |
|---|---|---|
| **4 MRET/halt zones unreachable on sha2-host** (D14 + §2.5) | Classifier cannot distinguish MRET from ordinary branches because both fall under `major=7` without re-decoding the instruction word | Limits variant I's generalization claims to non-MRET-heavy guests until C++ inspector is extended; affects Q5 |
| **Hook-fidelity audit and dispositions** | ~4000 mutations audited; net pass ≥ 99.9% after 6 documented architectural-boundary exclusions; **zero unclassified failures** | The exclusions are properties of the modified RISC0 binary (ECALL `major=8` vs decoded=7; multi-cycle steps; non-deterministic mem-txns at `HOST_ECALL_ADDR`; 2 `old_word`-only patterns at ECALL boundaries). If you disagree any exclusion is a hidden bug, IV.POS.7 validity is affected. |
| **Variant G (V2) reproduces the IV.POS.5 pathology** (§4-D33) | 85% of late-epoch pulls collapsed onto `INSTR_WORD_MOD_SUR`; final = 31.8/46 contexts (vs variant B's 42.9) | Confirms your §3–§4 diagnosis under cleaner experimental conditions (D2 calibration lock, identical reward, no nested step UCB confound). Extra confidence that the variant I architecture changes are the right fix, not noise. |
| **V0 uniform-baseline ablation (internal, complete)** | 10/10 seeds done; numbers held back from this packet | V0 is the true uniform-over-kinds anchor (variant B already contains the zoned step prior). Numbers held back to avoid mid-review re-interpretation of variant B; full V0 write-up will accompany IV.POS.8. |
| **V6 arguzz reproduction (internal, in flight)** | 4 of 10 seeds done at time of packet | Direct A4-vs-arguzz on a normalized metric is exactly Q4-(c). We deliberately withhold preliminary numbers — a 4-seed estimate that may shift materially at N=10 is worse than waiting for clean data in IV.POS.8. |

---

## §8 Pointers — detail available on request

| Document | Contents |
|---|---|
| `CLOUD1_DECISIONS_FOR_PRO_R2.md` | Full ~55 decision entries with rationale, including all Phase 7d audit decisions |
| `EXPECTED_ARMS.md` | Canonical 48-arm matrix for sha2-host (per-input variants); arm-by-arm step counts; categorization-uncertainty annotations |
| `V5_ARCHITECTURE_GUIDE.md` | Long-form variant I (V5) walkthrough: design philosophy, mode-by-mode mechanics, hyperparameter rationale, freeze protocol |
| `RACE_FINDING_AND_OPEN_QUESTIONS.md` | Q2 race deep-dive (the ~0.7% reward-noise finding) |
| `PHASE_7D_INC3D_B1_DISPOSITION.md` | Hook-fidelity verifier disposition framework (§7 item 2) |
| `INTERNAL_V0_V6_ANALYSIS.md` | V0 anchor + V6 fairness analysis (internal; to accompany IV.POS.8) |
| Raw CSVs / 50 SQLite databases | Regenerate via `analysis/build_artifacts.py`; aggregates in results report appendices |

**Not pre-loaded:** per-arm semantic-correctness evidence packs (48 markdown files), Phase 7d increment reports, full B1 disposition JSON — available if you request specific audit IDs.

---

## §9 Appendix — Unexplored A4 mutation surface (forward-looking)

This appendix is a forward-looking inventory of A4 mutation kinds we **have not implemented** but could add to expand the mutation surface beyond the 8 kinds used in IV.POS.7. It pairs with §6-Q3 (P2 "pure-A4 deepening" path): if you favor extending A4 over hybridizing with arguzz, these are the candidates.

**Disclaimer.** None of the mutation kinds below have been implemented, fuzzed, or evaluated. We have not yet investigated whether any of them produce useful constraint coverage, whether they crash witness generation, or whether they overlap meaningfully with the existing 8 kinds. The taxonomy is derived from a static read of the modified RISC0 preflight-trace data structures (verified against `workspace/risc0-modified` source on 2026-06-16) plus a planning document at `a4/docs/standalone/MUTATION_TAXONOMY.md`. **Treat this as a "what could exist if you built it" inventory, not as evidence about what does or would help.** Concrete payoffs require N=50-200 smoke campaigns per new kind.

### §9.1 The full post-execution trace data structure

A4 mutates the **preflight trace** — RISC0's intermediate representation produced by `Segment::preflight()` (`workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs:95-111`) after executing the guest, before witness generation. It is the surface where the trace is materialized as concrete `(cycle, transaction)` records but before the circuit constraints have been evaluated. Verified definitions:

**`PreflightTrace`** — top-level container (`workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs:63-75`):

```rust
pub(crate) struct PreflightTrace {
    pub cycles: Vec<RawPreflightCycle>,      // one entry per circuit cycle
    pub txns: Vec<RawMemoryTransaction>,     // memory/register read & write records
    pub bigint_bytes: Vec<u8>,               // BigInt accelerator byte stream
    pub backs: Vec<Back>,                    // per-special-cycle back-state (Poseidon2/Sha2/BigInt/Ecall)
    pub table_split_cycle: u32,              // boundary cycle for the U8/U16 lookup tables
    pub rand_z: ExtVal,                      // checksum randomness (FpExt)
}
```

**`RawPreflightCycle`** — one entry per cycle (`workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs:33-49`):

```rust
#[repr(C)]
pub struct RawPreflightCycle {
    pub state: u32,           // CycleState enum (Decode=48, MachineEcall=8, PoseidonEntry=16, ShaEcall=32, BigIntEcall=40, etc.)
    pub pc: u32,              // NEXT PC after this cycle's instruction executes
    pub major: u8,            // 0..=12 (MISC0..BIGINT0, see platform.rs::major)
    pub minor: u8,            // 0..=7 within the major
    pub machine_mode: u8,     // 0 = user, 1 = machine
    pub padding: u8,
    pub user_cycle: u32,      // step index (1 per logical instruction; multi-cycle steps share)
    pub txn_idx: u32,         // index into PreflightTrace::txns where this cycle's transactions start
    pub paging_idx: u32,      // index into paging operation stream
    pub bigint_idx: u32,      // index into bigint_bytes
    pub diff_count: [u32; 2], // memory-diff bookkeeping
}
```

**`RawMemoryTransaction`** — one per memory or register read/write (`workspace/risc0-modified/risc0/circuit/rv32im-sys/src/lib.rs:20-31`):

```rust
#[repr(C)]
pub struct RawMemoryTransaction {
    pub addr: u32,        // WORD address (byte_addr / 4)
    pub cycle: u32,       // memory cycle: READ if even, WRITE if odd
    pub word: u32,        // current value at addr
    pub prev_cycle: u32,  // cycle number of the previous access to addr
    pub prev_word: u32,   // previous value at addr (must equal word for READ per IsRead constraint)
}
```

User registers `x0`..`x31` are mapped to word addresses `[0x3FFFC020, 0x3FFFC040)` (corresponding to byte addresses `[0xFFFF_0080, 0xFFFF_0100)` per `platform.rs::USER_REGS_ADDR`); all other addresses are ordinary memory.

**`Back`** — per-special-cycle state (`workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs:50-61`):

```rust
pub(crate) enum Back {
    None,
    Ecall(u32, u32, u32),          // syscall params
    Poseidon2(Poseidon2State),     // Poseidon hash internal state
    Sha2(Sha2State),               // SHA-256 internal state
    BigInt(BigIntState),           // BigInt accelerator state
}
```

### §9.2 Coverage of the post-execution surface by the 8 IV.POS.7 kinds

The 8 mutation kinds we used in IV.POS.7 touch only **2 of the 5 PreflightTrace fields** and only **2 of the ~16 leaf fields** below them:

| PreflightTrace field | Fields actually mutated by the 8 kinds | Untouched fields |
|---|---|---|
| `cycles[]` | `cycles[].major`, `cycles[].minor` (INSTR_TYPE_MOD only) | `state`, `pc`, `machine_mode`, `user_cycle`, `txn_idx`, `paging_idx`, `bigint_idx`, `diff_count` |
| `txns[]` | `txns[].word` (multiple kinds, multiple contexts) + `txns[].prev_word` (only as a co-mutation in INSTR_WORD_MOD to satisfy IsRead) | `addr`, `cycle` (R/W bit), `prev_cycle`, `prev_word` as a first-class target |
| `bigint_bytes` | — | entire array |
| `backs` | — | all 4 variants (Ecall params, Poseidon2State, Sha2State, BigIntState) |
| `table_split_cycle` | — | — |
| `rand_z` | — | — |

So the IV.POS.7 mutation surface targets a single value-field (`word`) across multiple contexts, plus the cycle-classification fields (`major/minor`). Every other field of the post-execution trace is currently untouched.

### §9.3 Forward-looking mutation kinds (taxonomy, not commitments)

Grouped roughly by expected risk and what they would test. **Numbers in `[brackets]` are taxonomy IDs from `a4/docs/standalone/MUTATION_TAXONOMY.md`; "expected constraint failure" labels are predictions, not measurements.**

**Low-risk, novel-field targets (likely Bernoulli-success-generative):**

- `[3.8] TXN_PREV_WORD_MOD` — mutate `txns[].prev_word`. For READs the circuit enforces `word == prev_word` (IsRead constraint); for WRITEs `prev_word` is used for write consistency. Currently only set as a side-effect of INSTR_WORD_MOD; never mutated independently. Targets the IsRead constraint directly.
- `[3.9] TXN_PREV_CYCLE_MOD` — mutate `txns[].prev_cycle`. Tracks when the address was last accessed; mutating breaks the temporal ordering required by the memory permutation argument. Pairs with Hook 3's `cycle` family residue.
- `[3.14] CYCLE_MODE_MOD` — flip `cycles[].machine_mode` (0 ↔ 1). Tests user/machine privilege constraints. On sha2-host the kernel/user PC partitioning we exploit in `kernel_other` would have a parallel `machine_mode` partition this would target.

**Medium-risk, broader-blast-radius:**

- `[3.10] TXN_ADDR_MOD` — mutate `txns[].addr`. Likely large blast radius (every constraint touching the txn's address chain breaks); may crash witgen if mutated to an unmapped page.
- `[3.11] TXN_CYCLE_PHASE_MOD` — flip the even/odd bit of `txns[].cycle`, converting a READ into a WRITE or vice versa. Directly attacks the circuit's R/W classification.
- `[3.12] CYCLE_PC_MOD` — mutate `cycles[].pc`. The next-PC field; the instruction-fetch address is computed from `(pc-4)/4`. Different angle on the same fetch-consistency constraints INSTR_WORD_MOD targets.
- `[3.13] CYCLE_STATE_MOD` — mutate `cycles[].state` (CycleState enum: `Decode=48`, `MachineEcall=8`, `PoseidonEntry=16`, `ShaEcall=32`, `BigIntEcall=40`, etc.). Tests the cycle-state-machine transition constraints. Would touch the `step_Top` dispatch logic in the circuit.
- `[3.16] CYCLE_DIFF_COUNT_MOD` — mutate `cycles[].diff_count[0]` and/or `[1]`. These feed memory-diff bookkeeping; their consistency constraints are not currently exercised by any A4 kind.

**Higher-risk, structural / accelerator-internal:**

- `[3.15] CYCLE_INDEX_MOD` — mutate `cycles[].txn_idx`, `cycles[].paging_idx`, or `cycles[].bigint_idx`. These are pointers between the trace's three parallel arrays; mutating likely produces out-of-bounds or structural inconsistency that crashes witgen rather than producing a clean constraint failure.
- `[3.18] BIGINT_DATA_MOD` — mutate bytes in `bigint_bytes[]`. Only fires on guests that exercise BigInt (RSA, ECDSA, large-modulus crypto); on sha2-host this would be a no-op (`bigint_bytes` is empty).
- `[3.19] CRYPTO_STATE_MOD` — mutate fields inside `backs[]::Poseidon2(Poseidon2State)` or `backs[]::Sha2(Sha2State)`. Internal hash-state mutations; only fires on cycles whose `state` is in the Poseidon or SHA ranges.
- `[3.20] ECALL_BACK_MOD` — mutate the `(u32, u32, u32)` payload inside `backs[]::Ecall(...)`. Targets syscall-handling constraints; sha2-host has 33 ECALL cycles so this would have arms to pull.
- `[3.21] STRUCTURAL_MOD` — mutate `table_split_cycle` or `rand_z`. Trace-level scalars that affect U8/U16 lookup-table generation and the LogUp checksum randomness respectively. Likely catastrophic.

**Gap-filler kinds (extend existing mutations to new contexts):**

- `[3.17] REG_TXN_NON_INSN_MOD` — currently `PRE_EXEC_REG_MOD` targets only register transactions at `major ∈ [0, 6]` (instruction cycles). Register transactions also occur at non-instruction cycles (`major ≥ 7`: CONTROL, ECALL, POSEIDON, SHA, BIGINT); those are not mutated by anything. This kind would extend the existing `prev_write` / `next_read` strategies to that population.

### §9.4 What this would change for variant I's arm space

If even a subset of the kinds above were implemented, the per-zone arm count grows because each new kind multiplies into the 11 populated zones for sha2-host. As a rough order-of-magnitude (assuming, optimistically, ~half of the new kinds apply at most zones), adding 6 new kinds would expand the arm universe from 48 to ~80–110 arms. Variant I's constrained-TS scheduler would absorb this automatically (the arm universe is rebuilt per guest from `InspectionData`), but the cold-start cost (3 pulls per arm) and per-epoch floor cost (~1.15 pulls per arm per epoch) both scale linearly — at N=6000 the floor would dominate even more aggressively than today's 93.6%. This is a knob the IV.POS.8(b) hyperparameter sweep (§6-Q4) would need to widen to evaluate.

### §9.5 What we want from Pro on this

**Two questions, both subordinate to Q3:**

1. Of the kinds above, which (if any) would you expect to extend A4 into territory arguzz reaches but variant I currently does not? Specifically, would you prioritize the **low-risk novel-field** group (TXN_PREV_WORD/CYCLE, CYCLE_MODE), the **medium-risk** group (TXN_ADDR, TXN_CYCLE_PHASE, CYCLE_PC, CYCLE_STATE), or the **gap-filler** REG_TXN_NON_INSN?

2. Is there a category of post-execution mutation we are missing entirely (e.g., paging/page-table state, or cross-segment continuation fields) that the data structures above suggest but we have not enumerated?

---

*End of brief. Use the results report for numbers; use §6 for forward reasoning; use §9 for the forward-looking mutation-expansion question.*
