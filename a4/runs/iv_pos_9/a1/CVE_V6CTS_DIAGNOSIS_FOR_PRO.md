# CVE race — V6-cTS failure diagnosis + variant-design brief (for Pro)

**Purpose:** give Pro the full DB-extracted evidence to (1) diagnose why **V6-cTS finds 0** rs2-alias CVEs
while **V6-uniform finds 9**, and (2) design a new variant (or fix cTS) that **beats uniform** at this bug.
All numbers are from the live CVE-race DBs (`a4/runs/iv_pos_9/race/cve_results`, batches 1–3 = **6
seeds/variant**, B2 vulnerable build, guest `remu a0,a1`+`divu a2,a3`). Companion: mechanism narrative in
`WHY_V6CTS_MISSES_THE_CVE.md`; this doc is the **data**.

---

## 0. TL;DR — three independent failure layers (cTS hits all three)
1. **Wrong cycle of a multi-cycle op.** The rs2-alias is only triggerable by `INSTR_WORD_MOD` at the
   division **fetch/decode** cycle (remu=step 444, divu=step 449). cTS pours its division budget into the
   division **compute** cycles (zone `core_div`, steps 436/441) where the instruction word's rs2 field
   isn't in play. **223+223 pulls on the wrong cycles; 2+0 on the right ones.**
2. **Zone dilution of the right cycle.** The fetch cycles land in **huge zones** — divu@449 ∈
   `core_arithmetic` (**1056 distinct steps**), remu@444 ∈ `core_memory_store` — so the
   `INSTR_WORD|core_arithmetic` arm's ~238 floor-pulls are spread uniformly over 1056 steps → the divu
   fetch gets **~0.2 pulls**. (Within-arm step pick is uniform: `bandit_ts.py:287`.)
3. **No reward for the bug.** cTS's reward is coverage/failure-based; an accept-of-wrong is a *valid*
   execution of a mutated instruction → **no new coverage → ~0 reward**. Even if cTS hit the alias, the
   bandit would not reinforce it. (cTS reward | accepted = **0.0000**, | rejected = 0.0000.)

V6-uniform sidesteps all three: its `ArguzzScheduler` round-robins **instruction-kinds**, so the rare
`remu`/`divu` kinds map straight to their fetch steps (444/449) and get a full, coverage-blind share.

---

## 1. The outcome (replay-confirmed by committed output; honest=9000027, remu-alias=0, divu-alias=9000028)
| variant | scheduler | CVE finds (6 seeds) | per-seed | found in |
|---|---|--:|--:|--:|
| **V6_uniform** | ArguzzScheduler (instruction-kind round-robin) | **9** (3 remu + 6 divu) | ~1.5 | 4/6 seeds |
| V6_cTS | ConstrainedTSScheduler (coverage bandit + 0.55 floor) | **0** | 0 | 0/6 |
| Hybrid_cTS | cTS over A4∪Arguzz surfaces | **0** | 0 | 0/6 |
| V5_control | A4 only (post-exec) | **0** | 0 | 0/6 |

Per-attempt alias rate (uniform): **9 finds / 232 INSTR_WORD pulls on the fetch steps ≈ 1/26** (consistent
with the d=1 single-bit-flip rate; operands a0/a1, a2/a3 are 1 Hamming bit apart). Expected finds =
attempts × 1/26 → uniform 232/26≈9 ✓, cTS 2/26≈0.08→0 ✓. **cTS doesn't fail at aliasing; it fails at
landing INSTR_WORD on the fetch cycle.**

## 2. THE ALLOCATION GAP (the single most important table)
INSTR_WORD pulls on the division op's cycles (6 seeds). Fetch cycles (rs2-alias-able): remu=444, divu=449.
Compute cycles (zone `core_div`, NOT alias-able): 436/441.
| variant | **444 (remu fetch)** | **449 (divu fetch)** | 436 (div compute) | 441 (div compute) |
|---|--:|--:|--:|--:|
| **V6_uniform** | **114** | **118** | 0 | 20 |
| V6_cTS | **2** | **0** | 223 | 223 |
| Hybrid_cTS | 3 | 0 | 296 | 370 |
| V5_control | 0 | 0 | 298 | 305 |

uniform spends its division INSTR_WORD budget on the **fetch** cycles (232 total) → finds it. cTS spends
**446** on the **compute** cycles (where mutating the word can't create the rs2 alias) and **2** on the
fetch cycles. **cTS is hammering the division — just the wrong cycles of it.**

## 3. Mutation-kind distribution (% of all pulls) — cTS is NOT starving the *kind*
| kind | V6_uniform | V6_cTS | Hybrid | V5 |
|---|--:|--:|--:|--:|
| INSTR_WORD_MOD (arguzz) | 12.5% | **28.2%** | 11.5% | — |
| INSTR_WORD_MOD_FULL/SUR (a4) | — | — | 7.1%/7.0% | 8.3%/8.1% |
| (7 arguzz kinds, uniform) | ~12.5% each | (skewed) | — | — |
| INSTR_TYPE_MOD | — | — | 11.9% | 21.2% |
| TXN_PREV_*/CYCLE_DIFF (D2.B) | 0 | 0 | ~15% | ~33% |
cTS actually does **more** INSTR_WORD_MOD than uniform (28% vs 12.5%). The kind is fine; the **arm (kind,
zone) and step** are the problem.

## 4. Bandit allocation (cTS): mode split + arm structure
- `campaign_params`: `selector=v6_cTS, bernoulli_floor=true, floor=0.55, num_arms=417`.
- **Mode split (6 seeds, 30000 pulls):** floor **40%**, adaptive **33%**, cold **26%**, singleton **1%**.
- **417 arms**, each `arguzz_exec_fault|KIND|zone|opcode_class|pre_post`. Top arm = 1.2%; very flat.
- **54 INSTR_WORD arms, 28.2% of pulls, almost entirely `floor` mode** (e.g. one arm: cold 20, floor 237,
  **adaptive 0–1**). The adaptive (exploit) tier essentially **never** re-selects an INSTR_WORD arm.
- The two arguzz division arms `INSTR_WORD_MOD|core_div|{arithmetic,memory_load}|pre_exec` got **223+223 =
  446 pulls, reward mean 0.0000** → pure floor, never exploited → and (per §2) they sit on the compute
  cycles, so even those 446 are wasted for the alias.

## 5. Zone sizes (the dilution denominators)
| zone | distinct steps (cTS) | contains |
|---|--:|---|
| `core_arithmetic` | **1056** | divu **fetch** (449) — diluted to ~238/1056 ≈ 0.2 pulls |
| `core_memory_store` | (large) | remu **fetch** (444) |
| `core_div` | **2** | division **compute** cycles (436/441) — where cTS's 446 pulls land |
| `core_mul` | 53 | (mul) |
Within-arm step pick is **uniform** (`bandit_ts.py:287` `rng.choice(steps)`), so an arm's pulls split
evenly over its zone's steps. The fetch cycle that matters is 1 of 1056 in its zone; the wrong-cycle zone
is tiny (2) so cTS over-invests there.

## 6. Reward signal — blind to soundness (the second lever)
- **cTS reward | verifier_accepted=1: 0.0000 (n=1430); | rejected: 0.0000 (n=28570).** Accept-of-wrong is
  **not** distinguished — the reward is coverage/failure-novelty (`T_new, F_new, Q_loc, Q_glob, discovery`),
  and an accept-of-wrong yields **no new coverage** → 0 reward.
- Division mutations' reward: `current_reward` mean **0.004–0.006** (essentially nil; coverage saturates
  after the first hit). `fnew_only` = 0. So the adaptive tier has no reason to revisit the division.
- **Counterfactual rewards** (`reward_counterfactuals`, on division-touching mutations):
  `discovery_binary` mean 0.023 (max **1.0** — fires occasionally), `no_qloc` mean 0.195, `fnew_only` 0.
  → None of the *existing* reward variants rewards accept-of-wrong; a **new** soundness term is needed.
- (Hybrid's accept-reward looks high — 0.907 — but that's its benign A4 TXN/CYCLE accepts producing touch
  coverage, **not** the rs2-alias, which is rejected; see §7.)

## 7. The A4 surface reaches the alias but can't keep it (coherence) — `mutation_substrategy`, no replay
Decoding each mutated instruction's `rs1/rs2` directly:
| variant (a4 path) | division-decoded INSTR_WORD muts | **rs1==rs2 (alias) attempts** | **accepted** |
|---|--:|--:|--:|
| V5_control | 343 | **24** | **0** |
| Hybrid_cTS | 303 | **29** | **0** |
A4/Hybrid *do* construct the rs2-alias (24/29×) via post-exec `INSTR_WORD_MOD_SUR/FULL`, but **0 verify** —
the result cell isn't recomputed ⇒ `C_local` fires ⇒ reject. This is the coherence wall, confirmed
structurally. (V6_cTS/V6_uniform use the arguzz `--inject` path, whose mutated word isn't decoded into
`mutation_substrategy`, so their alias attempts are counted via §2's step pulls + replay instead.)

## 8. Why V6-uniform wins (the baseline to beat)
`ArguzzScheduler.pick()` = **least-used candidate instruction-kind first** (round-robin over
instruction-kinds), then step+kind. The scheduling unit is the **instruction-kind**, so:
- `remu` and `divu` are each their **own kind** → guaranteed equal share regardless of rarity → their
  fetch steps (444/449) get ~114/118 INSTR_WORD pulls.
- **No reward term** → coverage saturation never withdraws budget.
Uniform is "dumb" in exactly the way this bug needs: it keeps hammering one rare instruction.

## 9. Design options for a variant that BEATS uniform (with the lever each pulls)
The bug needs **depth on one rare instruction's fetch cycle**. Ranked by expected impact:

**(A) Instruction-aware arms (fix the granularity) — highest leverage.**
Make the arm key include the **instruction mnemonic** (or at least separate *fetch* from *compute*
cycles), so `(INSTR_WORD_MOD, remu)` and `(…, divu)` are their own arms. Then the floor (even at 0.55/417)
guarantees them a minimum, and they're not diluted across a 1056-step zone. *Evidence it would work:* the
only thing uniform does differently is treat instruction-kind as the unit (§8); under per-instruction
arms the floor alone gives remu ≈ `0.55·5000/n_arms` ≫ 2 pulls/seed.

**(B) Fetch-cycle-weighted within-arm step pick (fix the dilution) — cheap, composable.**
Replace the uniform `rng.choice(steps)` (`bandit_ts.py:287`) with a weighting that favors
**instruction/decode cycles** over compute/lookup cycles (or inverse-frequency over the zone's
instruction mnemonics). Directly counters the 1/1056 dilution and the wasted `core_div` compute-cycle
pulls (§2, §5).

**(C) Soundness reward term (fix the reinforcement) — needed to *exploit*, not just *reach*.**
Add an **accept-of-wrong / journal-divergence** reward (verifier_accepted AND committed≠honest, or a
constraint-residual proxy) so the adaptive tier *re-invests* once an arm yields a near-miss/find. Today
that signal is reward-invisible (§6). Best combined with (A)/(B): (A)/(B) get cTS to *reach* the alias;
(C) makes it *stay*. Note `discovery_binary` already fires to 1.0 occasionally — a soundness term is the
missing piece.

**(D) Uniform-floor hybrid scheduler.**
Keep cTS's adaptive tier for general coverage but replace the per-arm floor with a **per-instruction-kind
round-robin floor** (uniform's mechanism) for a fraction of pulls. Guarantees rare instructions the
uniform-style share while retaining bandit exploitation elsewhere. Most directly "beats uniform" =
uniform's strength + cTS's adaptivity.

**(E) Rarity/idle-time prior.**
Initialize/boost arm priors by **inverse instruction frequency** (rare instructions get higher initial
α), or add an idle-time/UCB exploration bonus so a long-unpulled rare arm resurfaces. Counters coverage
saturation without a new reward channel.

**Recommended combination to *beat* uniform (not just match):** **(A) instruction-aware arms + (C)
soundness reward.** (A) removes the targeting penalty (so cTS at least matches uniform's hammering of the
rare op); (C) lets the bandit *concentrate* on a productive arm once it gets a hit — which uniform's
coverage-blind round-robin can't do — so cTS would find it *faster* than uniform (uniform keeps wasting
~7/8 of its INSTR_WORD budget on non-vulnerable instructions; a soundness-reward bandit would shift budget
toward the rs2-alias arm after the first near-miss).

## 10. Data Pro may still want (extractable on request)
- `bandit_decisions.score`/`runnerup` time series for the division arms (exploit-vs-floor margin).
- `reward_counterfactuals` aggregated specifically over the **fetch-cycle** mutations (not all division).
- Full **10-seed** numbers (batches 4–5 finishing ~15:25 UTC) — current numbers are 6 seeds.
- `local_coverage_v2`/`coverage` saturation curves (when the division arm's novelty died).
- A small **simulation**: replay cTS allocation with arm=instruction to estimate finds under option (A).

## 11. Caveats
- 6 seeds (batches 1–3); the allocation/zone mechanism is structural so it will hold for 10, but find
  *counts* will grow for uniform.
- Two step indexings exist (arguzz `--inject`: fetch 444/449; a4-cli/zone: compute 436/441) — §2 reports
  the `--inject` steps the race/replay actually used; the zone classifier's `core_div@441` is the compute
  cycle (a red herring for the alias).
- Per project constraint, Arguzz itself is **not** modified; options (A)–(E) target the **a4-side
  scheduler** (`bandit_ts.py`/`semantic_arm_universe.py`) that drives V6-cTS/Hybrid, which is ours to change.
