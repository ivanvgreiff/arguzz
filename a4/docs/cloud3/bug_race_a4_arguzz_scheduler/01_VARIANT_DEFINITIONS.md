# V0 & V8 — precise definitions, distinction, and the design choices

> ⚠️ **ROUND-2 SUPERSEDES PARTS OF THIS DOC.** Where this doc proposes **V8 = round-robin over A4 *arms***, that is **wrong** — the lead corrected it: **V8 has no arms** (Arguzz instruction-balanced site-selection → A4 INSTR_TYPE_MOD, with mandatory executor→user_cycle step-domain translation). And **V0 uses the up-to-date `SemanticArmUniverse`** (5-field `ArmKey`, A4 collapses to kind|zone), not the geometric universe. See the **ROUND-2 block in `00_OVERVIEW.md`** (authoritative) and `02 §A`. The arm-space + V0/V5 material below remains correct.

Companion to `00_OVERVIEW.md`. All claims verified against the code by the research agents; file:line cited.

## 1. The scheduler abstraction (why this is well-posed)
- **A4 arm space is scheduler-agnostic.** Two builders exist, both built purely from `InspectionData.get_valid_steps_for_kind(kind)`:
  - **Geometric** `ArmUniverse` → arms = `(kind, time-bucket)` (`arm_universe.py:63-172`). Already driven by *two* schedulers: `DiscountedUCBScheduler` (bandit) **and** `UniformArmSelector` (no-reward) — proof the same A4 arms accept different schedulers.
  - **Semantic** `SemanticArmUniverse.build(data, mutation_kinds)` → arms = `ArmKey.v5(kind, zone)` (`semantic_arm_universe.py:234-330`). This is V5's arm space. Pure-A4 = don't pass `arguzz_kinds`.
  - A scheduler only needs `universe.available_arms`, `steps_for_arm(arm)`, `singleton_arms()` (`bandit_ts.py:165-166,282-287`) + a step picker (`SemanticZoneStepSelector.pick_step_in_zone`, `step_selector.py:503-515`). **This is the seam V0 and V8 plug into.**
- **Dispatch is NOT a registry** — it's hardcoded string `if/elif` across: `cli.py:205-221` (`--selector choices`), `fuzzer.py:137-156` (frozensets `V2_BANDIT_STRATEGIES` / `ALL_SEMANTIC_CTS_STRATEGIES` / …), `fuzzer.py:349-353` (`__init__` defer), `fuzzer.py:1838-1855` (`run_campaign` setup switch), `fuzzer.py:1862-1867` (per-mutation run dispatch), `step_selector.py:536-583` (`create_selector`, legacy step selectors only). **Every new selector must be threaded through each of these.**

## 2. V0 — A4 surface, uniform, no bandit
**Mechanism** (`UniformArmSelector`, `step_selector.py:416-454`; `MAB_DIAGNOSTIC…md:177-178`):
```
(kind, bucket) ← uniform_random(available_arms)     # uniform over ARMS, not kinds, not positions
step           ← uniform_random(steps_in_arm[kind,bucket])
# no reward, no .update(), no posterior — record_bandit_decision is never called
```
- Setup `fuzzer.py:985-1015` (`_setup_uniform`), run via `_run_single_mutation` (the `is_uniform` branch). No bandit update anywhere.
- **Historical V0** used the **geometric** `(kind,bucket)` space → differs from V5 (semantic `(kind,zone)`) in *arm discretization* as well as scheduler. Past run: IV.POS.7, 10 seeds 1234–1243, N=6000, `--selector uniform` (pin `--b-count`: the IV.POS.7 batch used `b_count=16`; the IV.POS.5 A/B used 128 → 967 arms; **the bucket count changes the arm universe + the per-kind skew, so pin it explicitly**).
- Performance anchor (IV.POS.7, `INTERNAL_V0_V6_ANALYSIS.md:54-73`): V0 local_final 35.0 (vs V5 46.4); CGC 140.7 (vs V5 188.1) — V0→V1 zoned step buys local but its CGC gain is *not significant*; most of V0→V5 CGC came from the bandit.

**Decision 1 — which arm space for the race V0?**
- (1a) **Geometric `(kind,bucket)`** = the literal historical V0. Pro: faithful "V0". Con: differs from V5 in 2 axes (scheduler + discretization) → not a clean scheduler ablation.
- (1b) **Semantic `(kind,zone)`** via a NEW `SemanticUniformArmSelector` (≈20 lines, mirror `UniformArmSelector` over `SemanticArmUniverse.available_arms`). Pro: V0 and V5 differ *only* in scheduler (uniform vs cTS) — the clean ablation. Con: not the literal historical V0 (but it is the *right* control for "does the bandit help on V5's surface").
- **Recommendation: 1b** as the primary V0 for the ablation; optionally also run the geometric historical V0 as a secondary anchor (cheap, binary-invariant). Note: cTS's floor mode does NOT collapse to V0 — even at floor=1.0 it (i) still updates the posterior and (ii) picks the *least-pulled* arm (balancing), not a uniform draw (`bandit_ts.py:205-299`). So V0 must be a genuine uniform selector, not a cTS config.

## 3. V8 — A4 surface, Arguzz-style scheduler (NEW CODE; the long pole)
**What "Arguzz's scheduler" is** (`ArguzzScheduler`, `iv_pos_7/drivers/v6_driver_v2.py:198-217`, imported by `v6_uniform_driver.py`):
```
instr ← balanced round-robin over RISC-V INSTRUCTION KINDS   # stateful _counter; least-pulled, rng tiebreak
step  ← uniform_random(instr_to_steps[instr])                # uniform site within that instruction
kind  ← uniform_random(valid_injection_kinds_for_instr(instr))  # uniform Arguzz injection kind
```
- **It cannot be reused for A4.** Its axis is RISC-V instruction mnemonics; its emitted kinds are Arguzz `ENABLED_KINDS` (`PRE_EXEC_PC_MOD`, `BR_NEG_COND`, … — and notably **`INSTR_TYPE_MOD` is NOT among them**). It executes via the Arguzz `--inject` host primitive, never the A4 `A4_MUTATION_CONFIG` path. So "ArguzzScheduler on A4 arms" is a category error — its arms ARE the Arguzz surface.
- **V8 = re-implement the *discipline*, not the class.** The discipline = "balanced round-robin over a kind-like axis → uniform site." On A4 there is no per-step instruction axis and the "injection-kind" third draw collapses (on A4 the kind IS the action). So V8 is a **2-draw** scheduler: `round-robin(arm) → uniform(step)`.

**Decision 2 — V8's round-robin axis?**
- (2a) over **A4 mutation kinds** (closest structural analog to Arguzz's instr-kind round-robin), then uniform step within the kind.
- (2b) over the **same `(kind,zone)` arms as V0/V5**, then uniform step within the arm.
- **Recommendation: 2b** — round-robin over the *same arm set* V0 samples uniformly, so V0-vs-V8 is exactly *uniform-random vs deterministic-balanced* over identical arms, and the whole A4 trio (V0/V5/V8) shares one arm universe. Implementation = a small `RoundRobinArmSelector` (a `_counter` over `available_arms`; pick least-pulled, rng tiebreak; `rng.choice(steps_for_arm)`), placed beside `UniformArmSelector` in `step_selector.py` (or as a scheduler in `bandit_ts.py`). No reward/update. ~30 lines.

## 4. V0 vs V8 — the definitive distinction
Same surface (A4), same arm set (if 1b+2b), same site rule (uniform within arm), **no reward feedback in either**. They differ ONLY in the kind/arm-selection discipline:

| | V0 (uniform) | V8 (round-robin) |
|---|---|---|
| arm selection | i.i.d. uniform each step (memoryless) | balanced round-robin (stateful `_counter`, deterministic + rng tiebreak) |
| per-arm allocation | proportional in expectation; finite-sample variance; (geometric V0: skewed by #buckets/kind) | enforced equal up to ±1 |
| determinism | stochastic | deterministic cycle |

It is the canonical *uniform-random vs round-robin* contrast — a real, defensible pair. At large N their *expected* per-arm allocation converges; they differ in finite-sample balance/determinism. **Both are wanted**: V0 = the unstructured stochastic floor; V8 = the structured non-learned balancer (the "fair scheduler that isn't a bandit").

## 5. Why the trio answers the thesis question
`P(find) = P(apply ITM) × P(find | ITM)` (ProG_Report_5 §3.7). `P(find|ITM)` is **bug-intrinsic** (~constant across schedulers, ~6.8%). The scheduler only moves the **first factor, `P(apply ITM)`**. So V0/V8/V5 isolate exactly how much each scheduling discipline (uniform / round-robin / learned) chooses the bug-relevant mutation — *the* scheduler-quality signal, holding surface + bug fixed.
