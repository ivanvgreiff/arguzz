# Appendix A — Full mechanics of the two schedulers (ArguzzScheduler / "V6_uniform" and ConstrainedTSScheduler / "V6_cTS")

Companion to `PRO_SCHEDULER_DIAGNOSIS_PACKAGE.md` (§4 there is the condensed version). This appendix gives the
code-level detail (the reviewer cannot open the source, so mechanisms are described in full). File:line refs are
to the project source for our own traceability.

## ArguzzScheduler (V6_uniform) — round-robin over instruction kinds
Scheduling unit = an (instruction_kind, step, mutation_kind) triple, chosen in three uniform stages:
1. **Instruction kind** (balanced round-robin): pick the kind with the minimum cumulative selection count
   `_counter`, ties broken uniformly at random. ~40 candidate kinds (`add`,`sub`,…,`remu`,`divu`,…,`eany`).
   ```python
   min_count = min(self._counter.get(c, 0) for c in self._candidate_instrs)
   prefs = [c for c in self._candidate_instrs if self._counter.get(c, 0) == min_count]
   instr = prefs[0] if len(prefs) == 1 else self._rng.choice(prefs)        # v6_driver_v2.py:210-213
   ```
2. **Step** within that kind: `step = self._rng.choice(self._instr_to_steps[instr])` — uniform over the trace
   steps that execute that kind (v6_driver_v2.py:214). For a once-occurring instruction this list has length 1.
3. **Mutation kind**: `kind = self._rng.choice(valid_injection_kinds_for_instr(instr))` — uniform over the kinds
   valid for that instruction class (all kinds get PRE/POST_EXEC_*, INSTR_WORD_MOD; branches add BR_NEG_COND;
   ALU/div add COMP_OUT_MOD; loads add LOAD_VAL_MOD; stores add STORE_OUT_MOD).
No rewards, no feedback. Because the unit is the instruction *kind*, a rare instruction that occurs once still
receives a full ≈1/40 share of the budget (rarity-independent).

## ConstrainedTSScheduler (V6_cTS) — constrained Thompson sampling over (kind, zone) arms
- **Arm** = `ArmKey(surface, kind, zone, opcode_class, pre_post)` (semantic_arm_universe.py:174). For the Arguzz
  surface this is effectively (mutation_kind, semantic_zone). An arm's step-set = the steps where that kind is
  valid AND that fall in that zone (empty arms are dropped, so the arm set adapts to each guest). This campaign
  had 417 arms.
- **Semantic zone**: each step is mapped to one of ~19 zones (core_arithmetic, core_div, core_memory_load,
  core_memory_store, core_mul, core_shr, core_branch, core_poseidon, …, plus boundary zones step0/last_step/
  pre_ecall/…). Mapping is by the step's cycle "major" field (e.g. major=5→core_memory_load, major→core_div).
- **Pick = four prioritized tiers** (bandit_ts.py:205-299):
  1. **cold-start** (lines 218-222): any arm with `pulls[a] < cold_start_pulls_per_arm` (default 3), round-robin.
  2. **singleton** (224-233): arms in SINGLETON_ZONES {step0,last_step} with a single step must reach
     `forced_singleton_pulls` (default 5), round-robin.
  3. **Bernoulli floor** (236-256): with probability `floor_schedule.current(...)` (default ConstantFloor 0.55)
     pick the arm with the fewest epoch pulls (pure exploration). [Legacy alternative: per-epoch integer quota.]
  4. **adaptive Thompson sampling** (269-279): sample θ_a ~ Beta(α_a, β_a) for every arm, pick argmax. With
     `α = prior_alpha + successes`, `β = prior_beta + (pulls − successes)` (lines 176-180).
- **Within-arm step**: `step = steps[0] if len(steps)==1 else self.rng.choice(steps)` — **uniform** over the
  arm's step-set (bandit_ts.py:287). The mutation kind is fixed by the arm (not separately randomized).
- **Reward**: Bernoulli success∈{0,1} passed to `update(arm, success)`; updates the Beta posteriors. Intended to
  fire on coverage novelty (computed by the driver). *(In the V6_cTS campaign this was identically 0 — see the
  master package §5.)*
- **Hyperparameters** (bandit_ts.py:134-163): `prior_alpha=1, prior_beta=1, coverage_floor_fraction=0.55,
  cold_start_pulls_per_arm=3, forced_singleton_pulls=5, epoch_size=100, bernoulli_floor`. This campaign's
  `campaign_params`: tau_new=35, tau_d=3, tau_g=6, gamma=0.9965, K_T_rare=31, floor=constant 0.55,
  num_arms=417.
Because the unit is the (kind, zone) *arm*, a rare instruction is NOT a first-class unit — it is one step inside
a zone-arm, competing against every other step in that zone via a uniform within-arm pick.

## Side-by-side
| | ArguzzScheduler (uniform) | ConstrainedTSScheduler (cTS) |
|---|---|---|
| unit | instruction kind (~40) | (kind, zone) arm (~417) |
| step pick | uniform over the kind's steps | uniform over the arm's steps |
| mutation-kind pick | uniform over valid kinds | fixed by the arm |
| feedback | none | Beta-posterior TS + cold/singleton/floor tiers |
| reward | n/a | Bernoulli (coverage novelty) — was 0 in V6_cTS |
| rare-instruction share | full ≈1/40 (rarity-independent) | diluted: 1 zone among ~19, then 1 step among many |
