According to the IV.POS.8 check-in dated 2026-06-19, you are at a real decision point: D1.E and D2.C are still specs, not built, and you want an architecture call before committing the integration work. The key caveats are that all empirical claims are still single-guest `sha2-host`, D1.A/B/C are post-hoc analyses, decay has only n=5 paired triplets, and no Hybrid-cTS result exists yet. 

My recommendation is:

> **Prioritize D2.C → D2.D/E → the four-variant POS checkpoint. Do not block that checkpoint on a full D1.E V5-only reward-rewire campaign. Keep D1.E, but demote it from “next critical path” to “parallel or follow-up causal test.”**

The reason is simple: your central research question is no longer “can V5 improve over old A4?” V5 already did that. The active question is now **whether constraint-space feedback improves Arguzz-like execution-fault fuzzing and whether Hybrid-cTS beats flat Arguzz on bug-relevant terrain**. D1.E answers a narrower V5-only question about decay and reward saturation. D2.C answers the architectural question closest to your thesis.

---

# 1. High-level architectural verdict

## What you should keep

Keep the following as load-bearing:

1. **V5/cTS semantic-zone architecture as the A4 survey engine.**
   V5 is still your strongest A4-side result. The check-in correctly describes it as floor-dominated semantic-zone exploration rather than a pure adaptive posterior success. That does not make it weak; it means the structural prior is doing the work.

2. **D2.C v0.4’s corrected kind-set split.**
   The correction is important: **V6-cTS must use all 11 Arguzz kinds** so that `V6-uniform` vs `V6-cTS` isolates scheduler logic only. **Hybrid-cTS should use the curated 4 selected Arguzz kinds** for the first checkpoint to keep the shared arm space bounded. D2.C v0.4 explicitly fixes the earlier conflation where V6-cTS would have used only 4 kinds, which would have made the comparison confounded. 

3. **Corrected production-log2 CGC as the active L0 reward channel.**
   D1.B makes the call pretty clear: coarsened CGC variants saturate earlier, while `production_log2_corrected` is the least-bad active reward representation. Use `page_class` as analysis telemetry, not as the reward L0. D1.B found the `byte_addr` bug, corrected it, and showed coarsening creates a saturation inversion rather than fixing late-stage reward signal decay. 

4. **The D1.C metrics as telemetry and future reward candidates.**
   `mutation_substrategy_uniqueness`, `d_loc_le_2_flag`, and `singleton_failure_flag` are useful. They should be logged in D2.G for V6-cTS and Hybrid-cTS. They should **not** automatically become active reward channels in Hybrid until re-audited on Hybrid telemetry. D1.C itself warns that its conclusions are V5-corpus-specific and may not transfer to Hybrid, V7, or Arguzz-with-TS. 

5. **Soundness-signal tagging, not reward.**
   Keep acceptance out of the bandit reward. D2.C’s `soundness_signal` tag is the right mechanism: log accepted applied faults, then triage them. Rewarding acceptance would teach the bandit to find fault no-ops. D2.C correctly treats the ~2.95% `prove_success` / applied bucket as a possible soundness signal or no-op requiring D2.G triage. 

## What you should drop or defer

Drop or defer the following:

1. **Drop `page_class` as active L0 reward.**
   Keep it as a diagnostic dimension. Do not make it the reward CGC. It saturates too early and lowers absolute headroom.

2. **Drop the five D2.B dead A4 arms from campaigns.**
   The D2.B mechanism report proves only 3 of the 8 newly requested A4 kinds are live on this guest: `TXN_PREV_WORD_MOD`, `TXN_PREV_CYCLE_MOD`, and `CYCLE_DIFF_COUNT_MOD`. The dead arms are structurally inert, not soundness bugs; they should not contaminate campaign data. 

3. **Do not use `f_new > 0` as a V5 L1 reward channel.**
   It is effectively dead post-local on V5. The notes say it fires on only about 0.17% of pulls full-campaign and ~0% post-local. It may revive on Hybrid, but must be re-audited there. 

4. **Do not chase every accepted Arguzz candidate.**
   Most accepted applied faults are likely fault no-ops. Add a propagation filter and triage queue. Do not let accepted candidates dominate the scheduler.

5. **Do not do another pure-A4 expansion cycle before the Hybrid checkpoint.**
   D2.B already narrowed the pure-A4 ceiling further than expected: only 3 of 8 new requested kinds are live. The next pure-A4 batch should be mechanism-selected—BigInt bytes, paging index, transaction index, BigInt index—but after the Hybrid checkpoint, not before. 

---

# 2. Main sequencing call

## Recommended order

### Phase 0 — Fix spec inconsistencies before implementation

Before building anything, fix two inconsistencies I noticed.

**First inconsistency: stale D2.C S5 pre/post assertion.**
D2.C v0.4 says `pre_post` varies: `PRE_EXEC_*`, `INSTR_WORD_MOD`, and `BR_NEG_COND` are `pre_exec`; `POST_EXEC_*`, `COMP_OUT_MOD`, `LOAD_VAL_MOD`, and `STORE_OUT_MOD` are `post_exec`. But the later arm-certainty stack still says all D2.C arms have `pre_post="pre_exec"`. That is stale and should be corrected before tests are written. The v0.4 changelog itself says the `pre_post` field is now nontrivial for the additional 7 V6-cTS kinds. 

**Second inconsistency: older NFP/plan tables still imply V6-cTS uses 4 V6 kinds.**
D2.C v0.4 correctly fixes V6-cTS to all 11 Arguzz kinds, while Hybrid-cTS keeps the selected 4. Any older notes saying `V6_uniform / V6_cTS = 4 V6 kinds` are superseded. The D2.C spec already calls this out as a plan-update issue. 

Neither looks like file corruption. They look like normal spec drift from v0.3 to v0.4. Fix them before Composer starts implementation.

### Phase 1 — Build D2.C

Build the Arguzz integration bridge and modernized V6-uniform driver first. The D2.C spec is directionally correct: modernize V6-uniform so it writes through `CoverageDB`, use full schema parity, normalize `constraint_loc` at write time, and expose Arguzz arms through the same `SemanticArmUniverse` builder. 

The most important D2.C details to preserve are:

```text
V6-uniform  = all 11 Arguzz kinds, round-robin / balanced baseline
V6-cTS      = all 11 Arguzz kinds, constrained TS
Hybrid-cTS  = 11 live A4 kinds + 4 selected Arguzz kinds, constrained TS
V5_control  = A4-only baseline
```

Do **not** let V6-cTS use only the four selected Hybrid kinds. That would make the V6-uniform vs V6-cTS result unusable.

### Phase 2 — Add Bernoulli floor before large Hybrid campaigns, but do not mutate the V5 archive baseline

The current floor scheduler’s integer quota geometry is too coarse. D1.A shows it supports only about three effective regimes: ~0%, ~48%, and ~96% floor. That means a nominal floor fraction like 0.35 or 0.20 does not behave continuously. 

For the **new** cTS variants—V6-cTS and Hybrid-cTS—I would add a Bernoulli floor mode:

```text
if rand() < floor_fraction:
    use floor exploration
else:
    use adaptive TS
```

This tests the design you actually intend. It also matters more once the arm count grows to ~160–350, because integer per-arm quotas become even less interpretable.

Do not replace the archived V5-control behavior. Treat old V5 as the deployed A4 baseline. If you want to isolate Bernoulli floor later, run a separate `V5_fresh_bernoulli` ablation. Do not let that block D2.C.

### Phase 3 — Run the four-variant checkpoint on the current guest

Run:

```text
V5_control
V6_uniform
V6_cTS
Hybrid_cTS
```

Use the current `sha2-host` guest first. This is the fastest way to answer whether your integration is alive. But label it as a **single-guest checkpoint**, not a paper-level conclusion.

I would use **N=6000 for direct comparability** with your prior archive. If compute is cheap, also run N=10000 for V6-cTS and Hybrid-cTS, because their arm spaces are much larger than V5’s 48-arm space. D2.C estimates V6-cTS may have ~200–350 actual arms and Hybrid-cTS ~160–240; at N=6000, many arms will still be under-sampled. 

### Phase 4 — Analyze by territory, not just raw loc count

Your D2.G analysis should report:

```text
common territory
A4-only territory
Arguzz-only territory
Hybrid-only territory
V5 signature ECALL/MRET contexts
V6-exclusive normalized locs
CGC final and CGC AUC
local_context AUC
applied-pull count
skipped/error rate
C1/C2/C5 rejection channel split
soundness_signal count
triaged non-noop accepted candidates
singleton_failure_rate
d_loc / d_glob distributions
arm occupancy and entropy
```

The most important comparison is not raw `constraint_loc_final`. The actual questions are:

```text
Does V6-cTS beat V6-uniform on the same 11 Arguzz kinds?
Does Hybrid-cTS beat V6-uniform on total useful territory?
Does Hybrid-cTS preserve V5's A4-only/kernel/ECALL discoveries?
Does Hybrid-cTS add Arguzz terrain without thinning A4 floor coverage too much?
Does cTS improve accepted-candidate quality, not just count?
```

### Phase 5 — Only then decide whether D1.E matters

After D2.G, decide whether to run D1.E or a Hybrid-specific reward rewire. My current recommendation:

```text
Do not block D2.C/D2.G on D1.E.
Run D1.E only if compute is available in parallel or if D2.G shows reward-signal saturation is the limiting factor.
```

D1.E is not bad. It is just not the highest-leverage next step for your main goal. Its scope is V5-only, and D1.E itself says results do not transfer automatically to Hybrid V7, V7, or Arguzz-with-thompson. 

---

# 3. Detailed decisions against your §5 questions

## Q1. Decay’s fate

**Do not drop decay. Do not make it the critical path.**

D1.A does not prove decay is useless. It proves that under the old sparse binary reward, decay did not move `local_context_final`, and that the scheduler’s integer floor geometry makes gradual decay hard to test. The report explicitly says decay remains scoped to the old reward and should be re-evaluated once richer reward signals exist. 

But for your main goal—beating Arguzz—V5-only decay is now secondary. The immediate uncertainty is not “static floor vs decayed floor on 48 A4 arms.” It is:

```text
Can cTS schedule Arguzz-style execution faults better than flat Arguzz?
Can Hybrid preserve A4's witness-internal strengths while importing Arguzz's broader terrain?
```

I would keep decay as follows:

```text
V5-only default: keep ConstantFloor(0.55)
V5-only D1.E: optional causal test, not blocker
Hybrid/V6-cTS: use Bernoulli floor with either static 0.55 or mild decay
D2.G: record whether arm-space dilution occurs
```

If you do run D1.E, use the D1.E retunes:

```text
Exponential K ≈ 200–300
EpochStageFloor: [(0, 0.55), (1000, 0.35)]
```

Those retunes are consistent with D1.A/D1.E: K=50 decayed too early; the old epoch boundary at 2000 fired too late and the third tier was mechanically invisible. 

## Q2. CGC reward

**Confirm `production_log2_corrected` as the active reward CGC. Reject page_class as L0 reward.**

D1.B is clear. Coarsening does the opposite of what we wanted: it saturates earlier. `page_class`, `region_only`, and `log4_explicit` may be useful for presentation or post-hoc semantic interpretation, but they shrink the post-local reward window. The corrected production log2 has the most remaining headroom near local saturation, even though that headroom is thin. 

Your ELF-derived `page_class` definition is conceptually sound as telemetry. I would keep it, with two caveats:

1. It must be derived per guest. Do not hardcode sha2-host ranges into the architecture.
2. Do not use `page_class` as an active reward unless a later multi-guest analysis shows it predicts bug-proximity better than production log2.

## Q3. L1 reward composition

For D1.E v1, the spec’s **naive OR with guards** is acceptable as a cheap causal test.

For Hybrid-cTS, **do not activate L1 on the first run**. Log the L1 signals, re-audit them, then decide.

The reason is that the D1.C signals are V5-corpus signals. D1.C explicitly says it did not test Hybrid-cTS, V7, or Arguzz-with-thompson, and that the fire rates/correlations may change materially. 

The highest-risk L1 signal is `d_loc_le_2_flag`. It fires post-local at about 60.7% on V5 and can create the opposite failure mode: an always-on bandit success bit. The D1.E spec’s guard at post-local mean >0.75 is necessary. 

For Hybrid, there are two additional risks:

### Risk A — `mutation_substrategy_uniqueness` may explode under Arguzz

A4 substrategy fields are relatively bounded: byte lane, value class, opcode field, bit mask. Arguzz faults may contain random addresses, random values, random PCs, or fault-specific strings. If you include raw mutated values in the uniqueness key, this signal may fire nearly every time and become useless.

For Hybrid/V6, define finite semantic substrategy classes:

```text
address_region / page_class
value_class, not raw value
pc_region, not raw PC
branch_taken_to_not_taken vs not_taken_to_taken
opcode_class transition, not raw instruction word
pre_exec vs post_exec
fault target role
```

Do not use raw addresses or raw values in active reward uniqueness keys.

### Risk B — `d_loc_le_2` behaves differently on C2-heavy V6

D2.C says many V6 rejections are C2 / global-polynomial / verify-segment failures with no local `<constraint_fail>` tag. If `d_loc=0` in those cases, `d_loc_le_2_flag` may reward a large fraction of applied rejected V6 faults. That might be useful, but it might also saturate immediately.

So for Hybrid:

```text
First run: base reward only; log L1
After D2.G: re-audit L1 on Hybrid telemetry
Second run: enable L1 only if post-local fire/correlation is sane
```

Longer-term, I would move away from naive OR and toward **per-channel posteriors**:

```text
survey_success       = l_new OR g_new OR s_new
surgical_success     = singleton_failure OR d_loc_le_2
global_success       = new CGC OR C2/failure_recording_gap novelty
soundness_queue_hit  = propagated soundness_signal, not generic accepted
```

Then combine channels as a weighted acquisition function rather than collapsing them into one bit. Naive OR is fine for D1.E v1; it is too blunt for the final architecture.

## Q4. Accept signal / no-op confound

I agree with your proposed direction:

```text
Keep acceptance out of the reward.
Add a fault-propagation filter.
Run broadly in survey mode.
Triage accepted candidates separately.
```

The current situation is exactly what we expected. A4 has 0 accepted-invalids across its corpus; Arguzz has an apparent ~2.95% applied+accepted bucket, but that bucket is untriaged and likely dominated by fault no-ops. The check-in states this asymmetry directly. 

D2.C’s outcome mapping is also correct: the old panic-first classifier was wrong. A `host_panic` string does not imply the mutation was a pre-prover crash. The relevant field is `prover_status`. D2.C recovers 91.6% APPLIED+REJECTED rows that the old interpretation would have thrown away, and distinguishes C1 local failures from C2 verify-segment/global-polynomial rejections. 

### Add a cheap propagation filter now

Do not wait for full witness repair. Add a lightweight accepted-candidate triage level immediately.

For each `soundness_signal=True` row, compute:

```text
fault_applied = <fault> tag present and parsed
guest_did_not_panic = prover_status == success
no_local_failures = failures empty
no_global_failures = global_failures empty
no_hook3_residue = rerun with A4_FAMILY_RESIDUE=1 shows no residue
propagated = one or more of:
    final register/memory digest changed
    journal/output changed
    post-fault trace hash changed
    later PC sequence changed
    later memory transaction sequence changed
    cycle count changed
    affected witness-relevant field changed
```

Then classify:

```text
accepted_noop:
    accepted + no rejection + no propagation evidence

accepted_propagated_candidate:
    accepted + no rejection + propagation evidence

accepted_hidden_global_reject:
    accepted in default run, but Hook 3 residue nonzero on rerun
```

Only `accepted_propagated_candidate` deserves deep Mode-B repair/minimization.

### Do not over-filter on output

Be careful: “program output unchanged” is not enough to call a candidate a no-op. A soundness bug can preserve public output but prove an invalid intermediate execution. Use trace/witness propagation, not just journal mismatch.

## Q5. Pure-A4 next batch

**Do not treat A4 as done. But do not run another pure-A4 batch before the Hybrid checkpoint.**

D2.B taught the right lesson: pure A4 expansion needs mechanism-first selection. Blindly adding trace fields is wasteful because many fields never enter the witness. The mechanism report identifies the next credible A4 targets:

```text
BIGINT_BYTES_MOD
CYCLE_PAGING_IDX_MOD
CYCLE_TXN_IDX_MOD
CYCLE_BIGINT_IDX_MOD
CYCLE_MODE_MOD on paging cycles
INSTR_TYPE_MOD on paging / ECALL cycle classes
```

Those are not random. They hit BigInt operands, paging cycles, and structural indices—surfaces no current kind exercises. 

But they should be IV.POS.9 or a post-D2.G branch, not pre-D2.C. The next immediate question is Hybrid.

My call:

```text
Now: D2.C / Hybrid checkpoint.
Later: mechanism-selected A4 batch, probably tied to a BigInt/paging guest.
Never: broad “mutate all remaining fields” catalog expansion.
```

## Q6. Sequencing: D1.E first or Hybrid first?

**Hybrid first.**

D1.E is useful, but it answers:

```text
Can V5-only decay exploit enriched L1 reward?
```

D2.C/D2.G answers:

```text
Can your feedback/scheduler improve Arguzz?
Can Hybrid beat Arguzz?
```

Your thesis is closer to the second question. The current V5 catalog has already saturated its local universe and has 0 accepted-invalids. D1.E may teach us something about decay, but it is unlikely to produce a decisive “beats Arguzz” architecture by itself.

My recommended implementation sequence:

```text
0. Fix D2.C spec drift.
1. Implement D2.C.
2. Implement minimal Bernoulli floor support for new cTS variants.
3. Implement D2.D/E/F enough to run:
   V5_control, V6_uniform, V6_cTS, Hybrid_cTS.
4. Log D1.C L1 channels in all fresh runs, but keep them inactive.
5. Run the four-variant checkpoint.
6. Re-audit L1 on V6-cTS and Hybrid-cTS.
7. Then choose:
   - Hybrid-L1 run,
   - D1.E V5-only causal test,
   - arm-space reduction,
   - or multi-guest expansion.
```

If you have spare POS capacity, run D1.E in parallel. But do not let it block D2.C.

## Q7. Multi-guest sequencing

Run the current single-guest checkpoint first. Then move to multi-guest before making any headline claim.

Single-guest first is justified because:

```text
D2.C is complex and needs a controlled integration checkpoint.
All prior baselines exist on sha2-host.
You can debug territory decomposition and schema parity fastest there.
```

But do not claim “beats Arguzz” from one guest.

For the next multi-guest suite, prioritize:

1. **Current sha2-host**
   Baseline continuity.

2. **ECALL/MRET/control-heavy guest**
   V5’s signature discoveries were kernel/ECALL/MRET-region contexts. This is the most important validation target, even if it needs an inspector extension.

3. **Memory-stress + branch/control guest**
   This exercises both Arguzz strengths and A4 memory-permutation metadata.

4. **BigInt/paging guest**
   Needed before the next mechanism-selected A4 batch, especially `BIGINT_BYTES_MOD`, `CYCLE_BIGINT_IDX_MOD`, and paging-cycle mutations.

5. **Stock SHA guest**
   Cheap sanity check, but likely less strategically distinct if the current guest is already SHA-ish.

I agree with deferring heavy witness-patching/repair until after the initial four-variant checkpoint. But do **not** defer the cheap soundness-signal propagation filter. That should be in D2.G immediately.

## Q8. Semantic mappings

Your mappings are mostly sound for a first checkpoint.

### Semantic zones

The 19 zones are reasonable. Keep them bounded. Do not add a large empirical zone taxonomy before the first Hybrid run. But you must report zone occupancy:

```text
zone has steps?
zone has arms?
zone has pulls?
zone has APPLIED pulls?
zone has new local/CGC?
```

If zones like `core_sha`, `core_poseidon`, `pre_mret`, `post_mret`, `pre_halt`, or `post_halt` are empty/rare on the current guest, do not let their absence distort architectural conclusions.

### Arm opcode class vs CGC opcode class

The split is defensible:

```text
Arm opcode_class: scheduler identity, finer where scheduling decisions differ.
CGC opcode_class: compressed telemetry, coarser to avoid key explosion.
```

Keep the 7-class arm taxonomy and 8-class CGC taxonomy for the first checkpoint. Do not inflate them now.

### `pre_post`

This is useful for Arguzz, but make sure the spec and tests agree. v0.4 says it should vary; the stale S5 row says all pre_exec. Fix that.

### `txn_role`

The six roles are acceptable:

```text
read, write, ifetch, register, prev_word, prev_cycle
```

For D2.G, pivot on `producer_kind` when you need finer per-kind analysis. Do not add `cycle_meta` or `structural_index` roles yet unless D2.G shows ambiguity.

### CGC address bucketing

Keep:

```text
address_region × log2(address_bucket) × txn_role × cycle_phase
```

for active reward.

Keep `page_class` as supplementary telemetry. It is useful, but guest-specific and not a good L0 reward on current data.

### Validation method

Source-level mechanism validation is sufficient for first checkpoint. For publication-level claims, add empirical occupancy and arm-health checks:

```text
arm exists
arm has valid steps
arm gets selected
mutation applies
witness/prover path exercised
rejection channel observed or accepted candidate triaged
```

This is especially important for Hybrid because source-level validity does not guarantee useful scheduling density.

---

# 4. Where I agree and disagree with your current judgments

## I agree: D2.C is the main path

Your intended four-variant comparison is the right checkpoint:

```text
V6-uniform vs V6-cTS vs Hybrid-cTS vs V5
```

This is the cleanest way to test whether your constraint feedback improves Arguzz and whether Hybrid beats flat Arguzz.

## I agree: acceptance should not be reward

Rewarding acceptance would likely select for fault no-ops. Keep `soundness_signal` as a triage tag, not a posterior success bit.

## I agree: coarsened CGC as L0 is dead

D1.B convincingly kills the page_class/log4/region_only L0-swap idea for this guest. Production-log2-corrected is the right default.

## I partially disagree: “duplicate Arguzz kind names” should not be treated as true redundancy

The decision to use only 4 selected Arguzz kinds in Hybrid is fine for arm-space control. But the justification should be **bounded first checkpoint**, not “duplicate names are redundant.”

`PRE_EXEC_REG_MOD` as an Arguzz execution-time fault is not semantically identical to A4 `PRE_EXEC_REG_MOD` as a post-execution trace-cell mutation. Same name, different timing, different propagation model. Excluding duplicate-named kinds from Hybrid may be correct for first-run budget control, but it should remain provisional.

Add a D2.G rule:

```text
If V6-cTS shows excluded Arguzz kinds have high unique coverage,
high accepted-propagated candidate rate,
or strong bug-proximity metrics,
then run Hybrid-full or Hybrid+excluded-kind follow-up.
```

## I partially disagree: D1.E naive OR should not be treated as the final reward architecture

Naive OR is fine as D1.E v1. It is not the architecture I would ship.

The final architecture should use channel-aware learning:

```text
coverage channel
surgical/low-cofailure channel
global/C2 channel
accepted-propagated queue
underexplored-substrategy channel
```

This avoids the two failure modes you have already seen:

```text
too sparse: discovery bit dies
too dense: d_loc_le_2 makes success always-on
```

## I disagree if the plan is to defer all triage

Defer heavy repair. Do not defer lightweight accepted-candidate triage. Arguzz’s accepted bucket is the only current signal that looks like possible soundness discovery. Even if most are no-ops, you need a cheap filter now so D2.G can report useful numbers.

---

# 5. What the first four-variant checkpoint should decide

Here is the decision matrix I would use after D2.G.

## Case A: V6-cTS beats V6-uniform

This validates your core feedback hypothesis on Arguzz’s own surface.

Then:

```text
Keep V6-cTS.
Run Hybrid-cTS.
Re-audit L1 on V6/Hybrid.
Consider active Hybrid-L1.
```

If Hybrid also beats V6-uniform, you have your strongest architecture.

## Case B: V6-cTS loses to V6-uniform, but Hybrid wins

This means your scheduler alone does not improve Arguzz, but Hybrid’s combined surface does. That is still valuable, but the paper framing changes:

```text
The win is hybrid surface + A4 witness-internal terrain,
not pure MAB scheduling over Arguzz.
```

Then investigate whether V6-cTS lost due to arm-space overfactorization. Try `V6-cTS-lite`.

## Case C: V6-cTS wins, Hybrid loses

This means Hybrid’s A4 arms dilute the Arguzz scheduler or the curated 4-kind subset is too narrow.

Then:

```text
Run Hybrid without A4 floor dominance,
or Hybrid with surface-level budget split:
  60% Arguzz cTS
  40% A4 V5/V5-expanded
```

Do not conclude A4 is useless. It may need a separate surface-level scheduler.

## Case D: Both V6-cTS and Hybrid lose to V6-uniform

Then your cTS arm space is likely too fragmented, the reward is too sparse, or the floor is too thin.

Next fixes:

```text
1. Collapse V6 arms:
   kind × zone, dropping opcode_class first,
   or kind × opcode_class, dropping fine zones except boundaries.

2. Increase N to 10000.

3. Activate channel-aware L1 after re-audit.

4. Try surface-level hierarchical scheduling:
   first choose surface/kind,
   then choose step/zone.
```

Do not conclude “constraint-space feedback failed” until you test a lower-dimensional V6-cTS-lite.

## Case E: Hybrid preserves V5-only terrain but does not beat V6 raw

This is still publishable as a complementary finding:

```text
Hybrid covers Arguzz terrain plus A4 witness-internal regions Arguzz misses,
but flat Arguzz has higher raw count.
```

Then your claim becomes not “strictly beats Arguzz on raw loc count,” but “dominates on unioned semantically normalized terrain / specific witness-internal families / bug-proximity.”

---

# 6. New suggestions

## Suggestion 1: Add a surface-level meta-bandit

Instead of one flat arm space:

```text
(surface, kind, zone, opcode_class, pre_post)
```

use a two-level scheduler:

```text
Level 1: choose surface
    A4_trace_cell
    arguzz_exec_fault

Level 2: choose arm within selected surface
```

This lets you enforce surface budgets:

```text
A4 minimum: preserve V5 discoveries
Arguzz minimum: preserve broad terrain
Adaptive: allocate remaining budget based on marginal utility
```

This addresses Hybrid’s biggest risk: A4 and Arguzz arms may compete destructively in one large posterior space.

A simple first version:

```text
40% A4 floor
40% Arguzz floor
20% adaptive surface/kind/zone TS
```

Then learn whether the adaptive 20% moves toward the better surface.

## Suggestion 2: Add V6-cTS-lite only if actual arm count exceeds 300

D2.C already has a safety valve if actual arm counts exceed ~300. Use it. If V6-cTS arm count is too high, reduce in this order:

```text
1. Drop pre_post as a separate dimension when kind already encodes it.
2. Merge core arithmetic/mul/div/shr into core_compute for Arguzz arms.
3. Keep boundary zones separate.
4. Keep opcode_class only for kinds where it changes applicability or behavior.
```

Do not start with the maximal 5-tuple if it crosses the advisory threshold and N remains 6000.

## Suggestion 3: Separate survey score from proximity score

Do not force all objectives into one Bernoulli reward.

Report and eventually learn from:

```text
survey_score:
    l_new, g_new, s_new

proximity_score:
    singleton_failure_flag, d_loc_le_2, d_glob_le_1, low co-failure degree

soundness_score:
    accepted + propagated + no C1/C2/C3/C5

global_score:
    C2/failure_recording_gap novelty, Hook3 residue novelty
```

The final architecture can allocate budget across these modes rather than OR-ing them.

## Suggestion 4: Add “repairability” as a logged metric even before repair

You can approximate repairability cheaply:

```text
repairability_proxy =
    low d_loc
    low d_glob
    singleton failure
    same target loc recurring with different co-failure sets
    accepted or proof_generated
    C2-only with no local failures
```

Then later repair/minimization can target high-proxy candidates.

## Suggestion 5: Track “unique useful failures,” not just failures

For cascade concerns, add:

```text
unique_locs_with_d_loc <= 2
unique_locs_with_singleton_hit
unique_locs_with_min_cofailure_size
per-loc min d_loc observed
per-loc min d_glob observed
per-loc singleton ever?
```

This directly answers your earlier worry: coverage is less useful if it only appears in giant cascades.

---

# 7. Final architecture recommendation

Your likely strongest architecture is not “pure A4 beats Arguzz.” It is:

```text
Hybrid-cTS:
  A4 witness-internal trace-cell mutations
  + Arguzz execution-fault mutations
  + semantic-zone / opcode-class / surface-aware arm space
  + corrected production-log2 CGC
  + applied accounting
  + soundness-signal triage
  + later channel-aware reward enrichment
  + later repair/minimization
```

The main scientific thesis should be adjusted slightly:

> **Constraint-space feedback is not a replacement for Arguzz’s execution-fault surface. It is a scheduler and triage layer that can make execution-fault fuzzing more directed, while A4 adds witness-internal mutation surfaces that execution-time fault injection does not naturally cover.**

This is stronger than trying to prove pure post-execution trace fuzzing beats Arguzz. The Arguzz paper’s own contribution is fault injection plus metamorphic testing for zkVM soundness/completeness, and it reports bugs across real zkVMs; you should not frame the competition as if uniform Arguzz were a weak baseline. ([arXiv][1])

The best next step is therefore:

```text
1. Fix D2.C spec drift.
2. Implement D2.C.
3. Add Bernoulli floor support for new cTS variants.
4. Run V5_control / V6_uniform / V6_cTS / Hybrid_cTS on current guest.
5. Analyze by territory + rejection channel + accepted-candidate propagation.
6. Re-audit L1 signals on V6/Hybrid.
7. Then decide whether to run Hybrid-L1, D1.E, V6-cTS-lite, or multi-guest.
```

If Hybrid-cTS wins that checkpoint on useful territory or bug-proximity, you have a credible candidate architecture. If it does not, the next fix is not more V5-only tuning; it is arm-space reduction, surface-level budgeting, and accepted-candidate propagation triage.

[1]: https://arxiv.org/abs/2509.10819?utm_source=chatgpt.com "Arguzz: Testing zkVMs for Soundness and Completeness Bugs"
